"""Secure file wiper — multi-pass overwrite then delete."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_wiper_report
from .runner import parse_collector_json


_SSD_CAVEAT = (
    'HDD overwrite note: a 3-pass wipe (zeros, ones, random) followed by deletion '
    'provides strong assurance on traditional spinning disks.\n'
    'SSD/NVMe caveat: wear leveling and internal remapping mean multi-pass overwrites '
    'do not guarantee that original flash cells were overwritten; remapped blocks may '
    'retain recoverable data inaccessible to the OS.'
)


def _build_linux_wiper(path: str) -> str:
    source = f'''
import os, secrets, platform
path = {json.dumps(path)}
if not os.path.isfile(path):
    _emit({{"error": "File not found or not a regular file", "path": path, "platform": "linux"}})
else:
    size = os.path.getsize(path)
    passes = [(0, "zeros"), (255, "ones"), (-1, "random")]
    with open(path, "r+b") as fh:
        for fill, label in passes:
            fh.seek(0)
            remaining = size
            chunk = 65536
            while remaining > 0:
                n = min(chunk, remaining)
                if fill == -1:
                    data = secrets.token_bytes(n)
                else:
                    data = bytes([fill]) * n
                fh.write(data)
                remaining -= n
            fh.flush()
            os.fsync(fh.fileno())
    os.remove(path)
    verified = not os.path.exists(path)
    _emit({{
        "path": path,
        "size": size,
        "passes": 3,
        "method": "zeros, ones, random (cryptographic)",
        "verified": verified,
        "platform": platform.system(),
        "message": "3-pass overwrite complete; file deleted" if verified else "Overwrite complete; file may remain",
    }})
'''
    return build_linux_collector_command(source)


def _build_windows_wiper(path: str) -> str:
    escaped = path.replace("'", "''")
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$path='{escaped}'
$result=@{{path=$path;platform='windows'}}
try {{
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    throw "File not found or not a regular file"
  }}
  $item=Get-Item -LiteralPath $path
  $size=$item.Length
  $fs=[System.IO.File]::Open($path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
  $buf=New-Object byte[] 65536
  $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
  foreach ($pass in @(
    @{{name='zeros';fill=0}},
    @{{name='ones';fill=255}},
    @{{name='random';fill=-1}}
  )) {{
    $fs.Seek(0,[System.IO.SeekOrigin]::Begin)|Out-Null
    $remaining=$size
    while ($remaining -gt 0) {{
      $n=[Math]::Min(65536,$remaining)
      if ($pass.fill -eq -1) {{ $rng.GetBytes($buf); [Array]::Clear($buf,$n,$buf.Length-$n) }}
      else {{ for ($i=0; $i -lt $n; $i++) {{ $buf[$i]=[byte]$pass.fill }} }}
      $fs.Write($buf,0,$n)|Out-Null
      $remaining-=$n
    }}
    $fs.Flush($true)
  }}
  $fs.Close()
  Remove-Item -LiteralPath $path -Force
  $result.size=$size
  $result.passes=3
  $result.method='zeros, ones, random (cryptographic)'
  $result.verified=-not (Test-Path -LiteralPath $path)
  $result.message='3-pass overwrite complete; file deleted'
}} catch {{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


@plugin.command(
    name='wiper',
    platforms=['linux', 'windows', 'unix'],
    description='Securely wipe a remote file (3-pass overwrite: zeros, ones, random)',
)
def run(session: SessionContext, args):
    if not args:
        session.print('Usage: run wiper <session_id> <remote_file_path>', 'red')
        return 1

    remote_path = ' '.join(args).strip().strip('"').strip("'")
    if not remote_path:
        session.print('Usage: run wiper <session_id> <remote_file_path>', 'red')
        return 1

    session.log_event(f'Plugin wiper: started for {remote_path}')
    session.print(_SSD_CAVEAT, 'yellow')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    if session.is_windows:
        win_ps = _build_windows_wiper(remote_path)
        unix_cmd = 'true'
    else:
        unix_cmd = _build_linux_wiper(remote_path)
        win_ps = ''

    raw = session.run_marked(
        unix_cmd,
        win_ps,
        timeout=120.0,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print("Plugin 'wiper' failed — no response from target.", 'red')
        session.log_plugin_result('wiper', '', f'no response for {remote_path}')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'wiper' failed — could not parse results.", 'red')
        session.log_plugin_result('wiper', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'wiper' error: {data['error']}", 'red')
        report = format_wiper_report(data)
        session.print(report, 'cyan')
        session.log_plugin_result('wiper', report, json.dumps(data, indent=2))
        return 1

    report = format_wiper_report(data)
    session.print(report, 'cyan')
    session.log_plugin_result('wiper', report, json.dumps(data, indent=2))
    session.log_command(f'run wiper {remote_path}', report)
    return 0
