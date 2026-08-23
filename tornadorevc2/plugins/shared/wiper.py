"""Secure file wiper — configurable multi-pass overwrite, rename, truncate, then delete."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_wiper_report
from .runner import parse_collector_json


WIPER_USAGE = """
Wiper — securely overwrite and delete a remote file.

Usage:
  run wiper <remote_file_path> [method=<profile>]

Profiles:
  quick      1-pass cryptographic random overwrite, rename, truncate, delete
  standard   3-pass zeros / ones / random (default)
  dod        DoD 5220.22-M E (3-pass: 0x00, 0xFF, random)
  thorough   7-pass enhanced overwrite (random, random, 0x00, 0xFF, 0xAA, 0x55, random)
  shred      Linux: GNU shred -u when available; otherwise falls back to thorough

Pre-delete hardening (all profiles):
  - Clear read-only / immutable attributes where possible
  - Rename to a random filename in the same directory
  - Truncate to zero length after the final overwrite pass
  - Sync to disk, unlink, and fsync parent directory (Linux)

Examples:
  run wiper /tmp/secret.bin
  run wiper C:\\Users\\Public\\notes.txt method=thorough
  run wiper method=quick /var/tmp/cache.dat
""".strip()

PLUGIN_INFO = WIPER_USAGE

_SSD_CAVEAT = (
    'HDD note: multi-pass overwrite plus rename/truncate/delete provides strong assurance '
    'on traditional spinning disks.\n'
    'SSD/NVMe caveat: wear leveling and internal remapping mean overwrites do not guarantee '
    'that original flash cells were overwritten; remapped blocks may retain recoverable data.'
)

_VALID_METHODS = frozenset({'quick', 'standard', 'dod', 'thorough', 'shred'})

_METHOD_PASSES = {
    'quick': [(-1, 'random')],
    'standard': [(0, 'zeros'), (255, 'ones'), (-1, 'random')],
    'dod': [(0, 'zeros'), (255, 'ones'), (-1, 'random')],
    'thorough': [
        (-1, 'random'),
        (-1, 'random'),
        (0, 'zeros'),
        (255, 'ones'),
        (0xAA, 'pattern_0xAA'),
        (0x55, 'pattern_0x55'),
        (-1, 'random'),
    ],
}

_METHOD_LABELS = {
    'quick': '1-pass random',
    'standard': 'zeros, ones, random (cryptographic)',
    'dod': 'DoD 5220.22-M E (0x00, 0xFF, random)',
    'thorough': '7-pass enhanced (random×2, 0x00, 0xFF, 0xAA, 0x55, random)',
    'shred': 'GNU shred -u (3 passes + zero)',
}


def _parse_wiper_args(args):
    if not args:
        return None, None, WIPER_USAGE

    method = 'standard'
    path_tokens = []
    for token in args:
        low = token.lower()
        if low.startswith('method='):
            method = low[7:].strip()
        elif low in _VALID_METHODS and not path_tokens:
            method = low
        elif low in _VALID_METHODS and path_tokens:
            path_tokens.append(token)
        else:
            path_tokens.append(token)

    remote_path = ' '.join(path_tokens).strip().strip('"').strip("'")
    if not remote_path:
        return None, None, WIPER_USAGE
    if method not in _VALID_METHODS:
        return None, None, WIPER_USAGE + f"\n\nUnknown method '{method}'. Choose: {', '.join(sorted(_VALID_METHODS))}"
    return remote_path, method, None


def _build_linux_wiper(path: str, method: str) -> str:
    passes = _METHOD_PASSES.get(method, _METHOD_PASSES['standard'])
    if method == 'shred':
        passes = _METHOD_PASSES['thorough']
    passes_literal = repr(passes)
    label = _METHOD_LABELS.get(method, method)
    use_shred = method == 'shred'
    return build_linux_collector_command(f'''
import os, secrets, platform, subprocess, stat

path = {json.dumps(path)}
profile = {json.dumps(method)}
passes = {passes_literal}
use_shred = {repr(use_shred)}
method_label = {json.dumps(label)}
steps = []
pass_count = 0
error = None

def sync_parent(p):
    parent = os.path.dirname(os.path.abspath(p)) or '.'
    try:
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass

if not os.path.isfile(path):
    _emit({{"error": "File not found or not a regular file", "path": path, "platform": "linux", "profile": profile}})
else:
    original_path = path
    size = os.path.getsize(path)

    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        steps.append('chmod_writable')
    except OSError:
        pass
    try:
        if subprocess.run(['chattr', '-i', path], capture_output=True, timeout=5).returncode == 0:
            steps.append('chattr_immutable_cleared')
    except Exception:
        pass

    parent = os.path.dirname(os.path.abspath(path)) or '.'
    renamed = os.path.join(parent, secrets.token_hex(12) + '.tmp')
    try:
        os.rename(path, renamed)
        path = renamed
        steps.append('renamed')
    except OSError:
        pass

    wiped = False
    if use_shred:
        shred_bin = subprocess.which('shred') or subprocess.which('/usr/bin/shred')
        if shred_bin:
            rc = subprocess.run(
                [shred_bin, '-u', '-n', '3', '-z', '--', path],
                capture_output=True,
                timeout=max(180, size // (1024 * 1024) * 20 + 60),
            ).returncode
            if rc == 0:
                wiped = True
                steps.append('gnu_shred')
                pass_count = 3
                method_label = {json.dumps(_METHOD_LABELS['shred'])}
            else:
                steps.append('gnu_shred_failed_fallback')

    if not wiped:
        pass_count = len(passes)
        if profile == 'shred':
            method_label = method_label + ' (fallback)'
        chunk = 65536
        try:
            with open(path, 'r+b') as fh:
                for fill, _label in passes:
                    fh.seek(0)
                    remaining = size
                    while remaining > 0:
                        n = min(chunk, remaining)
                        if fill == -1:
                            data = secrets.token_bytes(n)
                        else:
                            data = bytes([fill & 0xFF]) * n
                        fh.write(data)
                        remaining -= n
                    fh.flush()
                    os.fsync(fh.fileno())
            steps.append('overwrite')

            with open(path, 'r+b') as fh:
                fh.truncate(0)
                fh.flush()
                os.fsync(fh.fileno())
            steps.append('truncated')

            os.remove(path)
            steps.append('unlinked')
        except OSError as exc:
            error = str(exc)

    sync_parent(path if not error else original_path)
    if not error:
        steps.append('dir_synced')
    verified = not os.path.exists(path)
    payload = {{
        "path": path,
        "original_path": original_path,
        "size": size,
        "passes": pass_count,
        "profile": profile,
        "method": method_label,
        "steps": steps,
        "verified": verified,
        "platform": platform.system(),
        "message": "Secure wipe complete; file deleted" if verified and not error else "Wipe finished; file may remain",
    }}
    if error:
        payload["error"] = error
    _emit(payload)
''')


def _build_windows_wiper(path: str, method: str) -> str:
    passes = _METHOD_PASSES.get(method, _METHOD_PASSES['standard'])
    if method == 'shred':
        passes = _METHOD_PASSES['thorough']
    label = _METHOD_LABELS.get(method, method)
    if method == 'shred':
        label = _METHOD_LABELS['thorough'] + ' (shred profile)'
    escaped = path.replace("'", "''")
    ps_passes = ','.join(
        f"@{{name='{name}';fill={fill}}}" for fill, name in passes
    )
    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$path='{escaped}'
$profile='{method}'
$result=@{{path=$path;platform='windows';profile=$profile}}
$steps=@()
$originalPath=$path
function Clear-FileAttributes([string]$p) {{
  try {{ [IO.File]::SetAttributes($p,[IO.FileAttributes]::Normal) }} catch {{}}
  try {{
    $i=Get-Item -LiteralPath $p -Force -EA Stop
    $i.Attributes=[IO.FileAttributes]::Normal
  }} catch {{}}
}}
function Flush-ToDisk([IO.FileStream]$stream) {{
  try {{ $stream.Flush($true) }} catch {{ $stream.Flush() }}
}}
function Open-WriteRetry([string]$p,[int]$retries=6) {{
  for ($try=0; $try -lt $retries; $try++) {{
    try {{
      return [IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    }} catch {{
      if ($try -ge ($retries - 1)) {{ throw }}
      Start-Sleep -Milliseconds 350
    }}
  }}
}}
try {{
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    throw 'File not found or not a regular file'
  }}
  $originalPath=$path
  Clear-FileAttributes $path
  $steps+='attributes_cleared'
  $item=Get-Item -LiteralPath $path -Force
  $size=$item.Length

  $parent=Split-Path -Parent $path
  if ([string]::IsNullOrEmpty($parent)) {{ $parent='.' }}
  $renamed=Join-Path $parent (([guid]::NewGuid().ToString('N')) + '.tmp')
  try {{
    [IO.File]::Move($path,$renamed)
    $path=$renamed
    $result.path=$path
    $steps+='renamed'
  }} catch {{}}

  Clear-FileAttributes $path
  $fs=Open-WriteRetry $path
  $buf=New-Object byte[] 65536
  $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
  $passList=@({ps_passes})
  foreach ($pass in $passList) {{
    $fs.Seek(0,[IO.SeekOrigin]::Begin)|Out-Null
    $remaining=$size
    while ($remaining -gt 0) {{
      $n=[Math]::Min(65536,$remaining)
      if ($pass.fill -eq -1) {{
        $rng.GetBytes($buf)
        if ($n -lt $buf.Length) {{ [Array]::Clear($buf,$n,$buf.Length-$n) }}
      }} else {{
        for ($i=0; $i -lt $n; $i++) {{ $buf[$i]=[byte]($pass.fill -band 0xFF) }}
      }}
      $fs.Write($buf,0,$n)|Out-Null
      $remaining-=$n
    }}
    Flush-ToDisk $fs
  }}
  $steps+='overwrite'
  $fs.SetLength(0)|Out-Null
  Flush-ToDisk $fs
  $fs.Close()
  $fs=$null
  $steps+='truncated'
  [IO.File]::Delete($path)
  $steps+='unlinked'
  $result.original_path=$originalPath
  $result.size=$size
  $result.passes=$passList.Count
  $result.method='{label.replace("'", "''")}'
  $result.steps=$steps
  $result.verified=-not (Test-Path -LiteralPath $path)
  if (-not $result.verified) {{
    throw 'File still present after secure delete'
  }}
  $result.message='Secure wipe complete; file deleted'
}} catch {{
  $result.error=$_.Exception.Message
  $result.steps=$steps
  foreach ($target in @($path,$originalPath)) {{
    if ([string]::IsNullOrEmpty($target)) {{ continue }}
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {{ continue }}
    try {{
      Clear-FileAttributes $target
      Remove-Item -LiteralPath $target -Force -EA Stop
      $steps+='fallback_delete'
      $result.steps=$steps
      $result.verified=-not (Test-Path -LiteralPath $target)
      if ($result.verified) {{
        $result.error=$null
        $result.message='File deleted via fallback Remove-Item (overwrite may be incomplete)'
      }}
      break
    }} catch {{
      $result.fallback_error=$_.Exception.Message
    }}
  }}
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


_METHOD_TIMEOUTS = {
    'quick': 90.0,
    'standard': 120.0,
    'dod': 120.0,
    'thorough': 360.0,
    'shred': 300.0,
}


@plugin.command(
    name='wiper',
    platforms=['linux', 'windows', 'unix'],
    description='Securely wipe a remote file (multi-pass overwrite, rename, truncate, delete)',
)
def run(session: SessionContext, args, quiet=False, return_result=False):
    remote_path, method, usage = _parse_wiper_args(args)
    if usage:
        if not quiet:
            session.print(usage, 'yellow')
        return (1, None) if return_result else 1

    session.log_event(f'Plugin wiper: {method} wipe for {remote_path}')
    if not quiet:
        session.print(_SSD_CAVEAT, 'yellow')
    session._handler._flush_shell(session._client_sock, timeout=3.0 if quiet else 1.0)

    if session.is_windows:
        win_ps = _build_windows_wiper(remote_path, method)
        unix_cmd = 'true'
    else:
        unix_cmd = _build_linux_wiper(remote_path, method)
        win_ps = ''

    raw = session.run_marked(
        unix_cmd,
        win_ps,
        timeout=_METHOD_TIMEOUTS.get(method, 120.0),
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        if not quiet:
            session.print("Plugin 'wiper' failed — no response from target.", 'red')
        session.log_plugin_result('wiper', '', f'no response for {remote_path}')
        return (1, None) if return_result else 1

    data = parse_collector_json(raw)
    if not data:
        if not quiet:
            session.print("Plugin 'wiper' failed — could not parse results.", 'red')
            session.print(f'Raw snippet: {raw[:500]}', 'yellow')
        session.log_plugin_result('wiper', raw[:4000], 'parse error')
        return (1, None) if return_result else 1

    if data.get('error'):
        if not quiet:
            session.print(f"Plugin 'wiper' error: {data['error']}", 'red')
            if data.get('fallback_error'):
                session.print(f"Fallback delete error: {data['fallback_error']}", 'red')
        report = format_wiper_report(data)
        if not quiet:
            session.print(report, 'cyan')
        session.log_plugin_result('wiper', report, json.dumps(data, indent=2))
        return (1, data) if return_result else 1

    report = format_wiper_report(data)
    if not quiet:
        session.print(report, 'cyan')
    session.log_plugin_result('wiper', report, json.dumps(data, indent=2))
    session.log_command(f'run wiper {remote_path} method={method}', report)
    return (0, data) if return_result else 0
