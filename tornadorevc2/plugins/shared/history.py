"""Cross-platform shell and command history enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import json, os, glob, subprocess
def _scrub(s):
    if not s:
        return s
    return s.replace('__T_PLUGIN_START__', '').replace('__T_PLUGIN_END__', '')
hist_files = []
candidates = [
    os.path.expanduser('~/.bash_history'), os.path.expanduser('~/.zsh_history'),
    os.path.expanduser('~/.sh_history'), os.path.expanduser('~/.history'),
    '/root/.bash_history', '/root/.zsh_history',
]
for p in glob.glob('/home/*/.bash_history') + glob.glob('/home/*/.zsh_history'):
    candidates.append(p)
for p in candidates:
    if os.path.isfile(p) and os.access(p, os.R_OK):
        try:
            with open(p, 'r', errors='ignore') as f:
                lines = f.readlines()[-40:]
            hist_files.append({'path': p, 'recent': [_scrub(l.strip()[:200]) for l in lines if l.strip()]})
        except Exception:
            pass
pkg_hist = []
for p in ('/var/log/apt/history.log', '/var/log/dnf.log', '/var/log/yum.log'):
    if os.path.isfile(p):
        try:
            with open(p, 'r', errors='ignore') as f:
                pkg_hist.append({'path': p, 'tail': f.readlines()[-15:]})
        except Exception:
            pass
try:
    out = subprocess.check_output(['last', '-n', '15'], stderr=subprocess.STDOUT, timeout=5)
    last = out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
except Exception:
    last = ''
result = {
    'summary': {'history_files': len(hist_files), 'package_logs': len(pkg_hist)},
    'shell_history': hist_files[:20],
    'package_manager_history': [{'path': x['path'], 'recent': [_scrub(l.strip()[:160]) for l in x['tail']]} for x in pkg_hist],
    'recent_logins': [_scrub(l) for l in (last.splitlines()[:15] if last else [])],
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$histFiles=@()
foreach($p in @(
  (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Path $env:ProgramData 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Path $env:USERPROFILE '.python_history'),
  (Join-Path $env:USERPROFILE '.node_repl_history')
)){{
  if(Test-Path $p){{
    try{{
      $lines=Get-Content $p -Tail 40 -EA Stop
      $recent=@($lines|Where-Object{{$_.Trim()}}|ForEach-Object{{$_.Trim().Substring(0,[Math]::Min(200,$_.Trim().Length))}})
      if($recent.Count){{$histFiles+=@{{path=$p;recent=$recent}}}}
    }}catch{{}}
  }}
}}
try{{
  $cmdKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
  if(Test-Path $cmdKey){{
    $recent=@()
    Get-ItemProperty $cmdKey -EA 0|Get-Member -MemberType NoteProperty|Where-Object Name -notmatch '^PS'|ForEach-Object{{
      $v=(Get-ItemProperty $cmdKey -Name $_.Name -EA 0).($_.Name)
      if($v){{$recent+=($v -replace [char]0,'').Substring(0,[Math]::Min(200,$v.Length))}}
    }}
    if($recent.Count){{$histFiles+=@{{path=$cmdKey;recent=@($recent|Select-Object -Last 40)}}}}
  }}
}}catch{{}}
$pkgHist=@()
foreach($p in @('C:\Windows\Logs\CBS\CBS.log','C:\Windows\Logs\DISM\dism.log')){{
  if(Test-Path $p){{
    try{{
      $tail=Get-Content $p -Tail 15 -EA Stop
      $pkgHist+=@{{path=$p;recent=@($tail|ForEach-Object{{$_.Trim().Substring(0,[Math]::Min(160,$_.Trim().Length))}})}}
    }}catch{{}}
  }}
}}
$recentLogins=@()
try{{ quser 2>$null|ForEach-Object{{if($_.Trim()){{$recentLogins+=$_.Trim()}}}} }}catch{{}}
$result=[ordered]@{{
  summary=@{{history_files=$histFiles.Count;package_logs=$pkgHist.Count}}
  shell_history=$histFiles
  package_manager_history=$pkgHist
  recent_logins=@($recentLogins|Select-Object -First 15)
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='history',
    platforms=['linux', 'windows', 'unix'],
    description='Collect shell history, package/update logs, and recent login activity',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'history',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=25.0,
    )
