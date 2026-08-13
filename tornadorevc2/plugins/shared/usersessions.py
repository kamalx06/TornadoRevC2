"""Cross-platform user session enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import subprocess, os

def run_cmd(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

sessions = []
for cmd, stype in (
    ('who 2>/dev/null', 'who'),
    ('w -h 2>/dev/null', 'w'),
    ('users 2>/dev/null', 'users'),
):
    out = run_cmd(cmd)
    if out:
        for line in out.strip().splitlines()[:20]:
            sessions.append({'source': stype, 'line': line.strip()[:200]})

# loginctl sessions
loginctl = run_cmd('loginctl list-sessions --no-legend 2>/dev/null')
if loginctl:
    for line in loginctl.strip().splitlines()[:20]:
        parts = line.split()
        if parts:
            sessions.append({'source': 'loginctl', 'session_id': parts[0], 'user': parts[2] if len(parts) > 2 else '', 'seat': parts[3] if len(parts) > 3 else '', 'line': line.strip()[:200]})

# SSH connections
ssh = []
ss_out = run_cmd('ss -tn state established 2>/dev/null | grep :22')
if ss_out:
    for line in ss_out.strip().splitlines()[:15]:
        ssh.append(line.strip()[:200])
if not ssh:
    netstat = run_cmd('netstat -tn 2>/dev/null | grep :22 | grep ESTABLISHED')
    if netstat:
        ssh = [l.strip()[:200] for l in netstat.strip().splitlines()[:15]]

# last logins
last = run_cmd('last -n 15 2>/dev/null')
recent_logins = [l.strip()[:200] for l in last.strip().splitlines()[:15]] if last else []

# utmp via who -a
who_a = run_cmd('who -a 2>/dev/null')
utmp = [l.strip()[:200] for l in who_a.strip().splitlines()[:15]] if who_a else []

result = {
    'summary': {
        'active_sessions': len(sessions),
        'ssh_connections': len(ssh),
        'recent_logins': len(recent_logins),
    },
    'active_sessions': sessions[:30],
    'ssh_connections': ssh or ['N/A'],
    'recent_logins': recent_logins or ['N/A'],
    'utmp_details': utmp or ['N/A'],
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$sessions=@(); $rdp=@(); $services=@()

try{{
  quser 2>$null|Select-Object -Skip 1|ForEach-Object{{
    if($_.Trim()){{$sessions+=@{{source='quser';line=$_.Trim()}}}}
  }}
}}catch{{}}

try{{
  query session 2>$null|Select-Object -Skip 1|ForEach-Object{{
    if($_.Trim()){{$sessions+=@{{source='query_session';line=$_.Trim()}}}}
  }}
}}catch{{}}

try{{
  Get-CimInstance Win32_LogonSession -EA 0|ForEach-Object{{
    $sessions+=@{{source='logon_session';logon_id=$_.LogonId;auth=$_.AuthenticationPackage;type=$_.LogonType;start=$_.StartTime}}
  }}
}}catch{{}}

try{{
  Get-CimInstance Win32_LoggedOnUser -EA 0|ForEach-Object{{
    $u=Invoke-CimMethod -InputObject $_.Antecedent -MethodName Get -EA 0
    $s=Invoke-CimMethod -InputObject $_.Dependent -MethodName Get -EA 0
    if($u -and $s){{
      $sessions+=@{{source='logged_on_user';user=$u.Name;session=$s.Name}}
    }}
  }}
}}catch{{}}

try{{
  Get-CimInstance Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -EA 0|ForEach-Object{{
    $rdp+=@{{allow_ts=$_.AllowTSConnections;active_x=$_.ActiveDesktopEnabled}}
  }}
  Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA 0|ForEach-Object{{
    $rdp+=@{{fdeny_ts_connections=$_.fDenyTSConnections}}
  }}
}}catch{{}}

try{{
  Get-CimInstance Win32_Process -Filter "Name='services.exe'" -EA 0|ForEach-Object{{
    $services+=@{{note='services host';pid=$_.ProcessId}}
  }}
}}catch{{}}

$result=[ordered]@{{
  summary=@{{sessions=$sessions.Count;rdp_config=$rdp.Count}}
  active_sessions=@($sessions|Select-Object -First 40)
  rdp_configuration=$rdp
  service_context=$services
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='usersessions',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate active local, remote, SSH, RDP, console, and service sessions',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'usersessions',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=35.0,
    )
