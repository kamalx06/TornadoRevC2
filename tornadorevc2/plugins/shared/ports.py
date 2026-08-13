"""Cross-platform listening ports, connections, and routing enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import re, subprocess
result = {'summary': {}, 'listening_ports': [], 'established_connections': [], 'routing': []}

def sh(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

# Listening ports with process info
listen = sh('ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null', 10)
listen_count = 0
for line in listen.splitlines():
    if 'LISTEN' in line or 'State' in line.lower() or line.startswith('Proto'):
        if 'LISTEN' in line or re.search(r'\d+\.\d+\.\d+\.\d+:\d+|\:\d+\s', line):
            listen_count += 1
            if len(result['listening_ports']) < 60:
                result['listening_ports'].append(line.strip()[:220])

# Established connections
est = sh('ss -tn state established 2>/dev/null || netstat -tn 2>/dev/null | grep ESTAB', 8)
for line in est.splitlines()[:50]:
    if line.strip() and not line.lower().startswith('state'):
        result['established_connections'].append(line.strip()[:220])

# Routing table
routes = sh('ip route show 2>/dev/null || route -n 2>/dev/null', 6)
for line in routes.splitlines()[:30]:
    if line.strip():
        result['routing'].append(line.strip()[:200])

result['summary'] = {
    'Listening Endpoints': listen_count,
    'Established (sample)': len(result['established_connections']),
    'Routes (sample)': len(result['routing']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$listening=@(); $established=@(); $routing=@()
try{{
  Get-NetTCPConnection -State Listen -EA 0|Select-Object -First 60 LocalAddress,LocalPort,OwningProcess,State|ForEach-Object{{
    $proc=''
    try{{ $proc=(Get-Process -Id $_.OwningProcess -EA 0).ProcessName }}catch{{}}
    $listening+=@{{address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;process=$proc;state=$_.State}}
  }}
}}catch{{}}
try{{
  Get-NetTCPConnection -State Established -EA 0|Select-Object -First 50 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State|ForEach-Object{{
    $proc=''
    try{{ $proc=(Get-Process -Id $_.OwningProcess -EA 0).ProcessName }}catch{{}}
    $established+=@{{local="$($_.LocalAddress):$($_.LocalPort)";remote="$($_.RemoteAddress):$($_.RemotePort)";pid=$_.OwningProcess;process=$proc}}
  }}
}}catch{{}}
try{{
  Get-NetRoute -EA 0|Select-Object -First 30 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric|ForEach-Object{{
    $routing+=@{{dest=$_.DestinationPrefix;next_hop=$_.NextHop;interface=$_.InterfaceAlias;metric=$_.RouteMetric}}
  }}
}}catch{{}}
$result=[ordered]@{{
  summary=@{{Listening=$listening.Count;Established=$established.Count;Routes=$routing.Count}}
  listening_ports=$listening
  established_connections=$established
  routing=$routing
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='ports',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate listening ports, established connections, processes, and routing',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'ports',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=45.0,
    )
