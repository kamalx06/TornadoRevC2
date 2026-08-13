"""Cross-platform VPN client and connection enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import glob, os, subprocess
result = {'summary': {}, 'clients': [], 'connections': [], 'adapters': [], 'configs': []}

def sh(cmd, timeout=6):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

for name in ('openvpn', 'wireguard', 'wg', 'openconnect', 'strongswan', 'ipsec', 'nmcli', 'expressvpn', 'nordvpn'):
    if which(name):
        result['clients'].append({'name': name, 'installed': 'yes'})

# NetworkManager VPN connections
if which('nmcli'):
    conns = sh('nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null')
    for line in conns.splitlines():
        parts = line.split(':')
        if len(parts) >= 2 and 'vpn' in parts[1].lower():
            result['connections'].append({'name': parts[0], 'type': parts[1], 'device': parts[2] if len(parts) > 2 else ''})
    all_vpn = sh('nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep -i vpn')
    for line in all_vpn.splitlines()[:20]:
        result['connections'].append({'configured': line.strip()})

# WireGuard
if which('wg'):
    wg = sh('wg show all 2>/dev/null', 6)
    if wg.strip():
        result['connections'].append({'type': 'wireguard', 'status': wg[:2000]})

# OpenVPN status
if which('openvpn'):
    result['clients'].append({'name': 'openvpn', 'configs_found': len(glob.glob('/etc/openvpn/**/*.conf', recursive=True))})

# TUN/TAP adapters
tun = sh('ip -o link show type tun 2>/dev/null; ip -o link show type tap 2>/dev/null')
for line in tun.splitlines():
    if line.strip():
        result['adapters'].append(line.strip()[:200])

# Config metadata (paths only)
for pattern in (
    '/etc/openvpn/*.conf', '/etc/wireguard/*.conf',
    os.path.expanduser('~/.config/openvpn/*'),
    os.path.expanduser('~/.vpn/*'),
):
    for path in glob.glob(pattern):
        if os.path.isfile(path):
            result['configs'].append({'path': path, 'size': os.path.getsize(path)})

result['summary'] = {
    'Clients Detected': len(result['clients']),
    'Active Connections': len(result['connections']),
    'TUN/TAP Adapters': len(result['adapters']),
    'Config Files': len(result['configs']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$clients=@(); $connections=@(); $adapters=@(); $configs=@()
foreach($svc in @('RasMan','OpenVPNService','WireGuardTunnel$*','NordVPN','ExpressVPNService')){{
  $s=Get-Service -Name $svc -EA 0
  if($s){{ $clients+=@{{name=$svc;status=$s.Status}} }}
}}
try{{
  Get-VpnConnection -EA 0|ForEach-Object{{
    $connections+=@{{name=$_.Name;server=$_.ServerAddress;status=$_.ConnectionStatus;protocol=$_.TunnelType}}
  }}
}}catch{{}}
Get-NetAdapter -EA 0|Where-Object{{$_.InterfaceDescription -match 'VPN|TAP|TUN|WireGuard|OpenVPN|Cisco|AnyConnect|PANGP'}}|ForEach-Object{{
  $adapters+=@{{name=$_.Name;desc=$_.InterfaceDescription;status=$_.Status}}
}}
$paths=@(
  "$env:USERPROFILE\OpenVPN\config",
  "$env:ProgramData\OpenVPN\config",
  "$env:ProgramFiles\OpenVPN\config",
  "$env:USERPROFILE\AppData\Local\WireGuard"
)
foreach($p in $paths){{
  if(Test-Path $p){{
    Get-ChildItem $p -Recurse -File -EA 0|Select-Object -First 20|ForEach-Object{{
      $configs+=@{{path=$_.FullName;size=$_.Length}}
    }}
  }}
}}
try{{
  Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -EA 0|Out-Null
}}catch{{}}
$result=[ordered]@{{
  summary=@{{Clients=$clients.Count;Connections=$connections.Count;Adapters=$adapters.Count;Configs=$configs.Count}}
  clients=$clients
  connections=$connections
  adapters=$adapters
  configs=$configs
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='vpn',
    platforms=['linux', 'windows', 'unix'],
    description='Detect VPN clients, active connections, adapters, and configuration metadata',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'vpn',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=45.0,
    )
