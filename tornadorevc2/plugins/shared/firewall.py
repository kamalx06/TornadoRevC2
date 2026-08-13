"""Cross-platform firewall enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_firewall_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os, re, subprocess
result = {'summary': {}, 'ufw': {}, 'firewalld': {}, 'nftables': {}, 'iptables': {}, 'ip6tables': {}, 'other': []}

def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

active = []
if which('ufw'):
    st = sh('ufw status verbose 2>/dev/null', 8)
    result['ufw'] = {'available': 'yes', 'status': st.splitlines()[0].strip() if st else 'unknown'}
    if st:
        result['ufw']['details'] = st[:3000]
        if 'active' in st.lower():
            active.append('ufw')
if which('firewall-cmd'):
    st = sh('firewall-cmd --state 2>/dev/null').strip()
    zones = sh('firewall-cmd --get-active-zones 2>/dev/null', 8)
    default = sh('firewall-cmd --get-default-zone 2>/dev/null').strip()
    result['firewalld'] = {'available': 'yes', 'state': st or 'N/A', 'default_zone': default or 'N/A'}
    if zones:
        result['firewalld']['active_zones'] = zones[:2000]
        if st == 'running':
            active.append('firewalld')
if which('nft'):
    rules = sh('nft list ruleset 2>/dev/null', 10)
    if rules.strip():
        result['nftables'] = {'available': 'yes', 'ruleset_lines': len(rules.splitlines())}
        result['nftables']['sample'] = '\n'.join(rules.splitlines()[:40])
        active.append('nftables')
if which('iptables'):
    pol = sh('iptables -L -n -v 2>/dev/null', 8)
    if pol.strip():
        result['iptables'] = {'available': 'yes', 'policy_sample': '\n'.join(pol.splitlines()[:35])}
        active.append('iptables')
if which('ip6tables'):
    pol6 = sh('ip6tables -L -n -v 2>/dev/null', 8)
    if pol6.strip():
        result['ip6tables'] = {'available': 'yes', 'policy_sample': '\n'.join(pol6.splitlines()[:25])}
for path in ('/etc/ufw/ufw.conf', '/etc/firewalld/firewalld.conf', '/etc/nftables.conf'):
    if os.path.isfile(path):
        try:
            with open(path, 'r', errors='ignore') as f:
                result['other'].append(f'{path}: ' + f.read()[:400].replace('\n', '; '))
        except Exception:
            pass
result['summary'] = {
    'Active Backends': ', '.join(active) if active else 'none detected',
    'UFW': result['ufw'].get('status', 'N/A'),
    'firewalld': result['firewalld'].get('state', 'N/A'),
    'nftables': 'present' if result.get('nftables') else 'N/A',
    'iptables': 'present' if result.get('iptables') else 'N/A',
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$wdf=@{{}}
try{{
  $profiles=Get-NetFirewallProfile -EA 0
  foreach($p in $profiles){{
    $wdf[$p.Name]=@{{Enabled=$p.Enabled;DefaultInbound=$p.DefaultInboundAction;DefaultOutbound=$p.DefaultOutboundAction}}
  }}
}}catch{{}}
$rules=@()
try{{
  Get-NetFirewallRule -Enabled True -EA 0|Select-Object -First 40 DisplayName,Direction,Action,Profile,Enabled|ForEach-Object{{
    $rules+=@{{name=$_.DisplayName;direction=$_.Direction;action=$_.Action;profile=$_.Profile}}
  }}
}}catch{{}}
$netsh=netsh advfirewall show allprofiles 2>$null
$result=[ordered]@{{
  summary=@{{
    Profiles=($wdf.Keys -join ', ')
    Enabled_Profiles=(($wdf.GetEnumerator()|Where-Object{{$_.Value.Enabled}}).Name -join ', ')
    Notable_Rules=$rules.Count
  }}
  windows_defender_firewall=$wdf
  notable_rules=$rules
  netsh_output=($netsh -join "`n").Substring(0,[Math]::Min(3500,($netsh -join "`n").Length))
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='firewall',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate firewall status, profiles/zones, policies, and notable rules',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'firewall',
        _build_linux_command,
        _build_windows_command,
        format_firewall_report,
        timeout=45.0,
    )
