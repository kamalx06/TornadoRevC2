from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_firewall_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os
import re
import subprocess

result = {
    'summary': {},
    'ufw': {},
    'firewalld': {},
    'nftables': {},
    'iptables': {},
    'ip6tables': {},
    'listening': {
        'tcp': [],
        'udp': [],
    },
    'network': {},
    'services': {},
    'other': [],
}


def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''


def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())


def service_state(name):
    if not which('systemctl'):
        return 'unknown'

    active = sh(
        f'systemctl is-active {name} 2>/dev/null',
        5
    ).strip()

    enabled = sh(
        f'systemctl is-enabled {name} 2>/dev/null',
        5
    ).strip()

    return {
        'active': active or 'unknown',
        'enabled': enabled or 'unknown',
    }


def parse_default_policy(output, chain):
    m = re.search(
        rf'^Chain\s+{re.escape(chain)}\s+\(policy\s+(\S+)',
        output,
        re.MULTILINE | re.IGNORECASE,
    )
    return m.group(1) if m else 'unknown'


def parse_iptables_table(command, table_name):
    if not which('iptables'):
        return {}

    output = sh(
        f'iptables -t {table_name} -L -n -v 2>/dev/null',
        8,
    )

    if not output.strip():
        return {}

    return {
        'lines': len(output.splitlines()),
        'default_policies': {
            'INPUT': parse_default_policy(output, 'INPUT'),
            'OUTPUT': parse_default_policy(output, 'OUTPUT'),
            'FORWARD': parse_default_policy(output, 'FORWARD'),
        },
        'sample': '\n'.join(output.splitlines()[:35]),
    }

for service in (
    'ufw',
    'firewalld',
    'nftables',
    'iptables',
):
    result['services'][service] = service_state(service)

if which('ufw'):
    st = sh('ufw status verbose 2>/dev/null', 8)
    numbered = sh('ufw status numbered 2>/dev/null', 8)

    status_line = 'unknown'
    if st:
        for line in st.splitlines():
            if line.strip().lower().startswith('status:'):
                status_line = line.strip()
                break

    result['ufw'] = {
        'available': 'yes',
        'status': status_line,
    }

    if st:
        result['ufw']['details'] = st[:4000]

    if numbered:
        result['ufw']['rules'] = '\n'.join(
            numbered.splitlines()[:80]
        )

if which('firewall-cmd'):
    state = sh(
        'firewall-cmd --state 2>/dev/null',
        8,
    ).strip()

    default = sh(
        'firewall-cmd --get-default-zone 2>/dev/null',
        8,
    ).strip()

    active_zones_raw = sh(
        'firewall-cmd --get-active-zones 2>/dev/null',
        8,
    )

    result['firewalld'] = {
        'available': 'yes',
        'state': state or 'unknown',
        'default_zone': default or 'unknown',
    }

    active_zones = []

    for line in active_zones_raw.splitlines():
        line = line.strip()

        if line and not line.startswith(('interfaces:', 'sources:')):
            if not line.startswith(' '):
                active_zones.append(line.split()[0])

    if active_zones:
        result['firewalld']['active_zones'] = active_zones

        zone_details = {}

        for zone in active_zones:
            details = sh(
                f'firewall-cmd --zone="{zone}" --list-all 2>/dev/null',
                8,
            )

            if details.strip():
                zone_details[zone] = details[:3000]

        if zone_details:
            result['firewalld']['active_zone_details'] = zone_details

if which('nft'):
    rules = sh(
        'nft list ruleset 2>/dev/null',
        10,
    )

    if rules.strip():
        nft = {
            'available': 'yes',
            'ruleset_lines': len(rules.splitlines()),
            'sample': '\n'.join(rules.splitlines()[:60]),
        }

        nft_json = sh(
            'nft -j list ruleset 2>/dev/null',
            10,
        )

        if nft_json.strip():
            nft['json_available'] = True
            nft['json_sample'] = nft_json[:6000]
        else:
            nft['json_available'] = False

        nft['tables'] = sorted(set(
            re.findall(
                r'^\s*table\s+(\S+)\s+(\S+)',
                rules,
                re.MULTILINE,
            )
        ))

        nft['chains'] = sorted(set(
            re.findall(
                r'^\s*chain\s+(\S+)',
                rules,
                re.MULTILINE,
            )
        ))

        result['nftables'] = nft

if which('iptables'):
    filter_rules = sh(
        'iptables -L -n -v 2>/dev/null',
        8,
    )

    if filter_rules.strip():
        result['iptables'] = {
            'available': 'yes',
            'tables': {},
            'default_policies': {
                'INPUT': parse_default_policy(filter_rules, 'INPUT'),
                'OUTPUT': parse_default_policy(filter_rules, 'OUTPUT'),
                'FORWARD': parse_default_policy(filter_rules, 'FORWARD'),
            },
            'policy_sample': '\n'.join(
                filter_rules.splitlines()[:35]
            ),
        }

        for table in ('nat', 'mangle', 'raw'):
            parsed = parse_iptables_table(
                'iptables',
                table,
            )
            if parsed:
                result['iptables']['tables'][table] = parsed

if which('ip6tables'):
    filter6 = sh(
        'ip6tables -L -n -v 2>/dev/null',
        8,
    )

    if filter6.strip():
        result['ip6tables'] = {
            'available': 'yes',
            'default_policies': {
                'INPUT': parse_default_policy(filter6, 'INPUT'),
                'OUTPUT': parse_default_policy(filter6, 'OUTPUT'),
                'FORWARD': parse_default_policy(filter6, 'FORWARD'),
            },
            'policy_sample': '\n'.join(
                filter6.splitlines()[:30]
            ),
            'tables': {},
        }

        for table in ('nat', 'mangle', 'raw'):
            out = sh(
                f'ip6tables -t {table} -L -n -v 2>/dev/null',
                8,
            )

            if out.strip():
                result['ip6tables']['tables'][table] = {
                    'lines': len(out.splitlines()),
                    'sample': '\n'.join(
                        out.splitlines()[:25]
                    ),
                }

if which('ss'):
    tcp = sh(
        'ss -lntup 2>/dev/null',
        8,
    )

    udp = sh(
        'ss -lnup 2>/dev/null',
        8,
    )

    def parse_ss(output, protocol):
        entries = []

        for line in output.splitlines():
            if not line.startswith(('tcp', 'udp')):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            local = parts[4]
            process = ' '.join(parts[6:]) if len(parts) > 6 else ''

            entries.append({
                'protocol': protocol,
                'local': local,
                'process': process[:500],
            })

        return entries

    result['listening']['tcp'] = parse_ss(tcp, 'tcp')
    result['listening']['udp'] = parse_ss(udp, 'udp')

if which('ip'):
    addr = sh(
        'ip -brief addr 2>/dev/null',
        8,
    )

    routes = sh(
        'ip route 2>/dev/null',
        8,
    )

    result['network'] = {
        'interfaces': addr[:5000],
        'routes': routes[:5000],
    }

for path in (
    '/etc/ufw/ufw.conf',
    '/etc/default/ufw',
    '/etc/firewalld/firewalld.conf',
    '/etc/nftables.conf',
):
    if os.path.isfile(path):
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()

            result['other'].append({
                'path': path,
                'content': content[:1500],
            })
        except Exception:
            pass

backends = []

ufw_status = result['ufw'].get('status', '').lower()
if 'active' in ufw_status:
    backends.append('ufw')

if result['firewalld'].get('state') == 'running':
    backends.append('firewalld')

if result.get('nftables'):
    backends.append('nftables')

if result.get('iptables'):
    backends.append('iptables')

default_inbound = 'unknown'
default_outbound = 'unknown'
default_forward = 'unknown'

for backend in (
    result.get('iptables', {}),
    result.get('ip6tables', {}),
):unknown
    policies = backend.get('default_policies', {})

    if default_inbound == 'unknown':
        default_inbound = policies.get('INPUT', 'unknown')

    if default_outbound == 'unknown':
        default_outbound = policies.get('OUTPUT', 'unknown')

    if default_forward == 'unknown':
        default_forward = policies.get('FORWARD', 'unknown')

result['summary'] = {
    'Platform': 'Linux/Unix',
    'Firewall_Backends': ', '.join(backends) if backends else 'none detected',
    'UFW': result['ufw'].get('status', 'N/A'),
    'firewalld': result['firewalld'].get('state', 'N/A'),
    'nftables': 'present' if result.get('nftables') else 'N/A',
    'iptables': 'present' if result.get('iptables') else 'N/A',
    'Default_Inbound': default_inbound,
    'Default_Outbound': default_outbound,
    'Default_Forward': default_forward,
    'Listening_TCP': len(result['listening']['tcp']),
    'Listening_UDP': len(result['listening']['udp']),
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
$rules=@()
$network=@{{}}

try{{
  $profiles=Get-NetFirewallProfile -EA 0

  foreach($p in $profiles){{
    $wdf[$p.Name]=@{{
      Enabled=$p.Enabled
      DefaultInbound=$p.DefaultInboundAction
      DefaultOutbound=$p.DefaultOutboundAction
      LogAllowed=$p.LogAllowed
      LogBlocked=$p.LogBlocked
      LogFileName=$p.LogFileName
      LogMaxSizeKilobytes=$p.LogMaxSizeKilobytes
      NotifyOnListen=$p.NotifyOnListen
    }}
  }}
}}catch{{}}

try{{
  Get-NetFirewallRule -Enabled True -EA 0 |
    Select-Object -First 40 |
    ForEach-Object{{
      $rule=$_

      $portFilter=$null
      $addressFilter=$null
      $appFilter=$null

      try{{
        $portFilter=$rule | Get-NetFirewallPortFilter -EA 0
      }}catch{{}}

      try{{
        $addressFilter=$rule | Get-NetFirewallAddressFilter -EA 0
      }}catch{{}}

      try{{
        $appFilter=$rule | Get-NetFirewallApplicationFilter -EA 0
      }}catch{{}}

      $rules+=@{{
        name=$rule.DisplayName
        direction=[string]$rule.Direction
        action=[string]$rule.Action
        profile=[string]$rule.Profile
        enabled=[string]$rule.Enabled
        protocol=if($portFilter){{[string]$portFilter.Protocol}}else{{''}}
        local_port=if($portFilter){{[string]$portFilter.LocalPort}}else{{''}}
        remote_port=if($portFilter){{[string]$portFilter.RemotePort}}else{{''}}
        local_address=if($addressFilter){{[string]$addressFilter.LocalAddress}}else{{''}}
        remote_address=if($addressFilter){{[string]$addressFilter.RemoteAddress}}else{{''}}
        program=if($appFilter){{[string]$appFilter.Program}}else{{''}}
      }}
    }}
}}catch{{}}

try{{
  Get-NetIPConfiguration -EA 0 |
    ForEach-Object{{
      $network[$_.InterfaceAlias]=@{{
        InterfaceIndex=$_.InterfaceIndex
        IPv4=if($_.IPv4Address){{($_.IPv4Address.IPAddress -join ', ')}}else{{''}}
        IPv6=if($_.IPv6Address){{($_.IPv6Address.IPAddress -join ', ')}}else{{''}}
        Gateway=if($_.IPv4DefaultGateway){{($_.IPv4DefaultGateway.NextHop -join ', ')}}else{{''}}
        DNSServers=if($_.DNSServer){{($_.DNSServer.ServerAddresses -join ', ')}}else{{''}}
      }}
    }}
}}catch{{}}

$netsh=netsh advfirewall show allprofiles 2>$null
$netshText=($netsh -join "`n")

if($netshText.Length -gt 3500){{
  $netshText=$netshText.Substring(0,3500)
}}

$enabledProfiles=(
  $wdf.GetEnumerator() |
  Where-Object{{ $_.Value.Enabled }} |
  ForEach-Object{{ $_.Name }}
)

$result=[ordered]@{{
  summary=@{{
    Profiles=($wdf.Keys -join ', ')
    Enabled_Profiles=($enabledProfiles -join ', ')
    Notable_Rules=$rules.Count
    Network_Interfaces=$network.Count
  }}

  windows_defender_firewall=$wdf
  notable_rules=$rules
  network=$network
  netsh_output=$netshText
}}

Write-Output ($start+(ConvertTo-Json $result -Depth 7 -Compress)+$end)
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
        timeout=70.0,
    )
