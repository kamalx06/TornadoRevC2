"""Cross-platform Kerberos ticket enumeration – full metadata (no secrets)."""

import os
import re
from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os, subprocess, glob, re, stat, pwd, time
from datetime import datetime, timezone

result = {
    'env': {},
    'config_files': [],
    'cache_files': [],
    'keytab_files': [],
    'klist_details': {
        'default_principal': None,
        'realm': None,
        'tickets': [],
        'tgt': None,
        'cache_type': None,
    },
    'summary': {}
}

def sh(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

def parse_krb_timestamp(ts_str):
    """Convert 'MM/DD/YY HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS' to ISO."""
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    for fmt in ('%m/%d/%y %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return ts_str

def get_file_metadata(path):
    try:
        s = os.stat(path)
        mode = oct(s.st_mode)[-3:]
        return {
            'path': path,
            'size': s.st_size,
            'uid': s.st_uid,
            'gid': s.st_gid,
            'mode': mode,
            'mtime': datetime.fromtimestamp(s.st_mtime, tz=timezone.utc).isoformat()
        }
    except Exception:
        return {'path': path}

for var in ['KRB5CCNAME', 'KRB5_CONFIG', 'KRB5_CLIENT_KTNAME', 'KRB5_KTNAME']:
    val = os.environ.get(var)
    if val:
        result['env'][var] = val

for conf in ['/etc/krb5.conf', '/etc/krb5/krb5.conf'] + glob.glob(os.path.expanduser('~/.krb5.conf')):
    if os.path.isfile(conf):
        result['config_files'].append(get_file_metadata(conf))

keytab_paths = ['/etc/krb5.keytab'] + glob.glob(os.path.expanduser('~/*.keytab')) + glob.glob('/etc/*.keytab')
for kt in keytab_paths:
    if os.path.isfile(kt):
        result['keytab_files'].append(get_file_metadata(kt))

cache_type = None
cache_paths = []
env_cc = result['env'].get('KRB5CCNAME', '')

if env_cc:
    if env_cc.startswith('FILE:'):
        cache_paths.append(env_cc[5:])
        cache_type = 'FILE'
    elif env_cc.startswith('DIR:'):
        cache_paths.extend(glob.glob(os.path.join(env_cc[4:], 'krb5cc_*')))
        cache_type = 'DIR'
    elif env_cc.startswith('KEYRING:'):
        cache_type = 'KEYRING'
    elif env_cc.startswith('MEMORY:'):
        cache_type = 'MEMORY'
    else:
        cache_paths.append(env_cc)

cache_paths.extend(glob.glob('/tmp/krb5cc_*'))
cache_paths.extend(glob.glob('/run/user/*/krb5cc*'))
cache_paths.extend(glob.glob('/var/run/user/*/krb5cc*'))
cache_paths = list(set(cache_paths))

for cp in cache_paths:
    if os.path.isfile(cp):
        result['cache_files'].append(get_file_metadata(cp))

result['klist_details']['cache_type'] = cache_type or ('FILE' if result['cache_files'] else 'unknown')

if which('klist'):
    out = sh('klist -A -f -e -a -s 2>/dev/null', timeout=10)
    if out:
        lines = out.splitlines()
        principal = None
        realm = None
        tickets = []
        current_ticket = {}
        p_re = re.compile(r'Default principal:\s+([^\s]+)')
        for line in lines:
            if not line.strip():
                continue
            m = p_re.search(line)
            if m:
                principal = m.group(1)
                if '@' in principal:
                    realm = principal.split('@')[-1]
                continue
            parts = line.split()
            if len(parts) >= 4 and re.match(r'\d{2}/\d{2}/\d{2}', parts[0]):
                start = parse_krb_timestamp(parts[0] + ' ' + parts[1])
                end = parse_krb_timestamp(parts[2] + ' ' + parts[3])
                service = ' '.join(parts[4:-1]) if len(parts) > 5 else parts[4]
                flags_str = parts[-1] if parts[-1].startswith('(') and parts[-1].endswith(')') else ''
                ticket = {
                    'service': service,
                    'start_time': start,
                    'end_time': end,
                    'flags': flags_str.strip('()'),
                }
                if service.startswith('krbtgt/'):
                    result['klist_details']['tgt'] = ticket
                else:
                    tickets.append(ticket)
            elif 'Ticket server:' in line:
                service = line.split('Ticket server:')[-1].strip()
                tickets.append({'service': service, 'start_time': None, 'end_time': None})
            elif 'Etype:' in line and current_ticket:
                etype = line.split('Etype:')[-1].strip()
                if current_ticket:
                    current_ticket['encryption'] = etype
                    current_ticket = {}
        if cache_type == 'KEYRING':
            kr_out = sh('klist -5 -l 2>/dev/null', timeout=5)
            if kr_out:
                result['klist_details']['keyring_output'] = kr_out[:1000]

        result['klist_details']['default_principal'] = principal
        result['klist_details']['realm'] = realm
        result['klist_details']['tickets'] = tickets[:100]

result['summary'] = {
    'cache_type': result['klist_details']['cache_type'],
    'default_principal': result['klist_details']['default_principal'],
    'realm': result['klist_details']['realm'],
    'ticket_count': len(result['klist_details']['tickets']),
    'has_tgt': bool(result['klist_details']['tgt']),
    'config_files_found': len(result['config_files']),
    'cache_files_found': len(result['cache_files']),
    'keytab_files_found': len(result['keytab_files']),
    'env_vars_set': len(result['env']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'

$result = @{{
    env = @{{}}
    config_registry = @()
    cache_files = @()
    keytab_files = @()
    klist_details = @{{
        default_principal = $null
        realm = $null
        tickets = @()
        tgt = $null
        sessions = @()
        cache_type = $null
    }}
    summary = @{{}}
}}

foreach ($var in @('KRB5CCNAME','KRB5_CONFIG','KRB5_CLIENT_KTNAME','KRB5_KTNAME')) {{
    $val = [Environment]::GetEnvironmentVariable($var)
    if ($val) {{ $result.env[$var] = $val }}
}}

$regPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos"
)
foreach ($rp in $regPaths) {{
    if (Test-Path $rp) {{
        try {{
            $props = Get-ItemProperty -Path $rp -EA 0
            $entry = @{{ path = $rp; properties = @{{}} }}
            foreach ($prop in $props.PSObject.Properties) {{
                if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {{
                    $entry.properties[$prop.Name] = $prop.Value
                }}
            }}
            $result.config_registry += $entry
        }} catch {{}}
    }}
}}

$cacheDirs = @(
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Local\Kerberos",
    "$env:USERPROFILE\AppData\Roaming\Kerberos"
)
foreach ($dir in $cacheDirs) {{
    if (Test-Path $dir) {{
        Get-ChildItem -Path $dir -Filter "krb5cc*" -File -EA 0 | ForEach-Object {{
            $result.cache_files += @{{
                path = $_.FullName
                size = $_.Length
                last_write = $_.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }}
        }}
    }}
}}

$ktDirs = @("$env:USERPROFILE", "$env:ProgramData")
foreach ($dir in $ktDirs) {{
    if (Test-Path $dir) {{
        Get-ChildItem -Path $dir -Filter "*.keytab" -File -EA 0 | ForEach-Object {{
            $result.keytab_files += @{{
                path = $_.FullName
                size = $_.Length
                last_write = $_.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }}
        }}
    }}
}}

$klistCmd = Get-Command klist -EA 0
if ($klistCmd) {{
    $outTickets = klist tickets /v /f /e 2>&1 | Out-String
    $outTGT = klist tgt 2>&1 | Out-String
    $outSessions = klist sessions 2>&1 | Out-String

    $result.klist_details.cache_type = "MSLSA"

    $clientMatch = [regex]::Match($outTickets, "Client:\s*(.+)`r?`n")
    if ($clientMatch.Success) {{
        $principal = $clientMatch.Groups[1].Value.Trim()
        $result.klist_details.default_principal = $principal
        if ($principal -match "@(.+)") {{
            $result.klist_details.realm = $matches[1]
        }}
    }}

    $lines = $outTickets -split "`r?`n"
    $currentTicket = $null
    for ($i=0; $i -lt $lines.Count; $i++) {{
        $line = $lines[$i]
        if ($line -match "Server:\s*(.+)") {{
            $currentTicket = @{{ service = $matches[1].Trim() }}
        }}
        if ($line -match "Start Time:\s*(.+)") {{
            if ($currentTicket) {{ $currentTicket.start_time = $matches[1].Trim() }}
        }}
        if ($line -match "End Time:\s*(.+)") {{
            if ($currentTicket) {{ $currentTicket.end_time = $matches[1].Trim() }}
        }}
        if ($line -match "Ticket Flags:\s*(.+)") {{
            if ($currentTicket) {{ $currentTicket.flags = $matches[1].Trim() }}
        }}
        if ($line -match "Encryption:\s*(.+)") {{
            if ($currentTicket) {{ $currentTicket.encryption = $matches[1].Trim() }}
        }}
        if (-not $line.Trim() -or ($line -match "Server:" -and $currentTicket)) {{
            if ($currentTicket -and $currentTicket.service) {{
                if ($currentTicket.service -match "^krbtgt/") {{
                    $result.klist_details.tgt = $currentTicket
                }} else {{
                    $result.klist_details.tickets += $currentTicket
                }}
            }}
            $currentTicket = $null
        }}
    }}
    if ($currentTicket -and $currentTicket.service) {{
        if ($currentTicket.service -match "^krbtgt/") {{
            $result.klist_details.tgt = $currentTicket
        }} else {{
            $result.klist_details.tickets += $currentTicket
        }}
    }}

    $sessLines = $outSessions -split "`r?`n"
    foreach ($sl in $sessLines) {{
        if ($sl -match "User:\s*(.+)") {{
            $result.klist_details.sessions += @{{ user = $matches[1].Trim() }}
        }}
    }}

    $result.klist_details.raw_tickets = $outTickets.Substring(0, [Math]::Min($outTickets.Length, 1500))
    $result.klist_details.raw_tgt = $outTGT.Substring(0, [Math]::Min($outTGT.Length, 1500))

}} else {{
    $result.klist_details.cache_type = "unknown (klist not found)"
}}

$result.summary = @{{
    cache_type = $result.klist_details.cache_type
    default_principal = $result.klist_details.default_principal
    realm = $result.klist_details.realm
    ticket_count = $result.klist_details.tickets.Count
    has_tgt = [bool]($result.klist_details.tgt)
    config_registry_entries = $result.config_registry.Count
    cache_files_found = $result.cache_files.Count
    keytab_files_found = $result.keytab_files.Count
    env_vars_set = $result.env.Keys.Count
}}

Write-Output ($start+(ConvertTo-Json $result -Depth 8 -Compress)+$end)
"""


@plugin.command(
    name='kerberosenum',
    platforms=['linux', 'windows', 'unix'],
    description='Detailed Kerberos ticket enumeration – caches, principals, tickets, encryption, flags (metadata only)',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'kerberosenum',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=75.0,
    )