from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def _build_windows_command() -> str:
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'

$domain_info = [ordered]@{{
    is_domain_joined = $false
    domain = ''
    forest = ''
    computer = $env:COMPUTERNAME
}}

$trusts = @()
$local_admins = @()
$foreign_principals = @()
$notes = @()

# --- Domain join state ---
try {{
    $cs = Get-CimInstance Win32_ComputerSystem -EA 0
    if ($cs -and $cs.PartOfDomain -and $cs.Domain) {{
        $domain_info.is_domain_joined = $true
        $domain_info.domain = "$($cs.Domain)"
    }}
}} catch {{}}

# --- Trust enumeration via Get-ADTrust (RSAT) ---
$rsat_present = $false
try {{
    Import-Module ActiveDirectory -EA Stop
    $rsat_present = $true
}} catch {{}}

if ($domain_info.is_domain_joined -and $rsat_present) {{
    try {{
        foreach ($t in (Get-ADTrust -Filter * -EA 0)) {{
            $trusts += [ordered]@{{
                target = "$($t.Target)"
                direction = "$($t.Direction)"
                type = "$($t.TrustType)"
                transitive = [bool]$t.Transitive
                sid_filtering = [bool]$t.SIDFilteringQuarantined
                selective_auth = [bool]$t.SelectiveAuthentication
                forest_transitive = [bool]$t.ForestTransitive
                source = 'Get-ADTrust'
            }}
        }}
        if ($trusts.Count -eq 0) {{
            $notes += 'Get-ADTrust returned no trusts — this is unusual for a domain-joined machine'
        }}
    }} catch {{
        $notes += "Get-ADTrust failed: $($_.Exception.Message)"
    }}
}}

# --- Fallback: nltest ---
if ($domain_info.is_domain_joined -and $trusts.Count -eq 0) {{
    try {{
        $nltest = nltest /domain_trusts /all_trusts /v 2>&1
        $current = $null
        foreach ($line in $nltest) {{
            $line_s = "$line".Trim()
            if ($line_s -match '^\d+:\s+(\S+)\s+\((\S+)\)') {{
                if ($current) {{ $trusts += $current }}
                $current = [ordered]@{{
                    target = $matches[1]
                    direction = $matches[2]
                    type = 'unknown'
                    transitive = $true
                    sid_filtering = $null
                    selective_auth = $null
                    forest_transitive = $null
                    source = 'nltest'
                }}
            }} elseif ($current) {{
                if ($line_s -match 'Trust type:\s+(.+)') {{ $current.type = $matches[1].Trim() }}
                elseif ($line_s -match 'Direction:\s+(.+)') {{ $current.direction = $matches[1].Trim() }}
                elseif ($line_s -match 'SID filtering:\s+(.+)') {{ $current.sid_filtering = $matches[1].Trim() }}
                elseif ($line_s -match 'Forest transitive:\s+(.+)') {{ $current.forest_transitive = $matches[1].Trim() }}
            }}
        }}
        if ($current) {{ $trusts += $current }}
    }} catch {{
        $notes += "nltest failed: $($_.Exception.Message)"
    }}
}}

# --- Forest name via .NET ---
if ($domain_info.is_domain_joined) {{
    try {{
        Add-Type -AssemblyName System.DirectoryServices -EA 0
        $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        if ($d) {{
            $domain_info.forest = "$($d.Forest.Name)"
            if (-not $domain_info.domain) {{ $domain_info.domain = "$($d.Name)" }}
        }}
    }} catch {{}}
}}

# --- Local Administrators group membership ---
try {{
    foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -EA 0)) {{
        $entry = [ordered]@{{
            name = "$($m.Name)"
            object_class = "$($m.ObjectClass)"
            source = 'Get-LocalGroupMember'
        }}
        $local_admins += $entry
        if ($m.Name -match '\\') {{
            $foreign_principals += $entry
        }}
    }}
}} catch {{
    # Fallback to net localgroup
    try {{
        $out = net localgroup Administrators 2>&1
        foreach ($line in $out) {{
            $l = "$line".Trim()
            if ($l -and $l -notmatch '^(Alias name|Comment|Members|----|The command)') {{
                $entry = [ordered]@{{
                    name = $l
                    object_class = 'unknown'
                    source = 'net localgroup'
                }}
                $local_admins += $entry
                if ($l -match '\\') {{ $foreign_principals += $entry }}
            }}
        }}
    }} catch {{}}
}}

# --- Current user's SID history (best effort) ---
$sid_history = @()
try {{
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    foreach ($g in $id.Groups) {{
        try {{
            $nt = $g.Translate([System.Security.Principal.NTAccount])
            $name = "$($nt.Value)"
            if ($name -match '\\') {{
                $sid_history += [ordered]@{{
                    sid = "$($g.Value)"
                    name = $name
                    scope = 'group membership'
                }}
            }}
        }} catch {{}}
    }}
}} catch {{}}

# --- Netdom fallback for trust directions ---
if ($domain_info.is_domain_joined -and $trusts.Count -gt 0) {{
    foreach ($t in $trusts) {{
        if ($t.sid_filtering -eq $null) {{
            try {{
                $tgt = $t.target
                $nd = netdom trust $tgt /domain:$($domain_info.domain) /quarantine 2>&1
                foreach ($line in $nd) {{
                    $l = "$line".Trim()
                    if ($l -match 'Quarantine:\s+(.+)') {{
                        $t.sid_filtering = $matches[1].Trim()
                        break
                    }}
                }}
            }} catch {{}}
        }}
    }}
}}

# --- Analysis notes ---
if (-not $domain_info.is_domain_joined) {{
    $notes += 'Host is not domain-joined — trust enumeration not applicable'
}} else {{
    foreach ($t in $trusts) {{
        $dir = "$($t.direction)".ToLower()
        if ($dir -match 'outbound|bidirectional' -and -not $t.sid_filtering) {{
            $notes += "Trust to $($t.target) is $($t.direction) with SID filtering not enforced — SID history injection may be possible"
        }}
        if ($t.type -and $t.type -match 'forest' -and $t.forest_transitive) {{
            $notes += "Forest-transitive trust to $($t.target) — lateral movement to that forest may be viable"
        }}
    }}
    if ($foreign_principals.Count -gt 0) {{
        $notes += "Local Administrators contains $($foreign_principals.Count) principal(s) from outside this domain"
    }}
}}

$result = [ordered]@{{
    summary = @{{
        is_domain_joined = $domain_info.is_domain_joined
        domain = $domain_info.domain
        forest = $domain_info.forest
        trusts_found = $trusts.Count
        local_admin_count = $local_admins.Count
        foreign_principals = $foreign_principals.Count
        sid_history_entries = $sid_history.Count
        rsat_present = $rsat_present
        notes = $notes.Count
    }}
    domain_info = $domain_info
    trusts = $trusts
    local_administrators = $local_admins
    foreign_principals = $foreign_principals
    sid_history = $sid_history
    analysis = $notes
}}
Write-Output ($s + (ConvertTo-Json $result -Depth 6 -Compress) + $e)
"""


@plugin.command(
    name='trusts',
    platforms=['windows'],
    description='Domain trust relationships, foreign principals, SID history, and analysis',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'trusts',
        None,
        _build_windows_command,
        format_generic_report,
        timeout=60.0,
    )