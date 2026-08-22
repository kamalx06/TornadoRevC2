"""Windows Active Directory and domain enumeration."""

from typing import Any, Dict, List

from ..api import plugin, SessionContext
from ..shared.common import format_list_section, format_section, format_table_section
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector


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


def format_adinfo_report(data: Dict[str, Any]) -> str:
    if data.get('ad_environment') is False:
        return data.get('message') or 'Windows is not in an Active Directory environment.'

    sections: List[str] = []

    summary = data.get('summary') or {}
    if summary:
        display = dict(summary)
        role = display.pop('domain_role', None)
        if role is not None:
            display['domain_role'] = f"{role} ({_domain_role_name(int(role))})"
        sections.append(format_section('Summary', display))

    membership = data.get('domain_membership') or {}
    if membership:
        display = dict(membership)
        role = display.get('domain_role')
        if role is not None and 'domain_role_name' not in display:
            display['domain_role'] = f"{role} ({_domain_role_name(int(role))})"
        sections.append(format_section('Domain Membership', display))
    else:
        sections.append('Domain Membership\n-----------------\nN/A')

    dcs = data.get('domain_controllers') or []
    if dcs and isinstance(dcs[0], dict):
        cols = [c for c in ('name', 'host', 'ip', 'site', 'line') if any(row.get(c) for row in dcs)]
        sections.append(format_table_section('Domain Controllers', dcs, cols or ['line']))
    else:
        sections.append('Domain Controllers\n------------------\nN/A')

    forest = data.get('forest')
    if isinstance(forest, dict) and forest:
        display = dict(forest)
        domains = display.pop('domains', None)
        if isinstance(domains, list) and domains:
            display['domains'] = domains
        sections.append(format_section('Forest', display))
    elif isinstance(forest, str) and forest:
        sections.append(format_section('Forest', {'name': forest}))
    else:
        sections.append('Forest\n------\nN/A')

    trusts = data.get('trusts') or []
    if trusts and isinstance(trusts[0], dict):
        cols = [c for c in ('name', 'dir', 'type', 'line') if any(row.get(c) for row in trusts)]
        sections.append(format_table_section('Trusts', trusts, cols or ['line']))
    elif trusts:
        sections.append(format_list_section('Trusts', [str(t) for t in trusts]))
    else:
        sections.append('Trusts\n------\nN/A')

    ous = data.get('organizational_units') or []
    if ous and isinstance(ous[0], dict):
        cols = [c for c in ('name', 'dn', 'line') if any(row.get(c) for row in ous)]
        sections.append(format_table_section('Organizational Units', ous, cols or ['line']))
    elif ous:
        sections.append(format_list_section('Organizational Units', [str(ou) for ou in ous]))
    else:
        sections.append('Organizational Units\n--------------------\nN/A')

    if not sections:
        return 'ADInfo: no data collected.'
    return '\n\n'.join(sections)


def build_command():
    body = r"""
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

function Invoke-AdEnum($scriptBlock){
  try { return & $scriptBlock } catch { return $null }
}

$cs = Get-CimInstance Win32_ComputerSystem -EA 0
$join = ($cs -and ($cs.PartOfDomain -eq $true))

if(-not $join){
  $result = [ordered]@{
    ad_environment = $false
    message = 'Windows is not in an Active Directory environment.'
  }
  $json = ($result | ConvertTo-Json -Compress)
} else {
  $domain = $cs.Domain
  $role = $cs.DomainRole
  $adModule = $false
  try { Import-Module ActiveDirectory -EA Stop; $adModule = $true } catch {}

  # Domain membership
  $membership = [ordered]@{
    domain = $domain
    part_of_domain = $true
    domain_role = $role
    domain_role_name = (Get-DomainRoleLabel $role)
    workgroup = $cs.Workgroup
    dns_hostname = $cs.DNSHostName
    logon_domain = $env:USERDOMAIN
    computer_name = $cs.Name
  }
  $domainInfo = Invoke-AdEnum {
    if(-not $adModule){ return $null }
    $d = Get-ADDomain -EA Stop
    [ordered]@{
      dns_root = $d.DNSRoot
      netbios = $d.NetBIOSName
      functional_level = $d.DomainMode
      pdce = $d.PDCEmulator
      rid_master = $d.RIDMaster
      infrastructure_master = $d.InfrastructureMaster
    }
  }
  if($domainInfo){ $membership['domain_details'] = $domainInfo }

  $dcName = Invoke-AdEnum {
    $r = nltest /dsgetdc:$domain 2>$null
    if($r){ ($r | Select-String -Pattern 'DC:\\\\.*' | Select-Object -First 1).ToString().Trim() }
  }
  if($dcName){ $membership['nearest_dc'] = $dcName }

  # Domain controller discovery
  $dcs = @()
  if($adModule){
    $fromAd = Invoke-AdEnum {
      Get-ADDomainController -Filter * -EA Stop |
        Select-Object Name, HostName, IPv4Address, Site, IsGlobalCatalog, OperatingSystem |
        ForEach-Object {
          [ordered]@{
            name = $_.Name
            host = $_.HostName
            ip = $_.IPv4Address
            site = $_.Site
            gc = $_.IsGlobalCatalog
            os = $_.OperatingSystem
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
        if($line -and ($line -match '\\')){ $rows += [ordered]@{ line = $line } }
      }
      if($rows.Count){ $rows }
    }
    if($fromNltest){ $dcs = @($fromNltest) }
  }

  # Forest enumeration
  $forest = $null
  if($adModule){
    $forest = Invoke-AdEnum {
      $f = Get-ADForest -EA Stop
      [ordered]@{
        name = $f.Name
        root_domain = $f.RootDomain
        forest_mode = $f.ForestMode
        schema_master = $f.SchemaMaster
        domain_naming_master = $f.DomainNamingMaster
        domains = @($f.Domains)
        global_catalogs = @($f.GlobalCatalogs | Select-Object -First 10)
      }
    }
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

  # Trust enumeration
  $trusts = @()
  if($adModule){
    $fromAd = Invoke-AdEnum {
      Get-ADTrust -Filter * -EA Stop |
        Select-Object Name, Direction, TrustType, DisallowTransivity, SelectiveAuthentication |
        ForEach-Object {
          [ordered]@{
            name = $_.Name
            dir = $_.Direction
            type = $_.TrustType
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

  # Organizational unit enumeration
  $ous = @()
  if($adModule){
    $fromAd = Invoke-AdEnum {
      Get-ADOrganizationalUnit -Filter * -EA Stop |
        Select-Object -First 30 Name, DistinguishedName |
        ForEach-Object {
          [ordered]@{
            name = $_.Name
            dn = $_.DistinguishedName
          }
        }
    }
    if($fromAd){ $ous = @($fromAd) }
  }
  if(-not $ous.Count){
    $fromDsquery = Invoke-AdEnum {
      $rows = @()
      dsquery ou -limit 30 2>$null | ForEach-Object {
        $line = $_.Trim()
        if($line){ $rows += [ordered]@{ dn = $line } }
      }
      if($rows.Count){ $rows }
    }
    if($fromDsquery){ $ous = @($fromDsquery) }
  }

  $result = [ordered]@{
    ad_environment = $true
    summary = [ordered]@{
      domain_joined = $true
      domain = $domain
      domain_role = $role
      dcs = $dcs.Count
      trusts = $trusts.Count
      ous = $ous.Count
    }
    domain_membership = $membership
    domain_controllers = $dcs
    forest = $forest
    trusts = $trusts
    organizational_units = $ous
  }
  $json = ($result | ConvertTo-Json -Depth 7 -Compress)
}
"""
    return wrap_ps_collector(body)


@plugin.command(
    name='adinfo',
    platforms=['windows'],
    description='Enumerate domain membership, DCs, trusts, and AD environment details',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'adinfo',
        None,
        build_command,
        format_adinfo_report,
        timeout=70.0,
    )