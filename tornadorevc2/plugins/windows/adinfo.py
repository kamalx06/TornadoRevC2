"""Windows Active Directory and domain enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$cs=Get-CimInstance Win32_ComputerSystem -EA 0
$domain=$cs.Domain; $join=$cs.PartOfDomain; $role=$cs.DomainRole
$dcs=@(); $trusts=@(); $ous=@()
try{{Import-Module ActiveDirectory -EA 0; $dcs=Get-ADDomainController -Filter * -EA 0|Select-Object Name,HostName,IPv4Address,Site|ForEach-Object{{@{{name=$_.Name;host=$_.HostName;ip=$_.IPv4Address;site=$_.Site}}}}}}catch{{}}
if(-not $dcs.Count){{try{{nltest /dclist:$domain 2>$null|ForEach-Object{{if($_ -match '\\\\'){{$dcs+=@{{line=$_.Trim()}}}}}}catch{{}}}}
try{{$trusts=Get-ADTrust -Filter * -EA 0|Select-Object Name,Direction,TrustType|ForEach-Object{{@{{name=$_.Name;dir=$_.Direction;type=$_.TrustType}}}}}}catch{{}}
try{{$ous=Get-ADOrganizationalUnit -Filter * -EA 0|Select-Object -First 30 Name,DistinguishedName|ForEach-Object{{@{{name=$_.Name;dn=$_.DistinguishedName}}}}}}catch{{}}
$forest=''; try{{$forest=(Get-ADForest -EA 0).Name}}catch{{}}
$result=[ordered]@{{
  summary=@{{domain_joined=$join;domain=$domain;role=$role;dcs=$dcs.Count;trusts=$trusts.Count;ous=$ous.Count}}
  computer_system=@{{domain=$domain;part_of_domain=$join;domain_role=$role;workgroup=$cs.Workgroup;dns=$cs.DNSHostName}}
  domain_controllers=$dcs
  forest=$forest
  trusts=$trusts
  organizational_units=$ous
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


@plugin.command(name='adinfo', platforms=['windows'], description='Enumerate domain membership, DCs, trusts, and AD environment details')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'adinfo', None, build_command, format_generic_report, timeout=35.0)
