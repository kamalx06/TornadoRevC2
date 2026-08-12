"""Windows certificate store enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$certs=@()
$stores='My','Root','CA','TrustedPublisher','AuthRoot','Remote Desktop'
foreach($store in $stores){{
  Get-ChildItem Cert:\\LocalMachine\\$store -EA 0|ForEach-Object{{
    $certs+=@{{store=$store;subject=$_.Subject;issuer=$_.Issuer;thumb=$_.Thumbprint;notafter=$_.NotAfter.ToString('s');eku=($_.Extensions|? Oid -match 'Enhanced Key Usage'|ForEach-Object EnhancedKeyUsageList)-join ','}}
  }}
}}
$codesign=$certs|Where-Object{{$_.eku -match 'Code Signing' -or $_.subject -match 'Code Signing'}}
$enterprise=$certs|Where-Object{{$_.issuer -match 'Enterprise|Corp|ADCS|CA'}}
$result=[ordered]@{{
  summary=@{{total=$certs.Count;code_signing=$codesign.Count;enterprise=$enterprise.Count}}
  certificates=($certs|Select-Object -First 80)
  code_signing=($codesign|Select-Object -First 30)
  enterprise_certs=($enterprise|Select-Object -First 30)
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='certificates', platforms=['windows'], description='Enumerate certificate stores, code-signing, and enterprise certificates')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'certificates', None, build_command, format_generic_report, timeout=35.0)
