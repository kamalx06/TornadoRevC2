"""Windows Defender and security product enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$def=@{{}}; $products=@(); $asr=@()
try{{
  $pref=Get-MpPreference -EA 0
  $status=Get-MpComputerStatus -EA 0
  $def=@{{realtime=$status.RealTimeProtectionEnabled;tamper=$status.IsTamperProtected;engine=$status.AMEngineVersion;defs=$status.AntivirusSignatureVersion;last=$status.AntivirusSignatureLastUpdated;cloud=$pref.MAPSReporting;exclusions=@($pref.ExclusionPath)+@($pref.ExclusionProcess)+@($pref.ExclusionExtension)}}
}}catch{{}}
try{{Get-MpThreatDetection -EA 0|Select-Object -First 15|ForEach-Object{{$products+=@{{threat=$_.ThreatName;time=$_.InitialDetectionTime;resources=$_.Resources}}}}}}catch{{}}
try{{Get-MpPreference -EA 0|Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -EA 0|ForEach-Object{{$asr+=$_}}}}catch{{}}
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA 0|ForEach-Object{{$products+=@{{name=$_.displayName;path=$_.pathToSignedProductExe;state=$_.productState}}}}
$result=[ordered]@{{
  summary=@{{defender_loaded=($def.Count -gt 0);security_products=$products.Count;asr_rules=$asr.Count}}
  defender=$def
  security_products=$products
  asr_rule_ids=$asr
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='defender', platforms=['windows'], description='Enumerate Defender status, exclusions, ASR rules, and security products')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'defender', None, build_command, format_generic_report, timeout=30.0)
