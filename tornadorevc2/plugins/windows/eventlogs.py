"""Windows event log summary enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
function Get-LogSummary($log,$filter,$max=25){{
  $events=@()
  try{{
    Get-WinEvent -FilterHashtable @{{LogName=$log;StartTime=(Get-Date).AddDays(-3)}} -MaxEvents 200 -EA 0|
      Where-Object $filter|
      Select-Object -First $max TimeCreated,Id,LevelDisplayName,ProviderName,Message|
      ForEach-Object{{$events+=@{{time=$_.TimeCreated.ToString('s');id=$_.Id;level=$_.LevelDisplayName;provider=$_.ProviderName;msg=($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(180,$_.Message.Length))}}}}
  }}catch{{}}
  return $events
}}
$security=Get-LogSummary 'Security' {{$_.Id -in 4624,4625,4648,4672,4720,4728}}
$system=Get-LogSummary 'System' {{$_.Id -in 7036,7040,7045,1074,6005,6006}}
$app=Get-LogSummary 'Application' {{$true}} 15
$ps=Get-LogSummary 'Microsoft-Windows-PowerShell/Operational' {{$_.Id -in 4103,4104}} 20
$result=[ordered]@{{
  summary=@{{security=$security.Count;system=$system.Count;application=$app.Count;powershell=$ps.Count}}
  security_events=$security
  system_events=$system
  application_events=$app
  powershell_events=$ps
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='eventlogs', platforms=['windows'], description='Summarize Security, System, Application, and PowerShell event logs')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'eventlogs', None, build_command, format_generic_report, timeout=45.0)
