"""Windows scheduled task enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$tasks=@()
Get-ScheduledTask -EA 0|ForEach-Object{{
  $info=Get-ScheduledTaskInfo $_.TaskName -EA 0
  $actions=($_.Actions|ForEach-Object{{$_.Execute+' '+$_.Arguments}})-join '; '
  $tasks+=@{{name=$_.TaskName;path=$_.TaskPath;state=$_.State;user=$_.Principal.UserId;actions=$actions;last=$info.LastRunTime;next=$info.NextRunTime}}
}}
$result=[ordered]@{{
  summary=@{{tasks=$tasks.Count}}
  scheduled_tasks=($tasks|Select-Object -First 120)
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='scheduledtasks', platforms=['windows'], description='Enumerate scheduled tasks, triggers, and execution context')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'scheduledtasks', None, build_command, format_generic_report, timeout=40.0)
