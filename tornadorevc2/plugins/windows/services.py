"""Windows service enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$services=@()
Get-CimInstance Win32_Service -EA 0|ForEach-Object{{
  $services+=@{{name=$_.Name;display=$_.DisplayName;start=$_.StartMode;state=$_.State;account=$_.StartName;path=$_.PathName}}
}}
$interesting=$services|Where-Object{{$_.start -eq 'Auto' -or $_.account -match 'LocalSystem|NetworkService|Administrator' -or $_.path -match 'temp|appdata|programdata'}}
$result=[ordered]@{{
  summary=@{{total=$services.Count;interesting=$interesting.Count}}
  services=($services|Select-Object -First 100)
  notable=($interesting|Select-Object -First 50)
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='services', platforms=['windows'], description='Enumerate Windows services, startup types, binaries, and service accounts')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'services', None, build_command, format_generic_report, timeout=35.0)
