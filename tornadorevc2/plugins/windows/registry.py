"""Windows registry persistence and configuration enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$keys=@(
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
  'HKLM:\\SYSTEM\\CurrentControlSet\\Services'
)
$autoruns=@(); $software=@()
foreach($k in $keys[0..4]){{
  if(Test-Path $k){{Get-ItemProperty $k -EA 0|Get-Member -MemberType NoteProperty|? Name -notmatch '^PS'|ForEach-Object{{$p=Get-ItemProperty $k;$autoruns+=@{{key=$k;name=$_.Name;value=$p.($_.Name)}}}}}}
}
Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -EA 0|Select-Object -First 40 DisplayName,DisplayVersion,Publisher,InstallDate|ForEach-Object{{$software+=@{{name=$_.DisplayName;ver=$_.DisplayVersion;pub=$_.Publisher;date=$_.InstallDate}}}}
$result=[ordered]@{{
  summary=@{{autoruns=$autoruns.Count;software=$software.Count}}
  autorun_entries=$autoruns
  installed_software=$software
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='registry', platforms=['windows'], description='Enumerate autoruns, Run keys, startup locations, and installed software')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'registry', None, build_command, format_generic_report, timeout=35.0)
