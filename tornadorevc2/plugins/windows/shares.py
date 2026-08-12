"""Windows SMB share and network resource enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$shares=@(); $mapped=@(); $admin=@()
Get-SmbShare -EA 0|ForEach-Object{{$shares+=@{{name=$_.Name;path=$_.Path;desc=$_.Description}}}}
Get-SmbMapping -EA 0|ForEach-Object{{$mapped+=@{{local=$_.LocalPath;remote=$_.RemotePath;status=$_.Status}}}}
Get-WmiObject Win32_Share -EA 0|ForEach-Object{{$admin+=@{{name=$_.Name;path=$_.Path;type=$_.Type}}}}
$netview=@()
net view 2>$null|Select-Object -Skip 6|ForEach-Object{{if($_ -match '\\'){{$netview+=$_.Trim()}}}}
$result=[ordered]@{{
  summary=@{{local_shares=$shares.Count;mapped=$mapped.Count;wmi_shares=$admin.Count;net_view=$netview.Count}}
  smb_shares=$shares
  mapped_drives=$mapped
  wmi_shares=$admin
  network_hosts=$netview
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(name='shares', platforms=['windows'], description='Enumerate SMB shares, mapped drives, and network resources')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'shares', None, build_command, format_generic_report, timeout=30.0)
