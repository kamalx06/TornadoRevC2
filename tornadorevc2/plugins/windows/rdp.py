"""Windows Remote Desktop configuration and recent target enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$rdp=@{{}}
$recent=@()
$settings=@{{}}
try{{
  $ts='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $rdp.Enabled=(Get-ItemProperty $ts -Name fDenyTSConnections -EA 0).fDenyTSConnections
  $rdp.Enabled=if($rdp.Enabled -eq 0){{'yes'}}else{{'no'}}
  $rdp.AllowRemoteRPC=(Get-ItemProperty $ts -Name AllowRemoteRPC -EA 0).AllowRemoteRPC
  $rdp.Port=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -EA 0).PortNumber
  $rdp.NLA=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -EA 0).UserAuthentication
  $rdp.SecurityLayer=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -EA 0).SecurityLayer
}}catch{{}}
try{{
  $servers='HKCU:\Software\Microsoft\Terminal Server Client\Servers'
  if(Test-Path $servers){{
    Get-ChildItem $servers -EA 0|ForEach-Object{{
      $props=Get-ItemProperty $_.PSPath -EA 0
      $recent+=@{{host=$_.PSChildName;username=$props.UsernameHint;last_connected=$props}}
    }}
  }}
}}catch{{}}
try{{
  $def='HKCU:\Software\Microsoft\Terminal Server Client\Default'
  if(Test-Path $def){{
    $settings.MRU0=(Get-ItemProperty $def -Name MRU0 -EA 0).MRU0
    $settings.Addins=(Get-ItemProperty $def -EA 0|Get-Member -MemberType NoteProperty|Where-Object Name -notmatch '^PS'|Select-Object -ExpandProperty Name)
  }}
}}catch{{}}
try{{
  $fw=Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -EA 0|Select-Object DisplayName,Enabled,Direction,Action
  $settings.FirewallRules=@($fw|ForEach-Object{{ @{{name=$_.DisplayName;enabled=$_.Enabled;action=$_.Action}} }})
}}catch{{}}
try{{
  $sessions=quser 2>$null
  if($sessions){{ $settings.ActiveSessions=($sessions -split "`n").Count - 1 }}
}}catch{{}}
$result=[ordered]@{{
  summary=@{{RDP_Enabled=$rdp.Enabled;Port=$rdp.Port;Recent_Targets=$recent.Count;NLA=$rdp.NLA}}
  rdp_configuration=$rdp
  recent_targets=$recent
  client_settings=$settings
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='rdp',
    platforms=['windows'],
    description='Detect Remote Desktop configuration, status, recent targets, and settings',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'rdp',
        None,
        build_command,
        format_generic_report,
        timeout=35.0,
    )
