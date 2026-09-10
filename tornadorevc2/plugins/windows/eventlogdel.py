"""Windows event log clearing via native event log management."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_eventlogdel_report
from ..shared.runner import run_collector_plugin

EVENTLOGDEL_USAGE = """eventlogdel - Clear Windows Event Logs

USAGE:
  eventlogdel [OPTIONS]

OPTIONS:
  --all                Clear every event log that currently has records.
                       Cannot be combined with --no-security.
  --log NAME[,NAME...] Comma-separated list of log names to clear.
                       Overrides --all and the built-in defaults.
  --backup DIR         Export each target log to DIR as <log>.evtx before
                       clearing. A timestamped subdirectory
                       (DIR\\YYYY-MM-DD_HH-MM\\) is created for each run so
                       repeated runs never overwrite previous exports.
  --no-security        Skip the Security log. Cannot be combined with --all.
  -h, --help, /?       Show this help and exit.

DEFAULTS:
  Security
  System
  Application
  Microsoft-Windows-PowerShell/Operational

BEHAVIOUR:
  * Clears via a 3-step fallback: wevtutil cl -> Clear-EventLog -> .NET.
  * Each log is verified by re-reading RecordCount (soft check; a clear that
    returned success is still reported as cleared even if verification lags).
  * On success the .evtx is best-effort zeroed on disk.
  * Requires administrator privileges to clear the Security log.

EXAMPLES:
  eventlogdel
  eventlogdel --all
  eventlogdel --log Security,System,Microsoft-Windows-Sysmon/Operational
  eventlogdel --backup C:\\intel\\evtx --all
  eventlogdel --backup C:\\intel\\evtx --log Security,System
"""

_HELP_FLAGS = {'-h', '--help', '/?', '-?', 'help'}


def _parse_cli(args):
    opts = {
        'all': False,
        'log': None,
        'backup': None,
        'no_security': False,
        'help': False,
        '_unknown': [],
    }
    if args is None:
        return opts

    if isinstance(args, str):
        argv = args.split()
    else:
        try:
            argv = list(args)
        except TypeError:
            return opts

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in _HELP_FLAGS:
            opts['help'] = True
        elif a == '--all':
            opts['all'] = True
        elif a == '--no-security':
            opts['no_security'] = True
        elif a == '--log':
            if i + 1 < len(argv):
                i += 1
                opts['log'] = argv[i]
            else:
                opts['_unknown'].append('--log (missing value)')
        elif a.startswith('--log='):
            opts['log'] = a.split('=', 1)[1]
        elif a == '--backup':
            if i + 1 < len(argv):
                i += 1
                opts['backup'] = argv[i]
            else:
                opts['_unknown'].append('--backup (missing value)')
        elif a.startswith('--backup='):
            opts['backup'] = a.split('=', 1)[1]
        elif a.startswith('-'):
            opts['_unknown'].append(a)
        i += 1
    return opts


def _print_usage(session, *, reason=None):
    if reason:
        session.print(reason, 'red')
    for line in EVENTLOGDEL_USAGE.rstrip().splitlines():
        session.print(line, 'cyan')


def _make_build_command(opts):

    backup_dir = (opts.get('backup') or '').replace("'", "''")
    log_arg = (opts.get('log') or '').replace("'", "''")
    all_flag = '1' if opts.get('all') else '0'
    no_security_flag = '1' if opts.get('no_security') else '0'

    def build_command():
        return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$backupDir='{backup_dir}'
$customLogs='{log_arg}'
$clearAll=({all_flag} -eq 1)
$noSecurity=({no_security_flag} -eq 1)

function Convert-ExitCode([int]$code) {{
  switch ($code) {{
    0     {{ return 'Success' }}
    2     {{ return 'File not found (exit code 2)' }}
    3     {{ return 'Path not found (exit code 3)' }}
    5     {{ return 'Access denied - administrator privileges required (exit code 5)' }}
    13    {{ return 'Invalid data (exit code 13)' }}
    32    {{ return 'File in use / sharing violation (exit code 32)' }}
    50    {{ return 'Operation not supported (exit code 50)' }}
    87    {{ return 'Invalid parameter / log name rejected (exit code 87)' }}
    1058  {{ return 'Service disabled (exit code 1058)' }}
    1060  {{ return 'Service does not exist (exit code 1060)' }}
    1062  {{ return 'Service not started (exit code 1062)' }}
    1722  {{ return 'RPC server unavailable (exit code 1722)' }}
    1726  {{ return 'RPC call failed (exit code 1726)' }}
    15003 {{ return 'Event log channel path invalid (exit code 15003)' }}
    15005 {{ return 'Event log channel cannot activate (exit code 15005)' }}
    15007 {{ return 'Event log channel not found (exit code 15007)' }}
    default {{ return ("Unknown wevtutil error (exit code $code)") }}
  }}
}}

$isAdmin=$false
try {{
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $isAdmin=(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}} catch {{}}

$defaultLogs=@(
  'Security',
  'System',
  'Application',
  'Microsoft-Windows-PowerShell/Operational'
)

$logs=@()
$selectionMode='default'
if ($customLogs -and $customLogs.Trim()) {{
  $logs = @($customLogs -split ',' | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }})
  $selectionMode='custom'
}} elseif ($clearAll) {{
  $logs = @(Get-WinEvent -ListLog * -EA SilentlyContinue |
            Where-Object {{ $_.RecordCount -gt 0 }} |
            Select-Object -ExpandProperty LogName)
  $selectionMode='all'
}} else {{
  $logs = $defaultLogs
}}

if ($noSecurity) {{
  $logs = @($logs | Where-Object {{ $_ -ne 'Security' }})
}}

# --- Resolve backup root once: DIR\<timestamp> ----------------------------
$backupRoot = ''
if ($backupDir) {{
  try {{
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $backupRoot = Join-Path $backupDir $stamp
    if (-not (Test-Path -LiteralPath $backupRoot)) {{
      New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    }}
  }} catch {{ $backupRoot = '' }}
}}

$cleared=@()
$clearedDetails=@()
$failed=@()
$missing=@()

foreach($log in $logs) {{
  $logInfo = Get-WinEvent -ListLog $log -EA SilentlyContinue
  if (-not $logInfo) {{
    $missing += $log
    continue
  }}

  $before = [ordered]@{{
    RecordCount = [int]$logInfo.RecordCount
    FileSize    = [long]$logInfo.FileSize
    LogFilePath = $logInfo.LogFilePath
  }}

  $backupPath = ''
  if ($backupRoot) {{
    try {{
      $safeName = ($log -replace '[\\/:\*\?"<>\|]','_')
      $candidate = Join-Path $backupRoot ($safeName + '.evtx')
      & wevtutil.exe epl $log $candidate /ow:true 2>&1 | Out-Null
      $code = if ($null -ne $LASTEXITCODE) {{ [int]$LASTEXITCODE }} else {{ -1 }}
      if ($code -eq 0 -and (Test-Path -LiteralPath $candidate)) {{
        $backupPath = $candidate
      }}
    }} catch {{ $backupPath = '' }}
  }}

  $ok=$false; $method=''; $err=''

  try {{
    & wevtutil.exe cl $log 2>&1 | Out-Null
    $code = if ($null -ne $LASTEXITCODE) {{ [int]$LASTEXITCODE }} else {{ -1 }}
    if ($code -eq 0) {{ $ok=$true; $method='wevtutil cl' }}
    else {{ $err = "wevtutil cl: $(Convert-ExitCode $code)" }}
  }} catch {{ $err = $_.Exception.Message }}

  if (-not $ok) {{
    try {{
      Clear-EventLog -LogName $log -EA Stop
      $ok=$true; $method='Clear-EventLog'; $err=''
    }} catch {{
      if (-not $err) {{ $err = $_.Exception.Message }}
    }}
  }}

  if (-not $ok) {{
    try {{
      $el = New-Object System.Diagnostics.EventLog($log)
      try {{ $el.Clear() }} finally {{ $el.Dispose() }}
      $ok=$true; $method='EventLog.Clear'; $err=''
    }} catch {{
      if (-not $err) {{ $err = $_.Exception.Message }}
    }}
  }}

  $afterInfo = Get-WinEvent -ListLog $log -EA SilentlyContinue
  $after = [ordered]@{{}}
  $verified = $false
  if ($afterInfo) {{
    $after = [ordered]@{{
      RecordCount = [int]$afterInfo.RecordCount
      FileSize    = [long]$afterInfo.FileSize
      LogFilePath = $afterInfo.LogFilePath
    }}
    if ([int]$afterInfo.RecordCount -eq 0) {{ $verified = $true }}
  }}

  $zeroed = $false
  if ($ok -and $verified) {{
    $path = if ($afterInfo.LogFilePath) {{ $afterInfo.LogFilePath }} else {{ $before.LogFilePath }}
    if ($path -and (Test-Path -LiteralPath $path)) {{
      try {{
        $fi = Get-Item -LiteralPath $path -Force
        $len = [long]$fi.Length
        if ($len -le 0) {{
          $zeroed = $true
        }} else {{
          $fs = [System.IO.File]::Open(
            $path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::ReadWrite)
          try {{
            $buf = New-Object byte[] 65536
            $rem = $len
            while ($rem -gt 0) {{
              $chunk = [Math]::Min([long]$buf.Length, $rem)
              $fs.Write($buf, 0, [int]$chunk)
              $rem -= $chunk
            }}
            $fs.Flush()
            $zeroed = $true
          }} finally {{
            $fs.Close(); $fs.Dispose()
          }}
        }}
      }} catch {{ $zeroed = $false }}
    }}
  }}

  if ($ok) {{
    $cleared += $log
    $clearedDetails += [ordered]@{{
      log=$log
      method=$method
      backup=$backupPath
      zeroed=$zeroed
      verified=$verified
      before=$before
      after=$after
    }}
  }} else {{
    $kind = 'other'
    $msg = ($err -replace '\s+',' ').Trim()
    if ($msg -match '(?i)access.*denied|unauthorized|privilege|permission|exit code 5\b') {{
      $kind = 'access-denied'
    }} elseif ($msg -match '(?i)not.*found|does not exist|no such|exit code (2|3|87|15007)\b') {{
      $kind = 'not-found'
    }} elseif ($msg -match '(?i)in use|sharing violation|locked|exit code 32\b') {{
      $kind = 'locked'
    }}
    $failed += [ordered]@{{
      log=$log
      error=$msg
      errorType=$kind
      before=$before
    }}
  }}
}}

# --- Context-aware final message ------------------------------------------
$finalMsg = 'Event logs cleared using wevtutil/Clear-EventLog/.NET'
if ($cleared.Count -eq 0) {{
  if ($logs.Count -gt 0 -and $missing.Count -eq $logs.Count) {{
    $finalMsg = 'None of the requested logs exist on this host.'
  }} elseif (-not $isAdmin) {{
    $finalMsg = 'No event logs were cleared. Administrator privileges may be required to clear Security/System/Application.'
  }} else {{
    $finalMsg = 'No event logs were cleared. See failed[] for details.'
  }}
}}

$result=[ordered]@{{
  summary=[ordered]@{{
    Mode=$selectionMode
    IsAdmin=$isAdmin
    BackedUp=[bool]$backupDir
    BackupDir=$backupRoot
    SecuritySkipped=$noSecurity
    Requested=$logs.Count
    Cleared=$cleared.Count
    Failed=$failed.Count
    Missing=$missing.Count
  }}
  cleared=$cleared
  clearedDetails=$clearedDetails
  failed=$failed
  missing=$missing
  message=$finalMsg
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""
    return build_command


def _confirm_or_abort(session: SessionContext, args) -> bool:
    assume_yes = False
    if args is not None:
        for flag in ('yes', 'y', 'force', 'f'):
            if getattr(args, flag, False):
                assume_yes = True
                break
    if assume_yes:
        session.print('--yes supplied, skipping confirmation.', 'yellow')
        return True
    try:
        answer = input("Do you want to continue? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        session.print('', 'yellow')
        return False
    return answer in ('y', 'yes')

@plugin.command(
    name='eventlogdel',
    platforms=['windows'],
    description='Clear Windows Event Logs (Security, System, Application, PowerShell)',
)
def run(session: SessionContext, args):
    opts = _parse_cli(args)

    if opts['help']:
        _print_usage(session)
        return None

    if opts['_unknown']:
        _print_usage(
            session,
            reason=f"Unknown or malformed argument(s): {' '.join(opts['_unknown'])}",
        )
        return None

    if opts['all'] and opts['no_security']:
        session.print(
            'Error: --all and --no-security cannot be combined.',
            'red',
        )
        return None

    if opts['all']:
        session.print(
            'WARNING: this will clear nearly every Windows event log channel '
            'it can find on the target (Security, System, Application, '
            'PowerShell, Sysmon, Defender, Task Scheduler, RDP, DNS, '
            'firewall, and any other registered operational channel with '
            'records).',
            'red',
        )
        session.print(
            'This action is destructive and cannot be undone. '
            'Pass --backup DIR if the records are needed.',
            'red',
        )
        if not _confirm_or_abort(session, opts):
            session.print('Aborted by user.', 'yellow')
            session.log_event(
                'Plugin eventlogdel: aborted by user before execution'
            )
            return None
            
    session.log_event(
        "Plugin eventlogdel: clear started "
        f"(all={opts['all']}, log={opts['log']}, "
        f"backup={opts['backup']}, no_security={opts['no_security']})"
    )

    if opts['no_security']:
        session.print('Clearing Windows event logs (Security excluded).', 'yellow')
    else:
        session.print(
            'Clearing Windows event logs '
            '(Security log typically requires administrator privileges).',
            'yellow',
        )

    return run_collector_plugin(
        session,
        'eventlogdel',
        None,
        _make_build_command(opts),
        format_eventlogdel_report,
        timeout=300.0,
    )