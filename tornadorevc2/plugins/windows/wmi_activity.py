import json
from typing import Optional

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def _build_windows_command() -> str:
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'

$filters        = @()
$consumers_cmd  = @()
$consumers_scr  = @()
$consumers_logf = @()
$consumers_evt  = @()
$consumers_smtp = @()
$bindings       = @()
$custom_ns      = @()
$recent_events  = @()
$flags          = @()

# Known suspicious token patterns for a WMI consumer payload
$suspicious_patterns = @(
    'frombase64string',
    '-encodedcommand',
    ' -enc ',
    'iex(',
    'iex ',
    'invoke-expression',
    'downloadstring',
    'downloadfile',
    'http://',
    'https://',
    'mshta',
    'rundll32',
    'regsvr32',
    'wscript',
    'cscript',
    'certutil',
    'bitsadmin',
    'powershell -w hidden',
    'powershell -windowstyle hidden',
    'cmd /c',
    'cmd.exe /c',
    'mimikatz',
    'meterpreter',
    'cobaltstrike',
    'beacon'
)

function Test-Suspicious {{
    param([string]$text)
    if (-not $text) {{ return @() }}
    $low = $text.ToLower()
    $hits = @()
    foreach ($p in $suspicious_patterns) {{
        if ($low.Contains($p)) {{ $hits += $p.Trim() }}
    }}
    return $hits
}}

# --- Event filters ---
try {{
    foreach ($f in (Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter -EA 0)) {{
        $query = "$($f.Query)"
        $hits = Test-Suspicious $query
        $filters += [ordered]@{{
            name = "$($f.Name)"
            query = $query
            event_namespace = "$($f.EventNamespace)"
            suspicious = ($hits.Count -gt 0)
            suspicious_hits = $hits
        }}
        if ($hits.Count -gt 0) {{
            $flags += "WMI EventFilter '$($f.Name)' matches suspicious pattern(s): $($hits -join ', ')"
        }}
    }}
}} catch {{}}

# --- Command-line consumers ---
try {{
    foreach ($c in (Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer -EA 0)) {{
        $cmd = "$($c.CommandLineTemplate)"
        $hits = Test-Suspicious $cmd
        $consumers_cmd += [ordered]@{{
            name = "$($c.Name)"
            command = $cmd
            executable = "$($c.ExecutablePath)"
            working_dir = "$($c.WorkingDirectory)"
            suspicious = ($hits.Count -gt 0)
            suspicious_hits = $hits
        }}
        if ($hits.Count -gt 0) {{
            $flags += "WMI CommandLineEventConsumer '$($c.Name)' has suspicious command line"
        }}
    }}
}} catch {{}}

# --- ActiveScript (VBScript/JS) consumers ---
try {{
    foreach ($c in (Get-CimInstance -Namespace 'root\subscription' -ClassName ActiveScriptEventConsumer -EA 0)) {{
        $script = "$($c.ScriptText)"
        $hits = Test-Suspicious $script
        $consumers_scr += [ordered]@{{
            name = "$($c.Name)"
            engine = "$($c.ScriptingEngine)"
            script = $script
            script_length = $script.Length
            suspicious = ($hits.Count -gt 0)
            suspicious_hits = $hits
        }}
        if ($hits.Count -gt 0) {{
            $flags += "WMI ActiveScriptEventConsumer '$($c.Name)' has suspicious script content"
        }}
    }}
}} catch {{}}

# --- LogFile consumers ---
try {{
    foreach ($c in (Get-CimInstance -Namespace 'root\subscription' -ClassName LogFileEventConsumer -EA 0)) {{
        $consumers_logf += [ordered]@{{
            name = "$($c.Name)"
            filename = "$($c.Filename)"
            text = "$($c.Text)"
        }}
    }}
}} catch {{}}

# --- NTEventLog consumers ---
try {{
    foreach ($c in (Get-CimInstance -Namespace 'root\subscription' -ClassName NTEventLogEventConsumer -EA 0)) {{
        $consumers_evt += [ordered]@{{
            name = "$($c.Name)"
            source_name = "$($c.SourceName)"
            event_id = $c.EventID
            category = $c.Category
        }}
    }}
}} catch {{}}

# --- SMTP consumers ---
try {{
    foreach ($c in (Get-CimInstance -Namespace 'root\subscription' -ClassName SMTPEventConsumer -EA 0)) {{
        $consumers_smtp += [ordered]@{{
            name = "$($c.Name)"
            to = "$($c.ToLine)"
            subject = "$($c.Subject)"
            smtp_server = "$($c.SMTPServer)"
        }}
    }}
}} catch {{}}

# --- Filter to Consumer bindings ---
try {{
    foreach ($b in (Get-CimInstance -Namespace 'root\subscription' -ClassName __FilterToConsumerBinding -EA 0)) {{
        $bindings += [ordered]@{{
            filter = "$($b.Filter)"
            consumer = "$($b.Consumer)"
        }}
    }}
}} catch {{}}

# --- Custom WMI namespaces under root ---
$known_ns = @(
    'subscription','DEFAULT','CIMV2','SecurityCenter2','SecurityCenter',
    'Microsoft','WMI','msdtc','Cli','SECURITY','RSOP','PEH',
    'StandardCimv2','Windows','InventoryLogging','Hardware','Appv',
    'directory','Policy','Interop','Nap','ServiceModel','Intel_AMT'
)
try {{
    foreach ($ns in (Get-CimInstance -Namespace 'root' -ClassName __Namespace -EA 0)) {{
        if ($ns.Name -notin $known_ns) {{
            $custom_ns += "$($ns.Name)"
        }}
    }}
}} catch {{}}

# --- Recent WMI activity from event log ---
try {{
    $evts = Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -MaxEvents 25 -EA 0
    foreach ($ev in $evts) {{
        $msg = "$($ev.Message)"
        if ($msg.Length -gt 400) {{ $msg = $msg.Substring(0, 400) + '...' }}
        $recent_events += [ordered]@{{
            time = "$($ev.TimeCreated)"
            id = $ev.Id
            level = "$($ev.LevelDisplayName)"
            message = $msg
        }}
    }}
}} catch {{}}

# --- WMI repository integrity ---
$repo_status = 'unknown'
try {{
    $repo_out = (winmgmt /verifyrepository 2>&1) -join ' '
    if ($repo_out -match 'consistent') {{ $repo_status = 'consistent' }}
    elseif ($repo_out -match 'inconsistent|failed|corrupt') {{ $repo_status = 'INCONSISTENT' }}
    else {{ $repo_status = $repo_out.Trim() }}
}} catch {{}}

$result = [ordered]@{{
    summary = @{{
        event_filters = $filters.Count
        command_consumers = $consumers_cmd.Count
        script_consumers = $consumers_scr.Count
        logfile_consumers = $consumers_logf.Count
        eventlog_consumers = $consumers_evt.Count
        smtp_consumers = $consumers_smtp.Count
        bindings = $bindings.Count
        custom_namespaces = $custom_ns.Count
        recent_events = $recent_events.Count
        repository_status = $repo_status
        suspicious_count = $flags.Count
    }}
    event_filters = $filters
    command_line_consumers = $consumers_cmd
    script_consumers = $consumers_scr
    logfile_consumers = $consumers_logf
    eventlog_consumers = $consumers_evt
    smtp_consumers = $consumers_smtp
    bindings = $bindings
    custom_namespaces = $custom_ns
    recent_wmi_activity = $recent_events
    suspicious_findings = $flags
}}
Write-Output ($s + (ConvertTo-Json $result -Depth 6 -Compress) + $e)
"""


@plugin.command(
    name='wmi_activity',
    platforms=['windows'],
    description='WMI persistence, consumers, bindings, and recent activity',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'wmi_activity',
        None,
        _build_windows_command,
        format_generic_report,
        timeout=45.0,
    )