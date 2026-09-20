import re
from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


_USAGE = "Usage: run dlls <ID> <pid>"


_SUSPICIOUS_DIRS = (
    '\\temp\\',
    '\\tmp\\',
    '\\appdata\\local\\temp\\',
    '\\downloads\\',
    '\\public\\',
    '\\programdata\\',
    '\\users\\public\\',
    '\\\\',
)


def _build_windows_command(pid: int) -> str:
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'

$proc = Get-Process -Id {pid} -EA 0
if (-not $proc) {{
    $r = [ordered]@{{ summary = @{{ error = "PID {pid} not found" }} }}
    Write-Output ($s + (ConvertTo-Json $r -Compress) + $e)
    return
}}

$suspicious_dirs = @(
    '\temp\', '\tmp\', '\appdata\local\temp\', '\downloads\',
    '\public\', '\programdata\', '\users\public\'
)

$modules = @()
$flags = @()
$count = 0

foreach ($m in ($proc.Modules | Sort-Object ModuleName)) {{
    $count++
    if ($count -gt 200) {{ break }}

    $path = "$($m.FileName)"
    $path_low = $path.ToLower()
    $entry = [ordered]@{{
        name = "$($m.ModuleName)"
        path = $path
        base_address = ('0x{{0:X}}' -f $m.BaseAddress.ToInt64())
        size = $m.ModuleMemorySize
    }}

    # Signature and version info
    if ($path -and (Test-Path -LiteralPath $path -EA 0)) {{
        try {{
            $sig = Get-AuthenticodeSignature -LiteralPath $path -EA 0
            if ($sig) {{
                $entry.signature_status = "$($sig.Status)"
                $entry.signer = if ($sig.SignerCertificate) {{ "$($sig.SignerCertificate.Subject)" }} else {{ '' }}
            }}
        }} catch {{}}
        try {{
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
            $entry.company = "$($vi.CompanyName)"
            $entry.product = "$($vi.ProductName)"
            $entry.file_version = "$($vi.FileVersion)"
        }} catch {{}}
    }} else {{
        $entry.missing_on_disk = $true
        $flags += "Module '$($m.ModuleName)' is loaded from a path that no longer exists: $path"
    }}

    # Suspicious directory check
    foreach ($d in $suspicious_dirs) {{
        if ($path_low.Contains($d)) {{
            $entry.suspicious_path = $true
            $flags += "Module '$($m.ModuleName)' loaded from suspicious directory: $path"
            break
        }}
    }}

    # UNC path check
    if ($path_low.StartsWith('\\')) {{
        $entry.unc_path = $true
        $flags += "Module '$($m.ModuleName)' loaded from UNC path: $path"
    }}

    # Unsigned check (only for real on-disk files)
    if ($entry.signature_status -and $entry.signature_status -ne 'Valid') {{
        $entry.unsigned = $true
        $flags += "Module '$($m.ModuleName)' signature status: $($entry.signature_status) ($path)"
    }}

    # Company name inconsistency
    if ($entry.company -and $entry.signer) {{
        $cmp = "$($entry.company)".ToLower()
        $sign = "$($entry.signer)".ToLower()
        if ($cmp.Contains('microsoft') -and -not $sign.Contains('microsoft')) {{
            $flags += "Module '$($m.ModuleName)' claims Microsoft but is signed by a different publisher"
        }}
    }}

    $modules += $entry
}}

# Sort modules: suspicious first, then by path
$sorted = @($modules | Sort-Object @{{Expression={{ if ($_.suspicious_path -or $_.unc_path -or $_.unsigned -or $_.missing_on_disk) {{ 0 }} else {{ 1 }} }} }}, name)

$result = [ordered]@{{
    summary = @{{
        pid = {pid}
        process = "$($proc.ProcessName)"
        path = "$($proc.Path)"
        module_count = $modules.Count
        flag_count = $flags.Count
    }}
    suspicious = $flags
    modules = $sorted
}}
Write-Output ($s + (ConvertTo-Json $result -Depth 5 -Compress) + $e)
"""


def _format_dlls(data: dict) -> str:
    if not data:
        return "No data."
    summary = data.get('summary') or {}
    if summary.get('error'):
        return f"Error: {summary['error']}"

    lines = []
    lines.append("== PROCESS ==")
    lines.append(f"  PID:     {summary.get('pid', '?')}")
    lines.append(f"  Name:    {summary.get('process', '?')}")
    lines.append(f"  Path:    {summary.get('path', '?')}")
    lines.append(f"  Modules: {summary.get('module_count', 0)}")

    flags = data.get('suspicious') or []
    lines.append("")
    lines.append("== FLAGS ==")
    if not flags:
        lines.append("  (none — all modules signed, on-disk, and from expected directories)")
    else:
        for f in flags:
            lines.append(f"  * {f}")

    modules = data.get('modules') or []
    if modules:
        lines.append("")
        lines.append("== MODULES ==")
        for m in modules:
            marker = " "
            if m.get('suspicious_path') or m.get('unc_path') or m.get('unsigned') or m.get('missing_on_disk'):
                marker = "!"
            name = m.get('name', '?')
            path = m.get('path', '?')
            sig = m.get('signature_status', '?')
            lines.append(f"  [{marker}] {name:30} {sig:12} {path}")

    return "\n".join(lines)


@plugin.command(
    name='dlls',
    platforms=['windows'],
    description='Loaded module audit for a PID — unsigned, hijackable, or remotely-loaded DLLs',
)
def run(session: SessionContext, args):
    if not args or not re.match(r'^\d+$', args[0].strip()):
        session.print(_USAGE, 'yellow')
        return 1
    pid = int(args[0].strip())

    def build():
        return _build_windows_command(pid)

    return run_collector_plugin(
        session,
        'dlls',
        None,
        build,
        _format_dlls,
        timeout=60.0,
    )