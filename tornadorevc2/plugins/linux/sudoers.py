from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ._helpers import build_linux_collector_command
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os
import subprocess

result = {
    'summary': {},
    'sudo_info': {},
    'sudo_rights': [],
    'sudoers_root': [],
    'sudoers_d': [],
    'nopasswd_entries': [],
    'writable_sudoers': [],
    'group_memberships': [],
    'pkexec': {},
    'privesc_candidates': [],
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


# --- Sudo binary and version ---
sudo_path = ''
for p in ('/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo', '/usr/sbin/sudo'):
    if os.path.exists(p):
        sudo_path = p
        break

sudo_ver_line = ''
if sudo_path:
    out = sh(f'{sudo_path} --version 2>/dev/null | head -1')
    sudo_ver_line = out.strip()

result['sudo_info'] = {
    'binary': sudo_path or '(not found)',
    'version_line': sudo_ver_line or '(unavailable)',
}


# --- sudo -n -l (non-interactive, no password prompt) ---
sudo_list = sh(f'{sudo_path} -n -l 2>&1', timeout=8) if sudo_path else ''
if sudo_list:
    for line in sudo_list.splitlines():
        s = line.strip()
        if not s:
            continue
        result['sudo_rights'].append(s[:300])
        if 'NOPASSWD' in s:
            result['nopasswd_entries'].append(s[:300])


# --- /etc/sudoers ---
sudoers_root = '/etc/sudoers'
if os.path.exists(sudoers_root):
    if is_readable(sudoers_root):
        try:
            with open(sudoers_root, 'r', errors='ignore') as fh:
                for line in fh.read().splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    result['sudoers_root'].append(s[:300])
        except Exception as exc:
            result['sudoers_root'].append(f"(read error: {exc})")
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
            if is_readable(full):
                try:
                    with open(full, 'r', errors='ignore') as fh:
                        for line in fh.read().splitlines():
                            s = line.strip()
                            if not s or s.startswith('#'):
                                continue
                            result['sudoers_d'].append({
                                'file': entry,
                                'line': s[:300],
                            })
                except Exception:
                    continue
            if is_writable(full):
                result['writable_sudoers'].append(full)
    except Exception:
        pass


# --- Group memberships ---
current_groups = set(sh('id -nG 2>/dev/null').split())
privileged_groups = {'sudo', 'wheel', 'adm', 'docker', 'lxd', 'disk', 'shadow'}

for g in sorted(current_groups):
    entry = g
    if g in privileged_groups:
        entry = f"{g}  [privileged]"
    result['group_memberships'].append(entry)


# --- pkexec (PwnKit candidate) ---
pkexec_path = ''
for p in ('/usr/bin/pkexec', '/bin/pkexec'):
    if os.path.exists(p):
        pkexec_path = p
        break

if pkexec_path:
    ver = sh(f'{pkexec_path} --version 2>&1 | head -2').strip()
    result['pkexec'] = {
        'binary': pkexec_path,
        'version_line': ver.splitlines()[0] if ver else '(unknown)',
    }
else:
    result['pkexec'] = {'binary': '(not found)'}


# --- Privesc candidate summary ---
cands = []
if result['nopasswd_entries']:
    cands.append(f"NOPASSWD sudo entry present ({len(result['nopasswd_entries'])})")
if result['writable_sudoers']:
    cands.append(f"Writable sudoers file(s): {', '.join(result['writable_sudoers'])}")
if 'sudo' in current_groups:
    cands.append("User is member of sudo group")
if 'wheel' in current_groups:
    cands.append("User is member of wheel group")
if 'docker' in current_groups:
    cands.append("User is member of docker group (root-equivalent)")
if 'lxd' in current_groups:
    cands.append("User is member of lxd group (root-equivalent)")
if 'disk' in current_groups:
    cands.append("User is member of disk group (raw device access)")
if pkexec_path:
    cands.append("pkexec present - check against CVE-2021-4034 (PwnKit)")

result['privesc_candidates'] = cands


result['summary'] = {
    'sudo_binary': sudo_path or 'not found',
    'sudo_version': (sudo_ver_line or '(unavailable)')[:80],
    'sudo_rights_lines': len(result['sudo_rights']),
    'sudoers_root_lines': len(result['sudoers_root']),
    'sudoers_d_entries': len(result['sudoers_d']),
    'nopasswd_entries': len(result['nopasswd_entries']),
    'writable_sudoers': len(result['writable_sudoers']),
    'pkexec_present': bool(pkexec_path),
    'privesc_candidates': len(cands),
}

_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


@plugin.command(
    name='sudoers',
    platforms=['linux', 'unix'],
    description='Sudo configuration audit: NOPASSWD entries, writable sudoers, pkexec, group membership',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'sudoers',
        _build_linux_command,
        None,
        format_generic_report,
        timeout=30.0,
    )