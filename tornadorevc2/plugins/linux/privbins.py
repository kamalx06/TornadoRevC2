"""Linux SUID/SGID binary and file capability enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import os, stat, subprocess

def run_cmd(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def file_meta(path):
    try:
        st = os.stat(path, follow_symlinks=False)
        mode = oct(st.st_mode)[-4:]
        return {
            'path': path,
            'mode': mode,
            'owner': st.st_uid,
            'group': st.st_gid,
            'size': st.st_size,
        }
    except Exception:
        return None

suid = []
sgid = []
capabilities = []
writable_suid = []

# Common search roots to limit scope
search_roots = ['/', '/usr', '/usr/local', '/opt', '/sbin', '/bin', '/lib', '/lib64']
seen = set()

for root in search_roots:
    if not os.path.isdir(root):
        continue
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.count(os.sep) - root.count(os.sep)
        if depth > 6:
            dirnames[:] = []
            continue
        skip = ('/proc', '/sys', '/dev', '/run/user', '/var/lib/docker')
        if any(dirpath.startswith(s) for s in skip):
            dirnames[:] = []
            continue
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if fp in seen:
                continue
            seen.add(fp)
            try:
                st = os.lstat(fp)
            except Exception:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            su = bool(st.st_mode & stat.S_ISUID)
            sg = bool(st.st_mode & stat.S_ISGID)
            if su or sg:
                meta = file_meta(fp)
                if not meta:
                    continue
                if su:
                    suid.append(meta)
                    if st.st_mode & stat.S_IWOTH or st.st_mode & stat.S_IWGRP:
                        writable_suid.append(meta)
                if sg:
                    sgid.append(meta)
            if len(suid) + len(sgid) > 300:
                break
        if len(suid) + len(sgid) > 300:
            break

# File capabilities via getcap
cap_out = run_cmd('getcap -r /usr /bin /sbin /opt /lib /lib64 2>/dev/null | head -120')
if cap_out:
    for line in cap_out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) == 2:
            capabilities.append({'path': parts[0], 'caps': parts[1]})

# Notable SUID binaries (GTFOBins-style common names)
notable_names = {
    'bash', 'sh', 'dash', 'zsh', 'python', 'python3', 'perl', 'ruby',
    'lua', 'awk', 'gawk', 'php', 'node',
    'vim', 'nvim', 'vi', 'less', 'more', 'nano', 'view',
    'find', 'env', 'xargs', 'tar', 'zip', 'cp', 'mv',
    'gcc', 'g++', 'make', 'crontab', 'at',
    'sudo', 'su', 'pkexec', 'passwd', 'chsh', 'newgrp', 'gpasswd',
    'systemctl', 'journalctl', 'chroot', 'mount', 'umount',
    'docker', 'nmap', 'nc', 'socat', 'wget', 'curl', 'ftp', 'scp', 'rsync',
}

notable = []
for entry in suid + sgid:
    base = os.path.basename(entry['path']).lower()
    if base in notable_names:
        notable.append(entry)

result = {
    'summary': {
        'suid_count': len(suid),
        'sgid_count': len(sgid),
        'capabilities_count': len(capabilities),
        'writable_suid': len(writable_suid),
        'notable_count': len(notable),
    },
    'suid_binaries': suid[:80],
    'sgid_binaries': sgid[:60],
    'file_capabilities': capabilities[:80],
    'writable_suid': writable_suid[:20],
    'notable_privilege_binaries': notable[:40],
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(
    name='privbins',
    platforms=['linux', 'unix'],
    description='Enumerate SUID/SGID binaries, file capabilities, and privilege-escalation-relevant executables',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'privbins', build_command, None, format_generic_report, timeout=50.0)
