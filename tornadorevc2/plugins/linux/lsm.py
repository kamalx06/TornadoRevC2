"""Linux Security Module (LSM) enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import os, subprocess

def rd(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read().strip()
    except Exception:
        return ''

def run_cmd(cmd, timeout=6):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

loaded_lsm = rd('/sys/kernel/security/lsm')
selinux = {}
apparmor = {}
other = {}

# SELinux
if 'selinux' in loaded_lsm.lower() or os.path.isdir('/sys/fs/selinux'):
    selinux['loaded'] = True
    selinux['enforce'] = rd('/sys/fs/selinux/enforce') or run_cmd('getenforce 2>/dev/null').strip()
    selinux['status'] = run_cmd('sestatus 2>/dev/null').strip()[:800]
    selinux['config'] = rd('/etc/selinux/config')[:400]
    selinux['policy'] = rd('/etc/selinux/config').split('SELINUXTYPE=')[-1].splitlines()[0].strip() if 'SELINUXTYPE' in rd('/etc/selinux/config') else ''
    booleans = run_cmd('getsebool -a 2>/dev/null | head -30')
    if booleans:
        selinux['booleans_sample'] = booleans.strip().splitlines()[:30]
else:
    selinux['loaded'] = False

# AppArmor
if 'apparmor' in loaded_lsm.lower() or os.path.isdir('/sys/kernel/security/apparmor'):
    apparmor['loaded'] = True
    apparmor['status'] = run_cmd('aa-status 2>/dev/null').strip()[:800]
    if not apparmor['status']:
        apparmor['status'] = run_cmd('apparmor_status 2>/dev/null').strip()[:800]
    apparmor['enforce'] = rd('/sys/module/apparmor/parameters/enabled')
    profiles = []
    aa_dir = '/etc/apparmor.d'
    if os.path.isdir(aa_dir):
        for fn in sorted(os.listdir(aa_dir))[:40]:
            if fn.endswith(('.conf',)) or (not fn.startswith('.') and os.path.isfile(os.path.join(aa_dir, fn))):
                profiles.append(fn)
    apparmor['profiles_sample'] = profiles[:40]
    apparmor['profile_count'] = len(profiles)
else:
    apparmor['loaded'] = False

# Other LSMs
for lsm in loaded_lsm.replace(',', ' ').split():
    lsm = lsm.strip()
    if not lsm or lsm in ('selinux', 'apparmor'):
        continue
    info = {}
    param_dir = f'/sys/module/{lsm}/parameters'
    if os.path.isdir(param_dir):
        for fn in os.listdir(param_dir)[:10]:
            info[fn] = rd(os.path.join(param_dir, fn))
    other[lsm] = info or {'status': 'loaded'}

# Yama ptrace scope
yama = rd('/proc/sys/kernel/yama/ptrace_scope')
if yama:
    other['yama'] = {'ptrace_scope': yama}

result = {
    'summary': {
        'loaded_lsm': loaded_lsm or 'N/A',
        'selinux': selinux.get('loaded', False),
        'apparmor': apparmor.get('loaded', False),
        'other_modules': len(other),
    },
    'loaded_modules': loaded_lsm,
    'selinux': selinux,
    'apparmor': apparmor,
    'other_lsm': other,
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(
    name='lsm',
    platforms=['linux', 'unix'],
    description='Detect and enumerate SELinux, AppArmor, and other Linux Security Modules',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'lsm', build_command, None, format_generic_report, timeout=30.0)
