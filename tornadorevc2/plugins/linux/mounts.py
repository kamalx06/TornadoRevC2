"""Linux mount and filesystem enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, subprocess
MS="''' + PLUGIN_MARK_START + r'''"; ME="''' + PLUGIN_MARK_END + r'''"
mounts = []
try:
    with open('/proc/mounts', 'r', errors='ignore') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4:
                opts = parts[3].split(',')
                mounts.append({
                    'device': parts[0], 'mount': parts[1], 'fstype': parts[2],
                    'options': parts[3][:80],
                    'writable': 'rw' in opts,
                    'noexec': 'noexec' in opts,
                    'bind': parts[0].startswith('/') and parts[0] != parts[1],
                })
except Exception:
    pass
nfs = [m for m in mounts if m['fstype'] in ('nfs', 'nfs4', 'cifs', 'smbfs')]
docker_mounts = [m for m in mounts if 'docker' in m['device'] or 'kubelet' in m['mount'] or 'containerd' in m['device']]
writable_exec = [m for m in mounts if m.get('writable') and not m.get('noexec')]
result = {
    'summary': {'total_mounts': len(mounts), 'nfs_smb': len(nfs), 'container_mounts': len(docker_mounts), 'writable_exec': len(writable_exec)},
    'mounts': mounts[:80],
    'network_mounts': nfs[:30],
    'container_related': docker_mounts[:30],
    'writable_executable': writable_exec[:30],
}
print(MS + json.dumps(result, separators=(',', ':')) + ME)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(name='mounts', platforms=['linux', 'unix'], description='Enumerate mounts, bind mounts, NFS/SMB, and container filesystems')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'mounts', build_command, None, format_generic_report, timeout=20.0)
