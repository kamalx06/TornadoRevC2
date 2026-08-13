"""Linux mount, filesystem, and share enumeration collector."""

from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, subprocess
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

nfs_exports = []
try:
    with open('/etc/exports', 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            nfs_exports.append({'export': parts[0], 'clients': ' '.join(parts[1:])[:80]})
except Exception:
    pass

smb_shares = []
try:
    out = subprocess.check_output(['smbstatus', '--shares'], stderr=subprocess.DEVNULL, timeout=5)
    text = out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    for line in text.splitlines():
        line = line.strip()
        if line and not line.lower().startswith('service') and line[0].isalnum():
            parts = line.split(None, 1)
            smb_shares.append({'name': parts[0], 'path': parts[1] if len(parts) > 1 else ''})
except Exception:
    pass
if not smb_shares:
    try:
        with open('/etc/samba/smb.conf', 'r', errors='ignore') as f:
            section = ''
            for line in f:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1]
                elif line.startswith('path = ') and section and section not in ('global', 'homes'):
                    smb_shares.append({'name': section, 'path': line.split('=', 1)[1].strip()})
    except Exception:
        pass

result = {
    'summary': {
        'total_mounts': len(mounts), 'nfs_smb': len(nfs), 'container_mounts': len(docker_mounts),
        'writable_exec': len(writable_exec), 'local_shares': len(smb_shares),
        'nfs_exports': len(nfs_exports), 'mapped_drives': len(nfs),
    },
    'mounts': mounts[:80],
    'network_mounts': nfs[:30],
    'container_related': docker_mounts[:30],
    'writable_executable': writable_exec[:30],
    'nfs_exports': nfs_exports[:30],
    'smb_shares': smb_shares[:30],
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())
