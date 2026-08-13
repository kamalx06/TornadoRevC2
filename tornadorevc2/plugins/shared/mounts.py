"""Cross-platform mount and filesystem enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
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


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$mounts=@(); $mapped=@(); $smb=@(); $wmi=@()
Get-CimInstance Win32_LogicalDisk -EA 0|ForEach-Object{{
  $dt=switch([int]$_.DriveType){{2{{'Removable'}}3{{'Fixed'}}4{{'Network'}}5{{'CD-ROM'}}default{{'Other'}}}}
  $mounts+=@{{device=$_.DeviceID;mount=$_.DeviceID;fstype=($(if($_.FileSystem){{$_.FileSystem}}else{{'unknown'}}));options="type=$dt;size=$($_.Size);free=$($_.FreeSpace)";writable=$true;noexec=$false;bind=$false}}
}}
try{{
  Get-SmbMapping -EA Stop|ForEach-Object{{
    $mapped+=@{{local=$_.LocalPath;remote=$_.RemotePath;status=$_.Status}}
    $mounts+=@{{device=$_.RemotePath;mount=$_.LocalPath;fstype='smb';options="status=$($_.Status)";writable=$true;noexec=$false;bind=$false}}
  }}
}}catch{{}}
try{{
  Get-SmbShare -EA Stop|ForEach-Object{{$smb+=@{{name=$_.Name;path=$_.Path;desc=$_.Description}}}}
}}catch{{}}
Get-CimInstance Win32_Share -EA 0|ForEach-Object{{$wmi+=@{{name=$_.Name;path=$_.Path;type=$_.Type}}}}
$net=@($mounts|Where-Object{{$_.fstype -eq 'smb' -or $_.options -match 'type=Network'}})
$ctr=@($mounts|Where-Object{{$_.mount -match 'docker|wsl|containerd|kubelet' -or $_.device -match 'docker|wsl|containerd|kubelet'}})
$wex=@($mounts|Where-Object{{$_.writable -and -not $_.noexec}})
$result=[ordered]@{{
  summary=@{{total_mounts=$mounts.Count;nfs_smb=$net.Count;container_mounts=$ctr.Count;writable_exec=$wex.Count;local_shares=$smb.Count;mapped_drives=$mapped.Count;wmi_shares=$wmi.Count}}
  mounts=@($mounts|Select-Object -First 80)
  network_mounts=@($net|Select-Object -First 30)
  container_related=@($ctr|Select-Object -First 30)
  writable_executable=@($wex|Select-Object -First 30)
  smb_shares=$smb
  mapped_drives=$mapped
  wmi_shares=$wmi
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='mounts',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate mounts, SMB/NFS shares, mapped drives, and container filesystems',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'mounts',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=30.0,
    )
