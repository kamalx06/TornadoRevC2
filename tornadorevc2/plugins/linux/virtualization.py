"""Aggressive Linux virtualization and container detection collector."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_virtualization_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, re, socket, stat, struct, subprocess, sys, time
try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen

CLOUD_TIMEOUT = 1.0

def rd(p):
    try:
        with open(p, 'r', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''

def ex(p):
    try:
        return os.path.exists(p)
    except Exception:
        return False

def hit(d, k, text, weight=15):
    e = d.setdefault(k, {'detected': False, 'confidence': 0, 'indicators': []})
    if text and text not in e['indicators']:
        e['indicators'].append(text)
        e['detected'] = True
        e['confidence'] = min(100, e['confidence'] + weight)

def cloud_probe(url, hdr=None):
    try:
        req = Request(url, headers=hdr or {})
        r = urlopen(req, timeout=CLOUD_TIMEOUT)
        return r.read(512).decode('utf-8', 'ignore')[:256]
    except Exception:
        return ''

def readlink(p):
    try:
        return os.readlink(p)
    except Exception:
        return ''

def ns_ids():
    out = {}
    try:
        st = os.stat('/proc/self/ns/pid')
        out['pid'] = st.st_ino
        st = os.stat('/proc/self/ns/mnt')
        out['mnt'] = st.st_ino
        st = os.stat('/proc/self/ns/net')
        out['net'] = st.st_ino
        st = os.stat('/proc/self/ns/uts')
        out['uts'] = st.st_ino
        st = os.stat('/proc/1/ns/pid')
        out['pid_host'] = st.st_ino
    except Exception:
        pass
    return out

def sock_access(path):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(path)
        s.close()
        return True
    except Exception:
        return False

def main():
    det = {}
    indicators = []
    artifacts = []
    sockets = []
    env = dict(os.environ)
    cgroup = rd('/proc/1/cgroup') + rd('/proc/self/cgroup')
    mountinfo = rd('/proc/self/mountinfo')
    cpuinfo = rd('/proc/cpuinfo').lower()
    modules = rd('/proc/modules').lower()
    version = rd('/proc/version').lower()
    status = rd('/proc/self/status')
    cmdline = rd('/proc/cmdline')
    cloud_meta = {}

    # Docker
    if ex('/.dockerenv'):
        hit(det, 'docker', '/.dockerenv present', 25); artifacts.append('/.dockerenv')
    if 'docker' in cgroup.lower():
        hit(det, 'docker', 'docker hierarchy in cgroup', 20)
    if env.get('container') == 'docker':
        hit(det, 'docker', 'container=docker env', 15)
    for s in ('/var/run/docker.sock', '/run/docker.sock'):
        if ex(s):
            hit(det, 'docker', s + ' present', 15); sockets.append(s)
            if sock_access(s):
                hit(det, 'docker', s + ' accessible (host bridge risk)', 25)

    # Podman
    if ex('/run/.containerenv'):
        hit(det, 'podman', '/run/.containerenv present', 25); artifacts.append('/run/.containerenv')
    if 'podman' in cgroup.lower() or env.get('container') == 'podman':
        hit(det, 'podman', 'podman container markers', 20)
    for s in ('/run/podman/podman.sock', '/var/run/podman/podman.sock'):
        if ex(s):
            hit(det, 'podman', s, 15); sockets.append(s)

    # containerd / CRI-O
    for s in ('/run/containerd/containerd.sock', '/var/run/containerd/containerd.sock'):
        if ex(s):
            hit(det, 'containerd', s, 20); sockets.append(s)
    if 'containerd' in cgroup.lower() or 'cri-containerd' in cgroup.lower():
        hit(det, 'containerd', 'containerd in cgroup', 20)
    for s in ('/var/run/crio/crio.sock', '/run/crio/crio.sock'):
        if ex(s):
            hit(det, 'crio', s, 20); sockets.append(s)
    if 'crio' in cgroup.lower():
        hit(det, 'crio', 'CRI-O in cgroup', 20)

    # Kubernetes
    if env.get('KUBERNETES_SERVICE_HOST'):
        hit(det, 'kubernetes', 'KUBERNETES_SERVICE_HOST=' + env['KUBERNETES_SERVICE_HOST'], 25)
    if ex('/var/run/secrets/kubernetes.io/serviceaccount/token'):
        hit(det, 'kubernetes', 'K8s service account token', 25)
        artifacts.append('/var/run/secrets/kubernetes.io/serviceaccount/token')
    if 'kubepods' in cgroup.lower():
        hit(det, 'kubernetes', 'kubepods cgroup hierarchy', 20)
    sa_ns = rd('/var/run/secrets/kubernetes.io/serviceaccount/namespace').strip()
    pod = env.get('HOSTNAME', '')

    # LXC/LXD
    if 'lxc' in cgroup.lower() or env.get('container') in ('lxc', 'lxd'):
        hit(det, 'lxc_lxd', 'LXC/LXD markers', 20)
    if ex('/dev/lxd/sock'):
        hit(det, 'lxc_lxd', '/dev/lxd/sock', 15); sockets.append('/dev/lxd/sock')

    # systemd-nspawn
    if env.get('container') == 'systemd-nspawn' or ex('/run/systemd/container'):
        hit(det, 'systemd_nspawn', 'systemd-nspawn container', 20)

    # OpenVZ/Virtuozzo
    if ex('/proc/vz') or 'openvz' in cgroup.lower() or 'veid' in env:
        hit(det, 'openvz', 'OpenVZ/Virtuozzo markers', 20)

    # WSL
    if env.get('WSL_DISTRO_NAME') or 'microsoft' in version or ex('/proc/sys/fs/binfmt_misc/WSLInterop'):
        hit(det, 'wsl', 'WSL environment detected', 25)

    # DMI
    dmi = {}
    dmi_dir = '/sys/class/dmi/id'
    if os.path.isdir(dmi_dir):
        for k in ('product_name', 'sys_vendor', 'board_vendor', 'bios_vendor', 'chassis_vendor', 'product_serial'):
            v = rd(os.path.join(dmi_dir, k)).strip()
            if v and 'o.e.m' not in v.lower():
                dmi[k] = v
    blob = ' '.join(dmi.values()).lower()

    hv_rules = {
        'vmware': (['vmware'], ['vmw', 'vmxnet'], []),
        'virtualbox': (['virtualbox', 'innotek', 'vbox'], ['vboxguest', 'vboxsf'], []),
        'hyperv': (['microsoft', 'hyper-v'], ['hv_', 'hyperv', 'vmbus'], []),
        'kvm': (['kvm', 'qemu'], ['kvm', 'virtio'], ['hypervisor']),
        'qemu': (['qemu', 'bochs'], ['virtio'], []),
        'xen': (['xen'], ['xen'], []),
    }
    if ex('/proc/xen'):
        hit(det, 'xen', '/proc/xen present', 25)
    if ex('/sys/hypervisor/type'):
        hvtype = rd('/sys/hypervisor/type').strip()
        hit(det, 'hypervisor', '/sys/hypervisor/type=' + hvtype, 20)

    for hv, (dmi_t, mod_t, cpu_t) in hv_rules.items():
        for t in dmi_t:
            if t in blob:
                hit(det, hv, 'DMI match: ' + t, 20)
        for t in mod_t:
            if t in modules:
                hit(det, hv, 'kernel module: ' + t, 15)
        for t in cpu_t:
            if t in cpuinfo:
                hit(det, hv, 'cpuinfo: ' + t, 15)

    # Cloud VMs
    cloud_ep = [
        ('aws', 'http://169.254.169.254/latest/meta-data/instance-id', {'Metadata': 'true'}),
        ('azure', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', {'Metadata': 'true'}),
        ('gcp', 'http://metadata.google.internal/computeMetadata/v1/instance/id', {'Metadata-Flavor': 'Google'}),
        ('oci', 'http://169.254.169.254/opc/v1/instance/', {}),
        ('digitalocean', 'http://169.254.169.254/metadata/v1/id', {}),
    ]
    cloud_provider = ''
    for name, url, hdr in cloud_ep:
        resp = cloud_probe(url, hdr)
        if resp:
            hit(det, 'cloud_' + name, name.upper() + ' metadata endpoint responded', 25)
            cloud_meta[name] = resp[:120]
            cloud_provider = cloud_provider or name.upper()

    # cgroup v2
    cg2 = ' cgroup2 ' in (' ' + mountinfo + ' ') or ex('/sys/fs/cgroup/cgroup.controllers')
    if cg2:
        hit(det, 'cgroup', 'cgroup v2 detected', 10)
    if '0::/' in cgroup or '0::/init.scope' in cgroup:
        hit(det, 'cgroup', 'cgroup v2 unified hierarchy', 10)

    # Capabilities / privileged container hints
    caps = ''
    for line in status.splitlines():
        if line.startswith('CapEff:'):
            caps = line.split(':', 1)[1].strip()
    privileged = caps.endswith('ffffffff') or caps.endswith('ffffffffffffffff')
    if privileged:
        hit(det, 'privileges', 'effective capabilities appear fully privileged', 20)

    # Nested virt
    nested = 'nested' in cmdline.lower() or 'kvm_intel' in modules and 'nested' in rd('/sys/module/kvm_intel/parameters/nested').lower()
    nested_txt = 'Detected' if nested else 'Not detected'

    # Hardware virt in guest
    hw_virt = 'vmx' in cpuinfo or 'svm' in cpuinfo

    # Sandbox heuristics
    sandbox = []
    if dmi.get('product_name', '').lower() in ('virtualbox', 'vmware virtual platform', 'kvm'):
        sandbox.append('generic analysis VM product name')
    if dmi.get('sys_vendor', '').lower() in ('qemu', 'innotek', 'xen'):
        sandbox.append('common VM vendor string')
    try:
        if os.path.isdir('/home') and len(os.listdir('/home')) <= 1 and ex('/.dockerenv'):
            sandbox.append('minimal home + container (possible sandbox)')
    except Exception:
        pass

    namespaces = ns_ids()
    in_container = any(det.get(k, {}).get('detected') for k in (
        'docker', 'podman', 'containerd', 'crio', 'kubernetes', 'lxc_lxd', 'systemd_nspawn', 'openvz'
    )) or ex('/.dockerenv') or ex('/run/.containerenv')

    runtime = ''
    if det.get('docker', {}).get('detected'): runtime = 'Docker'
    elif det.get('podman', {}).get('detected'): runtime = 'Podman'
    elif det.get('containerd', {}).get('detected'): runtime = 'containerd'
    elif det.get('crio', {}).get('detected'): runtime = 'CRI-O'
    elif det.get('lxc_lxd', {}).get('detected'): runtime = 'LXC/LXD'
    elif det.get('systemd_nspawn', {}).get('detected'): runtime = 'systemd-nspawn'

    orchestrator = 'Kubernetes' if det.get('kubernetes', {}).get('detected') else ''
    virt_type = ''
    for hv in ('vmware', 'virtualbox', 'hyperv', 'kvm', 'qemu', 'xen'):
        if det.get(hv, {}).get('detected'):
            virt_type = hv.upper() if hv != 'hyperv' else 'Hyper-V'
            break

    if det.get('wsl', {}).get('detected'):
        env_type = 'WSL Environment'
    elif in_container:
        env_type = (orchestrator + ' Container') if orchestrator else ((runtime or 'Container') + ' Container')
    elif virt_type or cloud_provider:
        env_type = 'Virtual Machine'
    else:
        env_type = 'Physical Host'

    host_rel = 'bare metal'
    if in_container and (virt_type or cloud_provider):
        host_rel = 'container on virtual machine'
    elif in_container:
        host_rel = 'container on host'
    elif virt_type or cloud_provider:
        host_rel = 'guest virtual machine'

    host_access = []
    for s in ('/var/run/docker.sock', '/run/docker.sock'):
        if s in sockets and sock_access(s):
            host_access.append('Docker socket exposed and accessible')

    # Aggregate confidence
    scores = [v.get('confidence', 0) for v in det.values() if v.get('detected')]
    confidence = min(100, max(scores) if scores else (30 if env_type != 'Physical Host' else 5))
    if len(scores) >= 3:
        confidence = min(100, confidence + 15)
    if host_access:
        confidence = min(100, confidence + 10)

    for v in det.values():
        for i in v.get('indicators') or []:
            if i not in indicators:
                indicators.append(i)

    result = {
        'environment_type': env_type,
        'runtime': runtime,
        'orchestrator': orchestrator,
        'namespace': sa_ns or env.get('KUBERNETES_NAMESPACE', ''),
        'node': env.get('KUBERNETES_NODE_NAME', env.get('NODE_NAME', '')),
        'container_id': pod if in_container else '',
        'host_relationship': host_rel,
        'virtualization_type': virt_type,
        'cloud_provider': cloud_provider,
        'host_access': '; '.join(host_access) if host_access else 'None detected',
        'container_privileges': 'Likely privileged/full caps' if privileged else 'Standard/non-privileged',
        'nested_virtualization': nested_txt,
        'hardware_virtualization': 'Available in guest CPU' if hw_virt else 'Not detected in guest',
        'sandbox_indicators': '; '.join(sandbox) if sandbox else 'None',
        'confidence': confidence,
        'indicators': indicators[:60],
        'namespaces': namespaces,
        'sockets': sockets,
        'artifacts': artifacts,
        'cloud_metadata': cloud_meta,
        'detections': det,
        'dmi': dmi,
    }
    _emit(result)

main()
'''


def build_command():
    return build_linux_collector_command(_collector_source())
