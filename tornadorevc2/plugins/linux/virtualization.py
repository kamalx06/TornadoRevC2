"""Linux virtualization and container detection collector."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...sysinfo import _b64_exec_cmd


def _linux_collector_source():
    return r'''
import json, os, re, socket

MARK_START = "''' + PLUGIN_MARK_START + r'''"
MARK_END = "''' + PLUGIN_MARK_END + r'''"

def safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default

def read_text(path):
    try:
        with open(path, 'r', errors='ignore') as fh:
            return fh.read()
    except Exception:
        return ''

def file_exists(path):
    try:
        return os.path.exists(path)
    except Exception:
        return False

def read_lines(path):
    text = read_text(path)
    return text.splitlines() if text else []

def add_indicator(bucket, text):
    if text and text not in bucket:
        bucket.append(text)

def detect():
    indicators = []
    sockets = []
    artifacts = []
    detections = {}

    cgroup_text = read_text('/proc/1/cgroup') + '\n' + read_text('/proc/self/cgroup')
    mountinfo = read_text('/proc/self/mountinfo')
    version_text = read_text('/proc/version').lower()
    cpuinfo = read_text('/proc/cpuinfo').lower()
    env = dict(os.environ)

    def set_det(name, detected, confidence='low', extra=None):
        entry = detections.setdefault(name, {'detected': False, 'confidence': 'none', 'indicators': []})
        if detected:
            entry['detected'] = True
            order = {'none': 0, 'low': 1, 'medium': 2, 'high': 3}
            if order.get(confidence, 0) > order.get(entry['confidence'], 0):
                entry['confidence'] = confidence
        if extra:
            for item in extra:
                if item not in entry['indicators']:
                    entry['indicators'].append(item)

    # Docker
    docker_hits = []
    if file_exists('/.dockerenv'):
        docker_hits.append('/.dockerenv present')
        artifacts.append('/.dockerenv')
    if 'docker' in cgroup_text.lower():
        docker_hits.append('docker in cgroup')
    if env.get('container') == 'docker':
        docker_hits.append('container=docker env')
    for sock in ('/var/run/docker.sock', '/run/docker.sock'):
        if file_exists(sock):
            docker_hits.append(sock)
            sockets.append(sock)
    set_det('docker', bool(docker_hits), 'high' if file_exists('/.dockerenv') else 'medium', docker_hits)

    # Podman
    podman_hits = []
    if file_exists('/run/.containerenv'):
        podman_hits.append('/run/.containerenv present')
        artifacts.append('/run/.containerenv')
    if env.get('container') == 'podman':
        podman_hits.append('container=podman env')
    if 'podman' in cgroup_text.lower():
        podman_hits.append('podman in cgroup')
    for sock in ('/run/podman/podman.sock', '/var/run/podman/podman.sock'):
        if file_exists(sock):
            podman_hits.append(sock)
            sockets.append(sock)
    set_det('podman', bool(podman_hits), 'high' if file_exists('/run/.containerenv') else 'medium', podman_hits)

    # Kubernetes
    k8s_hits = []
    if env.get('KUBERNETES_SERVICE_HOST'):
        k8s_hits.append('KUBERNETES_SERVICE_HOST=' + env.get('KUBERNETES_SERVICE_HOST', ''))
    if file_exists('/var/run/secrets/kubernetes.io/serviceaccount/token'):
        k8s_hits.append('service account token present')
        artifacts.append('/var/run/secrets/kubernetes.io/serviceaccount/token')
    if 'kubepods' in cgroup_text.lower() or 'kube' in cgroup_text.lower():
        k8s_hits.append('kube in cgroup')
    if file_exists('/etc/kubernetes/kubelet.conf'):
        k8s_hits.append('/etc/kubernetes/kubelet.conf')
        artifacts.append('/etc/kubernetes/kubelet.conf')
    set_det('kubernetes', bool(k8s_hits), 'high' if env.get('KUBERNETES_SERVICE_HOST') else 'medium', k8s_hits)

    # LXC / LXD
    lxc_hits = []
    if 'lxc' in cgroup_text.lower():
        lxc_hits.append('lxc in cgroup')
    if env.get('container') in ('lxc', 'lxd'):
        lxc_hits.append('container=' + env.get('container'))
    for path in ('/proc/1/environ',):
        txt = read_text(path)
        if 'lxc' in txt.lower():
            lxc_hits.append('lxc in /proc/1/environ')
    if file_exists('/dev/lxd/sock'):
        lxc_hits.append('/dev/lxd/sock')
        sockets.append('/dev/lxd/sock')
    set_det('lxc_lxd', bool(lxc_hits), 'medium', lxc_hits)

    # systemd-nspawn
    nspawn_hits = []
    if env.get('container') == 'systemd-nspawn':
        nspawn_hits.append('container=systemd-nspawn env')
    if file_exists('/run/systemd/container'):
        nspawn_hits.append('/run/systemd/container')
        artifacts.append('/run/systemd/container')
        nspawn_hits.append(read_text('/run/systemd/container').strip())
    set_det('systemd_nspawn', bool(nspawn_hits), 'high' if nspawn_hits else 'none', nspawn_hits)

    # WSL
    wsl_hits = []
    if 'microsoft' in version_text or 'wsl' in version_text:
        wsl_hits.append('/proc/version indicates WSL')
    if env.get('WSL_DISTRO_NAME'):
        wsl_hits.append('WSL_DISTRO_NAME=' + env['WSL_DISTRO_NAME'])
    if file_exists('/proc/sys/fs/binfmt_misc/WSLInterop'):
        wsl_hits.append('WSLInterop binfmt')
    set_det('wsl', bool(wsl_hits), 'high' if env.get('WSL_DISTRO_NAME') else 'medium', wsl_hits)

    # DMI / SMBIOS
    dmi_dir = '/sys/class/dmi/id'
    dmi = {}
    if os.path.isdir(dmi_dir):
        for key in ('product_name', 'sys_vendor', 'board_vendor', 'bios_vendor', 'chassis_vendor'):
            val = read_text(os.path.join(dmi_dir, key)).strip()
            if val and val not in ('None', 'To Be Filled By O.E.M.'):
                dmi[key] = val

    vendor_blob = ' '.join(dmi.values()).lower()

    # Hypervisors
    hv_map = {
        'vmware': (['vmware'], ['vmware'], ['vmw_']),
        'virtualbox': (['virtualbox', 'innotek', 'vbox'], ['vboxguest', 'vboxsf'], []),
        'hyperv': (['microsoft', 'hyper-v'], ['hv_', 'hyperv'], []),
        'kvm': (['kvm', 'qemu'], ['kvm'], ['hypervisor']),
        'qemu': (['qemu', 'bochs'], [], []),
        'xen': (['xen'], ['xen'], []),
    }

    modules_text = read_text('/proc/modules').lower()
    for hv, (dmi_keys, mod_keys, cpu_keys) in hv_map.items():
        hits = []
        for token in dmi_keys:
            if token in vendor_blob:
                hits.append('DMI vendor/product: ' + token)
        for token in mod_keys:
            if token in modules_text:
                hits.append('kernel module: ' + token)
        for token in cpu_keys:
            if token in cpuinfo:
                hits.append('cpuinfo: ' + token)
        if hv == 'kvm' and 'hypervisor' in cpuinfo:
            hits.append('CPU hypervisor flag set')
        conf = 'high' if len(hits) >= 2 else ('medium' if hits else 'none')
        set_det(hv, bool(hits), conf, hits)

    # Generic container signals
    in_container = bool(
        file_exists('/.dockerenv') or file_exists('/run/.containerenv')
        or env.get('container') or 'docker' in cgroup_text.lower()
        or 'kubepods' in cgroup_text.lower() or 'lxc' in cgroup_text.lower()
    )

    # Derive summary
    runtime = None
    orchestrator = None
    environment_type = 'Physical Host'
    virtualization_type = None
    confidence = 'low'
    container_id = env.get('HOSTNAME', '')
    namespace = env.get('KUBERNETES_NAMESPACE') or env.get('POD_NAMESPACE')
    node = env.get('KUBERNETES_NODE_NAME') or env.get('NODE_NAME')

    if detections.get('docker', {}).get('detected'):
        runtime = 'docker'
    elif detections.get('podman', {}).get('detected'):
        runtime = 'podman'
    elif detections.get('lxc_lxd', {}).get('detected'):
        runtime = 'lxc/lxd'
    elif detections.get('systemd_nspawn', {}).get('detected'):
        runtime = 'systemd-nspawn'

    if detections.get('kubernetes', {}).get('detected'):
        orchestrator = 'Kubernetes'
    if detections.get('wsl', {}).get('detected'):
        environment_type = 'WSL Environment'
        virtualization_type = 'WSL'
        confidence = detections['wsl']['confidence']
    elif in_container:
        if orchestrator:
            environment_type = orchestrator + ' Pod/Container'
        else:
            environment_type = (runtime or 'container').title() + ' Container'
        confidence = 'high' if runtime else 'medium'
    else:
        for hv in ('vmware', 'virtualbox', 'hyperv', 'kvm', 'qemu', 'xen'):
            if detections.get(hv, {}).get('detected'):
                virtualization_type = hv.upper() if hv != 'hyperv' else 'Hyper-V'
                environment_type = 'Virtual Machine'
                confidence = detections[hv]['confidence']
                break

    host_relationship = 'bare metal'
    if in_container and virtualization_type:
        host_relationship = 'container on virtual machine'
    elif in_container:
        host_relationship = 'container on host'
    elif virtualization_type:
        host_relationship = 'guest virtual machine'

    for det in detections.values():
        for ind in det.get('indicators') or []:
            add_indicator(indicators, ind)

    return {
        'environment_type': environment_type,
        'container_id': container_id[:64] if in_container else '',
        'runtime': runtime or '',
        'orchestrator': orchestrator or '',
        'namespace': namespace or '',
        'node': node or '',
        'virtualization_type': virtualization_type or '',
        'host_relationship': host_relationship,
        'confidence': confidence,
        'indicators': indicators[:40],
        'sockets': sockets,
        'artifacts': artifacts,
        'detections': detections,
        'dmi': dmi,
    }

result = detect()
print(MARK_START + json.dumps(result, separators=(',', ':')) + MARK_END)
'''


def build_linux_detection_command():
    source = _linux_collector_source()
    interpreters = [
        ('python3', 'python'),
        ('python', 'python'),
        ('python2', 'python'),
    ]
    body = _b64_exec_cmd(source, interpreters)
    return f"({body}) 2>/dev/null; true"
