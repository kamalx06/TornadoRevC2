"""Linux container runtime and workload enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, subprocess

def sh(cmd, timeout=12):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

def lines(cmd, limit=40):
    return [l.strip() for l in sh(cmd, timeout).splitlines() if l.strip()][:limit]

result = {'summary': {}, 'runtimes': {}, 'containers': [], 'images': [], 'networks': [], 'volumes': [], 'compose': [], 'kubernetes': {}}
detected = []

sockets = []
for path in ('/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock', '/run/containerd/containerd.sock', '/var/run/crio/crio.sock'):
    if os.path.exists(path):
        sockets.append(path)
result['runtime_sockets'] = sockets

if which('docker'):
    detected.append('docker')
    result['runtimes']['docker'] = {
        'version': sh('docker version --format "{{.Server.Version}}" 2>/dev/null').strip() or sh('docker --version 2>/dev/null').strip(),
        'info': sh('docker info --format "{{.OperatingSystem}} {{.Driver}} {{.CgroupDriver}}" 2>/dev/null').strip(),
    }
    for line in lines('docker ps -a --no-trunc --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null', 50):
        parts = line.split('\t')
        if parts:
            result['containers'].append({'runtime': 'docker', 'id': parts[0], 'name': parts[1] if len(parts) > 1 else '', 'image': parts[2] if len(parts) > 2 else '', 'status': parts[3] if len(parts) > 3 else ''})
    for line in lines('docker images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}" 2>/dev/null', 40):
        parts = line.split('\t')
        if parts:
            result['images'].append({'runtime': 'docker', 'name': parts[0], 'id': parts[1] if len(parts) > 1 else '', 'size': parts[2] if len(parts) > 2 else ''})
    result['networks'].extend([{'runtime': 'docker', 'line': l} for l in lines('docker network ls --format "{{.Name}}\t{{.Driver}}\t{{.Scope}}" 2>/dev/null', 25)])
    result['volumes'].extend([{'runtime': 'docker', 'line': l} for l in lines('docker volume ls --format "{{.Name}}\t{{.Driver}}" 2>/dev/null', 25)])
    compose = lines('docker compose ls --format json 2>/dev/null || docker-compose ls 2>/dev/null', 20)
    if compose:
        result['compose'].append({'runtime': 'docker', 'projects': compose})

if which('podman'):
    detected.append('podman')
    result['runtimes']['podman'] = {'version': sh('podman --version 2>/dev/null').strip()}
    for line in lines('podman ps -a --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null', 40):
        parts = line.split('\t')
        if parts:
            result['containers'].append({'runtime': 'podman', 'id': parts[0], 'name': parts[1] if len(parts) > 1 else '', 'image': parts[2] if len(parts) > 2 else '', 'status': parts[3] if len(parts) > 3 else ''})
    for line in lines('podman images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}" 2>/dev/null', 30):
        parts = line.split('\t')
        if parts:
            result['images'].append({'runtime': 'podman', 'name': parts[0], 'id': parts[1] if len(parts) > 1 else ''})

if which('crictl'):
    detected.append('crictl')
    result['runtimes']['crictl'] = {'version': sh('crictl --version 2>/dev/null').strip()}
    for line in lines('crictl ps -a 2>/dev/null', 30):
        if not line.lower().startswith('container'):
            result['containers'].append({'runtime': 'crictl', 'line': line})
    for line in lines('crictl images 2>/dev/null', 25):
        if not line.lower().startswith('image'):
            result['images'].append({'runtime': 'crictl', 'line': line})

if which('ctr'):
    detected.append('containerd')
    result['runtimes']['containerd'] = {'version': sh('ctr version 2>/dev/null').strip()}
    ns_out = sh('ctr namespaces list 2>/dev/null')
    if ns_out.strip():
        result['runtimes']['containerd']['namespaces'] = ns_out.splitlines()[:15]

if which('lxc-ls'):
    detected.append('lxc')
    result['runtimes']['lxc'] = {'containers': lines('lxc-ls -1 2>/dev/null', 30)}

if which('lxc'):
    detected.append('lxd')
    result['runtimes']['lxd'] = {'list': lines('lxc list --format csv -c n,s,4 2>/dev/null', 30)}

if which('kubectl'):
    detected.append('kubectl')
    k8s = {}
    k8s['version'] = sh('kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null').strip()
    k8s['context'] = sh('kubectl config current-context 2>/dev/null').strip()
    k8s['nodes'] = lines('kubectl get nodes -o wide --no-headers 2>/dev/null', 15)
    k8s['namespaces'] = lines('kubectl get ns --no-headers 2>/dev/null', 20)
    k8s['pods'] = lines('kubectl get pods -A --no-headers 2>/dev/null', 40)
    result['kubernetes'] = k8s

if os.path.isdir('/var/lib/docker/containers'):
    result['runtimes']['docker_data_dir'] = {'path': '/var/lib/docker/containers', 'entries': len(os.listdir('/var/lib/docker/containers'))}
if os.path.isdir('/var/lib/containerd'):
    result['runtimes']['containerd_data_dir'] = {'path': '/var/lib/containerd'}

result['summary'] = {
    'runtimes': ', '.join(detected) if detected else 'none detected',
    'containers': len(result['containers']),
    'images': len(result['images']),
    'networks': len(result['networks']),
    'volumes': len(result['volumes']),
    'compose_projects': len(result['compose']),
    'kubernetes': 'yes' if result['kubernetes'] else 'N/A',
    'runtime_sockets': len(sockets),
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(
    name='containers',
    platforms=['linux', 'unix'],
    description='Enumerate container runtimes and workloads: Docker, Podman, containerd, CRI-O, LXC/LXD, and Kubernetes',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'containers', build_command, None, format_generic_report, timeout=55.0)
