"""Linux container runtime and workload enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_containers_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, stat, subprocess

def sh(cmd, timeout=12):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

def lines(cmd, limit=40, timeout=12):
    return [l.strip() for l in sh(cmd, timeout).splitlines() if l.strip()][:limit]

def tab_rows(cmd, fields, limit=50, timeout=12):
    rows = []
    for line in lines(cmd, limit, timeout):
        parts = line.split('\t')
        if not parts or not parts[0]:
            continue
        row = {}
        for i, key in enumerate(fields):
            row[key] = parts[i] if i < len(parts) else ''
        rows.append(row)
    return rows

def socket_info(path):
    info = {'path': path, 'exists': os.path.exists(path)}
    if not info['exists']:
        return info
    try:
        st = os.stat(path)
        info['mode'] = oct(st.st_mode)[-4:]
        info['socket'] = stat.S_ISSOCK(st.st_mode)
    except Exception:
        pass
    return info

def try_json(cmd, timeout=10):
    raw = sh(cmd, timeout).strip()
    if not raw or raw[0] not in '[{':
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

def add_runtime(result, name, meta):
    if meta:
        result['runtimes'][name] = meta
        if name not in result['detected_runtimes']:
            result['detected_runtimes'].append(name)

result = {
    'summary': {},
    'detected_runtimes': [],
    'runtime_sockets': [],
    'runtimes': {},
    'containers': [],
    'images': [],
    'networks': [],
    'volumes': [],
    'pods': [],
    'compose_projects': [],
    'kubernetes': {},
    'systemd_units': [],
    'container_processes': [],
}

# Runtime sockets and data directories
for path in (
    '/var/run/docker.sock', '/run/docker.sock',
    '/run/podman/podman.sock', '/var/run/podman/podman.sock',
    '/run/containerd/containerd.sock', '/var/run/containerd/containerd.sock',
    '/var/run/crio/crio.sock', '/run/crio/crio.sock',
    '/dev/lxd/sock',
):
    info = socket_info(path)
    if info.get('exists'):
        result['runtime_sockets'].append(info)

for path, label in (
    ('/var/lib/docker', 'docker'),
    ('/var/lib/containerd', 'containerd'),
    ('/var/lib/kubelet', 'kubelet'),
    ('/var/lib/rancher/k3s', 'k3s'),
    ('/var/snap/microk8s', 'microk8s'),
):
    if os.path.isdir(path):
        try:
            count = len(os.listdir(path))
        except Exception:
            count = 'N/A'
        result['runtimes'].setdefault('data_dirs', []).append({'runtime': label, 'path': path, 'entries': count})

# Container-related systemd units
for line in lines('systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | grep -Ei "docker|container|kube|crio|podman|lxd|containerd" | head -25', 25, 8):
    parts = line.split(None, 4)
    if parts:
        result['systemd_units'].append({
            'unit': parts[0],
            'load': parts[1] if len(parts) > 1 else '',
            'active': parts[2] if len(parts) > 2 else '',
            'sub': parts[3] if len(parts) > 3 else '',
            'desc': parts[4][:100] if len(parts) > 4 else '',
        })

# Running container-related processes
for line in lines('ps aux 2>/dev/null | grep -E "dockerd|containerd|kubelet|crio|podman|lxc|k3s" | grep -v grep | head -20', 20, 8):
    parts = line.split(None, 10)
    if len(parts) >= 11:
        result['container_processes'].append({'user': parts[0], 'pid': parts[1], 'cmd': parts[10][:140]})

# Docker
if which('docker'):
    meta = {
        'version': sh('docker version --format "{{.Server.Version}}" 2>/dev/null').strip() or sh('docker --version 2>/dev/null').strip(),
        'client': sh('docker version --format "{{.Client.Version}}" 2>/dev/null').strip(),
        'rootless': sh('docker info --format "{{.SecurityOptions}}" 2>/dev/null').strip(),
        'storage_driver': sh('docker info --format "{{.Driver}}" 2>/dev/null').strip(),
        'cgroup_driver': sh('docker info --format "{{.CgroupDriver}}" 2>/dev/null').strip(),
        'runtimes': sh('docker info --format "{{.Runtimes}}" 2>/dev/null').strip()[:200],
        'swarm': sh('docker info --format "{{.Swarm.LocalNodeState}}" 2>/dev/null').strip(),
        'service': sh('systemctl is-active docker 2>/dev/null').strip(),
    }
    add_runtime(result, 'docker', meta)
    for row in tab_rows(
        'docker ps -a --no-trunc --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.RunningFor}}\t{{.Labels}}"',
        ['id', 'name', 'image', 'status', 'state', 'ports', 'running_for', 'labels'], 60, 15,
    ):
        row['runtime'] = 'docker'
        result['containers'].append(row)
    for row in tab_rows(
        'docker images -a --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"',
        ['repository', 'tag', 'id', 'size', 'created'], 50, 12,
    ):
        row['runtime'] = 'docker'
        row['name'] = (row.get('repository', '') + ':' + row.get('tag', '')).strip(':')
        result['images'].append(row)
    for row in tab_rows(
        'docker network ls --format "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}"',
        ['id', 'name', 'driver', 'scope'], 30, 8,
    ):
        row['runtime'] = 'docker'
        result['networks'].append(row)
    for row in tab_rows(
        'docker volume ls --format "{{.Name}}\t{{.Driver}}"',
        ['name', 'driver'], 30, 8,
    ):
        row['runtime'] = 'docker'
        result['volumes'].append(row)
    compose = try_json('docker compose ls -a --format json 2>/dev/null', 10)
    if compose:
        for item in compose[:20]:
            if isinstance(item, dict):
                item['runtime'] = 'docker'
                result['compose_projects'].append(item)
    else:
        for line in lines('docker compose ls -a 2>/dev/null || docker-compose ls 2>/dev/null', 20, 10):
            result['compose_projects'].append({'runtime': 'docker', 'line': line})
    stacks = lines('docker stack ls 2>/dev/null', 15, 8)
    if stacks:
        result['runtimes']['docker']['stacks'] = stacks

# Podman
if which('podman'):
    meta = {
        'version': sh('podman --version 2>/dev/null').strip(),
        'rootless': sh('podman info --format "{{.Host.Security.Rootless}}" 2>/dev/null').strip(),
        'graph_driver': sh('podman info --format "{{.Store.GraphDriverName}}" 2>/dev/null').strip(),
        'service': sh('systemctl is-active podman 2>/dev/null').strip(),
    }
    add_runtime(result, 'podman', meta)
    for row in tab_rows(
        'podman ps -a --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.Labels}}"',
        ['id', 'name', 'image', 'status', 'state', 'ports', 'labels'], 50, 12,
    ):
        row['runtime'] = 'podman'
        result['containers'].append(row)
    for row in tab_rows(
        'podman pod ps -a --format "{{.ID}}\t{{.Name}}\t{{.Status}}\t{{.Containers}}"',
        ['id', 'name', 'status', 'containers'], 25, 10,
    ):
        row['runtime'] = 'podman'
        result['pods'].append(row)
    for row in tab_rows(
        'podman images -a --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"',
        ['repository', 'tag', 'id', 'size'], 40, 10,
    ):
        row['runtime'] = 'podman'
        row['name'] = (row.get('repository', '') + ':' + row.get('tag', '')).strip(':')
        result['images'].append(row)
    for row in tab_rows(
        'podman network ls --format "{{.Name}}\t{{.Driver}}"',
        ['name', 'driver'], 25, 8,
    ):
        row['runtime'] = 'podman'
        result['networks'].append(row)
    for row in tab_rows(
        'podman volume ls --format "{{.Name}}\t{{.Driver}}"',
        ['name', 'driver'], 25, 8,
    ):
        row['runtime'] = 'podman'
        result['volumes'].append(row)

# nerdctl (containerd frontend)
if which('nerdctl'):
    meta = {'version': sh('nerdctl --version 2>/dev/null').strip()}
    add_runtime(result, 'nerdctl', meta)
    for row in tab_rows(
        'nerdctl ps -a --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"',
        ['id', 'name', 'image', 'status', 'ports'], 40, 12,
    ):
        row['runtime'] = 'nerdctl'
        result['containers'].append(row)

# crictl (Kubernetes/CRI-O/containerd)
if which('crictl'):
    meta = {
        'version': sh('crictl --version 2>/dev/null').strip(),
        'runtime_endpoint': sh('crictl config runtime-endpoint 2>/dev/null || grep runtime-endpoint /etc/crictl.yaml 2>/dev/null | head -1').strip(),
    }
    add_runtime(result, 'crictl', meta)
    pods_json = try_json('crictl pods -o json 2>/dev/null', 10)
    if pods_json and isinstance(pods_json, dict) and pods_json.get('items'):
        for item in pods_json['items'][:30]:
            meta = item.get('metadata') or {}
            status = item.get('status') or {}
            result['pods'].append({
                'runtime': 'crictl',
                'id': meta.get('id', '')[:16],
                'name': meta.get('name', ''),
                'namespace': meta.get('namespace', ''),
                'state': status.get('state', ''),
            })
    else:
        for line in lines('crictl pods 2>/dev/null', 30, 10):
            if line.lower().startswith('pod'):
                continue
            result['pods'].append({'runtime': 'crictl', 'line': line})
    ctr_json = try_json('crictl ps -a -o json 2>/dev/null', 10)
    if ctr_json and isinstance(ctr_json, dict) and ctr_json.get('containers'):
        for item in ctr_json['containers'][:40]:
            meta = item.get('metadata') or {}
            status = item.get('status') or {}
            result['containers'].append({
                'runtime': 'crictl',
                'id': meta.get('id', '')[:16],
                'name': meta.get('name', ''),
                'image': status.get('image', {}).get('image', '') if isinstance(status.get('image'), dict) else '',
                'state': status.get('state', ''),
            })
    else:
        for line in lines('crictl ps -a 2>/dev/null', 35, 10):
            if line.lower().startswith('container'):
                continue
            result['containers'].append({'runtime': 'crictl', 'line': line})
    img_json = try_json('crictl images -o json 2>/dev/null', 10)
    if img_json and isinstance(img_json, dict) and img_json.get('images'):
        for item in img_json['images'][:35]:
            spec = item.get('status') or {}
            result['images'].append({
                'runtime': 'crictl',
                'id': (item.get('id') or '')[:16],
                'name': spec.get('id', ''),
                'size': spec.get('size', ''),
            })
    else:
        for line in lines('crictl images 2>/dev/null', 30, 10):
            if line.lower().startswith('image'):
                continue
            result['images'].append({'runtime': 'crictl', 'line': line})

# containerd (ctr)
if which('ctr'):
    meta = {'version': sh('ctr version 2>/dev/null').strip()}
    add_runtime(result, 'containerd', meta)
    namespaces = [n.strip() for n in lines('ctr namespaces list -q 2>/dev/null', 10, 8) if n.strip()]
    if namespaces:
        meta['namespaces'] = namespaces[:10]
    ctr_containers = []
    for ns in namespaces[:5]:
        for line in lines(f'ctr -n {ns} containers list 2>/dev/null', 20, 8):
            if line.strip():
                ctr_containers.append({'namespace': ns, 'line': line.strip()[:180]})
    if ctr_containers:
        result['runtimes']['containerd']['containers'] = ctr_containers[:40]
    ctr_images = []
    for ns in namespaces[:5]:
        for line in lines(f'ctr -n {ns} images list 2>/dev/null', 15, 8):
            if line.strip():
                ctr_images.append({'namespace': ns, 'line': line.strip()[:180]})
    if ctr_images:
        result['runtimes']['containerd']['images'] = ctr_images[:30]

# CRI-O status
if which('crio') or os.path.exists('/var/run/crio/crio.sock') or os.path.exists('/run/crio/crio.sock'):
    meta = {'version': sh('crio --version 2>/dev/null || crio version 2>/dev/null').strip()}
    meta['status'] = sh('crio-status info 2>/dev/null || crictl info 2>/dev/null | head -20').strip()[:500]
    add_runtime(result, 'crio', meta)

# LXC / LXD
if which('lxc-ls'):
    add_runtime(result, 'lxc', {'containers': lines('lxc-ls -f -1 2>/dev/null || lxc-ls -1 2>/dev/null', 30, 8)})
if which('lxc'):
    lxd = {
        'version': sh('lxc --version 2>/dev/null').strip(),
        'list': lines('lxc list -c ns4S6t --format csv 2>/dev/null', 30, 10),
        'profiles': lines('lxc profile list --format csv -c n,d 2>/dev/null', 20, 8),
        'networks': lines('lxc network list --format csv -c n,t,b 2>/dev/null', 20, 8),
    }
    add_runtime(result, 'lxd', lxd)

# systemd-nspawn / machinectl
if which('machinectl'):
    machines = lines('machinectl list --no-legend --no-pager 2>/dev/null', 25, 8)
    if machines:
        add_runtime(result, 'systemd_nspawn', {'machines': machines})

# Kubernetes (kubectl)
k8s = {}
if which('kubectl'):
    k8s['client_version'] = sh('kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null').strip()
    k8s['context'] = sh('kubectl config current-context 2>/dev/null').strip()
    k8s['cluster'] = sh('kubectl config view --minify -o jsonpath="{.clusters[0].name}" 2>/dev/null').strip()
    k8s['api_server'] = sh('kubectl cluster-info 2>/dev/null | head -3').strip()
    k8s['nodes'] = lines('kubectl get nodes -o wide --no-headers 2>/dev/null', 20, 12)
    k8s['namespaces'] = lines('kubectl get ns --no-headers 2>/dev/null', 25, 10)
    k8s['pods'] = lines('kubectl get pods -A -o wide --no-headers 2>/dev/null', 50, 15)
    k8s['deployments'] = lines('kubectl get deploy -A --no-headers 2>/dev/null', 30, 10)
    k8s['services'] = lines('kubectl get svc -A --no-headers 2>/dev/null', 30, 10)
    k8s['daemonsets'] = lines('kubectl get ds -A --no-headers 2>/dev/null', 20, 10)
    add_runtime(result, 'kubectl', {'available': 'yes'})
if which('helm'):
    k8s['helm_releases'] = lines('helm list -A --no-headers 2>/dev/null', 25, 10)
if os.path.isdir('/var/lib/rancher/k3s') or which('k3s'):
    k8s['k3s'] = sh('k3s --version 2>/dev/null; systemctl is-active k3s 2>/dev/null').strip()
if which('microk8s'):
    k8s['microk8s'] = sh('microk8s status --format short 2>/dev/null || microk8s status 2>/dev/null | head -15').strip()
sa_base = '/var/run/secrets/kubernetes.io/serviceaccount'
if os.path.isdir(sa_base):
    k8s['in_cluster'] = {
        'namespace': sh(f'cat {sa_base}/namespace 2>/dev/null').strip(),
        'token_present': os.path.isfile(os.path.join(sa_base, 'token')),
        'ca_present': os.path.isfile(os.path.join(sa_base, 'ca.crt')),
    }
if k8s:
    result['kubernetes'] = k8s
    if 'kubectl' not in result['detected_runtimes'] and (which('kubectl') or k8s.get('in_cluster')):
        result['detected_runtimes'].append('kubernetes')

running = sum(1 for c in result['containers'] if str(c.get('state', c.get('status', ''))).lower() in ('running', 'up'))

result['summary'] = {
    'runtimes': ', '.join(result['detected_runtimes']) if result['detected_runtimes'] else 'none detected',
    'containers_total': len(result['containers']),
    'containers_running': running,
    'images': len(result['images']),
    'networks': len(result['networks']),
    'volumes': len(result['volumes']),
    'pods': len(result['pods']),
    'compose_projects': len(result['compose_projects']),
    'kubernetes': 'yes' if result['kubernetes'] else 'N/A',
    'runtime_sockets': len(result['runtime_sockets']),
    'systemd_units': len(result['systemd_units']),
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
    return run_collector_plugin(
        session,
        'containers',
        build_command,
        None,
        format_containers_report,
        timeout=75.0,
    )
