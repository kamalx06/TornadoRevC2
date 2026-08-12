"""Fast Linux host assessment collector for QuickEnum."""

from ..api import plugin, SessionContext
from ..shared.common import format_quickenum_report
from ..shared.runner import run_collector_plugin
from ..windows._quickenum import build_command as build_windows_cmd
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, platform, re, socket, subprocess, time
start = time.time()
findings = []

def sh(cmd, timeout=3):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def exists(p):
    try:
        return os.path.exists(p)
    except Exception:
        return False

def add_f(text):
    if text and text not in findings:
        findings.append(text)

hostname = sh('hostname 2>/dev/null').strip() or platform.node()
user = sh('id -un 2>/dev/null').strip() or os.environ.get('USER', '')
uid = sh('id -u 2>/dev/null').strip()
gid = sh('id -g 2>/dev/null').strip()
sudo = 'yes' if sh('sudo -n true 2>/dev/null && echo ok').strip() == 'ok' else (
    'yes' if os.geteuid() == 0 else sh('grep -E "^[^#].*ALL=.*NOPASSWD" /etc/sudoers 2>/dev/null | head -1') and 'possible' or 'no'
)
if os.geteuid() == 0:
    sudo = 'yes (root)'

os_name = platform.system()
try:
    with open('/etc/os-release') as f:
        for line in f:
            if line.startswith('PRETTY_NAME='):
                os_name = line.split('=', 1)[1].strip().strip('"')
                break
except Exception:
    pass
kernel = sh('uname -r 2>/dev/null').strip()
arch = platform.machine() or sh('uname -m 2>/dev/null').strip()
cwd = os.getcwd()

# Environment / container (condensed virtualization plugin checks)
cgroup = ''
try:
    with open('/proc/1/cgroup') as f:
        cgroup = f.read()
except Exception:
    pass
env_type = 'Physical host'
runtime = ''
orch = ''
ns = os.environ.get('KUBERNETES_NAMESPACE', os.environ.get('POD_NAMESPACE', ''))
if exists('/.dockerenv'):
    env_type = 'Docker container'; runtime = 'docker'; add_f('Docker container (.dockerenv)')
if exists('/run/.containerenv'):
    env_type = 'Podman container'; runtime = 'podman'; add_f('Podman container')
if 'kubepods' in cgroup or os.environ.get('KUBERNETES_SERVICE_HOST'):
    orch = 'Kubernetes'; env_type = 'Kubernetes pod/container'; add_f('Kubernetes environment')
if os.environ.get('WSL_DISTRO_NAME'):
    env_type = 'WSL'; add_f('WSL environment')
docker_sock = exists('/var/run/docker.sock') or exists('/run/docker.sock')
if docker_sock:
    add_f('Docker socket present')
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect('/var/run/docker.sock' if exists('/var/run/docker.sock') else '/run/docker.sock')
        s.close()
        add_f('Docker socket exposed (accessible)')
    except Exception:
        pass

cloud = ''
try:
    from urllib.request import Request, urlopen
    req = Request('http://169.254.169.254/latest/meta-data/instance-id', headers={'Metadata': 'true'})
    r = urlopen(req, timeout=1).read(32).decode()
    if r:
        cloud = 'AWS'; add_f('Cloud instance (AWS metadata)')
except Exception:
    pass

# Network
ips = set()
try:
    for line in sh('ip -4 -o addr 2>/dev/null || ifconfig 2>/dev/null').splitlines():
        for tok in line.split():
            if re.match(r'\\d+\\.\\d+\\.\\d+\\.\\d+', tok.split('/')[0]) and not tok.startswith('127.'):
                ips.add(tok.split('/')[0])
except Exception:
    pass
gateway = sh("ip route 2>/dev/null | awk '/default/ {print $3; exit}'").strip()
dns = sh('grep nameserver /etc/resolv.conf 2>/dev/null | awk "{print $2}" | tr "\\n" ", "').strip().strip(',')
ports_raw = sh('ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null')
ports = []
for line in ports_raw.splitlines()[:30]:
    m = re.search(r':(\\d+)\\s', line)
    if m:
        ports.append(m.group(1))
ports = sorted(set(ports), key=int)[:20]

# Storage
mounts = []
writable_exec = []
try:
    with open('/proc/mounts') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4:
                opts = parts[3].split(',')
                mounts.append(parts[1])
                if 'rw' in opts and 'noexec' not in opts:
                    writable_exec.append(parts[1])
except Exception:
    pass
if writable_exec:
    add_f('Writable+executable mount points: ' + ', '.join(writable_exec[:5]))

# Systemd / cron
systemd = sh('systemctl is-system-running 2>/dev/null').strip() or 'unknown'
failed = len(sh('systemctl --failed --no-legend 2>/dev/null').splitlines())
cron_lines = sh('grep -hrEv "^#|^$" /etc/cron* 2>/dev/null | head -5').strip().splitlines()

# SSH / history / secrets (condensed secrets plugin checks)
cred_files = []
for p in (
    os.path.expanduser('~/.ssh/id_rsa'), os.path.expanduser('~/.ssh/authorized_keys'),
    os.path.expanduser('~/.aws/credentials'), os.path.expanduser('~/.docker/config.json'),
    os.path.expanduser('~/.kube/config'), '.env', '../.env', '/etc/passwd',
):
    if exists(p) and os.path.isfile(p):
        cred_files.append(p)
        if 'authorized_keys' in p:
            add_f('SSH authorized_keys present')
        if p.endswith('.env') or '.env' in p:
            add_f('.env file found')
        if 'credentials' in p:
            add_f('Cloud credentials file found')
hist = []
for p in (os.path.expanduser('~/.bash_history'), os.path.expanduser('~/.zsh_history')):
    if exists(p):
        hist.append(p)
        add_f('Shell history file present')

result = {
    'host_summary': {
        'Hostname': hostname,
        'OS': os_name,
        'Kernel': kernel,
        'Architecture': arch,
    },
    'user': {
        'User': user,
        'UID': uid,
        'GID': gid,
        'Sudo': sudo,
        'CWD': cwd,
    },
    'environment': {
        'Type': env_type,
        'Runtime': runtime or None,
        'Orchestrator': orch or None,
        'Namespace': ns or None,
        'Cloud': cloud or None,
    },
    'network': {
        'IP': ', '.join(sorted(ips)) or None,
        'Default Gateway': gateway or None,
        'DNS': dns or None,
        'Listening Ports': ', '.join(ports) if ports else None,
    },
    'storage': {
        'Mount Count': len(mounts),
        'Writable+Exec Mounts': ', '.join(writable_exec[:8]) if writable_exec else 'none',
    },
    'services': {
        'Systemd': systemd,
        'Failed Units': failed,
    },
    'persistence': {
        'Recent Cron Entries': len(cron_lines),
        'Cron Sample': '; '.join(c[:80] for c in cron_lines[:3]) if cron_lines else None,
    },
    'credentials': {
        'Sensitive Files': ', '.join(cred_files[:10]) if cred_files else 'none detected',
        'History Files': ', '.join(hist) if hist else 'none',
    },
    'findings': findings,
    'elapsed_sec': round(time.time() - start, 2),
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(
    name='quickenum',
    platforms=['linux', 'windows', 'unix'],
    description='Fast structured host assessment (hostname, user, network, findings)',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'quickenum',
        build_command,
        build_windows_cmd,
        format_quickenum_report,
        timeout=75.0,
    )
