"""Fast structured host assessment — Linux and Windows collectors."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_quickenum_report
from .runner import run_collector_plugin


def _linux_collector_source():
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


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$findings=@(); function Add-F($t){{ if($t -and ($findings -notcontains $t)){{ $findings+=$t }} }}
$sw=[Diagnostics.Stopwatch]::StartNew()
$cs=Get-CimInstance Win32_ComputerSystem -EA 0
$os=Get-CimInstance Win32_OperatingSystem -EA 0
$hostname=$env:COMPUTERNAME
$user=$env:USERNAME
$domain=$cs.Domain
$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isDomain=($cs.PartOfDomain -eq $true)
$build=$os.BuildNumber
$arch=$env:PROCESSOR_ARCHITECTURE
$osName=$os.Caption

# Virtualization / container
$envType='Physical host'
$bios=(Get-CimInstance Win32_BIOS -EA 0).SerialNumber
$model=$cs.Model
if($model -match 'Virtual|VMware|Hyper-V|KVM|QEMU|Xen|VirtualBox'){{ $envType='Virtual machine'; Add-F "Virtual machine ($model)" }}
if($env:COMPUTERNAME -match 'docker|container'){{ $envType='Container'; Add-F 'Container hostname pattern' }}
if(Test-Path '\\.\pipe\docker_engine'){{ Add-F 'Docker engine pipe present' }}
if($env:KUBERNETES_SERVICE_HOST){{ Add-F 'Kubernetes environment'; $envType='Kubernetes pod/container' }}

# Cloud
$cloud=''
try{{
  $r=Invoke-WebRequest -Uri 'http://169.254.169.254/latest/meta-data/instance-id' -Headers @{{Metadata='true'}} -TimeoutSec 1 -UseBasicParsing
  if($r.Content){{ $cloud='AWS'; Add-F 'Cloud instance (AWS metadata)' }}
}}catch{{}}

# Network
$ips=@()
Get-NetIPAddress -AddressFamily IPv4 -EA 0|Where-Object{{ $_.IPAddress -ne '127.0.0.1' }}|ForEach-Object{{ $ips+=$_.IPAddress }}
$gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA 0|Select-Object -First 1).NextHop
$dns=(Get-DnsClientServerAddress -AddressFamily IPv4 -EA 0|Select-Object -ExpandProperty ServerAddresses -Unique) -join ', '
$ports=@()
Get-NetTCPConnection -State Listen -EA 0|Select-Object -ExpandProperty LocalPort -Unique|Sort-Object|Select-Object -First 20|ForEach-Object{{ $ports+=$_ }}

# Shares
$shares=@()
Get-SmbShare -EA 0|ForEach-Object{{ $shares+="$($_.Name) ($($_.Path))" }}

# Services (notable)
$svcCount=(Get-Service -EA 0).Count
$running=(Get-Service -EA 0|Where-Object Status -eq Running).Count

# Scheduled tasks
$tasks=(Get-ScheduledTask -EA 0|Where-Object State -ne Disabled).Count

# Defender / security
$def=@{{}}; $secProducts=@()
try{{
  $st=Get-MpComputerStatus -EA 0
  $def.realtime=$st.RealTimeProtectionEnabled
  $def.signatures=$st.AntivirusSignatureVersion
  $def.tamper=$st.IsTamperProtected
}}catch{{}}
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA 0|ForEach-Object{{ $secProducts+=$_.displayName }}

# Registry autoruns (sample)
$autoruns=@()
$runKeys=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
foreach($rk in $runKeys){{
  if(Test-Path $rk){{
    Get-ItemProperty $rk -EA 0|Get-Member -MemberType NoteProperty|Where-Object Name -notmatch '^PS'|ForEach-Object{{
      $autoruns+="$($_.Name)"
    }}
  }}
}}
if($autoruns.Count -gt 0){{ Add-F "Registry autoruns: $($autoruns.Count) entries" }}

# PowerShell history
$psHist=$false
$histPath=(Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
if(Test-Path $histPath){{ $psHist=$true; Add-F 'PowerShell history present' }}

# Credential artifacts
$creds=@()
$paths=@(
  "$env:USERPROFILE\.aws\credentials",
  "$env:USERPROFILE\.ssh\id_rsa",
  "$env:USERPROFILE\.docker\config.json",
  "$env:USERPROFILE\.kube\config"
)
foreach($p in $paths){{ if(Test-Path $p){{ $creds+=$p; Add-F "Sensitive file: $p" }} }}

# Certificates summary
$certCount=(Get-ChildItem Cert:\CurrentUser\My -EA 0).Count + (Get-ChildItem Cert:\LocalMachine\My -EA 0).Count

$result=[ordered]@{{
  host_summary=@{{Hostname=$hostname;OS=$osName;Build=$build;Architecture=$arch}}
  user=@{{User=$user;Admin=$isAdmin;Domain=$domain;DomainJoined=$isDomain}}
  environment=@{{Type=$envType;Cloud=$cloud;Model=$model;BIOS=$bios}}
  network=@{{IP=($ips -join ', ');Default_Gateway=$gw;DNS=$dns;Listening_Ports=($ports -join ', ')}}
  storage=@{{SMB_Shares=($shares -join '; ')}}
  services=@{{Total=$svcCount;Running=$running;Scheduled_Tasks=$tasks}}
  security=@{{Defender_RealTime=$def.realtime;Defender_Signatures=$def.signatures;Security_Products=($secProducts -join ', ');Autorun_Entries=($autoruns -join ', ')}}
  credentials=@{{Sensitive_Files=($creds -join ', ');PowerShell_History=$psHist;Certificate_Store_Count=$certCount}}
  findings=$findings
  elapsed_sec=[math]::Round($sw.Elapsed.TotalSeconds,2)
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='quickenum',
    platforms=['linux', 'windows', 'unix'],
    description='Fast structured host assessment (hostname, user, network, findings)',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'quickenum',
        _build_linux_command,
        _build_windows_command,
        format_quickenum_report,
        timeout=75.0,
    )
