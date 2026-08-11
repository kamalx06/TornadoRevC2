import base64
import json
import re

from .constants import SYSINFO_MARK_END, SYSINFO_MARK_START


def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)


def _extract_marked(output, start_mark, end_mark):
    output = _strip_ansi(output)
    start = output.rfind(start_mark)
    if start == -1:
        return None
    end = output.find(end_mark, start + len(start_mark))
    if end == -1:
        return None
    payload = output[start + len(start_mark):end]
    return payload.strip()


def _b64_exec_cmd(source, interpreters):
    payload = base64.b64encode(source.strip().encode('utf-8')).decode('ascii')
    parts = []
    for name, flag in interpreters:
        parts.append(
            f"{name} -c 'import base64; exec(base64.b64decode(\"{payload}\"))' 2>/dev/null"
            if flag == 'python'
            else f"echo {payload} | base64 {flag} 2>/dev/null | {name} 2>/dev/null"
        )
    return ' || '.join(parts)


def _unix_collector_source():
    return f"""
import json, os, platform, shutil, socket, sys, time
try:
    import locale
except ImportError:
    locale = None

def safe(fn, default=''):
    try:
        val = fn()
        return default if val is None else val
    except Exception:
        return default

def get_shell():
    sh = os.environ.get('SHELL', '')
    if sh:
        return sh
    try:
        return __import__('pwd').getpwuid(os.getuid()).pw_shell
    except Exception:
        return ''

def get_os_name():
    try:
        with open('/etc/os-release') as fh:
            for line in fh:
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return platform.system()

def get_ips():
    ips = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = item[4][0]
            if not ip.startswith('127.'):
                ips.add(ip)
    except Exception:
        pass
    try:
        out = __import__('subprocess').check_output(
            ['hostname', '-I'], stderr=__import__('subprocess').DEVNULL, text=True, timeout=2
        )
        for ip in out.split():
            if not ip.startswith('127.'):
                ips.add(ip)
    except Exception:
        pass
    try:
        out = __import__('subprocess').check_output(
            ['ip', '-4', '-o', 'addr'], stderr=__import__('subprocess').DEVNULL, text=True, timeout=3
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3].split('/')[0]
                if not ip.startswith('127.'):
                    ips.add(ip)
    except Exception:
        pass
    return ', '.join(sorted(ips))

def get_uptime():
    try:
        secs = float(open('/proc/uptime').read().split()[0])
    except Exception:
        try:
            out = __import__('subprocess').check_output(['sysctl', '-n', 'kern.boottime'], text=True, timeout=2)
            boot = int(out.split('=')[-1].strip().split()[0].strip(','))
            secs = time.time() - boot
        except Exception:
            return ''
    total = int(secs)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(str(days) + 'd')
    if hours:
        parts.append(str(hours) + 'h')
    parts.append(str(minutes) + 'm')
    return ' '.join(parts)

def get_memory():
    try:
        mem = {{}}
        with open('/proc/meminfo') as fh:
            for line in fh:
                key, val = line.split(':', 1)
                mem[key.strip()] = int(val.strip().split()[0])
        total = mem.get('MemTotal', 0) // 1024
        avail = mem.get('MemAvailable', mem.get('MemFree', 0)) // 1024
        return str(avail) + ' MB free / ' + str(total) + ' MB total'
    except Exception:
        try:
            out = __import__('subprocess').check_output(['sysctl', '-n', 'hw.memsize'], text=True, timeout=2)
            total = int(out.strip()) // (1024 * 1024)
            return str(total) + ' MB total'
        except Exception:
            return ''

def get_disk():
    try:
        usage = shutil.disk_usage(os.getcwd())
        free_gb = usage.free / (1024 ** 3)
        total_gb = usage.total / (1024 ** 3)
        return '{{:.1f}} GB free / {{:.1f}} GB total'.format(free_gb, total_gb)
    except Exception:
        return ''

def get_timezone():
    tz = '/'.join(x for x in time.tzname if x)
    if tz:
        return tz
    tz_env = os.environ.get('TZ', '')
    if tz_env:
        return tz_env
    try:
        with open('/etc/timezone') as fh:
            return fh.read().strip()
    except Exception:
        pass
    try:
        out = __import__('subprocess').check_output(
            ['timedatectl', 'show', '-p', 'Timezone', '--value'],
            stderr=__import__('subprocess').DEVNULL, text=True, timeout=2,
        )
        return out.strip()
    except Exception:
        return ''

def get_locale():
    for key in ('LC_ALL', 'LANG', 'LC_CTYPE'):
        val = os.environ.get(key, '')
        if val:
            return val
    if locale:
        try:
            loc = locale.getlocale()
            return ','.join(x for x in loc if x) or ''
        except Exception:
            pass
    return ''

user = os.environ.get('USER') or os.environ.get('LOGNAME') or ''
try:
    user = user or __import__('getpass').getuser()
except Exception:
    pass

info = {{
    'hostname': socket.gethostname(),
    'fqdn': safe(lambda: socket.getfqdn()),
    'username': user,
    'home': safe(lambda: os.path.expanduser('~')),
    'shell': get_shell(),
    'uid': safe(lambda: os.geteuid(), '') if hasattr(os, 'geteuid') else '',
    'gid': safe(lambda: os.getegid(), '') if hasattr(os, 'getegid') else '',
    'is_root': bool(getattr(os, 'geteuid', lambda: -1)() == 0),
    'os': get_os_name(),
    'os_release': platform.release(),
    'os_version': platform.version(),
    'kernel': safe(lambda: platform.uname().release),
    'architecture': platform.machine(),
    'platform': platform.platform(),
    'cpu_count': safe(lambda: os.cpu_count(), ''),
    'memory': get_memory(),
    'disk': get_disk(),
    'uptime': get_uptime(),
    'timezone': get_timezone(),
    'locale': get_locale(),
    'ip_addresses': get_ips(),
    'cwd': os.getcwd(),
    'pid': os.getpid(),
    'python': sys.version.split()[0],
    'collection_mode': 'full',
}}
print('{SYSINFO_MARK_START}' + json.dumps(info) + '{SYSINFO_MARK_END}', end='')
"""


def _unix_shell_fallback_source():
    return f"""#!/bin/sh
# POSIX shell sysinfo collector (used when Python is unavailable)
START='{SYSINFO_MARK_START}'
END='{SYSINFO_MARK_END}'

json_escape() {{
    printf '%s' "$1" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g'
}}

num_or_empty() {{
    case "$1" in
        ''|*[!0-9]*) printf '' ;;
        *) printf '%s' "$1" ;;
    esac
}}

hostname_val=$(hostname 2>/dev/null)
fqdn_val=$(hostname -f 2>/dev/null)
[ -z "$fqdn_val" ] && fqdn_val="$hostname_val"
username_val=$(id -un 2>/dev/null || whoami 2>/dev/null)
home_val=${{HOME:-$(eval echo "~$username_val" 2>/dev/null)}}
shell_val=${{SHELL:-$(getent passwd "$username_val" 2>/dev/null | cut -d: -f7)}}
uid_val=$(id -u 2>/dev/null)
gid_val=$(id -g 2>/dev/null)
is_root=no
[ "$uid_val" = "0" ] && is_root=yes
os_val=$(uname -s 2>/dev/null)
kernel_val=$(uname -r 2>/dev/null)
arch_val=$(uname -m 2>/dev/null)
platform_val="$os_val $kernel_val $arch_val"
cpu_count_val=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null)
cpu_count_val=$(num_or_empty "$cpu_count_val")

memory_val=""
if [ -r /proc/meminfo ]; then
    total_kb=$(awk '/^MemTotal:/ {{print $2}}' /proc/meminfo)
    avail_kb=$(awk '/^MemAvailable:/ {{print $2}}' /proc/meminfo)
    [ -z "$avail_kb" ] && avail_kb=$(awk '/^MemFree:/ {{print $2}}' /proc/meminfo)
    if [ -n "$total_kb" ]; then
        total_mb=$((total_kb / 1024))
        avail_mb=$((avail_kb / 1024))
        memory_val="${{avail_mb}} MB free / ${{total_mb}} MB total"
    fi
fi

disk_val=""
if df -B1 . >/dev/null 2>&1; then
    set -- $(df -B1 . 2>/dev/null | awk 'NR==2 {{print $2, $4}}')
    if [ -n "$1" ] && [ -n "$2" ]; then
        total_gb=$(awk -v b="$1" 'BEGIN {{printf "%.1f", b/1073741824}}')
        free_gb=$(awk -v b="$2" 'BEGIN {{printf "%.1f", b/1073741824}}')
        disk_val="${{free_gb}} GB free / ${{total_gb}} GB total"
    fi
fi

uptime_val=""
if [ -r /proc/uptime ]; then
    secs=$(awk '{{print int($1)}}' /proc/uptime)
    days=$((secs / 86400))
    rem=$((secs % 86400))
    hours=$((rem / 3600))
    minutes=$(((rem % 3600) / 60))
    uptime_val=""
    [ "$days" -gt 0 ] && uptime_val="${{days}}d "
    [ "$hours" -gt 0 ] && uptime_val="${{uptime_val}}${{hours}}h "
    uptime_val="${{uptime_val}}${{minutes}}m"
fi

ip_val=$(hostname -I 2>/dev/null | sed 's/127\\.[0-9.]*//g; s/  */ /g; s/^ //; s/ $//; s/ /, /g')
if [ -z "$ip_val" ] && command -v ip >/dev/null 2>&1; then
    ip_val=$(ip -4 -o addr 2>/dev/null | awk '{{print $4}}' | cut -d/ -f1 | awk '!/^127\\./ && NF {{print}}' | tr '\\n' ',' | sed 's/,$//; s/,/, /g')
fi

timezone_val=${{TZ:-}}
[ -z "$timezone_val" ] && [ -r /etc/timezone ] && timezone_val=$(tr -d '\\n' </etc/timezone)
if [ -z "$timezone_val" ] && command -v timedatectl >/dev/null 2>&1; then
    timezone_val=$(timedatectl show -p Timezone --value 2>/dev/null)
fi

locale_val=${{LC_ALL:-${{LANG:-}}}}
cwd_val=$(pwd 2>/dev/null)
pid_val=$$
python_val=""

if [ -r /etc/os-release ]; then
    pretty=$(grep ^PRETTY_NAME= /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')
    [ -n "$pretty" ] && os_val="$pretty"
fi

printf '%s{{' "$START"
printf '"hostname":"%s",' "$(json_escape "$hostname_val")"
printf '"fqdn":"%s",' "$(json_escape "$fqdn_val")"
printf '"username":"%s",' "$(json_escape "$username_val")"
printf '"home":"%s",' "$(json_escape "$home_val")"
printf '"shell":"%s",' "$(json_escape "$shell_val")"
printf '"uid":"%s",' "$(json_escape "$uid_val")"
printf '"gid":"%s",' "$(json_escape "$gid_val")"
printf '"is_root":"%s",' "$is_root"
printf '"os":"%s",' "$(json_escape "$os_val")"
printf '"os_release":"%s",' "$(json_escape "$kernel_val")"
printf '"os_version":"%s",' "$(json_escape "$platform_val")"
printf '"kernel":"%s",' "$(json_escape "$kernel_val")"
printf '"architecture":"%s",' "$(json_escape "$arch_val")"
printf '"platform":"%s",' "$(json_escape "$platform_val")"
printf '"cpu_count":"%s",' "$(json_escape "$cpu_count_val")"
printf '"memory":"%s",' "$(json_escape "$memory_val")"
printf '"disk":"%s",' "$(json_escape "$disk_val")"
printf '"uptime":"%s",' "$(json_escape "$uptime_val")"
printf '"timezone":"%s",' "$(json_escape "$timezone_val")"
printf '"locale":"%s",' "$(json_escape "$locale_val")"
printf '"ip_addresses":"%s",' "$(json_escape "$ip_val")"
printf '"cwd":"%s",' "$(json_escape "$cwd_val")"
printf '"pid":"%s",' "$(json_escape "$pid_val")"
printf '"python":"%s"' "$(json_escape "$python_val")"
printf '}}%s' "$END"
"""


def _unix_stealth_collector_source():
    return f"""
import json, os, platform, socket, sys

def get_os_name():
    try:
        with open('/etc/os-release') as fh:
            for line in fh:
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return platform.system()

def get_ips():
    ips = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = item[4][0]
            if not ip.startswith('127.'):
                ips.add(ip)
    except Exception:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(('8.8.8.8', 80))
        ip = probe.getsockname()[0]
        probe.close()
        if ip and not ip.startswith('127.'):
            ips.add(ip)
    except Exception:
        pass
    try:
        with open('/proc/net/fib_trie') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('/32 host LOCAL'):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].count('.') == 3:
                    ip = parts[0]
                    if not ip.startswith('127.'):
                        ips.add(ip)
    except Exception:
        pass
    return ', '.join(sorted(ips))

user = os.environ.get('USER') or os.environ.get('LOGNAME') or ''
try:
    user = user or __import__('getpass').getuser()
except Exception:
    pass

info = {{
    'collection_mode': 'stealth',
    'hostname': socket.gethostname(),
    'username': user,
    'os': get_os_name(),
    'architecture': platform.machine(),
    'ip_addresses': get_ips(),
    'cwd': os.getcwd(),
    'pid': os.getpid(),
}}
print('{SYSINFO_MARK_START}' + json.dumps(info) + '{SYSINFO_MARK_END}', end='')
"""


def _unix_stealth_shell_fallback():
    return f"""#!/bin/sh
START='{SYSINFO_MARK_START}'
END='{SYSINFO_MARK_END}'
json_escape() {{ printf '%s' "$1" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g'; }}
hostname_val=$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null)
username_val=$(id -un 2>/dev/null || whoami 2>/dev/null)
os_val=$(uname -s 2>/dev/null)
arch_val=$(uname -m 2>/dev/null)
cwd_val=$(pwd 2>/dev/null)
pid_val=$$
if [ -r /etc/os-release ]; then
  pretty=$(grep ^PRETTY_NAME= /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')
  [ -n "$pretty" ] && os_val="$pretty"
fi
ip_val=""
if [ -r /proc/net/fib_trie ]; then
  ip_val=$(awk '/32 host LOCAL/{{next}} /^[0-9]/{{print $1}}' /proc/net/fib_trie 2>/dev/null | grep -v '^127\\.' | sort -u | tr '\\n' ',' | sed 's/,$//; s/,/, /g')
fi
printf '%s{{' "$START"
printf '"collection_mode":"stealth",'
printf '"hostname":"%s",' "$(json_escape "$hostname_val")"
printf '"username":"%s",' "$(json_escape "$username_val")"
printf '"os":"%s",' "$(json_escape "$os_val")"
printf '"architecture":"%s",' "$(json_escape "$arch_val")"
printf '"ip_addresses":"%s",' "$(json_escape "$ip_val")"
printf '"cwd":"%s",' "$(json_escape "$cwd_val")"
printf '"pid":"%s"' "$(json_escape "$pid_val")"
printf '}}%s' "$END"
"""


def _unix_stealth_collect_cmd():
    py_source = _unix_stealth_collector_source()
    sh_source = _unix_stealth_shell_fallback()
    py_cmd = _b64_exec_cmd(py_source, (
        ('python3', 'python'),
        ('python', 'python'),
    ))
    sh_cmd = _b64_exec_cmd(sh_source, (
        ('sh', '-d'),
        ('sh', '-D'),
    ))
    return f"{py_cmd} || {sh_cmd}"


def _win_stealth_ps():
    return f"""
$ErrorActionPreference = 'SilentlyContinue'
$os = [System.Environment]::OSVersion.VersionString
try {{ $os = (Get-CimInstance Win32_OperatingSystem).Caption }} catch {{}}
$ips = @(
    [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
    Where-Object {{ $_.AddressFamily -eq 'InterNetwork' -and $_.IPAddressToString -notlike '127.*' }} |
    ForEach-Object {{ $_.IPAddressToString }}
)
$info = @{{
    collection_mode = 'stealth'
    hostname = $env:COMPUTERNAME
    username = $env:USERNAME
    os = $os
    architecture = $env:PROCESSOR_ARCHITECTURE
    ip_addresses = ($ips | Sort-Object -Unique) -join ', '
    cwd = (Get-Location).Path
    pid = $PID
}}
'{SYSINFO_MARK_START}' + (ConvertTo-Json -Compress $info) + '{SYSINFO_MARK_END}'
"""


def _unix_collect_cmd():
    py_source = _unix_collector_source()
    sh_source = _unix_shell_fallback_source()
    py_cmd = _b64_exec_cmd(py_source, (
        ('python3', 'python'),
        ('python', 'python'),
    ))
    sh_cmd = _b64_exec_cmd(sh_source, (
        ('sh', '-d'),
        ('sh', '-D'),
    ))
    return f"{py_cmd} || {sh_cmd}"


def _win_collect_ps():
    return f"""
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$proc = Get-CimInstance Win32_Processor | Select-Object -First 1
$uptimeSpan = (Get-Date) - $os.LastBootUpTime
$uptime = @()
if ($uptimeSpan.Days) {{ $uptime += "$($uptimeSpan.Days)d" }}
if ($uptimeSpan.Hours) {{ $uptime += "$($uptimeSpan.Hours)h" }}
$uptime += "$($uptimeSpan.Minutes)m"
$uptimeText = ($uptime -join ' ')
$totalMemGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$freeMemMb = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
$memory = "$freeMemMb MB free / $totalMemGb GB total"
$driveName = (Get-Location).Drive.Name
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$driveName`:'"
if ($disk) {{
    $diskText = "{{0:N1}} GB free / {{1:N1}} GB total" -f ($disk.FreeSpace / 1GB), ($disk.Size / 1GB)
}} else {{
    $diskText = ''
}}
$ips = @(
    [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
    Where-Object {{ $_.AddressFamily -eq 'InterNetwork' -and $_.IPAddressToString -notlike '127.*' }} |
    ForEach-Object {{ $_.IPAddressToString }}
)
$ipText = ($ips | Sort-Object -Unique) -join ', '
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$info = @{{
    collection_mode = 'full'
    hostname = $env:COMPUTERNAME
    fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    username = $env:USERNAME
    domain = $env:USERDOMAIN
    home = $env:USERPROFILE
    is_admin = [bool]$isAdmin
    os = $os.Caption
    os_release = $os.Version
    os_version = $os.BuildNumber
    kernel = $os.Version
    architecture = $env:PROCESSOR_ARCHITECTURE
    platform = [System.Environment]::OSVersion.VersionString
    cpu_count = $env:NUMBER_OF_PROCESSORS
    cpu = $proc.Name
    memory = $memory
    disk = $diskText
    uptime = $uptimeText
    timezone = [System.TimeZoneInfo]::Local.DisplayName
    locale = [System.Globalization.CultureInfo]::CurrentCulture.Name
    ip_addresses = $ipText
    manufacturer = $cs.Manufacturer
    model = $cs.Model
    logged_on_user = $cs.UserName
    domain_joined = [bool]$cs.PartOfDomain
    system_directory = $os.SystemDirectory
    cwd = (Get-Location).Path
    pid = $PID
    powershell = $PSVersionTable.PSVersion.ToString()
}}
'{SYSINFO_MARK_START}' + (ConvertTo-Json -Compress $info) + '{SYSINFO_MARK_END}'
"""


def build_collect_commands(shell_type, mode='stealth'):
    if mode == 'full':
        unix_cmd = _unix_collect_cmd()
        win_ps = _win_collect_ps()
    else:
        unix_cmd = _unix_stealth_collect_cmd()
        win_ps = _win_stealth_ps()
    if shell_type == 'windows':
        return None, win_ps
    if shell_type == 'unix':
        return unix_cmd, None
    return unix_cmd, win_ps


def _stringify(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, (list, tuple, set)):
        return ', '.join(_stringify(v) for v in value if v not in (None, ''))
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value)


def parse_sysinfo(raw_payload):
    if not raw_payload:
        return None
    try:
        data = json.loads(raw_payload)
        if isinstance(data, dict):
            return {str(k): _stringify(v) for k, v in data.items()}
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def extract_sysinfo(output):
    payload = _extract_marked(output, SYSINFO_MARK_START, SYSINFO_MARK_END)
    return parse_sysinfo(payload)


SYSINFO_SECTIONS = (
    ('Identity', (
        'hostname', 'fqdn', 'username', 'domain', 'home',
        'uid', 'gid', 'is_root', 'is_admin', 'logged_on_user',
    )),
    ('System', (
        'os', 'os_release', 'os_version', 'kernel', 'architecture',
        'platform', 'manufacturer', 'model', 'domain_joined', 'system_directory',
    )),
    ('Resources', (
        'cpu', 'cpu_count', 'memory', 'disk', 'uptime',
    )),
    ('Network', (
        'ip_addresses', 'timezone', 'locale',
    )),
    ('Session', (
        'shell', 'cwd', 'pid', 'python', 'powershell',
    )),
)


SYSINFO_STEALTH_SECTIONS = (
    ('Essentials', (
        'hostname', 'username', 'os', 'architecture',
        'ip_addresses', 'cwd', 'pid',
    )),
)


def format_sysinfo(info, colors=None):
    if not info:
        return 'System information unavailable'
    c = colors or {}
    bold = c.get('bold', '')
    green = c.get('green', '')
    cyan = c.get('cyan', '')
    yellow = c.get('yellow', '')
    end = c.get('end', '')
    mode = info.get('collection_mode', 'stealth')
    lines = [f"{bold}{green}System Information{end} ({mode} mode)"]
    sections = SYSINFO_STEALTH_SECTIONS if mode == 'stealth' else SYSINFO_SECTIONS
    seen = {'collection_mode'}
    for section, keys in sections:
        section_lines = []
        for key in keys:
            value = info.get(key)
            if value:
                label = key.replace('_', ' ').title()
                section_lines.append(f"  {cyan}{label}:{end} {value}")
                seen.add(key)
        if section_lines:
            lines.append(f"{yellow}{section}{end}")
            lines.extend(section_lines)
    extras = []
    for key, value in sorted(info.items()):
        if key not in seen and value:
            label = key.replace('_', ' ').title()
            extras.append(f"  {cyan}{label}:{end} {value}")
    if extras:
        lines.append(f"{yellow}Other{end}")
        lines.extend(extras)
    return '\n'.join(lines)
