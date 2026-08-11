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


def _minify_python(source):
    lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        lines.append(stripped)
    return ';'.join(lines)


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
        out = __import__('subprocess').check_output(['ifconfig'], text=True, timeout=3)
        for match in __import__('re').findall(r'inet (\\d+\\.\\d+\\.\\d+\\.\\d+)', out):
            if not match.startswith('127.'):
                ips.add(match)
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

def get_locale():
    if not locale:
        return ''
    try:
        return ','.join(x for x in locale.getdefaultlocale() if x) or ''
    except Exception:
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
    'shell': os.environ.get('SHELL', ''),
    'uid': safe(lambda: os.geteuid(), '') if hasattr(os, 'geteuid') else '',
    'gid': safe(lambda: os.getegid(), '') if hasattr(os, 'getegid') else '',
    'is_root': bool(getattr(os, 'geteuid', lambda: -1)() == 0),
    'os': platform.system(),
    'os_release': platform.release(),
    'os_version': platform.version(),
    'kernel': safe(lambda: platform.uname().release),
    'architecture': platform.machine(),
    'platform': platform.platform(),
    'cpu_count': safe(lambda: os.cpu_count(), ''),
    'memory': get_memory(),
    'disk': get_disk(),
    'uptime': get_uptime(),
    'timezone': safe(lambda: '/'.join(x for x in time.tzname if x)),
    'locale': get_locale(),
    'ip_addresses': get_ips(),
    'cwd': os.getcwd(),
    'pid': os.getpid(),
    'python': sys.version.split()[0],
}}
print('{SYSINFO_MARK_START}' + json.dumps(info) + '{SYSINFO_MARK_END}', end='')
"""


def _unix_collect_cmd():
    script = _minify_python(_unix_collector_source())
    return (
        f"python3 -c \"{script}\" 2>/dev/null || "
        f"python -c \"{script}\" 2>/dev/null || "
        f"(printf '%s' '{SYSINFO_MARK_START}'; "
        f"printf '{{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"unknown\",\"cwd\":\"%s\"}}' "
        f"\"$(hostname 2>/dev/null)\" \"$(whoami 2>/dev/null || id -un 2>/dev/null)\" "
        f"\"$(pwd 2>/dev/null)\"; "
        f"printf '%s' '{SYSINFO_MARK_END}')"
    )


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


def build_collect_commands(shell_type):
    unix_cmd = _unix_collect_cmd()
    win_ps = _win_collect_ps()
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


def format_sysinfo(info, colors=None):
    if not info:
        return 'System information unavailable'
    c = colors or {}
    bold = c.get('bold', '')
    green = c.get('green', '')
    cyan = c.get('cyan', '')
    yellow = c.get('yellow', '')
    end = c.get('end', '')
    lines = [f"{bold}{green}System Information{end}"]
    seen = set()
    for section, keys in SYSINFO_SECTIONS:
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
