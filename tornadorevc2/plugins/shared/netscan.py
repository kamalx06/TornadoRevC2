from __future__ import annotations
import ipaddress
import json
import re
from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .runner import run_collector_plugin


# ---------------------------------------------------------------------------
# Port presets (nmap-style top-ports)
# ---------------------------------------------------------------------------

_TOP_10 = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]

_TOP_100 = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
    544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
]

_TOP_1000 = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
    42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163,
    179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464,
    465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548,
    554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667,
    668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777,
    783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903,
    911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007,
    1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
    1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
    1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053,
    1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065,
    1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
    1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
    1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102,
    1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119,
    1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145,
    1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174,
    1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217,
    1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287,
    1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433,
    1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556,
    1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718,
    1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839,
    1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974,
    1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
    2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040,
    2041, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099,
    2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160,
    2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301,
    2323, 2366, 2381, 2382, 2383, 2393, 2399, 2401, 2492, 2500, 2522, 2525,
    2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717,
    2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968,
    2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031,
    3050, 3052, 3071, 3077, 3080, 3089, 3118, 3128, 3129, 3150, 3159, 3216,
    3217, 3222, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404,
    3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737,
    3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
    3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129,
    4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567,
    4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030,
    5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120,
    5190, 5191, 5192, 5193, 5200, 5221, 5222, 5225, 5226, 5269, 5280, 5298,
    5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560,
    5566, 5631, 5633, 5666, 5672, 5678, 5679, 5718, 5730, 5800, 5801, 5802,
    5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902,
    5903, 5904, 5906, 5907, 5910, 5911, 5912, 5915, 5922, 5925, 5950, 5952,
    5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001,
    6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6544, 6565, 6566,
    6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788,
    6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019,
    7025, 7070, 7100, 7106, 7200, 7201, 7272, 7402, 7435, 7443, 7496, 7512,
    7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938,
    7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031,
    8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254,
    8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649,
    8651, 8652, 8654, 8701, 8800, 8873, 8880, 8888, 8889, 8899, 8994, 9000,
    9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090,
    9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290,
    9415, 9418, 9443, 9500, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9800,
    9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999,
    10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
    10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456,
    13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003,
    15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
    16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
    19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828,
    21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
    27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337,
    32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
    32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899,
    34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
    44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156,
    49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
    49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
    55055, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443,
    61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
]

TOP_PORT_PRESETS = {
    "10": _TOP_10,
    "100": _TOP_100,
    "1000": _TOP_1000,
}

MAX_TARGETS = 4096
DEFAULT_CONNECT_TIMEOUT = 0.3
LINUX_DEFAULT_CONCURRENCY = 4096
WINDOWS_DEFAULT_BATCH = 1024
WINDOWS_MAX_RUNSPACES = 64


# ---------------------------------------------------------------------------
# Argument parsing helpers
# ---------------------------------------------------------------------------

def _get_opt(args, names, default=None):
    if args is None:
        return default

    if not isinstance(args, (list, tuple)):
        for name in names:
            if isinstance(args, dict):
                if name in args and args[name] is not None:
                    return args[name]
            else:
                val = getattr(args, name, None)
                if val is not None:
                    return val
        return default

    forms = set()
    for name in names:
        forms.add(f"--{name}")
        if len(name) == 1:
            forms.add(f"-{name}")

    i = 0
    while i < len(args):
        tok = args[i]
        if "=" in tok and tok.split("=", 1)[0] in forms:
            _, value = tok.split("=", 1)
            return value
        if tok in forms:
            if i + 1 >= len(args):
                return default
            nxt = args[i + 1]
            if nxt.startswith("-") and nxt not in ("-",):
                return default
            return nxt
        i += 1

    return default


def _parse_ports(spec) -> list:
    if spec is None or str(spec).strip() == "":
        return list(_TOP_100)

    s = str(spec).strip().lower()

    m = re.fullmatch(r"top[\s\-_]?(\d+)", s)
    if m:
        key = m.group(1)
        if key not in TOP_PORT_PRESETS:
            raise ValueError(
                f"unsupported top-ports preset 'top{key}'. "
                f"Use one of: {', '.join(sorted(TOP_PORT_PRESETS))}"
            )
        return list(TOP_PORT_PRESETS[key])

    ports = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))

    ports = sorted(p for p in ports if 1 <= p <= 65535)
    if not ports:
        raise ValueError(f"no valid ports parsed from: {spec!r}")
    return ports


def _parse_targets(spec) -> list:
    if not spec or str(spec).strip() == "":
        raise ValueError(
            "no targets provided; pass --ip / -i (single IP, list, or CIDR)"
        )

    tokens = [t for t in re.split(r"[,\s]+", str(spec).strip()) if t]

    targets = []
    seen = set()
    for tok in tokens:
        if "/" in tok:
            net = ipaddress.ip_network(tok, strict=False)
            if net.num_addresses == 1:
                hosts = [net.network_address]
            elif net.num_addresses == 2:
                hosts = list(net)
            else:
                hosts = list(net.hosts())
            for host in hosts:
                ip = str(host)
                if ip not in seen:
                    seen.add(ip)
                    targets.append(ip)
        else:
            ip = str(ipaddress.ip_address(tok))
            if ip not in seen:
                seen.add(ip)
                targets.append(ip)

        if len(targets) > MAX_TARGETS:
            raise ValueError(
                f"target expansion exceeds limit of {MAX_TARGETS} hosts; "
                "narrow the CIDR or split the scan"
            )

    return targets


# ---------------------------------------------------------------------------
# Linux / unix collector — asyncio, non-blocking sockets
# ---------------------------------------------------------------------------

_LINUX_TEMPLATE = r'''
import asyncio, itertools, json, socket

_cfg = json.loads(__PAYLOAD__)
_targets = _cfg['targets']
_ports = _cfg['ports']
_timeout = _cfg['timeout']
_forced = _cfg.get('concurrency')

if _forced:
    _concurrency = int(_forced)
else:
    try:
        import resource
        _soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        _concurrency = max(256, min(16384, _soft - 64))
    except Exception:
        _concurrency = 512
_concurrency = max(1, _concurrency)

def _family(host):
    return socket.AF_INET6 if ':' in host else socket.AF_INET

_iter = itertools.product(_targets, _ports)

async def _worker(results):
    loop = asyncio.get_running_loop()
    while True:
        try:
            host, port = next(_iter)
        except StopIteration:
            return

        sock = socket.socket(_family(host), socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (host, port)),
                timeout=_timeout,
            )
        except Exception:
            pass
        else:
            lst = results.get(host)
            if lst is None:
                results[host] = [port]
            else:
                lst.append(port)
        finally:
            try:
                sock.close()
            except Exception:
                pass

async def _scan():
    results = {}
    workers = [
        asyncio.create_task(_worker(results)) for _ in range(_concurrency)
    ]
    await asyncio.gather(*workers)
    for h in results:
        results[h].sort()
    return results

open_ports = asyncio.run(_scan())

result = {
    'summary': {
        'targets': len(_targets),
        'ports_scanned': len(_ports),
        'hosts_with_open_ports': len(open_ports),
        'open_ports_total': sum(len(v) for v in open_ports.values()),
        'concurrency': _concurrency,
    },
    'targets': _targets,
    'ports': _ports,
    'open_ports': open_ports,
}
_emit(result)
'''


def _build_linux_command(targets, ports, connect_timeout, concurrency=None):
    payload = {
        "targets": targets,
        "ports": ports,
        "timeout": connect_timeout,
        "concurrency": concurrency,
    }
    src = _LINUX_TEMPLATE.replace("__PAYLOAD__", repr(json.dumps(payload)))
    return build_linux_collector_command(src)


# ---------------------------------------------------------------------------
# Windows collector — runspace pool + parallel BeginConnect per host
# ---------------------------------------------------------------------------

_WINDOWS_TEMPLATE = r"""
$ErrorActionPreference='SilentlyContinue'
$start='__START__'; $end='__END__'

$payload  = '__PAYLOAD__' | ConvertFrom-Json
$targets  = @($payload.targets)
$ports    = @($payload.ports)
$timeoutMs = [int]([double]$payload.timeout * 1000)
if ($timeoutMs -lt 100) { $timeoutMs = 100 }

$batchSize    = __BATCH__
$maxRunspaces = __MAXRS__
if ($targets.Count -lt $maxRunspaces) { $maxRunspaces = $targets.Count }
if ($maxRunspaces -lt 1) { $maxRunspaces = 1 }

$workerScript = @'
param($h, $ports, $timeoutMs, $batchSize)
$found = New-Object System.Collections.ArrayList
$n = $ports.Length
for ($i = 0; $i -lt $n; $i += $batchSize) {
    $endIdx = [Math]::Min($i + $batchSize, $n) - 1
    $batch  = @($ports[$i..$endIdx])

    $pending = New-Object System.Collections.Generic.List[object]
    foreach ($p in $batch) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $client.NoDelay = $true
            $iar = $client.BeginConnect($h, [int]$p, $null, $null)
            $pending.Add([pscustomobject]@{
                Port = [int]$p; Client = $client; IAR = $iar
            })
        } catch {
            try { $client.Close() } catch {}
        }
    }

    $deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs + 100)
    foreach ($item in $pending) {
        $remaining = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remaining -lt 1) { $remaining = 1 }
        try {
            if ($item.IAR.AsyncWaitHandle.WaitOne($remaining, $false)) {
                try {
                    $item.Client.EndConnect($item.IAR)
                    if ($item.Client.Connected) {
                        [void]$found.Add($item.Port)
                    }
                } catch {}
            }
        } catch {}
        try { $item.Client.Close() } catch {}
    }
}

if ($found.Count -eq 0) { return '[]' }
return (@($found | Sort-Object -Unique) | ConvertTo-Json -Compress)
'@

$openPorts = @{}

if ($targets.Count -gt 0) {
    $pool = [runspacefactory]::CreateRunspacePool(8, $maxRunspaces)
    $pool.Open()

    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($workerScript)
        [void]$ps.AddArgument($h)
        [void]$ps.AddArgument($ports)
        [void]$ps.AddArgument($timeoutMs)
        [void]$ps.AddArgument($batchSize)
        $handle = $ps.BeginInvoke()
        [void]$jobs.Add([pscustomobject]@{
            Host = $h; PS = $ps; Handle = $handle
        })
    }

    foreach ($job in $jobs) {
        try {
            $raw = @($job.PS.EndInvoke($job.Handle))
            if ($job.PS.Streams.Error.Count -gt 0) {
                Write-Warning ("Worker {0}: {1}" -f `
                    $job.Host, ($job.PS.Streams.Error | Out-String))
            }
            if ($raw.Count -gt 0) {
                $json   = [string]$raw[0]
                $parsed = $json | ConvertFrom-Json
                if ($parsed) {
                    $openPorts[$job.Host] = @($parsed)
                }
            }
        } catch {
            Write-Warning ("Invoke failed for {0}: {1}" -f $job.Host, $_)
        }
        try { $job.PS.Dispose() } catch {}
    }

    $pool.Close()
    $pool.Dispose()
}

$totalOpen = 0
foreach ($k in $openPorts.Keys) { $totalOpen += @($openPorts[$k]).Count }

$result = [ordered]@{
    summary = [ordered]@{
        targets               = $targets.Count
        ports_scanned         = $ports.Count
        hosts_with_open_ports = @($openPorts.Keys).Count
        open_ports_total      = $totalOpen
        runspaces             = $maxRunspaces
        batch_size            = $batchSize
    }
    targets    = $targets
    ports      = $ports
    open_ports = $openPorts
}

Write-Output ($start + (ConvertTo-Json $result -Depth 6 -Compress) + $end)
"""


def _build_windows_command(targets, ports, connect_timeout):
    payload = {
        "targets": targets,
        "ports": ports,
        "timeout": connect_timeout,
    }
    payload_ps = json.dumps(payload).replace("'", "''")
    return (
        _WINDOWS_TEMPLATE
        .replace("__START__", PLUGIN_MARK_START)
        .replace("__END__", PLUGIN_MARK_END)
        .replace("__PAYLOAD__", payload_ps)
        .replace("__BATCH__", str(WINDOWS_DEFAULT_BATCH))
        .replace("__MAXRS__", str(WINDOWS_MAX_RUNSPACES))
    )


def _format_netscan_report(data: dict, title: str = 'NetScan') -> str:
    summary = data.get('summary') or {}

    lines = []
    lines.append("NetScan")
    lines.append("=======")
    lines.append(
        f"Targets: {summary.get('targets', 0)}    "
        f"Ports/probe: {summary.get('ports_scanned', 0)}    "
        f"Probes: {summary.get('targets', 0) * summary.get('ports_scanned', 0)}"
    )
    lines.append(
        f"Hosts up: {summary.get('hosts_with_open_ports', 0)}    "
        f"Open ports: {summary.get('open_ports_total', 0)}"
    )
    lines.append("")

    open_ports = data.get('open_ports') or {}

    if not open_ports:
        lines.append("No hosts with open ports.")
        return "\n".join(lines)

    lines.append("Findings")
    lines.append("--------")

    def _ip_key(ip_str):
        try:
            return tuple(int(o) for o in ip_str.split('.'))
        except Exception:
            return (0, 0, 0, 0)

    for host in sorted(open_ports.keys(), key=_ip_key):
        ports = sorted(set(open_ports[host] or []))
        port_str = ", ".join(str(p) for p in ports)
        lines.append(f"  {host:<16}  {len(ports):>3} port(s)  {port_str}")

    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

@plugin.command(
    name="netscan",
    platforms=["linux", "windows", "unix"],
    description=(
        "Fast TCP connect scan of hosts/CIDRs with nmap-style port selection "
        "(--ip accepts single IP, list, or CIDR; --port accepts top10/top100/"
        "top1000, ranges like 1-500, and lists like 22,80,443)"
    ),
)

def run(session: SessionContext, args):
    target_spec = _get_opt(args, ("ip", "targets", "target", "i"))
    port_spec = _get_opt(args, ("port", "ports", "p"))

    raw_timeout = _get_opt(args, ("timeout", "connect_timeout", "t"),
                           DEFAULT_CONNECT_TIMEOUT)
    try:
        connect_timeout = float(raw_timeout)
    except (TypeError, ValueError):
        session.print(
            f"{session.colors['red']}Invalid --timeout value: "
            f"{raw_timeout!r}{session.colors['end']}"
        )
        return 1
    if connect_timeout <= 0:
        connect_timeout = DEFAULT_CONNECT_TIMEOUT

    concurrency = _get_opt(args, ("concurrency", "c"), None)
    if concurrency is not None:
        try:
            concurrency = int(concurrency)
            if concurrency < 1:
                concurrency = None
        except (TypeError, ValueError):
            concurrency = None

    if not target_spec:
        session.print(
            f"{session.colors['red']}Usage: run netscan --ip <target> "
            f"[--port <spec>] [--timeout <sec>]{session.colors['end']}"
        )
        session.print(
            f"{session.colors['yellow']}<target>: single IP, comma-separated "
            f"list, or CIDR (e.g. 10.0.0.5, 10.0.0.0/24){session.colors['end']}"
        )
        session.print(
            f"{session.colors['yellow']}<spec>:   top10 | top100 | top1000 | "
            f"1-500 | 22,80,443 | 22,80,1000-2000 (default: top100)"
            f"{session.colors['end']}"
        )
        return 1

    try:
        targets = _parse_targets(target_spec)
        ports = _parse_ports(port_spec)
    except ValueError as exc:
        session.print(f"{session.colors['red']}{exc}{session.colors['end']}")
        return 1

    n_jobs = max(1, len(targets) * len(ports))
    per_worker = concurrency or LINUX_DEFAULT_CONCURRENCY
    est = n_jobs * (connect_timeout + 0.1) / per_worker + 120.0
    overall_timeout = max(60.0, min(3600.0, est))

    def build_linux():
        return _build_linux_command(targets, ports, connect_timeout, concurrency)

    def build_windows():
        return _build_windows_command(targets, ports, connect_timeout)

    return run_collector_plugin(
        session,
        "netscan",
        build_linux,
        build_windows,
        _format_netscan_report,
        timeout=overall_timeout,
    )