"""Cross-platform process memory map and loaded module enumeration."""

import json
import re

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_memorymap_report, resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json


def _linux_collector_source(pid: str):
    return f'''
import os, subprocess
pid = {json.dumps(pid)}
result = {{'summary': {{'pid': pid}}, 'memory_maps': [], 'modules': [], 'loaded_libraries': []}}
maps_path = f'/proc/{{pid}}/maps'
status_path = f'/proc/{{pid}}/status'
if not os.path.isdir(f'/proc/{{pid}}'):
    result['summary']['error'] = 'Process not found'
    _emit(result)
else:
    try:
        with open(maps_path, 'r', errors='ignore') as f:
            lines = f.readlines()
        result['memory_maps'] = [l.strip() for l in lines[:80]]
        result['summary']['map_entries'] = len(lines)
    except Exception as e:
        result['summary']['maps_error'] = str(e)
    try:
        with open(status_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith(('Name:', 'VmRSS:', 'VmSize:', 'Threads:', 'Uid:', 'Gid:')):
                    k, _, v = line.partition(':')
                    result['summary'][k.strip()] = v.strip()
    except Exception:
        pass
    try:
        exe = os.readlink(f'/proc/{{pid}}/exe')
        result['summary']['exe'] = exe
    except Exception:
        pass
    try:
        out = subprocess.check_output(['lsof', '-p', pid], stderr=subprocess.STDOUT, timeout=8)
        text = out.decode('utf-8', 'ignore')
        for line in text.splitlines()[1:51]:
            parts = line.split()
            if len(parts) >= 9:
                result['loaded_libraries'].append({{'name': parts[-1], 'fd': parts[3], 'type': parts[4]}})
    except Exception:
        pass
    try:
        out = subprocess.check_output(['cat', f'/proc/{{pid}}/maps'], stderr=subprocess.STDOUT, timeout=5)
        libs = set()
        for line in out.decode('utf-8', 'ignore').splitlines():
            if '.so' in line:
                path = line.split()[-1]
                if path.startswith('/'):
                    libs.add(path)
        result['modules'] = sorted(libs)[:60]
        result['summary']['shared_libraries'] = len(libs)
    except Exception:
        pass
    _emit(result)
'''


def _build_linux_command(pid: str):
    return build_linux_collector_command(_linux_collector_source(pid))


def _build_windows_command(pid: str):
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$targetPid={pid}
$result=[ordered]@{{summary=@{{pid=$targetPid}};modules=@();memory_maps=@();loaded_libraries=@()}}
try{{
  $proc=Get-Process -Id $targetPid -EA Stop
  $result.summary.name=$proc.ProcessName
  $result.summary.path=$proc.Path
  $result.summary.working_set=[math]::Round($proc.WorkingSet64/1MB,2).ToString()+' MB'
}}catch{{
  $result.summary.error='Process not found'
  Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
  return
}}
try{{
  Get-Process -Id $targetPid -Module -EA 0|Select-Object -First 80 ModuleName,FileName,ModuleMemorySize|ForEach-Object{{
    $result.modules+=@{{name=$_.ModuleName;path=$_.FileName;size=$_.ModuleMemorySize}}
  }}
}}catch{{}}
try{{
  Get-CimInstance Win32_ProcessModule -Filter "ProcessId=$targetPid" -EA 0|Select-Object -First 80 Name,ExecutablePath|ForEach-Object{{
    $result.loaded_libraries+=@{{name=$_.Name;path=$_.ExecutablePath}}
  }}
}}catch{{}}
$result.summary.module_count=$result.modules.Count
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


def _parse_pid(args):
    if not args:
        return None, 'Usage: run memorymap <ID> <pid>'
    pid = args[0].strip()
    if not re.match(r'^\d+$', pid):
        return None, f"Invalid PID: {pid!r} (expected numeric process ID)"
    return pid, None


@plugin.command(
    name='memorymap',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate memory maps and loaded modules for a process (requires PID)',
)
def run(session: SessionContext, args):
    pid, err = _parse_pid(args)
    if err:
        session.print(err, 'yellow')
        return 1

    session.log_event(f'Plugin memorymap: collection started for PID {pid}')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    platform = resolve_session_platform(session)
    win_ps = ''
    unix_cmd = 'true'

    if platform == 'windows':
        win_ps = _build_windows_command(pid)
    elif platform in ('unix', 'linux'):
        unix_cmd = _build_linux_command(pid)
    else:
        win_ps = _build_windows_command(pid)
        unix_cmd = _build_linux_command(pid)
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 45.0)

    if raw is None:
        session.print("Plugin 'memorymap' failed — no response from target.", 'red')
        session.log_plugin_result('memorymap', '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'memorymap' failed — could not parse results.", 'red')
        session.log_plugin_result('memorymap', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'memorymap' error on target: {data['error']}", 'red')
        session.log_plugin_result('memorymap', raw[:4000], data.get('traceback', ''))
        return 1

    report = format_memorymap_report(data)
    session.print(report, 'cyan')
    session.log_plugin_result('memorymap', report, json.dumps(data, indent=2))
    session.log_command(f'run memorymap {pid}', report)
    return 0
