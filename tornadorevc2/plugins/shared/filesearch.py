"""Cross-platform file and directory search enumeration."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report, resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json


def _parse_search_opts(args):
    opts = {
        'path': '',
        'name': '',
        'ext': '',
        'size': '',
        'owner': '',
        'mtime': '',
        'recursive': False,
    }
    for arg in args or []:
        token = arg.strip()
        if not token:
            continue
        if token in ('-r', 'recursive', '--recursive'):
            opts['recursive'] = True
            continue
        if '=' in token:
            key, _, val = token.partition('=')
            key = key.lower().lstrip('-')
            if key in opts and key != 'recursive':
                opts[key] = val
            elif key == 'recursive':
                opts['recursive'] = val.lower() in ('1', 'true', 'yes', 'on')
        elif not opts['path']:
            opts['path'] = token
        elif not opts['name']:
            opts['name'] = token
        elif not opts['ext']:
            opts['ext'] = token
    if opts['ext'] and not opts['ext'].startswith('.'):
        opts['ext'] = '.' + opts['ext']
    return opts


def _linux_collector_source(opts):
    payload = json.dumps(opts)
    return f'''
import json, os, subprocess, stat as statmod
from datetime import datetime, timedelta

opts = {payload}
result = {{'summary': {{}}, 'matches': [], 'search': opts}}

def sh(cmd, timeout=12):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def parse_size(val):
    if not val:
        return None
    val = val.strip().lower()
    mult = 1
    if val.endswith('k'):
        mult, val = 1024, val[:-1]
    elif val.endswith('m'):
        mult, val = 1024 ** 2, val[:-1]
    elif val.endswith('g'):
        mult, val = 1024 ** 3, val[:-1]
    try:
        return int(float(val.lstrip('+-')) * mult)
    except Exception:
        return None

path = opts.get('path') or os.path.expanduser('~')
if not os.path.exists(path):
    path = '/tmp' if os.path.isdir('/tmp') else '/'
recursive = opts.get('recursive') or False
name = opts.get('name') or '*'
ext = opts.get('ext') or ''
owner = opts.get('owner') or ''
mtime_days = opts.get('mtime') or ''
min_size = parse_size(opts.get('size') or '')

def q(s):
    return "'" + str(s).replace("'", "'\\''") + "'"

find_parts = ['find', q(path)]
if not recursive:
    find_parts += ['-maxdepth', '3']
if name:
    find_parts += ['-name', q(name if '*' in name else f'*{{name}}*')]
if ext:
    find_parts += ['-name', q(f'*{{ext}}')]
if min_size:
    find_parts += ['-size', f'+{{max(1, min_size // 512)}}c']
if mtime_days:
    try:
        find_parts += ['-mtime', f'-{{int(mtime_days)}}']
    except Exception:
        pass
if owner:
    find_parts += ['-user', q(owner)]
find_parts += ['-print']

matches = []
if sh('command -v find 2>/dev/null').strip():
    out = sh(' '.join(find_parts), 20)
    for line in out.splitlines()[:80]:
        p = line.strip()
        if not p:
            continue
        entry = {{'path': p}}
        try:
            st = os.stat(p, follow_symlinks=False)
            entry['size'] = st.st_size
            entry['modified'] = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')
            entry['mode'] = oct(st.st_mode)[-4:]
            try:
                import pwd
                entry['owner'] = pwd.getpwuid(st.st_uid).pw_name
            except Exception:
                pass
        except Exception:
            pass
        matches.append(entry)
else:
    # fallback: limited walk
    max_depth = 4 if recursive else 2
    root = path
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        if depth >= max_depth:
            dirnames[:] = []
            continue
        for fn in filenames + dirnames:
            full = os.path.join(dirpath, fn)
            if name != '*' and name not in fn:
                continue
            if ext and not fn.endswith(ext):
                continue
            try:
                st = os.stat(full, follow_symlinks=False)
            except Exception:
                continue
            if min_size and st.st_size < min_size:
                continue
            if mtime_days:
                try:
                    if st.st_mtime < (datetime.now() - timedelta(days=int(mtime_days))).timestamp():
                        continue
                except Exception:
                    pass
            entry = {{'path': full, 'size': st.st_size, 'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')}}
            matches.append(entry)
            count += 1
            if count >= 80:
                break
        if count >= 80:
            break

result['matches'] = matches[:80]
result['summary'] = {{
    'search_path': path,
    'recursive': recursive,
    'name_filter': name or 'N/A',
    'extension': ext or 'N/A',
    'owner': owner or 'N/A',
    'mtime_days': mtime_days or 'N/A',
    'min_size': opts.get('size') or 'N/A',
    'matches': len(matches),
}}
_emit(result)
'''


def _build_linux_command(opts):
    return build_linux_collector_command(_linux_collector_source(opts))


def _build_windows_command(opts):
    path = opts.get('path') or ''
    name = opts.get('name') or '*'
    ext = opts.get('ext') or ''
    size = opts.get('size') or ''
    owner = opts.get('owner') or ''
    mtime = opts.get('mtime') or ''
    recursive = 'true' if opts.get('recursive') else 'false'
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$path={json.dumps(path)}; if(-not $path){{$path=$env:USERPROFILE}}
$name={json.dumps(name)}; $ext={json.dumps(ext)}; $sizeFilter={json.dumps(size)}
$ownerFilter={json.dumps(owner)}; $mtimeDays={json.dumps(mtime)}; $recursive={recursive}
$matches=@()
$params=@{{Path=$path;ErrorAction='SilentlyContinue'}}
if($recursive -eq 'true'){{$params['Recurse']=$true}}else{{$params['Depth']=3}}
try{{
  $items=Get-ChildItem @params -Force -EA 0
  if($name -and $name -ne '*'){{$items=$items|Where-Object{{$_.Name -like "*$name*"}}}}
  if($ext){{$items=$items|Where-Object{{$_.Extension -eq $ext -or $_.Name -like "*$ext"}}}}
  if($ownerFilter){{$items=$items|Where-Object{{(Get-Acl $_.FullName -EA 0).Owner -like "*$ownerFilter*"}}}}
  if($sizeFilter){{
    $min=[int64]0
    if($sizeFilter -match '^\d+$'){{$min=[int64]$sizeFilter}}
    elseif($sizeFilter -match '^(\d+(?:\.\d+)?)([kmg])$'){{
      $n=[double]$matches[1]; switch($matches[2].ToLower()){{'k'{{$min=[int64]($n*1024)}}'m'{{$min=[int64]($n*1024*1024)}}'g'{{$min=[int64]($n*1024*1024*1024)}}}}
    }}
    if($min -gt 0){{$items=$items|Where-Object{{$_.Length -ge $min}}}}
  }}
  if($mtimeDays){{
    $cut=(Get-Date).AddDays(-1*[int]$mtimeDays)
    $items=$items|Where-Object{{$_.LastWriteTime -ge $cut}}
  }}
  $items|Select-Object -First 80|ForEach-Object{{
    $matches+=@{{path=$_.FullName;size=$_.Length;modified=$_.LastWriteTime.ToString('s');type=if($_.PSIsContainer){{'dir'}}else{{'file'}}}}
  }}
}}catch{{}}
$result=[ordered]@{{
  summary=@{{search_path=$path;recursive=$recursive;name_filter=$name;extension=($ext -or 'N/A');owner=($ownerFilter -or 'N/A');mtime_days=($mtimeDays -or 'N/A');min_size=($sizeFilter -or 'N/A');matches=$matches.Count}}
  search=@{{path=$path;name=$name;ext=$ext;size=$sizeFilter;owner=$ownerFilter;mtime=$mtimeDays;recursive=$recursive}}
  matches=$matches
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='filesearch',
    platforms=['linux', 'windows', 'unix'],
    description='Search files and directories by name, extension, path, size, owner, and modification time',
)
def run(session: SessionContext, args):
    opts = _parse_search_opts(args)
    session.log_event('Plugin filesearch: collection started')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    platform = resolve_session_platform(session)
    win_ps = ''
    unix_cmd = 'true'

    if platform == 'windows':
        win_ps = _build_windows_command(opts)
    elif platform in ('unix', 'linux'):
        unix_cmd = _build_linux_command(opts)
    else:
        win_ps = _build_windows_command(opts)
        unix_cmd = _build_linux_command(opts)
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 45.0)

    if raw is None:
        session.print("Plugin 'filesearch' failed — no response from target.", 'red')
        session.log_plugin_result('filesearch', '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'filesearch' failed — could not parse results.", 'red')
        session.log_plugin_result('filesearch', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'filesearch' error on target: {data['error']}", 'red')
        session.log_plugin_result('filesearch', raw[:4000], data.get('traceback', ''))
        return 1

    report = format_generic_report(data, 'File Search')
    session.print(report, 'cyan')
    session.log_plugin_result('filesearch', report, json.dumps(data, indent=2))
    session.log_command(f'run filesearch {" ".join(args or [])}'.strip(), report)
    return 0
