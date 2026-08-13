"""Cross-platform file and directory search enumeration."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_section, format_table_section, resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json


FILESEARCH_USAGE = """
Filesearch — search files and directories on the target (read-only, max 80 results).

Usage:
  run filesearch [options]
  run filesearch help

Options (key=value):
  path=<dir|file> Root directory or absolute file path (/etc/passwd, C:\\...\\hosts)
  name=<pattern>   Filename match: exact if no wildcards; supports * and ? (Linux: case-sensitive)
  ext=<.ext>       Extension filter (.log or log)
  size=<min>       Minimum size in bytes, or with suffix: 512, 1k, 5m, 2g
  owner=<user>     Owner username (Linux: find -user; Windows: ACL owner match)
  mtime=<days>     Modified within the last N days
  recursive=<bool> true/false/yes/no/1/0 (default: false, searches depth 3)
  -r, recursive    Enable full recursive search

Positional shorthand (applied in order: path, name, ext):
  run filesearch /var/log passwd .conf
  run filesearch C:\\Users keyword .ps1 -r

Examples:
  run filesearch /etc/passwd
  run filesearch path=/etc name=passwd
  run filesearch path=/var/log ext=.log mtime=7 recursive
  run filesearch path=/tmp size=1m owner=root
  run filesearch path=C:\\Users\\Public ext=.txt mtime=30
  run filesearch /home backup .zip -r
""".strip()


def _format_filesearch_report(data):
    sections = []
    summary = data.get('summary') or {}
    search = data.get('search') or {}

    criteria = {
        'Path': summary.get('search_path') or search.get('path') or 'N/A',
        'Recursive': summary.get('recursive', search.get('recursive', 'N/A')),
        'Name': summary.get('name_filter') or search.get('name') or 'N/A',
        'Extension': summary.get('extension') or search.get('ext') or 'N/A',
        'Min Size': summary.get('min_size') or search.get('size') or 'N/A',
        'Owner': summary.get('owner') or search.get('owner') or 'N/A',
        'Modified (days)': summary.get('mtime_days') or search.get('mtime') or 'N/A',
        'Matches': summary.get('matches', 0),
    }
    sections.append(format_section('Search Criteria', criteria))

    matches = data.get('matches') or []
    if matches:
        cols = ['path', 'size', 'modified', 'owner', 'type', 'mode']
        sections.append(format_table_section('Matches', matches, cols))
    else:
        sections.append('Matches\n-------\n(none)')

    return '\n\n'.join(sections)


def _parse_search_opts(args):
    if args and args[0].strip().lower() in ('-h', '--help', 'help', '?'):
        return None, FILESEARCH_USAGE

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
    return opts, None


def _linux_collector_source(opts):
    payload = json.dumps(opts)
    return '''
import json, os, subprocess, fnmatch
from datetime import datetime, timedelta

opts = json.loads(''' + json.dumps(payload) + ''')
result = {'summary': {}, 'matches': [], 'search': opts}

def sh(cmd, timeout=15):
    try:
        out = subprocess.check_output(cmd + ' 2>/dev/null', shell=True, timeout=timeout)
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

def q(s):
    return "'" + str(s).replace("'", "'\\''") + "'"

def entry_for(path):
    try:
        st = os.stat(path, follow_symlinks=False)
    except Exception:
        return None
    row = {
        'path': path,
        'size': st.st_size,
        'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M'),
        'mode': oct(st.st_mode)[-4:],
        'type': 'dir' if os.path.isdir(path) else 'file',
    }
    try:
        import pwd
        row['owner'] = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        pass
    return row

def passes_filters(path, st, name, ext, min_size, mtime_days, owner):
    base = os.path.basename(path)
    if name and name != '*':
        if '*' in name or '?' in name:
            if not fnmatch.fnmatchcase(base, name):
                return False
        elif base != name:
            return False
    if ext:
        if not base.endswith(ext if ext.startswith('.') else '.' + ext):
            return False
    if min_size and st.st_size < min_size:
        return False
    if mtime_days:
        try:
            cutoff = (datetime.now() - timedelta(days=int(mtime_days))).timestamp()
            if st.st_mtime < cutoff:
                return False
        except Exception:
            pass
    if owner:
        try:
            import pwd
            if pwd.getpwuid(st.st_uid).pw_name != owner:
                return False
        except Exception:
            return False
    return True

def add_match(path, matches, seen, name, ext, min_size, mtime_days, owner):
    if path in seen or len(matches) >= 80:
        return
    try:
        st = os.stat(path, follow_symlinks=False)
    except Exception:
        return
    if not passes_filters(path, st, name, ext, min_size, mtime_days, owner):
        return
    row = entry_for(path)
    if row:
        seen.add(path)
        matches.append(row)

raw_path = (opts.get('path') or '').strip() or os.path.expanduser('~')
name = (opts.get('name') or '').strip()
ext = (opts.get('ext') or '').strip()
if ext and not ext.startswith('.'):
    ext = '.' + ext
owner = (opts.get('owner') or '').strip()
mtime_days = (opts.get('mtime') or '').strip()
min_size = parse_size(opts.get('size') or '')
recursive = bool(opts.get('recursive'))

matches = []
seen = set()

# Absolute file path: /etc/passwd or path= with no separate name
if raw_path and os.path.exists(raw_path) and not os.path.isdir(raw_path):
    if not name:
        name = os.path.basename(raw_path)
    add_match(raw_path, matches, seen, name, ext, min_size, mtime_days, owner)
    if not recursive:
        result['matches'] = matches[:80]
        result['summary'] = {
            'search_path': raw_path,
            'recursive': recursive,
            'name_filter': name or 'N/A',
            'extension': ext or 'N/A',
            'owner': owner or 'N/A',
            'mtime_days': mtime_days or 'N/A',
            'min_size': opts.get('size') or 'N/A',
            'matches': len(matches),
            'mode': 'exact_file',
        }
        _emit(result)

search_root = raw_path
if not os.path.exists(search_root):
    search_root = '/tmp' if os.path.isdir('/tmp') else '/'
elif os.path.isfile(search_root):
    search_root = os.path.dirname(search_root) or '/'

# Build find -name pattern (single predicate; multiple -name are ANDed)
if ext and (not name or name == '*'):
    name_pattern = '*' + ext
elif name and name != '*':
    if '*' in name or '?' in name:
        name_pattern = name
    else:
        name_pattern = name
else:
    name_pattern = '*'

if sh('command -v find 2>/dev/null').strip() and os.path.isdir(search_root):
    find_parts = ['find', q(search_root)]
    if not recursive:
        find_parts += ['-maxdepth', '5']
    find_parts += ['-name', q(name_pattern)]
    if min_size:
        find_parts += ['-size', '+%dc' % max(1, min_size // 512)]
    if mtime_days:
        try:
            find_parts += ['-mtime', '-%d' % int(mtime_days)]
        except Exception:
            pass
    if owner:
        find_parts += ['-user', q(owner)]
    find_parts += ['-print']
    out = sh(' '.join(find_parts), 20)
    for line in out.splitlines():
        p = line.strip()
        if p:
            add_match(p, matches, seen, name, ext, min_size, mtime_days, owner)
        if len(matches) >= 80:
            break

# Fallback / supplement: os.walk with permission skips
if len(matches) < 80 and os.path.isdir(search_root):
    max_depth = 99 if recursive else 5

    def _on_walk_error(_err):
        return

    for dirpath, dirnames, filenames in os.walk(search_root, topdown=True, onerror=_on_walk_error, followlinks=False):
        rel = os.path.relpath(dirpath, search_root)
        depth = 0 if rel == '.' else rel.count(os.sep) + 1
        if depth >= max_depth:
            dirnames[:] = []
            continue
        scrubbed = []
        for d in dirnames:
            full_d = os.path.join(dirpath, d)
            try:
                if os.access(full_d, os.R_OK | os.X_OK):
                    scrubbed.append(d)
            except Exception:
                pass
        dirnames[:] = scrubbed
        for fn in filenames:
            add_match(os.path.join(dirpath, fn), matches, seen, name, ext, min_size, mtime_days, owner)
            if len(matches) >= 80:
                break
        if len(matches) >= 80:
            break

result['matches'] = matches[:80]
result['summary'] = {
    'search_path': search_root,
    'recursive': recursive,
    'name_filter': name or 'N/A',
    'extension': ext or 'N/A',
    'owner': owner or 'N/A',
    'mtime_days': mtime_days or 'N/A',
    'min_size': opts.get('size') or 'N/A',
    'matches': len(matches),
}
_emit(result)
'''


def _build_linux_command(opts):
    return build_linux_collector_command(_linux_collector_source(opts))


def _build_windows_command(opts):
    path = opts.get('path') or ''
    name = opts.get('name') or ''
    ext = opts.get('ext') or ''
    size = opts.get('size') or ''
    owner = opts.get('owner') or ''
    mtime = opts.get('mtime') or ''
    recursive = 'true' if opts.get('recursive') else 'false'
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$path={json.dumps(path)}
$name={json.dumps(name)}; $ext={json.dumps(ext)}; $sizeFilter={json.dumps(size)}
$ownerFilter={json.dumps(owner)}; $mtimeDays={json.dumps(mtime)}; $recursive='{recursive}'
$found=@(); $seen=@{{}}

function Add-Match($item){{
  if(-not $item -or $seen.ContainsKey($item.FullName)){{return}}
  $seen[$item.FullName]=$true
  $script:found+=@{{path=$item.FullName;size=$item.Length;modified=$item.LastWriteTime.ToString('s');type=if($item.PSIsContainer){{'dir'}}else{{'file'}}}}
}}

function Test-SizeFilter($len){{
  if(-not $sizeFilter){{return $true}}
  $min=[int64]0
  if($sizeFilter -match '^\d+$'){{$min=[int64]$sizeFilter}}
  elseif($sizeFilter -match '^(\d+(?:\.\d+)?)([kmg])$'){{
    $n=[double]$Matches[1]
    switch($Matches[2].ToLower()){{'k'{{$min=[int64]($n*1024)}}'m'{{$min=[int64]($n*1024*1024)}}'g'{{$min=[int64]($n*1024*1024*1024)}}}}
  }}
  return ($min -le 0 -or $len -ge $min)
}}

function Test-MtimeFilter($dt){{
  if(-not $mtimeDays){{return $true}}
  try{{return $dt -ge (Get-Date).AddDays(-1*[int]$mtimeDays)}}catch{{return $true}}
}}

function Test-NameFilter($base){{
  if(-not $name){{return $true}}
  if($name -match '[\*\?]'){{return ($base -ilike $name)}}
  return ($base -ieq $name)
}}

function Test-ExtFilter($base){{
  if(-not $ext){{return $true}}
  $e=$ext; if($e -and $e[0] -ne '.'){{$e='.'+$e}}
  return ($base -ilike ('*'+$e))
}}

function Test-OwnerFilter($full){{
  if(-not $ownerFilter){{return $true}}
  try{{return ((Get-Acl $full -EA 0).Owner -ilike ('*'+$ownerFilter+'*'))}}catch{{return $false}}
}}

function Test-ItemFilters($item){{
  if(-not $item){{return $false}}
  if(-not (Test-NameFilter $item.Name)){{return $false}}
  if(-not (Test-ExtFilter $item.Name)){{return $false}}
  if(-not (Test-SizeFilter $item.Length)){{return $false}}
  if(-not (Test-MtimeFilter $item.LastWriteTime)){{return $false}}
  if(-not (Test-OwnerFilter $item.FullName)){{return $false}}
  return $true
}}

function Try-AddLiteral($target){{
  if($found.Count -ge 80){{return}}
  if(-not (Test-Path -LiteralPath $target -EA 0)){{return}}
  $f=Get-Item -LiteralPath $target -Force -EA 0
  if($f -and (Test-ItemFilters $f)){{Add-Match $f}}
}}

if(-not $path){{$path=$env:USERPROFILE}}

# Absolute file path
if(Test-Path -LiteralPath $path -PathType Leaf -EA 0){{
  if(-not $name){{$name=[IO.Path]::GetFileName($path)}}
  Try-AddLiteral $path
  if($recursive -ne 'true'){{
    $result=[ordered]@{{
      summary=@{{search_path=$path;recursive=$recursive;name_filter=($name -or 'N/A');extension=($ext -or 'N/A');owner=($ownerFilter -or 'N/A');mtime_days=($mtimeDays -or 'N/A');min_size=($sizeFilter -or 'N/A');matches=$found.Count;mode='exact_file'}}
      search=@{{path=$path;name=$name;ext=$ext;size=$sizeFilter;owner=$ownerFilter;mtime=$mtimeDays;recursive=$recursive}}
      matches=$found
    }}
    Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
    return
  }}
  $path=Split-Path -Parent $path
  if(-not $path){{$path='C:\'}}
}}

if(-not (Test-Path -LiteralPath $path -EA 0)){{
  $result=[ordered]@{{
    summary=@{{search_path=$path;matches=0;error='path not found'}}
    search=@{{path=$path;name=$name;ext=$ext;size=$sizeFilter;owner=$ownerFilter;mtime=$mtimeDays;recursive=$recursive}}
    matches=@()
  }}
  Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
  return
}}

try{{
  $exactName=($name -and $name -notmatch '[\*\?]')

  # Exact name in directory root (e.g. System32\cmd.exe)
  if($exactName){{Try-AddLiteral (Join-Path $path $name)}}

  if($found.Count -lt 80){{
    if($exactName -and $recursive -eq 'true'){{
      # Native recursive exact-name search — fast on large trees
      $whereCmd='where.exe /R "'+$path.Replace('"','""')+'" '+$name
      $whereOut=cmd /c $whereCmd 2>nul
      if($whereOut){{
        foreach($line in ($whereOut -split "`r?`n")){{
          $line=$line.Trim()
          if($line){{Try-AddLiteral $line}}
          if($found.Count -ge 80){{break}}
        }}
      }}
    }}elseif(-not $exactName -or $recursive -ne 'true'){{
      # Filtered enumeration — never scan unfiltered large directories
      $gciFilter=$null
      if($name){{$gciFilter=$name}}
      elseif($ext){{
        $e=$ext; if($e -and $e[0] -ne '.'){{$e='.'+$e}}
        $gciFilter='*'+$e
      }}
      $params=@{{Path=$path;Force=$true;ErrorAction='SilentlyContinue'}}
      if($gciFilter){{$params['Filter']=$gciFilter}}
      if($recursive -eq 'true'){{$params['Recurse']=$true}}
      Get-ChildItem @params|Select-Object -First 200|ForEach-Object{{
        if($found.Count -ge 80){{return}}
        if(-not (Test-NameFilter $_.Name)){{return}}
        if(Test-ItemFilters $_){{Add-Match $_}}
      }}
    }}
  }}
}}catch{{}}

$result=[ordered]@{{
  summary=@{{search_path=$path;recursive=$recursive;name_filter=($name -or 'N/A');extension=($ext -or 'N/A');owner=($ownerFilter -or 'N/A');mtime_days=($mtimeDays -or 'N/A');min_size=($sizeFilter -or 'N/A');matches=$found.Count}}
  search=@{{path=$path;name=$name;ext=$ext;size=$sizeFilter;owner=$ownerFilter;mtime=$mtimeDays;recursive=$recursive}}
  matches=$found
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='filesearch',
    platforms=['linux', 'windows', 'unix'],
    description='Search files by path, name, ext, size, owner, mtime (run filesearch help for options)',
)
def run(session: SessionContext, args):
    opts, usage = _parse_search_opts(args)
    if usage:
        session.print(usage, 'yellow')
        return 0

    session.log_event(f'Plugin filesearch: collection started ({json.dumps(opts)})')
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

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 60.0 if platform == 'windows' else 45.0)

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

    report = _format_filesearch_report(data)
    session.print(report, 'cyan')
    session.log_plugin_result('filesearch', report, json.dumps(data, indent=2))
    session.log_command(f'run filesearch {" ".join(args or [])}'.strip(), report)
    return 0
