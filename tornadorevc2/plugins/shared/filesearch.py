"""Cross-platform file and directory search enumeration."""

import json
import re

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
  run filesearch 'C:\\Program Files' cmd.exe recursive
  run filesearch "/opt/my app" config .yaml -r

Examples:
  run filesearch /etc/passwd
  run filesearch path=/etc name=passwd
  run filesearch path='C:\\Program Files' name=cmd.exe recursive
  run filesearch path="/opt/my app" name=config.yaml recursive
  run filesearch path=/var/log ext=.log mtime=7 recursive
  run filesearch path=/tmp size=1m owner=root
  run filesearch path=C:\\Users\\Public ext=.txt mtime=30
  run filesearch /home backup .zip -r
""".strip()

PLUGIN_INFO = FILESEARCH_USAGE

def _display_val(value):
    if isinstance(value, bool):
        return 'N/A'
    if value is None or value == '':
        return 'N/A'
    return str(value)


def _format_filesearch_report(data):
    sections = []
    summary = data.get('summary') or {}
    search = data.get('search') or {}

    criteria = {
        'Path': _display_val(summary.get('search_path') or search.get('path')),
        'Recursive': _display_val(summary.get('recursive', search.get('recursive'))),
        'Name': _display_val(summary.get('name_filter') or search.get('name')),
        'Extension': _display_val(summary.get('extension') or search.get('ext')),
        'Min Size': _display_val(summary.get('min_size') or search.get('size')),
        'Owner': _display_val(summary.get('owner') or search.get('owner')),
        'Modified (days)': _display_val(summary.get('mtime_days') or search.get('mtime')),
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


_FLAG_TOKENS = frozenset({'-r', 'recursive', '--recursive'})
_KNOWN_KEYS = frozenset({'path', 'name', 'ext', 'size', 'owner', 'mtime', 'recursive'})


def _strip_quotes(value):
    value = (value or '').strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def _reassemble_quote_fragments(tokens):
    """Join tokens broken by handler split() inside quoted strings."""
    out = []
    buf = ''
    quote = None
    for raw in tokens or []:
        token = raw.strip()
        if not token:
            continue
        if buf:
            buf += ' ' + token
            if (quote == "'" and token.endswith("'")) or (quote == '"' and token.endswith('"')):
                out.append(_strip_quotes(buf))
                buf = ''
                quote = None
            continue
        if token[0] in '"\'' and (len(token) == 1 or token[-1] != token[0]):
            buf = token
            quote = token[0]
            continue
        if len(token) >= 2 and token[0] in '"\'' and token[-1] == token[0]:
            out.append(_strip_quotes(token))
            continue
        out.append(token)
    if buf:
        out.append(_strip_quotes(buf))
    return out


def _looks_like_path_segment(token):
    return bool(
        re.match(r'^[A-Za-z]:', token)
        or token.startswith(('/', '~', '.'))
        or('\\' in token)
        or ('/' in token)
    )


def _looks_like_filename(token):
    if not token or token.lower() in _FLAG_TOKENS:
        return False
    if token.startswith('.'):
        return True
    if '/' in token or '\\' in token:
        return False
    if '*' in token or '?' in token:
        return True
    if '.' in token:
        return True
    return False


def _is_complete_dir_path(token):
    if token.startswith('/') and ' ' not in token:
        return True
    return False


def _split_spaced_path_name_ext(tokens):
    """Assign positional tokens that may include a multi-word path."""
    if not tokens:
        return '', '', ''
    parts = list(tokens)
    ext = ''
    if parts and parts[-1].startswith('.') and len(parts[-1]) > 1 and '\\' not in parts[-1] and '/' not in parts[-1]:
        ext = parts.pop()
    name = ''
    if parts and _looks_like_filename(parts[-1]):
        name = parts.pop()
    elif (
        len(parts) == 2
        and _is_complete_dir_path(parts[0])
        and (not _looks_like_path_segment(parts[1]) or '.' in parts[1])
    ):
        name = parts.pop()
    path = ' '.join(parts).strip()
    return path, name, ext


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
    expanded = _reassemble_quote_fragments(args)
    positionals = []
    i = 0
    while i < len(expanded):
        token = expanded[i]
        low = token.lower()
        if low in _FLAG_TOKENS:
            opts['recursive'] = True
            i += 1
            continue
        if '=' in token:
            key, _, val = token.partition('=')
            key = key.lower().lstrip('-')
            if key not in _KNOWN_KEYS:
                positionals.append(token)
                i += 1
                continue
            if key == 'recursive':
                opts['recursive'] = val.lower() in ('1', 'true', 'yes', 'on')
                i += 1
                continue
            parts = [_strip_quotes(val.strip())]
            i += 1
            while i < len(expanded):
                nxt = expanded[i]
                if nxt.lower() in _FLAG_TOKENS:
                    break
                nxt_key = nxt.partition('=')[0].lower().lstrip('-')
                if '=' in nxt and nxt_key in _KNOWN_KEYS:
                    break
                parts.append(nxt)
                i += 1
            opts[key] = _strip_quotes(' '.join(parts).strip())
            continue
        positionals.append(token)
        i += 1

    if positionals and not opts['path']:
        path, name, ext = _split_spaced_path_name_ext(positionals)
        if path:
            opts['path'] = _strip_quotes(path)
        if name and not opts['name']:
            opts['name'] = _strip_quotes(name)
        if ext and not opts['ext']:
            opts['ext'] = _strip_quotes(ext)

    for key in ('path', 'name', 'ext', 'size', 'owner', 'mtime'):
        if opts.get(key):
            opts[key] = _strip_quotes(str(opts[key]))
    if opts['ext'] and not opts['ext'].startswith('.'):
        opts['ext'] = '.' + opts['ext']
    return opts, None


def _normalize_windows_path(path):
    if not path:
        return path
    path = path.replace('/', '\\')
    if re.match(r'^[A-Za-z]:', path):
        drive = path[0:2]
        rest = path[2:].lstrip('\\')
        path = drive + '\\' + rest if rest else drive + '\\'
    elif len(path) > 3:
        path = path.rstrip('\\')
    return path


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
    path = _normalize_windows_path(opts.get('path') or '')
    name = opts.get('name') or ''
    ext = opts.get('ext') or ''
    size = opts.get('size') or ''
    owner = opts.get('owner') or ''
    mtime = opts.get('mtime') or ''
    recursive = 'true' if opts.get('recursive') else 'false'
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$fsPath={json.dumps(path)}
$fsName={json.dumps(name)}; $fsExt={json.dumps(ext)}; $fsSize={json.dumps(size)}
$fsOwner={json.dumps(owner)}; $fsMtime={json.dumps(mtime)}; $fsRecurse='{recursive}'
$found=@(); $seen=@{{}}

function Fmt([string]$v){{if([string]::IsNullOrEmpty($v)){{'N/A'}}else{{$v}}}}

function Add-Match($item){{
  if(-not $item -or $seen.ContainsKey($item.FullName)){{return}}
  $seen[$item.FullName]=$true
  $script:found+=@{{path=$item.FullName;size=$item.Length;modified=$item.LastWriteTime.ToString('s');type=if($item.PSIsContainer){{'dir'}}else{{'file'}}}}
}}

function Test-SizeFilter($len){{
  if([string]::IsNullOrEmpty($fsSize)){{return $true}}
  $min=[int64]0
  if($fsSize -match '^\d+$'){{$min=[int64]$fsSize}}
  elseif($fsSize -match '^(\d+(?:\.\d+)?)([kmg])$'){{
    $n=[double]$Matches[1]
    switch($Matches[2].ToLower()){{'k'{{$min=[int64]($n*1024)}}'m'{{$min=[int64]($n*1024*1024)}}'g'{{$min=[int64]($n*1024*1024*1024)}}}}
  }}
  return ($min -le 0 -or $len -ge $min)
}}

function Test-MtimeFilter($dt){{
  if([string]::IsNullOrEmpty($fsMtime)){{return $true}}
  try{{return $dt -ge (Get-Date).AddDays(-1*[int]$fsMtime)}}catch{{return $true}}
}}

function Test-NameFilter($base){{
  if([string]::IsNullOrEmpty($fsName)){{return $true}}
  if($fsName -match '[\*\?]'){{return ($base -ilike $fsName)}}
  return ($base -ieq $fsName)
}}

function Test-ExtFilter($base){{
  if([string]::IsNullOrEmpty($fsExt)){{return $true}}
  $e=$fsExt; if($e[0] -ne '.'){{$e='.'+$e}}
  return ($base -ilike ('*'+$e))
}}

function Test-OwnerFilter($full){{
  if([string]::IsNullOrEmpty($fsOwner)){{return $true}}
  try{{return ((Get-Acl $full -EA 0).Owner -ilike ('*'+$fsOwner+'*'))}}catch{{return $false}}
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
  if($script:found.Count -ge 80){{return}}
  if(-not (Test-Path -LiteralPath $target -EA 0)){{return}}
  $f=Get-Item -LiteralPath $target -Force -EA 0
  if($f -and (Test-ItemFilters $f)){{Add-Match $f}}
}}

if([string]::IsNullOrEmpty($fsPath)){{$fsPath=$env:USERPROFILE}}

# Absolute file path
if(Test-Path -LiteralPath $fsPath -PathType Leaf -EA 0){{
  if([string]::IsNullOrEmpty($fsName)){{$fsName=[IO.Path]::GetFileName($fsPath)}}
  Try-AddLiteral $fsPath
  if($fsRecurse -ne 'true'){{
    $result=[ordered]@{{
      summary=@{{search_path=$fsPath;recursive=$fsRecurse;name_filter=(Fmt $fsName);extension=(Fmt $fsExt);owner=(Fmt $fsOwner);mtime_days=(Fmt $fsMtime);min_size=(Fmt $fsSize);matches=$found.Count;mode='exact_file'}}
      search=@{{path=$fsPath;name=$fsName;ext=$fsExt;size=$fsSize;owner=$fsOwner;mtime=$fsMtime;recursive=$fsRecurse}}
      matches=$found
    }}
    Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
    return
  }}
  $fsPath=Split-Path -Parent $fsPath
  if([string]::IsNullOrEmpty($fsPath)){{$fsPath='C:\'}}
}}

if(-not (Test-Path -LiteralPath $fsPath -EA 0)){{
  $result=[ordered]@{{
    summary=@{{search_path=$fsPath;matches=0;error='path not found'}}
    search=@{{path=$fsPath;name=$fsName;ext=$fsExt;size=$fsSize;owner=$fsOwner;mtime=$fsMtime;recursive=$fsRecurse}}
    matches=@()
  }}
  Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
  return
}}

try{{
  $exactName=(-not [string]::IsNullOrEmpty($fsName)) -and ($fsName -notmatch '[\*\?]')

  if($exactName){{Try-AddLiteral (Join-Path $fsPath $fsName)}}

  if($script:found.Count -lt 80 -and $exactName -and $fsRecurse -eq 'true'){{
    $whereLines=@(& where.exe /R $fsPath $fsName 2>$null)
    if(-not $whereLines -or $whereLines.Count -eq 0){{
      Get-ChildItem -Path $fsPath -Filter $fsName -Recurse -Force -ErrorAction SilentlyContinue|
        Select-Object -First 80|ForEach-Object{{Try-AddLiteral $_.FullName}}
    }}else{{
      foreach($line in $whereLines){{
        $line=$line.Trim()
        if($line){{Try-AddLiteral $line}}
        if($script:found.Count -ge 80){{break}}
      }}
    }}
  }}elseif($script:found.Count -lt 80){{
    $gciFilter=$null
    if(-not [string]::IsNullOrEmpty($fsName)){{$gciFilter=$fsName}}
    elseif(-not [string]::IsNullOrEmpty($fsExt)){{
      $e=$fsExt; if($e[0] -ne '.'){{$e='.'+$e}}
      $gciFilter='*'+$e
    }}
    $params=@{{Path=$fsPath;Force=$true;ErrorAction='SilentlyContinue'}}
    if($gciFilter){{$params['Filter']=$gciFilter}}
    if($fsRecurse -eq 'true'){{$params['Recurse']=$true}}
    Get-ChildItem @params|Select-Object -First 200|ForEach-Object{{
      if($script:found.Count -ge 80){{return}}
      if(-not (Test-NameFilter $_.Name)){{return}}
      if(Test-ItemFilters $_){{Add-Match $_}}
    }}
  }}
}}catch{{}}

$result=[ordered]@{{
  summary=@{{search_path=$fsPath;recursive=$fsRecurse;name_filter=(Fmt $fsName);extension=(Fmt $fsExt);owner=(Fmt $fsOwner);mtime_days=(Fmt $fsMtime);min_size=(Fmt $fsSize);matches=$found.Count}}
  search=@{{path=$fsPath;name=$fsName;ext=$fsExt;size=$fsSize;owner=$fsOwner;mtime=$fsMtime;recursive=$fsRecurse}}
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

    raw = _run_collector_marked(
        session, unix_cmd, win_ps, platform,
        90.0 if platform == 'windows' and opts.get('recursive') else (60.0 if platform == 'windows' else 45.0),
    )

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
