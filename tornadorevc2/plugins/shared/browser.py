"""Cross-platform browser enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import glob, json, os, subprocess
result = {'summary': {}, 'browsers': [], 'profiles': [], 'extensions': [], 'bookmarks': [], 'policies': []}

def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

browser_defs = [
    ('Google Chrome', os.path.expanduser('~/.config/google-chrome')),
    ('Chromium', os.path.expanduser('~/.config/chromium')),
    ('Microsoft Edge', os.path.expanduser('~/.config/microsoft-edge')),
    ('Brave', os.path.expanduser('~/.config/BraveSoftware/Brave-Browser')),
    ('Opera', os.path.expanduser('~/.config/opera')),
    ('Firefox', os.path.expanduser('~/.mozilla/firefox')),
]
for name, path in browser_defs:
    if os.path.isdir(path):
        result['browsers'].append({'name': name, 'path': path, 'installed': 'yes'})
        if 'firefox' in path.lower():
            for prof in glob.glob(os.path.join(path, '*.default*')) + glob.glob(os.path.join(path, '*release*')):
                result['profiles'].append({'browser': name, 'profile': prof})
                bm = os.path.join(prof, 'places.sqlite')
                if os.path.isfile(bm):
                    result['bookmarks'].append({'browser': name, 'store': bm})
                ext_dir = os.path.join(prof, 'extensions')
                if os.path.isdir(ext_dir):
                    for ext in os.listdir(ext_dir)[:20]:
                        result['extensions'].append({'browser': name, 'extension': ext})
        else:
            default = os.path.join(path, 'Default')
            if os.path.isdir(default):
                result['profiles'].append({'browser': name, 'profile': default})
                pref = os.path.join(default, 'Preferences')
                if os.path.isfile(pref):
                    try:
                        with open(pref, 'r', errors='ignore') as f:
                            prefs = json.load(f)
                        acct = prefs.get('account_info') or prefs.get('profile', {}).get('name')
                        if acct:
                            result['profiles'][-1]['account'] = str(acct)[:120]
                    except Exception:
                        pass
                bm = os.path.join(default, 'Bookmarks')
                if os.path.isfile(bm):
                    result['bookmarks'].append({'browser': name, 'store': bm})
                ext_dir = os.path.join(default, 'Extensions')
                if os.path.isdir(ext_dir):
                    for ext in os.listdir(ext_dir)[:25]:
                        result['extensions'].append({'browser': name, 'extension_id': ext})

# Enterprise policies
for pol in (
    '/etc/opt/chrome/policies/managed',
    '/etc/chromium/policies/managed',
    '/usr/lib/firefox/distribution/policies.json',
    '/etc/firefox/policies/policies.json',
):
    if os.path.exists(pol):
        result['policies'].append({'path': pol, 'present': 'yes'})

result['summary'] = {
    'Installed Browsers': len(result['browsers']),
    'Profiles': len(result['profiles']),
    'Extensions': len(result['extensions']),
    'Bookmark Stores': len(result['bookmarks']),
    'Policy Files': len(result['policies']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$browsers=@(); $profiles=@(); $extensions=@(); $bookmarks=@(); $policies=@()
$defs=@(
  @{{name='Google Chrome';root="$env:LOCALAPPDATA\Google\Chrome\User Data"}},
  @{{name='Microsoft Edge';root="$env:LOCALAPPDATA\Microsoft\Edge\User Data"}},
  @{{name='Brave';root="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"}},
  @{{name='Opera';root="$env:APPDATA\Opera Software\Opera Stable"}},
  @{{name='Firefox';root="$env:APPDATA\Mozilla\Firefox\Profiles"}}
)
foreach($d in $defs){{
  if(Test-Path $d.root){{
    $browsers+=@{{name=$d.name;path=$d.root;installed='yes'}}
    if($d.name -eq 'Firefox'){{
      Get-ChildItem $d.root -Directory -EA 0|ForEach-Object{{
        $profiles+=@{{browser=$d.name;profile=$_.FullName}}
        $bm=Join-Path $_.FullName 'places.sqlite'
        if(Test-Path $bm){{$bookmarks+=@{{browser=$d.name;store=$bm}}}}
      }}
    }} else {{
      $def=Join-Path $d.root 'Default'
      if(Test-Path $def){{
        $profiles+=@{{browser=$d.name;profile=$def}}
        $bm=Join-Path $def 'Bookmarks'
        if(Test-Path $bm){{$bookmarks+=@{{browser=$d.name;store=$bm}}}}
        $ext=Join-Path $def 'Extensions'
        if(Test-Path $ext){{
          Get-ChildItem $ext -Directory -EA 0|Select-Object -First 25|ForEach-Object{{
            $extensions+=@{{browser=$d.name;extension_id=$_.Name}}
          }}
        }}
      }}
    }}
  }}
}}
foreach($rk in @(
  'HKLM:\Software\Policies\Google\Chrome',
  'HKLM:\Software\Policies\Microsoft\Edge',
  'HKLM:\Software\Policies\Mozilla\Firefox',
  'HKCU:\Software\Policies\Google\Chrome'
)){{
  if(Test-Path $rk){{ $policies+=@{{key=$rk;present='yes'}} }}
}}
$result=[ordered]@{{
  summary=@{{Installed_Browsers=$browsers.Count;Profiles=$profiles.Count;Extensions=$extensions.Count;Bookmark_Stores=$bookmarks.Count;Policies=$policies.Count}}
  browsers=$browsers
  profiles=$profiles
  extensions=$extensions
  bookmarks=$bookmarks
  policies=$policies
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='browser',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate installed browsers, profiles, extensions, bookmarks, and policies',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'browser',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=45.0,
    )
