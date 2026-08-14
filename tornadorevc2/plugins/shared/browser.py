"""Cross-platform browser enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import glob, json, os, subprocess, configparser, time

result = {
    'summary': {},
    'browsers': [],
    'profiles': [],
    'extensions': [],
    'bookmarks': [],
    'artifacts': [],
    'policies': [],
    'native_messaging': [],
    'packages': [],
    'environment': {},
}

def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

# Detect browser binaries
for binary in (
    'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser',
    'firefox', 'zen', 'zen-browser', 'brave-browser',
    'microsoft-edge', 'microsoft-edge-stable',
    'opera', 'vivaldi'
):
    path = sh(f'which {binary}').strip()
    if path:
        result['packages'].append({'binary': binary, 'path': path})

# Default browser
result['environment']['default_browser'] = sh('xdg-settings get default-web-browser').strip()
result['environment']['browser_env'] = os.environ.get('BROWSER', '')

browser_defs = [
    ('Google Chrome', os.path.expanduser('~/.config/google-chrome')),
    ('Chromium', os.path.expanduser('~/.config/chromium')),
    ('Microsoft Edge', os.path.expanduser('~/.config/microsoft-edge')),
    ('Brave', os.path.expanduser('~/.config/BraveSoftware/Brave-Browser')),
    ('Opera', os.path.expanduser('~/.config/opera')),
    ('Vivaldi', os.path.expanduser('~/.config/vivaldi')),
    ('Firefox', os.path.expanduser('~/.mozilla/firefox')),
    ('Zen Browser', os.path.expanduser('~/.zen')),
]

for name, path in browser_defs:
    if not os.path.isdir(path):
        continue

    result['browsers'].append({'name': name, 'path': path, 'installed': 'yes'})

    if name in ('Firefox', 'Zen Browser'):
        ini = os.path.join(path, 'profiles.ini')
        profiles = []

        if os.path.isfile(ini):
            cp = configparser.ConfigParser()
            try:
                cp.read(ini)
                for section in cp.sections():
                    if section.startswith('Profile'):
                        p = cp.get(section, 'Path', fallback='')
                        if p:
                            if cp.get(section, 'IsRelative', fallback='1') == '1':
                                p = os.path.join(path, p)
                            profiles.append(p)
            except Exception:
                pass

        if not profiles:
            profiles = glob.glob(os.path.join(path, '*.default*')) + glob.glob(os.path.join(path, '*release*'))

        for prof in profiles:
            entry = {'browser': name, 'profile': prof}
            result['profiles'].append(entry)

            for artifact in ('places.sqlite', 'cookies.sqlite', 'logins.json', 'key4.db'):
                p = os.path.join(prof, artifact)
                if os.path.exists(p):
                    result['artifacts'].append({
                        'browser': name,
                        'artifact': artifact,
                        'path': p,
                        'size': os.path.getsize(p),
                    })

            ext_dir = os.path.join(prof, 'extensions')
            if os.path.isdir(ext_dir):
                for ext in os.listdir(ext_dir)[:100]:
                    result['extensions'].append({'browser': name, 'extension': ext})

    else:
        profile_dirs = []
        for pattern in ('Default', 'Profile *', 'Guest Profile', 'System Profile'):
            profile_dirs.extend(glob.glob(os.path.join(path, pattern)))

        for prof in sorted(set(profile_dirs)):
            entry = {'browser': name, 'profile': prof}

            pref = os.path.join(prof, 'Preferences')
            if os.path.isfile(pref):
                try:
                    with open(pref, 'r', errors='ignore') as f:
                        prefs = json.load(f)
                    acct = prefs.get('account_info') or prefs.get('profile', {}).get('name')
                    if acct:
                        entry['account'] = str(acct)[:120]
                except Exception:
                    pass

            result['profiles'].append(entry)

            for artifact in ('Bookmarks', 'History', 'Login Data', 'Cookies', 'Web Data', 'Favicons'):
                p = os.path.join(prof, artifact)
                if os.path.exists(p):
                    result['artifacts'].append({
                        'browser': name,
                        'artifact': artifact,
                        'path': p,
                        'size': os.path.getsize(p),
                    })

            ext_dir = os.path.join(prof, 'Extensions')
            if os.path.isdir(ext_dir):
                for ext in os.listdir(ext_dir)[:200]:
                    ext_path = os.path.join(ext_dir, ext)
                    version = ''
                    manifest_name = ''
                    try:
                        versions = sorted(os.listdir(ext_path), reverse=True)
                        if versions:
                            version = versions[0]
                            manifest = os.path.join(ext_path, version, 'manifest.json')
                            if os.path.isfile(manifest):
                                with open(manifest, 'r', errors='ignore') as f:
                                    m = json.load(f)
                                manifest_name = m.get('name', '')
                    except Exception:
                        pass
                    result['extensions'].append({
                        'browser': name,
                        'extension_id': ext,
                        'version': version,
                        'name': manifest_name,
                    })

# Enterprise policies
for pol in (
    '/etc/opt/chrome/policies/managed',
    '/etc/chromium/policies/managed',
    '/etc/opt/edge/policies/managed',
    '/etc/brave/policies/managed',
    '/usr/lib/firefox/distribution/policies.json',
    '/etc/firefox/policies/policies.json',
):
    if os.path.exists(pol):
        result['policies'].append({'path': pol, 'present': 'yes'})

# Native messaging hosts
for nm in (
    '/etc/opt/chrome/native-messaging-hosts',
    '/etc/chromium/native-messaging-hosts',
    os.path.expanduser('~/.config/google-chrome/NativeMessagingHosts'),
    os.path.expanduser('~/.config/chromium/NativeMessagingHosts'),
):
    if os.path.isdir(nm):
        for entry in os.listdir(nm):
            result['native_messaging'].append({'path': os.path.join(nm, entry)})

result['summary'] = {
    'Installed Browsers': len(result['browsers']),
    'Profiles': len(result['profiles']),
    'Extensions': len(result['extensions']),
    'Browser Artifacts': len(result['artifacts']),
    'Policy Files': len(result['policies']),
    'Native Messaging Hosts': len(result['native_messaging']),
    'Detected Binaries': len(result['packages']),
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
  @{{name='Chromium';root="$env:LOCALAPPDATA\Chromium\User Data"}},
  @{{name='Microsoft Edge';root="$env:LOCALAPPDATA\Microsoft\Edge\User Data"}},
  @{{name='Brave';root="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"}},
  @{{name='Vivaldi';root="$env:LOCALAPPDATA\Vivaldi\User Data"}},
  @{{name='Opera';root="$env:APPDATA\Opera Software\Opera Stable"}},
  @{{name='Opera GX';root="$env:APPDATA\Opera Software\Opera GX Stable"}},
  @{{name='Firefox';root="$env:APPDATA\Mozilla\Firefox\Profiles"}},
  @{{name='Zen Browser';root="$env:APPDATA\zen\Profiles"}},
  @{{name='Arc';root="$env:LOCALAPPDATA\Packages\TheBrowserCompany.Arc*\LocalCache\Local\Arc\User Data"}}
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
  'HKCU:\Software\Policies\Google\Chrome',
  'HKLM:\Software\Policies\Chromium',
  'HKCU:\Software\Policies\Chromium',
  'HKLM:\Software\Policies\Microsoft\Edge',
  'HKCU:\Software\Policies\Microsoft\Edge',
  'HKLM:\Software\Policies\BraveSoftware\Brave',
  'HKCU:\Software\Policies\BraveSoftware\Brave',
  'HKLM:\Software\Policies\Vivaldi',
  'HKCU:\Software\Policies\Vivaldi',
  'HKLM:\Software\Policies\Mozilla\Firefox',
  'HKCU:\Software\Policies\Mozilla\Firefox',
  'HKLM:\Software\Policies\Zen',
  'HKCU:\Software\Policies\Zen'
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
