"""Cross-platform credential store enumeration (metadata only)."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import glob, os, subprocess
result = {'summary': {}, 'gnome_keyring': {}, 'kwallet': {}, 'browser_stores': [], 'ssh_agent': {}, 'other': []}

def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

# GNOME Keyring / libsecret
if which('secret-tool'):
    st = sh('secret-tool search service "" 2>/dev/null | head -20', 6)
    result['gnome_keyring'] = {'available': 'yes', 'sample': st[:1500] if st else 'empty or inaccessible'}
else:
    result['gnome_keyring'] = {'available': 'no'}
for kr in glob.glob(os.path.expanduser('~/.local/share/keyrings/*')) + glob.glob('/home/*/.local/share/keyrings/*'):
    if os.path.isfile(kr):
        try:
            result['other'].append(f'keyring file: {kr} ({os.path.getsize(kr)} bytes)')
        except Exception:
            result['other'].append(f'keyring file: {kr}')

# KWallet
if which('kwallet-query'):
    result['kwallet'] = {'available': 'yes', 'note': 'kwallet-query present (metadata enumeration only)'}
else:
    result['kwallet'] = {'available': 'no'}

# Browser credential store metadata (paths only, no decryption)
browser_paths = [
    os.path.expanduser('~/.config/google-chrome/Default/Login Data'),
    os.path.expanduser('~/.config/chromium/Default/Login Data'),
    os.path.expanduser('~/.mozilla/firefox'),
    os.path.expanduser('~/.config/microsoft-edge/Default/Login Data'),
    os.path.expanduser('~/.config/brave-browser/Default/Login Data'),
]
for bp in browser_paths:
    if os.path.exists(bp):
        info = {'path': bp, 'type': 'file' if os.path.isfile(bp) else 'directory'}
        try:
            if os.path.isfile(bp):
                info['size'] = os.path.getsize(bp)
        except Exception:
            pass
        result['browser_stores'].append(info)
for prof in glob.glob(os.path.expanduser('~/.mozilla/firefox/*.default*')):
    login = os.path.join(prof, 'logins.json')
    if os.path.isfile(login):
        result['browser_stores'].append({'path': login, 'type': 'firefox_logins_json'})

# SSH agent
agent = os.environ.get('SSH_AUTH_SOCK', '')
if agent:
    result['ssh_agent'] = {'socket': agent, 'present': 'yes'}

result['summary'] = {
    'GNOME Keyring': result['gnome_keyring'].get('available', 'N/A'),
    'KWallet': result['kwallet'].get('available', 'N/A'),
    'Browser Stores': len(result['browser_stores']),
    'Other Artifacts': len(result['other']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$credMgr=@()
try{{
  cmdkey /list 2>$null|ForEach-Object{{ if($_.Trim()){{ $credMgr+=$_.Trim() }} }}
}}catch{{}}
$vault=@()
try{{
  $v=Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Microsoft\Vault" -Recurse -EA 0 -File|Select-Object -First 15 FullName,Length
  $vault=@($v|ForEach-Object{{ @{{path=$_.FullName;size=$_.Length}} }})
}}catch{{}}
$browsers=@()
$paths=@(
  "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
  "$env:APPDATA\Mozilla\Firefox\Profiles",
  "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
)
foreach($p in $paths){{
  if(Test-Path $p){{
    $item=Get-Item $p -EA 0
    $browsers+=@{{path=$p;type=if($item.PSIsContainer){{'directory'}}else{{'file'}};size=if(-not $item.PSIsContainer){{$item.Length}}}}
  }}
}}
$policies=@()
foreach($rk in @(
  'HKLM:\Software\Policies\Google\Chrome',
  'HKLM:\Software\Policies\Microsoft\Edge',
  'HKCU:\Software\Policies\Google\Chrome'
)){{
  if(Test-Path $rk){{
    $policies+=@{{key=$rk;present='yes'}}
  }}
}}
$result=[ordered]@{{
  summary=@{{
    Credential_Manager_Entries=$credMgr.Count
    Vault_Files=$vault.Count
    Browser_Stores=$browsers.Count
    Browser_Policies=$policies.Count
  }}
  credential_manager=$credMgr
  vault_files=$vault
  browser_stores=$browsers
  browser_policies=$policies
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='credstore',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate credential stores and related metadata (no secret extraction)',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'credstore',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=40.0,
    )
