"""Cross-platform proxy settings enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import glob, os, subprocess
result = {'summary': {}, 'environment': {}, 'system': {}, 'browser': {}, 'pac_wpad': []}

def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

for var in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY', 'no_proxy', 'NO_PROXY'):
    val = os.environ.get(var)
    if val:
        result['environment'][var] = val

# gsettings (GNOME)
for schema, key in (
    ('org.gnome.system.proxy', 'mode'),
    ('org.gnome.system.proxy.http', 'host'),
    ('org.gnome.system.proxy.http', 'port'),
    ('org.gnome.system.proxy.https', 'host'),
    ('org.gnome.system.proxy', 'autoconfig-url'),
):
    val = sh(f'gsettings get {schema} {key} 2>/dev/null').strip()
    if val and val != "''":
        result['browser'][f'{schema}/{key}'] = val

# /etc/environment
if os.path.isfile('/etc/environment'):
    try:
        with open('/etc/environment', 'r', errors='ignore') as f:
            for line in f:
                if 'proxy' in line.lower():
                    result['system'][line.strip().split('=')[0]] = line.strip()
    except Exception:
        pass

# apt proxy
for path in ('/etc/apt/apt.conf.d/proxy.conf', '/etc/apt/apt.conf'):
    if os.path.isfile(path):
        try:
            with open(path, 'r', errors='ignore') as f:
                result['system'][path] = f.read()[:800]
        except Exception:
            pass

# WPAD / PAC
for path in glob.glob('/etc/wpad*.pac') + glob.glob('/usr/share/wpad*.pac'):
    result['pac_wpad'].append({'path': path, 'type': 'pac_file'})

# nmcli proxy
proxy = sh('nmcli dev show 2>/dev/null | grep -i proxy')
if proxy.strip():
    result['system']['NetworkManager'] = proxy[:1000]

result['summary'] = {
    'Env Proxy Vars': len(result['environment']),
    'System Entries': len(result['system']),
    'Browser/GNOME Settings': len(result['browser']),
    'PAC/WPAD Files': len(result['pac_wpad']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$envProxy=@{{}}; $system=@{{}}; $browser=@{{}}; $pac=@()
foreach($v in 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY'){{
  $val=[Environment]::GetEnvironmentVariable($v)
  if($val){{ $envProxy[$v]=$val }}
}}
try{{
  $winhttp=netsh winhttp show proxy 2>$null
  if($winhttp){{ $system['winhttp']=$winhttp -join "`n" }}
}}catch{{}}
try{{
  $ie=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA 0
  if($ie){{
    $browser['ProxyEnable']=$ie.ProxyEnable
    $browser['ProxyServer']=$ie.ProxyServer
    $browser['AutoConfigURL']=$ie.AutoConfigURL
    $browser['AutoDetect']=$ie.AutoDetect
    if($ie.AutoConfigURL){{ $pac+=@{{source='IE_AutoConfigURL';url=$ie.AutoConfigURL}} }}
  }}
}}catch{{}}
try{{
  $user=Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -EA 0
  if($user){{
    $browser['Policy_ProxySettings']='present'
    if($user.ProxyServer){{ $browser['Policy_ProxyServer']=$user.ProxyServer }}
  }}
}}catch{{}}
foreach($rk in @(
  'HKLM:\Software\Policies\Google\Chrome',
  'HKLM:\Software\Policies\Microsoft\Edge'
)){{
  if(Test-Path $rk){{
    $p=Get-ItemProperty $rk -EA 0
    if($p.ProxyMode){{ $browser["$rk/ProxyMode"]=$p.ProxyMode }}
    if($p.ProxyServer){{ $browser["$rk/ProxyServer"]=$p.ProxyServer }}
    if($p.ProxyPacUrl){{ $pac+=@{{source=$rk;url=$p.ProxyPacUrl}} }}
  }}
}}
$result=[ordered]@{{
  summary=@{{Env_Vars=$envProxy.Count;System=$system.Count;Browser=$browser.Count;PAC=$pac.Count}}
  environment=$envProxy
  system=$system
  browser=$browser
  pac_wpad=$pac
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='proxy',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate system, environment, PAC/WPAD, and browser proxy settings',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'proxy',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=40.0,
    )
