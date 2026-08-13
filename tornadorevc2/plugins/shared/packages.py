"""Cross-platform installed software and package manager enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os, subprocess

def sh(cmd, timeout=10):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

result = {'summary': {}, 'managers': {}, 'recent': [], 'repositories': []}
managers = []
pkg_count = 0

if which('dpkg'):
    managers.append('dpkg')
    listing = sh('dpkg-query -W -f="${Package}\t${Version}\t${Status}\n" 2>/dev/null', 15)
    pkgs = []
    for line in listing.splitlines()[:60]:
        parts = line.split('\t')
        if len(parts) >= 2:
            pkgs.append({'package': parts[0], 'version': parts[1], 'status': parts[2] if len(parts) > 2 else ''})
    result['managers']['dpkg'] = {'count': len(listing.splitlines()), 'sample': pkgs}
    pkg_count += len(listing.splitlines())
    recent = sh('grep " install " /var/log/dpkg.log 2>/dev/null | tail -20')
    if recent:
        result['recent'].append({'manager': 'dpkg', 'entries': recent.splitlines()[-15:]})
    sources = sh('cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null')
    if sources.strip():
        result['repositories'].append({'manager': 'apt', 'config': sources.splitlines()[:25]})

if which('rpm'):
    managers.append('rpm')
    listing = sh('rpm -qa --queryformat "%{NAME}\t%{VERSION}-%{RELEASE}\n" 2>/dev/null', 15)
    pkgs = []
    for line in listing.splitlines()[:60]:
        parts = line.split('\t')
        if parts:
            pkgs.append({'package': parts[0], 'version': parts[1] if len(parts) > 1 else ''})
    result['managers']['rpm'] = {'count': len(listing.splitlines()), 'sample': pkgs}
    pkg_count += len(listing.splitlines())
    recent = sh('grep "Installed:" /var/log/yum.log /var/log/dnf.log 2>/dev/null | tail -15')
    if recent:
        result['recent'].append({'manager': 'rpm/yum/dnf', 'entries': recent.splitlines()[-15:]})
    repos = sh('cat /etc/yum.repos.d/*.repo /etc/dnf/dnf.conf 2>/dev/null')
    if repos.strip():
        result['repositories'].append({'manager': 'yum/dnf', 'config': repos.splitlines()[:25]})

if which('pacman'):
    managers.append('pacman')
    listing = sh('pacman -Q 2>/dev/null', 12)
    pkgs = [{'package': ' '.join(l.split()[:-1]), 'version': l.split()[-1]} for l in listing.splitlines()[:60] if l.split()]
    result['managers']['pacman'] = {'count': len(listing.splitlines()), 'sample': pkgs}
    pkg_count += len(listing.splitlines())

if which('apk'):
    managers.append('apk')
    listing = sh('apk info -v 2>/dev/null', 12)
    pkgs = [{'package': l} for l in listing.splitlines()[:60]]
    result['managers']['apk'] = {'count': len(listing.splitlines()), 'sample': pkgs}
    pkg_count += len(listing.splitlines())

if which('snap'):
    managers.append('snap')
    listing = sh('snap list 2>/dev/null', 10)
    result['managers']['snap'] = {'output': listing.splitlines()[:40]}

if which('flatpak'):
    managers.append('flatpak')
    listing = sh('flatpak list --columns=application,version,origin 2>/dev/null', 10)
    result['managers']['flatpak'] = {'output': listing.splitlines()[:40]}

if which('pip') or which('pip3'):
    pip = 'pip3' if which('pip3') else 'pip'
    managers.append(pip)
    listing = sh(f'{pip} list --format=columns 2>/dev/null | head -40', 10)
    if listing.strip():
        result['managers'][pip] = {'output': listing.splitlines()[:40]}

if which('brew'):
    managers.append('brew')
    listing = sh('brew list --versions 2>/dev/null', 10)
    pkgs = []
    for line in listing.splitlines()[:60]:
        parts = line.split()
        if parts:
            pkgs.append({'package': parts[0], 'version': ' '.join(parts[1:])})
    result['managers']['brew'] = {'count': len(listing.splitlines()), 'sample': pkgs}

result['summary'] = {
    'package_managers': ', '.join(managers) if managers else 'none detected',
    'estimated_packages': pkg_count,
    'recent_install_logs': len(result['recent']),
    'repository_configs': len(result['repositories']),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$managers=@{{}}; $recent=@(); $repos=@(); $names=@(); $packages=@()

try{{
  Get-Package -EA 0|Select-Object -First 60 Name,Version,ProviderName|ForEach-Object{{
    $packages+=@{{name=$_.Name;version=$_.Version;provider=$_.ProviderName}}
  }}
  if($packages){{$managers['Get-Package']=@{{count=$packages.Count;sample=$packages}}; $names+='Get-Package'}}
}}catch{{}}

$uninstall=@()
try{{
  $paths=@(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  foreach($p in $paths){{
    Get-ItemProperty $p -EA 0|Where-Object{{$_.DisplayName}}|Select-Object -First 40 DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation|ForEach-Object{{
      $uninstall+=@{{name=$_.DisplayName;version=$_.DisplayVersion;publisher=$_.Publisher;date=$_.InstallDate;path=$_.InstallLocation}}
    }}
  }}
  if($uninstall){{$names+='registry'}}
}}catch{{}}

$winget=@()
try{{
  $w=winget list 2>$null
  if($LASTEXITCODE -eq 0 -or $w){{
    $winget=@($w|Select-Object -Skip 2|Select-Object -First 40)
    $names+='winget'
  }}
}}catch{{}}
$managers['registry_uninstall']=@{{count=$uninstall.Count;sample=$uninstall|Select-Object -First 60}}
$managers['winget']=@{{output=$winget}}

$choco=@()
try{{
  if(Get-Command choco -EA 0){{
    $choco=@((choco list -l 2>$null)|Select-Object -First 40)
    $names+='choco'
    $managers['choco']=@{{output=$choco}}
  }}
}}catch{{}}

try{{
  $recentEvents=Get-WinEvent -FilterHashtable @{{LogName='Application';ProviderName='MsiInstaller';StartTime=(Get-Date).AddDays(-30)}} -MaxEvents 20 -EA 0|
    Select-Object TimeCreated,Id,Message|ForEach-Object{{@{{time=$_.TimeCreated.ToString('s');id=$_.Id;msg=($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(160,$_.Message.Length))}}}}
  if($recentEvents){{$recent+=@{{source='MsiInstaller';events=$recentEvents}}}}
}}catch{{}}

try{{
  $repoPath='HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
  if(Test-Path $repoPath){{$repos+=@{{type='installer_cache';path=$repoPath}}}}
}}catch{{}}

$result=[ordered]@{{
  summary=@{{package_managers=($names -join ', ');registry_entries=$uninstall.Count;winget_lines=$winget.Count;choco_lines=$choco.Count}}
  managers=$managers
  recent=$recent
  repositories=$repos
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


@plugin.command(
    name='packages',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate installed software, package managers, repositories, and recent installs',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'packages',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=50.0,
    )
