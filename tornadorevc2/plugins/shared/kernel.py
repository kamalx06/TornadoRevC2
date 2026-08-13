"""Cross-platform kernel version, modules, and security configuration enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os, subprocess, platform

def rd(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read().strip()
    except Exception:
        return ''

def run_cmd(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def sysctl(key):
    return rd('/proc/sys/' + key.replace('.', '/'))

modules = []
mod_text = rd('/proc/modules')
if mod_text:
    for line in mod_text.splitlines()[:80]:
        parts = line.split()
        if parts:
            modules.append({'name': parts[0], 'size': parts[1] if len(parts) > 1 else '', 'used_by': parts[3] if len(parts) > 3 else ''})

mitigations = {
    'kptr_restrict': sysctl('kernel/kptr_restrict'),
    'dmesg_restrict': sysctl('kernel/dmesg_restrict'),
    'perf_event_paranoid': sysctl('kernel/perf_event_paranoid'),
    'unprivileged_bpf_disabled': sysctl('kernel/unprivileged_bpf_disabled'),
    'randomize_va_space': sysctl('kernel/randomize_va_space'),
    'ptrace_scope': sysctl('kernel/yama/ptrace_scope'),
    'lockdown': rd('/sys/kernel/security/lockdown')[:200],
}

virt = {}
for path, key in (
    ('/sys/hypervisor/type', 'hypervisor_type'),
    ('/proc/cpuinfo', 'cpuinfo'),
):
    val = rd(path)
    if val:
        virt[key] = val[:300] if key == 'cpuinfo' else val

cmdline = rd('/proc/cmdline')
config_gz = run_cmd('zcat /proc/config.gz 2>/dev/null | grep -E "SECURITY|HARDEN|KASLR|STACKPROTECTOR|LOCKDOWN" | head -25')

result = {
    'summary': {
        'kernel': platform.release(),
        'architecture': platform.machine(),
        'modules_loaded': len(modules),
        'mitigations_set': sum(1 for v in mitigations.values() if v),
    },
    'kernel_version': {
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'proc_version': rd('/proc/version'),
    },
    'loaded_modules': modules[:60],
    'security_mitigations': mitigations,
    'boot_cmdline': cmdline[:400],
    'kernel_config': config_gz.strip().splitlines()[:25] if config_gz else [],
    'virtualization': virt,
    'uname': run_cmd('uname -a 2>/dev/null').strip(),
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$modules=@(); $mitigations=@{{}}; $os=@{{}}

try{{
  $osInfo=Get-CimInstance Win32_OperatingSystem -EA 0
  if($osInfo){{
    $os=@{{caption=$osInfo.Caption;version=$osInfo.Version;build=$osInfo.BuildNumber;arch=$osInfo.OSArchitecture;install=$osInfo.InstallDate}}
  }}
}}catch{{}}

try{{
  driverquery /fo csv 2>$null|Select-Object -Skip 1|Select-Object -First 60|ForEach-Object{{
    $f=$_.Split(',')|ForEach-Object{{$_ -replace '"',''}}
    if($f.Count -ge 4){{$modules+=@{{name=$f[0];display=$f[1];type=$f[3]}}}}
  }}
}}catch{{}}

try{{
  $dg=Get-CimInstance -ClassName Win32_DeviceGuard -EA 0
  if($dg){{
    $mitigations['virtualization_based_security']=$dg.VirtualizationBasedSecurityStatus
    $mitigations['code_integrity']=$dg.CodeIntegrityPolicyEnforcementStatus
    $mitigations['credential_guard']=$dg.SecurityServicesConfigured
    $mitigations['hvci']=$dg.VirtualizationBasedSecurityStatus
  }}
}}catch{{}}

try{{
  $kcfg=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -EA 0
  if($kcfg){{
    $mitigations['disable_tsx']=$kcfg.DisableTsx
    $mitigations['mitigation_options']=$kcfg.MitigationOptions
  }}
}}catch{{}}

try{{
  $bcd=bcdedit /enum '{{current}}' 2>$null
  $mitigations['bcdedit']=@($bcd|Select-Object -First 25)
}}catch{{}}

try{{
  systeminfo /fo csv 2>$null|ConvertFrom-Csv|ForEach-Object{{
    $os['systeminfo_os']=$_.'OS Name'
    $os['systeminfo_version']=$_.'OS Version'
    $os['systeminfo_boot']=$_.'System Boot Time'
    $os['hypervisor']=$_.'Hyper-V Requirements'
  }}
}}catch{{}}

$result=[ordered]@{{
  summary=@{{kernel=($os.version);build=($os.build);modules=$modules.Count}}
  kernel_version=$os
  loaded_modules=$modules
  security_mitigations=$mitigations
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='kernel',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate kernel version, loaded modules, security mitigations, and kernel configuration',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'kernel',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=40.0,
    )
