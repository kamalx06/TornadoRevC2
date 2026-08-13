"""Cross-platform integrity and security posture assessment."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import os, subprocess

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

secure_boot = run_cmd('mokutil --sb-state 2>/dev/null').strip()
if not secure_boot and os.path.isfile('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'):
    secure_boot = 'EFI SecureBoot variable present'

luks = []
lsblk = run_cmd('lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT 2>/dev/null')
if lsblk:
    for line in lsblk.splitlines()[1:]:
        if 'crypt' in line.lower() or 'luks' in line.lower():
            luks.append(line.strip())

lockdown = rd('/sys/kernel/security/lockdown')
ima = rd('/sys/kernel/security/integrity/ima/policy')[:200]

signing = {
    'module_sig_enforce': rd('/sys/module/module/parameters/sig_enforce'),
    'lockdown_mode': lockdown[:120] if lockdown else '',
}

# dm-verity / integrity
verity = run_cmd('findmnt -no SOURCE,OPTIONS / 2>/dev/null').strip()

# SIP not applicable on Linux; note kernel lockdown
result = {
    'summary': {
        'secure_boot': bool(secure_boot),
        'luks_volumes': len(luks),
        'lockdown': bool(lockdown),
        'module_sig_enforce': signing.get('module_sig_enforce', ''),
    },
    'secure_boot': secure_boot or 'N/A',
    'disk_encryption': luks or ['N/A'],
    'kernel_lockdown': lockdown or 'N/A',
    'code_signing': signing,
    'integrity_measurement': {'ima_policy': ima or 'N/A'},
    'root_filesystem': verity or 'N/A',
    'sip': 'N/A (macOS only)',
}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$secureBoot='N/A'; $bitlocker=@(); $signing=@{{}}; $deviceGuard=@{{}}; $sip='N/A'

try{{
  Confirm-SecureBootUEFI -EA Stop|Out-Null
  $secureBoot='Enabled'
}}catch{{
  try{{$secureBoot=($(Confirm-SecureBootUEFI -EA 0) -eq $true) -as [string]}}catch{{$secureBoot='N/A'}}
}}

try{{
  manage-bde -status 2>$null|ForEach-Object{{if($_.Trim()){{$bitlocker+=@{{line=$_.Trim()}}}}}}
  Get-BitLockerVolume -EA 0|ForEach-Object{{
    $bitlocker+=@{{mount=$_.MountPoint;protection=$_.ProtectionStatus;encryption=$_.EncryptionPercentage;method=$_.EncryptionMethod}}
  }}
}}catch{{}}

try{{
  $dg=Get-CimInstance -ClassName Win32_DeviceGuard -EA 0
  if($dg){{
    $deviceGuard=@{{vbs=$dg.VirtualizationBasedSecurityStatus;ci=$dg.CodeIntegrityPolicyEnforcementStatus;services=$dg.SecurityServicesConfigured}}
  }}
}}catch{{}}

try{{
  $ci=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -EA 0
  if($ci){{$signing['policy_info']=$ci.PolicyInfo}}
  $ciState=Get-CimInstance -ClassName Win32_CodeSigningPolicy -EA 0
  if($ciState){{$signing['code_signing_policy']=$ciState}}
}}catch{{}}

try{{
  $tpm=Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftTpm -ClassName Win32_Tpm -EA 0
  if($tpm){{$signing['tpm_present']=$tpm.IsActivated_InitialValue;$signing['tpm_enabled']=$tpm.IsEnabled_InitialValue}}
}}catch{{}}

$result=[ordered]@{{
  summary=@{{secure_boot=$secureBoot;bitlocker_volumes=$bitlocker.Count;device_guard=($deviceGuard.Count -gt 0)}}
  secure_boot=$secureBoot
  bitlocker=@($bitlocker|Select-Object -First 20)
  device_guard=$deviceGuard
  code_signing=$signing
  kernel_lockdown='N/A'
  sip=$sip
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""


@plugin.command(
    name='integrity',
    platforms=['linux', 'windows', 'unix'],
    description='Assess Secure Boot, disk encryption, code signing, kernel lockdown, and integrity protections',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'integrity',
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=40.0,
    )
