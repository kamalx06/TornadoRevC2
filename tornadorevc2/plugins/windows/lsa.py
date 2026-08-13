"""Windows LSA and credential security feature enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$lsa=@{{}}; $deviceGuard=@{{}}; $credGuard=@{{}}; $vbs=@{{}}; $authPackages=@()

try{{
  $lsaPath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $lsaProps=Get-ItemProperty $lsaPath -EA 0
  if($lsaProps){{
    $lsa=@{{RunAsPPL=$lsaProps.RunAsPPL;LmCompatibilityLevel=$lsaProps.LmCompatibilityLevel;LimitBlankPasswordUse=$lsaProps.LimitBlankPasswordUse;NoLMHash=$lsaProps.NoLMHash;RestrictAnonymous=$lsaProps.RestrictAnonymous;RestrictAnonymousSAM=$lsaProps.RestrictAnonymousSAM;EveryoneIncludesAnonymous=$lsaProps.EveryoneIncludesAnonymous;DisableDomainCreds=$lsaProps.DisableDomainCreds;UseLogonCredential=$lsaProps.UseLogonCredential;AuthenticationPackages=@($lsaProps.AuthenticationPackages);SecurityPackages=@($lsaProps.SecurityPackages)}}
    $authPackages=@($lsaProps.AuthenticationPackages)
  }}
}}catch{{}}

try{{
  $dg=Get-CimInstance -ClassName Win32_DeviceGuard -EA 0
  if($dg){{
    $deviceGuard=@{{AvailableSecurityProperties=@($dg.AvailableSecurityProperties);RequiredSecurityProperties=@($dg.RequiredSecurityProperties);SecurityServicesConfigured=@($dg.SecurityServicesConfigured);SecurityServicesRunning=@($dg.SecurityServicesRunning);VirtualizationBasedSecurityStatus=$dg.VirtualizationBasedSecurityStatus;CodeIntegrityPolicyEnforcementStatus=$dg.CodeIntegrityPolicyEnforcementStatus}}
  }}
}}catch{{}}

try{{
  $cgPath='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
  if(Test-Path $cgPath){{
    $cg=Get-ItemProperty $cgPath -EA 0
    $credGuard=@{{EnableVirtualizationBasedSecurity=$cg.EnableVirtualizationBasedSecurity;RequirePlatformSecurityFeatures=$cg.RequirePlatformSecurityFeatures;Locked=$cg.Locked;CredentialGuard=$cg.LsaCfgFlags}}
  }}
  $lsaiso='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags'
  if(Test-Path $lsaiso){{
    $credGuard.lsa_cfg_flags=(Get-ItemProperty $lsaiso -EA 0).LsaCfgFlags
  }}
}}catch{{}}

try{{
  $hvci='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
  if(Test-Path $hvci){{
    $vbs.hvci=(Get-ItemProperty $hvci -EA 0).Enabled
  }}
  $kcfg='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\Cfg'
  if(Test-Path $kcfg){{
    $vbs.kernel_cfg=(Get-ItemProperty $kcfg -EA 0)
  }}
}}catch{{}}

$wdigest=@{{}}
try{{
  $wdPath='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
  if(Test-Path $wdPath){{
    $wdigest.UseLogonCredential=(Get-ItemProperty $wdPath -EA 0).UseLogonCredential
  }}
}}catch{{}}

$tpm=@{{}}
try{{
  $t=Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftTpm -ClassName Win32_Tpm -EA 0
  if($t){{$tpm=@{{present=$true;enabled=$t.IsEnabled_InitialValue;activated=$t.IsActivated_InitialValue;owned=$t.IsOwned_InitialValue}}}}
}}catch{{}}

$runAsPPL=$lsa.RunAsPPL
$result=[ordered]@{{
  summary=@{{lsa_protection=($runAsPPL -eq 1);credential_guard_configured=($credGuard.CredentialGuard -ne $null -or $credGuard.lsa_cfg_flags -ne $null);vbs_status=$deviceGuard.VirtualizationBasedSecurityStatus;wdigest_enabled=($wdigest.UseLogonCredential -eq 1)}}
  lsa=$lsa
  device_guard=$deviceGuard
  credential_guard=$credGuard
  virtualization_based_security=$vbs
  wdigest=$wdigest
  authentication_packages=$authPackages
  tpm=$tpm
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


@plugin.command(
    name='lsa',
    platforms=['windows'],
    description='Enumerate LSA protection, Credential Guard, VBS, and authentication security configuration',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'lsa', None, build_command, format_generic_report, timeout=35.0)
