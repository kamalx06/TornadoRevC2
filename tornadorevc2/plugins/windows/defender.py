"""Windows Defender and security product enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


DEFENDER_USAGE = """defender - Windows Defender enumeration and control

USAGE:
    defender [options]

OPTIONS:
    -d, --disable   Attempt to fully disable Defender (Realtime, Behavior,
                    IOAV, Script, Archive, Removable scanning), then stop
                    and disable the WinDefend service. Requires Administrator;
                    Tamper Protection may block some or all actions. No
                    enumeration is performed when this flag is used.
    -h, --help      Show this help and exit.

DEFAULT (no flags):
    Full enumeration: Defender status, signature age, exclusions, extended
    Get-MpPreference toggles (PUA, network protection, CFA, cloud block
    level, sample submission, Disable* flags, IP/ASR exclusions, signature
    update settings), ASR rules with actions, recent threats, registered AV
    products, service states, Exploit Protection config. Unavailable or
    inaccessible fields are reported as "N/A".
"""

PLUGIN_INFO = DEFENDER_USAGE

WARNING_TEXT = (
    "WARNING: The disable action requires Administrator privileges.\n"
    "If the current session is not elevated, attempts will fail with\n"
    "access denied. Tamper Protection may block some or all actions\n"
    "even when elevated. Results are reported per action below."
)

def _tokens(args):
    if args is None:
        return []
    if isinstance(args, str):
        return args.split()
    if isinstance(args, (list, tuple, set)):
        return list(args)
    return []


def _flag(args, *names):
    if args is None:
        return False
    for n in names:
        key = n.lstrip('-').replace('-', '_')
        if hasattr(args, key):
            try:
                if getattr(args, key):
                    return True
            except Exception:
                pass
    return any(t in _tokens(args) for t in names)


def _wants_help(args):
    return _flag(args, '--help', '-h')


def _wants_disable(args):
    return _flag(args, '--disable', '-d')

def build_disable_command(args=None):
    script = r"""
$ErrorActionPreference='SilentlyContinue'
$start='__START__'; $end='__END__'

function Convert-NullsToNa {
  param($o)
  if ($null -eq $o) { return 'N/A' }
  if ($o -is [System.Collections.IDictionary]) {
    $h = [ordered]@{}
    foreach ($k in @($o.Keys)) { $h[$k] = Convert-NullsToNa $o[$k] }
    return $h
  }
  if ($o -is [string]) { return $o }
  if ($o -is [System.Collections.IEnumerable]) {
    $a = @()
    foreach ($i in $o) { $a += ,(Convert-NullsToNa $i) }
    return $a
  }
  return $o
}

function Word($b) {
  if ($null -eq $b) { return 'N/A' }
  if ($b -eq $true)  { return 'ENABLED' }
  if ($b -eq $false) { return 'DISABLED' }
  return 'N/A'
}

function Shorten-Err($msg) {
  if (-not $msg) { return '' }
  $m = $msg
  $m = $m -replace "^Service 'Microsoft Defender Antivirus Service \(WinDefend\)' cannot be stopped due to the following error:\s*", ''
  $m = $m -replace "^Service 'Microsoft Defender Antivirus Service \(WinDefend\)' cannot be configured due to the following error:\s*", ''
  $m = $m -replace "\s+", ' '
  $m = $m.Trim().TrimEnd('.')
  if ($m.Length -gt 100) { $m = $m.Substring(0,97) + '...' }
  return $m
}

$is_admin = $false
try {
  $is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

$tamper = $null
try { $tamper = (Get-MpComputerStatus -EA 0).IsTamperProtected } catch {}

$ok_list  = @()
$bad_list = @()

$prefs = @(
  @{ Key='DisableRealtimeMonitoring';     Human='Realtime protection' },
  @{ Key='DisableBehaviorMonitoring';     Human='Behavior monitoring' },
  @{ Key='DisableIOAVProtection';         Human='IOAV protection' },
  @{ Key='DisableScriptScanning';         Human='Script scanning' },
  @{ Key='DisableArchiveScanning';        Human='Archive scanning' },
  @{ Key='DisableRemovableDriveScanning'; Human='Removable drive scanning' }
)

$set_errors = @{}
foreach ($item in $prefs) {
  try {
    $splat = @{ ErrorAction = 'Stop' }
    $splat[$item.Key] = $true
    Set-MpPreference @splat
  } catch {
    $set_errors[$item.Key] = $_.Exception.Message
  }
}

$snap = $null
try { $snap = Get-MpPreference -EA Stop } catch {}

foreach ($item in $prefs) {
  $actual = $null
  if ($snap) { try { $actual = $snap.($item.Key) } catch {} }
  $err = $set_errors[$item.Key]

  if ($actual -eq $true) {
    $ok_list += "$($item.Human): disabled"
  }
  elseif ($actual -eq $false) {
    if ($err) { $bad_list += "$($item.Human): still ENABLED - $(Shorten-Err $err)" }
    else      { $bad_list += "$($item.Human): still ENABLED (silently blocked)" }
  }
  else {
    if ($err) { $bad_list += "$($item.Human): unknown - $(Shorten-Err $err)" }
    else      { $bad_list += "$($item.Human): unknown state" }
  }
}

$svc_err = $null
try { Stop-Service WinDefend -Force -EA Stop } catch { $svc_err = $_.Exception.Message }
$svc = Get-Service WinDefend -EA 0
if ($svc -and $svc.Status -eq 'Stopped') {
  $ok_list += 'WinDefend service: stopped'
} else {
  $cur = if ($svc) { $svc.Status.ToString() } else { 'N/A' }
  if ($svc_err) { $bad_list += "WinDefend service: still $cur - $(Shorten-Err $svc_err)" }
  else          { $bad_list += "WinDefend service: still $cur" }
}

$start_err = $null
try { Set-Service WinDefend -StartupType Disabled -EA Stop } catch { $start_err = $_.Exception.Message }
$svc2 = Get-Service WinDefend -EA 0
if ($svc2 -and $svc2.StartType.ToString() -eq 'Disabled') {
  $ok_list += 'WinDefend startup: disabled'
} else {
  $cur = if ($svc2) { $svc2.StartType.ToString() } else { 'N/A' }
  if ($start_err) { $bad_list += "WinDefend startup: still $cur - $(Shorten-Err $start_err)" }
  else            { $bad_list += "WinDefend startup: still $cur" }
}

$realtime = $null; $behavior = $null; $ioav = $null; $on_access = $null; $running = 'N/A'
try {
  $s = Get-MpComputerStatus -EA 0
  $realtime  = $s.RealTimeProtectionEnabled
  $behavior  = $s.BehaviorMonitorEnabled
  $ioav      = $s.IoavProtectionEnabled
  $on_access = $s.OnAccessProtectionEnabled
  $running   = $s.AMRunningMode
} catch {}

$svc_status = 'N/A'; $svc_start = 'N/A'
$svc = Get-Service WinDefend -EA 0
if ($svc) {
  $svc_status = $svc.Status.ToString()
  $svc_start  = $svc.StartType.ToString()
}

if ($realtime -eq $false)     { $status_word = 'DISABLED' }
elseif ($realtime -eq $true)  { $status_word = 'ENABLED' }
else                          { $status_word = 'UNKNOWN' }

if ($status_word -eq 'DISABLED' -and $bad_list.Count -eq 0) {
  $reason = 'Defender is fully disabled.'
}
elseif ($status_word -eq 'DISABLED' -and $bad_list.Count -gt 0) {
  $reason = "Defender protections are disabled, but $($bad_list.Count) action(s) did not complete (see Blocked)."
}
elseif ($status_word -eq 'ENABLED' -and -not $is_admin) {
  $reason = 'Not an administrator: disable attempts were rejected with access denied. Defender is still enabled.'
}
elseif ($status_word -eq 'ENABLED' -and $tamper -eq $true) {
  $reason = 'Tamper Protection is enabled and blocked the disable attempts. Defender is still enabled.'
}
elseif ($status_word -eq 'ENABLED' -and $bad_list.Count -gt 0) {
  $reason = "Disable attempts did not fully succeed ($($bad_list.Count) issue(s)). Defender is still enabled."
}
elseif ($status_word -eq 'ENABLED') {
  $reason = 'Defender is still enabled.'
}
else {
  $reason = 'Could not determine Defender status.'
}

$result = [ordered]@{
  disable = @{
    status    = $status_word
    reason    = $reason
    is_admin  = $is_admin
    tamper    = (Word $tamper)
    attempted = 'YES'
    succeeded = $ok_list.Count
    failed    = $bad_list.Count
  }
  changes = @{
    applied = $ok_list
    blocked = $bad_list
  }
  service = @{
    name         = 'WinDefend'
    status       = $svc_status
    startup_type = $svc_start
    running_mode = $running
  }
  protections = @{
    realtime  = (Word $realtime)
    behavior  = (Word $behavior)
    ioav      = (Word $ioav)
    on_access = (Word $on_access)
    tamper    = (Word $tamper)
  }
}
$result = Convert-NullsToNa $result
Write-Output ($start + (ConvertTo-Json $result -Depth 6 -Compress) + $end)
"""
    script = (
        script
        .replace("__START__", PLUGIN_MARK_START)
        .replace("__END__", PLUGIN_MARK_END)
    )
    return script

def build_command(args=None):
    script = r"""
$ErrorActionPreference='SilentlyContinue'
$start='__START__'; $end='__END__'

function Convert-NullsToNa {
  param($o)
  if ($null -eq $o) { return 'N/A' }
  if ($o -is [System.Collections.IDictionary]) {
    $h = [ordered]@{}
    foreach ($k in @($o.Keys)) { $h[$k] = Convert-NullsToNa $o[$k] }
    return $h
  }
  if ($o -is [string]) { return $o }
  if ($o -is [System.Collections.IEnumerable]) {
    $a = @()
    foreach ($i in $o) { $a += ,(Convert-NullsToNa $i) }
    return $a
  }
  return $o
}

$def = @{}; $products = $null; $asr = $null; $threats = $null

try {
  $pref   = Get-MpPreference -EA 0
  $status = Get-MpComputerStatus -EA 0
  $def = @{
    realtime = $status.RealTimeProtectionEnabled
    tamper   = $status.IsTamperProtected
    engine   = $status.AMEngineVersion
    defs     = $status.AntivirusSignatureVersion
    last     = $status.AntivirusSignatureLastUpdated
    cloud    = $pref.MAPSReporting
    exclusions = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension)
  }
  $def.running_mode   = $status.AMRunningMode
  $def.quick_scan_age = $status.QuickScanAge
  $def.full_scan_age  = $status.FullScanAge
  $def.sig_age_days   = $status.AntivirusSignatureAge
  $def.pua                 = $pref.PUAProtection
  $def.network_prot        = $pref.EnableNetworkProtection
  $def.cfa                 = $pref.EnableControlledFolderAccess
  $def.cfa_folders         = @($pref.ControlledFolderAccessProtectedFolders)
  $def.cfa_allowed         = @($pref.ControlledFolderAccessAllowedApplications)
  $def.cloud_block_lvl     = $pref.CloudBlockLevel
  $def.cloud_timeout       = $pref.CloudExtendedTimeout
  $def.submit_samples      = $pref.SubmitSamplesConsent
  $def.disable_removable   = $pref.DisableRemovableDriveScanning
  $def.disable_archive     = $pref.DisableArchiveScanning
  $def.disable_net_scan    = $pref.DisableScanningNetworkFiles
  $def.disable_script      = $pref.DisableScriptScanning
  $def.disable_behavior    = $pref.DisableBehaviorMonitoring
  $def.disable_ioav        = $pref.DisableIOAVProtection
  $def.exclusions_ip       = @($pref.ExclusionIpAddress)
  $def.exclusions_asr      = @($pref.AttackSurfaceReductionOnlyExclusions)
  $def.sig_fallback        = $pref.SignatureUpdateFallbackOrder
  $def.sig_update_interval = $pref.SignatureUpdateInterval
} catch {}

try {
  $ids  = @($pref.AttackSurfaceReductionRules_Ids)
  $acts = @($pref.AttackSurfaceReductionRules_Actions)
  $tmp = @()
  for ($i = 0; $i -lt $ids.Count; $i++) {
    $act = if ($i -lt $acts.Count) { $acts[$i] } else { $null }
    $tmp += @{ id = $ids[$i]; action = $act }
  }
  $asr = $tmp
} catch { $asr = $null }

try {
  $tmp = @()
  Get-MpThreatDetection -EA 0 | Select-Object -First 15 | ForEach-Object {
    $tmp += @{ threat = $_.ThreatID; time = $_.InitialDetectionTime; resources = @($_.Resources) }
  }
  $threats = $tmp
} catch { $threats = $null }

try {
  $tmp = @()
  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA Stop | ForEach-Object {
    $tmp += @{ name = $_.displayName; path = $_.pathToSignedProductExe; state = $_.productState }
  }
  $products = $tmp
} catch { $products = $null }

$svcs = [ordered]@{}
foreach ($n in 'WinDefend','WdNisSvc','Sense','SecurityHealthService','MsMpSvc') {
  $s = Get-Service $n -EA 0
  if ($s) { $svcs[$n] = $s.Status.ToString() } else { $svcs[$n] = 'N/A' }
}

$exploit = 'N/A'
try {
  $r = Get-ProcessMitigation -System -EA Stop
  if ($r) { $exploit = ($r | Out-String).Trim() }
} catch {}

$sc = if ($null -eq $products) { 'N/A' } else { $products.Count }
$sa = if ($null -eq $asr)      { 'N/A' } else { $asr.Count }

$result = [ordered]@{
  summary = @{
    defender_loaded   = ($def.Count -gt 0)
    security_products = $sc
    asr_rules         = $sa
  }
  defender           = $def
  security_products  = $products
  asr_rules          = $asr
  threats            = $threats
  services           = $svcs
  exploit_mitigation = $exploit
}

$result = Convert-NullsToNa $result
Write-Output ($start + (ConvertTo-Json $result -Depth 8 -Compress) + $end)
"""
    script = (
        script
        .replace("__START__", PLUGIN_MARK_START)
        .replace("__END__", PLUGIN_MARK_END)
    )
    return script


@plugin.command(
    name='defender',
    platforms=['windows'],
    description=(
        'Enumerate Defender status, exclusions, ASR rules, and security products. '
        'Use -d/--disable to attempt a full disable (admin required; '
        'enumeration is skipped in that mode). Use -h/--help for usage.'
    ),
)
def run(session: SessionContext, args):
    if _wants_help(args):
        return DEFENDER_USAGE

    if _wants_disable(args):
        print(WARNING_TEXT)
        return run_collector_plugin(
            session, 'defender', args, build_disable_command,
            format_generic_report, timeout=60.0,
        )

    return run_collector_plugin(
        session, 'defender', args, build_command,
        format_generic_report, timeout=60.0,
    )