"""Windows Group Policy and security policy enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
function Invoke-Timed([scriptblock]$Block,[int]$Sec=12,[object[]]$ArgList=@()){
  $job=Start-Job -ScriptBlock $Block -ArgumentList $ArgList
  $done=Wait-Job $job -Timeout $Sec
  if($done){$out=Receive-Job $job;Remove-Job $job -Force -EA 0;return $out}
  Stop-Job $job -EA 0;Remove-Job $job -Force -EA 0;return $null
}

$gpos=@(); $localPolicy=@{}; $applocker=@{}; $wdac=@{}; $srp=@{}; $scripts=@(); $inheritance=@()

# Applied GPOs from registry (fast)
try{
  $hist='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
  if(Test-Path $hist){
    Get-ChildItem $hist -EA 0|ForEach-Object{
      $p=Get-ItemProperty $_.PSPath -EA 0
      $name=$p.DisplayName
      if($name){$gpos+=@{name=$name;id=$_.PSChildName;version=$p.Version;extensions=$p.Extensions}}
    }
  }
  $state='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List'
  if(Test-Path $state){
    Get-ChildItem $state -EA 0|ForEach-Object{
      $p=Get-ItemProperty $_.PSPath -EA 0
      $inheritance+=@{id=$_.PSChildName;name=$p.DisplayName;enabled=$p.Enabled;version=$p.Version}
    }
  }
}catch{}

# gpresult summary (timed fallback)
try{
  $gpOut=Invoke-Timed { gpresult /Scope Computer /R 2>$null } 15
  if($gpOut){
    $lines=@($gpOut|Where-Object{$_ -match 'Applied Group Policy|Group Policy was applied|Last time Group Policy|Domain Name|Site Name|OS Configuration'}|ForEach-Object{$_.Trim()})
    foreach($ln in $lines){if($inheritance -notcontains $ln){$inheritance+=@{line=$ln}}}
  }
}catch{}

# Local security policy export (timed)
try{
  $secFile=Join-Path $env:TEMP ('secpol_'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.inf')
  $exported=Invoke-Timed { param($f) secedit /export /cfg $f /quiet 2>$null; Test-Path $f } 12 @($secFile)
  if($exported -and (Test-Path $secFile)){
    $lines=Get-Content $secFile -EA 0|Select-Object -First 80
    $localPolicy=@{preview=@($lines|ForEach-Object{$_.Trim()}|Where-Object{$_})}
    Remove-Item $secFile -Force -EA 0
  }
}catch{}

# AppLocker
try{
  $alPolicy=Get-AppLockerPolicy -Local -EA 0
  if($alPolicy){
    $rules=@()
    foreach($rc in $alPolicy.RuleCollections){
      foreach($rule in $rc.Rules){
        $rules+=@{collection=$rc.GetType().Name;name=$rule.Name;action=$rule.Action;user=$rule.UserOrGroupSid}
        if($rules.Count -ge 40){break}
      }
      if($rules.Count -ge 40){break}
    }
    $applocker=@{enabled=$true;rule_count=$rules.Count;rules=$rules}
  }else{$applocker=@{enabled=$false}}
}catch{
  $applocker=@{enabled='N/A';error=$_.Exception.Message}
}

# WDAC / Code Integrity policy
try{
  $ciPath='HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
  if(Test-Path $ciPath){
    $ciProps=Get-ItemProperty $ciPath -EA 0
    $wdac=@{registry_present=$true;policy_info=$ciProps.PolicyInfo;upgraded=$ciProps.Upgraded}
  }else{$wdac=@{registry_present=$false}}
  $ciState=Get-CimInstance -ClassName Win32_DeviceGuard -EA 0
  if($ciState){
    $wdac['code_integrity_policy_enforcement_status']=$ciState.CodeIntegrityPolicyEnforcementStatus
    $wdac['user_mode_code_integrity_status']=$ciState.UserModeCodeIntegrityPolicyEnforcementStatus
  }
  $cipol=Get-ChildItem 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active\' -EA 0|Select-Object Name,Length,LastWriteTime
  if($cipol){$wdac['active_policies']=@($cipol|ForEach-Object{"$($_.Name) ($($_.Length) bytes)"})}
}catch{
  if(-not $wdac -or $wdac.Count -eq 0){$wdac=@{status='N/A'}}
}

# Software Restriction Policies (SRP)
try{
  $srpKey='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
  if(Test-Path $srpKey){
    $srpProps=Get-ItemProperty $srpKey -EA 0
    $srp=@{enabled=$true;default_level=$srpProps.DefaultLevel;authenticode_enabled=$srpProps.AuthenticodeEnabled;rules=@()}
    Get-ChildItem $srpKey -EA 0|Where-Object{$_.PSChildName -match '^\{'}|Select-Object -First 30|ForEach-Object{
      $p=Get-ItemProperty $_.PSPath -EA 0
      $srp.rules+=@{id=$_.PSChildName;item_data=$p.ItemData;description=$p.Description;safer_flags=$p.SaferFlags}
    }
  }else{$srp=@{enabled=$false;rules=@()}}
}catch{
  $srp=@{status='N/A';rules=@()}
}

# Startup / logon scripts
try{
  $scriptRoots=@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff'
  )
  foreach($root in $scriptRoots){
    if(Test-Path $root){
      Get-ChildItem $root -EA 0|ForEach-Object{
        $p=Get-ItemProperty $_.PSPath -EA 0
        $scripts+=@{type=($root -replace '.*\\','');name=$_.PSChildName;script=$p.Script;parameters=$p.Parameters;is_ps=$p.IsPowershell}
      }
    }
  }
}catch{}

# Domain GPO links (timed, if domain-joined)
try{
  $dom=(Get-CimInstance Win32_ComputerSystem -EA 0).Domain
  if($dom -and $dom -ne 'WORKGROUP'){
    $fromGpo=Invoke-Timed {
      Import-Module GroupPolicy -EA 0
      Get-GPO -All -EA 0|Select-Object -First 25 DisplayName,Id,GpoStatus,CreationTime,ModificationTime
    } 20
    if($fromGpo){
      foreach($g in $fromGpo){
        $gpos+=@{name=$g.DisplayName;id=$g.Id;status=$g.GpoStatus;source='Get-GPO'}
      }
    }
  }
}catch{}

$srpRuleCount=0
if($srp.rules){$srpRuleCount=@($srp.rules).Count}

$result=[ordered]@{
  summary=@{
    applied_gpos=$gpos.Count
    applocker_rules=($applocker.rule_count)
    srp_rules=$srpRuleCount
    startup_logon_scripts=$scripts.Count
  }
  applied_gpos=@($gpos|Select-Object -First 30)
  gpo_inheritance=@($inheritance|Select-Object -First 20)
  local_security_policy=$localPolicy
  applocker=$applocker
  wdac=$wdac
  software_restriction_policies=$srp
  startup_logon_scripts=@($scripts|Select-Object -First 30)
}
$json=($result|ConvertTo-Json -Depth 6 -Compress)
"""
    return wrap_ps_collector(body)


@plugin.command(
    name='gpo',
    platforms=['windows'],
    description='Enumerate applied GPOs, security policies, AppLocker, WDAC, SRP, and GPO scripts',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'gpo', None, build_command, format_generic_report, timeout=60.0)
