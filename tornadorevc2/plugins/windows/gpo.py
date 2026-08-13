"""Windows Group Policy and security policy enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
$gpos=@(); $localPolicy=@{}; $applocker=@{}; $wdac=@{}; $srp=@{}; $scripts=@(); $inheritance=@()

# Applied GPO summary via gpresult
try{
  $gpOut=gpresult /Scope Computer /R 2>$null
  if($gpOut){
    $inheritance=@($gpOut|Where-Object{$_ -match 'Applied Group Policy|Group Policy was applied|Last time Group Policy|Domain Name|Site Name'}|ForEach-Object{$_.Trim()})
    $gpos=@($gpOut|Where-Object{$_ -match '^\s{4}\S' -and $_ -notmatch 'Applied Group Policy|Group Policy was applied'}|ForEach-Object{$_.Trim()}|Select-Object -First 30)
  }
}catch{}

# RSOP / WMI GPO objects
try{
  Get-CimInstance -Namespace root\CIMV2 -ClassName Win32_GroupPolicy -EA 0|ForEach-Object{
    $gpos+=@($_.Name,$_.Description)|Where-Object{$_}|Select-Object -First 1
  }
}catch{}

# Local security policy export
try{
  $secFile=Join-Path $env:TEMP ('secpol_'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.inf')
  secedit /export /cfg $secFile /quiet 2>$null
  if(Test-Path $secFile){
    $lines=Get-Content $secFile -EA 0|Select-Object -First 80
    $localPolicy=@{exported=$secFile;preview=@($lines|ForEach-Object{$_.Trim()}|Where-Object{$_})}
    Remove-Item $secFile -Force -EA 0
  }
}catch{}

# AppLocker
try{
  $alPolicy=Get-AppLockerPolicy -Local -EA 0
  if($alPolicy){
    $rules=@($alPolicy.RuleCollections|ForEach-Object{
      @($_.Rules|ForEach-Object{@{
        collection=$_.GetType().Name
        name=$_.Name
        action=$_.Action
        user=$_.UserOrGroupSid
      }})}|Select-Object -First 40)
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
  }
  $ciState=Get-CimInstance -ClassName Win32_DeviceGuard -EA 0
  if($ciState){
    $wdac['code_integrity_policy_enforcement_status']=$ciState.CodeIntegrityPolicyEnforcementStatus
    $wdac['user_mode_code_integrity_status']=$ciState.UserModeCodeIntegrityPolicyEnforcementStatus
  }
  $cipol=Get-ChildItem 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active\' -EA 0|Select-Object Name,Length,LastWriteTime
  if($cipol){$wdac['active_policies']=@($cipol|ForEach-Object{"$($_.Name) ($($_.Length) bytes)"})}
}catch{
  if(-not $wdac.Count){$wdac=@{status='N/A'}}
}

# Software Restriction Policies (SRP)
try{
  $srpKey='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
  if(Test-Path $srpKey){
    $srpProps=Get-ItemProperty $srpKey -EA 0
    $srp=@{enabled=$true;default_level=$srpProps.DefaultLevel;authenticode_enabled=$srpProps.AuthenticodeEnabled}
    $rules=@()
    Get-ChildItem $srpKey -Recurse -EA 0|Where-Object{$_.PSChildName -match '^\{'}|ForEach-Object{
      $p=Get-ItemProperty $_.PSPath -EA 0
      $rules+=@{id=$_.PSChildName;item_data=$p.ItemData;description=$p.Description;safer_flags=$p.SaferFlags}
    }
    $srp['rules']=@($rules|Select-Object -First 30)
  }else{$srp=@{enabled=$false}}
}catch{
  $srp=@{status='N/A'}
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

# Domain GPO links (if domain-joined)
try{
  Import-Module GroupPolicy -EA 0
  $dom=(Get-CimInstance Win32_ComputerSystem -EA 0).Domain
  if($dom -and $dom -ne 'WORKGROUP'){
    Get-GPO -All -EA 0|Select-Object -First 25|ForEach-Object{
      $gpos+=@{'GPO: '+$_.DisplayName+' (id='+$_.Id+')'}
    }
  }
}catch{}

$result=[ordered]@{
  summary=@{
    applied_gpos=$gpos.Count
    applocker_rules=($applocker.rule_count)
    srp_rules=($srp.rules.Count)
    startup_logon_scripts=$scripts.Count
  }
  applied_gpos=@($gpos|Select-Object -Unique -First 30)
  gpo_inheritance=@($inheritance|Select-Object -First 15)
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
    return run_collector_plugin(session, 'gpo', None, build_command, format_generic_report, timeout=45.0)
