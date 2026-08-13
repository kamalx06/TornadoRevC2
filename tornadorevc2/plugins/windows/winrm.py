"""Windows Remote Management (WinRM) configuration enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
$ConfirmPreference='None'
$ProgressPreference='SilentlyContinue'

function Invoke-Timed([scriptblock]$Block,[int]$Sec=10,[object[]]$ArgList=@()){
  $job=Start-Job -ScriptBlock $Block -ArgumentList $ArgList
  $done=Wait-Job $job -Timeout $Sec
  if($done){$out=Receive-Job $job;Remove-Job $job -Force -EA 0;return $out}
  Stop-Job $job -EA 0;Remove-Job $job -Force -EA 0;return $null
}

function Test-TcpPort([string]$HostName,[int]$Port,[int]$Ms=1500){
  $client=$null
  try{
    $client=New-Object Net.Sockets.TcpClient
    $iar=$client.BeginConnect($HostName,$Port,$null,$null)
    if(-not $iar.AsyncWaitHandle.WaitOne($Ms,$false)){return $false}
    $client.EndConnect($iar)|Out-Null
    return $true
  }catch{return $false}
  finally{if($client){try{$client.Close()}catch{}}}
}

$service=@{}
$svc=$null
try{ $svc=Get-Service WinRM -EA 0 }catch{}
if($svc){
  $service=@{name=$svc.Name;status=[string]$svc.Status;start=[string]$svc.StartType}
}else{
  $service=@{name='WinRM';status='NotInstalled';start='N/A'}
}

try{
  Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -EA 0|
    Select-Object -First 1|ForEach-Object{
      $service['path']=[string]$_.PathName
      $service['account']=[string]$_.StartName
      $service['state']=[string]$_.State
    }
}catch{}

$winrmRunning=($svc -and $svc.Status -eq 'Running')

if(-not $winrmRunning){
  $statusText=[string]$service.status
  $result=[ordered]@{
    summary=@{
      winrm_enabled=$false
      winrm_service=$statusText
      listeners=0
      remoting_enabled=$false
      firewall_rules=0
      message='WinRM service is not running; extended enumeration skipped (read-only check only)'
    }
    service=$service
    note='Start the WinRM service locally to collect listeners, authentication, and remoting settings.'
  }
  $json=($result|ConvertTo-Json -Depth 5 -Compress)
}else{
  $config=@{}; $listeners=@(); $auth=@{}; $firewall=@(); $client=@{}
  $remoting=@(); $remotingEnabled=$false; $wsmanTest='N/A'

  try{
    $winrmOut=Invoke-Timed { winrm get winrm/config 2>$null } 8
    if($winrmOut){
      $config['winrm_config']=@($winrmOut|Select-Object -First 40|ForEach-Object{[string]$_})
    }
  }catch{}

  try{
    Get-ChildItem WSMan:\localhost\Listener -EA 0|ForEach-Object{
      $entry=@{address=$_.PSChildName}
      Get-ChildItem $_.PSPath -EA 0|ForEach-Object{ $entry[$_.PSChildName]=[string]$_.Value }
      $listeners+=@($entry)
    }
  }catch{}

  try{
    Get-ChildItem WSMan:\localhost\Service\Auth -EA 0|ForEach-Object{
      $auth[$_.Name]=[string]$_.Value
    }
    Get-ChildItem WSMan:\localhost\Client\Auth -EA 0|ForEach-Object{
      $auth['client_'+$_.Name]=[string]$_.Value
    }
  }catch{}

  try{
    $client['trusted_hosts']=[string](Get-Item WSMan:\localhost\Client\TrustedHosts -EA 0).Value
    $client['allow_unencrypted']=[string](Get-Item WSMan:\localhost\Client\AllowUnencrypted -EA 0).Value
  }catch{}

  try{
    foreach($ruleName in @(
      'Windows Remote Management (HTTP-In)',
      'Windows Remote Management (HTTPS-In)'
    )){
      $fwOut=netsh advfirewall firewall show rule name="$ruleName" 2>$null
      if($fwOut){
        $firewall+=@{
          name=$ruleName
          source='netsh'
          preview=@($fwOut|Select-Object -First 12|ForEach-Object{[string]$_})
        }
      }
    }
  }catch{}
  if($firewall.Count -lt 2){
    try{
      $fwRules=Invoke-Timed {
        Get-NetFirewallRule -EA 0|
          Where-Object{ $_.DisplayName -like '*Windows Remote Management*' -or $_.DisplayName -like '*WinRM*' }|
          Select-Object -First 12 DisplayName,Enabled,Direction,Action,Profile
      } 12
      if($fwRules){
        foreach($rule in $fwRules){
          $ports=''
          try{
            $pf=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -EA 0
            if($pf){$ports=($pf.LocalPort -join ',')}
          }catch{}
          $firewall+=@{
            name=[string]$rule.DisplayName
            enabled=[string]$rule.Enabled
            direction=[string]$rule.Direction
            action=[string]$rule.Action
            profile=([string]$rule.Profile -join ',')
            ports=$ports
            source='Get-NetFirewallRule'
          }
        }
      }
    }catch{}
  }

  try{
    $sessCfg=Invoke-Timed {
      Get-PSSessionConfiguration -EA 0|Select-Object -First 10 Name,Enabled,RunAsVirtualAccount
    } 10
    if($sessCfg){
      foreach($cfg in $sessCfg){
        $remoting+=@{
          name=[string]$cfg.Name
          enabled=[string]$cfg.Enabled
          run_as_virtual_account=[string]$cfg.RunAsVirtualAccount
        }
      }
      $remotingEnabled=($remoting|Where-Object{ $_.enabled -eq 'True' }).Count -gt 0
    }
  }catch{}
  if(-not $remotingEnabled){ $remotingEnabled=$true }

  try{
    $open=@()
    if(Test-TcpPort '127.0.0.1' 5985){$open+='5985'}
    if(Test-TcpPort '127.0.0.1' 5986){$open+='5986'}
    if($open.Count -gt 0){
      $wsmanTest='local ports open: '+($open -join ',')
    }elseif($listeners.Count -gt 0){
      $wsmanTest="$($listeners.Count) listener(s) configured"
    }else{
      $wsmanTest='service running; no listeners or open ports detected'
    }
  }catch{
    $wsmanTest='N/A'
  }

  $result=[ordered]@{
    summary=@{
      winrm_enabled=$true
      winrm_service='Running'
      listeners=$listeners.Count
      remoting_enabled=$remotingEnabled
      firewall_rules=$firewall.Count
      wsman_test=$wsmanTest
    }
    service=$service
    winrm_config=$config
    listeners=$listeners
    authentication=$auth
    client_settings=$client
    firewall_rules=@($firewall|Select-Object -First 15)
    remoting_configurations=$remoting
  }
  $json=($result|ConvertTo-Json -Depth 5 -Compress)
}
"""
    return wrap_ps_collector(body)


@plugin.command(
    name='winrm',
    platforms=['windows'],
    description='Read-only WinRM enumeration; skips WSMan probes when the WinRM service is not running',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'winrm', None, build_command, format_generic_report, timeout=55.0)
