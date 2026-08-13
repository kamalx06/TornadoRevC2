"""Windows Remote Management (WinRM) configuration enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
$config=@{}; $listeners=@(); $auth=@{}; $firewall=@(); $service=@{}; $client=@{}

# WinRM service
try{
  $svc=Get-Service WinRM -EA 0
  if($svc){$service=@{name=$svc.Name;status=$svc.Status;start=$svc.StartType}}
}catch{}

# winrm config (native)
try{
  $winrmOut=winrm get winrm/config 2>$null
  if($winrmOut){$config['winrm_config']=@($winrmOut|Select-Object -First 40)}
}catch{}

# Listeners via WSMan provider
try{
  Get-ChildItem WSMan:\localhost\Listener -EA 0|ForEach-Object{
    $props=Get-ChildItem $_.PSPath -EA 0
    $entry=@{address=$_.PSChildName}
    foreach($p in $props){$entry[$p.PSChildName]=$p.Value}
    $listeners+=@($entry)
  }
}catch{}

# Service config via CIM
try{
  Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -EA 0|ForEach-Object{
    $service['path']=$_.PathName
    $service['account']=$_.StartName
    $service['state']=$_.State
  }
}catch{}

# Authentication settings
try{
  $svcAuth=Get-Item WSMan:\localhost\Service\Auth -EA 0
  if($svcAuth){
    Get-ChildItem WSMan:\localhost\Service\Auth -EA 0|ForEach-Object{
      $auth[$_.Name]=$_.Value
    }
  }
  $clientAuth=Get-Item WSMan:\localhost\Client\Auth -EA 0
  if($clientAuth){
    Get-ChildItem WSMan:\localhost\Client\Auth -EA 0|ForEach-Object{
      $auth['client_'+$_.Name]=$_.Value
    }
  }
}catch{}

# Client trusted hosts
try{
  $client['trusted_hosts']=(Get-Item WSMan:\localhost\Client\TrustedHosts -EA 0).Value
  $client['allow_unencrypted']=(Get-Item WSMan:\localhost\Client\AllowUnencrypted -EA 0).Value
}catch{}

# Firewall rules for WinRM
try{
  Get-NetFirewallRule -EA 0|Where-Object{
    $_.DisplayName -match 'Windows Remote Management|WinRM'
  }|Select-Object -First 15|ForEach-Object{
    $fw=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -EA 0
    $firewall+=@{
      name=$_.DisplayName
      enabled=$_.Enabled
      direction=$_.Direction
      action=$_.Action
      profile=$_.Profile -join ','
      ports=($fw.LocalPort -join ',')
    }
  }
}catch{
  try{
    $fwOut=netsh advfirewall firewall show rule name="Windows Remote Management (HTTP-In)" 2>$null
    if($fwOut){$firewall+=@{netsh_http=$fwOut|Select-Object -First 10}}
    $fwOut2=netsh advfirewall firewall show rule name="Windows Remote Management (HTTPS-In)" 2>$null
    if($fwOut2){$firewall+=@{netsh_https=$fwOut2|Select-Object -First 10}}
  }catch{}
}

# Remoting status
$remotingEnabled=$false
try{
  $remotingEnabled=(Get-PSSessionConfiguration -EA 0|Where-Object{$_.Enabled -eq $true}).Count -gt 0
}catch{}
try{
  if(-not $remotingEnabled){$remotingEnabled=((Get-Service WinRM -EA 0).Status -eq 'Running')}
}catch{}

# Quick connectivity self-test
$wsmanTest='N/A'
try{
  Test-WSMan -ComputerName localhost -EA 0|Out-Null
  $wsmanTest='localhost reachable'
}catch{
  $wsmanTest='localhost not reachable'
}

$result=[ordered]@{
  summary=@{
    winrm_service=($service.status)
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
  remoting_configurations=@(
    Get-PSSessionConfiguration -EA 0|Select-Object Name,Enabled,Permission,RunAsVirtualAccount|Select-Object -First 10
  )
}
$json=($result|ConvertTo-Json -Depth 6 -Compress)
"""
    return wrap_ps_collector(body)


@plugin.command(
    name='winrm',
    platforms=['windows'],
    description='Detect WinRM configuration, listeners, authentication, firewall, and remoting status',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'winrm', None, build_command, format_generic_report, timeout=35.0)
