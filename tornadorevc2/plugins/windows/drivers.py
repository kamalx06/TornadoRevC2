"""Windows driver and kernel module enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
$drivers=@(); $notable=@(); $kernel=@()

# PnP signed drivers via CIM
try{
  Get-CimInstance Win32_PnPSignedDriver -EA 0|ForEach-Object{
    $drivers+=@{
      device=$_.DeviceName
      driver=$_.DriverVersion
      manufacturer=$_.Manufacturer
      signed=($_.IsSigned -eq $true)
      signer=($_.Signer)
      date=$_.DriverDate
      inf=$_.InfName
    }
  }
}catch{}

# driverquery fallback
try{
  if($drivers.Count -eq 0){
    driverquery /v /fo csv 2>$null|Select-Object -Skip 1|ForEach-Object{
      $fields=$_.Split(',')|ForEach-Object{$_ -replace '"',''}
      if($fields.Count -ge 5){
        $drivers+=@{
          module=$fields[0]
          display=$fields[1]
          description=$fields[2]
          driver_type=$fields[3]
          start_mode=$fields[4]
        }
      }
    }
  }
}catch{}

# Kernel / boot-start drivers via registry services
try{
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA 0|ForEach-Object{
    try{
      $p=Get-ItemProperty $_.PSPath -EA 0
      if($p.Start -eq 0 -or $p.Type -eq 1){
        $kernel+=@{
          name=$_.PSChildName
          start=$p.Start
          type=$p.Type
          image=$p.ImagePath
          group=$p.Group
        }
      }
    }catch{}
  }
}catch{}

# Notable security / virtualization drivers
$patterns=@(
  'vmware','vbox','virtualbox','xen','hyperv','hv_','vmci','vmusb','vmrawdsk',
  'crowdstrike','sentinel','carbon','cylance','sysmon','procmon','wireshark',
  'npcap','winpcap','wdfilter','wdboot','cb','csagent','elastic','falcon',
  'klif','asw','avg','avast','bdagent','edr','minifilter','fs_rec'
)
foreach($d in $drivers){
  $blob=($d.device,$d.driver,$d.manufacturer,$d.module,$d.display,$d.description -join ' ').ToLower()
  foreach($pat in $patterns){
    if($blob -match [regex]::Escape($pat)){
      $notable+=@{
        match=$pat
        device=($d.device -or $d.module)
        signed=($d.signed)
        start=($d.start_mode)
      }
      break
    }
  }
}
foreach($k in $kernel){
  $blob=($k.name,$k.image -join ' ').ToLower()
  foreach($pat in $patterns){
    if($blob -match [regex]::Escape($pat)){
      $notable+=@{match=$pat;device=$k.name;signed='N/A';start=$k.start}
      break
    }
  }
}

$result=[ordered]@{
  summary=@{
    total_drivers=$drivers.Count
    kernel_boot_drivers=$kernel.Count
    notable=$notable.Count
    unsigned=(@($drivers|Where-Object{$_.signed -eq $false}).Count)
  }
  drivers=@($drivers|Select-Object -First 80)
  kernel_boot_drivers=@($kernel|Select-Object -First 60)
  notable=@($notable|Select-Object -Unique -First 40)
}
$json=($result|ConvertTo-Json -Depth 6 -Compress)
"""
    return wrap_ps_collector(body)


@plugin.command(
    name='drivers',
    platforms=['windows'],
    description='Enumerate installed drivers, signed status, startup type, and notable security/VM drivers',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'drivers', None, build_command, format_generic_report, timeout=40.0)
