"""Aggressive Windows virtualization and container detection collector."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'
$end='{PLUGIN_MARK_END}'
function Hit($det,$name,$text,$w=15){{
  if(-not $det.ContainsKey($name)){{$det[$name]=@{{detected=$false;confidence=0;indicators=@()}}}}
  $e=$det[$name]
  if($text -and ($e.indicators -notcontains $text)){{$e.indicators+=$text;$e.detected=$true;$e.confidence=[Math]::Min(100,$e.confidence+$w)}}
}}
function CloudProbe($url,$hdr){{
  try{{$r=Invoke-WebRequest -Uri $url -Headers $hdr -TimeoutSec 2 -UseBasicParsing; return $r.Content.Substring(0,[Math]::Min(200,$r.Content.Length))}}catch{{return ''}}
}}
$det=@{{}}; $indicators=@(); $sockets=@(); $artifacts=@(); $cloud=@{{}}

# Docker / containerd / K8s
Hit $det 'docker' (Test-Path 'HKLM:\\SOFTWARE\\Docker Inc.\\Docker') 'Docker Desktop registry' 20
if(Test-Path '\\\\.\\pipe\\docker_engine'){{Hit $det 'docker' 'docker_engine pipe present' 20;$sockets+='\\\\.\\pipe\\docker_engine'}}
if($env:DOCKER_HOST){{Hit $det 'docker' ('DOCKER_HOST='+$env:DOCKER_HOST) 15}}
Get-Service -Name 'com.docker.service','docker','containerd' -EA 0|ForEach-Object{{Hit $det 'docker' ('service: '+$_.Name) 15}}
if($env:KUBERNETES_SERVICE_HOST){{Hit $det 'kubernetes' ('K8S service host='+$env:KUBERNETES_SERVICE_HOST) 25}}
Get-Service -Name 'kubelet','kube-proxy' -EA 0|ForEach-Object{{Hit $det 'kubernetes' ('service: '+$_.Name) 15}}
if(Test-Path 'C:\\ProgramData\\Docker'){{Hit $det 'docker' 'C:\\ProgramData\\Docker' 10;$artifacts+='C:\\ProgramData\\Docker'}}

# WSL
if($env:WSL_DISTRO_NAME){{Hit $det 'wsl' ('WSL_DISTRO_NAME='+$env:WSL_DISTRO_NAME) 25}}
if(Get-Command wsl.exe -EA 0){{Hit $det 'wsl' 'wsl.exe present' 10}}

# Hyper-V / VM detection via CIM
$cs=Get-CimInstance Win32_ComputerSystem -EA 0
$bios=Get-CimInstance Win32_BIOS -EA 0
if($cs.Manufacturer -match 'Microsoft' -and $cs.Model -match 'Virtual'){{Hit $det 'hyperv' ('Manufacturer/Model: '+$cs.Manufacturer+' / '+$cs.Model) 25}}
if($cs.Manufacturer -match 'VMware'){{Hit $det 'vmware' ('Manufacturer: '+$cs.Manufacturer) 20}}
if($cs.Manufacturer -match 'innotek|Oracle|VirtualBox'){{Hit $det 'virtualbox' ('Manufacturer: '+$cs.Manufacturer) 20}}
if($cs.Manufacturer -match 'Xen'){{Hit $det 'xen' ('Manufacturer: '+$cs.Manufacturer) 20}}
if($bios.SMBIOSBIOSVersion -match 'QEMU|Bochs|SeaBIOS'){{Hit $det 'qemu' ('BIOS: '+$bios.SMBIOSBIOSVersion) 20}}
Get-CimInstance Win32_SystemDriver -EA 0|?{{$_.Name -match 'vmw|vmx|vbox|xen|virtio|qemu|hv_'}}|ForEach-Object{{$n=$_.Name;if($n -match 'vmw'){{Hit $det 'vmware' ('driver: '+$n) 15}}elseif($n -match 'vbox'){{Hit $det 'virtualbox' ('driver: '+$n) 15}}elseif($n -match 'hv_'){{Hit $det 'hyperv' ('driver: '+$n) 15}}else{{Hit $det 'qemu' ('driver: '+$n) 10}}}}
try{{$hv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters' -EA 0;if($hv){{Hit $det 'hyperv' 'Hyper-V guest parameters registry' 20}}}}catch{{}}

# Windows containers
Get-Service -Name 'hns','vmcompute','vmms' -EA 0|ForEach-Object{{Hit $det 'windows_containers' ('service: '+$_.Name) 15}}
if(Test-Path 'C:\\ProgramData\\Docker\\windowsfilter'){{Hit $det 'windows_containers' 'windowsfilter directory' 15}}

# Cloud metadata
$aws=CloudProbe 'http://169.254.169.254/latest/meta-data/instance-id' @{{Metadata='true'}}
if($aws){{Hit $det 'cloud_aws' 'AWS metadata responded' 25;$cloud['aws']=$aws}}
$az=CloudProbe 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' @{{Metadata='true'}}
if($az){{Hit $det 'cloud_azure' 'Azure metadata responded' 25;$cloud['azure']=$az}}
$gcp=CloudProbe 'http://metadata.google.internal/computeMetadata/v1/instance/id' @{{'Metadata-Flavor'='Google'}}
if($gcp){{Hit $det 'cloud_gcp' 'GCP metadata responded' 25;$cloud['gcp']=$gcp}}

# CPUID hypervisor bit via WMI (best-effort)
try{{$proc=Get-CimInstance Win32_Processor -EA 0|Select-Object -First 1;if($proc -and $proc.Name -match 'Virtual'){{Hit $det 'hypervisor' 'Processor name indicates virtualization' 15}}}}catch{{}}

$inContainer = ($det['docker'].detected -or $env:CONTAINER -or $env:KUBERNETES_SERVICE_HOST -or $det['windows_containers'].detected)
$runtime=''; if($det['docker'].detected){{$runtime='Docker Desktop'}} elseif($det['windows_containers'].detected){{$runtime='Windows Containers'}}
$orchestrator = $(if($det['kubernetes'].detected){{'Kubernetes'}}else{{''}})
$virt=''; foreach($p in @(@('vmware','VMware'),@('virtualbox','VirtualBox'),@('hyperv','Hyper-V'),@('qemu','QEMU'),@('xen','Xen'))){{if($det[$p[0]].detected){{$virt=$p[1];break}}}}
$cloudp=''; foreach($k in @('cloud_aws','cloud_azure','cloud_gcp')){{if($det[$k].detected){{$cloudp=$k.Replace('cloud_','').ToUpper();break}}}}

if($det['wsl'].detected){{$envType='WSL Environment'}}
elseif($inContainer){{$envType=($(if($orchestrator){{$orchestrator+' Container'}}else{{$runtime+' Container'}}))}}
elseif($virt -or $cloudp){{$envType='Virtual Machine'}}
else{{$envType='Physical Host'}}

$hostRel='bare metal'
if($inContainer -and ($virt -or $cloudp)){{$hostRel='container on virtual machine'}}
elseif($inContainer){{$hostRel='container on host'}}
elseif($virt -or $cloudp){{$hostRel='guest virtual machine'}}

$hostAccess='None detected'
if(Test-Path '\\\\.\\pipe\\docker_engine'){{$hostAccess='Docker engine pipe present'}}

$scores=@($det.Values|? detected|ForEach-Object confidence)
$confidence=0; if($scores.Count){{$confidence=[Math]::Min(100,($scores|Measure-Object -Maximum).Maximum + $(if($scores.Count -ge 3){{15}}else{{0}}))}}

$nested='Not detected'
try{{$feat=Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -EA 0;if($feat -and $feat.State -eq 'Enabled' -and ($virt -or $cloudp)){{$nested='Hyper-V role enabled inside guest'}}}}catch{{}}

$sandbox=@()
if($cs -and $cs.Model -match 'Virtual Machine' -and $cs.Manufacturer -match 'Microsoft|VMware|innotek|QEMU'){{$sandbox+='common VM hardware profile'}}
if($cs -and -not $cs.UserName){{$sandbox+='no interactive username context'}}

foreach($e in $det.Values){{foreach($i in $e.indicators){{if($indicators -notcontains $i){{$indicators+=$i}}}}}}

$result=[ordered]@{{
  environment_type=$envType
  runtime=$runtime
  orchestrator=$orchestrator
  namespace=$env:POD_NAMESPACE
  node=$env:NODE_NAME
  container_id=$(if($inContainer){{$env:COMPUTERNAME}}else{{''}})
  host_relationship=$hostRel
  virtualization_type=$virt
  cloud_provider=$cloudp
  host_access=$hostAccess
  container_privileges=$(if($inContainer){{'Container context'}}else{{'N/A'}})
  nested_virtualization=$nested
  hardware_virtualization=$(if($virt){{'Guest VM environment'}}else{{'Not detected'}})
  sandbox_indicators=($(if($sandbox){{$sandbox -join '; '}}else{{'None'}}))
  confidence=$confidence
  indicators=$indicators
  namespaces=@{{}}
  sockets=$sockets
  artifacts=$artifacts
  cloud_metadata=$cloud
  detections=$det
}}
$json=($result|ConvertTo-Json -Depth 8 -Compress)
Write-Output ($start+$json+$end)
"""
