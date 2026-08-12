"""Windows virtualization and container detection collector."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def build_windows_detection_script():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'
$end='{PLUGIN_MARK_END}'
function Add-Det($map,$name,$detected,$conf,$items){{
  if(-not $map.ContainsKey($name)){{$map[$name]=@{{detected=$false;confidence='none';indicators=@()}}}}
  $e=$map[$name]
  if($detected){{$e.detected=$true
    $order=@{{none=0;low=1;medium=2;high=3}}
    if($order[$conf] -gt $order[$e.confidence]){{$e.confidence=$conf}}
  }}
  foreach($i in $items){{if($i -and ($e.indicators -notcontains $i)){{$e.indicators+=$i}}}}
}}
$det=@{{}}
$indicators=@()
$sockets=@()
$artifacts=@()

# Docker Desktop / containers
$dockerHits=@()
if(Test-Path 'HKLM:\\SOFTWARE\\Docker Inc.\\Docker'){{$dockerHits+='Docker Desktop registry key'}}
foreach($svc in Get-Service -Name 'com.docker.service','docker' -ErrorAction SilentlyContinue){{
  if($svc){{$dockerHits+=('service: '+$svc.Name)}}
}}
if($env:DOCKER_HOST){{$dockerHits+=('DOCKER_HOST='+$env:DOCKER_HOST)}}
if(Test-Path '\\\\.\\pipe\\docker_engine'){{$dockerHits+='docker_engine named pipe';$sockets+='\\\\.\\pipe\\docker_engine'}}
if(Test-Path 'C:\\ProgramData\\Docker'){{$dockerHits+='C:\\ProgramData\\Docker';$artifacts+='C:\\ProgramData\\Docker'}}
Add-Det $det 'docker' ($dockerHits.Count -gt 0) $(if($dockerHits.Count -ge 2){{'high'}}else{{'medium'}}) $dockerHits

# WSL
$wslHits=@()
if($env:WSL_DISTRO_NAME){{$wslHits+=('WSL_DISTRO_NAME='+$env:WSL_DISTRO_NAME)}}
if($env:WSL_INTEROP){{$wslHits+=('WSL_INTEROP present')}}
if(Get-Command wsl.exe -ErrorAction SilentlyContinue){{$wslHits+='wsl.exe available'}}
try{{
  $lxss=Get-ChildItem 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss' -ErrorAction SilentlyContinue
  if($lxss){{$wslHits+='WSL distributions registry'}}
}}catch{{}}
Add-Det $det 'wsl' ($wslHits.Count -gt 0) $(if($env:WSL_DISTRO_NAME){{'high'}}else{{'medium'}}) $wslHits

# Kubernetes
$k8sHits=@()
if($env:KUBERNETES_SERVICE_HOST){{$k8sHits+=('KUBERNETES_SERVICE_HOST='+$env:KUBERNETES_SERVICE_HOST)}}
foreach($svc in Get-Service -Name 'kubelet','kube-proxy' -ErrorAction SilentlyContinue){{
  if($svc){{$k8sHits+=('service: '+$svc.Name)}}
}}
if(Test-Path 'C:\\etc\\kubernetes'){{$k8sHits+='C:\\etc\\kubernetes';$artifacts+='C:\\etc\\kubernetes'}}
if(Test-Path 'C:\\ProgramData\\kubernetes'){{$k8sHits+='C:\\ProgramData\\kubernetes';$artifacts+='C:\\ProgramData\\kubernetes'}}
Add-Det $det 'kubernetes' ($k8sHits.Count -gt 0) $(if($env:KUBERNETES_SERVICE_HOST){{'high'}}else{{'medium'}}) $k8sHits

# Hyper-V
$hypervHits=@()
try{{
  $hv=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  if($hv -and $hv.Model -match 'Virtual Machine'){{$hypervHits+=('Model: '+$hv.Model)}}
  if($hv -and $hv.Manufacturer -match 'Microsoft'){{$hypervHits+=('Manufacturer: '+$hv.Manufacturer)}}
}}catch{{}}
foreach($svc in Get-Service -Name 'vmms','vmicheartbeat','vmickvpexchange' -ErrorAction SilentlyContinue){{
  if($svc){{$hypervHits+=('service: '+$svc.Name)}}
}}
try{{
  $key=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters' -ErrorAction SilentlyContinue
  if($key){{$hypervHits+='Hyper-V guest parameters registry'}}
}}catch{{}}
Add-Det $det 'hyperv' ($hypervHits.Count -gt 0) $(if($hypervHits.Count -ge 2){{'high'}}else{{'medium'}}) $hypervHits

# VMware
$vmwHits=@()
try{{
  $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  if($cs.Manufacturer -match 'VMware'){{$vmwHits+=('Manufacturer: '+$cs.Manufacturer)}}
  if($cs.Model -match 'VMware'){{$vmwHits+=('Model: '+$cs.Model)}}
}}catch{{}}
Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {{$_.Name -match 'VMware'}} | ForEach-Object {{$vmwHits+=('PnP: '+$_.Name)}}
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {{$_.Name -match 'vmw|vmx'}} | ForEach-Object {{$vmwHits+=('driver: '+$_.Name)}}
Add-Det $det 'vmware' ($vmwHits.Count -gt 0) $(if($vmwHits.Count -ge 2){{'high'}}else{{'medium'}}) $vmwHits

# VirtualBox
$vboxHits=@()
try{{
  $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  if($cs.Manufacturer -match 'innotek|Oracle|VirtualBox'){{$vboxHits+=('Manufacturer: '+$cs.Manufacturer)}}
}}catch{{}}
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {{$_.Name -match 'VBox|vbox'}} | ForEach-Object {{$vboxHits+=('driver: '+$_.Name)}}
Add-Det $det 'virtualbox' ($vboxHits.Count -gt 0) $(if($vboxHits.Count -ge 2){{'high'}}else{{'medium'}}) $vboxHits

# KVM / QEMU (via guest drivers or firmware)
$qemuHits=@()
try{{
  $bios=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
  if($bios.SMBIOSBIOSVersion -match 'QEMU|Bochs|SeaBIOS'){{$qemuHits+=('BIOS: '+$bios.SMBIOSBIOSVersion)}}
  if($bios.Manufacturer -match 'QEMU|Bochs'){{$qemuHits+=('BIOS vendor: '+$bios.Manufacturer)}}
}}catch{{}}
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {{$_.Name -match 'qemu|vios|virtio'}} | ForEach-Object {{$qemuHits+=('driver: '+$_.Name)}}
Add-Det $det 'qemu' ($qemuHits.Count -gt 0) 'medium' $qemuHits
Add-Det $det 'kvm' ($qemuHits.Count -gt 0) 'medium' $qemuHits

# Xen
$xenHits=@()
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {{$_.Name -match 'xen'}} | ForEach-Object {{$xenHits+=('driver: '+$_.Name)}}
try{{
  $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  if($cs.Manufacturer -match 'Xen'){{$xenHits+=('Manufacturer: '+$cs.Manufacturer)}}
}}catch{{}}
Add-Det $det 'xen' ($xenHits.Count -gt 0) 'medium' $xenHits

# Summary
$inContainer = ($det['docker'].detected -or $env:CONTAINER -or $env:KUBERNETES_SERVICE_HOST)
$runtime=''
$orchestrator=''
$environmentType='Physical Host'
$virtualizationType=''
$confidence='low'
$containerId=$env:COMPUTERNAME
$namespace=$env:POD_NAMESPACE
if(-not $namespace){{$namespace=$env:KUBERNETES_NAMESPACE}}
$node=$env:NODE_NAME
if(-not $node){{$node=$env:KUBERNETES_NODE_NAME}}

if($det['docker'].detected){{$runtime='docker'}}
if($det['kubernetes'].detected){{$orchestrator='Kubernetes'}}
if($det['wsl'].detected){{
  $environmentType='WSL Environment'
  $virtualizationType='WSL'
  $confidence=$det['wsl'].confidence
}} elseif($inContainer){{
  if($orchestrator){{$environmentType="$orchestrator Pod/Container"}}
  elseif($runtime){{$environmentType=(Get-Culture).TextInfo.ToTitleCase($runtime)+' Container'}}
  else {{$environmentType='Container'}}
  if($runtime){{$confidence='high'}} else {{$confidence='medium'}}
}} else {{
  foreach($pair in @(@('vmware','VMware'),@('virtualbox','VirtualBox'),@('hyperv','Hyper-V'),@('kvm','KVM'),@('qemu','QEMU'),@('xen','Xen'))){{
    $k=$pair[0];$label=$pair[1]
    if($det[$k].detected){{$virtualizationType=$label;$environmentType='Virtual Machine';$confidence=$det[$k].confidence;break}}
  }}
}}

$hostRelationship='bare metal'
if($inContainer -and $virtualizationType){{$hostRelationship='container on virtual machine'}}
elseif($inContainer){{$hostRelationship='container on host'}}
elseif($virtualizationType){{$hostRelationship='guest virtual machine'}}

foreach($e in $det.Values){{foreach($i in $e.indicators){{if($indicators -notcontains $i){{$indicators+=$i}}}}}}

$result=[ordered]@{{
  environment_type=$environmentType
  container_id=$(if($inContainer){{$containerId}}else{{''}})
  runtime=$runtime
  orchestrator=$orchestrator
  namespace=$(if($namespace){{$namespace}}else{{''}})
  node=$(if($node){{$node}}else{{''}})
  virtualization_type=$virtualizationType
  host_relationship=$hostRelationship
  confidence=$confidence
  indicators=$indicators
  sockets=$sockets
  artifacts=$artifacts
  detections=$det
}}
$json=($result | ConvertTo-Json -Depth 6 -Compress)
Write-Output ($start+$json+$end)
"""
