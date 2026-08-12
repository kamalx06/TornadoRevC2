"""Windows QuickEnum collector (internal — loaded by linux/quickenum plugin entry)."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$findings=@(); function Add-F($t){{ if($t -and ($findings -notcontains $t)){{ $findings+=$t }} }}
$sw=[Diagnostics.Stopwatch]::StartNew()
$cs=Get-CimInstance Win32_ComputerSystem -EA 0
$os=Get-CimInstance Win32_OperatingSystem -EA 0
$hostname=$env:COMPUTERNAME
$user=$env:USERNAME
$domain=$cs.Domain
$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isDomain=($cs.PartOfDomain -eq $true)
$build=$os.BuildNumber
$arch=$env:PROCESSOR_ARCHITECTURE
$osName=$os.Caption

# Virtualization / container
$envType='Physical host'
$bios=(Get-CimInstance Win32_BIOS -EA 0).SerialNumber
$model=$cs.Model
if($model -match 'Virtual|VMware|Hyper-V|KVM|QEMU|Xen|VirtualBox'){{ $envType='Virtual machine'; Add-F "Virtual machine ($model)" }}
if($env:COMPUTERNAME -match 'docker|container'){{ $envType='Container'; Add-F 'Container hostname pattern' }}
if(Test-Path '\\.\pipe\docker_engine'){{ Add-F 'Docker engine pipe present' }}
if($env:KUBERNETES_SERVICE_HOST){{ Add-F 'Kubernetes environment'; $envType='Kubernetes pod/container' }}

# Cloud
$cloud=''
try{{
  $r=Invoke-WebRequest -Uri 'http://169.254.169.254/latest/meta-data/instance-id' -Headers @{{Metadata='true'}} -TimeoutSec 1 -UseBasicParsing
  if($r.Content){{ $cloud='AWS'; Add-F 'Cloud instance (AWS metadata)' }}
}}catch{{}}

# Network
$ips=@()
Get-NetIPAddress -AddressFamily IPv4 -EA 0|Where-Object{{ $_.IPAddress -ne '127.0.0.1' }}|ForEach-Object{{ $ips+=$_.IPAddress }}
$gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA 0|Select-Object -First 1).NextHop
$dns=(Get-DnsClientServerAddress -AddressFamily IPv4 -EA 0|Select-Object -ExpandProperty ServerAddresses -Unique) -join ', '
$ports=@()
Get-NetTCPConnection -State Listen -EA 0|Select-Object -ExpandProperty LocalPort -Unique|Sort-Object|Select-Object -First 20|ForEach-Object{{ $ports+=$_ }}

# Shares
$shares=@()
Get-SmbShare -EA 0|ForEach-Object{{ $shares+="$($_.Name) ($($_.Path))" }}

# Services (notable)
$svcCount=(Get-Service -EA 0).Count
$running=(Get-Service -EA 0|Where-Object Status -eq Running).Count

# Scheduled tasks
$tasks=(Get-ScheduledTask -EA 0|Where-Object State -ne Disabled).Count

# Defender / security
$def=@{{}}; $secProducts=@()
try{{
  $st=Get-MpComputerStatus -EA 0
  $def=@{realtime=$st.RealTimeProtectionEnabled;signatures=$st.AntivirusSignatureVersion;tamper=$st.IsTamperProtected}
}}catch{{}}
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA 0|ForEach-Object{{ $secProducts+=$_.displayName }}

# Registry autoruns (sample)
$autoruns=@()
$runKeys=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
foreach($rk in $runKeys){{
  if(Test-Path $rk){{
    Get-ItemProperty $rk -EA 0|Get-Member -MemberType NoteProperty|Where-Object Name -notmatch '^PS'|ForEach-Object{{
      $autoruns+="$($_.Name)"
    }}
  }}
}}
if($autoruns.Count -gt 0){{ Add-F "Registry autoruns: $($autoruns.Count) entries" }}

# PowerShell history
$psHist=$false
$histPath=(Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
if(Test-Path $histPath){{ $psHist=$true; Add-F 'PowerShell history present' }}

# Credential artifacts
$creds=@()
$paths=@(
  "$env:USERPROFILE\.aws\credentials",
  "$env:USERPROFILE\.ssh\id_rsa",
  "$env:USERPROFILE\.docker\config.json",
  "$env:USERPROFILE\.kube\config"
)
foreach($p in $paths){{ if(Test-Path $p){{ $creds+=$p; Add-F "Sensitive file: $p" }} }}

# Certificates summary
$certCount=(Get-ChildItem Cert:\CurrentUser\My -EA 0).Count + (Get-ChildItem Cert:\LocalMachine\My -EA 0).Count

$result=[ordered]@{{
  host_summary=@{{Hostname=$hostname;OS=$osName;Build=$build;Architecture=$arch}}
  user=@{{User=$user;Admin=$isAdmin;Domain=$domain;DomainJoined=$isDomain}}
  environment=@{{Type=$envType;Cloud=$cloud;Model=$model;BIOS=$bios}}
  network=@{{IP=($ips -join ', ');Default_Gateway=$gw;DNS=$dns;Listening_Ports=($ports -join ', ')}}
  storage=@{{SMB_Shares=($shares -join '; ')}}
  services=@{{Total=$svcCount;Running=$running;Scheduled_Tasks=$tasks}}
  security=@{{Defender_RealTime=$def.realtime;Defender_Signatures=$def.signatures;Security_Products=($secProducts -join ', ');Autorun_Entries=($autoruns -join ', ')}}
  credentials=@{{Sensitive_Files=($creds -join ', ');PowerShell_History=$psHist;Certificate_Store_Count=$certCount}}
  findings=$findings
  elapsed_sec=[math]::Round($sw.Elapsed.TotalSeconds,2)
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
"""
