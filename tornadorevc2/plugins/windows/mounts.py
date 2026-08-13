"""Windows mount, filesystem, and SMB share enumeration collector."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
try {{
  $mounts=@(); $mapped=@(); $smb=@(); $wmi=@()
  Get-CimInstance Win32_LogicalDisk -EA 0|ForEach-Object{{
    $dt=switch([int]$_.DriveType){{2{{'Removable'}}3{{'Fixed'}}4{{'Network'}}5{{'CD-ROM'}}default{{'Other'}}}}
    $mounts+=[PSCustomObject]@{{
      device=$_.DeviceID; mount=$_.DeviceID; fstype=($(if($_.FileSystem){{$_.FileSystem}}else{{'unknown'}}))
      options="type=$dt;size=$($_.Size);free=$($_.FreeSpace)"; writable=$true; noexec=$false; bind=$false
    }}
  }}
  try {{
    Get-SmbMapping -EA Stop|ForEach-Object{{
      $mapped+=[PSCustomObject]@{{local=$_.LocalPath;remote=$_.RemotePath;status=$_.Status}}
      $mounts+=[PSCustomObject]@{{
        device=$_.RemotePath; mount=$_.LocalPath; fstype='smb'; options="status=$($_.Status)"
        writable=$true; noexec=$false; bind=$false
      }}
    }}
  }}catch{{}}
  try {{
    Get-SmbShare -EA Stop|ForEach-Object{{
      $smb+=[PSCustomObject]@{{name=$_.Name;path=$_.Path;desc=$_.Description}}
    }}
  }}catch{{}}
  Get-CimInstance Win32_Share -EA 0|ForEach-Object{{
    $wmi+=[PSCustomObject]@{{name=$_.Name;path=$_.Path;type=$_.Type}}
  }}
  $net=@($mounts|Where-Object{{$_.fstype -eq 'smb' -or $_.options -match 'type=Network'}})
  $ctr=@($mounts|Where-Object{{$_.mount -match 'docker|wsl|containerd|kubelet' -or $_.device -match 'docker|wsl|containerd|kubelet'}})
  $wex=@($mounts|Where-Object{{$_.writable -and -not $_.noexec}})
  $result=[ordered]@{{
    summary=[ordered]@{{
      total_mounts=$mounts.Count; nfs_smb=$net.Count; container_mounts=$ctr.Count; writable_exec=$wex.Count
      local_shares=$smb.Count; mapped_drives=$mapped.Count; wmi_shares=$wmi.Count
    }}
    mounts=@($mounts|Select-Object -First 80)
    network_mounts=@($net|Select-Object -First 30)
    container_related=@($ctr|Select-Object -First 30)
    writable_executable=@($wex|Select-Object -First 30)
    smb_shares=$smb
    mapped_drives=$mapped
    wmi_shares=$wmi
  }}
  Write-Output ($start+(ConvertTo-Json $result -Depth 5 -Compress)+$end)
}} catch {{
  Write-Output ($start+(ConvertTo-Json ([ordered]@{{error=$_.Exception.Message}}) -Compress)+$end)
}}
"""
