"""Windows mount, filesystem, and SMB share enumeration collector."""

from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
$driveTypes=@{0='Unknown';1='NoRoot';2='Removable';3='Fixed';4='Network';5='CD-ROM';6='RAM'}
$mounts=@()
Get-CimInstance Win32_LogicalDisk -EA 0|ForEach-Object{
  $dt=$driveTypes[[int]$_.DriveType]
  $mounts+=@{
    device=$_.DeviceID
    mount=($(if($_.DeviceID -match ':$'){"$($_.DeviceID)\"}else{$_.DeviceID}))
    fstype=($(if($_.FileSystem){$_.FileSystem}else{'unknown'}))
    options="drive_type=$dt;size=$($_.Size);free=$($_.FreeSpace)"
    writable=$true
    noexec=$false
    bind=$false
  }
}
$mapped=@()
Get-SmbMapping -EA 0|ForEach-Object{
  $mapped+=@{local=$_.LocalPath;remote=$_.RemotePath;status=$_.Status}
  $mounts+=@{
    device=$_.RemotePath
    mount=$_.LocalPath
    fstype='smb'
    options="status=$($_.Status)"
    writable=$true
    noexec=$false
    bind=$false
  }
}
Get-CimInstance Win32_MappedLogicalDisk -EA 0|ForEach-Object{
  $mounts+=@{
    device=$_.ProviderName
    mount=$_.Name
    fstype='mapped'
    options="status=$($_.Status)"
    writable=$true
    noexec=$false
    bind=$false
  }
}

$smbShares=@()
Get-SmbShare -EA 0|ForEach-Object{
  $smbShares+=@{name=$_.Name;path=$_.Path;desc=$_.Description}
}
$wmiShares=@()
Get-WmiObject Win32_Share -EA 0|ForEach-Object{
  $wmiShares+=@{name=$_.Name;path=$_.Path;type=$_.Type}
}
$netview=@()
net view 2>$null|Select-Object -Skip 6|ForEach-Object{if($_ -match '\\'){$netview+=$_.Trim()}}

$network=@($mounts|Where-Object{$_.fstype -in @('smb','mapped') -or $_.options -match 'drive_type=Network'})
$container=@($mounts|Where-Object{
  $_.mount -match 'docker|wsl|containerd|kubelet' -or $_.device -match 'docker|wsl|containerd|kubelet'
})
$writableExec=@($mounts|Where-Object{$_.writable -and -not $_.noexec})

$result=[ordered]@{
  summary=@{
    total_mounts=$mounts.Count
    nfs_smb=$network.Count
    container_mounts=$container.Count
    writable_exec=$writableExec.Count
    local_shares=$smbShares.Count
    mapped_drives=$mapped.Count
    wmi_shares=$wmiShares.Count
    net_view=$netview.Count
  }
  mounts=@($mounts|Select-Object -First 80)
  network_mounts=@($network|Select-Object -First 30)
  container_related=@($container|Select-Object -First 30)
  writable_executable=@($writableExec|Select-Object -First 30)
  smb_shares=$smbShares
  mapped_drives=$mapped
  wmi_shares=$wmiShares
  network_hosts=$netview
}
$json=($result|ConvertTo-Json -Depth 5 -Compress)
"""
    return wrap_ps_collector(body)
