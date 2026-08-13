"""Windows shell and command history enumeration collector."""

from ._helpers import wrap_ps_collector


def build_command():
    body = r"""
function Read-TailLines($path,$count,$maxLen=200){
  if(-not (Test-Path $path)){return $null}
  try{
    $lines=Get-Content $path -Tail $count -EA Stop
    return @{path=$path;recent=@($lines|Where-Object{$_.Trim()}|ForEach-Object{$_.Trim().Substring(0,[Math]::Min($maxLen,$_.Trim().Length))})}
  }catch{return $null}
}
$histFiles=@()
foreach($p in @(
  (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Path $env:ProgramData 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
  (Join-Path $env:USERPROFILE '.python_history'),
  (Join-Path $env:USERPROFILE '.node_repl_history')
)){
  $entry=Read-TailLines $p 40
  if($entry){$histFiles+=$entry}
}
try{
  $cmdKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
  if(Test-Path $cmdKey){
    $recent=@()
    Get-ItemProperty $cmdKey -EA 0|Get-Member -MemberType NoteProperty|Where-Object Name -notmatch '^PS'|ForEach-Object{
      $v=(Get-ItemProperty $cmdKey -Name $_.Name -EA 0).($_.Name)
      if($v){$recent+=($v -replace [char]0,'').Substring(0,[Math]::Min(200,$v.Length))}
    }
    if($recent.Count){$histFiles+=@{path=$cmdKey;recent=$recent[-40..-1]}}
  }
}catch{}

$pkgHist=@()
foreach($p in @(
  'C:\Windows\Logs\CBS\CBS.log',
  'C:\Windows\Logs\DISM\dism.log',
  'C:\ProgramData\USOShared\Logs\UpdateAssistant.log'
)){
  if(Test-Path $p){
    try{
      $tail=Get-Content $p -Tail 15 -EA Stop
      $pkgHist+=@{path=$p;recent=@($tail|ForEach-Object{$_.Trim().Substring(0,[Math]::Min(160,$_.Trim().Length))})}
    }catch{}
  }
}

$recentLogins=@()
try{
  quser 2>$null|ForEach-Object{if($_.Trim()){$recentLogins+=$_.Trim()}}
}catch{}
try{
  Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 15 -EA 0|
    ForEach-Object{$recentLogins+="$($_.TimeCreated.ToString('s')) Id=$($_.Id)"}
}catch{}

$result=[ordered]@{
  summary=@{history_files=$histFiles.Count;package_logs=$pkgHist.Count}
  shell_history=$histFiles
  package_manager_history=$pkgHist
  recent_logins=@($recentLogins|Select-Object -First 15)
}
$json=($result|ConvertTo-Json -Depth 5 -Compress)
"""
    return wrap_ps_collector(body)
