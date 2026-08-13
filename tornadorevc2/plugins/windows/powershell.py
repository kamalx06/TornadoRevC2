"""Windows PowerShell environment and configuration enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def build_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$version=@{{}}; $execPolicy=@{{}}; $profiles=@{{}}; $modules=@(); $remoting=@{{}}; $logging=@{{}}

try{{
  $PSVersionTable.GetEnumerator()|ForEach-Object{{$version[$_.Key]=$_.Value.ToString()}}
}}catch{{}}

try{{
  Get-ExecutionPolicy -List -EA 0|ForEach-Object{{$execPolicy[$_.Scope.ToString()]=$_.ExecutionPolicy.ToString()}}
}}catch{{}}

try{{
  $profiles=@{{AllUsersAllHosts=$PROFILE.AllUsersAllHosts;AllUsersCurrentHost=$PROFILE.AllUsersCurrentHost;CurrentUserAllHosts=$PROFILE.CurrentUserAllHosts;CurrentUserCurrentHost=$PROFILE.CurrentUserCurrentHost}}
  foreach($k in $profiles.Keys){{
    $profiles[$k]=@{{path=$profiles[$k];exists=(Test-Path $profiles[$k])}}
  }}
}}catch{{}}

try{{
  $env:PSModulePath -split ';'|Where-Object{{$_.Trim()}}|ForEach-Object{{$modules+=@{{path=$_;exists=(Test-Path $_)}}}}
}}catch{{}}

try{{
  $remoting.wsman=(Test-WSMan -EA 0) -ne $null
  $remoting.winrm_service=(Get-Service WinRM -EA 0|Select-Object -ExpandProperty Status)
  Get-PSSessionConfiguration -EA 0|Select-Object -First 15 Name,Permission,Enabled,RunAsCredential|ForEach-Object{{
    if(-not $remoting.session_configs){{$remoting.session_configs=@()}}
    $remoting.session_configs+=@{{name=$_.Name;enabled=$_.Enabled;permission=$_.Permission}}
  }}
}}catch{{}}

try{{
  $logKeys=@(
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ModuleNames'
  )
  foreach($k in $logKeys){{
    if(Test-Path $k){{
      $props=Get-ItemProperty $k -EA 0
      if($props){{$logging[$k]=@{{EnableModuleLogging=$props.EnableModuleLogging;EnableScriptBlockLogging=$props.EnableScriptBlockLogging;EnableTranscripting=$props.EnableTranscripting;OutputDirectory=$props.OutputDirectory}}}}
    }}
  }}
}}catch{{}}

$psReadLine=@{{}}
try{{
  $hist=Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
  $psReadLine=@{{history_path=$hist;history_exists=(Test-Path $hist)}}
  if(Test-Path $hist){{$psReadLine.history_lines=(Get-Content $hist -EA 0|Measure-Object -Line).Lines}}
}}catch{{}}

$languageMode=$ExecutionContext.SessionState.LanguageMode
$result=[ordered]@{{
  summary=@{{ps_version=$version.PSVersion;execution_policy=$execPolicy.MachinePolicy;language_mode=$languageMode;winrm=$remoting.winrm_service;module_paths=$modules.Count}}
  version=$version
  execution_policy=$execPolicy
  profiles=$profiles
  module_paths=$modules
  remoting=$remoting
  logging=$logging
  psreadline=$psReadLine
  language_mode=$languageMode
}}
Write-Output ($start+(ConvertTo-Json $result -Depth 6 -Compress)+$end)
"""


@plugin.command(
    name='powershell',
    platforms=['windows'],
    description='Enumerate PowerShell version, execution policy, logging, modules, remoting, and profiles',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'powershell', None, build_command, format_generic_report, timeout=35.0)
