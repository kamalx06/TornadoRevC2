# TornadoRevC2

A Python reverse shell handler for authorized security research, red-team exercises, malware analysis, and penetration testing. TornadoRevC2 provides multi-session shell management, TLS support, file transfer, in-memory payload execution, SOCKS pivoting, and a modular plugin system for host enumeration.

**Supported targets:** Linux and Windows (primary), with generic Unix/BSD compatibility where applicable.

---

## Legal Notice

Use this software only on systems you own or on systems where you have **explicit written authorization**. You are solely responsible for compliance with applicable laws. The authors and contributors accept no liability for misuse, damage, or legal consequences arising from use of this project.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Operator Commands](#operator-commands)
- [Core Features](#core-features)
- [Plugin System](#plugin-system)
- [Built-in Plugins](#built-in-plugins)
- [Session Logging](#session-logging)
- [Project Layout](#project-layout)
- [TLS Setup](#tls-setup)
- [License](#license)

---

## Overview

TornadoRevC2 is a reverse shell **handler**, not a beacon-based command-and-control platform. It focuses on reliable interactive sessions, operator tooling, and on-demand enumeration through plugins.

| Capability | Supported |
|------------|-----------|
| Multi-client TCP and TLS listeners | Yes |
| Interactive PTY/TTY sessions | Yes |
| File upload/download with resume | Yes |
| In-memory payload execution | Yes |
| SOCKS5 pivoting through sessions | Yes |
| Session persistence and reconnect | Yes |
| Extensible plugin architecture | Yes |
| Automated persistence or tasking | No |

---

## Requirements

- Python 3.7+
- OpenSSL (for TLS certificate generation)
- No third-party Python dependencies for the core handler

---

## Quick Start

```bash
# Default: TCP on 4444, TLS on 8443
python tornadorevc2.py

# Custom bind address and ports
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

After a session connects:

```bash
status                          # List active sessions
switch 1                        # Interact with session 1
sysinfo 1                       # Collect host information
run quickenum 1                 # Fast host triage
run secrets 1                   # Deeper Linux enumeration (example)
run privesccheck 1 ./linpeas.sh # Privilege escalation scan (operator-supplied script)
```

---

## Operator Commands

| Command | Description |
|---------|-------------|
| `status` / `ls` | List active reverse shell sessions |
| `sessions` | Show tracked sessions (active and disconnected) |
| `reconnects` | Show session reconnect history |
| `switch <ID>` | Attach to a session shell |
| `kill <ID>` | Terminate a session |
| `sysinfo <ID> [--stealth\|--full]` | Refresh and display host information |
| `plugins [list\|load\|unload\|reload\|info]` | Manage plugins |
| `run <plugin> <ID> [args...]` | Execute a plugin on a session |
| `runpy` / `runps` / `runexe` / `runelf <ID> <local>` | In-memory payload execution |
| `clipboard <ID>` | Read remote clipboard |
| `upload` / `download` / `verify` | File transfer with integrity checks |
| `socks <ID> <port>` | Start SOCKS5 pivot through a session |
| `socks stop <proxy_id>` | Stop SOCKS proxy and clean up remote artifacts |
| `tunnels` | List active SOCKS proxies |
| `export <ID>` | Export HTML session transcript |
| `rename` / `rn <ID> <name>` | Rename a session |
| `payloads` | Display payload reference |
| `help` | Show command reference |
| `exit` / `quit` | Shut down the handler |

Inside an attached shell (`switch <ID>`), omit the session ID for transfer and session-scoped commands.

---

## Core Features

### Listeners

Plain TCP and TLS listeners run concurrently. TLS uses TLS 1.2+ with configurable certificate and key files.

### Session Management

Thread-safe multi-session handling with stable session fingerprinting, reconnect tracking, and per-session directory logging.

### Host Information

Host data is collected on demand via `sysinfo`. Use default (stealth-oriented) collection or `--full` for comprehensive enumeration.

### File Transfer

Chunked upload and download with SHA-256 verification and resume support.

### In-Memory Execution

| Command | Target | Behavior |
|---------|--------|----------|
| `runpy` | Cross-platform | Execute Python from memory |
| `runps` | Windows | Execute PowerShell from memory |
| `runexe` | Windows | Execute PE with stdout/stderr capture and temp cleanup |
| `runelf` | Linux | Execute ELF via `memfd_create` with `/dev/shm` fallback |

```bash
runexe 1 C:\tools\payload.exe -- --flag value
runexe 1 beacon.exe --save-output C:\local\out.txt
```

### SOCKS5 Pivoting

Route operator tools through a compromised host to reach internal networks.

When the last SOCKS proxy for a session is stopped, TornadoRevC2 terminates the remote tunnel agent, removes uploaded scripts and marker files, and logs cleanup status. Session disconnect triggers the same remote cleanup path.

### Export and Clipboard

Generate HTML session transcripts and read the remote clipboard from the handler console.

---

## Plugin System

Plugins extend the handler at runtime without modifying core code. Built-in plugins ship under `tornadorevc2/plugins/`. External modules can be placed in a top-level `plugins/` directory or loaded from a custom path via `TORNADOREVC2_PLUGIN_DIR`.

### Management

| Command | Description |
|---------|-------------|
| `plugins` / `plugins list` | List registered plugins |
| `plugins list --verbose` | Show module paths and load state |
| `plugins load <name>` | Load a plugin at runtime |
| `plugins unload <name>` | Unload or disable a plugin |
| `plugins reload <name>` | Reload a plugin module |
| `plugins info <name>` | Show plugin details |
| `run <plugin> <session_id> [args...]` | Execute a plugin on a session |

Built-in plugins are soft-disabled with `plugins unload` (the module stays imported). External plugins are fully unloaded and unregistered. `plugins reload` unregisters stale commands before re-importing, so renamed commands do not linger in the registry.

### Creating a Custom Plugin

A plugin is a Python module that registers one or more commands with the `@plugin.command` decorator. Each command maps to a handler function that receives a `SessionContext` and an argument list from the operator console.

**Minimal example** (`plugins/uptime_check.py` — roughly 20 lines):

```python
"""Report how long the remote host has been up."""
import json
from tornadorevc2.plugins import plugin, SessionContext
from tornadorevc2.constants import PLUGIN_MARK_START, PLUGIN_MARK_END

@plugin.command(
    name="uptime_check",
    platforms=["linux", "unix", "windows"],
    description="Show remote system uptime",
)
def run(session: SessionContext, args):
    if session.is_windows:
        ps = (
            f"$s='{PLUGIN_MARK_START}';$e='{PLUGIN_MARK_END}';"
            "$up=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;"
            "$txt='up since '+$up;"
            "Write-Output ($s+$txt+$e)"
        )
        raw = session.run_marked("", ps, timeout=15.0)
    else:
        cmd = f"echo '{PLUGIN_MARK_START}'$(uptime -p 2>/dev/null || uptime)'{PLUGIN_MARK_END}'"
        raw = session.run_marked(cmd, "", timeout=15.0)
    if not raw:
        session.print("uptime_check: no response from target", "red")
        return 1
    text = raw.strip()
    session.print(f"Uptime: {text}", "cyan")
    session.log_plugin_result("uptime_check", text)
    return 0
```

```bash
plugins load uptime_check    # load from ./plugins/uptime_check.py
run uptime_check 1           # execute on session 1
plugins reload uptime_check  # pick up edits without restarting the handler
```

**Key concepts:**

| Element | Purpose |
|---------|---------|
| `@plugin.command(name=..., platforms=..., description=...)` | Registers the command at import time |
| `run(session, args)` | Entry point; return `0` on success, non-zero on failure |
| `session.run_shell(cmd)` | Run a raw shell command and capture output |
| `session.run_marked(unix_cmd, win_ps, timeout=...)` | Run a collector that wraps output in `__T_PLUGIN_START__` / `__T_PLUGIN_END__` markers |
| `session.print(text, color)` | Write colored output to the operator console |
| `session.log_plugin_result(name, report, detail='')` | Persist results under `logs/<session>/plugins/` |

For structured JSON collectors, use `run_collector_plugin` from `tornadorevc2.plugins.shared.runner` with platform-specific `build_command()` functions (see built-in plugins such as `services` or `virtualization`).

### SessionContext API

```python
from tornadorevc2.plugins import plugin, SessionContext

@plugin.command(
    name="myplugin",
    platforms=["linux", "unix"],
    description="Custom enumeration plugin",
)
def run(session: SessionContext, args):
    output = session.run_shell("id")
    session.print(output)
    session.log_plugin_result("myplugin", output)
    return 0
```

| Capability | Method / Property |
|------------|-------------------|
| Session metadata | `session_id`, `platform`, `sysinfo`, `identity`, `addr`, `tls` |
| Shell execution | `run_shell()`, `run_shell_streaming()`, `run_marked()` |
| File transfer | `upload()`, `download()`, `verify_remote()` |
| Logging | `log_event()`, `log_command()`, `log_plugin_result()` |
| Host info | `collect_sysinfo()`, `get_cwd()` |
| Terminal output | `print()` with handler color support |

### External Plugin Example

```python
from tornadorevc2.plugins import plugin, SessionContext
from tornadorevc2.plugins.shared.runner import run_collector_plugin
from tornadorevc2.plugins.shared.common import format_generic_report

@plugin.command(name="custom", platforms=["linux", "unix"], description="Custom enum")
def run(session: SessionContext, args):
    def build_cmd():
        return "python3 -c 'print(\"__T_PLUGIN_START__{\\\"summary\\\":{\\\"ok\\\":1}}__T_PLUGIN_END__\")'"
    return run_collector_plugin(session, "custom", build_cmd, None, format_generic_report)
```

```bash
plugins load custom
run custom 1
```

Plugin output is displayed in the terminal and written to `logs/<session>/plugins/`.

---

## Built-in Plugins

### Cross-Platform

| Plugin | Description |
|--------|-------------|
| `quickenum` | Fast structured host assessment (30–60 s): hostname, user, network, environment, findings |
| `virtualization` | VM, container, orchestration, and cloud environment detection |
| `privesccheck` | LinPEAS / WinPEAS privilege escalation enumeration (operator-supplied local script) |
| `wiper` | Secure multi-pass file overwrite (zeros → ones → random) then delete |
| `mounts` | Mounts, SMB/NFS shares, mapped drives, bind mounts, container filesystems |
| `history` | Shell history, package/update logs, recent login activity |

### Linux / Unix

| Plugin | Description |
|--------|-------------|
| `secrets` | Config files, environment variables, SSH keys, cloud credentials, tokens |
| `cron` | Cron jobs, system cron directories, user crontabs, at queues |
| `systemd` | Services, timers, failed units, enabled startup units |

### Windows

| Plugin | Description |
|--------|-------------|
| `adinfo` | Domain membership, domain controllers, forest/trusts, OUs |
| `services` | Services, startup types, binaries, service accounts |
| `scheduledtasks` | Scheduled tasks, triggers, execution context, actions |
| `registry` | Autoruns, Run keys, startup locations, installed software |
| `eventlogs` | Security, System, Application, and PowerShell log summaries |
| `defender` | Defender status, exclusions, ASR rules, security products |
| `certificates` | Certificate stores, code-signing and enterprise certificates |

---

## Plugin Reference

### QuickEnum

Single round-trip host triage. Collects condensed signals from virtualization, secrets, services, and related areas without chaining multiple plugins.

```bash
run quickenum 1
```

**Linux / Unix:** hostname, user, sudo, kernel, containers, cloud metadata, network, mounts, systemd/cron, credential artifacts.

**Windows:** hostname, user, admin status, domain, network, mounts/shares, services, Defender, autoruns, credential artifacts.

Example output:

```text
Host Summary
------------
Hostname:              web01
OS:                    Ubuntu 24.04
Kernel:                6.8.0
Architecture:          x86_64

Environment
-----------
Type:                  Docker container
Orchestrator:          Kubernetes

Findings
--------
- Docker container (.dockerenv)
- Kubernetes environment
- .env file found

Collection time: 4.2s
```

### Wiper

Three-pass overwrite followed by deletion:

1. Fill with `0x00`
2. Fill with `0xFF`
3. Fill with random data

Each pass is flushed before the next. The file is then removed.

```bash
run wiper 1 /tmp/exfil.log
run wiper 2 C:\Users\Public\staging.dat
```

**Note:** Multi-pass overwrite provides strong assurance on HDDs. On SSD/NVMe, wear leveling may leave data in remapped blocks inaccessible to the OS. Use full-disk encryption, secure erase utilities, or physical destruction when high-assurance sanitization is required.

### Privilege Escalation Check

Selects LinPEAS on Linux/Unix and WinPEAS on Windows. Provide the local script path on the operator machine — scripts are not bundled.

```bash
run privesccheck 1 ./linpeas.sh
run privesccheck 2 C:\tools\winPEAS.bat
```

| Target | File types | Execution |
|--------|------------|-----------|
| Linux / Unix | `.sh` | Piped into `bash` stdin; large scripts may stage in `/dev/shm` |
| Windows | `.bat`, `.cmd`, `.exe` | PowerShell decode or staged exe with cleanup |

Output streams to the terminal and is saved under `logs/<session>/plugins/`. Script contents are not logged.

Download LinPEAS / WinPEAS from [PEASS-ng](https://github.com/carlospolop/PEASS-ng).

### Virtualization

Multi-layer VM, container, and cloud detection with weighted confidence scoring. Use `run virtualization <ID>` for full detail, or `run quickenum <ID>` for a condensed summary.

---

## Session Logging

Each session writes to a dedicated directory:

```text
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log       # Commands and output
  sysinfo.json      # Host information snapshot
  transfers/        # Upload/download event logs
  executions/       # Payload execution metadata
  plugins/          # Plugin reports and raw JSON
      quickenum_20260812_054812.log
      wiper_20260812_055030.log
```

Plugin logs include a human-readable report and structured JSON when the collector produces JSON output.

---

## Project Layout

```text
tornadorevc2/
  handler.py              # Server, sessions, and operator console
  sysinfo.py              # Host information collection
  terminal.py             # PTY/TTY and signal handling
  transfer.py             # Chunked file transfers
  payload_exec.py         # In-memory payload execution
  tunnel.py               # SOCKS5 pivoting
  session_registry.py     # Session persistence and reconnect
  session_log.py          # Per-session directory logging
  export.py               # HTML transcript export
  payloads.py             # Payload catalog
  plugins/
    api.py                # SessionContext and @plugin.command
    manager.py            # Runtime loading and execution
    loader.py             # Module discovery
    shared/               # Cross-platform plugin entries
      common.py           # Formatting and platform helpers
      runner.py           # Collector execution and JSON parsing
    linux/                # Linux-specific collectors
    windows/              # Windows-specific collectors
tornadorevc2.py           # Entry point
plugins/                  # Optional external plugin directory
```

---

## TLS Setup

Generate a self-signed certificate for the TLS listener:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

Start the handler with explicit certificate paths:

```bash
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
