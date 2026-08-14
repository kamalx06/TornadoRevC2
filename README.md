# TornadoRevC2

A lightweight, modular post-exploitation framework for authorized security research, red-team operations, and penetration testing. TornadoRevC2 manages reverse shell sessions on Linux and Windows hosts through a unified operator console, extending core session handling with a cross-platform plugin architecture for host enumeration, situational awareness, and operational tasks.

> **Important:** TornadoRevC2 is a session handler and post-exploitation framework—not a beacon-style command-and-control platform. It prioritizes reliable interactive shells, structured operator workflows, and on-demand plugin execution over persistent agent infrastructure.

---

## Legal Notice

Use this software only on systems you own or on systems where you have **explicit written authorization**. You are solely responsible for compliance with applicable laws and organizational policies. The authors and contributors accept no liability for misuse, data loss, or legal consequences arising from the use of this project.

---

## Table of Contents

- [Introduction](#introduction)
- [Key Features](#key-features)
- [Design Philosophy](#design-philosophy)
- [Architecture](#architecture)
- [Requirements & Installation](#requirements--installation)
- [Quick Start](#quick-start)
- [Operator Reference](#operator-reference)
- [Built-in Plugins](#built-in-plugins)
- [Plugin Development](#plugin-development)
  - [Plugin system overview](#plugin-system-overview)
  - [Plugin placement](#plugin-placement)
  - [Registration](#registration)
  - [Execution lifecycle](#execution-lifecycle)
  - [Pattern 1: Simple shell plugin](#pattern-1-simple-shell-plugin)
  - [Pattern 2: Structured collector](#pattern-2-structured-collector-recommended)
  - [Pattern 3: Custom handler](#pattern-3-custom-handler)
  - [Linux collectors](#linux-collectors)
  - [Windows collectors](#windows-collectors)
  - [JSON payload conventions](#json-payload-conventions)
  - [Custom formatters](#custom-formatters)
  - [Platform-specific plugins](#platform-specific-plugins)
  - [External plugins](#external-plugins)
  - [SessionContext API](#sessioncontext-api)
  - [Error handling & return codes](#error-handling--return-codes)
  - [Best practices](#best-practices)
  - [Reference implementations](#reference-implementations)
- [Session Logging](#session-logging)
- [Project Structure](#project-structure)
- [TLS Configuration](#tls-configuration)
- [License](#license)

---

## Introduction

TornadoRevC2 accepts inbound reverse shell connections over plain TCP or TLS and provides a single interface for session management, host reconnaissance, file operations, network pivoting, and post-exploitation tasks. The project evolved from a basic reverse shell handler into a modular framework where each capability—firewall enumeration, credential store metadata, network mapping, browser profiling, and more—is delivered as an independent plugin.

**Supported platforms:** Linux and Windows (primary); generic Unix and BSD environments where applicable.

---

## Key Features

| Category | Capabilities |
|----------|-------------|
| **Session handling** | Multi-client TCP/TLS listeners, interactive PTY/TTY sessions, session fingerprinting, reconnect tracking |
| **Transfer & execution** | Chunked file transfer with resume and SHA-256 verification; in-memory payload execution (`py`, `ps`, `exe`, `elf`, `bat`, `sh`) |
| **Network operations** | SOCKS5 pivoting through compromised sessions with automatic remote cleanup |
| **Enumeration** | 28 built-in plugins covering host triage, network posture, credentials metadata, browsers, VPN/proxy config, and more |
| **Operational plugins** | Secure file wiping, shell history clearing, Windows event log clearing |
| **Extensibility** | Runtime plugin loading, reload, and external plugin support via `TORNADOREVC2_PLUGIN_DIR` |
| **Reporting** | Per-session logging, structured plugin output, HTML transcript export |

**Not supported:** Automated persistence, task scheduling, or beacon-style callback infrastructure.

---

## Design Philosophy

TornadoRevC2 is engineered for environments where deployment friction and operational footprint matter.

### Dependency-light, native-command design

Plugins leverage **native Windows and Linux utilities and built-in system commands** already present on the target host—`netsh`, `ss`, `iptables`, `ufw`, `firewall-cmd`, `nft`, PowerShell cmdlets, `nmcli`, `wevtutil`, and others. Collectors invoke these tools through the reverse shell channel and parse output remotely, minimizing the need to upload additional binaries or install dependencies.

### No target-side artifact drops

**Plugin operations execute through the existing reverse shell channel and do not require dropping binaries, executables, scripts, or temporary files onto the target system.** Enumeration tasks run as native commands or in-process collector scripts; results return as marked JSON over the shell. The only unavoidable artifact is normal command history generated by the shell itself.

### Graceful degradation

When an enumeration routine fails, is unavailable, or times out, the plugin does not abort entirely. The affected section is left empty or marked `N/A` while the remainder of the report continues.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Operator Console (handler)                  │
│  Sessions · Transfers · SOCKS · Plugins · Logging · Export      │
└────────────────────────────┬────────────────────────────────────┘
                             │ reverse shell channel (TCP/TLS)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Target Host                              │
│  Native commands · PowerShell · inline collectors               │
│  __T_PLUGIN_START__ + JSON + __T_PLUGIN_END__                   │
└─────────────────────────────────────────────────────────────────┘
```

### Plugin layout

```text
tornadorevc2/plugins/
  shared/     Cross-platform plugins with internal Windows/Linux implementations
  linux/      Linux/Unix-only plugins and collector builders
  windows/    Windows-only plugins (rdp, services, eventlogdel, …)
  api.py      SessionContext and @plugin.command registration
  manager.py  Runtime loading, execution, and platform filtering
  loader.py   Automatic module discovery
```

**Shared plugins** (`firewall`, `ports`, `browser`, `credstore`, and others) exist as single unified modules in `shared/`. **Platform-specific plugins** such as `rdp` and `eventlogdel` reside exclusively under `windows/` or `linux/` and are not duplicated in `shared/`.

Collectors emit JSON wrapped in marker tokens (`__T_PLUGIN_START__` / `__T_PLUGIN_END__`). The shared runner parses this output, formats an operator-facing report, and persists results under the session log directory.

---

## Requirements & Installation

**Handler (operator machine):**

- Python 3.7 or later
- OpenSSL (for TLS certificate generation)
- No third-party Python packages required

**Target host (varies by plugin):**

- Python 2/3, PowerShell, or standard Unix utilities for collectors
- Optional: `wl-clipboard` / `xclip` / `xsel` (Linux clipboard); `import` / `scrot` / `gnome-screenshot` (Linux screenshot)

```bash
git clone <repository-url>
cd TornadoRevC2
python tornadorevc2.py
```

---

## Quick Start

### 1. Start the handler

```bash
# Default: TCP on 4444, TLS on 8443
python tornadorevc2.py

# Custom bind address, ports, and TLS material
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

### 2. Establish a session

Deploy a reverse shell from the built-in catalog (`payloads`) or use your own implant. On connect, TornadoRevC2 assigns a session ID and begins logging under `logs/`.

### 3. Operate

```bash
status                          # List active sessions
switch 1                        # Attach to session 1
sysinfo 1                       # Collect host metadata
run quickenum 1                 # Fast structured triage
run firewall 1                  # Firewall status and rules
run ports 1                     # Listening ports and routing
run browser 1                   # Installed browsers and profiles
run credstore 1                 # Credential store metadata
run memorymap 1 1234            # Process memory maps (requires PID)
run screenshot 1                # Desktop capture (GUI sessions)
run inmemory 1 sh ./linpeas.sh  # In-memory script execution
```

When attached via `switch <ID>`, omit the session ID from subsequent commands (`run quickenum` instead of `run quickenum 1`). Plugin listings and TAB completion inside a client session are filtered to plugins compatible with that session's platform.

---

## Operator Reference

### Session management

| Command | Description |
|---------|-------------|
| `status` / `ls` | List active reverse shell sessions |
| `sessions` | Show tracked sessions, including disconnected hosts |
| `reconnects` | Display session reconnect history |
| `switch <ID>` | Attach to an interactive session shell |
| `kill <ID>` | Terminate a session |
| `rename <ID> <name>` / `rn <ID> <name>` | Assign a friendly name |
| `sysinfo <ID> [--stealth\|--full]` | Collect or refresh host information |
| `export <ID>` | Export an HTML session transcript |

### Plugins

| Command | Description |
|---------|-------------|
| `plugins` / `plugins list` | List registered plugins |
| `plugins list --verbose` | Show module paths and load state |
| `plugins load <name>` | Load an external plugin at runtime |
| `plugins unload <name>` | Disable or unload a plugin |
| `plugins reload <name>` | Reload a plugin module |
| `plugins info <name>` | Display plugin metadata |
| `run <plugin> <ID> [args...]` | Execute a plugin against a session |

### File transfer

| Command | Description |
|---------|-------------|
| `upload [--resume] <ID> <local> <remote>` | Upload with chunked transfer |
| `download [--resume] <ID> <remote> <local>` | Download with chunked transfer |
| `verify <ID> <remote>` / `hash <ID> <remote>` | Verify remote file size and SHA-256 |

### In-memory execution

| Command | Description |
|---------|-------------|
| `run inmemory <ID> <type> <local_file> [-- args] [--save-output <file>]` | Execute payload in memory |

Supported types: `py`, `ps`, `exe`, `elf`, `bat`, `sh`

### Network pivoting

| Command | In-session form | Description |
|---------|-----------------|-------------|
| `socks <ID> <listen_port>` | `socks <listen_port>` | Start a SOCKS5 proxy through a session (local listener on `127.0.0.1:<listen_port>`) |
| `socks <ID> test <host> <port>` | `socks test <host> <port>` | Test TCP reachability to an internal host through the tunnel agent |
| `socks <ID> reset` | `socks reset` | Reset tunnel agent streams and discard buffered data (does not stop active SOCKS listeners) |
| `socks stop <proxy_id>` | `socks stop <proxy_id>` | Stop a SOCKS proxy and clean up remote tunnel artifacts when no other proxy uses the session |
| `tunnels` | `tunnels` | List active SOCKS proxies, channel count, and status |

### General

| Command | Description |
|---------|-------------|
| `payloads` | Display the built-in payload reference |
| `help` | Show the command reference |
| `exit` / `quit` | Shut down the handler |

---

## Built-in Plugins

TornadoRevC2 ships with **43 built-in plugins** organized by function. All enumeration plugins are read-only unless noted otherwise.

### Host assessment & environment

| Plugin | Platform | Description |
|--------|----------|-------------|
| `quickenum` | Cross-platform | Fast structured host triage: identity, network, environment, prioritized findings |
| `virtualization` | Cross-platform | Virtualization, container, orchestration, and cloud environment detection |
| `kernel` | Cross-platform | Kernel version, loaded modules/drivers, security mitigations, and kernel configuration |
| `integrity` | Cross-platform | Secure Boot, BitLocker/LUKS, code-signing enforcement, kernel lockdown, and integrity protections |
| `filesearch` | Cross-platform | Search files by path, name, ext, size, owner, mtime (`run filesearch help` for options) |
| `packages` | Cross-platform | Installed software, package managers, repository configuration, and recent installs |
| `sysinfo` | Cross-platform | Host metadata collection (handler command, not a plugin) |

### Network & connectivity

| Plugin | Platform | Description |
|--------|----------|-------------|
| `firewall` | Cross-platform | Firewall status, profiles/zones, policies, and notable rules (WDF, UFW, firewalld, nftables, iptables) |
| `ports` | Cross-platform | Listening ports, established connections, owning processes, and routing |
| `proxy` | Cross-platform | System, environment, PAC/WPAD, and browser proxy settings |
| `vpn` | Cross-platform | VPN clients, active connections, adapters, and configuration metadata |

### Credentials, browsers & applications

| Plugin | Platform | Description |
|--------|----------|-------------|
| `credstore` | Cross-platform | Credential store metadata (no secret extraction): Credential Manager, keyrings, browser stores |
| `browser` | Cross-platform | Installed browsers, profiles, extensions, bookmarks, and enterprise policies |
| `clipboard` | Cross-platform | Remote clipboard text capture |
| `secrets` | Linux/Unix | Configuration files, environment variables, SSH keys, and cloud credentials |

### Host internals

| Plugin | Platform | Description |
|--------|----------|-------------|
| `history` | Cross-platform | Shell history, package/update logs, and recent login activity |
| `mounts` | Cross-platform | Mount points, SMB/NFS shares, mapped drives, container filesystems |
| `memorymap` | Cross-platform | Process memory maps and loaded modules for a specified PID |
| `screenshot` | Cross-platform | Desktop capture returned to the operator (GUI sessions; PNG saved locally) |
| `cron` | Linux/Unix | Cron jobs, system crontabs, user crontabs, and at queues |
| `systemd` | Linux/Unix | Services, timers, failed units, and enabled startup units |
| `privbins` | Linux/Unix | SUID/SGID binaries, file capabilities, and privilege-escalation-relevant executables |
| `lsm` | Linux/Unix | SELinux, AppArmor, and other Linux Security Modules: enforcement mode, policies, and configuration |
| `journal` | Linux/Unix | Structured journalctl summaries: authentication, kernel, service failures, and recent events |
| `containers` | Linux/Unix | Container runtimes and workloads: Docker, Podman, containerd, CRI-O, LXC/LXD, and Kubernetes indicators |
| `usersessions` | Cross-platform | Active local, remote, SSH, RDP, console, and service sessions with login/source metadata |

### Windows domain & system

| Plugin | Platform | Description |
|--------|----------|-------------|
| `adinfo` | Windows | Domain membership, domain controllers, forests, trusts, and OUs |
| `services` | Windows | Windows services, startup types, binaries, and service accounts |
| `scheduledtasks` | Windows | Scheduled tasks, triggers, execution context, and actions |
| `registry` | Windows | Autorun keys, startup locations, and installed software |
| `eventlogs` | Windows | Security, System, Application, and PowerShell log summaries |
| `defender` | Windows | Microsoft Defender status, exclusions, ASR rules, and third-party AV |
| `certificates` | Windows | Certificate stores, code-signing, and enterprise certificates |
| `rdp` | Windows | Remote Desktop configuration, status, recent targets, and settings |
| `gpo` | Windows | Applied GPOs, local/domain security policies, AppLocker, WDAC, SRP, and GPO scripts |
| `winrm` | Windows | WinRM configuration, listeners, authentication methods, firewall integration, and remoting status |
| `drivers` | Windows | Installed drivers and kernel modules, signed/unsigned status, startup type, and notable security/VM drivers |
| `powershell` | Windows | PowerShell version, execution policy, logging, modules, remoting settings, and profile paths |
| `lsa` | Windows | LSA protection, Credential Guard, virtualization-based security, and credential security configuration |

### Execution & operational

| Plugin | Platform | Description |
|--------|----------|-------------|
| `inmemory` | Cross-platform | In-memory payload execution (`py`, `ps`, `exe`, `elf`, `bat`, `sh`) |
| `nullcrypt` | Cross-platform | Hybrid encrypt a file (AES-GCM + RSA-wrapped key) then securely wipe the original via wiper |
| `wiper` | Cross-platform | Configurable multi-pass secure overwrite (rename, truncate, delete); profiles: quick, standard, dod, thorough, shred |
| `historydel` | Cross-platform | Clear current user shell history files and related storage |
| `eventlogdel` | Windows | Clear Windows Event Logs via native `wevtutil` / `Clear-EventLog` |

**In-memory execution methods:**

| Type | Method |
|------|--------|
| `py` | Python via `exec(compile(...))` |
| `ps` | PowerShell via `Invoke-Expression` |
| `exe` | Windows PE via in-memory RunPE (process hollowing) |
| `elf` | Linux ELF via `memfd_create` with `/dev/shm` fallback |
| `sh` | Shell script streamed via `bash -s` |
| `bat` | Batch script streamed via `cmd.exe /Q` stdin |

PEASS-ng scripts for in-memory privesccheck: [github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)

---

## Plugin Development

This section describes how to extend TornadoRevC2 with custom plugins. Plugins are plain Python modules that register commands with `@plugin.command` and receive a `SessionContext` for the target session. No changes to core handler code are required.

### Plugin system overview

The plugin system has four layers:

| Layer | Module | Responsibility |
|-------|--------|----------------|
| **Registration** | `plugins/api.py` | `@plugin.command` decorator, global command registry, `SessionContext` |
| **Discovery** | `plugins/loader.py` | Scans `shared/`, `linux/`, `windows/`, and external directories; imports modules |
| **Execution** | `plugins/manager.py` | Resolves platform, builds context, invokes handler, handles errors |
| **Collectors** | `plugins/shared/runner.py` | Marker parsing, JSON extraction, report formatting, logging |

At import time, the `@plugin.command` decorator registers each handler in a thread-safe global registry. At runtime, `PluginManager.run_plugin()` validates platform compatibility, constructs a `SessionContext`, and calls the handler with `(session, args)`.

Handlers return an integer exit code: `0` for success, non-zero for failure. The handler console displays warnings for non-zero returns.

### Plugin placement

Choose a location based on platform scope and whether the plugin ships with the project:

| Location | Scope | Loaded |
|----------|-------|--------|
| `tornadorevc2/plugins/shared/` | Cross-platform (internal Windows + Linux implementations) | Automatically at startup |
| `tornadorevc2/plugins/linux/` | Linux/Unix only | Automatically at startup |
| `tornadorevc2/plugins/windows/` | Windows only | Automatically at startup |
| `./plugins/myplugin.py` | External (any scope you define) | On demand via `plugins load` |
| `./plugins/myplugin/__init__.py` | External package | On demand via `plugins load` |
| Path in `TORNADOREVC2_PLUGIN_DIR` | External (custom directory) | On demand via `plugins load` |

**Layout rules:**

- Files named `common.py`, `runner.py`, and `__init__.py` under `shared/` are skipped during discovery.
- Files starting with `_` under `linux/` or `windows/` are helper modules, not plugins.
- **Shared plugins** must be a single module in `shared/` with internal platform branching—do not duplicate cross-platform plugins in both `shared/` and `linux/`/`windows/`.
- **Platform-specific plugins** (e.g. `rdp`, `eventlogdel`) belong exclusively in `windows/` or `linux/`.

### Registration

Register a command with the `@plugin.command` decorator:

```python
from tornadorevc2.plugins import plugin, SessionContext

@plugin.command(
    name="myplugin",                          # Command name used with `run myplugin <ID>`
    platforms=["linux", "windows", "unix"],   # Supported session platforms
    description="Short description for plugins list and TAB completion",
)
def run(session: SessionContext, args):
    ...
    return 0  # 0 = success, non-zero = failure
```

**Platform values:** `linux`, `windows`, `unix`. Linux and `unix` are treated as compatible— a plugin registered for `linux` runs on both. Default if omitted: `["linux", "windows", "unix"]`.

**Multiple commands per module:** A single file may register several commands by applying `@plugin.command` to multiple functions. Each gets an independent name.

### Execution lifecycle

When an operator runs `run myplugin 1 arg1 arg2`:

```text
1. PluginManager resolves session #1 and looks up "myplugin" in the registry
2. Platform check: plugin.platforms vs session shell type (unix/windows)
3. SessionContext(handler, client_socket) is constructed
4. Handler invoked: run(ctx, ["arg1", "arg2"])
5. Handler executes remote work via run_shell / run_marked / run_collector_plugin
6. Output printed to operator console; results logged under logs/<session>/plugins/
7. Exit code returned (0 = success)
```

Inside an attached session (`switch <ID>`), the session ID is omitted and args start immediately after the plugin name: `run myplugin arg1 arg2`.

### Pattern 1: Simple shell plugin

Use when you need a quick one-off command without structured JSON parsing. The handler runs a native shell command, prints output, and logs the result.

```python
from tornadorevc2.plugins import plugin, SessionContext

@plugin.command(
    name="whoami",
    platforms=["linux", "windows", "unix"],
    description="Print remote user identity",
)
def run(session: SessionContext, args):
    session.log_event("Plugin whoami: started")

    if session.is_windows:
        cmd = "whoami /all"
    else:
        cmd = "id 2>/dev/null || whoami"

    output = session.run_shell(cmd, timeout=10.0)
    if not output.strip():
        session.print("Plugin 'whoami' failed — no output from target.", "red")
        session.log_plugin_result("whoami", "", "no output")
        return 1

    report = output.strip()
    session.print(report, "cyan")
    session.log_plugin_result("whoami", report)
    session.log_command("run whoami", report)
    return 0
```

**When to use:** Simple probes, one-liner enumeration, commands that do not need structured reports.

**Key methods:** `session.run_shell(cmd, timeout)`, `session.print(text, color)`, `session.log_plugin_result(name, report, detail='')`.

### Pattern 2: Structured collector (recommended)

Use for enumeration plugins that gather structured data on the target and return a formatted report. This is the pattern used by all built-in reconnaissance plugins (`firewall`, `ports`, `browser`, etc.).

**Flow:**

```text
Handler                              Target host
  │                                       │
  ├─ session.log_event("started")         │
  ├─ flush shell buffer                   │
  ├─ resolve platform (unix/windows)      │
  ├─ build collector command/script ─────►│  Linux: inline Python or native shell
  │                                       │  Windows: PowerShell script in-process
  │                                       ├─ invoke native OS commands
  │                                       ├─ assemble result dict
  │                                       └─ emit __T_PLUGIN_START__ + JSON + __T_PLUGIN_END__
  │◄──────────────────────────────────────┤
  ├─ parse_collector_json(raw)            │
  ├─ formatter(data) → report string      │
  ├─ session.print(report)                │
  └─ session.log_plugin_result(...)       │
```

**Minimal cross-platform example:**

```python
from tornadorevc2.plugins import plugin, SessionContext
from tornadorevc2.plugins.linux._helpers import build_linux_collector_command
from tornadorevc2.plugins.shared.common import format_generic_report
from tornadorevc2.plugins.shared.runner import run_collector_plugin
from tornadorevc2.constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def _linux_collector_source():
    # Runs inside a try/except wrapper on the target.
    # Call _emit(result) with a JSON-serializable dict — do NOT print markers yourself.
    return r'''
import subprocess
result = {'summary': {}, 'processes': []}
try:
    out = subprocess.check_output(['ps', 'auxww'], stderr=subprocess.STDOUT, timeout=10)
    lines = out.decode('utf-8', errors='replace').splitlines()
    result['summary'] = {'count': max(0, len(lines) - 1)}
    result['processes'] = lines[1:51]
except Exception as exc:
    result['summary'] = {'error': str(exc)}
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$procs = Get-CimInstance Win32_Process -EA 0 |
  Select-Object -First 50 ProcessId, Name, CommandLine
$result = [ordered]@{{
  summary = @{{ count = @($procs).Count }}
  processes = @($procs)
}}
Write-Output ($start + (ConvertTo-Json $result -Depth 4 -Compress) + $end)
"""


@plugin.command(
    name="processes",
    platforms=["linux", "windows", "unix"],
    description="List running processes on the remote host",
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        "processes",
        _build_linux_command,       # callable — built at execution time
        _build_windows_command,     # callable — built at execution time
        format_generic_report,      # turns parsed dict into operator-facing text
        timeout=25.0,               # seconds to wait for marked output
    )
```

**`run_collector_plugin` parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `SessionContext` | Target session |
| `plugin_name` | `str` | Name used in logs and error messages |
| `unix_builder` | `Callable[[], str]` or `None` | Returns the Unix/Linux shell command; `None` if unavailable |
| `win_builder` | `Callable[[], str]` or `None` | Returns the PowerShell script; `None` if unavailable |
| `formatter` | `Callable[[dict], str]` | Converts parsed JSON dict to a report string |
| `timeout` | `float` | Maximum seconds to wait for marked output (default 30) |

Pass `None` for a platform builder to mark the plugin unavailable on that OS (see [Platform-specific plugins](#platform-specific-plugins)).

After saving an external plugin:

```bash
plugins load processes
plugins info processes
run processes 1
```

### Pattern 3: Custom handler

Use when you need argument validation, dynamic collector construction, post-collector processing, or operator-side file handling that `run_collector_plugin` does not cover alone.

**Examples in the codebase:**

| Plugin | Custom behavior |
|--------|-----------------|
| `memorymap` | Requires PID argument; builds collector dynamically with embedded PID |
| `wiper` | Requires remote path; destructive action with confirmation output |
| `screenshot` | Decodes base64 image and saves PNG locally on the operator machine |
| `historydel` | Runs collector, then sends follow-up shell command for in-memory history cleanup |
| `clipboard` | Custom soft-failure handling via `reason` field instead of hard `error` |

**Argument validation example** (from `memorymap`):

```python
import re
from tornadorevc2.plugins import plugin, SessionContext
from tornadorevc2.plugins.shared.runner import _run_collector_marked, parse_collector_json

@plugin.command(
    name="memorymap",
    platforms=["linux", "windows", "unix"],
    description="Enumerate memory maps for a process (requires PID)",
)
def run(session: SessionContext, args):
    if not args or not re.match(r"^\d+$", args[0].strip()):
        session.print("Usage: run memorymap <ID> <pid>", "yellow")
        return 1

    pid = args[0].strip()
    session.log_event(f"Plugin memorymap: started for PID {pid}")
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    unix_cmd = _build_linux_command(pid)   # builder accepts runtime args
    win_ps = _build_windows_command(pid)

    raw = _run_collector_marked(session, unix_cmd, win_ps, session.platform, 45.0)
    if raw is None:
        session.print("Plugin 'memorymap' failed — no response from target.", "red")
        return 1

    data = parse_collector_json(raw)
    report = format_memorymap_report(data)
    session.print(report, "cyan")
    session.log_plugin_result("memorymap", report, ...)
    return 0
```

**Post-collector processing example** (from `historydel`):

```python
def run(session: SessionContext, args):
    # ... run collector via _run_collector_marked ...
    data = parse_collector_json(raw)

    # Additional in-memory cleanup in the interactive shell
    if session.is_unix:
        session.run_shell("history -c 2>/dev/null; history -w 2>/dev/null; true", timeout=5.0)
    elif session.is_windows:
        session.run_marked("", "Clear-History -ErrorAction SilentlyContinue", timeout=5.0)

    report = format_historydel_report(data)
    session.print(report, "green" if data.get("cleared") else "yellow")
    return 0
```

For direct access to marked execution without the full collector wrapper, use `_run_collector_marked` and `parse_collector_json` from `plugins/shared/runner.py`.

### Linux collectors

Linux collectors are Python source strings executed on the target via `build_linux_collector_command()`.

**Structure:**

1. Define `_linux_collector_source()` returning a raw string (`r'''...'''`).
2. Write collector logic that builds a `result` dict.
3. Call `_emit(result)` at the end — never print markers manually.
4. Wrap with `_build_linux_command()` → `build_linux_collector_command(source)`.

The wrapper in `linux/_helpers.py` automatically:

- Indents your source inside a `try/except` block
- Defines `_emit(obj)` to write `__T_PLUGIN_START__` + JSON + `__T_PLUGIN_END__`
- Emits `{"error": "...", "traceback": "..."}` on unhandled exceptions
- Encodes the script for inline execution via `python3 -c` (or `python2` fallback)
- Falls back to chunked `/tmp` staging only when the encoded payload exceeds ~4000 bytes

**Prefer native commands:**

```python
def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode("utf-8", "ignore")
    except Exception:
        return ""

result = {"summary": {}, "ports": []}
output = sh("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null", 10)
for line in output.splitlines()[:60]:
    result["ports"].append(line.strip())
_emit(result)
```

**Guidelines:**

- Use `subprocess.check_output(..., timeout=N)` for every external command.
- Trim large lists before emitting (cap at 50–80 entries).
- Handle missing tools gracefully—leave sections empty rather than raising.
- Avoid embedding marker strings in output; the `history` plugin scrubs `__T_PLUGIN_*__` from collected text for this reason.
- Keep collectors compact to stay under the inline size limit and avoid `/tmp` staging.

### Windows collectors

Windows collectors are PowerShell script strings returned from `_build_windows_command()`.

**Structure:**

```python
from tornadorevc2.constants import PLUGIN_MARK_END, PLUGIN_MARK_START

def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$result = [ordered]@{{
  summary = @{{ count = 0 }}
  items = @()
}}
try {{
  Get-CimInstance Win32_Service -EA 0 | Select-Object -First 50 | ForEach-Object {{
    $result.items += @{{ name = $_.Name; state = $_.State }}
  }}
  $result.summary.count = $result.items.Count
}} catch {{
  $result.summary.error = $_.Exception.Message
}}
Write-Output ($start + (ConvertTo-Json $result -Depth 5 -Compress) + $end)
"""
```

**Guidelines:**

- Always set `$ErrorActionPreference='SilentlyContinue'` at the top.
- Use `-EA 0` (ErrorAction SilentlyContinue) on cmdlets that may fail on older systems.
- Brace-doubling is required inside Python f-strings and raw f-strings: `{{` and `}}` for PowerShell hashtables and script blocks.
- Use `[ordered]@{{...}}` to preserve key order in JSON output.
- Prefer built-in cmdlets (`Get-NetTCPConnection`, `Get-Process`, `netsh`, `wevtutil`) over external tools.
- Wrap each logical section in its own `try/catch` so one failure does not abort the entire collector.
- On interactive PowerShell sessions, scripts are delivered in-process via `win_client.py` for reliable output capture.

**Alternative:** For Windows-only plugins with minimal entry points, use a single `build_command()` function:

```python
# tornadorevc2/plugins/windows/services.py
@plugin.command(name="services", platforms=["windows"], description="...")
def run(session: SessionContext, args):
    return run_collector_plugin(session, "services", None, build_command, format_generic_report, timeout=35.0)
```

### JSON payload conventions

Collectors should return a JSON-serializable dict. The runner and formatters expect consistent key usage:

| Key | Type | Purpose |
|-----|------|---------|
| `summary` | `dict` | High-level counts and stats; rendered first by `format_generic_report()` |
| `error` | `str` | **Hard failure** — runner prints error and returns exit code 1 |
| `traceback` | `str` | Optional; logged as detail when `error` is set |
| `reason` | `str` | **Soft failure** — use with custom formatters (e.g. clipboard unavailable) |
| `ok` | `bool` | Success flag for operational plugins (screenshot, clipboard) |
| Lists of `dict` | `list` | Rendered as tables by `format_generic_report()` |
| Lists of `str` | `list` | Rendered as bullet lists |
| Nested `dict` | `dict` | Rendered as labeled sections |

**Graceful degradation:** For multi-section enumeration, use separate dict keys per section and catch exceptions locally. Do not set top-level `error` unless the entire collector failed—partial results are preferable.

```python
result = {"summary": {}, "ufw": {}, "iptables": {}}
# Each backend probed independently; failures leave that section empty
```

### Custom formatters

Pass a custom formatter to `run_collector_plugin` instead of `format_generic_report`:

```python
from tornadorevc2.plugins.shared.common import format_section, format_list_section

def format_firewall_report(data: dict) -> str:
    sections = []
    summary = data.get("summary") or {}
    if summary:
        sections.append(format_section("Summary", summary))
    for key in ("ufw", "iptables", "windows_defender_firewall"):
        block = data.get(key)
        if isinstance(block, dict) and block:
            sections.append(format_section(key.replace("_", " ").title(), block))
    if not sections:
        return "Firewall: no data collected."
    return "\n\n".join(sections)
```

Reusable helpers in `plugins/shared/common.py`:

| Function | Purpose |
|----------|---------|
| `format_generic_report(data, title='Results')` | Default table/section renderer |
| `format_section(title, fields, width=22)` | Key-value section |
| `format_list_section(title, items, empty='(none)')` | Bulleted list |
| `format_table_section(title, rows, columns)` | Dict rows as columns |
| `format_firewall_report`, `format_memorymap_report`, etc. | Plugin-specific formatters |

### Platform-specific plugins

**Windows-only:**

```python
@plugin.command(name="rdp", platforms=["windows"], description="...")
def run(session: SessionContext, args):
    return run_collector_plugin(
        session, "rdp",
        None,                    # no Linux builder
        build_command,
        format_generic_report,
        timeout=35.0,
    )
```

**Linux-only:**

```python
@plugin.command(name="cron", platforms=["linux", "unix"], description="...")
def run(session: SessionContext, args):
    return run_collector_plugin(
        session, "cron",
        build_linux_command,
        None,                    # no Windows builder
        format_generic_report,
        timeout=30.0,
    )
```

**Cross-platform with split builders:**

Some shared plugins delegate to platform-specific builder modules (e.g. `virtualization` imports from `linux/virtualization.py` and `windows/virtualization.py`). The `@plugin.command` entry point stays in `shared/`; builder modules under `linux/` or `windows/` contain no decorator and are not registered as independent plugins.

### External plugins

External plugins let you extend TornadoRevC2 without modifying the repository.

**Setup:**

```bash
# Default location (created automatically if missing)
./plugins/myplugin.py

# Or set a custom directory
export TORNADOREVC2_PLUGIN_DIR=/path/to/my/plugins
```

**Workflow:**

```bash
# From the handler console
plugins load myplugin          # import and register commands
plugins info myplugin          # verify name, platforms, description, module path
run myplugin 1                 # execute against session 1
run myplugin 1 --verbose       # extra args passed to handler as args=["--verbose"]
plugins reload myplugin        # re-import after editing (clears stale registrations)
plugins unload myplugin        # fully unload external plugin
```

**External vs built-in lifecycle:**

| Action | Built-in plugin | External plugin |
|--------|-----------------|-----------------|
| `plugins unload` | Soft-disabled (module stays imported) | Fully unloaded and unregistered |
| `plugins reload` | Re-imports module, clears stale command registrations | Removes from `sys.modules`, re-imports from disk |
| Startup | Auto-loaded | Loaded on demand |

External modules are imported as `tornado_ext_plugin_<name>` to avoid namespace collisions.

### SessionContext API

Every handler receives a `SessionContext` wrapping the handler and client socket:

**Metadata properties:**

| Property | Type | Description |
|----------|------|-------------|
| `session_id` | `str` | Assigned session identifier |
| `platform` | `str` | `unix`, `windows`, or `unknown` |
| `is_windows` / `is_unix` | `bool` | Platform convenience flags |
| `sysinfo` | `dict` | Cached host information from `sysinfo` collection |
| `identity` | `dict` | Session identity/fingerprint metadata |
| `addr` | `tuple` | Remote address |
| `tls` | `bool` | Whether session uses TLS |
| `name` | `str` | Operator-assigned friendly name |
| `fingerprint` | `str` | Stable host fingerprint |
| `logger` | `SessionLogger` | Per-session log writer (may be `None`) |
| `colors` | `dict` | Console color codes |
| `socket` | socket | Raw client socket (advanced use) |

**Execution methods:**

| Method | Description |
|--------|-------------|
| `run_shell(cmd, timeout=15.0)` | Send command, wait for output, return string |
| `run_shell_streaming(cmd, timeout, idle_timeout, on_chunk)` | Stream output with idle detection; useful for long-running commands |
| `run_marked(unix_cmd, win_ps_script, timeout, start_mark, end_mark, strip_ws)` | Execute platform-appropriate command and extract marked payload |
| `get_cwd()` | Return remote working directory |
| `collect_sysinfo(mode='stealth')` | Trigger host info collection |

**Transfer methods:**

| Method | Description |
|--------|-------------|
| `upload(local_path, remote_path, resume=False)` | Upload file to target |
| `download(remote_path, local_path, resume=False)` | Download file from target |
| `verify_remote(remote_path)` | Verify remote file size and SHA-256 |

**Logging and output:**

| Method | Description |
|--------|-------------|
| `print(text, color=None)` | Print to operator console with optional color (`red`, `green`, `yellow`, `cyan`) |
| `log_event(message)` | Append timestamped event to `session.log` |
| `log_command(cmd, output)` | Log command and output to `session.log` |
| `log_plugin_result(name, report, detail='')` | Write report to `logs/<session>/plugins/<name>_<timestamp>.log` |

### Error handling & return codes

| Return | Meaning | Handler behavior |
|--------|---------|------------------|
| `0` | Success | No warning displayed |
| `1` (or any non-zero) | Failure | Yellow warning: `Plugin 'name' returned code N` |
| Uncaught exception | Error | Red error message; logged to session log |

**Collector failure modes** (handled by `run_collector_plugin`):

| Condition | Behavior |
|-----------|----------|
| Timeout / no markers in output | Exit 1, log "no response" |
| Output not valid JSON | Exit 1, log raw output (truncated) as detail |
| `data["error"]` present | Exit 1, print error and traceback |
| Partial section failures | Should **not** set top-level `error`; leave section empty |

**Soft failures** (operational plugins): Use `reason` or `ok: false` and handle in a custom formatter or custom handler rather than relying on the runner's hard `error` check.

### Best practices

1. **Prefer native OS commands** over uploaded tooling—aligns with the framework's dependency-light design.
2. **Do not write files on the target** for enumeration; return data over the shell channel. Operational plugins (wiper, historydel) are exceptions with clear purpose.
3. **Degrade gracefully** — probe each backend independently; empty sections beat total failure.
4. **Cap output size** — trim lists to 50–80 items; truncate long strings to 200–500 characters.
5. **Set realistic timeouts** — quick probes: 15–30s; comprehensive enumeration: 45–75s.
6. **Log consistently** — call `session.log_event()` at start, `session.log_plugin_result()` on completion, `session.log_command()` for transcript export.
7. **Validate args early** — return 1 with usage message before sending anything to the target.
8. **Test from both consoles** — main handler (`run plugin <ID>`) and attached session (`switch` then `run plugin`).
9. **Use `plugins reload`** during development to pick up changes without restarting the handler.
10. **Scrub sensitive markers** from collected output if your plugin reads arbitrary file content.

### Reference implementations

| Plugin | File | Pattern | Notes |
|--------|------|---------|-------|
| `firewall` | `plugins/shared/firewall.py` | Cross-platform collector | Multi-backend graceful degradation |
| `ports` | `plugins/shared/ports.py` | Cross-platform collector | Native `ss` / `Get-NetTCPConnection` |
| `history` | `plugins/shared/history.py` | Cross-platform collector | Linux Python + Windows PowerShell builders |
| `memorymap` | `plugins/shared/memorymap.py` | Custom handler | PID argument, dynamic builder |
| `screenshot` | `plugins/shared/screenshot.py` | Custom handler | Base64 in JSON; operator-side PNG save |
| `clipboard` | `plugins/shared/clipboard.py` | Custom handler | Soft failure via `reason` field |
| `historydel` | `plugins/shared/historydel.py` | Custom handler | Destructive; post-collector shell cleanup |
| `wiper` | `plugins/shared/wiper.py` | Custom handler | Destructive; path argument validation |
| `services` | `plugins/windows/services.py` | Windows-only collector | Minimal entry point |
| `eventlogdel` | `plugins/windows/eventlogdel.py` | Windows-only collector | Destructive; per-log failure reporting |
| `rdp` | `plugins/windows/rdp.py` | Windows-only collector | Registry and firewall enumeration |
| `virtualization` | `plugins/shared/virtualization.py` | Shared entry + split builders | Imports `linux/` and `windows/` builders |
| `secrets` | `plugins/linux/secrets.py` | Linux-only collector | Platform-restricted listing |

For new enumeration plugins, start from `run_collector_plugin` in `plugins/shared/runner.py` and copy the layout from `firewall.py` or `ports.py`. For plugins with arguments or side effects, refer to `memorymap.py` or `wiper.py`.

---

## Session Logging

Each session writes to an isolated directory under `logs/`:

```text
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log           Operator commands and console output
  sysinfo.json          Host information snapshot
  transfers/            Upload and download event logs
  executions/           In-memory payload execution metadata
  plugins/              Plugin reports and collector output
      quickenum_20260812_054812.log
      firewall_20260812_055130.log
      screenshot_20260812_055412.png
```

Plugin logs contain a human-readable report and, when applicable, the raw JSON payload returned by the remote collector.

---

## Project Structure

```text
TornadoRevC2/
├── tornadorevc2.py                 Entry point
├── tornadorevc2/
│   ├── handler.py                  Listeners, sessions, operator console
│   ├── sysinfo.py                  Host information collection
│   ├── terminal.py                 PTY/TTY management
│   ├── transfer.py                 Chunked file transfers
│   ├── tunnel.py                   SOCKS5 pivoting
│   ├── win_client.py               Windows shell detection and script delivery
│   ├── session_registry.py         Session persistence and reconnect logic
│   ├── session_log.py              Per-session directory logging
│   ├── export.py                   HTML transcript export
│   ├── payloads.py                 Built-in payload catalog
│   └── plugins/
│       ├── api.py                  SessionContext and plugin registration
│       ├── manager.py              Plugin lifecycle and execution
│       ├── loader.py               Module discovery
│       ├── shared/                 Cross-platform plugins
│       ├── linux/                  Linux/Unix-only plugins
│       └── windows/                Windows-only plugins
├── plugins/                        Optional external plugin directory
└── logs/                           Session output (created at runtime)
```

---

## TLS Configuration

Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

Start with explicit TLS material:

```bash
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

For production engagements, use credentials issued by your organization's PKI or certificate authority.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
