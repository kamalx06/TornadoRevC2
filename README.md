# TornadoRevC2

**TornadoRevC2** is a Python-based reverse shell handler designed for authorized security research, red-team engagements, malware analysis, and penetration testing. It provides an operator-focused console for managing interactive sessions on Linux and Windows hosts, with built-in support for encrypted transport, file transfer, in-memory execution, network pivoting, and extensible host enumeration.

> **Scope:** TornadoRevC2 is a session handler—not a beacon-style command-and-control framework. It prioritizes reliable interactive shells, structured operator workflows, and on-demand enumeration through a modular plugin system.

**Primary targets:** Linux and Windows  
**Secondary support:** Generic Unix and BSD environments where applicable

---

## Legal Notice

Use this software only on systems you own or on systems where you have **explicit written authorization**. You are solely responsible for compliance with applicable laws and organizational policies. The authors and contributors accept no liability for misuse, data loss, or legal consequences arising from the use of this project.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Operator Reference](#operator-reference)
- [Core Capabilities](#core-capabilities)
- [Plugin System](#plugin-system)
- [Built-in Plugins](#built-in-plugins)
- [Session Logging](#session-logging)
- [Project Structure](#project-structure)
- [TLS Configuration](#tls-configuration)
- [License](#license)

---

## Overview

TornadoRevC2 accepts inbound reverse shell connections over plain TCP or TLS and exposes a unified operator interface for session management, host reconnaissance, file operations, and post-exploitation tasks.

| Capability | Status |
|------------|--------|
| Multi-client TCP and TLS listeners | Supported |
| Interactive PTY/TTY sessions | Supported |
| Chunked file transfer with resume | Supported |
| SHA-256 file integrity verification | Supported |
| In-memory payload execution | Supported |
| SOCKS5 pivoting through sessions | Supported |
| Session fingerprinting and reconnect tracking | Supported |
| Runtime plugin loading and reload | Supported |
| Automated persistence or task scheduling | Not supported |

---

## Requirements

- **Python** 3.7 or later
- **OpenSSL** (for TLS certificate generation)
- **No third-party Python packages** required for the core handler

Optional on target hosts (depending on plugin and feature usage):

- Python 2/3, PowerShell, or standard Unix utilities for collectors
- `wl-clipboard`, `xclip`, or `xsel` for clipboard enumeration on Linux graphical sessions

---

## Installation

Clone the repository and run the handler directly—no package installation step is required.

```bash
git clone <repository-url>
cd TornadoRevC2
python tornadorevc2.py
```

---

## Quick Start

### Start the handler

```bash
# Default: TCP listener on port 4444, TLS listener on port 8443
python tornadorevc2.py

# Custom bind address, ports, and TLS material
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

### Establish a session

Deploy a reverse shell payload from the built-in catalog (`payloads` command) or use your own implant. When a client connects, TornadoRevC2 assigns a session ID and begins logging activity under `logs/`.

### Typical workflow

```bash
status                          # List active sessions
switch 1                        # Attach to session 1
sysinfo 1                       # Collect host information
run quickenum 1                 # Fast structured triage
run history 1                   # Shell history and login activity
run mounts 1                    # Mounts, shares, and filesystem layout
run privesccheck 1 ./linpeas.sh # Privilege escalation scan (operator-supplied script)
```

When attached to a session via `switch <ID>`, omit the session ID from commands that normally require one (for example, `run quickenum` instead of `run quickenum 1`).

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
| `rename <ID> <name>` / `rn <ID> <name>` | Assign a friendly name to a session |
| `sysinfo <ID> [--stealth\|--full]` | Collect or refresh host information |
| `export <ID>` | Export an HTML session transcript |

### Plugins

| Command | Description |
|---------|-------------|
| `plugins` / `plugins list` | List registered plugins |
| `plugins list --verbose` | Show module paths and load state |
| `plugins load <name>` | Load a plugin at runtime |
| `plugins unload <name>` | Disable or unload a plugin |
| `plugins reload <name>` | Reload a plugin module |
| `plugins info <name>` | Display plugin metadata |
| `run <plugin> <ID> [args...]` | Execute a plugin against a session |

### File transfer

| Command | Description |
|---------|-------------|
| `upload [--resume] <ID> <local> <remote>` | Upload a file with chunked transfer |
| `download [--resume] <ID> <remote> <local>` | Download a file with chunked transfer |
| `verify <ID> <remote>` / `hash <ID> <remote>` | Verify remote file size and SHA-256 |

Inside an attached shell, omit `<ID>` from transfer commands.

### In-memory execution

| Command | Description |
|---------|-------------|
| `runpy <ID> <local.py> [-- args] [--save-output <file>]` | Execute Python from memory |
| `runps <ID> <local.ps1> [--save-output <file>]` | Execute PowerShell from memory |
| `runexe <ID> <local.exe> [-- args] [--save-output <file>]` | Execute a Windows PE with output capture |
| `runelf <ID> <local_binary> [-- args] [--save-output <file>]` | Execute a Linux ELF via `memfd_create` |

### Network pivoting

| Command | Description |
|---------|-------------|
| `socks <ID> <listen_port>` | Start a SOCKS5 proxy through a session |
| `socks stop <proxy_id>` | Stop a proxy and clean up remote artifacts |
| `tunnels` | List active SOCKS proxies |

When the last SOCKS proxy for a session is stopped, or when the session disconnects, TornadoRevC2 terminates the remote tunnel agent and removes associated staging files.

### General

| Command | Description |
|---------|-------------|
| `payloads` | Display the built-in payload reference |
| `help` | Show the command reference |
| `exit` / `quit` | Shut down the handler |

---

## Core Capabilities

### Listeners

Plain TCP and TLS listeners operate concurrently. The TLS listener enforces TLS 1.2 or later and accepts configurable certificate and key paths.

### Session management

Sessions are tracked with stable fingerprinting derived from host identity signals. Reconnecting clients can be mapped to prior session metadata, log directories, and collected sysinfo. All session state mutations are guarded for thread-safe multi-operator use.

### Host information

The `sysinfo` command collects host metadata on demand. Stealth mode (default) minimizes remote footprint; `--full` expands collection breadth for deeper baseline enumeration.

### File transfer

Uploads and downloads use chunked I/O with SHA-256 verification. The `--resume` flag allows interrupted transfers to continue from the last confirmed offset.

### In-memory execution

Payloads are staged and executed in memory where supported, with optional stdout/stderr capture to a local file. Temporary artifacts are cleaned up after Windows PE execution.

```bash
runexe 1 C:\tools\payload.exe -- --flag value
runexe 1 beacon.exe --save-output C:\local\output.txt
```

### SOCKS5 pivoting

Route operator tooling through a compromised host to reach otherwise unreachable internal networks. Remote cleanup is performed automatically when proxies are stopped or sessions drop.

### Session export

Generate HTML transcripts of operator activity for reporting, peer review, or engagement documentation.

---

## Plugin System

Plugins extend TornadoRevC2 at runtime without modifying core handler code. Built-in plugins ship under `tornadorevc2/plugins/`. External plugins may be placed in a top-level `plugins/` directory or loaded from a custom path via the `TORNADOREVC2_PLUGIN_DIR` environment variable.

### Discovery and lifecycle

- Built-in modules are discovered automatically at handler startup.
- External modules are loaded on demand with `plugins load <name>`.
- Built-in plugins are **soft-disabled** by `plugins unload` (the module remains imported).
- External plugins are **fully unloaded** and unregistered.
- `plugins reload` removes stale command registrations before re-importing, preventing orphaned entries after renames.

### Architecture

Cross-platform plugins follow a consistent layout:

```text
tornadorevc2/plugins/
  shared/          # Cross-platform entry points (history, mounts, clipboard, quickenum, …)
  linux/           # Linux/Unix collector builders
  windows/         # Windows collector builders
  api.py           # SessionContext and @plugin.command registration
  manager.py       # Runtime loading and execution
  loader.py        # Module discovery
```

Collectors emit JSON wrapped in marker tokens (`__T_PLUGIN_START__` / `__T_PLUGIN_END__`). The shared runner parses this output, formats a report, and persists results under the session log directory.

On Windows, plugin scripts are delivered in-process on PowerShell interactive sessions to ensure collector output returns reliably over the reverse shell channel.

### Writing a custom plugin

Register a handler with the `@plugin.command` decorator:

```python
from tornadorevc2.plugins import plugin, SessionContext

@plugin.command(
    name="myplugin",
    platforms=["linux", "windows", "unix"],
    description="Custom enumeration plugin",
)
def run(session: SessionContext, args):
    output = session.run_shell("whoami")
    session.print(output, "cyan")
    session.log_plugin_result("myplugin", output)
    return 0
```

Place the module in `./plugins/myplugin.py`, then:

```bash
plugins load myplugin
run myplugin 1
```

#### SessionContext API

| Category | Methods / Properties |
|----------|----------------------|
| Metadata | `session_id`, `platform`, `sysinfo`, `identity`, `addr`, `tls`, `name` |
| Execution | `run_shell()`, `run_shell_streaming()`, `run_marked()` |
| Transfer | `upload()`, `download()`, `verify_remote()` |
| Logging | `log_event()`, `log_command()`, `log_plugin_result()` |
| Host info | `collect_sysinfo()`, `get_cwd()` |
| Output | `print(text, color)` |

For structured JSON collectors, use `run_collector_plugin` from `tornadorevc2.plugins.shared.runner` with platform-specific command builders. See `tornadorevc2/plugins/shared/history.py` or `tornadorevc2/plugins/windows/services.py` for reference implementations.

---

## Built-in Plugins

### Cross-platform

| Plugin | Description |
|--------|-------------|
| `quickenum` | Fast structured host assessment: identity, network, environment, and prioritized findings |
| `virtualization` | Virtualization, container, orchestration, and cloud environment detection |
| `history` | Shell history, package/update logs, and recent login activity |
| `mounts` | Mount points, SMB/NFS shares, mapped drives, and container-related filesystems |
| `clipboard` | Remote clipboard text capture |
| `privesccheck` | LinPEAS / WinPEAS execution (operator-supplied script) |
| `wiper` | Multi-pass secure file overwrite followed by deletion |

### Linux / Unix

| Plugin | Description |
|--------|-------------|
| `secrets` | Configuration files, environment variables, SSH keys, and cloud credentials |
| `cron` | Cron jobs, system crontabs, user crontabs, and at queues |
| `systemd` | Services, timers, failed units, and enabled startup units |

### Windows

| Plugin | Description |
|--------|-------------|
| `adinfo` | Domain membership, domain controllers, forests, trusts, and OUs |
| `services` | Windows services, startup types, binaries, and service accounts |
| `scheduledtasks` | Scheduled tasks, triggers, execution context, and actions |
| `registry` | Autorun keys, startup locations, and installed software |
| `eventlogs` | Security, System, Application, and PowerShell log summaries |
| `defender` | Microsoft Defender status, exclusions, ASR rules, and third-party AV |
| `certificates` | Certificate stores, code-signing, and enterprise certificates |

---

## Plugin Reference

### QuickEnum

Single round-trip host triage that aggregates signals from virtualization detection, credential artifacts, services, and network configuration.

```bash
run quickenum 1
```

**Linux / Unix coverage:** hostname, user context, privilege indicators, kernel details, container and cloud metadata, network configuration, mounts, persistence mechanisms, and credential artifacts.

**Windows coverage:** hostname, user and admin status, domain context, network configuration, mounts and shares, services, Defender status, autoruns, and credential artifacts.

### History

Collects command history and login-related activity from the target host.

```bash
run history 1
```

**Linux / Unix:** bash/zsh history files, package manager logs, and recent logins via `last`.

**Windows:** PSReadLine history, Run MRU registry entries, CBS/DISM log tails, and `quser` output.

### Mounts

Enumerates filesystem layout, network shares, and storage-related configuration.

```bash
run mounts 1
```

**Linux / Unix:** `/proc/mounts`, NFS exports, Samba share definitions, and container-related mount points.

**Windows:** logical disks, SMB mappings, local shares, and WMI share metadata.

### Clipboard

Reads text from the remote clipboard.

```bash
run clipboard 1
```

**Windows:** `System.Windows.Forms.Clipboard` with `Get-Clipboard` fallback.  
**Linux / Unix:** `wl-paste`, `xclip`, or `xsel` (requires a graphical session).

### Privilege Escalation Check

Executes operator-supplied LinPEAS or WinPEAS scripts against the target. Scripts are not bundled with TornadoRevC2.

```bash
run privesccheck 1 ./linpeas.sh
run privesccheck 2 C:\tools\winPEAS.bat
```

| Platform | Accepted formats | Execution method |
|----------|------------------|------------------|
| Linux / Unix | `.sh` | Piped into `bash` stdin; large scripts may stage in `/dev/shm` |
| Windows | `.bat`, `.cmd`, `.exe` | PowerShell decode or staged binary with cleanup |

Download scripts from [PEASS-ng](https://github.com/carlospolop/PEASS-ng).

### Wiper

Performs a three-pass overwrite (zeros, ones, random) with flush between passes, then deletes the target file.

```bash
run wiper 1 /tmp/exfil.log
run wiper 2 C:\Users\Public\staging.dat
```

Multi-pass overwrite provides strong assurance on traditional HDDs. On SSD and NVMe media, wear leveling may retain data in remapped blocks not accessible to the operating system. For high-assurance sanitization on solid-state media, use full-disk encryption, vendor secure-erase utilities, or physical destruction.

### Virtualization

Multi-layer detection of virtual machines, containers, and cloud instances with weighted confidence scoring. For a condensed summary, use `run quickenum <ID>` instead.

```bash
run virtualization 1
```

---

## Session Logging

Each session writes to an isolated directory under `logs/`:

```text
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log         # Operator commands and console output
  sysinfo.json        # Host information snapshot
  transfers/          # Upload and download event logs
  executions/         # In-memory payload execution metadata
  plugins/            # Plugin reports and structured collector output
      quickenum_20260812_054812.log
      history_20260812_055130.log
      mounts_20260812_055245.log
```

Plugin logs contain a human-readable report and, when applicable, the raw JSON payload returned by the remote collector.

---

## Project Structure

```text
TornadoRevC2/
├── tornadorevc2.py              # Handler entry point
├── tornadorevc2/
│   ├── handler.py               # Listeners, sessions, and operator console
│   ├── sysinfo.py               # Host information collection
│   ├── terminal.py              # PTY/TTY management and signal handling
│   ├── transfer.py              # Chunked file transfers
│   ├── payload_exec.py          # In-memory payload execution
│   ├── tunnel.py                # SOCKS5 pivoting
│   ├── win_client.py            # Windows shell detection and script delivery
│   ├── session_registry.py      # Session persistence and reconnect logic
│   ├── session_log.py           # Per-session directory logging
│   ├── export.py                # HTML transcript export
│   ├── payloads.py              # Built-in payload catalog
│   └── plugins/
│       ├── api.py               # SessionContext and plugin registration
│       ├── manager.py           # Plugin lifecycle management
│       ├── loader.py            # Automatic module discovery
│       ├── shared/              # Cross-platform plugin implementations
│       ├── linux/               # Linux/Unix collector builders
│       └── windows/             # Windows collector builders
├── plugins/                     # Optional external plugin directory
└── logs/                        # Session log output (created at runtime)
```

---

## TLS Configuration

Generate a self-signed certificate for the TLS listener:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

Start the handler with explicit TLS material:

```bash
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

For production engagements, replace self-signed certificates with properly issued credentials from your organization's PKI or certificate authority.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
