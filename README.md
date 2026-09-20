# TornadoRevC2

A lightweight, modular post-exploitation framework for authorized security research, red-team operations, and penetration testing. TornadoRevC2 manages reverse shell sessions on Linux and Windows hosts through a unified operator console, extending core session handling with a cross-platform plugin architecture for host enumeration, situational awareness, and operational tasks.

> **Important:** TornadoRevC2 is a session handler and post-exploitation framework—not a beacon-style command-and-control platform. It prioritizes reliable interactive shells, structured operator workflows, and on-demand plugin execution over persistent agent infrastructure.

---

## Legal Notice

Use this software only on systems you own or on systems where you have **explicit written authorization**. You are solely responsible for compliance with applicable laws and organizational policies. The authors and contributors accept no liability for misuse, data loss, or legal consequences arising from the use of this project.

---

## Demo

<p align="center">
  <img src="demo/TornadoRevC2-Demo.GIF" alt="TornadoRevC2 Demo" width="900">
</p>

<p align="center">
  <strong>Quick demo:</strong> session management, plugin execution, SOCKS5 pivoting.
</p>

---

## Table of Contents

- [Introduction](#introduction)
- [Key Features](#key-features)
- [Design Philosophy](#design-philosophy)
- [Operational Security](#operational-security)
- [Architecture](#architecture)
- [Requirements & Installation](#requirements--installation)
- [Quick Start](#quick-start)
- [Operator Reference](#operator-reference)
- [Built-in Plugins](#built-in-plugins)
- [Plugin Development](#plugin-development)
- [Session Logging](#session-logging)
- [Project Structure](#project-structure)
- [TLS & mTLS Configuration](#tls--mtls-configuration)
- [License](#license)

---

## Introduction

TornadoRevC2 is a modular reverse shell management framework that accepts inbound connections over plain TCP, server-authenticated TLS, and mutual TLS (mTLS) with client-certificate verification, providing a unified operator console for session management, host reconnaissance, chunked file transfer, in-memory payload execution, SOCKS5 pivoting, plugin-driven post-exploitation, structured reporting, and a built-in `update` command for automatic Git-based updates and seamless handler restarts. Originally developed as a lightweight reverse shell handler, the project has evolved into an extensible framework in which capabilities such as firewall enumeration, credential store metadata collection, network mapping, browser profiling, and additional post-exploitation functionality are implemented as independent, modular plugins. The framework also includes the `make_token` plugin for establishing new C2 sessions via remote protocols (SSH, WinRM, SMB, WMI, MSSQL, DCOM, and MySQL/MariaDB) using command-line tools from the operator side, and an `upgrade_mtls` plugin that migrates a live session onto the mutual-TLS listener by pushing the handler's client certificate bundle to the target.

**Supported target platforms:** Linux and Windows (primary), with compatibility for generic Unix and BSD environments where applicable.

---

## Key Features

| Category | Capabilities |
|----------|-------------|
| **Session handling** | Multi-client TCP / TLS / mTLS listeners with automatic PKI bootstrapping · On-demand mTLS upgrade for live sessions · Interactive PTY/TTY shells · Session fingerprinting and reconnect tracking |
| **Operational security** | Shell history suppression on Linux and Windows · No `pty.spawn` or `Invoke-Expression` in command paths · Session-scoped probe markers · Jitter between automated commands · Host deny-list guardrails that refuse production-looking targets |
| **File transfer** | Chunked upload and download · SHA-256 integrity verification |
| **Payload execution** | In-memory execution for `py`, `ps`, `exe`, `elf`, `bat`, and `sh` — with memfd-based ELF execution (modern and legacy fallbacks) and subsystem-aware PE loading |
| **Pivoting & tunneling** | SOCKS5 proxy through compromised sessions with automatic remote agent cleanup on stop · Soft and hard tunnel reset (`socks reset [--hard]`) · Ligolo-NG and Chisel agent deployment with background persistence |
| **Remote session establishment** | `make_token` — establish new sessions over SSH, WinRM, SMB, WMI, MSSQL, DCOM, or MySQL/MariaDB from the operator side, with password / NTLM-hash / SSH-key / WinRM-client-certificate authentication, MySQL UDF auto-loading, custom-command execution, and netexec integration |
| **Impersonation** | `runas` — execute commands or spawn a TLS-encrypted shell as another user, local or remote, with domain support and netexec integration |
| **Enumeration** | Covering host triage, network posture, credentials and browser metadata, Kerberos tickets, Linux internals, and Windows domain and system configuration |
| **Operational plugins** | Multi-pass secure file wiping · Hybrid file encryption · Shell history clearing · Windows event log clearing |
| **Persistence** | Cross-platform backdoor installation using TLS-encrypted payloads — cron `@reboot` on Linux/Unix, Run registry on Windows |
| **Extensibility** | Runtime plugin load, reload, and unload · External plugins via `TORNADOREVC2_PLUGIN_DIR` · Documented `SessionContext` API |
| **Reporting** | Per-session logging · Structured plugin output · HTML transcript export |
| **Self-update** | Git-based `update` command with repository verification, fast-forward pull, and automatic handler restart |

**Not supported:** Task scheduling, or beacon-style callback infrastructure.

---

## Design Philosophy

TornadoRevC2 is engineered for environments where deployment friction and operational footprint matter.

### Dependency-light, native-command design

Plugins leverage **native Windows and Linux utilities and built-in system commands** already present on the target host—`netsh`, `ss`, `iptables`, `ufw`, `firewall-cmd`, `nft`, PowerShell cmdlets, `nmcli`, `wevtutil`, and others. Collectors invoke these tools through the reverse shell channel and parse output remotely, minimizing the need to upload additional binaries or install dependencies.

### Enumeration without artifact drops

**Enumeration plugins execute through the existing reverse shell channel and do not drop binaries, scripts, or temporary files for reconnaissance.** Native commands, inline Python collectors, and in-process PowerShell scripts return structured JSON over the shell. The only unavoidable artifact is normal command history generated by the shell itself — which TornadoRevC2 suppresses at session start (see [Operational Security](#operational-security)).

Operational plugins intentionally place artifacts on the target and document their own cleanup behavior:

- `ligolong` / `chisel` — deploy tunneling agents with background persistence.
- `persistence` — installs a reverse shell backdoor (cron `@reboot` / Run registry).
- `upgrade_mtls` — pushes `client.pem`, `client.key`, and `ca.pem` to the target (removed by default once the new mTLS session is up).
- SOCKS5 pivoting — deploys a Python agent to `/tmp` (Linux) or the Windows staging path, removed automatically on `socks stop` and on session cleanup.

### Graceful degradation

When an enumeration routine fails, is unavailable, or times out, the plugin does not abort entirely. The affected section is left empty or marked `N/A` while the remainder of the report continues.

### Operator-side maintenance

Handler updates are delivered through Git on the operator machine. The `update` command uses bounded subprocess timeouts, non-interactive Git settings, and a fast local shutdown path so the handler can restart reliably without waiting for remote session cleanup to complete.

---

## Operational Security

TornadoRevC2 applies a set of always-on operational security measures across every session. These are not optional flags — they run unconditionally so that even a hurried operator receives the full benefit.

### Shell history suppression

Every session neutralizes its own command history before doing anything else.

**Linux/Unix** — the PTY upgrade path unsets `HISTFILE`, points it at `/dev/null`, zeroes `HISTSIZE` and `HISTFILESIZE`, sets `HISTCONTROL=ignorespace`, and disables the shell's history via `set +o history`. Every subsequent command is space-prefixed where `ignorespace` is honored. Result: `~/.bash_history` receives nothing from the session.

**Windows** — on session init, the handler runs:

```powershell
Set-PSReadlineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
```

Result: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` receives nothing from the session.

### Command construction discipline

The handler and its plugins avoid command patterns that are widely known as red-team signatures.

- **No `python -c 'import pty; pty.spawn(...)'`.** The PTY upgrade path uses `script -qfc` (util-linux) or `script -q /dev/null` (BSD/macOS), both of which are legitimate sysadmin utilities. `pty.spawn` is not.
- **No `Invoke-Expression` (IEX).** PowerShell scripts are either sent inline (for short single statements) or wrapped in `[ScriptBlock]::Create(...).Invoke()`. When the payload is too large for a single command line, it is staged to a plausibly-named temp file under `%TEMP%`, executed with `-File`, and deleted immediately.
- **No static probe markers.** The platform and identity probes use per-session randomized markers, so no fixed string appears in command logs or process-creation telemetry.

### Jitter between automated commands

Plugin collectors insert a random 0.5–2.5 s delay at the start of each run and between fallback probes. This breaks the tight command-burst pattern that defenders associate with automated tooling.

### Guardrails

The handler refuses to operate on hosts that match a deny list of production-looking patterns:

- Hostnames containing `prod`, `prd`, or `dc1`-style prefixes
- Domains containing `.corp.`
- Known test hostnames (`localhost`, `sandbox`, `test-vm`, `testvm`, `kali`, `ubuntu`, `metasploitable`, `dvwa`)

When a session is blocked, the operator console shows the reason and every subsequent command is refused until the block is cleared manually. This prevents accidental impact on production infrastructure during an engagement.

### Session log hygiene

Session logs are written through an error-safe path (logging failures never abort a session) and ANSI/OSC/DCS terminal control sequences are stripped from target output so logs remain readable in any editor. Operator commands are stored verbatim.

### What this layer does not claim

TornadoRevC2 does **not** claim to evade EDR, AMSI, ScriptBlock logging, or memory forensics. The architecture (reverse-shell channel based post exploitation framework, no compiled implant) has a hard ceiling on what is possible. The measures above reduce forensic footprint and operational risk; they do not make the tool undetectable on a monitored host. Operators should treat every session as potentially observable and follow engagement-specific rules of engagement.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Operator Console (handler)                  │
│  Sessions · Transfers · SOCKS · Plugins · Logging · Export ·    │
│  update · Guardrails                                            │
└────────────────────────────┬────────────────────────────────────┘
                             │ reverse shell channel (TCP / TLS / mTLS)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Target Host                              │
│  Native commands · PowerShell · inline collectors               │
│  __T_PLUGIN_START__ + JSON + __T_PLUGIN_END__                   │
└─────────────────────────────────────────────────────────────────┘
```

### Listener Configuration

TornadoRevC2 runs **three independent listeners simultaneously**, so implants can connect over plaintext, server-authenticated TLS, or mutually authenticated TLS depending on the engagement's threat model:

| Listener | Default port | Flag | Authentication | Certificates |
|----------|--------------|------|----------------|--------------|
| TCP      | `4444`       | `-p` | None           | None |
| TLS      | `8443`       | `-tp` | Server-authenticated | `tls_certs/server.pem`, `tls_certs/server.key` |
| mTLS     | `9443`       | `-mp` | Mutual (client cert required) | `mtls_certs/` bundle (CA + server + client) |

The `-H` flag sets the bind address shared by all three listeners. All three can be enabled at once; disabling one is not currently required — leave the port free or unbound to ignore it.

**Automatic certificate generation.** On first launch the handler creates two isolated directories and bootstraps the material it needs:

```text
tls_certs/
  server.pem          # self-signed server certificate
  server.key          # server private key

mtls_certs/
  ca.pem              # mTLS certificate authority (self-signed, 4096-bit RSA)
  ca.key              # CA private key
  ca.srl              # OpenSSL serial counter (auto-generated)
  server-mtls.pem     # server cert signed by CA
  server-mtls.key     # server private key
  client.pem          # client cert signed by CA — ship to implant
  client.key          # client private key  — ship to implant
```

The bootstrap is **all-or-nothing per bundle**: if every expected file for a bundle already exists, generation is skipped; if any single file is missing, the entire bundle is regenerated. This means deleting one file from `mtls_certs/` invalidates the existing trust chain — remove the whole directory if you want a clean rebuild. If OpenSSL is not on `PATH`, the handler exits during first-run certificate generation.

### Plugin Layout

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

### SOCKS5 pivoting lifecycle

Each SOCKS proxy runs through a remote Python agent deployed on demand. The agent connects back to the handler over a dedicated tunnel listener (default: `revshell_port + 1`) and maintains a pool of channels for stream multiplexing. The operator controls the tunnel with four commands:

- `socks <listen_port>` — start a SOCKS5 proxy bound to `127.0.0.1:<listen_port>`
- `socks test <host> <port>` — verify TCP reachability through the agent
- `socks reset [--hard]` — soft reset (abort relays, purge streams, clear buffers, rebalance channels) or hard reset (kill + redeploy agent)
- `socks stop <proxy_id>` — stop a proxy; if it was the last proxy on the session, the remote agent is terminated and its `.tornado_agent_*.py` artifact is deleted from the target

The agent is **shared across proxies on the same session** and is cleaned up only when the last proxy on that session stops.

---

## Requirements & Installation

**Handler (operator machine):**

- Python 3.7 or later
- OpenSSL (for automatic TLS and mTLS certificate generation)
- Git (optional; required for the `update` operator command)
- No third-party Python packages required

```bash
git clone https://github.com/kamalx06/TornadoRevC2.git
cd TornadoRevC2
python3 tornadorevc2.py
```

---

## Quick Start

### 1. Start the handler

```bash
# Default: TCP on 4444, TLS on 8443, mTLS on 9443
python tornadorevc2.py

# Custom bind address and ports for all three listeners
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -mp 9443

# Point to your own certificate material
python tornadorevc2.py \
  -c tls_certs/server.pem -k tls_certs/server.key \
  --mtls-ca-cert mtls_certs/ca.pem --mtls-ca-key mtls_certs/ca.key \
  --mtls-server-cert mtls_certs/server-mtls.pem --mtls-server-key mtls_certs/server-mtls.key \
  --mtls-client-cert mtls_certs/client.pem --mtls-client-key mtls_certs/client.key
```

### 2. Establish a session

Deploy a reverse shell from the built-in catalog (`payloads`) or use your own implant. On connect, TornadoRevC2 assigns a session ID, suppresses shell history on the target, and begins logging under `logs/`.

### 3. Operate

```bash
status                            # List active sessions
switch 1                          # Attach to session 1
sysinfo 1                         # Collect host metadata
run credstore 1                   # Credential store metadata
run memorymap 1 1234              # Process memory maps (requires PID)
run inmemory 1 sh ./linpeas.sh    # In-memory script execution
run upgrade_mtls 1 --port 9443    # Migrate session to the mTLS listener
update                            # Pull latest from GitHub and restart (Git installs)
```

When attached via `switch <ID>`, omit the session ID from subsequent commands (`run quickenum` instead of `run quickenum 1`). Plugin listings and TAB completion inside a client session are filtered to plugins compatible with that session's platform.

The `update` command is available from the main handler prompt only. It verifies that Git is installed, confirms the installation is a Git working tree, fetches from the configured remote, fast-forward pulls when updates exist, and restarts the handler with the same executable and arguments. If the installation is already current, it prints `TornadoRevC2 is already running the latest version.` and leaves the server running.

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
| `socks <ID> reset` | `socks reset` | **Soft reset** — abort local relays, purge remote streams, clear buffers, and rebalance channels. Active SOCKS listeners remain bound. |
| `socks <ID> reset --hard` | `socks reset --hard` | **Hard reset** — kill and redeploy the remote tunnel agent for a fully fresh state |
| `socks stop <proxy_id>` | `socks stop <proxy_id>` | Stop a SOCKS proxy. When it was the last proxy on that session, the remote agent process is killed and its `.tornado_agent_*.py` artifact is removed from the target. |
| `tunnels` | `tunnels` | List active SOCKS proxies, channel count, and status |

### General

| Command | Description |
|---------|-------------|
| `payloads` | Display the built-in payload reference |
| `update` | Check for updates from the official GitHub repository and restart after a successful fast-forward pull (requires Git; main menu only) |
| `help` | Show the command reference |
| `exit` / `quit` | Shut down the handler |

---

## Built-in Plugins

TornadoRevC2 ships with **51 built-in plugins** organized by function. All enumeration-related plugins are read-only unless noted otherwise.

### Host assessment & environment

| Plugin | Platform | Description |
|--------|----------|-------------|
| `quickenum` | Cross-platform | Fast structured host triage: identity, network, environment, prioritized findings |
| `virtualization` | Cross-platform | Virtualization, container, orchestration, and cloud environment detection |
| `kernel` | Cross-platform | Kernel version, loaded modules/drivers, security mitigations, and kernel configuration |
| `integrity` | Cross-platform | Secure Boot, BitLocker/LUKS, code-signing enforcement, kernel lockdown, and integrity protections |
| `filesearch` | Cross-platform | Search files by path, name, ext, size, owner, mtime (`run filesearch help` for options) |
| `packages` | Cross-platform | Installed software, package managers, repository configuration, and recent installs |
| `kerberosenum` | Cross-platform | Kerberos ticket metadata: caches, default principal, realm, TGT, service tickets, encryption types, flags (renewable/forwardable), keytab files, krb5.conf/registry config, and environment variables (no secrets) |

> `sysinfo` is a handler command, not a plugin — see [Session management](#session-management).

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
| `sshaudit` | Linux/Unix | SSH server enumeration: effective sshd config, auth surface, pivoting options, host keys, authorized_keys, and CA trust |
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
| `defender` | Windows | Windows Defender status, exclusions, preferences, ASR rules, threats, AV products, services, and Exploit Protection config. `-d/--disable` attempts a full disable (admin required). |
| `certificates` | Windows | Certificate stores, code-signing, and enterprise certificates |
| `rdp` | Windows | Remote Desktop configuration, active sessions, recent targets, restricted-admin, start, adduser, and shadow (reverse shell as session user) |
| `gpo` | Windows | Applied GPOs, local/domain security policies, AppLocker, WDAC, SRP, and GPO scripts |
| `winrm` | Windows | WinRM configuration, listeners, authentication methods, client settings, certificate bind/exploitcert, start, adduser, and remoting status |
| `drivers` | Windows | Installed drivers and kernel modules, signed/unsigned status, startup type, and notable security/VM drivers |
| `powershell` | Windows | PowerShell version, execution policy, logging, modules, remoting settings, and profile paths |
| `lsa` | Windows | LSA protection, Credential Guard, virtualization-based security, and credential security configuration |

### Execution & operational

| Plugin | Platform | Description |
|--------|----------|-------------|
| `inmemory` | Cross-platform | In-memory payload execution (`py`, `ps`, `exe`, `elf`, `bat`, `sh`) |
| `make_token` | Cross-platform | Establish C2 sessions *to other hosts* over SSH, WinRM, SMB, WMI, MSSQL, DCOM, or MySQL/MariaDB using passwords, NTLM hashes, SSH keys, WinRM client certs, netexec, and MySQL UDF auto-loading. Supports custom commands (`-C`). |
| `nullcrypt` | Cross-platform | Hybrid encrypt a file (AES-GCM + RSA-wrapped key) then securely wipe the original via wiper |
| `wiper` | Cross-platform | Configurable multi-pass secure overwrite (rename, truncate, delete); profiles: quick, standard, dod, thorough, shred |
| `historydel` | Cross-platform | Clear current user shell history files and related storage |
| `eventlogdel` | Windows | Clear Windows Event Logs: defaults (Security, System, Application, PowerShell), a custom log list, or every log with records; optional .evtx backup |
| `runas` | Windows | Execute commands or launch a TLS-encrypted reverse shell *on the current host* as another user, with saved credential management and domain support |
| `ligolong` | Cross-platform | Deploy Ligolo-NG tunneling agent to Linux/Windows targets with background persistence |
| `chisel` | Cross-platform | Deploy Chisel tunneling agent in reverse (client) or bind (server) mode; supports SOCKS5 and background persistence |
| `persistence` | Cross-platform | Install a persistent reverse shell backdoor (cron @reboot / Run registry) using TLS-encrypted payload |
| `upgrade_mtls` | Cross-platform | Push the handler's mTLS client bundle to a session and relaunch it over the mTLS listener (opt-in; does not affect other listeners) |

> **`make_token` vs `runas`:** `make_token` establishes sessions *to other hosts* over remote protocols. `runas` executes *on the current host* as a different user.

> **SOCKS reset modes:** `socks reset` performs a soft reset (relays aborted, remote streams purged, buffers cleared). `socks reset --hard` additionally kills the remote tunnel agent and redeploys it for a clean slate. Stopping a SOCKS proxy with `socks stop <proxy_id>` automatically removes the remote agent artifact and process when no other proxy uses the session.

**In-memory execution methods:**

| Type | Method |
|------|--------|
| `py` | Python via `exec(compile(...))` |
| `ps` | PowerShell via `[ScriptBlock]::Create(...)` (no IEX) |
| `exe` | Windows PE via in-memory RunPE (process hollowing), subsystem-aware host selection, full `CONTEXT64` context, background pipe draining |
| `elf` | Linux ELF via `memfd_create` — modern (`os.memfd_create`, Python 3.8+), legacy (direct syscall via ctypes for older Python or unsupported architectures), or `/dev/shm` fallback |
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
| **Collectors** | `plugins/shared/runner.py` | Marker parsing, JSON extraction, report formatting, logging, unconditional jitter |

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
    name="myplugin",
    platforms=["linux", "windows", "unix"],
    description="Short description for plugins list and TAB completion",
)
def run(session: SessionContext, args):
    ...
    return 0
```

**Platform values:** `linux`, `windows`, `unix`. Linux and `unix` are treated as compatible — a plugin registered for `linux` runs on both `linux` and `unix` sessions. Default if omitted: `["linux", "windows", "unix"]`.

**Multiple commands per module:** A single file may register several commands by applying `@plugin.command` to multiple functions. Each gets an independent name.

### Execution lifecycle

When an operator runs `run myplugin 1 arg1 arg2`:

```text
1. PluginManager resolves session #1 and looks up "myplugin" in the registry
2. Platform check: plugin.platforms vs session shell type (unix/windows)
3. SessionContext(handler, client_socket) is constructed
4. Handler invoked: run(ctx, ["arg1", "arg2"])
5. Jitter delay (0.5–2.5 s) before the first target command
6. Handler executes remote work via run_shell / run_marked / run_collector_plugin
7. Output printed to operator console; results logged under logs/<session>/plugins/
8. Exit code returned (0 = success)
```

Inside an attached session (`switch <ID>`), the session ID is omitted and args start immediately after the plugin name: `run myplugin arg1 arg2`.

### Pattern 1: Simple shell plugin

Use this when you need a quick one-off command without structured JSON parsing.

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

### Pattern 2: Structured collector (recommended)

Use this for enumeration plugins that gather structured data on the target and return a formatted report.

```python
from tornadorevc2.plugins import plugin, SessionContext
from tornadorevc2.plugins.linux._helpers import build_linux_collector_command
from tornadorevc2.plugins.shared.common import format_generic_report
from tornadorevc2.plugins.shared.runner import run_collector_plugin
from tornadorevc2.constants import PLUGIN_MARK_END, PLUGIN_MARK_START


def _linux_collector_source():
    return r'''
import shutil, subprocess
result = {'summary': {}, 'processes': []}
# Prefer shutil.which() over spawning `which` — no process creation.
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
        _build_linux_command,
        _build_windows_command,
        format_generic_report,
        timeout=25.0,
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

### Pattern 3: Custom handler

Use this for argument validation, dynamic collector construction, post-collector processing, or operator-side file handling.

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

    unix_cmd = _build_linux_command(pid)
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

### Linux collectors

Linux collectors are Python source strings executed on the target via `build_linux_collector_command()`.

The wrapper in `linux/_helpers.py` automatically:

- Indents your source inside a `try/except` block
- Defines `_emit(obj)` to write `__T_PLUGIN_START__` + JSON + `__T_PLUGIN_END__`
- Emits `{"error": "...", "traceback": "..."}` on unhandled exceptions
- Encodes the script for inline execution via `python3 -c` (or `python2` fallback)
- Falls back to chunked `/tmp` staging only when the encoded payload exceeds ~20000 bytes

**Guidelines:**

- **Prefer `shutil.which()` over spawning `which`** — no process creation.
- **Prefer reading config files in-process** over spawning helper binaries (`xdg-settings`, etc.).
- Use `subprocess.check_output(..., timeout=N)` for external commands that cannot be avoided.
- Trim large lists before emitting (cap at 50–80 entries).
- Handle missing tools gracefully—leave sections empty rather than raising.
- Avoid embedding marker strings in output.
- Keep collectors compact to stay under the inline size limit and avoid `/tmp` staging.
- **Skip credential-store filenames** (`Login Data`, `logins.json`, `key4.db`, `Cookies`) when enumerating browser artifacts — even a `stat()` on these paths can trip EDR rules.

### Windows collectors

Windows collectors are PowerShell script strings returned from `_build_windows_command()`.

**Guidelines:**

- Always set `$ErrorActionPreference='SilentlyContinue'` at the top.
- Use `-EA 0` on cmdlets that may fail on older systems.
- Brace-doubling is required inside Python f-strings: `{{` and `}}`.
- Use `[ordered]@{{...}}` to preserve key order.
- Prefer built-in cmdlets over external tools.
- Wrap each logical section in its own `try/catch`.
- On interactive PowerShell sessions, scripts are delivered in-process via `win_client.py`.

### JSON payload conventions

| Key | Type | Purpose |
|-----|------|---------|
| `summary` | `dict` | High-level counts and stats; rendered first by `format_generic_report()` |
| `error` | `str` | **Hard failure** — runner prints error and returns exit code 1 |
| `traceback` | `str` | Optional; logged as detail when `error` is set |
| `reason` | `str` | **Soft failure** — use with custom formatters |
| `ok` | `bool` | Success flag for operational plugins |
| Lists of `dict` | `list` | Rendered as tables |
| Lists of `str` | `list` | Rendered as bullet lists |
| Nested `dict` | `dict` | Rendered as labeled sections |

**Graceful degradation:** For multi-section enumeration, use separate dict keys per section and catch exceptions locally. Do not set top-level `error` unless the entire collector failed.

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
        None,
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
        None,
        format_generic_report,
        timeout=30.0,
    )
```

### External plugins

External plugins let you extend TornadoRevC2 without modifying the repository.

```bash
# Default location (created automatically if missing)
./plugins/myplugin.py

# Or set a custom directory
export TORNADOREVC2_PLUGIN_DIR=/path/to/my/plugins
```

**Workflow:**

```bash
plugins load myplugin
plugins info myplugin
run myplugin 1
plugins reload myplugin
plugins unload myplugin
```

### SessionContext API

Every handler receives a `SessionContext` wrapping the handler and client socket:

**Metadata properties:**

| Property | Type | Description |
|----------|------|-------------|
| `session_id` | `str` | Assigned session identifier |
| `platform` | `str` | `unix`, `windows`, or `unknown` |
| `is_windows` / `is_unix` | `bool` | Platform convenience flags |
| `sysinfo` | `dict` | Cached host information |
| `identity` | `dict` | Session identity/fingerprint metadata |
| `addr` | `tuple` | Remote address |
| `tls` | `bool` | Whether session uses TLS |
| `name` | `str` | Operator-assigned friendly name |
| `fingerprint` | `str` | Stable host fingerprint |
| `logger` | `SessionLogger` | Per-session log writer |
| `colors` | `dict` | Console color codes |
| `socket` | socket | Raw client socket |

**Execution methods:**

| Method | Description |
|--------|-------------|
| `run_shell(cmd, timeout=15.0)` | Send command, wait for output, return string |
| `run_shell_streaming(cmd, timeout, idle_timeout, on_chunk)` | Stream output with idle detection |
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
| `print(text, color=None)` | Print to operator console with optional color |
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
| Partial section failures | Leave section empty; do **not** set top-level `error` |

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

**Log writing is error-safe:** if a write fails (disk full, permission error, etc.), the failure is swallowed and the session continues. Logging never aborts an active session.

**Terminal control sequences are stripped** from all target output before it is written to disk, so logs remain readable in any editor.

Tunnel operations (SOCKS start/stop, reset, cleanup, reconnect of the remote agent) are logged via the session logger under `session.log`, including remote artifact removal results.

---

## Project Structure

```text
TornadoRevC2/
├── tornadorevc2.py                 Entry point
├── tornadorevc2/
│   ├── handler.py                  Listeners, sessions, operator console
│   ├── guardrails.py               Host deny list and operational guardrails
│   ├── updater.py                  Git-based self-update and restart
│   ├── sysinfo.py                  Host information collection
│   ├── terminal.py                 PTY/TTY management (OPSEC-aware)
│   ├── transfer.py                 Chunked file transfers
│   ├── tunnel.py                   SOCKS5 pivoting
│   ├── remote_exec.py              Remote command builders
│   ├── win_client.py               Windows shell detection and script delivery
│   ├── session_registry.py         Session persistence and reconnect logic
│   ├── session_log.py              Per-session directory logging (error-safe)
│   ├── terminal_sanitize.py        ANSI/OSC/DCS sequence stripping
│   ├── export.py                   HTML transcript export
│   ├── payloads.py                 Built-in payload catalog
│   └── plugins/
│       ├── api.py                  SessionContext and plugin registration
│       ├── manager.py              Plugin lifecycle and execution
│       ├── loader.py               Module discovery
│       ├── shared/                 Cross-platform plugins
│       │   ├── runner.py           Collector execution + jitter
│       │   ├── inmemory.py         In-memory payload execution
│       │   └── _win_pe_loader.cs   Windows PE loader (C#)
│       ├── linux/                  Linux/Unix-only plugins
│       └── windows/                Windows-only plugins
├── plugins/                        Optional external plugin directory
└── logs/                           Session output (created at runtime)
```

---

## TLS & mTLS Configuration

TornadoRevC2 runs three isolated listeners, each with its own certificate source. Everything under `tls_certs/` and `mtls_certs/` is auto-generated on first run and never overwritten once the full bundle is present.

| Listener | Port | Client auth | Certificates |
|----------|------|-------------|--------------|
| TCP | `4444` | none | — |
| TLS | `8443` | server-only | `tls_certs/server.pem`, `tls_certs/server.key` |
| mTLS | `9443` | mutual (client certificate required) | `mtls_certs/` bundle |

### TLS

Auto-generated as a self-signed pair (`CN=localhost`, RSA-2048, 3650 days).

To supply your own:

```bash
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 \
  -c tls_certs/server.pem -k tls_certs/server.key
```

If the client connects using an IP address, the server certificate should include that IP in its **Subject Alternative Name (SAN)**. Avoid disabling hostname verification unless there is a specific reason to do so.

### mTLS

On first run, a full PKI is bootstrapped under `mtls_certs/`:

- `ca.pem` / `ca.key` — self-signed CA (RSA-4096, CN=`TornadoRevC2-mTLS-CA`)
- `server-mtls.pem` / `server-mtls.key` — server certificate signed by the CA
- `client.pem` / `client.key` — client certificate signed by the CA
- `ca.srl` — OpenSSL serial counter generated during certificate signing

Ship **`client.pem` + `client.key` + `ca.pem`** with the authorized client. The client must present its certificate on connect or the handshake is rejected.

Start with explicit paths:

```bash
python tornadorevc2.py -H 0.0.0.0 -mp 9443 \
  --mtls-ca-cert mtls_certs/ca.pem --mtls-ca-key mtls_certs/ca.key \
  --mtls-server-cert mtls_certs/server-mtls.pem --mtls-server-key mtls_certs/server-mtls.key \
  --mtls-client-cert mtls_certs/client.pem --mtls-client-key mtls_certs/client.key
```

### Upgrading a live session to mTLS

Existing sessions on plain TCP or server-auth TLS can be moved onto the mTLS listener without restarting the handler.

```bash
# From the main handler prompt
run upgrade_mtls 1 --port 9443 --host 10.10.14.7
run upgrade_mtls 1 --keep-bundle       # leave certs on disk after launch
run upgrade_mtls 1 --no-upload         # certificate bundle already uploaded manually

# From inside an attached session (switch 1)
run upgrade_mtls
```

**`upgrade_mtls` flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--port <port>` | mTLS listener port (`9443`) | Port on the handler to connect back to |
| `--host <ip>` | Session's remote address | Handler IP to connect back to |
| `--keep-bundle` | off | Leave the certificate bundle on disk after the new session starts |
| `--no-upload` | off | Skip the upload step (bundle already present on the target) |

### Flags

| Flag | Default |
|------|---------|
| `-H` / `--host` | `0.0.0.0` |
| `-p` / `--port` | `4444` |
| `-tp` / `--tls-port` | `8443` |
| `-mp` / `--mtls-port` | `9443` |
| `-c` / `--cert`, `-k` / `--key` | `tls_certs/server.{pem,key}` |
| `--mtls-ca-cert` / `--mtls-ca-key` | `mtls_certs/ca.{pem,key}` |
| `--mtls-server-cert` / `--mtls-server-key` | `mtls_certs/server-mtls.{pem,key}` |
| `--mtls-client-cert` / `--mtls-client-key` | `mtls_certs/client.{pem,key}` |

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).