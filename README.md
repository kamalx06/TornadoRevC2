# TORNADOREVC2 — Professional Reverse Shell Handler

TornadoRevC2 is a professional, universal reverse shell handler written in Python. It is **not** a full command-and-control framework — it is a highly capable reverse shell handler with advanced operator features, including a modular plugin system for post-compromise enumeration and operator assistance during authorized security research, red-team labs, malware analysis, and penetration testing.

**Supported target platforms:** Linux and Windows (primary), plus generic Unix/BSD compatibility where practical.

## ⚠️ Legal Disclaimer

This project is provided strictly for educational purposes, academic research, malware analysis, red-team laboratories, and authorized pentest. By using this software, you agree that:

- You will only deploy, execute, or test this tool on systems you own or systems for which you have received explicit, written authorization from the owner.
- You accept full responsibility for how this software is used, including compliance with all applicable local, national, and international laws.
- The author and contributors assume no liability for any misuse, damage, data loss, or legal consequences arising from the use of this software.

## What TornadoRevC2 is and is Not

### It is:

- A universal reverse shell handler
- A multi-client, multi-protocol shell receiver
- A combined TCP + TLS reverse shell server
- A fully interactive terminal
- A dynamic reverse shell payload reference
- An extensible plugin platform for on-demand enumeration and operator assistance

### It is not:

- Not a beacon-based C2
- Not a post-exploitation framework with persistence or automated tasking
- Not an offensive exploitation framework

## Project Structure

```
tornadorevc2/
  constants.py            # Shared constants and command lists
  handler.py              # Main server and session logic
  sysinfo.py              # Host information collection
  session_log.py          # Per-session directory logging
  terminal.py             # PTY/TTY, resize, and signal handling
  terminal_sanitize.py    # Strip control sequences from logged output
  transfer.py             # Chunked file transfers with resume support
  payload_exec.py         # In-memory payload transfer and execution
  clipboard.py            # Remote clipboard read
  tunnel.py               # SOCKS5 internal network pivoting
  session_registry.py     # Session persistence and reconnect support
  export.py               # HTML transcript report generation
  payloads.py             # Dynamic payload catalog
  plugins/
    __init__.py           # Plugin API exports
    api.py                # SessionContext and @plugin.command decorator
    manager.py            # Runtime plugin loading and execution
    loader.py             # Dynamic module discovery
    shared/
      common.py           # Formatting, confidence scoring, platform helpers
      runner.py           # Collector execution and JSON parsing
      virtualization.py   # Cross-platform virtualization plugin entry
      quickenum.py        # QuickEnum plugin entry + Linux collector
      wiper.py            # Secure multi-pass file wipe entry
      privesccheck.py     # LinPEAS / WinPEAS privilege escalation enumeration
    linux/
      virtualization.py   # Aggressive Linux VM/container/cloud collector
      quickenum.py        # QuickEnum plugin (Linux + Windows collectors)
      secrets.py          # Credential and config artifact search
      cron.py             # Cron and scheduled execution enumeration
      systemd.py          # Systemd services, timers, failed units
      mounts.py           # Mount, bind mount, and NFS enumeration
      history.py          # Shell history and login activity
    windows/
      virtualization.py   # Aggressive Windows VM/container/cloud collector
      _quickenum.py       # Windows QuickEnum collector (internal)
      shares.py           # SMB shares and mapped drives
      adinfo.py           # Active Directory and domain enumeration
      services.py         # Windows service enumeration
      scheduledtasks.py   # Scheduled task enumeration
      registry.py         # Autoruns and registry artifacts
      eventlogs.py        # Security, System, Application, PowerShell logs
      defender.py         # Windows Defender and security products
      certificates.py     # Certificate store enumeration
tornadorevc2.py           # Entry point
plugins/                  # Optional external plugin directory
```

## Plugin Architecture

TornadoRevC2 supports runtime-extensible plugins without modifying the core handler. Built-in plugins ship under `tornadorevc2/plugins/`; operators can also drop external modules into a top-level `plugins/` directory (or set `TORNADOREVC2_PLUGIN_DIR`).

### Plugin API

Plugins register commands via a decorator and receive a `SessionContext` with access to the session, shell execution, file transfer, logging, sysinfo, CWD, and platform information:

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

### Plugin Management Commands

| Command | Description |
|---------|-------------|
| `plugins` / `plugins list` | List registered plugins |
| `plugins list --verbose` | Show module paths and load state |
| `plugins load <name>` | Load a plugin at runtime |
| `plugins unload <name>` | Unload or disable a plugin |
| `plugins reload <name>` | Reload a plugin module |
| `plugins info <name>` | Show plugin details |
| `run <plugin> <session_id> [args...]` | Execute a plugin on an active session |

Plugins load dynamically — no handler restart required. The plugin registry is thread-safe.

### Plugin Workflow

```bash
# List available plugins
plugins list

# Inspect a plugin
plugins info quickenum

# Run against an active session
run quickenum 1
run secrets 2
run wiper 1 /tmp/sensitive.log
```

Results are displayed in the terminal and saved under `logs/<session>/plugins/` (human-readable report + raw JSON).

## Built-in Plugins

### Cross-Platform Plugins

| Plugin | Description |
|--------|-------------|
| `quickenum` | Fast structured host assessment (30–60 seconds) — hostname, user, network, environment, findings |
| `virtualization` | Aggressive VM, container, orchestration, and cloud detection |
| `privesccheck` | LinPEAS / WinPEAS privilege escalation enumeration (operator-supplied local script path) |
| `wiper` | Secure multi-pass file overwrite (zeros → ones → random) then delete |

### Linux / Unix Plugins

| Plugin | Description |
|--------|-------------|
| `quickenum` | Fast host overview: user, sudo, kernel, containers, network, mounts, cron, credentials |
| `virtualization` | Aggressive VM, container, orchestration, and cloud detection with multi-layer confidence scoring |
| `secrets` | Search configs, environment variables, SSH keys, cloud credentials, tokens, and sensitive artifacts |
| `cron` | Enumerate cron jobs, system cron directories, user crontabs, and at queues |
| `systemd` | Enumerate services, timers, failed units, and enabled startup units |
| `mounts` | Enumerate mounts, bind mounts, NFS/SMB, container mounts, and writable/executable mount points |
| `history` | Collect shell history, package manager logs, and recent login activity |

### Windows Plugins

| Plugin | Description |
|--------|-------------|
| `quickenum` | Fast host overview: admin status, domain, network, shares, services, Defender, autoruns, credentials |
| `virtualization` | Aggressive VM, container, orchestration, and cloud detection with multi-layer confidence scoring |
| `shares` | Enumerate SMB shares, administrative shares, mapped drives, and network hosts |
| `adinfo` | Domain membership, domain controllers, forest/trusts, and organizational units |
| `services` | Windows services, startup types, binaries, service accounts, and notable configurations |
| `scheduledtasks` | Scheduled tasks, triggers, execution context, and task actions |
| `registry` | Autoruns, Run keys, startup locations, and installed software |
| `eventlogs` | Security, System, Application, and PowerShell log summaries |
| `defender` | Windows Defender status, exclusions, ASR rules, and installed security products |
| `certificates` | Certificate stores, code-signing certs, and enterprise certificates |

## QuickEnum — Fast Host Assessment

The `quickenum` plugin answers: **“What is the most useful information I can gather from this host within 30–60 seconds?”**

It performs a single round-trip collection (not sequential plugin calls) and produces a structured report. Logic is condensed from existing collectors (virtualization, secrets, mounts, systemd, defender, etc.) for speed.

```bash
run quickenum 1
run quickenum 2
```

### Linux / Unix collection

- Hostname, user, UID/GID, sudo capability, OS, kernel, architecture
- Virtualization/container status (Docker, Podman, Kubernetes, WSL)
- Cloud instance detection, Docker socket exposure
- IP addresses, default route, DNS, listening ports
- Mount summary, writable+executable mount points
- Systemd status, recent cron entries
- SSH keys, authorized_keys, shell history, credential artifacts (`.env`, AWS, kubeconfig, etc.)

### Windows collection

- Hostname, user, admin/integrity status, OS, build, architecture
- Domain membership, Active Directory presence, virtualization/container status
- IP addresses, routes, DNS, listening ports
- SMB shares, running services, scheduled tasks
- Windows Defender status, security products, registry autoruns
- PowerShell history, credential artifacts, certificate store summary

### Example output

```text
Host Summary
------------
Hostname:              web01
OS:                    Ubuntu 24.04
Kernel:                6.8.0
Architecture:          x86_64

User
----
User:                  www-data
UID:                   33
GID:                   33
Sudo:                  no
CWD:                   /var/www

Environment
-----------
Type:                  Docker container
Orchestrator:          Kubernetes
Namespace:             production

Network
-------
IP:                    10.10.20.15
Default Gateway:       10.10.20.1
Listening Ports:       22, 80, 443

Findings
--------
- Docker container (.dockerenv)
- Kubernetes environment
- Docker socket exposed (accessible)
- .env file found
- SSH authorized_keys present

Collection time: 4.2s
```

Reports are saved to `logs/<session>/plugins/` as human-readable text and JSON.

## Secure File Wiper (`wiper`)

The `wiper` plugin securely removes a file on the remote target using a **3-pass overwrite** followed by deletion:

1. **Zeros** — entire file filled with `0x00`
2. **Ones** — entire file filled with `0xFF`
3. **Random** — entire file filled with cryptographically random data

Each pass is flushed to disk (`fsync` on Linux; `Flush(true)` on Windows) before the next pass. The file is then deleted.

```bash
# Linux target
run wiper 1 /tmp/exfil.log
run wiper 1 /home/user/.bash_history

# Windows target
run wiper 2 C:\Users\Public\staging.dat
run wiper 2 "C:\ProgramData\logs\sensitive.txt"
```

### Storage media caveat

**HDD:** A 3-pass overwrite followed by deletion provides strong assurance on traditional spinning disks.

**SSD / NVMe:** Because of wear leveling and internal remapping, overwriting a file multiple times **does not guarantee** that the original flash cells were overwritten. A 3-pass overwrite may leave previous versions in remapped blocks that the operating system cannot access. For SSDs, full-disk encryption, secure erase utilities, or physical destruction may be required for high-assurance sanitization.

The plugin displays this caveat before each wipe operation. Results (path, size, passes, verification status) are logged under `logs/<session>/plugins/`.

## Privilege Escalation Enumeration (`privesccheck`)

The `privesccheck` plugin automatically selects **LinPEAS** on Linux/Unix sessions and **WinPEAS** on Windows sessions. You provide the local script path on the command line — nothing is bundled or hard-coded.

```bash
# Linux target — path to your local linpeas.sh
run privesccheck 1 ./linpeas.sh
run privesccheck 1 /opt/peass/linpeas.sh

# Windows target — path to your local WinPEAS script or binary
run privesccheck 2 C:\tools\winPEAS.bat
run privesccheck 2 D:\arsenal\winPEASx64.exe
```

| Target | Expected file types | Tool run |
|--------|---------------------|----------|
| Linux / Unix | `.sh` shell script | LinPEAS via `bash` stdin |
| Windows | `.bat`, `.cmd`, or `.exe` | WinPEAS via in-memory decode or staged exe |

**In-memory execution:**

- **Linux:** Pipes base64-decoded script into `bash` stdin (no script file on target disk). Very large scripts use `/dev/shm` staging with automatic removal after execution.
- **Windows:** Decodes `.bat` in PowerShell with temp file removed in `finally`; `.exe` uses verified transfer, execution, and immediate temp cleanup.

**Output:** Live streaming to the terminal, full output saved under `logs/<session>/plugins/`, plus JSON metadata (tool, duration, exit code, path used). Script contents are never logged.

Download LinPEAS / WinPEAS from [PEASS-ng](https://github.com/carlospolop/PEASS-ng) and keep them anywhere on your operator machine — pass the path when you run the plugin.

## Aggressive Virtualization & Container Detection

The `virtualization` plugin performs deep multi-layer detection — not a single heuristic check. It combines independent signals into a weighted confidence score and lists every indicator that contributed.

Run `run virtualization <ID>` for full detail, or `run quickenum <ID>` for a condensed environment summary.

## Core Handler Features

### Dual TCP & TLS Reverse Shell Listener

Plain TCP and TLS encrypted listeners run simultaneously with TLS 1.2+, strong ciphers, and concurrent connection support.

### Universal Reverse Shell Compatibility

Handles TCP, TLS, UNIX, Windows, PTY, and unstable shells without assumptions about the target.

### Manual Host Information Collection

Host information is collected only when the operator runs `sysinfo` — stealth by default, `--full` for complete enumeration.

### Advanced Multi-Client Session Handling

Multi-session management with thread-safe client handling, session persistence, stable fingerprinting, and reconnect support.

### Internal Network Pivoting (SOCKS5)

Route operator tools through a session to reach internal hosts (`socks <ID> <port>`).

**Automatic cleanup:** When the last SOCKS proxy for a session is stopped (`socks stop <proxy_id>`), TornadoRevC2:

- Terminates the remote tunnel agent process
- Deletes the uploaded Python agent script
- Removes port marker files and SOCKS-related temp artifacts
- Verifies cleanup and logs the result to the session directory

Session disconnect also triggers full remote cleanup.

### In-Memory Payload Execution (`runexe` / `runpy` / `runps` / `runelf`)

Chunked upload with SHA256 verification, then in-memory execution:

- **`runpy` / `runps`:** Python and PowerShell scripts executed from memory
- **`runexe`:** Windows PE loaded from memory into a ephemeral temp process with stdout/stderr capture, command-line argument support, and immediate temp file removal
- **`runelf`:** Linux ELF via `memfd_create` with `/dev/shm` fallback

```bash
runexe 1 C:\tools\payload.exe -- --flag value
runexe 1 beacon.exe --save-output C:\local\out.txt
```

### File Transfer, Clipboard, Export

Chunked upload/download with SHA256 verification and resume support. Remote clipboard read. HTML session transcript export.

## Operator Commands

| Command | Description |
|---------|-------------|
| `status` / `ls` | Show active reverse shell sessions |
| `sessions` | Show tracked sessions (active + disconnected) |
| `reconnects` | Show session reconnect history |
| `switch <ID>` | Interact with a specific shell |
| `kill <ID>` | Terminate a shell session |
| `sysinfo <ID> [--stealth\|--full]` | Refresh and display host information |
| `plugins [list\|load\|unload\|reload\|info]` | Manage plugins |
| `run <plugin> <ID> [args...]` | Execute a plugin on a session |
| `run quickenum <ID>` | Fast structured host assessment |
| `run wiper <ID> <remote_path>` | Secure 3-pass file wipe on target |
| `runpy/runps/runexe/runelf <ID> <local>` | In-memory payload execution |
| `clipboard <ID>` | Read remote clipboard |
| `upload/download/verify` | File transfer with integrity checks |
| `socks <ID> <port>` | Start SOCKS5 internal pivoting |
| `socks stop <proxy_id>` | Stop SOCKS proxy and clean up remote artifacts |
| `tunnels` | List active SOCKS proxies |
| `export <ID>` | Export HTML session transcript |
| `rename/rn <ID> <name>` | Rename a session |
| `payloads` | Display payload list |
| `help` | Show help menu |
| `exit` / `quit` | Shut down the handler |

Inside a client shell (`switch <ID>`), omit the session ID for file transfer and session commands.

## Per-Session Logging

```
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log      # Commands and output
  sysinfo.json     # Host information snapshot
  transfers/       # Upload/download event logs
  executions/      # Payload execution metadata
  plugins/         # Plugin reports and raw JSON data
      quickenum_*.log
      wiper_*.log
```

Every plugin run writes a timestamped log file under `plugins/`:

- Human-readable report (Report section)
- Structured JSON export (Raw Data section) when the collector produces JSON

Example: `plugins/quickenum_20260812_054812.log`, `plugins/wiper_20260812_055030.log`

## Writing External Plugins

Place a Python module in the project `plugins/` directory:

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

## Usage

```bash
python tornadorevc2.py
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

### Example Session Workflow

```bash
# After a shell connects — fast triage first
run quickenum 1

# Deeper enumeration as needed
run virtualization 1
run secrets 1
run systemd 1

# Privilege escalation — provide your local PEAS script path
run privesccheck 1 ./linpeas.sh
run privesccheck 2 C:\tools\winPEAS.bat

# Windows target
run quickenum 2
run adinfo 2
run services 2
run defender 2

# Secure cleanup of a staged artifact on target
run wiper 1 /tmp/staging.log
run wiper 2 C:\Users\Public\temp.dat
```

## TLS Certificate Generation

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

## Changelog

- QuickEnum Plugin — fast structured host assessment (Added)
- Secure File Wiper Plugin — 3-pass overwrite with SSD/NVMe caveat (Added)
- Privilege Escalation Plugin (`privesccheck` — LinPEAS / WinPEAS) (Added)
- SOCKS Remote Artifact Cleanup on `socks stop` (Added)
- `runexe` Reliability Fix — stdout/stderr capture, args, temp cleanup (Fixed)
- Plugin Architecture with Linux and Windows Enumeration Suite (Added)
- Aggressive Virtualization & Container Detection Plugin (Added)
- Session Log and Export Control-Sequence Sanitization (Added)
- Session Transcript HTML Export (Added)
- SOCKS5 Internal Network Pivoting (Added)
- Session Persistence and Reconnect Support (Added)
- In-Memory Payload Execution (Added)
- Remote Clipboard Interaction (Added)
- Sysinfo Stealth and Full Modes (Added)
- Chunked File Upload & Download with Resume (Added)
- Enhanced PTY/TTY Terminal Handling (Added)
- Per-Session Directory Logging (Added)
- Modular Package Structure (Added)
