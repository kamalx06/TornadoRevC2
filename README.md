# TORNADOREVC2 — Professional Reverse Shell Handler

TornadoRevC2 is a professional, universal reverse shell handler written in Python. It is not a full C2 framework, but a highly capable reverse shell handler with advanced operator features — including a modular plugin system for post-compromise enumeration and operator assistance during authorized security research, red-team labs, and penetration testing.

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
      privesccheck.py     # LinPEAS / WinPEAS privilege escalation enumeration
    linux/
      virtualization.py   # Aggressive Linux VM/container/cloud collector
      secrets.py          # Credential and config artifact search
      cron.py             # Cron and scheduled execution enumeration
      systemd.py          # Systemd services, timers, failed units
      mounts.py           # Mount, bind mount, and NFS enumeration
      history.py          # Shell history and login activity
    windows/
      virtualization.py   # Aggressive Windows VM/container/cloud collector
      shares.py           # SMB shares and mapped drives
      adinfo.py           # Active Directory and domain enumeration
      services.py         # Windows service enumeration
      scheduledtasks.py   # Scheduled task enumeration
      registry.py         # Autoruns and registry artifacts
      eventlogs.py        # Security, System, Application, PowerShell logs
      defender.py         # Windows Defender and security products
      certificates.py     # Certificate store enumeration
tornadorevc2.py           # Entry point
tools/privesc/            # Operator-provided LinPEAS / WinPEAS scripts (not bundled)
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
| `run <plugin> <session_id>` | Execute a plugin on an active session |

Plugins load dynamically — no handler restart required. The plugin registry is thread-safe.

### Plugin Workflow

```bash
# List available plugins
plugins list

# Inspect a plugin
plugins info virtualization

# Run against an active session
run virtualization 1
run secrets 2
run services 3
```

Results are displayed in the terminal and saved under `logs/<session>/plugins/` (human-readable report + raw JSON).

## Built-in Plugins

### Linux / Unix Plugins

| Plugin | Description |
|--------|-------------|
| `virtualization` | Aggressive VM, container, orchestration, and cloud detection with multi-layer confidence scoring |
| `secrets` | Search configs, environment variables, SSH keys, cloud credentials, tokens, and sensitive artifacts |
| `cron` | Enumerate cron jobs, system cron directories, user crontabs, and at queues |
| `systemd` | Enumerate services, timers, failed units, and enabled startup units |
| `mounts` | Enumerate mounts, bind mounts, NFS/SMB, container mounts, and writable/executable mount points |
| `history` | Collect shell history, package manager logs, and recent login activity |

### Windows Plugins

| Plugin | Description |
|--------|-------------|
| `virtualization` | Aggressive VM, container, orchestration, and cloud detection with multi-layer confidence scoring |
| `shares` | Enumerate SMB shares, administrative shares, mapped drives, and network hosts |
| `adinfo` | Domain membership, domain controllers, forest/trusts, and organizational units |
| `services` | Windows services, startup types, binaries, service accounts, and notable configurations |
| `scheduledtasks` | Scheduled tasks, triggers, execution context, and task actions |
| `registry` | Autoruns, Run keys, startup locations, and installed software |
| `eventlogs` | Security, System, Application, and PowerShell log summaries |
| `defender` | Windows Defender status, exclusions, ASR rules, and installed security products |
| `certificates` | Certificate stores, code-signing certs, and enterprise certificates |

### Cross-Platform Plugins

| Plugin | Description |
|--------|-------------|
| `virtualization` | Aggressive VM, container, orchestration, and cloud detection |
| `privesccheck` | Automatic LinPEAS (Linux) or WinPEAS (Windows) privilege escalation enumeration |

## Privilege Escalation Enumeration (`privesccheck`)

The `privesccheck` plugin automatically selects the correct PEAS tool based on session platform — operators never choose between LinPEAS and WinPEAS manually.

| Target | Tool | Local path (default) |
|--------|------|----------------------|
| Linux / Unix | LinPEAS | `tools/privesc/linpeas.sh` |
| Windows | WinPEAS | `tools/privesc/winPEAS.bat` or `winPEASx64.exe` |

Override paths with `TORNADOREVC2_LINPEAS`, `TORNADOREVC2_WINPEAS`, or `TORNADOREVC2_PRIVESC_DIR`.

**In-memory execution:**

- **Linux:** Pipes base64-decoded `linpeas.sh` directly into `bash` stdin — no script file on disk. Very large scripts fall back to `/dev/shm` staging with automatic removal after execution.
- **Windows:** Decodes WinPEAS in PowerShell, runs via `cmd /c` or staged `.exe`, and deletes temporary artifacts immediately in a `finally` block.

**Output:** Live streaming to the terminal, full output saved under `logs/<session>/plugins/`, plus JSON metadata (tool, duration, exit code, success/failure). Tool contents are never logged.

```bash
# Place LinPEAS / WinPEAS in tools/privesc/ first
run privesccheck 1
```

## Aggressive Virtualization & Container Detection

The `virtualization` plugin performs deep multi-layer detection — not a single heuristic check. It combines independent signals into a weighted confidence score and lists every indicator that contributed.

### Linux Detection

Detects and enumerates: Docker, Podman, Kubernetes, containerd, CRI-O, LXC/LXD, systemd-nspawn, WSL, KVM, VMware, VirtualBox, Hyper-V, Xen, QEMU, OpenVZ/Virtuozzo, and cloud VMs (AWS, Azure, GCP, OCI, DigitalOcean).

**Techniques used:**

- `/proc/1/cgroup`, `/proc/self/cgroup`, `/proc/self/mountinfo`, `/proc/self/status`
- `/proc/cpuinfo`, `/proc/modules`, `/proc/xen`, `/proc/cmdline`
- `/sys/class/dmi/id/*`, `/sys/hypervisor`
- `/.dockerenv`, `/run/.containerenv`, runtime sockets
- Namespace inspection (pid, mnt, net, uts)
- cgroup v1/v2 analysis, mount namespace analysis
- Cloud metadata endpoints (non-blocking, short timeout)
- Docker socket accessibility testing
- Privileged container detection via capabilities
- Nested virtualization and sandbox heuristics

### Windows Detection

Detects: Hyper-V, VMware, VirtualBox, KVM/QEMU, Xen, WSL, Docker Desktop, containerd, Kubernetes, Windows containers, and cloud environments.

**Techniques used:**

- PowerShell, WMI/CIM, registry, services, drivers
- Device enumeration, SMBIOS/BIOS vendor strings
- Hyper-V guest parameters, Docker engine pipe
- Cloud metadata endpoints (AWS, Azure, GCP)
- Sandbox and analysis VM heuristics

### Example Output

```text
Environment
----------------------
Type:                  Docker Container
Runtime:               Docker
Orchestrator:          Kubernetes
Namespace:             production
Node:                  worker-02
Container ID:          8a1b2c3d4e5f
Host Relationship:     container on host
Host Access:           Docker socket exposed and accessible
Container Privileges:  Standard/non-privileged
Nested Virtualization: Not detected
Confidence:            98%

Indicators
----------
- /.dockerenv present
- docker hierarchy in cgroup
- /var/run/docker.sock accessible (host bridge risk)
- kubepods cgroup hierarchy
- K8s service account token

Detections
-----------
  docker               yes (40%)
    - /.dockerenv present
    - /var/run/docker.sock accessible (host bridge risk)
  kubernetes           yes (45%)
    - kubepods cgroup hierarchy
```

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
| `run <plugin> <ID>` | Execute a plugin on a session |
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
```

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
# After a shell connects
switch 1
sysinfo --stealth
exit

# Run enumeration plugins from the main menu
run virtualization 1
run secrets 1
run systemd 1

# Privilege escalation (place PEAS scripts in tools/privesc/ first)
run privesccheck 1

# Windows target
run adinfo 2
run services 2
run defender 2
run eventlogs 2
```

## TLS Certificate Generation

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

## Changelog

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
