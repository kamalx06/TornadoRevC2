# TORNADOREVC2 — Professional Reverse Shell Handler

TornadoRevC2 is a professional, universal reverse shell handler written in Python. It is not a full C2 framework, but a highly capable reverse shell handler that combines rock-solid shell handling with selected C2-style management features — including an extensible plugin system for operator-focused enumeration tasks.

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
- An extensible plugin platform for on-demand operator tasks

### It is not:

- Not a beacon-based C2
- Not a post-exploitation framework
- No persistence, implants, or automated tasking

## Project Structure

```
tornadorevc2/
  constants.py          # Shared constants and command lists
  sysinfo.py            # Host information collection and display
  session_log.py        # Per-session directory logging
  terminal_sanitize.py  # Strip control sequences from logged/exported output
  terminal.py           # PTY/TTY, resize, and signal handling
  transfer.py           # Chunked file transfers with resume support
  payload_exec.py       # In-memory payload transfer and execution
  clipboard.py          # Remote clipboard read
  tunnel.py             # SOCKS5 internal network pivoting
  session_registry.py   # Session persistence and reconnect support
  export.py             # HTML transcript report generation
  payloads.py           # Dynamic payload catalog
  handler.py            # Main server and session logic
  plugins/
    __init__.py         # Plugin API exports
    api.py              # SessionContext and @plugin.command decorator
    manager.py          # Runtime plugin loading and execution
    loader.py           # Dynamic module discovery
    linux/
      virtualization.py # Linux container/VM detection collector
    windows/
      virtualization.py # Windows container/VM detection collector
    shared/
      common.py         # Shared formatting and platform helpers
      virtualization.py # Virtualization plugin entry point
tornadorevc2.py         # Entry point
plugins/                # Optional external plugin directory (operator-provided)
```

## Core Features

### Dual TCP & TLS Reverse Shell Listener

TornadoRevC2 runs TCP and TLS reverse shell listeners at the same time, allowing it to handle both plaintext and encrypted reverse shells from a single handler.

- Plain TCP and TLS encrypted listeners
- Separate ports for each protocol
- Supports high numbers of concurrent connections
- TLS connection uses strong ciphers and enforces TLS 1.2+ for secure shells against MITM or downgrade attacks by blue teams

### Universal Reverse Shell Compatibility

Handles most reverse shell types (TCP, TLS, UNIX, Windows, PTY, unstable shells) without assumptions about the target.

### Dynamic Payload Arsenal

TornadoRevC2 includes a large, categorized reverse shell payload list.

- Payloads are originally sourced from revshells.com
- Each payload has been manually reviewed, rewritten, and adapted for this project
- Host and port values are injected dynamically from the server's configuration
- Payloads automatically update when listener settings change

This allows rapid deployment without editing payloads manually during operations.

### Plugin / Module Architecture

TornadoRevC2 supports runtime-extensible plugins without modifying the core handler. Built-in plugins ship under `tornadorevc2/plugins/`; operators can also drop external plugin modules into a top-level `plugins/` directory (or set `TORNADOREVC2_PLUGIN_DIR`).

Plugins register commands via a simple decorator:

```python
from tornadorevc2.plugins import plugin, SessionContext

@plugin.command(
    name="virtualization",
    platforms=["linux", "windows"],
    description="Detect virtualization, containers, and orchestration environments",
)
def run(session: SessionContext, args):
    output = session.run_shell("uname -a")
    session.log_plugin_result("virtualization", output)
    return 0
```

The `SessionContext` API exposes:

| Capability | Method / Property |
|------------|-------------------|
| Session metadata | `session_id`, `platform`, `sysinfo`, `identity`, `addr`, `tls` |
| Shell execution | `run_shell()`, `run_marked()` |
| File transfer | `upload()`, `download()`, `verify_remote()` |
| Logging | `log_event()`, `log_command()`, `log_plugin_result()` |
| Host info | `collect_sysinfo()`, `get_cwd()` |
| Terminal output | `print()` with handler color support |

Plugin management commands:

| Command | Description |
|---------|-------------|
| `plugins` / `plugins list` | List registered plugins |
| `plugins list --verbose` | Show module paths and load state |
| `plugins load <name>` | Load a plugin at runtime |
| `plugins unload <name>` | Unload or disable a plugin |
| `plugins reload <name>` | Reload a plugin module |
| `plugins info <name>` | Show plugin details |
| `run <plugin> <session_id>` | Execute a plugin on an active session |

Plugins are loaded dynamically — no handler restart required. The plugin registry is thread-safe for concurrent session operations.

Example:

```bash
plugins list
plugins info virtualization
run virtualization 1
```

### Virtualization & Container Detection Plugin

The built-in `virtualization` plugin quickly determines whether a compromised host is running inside a virtual machine, container, or orchestration platform. Results are displayed in the terminal and saved under the session log directory (`logs/<session>/plugins/`).

**Linux detection** covers Docker, Podman, Kubernetes, LXC/LXD, systemd-nspawn, WSL, KVM, VMware, VirtualBox, Hyper-V, Xen, and QEMU using multiple techniques:

- `/proc/1/cgroup` and `/proc/self/mountinfo`
- `/.dockerenv`, `/run/.containerenv`
- Container runtime sockets
- Environment variables and systemd container markers
- DMI/SMBIOS data, CPU virtualization flags, and loaded kernel modules

**Windows detection** covers Hyper-V, VMware, VirtualBox, KVM, QEMU, Xen, Docker Desktop, WSL, and Kubernetes-related components using PowerShell, WMI/CIM, registry keys, services, and drivers.

Example output:

```text
Environment
-----------
Type:        Docker Container
Container ID:8a1b2c3d4e5f
Runtime:     docker
Orchestrator:Kubernetes
Namespace:   production
Node:        worker-02
Host Relationship: container on host
Virtualization:
Confidence:  high

Detections
-----------
  docker           yes (high)
    - /.dockerenv present
    - docker in cgroup
  kubernetes       yes (high)
    - KUBERNETES_SERVICE_HOST=10.96.0.1
```

### Manual Host Information Collection

TornadoRevC2 collects host information **only when the operator explicitly executes the `sysinfo` command**, providing better operational stealth by avoiding automatic enumeration when a new session connects.

- Works on Linux, Unix, and Windows targets via inline Python/shell (Unix) or PowerShell (Windows)
- Executed only on demand through the `sysinfo` command
- **Stealth mode (default):** minimal process footprint; stdlib and `/proc` on Linux; essential fields only
- **Full mode (`--full`):** complete dataset with external utilities when needed
- Updates the session object with the latest host information
- Displays the results in grouped sections and saves them to the session log directory for later reference

Collected fields are organized into five sections when displayed:

| Section | Linux / Unix | Windows |
|---------|----------------------|---------|
| **Identity** | hostname, FQDN, username, home, shell, UID/GID, root status | hostname, FQDN, username, domain, home, admin status, logged-on user |
| **System** | OS, release, version, kernel, architecture, platform | OS, release, build, architecture, platform, manufacturer, model, domain-joined, system directory |
| **Resources** | CPU count, memory, disk (CWD drive), uptime | CPU name/count, memory, disk (current drive), uptime |
| **Network** | IP addresses, timezone, locale | IP addresses, timezone, locale |
| **Session** | CWD, PID, Python version | CWD, PID, PowerShell version |

On Linux and Unix targets without Python available, a lightweight shell fallback still returns hostname, username, OS, and CWD.

### Advanced Multi-Client Session Handling

- Handles multiple shells simultaneously
- Automatic unique session ID assignment
- Live session status tracking with host/user/OS details
- Safe disconnect detection
- Thread-safe client management
- **Session persistence:** metadata preserved on disconnect; restored when the same client reconnects
- **Stable fingerprinting:** hostname, username, persistent machine ID (`/etc/machine-id` or Windows `MachineGuid`), and shell type
- **`sessions` / `reconnects` commands** for registry and reconnect history

### Internal Network Pivoting (SOCKS5)

Route operator tools through a connected session to reach internal hosts on the target network.

- **SOCKS5 proxy:** pivot through a session with proxychains, Nmap, Impacket, NetExec, browsers, RDP clients, and similar tools
- Multiple simultaneous SOCKS proxies with unique IDs
- Remote tunnel agent deployed in-memory on first use (Python on target)
- Proxies auto-stop on session disconnect

| Command | Description |
|---------|-------------|
| `socks <ID> <listen_port>` | Start SOCKS5 proxy via session |
| `tunnels` | List active SOCKS proxies |
| `socks stop <proxy_id>` | Stop a SOCKS proxy |

Inside a client shell, omit `<ID>`: `socks 1080`.

Example:

```bash
socks 1 1080
proxychains nmap -sT -Pn 10.10.10.0/24
curl --socks5 127.0.0.1:1080 http://internal-server/
```

### Session Reconnect Support

When a session drops and the same host reconnects, TornadoRevC2 restores session ID, custom name, sysinfo cache, existing log directory, connect count, and fingerprint tracking.

On connect, a lightweight stealth identity probe reads hostname, username, and the system machine identifier. Registry stored at `logs/.registry/sessions.json`.

### Session Transcript Export

Generate clean, self-contained HTML reports for documentation or pentest deliverables.

- **`export <ID>`** from the main menu exports the selected session transcript
- Works for active and disconnected sessions tracked in the registry
- Command output in logs and exports is sanitized (ANSI/OSC/bracketed-paste stripped)

### Fully Interactive Operator Terminal

- Real interactive shell per client
- Clean, colorized prompts with `user@hostname` context when available
- Background sessions without termination
- Instant switching between shells
- PTY upgrade, terminal resize propagation, and remote Ctrl+C handling

### In-Memory Payload Execution

Execute scripts and binaries on the target without persistent disk artifacts whenever technically possible.

- **Python (`.py`):** `exec()` via `python -c` after chunked transfer
- **PowerShell (`.ps1`):** encoded/inline invocation
- **Windows PE (`.exe`):** reflective in-memory loader with temp-file fallback
- **Linux ELF:** `memfd_create` + execution from `/proc/self/fd/`

### Remote Clipboard Interaction

Read the remote desktop clipboard when a graphical session is available (Linux: wl-clipboard/xclip/xsel; Windows: PowerShell/WinForms).

### Chunked File Upload & Download

Transfer files with resumable chunked transfers, SHA256 verification, and live progress indicators. Platform-aware chunk sizes (32 KB Unix, 4 KB Windows).

## Operator Commands

| Command | Description |
|---------|-------------|
| `status` / `ls` | Show active reverse shell sessions |
| `sessions` | Show tracked sessions (active + awaiting reconnect) |
| `reconnects` | Show session reconnect history |
| `switch <ID>` | Interact with a specific shell |
| `kill <ID>` | Terminate a shell session |
| `sysinfo <ID> [--stealth\|--full]` | Refresh and display host information |
| `run <plugin> <ID>` | Execute a plugin on a session |
| `plugins [list\|load\|unload\|reload\|info]` | Manage plugins |
| `runpy/runps/runexe/runelf <ID> <local>` | Transfer and execute payload in memory |
| `clipboard <ID>` | Read remote clipboard text |
| `rename` / `rn <ID> <name>` | Rename a session |
| `payloads` | Display the payload list |
| `upload [--resume] <ID> <local> <remote>` | Chunked upload with SHA256 verify |
| `download [--resume] <ID> <remote> <local>` | Chunked download with SHA256 verify |
| `verify/hash <ID> <remote>` | Check remote file size and SHA256 |
| `socks <ID> <listen_port>` | SOCKS5 proxy for internal pivoting |
| `tunnels` | List active SOCKS proxies |
| `export <ID>` | Export HTML session transcript report |
| `clear` / `cls` | Clear screen |
| `help` | Show help menu |
| `exit` / `quit` | Shut down the handler |

Inside a client shell (`switch <ID>`), omit the session ID for file transfer and session commands.

## Per-Session Logging

Every session gets its own dedicated directory under `logs/`:

```
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log      # Every command and its output
  sysinfo.json     # Host information snapshot
  transfers/       # Upload/download event logs
  executions/      # In-memory payload execution metadata
  plugins/         # Plugin result reports and raw data
```

- Commands and output are appended to `session.log` in real time
- Terminal control sequences are stripped from logged command output
- Plugin results are saved to `plugins/` with formatted reports and raw JSON data
- Session connect, disconnect, and reconnect events are recorded automatically

## Writing External Plugins

Place a Python module (or package) in the `plugins/` directory at the project root:

```
plugins/
  my_enum.py
```

```python
from tornadorevc2.plugins import plugin, SessionContext

@plugin.command(name="my_enum", platforms=["linux", "unix"], description="Custom enumeration")
def run(session: SessionContext, args):
    result = session.run_shell("id")
    session.print(result)
    session.log_plugin_result("my_enum", result)
    return 0
```

Load and run at runtime:

```bash
plugins load my_enum
run my_enum 2
```

## Usage

```bash
python tornadorevc2.py
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 -c server.pem -k server.key
```

## TLS Certificate Generation

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

## Changelog

- Plugin / Module Architecture (Added)
- Virtualization & Container Detection Plugin (Added)
- Session Log and Export Control-Sequence Sanitization (Added)
- Session Transcript HTML Export (Added)
- SOCKS5 Internal Network Pivoting (Added)
- Session Persistence and Reconnect Support (Added)
- In-Memory Payload Execution (Added)
- Remote Clipboard Interaction (Added)
- Sysinfo Stealth and Full Modes (Added)
- Expanded Host Information Collection (Added)
- Session Renaming (Added)
- Chunked File Upload & Download (Added)
- File Integrity Verification (Added)
- File Transfer Progress Indicators (Added)
- Enhanced PTY/TTY Terminal Handling (Added)
- Per-Session Directory Logging (Added)
- Resumable File Transfers (Added)
- Modular Package Structure (Added)
