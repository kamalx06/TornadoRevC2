# TORNADOREVC2 — Professional Reverse Shell Handler
TornadoRevC2 is a professional, universal reverse shell handler written in Python. It is not a full C2 framework, but a highly capable reverse shell handler that combines rock-solid shell handling with selected C2 style management features.

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
  terminal.py     # PTY/TTY, resize, and signal handling
  transfer.py     # Chunked file transfers with resume support
  payloads.py     # Dynamic payload catalog
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

### Automatic Host Information Collection
When a shell connects, TornadoRevC2 automatically collects host details before the operator interacts with the session.
- Works on both Unix and Windows targets via inline Python (Unix) or PowerShell (Windows)
- Collected once at connect time and stored on the session
- Displayed immediately in the console in grouped sections and saved to the session log directory
- Reusable via the `sysinfo` command to refresh information at any time

Collected fields are organized into five sections when displayed:

| Section | Unix / Linux / macOS | Windows |
|---------|----------------------|---------|
| **Identity** | hostname, FQDN, username, home, shell, UID/GID, root status | hostname, FQDN, username, domain, home, admin status, logged-on user |
| **System** | OS, release, version, kernel, architecture, platform | OS, release, build, architecture, platform, manufacturer, model, domain-joined, system directory |
| **Resources** | CPU count, memory, disk (CWD drive), uptime | CPU name/count, memory, disk (current drive), uptime |
| **Network** | IP addresses, timezone, locale | IP addresses, timezone, locale |
| **Session** | CWD, PID, Python version | CWD, PID, PowerShell version |

On Unix targets without Python available, a lightweight shell fallback still returns hostname, username, OS, and CWD.

### Advanced Multi-Client Session Handling
- Handles multiple shells simultaneously
- Automatic unique session ID assignment
- Live session status tracking with host/user/OS details
- Safe disconnect detection
- Thread-safe client management

### Fully Interactive Operator Terminal
- Real interactive shell per client
- Clean, colorized prompts with `user@hostname` context when available
- Context aware session identification
- Background sessions without termination
- Instant switching between shells
- Individual shell termination

### Platform Detection & Smart Upgrades
- Automatic OS inference:
  - Linux / Unix / macOS
  - Windows
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
| `switch <ID>` | Interact with a specific shell |
| `kill <ID>` | Terminate a shell session |
| `sysinfo <ID>` | Refresh and display host information |
| `rename` / `rn <ID> <name>` | Rename a session |
| `payloads` | Display the payload list |
| `clear` / `cls` | Clear screen |
| `help` | Show help menu |
| `exit` / `quit` | Shut down the handler |

Inside a client shell (`switch <ID>`), omit the session ID for file transfer and session commands.

| Command | Description |
|---------|-------------|
| `sysinfo` | Refresh and display host information |
| `upload [--resume] <local> <remote>` | Push a local file to the target |
| `download [--resume] <remote> <local>` | Pull a remote file to the operator |
| `verify` / `hash <remote>` | Show remote file size and SHA256 |
| `help` | Show client-shell help |
| `exit` / `quit` | Return to the main menu |

### Per-Session Logging
Every session gets its own dedicated directory under `logs/`, named after the session (ID, user, hostname, IP, OS, and timestamp).

```
logs/001_user@hostname_192.168.1.10_unix_10-08-2026_143022/
  session.log      # Every command and its output
  sysinfo.json     # Host information snapshot
  transfers/       # Upload/download event logs
```

- Commands and output are appended to `session.log` in real time
- Initial and refreshed `sysinfo` data is saved to `sysinfo.json` (identity, system, resources, network, and session fields)
- Transfer results (complete, interrupted, hash mismatch) are logged under `transfers/`
- Session connect and disconnect events are recorded automatically

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
- Expanded Host Information Collection (Added)
- Session Renaming (Added)
- Chunked File Upload & Download (Added)
- File Integrity Verification (Added)
- File Transfer Progress Indicators (Added)
- Automatic Host Information Collection (Added)
- `sysinfo` Command (Added)
- Enhanced PTY/TTY Terminal Handling (Added)
- Per-Session Directory Logging (Added)
- Resumable File Transfers (Added)
- Modular Package Structure (Added)
