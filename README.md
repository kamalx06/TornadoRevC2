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

### Advanced Multi-Client Session Handling
- Handles multiple shells simultaneously
- Automatic unique session ID assignment
- Live session status tracking
- Safe disconnect detection
- Thread-safe client management

### Fully Interactive Operator Terminal
- Real interactive shell per client
- Clean, colorized prompts
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

### Stability & Reliability
- Non-blocking socket I/O (`select`)
- Adaptive read timeouts
- Graceful handling of unstable shells
- Automatic cleanup on disconnect
- Designed for long-running handler use

### Operator Commands

| Command      | Description                        |
|--------------|------------------------------------|
| status       | Show active reverse shell sessions |
| switch <ID>  | Interact with a specific shell     |
| kill <ID>    | Terminate a shell session          |
| payloads     | Display the payload list           |
| clear / cls  | Clear screen                       |
| help         | Show help menu                     |
| exit / quit  | Shut down the handler              |

### Session Command & Output Logging
- A unique session ID is generated when a session is opened
- Every command sent to target and its output are logged locally for further analysis

## TLS Certificate Generation
```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -keyout server.key \
  -out server.pem
```

## Future Enhancements
- Session Renaming 
- Chunked File Upload & Download
- File Integrity Verification
- File Transfer Progress Indicators
