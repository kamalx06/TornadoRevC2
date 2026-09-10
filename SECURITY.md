# Security Policy

**Legal Disclaimer:** This framework is designed exclusively for authorized security assessments, red teaming, and post‑exploitation research on systems you explicitly own or have contractual permission to test. I do not authorize or support any illegal or unethical use. You are solely responsible for your actions when using this software.

## Supported Versions

This project does not use version numbers or release tags. All updates are pushed directly as commits to the `main` branch.

- The **latest commit on `main`** is always the supported version for security fixes.
- If you are pinned to a specific older commit, please update to the latest commit to receive patches.

## Reporting a Vulnerability (Framework Flaws)

In this post‑exploitation framework, a "security vulnerability" means a flaw in **handler code** that compromises **your operational security (OPSEC)**, the **integrity of your operator host**, or the **stability of your C2 infrastructure**.

Specifically, I consider the following categories as security-critical code flaws:

- **Target-to-Operator attacks:** A compromised or malicious target manipulating its shell output to attack *you*—for example, sending malformed responses that exhaust memory (DoS), injecting terminal escape sequences (`\x1b`) to spoof output or clear your screen, or streaming massive JSON payloads to crash the parser.

- **Credential exposure (Logging & Process Lists):** The handler failing to redact sensitive data passed via plugins like `make_token` or `runas`. This includes:
  - Logging cleartext passwords, NTLM hashes, or API keys to `logs/` via `session.log_command()`.
  - Exposing those same credentials as plaintext arguments to external subprocesses (e.g., SSH, netexec), making them visible to any local user on the operator machine via `ps aux`.

- **Supply-Chain / Self-Update Poisoning:** The `update` command strictly pulls from the official GitHub origin (`kamalx06/TornadoRevC2`) to prevent malicious remote redirection. However, it does **not** currently verify GPG signatures on commits or tags. If my GitHub account is compromised, an attacker could push malicious code directly to the official repository, and your handler would fetch and execute it without warning. I recommend operators manually review `git log` before running `update` on critical engagements.

- **Insecure Command Construction (Operator‑Accidental Injection):** Failure to properly sanitize user‑supplied arguments (e.g., `filesearch` path strings, `upload`/`download` remote filenames) before passing them to `session.run_shell()`. This could allow an operator to accidentally (or a malicious external plugin to intentionally) inject destructive shell commands on the target. This is primarily an OPSEC risk rather than a target‑side attack.

- **Path Traversal via Target Metadata:** Session directories are created using the target's reported hostname (e.g., `logs/001_user@hostname_...`). A compromised target with a malicious hostname (e.g., `../../tmp/evil`) could force the handler to write logs outside the intended directory, potentially overwriting sensitive files on your operator machine.

- **Plugin Loading Vulnerabilities:** Flaws in the plugin-loading mechanism that allow an attacker to load, execute, or substitute a plugin without the operator's intended action. This includes unauthorized plugin execution, loading plugins from unintended locations, or bypassing plugin validation.

- **Rogue Client Connections (Resource Exhaustion):** The TCP/TLS listener accepts incoming connections without an initial handshake or pre-shared secret. While unauthenticated clients cannot hijack authenticated sessions, malicious clients may consume handler resources such as file descriptors or memory, inject unwanted data into logs, or trigger parser edge cases. Reports should demonstrate a meaningful security or availability impact.

**If you find something like this, you can report through:**

1. **Preferred:** Use GitHub's **"Private vulnerability reporting"** feature (go to the repo's "Security" tab → "Report a vulnerability"). This keeps all details confidential until I publish a fix.
2. **Alternative:** If that's unavailable, open a **GitHub Issue** with the `security` label, or email me directly at `kamalx06github@gmail.com`.
3. I will acknowledge your report within **48 hours**.
4. I will investigate and give you a status update within **5 business days**.
5. If I accept the vulnerability:
   - I will push a fix to `main` as soon as possible.
   - I will credit you in the commit (unless you want to stay hidden).
6. If I decline the report:
   - I will clearly explain why (e.g., it requires local access that an attacker already has, it's a feature, or it's out of scope).

## External Plugin Trust

External plugins execute as Python code within the operator process and have the same privileges as the handler.

Operators should only load plugins from trusted sources.

A malicious plugin intentionally loaded by an operator is **not considered a framework vulnerability**. However, vulnerabilities in the plugin-loading mechanism that allow unauthorized or unintended code execution are considered security issues as described above.

## Reporting Other Bugs (Modules & Execution)

Because my modules rely on **native commands that already exist on the target**, they may behave differently depending on the target OS, available tools, or command syntax.

For general bugs, such as:
- A module failing to run on a specific OS/version.
- Output not parsing correctly (e.g., encoding issues).
- Connection instability or session drops.
- Help text or UI glitches.
- Or any other non-security bug.

**Please just open a regular GitHub Issue** (without the `security` label). Include:
- The target OS and CPU architecture.
- The operator OS, Python version and CPU architecture.
- The exact command or module you ran.
- Any error messages or logs returned.

## Operator OPSEC Warning

The framework stores commands, plugin output, session metadata, and other data received from targets in the `logs/` directory.

Because targets may be compromised, logged data must be considered potentially attacker-controlled as well as sensitive.

Logs may contain:

- Internal IP addresses.
- Usernames.
- Hostnames.
- File paths.
- Credentials or authentication material.
- Terminal control characters.
- Maliciously crafted output.

Do not execute, render, or otherwise process untrusted log data in security-sensitive environments without appropriate precautions.

Never publicly share unredacted engagement logs. When reporting a non-security bug, sanitize sensitive and identifying information before including log excerpts.

I appreciate every report—they make the framework more reliable for everyone using it ethically!
