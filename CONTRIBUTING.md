# Contributing to TornadoRevC2

**Legal Disclaimer:** TornadoRevC2 is a dual-use post-exploitation framework intended for authorized security testing and research. Its features can also be misused, and the project cannot determine the operator’s intent.

Use TornadoRevC2 only on systems you own or have explicit permission to test. You are responsible for your actions and for following all applicable laws. I do not support or authorize illegal or unethical use.

By contributing to TornadoRevC2, you agree that your work is intended for lawful and authorized security testing, research, or other legitimate purposes. Contributions primarily intended to enable unauthorized access or cause harm will be rejected. Dual-use functionality by itself is not a reason for rejection, since security research often involves capabilities that can be used for both legitimate and malicious purposes.

---

## Ways to Contribute

Not every contribution has to be code. The most useful contributions roughly in order of impact:

1. **Bug reports** with reproducible steps (see [Reporting Bugs](#reporting-bugs)).
2. **Plugin contributions** — new enumeration, operational, or platform-specific plugins.
3. **Fixes for existing plugins** that break on specific OS versions or command variants.
4. **Documentation improvements** — README, plugin dev guide, inline docstrings.
5. **Code review** on open pull requests.
6. **Testing on different environments** (different Linux distros, Windows versions, shells).
7. **Security reports** — Do not open a public issue for security flaws.

If you're unsure whether something is worth contributing, open an issue first and describe what you have in mind. I'd rather discuss the approach before you spend time writing code that may not fit the project's direction.

---

## Reporting Bugs

Before opening an issue, check whether it's a security issue or a general bug.

**Security bugs** — do not open a public issue. Report privately through the process in [SECURITY.md](SECURITY.md).

**General bugs** — because the modules rely on native commands that already exist on the target, they may behave differently depending on the target OS, available tools, or command syntax. General bugs include:

- A module failing to run on a specific OS or version.
- Output not parsing correctly (e.g., encoding issues).
- Connection instability or session drops.
- Help text or UI glitches.
- Any other non-security bug.

For these, open a regular GitHub Issue (without the `security` label). Include:

- The target OS and CPU architecture.
- The operator OS, Python version, and CPU architecture.
- The exact command or module you ran.
- Any error messages or logs returned.

**Sanitize before posting.** Logs and screenshots may contain internal IPs, usernames, hostnames, file paths, credentials, terminal control characters, or maliciously crafted output from compromised targets. Remove all of that before pasting anything into a public issue.

If you're unsure whether something is a security bug or a general bug, report it privately through the process in [SECURITY.md](SECURITY.md). It's better to over-report than to leak a real flaw into a public issue.

---

## Before You Start

### Development environment

Requirements:

- Python 3.7 or later
- OpenSSL (for TLS/mTLS certificate generation)
- Git (optional; needed for the `update` command)
- No third-party Python packages are required or used

```bash
git clone https://github.com/kamalx06/TornadoRevC2.git
cd TornadoRevC2
python3 tornadorevc2.py
```
