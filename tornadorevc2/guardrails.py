"""Always-on guardrails.

These run unconditionally. The framework refuses to operate on hosts that
look like production, domain controllers, or test infrastructure.
"""

import re


_DENY_HOSTNAMES = {
    'localhost', 'sandbox', 'test-vm', 'testvm', 'kali', 'ubuntu',
    'metasploitable', 'dvwa',
}

_DENY_PATTERNS = [
    re.compile(r'prod', re.I),
    re.compile(r'prd', re.I),
    re.compile(r'^dc\d', re.I),
    re.compile(r'\.corp\.', re.I),
]


def check_host_guardrails(sysinfo: dict) -> tuple:
    """Return (ok, reason). ok=False means do not operate on this host."""
    if not sysinfo:
        return True, ''
    host = (sysinfo.get('hostname') or '').strip().lower()
    domain = (sysinfo.get('domain') or '').strip().lower()

    if host in _DENY_HOSTNAMES:
        return False, f"hostname '{host}' is on the deny list"

    for pat in _DENY_PATTERNS:
        if host and pat.search(host):
            return False, f"hostname matches production pattern: {pat.pattern}"
        if domain and pat.search(domain):
            return False, f"domain matches production pattern: {pat.pattern}"

    return True, ''