"""Linux systemd journal and system event log enumeration."""

from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import subprocess

def sh(cmd, timeout=12):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def which(name):
    return bool(sh(f'command -v {name} 2>/dev/null').strip())

result = {'summary': {}, 'journal': {}, 'auth_events': [], 'kernel_events': [], 'service_failures': [], 'recent_errors': [], 'boots': []}

if not which('journalctl'):
    result['summary'] = {'journalctl': 'not available'}
    _emit(result)
else:
    usage = sh('journalctl --disk-usage 2>/dev/null').strip()
    result['journal']['disk_usage'] = usage or 'N/A'
    result['journal']['active'] = sh('systemctl is-active systemd-journald 2>/dev/null').strip() or 'N/A'

    boots = sh('journalctl --list-boots --no-pager 2>/dev/null')
    if boots.strip():
        result['boots'] = boots.splitlines()[-10:]

    for line in sh('journalctl -p err..alert -n 30 --no-pager -o short-iso 2>/dev/null').splitlines():
        if line.strip():
            result['recent_errors'].append(line.strip()[:220])

    auth_filter = 'sshd|sudo|su:|authentication|pam_|login|polkit|Failed password|Accepted'
    for line in sh(f'journalctl -n 200 --no-pager -o short-iso 2>/dev/null | grep -Ei "{auth_filter}" | tail -25').splitlines():
        if line.strip():
            result['auth_events'].append(line.strip()[:220])

    for line in sh('journalctl -k -n 25 --no-pager -o short-iso 2>/dev/null').splitlines():
        if line.strip():
            result['kernel_events'].append(line.strip()[:220])

    failed_units = []
    for line in sh('systemctl --failed --no-pager --no-legend 2>/dev/null').splitlines():
        parts = line.split(None, 4)
        if parts:
            failed_units.append({'unit': parts[0], 'state': ' '.join(parts[1:4]) if len(parts) > 3 else ''})
    result['service_failures'] = failed_units[:30]

    svc_fail = sh('journalctl -p err -u "*.service" -n 20 --no-pager -o short-iso 2>/dev/null')
    if svc_fail.strip():
        result['journal']['service_error_sample'] = svc_fail.splitlines()[:20]

    result['summary'] = {
        'journalctl': 'available',
        'recent_errors': len(result['recent_errors']),
        'auth_events': len(result['auth_events']),
        'kernel_events': len(result['kernel_events']),
        'failed_units': len(failed_units),
        'boots_listed': len(result['boots']),
    }

_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(
    name='journal',
    platforms=['linux', 'unix'],
    description='Summarize journalctl logs: authentication, kernel, service failures, and recent events',
)
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'journal', build_command, None, format_generic_report, timeout=45.0)
