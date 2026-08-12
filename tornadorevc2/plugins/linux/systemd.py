"""Linux systemd service and timer enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, subprocess
services = []
timers = []
failed = []
enabled = []

def run(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'ignore')
        return out
    except Exception:
        return ''

for line in run('systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null').splitlines():
    parts = line.split(None, 4)
    if len(parts) >= 5:
        services.append({'unit': parts[0], 'load': parts[1], 'active': parts[2], 'sub': parts[3], 'desc': parts[4][:120]})
for line in run('systemctl list-units --type=timer --all --no-pager --no-legend 2>/dev/null').splitlines():
    parts = line.split(None, 4)
    if len(parts) >= 5:
        timers.append({'unit': parts[0], 'load': parts[1], 'active': parts[2], 'sub': parts[3], 'desc': parts[4][:120]})
for line in run('systemctl --failed --no-pager --no-legend 2>/dev/null').splitlines():
    parts = line.split(None, 4)
    if parts:
        failed.append({'unit': parts[0], 'state': ' '.join(parts[1:4]) if len(parts) > 3 else ''})
for line in run('systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null').splitlines():
    parts = line.split()
    if parts:
        enabled.append({'unit': parts[0], 'state': parts[1] if len(parts) > 1 else 'enabled'})
result = {
    'summary': {'services': len(services), 'timers': len(timers), 'failed': len(failed), 'enabled': len(enabled)},
    'services': services[:80],
    'timers': timers[:40],
    'failed_units': failed[:30],
    'enabled_services': enabled[:60],
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(name='systemd', platforms=['linux', 'unix'], description='Enumerate systemd services, timers, failed units, and startup persistence')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'systemd', build_command, None, format_generic_report, timeout=45.0)
