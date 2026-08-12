"""Linux cron and scheduled execution enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, glob, subprocess
MS="''' + PLUGIN_MARK_START + r'''"; ME="''' + PLUGIN_MARK_END + r'''"
entries = []
paths = glob.glob('/etc/cron.*/*') + glob.glob('/etc/cron.d/*') + ['/etc/crontab']
for p in paths:
    if os.path.isfile(p):
        try:
            with open(p, 'r', errors='ignore') as f:
                for i,line in enumerate(f, 1):
                    line=line.strip()
                    if line and not line.startswith('#'):
                        entries.append({'source': p, 'line': i, 'entry': line[:200]})
        except Exception:
            pass
# user crontabs
for p in glob.glob('/var/spool/cron/crontabs/*') + glob.glob('/var/spool/cron/*'):
    if os.path.isfile(p):
        try:
            with open(p, 'r', errors='ignore') as f:
                for i,line in enumerate(f, 1):
                    line=line.strip()
                    if line and not line.startswith('#'):
                        entries.append({'source': p, 'line': i, 'entry': line[:200]})
        except Exception:
            pass
# at jobs
at_list = ''
try:
    at_list = subprocess.check_output(['atq'], stderr=subprocess.DEVNULL, text=True, timeout=3)
except Exception:
    pass
result = {
    'summary': {'cron_entries': len(entries), 'at_jobs': len(at_list.splitlines()) if at_list else 0},
    'cron_jobs': entries[:100],
    'at_queue': at_list.splitlines()[:20] if at_list else [],
}
print(MS + json.dumps(result, separators=(',', ':')) + ME)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(name='cron', platforms=['linux', 'unix'], description='Enumerate cron jobs, crontabs, and scheduled execution')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'cron', build_command, None, format_generic_report, timeout=25.0)
