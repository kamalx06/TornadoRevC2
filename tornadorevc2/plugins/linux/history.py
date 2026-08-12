"""Linux shell and command history enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, glob, subprocess
MS="''' + PLUGIN_MARK_START + r'''"; ME="''' + PLUGIN_MARK_END + r'''"
hist_files = []
candidates = [
    os.path.expanduser('~/.bash_history'), os.path.expanduser('~/.zsh_history'),
    os.path.expanduser('~/.sh_history'), os.path.expanduser('~/.history'),
    '/root/.bash_history', '/root/.zsh_history',
]
for p in glob.glob('/home/*/.bash_history') + glob.glob('/home/*/.zsh_history'):
    candidates.append(p)
for p in candidates:
    if os.path.isfile(p) and os.access(p, os.R_OK):
        try:
            with open(p, 'r', errors='ignore') as f:
                lines = f.readlines()[-40:]
            hist_files.append({'path': p, 'recent': [l.strip()[:200] for l in lines if l.strip()]})
        except Exception:
            pass
pkg_hist = []
for p in ('/var/log/apt/history.log', '/var/log/dnf.log', '/var/log/yum.log'):
    if os.path.isfile(p):
        try:
            with open(p, 'r', errors='ignore') as f:
                pkg_hist.append({'path': p, 'tail': f.readlines()[-15:]})
        except Exception:
            pass
last = ''
try:
    last = subprocess.check_output(['last', '-n', '15'], stderr=subprocess.DEVNULL, text=True, timeout=5)
except Exception:
    pass
result = {
    'summary': {'history_files': len(hist_files), 'package_logs': len(pkg_hist)},
    'shell_history': hist_files[:20],
    'package_manager_history': [{'path': x['path'], 'recent': [l.strip()[:160] for l in x['tail']]} for x in pkg_hist],
    'recent_logins': last.splitlines()[:15] if last else [],
}
print(MS + json.dumps(result, separators=(',', ':')) + ME)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(name='history', platforms=['linux', 'unix'], description='Collect shell history, package manager logs, and recent login activity')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'history', build_command, None, format_generic_report, timeout=25.0)
