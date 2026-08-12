"""Linux secrets and credential artifact enumeration."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command


def _collector_source():
    return r'''
import json, os, re, glob
MS="''' + PLUGIN_MARK_START + r'''"; ME="''' + PLUGIN_MARK_END + r'''"
paths = [
    '/etc/passwd','/etc/shadow','/etc/sudoers','/etc/ssh/sshd_config',
    '/root/.ssh/id_rsa','/root/.ssh/id_ed25519','/root/.ssh/authorized_keys',
    os.path.expanduser('~/.ssh/id_rsa'), os.path.expanduser('~/.ssh/id_ed25519'),
    os.path.expanduser('~/.aws/credentials'), os.path.expanduser('~/.aws/config'),
    os.path.expanduser('~/.docker/config.json'), os.path.expanduser('~/.kube/config'),
    os.path.expanduser('~/.git-credentials'), os.path.expanduser('~/.netrc'),
    '/etc/mysql/my.cnf','/etc/postgresql/*/main/pg_hba.conf',
    '/var/lib/cloud/instance/user-data.txt','/var/lib/cloud/instance/vendor-data.txt',
]
env_keys = re.compile(r'(key|token|secret|password|passwd|credential|api[_-]?key|auth)', re.I)
findings = []
env_hits = []
for k,v in os.environ.items():
    if env_keys.search(k) and v and len(v) < 512:
        env_hits.append(k+'='+v[:120])
for p in paths:
    try:
        matches = glob.glob(p) if '*' in p else [p]
        for fp in matches:
            if os.path.isfile(fp) and os.access(fp, os.R_OK):
                st = os.stat(fp)
                findings.append({'path': fp, 'size': st.st_size, 'mode': oct(st.st_mode)[-3:]})
    except Exception:
        pass
# scan common config dirs lightly
for base in ('/etc', os.path.expanduser('~')):
    if not os.path.isdir(base):
        continue
    for root, dirs, files in os.walk(base):
        if root.count(os.sep) - base.count(os.sep) > 3:
            dirs[:] = []
            continue
        for fn in files:
            if fn.endswith(('.pem', '.key', '.env', '.conf', '.cfg', '.ini', 'credentials', 'secrets')):
                fp = os.path.join(root, fn)
                try:
                    if os.path.isfile(fp) and os.access(fp, os.R_OK) and os.path.getsize(fp) < 65536:
                        findings.append({'path': fp, 'size': os.path.getsize(fp), 'mode': oct(os.stat(fp).st_mode)[-3:]})
                except Exception:
                    pass
        if len(findings) > 120:
            break
result = {
    'summary': {'artifacts_found': len(findings), 'env_secrets': len(env_hits)},
    'files': findings[:100],
    'environment_variables': env_hits[:40],
}
print(MS + json.dumps(result, separators=(',', ':')) + ME)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(name='secrets', platforms=['linux', 'unix'], description='Search configs, env vars, SSH/cloud credentials, and sensitive artifacts')
def run(session: SessionContext, args):
    return run_collector_plugin(session, 'secrets', build_command, None, format_generic_report, timeout=40.0)
