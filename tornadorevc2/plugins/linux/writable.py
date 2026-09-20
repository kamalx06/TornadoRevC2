from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ._helpers import build_linux_collector_command
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


def _linux_collector_source():
    return r'''
import glob
import os
import subprocess

result = {
    'summary': {},
    'path_dirs': [],
    'path_writable_files': [],
    'cron': [],
    'systemd': [],
    'init': [],
    'profile': [],
    'ld_conf': [],
    'sensitive_files': [],
    'logrotate': [],
    'mail': [],
    'docker': {},
    'findings': [],
}


def is_writable(path):
    try:
        return os.path.exists(path) and os.access(path, os.W_OK)
    except Exception:
        return False


def note(kind, path, detail=''):
    result['findings'].append({
        'kind': kind,
        'path': path,
        'detail': detail,
    })


# --- PATH directories ---
path_env = os.environ.get('PATH', '')
for d in path_env.split(':'):
    if not d:
        continue
    writable = is_writable(d)
    result['path_dirs'].append({'dir': d, 'writable': writable})
    if writable:
        note('writable_path_dir', d)
        try:
            count = 0
            for name in sorted(os.listdir(d)):
                full = os.path.join(d, name)
                if os.path.isfile(full) and is_writable(full):
                    result['path_writable_files'].append(full)
                    count += 1
                    if count >= 20:
                        break
        except Exception:
            pass


# --- Cron ---
for p in ('/etc/crontab', '/etc/anacrontab'):
    if is_writable(p):
        result['cron'].append(p)
        note('writable_cron', p)

for pattern in ('/etc/cron.d/*', '/etc/cron.hourly/*', '/etc/cron.daily/*',
                '/etc/cron.weekly/*', '/etc/cron.monthly/*',
                '/var/spool/cron/crontabs/*', '/var/spool/cron/*'):
    for p in glob.glob(pattern)[:30]:
        if is_writable(p):
            result['cron'].append(p)
            note('writable_cron', p)


# --- Systemd units ---
for base in ('/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
    if not os.path.isdir(base):
        continue
    try:
        for name in os.listdir(base)[:200]:
            if not (name.endswith('.service') or name.endswith('.timer')):
                continue
            full = os.path.join(base, name)
            if is_writable(full):
                result['systemd'].append(full)
                note('writable_systemd', full)
                if len(result['systemd']) >= 30:
                    break
    except Exception:
        continue
    if len(result['systemd']) >= 30:
        break


# --- Init scripts ---
for base in ('/etc/init.d', '/etc/rc.d', '/etc/rc.local'):
    if os.path.isfile(base):
        if is_writable(base):
            result['init'].append(base)
            note('writable_init', base)
    elif os.path.isdir(base):
        try:
            for name in os.listdir(base)[:80]:
                full = os.path.join(base, name)
                if os.path.isfile(full) and is_writable(full):
                    result['init'].append(full)
                    note('writable_init', full)
        except Exception:
            pass


# --- Profile scripts ---
for pattern in ('/etc/profile', '/etc/profile.d/*', '/etc/bash.bashrc',
                '/etc/bashrc', '/etc/zsh/zshrc'):
    for p in glob.glob(pattern)[:50]:
        if is_writable(p):
            result['profile'].append(p)
            note('writable_profile', p)


# --- ld.so config ---
for pattern in ('/etc/ld.so.conf', '/etc/ld.so.conf.d/*'):
    for p in glob.glob(pattern)[:30]:
        if is_writable(p):
            result['ld_conf'].append(p)
            note('writable_ld_conf', p)


# --- Sensitive system files ---
for p in ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow'):
    if is_writable(p):
        result['sensitive_files'].append(p)
        note('writable_sensitive', p, 'direct credential file write possible')


# --- logrotate ---
for p in glob.glob('/etc/logrotate.d/*')[:40]:
    if is_writable(p):
        result['logrotate'].append(p)
        note('writable_logrotate', p)


# --- Mail spools ---
for pattern in ('/var/mail/*', '/var/spool/mail/*'):
    for p in glob.glob(pattern)[:20]:
        if os.path.isfile(p) and is_writable(p):
            result['mail'].append(p)
            note('writable_mail', p)


# --- Docker socket ---
for p in ('/var/run/docker.sock', '/run/docker.sock'):
    if os.path.exists(p):
        result['docker'] = {'path': p, 'writable': is_writable(p)}
        if result['docker']['writable']:
            note('writable_docker_socket', p, 'docker socket writable = root equivalent')
        break


result['summary'] = {
    'path_dirs_checked': len(result['path_dirs']),
    'writable_path_dirs': sum(1 for e in result['path_dirs'] if e['writable']),
    'writable_path_files': len(result['path_writable_files']),
    'writable_cron': len(result['cron']),
    'writable_systemd': len(result['systemd']),
    'writable_init': len(result['init']),
    'writable_profile': len(result['profile']),
    'writable_ld_conf': len(result['ld_conf']),
    'writable_sensitive_files': len(result['sensitive_files']),
    'writable_logrotate': len(result['logrotate']),
    'writable_mail': len(result['mail']),
    'docker_socket_writable': result['docker'].get('writable', False),
    'total_findings': len(result['findings']),
}

_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


@plugin.command(
    name='writable',
    platforms=['linux', 'unix'],
    description='Writable filesystem audit: PATH, cron, systemd, init, profile, ld.so, docker socket',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'writable',
        _build_linux_command,
        None,
        format_generic_report,
        timeout=45.0,
    )