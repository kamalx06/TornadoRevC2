"""Daemon process lifecycle: pid file, spawn, stop, already-running detection."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Optional

from . import auth
from .config import DaemonConfig


class DaemonAlreadyRunning(Exception):
    def __init__(self, pid: int, config: DaemonConfig):
        self.pid = pid
        self.config = config
        rs = config.reverse_shell
        super().__init__(
            f'Daemon already running (pid {pid}).\n'
            f'Reverse TCP listener: {rs.host}:{rs.tcp_port}\n'
            f'Reverse TLS listener: {rs.host}:{rs.tls_port}\n'
            'Use `tornadorevc2 restart` to change listener configuration, '
            'or `tornadorevc2 console` to attach.'
        )


def pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def read_pid(config: DaemonConfig) -> Optional[int]:
    if not os.path.exists(config.pid_path):
        return None
    try:
        with open(config.pid_path, 'r', encoding='utf-8') as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def load_saved_config(config: DaemonConfig) -> Optional[DaemonConfig]:
    if not os.path.exists(config.state_path):
        return None
    try:
        with open(config.state_path, 'r', encoding='utf-8') as handle:
            return DaemonConfig.from_mapping(json.load(handle))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def write_runtime_state(config: DaemonConfig, pid: int) -> None:
    auth.ensure_runtime_dir(config.persistence.runtime_dir)
    with open(config.pid_path, 'w', encoding='utf-8') as handle:
        handle.write(str(pid))
    try:
        os.chmod(config.pid_path, 0o600)
    except OSError:
        pass
    with open(config.state_path, 'w', encoding='utf-8') as handle:
        json.dump(config.as_dict(), handle, indent=2)
    try:
        os.chmod(config.state_path, 0o600)
    except OSError:
        pass


def clear_runtime_state(config: DaemonConfig) -> None:
    for path in (config.pid_path, config.management.socket_path):
        try:
            os.remove(path)
        except OSError:
            pass
    _cleanup_temp_directories()


def _cleanup_temp_directories() -> None:
    """Clean up tornado-* temporary directories in /tmp that may have been left behind."""
    temp_dir = tempfile.gettempdir()
    try:
        for entry in os.listdir(temp_dir):
            if entry.startswith('tornado-'):
                entry_path = os.path.join(temp_dir, entry)
                try:
                    if os.path.isdir(entry_path):
                        shutil.rmtree(entry_path, ignore_errors=True)
                except OSError:
                    pass
    except OSError:
        pass


def running_daemon(config: DaemonConfig) -> Optional[tuple[int, DaemonConfig]]:
    saved = load_saved_config(config) or config
    pid = read_pid(saved)
    if pid and pid_is_alive(pid):
        return pid, saved
    return None


def require_not_running(config: DaemonConfig) -> None:
    found = running_daemon(config)
    if found:
        pid, saved = found
        raise DaemonAlreadyRunning(pid, saved)


def spawn_detached(config: DaemonConfig) -> subprocess.Popen:
    auth.ensure_runtime_dir(config.persistence.runtime_dir)
    config_path = os.path.join(config.persistence.runtime_dir, 'start.json')
    with open(config_path, 'w', encoding='utf-8') as handle:
        json.dump(config.as_dict(), handle)
    os.makedirs(os.path.dirname(config.log_path), exist_ok=True)
    log = open(config.log_path, 'ab', buffering=0)
    cmd = [sys.executable, '-m', 'tornadorevc2', '_daemon', '--config', config_path]
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(package_root)
    env = os.environ.copy()
    env['PYTHONPATH'] = repo_root + os.pathsep + env.get('PYTHONPATH', '')
    kwargs = {
        'stdin': subprocess.DEVNULL,
        'stdout': log,
        'stderr': log,
        'close_fds': True,
        'env': env,
        'cwd': repo_root,
    }
    if os.name == 'nt':
        kwargs['creationflags'] = getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(
            subprocess, 'CREATE_NEW_PROCESS_GROUP', 0
        )
    else:
        kwargs['start_new_session'] = True
    return subprocess.Popen(cmd, **kwargs)


def wait_until_ready(config: DaemonConfig, timeout: float = 15.0) -> int:
    deadline = time.time() + timeout
    last_error = 'daemon did not become ready'
    while time.time() < deadline:
        found = running_daemon(config)
        if found:
            pid, saved = found
            if saved.management.transport == 'unix' and os.path.exists(saved.management.socket_path):
                return pid
            if saved.management.transport == 'tcp':
                return pid
        time.sleep(0.1)
    raise RuntimeError(last_error)


def stop_pid(pid: int, timeout: float = 10.0) -> None:
    if not pid_is_alive(pid):
        return
    sig = signal.SIGTERM if os.name != 'nt' else signal.SIGTERM
    try:
        os.kill(pid, sig)
    except OSError:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_is_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
