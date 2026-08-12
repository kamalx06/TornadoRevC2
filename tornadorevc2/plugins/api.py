"""Plugin API — session context and command registration decorator."""

import select
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class PluginCommand:
    name: str
    platforms: List[str]
    description: str
    handler: Callable
    module: str = ''
    source: str = 'builtin'


class _PluginRegistry:
    """Thread-safe global registry for plugin command definitions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._commands: Dict[str, PluginCommand] = {}

    def register(self, cmd: PluginCommand):
        with self._lock:
            self._commands[cmd.name] = cmd

    def unregister(self, name: str):
        with self._lock:
            self._commands.pop(name, None)

    def get(self, name: str) -> Optional[PluginCommand]:
        with self._lock:
            return self._commands.get(name)

    def all_commands(self) -> Dict[str, PluginCommand]:
        with self._lock:
            return dict(self._commands)


_registry = _PluginRegistry()


class plugin:
    """Decorator for registering plugin commands."""

    @staticmethod
    def command(name, platforms=None, description=''):
        platforms = platforms or ['linux', 'windows', 'unix']

        def decorator(fn):
            cmd = PluginCommand(
                name=name,
                platforms=[p.lower() for p in platforms],
                description=description,
                handler=fn,
                module=getattr(fn, '__module__', ''),
                source='builtin',
            )
            _registry.register(cmd)
            fn._plugin_command = cmd
            return fn

        return decorator


def get_registry():
    return _registry


class SessionContext:
    """Clean API surface exposed to plugins for a single session."""

    def __init__(self, handler, client_sock):
        self._handler = handler
        self._client_sock = client_sock
        self._info = handler._client_info(client_sock) or {}

    @property
    def socket(self):
        return self._client_sock

    @property
    def session_id(self):
        return self._info.get('id')

    @property
    def platform(self):
        """Shell type: unix, windows, or unknown."""
        return self._info.get('type', 'unknown')

    @property
    def is_windows(self):
        return self.platform == 'windows'

    @property
    def is_unix(self):
        return self.platform in ('unix', 'linux')

    @property
    def sysinfo(self) -> dict:
        return dict(self._info.get('sysinfo') or {})

    @property
    def identity(self) -> dict:
        return dict(self._info.get('identity') or {})

    @property
    def logger(self):
        return self._info.get('logger')

    @property
    def addr(self):
        return self._info.get('addr')

    @property
    def tls(self) -> bool:
        return bool(self._info.get('tls'))

    @property
    def name(self):
        return self._info.get('name')

    @property
    def fingerprint(self):
        return self._info.get('fingerprint')

    @property
    def colors(self) -> dict:
        return self._handler.colors

    def get_cwd(self) -> str:
        cwd = self.sysinfo.get('cwd')
        if cwd:
            return cwd
        if self.is_windows:
            payload = self._handler._run_marked(
                self._client_sock, '', "$PWD.Path", 'windows', timeout=5.0, strip_ws=False,
            )
        else:
            payload = self._handler._run_marked(
                self._client_sock, 'pwd 2>/dev/null', '', 'unix', timeout=5.0, strip_ws=False,
            )
        return (payload or '').strip()

    def run_shell(self, cmd: str, timeout: float = 15.0) -> str:
        self._handler._flush_shell(self._client_sock)
        if not self._handler.send_to_revshell(self._client_sock, cmd):
            return ''
        return self._handler.recv_output(self._client_sock, timeout=timeout)

    def run_shell_streaming(
        self,
        cmd: str,
        timeout: float = 3600.0,
        idle_timeout: float = 60.0,
        on_chunk=None,
    ) -> str:
        """Execute a command and stream output until idle or timeout."""
        self._handler._flush_shell(self._client_sock, timeout=1.0)
        if not self._handler.send_to_revshell(self._client_sock, cmd):
            return ''
        deadline = time.time() + timeout
        last_data = time.time()
        parts = []
        c = self.colors
        while time.time() < deadline:
            remaining = min(1.0, deadline - time.time())
            if remaining <= 0:
                break
            try:
                r, _, _ = select.select([self._client_sock], [], [], remaining)
            except Exception:
                break
            if r:
                try:
                    chunk = self._client_sock.recv(65536)
                except Exception:
                    break
                if not chunk:
                    break
                text = chunk.decode(errors='ignore')
                parts.append(text)
                last_data = time.time()
                if on_chunk:
                    on_chunk(text)
                else:
                    sys.stdout.write(text)
                    sys.stdout.flush()
            elif time.time() - last_data >= idle_timeout:
                break
        return ''.join(parts)

    def run_marked(
        self,
        unix_cmd: str,
        win_ps_script: str,
        timeout: float = 15.0,
        start_mark=None,
        end_mark=None,
        strip_ws: bool = True,
    ) -> Optional[str]:
        shell_type = self.platform
        if shell_type == 'unknown':
            for st in ('unix', 'windows'):
                payload = self._handler._run_marked(
                    self._client_sock, unix_cmd, win_ps_script, st,
                    timeout=timeout, start_mark=start_mark, end_mark=end_mark, strip_ws=strip_ws,
                )
                if payload is not None:
                    with self._handler.client_lock:
                        info = self._handler.revshell_clients.get(self._client_sock)
                        if info:
                            info['type'] = st
                    self._info = self._handler._client_info(self._client_sock) or self._info
                    return payload
            return None
        return self._handler._run_marked(
            self._client_sock, unix_cmd, win_ps_script, shell_type,
            timeout=timeout, start_mark=start_mark, end_mark=end_mark, strip_ws=strip_ws,
        )

    def upload(self, local_path: str, remote_path: str, resume: bool = False) -> bool:
        return self._handler.upload_file(
            self._client_sock, local_path, remote_path, resume=resume,
        )

    def download(self, remote_path: str, local_path: str, resume: bool = False) -> bool:
        return self._handler.download_file(
            self._client_sock, remote_path, local_path, resume=resume,
        )

    def verify_remote(self, remote_path: str):
        return self._handler.verify_file(self._client_sock, remote_path)

    def collect_sysinfo(self, mode: str = 'stealth') -> Optional[dict]:
        return self._handler.collect_sysinfo(self._client_sock, self.platform, mode=mode)

    def log_event(self, message: str):
        logger = self.logger
        if logger:
            logger.log_event(message)

    def log_command(self, cmd: str, output: str):
        logger = self.logger
        if logger:
            logger.log_command(cmd, output)

    def log_plugin_result(self, plugin_name: str, output: str, detail: str = ''):
        logger = self.logger
        if logger:
            logger.log_plugin(plugin_name, output, detail)

    def print(self, text: str, color: str = None):
        c = self.colors
        if color and color in c:
            print(f"{c[color]}{text}{c['end']}")
        else:
            print(text)
