"""Per-session structured logging."""

import datetime
import json
import os
import re

from .constants import LOGS_DIR
from .terminal_sanitize import sanitize_terminal_output


__all__ = ['SessionLogger']


def _sanitize(name: str) -> str:
    """Sanitize a session identifier for safe use as a directory name."""
    safe = re.sub(r'[^\w.\-@]+', '_', name)
    return safe.strip('._') or 'session'


def _timestamp() -> str:
    return datetime.datetime.now().isoformat(timespec='seconds')


def _stamp() -> str:
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


class SessionLogger:
    """Writes structured session logs to a per-session directory.

    Target output is passed through :func:`sanitize_terminal_output` to strip
    ANSI/OSC/DCS escape sequences so logs remain readable in any editor.
    No content filtering is applied — the raw output is preserved.
    """

    def __init__(self, session_id: str, base_dir: str = LOGS_DIR):
        self.session_id = session_id
        self.session_dir = os.path.join(base_dir, _sanitize(session_id))
        self.command_log = os.path.join(self.session_dir, 'session.log')
        self.sysinfo_path = os.path.join(self.session_dir, 'sysinfo.json')
        self.transfers_dir = os.path.join(self.session_dir, 'transfers')
        self.executions_dir = os.path.join(self.session_dir, 'executions')
        self.plugins_dir = os.path.join(self.session_dir, 'plugins')

        for directory in (
            self.session_dir,
            self.transfers_dir,
            self.executions_dir,
            self.plugins_dir,
        ):
            os.makedirs(directory, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _append_event(self, message: str) -> None:
        line = f"[{_timestamp()}] * {message}\n"
        self._write(self.command_log, line, mode='a')

    def _write(self, path: str, content: str, mode: str = 'w') -> None:
        """Write to a file, swallowing errors so logging never aborts a session."""
        try:
            with open(path, mode, encoding='utf-8') as fh:
                fh.write(content)
        except OSError:
            pass

    def _write_json(self, path: str, payload) -> None:
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
                fh.write('\n')
        except (OSError, TypeError):
            pass

    # ------------------------------------------------------------------
    # Session log
    # ------------------------------------------------------------------

    def log_event(self, message: str) -> None:
        """Append a timestamped operational event to session.log."""
        self._append_event(message)

    def log_command(self, cmd: str, output: str = '') -> None:
        """Record an operator command and its output."""
        parts = [f"[{_timestamp()}] $ {cmd}\n"]
        if output:
            parts.append(sanitize_terminal_output(output))
            parts.append('\n')
        parts.append('\n')
        self._write(self.command_log, ''.join(parts), mode='a')

    def log_tunnel(self, message: str) -> None:
        self._append_event(f"Tunnel: {message}")

    def log_reconnect(self, detail: str) -> None:
        self._append_event(f"Session reconnected — {detail}")

    # ------------------------------------------------------------------
    # Structured artefacts
    # ------------------------------------------------------------------

    def save_sysinfo(self, info: dict) -> None:
        if not info:
            return
        self._write_json(self.sysinfo_path, info)
        self.log_event('System information collected')

    def log_transfer(
        self,
        direction: str,
        local_path: str,
        remote_path: str,
        status: str,
        detail: str = '',
    ) -> None:
        name = f"{direction}_{_stamp()}.log"
        path = os.path.join(self.transfers_dir, name)
        lines = [
            f"Time:     {_timestamp()}\n",
            f"Direction:{direction}\n",
            f"Local:    {local_path}\n",
            f"Remote:   {remote_path}\n",
            f"Status:   {status}\n",
        ]
        if detail:
            lines.append(f"Detail:   {detail}\n")
        self._write(path, ''.join(lines))
        self.log_event(f"Transfer {direction}: {status} ({local_path} <-> {remote_path})")

    def log_execution(self, metadata: dict) -> None:
        name = metadata.get('name', 'payload')
        safe_name = re.sub(r'[^\w.\-]+', '_', str(name))[:48]
        path = os.path.join(self.executions_dir, f"exec_{safe_name}_{_stamp()}.json")
        record = dict(metadata)
        record['timestamp'] = _timestamp()
        self._write_json(path, record)
        status = 'success' if record.get('success') else 'failed'
        self.log_event(
            f"Payload execution {status}: {record.get('name')} "
            f"({record.get('type')}, {record.get('runtime_ms', 0)} ms)"
        )

    def log_plugin(self, plugin_name: str, output: str = '', detail: str = '') -> str:
        """Write a plugin report to disk. Returns the path written."""
        stamp = _stamp()
        safe_name = re.sub(r'[^\w.\-]+', '_', plugin_name)[:48]
        path = os.path.join(self.plugins_dir, f"{safe_name}_{stamp}.log")

        parts = [
            f"Time:   {_timestamp()}\n",
            f"Plugin: {plugin_name}\n",
        ]
        if output:
            parts.append(f"\n--- Report ---\n{sanitize_terminal_output(output)}\n")
        if detail:
            parts.append(f"\n--- Raw Data ---\n{detail}\n")
        self._write(path, ''.join(parts))
        self.log_event(f"Plugin {plugin_name}: completed")
        return path

    def log_privesc_check(
        self,
        tool: str,
        duration_sec: float,
        success: bool,
        output_path: str,
        exit_code: int | None = None,
        detail: str = '',
    ) -> str:
        stamp = _stamp()
        meta_path = os.path.join(self.plugins_dir, f"privesccheck_{stamp}.json")
        record = {
            'timestamp': _timestamp(),
            'tool': tool,
            'duration_sec': round(duration_sec, 2),
            'success': success,
            'exit_code': exit_code,
            'output_path': output_path,
            'detail': detail,
        }
        self._write_json(meta_path, record)
        status = 'success' if success else 'failed'
        self.log_event(
            f"Privesc check {status}: {tool} ({duration_sec:.1f}s) "
            f"-> {output_path or 'no output'}"
        )
        return meta_path