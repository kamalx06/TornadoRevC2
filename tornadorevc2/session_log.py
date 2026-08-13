import datetime
import json
import os
import re

from .constants import LOGS_DIR
from .terminal_sanitize import sanitize_terminal_output


def _sanitize(name):
    safe = re.sub(r'[^\w.\-@]+', '_', name)
    return safe.strip('._') or 'session'


class SessionLogger:
    def __init__(self, session_id, base_dir=LOGS_DIR):
        self.session_id = session_id
        self.session_dir = os.path.join(base_dir, _sanitize(session_id))
        self.command_log = os.path.join(self.session_dir, 'session.log')
        self.sysinfo_path = os.path.join(self.session_dir, 'sysinfo.json')
        self.transfers_dir = os.path.join(self.session_dir, 'transfers')
        self.executions_dir = os.path.join(self.session_dir, 'executions')
        self.plugins_dir = os.path.join(self.session_dir, 'plugins')
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(self.transfers_dir, exist_ok=True)
        os.makedirs(self.executions_dir, exist_ok=True)
        os.makedirs(self.plugins_dir, exist_ok=True)

    def _timestamp(self):
        return datetime.datetime.now().isoformat(timespec='seconds')

    def log_event(self, message):
        with open(self.command_log, 'a', encoding='utf-8') as f:
            f.write(f"[{self._timestamp()}] * {message}\n")

    def log_command(self, cmd, output):
        with open(self.command_log, 'a', encoding='utf-8') as f:
            f.write(f"[{self._timestamp()}] $ {cmd}\n")
            if output:
                f.write(f"{sanitize_terminal_output(output)}\n")
            f.write('\n')

    def save_sysinfo(self, info):
        if not info:
            return
        with open(self.sysinfo_path, 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2)
            f.write('\n')
        self.log_event('System information collected')

    def log_transfer(self, direction, local_path, remote_path, status, detail=''):
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        name = f"{direction}_{stamp}.log"
        path = os.path.join(self.transfers_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"Time:     {self._timestamp()}\n")
            f.write(f"Direction:{direction}\n")
            f.write(f"Local:    {local_path}\n")
            f.write(f"Remote:   {remote_path}\n")
            f.write(f"Status:   {status}\n")
            if detail:
                f.write(f"Detail:   {detail}\n")
        self.log_event(f"Transfer {direction}: {status} ({local_path} <-> {remote_path})")

    def log_execution(self, metadata):
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        name = metadata.get('name', 'payload')
        safe_name = re.sub(r'[^\w.\-]+', '_', name)[:48]
        path = os.path.join(self.executions_dir, f"exec_{safe_name}_{stamp}.json")
        record = dict(metadata)
        record['timestamp'] = self._timestamp()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=2)
            f.write('\n')
        status = 'success' if record.get('success') else 'failed'
        self.log_event(
            f"Payload execution {status}: {record.get('name')} "
            f"({record.get('type')}, {record.get('runtime_ms', 0)} ms)"
        )

    def log_tunnel(self, message):
        self.log_event(f"Tunnel: {message}")

    def log_plugin(self, plugin_name, output, detail=''):
        plugins_dir = getattr(self, 'plugins_dir', None) or os.path.join(self.session_dir, 'plugins')
        os.makedirs(plugins_dir, exist_ok=True)
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = re.sub(r'[^\w.\-]+', '_', plugin_name)[:48]
        path = os.path.join(plugins_dir, f"{safe_name}_{stamp}.log")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"Time:   {self._timestamp()}\n")
            f.write(f"Plugin: {plugin_name}\n")
            if output:
                f.write(f"\n--- Report ---\n{sanitize_terminal_output(output)}\n")
            if detail:
                f.write(f"\n--- Raw Data ---\n{detail}\n")
        self.log_event(f"Plugin {plugin_name}: completed")
        return path

    def log_privesc_check(self, tool, duration_sec, success, output_path, exit_code=None, detail=''):
        plugins_dir = getattr(self, 'plugins_dir', None) or os.path.join(self.session_dir, 'plugins')
        os.makedirs(plugins_dir, exist_ok=True)
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        meta_path = os.path.join(plugins_dir, f"privesccheck_{stamp}.json")
        record = {
            'timestamp': self._timestamp(),
            'tool': tool,
            'duration_sec': round(duration_sec, 2),
            'success': success,
            'exit_code': exit_code,
            'output_path': output_path,
            'detail': detail,
        }
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=2)
            f.write('\n')
        status = 'success' if success else 'failed'
        self.log_event(
            f"Privesc check {status}: {tool} ({duration_sec:.1f}s) -> {output_path or 'no output'}"
        )
        return meta_path

    def log_reconnect(self, detail):
        self.log_event(f"Session reconnected — {detail}")
