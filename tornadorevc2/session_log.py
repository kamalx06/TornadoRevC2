import datetime
import json
import os
import re

from .constants import LOGS_DIR


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
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(self.transfers_dir, exist_ok=True)

    def _timestamp(self):
        return datetime.datetime.now().isoformat(timespec='seconds')

    def log_event(self, message):
        with open(self.command_log, 'a', encoding='utf-8') as f:
            f.write(f"[{self._timestamp()}] * {message}\n")

    def log_command(self, cmd, output):
        with open(self.command_log, 'a', encoding='utf-8') as f:
            f.write(f"[{self._timestamp()}] $ {cmd}\n")
            if output:
                f.write(f"{output}\n")
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
