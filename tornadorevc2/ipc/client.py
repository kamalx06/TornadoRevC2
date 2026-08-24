"""CLI-side management IPC client (local-only)."""

from __future__ import annotations

import os
import socket
from typing import Any, Optional

from ..daemon.config import DaemonConfig
from .codec import read_message, write_message
from .protocol import request


class IpcError(Exception):
    def __init__(self, message: str, payload: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.payload = payload or {}


class ManagementClient:
    def __init__(self, config: DaemonConfig, token: str = ''):
        self.config = config
        self.token = token
        self._sock = None

    def connect(self, timeout: float = 5.0):
        mg = self.config.management
        if mg.transport == 'unix':
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(mg.socket_path)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((mg.host, mg.port))
        self._sock = sock
        return self

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    @property
    def sock(self):
        if self._sock is None:
            raise IpcError('Not connected to management daemon')
        return self._sock

    def call(self, method: str, params: Optional[dict[str, Any]] = None, timeout: Optional[float] = 120.0) -> Any:
        payload = dict(params or {})
        if self.token:
            payload['_token'] = self.token
        msg = request(method, payload)
        write_message(self.sock, msg)
        previous = self.sock.gettimeout()
        try:
            if timeout is not None:
                self.sock.settimeout(timeout)
            while True:
                reply = read_message(self.sock)
                if reply.get('type') == 'event':
                    continue
                if reply.get('id') != msg['id']:
                    continue
                if not reply.get('ok', False):
                    raise IpcError(reply.get('error') or 'IPC request failed', reply)
                return reply.get('result')
        finally:
            self.sock.settimeout(previous)

    def stream(self, method: str, params: Optional[dict[str, Any]] = None, timeout: Optional[float] = None, until_response: bool = True):
        payload = dict(params or {})
        if self.token:
            payload['_token'] = self.token
        msg = request(method, payload)
        write_message(self.sock, msg)
        previous = self.sock.gettimeout()
        try:
            self.sock.settimeout(timeout)
            while True:
                reply = read_message(self.sock)
                yield reply
                if until_response and reply.get('type') == 'response' and reply.get('id') == msg['id']:
                    return
        finally:
            self.sock.settimeout(previous)


def load_token(config: DaemonConfig) -> str:
    path = config.token_path
    if not os.path.exists(path):
        return ''
    with open(path, 'r', encoding='utf-8') as handle:
        return handle.read().strip()
