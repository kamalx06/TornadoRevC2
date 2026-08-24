"""Local management IPC authentication (token file + socket permissions)."""

from __future__ import annotations

import os
import secrets
from typing import Optional


def ensure_runtime_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_token(path: str, token: Optional[str] = None) -> str:
    value = token or secrets.token_hex(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, value.encode('utf-8'))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def read_token(path: str) -> str:
    if not os.path.exists(path):
        return ''
    with open(path, 'r', encoding='utf-8') as handle:
        return handle.read().strip()


def secure_socket_path(path: str) -> None:
    if os.path.exists(path):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def check_token(expected: str, provided: Optional[str]) -> bool:
    if not expected:
        return True
    if not provided:
        return False
    return secrets.compare_digest(expected, provided)
