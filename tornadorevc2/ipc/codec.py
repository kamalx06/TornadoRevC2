"""Length-prefixed JSON frames for management IPC."""

from __future__ import annotations

import json
import struct
from typing import Any, Optional

from .protocol import MAX_MESSAGE_BYTES

HEADER = struct.Struct('>I')


class CodecError(Exception):
    pass


def encode(message: dict[str, Any]) -> bytes:
    payload = json.dumps(message, separators=(',', ':'), default=str).encode('utf-8')
    if len(payload) > MAX_MESSAGE_BYTES:
        raise CodecError(f'Message too large: {len(payload)} bytes')
    return HEADER.pack(len(payload)) + payload


def decode(frame: bytes) -> dict[str, Any]:
    try:
        return json.loads(frame.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodecError(f'Invalid JSON frame: {exc}') from exc


def read_exactly(sock, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError('IPC connection closed')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def read_message(sock) -> dict[str, Any]:
    header = read_exactly(sock, HEADER.size)
    (length,) = HEADER.unpack(header)
    if length > MAX_MESSAGE_BYTES:
        raise CodecError(f'Frame length {length} exceeds limit')
    return decode(read_exactly(sock, length))


def write_message(sock, message: dict[str, Any]) -> None:
    sock.sendall(encode(message))


def try_read_message(sock, timeout: Optional[float] = None) -> Optional[dict[str, Any]]:
    previous = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        return read_message(sock)
    except TimeoutError:
        return None
    finally:
        sock.settimeout(previous)
