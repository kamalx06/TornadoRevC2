"""Management IPC message types."""

from __future__ import annotations

from typing import Any, Optional
import uuid


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 16 * 1024 * 1024


def new_id() -> str:
    return uuid.uuid4().hex


def request(method: str, params: Optional[dict[str, Any]] = None, req_id: Optional[str] = None) -> dict[str, Any]:
    return {
        'v': PROTOCOL_VERSION,
        'type': 'request',
        'id': req_id or new_id(),
        'method': method,
        'params': params or {},
    }


def response(req_id: str, result: Any = None, ok: bool = True, error: Optional[str] = None) -> dict[str, Any]:
    msg = {
        'v': PROTOCOL_VERSION,
        'type': 'response',
        'id': req_id,
        'ok': ok,
        'result': result,
    }
    if error:
        msg['error'] = error
    return msg


def event(name: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {
        'v': PROTOCOL_VERSION,
        'type': 'event',
        'event': name,
        'payload': payload or {},
    }
