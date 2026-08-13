"""Shared plugin execution helpers."""

import json
from typing import Callable, Dict, Optional

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...sysinfo import _extract_marked
from .common import resolve_session_platform


def parse_collector_json(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    payload = raw.strip()
    if PLUGIN_MARK_START in payload:
        extracted = _extract_marked(payload, PLUGIN_MARK_START, PLUGIN_MARK_END)
        if extracted:
            payload = extracted
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


def _run_collector_marked(session, unix_cmd: str, win_ps: str, platform: str, timeout: float) -> Optional[str]:
    handler = session._handler
    sock = session._client_sock
    kwargs = dict(
        timeout=timeout,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if platform == 'unknown':
        for shell_type in ('windows', 'unix'):
            if shell_type == 'windows' and not win_ps:
                continue
            if shell_type == 'unix' and not unix_cmd:
                continue
            payload = handler._run_marked(
                sock,
                unix_cmd if shell_type == 'unix' else 'true',
                win_ps if shell_type == 'windows' else '',
                shell_type,
                **kwargs,
            )
            if payload is not None:
                return payload
        return None

    return handler._run_marked(sock, unix_cmd, win_ps, platform, **kwargs)


def run_collector_plugin(
    session,
    plugin_name: str,
    unix_builder: Optional[Callable[[], str]],
    win_builder: Optional[Callable[[], str]],
    formatter: Callable[[dict], str],
    timeout: float = 30.0,
) -> int:
    session.log_event(f'Plugin {plugin_name}: collection started')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

    platform = resolve_session_platform(session)
    win_ps = ''
    unix_cmd = 'true'

    if platform == 'windows':
        if not win_builder:
            session.print(f"Plugin '{plugin_name}' is not available on Windows.", 'red')
            return 1
        win_ps = win_builder()
    elif platform in ('unix', 'linux'):
        if not unix_builder:
            session.print(f"Plugin '{plugin_name}' is not available on Linux/Unix.", 'red')
            return 1
        unix_cmd = unix_builder()
    else:
        if not win_builder and not unix_builder:
            session.print(f"Plugin '{plugin_name}' is not available on this platform.", 'red')
            return 1
        if win_builder:
            win_ps = win_builder()
        if unix_builder:
            unix_cmd = unix_builder()
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, timeout)

    if raw is None:
        session.print(f"Plugin '{plugin_name}' failed — no response from target.", 'red')
        session.log_plugin_result(plugin_name, '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print(f"Plugin '{plugin_name}' failed — could not parse results.", 'red')
        session.log_plugin_result(plugin_name, raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin '{plugin_name}' error on target: {data['error']}", 'red')
        detail = data.get('traceback', '')
        session.log_plugin_result(plugin_name, raw[:4000], detail or str(data))
        return 1

    report = formatter(data)
    session.print(report, 'cyan')
    session.log_plugin_result(plugin_name, report, json.dumps(data, indent=2))
    session.log_command(f'run {plugin_name}', report)
    return 0
