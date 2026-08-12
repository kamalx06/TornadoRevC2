"""Shared plugin execution helpers."""

import json
from typing import Callable, Dict, Optional

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...sysinfo import _extract_marked


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


def run_collector_plugin(
    session,
    plugin_name: str,
    unix_builder: Optional[Callable[[], str]],
    win_builder: Optional[Callable[[], str]],
    formatter: Callable[[dict], str],
    timeout: float = 30.0,
) -> int:
    session.log_event(f'Plugin {plugin_name}: collection started')

    if session.is_windows:
        if not win_builder:
            session.print(f"Plugin '{plugin_name}' is not available on Windows.", 'red')
            return 1
        win_ps = win_builder()
        unix_cmd = 'true'
    else:
        if not unix_builder:
            session.print(f"Plugin '{plugin_name}' is not available on Linux/Unix.", 'red')
            return 1
        unix_cmd = unix_builder()
        win_ps = ''

    raw = session.run_marked(
        unix_cmd,
        win_ps,
        timeout=timeout,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print(f"Plugin '{plugin_name}' failed — no response from target.", 'red')
        session.log_plugin_result(plugin_name, '', 'no response')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print(f"Plugin '{plugin_name}' failed — could not parse results.", 'red')
        session.log_plugin_result(plugin_name, raw[:4000], 'parse error')
        return 1

    report = formatter(data)
    session.print(report, 'cyan')
    session.log_plugin_result(plugin_name, report, json.dumps(data, indent=2))
    session.log_command(f'run {plugin_name}', report)
    return 0
