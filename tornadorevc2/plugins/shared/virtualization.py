"""Unified virtualization and container detection plugin."""

import json

from ..api import SessionContext, plugin
from ..linux.virtualization import build_linux_detection_command
from ..shared.common import format_detection_report
from ..windows.virtualization import build_windows_detection_script
from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...sysinfo import _extract_marked


def _parse_detection_output(raw: str) -> dict:
    if not raw:
        return {}
    payload = raw.strip()
    # run_marked() already returns content between markers; fall back if not
    if PLUGIN_MARK_START in payload:
        extracted = _extract_marked(payload, PLUGIN_MARK_START, PLUGIN_MARK_END)
        if extracted:
            payload = extracted
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


@plugin.command(
    name='virtualization',
    platforms=['linux', 'windows', 'unix'],
    description='Detect virtualization, containers, and orchestration environments',
)
def run(session: SessionContext, args):
    unix_cmd = build_linux_detection_command()
    win_ps = build_windows_detection_script()

    session.log_event('Plugin virtualization: detection started')
    raw = session.run_marked(
        unix_cmd,
        win_ps,
        timeout=25.0,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print('Virtualization detection failed — no response from target.', 'red')
        session.log_plugin_result('virtualization', '', 'detection failed: no response')
        return 1

    data = _parse_detection_output(raw)
    if not data:
        session.print('Virtualization detection failed — could not parse results.', 'red')
        session.log_plugin_result('virtualization', raw[:2000], 'parse error')
        return 1

    report = format_detection_report(data)
    session.print(report, 'cyan')
    session.log_plugin_result('virtualization', report, json.dumps(data, indent=2))
    session.log_command('run virtualization', report)
    return 0
