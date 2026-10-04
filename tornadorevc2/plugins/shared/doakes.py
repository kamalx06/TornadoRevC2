"""Operator-side Easter egg that opens James Doakes Iconic Word in the client's default browser."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json

SURPRISE_URL = "https://www.youtube.com/watch?v=5CfNarCjSHM"


def _build_linux_command():
    source = rf'''
import subprocess

url = {SURPRISE_URL!r}

try:
    subprocess.Popen(
        ['xdg-open', url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    result = {{"ok": True, "reason": ""}}
except Exception as exc:
    result = {{"ok": False, "reason": str(exc)}}

_emit(result)
'''
    return build_linux_collector_command(source)


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$result = @{{ ok = $false; reason = '' }}

try {{
    Start-Process '{SURPRISE_URL}'
    $result.ok = $true
}} catch {{
    $result.reason = $_.Exception.Message
}}

Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


@plugin.command(
    name='doakes',
    platforms=['linux', 'windows', 'unix'],
    description="Open a surprise in the client's default browser",
)
def run(session: SessionContext, args):
    platform = resolve_session_platform(session)

    win_ps = ''
    unix_cmd = 'true'

    if platform == 'windows':
        win_ps = _build_windows_command()
    elif platform in ('unix', 'linux'):
        unix_cmd = _build_linux_command()
    else:
        win_ps = _build_windows_command()
        unix_cmd = _build_linux_command()
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 15.0)

    if raw is None:
        session.print("Plugin 'doakes' failed — no response from target.", 'red')
        return 1

    data = parse_collector_json(raw)

    if not data:
        session.print("Plugin 'doakes' failed — could not parse results.", 'red')
        return 1

    if data.get('ok'):
        session.print("Motherfucker has been surprised.", 'green')
        return 0

    session.print(
        f"Plugin 'doakes' failed — {data.get('reason', 'unknown error')}",
        'red',
    )
    return 1