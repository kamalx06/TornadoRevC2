"""Unified aggressive virtualization and container detection plugin."""

from ..api import plugin, SessionContext
from ..linux.virtualization import build_command as build_linux_cmd
from ..windows.virtualization import build_command as build_windows_cmd
from ..shared.common import format_virtualization_report
from ..shared.runner import run_collector_plugin


@plugin.command(
    name='virtualization',
    platforms=['linux', 'windows', 'unix'],
    description='Aggressive virtualization, container, and cloud environment detection',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'virtualization',
        build_linux_cmd,
        build_windows_cmd,
        format_virtualization_report,
        timeout=50.0,
    )
