"""Cross-platform shell and command history enumeration."""

from ..api import plugin, SessionContext
from ..linux.history import build_command as build_linux_cmd
from ..windows.history import build_command as build_windows_cmd
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


@plugin.command(
    name='history',
    platforms=['linux', 'windows', 'unix'],
    description='Collect shell history, package/update logs, and recent login activity',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'history',
        build_linux_cmd,
        build_windows_cmd,
        format_generic_report,
        timeout=25.0,
    )
