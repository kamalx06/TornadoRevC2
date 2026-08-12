"""QuickEnum — fast structured host assessment (30–60 seconds)."""

from ..api import plugin, SessionContext
from ..linux.quickenum import build_command as build_linux_cmd
from ..windows.quickenum import build_command as build_windows_cmd
from .common import format_quickenum_report
from .runner import run_collector_plugin


@plugin.command(
    name='quickenum',
    platforms=['linux', 'windows', 'unix'],
    description='Fast structured host assessment (hostname, user, network, findings)',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'quickenum',
        build_linux_cmd,
        build_windows_cmd,
        format_quickenum_report,
        timeout=75.0,
    )
