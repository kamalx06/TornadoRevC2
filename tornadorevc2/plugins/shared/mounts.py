"""Cross-platform mount and filesystem enumeration."""

from ..api import plugin, SessionContext
from ..linux.mounts import build_command as build_linux_cmd
from ..windows.mounts import build_command as build_windows_cmd
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin


@plugin.command(
    name='mounts',
    platforms=['linux', 'windows', 'unix'],
    description='Enumerate mounts, SMB/NFS shares, mapped drives, and container filesystems',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'mounts',
        build_linux_cmd,
        build_windows_cmd,
        format_generic_report,
        timeout=70.0,
    )
