"""Linux plugin collector command builder."""

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ...sysinfo import _b64_exec_cmd


def build_linux_collector_command(source: str, timeout_note: str = '') -> str:
    interpreters = [
        ('python3', 'python'),
        ('python', 'python'),
        ('python2', 'python'),
    ]
    body = _b64_exec_cmd(source, interpreters)
    return f"({body}) 2>/dev/null; true"


def linux_markers():
    return PLUGIN_MARK_START, PLUGIN_MARK_END
