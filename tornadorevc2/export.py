"""Session transcript export to self-contained HTML reports."""

import datetime
import html
import json
import os
import re

from .constants import LOGS_DIR
from .session_log import _sanitize
from .terminal_sanitize import sanitize_terminal_output


EXPORTS_DIR = 'exports'
_LOG_LINE = re.compile(r'^\[([^\]]+)\]\s+(.*)$')
_CMD_LINE = re.compile(r'^\$\s+(.*)$')
_EVENT_LINE = re.compile(r'^\*\s+(.*)$')


def _parse_session_log(path):
    """Parse session.log into chronological transcript entries."""
    if not os.path.isfile(path):
        return []

    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        raw_lines = fh.read().splitlines()

    entries = []
    current = None
    output_lines = []

    def flush_output():
        nonlocal current, output_lines
        if current and current['kind'] == 'command' and output_lines:
            raw = '\n'.join(output_lines).strip('\n')
            current['output'] = sanitize_terminal_output(raw)
            output_lines = []

    for line in raw_lines:
        match = _LOG_LINE.match(line)
        if match:
            flush_output()
            timestamp, body = match.group(1), match.group(2)
            cmd_match = _CMD_LINE.match(body)
            event_match = _EVENT_LINE.match(body)
            if cmd_match:
                current = {
                    'kind': 'command',
                    'timestamp': timestamp,
                    'command': cmd_match.group(1),
                    'output': '',
                }
                entries.append(current)
            elif event_match:
                current = {
                    'kind': 'event',
                    'timestamp': timestamp,
                    'message': event_match.group(1),
                }
                entries.append(current)
            else:
                current = {
                    'kind': 'event',
                    'timestamp': timestamp,
                    'message': body,
                }
                entries.append(current)
            continue

        if current and current['kind'] == 'command':
            output_lines.append(line)

    flush_output()
    return entries


def _load_sysinfo(path):
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _first_event_time(entries, needle):
    needle = needle.lower()
    for entry in entries:
        if entry['kind'] == 'event' and needle in entry.get('message', '').lower():
            return entry['timestamp']
    return None


def _last_event_time(entries, needle):
    needle = needle.lower()
    found = None
    for entry in entries:
        if entry['kind'] == 'event' and needle in entry.get('message', '').lower():
            found = entry['timestamp']
    return found


def _detail_row(label, value):
    if value is None or value == '':
        value = '—'
    return (
        f'<tr><th>{html.escape(label)}</th>'
        f'<td>{html.escape(str(value))}</td></tr>'
    )


def _render_transcript(entries):
    blocks = []
    for entry in entries:
        ts = html.escape(entry.get('timestamp', ''))
        if entry['kind'] == 'event':
            msg = html.escape(entry.get('message', ''))
            blocks.append(
                f'<article class="entry event">'
                f'<div class="meta"><span class="time">{ts}</span> '
                f'<span class="badge event-badge">event</span></div>'
                f'<pre class="event-text">{msg}</pre>'
                f'</article>'
            )
        else:
            cmd = html.escape(entry.get('command', ''))
            output = html.escape(entry.get('output', '') or '')
            output_block = (
                f'<pre class="output">{output}</pre>' if output else '<pre class="output empty">(no output)</pre>'
            )
            blocks.append(
                f'<article class="entry command">'
                f'<div class="meta"><span class="time">{ts}</span> '
                f'<span class="badge cmd-badge">command</span></div>'
                f'<pre class="command-text">$ {cmd}</pre>'
                f'{output_block}'
                f'</article>'
            )
    if not blocks:
        blocks.append('<p class="empty">No transcript entries recorded for this session.</p>')
    return '\n'.join(blocks)


def _build_html(metadata, entries):
    generated = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = f"TornadoRevC2 Session #{metadata['session_id']} Transcript"

    rows = ''.join([
        _detail_row('Session ID', metadata.get('session_id')),
        _detail_row('Session Name', metadata.get('name')),
        _detail_row('Hostname', metadata.get('hostname')),
        _detail_row('Username', metadata.get('username')),
        _detail_row('Operating System', metadata.get('os')),
        _detail_row('Architecture', metadata.get('architecture')),
        _detail_row('IP Address', metadata.get('ip_address')),
        _detail_row('Remote Port', metadata.get('remote_port')),
        _detail_row('Protocol', metadata.get('protocol')),
        _detail_row('Shell Type', metadata.get('shell_type')),
        _detail_row('Status', metadata.get('status')),
        _detail_row('Connection Time', metadata.get('connected_at')),
        _detail_row('Disconnection Time', metadata.get('disconnected_at')),
        _detail_row('Connect Count', metadata.get('connect_count')),
        _detail_row('Log Directory', metadata.get('log_dir')),
    ])

    transcript = _render_transcript(entries)
    status = str(metadata.get('status', 'unknown')).lower()
    status_class = 'active' if status == 'active' else 'inactive'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{
    --bg: #0b1020;
    --bg-2: #111827;
    --panel: rgba(17,24,39,.82);
    --panel-2: rgba(15,23,42,.88);
    --text: #e5e7eb;
    --muted: #94a3b8;
    --border: rgba(148,163,184,.18);
    --accent: #60a5fa;
    --accent-2: #22c55e;
    --cmd: #f59e0b;
    --event: #a855f7;
    --danger: #ef4444;
    --shadow: 0 18px 40px rgba(0,0,0,.35);
}}

* {{ box-sizing: border-box; }}

html, body {{
margin: 0;
padding: 0;
background:
radial-gradient(circle at top right, rgba(96,165,250,.12), transparent 35%),
radial-gradient(circle at bottom left, rgba(34,197,94,.08), transparent 30%),
var(--bg);
color: var(--text);
font-family: Inter, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
line-height: 1.55;
}}

.wrap {{
max-width: 1180px;
margin: 0 auto;
padding: 36px 24px 56px;
}}

.hero {{
position: relative;
overflow: hidden;
background: linear-gradient(135deg, rgba(30,41,59,.98), rgba(15,23,42,.98));
border: 1px solid var(--border);
border-radius: 22px;
padding: 34px;
margin-bottom: 26px;
box-shadow: var(--shadow);
}}

.hero::after {{
content: "";
position: absolute;
inset: 0;
background:
linear-gradient(120deg, transparent 0%, rgba(255,255,255,.05) 45%, transparent 70%);
pointer-events: none;
}}

.brand {{
display: flex;
align-items: center;
justify-content: space-between;
gap: 18px;
}}

.brand h1 {{
margin: 0 0 8px;
font-size: 2rem;
font-weight: 800;
letter-spacing: -0.02em;
}}

.subtitle {{
margin: 0;
color: var(--muted);
}}

.status-pill {{
display: inline-flex;
align-items: center;
gap: 8px;
padding: 10px 16px;
border-radius: 999px;
border: 1px solid var(--border);
background: rgba(255,255,255,.04);
font-size: .85rem;
font-weight: 700;
text-transform: uppercase;
letter-spacing: .08em;
}}

.status-pill.active {{ color: #4ade80; }}
.status-pill.inactive {{ color: #f87171; }}

.grid {{
display: grid;
grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
gap: 16px;
margin-top: 24px;
}}

.card {{
background: rgba(255,255,255,.04);
border: 1px solid var(--border);
border-radius: 18px;
padding: 18px;
}}

.card .label {{
color: var(--muted);
font-size: .8rem;
text-transform: uppercase;
letter-spacing: .08em;
}}

.card .value {{
margin-top: 8px;
font-size: 1.15rem;
font-weight: 700;
}}

section {{
background: var(--panel);
border: 1px solid var(--border);
border-radius: 18px;
padding: 22px;
margin-bottom: 22px;
box-shadow: var(--shadow);
}}

.section-head {{
display: flex;
align-items: center;
justify-content: space-between;
gap: 12px;
margin-bottom: 18px;
}}

.section-head h2 {{
margin: 0;
font-size: 1.15rem;
}}

.badge {{
display: inline-flex;
align-items: center;
gap: 6px;
padding: 6px 10px;
border-radius: 999px;
font-size: .72rem;
font-weight: 700;
letter-spacing: .06em;
text-transform: uppercase;
}}

.badge.blue {{
background: rgba(96,165,250,.14);
color: #93c5fd;
border: 1px solid rgba(96,165,250,.22);
}}

.badge.green {{
background: rgba(34,197,94,.14);
color: #86efac;
border: 1px solid rgba(34,197,94,.22);
}}

table {{
width: 100%;
border-collapse: collapse;
overflow: hidden;
border-radius: 14px;
}}

th, td {{
padding: 12px 14px;
border-bottom: 1px solid rgba(148,163,184,.14);
vertical-align: top;
}}

th {{
width: 220px;
color: var(--muted);
font-weight: 600;
}}

tbody tr:nth-child(odd) {{
background: rgba(255,255,255,.02);
}}

.entry {{
background: var(--panel-2);
border: 1px solid var(--border);
border-radius: 16px;
padding: 16px;
margin-bottom: 16px;
}}

.meta {{
display: flex;
align-items: center;
justify-content: space-between;
gap: 12px;
margin-bottom: 12px;
color: var(--muted);
font-size: .9rem;
}}

.meta .left {{
display: flex;
align-items: center;
gap: 10px;
}}

.cmd-badge {{
background: rgba(245,158,11,.14);
color: var(--cmd);
border: 1px solid rgba(245,158,11,.22);
}}

.event-badge {{
background: rgba(168,85,247,.14);
color: #d8b4fe;
border: 1px solid rgba(168,85,247,.22);
}}

pre {{
margin: 0;
white-space: pre-wrap;
word-break: break-word;
font-family: "JetBrains Mono", Consolas, "SFMono-Regular", monospace;
font-size: .92rem;
}}

.command-text {{
color: var(--cmd);
background: rgba(245,158,11,.08);
border: 1px solid rgba(245,158,11,.18);
border-radius: 12px;
padding: 12px;
margin-bottom: 12px;
}}

.output {{
background: #060b16;
border: 1px solid rgba(148,163,184,.18);
border-radius: 12px;
padding: 14px;
overflow-x: auto;
}}

.output.empty {{
color: var(--muted);
font-style: italic;
}}

.event-text {{
color: #e9d5ff;
background: rgba(168,85,247,.08);
border: 1px solid rgba(168,85,247,.18);
border-radius: 12px;
padding: 12px;
}}

.empty {{
color: var(--muted);
}}

footer {{
text-align: center;
color: var(--muted);
font-size: .85rem;
padding-top: 8px;
}}

@media (max-width: 720px) {{
.brand {{
flex-direction: column;
align-items: flex-start;
}}

```
.meta {{
    flex-direction: column;
    align-items: flex-start;
}}

th {{
    width: 150px;
}}
```

}} </style>

</head>
<body>
<div class="wrap">

<header class="hero">
    <div class="brand">
        <div>
            <h1>{html.escape(title)}</h1>
            <p class="subtitle">Generated {html.escape(generated)} · TornadoRevC2 Session Transcript Export</p>
        </div>
        <div class="status-pill {status_class}">{html.escape(status.title())}</div>
    </div>

```
<div class="grid">
    <div class="card">
        <div class="label">Target Host</div>
        <div class="value">{html.escape(str(metadata.get('hostname') or '—'))}</div>
    </div>
    <div class="card">
        <div class="label">User</div>
        <div class="value">{html.escape(str(metadata.get('username') or '—'))}</div>
    </div>
    <div class="card">
        <div class="label">Operating System</div>
        <div class="value">{html.escape(str(metadata.get('os') or '—'))}</div>
    </div>
    <div class="card">
        <div class="label">Protocol</div>
        <div class="value">{html.escape(str(metadata.get('protocol') or '—'))}</div>
    </div>
</div>
```

</header>

<section>
    <div class="section-head">
        <h2>Session Metadata</h2>
        <span class="badge blue">Forensic Summary</span>
    </div>
    <table>
        <tbody>{rows}</tbody>
    </table>
</section>

<section>
    <div class="section-head">
        <h2>Command & Output Transcript</h2>
        <span class="badge green">{len(entries)} entries</span>
    </div>
    {transcript}
</section>

<footer>
    <strong>TornadoRevC2</strong> · Session transcript report · Authorized use only
</footer>

</div>
</body>
</html>
"""

class SessionExporter:
    """Build HTML transcript reports for active or archived sessions."""

    def __init__(self, handler):
        self.h = handler

    def _registry_record(self, session_id):
        registry = self.h.registry._data.get('sessions', {})
        matches = [rec for rec in registry.values() if rec.get('session_id') == session_id]
        if not matches:
            return None
        matches.sort(key=lambda rec: rec.get('last_seen', ''), reverse=True)
        return matches[0]

    def _active_info(self, session_id):
        with self.h.client_lock:
            for sock, info in self.h.revshell_clients.items():
                try:
                    if info.get('id') == session_id and sock.fileno() != -1:
                        return info
                except Exception:
                    pass
        return None

    def _resolve_log_paths(self, session_id, active_info=None, registry_rec=None):
        logger = active_info.get('logger') if active_info else None
        if logger and os.path.isfile(logger.command_log):
            return logger.command_log, logger.sysinfo_path, logger.session_dir

        log_session_id = None
        log_dir = None
        if registry_rec:
            log_session_id = registry_rec.get('log_session_id')
            log_dir = registry_rec.get('log_dir')

        if log_session_id:
            safe = _sanitize(log_session_id)
            session_dir = log_dir or os.path.join(LOGS_DIR, safe)
            return (
                os.path.join(session_dir, 'session.log'),
                os.path.join(session_dir, 'sysinfo.json'),
                session_dir,
            )

        if log_dir and os.path.isdir(log_dir):
            return (
                os.path.join(log_dir, 'session.log'),
                os.path.join(log_dir, 'sysinfo.json'),
                log_dir,
            )
        return None, None, None

    def _build_metadata(self, session_id, active_info, registry_rec, sysinfo, entries, log_dir):
        identity = (active_info or {}).get('identity') or (registry_rec or {}).get('identity') or {}
        sysinfo = sysinfo or (active_info or {}).get('sysinfo') or (registry_rec or {}).get('sysinfo') or {}

        hostname = sysinfo.get('hostname') or identity.get('hostname') or '—'
        username = sysinfo.get('username') or identity.get('username') or '—'
        os_name = sysinfo.get('os') or (active_info or {}).get('type') or (registry_rec or {}).get('type') or '—'
        architecture = sysinfo.get('architecture') or '—'

        if active_info:
            addr = active_info.get('addr') or ('—', '—')
            status = 'active'
            name = active_info.get('name')
            shell_type = active_info.get('type')
            protocol = 'TLS' if active_info.get('tls') else 'TCP'
            connect_count = active_info.get('connect_count', 1)
        else:
            addr = tuple(registry_rec.get('addr') or ['—', '—']) if registry_rec else ('—', '—')
            status = registry_rec.get('status', 'unknown') if registry_rec else 'unknown'
            name = registry_rec.get('name') if registry_rec else None
            shell_type = registry_rec.get('type') if registry_rec else '—'
            protocol = 'TLS' if registry_rec and registry_rec.get('tls') else 'TCP'
            connect_count = registry_rec.get('connect_count', 1) if registry_rec else 1

        connected_at = _first_event_time(entries, 'session connected') or _first_event_time(entries, 'connected from')
        if not connected_at and entries:
            connected_at = entries[0].get('timestamp')
        disconnected_at = _last_event_time(entries, 'session disconnected')
        if status != 'active' and not disconnected_at and registry_rec:
            disconnected_at = registry_rec.get('last_seen')

        return {
            'session_id': session_id,
            'name': name,
            'hostname': hostname,
            'username': username,
            'os': os_name,
            'architecture': architecture,
            'ip_address': addr[0] if addr else '—',
            'remote_port': addr[1] if addr and len(addr) > 1 else '—',
            'protocol': protocol,
            'shell_type': shell_type,
            'status': status,
            'connected_at': connected_at or '—',
            'disconnected_at': '—' if status == 'active' else (disconnected_at or '—'),
            'connect_count': connect_count,
            'log_dir': log_dir or '—',
        }

    def export_session(self, session_id):
        active_info = self._active_info(session_id)
        registry_rec = self._registry_record(session_id)
        if not active_info and not registry_rec:
            print(f"{self.h.colors['red']}Session #{session_id} not found{self.h.colors['end']}")
            return False

        log_path, sysinfo_path, log_dir = self._resolve_log_paths(session_id, active_info, registry_rec)
        if not log_path or not os.path.isfile(log_path):
            print(f"{self.h.colors['red']}No session log found for #{session_id}{self.h.colors['end']}")
            return False

        entries = _parse_session_log(log_path)
        sysinfo = _load_sysinfo(sysinfo_path)
        metadata = self._build_metadata(session_id, active_info, registry_rec, sysinfo, entries, log_dir)
        report_html = _build_html(metadata, entries)

        os.makedirs(EXPORTS_DIR, exist_ok=True)
        date_stamp = datetime.datetime.now().strftime('%Y-%m-%d')
        filename = f"session_{session_id}_{date_stamp}.html"
        out_path = os.path.join(EXPORTS_DIR, filename)
        if os.path.exists(out_path):
            suffix = datetime.datetime.now().strftime('%H%M%S')
            filename = f"session_{session_id}_{date_stamp}_{suffix}.html"
            out_path = os.path.join(EXPORTS_DIR, filename)

        with open(out_path, 'w', encoding='utf-8') as fh:
            fh.write(report_html)

        print(f"{self.h.colors['green']}Exported session #{session_id} transcript{self.h.colors['end']}")
        print(f"{self.h.colors['cyan']}  {os.path.abspath(out_path)}{self.h.colors['end']}")
        return True

    def handle_command(self, cmd_parts, client_sock=None):
        if not cmd_parts or cmd_parts[0].lower() != 'export':
            return False
        if client_sock is not None:
            info = self.h._client_info(client_sock)
            if not info:
                print(f"{self.h.colors['red']}Client disconnected{self.h.colors['end']}")
                return True
            self.export_session(info['id'])
            return True
        if len(cmd_parts) < 2:
            print(f"{self.h.colors['red']}Usage: export <session_id>{self.h.colors['end']}")
            return True
        try:
            session_id = int(cmd_parts[1])
        except ValueError:
            print(f"{self.h.colors['red']}Invalid session ID{self.h.colors['end']}")
            return True
        self.export_session(session_id)
        return True
