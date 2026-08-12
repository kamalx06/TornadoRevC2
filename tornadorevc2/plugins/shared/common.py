"""Shared plugin utilities."""

from typing import Any, Dict, List, Optional


CONFIDENCE_ORDER = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def merge_confidence(current: str, new: str) -> str:
    cur = CONFIDENCE_ORDER.get((current or 'none').lower(), 0)
    nxt = CONFIDENCE_ORDER.get((new or 'none').lower(), 0)
    for label, val in CONFIDENCE_ORDER.items():
        if val == max(cur, nxt):
            return label
    return 'none'


def confidence_percent(score: float) -> str:
    return f"{max(0, min(100, int(round(score))))}%"


def normalize_platform(platform: str) -> str:
    p = (platform or 'unknown').lower()
    if p in ('unix', 'linux', 'bsd'):
        return 'linux'
    if p == 'windows':
        return 'windows'
    return p


def platform_supported(cmd_platforms: List[str], session_platform: str) -> bool:
    norm = normalize_platform(session_platform)
    normalized = {normalize_platform(p) for p in cmd_platforms}
    if 'linux' in normalized and norm in ('linux', 'unix'):
        return True
    return norm in normalized or 'unknown' in normalized


def format_section(title: str, fields: Dict[str, Any], width: int = 22) -> str:
    lines = [title, '-' * len(title)]
    for key, value in fields.items():
        if value is None or value == '':
            continue
        if isinstance(value, list):
            if not value:
                continue
            lines.append(f"{key + ':':<{width}}{value[0]}")
            for item in value[1:]:
                lines.append(f"{'':<{width}}{item}")
        elif isinstance(value, dict):
            for sk, sv in value.items():
                if sv:
                    lines.append(f"  {sk}: {sv}")
        else:
            lines.append(f"{key + ':':<{width}}{value}")
    return '\n'.join(lines)


def format_list_section(title: str, items: List[str], empty: str = '(none)') -> str:
    lines = [title, '-' * len(title)]
    if not items:
        lines.append(empty)
    else:
        for item in items:
            lines.append(f"- {item}")
    return '\n'.join(lines)


def format_table_section(title: str, rows: List[Dict[str, str]], columns: List[str]) -> str:
    lines = [title, '-' * len(title)]
    if not rows:
        lines.append('(none)')
        return '\n'.join(lines)
    for row in rows[:80]:
        parts = [f"{col}={row.get(col, '')}" for col in columns if row.get(col)]
        lines.append('  ' + ' | '.join(parts))
    if len(rows) > 80:
        lines.append(f"  ... and {len(rows) - 80} more")
    return '\n'.join(lines)


def format_virtualization_report(data: Dict[str, Any]) -> str:
    sections = []
    env = {}
    for label, key in (
        ('Type', 'environment_type'),
        ('Runtime', 'runtime'),
        ('Orchestrator', 'orchestrator'),
        ('Namespace', 'namespace'),
        ('Node', 'node'),
        ('Container ID', 'container_id'),
        ('Host Relationship', 'host_relationship'),
        ('Virtualization', 'virtualization_type'),
        ('Cloud Provider', 'cloud_provider'),
        ('Host Access', 'host_access'),
        ('Container Privileges', 'container_privileges'),
        ('Nested Virtualization', 'nested_virtualization'),
        ('Hardware Virtualization', 'hardware_virtualization'),
        ('Sandbox / Analysis VM', 'sandbox_indicators'),
        ('Confidence', 'confidence'),
    ):
        val = data.get(key)
        if val not in (None, '', [], {}):
            if key == 'confidence' and isinstance(val, (int, float)):
                env[label] = confidence_percent(val)
            else:
                env[label] = val
    if env:
        sections.append(format_section('Environment', env))

    indicators = data.get('indicators') or []
    if indicators:
        sections.append(format_list_section('Indicators', indicators))

    namespaces = data.get('namespaces') or {}
    if namespaces:
        sections.append(format_section('Namespaces', namespaces))

    sockets = data.get('sockets') or []
    if sockets:
        sections.append(format_list_section('Runtime Sockets', sockets))

    artifacts = data.get('artifacts') or []
    if artifacts:
        sections.append(format_list_section('Artifacts', artifacts))

    cloud = data.get('cloud_metadata') or {}
    if cloud:
        sections.append(format_section('Cloud Metadata', cloud))

    detections = data.get('detections') or {}
    if detections:
        det_lines = ['Detections', '-' * 11]
        for name, info in sorted(detections.items()):
            if not isinstance(info, dict):
                continue
            mark = 'yes' if info.get('detected') else 'no'
            conf = info.get('confidence', 'none')
            if isinstance(conf, (int, float)):
                conf = confidence_percent(conf)
            det_lines.append(f"  {name:<20} {mark} ({conf})")
            for ind in info.get('indicators') or []:
                det_lines.append(f"    - {ind}")
        sections.append('\n'.join(det_lines))

    if not sections:
        return 'No virtualization or container environment detected.'
    return '\n\n'.join(sections)


def format_generic_report(data: Dict[str, Any], title: str = 'Results') -> str:
    sections = []
    summary = data.get('summary') or {}
    if summary:
        sections.append(format_section('Summary', summary))
    for key, value in data.items():
        if key in ('summary', 'raw'):
            continue
        if isinstance(value, list) and value:
            if isinstance(value[0], dict):
                cols = list(value[0].keys())[:6]
                sections.append(format_table_section(key.replace('_', ' ').title(), value, cols))
            else:
                sections.append(format_list_section(key.replace('_', ' ').title(), [str(v) for v in value]))
        elif isinstance(value, dict) and value:
            sections.append(format_section(key.replace('_', ' ').title(), value))
    if not sections:
        return f'{title}: no data collected.'
    return '\n\n'.join(sections)


def format_quickenum_report(data: Dict[str, Any]) -> str:
    sections = []
    host = data.get('host_summary') or {}
    if host:
        sections.append(format_section('Host Summary', host))
    user = data.get('user') or {}
    if user:
        sections.append(format_section('User', user))
    env = data.get('environment') or {}
    if env:
        sections.append(format_section('Environment', env))
    network = data.get('network') or {}
    if network:
        sections.append(format_section('Network', network))
    for title, key in (
        ('Storage', 'storage'),
        ('Services', 'services'),
        ('Security', 'security'),
        ('Credentials', 'credentials'),
        ('Persistence', 'persistence'),
    ):
        block = data.get(key) or {}
        if block:
            sections.append(format_section(title, block))
    findings = data.get('findings') or []
    if findings:
        sections.append(format_list_section('Findings', [str(f) for f in findings]))
    elapsed = data.get('elapsed_sec')
    if elapsed is not None:
        sections.append(f'Collection time: {elapsed:.1f}s')
    if not sections:
        return 'QuickEnum: no data collected.'
    return '\n\n'.join(sections)


def format_wiper_report(data: Dict[str, Any]) -> str:
    lines = ['Secure Wipe Result', '-' * 18]
    for key in ('path', 'size', 'passes', 'method', 'verified', 'platform'):
        val = data.get(key)
        if val not in (None, ''):
            lines.append(f'{key.replace("_", " ").title():<12}{val}')
    if data.get('message'):
        lines.append(f"Message:     {data['message']}")
    if data.get('error'):
        lines.append(f"Error:       {data['error']}")
    return '\n'.join(lines)
