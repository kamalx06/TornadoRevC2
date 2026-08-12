"""Shared plugin utilities."""

from typing import Any, Dict, List


CONFIDENCE_ORDER = {'none': 0, 'low': 1, 'medium': 2, 'high': 3}


def merge_confidence(current: str, new: str) -> str:
    cur = CONFIDENCE_ORDER.get((current or 'none').lower(), 0)
    nxt = CONFIDENCE_ORDER.get((new or 'none').lower(), 0)
    for label, val in CONFIDENCE_ORDER.items():
        if val == max(cur, nxt):
            return label
    return 'none'


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


def format_section(title: str, fields: Dict[str, Any], width: int = 11) -> str:
    lines = [title, '-' * len(title)]
    for key, value in fields.items():
        if value is None or value == '':
            continue
        if isinstance(value, list):
            if not value:
                continue
            lines.append(f"{key + ':':<{width}}}}{value[0]}")
            for item in value[1:]:
                lines.append(f"{'':<{width}}{item}")
        else:
            lines.append(f"{key + ':':<{width}}{value}")
    return '\n'.join(lines)


def format_detection_report(data: Dict[str, Any]) -> str:
    env_fields = {}
    mapping = [
        ('Type', 'environment_type'),
        ('Container ID', 'container_id'),
        ('Runtime', 'runtime'),
        ('Orchestrator', 'orchestrator'),
        ('Namespace', 'namespace'),
        ('Node', 'node'),
        ('Host Relationship', 'host_relationship'),
        ('Virtualization', 'virtualization_type'),
        ('Confidence', 'confidence'),
    ]
    for label, key in mapping:
        val = data.get(key)
        if val:
            env_fields[label] = val

    sections = []
    if env_fields:
        sections.append(format_section('Environment', env_fields))

    indicators = data.get('indicators') or []
    if indicators:
        sections.append(format_section('Indicators', {'Found': indicators}))

    sockets = data.get('sockets') or []
    if sockets:
        sections.append(format_section('Runtime Sockets', {'Paths': sockets}))

    artifacts = data.get('artifacts') or []
    if artifacts:
        sections.append(format_section('Artifacts', {'Paths': artifacts}))

    detections = data.get('detections') or {}
    if detections:
        det_lines = ['Detections', '-' * 11]
        for name, info in sorted(detections.items()):
            status = info.get('detected', False)
            conf = info.get('confidence', 'none')
            mark = 'yes' if status else 'no'
            det_lines.append(f"  {name:<16} {mark} ({conf})")
            for ind in info.get('indicators') or []:
                det_lines.append(f"    - {ind}")
        sections.append('\n'.join(det_lines))

    if not sections:
        return 'No virtualization or container environment detected.'
    return '\n\n'.join(sections)
