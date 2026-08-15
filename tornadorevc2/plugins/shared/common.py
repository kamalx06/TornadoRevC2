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


def filter_commands_by_platform(commands, session_platform: str):
    """Return only commands compatible with the given session platform."""
    return {
        name: cmd
        for name, cmd in commands.items()
        if platform_supported(cmd.platforms, session_platform)
    }


def resolve_session_platform(session) -> str:
    """Resolve unix/windows for collector dispatch, including unknown sessions."""
    platform = session.platform
    if platform and platform != 'unknown':
        return platform
    resolved = session._handler.resolve_shell_type(session._client_sock)
    return resolved or platform or 'unknown'


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


def format_containers_report(data: Dict[str, Any]) -> str:
    sections = []
    summary = data.get('summary') or {}
    if summary:
        sections.append(format_section('Summary', summary))

    sockets = data.get('runtime_sockets') or []
    if sockets:
        sock_lines = []
        for s in sockets:
            if isinstance(s, dict):
                sock_lines.append(f"{s.get('path', '?')} (mode={s.get('mode', 'N/A')})")
            else:
                sock_lines.append(str(s))
        sections.append(format_list_section('Runtime Sockets', sock_lines))

    runtimes = data.get('runtimes') or {}
    if runtimes:
        rt_fields = {}
        for name, meta in runtimes.items():
            if name == 'data_dirs' or not isinstance(meta, dict):
                continue
            parts = []
            for key in ('version', 'client', 'rootless', 'storage_driver', 'cgroup_driver', 'swarm', 'service'):
                val = meta.get(key)
                if val not in (None, '', 'N/A'):
                    parts.append(f'{key}={val}')
            rt_fields[name] = '; '.join(parts) if parts else 'detected'
        if rt_fields:
            sections.append(format_section('Runtimes', rt_fields))

    data_dirs = runtimes.get('data_dirs') if isinstance(runtimes, dict) else None
    if data_dirs:
        sections.append(format_table_section('Data Directories', data_dirs, ['runtime', 'path', 'entries']))

    for title, key, cols in (
        ('Containers', 'containers', ['runtime', 'name', 'image', 'state', 'status', 'ports']),
        ('Images', 'images', ['runtime', 'name', 'repository', 'tag', 'size']),
        ('Networks', 'networks', ['runtime', 'name', 'driver', 'scope']),
        ('Volumes', 'volumes', ['runtime', 'name', 'driver']),
        ('Pods', 'pods', ['runtime', 'name', 'namespace', 'status', 'state']),
        ('Compose Projects', 'compose_projects', ['runtime', 'name', 'status', 'line']),
    ):
        block = data.get(key) or []
        if block:
            if isinstance(block[0], dict):
                sections.append(format_table_section(title, block, cols))
            else:
                sections.append(format_list_section(title, [str(v) for v in block]))

    k8s = data.get('kubernetes') or {}
    if k8s:
        k8s_summary = {}
        for label, key in (
            ('Client', 'client_version'),
            ('Context', 'context'),
            ('Cluster', 'cluster'),
            ('API Server', 'api_server'),
            ('K3s', 'k3s'),
            ('MicroK8s', 'microk8s'),
        ):
            val = k8s.get(key)
            if val not in (None, '', [], {}):
                k8s_summary[label] = val if not isinstance(val, list) else f'{len(val)} entries'
        if k8s_summary:
            sections.append(format_section('Kubernetes', k8s_summary))
        for title, key in (
            ('K8s Nodes', 'nodes'),
            ('K8s Namespaces', 'namespaces'),
            ('K8s Pods', 'pods'),
            ('K8s Deployments', 'deployments'),
            ('K8s Services', 'services'),
            ('Helm Releases', 'helm_releases'),
        ):
            block = k8s.get(key) or []
            if block:
                sections.append(format_list_section(title, [str(v) for v in block[:40]]))

    units = data.get('systemd_units') or []
    if units:
        sections.append(format_table_section('Container Systemd Units', units, ['unit', 'active', 'sub', 'desc']))

    procs = data.get('container_processes') or []
    if procs:
        sections.append(format_table_section('Container Processes', procs, ['pid', 'user', 'cmd']))

    if not sections:
        return 'Containers: no container runtime data collected.'
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


def format_clipboard_report(data: Dict[str, Any]) -> str:
    if not data.get('ok'):
        reason = data.get('reason') or data.get('error') or 'unknown error'
        return f'Clipboard read failed: {reason}'
    text = data.get('text', '')
    tool = data.get('tool', 'unknown')
    preview = text if len(text) <= 200 else text[:200] + '...'
    lines = [f'Clipboard ({tool}):', preview]
    if len(text) > 200:
        lines.append(f'({len(text)} characters total)')
    return '\n'.join(lines)


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


def format_screenshot_report(data: Dict[str, Any]) -> str:
    if not data.get('ok'):
        reason = data.get('reason') or data.get('error') or 'unknown error'
        return f'Screenshot capture failed: {reason}'
    lines = [
        'Screenshot captured successfully',
        f"Tool:     {data.get('tool', 'unknown')}",
        f"Size:     {data.get('width', '?')}x{data.get('height', '?')}",
    ]
    if data.get('saved_path'):
        lines.append(f"Saved:    {data['saved_path']}")
    if data.get('bytes'):
        lines.append(f"Bytes:    {data['bytes']}")
    return '\n'.join(lines)


def format_memorymap_report(data: Dict[str, Any]) -> str:
    sections = []
    summary = data.get('summary') or {}
    if summary:
        sections.append(format_section('Process', summary))
    for key in ('memory_maps', 'modules', 'loaded_libraries'):
        block = data.get(key)
        if isinstance(block, list) and block:
            if isinstance(block[0], dict):
                cols = list(block[0].keys())[:6]
                sections.append(format_table_section(key.replace('_', ' ').title(), block, cols))
            else:
                sections.append(format_list_section(key.replace('_', ' ').title(), [str(v) for v in block[:60]]))
        elif isinstance(block, str) and block.strip():
            sections.append(format_list_section(key.replace('_', ' ').title(), block.strip().splitlines()[:60]))
    if not sections:
        return 'Memory map: no data collected.'
    return '\n\n'.join(sections)


def format_firewall_report(data: Dict[str, Any]) -> str:
    sections = []
    summary = data.get('summary') or {}
    if summary:
        sections.append(format_section('Summary', summary))
    for key in (
        'windows_defender_firewall', 'ufw', 'firewalld', 'nftables',
        'iptables', 'ip6tables', 'other',
    ):
        block = data.get(key)
        if isinstance(block, dict) and block:
            sections.append(format_section(key.replace('_', ' ').title(), block))
        elif isinstance(block, list) and block:
            sections.append(format_list_section(key.replace('_', ' ').title(), [str(v) for v in block]))
    rules = data.get('notable_rules') or []
    if rules:
        if isinstance(rules[0], dict):
            cols = list(rules[0].keys())[:6]
            sections.append(format_table_section('Notable Rules', rules, cols))
        else:
            sections.append(format_list_section('Notable Rules', [str(r) for r in rules]))
    if not sections:
        return 'Firewall: no data collected.'
    return '\n\n'.join(sections)


def _sshaudit_flag(val: Any) -> str:
    if isinstance(val, bool):
        return 'yes' if val else 'no'
    if val in (None, ''):
        return '-'
    return str(val)


def _sshaudit_basename(path: str) -> str:
    if not path:
        return ''
    if path.startswith('('):
        return path.strip('()')
    return path.rsplit('/', 1)[-1]


def _sshaudit_source(item: Dict[str, Any]) -> str:
    file_path = item.get('file') or ''
    line = item.get('line')
    if file_path in ('(default)', '(unset)', '(unknown)'):
        return 'default'
    if file_path == 'sshd -T':
        return 'sshd -T'
    name = _sshaudit_basename(file_path)
    if line:
        return f'{name}:{line}'
    return name or '?'


def _sshaudit_notes_by_interest(notes: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped = {'high': [], 'medium': [], 'low': []}
    for item in notes:
        level = (item.get('interest') or 'low').lower()
        if level not in grouped:
            level = 'low'
        grouped[level].append(item)
    return grouped


def _format_sshaudit_interest_block(title: str, notes: List[Dict[str, Any]]) -> str:
    if not notes:
        return ''
    lines = [title, '-' * len(title)]
    for item in notes[:40]:
        param = item.get('parameter', '?')
        value = item.get('value', '')
        source = _sshaudit_source(item)
        lines.append(f'  {param} = {value}  [{source}]')
        note = item.get('note')
        if note:
            lines.append(f'    -> {note}')
    if len(notes) > 40:
        lines.append(f'  ... and {len(notes) - 40} more')
    return '\n'.join(lines)


def format_sshaudit_report(data: Dict[str, Any]) -> str:
    sections = []
    summary = data.get('summary') or {}
    auth = summary.get('auth_surface') or {}
    pivot = summary.get('pivot_surface') or {}
    ssh_ver = data.get('ssh_version') or {}

    header = ['SSH Enumeration', '=' * 15]
    version = summary.get('sshd_version') or ssh_ver.get('version') or '?'
    listen = summary.get('listen') or '?'
    config_count = summary.get('config_files', 0)
    ca_status = summary.get('ca_status') or 'unknown'
    header.append(
        f"OpenSSH {version}  |  listen {listen}  |  {config_count} config file(s)  |  CA: {ca_status}"
    )
    if ssh_ver.get('raw'):
        header.append(str(ssh_ver.get('raw', '').splitlines()[0]))
    high = summary.get('high_interest', 0)
    medium = summary.get('medium_interest', 0)
    low = summary.get('low_interest', 0)
    header.append(f"Notes: {high} high, {medium} medium, {low} low")
    sections.append('\n'.join(header))

    auth_lines = ['Auth']
    for label, key in (
        ('PermitRootLogin', 'root_login'),
        ('PasswordAuthentication', 'password_auth'),
        ('PubkeyAuthentication', 'pubkey_auth'),
        ('PermitEmptyPasswords', 'empty_passwords'),
    ):
        val = auth.get(key)
        if key == 'root_login':
            display = val if val not in (None, '') else '?'
        else:
            display = _sshaudit_flag(val)
        auth_lines.append(f'  {label}: {display}')

    pivot_lines = ['Pivot']
    for label, key in (
        ('AllowTcpForwarding', 'tcp_forwarding'),
        ('AllowAgentForwarding', 'agent_forwarding'),
        ('GatewayPorts', 'gateway_ports'),
        ('PermitTunnel', 'tunnel'),
    ):
        pivot_lines.append(f'  {label}: {_sshaudit_flag(pivot.get(key))}')

    sections.append('\n'.join(auth_lines + [''] + pivot_lines))

    all_notes = (
        (data.get('authentication_notes') or [])
        + (data.get('access_notes') or [])
        + (data.get('cryptography_notes') or [])
        + (data.get('file_notes') or [])
        + (data.get('configuration_notes') or [])
        + (data.get('protocol_notes') or [])
        + (data.get('certificate_authority_notes') or [])
    )
    grouped = _sshaudit_notes_by_interest(all_notes)
    for title, level in (
        ('High Interest', 'high'),
        ('Medium Interest', 'medium'),
        ('Low Interest', 'low'),
    ):
        block = _format_sshaudit_interest_block(title, grouped.get(level) or [])
        if block:
            sections.append(block)

    config_files = data.get('configuration_files') or []
    if config_files:
        lines = ['Config Sources', '-' * 14]
        for item in config_files[:20]:
            path = item.get('path', '?')
            mode = item.get('mode', '')
            flags = []
            if item.get('writable'):
                flags.append('writable')
            suffix = f" ({', '.join(flags)})" if flags else ''
            lines.append(f'  {path}  {mode}{suffix}')
        sections.append('\n'.join(lines))

    ca = data.get('certificate_authority') or {}
    if ca and ca.get('status') not in (None, '', 'not configured'):
        ca_lines = ['CA Trust', '-' * 8, f"  status: {ca.get('status')}"]
        for label, key in (
            ('principals file', 'authorized_principals_file'),
            ('principals cmd', 'authorized_principals_command'),
            ('sig algorithms', 'ca_signature_algorithms'),
        ):
            val = ca.get(key)
            if val:
                ca_lines.append(f'  {label}: {val}')
        tuca = ca.get('trusted_user_ca_keys') or []
        for entry in tuca[:8]:
            ca_lines.append(f"  trusted CA: {entry.get('path', '?')}")
        sections.append('\n'.join(ca_lines))

    host_keys = data.get('host_keys') or []
    if host_keys:
        lines = ['Host Keys', '-' * 9]
        for item in host_keys[:20]:
            path = item.get('path', '?')
            bits = item.get('bits')
            extra = f" {bits}-bit" if bits else ''
            lines.append(f"  {path}{extra}  {item.get('mode', '')}")
        sections.append('\n'.join(lines))

    auth_keys = data.get('authorized_keys') or []
    if auth_keys:
        lines = ['Authorized Keys', '-' * 15]
        for item in auth_keys[:20]:
            path = item.get('path', '?')
            flags = []
            if item.get('writable'):
                flags.append('writable')
            suffix = f" ({', '.join(flags)})" if flags else ''
            lines.append(f"  {path}  {item.get('keys', 0)} key(s){suffix}")
        sections.append('\n'.join(lines))

    overrides = data.get('configuration_overrides') or []
    if overrides:
        lines = ['Config Overrides', '-' * 16]
        for item in overrides[:20]:
            param = item.get('parameter', '?')
            prev = f"{_sshaudit_basename(item.get('previous_file', ''))}:{item.get('previous_line', '')}={item.get('previous_value', '')}"
            curr = f"{_sshaudit_basename(item.get('current_file', ''))}:{item.get('current_line', '')}={item.get('current_value', '')}"
            lines.append(f'  {param}: {prev} -> {curr}')
        sections.append('\n'.join(lines))

    if not sections:
        return 'SSH enumeration: no data collected.'
    return '\n\n'.join(sections)


def format_eventlogdel_report(data: Dict[str, Any]) -> str:
    lines = ['Event Log Clear Result', '-' * 24]
    summary = data.get('summary') or {}
    for key, value in summary.items():
        if value not in (None, ''):
            lines.append(f"{key.replace('_', ' ').title():<18}{value}")
    cleared = data.get('cleared') or []
    if cleared:
        lines.append('')
        lines.append('Cleared logs:')
        for item in cleared:
            lines.append(f"  - {item}")
    failed = data.get('failed') or []
    if failed:
        lines.append('')
        lines.append('Failed logs:')
        for item in failed:
            if isinstance(item, dict):
                lines.append(f"  - {item.get('log', '?')}: {item.get('error', 'unknown')}")
            else:
                lines.append(f"  - {item}")
    if data.get('message'):
        lines.append('')
        lines.append(str(data['message']))
    if data.get('error') and not cleared:
        lines.append(f"Error: {data['error']}")
    return '\n'.join(lines)


def format_historydel_report(data: Dict[str, Any]) -> str:
    lines = ['History Clear Result', '-' * 22]
    summary = data.get('summary') or {}
    for key, value in summary.items():
        if value not in (None, ''):
            lines.append(f"{key.replace('_', ' ').title():<18}{value}")
    cleared = data.get('cleared') or []
    if cleared:
        lines.append('')
        lines.append('Cleared locations:')
        for item in cleared:
            lines.append(f"  - {item}")
    failed = data.get('failed') or []
    if failed:
        lines.append('')
        lines.append('Failed locations:')
        for item in failed:
            if isinstance(item, dict):
                lines.append(f"  - {item.get('path', '?')}: {item.get('error', 'unknown')}")
            else:
                lines.append(f"  - {item}")
    if data.get('session_cleanup'):
        lines.append('')
        lines.append(f"Session cleanup: {data['session_cleanup']}")
    if data.get('message'):
        lines.append('')
        lines.append(str(data['message']))
    if data.get('error') and not cleared:
        lines.append(f"Error: {data['error']}")
    return '\n'.join(lines)


def format_wiper_report(data: Dict[str, Any]) -> str:
    lines = ['Secure Wipe Result', '-' * 18]
    for key in ('original_path', 'path', 'size', 'profile', 'passes', 'method', 'verified', 'platform'):
        val = data.get(key)
        if val not in (None, ''):
            lines.append(f'{key.replace("_", " ").title():<14}{val}')
    steps = data.get('steps') or []
    if steps:
        lines.append(f"{'Steps':<14}{', '.join(steps)}")
    if data.get('message'):
        lines.append(f"Message:       {data['message']}")
    if data.get('error'):
        lines.append(f"Error:         {data['error']}")
    return '\n'.join(lines)


def format_nullcrypt_report(data: Dict[str, Any], wiped: Optional[bool] = None) -> str:
    lines = ['Nullcrypt Result', '-' * 16]
    for key in ('path', 'output', 'size', 'output_size', 'algorithm', 'sha256', 'platform'):
        val = data.get(key)
        if val not in (None, ''):
            lines.append(f'{key.replace("_", " ").title():<14}{val}')
    if wiped is not None:
        lines.append(f"{'Original wiped':<14}{'yes' if wiped else 'no'}")
    wipe_steps = data.get('wipe_steps') or []
    if wipe_steps:
        lines.append(f"{'Wipe steps':<14}{', '.join(wipe_steps)}")
    if data.get('wipe_detail'):
        lines.append(f"{'Wipe detail':<14}{data['wipe_detail']}")
    if data.get('message'):
        lines.append(f"Message:       {data['message']}")
    if data.get('error'):
        lines.append(f"Error:         {data['error']}")
    return '\n'.join(lines)
