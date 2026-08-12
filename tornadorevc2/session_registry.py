"""Handler-side session persistence for reconnect support."""

import datetime
import hashlib
import json
import os

from .constants import LOGS_DIR
from .session_log import SessionLogger, _sanitize


REGISTRY_DIR = os.path.join(LOGS_DIR, '.registry')
REGISTRY_FILE = os.path.join(REGISTRY_DIR, 'sessions.json')


def _norm(value):
    return str(value or '').strip().lower()


def normalize_ip(ip):
    ip = _norm(ip)
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    if ip == '::1':
        return '127.0.0.1'
    return ip


def _parse_hostname_from_probe(probe_output):
    for line in (probe_output or '').splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith('linux '):
            fields = line.split()
            if len(fields) >= 2:
                return _norm(fields[1])
        if lower.startswith('darwin '):
            fields = line.split()
            if len(fields) >= 2:
                return _norm(fields[1])
    return ''


def _norm_machine_id(value):
    value = str(value or '').strip().lower()
    return value.replace('{', '').replace('}', '')


def _machine_id_from_sources(sysinfo, identity):
    sysinfo = sysinfo or {}
    identity = identity or {}
    return _norm_machine_id(
        sysinfo.get('machine_id') or identity.get('machine_id')
    )


def machine_id_from_info(info, probe_output=''):
    sysinfo = info.get('sysinfo') if info else {}
    identity = info.get('identity') if info else {}
    return _machine_id_from_sources(sysinfo, identity)


def machine_id_from_record(record):
    if not record:
        return ''
    return _machine_id_from_sources(record.get('sysinfo'), record.get('identity'))


def identity_tuple(info, probe_output=''):
    sysinfo = info.get('sysinfo') or {}
    identity = info.get('identity') or {}
    hostname = _norm(sysinfo.get('hostname') or identity.get('hostname'))
    username = _norm(sysinfo.get('username') or identity.get('username'))
    machine_id = machine_id_from_info(info, probe_output)
    if not hostname:
        hostname = _parse_hostname_from_probe(probe_output)
    shell_type = _norm(info.get('type') or 'unknown')
    return hostname, username, shell_type, machine_id


def record_identity_tuple(record):
    sysinfo = record.get('sysinfo') or {}
    identity = record.get('identity') or {}
    return (
        _norm(sysinfo.get('hostname') or identity.get('hostname')),
        _norm(sysinfo.get('username') or identity.get('username')),
        _norm(record.get('type')),
        machine_id_from_record(record),
    )


def identities_match(incoming, stored, info=None, stored_record=None):
    in_host, in_user, in_type, in_mid = incoming
    rec_host, rec_user, rec_type, rec_mid = stored

    if in_mid and rec_mid:
        if in_mid != rec_mid:
            return False
        if in_user and rec_user:
            return in_user == rec_user
        return True

    if in_host and rec_host and in_host == rec_host:
        if in_user and rec_user:
            return in_user == rec_user
        return in_type == rec_type or not in_type or not rec_type
    if in_user and rec_user and in_user == rec_user and in_type == rec_type:
        return True
    if info and stored_record:
        in_ip = normalize_ip((info.get('addr') or ('',))[0])
        rec_ip = normalize_ip((stored_record.get('addr') or [''])[0])
        if in_ip and rec_ip and in_ip == rec_ip and in_type == rec_type:
            if in_host and rec_host and in_host == rec_host:
                return True
            if in_user and rec_user and in_user == rec_user:
                return True
    return False


def compute_fingerprint(info, probe_output=''):
    """Stable fingerprint from hostname, username, and persistent machine ID."""
    hostname, username, shell_type, machine_id = identity_tuple(info, probe_output)
    parts = [hostname, username, machine_id, shell_type]
    if not any([hostname, username, machine_id]):
        parts.append(normalize_ip((info.get('addr') or ('',))[0]))
    raw = '|'.join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


class SessionRegistry:
    """Preserve session metadata across disconnects and reconnects."""

    def __init__(self, base_dir=LOGS_DIR):
        self.base_dir = base_dir
        self.registry_dir = os.path.join(base_dir, '.registry')
        self.registry_file = os.path.join(self.registry_dir, 'sessions.json')
        os.makedirs(self.registry_dir, exist_ok=True)
        self._data = self._load()

    def _load(self):
        if not os.path.isfile(self.registry_file):
            return {'sessions': {}, 'reconnects': []}
        try:
            with open(self.registry_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            data.setdefault('sessions', {})
            data.setdefault('reconnects', [])
            return data
        except (json.JSONDecodeError, OSError):
            return {'sessions': {}, 'reconnects': []}

    def _save(self):
        try:
            with open(self.registry_file, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, indent=2)
                f.write('\n')
        except OSError:
            pass

    def _find_record_for_info(self, info):
        fp = info.get('fingerprint')
        if fp and fp in self._data['sessions']:
            return fp, self._data['sessions'][fp]
        sid = info.get('id')
        if sid is not None:
            for key, rec in self._data['sessions'].items():
                if rec.get('session_id') == sid:
                    return key, rec
        incoming = identity_tuple(info)
        for key, rec in self._data['sessions'].items():
            if identities_match(incoming, record_identity_tuple(rec), info, rec):
                return key, rec
        fp = compute_fingerprint(info)
        return fp, self._data['sessions'].get(fp, {})

    def register_active(self, info, fingerprint, probe_output=''):
        """Record or update metadata for an active session."""
        fp = fingerprint or compute_fingerprint(info, probe_output)
        info['fingerprint'] = fp
        record = {
            'session_id': info['id'],
            'fingerprint': fp,
            'name': info.get('name'),
            'type': info.get('type'),
            'tls': info.get('tls', False),
            'sysinfo': info.get('sysinfo'),
            'identity': info.get('identity'),
            'log_session_id': info.get('logger').session_id if info.get('logger') else None,
            'log_dir': info.get('logger').session_dir if info.get('logger') else None,
            'addr': list(info.get('addr') or ('', 0)),
            'status': 'active',
            'last_seen': datetime.datetime.now().isoformat(timespec='seconds'),
            'connect_count': info.get('connect_count', 1),
        }
        existing = self._data['sessions'].get(fp)
        if existing:
            if not record['name'] and existing.get('name'):
                record['name'] = existing['name']
            if not record['sysinfo'] and existing.get('sysinfo'):
                record['sysinfo'] = existing['sysinfo']
            if not record.get('identity') and existing.get('identity'):
                record['identity'] = existing['identity']
            if not record['log_session_id'] and existing.get('log_session_id'):
                record['log_session_id'] = existing['log_session_id']
                record['log_dir'] = existing.get('log_dir')
        record['connect_count'] = info.get('connect_count', record.get('connect_count', 1))
        self._data['sessions'][fp] = record
        self._save()
        return fp

    def find_reconnect(self, fingerprint, probe_output='', info=None, live_ids=None):
        """Return a prior session record that should be restored for this host."""
        live_ids = live_ids or set()
        incoming = identity_tuple(info or {}, probe_output)

        def is_restorable(rec):
            if not rec:
                return False
            sid = rec.get('session_id')
            if rec.get('status') == 'disconnected':
                return True
            return rec.get('status') == 'active' and sid not in live_ids

        if fingerprint:
            record = self._data['sessions'].get(fingerprint)
            if is_restorable(record):
                return record

        incoming_mid = machine_id_from_info(info or {}, probe_output)
        if incoming_mid:
            for rec in self._data['sessions'].values():
                if not is_restorable(rec):
                    continue
                if machine_id_from_record(rec) != incoming_mid:
                    continue
                incoming = identity_tuple(info or {}, probe_output)
                stored = record_identity_tuple(rec)
                if identities_match(incoming, stored, info, rec):
                    return rec

        best = None
        best_score = -1
        for rec in self._data['sessions'].values():
            if not is_restorable(rec):
                continue
            stored = record_identity_tuple(rec)
            if not identities_match(incoming, stored, info, rec):
                continue
            score = 0
            in_host, in_user, in_type, in_mid = incoming
            rec_host, rec_user, rec_type, rec_mid = stored
            if in_mid and rec_mid and in_mid == rec_mid:
                score += 10
            if in_host and rec_host and in_host == rec_host:
                score += 4
            if in_user and rec_user and in_user == rec_user:
                score += 4
            if in_type and rec_type and in_type == rec_type:
                score += 2
            if rec.get('status') == 'disconnected':
                score += 1
            if score > best_score:
                best = rec
                best_score = score

        return best

    def migrate_fingerprint(self, old_fp, new_fp, info):
        """Move registry state when fingerprint fields become available (e.g. after sysinfo)."""
        if not new_fp or not old_fp or old_fp == new_fp:
            return new_fp
        old_record = self._data['sessions'].pop(old_fp, None)
        if not old_record:
            return new_fp
        existing = self._data['sessions'].get(new_fp, {})
        merged = {**old_record, **existing}
        merged['fingerprint'] = new_fp
        merged['session_id'] = info.get('id', merged.get('session_id'))
        merged['status'] = info.get('status', merged.get('status', 'active'))
        merged['connect_count'] = max(
            old_record.get('connect_count', 1),
            existing.get('connect_count', 1),
        )
        if info.get('name'):
            merged['name'] = info['name']
        if info.get('sysinfo'):
            merged['sysinfo'] = info['sysinfo']
        if info.get('identity'):
            merged['identity'] = info['identity']
        logger = info.get('logger')
        if logger:
            merged['log_session_id'] = logger.session_id
            merged['log_dir'] = logger.session_dir
        self._data['sessions'][new_fp] = merged
        self._save()
        return new_fp

    def mark_disconnected(self, info):
        fp, record = self._find_record_for_info(info)
        if not fp:
            fp = compute_fingerprint(info)
        record = dict(record or {})
        record.update({
            'session_id': info['id'],
            'fingerprint': fp,
            'name': info.get('name'),
            'type': info.get('type'),
            'tls': info.get('tls', False),
            'sysinfo': info.get('sysinfo'),
            'identity': info.get('identity'),
            'log_session_id': info.get('logger').session_id if info.get('logger') else record.get('log_session_id'),
            'log_dir': info.get('logger').session_dir if info.get('logger') else record.get('log_dir'),
            'addr': list(info.get('addr') or ('', 0)),
            'status': 'disconnected',
            'last_seen': datetime.datetime.now().isoformat(timespec='seconds'),
            'connect_count': info.get('connect_count', record.get('connect_count', 1)),
        })
        old_keys = [key for key, rec in self._data['sessions'].items()
                    if key != fp and rec.get('session_id') == info.get('id')]
        for key in old_keys:
            self._data['sessions'].pop(key, None)
        self._data['sessions'][fp] = record
        info['fingerprint'] = fp
        self._save()

    def log_reconnect(self, old_id, new_id, fingerprint, addr):
        event = {
            'time': datetime.datetime.now().isoformat(timespec='seconds'),
            'fingerprint': fingerprint,
            'previous_id': old_id,
            'restored_id': new_id,
            'addr': list(addr),
        }
        self._data['reconnects'].append(event)
        if len(self._data['reconnects']) > 500:
            self._data['reconnects'] = self._data['reconnects'][-500:]
        if fingerprint in self._data['sessions']:
            rec = self._data['sessions'][fingerprint]
            rec['status'] = 'active'
            rec['session_id'] = new_id
            rec['connect_count'] = rec.get('connect_count', 1) + 1
            rec['last_seen'] = event['time']
            rec['addr'] = list(addr)
        self._save()

    def get_connect_count(self, fingerprint):
        return self._data.get('sessions', {}).get(fingerprint, {}).get('connect_count', 1)

    def restore_logger(self, log_session_id):
        """Reopen an existing session log directory."""
        if not log_session_id:
            return None
        safe = _sanitize(log_session_id)
        session_dir = os.path.join(self.base_dir, safe)
        if os.path.isdir(session_dir):
            logger = SessionLogger.__new__(SessionLogger)
            logger.session_id = log_session_id
            logger.session_dir = session_dir
            logger.command_log = os.path.join(session_dir, 'session.log')
            logger.sysinfo_path = os.path.join(session_dir, 'sysinfo.json')
            logger.transfers_dir = os.path.join(session_dir, 'transfers')
            logger.executions_dir = os.path.join(session_dir, 'executions')
            os.makedirs(logger.transfers_dir, exist_ok=True)
            os.makedirs(logger.executions_dir, exist_ok=True)
            return logger
        return SessionLogger(log_session_id, base_dir=self.base_dir)

    def list_sessions(self, colors):
        active = [r for r in self._data['sessions'].values() if r.get('status') == 'active']
        disconnected = [r for r in self._data['sessions'].values() if r.get('status') == 'disconnected']
        print(f"\n{colors['cyan']}SESSION REGISTRY{colors['end']}")
        print(f"{colors['green']}Active (tracked):{colors['end']} {len(active)}")
        for rec in sorted(active, key=lambda r: r.get('session_id', 0)):
            self._print_record(rec, colors)
        print(f"{colors['yellow']}Disconnected (awaiting reconnect):{colors['end']} {len(disconnected)}")
        for rec in sorted(disconnected, key=lambda r: r.get('last_seen', ''), reverse=True):
            self._print_record(rec, colors, disconnected=True)

    def list_reconnects(self, colors, limit=20):
        events = self._data.get('reconnects', [])
        print(f"\n{colors['cyan']}RECONNECT HISTORY{colors['end']} (last {limit})")
        if not events:
            print(f"{colors['yellow']}No reconnect events recorded{colors['end']}")
            return
        for ev in events[-limit:]:
            addr = ev.get('addr', ['?', '?'])
            print(
                f"  [{ev.get('time', '?')}] fingerprint={ev.get('fingerprint', '?')} "
                f"restored #{ev.get('restored_id')} (was #{ev.get('previous_id')}) "
                f"from {addr[0]}:{addr[1]}"
            )

    def _print_record(self, rec, colors, disconnected=False):
        sid = rec.get('session_id', '?')
        fp = rec.get('fingerprint', '?')
        name = rec.get('name')
        display = f"#{sid} ({name})" if name else f"#{sid}"
        sysinfo = rec.get('sysinfo') or {}
        identity = rec.get('identity') or {}
        host = sysinfo.get('hostname') or identity.get('hostname') or '?'
        user = sysinfo.get('username') or identity.get('username') or '?'
        addr = rec.get('addr', ['?', '?'])
        count = rec.get('connect_count', 1)
        status_color = colors['yellow'] if disconnected else colors['green']
        print(
            f"  {status_color}{display}{colors['end']} {user}@{host} "
            f"{addr[0]}:{addr[1]} fp={fp} connects={count}"
        )
        if rec.get('log_dir'):
            print(f"    {colors['blue']}Log: {rec['log_dir']}{colors['end']}")
