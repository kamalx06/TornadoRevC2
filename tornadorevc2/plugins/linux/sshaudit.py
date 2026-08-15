"""Linux SSH daemon enumeration for post-exploitation operators."""

from ..api import plugin, SessionContext
from ..shared.common import format_sshaudit_report
from ..shared.runner import run_collector_plugin
from ._helpers import build_linux_collector_command

PLUGIN_INFO = (
    "Read-only SSH server enumeration.\n"
    "Discovers all sshd configuration sources, resolves the effective configuration,\n"
    "and maps authentication surface, pivoting options, host keys, CA trust, and\n"
    "operator-relevant misconfigurations.\n"
    "Usage: run sshaudit <session_id>"
)


def _collector_source():
    return r'''
import glob, os, re, stat, subprocess

MAIN_CONFIG = '/etc/ssh/sshd_config'
SSH_DIR = '/etc/ssh'

def sh(cmd, timeout=10):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
    except Exception:
        return ''

def norm_key(key):
    return (key or '').strip().lower()

def norm_val(val):
    return (val or '').strip()

def file_info(path):
    info = {'path': path, 'exists': os.path.isfile(path)}
    if not info['exists']:
        return info
    try:
        st = os.stat(path)
        info['mode'] = oct(st.st_mode)[-4:]
        info['uid'] = st.st_uid
        info['gid'] = st.st_gid
        info['size'] = st.st_size
        info['readable'] = os.access(path, os.R_OK)
        info['writable'] = os.access(path, os.W_OK)
        info['world_writable'] = bool(st.st_mode & stat.S_IWOTH)
        info['group_writable'] = bool(st.st_mode & stat.S_IWGRP)
    except Exception:
        pass
    return info

def parse_config_lines(path):
    entries = []
    try:
        with open(path, 'r', errors='ignore') as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.split('#', 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                key = parts[0]
                val = parts[1] if len(parts) > 1 else ''
                entries.append({
                    'key': key,
                    'key_norm': norm_key(key),
                    'value': norm_val(val),
                    'file': path,
                    'line': lineno,
                    'raw': raw.rstrip('\n'),
                })
    except Exception:
        pass
    return entries

def expand_include(pattern, seen):
    paths = []
    if any(ch in pattern for ch in '*?[]'):
        for match in sorted(glob.glob(pattern)):
            if os.path.isfile(match) and match not in seen:
                paths.append(match)
    elif os.path.isfile(pattern) and pattern not in seen:
        paths.append(pattern)
    elif os.path.isdir(pattern):
        for match in sorted(glob.glob(os.path.join(pattern, '*.conf'))):
            if os.path.isfile(match) and match not in seen:
                paths.append(match)
    return paths

def discover_config_files(start=MAIN_CONFIG):
    ordered = []
    seen = set()
    queue = [start] if os.path.isfile(start) else []
    if not queue and os.path.isdir(os.path.join(SSH_DIR, 'sshd_config.d')):
        queue = sorted(glob.glob(os.path.join(SSH_DIR, 'sshd_config.d', '*.conf')))
    while queue:
        path = queue.pop(0)
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        ordered.append(path)
        for entry in parse_config_lines(path):
            if entry['key_norm'] == 'include':
                for inc in expand_include(entry['value'], seen):
                    if inc not in seen:
                        queue.append(inc)
    extra = sorted(glob.glob(os.path.join(SSH_DIR, 'sshd_config.d', '*.conf')))
    for path in extra:
        if path not in seen and os.path.isfile(path):
            seen.add(path)
            ordered.append(path)
    return ordered

def build_effective_config(files):
    effective = {}
    all_entries = []
    for path in files:
        for entry in parse_config_lines(path):
            all_entries.append(entry)
            kn = entry['key_norm']
            if kn == 'include':
                continue
            effective[kn] = {
                'value': entry['value'],
                'file': entry['file'],
                'line': entry['line'],
            }
    return effective, all_entries

def parse_sshd_test(config_path=MAIN_CONFIG):
    parsed = {}
    for cmd in (
        'sshd -T 2>/dev/null',
        'sshd -T -f %s 2>/dev/null' % config_path,
        '/usr/sbin/sshd -T 2>/dev/null',
        '/usr/sbin/sshd -T -f %s 2>/dev/null' % config_path,
    ):
        out = sh(cmd, 12).strip()
        if not out:
            continue
        for line in out.splitlines():
            if ' ' not in line:
                continue
            key, val = line.split(None, 1)
            parsed[norm_key(key)] = val.strip()
        if parsed:
            break
    return parsed

SSHD_DEFAULTS = {
    'permitrootlogin': 'prohibit-password',
    'passwordauthentication': 'yes',
    'permitemptypasswords': 'no',
    'pubkeyauthentication': 'yes',
    'hostbasedauthentication': 'no',
    'ignorerhosts': 'yes',
    'challengeresponseauthentication': 'no',
    'kbdinteractiveauthentication': 'yes',
    'usepam': 'yes',
    'maxauthtries': '6',
    'logingracetime': '120',
    'permituserenvironment': 'no',
    'permituserrc': 'yes',
    'permittty': 'yes',
    'allowtcpforwarding': 'yes',
    'allowagentforwarding': 'yes',
    'gatewayports': 'no',
    'permittunnel': 'no',
    'x11forwarding': 'no',
    'port': '22',
    'listenaddress': '0.0.0.0',
    'protocol': '2',
}

LEGACY_CIPHERS = {
    '3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'blowfish-cbc',
    'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
}
LEGACY_MACS = {'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96'}
LEGACY_KEX = {
    'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
    'diffie-hellman-group-exchange-sha1',
}
DEPRECATED_DIRECTIVES = {
    'challengeresponseauthentication', 'rhostsrsaauthentication', 'rsaauthentication',
    'useprivilegeseparation', 'keyregenerationinterval',
}

def truthy(val):
    return norm_val(val).lower() in ('yes', 'true', '1', 'on')

def falsy(val):
    return norm_val(val).lower() in ('no', 'false', '0', 'off')

def eff_val(key, effective, sshd_test):
    kn = norm_key(key)
    if kn in effective:
        return effective[kn]['value'], effective[kn], False
    if kn in sshd_test:
        return sshd_test[kn], {'file': 'sshd -T', 'line': None, 'value': sshd_test[kn]}, False
    if kn in SSHD_DEFAULTS:
        return SSHD_DEFAULTS[kn], {'file': '(default)', 'line': None, 'value': SSHD_DEFAULTS[kn]}, True
    return '', {'file': '(unset)', 'line': None, 'value': ''}, True

def src_meta(meta):
    return meta.get('file', ''), meta.get('line')

def add_note(notes, category, parameter, value, file_path, line, interest, note):
    notes.append({
        'category': category,
        'parameter': parameter,
        'value': value if value != '' else '(not set)',
        'file': file_path or '(unknown)',
        'line': line,
        'interest': interest,
        'note': note,
    })

def split_algo_list(val):
    return [x.strip() for x in (val or '').replace(',', ' ').split() if x.strip()]

def enumerate_authentication(notes, effective, sshd_test):
    checks = [
        ('PermitRootLogin', lambda v: v.lower() == 'yes', 'high',
         'Root SSH login permitted; direct privileged access if credentials obtained'),
        ('PermitRootLogin', lambda v: v.lower() in ('without-password', 'prohibit-password'), 'medium',
         'Root login allowed with key only; target root authorized_keys if accessible'),
        ('PasswordAuthentication', lambda v: truthy(v), 'high',
         'Password authentication enabled; credential spray and brute-force viable'),
        ('PermitEmptyPasswords', lambda v: truthy(v), 'high',
         'Empty passwords accepted; try blank-password logins'),
        ('PubkeyAuthentication', lambda v: falsy(v), 'medium',
         'Public key authentication disabled; password-only path likely required'),
        ('HostbasedAuthentication', lambda v: truthy(v), 'high',
         'Host-based authentication enabled; trust relationships may allow access without user creds'),
        ('IgnoreRhosts', lambda v: falsy(v), 'medium',
         'Rhosts/shosts honored; host-trust files may grant access'),
        ('KbdInteractiveAuthentication', lambda v: truthy(v), 'medium',
         'Keyboard-interactive auth enabled; may accept password prompts via PAM'),
        ('PermitUserEnvironment', lambda v: truthy(v), 'medium',
         'Users can set environment via ~/.ssh/environment or PermitUserEnvironment'),
        ('PermitUserRC', lambda v: truthy(v), 'low',
         '~/.ssh/rc executes on login; potential user-controlled code path'),
    ]
    seen = set()
    for param, pred, interest, note in checks:
        val, meta, _ = eff_val(param, effective, sshd_test)
        key = (param, val, note)
        if key in seen:
            continue
        if pred(val):
            seen.add(key)
            fp, ln = src_meta(meta)
            add_note(notes, 'authentication', param, val, fp, ln, interest, note)
    pam_val, pam_meta, _ = eff_val('UsePAM', effective, sshd_test)
    pass_val, _, _ = eff_val('PasswordAuthentication', effective, sshd_test)
    if truthy(pam_val) and truthy(pass_val):
        fp, ln = src_meta(pam_meta)
        add_note(notes, 'authentication', 'UsePAM', pam_val, fp, ln, 'medium',
                 'PAM backs password authentication; check /etc/pam.d/sshd for stack weaknesses')
    auth_methods, am_meta, _ = eff_val('AuthenticationMethods', effective, sshd_test)
    if auth_methods:
        fp, ln = src_meta(am_meta)
        add_note(notes, 'authentication', 'AuthenticationMethods', auth_methods, fp, ln, 'high',
                 'Explicit auth method chain defined; determines viable login techniques')
    try:
        tries = int(eff_val('MaxAuthTries', effective, sshd_test)[0] or '0')
        if tries > 4:
            val, meta, _ = eff_val('MaxAuthTries', effective, sshd_test)
            fp, ln = src_meta(meta)
            add_note(notes, 'authentication', 'MaxAuthTries', val, fp, ln, 'medium',
                     'Higher auth attempt limit; password spray has more tries per connection')
    except Exception:
        pass

def enumerate_access(notes, effective, sshd_test):
    restrictions = {}
    unset = []
    for name in ('AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups'):
        val, meta, _ = eff_val(name, effective, sshd_test)
        if val and val != '(not set)':
            fp, ln = src_meta(meta)
            restrictions[name] = val
            add_note(notes, 'access', name, val, fp, ln, 'high',
                     'Login restriction in effect; defines which accounts can authenticate')
        elif norm_key(name) not in effective and norm_key(name) not in sshd_test:
            unset.append(name)
    if len(unset) == 4:
        add_note(notes, 'access', 'Login restrictions', 'none', MAIN_CONFIG, None, 'medium',
                 'No AllowUsers/Groups or DenyUsers/Groups; all local accounts may attempt login')
    elif unset:
        add_note(notes, 'access', 'Login restrictions', 'partial', MAIN_CONFIG, None, 'medium',
                 'Unset: %s' % ', '.join(unset))
    checks = [
        ('AllowTcpForwarding', lambda v: truthy(v), 'high', 'TCP forwarding enabled; use for pivoting (-L/-R/-D)'),
        ('AllowAgentForwarding', lambda v: truthy(v), 'high', 'Agent forwarding enabled; hijack forwarded agent keys from sessions'),
        ('GatewayPorts', lambda v: truthy(v), 'high', 'GatewayPorts enabled; reverse tunnels can bind 0.0.0.0 for inbound pivot'),
        ('PermitTunnel', lambda v: truthy(v) and v.lower() != 'no', 'high', 'Tunnel interfaces permitted; additional tunnel-based pivot path'),
        ('X11Forwarding', lambda v: truthy(v), 'medium', 'X11 forwarding enabled; potential lateral movement via X11'),
        ('StreamLocalBindUnlink', lambda v: truthy(v), 'low', 'Unix socket forwarding can unlink existing socket paths'),
    ]
    for param, pred, interest, note in checks:
        val, meta, _ = eff_val(param, effective, sshd_test)
        if pred(val):
            fp, ln = src_meta(meta)
            add_note(notes, 'access', param, val, fp, ln, interest, note)
    for param in ('PermitOpen', 'PermitListen'):
        val, meta, _ = eff_val(param, effective, sshd_test)
        if val:
            fp, ln = src_meta(meta)
            note = 'Forwarding restriction in effect'
            if val.lower() in ('any', '*', 'all'):
                note = 'Unrestricted %s; broad forwarding surface' % param
            add_note(notes, 'access', param, val, fp, ln, 'medium', note)

def enumerate_crypto(notes, effective, sshd_test, host_keys):
    algo_checks = [
        ('Ciphers', LEGACY_CIPHERS, 'Legacy ciphers accepted; downgrade tooling may apply'),
        ('MACs', LEGACY_MACS, 'Legacy MACs accepted; weak integrity algorithms available'),
        ('KexAlgorithms', LEGACY_KEX, 'Legacy key exchange accepted; weak DH groups available'),
        ('HostKeyAlgorithms', {'ssh-dss', 'ssh-rsa'}, 'Legacy host key algorithms advertised'),
        ('PubkeyAcceptedAlgorithms', {'ssh-dss'}, 'Legacy user key algorithms accepted'),
        ('CASignatureAlgorithms', {'ssh-rsa', 'ssh-dss'}, 'Legacy CA signature algorithms accepted'),
    ]
    for param, weak_set, note_base in algo_checks:
        val, meta, _ = eff_val(param, effective, sshd_test)
        algos = split_algo_list(val)
        weak_hits = [a for a in algos if a in weak_set or 'sha1' in a.lower()]
        if weak_hits:
            fp, ln = src_meta(meta)
            add_note(notes, 'cryptography', param, val, fp, ln, 'medium',
                     note_base + ': ' + ', '.join(weak_hits))
        elif val:
            fp, ln = src_meta(meta)
            add_note(notes, 'cryptography', param, val, fp, ln, 'low',
                     'Algorithm policy explicitly configured')
    for hk in host_keys:
        path = hk.get('path', '')
        bits = hk.get('bits')
        if 'dsa' in os.path.basename(path).lower() or hk.get('type') == 'dsa':
            add_note(notes, 'cryptography', 'HostKey', path, path, None, 'medium',
                     'DSA host key present; weak host identity material')
        if bits and bits < 2048:
            add_note(notes, 'cryptography', 'HostKey', '%s (%s bits)' % (path, bits), path, None, 'medium',
                     'Short RSA host key; easier to factor for host impersonation research')

def enumerate_protocol(notes, effective, sshd_test, version):
    proto, meta, _ = eff_val('Protocol', effective, sshd_test)
    if proto and '1' in proto.replace(' ', ''):
        fp, ln = src_meta(meta)
        add_note(notes, 'protocol', 'Protocol', proto, fp, ln, 'high',
                 'SSH protocol v1 enabled; legacy protocol exploitation research applicable')

def enumerate_files(notes, config_files, host_key_paths):
    for path in config_files:
        info = file_info(path)
        if not info.get('exists'):
            continue
        if info.get('writable'):
            add_note(notes, 'files', 'Configuration file writable', info.get('mode', ''), path, None, 'high',
                     'Writable sshd config; persistence via config tampering or backdoor directives')
        elif info.get('readable'):
            add_note(notes, 'files', 'Configuration file', info.get('mode', ''), path, None, 'low',
                     'Readable sshd configuration source')
    for path in host_key_paths:
        info = file_info(path)
        if not info.get('exists'):
            add_note(notes, 'files', 'HostKey', '(missing)', path, None, 'low',
                     'Referenced host key path does not exist')
            continue
        if 'pub' in os.path.basename(path):
            if info.get('readable'):
                add_note(notes, 'files', 'Host public key', info.get('mode', ''), path, None, 'low',
                         'Host public key readable; fingerprint for known_hosts planting')
            continue
        mode = info.get('mode', '')
        try:
            perm = int(mode, 8) if mode else 0
        except Exception:
            perm = 0
        if perm & 0o077:
            add_note(notes, 'files', 'Host private key permissions', mode, path, None, 'high',
                     'Host private key readable by non-root; host impersonation if readable')
        elif info.get('readable'):
            add_note(notes, 'files', 'Host private key', mode, path, None, 'high',
                     'Host private key readable; extract for host impersonation on other systems')

def enumerate_overrides(notes, all_entries):
    overrides = []
    seen = {}
    for entry in all_entries:
        kn = entry['key_norm']
        if kn in ('include', ''):
            continue
        prev = seen.get(kn)
        if prev:
            overrides.append({
                'parameter': entry['key'],
                'previous_value': prev['value'],
                'previous_file': prev['file'],
                'previous_line': prev['line'],
                'current_value': entry['value'],
                'current_file': entry['file'],
                'current_line': entry['line'],
            })
            if prev['value'].lower() != entry['value'].lower():
                add_note(notes, 'configuration', entry['key'], entry['value'], entry['file'], entry['line'], 'medium',
                         'Overrides %r from %s:%s; later file wins for effective config' % (prev['value'], prev['file'], prev['line']))
        seen[kn] = entry
    for entry in all_entries:
        if entry['key_norm'] in DEPRECATED_DIRECTIVES:
            add_note(notes, 'configuration', entry['key'], entry['value'], entry['file'], entry['line'], 'low',
                     'Deprecated directive present; may indicate old config template')
    return overrides

def collect_host_keys(effective, sshd_test, all_entries):
    keys = []
    paths = []
    for entry in all_entries:
        if entry['key_norm'] == 'hostkey' and entry['value'] and entry['value'] not in paths:
            paths.append(entry['value'])
    val, _, _ = eff_val('HostKey', effective, sshd_test)
    if val and val not in paths:
        paths.append(val)
    for path in sorted(glob.glob(os.path.join(SSH_DIR, 'ssh_host_*_key*'))):
        if path not in paths:
            paths.append(path)
    for path in paths:
        info = file_info(path)
        rec = {'path': path, 'exists': info.get('exists', False), 'mode': info.get('mode', ''), 'readable': info.get('readable', False)}
        base = os.path.basename(path)
        if 'dsa' in base:
            rec['type'] = 'dsa'
        elif 'rsa' in base:
            rec['type'] = 'rsa'
        elif 'ed25519' in base:
            rec['type'] = 'ed25519'
        elif 'ecdsa' in base:
            rec['type'] = 'ecdsa'
        if 'pub' not in base:
            out = sh('ssh-keygen -l -f %s 2>/dev/null' % path, 6).strip()
            if out:
                parts = out.split()
                if parts and parts[0].isdigit():
                    rec['bits'] = int(parts[0])
                rec['fingerprint'] = parts[1] if len(parts) > 1 else ''
        keys.append(rec)
    return keys, [p for p in paths if 'pub' not in os.path.basename(p)]

def collect_authorized_keys():
    hits = []
    patterns = [
        '/root/.ssh/authorized_keys',
        '/home/*/.ssh/authorized_keys',
        os.path.expanduser('~/.ssh/authorized_keys'),
    ]
    for pattern in patterns:
        for fp in glob.glob(pattern):
            if os.path.isfile(fp):
                info = file_info(fp)
                try:
                    with open(fp, 'r', errors='ignore') as fh:
                        lines = [l.strip() for l in fh.readlines() if l.strip() and not l.strip().startswith('#')]
                except Exception:
                    lines = []
                hits.append({
                    'path': fp,
                    'mode': info.get('mode', ''),
                    'keys': len(lines),
                    'writable': info.get('writable', False),
                })
    return hits[:40]

def enumerate_ca(notes, effective, sshd_test):
    ca_result = {
        'status': 'not configured',
        'trusted_user_ca_keys': [],
        'authorized_principals_file': None,
        'authorized_principals_command': None,
        'ca_signature_algorithms': None,
        'host_certificate_directives': [],
    }
    tuca, tmeta, _ = eff_val('TrustedUserCAKeys', effective, sshd_test)
    principals_file, pf_meta, _ = eff_val('AuthorizedPrincipalsFile', effective, sshd_test)
    principals_cmd, pc_meta, _ = eff_val('AuthorizedPrincipalsCommand', effective, sshd_test)
    ca_sigs, _, _ = eff_val('CASignatureAlgorithms', effective, sshd_test)
    ca_result['authorized_principals_file'] = principals_file or None
    ca_result['authorized_principals_command'] = principals_cmd or None
    ca_result['ca_signature_algorithms'] = ca_sigs or None
    configured = False
    broken = False
    if tuca:
        configured = True
        for path in split_algo_list(tuca):
            info = file_info(path)
            entry = {'path': path, 'exists': info.get('exists', False), 'mode': info.get('mode', ''), 'readable': info.get('readable', False)}
            if info.get('exists') and info.get('readable'):
                try:
                    with open(path, 'r', errors='ignore') as fh:
                        entry['preview'] = fh.read(120).strip()
                    entry['valid'] = True
                    fp, ln = src_meta(tmeta)
                    add_note(notes, 'certificate_authority', 'TrustedUserCAKeys', path, fp, ln, 'high',
                             'CA public key trusted; forge user certs if CA private key obtained')
                except Exception:
                    entry['valid'] = False
                    broken = True
            else:
                broken = True
                fp, ln = src_meta(tmeta)
                add_note(notes, 'certificate_authority', 'TrustedUserCAKeys', path, fp, ln, 'medium',
                         'CA key path configured but file missing or unreadable')
            ca_result['trusted_user_ca_keys'].append(entry)
    if principals_file:
        configured = True
        fp, ln = src_meta(pf_meta)
        add_note(notes, 'certificate_authority', 'AuthorizedPrincipalsFile', principals_file, fp, ln, 'high',
                 'Principals file defines valid cert identities; enumerate for allowed usernames/roles')
    if principals_cmd:
        configured = True
        fp, ln = src_meta(pc_meta)
        add_note(notes, 'certificate_authority', 'AuthorizedPrincipalsCommand', principals_cmd, fp, ln, 'high',
                 'Principals resolved dynamically; inspect command for cert trust logic')
    for key, meta in effective.items():
        if 'hostcertificate' in key:
            ca_result['host_certificate_directives'].append(meta)
    if configured and broken:
        ca_result['status'] = 'configured but broken'
    elif configured:
        ca_result['status'] = 'active'
    return ca_result

def build_auth_surface(effective, sshd_test):
    root_val, _, _ = eff_val('PermitRootLogin', effective, sshd_test)
    pass_val, _, _ = eff_val('PasswordAuthentication', effective, sshd_test)
    pubkey_val, _, _ = eff_val('PubkeyAuthentication', effective, sshd_test)
    empty_val, _, _ = eff_val('PermitEmptyPasswords', effective, sshd_test)
    return {
        'root_login': root_val,
        'password_auth': truthy(pass_val),
        'pubkey_auth': not falsy(pubkey_val),
        'empty_passwords': truthy(empty_val),
    }

def build_pivot_surface(effective, sshd_test):
    return {
        'tcp_forwarding': truthy(eff_val('AllowTcpForwarding', effective, sshd_test)[0]),
        'agent_forwarding': truthy(eff_val('AllowAgentForwarding', effective, sshd_test)[0]),
        'gateway_ports': truthy(eff_val('GatewayPorts', effective, sshd_test)[0]),
        'tunnel': truthy(eff_val('PermitTunnel', effective, sshd_test)[0]) and eff_val('PermitTunnel', effective, sshd_test)[0].lower() != 'no',
    }

def parse_openssh_version(raw):
    m = re.search(r'OpenSSH[_\s]([0-9]+\.[0-9]+(?:p[0-9]+)?)', raw or '', re.I)
    return m.group(1) if m else (raw.strip()[:80] if raw else 'unknown')

# --- main collection ---
config_files = discover_config_files(MAIN_CONFIG)
effective, all_entries = build_effective_config(config_files)
sshd_test = parse_sshd_test(MAIN_CONFIG)
host_keys, host_key_paths = collect_host_keys(effective, sshd_test, all_entries)
authorized_keys = collect_authorized_keys()
sshd_version_raw = sh('sshd -V 2>&1; /usr/sbin/sshd -V 2>&1', 8).strip().splitlines()
sshd_version = parse_openssh_version('\n'.join(sshd_version_raw))
sshd_active = sh('systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null').strip()
listen_port, _, _ = eff_val('Port', effective, sshd_test)
listen_addr, _, _ = eff_val('ListenAddress', effective, sshd_test)

notes = []
enumerate_authentication(notes, effective, sshd_test)
enumerate_access(notes, effective, sshd_test)
enumerate_crypto(notes, effective, sshd_test, host_keys)
enumerate_protocol(notes, effective, sshd_test, sshd_version)
enumerate_files(notes, config_files, host_key_paths)
overrides = enumerate_overrides(notes, all_entries)
ca_info = enumerate_ca(notes, effective, sshd_test)

auth_surface = build_auth_surface(effective, sshd_test)
pivot_surface = build_pivot_surface(effective, sshd_test)
interest_counts = {'high': 0, 'medium': 0, 'low': 0}
for n in notes:
    interest_counts[n.get('interest', 'low')] = interest_counts.get(n.get('interest', 'low'), 0) + 1

effective_export = {}
for kn, meta in effective.items():
    effective_export[kn] = {
        'value': meta['value'],
        'file': meta['file'],
        'line': meta['line'],
    }

by_category = {
    'authentication': [],
    'access': [],
    'cryptography': [],
    'files': [],
    'configuration': [],
    'protocol': [],
    'certificate_authority': [],
}
for n in notes:
    by_category.setdefault(n.get('category', 'configuration'), []).append(n)

result = {
    'summary': {
        'sshd_active': sshd_active or 'unknown',
        'sshd_version': sshd_version,
        'listen': '%s:%s' % (listen_addr or '0.0.0.0', listen_port or '22'),
        'config_files': len(config_files),
        'notes_total': len(notes),
        'high_interest': interest_counts.get('high', 0),
        'medium_interest': interest_counts.get('medium', 0),
        'low_interest': interest_counts.get('low', 0),
        'auth_surface': auth_surface,
        'pivot_surface': pivot_surface,
        'ca_status': ca_info.get('status'),
        'authorized_keys_files': len(authorized_keys),
        'host_keys': len(host_keys),
    },
    'ssh_version': {
        'version': sshd_version,
        'raw': '\n'.join(sshd_version_raw[:3]),
    },
    'configuration_files': [{'path': p, **{k: v for k, v in file_info(p).items() if k != 'path'}} for p in config_files],
    'effective_configuration': effective_export,
    'sshd_test_configuration': sshd_test,
    'authentication_notes': by_category.get('authentication', []),
    'access_notes': by_category.get('access', []),
    'cryptography_notes': by_category.get('cryptography', []),
    'file_notes': by_category.get('files', []),
    'configuration_notes': by_category.get('configuration', []),
    'protocol_notes': by_category.get('protocol', []),
    'certificate_authority': ca_info,
    'certificate_authority_notes': by_category.get('certificate_authority', []),
    'configuration_overrides': overrides[:60],
    'host_keys': host_keys[:30],
    'authorized_keys': authorized_keys,
    'all_notes': notes[:200],
}
_emit(result)
'''


def build_command():
    return build_linux_collector_command(_collector_source())


@plugin.command(
    name='sshaudit',
    platforms=['linux', 'unix'],
    description='Enumerate SSH server configuration, auth surface, pivoting options, keys, and CA trust',
)
def run(session: SessionContext, args):
    return run_collector_plugin(
        session,
        'sshaudit',
        build_command,
        None,
        format_sshaudit_report,
        timeout=45.0,
    )
