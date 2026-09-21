import base64
import gzip
import hashlib
import re

from ..api import plugin, SessionContext

_USAGE = """enablepriv — enable or disable Windows privileges (current token).

Usage:
  run enablepriv --list                 Show privileges present in the token
  run enablepriv --list-all             Show the full catalogue + token status
  run enablepriv --vuln                 Classify held privileges by security risk
  run enablepriv <privilege>            Enable a privilege
  run enablepriv <privilege> --disable  Disable a privilege
  run enablepriv --all                  Enable every privilege in the token
  run enablepriv --all --disable        Disable every privilege in the token
  run enablepriv --help

Privilege name forms (all equivalent, case-insensitive):
  SeDebugPrivilege
  DebugPrivilege
  debug

Options:
  --list       Enumerate the privileges the current process token holds.
  --list-all   Enumerate the standard Windows privilege catalogue and mark
               each entry as Enabled / Disabled / Removed / Not held.
  --vuln       Show held privileges grouped by security significance
               (CRITICAL / HIGH / MEDIUM / LOW) with a short rationale.
  --all        Apply to every privilege already present in the token.
  --disable    Disable instead of enable.

Notes:
  - The change is applied to the current process token only. It is reverted
    when the shell process exits and does not affect other sessions.
  - Privileges absent from the token cannot be added here; a fresh logon
    with the right rights is required for those.
  - Privileges explicitly Removed from the token cannot be re-enabled.
"""

# --------------------------------------------------------------------------
# C# helper — P/Invoke to AdjustTokenPrivileges / GetTokenInformation
# --------------------------------------------------------------------------

_CS_SOURCE = r'''
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class PrivToggler {
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY             = 0x0008;
    const uint SE_PRIVILEGE_ENABLED    = 0x00000002;
    const uint SE_PRIVILEGE_REMOVED    = 0x00000004;

    const int TOKEN_INFORMATION_CLASS_PRIVILEGES = 3;
    const int ERROR_NOT_ALL_ASSIGNED = 1300;

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeName(string sys, ref LUID luid,
                                           StringBuilder name, ref int nameLen);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        int bufLen, IntPtr prev, IntPtr retLen);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(
        IntPtr token, int cls, IntPtr info, int infoLen, out int retLen);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    static string Normalize(string name) {
        if (string.IsNullOrEmpty(name)) return name;
        name = name.Trim();
        if (!name.StartsWith("Se", StringComparison.OrdinalIgnoreCase))
            name = "Se" + name;
        if (!name.EndsWith("Privilege", StringComparison.OrdinalIgnoreCase))
            name = name + "Privilege";
        return name;
    }

    static string StateOf(uint attrs) {
        if ((attrs & SE_PRIVILEGE_REMOVED) != 0) return "REMOVED";
        if ((attrs & SE_PRIVILEGE_ENABLED) != 0) return "ENABLED";
        return "DISABLED";
    }

    public static string SetPrivilege(string name, bool enable) {
        name = Normalize(name);
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            return "ERROR: OpenProcessToken failed (" + Marshal.GetLastWin32Error() + ")";
        try {
            LUID luid;
            if (!LookupPrivilegeValue(null, name, out luid))
                return "ERROR: unknown privilege '" + name + "' (" +
                       Marshal.GetLastWin32Error() + ")";

            var tp = new TOKEN_PRIVILEGES {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[1]
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

            if (!AdjustTokenPrivileges(token, false, ref tp,
                    Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
                return "ERROR: AdjustTokenPrivileges failed (" +
                       Marshal.GetLastWin32Error() + ")";

            if (Marshal.GetLastWin32Error() == ERROR_NOT_ALL_ASSIGNED)
                return "ERROR: " + name + " is not held by this token";
            return "OK: " + name + " " + (enable ? "enabled" : "disabled");
        } finally { CloseHandle(token); }
    }

    // Returns one line per privilege in the token:  "<name>|<STATE>"
    public static string ListTokenPrivileges() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
            return "";
        try {
            int needed = 0;
            GetTokenInformation(token, TOKEN_INFORMATION_CLASS_PRIVILEGES,
                IntPtr.Zero, 0, out needed);
            if (needed <= 0) return "";

            IntPtr buf = Marshal.AllocHGlobal(needed);
            try {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS_PRIVILEGES,
                        buf, needed, out needed))
                    return "";

                int count = Marshal.ReadInt32(buf, 0);
                var sb = new StringBuilder();
                for (int i = 0; i < count; i++) {
                    int off = 4 + i * 12;
                    uint low = unchecked((uint)Marshal.ReadInt32(buf, off));
                    int high = Marshal.ReadInt32(buf, off + 4);
                    uint attrs = unchecked((uint)Marshal.ReadInt32(buf, off + 8));

                    var luid = new LUID { LowPart = low, HighPart = high };
                    var nameBuf = new StringBuilder(256);
                    int nameLen = nameBuf.Capacity;
                    if (!LookupPrivilegeName(null, ref luid, nameBuf, ref nameLen))
                        continue;
                    sb.Append(nameBuf.ToString()).Append('|').Append(StateOf(attrs)).Append('\n');
                }
                return sb.ToString();
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(token); }
    }

    // Apply enable/disable to every privilege the token currently holds.
    // Returns "<name>|<result>" per line.
    public static string SetAllPrivileges(bool enable) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
            return "ERROR: OpenProcessToken failed";
        try {
            int needed = 0;
            GetTokenInformation(token, TOKEN_INFORMATION_CLASS_PRIVILEGES,
                IntPtr.Zero, 0, out needed);
            if (needed <= 0) return "ERROR: could not size token privileges";

            IntPtr buf = Marshal.AllocHGlobal(needed);
            try {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS_PRIVILEGES,
                        buf, needed, out needed))
                    return "ERROR: could not read token privileges";

                int count = Marshal.ReadInt32(buf, 0);
                var sb = new StringBuilder();
                for (int i = 0; i < count; i++) {
                    int off = 4 + i * 12;
                    uint low = unchecked((uint)Marshal.ReadInt32(buf, off));
                    int high = Marshal.ReadInt32(buf, off + 4);
                    var luid = new LUID { LowPart = low, HighPart = high };
                    var nameBuf = new StringBuilder(256);
                    int nameLen = nameBuf.Capacity;
                    if (!LookupPrivilegeName(null, ref luid, nameBuf, ref nameLen))
                        continue;
                    string name = nameBuf.ToString();
                    sb.Append(name).Append('|').Append(SetPrivilege(name, enable)).Append('\n');
                }
                return sb.ToString();
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(token); }
    }
}
'''

_CS_HASH    = hashlib.sha256(_CS_SOURCE.encode('utf-8')).hexdigest()[:8]
_CLASS_NAME = f'PrivToggler_{_CS_HASH}'
_TAGGED_CS  = _CS_SOURCE.replace('class PrivToggler', f'class {_CLASS_NAME}', 1)
_CS_GZ_B64  = base64.b64encode(
    gzip.compress(_TAGGED_CS.encode('utf-8'), compresslevel=9)
).decode('ascii')

_LIST_MARK = '__ENABLEPRIV_LIST__:'
_OK_MARK   = '__ENABLEPRIV_OK__:'
_ERR_MARK  = '__ENABLEPRIV_ERR__:'
_END_MARK  = '__ENABLEPRIV_END__'

_VALID_NAME = re.compile(r'^[A-Za-z0-9_]+$')

_CATALOGUE = {
    "SeAssignPrimaryTokenPrivilege":                "Replace a process-level token",
    "SeAuditPrivilege":                             "Generate security audits",
    "SeBackupPrivilege":                            "Back up files and directories",
    "SeChangeNotifyPrivilege":                      "Bypass traverse checking",
    "SeCreateGlobalPrivilege":                      "Create global objects",
    "SeCreatePagefilePrivilege":                    "Create a pagefile",
    "SeCreatePermanentPrivilege":                   "Create permanent shared objects",
    "SeCreateSymbolicLinkPrivilege":                "Create symbolic links",
    "SeCreateTokenPrivilege":                       "Create a token object",
    "SeDebugPrivilege":                             "Debug programs",
    "SeDelegateSessionUserImpersonatePrivilege":    "Obtain an impersonation token for another user in the same session",
    "SeEnableDelegationPrivilege":                  "Enable computer and user accounts to be trusted for delegation",
    "SeImpersonatePrivilege":                       "Impersonate a client after authentication",
    "SeIncreaseBasePriorityPrivilege":              "Increase scheduling priority",
    "SeIncreaseQuotaPrivilege":                     "Adjust memory quotas for a process",
    "SeIncreaseWorkingSetPrivilege":                "Increase a process working set",
    "SeLoadDriverPrivilege":                        "Load and unload device drivers",
    "SeLockMemoryPrivilege":                        "Lock pages in memory",
    "SeMachineAccountPrivilege":                    "Add workstations to domain",
    "SeManageVolumePrivilege":                      "Perform volume maintenance tasks",
    "SeProfileSingleProcessPrivilege":              "Profile single process",
    "SeRelabelPrivilege":                           "Modify an object label",
    "SeRemoteShutdownPrivilege":                    "Force shutdown from a remote system",
    "SeRestorePrivilege":                           "Restore files and directories",
    "SeSecurityPrivilege":                          "Manage auditing and security log",
    "SeShutdownPrivilege":                          "Shut down the system",
    "SeSyncAgentPrivilege":                         "Synchronize directory service data",
    "SeSystemEnvironmentPrivilege":                 "Modify firmware environment values",
    "SeSystemProfilePrivilege":                     "Profile system performance",
    "SeSystemtimePrivilege":                        "Change the system time",
    "SeTakeOwnershipPrivilege":                     "Take ownership of files or other objects",
    "SeTcbPrivilege":                               "Act as part of the operating system",
    "SeTimeZonePrivilege":                          "Change the time zone",
    "SeTrustedCredManAccessPrivilege":              "Access Credential Manager as a trusted caller",
    "SeUndockPrivilege":                            "Remove computer from docking station",
}

_VULN_TIERS = {
    "CRITICAL": {
        "SeImpersonatePrivilege": (
            "Impersonate a client after authentication — commonly present "
            "on service accounts and a well-known escalation vector."
        ),
        "SeAssignPrimaryTokenPrivilege": (
            "Replace a process-level token — same class of exposure as "
            "SeImpersonatePrivilege, weaker by default."
        ),
        "SeDebugPrivilege": (
            "Open any process with full access, including LSASS and other "
            "users' sessions; grants process memory read/write across the "
            "system."
        ),
        "SeTcbPrivilege": (
            "Act as part of the operating system — trusted-computer-base "
            "authority; effectively full trust on the host."
        ),
        "SeCreateTokenPrivilege": (
            "Create arbitrary token objects; the token can be forged with "
            "arbitrary group and privilege membership."
        ),
        "SeLoadDriverPrivilege": (
            "Load and unload kernel drivers; loads code at ring 0."
        ),
    },
    "HIGH": {
        "SeBackupPrivilege": (
            "Read any file regardless of ACL, including SAM, SECURITY, and "
            "SYSTEM hives."
        ),
        "SeRestorePrivilege": (
            "Write any file regardless of ACL; the write counterpart to "
            "SeBackupPrivilege."
        ),
        "SeTakeOwnershipPrivilege": (
            "Take ownership of any securable object, then change its ACL."
        ),
        "SeManageVolumePrivilege": (
            "Direct volume access — read/write raw disk, including files "
            "locked by the OS."
        ),
        "SeRelabelPrivilege": (
            "Modify the integrity label of any object — bypasses mandatory "
            "integrity controls."
        ),
        "SeSecurityPrivilege": (
            "Manage the audit log and security event sources; can erase "
            "the operator's own footprint."
        ),
        "SeCreatePermanentPrivilege": (
            "Create permanent shared objects in the object namespace."
        ),
        "SeEnableDelegationPrivilege": (
            "Configure Kerberos delegation on machine and user accounts — "
            "domain-wide impersonation setup."
        ),
    },
    "MEDIUM": {
        "SeCreateSymbolicLinkPrivilege": (
            "Create symbolic links — relevant to symlink-based file "
            "redirection in privileged contexts."
        ),
        "SeIncreaseQuotaPrivilege": (
            "Adjust memory quotas for a process — can be used to tamper "
            "with other processes' resource limits."
        ),
        "SeSystemEnvironmentPrivilege": (
            "Modify firmware environment variables — affects subsequent "
            "boot configuration."
        ),
        "SeTrustedCredManAccessPrivilege": (
            "Read the Credential Manager store as a trusted caller."
        ),
        "SeMachineAccountPrivilege": (
            "Add computers to the domain — relevant in AD environments."
        ),
        "SeSyncAgentPrivilege": (
            "Synchronize directory service data (domain controllers only)."
        ),
    },
    "LOW": {
        "SeShutdownPrivilege":           "Shut down the local system.",
        "SeRemoteShutdownPrivilege":     "Force shutdown from a remote system.",
        "SeUndockPrivilege":             "Remove the computer from a docking station.",
        "SeTimeZonePrivilege":           "Change the system time zone.",
        "SeSystemtimePrivilege":         "Change the system clock.",
        "SeChangeNotifyPrivilege":       "Bypass traverse checking — held by nearly all tokens.",
        "SeIncreaseWorkingSetPrivilege": "Increase the process working set.",
        "SeProfileSingleProcessPrivilege": "Profile a single process.",
        "SeSystemProfilePrivilege":      "Profile system performance.",
        "SeIncreaseBasePriorityPrivilege": "Raise a thread's scheduling priority.",
        "SeLockMemoryPrivilege":         "Lock pages in physical memory.",
        "SeCreateGlobalPrivilege":       "Create objects in the global namespace.",
        "SeDelegateSessionUserImpersonatePrivilege": (
            "Obtain an impersonation token for another user in the same session."
        ),
    },
}


# --------------------------------------------------------------------------
# PowerShell helpers
# --------------------------------------------------------------------------

def _bootstrap_ps():
    return (
        f"if (-not ('{_CLASS_NAME}' -as [type])) {{\n"
        f"  $b = '{_CS_GZ_B64}'\n"
        "  $raw = [Convert]::FromBase64String($b)\n"
        "  $ms  = New-Object IO.MemoryStream(,$raw)\n"
        "  $gz  = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)\n"
        "  $sr  = New-Object IO.StreamReader($gz)\n"
        "  $src = $sr.ReadToEnd()\n"
        "  $sr.Dispose(); $gz.Dispose(); $ms.Dispose()\n"
        "  Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop\n"
        "}\n"
    )


def _list_ps():
    return _bootstrap_ps() + (
        "try {\n"
        f"  $lines = [{_CLASS_NAME}]::ListTokenPrivileges()\n"
        "  foreach ($l in $lines -split \"`n\") {\n"
        "    if ($l) { Write-Output ('" + _LIST_MARK + "' + $l) }\n"
        "  }\n"
        "} catch {\n"
        f"  Write-Output ('{_ERR_MARK}ERROR: ' + $_.Exception.Message)\n"
        "}\n"
        f"Write-Output '{_END_MARK}'\n"
    )


def _set_ps(privilege, enable):
    safe = privilege.replace("'", "''")
    flag = '$true' if enable else '$false'
    return _bootstrap_ps() + (
        "try {\n"
        f"  $r = [{_CLASS_NAME}]::SetPrivilege('{safe}', {flag})\n"
        f"  if ($r -like 'OK:*') {{ Write-Output ('{_OK_MARK}'  + $r) }}\n"
        f"  else                {{ Write-Output ('{_ERR_MARK}' + $r) }}\n"
        "} catch {\n"
        f"  Write-Output ('{_ERR_MARK}ERROR: ' + $_.Exception.Message)\n"
        "}\n"
        f"Write-Output '{_END_MARK}'\n"
    )


def _set_all_ps(enable):
    flag = '$true' if enable else '$false'
    return _bootstrap_ps() + (
        "try {\n"
        f"  $lines = [{_CLASS_NAME}]::SetAllPrivileges({flag})\n"
        "  foreach ($l in $lines -split \"`n\") {\n"
        "    if (-not $l) { continue }\n"
        "    $i = $l.IndexOf('|')\n"
        "    if ($i -lt 0) { continue }\n"
        "    $name = $l.Substring(0, $i)\n"
        "    $res  = $l.Substring($i + 1)\n"
        "    if ($res -like 'OK:*') { Write-Output ('" + _OK_MARK + "'  + $name + ' -> ' + $res) }\n"
        "    else                   { Write-Output ('" + _ERR_MARK + "' + $name + ' -> ' + $res) }\n"
        "  }\n"
        "} catch {\n"
        f"  Write-Output ('{_ERR_MARK}ERROR: ' + $_.Exception.Message)\n"
        "}\n"
        f"Write-Output '{_END_MARK}'\n"
    )


def _run_ps(session, ps, timeout=45.0, until_marker=_END_MARK):
    handler = session._handler
    sock    = session._client_sock
    try:
        handler._flush_shell(sock, timeout=0.5)
    except Exception:
        pass
    try:
        if not handler._send_win_ps(sock, ps):
            return ''
    except Exception:
        return ''
    try:
        return handler.recv_output(
            sock, timeout=timeout, until_marker=until_marker,
        ) or ''
    except Exception:
        return ''


def _lines_after(text, marker):
    out = []
    for raw in text.splitlines():
        line = raw.rstrip('\r')
        idx = line.find(marker)
        if idx < 0:
            continue
        payload = line[idx + len(marker):]
        if _END_MARK in payload:
            payload = payload.split(_END_MARK, 1)[0]
        if payload:
            out.append(payload)
    return out


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def _parse_args(args):
    if args is None:
        return 'help', None
    if not isinstance(args, (list, tuple)):
        try:
            args = list(args)
        except TypeError:
            return None, 'invalid arguments'

    if not args:
        return 'help', None
    if args[0] in ('-h', '--help', 'help'):
        return 'help', None

    if '--list-all' in args or 'list-all' in args:
        return 'list-all', None
    if '--vuln' in args or args[0] == 'vuln':
        return 'vuln', None
    if '--list' in args or args[0] == 'list':
        return 'list', None

    disable = '--disable' in args or '-d' in args
    enable_all = '--all' in args

    name = None
    for a in args:
        if a.startswith('-'):
            if a in ('--disable', '-d', '--all'):
                continue
            return None, f'unknown option: {a!r}'
        if name is not None:
            return None, f'unexpected extra argument: {a!r}'
        name = a

    if enable_all:
        if name is not None:
            return None, '--all takes no privilege name'
        return ('disable-all' if disable else 'enable-all'), None

    if not name:
        return None, 'missing privilege name'
    if not _VALID_NAME.match(name):
        return None, f'invalid privilege name: {name!r}'

    return ('disable' if disable else 'enable'), {'name': name}


# --------------------------------------------------------------------------
# Plugin entry point
# --------------------------------------------------------------------------

@plugin.command(
    name='enablepriv',
    platforms=['windows'],
    description='Enable or disable any Windows privilege on the current token',
)
def run(session: SessionContext, args):
    colors = session.colors

    action, opts = _parse_args(args)
    if action == 'help':
        session.print(_USAGE)
        return 0
    if action is None:
        session.print(f"{colors['red']}{opts}{colors['end']}")
        session.print(_USAGE)
        return 1

    # ---- listing --------------------------------------------------------

    if action in ('list', 'list-all'):
        out = _run_ps(session, _list_ps(), timeout=30.0)
        if not out:
            session.print(
                f"{colors['red']}Failed to list privileges "
                f"(no output from target){colors['end']}"
            )
            session.log_plugin_result('enablepriv', '', 'list: no output')
            return 1

        err = _lines_after(out, _ERR_MARK)
        if err:
            session.print(f"{colors['red']}{err[0]}{colors['end']}")
            session.log_plugin_result('enablepriv', '', f'list: {err[0]}')
            return 1

        entries = {}
        for line in _lines_after(out, _LIST_MARK):
            if '|' not in line:
                continue
            name, _, state = line.partition('|')
            entries[name.strip()] = state.strip()

        if action == 'list':
            if not entries:
                session.print(
                    f"{colors['yellow']}Token reports no privileges"
                    f"{colors['end']}"
                )
                return 0

            order = {'ENABLED': 0, 'DISABLED': 1, 'REMOVED': 2}
            rows = sorted(
                entries.items(),
                key=lambda kv: (order.get(kv[1], 3), kv[0]),
            )

            session.print(
                f"{colors['cyan']}Privileges in current token "
                f"({len(rows)}):{colors['end']}"
            )
            for name, state in rows:
                desc = _CATALOGUE.get(name, '')
                session.print(
                    f"  {_render_state(state, colors)}  "
                    f"{name:<45} {desc}"
                )
            session.print(
                f"  {colors['cyan']}[+] enabled   [ ] disabled   "
                f"[-] removed{colors['end']}"
            )
            session.log_plugin_result(
                'enablepriv',
                '\n'.join(f'{n}|{s}' for n, s in rows),
                'list',
            )
            return 0

        held = []
        not_held = []
        for name in sorted(_CATALOGUE):
            state = entries.get(name)
            row = (name, state or 'NOT_HELD', _CATALOGUE[name])
            (held if state else not_held).append(row)

        extras = [
            (name, state, '(not in standard catalogue)')
            for name, state in sorted(entries.items())
            if name not in _CATALOGUE
        ]

        present = len(held)
        total_catalogue = len(_CATALOGUE)
        session.print(
            f"{colors['cyan']}Windows privilege catalogue "
            f"({total_catalogue} entries, {present} held by this token)"
            f"{colors['end']}"
        )

        if held:
            session.print(f"{colors['green']}Held by token:{colors['end']}")
            for name, state, desc in held:
                session.print(
                    f"  {_render_state(state, colors)}  "
                    f"{name:<45} {desc}"
                )

        if extras:
            session.print(f"{colors['green']}Additional (non-catalogue):{colors['end']}")
            for name, state, desc in extras:
                session.print(
                    f"  {_render_state(state, colors)}  "
                    f"{name:<45} {desc}"
                )

        if not_held:
            session.print(f"{colors['yellow']}Not held by this token:{colors['end']}")
            for name, state, desc in not_held:
                session.print(
                    f"  {colors['red']}[x]{colors['end']}  "
                    f"{name:<45} {desc}"
                )

        session.print(
            f"  {colors['cyan']}[+] enabled   [ ] disabled   "
            f"[-] removed   [x] not held{colors['end']}"
        )
        session.log_plugin_result(
            'enablepriv',
            '\n'.join(f'{n}|{s}|{d}' for n, s, d in held + extras + not_held),
            'list-all',
        )
        return 0

    # ---- --vuln ---------------------------------------------------------

    if action == 'vuln':
        out = _run_ps(session, _list_ps(), timeout=30.0)
        if not out:
            session.print(
                f"{colors['red']}Failed to enumerate privileges "
                f"(no output from target){colors['end']}"
            )
            session.log_plugin_result('enablepriv', '', 'vuln: no output')
            return 1

        err = _lines_after(out, _ERR_MARK)
        if err:
            session.print(f"{colors['red']}{err[0]}{colors['end']}")
            session.log_plugin_result('enablepriv', '', f'vuln: {err[0]}')
            return 1

        held = {}
        for line in _lines_after(out, _LIST_MARK):
            if '|' not in line:
                continue
            name, _, state = line.partition('|')
            held[name.strip()] = state.strip()

        if not held:
            session.print(
                f"{colors['yellow']}Token reports no privileges{colors['end']}"
            )
            return 0

        bucketed = {tier: [] for tier in _VULN_TIERS}
        uncategorised = []
        for name, state in sorted(held.items()):
            placed = False
            for tier, entries in _VULN_TIERS.items():
                if name in entries:
                    bucketed[tier].append((name, state, entries[name]))
                    placed = True
                    break
            if not placed:
                uncategorised.append((name, state))

        tier_style = {
            'CRITICAL': colors['red'],
            'HIGH':     colors['yellow'],
            'MEDIUM':   colors['cyan'],
            'LOW':      colors['blue'],
        }

        total = sum(len(v) for v in bucketed.values())
        session.print(
            f"{colors['cyan']}Privilege risk assessment — "
            f"{total} of {len(held)} held privileges carry security weight"
            f"{colors['end']}"
        )

        for tier in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            rows = bucketed[tier]
            if not rows:
                continue
            style = tier_style[tier]
            session.print(
                f"{style}{tier} ({len(rows)}):{colors['end']}"
            )
            rows.sort(key=lambda r: (0 if r[1] == 'ENABLED' else 1, r[0]))
            for name, state, reason in rows:
                session.print(
                    f"  {_render_state(state, colors)}  "
                    f"{name:<45} {reason}"
                )

        if uncategorised:
            session.print(f"{colors['cyan']}Uncategorised ({len(uncategorised)}):{colors['end']}")
            for name, state in uncategorised:
                session.print(
                    f"  {_render_state(state, colors)}  {name}"
                )

        session.print(
            f"  {colors['cyan']}[+] enabled   [ ] disabled   "
            f"[-] removed{colors['end']}"
        )
        session.log_plugin_result(
            'enablepriv',
            '\n'.join(
                f'{tier}|{n}|{s}|{r}'
                for tier in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
                for n, s, r in bucketed[tier]
            ),
            'vuln',
        )
        return 0

    # ---- --all ----------------------------------------------------------

    if action in ('enable-all', 'disable-all'):
        enable = (action == 'enable-all')
        verb = 'Enabling' if enable else 'Disabling'
        session.print(f"{colors['cyan']}{verb} every privilege in the token...{colors['end']}")
        out = _run_ps(session, _set_all_ps(enable), timeout=60.0)
        if not out:
            session.print(
                f"{colors['red']}No output from target "
                f"(transport failure or timeout){colors['end']}"
            )
            session.log_plugin_result('enablepriv', '', f'{action}: no output')
            return 1

        ok_lines  = _lines_after(out, _OK_MARK)
        err_lines = _lines_after(out, _ERR_MARK)

        for line in ok_lines:
            session.print(f"  {colors['green']}{line}{colors['end']}")
        for line in err_lines:
            session.print(f"  {colors['yellow']}{line}{colors['end']}")

        session.log_plugin_result(
            'enablepriv',
            '\n'.join(ok_lines + err_lines),
            action,
        )

        if not ok_lines and not err_lines:
            session.print(
                f"{colors['red']}No privileges toggled — token may be empty"
                f"{colors['end']}"
            )
            return 1
        return 0

    # ---- single privilege ----------------------------------------------

    name   = opts['name']
    enable = (action == 'enable')
    verb   = 'Enabling' if enable else 'Disabling'
    session.print(f"{colors['cyan']}{verb} {name}...{colors['end']}")

    out = _run_ps(session, _set_ps(name, enable), timeout=45.0)
    if not out:
        msg = 'no output from target (transport failure or timeout)'
        session.print(f"{colors['red']}Failed: {msg}{colors['end']}")
        session.log_plugin_result('enablepriv', '', f'{action} {name}: {msg}')
        return 1

    err_lines = _lines_after(out, _ERR_MARK)
    if err_lines:
        session.print(f"{colors['red']}{err_lines[0]}{colors['end']}")
        session.log_plugin_result('enablepriv', '', f'{action} {name}: {err_lines[0]}')
        return 1

    ok_lines = _lines_after(out, _OK_MARK)
    if not ok_lines:
        snippet = out.strip()[:300] or 'empty output'
        session.print(
            f"{colors['red']}Unexpected response from target: {snippet}"
            f"{colors['end']}"
        )
        session.log_plugin_result('enablepriv', '', f'{action} {name}: {snippet}')
        return 1

    session.print(f"{colors['green']}{ok_lines[0]}{colors['end']}")
    session.log_plugin_result('enablepriv', ok_lines[0], f'{action} {name}')
    return 0


def _render_state(state, colors):
    if state == 'ENABLED':
        return f"{colors['green']}[+]{colors['end']}"
    if state == 'DISABLED':
        return f"{colors['yellow']}[ ]{colors['end']}"
    if state == 'REMOVED':
        return f"{colors['red']}[-]{colors['end']}"
    return f"{colors['red']}[x]{colors['end']}"