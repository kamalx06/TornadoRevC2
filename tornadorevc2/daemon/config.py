"""Daemon configuration: reverse-shell listeners vs local-only management IPC."""

from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional


DEFAULT_REVERSE_HOST = '0.0.0.0'
DEFAULT_TCP_PORT = 4444
DEFAULT_TLS_PORT = 8443
DEFAULT_CERTFILE = 'server.pem'
DEFAULT_KEYFILE = 'server.key'
DEFAULT_JOB_WORKERS = 4
DEFAULT_JOB_QUEUE = 100
LOOPBACK_HOSTS = frozenset({'127.0.0.1', '::1', 'localhost'})


def user_token() -> str:
    if hasattr(os, 'getuid'):
        return str(os.getuid())
    return os.environ.get('USERNAME') or os.environ.get('USER') or 'user'


def default_runtime_dir() -> str:
    xdg = os.environ.get('XDG_RUNTIME_DIR')
    if xdg:
        return os.path.join(xdg, 'tornadorevc2')
    return os.path.join(tempfile.gettempdir(), f'tornadorevc2-{user_token()}')


@dataclass
class ReverseShellConfig:
    """Operator-configurable network-facing reverse-shell listeners."""

    host: str = DEFAULT_REVERSE_HOST
    tcp_port: int = DEFAULT_TCP_PORT
    tls_port: int = DEFAULT_TLS_PORT
    certfile: str = DEFAULT_CERTFILE
    keyfile: str = DEFAULT_KEYFILE

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ManagementConfig:
    """Local-only management IPC. Never inherits reverse-shell bind settings."""

    transport: str = 'unix'
    socket_path: str = ''
    host: str = '127.0.0.1'
    port: int = 47821

    def validate(self) -> None:
        transport = (self.transport or 'unix').lower()
        if transport not in ('unix', 'tcp'):
            raise ValueError(f'Unsupported management transport: {self.transport}')
        self.transport = transport
        if transport == 'tcp' and self.host not in LOOPBACK_HOSTS:
            raise ValueError(
                'Management IPC must remain local-only; '
                f'refused non-loopback host {self.host!r}'
            )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class JobsConfig:
    max_workers: int = DEFAULT_JOB_WORKERS
    max_queued: int = DEFAULT_JOB_QUEUE

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PersistenceConfig:
    runtime_dir: str = ''
    jobs_dir: str = ''
    retention: int = 100

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DaemonConfig:
    reverse_shell: ReverseShellConfig = field(default_factory=ReverseShellConfig)
    management: ManagementConfig = field(default_factory=ManagementConfig)
    jobs: JobsConfig = field(default_factory=JobsConfig)
    persistence: PersistenceConfig = field(default_factory=PersistenceConfig)

    def __post_init__(self) -> None:
        self.normalize()

    def normalize(self) -> None:
        runtime = self.persistence.runtime_dir or default_runtime_dir()
        self.persistence.runtime_dir = runtime
        if not self.persistence.jobs_dir:
            self.persistence.jobs_dir = os.path.join(runtime, 'jobs')
        if not self.management.socket_path:
            self.management.socket_path = os.path.join(runtime, 'management.sock')
        self.management.validate()

    @property
    def pid_path(self) -> str:
        return os.path.join(self.persistence.runtime_dir, 'daemon.pid')

    @property
    def state_path(self) -> str:
        return os.path.join(self.persistence.runtime_dir, 'daemon.json')

    @property
    def token_path(self) -> str:
        return os.path.join(self.persistence.runtime_dir, 'auth.token')

    @property
    def log_path(self) -> str:
        return os.path.join(self.persistence.runtime_dir, 'daemon.log')

    def as_dict(self) -> dict[str, Any]:
        return {
            'reverse_shell': self.reverse_shell.as_dict(),
            'management': self.management.as_dict(),
            'jobs': self.jobs.as_dict(),
            'persistence': self.persistence.as_dict(),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'DaemonConfig':
        rs = data.get('reverse_shell') or {}
        mg = data.get('management') or {}
        jb = data.get('jobs') or {}
        ps = data.get('persistence') or {}
        cfg = cls(
            reverse_shell=ReverseShellConfig(
                host=rs.get('host', DEFAULT_REVERSE_HOST),
                tcp_port=int(rs.get('tcp_port', DEFAULT_TCP_PORT)),
                tls_port=int(rs.get('tls_port', DEFAULT_TLS_PORT)),
                certfile=rs.get('certfile', DEFAULT_CERTFILE),
                keyfile=rs.get('keyfile', DEFAULT_KEYFILE),
            ),
            management=ManagementConfig(
                transport=mg.get('transport', 'unix'),
                socket_path=mg.get('socket_path', ''),
                host=mg.get('host', '127.0.0.1'),
                port=int(mg.get('port', 47821)),
            ),
            jobs=JobsConfig(
                max_workers=int(jb.get('max_workers', DEFAULT_JOB_WORKERS)),
                max_queued=int(jb.get('max_queued', DEFAULT_JOB_QUEUE)),
            ),
            persistence=PersistenceConfig(
                runtime_dir=ps.get('runtime_dir', ''),
                jobs_dir=ps.get('jobs_dir', ''),
                retention=int(ps.get('retention', 100)),
            ),
        )
        cfg.normalize()
        return cfg

    @classmethod
    def from_listener_args(
        cls,
        host: Optional[str] = None,
        port: Optional[int] = None,
        tls_port: Optional[int] = None,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        runtime_dir: Optional[str] = None,
        management_transport: str = 'unix',
        management_host: str = '127.0.0.1',
        management_port: int = 47821,
        management_socket: Optional[str] = None,
    ) -> 'DaemonConfig':
        """Build config from legacy -H/-p/-tp values without touching management bind."""
        cfg = cls(
            reverse_shell=ReverseShellConfig(
                host=DEFAULT_REVERSE_HOST if host is None else host,
                tcp_port=DEFAULT_TCP_PORT if port is None else int(port),
                tls_port=DEFAULT_TLS_PORT if tls_port is None else int(tls_port),
                certfile=DEFAULT_CERTFILE if certfile is None else certfile,
                keyfile=DEFAULT_KEYFILE if keyfile is None else keyfile,
            ),
            management=ManagementConfig(
                transport=management_transport,
                socket_path=management_socket or '',
                host=management_host,
                port=int(management_port),
            ),
            persistence=PersistenceConfig(runtime_dir=runtime_dir or ''),
        )
        cfg.normalize()
        return cfg
