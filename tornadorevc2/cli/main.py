"""Operator CLI: daemon lifecycle commands plus thin console client."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

from ..daemon.config import DaemonConfig
from ..daemon.lifecycle import (
    DaemonAlreadyRunning,
    clear_runtime_state,
    load_saved_config,
    require_not_running,
    running_daemon,
    spawn_detached,
    stop_pid,
    wait_until_ready,
)
from ..ipc.client import IpcError, ManagementClient, load_token
from .repl import run_console


def add_listener_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Reverse-shell bind address')
    parser.add_argument('-p', '--port', type=int, default=4444, help='TCP reverse-shell listener port')
    parser.add_argument('-tp', '--tls-port', type=int, default=8443, help='TLS reverse-shell listener port')
    parser.add_argument('-c', '--cert', default='server.pem', help='TLS certificate file')
    parser.add_argument('-k', '--key', default='server.key', help='TLS private key file')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='tornadorevc2',
        description='TornadoRevC2 daemon/client. -H/-p/-tp configure reverse-shell listeners only.',
        epilog='Commands: start, stop, restart, status, console, jobs',
    )
    add_listener_args(parser)
    parser.add_argument('--runtime-dir', default=None, help='Runtime directory for local management IPC state')
    parser.add_argument('--foreground', action='store_true', help='Run the daemon in this process')
    parser.add_argument('--config', default=None, help=argparse.SUPPRESS)
    parser.add_argument('command', nargs='?', default=None, help='start | stop | restart | status | console | jobs')
    parser.add_argument('extra', nargs=argparse.REMAINDER)
    return parser


def config_from_args(args) -> DaemonConfig:
    extra = list(args.extra or [])
    host, port, tls_port = args.host, args.port, args.tls_port
    cert, key = args.cert, args.key
    runtime_dir = args.runtime_dir
    foreground = args.foreground
    if args.command in ('start', 'restart') and extra:
        overlay = argparse.ArgumentParser(add_help=False)
        add_listener_args(overlay)
        overlay.add_argument('--runtime-dir', default=None)
        overlay.add_argument('--foreground', action='store_true')
        parsed, leftover = overlay.parse_known_args(extra)
        if leftover:
            raise SystemExit(f'Unrecognized arguments: {" ".join(leftover)}')
        host, port, tls_port = parsed.host, parsed.port, parsed.tls_port
        cert, key = parsed.cert, parsed.key
        if parsed.runtime_dir:
            runtime_dir = parsed.runtime_dir
        foreground = foreground or parsed.foreground
    args.foreground = foreground
    return DaemonConfig.from_listener_args(
        host=host,
        port=port,
        tls_port=tls_port,
        certfile=cert,
        keyfile=key,
        runtime_dir=runtime_dir,
    )


def print_start_banner(pid: int, config: DaemonConfig) -> None:
    rs = config.reverse_shell
    mg = config.management
    mg_line = mg.socket_path if mg.transport == 'unix' else f'{mg.host}:{mg.port}'
    print(f'Daemon started (pid {pid})')
    print()
    print(f'Reverse TCP listener: {rs.host}:{rs.tcp_port}')
    print(f'Reverse TLS listener: {rs.host}:{rs.tls_port}')
    print(f'Management socket: {mg_line}')


def print_status_payload(payload: dict) -> None:
    listeners = payload.get('reverse_listeners') or {}
    tcp = listeners.get('tcp') or {}
    tls = listeners.get('tls') or {}
    jobs = payload.get('jobs') or {}
    mg = payload.get('management') or {}
    print(f"Daemon: {payload.get('daemon', 'unknown')}")
    print(f"PID: {payload.get('pid', '?')}")
    print()
    print('Reverse listeners:')
    print(f"  TCP  {tcp.get('host')}:{tcp.get('port')}")
    print(f"  TLS  {tls.get('host')}:{tls.get('port')}")
    print()
    print('Management:')
    if mg.get('transport') == 'unix':
        print(f"  local IPC: {mg.get('socket_path')}")
    else:
        print(f"  local IPC: {mg.get('host')}:{mg.get('port')}")
    print()
    print(f"Sessions: {payload.get('sessions', 0)} active")
    print(
        f"Jobs: {jobs.get('running', 0)} running, "
        f"{jobs.get('completed', 0)} completed"
    )


def _client(config: DaemonConfig) -> ManagementClient:
    token = load_token(config)
    return ManagementClient(config, token=token)


def cmd_start(config: DaemonConfig, foreground: bool = False) -> int:
    try:
        require_not_running(config)
    except DaemonAlreadyRunning as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if foreground:
        from ..daemon.server import TornadoDaemon
        daemon = TornadoDaemon(config)
        daemon.start()
        print_start_banner(os.getpid(), config)
        daemon.serve_forever()
        return 0
    spawn_detached(config)
    try:
        pid = wait_until_ready(config)
    except Exception as exc:
        print(f'Failed to start daemon: {exc}', file=sys.stderr)
        return 1
    saved = load_saved_config(config) or config
    print_start_banner(pid, saved)
    return 0


def cmd_stop(config: DaemonConfig) -> int:
    found = running_daemon(config)
    if not found:
        print('Daemon: not running')
        clear_runtime_state(config)
        return 0
    pid, saved = found
    try:
        with _client(saved) as client:
            client.call('daemon.stop', timeout=5.0)
    except Exception:
        stop_pid(pid)
    else:
        stop_pid(pid)
    clear_runtime_state(saved)
    print(f'Daemon stopped (pid {pid})')
    return 0


def cmd_restart(config: DaemonConfig) -> int:
    cmd_stop(config)
    return cmd_start(config, foreground=False)


def cmd_status(config: DaemonConfig) -> int:
    found = running_daemon(config)
    if not found:
        print('Daemon: not running')
        return 1
    _pid, saved = found
    try:
        with _client(saved) as client:
            payload = client.call('daemon.status', timeout=5.0)
    except Exception as exc:
        print(f'Daemon: running but management IPC is unavailable ({exc})', file=sys.stderr)
        return 1
    print_status_payload(payload)
    return 0


def cmd_console(config: DaemonConfig) -> int:
    found = running_daemon(config)
    if not found:
        print('Daemon is not running. Start it with: tornadorevc2 start [-H HOST] [-p PORT] [-tp TLS_PORT]', file=sys.stderr)
        return 1
    _pid, saved = found
    return run_console(saved)


def cmd_jobs(config: DaemonConfig, extra: Sequence[str]) -> int:
    found = running_daemon(config)
    if not found:
        print('Daemon is not running.', file=sys.stderr)
        return 1
    _pid, saved = found
    args = list(extra)
    try:
        with _client(saved) as client:
            if not args or args[0] in ('list', 'ls'):
                result = client.call('console.command', {'line': 'jobs'})
                sys.stdout.write(result.get('output') or '')
                return 0
            if args[0] == 'attach' and len(args) >= 2:
                from .repl import attach_job
                attach_job(client, int(args[1]))
                return 0
            if args[0] in ('show', 'get') and len(args) >= 2:
                result = client.call('jobs.get', {'id': int(args[1])})
                sys.stdout.write(result.get('output') or '')
                if result.get('error'):
                    print(f"Error: {result['error']}")
                return 0
            print('Usage: tornadorevc2 jobs [list|attach <id>|show <id>]')
            return 2
    except IpcError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def cmd_daemon(config_path: str) -> int:
    with open(config_path, 'r', encoding='utf-8') as handle:
        config = DaemonConfig.from_mapping(json.load(handle))
    from ..daemon.server import TornadoDaemon
    import signal

    daemon = TornadoDaemon(config)
    daemon.start()

    def _handle_stop(signum, frame):
        daemon.handler.running = False

    signal.signal(signal.SIGTERM, _handle_stop)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, _handle_stop)
    daemon.serve_forever()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == '_daemon':
        config_path = args.config
        extra = list(args.extra or [])
        if not config_path and '--config' in extra:
            config_path = extra[extra.index('--config') + 1]
        if not config_path:
            raise SystemExit('_daemon requires --config')
        raise SystemExit(cmd_daemon(config_path))

    try:
        config = config_from_args(args)
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit(str(exc)) from exc

    command = args.command
    if command is None:
        found = running_daemon(config)
        if found:
            raise SystemExit(cmd_console(config))
        code = cmd_start(config, foreground=False)
        if code != 0:
            raise SystemExit(code)
        raise SystemExit(cmd_console(config))

    if command == 'start':
        raise SystemExit(cmd_start(config, foreground=args.foreground))
    if command == 'stop':
        raise SystemExit(cmd_stop(config))
    if command == 'restart':
        raise SystemExit(cmd_restart(config))
    if command == 'status':
        raise SystemExit(cmd_status(config))
    if command == 'console':
        raise SystemExit(cmd_console(config))
    if command == 'jobs':
        raise SystemExit(cmd_jobs(config, args.extra or []))
    parser.error(f'Unknown command {command}')


if __name__ == '__main__':
    main()
