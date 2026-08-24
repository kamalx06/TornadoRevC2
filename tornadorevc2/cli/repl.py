"""Thin operator console that talks to the local management daemon."""

from __future__ import annotations

import os
import sys
import threading

from ..daemon.config import DaemonConfig
from ..ipc.client import ManagementClient, load_token

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None


GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
END = '\033[0m'


def _init_readline():
    if not readline:
        return
    try:
        if 'libedit' in (readline.__doc__ or ''):
            readline.parse_and_bind('bind ^I rl_complete')
        else:
            readline.parse_and_bind('tab: complete')
    except Exception:
        pass
    readline.set_history_length(1000)


def attach_job(client: ManagementClient, job_id: int) -> None:
    try:
        for message in client.stream('jobs.attach', {'id': job_id}, timeout=None):
            if message.get('type') == 'event' and message.get('event') == 'job.output':
                chunk = (message.get('payload') or {}).get('chunk') or ''
                sys.stdout.write(chunk)
                sys.stdout.flush()
            elif message.get('type') == 'response':
                if not message.get('ok', False):
                    print(message.get('error') or 'attach failed', file=sys.stderr)
                return
    except KeyboardInterrupt:
        print(f'\n{YELLOW}Detached from job {job_id}{END}')


def _event_listener(config: DaemonConfig, token: str, stop: threading.Event) -> None:
    try:
        with ManagementClient(config, token=token) as client:
            for message in client.stream('events.subscribe', timeout=None, until_response=False):
                if stop.is_set():
                    return
                if message.get('type') == 'event' and message.get('event') == 'operator.message':
                    text = (message.get('payload') or {}).get('text') or ''
                    if text:
                        print(text)
    except Exception:
        return


def _session_loop(client: ManagementClient, session_id: int) -> None:
    while True:
        try:
            line = input(f'{GREEN}session {session_id}{END} {CYAN}>{END} ')
        except (EOFError, KeyboardInterrupt):
            print()
            return
        result = client.call('session.command', {'session_id': session_id, 'line': line}, timeout=None)
        sys.stdout.write(result.get('output') or '')
        if result.get('result') in ('exit_session', 'disconnected'):
            return


def run_console(config: DaemonConfig) -> int:
    token = load_token(config)
    stop = threading.Event()
    listener = threading.Thread(target=_event_listener, args=(config, token, stop), daemon=True)
    listener.start()
    _init_readline()
    print(f'{CYAN}Connected to TornadoRevC2 daemon. Type help; exit leaves the console running.{END}')
    try:
        with ManagementClient(config, token=token) as client:
            client.call('ping', timeout=5.0)
            while True:
                try:
                    line = input(f'{GREEN}tornadorevc2>{END} ')
                except EOFError:
                    print()
                    break
                except KeyboardInterrupt:
                    print(f'\n{YELLOW}For exiting please type exit(e) or quit(q){END}')
                    continue
                if not line.strip():
                    continue
                try:
                    result = client.call('console.command', {'line': line}, timeout=None)
                except Exception as exc:
                    print(f'{YELLOW}IPC error: {exc}{END}')
                    continue
                sys.stdout.write(result.get('output') or '')
                if result.get('exit_console'):
                    break
                if result.get('attach'):
                    _session_loop(client, int(result['attach']))
                if result.get('attach_job'):
                    attach_job(client, int(result['attach_job']))
    finally:
        stop.set()
    return 0
