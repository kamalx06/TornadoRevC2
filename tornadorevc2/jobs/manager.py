from __future__ import annotations

from contextlib import redirect_stdout
from threading import Lock
from typing import Any, Callable, Optional
import time

from ..events.bus import EventBus
from ..execution.context import ExecutionContext
from ..execution.sink import OutputSink
from .executor import JobExecutor
from .models import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    Job,
)
from .store import JobStore


JOB_COMMANDS = frozenset({'run', 'upload', 'download', 'sysinfo'})


class JobManager:
    def __init__(
        self,
        bus: EventBus,
        store: Optional[JobStore] = None,
        max_workers: int = 4,
        max_queued: int = 100,
    ):
        self.bus = bus
        self.store = store
        self.max_queued = max_queued
        self._lock = Lock()
        self._jobs: dict[int, Job] = {}
        self._next_id = 1
        self._executor = JobExecutor(max_workers=max_workers)
        if store:
            recovered = store.recover()
            if recovered:
                self._next_id = recovered[-1].id + 1
                for job in recovered:
                    self._jobs[job.id] = job

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    def get(self, job_id: int) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return [self._jobs[key] for key in sorted(self._jobs)]

    def counts(self) -> dict[str, int]:
        with self._lock:
            jobs = list(self._jobs.values())
        running = sum(1 for job in jobs if job.status == STATUS_RUNNING)
        queued = sum(1 for job in jobs if job.status == STATUS_QUEUED)
        completed = sum(1 for job in jobs if job.status == STATUS_COMPLETED)
        failed = sum(1 for job in jobs if job.status == STATUS_FAILED)
        return {
            'running': running,
            'queued': queued,
            'completed': completed,
            'failed': failed,
            'total': len(jobs),
        }

    def submit(
        self,
        operation: str,
        fn: Callable[[ExecutionContext], Any],
        session_id: Optional[int] = None,
    ) -> Job:
        with self._lock:
            queued = sum(1 for job in self._jobs.values() if job.status == STATUS_QUEUED)
            if queued >= self.max_queued:
                raise RuntimeError(f'Job queue is full ({self.max_queued})')
            job = Job(id=self._next_id, operation=operation, session_id=session_id)
            self._next_id += 1
            self._jobs[job.id] = job
        self._persist(job)
        self.bus.publish('job.submitted', job.summary())
        self._executor.submit(self._run, job.id, fn)
        return job

    def _run(self, job_id: int, fn: Callable[[ExecutionContext], Any]) -> None:
        job = self.get(job_id)
        if job is None:
            return
        job.status = STATUS_RUNNING
        job.started_at = time.time()
        self._persist(job)
        self.bus.publish('job.started', job.summary())

        def on_write(chunk: str) -> None:
            job.output += chunk
            self.bus.publish('job.output', {'id': job.id, 'chunk': chunk})

        sink = OutputSink(on_write=on_write)
        ctx = ExecutionContext(source='job', job_id=job.id, session_id=job.session_id, sink=sink)
        try:
            with redirect_stdout(sink):
                fn(ctx)
            job.status = STATUS_COMPLETED
        except Exception as exc:
            job.status = STATUS_FAILED
            job.error = str(exc)
            sink.write(f'\nJob failed: {exc}\n')
        finally:
            job.finished_at = time.time()
            self._persist(job)
            self.bus.publish('job.finished', job.summary())

    def _persist(self, job: Job) -> None:
        if self.store:
            try:
                self.store.save(job)
            except OSError:
                pass
