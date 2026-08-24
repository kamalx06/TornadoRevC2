from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
import time


STATUS_QUEUED = 'QUEUED'
STATUS_RUNNING = 'RUNNING'
STATUS_COMPLETED = 'COMPLETED'
STATUS_FAILED = 'FAILED'
STATUS_CANCELLED = 'CANCELLED'


@dataclass
class Job:
    id: int
    operation: str
    session_id: Optional[int] = None
    status: str = STATUS_QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    output: str = ''

    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        start = self.started_at or self.created_at
        return max(0.0, end - start)

    def as_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'operation': self.operation,
            'session_id': self.session_id,
            'status': self.status,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'finished_at': self.finished_at,
            'error': self.error,
            'elapsed': self.elapsed(),
            'output': self.output,
        }

    def summary(self) -> dict[str, Any]:
        data = self.as_dict()
        data.pop('output', None)
        data['output_len'] = len(self.output)
        return data
