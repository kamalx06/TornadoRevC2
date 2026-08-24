from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .sink import OutputSink


@dataclass
class ExecutionContext:
    """Source-agnostic execution wrapper so plugins stay unaware of CLI vs jobs."""

    source: str = 'cli'
    job_id: Optional[int] = None
    session_id: Optional[int] = None
    sink: OutputSink = field(default_factory=OutputSink)

    def emit(self, text: str) -> None:
        self.sink.write(text if text.endswith('\n') else text + '\n')
