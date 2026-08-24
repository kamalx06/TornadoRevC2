from __future__ import annotations

from typing import Callable, Optional


class OutputSink:
    """File-like sink used to capture operator output from handler/plugin code."""

    def __init__(self, on_write: Optional[Callable[[str], None]] = None):
        self._chunks: list[str] = []
        self._on_write = on_write

    def write(self, data) -> int:
        text = data if isinstance(data, str) else data.decode('utf-8', 'replace')
        if not text:
            return 0
        self._chunks.append(text)
        if self._on_write:
            self._on_write(text)
        return len(text)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False

    def getvalue(self) -> str:
        return ''.join(self._chunks)
