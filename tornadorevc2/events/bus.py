from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Callable, Optional

from .types import Event


class EventBus:
    def __init__(self, history: int = 200):
        self._subs: list[Callable[[Event], None]] = []
        self._lock = Lock()
        self._history: deque[Event] = deque(maxlen=history)

    def subscribe(self, callback: Callable[[Event], None]) -> Callable[[Event], None]:
        with self._lock:
            self._subs.append(callback)
        return callback

    def unsubscribe(self, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self._subs = [item for item in self._subs if item is not callback]

    def publish(self, name: str, payload: Optional[dict] = None) -> Event:
        event = Event(name=name, payload=payload or {})
        with self._lock:
            self._history.append(event)
            subscribers = list(self._subs)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:
                pass
        return event

    def history(self) -> list[Event]:
        with self._lock:
            return list(self._history)
