from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import time


@dataclass
class Event:
    name: str
    payload: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
