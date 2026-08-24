"""Tab-completion for the operator console (local paths + daemon snapshots)."""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

from ..constants import (
    CLIENT_COMMANDS,
    ID_COMMANDS,
    INMEMORY_FILETYPES,
    MAIN_COMMANDS,
)

JOBS_SUBCOMMANDS = ('list', 'ls', 'attach', 'show', 'get')
PLUGINS_SUBCOMMANDS = ('list', 'load', 'unload', 'reload', 'info', 'help')
CONSOLE_COMMANDS = MAIN_COMMANDS + ('jobs',)


def complete_paths(text: str) -> list[str]:
    raw = os.path.expanduser(text or '')
    if raw.endswith(os.sep) or raw.endswith('/'):
        dirname, basename = raw, ''
    else:
        dirname, basename = os.path.split(raw)
    if not dirname:
        dirname = '.'
    if not os.path.isdir(dirname):
        return []
    matches = []
    try:
        for entry in sorted(os.listdir(dirname)):
            if not entry.startswith(basename):
                continue
            full = os.path.join(dirname, entry)
            if os.path.isdir(full):
                matches.append(full + os.sep)
            else:
                matches.append(full)
    except OSError:
        return []
    return matches


def arg_index(line: str, begidx: int) -> int:
    prefix = line[:begidx]
    ends_space = prefix.endswith(' ') or prefix.endswith('\t')
    words = prefix.split()
    if not words:
        return 0
    if ends_space:
        return len(words)
    return len(words) - 1


def candidates(line: str, text: str, begidx: int, mode: str, snapshot: dict) -> list[str]:
    words = line.split()
    cmd = words[0].lower() if words else ''
    index = arg_index(line, begidx)
    session_ids = list(snapshot.get('session_ids') or [])
    plugins = list(snapshot.get('plugins') or [])
    job_ids = list(snapshot.get('job_ids') or [])
    needle = text.lower()

    if mode == 'client':
        if index == 0:
            return sorted(c for c in CLIENT_COMMANDS if c.startswith(needle))
        if cmd == 'upload' and index == 1:
            return complete_paths(text)
        if cmd == 'download' and index == 2:
            return complete_paths(text)
        if cmd == 'run' and index == 1:
            return sorted(p for p in plugins if p.startswith(needle))
        if cmd == 'run' and index == 2 and words[1].lower() == 'inmemory':
            return sorted(t for t in INMEMORY_FILETYPES if t.startswith(needle))
        if cmd == 'run' and index == 3 and words[1].lower() == 'inmemory':
            return complete_paths(text)
        if cmd == 'plugins' and index == 1:
            return sorted(s for s in PLUGINS_SUBCOMMANDS if s.startswith(needle))
        if cmd == 'plugins' and index == 2 and words[1].lower() in ('load', 'unload', 'reload', 'info'):
            return sorted(p for p in plugins if p.startswith(needle))
        # Show client commands as fallback when no specific condition matches
        return sorted(c for c in CLIENT_COMMANDS if c.startswith(needle))

    # Main console mode
    if index == 0:
        return sorted(c for c in CONSOLE_COMMANDS if c.startswith(needle))
    if index == 1 and cmd in ID_COMMANDS:
        return sorted(i for i in session_ids if i.startswith(text))
    if cmd == 'run' and index == 1:
        return sorted(p for p in plugins if p.startswith(needle))
    if cmd == 'run' and index == 2:
        return sorted(i for i in session_ids if i.startswith(text))
    if cmd == 'run' and index == 3 and words[1].lower() == 'inmemory':
        return sorted(t for t in INMEMORY_FILETYPES if t.startswith(needle))
    if cmd == 'run' and index == 4 and words[1].lower() == 'inmemory':
        return complete_paths(text)
    if cmd == 'plugins' and index == 1:
        return sorted(s for s in PLUGINS_SUBCOMMANDS if s.startswith(needle))
    if cmd == 'plugins' and index == 2 and words[1].lower() in ('load', 'unload', 'reload', 'info'):
        return sorted(p for p in plugins if p.startswith(needle))
    if cmd == 'jobs' and index == 1:
        return sorted(s for s in JOBS_SUBCOMMANDS if s.startswith(needle))
    if cmd == 'jobs' and index == 2 and words[1].lower() in ('attach', 'show', 'get'):
        return sorted(j for j in job_ids if j.startswith(needle))
    if cmd == 'upload' and index == 2:
        return complete_paths(text)
    if cmd == 'download' and index == 3:
        return complete_paths(text)
    # Fallback: show main console commands
    return sorted(c for c in CONSOLE_COMMANDS if c.startswith(needle))


class ConsoleCompleter:
    def __init__(self, fetch_snapshot: Callable[[Optional[int]], dict]):
        self._fetch_snapshot = fetch_snapshot
        self._mode = 'main'
        self._session_id: Optional[int] = None
        self._matches: list[str] = []
        self._snapshot: dict = {}
        self._snapshot_at = 0.0

    def set_mode(self, mode: str, session_id: Optional[int] = None) -> None:
        self._mode = mode
        self._session_id = session_id
        self._snapshot_at = 0.0

    def _snapshot(self) -> dict:
        now = time.monotonic()
        if now - self._snapshot_at > 0.4:
            try:
                self._snapshot = self._fetch_snapshot(self._session_id) or {}
            except Exception:
                self._snapshot = self._snapshot or {}
            self._snapshot_at = now
        return self._snapshot

    def complete(self, text: str, state: int) -> Optional[str]:
        if not readline:
            return None
        if state == 0:
            line = readline.get_line_buffer()
            begidx = readline.get_begidx()
            self._matches = candidates(line, text, begidx, self._mode, self._snapshot())
        try:
            return self._matches[state]
        except IndexError:
            return None
