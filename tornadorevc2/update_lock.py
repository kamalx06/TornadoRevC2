"""Cross-process update lock using OS advisory file locking."""

import os
import sys

from .update_state import UPDATE_STATE_DIR


class UpdateLockError(Exception):
    """Raised when the update lock cannot be acquired."""


class UpdateLock:
    """Advisory file lock shared across TornadoRevC2 processes."""

    def __init__(self, lock_path=None):
        self.lock_path = lock_path or os.path.join(UPDATE_STATE_DIR, 'update.lock')
        self._handle = None

    def acquire(self):
        os.makedirs(os.path.dirname(self.lock_path), exist_ok=True)
        self._handle = open(self.lock_path, 'a+b')
        try:
            if os.name == 'nt':
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._close_handle()
            raise UpdateLockError('Another update operation is already in progress') from exc
        return self

    def release(self):
        if not self._handle:
            return
        try:
            if os.name == 'nt':
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._close_handle()

    def _close_handle(self):
        if self._handle:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False
