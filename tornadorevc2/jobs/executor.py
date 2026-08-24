from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, Future
from typing import Callable


class JobExecutor:
    def __init__(self, max_workers: int = 4):
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='tornado-job')

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        return self._pool.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = False) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=True)
