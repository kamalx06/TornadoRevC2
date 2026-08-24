from __future__ import annotations

import json
import os
from typing import Optional

from .models import Job, STATUS_RUNNING, STATUS_FAILED


class JobStore:
    def __init__(self, jobs_dir: str, retention: int = 100):
        self.jobs_dir = jobs_dir
        self.retention = retention

    def path_for(self, job_id: int) -> str:
        return os.path.join(self.jobs_dir, f'{job_id}.json')

    def save(self, job: Job) -> None:
        os.makedirs(self.jobs_dir, exist_ok=True)
        path = self.path_for(job.id)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as handle:
            json.dump(job.as_dict(), handle)
        os.replace(tmp, path)
        self._trim()

    def load(self, job_id: int) -> Job | None:
        path = self.path_for(job_id)
        if not os.path.exists(path):
            return None
        with open(path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        return Job(
            id=int(data['id']),
            operation=data.get('operation', ''),
            session_id=data.get('session_id'),
            status=data.get('status', STATUS_FAILED),
            created_at=data.get('created_at') or 0.0,
            started_at=data.get('started_at'),
            finished_at=data.get('finished_at'),
            error=data.get('error'),
            output=data.get('output') or '',
        )

    def recover(self) -> list[Job]:
        if not os.path.isdir(self.jobs_dir):
            return []
        jobs = []
        for name in os.listdir(self.jobs_dir):
            if not name.endswith('.json'):
                continue
            try:
                job_id = int(os.path.splitext(name)[0])
            except ValueError:
                continue
            job = self.load(job_id)
            if job is None:
                continue
            if job.status == STATUS_RUNNING:
                job.status = STATUS_FAILED
                job.error = job.error or 'Interrupted by daemon restart'
            jobs.append(job)
        jobs.sort(key=lambda item: item.id)
        return jobs

    def _trim(self) -> None:
        if self.retention <= 0 or not os.path.isdir(self.jobs_dir):
            return
        files = []
        for name in os.listdir(self.jobs_dir):
            if name.endswith('.json'):
                files.append(os.path.join(self.jobs_dir, name))
        files.sort(key=os.path.getmtime, reverse=True)
        for stale in files[self.retention:]:
            try:
                os.remove(stale)
            except OSError:
                pass
