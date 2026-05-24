"""In-memory scan job orchestration for the REST API."""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from core.config import ScanConfig
from core.logging_setup import get_logger
from core.models import ScanResult
from core.progress import ProgressEmitter, set_emitter
from core.scan_service import complete_scan_result

log = get_logger(__name__)

ScanRunner = Callable[[ScanConfig], Awaitable[ScanResult]]


def _env_int(key: str, default: int) -> int:
    try:
        value = int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(1, value)


@dataclass
class ScanJob:
    id: str
    username: str
    request: dict[str, Any]
    save_history: bool = True
    case_id: int | None = None
    status: str = "queued"
    created_at: int = field(default_factory=lambda: int(time.time()))
    started_at: int | None = None
    finished_at: int | None = None
    error: str | None = None
    result: dict[str, Any] | None = None
    scan_id: int | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    max_events: int = 500
    _subs: list[asyncio.Queue[dict[str, Any] | None]] = field(default_factory=list, repr=False)
    _task: asyncio.Task[None] | None = field(default=None, repr=False)

    def publish(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
        for q in list(self._subs):
            q.put_nowait(event)

    def subscribe(self) -> tuple[asyncio.Queue[dict[str, Any] | None], int]:
        q: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self._subs.append(q)
        if self.finished_at is not None:
            q.put_nowait(None)
        return q, len(self.events)

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any] | None]) -> None:
        if q in self._subs:
            self._subs.remove(q)

    def close(self) -> None:
        for q in list(self._subs):
            q.put_nowait(None)

    def to_dict(self, *, include_result: bool = False) -> dict[str, Any]:
        data = {
            "id": self.id,
            "username": self.username,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "save_history": self.save_history,
            "case_id": self.case_id,
            "scan_id": self.scan_id,
            "error": self.error,
            "event_count": len(self.events),
            "request": self.request,
        }
        if include_result:
            data["result"] = self.result
        return data


class ScanJobStore:
    def __init__(
        self,
        *,
        runner: ScanRunner,
        max_jobs: int | None = None,
        max_concurrent: int | None = None,
        max_events_per_job: int | None = None,
    ) -> None:
        self._runner = runner
        self._jobs: dict[str, ScanJob] = {}
        self._max_jobs = max_jobs or _env_int("CYBERM4FIA_SCAN_JOB_MAX_JOBS", 100)
        self._max_events_per_job = max_events_per_job or _env_int(
            "CYBERM4FIA_SCAN_JOB_MAX_EVENTS", 500
        )
        concurrency = max_concurrent or _env_int("CYBERM4FIA_SCAN_JOB_CONCURRENCY", 2)
        self._semaphore = asyncio.Semaphore(concurrency)

    def create_job(
        self,
        cfg: ScanConfig,
        request_payload: dict[str, Any],
        *,
        save_history: bool,
        case_id: int | None = None,
    ) -> ScanJob:
        self._prune_finished()
        if len(self._jobs) >= self._max_jobs:
            raise RuntimeError("scan job queue is full")
        job = ScanJob(
            id=uuid.uuid4().hex,
            username=cfg.username,
            request=request_payload,
            save_history=save_history,
            case_id=case_id,
            max_events=self._max_events_per_job,
        )
        self._jobs[job.id] = job
        job.publish(
            {
                "kind": "job_accepted",
                "phase": "queued",
                "message": f"job {job.id} accepted",
                "data": {"job_id": job.id, "username": cfg.username},
            }
        )
        job._task = asyncio.create_task(self._run(job, cfg))
        return job

    def list_jobs(self, *, limit: int = 20) -> list[ScanJob]:
        jobs = sorted(
            self._jobs.values(),
            key=lambda job: (job.created_at, job.id),
            reverse=True,
        )
        return jobs[: max(1, limit)]

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def _prune_finished(self) -> None:
        overflow = len(self._jobs) - self._max_jobs + 1
        if overflow <= 0:
            return
        finished = sorted(
            (job for job in self._jobs.values() if job.finished_at is not None),
            key=lambda job: (job.finished_at or 0, job.created_at, job.id),
        )
        for job in finished[:overflow]:
            self._jobs.pop(job.id, None)

    async def _run(self, job: ScanJob, cfg: ScanConfig) -> None:
        async with self._semaphore:
            job.status = "running"
            job.started_at = int(time.time())
            job.publish(
                {
                    "kind": "job_started",
                    "phase": "queued",
                    "message": f"job {job.id} started",
                    "data": {"job_id": job.id, "username": cfg.username},
                }
            )

            emitter = ProgressEmitter()
            queue = emitter.subscribe()

            async def _forward_events() -> None:
                while True:
                    event = await queue.get()
                    if event is None:
                        break
                    payload = event.to_dict()
                    payload.setdefault("data", {})
                    payload["data"]["job_id"] = job.id
                    job.publish(payload)

            forwarder = asyncio.create_task(_forward_events())
            set_emitter(emitter)
            try:
                result = await self._runner(cfg)
                completed = complete_scan_result(
                    result,
                    cfg,
                    save_history=job.save_history,
                    case_id=job.case_id,
                    mark_watchlist=True,
                )
                job.result = completed.payload
                job.scan_id = completed.scan_id
                job.status = "completed"
                job.publish(
                    {
                        "kind": "result",
                        "phase": "done",
                        "message": "",
                        "data": {"payload": completed.payload, "job_id": job.id},
                    }
                )
            except Exception as exc:
                log.exception("scan job %s failed for %s", job.id, cfg.username)
                job.status = "error"
                job.error = str(exc)
                job.publish(
                    {
                        "kind": "error",
                        "phase": "error",
                        "message": str(exc),
                        "data": {"job_id": job.id},
                    }
                )
            finally:
                set_emitter(None)
                emitter.close()
                with contextlib.suppress(asyncio.CancelledError):
                    await forwarder
                emitter.unsubscribe(queue)
                job.finished_at = int(time.time())
                job.publish(
                    {
                        "kind": "job_finished",
                        "phase": "done",
                        "message": f"job {job.status}",
                        "data": {
                            "job_id": job.id,
                            "status": job.status,
                            "scan_id": job.scan_id,
                        },
                    }
                )
                job.close()
