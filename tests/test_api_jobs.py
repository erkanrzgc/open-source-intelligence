"""Tests for bounded REST scan job orchestration."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from core.api import jobs as jobs_mod
from core.api.jobs import ScanJob, ScanJobStore
from core.config import ScanConfig
from core.models import ScanResult


def test_scan_job_event_backlog_is_capped() -> None:
    job = ScanJob(id="j1", username="alice", request={}, max_events=2)
    job.publish({"kind": "one"})
    job.publish({"kind": "two"})
    job.publish({"kind": "three"})

    assert [event["kind"] for event in job.events] == ["two", "three"]
    assert job.to_dict()["event_count"] == 2


@pytest.mark.asyncio
async def test_running_job_cancellation_propagates_and_notifies_once():
    started = asyncio.Event()
    async def runner(cfg):
        started.set()
        await asyncio.Event().wait()
        return ScanResult(username=cfg.username)
    notifications = []
    store = ScanJobStore(runner=runner)
    job = store.create_job(ScanConfig(username="alice"), {}, save_history=False,
                           on_finish=lambda j: notifications.append(j.status))
    task = job._task
    await started.wait()
    store.cancel(job.id)
    with pytest.raises(asyncio.CancelledError):
        await task
    assert job.status == "cancelled"
    assert job.finished_at is not None
    assert notifications == ["cancelled"]


@pytest.mark.asyncio
async def test_scan_job_store_rejects_when_queue_full(monkeypatch) -> None:
    monkeypatch.setattr(
        jobs_mod,
        "complete_scan_result",
        lambda result, *args, **kwargs: SimpleNamespace(
            payload=result.to_dict(), scan_id=None
        ),
    )
    release = asyncio.Event()

    async def runner(cfg: ScanConfig) -> ScanResult:
        await release.wait()
        return ScanResult(username=cfg.username)

    store = ScanJobStore(runner=runner, max_jobs=1, max_concurrent=1)
    job = store.create_job(
        ScanConfig(username="alice"),
        {"username": "alice"},
        save_history=False,
    )

    with pytest.raises(RuntimeError, match="queue is full"):
        store.create_job(
            ScanConfig(username="bob"),
            {"username": "bob"},
            save_history=False,
        )

    release.set()
    assert job._task is not None
    await job._task


@pytest.mark.asyncio
async def test_scan_job_store_prunes_finished_jobs(monkeypatch) -> None:
    monkeypatch.setattr(
        jobs_mod,
        "complete_scan_result",
        lambda result, *args, **kwargs: SimpleNamespace(
            payload=result.to_dict(), scan_id=None
        ),
    )

    async def runner(cfg: ScanConfig) -> ScanResult:
        return ScanResult(username=cfg.username)

    store = ScanJobStore(runner=runner, max_jobs=1, max_concurrent=1)
    first = store.create_job(
        ScanConfig(username="alice"),
        {"username": "alice"},
        save_history=False,
    )
    assert first._task is not None
    await first._task

    second = store.create_job(
        ScanConfig(username="bob"),
        {"username": "bob"},
        save_history=False,
    )
    assert store.get(first.id) is None
    assert store.get(second.id) is second
    assert second._task is not None
    await second._task
