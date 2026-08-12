"""Regression coverage for scan isolation, security and bounded work."""

from __future__ import annotations

import asyncio
import socket

import pytest

from core import engine
from core.config import ScanConfig
from core.context import ScanContext
from core.http_client import HTTPClient, _SafeResolver
from core.progress import ProgressEmitter, set_emitter
from core.security import UnsafeTargetError, redact_secrets, validate_http_url
from modules.photo_compare import compare_profile_photos


def test_private_http_targets_require_explicit_opt_in() -> None:
    for url in (
        "http://127.0.0.1/admin",
        "http://10.1.2.3/",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/",
        "http://localhost/internal",
    ):
        with pytest.raises(UnsafeTargetError):
            validate_http_url(url)
        assert validate_http_url(url, allow_private_networks=True) == url


def test_non_http_and_credential_urls_are_rejected() -> None:
    with pytest.raises(UnsafeTargetError):
        validate_http_url("file:///etc/passwd")
    with pytest.raises(UnsafeTargetError):
        validate_http_url("https://user:pass@example.com/profile")


@pytest.mark.asyncio
async def test_dns_answers_cannot_rebind_to_private_networks() -> None:
    class _Resolver:
        async def resolve(self, host, port=0, family=socket.AF_INET):
            return [
                {
                    "hostname": host,
                    "host": "127.0.0.1",
                    "port": port,
                    "family": family,
                    "proto": 0,
                    "flags": 0,
                }
            ]

        async def close(self):
            return None

    resolver = _SafeResolver(_Resolver())
    with pytest.raises(UnsafeTargetError):
        await resolver.resolve("public.example", 443)


def test_recursive_secret_redaction_does_not_hide_finding_containers() -> None:
    data = redact_secrets(
        {
            "token": "abc",
            "nested": {"api_key": "def"},
            "leaked_secrets": [{"fingerprint": "safe"}],
        }
    )
    assert data["token"] == "[REDACTED]"
    assert data["nested"]["api_key"] == "[REDACTED]"
    assert data["leaked_secrets"] == [{"fingerprint": "safe"}]


@pytest.mark.asyncio
async def test_rate_wait_does_not_hold_request_semaphores() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class _RateBucket:
        async def acquire(self, host):
            entered.set()
            await release.wait()

        async def record_success(self, host):
            return None

        async def record_throttled(self, host, retry_after=None):
            return None

    client = HTTPClient(rate_bucket=_RateBucket())
    initial_global = client._semaphore._value
    host_lock = client._host_lock("https://example.com/x")
    initial_host = host_lock._value
    task = asyncio.create_task(client._acquire("https://example.com/x"))
    await entered.wait()
    assert client._semaphore._value == initial_global
    assert host_lock._value == initial_host
    release.set()
    global_lock, acquired_host = await task
    acquired_host.release()
    global_lock.release()


@pytest.mark.asyncio
async def test_photo_batch_timeout_returns_completed_partial_work() -> None:
    cancelled = asyncio.Event()

    class _Client:
        async def get_bytes(self, url):
            if url.endswith("slow.jpg"):
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cancelled.set()
                    raise
            return 200, b"identical", 0.01

    matches = await compare_profile_photos(
        _Client(),
        [
            ("one", "https://images.example/one.jpg"),
            ("two", "https://images.example/two.jpg"),
            ("slow", "https://images.example/slow.jpg"),
        ],
        timeout=0.2,
    )
    assert cancelled.is_set()
    assert matches == [
        {
            "platform_a": "one",
            "platform_b": "two",
            "similarity": 1.0,
            "method": "md5",
        }
    ]


@pytest.mark.asyncio
async def test_concurrent_run_scans_have_isolated_context_and_progress(monkeypatch) -> None:
    contexts: list[ScanContext] = []
    both_started = asyncio.Event()

    async def inspect_context(state):
        contexts.append(state.context)
        state.context.negative_cache.setdefault(state.cfg.username, set()).add("own")
        assert state.context.skill_budget.consume() is True
        if len(contexts) == 2:
            both_started.set()
        await both_started.wait()

    monkeypatch.setattr(
        engine,
        "_phase_registry",
        lambda: (
            engine.PhaseSpec("isolation_probe", lambda _state: True, inspect_context),
        ),
    )

    emitter_a = ProgressEmitter()
    emitter_b = ProgressEmitter()
    queue_a = emitter_a.subscribe()
    queue_b = emitter_b.subscribe()
    set_emitter(emitter_a)
    task_a = asyncio.create_task(
        engine.run_scan(
            ScanConfig(username="alice", enrichment=False, ai_skills=True)
        )
    )
    set_emitter(emitter_b)
    task_b = asyncio.create_task(
        engine.run_scan(
            ScanConfig(username="bob", enrichment=False, ai_skills=True)
        )
    )
    set_emitter(None)
    result_a, result_b = await asyncio.gather(task_a, task_b)

    assert len({id(ctx.negative_cache) for ctx in contexts}) == 2
    assert len({id(ctx.soft_404_cache) for ctx in contexts}) == 2
    assert len({id(ctx.skill_budget) for ctx in contexts}) == 2
    assert [ctx.skill_budget.used for ctx in contexts] == [1, 1]
    assert contexts[0].negative_cache != contexts[1].negative_cache
    assert result_a.diagnostics["phases"]["isolation_probe"]["status"] == "completed"
    assert result_b.diagnostics["phases"]["isolation_probe"]["status"] == "completed"
    assert (await queue_a.get()).phase == "isolation_probe"
    assert (await queue_b.get()).phase == "isolation_probe"


@pytest.mark.asyncio
async def test_registered_phase_failure_isolated_and_recorded(monkeypatch) -> None:
    async def bad(_state):
        raise RuntimeError("source failed")

    async def good(state):
        state.result.discovered_usernames.append("continued")

    monkeypatch.setattr(
        engine,
        "_phase_registry",
        lambda: (
            engine.PhaseSpec("bad_source", lambda _state: True, bad),
            engine.PhaseSpec("good_source", lambda _state: True, good),
        ),
    )
    result = await engine.run_scan(ScanConfig(username="alice", enrichment=False))
    assert result.discovered_usernames == ["continued"]
    assert result.diagnostics["phases"]["bad_source"]["status"] == "error"
    assert result.diagnostics["phases"]["good_source"]["status"] == "completed"


@pytest.mark.asyncio
async def test_run_scan_cancellation_stops_background_seed_tasks(monkeypatch) -> None:
    phase_started = asyncio.Event()
    seed_stopped = asyncio.Event()

    async def seed_worker():
        try:
            await asyncio.Event().wait()
        finally:
            seed_stopped.set()

    async def blocking_phase(state):
        state.context.track_seed(asyncio.create_task(seed_worker()))
        phase_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(
        engine,
        "_phase_registry",
        lambda: (
            engine.PhaseSpec("blocking", lambda _state: True, blocking_phase),
        ),
    )
    scan_task = asyncio.create_task(
        engine.run_scan(ScanConfig(username="alice", enrichment=False))
    )
    await phase_started.wait()
    scan_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await scan_task
    assert seed_stopped.is_set()


@pytest.mark.asyncio
async def test_run_scan_rejects_empty_direct_python_target() -> None:
    with pytest.raises(ValueError, match="username is empty"):
        await engine.run_scan(ScanConfig(username=""))
