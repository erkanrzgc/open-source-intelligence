"""Wire-attempt budgets cannot be bypassed by retries or hidden redirects."""

import asyncio

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient, RequestBudgetExceeded


@pytest.mark.asyncio
async def test_concurrent_calls_share_one_hard_cap():
    with aioresponses() as mocked:
        mocked.get("https://example.com/a", payload={"ok": True})
        mocked.get("https://example.com/b", payload={"ok": True})
        async with HTTPClient(max_requests=1) as client:
            results = await asyncio.gather(
                client.get_json("https://example.com/a"),
                client.get_json("https://example.com/b"),
                return_exceptions=True,
            )
            assert sum(isinstance(r, RequestBudgetExceeded) for r in results) == 1
            assert client.request_count == 1
            assert client.budget_exhausted
        assert sum(len(calls) for calls in mocked.requests.values()) == 1


@pytest.mark.asyncio
async def test_retry_reserves_budget_before_sending(monkeypatch):
    monkeypatch.setattr("core.http_client._backoff", lambda _: 0)
    with aioresponses() as mocked:
        mocked.get("https://example.com/timeout", exception=asyncio.TimeoutError(), repeat=True)
        async with HTTPClient(max_requests=1) as client:
            with pytest.raises(RequestBudgetExceeded):
                await client.get_json("https://example.com/timeout")
            assert client.request_count == 1
        assert sum(len(calls) for calls in mocked.requests.values()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get", "get_json", "get_bytes", "post_json", "post_form"])
async def test_all_methods_enforce_cap_and_disable_redirects(method):
    with aioresponses() as mocked:
        register = mocked.post if method.startswith("post") else mocked.get
        register(
            "https://example.com/start",
            status=302,
            headers={"Location": "https://example.com/hidden"},
        )
        mocked.get("https://example.com/hidden", payload={"secret": "not fetched"})
        async with HTTPClient(max_requests=1) as client:
            fn = getattr(client, method)
            args = (
                ("https://example.com/start", {})
                if method.startswith("post")
                else ("https://example.com/start",)
            )
            response = await fn(*args)
            assert response[0] == 302
            with pytest.raises(RequestBudgetExceeded):
                await fn(*args)
        assert sum(len(calls) for calls in mocked.requests.values()) == 1


@pytest.mark.asyncio
async def test_secondary_transport_cannot_escape_budget(monkeypatch):
    from unittest.mock import AsyncMock

    fallback = AsyncMock()
    monkeypatch.setattr("core.http_client._try_scrapling_get", fallback)
    monkeypatch.setattr("core.http_client._should_retry_scrapling", lambda *args: True)
    with aioresponses() as mocked:
        mocked.get("https://example.com/profile", status=403)
        async with HTTPClient(max_requests=1) as client:
            await client.get("https://example.com/profile")
    fallback.assert_not_awaited()


@pytest.mark.asyncio
async def test_pivot_engine_respects_platform_scope_and_wire_cap():
    from core.engine import run_scan
    from core.investigation import pivot_config

    with aioresponses() as mocked:
        mocked.get("https://api.github.com/users/alice", payload={"login": "alice"})
        mocked.get(
            "https://gitlab.com/api/v4/users?username=alice", payload=[{"username": "alice"}]
        )
        result = await run_scan(pivot_config("alice", ["GitHub", "GitLab"], 1))
    assert {p.platform for p in result.platforms} <= {"GitHub", "GitLab"}
    assert result.diagnostics["http_budget"] == {"limit": 1, "request_count": 1, "exhausted": True}
    assert result.identity_candidates == []
