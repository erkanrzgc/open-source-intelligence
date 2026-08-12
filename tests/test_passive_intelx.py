"""Tests for the Intelligence X paste / leak / dark-web index lookup.

IntelX uses a two-step search:

1. POST ``/intelligent/search`` returns a search ``id`` and a status
   code (0 = accepted, anything else = error).
2. GET ``/intelligent/search/result?id=<id>`` returns ``{records,
   status}`` where status 3 means "more results may arrive, poll
   again" and status 0 means "done".

We exercise both the fast-path (POST then a single GET with status 0)
and the poll path (GET returns status 3 once, then status 0).
"""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.passive import intelx

# ── Pure helpers ────────────────────────────────────────────────────


def test_record_to_hit_skips_records_without_name() -> None:
    assert intelx._record_to_hit({"name": "", "bucket": "x"}) is None
    assert intelx._record_to_hit({"bucket": "x"}) is None


def test_record_to_hit_builds_passive_hit() -> None:
    hit = intelx._record_to_hit(
        {
            "name": "https://pastebin.com/abc123",
            "systemid": "sys-1",
            "storageid": "stor-1",
            "date": "2024-01-15T00:00:00Z",
            "size": 1024,
            "bucket": "pastes.public",
            "type": 0,
            "accesslevel": 0,
        }
    )
    assert hit is not None
    assert hit.source == "intelx"
    assert hit.kind == "leak"
    assert hit.value == "https://pastebin.com/abc123"
    assert hit.title == "pastes.public"
    assert hit.metadata["systemid"] == "sys-1"
    assert hit.metadata["bucket"] == "pastes.public"
    assert hit.metadata["size"] == 1024


# ── search() — auth + input guards ─────────────────────────────────


@pytest.mark.asyncio
async def test_search_skips_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("INTELX_API_KEY", raising=False)
    async with HTTPClient() as client:
        assert await intelx.search(client, "acme.com") == []


@pytest.mark.asyncio
async def test_search_skips_blank_term(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    async with HTTPClient() as client:
        assert await intelx.search(client, "") == []
        assert await intelx.search(client, "   ") == []


# ── search() — happy path ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_post_then_get_parses_records(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    post_payload = {"id": "abc-123", "status": 0}
    get_payload = {
        "status": 0,
        "records": [
            {
                "name": "https://pastebin.com/aaaaaa",
                "systemid": "s1",
                "storageid": "st1",
                "date": "2024-01-01T00:00:00Z",
                "size": 800,
                "bucket": "pastes.public",
                "type": 0,
            },
            {
                "name": "leak-2024-acme.txt",
                "systemid": "s2",
                "storageid": "st2",
                "date": "2024-02-01T00:00:00Z",
                "size": 4096,
                "bucket": "leaks.private",
                "type": 1,
            },
        ],
    }
    with aioresponses() as m:
        m.post(re.compile(r"https://2\.intelx\.io/.*"), payload=post_payload)
        m.get(re.compile(r"https://2\.intelx\.io/.*"), payload=get_payload)
        async with HTTPClient() as client:
            hits = await intelx.search(client, "acme.com")
    assert len(hits) == 2
    assert {h.value for h in hits} == {
        "https://pastebin.com/aaaaaa",
        "leak-2024-acme.txt",
    }
    assert all(h.source == "intelx" for h in hits)
    assert all(h.kind == "leak" for h in hits)


# ── search() — error paths ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_returns_empty_when_post_status_nonzero(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    with aioresponses() as m:
        m.post(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"id": "", "status": 2},  # 2 = fail
        )
        async with HTTPClient() as client:
            hits = await intelx.search(client, "acme.com")
    assert hits == []


@pytest.mark.asyncio
async def test_search_returns_empty_when_post_returns_no_id(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    with aioresponses() as m:
        m.post(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"status": 0},  # missing id
        )
        async with HTTPClient() as client:
            assert await intelx.search(client, "acme.com") == []


@pytest.mark.asyncio
async def test_search_returns_empty_on_post_http_error(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    with aioresponses() as m:
        m.post(re.compile(r"https://2\.intelx\.io/.*"), status=401)
        async with HTTPClient() as client:
            assert await intelx.search(client, "acme.com") == []


@pytest.mark.asyncio
async def test_search_returns_empty_on_get_http_error(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    with aioresponses() as m:
        m.post(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"id": "abc", "status": 0},
        )
        m.get(re.compile(r"https://2\.intelx\.io/.*"), status=500)
        async with HTTPClient() as client:
            assert await intelx.search(client, "acme.com") == []


# ── search() — polling path ────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_polls_when_first_get_status_is_pending(monkeypatch) -> None:
    """status=3 means 'more data may arrive'; we should poll once more."""
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    monkeypatch.setattr(intelx, "_POLL_DELAY_SEC", 0)  # speed up the test

    with aioresponses() as m:
        m.post(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"id": "abc", "status": 0},
        )
        # First poll: still running (status 3, no records yet)
        m.get(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"status": 3, "records": []},
        )
        # Second poll: done with results
        m.get(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={
                "status": 0,
                "records": [
                    {
                        "name": "late-result.txt",
                        "systemid": "s",
                        "storageid": "st",
                        "date": "2024-01-01T00:00:00Z",
                        "size": 100,
                        "bucket": "leaks",
                    }
                ],
            },
        )
        async with HTTPClient() as client:
            hits = await intelx.search(client, "acme.com")
    assert len(hits) == 1
    assert hits[0].value == "late-result.txt"


@pytest.mark.asyncio
async def test_search_gives_up_after_max_polls(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    monkeypatch.setattr(intelx, "_POLL_DELAY_SEC", 0)
    monkeypatch.setattr(intelx, "_MAX_POLLS", 2)

    with aioresponses() as m:
        m.post(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"id": "abc", "status": 0},
        )
        # Always pending; module should bail out after _MAX_POLLS attempts
        m.get(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"status": 3, "records": []},
            repeat=True,
        )
        async with HTTPClient() as client:
            hits = await intelx.search(client, "acme.com")
    assert hits == []


# ── search() — limit ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_honors_max_results(monkeypatch) -> None:
    monkeypatch.setenv("INTELX_API_KEY", "fake")
    records = [
        {
            "name": f"hit-{i}",
            "systemid": f"s{i}",
            "storageid": f"st{i}",
            "date": "2024-01-01T00:00:00Z",
            "size": 100,
            "bucket": "leaks",
        }
        for i in range(20)
    ]
    with aioresponses() as m:
        m.post(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"id": "abc", "status": 0},
        )
        m.get(
            re.compile(r"https://2\.intelx\.io/.*"),
            payload={"status": 0, "records": records},
        )
        async with HTTPClient() as client:
            hits = await intelx.search(client, "acme.com", max_results=5)
    assert len(hits) == 5
