"""Tests for the Google Dork passive source.

We test:
- Provider chain (SerpAPI when key set, DDG HTML fallback otherwise)
- Preset dork expansion (`secrets`, `files`, `exposed`, `paste`, `subdomains`)
- Custom dork passthrough
- limit_per_dork honored
- Empty / malformed responses degrade gracefully
"""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.passive import google_dork
from modules.passive.google_dork import _build_dorks, _expand_presets

# ── Dork expansion (pure functions) ─────────────────────────────────


def test_expand_presets_unknown_preset_is_skipped() -> None:
    out = _expand_presets("example.com", ["secrets", "nonsense"])
    assert all(isinstance(d, str) for d in out)
    assert all("example.com" in d for d in out)
    assert out  # at least the secrets preset produced dorks


def test_expand_presets_secrets_targets_domain() -> None:
    dorks = _expand_presets("acme.io", ["secrets"])
    joined = " || ".join(dorks)
    assert "acme.io" in joined
    assert any(kw in joined.lower() for kw in ("password", "api_key", "secret"))


def test_expand_presets_files_includes_filetype_queries() -> None:
    dorks = _expand_presets("acme.io", ["files"])
    assert any("filetype:" in d for d in dorks)


def test_build_dorks_merges_presets_and_custom() -> None:
    dorks = _build_dorks(
        domain="acme.io",
        presets=["secrets"],
        custom_dorks=['intitle:"control panel" site:acme.io'],
    )
    assert 'intitle:"control panel" site:acme.io' in dorks
    assert any("acme.io" in d for d in dorks)


def test_build_dorks_default_presets_when_none_given() -> None:
    dorks = _build_dorks(domain="acme.io", presets=None, custom_dorks=None)
    # default preset set should produce at least a few dorks
    assert len(dorks) >= 3


# ── SerpAPI provider ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_serpapi_used_when_key_present(monkeypatch) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "fake")
    payload = {
        "organic_results": [
            {
                "title": "Internal wiki",
                "link": "https://wiki.example.com/secret",
                "snippet": "API_KEY=abcd1234",
            },
            {
                "title": "Forum post",
                "link": "https://forum.example.com/thread/1",
                "snippet": "user mentioned credentials",
            },
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://serpapi\.com/.*"), payload=payload, repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client,
                "example.com",
                presets=["secrets"],
                limit_per_dork=2,
            )
    assert hits, "expected at least one hit from SerpAPI"
    first = hits[0]
    assert first.source == "google_dork"
    assert first.kind == "dork"
    assert first.value.startswith("https://")
    assert "dork" in first.metadata
    assert first.metadata["provider"] == "serpapi"
    assert first.metadata.get("snippet")


@pytest.mark.asyncio
async def test_serpapi_respects_limit_per_dork(monkeypatch) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "fake")
    payload = {
        "organic_results": [
            {"title": f"r{i}", "link": f"https://x.example.com/{i}", "snippet": "s"}
            for i in range(20)
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://serpapi\.com/.*"), payload=payload, repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client,
                "example.com",
                presets=["secrets"],
                limit_per_dork=3,
            )
    # Each dork query is capped at 3 results
    by_dork: dict[str, int] = {}
    for h in hits:
        by_dork[h.metadata["dork"]] = by_dork.get(h.metadata["dork"], 0) + 1
    assert all(count <= 3 for count in by_dork.values())


@pytest.mark.asyncio
async def test_serpapi_malformed_response_yields_empty(monkeypatch) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "fake")
    with aioresponses() as m:
        m.get(re.compile(r"https://serpapi\.com/.*"), payload={"error": "quota"}, repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client, "example.com", presets=["secrets"]
            )
    assert hits == []


# ── DuckDuckGo HTML fallback ────────────────────────────────────────


@pytest.mark.asyncio
async def test_ddg_fallback_when_no_serpapi_key(monkeypatch) -> None:
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    html = """
    <div class="result">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fleak.example.com%2Fdoc&rut=x">Leaked doc</a>
      <a class="result__snippet" href="https://leak.example.com/doc">contains password=hunter2</a>
    </div>
    <div class="result">
      <a class="result__a" href="https://other.example.com/page">Plain link</a>
      <a class="result__snippet" href="#">snippet two</a>
    </div>
    """
    with aioresponses() as m:
        m.get(re.compile(r"https://html\.duckduckgo\.com/.*"), body=html, repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client,
                "example.com",
                presets=["secrets"],
                limit_per_dork=5,
            )
    assert hits, "DDG fallback should yield at least one hit"
    providers = {h.metadata["provider"] for h in hits}
    assert providers == {"ddg"}
    # DDG redirect URLs must be unwrapped
    values = {h.value for h in hits}
    assert "https://leak.example.com/doc" in values
    assert "https://other.example.com/page" in values
    # Snippet captured
    leak = next(h for h in hits if h.value == "https://leak.example.com/doc")
    assert "hunter2" in leak.metadata["snippet"]


@pytest.mark.asyncio
async def test_ddg_empty_html_returns_empty(monkeypatch) -> None:
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    with aioresponses() as m:
        m.get(re.compile(r"https://html\.duckduckgo\.com/.*"), body="", repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client, "example.com", presets=["secrets"]
            )
    assert hits == []


# ── Custom dorks ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_custom_dork_is_executed(monkeypatch) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "fake")
    payload = {
        "organic_results": [
            {"title": "match", "link": "https://hit.example.com/", "snippet": "found"},
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://serpapi\.com/.*"), payload=payload, repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client,
                "example.com",
                presets=[],  # disable presets, only run the custom dork
                custom_dorks=['inurl:"/admin" site:example.com'],
                limit_per_dork=5,
            )
    assert hits
    assert all(h.metadata["dork"] == 'inurl:"/admin" site:example.com' for h in hits)


# ── Empty domain guard ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_empty_domain_is_noop(monkeypatch) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "fake")
    async with HTTPClient() as client:
        assert await google_dork.search(client, "") == []


# ── Dedup within a single search call ───────────────────────────────


@pytest.mark.asyncio
async def test_duplicate_links_across_dorks_are_deduped(monkeypatch) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "fake")
    payload = {
        "organic_results": [
            {"title": "shared", "link": "https://same.example.com/p", "snippet": "s"},
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://serpapi\.com/.*"), payload=payload, repeat=True)
        async with HTTPClient() as client:
            hits = await google_dork.search(
                client,
                "example.com",
                presets=["secrets", "files"],
                limit_per_dork=5,
            )
    values = [h.value for h in hits]
    assert len(values) == len(set(values)), "duplicate URLs should be collapsed"
