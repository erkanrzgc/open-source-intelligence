"""Tests for the Sprint 2 passive-intel sources."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.passive import ahmia, censys, fofa, harvester, pastebin, shodan, wayback, zoomeye
from modules.passive.models import PassiveHit
from modules.passive.orchestrator import _dedupe, run_passive

# ── PassiveHit / dedupe ─────────────────────────────────────────────


def test_passive_hit_to_dict_is_json_safe() -> None:
    hit = PassiveHit(
        source="shodan", kind="host", value="1.2.3.4",
        title="host1", metadata={"port": 443},
    )
    d = hit.to_dict()
    assert d == {
        "source": "shodan", "kind": "host", "value": "1.2.3.4",
        "title": "host1", "metadata": {"port": 443},
    }


def test_dedupe_collapses_same_kind_value_case_insensitive() -> None:
    hits = [
        PassiveHit("shodan", "host", "1.2.3.4"),
        PassiveHit("censys", "host", "1.2.3.4"),
        PassiveHit("fofa", "host", "5.6.7.8"),
        PassiveHit("harvester", "subdomain", "mail.example.com"),
        PassiveHit("harvester", "subdomain", "MAIL.EXAMPLE.COM"),
    ]
    out = _dedupe(hits)
    assert len(out) == 3
    assert out[0].source == "shodan"
    assert out[2].value == "mail.example.com"


# ── Shodan ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_shodan_search_returns_empty_without_key(monkeypatch) -> None:
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    async with HTTPClient() as client:
        assert await shodan.search(client, "example.com") == []


@pytest.mark.asyncio
async def test_shodan_search_parses_matches(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "fake")
    payload = {
        "matches": [
            {
                "ip_str": "1.2.3.4", "port": 443,
                "hostnames": ["a.example.com"], "org": "Acme",
                "location": {"country_name": "NL"}, "product": "nginx",
            }
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.shodan\.io/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await shodan.search(client, "example.com")
    assert len(hits) == 1
    assert hits[0].value == "1.2.3.4"
    assert hits[0].metadata["org"] == "Acme"
    assert hits[0].metadata["country"] == "NL"


# ── Censys ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_censys_skips_without_credentials(monkeypatch) -> None:
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    async with HTTPClient() as client:
        assert await censys.search(client, "example.com") == []


@pytest.mark.asyncio
async def test_censys_parses_hits(monkeypatch) -> None:
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    payload = {
        "result": {
            "hits": [
                {
                    "ip": "9.9.9.9",
                    "name": "edge.example.com",
                    "autonomous_system": {"name": "Example ISP"},
                    "location": {"country": "US"},
                    "services": [{"port": 443, "service_name": "HTTPS"}],
                }
            ]
        }
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://search\.censys\.io/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await censys.search(client, "example.com")
    assert len(hits) == 1
    assert hits[0].metadata["ports"] == [443]
    assert hits[0].metadata["services"] == ["HTTPS"]


# ── FOFA ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fofa_parses_rows(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_EMAIL", "a@b")
    monkeypatch.setenv("FOFA_KEY", "k")
    payload = {
        "error": False,
        "results": [
            ["1.1.1.1", "80", "a.example.com", "Welcome", "US"],
            ["2.2.2.2", "443", "b.example.com", "Login", "NL"],
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://fofa\.info/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await fofa.search(client, "example.com")
    assert [h.value for h in hits] == ["1.1.1.1", "2.2.2.2"]
    assert hits[0].metadata["country"] == "US"


@pytest.mark.asyncio
async def test_fofa_skips_without_creds(monkeypatch) -> None:
    monkeypatch.delenv("FOFA_EMAIL", raising=False)
    monkeypatch.delenv("FOFA_KEY", raising=False)
    async with HTTPClient() as client:
        assert await fofa.search(client, "example.com") == []


# ── ZoomEye ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zoomeye_parses_matches(monkeypatch) -> None:
    monkeypatch.setenv("ZOOMEYE_API_KEY", "z")
    payload = {
        "matches": [
            {
                "ip": "3.3.3.3",
                "portinfo": {"port": 8080, "service": "http", "hostname": "x.example.com"},
                "geoinfo": {"country": {"names": {"en": "DE"}}, "city": {"names": {"en": "Berlin"}}},
            }
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.zoomeye\.org/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await zoomeye.search(client, "example.com")
    assert hits[0].value == "3.3.3.3"
    assert hits[0].metadata["country"] == "DE"
    assert hits[0].metadata["city"] == "Berlin"


# ── Pastebin (psbdmp) ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pastebin_search_parses_data() -> None:
    payload = {
        "data": [
            {"id": "abc123", "length": 400, "date": "2024-01-01", "tags": "creds"},
            {"id": "def456", "length": 120, "date": "2024-02-01"},
        ]
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://psbdmp\.ws/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await pastebin.search(client, "alice")
    assert [h.metadata["id"] for h in hits] == ["abc123", "def456"]
    assert hits[0].value == "https://pastebin.com/abc123"


@pytest.mark.asyncio
async def test_pastebin_empty_query_is_noop() -> None:
    async with HTTPClient() as client:
        assert await pastebin.search(client, "") == []


# ── Ahmia ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ahmia_extracts_onion_links() -> None:
    html = (
        '<ul>'
        '<li class="result">'
        '<h4><a href="/search/redirect?search_term=x&amp;'
        'redirect_url=http%3A%2F%2Fabcdefghijklmnop.onion%2Fpath">Secret Forum</a></h4>'
        '<p>Hidden service description</p>'
        '</li>'
        '<li class="result">'
        '<h4><a href="http://qrstuvwxyz234567.onion/">Another</a></h4>'
        '<p>More stuff</p>'
        '</li>'
        '</ul>'
    )
    with aioresponses() as m:
        m.get(re.compile(r"https://ahmia\.fi/.*"), body=html)
        async with HTTPClient() as client:
            hits = await ahmia.search(client, "alice")
    assert len(hits) == 2
    assert hits[0].kind == "onion"
    assert "abcdefghijklmnop.onion" in hits[0].value
    assert hits[1].title == "Another"


# ── Harvester ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_harvester_combines_hackertarget_and_threatcrowd() -> None:
    ht_body = "a.example.com,1.1.1.1\nb.example.com,2.2.2.2\nerror: nothing found"
    tc_payload = {
        "subdomains": ["c.example.com", ""],
        "emails": ["admin@example.com", "not-an-email"],
    }
    with aioresponses() as m:
        # hackertarget returns plain text; we need body=..., so mock it below.
        # But the second call we want a JSON response — put both in the mock.
        m.get(re.compile(r"https://api\.hackertarget\.com/.*"), body=ht_body)
        m.get(re.compile(r"https://www\.threatcrowd\.org/.*"), payload=tc_payload)
        async with HTTPClient() as client:
            hits = await harvester.search(client, "example.com")
    kinds = {(h.kind, h.value) for h in hits}
    # hackertarget body includes an "error" line => module should skip it entirely
    assert ("subdomain", "a.example.com") not in kinds
    assert ("subdomain", "c.example.com") in kinds
    assert ("email", "admin@example.com") in kinds
    assert ("email", "not-an-email") not in kinds


@pytest.mark.asyncio
async def test_harvester_hackertarget_clean_body() -> None:
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.hackertarget\.com/.*"),
            body="a.example.com,1.1.1.1\nb.example.com,2.2.2.2\n",
        )
        m.get(re.compile(r"https://www\.threatcrowd\.org/.*"), payload={})
        async with HTTPClient() as client:
            hits = await harvester.search(client, "example.com")
    subs = {h.value for h in hits if h.kind == "subdomain"}
    assert subs == {"a.example.com", "b.example.com"}


# ── Wayback ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wayback_snapshots_for_url_parses_cdx() -> None:
    payload = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["com,example)/", "20200101000000", "https://example.com/", "text/html", "200", "abc", "100"],
        ["com,example)/", "20210102030405", "https://example.com/", "text/html", "200", "def", "200"],
    ]
    with aioresponses() as m:
        m.get(re.compile(r"https://web\.archive\.org/cdx/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wayback.snapshots_for_url(client, "https://example.com/")
    assert len(hits) == 2
    assert hits[0].value.startswith("https://web.archive.org/web/20200101")
    assert hits[1].metadata["timestamp"] == "20210102030405"


@pytest.mark.asyncio
async def test_wayback_empty_cdx_returns_empty() -> None:
    with aioresponses() as m:
        m.get(re.compile(r"https://web\.archive\.org/cdx/.*"), payload=[])
        async with HTTPClient() as client:
            assert await wayback.snapshots_for_url(client, "https://example.com/") == []


# ── Orchestrator ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_passive_without_anything_is_empty(monkeypatch) -> None:
    for var in ("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                "FOFA_EMAIL", "FOFA_KEY", "ZOOMEYE_API_KEY", "SERPAPI_API_KEY",
                "CRIMINALIP_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    async with HTTPClient() as client:
        hits = await run_passive(client, username="", domain=None)
    assert hits == []


@pytest.mark.asyncio
async def test_run_passive_includes_google_dork_via_ddg_fallback(monkeypatch) -> None:
    for var in ("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                "FOFA_EMAIL", "FOFA_KEY", "ZOOMEYE_API_KEY", "SERPAPI_API_KEY",
                "CRIMINALIP_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    ddg_html = (
        '<div class="result">'
        '<a class="result__a" href="https://leak.example.com/x">Leaked</a>'
        '<a class="result__snippet" href="#">contains password</a>'
        '</div>'
    )
    with aioresponses() as m:
        m.get(re.compile(r"https://html\.duckduckgo\.com/.*"), body=ddg_html, repeat=True)
        m.get(re.compile(r"https://api\.hackertarget\.com/.*"), body="")
        m.get(re.compile(r"https://www\.threatcrowd\.org/.*"), payload={})
        m.get(re.compile(r"https://web\.archive\.org/cdx/.*"), payload=[])
        m.get(re.compile(r"https://psbdmp\.ws/.*"), payload={"data": []})
        m.get(re.compile(r"https://ahmia\.fi/.*"), body="")
        async with HTTPClient() as client:
            hits = await run_passive(
                client, username="alice", domain="example.com"
            )

    dork_hits = [h for h in hits if h.source == "google_dork"]
    assert dork_hits, "expected google_dork hits via DDG fallback"
    assert dork_hits[0].metadata["provider"] == "ddg"


@pytest.mark.asyncio
async def test_run_passive_includes_criminalip_when_key_set(monkeypatch) -> None:
    for var in ("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                "FOFA_EMAIL", "FOFA_KEY", "ZOOMEYE_API_KEY", "SERPAPI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CRIMINALIP_API_KEY", "k")

    cip_payload = {
        "status": 200,
        "data": {
            "ip_data": [
                {"ip_address": "7.7.7.7", "country_code": "JP",
                 "as_name": "ISP J", "open_port_no": 443,
                 "score": {"inbound": 5, "outbound": 1}},
            ]
        },
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.criminalip\.io/.*"), payload=cip_payload)
        m.get(re.compile(r"https://html\.duckduckgo\.com/.*"), body="")
        m.get(re.compile(r"https://api\.hackertarget\.com/.*"), body="")
        m.get(re.compile(r"https://www\.threatcrowd\.org/.*"), payload={})
        m.get(re.compile(r"https://web\.archive\.org/cdx/.*"), payload=[])
        m.get(re.compile(r"https://psbdmp\.ws/.*"), payload={"data": []})
        m.get(re.compile(r"https://ahmia\.fi/.*"), body="")
        async with HTTPClient() as client:
            hits = await run_passive(client, username="alice", domain="example.com")

    cip_hits = [h for h in hits if h.source == "criminalip"]
    assert cip_hits, "expected criminalip hits when key is set"
    assert cip_hits[0].metadata["score_inbound"] == 5


@pytest.mark.asyncio
async def test_run_passive_fan_out_merges_and_dedupes(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    for var in ("CENSYS_API_ID", "CENSYS_API_SECRET", "FOFA_EMAIL", "FOFA_KEY",
                "ZOOMEYE_API_KEY", "CRIMINALIP_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    shodan_payload = {
        "matches": [
            {"ip_str": "1.2.3.4", "port": 80, "hostnames": ["a"], "org": "o",
             "location": {"country_name": "NL"}},
        ]
    }
    ht_body = "dup.example.com,1.2.3.4\n"
    tc_payload = {"subdomains": ["dup.example.com"], "emails": ["a@example.com"]}

    with aioresponses() as m:
        m.get(re.compile(r"https://api\.shodan\.io/.*"), payload=shodan_payload)
        m.get(re.compile(r"https://api\.hackertarget\.com/.*"), body=ht_body)
        m.get(re.compile(r"https://www\.threatcrowd\.org/.*"), payload=tc_payload)
        m.get(re.compile(r"https://web\.archive\.org/cdx/.*"), payload=[])
        m.get(re.compile(r"https://psbdmp\.ws/.*"), payload={"data": []})
        m.get(re.compile(r"https://ahmia\.fi/.*"), body="")
        async with HTTPClient() as client:
            hits = await run_passive(
                client, username="alice", domain="example.com"
            )

    kinds = {(h.kind, h.value) for h in hits}
    assert ("host", "1.2.3.4") in kinds
    assert ("subdomain", "dup.example.com") in kinds  # deduped across sources
    assert ("email", "a@example.com") in kinds
    # first subdomain entry wins
    sub_hits = [h for h in hits if h.kind == "subdomain"]
    assert len(sub_hits) == 1
