"""Tests for the Wigle.net BSSID/SSID lookup."""

from __future__ import annotations

import base64
import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.passive import wigle
from modules.passive.wigle import _basic_auth

# ── Pure helpers ────────────────────────────────────────────────────


def test_basic_auth_encodes_name_and_token() -> None:
    header = _basic_auth("AID-name", "abc123")
    expected = "Basic " + base64.b64encode(b"AID-name:abc123").decode()
    assert header == expected


def test_basic_auth_handles_unicode() -> None:
    header = _basic_auth("user", "p@ss/w0rd")
    assert header.startswith("Basic ")


# ── BSSID lookup ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_bssid_skips_without_creds(monkeypatch) -> None:
    monkeypatch.delenv("WIGLE_API_NAME", raising=False)
    monkeypatch.delenv("WIGLE_API_TOKEN", raising=False)
    async with HTTPClient() as client:
        assert await wigle.lookup_bssid(client, "AA:BB:CC:DD:EE:FF") == []


@pytest.mark.asyncio
async def test_lookup_bssid_skips_with_only_one_cred(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.delenv("WIGLE_API_TOKEN", raising=False)
    async with HTTPClient() as client:
        assert await wigle.lookup_bssid(client, "AA:BB:CC:DD:EE:FF") == []


@pytest.mark.asyncio
async def test_lookup_bssid_skips_empty_input(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    async with HTTPClient() as client:
        assert await wigle.lookup_bssid(client, "") == []


@pytest.mark.asyncio
async def test_lookup_bssid_parses_results(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "totalResults": 1,
        "results": [
            {
                "netid": "AA:BB:CC:DD:EE:FF",
                "ssid": "ACME-WiFi",
                "trilat": 40.7128,
                "trilong": -74.0060,
                "lastupdt": "2024-01-15T00:00:00.000Z",
                "country": "US",
                "region": "NY",
                "city": "New York",
                "road": "Broadway",
                "housenumber": "1234",
                "postalcode": "10001",
                "encryption": "wpa2",
                "channel": 6,
                "qos": 5,
            }
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wigle.lookup_bssid(client, "AA:BB:CC:DD:EE:FF")
    assert len(hits) == 1
    h = hits[0]
    assert h.source == "wigle"
    assert h.kind == "bssid"
    assert h.value == "AA:BB:CC:DD:EE:FF"
    assert h.title == "ACME-WiFi"
    assert h.metadata["lat"] == 40.7128
    assert h.metadata["lon"] == -74.0060
    assert h.metadata["country"] == "US"
    assert h.metadata["city"] == "New York"
    assert h.metadata["address"] == "1234 Broadway, New York NY 10001, US"
    assert h.metadata["encryption"] == "wpa2"
    assert h.metadata["channel"] == 6


@pytest.mark.asyncio
async def test_lookup_bssid_handles_partial_address(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "results": [
            {
                "netid": "11:22:33:44:55:66",
                "ssid": "X",
                "trilat": 51.5,
                "trilong": -0.1,
                "country": "GB",
                # no city/road — make sure we don't crash building "address"
            }
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wigle.lookup_bssid(client, "11:22:33:44:55:66")
    assert len(hits) == 1
    assert "address" in hits[0].metadata


@pytest.mark.asyncio
async def test_lookup_bssid_returns_empty_on_failed_status(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), status=401)
        async with HTTPClient() as client:
            assert await wigle.lookup_bssid(client, "AA:BB:CC:DD:EE:FF") == []


@pytest.mark.asyncio
async def test_lookup_bssid_returns_empty_on_unsuccessful_payload(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.wigle\.net/.*"),
            payload={"success": False, "message": "rate limit"},
        )
        async with HTTPClient() as client:
            assert await wigle.lookup_bssid(client, "AA:BB:CC:DD:EE:FF") == []


# ── SSID lookup ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_ssid_skips_without_creds(monkeypatch) -> None:
    monkeypatch.delenv("WIGLE_API_NAME", raising=False)
    monkeypatch.delenv("WIGLE_API_TOKEN", raising=False)
    async with HTTPClient() as client:
        assert await wigle.lookup_ssid(client, "ACME-Guest") == []


@pytest.mark.asyncio
async def test_lookup_ssid_parses_multiple_results(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "results": [
            {
                "netid": "AA:AA:AA:AA:AA:AA",
                "ssid": "ACME-Guest",
                "trilat": 40.0,
                "trilong": -74.0,
                "country": "US",
                "city": "Trenton",
            },
            {
                "netid": "BB:BB:BB:BB:BB:BB",
                "ssid": "ACME-Guest",
                "trilat": 40.5,
                "trilong": -74.5,
                "country": "US",
                "city": "Princeton",
            },
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wigle.lookup_ssid(client, "ACME-Guest")
    assert len(hits) == 2
    assert all(h.kind == "ssid" for h in hits)
    assert all(h.value == "ACME-Guest" for h in hits)
    bssids = {h.metadata["bssid"] for h in hits}
    assert bssids == {"AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"}


@pytest.mark.asyncio
async def test_lookup_ssid_respects_limit(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "results": [
            {"netid": f"AA:AA:AA:AA:AA:{i:02x}", "ssid": "X", "trilat": 0, "trilong": 0}
            for i in range(20)
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wigle.lookup_ssid(client, "X", limit=5)
    assert len(hits) == 5


# ── Top-level dispatch ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_dispatches_to_bssid_when_bssid_given(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "results": [
            {"netid": "AA:BB:CC:DD:EE:FF", "ssid": "X", "trilat": 0, "trilong": 0}
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wigle.search(client, bssid="AA:BB:CC:DD:EE:FF")
    assert len(hits) == 1
    assert hits[0].kind == "bssid"


@pytest.mark.asyncio
async def test_search_dispatches_to_ssid_when_ssid_given(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "results": [
            {"netid": "AA:BB:CC:DD:EE:FF", "ssid": "ACME", "trilat": 0, "trilong": 0}
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await wigle.search(client, ssid="ACME")
    assert len(hits) == 1
    assert hits[0].kind == "ssid"


@pytest.mark.asyncio
async def test_search_without_inputs_is_noop(monkeypatch) -> None:
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    async with HTTPClient() as client:
        assert await wigle.search(client) == []


@pytest.mark.asyncio
async def test_search_runs_both_when_both_given(monkeypatch) -> None:
    """Caller passes both BSSID and SSID → we run both lookups and merge."""
    monkeypatch.setenv("WIGLE_API_NAME", "AID-foo")
    monkeypatch.setenv("WIGLE_API_TOKEN", "tok")
    payload = {
        "success": True,
        "results": [
            {"netid": "AA:BB:CC:DD:EE:FF", "ssid": "ACME", "trilat": 1, "trilong": 2}
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.wigle\.net/.*"), payload=payload, repeat=True)
        async with HTTPClient() as client:
            hits = await wigle.search(
                client, bssid="AA:BB:CC:DD:EE:FF", ssid="ACME"
            )
    kinds = {h.kind for h in hits}
    assert kinds == {"bssid", "ssid"}
