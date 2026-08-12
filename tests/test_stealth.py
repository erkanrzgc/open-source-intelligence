"""Tests for the Sprint 1 stealth/OPSEC primitives."""

from __future__ import annotations

import asyncio

import pytest

from modules.stealth import DomainRateBucket, fingerprint_headers, pick_ua, ua_family
from modules.stealth.rate_limit import DomainRateBucket as Bucket
from modules.stealth.tor_control import CircuitRotator
from modules.stealth.user_agents import _POOL, UAEntry, pool_size

# ── user_agents ─────────────────────────────────────────────────────


def test_pool_is_non_empty_and_every_entry_is_well_formed() -> None:
    assert pool_size() >= 10
    for entry in _POOL:
        assert isinstance(entry, UAEntry)
        assert entry.ua.startswith("Mozilla/5.0")
        assert entry.family in ("chrome", "firefox", "safari", "edge")
        assert entry.major > 0


def test_pick_ua_returns_a_valid_entry() -> None:
    entry = pick_ua()
    assert entry in _POOL


def test_pick_ua_desktop_only_excludes_mobile() -> None:
    for _ in range(50):
        entry = pick_ua(desktop_only=True)
        assert entry.platform not in ("Android", "iOS")


def test_ua_family_detects_edge_before_chrome() -> None:
    edge_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"
    )
    assert ua_family(edge_ua) == "edge"


def test_ua_family_detects_firefox_and_safari() -> None:
    assert ua_family("Mozilla/5.0 ... Firefox/131.0") == "firefox"
    safari_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
    )
    assert ua_family(safari_ua) == "safari"


# ── fingerprint headers ─────────────────────────────────────────────


def test_fingerprint_headers_always_include_core_fields() -> None:
    headers = fingerprint_headers(pick_ua())
    required = {
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
    }
    assert required <= headers.keys()


def test_fingerprint_adds_ch_ua_only_for_chromium_family() -> None:
    chrome_entry = next(u for u in _POOL if u.family == "chrome")
    firefox_entry = next(u for u in _POOL if u.family == "firefox")
    safari_entry = next(u for u in _POOL if u.family == "safari")
    edge_entry = next(u for u in _POOL if u.family == "edge")

    chrome_h = fingerprint_headers(chrome_entry)
    edge_h = fingerprint_headers(edge_entry)
    firefox_h = fingerprint_headers(firefox_entry)
    safari_h = fingerprint_headers(safari_entry)

    assert "sec-ch-ua" in chrome_h
    assert "Chromium" in chrome_h["sec-ch-ua"]
    assert "Google Chrome" in chrome_h["sec-ch-ua"]

    assert "sec-ch-ua" in edge_h
    assert "Microsoft Edge" in edge_h["sec-ch-ua"]

    assert "sec-ch-ua" not in firefox_h
    assert "sec-ch-ua" not in safari_h


def test_fingerprint_mobile_flag_matches_platform() -> None:
    mobile = next(u for u in _POOL if u.platform in ("Android", "iOS") and u.family == "chrome")
    desktop = next(u for u in _POOL if u.platform == "Windows" and u.family == "chrome")
    assert fingerprint_headers(mobile)["sec-ch-ua-mobile"] == "?1"
    assert fingerprint_headers(desktop)["sec-ch-ua-mobile"] == "?0"


def test_fingerprint_referer_switches_fetch_site() -> None:
    entry = pick_ua()
    without = fingerprint_headers(entry)
    with_ref = fingerprint_headers(entry, referer="https://example.com/")
    assert without["Sec-Fetch-Site"] == "none"
    assert with_ref["Sec-Fetch-Site"] == "cross-site"
    assert with_ref["Referer"] == "https://example.com/"


# ── rate limiter ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_bucket_spaces_consecutive_acquires() -> None:
    bucket = Bucket(min_interval=0.2, jitter=0.0)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await bucket.acquire("example.com")
    await bucket.acquire("example.com")
    elapsed = loop.time() - t0
    assert elapsed >= 0.18  # allow tiny slack


@pytest.mark.asyncio
async def test_rate_bucket_independent_per_host() -> None:
    bucket = Bucket(min_interval=0.5, jitter=0.0)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await bucket.acquire("a.example")
    await bucket.acquire("b.example")
    elapsed = loop.time() - t0
    assert elapsed < 0.3  # second host should not wait


@pytest.mark.asyncio
async def test_rate_bucket_records_throttle_increases_penalty() -> None:
    bucket = Bucket(min_interval=0.0, jitter=0.0, max_penalty=30.0)
    await bucket.record_throttled("slow.example")
    snap1 = bucket.snapshot()["slow.example"]
    await bucket.record_throttled("slow.example")
    snap2 = bucket.snapshot()["slow.example"]
    assert snap2 >= snap1
    assert snap1 >= 2.0


@pytest.mark.asyncio
async def test_rate_bucket_retry_after_is_honored() -> None:
    bucket = Bucket(min_interval=0.0, jitter=0.0, max_penalty=60.0)
    await bucket.record_throttled("x.example", retry_after=7.0)
    assert bucket.snapshot()["x.example"] == 7.0


@pytest.mark.asyncio
async def test_rate_bucket_success_decays_penalty() -> None:
    bucket = Bucket(min_interval=0.0, jitter=0.0)
    await bucket.record_throttled("y.example", retry_after=4.0)
    await bucket.record_success("y.example")
    assert bucket.snapshot()["y.example"] < 4.0


# ── Tor circuit rotator ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_circuit_rotator_only_fires_on_threshold(monkeypatch) -> None:
    calls: list[tuple[str, int]] = []

    async def fake_rotate(**kwargs):
        calls.append((kwargs.get("host", ""), kwargs.get("control_port", 0)))
        return True

    import modules.stealth.tor_control as tc

    monkeypatch.setattr(tc, "rotate_circuit", fake_rotate)

    rot = CircuitRotator(every=3)
    assert await rot.tick() is False
    assert await rot.tick() is False
    assert await rot.tick() is True
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_circuit_rotator_resets_counter_between_rotations(monkeypatch) -> None:
    async def fake_rotate(**_kwargs):
        return True

    import modules.stealth.tor_control as tc

    monkeypatch.setattr(tc, "rotate_circuit", fake_rotate)

    rot = CircuitRotator(every=2)
    assert await rot.tick() is False
    assert await rot.tick() is True
    assert await rot.tick() is False
    assert await rot.tick() is True


# ── HTTPClient integration ──────────────────────────────────────────


def test_default_bucket_is_created_when_not_injected() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient()
    assert isinstance(client._rate_bucket, DomainRateBucket)
    assert client._fingerprint is True


def test_headers_use_fingerprint_when_enabled() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient(fingerprint=True)
    headers = client._headers()
    assert "Sec-Fetch-Dest" in headers
    assert "User-Agent" in headers


def test_headers_fall_back_to_legacy_when_fingerprint_disabled() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient(fingerprint=False)
    headers = client._headers()
    assert "Sec-Fetch-Dest" not in headers
    assert headers["User-Agent"].startswith("Mozilla/5.0")
