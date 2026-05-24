"""Tests for modules/recon/crtsh.py — Certificate Transparency intelligence."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.recon import crtsh


def test_split_names_dedupes_and_lowercases() -> None:
    raw = "Acme.com\nwww.acme.com\nACME.com\n*.acme.com\n"
    out = crtsh._split_names(raw)

    assert out == ("acme.com", "www.acme.com", "*.acme.com")


def test_split_names_handles_empty() -> None:
    assert crtsh._split_names("") == ()
    assert crtsh._split_names("   \n  \n") == ()


def test_parse_entry_extracts_full_metadata() -> None:
    entry = {
        "id": 123456,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "api.acme.com",
        "name_value": "api.acme.com\nwww.api.acme.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "entry_timestamp": "2026-01-01T00:00:01",
        "serial_number": "0344",
    }

    rec = crtsh._parse_entry(entry)

    assert rec is not None
    assert rec.common_name == "api.acme.com"
    assert rec.issuer_name == "C=US, O=Let's Encrypt, CN=R3"
    assert rec.not_before == "2026-01-01T00:00:00"
    assert rec.not_after == "2026-04-01T00:00:00"
    assert rec.entry_timestamp == "2026-01-01T00:00:01"
    assert rec.serial_number == "0344"
    assert rec.crtsh_id == "123456"
    assert rec.url == "https://crt.sh/?id=123456"
    assert rec.name_value == ("api.acme.com", "www.api.acme.com")


def test_parse_entry_skips_records_without_hostname() -> None:
    assert crtsh._parse_entry({}) is None
    assert crtsh._parse_entry({"id": 1, "issuer_name": "x"}) is None


def test_parse_entry_rejects_non_dict() -> None:
    assert crtsh._parse_entry("not a dict") is None  # type: ignore[arg-type]
    assert crtsh._parse_entry(None) is None  # type: ignore[arg-type]


def test_dedupe_collapses_duplicate_serials() -> None:
    base = {
        "issuer_name": "Let's Encrypt R3",
        "common_name": "x.acme.com",
        "name_value": "x.acme.com",
        "not_before": "2026-01-01",
        "not_after": "2026-04-01",
        "entry_timestamp": "2026-01-01T00:00:01",
        "serial_number": "abcdef",
    }
    rec = crtsh._parse_entry({**base, "id": 1})
    dup = crtsh._parse_entry({**base, "id": 2})
    assert rec is not None and dup is not None

    out = crtsh._dedupe([rec, dup])

    assert len(out) == 1
    assert out[0].serial_number == "abcdef"


def test_dedupe_keeps_distinct_serials() -> None:
    a = crtsh._parse_entry(
        {
            "id": 1,
            "issuer_name": "Let's Encrypt",
            "common_name": "a.acme.com",
            "name_value": "a.acme.com",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
            "entry_timestamp": "2026-01-01",
            "serial_number": "aaaa",
        }
    )
    b = crtsh._parse_entry(
        {
            "id": 2,
            "issuer_name": "DigiCert",
            "common_name": "b.acme.com",
            "name_value": "b.acme.com",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
            "entry_timestamp": "2026-01-01",
            "serial_number": "bbbb",
        }
    )
    assert a is not None and b is not None

    assert len(crtsh._dedupe([a, b])) == 2


@pytest.mark.asyncio
async def test_fetch_returns_empty_for_blank_domain() -> None:
    async with HTTPClient() as client:
        assert await crtsh.fetch(client, "") == []
        assert await crtsh.fetch(client, "   ") == []


@pytest.mark.asyncio
async def test_fetch_returns_empty_on_non_200() -> None:
    with aioresponses() as m:
        m.get(
            "https://crt.sh/?q=%25.acme.com&output=json",
            status=503,
            body="overloaded",
        )
        async with HTTPClient() as client:
            assert await crtsh.fetch(client, "acme.com") == []


@pytest.mark.asyncio
async def test_fetch_returns_empty_when_payload_not_list() -> None:
    with aioresponses() as m:
        m.get(
            "https://crt.sh/?q=%25.acme.com&output=json",
            status=200,
            payload={"error": "rate limited"},
        )
        async with HTTPClient() as client:
            assert await crtsh.fetch(client, "acme.com") == []


@pytest.mark.asyncio
async def test_fetch_parses_dedupes_and_sorts_newest_first() -> None:
    payload = [
        {
            "id": 3,
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA",
            "common_name": "shop.acme.com",
            "name_value": "shop.acme.com\nwww.shop.acme.com",
            "not_before": "2025-06-01",
            "not_after": "2026-06-01",
            "entry_timestamp": "2025-06-01T00:00:00",
            "serial_number": "bbbb",
        },
        {
            "id": 1,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "api.acme.com",
            "name_value": "api.acme.com",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
            "entry_timestamp": "2026-01-01T10:00:00",
            "serial_number": "aaaa",
        },
        {
            "id": 2,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "api.acme.com",
            "name_value": "api.acme.com",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
            "entry_timestamp": "2026-01-01T11:00:00",
            "serial_number": "aaaa",
        },
    ]
    with aioresponses() as m:
        m.get(
            "https://crt.sh/?q=%25.acme.com&output=json",
            status=200,
            payload=payload,
        )
        async with HTTPClient() as client:
            records = await crtsh.fetch(client, "acme.com")

    assert len(records) == 2
    assert records[0].common_name == "api.acme.com"
    assert "DigiCert" in records[1].issuer_name
    assert "www.shop.acme.com" in records[1].name_value


@pytest.mark.asyncio
async def test_fetch_normalizes_input_domain() -> None:
    with aioresponses() as m:
        m.get(
            "https://crt.sh/?q=%25.acme.com&output=json",
            status=200,
            payload=[],
        )
        async with HTTPClient() as client:
            assert await crtsh.fetch(client, ".ACME.COM") == []
