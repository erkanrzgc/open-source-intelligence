"""Tests for the OpenCorporates corporate-records lookup."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.passive import opencorporates
from modules.recon.models import CompanyOfficer, CompanyRecord

# ── Pure parsing ────────────────────────────────────────────────────


def test_companyrecord_to_dict_roundtrips() -> None:
    rec = CompanyRecord(
        name="Acme Co",
        jurisdiction_code="us_de",
        company_number="12345",
        incorporation_date="2010-01-15",
        company_type="Corporation",
        registered_address="123 Main St, Wilmington, DE",
        status="active",
        url="https://opencorporates.com/companies/us_de/12345",
        officers=(
            CompanyOfficer(name="Alice Doe", position="director"),
            CompanyOfficer(name="Bob Roe", position="CEO", start_date="2020-01-01"),
        ),
    )
    d = rec.to_dict()
    assert d["name"] == "Acme Co"
    assert d["officers"][0]["name"] == "Alice Doe"
    assert d["officers"][1]["start_date"] == "2020-01-01"


# ── search() ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_returns_empty_for_blank_query() -> None:
    async with HTTPClient() as client:
        assert await opencorporates.search(client, "") == []
        assert await opencorporates.search(client, "   ") == []


@pytest.mark.asyncio
async def test_search_works_without_api_token(monkeypatch) -> None:
    """Free tier of OpenCorporates does not require auth."""
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    payload = {
        "results": {
            "companies": [
                {
                    "company": {
                        "name": "ACME CORP",
                        "company_number": "12345",
                        "jurisdiction_code": "us_de",
                        "incorporation_date": "2010-01-15",
                        "company_type": "Corporation",
                        "registered_address_in_full": "123 Main St, Wilmington, DE",
                        "current_status": "active",
                        "opencorporates_url": (
                            "https://opencorporates.com/companies/us_de/12345"
                        ),
                    }
                }
            ]
        }
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.opencorporates\.com/.*"), payload=payload)
        async with HTTPClient() as client:
            recs = await opencorporates.search(client, "Acme")
    assert len(recs) == 1
    rec = recs[0]
    assert isinstance(rec, CompanyRecord)
    assert rec.name == "ACME CORP"
    assert rec.jurisdiction_code == "us_de"
    assert rec.company_number == "12345"
    assert rec.status == "active"
    assert rec.url.endswith("/us_de/12345")


@pytest.mark.asyncio
async def test_search_honors_limit(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    payload = {
        "results": {
            "companies": [
                {
                    "company": {
                        "name": f"Company {i}",
                        "company_number": str(i),
                        "jurisdiction_code": "us_de",
                    }
                }
                for i in range(20)
            ]
        }
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.opencorporates\.com/.*"), payload=payload)
        async with HTTPClient() as client:
            recs = await opencorporates.search(client, "Company", limit=5)
    assert len(recs) == 5


@pytest.mark.asyncio
async def test_search_returns_empty_on_404(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.opencorporates\.com/.*"), status=404)
        async with HTTPClient() as client:
            assert await opencorporates.search(client, "Acme") == []


@pytest.mark.asyncio
async def test_search_returns_empty_on_malformed_payload(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.opencorporates\.com/.*"),
            payload={"unexpected": "shape"},
        )
        async with HTTPClient() as client:
            assert await opencorporates.search(client, "Acme") == []


@pytest.mark.asyncio
async def test_search_skips_rows_without_required_fields(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    payload = {
        "results": {
            "companies": [
                {"company": {"name": "Valid", "company_number": "1", "jurisdiction_code": "us_de"}},
                {"company": {"name": "", "company_number": "2", "jurisdiction_code": "us_de"}},
                {"company": {"name": "No-jurisdiction", "company_number": "3"}},
                {"not_a_company": "wat"},
                "scalar",
            ]
        }
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.opencorporates\.com/.*"), payload=payload)
        async with HTTPClient() as client:
            recs = await opencorporates.search(client, "x")
    assert len(recs) == 1
    assert recs[0].name == "Valid"


# ── get_company() ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_company_fetches_with_officers(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    payload = {
        "results": {
            "company": {
                "name": "ACME CORP",
                "company_number": "12345",
                "jurisdiction_code": "us_de",
                "incorporation_date": "2010-01-15",
                "company_type": "Corporation",
                "registered_address_in_full": "123 Main St, Wilmington, DE",
                "current_status": "active",
                "opencorporates_url": (
                    "https://opencorporates.com/companies/us_de/12345"
                ),
                "officers": [
                    {
                        "officer": {
                            "name": "Alice Doe",
                            "position": "director",
                            "start_date": "2015-03-01",
                            "end_date": None,
                        }
                    },
                    {
                        "officer": {
                            "name": "Bob Roe",
                            "position": "CEO",
                            "start_date": "2020-01-01",
                            "end_date": "2023-06-30",
                        }
                    },
                ],
            }
        }
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.opencorporates\.com/v0\.4/companies/us_de/12345.*"),
            payload=payload,
        )
        async with HTTPClient() as client:
            rec = await opencorporates.get_company(client, "us_de", "12345")
    assert rec is not None
    assert rec.name == "ACME CORP"
    assert len(rec.officers) == 2
    assert rec.officers[0].name == "Alice Doe"
    assert rec.officers[0].position == "director"
    assert rec.officers[1].end_date == "2023-06-30"


@pytest.mark.asyncio
async def test_get_company_handles_missing_officers(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    payload = {
        "results": {
            "company": {
                "name": "Tiny LLC",
                "company_number": "9",
                "jurisdiction_code": "us_de",
                # no officers key
            }
        }
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.opencorporates\.com/v0\.4/companies/us_de/9.*"),
            payload=payload,
        )
        async with HTTPClient() as client:
            rec = await opencorporates.get_company(client, "us_de", "9")
    assert rec is not None
    assert rec.officers == ()


@pytest.mark.asyncio
async def test_get_company_returns_none_on_404(monkeypatch) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.opencorporates\.com/.*"), status=404
        )
        async with HTTPClient() as client:
            rec = await opencorporates.get_company(client, "us_de", "0")
    assert rec is None


@pytest.mark.asyncio
async def test_get_company_rejects_blank_inputs() -> None:
    async with HTTPClient() as client:
        assert await opencorporates.get_company(client, "", "1") is None
        assert await opencorporates.get_company(client, "us_de", "") is None


# ── search_with_officers() ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_with_officers_combines_search_plus_per_company_fetch(
    monkeypatch,
) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    search_payload = {
        "results": {
            "companies": [
                {
                    "company": {
                        "name": "ACME CORP",
                        "company_number": "12345",
                        "jurisdiction_code": "us_de",
                    }
                },
                {
                    "company": {
                        "name": "BETA LTD",
                        "company_number": "67890",
                        "jurisdiction_code": "gb",
                    }
                },
            ]
        }
    }
    acme_full = {
        "results": {
            "company": {
                "name": "ACME CORP",
                "company_number": "12345",
                "jurisdiction_code": "us_de",
                "officers": [
                    {"officer": {"name": "Alice Doe", "position": "director"}}
                ],
            }
        }
    }
    beta_full = {
        "results": {
            "company": {
                "name": "BETA LTD",
                "company_number": "67890",
                "jurisdiction_code": "gb",
                "officers": [
                    {"officer": {"name": "Charlie Voe", "position": "secretary"}}
                ],
            }
        }
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.opencorporates\.com/v0\.4/companies/search.*"),
            payload=search_payload,
        )
        m.get(
            re.compile(
                r"https://api\.opencorporates\.com/v0\.4/companies/us_de/12345.*"
            ),
            payload=acme_full,
        )
        m.get(
            re.compile(
                r"https://api\.opencorporates\.com/v0\.4/companies/gb/67890.*"
            ),
            payload=beta_full,
        )
        async with HTTPClient() as client:
            recs = await opencorporates.search_with_officers(
                client, "Acme", limit=2
            )
    assert len(recs) == 2
    by_name = {r.name: r for r in recs}
    assert by_name["ACME CORP"].officers[0].name == "Alice Doe"
    assert by_name["BETA LTD"].officers[0].name == "Charlie Voe"


@pytest.mark.asyncio
async def test_search_with_officers_falls_back_to_search_record_on_fetch_failure(
    monkeypatch,
) -> None:
    monkeypatch.delenv("OPENCORPORATES_API_TOKEN", raising=False)
    search_payload = {
        "results": {
            "companies": [
                {
                    "company": {
                        "name": "ACME CORP",
                        "company_number": "12345",
                        "jurisdiction_code": "us_de",
                    }
                }
            ]
        }
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.opencorporates\.com/v0\.4/companies/search.*"),
            payload=search_payload,
        )
        # 404 on the officer fetch
        m.get(
            re.compile(
                r"https://api\.opencorporates\.com/v0\.4/companies/us_de/12345.*"
            ),
            status=404,
        )
        async with HTTPClient() as client:
            recs = await opencorporates.search_with_officers(
                client, "Acme", limit=1
            )
    # We still get the record from search, just without officers.
    assert len(recs) == 1
    assert recs[0].name == "ACME CORP"
    assert recs[0].officers == ()


# ── API token threading ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_includes_api_token_when_set(monkeypatch) -> None:
    monkeypatch.setenv("OPENCORPORATES_API_TOKEN", "tok-xyz")
    payload = {"results": {"companies": []}}
    captured: list[str] = []

    def callback(url, **_kwargs):
        captured.append(str(url))
        from aiohttp import web
        return web.Response(
            content_type="application/json", text='{"results":{"companies":[]}}'
        )

    with aioresponses() as m:
        # We don't need callback here — just record what URLs got called.
        m.get(re.compile(r"https://api\.opencorporates\.com/.*"), payload=payload)
        async with HTTPClient() as client:
            await opencorporates.search(client, "Acme")
        # aioresponses tracks calls in m.requests; pull the URL out
        for (method, url), _ in m.requests.items():
            captured.append(str(url))
    assert any("api_token=tok-xyz" in u for u in captured)
