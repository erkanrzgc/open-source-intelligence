"""Tests for core/geo.py — cache, extractor, geocoder, batch pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from core import geo
from core.geo import GeoPoint, extract_location_hints


def test_extract_location_hints_ignores_empty():
    payload = {
        "platforms": [
            {"platform": "GitHub", "profile_data": {"location": "Istanbul"}},
            {"platform": "Twitter / X", "profile_data": {"location": "  "}},
            {"platform": "Bluesky", "profile_data": {"bio": "no location here"}},
        ]
    }
    hits = extract_location_hints(payload)
    assert ("Istanbul", "GitHub") in hits
    assert len(hits) == 1


def test_extract_location_hints_prefers_multiple_keys():
    payload = {
        "platforms": [
            {
                "platform": "Scraper",
                "profile_data": {"city": "Berlin", "country": "Germany"},
            }
        ]
    }
    hits = extract_location_hints(payload)
    assert ("Berlin", "Scraper") in hits
    assert ("Germany", "Scraper") in hits


def test_extract_location_hints_skips_non_dict_profile_data():
    payload = {
        "platforms": [
            {"platform": "X", "profile_data": "oops"},
            {"platform": "Y", "profile_data": None},
        ]
    }
    assert extract_location_hints(payload) == []


def test_cache_roundtrip(tmp_path: Path):
    db = tmp_path / "cache.sqlite3"
    geo._cache_put(db, "istanbul", 41.0, 29.0, "Istanbul, Turkey", "Turkey")
    cached = geo._cache_get(db, "istanbul")
    assert cached == (41.0, 29.0, "Istanbul, Turkey", "Turkey")


def test_cache_miss_returns_none(tmp_path: Path):
    assert geo._cache_get(tmp_path / "missing.sqlite3", "anywhere") is None


def test_cache_records_negative_miss_as_none(tmp_path: Path):
    db = tmp_path / "neg.sqlite3"
    geo._cache_put(db, "nowhere", None, None, "", "")
    # _cache_get skips rows with NULL lat (treated as uncached).
    assert geo._cache_get(db, "nowhere") is None


def test_geopoint_to_dict_includes_source():
    g = GeoPoint(query="q", lat=1.0, lng=2.0, display="d", country="c", source="Twitter")
    d = g.to_dict()
    assert d == {
        "query": "q", "lat": 1.0, "lng": 2.0,
        "display": "d", "country": "c", "source": "Twitter",
    }


@pytest.mark.asyncio
async def test_geocode_empty_query_returns_none(tmp_path: Path):
    assert await geo.geocode("   ", db_path=tmp_path / "c.sqlite3") is None


@pytest.mark.asyncio
async def test_geocode_hits_cache_without_network(tmp_path: Path, monkeypatch):
    db = tmp_path / "c.sqlite3"
    geo._cache_put(db, "istanbul", 41.0, 29.0, "Istanbul, Turkey", "Turkey")

    # If the network were touched this would explode.
    def _boom(*a, **kw):
        raise AssertionError("aiohttp should not be imported on cache hit")

    monkeypatch.setitem(__import__("sys").modules, "aiohttp_boom_guard", _boom)

    out = await geo.geocode("Istanbul", db_path=db)
    assert out is not None
    assert out.lat == 41.0 and out.lng == 29.0
    assert out.country == "Turkey"


@pytest.mark.asyncio
async def test_geocode_many_dedupes_and_uses_cache(tmp_path: Path, monkeypatch):
    db = tmp_path / "c.sqlite3"
    geo._cache_put(db, "istanbul", 41.0, 29.0, "Istanbul, TR", "Turkey")
    geo._cache_put(db, "berlin", 52.52, 13.4, "Berlin, DE", "Germany")

    # Make sure nothing tries to hit the network.
    async def fake_geocode(query, *, session=None, db_path, timeout=10.0):
        raise AssertionError(f"unexpected upstream call for {query}")

    monkeypatch.setattr(geo, "geocode", fake_geocode)

    hits = [
        ("Istanbul", "GitHub"),
        ("istanbul", "Twitter / X"),  # duplicate, lowercased
        ("Berlin", "Bluesky"),
    ]
    out = await geo.geocode_many(hits, db_path=db)
    by_query = {p.query: p for p in out}
    assert set(by_query.keys()) == {"istanbul", "berlin"}
    assert by_query["istanbul"].source == "GitHub"  # first occurrence wins
    assert by_query["berlin"].country == "Germany"


@pytest.mark.asyncio
async def test_geocode_many_empty_short_circuits(tmp_path: Path):
    assert await geo.geocode_many([], db_path=tmp_path / "c.sqlite3") == []
    assert await geo.geocode_many([("  ", "X")], db_path=tmp_path / "c.sqlite3") == []
