"""Engine-level integration of the geocode phase."""

from __future__ import annotations

import pytest

from core.config import ScanConfig
from core.engine import _phase_geocode
from core.geo import GeoPoint
from core.models import PlatformResult, ScanResult


def _result_with_location(location: str) -> ScanResult:
    r = ScanResult(username="alice")
    r.platforms.append(
        PlatformResult(
            platform="GitHub",
            url="https://github.com/alice",
            category="dev",
            exists=True,
            status="found",
            profile_data={"location": location},
        )
    )
    return r


@pytest.mark.asyncio
async def test_phase_geocode_skipped_when_flag_off():
    cfg = ScanConfig(username="alice", geocode=False)
    result = _result_with_location("Istanbul")
    await _phase_geocode(cfg, result)
    assert result.geo_points == []


@pytest.mark.asyncio
async def test_phase_geocode_fills_points(monkeypatch):
    from core import geo as geo_mod

    async def fake_many(hints, **kwargs):
        return [
            GeoPoint(
                query="istanbul",
                lat=41.0,
                lng=29.0,
                display="Istanbul, Turkey",
                country="Turkey",
                source="GitHub",
            )
        ]

    monkeypatch.setattr(geo_mod, "geocode_many", fake_many)

    cfg = ScanConfig(username="alice", geocode=True)
    result = _result_with_location("Istanbul")
    await _phase_geocode(cfg, result)
    assert len(result.geo_points) == 1
    g = result.geo_points[0]
    assert g.lat == 41.0 and g.country == "Turkey"
    # GeoPoint serialises into the scan payload for the frontend.
    payload = result.to_dict()
    assert payload["geo_points"][0]["country"] == "Turkey"


@pytest.mark.asyncio
async def test_phase_geocode_no_hints_is_noop(monkeypatch):
    from core import geo as geo_mod

    called = {"n": 0}

    async def fake_many(hints, **kwargs):
        called["n"] += 1
        return []

    monkeypatch.setattr(geo_mod, "geocode_many", fake_many)

    cfg = ScanConfig(username="alice", geocode=True)
    result = ScanResult(username="alice")  # no platforms → no hints
    await _phase_geocode(cfg, result)
    assert called["n"] == 0
    assert result.geo_points == []
