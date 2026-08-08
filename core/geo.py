"""Geocoder with local SQLite cache.

Wraps Nominatim (OpenStreetMap) lookups and caches responses so repeat
scans do not re-hammer their endpoint. The cache is cross-run: every
successful or negative result is stored forever unless the caller
explicitly clears it.

Nominatim usage policy requires a descriptive User-Agent and at most
1 request/second. Both are enforced here. All network access is
optional — callers should treat a None return as "unresolved, skip".
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "open-source-intelligence" / "geocache.sqlite3"
NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
USER_AGENT = "open-source-intelligence/0.3 (https://github.com/erkanrzgc/open-source-intelligence)"
MIN_INTERVAL_S = 1.05  # Nominatim: ≤ 1 req / sec

_SCHEMA = """
CREATE TABLE IF NOT EXISTS geocache (
    query   TEXT PRIMARY KEY,
    lat     REAL,
    lng     REAL,
    display TEXT,
    country TEXT,
    ts      INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class GeoPoint:
    query: str
    lat: float
    lng: float
    display: str = ""
    country: str = ""
    source: str = ""  # "github", "profile_data", etc.

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "lat": self.lat,
            "lng": self.lng,
            "display": self.display,
            "country": self.country,
            "source": self.source,
        }


# ── cache ─────────────────────────────────────────────────────────────


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _cache_get(db_path: Path, query: str) -> tuple[float, float, str, str] | None:
    try:
        conn = _connect(db_path)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(
            "SELECT lat, lng, display, country FROM geocache WHERE query = ?",
            (query,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or row[0] is None:
        return None
    return float(row[0]), float(row[1]), row[2] or "", row[3] or ""


def _cache_put(
    db_path: Path,
    query: str,
    lat: float | None,
    lng: float | None,
    display: str,
    country: str,
) -> None:
    try:
        conn = _connect(db_path)
    except sqlite3.Error as exc:
        log.debug("geocache: could not open db: %s", exc)
        return
    try:
        conn.execute(
            "INSERT OR REPLACE INTO geocache(query, lat, lng, display, country, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (query, lat, lng, display, country, int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()


# ── extraction ────────────────────────────────────────────────────────


_LOCATION_KEYS = ("location", "city", "country", "place", "address")


def extract_location_hints(payload: dict) -> list[tuple[str, str]]:
    """Pull (raw_location, source_platform) pairs out of a scan payload.

    Walks ``payload['platforms'][*]['profile_data']`` looking for common
    geographic keys and returns each non-empty value paired with its
    platform name. Duplicate strings are preserved so the caller can use
    the frequency as a heatmap weight.
    """
    hits: list[tuple[str, str]] = []
    for p in payload.get("platforms", []):
        pd = p.get("profile_data") or {}
        if not isinstance(pd, dict):
            continue
        source = p.get("platform", "")
        for key in _LOCATION_KEYS:
            raw = pd.get(key)
            if isinstance(raw, str):
                cleaned = raw.strip()
                if cleaned:
                    hits.append((cleaned, source))
    return hits


# ── geocoding ─────────────────────────────────────────────────────────


async def geocode(
    query: str,
    *,
    session=None,
    db_path: Path = DEFAULT_DB_PATH,
    timeout: float = 10.0,
) -> GeoPoint | None:
    """Resolve ``query`` to a GeoPoint. Returns None on miss or error."""
    norm = query.strip()
    if not norm:
        return None
    key = norm.lower()

    cached = _cache_get(db_path, key)
    if cached is not None:
        lat, lng, display, country = cached
        return GeoPoint(
            query=key, lat=lat, lng=lng, display=display, country=country
        )

    try:
        import aiohttp  # local import so tests that don't need the net skip cleanly
    except ImportError:  # pragma: no cover
        return None

    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession()

    try:
        params = {"q": norm, "format": "jsonv2", "limit": 1, "addressdetails": 1}
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        async with session.get(
            NOMINATIM_URL,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                log.debug("nominatim %s → %s", norm, resp.status)
                _cache_put(db_path, key, None, None, "", "")
                return None
            raw = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        log.debug("nominatim failed for %s: %s", norm, exc)
        return None
    finally:
        if own_session:
            await session.close()

    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not items:
        _cache_put(db_path, key, None, None, "", "")
        return None

    first = items[0]
    try:
        lat = float(first["lat"])
        lng = float(first["lon"])
    except (KeyError, ValueError, TypeError):
        return None
    display = first.get("display_name", "")
    country = (first.get("address") or {}).get("country", "")
    _cache_put(db_path, key, lat, lng, display, country)
    return GeoPoint(
        query=key, lat=lat, lng=lng, display=display, country=country
    )


async def geocode_many(
    hints: Iterable[tuple[str, str]],
    *,
    db_path: Path = DEFAULT_DB_PATH,
    timeout: float = 10.0,
    rate_limit_s: float = MIN_INTERVAL_S,
) -> list[GeoPoint]:
    """Resolve a batch of (location, source) pairs, respecting rate limits.

    Cache hits are returned instantly. Cache misses are serialised with
    ``rate_limit_s`` between each upstream hit so we stay inside
    Nominatim's policy. Duplicate queries are deduped, but the returned
    GeoPoint carries the FIRST source we saw it on.
    """
    try:
        import aiohttp
    except ImportError:  # pragma: no cover
        return []

    seen: dict[str, str] = {}
    for query, source in hints:
        key = query.strip().lower()
        if key and key not in seen:
            seen[key] = source

    if not seen:
        return []

    out: list[GeoPoint] = []
    async with aiohttp.ClientSession() as session:
        last_net_call = 0.0
        for raw_query, source in seen.items():
            cached = _cache_get(db_path, raw_query)
            if cached is not None:
                lat, lng, display, country = cached
                out.append(
                    GeoPoint(
                        query=raw_query,
                        lat=lat,
                        lng=lng,
                        display=display,
                        country=country,
                        source=source,
                    )
                )
                continue
            # enforce spacing between actual network calls
            gap = max(0.0, time.monotonic() - last_net_call)
            if gap < rate_limit_s:
                await asyncio.sleep(rate_limit_s - gap)
            point = await geocode(
                raw_query, session=session, db_path=db_path, timeout=timeout
            )
            last_net_call = time.monotonic()
            if point is not None:
                out.append(
                    GeoPoint(
                        query=point.query,
                        lat=point.lat,
                        lng=point.lng,
                        display=point.display,
                        country=point.country,
                        source=source,
                    )
                )
    return out
