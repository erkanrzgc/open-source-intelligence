"""Intelligence X paste / leak / dark-web index lookup.

IntelX indexes pastes, document leaks, dark-web content, and breached
data dumps. We use it as a complementary signal next to
``modules.breach_check`` (HIBP-flavored credential leaks) and
``modules.comb_leaks`` (the COMB collection): IntelX surfaces the
*containers* — paste URLs, archive filenames, dark-web mentions — that
those other sources do not enumerate.

API shape
---------
IntelX search is two-step and *server-side asynchronous*:

1. ``POST /intelligent/search`` with ``{term, maxresults, ...}`` and
   the ``x-key`` header. The response is ``{id, status}`` where
   ``status == 0`` means the search was accepted; the ``id`` is the
   handle for the next step.
2. ``GET /intelligent/search/result?id=<id>`` returns
   ``{records, status}``. ``status == 0`` means the search is done
   and ``records`` is final. ``status == 3`` means more results may
   still arrive — poll the same endpoint after a short delay.

We poll a small bounded number of times to avoid burning quota when
a slow query never completes.

Auth: ``INTELX_API_KEY`` in the environment. Without it the module
silently no-ops, matching every other passive source.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_BASE = "https://2.intelx.io"
_SEARCH_ENDPOINT = f"{_BASE}/intelligent/search"
_RESULT_ENDPOINT = f"{_BASE}/intelligent/search/result"

# Polling knobs — kept as module-level so tests can monkeypatch them
# down to zero rather than waiting for real sleeps.
_POLL_DELAY_SEC: float = 1.0
_MAX_POLLS: int = 4


def _api_key() -> str:
    return os.environ.get("INTELX_API_KEY", "")


def _auth_headers(key: str) -> dict[str, str]:
    return {"x-key": key, "User-Agent": "open-source-intelligence"}


def _record_to_hit(row: dict[str, Any]) -> PassiveHit | None:
    """Translate one IntelX ``records`` entry into a ``PassiveHit``.

    ``name`` is the canonical artifact pointer (URL, paste id, archive
    filename); without it the row has nothing actionable. The bucket
    becomes the title so reporters can group by source.
    """
    if not isinstance(row, dict):
        return None
    name = (row.get("name") or "").strip()
    if not name:
        return None
    bucket = (row.get("bucket") or "").strip()
    return PassiveHit(
        source="intelx",
        kind="leak",
        value=name,
        title=bucket,
        metadata={
            "systemid": row.get("systemid") or "",
            "storageid": row.get("storageid") or "",
            "date": row.get("date") or "",
            "size": row.get("size"),
            "bucket": bucket,
            "type": row.get("type"),
            "accesslevel": row.get("accesslevel"),
        },
    )


async def _start_search(
    client: HTTPClient,
    *,
    term: str,
    max_results: int,
    key: str,
) -> str:
    """Issue the POST that registers a new search and return its id.

    Returns an empty string when the upstream rejects the request or
    the payload is missing the ``id``.
    """
    body = {
        "term": term,
        "maxresults": max_results,
        "media": 0,
        "sort": 4,        # sort by date desc
        "terminate": [],
        "buckets": [],    # empty = search everything available
        "timeout": 10,
        "lookuplevel": 0,
    }
    status, data, _ = await client.post_json(
        _SEARCH_ENDPOINT, json_body=body, headers=_auth_headers(key)
    )
    if status != 200 or not isinstance(data, dict):
        return ""
    if data.get("status") != 0:
        return ""
    return str(data.get("id") or "")


async def _fetch_results(
    client: HTTPClient,
    *,
    search_id: str,
    max_results: int,
    key: str,
) -> list[dict]:
    """Poll the result endpoint until it stops returning the
    "more data may arrive" status (3) or we run out of attempts.

    Returns the merged record list across polls. ``[]`` on persistent
    failure or quota exhaustion.
    """
    url = (
        f"{_RESULT_ENDPOINT}?id={quote(search_id)}"
        f"&limit={max_results}&previewlines=8"
    )
    collected: list[dict] = []
    for attempt in range(_MAX_POLLS):
        status, data, _ = await client.get_json(url, headers=_auth_headers(key))
        if status != 200 or not isinstance(data, dict):
            return []
        records = data.get("records")
        if isinstance(records, list):
            collected.extend(r for r in records if isinstance(r, dict))
        if data.get("status") != 3:
            # 0 = done; 1/2 = error; 4 = no more data — all terminal.
            return collected
        if attempt + 1 < _MAX_POLLS:
            await asyncio.sleep(_POLL_DELAY_SEC)
    # Persistent "still running" — give up rather than burn quota.
    return []


async def search(
    client: HTTPClient,
    term: str,
    *,
    max_results: int = 50,
) -> list[PassiveHit]:
    """Search IntelX for ``term`` and return parsed PassiveHit rows.

    ``term`` is anything IntelX recognizes as a selector: a domain,
    email, BTC address, IPv4/v6, or freeform text. Returns ``[]`` on
    auth/quota failure, blank input, or zero matches — passive sources
    are best-effort by contract.
    """
    if not term or not term.strip():
        return []
    key = _api_key()
    if not key:
        log.debug("INTELX_API_KEY not set; skipping intelx search")
        return []

    search_id = await _start_search(
        client, term=term.strip(), max_results=max_results, key=key
    )
    if not search_id:
        return []

    records = await _fetch_results(
        client, search_id=search_id, max_results=max_results, key=key
    )
    hits: list[PassiveHit] = []
    for row in records[:max_results]:
        hit = _record_to_hit(row)
        if hit is not None:
            hits.append(hit)
    return hits
