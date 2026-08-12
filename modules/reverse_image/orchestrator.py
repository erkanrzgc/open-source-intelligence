"""Fan out reverse-image queries across sources.

Same pattern as the passive-intel orchestrator: gather with per-source
exception isolation, then dedupe by ``(match_url,)`` so Yandex and
TinEye surfacing the same page from different angles only contributes
one hit. We keep the higher-scored entry when a collision happens.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.reverse_image import tineye, yandex
from modules.reverse_image.models import ReverseImageHit

log = get_logger(__name__)


async def _safe(
    name: str, coro: Awaitable[list[ReverseImageHit]]
) -> list[ReverseImageHit]:
    try:
        return await coro
    except Exception as exc:
        log.debug("reverse image source %s failed: %s", name, exc)
        return []


def _dedupe(hits: list[ReverseImageHit]) -> list[ReverseImageHit]:
    best: dict[str, ReverseImageHit] = {}
    for hit in hits:
        key = hit.match_url.lower()
        if not key:
            continue
        existing = best.get(key)
        if existing is None or hit.score > existing.score:
            best[key] = hit
    # preserve first-seen ordering where scores tie
    seen: set[str] = set()
    out: list[ReverseImageHit] = []
    for hit in hits:
        key = hit.match_url.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(best[key])
    return out


async def run_reverse_image(
    client: HTTPClient,
    *,
    image_urls: list[str],
    limit_per_source: int = 25,
) -> list[ReverseImageHit]:
    """Run every source against every image URL and merge the results."""
    if not image_urls:
        return []

    tasks: list[Awaitable[list[ReverseImageHit]]] = []
    for url in image_urls:
        tasks.append(_safe("yandex", yandex.search(client, url, limit=limit_per_source)))
        tasks.append(_safe("tineye", tineye.search(client, url, limit=limit_per_source)))

    results = await asyncio.gather(*tasks)
    merged: list[ReverseImageHit] = []
    for hits in results:
        merged.extend(hits)
    return _dedupe(merged)
