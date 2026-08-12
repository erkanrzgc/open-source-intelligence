"""Bulk scan orchestration — fan out ``run_scan`` across many usernames.

Wraps :func:`core.engine.run_scan` with an :class:`asyncio.Semaphore`
concurrency cap so sweeping the watchlist (or a newline-delimited file)
doesn't thrash upstream sources.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

from core.config import ScanConfig
from core.engine import run_scan
from core.logging_setup import get_logger
from core.models import ScanResult

log = get_logger(__name__)


def load_usernames_from_file(path: str | Path) -> list[str]:
    """Read usernames from ``path``: one per line, ``#`` starts a comment."""
    p = Path(path)
    usernames: list[str] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            usernames.append(line)
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    unique: list[str] = []
    for u in usernames:
        k = u.lower()
        if k in seen:
            continue
        seen.add(k)
        unique.append(u)
    return unique


async def run_bulk(
    usernames: list[str],
    cfg_template: ScanConfig,
    *,
    max_parallel: int = 3,
) -> list[ScanResult]:
    """Run ``run_scan`` for each username with a concurrency cap.

    Each scan gets its own :class:`ScanConfig` derived from ``cfg_template``
    by swapping the ``username`` field. Failures are logged and the scan
    returns an empty :class:`ScanResult` so one bad target doesn't sink
    the batch.
    """
    if not usernames:
        return []
    sem = asyncio.Semaphore(max(1, max_parallel))

    async def _one(username: str) -> ScanResult:
        async with sem:
            cfg = replace(cfg_template, username=username)
            try:
                return await run_scan(cfg)
            except Exception as exc:
                log.warning("bulk scan failed for %s: %s", username, exc)
                return ScanResult(username=username)

    return await asyncio.gather(*(_one(u) for u in usernames))
