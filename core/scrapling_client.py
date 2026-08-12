"""Scrapling-based HTTP client adapter.

Provides the same interface as HTTPClient (get, get_json, post_json) but uses
Scrapling's curl_cffi-backed transport, which impersonates Chrome's TLS
fingerprint and bypasses many bot-detection systems that block plain aiohttp.

Drop-in replacement::

    from core.scrapling_client import ScraplingClient
    async with ScraplingClient() as client:
        status, body, elapsed = await client.get(url)
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import time
from typing import Any

log = logging.getLogger(__name__)

AsyncFetcher: Any
try:
    from scrapling import AsyncFetcher as _AsyncFetcher

    AsyncFetcher = _AsyncFetcher
    SCRAPLING_AVAILABLE = True
except ImportError:  # pragma: no cover
    AsyncFetcher = None
    SCRAPLING_AVAILABLE = False


class ScraplingClient:
    """Async HTTP client backed by Scrapling's stealthy TLS transport."""

    def __init__(
        self,
        *,
        proxy: str | None = None,
        request_timeout: float = 15.0,
        fingerprint: bool = True,
    ) -> None:
        self._proxy = proxy
        self._timeout = request_timeout
        self._fingerprint = fingerprint
        self._fetcher: Any = None

    async def __aenter__(self) -> ScraplingClient:
        if not SCRAPLING_AVAILABLE:
            raise RuntimeError("Scrapling is not installed")
        self._fetcher = AsyncFetcher()
        return self

    async def __aexit__(self, *args: object) -> None:
        self._fetcher = None

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, float]:
        """Fetch *url* and return ``(status, body, elapsed)``."""
        t0 = time.monotonic()
        fetcher = self._fetcher
        if fetcher is None:
            return -1, "", 0.0
        try:
            resp = await asyncio.wait_for(
                fetcher.get(url, headers=headers),
                timeout=self._timeout,
            )
            elapsed = time.monotonic() - t0
            return resp.status, resp.html_content, elapsed
        except asyncio.TimeoutError:
            return 0, "", time.monotonic() - t0
        except Exception as exc:
            log.debug("Scrapling get failed for %s: %s", url, exc)
            return -1, "", time.monotonic() - t0

    async def get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict | None, float]:
        """Fetch JSON from *url* and return ``(status, parsed, elapsed)``."""
        t0 = time.monotonic()
        fetcher = self._fetcher
        if fetcher is None:
            return -1, None, 0.0
        try:
            resp = await asyncio.wait_for(
                fetcher.get(url, headers=headers),
                timeout=self._timeout,
            )
            elapsed = time.monotonic() - t0
            if resp.status != 200:
                return resp.status, None, elapsed
            try:
                return resp.status, resp.json(), elapsed
            except Exception:
                try:
                    return resp.status, _json.loads(resp.html_content), elapsed
                except Exception:
                    return resp.status, None, elapsed
        except asyncio.TimeoutError:
            return 0, None, time.monotonic() - t0
        except Exception as exc:
            log.debug("Scrapling get_json failed for %s: %s", url, exc)
            return -1, None, time.monotonic() - t0

    async def post_json(
        self,
        url: str,
        json_body: dict,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict | None, float]:
        """POST JSON and return ``(status, parsed, elapsed)``."""
        t0 = time.monotonic()
        fetcher = self._fetcher
        if fetcher is None:
            return -1, None, 0.0
        merged = dict(headers or {})
        merged.setdefault("Content-Type", "application/json")
        try:
            resp = await asyncio.wait_for(
                fetcher.post(url, json=json_body, headers=merged),
                timeout=self._timeout,
            )
            elapsed = time.monotonic() - t0
            if resp.status != 200:
                return resp.status, None, elapsed
            try:
                return resp.status, resp.json(), elapsed
            except Exception:
                try:
                    return resp.status, _json.loads(resp.html_content), elapsed
                except Exception:
                    return resp.status, None, elapsed
        except asyncio.TimeoutError:
            return 0, None, time.monotonic() - t0
        except Exception as exc:
            log.debug("Scrapling post failed for %s: %s", url, exc)
            return -1, None, time.monotonic() - t0
