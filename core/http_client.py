"""Async HTTP client with retry, proxy, and per-host rate limiting.

Notes
-----
- HTTP/HTTPS proxies are passed at request level so we can rotate per call.
- SOCKS proxies are bound at connector level because aiohttp does not
  support per-request SOCKS. To rotate SOCKS proxies callers should
  instantiate multiple HTTPClient objects.
- A per-host semaphore prevents hammering a single domain with the full
  MAX_CONCURRENT budget.
"""

from __future__ import annotations

import asyncio
import itertools
import os
import random
import time
from collections import defaultdict
from urllib.parse import urlparse

import aiohttp

from core.config import (
    MAX_CONCURRENT,
    PER_HOST_CONCURRENCY,
    REQUEST_TIMEOUT,
    RETRY_COUNT,
    RETRY_DELAY,
)
from core.logging_setup import get_logger
from core.proxy_pool import ProxyPool
from modules.stealth import DomainRateBucket, fingerprint_headers, pick_ua
from modules.stealth.tor_control import CircuitRotator

log = get_logger(__name__)


def _backoff(attempt: int) -> float:
    """Exponential backoff with jitter to avoid thundering-herd on mass retries."""
    return RETRY_DELAY * (2 ** attempt) * random.uniform(0.5, 1.5)


def _env_truthy(key: str) -> bool:
    return os.environ.get(key, "").strip().lower() in {"1", "true", "yes", "on"}


class HTTPClient:
    def __init__(
        self,
        proxy: str | None = None,
        proxies: list[str] | None = None,
        tor: bool = False,
        request_timeout: int | None = None,
        *,
        fingerprint: bool = True,
        rate_bucket: DomainRateBucket | None = None,
        new_circuit_every: int = 0,
        tor_control_password: str | None = None,
        verify_tls: bool | None = None,
    ) -> None:
        if tor:
            self.proxies = ["socks5://127.0.0.1:9050"]
        elif proxies:
            self.proxies = list(proxies)
        elif proxy:
            self.proxies = [proxy]
        else:
            self.proxies = []
        http_only = tuple(p for p in self.proxies if not p.startswith("socks"))
        self._pool = ProxyPool(proxies=http_only) if http_only else None
        self._proxy_cycle = itertools.cycle(self.proxies) if self.proxies else None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        self._host_semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(PER_HOST_CONCURRENCY)
        )
        self._session: aiohttp.ClientSession | None = None
        self._request_timeout = request_timeout or REQUEST_TIMEOUT
        self._fingerprint = fingerprint
        self._verify_tls = (
            not _env_truthy("OSINT_INSECURE_TLS")
            if verify_tls is None
            else verify_tls
        )
        self._rate_bucket = rate_bucket if rate_bucket is not None else DomainRateBucket()
        self._rotator: CircuitRotator | None = (
            CircuitRotator(every=new_circuit_every, password=tor_control_password)
            if tor and new_circuit_every > 0
            else None
        )

    async def __aenter__(self) -> HTTPClient:
        timeout = aiohttp.ClientTimeout(total=self._request_timeout)
        if self.proxies and any(p.startswith("socks") for p in self.proxies):
            try:
                from aiohttp_socks import ProxyConnector
            except ImportError as exc:
                raise RuntimeError(
                    "SOCKS/Tor support requires aiohttp-socks. "
                    "Install with: pip install aiohttp-socks"
                ) from exc
            connector: aiohttp.BaseConnector = ProxyConnector.from_url(self.proxies[0])
        else:
            connector = (
                aiohttp.TCPConnector(limit=MAX_CONCURRENT)
                if self._verify_tls
                else aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)
            )
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        if self._session:
            await self._session.close()

    # ── helpers ────────────────────────────────────────────────

    def _next_http_proxy(self) -> str | None:
        """Return the next healthy HTTP/HTTPS proxy; SOCKS handled at connector level."""
        if self._pool is None:
            return None
        return self._pool.next()

    def _record_proxy_result(self, proxy: str | None, *, success: bool) -> None:
        if self._pool is None or not proxy:
            return
        if success:
            self._pool.record_success(proxy)
        else:
            self._pool.record_failure(proxy)

    def _require_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("HTTPClient must be used as an async context manager")
        return self._session

    def _headers(self, extra: dict | None = None) -> dict:
        ua_entry = pick_ua()
        if self._fingerprint:
            merged: dict = dict(fingerprint_headers(ua_entry))
        else:
            merged = {
                "User-Agent": ua_entry.ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        if extra:
            merged.update(extra)
        return merged

    def _host(self, url: str) -> str:
        return urlparse(url).netloc or url

    def _host_lock(self, url: str) -> asyncio.Semaphore:
        return self._host_semaphores[self._host(url)]

    async def _acquire(self, url: str) -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
        host_lock = self._host_lock(url)
        await self._semaphore.acquire()
        await host_lock.acquire()
        await self._rate_bucket.acquire(self._host(url))
        return self._semaphore, host_lock

    @staticmethod
    def _retry_after(resp: aiohttp.ClientResponse) -> float | None:
        raw = resp.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    async def _post_request(self, url: str, status: int, resp: aiohttp.ClientResponse | None) -> None:
        host = self._host(url)
        if status in (429, 503):
            retry_after = self._retry_after(resp) if resp is not None else None
            await self._rate_bucket.record_throttled(host, retry_after=retry_after)
        elif 200 <= status < 400:
            await self._rate_bucket.record_success(host)
        if self._rotator is not None:
            await self._rotator.tick()

    # ── request methods ────────────────────────────────────────

    async def get(
        self,
        url: str,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> tuple[int, str, float]:
        status, body, elapsed, _ = await self._get_internal(
            url, headers, allow_redirects=allow_redirects
        )
        return status, body, elapsed

    async def get_with_meta(
        self,
        url: str,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> tuple[int, str, float, str | None]:
        """Same as :meth:`get` but also returns the final URL after redirects.

        ``final_url`` is the request URL post-redirect-chain; on the no-redirect
        path it equals the original URL. Returns ``None`` if the request errored
        before the response was received.
        """
        return await self._get_internal(
            url, headers, allow_redirects=allow_redirects
        )

    async def _get_internal(
        self,
        url: str,
        headers: dict | None,
        *,
        allow_redirects: bool,
    ) -> tuple[int, str, float, str | None]:
        session = self._require_session()
        merged = self._headers(headers)
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    async with session.get(
                        url,
                        headers=merged,
                        allow_redirects=allow_redirects,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text(errors="replace")
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        return resp.status, body, elapsed, str(resp.url)
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("timeout on %s (attempt %d)", url, attempt + 1)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, "", elapsed, None
                except (aiohttp.ClientError, OSError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("network error on %s: %s", url, exc)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, "", elapsed, None
                await asyncio.sleep(_backoff(attempt))
            return -1, "", 0.0, None
        finally:
            host_lock.release()
            global_lock.release()

    async def get_json(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, dict | None, float]:
        session = self._require_session()
        merged = self._headers(headers)
        merged["Accept"] = "application/json"
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    async with session.get(
                        url,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("json timeout on %s", url)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError, ValueError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("json error on %s: %s", url, exc)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
                await asyncio.sleep(_backoff(attempt))
            return -1, None, 0.0
        finally:
            host_lock.release()
            global_lock.release()

    async def post_json(
        self,
        url: str,
        json_body: dict,
        headers: dict | None = None,
    ) -> tuple[int, dict | None, float]:
        """POST a JSON body and parse the JSON response.

        Mirrors :meth:`get_json` — same fingerprinting, retry, proxy,
        and host-lock semantics. Returns ``(status, parsed_dict_or_None,
        elapsed_seconds)``. ``None`` body on non-200 status or parse
        failure.
        """
        session = self._require_session()
        merged = self._headers(headers)
        merged["Accept"] = "application/json"
        merged.setdefault("Content-Type", "application/json")
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    async with session.post(
                        url,
                        json=json_body,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("post_json timeout on %s", url)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError, ValueError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("post_json error on %s: %s", url, exc)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
                await asyncio.sleep(_backoff(attempt))
            return -1, None, 0.0
        finally:
            host_lock.release()
            global_lock.release()

    async def get_bytes(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, bytes | None, float]:
        session = self._require_session()
        merged = self._headers(headers)
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    async with session.get(
                        url,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        if resp.status == 200:
                            data = await resp.read()
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("bytes error on %s: %s", url, exc)
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
                await asyncio.sleep(_backoff(attempt))
            return -1, None, 0.0
        finally:
            host_lock.release()
            global_lock.release()
