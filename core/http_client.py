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
import ipaddress
import itertools
import os
import random
import socket
import time
from collections import defaultdict
from typing import Any
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
from core.security import UnsafeTargetError, validate_http_url
from modules.stealth import DomainRateBucket, fingerprint_headers, pick_ua
from modules.stealth.tor_control import CircuitRotator

log = get_logger(__name__)


def _safe_log_url(url: str) -> str:
    """Strip query/fragment data so API keys and tokens cannot enter logs."""
    parsed = urlparse(url)
    return parsed._replace(
        query="[redacted]" if parsed.query else "",
        fragment="",
    ).geturl()


class _SafeResolver(aiohttp.abc.AbstractResolver):
    """Reject DNS answers that would route an external URL to a local network."""

    def __init__(self, resolver: aiohttp.abc.AbstractResolver | None = None) -> None:
        self._resolver = resolver or aiohttp.resolver.DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[Any]:
        answers = await self._resolver.resolve(host, port, family)
        for answer in answers:
            resolved = str(answer["host"])
            try:
                address = ipaddress.ip_address(resolved)
            except ValueError as exc:
                raise UnsafeTargetError(
                    f"DNS returned an invalid address for {host}: {resolved}"
                ) from exc
            if not address.is_global:
                raise UnsafeTargetError(
                    f"private-network DNS result is disabled: {host} -> {resolved}"
                )
        return answers

    async def close(self) -> None:
        await self._resolver.close()


# ── Scrapling stealth transport (optional) ────────────────────────────
_SCRAPLING_AVAILABLE = False
_SCRAPLING_FETCHER = None
_SCRAPLING_INITED = False

try:
    from scrapling import AsyncFetcher  # type: ignore[import-not-found]

    _SCRAPLING_AVAILABLE = True
except ImportError:
    pass


async def _init_scrapling():
    global _SCRAPLING_INITED, _SCRAPLING_FETCHER
    if _SCRAPLING_INITED:
        return _SCRAPLING_FETCHER
    _SCRAPLING_INITED = True
    if not _SCRAPLING_AVAILABLE:
        return None
    try:
        _SCRAPLING_FETCHER = AsyncFetcher()
        log.debug("Scrapling transport active")
        return _SCRAPLING_FETCHER
    except Exception as exc:
        log.debug("Scrapling init failed: %s", exc)
        return None


async def _try_scrapling_get(url, headers, timeout):
    """Try Scrapling fetch. Returns None on failure (use aiohttp)."""
    if not _SCRAPLING_AVAILABLE:
        return None
    if not url.startswith("https://"):
        return None
    if any(d in url for d in ("example.com", "fake.test", "localhost", "127.0.0.1")):
        return None
    fetcher = await _init_scrapling()
    if fetcher is None:
        return None
    try:
        t0 = time.monotonic()
        resp = await asyncio.wait_for(
            fetcher.get(url, headers=headers),
            timeout=timeout,
        )
        elapsed = time.monotonic() - t0
        return resp.status, resp.html_content, elapsed, resp.url
    except asyncio.TimeoutError:
        return 0, "", time.monotonic() - t0, None
    except Exception as exc:
        log.debug(
            "Scrapling fetch failed for %s (%s)",
            _safe_log_url(url),
            type(exc).__name__,
        )
        return None


def _should_retry_scrapling(status, body, url):
    """Check if aiohttp response looks blocked — worth a Scrapling retry."""
    if not _SCRAPLING_AVAILABLE:
        return False
    if status in (-1, 0, 403, 429, 503):
        return True
    if status == 200 and body and len(body) < 2000:
        blocked = any(s in body for s in (
            "Just a moment",
            "cf-browser-verification",
            "Attention Required",
            "captcha",
            "_cf_chl_opt",
        ))
        if blocked:
            return True
    return False


def _backoff(attempt: int) -> float:
    """Exponential backoff with jitter to avoid thundering-herd on mass retries."""
    # Jitter only spreads retries; it does not create security material.
    return float(RETRY_DELAY * (2 ** attempt) * random.uniform(0.5, 1.5))  # nosec B311


def _env_truthy(key: str) -> bool:
    return os.environ.get(key, "").strip().lower() in {"1", "true", "yes", "on"}


class HTTPClient:
    def __init__(
        self,
        proxy: str | None = None,
        proxies: list[str] | None = None,
        tor: bool = False,
        request_timeout: float | None = None,
        *,
        fingerprint: bool = True,
        rate_bucket: DomainRateBucket | None = None,
        new_circuit_every: int = 0,
        tor_control_password: str | None = None,
        verify_tls: bool | None = None,
        allow_private_networks: bool = False,
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
        self._request_count = 0
        self._request_timeout = request_timeout or REQUEST_TIMEOUT
        self._fingerprint = fingerprint
        self._allow_private_networks = allow_private_networks
        self._verify_tls = (
            not _env_truthy("OSINT_INSECURE_TLS")
            if verify_tls is None
            else verify_tls
        )
        configured_delay = max(
            0.0, float(os.environ.get("OSINT_RATE_LIMIT_DELAY", "0.1"))
        )
        self._rate_bucket = rate_bucket if rate_bucket is not None else DomainRateBucket(
            # The configured pacing is per host. A global sleep serialized the
            # 1,922-host sweep to ten requests/second and defeated concurrency.
            min_interval=configured_delay,
            jitter=min(0.05, configured_delay / 2),
            global_delay=0.0,
        )
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
            resolver = None if self._allow_private_networks else _SafeResolver()
            connector = (
                aiohttp.TCPConnector(limit=MAX_CONCURRENT, resolver=resolver)
                if self._verify_tls
                else aiohttp.TCPConnector(
                    limit=MAX_CONCURRENT,
                    ssl=False,
                    resolver=resolver,
                )
            )
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        if self._session:
            await self._session.close()

    # ── helpers ────────────────────────────────────────────────

    @property
    def request_count(self) -> int:
        """Number of wire attempts made by this client, including retries."""
        return self._request_count

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
        validate_http_url(url, allow_private_networks=self._allow_private_networks)
        host_lock = self._host_lock(url)
        # Pacing happens before scarce request slots are acquired. Sleeping
        # while holding either semaphore can deadlock a large same-host fanout.
        await self._rate_bucket.acquire(self._host(url))
        await self._semaphore.acquire()
        try:
            await host_lock.acquire()
        except BaseException:
            self._semaphore.release()
            raise
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
        status, body, elapsed, _final = await self._get_internal(
            url, headers, allow_redirects=allow_redirects
        )
        # When aiohttp gets blocked (403 / empty body / CF challenge),
        # retry via Scrapling's stealthier TLS transport.
        if _should_retry_scrapling(status, body, url):
            sr = await _try_scrapling_get(url, headers, self._request_timeout)
            if sr is not None:
                return sr[0], sr[1], sr[2]
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
        for attempt in range(RETRY_COUNT + 1):
            global_lock, host_lock = await self._acquire(url)
            try:
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    self._request_count += 1
                    async with session.get(
                        url,
                        headers=merged,
                        allow_redirects=allow_redirects,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        validate_http_url(
                            str(resp.url),
                            allow_private_networks=self._allow_private_networks,
                        )
                        body = await resp.text(errors="replace")
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        return resp.status, body, elapsed, str(resp.url)
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug(
                        "timeout on %s (attempt %d)",
                        _safe_log_url(url),
                        attempt + 1,
                    )
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, "", elapsed, None
                except (aiohttp.ClientError, OSError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug(
                        "network error on %s (%s)",
                        _safe_log_url(url),
                        type(exc).__name__,
                    )
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, "", elapsed, None
            finally:
                host_lock.release()
                global_lock.release()
            await asyncio.sleep(_backoff(attempt))
        return -1, "", 0.0, None

    async def get_json(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, dict | None, float]:
        session = self._require_session()
        merged = self._headers(headers)
        merged["Accept"] = "application/json"
        for attempt in range(RETRY_COUNT + 1):
            global_lock, host_lock = await self._acquire(url)
            try:
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    self._request_count += 1
                    async with session.get(
                        url,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        validate_http_url(
                            str(resp.url),
                            allow_private_networks=self._allow_private_networks,
                        )
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("json timeout on %s", _safe_log_url(url))
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError, ValueError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug(
                        "json error on %s (%s)",
                        _safe_log_url(url),
                        type(exc).__name__,
                    )
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
            finally:
                host_lock.release()
                global_lock.release()
            await asyncio.sleep(_backoff(attempt))
        return -1, None, 0.0

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
        for attempt in range(RETRY_COUNT + 1):
            global_lock, host_lock = await self._acquire(url)
            try:
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    self._request_count += 1
                    async with session.post(
                        url,
                        json=json_body,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        validate_http_url(
                            str(resp.url),
                            allow_private_networks=self._allow_private_networks,
                        )
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("post_json timeout on %s", _safe_log_url(url))
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError, ValueError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug(
                        "post_json error on %s (%s)",
                        _safe_log_url(url),
                        type(exc).__name__,
                    )
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
            finally:
                host_lock.release()
                global_lock.release()
            await asyncio.sleep(_backoff(attempt))
        return -1, None, 0.0

    async def post_form(
        self,
        url: str,
        form_body: dict[str, str],
        headers: dict | None = None,
    ) -> tuple[int, dict | None, float]:
        """POST form-encoded data and parse a JSON object response.

        OAuth token endpoints commonly require
        ``application/x-www-form-urlencoded``. Keeping this transport here
        prevents provider modules from bypassing the centralized URL safety,
        proxy, retry, rate-limit and request-count policies.
        """
        session = self._require_session()
        merged = self._headers(headers)
        merged["Accept"] = "application/json"
        merged["Content-Type"] = "application/x-www-form-urlencoded"
        for attempt in range(RETRY_COUNT + 1):
            global_lock, host_lock = await self._acquire(url)
            try:
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    self._request_count += 1
                    async with session.post(
                        url,
                        data=form_body,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        validate_http_url(
                            str(resp.url),
                            allow_private_networks=self._allow_private_networks,
                        )
                        await self._post_request(url, resp.status, resp)
                        self._record_proxy_result(proxy, success=True)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("post_form timeout on %s", _safe_log_url(url))
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError, ValueError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug(
                        "post_form error on %s (%s)",
                        _safe_log_url(url),
                        type(exc).__name__,
                    )
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
            finally:
                host_lock.release()
                global_lock.release()
            await asyncio.sleep(_backoff(attempt))
        return -1, None, 0.0

    async def get_bytes(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, bytes | None, float]:
        session = self._require_session()
        merged = self._headers(headers)
        for attempt in range(RETRY_COUNT + 1):
            global_lock, host_lock = await self._acquire(url)
            try:
                start = time.monotonic()
                proxy = self._next_http_proxy()
                try:
                    self._request_count += 1
                    async with session.get(
                        url,
                        headers=merged,
                        proxy=proxy,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        validate_http_url(
                            str(resp.url),
                            allow_private_networks=self._allow_private_networks,
                        )
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
                    log.debug(
                        "bytes error on %s (%s)",
                        _safe_log_url(url),
                        type(exc).__name__,
                    )
                    self._record_proxy_result(proxy, success=False)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
            finally:
                host_lock.release()
                global_lock.release()
            await asyncio.sleep(_backoff(attempt))
        return -1, None, 0.0
