"""Holehe wrapper — email → 120+ site registration checks.

Holehe probes password-reset / sign-up endpoints on ~120 popular sites and
reports whether a given email is already registered, without ever trying to
log in. It is the fastest way to pivot from a known email into the services
that person uses. The upstream project exposes its checks as per-site async
functions following the signature::

    async def <site>(email, httpx_client, out) -> None

Each call appends a dict to ``out`` with the shape::

    {
        "name": "<site>",
        "domain": "<domain>",
        "method": "register" | "password recovery" | ...,
        "frequent_rate_limit": bool,
        "rateLimit": bool,
        "exists": bool,
        "emailrecovery": str | None,
        "phoneNumber": str | None,
        "others": dict | None,
    }

We import holehe lazily so it stays an optional dependency — if the install is
missing we report unavailable and every call is a no-op. The actual network
traffic goes through ``httpx`` (holehe's native client); we don't route it
through our aiohttp HTTPClient because holehe's checks are tightly coupled to
httpx response semantics.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from core.logging_setup import get_logger

log = get_logger(__name__)

try:  # pragma: no cover - import guard
    import httpx
    from holehe.core import get_functions, import_submodules

    _MODULES = import_submodules("holehe.modules")
    _FUNCS = get_functions(_MODULES)
    _AVAILABLE = True
except Exception as exc:  # pragma: no cover - import guard
    log.debug("holehe unavailable: %s", exc)
    httpx = None  # type: ignore[assignment]
    _FUNCS = []
    _AVAILABLE = False


@dataclass(frozen=True)
class HoleheHit:
    email: str
    site: str
    domain: str
    method: str = ""
    email_recovery: str | None = None
    phone_recovery: str | None = None
    others: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def is_available() -> bool:
    return _AVAILABLE


def module_count() -> int:
    return len(_FUNCS)


def _coerce_others(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        return ()
    return tuple((str(k), str(v)) for k, v in value.items() if v not in (None, ""))


async def _run_single(func, email: str, client, out: list[dict]) -> None:
    try:
        await func(email=email, client=client, out=out)
    except Exception as exc:  # pragma: no cover - third-party failure surface
        log.debug("holehe module %s raised: %s", getattr(func, "__name__", "?"), exc)


async def check_email(email: str, timeout: float = 10.0) -> list[HoleheHit]:
    """Run every holehe module against *email* and return the confirmed hits.

    Modules that rate-limit, error out, or return ``exists=False`` are dropped.
    Safe to call when holehe is not installed — returns an empty list.
    """
    if not _AVAILABLE or not email or "@" not in email:
        return []
    results: list[dict] = []
    async with httpx.AsyncClient(timeout=timeout) as client:  # type: ignore[operator]
        await asyncio.gather(
            *(_run_single(func, email, client, results) for func in _FUNCS),
            return_exceptions=True,
        )
    hits: list[HoleheHit] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        if not entry.get("exists"):
            continue
        hits.append(
            HoleheHit(
                email=email,
                site=str(entry.get("name", "")),
                domain=str(entry.get("domain", "")),
                method=str(entry.get("method", "") or ""),
                email_recovery=entry.get("emailrecovery") or None,
                phone_recovery=entry.get("phoneNumber") or None,
                others=_coerce_others(entry.get("others")),
            )
        )
    return hits


async def check_emails(
    emails: list[str], timeout: float = 10.0
) -> dict[str, list[HoleheHit]]:
    """Run holehe against many emails in parallel. Returns {email: hits}."""
    emails = [e for e in emails if e and "@" in e]
    if not emails or not _AVAILABLE:
        return {email: [] for email in emails}
    results = await asyncio.gather(
        *(check_email(email, timeout=timeout) for email in emails),
        return_exceptions=True,
    )
    out: dict[str, list[HoleheHit]] = {}
    for email, res in zip(emails, results, strict=True):
        out[email] = res if isinstance(res, list) else []
    return out
