"""Breach checking across multiple sources.

Primary: Have I Been Pwned (HIBP v3) — requires paid API key.
Free fallback: XposedOrNot — free public API, no key, 830+ breaches.

Both sources are queried when available; results are merged and deduped
by breach name so the user always gets the widest possible coverage.

API key is read at call time from the environment so runtime-loaded
.env files or test overrides work correctly.
"""

from __future__ import annotations

import asyncio
import hashlib
import os

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)


def _api_key() -> str:
    return os.environ.get("HIBP_API_KEY", "").strip()


def hibp_available() -> bool:
    return bool(_api_key())


def breach_check_available() -> bool:
    """XposedOrNot is always available; HIBP is a paid bonus."""
    return True


async def check_email_breaches(client: HTTPClient, email: str) -> list[dict]:
    key = _api_key()
    if not key:
        return []
    headers = {
        "hibp-api-key": key,
        "User-Agent": "open-source-intelligence",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        status, data, _ = await client.get_json(url, headers=headers)
    except Exception as exc:  # network-layer failure
        log.warning("HIBP request failed for %s: %s", email, exc)
        return []
    if status != 200 or not data:
        return []

    return [
        {
            "name": b.get("Name", ""),
            "title": b.get("Title", ""),
            "domain": b.get("Domain", ""),
            "breach_date": b.get("BreachDate", ""),
            "added_date": b.get("AddedDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "verified": b.get("IsVerified", False),
        }
        for b in data
    ]


async def check_email_xposedornot(client: HTTPClient, email: str) -> list[dict]:
    """Free public breach lookup — no API key required.

    XposedOrNot indexes 830+ breaches and returns a flat list of names.
    We upgrade each name to a dict shape matching HIBP for downstream code.
    """
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        status, data, _ = await client.get_json(url)
    except Exception as exc:
        log.debug("XposedOrNot request failed for %s: %s", email, exc)
        return []
    if status != 200 or not isinstance(data, dict):
        return []
    raw = data.get("breaches") or []
    # API returns [[name1, name2, ...]] or {"breaches":[["name1",...]]}
    names: list[str] = []
    if raw and isinstance(raw[0], list):
        names = [n for n in raw[0] if isinstance(n, str)]
    elif raw and isinstance(raw[0], str):
        names = [n for n in raw if isinstance(n, str)]

    return [
        {
            "name": name,
            "title": name,
            "domain": "",
            "breach_date": "",
            "added_date": "",
            "pwn_count": 0,
            "data_classes": [],
            "verified": True,
            "source": "xposedornot",
        }
        for name in names
    ]


def _merge_breaches(*lists: list[dict]) -> list[dict]:
    """Dedupe by lowercased breach name; HIBP fields override free sources."""
    merged: dict[str, dict] = {}
    for breaches in lists:
        for b in breaches:
            key = (b.get("name") or b.get("title") or "").strip().lower()
            if not key:
                continue
            if key in merged:
                # Prefer whichever entry has the richer HIBP metadata.
                existing = merged[key]
                if existing.get("source") == "xposedornot" and "source" not in b:
                    merged[key] = b
            else:
                merged[key] = b
    return list(merged.values())


async def check_many_emails(
    client: HTTPClient, emails: list[str]
) -> dict[str, list[dict]]:
    """Run breach lookups concurrently and return {email: breaches}.

    Queries HIBP (if key set) and XposedOrNot in parallel for every email,
    then merges and dedupes per address.
    """
    if not emails:
        return {}

    hibp_on = hibp_available()
    tasks = []
    for email in emails:
        tasks.append(check_email_xposedornot(client, email))
        if hibp_on:
            tasks.append(check_email_breaches(client, email))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    stride = 2 if hibp_on else 1
    out: dict[str, list[dict]] = {}
    for idx, email in enumerate(emails):
        base = idx * stride
        xpo = results[base]
        hibp = results[base + 1] if hibp_on else []
        xpo_list = xpo if isinstance(xpo, list) else []
        hibp_list = hibp if isinstance(hibp, list) else []
        if isinstance(xpo, BaseException):
            log.debug("xposedornot raised for %s: %s", email, xpo)
        if hibp_on and isinstance(hibp, BaseException):
            log.debug("hibp raised for %s: %s", email, hibp)
        out[email] = _merge_breaches(xpo_list, hibp_list)
    return out


async def check_password_pwned(client: HTTPClient, password: str) -> int:
    """K-anonymity password check. Returns breach count."""
    sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        status, body, _ = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    except Exception as exc:
        log.warning("pwned-passwords lookup failed: %s", exc)
        return 0
    if status != 200:
        return 0
    for line in body.splitlines():
        if ":" in line:
            h, count = line.strip().split(":")
            if h == suffix:
                try:
                    return int(count)
                except ValueError:
                    return 0
    return 0
