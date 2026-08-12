"""GHunt wrapper — Google account OSINT from an email address.

GHunt resolves a Gmail address to a Gaia ID and then walks several Google
people-graph APIs to harvest the public profile (display name, profile
picture, custom cover, last edit timestamps, linked YouTube/Maps activity).
The upstream tool is interactive and writes to its own Rich console; we
bypass that by calling :func:`PeoplePaHttp.people_lookup` directly with a
pre-loaded :class:`GHuntCreds` object.

Usage requires a one-time login:

    ghunt login

This stores OAuth cookies under ``~/.malfrats/ghunt/creds.m``. We detect that
file and skip the lookup gracefully when it is missing — the rest of the scan
is unaffected.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from core.logging_setup import get_logger

log = get_logger(__name__)

CREDS_PATH = Path.home() / ".malfrats" / "ghunt" / "creds.m"

try:  # pragma: no cover - import guard
    import httpx
    from ghunt.apis.peoplepa import PeoplePaHttp
    from ghunt.helpers import auth as _ghunt_auth

    _AVAILABLE = True
except Exception as exc:  # pragma: no cover - import guard
    log.debug("ghunt unavailable: %s", exc)
    httpx = None  # type: ignore[assignment]
    _AVAILABLE = False


@dataclass(frozen=True)
class GHuntResult:
    email: str
    gaia_id: str = ""
    name: str = ""
    profile_picture: str = ""
    cover_picture: str = ""
    last_edit: str = ""
    container_types: tuple[str, ...] = field(default_factory=tuple)
    services: tuple[str, ...] = field(default_factory=tuple)


def is_available() -> bool:
    return _AVAILABLE and CREDS_PATH.is_file()


def _safe_str(obj: object) -> str:
    if obj is None:
        return ""
    return str(obj)


async def lookup_email(email: str, timeout: float = 15.0) -> GHuntResult | None:
    """Resolve a Google account from an email. Returns ``None`` on any failure.

    The function never raises; it logs at debug level and falls through.
    Authentication state and creds are loaded once per call — for batch use
    prefer :func:`lookup_emails`.
    """
    if not is_available() or "@" not in email:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:  # type: ignore[operator]
            creds = await _ghunt_auth.load_and_auth(client)
            people_pa = PeoplePaHttp(creds)
            is_found, target = await people_pa.people_lookup(
                client, email, params_template="max_details"
            )
    except SystemExit:
        # Upstream sometimes calls exit() on failure paths. Swallow it.
        log.debug("ghunt called exit() for %s", email)
        return None
    except Exception as exc:
        log.debug("ghunt lookup failed for %s: %s", email, exc)
        return None
    if not is_found or not target:
        return None

    container = "PROFILE"
    name = ""
    if container in getattr(target, "names", {}):
        name = _safe_str(target.names[container].fullname)
    profile_pic = ""
    if container in getattr(target, "profilePhotos", {}):
        photo = target.profilePhotos[container]
        if not getattr(photo, "isDefault", True):
            profile_pic = _safe_str(getattr(photo, "url", ""))
    cover_pic = ""
    if container in getattr(target, "coverPhotos", {}):
        cover = target.coverPhotos[container]
        if not getattr(cover, "isDefault", True):
            cover_pic = _safe_str(getattr(cover, "url", ""))
    last_edit = ""
    if container in getattr(target, "sourceIds", {}):
        last_edit = _safe_str(getattr(target.sourceIds[container], "lastUpdated", ""))

    return GHuntResult(
        email=email,
        gaia_id=_safe_str(getattr(target, "personId", "")),
        name=name,
        profile_picture=profile_pic,
        cover_picture=cover_pic,
        last_edit=last_edit,
        container_types=tuple(sorted(getattr(target, "sourceIds", {}).keys())),
        services=tuple(),
    )


async def lookup_emails(emails: list[str]) -> dict[str, GHuntResult]:
    """Run lookup_email for many addresses in parallel; skips empty results."""
    emails = [e for e in emails if e and "@" in e]
    if not emails or not is_available():
        return {}
    results = await asyncio.gather(
        *(lookup_email(e) for e in emails), return_exceptions=True
    )
    out: dict[str, GHuntResult] = {}
    for email, res in zip(emails, results, strict=True):
        if isinstance(res, GHuntResult):
            out[email] = res
    return out
