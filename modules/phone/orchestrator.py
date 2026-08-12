"""Phone OSINT orchestrator — merges offline + NumVerify results."""

from __future__ import annotations

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.phone import numverify, offline
from modules.phone.models import PhoneIntel

log = get_logger(__name__)


async def lookup_phone(
    client: HTTPClient,
    raw: str,
    *,
    default_region: str | None = None,
) -> PhoneIntel | None:
    """Return a :class:`PhoneIntel` for ``raw`` or ``None`` if unparsable."""
    meta = offline.parse_offline(raw, default_region=default_region)
    if not meta:
        return None

    sources = ["phonenumbers"]
    extra = {}
    try:
        nv = await numverify.enrich(client, meta.get("e164", ""))
    except Exception as exc:
        log.debug("numverify failed: %s", exc)
        nv = {}

    if nv:
        sources.append("numverify")
        # Prefer NumVerify carrier/line_type when it provides a value —
        # the offline carrier DB is sparse for non-mobile lines.
        if nv.get("carrier"):
            meta["carrier"] = nv["carrier"]
        if nv.get("line_type"):
            meta["line_type"] = nv["line_type"]
        if nv.get("country_name") and not meta.get("country_name"):
            meta["country_name"] = nv["country_name"]
        extra = {"location": nv.get("location", "")}

    return PhoneIntel(
        raw=raw,
        e164=meta.get("e164", ""),
        national=meta.get("national", ""),
        country_code=int(meta.get("country_code") or 0),
        region=meta.get("region", ""),
        country_name=meta.get("country_name", ""),
        carrier=meta.get("carrier", ""),
        timezones=tuple(meta.get("timezones") or ()),
        line_type=meta.get("line_type", ""),
        valid=bool(meta.get("valid")),
        possible=bool(meta.get("possible")),
        sources=tuple(sources),
        metadata=extra,
    )
