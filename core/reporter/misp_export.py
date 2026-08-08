"""MISP event export.

Produces a single MISP Event JSON file compatible with ``misp-modules``
and the MISP REST API. The event contains one attribute per:

* platform profile URL → ``url`` attribute
* discovered email → ``email-src`` attribute
* crypto address → ``btc`` / ``eth`` attribute
* phone number → ``phone-number`` attribute
* historical alias → ``text`` attribute tagged ``aka``

Each attribute is grouped under an Object where it makes sense, but
MISP is tolerant of flat attribute lists, so we emit flat for
simplicity. Comments carry the originating source for traceability.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from core.models import ScanResult


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _attr(category: str, type_: str, value: str, comment: str = "") -> dict[str, Any]:
    return {
        "category": category,
        "type": type_,
        "value": value,
        "to_ids": False,
        "distribution": "0",
        "comment": comment,
    }


def build_misp_event(result: ScanResult) -> dict[str, Any]:
    attrs: list[dict[str, Any]] = []

    attrs.append(
        _attr(
            "External analysis",
            "text",
            result.username,
            comment="queried username",
        )
    )

    for p in result.platforms:
        if not p.exists:
            continue
        attrs.append(
            _attr(
                "Network activity",
                "url",
                p.url,
                comment=f"profile on {p.platform}",
            )
        )

    for e in result.emails:
        attrs.append(
            _attr(
                "Payload delivery",
                "email-src",
                e.email,
                comment=f"source: {e.source}",
            )
        )
        for breach in e.breaches or []:
            attrs.append(
                _attr(
                    "External analysis",
                    "text",
                    f"breach:{breach}",
                    comment=f"breach for {e.email}",
                )
            )

    for phone in result.phone_intel or []:
        value = getattr(phone, "e164", "") or getattr(phone, "raw", "")
        if value:
            attrs.append(
                _attr(
                    "Social network",
                    "phone-number",
                    value,
                    comment=getattr(phone, "country_name", ""),
                )
            )

    for crypto in result.crypto_intel or []:
        addr = getattr(crypto, "address", "")
        chain = getattr(crypto, "chain", "")
        if not addr:
            continue
        attr_type = {"btc": "btc", "eth": "eth"}.get(chain, "text")
        attrs.append(
            _attr(
                "Financial fraud",
                attr_type,
                addr,
                comment=f"chain:{chain} balance:{getattr(crypto, 'balance', 0)}",
            )
        )

    for alias in result.historical_usernames or []:
        username = getattr(alias, "username", "")
        if username:
            attrs.append(
                _attr(
                    "External analysis",
                    "text",
                    f"aka:{username}",
                    comment=f"{getattr(alias, 'platform', '')} "
                    f"({getattr(alias, 'snapshot_count', 0)} snapshots)",
                )
            )

    event = {
        "Event": {
            "info": f"OSINT sweep for {result.username}",
            "date": _ts(),
            "threat_level_id": "4",  # undefined
            "analysis": "1",          # ongoing
            "distribution": "0",      # your organization only
            "published": False,
            "Tag": [
                {"name": "osint:source=\"open-source-intelligence\""},
                {"name": f"osint:username=\"{result.username}\""},
            ],
            "Attribute": attrs,
        }
    }
    return event


def export_misp(result: ScanResult, filepath: str) -> None:
    event = build_misp_event(result)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2, ensure_ascii=False)
