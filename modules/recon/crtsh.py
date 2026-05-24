"""Certificate Transparency intelligence via crt.sh.

The crt.sh JSON endpoint exposes far more than the subdomain list
``modules.dns_lookup.enumerate_subdomains`` already mines from it. This
module returns the full per-entry record (issuing CA, validity dates,
serial number, CT entry timestamp) so callers can pivot on the metadata
itself:

* Fingerprint which CA an organization uses for which infra (Let's
  Encrypt for edge/staging, DigiCert for prod) and notice deviations.
* Pivot on ``entry_timestamp`` to surface very recently-issued certs —
  a strong signal that new infrastructure is coming online.
* Cross-reference still-resolving subdomains against ``not_after`` to
  flag forgotten services protected by long-expired certificates.

No API key, no auth. crt.sh occasionally times out under load — every
failure path degrades to an empty list so optional recon does not abort
the broader scan.
"""

from __future__ import annotations

from typing import Any

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.recon.models import CertificateRecord

log = get_logger(__name__)

_ENDPOINT = "https://crt.sh/?q=%25.{domain}&output=json"
_DETAIL_URL = "https://crt.sh/?id={crtsh_id}"


def _split_names(name_value: str) -> tuple[str, ...]:
    """Split crt.sh's newline-joined SAN list into a deduped lowercase tuple."""
    if not name_value:
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for raw in name_value.split("\n"):
        name = raw.strip().lower().rstrip(".")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return tuple(out)


def _str_field(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    if value is None:
        return ""
    return str(value).strip()


def _parse_entry(entry: Any) -> CertificateRecord | None:
    """Normalize one crt.sh JSON entry into ``CertificateRecord`` or skip."""
    if not isinstance(entry, dict):
        return None

    common_name = _str_field(entry, "common_name").lower()
    name_value = _split_names(_str_field(entry, "name_value"))
    if not (common_name or name_value):
        return None

    crtsh_id = _str_field(entry, "id")
    return CertificateRecord(
        common_name=common_name,
        name_value=name_value,
        issuer_name=_str_field(entry, "issuer_name"),
        not_before=_str_field(entry, "not_before"),
        not_after=_str_field(entry, "not_after"),
        entry_timestamp=_str_field(entry, "entry_timestamp"),
        serial_number=_str_field(entry, "serial_number"),
        crtsh_id=crtsh_id,
        url=_DETAIL_URL.format(crtsh_id=crtsh_id) if crtsh_id else "",
    )


def _dedupe(records: list[CertificateRecord]) -> list[CertificateRecord]:
    """Collapse identical certificates that appear in multiple CT logs.

    Each cert can be logged by several operators, producing multiple crt.sh
    rows with different ``id`` / ``entry_timestamp`` but the same ``(issuer,
    serial)``. When the serial is missing we fall back to ``(common_name,
    not_before)`` so we never silently swallow distinct certs.
    """
    seen: set[tuple[str, str]] = set()
    out: list[CertificateRecord] = []
    for rec in records:
        key = (
            (rec.issuer_name, rec.serial_number)
            if rec.serial_number
            else (rec.common_name, rec.not_before)
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


async def fetch(client: HTTPClient, domain: str) -> list[CertificateRecord]:
    """Query crt.sh for ``%.domain`` and return parsed certificate records.

    Sorted newest first by CT entry timestamp so callers that only look at
    the head of the list see the most recently-issued infrastructure.
    """
    domain = (domain or "").strip().lower().lstrip(".")
    if not domain:
        return []

    url = _ENDPOINT.format(domain=domain)
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, list):
        log.debug("crt.sh fetch returned %s for %s", status, domain)
        return []

    records: list[CertificateRecord] = []
    for entry in data:
        rec = _parse_entry(entry)
        if rec is not None:
            records.append(rec)

    deduped = _dedupe(records)
    deduped.sort(
        key=lambda r: (r.entry_timestamp, r.common_name),
        reverse=True,
    )
    return deduped
