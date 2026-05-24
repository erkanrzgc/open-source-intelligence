"""CSV / XLSX exports for scan results.

Each scan has several heterogeneous sections (platforms, emails,
breaches, phones, crypto, geo). A single flat CSV cannot represent
that without losing structure, so ``export_csv`` writes a ``.zip``
bundle with one CSV per section. ``export_xlsx`` writes the same
sections as separate sheets of a workbook (requires ``openpyxl``).
"""

from __future__ import annotations

import csv
import io
import zipfile
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from core.models import ScanResult
from core.reporter.console_ui import console

try:
    from openpyxl import Workbook

    _XLSX_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dep
    _XLSX_AVAILABLE = False


def xlsx_available() -> bool:
    return _XLSX_AVAILABLE


Section = tuple[str, list[str], list[list[Any]]]  # (name, header, rows)


def _fmt(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (list, tuple, set, frozenset)):
        return "; ".join(_fmt(v) for v in val)
    if isinstance(val, dict):
        return "; ".join(f"{k}={_fmt(v)}" for k, v in val.items())
    return str(val)


def _platform_rows(result: ScanResult) -> list[list[Any]]:
    return [
        [
            p.platform,
            p.category,
            p.url,
            p.exists,
            p.status,
            round(p.response_time, 3),
            p.http_status,
            round(p.confidence, 3),
            p.rendered,
            p.screenshot_path or "",
        ]
        for p in result.found_platforms
    ]


def _email_rows(result: ScanResult) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for e in result.emails:
        rows.append(
            [
                e.email,
                e.source,
                e.verified,
                e.gravatar,
                e.breach_count,
                "; ".join(_breach_name(b) for b in e.breaches),
            ]
        )
    return rows


def _breach_name(breach: Any) -> str:
    if isinstance(breach, str):
        return breach
    if isinstance(breach, dict):
        return str(breach.get("name") or breach.get("title") or breach)
    name = getattr(breach, "name", None)
    if isinstance(name, str):
        return name
    title = getattr(breach, "title", None)
    if isinstance(title, str):
        return title
    return str(breach)


def _phone_rows(result: ScanResult) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for p in result.phone_intel:
        d = p.to_dict() if hasattr(p, "to_dict") else p
        if not isinstance(d, dict):
            continue
        rows.append(
            [
                d.get("raw") or d.get("number") or "",
                d.get("e164") or "",
                d.get("country") or "",
                d.get("carrier") or "",
                d.get("line_type") or "",
                d.get("source") or "",
            ]
        )
    return rows


def _crypto_rows(result: ScanResult) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for c in result.crypto_intel:
        d = c.to_dict() if hasattr(c, "to_dict") else c
        if not isinstance(d, dict):
            continue
        rows.append(
            [
                d.get("address") or "",
                d.get("chain") or d.get("network") or "",
                d.get("balance") or "",
                d.get("tx_count") or "",
                d.get("source") or "",
            ]
        )
    return rows


def _geo_rows(result: ScanResult) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for g in result.geo_points:
        d = g.to_dict() if hasattr(g, "to_dict") else g
        if not isinstance(d, dict):
            continue
        rows.append(
            [
                d.get("raw") or d.get("location") or "",
                d.get("lat") or "",
                d.get("lon") or "",
                d.get("country") or "",
                d.get("city") or "",
                d.get("source") or "",
            ]
        )
    return rows


def _collect_sections(result: ScanResult) -> list[Section]:
    summary_rows: list[list[Any]] = [
        ["username", result.username],
        ["scan_time_s", round(result.scan_time, 2)],
        ["total_checked", result.total_checked],
        ["found_count", result.found_count],
        ["exported_at", datetime.now(tz=timezone.utc).isoformat()],
    ]
    return [
        ("summary", ["field", "value"], summary_rows),
        (
            "platforms",
            [
                "platform",
                "category",
                "url",
                "exists",
                "status",
                "response_time_s",
                "http_status",
                "confidence",
                "rendered",
                "screenshot_path",
            ],
            _platform_rows(result),
        ),
        (
            "emails",
            ["email", "source", "verified", "gravatar", "breach_count", "breaches"],
            _email_rows(result),
        ),
        (
            "phones",
            ["raw", "e164", "country", "carrier", "line_type", "source"],
            _phone_rows(result),
        ),
        (
            "crypto",
            ["address", "chain", "balance", "tx_count", "source"],
            _crypto_rows(result),
        ),
        (
            "geo",
            ["raw", "lat", "lon", "country", "city", "source"],
            _geo_rows(result),
        ),
    ]


def _write_csv(
    stream: io.TextIOBase, header: list[str], rows: Iterable[list[Any]]
) -> None:
    writer = csv.writer(stream)
    writer.writerow(header)
    for row in rows:
        writer.writerow([_fmt(v) for v in row])


def export_csv(result: ScanResult, filepath: str) -> None:
    """Write a ``.zip`` bundle with one CSV per section.

    If ``filepath`` ends with ``.csv`` we still produce a zip (renamed
    transparently) so callers always get a structured archive.
    """
    path = filepath if filepath.endswith(".zip") else _swap_ext(filepath, ".zip")
    sections = _collect_sections(result)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, header, rows in sections:
            buf = io.StringIO()
            _write_csv(buf, header, rows)
            zf.writestr(f"{name}.csv", buf.getvalue())
    console.print(f"\n  [green]CSV bundle kaydedildi:[/green] {path}")


def export_xlsx(result: ScanResult, filepath: str) -> None:
    if not _XLSX_AVAILABLE:
        raise RuntimeError(
            "XLSX export requires 'openpyxl'. Install it with: pip install openpyxl"
        )
    wb = Workbook()
    active = wb.active
    if active is not None:
        wb.remove(active)  # type: ignore[arg-type]  # Drop the default blank sheet.
    for name, header, rows in _collect_sections(result):
        ws = wb.create_sheet(title=name[:31])  # Excel caps sheet names at 31.
        ws.append(header)
        for row in rows:
            ws.append([_fmt(v) for v in row])
    wb.save(filepath)
    console.print(f"\n  [green]XLSX rapor kaydedildi:[/green] {filepath}")


def _swap_ext(path: str, new_ext: str) -> str:
    dot = path.rfind(".")
    slash = max(path.rfind("/"), path.rfind("\\"))
    if dot <= slash:
        return path + new_ext
    return path[:dot] + new_ext
