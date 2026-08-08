"""PDF export for scan results.

Uses ``reportlab`` when installed; without it we raise a clear
:class:`RuntimeError` instructing the user to install it. We keep the
PDF deliberately simple — a title page with the summary followed by
tables for each evidence section — so it renders on any reportlab
version without pulling in its optional dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.models import ScanResult

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _AVAILABLE = True
except ImportError:  # pragma: no cover - optional dep
    _AVAILABLE = False


def is_available() -> bool:
    return _AVAILABLE


def _section_table(rows: list[list[str]], header: list[str]) -> Any:
    data = [header] + rows
    table = Table(data, hAlign="LEFT", repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]
        )
    )
    return table


def export_pdf(result: ScanResult, filepath: str) -> None:
    if not _AVAILABLE:
        raise RuntimeError(
            "PDF export requires 'reportlab'. Install it with: pip install reportlab"
        )

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        title=f"OSINT sweep — {result.username}",
        author="open-source-intelligence",
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []

    story.append(Paragraph(f"OSINT sweep — <b>{result.username}</b>", styles["Title"]))
    story.append(
        Paragraph(
            datetime.now(tz=timezone.utc).strftime("Generated %Y-%m-%d %H:%M UTC"),
            styles["Italic"],
        )
    )
    story.append(Spacer(1, 12))

    summary = (
        f"<b>{result.found_count}</b> confirmed profiles out of "
        f"<b>{result.total_checked}</b> platforms checked. "
        f"<b>{len(result.emails)}</b> emails, "
        f"<b>{len(result.phone_intel or [])}</b> phones, "
        f"<b>{len(result.crypto_intel or [])}</b> crypto addresses."
    )
    story.append(Paragraph(summary, styles["BodyText"]))
    story.append(Spacer(1, 12))

    # Profiles
    profiles = [
        [p.platform, p.url, p.category, f"{getattr(p, 'confidence', 0.0):.2f}"]
        for p in result.platforms
        if p.exists
    ]
    if profiles:
        story.append(Paragraph("<b>Profiles</b>", styles["Heading2"]))
        story.append(
            _section_table(profiles, ["Platform", "URL", "Category", "Conf."])
        )
        story.append(Spacer(1, 12))

    # Emails
    emails = [
        [e.email, e.source, "yes" if e.verified else "no", str(len(e.breaches or []))]
        for e in result.emails
    ]
    if emails:
        story.append(Paragraph("<b>Emails</b>", styles["Heading2"]))
        story.append(_section_table(emails, ["Email", "Source", "Verified", "Breaches"]))
        story.append(Spacer(1, 12))

    # Phones
    phones = [
        [
            getattr(p, "e164", "") or getattr(p, "raw", ""),
            getattr(p, "country_name", ""),
            getattr(p, "carrier", ""),
            getattr(p, "line_type", ""),
        ]
        for p in (result.phone_intel or [])
    ]
    if phones:
        story.append(Paragraph("<b>Phones</b>", styles["Heading2"]))
        story.append(_section_table(phones, ["Number", "Country", "Carrier", "Line"]))
        story.append(Spacer(1, 12))

    # Crypto
    crypto = [
        [
            getattr(c, "address", ""),
            getattr(c, "chain", ""),
            f"{getattr(c, 'balance', 0.0):.6f}",
            str(getattr(c, "tx_count", 0)),
        ]
        for c in (result.crypto_intel or [])
    ]
    if crypto:
        story.append(Paragraph("<b>Crypto</b>", styles["Heading2"]))
        story.append(_section_table(crypto, ["Address", "Chain", "Balance", "Tx"]))
        story.append(Spacer(1, 12))

    doc.build(story)
