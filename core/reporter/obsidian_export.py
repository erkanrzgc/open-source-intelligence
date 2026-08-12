"""Obsidian-style markdown vault export.

Produces a small folder with one note per discovered entity and a
``MOC.md`` (map-of-content) root note that wikilinks them. The layout::

    vault/
    ├── MOC.md                  # index for the whole sweep
    ├── alice.md                # the identity note
    ├── profiles/GitHub.md
    ├── profiles/Twitter.md
    ├── emails/alice@x.md
    ├── phones/+14155552671.md
    ├── crypto/0xabc.md
    └── aliases/alice_old.md

All internal links use ``[[wikilink]]`` syntax so Obsidian picks up
the graph view automatically. Filenames are sanitised to strip
characters Windows and macOS dislike.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.models import ScanResult

_BAD_FILENAME = re.compile(r"[^A-Za-z0-9._@+\-]+")


def _safe(name: str, *, fallback: str = "item") -> str:
    cleaned = _BAD_FILENAME.sub("_", name).strip("._")
    return cleaned or fallback


def _write_note(root: Path, rel: str, title: str, body: str) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    content = f"# {title}\n\n{body.rstrip()}\n"
    path.write_text(content, encoding="utf-8")
    return rel


def _link(rel: str) -> str:
    # Obsidian wikilinks use the file stem (or the relative path
    # without extension). Strip the ``.md`` so graph view works.
    return f"[[{rel[:-3] if rel.endswith('.md') else rel}]]"


def _bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "_(none)_"


def export_obsidian(result: ScanResult, directory: str) -> list[str]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    identity_rel = f"{_safe(result.username)}.md"

    # ── Profiles ────────────────────────────────────────────────
    profile_links: list[str] = []
    for p in result.platforms:
        if not p.exists:
            continue
        rel = f"profiles/{_safe(p.platform)}.md"
        body_lines = [
            f"- **URL:** {p.url}",
            f"- **Category:** {p.category}",
            f"- **Confidence:** {getattr(p, 'confidence', 0.0):.2f}",
            f"- **Status:** {p.status}",
            "",
            f"Back to {_link(identity_rel)}",
        ]
        _write_note(root, rel, p.platform, "\n".join(body_lines))
        profile_links.append(_link(rel))
        written.append(rel)

    # ── Emails ──────────────────────────────────────────────────
    email_links: list[str] = []
    for e in result.emails:
        rel = f"emails/{_safe(e.email)}.md"
        breach_list = _bullet_list([str(b) for b in (e.breaches or [])])
        body = (
            f"- **Source:** {e.source}\n"
            f"- **Verified:** {e.verified}\n"
            f"- **Gravatar:** {getattr(e, 'gravatar', False)}\n\n"
            f"## Breaches\n{breach_list}\n\n"
            f"Back to {_link(identity_rel)}\n"
        )
        _write_note(root, rel, e.email, body)
        email_links.append(_link(rel))
        written.append(rel)

    # ── Phones ──────────────────────────────────────────────────
    phone_links: list[str] = []
    for phone in result.phone_intel or []:
        value = getattr(phone, "e164", "") or getattr(phone, "raw", "")
        if not value:
            continue
        rel = f"phones/{_safe(value)}.md"
        body = (
            f"- **Country:** {getattr(phone, 'country_name', '')}\n"
            f"- **Carrier:** {getattr(phone, 'carrier', '')}\n"
            f"- **Line type:** {getattr(phone, 'line_type', '')}\n"
            f"- **Timezones:** {', '.join(getattr(phone, 'timezones', ()) or ())}\n\n"
            f"Back to {_link(identity_rel)}\n"
        )
        _write_note(root, rel, value, body)
        phone_links.append(_link(rel))
        written.append(rel)

    # ── Crypto ──────────────────────────────────────────────────
    crypto_links: list[str] = []
    for crypto in result.crypto_intel or []:
        addr = getattr(crypto, "address", "")
        if not addr:
            continue
        rel = f"crypto/{_safe(addr)}.md"
        body = (
            f"- **Chain:** {getattr(crypto, 'chain', '')}\n"
            f"- **Balance:** {getattr(crypto, 'balance', 0.0)}\n"
            f"- **Tx count:** {getattr(crypto, 'tx_count', 0)}\n"
            f"- **Source:** {getattr(crypto, 'source', '')}\n\n"
            f"Back to {_link(identity_rel)}\n"
        )
        _write_note(root, rel, addr, body)
        crypto_links.append(_link(rel))
        written.append(rel)

    # ── Historical aliases ──────────────────────────────────────
    alias_links: list[str] = []
    for alias in result.historical_usernames or []:
        username = getattr(alias, "username", "")
        if not username:
            continue
        rel = f"aliases/{_safe(username)}.md"
        body = (
            f"- **Platform:** {getattr(alias, 'platform', '')}\n"
            f"- **First seen:** {getattr(alias, 'first_seen', '')}\n"
            f"- **Last seen:** {getattr(alias, 'last_seen', '')}\n"
            f"- **Snapshots:** {getattr(alias, 'snapshot_count', 0)}\n\n"
            f"Back to {_link(identity_rel)}\n"
        )
        _write_note(root, rel, username, body)
        alias_links.append(_link(rel))
        written.append(rel)

    # ── Identity note ───────────────────────────────────────────
    identity_body = (
        f"## Profiles\n{_bullet_list(profile_links)}\n\n"
        f"## Emails\n{_bullet_list(email_links)}\n\n"
        f"## Phones\n{_bullet_list(phone_links)}\n\n"
        f"## Crypto\n{_bullet_list(crypto_links)}\n\n"
        f"## Aliases\n{_bullet_list(alias_links)}\n"
    )
    _write_note(root, identity_rel, result.username, identity_body)
    written.append(identity_rel)

    # ── MOC root ────────────────────────────────────────────────
    moc_body = (
        f"Map of content for the sweep against {_link(identity_rel)}.\n\n"
        f"- Scanned username: **{result.username}**\n"
        f"- Confirmed profiles: **{result.found_count}** / {result.total_checked}\n"
        f"- Emails: **{len(result.emails)}**\n"
        f"- Phones: **{len(result.phone_intel or [])}**\n"
        f"- Crypto: **{len(result.crypto_intel or [])}**\n"
        f"- Aliases: **{len(result.historical_usernames or [])}**\n"
    )
    _write_note(root, "MOC.md", f"OSINT sweep — {result.username}", moc_body)
    written.append("MOC.md")

    return sorted(written)
