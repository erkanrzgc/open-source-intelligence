"""SQLite-backed watchlist of usernames to monitor.

Separate from :mod:`core.history` on purpose: the history table grows
with every scan, while the watchlist is a small curated set the user
maintains by hand. They share the same DB file by default but live in
distinct tables so either can be reset without touching the other.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "open-source-intelligence" / "watchlist.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS watchlist (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL UNIQUE,
    added_at     INTEGER NOT NULL,
    last_scan_at INTEGER,
    tags         TEXT    NOT NULL DEFAULT '[]',
    notes        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_watchlist_username ON watchlist(username);
"""


@dataclass
class WatchEntry:
    id: int
    username: str
    added_at: int
    last_scan_at: int | None
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "added_at": self.added_at,
            "last_scan_at": self.last_scan_at,
            "tags": list(self.tags),
            "notes": self.notes,
        }


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_entry(row: tuple) -> WatchEntry:
    return WatchEntry(
        id=row[0],
        username=row[1],
        added_at=row[2],
        last_scan_at=row[3],
        tags=json.loads(row[4] or "[]"),
        notes=row[5] or "",
    )


def add(
    username: str,
    *,
    tags: list[str] | None = None,
    notes: str = "",
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> WatchEntry:
    """Add ``username`` to the watchlist. Idempotent — updates tags/notes."""
    if not username or not username.strip():
        raise ValueError("username must be non-empty")
    username = username.strip()
    now = ts if ts is not None else int(time.time())
    tag_json = json.dumps(list(tags or []))

    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO watchlist (username, added_at, tags, notes)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                tags = excluded.tags,
                notes = excluded.notes
            """,
            (username, now, tag_json, notes),
        )
        conn.commit()
        cursor = conn.execute(
            "SELECT id, username, added_at, last_scan_at, tags, notes "
            "FROM watchlist WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        raise RuntimeError("watchlist insert failed")
    return _row_to_entry(row)


def remove(username: str, *, db_path: Path = DEFAULT_DB_PATH) -> bool:
    """Remove ``username``. Returns ``True`` if a row was deleted."""
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "DELETE FROM watchlist WHERE username = ?", (username.strip(),)
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def list_all(*, db_path: Path = DEFAULT_DB_PATH) -> list[WatchEntry]:
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, username, added_at, last_scan_at, tags, notes "
            "FROM watchlist ORDER BY added_at DESC"
        )
        return [_row_to_entry(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def mark_scanned(
    username: str,
    *,
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> None:
    now = ts if ts is not None else int(time.time())
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE watchlist SET last_scan_at = ? WHERE username = ?",
            (now, username.strip()),
        )
        conn.commit()
    finally:
        conn.close()


def get(username: str, *, db_path: Path = DEFAULT_DB_PATH) -> WatchEntry | None:
    if not db_path.exists():
        return None
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, username, added_at, last_scan_at, tags, notes "
            "FROM watchlist WHERE username = ?",
            (username.strip(),),
        )
        row = cursor.fetchone()
    finally:
        conn.close()
    return _row_to_entry(row) if row else None
