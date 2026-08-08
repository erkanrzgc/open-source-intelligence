"""Investigation case manager.

A case groups related artifacts — scans, notes, bookmarks — under one
workstream so an analyst working on a single suspect or incident can
keep context together instead of scattering it across bare scan
history. SQLite-backed, same default DB file as the watchlist but in
its own tables so either store can be reset without touching the other.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "open-source-intelligence" / "cases.sqlite3"

VALID_STATUSES = frozenset({"open", "closed", "archived"})
VALID_BOOKMARK_TYPES = frozenset(
    {"scan", "platform", "email", "phone", "wallet", "url", "note"}
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open',
    tags        TEXT    NOT NULL DEFAULT '[]',
    created_ts  INTEGER NOT NULL,
    updated_ts  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_name ON cases(name);

CREATE TABLE IF NOT EXISTS case_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    body       TEXT    NOT NULL,
    author     TEXT    NOT NULL DEFAULT '',
    created_ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);

CREATE TABLE IF NOT EXISTS case_bookmarks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    target_type   TEXT    NOT NULL,
    target_value  TEXT    NOT NULL,
    label         TEXT    NOT NULL DEFAULT '',
    tags          TEXT    NOT NULL DEFAULT '[]',
    scan_id       INTEGER,
    created_ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_bookmarks_case ON case_bookmarks(case_id);
"""


@dataclass
class Case:
    id: int
    name: str
    description: str
    status: str
    tags: list[str]
    created_ts: int
    updated_ts: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "tags": list(self.tags),
            "created_ts": self.created_ts,
            "updated_ts": self.updated_ts,
        }


@dataclass
class CaseNote:
    id: int
    case_id: int
    body: str
    author: str
    created_ts: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "body": self.body,
            "author": self.author,
            "created_ts": self.created_ts,
        }


@dataclass
class CaseBookmark:
    id: int
    case_id: int
    target_type: str
    target_value: str
    label: str
    tags: list[str]
    scan_id: int | None
    created_ts: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "target_type": self.target_type,
            "target_value": self.target_value,
            "label": self.label,
            "tags": list(self.tags),
            "scan_id": self.scan_id,
            "created_ts": self.created_ts,
        }


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def _now() -> int:
    return int(time.time())


def _row_to_case(row: tuple) -> Case:
    return Case(
        id=row[0],
        name=row[1],
        description=row[2] or "",
        status=row[3],
        tags=json.loads(row[4] or "[]"),
        created_ts=row[5],
        updated_ts=row[6],
    )


def _row_to_note(row: tuple) -> CaseNote:
    return CaseNote(
        id=row[0],
        case_id=row[1],
        body=row[2],
        author=row[3] or "",
        created_ts=row[4],
    )


def _row_to_bookmark(row: tuple) -> CaseBookmark:
    return CaseBookmark(
        id=row[0],
        case_id=row[1],
        target_type=row[2],
        target_value=row[3],
        label=row[4] or "",
        tags=json.loads(row[5] or "[]"),
        scan_id=row[6],
        created_ts=row[7],
    )


# ── case CRUD ────────────────────────────────────────────────────────


def create_case(
    name: str,
    *,
    description: str = "",
    tags: list[str] | None = None,
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> Case:
    clean = (name or "").strip()
    if not clean:
        raise ValueError("case name must be non-empty")
    stamp = ts if ts is not None else _now()
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO cases (name, description, status, tags, created_ts, updated_ts) "
            "VALUES (?, ?, 'open', ?, ?, ?)",
            (clean, description, json.dumps(tags or []), stamp, stamp),
        )
        conn.commit()
        case_id = cur.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"case {clean!r} already exists") from exc
    finally:
        conn.close()
    assert case_id is not None
    return Case(
        id=case_id,
        name=clean,
        description=description,
        status="open",
        tags=list(tags or []),
        created_ts=stamp,
        updated_ts=stamp,
    )


def get_case(case_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> Case | None:
    if not db_path.exists():
        return None
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT id, name, description, status, tags, created_ts, updated_ts "
            "FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_case(row) if row else None


def list_cases(*, db_path: Path = DEFAULT_DB_PATH) -> list[Case]:
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, name, description, status, tags, created_ts, updated_ts "
            "FROM cases ORDER BY created_ts DESC, id DESC"
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_case(r) for r in rows]


def update_case(
    case_id: int,
    *,
    description: str | None = None,
    status: str | None = None,
    tags: list[str] | None = None,
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> Case | None:
    if status is not None and status not in VALID_STATUSES:
        raise ValueError(
            f"status must be one of {sorted(VALID_STATUSES)}, got {status!r}"
        )
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT id, name, description, status, tags, created_ts, updated_ts "
            "FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()
        if row is None:
            return None
        existing = _row_to_case(row)
        new_description = description if description is not None else existing.description
        new_status = status if status is not None else existing.status
        new_tags = tags if tags is not None else existing.tags
        stamp = ts if ts is not None else _now()
        conn.execute(
            "UPDATE cases SET description = ?, status = ?, tags = ?, updated_ts = ? "
            "WHERE id = ?",
            (new_description, new_status, json.dumps(new_tags), stamp, case_id),
        )
        conn.commit()
    finally:
        conn.close()
    return Case(
        id=existing.id,
        name=existing.name,
        description=new_description,
        status=new_status,
        tags=list(new_tags),
        created_ts=existing.created_ts,
        updated_ts=stamp,
    )


def delete_case(case_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> bool:
    if not db_path.exists():
        return False
    conn = _connect(db_path)
    try:
        cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ── notes ───────────────────────────────────────────────────────────


def add_note(
    case_id: int,
    body: str,
    *,
    author: str = "",
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> CaseNote:
    clean = (body or "").strip()
    if not clean:
        raise ValueError("note body must be non-empty")
    stamp = ts if ts is not None else _now()
    conn = _connect(db_path)
    try:
        exists = conn.execute(
            "SELECT 1 FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if exists is None:
            raise ValueError(f"case {case_id} does not exist")
        cur = conn.execute(
            "INSERT INTO case_notes (case_id, body, author, created_ts) "
            "VALUES (?, ?, ?, ?)",
            (case_id, clean, author, stamp),
        )
        conn.commit()
        note_id = cur.lastrowid
    finally:
        conn.close()
    assert note_id is not None
    return CaseNote(
        id=note_id,
        case_id=case_id,
        body=clean,
        author=author,
        created_ts=stamp,
    )


def list_notes(
    case_id: int, *, db_path: Path = DEFAULT_DB_PATH
) -> list[CaseNote]:
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, case_id, body, author, created_ts FROM case_notes "
            "WHERE case_id = ? ORDER BY created_ts DESC, id DESC",
            (case_id,),
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_note(r) for r in rows]


def delete_note(note_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> bool:
    if not db_path.exists():
        return False
    conn = _connect(db_path)
    try:
        cur = conn.execute("DELETE FROM case_notes WHERE id = ?", (note_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ── bookmarks ──────────────────────────────────────────────────────


def add_bookmark(
    case_id: int,
    *,
    target_type: str,
    target_value: str,
    label: str = "",
    tags: list[str] | None = None,
    scan_id: int | None = None,
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> CaseBookmark:
    if target_type not in VALID_BOOKMARK_TYPES:
        raise ValueError(
            f"target_type must be one of {sorted(VALID_BOOKMARK_TYPES)}, "
            f"got {target_type!r}"
        )
    clean_value = (target_value or "").strip()
    if not clean_value:
        raise ValueError("target_value must be non-empty")
    stamp = ts if ts is not None else _now()
    conn = _connect(db_path)
    try:
        exists = conn.execute(
            "SELECT 1 FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if exists is None:
            raise ValueError(f"case {case_id} does not exist")
        cur = conn.execute(
            "INSERT INTO case_bookmarks "
            "(case_id, target_type, target_value, label, tags, scan_id, created_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                target_type,
                clean_value,
                label,
                json.dumps(tags or []),
                scan_id,
                stamp,
            ),
        )
        conn.commit()
        bm_id = cur.lastrowid
    finally:
        conn.close()
    assert bm_id is not None
    return CaseBookmark(
        id=bm_id,
        case_id=case_id,
        target_type=target_type,
        target_value=clean_value,
        label=label,
        tags=list(tags or []),
        scan_id=scan_id,
        created_ts=stamp,
    )


def list_bookmarks(
    case_id: int, *, db_path: Path = DEFAULT_DB_PATH
) -> list[CaseBookmark]:
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, case_id, target_type, target_value, label, tags, "
            "scan_id, created_ts FROM case_bookmarks "
            "WHERE case_id = ? ORDER BY created_ts DESC, id DESC",
            (case_id,),
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_bookmark(r) for r in rows]


def delete_bookmark(bookmark_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> bool:
    if not db_path.exists():
        return False
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "DELETE FROM case_bookmarks WHERE id = ?", (bookmark_id,)
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
