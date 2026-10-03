"""Case-scoped analyst decisions and durable, transactionally bounded pivots."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from core import cases

MAX_CASE_PIVOTS = 10
MAX_CASE_REQUESTS = 120

_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_edge_reviews (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    edge_id TEXT NOT NULL, decision TEXT NOT NULL, note TEXT NOT NULL,
    author TEXT NOT NULL, updated_ts INTEGER NOT NULL,
    PRIMARY KEY (case_id, edge_id)
);
CREATE TABLE IF NOT EXISTS case_pivots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    username TEXT NOT NULL, lead_id TEXT NOT NULL, source_scan_id INTEGER NOT NULL,
    depth INTEGER NOT NULL, request_budget INTEGER NOT NULL,
    platforms TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'reserved',
    job_id TEXT, scan_id INTEGER, created_ts INTEGER NOT NULL,
    UNIQUE(case_id, username)
);
"""


def _connect(db_path: Path | None) -> sqlite3.Connection:
    conn = cases._connect(db_path or cases.DEFAULT_DB_PATH)
    conn.executescript(_SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


def reviews(case_id: int, *, db_path: Path | None = None) -> dict[str, dict]:
    conn = _connect(db_path)
    try:
        return {
            row["edge_id"]: dict(row)
            for row in conn.execute("SELECT * FROM case_edge_reviews WHERE case_id = ?", (case_id,))
        }
    finally:
        conn.close()


def save_review(
    case_id: int,
    edge_id: str,
    decision: str,
    note: str,
    author: str,
    *,
    db_path: Path | None = None,
) -> dict:
    if decision not in {"accepted", "rejected", "unreviewed"}:
        raise ValueError("invalid analyst decision")
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO case_edge_reviews VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(case_id, edge_id) DO UPDATE SET decision=excluded.decision, "
            "note=excluded.note, author=excluded.author, updated_ts=excluded.updated_ts",
            (case_id, edge_id, decision, note[:2000], author, int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()
    return reviews(case_id, db_path=db_path)[edge_id]


def pivots(case_id: int, *, db_path: Path | None = None) -> list[dict]:
    conn = _connect(db_path)
    try:
        return [
            {**dict(row), "platforms": json.loads(row["platforms"])}
            for row in conn.execute(
                "SELECT * FROM case_pivots WHERE case_id = ? ORDER BY id", (case_id,)
            )
        ]
    finally:
        conn.close()


def reserve_pivot(
    case_id: int, lead: dict, platforms: list[str], budget: int, *, db_path: Path | None = None
) -> int:
    if not lead.get("eligible") or not 1 <= lead["depth"] <= 2:
        raise ValueError("lead depth is outside the allowed scope")
    if not 1 <= budget <= 20:
        raise ValueError("pivot request budget must be between 1 and 20")
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None or row["status"] != "open":
            raise ValueError("pivot requires an open case")
        count, total = conn.execute(
            "SELECT count(*), coalesce(sum(request_budget), 0) FROM case_pivots WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if count >= MAX_CASE_PIVOTS or total + budget > MAX_CASE_REQUESTS:
            raise ValueError("case pivot budget exhausted")
        cursor = conn.execute(
            "INSERT INTO case_pivots (case_id, username, lead_id, source_scan_id, depth, request_budget, platforms, created_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                lead["username"].casefold(),
                lead["id"],
                lead["source_scan_id"],
                lead["depth"],
                budget,
                json.dumps(platforms),
                int(time.time()),
            ),
        )
        conn.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("database did not return a pivot id")
        return cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError("lead already reserved or case missing") from exc
    finally:
        conn.close()


def update_pivot(
    pivot_id: int,
    *,
    status: str,
    job_id: str | None = None,
    scan_id: int | None = None,
    db_path: Path | None = None,
) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE case_pivots SET status=?, job_id=coalesce(?,job_id), scan_id=coalesce(?,scan_id) WHERE id=?",
            (status, job_id, scan_id, pivot_id),
        )
        conn.commit()
    finally:
        conn.close()


def release_unstarted(pivot_id: int, *, db_path: Path | None = None) -> None:
    """Release only an unstarted reservation when no job was accepted."""
    conn = _connect(db_path)
    try:
        conn.execute(
            "DELETE FROM case_pivots WHERE id=? AND status='reserved' AND job_id IS NULL",
            (pivot_id,),
        )
        conn.commit()
    finally:
        conn.close()


def budget_summary(rows: list[dict]) -> dict[str, Any]:
    return {
        "max_pivots": MAX_CASE_PIVOTS,
        "max_requests": MAX_CASE_REQUESTS,
        "reserved_pivots": len(rows),
        "reserved_requests": sum(r["request_budget"] for r in rows),
    }
