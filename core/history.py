"""SQLite-backed history store for scan results.

Stores each completed scan as a JSON blob keyed by (username, timestamp)
so users can list previous runs and diff the set of found platforms
between two scans.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "open-source-intelligence" / "history.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL,
    ts          INTEGER NOT NULL,
    found_count INTEGER NOT NULL,
    payload     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_username_ts ON scans(username, ts DESC);
CREATE TABLE IF NOT EXISTS _migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
"""

# Ordered list of migration SQL statements.
# Append new entries here when schema changes; the version number
# is the 1-based index in this list.
_MIGRATIONS: list[str] = [
    "ALTER TABLE scans ADD COLUMN payload_schema_version TEXT NOT NULL DEFAULT 'legacy';",
]


@dataclass
class HistoryEntry:
    id: int
    username: str
    ts: int
    found_count: int
    payload: dict

    def __post_init__(self) -> None:
        # Payloads predating identity-first alias discovery remain readable.
        self.payload.setdefault("identity_candidates", [])

    @property
    def found_names(self) -> set[str]:
        return {
            p["platform"]
            for p in self.payload.get("platforms", [])
            if p.get("exists")
        }


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    _run_migrations(conn)
    return conn


def _run_migrations(conn: sqlite3.Connection) -> None:
    """Apply any pending schema migrations."""
    applied = set(
        conn.execute("SELECT version FROM _migrations").fetchall()
    )
    for idx, sql in enumerate(_MIGRATIONS, start=1):
        if (idx,) not in applied:
            try:
                conn.executescript(sql)
            except sqlite3.OperationalError as exc:
                # A pre-versioned development database may already contain
                # the column even though it has no migration ledger entry.
                if "duplicate column name" not in str(exc).lower():
                    raise
            conn.execute("INSERT OR IGNORE INTO _migrations (version) VALUES (?)", (idx,))
            conn.commit()
            log.info("history: applied migration %d", idx)


def save_scan(payload: dict, *, ts: int, db_path: Path = DEFAULT_DB_PATH) -> int:
    """Insert a scan row and return its rowid."""
    username = payload.get("username")
    if not isinstance(username, str) or not username:
        raise ValueError("payload must contain non-empty username")
    found_count = int(payload.get("found_count", 0))
    try:
        conn = _connect(db_path)
    except sqlite3.Error as exc:
        log.warning("history: could not open db %s: %s", db_path, exc)
        return -1
    try:
        cur = conn.execute(
            "INSERT INTO scans(username, ts, found_count, payload, payload_schema_version) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                username,
                ts,
                found_count,
                json.dumps(payload, ensure_ascii=False),
                str(payload.get("schema_version") or "legacy"),
            ),
        )
        conn.commit()
        return int(cur.lastrowid or -1)
    except sqlite3.Error as exc:
        log.warning("history: could not save scan to %s: %s", db_path, exc)
        return -1
    finally:
        conn.close()


def update_scan_payload(
    scan_id: int,
    payload: dict,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> bool:
    """Replace the stored JSON payload for an existing scan row."""
    if scan_id <= 0:
        return False
    try:
        conn = _connect(db_path)
    except sqlite3.Error as exc:
        log.warning("history: could not open db %s: %s", db_path, exc)
        return False
    try:
        cursor = conn.execute(
            "UPDATE scans SET found_count = ?, payload = ?, payload_schema_version = ? "
            "WHERE id = ?",
            (
                int(payload.get("found_count", 0)),
                json.dumps(payload, ensure_ascii=False),
                str(payload.get("schema_version") or "legacy"),
                scan_id,
            ),
        )
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as exc:
        log.warning("history: could not update scan %s in %s: %s", scan_id, db_path, exc)
        return False
    finally:
        conn.close()


def list_scans(
    username: str | None = None, *, limit: int = 20,
    username_contains: str | None = None, db_path: Path = DEFAULT_DB_PATH
) -> list[HistoryEntry]:
    """List recent scans, optionally filtering before applying the limit."""
    if limit <= 0 or not db_path.exists():
        return []
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, username, ts, found_count, payload FROM scans "
            "WHERE (? IS NULL OR username = ?) "
            "AND (? IS NULL OR instr(lower(username), lower(?)) > 0) "
            "ORDER BY ts DESC, id DESC LIMIT ?",
            (username, username, username_contains, username_contains, limit),
        ).fetchall()
    finally:
        conn.close()
    return [
        HistoryEntry(
            id=row[0],
            username=row[1],
            ts=row[2],
            found_count=row[3],
            payload=json.loads(row[4]),
        )
        for row in rows
    ]


def get_latest(
    username: str, *, before_id: int | None = None, db_path: Path = DEFAULT_DB_PATH
) -> HistoryEntry | None:
    if not db_path.exists():
        return None
    conn = _connect(db_path)
    try:
        if before_id is None:
            row = conn.execute(
                "SELECT id, username, ts, found_count, payload FROM scans "
                "WHERE username = ? ORDER BY ts DESC, id DESC LIMIT 1",
                (username,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, username, ts, found_count, payload FROM scans "
                "WHERE username = ? AND id < ? ORDER BY ts DESC, id DESC LIMIT 1",
                (username, before_id),
            ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return HistoryEntry(
        id=row[0],
        username=row[1],
        ts=row[2],
        found_count=row[3],
        payload=json.loads(row[4]),
    )


def get_scan(scan_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> HistoryEntry | None:
    """Fetch a single scan by primary key, or None if it's gone."""
    if not db_path.exists():
        return None
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, ts, found_count, payload FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return HistoryEntry(
        id=row[0],
        username=row[1],
        ts=row[2],
        found_count=row[3],
        payload=json.loads(row[4]),
    )


@dataclass
class DiffResult:
    added: list[str]
    removed: list[str]
    unchanged: list[str]


def diff_entries(old: HistoryEntry, new: HistoryEntry) -> DiffResult:
    old_names = old.found_names
    new_names = new.found_names
    return DiffResult(
        added=sorted(new_names - old_names),
        removed=sorted(old_names - new_names),
        unchanged=sorted(old_names & new_names),
    )


def prune_history(max_age_seconds: int, *, db_path: Path = DEFAULT_DB_PATH) -> int:
    """Delete scans older than max_age_seconds from now. Returns deleted count."""
    if not db_path.exists():
        return 0
    cutoff = int(time.time()) - max_age_seconds
    conn = _connect(db_path)
    try:
        cur = conn.execute("DELETE FROM scans WHERE ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    except sqlite3.Error as exc:
        log.warning("history: prune_history failed on %s: %s", db_path, exc)
        return 0
    finally:
        conn.close()


def prune_provider_data(
    provider: str,
    max_age_seconds: int = 172800,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    """Redact provider-specific profile details for scans older than max_age_seconds.

    Enforces data retention compliance (e.g. Reddit 48h data retention recommendation)
    without destroying the entire scan history record.
    Returns count of updated scan records.
    """
    if not db_path.exists():
        return 0
    cutoff = int(time.time()) - max_age_seconds
    conn = _connect(db_path)
    updated_count = 0
    try:
        rows = conn.execute(
            "SELECT id, payload FROM scans WHERE ts < ?", (cutoff,)
        ).fetchall()
        for scan_id, payload_raw in rows:
            try:
                payload = json.loads(payload_raw)
            except (json.JSONDecodeError, TypeError):
                log.warning("history: skipping malformed scan %s during retention", scan_id)
                continue
            modified = False
            for p in payload.get("platforms", []):
                if p.get("platform", "").casefold() == provider.casefold():
                    if p.get("profile_data"):
                        p["profile_data"] = {"retention_redacted": True}
                        modified = True
            for c in payload.get("identity_candidates", []):
                if c.get("platform", "").casefold() == provider.casefold():
                    if c.get("profile"):
                        c["profile"] = {"retention_redacted": True}
                        modified = True
            if modified:
                conn.execute(
                    "UPDATE scans SET payload = ? WHERE id = ?",
                    (json.dumps(payload, ensure_ascii=False), scan_id),
                )
                updated_count += 1
        conn.commit()
        return updated_count
    except sqlite3.Error as exc:
        log.warning("history: prune_provider_data failed on %s: %s", db_path, exc)
        return 0
    finally:
        conn.close()


def search_scans_semantic(
    query: str,
    *,
    limit: int = 10,
    min_score: float = 0.05,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict]:
    """Search historical scans by natural language semantic relevance.

    Extracts biographical text from stored scan payloads and ranks them
    against the query using subword cosine similarity.
    """
    if not query.strip() or not db_path.exists():
        return []
    from core.semantic_matcher import extract_profile_corpus, rank_by_similarity

    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, username, ts, found_count, payload FROM scans ORDER BY ts DESC LIMIT 200"
        ).fetchall()
        if not rows:
            return []
        parsed_entries = []
        corpora = []
        for row in rows:
            scan_id, username, ts, found_count, payload_raw = row
            try:
                payload = json.loads(payload_raw)
            except Exception:
                payload = {}
            corpus = extract_profile_corpus(payload)
            corpora.append(corpus)
            parsed_entries.append({
                "id": scan_id,
                "username": username,
                "ts": ts,
                "found_count": found_count,
                "payload": payload,
            })

        ranked = rank_by_similarity(query, corpora)
        results = []
        for idx, score in ranked:
            if score < min_score:
                continue
            entry = parsed_entries[idx]
            entry["similarity_score"] = score
            results.append(entry)
            if len(results) >= limit:
                break
        return results
    except sqlite3.Error as exc:
        log.warning("history: semantic search failed on %s: %s", db_path, exc)
        return []
    finally:
        conn.close()

