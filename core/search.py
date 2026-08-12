"""SQLite FTS5 full-text search over scan history payloads.

Maintains a parallel virtual table ``scans_fts`` alongside the main
``scans`` table created by :mod:`core.history`. Each history row is
flattened into a searchable text document built from the scan payload
(username + found platforms, emails, phones, crypto wallets, locations,
and profile bios/names).

The index is rebuilt lazily on demand via :func:`reindex` when it is
missing or stale, so legacy history databases do not need a migration
step — the first ``search`` call hydrates the index from existing rows.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from core.history import DEFAULT_DB_PATH

log = logging.getLogger(__name__)

_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS scans_fts USING fts5(
    username,
    document
);
CREATE TABLE IF NOT EXISTS search_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_MAX_DOC_CHARS = 32_000
_INDEX_SCHEMA_VERSION = "3"


@dataclass(frozen=True)
class SearchHit:
    id: int
    username: str
    ts: int
    found_count: int
    snippet: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "ts": self.ts,
            "found_count": self.found_count,
            "snippet": self.snippet,
        }


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_FTS_SCHEMA)
    return conn


def _flatten_payload(payload: dict) -> str:
    """Project the JSON payload into a single searchable blob.

    Keeps only fields that an investigator would realistically query
    (names, handles, emails, phones, wallets, bios, locations).
    """
    parts: list[str] = []
    username = payload.get("username")
    if isinstance(username, str):
        parts.append(username)

    for platform in payload.get("platforms", []) or []:
        if not isinstance(platform, dict):
            continue
        if not platform.get("exists"):
            continue
        name = platform.get("platform")
        if isinstance(name, str):
            parts.append(name)
        url = platform.get("url")
        if isinstance(url, str):
            parts.append(url)
        profile = platform.get("profile_data") or {}
        if isinstance(profile, dict):
            for key in ("name", "full_name", "display_name", "bio",
                        "description", "location", "email", "company",
                        "website", "blog"):
                value = profile.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value.strip())

    for candidate in payload.get("identity_candidates", []) or []:
        if not isinstance(candidate, dict):
            continue
        alias = candidate.get("username")
        if isinstance(alias, str) and alias.strip():
            parts.append(alias.strip())
        verdict = candidate.get("verdict")
        if isinstance(verdict, str):
            parts.append(verdict)
        for profile in candidate.get("profiles", []) or []:
            if not isinstance(profile, dict):
                continue
            platform_name = profile.get("platform")
            if isinstance(platform_name, str):
                parts.append(platform_name)
            data = profile.get("profile_data") or {}
            if isinstance(data, dict):
                for key in (
                    "name", "full_name", "fullname", "display_name", "bio",
                    "details", "description", "location", "organization",
                ):
                    value = data.get(key)
                    if isinstance(value, str) and value.strip():
                        parts.append(value.strip())

    for email in payload.get("emails", []) or []:
        if isinstance(email, str):
            parts.append(email)
        elif isinstance(email, dict):
            addr = email.get("email") or email.get("address")
            if isinstance(addr, str):
                parts.append(addr)

    for phone in [
        *(payload.get("phone_intel", []) or []),
        *(payload.get("phones", []) or []),
    ]:
        if isinstance(phone, str):
            parts.append(phone)
        elif isinstance(phone, dict):
            for key in ("number", "e164", "raw", "country", "carrier", "location"):
                value = phone.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value.strip())

    for wallet in [
        *(payload.get("crypto_intel", []) or []),
        *(payload.get("crypto", []) or []),
    ]:
        if isinstance(wallet, str):
            parts.append(wallet)
        elif isinstance(wallet, dict):
            for key in ("address", "network", "currency"):
                value = wallet.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value.strip())

    for geo in [
        *(payload.get("geo_points", []) or []),
        *(payload.get("geo", []) or []),
    ]:
        if isinstance(geo, dict):
            for key in ("display_name", "label", "location", "query", "country"):
                value = geo.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value.strip())

    doc = " \n".join(parts)
    if len(doc) > _MAX_DOC_CHARS:
        doc = doc[:_MAX_DOC_CHARS]
    return doc


def index_scan(
    scan_id: int,
    payload: dict,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    """Upsert a single scan row into the FTS index.

    Safe to call multiple times for the same ``scan_id``: the previous
    row is replaced first so the index stays in sync.
    """
    username = payload.get("username") or ""
    document = _flatten_payload(payload)
    try:
        conn = _connect(db_path)
    except sqlite3.Error as exc:
        log.warning("search: could not open db %s: %s", db_path, exc)
        return
    try:
        conn.execute("DELETE FROM scans_fts WHERE rowid = ?", (scan_id,))
        conn.execute(
            "INSERT INTO scans_fts(rowid, username, document) VALUES (?, ?, ?)",
            (scan_id, username, document),
        )
        conn.execute(
            "INSERT OR REPLACE INTO search_meta(key, value) VALUES ('schema_version', ?)",
            (_INDEX_SCHEMA_VERSION,),
        )
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("search: index upsert failed for id=%s: %s", scan_id, exc)
    finally:
        conn.close()


def _rebuild_on(conn: sqlite3.Connection) -> int:
    """Rebuild the FTS rows inside an open connection."""
    conn.execute("DELETE FROM scans_fts")
    try:
        cursor = conn.execute("SELECT id, payload FROM scans ORDER BY id ASC")
    except sqlite3.OperationalError:
        conn.commit()
        return 0
    count = 0
    for row_id, raw in cursor.fetchall():
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            continue
        conn.execute(
            "INSERT INTO scans_fts(rowid, username, document) VALUES (?, ?, ?)",
            (row_id, payload.get("username") or "", _flatten_payload(payload)),
        )
        count += 1
    conn.commit()
    conn.execute(
        "INSERT OR REPLACE INTO search_meta(key, value) VALUES ('schema_version', ?)",
        (_INDEX_SCHEMA_VERSION,),
    )
    conn.commit()
    return count


def _index_schema_is_current(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT value FROM search_meta WHERE key = 'schema_version'"
    ).fetchone()
    return bool(row and row[0] == _INDEX_SCHEMA_VERSION)


def reindex(*, db_path: Path = DEFAULT_DB_PATH) -> int:
    """Rebuild the FTS index from the scans table. Returns rows indexed."""
    if not db_path.exists():
        return 0
    try:
        conn = _connect(db_path)
    except sqlite3.Error as exc:
        log.warning("search: reindex open failed: %s", exc)
        return 0
    try:
        return _rebuild_on(conn)
    finally:
        conn.close()


def _index_row_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM scans_fts").fetchone()
    return int(row[0]) if row else 0


def _history_row_count(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    except sqlite3.OperationalError:
        return 0
    return int(row[0]) if row else 0


def _sanitize_fts5(query: str) -> str:
    """Strip FTS5 operators from user input so bare words become safe phrase matches.

    SQLite FTS5 treats ``AND``, ``OR``, ``NOT``, ``NEAR``, ``*``, ``"``,
    and parentheses as operators. We strip them and return the cleaned text.
    Leading/trailing ``*`` is removed; internal ``*`` is kept as a wildcard hint.
    """
    cleaned = re.sub(r'["()]', " ", query)
    cleaned = re.sub(r"\b(AND|OR|NOT|NEAR)\b", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\*+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def search(
    query: str,
    *,
    limit: int = 20,
    username: str | None = None,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[SearchHit]:
    """Run an FTS5 MATCH query over scan history and return ranked hits.

    Hits are ordered by bm25 ranking (lower = more relevant). When
    ``username`` is provided, results are scoped to that investigator
    target. Returns an empty list on invalid queries or if no history
    exists yet.
    """
    q = (query or "").strip()
    if not q or limit <= 0 or not db_path.exists():
        return []
    safe = _sanitize_fts5(q)
    if not safe:
        return []
    try:
        conn = _connect(db_path)
    except sqlite3.Error as exc:
        log.warning("search: open failed: %s", exc)
        return []
    try:
        history_rows = _history_row_count(conn)
        if history_rows == 0:
            return []
        if not _index_schema_is_current(conn) or _index_row_count(conn) < history_rows:
            _rebuild_on(conn)

        sql = (
            "SELECT s.id, s.username, s.ts, s.found_count, "
            "snippet(scans_fts, 1, '[', ']', '…', 12) "
            "FROM scans_fts "
            "JOIN scans s ON s.id = scans_fts.rowid "
            "WHERE scans_fts MATCH ? "
        )
        params: list = [safe]
        if username:
            sql += "AND s.username = ? "
            params.append(username)
        sql += "ORDER BY bm25(scans_fts) LIMIT ?"
        params.append(int(limit))
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            log.info("search: FTS query failed for %r (sanitized=%r): %s", q, safe, exc)
            return []
    finally:
        conn.close()
    return [
        SearchHit(
            id=row[0],
            username=row[1],
            ts=row[2],
            found_count=row[3],
            snippet=row[4] or "",
        )
        for row in rows
    ]
