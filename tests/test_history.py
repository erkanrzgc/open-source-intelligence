"""Tests for core/history.py — SQLite scan history and diffing."""

import sqlite3
from pathlib import Path

import pytest

from core.history import (
    HistoryEntry,
    diff_entries,
    get_latest,
    list_scans,
    save_scan,
    update_scan_payload,
)


def _payload(username: str, found: list[str]) -> dict:
    return {
        "username": username,
        "found_count": len(found),
        "platforms": [
            {"platform": name, "url": f"https://{name}/x", "exists": True}
            for name in found
        ],
    }


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "history.sqlite3"


def test_save_and_list(db: Path):
    rid = save_scan(_payload("alice", ["GitHub"]), ts=1000, db_path=db)
    assert rid > 0
    entries = list_scans("alice", db_path=db)
    assert len(entries) == 1
    assert entries[0].found_count == 1
    assert entries[0].found_names == {"GitHub"}
    assert entries[0].payload["identity_candidates"] == []


def test_list_ordered_desc(db: Path):
    save_scan(_payload("alice", ["GitHub"]), ts=1000, db_path=db)
    save_scan(_payload("alice", ["GitHub", "Reddit"]), ts=2000, db_path=db)
    save_scan(_payload("alice", ["Reddit"]), ts=3000, db_path=db)
    entries = list_scans("alice", db_path=db)
    assert [e.ts for e in entries] == [3000, 2000, 1000]


def test_list_limit(db: Path):
    for i in range(5):
        save_scan(_payload("bob", ["GitHub"]), ts=1000 + i, db_path=db)
    assert len(list_scans("bob", db_path=db, limit=3)) == 3


def test_list_filters_by_username(db: Path):
    save_scan(_payload("alice", ["GitHub"]), ts=1000, db_path=db)
    save_scan(_payload("bob", ["Reddit"]), ts=1000, db_path=db)
    assert len(list_scans("alice", db_path=db)) == 1
    assert len(list_scans("bob", db_path=db)) == 1


def test_list_missing_db(tmp_path: Path):
    missing = tmp_path / "missing.sqlite3"
    assert list_scans("alice", db_path=missing) == []


def test_get_latest_none(db: Path):
    assert get_latest("ghost", db_path=db) is None


def test_get_latest_and_previous(db: Path):
    save_scan(_payload("alice", ["GitHub"]), ts=1000, db_path=db)
    save_scan(_payload("alice", ["GitHub", "Reddit"]), ts=2000, db_path=db)
    current = get_latest("alice", db_path=db)
    assert current is not None
    assert current.ts == 2000
    previous = get_latest("alice", before_id=current.id, db_path=db)
    assert previous is not None
    assert previous.ts == 1000


def test_diff_entries_added_removed():
    old = HistoryEntry(
        id=1, username="a", ts=1, found_count=1, payload=_payload("a", ["GitHub"])
    )
    new = HistoryEntry(
        id=2,
        username="a",
        ts=2,
        found_count=2,
        payload=_payload("a", ["GitHub", "Reddit"]),
    )
    d = diff_entries(old, new)
    assert d.added == ["Reddit"]
    assert d.removed == []
    assert d.unchanged == ["GitHub"]


def test_diff_entries_removed_only():
    old = HistoryEntry(
        id=1,
        username="a",
        ts=1,
        found_count=2,
        payload=_payload("a", ["GitHub", "Reddit"]),
    )
    new = HistoryEntry(
        id=2, username="a", ts=2, found_count=1, payload=_payload("a", ["GitHub"])
    )
    d = diff_entries(old, new)
    assert d.added == []
    assert d.removed == ["Reddit"]


def test_save_rejects_empty_username(db: Path):
    with pytest.raises(ValueError):
        save_scan({"username": "", "found_count": 0, "platforms": []}, ts=1, db_path=db)


def test_save_rejects_missing_username(db: Path):
    with pytest.raises(ValueError):
        save_scan({"found_count": 0, "platforms": []}, ts=1, db_path=db)


def test_update_scan_payload_replaces_json_blob(db: Path):
    scan_id = save_scan(_payload("alice", ["GitHub"]), ts=1000, db_path=db)
    ok = update_scan_payload(
        scan_id,
        {
            **_payload("alice", ["GitHub"]),
            "schema_version": "test",
            "scan_id": scan_id,
        },
        db_path=db,
    )
    assert ok is True
    updated = get_latest("alice", db_path=db)
    assert updated is not None
    assert updated.payload["schema_version"] == "test"
    assert updated.payload["scan_id"] == scan_id


def test_history_migration_tracks_payload_schema_version(db: Path):
    scan_id = save_scan(
        {**_payload("alice", []), "schema_version": "2026-08-08"},
        ts=1000,
        db_path=db,
    )
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT payload_schema_version FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        migrations = conn.execute("SELECT version FROM _migrations").fetchall()
    assert row == ("2026-08-08",)
    assert migrations == [(1,)]


def test_history_migration_adopts_preexisting_column_without_ledger(db: Path):
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ts INTEGER NOT NULL,
                found_count INTEGER NOT NULL,
                payload TEXT NOT NULL,
                payload_schema_version TEXT NOT NULL DEFAULT 'legacy'
            );
            """
        )
    assert list_scans("alice", db_path=db) == []
    with sqlite3.connect(db) as conn:
        migrations = conn.execute("SELECT version FROM _migrations").fetchall()
    assert migrations == [(1,)]
