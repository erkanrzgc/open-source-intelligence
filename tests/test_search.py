"""Tests for core/search.py — SQLite FTS5 full-text search over scan history."""

from pathlib import Path

import pytest

from core.history import save_scan
from core.search import index_scan, reindex, search


def _payload(
    username: str,
    platforms: list[str] | None = None,
    emails: list[str] | None = None,
    phones: list[str] | None = None,
    crypto: list[str] | None = None,
    bio: str | None = None,
    location: str | None = None,
) -> dict:
    return {
        "username": username,
        "found_count": len(platforms or []),
        "platforms": [
            {
                "platform": name,
                "url": f"https://{name.lower()}.test/{username}",
                "exists": True,
                "profile_data": {
                    "name": f"{username} person",
                    "bio": bio,
                    "location": location,
                },
            }
            for name in (platforms or [])
        ],
        "emails": emails or [],
        "phones": phones or [],
        "crypto": crypto or [],
    }


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "history.sqlite3"


def _save_and_index(payload: dict, *, ts: int, db: Path) -> int:
    scan_id = save_scan(payload, ts=ts, db_path=db)
    index_scan(scan_id, payload, db_path=db)
    return scan_id


def test_search_empty_query_returns_nothing(db: Path):
    _save_and_index(_payload("alice", ["GitHub"]), ts=1000, db=db)
    assert search("", db_path=db) == []
    assert search("   ", db_path=db) == []


def test_search_missing_db_returns_empty(tmp_path: Path):
    assert search("anything", db_path=tmp_path / "missing.sqlite3") == []


def test_search_finds_username(db: Path):
    _save_and_index(_payload("alice", ["GitHub"]), ts=1000, db=db)
    _save_and_index(_payload("bob", ["Reddit"]), ts=2000, db=db)
    hits = search("alice", db_path=db)
    assert [h.username for h in hits] == ["alice"]


def test_search_finds_platform(db: Path):
    _save_and_index(_payload("alice", ["GitHub"]), ts=1000, db=db)
    _save_and_index(_payload("bob", ["Reddit"]), ts=2000, db=db)
    hits = search("Reddit", db_path=db)
    assert len(hits) == 1
    assert hits[0].username == "bob"


def test_search_finds_email(db: Path):
    _save_and_index(
        _payload("alice", ["GitHub"], emails=["alice@example.com"]),
        ts=1000,
        db=db,
    )
    _save_and_index(
        _payload("bob", ["Reddit"], emails=["bob@elsewhere.org"]),
        ts=2000,
        db=db,
    )
    hits = search("elsewhere", db_path=db)
    assert len(hits) == 1
    assert hits[0].username == "bob"


def test_search_finds_phone(db: Path):
    _save_and_index(
        _payload("alice", ["GitHub"], phones=["+905551234567"]), ts=1000, db=db
    )
    hits = search("905551234567", db_path=db)
    assert len(hits) == 1
    assert hits[0].username == "alice"


def test_search_finds_crypto_wallet(db: Path):
    addr = "0xAbC1234567890DeAdBeEf0000000000000000000"
    _save_and_index(_payload("alice", ["GitHub"], crypto=[addr]), ts=1000, db=db)
    hits = search(addr, db_path=db)
    assert len(hits) == 1


def test_search_filter_by_username(db: Path):
    _save_and_index(
        _payload("alice", ["GitHub"], bio="loves python"), ts=1000, db=db
    )
    _save_and_index(
        _payload("bob", ["Reddit"], bio="loves python"), ts=2000, db=db
    )
    hits = search("python", username="bob", db_path=db)
    assert len(hits) == 1
    assert hits[0].username == "bob"


def test_search_limit(db: Path):
    for i in range(5):
        _save_and_index(
            _payload(f"user{i}", ["GitHub"], bio="distinctive"), ts=1000 + i, db=db
        )
    hits = search("distinctive", limit=3, db_path=db)
    assert len(hits) == 3


def test_search_ignores_invalid_fts_query(db: Path):
    _save_and_index(_payload("alice", ["GitHub"]), ts=1000, db=db)
    assert search('"unterminated', db_path=db) == []


def test_search_snippet_highlights_match(db: Path):
    _save_and_index(
        _payload("alice", ["GitHub"], bio="works at NovaCorp in Istanbul"),
        ts=1000,
        db=db,
    )
    hits = search("NovaCorp", db_path=db)
    assert len(hits) == 1
    assert "[NovaCorp]" in hits[0].snippet


def test_reindex_hydrates_legacy_history(db: Path):
    """save_scan-only rows (no index_scan) should be searchable after reindex."""
    save_scan(_payload("alice", ["GitHub"], bio="auroral"), ts=1000, db_path=db)
    save_scan(_payload("bob", ["Reddit"]), ts=2000, db_path=db)

    count = reindex(db_path=db)
    assert count == 2

    hits = search("auroral", db_path=db)
    assert len(hits) == 1
    assert hits[0].username == "alice"


def test_search_auto_reindex_on_stale_index(db: Path):
    """search() should transparently hydrate a stale FTS index."""
    save_scan(_payload("alice", ["GitHub"], bio="zephyr"), ts=1000, db_path=db)
    hits = search("zephyr", db_path=db)
    assert len(hits) == 1


def test_index_upsert_replaces_previous(db: Path):
    scan_id = _save_and_index(
        _payload("alice", ["GitHub"], bio="first"), ts=1000, db=db
    )
    index_scan(scan_id, _payload("alice", ["GitHub"], bio="second"), db_path=db)
    assert search("first", db_path=db) == []
    hits = search("second", db_path=db)
    assert len(hits) == 1


def test_search_ranks_more_relevant_first(db: Path):
    _save_and_index(
        _payload("alice", ["GitHub"], bio="python python python"),
        ts=1000,
        db=db,
    )
    _save_and_index(
        _payload("bob", ["GitHub"], bio="once mentions python"),
        ts=2000,
        db=db,
    )
    hits = search("python", db_path=db)
    assert len(hits) == 2
    assert hits[0].username == "alice"


def test_search_hit_to_dict(db: Path):
    _save_and_index(_payload("alice", ["GitHub"]), ts=1000, db=db)
    hits = search("alice", db_path=db)
    d = hits[0].to_dict()
    assert d["username"] == "alice"
    assert d["ts"] == 1000
    assert "snippet" in d


def test_search_indexes_current_phone_crypto_and_geo_fields(db: Path):
    payload = {
        "username": "alice",
        "found_count": 0,
        "schema_version": "2026-08-08",
        "phone_intel": [{"e164": "+905551112233", "carrier": "ExampleTel"}],
        "crypto_intel": [{"address": "0xabcdef123456", "network": "ethereum"}],
        "geo_points": [{"display_name": "Kadikoy Istanbul", "country": "Turkiye"}],
    }
    scan_id = save_scan(payload, ts=1000, db_path=db)
    index_scan(scan_id, payload, db_path=db)

    assert search("ExampleTel", db_path=db)[0].id == scan_id
    assert search("0xabcdef123456", db_path=db)[0].id == scan_id
    assert search("Kadikoy", db_path=db)[0].id == scan_id


def test_search_indexes_identity_candidates(db: Path):
    payload = _payload("alice", ["GitHub"])
    payload["identity_candidates"] = [
        {
            "username": "alice_dev",
            "verdict": "likely_same",
            "profiles": [
                {
                    "platform": "Hugging Face",
                    "profile_data": {"name": "Alice Example", "bio": "quantum otter"},
                }
            ],
        }
    ]
    scan_id = save_scan(payload, ts=1000, db_path=db)
    index_scan(scan_id, payload, db_path=db)
    assert search("alice_dev", db_path=db)[0].id == scan_id
    assert search("quantum", db_path=db)[0].id == scan_id
