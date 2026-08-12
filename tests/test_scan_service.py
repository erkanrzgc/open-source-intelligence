"""Tests for shared scan finalization helpers."""

from __future__ import annotations

from pathlib import Path

from core import cases, history, scan_service, watchlist
from core.config import ScanConfig
from core.models import PlatformResult, ScanResult
from core.plugins import PluginRegistry
from core.scan_service import SCAN_PAYLOAD_SCHEMA_VERSION, complete_scan_result


def _result(username: str) -> ScanResult:
    result = ScanResult(username=username)
    result.platforms = [
        PlatformResult(
            platform="GitHub",
            url=f"https://github.com/{username}",
            category="dev",
            exists=True,
            status="found",
        )
    ]
    return result


def test_complete_scan_result_adds_metadata_without_history():
    result = _result("alice")
    completed = complete_scan_result(
        result,
        ScanConfig(username="alice"),
        save_history=False,
    )

    assert completed.scan_id is None
    assert completed.saved_to_history is False
    assert completed.payload["schema_version"] == SCAN_PAYLOAD_SCHEMA_VERSION
    assert "capabilities" in completed.payload
    assert "warnings" in completed.payload
    assert "investigator_summary" in completed.payload
    assert "priority_score" in completed.payload["investigator_summary"]
    assert completed.payload["saved_to_history"] is False


def test_complete_scan_result_persists_case_and_watchlist(tmp_path: Path):
    hist_db = tmp_path / "history.sqlite3"
    watch_db = tmp_path / "watch.sqlite3"
    cases_db = tmp_path / "cases.sqlite3"

    entry = watchlist.add("alice", db_path=watch_db)
    case = cases.create_case("alpha", db_path=cases_db)
    result = _result("alice")

    completed = complete_scan_result(
        result,
        ScanConfig(username="alice"),
        save_history=True,
        case_id=case.id,
        mark_watchlist=True,
        history_db=hist_db,
        watchlist_db=watch_db,
        cases_db=cases_db,
    )

    assert completed.scan_id is not None
    assert completed.saved_to_history is True
    assert completed.watchlist_entry_id == entry.id
    assert completed.case_bookmark_id is not None

    saved = history.get_scan(completed.scan_id, db_path=hist_db)
    assert saved is not None
    assert saved.payload["scan_id"] == completed.scan_id
    assert saved.payload["watchlist_entry_id"] == entry.id
    assert saved.payload["case_id"] == case.id
    assert saved.payload["investigator_summary"]["headline"]

    refreshed = watchlist.get("alice", db_path=watch_db)
    assert refreshed is not None
    assert refreshed.last_scan_at is not None

    bookmarks = cases.list_bookmarks(case.id, db_path=cases_db)
    assert len(bookmarks) == 1
    assert bookmarks[0].scan_id == completed.scan_id


def test_completion_runs_plugins_once_and_records_timing(monkeypatch):
    registry = PluginRegistry()
    calls: list[str] = []
    registry.post_scan(lambda result, cfg: calls.append(result.username))
    monkeypatch.setattr(scan_service, "_PLUGIN_REGISTRY", registry)
    result = _result("alice")
    cfg = ScanConfig(username="alice")

    complete_scan_result(result, cfg, save_history=False)
    complete_scan_result(result, cfg, save_history=False)

    assert calls == ["alice"]
    plugin_diag = result.diagnostics["phases"]["plugins"]
    assert plugin_diag["status"] == "completed"
    assert plugin_diag["metrics"]["completed"] == 1
    assert plugin_diag["duration_ms"] >= 0
