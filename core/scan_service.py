"""Shared scan payload and persistence helpers."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core import cases, history, watchlist
from core.capabilities import collect_capabilities, collect_scan_warnings
from core.config import ScanConfig
from core.investigator_summary import build_investigator_summary
from core.logging_setup import get_logger
from core.models import ScanResult
from core.plugins import PluginRegistry, load_plugins
from core.search import index_scan

log = get_logger(__name__)

SCAN_PAYLOAD_SCHEMA_VERSION = "2026-08-09"
_PLUGIN_REGISTRY: PluginRegistry | None = None


def _plugin_registry() -> PluginRegistry:
    global _PLUGIN_REGISTRY
    if _PLUGIN_REGISTRY is None:
        _PLUGIN_REGISTRY = load_plugins()
    return _PLUGIN_REGISTRY


@dataclass(frozen=True)
class CompletedScan:
    result: ScanResult
    payload: dict[str, Any]
    scan_id: int | None
    saved_to_history: bool
    case_id: int | None
    case_bookmark_id: int | None
    watchlist_entry_id: int | None
    capabilities: dict[str, dict[str, Any]]
    warnings: list[str]


def decorate_scan_payload(
    payload: dict[str, Any],
    *,
    capabilities: dict[str, dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
    scan_id: int | None = None,
    saved_to_history: bool = False,
    case_id: int | None = None,
    case_bookmark_id: int | None = None,
    watchlist_entry_id: int | None = None,
) -> dict[str, Any]:
    """Attach stable metadata to a raw ``ScanResult.to_dict()`` payload."""
    out = dict(payload)
    out["schema_version"] = SCAN_PAYLOAD_SCHEMA_VERSION
    out["capabilities"] = capabilities or collect_capabilities()
    out["warnings"] = list(warnings or [])
    out["scan_id"] = scan_id
    out["saved_to_history"] = saved_to_history
    if case_id is not None:
        out["case_id"] = case_id
    if case_bookmark_id is not None:
        out["case_bookmark_id"] = case_bookmark_id
    if watchlist_entry_id is not None:
        out["watchlist_entry_id"] = watchlist_entry_id
    return out


def complete_scan_result(
    result: ScanResult,
    cfg: ScanConfig,
    *,
    save_history: bool = True,
    case_id: int | None = None,
    mark_watchlist: bool = False,
    ts: int | None = None,
    history_db: Path = history.DEFAULT_DB_PATH,
    watchlist_db: Path = watchlist.DEFAULT_DB_PATH,
    cases_db: Path = cases.DEFAULT_DB_PATH,
    capabilities: dict[str, dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
) -> CompletedScan:
    """Serialize, persist, and cross-link a completed scan result."""
    stamp = ts if ts is not None else int(time.time())
    caps = capabilities or collect_capabilities()
    scan_warnings = list(warnings or collect_scan_warnings(cfg, capabilities=caps))
    result.diagnostics["missing_capabilities"] = sorted(
        name for name, meta in caps.items() if not bool(meta.get("ready"))
    )

    if case_id is not None and cases.get_case(case_id, db_path=cases_db) is None:
        raise ValueError(f"case {case_id} does not exist")

    plugin_diag = result.diagnostics.setdefault("phases", {}).get("plugins")
    if not isinstance(plugin_diag, dict) or plugin_diag.get("status") != "completed":
        plugin_started = time.monotonic()
        stats = _plugin_registry().run_post_scan(result, cfg)
        result.diagnostics.setdefault("phases", {})["plugins"] = {
            "status": "completed",
            "duration_ms": round((time.monotonic() - plugin_started) * 1000, 2),
            "metrics": stats,
        }

    watch_entry = watchlist.get(result.username, db_path=watchlist_db)
    watch_entry_id = watch_entry.id if watch_entry is not None else None

    base_payload = result.to_dict()
    result.investigator_summary = build_investigator_summary(
        base_payload,
        warnings=scan_warnings,
    )
    base_payload = result.to_dict()

    payload = decorate_scan_payload(
        base_payload,
        capabilities=caps,
        warnings=scan_warnings,
        watchlist_entry_id=watch_entry_id,
    )
    result.investigator_summary = payload.get("investigator_summary")

    scan_id: int | None = None
    saved_to_history = False
    if save_history:
        scan_id = history.save_scan(payload, ts=stamp, db_path=history_db)
        saved_to_history = bool(scan_id and scan_id > 0)

    case_bookmark_id: int | None = None
    if case_id is not None:
        label = f"Scan #{scan_id}" if saved_to_history and scan_id is not None else "Unsaved scan"
        bookmark = cases.add_bookmark(
            case_id,
            target_type="scan",
            target_value=result.username,
            label=f"{label} for {result.username}",
            scan_id=scan_id if saved_to_history else None,
            db_path=cases_db,
        )
        case_bookmark_id = bookmark.id

    if mark_watchlist and watch_entry_id is not None:
        watchlist.mark_scanned(result.username, ts=stamp, db_path=watchlist_db)

    payload = decorate_scan_payload(
        payload,
        capabilities=caps,
        warnings=scan_warnings,
        scan_id=scan_id if saved_to_history else None,
        saved_to_history=saved_to_history,
        case_id=case_id,
        case_bookmark_id=case_bookmark_id,
        watchlist_entry_id=watch_entry_id,
    )
    result.investigator_summary = payload.get("investigator_summary")

    if saved_to_history and scan_id is not None:
        history.update_scan_payload(scan_id, payload, db_path=history_db)
        index_scan(scan_id, payload, db_path=history_db)

    return CompletedScan(
        result=result,
        payload=payload,
        scan_id=scan_id if saved_to_history else None,
        saved_to_history=saved_to_history,
        case_id=case_id,
        case_bookmark_id=case_bookmark_id,
        watchlist_entry_id=watch_entry_id,
        capabilities=caps,
        warnings=scan_warnings,
    )
