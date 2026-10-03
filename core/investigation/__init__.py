"""Evidence workbench over explicitly case-linked scan history."""

from pathlib import Path

from core import cases, history
from core.config import ScanConfig
from core.investigation import store
from core.investigation.view import MAX_SCANS, build_workbench

PIVOT_PLATFORMS = ("GitHub", "GitLab", "Dev.to", "Hacker News", "Keybase", "Bluesky")


def load_workbench(
    case_id: int, *, cases_db: Path | None = None, history_db: Path | None = None
) -> dict:
    case = cases.get_case(case_id, db_path=cases_db or cases.DEFAULT_DB_PATH)
    if case is None:
        raise ValueError("case not found")
    ids = list(
        dict.fromkeys(
            b.scan_id
            for b in cases.list_bookmarks(case_id, db_path=cases_db or cases.DEFAULT_DB_PATH)
            if b.scan_id is not None
        )
    )
    entries = []
    missing = []
    for scan_id in ids[:MAX_SCANS]:
        entry = history.get_scan(scan_id, db_path=history_db or history.DEFAULT_DB_PATH)
        if entry:
            entries.append(entry)
        else:
            missing.append(scan_id)
    result = build_workbench(entries, store.reviews(case_id, db_path=cases_db))
    result["case"] = case.to_dict()
    result["pivots"] = store.pivots(case_id, db_path=cases_db)
    result["budget"] = store.budget_summary(result["pivots"])
    result["allowed_platforms"] = list(PIVOT_PLATFORMS)
    reserved = {row["username"] for row in result["pivots"]}
    for lead in result["leads"]:
        if lead["username"] in reserved or case.status != "open":
            lead.update(
                eligible=False,
                blocked_reason="already_reserved"
                if lead["username"] in reserved
                else "case_closed",
            )
    if missing:
        result["warnings"].append(f"missing_linked_scans:{','.join(map(str, missing))}")
    if len(ids) > MAX_SCANS:
        result["warnings"].append("scan_window_truncated_to_latest_200_bookmarks")
    return result


def pivot_config(username: str, platforms: list[str], budget: int) -> ScanConfig:
    if not platforms or set(platforms) - set(PIVOT_PLATFORMS):
        raise ValueError("select supported public exact-profile providers")
    if not 1 <= budget <= 20:
        raise ValueError("pivot request budget must be between 1 and 20")
    return ScanConfig(
        username=username,
        platform_scope="full",
        platform_names=tuple(platforms),
        http_request_budget=budget,
        deep=False,
        smart=False,
        recursive=False,
        enrichment=False,
        no_auto_render=True,
        fingerprint=False,
        request_timeout=8,
    )
