"""Case evidence stays scoped, provenance-preserving and budgeted."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from core import cases, history
from core.investigation import load_workbench, pivot_config, store
from core.investigation.view import build_workbench


def snapshot(
    scan_id, username="alice", *, bio="first bio", status="confirmed", platform="GitHub", alias=None
):
    row = {
        "platform": platform,
        "url": f"https://github.com/{username}",
        "queried_username": username,
        "exists": status == "confirmed",
        "verification": {"verdict": status},
        "probe_outcome": "not_found"
        if status == "not_found"
        else "found"
        if status == "confirmed"
        else "blocked",
        "http_status": 200 if status == "confirmed" else 404 if status == "not_found" else 403,
        "checked_at": f"2026-10-03T00:00:{scan_id:02d}+00:00",
        "contract_revision": "fixture-v1",
        "profile_data": {
            "bio": bio,
            "name": "Same Name",
            "github_username": "alice_dev",
            "website_url": "https://example.test",
            "company": "Example",
        },
    }
    payload = {"username": username, "platforms": [row]}
    if alias:
        payload["identity_candidates"] = [
            {
                "username": alias,
                "verdict": "uncertain",
                "score": 0.1,
                "profiles": [
                    {**row, "url": f"https://github.com/{alias}", "queried_username": alias}
                ],
            }
        ]
    return history.HistoryEntry(scan_id, username, scan_id * 100, 1, payload)


def test_graph_separates_profiles_and_preserves_provenance():
    result = build_workbench([snapshot(1), snapshot(2, "bob")])
    nodes = [n["data"] for n in result["graph"]["nodes"]]
    assert len([n for n in nodes if n["kind"] == "profile"]) == 2
    assert len([n for n in nodes if n["kind"] == "organization"]) == 1
    for edge in result["graph"]["edges"]:
        assert edge["data"]["observations"][0]["source_url"]
        assert edge["data"]["observations"][0]["checked_at"]
        assert edge["data"]["observations"][0]["contract_revision"] == "fixture-v1"


def test_timeline_distinguishes_blocking_omission_absence_and_metadata_change():
    first, changed, blocked = (
        snapshot(1),
        snapshot(2, bio="new bio"),
        snapshot(3, status="uncertain"),
    )
    omitted = history.HistoryEntry(4, "alice", 400, 0, {"platforms": []})
    missing = snapshot(5, status="not_found")
    restored = snapshot(6, bio="new bio")
    result = build_workbench([restored, first, blocked, missing, omitted, changed])
    kinds = [event["kind"] for event in result["timeline"]]
    assert kinds.count("metadata_changed") == 1
    assert kinds.count("coverage_lost") == 1
    assert kinds.count("absence_observed") == 1
    assert kinds.count("coverage_restored") == 1
    assert [event["kind"] for event in result["timeline"] if event["scan_id"] == 4] == ["scan"]
    change = next(e for e in result["timeline"] if e["kind"] == "metadata_changed")
    assert change["changes"]["bio"] == {"before": "first bio", "after": "new bio"}


def test_alias_hypothesis_not_merged_and_reviews_do_not_upgrade_it():
    first = build_workbench([snapshot(1, alias="alicee")])
    edge = next(
        e["data"] for e in first["graph"]["edges"] if e["data"]["relation"] == "identity_candidate"
    )
    result = build_workbench([snapshot(1, alias="alicee")], {edge["id"]: {"decision": "accepted"}})
    updated = next(e["data"] for e in result["graph"]["edges"] if e["data"]["id"] == edge["id"])
    assert updated["verdict"] == "uncertain"
    assert updated["analyst_review"]["decision"] == "accepted"
    assert len([n for n in result["graph"]["nodes"] if n["data"]["kind"] == "query"]) == 2


def test_missing_metadata_is_unknown_but_explicit_empty_value_is_a_change():
    first = snapshot(1)
    partial = snapshot(2)
    partial.payload["platforms"][0]["profile_data"] = {"name": "Same Name"}
    restored = snapshot(3)
    cleared = snapshot(4, bio="")
    result = build_workbench([first, partial, restored, cleared])
    changes = [event for event in result["timeline"] if event["kind"] == "metadata_changed"]
    assert len(changes) == 1
    assert changes[0]["scan_id"] == 4
    assert changes[0]["changes"] == {"bio": {"before": "first bio", "after": ""}}


def test_leads_are_deduplicated_and_depth_limited():
    entry = snapshot(1)
    entry.payload["diagnostics"] = {"investigation": {"depth": 2}}
    result = build_workbench([entry, entry])
    assert result["summary"]["scans"] == 1
    assert len(result["leads"]) == 1
    assert result["leads"][0]["depth"] == 3
    assert result["leads"][0]["eligible"] is False
    assert build_workbench([snapshot(1), snapshot(2, "alice_dev")])["leads"] == []


def test_case_only_loads_its_linked_scans(tmp_path):
    cdb, hdb = tmp_path / "cases.db", tmp_path / "history.db"
    one = cases.create_case("one", db_path=cdb)
    two = cases.create_case("two", db_path=cdb)
    for case, handle in ((one, "alice"), (two, "bob")):
        entry = snapshot(1, handle)
        sid = history.save_scan(entry.payload, ts=100, db_path=hdb)
        cases.add_bookmark(
            case.id, target_type="scan", target_value=handle, scan_id=sid, db_path=cdb
        )
    view = load_workbench(one.id, cases_db=cdb, history_db=hdb)
    labels = {n["data"]["label"] for n in view["graph"]["nodes"]}
    assert "alice" in labels
    assert "bob" not in labels
    assert view["summary"]["scans"] == 1


def test_reservations_enforce_duplicate_and_case_request_budget(tmp_path):
    db = tmp_path / "cases.db"
    case = cases.create_case("budget", db_path=db)
    lead = {"id": "l1", "username": "alice", "eligible": True, "depth": 1, "source_scan_id": 1}
    store.reserve_pivot(case.id, lead, ["GitHub"], 20, db_path=db)
    with pytest.raises(ValueError, match="already reserved"):
        store.reserve_pivot(case.id, {**lead, "username": "ALICE"}, ["GitHub"], 20, db_path=db)
    for i in range(5):
        store.reserve_pivot(case.id, {**lead, "username": f"other{i}"}, ["GitHub"], 20, db_path=db)
    with pytest.raises(ValueError, match="budget exhausted"):
        store.reserve_pivot(case.id, {**lead, "username": "overflow"}, ["GitHub"], 1, db_path=db)


def test_concurrent_reservations_admit_a_duplicate_only_once(tmp_path):
    db = tmp_path / "cases.db"
    case = cases.create_case("concurrent", db_path=db)
    store.pivots(case.id, db_path=db)  # Initialize tables before racing transactions.
    lead = {"id": "l1", "username": "alice", "eligible": True, "depth": 1, "source_scan_id": 1}

    def reserve(_):
        try:
            return store.reserve_pivot(case.id, lead, ["GitHub"], 2, db_path=db)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted = list(pool.map(reserve, range(2)))
    assert sum(value is not None for value in accepted) == 1


def test_pivot_configuration_disables_unbounded_phases_and_rejects_arbitrary_targets():
    cfg = pivot_config("alice", ["GitHub"], 3)
    assert cfg.platform_names == ("GitHub",)
    assert cfg.http_request_budget == 3
    assert not any(
        (cfg.smart, cfg.recursive, cfg.deep, cfg.enrichment, cfg.ai_skills, cfg.email, cfg.whois)
    )
    assert cfg.no_auto_render
    with pytest.raises(ValueError):
        pivot_config("alice", ["https://127.0.0.1"], 3)


def test_case_review_is_separate_and_cascades_on_case_delete(tmp_path):
    db = tmp_path / "cases.db"
    case = cases.create_case("review", db_path=db)
    store.save_review(case.id, "edge", "rejected", "different people", "analyst", db_path=db)
    assert store.reviews(case.id, db_path=db)["edge"]["note"] == "different people"
    cases.delete_case(case.id, db_path=db)
    assert store.reviews(case.id, db_path=db) == {}
