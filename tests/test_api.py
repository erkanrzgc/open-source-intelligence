"""FastAPI REST surface tests."""

from __future__ import annotations

import asyncio
from dataclasses import fields
from pathlib import Path

import pytest

fastapi_mod = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import httpx  # noqa: E402

from core import api, auth, cases, history, watchlist  # noqa: E402
from core.api import server as api_server  # noqa: E402
from core.config import ScanConfig  # noqa: E402
from core.models import PlatformResult, ScanResult  # noqa: E402

if Path(fastapi_mod.__file__).as_posix().startswith("/usr/lib/python3/dist-packages/"):
    pytest.skip(
        "system FastAPI/Starlette package hangs with local httpx ASGI transport",
        allow_module_level=True,
    )


class ASGITestClient:
    __test__ = False

    def __init__(self, app):
        self.app = app

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async def _send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as ac:
                return await ac.request(method, url, **kwargs)

        return asyncio.run(_send())

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def patch(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)


TestClient = ASGITestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    # Redirect watchlist DB to a temp file so tests don't trample state.
    wl_db = tmp_path / "wl.sqlite3"
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", wl_db)
    # Module-level functions bound `db_path=DEFAULT_DB_PATH` at def time, so
    # callers without an explicit db_path still reference the original path.
    # Rebind the defaults so the API layer picks up the tmp DB too.
    for fn in (watchlist.add, watchlist.remove, watchlist.list_all,
              watchlist.mark_scanned, watchlist.get):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", wl_db)

    # Same trick for the cases store — keep its sqlite file in tmp so the
    # API tests can't pollute the user's real cases DB.
    cases_db = tmp_path / "cases.sqlite3"
    monkeypatch.setattr(cases, "DEFAULT_DB_PATH", cases_db)
    for fn in (
        cases.create_case, cases.get_case, cases.list_cases,
        cases.update_case, cases.delete_case,
        cases.add_note, cases.list_notes, cases.delete_note,
        cases.add_bookmark, cases.list_bookmarks, cases.delete_bookmark,
    ):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", cases_db)

    # Users DB also isolated to tmp.
    users_db = tmp_path / "users.sqlite3"
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", users_db)
    for fn in (
        auth.create_user, auth.get_user, auth.list_users, auth.authenticate,
    ):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", users_db)
    # History DB isolated to tmp as well.
    hist_db = tmp_path / "history.sqlite3"
    monkeypatch.setattr(history, "DEFAULT_DB_PATH", hist_db)
    for fn in (
        history.save_scan, history.update_scan_payload, history.list_scans,
        history.get_latest, history.get_scan,
    ):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", hist_db)
    # Pin the JWT secret so tokens are deterministic across the test.
    monkeypatch.setenv("OSINT_AUTH_SECRET", "test-secret")
    # Make sure no stray env var forces auth on.
    monkeypatch.delenv("OSINT_AUTH_REQUIRED", raising=False)

    async def fake_run_scan(cfg):
        r = ScanResult(username=cfg.username)
        r.platforms = [
            PlatformResult(
                platform="GitHub",
                url=f"https://github.com/{cfg.username}",
                category="dev",
                exists=True,
                status="found",
            )
        ]
        return r

    monkeypatch.setattr(api_server, "run_scan", fake_run_scan)

    app = api.create_app()
    return TestClient(app)


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_platform_catalog_contract(client: TestClient) -> None:
    response = client.get("/platforms")
    assert response.status_code == 200
    payload = response.json()
    assert payload["core_count"] == 100
    assert payload["full_count"] <= 500
    assert any(row["value"] == "content" for row in payload["categories"])
    assert sum(row["alias_probe"] for row in payload["platforms"]) == 15


def test_openapi_uses_project_name(client: TestClient) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["title"] == "Open Source Intelligence API"


def test_scan_endpoint_returns_payload(client: TestClient) -> None:
    r = client.post(
        "/scan",
        json={"username": "alice", "save_history": False},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["username"] == "alice"
    assert any(p["exists"] for p in data["platforms"])
    assert data["schema_version"]
    assert "capabilities" in data
    assert "warnings" in data
    assert data["investigator_summary"]["headline"]
    assert "priority_score" in data["investigator_summary"]
    assert "confidence_band" in data["investigator_summary"]


def test_scan_rejects_empty_username(client: TestClient) -> None:
    r = client.post("/scan", json={"username": "", "save_history": False})
    assert r.status_code == 422


def test_scan_rejects_alias_candidate_limit_above_24(client: TestClient) -> None:
    response = client.post(
        "/scan",
        json={
            "username": "alice",
            "alias_max_candidates": 25,
            "save_history": False,
        },
    )
    assert response.status_code == 422


def test_scan_request_maps_advanced_config_fields() -> None:
    req = api_server.ScanRequest(
        username="alice",
        holehe=True,
        recursive_depth=2,
        crypto_addresses=["0xabc"],
        proxies=["http://proxy.example:8080"],
        browser_backend="obscura",
        gitleaks_paths=["/workspace/repo"],
        exif_image_urls=["https://example.test/photo.jpg"],
        company_query="Example Ltd",
        full_name="Alice Example",
        ai_skills=True,
    )
    cfg = api_server._cfg_from_request(req)
    assert cfg.holehe is True
    assert cfg.recursive_depth == 2
    assert cfg.crypto_addresses == ("0xabc",)
    assert cfg.proxies == ("http://proxy.example:8080",)
    assert cfg.browser_backend == "obscura"
    assert cfg.gitleaks_paths == ("/workspace/repo",)
    assert cfg.exif_image_urls == ("https://example.test/photo.jpg",)
    assert cfg.company_query == "Example Ltd"
    assert cfg.full_name == "Alice Example"
    assert cfg.ai_skills is True


def test_scan_request_covers_scan_config_surface() -> None:
    config_fields = {item.name for item in fields(ScanConfig)}
    assert config_fields <= set(api_server.ScanRequest.model_fields)


def test_watchlist_add_and_list(client: TestClient) -> None:
    r = client.post("/watchlist", json={"username": "bob", "tags": ["red"]})
    assert r.status_code == 200
    assert r.json()["username"] == "bob"

    r = client.get("/watchlist")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["entries"][0]["username"] == "bob"


def test_watchlist_remove(client: TestClient) -> None:
    client.post("/watchlist", json={"username": "carol", "tags": []})
    r = client.delete("/watchlist/carol")
    assert r.status_code == 200
    assert r.json()["removed"] == "carol"
    # Second delete 404s.
    r2 = client.delete("/watchlist/carol")
    assert r2.status_code == 404


def test_watchlist_add_rejects_empty(client: TestClient) -> None:
    # Pydantic min_length=1 handles empty string — returns 422.
    r = client.post("/watchlist", json={"username": "", "tags": []})
    assert r.status_code == 422


def test_history_endpoints_missing_user(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "list_scans", lambda u, limit=20: [])
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)

    r = client.get("/history/ghost")
    assert r.status_code == 200
    assert r.json()["count"] == 0

    r = client.get("/history/ghost/latest")
    assert r.status_code == 404

    r = client.get("/history/ghost/diff")
    assert r.status_code == 404


def test_history_scan_returns_saved_payload(client: TestClient) -> None:
    scan_id = history.save_scan(
        {"username": "alice", "found_count": 1, "platforms": [{"platform": "GitHub", "exists": True}]},
        ts=1000,
    )
    r = client.get(f"/history/scan/{scan_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == scan_id
    assert data["payload"]["username"] == "alice"


def test_is_available_true_when_deps_installed() -> None:
    assert api.is_available() is True


def test_search_endpoint_rejects_empty_query(client: TestClient) -> None:
    r = client.get("/search", params={"q": "   "})
    assert r.status_code == 400


def test_search_endpoint_returns_hits(
    client: TestClient, tmp_path: Path, monkeypatch
) -> None:
    from core import history
    from core import search as search_mod
    hist_db = tmp_path / "history.sqlite3"
    monkeypatch.setattr(history, "DEFAULT_DB_PATH", hist_db)
    monkeypatch.setattr(search_mod, "DEFAULT_DB_PATH", hist_db)
    for fn in (history.save_scan, history.list_scans, history.get_latest,
               history.get_scan):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", hist_db)
    for fn in (search_mod.search, search_mod.index_scan, search_mod.reindex):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", hist_db)

    payload = {
        "username": "alice",
        "found_count": 1,
        "platforms": [
            {
                "platform": "GitHub",
                "url": "https://github.com/alice",
                "exists": True,
                "profile_data": {"bio": "distinctivephrase"},
            }
        ],
    }
    scan_id = history.save_scan(payload, ts=1000)
    search_mod.index_scan(scan_id, payload)

    r = client.get("/search", params={"q": "distinctivephrase"})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["hits"][0]["username"] == "alice"


@pytest.mark.asyncio
async def test_scan_stream_emits_events(client: TestClient) -> None:
    transport = httpx.ASGITransport(app=client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac, ac.stream(
        "POST",
        "/scan/stream",
        json={"username": "eve", "save_history": False},
    ) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        chunks = [chunk async for chunk in r.aiter_bytes()]
        body = b"".join(chunks)
    text = body.decode()
    # At least the terminal result event must arrive.
    assert "\"kind\": \"result\"" in text
    assert "eve" in text


def test_capabilities_endpoint_returns_map(client: TestClient) -> None:
    r = client.get("/capabilities")
    assert r.status_code == 200
    data = r.json()
    assert data["schema_version"]
    assert "capabilities" in data
    assert "api" in data["capabilities"]


@pytest.mark.asyncio
async def test_scan_job_lifecycle_returns_result_payload(client: TestClient) -> None:
    transport = httpx.ASGITransport(app=client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        created = await ac.post(
            "/scan-jobs",
            json={"username": "alice", "save_history": False},
        )
        assert created.status_code == 202
        job_id = created.json()["id"]

        for _ in range(20):
            detail = await ac.get(f"/scan-jobs/{job_id}")
            assert detail.status_code == 200
            data = detail.json()
            if data["status"] == "completed":
                assert data["result"]["username"] == "alice"
                assert data["result"]["schema_version"]
                break
            await asyncio.sleep(0)
        else:
            pytest.fail("scan job did not complete in time")

        result = await ac.get(f"/scan-jobs/{job_id}/result")
        assert result.status_code == 200
        assert result.json()["username"] == "alice"


@pytest.mark.asyncio
async def test_scan_job_events_stream_result(client: TestClient) -> None:
    transport = httpx.ASGITransport(app=client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        created = await ac.post(
            "/scan-jobs",
            json={"username": "mallory", "save_history": False},
        )
        job_id = created.json()["id"]
        async with ac.stream(
            "GET",
            f"/scan-jobs/{job_id}/events",
        ) as r:
            assert r.status_code == 200
            body = b"".join([chunk async for chunk in r.aiter_bytes()])
    text = body.decode()
    assert "\"kind\": \"result\"" in text
    assert "mallory" in text


def test_scan_job_capacity_returns_429(client: TestClient) -> None:
    class _FullStore:
        def create_job(self, *args, **kwargs):
            raise RuntimeError("scan job queue is full")

    client.app.state.scan_jobs = _FullStore()
    r = client.post(
        "/scan-jobs",
        json={"username": "alice", "save_history": False},
    )

    assert r.status_code == 429
    assert "queue is full" in r.json()["detail"]


def test_graph_404_when_no_history(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)
    r = client.get("/graph/ghost")
    assert r.status_code == 404


def test_heatmap_404_when_no_history(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)
    r = client.get("/heatmap/ghost")
    assert r.status_code == 404


def test_heatmap_folds_duplicate_coords(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    payload = {
        "username": "mallory",
        "platforms": [],
        "geo_points": [
            {"lat": 41.0, "lng": 29.0, "display": "Istanbul", "source": "GitHub"},
            {"lat": 41.00004, "lng": 29.00003, "display": "Istanbul", "source": "Twitter"},
            {"lat": 52.52, "lng": 13.4, "display": "Berlin", "source": "Bluesky"},
            {"lat": "bad", "lng": 0.0, "display": "skip me"},  # must be discarded
        ],
    }
    entry = HistoryEntry(id=7, username="mallory", ts=1, found_count=0, payload=payload)
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: entry)

    r = client.get("/heatmap/mallory")
    assert r.status_code == 200
    data = r.json()
    # Two unique rounded coords → two heatmap points.
    assert len(data["points"]) == 2
    istanbul = next(p for p in data["points"] if round(p[0], 1) == 41.0)
    # Weight reflects the two Istanbul hits that fold together.
    assert istanbul[2] == 2
    # Markers expose source + label.
    sources = {m["source"] for m in data["markers"]}
    assert {"GitHub", "Twitter", "Bluesky"}.issubset(sources)


def test_compare_404_when_either_has_no_history(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)
    r = client.get("/compare", params={"a": "alice", "b": "bob"})
    assert r.status_code == 404


def test_compare_returns_diff_and_both_payloads(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    a_payload = {
        "username": "alice",
        "found_count": 1,
        "platforms": [
            {"platform": "GitHub", "exists": True, "profile_data": {"bio": "old"}}
        ],
    }
    b_payload = {
        "username": "alice",
        "found_count": 2,
        "platforms": [
            {"platform": "GitHub", "exists": True, "profile_data": {"bio": "new"}},
            {"platform": "Twitter", "exists": True, "profile_data": {}},
        ],
    }
    a_entry = HistoryEntry(id=1, username="alice", ts=10, found_count=1, payload=a_payload)
    b_entry = HistoryEntry(id=2, username="alice", ts=20, found_count=2, payload=b_payload)

    monkeypatch.setattr(
        api_server,
        "get_latest",
        lambda u, before_id=None: a_entry if u == "alice" else b_entry,
    )
    r = client.get("/compare", params={"a": "alice", "b": "alice2"})
    assert r.status_code == 200
    data = r.json()
    assert data["platforms"]["added"] == ["Twitter"]
    assert data["found_count_delta"] == 1
    assert any(pc["platform"] == "GitHub" for pc in data["platform_changes"])
    assert data["scan_a"]["id"] == 1
    assert data["scan_b"]["id"] == 2
    assert data["scan_a"]["payload"]["username"] == "alice"


def test_compare_respects_explicit_scan_ids(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    entries = {
        7: HistoryEntry(id=7, username="alice", ts=100, found_count=0, payload={"username": "alice"}),
        8: HistoryEntry(id=8, username="alice", ts=200, found_count=1, payload={"username": "alice", "found_count": 1}),
    }
    monkeypatch.setattr(api_server, "get_scan", lambda sid: entries.get(sid))
    # get_latest must not be consulted when both ids are pinned.
    monkeypatch.setattr(api_server, "get_latest", lambda *a, **kw: None)

    r = client.get("/compare", params={"a": "alice", "b": "alice", "a_scan": 7, "b_scan": 8})
    assert r.status_code == 200
    data = r.json()
    assert data["scan_a"]["id"] == 7
    assert data["scan_b"]["id"] == 8


def test_correlate_requires_both_usernames(client: TestClient) -> None:
    r = client.get("/correlate", params={"a": "alice", "b": ""})
    assert r.status_code == 422
    r = client.get("/correlate", params={"a": "alice", "b": "Alice"})
    assert r.status_code == 400


def test_correlate_404_when_either_has_no_history(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    alice = HistoryEntry(id=1, username="alice", ts=1, found_count=0, payload={"username": "alice"})

    def fake_latest(u, before_id=None):
        return alice if u == "alice" else None

    monkeypatch.setattr(api_server, "get_latest", fake_latest)
    r = client.get("/correlate", params={"a": "alice", "b": "ghost"})
    assert r.status_code == 404


def test_correlate_returns_score_and_signals(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    a_payload = {
        "username": "alice",
        "emails": [{"email": "shared@x.io"}],
        "phone_intel": [{"e164": "+905551234567"}],
    }
    b_payload = {
        "username": "alice2",
        "emails": [{"email": "shared@x.io"}],
        "phone_intel": [{"e164": "+905551234567"}],
    }
    a_entry = HistoryEntry(id=1, username="alice", ts=10, found_count=1, payload=a_payload)
    b_entry = HistoryEntry(id=2, username="alice2", ts=20, found_count=1, payload=b_payload)

    monkeypatch.setattr(
        api_server,
        "get_latest",
        lambda u, before_id=None: a_entry if u == "alice" else b_entry,
    )
    r = client.get("/correlate", params={"a": "alice", "b": "alice2"})
    assert r.status_code == 200
    data = r.json()
    assert data["username_a"] == "alice"
    assert data["username_b"] == "alice2"
    assert data["verdict"] == "very_likely_same"
    kinds = {s["kind"] for s in data["signals"]}
    assert {"email", "phone"} <= kinds
    assert data["scan_a"]["id"] == 1
    assert data["scan_b"]["id"] == 2


def test_social_graph_rejects_empty_usernames(client: TestClient) -> None:
    r = client.get("/social-graph", params={"a": "", "b": "bob"})
    assert r.status_code == 422


def test_social_graph_rejects_unknown_platform(client: TestClient) -> None:
    r = client.get(
        "/social-graph", params={"a": "alice", "b": "bob", "platform": "twitter"}
    )
    assert r.status_code == 400


def test_social_graph_returns_overlap(client: TestClient, monkeypatch) -> None:
    from core.social_graph import SocialNeighbors

    async def fake_fetch(client_, username, *, max_pages=5, token=None):
        if username == "alice":
            return SocialNeighbors(
                platform="github",
                username="alice",
                followers=frozenset({"carol", "dave"}),
                following=frozenset({"eve"}),
            )
        return SocialNeighbors(
            platform="github",
            username="alice2",
            followers=frozenset({"carol", "frank"}),
            following=frozenset({"eve", "grace"}),
        )

    monkeypatch.setattr(api_server, "fetch_github_neighbors", fake_fetch)

    class _StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(api_server, "HTTPClient", _StubClient)

    r = client.get(
        "/social-graph", params={"a": "alice", "b": "alice2", "platform": "github"}
    )
    assert r.status_code == 200
    data = r.json()
    assert data["platform"] == "github"
    assert data["shared_followers"] == ["carol"]
    assert data["shared_following"] == ["eve"]
    assert data["neighbors_a"]["username"] == "alice"
    assert data["neighbors_b"]["username"] == "alice2"


def test_graph_returns_cytoscape_payload(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    payload = {
        "username": "mallory",
        "platforms": [
            {
                "platform": "GitHub",
                "url": "https://github.com/mallory",
                "category": "dev",
                "exists": True,
                "confidence": 0.9,
            }
        ],
        "emails": [{"email": "m@e.com", "source": "github", "breaches": ["LinkedIn"]}],
    }
    entry = HistoryEntry(id=1, username="mallory", ts=1, found_count=1, payload=payload)
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: entry)

    r = client.get("/graph/mallory")
    assert r.status_code == 200
    data = r.json()
    ids = {n["data"]["id"] for n in data["nodes"]}
    assert "mallory" in ids
    assert "platform::GitHub" in ids
    assert "email::m@e.com" in ids
    assert "breach::LinkedIn" in ids
    # Edges must include the root→platform relation.
    assert any(
        e["data"]["source"] == "mallory" and e["data"]["target"] == "platform::GitHub"
        for e in data["edges"]
    )


def test_cases_create_and_list(client: TestClient) -> None:
    r = client.post(
        "/cases",
        json={"name": "op-lighthouse", "description": "suspect X", "tags": ["urgent"]},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "op-lighthouse"

    r = client.get("/cases")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["entries"][0]["status"] == "open"


def test_cases_create_rejects_duplicate(client: TestClient) -> None:
    client.post("/cases", json={"name": "dupe", "description": ""})
    r = client.post("/cases", json={"name": "dupe", "description": ""})
    assert r.status_code == 400


def test_cases_detail_includes_notes_and_bookmarks(client: TestClient) -> None:
    r = client.post("/cases", json={"name": "op", "description": ""})
    case_id = r.json()["id"]
    client.post(f"/cases/{case_id}/notes", json={"body": "initial lead"})
    client.post(
        f"/cases/{case_id}/bookmarks",
        json={"target_type": "email", "target_value": "x@y.io", "label": "primary"},
    )
    r = client.get(f"/cases/{case_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "op"
    assert len(data["notes"]) == 1
    assert data["notes"][0]["body"] == "initial lead"
    assert len(data["bookmarks"]) == 1
    assert data["bookmarks"][0]["target_value"] == "x@y.io"


def test_cases_detail_404_when_missing(client: TestClient) -> None:
    r = client.get("/cases/999")
    assert r.status_code == 404


def test_cases_update_status(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    r = client.patch(f"/cases/{case_id}", json={"status": "closed"})
    assert r.status_code == 200
    assert r.json()["status"] == "closed"


def test_cases_update_rejects_bad_status(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    r = client.patch(f"/cases/{case_id}", json={"status": "pending"})
    assert r.status_code == 400


def test_cases_delete_cascades(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    client.post(f"/cases/{case_id}/notes", json={"body": "n"})
    r = client.delete(f"/cases/{case_id}")
    assert r.status_code == 200
    r = client.get(f"/cases/{case_id}")
    assert r.status_code == 404


def test_cases_note_on_missing_case_404(client: TestClient) -> None:
    r = client.post("/cases/999/notes", json={"body": "ghost"})
    assert r.status_code == 404


def test_cases_bookmark_rejects_bad_target_type(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    r = client.post(
        f"/cases/{case_id}/bookmarks",
        json={"target_type": "carrier-pigeon", "target_value": "x"},
    )
    assert r.status_code == 400


def test_cases_delete_note_and_bookmark(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    note_id = client.post(
        f"/cases/{case_id}/notes", json={"body": "n"}
    ).json()["id"]
    bm_id = client.post(
        f"/cases/{case_id}/bookmarks",
        json={"target_type": "url", "target_value": "https://x"},
    ).json()["id"]
    assert client.delete(f"/cases/notes/{note_id}").status_code == 200
    assert client.delete(f"/cases/bookmarks/{bm_id}").status_code == 200
    assert client.delete(f"/cases/notes/{note_id}").status_code == 404
    assert client.delete(f"/cases/bookmarks/{bm_id}").status_code == 404


def test_cases_link_existing_scan(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    scan_id = history.save_scan(
        {
            "username": "alice",
            "found_count": 1,
            "platforms": [{"platform": "GitHub", "exists": True}],
        },
        ts=1000,
    )
    r = client.post(f"/cases/{case_id}/scans", json={"scan_id": scan_id})
    assert r.status_code == 200
    data = r.json()
    assert data["target_type"] == "scan"
    assert data["scan_id"] == scan_id
    assert data["scan"]["username"] == "alice"


def test_cases_link_existing_scan_404_when_missing(client: TestClient) -> None:
    case_id = client.post("/cases", json={"name": "op", "description": ""}).json()["id"]
    r = client.post(f"/cases/{case_id}/scans", json={"scan_id": 999})
    assert r.status_code == 404


def test_auth_login_success_and_token_shape(client: TestClient) -> None:
    auth.create_user("alice", "s3cret", role="analyst")
    r = client.post("/auth/login", json={"username": "alice", "password": "s3cret"})
    assert r.status_code == 200
    data = r.json()
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    assert data["user"]["username"] == "alice"
    # Token parses back.
    payload = auth.decode_token(data["access_token"], secret="test-secret")
    assert payload["sub"] == "alice"


def test_auth_login_rejects_wrong_password(client: TestClient) -> None:
    auth.create_user("alice", "right")
    r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_auth_login_rejects_unknown_user(client: TestClient) -> None:
    r = client.post("/auth/login", json={"username": "ghost", "password": "x"})
    assert r.status_code == 401


def test_auth_me_requires_bearer_token(client: TestClient) -> None:
    r = client.get("/auth/me")
    assert r.status_code == 401

    auth.create_user("alice", "pw")
    login = client.post(
        "/auth/login", json={"username": "alice", "password": "pw"}
    ).json()
    token = login["access_token"]
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["username"] == "alice"


def test_auth_me_rejects_invalid_token(client: TestClient) -> None:
    r = client.get("/auth/me", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


def test_auth_gate_off_by_default(client: TestClient) -> None:
    # When OSINT_AUTH_REQUIRED is unset, every route is public as before.
    r = client.get("/watchlist")
    assert r.status_code == 200


def test_auth_gate_blocks_protected_when_required(
    tmp_path: Path, monkeypatch
) -> None:
    # Stand up a second client with the gate forced on.
    wl_db = tmp_path / "wl2.sqlite3"
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", wl_db)
    for fn in (watchlist.add, watchlist.remove, watchlist.list_all,
              watchlist.mark_scanned, watchlist.get):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", wl_db)

    users_db = tmp_path / "users2.sqlite3"
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", users_db)
    for fn in (auth.create_user, auth.get_user, auth.list_users, auth.authenticate):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", users_db)

    monkeypatch.setenv("OSINT_AUTH_SECRET", "t2")
    monkeypatch.setenv("OSINT_AUTH_REQUIRED", "1")

    gated = TestClient(api.create_app())
    # /health stays public even with the gate on.
    assert gated.get("/health").status_code == 200
    # /watchlist is not public → 401.
    assert gated.get("/watchlist").status_code == 401

    auth.create_user("alice", "pw")
    token = gated.post(
        "/auth/login", json={"username": "alice", "password": "pw"}
    ).json()["access_token"]
    r = gated.get("/watchlist", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_auth_gate_viewer_is_read_only(tmp_path: Path, monkeypatch) -> None:
    wl_db = tmp_path / "wl-viewer.sqlite3"
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", wl_db)
    for fn in (watchlist.add, watchlist.remove, watchlist.list_all,
              watchlist.mark_scanned, watchlist.get):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", wl_db)

    users_db = tmp_path / "users-viewer.sqlite3"
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", users_db)
    for fn in (auth.create_user, auth.get_user, auth.list_users, auth.authenticate):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", users_db)

    monkeypatch.setenv("OSINT_AUTH_SECRET", "viewer-secret")
    monkeypatch.setenv("OSINT_AUTH_REQUIRED", "1")

    gated = TestClient(api.create_app())
    auth.create_user("viewer", "pw", role="viewer")
    token = gated.post(
        "/auth/login", json={"username": "viewer", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert gated.get("/watchlist", headers=headers).status_code == 200
    assert gated.post(
        "/watchlist", json={"username": "alice"}, headers=headers
    ).status_code == 403


def test_auth_gate_delete_requires_admin(tmp_path: Path, monkeypatch) -> None:
    wl_db = tmp_path / "wl-admin.sqlite3"
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", wl_db)
    for fn in (watchlist.add, watchlist.remove, watchlist.list_all,
              watchlist.mark_scanned, watchlist.get):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", wl_db)

    users_db = tmp_path / "users-admin.sqlite3"
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", users_db)
    for fn in (auth.create_user, auth.get_user, auth.list_users, auth.authenticate):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", users_db)

    monkeypatch.setenv("OSINT_AUTH_SECRET", "admin-secret")
    monkeypatch.setenv("OSINT_AUTH_REQUIRED", "1")

    watchlist.add("alice")
    gated = TestClient(api.create_app())
    auth.create_user("analyst", "pw", role="analyst")
    auth.create_user("admin", "pw", role="admin")
    analyst_token = gated.post(
        "/auth/login", json={"username": "analyst", "password": "pw"}
    ).json()["access_token"]
    admin_token = gated.post(
        "/auth/login", json={"username": "admin", "password": "pw"}
    ).json()["access_token"]

    assert gated.delete(
        "/watchlist/alice",
        headers={"Authorization": f"Bearer {analyst_token}"},
    ).status_code == 403
    assert gated.delete(
        "/watchlist/alice",
        headers={"Authorization": f"Bearer {admin_token}"},
    ).status_code == 200
