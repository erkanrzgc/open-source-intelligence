"""End-to-end local case routes with stub scans and isolated SQLite stores."""
# ruff: noqa: E402 -- optional API dependencies checked first.

import asyncio

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from core import auth, cases, history
from core.api import jobs, server
from core.api.jobs import ScanJobStore
from core.models import PlatformResult, ScanResult
from core.scan_service import complete_scan_result


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    cdb, hdb = tmp_path / "cases.db", tmp_path / "history.db"
    monkeypatch.setattr(cases, "DEFAULT_DB_PATH", cdb)
    monkeypatch.setattr(history, "DEFAULT_DB_PATH", hdb)
    monkeypatch.delenv("OSINT_AUTH_REQUIRED", raising=False)
    case = cases.create_case("case", db_path=cdb)
    root = ScanResult(
        username="alice",
        platforms=[
            PlatformResult(
                platform="GitHub",
                url="https://github.com/alice",
                category="dev",
                exists=True,
                verification={"verdict": "confirmed"},
                profile_data={"github_username": "alice_dev"},
            )
        ],
    )
    sid = history.save_scan(root.to_dict(), ts=100, db_path=hdb)
    cases.add_bookmark(case.id, target_type="scan", target_value="alice", scan_id=sid, db_path=cdb)
    configs = []

    async def runner(cfg):
        configs.append(cfg)
        return ScanResult(username=cfg.username, diagnostics={"http_budget": {"request_count": 1}})

    def complete(result, cfg, **kwargs):
        return complete_scan_result(
            result, cfg, **kwargs, cases_db=cdb, history_db=hdb, watchlist_db=tmp_path / "watch.db"
        )

    monkeypatch.setattr(server, "run_scan", runner)
    monkeypatch.setattr(jobs, "complete_scan_result", complete)
    return server.build_app(), case, configs


@pytest.mark.asyncio
async def test_workbench_read_does_not_scan_and_pivot_is_explicit(workspace):
    app, case, configs = workspace
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert configs == []
        lead = first["leads"][0]
        response = await client.post(
            f"/cases/{case.id}/pivots",
            json={"lead_id": lead["id"], "platforms": ["GitHub"], "request_budget": 3},
        )
        assert response.status_code == 202
        job = app.state.scan_jobs.get(response.json()["job"]["id"])
        task = job._task
        if task is not None:
            await task
        assert configs[0].platform_names == ("GitHub",)
        assert configs[0].http_request_budget == 3
        assert not configs[0].smart and not configs[0].recursive
        second = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert second["summary"]["scans"] == 2
        assert second["pivots"][0]["status"] == "completed"
        saved = history.get_scan(job.scan_id, db_path=history.DEFAULT_DB_PATH)
        assert saved.payload["diagnostics"]["investigation"]["depth"] == 1
        duplicate = await client.post(f"/cases/{case.id}/pivots", json={"lead_id": lead["id"]})
        assert duplicate.status_code in (404, 409)
        assert len(configs) == 1


@pytest.mark.asyncio
async def test_queue_failure_releases_unstarted_reservation(workspace, monkeypatch):
    app, case, _ = workspace

    def full(*args, **kwargs):
        raise RuntimeError("scan job queue is full")

    monkeypatch.setattr(app.state.scan_jobs, "create_job", full)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        view = (await client.get(f"/cases/{case.id}/workbench")).json()
        response = await client.post(
            f"/cases/{case.id}/pivots", json={"lead_id": view["leads"][0]["id"]}
        )
        assert response.status_code == 429
        after = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert after["pivots"] == []
        assert after["budget"]["reserved_requests"] == 0


@pytest.mark.asyncio
async def test_exhausted_pivot_remains_partial_after_job_store_restart(workspace):
    app, case, _ = workspace

    async def exhausted(cfg):
        return ScanResult(
            username=cfg.username,
            diagnostics={"http_budget": {"limit": 1, "request_count": 1, "exhausted": True}},
        )

    app.state.scan_jobs = ScanJobStore(runner=exhausted)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        view = (await client.get(f"/cases/{case.id}/workbench")).json()
        accepted = await client.post(
            f"/cases/{case.id}/pivots",
            json={"lead_id": view["leads"][0]["id"], "request_budget": 1},
        )
        assert accepted.status_code == 202
        job = app.state.scan_jobs.get(accepted.json()["job"]["id"])
        if job._task is not None:
            await job._task
        after = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert after["pivots"][0]["status"] == "partial"
        assert after["budget"]["reserved_requests"] == 1
        assert after["summary"]["scans"] == 2
        app.state.scan_jobs = ScanJobStore(runner=exhausted)
        restored = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert restored["pivots"][0]["status"] == "partial"
        assert restored["budget"] == after["budget"]


@pytest.mark.asyncio
async def test_viewer_can_read_but_cannot_mutate_workbench(workspace, monkeypatch):
    _, case, configs = workspace
    monkeypatch.setenv("OSINT_AUTH_REQUIRED", "1")
    monkeypatch.setenv("OSINT_AUTH_SECRET", "workbench-test-secret")
    app = server.build_app()
    token = auth.issue_token(
        user_id=1, username="reader", role="viewer", secret="workbench-test-secret"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        response = await client.get(f"/cases/{case.id}/workbench")
        assert response.status_code == 200
        view = response.json()
        edge_id = view["graph"]["edges"][0]["data"]["id"]
        pivot = await client.post(
            f"/cases/{case.id}/pivots", json={"lead_id": view["leads"][0]["id"]}
        )
        review = await client.put(
            f"/cases/{case.id}/edges/{edge_id}/review", json={"decision": "accepted"}
        )
        cancel = await client.post("/scan-jobs/unknown/cancel")
        assert [pivot.status_code, review.status_code, cancel.status_code] == [403, 403, 403]
        assert configs == []
        after = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert after["pivots"] == []
        assert after["graph"]["edges"][0]["data"]["analyst_review"] is None


@pytest.mark.asyncio
async def test_reviews_validate_case_edge_and_do_not_change_verdict(workspace):
    app, case, _ = workspace
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        view = (await client.get(f"/cases/{case.id}/workbench")).json()
        edge = view["graph"]["edges"][0]["data"]
        response = await client.put(
            f"/cases/{case.id}/edges/{edge['id']}/review",
            json={"decision": "rejected", "note": "Review separately"},
        )
        assert response.status_code == 200
        after = (await client.get(f"/cases/{case.id}/workbench")).json()
        updated = after["graph"]["edges"][0]["data"]
        assert updated["verdict"] == edge["verdict"]
        assert updated["analyst_review"]["decision"] == "rejected"
        assert (
            await client.put(
                f"/cases/{case.id}/edges/foreign-edge/review", json={"decision": "accepted"}
            )
        ).status_code == 404
        assert (await client.get("/cases/999/workbench")).status_code == 404


@pytest.mark.asyncio
async def test_restart_does_not_replay_or_release_pivot(workspace):
    app, case, configs = workspace
    release = asyncio.Event()

    async def slow(cfg):
        await release.wait()
        return ScanResult(username=cfg.username)

    app.state.scan_jobs = ScanJobStore(runner=slow)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        view = (await client.get(f"/cases/{case.id}/workbench")).json()
        accepted = (
            await client.post(f"/cases/{case.id}/pivots", json={"lead_id": view["leads"][0]["id"]})
        ).json()
        old_store = app.state.scan_jobs
        old_job = old_store.get(accepted["job"]["id"])
        task = old_job._task
        app.state.scan_jobs = ScanJobStore(runner=slow)
        restored = (await client.get(f"/cases/{case.id}/workbench")).json()
        assert restored["pivots"][0]["status"] == "interrupted"
        assert restored["budget"]["reserved_requests"] == 8
        assert configs == []
        old_store.cancel(old_job.id)
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_workbench_python_rest_mcp_and_cli_share_payload(workspace, capsys):
    import mcp_server
    from core import cli
    from core.investigation import load_workbench

    app, case, configs = workspace
    expected = load_workbench(case.id)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get(f"/cases/{case.id}/workbench")).json() == expected
    assert mcp_server._get_case_workbench({"case_id": case.id}) == expected
    assert cli.main(["workbench", str(case.id)]) == 0
    import json

    assert json.loads(capsys.readouterr().out) == expected
    assert configs == []
