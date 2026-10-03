"""Offline browser verification of explicit lead execution and safe evidence UI."""

import json
from pathlib import Path

import pytest


def test_workbench_browser_requires_click_and_uses_header_auth(tmp_path):
    playwright = pytest.importorskip("playwright.sync_api")
    root = Path(__file__).resolve().parents[1]
    mutations = []
    view = {
        "summary": {"scans": 1, "nodes": 2, "edges": 1},
        "warnings": [],
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "data": {
                        "id": "edge-1",
                        "relation": "identity_candidate",
                        "verdict": "uncertain",
                        "observations": [
                            {
                                "scan_id": 1,
                                "checked_at": None,
                                "http_status": 200,
                                "presence": "confirmed",
                                "source_url": "https://example.test/<img src=x onerror=boom>",
                                "contract_revision": "fixture",
                                "reason_codes": ["exact_username"],
                            }
                        ],
                    }
                }
            ],
        },
        "timeline": [{"kind": "coverage_lost", "ts": 100, "scan_id": 1}],
        "budget": {
            "max_pivots": 10,
            "reserved_pivots": 0,
            "max_requests": 120,
            "reserved_requests": 0,
        },
        "allowed_platforms": ["GitHub", "GitLab"],
        "leads": [
            {
                "id": "lead-1",
                "username": "alice_dev",
                "depth": 1,
                "verdict": "uncertain",
                "reason": "public_profile_link_or_mention",
                "source_scan_id": 1,
                "eligible": True,
            }
        ],
        "pivots": [],
    }
    with playwright.sync_playwright() as p:
        if not Path(p.chromium.executable_path).exists():
            pytest.skip("optional Chromium browser not installed")
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1100, "height": 900})

            def route_request(route):
                request = route.request
                if request.url == "http://workbench.test/":
                    route.fulfill(
                        content_type="text/html",
                        body="<html><body><main id='host'></main></body></html>",
                    )
                    return
                assert request.headers.get("authorization") == "Bearer local-fixture-token"
                assert "token=" not in request.url
                if request.method != "GET":
                    mutations.append((request.url, request.post_data_json))
                    if request.url.endswith("/pivots"):
                        view["leads"][0].update(eligible=False, blocked_reason="already_reserved")
                        view["pivots"] = [
                            {
                                "username": "alice_dev",
                                "status": "queued",
                                "request_budget": 8,
                                "job_id": "job-1",
                            }
                        ]
                    elif request.url.endswith("/cancel"):
                        view["pivots"][0]["status"] = "cancelled"
                    route.fulfill(content_type="application/json", body="{}")
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(view))

            page.route("**/*", route_request)
            page.goto("http://workbench.test/")
            page.evaluate("localStorage.setItem('osint_token', 'local-fixture-token')")
            page.add_style_tag(path=str(root / "web/style.css"))
            page.add_script_tag(path=str(root / "web/workbench.js"))
            page.evaluate("renderCaseWorkbench(1, document.getElementById('host'))")
            assert mutations == []
            page.get_by_text("Evidence list (first 150 links)").click()
            page.get_by_role(
                "button", name="identity_candidate · uncertain · 1 observations"
            ).click()
            assert page.get_by_text("observation time unknown", exact=False).count() == 1
            assert page.locator("img").count() == 0
            page.screenshot(path=str(tmp_path / "workbench.png"), full_page=True)
            page.get_by_role("button", name="Run this lead").click()
            page.get_by_role("button", name="already_reserved").wait_for()
            assert mutations[0][1] == {
                "lead_id": "lead-1",
                "platforms": ["GitHub", "GitLab"],
                "request_budget": 8,
            }
            page.get_by_role("button", name="Cancel", exact=True).click()
            page.get_by_text("alice_dev · cancelled", exact=False).wait_for()
            assert len(mutations) == 2
        finally:
            browser.close()
