"""Tests for mcp_server.py — JSON-RPC dispatch and scan tool."""

import pytest

import mcp_server
from core.models import ScanResult
from mcp_server import PROTOCOL_VERSION, _dispatch


@pytest.mark.asyncio
async def test_initialize():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp is not None
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == "open-source-intelligence"


@pytest.mark.asyncio
async def test_tools_list():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert resp is not None
    tools = resp["result"]["tools"]
    assert any(t["name"] == "scan_username" for t in tools)
    assert any(t["name"] == "get_scan" for t in tools)
    scan_tool = next(t for t in tools if t["name"] == "scan_username")
    properties = scan_tool["inputSchema"]["properties"]
    assert properties["smart"]["default"] is True
    assert properties["platform_scope"]["default"] == "core"
    assert properties["alias_max_candidates"]["maximum"] == 24
    assert properties["alias_max_candidates"]["default"] == 24
    assert properties["alias_platform_limit"]["maximum"] == 15
    assert properties["ai_correlate"]["default"] is False


@pytest.mark.asyncio
async def test_initialized_notification_no_response():
    resp = await _dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert resp is None


@pytest.mark.asyncio
async def test_unknown_method():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 3, "method": "bogus"})
    assert resp is not None
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_unknown_notification():
    resp = await _dispatch({"jsonrpc": "2.0", "method": "bogus/notify"})
    assert resp is None


@pytest.mark.asyncio
async def test_tools_call_unknown_tool():
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "wat", "arguments": {}},
        }
    )
    assert resp is not None
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_tools_call_invalid_username(monkeypatch):
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "scan_username", "arguments": {"username": ""}},
        }
    )
    assert resp is not None
    assert resp["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_tools_call_scan(monkeypatch):
    async def fake_run_scan(cfg):
        r = ScanResult(username=cfg.username)
        return r

    monkeypatch.setattr(mcp_server, "run_scan", fake_run_scan)

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "scan_username",
                "arguments": {"username": "alice", "categories": ["dev"]},
            },
        }
    )
    assert resp is not None
    content = resp["result"]["content"][0]["text"]
    assert '"username": "alice"' in content
    assert '"schema_version"' in content


@pytest.mark.asyncio
async def test_tools_call_scan_maps_identity_configuration(monkeypatch):
    captured = []

    async def fake_run_scan(cfg):
        captured.append(cfg)
        return ScanResult(username=cfg.username)

    monkeypatch.setattr(mcp_server, "run_scan", fake_run_scan)
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 61,
            "method": "tools/call",
            "params": {
                "name": "scan_username",
                "arguments": {
                    "username": "alice",
                    "smart": False,
                    "platform_scope": "full",
                    "alias_max_candidates": 4,
                    "alias_platform_limit": 7,
                },
            },
        }
    )

    assert resp is not None and "result" in resp
    assert len(captured) == 1
    cfg = captured[0]
    assert cfg.smart is False
    assert cfg.platform_scope == "full"
    assert cfg.alias_max_candidates == 4
    assert cfg.alias_platform_limit == 7


@pytest.mark.asyncio
async def test_tools_call_list_history(monkeypatch):
    monkeypatch.setattr(mcp_server, "list_scans", lambda username, limit=20: [])
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "list_history",
                "arguments": {"username": "alice"},
            },
        }
    )
    assert resp is not None
    content = resp["result"]["content"][0]["text"]
    assert '"count": 0' in content


@pytest.mark.asyncio
async def test_redteam_recon_tool_listed():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})
    assert resp is not None
    assert any(t["name"] == "redteam_recon" for t in resp["result"]["tools"])


@pytest.mark.asyncio
async def test_redteam_recon_requires_domain():
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {"name": "redteam_recon", "arguments": {}},
        }
    )
    assert resp is not None
    assert resp["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_redteam_recon_happy_path(monkeypatch):
    from modules.recon.models import (
        EmailCandidate,
        GithubCommitter,
        ReconSubdomain,
    )

    async def fake_enum(_client, _domain):
        return ["api.acme.com"]

    async def fake_scan_org(_client, _org, *, max_repos=30, commits_per_repo=30):
        return [GithubCommitter(email="ada@acme.com", name="Ada", repo="acme/x")]

    async def fake_enrich(_client, domain, *, existing=None):
        hosts = list(existing or []) + ["vpn.acme.com"]
        return [ReconSubdomain(host=h, source="dns_lookup") for h in hosts]

    fake_candidate = EmailCandidate(
        email="a.b@acme.com",
        first_name="a",
        last_name="b",
        pattern="{first}.{last}",
        domain="acme.com",
    )

    import modules.dns_lookup as dns_lookup
    from modules.recon import email_patterns, github_org, subdomains_extra

    monkeypatch.setattr(dns_lookup, "enumerate_subdomains", fake_enum)
    monkeypatch.setattr(github_org, "scan_org", fake_scan_org)
    monkeypatch.setattr(subdomains_extra, "enrich_subdomains", fake_enrich)
    monkeypatch.setattr(
        email_patterns, "generate_bulk", lambda names, domain: [fake_candidate] if names else []
    )

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {
                "name": "redteam_recon",
                "arguments": {
                    "domain": "acme.com",
                    "names": ["A B"],
                    "github_org": "acme",
                },
            },
        }
    )
    assert resp is not None
    content = resp["result"]["content"][0]["text"]
    assert '"domain": "acme.com"' in content
    assert '"github_committers"' in content
    assert '"email_candidates"' in content
    assert '"subdomains"' in content
    assert '"counts"' in content


@pytest.mark.asyncio
async def test_tools_call_add_watchlist(monkeypatch):
    class Entry:
        def to_dict(self):
            return {"id": 1, "username": "alice"}

    monkeypatch.setattr(mcp_server.watchlist, "add", lambda username, tags, notes: Entry())
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "add_watchlist",
                "arguments": {"username": "alice", "tags": ["red"]},
            },
        }
    )
    assert resp is not None
    content = resp["result"]["content"][0]["text"]
    assert '"username": "alice"' in content


@pytest.mark.asyncio
async def test_tools_call_scan_phone(monkeypatch):
    class FakeIntel:
        def to_dict(self):
            return {"raw": "+14155552671", "valid": True, "carrier": "TestCarrier"}

    async def fake_lookup(client, raw, default_region=None):
        return FakeIntel()

    import modules.phone.orchestrator
    monkeypatch.setattr(modules.phone.orchestrator, "lookup_phone", fake_lookup)

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {
                "name": "scan_phone",
                "arguments": {"phone": "+14155552671"},
            },
        }
    )
    assert resp is not None
    assert "TestCarrier" in resp["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_tools_call_scan_crypto(monkeypatch):
    class FakeCrypto:
        def to_dict(self):
            return {"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "network": "btc", "balance": "50.0"}

    async def fake_lookup(client, addresses):
        return [FakeCrypto()]

    import modules.crypto.orchestrator
    monkeypatch.setattr(modules.crypto.orchestrator, "lookup_crypto", fake_lookup)

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 61,
            "method": "tools/call",
            "params": {
                "name": "scan_crypto",
                "arguments": {"addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]},
            },
        }
    )
    assert resp is not None
    assert "50.0" in resp["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_tools_call_scan_email(monkeypatch):
    async def fake_scan(cfg):
        return ScanResult(username=cfg.username)

    monkeypatch.setattr(mcp_server, "run_scan", fake_scan)

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 62,
            "method": "tools/call",
            "params": {
                "name": "scan_email",
                "arguments": {"email": "test@example.com"},
            },
        }
    )
    assert resp is not None
    assert "test" in resp["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_tools_call_manage_case(tmp_path, monkeypatch):
    from core import cases
    db_file = tmp_path / "test_cases.sqlite3"
    monkeypatch.setattr(cases, "DEFAULT_DB_PATH", db_file)
    for fn in (
        cases.create_case, cases.get_case, cases.list_cases,
        cases.update_case, cases.delete_case,
        cases.add_note, cases.list_notes, cases.delete_note,
        cases.add_bookmark, cases.list_bookmarks, cases.delete_bookmark,
    ):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", db_file)

    # 1. Create case

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 63,
            "method": "tools/call",
            "params": {
                "name": "manage_case",
                "arguments": {"action": "create", "name": "Operation Titan", "description": "Test case"},
            },
        }
    )
    assert resp is not None
    assert "Operation Titan" in resp["result"]["content"][0]["text"]

    # 2. Add note
    resp_note = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 64,
            "method": "tools/call",
            "params": {
                "name": "manage_case",
                "arguments": {"action": "add_note", "case_id": 1, "body": "Suspect located", "author": "agent_007"},
            },
        }
    )
    assert resp_note is not None
    assert "Suspect located" in resp_note["result"]["content"][0]["text"]

    # 3. Get case
    resp_get = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 65,
            "method": "tools/call",
            "params": {
                "name": "manage_case",
                "arguments": {"action": "get", "case_id": 1},
            },
        }
    )
    assert resp_get is not None
    assert "Operation Titan" in resp_get["result"]["content"][0]["text"]
    assert "Suspect located" in resp_get["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_tools_call_export_scan(tmp_path, monkeypatch):
    out_file = tmp_path / "report.html"
    sample = {
        "username": "eve",
        "total_checked": 0,
        "found_count": 0,
        "scan_time": 0.1,
        "platforms": [],
    }
    mock_entry = type("Entry", (), {"payload": sample})()
    monkeypatch.setattr(mcp_server, "get_latest", lambda u: mock_entry)

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 66,
            "method": "tools/call",
            "params": {
                "name": "export_scan",
                "arguments": {"username": "eve", "format": "html", "output_path": str(out_file)},
            },
        }
    )
    assert resp is not None
    assert out_file.is_file()
    assert "eve" in out_file.read_text(encoding="utf-8")
