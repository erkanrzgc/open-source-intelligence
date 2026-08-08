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
