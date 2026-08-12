"""Identity payload parity across the public scan entrypoints."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

import mcp_server  # noqa: E402
from core import cli  # noqa: E402
from core.api import server as api_server  # noqa: E402
from core.config import ScanConfig  # noqa: E402
from core.models import IdentityCandidate, PlatformResult, ScanResult  # noqa: E402


def _golden_result() -> ScanResult:
    root = PlatformResult(
        platform="Hugging Face",
        url="https://huggingface.co/erkanrzgc",
        category="dev",
        exists=True,
        status="found",
        confidence=1.0,
        queried_username="erkanrzgc",
        canonical_username="erkanrzgc",
        verification={"verdict": "confirmed", "score": 1.0},
    )
    alias_profile = PlatformResult(
        platform="Hugging Face",
        url="https://huggingface.co/erkanrzgcc",
        category="dev",
        exists=True,
        status="found (variation)",
        confidence=1.0,
        queried_username="erkanrzgcc",
        canonical_username="erkanrzgcc",
        verification={"verdict": "confirmed", "score": 1.0},
    )
    candidate = IdentityCandidate(
        username="erkanrzgcc",
        handle_similarity=0.95,
        discovery_reasons=["repeat_last_character"],
        verdict="confirmed_same",
        score=0.95,
        evidence=[{"type": "direct_profile_link", "weight": 0.95}],
        profiles=[alias_profile],
    )
    return ScanResult(
        username="erkanrzgc",
        platforms=[root],
        discovered_usernames=["erkanrzgcc"],
        identity_candidates=[candidate],
    )


def _identity_view(payload: dict) -> dict:
    return {
        "username": payload["username"],
        "platforms": [
            {
                "platform": row["platform"],
                "url": row["url"],
                "verdict": row["verification"]["verdict"],
            }
            for row in payload["platforms"]
        ],
        "identity_candidates": payload["identity_candidates"],
    }


@pytest.mark.asyncio
async def test_python_cli_rest_and_mcp_preserve_identical_identity_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured_configs: list[ScanConfig] = []

    async def fake_run_scan(cfg: ScanConfig) -> ScanResult:
        captured_configs.append(cfg)
        return copy.deepcopy(_golden_result())

    def fake_complete(result: ScanResult, _cfg: ScanConfig, **_kwargs):
        return SimpleNamespace(payload=result.to_dict())

    golden = _identity_view(_golden_result().to_dict())

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_selected_platforms", lambda *_args: [])
    monkeypatch.setattr(cli, "_print_header", lambda *_args: None)
    monkeypatch.setattr(cli, "_show_result", lambda *_args: None)
    cli_output = tmp_path / "cli.json"
    monkeypatch.setattr(cli, "_log_path", lambda _username: cli_output)
    assert await cli._run_scan_fast(ScanConfig(username="erkanrzgc")) == 0
    cli_payload = json.loads(cli_output.read_text(encoding="utf-8"))

    monkeypatch.setattr(api_server, "run_scan", fake_run_scan)
    monkeypatch.setattr(api_server, "complete_scan_result", fake_complete)
    rest_payload = await api_server._execute_api_scan(
        api_server.ScanRequest(username="erkanrzgc", save_history=False)
    )

    monkeypatch.setattr(mcp_server, "run_scan", fake_run_scan)
    monkeypatch.setattr(mcp_server, "complete_scan_result", fake_complete)
    mcp_payload = await mcp_server._scan({"username": "erkanrzgc"})

    assert _identity_view(cli_payload) == golden
    assert _identity_view(rest_payload) == golden
    assert _identity_view(mcp_payload) == golden
    assert len(captured_configs) == 3
    assert {
        (
            cfg.smart,
            cfg.platform_scope,
            cfg.alias_max_candidates,
            cfg.alias_platform_limit,
        )
        for cfg in captured_configs
    } == {(True, "core", 24, 15)}
