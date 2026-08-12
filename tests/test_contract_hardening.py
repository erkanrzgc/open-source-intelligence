"""Public contract and package metadata hardening tests."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from core.api.server import ScanRequest, _cfg_from_request  # noqa: E402
from core.config import ScanConfig  # noqa: E402
from core.models import PlatformResult, ScanResult  # noqa: E402
from core.scan_service import SCAN_PAYLOAD_SCHEMA_VERSION  # noqa: E402
from core.version import __version__  # noqa: E402
from mcp_server import SERVER_INFO  # noqa: E402
from modules.fp_filter import DEFAULT_THRESHOLD  # noqa: E402
from modules.recon.models import LeakedSecret  # noqa: E402


def test_confidence_default_is_shared_by_python_and_rest() -> None:
    assert ScanConfig(username="alice").fp_threshold == DEFAULT_THRESHOLD
    assert _cfg_from_request(ScanRequest(username="alice")).fp_threshold == DEFAULT_THRESHOLD


def test_identity_defaults_are_shared_by_python_and_rest() -> None:
    python_cfg = ScanConfig(username="alice")
    rest_cfg = _cfg_from_request(ScanRequest(username="alice"))
    assert python_cfg.smart is rest_cfg.smart is True
    assert rest_cfg.platform_scope == python_cfg.platform_scope == "core"
    assert rest_cfg.alias_max_candidates == python_cfg.alias_max_candidates == 24
    assert rest_cfg.alias_platform_limit == python_cfg.alias_platform_limit == 15


def test_project_and_mcp_versions_share_one_source() -> None:
    assert SERVER_INFO["version"] == __version__


def test_new_payload_schema_and_verification_are_declared() -> None:
    row = PlatformResult(
        platform="Example",
        url="https://example.com/alice",
        category="social",
        exists=False,
        confidence=0.4,
        verification={
            "verdict": "uncertain",
            "score": 0.4,
            "evidence": ["body"],
            "reason_codes": ["score_below_threshold"],
        },
    )
    payload = ScanResult(username="alice", platforms=[row]).to_dict()
    assert payload["platforms"][0]["verification"]["verdict"] == "uncertain"
    assert payload["found_count"] == 0
    assert payload["verification_counts"]["uncertain"] == 1
    assert SCAN_PAYLOAD_SCHEMA_VERSION == "2026-08-09"


def test_secret_findings_serialize_only_fingerprint_and_safe_preview() -> None:
    secret = LeakedSecret(
        rule_id="token",
        value="super-secret-value",
        repo="acme/app",
        file_path="config.py",
        url="https://example.com/config.py",
        snippet="TOKEN=super-secret-value",
    ).to_dict()
    assert "value" not in secret
    assert len(secret["fingerprint"]) == 64
    assert "super-secret-value" not in secret["safe_preview"]
    assert "super-secret-value" not in secret["snippet"]
