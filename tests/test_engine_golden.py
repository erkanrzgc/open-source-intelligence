"""Golden-set regression tests for engine._check_platform.

Loads tests/golden/golden_cases.yaml and asserts behaviour for each
scenario. Adding a new edge case = adding a YAML entry, no Python
change required.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Isolate the soft-404 cache to a per-test-run tmp dir so previous runs
# don't pollute fingerprints. Runs before engine is imported below.
import core.engine as _engine_mod
from modules.stealth.soft_404 import Soft404Cache as _Soft404Cache

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - covered by skip
    yaml = None  # type: ignore[assignment]

from core.config import ScanConfig
from core.engine import _check_platform
from core.platform_loader import Platform


GOLDEN_PATH = Path(__file__).parent / "golden" / "golden_cases.yaml"


def _load_cases() -> list[dict]:
    if yaml is None:
        return []
    if not GOLDEN_PATH.exists():
        return []
    raw = yaml.safe_load(GOLDEN_PATH.read_text("utf-8"))
    return raw.get("cases", []) if raw else []


class _ScriptedClient:
    """HTTP client stub that replays a pre-recorded response."""

    def __init__(self, status: int, body: str, final_url: str | None = None):
        self.status = status
        self.body = body
        self.final_url = final_url

    async def get(self, url, _headers=None):  # legacy contract
        return self.status, self.body, 0.01

    async def get_with_meta(self, url, _headers=None):
        return self.status, self.body, 0.01, self.final_url or url


def _case_id(case: dict) -> str:
    return str(case.get("case_name", "unnamed"))


@pytest.fixture(autouse=True)
def _isolate_soft_404_cache(tmp_path, monkeypatch):
    """Fresh per-test soft-404 cache so the fixture-seeded baselines
    from one case don't bleed into another."""
    monkeypatch.setattr(_engine_mod, "_SOFT_404_CACHE", _Soft404Cache(root=tmp_path / "s404"))
    yield


@pytest.mark.skipif(yaml is None, reason="PyYAML not installed")
@pytest.mark.skipif(not GOLDEN_PATH.exists(), reason="golden cases file missing")
@pytest.mark.parametrize("case", _load_cases(), ids=_case_id)
@pytest.mark.asyncio
async def test_golden_case(case: dict):
    platform = Platform(
        name=case["platform_name"],
        url=case["platform_url"],
        category="test",
        check_type=case["check_type"],
        error_text=case.get("error_text", ""),
        success_text=case.get("success_text", ""),
    )
    response = case["response"]
    client = _ScriptedClient(
        status=int(response["status"]),
        body=response.get("body", ""),
        final_url=response.get("final_url"),
    )
    cfg = ScanConfig(username=case["username"])

    result = await _check_platform(client, cfg, platform)

    expect = case.get("expect", {})
    if "exists" in expect:
        assert result.exists is expect["exists"], (
            f"{case['case_name']}: exists={result.exists}, expected {expect['exists']} "
            f"(status={result.status}, conf={result.confidence:.2f}, "
            f"signals={result.fp_signals})"
        )
    if "confidence_at_least" in expect:
        assert result.confidence >= expect["confidence_at_least"], (
            f"{case['case_name']}: confidence={result.confidence:.2f} < "
            f"{expect['confidence_at_least']}"
        )
    if "confidence_at_most" in expect:
        assert result.confidence <= expect["confidence_at_most"], (
            f"{case['case_name']}: confidence={result.confidence:.2f} > "
            f"{expect['confidence_at_most']}"
        )
    if "signals_include" in expect:
        joined = " ".join(result.fp_signals)
        for needle in expect["signals_include"]:
            assert needle in joined, (
                f"{case['case_name']}: missing fp signal {needle!r} "
                f"in {result.fp_signals}"
            )
    if "status_contains" in expect:
        assert expect["status_contains"] in result.status, (
            f"{case['case_name']}: status={result.status!r} does not contain "
            f"{expect['status_contains']!r}"
        )


def test_golden_cases_load_correctly():
    """Sanity check: the YAML parses and contains at least one case."""
    if yaml is None:
        pytest.skip("PyYAML not installed")
    cases = _load_cases()
    assert len(cases) >= 3
    for case in cases:
        assert "case_name" in case
        assert "platform_name" in case
        assert "response" in case
        assert "expect" in case
