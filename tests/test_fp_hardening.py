"""Tests for precision-first false-positive hardening."""

from __future__ import annotations

import pytest

from core.config import ScanConfig
from core.engine import _check_platform, _evaluate_platform_result
from core.platform_loader import Platform, _coerce
from modules.fp_filter import looks_like_error_title, score_match


class _MockClient:
    def __init__(self, status: int = 200, text: str = "", json_data: dict | None = None):
        self.status = status
        self.text = text
        self.json_data = json_data
        self.elapsed = 0.05

    async def get(self, url, headers=None):
        return self.status, self.text, self.elapsed

    async def get_with_meta(self, url, headers=None):
        return self.status, self.text, self.elapsed, None

    async def get_json(self, url, headers=None):
        return self.status, self.json_data, self.elapsed


def test_looks_like_error_title_patterns():
    assert looks_like_error_title("<title>404 Not Found</title>")
    assert looks_like_error_title("<title>User Not Found | HackerRank</title>")
    assert looks_like_error_title("<title>Page no longer exists</title>")
    assert looks_like_error_title("<title>Security Verification</title>")
    assert looks_like_error_title("<title>Client Challenge</title>")
    assert looks_like_error_title("<title>alice - Profile Unavailable</title>")
    assert looks_like_error_title('<meta property="og:title" content="Account Suspended">')
    assert looks_like_error_title("Page not found")
    assert not looks_like_error_title("<title>alice | Developer Profile</title>")
    assert not looks_like_error_title("<title>alice on GitHub</title>")


def test_score_match_error_title_penalty():
    body = "<html><head><title>alice - Page Not Found</title></head><body>alice cannot be found" + ("x" * 800) + "</body></html>"
    score = score_match(username="alice", body=body, check_type="status", http_status=200)
    assert "title_error_marker" in score.signals
    assert "title" not in score.signals
    assert score.confidence < 0.45


@pytest.mark.asyncio
async def test_engine_soft_404_title_guard():
    cfg = ScanConfig(username="alice")
    platform = Platform(
        name="Example404",
        url="https://example.com/u/{username}",
        category="social",
        check_type="status",
        evidence_class="official_exact",
        lookup_semantics="exact",
    )
    # Returns 200 OK with username in body, but title says "User Not Found"
    html = "<html><head><title>alice - User Not Found</title></head><body>alice is missing</body></html>"
    client = _MockClient(status=200, text=html)

    result = await _check_platform(client, cfg, platform)
    assert not result.exists
    assert result.status == "soft_404_title"
    assert "title_error_marker" in result.fp_signals

    _evaluate_platform_result(result, platform, cfg)
    assert not result.exists
    assert result.verification["verdict"] == "rejected"
    assert "title_error_marker" in result.verification["reason_codes"]


@pytest.mark.asyncio
async def test_engine_presence_strings_enforced_on_status_platform():
    cfg = ScanConfig(username="alice")
    platform = Platform(
        name="ExamplePresence",
        url="https://example.com/u/{username}",
        category="social",
        check_type="status",
        presence_strings=("verified_profile_token_xyz",),
        evidence_class="official_exact",
        lookup_semantics="exact",
    )
    # Returns 200 OK with username in body and title, but missing the presence string
    html = "<html><head><title>alice</title></head><body>alice profile page</body></html>"
    client = _MockClient(status=200, text=html)

    result = await _check_platform(client, cfg, platform)
    assert not result.exists
    assert result.status == "soft_404_missing_presence"
    assert "presence_strings_missing" in result.fp_signals

    _evaluate_platform_result(result, platform, cfg)
    assert not result.exists
    assert result.verification["verdict"] == "rejected"
    assert "presence_strings_missing" in result.verification["reason_codes"]


@pytest.mark.asyncio
async def test_engine_presence_strings_enforced_on_url_probe():
    cfg = ScanConfig(username="alice")
    platform = Platform(
        name="ExampleProbePresence",
        url="https://example.com/u/{username}",
        url_probe="https://api.example.com/users/{username}",
        category="dev",
        check_type="status",
        presence_strings=('"user_id":',),
        evidence_class="official_exact",
        lookup_semantics="exact",
    )
    # API probe returns 200 with empty JSON or error message without user_id
    client = _MockClient(status=200, json_data={"message": "no user"})

    result = await _check_platform(client, cfg, platform)
    assert not result.exists
    assert result.status == "not_found"
    assert "url_probe_absence" in result.fp_signals


def test_platform_loader_infers_check_type():
    entry_present = {
        "name": "TestPresent",
        "url": "https://example.com/{username}",
        "category": "social",
        "check_method": "message",
        "presence_strings": ["og:type\" content=\"profile"],
    }
    p1 = _coerce(entry_present)
    assert p1.check_type == "content_present"

    entry_absent = {
        "name": "TestAbsent",
        "url": "https://example.com/{username}",
        "category": "social",
        "check_method": "message",
        "absence_strings": ["User not found"],
    }
    p2 = _coerce(entry_absent)
    assert p2.check_type == "content_absent"

    # URL without scheme is normalized
    entry_noscheme = {
        "name": "TestNoScheme",
        "url": "{username}.ddns.net",
        "category": "community",
        "check_method": "status",
    }
    p3 = _coerce(entry_noscheme)
    assert p3.url.startswith("https://")
