"""Tests for email_only mode wiring in core.engine."""

from __future__ import annotations

import pytest

from core.config import ScanConfig
from core.engine import _phase_email_breach
from core.models import ScanResult


class _StubClient:
    """Minimal HTTP client stub that returns no Gravatar hits."""

    async def get_json(self, _url, _headers=None):
        return 404, None, 0.0

    async def get(self, _url, _headers=None):
        return 404, "", 0.0


@pytest.mark.asyncio
async def test_email_only_seeds_email_into_results(monkeypatch):
    cfg = ScanConfig(
        username="alice",
        email=True,
        breach=False,
        email_only="target@example.com",
    )
    result = ScanResult(username="alice")

    # Stub out the Gravatar lookup so the test stays offline.
    async def _no_gravatar(_client, _email):
        return None

    monkeypatch.setattr("modules.email_discovery.check_gravatar", _no_gravatar)

    await _phase_email_breach(_StubClient(), cfg, platform_results=[], result=result)

    emails = [er.email for er in result.emails]
    assert "target@example.com" in emails
    seeded = next(er for er in result.emails if er.email == "target@example.com")
    assert seeded.source == "user_supplied"
    assert seeded.verified is True


@pytest.mark.asyncio
async def test_email_only_skipped_when_email_phase_disabled():
    """If ``cfg.email`` is False, the phase is a no-op even with email_only set.

    The run_scan dispatcher forces ``cfg.email=True`` in email-only mode, but
    if a caller invokes _phase_email_breach directly without that flag, no
    user-supplied email should leak into the result silently.
    """
    cfg = ScanConfig(
        username="alice",
        email=False,
        email_only="target@example.com",
    )
    result = ScanResult(username="alice")
    await _phase_email_breach(_StubClient(), cfg, platform_results=[], result=result)
    assert result.emails == []


def test_scan_config_accepts_email_only_field():
    cfg = ScanConfig(username="alice", email_only="target@example.com")
    assert cfg.email_only == "target@example.com"


def test_scan_config_email_only_default_none():
    cfg = ScanConfig(username="alice")
    assert cfg.email_only is None
