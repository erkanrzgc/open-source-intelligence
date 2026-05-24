"""Tests for modules.stealth.soft_404 fingerprint-based 404 detection."""

from __future__ import annotations

import time
from pathlib import Path

from modules.stealth.soft_404 import (
    Soft404Baseline,
    Soft404Cache,
    is_soft_404,
    make_baseline,
)


def _baseline_html(username: str) -> str:
    return f"""
    <html>
      <head><title>Profile not found</title></head>
      <body>
        <h1>We couldn't find that user</h1>
        <p>The profile "{username}" doesn't exist on this site.</p>
        <a href="/discover">Discover popular profiles</a>
      </body>
    </html>
    """


def _real_profile_html(username: str) -> str:
    return f"""
    <html>
      <head><title>{username} (@{username})</title></head>
      <body>
        <h1>{username}</h1>
        <img src="/avatars/{username}.png" alt="avatar" />
        <p>Bio: passionate developer interested in OSINT.</p>
        <span>Followers: 1240</span>
      </body>
    </html>
    """


def test_simhash_baseline_self_match():
    body = _baseline_html("__nonexistent__")
    base = make_baseline(
        platform="ExampleSite",
        status=200,
        body=body,
        probe_username="__nonexistent__",
    )
    # Refetching the exact same body should be flagged as soft-404.
    is_soft, reason = is_soft_404(
        platform="ExampleSite",
        status=200,
        body=body,
        real_username="alice",
        baseline=base,
    )
    assert is_soft is True
    assert reason and reason.startswith("soft_404_template")


def test_real_profile_does_not_match_baseline():
    base = make_baseline(
        platform="ExampleSite",
        status=200,
        body=_baseline_html("__nonexistent__"),
        probe_username="__nonexistent__",
    )
    is_soft, reason = is_soft_404(
        platform="ExampleSite",
        status=200,
        body=_real_profile_html("alice"),
        real_username="alice",
        baseline=base,
    )
    assert is_soft is False
    assert reason is None


def test_missing_baseline_short_circuits():
    is_soft, reason = is_soft_404(
        platform="ExampleSite",
        status=200,
        body="<html>some body</html>",
        real_username="alice",
        baseline=None,
    )
    assert is_soft is False
    assert reason is None


def test_cache_roundtrip(tmp_path: Path):
    cache = Soft404Cache(root=tmp_path)
    base = make_baseline(
        platform="GitHub",
        status=200,
        body=_baseline_html("__nope__"),
        probe_username="__nope__",
    )
    cache.put(base)
    loaded = cache.get("GitHub")
    assert loaded is not None
    assert loaded.fingerprint == base.fingerprint
    assert loaded.platform == "GitHub"


def test_cache_returns_none_for_expired(tmp_path: Path):
    cache = Soft404Cache(root=tmp_path)
    stale = Soft404Baseline(
        platform="GitHub",
        fingerprint=12345,
        status=200,
        body_length=500,
        recorded_at=time.time() - (8 * 24 * 3600),  # >7 days old
    )
    cache.put(stale)
    assert cache.get("GitHub") is None


def test_size_gap_short_circuits_mismatch():
    base = make_baseline(
        platform="ExampleSite",
        status=200,
        body=_baseline_html("__nonexistent__"),
        probe_username="__nonexistent__",
    )
    huge_real_body = _real_profile_html("alice") * 50
    is_soft, _ = is_soft_404(
        platform="ExampleSite",
        status=200,
        body=huge_real_body,
        real_username="alice",
        baseline=base,
    )
    assert is_soft is False


def test_status_mismatch_short_circuits():
    base = make_baseline(
        platform="ExampleSite",
        status=200,
        body=_baseline_html("__nonexistent__"),
        probe_username="__nonexistent__",
    )
    is_soft, _ = is_soft_404(
        platform="ExampleSite",
        status=404,
        body=_baseline_html("alice"),
        real_username="alice",
        baseline=base,
    )
    assert is_soft is False
