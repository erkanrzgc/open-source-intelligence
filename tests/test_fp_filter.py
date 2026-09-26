"""Tests for the false-positive filter."""

from __future__ import annotations

from modules.fp_filter import score_match


def _make_body(**parts: str) -> str:
    return (
        f"<html><head><title>{parts.get('title', '')}</title>"
        f"{parts.get('head_extra', '')}"
        f"</head><body>{parts.get('body', '')}</body></html>"
    )


def test_zero_for_non_200():
    out = score_match(username="alice", body="<html/>", check_type="status", http_status=404)
    assert out.confidence == 0.0
    assert out.signals == ()


def test_high_confidence_title_and_body():
    body = _make_body(title="alice | Example", body="profile of alice here" + ("x" * 800))
    out = score_match(username="alice", body=body, check_type="content_absent", http_status=200)
    assert out.confidence >= 0.9
    assert "title" in out.signals
    assert "body" in out.signals


def test_low_confidence_generic_page():
    body = _make_body(title="Welcome", body="home page")
    out = score_match(username="alice", body=body, check_type="status", http_status=200)
    # Only baseline (0.3) — no username anywhere
    assert out.confidence < 0.45


def test_canonical_signal():
    body = _make_body(
        title="Example",
        head_extra='<link rel="canonical" href="https://example.com/u/alice">',
        body="x" * 1000,
    )
    out = score_match(username="alice", body=body, check_type="status", http_status=200)
    assert "canonical" in out.signals
    assert "body" in out.signals


def test_og_profile_signal():
    body = _make_body(
        title="Example",
        head_extra='<meta property="og:type" content="profile">',
        body="alice is here" + "y" * 800,
    )
    out = score_match(username="alice", body=body, check_type="content_absent", http_status=200)
    assert "og_profile" in out.signals


def test_short_body_loses_size_signal():
    body = _make_body(title="alice", body="alice")
    out = score_match(username="alice", body=body, check_type="status", http_status=200)
    assert "size" not in out.signals


def test_error_title_penalized_and_blocks_title_bonus():
    body = _make_body(title="alice - Page Not Found", body="Sorry, user alice cannot be found" + ("x" * 800))
    out = score_match(username="alice", body=body, check_type="status", http_status=200)
    assert "title_error_marker" in out.signals
    assert "title" not in out.signals
    assert out.confidence < 0.45


def test_og_error_title_penalized():
    body = _make_body(
        title="Example Service",
        head_extra='<meta property="og:title" content="Error 404 - Profile Not Found">',
        body="x" * 800,
    )
    out = score_match(username="alice", body=body, check_type="status", http_status=200)
    assert "title_error_marker" in out.signals
    assert out.confidence < 0.45

