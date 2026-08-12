"""Tests for core/graph_export.py — DOT graph rendering."""

from pathlib import Path

from core.graph_export import export_dot, render_dot
from core.models import EmailResult, IdentityCandidate, PlatformResult, ScanResult


def _result() -> ScanResult:
    r = ScanResult(username="alice")
    r.platforms = [
        PlatformResult(
            platform="GitHub",
            url="https://github.com/alice",
            category="dev",
            exists=True,
        ),
        PlatformResult(
            platform="Ghost",
            url="https://ghost/alice",
            category="social",
            exists=False,
        ),
    ]
    r.emails = [
        EmailResult(email="a@b.com", source="gravatar", breach_count=2),
        EmailResult(email="c@d.com", source="profile"),
    ]
    r.whois_records = [{"domain": "alice.com", "registrar": "R"}]
    r.discovered_usernames = ["alice_dev", "alice"]  # self filtered out
    r.identity_candidates = [
        IdentityCandidate(
            username="alice_dev",
            handle_similarity=0.9,
            verdict="likely_same",
            score=0.8,
        )
    ]
    return r


def test_render_dot_contains_nodes_and_edges():
    dot = render_dot(_result())
    assert dot.startswith("digraph")
    assert "user:alice" in dot
    assert "platform:GitHub" in dot
    assert "platform:Ghost" not in dot  # not exists -> skipped
    assert "email:a@b.com" in dot
    assert "domain:alice.com" in dot
    assert "alias:alice_dev" in dot
    assert "likely_same" in dot
    assert dot.rstrip().endswith("}")


def test_render_dot_breach_color():
    dot = render_dot(_result())
    # breached email => crimson, clean => forestgreen
    assert "crimson" in dot
    assert "forestgreen" in dot


def test_render_dot_escapes_quotes():
    r = ScanResult(username='ali"ce')
    dot = render_dot(r)
    assert '\\"' in dot


def test_export_dot_writes_file(tmp_path: Path):
    out = tmp_path / "graph.dot"
    export_dot(_result(), str(out))
    content = out.read_text(encoding="utf-8")
    assert content.startswith("digraph")
    assert "platform:GitHub" in content


def test_render_dot_accepts_dict():
    payload = {"username": "bob", "platforms": [], "emails": []}
    dot = render_dot(payload)
    assert "user:bob" in dot


def test_render_dot_empty_result():
    dot = render_dot(ScanResult(username="empty"))
    assert "user:empty" in dot
    assert dot.count("->") == 0
