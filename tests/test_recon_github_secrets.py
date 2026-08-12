"""Tests for GitHub-scoped secret scanning (red-team recon)."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.recon import github_secrets
from modules.recon.github_secrets import (
    DENYLIST_VALUES,
    RULES,
    _build_queries,
    _is_excluded_path,
    _scan_text,
)
from modules.recon.models import LeakedSecret

# ── Rule catalog & pattern matching ─────────────────────────────────


def test_rule_catalog_has_expected_ids() -> None:
    ids = {r.rule_id for r in RULES}
    expected = {
        "aws_access_key",
        "github_pat",
        "slack_webhook",
        "slack_token",
        "google_api_key",
        "stripe_live_key",
        "private_key_block",
        "jwt_token",
    }
    assert expected.issubset(ids)


# All secret-shaped fixtures below are split with runtime concatenation
# so this test file does not itself trip secret scanners (GitHub Push
# Protection, TruffleHog, etc.) on what are clearly fake values. The
# concatenation is the ONLY change — the values are still synthetic.

_AWS_FAKE = "AKIA" + "IOSFODNN7EXAMPLF"        # not the canonical sample
_AWS_DENYLIST_SAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
_GITHUB_PAT_FAKE = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
_GOOGLE_FAKE = "AIza" + "SyA-1234567890abcdefghijklmnopqrstu"
_STRIPE_FAKE = "sk_live_" + "aBcDeFgHiJkLmNoPqRsTuVwX"
_AWS_FRAGMENT = "AKIA" + "IOSFODNN7XAAAAAA"      # synthetic, lives in fragment fixtures
_GH_PAT_FRAGMENT = "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
_SLACK_WEBHOOK_FAKE = (
    "https://hooks.slack.com/services/"
    + "T01ABCDEFGH"
    + "/B02IJKLMNOP"
    + "/abcdefghijklmnopqrstuvwx"
)


def test_scan_text_finds_aws_access_key() -> None:
    text = f'aws_key = "{_AWS_FAKE}"'
    hits = _scan_text(text)
    assert any(rule_id == "aws_access_key" for rule_id, _ in hits)


def test_scan_text_rejects_denylisted_aws_example() -> None:
    text = f'aws_key = "{_AWS_DENYLIST_SAMPLE}"'
    hits = _scan_text(text)
    aws = [(r, v) for r, v in hits if r == "aws_access_key"]
    assert aws == []
    assert _AWS_DENYLIST_SAMPLE in DENYLIST_VALUES


def test_scan_text_finds_github_pat() -> None:
    text = f"GITHUB_TOKEN={_GITHUB_PAT_FAKE}"
    hits = _scan_text(text)
    rule_ids = {r for r, _ in hits}
    assert "github_pat" in rule_ids


def test_scan_text_finds_slack_webhook() -> None:
    text = f"url={_SLACK_WEBHOOK_FAKE}"
    hits = _scan_text(text)
    assert ("slack_webhook", _SLACK_WEBHOOK_FAKE) in [
        (r, v) for r, v in hits if r == "slack_webhook"
    ]


def test_scan_text_finds_google_api_key() -> None:
    # AIza + 35 chars = canonical Google API key length
    text = f'KEY="{_GOOGLE_FAKE}"'
    hits = _scan_text(text)
    assert any(r == "google_api_key" for r, _ in hits)


def test_scan_text_finds_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA..."
    hits = _scan_text(text)
    assert any(r == "private_key_block" for r, _ in hits)


def test_scan_text_finds_stripe_live_key() -> None:
    text = f"stripe = '{_STRIPE_FAKE}'"
    hits = _scan_text(text)
    assert any(r == "stripe_live_key" for r, _ in hits)


def test_scan_text_finds_jwt() -> None:
    jwt = (
        "eyJ" + "hbGciOiJIUzI1NiJ9"
        + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0"
        + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    hits = _scan_text(f"token={jwt}")
    assert any(r == "jwt_token" for r, _ in hits)


def test_scan_text_returns_empty_for_clean_text() -> None:
    assert _scan_text("hello world\nlorem ipsum dolor sit amet") == []


# ── Path exclusion ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_keys.py",
        "src/__tests__/fixtures.js",
        "examples/sample_config.yml",
        "docs/example.md",
        "spec/mocks/data.rb",
        "fixtures/aws_creds.txt",
    ],
)
def test_is_excluded_path_skips_test_and_example_files(path: str) -> None:
    assert _is_excluded_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "src/auth/aws.py",
        "config/production.env",
        "lib/credentials.go",
        ".env",
    ],
)
def test_is_excluded_path_keeps_real_paths(path: str) -> None:
    assert not _is_excluded_path(path)


# ── Query building ──────────────────────────────────────────────────


def test_build_queries_for_org_includes_org_qualifier() -> None:
    queries = _build_queries(org="acme", domain=None, repos=None, max_queries=10)
    assert any(q.startswith("org:acme ") for q in queries)
    # at least one query per high-signal rule term
    assert any("AKIA" in q for q in queries)
    assert any("ghp_" in q for q in queries)


def test_build_queries_for_repos_includes_repo_qualifier() -> None:
    queries = _build_queries(
        org=None, domain=None, repos=["a/b", "c/d"], max_queries=10
    )
    assert any("repo:a/b" in q for q in queries)
    assert any("repo:c/d" in q for q in queries)


def test_build_queries_for_domain_includes_domain_string() -> None:
    queries = _build_queries(
        org=None, domain="acme.com", repos=None, max_queries=10
    )
    assert any('"acme.com"' in q for q in queries)


def test_build_queries_caps_at_max_queries() -> None:
    queries = _build_queries(org="acme", domain=None, repos=None, max_queries=3)
    assert len(queries) <= 3


def test_build_queries_returns_empty_when_no_target() -> None:
    assert _build_queries(org=None, domain=None, repos=None, max_queries=10) == []


# ── scan_target — full integration with mocked GitHub API ───────────


@pytest.mark.asyncio
async def test_scan_target_returns_empty_without_token(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    async with HTTPClient() as client:
        hits = await github_secrets.scan_target(client, org="acme")
    assert hits == []


@pytest.mark.asyncio
async def test_scan_target_returns_empty_for_no_target(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake")
    async with HTTPClient() as client:
        hits = await github_secrets.scan_target(client)
    assert hits == []


@pytest.mark.asyncio
async def test_scan_target_parses_code_search_results(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake")
    payload = {
        "items": [
            {
                "name": "deploy.sh",
                "path": "scripts/deploy.sh",
                "repository": {"full_name": "acme/api"},
                "html_url": (
                    "https://github.com/acme/api/blob/main/scripts/deploy.sh"
                ),
                "text_matches": [
                    {
                        "fragment": (
                            f"export AWS_KEY={_AWS_FRAGMENT}\n"
                            f"export TOKEN={_GH_PAT_FRAGMENT}"
                        )
                    }
                ],
            }
        ]
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.github\.com/search/code.*"),
            payload=payload,
            repeat=True,
        )
        async with HTTPClient() as client:
            hits = await github_secrets.scan_target(
                client, org="acme", max_queries=2
            )

    assert hits, "expected at least one secret found"
    rule_ids = {h.rule_id for h in hits}
    assert "aws_access_key" in rule_ids
    assert "github_pat" in rule_ids
    sample = next(h for h in hits if h.rule_id == "aws_access_key")
    assert sample.repo == "acme/api"
    assert sample.file_path == "scripts/deploy.sh"
    assert sample.url.startswith("https://github.com/acme/api/")
    assert isinstance(sample, LeakedSecret)


@pytest.mark.asyncio
async def test_scan_target_skips_excluded_paths(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake")
    payload = {
        "items": [
            {
                "name": "test_keys.py",
                "path": "tests/test_keys.py",
                "repository": {"full_name": "acme/api"},
                "html_url": "https://github.com/acme/api/blob/main/tests/test_keys.py",
                "text_matches": [
                    {"fragment": f"AWS_KEY={_AWS_FRAGMENT}"}
                ],
            }
        ]
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.github\.com/search/code.*"),
            payload=payload,
            repeat=True,
        )
        async with HTTPClient() as client:
            hits = await github_secrets.scan_target(
                client, org="acme", max_queries=1
            )
    assert hits == []


@pytest.mark.asyncio
async def test_scan_target_dedupes_repeated_findings(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake")
    payload = {
        "items": [
            {
                "name": "config.py",
                "path": "src/config.py",
                "repository": {"full_name": "acme/api"},
                "html_url": "https://github.com/acme/api/blob/main/src/config.py",
                "text_matches": [
                    {"fragment": f"KEY={_AWS_FRAGMENT}"},
                    {"fragment": f"KEY={_AWS_FRAGMENT}"},
                ],
            }
        ]
    }
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.github\.com/search/code.*"),
            payload=payload,
            repeat=True,
        )
        async with HTTPClient() as client:
            hits = await github_secrets.scan_target(
                client, org="acme", max_queries=1
            )
    aws_hits = [h for h in hits if h.rule_id == "aws_access_key"]
    assert len(aws_hits) == 1


@pytest.mark.asyncio
async def test_scan_target_handles_api_failure(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake")
    with aioresponses() as m:
        m.get(
            re.compile(r"https://api\.github\.com/search/code.*"),
            status=500,
            repeat=True,
        )
        async with HTTPClient() as client:
            hits = await github_secrets.scan_target(
                client, org="acme", max_queries=2
            )
    assert hits == []
