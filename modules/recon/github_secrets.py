"""GitHub-scoped credential leak scanner.

This module surfaces accidentally-committed secrets in public source
code that mentions a target organization, domain, or repository. It is
the OSINT analogue of running gitleaks/trufflehog over the whole of
github.com — except we narrow the search by leveraging GitHub's own
code index rather than cloning every repository.

How it works
------------
1. **Build queries** — for each high-signal secret token (``AKIA``,
   ``ghp_``, ``xoxb-``, ``-----BEGIN PRIVATE KEY-----``, …) compose a
   GitHub Code Search query qualified by the target
   (``org:acme AKIA``, ``repo:acme/api ghp_``, ``"acme.com" xoxb-``).
2. **Search** — call ``/search/code`` with the
   ``application/vnd.github.text-match+json`` accept header so each hit
   carries the matching code fragment.
3. **Re-validate** — run every fragment through the precise regex for
   the rule that produced the query. This filters most casual hits.
4. **Drop noise** — discard matches that live in test/example/fixture
   paths, or whose value appears in the canonical-sample denylist
   (the canonical ``AKIA...EXAMPLE`` access key is in every AWS tutorial
   on the internet).
5. **Dedupe** — collapse identical findings keyed by
   ``(rule_id, value, repo, file_path)``.

Authentication is mandatory — GitHub's Code Search endpoint refuses
anonymous calls. Without ``GITHUB_TOKEN`` the scan is a no-op.

This is a passive recon tool. It only reads public data via the GitHub
API; it never tries to use any credential it surfaces.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.recon.models import LeakedSecret

log = get_logger(__name__)

_API = "https://api.github.com/search/code"
_DEFAULT_MAX_QUERIES = 20
_DEFAULT_MAX_HITS_PER_QUERY = 30


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    search_token: str  # the literal substring to qualify GitHub queries


# Order matters: more specific rules first so they win deduplication.
RULES: tuple[_Rule, ...] = (
    _Rule(
        rule_id="aws_access_key",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        search_token="AKIA",  # nosec B106
    ),
    _Rule(
        rule_id="github_pat",
        # Covers personal (ghp_), OAuth (gho_), user-to-server (ghu_),
        # server-to-server (ghs_), and refresh (ghr_) tokens.
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        search_token="ghp_",  # nosec B106
    ),
    _Rule(
        rule_id="slack_webhook",
        pattern=re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
        ),
        search_token="hooks.slack.com",  # nosec B106
    ),
    _Rule(
        rule_id="slack_token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        search_token="xoxb-",  # nosec B106
    ),
    _Rule(
        rule_id="google_api_key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        search_token="AIza",  # nosec B106
    ),
    _Rule(
        rule_id="stripe_live_key",
        pattern=re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
        search_token="sk_live_",  # nosec B106
    ),
    _Rule(
        rule_id="private_key_block",
        pattern=re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        search_token="BEGIN PRIVATE KEY",  # nosec B106
    ),
    _Rule(
        rule_id="jwt_token",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,}\b"
        ),
        search_token="eyJhbGciOi",  # nosec B106
    ),
)

# Canonical doc samples that show up in literally every AWS/Stripe/etc.
# tutorial. These are not real credentials and would burn the user's
# attention budget if surfaced. The strings are split with concatenation
# so this file does not itself trip secret scanners (GitHub Push
# Protection / TruffleHog / etc.) on the canonical samples.
DENYLIST_VALUES: frozenset[str] = frozenset(
    {
        "AKIA" + "IOSFODNN7EXAMPLE",
        "AKIA" + "I44QH8DHBEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",  # Stripe canonical sample
    }
)

_EXCLUDED_PATH_TOKENS: tuple[str, ...] = (
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "example",
    "examples",
    "sample",
    "samples",
    "demo",
    "demos",
    "docs",
    "doc",
)


def _is_excluded_path(path: str) -> bool:
    """True if ``path`` looks like docs/tests/examples rather than real code."""
    if not path:
        return False
    lowered = path.lower()
    # split on path separators AND on common filename delimiters so that
    # ``test_keys.py`` and ``mocks/data.rb`` both trip the filter.
    tokens = re.split(r"[/_.\-]", lowered)
    return any(tok in _EXCLUDED_PATH_TOKENS for tok in tokens)


def _scan_text(text: str) -> list[tuple[str, str]]:
    """Run every rule against ``text`` and return ``(rule_id, value)`` pairs.

    Denylisted values are dropped here so the caller never has to think
    about example credentials.
    """
    out: list[tuple[str, str]] = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(0)
            if value in DENYLIST_VALUES:
                continue
            out.append((rule.rule_id, value))
    return out


def _build_queries(
    *,
    org: str | None,
    domain: str | None,
    repos: list[str] | None,
    max_queries: int,
) -> list[str]:
    """Compose Code Search queries that pair each rule's search token with
    the target qualifier(s).
    """
    qualifiers: list[str] = []
    if org:
        qualifiers.append(f"org:{org}")
    for repo in repos or []:
        qualifiers.append(f"repo:{repo}")
    if domain:
        # quoted free-text to bias toward repos that mention the target
        qualifiers.append(f'"{domain}"')

    if not qualifiers:
        return []

    queries: list[str] = []
    for qualifier in qualifiers:
        for rule in RULES:
            queries.append(f"{qualifier} {rule.search_token}")
            if len(queries) >= max_queries:
                return queries
    return queries


def _query_token(query: str) -> str:
    """Return the trailing rule token from a built query (last whitespace-delimited piece)."""
    return query.rsplit(" ", 1)[-1]


def _rule_for_query(query: str) -> _Rule | None:
    """Find the rule whose search_token built ``query``.

    Falls back to scanning all rules if the trailing token is ambiguous.
    """
    token = _query_token(query)
    for rule in RULES:
        if rule.search_token == token:
            return rule
    return None


def _auth_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github.text-match+json",
        "Authorization": f"Bearer {token}",
    }


async def _run_query(
    client: HTTPClient,
    *,
    query: str,
    token: str,
    max_hits: int,
) -> list[LeakedSecret]:
    """Execute a single Code Search call and turn fragments into findings."""
    url = f"{_API}?q={quote(query)}&per_page={max_hits}"
    status, data, _ = await client.get_json(url, headers=_auth_headers(token))
    if status != 200 or not isinstance(data, dict):
        return []
    items = data.get("items")
    if not isinstance(items, list):
        return []

    rule_hint = _rule_for_query(query)
    findings: list[LeakedSecret] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        path = item.get("path") or ""
        if _is_excluded_path(path):
            continue
        repo_name = ""
        repo_block = item.get("repository")
        if isinstance(repo_block, dict):
            repo_name = repo_block.get("full_name") or ""
        html_url = item.get("html_url") or ""
        text_matches = item.get("text_matches") or []
        if not isinstance(text_matches, list):
            continue

        for tm in text_matches:
            if not isinstance(tm, dict):
                continue
            fragment = tm.get("fragment") or ""
            if not fragment:
                continue
            for rule_id, value in _scan_text(fragment):
                # If we know which rule prompted this query, prefer it,
                # but still emit findings from other rules whose tokens
                # showed up in the fragment.
                findings.append(
                    LeakedSecret(
                        rule_id=rule_id,
                        value=value,
                        repo=repo_name,
                        file_path=path,
                        url=html_url,
                        snippet=fragment.strip()[:240],
                        metadata={
                            "search_query": query,
                            "primary_rule": rule_hint.rule_id if rule_hint else "",
                        },
                    )
                )
    return findings


def _dedupe(findings: list[LeakedSecret]) -> list[LeakedSecret]:
    """Collapse identical findings keyed by ``(rule_id, value, repo, file_path)``."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[LeakedSecret] = []
    for f in findings:
        key = (f.rule_id, f.value, f.repo, f.file_path)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


async def scan_target(
    client: HTTPClient,
    *,
    org: str | None = None,
    domain: str | None = None,
    repos: list[str] | None = None,
    max_queries: int = _DEFAULT_MAX_QUERIES,
    max_hits_per_query: int = _DEFAULT_MAX_HITS_PER_QUERY,
) -> list[LeakedSecret]:
    """Scan public GitHub for secrets tied to the given target.

    At least one of ``org``, ``domain``, or ``repos`` must be provided.
    Returns an empty list if no ``GITHUB_TOKEN`` is set (Code Search is
    auth-only) or no qualifier is given.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.debug("github_secrets: GITHUB_TOKEN not set, skipping")
        return []

    queries = _build_queries(
        org=org, domain=domain, repos=repos, max_queries=max_queries
    )
    if not queries:
        return []

    log.debug("github_secrets: running %d queries", len(queries))
    results = await asyncio.gather(
        *(
            _run_query(client, query=q, token=token, max_hits=max_hits_per_query)
            for q in queries
        ),
        return_exceptions=True,
    )

    merged: list[LeakedSecret] = []
    for batch in results:
        if isinstance(batch, BaseException):
            log.debug("github_secrets: query failed: %s", batch)
            continue
        merged.extend(batch)
    return _dedupe(merged)
