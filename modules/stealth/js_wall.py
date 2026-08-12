"""Detect when an HTML response is actually a JavaScript/CDN wall.

Some platforms return HTTP 200 with body that is essentially "you need
JavaScript / accept the challenge". A pure aiohttp fetch sees that page,
treats the username as found, and produces a soft-positive that the rest
of the pipeline cannot easily distinguish from a real profile.

This module exposes ``looks_like_js_wall(body, headers, status)`` so the
engine can decide to re-fetch the same URL through Playwright/Camoufox.

Heuristics (any one fires → wall detected):

  * Cloudflare ``cf-mitigated``/``cf-chl-bypass`` headers or Just-a-moment
    body snippet
  * DataDome / PerimeterX challenge phrases
  * ``<noscript>You need to enable JavaScript</noscript>`` plus a body
    that is mostly script tags and very little visible text
  * Empty ``__NEXT_DATA__`` / Nuxt placeholder shells (HTML present but
    actual content is bootstrapped client-side)
  * Body size < 2KB AND has at least one ``<script>`` tag (Single-Page
    App skeleton)

We are intentionally conservative — false positives here cause us to
launch a heavy headless browser, so the bar must be obvious wall behaviour.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_CF_BODY_RE = re.compile(
    r"(just a moment|attention required|checking your browser|cf-browser-verification|cf-spinner|"
    r"performance &amp; security by cloudflare)",
    re.IGNORECASE,
)
_DATADOME_RE = re.compile(
    r"(datadome|please enable cookies|blocked by datadome)", re.IGNORECASE
)
_PERIMETERX_RE = re.compile(
    r"(perimeterx|px-captcha|/_px/captcha)", re.IGNORECASE
)
_NOSCRIPT_REQUIRED_RE = re.compile(
    r"<noscript[^>]*>[^<]*?(you need to enable javascript|please enable javascript|"
    r"javascript is (required|disabled)|enable javascript to|requires javascript)",
    re.IGNORECASE,
)
_EMPTY_NEXT_DATA_RE = re.compile(
    r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL
)
_NUXT_PLACEHOLDER_RE = re.compile(
    r'<div id="__nuxt"[^>]*>\s*</div>|<div id="app"[^>]*>\s*</div>',
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)


def _strip_tags(body: str) -> str:
    return _TAG_RE.sub(" ", body)


def _visible_text_ratio(body: str) -> float:
    if not body:
        return 0.0
    stripped = _strip_tags(body).strip()
    return len(stripped) / max(len(body), 1)


def looks_like_js_wall(
    body: str,
    headers: Mapping[str, str] | None = None,
    status: int = 200,
) -> tuple[bool, str | None]:
    """Return ``(is_wall, reason)`` for the supplied response.

    ``reason`` is a short identifier suitable for ``fp_signals``. When the
    function returns ``False`` it short-circuits with ``reason=None``.
    """
    if not body:
        return False, None

    headers = headers or {}
    # 1. CDN challenge headers
    cf_headers = {k.lower(): v for k, v in headers.items()}
    if "cf-mitigated" in cf_headers or "cf-chl-bypass" in cf_headers:
        return True, "cloudflare_challenge_header"
    if cf_headers.get("server", "").lower().startswith("cloudflare") and status in (
        403,
        503,
    ):
        return True, "cloudflare_block"

    # 2. Body-level CDN challenges
    if _CF_BODY_RE.search(body):
        return True, "cloudflare_challenge_body"
    if _DATADOME_RE.search(body):
        return True, "datadome_challenge"
    if _PERIMETERX_RE.search(body):
        return True, "perimeterx_challenge"

    # 3. JavaScript-required noscript banner — the wording itself is the wall
    # signal. We additionally require that the body lacks substantial
    # editorial content (no <article>, <h1> outside noscript, etc.) so that
    # SEO-friendly SPAs that ship server-rendered content aren't flagged.
    if _NOSCRIPT_REQUIRED_RE.search(body):
        has_real_content = bool(
            re.search(r"<(article|main)\b", body, re.IGNORECASE)
            or len(_strip_tags(body).strip()) > 1500
        )
        if not has_real_content:
            return True, "noscript_required"

    # 4. SPA shell with empty __NEXT_DATA__ payload
    next_match = _EMPTY_NEXT_DATA_RE.search(body)
    if next_match:
        payload = next_match.group(1).strip()
        # An empty or near-empty Next data block means the page renders later.
        if len(payload) < 100 or payload in ("{}", '{"props":{},"page":""}'):
            return True, "empty_next_data"

    # 5. Empty mount points (#__nuxt, #app) with otherwise tiny body
    if _NUXT_PLACEHOLDER_RE.search(body) and len(body) < 5000:
        return True, "empty_spa_mount"

    # 6. Very small body that's almost entirely scripts
    if len(body) < 2048 and _SCRIPT_RE.search(body):
        text_ratio = _visible_text_ratio(body)
        if text_ratio < 0.05:
            return True, "script_only_shell"

    return False, None
