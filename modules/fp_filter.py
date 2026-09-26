"""False-positive filter for platform results.

When a site returns 200 OK and the configured error-text isn't present,
we still can't be sure the profile actually exists: many sites serve a
generic landing/redirect with 200, some forums rewrite unknown usernames
to a search page, others gate profiles behind soft walls.

This module scores each positive match against lightweight heuristics and
emits a confidence in [0.0, 1.0]. Downstream code can gate reporting on a
threshold or just surface the score to the user.

Heuristics (each contributes to the score, not a hard gate):

1. username-in-title        +0.35    Strong signal (real profile pages
                                    almost always put the handle in <title>).
2. username-in-body         +0.20    Baseline sanity check.
3. body-length-reasonable   +0.15    Too small (< 500b) = likely 404 shell;
                                    too large is fine.
4. canonical-url-matches    +0.15    <link rel="canonical"> ending in the
                                    username means the server resolved it.
5. og:profile / h-card       +0.15   OpenGraph type=profile or microformats.

A platform whose check_type is `content_absent`/`content_present` already
passed its primary gate, so its baseline is 0.5.  A bare `status` check
gets baseline 0.3 — we're less sure it's a real match.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_OG_TITLE_RE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_CANONICAL_RE = re.compile(
    r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_PROFILE_RE = re.compile(
    r'<meta[^>]+property=["\']og:type["\'][^>]+content=["\']profile["\']',
    re.IGNORECASE,
)
_H_CARD_RE = re.compile(r'class=["\'][^"\']*h-card[^"\']*["\']', re.IGNORECASE)

_ERROR_TITLE_RE = re.compile(
    r"(?i)\b("
    r"404|not\s+found|page\s+not\s+found|user\s+not\s+found|profile\s+not\s+found|"
    r"doesn.?t\s+exist|does\s+not\s+exist|no\s+such\s+user|no\s+such\s+account|"
    r"page\s+no\s+longer\s+exists|page\s+unavailable|profile\s+unavailable|"
    r"something\s+went\s+wrong|error\s+404|resource\s+not\s+found|"
    r"security\s+verification|client\s+challenge|attention\s+required|"
    r"just\s+a\s+moment|access\s+denied|suspended\s+account|account\s+suspended|"
    r"nobody\s+here|cannot\s+be\s+found|can.?t\s+be\s+found"
    r")\b"
)

MIN_BODY = 500
MAX_SCORE = 1.0
DEFAULT_THRESHOLD = 0.45


def extract_html_title(body: str) -> str:
    """Extract contents of <title> tag if present."""
    match = _TITLE_RE.search(body)
    return match.group(1).strip() if match else ""


def extract_og_title(body: str) -> str:
    """Extract og:title content if present."""
    match = _OG_TITLE_RE.search(body)
    return match.group(1).strip() if match else ""


def looks_like_error_title(title_or_body: str) -> bool:
    """Check whether a title or HTML body title explicitly signals a 404/error/challenge."""
    if not title_or_body:
        return False
    if "<title" in title_or_body.lower() or "og:title" in title_or_body.lower():
        t1 = extract_html_title(title_or_body)
        t2 = extract_og_title(title_or_body)
        return bool((t1 and _ERROR_TITLE_RE.search(t1)) or (t2 and _ERROR_TITLE_RE.search(t2)))
    return bool(_ERROR_TITLE_RE.search(title_or_body))


@dataclass(frozen=True)
class FPScore:
    confidence: float
    signals: tuple[str, ...]


def score_match(
    *,
    username: str,
    body: str,
    check_type: str,
    http_status: int,
) -> FPScore:
    """Return a confidence score and the list of signals that fired."""
    if http_status != 200 or not body:
        return FPScore(0.0, ())

    baseline = 0.5 if check_type in ("content_absent", "content_present") else 0.15
    score = baseline
    signals: list[str] = []
    uname_lower = username.lower()
    body_lower = body.lower()

    title_match = _TITLE_RE.search(body)
    og_title_match = _OG_TITLE_RE.search(body)
    title_text = title_match.group(1).strip() if title_match else ""
    og_title_text = og_title_match.group(1).strip() if og_title_match else ""

    if (title_text and _ERROR_TITLE_RE.search(title_text)) or (
        og_title_text and _ERROR_TITLE_RE.search(og_title_text)
    ):
        score = max(0.0, score - 0.40)
        signals.append("title_error_marker")
    elif title_match and uname_lower in title_text.lower():
        score += 0.25
        signals.append("title")

    if uname_lower in body_lower:
        score += 0.15
        signals.append("body")

    if len(body) >= MIN_BODY:
        score += 0.10
        signals.append("size")

    canonical_match = _CANONICAL_RE.search(body)
    if canonical_match and uname_lower in canonical_match.group(1).lower():
        score += 0.15
        signals.append("canonical")

    if _OG_PROFILE_RE.search(body) or _H_CARD_RE.search(body):
        score += 0.15
        signals.append("og_profile")

    return FPScore(min(score, MAX_SCORE), tuple(signals))
