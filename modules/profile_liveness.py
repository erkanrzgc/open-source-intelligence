"""Profile liveness signals — distinguish real profiles from empty shells.

A platform returning HTTP 200 only tells us the URL resolves; it does NOT
tell us the profile has actual content. Many sites (Reddit, dev forums,
gaming platforms) keep username slugs reserved even after deletion, or
serve a "create your profile" placeholder for unregistered handles.

This module scores each fetched profile body across five liveness signals:

  ============  ===========  ============================================
  Signal        Score        What it checks
  ============  ===========  ============================================
  avatar         +0.30       <img src=...> looks like a real avatar URL,
                             not on the default-fingerprint denylist
  bio            +0.25       bio/description text > 5 chars
  og_title       +0.20       og:title or twitter:title mentions username
  jsonld_person  +0.15       schema.org/Person JSON-LD block present
  activity       +0.10       follower/post/karma counter > 0
  ============  ===========  ============================================

A score ≥ 0.40 is considered "active". Below that, the profile is most
likely an empty shell and should be downgraded by the engine.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Body heuristics
_BIO_KEYS = ("bio", "description", "about", "summary", "headline", "status")
_AVATAR_KEYS = ("avatar_url", "avatar", "profile_image", "image", "icon_img")
_ACTIVITY_KEYS = (
    "followers", "follower_count", "following", "following_count",
    "posts", "public_repos", "karma", "post_count", "reputation",
)

# Default-avatar fingerprints — sites that serve a known placeholder for
# unset profile pictures. URLs that exactly match these (or end with these
# slugs) should not count as a real avatar.
_DEFAULT_AVATAR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"abs\.twimg\.com/sticky/default_profile_images", re.IGNORECASE),
    re.compile(r"github\.com/identicons/", re.IGNORECASE),
    re.compile(r"gravatar\.com/avatar/[0-9a-f]+\?d=mp", re.IGNORECASE),
    re.compile(r"/default[-_]?avatar", re.IGNORECASE),
    re.compile(r"/anonymous[-_]?user", re.IGNORECASE),
    re.compile(r"styles/profile_pics/profile_default", re.IGNORECASE),
    re.compile(r"/no[-_]?(profile|avatar|image)", re.IGNORECASE),
    re.compile(r"/blank[-_]?(profile|avatar)", re.IGNORECASE),
)

# Body regexes
_OG_TITLE_RE = re.compile(
    r'<meta[^>]+property=["\'](?:og:title|twitter:title)["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JSON_LD_PERSON_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_AVATAR_IMG_RE = re.compile(
    r'<img[^>]+(?:class=["\'][^"\']*(?:avatar|profile[-_]?(?:pic|image|photo))[^"\']*["\']|alt=["\'](?:avatar|profile)[^"\']*["\'])[^>]+src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_FOLLOWER_COUNT_RE = re.compile(
    r'(?:followers?|posts?|repositories|repos|karma|reputation|tweets?)[:\s>"]*?(\d[\d,]*)',
    re.IGNORECASE,
)

LIVENESS_THRESHOLD = 0.40


@dataclass(frozen=True)
class LivenessScore:
    score: float
    signals: tuple[str, ...]
    is_active: bool


def _is_default_avatar(url: str) -> bool:
    if not url:
        return True
    return any(pat.search(url) for pat in _DEFAULT_AVATAR_PATTERNS)


def _has_jsonld_person(body: str) -> bool:
    for match in _JSON_LD_PERSON_RE.finditer(body):
        payload = match.group(1)
        # Cheap check — full JSON parse not required.
        if '"@type"' in payload and "Person" in payload:
            return True
    return False


def _activity_count_from_body(body: str) -> int:
    """Extract the largest activity counter we can find (followers/posts/karma)."""
    best = 0
    for match in _FOLLOWER_COUNT_RE.finditer(body):
        raw = match.group(1).replace(",", "")
        try:
            n = int(raw)
        except ValueError:
            continue
        if n > best:
            best = n
        if best > 1000:  # short-circuit on a clearly-real account
            break
    return best


def score_liveness(
    *,
    username: str,
    body: str,
    profile_data: dict | None = None,
) -> LivenessScore:
    """Score how "alive" a profile looks. Free of network I/O.

    Combines structured data we already extracted (``profile_data``, from
    socid_extractor or deep scrapers) with cheap regex passes over the raw
    body. Falls back gracefully when either input is empty.
    """
    score = 0.0
    signals: list[str] = []
    profile_data = profile_data or {}

    # 1. Avatar (+0.30)
    avatar_url = ""
    for key in _AVATAR_KEYS:
        val = profile_data.get(key)
        if isinstance(val, str) and val.startswith("http"):
            avatar_url = val
            break
    if not avatar_url and body:
        img_match = _AVATAR_IMG_RE.search(body)
        if img_match:
            avatar_url = img_match.group(1)
    if avatar_url and not _is_default_avatar(avatar_url):
        score += 0.30
        signals.append("avatar")
    elif avatar_url:
        signals.append("default_avatar")  # informational, no score

    # 2. Bio (+0.25)
    bio_text = ""
    for key in _BIO_KEYS:
        val = profile_data.get(key)
        if isinstance(val, str) and len(val.strip()) > 5:
            bio_text = val
            break
    if bio_text:
        score += 0.25
        signals.append("bio")

    # 3. og:title / twitter:title mentions username (+0.20)
    if body and username:
        og_match = _OG_TITLE_RE.search(body)
        if og_match and username.lower() in og_match.group(1).lower():
            score += 0.20
            signals.append("og_title")

    # 4. JSON-LD Person (+0.15)
    if body and _has_jsonld_person(body):
        score += 0.15
        signals.append("jsonld_person")

    # 5. Activity counter > 0 (+0.10)
    activity = 0
    for key in _ACTIVITY_KEYS:
        raw = profile_data.get(key)
        try:
            n = int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            n = 0
        if n > activity:
            activity = n
    if activity == 0 and body:
        activity = _activity_count_from_body(body)
    if activity > 0:
        score += 0.10
        signals.append(f"activity:{activity}")

    score = min(score, 1.0)
    return LivenessScore(
        score=score,
        signals=tuple(signals),
        is_active=score >= LIVENESS_THRESHOLD,
    )
