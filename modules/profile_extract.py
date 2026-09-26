"""Universal profile extractor for opportunistic and deep profile scraping.

Extracts structured intelligence (names, usernames, bios, avatars, emails,
locations, outbound social handles, linked accounts, and contacts) from any
HTML page via:
1. Schema.org JSON-LD (Person, ProfilePage, Organization, Author)
2. OpenGraph and Twitter Cards (<meta property="og:..." / "twitter:...">)
3. Hydration state payloads (__NEXT_DATA__, __UNIVERSAL_DATA_FOR_REHYDRATION__)
4. Semantic HTML tags (<a> with rel="me" or social profile links, mailto:, etc.)
5. Upstream `socid_extractor` (if installed)
"""

from __future__ import annotations

import html as html_lib
import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency guard
    from socid_extractor import extract as _socid_extract  # type: ignore[import-not-found]

    _SOCID_AVAILABLE = True
except ImportError:
    _socid_extract = None
    _SOCID_AVAILABLE = False

# Public availability flag (built-in universal extraction is always available)
_AVAILABLE = True


_INTERESTING_KEYS = {
    "fullname",
    "name",
    "username",
    "nickname",
    "first_name",
    "last_name",
    "email",
    "emails",
    "bio",
    "description",
    "location",
    "country",
    "city",
    "website",
    "website_url",
    "links",
    "twitter",
    "github",
    "instagram",
    "telegram",
    "reddit",
    "avatar",
    "avatar_url",
    "image",
    "profile_image",
    "created_at",
    "joined",
    "gender",
    "age",
    "birthday",
    "language",
    "following",
    "followers",
    "posts",
    "social_handles",
    "twitter_username",
    "github_username",
    "linkedin_username",
    "telegram_username",
    "instagram_username",
    "youtube_username",
    "medium_username",
    "reddit_username",
    "bluesky_username",
    "tiktok_username",
    "threads_username",
    "gitlab_username",
    "pinterest_username",
    "twitch_username",
}

_OG_PROP_RE = re.compile(
    r'<meta\s+[^>]*(?:property|name)=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_OG_CONTENT_FIRST_RE = re.compile(
    r'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*(?:property|name)=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JSON_LD_RE = re.compile(
    r'<script\b[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_NEXT_DATA_RE = re.compile(
    r'<script\b[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_A_HREF_RE = re.compile(
    r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_MAILTO_RE = re.compile(r"mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", re.IGNORECASE)
_EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")

_SOCIAL_PATTERNS = [
    ("twitter", re.compile(r"(?:https?://|(?:\b))(?:www\.)?(?:twitter\.com|x\.com)/(?:#!/)?@?([a-zA-Z0-9_]{1,25})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("github", re.compile(r"(?:https?://|(?:\b))(?:www\.)?github\.com/([a-zA-Z0-9\-_]{1,39})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("linkedin", re.compile(r"(?:https?://|(?:\b))(?:[a-z]{2,3}\.)?linkedin\.com/in/([a-zA-Z0-9\-_%]+)(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("instagram", re.compile(r"(?:https?://|(?:\b))(?:www\.)?instagram\.com/([a-zA-Z0-9_\.]{1,30})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("telegram", re.compile(r"(?:https?://|(?:\b))(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{4,32})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("youtube", re.compile(r"(?:https?://|(?:\b))(?:www\.)?youtube\.com/@([a-zA-Z0-9_\-\.]{1,50})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("medium", re.compile(r"(?:https?://|(?:\b))(?:www\.)?medium\.com/@([a-zA-Z0-9_\-\.]{1,50})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("reddit", re.compile(r"(?:https?://|(?:\b))(?:www\.)?reddit\.com/user/([a-zA-Z0-9_\-]{3,20})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("bluesky", re.compile(r"(?:https?://|(?:\b))(?:www\.)?bsky\.app/profile/([a-zA-Z0-9_\.\-]+)(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("tiktok", re.compile(r"(?:https?://|(?:\b))(?:www\.)?tiktok\.com/@([a-zA-Z0-9_\.]{1,24})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("threads", re.compile(r"(?:https?://|(?:\b))(?:www\.)?threads\.net/@([a-zA-Z0-9_\.]{1,30})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("gitlab", re.compile(r"(?:https?://|(?:\b))(?:www\.)?gitlab\.com/([a-zA-Z0-9_\-\.]{1,39})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("pinterest", re.compile(r"(?:https?://|(?:\b))(?:www\.)?pinterest\.com/([a-zA-Z0-9_\-]{1,30})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
    ("twitch", re.compile(r"(?:https?://|(?:\b))(?:www\.)?twitch\.tv/([a-zA-Z0-9_]{2,25})(?:[/?#\s\"'\)]|$)", re.IGNORECASE)),
]

_GENERIC_PATHS = frozenset({
    "about", "privacy", "terms", "login", "signup", "settings", "help", "support",
    "search", "explore", "home", "contact", "blog", "jobs", "press", "legal",
    "security", "cookies", "status", "share", "intent", "hashtag", "direct", "notifications",
})


def _parse_social_url(url: str) -> tuple[str, str] | None:
    url = url.strip()
    for service, pat in _SOCIAL_PATTERNS:
        m = pat.match(url)
        if m:
            handle = m.group(1).lstrip("@").strip()
            if handle.lower() not in _GENERIC_PATHS:
                return service, handle
    return None


def _clean_title(title: str) -> str:
    title = re.sub(
        r"\s*[-|·•/]\s*(?:Twitter|X|GitHub|LinkedIn|Medium|Instagram|YouTube|Reddit|Bluesky|Threads|TikTok).*$",
        "",
        title,
        flags=re.IGNORECASE,
    )
    title = re.sub(r"\s*[\(\[@][@\w\-]+[\)\]]\s*$", "", title, flags=re.IGNORECASE)
    return title.strip()


def is_available() -> bool:
    """Return whether profile extraction capabilities are available."""
    return _AVAILABLE


def extract_profile(html: str) -> dict[str, Any]:
    """Run universal profile extractor and socid_extractor over HTML.

    Returns a normalized field dict including name, username, bio, avatar_url,
    emails, linked social handles, locations, and outbound profile links.
    """
    if not _AVAILABLE or not html:
        return {}

    data: dict[str, Any] = {}
    social_handles: dict[str, str] = {}
    links: set[str] = set()
    emails: set[str] = set()

    # 1. JSON-LD parsing (Highest specificity: structured semantic Person / Profile data)
    for match in _JSON_LD_RE.finditer(html):
        try:
            ld_raw = json.loads(match.group(1).strip())
        except Exception:
            continue

        items = ld_raw if isinstance(ld_raw, list) else [ld_raw]
        if isinstance(ld_raw, dict) and "@graph" in ld_raw and isinstance(ld_raw["@graph"], list):
            items.extend(ld_raw["@graph"])

        for item in items:
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("@type", ""))
            if any(t in item_type for t in ["Person", "ProfilePage", "Organization", "Author"]):
                if item.get("name") and not data.get("name"):
                    data["name"] = str(item["name"]).strip()
                if item.get("alternateName") and not data.get("username"):
                    alt = item["alternateName"]
                    data["username"] = str(alt[0] if isinstance(alt, list) else alt).lstrip("@").strip()
                if item.get("description") and not data.get("bio"):
                    data["bio"] = str(item["description"]).strip()
                img = item.get("image")
                if img and not data.get("avatar_url"):
                    if isinstance(img, str):
                        data["avatar_url"] = img
                    elif isinstance(img, dict) and "url" in img:
                        data["avatar_url"] = img["url"]
                if item.get("email"):
                    raw_email = str(item["email"]).replace("mailto:", "").strip()
                    if "@" in raw_email:
                        emails.add(raw_email)
                if item.get("telephone"):
                    data["phone"] = str(item["telephone"]).strip()
                if item.get("jobTitle"):
                    data["job_title"] = str(item["jobTitle"]).strip()
                works = item.get("worksFor")
                if works:
                    if isinstance(works, str):
                        data["company"] = works.strip()
                    elif isinstance(works, dict) and "name" in works:
                        data["company"] = str(works["name"]).strip()
                loc = item.get("homeLocation") or item.get("address")
                if loc:
                    if isinstance(loc, str):
                        data["location"] = loc.strip()
                    elif isinstance(loc, dict) and "name" in loc:
                        data["location"] = str(loc["name"]).strip()

                same_as = item.get("sameAs", [])
                if isinstance(same_as, str):
                    same_as = [same_as]
                if isinstance(same_as, list):
                    for u in same_as:
                        if isinstance(u, str):
                            res = _parse_social_url(u)
                            if res:
                                social_handles[res[0]] = res[1]
                            elif u.startswith(("http://", "https://")):
                                links.add(u)

    # 2. Next.js hydration state (__NEXT_DATA__)
    for match in _NEXT_DATA_RE.finditer(html):
        try:
            nd = json.loads(match.group(1).strip())
            page_props = nd.get("props", {}).get("pageProps", {})
            user_obj = (
                page_props.get("user")
                or page_props.get("profile")
                or page_props.get("userData")
                or page_props.get("account")
            )
            if isinstance(user_obj, dict):
                if user_obj.get("name") and not data.get("name"):
                    data["name"] = str(user_obj["name"]).strip()
                if user_obj.get("username") and not data.get("username"):
                    data["username"] = str(user_obj["username"]).strip()
                if (user_obj.get("bio") or user_obj.get("description")) and not data.get("bio"):
                    data["bio"] = str(user_obj.get("bio") or user_obj.get("description")).strip()
                avatar = user_obj.get("avatar") or user_obj.get("avatarUrl") or user_obj.get("profileImage")
                if avatar and not data.get("avatar_url"):
                    data["avatar_url"] = str(avatar).strip()
                if user_obj.get("location") and not data.get("location"):
                    data["location"] = str(user_obj["location"]).strip()
                if user_obj.get("email"):
                    emails.add(str(user_obj["email"]).strip())
        except Exception:
            pass

    # 3. OpenGraph & Meta tags (Fill in anything not yet discovered)
    meta_tags: dict[str, str] = {}
    for match in _OG_PROP_RE.finditer(html):
        k, v = match.group(1).lower().strip(), html_lib.unescape(match.group(2).strip())
        if v and k not in meta_tags:
            meta_tags[k] = v
    for match in _OG_CONTENT_FIRST_RE.finditer(html):
        k, v = match.group(2).lower().strip(), html_lib.unescape(match.group(1).strip())
        if v and k not in meta_tags:
            meta_tags[k] = v

    if not data.get("name"):
        og_title = meta_tags.get("og:title") or meta_tags.get("twitter:title")
        if og_title:
            data["name"] = _clean_title(og_title)

    if not data.get("bio"):
        og_desc = meta_tags.get("og:description") or meta_tags.get("twitter:description") or meta_tags.get("description")
        if og_desc and len(og_desc) > 3:
            data["bio"] = og_desc

    if not data.get("avatar_url"):
        og_img = meta_tags.get("og:image") or meta_tags.get("twitter:image") or meta_tags.get("twitter:image:src")
        if og_img and og_img.startswith(("http://", "https://")):
            data["avatar_url"] = og_img

    if not data.get("url"):
        og_url = meta_tags.get("og:url")
        if og_url:
            data["url"] = og_url

    if not data.get("username"):
        username_meta = meta_tags.get("profile:username") or meta_tags.get("twitter:creator")
        if username_meta:
            cleaned_user = username_meta.lstrip("@").strip()
            if cleaned_user:
                data["username"] = cleaned_user

    # 4. Outbound Links (<a> tags)
    for match in _A_HREF_RE.finditer(html):
        href = match.group(1).strip()
        mailto = _MAILTO_RE.search(href)
        if mailto:
            emails.add(mailto.group(1))
            continue
        res = _parse_social_url(href)
        if res:
            social_handles[res[0]] = res[1]
        elif href.startswith(("http://", "https://")):
            if not any(x in href for x in ["w3.org", "schema.org", "google.com/search", "twitter.com/intent"]):
                links.add(href)

    # 5. Extract social handles and emails from bio text
    if data.get("bio"):
        bio_text = data["bio"]
        for srv, pat in _SOCIAL_PATTERNS:
            if srv not in social_handles:
                for match in pat.finditer(bio_text):
                    h = match.group(1).lstrip("@").strip()
                    if h.lower() not in _GENERIC_PATHS:
                        social_handles[srv] = h
                        break

        for email_match in _EMAIL_REGEX.finditer(bio_text):
            candidate = email_match.group(0)
            if not candidate.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
                emails.add(candidate)

    # Format structured output fields
    if emails:
        data["email"] = sorted(emails)[0]
        data["emails"] = sorted(emails)

    if social_handles:
        data["social_handles"] = social_handles
        for srv, handle in social_handles.items():
            data[f"{srv}_username"] = handle

    if links:
        data["links"] = sorted(links)[:10]
        if not data.get("website_url"):
            data["website_url"] = sorted(links)[0]

    # 6. Upstream socid_extractor integration (if available)
    if _socid_extract is not None:
        try:
            raw = _socid_extract(html)
            if isinstance(raw, dict):
                for k, v in raw.items():
                    if v not in (None, "", [], {}) and k not in data:
                        data[k] = v
        except Exception as exc:
            log.debug("socid_extractor error: %s", exc)

    return {k: v for k, v in data.items() if v not in (None, "", [], {})}
