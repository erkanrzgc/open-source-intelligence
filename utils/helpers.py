import hashlib
import re
import sys
from urllib.parse import urlparse

# Common social-profile path prefixes that wrap the actual handle.
# e.g. https://www.linkedin.com/in/erkanrzgc  →  erkanrzgc
_PROFILE_PATH_PREFIXES = ("in", "u", "user", "users", "profile", "@")


def sanitize_username(username: str) -> str:
    """Normalize a username supplied through an API, MCP, or library call.

    Accepts either a bare handle (`alice`, `@alice`, `erkan.rzgc`) or a
    profile URL (`https://github.com/erkanrzgc`, `twitter.com/erkanrzgc`).
    URLs are detected only by explicit signals (`://`, leading `www.`, or
    a `/` in the input) so dotted handles like `erkan.rzgc` are preserved.

    Raises ValueError on empty/whitespace-only input or a URL with no
    extractable handle (e.g. `https://github.com/`).
    """
    if not username or not username.strip():
        raise ValueError("username is empty")

    raw = username.strip()
    looks_like_url = (
        "://" in raw
        or raw.lower().startswith("www.")
        or "/" in raw
    )

    if looks_like_url:
        handle = _extract_handle_from_url(raw)
        if not handle:
            raise ValueError(
                f"could not extract a username from {username!r}. "
                "Pass just the handle (e.g. 'erkanrzgc') instead of the full URL."
            )
        print(
            f"[sanitize_username] interpreted {username!r} as URL → handle {handle!r}",
            file=sys.stderr,
        )
        return handle.lstrip("@")

    return raw.lstrip("@")


def _extract_handle_from_url(raw: str) -> str:
    """Pull the most likely handle out of a profile-style URL or path."""
    candidate = raw if "://" in raw else f"https://{raw.lstrip('/')}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ""

    path_parts = [p for p in parsed.path.split("/") if p]
    if not path_parts:
        return ""

    # Skip leading prefixes like /in/, /user/, /@ until a real handle remains.
    while path_parts and path_parts[0].lower().lstrip("@") in _PROFILE_PATH_PREFIXES:
        path_parts.pop(0)

    if not path_parts:
        return ""
    return path_parts[0].lstrip("@")


def md5_hash(text: str) -> str:
    return hashlib.md5(text.lower().strip().encode(), usedforsecurity=False).hexdigest()


def extract_emails_from_text(text: str) -> list[str]:
    if not text:
        return []
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))


def extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    pattern = r"https?://[^\s<>\"')\]]+"
    return list(set(re.findall(pattern, text)))


def normalize_name(name: str) -> str:
    if not name:
        return ""
    return re.sub(r"\s+", " ", name.strip().lower())


def fuzzy_name_match(name1: str, name2: str) -> float:
    if not name1 or not name2:
        return 0.0
    n1 = normalize_name(name1)
    n2 = normalize_name(name2)
    if n1 == n2:
        return 1.0
    parts1 = set(n1.split())
    parts2 = set(n2.split())
    if not parts1 or not parts2:
        return 0.0
    intersection = parts1 & parts2
    union = parts1 | parts2
    return len(intersection) / len(union)
