"""Input-boundary security helpers.

The network client applies these checks to every outbound request so optional
modules cannot accidentally bypass the same SSRF policy used by REST/MCP.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit


class UnsafeTargetError(ValueError):
    """Raised when an outbound URL targets a disallowed address."""


_LOCAL_HOSTS = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def validate_http_url(url: str, *, allow_private_networks: bool = False) -> str:
    """Return *url* when it is an allowed HTTP(S) target.

    Literal loopback, link-local, private, reserved and multicast addresses are
    rejected by default. Hostnames ending in ``.localhost`` are rejected too.
    The connector still performs DNS resolution; this boundary check prevents
    the common direct-address and localhost forms without doing blocking DNS in
    the event loop.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeTargetError("URL must be a non-empty string")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port  # force validation of malformed ports
    except ValueError as exc:
        raise UnsafeTargetError(f"invalid URL: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTargetError("only http:// and https:// URLs are allowed")
    if not parsed.hostname:
        raise UnsafeTargetError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("credentials in URLs are not allowed")
    if port is not None and not 1 <= port <= 65535:
        raise UnsafeTargetError("URL port is outside the valid range")

    host = parsed.hostname.rstrip(".").lower()
    if allow_private_networks:
        return url.strip()
    if host in _LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".local"):
        raise UnsafeTargetError(f"private-network target is disabled: {host}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return url.strip()
    if not address.is_global:
        raise UnsafeTargetError(f"private-network target is disabled: {host}")
    return url.strip()


_SECRET_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "password",
        "passwd",
        "secret",
        "token",
    }
)


def _is_secret_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SECRET_KEYS or normalized.endswith(
        ("_api_key", "_access_token", "_password", "_secret", "_token")
    )


def redact_secrets(value: object) -> object:
    """Recursively redact values stored under credential-shaped keys."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _is_secret_key(key) else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    return value


def ensure_path_within(path: str | Path, roots: tuple[Path, ...]) -> Path:
    """Resolve *path* and require it to be below one of the allowed roots."""
    candidate = Path(path).expanduser().resolve(strict=False)
    for root in roots:
        resolved_root = root.expanduser().resolve(strict=False)
        if candidate == resolved_root or resolved_root in candidate.parents:
            return candidate
    allowed = ", ".join(str(root) for root in roots)
    raise ValueError(f"path {candidate} is outside allowed roots: {allowed}")
