"""Backward-compatible façade over core.platform_loader.

Platform definitions now live in ``modules/platforms.yaml`` and can be
extended or overridden via ``~/.config/open-source-intelligence/platforms.yaml`` or the
``OSINT_PLATFORMS_FILE`` environment variable. See
``core/platform_loader.py`` for the loader rules.
"""

from core.platform_loader import Platform, load_platforms

_PLATFORMS: list[Platform] | None = None


def _ensure_loaded() -> list[Platform]:
    global _PLATFORMS
    if _PLATFORMS is None:
        _PLATFORMS = load_platforms()
    return _PLATFORMS


def __getattr__(name: str):
    if name == "PLATFORMS":
        return _ensure_loaded()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_platform_count() -> int:
    return len(_ensure_loaded())


__all__ = ["PLATFORMS", "Platform", "get_platform_count"]  # noqa: F822
