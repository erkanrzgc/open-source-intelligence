"""FastAPI REST surface — optional dependency.

The app factory lives in :mod:`core.api.server` behind a lazy import so
FastAPI remains an optional dependency for library and MCP consumers.
"""

from __future__ import annotations


def is_available() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        return False
    return True


def create_app():
    """Return a FastAPI app instance. Raises RuntimeError if deps missing."""
    if not is_available():
        raise RuntimeError(
            "REST API requires 'fastapi' and 'uvicorn'. Install with: "
            "pip install fastapi uvicorn"
        )
    from core.api.server import build_app
    return build_app()


__all__ = ["create_app", "is_available"]
