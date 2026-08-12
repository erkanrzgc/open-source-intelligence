"""Centralized logging for open-source-intelligence.

Separates diagnostic logging from response serialization and exporters.
Use get_logger(__name__) inside modules.
"""

from __future__ import annotations

import logging
import os
import re

_CONFIGURED = False

_LOG_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|password|secret|token)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"(?i)(/bot)[^/\s]+"),
)


class _RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        for pattern in _LOG_SECRET_PATTERNS:
            rendered = pattern.sub(
                lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]",
                rendered,
            )
        return rendered


def configure_logging(level: str | None = None) -> None:
    """Configure the root logger once.

    Level precedence: explicit arg > OSINT_LOG_LEVEL env var > WARNING.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    resolved = (level or os.environ.get("OSINT_LOG_LEVEL") or "WARNING").upper()
    numeric = getattr(logging, resolved, logging.WARNING)

    handler = logging.StreamHandler()
    handler.setFormatter(
        _RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    root = logging.getLogger("open_source_intelligence")
    root.setLevel(numeric)
    root.handlers = [handler]
    root.propagate = False

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger under the application hierarchy."""
    if not _CONFIGURED:
        configure_logging()
    short = name.split(".")[-1] if name else "open_source_intelligence"
    return logging.getLogger(f"open_source_intelligence.{short}")
