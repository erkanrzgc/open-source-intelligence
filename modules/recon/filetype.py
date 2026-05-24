"""Optional Magika-backed file type detection.

The document metadata harvester can work from magic bytes alone, but
Magika gives us better coverage for spoofed extensions and textual file
types. This wrapper keeps Magika optional so the rest of the project can
run without the extra dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.logging_setup import get_logger

log = get_logger(__name__)

try:
    from magika import Magika  # type: ignore[import-not-found]

    _AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    Magika = None  # type: ignore[assignment]
    _AVAILABLE = False

_CLIENT: Any | None = None


@dataclass(frozen=True)
class FileTypeDetection:
    label: str
    description: str = ""
    mime_type: str = ""
    group: str = ""
    score: float = 0.0
    is_text: bool = False
    source: str = "magika"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_label": self.label,
            "detected_description": self.description,
            "detected_mime_type": self.mime_type,
            "detected_group": self.group,
            "detected_score": self.score,
            "detected_is_text": self.is_text,
            "detected_source": self.source,
        }


def is_available() -> bool:
    return _AVAILABLE


def _client():
    global _CLIENT
    if not _AVAILABLE or Magika is None:
        return None
    if _CLIENT is None:
        _CLIENT = Magika()
    return _CLIENT


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def identify_bytes(data: bytes) -> FileTypeDetection | None:
    """Return Magika's best content-type guess for ``data``.

    Returns ``None`` when Magika is unavailable or the model fails. The
    caller should treat detection as enrichment, not as a hard dependency.
    """
    if not data:
        return None
    client = _client()
    if client is None:
        return None
    try:
        result = client.identify_bytes(data)
    except Exception as exc:
        log.debug("magika detection failed: %s", exc)
        return None

    output = _field(result, "output")
    if output is None:
        value = _field(_field(result, "result", {}), "value", {})
        output = _field(value, "output")
    if output is None:
        return None

    score = _field(result, "score")
    if score is None:
        value = _field(_field(result, "result", {}), "value", {})
        score = _field(value, "score", 0.0)

    return FileTypeDetection(
        label=str(_field(output, "label", None) or _field(output, "ct_label", "") or ""),
        description=str(_field(output, "description", "") or ""),
        mime_type=str(_field(output, "mime_type", "") or ""),
        group=str(_field(output, "group", "") or ""),
        score=float(score or 0.0),
        is_text=bool(_field(output, "is_text", False)),
    )


def supported_document_format(detection: FileTypeDetection | None) -> str:
    """Map a Magika result to a parser-supported document format."""
    if detection is None:
        return ""
    label = detection.label.lower()
    mime = detection.mime_type.lower()
    if label == "pdf" or mime == "application/pdf":
        return "pdf"
    if label in {"docx", "xlsx", "pptx"}:
        return label
    if "wordprocessingml.document" in mime:
        return "docx"
    if "spreadsheetml.sheet" in mime:
        return "xlsx"
    if "presentationml.presentation" in mime:
        return "pptx"
    return ""
