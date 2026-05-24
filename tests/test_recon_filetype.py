"""Tests for optional Magika file-type detection wrapper."""

from __future__ import annotations

from modules.recon import filetype
from modules.recon.filetype import FileTypeDetection


def test_identify_bytes_returns_none_when_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(filetype, "_AVAILABLE", False)
    assert filetype.identify_bytes(b"%PDF-1.4") is None


def test_supported_document_format_from_label() -> None:
    assert filetype.supported_document_format(FileTypeDetection(label="pdf")) == "pdf"
    assert filetype.supported_document_format(FileTypeDetection(label="docx")) == "docx"
    assert filetype.supported_document_format(FileTypeDetection(label="html")) == ""


def test_detection_to_dict_uses_report_field_names() -> None:
    d = FileTypeDetection(
        label="pdf",
        description="PDF document",
        mime_type="application/pdf",
        group="document",
        score=0.99,
        is_text=False,
    )
    out = d.to_dict()
    assert out["detected_label"] == "pdf"
    assert out["detected_mime_type"] == "application/pdf"
    assert out["detected_score"] == 0.99
