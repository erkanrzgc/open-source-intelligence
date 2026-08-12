"""Tests for the public-document metadata extractor.

Fixtures are built in-memory (no binary files committed): each test
constructs a minimal OOXML zip or a one-page PDF so we control exactly
which metadata fields the parser should see.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.recon import doc_metadata
from modules.recon.doc_metadata import (
    _detect_format,
    _extract_network_paths,
    _parse_docx,
    _parse_pdf,
)
from modules.recon.filetype import FileTypeDetection
from modules.recon.models import DocumentMetadata

# ── Format detection ────────────────────────────────────────────────


def test_detect_format_pdf_by_magic() -> None:
    assert _detect_format(b"%PDF-1.4\n...", url="anything.bin") == "pdf"


def test_detect_format_docx_by_zip_and_content_types() -> None:
    buf = _build_minimal_docx({"creator": "alice"})
    assert _detect_format(buf, url="report.docx") == "docx"


def test_detect_format_xlsx_recognized() -> None:
    buf = _build_minimal_xlsx({"creator": "bob"})
    assert _detect_format(buf, url="numbers.xlsx") == "xlsx"


def test_detect_format_unknown_returns_empty_string() -> None:
    assert _detect_format(b"plain text body", url="thing.txt") == ""


# ── Network path extraction ─────────────────────────────────────────


def test_extract_network_paths_finds_unc_paths() -> None:
    text = (
        r"see \\acme-fs01\reports\q3.docx for details, also "
        r"\\corp.acme.local\share\HR\offer.pdf in the appendix"
    )
    paths = _extract_network_paths(text)
    assert r"\\acme-fs01\reports\q3.docx" in paths
    assert r"\\corp.acme.local\share\HR\offer.pdf" in paths


def test_extract_network_paths_dedupes() -> None:
    text = r"\\srv\path appears twice: \\srv\path"
    assert _extract_network_paths(text) == (r"\\srv\path",)


def test_extract_network_paths_returns_empty_on_clean_text() -> None:
    assert _extract_network_paths("regular http://example.com/path text") == ()


# ── DOCX parsing ────────────────────────────────────────────────────


def test_parse_docx_extracts_core_and_app_props() -> None:
    blob = _build_minimal_docx(
        {
            "creator": "alice@acme.com",
            "lastModifiedBy": "bob",
            "title": "Q3 Plan",
            "subject": "internal",
            "keywords": "confidential, draft",
            "Application": "Microsoft Office Word",
            "Company": "Acme Corp",
            "created": "2024-01-15T10:00:00Z",
            "modified": "2024-02-20T14:30:00Z",
            "extra_text": r"network share is \\acme-fs01\public",
        }
    )
    meta = _parse_docx(blob, url="https://acme.com/Q3.docx")
    assert isinstance(meta, DocumentMetadata)
    assert meta.format == "docx"
    assert meta.author == "alice@acme.com"
    assert meta.last_author == "bob"
    assert meta.title == "Q3 Plan"
    assert meta.keywords == "confidential, draft"
    assert meta.software == "Microsoft Office Word"
    assert meta.company == "Acme Corp"
    assert meta.created == "2024-01-15T10:00:00Z"
    assert meta.modified == "2024-02-20T14:30:00Z"
    assert r"\\acme-fs01\public" in meta.network_paths


def test_parse_docx_handles_missing_app_xml() -> None:
    # Build a docx with only core.xml, no app.xml
    blob = _build_minimal_docx({"creator": "carol"}, include_app=False)
    meta = _parse_docx(blob, url="x.docx")
    assert meta is not None
    assert meta.author == "carol"
    assert meta.company == ""
    assert meta.software == ""


def test_parse_docx_returns_none_for_corrupt_zip() -> None:
    assert _parse_docx(b"not a zip", url="x.docx") is None


# ── PDF parsing ─────────────────────────────────────────────────────


def test_parse_pdf_extracts_metadata() -> None:
    blob = _build_minimal_pdf(
        {
            "/Author": "alice@acme.com",
            "/Title": "Annual Report",
            "/Creator": "Word",
            "/Producer": "Acrobat 11",
            "/Subject": "FY2024",
        }
    )
    meta = _parse_pdf(blob, url="https://acme.com/r.pdf")
    assert isinstance(meta, DocumentMetadata)
    assert meta.format == "pdf"
    assert meta.author == "alice@acme.com"
    assert meta.title == "Annual Report"
    assert meta.creator == "Word"
    # Producer (PDF software) maps to ``software``
    assert meta.software == "Acrobat 11"


def test_parse_pdf_returns_none_for_garbage() -> None:
    assert _parse_pdf(b"definitely not a pdf", url="x.pdf") is None


# ── Top-level extract API (HTTP-driven) ─────────────────────────────


@pytest.mark.asyncio
async def test_extract_from_url_routes_to_pdf_parser() -> None:
    blob = _build_minimal_pdf({"/Author": "dora", "/Title": "X"})
    with aioresponses() as m:
        m.get("https://t.example/file.pdf", body=blob, content_type="application/pdf")
        async with HTTPClient() as client:
            meta = await doc_metadata.extract_from_url(
                client, "https://t.example/file.pdf"
            )
    assert meta is not None
    assert meta.format == "pdf"
    assert meta.author == "dora"


@pytest.mark.asyncio
async def test_extract_from_url_routes_to_docx_parser() -> None:
    blob = _build_minimal_docx({"creator": "eve", "Company": "Foo"})
    with aioresponses() as m:
        m.get(
            "https://t.example/d.docx",
            body=blob,
            content_type=(
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
        )
        async with HTTPClient() as client:
            meta = await doc_metadata.extract_from_url(
                client, "https://t.example/d.docx"
            )
    assert meta is not None
    assert meta.format == "docx"
    assert meta.author == "eve"
    assert meta.company == "Foo"


@pytest.mark.asyncio
async def test_extract_from_url_attaches_magika_detection(monkeypatch) -> None:
    blob = _build_minimal_pdf({"/Author": "dora", "/Title": "X"})
    monkeypatch.setattr(
        doc_metadata.filetype,
        "identify_bytes",
        lambda data: FileTypeDetection(
            label="pdf",
            description="PDF document",
            mime_type="application/pdf",
            group="document",
            score=0.99,
        ),
    )
    with aioresponses() as m:
        m.get("https://t.example/file.pdf", body=blob, content_type="application/pdf")
        async with HTTPClient() as client:
            meta = await doc_metadata.extract_from_url(
                client, "https://t.example/file.pdf"
            )
    assert meta is not None
    assert meta.raw["detected_label"] == "pdf"
    assert meta.raw["detected_score"] == 0.99


@pytest.mark.asyncio
async def test_extract_from_url_reports_spoofed_document(monkeypatch) -> None:
    monkeypatch.setattr(
        doc_metadata.filetype,
        "identify_bytes",
        lambda data: FileTypeDetection(
            label="html",
            description="HTML document",
            mime_type="text/html",
            group="text",
            score=0.98,
            is_text=True,
        ),
    )
    with aioresponses() as m:
        m.get("https://t.example/invoice.pdf", body=b"<html>login</html>")
        async with HTTPClient() as client:
            meta = await doc_metadata.extract_from_url(
                client, "https://t.example/invoice.pdf"
            )
    assert meta is not None
    assert meta.format == "html"
    assert meta.raw["unsupported_document_payload"] is True
    assert meta.raw["detected_mime_type"] == "text/html"


@pytest.mark.asyncio
async def test_extract_from_url_returns_none_on_404() -> None:
    with aioresponses() as m:
        m.get("https://t.example/missing.pdf", status=404)
        async with HTTPClient() as client:
            meta = await doc_metadata.extract_from_url(
                client, "https://t.example/missing.pdf"
            )
    assert meta is None


@pytest.mark.asyncio
async def test_extract_from_url_skips_oversized_responses() -> None:
    # 5MB blob; cap at 1MB
    blob = b"%PDF-1.4\n" + b"x" * (5 * 1024 * 1024)
    with aioresponses() as m:
        m.get("https://t.example/big.pdf", body=blob, content_type="application/pdf")
        async with HTTPClient() as client:
            meta = await doc_metadata.extract_from_url(
                client, "https://t.example/big.pdf", max_size=1024 * 1024
            )
    assert meta is None


@pytest.mark.asyncio
async def test_extract_batch_runs_in_parallel() -> None:
    pdf_blob = _build_minimal_pdf({"/Author": "a"})
    docx_blob = _build_minimal_docx({"creator": "b"})
    urls = [
        "https://t.example/a.pdf",
        "https://t.example/b.docx",
        "https://t.example/missing.pdf",
    ]
    with aioresponses() as m:
        m.get(urls[0], body=pdf_blob, content_type="application/pdf")
        m.get(
            urls[1],
            body=docx_blob,
            content_type=(
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
        )
        m.get(urls[2], status=404)
        async with HTTPClient() as client:
            results = await doc_metadata.extract_batch(client, urls)
    # Only the two successful fetches should produce results
    assert len(results) == 2
    authors = {m.author for m in results}
    assert authors == {"a", "b"}


# ── Fixture builders ────────────────────────────────────────────────


_CONTENT_TYPES_DOCX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_CONTENT_TYPES_XLSX = _CONTENT_TYPES_DOCX.replace(
    "wordprocessingml.document.main", "spreadsheetml.sheet.main"
).replace("/word/document.xml", "/xl/workbook.xml")


def _core_xml(props: dict) -> str:
    fields = []
    for tag, ns in (
        ("creator", "dc"),
        ("title", "dc"),
        ("subject", "dc"),
        ("description", "dc"),
        ("keywords", "cp"),
        ("lastModifiedBy", "cp"),
        ("created", "dcterms"),
        ("modified", "dcterms"),
    ):
        if tag in props:
            fields.append(f"<{ns}:{tag}>{props[tag]}</{ns}:{tag}>")
    body = "\n  ".join(fields)
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
  xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/">
  {body}
</cp:coreProperties>"""


def _app_xml(props: dict) -> str:
    fields = []
    for tag in ("Application", "Company", "Manager"):
        if tag in props:
            fields.append(f"<{tag}>{props[tag]}</{tag}>")
    body = "\n  ".join(fields)
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  {body}
</Properties>"""


def _build_minimal_docx(props: dict, *, include_app: bool = True) -> bytes:
    """Compose a tiny but structurally valid DOCX zip in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES_DOCX)
        z.writestr("docProps/core.xml", _core_xml(props))
        if include_app:
            z.writestr("docProps/app.xml", _app_xml(props))
        # Minimal document.xml — content engines may search it for UNC paths
        text = props.get("extra_text", "")
        z.writestr(
            "word/document.xml",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                'wordprocessingml/2006/main">'
                f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>"
                "</w:document>"
            ),
        )
    return buf.getvalue()


def _build_minimal_xlsx(props: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES_XLSX)
        z.writestr("docProps/core.xml", _core_xml(props))
        z.writestr("docProps/app.xml", _app_xml(props))
        z.writestr(
            "xl/workbook.xml",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/'
                'spreadsheetml/2006/main"/>'
            ),
        )
    return buf.getvalue()


def _build_minimal_pdf(metadata: dict) -> bytes:
    """Use pypdf to write a one-blank-page PDF carrying ``metadata``."""
    PdfWriter = pytest.importorskip("pypdf").PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_metadata(metadata)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
