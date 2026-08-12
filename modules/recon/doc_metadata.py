"""Public-document metadata harvester (Metagoofil-style).

Pairs naturally with ``modules/passive/google_dork`` — that module
surfaces public PDF/DOCX/XLSX URLs hosted on the target's domain;
this one downloads each, parses the embedded metadata, and returns a
:class:`DocumentMetadata` per file.

Why this matters
----------------
Office documents and PDFs typically embed:

* The author's full name or login (often ``firstname.lastname`` or
  the AD account that saved the file).
* The "Last modified by" identity — sometimes a different person than
  the original author, exposing additional employee names.
* The authoring software with version (`Microsoft Word 16.0`,
  `LibreOffice 7.6`) — useful for crafting a believable file payload
  if you are doing red-team email delivery.
* Company name as the registered Office license holder.
* Network paths embedded in revision metadata
  (e.g. ``\\\\acme-fs01\\reports``) — these are real internal SMB
  shares, gold for SE pretexting and lateral movement planning.

Implementation
--------------
* PDF: use ``pypdf`` (already a transitive dep) to read the
  ``/Author``, ``/Creator``, ``/Producer``, ``/Title``, ``/Subject``,
  ``/CreationDate``, ``/ModDate`` info dictionary.
* DOCX/XLSX/PPTX: stdlib ``zipfile`` + ``xml.etree`` to read
  ``docProps/core.xml`` (Dublin Core fields) and ``docProps/app.xml``
  (extended properties — Application, Company, Manager).
* Network paths: regex over the entire raw text content of the
  document, which catches UNC paths in any embedded location.

This module never executes any document content; it only reads the
metadata containers. There is no SSRF / RCE surface beyond what an
already-hostile URL can do via the underlying HTTP client.
"""

from __future__ import annotations

import asyncio
import io
import re
import zipfile
from dataclasses import replace
from typing import Any, Final
from xml.etree import ElementTree as ET  # nosec B405

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.recon import filetype
from modules.recon.models import DocumentMetadata

log = get_logger(__name__)

_DEFAULT_MAX_SIZE: Final[int] = 10 * 1024 * 1024  # 10 MB

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"
_DOC_URL_RE = re.compile(r"\.(?:pdf|docx|xlsx|pptx)(?:[?#].*)?$", re.I)

# UNC paths: \\host\share[\subpath...]. Host can have dots (FQDN). The
# tail accepts standard share-name and path characters.
_UNC_RE = re.compile(r"\\\\[A-Za-z0-9_.\-]+\\[A-Za-z0-9_$./\\\-]+")

# OOXML XML namespaces
_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ext": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


# ── Detection helpers ───────────────────────────────────────────────


def _detect_format(data: bytes, *, url: str) -> str:
    """Identify the document format from magic bytes (and content type
    hint inside zip containers).

    Returns one of ``"pdf"``, ``"docx"``, ``"xlsx"``, ``"pptx"``, or
    an empty string if unknown.
    """
    if data.startswith(_PDF_MAGIC):
        return "pdf"
    if data.startswith(_ZIP_MAGIC):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if "[Content_Types].xml" not in z.namelist():
                    return ""
                ct = z.read("[Content_Types].xml").decode("utf-8", "ignore")
                if "wordprocessingml" in ct:
                    return "docx"
                if "spreadsheetml" in ct:
                    return "xlsx"
                if "presentationml" in ct:
                    return "pptx"
        except zipfile.BadZipFile:
            return ""
    return ""


def _detection_raw(detection: filetype.FileTypeDetection | None) -> dict:
    return detection.to_dict() if detection is not None else {}


def _with_detection(
    meta: DocumentMetadata,
    detection: filetype.FileTypeDetection | None,
) -> DocumentMetadata:
    raw = dict(meta.raw)
    raw.update(_detection_raw(detection))
    return replace(meta, raw=raw)


def _spoof_report(
    *,
    url: str,
    detection: filetype.FileTypeDetection | None,
) -> DocumentMetadata | None:
    """Return a lightweight report for document-looking URLs that are not
    parser-supported documents.

    This catches cases like ``invoice.pdf`` serving HTML, script, or a
    binary blob. We do not attempt metadata extraction for those files;
    we just surface the mismatch for the operator.
    """
    if detection is None or not _DOC_URL_RE.search(url):
        return None
    raw = _detection_raw(detection)
    raw["unsupported_document_payload"] = True
    return DocumentMetadata(
        url=url,
        format=detection.label or "unknown",
        raw=raw,
    )


def _extract_network_paths(text: str) -> tuple[str, ...]:
    """Return UNC paths discovered in ``text``, deduped, source order."""
    seen: set[str] = set()
    out: list[str] = []
    for match in _UNC_RE.finditer(text):
        path = match.group(0)
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return tuple(out)


# ── DOCX / XLSX / PPTX (OOXML) ──────────────────────────────────────


def _xml_text(root: ET.Element | None, path: str) -> str:
    if root is None:
        return ""
    el = root.find(path, _NS)
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _parse_docx(data: bytes, *, url: str) -> DocumentMetadata | None:
    """Parse an OOXML container's metadata.

    Used for docx/xlsx/pptx — the metadata layout is identical, only
    the main content part differs.
    """
    fmt = _detect_format(data, url=url)
    if fmt not in ("docx", "xlsx", "pptx"):
        return None

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            core = _read_xml(z, "docProps/core.xml")
            app = _read_xml(z, "docProps/app.xml")
            full_text = _all_text_from_zip(z)
    except zipfile.BadZipFile:
        return None
    except Exception as exc:
        log.debug("docx parse failed for %s: %s", url, exc)
        return None

    raw: dict = {}
    author = _xml_text(core, "dc:creator")
    title = _xml_text(core, "dc:title")
    subject = _xml_text(core, "dc:subject")
    keywords = _xml_text(core, "cp:keywords")
    last_author = _xml_text(core, "cp:lastModifiedBy")
    created = _xml_text(core, "dcterms:created")
    modified = _xml_text(core, "dcterms:modified")
    application = _xml_text(app, "ext:Application")
    company = _xml_text(app, "ext:Company")
    manager = _xml_text(app, "ext:Manager")

    if manager:
        raw["manager"] = manager

    return DocumentMetadata(
        url=url,
        format=fmt,
        author=author,
        last_author=last_author,
        creator=author,
        title=title,
        subject=subject,
        keywords=keywords,
        company=company,
        software=application,
        created=created,
        modified=modified,
        network_paths=_extract_network_paths(full_text),
        raw=raw,
    )


def _read_xml(z: zipfile.ZipFile, name: str) -> ET.Element | None:
    if name not in z.namelist():
        return None
    try:
        raw = z.read(name)
        # OOXML metadata never needs DTDs or custom entities. Reject them
        # before the stdlib parser sees attacker-controlled document XML.
        upper = raw.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            return None
        return ET.fromstring(raw)  # nosec B314
    except ET.ParseError:
        return None


def _all_text_from_zip(z: zipfile.ZipFile) -> str:
    """Concatenate every ``.xml`` / ``.rels`` part inside the zip into
    a single string for UNC-path mining.
    """
    pieces: list[str] = []
    for name in z.namelist():
        if not (name.endswith(".xml") or name.endswith(".rels")):
            continue
        try:
            pieces.append(z.read(name).decode("utf-8", "ignore"))
        except KeyError:
            continue
    return "\n".join(pieces)


# ── PDF ─────────────────────────────────────────────────────────────


def _parse_pdf(data: bytes, *, url: str) -> DocumentMetadata | None:
    if not data.startswith(_PDF_MAGIC):
        return None
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError

        reader = PdfReader(io.BytesIO(data))
        info: dict[str, Any] = reader.metadata or {}
    except (PdfReadError, ValueError, OSError) as exc:
        log.debug("pdf parse failed for %s: %s", url, exc)
        return None
    except Exception as exc:
        log.debug("pdf parse unexpected error for %s: %s", url, exc)
        return None

    def _get(key: str) -> str:
        v = info.get(key)
        if v is None:
            return ""
        return str(v).strip()

    text_for_paths = _safe_pdf_text(data)

    return DocumentMetadata(
        url=url,
        format="pdf",
        author=_get("/Author"),
        last_author="",
        creator=_get("/Creator"),
        title=_get("/Title"),
        subject=_get("/Subject"),
        keywords=_get("/Keywords"),
        company="",
        software=_get("/Producer"),
        created=_get("/CreationDate"),
        modified=_get("/ModDate"),
        network_paths=_extract_network_paths(text_for_paths),
        raw={k.lstrip("/"): str(v) for k, v in info.items() if v is not None},
    )


def _safe_pdf_text(data: bytes) -> str:
    """Best-effort raw-bytes scan for UNC paths. We deliberately avoid
    full text extraction (slow, lossy) — UNC paths show up verbatim in
    the byte stream of any modern PDF that contains them.
    """
    try:
        return data.decode("latin-1", "ignore")
    except Exception:
        return ""


# ── Public entry points ─────────────────────────────────────────────


def _parse(
    data: bytes,
    *,
    url: str,
    detection: filetype.FileTypeDetection | None = None,
) -> DocumentMetadata | None:
    fmt = filetype.supported_document_format(detection) or _detect_format(data, url=url)
    parsed: DocumentMetadata | None = None
    if fmt == "pdf":
        parsed = _parse_pdf(data, url=url)
    elif fmt in ("docx", "xlsx", "pptx"):
        parsed = _parse_docx(data, url=url)
    if parsed is not None:
        return _with_detection(parsed, detection)
    return _spoof_report(url=url, detection=detection)


async def extract_from_url(
    client: HTTPClient,
    url: str,
    *,
    max_size: int = _DEFAULT_MAX_SIZE,
) -> DocumentMetadata | None:
    """Fetch ``url`` and return parsed metadata, or ``None`` on failure.

    ``max_size`` caps the response body so a single large document
    cannot starve a batch run.
    """
    if not url:
        return None
    status, data, _ = await client.get_bytes(url)
    if status != 200 or not data:
        return None
    if len(data) > max_size:
        log.debug(
            "doc_metadata: %s exceeds max_size (%d > %d)", url, len(data), max_size
        )
        return None
    detection = filetype.identify_bytes(data)
    return _parse(data, url=url, detection=detection)


async def extract_batch(
    client: HTTPClient,
    urls: list[str],
    *,
    max_size: int = _DEFAULT_MAX_SIZE,
) -> list[DocumentMetadata]:
    """Run ``extract_from_url`` over many URLs concurrently.

    Failures are silently dropped; the caller gets only the documents
    that actually parsed.
    """
    if not urls:
        return []
    coros = [extract_from_url(client, u, max_size=max_size) for u in urls]
    results = await asyncio.gather(*coros, return_exceptions=True)
    out: list[DocumentMetadata] = []
    for entry in results:
        if isinstance(entry, BaseException):
            log.debug("doc_metadata batch entry failed: %s", entry)
            continue
        if entry is not None:
            out.append(entry)
    return out
