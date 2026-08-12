"""Shared dataclasses for the red-team recon package.

Each output type is a frozen dataclass with a ``to_dict`` so the reporter
can serialize it uniformly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EmailCandidate:
    """A generated email guess for an employee name.

    ``pattern`` is the template key that produced it
    (e.g. ``first.last``), useful when the caller wants to rank by how
    common a pattern is inside the target org.
    """

    email: str
    first_name: str
    last_name: str
    pattern: str
    domain: str

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "pattern": self.pattern,
            "domain": self.domain,
        }


@dataclass(frozen=True)
class GithubCommitter:
    """A committer identity pulled from a public GitHub org.

    ``repo`` is the ``owner/name`` slug the email was first seen in,
    ``commits_seen`` counts appearances across the whole sweep.
    """

    email: str
    name: str
    login: str = ""
    repo: str = ""
    commits_seen: int = 1
    is_noreply: bool = False

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "name": self.name,
            "login": self.login,
            "repo": self.repo,
            "commits_seen": self.commits_seen,
            "is_noreply": self.is_noreply,
        }


@dataclass(frozen=True)
class ReconSubdomain:
    """Subdomain hit with source attribution for ranking/dedup."""

    host: str
    source: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "source": self.source,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class CompanyOfficer:
    """One officer/director row attached to a CompanyRecord.

    OpenCorporates exposes the officer's display name, role title
    (``director`` / ``secretary`` / ``CEO``…), and tenure dates.
    These rows are the highest-value pivot back into the people-side
    OSINT pipeline: every officer name → email_patterns → SE arsenal.
    """

    name: str
    position: str = ""
    start_date: str = ""
    end_date: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "position": self.position,
            "start_date": self.start_date,
            "end_date": self.end_date,
        }


@dataclass(frozen=True)
class CompanyRecord:
    """A corporate registry entry from OpenCorporates.

    Combines the public-search payload (name, jurisdiction, number,
    address, status, url) with the per-company officer/director list
    when ``officers`` is populated. ``url`` always points to the
    OpenCorporates page for human verification — corporate registry
    data is high-stakes, never act on it without spot-checking the
    source.
    """

    name: str
    jurisdiction_code: str
    company_number: str
    incorporation_date: str = ""
    company_type: str = ""
    registered_address: str = ""
    status: str = ""
    url: str = ""
    officers: tuple[CompanyOfficer, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "jurisdiction_code": self.jurisdiction_code,
            "company_number": self.company_number,
            "incorporation_date": self.incorporation_date,
            "company_type": self.company_type,
            "registered_address": self.registered_address,
            "status": self.status,
            "url": self.url,
            "officers": [o.to_dict() for o in self.officers],
        }


@dataclass(frozen=True)
class DocumentMetadata:
    """Metadata extracted from a public document (PDF / DOCX / XLSX).

    Public corporate documents routinely leak the author's full name,
    domain login, internal share paths, and the editing software used.
    These are direct inputs to a SE pretext: knowing that ``acme.local``
    is the AD domain or that ``\\\\acme-fs01\\reports`` is a real share
    is more believable than any guess.

    ``network_paths`` collects UNC / SMB paths discovered anywhere in
    the document (typical sources: relationship XML in OOXML files, or
    raw text in PDF). ``raw`` keeps the unparsed key/value blob so
    downstream code can mine fields we did not normalize.
    """

    url: str
    format: str  # "pdf" | "docx" | "xlsx" | "pptx"
    author: str = ""
    last_author: str = ""
    creator: str = ""
    title: str = ""
    subject: str = ""
    keywords: str = ""
    company: str = ""
    software: str = ""
    created: str = ""
    modified: str = ""
    network_paths: tuple[str, ...] = ()
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "format": self.format,
            "author": self.author,
            "last_author": self.last_author,
            "creator": self.creator,
            "title": self.title,
            "subject": self.subject,
            "keywords": self.keywords,
            "company": self.company,
            "software": self.software,
            "created": self.created,
            "modified": self.modified,
            "network_paths": list(self.network_paths),
            "raw": dict(self.raw),
        }


@dataclass(frozen=True)
class CertificateRecord:
    """A Certificate Transparency log entry pulled from crt.sh.

    The subdomain enumerator already mines ``name_value`` from these
    records to discover hostnames. This richer view keeps the issuing
    CA, validity window, and CT entry timestamp so callers can pivot
    on the metadata itself: a recently-issued LE cert points at new
    infra coming online, a cert whose ``not_after`` has passed but
    whose hostname still resolves points at forgotten services, and
    tracking the dominant issuer per-org reveals procurement choices
    a defender would prefer to keep quiet.

    ``name_value`` keeps the full Subject-Alt-Name list (lower-cased,
    deduped) instead of collapsing to one host. ``url`` points at the
    crt.sh detail page so an analyst can verify the entry by hand.
    """

    common_name: str
    name_value: tuple[str, ...]
    issuer_name: str
    not_before: str
    not_after: str
    entry_timestamp: str
    serial_number: str
    crtsh_id: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "common_name": self.common_name,
            "name_value": list(self.name_value),
            "issuer_name": self.issuer_name,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "entry_timestamp": self.entry_timestamp,
            "serial_number": self.serial_number,
            "crtsh_id": self.crtsh_id,
            "url": self.url,
        }


@dataclass(frozen=True)
class LeakedSecret:
    """A credential-shaped string surfaced from public source code.

    ``rule_id`` identifies which detector matched (``aws_access_key``,
    ``github_pat``, etc.). ``value`` is the raw match — the caller is
    expected to treat this data sensitively even though it came from a
    public source.

    ``url`` points to the GitHub blob view at the matching line so a
    human can verify the finding before acting on it.
    """

    rule_id: str
    value: str
    repo: str
    file_path: str
    url: str
    snippet: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        fingerprint = hashlib.sha256(self.value.encode("utf-8", "replace")).hexdigest()
        suffix = self.value[-4:] if len(self.value) >= 4 else ""
        safe_preview = f"[REDACTED …{suffix}]" if suffix else "[REDACTED]"
        safe_snippet = self.snippet.replace(self.value, "[REDACTED]") if self.value else self.snippet
        return {
            "rule_id": self.rule_id,
            "fingerprint": fingerprint,
            "safe_preview": safe_preview,
            "repo": self.repo,
            "file_path": self.file_path,
            "url": self.url,
            "snippet": safe_snippet,
            "metadata": dict(self.metadata),
        }
