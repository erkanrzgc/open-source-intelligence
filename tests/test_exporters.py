"""Tests for the Sprint 6 reporting exporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.models import EmailResult, PlatformResult, ScanResult
from core.reporter import (
    build_misp_event,
    build_stix_bundle,
    export_misp,
    export_obsidian,
    export_stix,
)
from core.reporter.pdf_export import export_pdf
from core.reporter.pdf_export import is_available as pdf_available
from modules.crypto.models import CryptoIntel
from modules.history.models import HistoricalUsername
from modules.phone.models import PhoneIntel


def _result() -> ScanResult:
    r = ScanResult(username="alice")
    r.platforms = [
        PlatformResult(
            platform="GitHub",
            url="https://github.com/alice",
            category="dev",
            exists=True,
            confidence=0.9,
            status="found",
        ),
        PlatformResult(
            platform="Twitter",
            url="https://twitter.com/alice",
            category="social",
            exists=False,
            status="not_found",
        ),
    ]
    r.emails = [
        EmailResult(
            email="alice@example.com",
            source="gravatar",
            verified=True,
            breaches=["LinkedIn2012", "Adobe2013"],
        )
    ]
    r.phone_intel = [
        PhoneIntel(
            raw="+14155552671",
            e164="+14155552671",
            country_code=1,
            region="US",
            country_name="United States",
            carrier="AT&T",
            line_type="mobile",
            timezones=("America/Los_Angeles",),
            valid=True,
            sources=("phonenumbers",),
        )
    ]
    r.crypto_intel = [
        CryptoIntel(
            address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            chain="eth",
            balance=1.5,
            tx_count=10,
            source="etherscan",
        )
    ]
    r.historical_usernames = [
        HistoricalUsername(
            username="alice_old",
            platform="twitter.com",
            first_seen="20180101",
            last_seen="20190101",
            snapshot_count=5,
        )
    ]
    return r


# ── MISP ────────────────────────────────────────────────────────────


def test_build_misp_event_has_expected_attributes() -> None:
    event = build_misp_event(_result())
    assert event["Event"]["info"].startswith("OSINT sweep")
    attrs = event["Event"]["Attribute"]
    types = {a["type"] for a in attrs}
    assert "url" in types
    assert "email-src" in types
    assert "phone-number" in types
    assert "eth" in types
    # GitHub profile must be included; Twitter (exists=False) must not
    urls = [a["value"] for a in attrs if a["type"] == "url"]
    assert "https://github.com/alice" in urls
    assert "https://twitter.com/alice" not in urls


def test_export_misp_writes_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "event.misp.json"
    export_misp(_result(), str(path))
    data = json.loads(path.read_text())
    assert "Event" in data
    assert data["Event"]["Attribute"]


# ── STIX ────────────────────────────────────────────────────────────


def test_build_stix_bundle_has_identity_root() -> None:
    bundle = build_stix_bundle(_result())
    assert bundle["type"] == "bundle"
    identities = [o for o in bundle["objects"] if o["type"] == "identity"]
    assert len(identities) == 1
    assert identities[0]["name"] == "alice"


def test_build_stix_bundle_is_deterministic() -> None:
    a = build_stix_bundle(_result())
    b = build_stix_bundle(_result())
    # Identity UUIDs are deterministic (uuid5), so identity IDs match.
    a_ids = {o["id"] for o in a["objects"] if o["type"] != "relationship"}
    b_ids = {o["id"] for o in b["objects"] if o["type"] != "relationship"}
    assert a_ids == b_ids


def test_build_stix_bundle_includes_crypto_wallet() -> None:
    bundle = build_stix_bundle(_result())
    wallets = [o for o in bundle["objects"] if o["type"] == "cryptocurrency-wallet"]
    assert len(wallets) == 1
    assert wallets[0]["value"].startswith("0x")


def test_export_stix_writes_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "bundle.stix.json"
    export_stix(_result(), str(path))
    data = json.loads(path.read_text())
    assert data["type"] == "bundle"
    assert data["objects"]


# ── Obsidian ────────────────────────────────────────────────────────


def test_export_obsidian_creates_vault_layout(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    written = export_obsidian(_result(), str(vault))

    # MOC + identity + one file per entity
    assert "MOC.md" in written
    assert "alice.md" in written
    assert any(f.startswith("profiles/") for f in written)
    assert any(f.startswith("emails/") for f in written)
    assert any(f.startswith("phones/") for f in written)
    assert any(f.startswith("crypto/") for f in written)
    assert any(f.startswith("aliases/") for f in written)

    moc = (vault / "MOC.md").read_text()
    assert "[[alice]]" in moc  # wikilink into identity note
    assert "alice" in moc

    identity = (vault / "alice.md").read_text()
    assert "[[profiles/GitHub]]" in identity
    # Excluded profile must not be linked
    assert "[[profiles/Twitter]]" not in identity


def test_export_obsidian_sanitises_bad_filename_chars(tmp_path: Path) -> None:
    r = ScanResult(username="alice")
    r.emails = [EmailResult(email="foo/bar@example.com", source="s")]
    export_obsidian(r, str(tmp_path / "v"))
    # The slash must have been stripped
    assert list((tmp_path / "v" / "emails").iterdir())


# ── PDF (reportlab-gated) ───────────────────────────────────────────


def test_pdf_export_raises_cleanly_without_reportlab(tmp_path: Path) -> None:
    if pdf_available():
        pytest.skip("reportlab installed — cannot test missing-dep path")
    with pytest.raises(RuntimeError, match="reportlab"):
        export_pdf(_result(), str(tmp_path / "out.pdf"))
