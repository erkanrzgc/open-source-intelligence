"""Tests for core/capabilities.py — capability discovery and scan warnings."""

from __future__ import annotations

from unittest.mock import patch

from core.capabilities import (
    _capability,
    _has_module,
    collect_capabilities,
    collect_scan_warnings,
)
from core.config import ScanConfig


def test_capability_helper_shapes():
    c = _capability(available=True, configured=True)
    assert c["available"] is True
    assert c["configured"] is True
    assert c["ready"] is True

    c2 = _capability(available=True, configured=False, reason="missing API key")
    assert c2["available"] is True
    assert c2["ready"] is False
    assert "missing API key" in c2.get("reason", "")


def test_has_module_builtin():
    assert _has_module("json") is True


def test_has_module_missing():
    assert _has_module("this_module_does_not_exist_xyz") is False


def test_has_module_invalid_name():
    assert _has_module("") is False


def test_collect_capabilities_returns_expected_shape():
    caps = collect_capabilities()
    assert len(caps) > 0
    for key, data in caps.items():
        assert "available" in data, f"{key} missing 'available'"
        assert "configured" in data, f"{key} missing 'configured'"
        assert "ready" in data, f"{key} missing 'ready'"


def test_collect_capabilities_has_core_keys():
    caps = collect_capabilities()
    assert "api" in caps
    assert "profile_extract" in caps
    assert "holehe" in caps


def test_collect_scan_warnings_no_flags_no_warnings():
    cfg = ScanConfig(
        username="test",
        deep=False, smart=False, email=False, web=False,
        whois=False, breach=False, photo=False,
        dns=False, subdomain=False,
        holehe=False, ghunt=False, toutatis=False,
        gitleaks_paths=(), exif_image_urls=(),
    )
    caps = collect_capabilities()
    warnings = collect_scan_warnings(cfg, capabilities=caps)
    assert warnings == []


def test_collect_scan_warnings_breach_no_api_key():
    with patch.dict("os.environ", {}, clear=True):
        cfg = ScanConfig(
            username="test",
            breach=True,
            deep=False, smart=False, email=False, web=False,
            whois=False, photo=False, dns=False, subdomain=False,
            holehe=False, ghunt=False, toutatis=False,
            gitleaks_paths=(), exif_image_urls=(),
        )
        warnings = collect_scan_warnings(cfg, capabilities=collect_capabilities())
        assert any("HIBP" in w or "breach" in w.lower() for w in warnings)


def test_collect_scan_warnings_disabled_flags_no_false_positives():
    cfg = ScanConfig(
        username="test",
        breach=True,
        holehe=True,
        deep=False, smart=False, email=False, web=False,
        whois=False, photo=False, dns=False, subdomain=False,
        ghunt=False, toutatis=False,
        gitleaks_paths=(), exif_image_urls=(),
    )
    caps = collect_capabilities()
    warnings = collect_scan_warnings(cfg, capabilities=caps)
    assert not any("toutatis" in w.lower() for w in warnings)
    assert not any("ghunt" in w.lower() for w in warnings)
    assert not any("photo" in w.lower() for w in warnings)
