"""Tests for the opportunistic profile extractor wrapper."""

from __future__ import annotations

import modules.profile_extract as profile_extract


def test_no_op_when_library_missing(monkeypatch):
    monkeypatch.setattr(profile_extract, "_AVAILABLE", False)
    assert profile_extract.extract_profile("<html>zuck</html>") == {}


def test_returns_empty_for_empty_html():
    assert profile_extract.extract_profile("") == {}


def test_library_available_flag_reflects_import():
    # is_available() is stable within a session; ensure the public API works.
    value = profile_extract.is_available()
    assert isinstance(value, bool)


def test_extract_tolerates_extractor_raising(monkeypatch):
    monkeypatch.setattr(profile_extract, "_AVAILABLE", True)

    def boom(_html: str):
        raise RuntimeError("bad scheme")

    monkeypatch.setattr(profile_extract, "_socid_extract", boom)
    assert profile_extract.extract_profile("<html/>") == {}


def test_extract_filters_empty_values(monkeypatch):
    monkeypatch.setattr(profile_extract, "_AVAILABLE", True)

    def fake(_html: str):
        return {"name": "Alice", "bio": "", "links": [], "email": "a@b.c", "meta": None}

    monkeypatch.setattr(profile_extract, "_socid_extract", fake)
    out = profile_extract.extract_profile("<html/>")
    assert out == {"name": "Alice", "email": "a@b.c"}
