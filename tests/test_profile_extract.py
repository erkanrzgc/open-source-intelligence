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


def test_extract_json_ld_person():
    html_doc = """
    <html>
    <head>
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Person",
            "name": "Jane Doe",
            "alternateName": "janedoe99",
            "description": "Security researcher",
            "image": "https://example.com/avatar.jpg",
            "email": "jane@example.com",
            "sameAs": [
                "https://github.com/janedoe99",
                "https://twitter.com/janedoe99"
            ]
        }
        </script>
    </head>
    <body></body>
    </html>
    """
    res = profile_extract.extract_profile(html_doc)
    assert res["name"] == "Jane Doe"
    assert res["username"] == "janedoe99"
    assert res["bio"] == "Security researcher"
    assert res["avatar_url"] == "https://example.com/avatar.jpg"
    assert res["email"] == "jane@example.com"
    assert res["github_username"] == "janedoe99"
    assert res["twitter_username"] == "janedoe99"


def test_extract_opengraph_and_outbound_links():
    html_doc = """
    <html>
    <head>
        <meta property="og:title" content="John Smith (@jsmith) / X">
        <meta property="og:description" content="AI engineer. Contact me on t.me/jsmith_dev or test@domain.org">
        <meta property="og:image" content="https://example.com/pic.png">
        <meta property="profile:username" content="jsmith">
    </head>
    <body>
        <a rel="me" href="https://github.com/jsmith-dev">GitHub</a>
        <a href="https://www.linkedin.com/in/john-smith-dev/">LinkedIn</a>
    </body>
    </html>
    """
    res = profile_extract.extract_profile(html_doc)
    assert res["name"] == "John Smith"
    assert res["username"] == "jsmith"
    assert res["avatar_url"] == "https://example.com/pic.png"
    assert res["github_username"] == "jsmith-dev"
    assert res["linkedin_username"] == "john-smith-dev"
    assert res["telegram_username"] == "jsmith_dev"
    assert res["email"] == "test@domain.org"


def test_extract_next_data_hydration():
    html_doc = """
    <html>
    <body>
        <script id="__NEXT_DATA__" type="application/json">
        {
            "props": {
                "pageProps": {
                    "user": {
                        "name": "Bob Builder",
                        "username": "bob_b",
                        "bio": "Building things",
                        "avatarUrl": "https://example.com/bob.jpg",
                        "email": "bob@builder.com"
                    }
                }
            }
        }
        </script>
    </body>
    </html>
    """
    res = profile_extract.extract_profile(html_doc)
    assert res["name"] == "Bob Builder"
    assert res["username"] == "bob_b"
    assert res["bio"] == "Building things"
    assert res["avatar_url"] == "https://example.com/bob.jpg"
    assert res["email"] == "bob@builder.com"

