"""Deterministic HTML export coverage for escaping and section parity."""

from core.models import (
    CrossReferenceResult,
    EmailResult,
    IdentityCandidate,
    PhotoMatch,
    PlatformResult,
    ScanResult,
)
from core.reporter import export_html


def test_export_html_escapes_username_and_renders_sections(tmp_path):
    result = ScanResult(
        username="<script>alert(1)</script>",
        platforms=[
            PlatformResult(
                platform="GitHub",
                url="https://github.com/alice",
                category="dev",
                exists=True,
                status="found",
                response_time=0.42,
                profile_data={"name": "Alice", "location": "Istanbul"},
            )
        ],
        emails=[
            EmailResult(
                email="alice@example.com",
                source="gravatar",
                verified=True,
                gravatar=True,
                breach_count=2,
            )
        ],
        web_presence=[
            {"type": "wayback", "original_url": "https://github.com/alice", "url": "https://web.archive.org/example"}
        ],
        whois_records=[
            {
                "domain": "alice.dev",
                "registrar": "Example Registrar",
                "creation_date": "2024-01-01",
                "expiration_date": "2027-01-01",
                "org": "Alice Labs",
            }
        ],
        dns_records={"alice.dev": {"A": ["1.2.3.4"], "MX": ["mail.alice.dev"]}},
        subdomains=["api.alice.dev", "www.alice.dev"],
        variations_checked=["alice_", "realalice"],
        discovered_usernames=["alice_dev"],
        identity_candidates=[
            IdentityCandidate(
                username="alice_dev",
                handle_similarity=0.9,
                verdict="possible_same",
                score=0.46,
                evidence=[{"kind": "display_name", "detail": "exact display name"}],
                profiles=[
                    PlatformResult(
                        platform="GitLab",
                        url="https://gitlab.com/alice_dev",
                        category="dev",
                        exists=True,
                    )
                ],
            )
        ],
        photo_matches=[
            PhotoMatch(
                platform_a="GitHub",
                platform_b="Twitter / X",
                similarity=0.91,
                method="phash",
            )
        ],
        scan_time=1.23,
    )
    result.cross_reference = CrossReferenceResult(
        confidence=88.0,
        matched_names=["alice -> GitHub, Twitter / X"],
        matched_locations=["istanbul -> GitHub"],
        matched_photos=["GitHub ↔ Twitter / X (91%, phash)"],
        notes=["1 profil fotografi eslesti"],
    )

    report = tmp_path / "report.html"
    export_html(result, str(report))
    html = report.read_text(encoding="utf-8")

    assert "<title>Open Source Intelligence" in html
    assert "<h1>OPEN SOURCE INTELLIGENCE</h1>" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    for section in (
        "Investigator Brief",
        "Discovered Emails",
        "Profile Photo Matches",
        "Web Presence",
        "WHOIS Records",
        "DNS Records",
        "Subdomains",
        "Smart Search",
        "Confidence Score",
        "Similar Usernames / Identity Candidates",
    ):
        assert section in html
    assert "Risk Flags" in html
    assert "Next Steps" in html
    assert "Priority" in html
    assert "Confidence" in html
    assert "Recommended Actions By Severity" in html
    assert "alice_dev" in html
    assert "possible_same" in html
