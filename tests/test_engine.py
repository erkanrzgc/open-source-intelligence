"""Tests for core/engine.py — exercise pure helpers and integration phases."""


import pytest
from aioresponses import aioresponses

from core import engine as engine_mod
from core.config import ScanConfig
from core.engine import (
    _check_platform,
    _extract_avatar_urls,
    _phase_recursive,
    _phase_smart_search,
    _select_platforms,
    _status_from_http,
    run_scan,
)
from core.models import PlatformResult, ScanResult
from modules.platforms import PLATFORMS, Platform


class TestStatusFromHttp:
    def test_timeout(self):
        assert _status_from_http(0, False) == "timeout"

    def test_error(self):
        assert _status_from_http(-1, False) == "error"

    def test_blocked(self):
        assert _status_from_http(429, False) == "blocked"

    def test_login_required(self):
        assert _status_from_http(401, False) == "login_required"
        assert _status_from_http(403, False) == "login_required"

    def test_found(self):
        assert _status_from_http(200, True) == "found"

    def test_not_found(self):
        assert _status_from_http(200, False) == "not_found"


class TestSelectPlatforms:
    def test_all_when_none(self):
        from core import engine as eng
        eng._VERIFIED_CACHE = None
        result = _select_platforms(None)
        assert len(result) > 0
        assert len(result) < len(PLATFORMS)

    def test_all_when_explicit(self):
        result = _select_platforms(("__all__",))
        assert len(result) == len(PLATFORMS)

    def test_verified_when_requested(self):
        from core import engine as eng
        eng._VERIFIED_CACHE = None
        result = _select_platforms(("__verified__",))
        assert len(result) > 0
        assert len(result) < len(PLATFORMS)

    def test_filter_by_category(self):
        result = _select_platforms(("dev",))
        assert all(p.category == "dev" for p in result)
        assert len(result) > 0

    def test_multiple_categories(self):
        result = _select_platforms(("dev", "gaming"))
        cats = {p.category for p in result}
        assert cats == {"dev", "gaming"}


class TestExtractAvatarUrls:
    def test_empty(self):
        assert _extract_avatar_urls([]) == []

    def test_finds_avatar_url(self):
        p = PlatformResult(
            platform="gh",
            url="https://x",
            category="dev",
            exists=True,
            profile_data={"avatar_url": "https://cdn/a.jpg"},
        )
        result = _extract_avatar_urls([p])
        assert result == [("gh", "https://cdn/a.jpg")]

    def test_icon_img_fallback(self):
        p = PlatformResult(
            platform="reddit",
            url="https://x",
            category="social",
            exists=True,
            profile_data={"icon_img": "https://cdn/i.jpg"},
        )
        result = _extract_avatar_urls([p])
        assert result == [("reddit", "https://cdn/i.jpg")]

    def test_skips_non_http(self):
        p = PlatformResult(
            platform="gh",
            url="https://x",
            category="dev",
            exists=True,
            profile_data={"avatar_url": "not-a-url"},
        )
        assert _extract_avatar_urls([p]) == []

    def test_no_profile_data(self):
        p = PlatformResult(platform="gh", url="https://x", category="dev")
        assert _extract_avatar_urls([p]) == []


class _HTMLClient:
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body

    async def get(self, _url, _headers=None):
        return self.status, self.body, 0.01


@pytest.mark.asyncio
async def test_check_platform_marks_login_wall_as_not_found():
    body = """
    <html><head><title>alice profile</title></head>
    <body>You must log in to view this profile.</body></html>
    """
    platform = Platform(
        name="LockedSite",
        url="https://locked.example/{username}",
        category="social",
        check_type="status",
    )

    result = await _check_platform(_HTMLClient(200, body), ScanConfig(username="alice"), platform)

    assert result.exists is False
    assert result.status == "login_required"
    assert result.fp_signals == ["login_required"]


def test_scan_result_payload_omits_not_found_platforms():
    result = ScanResult(username="alice")
    result.platforms = [
        PlatformResult(
            platform="GitHub",
            url="https://github.com/alice",
            category="dev",
            exists=True,
            status="found",
        ),
        PlatformResult(
            platform="Twitter",
            url="https://twitter.com/alice",
            category="social",
            exists=False,
            status="not_found",
        ),
        PlatformResult(
            platform="LockedSite",
            url="https://locked.example/alice",
            category="social",
            exists=False,
            status="login_required",
        ),
    ]

    payload = result.to_dict()

    assert payload["total_checked"] == 3
    assert payload["found_count"] == 1
    assert [p["platform"] for p in payload["platforms"]] == ["GitHub"]


@pytest.mark.asyncio
async def test_run_scan_minimal_category_filter():
    """Run a restricted scan to keep mocking manageable."""
    cfg = ScanConfig(
        username="alice",
        deep=False,
        smart=False,
        email=False,
        web=False,
        whois=False,
        breach=False,
        photo=False,
        dns=False,
        subdomain=False,
        categories=("dev",),
    )
    dev_platforms = [p for p in PLATFORMS if p.category == "dev"]

    with aioresponses() as m:
        for p in dev_platforms:
            url = p.url.replace("{username}", "alice")
            m.get(url, status=404, repeat=True)

        result = await run_scan(cfg)

    assert result.username == "alice"
    assert result.found_count == 0
    assert result.total_checked == len(dev_platforms)
    assert result.scan_time >= 0


@pytest.mark.asyncio
async def test_run_scan_with_deep_scrape():
    cfg = ScanConfig(
        username="alice",
        deep=True,
        categories=("dev",),
    )
    dev_platforms = [p for p in PLATFORMS if p.category == "dev"]

    with aioresponses() as m:
        # Register the deep-scraper API mock FIRST so it takes priority over
        # any platform check that happens to hit the same URL (e.g. the WMN
        # "GitHub (User)" entry which targets api.github.com/users/{u}).
        m.get(
            "https://api.github.com/users/alice",
            status=200,
            payload={"name": "Alice", "location": "TR"},
            repeat=True,
        )
        for p in dev_platforms:
            url = p.url.replace("{username}", "alice")
            if url == "https://api.github.com/users/alice":
                continue  # already mocked above
            if p.name == "GitHub":
                m.get(url, status=200, body="", repeat=True)
            else:
                m.get(url, status=404, repeat=True)

        result = await run_scan(cfg)

    gh_result = next((r for r in result.platforms if r.platform == "GitHub"), None)
    assert gh_result is not None
    assert gh_result.exists is True
    assert gh_result.profile_data.get("name") == "Alice"


@pytest.mark.asyncio
async def test_run_scan_email_without_hibp_skips_breach(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    cfg = ScanConfig(
        username="alice",
        deep=False,
        email=True,
        breach=True,
        categories=("dev",),
    )
    dev_platforms = [p for p in PLATFORMS if p.category == "dev"]

    with aioresponses() as m:
        for p in dev_platforms:
            url = p.url.replace("{username}", "alice")
            m.get(url, status=404, repeat=True)
        # email discovery will call gravatar for every candidate
        import re as _re
        m.get(_re.compile(r"https://en\.gravatar\.com/.*\.json"), status=404, repeat=True)

        result = await run_scan(cfg)

    assert result.emails == []


@pytest.mark.asyncio
async def test_phase_smart_search_checks_variations_with_scan_config(monkeypatch):
    cfg = ScanConfig(username="alice1", smart=True, fp_threshold=0.0)
    platforms = [
        Platform(
            name="GitHub",
            url="https://fake.test/{username}",
            category="dev",
            check_type="status",
        ),
    ]
    platform_results = [
        PlatformResult(
            platform="GitHub",
            url="https://fake.test/alice1",
            category="dev",
            exists=False,
        ),
    ]
    result = ScanResult(username="alice_1")

    checked: list[str] = []

    async def fake_check_platform(client, cfg_arg, platform):
        checked.append(cfg_arg.username)
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", cfg_arg.username),
            category=platform.category,
            exists=cfg_arg.username == "alice",
            confidence=1.0,
            status="found",
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check_platform)

    await _phase_smart_search(
        client=None,
        cfg=cfg,
        platforms=platforms,
        platform_results=platform_results,
        result=result,
    )

    assert "alice" in checked  # stripped trailing digits
    assert any(r.status == "found (variation)" for r in result.platforms)


@pytest.mark.asyncio
async def test_phase_recursive_pivots_on_discovered_username(monkeypatch):
    """The recursive phase should pick up usernames from profile_data and
    discovered_usernames, re-run the platform sweep, and tag hits with the
    pivoted handle so they stay distinguishable from the primary sweep."""
    cfg = ScanConfig(username="alice", recursive=True, recursive_depth=1, fp_threshold=0.0)
    platforms = [
        Platform(name="FakeNet", url="https://fake.test/{username}", category="social",
                 check_type="status"),
    ]
    seed = PlatformResult(
        platform="GitHub", url="https://gh/alice", category="dev",
        exists=True, profile_data={"login": "alice_alt"},
    )
    result = ScanResult(username="alice")
    result.platforms = [seed]
    result.discovered_usernames = ["alice_other"]

    calls: list[str] = []

    async def fake_check_platform(client, cfg_arg, platform):
        calls.append(cfg_arg.username)
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", cfg_arg.username),
            category=platform.category,
            exists=True,
            confidence=1.0,
            status="found",
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check_platform)

    await _phase_recursive(client=None, cfg=cfg, platforms=platforms, result=result)

    assert set(calls) == {"alice_alt", "alice_other"}
    pivot_hits = [r for r in result.platforms if r.status.startswith("found (pivot:")]
    assert len(pivot_hits) == 2
    assert {r.status for r in pivot_hits} == {
        "found (pivot:alice_alt)",
        "found (pivot:alice_other)",
    }


@pytest.mark.asyncio
async def test_phase_recursive_disabled_is_noop(monkeypatch):
    cfg = ScanConfig(username="alice", recursive=False)
    result = ScanResult(username="alice")
    result.discovered_usernames = ["bob"]

    called = False

    async def boom(*args, **kwargs):
        nonlocal called
        called = True
        return PlatformResult(platform="x", url="y", category="z")

    monkeypatch.setattr(engine_mod, "_check_platform", boom)
    await _phase_recursive(client=None, cfg=cfg, platforms=[], result=result)

    assert called is False


@pytest.mark.asyncio
async def test_phase_recon_noop_without_domain():
    from core.engine import _phase_recon

    cfg = ScanConfig(username="u")  # redteam_domain=None
    result = ScanResult(username="u")
    await _phase_recon(client=None, cfg=cfg, result=result)
    assert result.email_candidates == []
    assert result.github_committers == []
    assert result.recon_subdomains == []


@pytest.mark.asyncio
async def test_phase_recon_populates_all_three_slots(monkeypatch, tmp_path):
    from core.engine import _phase_recon
    from modules.recon.models import (
        EmailCandidate,
        GithubCommitter,
        ReconSubdomain,
    )

    names_path = tmp_path / "names.txt"
    names_path.write_text("Ada Byron\n")

    async def fake_enum(_client, _domain):
        return ["api.acme.com"]

    async def fake_scan_org(_client, _org, *, max_repos=30, commits_per_repo=30):
        return [GithubCommitter(email="ada@acme.com", name="Ada", repo="acme/x")]

    async def fake_enrich(_client, _domain, *, existing=None):
        hosts = [*list(existing or []), "vpn.acme.com"]
        return [ReconSubdomain(host=h, source="dns_lookup") for h in hosts]

    async def fake_secret_scan(_client, *, org=None, domain=None, repos=None,
                               max_queries=20, max_hits_per_query=30):
        return []

    import modules.dns_lookup as dns_lookup
    from modules.recon import email_patterns, github_org, github_secrets, subdomains_extra

    monkeypatch.setattr(dns_lookup, "enumerate_subdomains", fake_enum)
    monkeypatch.setattr(github_org, "scan_org", fake_scan_org)
    monkeypatch.setattr(github_secrets, "scan_target", fake_secret_scan)
    monkeypatch.setattr(subdomains_extra, "enrich_subdomains", fake_enrich)
    monkeypatch.setattr(
        email_patterns,
        "generate_bulk",
        lambda names, domain: [
            EmailCandidate(
                email="a.b@acme.com",
                first_name="ada",
                last_name="byron",
                pattern="{first}.{last}",
                domain=domain,
            )
        ]
        if names
        else [],
    )

    cfg = ScanConfig(
        username="u",
        redteam_domain="acme.com",
        redteam_names_file=str(names_path),
        redteam_github_org="acme",
    )
    result = ScanResult(username="u")
    await _phase_recon(client=None, cfg=cfg, result=result)

    assert len(result.email_candidates) == 1
    assert len(result.github_committers) == 1
    assert len(result.recon_subdomains) == 2
    assert result.recon_subdomains[0]["host"] == "api.acme.com"

    payload = result.to_dict()
    assert "email_candidates" in payload
    assert "github_committers" in payload
    assert "recon_subdomains" in payload
    assert payload["email_candidates"][0]["email"] == "a.b@acme.com"


@pytest.mark.asyncio
async def test_phase_recon_populates_leaked_secrets(monkeypatch):
    from core.engine import _phase_recon
    from modules.recon.models import LeakedSecret

    async def fake_enum(_client, _domain):
        return []

    async def fake_scan_org(_client, _org, *, max_repos=30, commits_per_repo=30):
        return []

    async def fake_enrich(_client, _domain, *, existing=None):
        return []

    async def fake_secret_scan(_client, *, org=None, domain=None, repos=None,
                               max_queries=20, max_hits_per_query=30):
        assert org == "acme"
        assert domain == "acme.com"
        return [
            LeakedSecret(
                rule_id="aws_access_key",
                value="AKIAIOSFODNN7XAAAAAA",
                repo="acme/api",
                file_path="src/config.py",
                url="https://github.com/acme/api/blob/main/src/config.py",
                snippet="KEY=AKIA...",
            )
        ]

    import modules.dns_lookup as dns_lookup
    from modules.recon import email_patterns, github_org, github_secrets, subdomains_extra

    monkeypatch.setattr(dns_lookup, "enumerate_subdomains", fake_enum)
    monkeypatch.setattr(github_org, "scan_org", fake_scan_org)
    monkeypatch.setattr(github_secrets, "scan_target", fake_secret_scan)
    monkeypatch.setattr(subdomains_extra, "enrich_subdomains", fake_enrich)
    monkeypatch.setattr(email_patterns, "generate_bulk", lambda *a, **k: [])

    cfg = ScanConfig(
        username="u",
        redteam_domain="acme.com",
        redteam_github_org="acme",
    )
    result = ScanResult(username="u")
    await _phase_recon(client=None, cfg=cfg, result=result)

    assert len(result.leaked_secrets) == 1
    assert result.leaked_secrets[0]["rule_id"] == "aws_access_key"
    assert result.leaked_secrets[0]["repo"] == "acme/api"

    payload = result.to_dict()
    assert "leaked_secrets" in payload
    assert payload["leaked_secrets"][0]["value"] == "AKIAIOSFODNN7XAAAAAA"


@pytest.mark.asyncio
async def test_phase_gitleaks_appends_local_secret_findings(monkeypatch):
    from core.engine import _phase_gitleaks
    from modules.recon import gitleaks
    from modules.recon.models import LeakedSecret

    async def fake_scan_path(path, *, no_git=False, timeout=120):
        assert path == "/tmp/repo"
        assert no_git is True
        assert timeout == 9
        return [
            LeakedSecret(
                rule_id="generic-api-key",
                value="dummy-secret-value",
                repo="repo",
                file_path="src/config.py",
                url="file:///tmp/repo/src/config.py",
                metadata={"source": "gitleaks"},
            )
        ]

    monkeypatch.setattr(gitleaks, "scan_path", fake_scan_path)

    cfg = ScanConfig(
        username="u",
        gitleaks_paths=("/tmp/repo",),
        gitleaks_no_git=True,
        gitleaks_timeout=9,
    )
    result = ScanResult(username="u")
    result.leaked_secrets = [{"rule_id": "existing", "value": "already-there"}]

    await _phase_gitleaks(cfg, result)

    assert len(result.leaked_secrets) == 2
    assert result.leaked_secrets[1]["rule_id"] == "generic-api-key"
    assert result.leaked_secrets[1]["metadata"]["source"] == "gitleaks"


@pytest.mark.asyncio
async def test_phase_exif_processes_image_urls(monkeypatch):
    from core.engine import _phase_exif
    from modules.analysis.models import ExifReport

    async def fake_extract(_client, url):
        return ExifReport(
            source=url,
            gps_lat=48.85833,
            gps_lon=2.29444,
            camera_model="Pixel 7",
            taken_at="2023:11:20 09:15:00",
        )

    from modules.analysis import exif

    monkeypatch.setattr(exif, "extract_from_url", fake_extract)

    cfg = ScanConfig(
        username="u",
        exif_image_urls=(
            "https://cdn.example.com/a.jpg",
            "https://cdn.example.com/b.jpg",
        ),
    )
    result = ScanResult(username="u")
    await _phase_exif(client=None, cfg=cfg, result=result)

    assert len(result.exif_reports) == 2
    assert result.exif_reports[0]["camera_model"] == "Pixel 7"
    assert result.exif_reports[0]["gps_lat"] == 48.85833

    payload = result.to_dict()
    assert "exif_reports" in payload
    assert payload["exif_reports"][1]["source"].endswith("b.jpg")


@pytest.mark.asyncio
async def test_phase_exif_noop_without_urls() -> None:
    from core.engine import _phase_exif

    cfg = ScanConfig(username="u")
    result = ScanResult(username="u")
    await _phase_exif(client=None, cfg=cfg, result=result)
    assert result.exif_reports == []


# ── _phase_wigle ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_wigle_noop_without_bssid_or_ssid() -> None:
    from core.engine import _phase_wigle

    cfg = ScanConfig(username="u")  # no bssid, no ssid
    result = ScanResult(username="u")
    await _phase_wigle(client=None, cfg=cfg, result=result)
    assert result.passive_hits == []


@pytest.mark.asyncio
async def test_phase_wigle_appends_to_passive_hits(monkeypatch) -> None:
    from core.engine import _phase_wigle
    from modules.passive.models import PassiveHit

    async def fake_search(_client, *, bssid=None, ssid=None, limit=10):
        return [
            PassiveHit(
                source="wigle",
                kind="bssid",
                value=bssid or "",
                title="ACME-WiFi",
                metadata={"lat": 40.0, "lon": -74.0},
            )
        ]

    from modules.passive import wigle

    monkeypatch.setattr(wigle, "search", fake_search)

    # Pre-existing passive_hit must be preserved
    pre = PassiveHit(source="shodan", kind="host", value="1.2.3.4")
    cfg = ScanConfig(username="u", bssid="AA:BB:CC:DD:EE:FF")
    result = ScanResult(username="u", passive_hits=[pre])
    await _phase_wigle(client=None, cfg=cfg, result=result)

    assert len(result.passive_hits) == 2
    sources = {h.source for h in result.passive_hits}
    assert sources == {"shodan", "wigle"}


# ── _phase_company ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_company_noop_without_query() -> None:
    from core.engine import _phase_company

    cfg = ScanConfig(username="u")
    result = ScanResult(username="u")
    await _phase_company(client=None, cfg=cfg, result=result)
    assert result.company_records == []


@pytest.mark.asyncio
async def test_phase_company_populates_records(monkeypatch) -> None:
    from core.engine import _phase_company
    from modules.recon.models import CompanyOfficer, CompanyRecord

    async def fake_search_with_officers(_client, query, *, limit=5):
        return [
            CompanyRecord(
                name="ACME CORP",
                jurisdiction_code="us_de",
                company_number="12345",
                officers=(CompanyOfficer(name="Alice Doe", position="director"),),
            )
        ]

    from modules.passive import opencorporates

    monkeypatch.setattr(
        opencorporates, "search_with_officers", fake_search_with_officers
    )

    cfg = ScanConfig(username="u", company_query="Acme")
    result = ScanResult(username="u")
    await _phase_company(client=None, cfg=cfg, result=result)

    assert len(result.company_records) == 1
    assert result.company_records[0]["name"] == "ACME CORP"
    assert result.company_records[0]["officers"][0]["name"] == "Alice Doe"

    payload = result.to_dict()
    assert "company_records" in payload
    assert payload["company_records"][0]["jurisdiction_code"] == "us_de"


# ── _phase_doc_metadata ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_doc_metadata_noop_without_urls() -> None:
    from core.engine import _phase_doc_metadata

    cfg = ScanConfig(username="u")
    result = ScanResult(username="u")
    await _phase_doc_metadata(client=None, cfg=cfg, result=result)
    assert result.document_metadata == []


@pytest.mark.asyncio
async def test_phase_doc_metadata_extracts_batch(monkeypatch) -> None:
    from core.engine import _phase_doc_metadata
    from modules.recon.models import DocumentMetadata

    async def fake_extract_batch(_client, urls, *, max_size=10 * 1024 * 1024):
        return [
            DocumentMetadata(
                url=u,
                format="pdf",
                author=f"author-{i}",
            )
            for i, u in enumerate(urls)
        ]

    from modules.recon import doc_metadata

    monkeypatch.setattr(doc_metadata, "extract_batch", fake_extract_batch)

    cfg = ScanConfig(
        username="u",
        harvest_doc_urls=(
            "https://t.example/a.pdf",
            "https://t.example/b.pdf",
        ),
    )
    result = ScanResult(username="u")
    await _phase_doc_metadata(client=None, cfg=cfg, result=result)

    assert len(result.document_metadata) == 2
    assert result.document_metadata[0]["author"] == "author-0"

    payload = result.to_dict()
    assert "document_metadata" in payload
    assert payload["document_metadata"][1]["url"].endswith("b.pdf")


# ── _phase_intelx ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_intelx_noop_without_term() -> None:
    from core.engine import _phase_intelx

    cfg = ScanConfig(username="u")
    result = ScanResult(username="u")
    await _phase_intelx(client=None, cfg=cfg, result=result)
    assert result.passive_hits == []


@pytest.mark.asyncio
async def test_phase_intelx_appends_to_passive_hits(monkeypatch) -> None:
    from core.engine import _phase_intelx
    from modules.passive.models import PassiveHit

    async def fake_search(_client, term, *, max_results=50):
        return [
            PassiveHit(
                source="intelx",
                kind="leak",
                value=f"paste-for-{term}",
                title="pastes.public",
                metadata={"size": 1024},
            )
        ]

    from modules.passive import intelx

    monkeypatch.setattr(intelx, "search", fake_search)

    pre = PassiveHit(source="shodan", kind="host", value="1.2.3.4")
    cfg = ScanConfig(username="u", intelx_term="acme.com", intelx_limit=10)
    result = ScanResult(username="u", passive_hits=[pre])
    await _phase_intelx(client=None, cfg=cfg, result=result)

    assert len(result.passive_hits) == 2
    sources = {h.source for h in result.passive_hits}
    assert sources == {"shodan", "intelx"}
