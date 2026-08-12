"""Identity-first catalogue, alias probing and resolver acceptance tests."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from core import engine as engine_mod
from core.config import ScanConfig
from core.correlation import correlate_identity
from core.engine import _phase_registry, _phase_smart_search
from core.http_client import HTTPClient
from core.models import PlatformResult, ScanResult
from core.platform_loader import (
    ALIAS_PROBE_PLATFORMS,
    CORE_CATEGORY_QUOTAS,
    MANDATORY_CORE_PLATFORMS,
    catalogue_summary,
    load_platforms,
)
from core.smart_search import generate_candidates
from modules.deep_scrapers import scrape_hugging_face
from modules.platforms import Platform


def _payload(username: str, profile: dict | None = None) -> dict:
    return {
        "username": username,
        "platforms": (
            [{"platform": "Example", "profile_data": profile}] if profile else []
        ),
        "emails": [],
        "phone_intel": [],
    }


def test_catalogue_has_exact_core_distribution_and_bounded_full_scope() -> None:
    platforms = load_platforms()
    summary = catalogue_summary(platforms)
    assert summary["core_count"] == 100
    assert summary["full_count"] <= 500
    counts = {
        row["value"]: row["core_count"] for row in summary["categories"]
    }
    assert counts == CORE_CATEGORY_QUOTAS
    core_names = {platform.name for platform in platforms if platform.tier == "core"}
    assert core_names >= MANDATORY_CORE_PLATFORMS
    assert {platform.name for platform in platforms if platform.alias_probe} == set(
        ALIAS_PROBE_PLATFORMS
    )


def test_erkan_repeat_candidate_is_in_ranked_top_twelve() -> None:
    candidates = generate_candidates("erkanrzgc")
    assert len(candidates) == 12
    assert candidates[0].username == "erkanrzgcc"
    assert "repeat_last_character" in candidates[0].discovery_reasons


def test_identity_phases_follow_the_documented_order() -> None:
    names = [phase.name for phase in _phase_registry()]
    assert names[:5] == [
        "handle_resolve",
        "platform_check",
        "profile_validate",
        "deep_scrape",
        "smart_search",
    ]


def test_oauth_token_prep_is_limited_to_reachable_providers() -> None:
    platforms = {platform.name: platform for platform in load_platforms()}

    assert engine_mod._providers_requiring_token_prep(
        ScanConfig(username="alice", smart=False),
        {"GitHub": platforms["GitHub"]},
    ) == ()
    assert engine_mod._providers_requiring_token_prep(
        ScanConfig(username="alice", smart=True, alias_platform_limit=5),
        {"GitHub": platforms["GitHub"]},
    ) == ()
    assert engine_mod._providers_requiring_token_prep(
        ScanConfig(username="alice", smart=True, alias_platform_limit=6),
        {"GitHub": platforms["GitHub"]},
    ) == ("Reddit",)
    assert engine_mod._providers_requiring_token_prep(
        ScanConfig(username="alice", smart=False),
        {"Twitch": platforms["Twitch"]},
    ) == ("Twitch",)


def test_identity_verdict_rules_are_evidence_first() -> None:
    handle_only = correlate_identity(_payload("alice"), _payload("alicee"))
    assert handle_only.verdict == "uncertain"

    same_name = correlate_identity(
        _payload("alice", {"name": "Alice Example"}),
        _payload("alicee", {"name": "Alice Example"}),
    )
    assert same_name.verdict == "possible_same"

    direct = correlate_identity(
        _payload("alice"), _payload("alicee"), direct_link=True
    )
    assert direct.verdict == "confirmed_same"

    multi_signal = correlate_identity(
        _payload(
            "alice",
            {"name": "Alice Example", "website_url": "https://alice.example"},
        ),
        _payload(
            "alicee",
            {"name": "Alice Example", "website_url": "https://alice.example/"},
        ),
    )
    assert multi_signal.verdict == "likely_same"


@pytest.mark.asyncio
async def test_hugging_face_scraper_normalizes_overview_and_socials() -> None:
    overview = {
        "user": "alicee",
        "fullname": "Alice Example",
        "details": "security researcher",
        "avatarUrl": "https://cdn.example/avatar.png",
        "orgs": [{"name": "Example Org"}],
        "numModels": 2,
    }
    socials = {
        "user": "alicee",
        "socialHandles": {"github": "alice", "twitter": "alice_sec"},
    }
    with aioresponses() as mocked:
        mocked.get(
            "https://huggingface.co/api/users/alicee/overview",
            status=200,
            payload=overview,
        )
        mocked.get(
            "https://huggingface.co/api/users/alicee/socials",
            status=200,
            payload=socials,
        )
        async with HTTPClient() as client:
            result = await scrape_hugging_face(client, "alicee")
    assert result["name"] == "Alice Example"
    assert result["bio"] == "security researcher"
    assert result["organizations"] == ["Example Org"]
    assert result["github_username"] == "alice"


@pytest.mark.asyncio
async def test_alias_is_probed_on_hugging_face_even_when_root_exists(monkeypatch) -> None:
    monkeypatch.setattr(engine_mod, "ALIAS_PROBE_PLATFORMS", ("Hugging Face",))
    platform = Platform(
        name="Hugging Face",
        url="https://huggingface.co/{username}",
        category="dev",
        url_probe="https://huggingface.co/api/users/{username}/overview",
        tier="core",
        alias_probe=True,
        evidence_class="official_exact",
        lookup_semantics="exact",
    )
    root_profile = PlatformResult(
        platform="Hugging Face",
        url="https://huggingface.co/erkanrzgc",
        category="dev",
        exists=True,
        status="found",
        confidence=1.0,
        profile_data={"name": "Erkan Example"},
        verification={"verdict": "confirmed", "score": 1.0},
    )
    result = ScanResult(username="erkanrzgc", platforms=[root_profile])
    checked: list[str] = []

    async def fake_check(_client, cfg_arg, _platform):
        checked.append(cfg_arg.username)
        return PlatformResult(
            platform="Hugging Face",
            url=f"https://huggingface.co/{cfg_arg.username}",
            category="dev",
            exists=True,
            status="found",
            confidence=1.0,
            profile_data={
                "username": cfg_arg.username,
                "name": "Erkan Example",
            },
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check)
    monkeypatch.setattr(engine_mod, "_deep_scrape", lambda *_args: _empty_profile())

    await _phase_smart_search(
        client=None,
        cfg=ScanConfig(
            username="erkanrzgc",
            smart=True,
            alias_max_candidates=1,
            alias_platform_limit=1,
        ),
        platforms=[platform],
        platform_results=[root_profile],
        result=result,
    )

    assert "erkanrzgcc" in checked
    assert [candidate.username for candidate in result.identity_candidates] == [
        "erkanrzgcc"
    ]
    assert result.identity_candidates[0].verdict == "possible_same"
    assert result.platforms == [root_profile]
    assert result.diagnostics["alias_search"]["probe_count"] == 1


@pytest.mark.asyncio
async def test_login_wall_alias_is_diagnostic_not_identity_candidate(monkeypatch) -> None:
    monkeypatch.setattr(engine_mod, "ALIAS_PROBE_PLATFORMS", ("GitHub",))
    platform = Platform(
        name="GitHub",
        url="https://github.test/{username}",
        category="dev",
        url_probe="https://api.github.test/{username}",
        tier="core",
        alias_probe=True,
    )
    result = ScanResult(username="alice")

    async def fake_check(_client, cfg_arg, _platform):
        return PlatformResult(
            platform="GitHub",
            url=f"https://github.test/{cfg_arg.username}",
            category="dev",
            exists=False,
            status="login_required",
            confidence=0.8,
            fp_signals=["login_required"],
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check)
    await _phase_smart_search(
        client=None,
        cfg=ScanConfig(
            username="alice",
            alias_max_candidates=1,
            alias_platform_limit=1,
        ),
        platforms=[platform],
        platform_results=[],
        result=result,
    )
    assert result.identity_candidates == []
    assert result.diagnostics["alias_search"]["confirmed_profiles"] == 0


@pytest.mark.asyncio
async def test_alias_phase_never_exceeds_twelve_by_fifteen_probes(monkeypatch) -> None:
    platforms = [platform for platform in load_platforms() if platform.alias_probe]
    result = ScanResult(username="erkanrzgc")
    checked: list[tuple[str, str]] = []

    async def fake_check(_client, cfg_arg, platform):
        checked.append((cfg_arg.username, platform.name))
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", cfg_arg.username),
            category=platform.category,
            exists=False,
            status="not_found",
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check)
    await _phase_smart_search(
        client=None,
        cfg=ScanConfig(
            username="erkanrzgc",
            alias_max_candidates=12,
            alias_platform_limit=15,
        ),
        platforms=platforms,
        platform_results=[],
        result=result,
    )

    diagnostics = result.diagnostics["alias_search"]
    assert len(checked) == diagnostics["probe_count"] == 180
    assert len(set(checked)) == 180
    assert diagnostics["candidate_count"] == 12
    assert diagnostics["platform_count"] == 15
    assert diagnostics["max_probes"] == 180
    assert result.identity_candidates == []


@pytest.mark.asyncio
async def test_adaptive_alias_fallback_is_capped_at_240_probes(monkeypatch) -> None:
    platforms = [platform for platform in load_platforms() if platform.alias_probe]
    result = ScanResult(username="erkanrzgc")
    checked: list[tuple[str, str]] = []

    async def fake_check(_client, cfg_arg, platform):
        checked.append((cfg_arg.username, platform.name))
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", cfg_arg.username),
            category=platform.category,
            exists=False,
            status="not_found",
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check)
    await _phase_smart_search(
        client=None,
        cfg=ScanConfig(username="erkanrzgc"),
        platforms=platforms,
        platform_results=[],
        result=result,
    )

    diagnostics = result.diagnostics["alias_search"]
    assert len(checked) == len(set(checked)) == 240
    assert diagnostics["probe_count"] == diagnostics["max_probes"] == 240
    assert diagnostics["primary_probe_count"] == 180
    assert diagnostics["fallback_probe_count"] == 60
    assert diagnostics["primary_candidate_count"] == 12
    assert diagnostics["fallback_candidate_count"] == 12
    assert diagnostics["fallback_platform_count"] == 5
    assert diagnostics["fallback_triggered"] is True
    assert diagnostics["strong_primary"] is False
    assert len(result.variations_checked) == 24


@pytest.mark.asyncio
async def test_strong_primary_alias_stops_before_adaptive_fallback(monkeypatch) -> None:
    platforms = [platform for platform in load_platforms() if platform.alias_probe]
    root_profile = PlatformResult(
        platform="Hugging Face",
        url="https://huggingface.co/erkanrzgc",
        category="dev",
        exists=True,
        status="found",
        confidence=1.0,
        verification={"verdict": "confirmed", "score": 1.0},
    )
    result = ScanResult(username="erkanrzgc", platforms=[root_profile])
    checked: list[tuple[str, str]] = []

    async def fake_check(_client, cfg_arg, platform):
        checked.append((cfg_arg.username, platform.name))
        found = (
            cfg_arg.username == "erkanrzgcc"
            and platform.name == "Hugging Face"
        )
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", cfg_arg.username),
            category=platform.category,
            exists=found,
            status="found" if found else "not_found",
            confidence=1.0 if found else 0.0,
            profile_data=(
                {
                    "username": cfg_arg.username,
                    "github_username": "erkanrzgc",
                }
                if found
                else {}
            ),
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check)
    monkeypatch.setattr(engine_mod, "_deep_scrape", lambda *_args: _empty_profile())
    await _phase_smart_search(
        client=None,
        cfg=ScanConfig(username="erkanrzgc"),
        platforms=platforms,
        platform_results=[root_profile],
        result=result,
    )

    diagnostics = result.diagnostics["alias_search"]
    assert len(checked) == diagnostics["probe_count"] == 180
    assert diagnostics["fallback_probe_count"] == 0
    assert diagnostics["fallback_triggered"] is False
    assert diagnostics["strong_primary"] is True
    assert len(result.variations_checked) == 12
    assert result.identity_candidates[0].username == "erkanrzgcc"
    assert result.identity_candidates[0].verdict == "confirmed_same"


async def _empty_profile() -> dict:
    return {}
