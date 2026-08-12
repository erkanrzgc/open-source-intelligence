"""Tests for core/platform_loader.py — YAML loading and user overrides."""

from pathlib import Path

import pytest

from core import platform_loader
from core.platform_loader import (
    ALIAS_PROBE_PLATFORMS,
    CORE_CATEGORY_QUOTAS,
    FULL_CATEGORY_LIMITS,
    MANDATORY_CORE_PLATFORMS,
    Platform,
    _coerce,
    catalogue_summary,
    load_platforms,
    supports_confirmation,
)


def test_coerce_minimal():
    p = _coerce({"name": "X", "url": "https://x/{username}", "category": "social"})
    assert p.name == "X"
    assert p.check_type == "status"
    assert p.has_deep_scraper is False


def test_coerce_full():
    p = _coerce(
        {
            "name": "Y",
            "url": "https://y/{username}",
            "category": "dev",
            "check_type": "content_absent",
            "error_text": "nope",
            "headers": {"X": "v"},
            "has_deep_scraper": True,
        }
    )
    assert p.check_type == "content_absent"
    assert p.error_text == "nope"
    assert p.headers == {"X": "v"}
    assert p.has_deep_scraper is True


def test_coerce_missing_field():
    with pytest.raises(ValueError):
        _coerce({"name": "X", "category": "s"})


def test_coerce_bad_placeholder():
    with pytest.raises(ValueError):
        _coerce({"name": "X", "url": "https://x", "category": "s"})


def test_coerce_invalid_check_type():
    with pytest.raises(ValueError):
        _coerce(
            {"name": "X", "url": "https://x/{username}", "category": "s", "check_type": "bogus"}
        )


def test_coerce_bad_headers():
    with pytest.raises(ValueError):
        _coerce(
            {
                "name": "X",
                "url": "https://x/{username}",
                "category": "s",
                "headers": "not-a-dict",
            }
        )


def test_load_platforms_default():
    platforms = load_platforms()
    assert len(platforms) == sum(FULL_CATEGORY_LIMITS.values()) == 500
    names = {p.name for p in platforms}
    assert "GitHub" in names
    assert "Instagram" in names


def test_builtin_catalogue_contract_is_exact_and_pinned():
    platforms = load_platforms()
    summary = catalogue_summary(platforms)
    core = {platform.name for platform in platforms if platform.tier == "core"}
    aliases = {platform.name for platform in platforms if platform.alias_probe}

    assert summary["core_count"] == sum(CORE_CATEGORY_QUOTAS.values()) == 100
    assert summary["full_count"] == 500
    assert core >= MANDATORY_CORE_PLATFORMS
    assert aliases == set(ALIAS_PROBE_PLATFORMS)
    assert len(aliases) == 15


def test_user_override_adds_and_replaces(tmp_path: Path, monkeypatch):
    user_file = tmp_path / "custom.yaml"
    user_file.write_text(
        """
platforms:
  - name: GitHub
    url: https://github.test/{username}
    category: dev
    has_deep_scraper: false
  - name: MyCustomSite
    url: https://my.test/{username}
    category: other
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OSINT_PLATFORMS_FILE", str(user_file))
    monkeypatch.setattr(platform_loader, "USER_YAML", tmp_path / "absent.yaml")

    platforms = load_platforms()
    by_name = {p.name: p for p in platforms}

    assert "MyCustomSite" in by_name
    assert by_name["MyCustomSite"].category == "other"
    assert by_name["GitHub"].url == "https://github.test/{username}"
    assert by_name["GitHub"].has_deep_scraper is False


def test_user_disable_removes_builtin(tmp_path: Path, monkeypatch):
    user_file = tmp_path / "disable.yaml"
    user_file.write_text(
        """
platforms:
  - name: GitHub
    disabled: true
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OSINT_PLATFORMS_FILE", str(user_file))
    monkeypatch.setattr(platform_loader, "USER_YAML", tmp_path / "absent.yaml")

    platforms = load_platforms()
    assert not any(p.name == "GitHub" for p in platforms)


def test_malformed_yaml_ignored(tmp_path: Path, monkeypatch):
    user_file = tmp_path / "bad.yaml"
    user_file.write_text(": : not yaml :\n", encoding="utf-8")
    monkeypatch.setenv("OSINT_PLATFORMS_FILE", str(user_file))
    monkeypatch.setattr(platform_loader, "USER_YAML", tmp_path / "absent.yaml")

    # Loader must survive and still return builtins
    platforms = load_platforms()
    assert len(platforms) >= 80


def test_non_mapping_top_level_ignored(tmp_path: Path, monkeypatch):
    user_file = tmp_path / "list.yaml"
    user_file.write_text("- just a list\n", encoding="utf-8")
    monkeypatch.setenv("OSINT_PLATFORMS_FILE", str(user_file))
    monkeypatch.setattr(platform_loader, "USER_YAML", tmp_path / "absent.yaml")

    platforms = load_platforms()
    assert len(platforms) >= 80


def test_invalid_entry_in_user_file_skipped(tmp_path: Path, monkeypatch):
    user_file = tmp_path / "mix.yaml"
    user_file.write_text(
        """
platforms:
  - name: Broken
    category: dev
  - name: Good
    url: https://good.test/{username}
    category: dev
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OSINT_PLATFORMS_FILE", str(user_file))
    monkeypatch.setattr(platform_loader, "USER_YAML", tmp_path / "absent.yaml")

    platforms = load_platforms()
    names = {p.name for p in platforms}
    assert "Good" in names
    assert "Broken" not in names


def test_platform_dataclass_defaults():
    p = Platform(name="A", url="https://a/{username}", category="dev")
    assert p.check_type == "status"
    assert p.headers is None
    assert p.js_heavy is False
    assert p.wait_for_selector is None


def test_coerce_js_heavy_flag():
    p = _coerce(
        {
            "name": "X",
            "url": "https://x/{username}",
            "category": "social",
            "js_heavy": True,
            "wait_for_selector": "main[role=main]",
        }
    )
    assert p.js_heavy is True
    assert p.wait_for_selector == "main[role=main]"


def test_coerce_rejects_non_string_selector():
    with pytest.raises(ValueError):
        _coerce(
            {
                "name": "X",
                "url": "https://x/{username}",
                "category": "s",
                "wait_for_selector": 42,
            }
        )


def test_builtin_tags_known_js_heavy_sites():
    by_name = {p.name: p for p in load_platforms()}
    assert by_name["Instagram"].js_heavy is True
    assert by_name["TikTok"].js_heavy is True
    assert by_name["LinkedIn"].js_heavy is True


def test_transport_shape_alone_is_not_a_confirmation_contract():
    platform = Platform(
        name="SearchOnly",
        url="https://search.test/{username}",
        category="social",
        url_probe="https://api.test/search?q={username}",
        has_deep_scraper=True,
    )
    assert supports_confirmation(platform) is False


def test_researched_alias_contracts_gate_supported_and_unsupported_automation():
    by_name = {platform.name: platform for platform in load_platforms()}

    assert by_name["X"].automated is True
    assert by_name["X"].headers is None
    assert by_name["X"].url_probe is None
    assert by_name["Twitch"].automated is True
    assert by_name["Twitch"].url_probe is None
    assert by_name["LinkedIn"].auth_mode == "prohibited"
    assert by_name["LinkedIn"].automated is False
    assert by_name["Reddit"].auth_mode == "required"
    assert by_name["Reddit"].url_probe is None
    assert by_name["Instagram"].has_deep_scraper is False

    confirmable_aliases = {
        name
        for name in ALIAS_PROBE_PLATFORMS
        if supports_confirmation(by_name[name])
    }
    assert confirmable_aliases == {
        "GitHub",
        "GitLab",
        "Hugging Face",
        "Dev.to",
        "Reddit",
        "X",
        "YouTube",
        "Medium",
        "Twitch",
        "Steam",
    }
    # A plain-HTML site should remain aiohttp-only.
    assert by_name["GitHub"].js_heavy is False
