"""Load platform definitions from YAML files.

Priority order (highest wins on name conflict):
    1. User override: $OSINT_PLATFORMS_FILE
    2. User config:   ~/.config/open-source-intelligence/platforms.yaml
    3. Builtin:       modules/platforms.yaml

User files can also extend via a `platforms:` list. To remove a
builtin platform, set `disabled: true` on an entry whose `name`
matches the builtin.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)


@dataclass
class Platform:
    name: str
    url: str
    category: str
    check_type: str = "status"
    error_text: str = ""
    success_text: str = ""
    headers: dict | None = None
    has_deep_scraper: bool = False
    js_heavy: bool = False
    wait_for_selector: str | None = None
    username_pattern: str | None = None
    absence_strings: tuple[str, ...] = ()
    presence_strings: tuple[str, ...] = ()
    url_probe: str | None = None
    check_method: str = "status"
    probe_method: str = "GET"
    probe_body: dict | None = None
    tier: str = "full"
    priority: int = 0
    alias_probe: bool = False
    golden_fixture: bool = False
    # Fail-closed provider contract metadata. Transport shape and parser
    # availability alone never make an account-presence claim trustworthy.
    evidence_class: str = "heuristic"
    entity_scope: str = "person"
    lookup_semantics: str = "heuristic"
    auth_mode: str = "none"
    contract_revision: str = ""
    docs_url: str = ""
    automated: bool = True


BUILTIN_YAML = Path(__file__).resolve().parent.parent / "modules" / "platforms.yaml"
USER_YAML = Path.home() / ".config" / "open-source-intelligence" / "platforms.yaml"

_VALID_CHECK_TYPES = {"status", "content_absent", "content_present", "json_api"}
EVIDENCE_CLASSES = frozenset(
    {
        "official_exact",
        "official_scoped",
        "public_contract",
        "page_verified",
        "heuristic",
        "disabled",
    }
)
LOOKUP_SEMANTICS = frozenset({"exact", "scoped", "search", "heuristic", "disabled"})
AUTH_MODES = frozenset({"none", "optional", "required", "prohibited"})
_CONFIRMING_EVIDENCE_CLASSES = frozenset(
    {"official_exact", "official_scoped", "public_contract"}
)
_CONFIRMING_LOOKUP_SEMANTICS = frozenset({"exact", "scoped"})

CATEGORY_LABELS: dict[str, str] = {
    "social": "Social",
    "dev": "Developer",
    "content": "Yayın / İçerik",
    "community": "Community",
    "professional": "Professional",
    "gaming": "Gaming",
    "other": "Other",
    "dating": "Dating",
}

# The order is part of the public catalogue contract.  The quotas add up to
# exactly 100; the full limits cap the checked-in runtime catalogue at 500.
CORE_CATEGORY_QUOTAS: dict[str, int] = {
    "social": 25,
    "dev": 20,
    "content": 20,
    "community": 12,
    "professional": 10,
    "gaming": 8,
    "other": 4,
    "dating": 1,
}
FULL_CATEGORY_LIMITS: dict[str, int] = {
    "social": 100,
    "dev": 90,
    "content": 90,
    "community": 90,
    "professional": 60,
    "gaming": 45,
    "other": 15,
    "dating": 10,
}

MANDATORY_CORE_PLATFORMS = frozenset(
    {
        "GitHub", "GitLab", "Hugging Face", "StackOverflow", "npm", "PyPI",
        "Dev.to", "Docker Hub", "Kaggle", "Reddit", "X", "Instagram",
        "TikTok", "YouTube", "Facebook", "Telegram", "LinkedIn", "Medium",
        "Twitch", "Steam", "Keybase", "Hacker News", "Mastodon",
        "Pinterest", "Vimeo", "SoundCloud", "Behance", "Dribbble", "Chess.com",
        "Lichess", "Linktree", "About.me",
    }
)

ALIAS_PROBE_PLATFORMS: tuple[str, ...] = (
    "GitHub", "GitLab", "Hugging Face", "StackOverflow", "Dev.to", "Reddit",
    "X", "Instagram", "TikTok", "LinkedIn", "Telegram", "YouTube", "Medium",
    "Twitch", "Steam",
)
_ALIAS_PROBE_SET = frozenset(ALIAS_PROBE_PLATFORMS)


def _coerce(entry: dict[str, Any]) -> Platform:
    name = entry.get("name")
    url = entry.get("url")
    category = entry.get("category")
    if not (isinstance(name, str) and isinstance(url, str) and isinstance(category, str)):
        raise ValueError(f"platform entry missing name/url/category: {entry!r}")
    check_type = entry.get("check_type", "status")
    if check_type not in _VALID_CHECK_TYPES:
        raise ValueError(f"platform {name!r} invalid check_type {check_type!r}")
    if "{username}" not in url and check_type != "json_api":
        raise ValueError(f"platform {name!r} url must contain {{username}}")
    headers = entry.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise ValueError(f"platform {name!r} headers must be a mapping")
    wait_for_selector = entry.get("wait_for_selector")
    if wait_for_selector is not None and not isinstance(wait_for_selector, str):
        raise ValueError(f"platform {name!r} wait_for_selector must be a string")
    username_pattern = entry.get("username_pattern")
    if username_pattern is not None and not isinstance(username_pattern, str):
        raise ValueError(f"platform {name!r} username_pattern must be a string")
    absence = entry.get("absence_strings")
    if absence is None:
        absence = []
    elif not isinstance(absence, list):
        raise ValueError(f"platform {name!r} absence_strings must be a list")
    presence = entry.get("presence_strings")
    if presence is None:
        presence = []
    elif not isinstance(presence, list):
        raise ValueError(f"platform {name!r} presence_strings must be a list")
    url_probe = entry.get("url_probe")
    if url_probe is not None and not isinstance(url_probe, str):
        raise ValueError(f"platform {name!r} url_probe must be a string")
    check_method = entry.get("check_method", "status")
    if check_method not in ("status", "message", "response_url"):
        raise ValueError(f"platform {name!r} invalid check_method {check_method!r}")
    probe_method = entry.get("probe_method", "GET")
    if probe_method not in ("GET", "POST"):
        raise ValueError(f"platform {name!r} invalid probe_method {probe_method!r}")
    probe_body = entry.get("probe_body")
    if probe_body is not None and not isinstance(probe_body, dict):
        raise ValueError(f"platform {name!r} probe_body must be a mapping")
    tier = entry.get("tier", "full")
    if tier not in ("core", "full"):
        raise ValueError(f"platform {name!r} invalid tier {tier!r}")
    priority = entry.get("priority", 0)
    if not isinstance(priority, int):
        raise ValueError(f"platform {name!r} priority must be an integer")
    evidence_class = entry.get("evidence_class", "heuristic")
    if evidence_class not in EVIDENCE_CLASSES:
        raise ValueError(f"platform {name!r} invalid evidence_class {evidence_class!r}")
    entity_scope = entry.get("entity_scope", "person")
    if not isinstance(entity_scope, str) or not entity_scope.strip():
        raise ValueError(f"platform {name!r} entity_scope must be a non-empty string")
    lookup_semantics = entry.get("lookup_semantics", "heuristic")
    if lookup_semantics not in LOOKUP_SEMANTICS:
        raise ValueError(
            f"platform {name!r} invalid lookup_semantics {lookup_semantics!r}"
        )
    auth_mode = entry.get("auth_mode", "none")
    if auth_mode not in AUTH_MODES:
        raise ValueError(f"platform {name!r} invalid auth_mode {auth_mode!r}")
    contract_revision = entry.get("contract_revision", "") or ""
    docs_url = entry.get("docs_url", "") or ""
    if not isinstance(contract_revision, str):
        raise ValueError(f"platform {name!r} contract_revision must be a string")
    if not isinstance(docs_url, str):
        raise ValueError(f"platform {name!r} docs_url must be a string")
    automated = entry.get("automated", True)
    if not isinstance(automated, bool):
        raise ValueError(f"platform {name!r} automated must be a boolean")
    return Platform(
        name=name,
        url=url,
        category=category,
        check_type=check_type,
        error_text=entry.get("error_text", "") or "",
        success_text=entry.get("success_text", "") or "",
        headers=headers,
        has_deep_scraper=bool(entry.get("has_deep_scraper", False)),
        js_heavy=bool(entry.get("js_heavy", False)),
        wait_for_selector=wait_for_selector,
        username_pattern=username_pattern,
        absence_strings=tuple(str(s) for s in absence if str(s).strip()),
        presence_strings=tuple(str(s) for s in presence if str(s).strip()),
        url_probe=url_probe,
        check_method=check_method,
        probe_method=probe_method,
        probe_body=probe_body,
        tier=tier,
        priority=priority,
        alias_probe=bool(entry.get("alias_probe", False)),
        golden_fixture=bool(entry.get("golden_fixture", False)),
        evidence_class=evidence_class,
        entity_scope=entity_scope.strip(),
        lookup_semantics=lookup_semantics,
        auth_mode=auth_mode,
        contract_revision=contract_revision,
        docs_url=docs_url,
        automated=automated,
    )


def _curate_builtins(platforms: list[Platform]) -> list[Platform]:
    """Return the deterministic, bounded built-in runtime catalogue.

    The checked-in YAML remains the source of platform wire contracts.  This
    function is the checked-in selection policy: source order is stable, pinned
    high-value services sort first within their category, and hard category
    limits prevent imported long-tail records from leaking into runtime.
    """
    source_index = {platform.name: index for index, platform in enumerate(platforms)}
    full_names: set[str] = set()
    core_names: set[str] = set()

    for category in CATEGORY_LABELS:
        group = [platform for platform in platforms if platform.category == category]
        ranked = sorted(
            group,
            key=lambda platform: (
                platform.name not in MANDATORY_CORE_PLATFORMS,
                source_index[platform.name],
                platform.name.casefold(),
            ),
        )
        full_group = ranked[: FULL_CATEGORY_LIMITS[category]]
        core_group = full_group[: CORE_CATEGORY_QUOTAS[category]]
        full_names.update(platform.name for platform in full_group)
        core_names.update(platform.name for platform in core_group)

    missing = MANDATORY_CORE_PLATFORMS - core_names
    if missing:
        raise RuntimeError(
            "mandatory core platforms missing from curated catalogue: "
            + ", ".join(sorted(missing))
        )

    curated: list[Platform] = []
    for platform in platforms:
        if platform.name not in full_names:
            continue
        index = source_index[platform.name]
        pinned_bonus = 1_000_000 if platform.name in MANDATORY_CORE_PLATFORMS else 0
        curated.append(
            replace(
                platform,
                tier="core" if platform.name in core_names else "full",
                priority=pinned_bonus + max(1, 100_000 - index),
                alias_probe=platform.name in _ALIAS_PROBE_SET,
            )
        )
    return curated


def supports_confirmation(platform: Platform) -> bool:
    """Whether the checked-in provider contract can prove exact presence."""
    if not platform.automated or platform.evidence_class == "disabled":
        return False
    return bool(
        (
            platform.evidence_class in _CONFIRMING_EVIDENCE_CLASSES
            and platform.lookup_semantics in _CONFIRMING_LOOKUP_SEMANTICS
        )
        or (
            platform.golden_fixture
            and platform.lookup_semantics in _CONFIRMING_LOOKUP_SEMANTICS
        )
    )


def _read_yaml(path: Path, *, required: bool = False) -> list[dict[str, Any]]:
    if not path.is_file():
        if required:
            raise RuntimeError(f"required platforms file not found: {path}")
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        if required:
            raise RuntimeError(f"failed to parse required platforms file {path}: {exc}") from exc
        log.warning("failed to parse %s: %s", path, exc)
        return []
    if not isinstance(raw, dict):
        msg = f"{path}: expected top-level mapping, got {type(raw).__name__}"
        if required:
            raise RuntimeError(msg)
        log.warning(msg)
        return []
    platforms = raw.get("platforms", [])
    if not isinstance(platforms, list):
        msg = f"{path}: 'platforms' must be a list"
        if required:
            raise RuntimeError(msg)
        log.warning(msg)
        return []
    return platforms


def _user_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("OSINT_PLATFORMS_FILE")
    if env:
        paths.append(Path(env).expanduser())
    if USER_YAML.is_file():
        paths.append(USER_YAML)
    return paths


def load_platforms() -> list[Platform]:
    """Load builtin platforms plus any user overrides."""
    merged: dict[str, Platform] = {}
    disabled: set[str] = set()

    builtins: list[Platform] = []
    for entry in _read_yaml(BUILTIN_YAML, required=True):
        try:
            p = _coerce(entry)
        except ValueError as exc:
            log.warning("skipping builtin entry: %s", exc)
            continue
        builtins.append(p)

    for p in _curate_builtins(builtins):
        merged[p.name] = p

    for path in _user_paths():
        for entry in _read_yaml(path):
            if entry.get("disabled"):
                name = entry.get("name")
                if isinstance(name, str):
                    disabled.add(name)
                continue
            try:
                p = _coerce(entry)
            except ValueError as exc:
                log.warning("skipping user entry from %s: %s", path, exc)
                continue
            previous = merged.get(p.name)
            if previous is not None:
                # A wire-contract override should not silently demote a curated
                # platform when the user omitted catalogue metadata.
                p = replace(
                    p,
                    tier=p.tier if "tier" in entry else previous.tier,
                    priority=p.priority if "priority" in entry else previous.priority,
                    alias_probe=(
                        p.alias_probe if "alias_probe" in entry else previous.alias_probe
                    ),
                    golden_fixture=(
                        p.golden_fixture
                        if "golden_fixture" in entry
                        else previous.golden_fixture
                    ),
                    evidence_class=(
                        p.evidence_class
                        if "evidence_class" in entry
                        else previous.evidence_class
                    ),
                    entity_scope=(
                        p.entity_scope if "entity_scope" in entry else previous.entity_scope
                    ),
                    lookup_semantics=(
                        p.lookup_semantics
                        if "lookup_semantics" in entry
                        else previous.lookup_semantics
                    ),
                    auth_mode=p.auth_mode if "auth_mode" in entry else previous.auth_mode,
                    contract_revision=(
                        p.contract_revision
                        if "contract_revision" in entry
                        else previous.contract_revision
                    ),
                    docs_url=p.docs_url if "docs_url" in entry else previous.docs_url,
                    automated=p.automated if "automated" in entry else previous.automated,
                )
            merged[p.name] = p  # user wins on name conflict

    for name in disabled:
        merged.pop(name, None)

    return list(merged.values())


def catalogue_summary(platforms: list[Platform] | None = None) -> dict[str, Any]:
    """Return counts, labels and selectable platform metadata for REST/Web."""
    rows = list(platforms) if platforms is not None else load_platforms()
    bundled = [platform for platform in rows if platform.priority > 0]
    return {
        "core_count": sum(platform.tier == "core" for platform in bundled),
        "full_count": len(bundled),
        "categories": [
            {
                "value": category,
                "label": label,
                "core_count": sum(
                    platform.tier == "core" and platform.category == category
                    for platform in bundled
                ),
                "full_count": sum(
                    platform.category == category for platform in bundled
                ),
            }
            for category, label in CATEGORY_LABELS.items()
        ],
        "platforms": [
            {
                "name": platform.name,
                "category": platform.category,
                "tier": platform.tier,
                "priority": platform.priority,
                "alias_probe": platform.alias_probe,
                "confirmable": supports_confirmation(platform),
                "evidence_class": platform.evidence_class,
                "entity_scope": platform.entity_scope,
                "lookup_semantics": platform.lookup_semantics,
                "auth_mode": platform.auth_mode,
                "contract_revision": platform.contract_revision,
                "docs_url": platform.docs_url,
                "automated": platform.automated,
            }
            for platform in sorted(
                rows,
                key=lambda item: (
                    item.tier != "core",
                    -item.priority,
                    item.name.casefold(),
                ),
            )
        ],
    }
