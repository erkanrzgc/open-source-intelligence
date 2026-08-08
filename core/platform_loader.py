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
from dataclasses import dataclass
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


BUILTIN_YAML = Path(__file__).resolve().parent.parent / "modules" / "platforms.yaml"
USER_YAML = Path.home() / ".config" / "open-source-intelligence" / "platforms.yaml"

_VALID_CHECK_TYPES = {"status", "content_absent", "content_present", "json_api"}


def _coerce(entry: dict[str, Any]) -> Platform:
    name = entry.get("name")
    url = entry.get("url")
    category = entry.get("category")
    if not (isinstance(name, str) and isinstance(url, str) and isinstance(category, str)):
        raise ValueError(f"platform entry missing name/url/category: {entry!r}")
    if "{username}" not in url:
        raise ValueError(f"platform {name!r} url must contain {{username}}")
    check_type = entry.get("check_type", "status")
    if check_type not in _VALID_CHECK_TYPES:
        raise ValueError(f"platform {name!r} invalid check_type {check_type!r}")
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

    for entry in _read_yaml(BUILTIN_YAML, required=True):
        try:
            p = _coerce(entry)
        except ValueError as exc:
            log.warning("skipping builtin entry: %s", exc)
            continue
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
            merged[p.name] = p  # user wins on name conflict

    for name in disabled:
        merged.pop(name, None)

    return list(merged.values())
