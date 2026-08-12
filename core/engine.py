"""OSINT scan engine — orchestrates modular phases.

Kept deliberately thin: each phase is a small coroutine that mutates the
ScanResult in place. Adding a new phase means adding a _phase_* method
and wiring it into scan().
"""

from __future__ import annotations

import asyncio
import inspect
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.config import ScanConfig
from core.context import ScanContext
from core.correlation import correlate_identity
from core.cross_reference import cross_reference
from core.http_client import HTTPClient
from core.logging_setup import get_logger
from core.models import (
    EmailResult,
    IdentityCandidate,
    PhotoMatch,
    PlatformResult,
    ProbeOutcome,
    ScanResult,
)
from core.platform_loader import ALIAS_PROBE_PLATFORMS, supports_confirmation
from core.progress import emit as _emit
from core.reporter import console
from core.smart_search import (
    UsernameCandidate,
    extract_discoverable_data,
    generate_candidates,
    merge_discoveries,
)
from core.verification import evaluate_platform
from modules.breach_check import breach_check_available, check_many_emails, hibp_available
from modules.comb_leaks import search_comb_many
from modules.deep_scrapers import DEEP_SCRAPERS
from modules.dns_lookup import enumerate_subdomains, get_dns_records
from modules.email_discovery import discover_emails
from modules.fp_filter import score_match
from modules.ghunt_lookup import is_available as ghunt_available
from modules.ghunt_lookup import lookup_emails as ghunt_lookup_emails
from modules.holehe_check import check_emails as holehe_check_emails
from modules.holehe_check import is_available as holehe_available
from modules.holehe_check import module_count as holehe_module_count
from modules.photo_compare import compare_profile_photos
from modules.platforms import PLATFORMS, Platform
from modules.profile_extract import extract_profile
from modules.profile_extract import is_available as _extract_available
from modules.profile_liveness import score_liveness
from modules.providers import (
    PROVIDERS,
    has_provider,
    prepare_provider_credentials,
)
from modules.providers import is_configured as provider_is_configured
from modules.providers import lookup_many as lookup_provider_many
from modules.stealth import obscura_fallback
from modules.stealth.js_wall import looks_like_js_wall
from modules.stealth.playwright_fallback import (
    AVAILABLE as PLAYWRIGHT_AVAILABLE,
)
from modules.stealth.playwright_fallback import (
    fetch_rendered,
)
from modules.stealth.soft_404 import (
    IMPOSSIBLE_USERNAME,
    Soft404Cache,
    is_soft_404,
    make_baseline,
)
from modules.toutatis_lookup import is_available as toutatis_available
from modules.toutatis_lookup import lookup_usernames as toutatis_lookup_usernames
from modules.web_presence import discover_web_presence
from modules.whois_lookup import check_username_domains

log = get_logger(__name__)

AVATAR_KEYS = ("avatar_url", "icon_img", "avatar", "profile_image")

# Module-level soft-404 baseline cache. Lazily instantiated so test code
# that imports the engine without scanning doesn't touch the filesystem.
_SOFT_404_CACHE: Soft404Cache | None = None


def _soft_404_cache() -> Soft404Cache:
    global _SOFT_404_CACHE
    if _SOFT_404_CACHE is None:
        _SOFT_404_CACHE = Soft404Cache()
    return _SOFT_404_CACHE


def _providers_requiring_token_prep(
    cfg: ScanConfig,
    selected_by_name: dict[str, Platform],
) -> tuple[str, ...]:
    """Return OAuth providers that this scan can actually query."""
    required = {
        name
        for name in ("Reddit", "Twitch")
        if name in selected_by_name
    }
    if cfg.smart:
        required.update(
            name
            for name in ALIAS_PROBE_PLATFORMS[: cfg.alias_platform_limit]
            if name in {"Reddit", "Twitch"}
        )
    return tuple(sorted(required))


# Pending baseline-seed background tasks; awaited at end of run_scan so the
# scan completes deterministically without leaking warnings about unawaited
# coroutines.
_PENDING_SEED_TASKS: set[asyncio.Task] = set()


def _track_seed(task: asyncio.Task) -> None:
    _PENDING_SEED_TASKS.add(task)
    task.add_done_callback(_PENDING_SEED_TASKS.discard)
_LOGIN_WALL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:log\s*in|login|sign\s*in|signin)\b.{0,80}"
        r"\b(?:to\s+(?:view|continue|see)|required|profile|account)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\b(?:you\s+(?:must|need\s+to)|please)\b.{0,80}"
        r"\b(?:log\s*in|login|sign\s*in|signin)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\b(?:authentication\s+required|login\s+required|private\s+profile|"
        r"private\s+account|this\s+account\s+is\s+private|protected\s+profile)\b",
        re.IGNORECASE,
    ),
)


# ── Phase helpers ─────────────────────────────────────────────────────────


def _should_render(platform: Platform, cfg: ScanConfig) -> bool:
    if not _selected_browser_available(cfg):
        return False
    if platform.check_type == "json_api":
        return False
    # Explicit rendering always wins. Automatic rendering for catalogued
    # JS-heavy sites can be disabled for deterministic/offline operation.
    return bool(cfg.playwright or (platform.js_heavy and not cfg.no_auto_render))


def _selected_browser_available(cfg: ScanConfig) -> bool:
    if cfg.browser_backend == "obscura":
        return obscura_fallback.is_available()
    return PLAYWRIGHT_AVAILABLE


async def _fetch_rendered_with_backend(
    cfg: ScanConfig,
    url: str,
    *,
    wait_for_selector: str | None,
    timeout_ms: int,
    proxy: str | None,
    screenshot_dir: Path | None,
    screenshot_name: str | None,
):
    if cfg.browser_backend == "obscura":
        return await obscura_fallback.fetch_rendered(
            url,
            wait_for_selector=wait_for_selector,
            timeout_ms=timeout_ms,
            proxy=proxy,
            screenshot_dir=screenshot_dir,
            screenshot_name=screenshot_name,
        )
    return await fetch_rendered(
        url,
        wait_for_selector=wait_for_selector,
        timeout_ms=timeout_ms,
        proxy=proxy,
        screenshot_dir=screenshot_dir,
        screenshot_name=screenshot_name,
    )


def _screenshot_dir_for(cfg: ScanConfig) -> Path | None:
    if not cfg.screenshots:
        return None
    base = cfg.screenshot_dir or "reports/screenshots"
    return Path(base) / cfg.username


def _any_absence_match(body: str, strings: tuple[str, ...]) -> bool:
    """Return True if any absence indicator is found in *body*."""
    if not strings or not body:
        return False
    body_lower = body.lower()
    return any(s.lower() in body_lower for s in strings)


def _any_presence_match(body: str, strings: tuple[str, ...]) -> bool:
    """Return True if any presence indicator is found in *body*."""
    if not strings or not body:
        return False
    return any(s in body for s in strings)


def _canonical_username_from_payload(data: object, expected: str) -> str | None:
    """Extract the provider's canonical handle from a small API payload.

    Search/list endpoints are deliberately not treated as exact simply because
    they returned a row: an exact case-insensitive handle match is preferred,
    and a different first row is retained so the contract gate can reject it.
    """
    rows = data if isinstance(data, list) else [data]
    candidates: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("username", "login", "user", "handle", "uniqueId"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip().lstrip("@"))
                break
    return next(
        (value for value in candidates if value.casefold() == expected.casefold()),
        candidates[0] if candidates else None,
    )


_PATTERN_CACHE: dict[str, re.Pattern[str] | None] = {}
"""Compiled regex cache for platform username_pattern fields. None = tried and failed."""


def _username_matches_platform(username: str, platform: Platform) -> bool:
    """Check whether *username* conforms to *platform.username_pattern*.

    Returns True when there is no pattern (don't filter) or the pattern matches.
    """
    pattern = platform.username_pattern
    if not pattern:
        return True
    if pattern not in _PATTERN_CACHE:
        try:
            _PATTERN_CACHE[pattern] = re.compile(pattern)
        except re.error:
            _PATTERN_CACHE[pattern] = None
            log.debug("invalid username_pattern for %s: %s", platform.name, pattern)
            return True
    compiled = _PATTERN_CACHE[pattern]
    if compiled is None:
        return True
    return bool(compiled.fullmatch(username))


async def _check_platform(
    client: HTTPClient,
    cfg: ScanConfig,
    platform: Platform,
    context: ScanContext | None = None,
) -> PlatformResult:
    if context is None:
        # Backwards-compatible direct helper calls share the legacy test cache;
        # run_scan always supplies a fresh context.
        context = ScanContext(
            negative_cache=_NEGATIVE_CACHE,
            soft_404_cache=_soft_404_cache(),
        )
    username = cfg.username
    url = platform.url.replace("{username}", username)
    result = PlatformResult(
        platform=platform.name,
        url=url,
        category=platform.category,
        queried_username=username,
        evidence_class=platform.evidence_class,
        entity_scope=platform.entity_scope,
        contract_revision=platform.contract_revision,
        confirmation_capable=supports_confirmation(platform),
    )
    login_required = False

    if not platform.automated:
        if platform.auth_mode == "required":
            result.status = "unavailable_auth"
            result.probe_outcome = ProbeOutcome.UNAVAILABLE_AUTH
        else:
            result.status = "unavailable_policy"
            result.probe_outcome = ProbeOutcome.UNAVAILABLE_POLICY
        result.fp_signals = ["automated_lookup_disabled"]
        return result

    if cfg.skip_invalid_usernames:
        if not _username_matches_platform(username, platform):
            result.status = "invalid_username"
            result.fp_signals = ["username_pattern_mismatch"]
            return result
        if _is_known_not_found(username, platform.name, context=context):
            result.status = "cached_not_found"
            result.fp_signals = ["negative_cache_hit"]
            return result

    try:
        if platform.check_type == "json_api":
            import json as _json
            if platform.probe_method == "POST" and platform.probe_body:
                _body_str = _json.dumps(platform.probe_body, separators=(",", ":")).replace("{username}", username)
                status, data, elapsed = await client.post_json(
                    url, _json.loads(_body_str), platform.headers
                )
            else:
                status, data, elapsed = await client.get_json(url, platform.headers)
            result.http_status = status
            result.response_time = elapsed
            result.exists = status == 200 and data is not None
            result.canonical_username = _canonical_username_from_payload(data, username)
            result.contract_verified = bool(
                result.canonical_username
                and result.canonical_username.casefold() == username.casefold()
            )
            if result.exists and data is not None and (platform.absence_strings or platform.presence_strings):
                _data_text = _json.dumps(data, separators=(",", ":"))
                absent = _any_absence_match(_data_text, platform.absence_strings)
                if absent:
                    result.exists = False
                    result.status = "not_found"
                    result.fp_signals = ["json_api_absence"]
        else:
            status = -1
            body: str = ""
            elapsed = 0.0
            final_url: str | None = None

            # Quick API probe (url_probe) — skip heavy fetch when the profile clearly doesn't exist.
            if platform.url_probe:
                probe_url = platform.url_probe.replace("{username}", username)
                try:
                    if platform.probe_method == "POST" and platform.probe_body:
                        import json as _json
                        _body_str = _json.dumps(platform.probe_body, separators=(",", ":")).replace("{username}", username)
                        _probe_status, _probe_data, _probe_elapsed = await client.post_json(
                            probe_url, _json.loads(_body_str), platform.headers
                        )
                    else:
                        _probe_status, _probe_data, _probe_elapsed = await client.get_json(
                            probe_url, platform.headers
                        )
                except Exception:
                    _probe_status, _probe_data, _probe_elapsed = -1, None, 0.0
                if _probe_status != 200:
                    result.http_status = _probe_status
                    result.response_time = _probe_elapsed
                    result.exists = False
                    if _probe_status in (401, 403):
                        result.status = "unavailable_auth"
                    elif _probe_status == 429:
                        result.status = "blocked"
                    elif _probe_status in (-1, 0) or _probe_status >= 500:
                        result.status = "error"
                    else:
                        result.status = "not_found"
                    return result
                result.canonical_username = _canonical_username_from_payload(
                    _probe_data, username
                )
                result.contract_verified = bool(
                    result.canonical_username
                    and result.canonical_username.casefold() == username.casefold()
                )
                if _probe_data is not None and platform.absence_strings:
                    import json as _json
                    _probe_text = _json.dumps(
                        _probe_data, separators=(",", ":"), ensure_ascii=False
                    ) if isinstance(_probe_data, dict | list) else str(_probe_data)
                    if _any_absence_match(_probe_text, platform.absence_strings):
                        result.http_status = _probe_status
                        result.response_time = _probe_elapsed
                        result.exists = False
                        result.status = "not_found"
                        result.fp_signals = ["url_probe_absence"]
                        return result

            if _should_render(platform, cfg):
                t0 = time.monotonic()
                rendered = await _fetch_rendered_with_backend(
                    cfg,
                    url,
                    wait_for_selector=platform.wait_for_selector,
                    timeout_ms=max(5000, cfg.request_timeout * 1000),
                    proxy=cfg.proxy,
                    screenshot_dir=_screenshot_dir_for(cfg),
                    screenshot_name=platform.name,
                )
                elapsed = time.monotonic() - t0
                if rendered is not None:
                    status = rendered.status
                    body = rendered.html
                    result.rendered = True
                    result.screenshot_path = rendered.screenshot_path
                    final_url = getattr(rendered, "final_url", None)

            if not result.rendered:
                if hasattr(client, "get_with_meta"):
                    status, body, elapsed, final_url = await client.get_with_meta(
                        url, platform.headers
                    )
                else:
                    # Test stubs and older clients only expose get(); skip
                    # final-URL detection in that case.
                    status, body, elapsed = await client.get(url, platform.headers)
                    final_url = None

            # Auto-fallback to a headless browser when the aiohttp response
            # looks like a CDN challenge or empty SPA shell. Only fires when
            # we didn't already render (i.e., js_heavy=False) and a browser
            # backend is wired up.
            if (
                not result.rendered
                and body
                and _selected_browser_available(cfg)
                and not cfg.no_auto_render
            ):
                wall, reason = looks_like_js_wall(body, headers=None, status=status)
                if wall:
                    log.debug(
                        "auto-fallback to browser for %s (reason=%s)",
                        platform.name,
                        reason,
                    )
                    t0 = time.monotonic()
                    rendered = await _fetch_rendered_with_backend(
                        cfg,
                        url,
                        wait_for_selector=platform.wait_for_selector,
                        timeout_ms=max(5000, cfg.request_timeout * 1000),
                        proxy=cfg.proxy,
                        screenshot_dir=_screenshot_dir_for(cfg),
                        screenshot_name=platform.name,
                    )
                    elapsed += time.monotonic() - t0
                    if rendered is not None:
                        status = rendered.status
                        body = rendered.html
                        result.rendered = True
                        result.screenshot_path = rendered.screenshot_path
                        final_url = getattr(rendered, "final_url", None) or final_url
                        result.fp_signals = list(result.fp_signals) + [
                            f"auto_render:{reason}"
                        ]

            result.http_status = status
            result.final_url = final_url if final_url and final_url != url else None
            if platform.check_type == "status":
                result.exists = status == 200
                # Honour maigret's absence_strings even for status-type platforms.
                # Many sites return 200 with an empty profile page rather than a
                # proper 404, so a message-based absent check is more reliable.
                if result.exists and body and platform.absence_strings:
                    if _any_absence_match(body, platform.absence_strings):
                        result.exists = False
                        result.status = "soft_404_message"
                        result.fp_signals = list(result.fp_signals) + ["maigret_absence_match"]
            elif platform.check_type == "content_absent":
                absent = (platform.error_text and platform.error_text in body) or _any_absence_match(body, platform.absence_strings)
                result.exists = status == 200 and not absent
            elif platform.check_type == "content_present":
                present = (platform.success_text and platform.success_text in body) or _any_presence_match(body, platform.presence_strings)
                result.exists = status == 200 and present

            # Soft-404 detection via redirect to a URL that doesn't carry the username.
            redirected_off = _looks_redirected_off(url, final_url, username)
            if result.exists and redirected_off and platform.check_type == "status":
                result.exists = False
                result.status = "soft_404_redirected"
                result.fp_signals = list(result.fp_signals) + ["redirect_off_target"]

            # SPA / generic-page guard: if the page says the profile exists but
            # doesn't even mention the username, it's almost certainly a false
            # match (empty SPA shell, login page, search page, etc.).
            if result.exists and body and username.lower() not in body.lower():
                result.exists = False
                result.status = "username_not_in_body"
                result.fp_signals = list(result.fp_signals) + ["username_absent"]

            login_required = result.exists and _looks_login_required(status, body)
            if login_required:
                result.exists = False
                result.confidence = 0.0
                result.fp_signals = ["login_required"]

            # Opportunistic profile parsing: if the upstream socid_extractor
            # recognises this HTML, pull out names/emails/links for free.
            if result.exists and body and _extract_available():
                extracted = extract_profile(body)
                if extracted:
                    result.profile_data = extracted

            # False-positive scoring on any positive match.
            if result.exists and body:
                fp = score_match(
                    username=username,
                    body=body,
                    check_type=platform.check_type,
                    http_status=status,
                )
                result.confidence = fp.confidence
                result.fp_signals = list(result.fp_signals) + list(fp.signals)
                # Penalise off-target redirects even when content checks passed,
                # but only as a soft signal here (not a hard exists=False).
                if redirected_off:
                    result.confidence = max(0.0, result.confidence - 0.3)
                    result.fp_signals.append("redirect_off_target")

            # Profile liveness — penalise empty shells (avatar+bio+og absent).
            # Only judges; never hard-fails. The FP threshold drop happens in
            # _phase_platform_check based on the recorded score.
            if result.exists and (body or result.profile_data):
                liveness = score_liveness(
                    username=username,
                    body=body,
                    profile_data=result.profile_data,
                )
                result.is_active_profile = liveness.is_active
                result.fp_signals = list(result.fp_signals) + [
                    f"liveness:{liveness.score:.2f}"
                ] + list(liveness.signals)
                if not liveness.is_active:
                    # Pull confidence down so the FP threshold catches it,
                    # but only by a moderate amount — content-based check_type
                    # platforms (content_present/content_absent) already
                    # passed a real signal so we don't want to obliterate them.
                    penalty = 0.25 if platform.check_type == "status" else 0.15
                    result.confidence = max(0.0, result.confidence - penalty)

            # Soft-404 fingerprint comparison — uses cached baselines.
            # Lazily seeds the baseline (fire-and-forget) when first encountering
            # a status-only platform with no cached fingerprint.
            if result.exists and body and platform.check_type == "status":
                cache = context.soft_404_cache
                baseline = cache.get(platform.name)
                if baseline is not None:
                    soft, reason = is_soft_404(
                        platform=platform.name,
                        status=status,
                        body=body,
                        real_username=username,
                        baseline=baseline,
                    )
                    if soft:
                        result.exists = False
                        result.status = "soft_404_template"
                        if reason:
                            result.fp_signals = list(result.fp_signals) + [reason]
                else:
                    # Kick off a background probe so the next scan benefits.
                    context.track_seed(
                        asyncio.create_task(
                            _seed_soft_404_baseline(client, platform, context=context)
                        )
                    )

            # Playwright re-check for ambiguous aiohttp responses (short body = likely JS shell).
            if (
                not result.rendered
                and result.exists
                and _selected_browser_available(cfg)
                and not cfg.no_auto_render
                and (platform.absence_strings or platform.presence_strings)
                and len(body) < 500
            ):
                t0 = time.monotonic()
                rendered = await _fetch_rendered_with_backend(
                    cfg, url,
                    wait_for_selector=platform.wait_for_selector,
                    timeout_ms=max(5000, cfg.request_timeout * 1000),
                    proxy=cfg.proxy,
                    screenshot_dir=_screenshot_dir_for(cfg),
                    screenshot_name=platform.name,
                )
                elapsed += time.monotonic() - t0
                if rendered is not None and rendered.html:
                    result.rendered = True
                    status = rendered.status
                    body = rendered.html
                    result.screenshot_path = rendered.screenshot_path
                    final_url = getattr(rendered, "final_url", None) or final_url
                    result.fp_signals = list(result.fp_signals) + ["playwright_recheck"]
                    if platform.check_type == "content_absent":
                        absent = (platform.error_text and platform.error_text in body) or _any_absence_match(body, platform.absence_strings)
                        result.exists = status == 200 and not absent
                    elif platform.check_type == "content_present":
                        present = (platform.success_text and platform.success_text in body) or _any_presence_match(body, platform.presence_strings)
                        result.exists = status == 200 and present
                    # Re-score after render — the rendered body has real content
                    if result.exists:
                        # Username must be in the rendered body
                        if username.lower() not in body.lower():
                            result.exists = False
                            result.status = "username_not_in_body"
                            result.fp_signals = list(result.fp_signals) + ["username_absent", "pw_rescore"]
                        else:
                            fp = score_match(
                                username=username,
                                body=body,
                                check_type=platform.check_type,
                                http_status=status,
                            )
                            result.confidence = fp.confidence
                            result.fp_signals = list(result.fp_signals) + ["pw_rescore"] + list(fp.signals)
                            liveness = score_liveness(
                                username=username,
                                body=body,
                                profile_data=result.profile_data,
                            )
                            result.is_active_profile = liveness.is_active
                            result.fp_signals = result.fp_signals + [
                                f"liveness:{liveness.score:.2f}"
                            ] + list(liveness.signals)
                            if not liveness.is_active:
                                penalty = 0.25 if platform.check_type == "status" else 0.15
                                result.confidence = max(0.0, result.confidence - penalty)

        if result.status == "pending":
            result.status = (
                "unavailable_auth"
                if login_required
                else _status_from_http(status, result.exists)
            )
    except (asyncio.TimeoutError, OSError) as exc:
        log.debug("platform %s errored: %s", platform.name, exc)
        result.status = "error"
    except Exception as exc:
        log.warning("unexpected error checking %s: %s", platform.name, exc)
        result.status = "error"

    if not result.exists and result.status not in ("error",):
        _mark_not_found(username, platform.name, context=context)

    return result


async def _check_platform_for_context(
    client: HTTPClient,
    cfg: ScanConfig,
    platform: Platform,
    context: ScanContext | None,
) -> PlatformResult:
    """Keep monkeypatched/legacy three-argument checkers compatible."""
    if context is not None and has_provider(platform.name):
        try:
            batch = await lookup_provider_many(
                client,
                platform.name,
                [cfg.username],
                context.provider_credentials,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning(
                "provider %s lookup failed (%s)",
                platform.name,
                type(exc).__name__,
            )
            return PlatformResult(
                platform=platform.name,
                url=platform.url.replace("{username}", cfg.username),
                category=platform.category,
                status="error",
                queried_username=cfg.username,
                fp_signals=["provider_adapter_error"],
            )
        if batch is not None:
            context.provider_http_requests += batch.http_request_count
            observation = batch.observations.get(cfg.username)
            if observation is not None:
                return observation.to_platform_result(platform)
    if context is None:
        return await _check_platform(client, cfg, platform)
    return await _check_platform(client, cfg, platform, context=context)


async def _seed_soft_404_baseline(
    client: HTTPClient,
    platform: Platform,
    *,
    context: ScanContext | None = None,
) -> None:
    """Fire-and-forget probe to populate the soft-404 baseline cache.

    Fetches the platform URL with an impossible username, fingerprints the
    body, and persists it for the next scan. Runs concurrently with the
    main sweep so it does not slow the current scan.
    """
    try:
        probe_url = platform.url.replace("{username}", IMPOSSIBLE_USERNAME)
        if not hasattr(client, "get_with_meta"):
            return
        status, body, _elapsed, _final = await client.get_with_meta(
            probe_url, platform.headers
        )
        if not body or status not in (200, 404):
            return
        baseline = make_baseline(
            platform=platform.name,
            status=status,
            body=body,
            probe_username=IMPOSSIBLE_USERNAME,
        )
        (context.soft_404_cache if context is not None else _soft_404_cache()).put(baseline)
        log.debug("seeded soft-404 baseline for %s", platform.name)
    except Exception as exc:
        log.debug("soft-404 seed failed for %s: %s", platform.name, exc)


def _looks_redirected_off(
    requested_url: str, final_url: str | None, username: str
) -> bool:
    """Return True when the server redirected us to a URL that doesn't carry
    the username (typical soft-404: ``/u/xyz`` → ``/explore`` or ``/login``).

    Conservative — only fires when:
      * final_url is known and differs from requested_url
      * the username (case-insensitive) is absent from the final URL
      * the final URL path looks "generic" (root, /login, /explore, /404, /not-found)
    """
    if not final_url or final_url == requested_url:
        return False
    final_lower = final_url.lower()
    if username.lower() in final_lower:
        return False
    try:
        parsed = urlparse(final_lower)
    except ValueError:
        return False
    path = parsed.path.rstrip("/")
    if not path:
        return True  # bare host = root redirect
    suspicious = (
        "/login", "/signin", "/sign-in", "/explore", "/404", "/not-found",
        "/error", "/home", "/search", "/discover", "/oops",
    )
    return any(path.endswith(s) or s in path for s in suspicious)


_HANDLE_PROBE_PLATFORMS: frozenset[str] = frozenset(
    {
        "GitHub", "X", "Instagram", "Reddit", "TikTok",
        "YouTube", "LinkedIn", "Telegram", "Steam", "Twitch",
        "Pinterest", "Medium", "Dev.to", "Keybase", "Mastodon",
        "GitLab", "Hacker News", "StackOverflow", "Quora", "Vimeo",
    }
)


async def _phase_profile_validate(
    cfg: ScanConfig,
    result: ScanResult,
    context: ScanContext | None = None,
) -> None:
    """LLM-augmented verdict on borderline-confidence profile matches.

    Only runs when ``cfg.ai_skills`` is on. Sends each platform with a
    confidence in the uncertain band (0.45 ≤ conf ≤ 0.70) to the
    ``profile_validator`` skill. The skill's verdict NEVER hard-deletes a
    match — at worst it lowers confidence below the FP threshold; at best
    it boosts borderline matches by up to +0.15.

    Skill backends are async; validation concurrency is bounded below so a
    scan cannot burst the configured endpoint.
    """
    if not cfg.ai_skills:
        return
    try:
        from core.analysis.skill_loader import SkillBudget, SkillError, run_skill
    except ImportError:
        log.debug("skill_loader unavailable; skipping profile_validate phase")
        return

    borderline = [
        p for p in result.platforms
        if (p.verification or {}).get("verdict") == "uncertain"
        and p.status == "uncertain"
    ]
    if not borderline:
        return

    budget = (
        context.skill_budget
        if context is not None and context.skill_budget is not None
        else SkillBudget(limit=cfg.ai_skill_budget)
    )
    console.print(
        f"  [bold yellow][ai][/bold yellow] Profile validation: "
        f"{len(borderline)} borderline match(es), budget={budget.limit}..."
    )

    async def _validate_one(p: PlatformResult) -> None:
        inputs = {
            "target": {
                "username": cfg.username,
                "full_name": cfg.full_name or "",
                "known_emails": [e.email for e in result.emails][:5],
                "known_locations": list(result.cross_reference.matched_locations)[:3],
            },
            "profile": {
                "platform": p.platform,
                "url": p.url,
                "display_name": p.profile_data.get("name")
                or p.profile_data.get("display_name", ""),
                "bio": p.profile_data.get("bio")
                or p.profile_data.get("description", ""),
                "location": p.profile_data.get("location", ""),
                "followers": p.profile_data.get("followers", 0),
                "linked_accounts": [
                    p.profile_data.get(k, "")
                    for k in ("twitter_username", "github_username")
                    if p.profile_data.get(k)
                ],
            },
        }
        try:
            out = await run_skill(
                "profile_validator", inputs, budget=budget
            )
        except SkillError as exc:
            log.debug("profile_validator failed for %s: %s", p.platform, exc)
            return
        score = int(out.get("match_score", 0))
        verdict = str(out.get("verdict", "uncertain"))
        signals = list(out.get("signals", []))
        red_flags = list(out.get("red_flags", []))
        # Boost or penalise within a bounded range. Never push to 1.0 or below 0.
        if verdict in ("match", "likely_match"):
            delta = 0.10 if verdict == "likely_match" else 0.15
            p.confidence = min(1.0, p.confidence + delta)
        elif verdict in ("likely_other", "other"):
            penalty = 0.20 if verdict == "likely_other" else 0.35
            p.confidence = max(0.0, p.confidence - penalty)
        p.fp_signals = list(p.fp_signals) + [
            f"ai_verdict:{verdict}",
            f"ai_score:{score}",
        ]
        if red_flags:
            p.fp_signals.append("ai_red_flags:" + ",".join(red_flags[:3]))
        if signals:
            p.fp_signals.append("ai_signals:" + "|".join(signals[:3]))
        # AI may refine only an uncertain score. Deterministic hard-negative
        # rows never enter this phase and therefore cannot be resurrected.
        platform = _platform_by_name(p.platform)
        if platform is not None:
            _evaluate_platform_result(p, platform, cfg)

    # Bound parallelism so we don't burst the LLM endpoint.
    sem = asyncio.Semaphore(4)

    async def _bounded(p: PlatformResult) -> None:
        async with sem:
            await _validate_one(p)

    await asyncio.gather(*(_bounded(p) for p in borderline), return_exceptions=True)
    console.print(
        f"  [bold green][ai][/bold green] Profile validation: "
        f"{budget.used}/{budget.limit} LLM calls used"
    )


async def _phase_handle_resolve(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    result: ScanResult,
    context: ScanContext | None = None,
) -> ScanConfig:
    """Resolve a real name into the most likely username via quick probes.

    Triggered when ``cfg.full_name`` is set. Generates candidate handles
    (deterministic permutations + diacritic folding), probes each against a
    curated set of high-signal platforms, and returns a new ``ScanConfig``
    pointing at the best candidate. Findings from the probe phase are
    folded into ``result.platforms`` so the user sees what we tried.

    The full platform sweep then runs against the chosen handle as usual.
    """
    if not cfg.full_name:
        return cfg
    from modules.recon.handle_generator import generate as _gen_handles

    candidates = _gen_handles(
        cfg.full_name,
        year=cfg.name_year,
        max_candidates=max(cfg.name_max_handles * 2, 8),
    )
    if not candidates:
        log.debug("handle generator returned nothing for %r", cfg.full_name)
        return cfg

    # Probe set: high-signal platforms only — we want to spend N×M HTTP
    # requests, not catalogue×N. Pick handles up to name_max_handles after the
    # quick probe.
    probe_targets = [p for p in platforms if p.name in _HANDLE_PROBE_PLATFORMS]
    if not probe_targets:
        probe_targets = platforms[:20]  # fallback when categories filter is set
    top_candidates = candidates[: max(cfg.name_max_handles, 3)]

    console.print(
        f"  [bold yellow][0/8][/bold yellow] Name → handle: probing "
        f"{len(top_candidates)} candidate(s) on {len(probe_targets)} platforms..."
    )
    _emit(
        "phase_start",
        phase="handle_resolve",
        candidates=len(top_candidates),
        probe_targets=len(probe_targets),
    )

    scoreboard: list[tuple[str, float, int, list[PlatformResult]]] = []
    for cand in top_candidates:
        probe_cfg = replace(cfg, username=cand.handle, full_name=None)
        probe_tasks = [
            _check_platform_for_context(client, probe_cfg, p, context)
            for p in probe_targets
        ]
        probe_results = await asyncio.gather(*probe_tasks)
        for probe_result, platform in zip(
            probe_results, probe_targets, strict=True
        ):
            _evaluate_platform_result(probe_result, platform, cfg)
        hits = [r for r in probe_results if r.exists]
        # Score = sum of confidence × candidate.score so high-likelihood handles
        # with strong site signals win, but a low-rank handle with multiple solid
        # hits can also surface.
        total = sum(r.confidence for r in hits) * (0.5 + 0.5 * cand.score)
        scoreboard.append((cand.handle, total, len(hits), hits))

    scoreboard.sort(key=lambda row: (row[1], row[2]), reverse=True)
    best_handle, best_score, best_hit_count, best_hits = scoreboard[0]

    # Persist what we tried so the report shows the resolution.
    result.discovered_usernames = [row[0] for row in scoreboard if row[2] > 0]
    result.variations_checked = [c.handle for c in candidates]
    for r in best_hits:
        r.status = f"{r.status} (resolved-from-name)"
        result.platforms.append(r)

    console.print(
        f"  [bold green][0/8][/bold green] Resolved: [bold]{best_handle}[/bold] "
        f"(score={best_score:.2f}, {best_hit_count} hits)"
    )
    _emit(
        "phase_end",
        phase="handle_resolve",
        chosen=best_handle,
        score=round(best_score, 2),
        hits=best_hit_count,
    )

    if cfg.username and cfg.username.strip().lower() != best_handle.lower():
        console.print(
            f"  [bold cyan][0/8][/bold cyan] Keeping original username "
            f"[bold]{cfg.username}[/bold] for main sweep; "
            f"[bold]{best_handle}[/bold] queued as variation."
        )
        return replace(cfg, full_name=None)

    return replace(cfg, username=best_handle)


def _status_from_http(status: int, exists: bool) -> str:
    if status == 0:
        return "timeout"
    if status == -1:
        return "error"
    if status in (401, 403):
        return "unavailable_auth"
    if status == 429:
        return "blocked"
    if status >= 500:
        return "error"
    return "found" if exists else "not_found"


# Per-scan negative cache: username -> set of platform names that returned 404/not_found.
# Cleared at the start of each scan; used by recursive/deep phases to avoid
# re-checking platforms that already failed for a given username.
_NEGATIVE_CACHE: dict[str, set[str]] = {}


def _mark_not_found(
    username: str,
    platform_name: str,
    *,
    context: ScanContext | None = None,
) -> None:
    cache = context.negative_cache if context is not None else _NEGATIVE_CACHE
    cache.setdefault(username, set()).add(platform_name)


def _is_known_not_found(
    username: str,
    platform_name: str,
    *,
    context: ScanContext | None = None,
) -> bool:
    cache = context.negative_cache if context is not None else _NEGATIVE_CACHE
    return platform_name in cache.get(username, set())


def _clear_negative_cache() -> None:
    _NEGATIVE_CACHE.clear()


def _looks_login_required(status: int, body: str) -> bool:
    if status in (401, 403):
        return True
    if status != 200 or not body:
        return False
    return any(pattern.search(body) for pattern in _LOGIN_WALL_PATTERNS)


async def _deep_scrape(
    client: HTTPClient, username: str, platform_result: PlatformResult
) -> dict:
    scraper = DEEP_SCRAPERS.get(platform_result.platform)
    if not scraper:
        return {}
    try:
        return await scraper(client, username)
    except Exception as exc:
        log.debug("deep scrape %s failed: %s", platform_result.platform, exc)
        return {}


def _extract_avatar_urls(platforms: list[PlatformResult]) -> list[tuple[str, str]]:
    avatars: list[tuple[str, str]] = []
    for p in platforms:
        if not p.profile_data:
            continue
        for key in AVATAR_KEYS:
            url = p.profile_data.get(key, "")
            if url and isinstance(url, str) and url.startswith("http"):
                avatars.append((p.platform, url))
                break
    return avatars


def _select_platforms(
    categories: tuple[str, ...] | None,
    platform_scope: str = "core",
) -> list[Platform]:
    """Select only from the deterministic checked-in catalogue metadata."""
    if categories == ("__all__",):
        return list(PLATFORMS)
    if categories == ("__popular__",):
        return _popular_platforms()
    if categories == ("__verified__",):
        return _verified_platforms()
    if categories:
        # Explicit category filters preserve their legacy meaning: search every
        # curated platform in those categories, independent of the default core
        # scope. Callers wanting all categories use platform_scope/full instead.
        return [p for p in PLATFORMS if p.category in categories]
    scope = "full" if platform_scope == "full" else "core"
    return [p for p in PLATFORMS if scope == "full" or p.tier == "core"]


_VERIFIED_CACHE: list[Platform] | None = None


def _verified_platforms() -> list[Platform]:
    """Legacy selector backed by deterministic wire-contract metadata."""
    global _VERIFIED_CACHE
    if _VERIFIED_CACHE is not None:
        return _VERIFIED_CACHE
    _VERIFIED_CACHE = [
        platform
        for platform in PLATFORMS
        if (
            platform.url_probe
            or platform.check_type == "json_api"
            or (platform.absence_strings and platform.presence_strings)
            or platform.golden_fixture
        )
    ]
    return _VERIFIED_CACHE


_POPULAR_CACHE: list[Platform] | None = None


def _popular_platforms() -> list[Platform]:
    global _POPULAR_CACHE
    if _POPULAR_CACHE is not None:
        return _POPULAR_CACHE
    _POPULAR_CACHE = [platform for platform in PLATFORMS if platform.tier == "core"]
    return _POPULAR_CACHE


def _platform_by_name(name: str) -> Platform | None:
    return next((platform for platform in PLATFORMS if platform.name == name), None)


def _initial_confirmation_allowed(platform: Platform) -> bool:
    """Compatibility wrapper for the fail-closed provider contract gate."""
    return supports_confirmation(platform)


def _result_username(result: PlatformResult, platform: Platform) -> str:
    if result.queried_username:
        return result.queried_username
    prefix, marker, suffix = platform.url.partition("{username}")
    if marker and result.url.startswith(prefix) and result.url.endswith(suffix):
        end = len(result.url) - len(suffix) if suffix else len(result.url)
        return result.url[len(prefix):end]
    return ""


def _set_probe_outcome(result: PlatformResult) -> None:
    verdict = (result.verification or {}).get("verdict")
    status = result.status.split(" ", 1)[0]
    if verdict == "confirmed":
        result.probe_outcome = ProbeOutcome.FOUND
    elif status in {"unavailable_auth", "login_required"}:
        result.probe_outcome = ProbeOutcome.UNAVAILABLE_AUTH
    elif status == "unavailable_policy":
        result.probe_outcome = ProbeOutcome.UNAVAILABLE_POLICY
    elif status == "blocked":
        result.probe_outcome = (
            ProbeOutcome.RATE_LIMITED
            if result.http_status == 429
            else ProbeOutcome.BLOCKED
        )
    elif status in {"error", "timeout", "pending"}:
        result.probe_outcome = ProbeOutcome.ERROR
    elif status == "invalid_username":
        result.probe_outcome = ProbeOutcome.INVALID
    elif status == "contract_mismatch":
        result.probe_outcome = ProbeOutcome.CONTRACT_BROKEN
    elif verdict == "uncertain":
        result.probe_outcome = ProbeOutcome.AMBIGUOUS
    else:
        result.probe_outcome = ProbeOutcome.NOT_FOUND


def _evaluate_platform_result(
    result: PlatformResult,
    platform: Platform,
    cfg: ScanConfig,
    *,
    deep_scraped: bool = False,
) -> None:
    result.evidence_class = platform.evidence_class
    result.entity_scope = platform.entity_scope
    result.contract_revision = platform.contract_revision
    result.confirmation_capable = supports_confirmation(platform)
    expected_username = _result_username(result, platform)
    canonical = _canonical_username_from_payload(result.profile_data, expected_username)
    if canonical:
        result.canonical_username = canonical
    if result.canonical_username and expected_username:
        result.contract_verified = (
            result.canonical_username.casefold() == expected_username.casefold()
        )
        if not result.contract_verified:
            result.exists = False
            result.status = "contract_mismatch"
            result.fp_signals = list(result.fp_signals) + ["canonical_username_mismatch"]

    presence_contract_verified = bool(
        result.confirmation_capable
        and (result.contract_verified or platform.golden_fixture)
    )
    evaluate_platform(
        result,
        threshold=cfg.fp_threshold,
        trusted=deep_scraped and presence_contract_verified,
        allow_confirmed=presence_contract_verified,
    )
    result.verification["provider_contract"] = {
        "evidence_class": platform.evidence_class,
        "entity_scope": platform.entity_scope,
        "lookup_semantics": platform.lookup_semantics,
        "auth_mode": platform.auth_mode,
        "revision": platform.contract_revision,
        "canonical_username": result.canonical_username,
        "verified": result.contract_verified,
        "confirmation_capable": result.confirmation_capable,
    }
    _set_probe_outcome(result)


# ── Phase implementations ────────────────────────────────────────────────


async def _phase_platform_check(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    result: ScanResult,
    context: ScanContext | None = None,
) -> list[PlatformResult]:
    console.print("  [bold yellow][1/8][/bold yellow] Starting platform sweep...")
    _emit("phase_start", phase="platform_sweep", total=len(platforms))
    tasks = [_check_platform_for_context(client, cfg, p, context) for p in platforms]
    platform_results = await asyncio.gather(*tasks)

    dropped = 0
    for r, platform in zip(platform_results, platforms, strict=True):
        was_candidate = r.exists
        _evaluate_platform_result(r, platform, cfg)
        if was_candidate and (r.verification or {}).get("verdict") == "uncertain":
            dropped += 1

    found_count = sum(1 for r in platform_results if r.exists)
    suffix = f", [yellow]{dropped}[/yellow] dropped by FP filter" if dropped else ""
    console.print(
        f"  [bold green][1/8][/bold green] Done: "
        f"[green]{found_count}[/green]/{len(platform_results)} platforms matched{suffix}"
    )
    result.platforms = list(platform_results)
    _emit(
        "phase_end",
        phase="platform_sweep",
        found=found_count,
        total=len(platform_results),
        dropped=dropped,
    )
    return platform_results


async def _phase_deep_scrape(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
) -> None:
    if not cfg.deep:
        console.print("  [dim][2/8] Deep scrape: skipped[/dim]")
        return

    targets = [
        r
        for r in platform_results
        if r.platform in DEEP_SCRAPERS
        and not has_provider(r.platform)
        and (
            (platform := _platform_by_name(r.platform)) is not None
            and platform.automated
        )
        and (
            r.exists
            or (r.verification or {}).get("verdict") == "uncertain"
        )
    ]
    if not targets:
        console.print("  [bold green][2/8][/bold green] Deep scrape: no eligible profiles")
        return

    console.print(
        f"  [bold yellow][2/8][/bold yellow] Deep scrape: analyzing {len(targets)} profiles..."
    )
    deep_results = await asyncio.gather(
        *(_deep_scrape(client, cfg.username, r) for r in targets)
    )
    for target, data in zip(targets, deep_results, strict=True):
        if data:
            # Deep scraper output wins over opportunistic extractor output.
            merged = {**(target.profile_data or {}), **data}
            target.profile_data = merged
            target.exists = True
            target.status = "found"
            target.confidence = max(target.confidence, 0.85)
            platform = _platform_by_name(target.platform)
            if platform is not None:
                _evaluate_platform_result(
                    target, platform, cfg, deep_scraped=True
                )

    scraped = sum(1 for d in deep_results if d)
    console.print(f"  [bold green][2/8][/bold green] Done: {scraped} profile details pulled")


_ALIAS_PRIMARY_CANDIDATE_LIMIT = 12
_ALIAS_FALLBACK_PLATFORM_LIMIT = 5
_STRONG_IDENTITY_VERDICTS = frozenset({"confirmed_same", "likely_same"})


async def _probe_alias_batch(
    client: HTTPClient,
    cfg: ScanConfig,
    candidates: list[UsernameCandidate],
    platforms: list[Platform],
    context: ScanContext | None,
) -> tuple[list[tuple[UsernameCandidate, Platform]], list[PlatformResult]]:
    """Probe one bounded alias tier, batching supported provider APIs."""
    probe_specs = [
        (candidate, platform)
        for candidate in candidates
        for platform in platforms
    ]
    if not probe_specs:
        return [], []

    async def _probe_platform(platform: Platform) -> list[PlatformResult]:
        if context is not None and has_provider(platform.name):
            try:
                batch = await lookup_provider_many(
                    client,
                    platform.name,
                    [candidate.username for candidate in candidates],
                    context.provider_credentials,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "provider %s alias batch failed (%s)",
                    platform.name,
                    type(exc).__name__,
                )
                return [
                    PlatformResult(
                        platform=platform.name,
                        url=platform.url.replace("{username}", candidate.username),
                        category=platform.category,
                        status="error",
                        queried_username=candidate.username,
                        fp_signals=["provider_adapter_error"],
                    )
                    for candidate in candidates
                ]
            if batch is not None:
                context.provider_http_requests += batch.http_request_count
                rows: list[PlatformResult] = []
                for candidate in candidates:
                    observation = batch.observations.get(candidate.username)
                    if observation is None:
                        rows.append(
                            PlatformResult(
                                platform=platform.name,
                                url=platform.url.replace(
                                    "{username}", candidate.username
                                ),
                                category=platform.category,
                                status="error",
                                queried_username=candidate.username,
                                fp_signals=["provider_observation_missing"],
                            )
                        )
                    else:
                        rows.append(observation.to_platform_result(platform))
                return rows
        return list(
            await asyncio.gather(
                *(
                    _check_platform_for_context(
                        client,
                        replace(cfg, username=candidate.username),
                        platform,
                        context,
                    )
                    for candidate in candidates
                )
            )
        )

    platform_rows = await asyncio.gather(
        *(_probe_platform(platform) for platform in platforms)
    )
    by_spec = {
        (candidate.username, platform.name): row
        for platform, rows in zip(platforms, platform_rows, strict=True)
        for candidate, row in zip(candidates, rows, strict=True)
    }
    var_results = [
        by_spec[(candidate.username, platform.name)]
        for candidate, platform in probe_specs
    ]
    for var_result, (_candidate, platform) in zip(
        var_results, probe_specs, strict=True
    ):
        _evaluate_platform_result(var_result, platform, cfg)

    # An official deep scraper can turn a transport-level/heuristic candidate
    # into deterministic presence proof. Empty responses never do.
    deep_specs = [
        (candidate, platform, var_result)
        for var_result, (candidate, platform) in zip(
            var_results, probe_specs, strict=True
        )
        if platform.name in DEEP_SCRAPERS
        and not has_provider(platform.name)
        and platform.automated
        and (
            var_result.exists
            or (var_result.verification or {}).get("verdict") == "uncertain"
        )
    ]
    deep_payloads = await asyncio.gather(
        *(
            _deep_scrape(client, candidate.username, var_result)
            for candidate, _platform, var_result in deep_specs
        )
    )
    for (_candidate, platform, var_result), data in zip(
        deep_specs, deep_payloads, strict=True
    ):
        if not data:
            continue
        var_result.profile_data = {**(var_result.profile_data or {}), **data}
        var_result.exists = True
        var_result.status = "found (variation)"
        var_result.confidence = max(var_result.confidence, 0.85)
        _evaluate_platform_result(var_result, platform, cfg, deep_scraped=True)
    return probe_specs, list(var_results)


def _collect_alias_profiles(
    probe_specs: list[tuple[UsernameCandidate, Platform]],
    var_results: list[PlatformResult],
) -> tuple[dict[str, list[PlatformResult]], list[dict[str, str]]]:
    confirmed_by_username: dict[str, list[PlatformResult]] = {}
    uncertain_profiles: list[dict[str, str]] = []
    for var_result, (candidate, _platform) in zip(
        var_results, probe_specs, strict=True
    ):
        verdict = (var_result.verification or {}).get("verdict")
        if verdict == "confirmed" and var_result.exists:
            var_result.status = "found (variation)"
            confirmed_by_username.setdefault(candidate.username, []).append(var_result)
        elif verdict == "uncertain":
            uncertain_profiles.append(
                {
                    "username": candidate.username,
                    "platform": var_result.platform,
                    "status": var_result.status,
                }
            )
    return confirmed_by_username, uncertain_profiles


def _resolve_alias_candidates(
    *,
    cfg: ScanConfig,
    root_payload: dict[str, Any],
    candidates: list[UsernameCandidate],
    confirmed_by_username: dict[str, list[PlatformResult]],
) -> list[IdentityCandidate]:
    identity_candidates: list[IdentityCandidate] = []
    for candidate in candidates:
        profiles = confirmed_by_username.get(candidate.username, [])
        if not profiles:
            continue
        candidate_payload = {
            "username": candidate.username,
            "platforms": [profile.to_dict() for profile in profiles],
            "emails": [],
            "phone_intel": [],
        }
        candidate_discovery = merge_discoveries(
            [
                extract_discoverable_data(profile.profile_data)
                for profile in profiles
                if profile.profile_data
            ]
        )
        reciprocal_link = cfg.username.casefold() in {
            value.casefold()
            for value in candidate_discovery.get("linked_usernames", [])
            if isinstance(value, str)
        }
        resolution = correlate_identity(
            root_payload,
            candidate_payload,
            handle_score=candidate.handle_similarity,
            direct_link=(
                "linked_profile" in candidate.discovery_reasons or reciprocal_link
            ),
        )
        warnings = []
        if not any(profile.profile_data for profile in profiles):
            warnings.append("confirmed presence has insufficient public profile metadata")
        identity_candidates.append(
            IdentityCandidate(
                username=candidate.username,
                handle_similarity=candidate.handle_similarity,
                discovery_reasons=list(candidate.discovery_reasons),
                verdict=resolution.verdict,
                score=resolution.score,
                evidence=[signal.to_dict() for signal in resolution.signals],
                profiles=profiles,
                warnings=warnings,
            )
        )
    return identity_candidates


async def _phase_smart_search(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    platform_results: list[PlatformResult],
    result: ScanResult,
    context: ScanContext | None = None,
) -> None:
    if not cfg.smart:
        console.print("  [dim][3/8] Smart search: skipped[/dim]")
        return

    console.print("  [bold yellow][3/8][/bold yellow] Starting smart search...")
    wire_start = getattr(client, "request_count", None)
    provider_wire_start = context.provider_http_requests if context is not None else 0

    discoveries = [
        extract_discoverable_data(r.profile_data)
        for r in platform_results
        if r.exists and r.profile_data
    ]
    merged = merge_discoveries(discoveries)
    candidates = generate_candidates(
        cfg.username,
        linked_usernames=merged.get("linked_usernames", []),
        max_candidates=cfg.alias_max_candidates,
    )

    # Prefer the platform object passed into this scan (so user YAML overrides
    # remain effective), then fill missing aliases from the full curated catalog.
    passed_by_name = {platform.name: platform for platform in platforms}
    full_by_name = {platform.name: platform for platform in PLATFORMS}
    check_platforms: list[Platform] = []
    for name in ALIAS_PROBE_PLATFORMS[: cfg.alias_platform_limit]:
        platform = passed_by_name.get(name) or full_by_name.get(name)
        if platform is not None:
            check_platforms.append(platform)
    primary_candidates = candidates[:_ALIAS_PRIMARY_CANDIDATE_LIMIT]
    fallback_candidates = candidates[_ALIAS_PRIMARY_CANDIDATE_LIMIT:]
    batch_extension_platforms = [
        platform
        for platform in check_platforms
        if platform.name in {"X", "Twitch"}
        and context is not None
        and provider_is_configured(
            platform.name, context.provider_credentials
        )
    ]
    batch_extension_names = {
        platform.name for platform in batch_extension_platforms
    }
    primary_regular_platforms = [
        platform
        for platform in check_platforms
        if platform.name not in batch_extension_names
    ]
    fallback_platform_budget = max(
        0, _ALIAS_FALLBACK_PLATFORM_LIMIT - len(batch_extension_platforms)
    )
    fallback_platforms = primary_regular_platforms[:fallback_platform_budget]
    configured_max_probes = (
        len(primary_candidates) * len(primary_regular_platforms)
        + len(candidates) * len(batch_extension_platforms)
        + len(fallback_candidates) * len(fallback_platforms)
    )
    if not candidates or not check_platforms:
        result.variations_checked = []
        result.diagnostics["alias_search"] = {
            "generated_candidate_count": len(candidates),
            "candidate_count": 0,
            "primary_candidate_count": 0,
            "fallback_candidate_count": 0,
            "batch_extended_candidate_count": 0,
            "batch_extension_platform_count": len(batch_extension_platforms),
            "platform_count": len(check_platforms),
            "fallback_platform_count": len(fallback_platforms),
            "probe_count": 0,
            "logical_probe_count": 0,
            "http_request_count": 0,
            "provider_http_request_count": 0,
            "primary_probe_count": 0,
            "fallback_probe_count": 0,
            "fallback_triggered": False,
            "strong_primary": False,
            "confirmed_profiles": 0,
            "identity_candidates": 0,
            "uncertain_profiles": [],
            "max_probes": configured_max_probes,
        }
        console.print("  [bold green][3/8][/bold green] No platforms left to check variations on")
        return

    primary_specs, primary_results = await _probe_alias_batch(
        client,
        cfg,
        primary_candidates,
        primary_regular_platforms,
        context,
    )
    extension_specs, extension_results = await _probe_alias_batch(
        client,
        cfg,
        candidates,
        batch_extension_platforms,
        context,
    )
    primary_specs.extend(extension_specs)
    primary_results.extend(extension_results)
    confirmed_by_username, uncertain_profiles = _collect_alias_profiles(
        primary_specs,
        primary_results,
    )
    root_payload = result.to_dict(include_all=False)
    root_payload["identity_candidates"] = []
    identity_candidates = _resolve_alias_candidates(
        cfg=cfg,
        root_payload=root_payload,
        candidates=(
            candidates if batch_extension_platforms else primary_candidates
        ),
        confirmed_by_username=confirmed_by_username,
    )
    strong_primary = any(
        candidate.verdict in _STRONG_IDENTITY_VERDICTS
        for candidate in identity_candidates
    )

    fallback_triggered = bool(
        fallback_candidates and fallback_platforms and not strong_primary
    )
    fallback_specs: list[tuple[UsernameCandidate, Platform]] = []
    fallback_results: list[PlatformResult] = []
    if fallback_triggered:
        fallback_specs, fallback_results = await _probe_alias_batch(
            client,
            cfg,
            fallback_candidates,
            fallback_platforms,
            context,
        )
        fallback_confirmed, fallback_uncertain = _collect_alias_profiles(
            fallback_specs,
            fallback_results,
        )
        for username, profiles in fallback_confirmed.items():
            confirmed_by_username.setdefault(username, []).extend(profiles)
        uncertain_profiles.extend(fallback_uncertain)
        identity_candidates = _resolve_alias_candidates(
            cfg=cfg,
            root_payload=root_payload,
            candidates=[*primary_candidates, *fallback_candidates],
            confirmed_by_username=confirmed_by_username,
        )

    checked_candidates = [
        *primary_candidates,
        *(
            fallback_candidates
            if fallback_triggered or batch_extension_platforms
            else []
        ),
    ]
    result.variations_checked = [
        candidate.username for candidate in checked_candidates
    ]
    all_probe_specs = [*primary_specs, *fallback_specs]

    result.identity_candidates = identity_candidates
    discovered = list(result.discovered_usernames)
    for identity_candidate in identity_candidates:
        if identity_candidate.username not in discovered:
            discovered.append(identity_candidate.username)
    result.discovered_usernames = discovered
    result.diagnostics["alias_search"] = {
        "generated_candidate_count": len(candidates),
        "candidate_count": len(checked_candidates),
        "primary_candidate_count": len(primary_candidates),
        "fallback_candidate_count": (
            len(fallback_candidates)
            if fallback_triggered or batch_extension_platforms
            else 0
        ),
        "batch_extended_candidate_count": (
            len(fallback_candidates) if batch_extension_platforms else 0
        ),
        "batch_extension_platform_count": len(batch_extension_platforms),
        "platform_count": len(check_platforms),
        "fallback_platform_count": len(fallback_platforms),
        "probe_count": len(all_probe_specs),
        "logical_probe_count": len(all_probe_specs),
        "http_request_count": (
            max(0, client.request_count - wire_start)
            if wire_start is not None and hasattr(client, "request_count")
            else len(all_probe_specs)
        ),
        "provider_http_request_count": (
            context.provider_http_requests - provider_wire_start
            if context is not None
            else 0
        ),
        "primary_probe_count": len(primary_specs),
        "fallback_probe_count": len(fallback_specs),
        "fallback_triggered": fallback_triggered,
        "strong_primary": strong_primary,
        "confirmed_profiles": sum(len(rows) for rows in confirmed_by_username.values()),
        "identity_candidates": len(identity_candidates),
        "uncertain_profiles": uncertain_profiles,
        "max_probes": configured_max_probes,
    }

    console.print(
        f"  [bold green][3/8][/bold green] Done: "
        f"{len(checked_candidates)} variations, {len(all_probe_specs)} logical probes, "
        f"{result.diagnostics['alias_search']['http_request_count']} HTTP requests, "
        f"{len(identity_candidates)} identity candidates"
    )


async def _phase_photo(
    client: HTTPClient, cfg: ScanConfig, result: ScanResult
) -> None:
    if not cfg.photo:
        console.print("  [dim][4/8] Photo comparison: skipped[/dim]")
        return

    console.print("  [bold yellow][4/8][/bold yellow] Comparing profile photos...")
    avatars = _extract_avatar_urls(result.found_platforms)
    if len(avatars) < 2:
        console.print(
            "  [bold green][4/8][/bold green] Not enough profile photos (need at least 2)"
        )
        return

    photo_results = await compare_profile_photos(client, avatars)
    result.photo_matches = [
        PhotoMatch(
            platform_a=m["platform_a"],
            platform_b=m["platform_b"],
            similarity=m["similarity"],
            method=m["method"],
        )
        for m in photo_results
    ]
    console.print(
        f"  [bold green][4/8][/bold green] Done: "
        f"{len(avatars)} photos checked, {len(photo_results)} matches found"
    )


async def _phase_email_breach(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.email:
        console.print("  [dim][5/8] Email discovery: skipped[/dim]")
        return

    console.print("  [bold yellow][5/8][/bold yellow] Discovering emails...")
    known_emails = [
        e
        for r in platform_results
        if r.profile_data
        for e in [r.profile_data.get("email")]
        if e and isinstance(e, str) and "@" in e
    ]
    # A caller-supplied email_only value is the most authoritative source.
    if cfg.email_only and cfg.email_only not in known_emails:
        known_emails.insert(0, cfg.email_only)

    email_results = await discover_emails(client, cfg.username, known_emails, cfg.full_name)
    # Make sure the explicit email_only target is always represented in
    # results even when discover_emails couldn't verify it via Gravatar.
    if cfg.email_only and not any(er.email == cfg.email_only for er in email_results):
        email_results.insert(
            0,
            EmailResult(
                email=cfg.email_only,
                source="user_supplied",
                verified=True,
            ),
        )

    if cfg.breach and breach_check_available():
        label = "HIBP + XposedOrNot" if hibp_available() else "XposedOrNot (free)"
        console.print(f"  [bold yellow][5/8][/bold yellow] Breach check: {label}...")
        # Collect every unique email once, look them up in parallel.
        unique_emails = list({er.email for er in email_results} | set(known_emails))
        breach_map = await check_many_emails(client, unique_emails)
        for er in email_results:
            er.breaches = breach_map.get(er.email, [])
            er.breach_count = len(er.breaches)
        # Add known emails not already present in email_results if they have breaches.
        seen = {er.email for er in email_results}
        for known in known_emails:
            if known in seen:
                continue
            breaches = breach_map.get(known, [])
            if breaches:
                email_results.append(
                    EmailResult(
                        email=known,
                        source="profile",
                        verified=True,
                        breach_count=len(breaches),
                        breaches=breaches,
                    )
                )

    result.emails = email_results
    console.print(
        f"  [bold green][5/8][/bold green] Done: {len(email_results)} emails found"
    )

    # COMB leak lookup: piggyback on the breach phase.
    if cfg.breach:
        queries = list({cfg.username} | {er.email for er in email_results})
        console.print(
            f"  [bold yellow][5/8][/bold yellow] COMB leak search ({len(queries)} queries)..."
        )
        comb_map = await search_comb_many(client, queries)
        all_leaks = [leak for leaks in comb_map.values() for leak in leaks]
        # Dedupe by (identifier, preview) pair.
        seen_pairs: set[tuple[str, str]] = set()
        unique: list = []
        for leak in all_leaks:
            key = (leak.identifier.lower(), leak.password_preview)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            unique.append(leak)
        result.comb_leaks = unique
        console.print(
            f"  [bold green][5/8][/bold green] COMB: {len(unique)} unique credential leaks"
        )

    # Holehe: pivot each discovered email into ~120 registration checks.
    if cfg.holehe and holehe_available():
        target_emails = list({er.email for er in result.emails})
        if target_emails:
            console.print(
                f"  [bold yellow][5/8][/bold yellow] Holehe: "
                f"{len(target_emails)} email(s) x {holehe_module_count()} sites..."
            )
            holehe_map = await holehe_check_emails(target_emails)
            all_hits = [h for hits in holehe_map.values() for h in hits]
            result.holehe_hits = all_hits
            console.print(
                f"  [bold green][5/8][/bold green] Holehe: {len(all_hits)} registered accounts"
            )
    elif cfg.holehe and not holehe_available():
        console.print(
            "  [dim][5/8] Holehe: skipped (install the 'holehe' extra to enable)[/dim]"
        )

    # GHunt: only when enabled AND the user has logged in once via `ghunt login`.
    if cfg.ghunt and ghunt_available():
        target_emails = list({er.email for er in result.emails})
        if target_emails:
            console.print(
                f"  [bold yellow][5/8][/bold yellow] GHunt: "
                f"{len(target_emails)} email(s) → Google account lookup..."
            )
            ghunt_map = await ghunt_lookup_emails(target_emails)
            result.ghunt_results = list(ghunt_map.values())
            console.print(
                f"  [bold green][5/8][/bold green] GHunt: {len(result.ghunt_results)} Google accounts resolved"
            )
    elif cfg.ghunt and not ghunt_available():
        console.print(
            "  [dim][5/8] GHunt: skipped (run 'ghunt login' once to enable)[/dim]"
        )

    # Toutatis: pivots on the original username + any pivoted handles.
    if cfg.toutatis and toutatis_available():
        ig_handles = list({cfg.username, *result.discovered_usernames})
        console.print(
            f"  [bold yellow][5/8][/bold yellow] Toutatis: "
            f"{len(ig_handles)} Instagram handle(s)..."
        )
        tout_map = await toutatis_lookup_usernames(ig_handles)
        result.toutatis_results = list(tout_map.values())
        console.print(
            f"  [bold green][5/8][/bold green] Toutatis: {len(result.toutatis_results)} IG profiles"
        )
    elif cfg.toutatis and not toutatis_available():
        console.print(
            "  [dim][5/8] Toutatis: skipped (install the 'toutatis' extra to enable)[/dim]"
        )


async def _phase_web_presence(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.web:
        console.print("  [dim][6/8] Web presence: skipped[/dim]")
        return
    console.print("  [bold yellow][6/8][/bold yellow] Investigating web presence...")
    found_urls = [r.url for r in platform_results if r.exists]
    result.web_presence = await discover_web_presence(client, cfg.username, found_urls)
    console.print(
        f"  [bold green][6/8][/bold green] Done: {len(result.web_presence)} web presence entries found"
    )


async def _phase_whois(cfg: ScanConfig, result: ScanResult) -> None:
    if not cfg.whois:
        console.print("  [dim][7/8] WHOIS: skipped[/dim]")
        return
    console.print("  [bold yellow][7/8][/bold yellow] Running WHOIS lookups...")
    result.whois_records = await check_username_domains(cfg.username)
    console.print(
        f"  [bold green][7/8][/bold green] Done: {len(result.whois_records)} registered domains"
    )


async def _phase_dns_subdomain(
    client: HTTPClient, cfg: ScanConfig, result: ScanResult
) -> None:
    if not (cfg.dns or cfg.subdomain):
        console.print("  [dim][8/8] DNS/subdomain: skipped[/dim]")
        return

    console.print("  [bold yellow][8/8][/bold yellow] DNS / subdomain scan...")
    domains_to_check = [r["domain"] for r in result.whois_records] or [f"{cfg.username}.com"]

    for domain in domains_to_check[:3]:
        if cfg.dns:
            records = await get_dns_records(domain)
            if records:
                result.dns_records[domain] = records
        if cfg.subdomain:
            subs = await enumerate_subdomains(client, domain)
            if subs:
                result.subdomains.extend(subs[:50])

    console.print(
        f"  [bold green][8/8][/bold green] Done: "
        f"{len(result.dns_records)} DNS, {len(result.subdomains)} subdomains"
    )


async def _phase_recursive(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    result: ScanResult,
    context: ScanContext | None = None,
) -> None:
    """Feed freshly-discovered usernames back into the platform sweep.

    Bounded by ``cfg.recursive_depth``. On each pass we:
      * gather new candidate usernames from profile data and discovered_usernames
      * skip anything already seen (the original target and prior passes)
      * run the full platform check for each candidate, sequentially per pass
      * merge hits into ``result.platforms`` with a status marking the pivot

    This is the Maigret-style pivot loop, implemented natively so we keep the
    FP filter, deep scrape, and profile_extract pipeline on the new hits.
    """
    if not cfg.recursive or cfg.recursive_depth <= 0:
        return

    seen: set[str] = {cfg.username.lower()}
    queue: list[str] = []

    def _harvest() -> None:
        for r in result.platforms:
            if not r.exists or not r.profile_data:
                continue
            for key in ("username", "nickname", "screen_name", "login"):
                val = r.profile_data.get(key)
                if isinstance(val, str) and val and val.lower() not in seen:
                    seen.add(val.lower())
                    queue.append(val)
        for u in result.discovered_usernames:
            if isinstance(u, str) and u and u.lower() not in seen:
                seen.add(u.lower())
                queue.append(u)

    _harvest()
    if not queue:
        return

    total_new = 0
    for depth in range(cfg.recursive_depth):
        if not queue:
            break
        pass_queue = list(queue)
        queue.clear()
        console.print(
            f"  [bold yellow][+][/bold yellow] Recursive pass {depth + 1}/"
            f"{cfg.recursive_depth}: probing {len(pass_queue)} pivoted username(s)"
        )
        for candidate in pass_queue:
            candidate_cfg = replace(cfg, username=candidate)
            tasks = [
                _check_platform_for_context(client, candidate_cfg, p, context)
                for p in platforms
            ]
            new_results = await asyncio.gather(*tasks)
            for r, platform in zip(new_results, platforms, strict=True):
                _evaluate_platform_result(r, platform, cfg)
                if r.exists:
                    r.status = f"found (pivot:{candidate})"
                    result.platforms.append(r)
                    total_new += 1
        _harvest()

    console.print(
        f"  [bold green][+][/bold green] Recursive: {total_new} additional profiles"
    )


def _finalize_cross_reference(result: ScanResult) -> None:
    found = [r for r in result.platforms if r.exists]
    cr = cross_reference(found)
    cr.matched_photos = [
        f"{m.platform_a} ↔ {m.platform_b} ({m.similarity:.0%}, {m.method})"
        for m in result.photo_matches
    ]
    if result.photo_matches:
        cr.confidence = min(100.0, cr.confidence + 20.0 * len(result.photo_matches))
        cr.notes.append(f"{len(result.photo_matches)} profile photos matched")
    result.cross_reference = cr


async def _phase_reverse_image(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Reverse-image search on every avatar we harvested.

    Pulls avatar URLs out of ``profile_data`` for each found platform.
    We cap the input set to avoid racking up rate-limit hits against
    Yandex when a target has 50+ profiles.
    """
    if not cfg.reverse_image:
        return
    from modules.reverse_image import run_reverse_image

    image_urls: list[str] = []
    seen: set[str] = set()
    for r in result.platforms:
        if not r.exists:
            continue
        for key in ("avatar", "profile_pic", "profile_image", "image", "photo"):
            val = (r.profile_data or {}).get(key)
            if isinstance(val, str) and val.startswith("http") and val not in seen:
                seen.add(val)
                image_urls.append(val)
                if len(image_urls) >= 8:
                    break
        if len(image_urls) >= 8:
            break

    if not image_urls:
        return
    hits = await run_reverse_image(client, image_urls=image_urls)
    result.reverse_image_hits = list(hits)


async def _phase_username_history(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Wayback-based historical alias discovery for found profile URLs."""
    if not cfg.past_usernames:
        return
    from modules.history import discover_historical_usernames

    profile_urls = [r.url for r in result.platforms if r.exists and r.url]
    if not profile_urls:
        return
    hits = await discover_historical_usernames(
        client,
        profile_urls=profile_urls[:25],
        current_username=cfg.username,
    )
    result.historical_usernames = list(hits)


async def _phase_passive(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Run passive intel sources (shodan/censys/fofa/zoomeye/pastebin/…).

    Domain-keyed sources run when ``cfg.passive_domain`` is set; username
    and profile-URL sources run regardless. The orchestrator swallows
    per-source failures, so this phase is always best-effort.
    """
    if not cfg.passive:
        return
    from modules.passive import run_passive

    profile_urls = [r.url for r in result.platforms if r.exists and r.url]
    hits = await run_passive(
        client,
        username=cfg.username,
        domain=cfg.passive_domain,
        profile_urls=profile_urls[:10],  # cap wayback fan-out
    )
    result.passive_hits = list(hits)


async def _phase_phone(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Offline + NumVerify metadata for a user-supplied phone number."""
    if not cfg.phone:
        return
    from modules.phone import lookup_phone

    intel = await lookup_phone(
        client, cfg.phone, default_region=cfg.phone_region
    )
    if intel is not None:
        result.phone_intel = [intel]


async def _phase_crypto(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Balance/tx lookups for user-supplied BTC/ETH addresses."""
    if not cfg.crypto_addresses:
        return
    from modules.crypto import lookup_crypto

    intel = await lookup_crypto(client, list(cfg.crypto_addresses))
    result.crypto_intel = list(intel)


async def _phase_recon(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Red-team corporate recon: email patterns + GitHub org + subdomain enrichment.

    Runs only when ``cfg.redteam_domain`` is set. Fans out the three
    independent sources concurrently and merges results into ``ScanResult``.
    Each source swallows its own errors; failure of one does not abort the
    others.
    """
    if not cfg.redteam_domain:
        return
    from modules.dns_lookup import enumerate_subdomains
    from modules.recon import email_patterns, github_org, github_secrets, subdomains_extra

    domain = cfg.redteam_domain.strip().lower().lstrip("@")
    org = (cfg.redteam_github_org or domain.split(".", 1)[0]).strip()

    names: list[str] = []
    if cfg.redteam_names_file:
        try:
            with open(cfg.redteam_names_file, encoding="utf-8") as fh:
                names = [line.strip() for line in fh if line.strip()]
        except OSError:
            names = []

    seed_subs, committers, secrets = await asyncio.gather(
        enumerate_subdomains(client, domain),
        github_org.scan_org(client, org),
        github_secrets.scan_target(client, org=org, domain=domain),
    )
    subs = await subdomains_extra.enrich_subdomains(
        client, domain, existing=seed_subs
    )
    candidates = email_patterns.generate_bulk(names, domain) if names else []

    result.email_candidates = [c.to_dict() for c in candidates]
    result.github_committers = [g.to_dict() for g in committers]
    result.recon_subdomains = [s.to_dict() for s in subs]
    result.leaked_secrets = [s.to_dict() for s in secrets]


async def _phase_gitleaks(cfg: ScanConfig, result: ScanResult) -> None:
    """Optional local Gitleaks scan for caller-provided repo/path targets."""
    if not cfg.gitleaks_paths:
        return
    from modules.recon import gitleaks

    batches = await asyncio.gather(
        *(
            gitleaks.scan_path(
                path,
                no_git=cfg.gitleaks_no_git,
                timeout=cfg.gitleaks_timeout,
            )
            for path in cfg.gitleaks_paths
        ),
        return_exceptions=True,
    )

    leaked = list(result.leaked_secrets or [])
    for batch in batches:
        if isinstance(batch, BaseException):
            log.debug("gitleaks scan failed: %s", batch)
            continue
        leaked.extend(secret.to_dict() for secret in batch)
    result.leaked_secrets = leaked


async def _phase_exif(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Pull EXIF metadata from any image URLs the caller supplied.

    EXIF blocks routinely leak GPS, capture timestamp, device serial,
    and editing-software fingerprint — all directly actionable for
    geolocation and pretext crafting. Runs only when the caller
    populates ``cfg.exif_image_urls``; we do not auto-discover images
    here to keep the phase predictable.
    """
    if not cfg.exif_image_urls:
        return
    from modules.analysis import exif

    reports = await asyncio.gather(
        *(exif.extract_from_url(client, url) for url in cfg.exif_image_urls),
        return_exceptions=True,
    )
    out = []
    for r in reports:
        if isinstance(r, BaseException):
            continue
        out.append(r.to_dict())
    result.exif_reports = out


async def _phase_wigle(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Resolve a BSSID/MAC or SSID to physical locations via Wigle.net.

    Appends each hit (kind="bssid" or kind="ssid") to ``result.passive_hits``
    so existing reporters surface them next to the other passive sources.
    Silently skips when no creds are configured or no inputs are given.
    """
    if not (cfg.bssid or cfg.ssid):
        return
    from modules.passive import wigle

    hits = await wigle.search(client, bssid=cfg.bssid, ssid=cfg.ssid)
    result.passive_hits = list(result.passive_hits) + list(hits)


async def _phase_company(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Fetch corporate registry records (with officers) for a company query.

    Stores the enriched ``CompanyRecord`` dicts in
    ``result.company_records``; downstream reporters key on that field.
    """
    if not cfg.company_query:
        return
    from modules.passive import opencorporates

    recs = await opencorporates.search_with_officers(
        client, cfg.company_query, limit=cfg.company_limit
    )
    result.company_records = [r.to_dict() for r in recs]


async def _phase_intelx(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Search Intelligence X for paste / leak / dark-web mentions of ``intelx_term``.

    Appends each hit (kind="leak", source="intelx") to
    ``result.passive_hits`` so existing reporters surface them next to
    Shodan / Censys / Wigle / etc. Silently skips when no API key is
    set or no term is given.
    """
    if not cfg.intelx_term:
        return
    from modules.passive import intelx

    hits = await intelx.search(
        client, cfg.intelx_term, max_results=cfg.intelx_limit
    )
    result.passive_hits = list(result.passive_hits) + list(hits)


async def _phase_doc_metadata(
    client: HTTPClient,
    cfg: ScanConfig,
    result: ScanResult,
) -> None:
    """Extract embedded metadata from a list of public document URLs.

    Pairs naturally with passive/google_dork's "files" preset — feed
    the dork hits straight into ``cfg.harvest_doc_urls`` to surface authors,
    last-modifiers, and internal SMB share paths.
    """
    if not cfg.harvest_doc_urls:
        return
    from modules.recon import doc_metadata

    docs = await doc_metadata.extract_batch(client, list(cfg.harvest_doc_urls))
    result.document_metadata = [d.to_dict() for d in docs]


async def _phase_geocode(cfg: ScanConfig, result: ScanResult) -> None:
    """Resolve location strings found in profile data to lat/lng.

    Network-bound and politely rate-limited; only runs when the user opts
    in when ``cfg.geocode`` is enabled because Nominatim enforces a 1 req/s policy.
    """
    if not cfg.geocode:
        return
    from core import geo

    payload = result.to_dict()
    hints = geo.extract_location_hints(payload)
    if not hints:
        return
    points = await geo.geocode_many(hints)
    result.geo_points = list(points)


def _phase_enrichment(cfg: ScanConfig, result: ScanResult) -> None:
    """Run synchronous enrichment (stylometry/language/timezone/graph)."""
    if not cfg.enrichment:
        return
    from modules.analysis import run_enrichment

    report = run_enrichment(result)
    result.enrichment = report.to_dict()


async def _phase_ai_report(
    cfg: ScanConfig,
    result: ScanResult,
    context: ScanContext,
) -> None:
    """Generate the optional executive summary through the skill registry."""
    if not cfg.ai_report:
        return
    from core.analysis.prompts import _trim_payload
    from core.analysis.skill_loader import SkillError, run_skill

    try:
        result.ai_report = await run_skill(
            "exec_summary",
            {"scan": _trim_payload(result.to_dict(include_all=True))},
            budget=context.skill_budget,
        )
    except SkillError as exc:
        log.debug("exec_summary failed: %s", exc)
        result.diagnostics.setdefault("warnings", []).append(
            "AI executive summary was requested but could not be generated"
        )


@dataclass
class _ScanState:
    cfg: ScanConfig
    result: ScanResult
    platforms: list[Platform]
    client: HTTPClient
    context: ScanContext
    platform_results: list[PlatformResult]


@dataclass(frozen=True)
class PhaseSpec:
    """One centrally registered engine phase."""

    name: str
    enabled: Callable[[_ScanState], bool]
    runner: Callable[[_ScanState], Awaitable[Any] | Any]
    metrics: Callable[[_ScanState], dict[str, Any]] = lambda _state: {}


async def _execute_phase(spec: PhaseSpec, state: _ScanState) -> Any:
    """Run one phase with timing, diagnostics, isolation and cancellation."""
    phases = state.result.diagnostics.setdefault("phases", {})
    if not spec.enabled(state):
        phases[spec.name] = {"status": "skipped", "duration_ms": 0, "metrics": {}}
        return None

    started = time.monotonic()
    state.context.emit("phase_start", phase=spec.name)
    try:
        value = spec.runner(state)
        if inspect.isawaitable(value):
            value = await value
    except asyncio.CancelledError:
        phases[spec.name] = {
            "status": "cancelled",
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "metrics": {},
        }
        state.context.emit("phase_end", phase=spec.name, status="cancelled")
        raise
    except Exception as exc:
        duration = round((time.monotonic() - started) * 1000, 2)
        log.warning("phase %s failed: %s", spec.name, exc)
        phases[spec.name] = {
            "status": "error",
            "duration_ms": duration,
            "metrics": {},
            "error": type(exc).__name__,
        }
        warning = f"phase {spec.name} failed ({type(exc).__name__})"
        state.result.diagnostics.setdefault("warnings", []).append(warning)
        state.context.emit("error", phase=spec.name, message=warning)
        return None

    duration = round((time.monotonic() - started) * 1000, 2)
    metrics = spec.metrics(state)
    phases[spec.name] = {
        "status": "completed",
        "duration_ms": duration,
        "metrics": metrics,
    }
    state.context.emit("phase_end", phase=spec.name, status="completed", **metrics)
    return value


def _phase_metrics(state: _ScanState) -> dict[str, Any]:
    return {
        "confirmed": state.result.found_count,
        "uncertain": sum(
            1
            for item in state.result.platforms
            if (item.verification or {}).get("verdict") == "uncertain"
        ),
        "platforms": len(state.result.platforms),
    }


def _alias_phase_metrics(state: _ScanState) -> dict[str, Any]:
    metrics = state.result.diagnostics.get("alias_search") or {}
    return {
        "candidates": int(metrics.get("candidate_count", 0)),
        "platforms": int(metrics.get("platform_count", 0)),
        "requests": int(metrics.get("probe_count", 0)),
        "logical_probes": int(metrics.get("logical_probe_count", 0)),
        "http_requests": int(metrics.get("http_request_count", 0)),
        "provider_http_requests": int(
            metrics.get("provider_http_request_count", 0)
        ),
        "batch_extended_candidates": int(
            metrics.get("batch_extended_candidate_count", 0)
        ),
        "batch_extension_platforms": int(
            metrics.get("batch_extension_platform_count", 0)
        ),
        "primary_requests": int(metrics.get("primary_probe_count", 0)),
        "fallback_requests": int(metrics.get("fallback_probe_count", 0)),
        "fallback_triggered": bool(metrics.get("fallback_triggered", False)),
        "confirmed_profiles": int(metrics.get("confirmed_profiles", 0)),
        "identity_candidates": int(metrics.get("identity_candidates", 0)),
        "uncertain_profiles": len(metrics.get("uncertain_profiles", [])),
    }


def _phase_registry() -> tuple[PhaseSpec, ...]:
    """Return the fixed-order registry used by every entrypoint."""

    async def handle_resolve(state: _ScanState) -> None:
        state.cfg = await _phase_handle_resolve(
            state.client,
            state.cfg,
            state.platforms,
            state.result,
            context=state.context,
        )
        state.result.username = state.cfg.username

    async def platform_check(state: _ScanState) -> None:
        if state.cfg.email_only:
            state.cfg = replace(
                state.cfg,
                email=True,
                breach=True,
                holehe=True,
                ghunt=True,
            )
            state.platform_results = []
            state.result.platforms = []
            return
        state.platform_results = await _phase_platform_check(
            state.client,
            state.cfg,
            state.platforms,
            state.result,
            context=state.context,
        )

    return (
        PhaseSpec("handle_resolve", lambda s: bool(s.cfg.full_name), handle_resolve),
        PhaseSpec("platform_check", lambda _s: True, platform_check, _phase_metrics),
        PhaseSpec(
            "profile_validate",
            lambda s: s.cfg.ai_skills,
            lambda s: _phase_profile_validate(s.cfg, s.result, context=s.context),
            _phase_metrics,
        ),
        PhaseSpec(
            "deep_scrape",
            lambda s: s.cfg.deep and not bool(s.cfg.email_only),
            lambda s: _phase_deep_scrape(s.client, s.cfg, s.platform_results),
            _phase_metrics,
        ),
        PhaseSpec(
            "smart_search",
            lambda s: s.cfg.smart and not bool(s.cfg.email_only),
            lambda s: _phase_smart_search(
                s.client,
                s.cfg,
                s.platforms,
                s.platform_results,
                s.result,
                context=s.context,
            ),
            _alias_phase_metrics,
        ),
        PhaseSpec("photo", lambda s: s.cfg.photo, lambda s: _phase_photo(s.client, s.cfg, s.result)),
        PhaseSpec(
            "email_breach",
            lambda s: s.cfg.email,
            lambda s: _phase_email_breach(
                s.client, s.cfg, s.platform_results, s.result
            ),
        ),
        PhaseSpec(
            "web_presence",
            lambda s: s.cfg.web,
            lambda s: _phase_web_presence(
                s.client, s.cfg, s.platform_results, s.result
            ),
        ),
        PhaseSpec("whois", lambda s: s.cfg.whois, lambda s: _phase_whois(s.cfg, s.result)),
        PhaseSpec(
            "dns_subdomain",
            lambda s: s.cfg.dns or s.cfg.subdomain,
            lambda s: _phase_dns_subdomain(s.client, s.cfg, s.result),
        ),
        PhaseSpec(
            "recursive",
            lambda s: s.cfg.recursive and s.cfg.recursive_depth > 0,
            lambda s: _phase_recursive(
                s.client, s.cfg, s.platforms, s.result, context=s.context
            ),
            _phase_metrics,
        ),
        PhaseSpec(
            "reverse_image",
            lambda s: s.cfg.reverse_image,
            lambda s: _phase_reverse_image(s.client, s.cfg, s.result),
        ),
        PhaseSpec(
            "username_history",
            lambda s: s.cfg.past_usernames,
            lambda s: _phase_username_history(s.client, s.cfg, s.result),
        ),
        PhaseSpec("passive", lambda s: s.cfg.passive, lambda s: _phase_passive(s.client, s.cfg, s.result)),
        PhaseSpec("phone", lambda s: bool(s.cfg.phone), lambda s: _phase_phone(s.client, s.cfg, s.result)),
        PhaseSpec(
            "crypto",
            lambda s: bool(s.cfg.crypto_addresses),
            lambda s: _phase_crypto(s.client, s.cfg, s.result),
        ),
        PhaseSpec("recon", lambda s: bool(s.cfg.redteam_domain), lambda s: _phase_recon(s.client, s.cfg, s.result)),
        PhaseSpec("gitleaks", lambda s: bool(s.cfg.gitleaks_paths), lambda s: _phase_gitleaks(s.cfg, s.result)),
        PhaseSpec("exif", lambda s: bool(s.cfg.exif_image_urls), lambda s: _phase_exif(s.client, s.cfg, s.result)),
        PhaseSpec("wigle", lambda s: bool(s.cfg.bssid or s.cfg.ssid), lambda s: _phase_wigle(s.client, s.cfg, s.result)),
        PhaseSpec("company", lambda s: bool(s.cfg.company_query), lambda s: _phase_company(s.client, s.cfg, s.result)),
        PhaseSpec(
            "doc_metadata",
            lambda s: bool(s.cfg.harvest_doc_urls),
            lambda s: _phase_doc_metadata(s.client, s.cfg, s.result),
        ),
        PhaseSpec("intelx", lambda s: bool(s.cfg.intelx_term), lambda s: _phase_intelx(s.client, s.cfg, s.result)),
        PhaseSpec("cross_reference", lambda _s: True, lambda s: _finalize_cross_reference(s.result)),
        PhaseSpec("geocode", lambda s: s.cfg.geocode, lambda s: _phase_geocode(s.cfg, s.result)),
        PhaseSpec("enrichment", lambda s: s.cfg.enrichment, lambda s: _phase_enrichment(s.cfg, s.result)),
        PhaseSpec("ai_report", lambda s: s.cfg.ai_report, lambda s: _phase_ai_report(s.cfg, s.result, s.context)),
    )


async def _drain_seed_tasks(context: ScanContext, *, cancel: bool = False) -> None:
    """Finish cache warmers on success and stop them promptly on cancellation."""
    tasks = tuple(context.seed_tasks)
    if not tasks:
        return
    if cancel:
        for task in tasks:
            task.cancel()
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=5.0,
        )
    except asyncio.TimeoutError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        log.debug("soft-404 seed drain timed out; pending tasks cancelled")


# ── Public entrypoint ────────────────────────────────────────────────────


async def run_scan(cfg: ScanConfig) -> ScanResult:
    """Run an OSINT scan based on the provided immutable configuration."""
    if not cfg.username and not (cfg.full_name or cfg.email_only):
        raise ValueError("username is empty")
    start_time = time.monotonic()
    result = ScanResult(username=cfg.username)
    platforms = _select_platforms(cfg.categories, cfg.platform_scope)
    context = ScanContext.create(cfg)
    selected_by_name = {platform.name: platform for platform in platforms}

    async with HTTPClient(
        proxy=cfg.proxy if not cfg.proxies else None,
        proxies=list(cfg.proxies) if cfg.proxies else None,
        tor=cfg.tor,
        request_timeout=cfg.request_timeout,
        fingerprint=cfg.fingerprint,
        new_circuit_every=cfg.new_circuit_every,
        tor_control_password=cfg.tor_control_password,
        allow_private_networks=cfg.allow_private_networks,
    ) as client:
        prepared_credentials = await prepare_provider_credentials(
            client,
            context.provider_credentials,
            provider_names=_providers_requiring_token_prep(cfg, selected_by_name),
        )
        context.provider_credentials = prepared_credentials.credentials
        context.provider_http_requests += prepared_credentials.http_request_count
        result.diagnostics["provider_auth"] = {
            name: status.to_safe_dict()
            for name, status in prepared_credentials.statuses.items()
        }
        result.diagnostics["provider_coverage"] = {
            name: {
                "configured": provider_is_configured(
                    name, context.provider_credentials
                ),
                "selected": name in selected_by_name,
                "auth_mode": (
                    selected_by_name[name].auth_mode
                    if name in selected_by_name
                    else "unknown"
                ),
            }
            for name in sorted(PROVIDERS)
        }
        if cfg.breach and not hibp_available():
            console.print(
                "  [yellow]Warning:[/yellow] [bold]HIBP_API_KEY[/bold] not set; breach check will be skipped."
            )

        state = _ScanState(
            cfg=cfg,
            result=result,
            platforms=platforms,
            client=client,
            context=context,
            platform_results=[],
        )
        try:
            for phase in _phase_registry():
                await _execute_phase(phase, state)
        except asyncio.CancelledError:
            await _drain_seed_tasks(context, cancel=True)
            raise
        else:
            cfg = state.cfg
            # Cache warmers need the HTTP session, so drain them before the
            # client context exits. They never get to delay a scan indefinitely.
            await _drain_seed_tasks(context)

    result.scan_time = time.monotonic() - start_time
    context.emit(
        "done",
        phase="done",
        scan_time=result.scan_time,
        found_platforms=sum(1 for p in result.platforms if p.exists),
    )
    return result


# ── Backwards-compatible wrapper ─────────────────────────────────────────


async def scan(
    username: str,
    deep: bool = True,
    smart: bool = True,
    email: bool = False,
    web: bool = False,
    whois_check: bool = False,
    breach: bool = False,
    photo: bool = False,
    dns: bool = False,
    subdomain: bool = False,
    proxy: str | None = None,
    tor: bool = False,
    categories: list[str] | None = None,
) -> ScanResult:
    cfg = ScanConfig(
        username=username,
        deep=deep,
        smart=smart,
        email=email,
        web=web,
        whois=whois_check,
        breach=breach,
        photo=photo,
        dns=dns,
        subdomain=subdomain,
        proxy=proxy,
        tor=tor,
        categories=tuple(categories) if categories else None,
    )
    return await run_scan(cfg)
