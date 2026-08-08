"""OSINT scan engine — orchestrates modular phases.

Kept deliberately thin: each phase is a small coroutine that mutates the
ScanResult in place. Adding a new phase means adding a _phase_* method
and wiring it into scan().
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

from core.config import ScanConfig
from core.cross_reference import cross_reference
from core.http_client import HTTPClient
from core.logging_setup import get_logger
from core.models import EmailResult, PhotoMatch, PlatformResult, ScanResult
from core.progress import emit as _emit
from core.reporter import console
from core.smart_search import (
    extract_discoverable_data,
    generate_variations,
    merge_discoveries,
)
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
from modules.stealth import obscura_fallback
from modules.stealth.js_wall import looks_like_js_wall
from modules.stealth.soft_404 import (
    IMPOSSIBLE_USERNAME,
    Soft404Cache,
    is_soft_404,
    make_baseline,
)
from modules.stealth.playwright_fallback import (
    AVAILABLE as PLAYWRIGHT_AVAILABLE,
)
from modules.stealth.playwright_fallback import (
    fetch_rendered,
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


# Pending baseline-seed background tasks; awaited at end of run_scan so the
# scan completes deterministically without leaking warnings about unawaited
# coroutines.
_PENDING_SEED_TASKS: set[asyncio.Task] = set()


def _track_seed(task: asyncio.Task) -> None:
    _PENDING_SEED_TASKS.add(task)
    task.add_done_callback(_PENDING_SEED_TASKS.discard)
IMPORTANT_PLATFORMS_FOR_VARIATIONS = frozenset(
    {
        "GitHub",
        "X",
        "Instagram",
        "Reddit",
        "LinkedIn",
        "YouTube",
        "TikTok",
        "Steam",
    }
)

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
    # Forced global opt-in (cfg.playwright) OR platform flagged as js_heavy.
    return bool(cfg.playwright or platform.js_heavy)


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
    client: HTTPClient, cfg: ScanConfig, platform: Platform
) -> PlatformResult:
    username = cfg.username
    url = platform.url.replace("{username}", username)
    result = PlatformResult(platform=platform.name, url=url, category=platform.category)
    login_required = False

    if cfg.skip_invalid_usernames:
        if not _username_matches_platform(username, platform):
            result.status = "invalid_username"
            result.fp_signals = ["username_pattern_mismatch"]
            return result
        if _is_known_not_found(username, platform.name):
            result.status = "cached_not_found"
            result.fp_signals = ["negative_cache_hit"]
            return result

    try:
        if platform.check_type == "json_api":
            status, data, elapsed = await client.get_json(url, platform.headers)
            result.http_status = status
            result.response_time = elapsed
            result.exists = status == 200 and data is not None
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
                        _body_str = _json.dumps(platform.probe_body).replace("{username}", username)
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
                    result.status = "not_found"
                    return result
                if _probe_data is not None and platform.absence_strings:
                    import json as _json
                    _probe_text = _json.dumps(_probe_data) if isinstance(_probe_data, (dict, list)) else str(_probe_data)
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
            # Only applied when the platform didn't already give a definitive signal.
            redirected_off = _looks_redirected_off(url, final_url, username)
            if result.exists and redirected_off and platform.check_type == "status":
                result.exists = False
                result.status = "soft_404_redirected"
                result.fp_signals = list(result.fp_signals) + ["redirect_off_target"]

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
                cache = _soft_404_cache()
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
                    _track_seed(
                        asyncio.create_task(
                            _seed_soft_404_baseline(client, platform)
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
                        fp = score_match(
                            username=username,
                            platform_name=platform.name,
                            status=status,
                            body=body,
                            check_type=platform.check_type,
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
                "login_required" if login_required else _status_from_http(status, result.exists)
            )
    except (asyncio.TimeoutError, OSError) as exc:
        log.debug("platform %s errored: %s", platform.name, exc)
        result.status = "error"
    except Exception as exc:
        log.warning("unexpected error checking %s: %s", platform.name, exc)
        result.status = "error"

    if not result.exists and result.status not in ("error",):
        _mark_not_found(username, platform.name)

    return result


async def _seed_soft_404_baseline(client: HTTPClient, platform: Platform) -> None:
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
        _soft_404_cache().put(baseline)
        log.debug("seeded soft-404 baseline for %s", platform.name)
    except Exception as exc:  # noqa: BLE001 - best-effort background work
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
        "Pinterest", "Medium", "Dev.to", "Keybase", "Mastodon (mastodon.social)",
        "GitLab", "HackerNews", "StackOverflow", "Quora", "Vimeo",
    }
)


async def _phase_profile_validate(
    cfg: ScanConfig, result: ScanResult
) -> None:
    """LLM-augmented verdict on borderline-confidence profile matches.

    Only runs when ``cfg.ai_skills`` is on. Sends each platform with a
    confidence in the uncertain band (0.45 ≤ conf ≤ 0.70) to the
    ``profile_validator`` skill. The skill's verdict NEVER hard-deletes a
    match — at worst it lowers confidence below the FP threshold; at best
    it boosts borderline matches by up to +0.15.

    Synchronous skill calls are wrapped in ``asyncio.to_thread`` so the
    engine doesn't block on network I/O.
    """
    if not cfg.ai_skills:
        return
    try:
        from core.analysis.skill_loader import SkillBudget, SkillError, run_skill
    except ImportError:
        log.debug("skill_loader unavailable; skipping profile_validate phase")
        return

    borderline = [
        p
        for p in result.platforms
        if p.exists and p.confidence >= 0.25
    ]
    if not borderline:
        return

    budget = SkillBudget(limit=cfg.ai_skill_budget)
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
    client: HTTPClient, cfg: ScanConfig, platforms: list[Platform], result: ScanResult
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
    # requests, not 1924×N. Pick handles up to name_max_handles after the
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
        probe_tasks = [_check_platform(client, probe_cfg, p) for p in probe_targets]
        probe_results = await asyncio.gather(*probe_tasks)
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
        return "login_required"
    if status == 429:
        return "blocked"
    return "found" if exists else "not_found"


# Per-scan negative cache: username -> set of platform names that returned 404/not_found.
# Cleared at the start of each scan; used by recursive/deep phases to avoid
# re-checking platforms that already failed for a given username.
_NEGATIVE_CACHE: dict[str, set[str]] = {}


def _mark_not_found(username: str, platform_name: str) -> None:
    _NEGATIVE_CACHE.setdefault(username, set()).add(platform_name)


def _is_known_not_found(username: str, platform_name: str) -> bool:
    return platform_name in _NEGATIVE_CACHE.get(username, set())


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


def _select_platforms(categories: tuple[str, ...] | None) -> list[Platform]:
    if not categories:
        return _verified_platforms()
    if categories == ("__all__",):
        return list(PLATFORMS)
    if categories == ("__popular__",):
        return _popular_platforms()
    if categories == ("__verified__",):
        return _verified_platforms()
    return [p for p in PLATFORMS if p.category in categories]


_VERIFIED_CACHE: list[Platform] | None = None
_VERIFIED_ALIASES: dict[str, str] = {
    "x": "twitter",  # Twitter → X
}


def _verified_platforms() -> list[Platform]:
    """Return platforms with maigret-verified detection signals (2+ of absenceStrs,
    presenseStrs, urlProbe). ~450 platforms, near-zero fake positives."""
    global _VERIFIED_CACHE
    if _VERIFIED_CACHE is not None:
        return _VERIFIED_CACHE
    verified = set()
    try:
        import json
        data = json.loads(
            _MAIGRET_PATH.read_text(encoding="utf-8")
        )["sites"]
        for name, d in data.items():
            has_absence = bool(d.get("absenceStrs"))
            has_presence = bool(d.get("presenseStrs"))
            has_probe = bool(d.get("urlProbe"))
            if (has_absence and has_presence) or (has_presence and has_probe) or (has_absence and has_probe):
                verified.add(name.lower().strip().rstrip("."))
    except Exception:
        pass
    if not verified:
        return _popular_platforms()
    from difflib import SequenceMatcher
    result = []
    for p in PLATFORMS:
        pkey = p.name.lower().strip().rstrip(".")
        maigret_key = _VERIFIED_ALIASES.get(pkey, pkey)
        if maigret_key in verified or pkey in verified:
            result.append(p)
            continue
        for vname in verified:
            if SequenceMatcher(None, pkey, vname).ratio() > 0.85:
                result.append(p)
                break
    log.debug("verified platforms: %d out of %d", len(result), len(PLATFORMS))
    _VERIFIED_CACHE = result
    return result


_POPULAR_PLATFORM_NAMES: set[str] | None = None
_VERIFIED_PLATFORM_NAMES: set[str] | None = None
_MAIGRET_PATH = Path(__file__).resolve().parent.parent / "scripts" / "maigret_data.json"


def _popular_platforms() -> list[Platform]:
    global _POPULAR_PLATFORM_NAMES
    if _POPULAR_PLATFORM_NAMES is None:
        try:
            import json
            data = json.loads(
                _MAIGRET_PATH.read_text(encoding="utf-8")
            )["sites"]
            scored = sorted(
                (d.get("alexaRank", 99999), name)
                for name, d in data.items()
                if d.get("alexaRank") and d["alexaRank"] < 100000
            )
            _POPULAR_PLATFORM_NAMES = {
                name.lower().strip().rstrip(".") for _, name in scored[:300]
            }
        except Exception:
            _POPULAR_PLATFORM_NAMES = set()
    popular = _POPULAR_PLATFORM_NAMES
    if not popular:
        return list(PLATFORMS)
    from difflib import SequenceMatcher
    result = []
    for p in PLATFORMS:
        pkey = p.name.lower().strip().rstrip(".")
        if pkey in popular:
            result.append(p)
            continue
        for mname in popular:
            ratio = SequenceMatcher(None, pkey, mname).ratio()
            if ratio > 0.85:
                result.append(p)
                break
    return result


# ── Phase implementations ────────────────────────────────────────────────


async def _phase_platform_check(
    client: HTTPClient, cfg: ScanConfig, platforms: list[Platform], result: ScanResult
) -> list[PlatformResult]:
    console.print("  [bold yellow][1/8][/bold yellow] Starting platform sweep...")
    _emit("phase_start", phase="platform_sweep", total=len(platforms))
    tasks = [_check_platform(client, cfg, p) for p in platforms]
    platform_results = await asyncio.gather(*tasks)

    # Deep-scraped platforms are hand-curated and verified via API calls,
    # so we trust them regardless of the heuristic confidence score.
    dropped = 0
    for r in platform_results:
        if (
            r.exists
            and r.platform not in DEEP_SCRAPERS
            and r.confidence < cfg.fp_threshold
        ):
            r.exists = False
            r.status = "low_confidence"
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
        r for r in platform_results if r.exists and r.platform in DEEP_SCRAPERS
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

    scraped = sum(1 for d in deep_results if d)
    console.print(f"  [bold green][2/8][/bold green] Done: {scraped} profile details pulled")


async def _phase_smart_search(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.smart:
        console.print("  [dim][3/8] Smart search: skipped[/dim]")
        return

    console.print("  [bold yellow][3/8][/bold yellow] Starting smart search...")

    discoveries = [
        extract_discoverable_data(r.profile_data)
        for r in platform_results
        if r.exists and r.profile_data
    ]
    merged = merge_discoveries(discoveries)
    variations = generate_variations(cfg.username)
    result.variations_checked = variations

    for linked_u in merged.get("linked_usernames", []):
        if linked_u.lower() != cfg.username.lower() and linked_u not in variations:
            variations.append(linked_u)
            result.discovered_usernames.append(linked_u)

    not_found_platforms = [
        p for p in platforms
        if not any(r.platform == p.name and r.exists for r in platform_results)
    ]
    if not (variations and not_found_platforms):
        console.print("  [bold green][3/8][/bold green] Done")
        return

    important = [p for p in not_found_platforms if p.name in IMPORTANT_PLATFORMS_FOR_VARIATIONS]
    check_platforms = important[:8]
    check_variations = variations[:12]
    if not check_platforms:
        console.print("  [bold green][3/8][/bold green] No platforms left to check variations on")
        return

    var_tasks = [
        _check_platform(client, replace(cfg, username=var), p)
        for var in check_variations
        for p in check_platforms
    ]
    var_results = await asyncio.gather(*var_tasks)
    var_found = [r for r in var_results if r.exists]
    for vr in var_found:
        vr.status = "found (variation)"
        result.platforms.append(vr)

    console.print(
        f"  [bold green][3/8][/bold green] Done: "
        f"{len(check_variations)} variations x {len(check_platforms)} platforms, "
        f"{len(var_found)} new results"
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

    email_results = await discover_emails(client, cfg.username, known_emails)
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
            tasks = [_check_platform(client, candidate_cfg, p) for p in platforms]
            new_results = await asyncio.gather(*tasks)
            for r in new_results:
                if (
                    r.exists
                    and r.platform not in DEEP_SCRAPERS
                    and r.confidence < cfg.fp_threshold
                ):
                    r.exists = False
                    r.status = "low_confidence"
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


# ── Public entrypoint ────────────────────────────────────────────────────


async def run_scan(cfg: ScanConfig) -> ScanResult:
    """Run an OSINT scan based on the provided immutable configuration."""
    start_time = time.monotonic()
    _clear_negative_cache()
    result = ScanResult(username=cfg.username)
    platforms = _select_platforms(cfg.categories)

    async with HTTPClient(
        proxy=cfg.proxy if not cfg.proxies else None,
        proxies=list(cfg.proxies) if cfg.proxies else None,
        tor=cfg.tor,
        request_timeout=cfg.request_timeout,
        fingerprint=cfg.fingerprint,
        new_circuit_every=cfg.new_circuit_every,
        tor_control_password=cfg.tor_control_password,
    ) as client:
        if cfg.breach and not hibp_available():
            console.print(
                "  [yellow]Warning:[/yellow] [bold]HIBP_API_KEY[/bold] not set; breach check will be skipped."
            )

        # Phase 0 (optional): resolve cfg.full_name to a username via quick
        # candidate probes. Mutates cfg.username for the rest of the scan.
        if cfg.full_name:
            cfg = await _phase_handle_resolve(client, cfg, platforms, result)
            result.username = cfg.username

        # cfg.email_only short-circuits the platform sweep: caller already
        # has an identifier, so we jump straight to the breach/holehe/ghunt
        # chain. Force the relevant flags on so downstream phases run.
        if cfg.email_only:
            cfg = replace(
                cfg,
                email=True,
                breach=True,
                holehe=True,
                ghunt=True,
            )
            platform_results = []
            result.platforms = []
            console.print(
                f"  [bold cyan][email-only][/bold cyan] Target: {cfg.email_only} "
                f"— skipping platform sweep, running email pivots only."
            )
        else:
            platform_results = await _phase_platform_check(client, cfg, platforms, result)

        _emit("phase_start", phase="deep_scrape")
        await _phase_deep_scrape(client, cfg, platform_results)
        _emit("phase_end", phase="deep_scrape")

        # AI-augmented validation of borderline matches (cfg.ai_skills).
        _emit("phase_start", phase="profile_validate")
        await _phase_profile_validate(cfg, result)
        _emit("phase_end", phase="profile_validate")

        _emit("phase_start", phase="smart_search")
        await _phase_smart_search(client, cfg, platforms, platform_results, result)
        _emit("phase_end", phase="smart_search")

        _emit("phase_start", phase="photo")
        await _phase_photo(client, cfg, result)
        _emit("phase_end", phase="photo")

        _emit("phase_start", phase="email_breach")
        await _phase_email_breach(client, cfg, platform_results, result)
        _emit("phase_end", phase="email_breach", emails=len(result.emails))

        _emit("phase_start", phase="web_presence")
        await _phase_web_presence(client, cfg, platform_results, result)
        _emit("phase_end", phase="web_presence")

        _emit("phase_start", phase="whois")
        await _phase_whois(cfg, result)
        _emit("phase_end", phase="whois")

        _emit("phase_start", phase="dns_subdomain")
        await _phase_dns_subdomain(client, cfg, result)
        _emit("phase_end", phase="dns_subdomain")

        _emit("phase_start", phase="recursive")
        await _phase_recursive(client, cfg, platforms, result)
        _emit("phase_end", phase="recursive")

        _emit("phase_start", phase="reverse_image")
        await _phase_reverse_image(client, cfg, result)
        _emit("phase_end", phase="reverse_image")

        _emit("phase_start", phase="username_history")
        await _phase_username_history(client, cfg, result)
        _emit("phase_end", phase="username_history")

        _emit("phase_start", phase="passive")
        await _phase_passive(client, cfg, result)
        _emit("phase_end", phase="passive")

        _emit("phase_start", phase="phone")
        await _phase_phone(client, cfg, result)
        _emit("phase_end", phase="phone")

        _emit("phase_start", phase="crypto")
        await _phase_crypto(client, cfg, result)
        _emit("phase_end", phase="crypto")

        _emit("phase_start", phase="recon")
        await _phase_recon(client, cfg, result)
        _emit(
            "phase_end",
            phase="recon",
            subdomains=len(result.recon_subdomains),
            committers=len(result.github_committers),
            candidates=len(result.email_candidates),
            secrets=len(result.leaked_secrets),
        )

        _emit("phase_start", phase="gitleaks")
        await _phase_gitleaks(cfg, result)
        _emit("phase_end", phase="gitleaks", secrets=len(result.leaked_secrets))

        _emit("phase_start", phase="exif")
        await _phase_exif(client, cfg, result)
        _emit("phase_end", phase="exif", reports=len(result.exif_reports))

        _emit("phase_start", phase="wigle")
        await _phase_wigle(client, cfg, result)
        _emit("phase_end", phase="wigle")

        _emit("phase_start", phase="company")
        await _phase_company(client, cfg, result)
        _emit(
            "phase_end",
            phase="company",
            companies=len(result.company_records),
        )

        _emit("phase_start", phase="doc_metadata")
        await _phase_doc_metadata(client, cfg, result)
        _emit(
            "phase_end",
            phase="doc_metadata",
            documents=len(result.document_metadata),
        )

        _emit("phase_start", phase="intelx")
        await _phase_intelx(client, cfg, result)
        _emit("phase_end", phase="intelx")

        # Drain any in-flight soft-404 baseline seed tasks while the
        # HTTPClient session is still alive. Short timeout — these are
        # purely cache-warming and must not block the scan if a site stalls.
        if _PENDING_SEED_TASKS:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*_PENDING_SEED_TASKS, return_exceptions=True),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                log.debug("soft-404 seed drain timed out; tasks will continue in background")

    _emit("phase_start", phase="cross_reference")
    _finalize_cross_reference(result)
    _emit("phase_end", phase="cross_reference")

    if cfg.geocode:
        _emit("phase_start", phase="geocode")
        await _phase_geocode(cfg, result)
        _emit("phase_end", phase="geocode", resolved=len(result.geo_points))

    _emit("phase_start", phase="enrichment")
    _phase_enrichment(cfg, result)
    _emit("phase_end", phase="enrichment")

    result.scan_time = time.monotonic() - start_time
    _emit(
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
    smart: bool = False,
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
