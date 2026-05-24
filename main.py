#!/usr/bin/env python3
"""CyberM4fia OSINT — Public intelligence gathering framework entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import replace
from datetime import datetime, timezone

from core import watchlist
from core.bulk import load_usernames_from_file, run_bulk
from core.config import ScanConfig
from core.engine import run_scan
from core.graph_export import export_dot
from core.history import diff_entries, get_latest, list_scans
from core.logging_setup import configure_logging, get_logger
from core.plugins import load_plugins
from core.reporter import (
    console,
    export_csv,
    export_html,
    export_json,
    export_misp,
    export_obsidian,
    export_pdf,
    export_stix,
    export_xlsx,
    pdf_available,
    print_banner,
    print_breach_notice,
    print_results,
    print_scan_start,
    xlsx_available,
)
from core.scan_service import complete_scan_result
from core.search import search as history_search
from modules.platforms import get_platform_count
from utils.helpers import sanitize_username

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberm4fia-osint",
        description="OSINT intelligence gathering tool",
    )
    p.add_argument(
        "username",
        nargs="?",
        default=None,
        help="Username to search for (optional when using --watchlist-* or --bulk)",
    )
    p.add_argument(
        "--smart", "-s", action="store_true",
        help="Smart search: username variations + discovered accounts",
    )
    p.add_argument(
        "--deep", "-d", action="store_true", default=True,
        help="Deep profile scraping (default: on)",
    )
    p.add_argument("--no-deep", action="store_true", help="Disable deep profile scraping")
    p.add_argument("--email", "-e", action="store_true", help="Email discovery and Gravatar check")
    p.add_argument("--web", "-w", action="store_true", help="Web presence scan")
    p.add_argument(
        "--full", "-f", action="store_true",
        help="Full scan (default: already on). Kept for backward compatibility.",
    )
    p.add_argument(
        "--quick", "-q", action="store_true",
        help="Quick mode: platform sweep only (disables default full scan)",
    )
    p.add_argument(
        "--category", "-c", type=str, default=None,
        help="Restrict to specific categories (example: social,dev,gaming)",
    )
    p.add_argument("--whois", action="store_true", help="WHOIS lookups (9 TLDs)")
    p.add_argument(
        "--breach", "--hibp", dest="breach", action="store_true",
        help="HIBP breach check (enables email discovery; HIBP_API_KEY required)",
    )
    p.add_argument("--photo", action="store_true", help="Profile photo comparison")
    p.add_argument("--dns", action="store_true", help="DNS record lookup")
    p.add_argument("--subdomain", action="store_true", help="Subdomain enumeration (crt.sh)")
    p.add_argument(
        "--holehe", action="store_true",
        help="Probe ~120 sites for each discovered email (requires holehe extra)",
    )
    p.add_argument(
        "--ghunt", action="store_true",
        help="Resolve Google account from each email (requires `ghunt login` once)",
    )
    p.add_argument(
        "--toutatis", action="store_true",
        help="Instagram OSINT lookup (set IG_SESSION_ID env for richer data)",
    )
    p.add_argument(
        "--recursive", action="store_true",
        help="Feed discovered usernames back into the platform sweep",
    )
    p.add_argument(
        "--recursive-depth", dest="recursive_depth", type=int, default=1,
        help="How many recursion passes to run (default 1)",
    )
    p.add_argument(
        "--tor", "-toor", action="store_true",
        help="Route through Tor (socks5://127.0.0.1:9050)",
    )
    p.add_argument("--proxy", type=str, default=None, help="Proxy address")
    p.add_argument(
        "--proxy-pool",
        dest="proxy_pool",
        type=str,
        default=None,
        metavar="P1,P2,...",
        help="Comma-separated list of HTTP/HTTPS proxies rotated round-robin "
             "with dead-proxy pruning",
    )
    p.add_argument(
        "--proxy-file",
        dest="proxy_file",
        type=str,
        default=None,
        metavar="PATH",
        help="Newline-delimited proxy file (#-prefixed lines are comments)",
    )
    p.add_argument(
        "--output", "-o", type=str, default=None,
        help="Save results (.json/.html/.pdf/.csv/.xlsx/.dot/.misp.json/.stix.json or dir ending with / for Obsidian vault)",
    )
    p.add_argument("--timeout", "-t", type=int, default=None, help="Request timeout (seconds)")
    p.add_argument(
        "--fp-threshold",
        dest="fp_threshold",
        type=float,
        default=None,
        help="Drop platform matches below this confidence score (default 0.45)",
    )
    p.add_argument(
        "--log-level", default=None,
        help="Diagnostic log level (DEBUG, INFO, WARNING, ERROR)",
    )
    p.add_argument(
        "--history", action="store_true",
        help="List prior scans for this username and exit",
    )
    p.add_argument(
        "--diff", action="store_true",
        help="Diff against the previous scan after running",
    )
    p.add_argument(
        "--no-history", action="store_true",
        help="Do not persist this scan to history",
    )
    p.add_argument(
        "--no-fingerprint",
        dest="no_fingerprint",
        action="store_true",
        help="Disable browser-consistent sec-ch-ua/sec-fetch fingerprint headers",
    )
    p.add_argument(
        "--new-circuit-every",
        dest="new_circuit_every",
        type=int,
        default=0,
        help="Rotate Tor circuit every N requests (requires --tor and stem)",
    )
    p.add_argument(
        "--tor-control-password",
        dest="tor_control_password",
        type=str,
        default=None,
        help="Password for the Tor control port (optional)",
    )
    p.add_argument(
        "--playwright",
        action="store_true",
        help="Force the selected browser backend for every platform (default: only js_heavy ones)",
    )
    p.add_argument(
        "--browser-backend",
        dest="browser_backend",
        choices=("playwright", "obscura"),
        default="playwright",
        help="Browser renderer for JS-heavy pages (default: playwright)",
    )
    p.add_argument(
        "--no-auto-render",
        dest="no_auto_render",
        action="store_true",
        help="Disable automatic browser fallback when aiohttp hits a JS/CDN wall",
    )
    p.add_argument(
        "--screenshots",
        action="store_true",
        help="Save Playwright screenshots alongside the scan payload",
    )
    p.add_argument(
        "--screenshot-dir",
        dest="screenshot_dir",
        type=str,
        default=None,
        help="Directory to drop screenshots into (default: reports/screenshots/<user>)",
    )
    p.add_argument(
        "--geocode",
        action="store_true",
        help="Resolve discovered locations via Nominatim for the heatmap "
        "(cached locally; 1 req/s upstream rate limit)",
    )
    p.add_argument(
        "--passive",
        action="store_true",
        help="Run passive intel sources (Shodan/Censys/FOFA/ZoomEye/Pastebin/Ahmia/Wayback)",
    )
    p.add_argument(
        "--domain",
        dest="domain",
        type=str,
        default=None,
        help="Domain pivot for passive intel (e.g. example.com)",
    )
    p.add_argument(
        "--reverse-image",
        dest="reverse_image",
        action="store_true",
        help="Run reverse image search on discovered profile pictures (Yandex + TinEye)",
    )
    p.add_argument(
        "--past-usernames",
        dest="past_usernames",
        action="store_true",
        help="Discover historical usernames via Wayback CDX",
    )
    p.add_argument(
        "--phone",
        dest="phone",
        type=str,
        default=None,
        help="Phone number to enrich (E.164 preferred, e.g. +14155552671)",
    )
    p.add_argument(
        "--phone-region",
        dest="phone_region",
        type=str,
        default=None,
        help="Default ISO region for --phone (e.g. US, TR) when not E.164",
    )
    p.add_argument(
        "--crypto",
        dest="crypto",
        type=str,
        default=None,
        help="Comma-separated BTC/ETH addresses to enrich",
    )
    p.add_argument(
        "--serve", action="store_true",
        help="Start the FastAPI REST server (requires fastapi + uvicorn)",
    )
    p.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Bind host for --serve (default 127.0.0.1)",
    )
    p.add_argument(
        "--port", type=int, default=8000,
        help="Bind port for --serve (default 8000)",
    )
    p.add_argument(
        "--correlate",
        dest="correlate",
        type=str,
        default=None,
        metavar="USER_A,USER_B",
        help="Score how likely two usernames are the same person "
             "(uses the latest scan history for each). Exits after printing.",
    )
    p.add_argument(
        "--compare",
        dest="compare",
        type=str,
        default=None,
        metavar="USER_A,USER_B",
        help="Side-by-side diff of two scans (latest for each user). "
             "Exits after printing the change summary.",
    )
    p.add_argument(
        "--social-graph",
        dest="social_graph",
        type=str,
        default=None,
        metavar="USER_A,USER_B",
        help="Compare GitHub follower/following overlap between two users. "
             "Exits after printing the shared-connections report.",
    )
    p.add_argument(
        "--search-history",
        dest="search_history",
        type=str,
        default=None,
        metavar="QUERY",
        help="Full-text search across saved scan history (FTS5). "
             "Exits after printing the top matches.",
    )
    p.add_argument(
        "--case-new", dest="case_new", type=str, default=None, metavar="NAME",
        help="Create a new investigation case and exit",
    )
    p.add_argument(
        "--case-list", dest="case_list", action="store_true",
        help="List all investigation cases and exit",
    )
    p.add_argument(
        "--case-show", dest="case_show", type=int, default=None, metavar="ID",
        help="Show a case with its notes and bookmarks, then exit",
    )
    p.add_argument(
        "--case-note", dest="case_note", type=str, default=None, metavar="ID:BODY",
        help="Append a note to a case (format: '7:lead on suspect X')",
    )
    p.add_argument(
        "--case-bookmark", dest="case_bookmark", type=str, default=None,
        metavar="ID:TYPE:VALUE",
        help="Add a bookmark to a case (e.g. '7:email:x@y.io')",
    )
    p.add_argument(
        "--case-close", dest="case_close", type=int, default=None, metavar="ID",
        help="Mark a case as closed and exit",
    )
    p.add_argument(
        "--create-user",
        dest="create_user",
        type=str,
        default=None,
        metavar="USER:PASS[:ROLE]",
        help="Create an auth user and exit (role defaults to analyst; "
             "valid: admin/analyst/viewer). Enable the gate with OSINT_AUTH_REQUIRED=1.",
    )
    p.add_argument(
        "--watchlist-add", dest="watchlist_add", type=str, default=None,
        help="Add a username to the watchlist and exit",
    )
    p.add_argument(
        "--watchlist-remove", dest="watchlist_remove", type=str, default=None,
        help="Remove a username from the watchlist and exit",
    )
    p.add_argument(
        "--watchlist-list", dest="watchlist_list", action="store_true",
        help="List watchlist entries and exit",
    )
    p.add_argument(
        "--watchlist-scan", dest="watchlist_scan", action="store_true",
        help="Run a scan for every username in the watchlist",
    )
    p.add_argument(
        "--bulk", dest="bulk", type=str, default=None,
        help="Path to a newline-delimited file of usernames to scan in bulk",
    )
    p.add_argument(
        "--bulk-parallel", dest="bulk_parallel", type=int, default=3,
        help="Concurrency cap for --bulk / --watchlist-scan (default 3)",
    )
    p.add_argument(
        "--no-enrichment",
        dest="no_enrichment",
        action="store_true",
        help="Skip offline enrichment (stylometry/language/timezone/entity graph)",
    )
    p.add_argument(
        "--schedule", dest="schedule", action="store_true",
        help="Run the scheduler: repeatedly scan every watchlist entry and fire notifications on diffs",
    )
    p.add_argument(
        "--schedule-interval", dest="schedule_interval", type=float, default=60.0,
        help="Minutes between scheduled passes (default 60)",
    )
    # ── Name / email entrypoints — alternatives to the positional username ──
    p.add_argument(
        "--name", dest="name", type=str, default=None,
        metavar="\"Tam Ad\"",
        help="Real name → generate candidate handles (Turkish diacritic fold + "
        "permutations) and run the full sweep against the top-N candidates. "
        "Works without a positional username.",
    )
    p.add_argument(
        "--name-year", dest="name_year", type=int, default=None,
        help="Birth/registration year hint for --name (adds year-suffix variants)",
    )
    p.add_argument(
        "--name-max-handles", dest="name_max_handles", type=int, default=8,
        help="How many top candidate handles to actually scan (default 8)",
    )
    p.add_argument(
        "--email-only", dest="email_only", type=str, default=None,
        metavar="user@example.com",
        help="Email-first scan: Gravatar + HIBP + Holehe + GHunt + IntelX. "
        "Local-part is also fed into the --name handle generator.",
    )
    p.add_argument(
        "--ai-skills", dest="ai_skills", action="store_true",
        help="Enable LLM-backed augmentation skills (handle generation, "
        "profile validation). Requires CYBERM4FIA_LLM_API_KEY for NVIDIA NIM.",
    )
    p.add_argument(
        "--ai-skill-budget", dest="ai_skill_budget", type=int, default=20,
        help="Max LLM calls per scan when --ai-skills is on (default 20)",
    )

    # ── Standalone OSINT pivots (independent of username/redteam flow) ──
    p.add_argument(
        "--bssid", dest="bssid", type=str, default=None,
        metavar="MAC",
        help="BSSID/MAC to resolve to a physical location via Wigle.net "
        "(needs WIGLE_API_NAME + WIGLE_API_TOKEN)",
    )
    p.add_argument(
        "--ssid", dest="ssid", type=str, default=None,
        help="SSID name to enumerate every location it has been seen at "
        "(Wigle.net; same auth as --bssid)",
    )
    p.add_argument(
        "--company", dest="company", type=str, default=None,
        metavar="NAME",
        help="Company name (or domain root) to look up in OpenCorporates: "
        "fetches officers/directors per result. Anonymous tier works; "
        "OPENCORPORATES_API_TOKEN raises rate limits.",
    )
    p.add_argument(
        "--company-limit", dest="company_limit", type=int, default=5,
        help="Max companies to fully enrich for --company (default 5; each "
        "company costs one extra API call for the officer list)",
    )
    p.add_argument(
        "--harvest-doc", dest="harvest_doc", action="append", default=None,
        metavar="URL",
        help="URL of a public PDF/DOCX/XLSX/PPTX to extract embedded "
        "metadata from (repeatable). Pairs with --passive output's google "
        "dork \"files\" preset.",
    )
    p.add_argument(
        "--intelx", dest="intelx", type=str, default=None,
        metavar="TERM",
        help="Intelligence X selector to search (domain / email / IP / "
        "BTC address / freeform). Hits land in passive_hits. "
        "Requires INTELX_API_KEY.",
    )
    p.add_argument(
        "--intelx-limit", dest="intelx_limit", type=int, default=50,
        help="Cap on IntelX records per search (default 50)",
    )
    p.add_argument(
        "--gitleaks-path",
        dest="gitleaks_path",
        action="append",
        default=[],
        metavar="PATH",
        help="Run optional local Gitleaks secret scan against a repo/path. "
        "Requires the gitleaks binary.",
    )
    p.add_argument(
        "--gitleaks-no-git",
        dest="gitleaks_no_git",
        action="store_true",
        help="Pass --no-git to Gitleaks for plain directory snapshots",
    )
    p.add_argument(
        "--gitleaks-timeout",
        dest="gitleaks_timeout",
        type=int,
        default=120,
        help="Seconds before a local Gitleaks scan is cancelled (default 120)",
    )

    # ── Red-team recon mode (corporate attack surface, CSV exports only) ──
    p.add_argument(
        "--redteam-domain", dest="redteam_domain", type=str, default=None,
        help="Enable red-team recon for a corporate domain (e.g. acme.com)",
    )
    p.add_argument(
        "--redteam-names-file", dest="redteam_names_file", type=str, default=None,
        help="Newline-delimited file of employee full names for email pattern generation",
    )
    p.add_argument(
        "--redteam-github-org", dest="redteam_github_org", type=str, default=None,
        help="GitHub org to harvest committer emails from (defaults to domain label)",
    )
    p.add_argument(
        "--redteam-out", dest="redteam_out", type=str, default="reports/redteam",
        help="Output directory for red-team CSVs (default reports/redteam)",
    )
    # ── Social engineering arsenal (opt-in, needs a preceding --redteam-*) ──
    p.add_argument(
        "--se-arsenal", dest="se_arsenal", action="store_true",
        help="After red-team recon, generate lookalike domains + (optional) "
        "GoPhish push + LLM pretext drafts",
    )
    p.add_argument(
        "--se-gophish-url", dest="se_gophish_url", type=str, default=None,
        help="GoPhish base URL (e.g. https://host:3333). If set with --se-gophish-key, "
        "pushes targets as a new group",
    )
    p.add_argument(
        "--se-gophish-key", dest="se_gophish_key", type=str, default=None,
        help="GoPhish API key (defaults to $GOPHISH_API_KEY)",
    )
    p.add_argument(
        "--se-gophish-insecure", dest="se_gophish_insecure", action="store_true",
        help="Skip TLS verification for GoPhish (self-signed lab hosts only)",
    )
    p.add_argument(
        "--se-pretext-targets", dest="se_pretext_targets", type=str, default=None,
        help="Comma-separated target emails for LLM pretext drafts (max ~5)",
    )
    p.add_argument(
        "--se-pretext-hint", dest="se_pretext_hint", type=str, default="",
        help="Operator hint steering pretext style (e.g. 'Q1 close, vendor invoice')",
    )
    return p


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _show_history(username: str) -> None:
    entries = list_scans(username)
    if not entries:
        console.print(f"  [yellow]No saved scans for '{username}'.[/yellow]")
        return
    console.print(f"\n  [bold]Scan history for '{username}'[/bold] ({len(entries)})")
    for e in entries:
        console.print(f"    [cyan]#{e.id}[/cyan]  {_fmt_ts(e.ts)}  found: {e.found_count}")


def _run_ai_analysis(result) -> None:
    """Run AI analysis if a local LLM is available — skip silently if not."""
    try:
        from core.analysis import LLMAnalyzer, LLMUnavailable
    except ImportError:
        log.debug("AI module not importable — skipping")
        return
    try:
        analyzer = LLMAnalyzer.from_env()
    except LLMUnavailable:
        log.debug("no GGUF model configured — skipping AI analysis")
        return
    console.print("  [cyan]Running AI analysis (local LLM)...[/cyan]")
    try:
        report = analyzer.analyze(result.to_dict())
    except Exception as exc:
        log.warning("AI analysis failed: %s", exc)
        return
    result.ai_report = report.to_dict()


def _print_diff(username: str, result) -> None:
    current = get_latest(username)
    if current is None:
        console.print("  [dim]diff: no previous scan to compare against.[/dim]")
        return
    previous = get_latest(username, before_id=current.id)
    if previous is None:
        console.print("  [dim]diff: no previous scan to compare against.[/dim]")
        return
    d = diff_entries(previous, current)
    console.print(
        f"\n  [bold]Diff[/bold] #{previous.id} ({_fmt_ts(previous.ts)}) "
        f"-> #{current.id} ({_fmt_ts(current.ts)})"
    )
    if d.added:
        console.print("    [green]+ " + ", ".join(d.added) + "[/green]")
    if d.removed:
        console.print("    [red]- " + ", ".join(d.removed) + "[/red]")
    if not d.added and not d.removed:
        console.print("    [dim]no changes.[/dim]")


def _save_report(result, path: str) -> None:
    lower = path.lower()
    if lower.endswith(".json"):
        export_json(result, path)
    elif lower.endswith(".html"):
        export_html(result, path)
    elif lower.endswith(".dot"):
        export_dot(result, path)
    elif lower.endswith(".pdf"):
        if not pdf_available():
            console.print(
                "  [yellow]reportlab not installed; skipping PDF export.[/yellow]"
            )
            return
        export_pdf(result, path)
        console.print(f"  [green]PDF rapor kaydedildi:[/green] {path}")
    elif lower.endswith(".csv") or lower.endswith(".csv.zip"):
        export_csv(result, path)
    elif lower.endswith(".xlsx"):
        if not xlsx_available():
            console.print(
                "  [yellow]openpyxl not installed; skipping XLSX export.[/yellow]"
            )
            return
        export_xlsx(result, path)
    elif lower.endswith(".misp.json"):
        export_misp(result, path)
        console.print(f"  [green]MISP event kaydedildi:[/green] {path}")
    elif lower.endswith(".stix.json"):
        export_stix(result, path)
        console.print(f"  [green]STIX bundle kaydedildi:[/green] {path}")
    elif lower.endswith("/") or lower.endswith(".obsidian"):
        export_obsidian(result, path.rstrip("/"))
        console.print(f"  [green]Obsidian vault kaydedildi:[/green] {path}")
    else:
        export_json(result, path + ".json")


def _handle_watchlist_commands(args) -> bool:
    """Handle --watchlist-* commands. Returns True if one was executed."""
    if args.watchlist_add:
        entry = watchlist.add(args.watchlist_add)
        console.print(
            f"  [green]Added[/green] [bold]{entry.username}[/bold] to watchlist "
            f"(id={entry.id})"
        )
        return True
    if args.watchlist_remove:
        ok = watchlist.remove(args.watchlist_remove)
        color = "green" if ok else "yellow"
        verb = "Removed" if ok else "Not found"
        console.print(
            f"  [{color}]{verb}[/{color}] [bold]{args.watchlist_remove}[/bold]"
        )
        return True
    if args.watchlist_list:
        entries = watchlist.list_all()
        if not entries:
            console.print("  [yellow]Watchlist is empty.[/yellow]")
            return True
        console.print(f"\n  [bold]Watchlist[/bold] ({len(entries)} entries)")
        for e in entries:
            last = _fmt_ts(e.last_scan_at) if e.last_scan_at else "never"
            tag_str = ",".join(e.tags) if e.tags else "-"
            console.print(
                f"    [cyan]#{e.id}[/cyan] {e.username}  "
                f"added:{_fmt_ts(e.added_at)}  last:{last}  tags:{tag_str}"
            )
        return True
    return False


async def _run_bulk_mode(usernames: list[str], args, from_watchlist: bool) -> None:
    if not usernames:
        console.print("  [yellow]No usernames to scan.[/yellow]")
        return

    template_ns = argparse.Namespace(**vars(args))
    template_ns.username = usernames[0]
    cfg_template = ScanConfig.from_args(template_ns, usernames[0])

    print_banner()
    console.print(
        f"  [bold]Bulk scan[/bold]: {len(usernames)} targets, "
        f"parallel={args.bulk_parallel}"
    )

    results = await run_bulk(
        usernames, cfg_template, max_parallel=args.bulk_parallel
    )
    plugin_registry = load_plugins()

    for username, result in zip(usernames, results, strict=True):
        print_results(result)
        cfg = replace(cfg_template, username=username)
        try:
            complete_scan_result(
                result,
                cfg,
                save_history=not args.no_history,
                mark_watchlist=from_watchlist,
            )
        except (OSError, ValueError) as exc:
            log.warning("scan finalization failed for %s: %s", username, exc)
        try:
            plugin_registry.run_post_scan(
                result, cfg
            )
        except Exception as exc:
            log.warning("plugin hooks failed for %s: %s", username, exc)

    console.print(
        f"\n  [bold green]Bulk complete[/bold green]: {len(results)} scans"
    )


def _run_correlate(spec: str) -> None:
    """Handle --correlate USER_A,USER_B: compare latest histories and print."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if len(parts) != 2:
        console.print(
            "  [red]--correlate expects exactly two usernames, "
            "comma-separated (e.g. --correlate alice,bob)[/red]"
        )
        sys.exit(2)
    a_user, b_user = parts
    if a_user.lower() == b_user.lower():
        console.print("  [red]--correlate: a and b must differ[/red]")
        sys.exit(2)

    from core.correlation import correlate
    from core.history import get_latest

    a_entry = get_latest(a_user)
    if a_entry is None:
        console.print(f"  [red]No scan history for {a_user} — run a scan first.[/red]")
        sys.exit(1)
    b_entry = get_latest(b_user)
    if b_entry is None:
        console.print(f"  [red]No scan history for {b_user} — run a scan first.[/red]")
        sys.exit(1)

    result = correlate(a_entry.payload, b_entry.payload)
    pct = round(result.score * 100)
    verdict_color = {
        "very_likely_same": "bright_green",
        "likely_same": "green",
        "possible": "yellow",
        "weak_signal": "yellow",
        "no_evidence": "red",
    }.get(result.verdict, "white")
    console.print(
        f"\n  [bold]{a_user}[/bold] vs [bold]{b_user}[/bold] — "
        f"[{verdict_color}]{pct}%[/{verdict_color}] "
        f"([{verdict_color}]{result.verdict}[/{verdict_color}])"
    )
    if not result.signals:
        console.print("  [dim]no shared signals[/dim]")
        return
    for sig in result.signals:
        console.print(
            f"    [cyan]{sig.kind:<9}[/cyan] +{round(sig.weight * 100):>3}%  {sig.detail}"
        )


def _run_compare(spec: str) -> None:
    """Handle --compare USER_A,USER_B: deep-diff latest scans and print summary."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if len(parts) != 2:
        console.print(
            "  [red]--compare expects exactly two usernames, "
            "comma-separated (e.g. --compare alice,bob)[/red]"
        )
        sys.exit(2)
    a_user, b_user = parts

    from core.compare import compare_payloads
    from core.history import get_latest

    a_entry = get_latest(a_user)
    if a_entry is None:
        console.print(f"  [red]No scan history for {a_user} — run a scan first.[/red]")
        sys.exit(1)
    b_entry = get_latest(b_user)
    if b_entry is None:
        console.print(f"  [red]No scan history for {b_user} — run a scan first.[/red]")
        sys.exit(1)

    diff = compare_payloads(a_entry.payload, b_entry.payload)
    delta = diff.found_count_delta
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    console.print(
        f"\n  [bold]{a_user}[/bold] (#{a_entry.id}, {_fmt_ts(a_entry.ts)})  →  "
        f"[bold]{b_user}[/bold] (#{b_entry.id}, {_fmt_ts(b_entry.ts)})"
    )
    console.print(f"  [dim]{diff.summary}[/dim]  found_count Δ {delta_str}")

    buckets = [
        ("platforms", diff.platforms),
        ("emails", diff.emails),
        ("breaches", diff.breaches),
        ("phones", diff.phones),
        ("crypto", diff.crypto),
        ("geo", diff.geo),
    ]
    for title, bucket in buckets:
        if not bucket.added and not bucket.removed:
            continue
        console.print(f"\n  [bold]{title}[/bold]")
        for item in bucket.added:
            console.print(f"    [green]+ {item}[/green]")
        for item in bucket.removed:
            console.print(f"    [red]- {item}[/red]")

    if diff.platform_changes:
        console.print("\n  [bold]platform profile changes[/bold]")
        for pc in diff.platform_changes:
            console.print(f"    [cyan]{pc.platform}[/cyan]")
            for fc in pc.changes:
                console.print(
                    f"      {fc.field}: [red]{fc.old!r}[/red] → [green]{fc.new!r}[/green]"
                )


def _run_case_commands(args) -> bool:
    """Dispatch --case-* flags. Returns True if a case command ran."""
    from core import cases

    if args.case_new:
        try:
            c = cases.create_case(args.case_new)
        except ValueError as exc:
            console.print(f"  [red]{exc}[/red]")
            sys.exit(1)
        console.print(
            f"  [green]Created case #{c.id}[/green]: {c.name} ({c.status})"
        )
        return True

    if args.case_list:
        entries = cases.list_cases()
        if not entries:
            console.print("  [yellow]No cases yet. Use --case-new NAME.[/yellow]")
            return True
        console.print(f"\n  [bold]Cases[/bold] ({len(entries)})")
        for c in entries:
            console.print(
                f"    [cyan]#{c.id:>3}[/cyan]  {c.status:<8}  "
                f"{_fmt_ts(c.created_ts)}  {c.name}"
            )
        return True

    if args.case_show is not None:
        c = cases.get_case(args.case_show)
        if c is None:
            console.print(f"  [red]Case #{args.case_show} not found[/red]")
            sys.exit(1)
        console.print(
            f"\n  [bold]Case #{c.id}[/bold]: {c.name} "
            f"([yellow]{c.status}[/yellow])"
        )
        if c.description:
            console.print(f"  {c.description}")
        console.print(
            f"  [dim]created {_fmt_ts(c.created_ts)}  updated {_fmt_ts(c.updated_ts)}[/dim]"
        )
        notes = cases.list_notes(c.id)
        if notes:
            console.print("\n  [bold]Notes[/bold]")
            for n in notes:
                console.print(f"    [cyan]#{n.id}[/cyan]  {_fmt_ts(n.created_ts)}")
                console.print(f"      {n.body}")
        bms = cases.list_bookmarks(c.id)
        if bms:
            console.print("\n  [bold]Bookmarks[/bold]")
            for b in bms:
                label = f" — {b.label}" if b.label else ""
                console.print(
                    f"    [cyan]#{b.id}[/cyan]  {b.target_type}:{b.target_value}{label}"
                )
        return True

    if args.case_note:
        spec = args.case_note
        sep = spec.find(":")
        if sep <= 0:
            console.print(
                "  [red]--case-note expects 'ID:BODY' (e.g. '7:lead on X')[/red]"
            )
            sys.exit(2)
        try:
            case_id = int(spec[:sep])
        except ValueError:
            console.print("  [red]--case-note: ID must be an integer[/red]")
            sys.exit(2)
        body = spec[sep + 1:]
        try:
            n = cases.add_note(case_id, body)
        except ValueError as exc:
            console.print(f"  [red]{exc}[/red]")
            sys.exit(1)
        console.print(f"  [green]Added note #{n.id}[/green] to case #{case_id}")
        return True

    if args.case_bookmark:
        parts = args.case_bookmark.split(":", 2)
        if len(parts) != 3:
            console.print(
                "  [red]--case-bookmark expects 'ID:TYPE:VALUE' "
                "(e.g. '7:email:x@y.io')[/red]"
            )
            sys.exit(2)
        try:
            case_id = int(parts[0])
        except ValueError:
            console.print("  [red]--case-bookmark: ID must be an integer[/red]")
            sys.exit(2)
        try:
            b = cases.add_bookmark(
                case_id, target_type=parts[1], target_value=parts[2]
            )
        except ValueError as exc:
            console.print(f"  [red]{exc}[/red]")
            sys.exit(1)
        console.print(
            f"  [green]Added bookmark #{b.id}[/green]: "
            f"{b.target_type}:{b.target_value}"
        )
        return True

    if args.case_close is not None:
        updated = cases.update_case(args.case_close, status="closed")
        if updated is None:
            console.print(f"  [red]Case #{args.case_close} not found[/red]")
            sys.exit(1)
        console.print(f"  [green]Closed case #{updated.id}[/green]: {updated.name}")
        return True

    return False


def _run_create_user(spec: str) -> None:
    """Handle --create-user USER:PASS[:ROLE]: persist a new auth user."""
    from core import auth

    parts = spec.split(":", 2)
    if len(parts) < 2 or not parts[0].strip() or not parts[1]:
        console.print(
            "  [red]--create-user expects 'USER:PASS' or 'USER:PASS:ROLE' "
            "(e.g. 'alice:s3cret' or 'alice:s3cret:admin')[/red]"
        )
        sys.exit(2)
    username = parts[0].strip()
    password = parts[1]
    role = parts[2].strip() if len(parts) == 3 and parts[2].strip() else "analyst"
    if role not in auth.VALID_ROLES:
        console.print(
            f"  [red]--create-user: role must be one of "
            f"{sorted(auth.VALID_ROLES)}[/red]"
        )
        sys.exit(2)
    try:
        user = auth.create_user(username, password, role=role)
    except ValueError as exc:
        console.print(f"  [red]--create-user: {exc}[/red]")
        sys.exit(1)
    console.print(
        f"  [green]Created user[/green] #{user.id} "
        f"[bold]{user.username}[/bold] role=[cyan]{user.role}[/cyan]"
    )


def _run_social_graph(spec: str) -> None:
    """Handle --social-graph USER_A,USER_B: fetch GitHub neighbours + overlap."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if len(parts) != 2:
        console.print(
            "  [red]--social-graph expects exactly two usernames, "
            "comma-separated (e.g. --social-graph alice,bob)[/red]"
        )
        sys.exit(2)
    a_user, b_user = parts

    from core.http_client import HTTPClient
    from core.social_graph import compute_overlap, fetch_github_neighbors

    async def _go():
        async with HTTPClient() as client:
            a = await fetch_github_neighbors(client, a_user)
            b = await fetch_github_neighbors(client, b_user)
        return a, b

    console.print(
        f"  [cyan]Fetching GitHub neighbours for {a_user} and {b_user}…[/cyan]"
    )
    neighbors_a, neighbors_b = asyncio.run(_go())
    overlap = compute_overlap(neighbors_a, neighbors_b)

    pct = round(overlap.combined_score * 100)
    console.print(
        f"\n  [bold]{a_user}[/bold] ({len(neighbors_a.followers)} followers, "
        f"{len(neighbors_a.following)} following) ↔ "
        f"[bold]{b_user}[/bold] ({len(neighbors_b.followers)} followers, "
        f"{len(neighbors_b.following)} following) — "
        f"[yellow]{pct}% overlap[/yellow]"
    )
    if overlap.shared_followers:
        console.print("\n  [bold]shared followers[/bold]")
        for login in overlap.shared_followers:
            console.print(f"    [green]+ {login}[/green]")
    if overlap.shared_following:
        console.print("\n  [bold]shared following[/bold]")
        for login in overlap.shared_following:
            console.print(f"    [green]+ {login}[/green]")
    if not overlap.shared_followers and not overlap.shared_following:
        console.print("  [dim]no shared connections[/dim]")


def _run_search_history(query: str) -> None:
    """Handle --search-history QUERY: FTS5 full-text search across saved scans."""
    q = query.strip()
    if not q:
        console.print("  [red]--search-history: query is empty[/red]")
        sys.exit(2)

    hits = history_search(q, limit=20)
    if not hits:
        console.print(f"  [yellow]no matches for[/yellow] [bold]{q}[/bold]")
        return

    console.print(
        f"\n  [bold]{len(hits)} match{'es' if len(hits) != 1 else ''}[/bold] "
        f"for [cyan]{q}[/cyan]\n"
    )
    for hit in hits:
        when = datetime.fromtimestamp(hit.ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M"
        )
        console.print(
            f"  [green]#{hit.id}[/green] "
            f"[bold]{hit.username}[/bold] "
            f"[dim]{when}[/dim] "
            f"({hit.found_count} found)"
        )
        if hit.snippet:
            console.print(f"    [dim]{hit.snippet}[/dim]")


def _load_names(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError as exc:
        console.print(f"  [red]Could not read names file {path}: {exc}[/red]")
        return []


async def _redteam_pipeline(args: argparse.Namespace) -> int:
    """Run every red-team phase and emit CSVs. Returns exit code."""
    from pathlib import Path

    from core.http_client import HTTPClient
    from core.reporter.redteam_export import (
        export_attack_surface,
        export_phishing_targets,
    )
    from modules.dns_lookup import enumerate_subdomains
    from modules.recon import email_patterns, github_org, subdomains_extra

    domain = args.redteam_domain.strip().lower().lstrip("@")
    org = (args.redteam_github_org or domain.split(".", 1)[0]).strip()
    names = _load_names(args.redteam_names_file) if args.redteam_names_file else []
    out_dir = Path(args.redteam_out)

    console.print(
        f"  [cyan]Red-team recon[/cyan] domain=[bold]{domain}[/bold] "
        f"github_org=[bold]{org}[/bold] names={len(names)}"
    )

    async with HTTPClient() as client:
        seed_subs, committers = await asyncio.gather(
            enumerate_subdomains(client, domain),
            github_org.scan_org(client, org),
        )
        subs = await subdomains_extra.enrich_subdomains(
            client, domain, existing=seed_subs
        )

    candidates = email_patterns.generate_bulk(names, domain) if names else []

    targets_path = out_dir / "phishing_targets.csv"
    surface_path = out_dir / "attack_surface.csv"
    n_targets = export_phishing_targets(
        targets_path, candidates=candidates, committers=committers
    )
    n_surface = export_attack_surface(surface_path, subs)

    console.print(
        f"  [green]targets[/green]={n_targets} → {targets_path}\n"
        f"  [green]surface[/green]={n_surface} → {surface_path}\n"
        f"  [green]committers[/green]={len(committers)} "
        f"[green]candidates[/green]={len(candidates)}"
    )

    if getattr(args, "se_arsenal", False):
        _se_arsenal_stage(
            args,
            out_dir=out_dir,
            domain=domain,
            subs=subs,
            candidates=candidates,
            committers=committers,
        )
    return 0


def _se_arsenal_stage(
    args: argparse.Namespace,
    *,
    out_dir,
    domain: str,
    subs: list,
    candidates: list,
    committers: list,
) -> None:
    """Run lookalike + GoPhish push + LLM pretext stages after recon."""
    import csv
    import os

    from modules.se_arsenal import gophish_client, lookalike, pretext

    # ── lookalike domains ─────────────────────────────────────────────
    seed_domains = [domain] + sorted(
        {s.host for s in subs if s.host and "." in s.host}
    )[:20]
    look = lookalike.generate_bulk(seed_domains)
    out_dir.mkdir(parents=True, exist_ok=True)
    look_path = out_dir / "lookalike_domains.csv"
    with open(look_path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["domain", "technique", "base"])
        for r in look:
            writer.writerow([r.domain, r.technique, r.base])
    console.print(
        f"  [green]lookalikes[/green]={len(look)} → {look_path}"
    )

    # ── GoPhish push (optional) ────────────────────────────────────────
    gurl = args.se_gophish_url
    gkey = args.se_gophish_key or os.environ.get("GOPHISH_API_KEY", "")
    if gurl and gkey:
        targets = gophish_client.targets_from_candidates(
            candidates=candidates, committers=committers
        )
        try:
            client = gophish_client.GoPhishClient(
                gurl, gkey, verify_tls=not args.se_gophish_insecure
            )
            resp = client.push_group(f"cyberm4fia-{domain}", targets)
            console.print(
                f"  [green]gophish[/green] group id={resp.get('id')} "
                f"targets={len(targets)}"
            )
        except gophish_client.GoPhishError as exc:
            console.print(f"  [red]gophish push failed:[/red] {exc}")

    # ── LLM pretext drafts (optional) ──────────────────────────────────
    raw_targets = (args.se_pretext_targets or "").strip()
    if raw_targets:
        target_emails = [t.strip() for t in raw_targets.split(",") if t.strip()][:5]
        payload = {
            "username": domain,
            "platforms": [],
            "recon_subdomains": [s.to_dict() for s in subs],
            "github_committers": [c.to_dict() for c in committers],
            "emails": [{"email": t} for t in target_emails],
        }
        drafts = pretext.generate_bulk(
            payload, target_emails, scenario_hint=args.se_pretext_hint
        )
        pretext_dir = out_dir / "pretexts"
        pretext_dir.mkdir(parents=True, exist_ok=True)
        for draft in drafts:
            safe = draft.target_email.replace("@", "_at_").replace("/", "_")
            path = pretext_dir / f"{safe}.md"
            path.write_text(pretext.render_markdown(draft), encoding="utf-8")
        console.print(
            f"  [green]pretexts[/green]={len(drafts)}/{len(target_emails)} "
            f"→ {pretext_dir}"
        )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.log_level)

    if args.redteam_domain and not args.username:
        sys.exit(asyncio.run(_redteam_pipeline(args)))

    if args.serve:
        from core.api import is_available as api_available
        if not api_available():
            console.print(
                "  [red]--serve requires 'fastapi' and 'uvicorn'. "
                "Install with: pip install fastapi uvicorn[/red]"
            )
            sys.exit(1)
        from core.api.server import serve
        console.print(
            f"  [cyan]Starting API on http://{args.host}:{args.port}[/cyan]"
        )
        serve(host=args.host, port=args.port)
        return

    if args.schedule:
        from core.notify import build_default_notifiers
        from core.scheduler import run_forever

        cfg_template = ScanConfig.from_args(args, username="")
        sinks = build_default_notifiers()
        sink_names = ", ".join(n.name for n in sinks) if sinks else "none"
        console.print(
            f"  [cyan]Scheduler running[/cyan] — interval={args.schedule_interval:.1f} min, "
            f"notifiers=[{sink_names}]"
        )
        try:
            asyncio.run(
                run_forever(
                    cfg_template,
                    interval_minutes=args.schedule_interval,
                    notifiers=sinks,
                )
            )
        except KeyboardInterrupt:
            console.print("  [yellow]Scheduler stopped.[/yellow]")
        return

    if args.correlate:
        _run_correlate(args.correlate)
        return

    if args.compare:
        _run_compare(args.compare)
        return

    if args.social_graph:
        _run_social_graph(args.social_graph)
        return

    if args.search_history:
        _run_search_history(args.search_history)
        return

    if args.create_user:
        _run_create_user(args.create_user)
        return

    if _run_case_commands(args):
        return

    if _handle_watchlist_commands(args):
        return

    if args.watchlist_scan:
        usernames = [e.username for e in watchlist.list_all()]
        asyncio.run(_run_bulk_mode(usernames, args, from_watchlist=True))
        return

    if args.bulk:
        usernames = load_usernames_from_file(args.bulk)
        asyncio.run(_run_bulk_mode(usernames, args, from_watchlist=False))
        return

    # When --name or --email-only is used, a positional username is optional.
    # We synthesise a placeholder so the rest of the CLI keeps working;
    # the engine's handle-resolve / email-only phase replaces it before
    # the platform sweep starts.
    if args.username is None:
        if getattr(args, "name", None):
            args.username = "_name_placeholder_"
        elif getattr(args, "email_only", None):
            local = args.email_only.split("@", 1)[0]
            args.username = sanitize_username(local) or "_email_placeholder_"
        else:
            console.print("[red]Error: please provide a valid username (or use --name / --email-only).[/red]")
            sys.exit(1)

    username = sanitize_username(args.username)
    if not username:
        console.print("[red]Error: please provide a valid username.[/red]")
        sys.exit(1)

    if args.history:
        _show_history(username)
        return

    cfg = ScanConfig.from_args(args, username)

    mode_str = " + ".join(cfg.mode_parts()) or "Basic"
    print_banner()
    if cfg.breach and not args.email and not args.full:
        print_breach_notice()
    print_scan_start(username, mode_str, get_platform_count())

    try:
        result = asyncio.run(run_scan(cfg))
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Scan cancelled.[/yellow]")
        sys.exit(0)

    _run_ai_analysis(result)

    print_results(result)

    try:
        complete_scan_result(
            result,
            cfg,
            save_history=not args.no_history,
            mark_watchlist=True,
        )
    except (OSError, ValueError) as exc:
        log.warning("scan finalization failed: %s", exc)

    if args.diff:
        _print_diff(username, result)

    if args.output:
        _save_report(result, args.output)

    try:
        plugin_registry = load_plugins()
        plugin_registry.run_post_scan(result, cfg)
    except Exception as exc:
        log.warning("plugin hooks failed: %s", exc)


if __name__ == "__main__":
    main()
