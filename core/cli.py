"""Interactive CLI for open-source-intelligence scans.

Usage:
    osint                         # interactive mode
    osint scan <username>         # quick scan with flags
    osint scan <username> --full --no-smart --email

Scans are saved to: log/<username>/<timestamp>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core import history
from core.config import REQUEST_TIMEOUT, ScanConfig
from core.engine import run_scan
from core.models import ScanResult
from core.platform_loader import CATEGORY_LABELS
from core.reporter import (
    export_csv,
    export_html,
    export_json,
    export_misp,
    export_obsidian,
    export_pdf,
    export_stix,
)
from core.scan_service import complete_scan_result
from modules.platforms import PLATFORMS

console = Console()

LOG_DIR = Path("log")
CATEGORIES = sorted(set(p.category for p in PLATFORMS))


def _log_path(username: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in username)
    ts = time.strftime("%Y%m%d_%H%M%S")
    directory = LOG_DIR / safe
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{ts}.json"


def _print_header(username: str, full_name: str | None, platform_count: int) -> None:
    lines = [f"[bold]Target:[/bold] {username}"]
    if full_name:
        lines.append(f"[bold]Full name:[/bold] {full_name}")
    lines.append(f"[bold]Platforms:[/bold] {platform_count}")
    console.print(Panel("\n".join(lines), title="OSINT Scan", border_style="blue"))


def _print_results(result: ScanResult, elapsed: float) -> None:
    found = [
        p for p in result.platforms
        if (p.verification or {}).get("verdict") == "confirmed" or p.exists
    ]
    uncertain = [
        p for p in result.platforms
        if (p.verification or {}).get("verdict") == "uncertain"
    ]
    fake = [
        p for p in result.platforms
        if (p.verification or {}).get("verdict") == "rejected"
    ]
    table = Table(title="Results", border_style="green")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Confirmed platforms", str(len(found)))
    table.add_row("Uncertain candidates", str(len(uncertain)))
    table.add_row("Dropped (false positive)", str(len(fake)))
    table.add_row("Matched before verify", str(sum(1 for p in result.platforms if p.exists)))
    table.add_row("Total checked", str(result.total_checked))
    table.add_row("Emails", str(len(result.emails)))
    table.add_row("Discovered usernames", str(len(result.discovered_usernames)))
    table.add_row("Identity candidates", str(len(result.identity_candidates)))
    table.add_row("Time", f"{elapsed:.1f}s")
    console.print(table)

    if found:
        from collections import defaultdict
        by_cat: dict[str, list] = defaultdict(list)
        for p in sorted(found, key=lambda x: x.confidence, reverse=True):
            by_cat[p.category].append(p)

        for cat in sorted(by_cat):
            cat_found = by_cat[cat]
            cat_table = Table(title=f"[bold]{cat}[/bold] ({len(cat_found)})", border_style="cyan")
            cat_table.add_column("Platform")
            cat_table.add_column("URL", max_width=55)
            cat_table.add_column("Conf", justify="right")
            for p in cat_found:
                conf_str = f"{p.confidence:.0%}" if p.confidence else "?"
                cat_table.add_row(p.platform, p.url[:55], conf_str)
            console.print(cat_table)

    if fake:
        console.print()
        fake_table = Table(title=f"[red]Dropped[/red] ({len(fake)})", border_style="red")
        fake_table.add_column("Platform")
        fake_table.add_column("URL", max_width=55)
        fake_table.add_column("Reason", style="dim")
        for p in sorted(fake, key=lambda x: x.platform):
            reason = p.fp_signals[-1] if p.fp_signals else p.status
            fake_table.add_row(p.platform, p.url[:55], reason)
        console.print(fake_table)

    if not found:
        console.print("\n[dim]No matches confirmed. Try fewer filters or --smart for variations.[/dim]")


def _show_result(result: ScanResult, elapsed: float, log_file: Path | None) -> None:
    _print_results(result, elapsed)
    console.print()

    if result.discovered_usernames:
        console.print(f"[bold]Discovered usernames:[/bold] {', '.join(result.discovered_usernames)}")
        console.print()

    if result.identity_candidates:
        identity_table = Table(
            title="Similar usernames / Identity candidates", border_style="magenta"
        )
        identity_table.add_column("Handle")
        identity_table.add_column("Platforms")
        identity_table.add_column("Verdict")
        identity_table.add_column("Score", justify="right")
        identity_table.add_column("Evidence", max_width=50)
        for candidate in result.identity_candidates:
            row = candidate.to_dict() if hasattr(candidate, "to_dict") else candidate
            profiles = ", ".join(
                profile.get("platform", "") for profile in row.get("profiles", [])
            )
            evidence = "; ".join(
                item.get("detail", "") for item in row.get("evidence", [])[:3]
            )
            identity_table.add_row(
                row.get("username", ""),
                profiles,
                row.get("verdict", "uncertain"),
                f"{float(row.get('score', 0)):.2f}",
                evidence,
            )
        console.print(identity_table)
        console.print()

    if result.emails:
        email_table = Table(title="Emails Found", border_style="yellow")
        email_table.add_column("Email")
        email_table.add_column("Source")
        email_table.add_column("Breaches")
        for e in result.emails:
            email_table.add_row(e.email, e.source, str(e.breach_count))
        console.print(email_table)
        console.print()

    if result.phone_intel:
        phone_table = Table(title="Phone Intel", border_style="cyan")
        phone_table.add_column("Input")
        phone_table.add_column("Country")
        phone_table.add_column("Carrier")
        phone_table.add_column("Line Type")
        phone_table.add_column("Valid")
        for p_item in result.phone_intel:
            p_row = p_item.to_dict() if hasattr(p_item, "to_dict") else p_item
            phone_table.add_row(
                str(p_row.get("input", "")),
                str(p_row.get("country", "")),
                str(p_row.get("carrier", "")),
                str(p_row.get("line_type", "")),
                "Yes" if p_row.get("valid") else "No",
            )
        console.print(phone_table)
        console.print()

    if result.crypto_intel:
        crypto_table = Table(title="Crypto Intel", border_style="green")
        crypto_table.add_column("Address")
        crypto_table.add_column("Network")
        crypto_table.add_column("Balance")
        crypto_table.add_column("Tx Count")
        for c_item in result.crypto_intel:
            c_row = c_item.to_dict() if hasattr(c_item, "to_dict") else c_item
            crypto_table.add_row(
                str(c_row.get("address", ""))[:30],
                str(c_row.get("network", "")),
                str(c_row.get("balance", "0")),
                str(c_row.get("total_txs", 0)),
            )
        console.print(crypto_table)
        console.print()

    if log_file:
        console.print(f"[bold]Saved:[/bold] {log_file}")
    else:
        console.print("[dim]Not saved[/dim]")


def _pick_categories() -> tuple[str, ...] | None:
    console.print("\n[bold]Available categories:[/bold]")
    for i, cat in enumerate(CATEGORIES, 1):
        console.print(f"  {i:2d}. {CATEGORY_LABELS.get(cat, cat)} ({cat})")
    console.print("   a. All categories")
    choice = Prompt.ask("Pick categories (numbers/comma-separated, or 'a')", default="a")
    if choice.strip().lower() == "a":
        return None
    picked = []
    for part in choice.replace(",", " ").split():
        try:
            idx = int(part) - 1
            if 0 <= idx < len(CATEGORIES):
                picked.append(CATEGORIES[idx])
        except ValueError:
            pass
    return tuple(picked) if picked else None


def _selected_platforms(
    categories: tuple[str, ...] | None,
    platform_scope: str = "core",
) -> list:
    from core.engine import _select_platforms

    return _select_platforms(categories, platform_scope)


async def _verify_all_matches(result: ScanResult) -> ScanResult:
    """Compatibility shim; engine verification is the sole decision path."""
    # Kept as a compatibility shim for callers that imported this private
    # helper. Verification now happens once inside core.engine for every
    # entrypoint; the CLI no longer has a second network/AI decision path.
    return result


async def _interactive() -> int:
    console.print(Panel(
        "[bold blue]Open Source Intelligence[/bold blue] — username scanner\n"
        "100 core platforms · deterministic alias discovery · optional AI",
        border_style="blue",
    ))
    console.print()

    username = Prompt.ask("Username").strip()
    if not username:
        console.print("[red]Username required[/red]")
        return 1

    console.print()
    console.print("[bold]Scan type:[/bold]")
    console.print("  [1] Core      — 100 high-value platforms")
    console.print("  [2] Full      — up to 500 curated platforms")
    console.print("  [3] Custom    — pick everything yourself")
    console.print()

    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")

    categories: tuple[str, ...] | None = None
    smart = True
    platform_scope = "core"
    full_name: str | None = None

    if choice == "1":
        categories = None
    elif choice == "2":
        categories = ("__all__",)
        platform_scope = "full"
    elif choice == "3":
        cats_raw = _pick_categories()
        if cats_raw is None:
            categories = None
        else:
            categories = cats_raw
        smart = Confirm.ask("Smart search? (username variations, finds aliases)", default=True)
        if smart:
            full_name = Prompt.ask("Full name (optional)", default="").strip() or None

    deep = Confirm.ask("Deep scraping?", default=True)

    cfg = ScanConfig(
        username=username,
        full_name=full_name,
        deep=deep,
        smart=smart or (choice in ("1", "2")),
        email=True,
        breach=True,
        holehe=True,
        ghunt=True,
        categories=categories,
        platform_scope=platform_scope,
        ai_skills=False,
    )

    platforms = _selected_platforms(cfg.categories, cfg.platform_scope)
    _print_header(cfg.username, cfg.full_name, len(platforms))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )
    task = progress.add_task("Scanning...", total=None)

    with Live(progress, console=console, refresh_per_second=4):
        t0 = time.monotonic()
        result = await run_scan(cfg)
        elapsed = time.monotonic() - t0
        progress.update(task, completed=100, total=100, description="Done")

    completed = complete_scan_result(result, cfg, save_history=True)
    log_file = _log_path(username)

    log_file.write_text(
        json.dumps(completed.payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    _show_result(result, elapsed, log_file)
    return 0


def _handle_exports(result: ScanResult, args: argparse.Namespace) -> None:
    if getattr(args, "export_html", None):
        try:
            export_html(result, args.export_html)
        except Exception as exc:
            console.print(f"[red]HTML export error: {exc}[/red]")
    if getattr(args, "export_pdf", None):
        try:
            export_pdf(result, args.export_pdf)
        except Exception as exc:
            console.print(f"[red]PDF export error: {exc}[/red]")
    if getattr(args, "export_csv", None):
        try:
            export_csv(result, args.export_csv)
        except Exception as exc:
            console.print(f"[red]CSV export error: {exc}[/red]")
    if getattr(args, "export_stix", None):
        try:
            export_stix(result, args.export_stix)
        except Exception as exc:
            console.print(f"[red]STIX export error: {exc}[/red]")
    if getattr(args, "export_misp", None):
        try:
            export_misp(result, args.export_misp)
        except Exception as exc:
            console.print(f"[red]MISP export error: {exc}[/red]")
    if getattr(args, "export_obsidian", None):
        try:
            export_obsidian(result, args.export_obsidian)
        except Exception as exc:
            console.print(f"[red]Obsidian export error: {exc}[/red]")
    if getattr(args, "export_json", None):
        try:
            export_json(result, args.export_json)
        except Exception as exc:
            console.print(f"[red]JSON export error: {exc}[/red]")


def _cli_export(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="osint export",
        description="Export a previous scan result to HTML, PDF, CSV, STIX, MISP, or Obsidian",
    )
    parser.add_argument("target", help="Scan JSON file path, scan ID from history, or username")
    parser.add_argument(
        "--format", "-f",
        choices=["html", "pdf", "csv", "stix", "misp", "obsidian", "json"],
        required=True,
        help="Target export format",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Destination file path (or directory path for obsidian)",
    )
    args = parser.parse_args(argv)

    target_path = Path(args.target)
    payload: dict[str, Any] | None = None

    if target_path.is_file():
        try:
            payload = json.loads(target_path.read_text(encoding="utf-8"))
        except Exception as exc:
            console.print(f"[red]Failed to read JSON file {target_path}: {exc}[/red]")
            return 1
    elif args.target.isdigit():
        entry = history.get_scan(int(args.target))
        if entry is None:
            console.print(f"[red]No scan found in history with ID {args.target}[/red]")
            return 1
        payload = entry.payload
    else:
        entry = history.get_latest(args.target)
        if entry is None:
            console.print(f"[red]No scan found in history for username {args.target!r}[/red]")
            return 1
        payload = entry.payload

    if not isinstance(payload, dict):
        console.print("[red]Invalid scan payload[/red]")
        return 1

    result = ScanResult.from_dict(payload)

    try:
        if args.format == "html":
            export_html(result, args.output)
        elif args.format == "pdf":
            export_pdf(result, args.output)
        elif args.format == "csv":
            export_csv(result, args.output)
        elif args.format == "stix":
            export_stix(result, args.output)
        elif args.format == "misp":
            export_misp(result, args.output)
        elif args.format == "obsidian":
            export_obsidian(result, args.output)
        elif args.format == "json":
            export_json(result, args.output)
    except Exception as exc:
        console.print(f"[red]Export failed: {exc}[/red]")
        return 1

    return 0


def _cli_history(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="osint history",
        description="Search or view previous OSINT scans",
    )
    parser.add_argument("query", nargs="?", help="Username or natural language semantic search query")
    parser.add_argument("--semantic", "-s", action="store_true", help="Perform natural language semantic search")
    parser.add_argument("--limit", "-n", type=int, default=10, help="Maximum number of results to display")
    args = parser.parse_args(argv)
    if args.limit <= 0:
        parser.error("--limit must be positive")

    if not args.query:
        scans = history.list_scans(limit=args.limit)
        if not scans:
            console.print("[dim]No previous scans found in history.[/dim]")
            return 0
        table = Table(title="Recent OSINT Scans")
        table.add_column("ID", style="cyan")
        table.add_column("Username", style="bold green")
        table.add_column("Found", justify="right")
        table.add_column("Date", style="dim")
        for s in scans:
            date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.ts))
            table.add_row(str(s.id), s.username, str(s.found_count), date_str)
        console.print(table)
        return 0

    if args.semantic:
        results = history.search_scans_semantic(args.query, limit=args.limit)
        if not results:
            console.print(f"[yellow]No matching scans found for semantic query: {args.query!r}[/yellow]")
            return 0
        table = Table(title=f"Semantic Search Results for: {args.query}")
        table.add_column("ID", style="cyan")
        table.add_column("Username", style="bold green")
        table.add_column("Relevance", justify="right", style="bold yellow")
        table.add_column("Found", justify="right")
        table.add_column("Date", style="dim")
        for r in results:
            date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
            table.add_row(
                str(r["id"]),
                r["username"],
                f"{r.get('similarity_score', 0):.1%}",
                str(r["found_count"]),
                date_str,
            )
        console.print(table)
        return 0
    else:
        scans = history.list_scans(username_contains=args.query, limit=args.limit)
        if not scans:
            console.print(f"[yellow]No scans found matching username {args.query!r}[/yellow]")
            return 0
        table = Table(title=f"Scans matching '{args.query}'")
        table.add_column("ID", style="cyan")
        table.add_column("Username", style="bold green")
        table.add_column("Found", justify="right")
        table.add_column("Date", style="dim")
        for s in scans:
            date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.ts))
            table.add_row(str(s.id), s.username, str(s.found_count), date_str)
        console.print(table)
        return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv:
        if argv[0] == "scan":
            return _cli_scan(argv[1:])
        if argv[0] == "export":
            return _cli_export(argv[1:])
        if argv[0] == "history":
            return _cli_history(argv[1:])
        if argv[0] == "workbench":
            from core.investigation import load_workbench

            parser = argparse.ArgumentParser(prog="osint workbench")
            parser.add_argument("case_id", type=int)
            args = parser.parse_args(argv[1:])
            try:
                print(json.dumps(load_workbench(args.case_id), ensure_ascii=False, indent=2))
                return 0
            except ValueError as exc:
                console.print(f"[red]{exc}[/red]")
                return 1

    return asyncio.run(_interactive())


def _cli_scan(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="osint scan")
    parser.add_argument("username", nargs="?")
    parser.add_argument("--full-name")
    parser.add_argument("--email-only")
    parser.add_argument("--verified", action="store_true", help="Use legacy deterministic verified selector")
    parser.add_argument("--full", action="store_true", help="Use up to 500 curated platforms")
    parser.add_argument("--no-deep", action="store_true")
    smart_group = parser.add_mutually_exclusive_group()
    smart_group.add_argument("--smart", dest="smart", action="store_true")
    smart_group.add_argument(
        "--no-smart", dest="smart", action="store_false",
        help="Disable similar-username and identity-candidate discovery",
    )
    parser.set_defaults(smart=True)
    parser.add_argument(
        "--alias-max-candidates",
        type=int,
        default=24,
        metavar="1-24",
        help="Alias candidate cap; candidates 13-24 use adaptive fallback",
    )
    parser.add_argument("--alias-platform-limit", type=int, default=15)
    parser.add_argument("--platform", action="append", default=[], help="Restrict platform probes by exact catalogue name (repeatable)")
    parser.add_argument("--http-request-budget", type=int, help="Cap central HTTP attempts, including retries; disables HTTP redirects")
    parser.add_argument("--email", action="store_true")
    parser.add_argument("--breach", action="store_true")
    parser.add_argument("--photo", action="store_true")
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--dns", action="store_true", help="Perform DNS record enumeration")
    parser.add_argument("--subdomain", action="store_true", help="Enumerate subdomains via crt.sh")
    parser.add_argument("--passive", action="store_true", help="Search passive threat and search intelligence")
    parser.add_argument("--passive-domain", help="Target domain for passive reconnaissance")
    parser.add_argument("--reverse-image", action="store_true", help="Search reverse image engines for avatar")
    parser.add_argument("--past-usernames", action="store_true", help="Mine Wayback for historical handles")
    parser.add_argument("--phone", help="Target phone number (e.g. +14155552671)")
    parser.add_argument("--phone-region", help="2-letter region code for phone parsing (e.g. US, TR)")
    parser.add_argument("--crypto", help="Crypto wallet addresses, comma-separated")
    parser.add_argument("--recon-domain", help="Corporate domain for red-team recon")
    parser.add_argument("--recon-names", help="Path to employee names file for email permutations")
    parser.add_argument("--recon-github-org", help="GitHub org to harvest committer emails from")
    parser.add_argument("--gitleaks", help="Local paths to scan with gitleaks, comma-separated")
    parser.add_argument("--geocode", action="store_true", help="Geocode extracted profile locations")
    parser.add_argument("--tor", action="store_true", help="Route requests through local Tor proxy")
    parser.add_argument("--proxy", help="HTTP or SOCKS proxy URL")
    parser.add_argument("--playwright", action="store_true", help="Enable Playwright browser fallback")
    parser.add_argument("--screenshots", action="store_true", help="Capture profile screenshots")
    parser.add_argument("--screenshot-dir", help="Output directory for screenshots")
    parser.add_argument("--export-html", help="Path to export HTML report")
    parser.add_argument("--export-pdf", help="Path to export PDF report")
    parser.add_argument("--export-csv", help="Path to export CSV zip bundle")
    parser.add_argument("--export-stix", help="Path to export STIX 2.1 JSON bundle")
    parser.add_argument("--export-misp", help="Path to export MISP event JSON")
    parser.add_argument("--export-obsidian", help="Directory path to export Obsidian notes")
    parser.add_argument("--export-json", help="Path to export JSON payload")
    parser.add_argument("--categories")
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT)
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Opt in to LLM validation and the executive summary skill",
    )
    parser.add_argument(
        "--ai-correlate",
        action="store_true",
        help="Synthesize cross-platform identities with the AI correlator skill",
    )
    parser.add_argument(
        "--allow-private-networks",
        action="store_true",
        help="Allow HTTP targets on loopback/private networks",
    )

    args = parser.parse_args(argv)
    if not args.username:
        args.username = input("Username: ").strip()
        if not args.username:
            console.print("[red]Username required[/red]")
            return 1

    categories: tuple[str, ...] | None = None
    platform_scope = "core"
    if args.categories:
        categories = tuple(c.strip() for c in args.categories.split(",") if c.strip())
    elif args.full:
        categories = ("__all__",)
        platform_scope = "full"
    elif args.verified:
        categories = ("__verified__",)

    crypto_list = (
        tuple(c.strip() for c in args.crypto.split(",") if c.strip())
        if args.crypto
        else ()
    )
    gitleaks_list = (
        tuple(p.strip() for p in args.gitleaks.split(",") if p.strip())
        if args.gitleaks
        else ()
    )

    cfg = ScanConfig(
        username=args.username,
        full_name=args.full_name,
        email_only=args.email_only,
        deep=not args.no_deep,
        smart=args.smart,
        email=args.email or args.breach,
        breach=args.breach or args.email,
        photo=args.photo,
        whois=args.whois,
        dns=args.dns,
        subdomain=args.subdomain,
        passive=args.passive,
        passive_domain=args.passive_domain,
        reverse_image=args.reverse_image,
        past_usernames=args.past_usernames,
        phone=args.phone,
        phone_region=args.phone_region,
        crypto_addresses=crypto_list,
        redteam_domain=args.recon_domain,
        redteam_names_file=args.recon_names,
        redteam_github_org=args.recon_github_org,
        gitleaks_paths=gitleaks_list,
        geocode=args.geocode,
        tor=args.tor,
        proxy=args.proxy,
        playwright=args.playwright,
        screenshots=args.screenshots,
        screenshot_dir=args.screenshot_dir,
        categories=categories,
        platform_scope=platform_scope,
        alias_max_candidates=args.alias_max_candidates,
        platform_names=tuple(args.platform),
        http_request_budget=args.http_request_budget,
        alias_platform_limit=args.alias_platform_limit,
        request_timeout=args.timeout,
        ai_skills=args.ai,
        ai_report=args.ai,
        ai_correlate=args.ai_correlate or args.ai,
        allow_private_networks=args.allow_private_networks,
    )

    return asyncio.run(_run_scan_fast(cfg, args))


async def _run_scan_fast(
    cfg: ScanConfig, args: argparse.Namespace | None = None
) -> int:
    platforms = _selected_platforms(cfg.categories, cfg.platform_scope)
    if cfg.platform_names:
        platforms = [platform for platform in platforms if platform.name in cfg.platform_names]
    _print_header(cfg.username, cfg.full_name, len(platforms))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
    )
    task = progress.add_task("Scanning...", total=None)

    with Live(progress, console=console, refresh_per_second=4):
        t0 = time.monotonic()
        result = await run_scan(cfg)
        elapsed = time.monotonic() - t0
        progress.update(task, completed=100, total=100, description="Done")

    completed = complete_scan_result(result, cfg, save_history=True)
    log_file = _log_path(cfg.username)
    log_file.write_text(
        json.dumps(completed.payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    _show_result(result, elapsed, log_file)
    if args is not None:
        _handle_exports(result, args)
    return 0



if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] if len(sys.argv) > 1 else None))
