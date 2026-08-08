"""Interactive CLI for open-source-intelligence scans.

Usage:
    osint                         # interactive mode
    osint scan <username>         # quick scan with flags
    osint scan <username> --popular --smart --email

Scans are saved to: log/<username>/<timestamp>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.config import ScanConfig
from core.engine import run_scan
from modules.platforms import PLATFORMS
from core.models import ScanResult

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
    found = [p for p in result.found_platforms if p.status == "verified"]
    table = Table(title="Results", border_style="green")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Confirmed platforms", str(len(found)))
    table.add_row("Total checked", str(result.total_checked))
    table.add_row("Emails", str(len(result.emails)))
    table.add_row("Discovered usernames", str(len(result.discovered_usernames)))
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

    if not found:
        console.print("\n[dim]No matches confirmed. Try fewer filters or --smart for variations.[/dim]")


def _show_result(result: ScanResult, elapsed: float, log_file: Path | None) -> None:
    _print_results(result, elapsed)
    console.print()

    if result.discovered_usernames:
        console.print(f"[bold]Discovered usernames:[/bold] {', '.join(result.discovered_usernames)}")
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

    if log_file:
        console.print(f"[bold]Saved:[/bold] {log_file}")
    else:
        console.print("[dim]Not saved[/dim]")


def _pick_categories() -> tuple[str, ...] | None:
    console.print("\n[bold]Available categories:[/bold]")
    for i, cat in enumerate(CATEGORIES, 1):
        console.print(f"  {i:2d}. {cat}")
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


def _selected_platforms(categories: tuple[str, ...] | None) -> list:
    if not categories:
        from core.engine import _verified_platforms
        return _verified_platforms()
    if categories == ("__all__",):
        return list(PLATFORMS)
    if categories in (("__popular__",), ("__verified__",)):
        from core.engine import _select_platforms
        return _select_platforms(categories)
    return [p for p in PLATFORMS if p.category in categories]


async def _verify_all_matches(result: ScanResult) -> ScanResult:
    """Re-check ALL found URLs. AI-powered when available, strict body check as fallback.

    For each match:
    1. URL must return HTTP 200
    2. If LLM available → AI decides real vs fake based on page content
    3. If LLM unavailable → body must contain username (strict fallback)
    """
    import aiohttp

    candidates = [p for p in result.platforms if p.exists]
    if not candidates:
        return result

    console.print(f"\n  [yellow]Verifying {len(candidates)} matches...[/yellow]")

    # Check if AI is available
    ai_available = False
    try:
        from core.analysis.llm import LLMAnalyzer, LLMUnavailable
        analyzer = LLMAnalyzer.from_env()
        ai_available = True
    except Exception:
        analyzer = None

    if ai_available:
        console.print("  [green]AI-powered verification active[/green]")
    else:
        console.print("  [dim]AI unavailable — using strict body check[/dim]")

    kept = 0
    dropped = 0

    async with aiohttp.ClientSession() as session:
        for p in candidates:
            try:
                async with session.get(p.url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        p.exists = False
                        p.status = "verified_bad"
                        p.fp_signals = list(p.fp_signals) + [f"verify:{resp.status}"]
                        dropped += 1
                        continue

                    body = await resp.text()
                    is_real = False

                    if ai_available and analyzer:
                        is_real = await _ai_verify_page(analyzer, result.username, p.platform, p.url, body[:8000])
                    else:
                        is_real = result.username.lower() in body.lower()

                    if is_real:
                        p.confidence = 1.0
                        p.status = "verified"
                        p.fp_signals = list(p.fp_signals) + ["verify:confirmed"]
                        kept += 1
                    else:
                        p.exists = False
                        p.status = "verified_fake"
                        p.fp_signals = list(p.fp_signals) + ["verify:ai_rejected"]
                        dropped += 1

            except Exception:
                p.exists = False
                p.status = "verified_error"
                dropped += 1

    console.print(f"  [green]Real: {kept}[/green]  [red]Fake: {dropped}[/red]")
    return result


async def _ai_verify_page(analyzer, username: str, platform: str, url: str, html: str) -> bool:
    """Ask AI: is this page a real profile for {username} on {platform}?"""
    import json as _json
    from core.analysis.skill_loader import run_skill, SkillError

    # Extract visible text from HTML for the LLM
    import re
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()[:4000]

    try:
        result = await run_skill(
            "profile_validator",
            {
                "target": {"username": username},
                "profile": {
                    "platform": platform,
                    "url": url,
                    "bio": text[:2000],
                },
            },
            budget=None,
            use_cache=False,
        )
        verdict = result.get("verdict", "uncertain")
        score = int(result.get("match_score", 0))
        return verdict in ("match", "likely_match") and score >= 40
    except SkillError:
        return username.lower() in text.lower()


async def _interactive() -> int:
    console.print(Panel(
        "[bold blue]Open Source Intelligence[/bold blue] — username scanner\n"
        "~500 platforms · email breach · AI validation",
        border_style="blue",
    ))
    console.print()

    username = Prompt.ask("Username").strip()
    if not username:
        console.print("[red]Username required[/red]")
        return 1

    console.print()
    console.print("[bold]Scan type:[/bold]")
    console.print("  [1] Quick     — default platforms (~500)")
    console.print("  [2] Full      — all 1924 platforms")
    console.print("  [3] Custom    — pick everything yourself")
    console.print()

    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")

    categories: tuple[str, ...] | None = None
    smart = False
    full_name: str | None = None

    if choice == "1":
        categories = None
    elif choice == "2":
        categories = ("__all__",)
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
        ai_skills=True,
        ai_skill_budget=30,
        fp_threshold=0.25,
    )

    platforms = _selected_platforms(cfg.categories)
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

    if result.found_platforms:
        progress2 = Progress(
            SpinnerColumn(),
            TextColumn("[yellow]Verifying...[/yellow]"),
            TimeElapsedColumn(),
        )
        with Live(progress2, console=console, refresh_per_second=4):
            result = await _verify_all_matches(result)

    log_file = _log_path(username)

    ...  # continues with show_result
    log_file.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    _show_result(result, elapsed, log_file)
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] == "scan":
        return _cli_scan(argv[1:])

    return asyncio.run(_interactive())


def _cli_scan(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="osint scan")
    parser.add_argument("username", nargs="?")
    parser.add_argument("--full-name")
    parser.add_argument("--email-only")
    parser.add_argument("--verified", action="store_true", help="Use verified platforms (~500, default)")
    parser.add_argument("--full", action="store_true", help="Use all 1924 platforms")
    parser.add_argument("--no-deep", action="store_true")
    parser.add_argument("--smart", action="store_true")
    parser.add_argument("--email", action="store_true")
    parser.add_argument("--breach", action="store_true")
    parser.add_argument("--photo", action="store_true")
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--categories")
    parser.add_argument("--timeout", type=int, default=15)

    args = parser.parse_args(argv)
    if not args.username:
        args.username = input("Username: ").strip()
        if not args.username:
            console.print("[red]Username required[/red]")
            return 1

    categories: tuple[str, ...] | None = None
    if args.categories:
        categories = tuple(c.strip() for c in args.categories.split(",") if c.strip())
    elif args.full:
        categories = ("__all__",)

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
        categories=categories,
        request_timeout=args.timeout,
        ai_skills=True,
        ai_skill_budget=30,
        fp_threshold=0.25,
    )

    return asyncio.run(_run_scan_fast(cfg))


async def _run_scan_fast(cfg: ScanConfig) -> int:
    platforms = _selected_platforms(cfg.categories)
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

    if result.found_platforms:
        progress2 = Progress(
            SpinnerColumn(),
            TextColumn("[yellow]Verifying...[/yellow]"),
            TimeElapsedColumn(),
        )
        with Live(progress2, console=console, refresh_per_second=4):
            result = await _verify_all_matches(result)

    log_file = _log_path(cfg.username)
    log_file.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    _show_result(result, elapsed, log_file)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] if len(sys.argv) > 1 else None))
