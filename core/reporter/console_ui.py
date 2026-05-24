"""Rich terminal output for scan progress and results."""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from core.config import BANNER, CATEGORIES
from core.investigator_summary import build_investigator_summary
from core.models import PlatformResult, ScanResult

console = Console()

CATEGORY_COLORS = {
    "social": "magenta",
    "dev": "green",
    "gaming": "yellow",
    "content": "blue",
    "professional": "cyan",
    "community": "red",
    "other": "white",
}

DISPLAY_KEYS = {
    "name": "Name",
    "full_name": "Full Name",
    "real_name": "Real Name",
    "persona_name": "Profile Name",
    "bio": "Bio",
    "summary": "Summary",
    "about": "About",
    "location": "Location",
    "country": "Country",
    "email": "Email",
    "company": "Company",
    "organization": "Organization",
    "job_title": "Job Title",
    "blog": "Blog",
    "website_url": "Website",
    "twitter_username": "Twitter",
    "github_username": "GitHub",
    "followers": "Followers",
    "following": "Following",
    "public_repos": "Public Repos",
    "karma": "Karma",
    "link_karma": "Link Karma",
    "comment_karma": "Comment Karma",
    "total_karma": "Total Karma",
    "created_at": "Created",
    "joined_at": "Joined",
    "member_since": "Member Since",
    "hireable": "Hireable",
    "has_verified_email": "Email Verified",
    "is_gold": "Reddit Gold",
    "is_mod": "Moderator",
    "status": "Status",
    "is_streamer": "Streamer",
    "steam_id": "Steam ID",
    "vac_banned": "VAC Banned",
    "online_state": "Online State",
    "submitted_count": "Submissions",
    "count_all": "Total Games",
    "patron": "Patron",
    "play_time_total": "Total Playtime",
}

RATING_KEYS = (
    "chess_rapid_rating",
    "chess_blitz_rating",
    "chess_bullet_rating",
    "rapid_rating",
    "blitz_rating",
    "bullet_rating",
    "classical_rating",
)


def print_banner() -> None:
    lines = BANNER.strip("\n").split("\n")
    start, end = (230, 230, 230), (40, 40, 40)
    denom = max(len(lines) - 1, 1)
    for i, line in enumerate(lines):
        ratio = i / denom
        r, g, b = (int(start[j] + (end[j] - start[j]) * ratio) for j in range(3))
        console.print(f"[#{r:02x}{g:02x}{b:02x}]{line}[/]")
    console.print(f"[#646464]{'─' * 80}[/]")
    console.print(
        "  [dim]Open Source Intelligence by cyberm4fia[/dim]\n",
        justify="center",
    )


def print_breach_notice() -> None:
    console.print(
        Panel(
            "[yellow]--breach[/yellow] selected; [cyan]email discovery[/cyan] has been auto-enabled.",
            title="[bold yellow]NOTICE[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        )
    )
    console.print()


def print_scan_start(username: str, mode: str, platform_count: int) -> None:
    console.print()
    console.print(
        Panel(
            f"[bold white]Target:[/bold white] [cyan]{username}[/cyan]\n"
            f"[bold white]Mode:[/bold white] [yellow]{mode}[/yellow]\n"
            f"[bold white]Platforms:[/bold white] [green]{platform_count}[/green] sites to scan",
            title="[bold red]STARTING SCAN[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()


def print_progress(current: int, total: int, platform: str, found: bool) -> None:
    status = "[bold green]FOUND[/bold green]" if found else "[dim]not found[/dim]"
    bar_len = 30
    filled = int(bar_len * current / total) if total else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    console.print(f"\r  [{bar}] {current}/{total} | {platform}: {status}", end="")


def print_results(result: ScanResult) -> None:
    console.print("\n")
    _print_summary(result)
    _print_investigator_summary(result)

    if not result.found_platforms:
        console.print("\n  [yellow]No profiles found on any platform.[/yellow]\n")
        return

    _print_platforms_table(result)
    _print_deep_profiles(result)
    _print_cross_reference(result)
    _print_emails(result)
    _print_holehe(result)
    _print_ghunt(result)
    _print_toutatis(result)
    _print_comb_leaks(result)
    _print_photo_matches(result)
    _print_whois(result)
    _print_dns(result)
    _print_subdomains(result)
    _print_redteam_recon(result)
    _print_company_records(result)
    _print_document_metadata(result)
    _print_web_presence(result)
    _print_variations(result)
    _print_discovered_usernames(result)
    _print_ai_report(result)
    console.print()


def _print_ai_report(result: ScanResult) -> None:
    report = getattr(result, "ai_report", None)
    if not report:
        return
    console.print()
    summary = report.get("identity_summary") or "(no summary)"
    confidence = report.get("confidence", 0)
    body_lines = [f"[bold]Summary:[/bold] {summary}"]
    body_lines.append(f"[bold]Confidence:[/bold] {confidence}/100")
    linkages = report.get("strong_linkages") or []
    if linkages:
        body_lines.append("\n[bold]Strong linkages:[/bold]")
        body_lines.extend(f"  - {item}" for item in linkages)
    exposures = report.get("exposures") or []
    if exposures:
        body_lines.append("\n[bold red]Exposures:[/bold red]")
        body_lines.extend(f"  - {item}" for item in exposures)
    next_steps = report.get("next_steps") or []
    if next_steps:
        body_lines.append("\n[bold]Next steps:[/bold]")
        body_lines.extend(f"  - {item}" for item in next_steps)
    console.print(
        Panel(
            "\n".join(body_lines),
            title="[bold magenta]AI ANALYSIS[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )


def _print_summary(result: ScanResult) -> None:
    summary = (
        f"[bold white]Username:[/bold white] [cyan]{result.username}[/cyan]\n"
        f"[bold white]Scanned:[/bold white] [yellow]{result.total_checked}[/yellow] platforms\n"
        f"[bold white]Found:[/bold white] [bold green]{result.found_count}[/bold green] profiles\n"
        f"[bold white]Duration:[/bold white] [dim]{result.scan_time:.1f}s[/dim]"
    )
    console.print(
        Panel(summary, title="[bold green]SCAN COMPLETE[/bold green]", border_style="green")
    )


def _print_investigator_summary(result: ScanResult) -> None:
    summary = getattr(result, "investigator_summary", None) or build_investigator_summary(
        result.to_dict()
    )
    headline = summary.get("headline") or ""
    priority_score = summary.get("priority_score", 0)
    confidence_band = str(summary.get("confidence_band") or "low").replace("_", " ")
    overview = summary.get("overview") or []
    risks = summary.get("risk_flags") or []
    next_steps = summary.get("next_steps") or []
    grouped_actions = summary.get("recommended_actions_by_severity") or {}
    body_lines = [headline] if headline else []
    body_lines.append(
        f"[bold]Priority Score:[/bold] {priority_score}/100   "
        f"[bold]Confidence Band:[/bold] {confidence_band}"
    )
    if overview:
        body_lines.append("\n[bold]Overview:[/bold]")
        body_lines.extend(f"  - {item}" for item in overview)
    if risks:
        body_lines.append("\n[bold red]Risk Flags:[/bold red]")
        for risk in risks:
            severity = str(risk.get("severity") or "low").upper()
            title = risk.get("title") or "Signal"
            detail = risk.get("detail") or ""
            body_lines.append(f"  - [{severity}] {title}: {detail}")
    if next_steps:
        body_lines.append("\n[bold]Next Steps:[/bold]")
        body_lines.extend(f"  - {item}" for item in next_steps)
    if grouped_actions:
        labels = {
            "high": "Immediate",
            "medium": "Follow-up",
            "low": "Background",
        }
        for key in ("high", "medium", "low"):
            actions = grouped_actions.get(key) or []
            if not actions:
                continue
            body_lines.append(f"\n[bold]{labels[key]} Actions:[/bold]")
            body_lines.extend(f"  - {item}" for item in actions)
    if not body_lines:
        return
    console.print(
        Panel(
            "\n".join(body_lines),
            title="[bold cyan]INVESTIGATOR BRIEF[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def _print_platforms_table(result: ScanResult) -> None:
    console.print()
    table = Table(
        title="Profiles Found",
        box=box.DOUBLE_EDGE,
        title_style="bold cyan",
        header_style="bold white",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Platform", style="bold", min_width=15)
    table.add_column("Category", min_width=12)
    table.add_column("URL", style="blue underline", min_width=30)
    table.add_column("Response", justify="right", width=8)

    for i, p in enumerate(result.found_platforms, 1):
        cat = CATEGORIES.get(p.category, p.category)
        color = CATEGORY_COLORS.get(p.category, "white")
        rt = f"{p.response_time:.1f}s" if p.response_time else "-"
        table.add_row(str(i), p.platform, f"[{color}]{cat}[/{color}]", p.url, rt)

    console.print(table)


def _print_deep_profiles(result: ScanResult) -> None:
    profiles_with_data = [p for p in result.found_platforms if p.profile_data]
    if not profiles_with_data:
        return
    console.print()
    console.print(
        Panel("[bold]Deep Profile Information[/bold]", border_style="yellow", padding=(0, 1))
    )
    for p in profiles_with_data:
        _print_profile_detail(p)


def _print_profile_detail(p: PlatformResult) -> None:
    d = p.profile_data
    if not d:
        return
    tree = Tree(f"[bold yellow]{p.platform}[/bold yellow] — [blue]{p.url}[/blue]")

    for key, label in DISPLAY_KEYS.items():
        val = d.get(key)
        if val in (None, "", 0):
            continue
        if isinstance(val, bool):
            val = "[green]Yes[/green]" if val else "[red]No[/red]"
        elif isinstance(val, int) and key.endswith("_utc"):
            with contextlib.suppress(OSError, ValueError):
                val = datetime.fromtimestamp(val, tz=timezone.utc).strftime("%Y-%m-%d")
        elif isinstance(val, int) and val > 1_000_000_000:
            with contextlib.suppress(OSError, ValueError):
                val = datetime.fromtimestamp(val / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
        tree.add(f"[bold]{label}:[/bold] {val}")

    for rk in RATING_KEYS:
        val = d.get(rk)
        if val:
            label = rk.replace("_", " ").replace("chess ", "").title()
            tree.add(f"[bold]{label}:[/bold] {val}")

    proofs = d.get("proofs", [])
    if proofs:
        proofs_branch = tree.add("[bold]Linked Accounts (Keybase):[/bold]")
        for proof in proofs:
            if isinstance(proof, dict):
                proofs_branch.add(
                    f"{proof.get('service', '?')}: [cyan]{proof.get('username', '?')}[/cyan]"
                )

    console.print(tree)
    console.print()


def _print_cross_reference(result: ScanResult) -> None:
    cr = result.cross_reference
    if not (cr.confidence > 0 or cr.notes):
        return
    console.print()
    conf_color = "green" if cr.confidence >= 70 else "yellow" if cr.confidence >= 40 else "red"
    text = f"[bold]Confidence Score:[/bold] [{conf_color}]{cr.confidence:.0f}%[/{conf_color}]\n"
    for title, items in (
        ("Matched Names", cr.matched_names),
        ("Matched Locations", cr.matched_locations),
        ("Matched Photos", cr.matched_photos),
        ("Notes", cr.notes),
    ):
        if items:
            text += f"\n[bold]{title}:[/bold]\n"
            for item in items:
                text += f"  • {item}\n"

    console.print(
        Panel(text, title="[bold]Cross-Reference Analysis[/bold]", border_style="magenta")
    )


def _print_emails(result: ScanResult) -> None:
    if not result.emails:
        return
    console.print()
    table = Table(
        title="Discovered Emails",
        box=box.SIMPLE_HEAVY,
        title_style="bold yellow",
        header_style="bold",
    )
    table.add_column("Email", style="cyan")
    table.add_column("Source")
    table.add_column("Verified", justify="center")
    table.add_column("Gravatar", justify="center")
    table.add_column("Breaches", justify="right")
    for e in result.emails:
        breach_cell = f"[bold red]{e.breach_count}[/bold red]" if e.breach_count else "[dim]0[/dim]"
        table.add_row(
            e.email,
            e.source,
            "[green]✓[/green]" if e.verified else "[red]✗[/red]",
            "[green]✓[/green]" if e.gravatar else "[red]✗[/red]",
            breach_cell,
        )
    console.print(table)

    breached = [e for e in result.emails if e.breaches]
    for e in breached:
        btxt = f"[bold cyan]{e.email}[/bold cyan] — {len(e.breaches)} breaches\n"
        for b in e.breaches[:10]:
            if isinstance(b, dict):
                name = b.get("Name") or b.get("name", "?")
                date = b.get("BreachDate") or b.get("breach_date", "")
                pwn = b.get("PwnCount") or b.get("pwn_count", 0)
                btxt += f"  • [red]{name}[/red] ({date}) — {pwn:,} accounts\n"
            else:
                btxt += f"  • {b}\n"
        console.print(
            Panel(btxt.rstrip(), title="[bold red]HIBP Breach[/bold red]", border_style="red")
        )


def _print_comb_leaks(result: ScanResult) -> None:
    leaks = getattr(result, "comb_leaks", None) or []
    if not leaks:
        return
    console.print()
    table = Table(
        title=f"COMB Credential Leaks ({len(leaks)})",
        box=box.SIMPLE_HEAVY,
        title_style="bold red",
        header_style="bold",
        caption="[dim]Source: ProxyNova COMB public search[/dim]",
    )
    table.add_column("Identifier", style="cyan")
    table.add_column("Password", style="red")
    table.add_column("Length", justify="right")
    table.add_column("Extras", style="dim")
    for leak in leaks[:25]:
        extras = ", ".join(leak.extras) if getattr(leak, "extras", None) else ""
        table.add_row(
            leak.identifier,
            leak.password_preview or "[dim]—[/dim]",
            str(leak.raw_length),
            extras,
        )
    console.print(table)
    if len(leaks) > 25:
        console.print(f"  [dim]… {len(leaks) - 25} more[/dim]")


def _print_holehe(result: ScanResult) -> None:
    hits = getattr(result, "holehe_hits", None) or []
    if not hits:
        return
    console.print()
    by_email: dict[str, list] = {}
    for h in hits:
        by_email.setdefault(h.email, []).append(h)
    for email, ehits in by_email.items():
        tree = Tree(
            f"[bold cyan]{email}[/bold cyan] — [bold]{len(ehits)}[/bold] registered accounts"
        )
        for h in sorted(ehits, key=lambda x: x.site):
            extra = []
            if h.email_recovery:
                extra.append(f"recovery: {h.email_recovery}")
            if h.phone_recovery:
                extra.append(f"phone: {h.phone_recovery}")
            tail = f" [dim]({', '.join(extra)})[/dim]" if extra else ""
            tree.add(f"[green]✓[/green] {h.site} [dim]{h.domain}[/dim]{tail}")
        console.print(
            Panel(
                tree,
                title="[bold red]Holehe — Email → Site Enumeration[/bold red]",
                border_style="red",
            )
        )


def _print_ghunt(result: ScanResult) -> None:
    results = getattr(result, "ghunt_results", None) or []
    if not results:
        return
    console.print()
    table = Table(
        title="GHunt — Google Account Lookup",
        box=box.SIMPLE_HEAVY,
        title_style="bold yellow",
        header_style="bold",
    )
    table.add_column("Email", style="cyan")
    table.add_column("Name")
    table.add_column("Gaia ID", style="dim")
    table.add_column("Services", style="dim")
    for g in results:
        table.add_row(
            g.email,
            g.name or "[dim]—[/dim]",
            g.gaia_id or "[dim]—[/dim]",
            ", ".join(g.services) if g.services else "[dim]—[/dim]",
        )
    console.print(table)


def _print_toutatis(result: ScanResult) -> None:
    results = getattr(result, "toutatis_results", None) or []
    if not results:
        return
    console.print()
    for t in results:
        body = (
            f"[bold]Username:[/bold] [cyan]{t.username}[/cyan]\n"
            f"[bold]User ID:[/bold] {t.user_id or '—'}\n"
            f"[bold]Full Name:[/bold] {t.full_name or '—'}\n"
            f"[bold]Followers:[/bold] {t.follower_count:,} | "
            f"[bold]Following:[/bold] {t.following_count:,}\n"
            f"[bold]Private:[/bold] {'Yes' if t.is_private else 'No'} | "
            f"[bold]Verified:[/bold] {'Yes' if t.is_verified else 'No'}"
        )
        if t.biography:
            body += f"\n[bold]Bio:[/bold] {t.biography[:200]}"
        if t.external_url:
            body += f"\n[bold]URL:[/bold] [blue]{t.external_url}[/blue]"
        if t.obfuscated_email:
            body += f"\n[bold red]Obf. Email:[/bold red] {t.obfuscated_email}"
        if t.obfuscated_phone:
            body += f"\n[bold red]Obf. Phone:[/bold red] {t.obfuscated_phone}"
        console.print(
            Panel(
                body,
                title="[bold magenta]Toutatis — Instagram Profile[/bold magenta]",
                border_style="magenta",
            )
        )


def _print_photo_matches(result: ScanResult) -> None:
    if not result.photo_matches:
        return
    console.print()
    table = Table(
        title="Profile Photo Matches",
        box=box.SIMPLE_HEAVY,
        title_style="bold magenta",
        header_style="bold",
    )
    table.add_column("Platform A", style="cyan")
    table.add_column("Platform B", style="cyan")
    table.add_column("Similarity", justify="right")
    table.add_column("Method", justify="center")
    for m in result.photo_matches:
        sim_color = "green" if m.similarity >= 0.9 else "yellow"
        table.add_row(
            m.platform_a,
            m.platform_b,
            f"[{sim_color}]{m.similarity:.0%}[/{sim_color}]",
            m.method,
        )
    console.print(table)


def _print_whois(result: ScanResult) -> None:
    if not result.whois_records:
        return
    console.print()
    table = Table(
        title="WHOIS Records",
        box=box.SIMPLE_HEAVY,
        title_style="bold yellow",
        header_style="bold",
    )
    table.add_column("Domain", style="cyan")
    table.add_column("Registrar")
    table.add_column("Created")
    table.add_column("Expires")
    table.add_column("Org")
    for w in result.whois_records:
        table.add_row(
            str(w.get("domain", "")),
            str(w.get("registrar", ""))[:30],
            str(w.get("creation_date", ""))[:10],
            str(w.get("expiration_date", ""))[:10],
            str(w.get("org", ""))[:25],
        )
    console.print(table)


def _print_dns(result: ScanResult) -> None:
    if not result.dns_records:
        return
    console.print()
    for domain, records in result.dns_records.items():
        tree = Tree(f"[bold yellow]{domain}[/bold yellow] DNS")
        for rtype, values in records.items():
            if values:
                branch = tree.add(f"[bold]{rtype}[/bold]")
                for v in values[:10]:
                    branch.add(f"[cyan]{v}[/cyan]")
        console.print(tree)


def _print_subdomains(result: ScanResult) -> None:
    if not result.subdomains:
        return
    console.print()
    unique_subs = sorted(set(result.subdomains))
    shown = unique_subs[:50]
    text = "\n".join(f"  • [cyan]{s}[/cyan]" for s in shown)
    extra = f"\n  [dim]... and {len(unique_subs) - 50} more[/dim]" if len(unique_subs) > 50 else ""
    console.print(
        Panel(
            text + extra,
            title=f"[bold]Subdomains ({len(unique_subs)})[/bold]",
            border_style="blue",
        )
    )


def _print_redteam_recon(result: ScanResult) -> None:
    """Render red-team recon output: extra subdomains, committers, email candidates."""
    subs = getattr(result, "recon_subdomains", None) or []
    committers = getattr(result, "github_committers", None) or []
    candidates = getattr(result, "email_candidates", None) or []
    if not (subs or committers or candidates):
        return
    console.print()

    if subs:
        unique_hosts = sorted({s.get("host", "") for s in subs if s.get("host")})
        shown = unique_hosts[:30]
        lines = [f"  • [cyan]{h}[/cyan]" for h in shown]
        if len(unique_hosts) > 30:
            lines.append(f"  [dim]... and {len(unique_hosts) - 30} more[/dim]")
        console.print(
            Panel(
                "\n".join(lines),
                title=f"[bold]Attack Surface — Subdomains ({len(unique_hosts)})[/bold]",
                border_style="red",
            )
        )

    if committers:
        table = Table(
            title="GitHub Org Committers",
            box=box.SIMPLE_HEAVY,
            title_style="bold red",
            header_style="bold",
        )
        table.add_column("Email", min_width=28)
        table.add_column("Name", min_width=16)
        table.add_column("Repo", min_width=20)
        table.add_column("NoReply", justify="center")
        for c in committers[:30]:
            noreply = "!" if c.get("is_noreply") else ""
            table.add_row(
                c.get("email", ""),
                c.get("name", ""),
                c.get("repo", ""),
                noreply,
            )
        if len(committers) > 30:
            table.caption = f"... and {len(committers) - 30} more"
        console.print(table)

    if candidates:
        table = Table(
            title="Email Pattern Candidates",
            box=box.SIMPLE_HEAVY,
            title_style="bold red",
            header_style="bold",
        )
        table.add_column("Email", min_width=28)
        table.add_column("Pattern", min_width=16)
        for c in candidates[:30]:
            table.add_row(c.get("email", ""), c.get("pattern", ""))
        if len(candidates) > 30:
            table.caption = f"... and {len(candidates) - 30} more"
        console.print(table)


def _print_company_records(result: ScanResult) -> None:
    """Render OpenCorporates company records and their officers."""
    companies = getattr(result, "company_records", None) or []
    if not companies:
        return
    console.print()
    for c in companies:
        title = (
            f"{c.get('name', '?')} "
            f"({c.get('jurisdiction_code', '')}/{c.get('company_number', '')})"
        )
        meta_bits = [
            c.get("company_type") or "",
            f"status={c.get('status') or '-'}",
            f"inc={c.get('incorporation_date') or '-'}",
        ]
        meta_line = " · ".join(b for b in meta_bits if b)
        body_lines = [f"  [dim]{meta_line}[/dim]"]
        addr = c.get("registered_address")
        if addr:
            body_lines.append(f"  [white]{addr}[/white]")
        officers = c.get("officers") or []
        if officers:
            body_lines.append("")
            for o in officers[:10]:
                pos = o.get("position") or ""
                pos_part = f" [dim]({pos})[/dim]" if pos else ""
                body_lines.append(f"  • [cyan]{o.get('name', '?')}[/cyan]{pos_part}")
            if len(officers) > 10:
                body_lines.append(f"  [dim]... and {len(officers) - 10} more[/dim]")
        console.print(
            Panel(
                "\n".join(body_lines),
                title=f"[bold]{title}[/bold]",
                border_style="magenta",
            )
        )


def _print_document_metadata(result: ScanResult) -> None:
    """Render document metadata (Metagoofil-style harvest)."""
    docs = getattr(result, "document_metadata", None) or []
    if not docs:
        return
    console.print()
    table = Table(
        title="Document Metadata",
        box=box.SIMPLE_HEAVY,
        title_style="bold magenta",
        header_style="bold",
    )
    table.add_column("Type", min_width=5)
    table.add_column("Author", min_width=18)
    table.add_column("Last Modified By", min_width=14)
    table.add_column("Software", min_width=18)
    table.add_column("Network Paths", min_width=20)
    for d in docs[:30]:
        paths = ", ".join(d.get("network_paths") or [])
        table.add_row(
            (d.get("format") or "").upper(),
            d.get("author") or "",
            d.get("last_author") or "",
            d.get("software") or "",
            paths,
        )
    if len(docs) > 30:
        table.caption = f"... and {len(docs) - 30} more"
    console.print(table)


def _print_web_presence(result: ScanResult) -> None:
    if not result.web_presence:
        return
    console.print()
    table = Table(
        title="Web Presence",
        box=box.SIMPLE_HEAVY,
        title_style="bold blue",
        header_style="bold",
    )
    table.add_column("Type", min_width=12)
    table.add_column("Detail", min_width=40)
    for wp in result.web_presence:
        wp_type = wp.get("type", "?")
        if wp_type == "wayback":
            detail = f"{wp.get('original_url', '')} → {wp.get('url', '')}"
        elif wp_type == "domain_wayback":
            detail = f"{wp.get('domain', '')} found in archive"
        elif wp_type == "paste":
            detail = f"Paste ID: {wp.get('id', '')} ({wp.get('time', '')})"
        else:
            detail = str(wp)
        table.add_row(wp_type, detail)
    console.print(table)


def _print_variations(result: ScanResult) -> None:
    if not result.variations_checked:
        return
    console.print()
    shown = ", ".join(result.variations_checked[:10])
    extra = (
        f" ... and {len(result.variations_checked) - 10} more"
        if len(result.variations_checked) > 10
        else ""
    )
    console.print(f"  [dim]Variations checked: {shown}{extra}[/dim]")


def _print_discovered_usernames(result: ScanResult) -> None:
    if not result.discovered_usernames:
        return
    console.print()
    console.print(
        Panel(
            "\n".join(f"  • [cyan]{u}[/cyan]" for u in result.discovered_usernames),
            title="[bold]Discovered Linked Accounts[/bold]",
            border_style="green",
        )
    )
