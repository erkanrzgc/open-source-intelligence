"""HTML export with strict escaping and a small template helper.

All user-controlled values are passed through ``html.escape`` before being
embedded in the rendered document to avoid reflected XSS when reports are
shared.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from core.investigator_summary import build_investigator_summary
from core.models import ScanResult
from core.reporter.console import console
from core.reporter.html_style import HTML_STYLE


def _fmt(value: object) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(_fmt(v) for v in value if v not in (None, "", [], {})) or "-"
    if isinstance(value, dict):
        parts = [
            f"{escape(str(k))}: {_fmt(v)}"
            for k, v in value.items()
            if v not in (None, "", [], {})
        ]
        return ", ".join(parts) or "-"
    if value in (None, "", [], {}):
        return "-"
    return escape(str(value))


def _render_badges(values: list, class_name: str = "badge") -> str:
    if not values:
        return '<p class="muted">No data</p>'
    return "".join(f'<span class="{class_name}">{_fmt(value)}</span>' for value in values)


def _platforms_table(data: dict) -> str:
    rows = "".join(
        f"""
            <tr>
                <td>{index}</td>
                <td>{escape(p['platform'])}</td>
                <td>{escape(str(p['category']))}</td>
                <td><a href="{escape(p['url'])}" target="_blank" rel="noreferrer noopener">{escape(p['url'])}</a></td>
                <td>{escape(str(p['response_time']))}s</td>
                <td>{escape(str(p['status']))}</td>
            </tr>"""
        for index, p in enumerate((pf for pf in data["platforms"] if pf["exists"]), 1)
    )
    return f"""
    <h2>Profiles Found</h2>
    <table>
        <tr><th>#</th><th>Platform</th><th>Category</th><th>URL</th><th>Response</th><th>Status</th></tr>
        {rows}
    </table>"""


def _profile_sections(data: dict) -> str:
    sections = ""
    for p in data["platforms"]:
        if not (p["exists"] and p.get("profile_data")):
            continue
        items = "".join(
            f"<li><strong>{escape(str(k))}:</strong> {_fmt(v)}</li>"
            for k, v in p["profile_data"].items()
            if v not in (None, "", [], {})
        )
        if items:
            sections += f"""
            <div class="card">
                <h3>{escape(p['platform'])}</h3>
                <ul>{items}</ul>
            </div>"""
    return sections or '<p class="muted">No deep profile data.</p>'


def _cross_reference_block(data: dict) -> str:
    cr = data["cross_reference"]
    return f"""
    <h2>Cross-Reference</h2>
    <div class="grid grid-2">
        <div class="card metric-card">
            <div class="metric-label">Confidence Score</div>
            <div class="metric-value">{escape(str(cr['confidence']))}%</div>
        </div>
        <div class="card">
            <h3>Notes</h3>
            {_render_badges(cr['notes'])}
        </div>
        <div class="card">
            <h3>Matched Names</h3>
            {_render_badges(cr['matched_names'])}
        </div>
        <div class="card">
            <h3>Matched Locations</h3>
            {_render_badges(cr['matched_locations'])}
        </div>
        <div class="card card-full">
            <h3>Matched Photos</h3>
            {_render_badges(cr['matched_photos'])}
        </div>
    </div>"""


def _emails_block(data: dict) -> str:
    if not data["emails"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(e['email'])}</td>
            <td>{escape(e['source'])}</td>
            <td>{_fmt(e['verified'])}</td>
            <td>{_fmt(e['gravatar'])}</td>
            <td>{escape(str(e['breach_count']))}</td>
        </tr>"""
        for e in data["emails"]
    )
    return f"""
    <h2>Discovered Emails</h2>
    <table>
        <tr><th>Email</th><th>Source</th><th>Verified</th><th>Gravatar</th><th>Breaches</th></tr>
        {rows}
    </table>"""


def _comb_block(data: dict) -> str:
    leaks = data.get("comb_leaks") or []
    if not leaks:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(leak['identifier'])}</td>
            <td>{escape(leak['password_preview'] or '-')}</td>
            <td>{escape(str(leak['raw_length']))}</td>
            <td>{escape(leak.get('source', ''))}</td>
            <td>{_fmt(leak.get('extras') or [])}</td>
        </tr>"""
        for leak in leaks
    )
    return f"""
    <h2>COMB Credential Leaks ({len(leaks)})</h2>
    <p class="muted">Source: ProxyNova COMB public search. Passwords are masked.</p>
    <table>
        <tr><th>Identifier</th><th>Password</th><th>Length</th><th>Source</th><th>Extras</th></tr>
        {rows}
    </table>"""


def _holehe_block(data: dict) -> str:
    hits = data.get("holehe_hits") or []
    if not hits:
        return ""
    by_email: dict[str, list] = {}
    for h in hits:
        by_email.setdefault(h["email"], []).append(h)
    cards = ""
    for email, ehits in by_email.items():
        items = "".join(
            f"<li>{escape(h['site'])} <span class='muted'>({escape(h['domain'])})</span></li>"
            for h in sorted(ehits, key=lambda x: x["site"])
        )
        cards += f"""
        <div class="card">
            <h3>{escape(email)} <span class="muted">— {len(ehits)} accounts</span></h3>
            <ul>{items}</ul>
        </div>"""
    return f"""
    <h2>Holehe — Email → Site Enumeration</h2>
    <div class="grid grid-2">{cards}</div>"""


def _ghunt_block(data: dict) -> str:
    results = data.get("ghunt_results") or []
    if not results:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(g['email'])}</td>
            <td>{escape(g['name'] or '-')}</td>
            <td>{escape(g['gaia_id'] or '-')}</td>
            <td>{_fmt(g.get('services') or [])}</td>
        </tr>"""
        for g in results
    )
    return f"""
    <h2>GHunt — Google Account Lookup</h2>
    <table>
        <tr><th>Email</th><th>Name</th><th>Gaia ID</th><th>Services</th></tr>
        {rows}
    </table>"""


def _toutatis_block(data: dict) -> str:
    results = data.get("toutatis_results") or []
    if not results:
        return ""
    cards = ""
    for t in results:
        cards += f"""
        <div class="card">
            <h3>@{escape(t['username'])}</h3>
            <ul>
                <li><strong>User ID:</strong> {escape(t['user_id'] or '-')}</li>
                <li><strong>Full Name:</strong> {escape(t['full_name'] or '-')}</li>
                <li><strong>Followers:</strong> {escape(str(t['follower_count']))}</li>
                <li><strong>Following:</strong> {escape(str(t['following_count']))}</li>
                <li><strong>Private:</strong> {_fmt(t['is_private'])}</li>
                <li><strong>Verified:</strong> {_fmt(t['is_verified'])}</li>
                <li><strong>Bio:</strong> {escape(t['biography'] or '-')}</li>
                <li><strong>URL:</strong> {escape(t['external_url'] or '-')}</li>
                <li><strong>Obf. Email:</strong> {escape(t['obfuscated_email'] or '-')}</li>
                <li><strong>Obf. Phone:</strong> {escape(t['obfuscated_phone'] or '-')}</li>
            </ul>
        </div>"""
    return f"""
    <h2>Toutatis — Instagram Profiles</h2>
    <div class="grid grid-2">{cards}</div>"""


def _photo_block(data: dict) -> str:
    if not data["photo_matches"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(m['platform_a'])}</td>
            <td>{escape(m['platform_b'])}</td>
            <td>{escape(str(m['similarity']))}</td>
            <td>{escape(m['method'])}</td>
        </tr>"""
        for m in data["photo_matches"]
    )
    return f"""
    <h2>Profile Photo Matches</h2>
    <table>
        <tr><th>Platform A</th><th>Platform B</th><th>Similarity</th><th>Method</th></tr>
        {rows}
    </table>"""


def _web_presence_block(data: dict) -> str:
    if not data["web_presence"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(str(entry.get('type', '-')))}</td>
            <td>{_fmt(entry)}</td>
        </tr>"""
        for entry in data["web_presence"]
    )
    return f"""
    <h2>Web Presence</h2>
    <table>
        <tr><th>Type</th><th>Detail</th></tr>
        {rows}
    </table>"""


def _whois_block(data: dict) -> str:
    if not data["whois_records"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(str(r.get('domain', '')))}</td>
            <td>{escape(str(r.get('registrar', '')))}</td>
            <td>{escape(str(r.get('creation_date', '')))}</td>
            <td>{escape(str(r.get('expiration_date', '')))}</td>
            <td>{escape(str(r.get('org', '')))}</td>
        </tr>"""
        for r in data["whois_records"]
    )
    return f"""
    <h2>WHOIS Records</h2>
    <table>
        <tr><th>Domain</th><th>Registrar</th><th>Created</th><th>Expires</th><th>Org</th></tr>
        {rows}
    </table>"""


def _dns_block(data: dict) -> str:
    if not data["dns_records"]:
        return ""
    cards = ""
    for domain, records in data["dns_records"].items():
        items = "".join(
            f"<li><strong>{escape(rtype)}:</strong> {_fmt(values)}</li>"
            for rtype, values in records.items()
            if values
        )
        cards += f"""
        <div class="card">
            <h3>{escape(domain)}</h3>
            <ul>{items or '<li>No records found</li>'}</ul>
        </div>"""
    return f"""
    <h2>DNS Records</h2>
    <div class="grid grid-2">{cards}</div>"""


def _subdomain_block(data: dict) -> str:
    if not data["subdomains"]:
        return ""
    return f"""
    <h2>Subdomains</h2>
    <div class="card">
        {_render_badges(sorted(set(data['subdomains'])))}
    </div>"""


def _redteam_recon_block(data: dict) -> str:
    subs = data.get("recon_subdomains") or []
    committers = data.get("github_committers") or []
    candidates = data.get("email_candidates") or []
    if not (subs or committers or candidates):
        return ""

    sections: list[str] = []

    if subs:
        hosts = sorted({s.get("host", "") for s in subs if s.get("host")})
        sections.append(f"""
        <div class="card">
            <h3>Attack Surface — Subdomains ({len(hosts)})</h3>
            {_render_badges(hosts)}
        </div>""")

    if committers:
        rows = "".join(
            f"<tr><td>{escape(str(c.get('email', '')))}</td>"
            f"<td>{escape(str(c.get('name', '')))}</td>"
            f"<td>{escape(str(c.get('repo', '')))}</td>"
            f"<td>{'yes' if c.get('is_noreply') else ''}</td></tr>"
            for c in committers
        )
        sections.append(f"""
        <div class="card">
            <h3>GitHub Org Committers ({len(committers)})</h3>
            <table>
                <thead><tr><th>Email</th><th>Name</th><th>Repo</th><th>NoReply</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>""")

    if candidates:
        rows = "".join(
            f"<tr><td>{escape(str(c.get('email', '')))}</td>"
            f"<td>{escape(str(c.get('pattern', '')))}</td></tr>"
            for c in candidates
        )
        sections.append(f"""
        <div class="card">
            <h3>Email Pattern Candidates ({len(candidates)})</h3>
            <table>
                <thead><tr><th>Email</th><th>Pattern</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>""")

    return f"""
    <h2>Red-Team Recon</h2>
    {''.join(sections)}"""


def _company_records_block(data: dict) -> str:
    """OpenCorporates records — companies + their officers/directors."""
    companies = data.get("company_records") or []
    if not companies:
        return ""

    cards: list[str] = []
    for c in companies:
        officer_rows = "".join(
            f"<tr><td>{escape(str(o.get('name', '')))}</td>"
            f"<td>{escape(str(o.get('position', '')))}</td>"
            f"<td>{escape(str(o.get('start_date', '')))}</td>"
            f"<td>{escape(str(o.get('end_date', '')))}</td></tr>"
            for o in (c.get("officers") or [])
        )
        officer_table = ""
        if officer_rows:
            officer_table = (
                "<table>"
                "<thead><tr><th>Name</th><th>Position</th>"
                "<th>Start</th><th>End</th></tr></thead>"
                f"<tbody>{officer_rows}</tbody>"
                "</table>"
            )
        url = escape(str(c.get("url") or ""))
        url_link = f'<a href="{url}" target="_blank">view</a>' if url else ""
        cards.append(f"""
        <div class="card">
            <h3>{escape(str(c.get('name', '')))} ({escape(str(c.get('jurisdiction_code', '')))}/{escape(str(c.get('company_number', '')))})</h3>
            <p class="muted">
                Status: {escape(str(c.get('status') or '-'))} ·
                Type: {escape(str(c.get('company_type') or '-'))} ·
                Incorporated: {escape(str(c.get('incorporation_date') or '-'))} ·
                {url_link}
            </p>
            <p>{escape(str(c.get('registered_address') or ''))}</p>
            {officer_table}
        </div>""")

    return f"""
    <h2>Corporate Records ({len(companies)})</h2>
    {''.join(cards)}"""


def _document_metadata_block(data: dict) -> str:
    """Metagoofil-style document metadata harvest."""
    docs = data.get("document_metadata") or []
    if not docs:
        return ""

    rows = "".join(
        f"<tr>"
        f"<td><a href=\"{escape(str(d.get('url', '')))}\" target=\"_blank\">"
        f"{escape(str(d.get('format', '')).upper())}</a></td>"
        f"<td>{escape(str(d.get('author') or ''))}</td>"
        f"<td>{escape(str(d.get('last_author') or ''))}</td>"
        f"<td>{escape(str(d.get('software') or ''))}</td>"
        f"<td>{escape(str(d.get('company') or ''))}</td>"
        f"<td>{escape(', '.join(d.get('network_paths') or []))}</td>"
        f"</tr>"
        for d in docs
    )
    return f"""
    <h2>Document Metadata ({len(docs)})</h2>
    <div class="card">
        <table>
            <thead><tr>
                <th>Type</th><th>Author</th><th>Last Modified By</th>
                <th>Software</th><th>Company</th><th>Network Paths</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""


def _variations_block(data: dict) -> str:
    if not (data["variations_checked"] or data["discovered_usernames"]):
        return ""
    return f"""
    <h2>Smart Search</h2>
    <div class="grid grid-2">
        <div class="card">
            <h3>Variations Checked</h3>
            {_render_badges(data['variations_checked'])}
        </div>
        <div class="card">
            <h3>Discovered Linked Accounts</h3>
            {_render_badges(data['discovered_usernames'])}
        </div>
    </div>"""


def _investigator_brief_block(data: dict) -> str:
    brief = data.get("investigator_summary") or build_investigator_summary(data)
    headline = escape(str(brief.get("headline") or ""))
    priority_score = escape(str(brief.get("priority_score") or 0))
    confidence_band = escape(str(brief.get("confidence_band") or "low").replace("_", " "))
    overview = brief.get("overview") or []
    risks = brief.get("risk_flags") or []
    next_steps = brief.get("next_steps") or []
    grouped_actions = brief.get("recommended_actions_by_severity") or {}

    def _items(items: list[str]) -> str:
        if not items:
            return '<p class="muted">No highlights.</p>'
        return "<ul>" + "".join(f"<li>{escape(str(item))}</li>" for item in items) + "</ul>"

    risk_html = ""
    if risks:
        risk_html = "".join(
            f"""
            <li class="risk-item risk-{escape(str(risk.get('severity') or 'low'))}">
                <strong>{escape(str(risk.get('title') or 'Signal'))}</strong>
                <span>{escape(str(risk.get('detail') or ''))}</span>
            </li>"""
            for risk in risks
        )
        risk_html = f"<ul class='risk-list'>{risk_html}</ul>"
    else:
        risk_html = '<p class="muted">No immediate exposure flags.</p>'

    action_html = ""
    for key, label in (("high", "Immediate"), ("medium", "Follow-up"), ("low", "Background")):
        items = grouped_actions.get(key) or []
        if not items:
            continue
        action_html += (
            f"<h4>{label}</h4>"
            + _items(items)
        )
    if not action_html:
        action_html = '<p class="muted">No action buckets.</p>'

    return f"""
    <h2>Investigator Brief</h2>
    <div class="brief-headline">{headline}</div>
    <div class="brief-metrics">
        <div class="metric-chip"><span>Priority</span><strong>{priority_score}/100</strong></div>
        <div class="metric-chip"><span>Confidence</span><strong>{confidence_band}</strong></div>
    </div>
    <div class="grid grid-3">
        <div class="card">
            <h3>Overview</h3>
            {_items(overview)}
        </div>
        <div class="card">
            <h3>Risk Flags</h3>
            {risk_html}
        </div>
        <div class="card">
            <h3>Next Steps</h3>
            {_items(next_steps)}
        </div>
        <div class="card card-full">
            <h3>Recommended Actions By Severity</h3>
            {action_html}
        </div>
    </div>"""


def render_html(data: dict) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
    <title>Open Source Intelligence - {escape(data['username'])}</title>
    <style>{HTML_STYLE}</style>
</head>
<body>
    <h1>OPEN SOURCE INTELLIGENCE</h1>
    <p class="meta">Report: {escape(data['username'])} | {escape(data['exported_at'])}</p>

    <div class="summary">
        <p>Target: <span>{escape(data['username'])}</span></p>
        <p>Scanned: <span>{escape(str(data['total_checked']))}</span> platforms</p>
        <p>Found: <span>{escape(str(data['found_count']))}</span> profiles</p>
        <p>Duration: <span>{escape(str(data['scan_time']))}s</span></p>
    </div>

    {_investigator_brief_block(data)}
    {_platforms_table(data)}

    <h2>Profile Details</h2>
    {_profile_sections(data)}

    {_cross_reference_block(data)}
    {_emails_block(data)}
    {_holehe_block(data)}
    {_ghunt_block(data)}
    {_toutatis_block(data)}
    {_comb_block(data)}
    {_photo_block(data)}
    {_web_presence_block(data)}
    {_whois_block(data)}
    {_dns_block(data)}
    {_subdomain_block(data)}
    {_redteam_recon_block(data)}
    {_company_records_block(data)}
    {_document_metadata_block(data)}
    {_variations_block(data)}
</body>
</html>"""


def export_html(result: ScanResult, filepath: str) -> None:
    data = result.to_dict()
    if not data.get("investigator_summary"):
        data["investigator_summary"] = build_investigator_summary(data)
    data["exported_at"] = datetime.now(tz=timezone.utc).isoformat()
    html = render_html(data)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"\n  [green]HTML report saved:[/green] {filepath}")
