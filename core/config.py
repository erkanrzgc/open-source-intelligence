"""Runtime configuration with environment overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except ValueError:
        return default


MAX_CONCURRENT = _env_int("CYBERM4FIA_MAX_CONCURRENT", 50)
REQUEST_TIMEOUT = _env_int("CYBERM4FIA_TIMEOUT", 15)
RETRY_COUNT = _env_int("CYBERM4FIA_RETRIES", 2)
RETRY_DELAY = _env_float("CYBERM4FIA_RETRY_DELAY", 1.0)
RATE_LIMIT_DELAY = _env_float("CYBERM4FIA_RATE_LIMIT_DELAY", 0.1)
PER_HOST_CONCURRENCY = _env_int("CYBERM4FIA_PER_HOST_CONCURRENCY", 6)


def _collect_proxy_pool(args) -> tuple[str, ...]:
    """Merge --proxy / --proxy-pool / --proxy-file into a deduped tuple."""
    collected: list[str] = []
    raw_pool = getattr(args, "proxy_pool", None)
    if raw_pool:
        collected.extend(p.strip() for p in raw_pool.split(",") if p.strip())
    pool_file = getattr(args, "proxy_file", None)
    if pool_file:
        from core.proxy_pool import load_from_file

        collected.extend(load_from_file(pool_file))
    single = getattr(args, "proxy", None)
    if single and single not in collected:
        collected.append(single)
    seen: set[str] = set()
    unique: list[str] = []
    for p in collected:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return tuple(unique)

BANNER = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

CATEGORIES = {
    "social": "Social Media",
    "dev": "Developer",
    "gaming": "Gaming",
    "content": "Content",
    "professional": "Professional",
    "community": "Community",
    "other": "Other",
}


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration — replaces a wide boolean parameter list."""

    username: str
    deep: bool = True
    smart: bool = False
    email: bool = False
    web: bool = False
    whois: bool = False
    breach: bool = False
    photo: bool = False
    dns: bool = False
    subdomain: bool = False
    holehe: bool = False
    ghunt: bool = False
    toutatis: bool = False
    recursive: bool = False
    recursive_depth: int = 1
    passive: bool = False
    passive_domain: str | None = None
    reverse_image: bool = False
    past_usernames: bool = False
    phone: str | None = None
    phone_region: str | None = None
    crypto_addresses: tuple[str, ...] = ()
    enrichment: bool = True
    proxy: str | None = None
    proxies: tuple[str, ...] = ()
    tor: bool = False
    categories: tuple[str, ...] | None = None
    request_timeout: int = REQUEST_TIMEOUT
    fp_threshold: float = 0.45  # drop matches below this confidence
    fingerprint: bool = True
    new_circuit_every: int = 0
    tor_control_password: str | None = None
    playwright: bool = False
    browser_backend: str = "playwright"
    no_auto_render: bool = False  # opt OUT of auto JS-wall fallback when a browser is available
    screenshots: bool = False
    screenshot_dir: str | None = None
    geocode: bool = False
    redteam_domain: str | None = None
    redteam_names_file: str | None = None
    redteam_github_org: str | None = None
    gitleaks_paths: tuple[str, ...] = ()
    gitleaks_no_git: bool = False
    gitleaks_timeout: int = 120
    exif_image_urls: tuple[str, ...] = ()
    bssid: str | None = None
    ssid: str | None = None
    company_query: str | None = None
    company_limit: int = 5
    harvest_doc_urls: tuple[str, ...] = ()
    intelx_term: str | None = None
    intelx_limit: int = 50
    full_name: str | None = None  # --name "Tam Ad" → handle generator phase 0
    name_year: int | None = None  # birth/registration year hint for handle gen
    name_max_handles: int = 8  # how many candidate handles to actually probe
    email_only: str | None = None  # --email-only target@example.com
    ai_skills: bool = False  # opt-in: use LLM-backed skills during scan
    ai_skill_budget: int = 20  # max LLM calls per scan when ai_skills is on

    @classmethod
    def from_args(cls, args, username: str) -> ScanConfig:
        # Default behavior: run everything. Individual --flags still work
        # as explicit toggles; --quick restricts to the minimal profile sweep.
        full_default = not getattr(args, "quick", False)

        deep = (not args.no_deep) and (full_default or args.deep)
        smart = args.smart or full_default
        email = args.email or full_default
        web = args.web or full_default
        whois = args.whois or full_default
        breach = args.breach or full_default
        photo = args.photo or full_default
        dns = args.dns or full_default
        subdomain = args.subdomain or full_default
        holehe = getattr(args, "holehe", False) or full_default
        ghunt = getattr(args, "ghunt", False) or full_default
        toutatis = getattr(args, "toutatis", False) or full_default
        recursive = getattr(args, "recursive", False) or full_default
        recursive_depth = int(getattr(args, "recursive_depth", 1) or 1)
        passive = getattr(args, "passive", False) or full_default
        passive_domain = getattr(args, "domain", None)
        reverse_image = getattr(args, "reverse_image", False) or full_default
        past_usernames = getattr(args, "past_usernames", False) or full_default
        phone = getattr(args, "phone", None)
        phone_region = getattr(args, "phone_region", None)
        raw_crypto = getattr(args, "crypto", None)
        crypto_addresses: tuple[str, ...] = ()
        if raw_crypto:
            crypto_addresses = tuple(
                addr.strip() for addr in raw_crypto.split(",") if addr.strip()
            )

        if args.full:
            deep = smart = email = web = True
            whois = breach = photo = dns = subdomain = True
            holehe = ghunt = toutatis = recursive = True
            passive = reverse_image = past_usernames = True

        if breach and not email:
            email = True

        categories: tuple[str, ...] | None = None
        if args.category:
            categories = tuple(c.strip() for c in args.category.split(",") if c.strip())

        return cls(
            username=username,
            deep=deep,
            smart=smart,
            email=email,
            web=web,
            whois=whois,
            breach=breach,
            photo=photo,
            dns=dns,
            subdomain=subdomain,
            holehe=holehe,
            ghunt=ghunt,
            toutatis=toutatis,
            recursive=recursive,
            recursive_depth=recursive_depth,
            passive=passive,
            passive_domain=passive_domain,
            reverse_image=reverse_image,
            past_usernames=past_usernames,
            proxy=args.proxy,
            proxies=_collect_proxy_pool(args),
            tor=args.tor,
            categories=categories,
            request_timeout=args.timeout or REQUEST_TIMEOUT,
            fp_threshold=getattr(args, "fp_threshold", None) or 0.45,
            fingerprint=not getattr(args, "no_fingerprint", False),
            new_circuit_every=int(getattr(args, "new_circuit_every", 0) or 0),
            tor_control_password=getattr(args, "tor_control_password", None),
            playwright=getattr(args, "playwright", False),
            browser_backend=(
                getattr(args, "browser_backend", "playwright") or "playwright"
            ),
            no_auto_render=bool(getattr(args, "no_auto_render", False)),
            screenshots=getattr(args, "screenshots", False),
            screenshot_dir=getattr(args, "screenshot_dir", None),
            geocode=getattr(args, "geocode", False),
            phone=phone,
            phone_region=phone_region,
            crypto_addresses=crypto_addresses,
            enrichment=not getattr(args, "no_enrichment", False),
            redteam_domain=(getattr(args, "redteam_domain", None) or None),
            redteam_names_file=(getattr(args, "redteam_names_file", None) or None),
            redteam_github_org=(getattr(args, "redteam_github_org", None) or None),
            gitleaks_paths=tuple(
                p.strip()
                for p in (getattr(args, "gitleaks_path", None) or [])
                if p and p.strip()
            ),
            gitleaks_no_git=bool(getattr(args, "gitleaks_no_git", False)),
            gitleaks_timeout=int(getattr(args, "gitleaks_timeout", 120) or 120),
            exif_image_urls=tuple(
                u.strip()
                for u in (getattr(args, "exif_url", None) or [])
                if u and u.strip()
            ),
            bssid=(getattr(args, "bssid", None) or None),
            ssid=(getattr(args, "ssid", None) or None),
            company_query=(getattr(args, "company", None) or None),
            company_limit=int(getattr(args, "company_limit", 5) or 5),
            harvest_doc_urls=tuple(
                u.strip()
                for u in (getattr(args, "harvest_doc", None) or [])
                if u and u.strip()
            ),
            intelx_term=(getattr(args, "intelx", None) or None),
            intelx_limit=int(getattr(args, "intelx_limit", 50) or 50),
            full_name=(getattr(args, "name", None) or None),
            name_year=(getattr(args, "name_year", None) or None),
            name_max_handles=int(getattr(args, "name_max_handles", 8) or 8),
            email_only=(getattr(args, "email_only", None) or None),
            ai_skills=bool(getattr(args, "ai_skills", False)),
            ai_skill_budget=int(
                getattr(args, "ai_skill_budget", 20) or 20
            ),
        )

    def mode_parts(self) -> list[str]:
        parts: list[str] = []
        mapping = [
            (self.deep, "Deep"),
            (self.smart, "Smart"),
            (self.email, "Email"),
            (self.web, "Web"),
            (self.whois, "WHOIS"),
            (self.breach, "Breach"),
            (self.photo, "Photo"),
            (self.dns, "DNS"),
            (self.subdomain, "Subdomain"),
            (self.holehe, "Holehe"),
            (self.ghunt, "GHunt"),
            (self.toutatis, "Toutatis"),
            (self.recursive, "Recursive"),
            (self.passive, "Passive"),
            (self.reverse_image, "ReverseImage"),
            (self.past_usernames, "PastUsernames"),
            (bool(self.phone), "Phone"),
            (bool(self.crypto_addresses), "Crypto"),
            (bool(self.bssid or self.ssid), "Wigle"),
            (bool(self.company_query), "Company"),
            (bool(self.harvest_doc_urls), "DocMeta"),
            (bool(self.intelx_term), "IntelX"),
            (bool(self.gitleaks_paths), "GitLeaks"),
            (bool(self.redteam_domain), "Redteam"),
            (self.enrichment, "Enrichment"),
            (self.browser_backend == "obscura", "Obscura"),
            (self.tor, "Tor"),
        ]
        for flag, label in mapping:
            if flag:
                parts.append(label)
        return parts
