"""Runtime configuration with environment overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass

from modules.fp_filter import DEFAULT_THRESHOLD
from utils.helpers import sanitize_username


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


MAX_CONCURRENT = _env_int("OSINT_MAX_CONCURRENT", 50)
REQUEST_TIMEOUT = _env_int("OSINT_TIMEOUT", 15)
RETRY_COUNT = _env_int("OSINT_RETRIES", 2)
RETRY_DELAY = _env_float("OSINT_RETRY_DELAY", 1.0)
RATE_LIMIT_DELAY = _env_float("OSINT_RATE_LIMIT_DELAY", 0.1)
PER_HOST_CONCURRENCY = _env_int("OSINT_PER_HOST_CONCURRENCY", 6)

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


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration — replaces a wide boolean parameter list."""

    username: str
    deep: bool = True
    smart: bool = True
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
    platform_scope: str = "core"
    alias_max_candidates: int = 24
    alias_platform_limit: int = 15
    request_timeout: int = REQUEST_TIMEOUT
    fp_threshold: float = DEFAULT_THRESHOLD  # shared by Python, CLI, REST and MCP
    skip_invalid_usernames: bool = True  # pre-filter platforms where username doesn't match pattern
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
    full_name: str | None = None  # real name → handle generator phase 0
    name_year: int | None = None  # birth/registration year hint for handle gen
    name_max_handles: int = 8  # how many candidate handles to actually probe
    email_only: str | None = None  # email-first scan target
    ai_skills: bool = False  # opt-in: use LLM-backed skills during scan
    ai_skill_budget: int = 20  # max LLM calls per scan when ai_skills is on
    ai_report: bool = False  # opt-in executive summary skill
    allow_private_networks: bool = False  # explicit opt-in for local-network research

    def __post_init__(self) -> None:
        """Normalize the target at the single public configuration boundary."""
        if self.username:
            object.__setattr__(self, "username", sanitize_username(self.username))
        if not 0.0 <= self.fp_threshold <= 1.0:
            raise ValueError("fp_threshold must be between 0 and 1")
        if self.ai_skill_budget < 0:
            raise ValueError("ai_skill_budget must be non-negative")
        if self.platform_scope not in ("core", "full"):
            raise ValueError("platform_scope must be 'core' or 'full'")
        if not 1 <= self.alias_max_candidates <= 24:
            raise ValueError("alias_max_candidates must be between 1 and 24")
        if not 1 <= self.alias_platform_limit <= 15:
            raise ValueError("alias_platform_limit must be between 1 and 15")
