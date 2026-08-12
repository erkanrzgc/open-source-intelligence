"""Google dork search across a target domain.

Two-tier provider chain:

1. **SerpAPI** when ``SERPAPI_API_KEY`` is in the environment — paid,
   reliable JSON output.
2. **DuckDuckGo HTML** as the keyless fallback — DDG indexes Google
   results for many queries and does not require an API key. We hit
   ``html.duckduckgo.com`` so the response is plain HTML we can parse
   with the stdlib.

Why dorks?  Pre-built queries surface low-hanging recon fruit that
``hostname:`` searches on Shodan/Censys miss: leaked credentials in
public Pastebin-style indexes, exposed admin panels, indexed config
files, document leaks. Each preset is tagged in ``metadata["preset"]``
so the reporter can group results.

This module is read-only — every call is a search engine query, never
a request to the target domain itself.
"""

from __future__ import annotations

import asyncio
import os
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, urlparse

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_SERPAPI_ENDPOINT = "https://serpapi.com/search.json"
_DDG_ENDPOINT = "https://html.duckduckgo.com/html/"

_PRESETS: dict[str, tuple[str, ...]] = {
    "secrets": (
        'site:{d} (intext:"api_key" OR intext:"apikey" OR intext:"password" OR intext:"secret")',
        'site:{d} (ext:env OR ext:cfg OR ext:ini OR ext:conf)',
        'site:pastebin.com "{d}"',
        'site:github.com "{d}" (password OR api_key OR secret)',
    ),
    "files": (
        'site:{d} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)',
        'site:{d} (filetype:sql OR filetype:bak OR filetype:log)',
        'site:{d} filetype:txt',
    ),
    "exposed": (
        'site:{d} intitle:"index of"',
        'site:{d} (inurl:admin OR inurl:login OR inurl:dashboard)',
        'site:{d} (inurl:wp-config OR inurl:phpinfo OR inurl:.git)',
    ),
    "paste": (
        '"{d}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:gist.github.com)',
    ),
    "subdomains": (
        'site:*.{d} -www',
    ),
}

_DEFAULT_PRESETS: tuple[str, ...] = ("secrets", "files", "exposed")


def _expand_presets(domain: str, presets: list[str]) -> list[str]:
    """Materialize preset templates against ``domain``.

    Unknown preset names are silently dropped so callers can pass a
    user-supplied list without pre-validating it.
    """
    out: list[str] = []
    for name in presets:
        templates = _PRESETS.get(name)
        if not templates:
            continue
        for tpl in templates:
            out.append(tpl.format(d=domain))
    return out


def _build_dorks(
    *,
    domain: str,
    presets: list[str] | None,
    custom_dorks: list[str] | None,
) -> list[str]:
    """Combine preset and custom dorks into a deduped, ordered list."""
    if presets is None:
        presets = list(_DEFAULT_PRESETS)
    dorks = _expand_presets(domain, presets)
    for raw in custom_dorks or []:
        if raw and raw not in dorks:
            dorks.append(raw)
    return dorks


# ── SerpAPI ─────────────────────────────────────────────────────────


async def _serpapi_query(
    client: HTTPClient,
    query: str,
    *,
    api_key: str,
    limit: int,
) -> list[tuple[str, str, str]]:
    """Return ``[(url, title, snippet), ...]`` from one SerpAPI call."""
    url = (
        f"{_SERPAPI_ENDPOINT}"
        f"?engine=google&q={quote(query)}"
        f"&api_key={api_key}&num={limit}"
    )
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return []
    results = data.get("organic_results")
    if not isinstance(results, list):
        return []
    out: list[tuple[str, str, str]] = []
    for r in results[:limit]:
        link = r.get("link") or ""
        if not link:
            continue
        out.append((link, r.get("title") or "", r.get("snippet") or ""))
    return out


# ── DuckDuckGo HTML ─────────────────────────────────────────────────


class _DDGHTMLParser(HTMLParser):
    """Streaming parser for DDG's HTML SERP layout.

    The page emits ``<a class="result__a">`` for the headline link and
    ``<a class="result__snippet">`` for the body text, both inside a
    common ``<div class="result">`` wrapper. We pair them up in order.
    """

    def __init__(self) -> None:
        super().__init__()
        self._mode: str | None = None  # "title" | "snippet"
        self._href: str = ""
        self._text_buf: list[str] = []
        self.results: list[tuple[str, str, str]] = []
        self._pending: tuple[str, str] | None = None  # (url, title)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        attr = dict(attrs)
        cls = (attr.get("class") or "").split()
        if "result__a" in cls:
            self._mode = "title"
            self._href = attr.get("href") or ""
            self._text_buf = []
        elif "result__snippet" in cls:
            self._mode = "snippet"
            self._text_buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or self._mode is None:
            return
        text = "".join(self._text_buf).strip()
        if self._mode == "title":
            url = _unwrap_ddg(self._href)
            if url:
                self._pending = (url, text)
        elif self._mode == "snippet" and self._pending is not None:
            url, title = self._pending
            self.results.append((url, title, text))
            self._pending = None
        self._mode = None
        self._text_buf = []

    def handle_data(self, data: str) -> None:
        if self._mode is not None:
            self._text_buf.append(data)


_DDG_REDIRECT_RE = re.compile(r"^(?://duckduckgo\.com/l/|https?://duckduckgo\.com/l/)")


def _unwrap_ddg(href: str) -> str:
    """Resolve DDG redirect wrappers to the underlying target URL."""
    if not href:
        return ""
    if _DDG_REDIRECT_RE.match(href):
        # parse_qs needs a scheme to behave; prepend https: for protocol-relative
        normalized = href if href.startswith("http") else f"https:{href}"
        qs = parse_qs(urlparse(normalized).query)
        target = qs.get("uddg", [""])[0]
        return target
    if href.startswith("//"):
        return f"https:{href}"
    return href


async def _ddg_query(
    client: HTTPClient,
    query: str,
    *,
    limit: int,
) -> list[tuple[str, str, str]]:
    """Return ``[(url, title, snippet), ...]`` from DDG HTML."""
    url = f"{_DDG_ENDPOINT}?q={quote(query)}"
    status, body, _ = await client.get(url)
    if status != 200 or not body:
        return []
    parser = _DDGHTMLParser()
    try:
        parser.feed(body)
    except Exception as exc:
        log.debug("DDG parse failed for %r: %s", query, exc)
        return []
    return parser.results[:limit]


# ── Public entry point ──────────────────────────────────────────────


async def search(
    client: HTTPClient,
    domain: str,
    *,
    presets: list[str] | None = None,
    custom_dorks: list[str] | None = None,
    limit_per_dork: int = 10,
) -> list[PassiveHit]:
    """Run dork queries against SerpAPI (preferred) or DDG fallback.

    Returns a deduplicated list of :class:`PassiveHit`. Empty when
    ``domain`` is blank or no presets/custom dorks resolve.
    """
    if not domain:
        return []

    dorks = _build_dorks(
        domain=domain, presets=presets, custom_dorks=custom_dorks
    )
    if not dorks:
        return []

    api_key = os.environ.get("SERPAPI_API_KEY")
    provider = "serpapi" if api_key else "ddg"
    log.debug("google_dork: provider=%s dorks=%d", provider, len(dorks))

    async def run_one(query: str) -> tuple[str, list[tuple[str, str, str]]]:
        if api_key:
            rows = await _serpapi_query(
                client, query, api_key=api_key, limit=limit_per_dork
            )
        else:
            rows = await _ddg_query(client, query, limit=limit_per_dork)
        return query, rows

    results = await asyncio.gather(
        *(run_one(d) for d in dorks),
        return_exceptions=True,
    )

    hits: list[PassiveHit] = []
    seen: set[str] = set()
    preset_for_dork = _preset_index(domain, presets)

    for entry in results:
        if isinstance(entry, BaseException):
            log.debug("google_dork: dork failed: %s", entry)
            continue
        query, rows = entry
        for url, title, snippet in rows:
            key = url.lower()
            if not url or key in seen:
                continue
            seen.add(key)
            hits.append(
                PassiveHit(
                    source="google_dork",
                    kind="dork",
                    value=url,
                    title=title,
                    metadata={
                        "dork": query,
                        "snippet": snippet,
                        "preset": preset_for_dork.get(query, "custom"),
                        "provider": provider,
                    },
                )
            )
    return hits


def _preset_index(
    domain: str, presets: list[str] | None
) -> dict[str, str]:
    """Build a reverse lookup ``dork -> preset name`` for tagging hits."""
    if presets is None:
        presets = list(_DEFAULT_PRESETS)
    mapping: dict[str, str] = {}
    for name in presets:
        for tpl in _PRESETS.get(name, ()):
            mapping[tpl.format(d=domain)] = name
    return mapping
