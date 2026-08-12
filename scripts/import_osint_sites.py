#!/usr/bin/env python3
"""Reverse-engineer Maigret, Sherlock and WhatsMyName site databases into platforms.yaml.

Produces modules/platforms.yaml enriched with 2000+ platforms while preserving
the curated top entries (deep scrapers, check_type overrides) from the existing
file. WhatsMyName is community-maintained and tends to be the freshest source.

Usage:
    python scripts/import_osint_sites.py \\
        --maigret /tmp/osint-src/maigret_data.json \\
        --sherlock /tmp/osint-src/sherlock_data.json \\
        --wmn /tmp/osint-src/wmn-data.json \\
        --out modules/platforms.yaml
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CURATED_YAML = ROOT / "modules" / "platforms.yaml"

MAIGRET_CHECK_MAP = {
    "status_code": "status",
    "message": "content_absent",
    "response_url": "status",
}

SHERLOCK_ERROR_MAP = {
    "status_code": "status",
    "message": "content_absent",
    "response_url": "status",
}

WMN_CATEGORY_MAP: dict[str, str] = {
    "social": "social",
    "gaming": "gaming",
    "hobby": "community",
    "tech": "dev",
    "coding": "dev",
    "misc": "community",
    "finance": "professional",
    "images": "content",
    "business": "professional",
    "music": "content",
    "shopping": "professional",
    "blog": "content",
    "art": "content",
    "health": "community",
    "dating": "dating",
    "political": "community",
    "archived": "community",
    "video": "content",
    "news": "content",
}


TAG_CATEGORY_PRIORITY: list[tuple[str, str]] = [
    ("dating", "dating"),
    ("gaming", "gaming"),
    ("coding", "dev"),
    ("tech", "dev"),
    ("hacking", "dev"),
    ("music", "content"),
    ("video", "content"),
    ("photo", "content"),
    ("art", "content"),
    ("blog", "content"),
    ("news", "content"),
    ("sharing", "content"),
    ("reading", "content"),
    ("writing", "content"),
    ("social", "social"),
    ("freelance", "professional"),
    ("finance", "professional"),
    ("crypto", "professional"),
    ("shopping", "professional"),
    ("business", "professional"),
    ("education", "community"),
    ("sport", "community"),
    ("travel", "community"),
    ("forum", "community"),
]

# Tags that we consider low-value language/country-only markers.
STOP_TAGS = {
    "ru", "ua", "us", "gb", "de", "tr", "jp", "pk", "fr", "it", "es", "br",
    "cn", "in", "kr", "nl", "pl", "cz", "fi", "se", "no", "dk", "hu", "ro",
    "by", "kz", "id", "th", "vn", "ph", "sa", "ae", "il", "gr", "pt", "mx",
    "ar", "cl", "co", "pe", "ve", "za", "ng", "eg", "my", "tw", "hk", "au",
    "ca", "nz", "ie",
}

MAX_ALEXA_FOR_ENGINE = 500_000  # engine-only forums need popularity threshold


@dataclass
class OutPlatform:
    name: str
    url: str
    category: str
    check_type: str = "status"
    error_text: str = ""
    success_text: str = ""
    headers: dict[str, str] | None = None
    has_deep_scraper: bool = False

    def to_yaml_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "url": self.url, "category": self.category}
        if self.check_type != "status":
            d["check_type"] = self.check_type
        if self.error_text:
            d["error_text"] = self.error_text
        if self.success_text:
            d["success_text"] = self.success_text
        if self.headers:
            d["headers"] = self.headers
        if self.has_deep_scraper:
            d["has_deep_scraper"] = True
        return d


def _pick_category(tags: list[str]) -> str:
    t = {x.lower() for x in tags}
    for tag, cat in TAG_CATEGORY_PRIORITY:
        if tag in t:
            return cat
    return "community"


def _first_str(val: Any) -> str:
    if isinstance(val, list) and val:
        v = val[0]
        return v if isinstance(v, str) else ""
    if isinstance(val, str):
        return val
    return ""


def _resolve_maigret_site(name: str, site: dict, engines: dict) -> dict | None:
    """Expand engine references and return a merged dict with url/checkType/etc."""
    if site.get("disabled"):
        return None
    merged = dict(site)
    engine_name = site.get("engine")
    if engine_name:
        engine = engines.get(engine_name)
        if not engine:
            return None
        template = engine.get("site", {})
        for k, v in template.items():
            merged.setdefault(k, v)
    url = merged.get("url")
    if not isinstance(url, str):
        return None
    if "{urlMain}" in url:
        main = merged.get("urlMain")
        if not main:
            return None
        url = url.replace("{urlMain}", main.rstrip("/"))
    if "{urlSubpath}" in url:
        sub = merged.get("urlSubpath", "")
        url = url.replace("{urlSubpath}", sub)
    if "{username}" not in url:
        return None
    merged["_resolved_url"] = url
    return merged


def _convert_maigret(data: dict) -> list[OutPlatform]:
    sites = data.get("sites", {})
    engines = data.get("engines", {})
    out: list[OutPlatform] = []
    for name, site in sites.items():
        resolved = _resolve_maigret_site(name, site, engines)
        if resolved is None:
            continue
        # Engine-only forums: require a minimum popularity
        is_engine_only = not site.get("url") and site.get("engine")
        if is_engine_only:
            rank = resolved.get("alexaRank", 10**9)
            if not isinstance(rank, int) or rank > MAX_ALEXA_FOR_ENGINE:
                continue
        url = resolved["_resolved_url"]
        check_type = MAIGRET_CHECK_MAP.get(resolved.get("checkType", ""), "status")
        abs_str = _first_str(resolved.get("absenceStrs"))
        pres_str = _first_str(resolved.get("presenseStrs"))
        # Prefer content_absent when we have abs_str, content_present when only pres_str
        if check_type == "content_absent" and not abs_str and pres_str:
            check_type = "content_present"
        headers = resolved.get("headers")
        if not isinstance(headers, dict):
            headers = None
        tags = [t for t in resolved.get("tags", []) if isinstance(t, str) and t not in STOP_TAGS]
        category = _pick_category(tags)
        out.append(
            OutPlatform(
                name=name,
                url=url,
                category=category,
                check_type=check_type,
                error_text=abs_str,
                success_text=pres_str if check_type == "content_present" else "",
                headers=headers,
            )
        )
    return out


def _convert_sherlock(data: dict) -> list[OutPlatform]:
    out: list[OutPlatform] = []
    for name, site in data.items():
        if name.startswith("$"):
            continue
        if not isinstance(site, dict):
            continue
        if site.get("isNSFW"):
            continue
        url = site.get("url")
        if not isinstance(url, str):
            continue
        if "{}" in url:
            url = url.replace("{}", "{username}")
        if "{username}" not in url:
            continue
        error_type = site.get("errorType", "status_code")
        check_type = SHERLOCK_ERROR_MAP.get(error_type, "status")
        error_text = site.get("errorMsg") or ""
        if isinstance(error_text, list):
            error_text = error_text[0] if error_text else ""
        headers = site.get("headers")
        if not isinstance(headers, dict):
            headers = None
        out.append(
            OutPlatform(
                name=name,
                url=url,
                category="community",  # Sherlock has no categories
                check_type=check_type,
                error_text=error_text,
                headers=headers,
            )
        )
    return out


def _convert_wmn(data: dict) -> list[OutPlatform]:
    sites = data.get("sites", [])
    out: list[OutPlatform] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        cat_raw = str(site.get("cat", "")).strip()
        if "nsfw" in cat_raw.lower():
            continue
        name = site.get("name")
        url = site.get("uri_check")
        if not (isinstance(name, str) and isinstance(url, str)):
            continue
        if "{account}" in url:
            url = url.replace("{account}", "{username}")
        if "{username}" not in url:
            continue
        e_string = site.get("e_string") or ""
        m_string = site.get("m_string") or ""
        if isinstance(e_string, str) and e_string:
            check_type = "content_present"
            success_text = e_string
            error_text = ""
        elif isinstance(m_string, str) and m_string:
            check_type = "content_absent"
            success_text = ""
            error_text = m_string
        else:
            check_type = "status"
            success_text = ""
            error_text = ""
        category = WMN_CATEGORY_MAP.get(cat_raw, "community")
        out.append(
            OutPlatform(
                name=name,
                url=url,
                category=category,
                check_type=check_type,
                error_text=error_text,
                success_text=success_text,
            )
        )
    return out


def _load_curated() -> tuple[list[dict], dict[str, dict]]:
    raw = yaml.safe_load(CURATED_YAML.read_text(encoding="utf-8"))
    plats = raw.get("platforms", [])
    by_name = {p["name"]: p for p in plats}
    return plats, by_name


_URL_NORMALIZE_RE = re.compile(r"^https?://(www\.)?")


def _url_key(url: str) -> str:
    stripped = _URL_NORMALIZE_RE.sub("", url.strip().rstrip("/").lower())
    return stripped.replace("{username}", "{u}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--maigret", required=True)
    ap.add_argument("--sherlock", required=True)
    ap.add_argument("--wmn", default="")
    ap.add_argument("--out", default=str(CURATED_YAML))
    args = ap.parse_args()

    maigret = json.loads(Path(args.maigret).read_text(encoding="utf-8"))
    sherlock = json.loads(Path(args.sherlock).read_text(encoding="utf-8"))
    wmn = (
        json.loads(Path(args.wmn).read_text(encoding="utf-8")) if args.wmn else None
    )

    curated, _curated_by_name = _load_curated()
    curated_url_keys = {_url_key(p["url"]) for p in curated}
    curated_name_keys = {p["name"].lower() for p in curated}

    imported: dict[str, OutPlatform] = {}

    for p in _convert_maigret(maigret):
        imported[p.name] = p
    if wmn is not None:
        # WhatsMyName often has sharper e_string/m_string — prefer its entries
        # when a site is present in both, to benefit from community upkeep.
        for p in _convert_wmn(wmn):
            imported[p.name] = p
    for p in _convert_sherlock(sherlock):
        # Sherlock is secondary; don't overwrite Maigret/WMN entries.
        imported.setdefault(p.name, p)

    final: list[dict] = list(curated)  # curated always wins, preserves order
    added = 0
    for name, plat in imported.items():
        if name.lower() in curated_name_keys:
            continue
        key = _url_key(plat.url)
        if key in curated_url_keys:
            continue
        curated_url_keys.add(key)
        curated_name_keys.add(name.lower())
        final.append(plat.to_yaml_dict())
        added += 1

    out_path = Path(args.out)
    out_path.write_text(
        yaml.safe_dump(
            {"platforms": final},
            sort_keys=False,
            allow_unicode=True,
            width=1000,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    print(f"Curated kept: {len(curated)}")
    print(f"Imported added: {added}")
    print(f"Total platforms: {len(final)}")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
