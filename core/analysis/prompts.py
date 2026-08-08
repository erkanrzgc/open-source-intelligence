"""Prompt templates for the local OSINT analyst LLM."""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are a senior OSINT / threat-intelligence analyst. You receive the
JSON output of an automated username reconnaissance scan and must produce a
structured briefing suitable for a SOC or investigator.

Your objectives:

1. IDENTITY — Who is the target, to the extent the data supports?
   Pull names, locations, languages, apparent profession, timezone/activity hints,
   and age/tenure signals from bios, join dates, and post counts.

2. LINKAGE — Which signals most strongly tie the observed accounts to one person?
   Rank by strength: shared email > shared avatar hash > identical bio/name on
   multiple platforms > cross-referenced username > location/timezone overlap.
   Cite the platforms that contributed each signal.

3. EXPOSURE — Threat-model the footprint for the subject's OPSEC:
   * HIGH: breached credentials, leaked real names on pseudonymous accounts,
     resolvable home location, exposed email + username reuse enabling
     credential stuffing, long-lived account reuse across NSFW/anon contexts.
   * MED: predictable username patterns, publicly indexed resume/CV material,
     personal email on professional site, photo reuse across contexts.
   * LOW: minor metadata leaks, third-party tagging, bio overshares.

4. NEXT STEPS — 3-5 concrete, runnable investigative follow-ups (specific
   platforms, queries, dorks, reverse-image searches). No generic advice.

Rules:
- Work ONLY from the supplied JSON. NEVER invent platforms, URLs, breaches,
  or facts. If a field is empty, treat it as unknown.
- A match with low `confidence` (< 0.6) or only a "size" FP signal is weak —
  discount or exclude it from strong_linkages.
- Prefer terse, factual bullets. No disclaimers, no hedging, no apologies.
- Output MUST be valid JSON matching the schema in the user message. No prose
  outside the JSON object. No markdown fences.
- Never omit a schema key; use empty string or empty list when you have nothing.
- Respond in the same language the scan clearly targets; default to English.
"""


OUTPUT_SCHEMA = {
    "identity_summary": "str — 1-3 sentence profile of the subject",
    "likely_names": ["str — real names or persistent aliases with source platform"],
    "likely_locations": ["str — city/country/timezone with source platform"],
    "strong_linkages": ["str — each: platform(s) + specific linking signal"],
    "exposures": ["str — each: HIGH/MED/LOW prefix + concrete evidence"],
    "credential_risk": "str — none|low|medium|high, based on breach data + reuse",
    "next_steps": ["str — specific platform/query/dork to run next"],
    "confidence": "int — 0..100 overall identity-match confidence",
}


def build_user_prompt(scan_payload: dict[str, Any]) -> str:
    """Format the scan payload as a compact JSON block plus response schema."""
    trimmed = _trim_payload(scan_payload)
    return (
        "SCAN_JSON:\n"
        f"{json.dumps(trimmed, ensure_ascii=False, indent=2)}\n\n"
        "RESPONSE_SCHEMA:\n"
        f"{json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2)}\n\n"
        "Return a single JSON object matching RESPONSE_SCHEMA. No prose outside JSON."
    )


def _trim_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip noise so the model sees only the signal-dense fields."""
    found_platforms = [
        {
            "platform": p.get("platform"),
            "url": p.get("url"),
            "category": p.get("category"),
            "confidence": round(p.get("confidence", 0.0), 2),
            "fp_signals": p.get("fp_signals", []),
            "profile_data": _trim_profile(p.get("profile_data") or {}),
        }
        for p in payload.get("platforms", [])
        if isinstance(p, dict) and p.get("exists")
    ]
    emails = [
        {
            "email": e.get("email"),
            "source": e.get("source"),
            "breach_count": e.get("breach_count", 0),
            "breaches": [b.get("Name") if isinstance(b, dict) else b for b in e.get("breaches", [])],
        }
        for e in payload.get("emails", [])
    ]
    return {
        "username": payload.get("username"),
        "found_count": payload.get("found_count"),
        "platforms": found_platforms,
        "emails": emails,
        "discovered_usernames": payload.get("discovered_usernames", []),
        "whois_records": payload.get("whois_records", []),
        "web_presence": payload.get("web_presence", [])[:10],
        "photo_matches": payload.get("photo_matches", []),
        "cross_reference": payload.get("cross_reference", {}),
        "comb_leaks": [
            {
                "identifier": leak.get("identifier"),
                "password_preview": leak.get("password_preview"),
                "raw_length": leak.get("raw_length"),
                "source": leak.get("source"),
            }
            for leak in payload.get("comb_leaks", [])
        ],
        "holehe_hits": [
            {
                "email": h.get("email"),
                "site": h.get("site"),
                "domain": h.get("domain"),
            }
            for h in payload.get("holehe_hits", [])
        ],
        "ghunt_results": [
            {
                "email": g.get("email"),
                "name": g.get("name"),
                "gaia_id": g.get("gaia_id"),
                "services": g.get("services", []),
            }
            for g in payload.get("ghunt_results", [])
        ],
        "toutatis_results": [
            {
                "username": t.get("username"),
                "user_id": t.get("user_id"),
                "full_name": t.get("full_name"),
                "is_private": t.get("is_private"),
                "is_verified": t.get("is_verified"),
                "follower_count": t.get("follower_count"),
                "following_count": t.get("following_count"),
                "biography": t.get("biography"),
                "external_url": t.get("external_url"),
                "obfuscated_email": t.get("obfuscated_email"),
                "obfuscated_phone": t.get("obfuscated_phone"),
            }
            for t in payload.get("toutatis_results", [])
        ],
    }


_KEEP_PROFILE_KEYS = {
    # identity
    "name", "fullname", "nickname", "first_name", "last_name", "real_name",
    # bio / self-description
    "bio", "description", "about", "status",
    # location
    "location", "country", "city", "timezone", "language",
    # contact / linked
    "email", "website", "blog", "links", "twitter_username", "github_username",
    # professional
    "company", "occupation", "job", "title",
    # activity / tenure
    "followers", "following", "posts", "public_repos", "karma",
    "created_at", "joined", "last_seen",
    # visual
    "avatar_url", "avatar", "profile_image", "image",
    # demographics
    "gender", "birthday", "age",
}


def _trim_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in profile.items() if k in _KEEP_PROFILE_KEYS and v not in (None, "")}
