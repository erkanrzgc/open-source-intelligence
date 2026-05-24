---
name: passive
description: Third-party intel sources (Shodan, Censys, Fofa, ZoomEye, IntelX, Wigle, OpenCorporates, …).
inputs:
  username: str
  domain: str (optional)
  profile_urls: list[str]
outputs:
  passive_hits: list[PassiveHit]
  company_records: list[CompanyRecord]
triggers:
  - cfg.passive (default true)
  - cfg.intelx_term
  - cfg.bssid / cfg.ssid
  - cfg.company_query
dependencies:
  - core.http_client
  - api keys per source (see env list)
ai_required: false
---

## When to use

Always-on for username scans; selective for keyword/MAC/SSID/company
lookups. Each source has its own opt-in env var — missing creds means
the source silently skips.

## Sources & env vars

| Module | Required env | Purpose |
|---|---|---|
| `shodan.py` | `SHODAN_API_KEY` | Internet-exposed host data |
| `censys.py` | `CENSYS_API_ID`, `CENSYS_API_SECRET` | Cert + host fingerprints |
| `fofa.py` | `FOFA_EMAIL`, `FOFA_KEY` | Chinese cyber intel |
| `zoomeye.py` | `ZOOMEYE_API_KEY` | Asia-Pacific host intel |
| `criminalip.py` | `CRIMINALIP_API_KEY` | IP threat-intel |
| `intelx.py` | `INTELX_API_KEY` | Paste/leak/dark-web search |
| `wigle.py` | `WIGLE_API_NAME`, `WIGLE_API_TOKEN` | BSSID/SSID geolocation |
| `opencorporates.py` | `OPENCORPORATES_API_TOKEN` (optional, raises limits) | Company registry + officers |
| `pastebin.py` | none | Pastebin scrape |
| `wayback.py` | none | Archive.org snapshots |
| `ahmia.py` | none | Tor hidden service search |
| `harvester.py` | none | theHarvester-style email scrape |
| `google_dork.py` | none | Targeted SERP dorks |

## Output contract

All sources return `PassiveHit(kind: str, source: str, ...)` dataclasses
appended to `result.passive_hits`. Company records go to a separate
`result.company_records` field because they have richer structure.

## Failure modes

* No API key → return empty list, log at debug.
* Rate-limit / 429 → backoff handled by HTTPClient.
* Truncated/malformed response → skipped, others continue.

## Orchestration

`modules.passive.orchestrator.run_passive(client, username, domain, profile_urls)`
fans out all enabled sources concurrently. The engine doesn't call
individual sources directly.
