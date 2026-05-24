# AGENTS.md — cyberm4fia-osint architecture & skill registry

This file is the **architecture map and contract index** for the project.
It complements `README.md` (which is end-user-facing) and is intended for
contributors, automated coding agents, and reviewers who need to know
*how* the system is laid out, *what each module promises*, and *which
skills the LLM is allowed to invoke*.

If you're adding a new module, follow this file's layout and drop a
`SKILL.md` next to your code (see `## Per-module SKILL.md contract`
below).

---

## High-level flow

```
┌─ CLI / FastAPI / MCP entrypoint ─────────────────────────────────────┐
│   main.py | core/api/server.py | mcp_server.py                       │
│   parse args / request → build ScanConfig (core/config.py)           │
└──────────────────────────────────────────────────────────────────────┘
                          │ ScanConfig (frozen dataclass)
                          ▼
┌─ Scan engine ────────────────────────────────────────────────────────┐
│   core/engine.py  run_scan(cfg) → ScanResult                         │
│   Phases run in fixed order; each is opt-in via cfg flags.           │
└──────────────────────────────────────────────────────────────────────┘
                          │ ScanResult (mutable dataclass)
                          ▼
┌─ Reporters / persistence ────────────────────────────────────────────┐
│   core/reporter/* — console UI, CSV, HTML, JSON                      │
│   core/history.py — SQLite scan history                              │
│   core/api/server.py — JSON response                                 │
└──────────────────────────────────────────────────────────────────────┘
```

`HTTPClient` (`core/http_client.py`) is the only network layer. Every
module that needs the wire goes through it — no module imports
`aiohttp` directly except `http_client.py` itself.

---

## Engine phase order

```
[0]  handle_resolve     — only when --name is set (resolves real name → handle)
[1]  platform_check     — sweep 1924 platforms in parallel
     └─ per platform: get → final-URL check → soft-404 cache lookup →
        liveness scoring → FP filter
[1.5] profile_validate  — opt-in (--ai-skills): LLM verdict for borderline matches
[2]  deep_scrape        — hand-curated API/HTML parsers for ~12 sites
[3]  smart_search       — username variations + linked-account discovery
[4]  photo              — perceptual-hash avatar comparison (CPU-bound,
                          offloaded via asyncio.to_thread)
[5]  email_breach       — Gravatar → discover_emails → HIBP/XposedOrNot →
                          COMB → holehe → ghunt → toutatis
[6]  web_presence       — Wayback + paste sites
[7]  whois              — multi-TLD WHOIS for the username
[8]  dns_subdomain      — DNS records + crt.sh subdomain enumeration
[+]  recursive          — feed discovered usernames back into [1]
[+]  reverse_image      — Yandex/IQDB reverse search on avatar URLs
[+]  username_history   — Wayback CDX for historical alias mining
[+]  passive            — Shodan/Censys/Fofa/ZoomEye/Pastebin/IntelX/Wigle
[+]  phone              — phonenumbers + NumVerify metadata
[+]  crypto             — BTC/ETH balance + tx lookup
[+]  recon              — corporate red-team: email patterns + GitHub
                          org + subdomain enrichment + secret scanning
[+]  gitleaks           — local repo secret scan (optional CLI list)
[+]  exif               — image GPS/timestamp metadata
[+]  wigle              — BSSID/SSID geolocation
[+]  company            — OpenCorporates registry + officers
[+]  doc_metadata       — public document author/last-editor extraction
[+]  intelx             — Intelligence X paste/leak/dark-web search
[+]  cross_reference    — name/location/linked-accounts identity scoring
[+]  geocode            — Nominatim location resolution
[+]  enrichment         — stylometry + language + timezone + entity graph
```

**Rule:** new phases append to `engine.py:run_scan`. They MUST be no-ops
when their `cfg.<flag>` is False. They MUST NOT throw — failures get
logged and swallowed so one bad source doesn't tank the whole scan.

---

## Accuracy hardening (added 2026-05)

Three layers protect against the "200 OK but actually a soft-404 / empty
shell / wrong person" failure mode:

1. **Final-URL detection** (`engine._looks_redirected_off`). When the
   server redirects us off the requested path to a generic page
   (`/login`, `/explore`, …) we drop the confidence by 0.30 and may flip
   `exists=False` for `check_type=status` platforms.

2. **Soft-404 fingerprint cache** (`modules/stealth/soft_404.py`). For
   each platform we maintain a SimHash fingerprint of "what the page
   looks like when the username does NOT exist". Fetched bodies are
   compared against this baseline; matches within Hamming distance ≤ 6
   are flagged as soft-404. Baselines auto-seed on first found match
   (fire-and-forget) and live in `~/.cache/cyberm4fia/soft404/` for 7
   days.

3. **Profile liveness scoring** (`modules/profile_liveness.py`). After
   a match we score the body across five signals: real avatar (+0.30),
   bio (+0.25), `og:title` mentions username (+0.20), JSON-LD Person
   (+0.15), activity counter > 0 (+0.10). Scores below 0.40 → profile
   considered an empty shell, confidence reduced.

Additionally:

* **JS-wall auto-fallback** (`modules/stealth/js_wall.py`). When
  aiohttp's body looks like a Cloudflare challenge / DataDome page /
  empty `__NEXT_DATA__` shell, the engine automatically re-fetches via
  Playwright (or Camoufox) — even if `--playwright` wasn't passed.
  Disable with `--no-auto-render`.

---

## AI skill registry

The LLM is **never** invoked from a hand-rolled prompt scattered around
the codebase. Every LLM task is a markdown file under
`core/analysis/skills/` with YAML frontmatter declaring its name,
description, model overrides, and output schema. The loader at
`core/analysis/skill_loader.py` parses, validates, caches, and
budget-tracks each call.

Currently shipped skills:

| Skill | Triggered by | Purpose |
|---|---|---|
| `handle_generator.md` | `--name` CLI flag, `_phase_handle_resolve` | Suggest 15 culturally-aware username candidates from a real name. |
| `profile_validator.md` | `--ai-skills` + borderline confidence | Decide whether a borderline-scored profile belongs to the target. |

The legacy "exec summary" prompt in `core/analysis/prompts.py` will
migrate to a `exec_summary.md` skill in a future change; today it is
called directly by `LLMAnalyzer.analyze()`.

### Adding a new skill

1. Create `core/analysis/skills/<name>.md` with the frontmatter format
   documented in `skill_loader.py`. `output_schema` MUST be inline JSON
   on one line.
2. Write the system prompt as the body. Include 1–3 few-shot examples.
3. From the engine, call `run_skill(name, inputs, budget=…)`. Always
   wrap in `try/except SkillError` and fall back to the deterministic
   path.
4. Add tests in `tests/test_skill_loader.py` (loader contract) plus a
   thin wrapper test that pins the prompt against a stub backend.

### Budget & cost

`cfg.ai_skill_budget` (default 20) caps total LLM calls per scan. The
cache (`~/.cache/cyberm4fia/skills/`, 24 h TTL) eliminates repeat calls
for identical inputs. NVIDIA NIM is the default backend (free tier);
override via `CYBERM4FIA_LLM_URL`, `CYBERM4FIA_LLM_MODEL`,
`CYBERM4FIA_LLM_API_KEY`.

---

## Per-module SKILL.md contract

Every module under `modules/` and `core/` that exposes a non-trivial
public surface should ship a `SKILL.md` next to its code. The format:

```markdown
---
name: <kebab-case identifier matching the module>
description: <one-line summary, shown in indexes>
inputs: <key: type pairs documenting the main entry function>
outputs: <key: type pairs documenting the return value>
triggers: <list of ScanConfig flags / CLI flags that activate this module>
dependencies: <list of imports that this module depends on>
ai_required: <true | false>
---

## When to use
## Input contract
## Output contract
## Examples
## Failure modes
```

Aim for under 120 lines per `SKILL.md`. It is documentation, not a
manual — the code is the source of truth.

---

## Configuration surface

`ScanConfig` (frozen dataclass at `core/config.py`) is the **only**
sanctioned way to drive a scan. Adding a new feature means:

1. Add a field to `ScanConfig` (with a sensible default).
2. Wire it through `ScanConfig.from_args()` so the CLI picks it up.
3. Reference it in the relevant engine phase. NEVER read `os.environ`
   inside an engine phase — environment overrides live exclusively in
   `core/config.py` so they show up in one place.

Environment overrides currently honoured (see `core/config.py`):

```
CYBERM4FIA_MAX_CONCURRENT       (default 50)
CYBERM4FIA_PER_HOST_CONCURRENCY (default 6)
CYBERM4FIA_TIMEOUT              (default 15)
CYBERM4FIA_RETRIES              (default 2)
CYBERM4FIA_RETRY_DELAY          (default 1.0)
CYBERM4FIA_RATE_LIMIT_DELAY     (default 0.1)
CYBERM4FIA_INSECURE_TLS         (off)
CYBERM4FIA_LLM_BACKEND          ("http", "llama_cpp")
CYBERM4FIA_LLM_URL              (NVIDIA NIM by default)
CYBERM4FIA_LLM_MODEL
CYBERM4FIA_LLM_API_KEY
CYBERM4FIA_LLM_CTX              (4096)
CYBERM4FIA_LLM_MAX_TOKENS       (768)
CYBERM4FIA_LLM_TEMPERATURE      (0.2)
CYBERM4FIA_SKILL_CACHE          (~/.cache/cyberm4fia/skills)
CYBERM4FIA_SKILL_CACHE_TTL      (86400)
CYBERM4FIA_SOFT404_CACHE        (~/.cache/cyberm4fia/soft404)
CYBERM4FIA_PLATFORMS_FILE       (override modules/platforms.yaml)
```

---

## Testing rules

* `tests/test_<module>.py` per module; co-located is fine for new
  modules during initial bring-up but moved to `tests/` before merge.
* No live network in unit tests. Use stub backends / fixtures.
* For LLM-touching code: use `_StubBackend` returning a canned JSON
  response. Pin the prompt → response contract.
* Image hashing, browser rendering, gitleaks: mark with
  `@pytest.mark.skipif` when the optional dep isn't installed.

Pre-existing tests must stay green. Run the full suite before pushing:

```
.venv/bin/python -m pytest -q
```

---

## Where to look first when something breaks

| Symptom | First place to check |
|---|---|
| Scan returns no platforms | `_phase_platform_check`, `fp_threshold`, `MAX_CONCURRENT` |
| "Found" platform 404s when clicked | `_looks_redirected_off`, soft-404 cache, `profile_liveness` |
| Cloudflare blocks half the scan | `js_wall.looks_like_js_wall`, ensure `--no-auto-render` is NOT set, playwright installed |
| `--name "X Y"` finds nothing | `modules/recon/handle_generator.py`, then `_HANDLE_PROBE_PLATFORMS` in engine |
| `--email-only foo@x.com` returns empty | `_phase_email_breach` flag-gating, NVIDIA/HIBP env vars |
| LLM call rejected | `core/analysis/llm.py:HttpBackend`, `CYBERM4FIA_LLM_API_KEY` |
| Skill schema mismatch | `core/analysis/skill_loader.py:_validate_against_schema` |
