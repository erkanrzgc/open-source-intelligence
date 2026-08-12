---
name: core
description: Scan orchestration, configuration, models, HTTP, identity scoring, reporters.
inputs: ScanConfig (frozen dataclass) — see core/config.py
outputs: ScanResult (mutable dataclass) — see core/models.py
triggers: always — this is the engine.
dependencies:
  - aiohttp, aiohttp-socks (when tor=True)
  - rich (shared exporter/diagnostic console)
  - all modules under modules/* are orchestrated from here
ai_required: false  # individual phases may opt into LLM via core/analysis/skills
---

## Map

```
core/
├── engine.py               # phases + orchestrator (run_scan)
├── context.py              # per-scan cache, LLM budget, progress and tasks
├── config.py               # ScanConfig + env overrides
├── models.py               # PlatformResult, ScanResult, dataclasses
├── verification.py         # deterministic confirmed/uncertain/rejected verdicts
├── security.py             # URL/path validation and output redaction
├── http_client.py          # async HTTP with retry, proxy, rate limit
├── platform_loader.py      # deterministic 100-core / 500-full catalogue
├── cross_reference.py      # name/location/linked-account identity scoring
├── smart_search.py         # ranked alias candidate generator
├── plugins.py              # third-party plugin loader
├── progress.py             # event emitter for live UI
├── reporter/               # CSV, HTML, JSON, PDF, STIX, MISP
├── api/                    # FastAPI server + job queue
├── analysis/               # LLM analyzer + skill registry
├── history.py              # SQLite scan history
├── cases.py                # case management
├── watchlist.py            # watchlist persistence
├── scheduler.py            # periodic scan + notification
├── geo.py                  # Nominatim geocoding
├── bulk.py                 # bulk scan dispatcher
├── search.py               # full-text search across scan history
├── proxy_pool.py           # round-robin proxy rotation with health
├── auth.py                 # API JWT auth
└── investigator_summary.py # rule-based summary fallback
```

## ScanConfig — the single source of truth

Every scan setting is a field on the frozen `ScanConfig` dataclass.
The default scope is the 100-platform core catalogue and smart alias
discovery is enabled. `platform_scope="full"` selects at most 500;
alias fan-out is capped by `alias_max_candidates` and `alias_platform_limit`.
The default adaptive strategy probes 12 candidates on 15 platforms, then
tries candidates 13–24 on 5 platforms only when the first tier has no strong
identity verdict (maximum 240 alias probes).
Adding a new scan-time setting means:

1. Add the field with a sensible default.
2. Map it through `core.api.server.ScanRequest` and `_cfg_from_request`;
   expose it through MCP when required.
3. The engine reads `cfg.<your_field>` — never `os.environ`.

Environment overrides live in `core/config.py` constants
(`MAX_CONCURRENT`, `REQUEST_TIMEOUT`, …). The relevant env names are
listed in the root `AGENTS.md`.

## ScanResult — the single output object

Every phase writes into `ScanResult`. The reporter pulls everything off
of `result.to_dict()`. New result fields require:

1. Add the field to `ScanResult` (with a `default_factory`).
2. Add the corresponding entry in `to_dict()`.
3. Reporter / API / CSV writers pick up the new key automatically if
   they iterate generically; otherwise add per-reporter rendering.

Alias profiles are never appended to root `platforms`; they live under
`identity_candidates` with deterministic verdict, score and evidence.

Supported official endpoints are implemented under `modules/providers/`.
`ScanContext.create()` loads provider credentials once; secrets never enter
`ScanConfig` or results. X and Twitch batch all configured alias candidates,
while diagnostics report logical probes separately from real HTTP requests.

`PlatformResult.probe_outcome` is a typed `ProbeOutcome`, separate from the
legacy `exists` boolean. Every evaluated row also records its evidence class,
entity scope, contract revision, requested/canonical handles, and whether the
provider contract was actually verified. Only an exact canonical match from a
confirmation-capable checked-in contract can set `exists=True`; a URL probe or
non-empty deep parser result alone remains ambiguous.

## HTTPClient contract

```
async with HTTPClient(...) as client:
    status, body, elapsed = await client.get(url, headers)
    status, body, elapsed, final_url = await client.get_with_meta(url, headers)
    status, data, elapsed = await client.get_json(url, headers)
    status, data, elapsed = await client.post_json(url, json_body, headers)
    status, bytes_, elapsed = await client.get_bytes(url, headers)
```

`get_with_meta` returns the post-redirect final URL — used by the
soft-404 detection in `engine._check_platform`.

## Failure modes

* The phase runner records ordinary failures in `ScanResult.diagnostics` and
  continues; `asyncio.CancelledError` always propagates.
* HTTPClient retries `RETRY_COUNT` times; on final failure returns
  `(0, "", elapsed)` for timeout or `(-1, "", elapsed)` for errors.
* Missing provider credentials, rate limits, policy-disabled automation and
  login walls are coverage-loss outcomes, never account absence.
* SimHash / FP scoring failures don't propagate — the match is left in
  place with default confidence.

## Adding a new phase

```python
async def _phase_my_thing(state: _ScanState) -> None:
    # do work and mutate state.result
    ...
```

Register a `PhaseSpec` in `_phase_registry()` in the correct order, including
its `enabled` predicate. The central runner owns timing, progress emission,
failure isolation and diagnostic recording.
