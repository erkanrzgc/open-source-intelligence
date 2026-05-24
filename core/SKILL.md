---
name: core
description: Scan orchestration, configuration, models, HTTP, identity scoring, reporters.
inputs: ScanConfig (frozen dataclass) — see core/config.py
outputs: ScanResult (mutable dataclass) — see core/models.py
triggers: always — this is the engine.
dependencies:
  - aiohttp, aiohttp-socks (when tor=True)
  - rich (console reporter)
  - all modules under modules/* are orchestrated from here
ai_required: false  # individual phases may opt into LLM via core/analysis/skills
---

## Map

```
core/
├── engine.py               # phases + orchestrator (run_scan)
├── config.py               # ScanConfig + env overrides
├── models.py               # PlatformResult, ScanResult, dataclasses
├── http_client.py          # async HTTP with retry, proxy, rate limit
├── platform_loader.py      # parses modules/platforms.yaml
├── cross_reference.py      # name/location/linked-account identity scoring
├── smart_search.py         # username variation generator
├── plugins.py              # third-party plugin loader
├── progress.py             # event emitter for live UI
├── reporter/               # console UI, CSV, HTML
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
Adding a new scan-time flag means:

1. Add the field with a sensible default.
2. Wire `ScanConfig.from_args()` to read the argparse Namespace.
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

* Engine phases never raise. They catch broadly and log at debug/warning.
* HTTPClient retries `RETRY_COUNT` times; on final failure returns
  `(0, "", elapsed)` for timeout or `(-1, "", elapsed)` for errors.
* SimHash / FP scoring failures don't propagate — the match is left in
  place with default confidence.

## Adding a new phase

```python
async def _phase_my_thing(client: HTTPClient, cfg: ScanConfig, result: ScanResult) -> None:
    if not cfg.my_thing_enabled:
        return
    try:
        # do work, mutate result.* fields
        ...
    except Exception as exc:  # noqa: BLE001 — phases must not raise
        log.debug("my_thing failed: %s", exc)
```

Append the call inside `run_scan()` in the correct order. Emit
`phase_start` / `phase_end` events so the live UI tracks it.
