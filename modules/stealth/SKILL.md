---
name: stealth
description: Anti-detection helpers — UA rotation, fingerprints, rate limit, Tor, headless browsers, JS-wall detection, soft-404 fingerprints.
inputs: per-helper, see below
outputs: per-helper, see below
triggers:
  - always-on for any HTTP fetch (UA / fingerprint headers)
  - cfg.playwright / cfg.browser_backend
  - cfg.no_auto_render disables the JS-wall fallback path
  - cfg.tor / cfg.new_circuit_every
dependencies:
  - playwright (optional)
  - obscura / camoufox (optional)
  - aiohttp-socks (only when tor=True)
ai_required: false
---

## Components

| File | Role |
|---|---|
| `user_agents.py` | UA pool + selection. Mirrors realistic Chrome/FF/Safari mixes. |
| `fingerprint.py` | Header bundle matching the chosen UA (Sec-CH-UA, Accept-Language, Accept-Encoding). |
| `rate_limit.py` | DomainRateBucket — per-host adaptive throttle, honours `Retry-After`. |
| `tor_control.py` | Tor circuit rotation via ControlPort. |
| `playwright_fallback.py` | Headless Chromium for JS-heavy / login-walled pages. Returns `RenderedPage` with `final_url` and optional `screenshot_path`. |
| `obscura_fallback.py` | Camoufox-based alternative renderer (better stealth profile for some CDNs). |
| `js_wall.py` | Detects Cloudflare challenges / DataDome / empty SPA shells — triggers auto-fallback to a browser. |
| `soft_404.py` | SimHash baselines per platform; flags responses that look like the platform's "user not found" template. |

## When to use

* The engine always uses `user_agents` and `fingerprint` via
  `HTTPClient`.
* `playwright_fallback` / `obscura_fallback` only run when:
  - the platform is flagged `js_heavy: true` in `modules/platforms.yaml`, OR
  - `cfg.playwright` is true (renders everything), OR
  - `js_wall.looks_like_js_wall(...)` says the aiohttp body is a wall.
* `soft_404` runs after every status-type platform match.

## Output contract

```
playwright_fallback.fetch_rendered(url, *, user_agent, wait_for_selector,
                                   timeout_ms, proxy, screenshot_dir,
                                   screenshot_name)
    -> RenderedPage | None  # None means "fallback unavailable"

js_wall.looks_like_js_wall(body, headers, status)
    -> tuple[bool, str | None]  # (is_wall, reason)

soft_404.make_baseline(*, platform, status, body, probe_username)
    -> Soft404Baseline
soft_404.is_soft_404(*, platform, status, body, real_username, baseline)
    -> tuple[bool, str | None]
```

## Failure modes

* Playwright not installed → `AVAILABLE=False`, fetch_rendered returns
  None; engine carries on with the aiohttp body.
* Camoufox not installed → same pattern, isolated to obscura backend.
* Tor not running → SOCKS connect fails fast; engine logs and continues
  in clear-net mode (if no proxy is required).
* Soft-404 cache dir unwritable → in-memory only, no persistence.
