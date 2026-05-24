---
name: soft_404
description: Per-platform "user not found" template fingerprint cache. Detects 200-OK soft-404s.
inputs:
  platform: str
  status: int
  body: str
  real_username: str
  baseline: Soft404Baseline | None
outputs:
  is_soft_404: tuple[bool, str | None]  # (verdict, signal name)
triggers: engine._check_platform calls it for every status check_type platform with a positive match.
dependencies: none (pure stdlib — hashlib.blake2b, regex)
ai_required: false
---

## Algorithm

1. `_normalise(body, probe_username)` strips comments, scripts, styles,
   CSRF tokens, nonces, long hex IDs, ISO/epoch timestamps, the probe
   username string, and collapses whitespace.
2. `_simhash(text)` computes a 64-bit SimHash over 4-character n-grams.
   Each n-gram's blake2b hash contributes a weighted vote to each of
   the 64 bits.
3. Comparison: Hamming distance ≤ 6 → soft-404. (Threshold tuned for
   typical CDN-cached template variation.)

## Baseline lifecycle

* Empty cache on first run.
* When engine finds a status-only platform with no cached baseline, it
  fires off `_seed_soft_404_baseline(...)` as a background task (not
  awaited during the scan; awaited at scan end with 5 s timeout).
* The seed task fetches the URL with `IMPOSSIBLE_USERNAME` and stores
  the fingerprint to `~/.cache/cyberm4fia/soft404/<slug>.json`.
* Baselines expire after 7 days (`_BASELINE_TTL_SECONDS`).

## False positives we accept

* Some platforms (e.g. very lightweight 404 pages with no template)
  may match real profiles by accident. Mitigated by the body-length
  short-circuit: if real body is > 2× baseline length, we don't even
  hash it.
* HTTP status mismatch (baseline=200, real=404) short-circuits before
  hashing.

## What this does NOT detect

* JS-walled pages where the soft-404 is rendered client-side. Those
  are caught by `js_wall.looks_like_js_wall(...)` instead, which
  triggers a Playwright re-fetch.
* Personalised 404 pages (e.g. "User <X> doesn't exist" — the
  username gets normalised out, but the surrounding template still
  matches).
