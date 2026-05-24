# fp_filter SKILL

(See `modules/fp_filter.py` source for the algorithm. This file
documents the contract.)

---
name: fp_filter
description: Confidence scoring for "is this 200 OK really a profile?"
inputs:
  username: str
  body: str (HTML)
  check_type: str ("status" | "content_absent" | "content_present" | "json_api")
  http_status: int
outputs:
  FPScore: {confidence: float [0-1], signals: tuple[str]}
triggers: invoked from engine._check_platform after every status==200 match.
dependencies: none (pure regex)
ai_required: false
---

## Signals & weights

| Signal | Score | What it checks |
|---|---|---|
| baseline (content_* check_type) | +0.50 | Platform already had a content gate. |
| baseline (status check_type) | +0.30 | No primary signal — we're starting low. |
| `title` | +0.35 | Username appears inside `<title>` tag. |
| `body` | +0.20 | Username appears anywhere in body. |
| `size` | +0.15 | Body ≥ 500 bytes (rules out 404 shells). |
| `canonical` | +0.15 | `<link rel="canonical">` ends with the username. |
| `og_profile` | +0.15 | `og:type=profile` or h-card microformat. |

Max score is clamped to 1.0. The engine then drops matches below
`cfg.fp_threshold` (default 0.45) unless the platform has a hand-curated
deep scraper.

## Why these weights?

The numbers are empirically tuned against a known-handle set across the
top-200 popular platforms. Title-in-username is the single best signal
because real profile pages almost always personalise the `<title>`,
while soft-404 shells use a generic title. Canonical-URL match catches
sites that 200 OK an unknown handle but emit a corrective canonical.

## Adding new signals

Signals that have come up but **deliberately not added**:

* Number of unique words (too noisy, false-positive on SEO-padded shells).
* Image count (browsers render lazily, hard to count from raw HTML).
* JSON-LD Person — this DID get added, but in `profile_liveness.py`,
  not here, because liveness is "is the account real and active",
  whereas fp_filter is "is the URL a profile at all".
