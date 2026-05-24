---
name: profile_liveness
description: Score how "alive" a profile looks — distinguishes real accounts from reserved empty shells.
inputs:
  username: str
  body: str (HTML, optional)
  profile_data: dict (extracted via socid_extractor / deep scrapers)
outputs:
  LivenessScore: {score: float [0-1], signals: tuple[str], is_active: bool}
triggers: engine._check_platform calls it on every found platform.
dependencies: none (pure regex + dict introspection)
ai_required: false
---

## Signals & weights

| Signal | Score | Source |
|---|---|---|
| avatar | +0.30 | profile_data avatar URL OR `<img class="avatar">` not on the default-fingerprint denylist |
| bio | +0.25 | bio / description / about text > 5 chars |
| og_title | +0.20 | og:title or twitter:title contains username |
| jsonld_person | +0.15 | schema.org/Person JSON-LD block |
| activity | +0.10 | follower / posts / karma counter > 0 |

`is_active` is True when score ≥ `LIVENESS_THRESHOLD` (0.40).

## Default-avatar denylist

Includes Twitter egg/default, GitHub identicon, Gravatar mystery person,
common `/default-avatar`, `/no-profile-image`, `/blank-avatar` patterns.
Extend `_DEFAULT_AVATAR_PATTERNS` when you find a new placeholder.

## Engine integration

Engine drops confidence by 0.25 (status check_type) or 0.15 (content
check_type) when liveness < 0.40. Liveness signals are appended to
`PlatformResult.fp_signals` for transparency.

## What this does NOT do

* Doesn't reach out to the avatar URL to inspect bytes — that would
  add latency to every match. We trust the URL pattern.
* Doesn't try to detect bot accounts (very hard heuristically).
* Doesn't validate identity — that's `profile_validator` skill's job.
