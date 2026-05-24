---
name: modules
description: Index — per-module SKILL.md entries.
inputs: see individual SKILL.md files
outputs: see individual SKILL.md files
triggers: orchestrated by core/engine.py
dependencies: each module is independently optional
ai_required: false
---

## Module index

| Module | Subject | SKILL.md |
|---|---|---|
| `recon/` | Corporate red-team recon + handle generation | `recon/SKILL.md` |
| `passive/` | Third-party intel sources | `passive/SKILL.md` |
| `phone/` | Phone metadata extraction | `phone/SKILL.md` |
| `stealth/` | Anti-detection, browser fallback, soft-404, JS-wall | `stealth/SKILL.md` |
| `crypto/` | BTC/ETH balance + tx lookup | (see code) |
| `analysis/` | Image EXIF, stylometry, enrichment | (see code) |
| `reverse_image/` | Reverse image search | (see code) |
| `history/` | Wayback CDX historical username discovery | (see code) |
| `se_arsenal/` | Social engineering (pretext, gophish, lookalike) | (see code) |

## Flat-file modules

These live directly under `modules/` and have public functions called
by `core/engine.py`:

| File | Purpose |
|---|---|
| `platforms.py` / `platforms.yaml` | Platform registry (1924 sites) |
| `web_presence.py` | Wayback snapshots + paste sites |
| `dns_lookup.py` | DNS records + subdomain enumeration |
| `email_discovery.py` | Email candidates + Gravatar |
| `breach_check.py` | HIBP + XposedOrNot |
| `comb_leaks.py` | COMB leak search |
| `holehe_check.py` | ~120-site email account check |
| `ghunt_lookup.py` | Google account resolution from email |
| `toutatis_lookup.py` | Instagram OSINT lookup |
| `whois_lookup.py` | WHOIS for username-as-domain |
| `photo_compare.py` | Perceptual-hash avatar comparison |
| `profile_extract.py` | socid_extractor wrapper |
| `profile_liveness.py` | Active-profile scoring (avatar/bio/og/jsonld) |
| `fp_filter.py` | False-positive confidence scoring |
| `deep_scrapers.py` | Hand-curated deep-profile scrapers (~12 sites) |

## Module-author checklist

1. Single public entry function, typed signature.
2. Returns a dataclass with `to_dict()` (or `None` for "skip me").
3. NEVER raises in the public entry — log and return empty.
4. Optional dependencies are import-guarded with a module-level
   `_AVAILABLE = bool`.
5. Add a SKILL.md when the module's contract isn't obvious from the
   function signature.
6. Tests in `tests/test_<module>.py`.

## Importing in engine

The engine imports modules lazily inside the phase function when the
module is opt-in (e.g. `if cfg.passive: from modules.passive import run_passive`).
Top-of-file imports are reserved for always-on modules.
