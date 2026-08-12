---
name: smart-search
description: Ranked alias candidate generator and linked-account harvester.
inputs:
  username: str (for generate_candidates / generate_variations)
  linked_usernames: Iterable[str]
  profile_data: dict (for extract_discoverable_data)
  list[dict] (for merge_discoveries)
outputs:
  generate_candidates: list[UsernameCandidate]
  generate_variations: list[str]
  extract_discoverable_data: {names, emails, locations, linked_usernames, urls}
  merge_discoveries: same shape, merged across profiles
triggers:
  - cfg.smart=True → engine._phase_smart_search
  - Always indirectly via cfg.recursive (which generates variations to probe)
dependencies:
  - utils.helpers (extract_emails_from_text, extract_urls_from_text)
ai_required: false  # augmented by the handle-generator module and skill when cfg.full_name is set
---

## Candidate ranking

`generate_candidates` emits at most the requested limit, ordered by:

1. Direct profile-linked handles.
2. Last-character repeat/removal.
3. One deletion or adjacent transposition.
4. Separator mutations.
5. Short numeric suffix mutations.
6. One leet substitution.
7. Limited `real`, `official`, `dev` affixes.

Each row carries Damerau-Levenshtein similarity, source confidence and
auditable reason codes. `generate_variations` is the sorted legacy string view.

## What this is NOT

This module is **not** the name → handle pipeline. For real-name input
(e.g. "Erkan Rizgic"), the dedicated `modules/recon/handle_generator.py`
applies diacritic folding + cultural permutation rules and emits ranked
`HandleCandidate` objects. `smart_search` operates on a handle that
already exists, generating variations of THAT handle.

## extract_discoverable_data

Reads structured fields out of profile dicts:

* names: `name`, `full_name`, `persona_name`, `real_name`, `first_name`+`last_name`
* emails: `email` + any emails found in bio text
* locations: `location`, `country`
* linked_usernames: `twitter_username`, `github_username`, Keybase proofs
* urls: `blog`, `website_url`, `web_url`, `links` + URLs in bio text

The engine probes the first 12 candidates across the 15 catalogued
`alias_probe` platforms. If that tier produces no `likely_same` or
`confirmed_same` verdict, candidates 13–24 are probed on the first 5
alias platforms. The adaptive fan-out is capped at 240 profile probes.
Confirmed profiles become `identity_candidates`; transport/login/soft-404
uncertainty stays in diagnostics.

Confirmation is fail-closed against the provider catalogue contract. The
platform must declare an official/public exact lookup and the returned
canonical username must match the probed candidate. Search results, internal
APIs, third-party probes, page hydration parsers and disabled/auth-gated
providers cannot create an identity candidate.
