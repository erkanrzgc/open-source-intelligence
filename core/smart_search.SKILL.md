---
name: smart_search
description: Username variation generator and linked-account harvester.
inputs:
  username: str (for generate_variations)
  profile_data: dict (for extract_discoverable_data)
  list[dict] (for merge_discoveries)
outputs:
  generate_variations: list[str]
  extract_discoverable_data: {names, emails, locations, linked_usernames, urls}
  merge_discoveries: same shape, merged across profiles
triggers:
  - cfg.smart=True → engine._phase_smart_search
  - Always indirectly via cfg.recursive (which generates variations to probe)
dependencies:
  - utils.helpers (extract_emails_from_text, extract_urls_from_text)
ai_required: false  # supersedes by the recon/handle_generator + AI handle_generator skill for --name mode
---

## generate_variations rules

* Separator mutations: split on `._-`, rejoin with each.
* Reversed order: `john_doe` → `doe_john`.
* Trim trailing digits: `alice123` → `alice`.
* Strip leading/trailing `_.-`.
* Common suffix decorations: `_`, `0`, `1`, `x`, `official`, `real`, `dev`.
* Common prefix decorations: `_`, `x`, `the`, `real`, `its`.

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

The engine's recursive phase uses `linked_usernames` to find pivot
handles to probe.
