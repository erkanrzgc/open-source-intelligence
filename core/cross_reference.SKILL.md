---
name: cross_reference
description: Identity-scoring across multiple found profiles — "are these the same person?"
inputs:
  found_platforms: list[PlatformResult] with profile_data populated
outputs:
  CrossReferenceResult: {confidence: float [0-100], matched_names, matched_locations, matched_bios, matched_photos, notes}
triggers: engine._finalize_cross_reference (always runs when ≥ 2 deep-scraped profiles exist)
dependencies:
  - utils.helpers.fuzzy_name_match, normalize_name
ai_required: false  # an optional identity_judge skill may augment in future
---

## Scoring rubric (weights sum to 100)

| Signal | Weight | Logic |
|---|---|---|
| name match | 40 | Exact match across ≥ 2 profiles, or fuzzy similarity > 0.70 |
| location match | 30 | Identical location or substring match across ≥ 2 profiles |
| linked accounts | 30 | A profile's `twitter_username` / `github_username` / Keybase proof points to another profile we already found |

Photo matches are added by the engine after `compare_profile_photos`
runs: each match contributes +20 (capped at 100).

## When the score is meaningful

* ≥ 80 → "very likely same person" — multiple independent signals.
* 60–80 → "likely same" — one strong + one weak signal.
* 40–60 → "uncertain" — partial overlap, may be coincidence.
* < 40 → "unlikely" — sparse data; could be different people with the
  same handle pattern.

## Limitations

* Profile data comes from `socid_extractor` and per-site deep scrapers.
  Sites without either contribute nothing.
* Display names are normalised (lower-case, diacritic-fold) but a
  legal-name vs. nickname mismatch still costs the score.
* The optional `cfg.ai_skills` mode will feed borderline matches through
  the `profile_validator` skill — that's per-profile, not aggregate;
  this module remains the aggregate scorer.
