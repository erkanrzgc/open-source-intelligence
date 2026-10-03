---
name: identity-evaluation
description: Offline labelled identity and alias-ranking evaluation with explicit abstentions.
inputs: dataset: dict (identity_pairs and optional alias_discovery)
outputs: report: dict (confusion counts, precision, recall, abstentions, ranks, timings)
triggers: explicit python -m scripts.identity_benchmark
dependencies: core.correlation, core.smart_search
ai_required: false
---

## When to use
Before releasing identity-scoring or alias-ranking changes. Never describe the
bundled synthetic regression set as real-world accuracy or independent validation.

## Input contract
Unique pair IDs, boolean `same_person`, `left`/`right` normalized profile fixtures,
optional `direct_link` representing independently established profile evidence.
Labels must be assigned independently of the scorer. Use synthetic or consented
public data; do not put private contacts or credentials in checked-in fixtures.

## Output contract
Strong predictions are `likely_same` and `confirmed_same`. All other verdicts
abstain; positive-labelled abstentions count as false negatives. No negative
identity claim is implied by `true_negative`. Zero denominators yield null.
Per-case IDs, evidence types and timing make regressions auditable without
dumping profile values. `--check` fails on any false strong match.

## Examples
`python -m scripts.identity_benchmark --check --output reports/identity.json`

## Failure modes
Malformed/empty input raises ValueError. The evaluator performs no network or
LLM calls and does not mutate labels, thresholds, history or scan results.
