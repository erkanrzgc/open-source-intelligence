---
name: case-investigation
description: Case-scoped evidence graphs, snapshot timelines and explicitly authorized public-profile pivots.
inputs: case_id: int; case-linked HistoryEntry snapshots; analyst review or lead selection
outputs: graph: Cytoscape elements; timeline: events; leads: bounded proposals; pivots: durable reservations
triggers: GET /cases/{id}/workbench; PUT edge review; POST case pivot
dependencies: core.cases, core.history, core.config, core.smart_search, core.api.jobs
ai_required: false
---

## When to use
Use the workbench to investigate existing, explicitly case-linked scans. Reading
the workbench never starts a scan. Query nodes are not proven identities.

## Input contract
At most 200 distinct linked snapshots per view. Platform observations carry
URL, scan ID, checked_at, HTTP status, provider contract and reason codes.
Legacy missing timestamps stay null. Names alone never merge profile nodes.
Analyst decisions belong to the case edge and never change deterministic verdicts.

## Output contract
Graph edges retain individual observations. Timeline compares confirmed profile
metadata, reports explicit NOT_FOUND as absence_observed and access loss as
coverage_lost. Omitted platforms never imply account deletion. At most 100 lead
proposals are exposed; truncated views are labelled.

## Examples
GET `/cases/1/workbench`; inspect an edge, optionally review it, then POST
`/cases/1/pivots` with a returned lead_id, allowed platforms and request_budget.

## Pivot bounds
Only GitHub, GitLab, Dev.to, Hacker News, Keybase and Bluesky exact providers.
ScanConfig disables smart, recursive, deep, browser and enrichment phases.
Each lead needs a separate explicit action. Max depth 2; max 10 pivots and
120 reserved HTTP attempts per case; max 20 attempts per pivot. Concurrent
reservations are transactional and duplicate usernames cannot be requeued.
Central HTTPClient counts retries and disables redirects and secondary TLS
fallback when a request cap is active. The cap is on HTTPClient attempts, not
arbitrary optional modules; pivots deliberately enable none of those modules.

## Failure modes
Missing linked scans and truncation generate warnings. Missing in-memory jobs
after restart appear interrupted and are never auto-replayed. Accepted jobs
retain their reservations on error/cancellation; only queue admission failures
release an unstarted reservation. The case must be open for a new pivot.
No private contacts, domain probing, geolocation or automatic recursive
collection is added by this workflow. Those require a separate explicit scope.
