---
name: recon
description: Corporate red-team & target-aware reconnaissance modules.
inputs:
  domain: str
  github_org: str
  names_file: str (optional newline-delimited list of employee names)
outputs:
  email_candidates: list[EmailCandidate]
  github_committers: list[GithubCommitter]
  recon_subdomains: list[ReconSubdomain]
  leaked_secrets: list[LeakedSecret]
  document_metadata: list[DocumentMetadata]
  crtsh_hits: list[dict]
  filetype_hits: list[dict]
triggers:
  - cfg.redteam_domain
  - cfg.gitleaks_paths
  - cfg.harvest_doc_urls
dependencies:
  - core.http_client
  - modules.dns_lookup (subdomain enrichment)
  - modules.recon.handle_generator (used by engine, not by recon itself)
ai_required: false
---

## When to use

Activates for corporate / domain-scoped scans. Pure-username scans skip
this entire sub-tree. Email pattern generation requires `cfg.redteam_names_file`;
GitHub org enumeration only needs the org name.

## Input contract

Each sub-module exposes a single async entry function:

```
email_patterns.generate_bulk(names: list[str], domain: str) -> list[EmailCandidate]
github_org.scan_org(client, org: str) -> list[GithubCommitter]
github_secrets.scan_target(client, org: str, domain: str) -> list[LeakedSecret]
subdomains_extra.enrich_subdomains(client, domain: str, existing: list[str]) -> list[ReconSubdomain]
doc_metadata.extract_batch(client, urls: list[str]) -> list[DocumentMetadata]
gitleaks.scan_path(path: str, no_git: bool, timeout: int) -> list[LeakedSecret]
crtsh.search(client, domain: str) -> list[dict]
filetype.detect(client, url: str) -> dict
handle_generator.generate(name: str, year: int | None) -> list[HandleCandidate]
```

## Output contract

All recon sub-modules return dataclasses with `to_dict()` so the engine
can serialise them into `ScanResult` without bespoke handling.

## Failure modes

* External APIs unreachable → return empty list, no exception.
* Gitleaks binary missing → log debug, return empty list. Do NOT raise.
* Document download fails → that document is skipped, others continue.

## Examples

See `tests/test_recon_email_patterns.py`, `tests/test_recon_github_org.py`,
`tests/test_recon_doc_metadata.py`, `tests/test_handle_generator.py`.
