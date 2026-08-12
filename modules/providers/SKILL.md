---
name: profile-providers
description: Typed official exact-username adapters with injected credentials and batch lookup.
inputs: platform_name: str, usernames: Sequence[str], credentials: ProviderCredentials
outputs: ProviderBatchResult containing ProviderObservation rows and wire request count
triggers: platform sweep, smart alias search, recursive handle probes
dependencies: core.http_client, core.models, core.platform_loader
ai_required: false
---

## When to use

Use this package for supported exact provider APIs whose auth, batching or
response semantics cannot be represented safely by a generic YAML URL.

## Input contract

Credentials are loaded once into `ScanContext`. Never place them in
`ScanConfig`, `ScanResult`, diagnostics, history or logs. `lookup_many()`
deduplicates usernames and obeys each provider's batch-size limit.
`prepare_provider_credentials()` uses Reddit/Twitch client credentials to mint
fresh short-lived app tokens once per scan. Pre-minted bearer variables remain
supported for backwards compatibility.

## Output contract

Every requested username receives a `ProviderObservation`. Only `FOUND` with a
matching canonical username can become a confirmed `PlatformResult`.
Authentication, quota, schema and transport failures are coverage outcomes.

## Examples

```python
batch = await lookup_many(client, "Twitch", ["alice", "alice_dev"], creds)
assert batch is not None
assert batch.http_request_count <= 1
```

## Failure modes

- Missing credentials: `UNAVAILABLE_AUTH`, zero wire requests.
- 401/403: `UNAVAILABLE_AUTH`; 429: `RATE_LIMITED`.
- 5xx/network failure: `ERROR`.
- Malformed or canonically mismatched success: `CONTRACT_BROKEN`.
- Documented empty/missing result: `NOT_FOUND`.

## Live contract assurance

`scripts/provider_contract_smoke.py` is the only supported live-smoke entrypoint.
It probes a known positive and a generated improbable username, emits no raw
payloads or credentials, and returns non-zero when a configured contract drifts.
Missing optional credentials are reported as skipped; `--require-provider`
turns a missing credential into a hard failure.
