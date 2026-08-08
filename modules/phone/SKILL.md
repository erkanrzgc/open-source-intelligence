---
name: phone
description: Phone-number metadata extraction (offline phonenumbers + NumVerify).
inputs:
  raw: str (E.164 or any reasonable phone format)
  default_region: str (e.g. "TR", "US"; ISO 3166-1 alpha-2)
outputs:
  PhoneIntel: {e164, national, country_code, country_name, region, carrier, line_type, timezones, valid, possible, sources, metadata}
triggers:
  - cfg.phone non-empty in ScanConfig
dependencies:
  - phonenumbers package
  - NUMVERIFY_API_KEY env (optional; offline metadata works without it)
ai_required: false
---

## When to use

When the user supplies a phone number alongside (or instead of) a
username. Offline parse is always available; NumVerify enrichment kicks
in when the API key is set.

## Input contract

```
modules.phone.lookup_phone(client, raw, default_region) -> PhoneIntel | None
```

Returns `None` if the input is completely unparseable.

## Output contract

`PhoneIntel` is a dataclass with `to_dict()`. Fields:

* `valid`: passed E.164 + region validation
* `possible`: looser sanity check (right number of digits)
* `sources`: which modules contributed data (`["phonenumbers"]` or
  `["phonenumbers", "numverify"]`)
* `metadata.location`: NumVerify-supplied city/region string

## Failure modes

* NumVerify auth fails → silently fall back to offline-only result.
* Region detection fails → returns offline result without country
  enrichment; `possible=True`, `valid=False`.

## What this module deliberately does NOT do

* No Truecaller scraping (ToS violation, also unreliable).
* No SMS verification (out of scope for OSINT).
* No reverse lookup to person — that would require a social-pivot pass
  the engine doesn't currently implement.
