# Platform Endpoint Reliability Research

Date: 2026-08-10

Scope: the 15 platforms used by the identity-first alias phase. This document
compares the checked-in wire contracts with the providers' current official
contracts, then defines the architecture needed to survive endpoint drift.

## Executive decision

The current alias platform list should not be treated as 15 equally reliable
presence checks.

- Four integrations can remain on their current public contract after small
  hardening: GitHub, GitLab, Hugging Face, and Medium.
- Six have a supported migration path, usually requiring credentials: DEV,
  Reddit, X, YouTube, Twitch, and Steam.
- Five do not offer a general-purpose official exact username lookup suitable
  for the current claim: Stack Overflow, Instagram, TikTok, LinkedIn, and
  Telegram.

The most important correction is architectural: the existence of a
`url_probe` or a deep scraper must not grant confirmation authority. A provider
may return `confirmed` only when its adapter declares an official or otherwise
tested exact-lookup contract and its response satisfies that contract.

Until the migrations below land, the existing implementation should be
described as an evidence-first beta, not as a uniformly verified 15-platform
alias resolver.

## Implementation status (2026-08-11)

P0 is implemented in the working tree:

- catalogue rows expose evidence class, entity scope, lookup semantics, auth
  mode, contract revision, documentation URL, and automation state;
- `ProbeOutcome` and canonical-handle validation gate every confirmation;
- a URL probe or non-empty deep scraper can no longer grant trust by itself;
- Stack Overflow, Instagram, TikTok, Telegram, and the current page parsers are
  non-confirming; Reddit is auth-unavailable; LinkedIn, X, and Twitch are
  disabled for default automated lookup;
- the embedded X guest material, Instagram internal probe, and TwitchTracker
  probe were removed; GitHub/GitLab/Hugging Face exact payloads were hardened;
- auth, policy, rate, transport, and schema failures remain coverage outcomes
  rather than account absence.

P1 now includes typed adapters for GitHub, Forem/DEV, Reddit OAuth, X API v2,
YouTube Data API `forHandle`, Twitch Helix, and Steam's official two-step Web
API. Credentials are loaded once into scan context and never serialized. X and
Twitch batch the configured 24-candidate set, and alias diagnostics distinguish
logical probes from wire requests. GitLab, Hugging Face, and Medium retain
their hardened public contracts.

P2 response-header/error-body preservation, provider-aware scheduling,
retention controls, and automated drift monitoring remain the next milestone.

## Current code findings

The present model in `core/platform_loader.py` and `core/engine.py` has four
endpoint-drift hazards:

1. `supports_confirmation()` and `_initial_confirmation_allowed()` treat any
   `url_probe` as deterministic evidence. This gives the same authority to an
   official exact API and to an undocumented or third-party URL.
2. A successful deep scraper is passed to `evaluate_platform(...,
   trusted=True)`. HTML rehydration and internal APIs can therefore become
   trusted merely because a parser returned a non-empty object.
3. `HTTPClient.get_json()` discards response headers and non-200 JSON bodies.
   It cannot expose provider rate-limit resets, `Deprecation`, `Sunset`,
   Stack Exchange `backoff`, or structured 401/403/429 reasons to an adapter.
4. The JSON return type is declared as a mapping even though valid providers,
   notably GitLab, return a top-level array. Contract validation is therefore
   ad hoc rather than typed.

There are also concrete high-risk dependencies in the checked-in catalogue:

- Stack Overflow's `inname` query searches display-name substrings, not unique
  handles.
- X uses an internal GraphQL query hash plus checked-in guest request material.
- Instagram uses an undocumented web endpoint and public web app identifier.
- Twitch confirmation is delegated to the third-party TwitchTracker site.
- Reddit is called without the OAuth identity its current rules require.
- LinkedIn is automatically fetched despite its current user agreement
  prohibiting unauthorized crawlers and profile scraping.

## Core-100 catalogue audit

The endpoint problem is wider than the 15 alias platforms. A static audit of
the checked-in 100-platform core catalogue produced this inventory:

| Signal | Count |
|---|---:|
| Core platforms | 100 |
| `check_type=status` | 87 |
| `check_type=content_absent` | 13 |
| Entries with `url_probe` | 32 |
| Entries with a deep scraper | 15 |
| Entries with a golden fixture | 0 |
| JS-heavy entries | 6 |
| Status checks with no probe and no paired presence/absence markers | 46 |

The 46 weak status-only entries are already prevented from initial
confirmation by the core gate, but they still create network cost and unclear
coverage. More importantly, a non-empty deep scraper can bypass that caution.
The zero golden-fixture count means no core endpoint presently earns trust from
a checked-in positive/negative wire fixture.

Six probes use a different hostname family from the displayed profile. Some
are legitimate first-party services (npm registry and the official Hacker News
Firebase API), but two are semantic substitutions rather than the same account
system: Twitch uses TwitchTracker and Spotify uses stats.fm.

The second-wave endpoint review found additional concrete contract debt:

- Spotify removed the official arbitrary-user `GET /users/{id}` operation in
  February 2026 with no replacement; only the authenticated `/me` profile
  remains. A stats.fm username therefore cannot confirm a Spotify identity.
- The 500px public API was shut down in 2018. The current internal GraphQL URL
  is not a supported replacement.
- Docker's current Hub OpenAPI reference does not document the checked-in
  public `GET /v2/users/{username}/` profile route. It must be heuristic unless
  Docker publishes a replacement contract.
- Dailymotion's current API v2 documents `GET /v2/users/{id}` with bearer scope;
  the catalogue still uses the legacy `/user/{username}` shape.
- Gravatar now publishes a versioned v3 profile endpoint with a documented
  identifier, 404, 429, and OpenAPI contract. The catalogue still uses an
  unencrypted legacy `http://en.gravatar.com/{username}.json` URL.
- Bitbucket's exact endpoint is a workspace lookup. Atlassian explicitly says
  workspaces replace users and teams in API calls, so a success is
  `found_workspace`, not automatically a person profile.
- npm's registry search for `maintainer:{username}` proves that at least one
  package is indexed for that maintainer. It cannot prove that an npm account
  exists when the account has no package, and an empty search is not absence.
- Vimeo's current API uses `/users/{user_id}` and requires an application
  access token even for public data. The checked-in vanity-name call has no
  credential contract.
- Disqus documents public-key/referrer or server-secret authentication. A
  third-party public application key embedded in the catalogue must not be
  reused as project-owned authority.
- Hacker News, Keybase, and MediaWiki have documented exact public lookups and
  are good candidates for the first official-exact provider set. The Hacker
  News API is scoped to accounts with public activity.
- HackerRank, LeetCode, CodeSandbox, HackTheBox, Substack, Kick, Weibo, Imgur,
  and the current 500px query depend on internal, legacy, or incompletely
  documented web contracts. They belong in `heuristic` until an official
  exact adapter and fixtures exist.

This broader audit changes the catalogue roadmap: the first milestone should
not claim “100 verified platforms.” It should expose 100 attempted platforms
plus an explicit count of official-exact, scoped, heuristic, unavailable, and
disabled coverage.

## Provider matrix

| Platform | Current dependency | Official/defensible contract | Required runtime outcome | Action |
|---|---|---|---|---|
| GitHub | `GET api.github.com/users/{username}` | The official user endpoint; `200` user, `404` not found. Public calls work without auth, but the unauthenticated limit is 60/hour versus 5,000/hour with auth. | `found` only when `login` case-folds to the requested handle; `not_found` on documented 404; quota/auth failures are unavailable. | Keep; add the current media type, an explicit API version, optional token, exact field validation, and rate/deprecation headers. |
| GitLab | `GET /api/v4/users?username=` | Official Users API. `username` lookup is case-insensitive and distinct from fuzzy `search`. | `found` only for an exact returned `username`; `not_found` for an empty list. | Keep; validate every returned row and parse rate headers. |
| Hugging Face | `/api/users/{username}/overview` and `/socials` | Both paths are present in the official live OpenAPI document. Hub API and page quotas are separate five-minute buckets. | `found` only when the overview `user` matches; 404 is not found; 429 is rate-limited. | Keep; continuously diff the two paths and consumed fields against the published OpenAPI schema. |
| Stack Overflow | `/2.3/users?...&inname=` | Official API, but `inname` means display-name substring. Stable profile identity is a numeric user ID, not a unique username. | Always `ambiguous` for handle lookup. It can discover possible profiles but cannot prove handle presence or absence. | Remove confirmation authority and exclude from alias candidates unless another source links a specific numeric profile. |
| DEV / Forem | Public `/api/users/by_username?url=` compatibility route with the V1 media type | The generated V1 reference says `GET /api/users/{id}` accepts a username, but DEV production returned 404 for `/users/ben` on 2026-08-11. Forem's current controller resolves usernames only when `id == by_username` and then performs an exact `find_by!(username: params[:url])`; its API policy says V0 routes remain callable with the V1 `Accept` header. | Exact returned username is found; 404 is not found; a mismatched/malformed 200 is contract-broken; 401/403 means unavailable. | Keep the controller-backed compatibility route, pin response fixtures, and monitor the generated V1 schema/runtime mismatch. |
| Reddit | Unauthenticated `/user/{username}/about.json` | Reddit requires registered OAuth clients and an honest, unique User-Agent. Free eligible access is 100 QPM per OAuth client averaged over ten minutes. | Without OAuth: `unavailable_auth`, never absent. With OAuth: exact payload is found; documented missing-user response is not found. | Make the provider credential-gated; honor rate headers and Reddit deletion/retention rules. |
| X | Internal web GraphQL query hash | Official X API v2 supports exact single and batch username lookup; the batch endpoint accepts up to 100 usernames. A bearer token is required. | Without token: unavailable, or at most a separate page heuristic. Official `data` row is found; per-item not-found errors are not found. | Delete the internal GraphQL contract and checked-in guest material; use one batch lookup for the alias set. |
| Instagram | Internal `/api/v1/users/web_profile_info` | Meta's supported Instagram APIs are token-based and aimed at professional business/creator accounts. There is no supported general lookup for arbitrary personal accounts. | Professional API success is scoped `found_professional`; absence there does not prove a personal account is absent. Public page results remain heuristic. | Stop allowing internal endpoint/page data to confirm. Keep only scoped professional support or manual/heuristic evidence. |
| TikTok | Public page rehydration JSON | Display API returns the authorizing user's profile. Arbitrary public-user lookup is available only through the approval-gated Research API and its `research.data.basic` scope. | Research credential missing: unavailable. Research result: found within the API's public 18+ scope. Page parser: heuristic only. | Add an optional Research provider; never turn page failure into absence. |
| LinkedIn | Public profile page status | Open APIs primarily cover the authenticated member; other-member access is restricted. The User Agreement explicitly prohibits unauthorized crawlers/scripts that scrape profiles. | Automated default lookup disabled. A user-supplied link may be retained as external evidence, not independently probed. | Remove from default automated alias fan-out unless an approved LinkedIn agreement/provider is configured. |
| Telegram | `t.me/{username}` HTML | Bot API `getChat` resolves public supergroup/channel usernames, not arbitrary private users. The public preview page is not a documented data contract. | Bot API can return `found_channel`/`found_supergroup`; it cannot establish person-account absence. Page parsing is heuristic with entity type attached. | Split entity types and confirmation scopes; do not present channels as confirmed person profiles. |
| YouTube | `youtube.com/@{username}` HTML metadata | Official Data API `channels.list` supports exact `forHandle`; it returns zero or more channels and costs one quota unit. Default project quota is 10,000 units/day. | Non-empty exact handle result is found; empty list is not found; missing key/403 quota is unavailable. | Prefer the official API and use HTML only as a labelled fallback. |
| Medium | `medium.com/feed/@{username}` | Medium officially documents profile RSS at this URL and the username-subdomain equivalent. | Found only when the feed's canonical/profile identity matches the request; generic or malformed feeds are contract errors. | Keep; add canonical/author validation and fixtures for empty/missing profiles. |
| Twitch | Third-party `twitchtracker.com/{username}` | Official Helix `GET /helix/users?login=` accepts up to 100 login names and requires Client-ID plus an app/user token. Missing users are omitted from `data`. | Returned exact login is found; requested handles omitted from a successful response are not found; missing/invalid token is unavailable. | Replace TwitchTracker and batch all aliases in one Helix call. |
| Steam | Undocumented community profile `?xml=1` | Official Web API provides `ResolveVanityURL/v1`, followed by `GetPlayerSummaries/v2`; an API key is required. | Successful vanity resolution is found; documented no-match is not found; missing key is unavailable. Public XML is heuristic only. | Add the official two-step provider; batch resolved SteamIDs for summaries. |

## Evidence classes

The platform catalogue needs an explicit evidence class. It must not infer
trust from the presence of a URL.

| Class | Meaning | May confirm platform presence? | May establish absence? |
|---|---|---:|---:|
| `official_exact` | Supported API performs an exact lookup for the requested entity and scope. | Yes | Yes, only according to the documented no-result contract. |
| `official_scoped` | Supported API is exact but covers only a subset, such as Instagram professionals, TikTok Research eligibility, or Telegram channels. | Yes, with scope in evidence | No outside that scope |
| `public_contract` | Provider explicitly documents a public feed/page contract, such as Medium RSS. | Yes, after canonical identity validation | Only with tested negative fixtures |
| `page_verified` | Public page has golden positive/negative fixtures but no stable official API. | At most `possible`; it cannot be the sole identity proof | No |
| `heuristic` | Internal API, JS state, search results, third-party service, login wall, or unversioned HTML parser. | No; diagnostics/discovery only | No |
| `disabled` | Terms, scope, or technical behavior make automated probing unsuitable. | No | No |

An exact platform-presence result is still not an identity verdict. A found X,
GitHub, or YouTube handle supplies a profile for correlation; handle similarity
alone remains `uncertain` under the identity rules.

## Typed provider result

The boolean `exists` model is too small for credentialed and rate-limited
providers. Provider adapters should return a typed observation:

```python
class ProbeOutcome(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE_AUTH = "unavailable_auth"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    CONTRACT_BROKEN = "contract_broken"
    ERROR = "error"

@dataclass(frozen=True)
class ProviderObservation:
    provider: str
    requested_username: str
    canonical_username: str | None
    outcome: ProbeOutcome
    evidence_class: str
    entity_scope: str
    profile: dict[str, object]
    http_status: int | None
    contract_revision: str
    checked_at: datetime
    warnings: tuple[str, ...] = ()
```

Only `FOUND` from a confirmation-capable evidence class may enter
`identity_candidates`. `AMBIGUOUS`, `BLOCKED`, and `CONTRACT_BROKEN` belong in
diagnostics. `UNAVAILABLE_AUTH` and `RATE_LIMITED` must never be converted into
negative evidence.

## Provider adapter boundary

Endpoint behavior belongs in typed Python adapters, not only in generic YAML
strings. YAML remains useful for catalogue selection and public profile URL
templates, but each high-value integration should implement this interface:

```python
class ProfileProvider(Protocol):
    key: str
    evidence_class: EvidenceClass
    entity_scope: str
    auth_mode: AuthMode
    batch_size: int
    contract_revision: str

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> Mapping[str, ProviderObservation]: ...
```

This enables X and Twitch to resolve up to 100 handles in one request, while
Steam can resolve vanity names individually and batch the resulting IDs. Alias
diagnostics should record both `logical_probe_count` and
`http_request_count`; the existing 240 logical-probe cap remains unchanged.

Provider credentials should be resolved once at the process/engine adapter
boundary and injected into providers. Secrets must never be stored in
`ScanConfig`, `ScanResult`, history, diagnostics, or reports. Suggested
process-level inputs include GitHub token, Reddit OAuth client, X bearer token,
YouTube key, Twitch client/token, Steam Web API key, and optional TikTok
Research credentials.

## HTTP and rate-limit changes

`HTTPClient` should gain a response object that preserves:

- status, final URL, elapsed time, headers, raw body, and parsed JSON value;
- top-level JSON arrays as well as objects;
- error JSON for non-200 responses;
- `Retry-After`, `RateLimit`, `RateLimit-Policy`, provider-specific reset
  headers, `Deprecation`, `Sunset`, and `Link rel=deprecation`;
- cancellation propagation and the current SSRF/TLS controls.

Rate scheduling must be provider/credential-bucket aware rather than only
host-aware. Important provider-specific behavior includes:

- GitHub primary and secondary limits, including reset headers;
- Reddit `X-Ratelimit-*` headers and its required application identity;
- X and Twitch epoch reset headers;
- Hugging Face `RateLimit` and `RateLimit-Policy` fields;
- Stack Exchange's response-body `backoff`, which must be honored even on a
  successful HTTP response.

The official-API transport should use a stable honest User-Agent. Browser-like
fingerprint rotation is inappropriate for contracts such as Reddit that
explicitly require client identification.

## Drift detection

Endpoint freshness needs three independent controls.

### Offline contract tests on every change

Each provider gets fixtures for:

- exact found result;
- documented not-found result;
- 401/403 missing or insufficient credentials;
- 429/backoff behavior;
- malformed JSON and changed schema;
- a successful response whose canonical username does not match;
- platform-specific partial scope, such as Telegram channel versus person.

Schema drift must fail closed as `contract_broken`, never as found or absent.
Unit and golden tests remain network-free.

### Credentialed live smoke tests

Run an opt-in nightly job, not the ordinary unit suite. For each enabled
provider, query one provider-owned known account and one generated impossible
handle. Limit it to two or three calls per provider. Record only status,
schema fingerprint, latency, contract revision, and redacted failure reason.

A single failure opens a warning; repeated failures should automatically
disable confirmation for that provider until a fixture or contract update is
reviewed. Provider downtime must reduce coverage, not create false absence.

### Specification and lifecycle monitoring

- Weekly-diff Hugging Face's published OpenAPI paths/fields.
- Weekly-diff Forem's published OpenAPI document and Google's YouTube Discovery
  schema for consumed operations.
- Poll official changelog/deprecation pages for GitHub, GitLab, TikTok,
  Twitch, and Stack Exchange.
- Capture standard `Deprecation` and `Sunset` response headers at runtime.
- Store `docs_url`, `contract_revision`, and `last_contract_reviewed` in the
  provider manifest so stale contracts are visible in `GET /platforms`.

RFC 9745 defines the `Deprecation` response header and deprecation link
relation; RFC 8594 defines `Sunset`. These signals are advisory, so alerts
should point to the provider documentation rather than automatically changing
URLs.

## Privacy and terms controls

Operational correctness includes provider terms and data lifecycle, not only
HTTP success.

- Reddit requires deletion of deleted user/account data and recommends routine
  deletion of stored user data within 48 hours. History storage needs a
  provider-aware retention/deletion mechanism before Reddit enrichment is
  enabled by default.
- LinkedIn automated profile crawling should be disabled without explicit
  approved access.
- Instagram and TikTok results must carry their account/research scope so the
  UI cannot imply universal coverage.
- Raw provider responses and tokens must not enter logs, history, or reports.
- A provider becoming unavailable should be shown as coverage loss, not hidden
  behind a lower found count.

## Recommended implementation sequence

### P0: stop false authority

1. Add `evidence_class`, `entity_scope`, `lookup_semantics`, `auth_mode`,
   `contract_revision`, and `docs_url` to the provider/catalogue model.
2. Introduce `ProbeOutcome`; make confirmation depend on evidence class and
   exact canonical-username validation.
3. Demote Stack Overflow, Instagram, TikTok page parsing, Telegram person
   lookup, and unauthenticated X to heuristic/ambiguous.
4. Remove TwitchTracker confirmation and disable LinkedIn automated probing.
5. Gate Reddit behind OAuth. Missing credentials become diagnostics, not
   absence.

### P1: supported providers

1. Harden GitHub headers/version/token, GitLab exact validation, Hugging Face
   schema checks, and Medium canonical feed validation.
2. Keep DEV on Forem's exact `by_username` compatibility route with the V1 media type until the generated V1 username path works in production.
3. Add YouTube `forHandle` and Twitch Helix batch adapters.
4. Add Reddit OAuth, X API v2 batch, and Steam official two-step adapters.
5. Make alias scheduling batch-aware and expose logical versus wire request
   counts.

Reddit and Twitch now prefer client credentials and mint a fresh ephemeral app
token once per scan/live-smoke invocation. Pre-minted bearer tokens remain a
backwards-compatible fallback; auth diagnostics expose only source, outcome,
expiry and request count.

### P2: continuous assurance

1. Preserve headers/error bodies in `HTTPClient` and add provider-aware quota
   parsing.
2. Add offline provider contract suites and golden fixtures.
3. The opt-in live provider matrix and weekly runtime-contract drift workflow
   are implemented in `scripts/provider_contract_smoke.py` and
   `.github/workflows/provider-contract-smoke.yml`; spec/changelog snapshot
   diffing remains separate work.
4. Expose provider availability, contract age, and last smoke status through
   `GET /platforms` and scan diagnostics.
5. Add provider-aware retention and deletion, beginning with Reddit.

## Acceptance criteria

- A URL or non-empty scraper payload alone can never grant confirmation.
- Every confirmed platform profile records provider, evidence class, entity
  scope, contract revision, and canonical username.
- Auth failure, quota exhaustion, login wall, and provider outage cannot become
  `not_found`.
- Stack Overflow display-name matches never become alias presence.
- X and Twitch resolve the 24-candidate set in at most one batch request each
  when credentials are configured.
- YouTube uses exact `forHandle` semantics and distinguishes empty results from
  quota/auth errors.
- LinkedIn makes no automated request in the default scan.
- Offline tests cover all provider outcomes without network access and the full
  suite remains under 120 seconds.
- Live smoke failures fail closed and never alter deterministic identity
  verdict rules.

## Primary sources

- GitHub: [Get a user](https://docs.github.com/en/rest/users/users?apiVersion=2026-03-10#get-a-user), [REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2026-03-10), [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2026-03-10)
- GitLab: [Users API](https://docs.gitlab.com/api/users/), [REST API deprecations](https://docs.gitlab.com/api/rest/deprecations/)
- Hugging Face: [Hub API and OpenAPI](https://huggingface.co/docs/hub/api), [Hub rate limits](https://huggingface.co/docs/hub/main/rate-limits)
- Stack Exchange: [`/users` and `inname`](https://api.stackexchange.com/docs/users), [throttles and `backoff`](https://api.stackexchange.com/docs/throttle)
- Forem: [API version policy](https://developers.forem.com/api/), [V1 reference](https://developers.forem.com/api/v1)
- Reddit: [Data API Wiki](https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki), [Data API Terms](https://redditinc.com/policies/data-api-terms)
- X: [User lookup](https://docs.x.com/x-api/users/lookup/introduction), [batch usernames](https://docs.x.com/x-api/users/get-users-by-usernames), [rate limits](https://docs.x.com/x-api/fundamentals/rate-limits)
- Instagram: [Meta's official Instagram API collection](https://www.postman.com/meta/instagram/documentation/6yqw8pt/instagram-api)
- TikTok: [Display API authorization](https://developers.tiktok.com/doc/display-api-get-started), [Research user lookup](https://developers.tiktok.com/doc/research-api-specs-query-user-info), [Research access FAQ](https://developers.tiktok.com/doc/research-api-faq)
- LinkedIn: [User Agreement](https://www.linkedin.com/legal/user-agreement), [Profile API restrictions](https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/profile-api), [API access](https://learn.microsoft.com/en-us/linkedin/shared/authentication/getting-access)
- Telegram: [Bot API `getChat`](https://core.telegram.org/bots/api#getchat)
- YouTube: [`channels.list` and `forHandle`](https://developers.google.com/youtube/v3/docs/channels/list), [quota policy](https://developers.google.com/youtube/v3/guides/quota_and_compliance_audits)
- Medium: [Official profile RSS formats](https://help.medium.com/hc/en-us/articles/214874118-Using-RSS-feeds-of-profiles-publications-and-topics)
- Twitch: [Helix Get Users](https://dev.twitch.tv/docs/api/reference#get-users), [rate-limit behavior](https://dev.twitch.tv/docs/api/guide)
- Steam: [`ResolveVanityURL` and `GetPlayerSummaries`](https://partner.steamgames.com/doc/webapi/ISteamUser)
- Bluesky: [`app.bsky.actor.getProfile`](https://docs.bsky.app/docs/api/app-bsky-actor-get-profile), [rate limits](https://docs.bsky.app/docs/advanced-guides/rate-limits)
- Bitbucket: [workspace API and entity semantics](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-workspaces/#api-workspaces-workspace-get)
- Spotify: [February 2026 removed user endpoint](https://developer.spotify.com/documentation/web-api/references/changes/february-2026), [migration guide](https://developer.spotify.com/documentation/web-api/tutorials/february-2026-migration-guide)
- Docker Hub: [current API and OpenAPI reference](https://docs.docker.com/reference/api/hub/latest/), [deprecations](https://docs.docker.com/reference/api/hub/deprecated/)
- Dailymotion: [API v2 Get a user](https://developers.dailymotion.com/reference/get-user)
- Vimeo: [API resource identifiers](https://developer.vimeo.com/api/reference), [authentication](https://developer.vimeo.com/api/authentication)
- Gravatar: [v3 profile contract and OpenAPI](https://docs.gravatar.com/profiles/)
- 500px: [official API shutdown notice](https://support.500px.com/hc/en-us/articles/360002435653-API)
- Hacker News: [official Firebase API](https://github.com/HackerNews/API)
- Keybase: [official user lookup](https://keybase.io/docs/api/1.0/call/user/lookup)
- MediaWiki: [Users API](https://www.mediawiki.org/wiki/API:Users)
- Disqus: [API request and key contract](https://disqus.com/api/docs/requests/)
- HTTP lifecycle standards: [RFC 9745 Deprecation](https://www.rfc-editor.org/rfc/rfc9745.html), [RFC 8594 Sunset](https://www.rfc-editor.org/info/rfc8594/)
