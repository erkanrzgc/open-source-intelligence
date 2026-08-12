"""Official and documented exact-username provider adapters."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from urllib.parse import quote, urlencode

from core.http_client import HTTPClient
from core.models import ProbeOutcome
from modules.providers.models import (
    ProviderBatchResult,
    ProviderCredentials,
    ProviderObservation,
)


class ProfileProvider(Protocol):
    platform_name: str
    evidence_class: str
    entity_scope: str
    contract_revision: str
    batch_size: int

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult: ...


def _observation(
    provider: ProfileProvider,
    username: str,
    outcome: ProbeOutcome,
    *,
    canonical: str | None = None,
    profile: dict[str, object] | None = None,
    status: int | None = None,
    warnings: tuple[str, ...] = (),
) -> ProviderObservation:
    return ProviderObservation(
        provider=provider.platform_name,
        requested_username=username,
        canonical_username=canonical,
        outcome=outcome,
        evidence_class=provider.evidence_class,
        entity_scope=provider.entity_scope,
        profile=profile or {},
        http_status=status,
        contract_revision=provider.contract_revision,
        warnings=warnings,
    )


def _transport_outcome(status: int) -> ProbeOutcome | None:
    if status in (401, 403):
        return ProbeOutcome.UNAVAILABLE_AUTH
    if status == 429:
        return ProbeOutcome.RATE_LIMITED
    if status in (0, -1) or status >= 500:
        return ProbeOutcome.ERROR
    return None


def _missing_credentials(
    provider: ProfileProvider, usernames: Sequence[str]
) -> ProviderBatchResult:
    return ProviderBatchResult(
        {
            username: _observation(
                provider,
                username,
                ProbeOutcome.UNAVAILABLE_AUTH,
                warnings=("provider_credentials_missing",),
            )
            for username in usernames
        }
    )


class ForemProvider:
    platform_name = "Dev.to"
    evidence_class = "official_exact"
    entity_scope = "person_or_org"
    # Forem's current controller still resolves public usernames through the
    # documented compatibility route (`id=by_username`, `url=<username>`).
    # `/api/users/<username>` is described by the generated V1 reference but
    # DEV production and the controller's non-compatibility branch treat the
    # path value as a numeric database id.
    contract_revision = "forem-v1-compat-by-username-2026-08"
    batch_size = 1

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        observations: dict[str, ProviderObservation] = {}
        request_count = 0
        headers = {"Accept": "application/vnd.forem.api-v1+json"}
        if credentials.forem_api_key:
            headers["api-key"] = credentials.forem_api_key
        for username in usernames:
            query = urlencode({"url": username})
            status, data, _ = await client.get_json(
                f"https://dev.to/api/users/by_username?{query}", headers
            )
            request_count += 1
            transport = _transport_outcome(status)
            if transport is not None:
                observations[username] = _observation(
                    self, username, transport, status=status
                )
            elif status == 404:
                observations[username] = _observation(
                    self, username, ProbeOutcome.NOT_FOUND, status=status
                )
            elif status != 200 or not isinstance(data, dict):
                observations[username] = _observation(
                    self, username, ProbeOutcome.CONTRACT_BROKEN, status=status
                )
            else:
                canonical = data.get("username")
                canonical = canonical if isinstance(canonical, str) else None
                outcome = (
                    ProbeOutcome.FOUND
                    if canonical and canonical.casefold() == username.casefold()
                    else ProbeOutcome.CONTRACT_BROKEN
                )
                observations[username] = _observation(
                    self,
                    username,
                    outcome,
                    canonical=canonical,
                    profile=dict(data),
                    status=status,
                )
        return ProviderBatchResult(observations, request_count)


class GitHubProvider:
    platform_name = "GitHub"
    evidence_class = "official_exact"
    entity_scope = "person_or_org"
    contract_revision = "github-rest-2026-03-10"
    batch_size = 1

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if credentials.github_token:
            headers["Authorization"] = f"Bearer {credentials.github_token}"
        observations: dict[str, ProviderObservation] = {}
        request_count = 0
        for username in usernames:
            status, data, _ = await client.get_json(
                f"https://api.github.com/users/{quote(username, safe='')}", headers
            )
            request_count += 1
            transport = _transport_outcome(status)
            profile: dict[str, object]
            if transport is not None:
                outcome = transport
                canonical = None
                profile = {}
            elif status == 404:
                outcome = ProbeOutcome.NOT_FOUND
                canonical = None
                profile = {}
            elif status == 200 and isinstance(data, dict):
                profile = dict(data)
                raw = profile.get("login")
                canonical = raw if isinstance(raw, str) else None
                outcome = (
                    ProbeOutcome.FOUND
                    if canonical and canonical.casefold() == username.casefold()
                    else ProbeOutcome.CONTRACT_BROKEN
                )
                if canonical:
                    profile.setdefault("username", canonical)
            else:
                outcome = ProbeOutcome.CONTRACT_BROKEN
                canonical = None
                profile = {}
            observations[username] = _observation(
                self,
                username,
                outcome,
                canonical=canonical,
                profile=profile,
                status=status,
            )
        return ProviderBatchResult(observations, request_count)


class RedditProvider:
    platform_name = "Reddit"
    evidence_class = "official_exact"
    entity_scope = "person"
    contract_revision = "reddit-oauth-2026-08"
    batch_size = 1

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        if not credentials.reddit_bearer_token or not credentials.reddit_user_agent:
            return _missing_credentials(self, usernames)
        headers = {
            "Authorization": f"Bearer {credentials.reddit_bearer_token}",
            "User-Agent": credentials.reddit_user_agent,
        }
        observations: dict[str, ProviderObservation] = {}
        request_count = 0
        for username in usernames:
            status, data, _ = await client.get_json(
                f"https://oauth.reddit.com/user/{quote(username, safe='')}/about",
                headers,
            )
            request_count += 1
            transport = _transport_outcome(status)
            if transport is not None:
                outcome = transport
                canonical = None
                profile: dict[str, object] = {}
            elif status == 404:
                outcome = ProbeOutcome.NOT_FOUND
                canonical = None
                profile = {}
            elif status == 200 and isinstance(data, dict) and isinstance(data.get("data"), dict):
                profile = dict(data["data"])
                raw = profile.get("name")
                canonical = raw if isinstance(raw, str) else None
                outcome = (
                    ProbeOutcome.FOUND
                    if canonical and canonical.casefold() == username.casefold()
                    else ProbeOutcome.CONTRACT_BROKEN
                )
            else:
                outcome = ProbeOutcome.CONTRACT_BROKEN
                canonical = None
                profile = {}
            observations[username] = _observation(
                self,
                username,
                outcome,
                canonical=canonical,
                profile=profile,
                status=status,
            )
        return ProviderBatchResult(observations, request_count)


class XProvider:
    platform_name = "X"
    evidence_class = "official_exact"
    entity_scope = "person_or_org"
    contract_revision = "x-api-v2-2026-08"
    batch_size = 100

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        if not credentials.x_bearer_token:
            return _missing_credentials(self, usernames)
        query = urlencode(
            {
                "usernames": ",".join(usernames),
                "user.fields": "created_at,description,location,profile_image_url,verified,url",
            }
        )
        status, data, _ = await client.get_json(
            f"https://api.x.com/2/users/by?{query}",
            {"Authorization": f"Bearer {credentials.x_bearer_token}"},
        )
        transport = _transport_outcome(status)
        if transport is not None:
            return ProviderBatchResult(
                {
                    username: _observation(self, username, transport, status=status)
                    for username in usernames
                },
                1,
            )
        if status != 200 or not isinstance(data, dict):
            return ProviderBatchResult(
                {
                    username: _observation(
                        self, username, ProbeOutcome.CONTRACT_BROKEN, status=status
                    )
                    for username in usernames
                },
                1,
            )
        rows = data.get("data", [])
        errors = data.get("errors", [])
        if (
            not ({"data", "errors"} & data.keys())
            or not isinstance(rows, list)
            or not isinstance(errors, list)
        ):
            rows = []
            schema_broken = True
        else:
            schema_broken = False
        exact: dict[str, dict[str, object]] = {}
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("username"), str):
                exact[str(row["username"]).casefold()] = dict(row)
        observations = {}
        for username in usernames:
            profile = exact.get(username.casefold())
            outcome = (
                ProbeOutcome.CONTRACT_BROKEN
                if schema_broken
                else ProbeOutcome.FOUND
                if profile is not None
                else ProbeOutcome.NOT_FOUND
            )
            observations[username] = _observation(
                self,
                username,
                outcome,
                canonical=(str(profile["username"]) if profile else None),
                profile=profile,
                status=status,
            )
        return ProviderBatchResult(observations, 1)


class YouTubeProvider:
    platform_name = "YouTube"
    evidence_class = "official_exact"
    entity_scope = "channel"
    contract_revision = "youtube-data-v3-2026-08"
    batch_size = 1

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        if not credentials.youtube_api_key:
            return _missing_credentials(self, usernames)
        observations: dict[str, ProviderObservation] = {}
        request_count = 0
        for username in usernames:
            query = urlencode(
                {
                    "part": "id,snippet,statistics",
                    "forHandle": username,
                    "key": credentials.youtube_api_key,
                }
            )
            status, data, _ = await client.get_json(
                f"https://www.googleapis.com/youtube/v3/channels?{query}"
            )
            request_count += 1
            transport = _transport_outcome(status)
            if transport is not None:
                outcome = transport
                profile = None
            elif status == 200 and isinstance(data, dict) and isinstance(data.get("items"), list):
                items = data["items"]
                profile = dict(items[0]) if items and isinstance(items[0], dict) else None
                outcome = ProbeOutcome.FOUND if profile else ProbeOutcome.NOT_FOUND
            else:
                outcome = ProbeOutcome.CONTRACT_BROKEN
                profile = None
            observations[username] = _observation(
                self,
                username,
                outcome,
                canonical=username if outcome == ProbeOutcome.FOUND else None,
                profile=profile,
                status=status,
            )
        return ProviderBatchResult(observations, request_count)


class TwitchProvider:
    platform_name = "Twitch"
    evidence_class = "official_exact"
    entity_scope = "person_or_org"
    contract_revision = "twitch-helix-2026-08"
    batch_size = 100

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        if not credentials.twitch_client_id or not credentials.twitch_access_token:
            return _missing_credentials(self, usernames)
        query = urlencode([("login", username) for username in usernames])
        status, data, _ = await client.get_json(
            f"https://api.twitch.tv/helix/users?{query}",
            {
                "Authorization": f"Bearer {credentials.twitch_access_token}",
                "Client-Id": credentials.twitch_client_id,
            },
        )
        transport = _transport_outcome(status)
        if transport is not None:
            return ProviderBatchResult(
                {
                    username: _observation(self, username, transport, status=status)
                    for username in usernames
                },
                1,
            )
        if status != 200 or not isinstance(data, dict) or not isinstance(data.get("data"), list):
            return ProviderBatchResult(
                {
                    username: _observation(
                        self, username, ProbeOutcome.CONTRACT_BROKEN, status=status
                    )
                    for username in usernames
                },
                1,
            )
        exact = {
            str(row["login"]).casefold(): dict(row)
            for row in data["data"]
            if isinstance(row, dict) and isinstance(row.get("login"), str)
        }
        observations = {}
        for username in usernames:
            profile = exact.get(username.casefold())
            observations[username] = _observation(
                self,
                username,
                ProbeOutcome.FOUND if profile else ProbeOutcome.NOT_FOUND,
                canonical=str(profile["login"]) if profile else None,
                profile=profile,
                status=status,
            )
        return ProviderBatchResult(observations, 1)


class SteamProvider:
    platform_name = "Steam"
    evidence_class = "official_exact"
    entity_scope = "person"
    contract_revision = "steam-web-api-2026-08"
    batch_size = 100

    async def lookup_many(
        self,
        client: HTTPClient,
        usernames: Sequence[str],
        credentials: ProviderCredentials,
    ) -> ProviderBatchResult:
        if not credentials.steam_api_key:
            return _missing_credentials(self, usernames)
        observations: dict[str, ProviderObservation] = {}
        steam_ids: dict[str, str] = {}
        request_count = 0
        for username in usernames:
            query = urlencode(
                {"key": credentials.steam_api_key, "vanityurl": username}
            )
            status, data, _ = await client.get_json(
                "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/"
                f"?{query}"
            )
            request_count += 1
            transport = _transport_outcome(status)
            response = data.get("response") if isinstance(data, dict) else None
            if transport is not None:
                observations[username] = _observation(
                    self, username, transport, status=status
                )
            elif status != 200 or not isinstance(response, dict):
                observations[username] = _observation(
                    self, username, ProbeOutcome.CONTRACT_BROKEN, status=status
                )
            elif response.get("success") == 1 and isinstance(response.get("steamid"), str):
                steam_ids[username] = str(response["steamid"])
            elif response.get("success") == 42:
                observations[username] = _observation(
                    self, username, ProbeOutcome.NOT_FOUND, status=status
                )
            else:
                observations[username] = _observation(
                    self, username, ProbeOutcome.CONTRACT_BROKEN, status=status
                )
        if not steam_ids:
            return ProviderBatchResult(observations, request_count)

        query = urlencode(
            {
                "key": credentials.steam_api_key,
                "steamids": ",".join(steam_ids.values()),
            }
        )
        status, data, _ = await client.get_json(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
            f"?{query}"
        )
        request_count += 1
        transport = _transport_outcome(status)
        response = data.get("response") if isinstance(data, dict) else None
        players = response.get("players") if isinstance(response, dict) else None
        by_id = {
            str(row["steamid"]): dict(row)
            for row in players or []
            if isinstance(row, dict) and isinstance(row.get("steamid"), str)
        }
        for username, steam_id in steam_ids.items():
            profile = by_id.get(steam_id)
            outcome = (
                transport
                if transport is not None
                else ProbeOutcome.FOUND
                if profile is not None
                else ProbeOutcome.CONTRACT_BROKEN
            )
            observations[username] = _observation(
                self,
                username,
                outcome,
                canonical=username if outcome == ProbeOutcome.FOUND else None,
                profile=profile,
                status=status,
            )
        return ProviderBatchResult(observations, request_count)


_PROVIDER_INSTANCES: tuple[ProfileProvider, ...] = (
    GitHubProvider(),
    ForemProvider(),
    RedditProvider(),
    XProvider(),
    YouTubeProvider(),
    TwitchProvider(),
    SteamProvider(),
)

PROVIDERS: dict[str, ProfileProvider] = {
    provider.platform_name: provider
    for provider in _PROVIDER_INSTANCES
}


def has_provider(platform_name: str) -> bool:
    return platform_name in PROVIDERS


def is_configured(
    platform_name: str, credentials: ProviderCredentials
) -> bool:
    """Whether a credential-gated provider can make an authenticated call."""
    if platform_name == "X":
        return bool(credentials.x_bearer_token)
    if platform_name == "Twitch":
        return bool(
            credentials.twitch_client_id
            and (
                credentials.twitch_access_token
                or credentials.twitch_client_secret
            )
        )
    if platform_name == "Reddit":
        return bool(
            credentials.reddit_user_agent
            and (
                credentials.reddit_bearer_token
                or (
                    credentials.reddit_client_id
                    and credentials.reddit_client_secret
                )
            )
        )
    if platform_name == "YouTube":
        return bool(credentials.youtube_api_key)
    if platform_name == "Steam":
        return bool(credentials.steam_api_key)
    return platform_name in PROVIDERS


async def lookup_many(
    client: HTTPClient,
    platform_name: str,
    usernames: Sequence[str],
    credentials: ProviderCredentials,
) -> ProviderBatchResult | None:
    provider = PROVIDERS.get(platform_name)
    if provider is None:
        return None
    unique = list(dict.fromkeys(usernames))
    return await provider.lookup_many(client, unique, credentials)
