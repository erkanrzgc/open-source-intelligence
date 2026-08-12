"""Offline contract fixtures for supported exact-profile providers."""

from __future__ import annotations

from typing import Any

import pytest

from core import engine as engine_mod
from core.config import ScanConfig
from core.context import ScanContext
from core.engine import _phase_smart_search, _probe_alias_batch
from core.models import ProbeOutcome, ScanResult
from core.platform_loader import load_platforms
from core.smart_search import UsernameCandidate
from modules.providers import ProviderCredentials, lookup_many


class _StubClient:
    def __init__(self, responder):
        self.responder = responder
        self.calls: list[tuple[str, dict | None]] = []
        self.request_count = 0

    async def get_json(self, url: str, headers: dict | None = None):
        self.calls.append((url, headers))
        self.request_count += 1
        status, data = self.responder(url)
        return status, data, 0.01


def _candidate(username: str) -> UsernameCandidate:
    return UsernameCandidate(username, 0.9, 0.9, 0.9, ("test",))


def test_credentials_are_loaded_once_from_explicit_environment():
    credentials = ProviderCredentials.from_environment(
        {
            "GITHUB_TOKEN": "gh-secret",
            "OSINT_X_BEARER_TOKEN": "x-secret",
            "OSINT_REDDIT_CLIENT_ID": "reddit-client",
            "OSINT_REDDIT_CLIENT_SECRET": "reddit-super-secret",
            "OSINT_TWITCH_CLIENT_ID": "client",
            "OSINT_TWITCH_CLIENT_SECRET": "twitch-super-secret",
        }
    )
    assert credentials.github_token == "gh-secret"
    assert credentials.x_bearer_token == "x-secret"
    assert credentials.reddit_client_id == "reddit-client"
    assert credentials.reddit_client_secret == "reddit-super-secret"
    assert credentials.twitch_client_id == "client"
    assert credentials.twitch_client_secret == "twitch-super-secret"
    rendered = repr(credentials)
    assert "reddit-super-secret" not in rendered
    assert "twitch-super-secret" not in rendered
    assert "x-secret" not in rendered


@pytest.mark.asyncio
async def test_github_and_forem_require_exact_canonical_username():
    def responder(url: str) -> tuple[int, Any]:
        if "api.github.com" in url:
            return 200, {"login": "Alice", "name": "Alice Example"}
        return 200, {"username": "alice-other", "name": "Other"}

    client = _StubClient(responder)
    github = await lookup_many(
        client, "GitHub", ["alice"], ProviderCredentials(github_token="token")
    )
    forem = await lookup_many(client, "Dev.to", ["alice"], ProviderCredentials())

    assert github is not None and forem is not None
    assert github.observations["alice"].outcome == ProbeOutcome.FOUND
    assert forem.observations["alice"].outcome == ProbeOutcome.CONTRACT_BROKEN
    assert client.calls[0][1]["Authorization"] == "Bearer token"
    assert "application/vnd.forem.api-v1+json" in client.calls[1][1]["Accept"]
    assert client.calls[1][0].endswith("/api/users/by_username?url=alice")


@pytest.mark.asyncio
async def test_forem_uses_exact_compatibility_route_and_encodes_username():
    client = _StubClient(lambda _url: (200, {"username": "alice bob"}))

    batch = await lookup_many(
        client, "Dev.to", ["alice bob"], ProviderCredentials()
    )

    assert batch is not None
    assert batch.observations["alice bob"].outcome == ProbeOutcome.FOUND
    assert client.calls[0][0].endswith(
        "/api/users/by_username?url=alice+bob"
    )


@pytest.mark.asyncio
async def test_reddit_missing_credentials_is_unavailable_without_wire_request():
    client = _StubClient(lambda _url: (500, None))
    batch = await lookup_many(
        client, "Reddit", ["alice", "bob"], ProviderCredentials()
    )

    assert batch is not None
    assert batch.http_request_count == 0
    assert client.calls == []
    assert {
        observation.outcome for observation in batch.observations.values()
    } == {ProbeOutcome.UNAVAILABLE_AUTH}


@pytest.mark.asyncio
async def test_reddit_oauth_exact_profile_and_honest_user_agent():
    client = _StubClient(lambda _url: (200, {"data": {"name": "Alice"}}))
    credentials = ProviderCredentials(
        reddit_bearer_token="token",
        reddit_user_agent="osi-test/1.0 by investigator",
    )
    batch = await lookup_many(client, "Reddit", ["alice"], credentials)

    assert batch is not None
    assert batch.observations["alice"].outcome == ProbeOutcome.FOUND
    assert client.calls[0][1] == {
        "Authorization": "Bearer token",
        "User-Agent": "osi-test/1.0 by investigator",
    }


@pytest.mark.asyncio
async def test_x_and_twitch_batch_exact_rows_and_omissions():
    def responder(url: str) -> tuple[int, Any]:
        if "api.x.com" in url:
            return 200, {"data": [{"id": "1", "username": "alice"}], "errors": []}
        return 200, {"data": [{"id": "2", "login": "bob"}]}

    client = _StubClient(responder)
    credentials = ProviderCredentials(
        x_bearer_token="x-token",
        twitch_client_id="client",
        twitch_access_token="twitch-token",
    )
    x_batch = await lookup_many(client, "X", ["alice", "bob"], credentials)
    twitch_batch = await lookup_many(
        client, "Twitch", ["alice", "bob"], credentials
    )

    assert x_batch is not None and twitch_batch is not None
    assert x_batch.http_request_count == twitch_batch.http_request_count == 1
    assert x_batch.observations["alice"].outcome == ProbeOutcome.FOUND
    assert x_batch.observations["bob"].outcome == ProbeOutcome.NOT_FOUND
    assert twitch_batch.observations["alice"].outcome == ProbeOutcome.NOT_FOUND
    assert twitch_batch.observations["bob"].outcome == ProbeOutcome.FOUND
    assert len(client.calls) == 2
    assert "usernames=alice%2Cbob" in client.calls[0][0]
    assert "login=alice&login=bob" in client.calls[1][0]


@pytest.mark.asyncio
async def test_youtube_for_handle_distinguishes_empty_and_quota_failure():
    responses = iter(
        [
            (200, {"items": [{"id": "channel-1", "snippet": {"title": "Alice"}}]}),
            (200, {"items": []}),
            (403, None),
        ]
    )
    client = _StubClient(lambda _url: next(responses))
    credentials = ProviderCredentials(youtube_api_key="key")
    batch = await lookup_many(
        client, "YouTube", ["alice", "missing", "quota"], credentials
    )

    assert batch is not None
    assert batch.observations["alice"].outcome == ProbeOutcome.FOUND
    assert batch.observations["missing"].outcome == ProbeOutcome.NOT_FOUND
    assert batch.observations["quota"].outcome == ProbeOutcome.UNAVAILABLE_AUTH
    assert all("forHandle=" in url for url, _headers in client.calls)


@pytest.mark.asyncio
async def test_steam_resolves_vanity_then_batches_summaries():
    def responder(url: str) -> tuple[int, Any]:
        if "ResolveVanityURL" in url and "vanityurl=alice" in url:
            return 200, {"response": {"success": 1, "steamid": "11"}}
        if "ResolveVanityURL" in url:
            return 200, {"response": {"success": 42, "message": "No match"}}
        return 200, {
            "response": {
                "players": [
                    {"steamid": "11", "personaname": "Alice", "profileurl": "https://steam/alice"}
                ]
            }
        }

    client = _StubClient(responder)
    batch = await lookup_many(
        client,
        "Steam",
        ["alice", "missing"],
        ProviderCredentials(steam_api_key="key"),
    )

    assert batch is not None
    assert batch.http_request_count == 3
    assert batch.observations["alice"].outcome == ProbeOutcome.FOUND
    assert batch.observations["missing"].outcome == ProbeOutcome.NOT_FOUND
    assert "steamids=11" in client.calls[-1][0]


@pytest.mark.asyncio
async def test_alias_scheduler_batches_x_and_twitch_and_counts_wire_requests():
    def responder(url: str) -> tuple[int, Any]:
        if "api.x.com" in url:
            return 200, {
                "data": [{"id": "1", "username": "alicee"}],
                "errors": [],
            }
        return 200, {"data": [{"id": "2", "login": "alice_dev"}]}

    client = _StubClient(responder)
    credentials = ProviderCredentials(
        x_bearer_token="x-token",
        twitch_client_id="client",
        twitch_access_token="twitch-token",
    )
    context = ScanContext(provider_credentials=credentials)
    by_name = {platform.name: platform for platform in load_platforms()}
    candidates = [_candidate("alicee"), _candidate("alice_dev")]

    specs, results = await _probe_alias_batch(
        client,
        ScanConfig(username="alice"),
        candidates,
        [by_name["X"], by_name["Twitch"]],
        context,
    )

    assert len(specs) == len(results) == 4
    assert client.request_count == context.provider_http_requests == 2
    confirmed = {
        (result.queried_username, result.platform)
        for result in results
        if result.exists
    }
    assert confirmed == {("alicee", "X"), ("alice_dev", "Twitch")}


@pytest.mark.asyncio
async def test_configured_batch_providers_cover_all_twenty_four_aliases_once(
    monkeypatch,
):
    monkeypatch.setattr(engine_mod, "ALIAS_PROBE_PLATFORMS", ("X", "Twitch"))

    def responder(url: str) -> tuple[int, Any]:
        if "api.x.com" in url:
            return 200, {"data": [], "errors": []}
        return 200, {"data": []}

    client = _StubClient(responder)
    context = ScanContext(
        provider_credentials=ProviderCredentials(
            x_bearer_token="x-token",
            twitch_client_id="client",
            twitch_access_token="twitch-token",
        )
    )
    by_name = {platform.name: platform for platform in load_platforms()}
    result = ScanResult(username="erkanrzgc")

    await _phase_smart_search(
        client,
        ScanConfig(username="erkanrzgc"),
        [by_name["X"], by_name["Twitch"]],
        [],
        result,
        context=context,
    )

    diagnostics = result.diagnostics["alias_search"]
    assert len(result.variations_checked) == 24
    assert diagnostics["probe_count"] == 48
    assert diagnostics["primary_probe_count"] == 48
    assert diagnostics["fallback_probe_count"] == 0
    assert diagnostics["batch_extended_candidate_count"] == 12
    assert diagnostics["batch_extension_platform_count"] == 2
    assert diagnostics["http_request_count"] == 2
    assert diagnostics["provider_http_request_count"] == 2
    assert len(client.calls) == 2
