"""Offline OAuth contract fixtures for ephemeral provider tokens."""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import pytest

from modules.providers import ProviderCredentials, prepare_provider_credentials
from modules.providers.adapters import is_configured


class _StubClient:
    def __init__(self, responder):
        self.responder = responder
        self.calls: list[tuple[str, dict[str, str], dict | None]] = []
        self.request_count = 0

    async def post_form(
        self,
        url: str,
        form_body: dict[str, str],
        headers: dict | None = None,
    ):
        self.calls.append((url, form_body, headers))
        self.request_count += 1
        status, data = self.responder(url)
        return status, data, 0.01


@pytest.mark.asyncio
async def test_reddit_and_twitch_mint_fresh_client_credentials_tokens():
    def responder(url: str) -> tuple[int, dict[str, Any]]:
        if "reddit.com" in url:
            return 200, {
                "access_token": "reddit-short-lived",
                "token_type": "bearer",
                "expires_in": 3600,
            }
        return 200, {
            "access_token": "twitch-short-lived",
            "token_type": "bearer",
            "expires_in": 5000,
        }

    client = _StubClient(responder)
    credentials = ProviderCredentials(
        reddit_client_id="reddit-client",
        reddit_client_secret="reddit-secret",
        reddit_user_agent="osi-contract-test/1.0",
        twitch_client_id="twitch-client",
        twitch_client_secret="twitch-secret",
    )

    prepared = await prepare_provider_credentials(  # type: ignore[arg-type]
        client, credentials
    )

    assert prepared.credentials.reddit_bearer_token == "reddit-short-lived"
    assert prepared.credentials.twitch_access_token == "twitch-short-lived"
    assert prepared.http_request_count == 2
    assert prepared.statuses["Reddit"].outcome == "ready"
    assert prepared.statuses["Twitch"].expires_in_seconds == 5000
    reddit_call, twitch_call = client.calls
    expected_basic = base64.b64encode(
        b"reddit-client:reddit-secret"
    ).decode("ascii")
    assert reddit_call == (
        "https://www.reddit.com/api/v1/access_token",
        {"grant_type": "client_credentials"},
        {
            "Authorization": f"Basic {expected_basic}",
            "User-Agent": "osi-contract-test/1.0",
        },
    )
    assert twitch_call[1] == {
        "client_id": "twitch-client",
        "client_secret": "twitch-secret",
        "grant_type": "client_credentials",
    }
    safe_statuses = {
        name: status.to_safe_dict()
        for name, status in prepared.statuses.items()
    }
    serialized = json.dumps(safe_statuses)
    assert "reddit-secret" not in serialized
    assert "twitch-secret" not in serialized
    assert "short-lived" not in serialized


@pytest.mark.asyncio
async def test_static_bearers_remain_backward_compatible_without_token_wire():
    client = _StubClient(lambda _url: (500, {}))
    credentials = ProviderCredentials(
        reddit_bearer_token="reddit-static",
        reddit_user_agent="osi-test/1.0",
        twitch_client_id="client",
        twitch_access_token="twitch-static",
    )

    prepared = await prepare_provider_credentials(  # type: ignore[arg-type]
        client, credentials
    )

    assert prepared.credentials == credentials
    assert prepared.http_request_count == 0
    assert client.calls == []
    assert prepared.statuses["Reddit"].source == "supplied_bearer"
    assert prepared.statuses["Twitch"].source == "supplied_bearer"


@pytest.mark.asyncio
async def test_explicit_empty_provider_selection_does_not_prepare_tokens():
    client = _StubClient(lambda _url: (200, {}))
    credentials = ProviderCredentials(
        reddit_client_id="reddit-client",
        reddit_client_secret="reddit-secret",
        reddit_user_agent="osi-test/1.0",
        twitch_client_id="twitch-client",
        twitch_client_secret="twitch-secret",
    )

    prepared = await prepare_provider_credentials(  # type: ignore[arg-type]
        client,
        credentials,
        provider_names=[],
    )

    assert prepared.credentials == credentials
    assert prepared.statuses == {}
    assert prepared.http_request_count == 0
    assert client.calls == []


@pytest.mark.asyncio
async def test_malformed_token_payload_fails_closed_and_is_configured_for_attempt():
    client = _StubClient(lambda _url: (200, {"access_token": "secret"}))
    credentials = ProviderCredentials(
        reddit_client_id="client",
        reddit_client_secret="secret",
        reddit_user_agent="osi-test/1.0",
    )
    assert is_configured("Reddit", credentials) is True

    prepared = await prepare_provider_credentials(  # type: ignore[arg-type]
        client, credentials, provider_names=["Reddit"]
    )

    assert prepared.credentials.reddit_bearer_token == ""
    assert prepared.statuses["Reddit"].outcome == "contract_broken"
    assert "secret" not in json.dumps(prepared.statuses["Reddit"].to_safe_dict())


@pytest.mark.asyncio
async def test_token_preparation_propagates_cancellation():
    async def cancelled(_url: str):
        raise asyncio.CancelledError

    class _CancelledClient(_StubClient):
        async def post_form(self, url, form_body, headers=None):
            self.request_count += 1
            await cancelled(url)

    credentials = ProviderCredentials(
        twitch_client_id="client",
        twitch_client_secret="secret",
    )
    with pytest.raises(asyncio.CancelledError):
        await prepare_provider_credentials(  # type: ignore[arg-type]
            _CancelledClient(lambda _url: (500, {})),
            credentials,
            provider_names=["Twitch"],
        )
