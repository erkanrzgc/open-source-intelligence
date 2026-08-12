"""Offline tests for the opt-in provider contract smoke runner."""

from __future__ import annotations

import json
from typing import Any

import pytest

from modules.providers import ProviderCredentials
from scripts.provider_contract_smoke import run_provider_contract_smoke


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


@pytest.mark.asyncio
async def test_public_contract_matrix_checks_positive_and_negative_profiles():
    def responder(url: str) -> tuple[int, Any]:
        if "api.github.com/users/octocat" in url:
            return 200, {"login": "octocat"}
        if "dev.to/api/users/by_username?url=ben" in url:
            return 200, {"username": "ben"}
        return 404, None

    client = _StubClient(responder)
    report = await run_provider_contract_smoke(
        client,  # type: ignore[arg-type]
        ProviderCredentials(),
        provider_names=["GitHub", "Dev.to"],
        nonce="abc12345",
    )

    assert report["success"] is True
    assert report["summary"] == {
        "selected": 2,
        "passed": 2,
        "skipped": 0,
        "failed": 0,
        "http_request_count": 4,
        "authentication_http_request_count": 0,
        "provider_http_request_count": 4,
    }
    assert len(client.calls) == 4
    assert "api-key" not in json.dumps(report).casefold()


@pytest.mark.asyncio
async def test_missing_optional_credentials_skip_without_wire_requests():
    client = _StubClient(lambda _url: (500, None))
    report = await run_provider_contract_smoke(
        client,  # type: ignore[arg-type]
        ProviderCredentials(),
        provider_names=["Reddit", "YouTube", "Twitch", "Steam"],
        nonce="abc12345",
    )

    assert report["success"] is True
    assert report["summary"]["skipped"] == 4
    assert report["summary"]["http_request_count"] == 0
    assert client.calls == []


@pytest.mark.asyncio
async def test_required_unconfigured_provider_fails_closed():
    client = _StubClient(lambda _url: (500, None))
    report = await run_provider_contract_smoke(
        client,  # type: ignore[arg-type]
        ProviderCredentials(),
        provider_names=["X"],
        required_providers=["X"],
        nonce="abc12345",
    )

    assert report["success"] is False
    assert report["summary"]["failed"] == 1
    assert report["providers"][0]["failures"] == [
        "required_provider_unconfigured"
    ]
    assert client.calls == []


@pytest.mark.asyncio
async def test_configured_x_uses_one_batch_and_report_excludes_token():
    def responder(url: str) -> tuple[int, Any]:
        assert "usernames=X%2Cosismkabc12345" in url
        return 200, {
            "data": [{"id": "1", "username": "X"}],
            "errors": [{"value": "osismkabc12345", "detail": "not found"}],
        }

    client = _StubClient(responder)
    token = "x-super-secret-token"
    report = await run_provider_contract_smoke(
        client,  # type: ignore[arg-type]
        ProviderCredentials(x_bearer_token=token),
        provider_names=["X"],
        required_providers=["X"],
        nonce="abc12345",
    )

    assert report["success"] is True
    assert report["summary"]["http_request_count"] == 1
    assert len(client.calls) == 1
    assert token not in json.dumps(report)


@pytest.mark.asyncio
async def test_twitch_client_secret_mints_token_before_one_profile_batch():
    class _OAuthStubClient(_StubClient):
        def __init__(self):
            super().__init__(
                lambda _url: (200, {"data": [{"id": "1", "login": "twitch"}]})
            )
            self.form_calls: list[tuple[str, dict[str, str]]] = []

        async def post_form(self, url, form_body, headers=None):
            self.form_calls.append((url, form_body))
            self.request_count += 1
            return 200, {
                "access_token": "ephemeral-twitch-token",
                "token_type": "bearer",
                "expires_in": 5000,
            }, 0.01

    client = _OAuthStubClient()
    report = await run_provider_contract_smoke(
        client,  # type: ignore[arg-type]
        ProviderCredentials(
            twitch_client_id="client",
            twitch_client_secret="client-secret",
        ),
        provider_names=["Twitch"],
        required_providers=["Twitch"],
        nonce="abc12345",
    )

    assert report["success"] is True
    assert report["summary"]["authentication_http_request_count"] == 1
    assert report["summary"]["provider_http_request_count"] == 1
    assert report["summary"]["http_request_count"] == 2
    assert report["authentication"]["Twitch"]["outcome"] == "ready"
    assert len(client.form_calls) == 1
    assert len(client.calls) == 1
    serialized = json.dumps(report)
    assert "client-secret" not in serialized
    assert "ephemeral-twitch-token" not in serialized


@pytest.mark.asyncio
async def test_contract_mismatch_records_failure_without_raw_payload():
    client = _StubClient(
        lambda _url: (
            200,
            {"login": "someone-else", "provider_private_field": "raw-secret"},
        )
    )
    report = await run_provider_contract_smoke(
        client,  # type: ignore[arg-type]
        ProviderCredentials(github_token="hidden"),
        provider_names=["GitHub"],
        nonce="abc12345",
    )

    assert report["success"] is False
    assert report["summary"]["failed"] == 1
    assert "contract_broken" in report["providers"][0]["failures"][0]
    serialized = json.dumps(report)
    assert "someone-else" in serialized  # Canonical mismatch is contract evidence.
    assert "provider_private_field" not in serialized
    assert "raw-secret" not in serialized
