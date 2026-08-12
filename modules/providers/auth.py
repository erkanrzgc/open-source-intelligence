"""Short-lived provider token preparation through official OAuth flows."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, replace

from core.http_client import HTTPClient
from modules.providers.models import ProviderCredentials


@dataclass(frozen=True)
class ProviderAuthStatus:
    platform: str
    source: str
    outcome: str
    http_status: int | None = None
    expires_in_seconds: int | None = None
    http_request_count: int = 0
    warnings: tuple[str, ...] = ()

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "outcome": self.outcome,
            "http_status": self.http_status,
            "expires_in_seconds": self.expires_in_seconds,
            "http_request_count": self.http_request_count,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class PreparedProviderCredentials:
    credentials: ProviderCredentials
    statuses: dict[str, ProviderAuthStatus]
    http_request_count: int = 0


def _request_count(client: HTTPClient) -> int:
    """Support legacy/test HTTPClient doubles that predate request metrics."""
    value = getattr(client, "request_count", 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _failure_outcome(status: int) -> str:
    if status in (401, 403):
        return "unavailable_auth"
    if status == 429:
        return "rate_limited"
    if status in (0, -1) or status >= 500:
        return "error"
    return "contract_broken"


def _token_payload(
    status: int, data: dict | None
) -> tuple[str | None, int | None, str]:
    if status != 200 or not isinstance(data, dict):
        return None, None, _failure_outcome(status)
    token = data.get("access_token")
    token_type = data.get("token_type")
    expires_in = data.get("expires_in")
    if (
        not isinstance(token, str)
        or not token.strip()
        or not isinstance(token_type, str)
        or token_type.casefold() != "bearer"
        or not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or expires_in <= 0
    ):
        return None, None, "contract_broken"
    return token.strip(), expires_in, "ready"


async def _prepare_reddit(
    client: HTTPClient, credentials: ProviderCredentials
) -> tuple[str | None, ProviderAuthStatus]:
    has_client = bool(
        credentials.reddit_client_id
        and credentials.reddit_client_secret
        and credentials.reddit_user_agent
    )
    if not has_client:
        if credentials.reddit_bearer_token and credentials.reddit_user_agent:
            return credentials.reddit_bearer_token, ProviderAuthStatus(
                "Reddit", "supplied_bearer", "ready"
            )
        return None, ProviderAuthStatus("Reddit", "missing", "unavailable_auth")

    basic_value = base64.b64encode(
        (
            f"{credentials.reddit_client_id}:"
            f"{credentials.reddit_client_secret}"
        ).encode()
    ).decode("ascii")
    before = _request_count(client)
    status, data, _ = await client.post_form(
        "https://www.reddit.com/api/v1/access_token",
        {"grant_type": "client_credentials"},
        {
            "Authorization": f"Basic {basic_value}",
            "User-Agent": credentials.reddit_user_agent,
        },
    )
    request_count = _request_count(client) - before
    token, expires_in, outcome = _token_payload(status, data)
    warnings: tuple[str, ...] = ()
    if token is None and credentials.reddit_bearer_token:
        token = credentials.reddit_bearer_token
        outcome = "ready"
        warnings = ("client_credentials_failed_using_supplied_bearer",)
    return token, ProviderAuthStatus(
        "Reddit",
        "client_credentials",
        outcome,
        http_status=status,
        expires_in_seconds=expires_in,
        http_request_count=request_count,
        warnings=warnings,
    )


async def _prepare_twitch(
    client: HTTPClient, credentials: ProviderCredentials
) -> tuple[str | None, ProviderAuthStatus]:
    has_client = bool(
        credentials.twitch_client_id and credentials.twitch_client_secret
    )
    if not has_client:
        if credentials.twitch_client_id and credentials.twitch_access_token:
            return credentials.twitch_access_token, ProviderAuthStatus(
                "Twitch", "supplied_bearer", "ready"
            )
        return None, ProviderAuthStatus("Twitch", "missing", "unavailable_auth")

    before = _request_count(client)
    status, data, _ = await client.post_form(
        "https://id.twitch.tv/oauth2/token",
        {
            "client_id": credentials.twitch_client_id,
            "client_secret": credentials.twitch_client_secret,
            "grant_type": "client_credentials",
        },
    )
    request_count = _request_count(client) - before
    token, expires_in, outcome = _token_payload(status, data)
    warnings: tuple[str, ...] = ()
    if token is None and credentials.twitch_access_token:
        token = credentials.twitch_access_token
        outcome = "ready"
        warnings = ("client_credentials_failed_using_supplied_bearer",)
    return token, ProviderAuthStatus(
        "Twitch",
        "client_credentials",
        outcome,
        http_status=status,
        expires_in_seconds=expires_in,
        http_request_count=request_count,
        warnings=warnings,
    )


async def prepare_provider_credentials(
    client: HTTPClient,
    credentials: ProviderCredentials,
    *,
    provider_names: tuple[str, ...] | list[str] | None = None,
) -> PreparedProviderCredentials:
    """Mint fresh app tokens once for the selected scan/smoke invocation."""
    selected = set(
        ("Reddit", "Twitch") if provider_names is None else provider_names
    )
    prepared = credentials
    statuses: dict[str, ProviderAuthStatus] = {}

    if "Reddit" in selected:
        before = _request_count(client)
        try:
            reddit_token, reddit_status = await _prepare_reddit(client, credentials)
            statuses["Reddit"] = reddit_status
            prepared = replace(prepared, reddit_bearer_token=reddit_token or "")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            statuses["Reddit"] = ProviderAuthStatus(
                "Reddit",
                "client_credentials",
                "error",
                http_request_count=_request_count(client) - before,
                warnings=(f"token_exception:{type(exc).__name__}",),
            )
            prepared = replace(
                prepared,
                reddit_bearer_token=credentials.reddit_bearer_token,
            )
    if "Twitch" in selected:
        before = _request_count(client)
        try:
            twitch_token, twitch_status = await _prepare_twitch(client, credentials)
            statuses["Twitch"] = twitch_status
            prepared = replace(prepared, twitch_access_token=twitch_token or "")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            statuses["Twitch"] = ProviderAuthStatus(
                "Twitch",
                "client_credentials",
                "error",
                http_request_count=_request_count(client) - before,
                warnings=(f"token_exception:{type(exc).__name__}",),
            )
            prepared = replace(
                prepared,
                twitch_access_token=credentials.twitch_access_token,
            )

    return PreparedProviderCredentials(
        credentials=prepared,
        statuses=statuses,
        http_request_count=sum(
            status.http_request_count for status in statuses.values()
        ),
    )
