"""Typed contracts shared by official profile providers."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.models import PlatformResult, ProbeOutcome
from core.platform_loader import Platform


@dataclass(frozen=True)
class ProviderCredentials:
    """Process-owned provider secrets; never serialized into scan output."""

    github_token: str = field(default="", repr=False)
    forem_api_key: str = field(default="", repr=False)
    reddit_bearer_token: str = field(default="", repr=False)
    reddit_user_agent: str = ""
    x_bearer_token: str = field(default="", repr=False)
    youtube_api_key: str = field(default="", repr=False)
    twitch_client_id: str = ""
    twitch_access_token: str = field(default="", repr=False)
    steam_api_key: str = field(default="", repr=False)
    # App credentials are appended to preserve the historical positional
    # constructor order. Prefer keyword arguments for all new callers.
    reddit_client_id: str = ""
    reddit_client_secret: str = field(default="", repr=False)
    twitch_client_secret: str = field(default="", repr=False)

    @classmethod
    def from_environment(
        cls, environ: Mapping[str, str] | None = None
    ) -> ProviderCredentials:
        source = os.environ if environ is None else environ

        def value(key: str) -> str:
            return source.get(key, "").strip()

        return cls(
            github_token=value("GITHUB_TOKEN"),
            forem_api_key=value("OSINT_FOREM_API_KEY"),
            reddit_bearer_token=value("OSINT_REDDIT_BEARER_TOKEN"),
            reddit_client_id=value("OSINT_REDDIT_CLIENT_ID"),
            reddit_client_secret=value("OSINT_REDDIT_CLIENT_SECRET"),
            reddit_user_agent=value("OSINT_REDDIT_USER_AGENT"),
            x_bearer_token=value("OSINT_X_BEARER_TOKEN"),
            youtube_api_key=value("OSINT_YOUTUBE_API_KEY"),
            twitch_client_id=value("OSINT_TWITCH_CLIENT_ID"),
            twitch_client_secret=value("OSINT_TWITCH_CLIENT_SECRET"),
            twitch_access_token=value("OSINT_TWITCH_ACCESS_TOKEN"),
            steam_api_key=value("OSINT_STEAM_API_KEY"),
        )


@dataclass(frozen=True)
class ProviderObservation:
    provider: str
    requested_username: str
    canonical_username: str | None
    outcome: ProbeOutcome
    evidence_class: str
    entity_scope: str
    profile: dict[str, object] = field(default_factory=dict)
    http_status: int | None = None
    contract_revision: str = ""
    checked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    warnings: tuple[str, ...] = ()

    def to_platform_result(self, platform: Platform) -> PlatformResult:
        status_by_outcome = {
            ProbeOutcome.FOUND: "found",
            ProbeOutcome.NOT_FOUND: "not_found",
            ProbeOutcome.AMBIGUOUS: "uncertain",
            ProbeOutcome.UNAVAILABLE_AUTH: "unavailable_auth",
            ProbeOutcome.UNAVAILABLE_POLICY: "unavailable_policy",
            ProbeOutcome.RATE_LIMITED: "blocked",
            ProbeOutcome.BLOCKED: "blocked",
            ProbeOutcome.CONTRACT_BROKEN: "contract_mismatch",
            ProbeOutcome.ERROR: "error",
            ProbeOutcome.INVALID: "invalid_username",
            ProbeOutcome.PENDING: "pending",
        }
        found = self.outcome == ProbeOutcome.FOUND
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", self.requested_username),
            category=platform.category,
            exists=found,
            status=status_by_outcome[self.outcome],
            profile_data=dict(self.profile),
            http_status=self.http_status or 0,
            confidence=1.0 if found else 0.0,
            fp_signals=["official_provider", *self.warnings],
            queried_username=self.requested_username,
            canonical_username=self.canonical_username,
            probe_outcome=self.outcome,
            evidence_class=self.evidence_class,
            entity_scope=self.entity_scope,
            contract_revision=self.contract_revision,
            confirmation_capable=platform.evidence_class
            in {"official_exact", "official_scoped", "public_contract"},
            contract_verified=bool(
                found
                and self.canonical_username
                and self.canonical_username.casefold()
                == self.requested_username.casefold()
            ),
        )


@dataclass(frozen=True)
class ProviderBatchResult:
    observations: dict[str, ProviderObservation]
    http_request_count: int = 0
