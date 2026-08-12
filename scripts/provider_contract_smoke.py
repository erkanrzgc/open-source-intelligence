#!/usr/bin/env python3
"""Opt-in live contract smoke tests for exact-profile providers.

The command checks one stable public account and one generated improbable
handle per provider. It records only normalized contract outcomes: credentials,
authorization headers and raw provider payloads never enter the report.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.http_client import HTTPClient
from core.models import ProbeOutcome
from modules.providers import (
    PROVIDERS,
    ProviderCredentials,
    ProviderObservation,
    is_configured,
    lookup_many,
    prepare_provider_credentials,
)


@dataclass(frozen=True)
class ProviderSmokeFixture:
    platform: str
    positive_username: str
    negative_template: str
    public: bool = False

    def negative_username(self, nonce: str) -> str:
        return self.negative_template.format(nonce=nonce)


PROVIDER_SMOKE_FIXTURES: dict[str, ProviderSmokeFixture] = {
    "GitHub": ProviderSmokeFixture(
        "GitHub", "octocat", "osi-smoke-{nonce}", public=True
    ),
    "Dev.to": ProviderSmokeFixture(
        "Dev.to", "ben", "osi_smoke_{nonce}", public=True
    ),
    "Reddit": ProviderSmokeFixture("Reddit", "spez", "osi_smoke_{nonce}"),
    # X usernames are limited to 15 characters. Eight hex characters plus the
    # six-character prefix remain inside that provider contract.
    "X": ProviderSmokeFixture("X", "X", "osismk{nonce}"),
    "YouTube": ProviderSmokeFixture(
        "YouTube", "GoogleDevelopers", "osismoke{nonce}"
    ),
    "Twitch": ProviderSmokeFixture("Twitch", "twitch", "osismoke{nonce}"),
    "Steam": ProviderSmokeFixture("Steam", "gaben", "osi_smoke_{nonce}"),
}


def _safe_observation(observation: ProviderObservation) -> dict[str, Any]:
    """Serialize contract metadata without raw response data or secrets."""
    return {
        "requested_username": observation.requested_username,
        "canonical_username": observation.canonical_username,
        "outcome": observation.outcome.value,
        "http_status": observation.http_status,
        "evidence_class": observation.evidence_class,
        "entity_scope": observation.entity_scope,
        "contract_revision": observation.contract_revision,
        "warnings": list(observation.warnings),
    }


def _validate_observations(
    fixture: ProviderSmokeFixture,
    positive: ProviderObservation,
    negative: ProviderObservation,
) -> list[str]:
    failures: list[str] = []
    if positive.outcome != ProbeOutcome.FOUND:
        failures.append(f"positive_expected_found_got_{positive.outcome.value}")
    elif (
        not positive.canonical_username
        or positive.canonical_username.casefold()
        != fixture.positive_username.casefold()
    ):
        failures.append("positive_canonical_username_mismatch")
    if negative.outcome != ProbeOutcome.NOT_FOUND:
        failures.append(f"negative_expected_not_found_got_{negative.outcome.value}")
    return failures


async def run_provider_contract_smoke(
    client: HTTPClient,
    credentials: ProviderCredentials,
    *,
    provider_names: Sequence[str] | None = None,
    required_providers: Sequence[str] = (),
    nonce: str | None = None,
) -> dict[str, Any]:
    """Run every selected provider and return a secret-free JSON-safe report."""
    selected = list(provider_names or PROVIDER_SMOKE_FIXTURES)
    unknown = sorted(set(selected) - PROVIDER_SMOKE_FIXTURES.keys())
    if unknown:
        raise ValueError(f"unknown provider(s): {', '.join(unknown)}")
    required = set(required_providers)
    unknown_required = sorted(required - PROVIDER_SMOKE_FIXTURES.keys())
    if unknown_required:
        raise ValueError(
            f"unknown required provider(s): {', '.join(unknown_required)}"
        )

    prepared = await prepare_provider_credentials(
        client,
        credentials,
        provider_names=selected,
    )
    credentials = prepared.credentials
    smoke_nonce = (nonce or secrets.token_hex(4)).casefold()
    rows: list[dict[str, Any]] = []
    for platform_name in selected:
        fixture = PROVIDER_SMOKE_FIXTURES[platform_name]
        provider = PROVIDERS[platform_name]
        configured = is_configured(platform_name, credentials)
        is_required = fixture.public or platform_name in required
        base: dict[str, Any] = {
            "platform": platform_name,
            "public": fixture.public,
            "configured": configured,
            "required": is_required,
            "contract_revision": provider.contract_revision,
            "http_request_count": 0,
        }
        if not configured:
            base.update(
                {
                    "status": "failed" if is_required else "skipped",
                    "failures": (
                        ["required_provider_unconfigured"] if is_required else []
                    ),
                    "reason": "provider_credentials_missing",
                    "duration_ms": 0,
                }
            )
            rows.append(base)
            continue

        negative_username = fixture.negative_username(smoke_nonce)
        started = time.monotonic()
        try:
            batch = await lookup_many(
                client,
                platform_name,
                [fixture.positive_username, negative_username],
                credentials,
            )
            if batch is None:
                raise RuntimeError("registered provider lookup returned no batch")
            positive = batch.observations.get(fixture.positive_username)
            negative = batch.observations.get(negative_username)
            if positive is None or negative is None:
                missing = [
                    username
                    for username, observation in (
                        (fixture.positive_username, positive),
                        (negative_username, negative),
                    )
                    if observation is None
                ]
                base.update(
                    {
                        "status": "failed",
                        "failures": ["provider_observation_missing"],
                        "missing_usernames": missing,
                        "http_request_count": batch.http_request_count,
                    }
                )
            else:
                failures = _validate_observations(fixture, positive, negative)
                base.update(
                    {
                        "status": "failed" if failures else "passed",
                        "failures": failures,
                        "positive": _safe_observation(positive),
                        "negative": _safe_observation(negative),
                        "http_request_count": batch.http_request_count,
                    }
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            base.update(
                {
                    "status": "failed",
                    "failures": [f"provider_exception:{type(exc).__name__}"],
                }
            )
        base["duration_ms"] = round((time.monotonic() - started) * 1000)
        rows.append(base)

    passed = sum(row["status"] == "passed" for row in rows)
    skipped = sum(row["status"] == "skipped" for row in rows)
    failed = sum(row["status"] == "failed" for row in rows)
    provider_http_requests = sum(
        int(row["http_request_count"]) for row in rows
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "success": failed == 0,
        "summary": {
            "selected": len(rows),
            "passed": passed,
            "skipped": skipped,
            "failed": failed,
            "http_request_count": (
                provider_http_requests + prepared.http_request_count
            ),
            "authentication_http_request_count": prepared.http_request_count,
            "provider_http_request_count": provider_http_requests,
        },
        "authentication": {
            platform: status.to_safe_dict()
            for platform, status in prepared.statuses.items()
        },
        "providers": rows,
    }


def _print_report(report: dict[str, Any]) -> None:
    for row in report["providers"]:
        detail = ",".join(row.get("failures", ())) or row.get("reason", "ok")
        print(
            f"{row['platform']}: {row['status']} "
            f"(wire={row['http_request_count']}, {detail})"
        )
    summary = report["summary"]
    print(
        "summary: "
        f"passed={summary['passed']} skipped={summary['skipped']} "
        f"failed={summary['failed']} wire={summary['http_request_count']}"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run opt-in live exact-provider contract smoke tests"
    )
    parser.add_argument(
        "--provider",
        action="append",
        choices=tuple(PROVIDER_SMOKE_FIXTURES),
        dest="providers",
        help="Provider to check; repeat to select multiple (default: all)",
    )
    parser.add_argument(
        "--require-provider",
        action="append",
        choices=tuple(PROVIDER_SMOKE_FIXTURES),
        default=[],
        help="Fail if this credential-gated provider is not configured",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the secret-free JSON report to this path",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-request timeout in seconds (default: 15)",
    )
    return parser


async def _run_from_args(args: argparse.Namespace) -> dict[str, Any]:
    credentials = ProviderCredentials.from_environment()
    async with HTTPClient(
        request_timeout=max(1.0, args.timeout), fingerprint=False
    ) as client:
        return await run_provider_contract_smoke(
            client,
            credentials,
            provider_names=args.providers,
            required_providers=args.require_provider,
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = asyncio.run(_run_from_args(args))
    _print_report(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
