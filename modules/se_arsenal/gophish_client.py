"""Minimal GoPhish REST API wrapper for pushing phishing targets.

GoPhish is self-hosted (``https://<host>:3333`` by default) and exposes
an API key per admin user. We only need the ``/api/groups/`` endpoint to
drop a phishing-target group; campaign/template management stays in the
GoPhish UI where the operator already has workflows.

Kept synchronous on purpose: this is a one-shot push operation, not a
fan-out. No async machinery, no extra deps.
"""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

from modules.recon.models import EmailCandidate, GithubCommitter
from modules.se_arsenal.models import GoPhishTarget

log = logging.getLogger(__name__)


class GoPhishError(RuntimeError):
    """Raised when the GoPhish server rejects or cannot answer a request."""


def _split_name(full_name: str) -> tuple[str, str]:
    parts = [p for p in (full_name or "").split() if p]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], " ".join(parts[1:])


def targets_from_candidates(
    candidates: Iterable[EmailCandidate],
    committers: Iterable[GithubCommitter] = (),
    *,
    include_noreply: bool = False,
) -> list[GoPhishTarget]:
    """Merge pattern candidates + real committers into a deduped target list.

    Mirrors the policy in ``core.reporter.redteam_export``: drop GitHub
    no-reply addresses by default (they bounce or route to GitHub itself).
    """
    seen: set[str] = set()
    out: list[GoPhishTarget] = []

    for cand in candidates:
        email = (cand.email or "").strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)
        out.append(
            GoPhishTarget(
                email=email,
                first_name=cand.first_name or "",
                last_name=cand.last_name or "",
            )
        )

    for com in committers:
        email = (com.email or "").strip().lower()
        if not email or email in seen:
            continue
        if com.is_noreply and not include_noreply:
            continue
        seen.add(email)
        first, last = _split_name(com.name)
        out.append(GoPhishTarget(email=email, first_name=first, last_name=last))

    return out


class GoPhishClient:
    """Thin POST wrapper around the GoPhish ``/api`` namespace."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        verify_tls: bool = True,
        timeout: float = 30.0,
    ) -> None:
        if not base_url:
            raise GoPhishError("GoPhish base_url is required")
        if not api_key:
            raise GoPhishError("GoPhish api_key is required")
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._timeout = timeout
        self._ssl_ctx = (
            ssl.create_default_context()
            if verify_tls
            else ssl._create_unverified_context()  # noqa: SLF001 — self-signed lab hosts
        )

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base}{path}"
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._key}",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(  # noqa: S310 — validated https host
                req, timeout=self._timeout, context=self._ssl_ctx
            ) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            raise GoPhishError(f"GoPhish {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise GoPhishError(f"GoPhish transport error: {exc}") from exc
        try:
            return json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            raise GoPhishError(f"GoPhish returned non-JSON body: {exc}") from exc

    def push_group(self, name: str, targets: list[GoPhishTarget]) -> dict[str, Any]:
        """Create a ``groups`` object. Duplicate names return 409 from GoPhish."""
        if not name:
            raise GoPhishError("group name is required")
        if not targets:
            raise GoPhishError("at least one target is required")
        payload = {"name": name, "targets": [t.to_dict() for t in targets]}
        return self._post("/api/groups/", payload)
