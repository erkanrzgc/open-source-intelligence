"""LLM-driven pretext template generator.

Given an OSINT payload (``ScanResult.to_dict()``) and a target email,
produces a phishing-email draft with subject + body + technique +
justification. Uses whatever ``core.analysis.llm.LLMAnalyzer`` is
configured (NVIDIA NIM by default; OpenAI / Groq / Ollama work via
the same OpenAI-compatible HTTP shape) — the backend is
pluggable.

We do **not** send the mail. Output is a ``PretextEmail`` the operator
reviews, edits, and hands off to their sender (GoPhish, Evilginx2,
manual). That review gate is intentional: an unreviewed LLM draft is
both legally and operationally unsafe.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
from collections.abc import Coroutine
from typing import Any, cast

from core.analysis.llm import Backend, LLMAnalyzer, LLMUnavailable
from modules.se_arsenal.models import PretextEmail

log = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are a red-team phishing operator drafting an
authorized spear-phishing email for a sanctioned engagement. Use the
provided OSINT payload to craft a single email targeting the given
recipient. The email must look plausible, reference at least one
concrete signal from the payload (platform, employer, interest, …),
and choose a pretext that fits the observed context.

Return ONLY a JSON object with these keys:
  subject          — short subject line (under 80 chars)
  body             — plain-text email body, 3–6 short paragraphs
  technique        — pretext category (vendor_invoice, it_helpdesk,
                     recruiter, shared_document, event_invite, …)
  justification    — one sentence explaining why this pretext fits
                     THIS target (tie to specific signal)
  sender_persona   — suggested From: name + role
  linked_signals   — list of 1-5 signals from payload used in the draft

No prose outside the JSON. No markdown fences."""


def _build_user_prompt(
    payload: dict[str, Any], target_email: str, scenario_hint: str
) -> str:
    # Trim the payload down to the fields that actually influence pretext
    # choice; keeps token usage sane even for deep scans.
    slim = {
        "username": payload.get("username"),
        "platforms_found": [
            {
                "platform": p.get("platform"),
                "url": p.get("url"),
                "profile_data": p.get("profile_data"),
            }
            for p in (payload.get("platforms") or [])
            if p.get("exists")
        ][:8],
        "emails": [e.get("email") for e in (payload.get("emails") or [])][:5],
        "github_committers": (payload.get("github_committers") or [])[:5],
        "recon_subdomains": [
            s.get("host") for s in (payload.get("recon_subdomains") or [])
        ][:10],
        "enrichment": payload.get("enrichment"),
    }
    hint = f"\nOperator hint: {scenario_hint}" if scenario_hint else ""
    return (
        f"Target email: {target_email}\n"
        f"OSINT payload (JSON):\n{json.dumps(slim, ensure_ascii=False, default=str)}"
        f"{hint}"
    )


_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    match = _JSON_FENCE.search(text)
    if match:
        text = match.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"pretext LLM output was not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMUnavailable("pretext LLM output was not a JSON object")
    return parsed


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None]


def generate_pretext(
    payload: dict[str, Any],
    target_email: str,
    *,
    backend: Backend | None = None,
    scenario_hint: str = "",
    max_tokens: int = 900,
    temperature: float = 0.4,
) -> PretextEmail:
    """Produce a single PretextEmail draft for one target.

    ``backend`` can be injected for tests; otherwise the configured
    ``LLMAnalyzer.from_env()`` backend is used. Temperature defaults a
    bit higher than the OSINT analyzer's 0.2 because pretext drafting
    benefits from mild stylistic variance.
    """
    if not target_email:
        raise ValueError("target_email is required")
    if backend is None:
        analyzer = LLMAnalyzer.from_env()
        backend = analyzer._backend  # type: ignore[assignment]
    if backend is None:
        raise LLMUnavailable("no LLM backend available for pretext generation")

    user_prompt = _build_user_prompt(payload, target_email, scenario_hint)
    completion: Any = backend.complete(
        _SYSTEM_PROMPT,
        user_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    raw: str
    if inspect.isawaitable(completion):
        coroutine = cast(Coroutine[Any, Any, str], completion)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            raw = asyncio.run(coroutine)
        else:
            coroutine.close()
            raise LLMUnavailable(
                "generate_pretext cannot block inside a running event loop"
            )
    else:
        # Retain compatibility with third-party synchronous backends that
        # pre-date the async Backend protocol.
        raw = str(completion)
    data = _extract_json(raw)
    return PretextEmail(
        target_email=target_email,
        subject=str(data.get("subject", "") or ""),
        body=str(data.get("body", "") or ""),
        technique=str(data.get("technique", "") or "generic"),
        justification=str(data.get("justification", "") or ""),
        sender_persona=str(data.get("sender_persona", "") or ""),
        linked_signals=_str_list(data.get("linked_signals")),
    )


def generate_bulk(
    payload: dict[str, Any],
    target_emails: list[str],
    *,
    backend: Backend | None = None,
    scenario_hint: str = "",
) -> list[PretextEmail]:
    """Generate pretexts for multiple targets sequentially.

    Sequential on purpose: most LLM backends rate-limit and we do not
    want to burn an NVIDIA quota with 50 parallel requests for a
    one-shot red-team briefing.
    """
    drafts: list[PretextEmail] = []
    for email in target_emails:
        try:
            drafts.append(
                generate_pretext(
                    payload, email, backend=backend, scenario_hint=scenario_hint
                )
            )
        except LLMUnavailable as exc:
            log.warning("pretext draft failed for %s: %s", email, exc)
    return drafts


def render_markdown(draft: PretextEmail) -> str:
    """Render a draft as a review-friendly markdown file."""
    signals = "\n".join(f"- {s}" for s in draft.linked_signals) or "- (none)"
    return (
        f"# Pretext draft — {draft.target_email}\n\n"
        f"**Technique**: {draft.technique}\n\n"
        f"**Justification**: {draft.justification}\n\n"
        f"**Sender persona**: {draft.sender_persona}\n\n"
        f"**Linked signals**:\n{signals}\n\n"
        f"---\n\n"
        f"**Subject**: {draft.subject}\n\n"
        f"{draft.body}\n"
    )
