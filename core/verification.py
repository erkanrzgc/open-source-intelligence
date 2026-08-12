"""Deterministic, precision-first platform verdict rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import PlatformResult


HARD_NEGATIVE_STATUSES = frozenset(
    {
        "cached_not_found",
        "invalid_username",
        "not_found",
        "soft_404_message",
        "soft_404_redirected",
        "soft_404_template",
        "username_not_in_body",
        "verified_bad",
        "verified_fake",
    }
)


def evaluate_platform(
    result: PlatformResult,
    *,
    threshold: float,
    trusted: bool = False,
    allow_confirmed: bool = True,
) -> dict:
    """Assign a machine-readable verdict and enforce ``exists`` semantics.

    Hard deterministic negatives cannot be reversed by later AI phases.
    Candidates below the configured threshold remain serializable as
    ``uncertain`` while legacy ``exists`` stays true only for confirmations.
    """
    status = result.status.split(" ", 1)[0]
    signals = list(dict.fromkeys(str(item) for item in result.fp_signals))
    hard_codes = [
        code
        for code in (
            "redirect_off_target",
            "maigret_absence_match",
            "json_api_absence",
            "url_probe_absence",
            "username_absent",
        )
        if code in signals or status == code
    ]
    previous_verdict = (result.verification or {}).get("verdict")
    candidate = bool(result.exists or previous_verdict == "uncertain")

    if status in HARD_NEGATIVE_STATUSES or hard_codes:
        verdict = "rejected"
        reason_codes = hard_codes or [status]
        score = 0.0 if status != "invalid_username" else result.confidence
    elif status in {
        "blocked",
        "error",
        "timeout",
        "pending",
        "contract_mismatch",
        "login_required",
        "unavailable_auth",
        "unavailable_policy",
    }:
        verdict = (
            "uncertain"
            if status
            in {
                "blocked",
                "contract_mismatch",
                "error",
                "login_required",
                "timeout",
                "unavailable_auth",
                "unavailable_policy",
            }
            else "rejected"
        )
        reason_codes = [f"transport_{status}"]
        score = result.confidence
    elif candidate and not allow_confirmed:
        verdict = "uncertain"
        reason_codes = ["insufficient_presence_contract"]
        score = result.confidence
    elif candidate and (trusted or result.confidence >= threshold):
        verdict = "confirmed"
        reason_codes = ["trusted_source" if trusted else "score_threshold_met"]
        score = max(result.confidence, threshold if trusted else result.confidence)
    elif candidate:
        verdict = "uncertain"
        reason_codes = ["score_below_threshold"]
        score = result.confidence
    else:
        verdict = "rejected"
        reason_codes = [status or "not_found"]
        score = result.confidence

    result.exists = verdict == "confirmed"
    if verdict == "uncertain" and status not in {
        "blocked",
        "pending",
        "contract_mismatch",
        "error",
        "login_required",
        "timeout",
        "unavailable_auth",
        "unavailable_policy",
    }:
        result.status = "uncertain"
    result.verification = {
        "verdict": verdict,
        "score": round(max(0.0, min(1.0, float(score))), 3),
        "evidence": signals,
        "reason_codes": list(dict.fromkeys(reason_codes)),
    }
    return result.verification
