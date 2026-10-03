"""Offline, labelled identity evaluation; scores are not population estimates."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from core.correlation import correlate_identity
from core.smart_search import generate_candidates

STRONG_VERDICTS = frozenset({"confirmed_same", "likely_same"})


def evaluate_dataset(dataset: dict[str, Any]) -> dict[str, Any]:
    """Evaluate explicit same-person labels without treating abstention as a match.

    Inputs are normalized public-profile fixtures, not live lookup targets.
    Sparse same-person cases count as false negatives at the strong-match
    threshold. Empty denominators return None, never misleading 100% scores.
    """
    pairs = dataset.get("identity_pairs", [])
    if not pairs:
        raise ValueError("identity_pairs must not be empty")
    ids = [row["id"] for row in pairs]
    if len(ids) != len(set(ids)):
        raise ValueError("identity pair ids must be unique")
    started = time.perf_counter()
    counts: Counter[str] = Counter()
    rows = []
    for pair in pairs:
        if not isinstance(pair.get("same_person"), bool):
            raise ValueError(f"{pair['id']}: same_person must be a boolean label")
        # A synthetic fixture's direct_link flag represents separately verified
        # profile-link evidence; it must not be inferred from handle similarity.
        left = pair["left"]
        right = pair["right"]

        def payload(profile: dict, default_username: str) -> dict:
            return {
                "username": profile.get("username", default_username),
                "platforms": [{"profile_data": profile.get("profile", {})}],
            }

        result = correlate_identity(
            payload(left, "alice"), payload(right, "alicee"),
            direct_link=pair.get("direct_link", False),
        )
        predicted = result.verdict in STRONG_VERDICTS
        label = pair["same_person"]
        outcome = ("true_" if predicted == label else "false_") + (
            "positive" if predicted else "negative"
        )
        counts[outcome] += 1
        counts["abstained"] += not predicted
        counts["positive_labels"] += label
        counts["negative_labels"] += not label
        if not label and result.verdict == "confirmed_same":
            counts["false_confirmations"] += 1
        rows.append({
            "id": pair["id"], "same_person": label, "outcome": outcome,
            "verdict": result.verdict, "score": result.score,
            "evidence_kinds": [signal.kind for signal in result.signals],
            "label_reason": pair.get("label_reason", ""),
        })

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    tp, fp, fn = (counts[key] for key in ("true_positive", "false_positive", "false_negative"))
    discovery = []
    for case in dataset.get("alias_discovery", []):
        candidates = generate_candidates(
            case["username"], linked_usernames=case.get("linked_usernames", []),
            max_candidates=24,
        )
        names = [candidate.username for candidate in candidates]
        rank = names.index(case["alias"]) + 1 if case["alias"] in names else None
        discovery.append({"id": case["id"], "rank": rank, "hit_at_12": rank is not None and rank <= 12,
                          "hit_at_24": rank is not None})
    return {
        "schema_version": 1,
        "dataset_id": dataset.get("dataset_id", "unknown"),
        "data_kind": dataset.get("data_kind", "unspecified"),
        "scope": "normalized identity scoring and candidate ranking; not end-to-end live accuracy",
        "positive_prediction": sorted(STRONG_VERDICTS),
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "metrics": {
            "pairs": len(rows),
            **{key: counts[key] for key in (
                "positive_labels", "negative_labels", "true_positive", "false_positive",
                "true_negative", "false_negative", "abstained", "false_confirmations",
            )},
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, counts["negative_labels"]),
            "abstention_rate": ratio(counts["abstained"], len(rows)),
        },
        "identity_pairs": rows,
        "discovery": {
            "cases": len(discovery),
            "hit_at_12": ratio(sum(row["hit_at_12"] for row in discovery), len(discovery)),
            "hit_at_24": ratio(sum(row["hit_at_24"] for row in discovery), len(discovery)),
            "results": discovery,
        },
        "limitations": [
            "Small development regression set, not an independent or representative field benchmark.",
            "No live profile discovery, network latency, API coverage, or LLM quality is measured here.",
            "Possible/uncertain verdicts abstain; same-person abstentions remain missed strong matches.",
        ],
    }
