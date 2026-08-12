"""Tests for the Sprint 5 enrichment/analysis module."""

from __future__ import annotations

from core.models import EmailResult, PlatformResult, ScanResult
from modules.analysis import (
    build_entity_graph,
    compute_stylometry,
    detect_languages,
    graph_to_dict,
    infer_timezones,
    run_enrichment,
)
from modules.analysis.models import LanguageGuess
from modules.crypto.models import CryptoIntel
from modules.history.models import HistoricalUsername
from modules.phone.models import PhoneIntel

# ── Stylometry ──────────────────────────────────────────────────────


def test_stylometry_empty_returns_zero_report() -> None:
    r = compute_stylometry([])
    assert r.sample_count == 0
    assert r.total_words == 0
    assert r.top_words == ()


def test_stylometry_basic_metrics() -> None:
    samples = [
        "I love building open source software.",
        "Software is my passion. Open!",
        "Building things is fun!!!",
    ]
    r = compute_stylometry(samples)
    assert r.sample_count == 3
    assert r.total_words > 0
    assert r.avg_word_length > 3
    assert r.lexical_diversity > 0
    assert r.punctuation_ratio > 0
    top_words = {w for w, _ in r.top_words}
    assert "software" in top_words  # content word, survives stopword filter
    assert "the" not in top_words  # stopword


def test_stylometry_counts_emoji() -> None:
    r = compute_stylometry(["Hello 🌍 world 🚀"])
    assert r.emoji_count == 2


def test_stylometry_to_dict_is_json_safe() -> None:
    r = compute_stylometry(["quick test with some words"])
    d = r.to_dict()
    assert isinstance(d["top_words"], list)
    assert d["total_words"] == 5


# ── Language detection ─────────────────────────────────────────────


def test_detect_languages_empty() -> None:
    assert detect_languages([]) == []


def test_detect_languages_turkish_fallback() -> None:
    # Uses Turkish-specific chars — the fallback heuristic must
    # classify this as tr even without langdetect installed.
    guesses = detect_languages(["Merhaba dünya, bu bir test çığlığı"])
    assert guesses
    codes = {g.code for g in guesses}
    # Either langdetect or fallback should pick tr
    assert "tr" in codes or any(g.code == "tr" for g in guesses)


def test_detect_languages_sorted_by_confidence() -> None:
    guesses = detect_languages(["hello world hello world hello"])
    assert guesses == sorted(guesses, key=lambda g: g.confidence, reverse=True)


# ── Timezone inference ─────────────────────────────────────────────


def test_infer_timezones_empty() -> None:
    assert infer_timezones(
        location_strings=[], phone_timezones=[], languages=[]
    ) == []


def test_infer_timezones_phone_dominates() -> None:
    guesses = infer_timezones(
        location_strings=["New York, USA"],
        phone_timezones=["Europe/Istanbul"],
        languages=[],
    )
    assert guesses[0].tz == "Europe/Istanbul"
    assert "phone_region" in guesses[0].reasons


def test_infer_timezones_city_beats_country() -> None:
    guesses = infer_timezones(
        location_strings=["Istanbul, Turkey"],
        phone_timezones=[],
        languages=[],
    )
    assert guesses[0].tz == "Europe/Istanbul"
    assert any(r.startswith("city:") for r in guesses[0].reasons)


def test_infer_timezones_language_weak_tiebreak() -> None:
    guesses = infer_timezones(
        location_strings=[],
        phone_timezones=[],
        languages=[LanguageGuess(code="ja", confidence=0.9)],
    )
    assert guesses
    assert guesses[0].tz == "Asia/Tokyo"


# ── Entity graph ───────────────────────────────────────────────────


def _sample_result() -> ScanResult:
    r = ScanResult(username="alice")
    r.platforms = [
        PlatformResult(
            platform="GitHub",
            url="https://github.com/alice",
            category="dev",
            exists=True,
            profile_data={"bio": "Loves Python", "location": "Istanbul, Turkey"},
        ),
        PlatformResult(
            platform="Twitter",
            url="https://twitter.com/alice",
            category="social",
            exists=False,  # excluded
        ),
    ]
    r.emails = [
        EmailResult(email="alice@example.com", source="gravatar", verified=True,
                    breaches=["LinkedIn2012"])
    ]
    r.phone_intel = [
        PhoneIntel(
            raw="+14155552671", e164="+14155552671",
            country_code=1, region="US", country_name="United States",
            timezones=("America/Los_Angeles",), valid=True,
            sources=("phonenumbers",),
        )
    ]
    r.crypto_intel = [
        CryptoIntel(address="0xabc", chain="eth", balance=1.5, tx_count=10,
                    source="etherscan")
    ]
    r.historical_usernames = [
        HistoricalUsername(
            username="alice_old", platform="twitter.com",
            first_seen="20180101", last_seen="20190101", snapshot_count=5,
        )
    ]
    return r


def test_build_entity_graph_has_expected_nodes() -> None:
    g = build_entity_graph(_sample_result())
    kinds = {g.nodes[n]["kind"] for n in g.nodes}
    assert {"identity", "platform", "email", "breach", "phone", "crypto", "alias"} <= kinds
    # The disabled twitter profile must NOT appear as a platform node
    assert "platform::Twitter" not in g.nodes
    assert "platform::GitHub" in g.nodes


def test_graph_to_dict_is_json_safe() -> None:
    g = build_entity_graph(_sample_result())
    data = graph_to_dict(g)
    assert "nodes" in data
    assert any(n["id"] == "alice" for n in data["nodes"])


# ── Orchestrator ───────────────────────────────────────────────────


def test_run_enrichment_on_sample_result() -> None:
    report = run_enrichment(_sample_result())
    d = report.to_dict()
    assert d["stylometry"] is not None
    assert d["stylometry"]["total_words"] > 0
    assert isinstance(d["languages"], list)
    assert isinstance(d["timezones"], list)
    # Phone timezone should dominate timezone ranking
    if d["timezones"]:
        assert d["timezones"][0]["tz"] == "America/Los_Angeles"
    assert d["graph"]["nodes"]


def test_run_enrichment_empty_result_does_not_crash() -> None:
    report = run_enrichment(ScanResult(username="ghost"))
    d = report.to_dict()
    assert d["stylometry"] is None
    assert d["languages"] == []
    assert d["timezones"] == []
    assert d["graph"]["nodes"]  # at minimum the root identity node
