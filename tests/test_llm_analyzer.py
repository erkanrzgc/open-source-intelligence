"""Tests for core/analysis/llm.py — stub backend, no real model loaded."""

import json

import pytest

from core.analysis.llm import (
    AIReport,
    Backend,
    LLMAnalyzer,
    LLMUnavailable,
    parse_report,
)
from core.analysis.prompts import build_user_prompt
from core.models import ScanResult


class StubBackend:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    async def complete(
        self, system: str, user: str, *, max_tokens: int, temperature: float
    ) -> str:
        self.calls.append((system, user))
        return self.response


def _sample_payload() -> dict:
    return {
        "username": "alice",
        "found_count": 2,
        "platforms": [
            {
                "platform": "GitHub",
                "url": "https://github.com/alice",
                "category": "dev",
                "exists": True,
                "profile_data": {
                    "name": "Alice",
                    "bio": "dev",
                    "location": "TR",
                    "followers": 10,
                    "some_noise_key": "drop me",
                },
            },
            {
                "platform": "GhostNet",
                "url": "https://gn/alice",
                "category": "social",
                "exists": False,
            },
        ],
        "emails": [
            {
                "email": "a@b.com",
                "source": "gravatar",
                "breach_count": 1,
                "breaches": [{"Name": "Leak1"}],
            }
        ],
        "discovered_usernames": ["alice_dev"],
        "whois_records": [],
        "web_presence": [],
        "cross_reference": {"confidence": 80.0},
    }


def test_parse_report_plain_json():
    raw = json.dumps(
        {
            "identity_summary": "Alice is a TR dev",
            "strong_linkages": ["GitHub bio matches Reddit"],
            "exposures": ["HIGH: email in Leak1"],
            "next_steps": ["Check HIBP for a@b.com"],
            "confidence": 85,
        }
    )
    report = parse_report(raw)
    assert report.identity_summary == "Alice is a TR dev"
    assert report.confidence == 85
    assert len(report.strong_linkages) == 1


def test_parse_report_fenced_json():
    raw = "```json\n" + json.dumps({"identity_summary": "ok", "confidence": 50}) + "\n```"
    report = parse_report(raw)
    assert report.identity_summary == "ok"
    assert report.confidence == 50


def test_parse_report_with_leading_prose():
    raw = "Here you go:\n{\"identity_summary\": \"x\", \"confidence\": 10}"
    report = parse_report(raw)
    assert report.identity_summary == "x"


def test_parse_report_invalid_json_raises():
    with pytest.raises(LLMUnavailable):
        parse_report("not json at all")


def test_parse_report_non_object_raises():
    with pytest.raises(LLMUnavailable):
        parse_report("[1, 2, 3]")


def test_parse_report_coerces_confidence():
    report = parse_report(json.dumps({"confidence": "nan"}))
    assert report.confidence == 0
    report2 = parse_report(json.dumps({"confidence": 250}))
    assert report2.confidence == 100
    report3 = parse_report(json.dumps({"confidence": -5}))
    assert report3.confidence == 0


def test_parse_report_filters_non_list_fields():
    raw = json.dumps(
        {
            "identity_summary": "x",
            "strong_linkages": "not-a-list",
            "exposures": [None, "ok"],
            "confidence": 0,
        }
    )
    report = parse_report(raw)
    assert report.strong_linkages == []
    assert report.exposures == ["ok"]


async def test_analyze_with_stub_backend():
    stub = StubBackend(
        json.dumps(
            {
                "identity_summary": "Alice, Turkish dev",
                "strong_linkages": ["GitHub location=TR"],
                "exposures": ["MED: 1 breach on a@b.com"],
                "next_steps": ["query Reddit /u/alice"],
                "confidence": 72,
            }
        )
    )
    analyzer = LLMAnalyzer(backend=stub)
    report = await analyzer.analyze(_sample_payload())

    assert isinstance(report, AIReport)
    assert report.confidence == 72
    assert report.identity_summary.startswith("Alice")
    assert stub.calls, "backend should have been called"
    # Prompt must embed the trimmed scan payload
    _, user_msg = stub.calls[0]
    assert "alice" in user_msg
    assert "GitHub" in user_msg
    # Noise key should have been stripped by _trim_profile
    assert "some_noise_key" not in user_msg
    # Not-found platforms should be stripped
    assert "GhostNet" not in user_msg


async def test_analyze_without_backend_raises():
    analyzer = LLMAnalyzer(backend=None)
    with pytest.raises(LLMUnavailable):
        await analyzer.analyze(_sample_payload())


async def test_analyze_backend_bad_json_propagates():
    analyzer = LLMAnalyzer(backend=StubBackend("totally broken"))
    with pytest.raises(LLMUnavailable):
        await analyzer.analyze(_sample_payload())


def test_build_user_prompt_contains_schema():
    prompt = build_user_prompt(_sample_payload())
    assert "RESPONSE_SCHEMA" in prompt
    assert "identity_summary" in prompt
    assert "alice" in prompt


def test_ai_report_to_dict_roundtrip():
    report = AIReport(
        identity_summary="x", strong_linkages=["a"], confidence=55
    )
    d = report.to_dict()
    assert d["identity_summary"] == "x"
    assert d["strong_linkages"] == ["a"]
    assert d["confidence"] == 55
    # Ensure it plugs into ScanResult cleanly
    r = ScanResult(username="alice", ai_report=d)
    assert r.to_dict()["ai_report"]["confidence"] == 55


def test_backend_protocol_accepts_stub():
    # Compile-time check that StubBackend satisfies Backend
    backend: Backend = StubBackend("{}")
    assert hasattr(backend, "complete")
