"""Tests for the Cytoscape.js payload converter."""

from __future__ import annotations

from core.api.cytoscape import payload_to_cytoscape


def test_empty_payload_has_identity_only():
    out = payload_to_cytoscape({"username": "alice"})
    assert len(out["nodes"]) == 1
    assert out["nodes"][0]["data"] == {
        "id": "alice",
        "label": "alice",
        "kind": "identity",
    }
    assert out["edges"] == []


def test_platforms_skip_nonexistent():
    payload = {
        "username": "u",
        "platforms": [
            {"platform": "A", "url": "x", "category": "c", "exists": True},
            {"platform": "B", "url": "y", "category": "c", "exists": False},
        ],
    }
    out = payload_to_cytoscape(payload)
    ids = {n["data"]["id"] for n in out["nodes"]}
    assert "platform::A" in ids
    assert "platform::B" not in ids


def test_breach_dedupe_across_emails():
    payload = {
        "username": "u",
        "emails": [
            {"email": "a@x", "source": "s", "breaches": ["LinkedIn"]},
            {"email": "b@x", "source": "s", "breaches": ["LinkedIn"]},
        ],
    }
    out = payload_to_cytoscape(payload)
    breach_nodes = [n for n in out["nodes"] if n["data"]["kind"] == "breach"]
    assert len(breach_nodes) == 1


def test_phone_and_crypto_nodes():
    payload = {
        "username": "u",
        "phone_intel": [{"e164": "+15551234", "country_name": "US"}],
        "crypto_intel": [{"address": "0xabc", "chain": "eth", "balance": 1.5}],
    }
    out = payload_to_cytoscape(payload)
    ids = {n["data"]["id"] for n in out["nodes"]}
    assert "phone::+15551234" in ids
    assert "crypto::0xabc" in ids


def test_identity_candidate_alias_node():
    out = payload_to_cytoscape(
        {
            "username": "alice",
            "identity_candidates": [
                {"username": "alice_dev", "verdict": "likely_same", "score": 0.8}
            ],
        }
    )
    alias = next(node for node in out["nodes"] if node["data"]["id"] == "alias::alice_dev")
    assert alias["data"]["verdict"] == "likely_same"
    assert any(edge["data"]["relation"] == "identity_candidate" for edge in out["edges"])
