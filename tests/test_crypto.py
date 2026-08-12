"""Tests for the Sprint 4 crypto OSINT module."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.crypto import bitcoin, ethereum, lookup_crypto
from modules.crypto.models import CryptoIntel
from modules.crypto.validators import classify

# ── Validators ──────────────────────────────────────────────────────


def test_classify_btc_legacy() -> None:
    assert classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"


def test_classify_btc_bech32() -> None:
    assert classify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "btc"


def test_classify_eth() -> None:
    assert classify("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0") == "eth"


def test_classify_rejects_garbage() -> None:
    assert classify("") is None
    assert classify("not an address") is None
    assert classify("0x1234") is None  # too short for eth


def test_crypto_intel_to_dict_roundtrip() -> None:
    intel = CryptoIntel(
        address="0xabc",
        chain="eth",
        balance=1.5,
        balance_raw=1500000000000000000,
        tx_count=42,
        source="etherscan",
    )
    d = intel.to_dict()
    assert d["chain"] == "eth"
    assert d["tx_count"] == 42
    assert d["balance"] == 1.5


# ── Bitcoin (blockchain.info) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_bitcoin_lookup_parses_rawaddr() -> None:
    payload = {
        "hash160": "deadbeef",
        "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "n_tx": 2,
        "total_received": 5_000_000_000,   # 50 BTC
        "total_sent": 1_000_000_000,       # 10 BTC
        "final_balance": 4_000_000_000,    # 40 BTC
        "txs": [
            {"time": 1_700_000_000, "hash": "tx-latest"},
            {"time": 1_600_000_000, "hash": "tx-oldest"},
        ],
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://blockchain\.info/rawaddr/.*"), payload=payload)
        async with HTTPClient() as client:
            intel = await bitcoin.lookup(
                client, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            )
    assert intel is not None
    assert intel.chain == "btc"
    assert intel.balance == 40.0
    assert intel.total_received == 50.0
    assert intel.total_sent == 10.0
    assert intel.tx_count == 2
    assert intel.first_seen.startswith("2020-")
    assert intel.last_seen.startswith("2023-")


@pytest.mark.asyncio
async def test_bitcoin_lookup_handles_error() -> None:
    with aioresponses() as m:
        m.get(re.compile(r"https://blockchain\.info/rawaddr/.*"), status=500)
        async with HTTPClient() as client:
            intel = await bitcoin.lookup(
                client, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            )
    assert intel is None


# ── Ethereum (Etherscan) ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ethereum_lookup_requires_key(monkeypatch) -> None:
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    async with HTTPClient() as client:
        assert await ethereum.lookup(
            client, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        ) is None


@pytest.mark.asyncio
async def test_ethereum_lookup_parses_balance_and_txs(monkeypatch) -> None:
    monkeypatch.setenv("ETHERSCAN_API_KEY", "fake")
    bal_payload = {"status": "1", "message": "OK", "result": "2500000000000000000"}
    tx_payload = {
        "status": "1",
        "message": "OK",
        "result": [
            {"timeStamp": "1700000000", "hash": "0xa"},
            {"timeStamp": "1600000000", "hash": "0xb"},
        ],
    }

    call_count = {"n": 0}

    def callback(url, **kwargs):
        call_count["n"] += 1
        import json

        from aioresponses.core import CallbackResult

        if "action=balance" in str(url):
            return CallbackResult(status=200, body=json.dumps(bal_payload),
                                  headers={"Content-Type": "application/json"})
            # (headers ensure get_json treats body as JSON)
        return CallbackResult(status=200, body=json.dumps(tx_payload),
                              headers={"Content-Type": "application/json"})

    with aioresponses() as m:
        m.get(re.compile(r"https://api\.etherscan\.io/.*"), callback=callback, repeat=True)
        async with HTTPClient() as client:
            intel = await ethereum.lookup(
                client, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
            )
    assert intel is not None
    assert intel.chain == "eth"
    assert intel.balance == pytest.approx(2.5)
    assert intel.tx_count == 2


# ── Orchestrator ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_crypto_routes_btc(monkeypatch) -> None:
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    payload = {"n_tx": 0, "total_received": 0, "total_sent": 0, "final_balance": 0, "txs": []}
    with aioresponses() as m:
        m.get(re.compile(r"https://blockchain\.info/rawaddr/.*"), payload=payload)
        async with HTTPClient() as client:
            intel = await lookup_crypto(
                client, ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
            )
    assert len(intel) == 1
    assert intel[0].chain == "btc"


@pytest.mark.asyncio
async def test_lookup_crypto_dedupes_and_drops_invalid(monkeypatch) -> None:
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    payload = {"n_tx": 0, "total_received": 0, "total_sent": 0, "final_balance": 0, "txs": []}
    with aioresponses() as m:
        m.get(
            re.compile(r"https://blockchain\.info/rawaddr/.*"),
            payload=payload,
            repeat=True,
        )
        async with HTTPClient() as client:
            intel = await lookup_crypto(
                client,
                [
                    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # dup
                    "not-an-address",
                ],
            )
    assert len(intel) == 1
