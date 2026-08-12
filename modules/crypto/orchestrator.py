"""Crypto OSINT orchestrator."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.crypto import bitcoin, ethereum
from modules.crypto.models import CryptoIntel
from modules.crypto.validators import classify

log = get_logger(__name__)


def classify_address(address: str) -> str | None:
    return classify(address)


async def _safe(
    name: str, coro: Awaitable[CryptoIntel | None]
) -> CryptoIntel | None:
    try:
        return await coro
    except Exception as exc:
        log.debug("crypto source %s failed: %s", name, exc)
        return None


async def lookup_crypto(
    client: HTTPClient,
    addresses: list[str],
) -> list[CryptoIntel]:
    """Resolve every address in ``addresses`` to a :class:`CryptoIntel`.

    Invalid addresses (chain unknown) are dropped silently. Duplicates
    are collapsed case-insensitively so the same ETH address in two
    casings is only looked up once.
    """
    seen: set[str] = set()
    tasks: list[Awaitable[CryptoIntel | None]] = []

    for addr in addresses:
        if not addr:
            continue
        key = addr.lower()
        if key in seen:
            continue
        chain = classify(addr)
        if chain is None:
            continue
        seen.add(key)
        if chain == "btc":
            tasks.append(_safe("blockchain.info", bitcoin.lookup(client, addr)))
        elif chain == "eth":
            tasks.append(_safe("etherscan", ethereum.lookup(client, addr)))

    if not tasks:
        return []
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]
