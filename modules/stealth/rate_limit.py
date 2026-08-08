"""Per-domain adaptive rate limiting.

Two jobs:

1. **Polite pacing.** Enforce a minimum interval between requests to the same
   host, with a small random jitter so we don't look like a metronome.
2. **Adaptive backoff.** When a host hands back HTTP 429 / 503, exponentially
   increase its cooldown so we stop hammering it. Successful requests slowly
   decay that penalty back to baseline.

Everything is keyed by eTLD+1-ish host string — the caller passes whatever
host it already has. No DNS, no suffix-list parsing here.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field


@dataclass
class _HostState:
    next_allowed: float = 0.0
    penalty: float = 0.0  # extra cooldown (seconds) layered on top of interval
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class DomainRateBucket:
    """Async per-domain token bucket with adaptive 429 cooldown.

    Parameters
    ----------
    min_interval:
        Minimum seconds between two requests to the same host.
    jitter:
        Upper bound on a uniform random delay added to each wait.
    max_penalty:
        Hard cap on the adaptive backoff so a stuck host can't freeze the scan
        forever.
    """

    def __init__(
        self,
        *,
        min_interval: float = 1.0,
        jitter: float = 0.5,
        max_penalty: float = 60.0,
        global_delay: float = 0.0,
    ) -> None:
        self._min_interval = min_interval
        self._jitter = jitter
        self._max_penalty = max_penalty
        self._hosts: dict[str, _HostState] = {}
        self._global_lock = asyncio.Lock()
        self._global_delay = global_delay
        self._last_global: float = 0.0

    async def _state(self, host: str) -> _HostState:
        async with self._global_lock:
            state = self._hosts.get(host)
            if state is None:
                state = _HostState()
                self._hosts[host] = state
            return state

    def _jitter_value(self) -> float:
        if self._jitter <= 0:
            return 0.0
        # secrets.randbelow gives uniform int in [0, N); scale to [0, jitter).
        return (secrets.randbelow(1000) / 1000.0) * self._jitter

    async def acquire(self, host: str) -> None:
        """Block until it is polite to hit ``host`` again."""
        # Global throttle — minimum delay between any two requests
        if self._global_delay > 0:
            async with self._global_lock:
                now = time.monotonic()
                wait = (self._last_global + self._global_delay) - now
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = time.monotonic()
                self._last_global = now

        state = await self._state(host)
        async with state.lock:
            now = time.monotonic()
            wait = state.next_allowed - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            state.next_allowed = (
                now + self._min_interval + state.penalty + self._jitter_value()
            )

    async def record_success(self, host: str) -> None:
        """Successful request — decay any accumulated penalty."""
        state = await self._state(host)
        async with state.lock:
            if state.penalty > 0:
                state.penalty = max(0.0, state.penalty / 2.0 - 0.1)

    async def record_throttled(self, host: str, *, retry_after: float | None = None) -> None:
        """429/503 seen — raise the cooldown for this host.

        If the server told us ``Retry-After`` we honor it directly; otherwise
        we double the current penalty (starting at 2s) up to ``max_penalty``.
        """
        state = await self._state(host)
        async with state.lock:
            if retry_after is not None and retry_after > 0:
                state.penalty = min(self._max_penalty, float(retry_after))
            else:
                state.penalty = min(
                    self._max_penalty, max(2.0, state.penalty * 2 or 2.0)
                )
            state.next_allowed = time.monotonic() + state.penalty

    def snapshot(self) -> dict[str, float]:
        """Debug helper: current penalty per host."""
        return {host: st.penalty for host, st in self._hosts.items()}
