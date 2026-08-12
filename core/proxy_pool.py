"""Round-robin proxy pool with dead-proxy pruning.

The pool tracks consecutive failures per proxy and removes one from
rotation once it crosses ``max_consecutive_failures`` (default 3). A
successful request resets the counter. When every proxy is dead the
pool resurrects the list (rather than returning ``None``) so callers
can keep trying — the network path may have recovered meanwhile.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field


@dataclass
class ProxyPool:
    """Thread-safe rotating pool with light health tracking."""

    proxies: tuple[str, ...] = ()
    max_consecutive_failures: int = 3
    _failures: dict[str, int] = field(default_factory=dict)
    _dead: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _cycle: itertools.cycle[str] | None = None

    def __post_init__(self) -> None:
        self.proxies = tuple(p for p in self.proxies if p)
        self._cycle = itertools.cycle(self.proxies) if self.proxies else None

    def __bool__(self) -> bool:
        return bool(self.proxies)

    def __len__(self) -> int:
        return len(self.proxies)

    @property
    def alive(self) -> tuple[str, ...]:
        return tuple(p for p in self.proxies if p not in self._dead)

    def next(self) -> str | None:
        """Return the next alive proxy, or ``None`` if the pool is empty."""
        if not self._cycle:
            return None
        with self._lock:
            if len(self._dead) >= len(self.proxies):
                # Every proxy failed — wipe the graveyard and try again.
                self._dead.clear()
                self._failures.clear()
            for _ in range(len(self.proxies)):
                candidate = next(self._cycle)
                if candidate not in self._dead:
                    return candidate
            return None

    def record_success(self, proxy: str | None) -> None:
        if not proxy:
            return
        with self._lock:
            self._failures.pop(proxy, None)
            self._dead.discard(proxy)

    def record_failure(self, proxy: str | None) -> None:
        if not proxy:
            return
        with self._lock:
            count = self._failures.get(proxy, 0) + 1
            self._failures[proxy] = count
            if count >= self.max_consecutive_failures:
                self._dead.add(proxy)


def load_from_file(path: str) -> tuple[str, ...]:
    """Load a newline-delimited proxy file.

    Blank lines and ``#``-prefixed comments are ignored. Tabs and
    surrounding whitespace are stripped.
    """
    with open(path, encoding="utf-8") as fp:
        items: list[str] = []
        for raw in fp:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)
    return tuple(items)
