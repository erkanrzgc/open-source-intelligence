"""ProxyPool rotation + health tracking tests."""

from __future__ import annotations

from pathlib import Path

from core.proxy_pool import ProxyPool, load_from_file


def test_empty_pool_returns_none() -> None:
    pool = ProxyPool()
    assert pool.next() is None
    assert not pool


def test_single_proxy_cycles() -> None:
    pool = ProxyPool(proxies=("http://a:1",))
    assert pool.next() == "http://a:1"
    assert pool.next() == "http://a:1"


def test_round_robin_order() -> None:
    pool = ProxyPool(proxies=("http://a", "http://b", "http://c"))
    got = [pool.next() for _ in range(6)]
    assert got == [
        "http://a", "http://b", "http://c",
        "http://a", "http://b", "http://c",
    ]


def test_dead_proxy_is_skipped_after_threshold() -> None:
    pool = ProxyPool(
        proxies=("http://a", "http://b"),
        max_consecutive_failures=2,
    )
    # Burn a: two failures -> dead
    pool.record_failure("http://a")
    pool.record_failure("http://a")
    # Now rotation should only yield b
    got = {pool.next() for _ in range(10)}
    assert got == {"http://b"}
    assert "http://a" not in pool.alive


def test_success_resets_failure_count() -> None:
    pool = ProxyPool(
        proxies=("http://a",), max_consecutive_failures=3,
    )
    pool.record_failure("http://a")
    pool.record_failure("http://a")
    pool.record_success("http://a")
    # Two more failures should NOT kill it (counter was reset).
    pool.record_failure("http://a")
    pool.record_failure("http://a")
    assert "http://a" in pool.alive


def test_all_dead_pool_resurrects() -> None:
    pool = ProxyPool(
        proxies=("http://a", "http://b"),
        max_consecutive_failures=1,
    )
    pool.record_failure("http://a")
    pool.record_failure("http://b")
    assert pool.alive == ()
    # next() must not return None — it resurrects.
    nxt = pool.next()
    assert nxt in {"http://a", "http://b"}


def test_record_ignores_unknown_proxy() -> None:
    pool = ProxyPool(proxies=("http://a",))
    pool.record_failure(None)
    pool.record_failure("")
    pool.record_success(None)
    assert pool.next() == "http://a"


# ── load_from_file ─────────────────────────────────────────────────


def test_load_from_file_skips_blanks_and_comments(tmp_path: Path) -> None:
    f = tmp_path / "pool.txt"
    f.write_text(
        "\n"
        "# a comment\n"
        "http://one:8080\n"
        "  http://two:8080  \n"
        "\n"
        "# trailing\n"
        "socks5://tor:9050\n"
    )
    assert load_from_file(str(f)) == (
        "http://one:8080",
        "http://two:8080",
        "socks5://tor:9050",
    )


# ── HTTPClient integration ─────────────────────────────────────────


def test_http_client_builds_pool_for_http_proxies() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient(proxies=["http://a", "http://b"])
    assert client._pool is not None
    assert client._next_http_proxy() in {"http://a", "http://b"}


def test_http_client_no_pool_when_only_socks() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient(proxies=["socks5://tor:9050"])
    # SOCKS must bypass the HTTP pool (they bind at connector level).
    assert client._pool is None
    assert client._next_http_proxy() is None
