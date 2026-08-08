"""Tests for core/config.py."""

from core.config import ScanConfig, _env_float, _env_int


def test_env_int_default(monkeypatch):
    monkeypatch.delenv("TEST_K", raising=False)
    assert _env_int("TEST_K", 5) == 5


def test_env_int_valid(monkeypatch):
    monkeypatch.setenv("TEST_K", "42")
    assert _env_int("TEST_K", 5) == 42


def test_env_int_invalid(monkeypatch):
    monkeypatch.setenv("TEST_K", "not-a-number")
    assert _env_int("TEST_K", 5) == 5


def test_env_float_default(monkeypatch):
    monkeypatch.delenv("TEST_F", raising=False)
    assert _env_float("TEST_F", 1.5) == 1.5


def test_env_float_valid(monkeypatch):
    monkeypatch.setenv("TEST_F", "3.14")
    assert _env_float("TEST_F", 0.0) == 3.14


def test_env_float_invalid(monkeypatch):
    monkeypatch.setenv("TEST_F", "abc")
    assert _env_float("TEST_F", 2.0) == 2.0


class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(username="alice")
        assert cfg.username == "alice"
        assert cfg.deep is True
        assert cfg.smart is False
        assert cfg.categories is None
        assert cfg.browser_backend == "playwright"

    def test_frozen(self):
        cfg = ScanConfig(username="alice")
        try:
            cfg.username = "bob"  # type: ignore[misc]
        except Exception:
            return
        raise AssertionError("ScanConfig should be frozen")
