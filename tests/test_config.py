"""Tests for core/config.py."""

from argparse import Namespace

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


def _args(**overrides):
    defaults = dict(
        no_deep=False,
        smart=False,
        email=False,
        web=False,
        whois=False,
        breach=False,
        photo=False,
        dns=False,
        subdomain=False,
        full=False,
        category=None,
        proxy=None,
        tor=False,
        timeout=None,
    )
    defaults.update(overrides)
    return Namespace(**defaults)


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

    def test_from_args_basic(self):
        cfg = ScanConfig.from_args(_args(smart=True), "alice")
        assert cfg.smart is True
        assert cfg.deep is True
        assert cfg.username == "alice"

    def test_from_args_full_enables_everything(self):
        cfg = ScanConfig.from_args(_args(full=True), "alice")
        assert cfg.deep is True
        assert cfg.smart is True
        assert cfg.email is True
        assert cfg.web is True
        assert cfg.whois is True
        assert cfg.breach is True
        assert cfg.photo is True
        assert cfg.dns is True
        assert cfg.subdomain is True

    def test_from_args_breach_implies_email(self):
        cfg = ScanConfig.from_args(_args(breach=True), "alice")
        assert cfg.email is True

    def test_from_args_categories(self):
        cfg = ScanConfig.from_args(_args(category="social, dev"), "alice")
        assert cfg.categories == ("social", "dev")

    def test_from_args_browser_backend(self):
        cfg = ScanConfig.from_args(_args(browser_backend="obscura"), "alice")
        assert cfg.browser_backend == "obscura"

    def test_from_args_gitleaks(self):
        cfg = ScanConfig.from_args(
            _args(
                gitleaks_path=["/tmp/repo", " "],
                gitleaks_no_git=True,
                gitleaks_timeout=7,
            ),
            "alice",
        )
        assert cfg.gitleaks_paths == ("/tmp/repo",)
        assert cfg.gitleaks_no_git is True
        assert cfg.gitleaks_timeout == 7
        assert "GitLeaks" in cfg.mode_parts()

    def test_from_args_no_deep(self):
        cfg = ScanConfig.from_args(_args(no_deep=True), "alice")
        assert cfg.deep is False

    def test_mode_parts(self):
        cfg = ScanConfig(
            username="a", deep=True, smart=True, email=True, browser_backend="obscura"
        )
        parts = cfg.mode_parts()
        assert "Deep" in parts
        assert "Smart" in parts
        assert "Email" in parts
        assert "Obscura" in parts

    def test_mode_parts_empty(self):
        cfg = ScanConfig(username="a", deep=False, enrichment=False)
        assert cfg.mode_parts() == []
