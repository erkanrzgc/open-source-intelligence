"""Sprint 11: Playwright fallback routing + screenshot wiring."""

from __future__ import annotations

import pytest

from core import engine as engine_mod
from core.config import ScanConfig
from core.engine import _check_platform, _screenshot_dir_for, _should_render
from core.platform_loader import Platform
from modules.stealth import playwright_fallback as pw_mod

JS_HEAVY = Platform(
    name="Instagram",
    url="https://www.instagram.com/{username}/",
    category="social",
    check_type="content_absent",
    error_text="Sorry, this page isn't available",
    js_heavy=True,
)
PLAIN = Platform(
    name="GitHub",
    url="https://github.com/{username}",
    category="dev",
)
JSON_API = Platform(
    name="NPM",
    url="https://registry.npmjs.org/-/v1/search?text={username}",
    category="dev",
    check_type="json_api",
)


def test_should_render_false_when_playwright_missing(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", False)
    cfg = ScanConfig(username="alice")
    assert _should_render(JS_HEAVY, cfg) is False


def test_should_render_true_for_js_heavy_when_available(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)
    cfg = ScanConfig(username="alice")
    assert _should_render(JS_HEAVY, cfg) is True


def test_should_render_false_for_plain_without_force(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)
    cfg = ScanConfig(username="alice")
    assert _should_render(PLAIN, cfg) is False


def test_should_render_true_for_plain_when_forced(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)
    cfg = ScanConfig(username="alice", playwright=True)
    assert _should_render(PLAIN, cfg) is True


def test_should_render_respects_no_auto_render_for_js_heavy(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)
    cfg = ScanConfig(username="alice", no_auto_render=True)
    assert _should_render(JS_HEAVY, cfg) is False


def test_should_render_skips_json_api(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)
    cfg = ScanConfig(username="alice", playwright=True)
    assert _should_render(JSON_API, cfg) is False


def test_should_render_uses_obscura_backend(monkeypatch):
    monkeypatch.setattr(
        engine_mod.obscura_fallback, "is_available", lambda: True
    )
    cfg = ScanConfig(username="alice", browser_backend="obscura")
    assert _should_render(JS_HEAVY, cfg) is True


def test_should_render_false_when_obscura_missing(monkeypatch):
    monkeypatch.setattr(
        engine_mod.obscura_fallback, "is_available", lambda: False
    )
    cfg = ScanConfig(username="alice", browser_backend="obscura")
    assert _should_render(JS_HEAVY, cfg) is False


def test_screenshot_dir_off_by_default():
    cfg = ScanConfig(username="alice")
    assert _screenshot_dir_for(cfg) is None


def test_screenshot_dir_uses_username(tmp_path):
    cfg = ScanConfig(
        username="alice", screenshots=True, screenshot_dir=str(tmp_path)
    )
    d = _screenshot_dir_for(cfg)
    assert d is not None
    assert d == tmp_path / "alice"


@pytest.mark.asyncio
async def test_check_platform_uses_playwright_for_js_heavy(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)

    class _Client:
        async def get(self, *a, **kw):  # pragma: no cover - should not be called
            raise AssertionError("aiohttp path must not run for js_heavy")

        async def get_json(self, *a, **kw):  # pragma: no cover
            raise AssertionError("json_api path must not run here")

    calls: dict = {}

    async def fake_fetch(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return pw_mod.RenderedPage(
            url=url,
            status=200,
            html="<html><body>hello alice</body></html>",
            final_url=url,
            screenshot_path=str(tmp_path / "alice" / "Instagram.png"),
        )

    monkeypatch.setattr(engine_mod, "fetch_rendered", fake_fetch)

    cfg = ScanConfig(
        username="alice", screenshots=True, screenshot_dir=str(tmp_path)
    )
    result = await _check_platform(_Client(), cfg, JS_HEAVY)

    assert result.rendered is True
    assert result.http_status == 200
    assert result.exists is True
    assert result.screenshot_path.endswith("Instagram.png")
    # Playwright saw the right URL and screenshot dir.
    assert calls["url"] == "https://www.instagram.com/alice/"
    assert calls["kwargs"]["screenshot_dir"] == tmp_path / "alice"


@pytest.mark.asyncio
async def test_check_platform_falls_back_to_aiohttp_when_render_fails(monkeypatch):
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)

    class _Client:
        calls = 0

        async def get(self, url, headers=None):
            _Client.calls += 1
            return (200, "<html>alice lives here</html>", 0.01)

        async def get_json(self, *a, **kw):  # pragma: no cover
            raise AssertionError

    async def fake_fetch(url, **kwargs):
        return None  # simulate render failure

    monkeypatch.setattr(engine_mod, "fetch_rendered", fake_fetch)

    cfg = ScanConfig(username="alice")
    result = await _check_platform(_Client(), cfg, JS_HEAVY)

    assert _Client.calls == 1
    assert result.rendered is False
    assert result.screenshot_path is None
    assert result.http_status == 200


@pytest.mark.asyncio
async def test_check_platform_uses_obscura_backend(monkeypatch):
    monkeypatch.setattr(
        engine_mod.obscura_fallback, "is_available", lambda: True
    )

    class _Client:
        async def get(self, *a, **kw):  # pragma: no cover - should not be called
            raise AssertionError("aiohttp path must not run when obscura renders")

        async def get_json(self, *a, **kw):  # pragma: no cover
            raise AssertionError

    calls: dict = {}

    async def fake_fetch(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return pw_mod.RenderedPage(
            url=url,
            status=200,
            html="<html><body>alice</body></html>",
            final_url=url,
        )

    monkeypatch.setattr(engine_mod.obscura_fallback, "fetch_rendered", fake_fetch)

    cfg = ScanConfig(username="alice", browser_backend="obscura")
    result = await _check_platform(_Client(), cfg, JS_HEAVY)

    assert result.rendered is True
    assert result.exists is True
    assert calls["url"] == "https://www.instagram.com/alice/"


def test_rendered_page_exposes_screenshot_path():
    page = pw_mod.RenderedPage(
        url="u", status=200, html="h", final_url="u", screenshot_path="/tmp/x.png"
    )
    assert page.screenshot_path == "/tmp/x.png"


def test_slugify_sanitises_unsafe_chars():
    assert pw_mod._slugify("Twitter / X") == "Twitter_X"
    assert pw_mod._slugify("") == "page"


@pytest.mark.asyncio
async def test_short_body_browser_recheck_uses_score_contract(monkeypatch):
    """Regression: the rendered re-score used obsolete score_match kwargs."""
    monkeypatch.setattr(engine_mod, "PLAYWRIGHT_AVAILABLE", True)
    platform = Platform(
        name="ShortProfile",
        url="https://profiles.example/{username}",
        category="social",
        check_type="content_absent",
        absence_strings=("profile not found",),
    )

    class _Client:
        async def get_with_meta(self, url, headers=None):
            return 200, "<html><body>alice</body></html>", 0.01, url

    rendered_body = (
        "<html><head><title>alice profile</title>"
        '<link rel="canonical" href="https://profiles.example/alice">'
        "</head><body><h1>alice</h1><img class='avatar' src='/alice.jpg'>"
        "<p>Bio: active researcher with 42 posts.</p>" + (" activity" * 80) + "</body></html>"
    )

    async def fake_fetch(url, **kwargs):
        return pw_mod.RenderedPage(url=url, status=200, html=rendered_body, final_url=url)

    monkeypatch.setattr(engine_mod, "fetch_rendered", fake_fetch)
    result = await _check_platform(_Client(), ScanConfig(username="alice"), platform)

    assert result.rendered is True
    assert result.exists is True
    assert "pw_rescore" in result.fp_signals
    assert result.confidence >= 0.45
