"""Headless-browser fallback for JS-rendered / login-walled profiles.

Plain aiohttp fetches fail on sites like Instagram or X that return a
login wall or an empty shell that is hydrated with JS. When the scan
engine decides a URL needs real rendering, it can call ``fetch_rendered``
here and get back the DOM after ``domcontentloaded`` (or a custom
selector) has fired.

Browser priority:
    1. Patchright (stealth Playwright fork, 30/30 bot-detection tests)
    2. Playwright  (standard, requires manual stealth patches)
    3. None        (aiohttp-only fallback)

All are **optional** dependencies. The module imports cleanly without
any of them and exposes ``AVAILABLE = False``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── browser backend selection ──────────────────────────────────────────
_async_playwright: Any = None
_BACKEND = ""

try:
    from patchright.async_api import (
        async_playwright as _patchright_playwright,  # type: ignore[import-not-found]
    )
    _async_playwright = _patchright_playwright
    _BACKEND = "patchright"
    AVAILABLE = True
except ImportError:
    try:
        from playwright.async_api import (  # type: ignore[import-not-found]
            async_playwright as _pw,
        )
        _async_playwright = _pw
        _BACKEND = "playwright"
        AVAILABLE = True
    except ImportError:  # pragma: no cover - optional dep
        AVAILABLE = False

log.debug("browser backend: %s (available=%s)", _BACKEND or "none", AVAILABLE)


@dataclass(frozen=True)
class RenderedPage:
    url: str
    status: int
    html: str
    final_url: str
    screenshot_path: str | None = None


_SAFE_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


def _slugify(value: str) -> str:
    return _SAFE_SLUG.sub("_", value).strip("_") or "page"


async def fetch_rendered(
    url: str,
    *,
    user_agent: str | None = None,
    wait_for_selector: str | None = None,
    timeout_ms: int = 15000,
    proxy: str | None = None,
    screenshot_dir: Path | None = None,
    screenshot_name: str | None = None,
) -> RenderedPage | None:
    """Fetch ``url`` via a headless Chromium (Patchright or Playwright).

    Returns None if no browser is installed or the render failed. Callers
    should treat None as "fallback unavailable, move on". When
    ``screenshot_dir`` is provided a PNG is saved inside it and the path
    is returned on ``RenderedPage.screenshot_path``.
    """
    if not AVAILABLE:
        log.debug("no browser backend installed; skipping rendered fetch for %s", url)
        return None

    try:
        async with _async_playwright() as pw:  # type: ignore[misc]
            launch_args: dict[str, object] = {"headless": True}
            if proxy:
                launch_args["proxy"] = {"server": proxy}
            browser = await pw.chromium.launch(**launch_args)  # type: ignore[arg-type]
            try:
                context = await browser.new_context(user_agent=user_agent)
                page = await context.new_page()
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=timeout_ms
                )
                if wait_for_selector:
                    try:
                        await page.wait_for_selector(
                            wait_for_selector, timeout=timeout_ms
                        )
                    except Exception:
                        log.debug("selector %s not found on %s", wait_for_selector, url)
                html = await page.content()
                status = response.status if response else 0
                final_url = page.url
                shot_path: str | None = None
                if screenshot_dir is not None:
                    try:
                        screenshot_dir.mkdir(parents=True, exist_ok=True)
                        filename = f"{_slugify(screenshot_name or final_url)}.png"
                        dest = screenshot_dir / filename
                        await page.screenshot(path=str(dest), full_page=False)
                        shot_path = str(dest)
                    except Exception as exc:
                        log.debug("screenshot save failed for %s: %s", url, exc)
                return RenderedPage(
                    url=url,
                    status=status,
                    html=html,
                    final_url=final_url,
                    screenshot_path=shot_path,
                )
            finally:
                await browser.close()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.debug("browser render failed for %s: %s", url, exc)
        return None
