"""Obscura-backed browser fallback for JS-rendered profiles.

Obscura is an optional external binary. This wrapper deliberately keeps
the same return contract as ``playwright_fallback.fetch_rendered`` so the
scan engine can switch browser backends without changing platform logic.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path

from modules.stealth.playwright_fallback import RenderedPage

log = logging.getLogger(__name__)

_DEFAULT_BINARY = "obscura"


def _binary_path() -> str | None:
    configured = os.environ.get("OSINT_OBSCURA_BIN", "").strip()
    if configured:
        path = Path(configured).expanduser()
        return str(path) if path.is_file() else None
    return shutil.which(_DEFAULT_BINARY)


def is_available() -> bool:
    return _binary_path() is not None


AVAILABLE = is_available()


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
    """Fetch ``url`` via the Obscura CLI.

    The current Obscura ``fetch`` command does not expose HTTP status,
    final URL, proxy, or screenshot output. A successful process is
    therefore treated as status 200, with ``final_url`` set to the input
    URL. Missing binary or render failure returns ``None`` so callers can
    fall back to the normal HTTP path.
    """
    binary = _binary_path()
    if binary is None:
        log.debug("obscura binary not found; skipping rendered fetch for %s", url)
        return None

    wait_seconds = max(1, int((timeout_ms + 999) / 1000))
    cmd = [
        binary,
        "fetch",
        url,
        "--dump",
        "html",
        "--wait-until",
        "domcontentloaded",
        "--wait",
        str(wait_seconds),
        "--quiet",
    ]
    if wait_for_selector:
        cmd.extend(["--selector", wait_for_selector])
    if user_agent:
        cmd.extend(["--user-agent", user_agent])
    if os.environ.get("OSINT_OBSCURA_STEALTH", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        cmd.append("--stealth")

    if proxy:
        log.debug("obscura fetch does not support proxy in this wrapper; ignoring proxy")
    if screenshot_dir is not None or screenshot_name:
        log.debug("obscura fetch does not support screenshots in this wrapper")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=wait_seconds + 5,
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            log.warning("obscura render timed out for %s", url)
            return None
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.warning("obscura render failed for %s: %s", url, exc)
        return None

    if proc.returncode != 0:
        err = stderr.decode("utf-8", "replace").strip()
        log.warning("obscura render failed for %s: %s", url, err or proc.returncode)
        return None

    html = stdout.decode("utf-8", "replace").strip()
    if not html:
        return None

    return RenderedPage(url=url, status=200, html=html, final_url=url)
