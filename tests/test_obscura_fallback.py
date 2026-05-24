"""Tests for the optional Obscura browser fallback wrapper."""

from __future__ import annotations

import asyncio

import pytest

from modules.stealth import obscura_fallback


class _Proc:
    def __init__(self, *, returncode: int = 0, stdout: bytes = b"<html>ok</html>"):
        self.returncode = returncode
        self._stdout = stdout

    async def communicate(self):
        return self._stdout, b""

    def kill(self):  # pragma: no cover - timeout path only
        self.returncode = -9

    async def wait(self):  # pragma: no cover - timeout path only
        return self.returncode


@pytest.mark.asyncio
async def test_fetch_rendered_invokes_obscura(monkeypatch) -> None:
    captured: dict = {}

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(obscura_fallback, "_binary_path", lambda: "/bin/obscura")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    page = await obscura_fallback.fetch_rendered(
        "https://example.com",
        wait_for_selector="main",
        timeout_ms=5000,
    )

    assert page is not None
    assert page.status == 200
    assert page.html == "<html>ok</html>"
    assert captured["cmd"][:3] == ("/bin/obscura", "fetch", "https://example.com")
    assert "--selector" in captured["cmd"]
    assert "main" in captured["cmd"]


@pytest.mark.asyncio
async def test_fetch_rendered_returns_none_without_binary(monkeypatch) -> None:
    monkeypatch.setattr(obscura_fallback, "_binary_path", lambda: None)
    assert await obscura_fallback.fetch_rendered("https://example.com") is None


@pytest.mark.asyncio
async def test_fetch_rendered_returns_none_on_nonzero(monkeypatch) -> None:
    async def fake_exec(*cmd, **kwargs):
        return _Proc(returncode=1, stdout=b"")

    monkeypatch.setattr(obscura_fallback, "_binary_path", lambda: "/bin/obscura")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    assert await obscura_fallback.fetch_rendered("https://example.com") is None
