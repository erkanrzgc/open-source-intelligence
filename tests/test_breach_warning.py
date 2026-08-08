"""Deterministic tests for breach warning behavior."""

import asyncio

from core import engine
from core.config import ScanConfig
from core.models import CrossReferenceResult


class PrintSpy:
    def __init__(self):
        self.calls = []

    def print(self, message="", *args, **kwargs):
        self.calls.append(str(message))


def test_engine_warns_when_hibp_key_missing(monkeypatch):
    spy = PrintSpy()

    class FakeHTTPClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def fake_discover_emails(client, username, known_emails=None):
        return []

    monkeypatch.setattr(engine, "HTTPClient", FakeHTTPClient)
    monkeypatch.setattr(engine, "PLATFORMS", [])
    monkeypatch.setattr(engine, "discover_emails", fake_discover_emails)
    monkeypatch.setattr(engine, "hibp_available", lambda: False)
    monkeypatch.setattr(engine, "cross_reference", lambda found: CrossReferenceResult())
    monkeypatch.setattr(engine, "console", spy)

    cfg = ScanConfig(username="testuser", deep=False, email=True, breach=True)
    result = asyncio.run(engine.run_scan(cfg))

    assert result.username == "testuser"
    assert any("HIBP_API_KEY" in call for call in spy.calls)
    assert any("skip" in call.lower() for call in spy.calls)
