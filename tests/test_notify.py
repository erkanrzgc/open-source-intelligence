"""Tests for the notification layer."""

from __future__ import annotations

from typing import ClassVar

import pytest

from core.notify import telegram as telegram_module
from core.notify import webhook as webhook_module
from core.notify.base import Notification
from core.notify.dispatcher import build_default_notifiers, notify_all
from core.notify.telegram import TelegramNotifier
from core.notify.webhook import WebhookNotifier


class _FakeNotifier:
    name = "fake"

    def __init__(self, *, fail: bool = False, raise_exc: bool = False) -> None:
        self.calls: list[Notification] = []
        self.fail = fail
        self.raise_exc = raise_exc

    async def send(self, notification: Notification) -> bool:
        if self.raise_exc:
            raise RuntimeError("boom")
        self.calls.append(notification)
        return not self.fail


class _FakeHTTPClient:
    response: tuple[int, dict | None, float] = (200, {}, 0.01)
    calls: ClassVar[list[tuple[str, dict, dict | None]]] = []

    def __init__(self, **_kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post_json(self, url, json_body, headers=None):
        self.calls.append((url, json_body, headers))
        return self.response


def test_notification_to_dict_roundtrip():
    n = Notification(
        kind="scan_diff",
        username="alice",
        title="t",
        body="b",
        data={"added": ["x"]},
    )
    d = n.to_dict()
    assert d["kind"] == "scan_diff"
    assert d["username"] == "alice"
    assert d["data"] == {"added": ["x"]}


@pytest.mark.asyncio
async def test_notify_all_fans_out_to_every_sink():
    a, b = _FakeNotifier(), _FakeNotifier()
    n = Notification(kind="scan_complete", username="u", title="t", body="b")
    results = await notify_all(n, [a, b])
    assert results == {"fake": True}  # Both sinks share name="fake" → dict collapses
    # Both sinks actually received the event.
    assert len(a.calls) == 1 and len(b.calls) == 1


@pytest.mark.asyncio
async def test_notify_all_isolates_exceptions():
    good = _FakeNotifier()
    bad = _FakeNotifier(raise_exc=True)
    bad.name = "bad"
    n = Notification(kind="scan_complete", username="u", title="t", body="b")
    results = await notify_all(n, [good, bad])
    assert results["fake"] is True
    assert results["bad"] is False
    assert len(good.calls) == 1


@pytest.mark.asyncio
async def test_notify_all_empty_sinks_returns_empty():
    n = Notification(kind="scan_complete", username="u", title="t", body="b")
    out = await notify_all(n, [])
    assert out == {}


def test_telegram_from_env_none_without_credentials(monkeypatch):
    monkeypatch.delenv("OSINT_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("OSINT_TELEGRAM_CHAT_ID", raising=False)
    assert TelegramNotifier.from_env() is None


def test_telegram_from_env_builds_when_set(monkeypatch):
    monkeypatch.setenv("OSINT_TELEGRAM_BOT_TOKEN", "abc")
    monkeypatch.setenv("OSINT_TELEGRAM_CHAT_ID", "123")
    n = TelegramNotifier.from_env()
    assert isinstance(n, TelegramNotifier)
    assert n.name == "telegram"


def test_webhook_from_env_none_without_url(monkeypatch):
    monkeypatch.delenv("OSINT_WEBHOOK_URL", raising=False)
    assert WebhookNotifier.from_env() is None


def test_webhook_from_env_builds_when_set(monkeypatch):
    monkeypatch.setenv("OSINT_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("OSINT_WEBHOOK_SECRET", "s3cret")
    n = WebhookNotifier.from_env()
    assert isinstance(n, WebhookNotifier)
    assert n._secret == "s3cret"


def test_build_default_notifiers_picks_up_configured_sinks(monkeypatch):
    monkeypatch.delenv("OSINT_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("OSINT_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setenv("OSINT_WEBHOOK_URL", "https://example.com/hook")
    sinks = build_default_notifiers()
    assert [s.name for s in sinks] == ["webhook"]


def test_build_default_notifiers_empty_when_nothing_configured(monkeypatch):
    for var in (
        "OSINT_TELEGRAM_BOT_TOKEN",
        "OSINT_TELEGRAM_CHAT_ID",
        "OSINT_WEBHOOK_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    assert build_default_notifiers() == []


@pytest.mark.asyncio
async def test_webhook_send_uses_shared_http_client(monkeypatch):
    _FakeHTTPClient.calls = []
    _FakeHTTPClient.response = (204, None, 0.01)
    monkeypatch.setattr(webhook_module, "HTTPClient", _FakeHTTPClient)
    notification = Notification(
        kind="scan_complete", username="alice", title="done", body="ok"
    )
    notifier = WebhookNotifier("https://hooks.example/notify", secret="shared")

    assert await notifier.send(notification) is True
    url, payload, headers = _FakeHTTPClient.calls[0]
    assert url == "https://hooks.example/notify"
    assert payload["username"] == "alice"
    assert headers == {"Content-Type": "application/json", "X-OSINT-Secret": "shared"}


@pytest.mark.asyncio
async def test_telegram_send_uses_shared_http_client(monkeypatch):
    _FakeHTTPClient.calls = []
    _FakeHTTPClient.response = (200, {"ok": True}, 0.01)
    monkeypatch.setattr(telegram_module, "HTTPClient", _FakeHTTPClient)
    notification = Notification(
        kind="scan_complete", username="alice", title="done", body="ok"
    )

    assert await TelegramNotifier("secret-token", "42").send(notification) is True
    url, payload, headers = _FakeHTTPClient.calls[0]
    assert url.endswith("/botsecret-token/sendMessage")
    assert payload["chat_id"] == "42"
    assert headers is None
