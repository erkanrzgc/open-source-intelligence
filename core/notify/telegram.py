"""Telegram Bot API notifier.

Reads ``OSINT_TELEGRAM_BOT_TOKEN`` and ``OSINT_TELEGRAM_CHAT_ID``
from the environment. If either is missing, :func:`from_env` returns
``None`` so the scheduler silently skips Telegram delivery.
"""

from __future__ import annotations

import os

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from core.notify.base import Notification

log = get_logger(__name__)

_API_BASE = "https://api.telegram.org"


class TelegramNotifier:
    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str, *, timeout: float = 10.0) -> None:
        self._token = bot_token
        self._chat_id = chat_id
        self._timeout = timeout

    @classmethod
    def from_env(cls) -> TelegramNotifier | None:
        token = os.environ.get("OSINT_TELEGRAM_BOT_TOKEN", "").strip()
        chat = os.environ.get("OSINT_TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat:
            return None
        return cls(token, chat)

    async def send(self, notification: Notification) -> bool:
        text = f"*{notification.title}*\n{notification.body}"
        url = f"{_API_BASE}/bot{self._token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        try:
            async with HTTPClient(request_timeout=self._timeout) as client:
                status, _body, _elapsed = await client.post_json(url, payload)
            if status <= 0 or status >= 400:
                log.warning("telegram notify HTTP %s", status)
                return False
            return True
        except (OSError, ValueError) as exc:
            log.warning("telegram notify failed: %s", exc)
            return False
