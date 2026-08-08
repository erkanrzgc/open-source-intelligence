"""Telegram Bot API notifier.

Reads ``OSINT_TELEGRAM_BOT_TOKEN`` and ``OSINT_TELEGRAM_CHAT_ID``
from the environment. If either is missing, :func:`from_env` returns
``None`` so the scheduler silently skips Telegram delivery.
"""

from __future__ import annotations

import os

import aiohttp

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
    def from_env(cls) -> "TelegramNotifier | None":
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
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status >= 400:
                        body = await resp.text()
                        log.warning(
                            "telegram notify HTTP %s: %s", resp.status, body[:200]
                        )
                        return False
                    return True
        except (aiohttp.ClientError, OSError) as exc:
            log.warning("telegram notify failed: %s", exc)
            return False
