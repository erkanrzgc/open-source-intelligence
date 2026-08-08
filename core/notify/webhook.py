"""Generic webhook notifier — POSTs the notification as JSON.

Reads ``OSINT_WEBHOOK_URL`` (and optional ``OSINT_WEBHOOK_SECRET``
which, when set, is sent as the ``X-OSINT-Secret`` header for
receiver-side auth) from the environment.
"""

from __future__ import annotations

import os

import aiohttp

from core.logging_setup import get_logger
from core.notify.base import Notification

log = get_logger(__name__)


class WebhookNotifier:
    name = "webhook"

    def __init__(
        self,
        url: str,
        *,
        secret: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = url
        self._secret = secret
        self._timeout = timeout

    @classmethod
    def from_env(cls) -> "WebhookNotifier | None":
        url = os.environ.get("OSINT_WEBHOOK_URL", "").strip()
        if not url:
            return None
        secret = os.environ.get("OSINT_WEBHOOK_SECRET", "").strip() or None
        return cls(url, secret=secret)

    async def send(self, notification: Notification) -> bool:
        headers = {"Content-Type": "application/json"}
        if self._secret:
            headers["X-OSINT-Secret"] = self._secret
        try:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    self._url, json=notification.to_dict(), headers=headers
                ) as resp:
                    if resp.status >= 400:
                        body = await resp.text()
                        log.warning(
                            "webhook notify HTTP %s: %s", resp.status, body[:200]
                        )
                        return False
                    return True
        except (aiohttp.ClientError, OSError) as exc:
            log.warning("webhook notify failed: %s", exc)
            return False
