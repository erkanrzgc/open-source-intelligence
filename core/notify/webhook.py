"""Generic webhook notifier — POSTs the notification as JSON.

Reads ``OSINT_WEBHOOK_URL`` (and optional ``OSINT_WEBHOOK_SECRET``
which, when set, is sent as the ``X-OSINT-Secret`` header for
receiver-side auth) from the environment.
"""

from __future__ import annotations

import os

from core.http_client import HTTPClient
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
        allow_private_networks: bool = False,
    ) -> None:
        self._url = url
        self._secret = secret
        self._timeout = timeout
        self._allow_private_networks = allow_private_networks

    @classmethod
    def from_env(cls) -> WebhookNotifier | None:
        url = os.environ.get("OSINT_WEBHOOK_URL", "").strip()
        if not url:
            return None
        secret = os.environ.get("OSINT_WEBHOOK_SECRET", "").strip() or None
        allow_private = os.environ.get(
            "OSINT_WEBHOOK_ALLOW_PRIVATE_NETWORKS", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
        return cls(url, secret=secret, allow_private_networks=allow_private)

    async def send(self, notification: Notification) -> bool:
        headers = {"Content-Type": "application/json"}
        if self._secret:
            headers["X-OSINT-Secret"] = self._secret
        try:
            async with HTTPClient(
                request_timeout=self._timeout,
                allow_private_networks=self._allow_private_networks,
            ) as client:
                status, _body, _elapsed = await client.post_json(
                    self._url,
                    notification.to_dict(),
                    headers,
                )
            if status <= 0 or status >= 400:
                log.warning("webhook notify HTTP %s", status)
                return False
            return True
        except (OSError, ValueError) as exc:
            log.warning("webhook notify failed: %s", exc)
            return False
