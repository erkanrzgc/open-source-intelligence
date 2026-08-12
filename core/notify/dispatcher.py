"""Fan-out dispatcher that sends a notification to every configured sink."""

from __future__ import annotations

import asyncio

from core.logging_setup import get_logger
from core.notify.base import Notification, Notifier
from core.notify.telegram import TelegramNotifier
from core.notify.webhook import WebhookNotifier

log = get_logger(__name__)


def build_default_notifiers() -> list[Notifier]:
    """Return every notifier whose credentials are present in the env."""
    sinks: list[Notifier] = []
    tg = TelegramNotifier.from_env()
    if tg is not None:
        sinks.append(tg)
    wh = WebhookNotifier.from_env()
    if wh is not None:
        sinks.append(wh)
    return sinks


async def notify_all(
    notification: Notification, notifiers: list[Notifier] | None = None
) -> dict[str, bool]:
    """Fan out to every notifier in parallel.

    Returns a ``{notifier_name: success}`` dict so callers can log partial
    failures without halting scheduler progress.
    """
    sinks = notifiers if notifiers is not None else build_default_notifiers()
    if not sinks:
        log.debug("notify: no sinks configured, skipping %s", notification.kind)
        return {}

    async def _one(n: Notifier) -> tuple[str, bool]:
        try:
            ok = await n.send(notification)
        except Exception as exc:
            log.warning("notifier %s raised: %s", n.name, exc)
            ok = False
        return n.name, ok

    pairs = await asyncio.gather(*(_one(n) for n in sinks))
    return dict(pairs)
