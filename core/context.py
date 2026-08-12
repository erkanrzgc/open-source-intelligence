"""Mutable state owned by one scan invocation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from core.config import ScanConfig
from core.progress import ProgressEmitter, get_emitter
from modules.providers.models import ProviderCredentials
from modules.stealth.soft_404 import Soft404Cache


@dataclass
class ScanContext:
    """Per-scan caches, budgets, background tasks and progress channel."""

    negative_cache: dict[str, set[str]] = field(default_factory=dict)
    soft_404_cache: Soft404Cache = field(default_factory=Soft404Cache)
    seed_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    skill_budget: Any = None
    emitter: ProgressEmitter | None = None
    provider_credentials: ProviderCredentials = field(
        default_factory=ProviderCredentials
    )
    provider_http_requests: int = 0

    @classmethod
    def create(cls, cfg: ScanConfig) -> ScanContext:
        budget = None
        if cfg.ai_skills or cfg.ai_report:
            from core.analysis.skill_loader import SkillBudget

            budget = SkillBudget(limit=cfg.ai_skill_budget)
        return cls(
            skill_budget=budget,
            emitter=get_emitter(),
            provider_credentials=ProviderCredentials.from_environment(),
        )

    def emit(self, kind: str, **fields: Any) -> None:
        if self.emitter is None:
            return
        from core.progress import ProgressEvent

        phase = str(fields.pop("phase", ""))
        message = str(fields.pop("message", ""))
        self.emitter.emit(
            ProgressEvent(kind=kind, phase=phase, message=message, data=dict(fields))
        )

    def track_seed(self, task: asyncio.Task[Any]) -> None:
        self.seed_tasks.add(task)
        task.add_done_callback(self.seed_tasks.discard)
