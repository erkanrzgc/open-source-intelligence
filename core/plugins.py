"""Lightweight plugin loader.

A plugin is any ``.py`` file in one of the plugin directories that
exposes a top-level ``register(registry)`` callable. The registry
exposes hook points the plugin can subscribe to — currently only
``post_scan(result, cfg)``.

Plugins are discovered from (in order):

1. ``./plugins/`` relative to the working directory
2. ``~/.config/open-source-intelligence/plugins/``
3. Any extra paths passed explicitly to :func:`load_plugins`

We deliberately keep the API minimal — a plugin that just wants to
dump results into its own store looks like::

    def register(registry):
        def on_scan(result, cfg):
            ...
        registry.post_scan(on_scan)
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from core.config import ScanConfig
from core.logging_setup import get_logger
from core.models import ScanResult

log = get_logger(__name__)

PostScanHook = Callable[[ScanResult, ScanConfig], None]


@dataclass
class PluginRegistry:
    """Registry handed to each plugin's ``register()`` function."""

    _post_scan: list[PostScanHook] = field(default_factory=list)

    def post_scan(self, hook: PostScanHook) -> None:
        """Register a function to run after every scan completes."""
        self._post_scan.append(hook)

    def run_post_scan(self, result: ScanResult, cfg: ScanConfig) -> dict[str, int]:
        completed = 0
        failed = 0
        for hook in self._post_scan:
            try:
                hook(result, cfg)
                completed += 1
            except Exception as exc:
                failed += 1
                log.warning("plugin post_scan hook failed: %s", exc)
        return {"hooks": len(self._post_scan), "completed": completed, "failed": failed}

    @property
    def post_scan_hooks(self) -> list[PostScanHook]:
        return list(self._post_scan)


DEFAULT_PLUGIN_DIRS: tuple[Path, ...] = (
    Path.cwd() / "plugins",
    Path.home() / ".config" / "open-source-intelligence" / "plugins",
)


def _iter_plugin_files(dirs: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for d in dirs:
        if not d.exists() or not d.is_dir():
            continue
        for p in sorted(d.glob("*.py")):
            if p.name.startswith("_"):
                continue
            files.append(p)
    return files


def load_plugins(
    *,
    extra_dirs: Iterable[Path] | None = None,
    registry: PluginRegistry | None = None,
) -> PluginRegistry:
    """Discover and register plugins. Returns the populated registry."""
    registry = registry or PluginRegistry()
    dirs = list(DEFAULT_PLUGIN_DIRS) + list(extra_dirs or ())
    for path in _iter_plugin_files(dirs):
        module_name = f"open_source_intelligence_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            log.warning("plugin load failed for %s: %s", path, exc)
            continue

        register = getattr(module, "register", None)
        if not callable(register):
            log.debug("plugin %s has no register() — skipping", path.name)
            continue
        try:
            register(registry)
        except Exception as exc:
            log.warning("plugin %s register() failed: %s", path.name, exc)
    return registry
