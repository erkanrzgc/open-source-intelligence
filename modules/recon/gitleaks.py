"""Optional Gitleaks wrapper for local repository/path secret scans.

The GitHub code-search scanner is passive and remote. This module is the
explicit local counterpart: it runs an installed ``gitleaks`` binary against a
caller-provided path and normalizes the JSON report into ``LeakedSecret``
records. Missing binary, missing path, scanner failure, or timeout all degrade
to an empty result so optional scans do not abort the broader OSINT run.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from core.logging_setup import get_logger
from modules.recon.models import LeakedSecret

log = get_logger(__name__)

_DEFAULT_BINARY = "gitleaks"
_DEFAULT_TIMEOUT = 120


def _binary_path(binary: str | None = None) -> str | None:
    configured = (binary or os.environ.get("OSINT_GITLEAKS_BIN", "")).strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path)
        if len(path.parts) == 1:
            return shutil.which(configured)
        return None
    return shutil.which(_DEFAULT_BINARY)


def is_available(binary: str | None = None) -> bool:
    return _binary_path(binary) is not None


def _first_str(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str):
            return value
        if value is not None:
            return str(value)
    return ""


def _local_url(source: Path, file_path: str) -> str:
    path = Path(file_path)
    if not path.is_absolute():
        path = source / path
    try:
        return path.expanduser().absolute().as_uri()
    except ValueError:
        return str(path)


def _report_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("findings", "Findings", "results", "Results"):
            items = data.get(key)
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    return []


def _parse_report(data: Any, source: str | Path) -> list[LeakedSecret]:
    """Normalize a Gitleaks JSON report into ``LeakedSecret`` entries."""
    source_path = Path(source).expanduser()
    repo = source_path.name or str(source_path)
    findings: list[LeakedSecret] = []

    for item in _report_items(data):
        rule_id = _first_str(item, "RuleID", "RuleId", "rule_id", "ruleID")
        value = _first_str(item, "Secret", "secret")
        if not value:
            value = _first_str(item, "Match", "match")
        file_path = _first_str(item, "File", "file")
        if not rule_id or not value:
            continue

        start_line = _first_str(item, "StartLine", "start_line", "startLine")
        fingerprint = _first_str(item, "Fingerprint", "fingerprint")
        finding_repo = _first_str(item, "Repo", "repo") or repo
        snippet = _first_str(item, "Match", "match").strip()[:240]
        metadata = {
            "source": "gitleaks",
            "source_path": str(source_path),
        }
        if start_line:
            metadata["start_line"] = start_line
        if fingerprint:
            metadata["fingerprint"] = fingerprint

        findings.append(
            LeakedSecret(
                rule_id=rule_id,
                value=value,
                repo=finding_repo,
                file_path=file_path,
                url=_local_url(source_path, file_path) if file_path else str(source_path),
                snippet=snippet,
                metadata=metadata,
            )
        )

    return _dedupe(findings)


def _dedupe(findings: list[LeakedSecret]) -> list[LeakedSecret]:
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[LeakedSecret] = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.value,
            finding.repo,
            finding.file_path,
            str(finding.metadata.get("start_line", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


async def scan_path(
    path: str | Path,
    *,
    binary: str | None = None,
    no_git: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
) -> list[LeakedSecret]:
    """Run Gitleaks against ``path`` and return normalized findings.

    ``no_git`` maps to Gitleaks' ``--no-git`` mode for directory snapshots that
    are not Git repositories. The default keeps Gitleaks' normal repository
    behavior, including history-aware scans where supported.
    """
    exe = _binary_path(binary)
    if exe is None:
        log.debug("gitleaks binary not found; skipping local secret scan")
        return []

    source = Path(path).expanduser()
    if not source.exists():
        log.warning("gitleaks source path does not exist: %s", source)
        return []

    with tempfile.TemporaryDirectory(prefix="open-source-intelligence-gitleaks-") as tmp:
        report_path = Path(tmp) / "gitleaks.json"
        cmd = [
            exe,
            "detect",
            "--source",
            str(source),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--exit-code",
            "0",
        ]
        if no_git:
            cmd.append("--no-git")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=max(1, int(timeout)),
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                log.warning("gitleaks scan timed out for %s", source)
                return []
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("gitleaks scan failed for %s: %s", source, exc)
            return []

        if proc.returncode != 0:
            err = stderr.decode("utf-8", "replace").strip()
            log.warning("gitleaks scan failed for %s: %s", source, err or proc.returncode)
            return []

        if not report_path.exists() or report_path.stat().st_size == 0:
            return []

        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("could not parse gitleaks report for %s: %s", source, exc)
            return []

    return _parse_report(data, source)
