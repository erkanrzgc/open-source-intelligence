"""Tests for the optional local Gitleaks wrapper."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from modules.recon import gitleaks


class _Proc:
    def __init__(self, *, returncode: int = 0):
        self.returncode = returncode

    async def communicate(self):
        return b"", b""

    def kill(self):  # pragma: no cover - timeout path only
        self.returncode = -9

    async def wait(self):  # pragma: no cover - timeout path only
        return self.returncode


def test_binary_path_accepts_plain_binary_name(monkeypatch) -> None:
    monkeypatch.delenv("OSINT_GITLEAKS_BIN", raising=False)
    monkeypatch.setattr(gitleaks.shutil, "which", lambda name: f"/usr/bin/{name}")

    assert gitleaks._binary_path("gitleaks") == "/usr/bin/gitleaks"


def test_binary_path_accepts_env_binary_name(monkeypatch) -> None:
    monkeypatch.setenv("OSINT_GITLEAKS_BIN", "gitleaks")
    monkeypatch.setattr(gitleaks.shutil, "which", lambda name: f"/opt/bin/{name}")

    assert gitleaks._binary_path() == "/opt/bin/gitleaks"


def test_parse_report_normalizes_gitleaks_findings(tmp_path: Path) -> None:
    report = [
        {
            "RuleID": "generic-api-key",
            "Secret": "dummy-secret-value",
            "Match": "API_KEY=dummy-secret-value",
            "File": "src/config.py",
            "StartLine": 12,
            "Fingerprint": "repo:src/config.py:generic-api-key:12",
        }
    ]

    findings = gitleaks._parse_report(report, tmp_path)

    assert len(findings) == 1
    hit = findings[0]
    assert hit.rule_id == "generic-api-key"
    assert hit.value == "dummy-secret-value"
    assert hit.repo == tmp_path.name
    assert hit.file_path == "src/config.py"
    assert hit.url.endswith("/src/config.py")
    assert hit.metadata["source"] == "gitleaks"
    assert hit.metadata["start_line"] == "12"


@pytest.mark.asyncio
async def test_scan_path_invokes_gitleaks_and_reads_report(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, tuple[str, ...]] = {}

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "private-key",
                        "Secret": "dummy-private-key",
                        "File": "keys/prod.pem",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return _Proc()

    monkeypatch.setattr(gitleaks, "_binary_path", lambda binary=None: "/bin/gitleaks")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    findings = await gitleaks.scan_path(tmp_path, no_git=True, timeout=5)

    assert len(findings) == 1
    assert findings[0].rule_id == "private-key"
    assert captured["cmd"][:2] == ("/bin/gitleaks", "detect")
    assert "--source" in captured["cmd"]
    assert str(tmp_path) in captured["cmd"]
    assert "--no-git" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--exit-code") + 1] == "0"


@pytest.mark.asyncio
async def test_scan_path_returns_empty_without_binary(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(gitleaks, "_binary_path", lambda binary=None: None)
    assert await gitleaks.scan_path(tmp_path) == []
