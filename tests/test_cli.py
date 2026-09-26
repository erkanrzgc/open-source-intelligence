from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from core import cli
from core.models import PlatformResult, ScanResult


def test_scan_result_from_dict_roundtrip():
    res = ScanResult(
        username="alice",
        platforms=[
            PlatformResult(
                platform="GitHub",
                url="https://github.com/alice",
                category="dev",
                exists=True,
                status="found",
                confidence=1.0,
            )
        ],
        scan_time=1.23,
    )
    d = res.to_dict()
    reconstructed = ScanResult.from_dict(d)
    assert reconstructed.username == "alice"
    assert len(reconstructed.platforms) == 1
    assert reconstructed.platforms[0].platform == "GitHub"
    assert reconstructed.platforms[0].exists is True
    assert reconstructed.platforms[0].confidence == 1.0


def test_cli_scan_args_parsing():
    with patch("core.cli.run_scan", new_callable=AsyncMock) as mock_run, patch(
        "core.cli.complete_scan_result"
    ) as mock_complete, patch("core.cli._show_result"):
        mock_run.return_value = ScanResult(username="bob")
        mock_complete.return_value = MagicMock(payload={"username": "bob", "platforms": []})

        code = cli.main(
            [
                "scan",
                "bob",
                "--full-name",
                "Bob Smith",
                "--phone",
                "+14155552671",
                "--phone-region",
                "US",
                "--crypto",
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "--dns",
                "--subdomain",
                "--passive",
                "--reverse-image",
                "--geocode",
                "--tor",
                "--proxy",
                "socks5://127.0.0.1:9050",
            ]
        )
        assert code == 0
        assert mock_run.called
        cfg = mock_run.call_args[0][0]
        assert cfg.username == "bob"
        assert cfg.full_name == "Bob Smith"
        assert cfg.phone == "+14155552671"
        assert cfg.phone_region == "US"
        assert cfg.crypto_addresses == ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",)
        assert cfg.dns is True
        assert cfg.subdomain is True
        assert cfg.passive is True
        assert cfg.reverse_image is True
        assert cfg.geocode is True
        assert cfg.tor is True
        assert cfg.proxy == "socks5://127.0.0.1:9050"


def test_cli_export_file(tmp_path: Path):
    sample = {
        "username": "charlie",
        "total_checked": 1,
        "found_count": 1,
        "scan_time": 0.5,
        "platforms": [
            {
                "platform": "GitLab",
                "url": "https://gitlab.com/charlie",
                "category": "dev",
                "exists": True,
                "status": "found",
                "confidence": 1.0,
            }
        ],
    }
    input_file = tmp_path / "scan.json"
    input_file.write_text(json.dumps(sample), encoding="utf-8")
    out_html = tmp_path / "report.html"

    code = cli.main(["export", str(input_file), "--format", "html", "-o", str(out_html)])
    assert code == 0
    assert out_html.is_file()
    assert "charlie" in out_html.read_text(encoding="utf-8")


def test_cli_export_history(tmp_path: Path):
    sample = {
        "username": "david",
        "total_checked": 0,
        "found_count": 0,
        "scan_time": 0.1,
        "platforms": [],
    }
    mock_entry = MagicMock(payload=sample)
    with patch("core.history.get_latest", return_value=mock_entry):
        out_json = tmp_path / "out.json"
        code = cli.main(["export", "david", "--format", "json", "-o", str(out_json)])
        assert code == 0
        assert out_json.is_file()
        assert "david" in out_json.read_text(encoding="utf-8")


def test_cli_export_invalid_target():
    with patch("core.history.get_latest", return_value=None):
        code = cli.main(["export", "nonexistent_target", "--format", "html", "-o", "dummy.html"])
        assert code == 1
