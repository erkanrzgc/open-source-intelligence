"""JSON export for scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from core.investigator_summary import build_investigator_summary
from core.models import ScanResult
from core.reporter.console import console


def export_json(result: ScanResult, filepath: str) -> None:
    data = result.to_dict()
    if not data.get("investigator_summary"):
        data["investigator_summary"] = build_investigator_summary(data)
    data["exported_at"] = datetime.now(tz=timezone.utc).isoformat()
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    console.print(f"\n  [green]JSON rapor kaydedildi:[/green] {filepath}")
