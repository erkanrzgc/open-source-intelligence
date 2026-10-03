"""Reproducible, network-free identity regression report."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from core.evaluation import evaluate_dataset
from core.version import __version__

DEFAULT_DATASET = Path(__file__).parent / "fixtures" / "identity_benchmark.json"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="Fail on false strong matches")
    args = parser.parse_args(argv)
    try:
        dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
        report = evaluate_dataset(dataset)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(f"invalid benchmark dataset: {exc}")
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["tool_version"] = __version__
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized)
    return int(args.check and report["metrics"]["false_positive"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
