"""One-shot GGUF model downloader.

Usage:
    python -m core.analysis.download
    python -m core.analysis.download --repo TheBloke/... --file xx.gguf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.analysis.llm import (
    DEFAULT_CACHE_DIR,
    DEFAULT_MODEL_FILE,
    DEFAULT_REPO_ID,
)


def download(repo_id: str, filename: str, dest_dir: Path) -> Path:
    try:
        from huggingface_hub import hf_hub_download  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "huggingface_hub is not installed. Install with: pip install 'open-source-intelligence[ai]'"
        ) from exc
    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] downloading {repo_id}/{filename} -> {dest_dir}")
    path = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        local_dir=str(dest_dir),
    )
    return Path(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="open-source-intelligence-download-model")
    parser.add_argument("--repo", default=DEFAULT_REPO_ID, help="HF repo id")
    parser.add_argument("--file", default=DEFAULT_MODEL_FILE, help="GGUF filename")
    parser.add_argument(
        "--dest", type=Path, default=DEFAULT_CACHE_DIR, help="Destination directory"
    )
    args = parser.parse_args(argv)
    try:
        path = download(args.repo, args.file, args.dest)
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"[+] saved: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
