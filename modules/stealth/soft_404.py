"""Soft-404 detection via baseline body fingerprinting.

Many sites return HTTP 200 for non-existent profiles — they redirect to the
homepage, render a "create your account" splash, or serve a search page. A
``check_type=status`` platform definition cannot distinguish those from real
matches on its own, so we maintain a per-platform baseline: fetch the URL
with a deliberately-impossible username once, hash the normalised body, and
compare every real scan against it.

Algorithm
~~~~~~~~~
1. ``_normalise`` strips timestamps, CSRF tokens, random IDs and the
   probe-username substring so the fingerprint stays stable across runs.
2. ``_simhash`` produces a 64-bit fingerprint via a simple feature-bag
   approach (token shingles).  Hamming-distance comparison is cheap and
   robust to small template changes.
3. Baselines are cached on disk for 7 days so we pay the probe cost at
   most once per platform per week.

The module is intentionally self-contained and dependency-free so it can
be invoked from anywhere in the scan pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


_IMPOSSIBLE_USERNAME = "__zzz_nonexistent_probe_9999__"
_BASELINE_TTL_SECONDS = 7 * 24 * 3600  # 7 days
_DEFAULT_CACHE_DIR = Path(
    os.environ.get(
        "CYBERM4FIA_SOFT404_CACHE",
        str(Path.home() / ".cache" / "cyberm4fia" / "soft404"),
    )
)
SIMHASH_HAMMING_THRESHOLD = 6  # ≤6 bits different ⇒ same template

# Strip volatile fragments so two fetches of the same template hash equal.
_VOLATILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bcsrf[_-]?token['\"=:\s]+[A-Za-z0-9+/=_-]{8,}", re.IGNORECASE),
    re.compile(r"\bnonce[\"'=:\s]+[A-Za-z0-9+/=_-]{8,}", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{16,64}\b"),  # long hex ids
    re.compile(r"\b\d{10,}\b"),  # epoch timestamps
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}"),  # ISO timestamps
    re.compile(r"\s+"),  # collapse whitespace last
)


def _normalise(body: str, probe_username: str | None = None) -> str:
    """Remove volatile noise so two fetches of the same template are equal."""
    cleaned = body
    for pat in _VOLATILE_PATTERNS:
        cleaned = pat.sub(" ", cleaned)
    if probe_username:
        cleaned = cleaned.replace(probe_username, "USERNAME")
        cleaned = cleaned.replace(probe_username.lower(), "USERNAME")
    return cleaned.strip().lower()


def _simhash(text: str, *, ngram: int = 4) -> int:
    """Compute a 64-bit SimHash over character n-grams.

    Lightweight: ~O(n) and dependency-free. Hamming distance between two
    SimHashes correlates with template similarity.
    """
    if not text:
        return 0
    bits = [0] * 64
    # Use character n-grams (4-gram works well for HTML templates).
    seen: dict[str, int] = {}
    for i in range(len(text) - ngram + 1):
        gram = text[i : i + ngram]
        seen[gram] = seen.get(gram, 0) + 1
    if not seen:
        return 0
    for gram, weight in seen.items():
        h = int.from_bytes(
            hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest(),
            "big",
        )
        for b in range(64):
            if (h >> b) & 1:
                bits[b] += weight
            else:
                bits[b] -= weight
    fingerprint = 0
    for b in range(64):
        if bits[b] >= 0:
            fingerprint |= 1 << b
    return fingerprint


def _hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


@dataclass(frozen=True)
class Soft404Baseline:
    platform: str
    fingerprint: int
    status: int
    body_length: int
    recorded_at: float

    def is_fresh(self) -> bool:
        return time.time() - self.recorded_at < _BASELINE_TTL_SECONDS

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "body_length": self.body_length,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Soft404Baseline:
        return cls(
            platform=data["platform"],
            fingerprint=int(data["fingerprint"]),
            status=int(data["status"]),
            body_length=int(data["body_length"]),
            recorded_at=float(data["recorded_at"]),
        )


def _slug(platform: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", platform.lower()).strip("_") or "platform"


class Soft404Cache:
    """Disk-backed baseline cache, one JSON file per platform.

    Safe to instantiate per scan; lookups are O(1) once loaded.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root else _DEFAULT_CACHE_DIR
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.debug("soft404 cache dir unwritable: %s", exc)

    def _path(self, platform: str) -> Path:
        return self.root / f"{_slug(platform)}.json"

    def get(self, platform: str) -> Soft404Baseline | None:
        path = self._path(platform)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            log.debug("soft404 cache read failed for %s: %s", platform, exc)
            return None
        try:
            baseline = Soft404Baseline.from_dict(data)
        except (KeyError, ValueError, TypeError):
            return None
        if not baseline.is_fresh():
            return None
        return baseline

    def put(self, baseline: Soft404Baseline) -> None:
        path = self._path(baseline.platform)
        try:
            path.write_text(
                json.dumps(baseline.to_dict(), ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            log.debug("soft404 cache write failed for %s: %s", baseline.platform, exc)


def make_baseline(
    *, platform: str, status: int, body: str, probe_username: str | None = None
) -> Soft404Baseline:
    """Fingerprint a body. Caller has already fetched it with an impossible name."""
    probe = probe_username or _IMPOSSIBLE_USERNAME
    fp = _simhash(_normalise(body, probe))
    return Soft404Baseline(
        platform=platform,
        fingerprint=fp,
        status=status,
        body_length=len(body),
        recorded_at=time.time(),
    )


def is_soft_404(
    *,
    platform: str,
    status: int,
    body: str,
    real_username: str,
    baseline: Soft404Baseline | None,
) -> tuple[bool, str | None]:
    """Compare a real fetch against the stored baseline.

    Returns ``(is_soft, reason)``. ``reason`` is a short human-readable
    signal name suitable for ``PlatformResult.fp_signals``. ``baseline``
    may be ``None`` — in which case no judgment is made.
    """
    if baseline is None or not body:
        return False, None
    # Mismatch on HTTP status is a strong "different page" signal.
    if status != baseline.status:
        return False, None
    # If the body is wildly different in size, the template is unlikely to
    # be the same — early exit avoids noisy normalisation work.
    if baseline.body_length and abs(len(body) - baseline.body_length) > max(
        500, baseline.body_length * 2
    ):
        return False, None
    real_fp = _simhash(_normalise(body, real_username))
    distance = _hamming(real_fp, baseline.fingerprint)
    if distance <= SIMHASH_HAMMING_THRESHOLD:
        return True, f"soft_404_template:hamming={distance}"
    return False, None


IMPOSSIBLE_USERNAME = _IMPOSSIBLE_USERNAME  # public alias for engine use
