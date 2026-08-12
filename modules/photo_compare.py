"""Profile photo comparison via perceptual hashing."""

from __future__ import annotations

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)

# Keep image decoding off the event loop without touching asyncio's default
# executor. A short-lived one-worker pool per hash avoids a runtime edge case
# where a second callback from a shared pool is delivered only when a timer
# wakes the loop, which was the source of the historical suite hang.
DEFAULT_DOWNLOAD_TIMEOUT = 15.0
DEFAULT_HASH_TIMEOUT = 10.0
MAX_IMAGE_BYTES = 20 * 1024 * 1024

try:
    import imagehash
    from PIL import Image
    _HAS_IMAGEHASH = True
except ImportError:
    _HAS_IMAGEHASH = False
    log.debug("imagehash/Pillow not installed; falling back to md5 comparison")


def _hash_bytes(data: bytes) -> dict:
    """CPU-bound: decode image and compute perceptual hashes. Called via to_thread."""
    out: dict = {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "size": len(data),
    }
    looks_like_image = data.startswith(
        (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")
    ) or (len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP")
    if not _HAS_IMAGEHASH or not looks_like_image:
        return out
    try:
        img = Image.open(BytesIO(data)).convert("RGB")
        out["phash"] = str(imagehash.phash(img))
        out["dhash"] = str(imagehash.dhash(img))
        out["width"] = img.width
        out["height"] = img.height
    except (OSError, ValueError) as exc:
        log.debug("image decode failed: %s", exc)
    return out


async def fetch_and_hash(
    client: HTTPClient,
    url: str,
    *,
    download_timeout: float = DEFAULT_DOWNLOAD_TIMEOUT,
    hash_timeout: float = DEFAULT_HASH_TIMEOUT,
) -> dict | None:
    if not url or not url.startswith(("http://", "https://")):
        return None

    try:
        status, data, _ = await asyncio.wait_for(
            client.get_bytes(url), timeout=max(0.1, download_timeout)
        )
    except asyncio.TimeoutError:
        log.debug("photo download timed out: %s", url)
        return None
    if status != 200 or not data:
        return None
    if len(data) > MAX_IMAGE_BYTES:
        log.debug("photo exceeds size limit: %s (%d bytes)", url, len(data))
        return None

    # Offload CPU-bound decode+hash to a worker thread so the event loop
    # keeps issuing HTTP requests while images are being processed.
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="osint-photo")
    try:
        hashed = await asyncio.wait_for(
            loop.run_in_executor(executor, _hash_bytes, data),
            timeout=max(0.1, hash_timeout),
        )
    except asyncio.TimeoutError:
        log.debug("photo hashing timed out: %s", url)
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return {"url": url, **hashed}


def compare_phashes(h1: str, h2: str) -> float:
    """Returns similarity 0.0-1.0 between two perceptual hashes."""
    if not _HAS_IMAGEHASH or not h1 or not h2:
        return 1.0 if h1 == h2 else 0.0
    try:
        hash1 = imagehash.hex_to_hash(h1)
        hash2 = imagehash.hex_to_hash(h2)
        diff = hash1 - hash2
        return max(0.0, 1.0 - diff / 64.0)
    except (ValueError, TypeError) as exc:
        log.debug("phash compare failed: %s", exc)
        return 0.0


async def compare_profile_photos(
    client: HTTPClient,
    photo_urls: list[tuple[str, str]],
    *,
    timeout: float = 30.0,
    max_concurrent: int = 8,
) -> list[dict]:
    """Given list of (platform, url) tuples, hash and compare all photos.
    Returns list of match dicts {p1, p2, similarity}."""
    if len(photo_urls) < 2:
        return []

    semaphore = asyncio.Semaphore(max(1, max_concurrent))

    async def _bounded(url: str) -> dict | None:
        async with semaphore:
            return await fetch_and_hash(
                client,
                url,
                download_timeout=min(DEFAULT_DOWNLOAD_TIMEOUT, max(0.1, timeout)),
                hash_timeout=min(DEFAULT_HASH_TIMEOUT, max(0.1, timeout)),
            )

    tasks = [asyncio.create_task(_bounded(url)) for _, url in photo_urls]
    try:
        fetched = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=max(0.1, timeout),
        )
    except asyncio.TimeoutError:
        # Preserve work that finished before the batch deadline, cancel the
        # rest, and return comparisons from the partial result set.
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        fetched = [
            task.result() if task.done() and not task.cancelled() and task.exception() is None else None
            for task in tasks
        ]
    hash_results: list[tuple[str, dict]] = []
    for (platform, _url), h in zip(photo_urls, fetched, strict=True):
        if isinstance(h, dict):
            hash_results.append((platform, h))

    matches = []
    for i, (p1, h1) in enumerate(hash_results):
        for p2, h2 in hash_results[i + 1:]:
            phash1 = h1.get("phash", "")
            phash2 = h2.get("phash", "")
            if phash1 and phash2:
                sim = compare_phashes(phash1, phash2)
                if sim > 0.7:
                    matches.append({
                        "platform_a": p1,
                        "platform_b": p2,
                        "similarity": round(sim, 2),
                        "method": "phash",
                    })
            elif h1.get("md5") == h2.get("md5"):
                matches.append({
                    "platform_a": p1,
                    "platform_b": p2,
                    "similarity": 1.0,
                    "method": "md5",
                })

    return matches


def imagehash_available() -> bool:
    return _HAS_IMAGEHASH
