"""Language detection with an optional ``langdetect`` dependency.

If ``langdetect`` is installed we run it on each sample and aggregate
the per-language confidence. Without it we fall back to a character
unigram heuristic that can only distinguish a handful of scripts —
enough to split "Latin w/ Turkish diacritics", "Latin", "Cyrillic",
"Arabic", "CJK". The fallback is intentionally coarse; it exists so
the module never returns nothing.
"""

from __future__ import annotations

from collections import defaultdict

from modules.analysis.models import LanguageGuess

try:
    from langdetect import DetectorFactory, detect_langs  # type: ignore[import-not-found]

    DetectorFactory.seed = 0  # reproducible
    _LANGDETECT = True
except ImportError:  # pragma: no cover - optional dep
    detect_langs = None  # type: ignore[assignment]
    _LANGDETECT = False


_TR_CHARS = set("ğĞıİşŞçÇöÖüÜ")


def _fallback(sample: str) -> str:
    """Coarse script-based classifier."""
    if not sample:
        return "und"
    counts: dict[str, int] = defaultdict(int)
    # Presence of Turkish diacritics is a strong signal even when most
    # letters are plain Latin — weight them heavily so "Merhaba dünya"
    # classifies as tr instead of en.
    for ch in sample:
        o = ord(ch)
        if ch in _TR_CHARS:
            counts["tr"] += 10
        elif 0x0400 <= o <= 0x04FF:
            counts["ru"] += 1
        elif 0x0600 <= o <= 0x06FF:
            counts["ar"] += 1
        elif 0x4E00 <= o <= 0x9FFF:
            counts["zh"] += 1
        elif 0x3040 <= o <= 0x30FF:
            counts["ja"] += 1
        elif ch.isalpha():
            counts["en"] += 1
    if not counts:
        return "und"
    return max(counts.items(), key=lambda kv: kv[1])[0]


def detect_languages(samples: list[str]) -> list[LanguageGuess]:
    """Return a confidence-ordered list of language guesses."""
    cleaned = [s.strip() for s in samples if s and s.strip()]
    if not cleaned:
        return []

    per_lang: dict[str, list[float]] = defaultdict(list)

    if _LANGDETECT and detect_langs is not None:
        for sample in cleaned:
            try:
                for guess in detect_langs(sample):
                    per_lang[guess.lang].append(float(guess.prob))
            except Exception:
                code = _fallback(sample)
                per_lang[code].append(0.4)
    else:
        for sample in cleaned:
            code = _fallback(sample)
            per_lang[code].append(0.6)

    results: list[LanguageGuess] = []
    for code, probs in per_lang.items():
        confidence = sum(probs) / len(probs)
        results.append(LanguageGuess(code=code, confidence=confidence))

    results.sort(key=lambda g: g.confidence, reverse=True)
    return results
