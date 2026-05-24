"""Generate plausible usernames from a real name.

Used by the ``--name`` CLI mode. Given a full name like "Erkan Rizgic" we
emit ~20 candidate handles ordered by likelihood, then the scan engine
runs each one through the standard platform sweep. The top FP-scored
hits across all candidates are presented to the user as a ranked list.

Strategy
~~~~~~~~
1. **Normalise**: Turkish diacritics fold to ASCII (``ı→i, ş→s, ğ→g,
   ç→c, ö→o, ü→u``), lowercase, collapse whitespace. Same logic is
   applied for Spanish/Portuguese/German diacritics (``ñ, ó, ü, ß``).
2. **Combine**: first + last, last + first, with separators
   (``.``, ``_``, ``-``, ``""``).
3. **Truncate**: initials + last (``erizgic``, ``e.rizgic``).
4. **Compress**: drop vowels from surname (``rzgic``, ``erkanrzgic``).
5. **Decorate**: append common suffixes (``official``, ``real``, year,
   single digits).

Each candidate gets a heuristic ``score`` in (0, 1] reflecting how
"natural" the handle looks — used to truncate to top-N when fan-out
budget matters.

The module has zero external dependencies. AI-assisted expansion is a
separate skill (``core/analysis/skills/handle_generator.md``) called
optionally from the engine to add culturally-aware variants the
deterministic rules miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Diacritic folding map. Order matters: capital first so .lower() on the
# result is safe.
_FOLD_MAP = str.maketrans({
    "ı": "i", "İ": "i", "I": "I",
    "ğ": "g", "Ğ": "g",
    "ş": "s", "Ş": "s",
    "ç": "c", "Ç": "c",
    "ö": "o", "Ö": "o",
    "ü": "u", "Ü": "u",
    "ñ": "n", "Ñ": "n",
    "á": "a", "Á": "a", "à": "a", "À": "a", "â": "a", "Â": "a", "ä": "a", "Ä": "a",
    "é": "e", "É": "e", "è": "e", "È": "e", "ê": "e", "Ê": "e", "ë": "e", "Ë": "e",
    "í": "i", "Í": "i", "ì": "i", "Ì": "i", "î": "i", "Î": "i", "ï": "i", "Ï": "i",
    "ó": "o", "Ó": "o", "ò": "o", "Ò": "o", "ô": "o", "Ô": "o",
    "ú": "u", "Ú": "u", "ù": "u", "Ù": "u", "û": "u", "Û": "u",
    "ß": "ss",
    "œ": "oe", "Œ": "oe",
    "æ": "ae", "Æ": "ae",
})

_SAFE_RE = re.compile(r"[^a-z0-9._-]+")
_WHITESPACE_RE = re.compile(r"\s+")
_VOWEL_RE = re.compile(r"[aeiouy]")


@dataclass(frozen=True)
class HandleCandidate:
    handle: str
    score: float
    rationale: str

    def __post_init__(self) -> None:  # pragma: no cover - dataclass guard
        if not self.handle:
            raise ValueError("handle must not be empty")


def fold(value: str) -> str:
    """Fold diacritics to ASCII, lower-case, strip whitespace, keep ``._-``.

    ``fold("Erkan Rizgic")`` → ``"erkanrizgic"``;
    ``fold("e.rzgic_dev")`` → ``"e.rzgic_dev"`` (separators preserved).
    """
    if not value:
        return ""
    folded = value.translate(_FOLD_MAP)
    no_space = _WHITESPACE_RE.sub("", folded)
    return _SAFE_RE.sub("", no_space.lower())


def split_name(name: str) -> tuple[str, ...]:
    """Split a full name into folded parts. Empty input → empty tuple."""
    parts = [fold(p) for p in re.split(r"\s+", name.strip()) if p.strip()]
    return tuple(p for p in parts if p)


def _drop_vowels(text: str) -> str:
    if not text:
        return ""
    # Keep the first letter even if it's a vowel — "erkan" → "ekn" is too lossy.
    head = text[0]
    tail = _VOWEL_RE.sub("", text[1:])
    return head + tail


def _dedup_preserve_order(values: list[HandleCandidate]) -> list[HandleCandidate]:
    seen: set[str] = set()
    out: list[HandleCandidate] = []
    for v in values:
        if v.handle in seen:
            continue
        seen.add(v.handle)
        out.append(v)
    return out


def generate(
    name: str,
    *,
    year: int | None = None,
    extra_seeds: tuple[str, ...] = (),
    max_candidates: int = 30,
) -> list[HandleCandidate]:
    """Return a ranked list of candidate handles for ``name``.

    ``year`` enables ``alice2026`` / ``alice96`` style suffixes.
    ``extra_seeds`` lets callers (e.g. the email-only mode) add the email
    local-part or a partial nickname as a guaranteed seed.
    Output is deduplicated and capped at ``max_candidates``.
    """
    parts = split_name(name)
    if not parts:
        return []

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    middles = parts[1:-1] if len(parts) > 2 else ()

    candidates: list[HandleCandidate] = []

    # Single-token names: still useful for handles
    if not last:
        candidates.append(HandleCandidate(first, 0.9, "single-token name"))
        candidates.append(HandleCandidate(_drop_vowels(first), 0.4, "vowel-drop single"))
    else:
        # 1. Direct combinations (highest signal)
        for sep, weight in (("", 1.0), (".", 0.95), ("_", 0.9), ("-", 0.7)):
            candidates.append(
                HandleCandidate(
                    f"{first}{sep}{last}",
                    weight,
                    f"first{sep}last",
                )
            )
            candidates.append(
                HandleCandidate(
                    f"{last}{sep}{first}",
                    weight * 0.55,
                    f"last{sep}first",
                )
            )

        # 2. Initial + last (very common professional handle)
        candidates.append(HandleCandidate(f"{first[0]}{last}", 0.85, "first-initial+last"))
        candidates.append(HandleCandidate(f"{first[0]}.{last}", 0.80, "f.last"))
        candidates.append(HandleCandidate(f"{first[0]}_{last}", 0.70, "f_last"))
        candidates.append(HandleCandidate(f"{first}{last[0]}", 0.55, "first+last-initial"))

        # 3. Vowel-drop variants (Turkish handles especially)
        last_compressed = _drop_vowels(last)
        if last_compressed != last:
            candidates.append(
                HandleCandidate(f"{first}{last_compressed}", 0.70, "first+vowel-drop-last")
            )
            candidates.append(
                HandleCandidate(f"{first[0]}{last_compressed}", 0.65, "f+vowel-drop-last")
            )
            candidates.append(HandleCandidate(last_compressed, 0.40, "vowel-drop-last"))

        first_compressed = _drop_vowels(first)
        if first_compressed != first:
            candidates.append(
                HandleCandidate(
                    f"{first_compressed}{last}", 0.50, "vowel-drop-first+last"
                )
            )

        # 4. Middle name combinations
        if middles:
            mid = middles[0]
            candidates.append(HandleCandidate(f"{first}{mid}{last}", 0.55, "first+middle+last"))
            candidates.append(HandleCandidate(f"{first[0]}{mid[0]}{last}", 0.50, "f+m+last"))

    # 5. Optional year suffix (common for older accounts)
    if year is not None:
        base_handles = [c.handle for c in candidates[:6] if c.handle]
        for base in base_handles:
            candidates.append(
                HandleCandidate(f"{base}{year}", 0.45, f"base+{year}")
            )
            candidates.append(
                HandleCandidate(f"{base}{year % 100:02d}", 0.40, f"base+{year % 100:02d}")
            )

    # 6. Common decoration suffixes (lower weight — many false positives)
    if last:
        for suffix in ("official", "real", "tr", "_"):
            candidates.append(
                HandleCandidate(f"{first}{last}{suffix}", 0.30, f"first+last+{suffix}")
            )

    # 7. External seeds (e.g. from an email local-part) — high weight, the
    # caller already has evidence these are likely real.
    for seed in extra_seeds:
        seed_clean = fold(seed)
        if seed_clean:
            candidates.append(HandleCandidate(seed_clean, 0.95, "seed"))

    deduped = _dedup_preserve_order(candidates)
    deduped.sort(key=lambda c: c.score, reverse=True)
    return deduped[:max_candidates]
