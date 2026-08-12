"""Deterministic username-candidate generation and profile discoveries."""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from utils.helpers import extract_emails_from_text, extract_urls_from_text


@dataclass(frozen=True)
class UsernameCandidate:
    """A ranked alias hypothesis with an auditable generation reason."""

    username: str
    handle_similarity: float
    source_confidence: float
    score: float
    discovery_reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "handle_similarity": round(self.handle_similarity, 3),
            "source_confidence": round(self.source_confidence, 3),
            "score": round(self.score, 3),
            "discovery_reasons": list(self.discovery_reasons),
        }


def damerau_levenshtein_distance(left: str, right: str) -> int:
    """Return optimal-string-alignment Damerau-Levenshtein distance."""
    left, right = left.casefold(), right.casefold()
    rows, cols = len(left) + 1, len(right) + 1
    matrix = [[0] * cols for _ in range(rows)]
    for row in range(rows):
        matrix[row][0] = row
    for col in range(cols):
        matrix[0][col] = col
    for row in range(1, rows):
        for col in range(1, cols):
            substitution = 0 if left[row - 1] == right[col - 1] else 1
            matrix[row][col] = min(
                matrix[row - 1][col] + 1,
                matrix[row][col - 1] + 1,
                matrix[row - 1][col - 1] + substitution,
            )
            if (
                row > 1
                and col > 1
                and left[row - 1] == right[col - 2]
                and left[row - 2] == right[col - 1]
            ):
                matrix[row][col] = min(
                    matrix[row][col], matrix[row - 2][col - 2] + 1
                )
    return matrix[-1][-1]


def handle_similarity(left: str, right: str) -> float:
    longest = max(len(left), len(right))
    if not longest:
        return 1.0
    return max(0.0, 1.0 - damerau_levenshtein_distance(left, right) / longest)


_REASON_CONFIDENCE: dict[str, float] = {
    "linked_profile": 1.0,
    "repeat_last_character": 0.98,
    "remove_repeated_last_character": 0.97,
    "delete_one_character": 0.90,
    "transpose_adjacent_characters": 0.88,
    "separator_mutation": 0.82,
    "numeric_suffix_mutation": 0.75,
    "single_leet_substitution": 0.70,
    "limited_affix": 0.65,
    "legacy_separator_order": 0.55,
}
_REASON_ORDER = {reason: index for index, reason in enumerate(_REASON_CONFIDENCE)}
_SAFE_HANDLE = re.compile(r"^[a-z0-9_.-]+$")


def generate_candidates(
    username: str,
    *,
    linked_usernames: Iterable[str] = (),
    max_candidates: int = 12,
) -> list[UsernameCandidate]:
    """Generate and rank bounded alias hypotheses.

    Ranking is deterministic and precision-first: profile-linked handles lead,
    followed by one-edit mutations, separators, numbers, leet and a small affix
    vocabulary.  Similarity contributes to ordering but can never become identity
    proof by itself.
    """
    root = username.strip().casefold()
    if not root or max_candidates <= 0:
        return []

    reasons: dict[str, set[str]] = {}

    def add(candidate: str, reason: str) -> None:
        value = candidate.strip().casefold()
        if (
            value
            and value != root
            and len(value) <= 64
            and _SAFE_HANDLE.fullmatch(value)
        ):
            reasons.setdefault(value, set()).add(reason)

    for linked in linked_usernames:
        if isinstance(linked, str):
            add(linked, "linked_profile")

    if root:
        add(root + root[-1], "repeat_last_character")
    if len(root) > 1 and root[-1] == root[-2]:
        add(root[:-1], "remove_repeated_last_character")

    for index in range(len(root)):
        add(root[:index] + root[index + 1 :], "delete_one_character")
    for index in range(len(root) - 1):
        if root[index] != root[index + 1]:
            add(
                root[:index] + root[index + 1] + root[index] + root[index + 2 :],
                "transpose_adjacent_characters",
            )

    parts = [part for part in re.split(r"[._-]+", root) if part]
    if len(parts) > 1:
        for separator in ("", ".", "_", "-"):
            add(separator.join(parts), "separator_mutation")
        for separator in ("", ".", "_", "-"):
            add(separator.join(reversed(parts)), "legacy_separator_order")
    elif len(root) >= 5:
        for index in range(3, len(root) - 2):
            for separator in (".", "_", "-"):
                add(root[:index] + separator + root[index:], "separator_mutation")
    clean = root.strip("._-")
    add(clean, "separator_mutation")

    stripped_digits = re.sub(r"\d+$", "", root)
    add(stripped_digits, "numeric_suffix_mutation")
    for suffix in ("1", "2", "01", "123"):
        add(root + suffix, "numeric_suffix_mutation")

    leet_map = {"o": "0", "l": "1", "e": "3", "a": "4", "s": "5", "t": "7", "b": "8", "g": "9"}
    for index, character in enumerate(root):
        replacement = leet_map.get(character)
        if replacement:
            add(root[:index] + replacement + root[index + 1 :], "single_leet_substitution")

    for suffix in ("real", "official", "dev"):
        add(root + suffix, "limited_affix")
    for prefix in ("real", "the"):
        add(prefix + root, "limited_affix")

    candidates: list[UsernameCandidate] = []
    for candidate, candidate_reasons in reasons.items():
        ordered_reasons = tuple(
            sorted(candidate_reasons, key=lambda item: _REASON_ORDER[item])
        )
        source_confidence = max(_REASON_CONFIDENCE[item] for item in ordered_reasons)
        similarity = handle_similarity(root, candidate)
        score = 0.65 * source_confidence + 0.35 * similarity
        candidates.append(
            UsernameCandidate(
                username=candidate,
                handle_similarity=round(similarity, 6),
                source_confidence=source_confidence,
                score=round(score, 6),
                discovery_reasons=ordered_reasons,
            )
        )
    candidates.sort(
        key=lambda candidate: (
            min(_REASON_ORDER[reason] for reason in candidate.discovery_reasons),
            -candidate.score,
            candidate.username,
        )
    )
    return candidates[:max_candidates]


def generate_variations(username: str) -> list[str]:
    """Backward-compatible, alphabetic view of the scored candidate set."""
    return sorted(
        candidate.username
        for candidate in generate_candidates(username, max_candidates=256)
    )


def extract_discoverable_data(profile_data: dict) -> dict:
    """Extract names, emails, locations, and linked accounts from profile data."""
    names = set()
    emails = set()
    locations = set()
    linked_usernames = set()
    urls = set()

    for key in ["name", "full_name", "persona_name", "real_name"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            names.add(val.strip())

    first = profile_data.get("first_name", "")
    last = profile_data.get("last_name", "")
    if first and last:
        names.add(f"{first} {last}")

    for key in ["email"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and "@" in val:
            emails.add(val.strip())

    for key in ["location", "country"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            locations.add(val.strip())

    for key, val in profile_data.items():
        if (
            key.endswith("_username")
            and val
            and isinstance(val, str)
            and val.strip()
        ):
            linked_usernames.add(val.strip().lstrip("@"))
    social_handles = profile_data.get("social_handles") or profile_data.get("socials")
    if isinstance(social_handles, dict):
        for val in social_handles.values():
            if isinstance(val, str) and val.strip():
                linked_usernames.add(val.strip().lstrip("@"))

    # keybase proofs
    proofs = profile_data.get("proofs", [])
    for proof in proofs:
        if isinstance(proof, dict) and proof.get("username"):
            linked_usernames.add(proof["username"])

    for key in ["blog", "website_url", "web_url", "links"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            urls.add(val.strip())

    # scan text fields for emails and urls
    for key in ["bio", "summary", "about", "subreddit_description"]:
        val = profile_data.get(key, "")
        if val:
            emails.update(extract_emails_from_text(val))
            urls.update(extract_urls_from_text(val))

    return {
        "names": sorted(names),
        "emails": sorted(emails),
        "locations": sorted(locations),
        "linked_usernames": sorted(linked_usernames),
        "urls": sorted(urls),
    }


def merge_discoveries(discoveries: list[dict]) -> dict:
    """Merge discovery data from multiple profiles."""
    merged: dict[str, set[str]] = {
        "names": set(),
        "emails": set(),
        "locations": set(),
        "linked_usernames": set(),
        "urls": set(),
    }
    for d in discoveries:
        for key in merged:
            merged[key].update(d.get(key, []))
    return {k: sorted(v) for k, v in merged.items()}
