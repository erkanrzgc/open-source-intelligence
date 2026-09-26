"""Lightweight semantic text similarity and bio comparison for OSINT."""

from __future__ import annotations

import math
import re
from collections import Counter

_STOPWORDS = frozenset({
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves",
    "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves", "ve", "ile", "bir", "bu", "da", "de", "icin",
})


def extract_features(text: str) -> Counter[str]:
    """Extract word unigrams, bigrams, and character 4-grams for subword matching."""
    if not text:
        return Counter()
    words = [w for w in re.findall(r"[a-z0-9_]+", text.lower()) if w not in _STOPWORDS]
    features: list[str] = list(words)
    # Bigrams
    for i in range(len(words) - 1):
        features.append(f"{words[i]}_{words[i+1]}")
    # Subword 4-grams for morphological/stem matching
    for w in words:
        if len(w) >= 4:
            for j in range(len(w) - 3):
                features.append(w[j : j + 4])
    return Counter(features)


def cosine_similarity(v1: Counter[str], v2: Counter[str]) -> float:
    """Compute cosine similarity between two sparse feature counters."""
    if not v1 or not v2:
        return 0.0
    common = set(v1.keys()) & set(v2.keys())
    if not common:
        return 0.0
    numerator = sum(v1[k] * v2[k] for k in common)
    denom1 = math.sqrt(sum(v**2 for v in v1.values()))
    denom2 = math.sqrt(sum(v**2 for v in v2.values()))
    denom = denom1 * denom2
    return float(numerator) / denom if denom > 0 else 0.0


def compute_semantic_similarity(text1: str, text2: str) -> float:
    """Return similarity score in [0.0, 1.0] between two texts."""
    t1, t2 = text1.strip(), text2.strip()
    if not t1 or not t2:
        return 0.0
    if t1.lower() == t2.lower():
        return 1.0
    return round(cosine_similarity(extract_features(t1), extract_features(t2)), 4)


def match_bios(bios: dict[str, str], threshold: float = 0.25) -> list[tuple[str, str, float]]:
    """Compare bios across multiple platforms and return high-confidence pairs."""
    matched = []
    platforms = list(bios.keys())
    for i, p1 in enumerate(platforms):
        for p2 in platforms[i + 1 :]:
            sim = compute_semantic_similarity(bios[p1], bios[p2])
            if sim >= threshold:
                matched.append((p1, p2, sim))
    matched.sort(key=lambda item: -item[2])
    return matched


def rank_by_similarity(query: str, documents: list[str]) -> list[tuple[int, float]]:
    """Rank documents by their semantic similarity to a query string."""
    q_vec = extract_features(query)
    if not q_vec:
        return [(idx, 0.0) for idx in range(len(documents))]
    scored = []
    for idx, doc in enumerate(documents):
        d_vec = extract_features(doc)
        sim = round(cosine_similarity(q_vec, d_vec), 4)
        scored.append((idx, sim))
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored


def extract_profile_corpus(payload: dict) -> str:
    """Aggregate biographical and contextual text fields from a scan result or profile."""
    parts: list[str] = []
    username = payload.get("username")
    if username:
        parts.append(str(username))

    # Search top-level cross-reference metadata
    xref = payload.get("cross_reference") or {}
    if isinstance(xref, dict):
        for name in xref.get("matched_names", []):
            parts.append(str(name))
        for loc in xref.get("matched_locations", []):
            parts.append(str(loc))
        for bio in xref.get("matched_bios", []):
            parts.append(str(bio))

    # Iterate through platforms
    platforms = payload.get("platforms") or []
    if isinstance(platforms, list):
        for p in platforms:
            if not isinstance(p, dict) or not p.get("exists"):
                continue
            p_data = p.get("profile_data") or {}
            if isinstance(p_data, dict):
                for key in ("name", "full_name", "display_name", "bio", "about", "summary", "location", "company", "occupation"):
                    val = p_data.get(key)
                    if val and isinstance(val, str) and val.strip():
                        parts.append(val.strip())
            # Capture platform title / description if present
            for key in ("title", "description"):
                val = p.get(key)
                if val and isinstance(val, str) and val.strip():
                    parts.append(val.strip())

    # De-duplicate while preserving order
    seen: set[str] = set()
    cleaned: list[str] = []
    for part in parts:
        normalized = part.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append(part.strip())
    return " ".join(cleaned)
