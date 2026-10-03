"""Tests for core/semantic_matcher.py."""

from core.semantic_matcher import (
    compute_semantic_similarity,
    match_bios,
)


def test_identical_texts():
    assert compute_semantic_similarity("Security Researcher", "Security Researcher") == 1.0


def test_empty_texts():
    assert compute_semantic_similarity("", "Security Researcher") == 0.0
    assert compute_semantic_similarity("   ", "") == 0.0


def test_similar_domains():
    t1 = "Software engineer building OSINT and cyber intelligence tools in Python."
    t2 = "Python developer focused on open-source intelligence and cybersecurity."
    sim = compute_semantic_similarity(t1, t2)
    assert sim > 0.25


def test_unrelated_domains():
    t1 = "Software engineer building OSINT and cyber intelligence tools in Python."
    t2 = "Professional pastry chef and French bakery owner in Paris."
    sim = compute_semantic_similarity(t1, t2)
    assert sim < 0.15


def test_match_bios_multiple_platforms():
    bios = {
        "github": "Building security intelligence tools and automation scripts.",
        "twitter": "Security researcher interested in cyber intelligence and threat analysis.",
        "cooking_blog": "Baking sourdough bread every weekend with organic flour.",
    }
    matches = match_bios(bios, threshold=0.20)
    assert len(matches) >= 1
    p1, p2, score = matches[0]
    assert {p1, p2} == {"github", "twitter"}
    assert score > 0.25


def test_rank_by_similarity():
    from core.semantic_matcher import rank_by_similarity

    query = "cyber security python osint developer"
    docs = [
        "French pastry chef baking sourdough in Paris.",
        "Python developer building OSINT automation and cybersecurity tools.",
        "Mobile gaming streamer on Twitch.",
    ]
    ranked = rank_by_similarity(query, docs)
    assert len(ranked) == 3
    # Most relevant should be index 1
    assert ranked[0][0] == 1
    assert ranked[0][1] > 0.25
    # Least relevant should be pastry chef or gaming
    assert ranked[0][1] > ranked[2][1]


def test_extract_profile_corpus():
    from core.semantic_matcher import extract_profile_corpus

    payload = {
        "username": "erkanrzgc",
        "cross_reference": {
            "matched_names": ["Erkan Rizgic"],
            "matched_locations": ["Istanbul"],
        },
        "platforms": [
            {
                "platform": "GitHub",
                "exists": True,
                "profile_data": {
                    "bio": "Building open source intelligence tools.",
                    "company": "Retain",
                },
            },
            {
                "platform": "Fake",
                "exists": False,
                "profile_data": {"bio": "Should not be included"},
            },
        ],
    }
    corpus = extract_profile_corpus(payload)
    assert "erkanrzgc" in corpus.lower()
    assert "erkan rizgic" in corpus.lower()
    assert "istanbul" in corpus.lower()
    assert "intelligence" in corpus.lower()
    assert "should not be included" not in corpus.lower()

