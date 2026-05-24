"""Tests for modules.recon.handle_generator."""

from __future__ import annotations

from modules.recon.handle_generator import (
    HandleCandidate,
    fold,
    generate,
    split_name,
)


def test_fold_turkish_characters():
    assert fold("Erkan Rıza Güç") == "erkanrizaguc"
    assert fold("Şirin Öztürk") == "sirinozturk"
    assert fold("Çağlar İnce") == "caglarince"


def test_fold_spanish_german_french():
    assert fold("José Martínez") == "josemartinez"
    assert fold("Heinrich Müller") == "heinrichmuller"
    assert fold("Renée Élise") == "reneeelise"
    assert fold("Straße") == "strasse"


def test_split_name_handles_multi_word():
    assert split_name("Mary Jane Smith") == ("mary", "jane", "smith")
    assert split_name("  Alice  ") == ("alice",)
    assert split_name("") == ()


def test_generate_returns_ranked_handles_for_two_part_name():
    candidates = generate("Erkan Rizgic")
    handles = [c.handle for c in candidates]
    assert "erkanrizgic" in handles
    assert "erkan.rizgic" in handles
    assert "erizgic" in handles  # f+last
    assert "e.rizgic" in handles
    # First entry should be the highest-scoring combination.
    assert candidates[0].score >= candidates[-1].score


def test_generate_includes_vowel_drop_for_turkish_surnames():
    candidates = generate("Erkan Rizgic")
    handles = [c.handle for c in candidates]
    # "rizgic" → "rzgc" (vowel drop) - wait, "rizgic" has i,i which are vowels
    # rizgic → r + zgc = "rzgc"
    assert any("rzgc" in h for h in handles)


def test_generate_with_year_suffix():
    candidates = generate("Alice Smith", year=2024)
    handles = [c.handle for c in candidates]
    assert any("2024" in h for h in handles)
    assert any(h.endswith("24") for h in handles)


def test_generate_handles_diacritic_names():
    candidates = generate("Şirin Öztürk")
    handles = [c.handle for c in candidates]
    assert "sirinozturk" in handles
    assert any(h.startswith("s") and "ozturk" in h for h in handles)
    # No raw diacritics should leak through
    for h in handles:
        assert all(c.isascii() for c in h)


def test_generate_empty_name_returns_empty():
    assert generate("") == []
    assert generate("   ") == []


def test_generate_single_token_name():
    candidates = generate("madonna")
    handles = [c.handle for c in candidates]
    assert "madonna" in handles


def test_generate_three_part_name_includes_middle():
    candidates = generate("Mary Jane Smith")
    handles = [c.handle for c in candidates]
    assert "maryjanesmith" in handles
    assert any(h == "mjsmith" or h == "marysmith" for h in handles)


def test_generate_dedupes_candidates():
    candidates = generate("Aa Aa")  # likely produces dupes
    handles = [c.handle for c in candidates]
    assert len(handles) == len(set(handles))


def test_generate_respects_max_candidates():
    candidates = generate("Erkan Rizgic", year=2024, max_candidates=5)
    assert len(candidates) <= 5


def test_extra_seeds_high_weight():
    candidates = generate("Alice Smith", extra_seeds=("asmith_dev",))
    seeded = [c for c in candidates if c.handle == "asmith_dev"]
    assert len(seeded) == 1
    assert seeded[0].score >= 0.9
    assert seeded[0].rationale == "seed"


def test_candidates_are_hashable():
    c = HandleCandidate("alice", 0.9, "first-only")
    assert hash(c) == hash(c)  # frozen dataclass
