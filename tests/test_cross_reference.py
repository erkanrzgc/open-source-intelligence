"""Tests for core/cross_reference.py."""

from core.cross_reference import cross_reference
from core.models import PlatformResult


def _profile(platform: str, url: str, **data) -> PlatformResult:
    return PlatformResult(
        platform=platform,
        url=url,
        category="social",
        exists=True,
        profile_data=data,
    )


class TestCrossReference:
    def test_insufficient_data(self):
        result = cross_reference([])
        assert result.confidence == 0.0
        assert "Insufficient profile" in result.notes[0]

    def test_single_profile(self):
        result = cross_reference([_profile("gh", "https://a", name="A")])
        assert result.confidence == 0.0

    def test_same_name_two_platforms(self):
        profiles = [
            _profile("gh", "https://gh/alice", name="Alice Jones"),
            _profile("tw", "https://tw/alice", name="Alice Jones"),
        ]
        result = cross_reference(profiles)
        assert result.confidence > 30
        assert any("Alice" in m.lower() or "alice" in m for m in result.matched_names)

    def test_different_names(self):
        profiles = [
            _profile("gh", "https://gh/a", name="Alice Jones"),
            _profile("tw", "https://tw/b", name="Bob Smith"),
        ]
        result = cross_reference(profiles)
        assert result.confidence < 50

    def test_similar_name_fuzzy(self):
        profiles = [
            _profile("gh", "https://gh/a", name="Alice M Jones"),
            _profile("tw", "https://tw/a", name="Alice Jones"),
        ]
        result = cross_reference(profiles)
        assert result.confidence > 0

    def test_same_location(self):
        profiles = [
            _profile("gh", "https://gh/a", name="A B", location="Istanbul"),
            _profile("tw", "https://tw/a", name="A B", location="Istanbul"),
        ]
        result = cross_reference(profiles)
        assert len(result.matched_locations) > 0

    def test_linked_twitter(self):
        profiles = [
            _profile("gh", "https://gh/alice", name="Alice", twitter_username="alice_t"),
            _profile("twitter", "https://twitter.com/alice_t", name="Alice"),
        ]
        result = cross_reference(profiles)
        assert result.confidence > 50

    def test_first_last_name(self):
        profiles = [
            _profile("gh", "https://gh/a", first_name="Jane", last_name="Doe"),
            _profile("tw", "https://tw/a", first_name="Jane", last_name="Doe"),
        ]
        result = cross_reference(profiles)
        assert result.confidence > 0
