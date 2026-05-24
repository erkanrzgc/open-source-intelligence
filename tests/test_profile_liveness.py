"""Tests for modules.profile_liveness liveness scoring."""

from __future__ import annotations

from modules.profile_liveness import (
    LIVENESS_THRESHOLD,
    score_liveness,
)


def test_real_profile_scores_high():
    body = """
    <html>
      <head>
        <meta property="og:title" content="alice (@alice) on GitHub" />
        <script type="application/ld+json">
          {"@context":"https://schema.org","@type":"Person","name":"Alice"}
        </script>
      </head>
      <body>
        <img class="avatar avatar-user" src="https://avatars.githubusercontent.com/u/1234?v=4" />
        <span>Followers: 4,231</span>
      </body>
    </html>
    """
    profile_data = {
        "bio": "Software engineer interested in security and OSINT.",
        "avatar_url": "https://avatars.githubusercontent.com/u/1234?v=4",
        "followers": 4231,
    }
    result = score_liveness(username="alice", body=body, profile_data=profile_data)
    assert result.is_active is True
    assert result.score >= 0.7
    assert "avatar" in result.signals
    assert "bio" in result.signals
    assert "og_title" in result.signals
    assert "jsonld_person" in result.signals


def test_empty_shell_scores_low():
    body = "<html><body><p>This user has not created a profile yet.</p></body></html>"
    result = score_liveness(username="ghost", body=body, profile_data={})
    assert result.is_active is False
    assert result.score < LIVENESS_THRESHOLD


def test_default_avatar_does_not_count():
    body = "<html></html>"
    profile_data = {
        "avatar_url": "https://abs.twimg.com/sticky/default_profile_images/default.png",
    }
    result = score_liveness(username="bob", body=body, profile_data=profile_data)
    assert "default_avatar" in result.signals
    assert "avatar" not in result.signals


def test_bio_alone_is_not_enough():
    body = "<html></html>"
    profile_data = {"bio": "Just here to read."}
    result = score_liveness(username="bob", body=body, profile_data=profile_data)
    assert result.score == 0.25
    assert result.is_active is False  # below 0.40 threshold


def test_activity_extracted_from_body():
    body = '<div>Followers: 1240</div><div>Posts: 87</div>'
    result = score_liveness(username="alice", body=body, profile_data=None)
    activity_signals = [s for s in result.signals if s.startswith("activity:")]
    assert activity_signals
    assert int(activity_signals[0].split(":")[1]) >= 87


def test_handles_missing_inputs_gracefully():
    result = score_liveness(username="", body="", profile_data=None)
    assert result.score == 0.0
    assert result.is_active is False
    assert result.signals == ()


def test_jsonld_without_person_type_does_not_count():
    body = """
    <script type="application/ld+json">
      {"@context":"https://schema.org","@type":"WebSite","name":"Example"}
    </script>
    """
    result = score_liveness(username="alice", body=body, profile_data={})
    assert "jsonld_person" not in result.signals
