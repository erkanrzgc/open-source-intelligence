"""Tests for modules.se_arsenal.gophish_client — target merge + HTTP wiring."""

import io
import json
import urllib.error

import pytest

from modules.recon.models import EmailCandidate, GithubCommitter
from modules.se_arsenal import gophish_client
from modules.se_arsenal.gophish_client import (
    GoPhishClient,
    GoPhishError,
    targets_from_candidates,
)


def _cand(email: str, first: str = "a", last: str = "b") -> EmailCandidate:
    return EmailCandidate(
        email=email,
        first_name=first,
        last_name=last,
        pattern="{first}.{last}",
        domain="acme.com",
    )


def _committer(email: str, name: str = "Ada Byron", noreply: bool = False) -> GithubCommitter:
    return GithubCommitter(
        email=email, name=name, login="", repo="acme/x", is_noreply=noreply
    )


def test_targets_from_candidates_merges_and_dedupes():
    targets = targets_from_candidates(
        candidates=[_cand("a.b@acme.com"), _cand("c.d@acme.com")],
        committers=[_committer("a.b@acme.com"), _committer("e.f@acme.com")],
    )
    emails = [t.email for t in targets]
    assert emails == ["a.b@acme.com", "c.d@acme.com", "e.f@acme.com"]


def test_targets_from_candidates_drops_noreply_by_default():
    targets = targets_from_candidates(
        candidates=[],
        committers=[_committer("12345+user@users.noreply.github.com", noreply=True)],
    )
    assert targets == []


def test_targets_from_candidates_can_include_noreply():
    targets = targets_from_candidates(
        candidates=[],
        committers=[_committer("12345+user@users.noreply.github.com", noreply=True)],
        include_noreply=True,
    )
    assert len(targets) == 1


def test_committer_name_split():
    targets = targets_from_candidates(
        candidates=[], committers=[_committer("x@acme.com", name="Ada Lovelace Byron")]
    )
    assert targets[0].first_name == "Ada"
    assert targets[0].last_name == "Lovelace Byron"


def test_client_requires_url_and_key():
    with pytest.raises(GoPhishError):
        GoPhishClient("", "k")
    with pytest.raises(GoPhishError):
        GoPhishClient("https://g", "")


def test_push_group_requires_targets():
    client = GoPhishClient("https://g", "k", verify_tls=False)
    with pytest.raises(GoPhishError):
        client.push_group("team", [])
    with pytest.raises(GoPhishError):
        client.push_group("", [_cand("x@acme.com")])  # missing name


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_push_group_posts_expected_payload(monkeypatch):
    captured: dict = {}

    def fake_urlopen(req, timeout, context):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(b'{"id": 42, "name": "team"}')

    monkeypatch.setattr(gophish_client.urllib.request, "urlopen", fake_urlopen)

    client = GoPhishClient("https://g.example:3333/", "supersecret", verify_tls=False)
    targets = targets_from_candidates(
        candidates=[_cand("a.b@acme.com", "Alice", "Byron")],
    )
    result = client.push_group("team", targets)

    assert result == {"id": 42, "name": "team"}
    assert captured["url"] == "https://g.example:3333/api/groups/"
    assert captured["method"] == "POST"
    # Headers are capitalized as Title-Case by urllib.
    assert captured["headers"]["Authorization"] == "Bearer supersecret"
    assert captured["body"]["name"] == "team"
    assert captured["body"]["targets"][0]["email"] == "a.b@acme.com"


def test_push_group_rejects_non_object_json(monkeypatch):
    monkeypatch.setattr(
        gophish_client.urllib.request,
        "urlopen",
        lambda req, timeout, context: _FakeResponse(b"[]"),
    )

    client = GoPhishClient("https://g", "k", verify_tls=False)
    with pytest.raises(GoPhishError, match="non-object JSON"):
        client.push_group("team", [_cand_target()])


def test_push_group_wraps_http_errors(monkeypatch):
    def fake_urlopen(req, timeout, context):
        raise urllib.error.HTTPError(
            url="x", code=401, msg="unauthorized", hdrs=None, fp=io.BytesIO(b"bad key")
        )

    monkeypatch.setattr(gophish_client.urllib.request, "urlopen", fake_urlopen)

    client = GoPhishClient("https://g", "k", verify_tls=False)
    with pytest.raises(GoPhishError) as exc:
        client.push_group("team", [_cand_target()])
    assert "401" in str(exc.value)


def _cand_target():
    from modules.se_arsenal.models import GoPhishTarget

    return GoPhishTarget(email="x@acme.com", first_name="x", last_name="y")
