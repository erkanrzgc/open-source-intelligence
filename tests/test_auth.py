"""Auth module tests — user store, password hashing, HS256 JWT."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from core import auth


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "users.sqlite3"


# ── user store ──────────────────────────────────────────────────────


def test_create_user_returns_user_with_id(db: Path) -> None:
    u = auth.create_user("alice", "s3cret!", db_path=db)
    assert u.id >= 1
    assert u.username == "alice"
    assert u.role == "analyst"
    # Password hash must never be the plaintext.
    assert "s3cret!" not in u.password_hash
    assert u.password_hash.startswith("pbkdf2_sha256$")


def test_create_user_rejects_empty(db: Path) -> None:
    with pytest.raises(ValueError):
        auth.create_user("", "pw", db_path=db)
    with pytest.raises(ValueError):
        auth.create_user("alice", "", db_path=db)


def test_create_user_duplicate_raises(db: Path) -> None:
    auth.create_user("alice", "pw", db_path=db)
    with pytest.raises(ValueError):
        auth.create_user("alice", "pw2", db_path=db)


def test_get_user_returns_none_when_missing(db: Path) -> None:
    assert auth.get_user("ghost", db_path=db) is None


def test_authenticate_success_and_failure(db: Path) -> None:
    auth.create_user("alice", "correct", db_path=db)
    assert auth.authenticate("alice", "correct", db_path=db) is not None
    assert auth.authenticate("alice", "wrong", db_path=db) is None
    assert auth.authenticate("ghost", "correct", db_path=db) is None


def test_password_hashes_are_unique_per_user(db: Path) -> None:
    # Two users with the same password must have different hashes because
    # the salt is random.
    a = auth.create_user("alice", "samepw", db_path=db)
    b = auth.create_user("bob", "samepw", db_path=db)
    assert a.password_hash != b.password_hash
    # Yet both still authenticate.
    assert auth.authenticate("alice", "samepw", db_path=db) is not None
    assert auth.authenticate("bob", "samepw", db_path=db) is not None


def test_list_users_excludes_hashes(db: Path) -> None:
    auth.create_user("alice", "pw", db_path=db)
    auth.create_user("bob", "pw", db_path=db, role="admin")
    listed = auth.list_users(db_path=db)
    names = {u.username for u in listed}
    assert names == {"alice", "bob"}
    roles = {u.username: u.role for u in listed}
    assert roles["bob"] == "admin"


# ── JWT (HS256) ────────────────────────────────────────────────────


def test_issue_and_decode_token_roundtrip() -> None:
    token = auth.issue_token(
        user_id=7, username="alice", role="analyst", secret="s3cret", ttl=60
    )
    payload = auth.decode_token(token, secret="s3cret")
    assert payload["sub"] == "alice"
    assert payload["uid"] == 7
    assert payload["role"] == "analyst"
    assert payload["exp"] > int(time.time())


def test_decode_token_rejects_wrong_secret() -> None:
    token = auth.issue_token(
        user_id=1, username="alice", role="analyst", secret="right", ttl=60
    )
    with pytest.raises(auth.AuthError):
        auth.decode_token(token, secret="wrong")


def test_decode_token_rejects_tampered_payload() -> None:
    token = auth.issue_token(
        user_id=1, username="alice", role="analyst", secret="s", ttl=60
    )
    header, payload, sig = token.split(".")
    tampered = f"{header}.{payload}AAAA.{sig}"
    with pytest.raises(auth.AuthError):
        auth.decode_token(tampered, secret="s")


def test_decode_token_rejects_expired() -> None:
    token = auth.issue_token(
        user_id=1, username="alice", role="analyst", secret="s", ttl=-1
    )
    with pytest.raises(auth.AuthError):
        auth.decode_token(token, secret="s")


def test_decode_token_rejects_malformed() -> None:
    with pytest.raises(auth.AuthError):
        auth.decode_token("not.a.jwt", secret="s")
    with pytest.raises(auth.AuthError):
        auth.decode_token("missing-dots", secret="s")


def test_decode_token_rejects_signed_non_object_payload() -> None:
    import base64
    import hashlib
    import hmac
    import json

    def encode(value) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode(["valid-signature", "wrong-shape"])
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = base64.urlsafe_b64encode(
        hmac.new(b"s", signing_input, hashlib.sha256).digest()
    ).rstrip(b"=").decode()

    with pytest.raises(auth.AuthError, match="malformed payload"):
        auth.decode_token(f"{header}.{payload}.{signature}", secret="s")


def test_decode_token_rejects_wrong_algorithm() -> None:
    import base64
    import json

    # Forge an alg=none token — must be rejected.
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "x", "exp": int(time.time()) + 60}).encode()
    ).rstrip(b"=").decode()
    forged = f"{header}.{payload}."
    with pytest.raises(auth.AuthError):
        auth.decode_token(forged, secret="any")
