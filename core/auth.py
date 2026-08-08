"""User store + HS256 JWT auth — zero-dependency.

Uses ``hashlib.pbkdf2_hmac`` for password hashing and raw ``hmac`` /
``hashlib`` for JWT (HS256) so the project stays within its current
dependency envelope. If a real auth story ever shows up (SSO, OIDC),
swap this for ``pyjwt`` + ``passlib`` at that point — until then the
stdlib surface is more than enough for a single-operator tool.

Auth is *opt-in*: the REST surface only enforces tokens when the
environment variable ``OSINT_AUTH_REQUIRED`` is set to a truthy value.
This keeps a localhost-only deployment frictionless.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "open-source-intelligence" / "users.sqlite3"

VALID_ROLES = frozenset({"admin", "analyst", "viewer"})

PBKDF2_ITERATIONS = 260_000
PBKDF2_SALT_BYTES = 16

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'analyst',
    created_ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
"""


class AuthError(Exception):
    """Raised when a credential, token, or signature fails validation."""


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    role: str
    created_ts: int

    def to_dict(self, *, include_hash: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_ts": self.created_ts,
        }
        if include_hash:
            d["password_hash"] = self.password_hash
        return d


# ── password hashing ────────────────────────────────────────────────


def _hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    )


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters_s, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(actual, expected)


# ── user store ──────────────────────────────────────────────────────


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _row_to_user(row: tuple) -> User:
    return User(
        id=row[0],
        username=row[1],
        password_hash=row[2],
        role=row[3],
        created_ts=row[4],
    )


def create_user(
    username: str,
    password: str,
    *,
    role: str = "analyst",
    db_path: Path = DEFAULT_DB_PATH,
    ts: int | None = None,
) -> User:
    clean = (username or "").strip()
    if not clean:
        raise ValueError("username must be non-empty")
    if not password:
        raise ValueError("password must be non-empty")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
    stamp = ts if ts is not None else int(time.time())
    pw_hash = _hash_password(password)
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_ts) "
            "VALUES (?, ?, ?, ?)",
            (clean, pw_hash, role, stamp),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"user {clean!r} already exists") from exc
    finally:
        conn.close()
    assert user_id is not None
    return User(
        id=user_id,
        username=clean,
        password_hash=pw_hash,
        role=role,
        created_ts=stamp,
    )


def get_user(
    username: str, *, db_path: Path = DEFAULT_DB_PATH
) -> User | None:
    if not db_path.exists():
        return None
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, password_hash, role, created_ts "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_user(row) if row else None


def list_users(*, db_path: Path = DEFAULT_DB_PATH) -> list[User]:
    if not db_path.exists():
        return []
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, username, password_hash, role, created_ts "
            "FROM users ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_user(r) for r in rows]


def authenticate(
    username: str, password: str, *, db_path: Path = DEFAULT_DB_PATH
) -> User | None:
    user = get_user(username, db_path=db_path)
    if user is None:
        # Still spend roughly one hash's worth of CPU so a caller can't
        # distinguish "no such user" from "wrong password" by timing.
        _verify_password(password, _hash_password("decoy"))
        return None
    return user if _verify_password(password, user.password_hash) else None


# ── JWT (HS256) ────────────────────────────────────────────────────


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def issue_token(
    *,
    user_id: int,
    username: str,
    role: str,
    secret: str,
    ttl: int = 3600,
) -> str:
    """Return a signed HS256 JWT. ``ttl`` may be negative for test fixtures."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": username,
        "uid": user_id,
        "role": role,
        "iat": now,
        "exp": now + ttl,
    }
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = hmac.new(
        secret.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def decode_token(token: str, *, secret: str) -> dict[str, Any]:
    """Verify HS256 signature + expiry. Raises AuthError on any failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed token")
    h_b64, p_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(h_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError("malformed header") from exc
    if header.get("alg") != "HS256":
        raise AuthError(f"unsupported alg: {header.get('alg')!r}")
    try:
        payload_bytes = _b64url_decode(p_b64)
        provided_sig = _b64url_decode(sig_b64)
    except ValueError as exc:
        raise AuthError("malformed token") from exc
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected_sig = hmac.new(
        secret.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise AuthError("invalid signature")
    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise AuthError("malformed payload") from exc
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        raise AuthError("token expired")
    if not isinstance(payload, dict):
        raise AuthError("malformed payload")
    return payload


# ── helpers for the API layer ──────────────────────────────────────


def is_auth_required() -> bool:
    return os.environ.get("OSINT_AUTH_REQUIRED", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


_EPHEMERAL_SECRET = ""
_EPHEMERAL_SECRET_LOCK = threading.Lock()


def get_secret() -> str:
    """JWT signing secret. Falls back to a process-lifetime random key so
    tokens still sign consistently within a single run when the operator
    forgot to set one."""
    env = os.environ.get("OSINT_AUTH_SECRET")
    if env:
        return env
    global _EPHEMERAL_SECRET
    if _EPHEMERAL_SECRET:
        return _EPHEMERAL_SECRET
    with _EPHEMERAL_SECRET_LOCK:
        if _EPHEMERAL_SECRET:
            return _EPHEMERAL_SECRET
        _EPHEMERAL_SECRET = secrets.token_urlsafe(48)
        return _EPHEMERAL_SECRET
