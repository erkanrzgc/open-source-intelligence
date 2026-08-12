"""Username correlation scoring.

Given two scan payloads (``ScanResult.to_dict()`` shapes, typically
loaded from the history store), compute a single 0..1 probability that
both usernames belong to the same real-world identity, alongside the
list of signals that contributed.

The scorer is deliberately evidence-first: every point of overlap is
surfaced so the analyst can eyeball *why* the score is high. Scoring
uses a probabilistic OR — ``1 - Π(1 - w_i)`` — so additional weak
signals keep pushing the score up without overflowing past 1.0, and a
single strong signal (shared email, shared phone, shared wallet) can
already tip the verdict on its own.

Pure-Python, zero network I/O — callers feed in payload dicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit

# ── tunables ──────────────────────────────────────────────────────────

# Per-signal weight. A weight of 0.9 means "this one signal alone pushes
# the score to 0.9". Combination via probabilistic OR.
WEIGHT_EMAIL = 0.92
WEIGHT_PHONE = 0.90
WEIGHT_CRYPTO = 0.85
WEIGHT_NAME_EXACT = 0.45
WEIGHT_NAME_FUZZY = 0.25
WEIGHT_LOCATION_EXACT = 0.35
WEIGHT_COUNTRY = 0.12
WEIGHT_BIO_JACCARD = 0.25
WEIGHT_ALIAS = 0.55  # discovered_usernames cross-reference
WEIGHT_GRAVATAR_AVATAR = 0.70  # shared gravatar/profile pic URL

NAME_FUZZY_MIN = 0.82
BIO_JACCARD_MIN = 0.30
MIN_BIO_TOKENS = 3

# Cheap stopword list — we only use it for bio similarity, so we err on
# the side of over-trimming common filler rather than tuning for recall.
_STOPWORDS = frozenset(
    {
        "a", "an", "and", "or", "the", "of", "to", "in", "on", "at",
        "with", "for", "is", "it", "my", "me", "i", "you", "we", "be",
        "by", "as", "from", "this", "that", "but", "not", "are", "was",
    }
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


# ── data shapes ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class MatchSignal:
    """A single piece of evidence that links two identities."""
    kind: str        # "email" | "phone" | "crypto" | "name" | "location" | "bio" | "alias" | "avatar"
    weight: float    # 0..1 contribution used in the probabilistic OR
    detail: str      # short human-readable description of the match
    a_value: str = ""
    b_value: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "weight": round(self.weight, 3),
            "detail": self.detail,
            "a_value": self.a_value,
            "b_value": self.b_value,
        }


@dataclass(frozen=True)
class CorrelationResult:
    """Scoring output: the score, the verdict, and every contributing signal."""
    username_a: str
    username_b: str
    score: float
    verdict: str
    signals: tuple[MatchSignal, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "username_a": self.username_a,
            "username_b": self.username_b,
            "score": round(self.score, 3),
            "verdict": self.verdict,
            "signals": [s.to_dict() for s in self.signals],
        }


# ── extraction helpers ────────────────────────────────────────────────


def _clean(s: str | None) -> str:
    return (s or "").strip()


def _lower(s: str | None) -> str:
    return _clean(s).lower()


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 2}


def _emails(payload: dict) -> set[str]:
    out: set[str] = set()
    for e in payload.get("emails") or []:
        if isinstance(e, dict):
            addr = _lower(e.get("email"))
            if addr:
                out.add(addr)
    for h in payload.get("holehe_hits") or []:
        if isinstance(h, dict):
            addr = _lower(h.get("email"))
            if addr:
                out.add(addr)
    for leak in payload.get("comb_leaks") or []:
        if isinstance(leak, dict):
            ident = _lower(leak.get("identifier"))
            if ident and "@" in ident:
                out.add(ident)
    return out


def _phones(payload: dict) -> set[str]:
    out: set[str] = set()
    for p in payload.get("phone_intel") or []:
        if isinstance(p, dict):
            e164 = _clean(p.get("e164"))
            if e164:
                out.add(e164)
    return out


def _crypto(payload: dict) -> set[str]:
    out: set[str] = set()
    for c in payload.get("crypto_intel") or []:
        if isinstance(c, dict):
            addr = _clean(c.get("address"))
            if addr:
                out.add(addr.lower())
    return out


def _names(payload: dict) -> set[str]:
    out: set[str] = set()
    for p in payload.get("platforms") or []:
        pd = p.get("profile_data") if isinstance(p, dict) else None
        if not isinstance(pd, dict):
            continue
        for key in ("display_name", "name", "full_name"):
            name = _clean(pd.get(key))
            if name:
                out.add(name)
    for t in payload.get("toutatis_results") or []:
        if isinstance(t, dict):
            name = _clean(t.get("full_name"))
            if name:
                out.add(name)
    for g in payload.get("ghunt_results") or []:
        if isinstance(g, dict):
            name = _clean(g.get("name"))
            if name:
                out.add(name)
    return out


def _bios(payload: dict) -> list[str]:
    out: list[str] = []
    for p in payload.get("platforms") or []:
        pd = p.get("profile_data") if isinstance(p, dict) else None
        if not isinstance(pd, dict):
            continue
        for key in ("bio", "description", "about"):
            bio = _clean(pd.get(key))
            if bio:
                out.append(bio)
    for t in payload.get("toutatis_results") or []:
        if isinstance(t, dict):
            bio = _clean(t.get("biography"))
            if bio:
                out.append(bio)
    return out


def _locations(payload: dict) -> set[str]:
    """Normalized free-form location strings (for exact-ish overlap)."""
    out: set[str] = set()
    for g in payload.get("geo_points") or []:
        if isinstance(g, dict):
            disp = _lower(g.get("display")) or _lower(g.get("query"))
            if disp:
                out.add(disp)
    for p in payload.get("platforms") or []:
        pd = p.get("profile_data") if isinstance(p, dict) else None
        if isinstance(pd, dict):
            loc = _lower(pd.get("location"))
            if loc:
                out.add(loc)
    return out


def _countries(payload: dict) -> set[str]:
    out: set[str] = set()
    for g in payload.get("geo_points") or []:
        if isinstance(g, dict):
            c = _lower(g.get("country"))
            if c:
                out.add(c)
    return out


def _aliases(payload: dict) -> set[str]:
    """Usernames the scan explicitly surfaced as variants/aliases."""
    out: set[str] = set()
    for u in payload.get("discovered_usernames") or []:
        if isinstance(u, str):
            u = _lower(u)
            if u:
                out.add(u)
    for h in payload.get("historical_usernames") or []:
        if isinstance(h, dict):
            u = _lower(h.get("username"))
            if u:
                out.add(u)
    return out


def _avatars(payload: dict) -> set[str]:
    out: set[str] = set()
    for p in payload.get("platforms") or []:
        pd = p.get("profile_data") if isinstance(p, dict) else None
        if isinstance(pd, dict):
            for key in ("avatar", "profile_picture", "picture"):
                url = _lower(pd.get(key))
                if url:
                    out.add(url)
    for t in payload.get("toutatis_results") or []:
        if isinstance(t, dict):
            url = _lower(t.get("profile_pic"))
            if url:
                out.add(url)
    for g in payload.get("ghunt_results") or []:
        if isinstance(g, dict):
            url = _lower(g.get("profile_picture"))
            if url:
                out.add(url)
    return out


# ── individual matchers ───────────────────────────────────────────────


def _match_exact_set(
    a: set[str], b: set[str], kind: str, weight: float, label: str
) -> list[MatchSignal]:
    return [
        MatchSignal(kind=kind, weight=weight, detail=f"{label}: {v}", a_value=v, b_value=v)
        for v in sorted(a & b)
    ]


def _match_names(a: set[str], b: set[str]) -> list[MatchSignal]:
    signals: list[MatchSignal] = []
    a_lower = {n.lower(): n for n in a}
    b_lower = {n.lower(): n for n in b}

    exact = set(a_lower) & set(b_lower)
    for key in sorted(exact):
        signals.append(
            MatchSignal(
                kind="name",
                weight=WEIGHT_NAME_EXACT,
                detail=f"display name matches: {a_lower[key]}",
                a_value=a_lower[key],
                b_value=b_lower[key],
            )
        )
    # Fuzzy pass — find best match per left-hand name.
    for an in a_lower:
        if an in exact:
            continue
        best_ratio = 0.0
        best_bn = ""
        for bn in b_lower:
            if bn in exact:
                continue
            ratio = SequenceMatcher(None, an, bn).ratio()
            if ratio >= NAME_FUZZY_MIN and ratio > best_ratio:
                best_ratio = ratio
                best_bn = bn
        if best_bn:
            signals.append(
                MatchSignal(
                    kind="name",
                    weight=WEIGHT_NAME_FUZZY,
                    detail=f"display name similar ({best_ratio:.2f})",
                    a_value=a_lower[an],
                    b_value=b_lower[best_bn],
                )
            )
    return signals


def _match_bios(a_bios: list[str], b_bios: list[str]) -> list[MatchSignal]:
    """Jaccard-overlap on meaningful bio tokens."""
    a_tokens: set[str] = set()
    for bio in a_bios:
        a_tokens |= _tokens(bio)
    b_tokens: set[str] = set()
    for bio in b_bios:
        b_tokens |= _tokens(bio)
    if len(a_tokens) < MIN_BIO_TOKENS or len(b_tokens) < MIN_BIO_TOKENS:
        return []
    shared = a_tokens & b_tokens
    union = a_tokens | b_tokens
    if not union:
        return []
    jaccard = len(shared) / len(union)
    if jaccard < BIO_JACCARD_MIN:
        return []
    preview = ", ".join(sorted(shared)[:5])
    return [
        MatchSignal(
            kind="bio",
            weight=WEIGHT_BIO_JACCARD,
            detail=f"bio tokens overlap ({jaccard:.2f}): {preview}",
            a_value=preview,
            b_value=preview,
        )
    ]


def _match_aliases(
    a_user: str, b_user: str, a_aliases: set[str], b_aliases: set[str]
) -> list[MatchSignal]:
    signals: list[MatchSignal] = []
    a_low, b_low = a_user.lower(), b_user.lower()
    if b_low and b_low in a_aliases:
        signals.append(
            MatchSignal(
                kind="alias",
                weight=WEIGHT_ALIAS,
                detail=f"{a_user}'s scan surfaced {b_user} as a variant",
                a_value=a_user,
                b_value=b_user,
            )
        )
    if a_low and a_low in b_aliases:
        signals.append(
            MatchSignal(
                kind="alias",
                weight=WEIGHT_ALIAS,
                detail=f"{b_user}'s scan surfaced {a_user} as a variant",
                a_value=b_user,
                b_value=a_user,
            )
        )
    return signals


def _match_countries(a: set[str], b: set[str]) -> list[MatchSignal]:
    # Country is weak on its own — cap impact by only surfacing up to 2.
    shared = sorted(a & b)[:2]
    return [
        MatchSignal(
            kind="country",
            weight=WEIGHT_COUNTRY,
            detail=f"country overlap: {c}",
            a_value=c,
            b_value=c,
        )
        for c in shared
    ]


# ── aggregation ───────────────────────────────────────────────────────


def _combine(signals: list[MatchSignal]) -> float:
    """Probabilistic OR: 1 - Π(1 - w). Always in [0, 1]."""
    leftover = 1.0
    for s in signals:
        w = max(0.0, min(1.0, s.weight))
        leftover *= 1.0 - w
    return round(1.0 - leftover, 6)


def _verdict(score: float, signals: list[MatchSignal]) -> str:
    if not signals:
        return "no_evidence"
    if score >= 0.80:
        return "very_likely_same"
    if score >= 0.50:
        return "likely_same"
    if score >= 0.25:
        return "possible"
    if score >= 0.10:
        return "weak_signal"
    return "no_evidence"


# ── public API ────────────────────────────────────────────────────────


def correlate(a: dict, b: dict) -> CorrelationResult:
    """Score the likelihood that two scan payloads describe the same person.

    Both inputs are expected to look like ``ScanResult.to_dict()`` — the
    usual history payload shape. Missing fields are tolerated; only the
    ones that are present contribute signals.
    """
    username_a = _clean(a.get("username"))
    username_b = _clean(b.get("username"))

    signals: list[MatchSignal] = []
    signals.extend(
        _match_exact_set(_emails(a), _emails(b), "email", WEIGHT_EMAIL, "shared email")
    )
    signals.extend(
        _match_exact_set(_phones(a), _phones(b), "phone", WEIGHT_PHONE, "shared phone")
    )
    signals.extend(
        _match_exact_set(_crypto(a), _crypto(b), "crypto", WEIGHT_CRYPTO, "shared wallet")
    )
    signals.extend(_match_names(_names(a), _names(b)))
    signals.extend(
        _match_exact_set(
            _locations(a), _locations(b), "location", WEIGHT_LOCATION_EXACT, "shared location"
        )
    )
    signals.extend(_match_countries(_countries(a), _countries(b)))
    signals.extend(_match_bios(_bios(a), _bios(b)))
    signals.extend(
        _match_aliases(username_a, username_b, _aliases(a), _aliases(b))
    )
    signals.extend(
        _match_exact_set(
            _avatars(a), _avatars(b), "avatar", WEIGHT_GRAVATAR_AVATAR, "shared avatar URL"
        )
    )

    score = _combine(signals)
    return CorrelationResult(
        username_a=username_a,
        username_b=username_b,
        score=score,
        verdict=_verdict(score, signals),
        signals=tuple(signals),
    )


# ── identity-candidate resolution ─────────────────────────────────────

IDENTITY_WEIGHT_DIRECT = 0.96
IDENTITY_WEIGHT_VERIFIED_EMAIL = 0.92
IDENTITY_WEIGHT_VERIFIED_PHONE = 0.92
IDENTITY_WEIGHT_EXTERNAL = 0.75
IDENTITY_WEIGHT_AVATAR = 0.75
IDENTITY_WEIGHT_NAME_EXACT = 0.40
IDENTITY_WEIGHT_NAME_FUZZY = 0.25
IDENTITY_WEIGHT_BIO = 0.25
IDENTITY_WEIGHT_LOCATION = 0.20
IDENTITY_WEIGHT_ORGANIZATION = 0.15
IDENTITY_WEIGHT_HANDLE = 0.10


def _profile_dicts(payload: dict) -> list[dict]:
    profiles: list[dict] = []
    for row in payload.get("platforms") or []:
        if not isinstance(row, dict):
            continue
        data = row.get("profile_data")
        if isinstance(data, dict):
            profiles.append(data)
    return profiles


def _identity_strings(payload: dict, keys: tuple[str, ...]) -> set[str]:
    values: set[str] = set()
    for profile in _profile_dicts(payload):
        for key in keys:
            value = profile.get(key)
            if isinstance(value, str) and value.strip():
                values.add(value.strip())
    return values


def _verified_contacts(payload: dict, *, kind: str) -> set[str]:
    values: set[str] = set()
    if kind == "email":
        for row in payload.get("emails") or []:
            if isinstance(row, dict) and row.get("verified"):
                value = row.get("email") or row.get("address")
                if isinstance(value, str) and value.strip():
                    values.add(value.strip().casefold())
        plural_key, value_keys, verified_key = (
            "verified_emails", ("email", "public_email"), "email_verified"
        )
    else:
        for row in payload.get("phone_intel") or []:
            if isinstance(row, dict) and row.get("verified"):
                value = row.get("e164") or row.get("number")
                if isinstance(value, str) and value.strip():
                    values.add(value.strip())
        plural_key, value_keys, verified_key = (
            "verified_phones", ("phone", "phone_number"), "phone_verified"
        )
    for profile in _profile_dicts(payload):
        plural = profile.get(plural_key) or []
        if isinstance(plural, list | tuple | set):
            values.update(
                str(value).strip().casefold()
                for value in plural
                if str(value).strip()
            )
        if profile.get(verified_key):
            for key in value_keys:
                value = profile.get(key)
                if isinstance(value, str) and value.strip():
                    values.add(value.strip().casefold())
    return values


def _normal_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    host = (parsed.hostname or "").casefold()
    if not host:
        return ""
    path = re.sub(r"/+", "/", parsed.path).rstrip("/")
    return urlunsplit(("https", host, path, "", ""))


def _external_urls(payload: dict) -> set[str]:
    values: set[str] = set()
    keys = ("blog", "website", "website_url", "web_url", "external_url", "url")
    for profile in _profile_dicts(payload):
        for key in keys:
            value = profile.get(key)
            if isinstance(value, str):
                normalized = _normal_url(value)
                if normalized:
                    values.add(normalized)
        links = profile.get("links")
        if isinstance(links, str):
            for value in re.findall(r"https?://[^\s,]+", links):
                normalized = _normal_url(value)
                if normalized:
                    values.add(normalized)
        elif isinstance(links, list | tuple | set):
            for value in links:
                if isinstance(value, str):
                    normalized = _normal_url(value)
                    if normalized:
                        values.add(normalized)
    return values


def _social_handles(payload: dict) -> set[str]:
    values: set[str] = set()
    for profile in _profile_dicts(payload):
        for key, value in profile.items():
            if key.endswith("_username") and isinstance(value, str) and value.strip():
                values.add(f"{key[:-9].casefold()}:{value.strip().lstrip('@').casefold()}")
        for container_key in ("social_handles", "socials"):
            container = profile.get(container_key)
            if isinstance(container, dict):
                for service, value in container.items():
                    if isinstance(value, str) and value.strip():
                        values.add(
                            f"{str(service).casefold()}:{value.strip().lstrip('@').casefold()}"
                        )
    return values


def _identity_avatars(payload: dict) -> set[str]:
    values = _identity_strings(
        payload,
        ("avatar", "avatar_url", "profile_picture", "profile_pic", "picture", "icon_img"),
    )
    return {
        value.strip().casefold()
        for value in values
        if not any(
            marker in value.casefold()
            for marker in ("default", "placeholder", "identicon", "blank-avatar")
        )
    }


def _identity_names(payload: dict) -> set[str]:
    return _identity_strings(
        payload, ("display_name", "name", "full_name", "fullname", "real_name")
    )


def _identity_bios(payload: dict) -> list[str]:
    return sorted(
        _identity_strings(payload, ("bio", "description", "details", "about", "summary"))
    )


def _identity_locations(payload: dict) -> set[str]:
    return {
        value.casefold()
        for value in _identity_strings(payload, ("location", "country", "region"))
    }


def _identity_organizations(payload: dict) -> set[str]:
    values = {
        value.casefold()
        for value in _identity_strings(
            payload, ("organization", "organisation", "company", "workplace")
        )
    }
    for profile in _profile_dicts(payload):
        organizations = profile.get("organizations") or profile.get("orgs") or []
        if isinstance(organizations, list | tuple | set):
            for row in organizations:
                if isinstance(row, str) and row.strip():
                    values.add(row.strip().casefold())
                elif isinstance(row, dict):
                    value = row.get("name") or row.get("fullname") or row.get("user")
                    if isinstance(value, str) and value.strip():
                        values.add(value.strip().casefold())
    return values


def _identity_name_signals(a: dict, b: dict) -> list[MatchSignal]:
    left = {name.casefold(): name for name in _identity_names(a)}
    right = {name.casefold(): name for name in _identity_names(b)}
    exact = sorted(set(left) & set(right))
    if exact:
        value = exact[0]
        return [
            MatchSignal(
                kind="display_name",
                weight=IDENTITY_WEIGHT_NAME_EXACT,
                detail=f"exact display name: {left[value]}",
                a_value=left[value],
                b_value=right[value],
            )
        ]
    best: tuple[float, str, str] | None = None
    for left_key, left_value in left.items():
        for right_key, right_value in right.items():
            ratio = SequenceMatcher(None, left_key, right_key).ratio()
            if ratio >= NAME_FUZZY_MIN and (best is None or ratio > best[0]):
                best = (ratio, left_value, right_value)
    if best is None:
        return []
    return [
        MatchSignal(
            kind="display_name_fuzzy",
            weight=IDENTITY_WEIGHT_NAME_FUZZY,
            detail=f"similar display name ({best[0]:.2f})",
            a_value=best[1],
            b_value=best[2],
        )
    ]


def _identity_bio_signal(a: dict, b: dict) -> list[MatchSignal]:
    matches = _match_bios(_identity_bios(a), _identity_bios(b))
    return [
        MatchSignal(
            kind="bio",
            weight=IDENTITY_WEIGHT_BIO,
            detail=match.detail,
            a_value=match.a_value,
            b_value=match.b_value,
        )
        for match in matches[:1]
    ]


def _identity_verdict(score: float, signals: list[MatchSignal]) -> str:
    kinds = {signal.kind for signal in signals}
    if kinds & {"direct_profile_link", "verified_email", "verified_phone"}:
        return "confirmed_same"
    non_handle = kinds - {"handle_similarity"}
    strong = any(signal.weight >= 0.75 for signal in signals)
    if score >= 0.70 and len(non_handle) >= 2 and strong:
        return "likely_same"
    if score >= 0.35 and non_handle:
        return "possible_same"
    return "uncertain"


def correlate_identity(
    a: dict,
    b: dict,
    *,
    handle_score: float | None = None,
    direct_link: bool = False,
) -> CorrelationResult:
    """Resolve an alias candidate without allowing handle similarity to prove identity."""
    username_a = _clean(a.get("username"))
    username_b = _clean(b.get("username"))
    if handle_score is None:
        from core.smart_search import handle_similarity

        handle_score = handle_similarity(username_a, username_b)
    handle_score = max(0.0, min(1.0, float(handle_score)))

    signals: list[MatchSignal] = []
    if direct_link:
        signals.append(
            MatchSignal(
                kind="direct_profile_link",
                weight=IDENTITY_WEIGHT_DIRECT,
                detail="a public profile directly links the other handle",
                a_value=username_a,
                b_value=username_b,
            )
        )
    signals.extend(
        _match_exact_set(
            _verified_contacts(a, kind="email"),
            _verified_contacts(b, kind="email"),
            "verified_email",
            IDENTITY_WEIGHT_VERIFIED_EMAIL,
            "verified shared email",
        )[:1]
    )
    signals.extend(
        _match_exact_set(
            _verified_contacts(a, kind="phone"),
            _verified_contacts(b, kind="phone"),
            "verified_phone",
            IDENTITY_WEIGHT_VERIFIED_PHONE,
            "verified shared phone",
        )[:1]
    )
    signals.extend(
        _match_exact_set(
            _external_urls(a), _external_urls(b), "external_url",
            IDENTITY_WEIGHT_EXTERNAL, "shared external URL",
        )[:1]
    )
    signals.extend(
        _match_exact_set(
            _social_handles(a), _social_handles(b), "social_handle",
            IDENTITY_WEIGHT_EXTERNAL, "shared external social handle",
        )[:1]
    )
    signals.extend(
        _match_exact_set(
            _identity_avatars(a), _identity_avatars(b), "avatar",
            IDENTITY_WEIGHT_AVATAR, "shared non-default avatar",
        )[:1]
    )
    signals.extend(_identity_name_signals(a, b))
    signals.extend(_identity_bio_signal(a, b))
    signals.extend(
        _match_exact_set(
            _identity_locations(a), _identity_locations(b), "location",
            IDENTITY_WEIGHT_LOCATION, "shared location",
        )[:1]
    )
    signals.extend(
        _match_exact_set(
            _identity_organizations(a), _identity_organizations(b), "organization",
            IDENTITY_WEIGHT_ORGANIZATION, "shared organization",
        )[:1]
    )
    if username_a and username_b:
        signals.append(
            MatchSignal(
                kind="handle_similarity",
                weight=min(IDENTITY_WEIGHT_HANDLE, IDENTITY_WEIGHT_HANDLE * handle_score),
                detail=f"Damerau-Levenshtein handle similarity ({handle_score:.2f})",
                a_value=username_a,
                b_value=username_b,
            )
        )

    score = _combine(signals)
    return CorrelationResult(
        username_a=username_a,
        username_b=username_b,
        score=score,
        verdict=_identity_verdict(score, signals),
        signals=tuple(signals),
    )
