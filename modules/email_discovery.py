"""Email discovery and breach checking."""

from core.http_client import HTTPClient
from core.models import EmailResult
from utils.helpers import md5_hash

COMMON_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "icloud.com",
    "mail.com",
    "yandex.com",
]


def generate_email_candidates(username: str, full_name: str | None = None) -> list[str]:
    candidates: list[str] = []
    clean = username.lower().strip().replace(" ", "")
    seen: set[str] = set()

    def add(candidate: str) -> None:
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

    # Username-based candidates
    for domain in COMMON_DOMAINS:
        add(f"{clean}@{domain}")

    # Name-based candidates from full_name
    if full_name:
        parts = [p.lower().strip() for p in full_name.split() if p.strip()]
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            patterns = [
                f"{first}.{last}",           # erkan.rizgic
                f"{first}{last}",            # erkanrizgic
                f"{last}.{first}",           # rizgic.erkan
                f"{last}{first}",            # rizgicerkan
                f"{first[0]}.{last}",        # e.rizgic
                f"{first[0]}{last}",         # erizgic
                f"{first}.{last[0]}",        # erkan.r
                f"{first}",                  # erkan
                f"{last}",                   # rizgic
            ]
            if len(parts) >= 3:
                middle = parts[1]
                patterns.extend([
                    f"{first}{middle[0]}{last}",     # erkanrrizgic
                    f"{first[0]}{middle[0]}{last}",  # errrizgic
                ])
            for pattern in patterns:
                for domain in COMMON_DOMAINS:
                    add(f"{pattern}@{domain}")

    return candidates


async def check_gravatar(client: HTTPClient, email: str) -> dict | None:
    h = md5_hash(email)
    status, data, _ = await client.get_json(
        f"https://en.gravatar.com/{h}.json"
    )
    if status != 200 or not data:
        return None

    entries = data.get("entry", [])
    if not entries:
        return None

    entry = entries[0]
    return {
        "display_name": entry.get("displayName", ""),
        "name": entry.get("name", {}).get("formatted", ""),
        "location": entry.get("currentLocation", ""),
        "about": entry.get("aboutMe", ""),
        "urls": [u.get("value") for u in entry.get("urls", [])],
        "photos": [p.get("value") for p in entry.get("photos", [])],
        "accounts": [
            {"service": a.get("shortname"), "url": a.get("url")}
            for a in entry.get("accounts", [])
        ],
    }


async def discover_emails(
    client: HTTPClient,
    username: str,
    known_emails: list[str] | None = None,
    full_name: str | None = None,
) -> list[EmailResult]:
    results = []
    candidates = generate_email_candidates(username, full_name)
    if known_emails:
        for e in known_emails:
            if e not in candidates:
                candidates.insert(0, e)

    for email in candidates:
        gravatar = await check_gravatar(client, email)
        if gravatar:
            results.append(
                EmailResult(
                    email=email,
                    source="gravatar",
                    verified=True,
                    gravatar=True,
                )
            )

    return results
