"""Email discovery and breach checking."""

from core.http_client import HTTPClient
from core.models import EmailResult
from utils.helpers import md5_hash

COMMON_DOMAINS = [
    # global personal
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "protonmail.com",
    "proton.me",
    "pm.me",
    "icloud.com",
    "me.com",
    "mac.com",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    # business / privacy
    "zoho.com",
    "fastmail.com",
    "tutanota.com",
    "tuta.io",
    "hey.com",
    "skiff.com",
    "mailbox.org",
    # regional
    "web.de",
    "gmx.de",
    "gmx.net",
    "gmx.com",
    "rambler.ru",
    "mail.ru",
    "inbox.ru",
    "list.ru",
    "bk.ru",
    "qq.com",
    "163.com",
    "126.com",
    "foxmail.com",
    "sina.com",
    "sohu.com",
    "rediffmail.com",
    "in.com",
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
            fi, li = first[0], last[0]  # initials
            patterns = [
                # first-last combos
                f"{first}.{last}",
                f"{first}{last}",
                f"{first}_{last}",
                f"{first}-{last}",
                f"{last}.{first}",
                f"{last}{first}",
                f"{last}_{first}",
                f"{last}-{first}",
                # initial combos
                f"{fi}.{last}",
                f"{fi}_{last}",
                f"{fi}{last}",
                f"{first}.{li}",
                f"{first}_{li}",
                f"{first}{li}",
                f"{fi}.{li}",
                f"{fi}_{li}",
                f"{fi}{li}",
                # standalone
                f"{first}",
                f"{last}",
                # common suffixes on first name
                f"{first}_",
                f"{first}01",
                f"{first}1",
                f"{first}123",
            ]
            if len(parts) >= 3:
                middle = parts[1]
                mi = middle[0]
                patterns.extend([
                    f"{first}.{mi}.{last}",
                    f"{fi}{mi}{last}",
                    f"{first}{mi}{last}",
                    f"{first}_{mi}_{last}",
                    f"{fi}.{mi}.{last}",
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
