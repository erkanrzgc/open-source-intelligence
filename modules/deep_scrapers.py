"""Deep profile scrapers for platforms with accessible APIs."""

import html
import re
from urllib.parse import urlencode, urlparse

from core.http_client import HTTPClient


async def scrape_github(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://api.github.com/users/{username}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if status != 200 or not data:
        return {}
    return {
        "username": data.get("login", ""),
        "name": data.get("name", ""),
        "bio": data.get("bio", ""),
        "location": data.get("location", ""),
        "email": data.get("email", ""),
        "company": data.get("company", ""),
        "blog": data.get("blog", ""),
        "twitter_username": data.get("twitter_username", ""),
        "public_repos": data.get("public_repos", 0),
        "public_gists": data.get("public_gists", 0),
        "followers": data.get("followers", 0),
        "following": data.get("following", 0),
        "created_at": data.get("created_at", ""),
        "avatar_url": data.get("avatar_url", ""),
        "hireable": data.get("hireable"),
    }


async def scrape_reddit(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://www.reddit.com/user/{username}/about.json"
    )
    if status != 200 or not data:
        return {}
    d = data.get("data", {})
    return {
        "name": d.get("name", ""),
        "total_karma": d.get("total_karma", 0),
        "created_utc": d.get("created_utc", 0),
        "has_verified_email": d.get("has_verified_email", False),
        "is_gold": d.get("is_gold", False),
        "is_mod": d.get("is_mod", False),
        "icon_img": d.get("icon_img", ""),
        "subreddit_name": d.get("subreddit", {}).get("display_name_prefixed", ""),
        "subreddit_title": d.get("subreddit", {}).get("title", ""),
        "subreddit_description": d.get("subreddit", {}).get("public_description", ""),
    }


async def scrape_gitlab(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://gitlab.com/api/v4/users?username={username}"
    )
    if status != 200 or not data or not isinstance(data, list) or len(data) == 0:
        return {}
    user = next(
        (
            row
            for row in data
            if isinstance(row, dict)
            and str(row.get("username", "")).casefold() == username.casefold()
        ),
        None,
    )
    if user is None:
        return {}
    return {
        "name": user.get("name", ""),
        "username": user.get("username", ""),
        "bio": user.get("bio", ""),
        "location": user.get("location", ""),
        "avatar_url": user.get("avatar_url", ""),
        "web_url": user.get("web_url", ""),
        "website_url": user.get("website_url", ""),
        "organization": user.get("organization", ""),
        "job_title": user.get("job_title", ""),
        "followers": user.get("followers", 0),
        "following": user.get("following", 0),
    }


async def scrape_devto(client: HTTPClient, username: str) -> dict:
    query = urlencode({"url": username})
    status, data, _ = await client.get_json(
        f"https://dev.to/api/users/by_username?{query}",
        headers={"Accept": "application/vnd.forem.api-v1+json"},
    )
    if (
        status != 200
        or not isinstance(data, dict)
        or str(data.get("username", "")).casefold() != username.casefold()
    ):
        return {}
    return {
        "name": data.get("name", ""),
        "username": data.get("username", ""),
        "summary": data.get("summary", ""),
        "location": data.get("location", ""),
        "joined_at": data.get("joined_at", ""),
        "github_username": data.get("github_username", ""),
        "twitter_username": data.get("twitter_username", ""),
        "website_url": data.get("website_url", ""),
        "profile_image": data.get("profile_image", ""),
    }


async def scrape_hugging_face(client: HTTPClient, username: str) -> dict:
    """Normalize the public Hub user overview and social endpoints."""
    overview_status, overview, _ = await client.get_json(
        f"https://huggingface.co/api/users/{username}/overview",
        headers={"Accept": "application/json"},
    )
    if overview_status != 200 or not isinstance(overview, dict):
        return {}

    socials_status, socials, _ = await client.get_json(
        f"https://huggingface.co/api/users/{username}/socials",
        headers={"Accept": "application/json"},
    )
    social_handles: dict[str, str] = {}
    if socials_status == 200 and isinstance(socials, dict):
        raw_handles = socials.get("socialHandles") or {}
        if isinstance(raw_handles, dict):
            social_handles = {
                str(service).casefold(): value.strip().lstrip("@")
                for service, value in raw_handles.items()
                if isinstance(value, str) and value.strip()
            }

    organizations: list[str] = []
    for organization in overview.get("orgs") or []:
        if isinstance(organization, str) and organization.strip():
            organizations.append(organization.strip())
        elif isinstance(organization, dict):
            value = (
                organization.get("fullname")
                or organization.get("name")
                or organization.get("user")
            )
            if isinstance(value, str) and value.strip():
                organizations.append(value.strip())

    return {
        "username": overview.get("user", ""),
        "name": overview.get("fullname", ""),
        "bio": overview.get("details", ""),
        "avatar_url": overview.get("avatarUrl", ""),
        "organizations": organizations,
        "social_handles": social_handles,
        "twitter_username": social_handles.get("twitter", ""),
        "github_username": social_handles.get("github", ""),
        "linkedin_username": social_handles.get("linkedin", ""),
        "followers": overview.get("numFollowers", 0),
        "following": overview.get("numFollowing", 0),
        "models": overview.get("numModels", 0),
        "datasets": overview.get("numDatasets", 0),
        "spaces": overview.get("numSpaces", 0),
        "created_at": overview.get("createdAt", ""),
    }


async def scrape_medium(client: HTTPClient, username: str) -> dict:
    """Validate Medium's documented profile RSS against its canonical link."""
    status, body, _ = await client.get(f"https://medium.com/feed/@{username}")
    if status != 200 or not body:
        return {}

    raw_links = re.findall(
        r"<link(?:\s[^>]*)?>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</link>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    expected_path = f"/@{username}".casefold()
    for raw_link in raw_links:
        candidate = html.unescape(raw_link.strip())
        parsed = urlparse(candidate)
        if parsed.netloc.casefold() in {"medium.com", "www.medium.com"} and (
            parsed.path.rstrip("/").casefold() == expected_path
        ):
            return {"username": username, "canonical_url": candidate}
    return {}


async def scrape_hackernews(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://hacker-news.firebaseio.com/v0/user/{username}.json"
    )
    if status != 200 or not data:
        return {}
    return {
        "id": data.get("id", ""),
        "karma": data.get("karma", 0),
        "about": data.get("about", ""),
        "created": data.get("created", 0),
        "submitted_count": len(data.get("submitted", [])),
    }


async def scrape_chess_com(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://api.chess.com/pub/player/{username}"
    )
    if status != 200 or not data:
        return {}
    result = {
        "username": data.get("username", ""),
        "name": data.get("name", ""),
        "location": data.get("location", ""),
        "country": data.get("country", ""),
        "joined": data.get("joined", 0),
        "last_online": data.get("last_online", 0),
        "followers": data.get("followers", 0),
        "status": data.get("status", ""),
        "is_streamer": data.get("is_streamer", False),
        "avatar": data.get("avatar", ""),
    }
    stats_status, stats_data, _ = await client.get_json(
        f"https://api.chess.com/pub/player/{username}/stats"
    )
    if stats_status == 200 and stats_data:
        for mode in ["chess_rapid", "chess_blitz", "chess_bullet"]:
            mode_data = stats_data.get(mode, {})
            last = mode_data.get("last", {})
            if last:
                result[f"{mode}_rating"] = last.get("rating", 0)
    return result


async def scrape_lichess(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://lichess.org/api/user/{username}",
        headers={"Accept": "application/json"},
    )
    if status != 200 or not data:
        return {}
    perfs = data.get("perfs", {})
    result = {
        "username": data.get("username", ""),
        "bio": data.get("profile", {}).get("bio", ""),
        "country": data.get("profile", {}).get("country", ""),
        "location": data.get("profile", {}).get("location", ""),
        "first_name": data.get("profile", {}).get("firstName", ""),
        "last_name": data.get("profile", {}).get("lastName", ""),
        "links": data.get("profile", {}).get("links", ""),
        "created_at": data.get("createdAt", 0),
        "seen_at": data.get("seenAt", 0),
        "play_time_total": data.get("playTime", {}).get("total", 0),
        "count_all": data.get("count", {}).get("all", 0),
        "patron": data.get("patron", False),
    }
    for mode in ["rapid", "blitz", "bullet", "classical"]:
        mode_data = perfs.get(mode, {})
        if mode_data:
            result[f"{mode}_rating"] = mode_data.get("rating", 0)
            result[f"{mode}_games"] = mode_data.get("games", 0)
    return result


async def scrape_steam(client: HTTPClient, username: str) -> dict:
    status, body, _ = await client.get(
        f"https://steamcommunity.com/id/{username}/?xml=1"
    )
    if status != 200 or not body:
        return {}

    def extract_xml(tag: str, text: str) -> str:
        m = re.search(rf"<{tag}><!\[CDATA\[(.*?)\]\]></{tag}>", text, re.DOTALL)
        if m:
            return m.group(1).strip()
        m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
        return m.group(1).strip() if m else ""

    return {
        "steam_id": extract_xml("steamID64", body),
        "persona_name": extract_xml("steamID", body),
        "real_name": extract_xml("realname", body),
        "summary": extract_xml("summary", body),
        "member_since": extract_xml("memberSince", body),
        "location": extract_xml("location", body),
        "avatar_url": extract_xml("avatarFull", body),
        "online_state": extract_xml("onlineState", body),
        "vac_banned": extract_xml("vacBanned", body),
    }


async def scrape_keybase(client: HTTPClient, username: str) -> dict:
    status, data, _ = await client.get_json(
        f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}"
    )
    if status != 200 or not data:
        return {}
    them = data.get("them", [])
    if not them:
        return {}
    user = them[0]
    profile = user.get("profile", {})
    proofs = user.get("proofs_summary", {}).get("all", [])
    proof_list = [
        {"service": p.get("proof_type"), "username": p.get("nametag")}
        for p in proofs
    ]
    return {
        "username": user.get("basics", {}).get("username", ""),
        "full_name": profile.get("full_name", ""),
        "bio": profile.get("bio", ""),
        "location": profile.get("location", ""),
        "proofs": proof_list,
    }


async def scrape_twitter(client: HTTPClient, username: str) -> dict:
    """Try Twitter syndication API (no auth required, may be limited)."""
    url = f"https://cdn.syndication.twimg.com/timeline/profile?screen_name={username}"
    headers = {"Accept": "application/json"}
    status, data, _ = await client.get_json(url, headers=headers)
    if status != 200 or not data:
        return {}
    headline = data.get("headline", {}) or {}
    return {
        "name": headline.get("title", ""),
        "username": username,
        "bio": (headline.get("description") or {}).get("text", "") if isinstance(headline.get("description"), dict) else "",
    }


async def scrape_tiktok(client: HTTPClient, username: str) -> dict:
    """Parse TikTok profile by extracting __UNIVERSAL_DATA_FOR_REHYDRATION__ JSON."""
    import json
    import re

    url = f"https://www.tiktok.com/@{username}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        ),
    }
    status, body, _ = await client.get(url, headers=headers)
    if status != 200 or not body:
        return {}

    pattern = r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>'
    m = re.search(pattern, body, re.DOTALL)
    if not m:
        return {}

    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}

    user_detail = (
        data.get("__DEFAULT_SCOPE__", {})
        .get("webapp.user-detail", {})
        .get("userInfo", {})
    )
    user = user_detail.get("user", {})
    stats = user_detail.get("stats", {})

    if not user:
        return {}

    return {
        "name": user.get("nickname", ""),
        "username": user.get("uniqueId", ""),
        "bio": user.get("signature", ""),
        "is_verified": user.get("verified", False),
        "is_private": user.get("privateAccount", False),
        "avatar_url": user.get("avatarLarger", "") or user.get("avatarMedium", ""),
        "region": user.get("region", ""),
        "language": user.get("language", ""),
        "followers": stats.get("followerCount", 0),
        "following": stats.get("followingCount", 0),
        "video_count": stats.get("videoCount", 0),
        "heart_count": stats.get("heartCount", 0),
        "id": user.get("id", ""),
    }


async def scrape_youtube(client: HTTPClient, username: str) -> dict:
    """Extract YouTube channel info from page meta tags."""
    import re

    url = f"https://www.youtube.com/@{username}"
    status, body, _ = await client.get(url)
    if status != 200 or not body:
        return {}

    def meta(prop: str) -> str:
        m = re.search(
            rf'<meta\s+(?:property|name|itemprop)="{re.escape(prop)}"\s+content="([^"]*)"',
            body,
        )
        return m.group(1) if m else ""

    name = meta("og:title")
    if not name:
        return {}

    description = meta("og:description")
    avatar = meta("og:image")
    keywords = meta("keywords")

    sub_match = re.search(r'"subscriberCountText":\{"accessibility".*?"simpleText":"([^"]*)"', body)
    subs = sub_match.group(1) if sub_match else ""

    video_match = re.search(r'"videoCountText":\{"runs":\[\{"text":"([^"]*)"', body)
    video_count = video_match.group(1) if video_match else ""

    return {
        "name": name,
        "bio": description,
        "avatar_url": avatar,
        "keywords": keywords,
        "subscribers": subs,
        "video_count": video_count,
    }


async def scrape_npm(client: HTTPClient, username: str) -> dict:
    url = f"https://www.npmjs.com/~{username}"
    headers = {"X-Spiferack": "1", "Accept": "application/json"}
    status, data, _ = await client.get_json(url, headers=headers)
    if status != 200 or not data:
        return {}
    return {
        "name": data.get("scope", {}).get("parent", {}).get("fullname", ""),
        "username": username,
        "email": data.get("scope", {}).get("parent", {}).get("email", ""),
        "github": data.get("scope", {}).get("parent", {}).get("github", ""),
        "twitter": data.get("scope", {}).get("parent", {}).get("twitter", ""),
        "package_count": len(data.get("packages", {}).get("objects", [])),
    }


DEEP_SCRAPERS = {
    "GitHub": scrape_github,
    "GitLab": scrape_gitlab,
    "Dev.to": scrape_devto,
    "Hugging Face": scrape_hugging_face,
    "Medium": scrape_medium,
    "Hacker News": scrape_hackernews,
    "Chess.com": scrape_chess_com,
    "Lichess": scrape_lichess,
    "Steam": scrape_steam,
    "Keybase": scrape_keybase,
    "TikTok": scrape_tiktok,
    "YouTube": scrape_youtube,
    "npm": scrape_npm,
}
