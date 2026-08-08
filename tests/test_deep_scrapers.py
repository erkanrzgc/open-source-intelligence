"""Tests for modules/deep_scrapers.py."""

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.deep_scrapers import (
    DEEP_SCRAPERS,
    scrape_chess_com,
    scrape_devto,
    scrape_github,
    scrape_gitlab,
    scrape_hackernews,
    scrape_instagram,
    scrape_keybase,
    scrape_lichess,
    scrape_npm,
    scrape_reddit,
    scrape_steam,
    scrape_tiktok,
    scrape_twitter,
    scrape_youtube,
)


def test_registry_contains_expected_platforms():
    expected = [
        "GitHub",
        "Reddit",
        "GitLab",
        "Dev.to",
        "Hacker News",
        "Chess.com",
        "Lichess",
        "Steam",
        "Keybase",
        "Instagram",
    ]
    for name in expected:
        assert name in DEEP_SCRAPERS


@pytest.mark.asyncio
async def test_github_success():
    payload = {
        "name": "Alice",
        "bio": "dev",
        "location": "TR",
        "email": "a@b.com",
        "blog": "https://me",
        "twitter_username": "alice_t",
        "public_repos": 10,
        "followers": 5,
        "following": 2,
        "avatar_url": "https://gh/av",
    }
    with aioresponses() as m:
        m.get("https://api.github.com/users/alice", status=200, payload=payload)
        async with HTTPClient() as client:
            result = await scrape_github(client, "alice")
    assert result["name"] == "Alice"
    assert result["twitter_username"] == "alice_t"
    assert result["public_repos"] == 10


@pytest.mark.asyncio
async def test_github_404():
    with aioresponses() as m:
        m.get("https://api.github.com/users/alice", status=404)
        async with HTTPClient() as client:
            result = await scrape_github(client, "alice")
    assert result == {}


@pytest.mark.asyncio
async def test_reddit_success():
    payload = {
        "data": {
            "name": "alice",
            "total_karma": 666,
            "created_utc": 1600000000,
            "has_verified_email": True,
            "icon_img": "https://r/av",
            "subreddit": {
                "display_name_prefixed": "u/alice",
                "title": "Alice",
                "public_description": "hi",
            },
        }
    }
    with aioresponses() as m:
        m.get(
            "https://www.reddit.com/user/alice/about.json",
            status=200,
            payload=payload,
        )
        async with HTTPClient() as client:
            result = await scrape_reddit(client, "alice")
    assert result["total_karma"] == 666
    assert result["subreddit_name"] == "u/alice"


@pytest.mark.asyncio
async def test_gitlab_success():
    with aioresponses() as m:
        m.get(
            "https://gitlab.com/api/v4/users?username=alice",
            status=200,
            payload=[{"name": "Alice", "username": "alice", "bio": "b"}],
        )
        async with HTTPClient() as client:
            result = await scrape_gitlab(client, "alice")
    assert result["name"] == "Alice"


@pytest.mark.asyncio
async def test_gitlab_empty_list():
    with aioresponses() as m:
        m.get(
            "https://gitlab.com/api/v4/users?username=alice",
            status=200,
            payload=[],
        )
        async with HTTPClient() as client:
            result = await scrape_gitlab(client, "alice")
    assert result == {}


@pytest.mark.asyncio
async def test_devto_success():
    with aioresponses() as m:
        m.get(
            "https://dev.to/api/users/by_username?url=alice",
            status=200,
            payload={"name": "Alice", "username": "alice", "summary": "s"},
        )
        async with HTTPClient() as client:
            result = await scrape_devto(client, "alice")
    assert result["name"] == "Alice"


@pytest.mark.asyncio
async def test_hackernews_success():
    with aioresponses() as m:
        m.get(
            "https://hacker-news.firebaseio.com/v0/user/alice.json",
            status=200,
            payload={"id": "alice", "karma": 42, "submitted": [1, 2, 3]},
        )
        async with HTTPClient() as client:
            result = await scrape_hackernews(client, "alice")
    assert result["karma"] == 42
    assert result["submitted_count"] == 3


@pytest.mark.asyncio
async def test_chess_com_with_stats():
    with aioresponses() as m:
        m.get(
            "https://api.chess.com/pub/player/alice",
            status=200,
            payload={"username": "alice", "name": "Alice"},
        )
        m.get(
            "https://api.chess.com/pub/player/alice/stats",
            status=200,
            payload={"chess_rapid": {"last": {"rating": 1500}}},
        )
        async with HTTPClient() as client:
            result = await scrape_chess_com(client, "alice")
    assert result["chess_rapid_rating"] == 1500


@pytest.mark.asyncio
async def test_lichess_success():
    payload = {
        "username": "alice",
        "profile": {"bio": "b", "country": "TR", "firstName": "A", "lastName": "B"},
        "perfs": {"rapid": {"rating": 1800, "games": 100}},
        "createdAt": 1600000000,
    }
    with aioresponses() as m:
        m.get("https://lichess.org/api/user/alice", status=200, payload=payload)
        async with HTTPClient() as client:
            result = await scrape_lichess(client, "alice")
    assert result["rapid_rating"] == 1800
    assert result["first_name"] == "A"


@pytest.mark.asyncio
async def test_steam_xml_parse():
    body = """<profile>
        <steamID64>123456</steamID64>
        <steamID><![CDATA[alice]]></steamID>
        <realname><![CDATA[Alice Doe]]></realname>
        <summary><![CDATA[hi]]></summary>
        <location><![CDATA[TR]]></location>
    </profile>"""
    with aioresponses() as m:
        m.get("https://steamcommunity.com/id/alice/?xml=1", status=200, body=body)
        async with HTTPClient() as client:
            result = await scrape_steam(client, "alice")
    assert result["steam_id"] == "123456"
    assert result["real_name"] == "Alice Doe"
    assert result["location"] == "TR"


@pytest.mark.asyncio
async def test_keybase_success():
    payload = {
        "them": [
            {
                "basics": {"username": "alice"},
                "profile": {"full_name": "Alice", "bio": "b", "location": "TR"},
                "proofs_summary": {
                    "all": [{"proof_type": "twitter", "nametag": "alice_t"}]
                },
            }
        ]
    }
    with aioresponses() as m:
        m.get(
            "https://keybase.io/_/api/1.0/user/lookup.json?usernames=alice",
            status=200,
            payload=payload,
        )
        async with HTTPClient() as client:
            result = await scrape_keybase(client, "alice")
    assert result["full_name"] == "Alice"
    assert result["proofs"][0]["service"] == "twitter"


@pytest.mark.asyncio
async def test_keybase_empty_them():
    with aioresponses() as m:
        m.get(
            "https://keybase.io/_/api/1.0/user/lookup.json?usernames=alice",
            status=200,
            payload={"them": []},
        )
        async with HTTPClient() as client:
            result = await scrape_keybase(client, "alice")
    assert result == {}


@pytest.mark.asyncio
async def test_instagram_success():
    payload = {
        "data": {
            "user": {
                "full_name": "Alice",
                "username": "alice",
                "biography": "bio",
                "edge_followed_by": {"count": 1000},
                "edge_follow": {"count": 100},
                "edge_owner_to_timeline_media": {"count": 50},
                "profile_pic_url_hd": "https://i/a.jpg",
                "id": "123",
            }
        }
    }
    with aioresponses() as m:
        m.get(
            "https://www.instagram.com/api/v1/users/web_profile_info/?username=alice",
            status=200,
            payload=payload,
        )
        async with HTTPClient() as client:
            result = await scrape_instagram(client, "alice")
    assert result["name"] == "Alice"
    assert result["followers"] == 1000


@pytest.mark.asyncio
async def test_twitter_syndication_success():
    with aioresponses() as m:
        m.get(
            "https://cdn.syndication.twimg.com/timeline/profile?screen_name=alice",
            status=200,
            payload={"headline": {"title": "Alice"}},
        )
        async with HTTPClient() as client:
            result = await scrape_twitter(client, "alice")
    assert result["name"] == "Alice"


@pytest.mark.asyncio
async def test_tiktok_no_script():
    with aioresponses() as m:
        m.get("https://www.tiktok.com/@alice", status=200, body="<html></html>")
        async with HTTPClient() as client:
            result = await scrape_tiktok(client, "alice")
    assert result == {}


@pytest.mark.asyncio
async def test_tiktok_404():
    with aioresponses() as m:
        m.get("https://www.tiktok.com/@alice", status=404)
        async with HTTPClient() as client:
            result = await scrape_tiktok(client, "alice")
    assert result == {}


@pytest.mark.asyncio
async def test_youtube_no_title():
    with aioresponses() as m:
        m.get("https://www.youtube.com/@alice", status=200, body="<html></html>")
        async with HTTPClient() as client:
            result = await scrape_youtube(client, "alice")
    assert result == {}


@pytest.mark.asyncio
async def test_youtube_with_meta():
    body = (
        '<meta property="og:title" content="Alice Channel">'
        '<meta property="og:description" content="hi">'
        '<meta property="og:image" content="https://y/a.jpg">'
    )
    with aioresponses() as m:
        m.get("https://www.youtube.com/@alice", status=200, body=body)
        async with HTTPClient() as client:
            result = await scrape_youtube(client, "alice")
    assert result["name"] == "Alice Channel"
    assert result["bio"] == "hi"


@pytest.mark.asyncio
async def test_npm_success():
    payload = {
        "scope": {"parent": {"fullname": "Alice", "email": "a@b.com", "github": "alice"}},
        "packages": {"objects": [{"name": "pkg1"}, {"name": "pkg2"}]},
    }
    with aioresponses() as m:
        m.get("https://www.npmjs.com/~alice", status=200, payload=payload)
        async with HTTPClient() as client:
            result = await scrape_npm(client, "alice")
    assert result["name"] == "Alice"
    assert result["package_count"] == 2
