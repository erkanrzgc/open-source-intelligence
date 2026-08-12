"""Tests for the Sprint 3 reverse image sources."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.reverse_image import tineye, yandex
from modules.reverse_image.models import ReverseImageHit
from modules.reverse_image.orchestrator import _dedupe, run_reverse_image

# ── ReverseImageHit / dedupe ────────────────────────────────────────


def test_reverse_image_hit_to_dict_is_json_safe() -> None:
    hit = ReverseImageHit(
        source="yandex",
        source_url="https://cdn.example.com/a.jpg",
        match_url="https://blog.example.com/post",
        title="Example blog",
        image_url="https://thumb.example.com/a.jpg",
        score=0.5,
        metadata={"host": "blog.example.com"},
    )
    d = hit.to_dict()
    assert d["source"] == "yandex"
    assert d["match_url"] == "https://blog.example.com/post"
    assert d["metadata"]["host"] == "blog.example.com"


def test_dedupe_keeps_highest_score_match() -> None:
    hits = [
        ReverseImageHit("yandex", "img", "https://page.example.com/x", score=0.1),
        ReverseImageHit("tineye", "img", "https://page.example.com/x", score=0.9),
        ReverseImageHit("yandex", "img", "https://other.example.com/y", score=0.3),
        ReverseImageHit("yandex", "img", "", score=0.5),  # dropped — empty
    ]
    out = _dedupe(hits)
    assert len(out) == 2
    first = [h for h in out if h.match_url == "https://page.example.com/x"][0]
    assert first.score == 0.9
    assert first.source == "tineye"


# ── Yandex ──────────────────────────────────────────────────────────


_YANDEX_HTML = """
<html><body>
<ul>
  <li class="CbirSites-Item">
    <div class="CbirSites-ItemTitle">
      <a href="https://blog.example.com/post">Example Post</a>
    </div>
    <div class="CbirSites-ItemThumb"><img src="https://thumb.example.com/1.jpg"></div>
    <div class="CbirSites-ItemDescription">A nice blog post</div>
  </li>
  <li class="CbirSites-Item">
    <div class="CbirSites-ItemTitle">
      <a href="https://other.example.com/x">Other</a>
    </div>
    <div class="CbirSites-ItemDescription">Other description</div>
  </li>
</ul>
</body></html>
"""


@pytest.mark.asyncio
async def test_yandex_search_parses_cbir_items() -> None:
    with aioresponses() as m:
        m.get(re.compile(r"https://yandex\.com/.*"), status=200, body=_YANDEX_HTML)
        async with HTTPClient() as client:
            hits = await yandex.search(client, "https://cdn.example.com/a.jpg")
    assert len(hits) == 2
    assert hits[0].match_url == "https://blog.example.com/post"
    assert hits[0].title == "Example Post"
    assert hits[0].image_url == "https://thumb.example.com/1.jpg"
    assert hits[0].metadata["host"] == "blog.example.com"
    assert hits[0].metadata["description"].startswith("A nice")


@pytest.mark.asyncio
async def test_yandex_search_returns_empty_on_non_200() -> None:
    with aioresponses() as m:
        m.get(re.compile(r"https://yandex\.com/.*"), status=429, body="")
        async with HTTPClient() as client:
            hits = await yandex.search(client, "https://cdn.example.com/a.jpg")
    assert hits == []


@pytest.mark.asyncio
async def test_yandex_search_skips_empty_url() -> None:
    async with HTTPClient() as client:
        assert await yandex.search(client, "") == []


# ── TinEye ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tineye_search_no_credentials(monkeypatch) -> None:
    monkeypatch.delenv("TINEYE_API_USER", raising=False)
    monkeypatch.delenv("TINEYE_API_KEY", raising=False)
    async with HTTPClient() as client:
        assert await tineye.search(client, "https://cdn.example.com/a.jpg") == []


@pytest.mark.asyncio
async def test_tineye_search_parses_matches(monkeypatch) -> None:
    monkeypatch.setenv("TINEYE_API_USER", "user")
    monkeypatch.setenv("TINEYE_API_KEY", "key")
    payload = {
        "status": "ok",
        "results": {
            "matches": [
                {
                    "score": 0.97,
                    "filepath": "https://thumb.example.com/a.jpg",
                    "domain": "blog.example.com",
                    "backlinks": [
                        {"url": "https://blog.example.com/post", "crawl_date": "2024-01-01"}
                    ],
                },
                {
                    "score": 0.5,
                    "filepath": "https://thumb.example.com/b.jpg",
                    "domain": "no-backlink.example.com",
                    "backlinks": [],
                },
            ]
        },
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.tineye\.com/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await tineye.search(client, "https://cdn.example.com/a.jpg")
    assert len(hits) == 1
    assert hits[0].score == pytest.approx(0.97)
    assert hits[0].match_url == "https://blog.example.com/post"
    assert hits[0].title == "blog.example.com"


# ── Orchestrator ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_reverse_image_merges_sources(monkeypatch) -> None:
    monkeypatch.delenv("TINEYE_API_USER", raising=False)
    monkeypatch.delenv("TINEYE_API_KEY", raising=False)
    with aioresponses() as m:
        m.get(re.compile(r"https://yandex\.com/.*"), status=200, body=_YANDEX_HTML)
        async with HTTPClient() as client:
            hits = await run_reverse_image(
                client, image_urls=["https://cdn.example.com/a.jpg"]
            )
    assert len(hits) == 2
    urls = {h.match_url for h in hits}
    assert "https://blog.example.com/post" in urls


@pytest.mark.asyncio
async def test_run_reverse_image_empty_input() -> None:
    async with HTTPClient() as client:
        assert await run_reverse_image(client, image_urls=[]) == []
