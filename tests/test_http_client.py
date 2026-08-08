"""Tests for core/http_client.py using aioresponses."""

import aiohttp
import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient


@pytest.mark.asyncio
async def test_get_success():
    with aioresponses() as m:
        m.get("https://example.com/u", status=200, body="<html>hi</html>")
        async with HTTPClient() as client:
            status, body, _ = await client.get("https://example.com/u")
        assert status == 200
        assert "hi" in body


@pytest.mark.asyncio
async def test_get_404():
    with aioresponses() as m:
        m.get("https://example.com/u", status=404, body="")
        async with HTTPClient() as client:
            status, _body, _ = await client.get("https://example.com/u")
        assert status == 404


@pytest.mark.asyncio
async def test_get_json_success():
    with aioresponses() as m:
        m.get("https://api.example.com/x", status=200, payload={"k": "v"})
        async with HTTPClient() as client:
            status, data, _ = await client.get_json("https://api.example.com/x")
        assert status == 200
        assert data == {"k": "v"}


@pytest.mark.asyncio
async def test_get_json_error_status():
    with aioresponses() as m:
        m.get("https://api.example.com/x", status=500)
        async with HTTPClient() as client:
            status, data, _ = await client.get_json("https://api.example.com/x")
        assert status == 500
        assert data is None


@pytest.mark.asyncio
async def test_get_bytes_success():
    with aioresponses() as m:
        m.get("https://cdn.example.com/img", status=200, body=b"\x89PNG\r\n")
        async with HTTPClient() as client:
            status, data, _ = await client.get_bytes("https://cdn.example.com/img")
        assert status == 200
        assert data is not None and data.startswith(b"\x89PNG")


@pytest.mark.asyncio
async def test_get_network_error_returns_neg1():
    with aioresponses() as m:
        m.get(
            "https://example.com/u",
            exception=aiohttp.ClientConnectionError("boom"),
        )
        # Retries will each re-raise; final attempt returns -1
        async with HTTPClient() as client:
            status, _body, _ = await client.get("https://example.com/u")
        assert status == -1


@pytest.mark.asyncio
async def test_require_session_raises_without_context():
    client = HTTPClient()
    with pytest.raises(RuntimeError):
        client._require_session()


@pytest.mark.asyncio
async def test_headers_include_user_agent():
    client = HTTPClient()
    headers = client._headers({"X-Extra": "v"})
    assert "User-Agent" in headers
    assert headers["X-Extra"] == "v"


def test_next_http_proxy_none():
    client = HTTPClient()
    assert client._next_http_proxy() is None


def test_next_http_proxy_rotation():
    client = HTTPClient(proxies=["http://p1:8080", "http://p2:8080"])
    # Cycles infinitely
    assert client._next_http_proxy() == "http://p1:8080"
    assert client._next_http_proxy() == "http://p2:8080"
    assert client._next_http_proxy() == "http://p1:8080"


def test_socks_proxy_not_returned_per_request():
    client = HTTPClient(proxies=["socks5://127.0.0.1:9050"])
    assert client._next_http_proxy() is None


def test_tls_verification_is_on_by_default(monkeypatch):
    monkeypatch.delenv("OSINT_INSECURE_TLS", raising=False)
    client = HTTPClient()
    assert client._verify_tls is True


def test_tls_verification_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setenv("OSINT_INSECURE_TLS", "1")
    client = HTTPClient()
    assert client._verify_tls is False
