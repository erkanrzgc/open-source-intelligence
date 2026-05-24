"""Tests for modules.stealth.js_wall JS-wall detection."""

from modules.stealth.js_wall import looks_like_js_wall


def test_cloudflare_challenge_header_detected():
    is_wall, reason = looks_like_js_wall(
        body="some body",
        headers={"CF-Mitigated": "challenge"},
        status=200,
    )
    assert is_wall is True
    assert reason == "cloudflare_challenge_header"


def test_cloudflare_just_a_moment_body():
    body = """
    <html><head><title>Just a moment...</title></head>
    <body><div class="cf-spinner"></div>
    <p>Checking your browser before accessing site.com</p></body></html>
    """
    is_wall, reason = looks_like_js_wall(body=body, headers={}, status=503)
    assert is_wall is True
    assert reason and "cloudflare" in reason


def test_datadome_block_detected():
    body = "<html><body>Please enable cookies. blocked by DataDome.</body></html>"
    is_wall, reason = looks_like_js_wall(body=body)
    assert is_wall is True
    assert reason == "datadome_challenge"


def test_noscript_required_with_thin_body():
    body = (
        "<html><head><script src='/app.js'></script></head>"
        "<body><noscript>You need to enable JavaScript to run this app.</noscript></body></html>"
    )
    is_wall, reason = looks_like_js_wall(body=body)
    assert is_wall is True
    assert reason == "noscript_required"


def test_empty_next_data_shell():
    body = (
        '<html><body><div id="__next"></div>'
        '<script id="__NEXT_DATA__" type="application/json">{}</script>'
        '</body></html>'
    )
    is_wall, reason = looks_like_js_wall(body=body)
    assert is_wall is True
    assert reason == "empty_next_data"


def test_real_profile_not_flagged():
    body = """
    <html>
      <head><title>alice profile</title></head>
      <body>
        <h1>alice</h1>
        <p>Bio: working on OSINT tooling. 1240 followers, 87 posts.</p>
        <img src="/avatar.jpg" />
        <article>Lots of real text content here that fills the body with visible content.</article>
        <article>More posts and updates. Active profile with significant content.</article>
      </body>
    </html>
    """
    is_wall, reason = looks_like_js_wall(body=body)
    assert is_wall is False
    assert reason is None


def test_empty_body_not_flagged():
    is_wall, reason = looks_like_js_wall(body="")
    assert is_wall is False
    assert reason is None


def test_script_only_shell_detected():
    body = "<html><head><script src='/a.js'></script></head><body><div id='app'></div></body></html>"
    is_wall, reason = looks_like_js_wall(body=body)
    # length < 2048 + has script + low visible text → wall
    assert is_wall is True
    assert reason in ("script_only_shell", "empty_spa_mount")
