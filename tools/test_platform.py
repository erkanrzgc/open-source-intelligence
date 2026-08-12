#!/usr/bin/env python3
"""Test detection signals for a platform manually.

Usage:
    python tools/test_platform.py <platform_name> <username>

Fetches the platform URL and prints unique markers so you can find
good presence/absence strings.
"""
import asyncio
import re
import sys
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

async def main(platform_name: str, username: str):
    from modules.platforms import PLATFORMS
    platform = next((p for p in PLATFORMS if p.name == platform_name), None)
    if not platform:
        print(f"Platform '{platform_name}' not found")
        names = sorted(p.name for p in PLATFORMS if platform_name.lower() in p.name.lower())
        if names:
            print(f"Did you mean: {', '.join(names[:10])}?")
        return 1

    url = platform.url.replace("{username}", username)
    headers = platform.headers or {}
    headers.setdefault("User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    print(f"Platform: {platform.name}")
    print(f"URL:      {url}")
    print(f"Category: {platform.category}")
    print("Current detection:")
    print(f"  check_type: {platform.check_type}")
    print(f"  absence:    {list(platform.absence_strings)[:5]}")
    print(f"  presence:   {list(platform.presence_strings)[:5]}")
    if platform.url_probe:
        print(f"  url_probe:  {platform.url_probe}")
    print()

    async with aiohttp.ClientSession() as s:
        print("Fetching... (may include JS-wall redirects)")
        async with s.get(url, timeout=15, headers=headers, allow_redirects=True) as r:
            body = await r.text()
            print(f"HTTP: {r.status}  final_url: {str(r.url)[:100]}  length: {len(body)}")

            # Show URL redirect chain
            if str(r.url) != url:
                print(f"\n!! REDIRECTED: {url} -> {str(r.url)[:100]}")
                print("   This often means the page doesn't exist or redirects to login.\n")

            print()
            print("--- HINTS FOR MANUAL SEARCH ---")
            print("Search the body (below) for:")
            print("  PRESENCE signal (only on REAL profile pages):")
            print(f"    - Username '{username}' embedded in JSON/HTML?")
            print("    - Unique CSS classes or IDs?")
            print("    - Meta tags like og:title with the username?")
            print("  ABSENCE signal (only on MISSING profile pages):")
            print("    - Error messages like 'Not Found', '404', 'does not exist'?")
            print("    - Unique error page CSS classes?")
            print("    - API error codes in JSON?")
            print()

            # Auto-suggest markers
            # Look for JSON containing the username
            json_snippets = re.findall(r'\{[^{}]*?"?\w*"?\s*:\s*"[^"]*\b' + re.escape(username) + r'\b[^"]*"[^{}]*?\}', body)
            if json_snippets:
                print("--- JSON SNIPPETS WITH USERNAME ---")
                for js in json_snippets[:3]:
                    print(f"  {js[:200]}")

            # Look for error patterns on non-existent user page
            error_patterns = re.findall(r'(?i)(not found|doesn.t exist|page not found|error 404|no such user|user not found|profile not found)', body)
            if error_patterns:
                print("\n--- ERROR PATTERNS ---")
                for ep in set(error_patterns[:5]):
                    print(f"  {ep}")

            # Show first 500 chars of relevant text
            text = re.sub(r"<script[^>]*>.*?</script>", "", body, flags=re.DOTALL)
            text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            print("\n--- TEXT CONTENT (first 800 chars) ---")
            print(text[:800])

    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tools/test_platform.py <platform_name> <username>")
        print("Example: python tools/test_platform.py 'Stack Overflow' erkanrzgc")
        sys.exit(1)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
