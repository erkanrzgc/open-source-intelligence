<h1 align="center">open-source-intelligence</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/platforms-100_core%20%7C%20500_full-purple?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-971%20passed-success?style=flat-square" alt="Tests">
</p>

<p align="center">
  <strong>Identity-first username reconnaissance across 100 core platforms.</strong><br>
  Email breach discovery • smart username variations • optional AI triage
</p>

---

## Quickstart

```bash
git clone https://github.com/erkanrzgc/open-source-intelligence.git
cd open-source-intelligence
pip install -e .
python osint.py      # or just: osint
```

```
╭──────────────────────────────────────────────╮
│ Open Source Intelligence — username scanner  │
│ 100 core platforms · deterministic aliases    │
╰──────────────────────────────────────────────╯

Username: erkanrzgc

[1] Core   — 100 high-value platforms
[2] Full   — up to 500 curated platforms
[3] Custom — pick categories yourself

Choose: 1

→ Scanning 100 core platforms plus bounded alias probes...
→ Applying soft-404, redirect and profile-liveness rules...
  Confirmed: 7  Uncertain: 2  Rejected: 6

Results
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Confirmed profiles  ┃ 7     ┃
┃ Time                ┃ 45.2s ┃
┗━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━┛
```

Or one-liner:

```bash
osint scan erkanrzgc
```

---

## What it does

| Phase | Description |
|-------|-------------|
| Platform sweep | Checks 100 core platforms (up to 500 with `--full`) |
| Adaptive alias search | Checks 12 candidates on 15 sites, then up to 12 more on 5 sites only when no strong match is found (max 240 probes) |
| Identity resolution | Scores confirmed alias profiles using independent shared evidence; handle similarity alone stays uncertain |
| Optional AI triage | With `--ai`, the LLM evaluates only uncertain matches |
| Deep scrape | Extracts names, bios, locations from known platforms |
| Smart search | Generates username variations (john → j0hn, johndoe42) |
| Email discovery | Gravatar → HIBP → COMB leak lookup → Holehe → GHunt |
| Photo compare | Perceptual-hash avatar comparison across platforms |
| Deterministic verification | Combines redirects, soft-404, canonical metadata and liveness signals |

---

## CLI reference

```bash
osint                          # interactive mode
osint scan <username>          # 100 core platforms + similar usernames
osint scan <username> --full   # up to 500 curated platforms
osint scan <username> --no-smart  # disable alias discovery
osint scan <username> --smart  # username variations
osint scan <username> --ai     # opt in to uncertain-match AI triage + summary
osint scan <username> --full-name "John Doe"  # name → handle resolution
```

Results saved to `log/<username>/<timestamp>.json`.

---

## Installation

Python 3.10+ required.

```bash
git clone https://github.com/erkanrzgc/open-source-intelligence.git
cd open-source-intelligence
pip install -e .
```

Optional extras:

```bash
pip install -e '.[browser]'   # Playwright rendering for JS-heavy sites
pip install -e '.[photo]'     # avatar photo hashing
pip install -e '.[holehe]'    # email registration probes (120+ sites)
pip install -e '.[ghunt]'     # Google account lookup
pip install -e '.[toutatis]'  # Instagram enrichment
pip install -e '.[report]'    # PDF, XLSX exports
pip install -e '.[ai]'        # local LLM via llama-cpp
pip install -e '.[api]'       # FastAPI + uvicorn web server
pip install -e '.[dev]'       # pytest, ruff, mypy
```

For AI-powered verification, set your NVIDIA NIM / OpenAI-compatible endpoint:

```bash
export OSINT_LLM_API_KEY="nvapi-..."
export OSINT_LLM_URL="https://integrate.api.nvidia.com/v1/chat/completions"
```

Without an API key, AI features gracefully fall back to strict body-based checks.

---

## Python library

```python
import asyncio
from core.config import ScanConfig
from core.engine import run_scan

async def main():
    cfg = ScanConfig(
        username="erkanrzgc",
        deep=True,
        smart=True,
        email=True,
        breach=True,
        ai_skills=True,
    )
    result = await run_scan(cfg)
    for p in result.found_platforms:
        print(f"{p.platform}: {p.url}")

asyncio.run(main())
```

---

## Web API

```bash
python -m uvicorn core.api.server:build_app --factory --host 127.0.0.1 --port 8000
```

```
http://127.0.0.1:8000       — web UI
http://127.0.0.1:8000/docs  — OpenAPI docs
```

```bash
curl -H 'Content-Type: application/json' \
  -d '{"username":"erkanrzgc","deep":true,"smart":true}' \
  http://127.0.0.1:8000/scan
```

---

## MCP server

```bash
python mcp_server.py
```

```json
{
  "mcpServers": {
    "open-source-intelligence": {
      "command": "python",
      "args": ["mcp_server.py"]
    }
  }
}
```

---

## Docker

```bash
docker build -t open-source-intelligence .
docker run --rm -p 127.0.0.1:8000:8000 open-source-intelligence
```

Or with Compose:

```bash
docker compose up --build api
```

---

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `OSINT_MAX_CONCURRENT` | 50 | Global request concurrency |
| `OSINT_TIMEOUT` | 15 | Request timeout (seconds) |
| `OSINT_RETRIES` | 2 | Retry count |
| `OSINT_LLM_BACKEND` | http | `http` or `llama_cpp` |
| `OSINT_LLM_API_KEY` | — | NVIDIA / OpenAI API key |
| `OSINT_LLM_MODEL` | nemotron-70b | Model identifier |
| `OSINT_LLM_ALLOW_PRIVATE_NETWORKS` | off | Permit an explicit local HTTP LLM endpoint |
| `OSINT_AUTH_REQUIRED` | off | Enable API auth |
| `OSINT_WEBHOOK_ALLOW_PRIVATE_NETWORKS` | off | Permit an explicit local webhook receiver |
| `OSINT_PLATFORMS_FILE` | built-in | Custom platform YAML |
| `GITHUB_TOKEN` | — | Optional authenticated GitHub exact-profile lookup |
| `OSINT_FOREM_API_KEY` | — | Optional Forem/DEV API key |
| `OSINT_REDDIT_BEARER_TOKEN` | — | Optional pre-minted Reddit OAuth token |
| `OSINT_REDDIT_CLIENT_ID` | — | Reddit app-token client identity |
| `OSINT_REDDIT_CLIENT_SECRET` | — | Mint a fresh Reddit app token per scan |
| `OSINT_REDDIT_USER_AGENT` | — | Required honest Reddit API User-Agent |
| `OSINT_X_BEARER_TOKEN` | — | X API v2 batch username lookup |
| `OSINT_YOUTUBE_API_KEY` | — | YouTube Data API `forHandle` lookup |
| `OSINT_TWITCH_CLIENT_ID` | — | Twitch Helix client identity |
| `OSINT_TWITCH_CLIENT_SECRET` | — | Mint a fresh Twitch app token per scan |
| `OSINT_TWITCH_ACCESS_TOKEN` | — | Optional pre-minted Twitch access token |
| `OSINT_STEAM_API_KEY` | — | Steam vanity resolution and summaries |

See `.env.example` for all options.

---

## Development

```bash
pip install -e '.[dev,api]'
pytest                                  # 971 offline tests
ruff check core modules utils scripts tests mcp_server.py
mypy --ignore-missing-imports core modules utils scripts/provider_contract_smoke.py
```

Unit tests use no live network.

Live provider contracts are an explicit operational check, not part of the
offline suite. Public providers always run; credential-gated providers run only
when their environment variables are configured:

```bash
python scripts/provider_contract_smoke.py \
  --output provider-contract-report.json

# Treat a missing/expired X credential as a hard failure:
python scripts/provider_contract_smoke.py --provider X --require-provider X
```

The report contains normalized outcomes and request counts only. Credentials,
authorization headers and raw provider payloads are excluded. The checked-in
`Provider Contract Smoke` workflow runs this matrix every Monday and uploads the
JSON report for 30 days.

---

## License

[MIT](LICENSE) © erkanrzgc
