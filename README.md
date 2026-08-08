<h1 align="center">open-source-intelligence</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/platforms-~500-purple?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-809%20passed-success?style=flat-square" alt="Tests">
</p>

<p align="center">
  <strong>Username reconnaissance across ~500 platforms — AI-powered.</strong><br>
  Email breach discovery • smart username variations • post-verify AI
</p>

---

<h2 align="center">Quickstart</h2>

```bash
git clone https://github.com/erkanrzgc/open-source-intelligence.git
cd open-source-intelligence
pip install -e .
python osint.py      # or just: osint
```

```
╭──────────────────────────────────────────────╮
│ Open Source Intelligence — username scanner  │
│ ~500 platforms · AI validation               │
╰──────────────────────────────────────────────╯

Username: erkanrzgc

[1] Quick  — ~500 platforms
[2] Full   — all 1922 platforms
[3] Custom — pick categories yourself

Choose: 1

→ Scanning ~500 platforms...
→ AI validating matches...
→ Verifying 15 matches...
  Real: 7  Fake: 8

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

<h2 align="center">What it does</h2>

| Phase | Description |
|-------|-------------|
| Platform sweep | Checks ~500 platforms in parallel for the username |
| AI validation | LLM evaluates borderline matches, reduces false positives |
| Deep scrape | Extracts names, bios, locations from known platforms |
| Smart search | Generates username variations (john → j0hn, johndoe42) |
| Email discovery | Gravatar → HIBP → COMB leak lookup → Holehe → GHunt |
| Photo compare | Perceptual-hash avatar comparison across platforms |
| Post-verify | Re-checks every found URL — drops redirects, 404s, search pages |

---

<h2 align="center">CLI reference</h2>

```bash
osint                          # interactive mode
osint scan <username>          # one-liner, ~500 platforms
osint scan <username> --full   # all 1922 platforms
osint scan <username> --smart  # username variations
osint scan <username> --full-name "John Doe"  # name → handle resolution
```

Results saved to `log/<username>/<timestamp>.json`.

---

<h2 align="center">Installation</h2>

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

<h2 align="center">Python library</h2>

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

<h2 align="center">Web API</h2>

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

<h2 align="center">MCP server</h2>

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

<h2 align="center">Docker</h2>

```bash
docker build -t open-source-intelligence .
docker run --rm -p 127.0.0.1:8000:8000 open-source-intelligence
```

Or with Compose:

```bash
docker compose up --build api
```

---

<h2 align="center">Configuration</h2>

| Variable | Default | Purpose |
|----------|---------|---------|
| `OSINT_MAX_CONCURRENT` | 50 | Global request concurrency |
| `OSINT_TIMEOUT` | 15 | Request timeout (seconds) |
| `OSINT_RETRIES` | 2 | Retry count |
| `OSINT_LLM_BACKEND` | http | `http` or `llama_cpp` |
| `OSINT_LLM_API_KEY` | — | NVIDIA / OpenAI API key |
| `OSINT_LLM_MODEL` | nemotron-70b | Model identifier |
| `OSINT_AUTH_REQUIRED` | off | Enable API auth |
| `OSINT_PLATFORMS_FILE` | built-in | Custom platform YAML |

See `.env.example` for all options.

---

<h2 align="center">Development</h2>

```bash
pip install -e '.[dev,api]'
pytest                                  # 809 tests
ruff check core modules tests           # lint
mypy core modules                       # type check
```

Unit tests use no live network.

---

<h2 align="center">License</h2>

<p align="center">
  <a href="LICENSE">MIT</a> © erkanrzgc
</p>
