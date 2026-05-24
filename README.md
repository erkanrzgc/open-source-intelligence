<h1 align="center">cyberm4fia-osint</h1>

<p align="center">
  <img src="https://img.shields.io/badge/mission-open%20source%20intelligence-blueviolet?style=for-the-badge" alt="mission">
</p>

<table align="center"><tr><td valign="middle">
<pre>
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
</pre>
</td><td valign="middle">
<img src="https://raw.githubusercontent.com/erkanrzgc/cyberm4fia-osint/main/resources/osint_icon.png" width="150">
</td></tr></table>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python" alt="python">
  <img src="https://img.shields.io/badge/platforms-1900+-purple?style=flat-square" alt="platforms">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/AI-local%20LLM-orange?style=flat-square" alt="AI">
  <img src="https://img.shields.io/github/last-commit/erkanrzgc/cyberm4fia-osint?style=flat-square" alt="last commit">
</p>

<p align="center">
  <b>cyberm4fia-osint</b> is a terminal-first OSINT username reconnaissance framework that hunts a single username across <b>1,900+ platforms</b> — then enriches findings with deep profile scraping, breach checks, cross-referencing, and optional <b>local LLM analysis</b>.
</p>

---

## Features

- **1,900+ platforms** checked in parallel
- **Zero-flag full scan** by default — everything on unless you opt out with `--quick`
- **Deep profile scraping** for GitHub, GitLab, Reddit, Steam, Chess.com, Lichess, Keybase, Hacker News, Dev.to, and more
- **Opportunistic profile parsing** — pulls names, emails, locations, and linked accounts out of any HTML we fetched (200+ site schemes, optional install)
- **Cross-reference engine** with confidence scoring across names, locations, and profile photos
- **Smart search** — generates username variations and discovers linked accounts from scraped bios
- **Email discovery** + Gravatar detection + free breach lookup + public credential-leak search
- **Email → site enumeration** — pivot any discovered email through 120+ site registration probes (`--holehe`)
- **Google account lookup** — resolve emails to Google accounts (Gaia ID, name, services) (`--ghunt`)
- **Instagram profile OSINT** — optional `IG_SESSION_ID` for richer data (`--toutatis`)
- **Recursive pivot discovery** — usernames found inside profile data are fed back into the platform sweep (`--recursive`)
- **Profile photo matching** via perceptual hashing
- **WHOIS / DNS / subdomain enumeration** (crt.sh)
- **Wayback Machine** and paste-site presence
- **Scan history** with SQLite + diff mode (`--diff` shows what changed between runs)
- **LLM-driven analysis** — defaults to NVIDIA NIM (free tier), works with any OpenAI-compatible endpoint (OpenAI, Groq, Ollama, llama.cpp server, vLLM); generates an AI-written identity / exposure report
- **HTML + JSON + DOT graph** exports
- **Tor / SOCKS / HTTP proxy** support
- **MCP server** for Claude Desktop and other MCP-compatible clients
- **CI-ready** — 500+ tests with ruff, mypy, bandit, and coverage checks

---

## Installation

Requires Python **3.10+**.

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-osint.git
cd cyberm4fia-osint
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

After the editable install, the `cyberm4fia` command is available on your `$PATH`.

Optional extras:

```bash
pip install -e '.[ai]'        # local LLM via llama-cpp-python
pip install -e '.[photo]'     # profile photo hashing (Pillow, imagehash)
pip install -e '.[extract]'   # socid-extractor — auto-parse 200+ profile pages
pip install -e '.[holehe]'    # 120+ site email registration probes
pip install -e '.[ghunt]'     # Google account lookup (run `ghunt login` once after install)
pip install -e '.[toutatis]'  # Instagram profile OSINT
pip install -e '.[socks]'     # SOCKS / Tor support (aiohttp-socks)
pip install -e '.[api]'       # FastAPI REST server + web UI
pip install -e '.[report]'    # PDF/XLSX report exporters
pip install -e '.[browser]'   # Playwright browser fallback
pip install -e '.[filetype]'  # Magika file-type detection for harvested docs
pip install -e '.[dev]'       # pytest, ruff, mypy, coverage
```

Obscura can be used as an alternative browser renderer by installing the
`obscura` binary and running:

```bash
cyberm4fia johndoe --browser-backend obscura
```

Set `CYBERM4FIA_OBSCURA_BIN=/path/to/obscura` if the binary is not on `$PATH`.

---

## Quick Start

Full scan (everything on):

```bash
cyberm4fia johndoe
```

Fast sweep — platform check only:

```bash
cyberm4fia johndoe --quick
```

Only a specific category:

```bash
cyberm4fia johndoe --category social,dev
```

Export an HTML report:

```bash
cyberm4fia johndoe --output reports/johndoe.html
```

Run it behind Tor:

```bash
cyberm4fia johndoe --tor
```

Diff against the previous run for the same username:

```bash
cyberm4fia johndoe --diff
```

---

## AI Analysis

`cyberm4fia` ships with an optional LLM analyst. It takes the structured scan result and generates a concise cybersecurity report: identity summary, strong linkages, exposures, and next steps — all as JSON, parsed and displayed inline. The same backend powers the SE-arsenal pretext drafter.

### Option A — NVIDIA NIM (default, free tier)

1. Get a free key at [build.nvidia.com](https://build.nvidia.com) (~1000 req/month across all hosted models).
2. Set the key:

```bash
export CYBERM4FIA_LLM_API_KEY="nvapi-..."
cyberm4fia johndoe --ai
```

The defaults (`CYBERM4FIA_LLM_URL`, `CYBERM4FIA_LLM_MODEL`) already point at NVIDIA NIM with `meta/llama-3.3-70b-instruct`. Override `CYBERM4FIA_LLM_MODEL` for any other NIM-hosted model — see `.env.example` for curated red-team picks.

### Option B — Any other OpenAI-compatible endpoint

The HTTP backend speaks plain OpenAI Chat Completions, so OpenAI, Groq, Ollama, llama.cpp server, and vLLM all work by overriding three env vars:

```bash
export CYBERM4FIA_LLM_URL="https://api.openai.com/v1/chat/completions"
export CYBERM4FIA_LLM_API_KEY="sk-..."
export CYBERM4FIA_LLM_MODEL="gpt-4o-mini"
cyberm4fia johndoe --ai
```

### Option C — Embedded `llama-cpp-python` (offline GGUF)

```bash
pip install -e '.[ai]'
export CYBERM4FIA_LLM_BACKEND=llama_cpp
python -m core.analysis.download   # fetches the default GGUF
cyberm4fia johndoe --ai
```

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CYBERM4FIA_LLM_BACKEND` | `http` | `http` or `llama_cpp` |
| `CYBERM4FIA_LLM_URL` | NVIDIA NIM chat completions | OpenAI-compatible endpoint |
| `CYBERM4FIA_LLM_MODEL` | `meta/llama-3.3-70b-instruct` | Model ID sent in the request |
| `CYBERM4FIA_LLM_API_KEY` | _(empty)_ | Bearer token — required for hosted backends |
| `CYBERM4FIA_LLM_TIMEOUT` | `120` | HTTP timeout (seconds) |
| `CYBERM4FIA_LLM_REPO` | _(your HF repo)_ | HF repo for `llama_cpp` backend |
| `CYBERM4FIA_LLM_FILE` | _(your GGUF file)_ | GGUF filename |
| `CYBERM4FIA_LLM_CTX` | `4096` | Context window |
| `CYBERM4FIA_LLM_MAX_TOKENS` | `768` | Max output tokens |
| `CYBERM4FIA_LLM_TEMPERATURE` | `0.2` | Sampling temperature |
| `CYBERM4FIA_LLM_GPU_LAYERS` | `-1` | llama.cpp GPU offload layers |

---

## CLI Reference

| Flag | Alias | Description |
| --- | --- | --- |
| `username` | — | Target username (positional) |
| `--quick` | `-q` | Quick mode — platform sweep only |
| `--full` | `-f` | Full scan (kept for backward compatibility; already the default) |
| `--smart` | `-s` | Username variations + discovered linked accounts |
| `--deep` / `--no-deep` | `-d` | Deep profile scraping (default: on) |
| `--email` | `-e` | Email discovery + Gravatar |
| `--breach` | — | Free breach lookup + public credential-leak search (auto-enables `--email`) |
| `--holehe` | — | Probe ~120 sites for each discovered email (requires `[holehe]` extra) |
| `--ghunt` | — | Google account lookup for each email (requires `[ghunt]` extra + `ghunt login`) |
| `--toutatis` | — | Instagram OSINT for the username (requires `[toutatis]` extra; set `IG_SESSION_ID` for richer data) |
| `--recursive` | — | Feed discovered usernames back into the platform sweep |
| `--recursive-depth N` | — | Recursive pivot depth (default `1`) |
| `--photo` | — | Profile photo perceptual-hash comparison |
| `--web` | `-w` | Wayback / paste / domain presence |
| `--whois` | — | WHOIS across 9 TLDs |
| `--dns` | — | DNS record lookup |
| `--subdomain` | — | crt.sh subdomain enumeration |
| `--category` | `-c` | Restrict to categories (`social,dev,gaming,...`) |
| `--tor` | `-toor` | Route through `socks5://127.0.0.1:9050` |
| `--proxy` | — | Custom HTTP/SOCKS proxy |
| `--browser-backend` | — | Browser renderer for JS-heavy pages: `playwright` or `obscura` |
| `--output` | `-o` | Save report to `.json`, `.html`, or `.dot` |
| `--timeout` | `-t` | Per-request timeout (seconds) |
| `--history` | — | List prior scans for the username and exit |
| `--diff` | — | Diff against the previous scan after running |
| `--no-history` | — | Do not persist this scan |
| `--ai` | — | Run local-LLM analysis on the result |
| `--log-level` | — | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Platform Coverage

**1,900+ platforms** across seven categories. Highlights:

- **Social:** Instagram, X / Twitter, TikTok, Facebook, Snapchat, Threads, Bluesky, Mastodon, Reddit, Tumblr, VK, Telegram, Weibo, MySpace, Gab, Truth Social, Flipboard, Matrix, Clubhouse, Quora, Pinterest, Ask.fm, Badoo
- **Dating:** Tinder, Badoo, MeetMe, Mamba, Hily, Tagged
- **Dev:** GitHub, GitLab, Bitbucket, Dev.to, Stack Overflow, HackerOne, TryHackMe, HackTheBox, Kaggle, Hugging Face, Codeforces, LeetCode, Replit, CodePen, npm, PyPI, crates.io, Docker Hub
- **Gaming:** Steam, Twitch, Chess.com, Lichess, Roblox, Xbox, NameMC, osu!, Speedrun.com, Fortnite Tracker
- **Content:** YouTube, Medium, Substack, WordPress, Hashnode, SoundCloud, Spotify, Bandcamp, Vimeo, Dailymotion, Rumble, Kick
- **Professional:** LinkedIn, Keybase, Behance, Dribbble, About.me, Gravatar, Wellfound, Crunchbase, Xing, ResearchGate, Academia.edu, Fiverr, Patreon
- **Community & other:** Hacker News, Product Hunt, Ko-fi, BuyMeACoffee, Venmo, Cash App, PayPal.me, Strava, Untappd, Letterboxd, MyAnimeList, Goodreads, Tripadvisor, Couchsurfing, Meetup, Wattpad, Itch.io

Want to add a platform? Edit `modules/platforms.yaml` — no code changes needed.

---

## Output Formats

- **Console** — rich, color-coded panels and tables (default)
- **JSON** — `cyberm4fia user --output out.json`
- **HTML** — `cyberm4fia user --output out.html` (self-contained, CSP-hardened)
- **Graphviz DOT** — `cyberm4fia user --output out.dot`

---

## Scan History

Every run is persisted to a local SQLite database (`history.db`). Disable with `--no-history`.

```bash
cyberm4fia johndoe --history   # list prior scans
cyberm4fia johndoe --diff      # diff against the last run
```

---

## Docker

```bash
docker build -t cyberm4fia-osint .
docker run --rm cyberm4fia-osint johndoe --quick
```

The compose API service binds to `127.0.0.1:8000` by default. If you expose it
outside localhost, enable the auth gate first:

```bash
docker compose run --rm cli --create-user analyst:change-me
OSINT_AUTH_REQUIRED=1 OSINT_AUTH_SECRET="$(openssl rand -hex 32)" docker compose up api
```

API auth roles are enforced when `OSINT_AUTH_REQUIRED=1`: `viewer` is
read-only, `analyst` can create/update, and `admin` is required for deletes.
Background scan jobs are bounded by `CYBERM4FIA_SCAN_JOB_MAX_JOBS`,
`CYBERM4FIA_SCAN_JOB_CONCURRENCY`, and `CYBERM4FIA_SCAN_JOB_MAX_EVENTS`.
TLS verification is on by default; only set `CYBERM4FIA_INSECURE_TLS=1` for
controlled lab targets with broken certificates.

---

## Development

```bash
pip install -e '.[dev,api,report,socks,whois,photo,dns]'
pytest
pytest --cov=core --cov=modules     # coverage report
ruff check main.py core modules utils tests
mypy --ignore-missing-imports core modules utils
```

GitHub Actions runs the full matrix on every push.

---

## Legal & Ethical Use

This tool queries **public** profile endpoints — the same information anyone can view in a browser. Use it for:

- Security research and defensive OSINT
- CTF challenges and red-team exercises with written authorization
- Your own digital-footprint audit
- Journalism and investigative research within applicable law

**Do not** use it for harassment, stalking, doxing, or any activity that violates local law or the target platform's terms of service. The authors accept no responsibility for misuse.

---

## License

MIT — see [LICENSE](LICENSE).
