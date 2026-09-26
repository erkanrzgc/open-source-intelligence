#!/usr/bin/env python3
"""Minimal MCP (Model Context Protocol) stdio server for Open Source Intelligence.

Exposes a single tool, ``scan_username``, that runs a ScanConfig against
the engine and returns the JSON payload. Implements just enough of MCP
2024-11 to answer ``initialize``, ``tools/list`` and ``tools/call`` over
newline-delimited JSON-RPC 2.0 on stdio.

Run with:
    python3 mcp_server.py

Tested ad-hoc with a line-oriented JSON-RPC client; does not depend on
the optional ``mcp`` python package.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from typing import Any, cast

from core import cases, watchlist
from core.config import ScanConfig
from core.engine import run_scan
from core.history import get_latest, get_scan, list_scans
from core.models import ScanResult
from core.scan_service import complete_scan_result
from core.version import __version__
from utils.helpers import sanitize_username

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "open-source-intelligence", "version": __version__}
_MAX_LINE_BYTES = 1_048_576  # 1 MiB stdin line limit

TOOLS = [
    {
        "name": "scan_username",
        "description": (
            "Run a precision-first OSINT identity scan across the 100-site core "
            "or curated 500-site full catalog, including bounded alias discovery."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Target username"},
                "categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional category filter (social, dev, gaming, ...)",
                },
                "deep": {"type": "boolean", "default": True},
                "email": {"type": "boolean", "default": False},
                "smart": {"type": "boolean", "default": True},
                "platform_scope": {
                    "type": "string",
                    "enum": ["core", "full"],
                    "default": "core",
                },
                "alias_max_candidates": {
                    "type": "integer", "minimum": 1, "maximum": 24, "default": 24,
                    "description": "Adaptive alias cap; candidates 13-24 use five sites",
                },
                "alias_platform_limit": {
                    "type": "integer", "minimum": 1, "maximum": 15, "default": 15,
                },
                "ai_skills": {"type": "boolean", "default": False},
                "ai_report": {"type": "boolean", "default": False},
                "allow_private_networks": {"type": "boolean", "default": False},
            },
            "required": ["username"],
        },
    },
    {
        "name": "get_scan",
        "description": "Fetch a saved scan payload by scan_id or latest username history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "integer", "description": "History row ID"},
                "username": {"type": "string", "description": "Fallback: latest scan for username"},
            },
        },
    },
    {
        "name": "list_history",
        "description": "List recent saved scans for a username.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Target username"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["username"],
        },
    },
    {
        "name": "add_watchlist",
        "description": "Add or update a watchlist entry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Target username"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string", "default": ""},
            },
            "required": ["username"],
        },
    },
    {
        "name": "list_cases",
        "description": "List investigation cases with status and timestamps.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "redteam_recon",
        "description": (
            "Corporate red-team recon: email pattern candidates for given "
            "employee names, GitHub org committer harvest, extra subdomain "
            "sources on top of the built-in DNS enumerator. Any combination "
            "of names / github_org may be omitted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target corporate domain (e.g. acme.com)",
                },
                "names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Full employee names for email pattern generation",
                },
                "github_org": {
                    "type": "string",
                    "description": "GitHub org to harvest committer emails from "
                    "(defaults to the first label of domain)",
                },
                "max_repos": {"type": "integer", "default": 30},
                "commits_per_repo": {"type": "integer", "default": 30},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "scan_phone",
        "description": "Analyze a phone number for country, carrier, line type, and validation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "phone": {"type": "string", "description": "Target phone number (e.g. +14155552671)"},
                "region": {"type": "string", "description": "Optional default 2-letter region code (e.g. US, TR)"},
            },
            "required": ["phone"],
        },
    },
    {
        "name": "scan_crypto",
        "description": "Inspect cryptocurrency wallet addresses (Bitcoin, Ethereum) for balances and transactions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addresses": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Cryptocurrency wallet addresses",
                },
            },
            "required": ["addresses"],
        },
    },
    {
        "name": "scan_email",
        "description": "Perform an email-first breach, Gravatar, Holehe, and Google account footprint scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "Target email address"},
                "holehe": {"type": "boolean", "default": True},
                "ghunt": {"type": "boolean", "default": True},
            },
            "required": ["email"],
        },
    },
    {
        "name": "manage_case",
        "description": "Create a case, add an investigator note, or bookmark a discovered artifact/target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create", "add_note", "add_bookmark", "get"],
                    "description": "Action to perform",
                },
                "case_id": {"type": "integer", "description": "Case ID (for add_note, add_bookmark, get)"},
                "name": {"type": "string", "description": "Case name (for create)"},
                "description": {"type": "string", "description": "Case description (for create)"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "body": {"type": "string", "description": "Note body (for add_note)"},
                "author": {"type": "string", "description": "Note author (for add_note)"},
                "target_type": {"type": "string", "description": "Bookmark target type (for add_bookmark)"},
                "target_value": {"type": "string", "description": "Bookmark target value (for add_bookmark)"},
                "label": {"type": "string", "description": "Bookmark label (for add_bookmark)"},
                "scan_id": {"type": "integer", "description": "Associated scan ID (for add_bookmark)"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "export_scan",
        "description": "Export a scan payload or history entry into HTML, PDF, CSV, STIX, MISP, or Obsidian format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_path": {"type": "string", "description": "Destination file path (or directory for obsidian)"},
                "format": {
                    "type": "string",
                    "enum": ["html", "pdf", "csv", "stix", "misp", "obsidian", "json"],
                    "default": "html",
                },
                "scan_id": {"type": "integer", "description": "History scan ID"},
                "username": {"type": "string", "description": "Fallback: latest scan for username"},
            },
            "required": ["output_path"],
        },
    },
]


def _ok(msg_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


async def _scan(args: dict) -> dict:
    raw = args.get("username")
    if not isinstance(raw, str):
        raise ValueError("username must be a string")
    username = sanitize_username(raw)
    if not username:
        raise ValueError("invalid username")
    categories = args.get("categories")
    cat_tuple = tuple(categories) if isinstance(categories, list) and categories else None
    cfg = ScanConfig(
        username=username,
        deep=bool(args.get("deep", True)),
        smart=bool(args.get("smart", True)),
        email=bool(args.get("email", False)),
        web=False,
        whois=False,
        breach=False,
        photo=False,
        dns=False,
        subdomain=False,
        categories=cat_tuple,
        platform_scope=str(args.get("platform_scope", "core")),
        alias_max_candidates=int(args.get("alias_max_candidates", 24)),
        alias_platform_limit=int(args.get("alias_platform_limit", 15)),
        ai_skills=bool(args.get("ai_skills", False)),
        ai_report=bool(args.get("ai_report", False)),
        allow_private_networks=bool(args.get("allow_private_networks", False)),
    )
    result = await run_scan(cfg)
    completed = complete_scan_result(
        result,
        cfg,
        save_history=False,
        mark_watchlist=False,
    )
    return cast(dict, completed.payload)


def _get_scan(args: dict) -> dict:
    scan_id = args.get("scan_id")
    username = args.get("username")
    entry = None
    if isinstance(scan_id, int):
        entry = get_scan(scan_id)
    elif isinstance(username, str) and username.strip():
        entry = get_latest(username.strip())
    else:
        raise ValueError("provide either scan_id or username")
    if entry is None:
        raise ValueError("scan not found")
    return {
        "id": entry.id,
        "username": entry.username,
        "ts": entry.ts,
        "found_count": entry.found_count,
        "payload": entry.payload,
    }


def _list_history(args: dict) -> dict:
    username = args.get("username")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")
    limit = args.get("limit", 20)
    try:
        limit_int = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        limit_int = 20
    entries = list_scans(username.strip(), limit=limit_int)
    return {
        "username": username.strip(),
        "count": len(entries),
        "entries": [
            {"id": entry.id, "ts": entry.ts, "found_count": entry.found_count}
            for entry in entries
        ],
    }


def _add_watchlist(args: dict) -> dict:
    raw = args.get("username")
    if not isinstance(raw, str):
        raise ValueError("username must be a string")
    username = sanitize_username(raw)
    if not username:
        raise ValueError("invalid username")
    tags = args.get("tags") or []
    if not isinstance(tags, list):
        raise ValueError("tags must be a list of strings")
    notes = args.get("notes", "")
    entry = watchlist.add(
        username,
        tags=[str(tag) for tag in tags if str(tag).strip()],
        notes=str(notes or ""),
    )
    return entry.to_dict()


def _list_cases(_args: dict) -> dict:
    entries = cases.list_cases()
    return {
        "count": len(entries),
        "entries": [entry.to_dict() for entry in entries],
    }


async def _redteam_recon(args: dict) -> dict:
    from core.http_client import HTTPClient
    from modules.dns_lookup import enumerate_subdomains
    from modules.recon import email_patterns, github_org, subdomains_extra

    raw_domain = args.get("domain")
    if not isinstance(raw_domain, str) or not raw_domain.strip():
        raise ValueError("domain must be a non-empty string")
    domain = raw_domain.strip().lower().lstrip("@")

    names = args.get("names") or []
    if not isinstance(names, list):
        raise ValueError("names must be a list of strings")
    name_list = [str(n) for n in names if str(n).strip()]

    raw_org = args.get("github_org")
    org = (raw_org if isinstance(raw_org, str) and raw_org.strip() else domain.split(".", 1)[0]).strip()

    max_repos = int(args.get("max_repos", github_org.DEFAULT_MAX_REPOS))
    commits_per_repo = int(args.get("commits_per_repo", github_org.DEFAULT_COMMITS_PER_REPO))

    async with HTTPClient() as client:
        seed_subs, committers = await asyncio.gather(
            enumerate_subdomains(client, domain),
            github_org.scan_org(
                client,
                org,
                max_repos=max_repos,
                commits_per_repo=commits_per_repo,
            ),
        )
        subs = await subdomains_extra.enrich_subdomains(
            client, domain, existing=seed_subs
        )

    candidates = email_patterns.generate_bulk(name_list, domain) if name_list else []

    return {
        "domain": domain,
        "github_org": org,
        "email_candidates": [c.to_dict() for c in candidates],
        "github_committers": [g.to_dict() for g in committers],
        "subdomains": [s.to_dict() for s in subs],
        "counts": {
            "email_candidates": len(candidates),
            "github_committers": len(committers),
            "subdomains": len(subs),
        },
    }


async def _scan_phone(args: dict) -> dict:
    from core.http_client import HTTPClient
    from modules.phone.orchestrator import lookup_phone

    phone = args.get("phone")
    if not isinstance(phone, str) or not phone.strip():
        raise ValueError("phone must be a non-empty string")
    region = args.get("region")
    region_str = str(region).strip() if region else None

    async with HTTPClient() as client:
        intel = await lookup_phone(client, phone.strip(), default_region=region_str)
        if intel is None:
            return {"valid": False, "raw": phone, "error": "unparsable phone number"}
        return intel.to_dict()


async def _scan_crypto(args: dict) -> dict:
    from core.http_client import HTTPClient
    from modules.crypto.orchestrator import lookup_crypto

    addresses = args.get("addresses") or []
    if not isinstance(addresses, list) or not addresses:
        raise ValueError("addresses must be a non-empty list of strings")
    addr_list = [str(a).strip() for a in addresses if str(a).strip()]

    async with HTTPClient() as client:
        results = await lookup_crypto(client, addr_list)
        return {
            "count": len(results),
            "results": [r.to_dict() for r in results],
        }


async def _scan_email(args: dict) -> dict:
    raw = args.get("email")
    if not isinstance(raw, str) or "@" not in raw:
        raise ValueError("email must be a valid email address")
    cfg = ScanConfig(
        username=raw.split("@", 1)[0],
        email_only=raw.strip(),
        email=True,
        breach=True,
        holehe=bool(args.get("holehe", True)),
        ghunt=bool(args.get("ghunt", True)),
        allow_private_networks=bool(args.get("allow_private_networks", False)),
    )
    result = await run_scan(cfg)
    completed = complete_scan_result(
        result,
        cfg,
        save_history=False,
        mark_watchlist=False,
    )
    return cast(dict, completed.payload)


def _manage_case(args: dict) -> dict:
    action = args.get("action")
    if action == "create":
        name = args.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name is required for creating a case")
        desc = str(args.get("description") or "")
        tags = [str(t) for t in args.get("tags") or []]
        case_obj = cases.create_case(name.strip(), description=desc, tags=tags)
        return case_obj.to_dict()

    if action == "add_note":
        case_id = args.get("case_id")
        if not isinstance(case_id, int):
            raise ValueError("case_id is required for adding a note")
        body = args.get("body")
        if not isinstance(body, str) or not body.strip():
            raise ValueError("body is required for adding a note")
        author = str(args.get("author") or "mcp_agent")
        note = cases.add_note(case_id, body=body.strip(), author=author)
        return note.to_dict()

    if action == "add_bookmark":
        case_id = args.get("case_id")
        if not isinstance(case_id, int):
            raise ValueError("case_id is required for adding a bookmark")
        t_type = args.get("target_type")
        t_val = args.get("target_value")
        if not isinstance(t_type, str) or not isinstance(t_val, str):
            raise ValueError("target_type and target_value are required")
        label = str(args.get("label") or "")
        tags = [str(t) for t in args.get("tags") or []]
        scan_id = args.get("scan_id") if isinstance(args.get("scan_id"), int) else None
        bm = cases.add_bookmark(
            case_id,
            target_type=t_type,
            target_value=t_val,
            label=label,
            tags=tags,
            scan_id=scan_id,
        )
        return bm.to_dict()

    if action == "get":
        case_id = args.get("case_id")
        if not isinstance(case_id, int):
            raise ValueError("case_id is required")
        found_case = cases.get_case(case_id)
        if found_case is None:
            raise ValueError(f"case {case_id} not found")
        notes = cases.list_notes(case_id)
        bookmarks = cases.list_bookmarks(case_id)
        out = found_case.to_dict()
        out["notes"] = [n.to_dict() for n in notes]
        out["bookmarks"] = [b.to_dict() for b in bookmarks]
        return out

    raise ValueError(f"unknown action: {action}")


def _export_scan(args: dict) -> dict:
    scan_id = args.get("scan_id")
    username = args.get("username")
    fmt = str(args.get("format", "html")).lower()
    output_path = args.get("output_path")
    if not isinstance(output_path, str) or not output_path.strip():
        raise ValueError("output_path must be a non-empty string")

    entry = None
    if isinstance(scan_id, int):
        entry = get_scan(scan_id)
    elif isinstance(username, str) and username.strip():
        entry = get_latest(username.strip())
    else:
        raise ValueError("provide either scan_id or username")

    if entry is None:
        raise ValueError("scan not found")

    result = ScanResult.from_dict(entry.payload)

    from core.reporter import (
        export_csv,
        export_html,
        export_json,
        export_misp,
        export_obsidian,
        export_pdf,
        export_stix,
    )

    if fmt == "html":
        export_html(result, output_path)
    elif fmt == "pdf":
        export_pdf(result, output_path)
    elif fmt == "csv":
        export_csv(result, output_path)
    elif fmt == "stix":
        export_stix(result, output_path)
    elif fmt == "misp":
        export_misp(result, output_path)
    elif fmt == "obsidian":
        export_obsidian(result, output_path)
    elif fmt == "json":
        export_json(result, output_path)
    else:
        raise ValueError(f"unsupported format: {fmt}")

    return {"status": "success", "format": fmt, "path": output_path}


async def _dispatch(request: dict) -> dict | None:
    method = request.get("method")
    msg_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return _ok(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )
    if method == "notifications/initialized":
        return None  # notification, no response
    if method == "tools/list":
        return _ok(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        handlers = {
            "scan_username": _scan,
            "get_scan": _get_scan,
            "list_history": _list_history,
            "add_watchlist": _add_watchlist,
            "list_cases": _list_cases,
            "redteam_recon": _redteam_recon,
            "scan_phone": _scan_phone,
            "scan_crypto": _scan_crypto,
            "scan_email": _scan_email,
            "manage_case": _manage_case,
            "export_scan": _export_scan,
        }
        handler = handlers.get(str(name))
        if handler is None:
            return _err(msg_id, -32601, f"unknown tool: {name}")
        try:
            arguments = params.get("arguments") or {}
            payload = await handler(arguments) if asyncio.iscoroutinefunction(handler) else handler(arguments)
        except ValueError as exc:
            return _err(msg_id, -32602, f"Invalid params: {exc}")
        except RuntimeError as exc:
            return _err(msg_id, -32603, f"Internal error: {exc}")
        return _ok(
            msg_id,
            {
                "content": [
                    {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}
                ]
            },
        )

    if msg_id is None:
        return None  # unknown notification
    return _err(msg_id, -32601, f"method not found: {method}")


async def _serve() -> None:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    while True:
        line = await _readline_limited(reader, _MAX_LINE_BYTES)
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, ValueError):
            continue
        response = await _dispatch(request)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()


async def _readline_limited(reader: asyncio.StreamReader, limit: int) -> bytes | None:
    """Read a newline-terminated line, bounded to *limit* bytes."""
    buf = bytearray()
    while len(buf) < limit:
        chunk = await reader.read(1)
        if not chunk:
            return bytes(buf) if buf else None
        if chunk == b"\n":
            return bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


def main() -> None:
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve())


if __name__ == "__main__":
    main()
