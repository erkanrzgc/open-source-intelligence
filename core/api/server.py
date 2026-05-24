"""FastAPI REST server.

Exposes a thin JSON surface over the scan engine, watchlist, and
history store. Intentionally kept flat — one file, no routers, no
background queues — because the CLI is still the first-class client
and the API is a supplementary surface.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from core import auth, cases, watchlist
from core.api.cytoscape import payload_to_cytoscape
from core.api.jobs import ScanJobStore
from core.capabilities import collect_capabilities
from core.compare import compare_payloads
from core.config import ScanConfig
from core.correlation import correlate
from core.engine import run_scan
from core.history import diff_entries, get_latest, get_scan, list_scans
from core.http_client import HTTPClient
from core.logging_setup import get_logger
from core.progress import ProgressEmitter, set_emitter
from core.scan_service import SCAN_PAYLOAD_SCHEMA_VERSION, complete_scan_result
from core.search import search as history_search
from core.social_graph import compute_overlap, fetch_github_neighbors

log = get_logger(__name__)

_WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"

_PUBLIC_PATHS = frozenset({"/", "/health", "/capabilities", "/auth/login", "/docs",
                           "/openapi.json", "/redoc"})

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _auth_dependency(request: Request) -> None:
    path = request.url.path
    if (
        path in _PUBLIC_PATHS
        or path.startswith("/static/")
        or request.method == "OPTIONS"
    ):
        return

    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = header.split(" ", 1)[1].strip()
    try:
        payload = auth.decode_token(token, secret=auth.get_secret())
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc

    role = str(payload.get("role") or "viewer")
    if role not in auth.VALID_ROLES:
        raise HTTPException(status_code=403, detail="invalid role")
    if request.method == "DELETE" and role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    if request.method in _MUTATING_METHODS and role == "viewer":
        raise HTTPException(status_code=403, detail="viewer role is read-only")
    request.state.user = payload


# ── Request/response schemas ─────────────────────────────────────────


class ScanRequest(BaseModel):
    username: str = Field(..., min_length=1)
    deep: bool = True
    smart: bool = False
    email: bool = False
    web: bool = False
    whois: bool = False
    breach: bool = False
    photo: bool = False
    dns: bool = False
    subdomain: bool = False
    recursive: bool = False
    passive: bool = False
    reverse_image: bool = False
    past_usernames: bool = False
    enrichment: bool = True
    tor: bool = False
    proxy: str | None = None
    categories: list[str] | None = None
    fp_threshold: float = 0.45
    save_history: bool = True
    case_id: int | None = None


class WatchlistAddRequest(BaseModel):
    username: str = Field(..., min_length=1)
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


class CaseCreateRequest(BaseModel):
    name: str = Field(..., min_length=1)
    description: str = ""
    tags: list[str] = Field(default_factory=list)


class CaseUpdateRequest(BaseModel):
    description: str | None = None
    status: str | None = None
    tags: list[str] | None = None


class CaseNoteRequest(BaseModel):
    body: str = Field(..., min_length=1)
    author: str = ""


class CaseBookmarkRequest(BaseModel):
    target_type: str = Field(..., min_length=1)
    target_value: str = Field(..., min_length=1)
    label: str = ""
    tags: list[str] = Field(default_factory=list)
    scan_id: int | None = None


class CaseLinkScanRequest(BaseModel):
    scan_id: int = Field(..., ge=1)
    label: str = ""


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


def _cfg_from_request(req: ScanRequest) -> ScanConfig:
    return ScanConfig(
        username=req.username.strip(),
        deep=req.deep,
        smart=req.smart,
        email=req.email,
        web=req.web,
        whois=req.whois,
        breach=req.breach,
        photo=req.photo,
        dns=req.dns,
        subdomain=req.subdomain,
        recursive=req.recursive,
        passive=req.passive,
        reverse_image=req.reverse_image,
        past_usernames=req.past_usernames,
        enrichment=req.enrichment,
        tor=req.tor,
        proxy=req.proxy,
        categories=tuple(req.categories) if req.categories else None,
        fp_threshold=req.fp_threshold,
    )


async def _execute_api_scan(req: ScanRequest) -> dict[str, Any]:
    cfg = _cfg_from_request(req)
    result = await run_scan(cfg)
    completed = complete_scan_result(
        result,
        cfg,
        save_history=req.save_history,
        case_id=req.case_id,
        mark_watchlist=True,
    )
    return completed.payload


# ── App factory ──────────────────────────────────────────────────────


def build_app() -> FastAPI:
    dependencies = [Depends(_auth_dependency)] if auth.is_auth_required() else None
    app = FastAPI(
        title="cyberm4fia-osint API",
        version="0.3.0",
        description="REST surface around the OSINT scan engine.",
        dependencies=dependencies,
    )
    app.state.scan_jobs = ScanJobStore(runner=run_scan)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "ts": int(time.time())}

    @app.get("/capabilities")
    def capabilities() -> dict[str, Any]:
        return {
            "schema_version": SCAN_PAYLOAD_SCHEMA_VERSION,
            "generated_at": int(time.time()),
            "capabilities": collect_capabilities(),
        }

    @app.post("/auth/login")
    def auth_login(req: LoginRequest) -> dict[str, Any]:
        user = auth.authenticate(req.username, req.password)
        if user is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        ttl = 3600
        token = auth.issue_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
            secret=auth.get_secret(),
            ttl=ttl,
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": ttl,
            "user": user.to_dict(),
        }

    @app.get("/auth/me")
    def auth_me(request: Request) -> dict[str, Any]:
        # When the gate is off we have no request.state.user. Require the
        # header ourselves so /auth/me always needs a valid token — the
        # gate is *about the rest of the surface*, not this endpoint.
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = header.split(" ", 1)[1].strip()
        try:
            payload = auth.decode_token(token, secret=auth.get_secret())
        except auth.AuthError as exc:
            raise HTTPException(
                status_code=401, detail=f"invalid token: {exc}"
            ) from exc
        return {
            "username": payload.get("sub"),
            "uid": payload.get("uid"),
            "role": payload.get("role"),
            "exp": payload.get("exp"),
        }

    @app.post("/scan")
    async def scan(req: ScanRequest) -> dict[str, Any]:
        try:
            return await _execute_api_scan(req)
        except Exception as exc:
            log.exception("scan failed for %s", req.username)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/scan/stream")
    async def scan_stream(req: ScanRequest) -> StreamingResponse:
        cfg = _cfg_from_request(req)

        async def _stream() -> AsyncIterator[bytes]:
            emitter = ProgressEmitter()
            queue = emitter.subscribe()

            async def _runner() -> None:
                set_emitter(emitter)
                try:
                    try:
                        result = await run_scan(cfg)
                    except Exception as exc:
                        log.exception("streamed scan failed for %s", req.username)
                        emitter.emit_error(str(exc))
                        return
                    completed = complete_scan_result(
                        result,
                        cfg,
                        save_history=req.save_history,
                        case_id=req.case_id,
                        mark_watchlist=True,
                    )
                    emitter.emit_result(completed.payload)
                finally:
                    set_emitter(None)
                    emitter.close()

            task = asyncio.create_task(_runner())
            try:
                while True:
                    if task.done() and queue.empty():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=0.5)
                    except asyncio.TimeoutError:
                        if task.done():
                            break
                        continue
                    if event is None:
                        break
                    yield f"data: {json.dumps(event.to_dict())}\n\n".encode()
                    if event.kind in {"done", "error", "result"}:
                        # keep draining until emitter closes so result/done both flow
                        continue
            finally:
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                emitter.unsubscribe(queue)

        return StreamingResponse(_stream(), media_type="text/event-stream")

    @app.post("/scan-jobs", status_code=202)
    async def create_scan_job(req: ScanRequest, request: Request) -> dict[str, Any]:
        cfg = _cfg_from_request(req)
        store: ScanJobStore = request.app.state.scan_jobs
        try:
            job = store.create_job(
                cfg,
                req.model_dump(),
                save_history=req.save_history,
                case_id=req.case_id,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        return job.to_dict()

    @app.get("/scan-jobs")
    def list_scan_jobs(request: Request, limit: int = 20) -> dict[str, Any]:
        store: ScanJobStore = request.app.state.scan_jobs
        jobs = store.list_jobs(limit=max(1, min(int(limit), 100)))
        return {
            "count": len(jobs),
            "jobs": [job.to_dict() for job in jobs],
        }

    @app.get("/scan-jobs/{job_id}")
    def get_scan_job(job_id: str, request: Request) -> dict[str, Any]:
        store: ScanJobStore = request.app.state.scan_jobs
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan job not found")
        return job.to_dict(include_result=True)

    @app.get("/scan-jobs/{job_id}/result")
    def get_scan_job_result(job_id: str, request: Request) -> dict[str, Any]:
        store: ScanJobStore = request.app.state.scan_jobs
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan job not found")
        if job.result is None:
            raise HTTPException(status_code=409, detail=f"scan job is still {job.status}")
        return job.result

    @app.get("/scan-jobs/{job_id}/events")
    async def stream_scan_job_events(job_id: str, request: Request) -> StreamingResponse:
        store: ScanJobStore = request.app.state.scan_jobs
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan job not found")

        async def _stream() -> AsyncIterator[bytes]:
            queue, backlog_size = job.subscribe()
            try:
                for event in job.events[:backlog_size]:
                    yield f"data: {json.dumps(event)}\n\n".encode()
                while True:
                    item = await queue.get()
                    if item is None:
                        break
                    yield f"data: {json.dumps(item)}\n\n".encode()
            finally:
                job.unsubscribe(queue)

        return StreamingResponse(_stream(), media_type="text/event-stream")

    @app.get("/graph/{username}")
    def graph(username: str) -> dict[str, Any]:
        entry = get_latest(username)
        if entry is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        return {
            "username": username,
            "scan_id": entry.id,
            "ts": entry.ts,
            **payload_to_cytoscape(entry.payload),
        }

    @app.get("/heatmap/{username}")
    def heatmap(username: str) -> dict[str, Any]:
        entry = get_latest(username)
        if entry is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        points = entry.payload.get("geo_points") or []
        # Leaflet.heat wants [[lat, lng, weight], ...]. Weight starts at 1
        # per hit; duplicate coords are folded so popular cities pop.
        weights: dict[tuple[float, float], int] = {}
        markers: list[dict[str, Any]] = []
        for g in points:
            try:
                lat = float(g["lat"])
                lng = float(g["lng"])
            except (KeyError, TypeError, ValueError):
                continue
            key = (round(lat, 4), round(lng, 4))
            weights[key] = weights.get(key, 0) + 1
            markers.append(
                {
                    "lat": lat,
                    "lng": lng,
                    "label": g.get("display") or g.get("query") or "",
                    "source": g.get("source") or "",
                    "country": g.get("country") or "",
                }
            )
        heat = [[lat, lng, w] for (lat, lng), w in weights.items()]
        return {
            "username": username,
            "scan_id": entry.id,
            "ts": entry.ts,
            "points": heat,
            "markers": markers,
        }

    @app.get("/compare")
    def compare_scans(
        a: str,
        b: str,
        a_scan: int | None = None,
        b_scan: int | None = None,
    ) -> dict[str, Any]:
        """Deep-diff two scans for side-by-side review.

        ``a`` and ``b`` are usernames; optional ``a_scan``/``b_scan``
        pin to specific history IDs (defaults: latest). Returns the
        structured diff *plus* both payloads so the UI can render each
        side without a second round-trip.
        """
        a_clean, b_clean = a.strip(), b.strip()
        if not a_clean or not b_clean:
            raise HTTPException(status_code=422, detail="both a and b are required")
        entry_a = get_scan(a_scan) if a_scan is not None else get_latest(a_clean)
        if entry_a is None:
            raise HTTPException(status_code=404, detail=f"no scan for {a_clean}")
        entry_b = get_scan(b_scan) if b_scan is not None else get_latest(b_clean)
        if entry_b is None:
            raise HTTPException(status_code=404, detail=f"no scan for {b_clean}")
        diff = compare_payloads(entry_a.payload, entry_b.payload)
        return {
            "scan_a": {
                "id": entry_a.id,
                "ts": entry_a.ts,
                "username": entry_a.username,
                "payload": entry_a.payload,
            },
            "scan_b": {
                "id": entry_b.id,
                "ts": entry_b.ts,
                "username": entry_b.username,
                "payload": entry_b.payload,
            },
            **diff.to_dict(),
        }

    @app.get("/correlate")
    def correlate_users(a: str, b: str) -> dict[str, Any]:
        """Score how likely two usernames are the same person.

        Pulls the latest scan payload from history for each side and
        runs the correlation scorer. 404s if either user has no history —
        the scorer needs something to compare against.
        """
        a_clean, b_clean = a.strip(), b.strip()
        if not a_clean or not b_clean:
            raise HTTPException(status_code=422, detail="both a and b are required")
        if a_clean.lower() == b_clean.lower():
            raise HTTPException(status_code=400, detail="a and b must differ")
        entry_a = get_latest(a_clean)
        if entry_a is None:
            raise HTTPException(status_code=404, detail=f"no scans for {a_clean}")
        entry_b = get_latest(b_clean)
        if entry_b is None:
            raise HTTPException(status_code=404, detail=f"no scans for {b_clean}")
        result = correlate(entry_a.payload, entry_b.payload)
        return {
            "scan_a": {"id": entry_a.id, "ts": entry_a.ts},
            "scan_b": {"id": entry_b.id, "ts": entry_b.ts},
            **result.to_dict(),
        }

    @app.get("/social-graph")
    async def social_graph_compare(
        a: str,
        b: str,
        platform: str = "github",
        max_pages: int = 5,
    ) -> dict[str, Any]:
        """Compare follower/following overlap between two accounts."""
        a_clean, b_clean = a.strip(), b.strip()
        if not a_clean or not b_clean:
            raise HTTPException(status_code=422, detail="both a and b are required")
        if platform != "github":
            raise HTTPException(
                status_code=400,
                detail=f"platform {platform!r} not supported (only 'github')",
            )
        async with HTTPClient() as client:
            neighbors_a = await fetch_github_neighbors(
                client, a_clean, max_pages=max_pages
            )
            neighbors_b = await fetch_github_neighbors(
                client, b_clean, max_pages=max_pages
            )
        overlap = compute_overlap(neighbors_a, neighbors_b)
        return {
            "neighbors_a": neighbors_a.to_dict(),
            "neighbors_b": neighbors_b.to_dict(),
            **overlap.to_dict(),
        }

    @app.get("/history/{username}")
    def history(username: str, limit: int = 20) -> dict[str, Any]:
        entries = list_scans(username, limit=limit)
        return {
            "username": username,
            "count": len(entries),
            "entries": [
                {
                    "id": e.id,
                    "ts": e.ts,
                    "found_count": e.found_count,
                }
                for e in entries
            ],
        }

    @app.get("/history/{username}/latest")
    def history_latest(username: str) -> dict[str, Any]:
        entry = get_latest(username)
        if entry is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        return {
            "id": entry.id,
            "ts": entry.ts,
            "found_count": entry.found_count,
            "payload": entry.payload,
        }

    @app.get("/history/scan/{scan_id}")
    def history_scan(scan_id: int) -> dict[str, Any]:
        entry = get_scan(scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return {
            "id": entry.id,
            "username": entry.username,
            "ts": entry.ts,
            "found_count": entry.found_count,
            "payload": entry.payload,
        }

    @app.get("/history/{username}/diff")
    def history_diff(username: str) -> dict[str, Any]:
        current = get_latest(username)
        if current is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        previous = get_latest(username, before_id=current.id)
        if previous is None:
            return {"added": [], "removed": [], "message": "no previous scan"}
        d = diff_entries(previous, current)
        return {
            "previous_id": previous.id,
            "current_id": current.id,
            "added": list(d.added),
            "removed": list(d.removed),
        }

    @app.get("/search")
    def search_history(
        q: str,
        limit: int = 20,
        username: str | None = None,
    ) -> dict[str, Any]:
        query = (q or "").strip()
        if not query:
            raise HTTPException(status_code=400, detail="q is required")
        capped = max(1, min(int(limit), 100))
        hits = history_search(query, limit=capped, username=username)
        return {
            "query": query,
            "count": len(hits),
            "hits": [h.to_dict() for h in hits],
        }

    @app.get("/cases")
    def cases_list() -> dict[str, Any]:
        entries = cases.list_cases()
        return {
            "count": len(entries),
            "entries": [c.to_dict() for c in entries],
        }

    @app.post("/cases")
    def cases_create(req: CaseCreateRequest) -> dict[str, Any]:
        try:
            c = cases.create_case(
                req.name, description=req.description, tags=req.tags
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return c.to_dict()

    @app.get("/cases/{case_id}")
    def cases_detail(case_id: int) -> dict[str, Any]:
        c = cases.get_case(case_id)
        if c is None:
            raise HTTPException(status_code=404, detail="case not found")
        return {
            **c.to_dict(),
            "notes": [n.to_dict() for n in cases.list_notes(case_id)],
            "bookmarks": [b.to_dict() for b in cases.list_bookmarks(case_id)],
        }

    @app.patch("/cases/{case_id}")
    def cases_update(case_id: int, req: CaseUpdateRequest) -> dict[str, Any]:
        try:
            updated = cases.update_case(
                case_id,
                description=req.description,
                status=req.status,
                tags=req.tags,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if updated is None:
            raise HTTPException(status_code=404, detail="case not found")
        return updated.to_dict()

    @app.delete("/cases/{case_id}")
    def cases_delete(case_id: int) -> dict[str, Any]:
        if not cases.delete_case(case_id):
            raise HTTPException(status_code=404, detail="case not found")
        return {"deleted": case_id}

    @app.post("/cases/{case_id}/notes")
    def cases_add_note(case_id: int, req: CaseNoteRequest) -> dict[str, Any]:
        try:
            note = cases.add_note(case_id, req.body, author=req.author)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return note.to_dict()

    @app.delete("/cases/notes/{note_id}")
    def cases_delete_note(note_id: int) -> dict[str, Any]:
        if not cases.delete_note(note_id):
            raise HTTPException(status_code=404, detail="note not found")
        return {"deleted": note_id}

    @app.post("/cases/{case_id}/bookmarks")
    def cases_add_bookmark(
        case_id: int, req: CaseBookmarkRequest
    ) -> dict[str, Any]:
        try:
            bm = cases.add_bookmark(
                case_id,
                target_type=req.target_type,
                target_value=req.target_value,
                label=req.label,
                tags=req.tags,
                scan_id=req.scan_id,
            )
        except ValueError as exc:
            # Unknown target_type is a 400; missing case is a 404.
            status = 404 if "does not exist" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return bm.to_dict()

    @app.post("/cases/{case_id}/scans")
    def cases_link_scan(case_id: int, req: CaseLinkScanRequest) -> dict[str, Any]:
        entry = get_scan(req.scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="scan not found")
        try:
            bm = cases.add_bookmark(
                case_id,
                target_type="scan",
                target_value=entry.username,
                label=req.label or f"Scan #{entry.id} for {entry.username}",
                scan_id=entry.id,
            )
        except ValueError as exc:
            status = 404 if "does not exist" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {
            **bm.to_dict(),
            "scan": {
                "id": entry.id,
                "username": entry.username,
                "ts": entry.ts,
                "found_count": entry.found_count,
            },
        }

    @app.delete("/cases/bookmarks/{bookmark_id}")
    def cases_delete_bookmark(bookmark_id: int) -> dict[str, Any]:
        if not cases.delete_bookmark(bookmark_id):
            raise HTTPException(status_code=404, detail="bookmark not found")
        return {"deleted": bookmark_id}

    @app.get("/watchlist")
    def watchlist_list() -> dict[str, Any]:
        entries = watchlist.list_all()
        return {
            "count": len(entries),
            "entries": [e.to_dict() for e in entries],
        }

    @app.post("/watchlist")
    def watchlist_add(req: WatchlistAddRequest) -> dict[str, Any]:
        try:
            entry = watchlist.add(req.username, tags=req.tags, notes=req.notes)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return entry.to_dict()

    @app.delete("/watchlist/{username}")
    def watchlist_remove(username: str) -> dict[str, Any]:
        ok = watchlist.remove(username)
        if not ok:
            raise HTTPException(status_code=404, detail="not in watchlist")
        return {"removed": username}

    # ── Static Web UI ────────────────────────────────────────────
    if _WEB_DIR.exists():
        @app.get("/", response_model=None)
        def index():
            index_path = _WEB_DIR / "index.html"
            if index_path.exists():
                return FileResponse(str(index_path))
            return JSONResponse({"message": "cyberm4fia-osint API", "docs": "/docs"})

        @app.get("/static/{asset_path:path}", response_model=None)
        def static_asset(asset_path: str):
            web_root = _WEB_DIR.resolve()
            target = (web_root / asset_path).resolve()
            if web_root not in target.parents or not target.is_file():
                raise HTTPException(status_code=404, detail="static asset not found")
            return FileResponse(str(target))
    else:
        @app.get("/")
        def index_fallback() -> dict[str, Any]:
            return {"message": "cyberm4fia-osint API", "docs": "/docs"}

    return app


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the dev server via uvicorn."""
    import uvicorn

    app = build_app()
    uvicorn.run(app, host=host, port=port)
