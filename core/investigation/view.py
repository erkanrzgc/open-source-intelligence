"""Pure, evidence-preserving case graph, timeline and lead projection."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from core.history import HistoryEntry
from core.smart_search import extract_discoverable_data
from utils.helpers import sanitize_username

MAX_DEPTH = 2
MAX_SCANS = 200
MAX_LEADS = 100
METADATA_FIELDS = (
    "name",
    "display_name",
    "bio",
    "description",
    "location",
    "website_url",
    "blog",
    "company",
)


def entity_id(kind: str, *parts: str) -> str:
    value = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return kind + ":" + hashlib.sha256(value.encode()).hexdigest()[:32]


def _presence(row: dict) -> str:
    if row.get("exists") and (row.get("verification") or {}).get("verdict") == "confirmed":
        return "confirmed"
    if row.get("probe_outcome") == "not_found":
        return "not_found"
    return "unavailable_or_uncertain"


def build_workbench(entries: list[HistoryEntry], reviews: dict | None = None) -> dict[str, Any]:
    """Never merge people by name or translate a missing row into account deletion."""
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    timeline: list[dict] = []
    leads: dict[str, dict] = {}
    previous: dict[tuple[str, str], dict] = {}
    previous_metadata: dict[tuple[str, str], dict] = {}
    entries = sorted({entry.id: entry for entry in entries}.values(), key=lambda e: (e.ts, e.id))
    scanned = {entry.username.casefold() for entry in entries}

    def node(kind: str, label: str, *key: str, **attrs: Any) -> str:
        nid = entity_id(kind, *key)
        nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, **attrs})
        return nid

    def edge(source: str, target: str, relation: str, evidence: dict, **attrs: Any) -> str:
        eid = entity_id("edge", source, target, relation)
        record = edges.setdefault(
            eid,
            {
                "id": eid,
                "source": source,
                "target": target,
                "relation": relation,
                "observations": [],
            },
        )
        record.update(attrs)
        if evidence not in record["observations"]:
            record["observations"].append(evidence)
        record["analyst_review"] = (reviews or {}).get(eid)
        return eid

    def lead(username: str, evidence: dict, depth: int, reason: str, verdict: str) -> None:
        try:
            handle = sanitize_username(username).casefold()
        except (TypeError, ValueError):
            return
        if not handle or handle in scanned:
            return
        lid = entity_id("lead", handle)
        existing = leads.get(lid)
        if existing is None or depth < existing["depth"]:
            leads[lid] = {
                "id": lid,
                "username": handle,
                "depth": depth,
                "source_scan_id": evidence["scan_id"],
                "source_url": evidence["source_url"],
                "reason": reason,
                "verdict": verdict,
                "eligible": depth <= MAX_DEPTH,
                "blocked_reason": None if depth <= MAX_DEPTH else "depth_limit",
            }

    for entry in entries:
        root = node("query", entry.username, entry.username.casefold())
        depth = int(
            ((entry.payload.get("diagnostics") or {}).get("investigation") or {}).get("depth", 0)
        )
        timeline.append(
            {"kind": "scan", "scan_id": entry.id, "ts": entry.ts, "username": entry.username}
        )

        def profile(
            row: dict,
            owner_node: str,
            handle: str,
            *,
            entry: HistoryEntry = entry,
            depth: int = depth,
        ) -> dict:
            platform = str(row.get("platform", "Unknown"))
            url = str(row.get("url") or "")
            canonical = str(row.get("canonical_username") or row.get("queried_username") or handle)
            try:
                host = urlsplit(url).hostname or ""
            except ValueError:
                host = ""
            pid = node(
                "profile",
                f"{platform}: {canonical}",
                platform.casefold(),
                host.casefold(),
                canonical.casefold(),
                url=url,
            )
            presence = _presence(row)
            proof = {
                "scan_id": entry.id,
                "scan_ts": entry.ts,
                "source_url": url,
                "checked_at": row.get("checked_at"),
                "platform": platform,
                "presence": presence,
                "http_status": row.get("http_status"),
                "contract_revision": row.get("contract_revision", ""),
                "reason_codes": list((row.get("verification") or {}).get("reason_codes", [])),
            }
            edge(owner_node, pid, "observed_profile", proof, verdict=presence)
            key = (entry.username.casefold(), pid)
            old = previous.get(key)
            data = row.get("profile_data") or {}
            if not isinstance(data, dict):
                data = {}
            if presence == "confirmed":
                metadata = {k: data[k] for k in METADATA_FIELDS if isinstance(data.get(k), str)}
                if old is None:
                    timeline.append(
                        {
                            "kind": "profile_observed",
                            "scan_id": entry.id,
                            "ts": entry.ts,
                            "profile_id": pid,
                            "evidence": proof,
                        }
                    )
                elif old["presence"] != "confirmed":
                    timeline.append(
                        {
                            "kind": "coverage_restored",
                            "scan_id": entry.id,
                            "ts": entry.ts,
                            "profile_id": pid,
                            "evidence": proof,
                        }
                    )
                prior = previous_metadata.get(key)
                if prior is not None:
                    changes = {
                        k: {"before": prior.get(k), "after": metadata.get(k)}
                        for k in sorted(prior.keys() & metadata.keys())
                        if prior.get(k) != metadata.get(k)
                    }
                    if changes:
                        timeline.append(
                            {
                                "kind": "metadata_changed",
                                "scan_id": entry.id,
                                "ts": entry.ts,
                                "profile_id": pid,
                                "changes": changes,
                                "evidence": proof,
                            }
                        )
                # Missing parser fields are unknown, not evidence of deletion.
                # Explicit empty strings remain observable values.
                previous_metadata[key] = {**(prior or {}), **metadata}
                for value in extract_discoverable_data(data)["linked_usernames"]:
                    lead(value, proof, depth + 1, "public_profile_link_or_mention", "unresolved")
                for field in ("website_url", "website", "blog"):
                    value = data.get(field)
                    if not isinstance(value, str):
                        continue
                    try:
                        parsed = urlsplit(value if "://" in value else "https://" + value)
                        domain = parsed.hostname
                    except ValueError:
                        continue
                    if domain and parsed.scheme in {"http", "https"}:
                        did = node("domain", domain, domain.casefold())
                        edge(pid, did, "declares_website", proof, verdict="observed_not_ownership")
                organizations = data.get("organizations") or []
                if not isinstance(organizations, list):
                    organizations = []
                for organization in [data.get("company"), *organizations[:10]]:
                    if isinstance(organization, dict):
                        organization = organization.get("name")
                    if isinstance(organization, str) and organization.strip():
                        oid = node("organization", organization, organization.strip().casefold())
                        edge(pid, oid, "declares_organization", proof, verdict="self_reported")
            elif old and old["presence"] != presence:
                timeline.append(
                    {
                        "kind": "absence_observed" if presence == "not_found" else "coverage_lost",
                        "scan_id": entry.id,
                        "ts": entry.ts,
                        "profile_id": pid,
                        "evidence": proof,
                    }
                )
            previous[key] = proof
            return proof

        for row in entry.payload.get("platforms") or []:
            if isinstance(row, dict):
                profile(row, root, entry.username)
        for candidate in entry.payload.get("identity_candidates") or []:
            if not isinstance(candidate, dict) or not candidate.get("username"):
                continue
            username = str(candidate["username"])
            alias = node("query", username, username.casefold())
            for row in candidate.get("profiles") or []:
                if not isinstance(row, dict):
                    continue
                proof = profile(row, alias, username)
                verdict = str(candidate.get("verdict", "uncertain"))
                edge(
                    root,
                    alias,
                    "identity_candidate",
                    proof,
                    verdict=verdict,
                    score=candidate.get("score", 0),
                    identity_evidence=candidate.get("evidence", []),
                )
                if proof["presence"] == "confirmed":
                    lead(username, proof, depth + 1, "confirmed_alias_presence", verdict)

    ordered_leads = sorted(leads.values(), key=lambda r: (r["depth"], r["username"]))
    return {
        "schema_version": 1,
        "graph": {
            "nodes": [{"data": v} for v in nodes.values()],
            "edges": [{"data": v} for v in edges.values()],
        },
        "timeline": sorted(timeline, key=lambda e: (e["ts"], e["scan_id"]), reverse=True),
        "leads": ordered_leads[:MAX_LEADS],
        "warnings": (["lead_list_truncated"] if len(ordered_leads) > MAX_LEADS else []),
        "summary": {
            "scans": len(entries),
            "nodes": len(nodes),
            "edges": len(edges),
            "leads": len(ordered_leads),
        },
    }
