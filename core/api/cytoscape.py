"""Convert a scan payload dict into Cytoscape.js-compatible elements.

Cytoscape wants a flat ``[{data: {...}}]`` array where each entry is
either a node (has ``id``) or an edge (has ``source`` and ``target``).
We read the same fields the NetworkX graph builder reads, but operate on
the JSON payload stored in history so the web UI can render any past
scan without rerunning it.
"""

from __future__ import annotations

from typing import Any


def payload_to_cytoscape(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    username = payload.get("username", "?")
    nodes: list[dict[str, Any]] = [
        {"data": {"id": username, "label": username, "kind": "identity"}}
    ]
    edges: list[dict[str, Any]] = []

    for p in payload.get("platforms", []) or []:
        if not p.get("exists"):
            continue
        pid = f"platform::{p.get('platform', '')}"
        nodes.append(
            {
                "data": {
                    "id": pid,
                    "label": p.get("platform", ""),
                    "kind": "platform",
                    "url": p.get("url", ""),
                    "category": p.get("category", ""),
                    "confidence": p.get("confidence", 0.0),
                }
            }
        )
        edges.append({"data": {"source": username, "target": pid, "relation": "has_profile"}})

    for e in payload.get("emails", []) or []:
        eid = f"email::{e.get('email', '')}"
        nodes.append(
            {
                "data": {
                    "id": eid,
                    "label": e.get("email", ""),
                    "kind": "email",
                    "verified": e.get("verified", False),
                    "source": e.get("source", ""),
                }
            }
        )
        edges.append({"data": {"source": username, "target": eid, "relation": "has_email"}})
        for breach in e.get("breaches", []) or []:
            bid = f"breach::{breach}"
            nodes.append({"data": {"id": bid, "label": str(breach), "kind": "breach"}})
            edges.append(
                {"data": {"source": eid, "target": bid, "relation": "appeared_in"}}
            )

    for phone in payload.get("phone_intel", []) or []:
        label = phone.get("e164") or phone.get("raw") or ""
        if not label:
            continue
        pid = f"phone::{label}"
        nodes.append(
            {
                "data": {
                    "id": pid,
                    "label": label,
                    "kind": "phone",
                    "country": phone.get("country_name", ""),
                    "carrier": phone.get("carrier", ""),
                    "line_type": phone.get("line_type", ""),
                }
            }
        )
        edges.append({"data": {"source": username, "target": pid, "relation": "has_phone"}})

    for crypto in payload.get("crypto_intel", []) or []:
        addr = crypto.get("address", "")
        if not addr:
            continue
        cid = f"crypto::{addr}"
        nodes.append(
            {
                "data": {
                    "id": cid,
                    "label": addr,
                    "kind": "crypto",
                    "chain": crypto.get("chain", ""),
                    "balance": crypto.get("balance", 0.0),
                    "tx_count": crypto.get("tx_count", 0),
                }
            }
        )
        edges.append({"data": {"source": username, "target": cid, "relation": "owns"}})

    for alias in payload.get("historical_usernames", []) or []:
        uname = alias.get("username", "")
        if not uname:
            continue
        aid = f"alias::{uname}@{alias.get('platform', '')}"
        nodes.append(
            {
                "data": {
                    "id": aid,
                    "label": uname,
                    "kind": "alias",
                    "platform": alias.get("platform", ""),
                    "first_seen": alias.get("first_seen", ""),
                    "last_seen": alias.get("last_seen", ""),
                }
            }
        )
        edges.append(
            {"data": {"source": username, "target": aid, "relation": "was_known_as"}}
        )

    for candidate in payload.get("identity_candidates", []) or []:
        if not isinstance(candidate, dict):
            continue
        alias = candidate.get("username", "")
        if not alias:
            continue
        aid = f"alias::{alias}"
        nodes.append(
            {
                "data": {
                    "id": aid,
                    "label": alias,
                    "kind": "alias",
                    "verdict": candidate.get("verdict", "uncertain"),
                    "score": candidate.get("score", 0.0),
                }
            }
        )
        edges.append(
            {"data": {"source": username, "target": aid, "relation": "identity_candidate"}}
        )

    # Dedupe nodes by id — a breach can repeat across emails.
    # Dedupe edges by (source, target, relation) tuple.
    seen: set[str] = set()
    unique_nodes: list[dict[str, Any]] = []
    for n in nodes:
        nid = n["data"]["id"]
        if nid in seen:
            continue
        seen.add(nid)
        unique_nodes.append(n)

    seen_edges: set[tuple[str, str, str]] = set()
    unique_edges: list[dict[str, Any]] = []
    for e in edges:
        key = (e["data"]["source"], e["data"]["target"], e["data"]["relation"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        unique_edges.append(e)

    return {"nodes": unique_nodes, "edges": unique_edges}
