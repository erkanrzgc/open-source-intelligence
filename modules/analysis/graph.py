"""NetworkX entity graph for a scan result.

Nodes:

* ``identity``   — the queried username (single root)
* ``platform``   — every confirmed platform profile
* ``email``      — discovered emails
* ``phone``      — phone_intel entries
* ``crypto``     — crypto_intel entries
* ``alias``      — historical usernames
* ``breach``     — COMB / HIBP breach records linked to an email

Edges all point from the root outward; we keep the graph simple and
directed. The orchestrator exports it as a NetworkX node-link dict so
the reporter can dump it to JSON or feed it to a visualiser.
"""

from __future__ import annotations

from typing import Any, cast

import networkx as nx


def build_entity_graph(result: Any) -> nx.DiGraph:
    """Return a :class:`networkx.DiGraph` describing the scan result.

    ``result`` is duck-typed; we only read attributes we know exist on
    :class:`core.models.ScanResult`.
    """
    g = nx.DiGraph()

    root = result.username
    g.add_node(root, kind="identity", label=root)

    for p in getattr(result, "platforms", []) or []:
        if not getattr(p, "exists", False):
            continue
        node_id = f"platform::{p.platform}"
        g.add_node(
            node_id,
            kind="platform",
            label=p.platform,
            url=p.url,
            category=p.category,
            confidence=getattr(p, "confidence", 0.0),
        )
        g.add_edge(root, node_id, relation="has_profile")

    for e in getattr(result, "emails", []) or []:
        node_id = f"email::{e.email}"
        g.add_node(
            node_id,
            kind="email",
            label=e.email,
            verified=getattr(e, "verified", False),
            source=getattr(e, "source", ""),
        )
        g.add_edge(root, node_id, relation="has_email")
        for breach in getattr(e, "breaches", []) or []:
            b_id = f"breach::{breach}"
            g.add_node(b_id, kind="breach", label=str(breach))
            g.add_edge(node_id, b_id, relation="appeared_in")

    for phone in getattr(result, "phone_intel", []) or []:
        label = getattr(phone, "e164", "") or getattr(phone, "raw", "")
        if not label:
            continue
        node_id = f"phone::{label}"
        g.add_node(
            node_id,
            kind="phone",
            label=label,
            country=getattr(phone, "country_name", ""),
            carrier=getattr(phone, "carrier", ""),
            line_type=getattr(phone, "line_type", ""),
        )
        g.add_edge(root, node_id, relation="has_phone")

    for crypto in getattr(result, "crypto_intel", []) or []:
        addr = getattr(crypto, "address", "")
        if not addr:
            continue
        node_id = f"crypto::{addr}"
        g.add_node(
            node_id,
            kind="crypto",
            label=addr,
            chain=getattr(crypto, "chain", ""),
            balance=getattr(crypto, "balance", 0.0),
            tx_count=getattr(crypto, "tx_count", 0),
        )
        g.add_edge(root, node_id, relation="owns")

    for alias in getattr(result, "historical_usernames", []) or []:
        username = getattr(alias, "username", "")
        if not username:
            continue
        node_id = f"alias::{username}@{getattr(alias, 'platform', '')}"
        g.add_node(
            node_id,
            kind="alias",
            label=username,
            platform=getattr(alias, "platform", ""),
            first_seen=getattr(alias, "first_seen", ""),
            last_seen=getattr(alias, "last_seen", ""),
        )
        g.add_edge(root, node_id, relation="was_known_as")

    for candidate in getattr(result, "identity_candidates", []) or []:
        username = (
            candidate.get("username", "")
            if isinstance(candidate, dict)
            else getattr(candidate, "username", "")
        )
        if not username:
            continue
        verdict = (
            candidate.get("verdict", "uncertain")
            if isinstance(candidate, dict)
            else getattr(candidate, "verdict", "uncertain")
        )
        score = (
            candidate.get("score", 0.0)
            if isinstance(candidate, dict)
            else getattr(candidate, "score", 0.0)
        )
        node_id = f"alias::{username}"
        g.add_node(
            node_id,
            kind="alias",
            label=username,
            verdict=verdict,
            score=score,
        )
        g.add_edge(root, node_id, relation="identity_candidate")

    return g


def graph_to_dict(g: nx.DiGraph) -> dict[str, Any]:
    """Serialize the graph to a JSON-safe node-link dict."""
    return cast(dict[str, Any], nx.node_link_data(g))
