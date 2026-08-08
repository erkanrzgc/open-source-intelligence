"""Export ScanResult as a Graphviz DOT graph.

Nodes: the target username, discovered platforms, emails, linked
domains. Edges are labelled by relation type. DOT was chosen because
it renders with any graphviz install and needs no runtime dependency.
"""

from __future__ import annotations

from typing import Any


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")

_VALID_SHAPES = frozenset({"box", "ellipse", "circle", "doublecircle", "hexagon", "diamond", "plaintext"})
_VALID_COLORS = frozenset({
    "steelblue", "crimson", "forestgreen", "darkorange", "purple", "gray",
    "red", "blue", "green", "orange", "black",
})


def _node(node_id: str, label: str, shape: str, color: str) -> str:
    safe_shape = shape if shape in _VALID_SHAPES else "box"
    safe_color = color if color in _VALID_COLORS else "black"
    return f'  "{_escape(node_id)}" [label="{_escape(label)}", shape={safe_shape}, color={safe_color}];'


def render_dot(result: Any) -> str:
    """Render a ScanResult (or its to_dict() payload) as DOT source."""
    payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    username = payload.get("username", "?")

    lines: list[str] = [
        f'digraph "open_source_intelligence_{_escape(username)}" {{',
        "  rankdir=LR;",
        '  node [fontname="Helvetica"];',
        _node(f"user:{username}", username, "doublecircle", "darkorange"),
    ]

    seen: set[str] = set()

    for p in payload.get("platforms", []):
        if not p.get("exists"):
            continue
        node_id = f"platform:{p['platform']}"
        if node_id in seen:
            continue
        seen.add(node_id)
        lines.append(_node(node_id, p["platform"], "box", "steelblue"))
        lines.append(
            f'  "user:{_escape(username)}" -> "{_escape(node_id)}" [label="account"];'
        )

    for email in payload.get("emails", []):
        addr = email.get("email") if isinstance(email, dict) else None
        if not addr:
            continue
        node_id = f"email:{addr}"
        if node_id in seen:
            continue
        seen.add(node_id)
        color = "crimson" if isinstance(email.get("breach_count"), (int, float)) and email.get("breach_count", 0) > 0 else "forestgreen"
        lines.append(_node(node_id, addr, "ellipse", color))
        lines.append(
            f'  "user:{_escape(username)}" -> "{_escape(node_id)}" [label="email"];'
        )

    for whois in payload.get("whois_records", []):
        domain = whois.get("domain") if isinstance(whois, dict) else None
        if not domain:
            continue
        node_id = f"domain:{domain}"
        if node_id in seen:
            continue
        seen.add(node_id)
        lines.append(_node(node_id, domain, "hexagon", "purple"))
        lines.append(
            f'  "user:{_escape(username)}" -> "{_escape(node_id)}" [label="domain"];'
        )

    for other in payload.get("discovered_usernames", []):
        if not isinstance(other, str) or other == username:
            continue
        node_id = f"alias:{other}"
        if node_id in seen:
            continue
        seen.add(node_id)
        lines.append(_node(node_id, other, "box", "gray"))
        lines.append(
            f'  "user:{_escape(username)}" -> "{_escape(node_id)}" [label="alias", style=dashed];'
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def export_dot(result: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_dot(result))
