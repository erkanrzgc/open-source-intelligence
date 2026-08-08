#!/usr/bin/env python3
"""Enrich platforms.yaml with maigret data (regexCheck, absenceStrs, urlProbe).

Usage:
    python scripts/enrich_maigret.py \\
        --maigret /tmp/maigret_data.json \\
        --out modules/platforms.yaml
"""
from __future__ import annotations

import argparse
import json
import sys
from difflib import SequenceMatcher
from pathlib import Path

import yaml


def _normalize(name: str) -> str:
    return name.lower().strip().rstrip(".")


def _match_maigret(maigret_sites: dict, our_names: list[str]) -> dict[str, str]:
    """Build mapping: our_name -> maigret_key (best match)."""
    mapping: dict[str, str] = {}
    our_index = {_normalize(n): n for n in our_names}
    maigret_index = {_normalize(k): k for k in maigret_sites}

    # Exact match
    for norm, mkey in maigret_index.items():
        if norm in our_index:
            mapping[our_index[norm]] = mkey

    # Fuzzy match for remaining
    unmatched_ours = set(our_index.values()) - set(mapping.keys())
    unmatched_maigret = set(maigret_index.values()) - set(mapping.values())
    for oname in sorted(unmatched_ours):
        best = None
        best_ratio = 0.0
        onorm = _normalize(oname)
        for mkey in sorted(unmatched_maigret):
            mnorm = _normalize(mkey)
            ratio = SequenceMatcher(None, onorm, mnorm).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best = mkey
        if best and best_ratio > 0.80:
            mapping[oname] = best
            unmatched_maigret.discard(best)

    return mapping


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich platforms.yaml with maigret data")
    parser.add_argument("--maigret", required=True, help="Path to maigret data.json")
    parser.add_argument("--yaml", default="modules/platforms.yaml", help="Platforms YAML to enrich")
    parser.add_argument("--out", default=None, help="Output file (default: overwrite --yaml)")
    args = parser.parse_args(argv)

    maigret_path = Path(args.maigret)
    if not maigret_path.is_file():
        print(f"ERROR: maigret file not found: {maigret_path}", file=sys.stderr)
        return 1

    yaml_path = Path(args.yaml)
    if not yaml_path.is_file():
        print(f"ERROR: platforms yaml not found: {yaml_path}", file=sys.stderr)
        return 1

    out_path = Path(args.out) if args.out else yaml_path

    # Load maigret
    maigret = json.loads(maigret_path.read_text(encoding="utf-8")).get("sites", {})
    print(f"Loaded {len(maigret)} maigret sites")

    # Load our YAML
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    platforms = raw.get("platforms", [])
    our_names = [p["name"] for p in platforms if isinstance(p, dict) and "name" in p]
    print(f"Loaded {len(our_names)} platforms from YAML")

    # Match
    mapping = _match_maigret(maigret, our_names)
    print(f"Matched {len(mapping)} platforms")

    # Enrich
    added_pattern = 0
    added_absence = 0
    added_probe = 0
    for entry in platforms:
        name = entry.get("name")
        mkey = mapping.get(name)
        if not mkey:
            continue
        mdata = maigret[mkey]

        regex = mdata.get("regexCheck")
        if regex and isinstance(regex, str) and "username_pattern" not in entry:
            entry["username_pattern"] = regex
            added_pattern += 1

        absence = mdata.get("absenceStrs")
        if absence and isinstance(absence, list) and len(absence) > 0 and "absence_strings" not in entry:
            entry["absence_strings"] = [str(s) for s in absence if s and str(s).strip()]
            if entry["absence_strings"]:
                added_absence += 1

        presence = mdata.get("presenseStrs")
        if presence and isinstance(presence, list) and len(presence) > 0 and "presence_strings" not in entry:
            entry["presence_strings"] = [str(s) for s in presence if s and str(s).strip()]

        probe = mdata.get("urlProbe")
        if probe and isinstance(probe, str) and "url_probe" not in entry:
            entry["url_probe"] = probe
            added_probe += 1

        check_type = mdata.get("checkType")
        if check_type and isinstance(check_type, str) and "check_method" not in entry:
            method_map = {
                "status_code": "status",
                "message": "message",
                "response_url": "response_url",
            }
            entry["check_method"] = method_map.get(check_type, "status")

    # Write
    out_path.write_text(yaml.dump(raw, allow_unicode=True, default_flow_style=False), encoding="utf-8")
    print(f"\nEnrichment results:")
    print(f"  username_pattern added: {added_pattern}")
    print(f"  absence_strings added: {added_absence}")
    print(f"  url_probe added:        {added_probe}")
    print(f"Written to {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
