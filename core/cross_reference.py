"""Cross-reference found profiles to determine if they belong to the same person."""

from core.models import CrossReferenceResult, PlatformResult
from utils.helpers import fuzzy_name_match, normalize_name


def cross_reference(found_platforms: list[PlatformResult]) -> CrossReferenceResult:
    profiles_with_data = [p for p in found_platforms if p.profile_data]
    if len(profiles_with_data) < 2:
        return CrossReferenceResult(
            confidence=0.0,
            notes=["Insufficient profile data (requires at least 2 deep-scraped profiles)"],
        )

    names: dict[str, list[str]] = {}
    locations: dict[str, list[str]] = {}
    bios: dict[str, str] = {}

    for p in profiles_with_data:
        d = p.profile_data
        for key in ["name", "full_name", "persona_name", "real_name"]:
            val = d.get(key)
            if val and isinstance(val, str) and val.strip():
                names.setdefault(normalize_name(val), []).append(p.platform)
                break
        first = d.get("first_name", "")
        last = d.get("last_name", "")
        if first and last:
            names.setdefault(normalize_name(f"{first} {last}"), []).append(p.platform)

        for key in ["location", "country"]:
            val = d.get(key)
            if val and isinstance(val, str) and val.strip():
                locations.setdefault(val.strip().lower(), []).append(p.platform)

        for key in ["bio", "summary", "about"]:
            val = d.get(key)
            if val and isinstance(val, str) and len(val.strip()) > 10:
                bios[p.platform] = val.strip()

    score = 0.0
    total_weight = 0.0
    matched_names = []
    matched_locations = []
    notes = []

    # name matching (weight: 40)
    total_weight += 40
    all_names = list(names.keys())
    if len(all_names) == 1 and len(names[all_names[0]]) >= 2:
        score += 40
        matched_names.append(
            f"'{all_names[0]}' → {', '.join(names[all_names[0]])}"
        )
    elif len(all_names) > 1:
        best_match = 0.0
        best_pair = ("", "")
        for i, n1 in enumerate(all_names):
            for n2 in all_names[i + 1 :]:
                sim = fuzzy_name_match(n1, n2)
                if sim > best_match:
                    best_match = sim
                    best_pair = (n1, n2)
        if best_match > 0.7:
            score += 40 * best_match
            matched_names.append(
                f"'{best_pair[0]}' ~ '{best_pair[1]}' (similarity: {best_match:.0%})"
            )
        elif best_match > 0.3:
            score += 40 * best_match * 0.5
            notes.append(
                f"Partial name match: '{best_pair[0]}' / '{best_pair[1]}'"
            )
        else:
            notes.append(f"Names differ: {', '.join(all_names)}")

    # location matching (weight: 30)
    total_weight += 30
    if len(locations) == 1:
        loc = next(iter(locations.keys()))
        platforms = locations[loc]
        if len(platforms) >= 2:
            score += 30
            matched_locations.append(f"'{loc}' → {', '.join(platforms)}")
    elif len(locations) > 1:
        locs = list(locations.keys())
        for i, l1 in enumerate(locs):
            for l2 in locs[i + 1 :]:
                if l1 in l2 or l2 in l1:
                    score += 20
                    matched_locations.append(f"'{l1}' ~ '{l2}'")
                    break

    # linked accounts (weight: 30)
    total_weight += 30
    linked_found = False
    for p in profiles_with_data:
        d = p.profile_data
        for key in ["twitter_username", "github_username"]:
            linked = d.get(key, "")
            if linked:
                for other in profiles_with_data:
                    if other.platform != p.platform and linked.lower() in other.url.lower():
                        score += 30
                        linked_found = True
                        notes.append(
                            f"{p.platform} → {key}: '{linked}' (verified link)"
                        )
                        break
            if linked_found:
                break
        if linked_found:
            break

        proofs = d.get("proofs", [])
        for proof in proofs:
            if isinstance(proof, dict):
                for other in profiles_with_data:
                    proof_name = proof.get("username", "").lower()
                    if proof_name and proof_name in other.url.lower():
                        score += 30
                        linked_found = True
                        notes.append(
                            f"Keybase proof: {proof.get('service')} → '{proof_name}'"
                        )
                        break
            if linked_found:
                break

    confidence = (score / total_weight * 100) if total_weight > 0 else 0.0
    confidence = min(confidence, 100.0)

    return CrossReferenceResult(
        confidence=round(confidence, 1),
        matched_names=matched_names,
        matched_locations=matched_locations,
        notes=notes,
    )
