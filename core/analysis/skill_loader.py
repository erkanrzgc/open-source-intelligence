"""Multi-skill LLM registry — loads YAML-frontmatter markdown files.

Each file under ``core/analysis/skills/`` defines a single LLM task:

    ---
    name: profile_validator
    description: Validate that a found profile actually belongs to the target.
    model: nvidia/llama-3.1-nemotron-70b-instruct  # optional override
    max_tokens: 512
    temperature: 0.15
    output_schema:
      type: object
      required: [match_score, signals]
      properties:
        match_score: {type: integer, minimum: 0, maximum: 100}
        signals: {type: array, items: {type: string}}
    ---

    SYSTEM PROMPT BODY GOES HERE.

    Few-shot examples may follow.

The loader exposes ``load_skill(name)`` and ``run_skill(name, inputs)``
plus an opt-in disk cache and an in-process LLM call budget. The cache
key hashes (skill version + inputs), so prompt edits invalidate stale
entries automatically.

Skills are dependency-light by design — they MUST work without
``llama-cpp-python`` or any heavyweight extras. Only the standard
library plus the project's ``HttpBackend`` is required.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.analysis.llm import (
    DEFAULT_HTTP_API_KEY,
    DEFAULT_HTTP_MODEL,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_HTTP_URL,
    Backend,
    HttpBackend,
    LLMUnavailable,
    parse_report,  # noqa: F401  (re-exported for convenience)
)

log = logging.getLogger(__name__)


SKILLS_DIR = Path(__file__).parent / "skills"
CACHE_DIR = Path(
    os.environ.get(
        "CYBERM4FIA_SKILL_CACHE",
        str(Path.home() / ".cache" / "cyberm4fia" / "skills"),
    )
)
CACHE_TTL_SECONDS = int(
    os.environ.get("CYBERM4FIA_SKILL_CACHE_TTL", str(24 * 3600))
)
DEFAULT_MAX_TOKENS = 512
DEFAULT_TEMPERATURE = 0.2


class SkillError(RuntimeError):
    """Raised when a skill cannot be loaded, parsed, or executed."""


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    system_prompt: str
    output_schema: dict[str, Any]
    model: str = ""
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    triggers: tuple[str, ...] = ()
    raw_frontmatter: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash over the prompt + schema; used as cache key prefix."""
        h = hashlib.blake2b(digest_size=12)
        h.update(self.name.encode())
        h.update(self.system_prompt.encode())
        h.update(json.dumps(self.output_schema, sort_keys=True).encode())
        return h.hexdigest()


_FRONTMATTER_RE = re.compile(
    r"^---\s*\n(?P<fm>.*?)\n---\s*\n(?P<body>.*)$", re.DOTALL
)

_SKILL_CACHE: dict[str, Skill] = {}


def _parse_yaml_lite(text: str) -> dict[str, Any]:
    """Minimal YAML-ish parser sufficient for skill frontmatter.

    We do not bring in PyYAML to keep deps lean. The accepted subset:

        key: scalar value          # str/int/float/bool
        key:
          nested_key: value        # one level of indentation
          - list item              # list of scalars
        key: [a, b, c]             # inline list

    Anything fancier (multiline strings, anchors, flow maps with objects)
    is rejected with ``SkillError``. Skill authors must keep frontmatter
    simple — heavy schemas should be inlined as JSON in a single-line
    ``output_schema: { ... }`` declaration.
    """
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[Any] | None = None
    current_obj: dict[str, Any] | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0:
            current_list = None
            current_obj = None
            current_key = None
            if ":" not in stripped:
                raise SkillError(f"frontmatter line missing colon: {stripped!r}")
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if not rest:
                # Either nested object or nested list — decided by next line.
                result[key] = {}
                current_key = key
                current_list = None
                current_obj = result[key]
            elif rest.startswith("[") and rest.endswith("]"):
                # Inline list
                inner = rest[1:-1].strip()
                items = [_coerce(p.strip()) for p in inner.split(",") if p.strip()]
                result[key] = items
            elif rest.startswith("{"):
                # Inline JSON (allows output_schema in one line)
                try:
                    result[key] = json.loads(rest)
                except json.JSONDecodeError as exc:
                    raise SkillError(
                        f"frontmatter key {key!r}: invalid inline JSON ({exc})"
                    ) from exc
            else:
                result[key] = _coerce(rest)
        else:
            # Indented continuation — either dict child or list child.
            if current_key is None:
                raise SkillError(f"unexpected indent at: {stripped!r}")
            if stripped.startswith("- "):
                if not isinstance(result[current_key], list):
                    if isinstance(result[current_key], dict) and not result[current_key]:
                        result[current_key] = []
                    else:
                        raise SkillError(
                            f"key {current_key!r} contains both list and dict children"
                        )
                result[current_key].append(_coerce(stripped[2:].strip()))
            else:
                if ":" not in stripped:
                    raise SkillError(f"nested line missing colon: {stripped!r}")
                k, _, v = stripped.partition(":")
                if not isinstance(result[current_key], dict):
                    raise SkillError(
                        f"key {current_key!r} cannot mix list and dict children"
                    )
                result[current_key][k.strip()] = _coerce(v.strip())
    return result


def _coerce(value: str) -> Any:
    if value == "":
        return ""
    lower = value.lower()
    if lower in ("true", "yes"):
        return True
    if lower in ("false", "no"):
        return False
    if lower in ("null", "none", "~"):
        return None
    # Strip quotes
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    # Number
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def load_skill(name: str, *, force_reload: bool = False) -> Skill:
    """Load and parse a skill from ``SKILLS_DIR/<name>.md``."""
    if not force_reload and name in _SKILL_CACHE:
        return _SKILL_CACHE[name]

    path = SKILLS_DIR / f"{name}.md"
    if not path.exists():
        raise SkillError(f"skill file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    match = _FRONTMATTER_RE.match(raw)
    if not match:
        raise SkillError(f"skill {name!r} missing YAML frontmatter")
    fm = _parse_yaml_lite(match.group("fm"))
    body = match.group("body").strip()
    if not body:
        raise SkillError(f"skill {name!r} has empty body")

    schema = fm.get("output_schema")
    if not isinstance(schema, dict):
        raise SkillError(
            f"skill {name!r}: output_schema must be an inline JSON object"
        )

    skill = Skill(
        name=name,
        description=str(fm.get("description", "")),
        system_prompt=body,
        output_schema=schema,
        model=str(fm.get("model", "") or ""),
        max_tokens=int(fm.get("max_tokens", DEFAULT_MAX_TOKENS) or DEFAULT_MAX_TOKENS),
        temperature=float(
            fm.get("temperature", DEFAULT_TEMPERATURE) or DEFAULT_TEMPERATURE
        ),
        triggers=tuple(fm.get("triggers", []) or ()),
        raw_frontmatter=fm,
    )
    _SKILL_CACHE[name] = skill
    return skill


# ── Cache ─────────────────────────────────────────────────────────────


def _cache_key(skill: Skill, inputs: dict[str, Any]) -> str:
    payload = json.dumps(inputs, sort_keys=True, ensure_ascii=False, default=str)
    h = hashlib.blake2b(digest_size=16)
    h.update(skill.fingerprint().encode())
    h.update(payload.encode())
    return h.hexdigest()


def _cache_path(key: str) -> Path:
    return CACHE_DIR / f"{key}.json"


def _cache_get(skill: Skill, inputs: dict[str, Any]) -> dict[str, Any] | None:
    path = _cache_path(_cache_key(skill, inputs))
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    recorded = float(data.get("_recorded_at", 0))
    if time.time() - recorded > CACHE_TTL_SECONDS:
        return None
    return data.get("payload")


def _cache_put(skill: Skill, inputs: dict[str, Any], output: dict[str, Any]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    path = _cache_path(_cache_key(skill, inputs))
    try:
        path.write_text(
            json.dumps(
                {"_recorded_at": time.time(), "payload": output},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        log.debug("skill cache write failed: %s", exc)


# ── Budget ────────────────────────────────────────────────────────────


@dataclass
class SkillBudget:
    """Track and limit LLM calls per scan to control cost/rate-limit risk."""

    limit: int
    used: int = 0

    def consume(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


# ── Execution ─────────────────────────────────────────────────────────


_JSON_BLOB_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first balanced JSON object out of a possibly noisy response.

    LLM responses sometimes wrap JSON in markdown fences or commentary. We
    are permissive: strip code fences, find the first ``{...}`` block, and
    parse it. Anything else raises ``SkillError``.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    match = _JSON_BLOB_RE.search(cleaned)
    if not match:
        raise SkillError(f"no JSON object in response: {text[:200]!r}")
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise SkillError(f"invalid JSON in response: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SkillError("skill response was JSON but not an object")
    return parsed


def _validate_against_schema(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    """Cheap JSONSchema-ish validation: required keys + type tags.

    We don't pull in jsonschema; a full validator is overkill for our
    structured outputs and the runtime budget loss would matter when
    skills run inside the scan pipeline.
    """
    required = schema.get("required", [])
    if required:
        missing = [k for k in required if k not in payload]
        if missing:
            raise SkillError(f"skill output missing keys: {missing}")
    properties = schema.get("properties") or {}
    for key, spec in properties.items():
        if key not in payload:
            continue
        expected = spec.get("type") if isinstance(spec, dict) else None
        if not expected:
            continue
        value = payload[key]
        type_ok = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "array": isinstance(value, list),
            "object": isinstance(value, dict),
            "null": value is None,
        }.get(expected, True)
        if not type_ok:
            raise SkillError(
                f"skill output key {key!r} expected {expected}, got {type(value).__name__}"
            )


def _default_backend() -> Backend:
    return HttpBackend(
        DEFAULT_HTTP_URL,
        model=DEFAULT_HTTP_MODEL,
        api_key=DEFAULT_HTTP_API_KEY,
        timeout=DEFAULT_HTTP_TIMEOUT,
    )


def run_skill(
    name: str,
    inputs: dict[str, Any],
    *,
    backend: Backend | None = None,
    budget: SkillBudget | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Execute a skill and return its validated JSON output.

    Raises ``SkillError`` for any unrecoverable failure (skill missing,
    schema mismatch, LLM unreachable, budget exhausted). Callers should
    handle this gracefully — skills are meant to *augment* deterministic
    decisions, never replace them.
    """
    skill = load_skill(name)
    if use_cache:
        cached = _cache_get(skill, inputs)
        if cached is not None:
            log.debug("skill %s served from cache", name)
            return cached
    if budget is not None and not budget.consume():
        raise SkillError(f"LLM budget exhausted before running skill {name!r}")
    if backend is None:
        try:
            backend = _default_backend()
        except LLMUnavailable as exc:
            raise SkillError(f"no LLM backend available: {exc}") from exc

    user_prompt = json.dumps(inputs, ensure_ascii=False, indent=2, default=str)
    try:
        raw = backend.complete(
            skill.system_prompt,
            user_prompt,
            max_tokens=skill.max_tokens,
            temperature=skill.temperature,
        )
    except LLMUnavailable as exc:
        raise SkillError(f"backend failed for skill {name!r}: {exc}") from exc

    parsed = _extract_json_object(raw)
    _validate_against_schema(parsed, skill.output_schema)
    if use_cache:
        _cache_put(skill, inputs, parsed)
    return parsed


def clear_cache(memory_only: bool = False) -> None:
    """Drop the in-memory skill cache (and optionally the disk cache too)."""
    _SKILL_CACHE.clear()
    if memory_only:
        return
    try:
        for p in CACHE_DIR.glob("*.json"):
            p.unlink(missing_ok=True)
    except OSError as exc:
        log.debug("clear_cache failed: %s", exc)
