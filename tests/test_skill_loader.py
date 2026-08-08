"""Tests for core.analysis.skill_loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.analysis.skill_loader import (
    Skill,
    SkillBudget,
    SkillError,
    _extract_json_object,
    _parse_yaml_lite,
    _validate_against_schema,
    clear_cache,
    load_skill,
    run_skill,
)


class _StubBackend:
    def __init__(self, response: str):
        self.response = response
        self.calls: list[tuple[str, str]] = []

    async def complete(self, system, user, *, max_tokens, temperature):
        self.calls.append((system, user))
        return self.response


def test_parse_yaml_lite_basic():
    text = """
name: handle_generator
description: short description
max_tokens: 600
temperature: 0.3
triggers:
  - cfg.full_name
  - second trigger
"""
    parsed = _parse_yaml_lite(text)
    assert parsed["name"] == "handle_generator"
    assert parsed["max_tokens"] == 600
    assert parsed["temperature"] == 0.3
    assert parsed["triggers"] == ["cfg.full_name", "second trigger"]


def test_parse_yaml_lite_inline_json_schema():
    text = 'output_schema: {"type": "object", "required": ["x"]}'
    parsed = _parse_yaml_lite(text)
    assert parsed["output_schema"]["type"] == "object"
    assert parsed["output_schema"]["required"] == ["x"]


def test_load_skill_returns_valid_skill():
    # Loads the actual handle_generator skill we ship in repo.
    skill = load_skill("handle_generator")
    assert isinstance(skill, Skill)
    assert skill.name == "handle_generator"
    assert "JSON" in skill.system_prompt
    assert skill.output_schema["type"] == "object"


def test_load_skill_missing_raises():
    with pytest.raises(SkillError):
        load_skill("nonexistent_skill_xyz_123")


def test_extract_json_object_from_fenced():
    text = '```json\n{"a": 1, "b": [2, 3]}\n```'
    assert _extract_json_object(text) == {"a": 1, "b": [2, 3]}


def test_extract_json_object_from_noisy():
    text = 'Here is the result: {"score": 0.9, "ok": true} and that is all.'
    assert _extract_json_object(text) == {"score": 0.9, "ok": True}


def test_extract_json_object_raises_on_garbage():
    with pytest.raises(SkillError):
        _extract_json_object("no json here just words")


def test_validate_schema_catches_missing_required():
    schema = {"required": ["a", "b"], "properties": {"a": {"type": "string"}}}
    with pytest.raises(SkillError):
        _validate_against_schema({"a": "x"}, schema)


def test_validate_schema_catches_wrong_type():
    schema = {"required": ["count"], "properties": {"count": {"type": "integer"}}}
    with pytest.raises(SkillError):
        _validate_against_schema({"count": "not an int"}, schema)


def test_validate_schema_accepts_valid():
    schema = {
        "required": ["count", "items"],
        "properties": {
            "count": {"type": "integer"},
            "items": {"type": "array"},
        },
    }
    # Should not raise
    _validate_against_schema({"count": 3, "items": ["a", "b", "c"]}, schema)


def test_skill_budget_consumes_until_exhausted():
    b = SkillBudget(limit=2)
    assert b.consume() is True
    assert b.consume() is True
    assert b.consume() is False
    assert b.remaining == 0


async def test_run_skill_with_stub_backend(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "core.analysis.skill_loader.CACHE_DIR", tmp_path
    )
    clear_cache(memory_only=True)
    backend = _StubBackend(
        '{"candidates":[{"handle":"alice","score":0.9,"rationale":"first-only"}]}'
    )
    out = await run_skill(
        "handle_generator",
        {"full_name": "Alice"},
        backend=backend,
        use_cache=False,
    )
    assert "candidates" in out
    assert out["candidates"][0]["handle"] == "alice"
    assert len(backend.calls) == 1


async def test_run_skill_cache_hits_skip_backend(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "core.analysis.skill_loader.CACHE_DIR", tmp_path
    )
    clear_cache(memory_only=True)
    backend = _StubBackend(
        '{"candidates":[{"handle":"bob","score":0.8,"rationale":"first-only"}]}'
    )
    inputs = {"full_name": "Bob"}
    out1 = await run_skill("handle_generator", inputs, backend=backend, use_cache=True)
    out2 = await run_skill("handle_generator", inputs, backend=backend, use_cache=True)
    assert out1 == out2
    # Backend called only once even though run_skill was invoked twice.
    assert len(backend.calls) == 1


async def test_run_skill_budget_exhaustion_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "core.analysis.skill_loader.CACHE_DIR", tmp_path
    )
    clear_cache(memory_only=True)
    backend = _StubBackend('{"candidates":[]}')
    budget = SkillBudget(limit=1)
    await run_skill(
        "handle_generator",
        {"full_name": "Alice"},
        backend=backend,
        budget=budget,
        use_cache=False,
    )
    with pytest.raises(SkillError, match="budget exhausted"):
        await run_skill(
            "handle_generator",
            {"full_name": "Charlie"},
            backend=backend,
            budget=budget,
            use_cache=False,
        )


async def test_run_skill_schema_violation_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "core.analysis.skill_loader.CACHE_DIR", tmp_path
    )
    clear_cache(memory_only=True)
    backend = _StubBackend('{"unrelated_key": 1}')
    with pytest.raises(SkillError, match="missing keys"):
        await run_skill(
            "handle_generator",
            {"full_name": "Alice"},
            backend=backend,
            use_cache=False,
        )


def test_profile_validator_loads():
    skill = load_skill("profile_validator")
    assert skill.name == "profile_validator"
    assert "match_score" in skill.output_schema.get("required", [])
