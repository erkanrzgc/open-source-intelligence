---
name: analysis
description: LLM-backed analyst — single monolithic exec-summary today; multi-skill registry under skills/.
inputs:
  scan_payload: dict (ScanResult.to_dict() output)
  per-skill: see skills/<skill_name>.md frontmatter
outputs:
  AIReport: {identity_summary, strong_linkages, exposures, next_steps, confidence}
  per-skill: structured JSON validated against skills/<name>.md output_schema
triggers:
  - --ai-summary / --ai-analysis CLI flags → LLMAnalyzer.analyze()
  - --ai-skills CLI flag → engine phases call run_skill()
  - cfg.ai_skills in ScanConfig
dependencies:
  - core.http_client (NOT directly — HttpBackend uses urllib)
  - llama-cpp-python (optional, for local GGUF backend)
  - CYBERM4FIA_LLM_* env vars
ai_required: true
---

## Components

```
core/analysis/
├── llm.py            # LLMAnalyzer, HttpBackend, LlamaCppBackend, parse_report
├── prompts.py        # SYSTEM_PROMPT for the legacy monolithic analyst path
├── download.py       # one-time GGUF model download helper
├── skill_loader.py   # YAML-frontmatter skill parser + cache + budget
└── skills/
    ├── handle_generator.md
    └── profile_validator.md
```

## Two paths

### 1. Monolithic exec summary (legacy)

`LLMAnalyzer.from_env()` builds a single backend and calls
`analyze(scan_payload)` which returns an `AIReport`. Used by
`main.py:_run_ai_analysis` and the `--ai-summary` flag. This path
predates the skill registry and should migrate to a
`skills/exec_summary.md` in a future change.

### 2. Skill registry (current)

```python
from core.analysis.skill_loader import run_skill, SkillBudget, SkillError

try:
    out = run_skill(
        "profile_validator",
        {"target": {...}, "profile": {...}},
        budget=SkillBudget(limit=cfg.ai_skill_budget),
    )
except SkillError as exc:
    log.debug("skill failed, falling back to deterministic: %s", exc)
```

Skills are markdown files with YAML frontmatter. The loader caches both
the parsed Skill object and the (skill, inputs)-keyed response.

## Backends

| Backend | When | Activation |
|---|---|---|
| HttpBackend | default | `CYBERM4FIA_LLM_BACKEND=http` (NVIDIA NIM, OpenAI, vLLM, llama.cpp server). `CYBERM4FIA_LLM_URL`, `CYBERM4FIA_LLM_MODEL`, `CYBERM4FIA_LLM_API_KEY`. |
| LlamaCppBackend | offline use | `CYBERM4FIA_LLM_BACKEND=llama_cpp`, GGUF in `~/.cache/cyberm4fia/models/`. |

## Failure modes

* `LLMUnavailable` raised when no backend / unreachable / non-JSON
  response. Callers MUST catch and fall back to deterministic logic.
* `SkillError` raised when the schema check fails — same handling.
* Cache write fails → in-memory only, no scan-time impact.
* Budget exhausted → `SkillError("LLM budget exhausted ...")`; calling
  phase should log and continue without LLM assist.

## Privacy

Every skill receives only the data the engine explicitly hands it.
There is no auto-dump of the full ScanResult to the LLM. When building
inputs for a new skill, include the minimum needed for the verdict.
