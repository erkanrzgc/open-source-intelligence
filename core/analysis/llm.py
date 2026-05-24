"""Local LLM analyzer built on llama-cpp-python + GGUF models.

Design notes
------------
- llama_cpp is an OPTIONAL dependency. Import is lazy and wrapped in a
  ``LLMUnavailable`` error so the rest of the framework runs fine without it.
- The analyzer talks to a ``Backend`` Protocol, not llama_cpp directly, so
  tests can inject a stub that returns a canned JSON string without needing
  a 5GB GGUF file.
- Model defaults target Cisco Foundation-Sec-8B Q5_K_M — ~5.7GB on disk, fits
  a single RTX 5060 8GB at ``n_gpu_layers=-1``. Override via env vars.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from core.analysis.prompts import SYSTEM_PROMPT, build_user_prompt

log = logging.getLogger(__name__)


DEFAULT_REPO_ID = os.environ.get(
    "CYBERM4FIA_LLM_REPO",
    "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF",
)
DEFAULT_MODEL_FILE = os.environ.get(
    "CYBERM4FIA_LLM_FILE",
    "foundation-sec-1.1-8b-instruct-q4_k_m.gguf",
)
DEFAULT_CACHE_DIR = Path(
    os.environ.get(
        "CYBERM4FIA_MODEL_CACHE",
        str(Path.home() / ".cache" / "cyberm4fia" / "models"),
    )
)

DEFAULT_CTX = int(os.environ.get("CYBERM4FIA_LLM_CTX", "4096"))
DEFAULT_MAX_TOKENS = int(os.environ.get("CYBERM4FIA_LLM_MAX_TOKENS", "768"))
DEFAULT_TEMPERATURE = float(os.environ.get("CYBERM4FIA_LLM_TEMPERATURE", "0.2"))
DEFAULT_GPU_LAYERS = int(os.environ.get("CYBERM4FIA_LLM_GPU_LAYERS", "-1"))

DEFAULT_BACKEND = os.environ.get("CYBERM4FIA_LLM_BACKEND", "http").lower()
DEFAULT_HTTP_URL = os.environ.get(
    "CYBERM4FIA_LLM_URL",
    "https://integrate.api.nvidia.com/v1/chat/completions",
)
DEFAULT_HTTP_MODEL = os.environ.get(
    "CYBERM4FIA_LLM_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct"
)
DEFAULT_HTTP_API_KEY = os.environ.get("CYBERM4FIA_LLM_API_KEY", "")
DEFAULT_HTTP_TIMEOUT = float(os.environ.get("CYBERM4FIA_LLM_TIMEOUT", "120"))


class LLMUnavailable(RuntimeError):
    """Raised when the local LLM cannot be loaded or invoked."""


@dataclass
class AIReport:
    identity_summary: str = ""
    strong_linkages: list[str] = field(default_factory=list)
    exposures: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    confidence: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Backend(Protocol):
    def complete(self, system: str, user: str, *, max_tokens: int, temperature: float) -> str: ...


class LlamaCppBackend:
    """Thin wrapper around llama_cpp.Llama, loaded lazily."""

    def __init__(self, model_path: Path, *, n_ctx: int, n_gpu_layers: int) -> None:
        try:
            from llama_cpp import Llama  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover — exercised only with the extra installed
            raise LLMUnavailable(
                "llama-cpp-python is not installed. Install with: pip install 'cyberm4fia-osint[ai]'"
            ) from exc
        if not model_path.exists():
            raise LLMUnavailable(
                f"GGUF model not found at {model_path}. "
                "Run: python -m core.analysis.download"
            )
        log.info("loading llm model %s (ctx=%d, gpu_layers=%d)", model_path, n_ctx, n_gpu_layers)
        self._llm = Llama(
            model_path=str(model_path),
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            verbose=False,
        )

    def complete(self, system: str, user: str, *, max_tokens: int, temperature: float) -> str:
        result = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        choices = result.get("choices") or []
        if not choices:
            raise LLMUnavailable("LLM returned no choices")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if not isinstance(content, str):
            raise LLMUnavailable("LLM returned non-string content")
        return content


class HttpBackend:
    """OpenAI-compatible HTTP backend (NVIDIA NIM, OpenAI, Groq, Ollama, llama.cpp server, vLLM)."""

    def __init__(
        self,
        url: str,
        *,
        model: str = "",
        api_key: str = "",
        timeout: float = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        self._url = url
        self._model = model
        self._api_key = api_key
        self._timeout = timeout

    def complete(self, system: str, user: str, *, max_tokens: int, temperature: float) -> str:
        payload: dict[str, Any] = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if self._model:
            payload["model"] = self._model
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(self._url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                body = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise LLMUnavailable(f"HTTP LLM request failed: {exc}") from exc
        try:
            result = json.loads(body)
        except json.JSONDecodeError as exc:
            raise LLMUnavailable(f"HTTP LLM returned non-JSON body: {exc}") from exc
        choices = result.get("choices") or []
        if not choices:
            raise LLMUnavailable("HTTP LLM returned no choices")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if not isinstance(content, str):
            raise LLMUnavailable("HTTP LLM returned non-string content")
        return content


class LLMAnalyzer:
    def __init__(
        self,
        backend: Backend | None = None,
        *,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> None:
        self._backend = backend
        self._max_tokens = max_tokens
        self._temperature = temperature

    @classmethod
    def from_env(cls) -> LLMAnalyzer:
        backend_kind = DEFAULT_BACKEND
        backend: Backend
        if backend_kind in ("http", "openai", "nim", "nvidia"):
            backend = HttpBackend(
                DEFAULT_HTTP_URL,
                model=DEFAULT_HTTP_MODEL,
                api_key=DEFAULT_HTTP_API_KEY,
                timeout=DEFAULT_HTTP_TIMEOUT,
            )
        elif backend_kind in ("llama", "llama_cpp", "llamacpp", "local"):
            model_path = DEFAULT_CACHE_DIR / DEFAULT_MODEL_FILE
            backend = LlamaCppBackend(
                model_path,
                n_ctx=DEFAULT_CTX,
                n_gpu_layers=DEFAULT_GPU_LAYERS,
            )
        else:
            raise LLMUnavailable(
                f"Unknown CYBERM4FIA_LLM_BACKEND={backend_kind!r} "
                "(expected one of: http, llama_cpp)"
            )
        return cls(backend)

    def analyze(self, scan_payload: dict[str, Any]) -> AIReport:
        if self._backend is None:
            raise LLMUnavailable("LLMAnalyzer has no backend — call from_env() or inject one")
        user_prompt = build_user_prompt(scan_payload)
        raw = self._backend.complete(
            SYSTEM_PROMPT,
            user_prompt,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        return parse_report(raw)


_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def parse_report(raw: str) -> AIReport:
    """Parse an LLM response into an AIReport, tolerating fenced code blocks."""
    text = raw.strip()
    match = _JSON_FENCE.search(text)
    if match:
        text = match.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"LLM output was not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LLMUnavailable("LLM output was not a JSON object")

    def _str_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(v) for v in value if v is not None]

    confidence = data.get("confidence", 0)
    try:
        confidence_int = int(confidence)
    except (TypeError, ValueError):
        confidence_int = 0
    confidence_int = max(0, min(100, confidence_int))

    return AIReport(
        identity_summary=str(data.get("identity_summary", "") or ""),
        strong_linkages=_str_list(data.get("strong_linkages")),
        exposures=_str_list(data.get("exposures")),
        next_steps=_str_list(data.get("next_steps")),
        confidence=confidence_int,
    )
