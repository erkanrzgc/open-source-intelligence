"""Runtime capability discovery for optional cyberm4fia features."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

from core import auth
from core.api import is_available as api_available
from core.config import ScanConfig
from core.reporter import pdf_available, xlsx_available
from modules.breach_check import breach_check_available, hibp_available
from modules.ghunt_lookup import CREDS_PATH as GHUNT_CREDS_PATH
from modules.ghunt_lookup import is_available as ghunt_available
from modules.holehe_check import is_available as holehe_available
from modules.holehe_check import module_count as holehe_module_count
from modules.photo_compare import imagehash_available
from modules.profile_extract import is_available as profile_extract_available
from modules.recon import filetype as filetype_detector
from modules.recon import gitleaks
from modules.stealth import obscura_fallback
from modules.stealth.playwright_fallback import AVAILABLE as PLAYWRIGHT_AVAILABLE
from modules.toutatis_lookup import is_available as toutatis_available


def _has_module(name: str) -> bool:
    # find_spec raises ModuleNotFoundError on a dotted name whose parent
    # package is missing (e.g. "dns.resolver" when dnspython is absent).
    # Treat that as "not installed" rather than bubbling the error.
    try:
        return importlib.util.find_spec(name) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def _env_enabled(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def _capability(
    *,
    available: bool,
    configured: bool = True,
    reason: str = "",
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "available": available,
        "configured": configured,
        "ready": bool(available and configured),
    }
    if reason:
        data["reason"] = reason
    if extras:
        data.update(extras)
    return data


def collect_capabilities() -> dict[str, dict[str, Any]]:
    """Return the current optional-feature readiness map."""
    holehe_ok = holehe_available()
    ghunt_installed = _has_module("ghunt")
    toutatis_ok = toutatis_available()
    toutatis_session = _env_enabled("IG_SESSION_ID")
    tor_transport = _has_module("aiohttp_socks")
    tor_control = _has_module("stem")
    shodan_key = _env_enabled("SHODAN_API_KEY")
    censys_ok = _env_enabled("CENSYS_API_ID") and _env_enabled("CENSYS_API_SECRET")
    fofa_ok = _env_enabled("FOFA_EMAIL") and _env_enabled("FOFA_KEY")
    zoomeye_ok = _env_enabled("ZOOMEYE_API_KEY")
    gitleaks_ok = gitleaks.is_available()
    llama_cpp_installed = _has_module("llama_cpp")
    llm_model_path = Path(
        os.environ.get(
            "CYBERM4FIA_MODEL_CACHE",
            str(Path.home() / ".cache" / "cyberm4fia" / "models"),
        )
    ) / os.environ.get(
        "CYBERM4FIA_LLM_FILE",
        "foundation-sec-1.1-8b-instruct-q4_k_m.gguf",
    )

    return {
        "api": _capability(
            available=api_available(),
            reason="" if api_available() else "fastapi/uvicorn extras are not installed",
        ),
        "auth_gate": _capability(
            available=True,
            configured=auth.is_auth_required(),
            reason="auth gate disabled" if not auth.is_auth_required() else "",
        ),
        "profile_extract": _capability(
            available=profile_extract_available(),
            reason=(
                "" if profile_extract_available()
                else "socid-extractor extra is not installed"
            ),
        ),
        "dns": _capability(
            available=_has_module("dns.resolver"),
            reason="" if _has_module("dns.resolver") else "dnspython extra is not installed",
        ),
        "whois": _capability(
            available=_has_module("whois"),
            reason="" if _has_module("whois") else "python-whois extra is not installed",
        ),
        "photo_hash": _capability(
            available=imagehash_available(),
            reason=(
                "" if imagehash_available()
                else "photo extras (Pillow + imagehash) are not installed"
            ),
        ),
        "breach_free": _capability(available=breach_check_available()),
        "breach_hibp": _capability(
            available=True,
            configured=hibp_available(),
            reason="HIBP_API_KEY is not configured" if not hibp_available() else "",
        ),
        "holehe": _capability(
            available=holehe_ok,
            reason="" if holehe_ok else "holehe extra is not installed",
            extras={"module_count": holehe_module_count() if holehe_ok else 0},
        ),
        "ghunt": _capability(
            available=ghunt_installed,
            configured=ghunt_available(),
            reason=(
                ""
                if ghunt_available()
                else (
                    f"credentials missing at {GHUNT_CREDS_PATH}"
                    if ghunt_installed
                    else "ghunt extra is not installed"
                )
            ),
            extras={"creds_path": str(GHUNT_CREDS_PATH)},
        ),
        "toutatis": _capability(
            available=toutatis_ok,
            configured=toutatis_session,
            reason=(
                ""
                if not toutatis_ok
                else (
                    ""
                    if toutatis_session
                    else "IG_SESSION_ID not set; public-only lookup mode"
                )
            ) if toutatis_ok else "toutatis extra is not installed",
        ),
        "playwright": _capability(
            available=PLAYWRIGHT_AVAILABLE,
            reason="" if PLAYWRIGHT_AVAILABLE else "playwright extra is not installed",
        ),
        "obscura": _capability(
            available=obscura_fallback.is_available(),
            reason=(
                ""
                if obscura_fallback.is_available()
                else "obscura binary not found; set CYBERM4FIA_OBSCURA_BIN or install obscura"
            ),
        ),
        "filetype_magika": _capability(
            available=filetype_detector.is_available(),
            reason="" if filetype_detector.is_available() else "magika extra is not installed",
        ),
        "gitleaks": _capability(
            available=gitleaks_ok,
            reason=(
                ""
                if gitleaks_ok
                else "gitleaks binary not found; set CYBERM4FIA_GITLEAKS_BIN or install gitleaks"
            ),
        ),
        "tor_transport": _capability(
            available=tor_transport,
            reason="" if tor_transport else "aiohttp-socks extra is not installed",
        ),
        "tor_control": _capability(
            available=tor_control,
            reason="" if tor_control else "stem extra is not installed",
        ),
        "passive_shodan": _capability(
            available=True,
            configured=shodan_key,
            reason="SHODAN_API_KEY not configured" if not shodan_key else "",
        ),
        "passive_censys": _capability(
            available=True,
            configured=censys_ok,
            reason=(
                "CENSYS_API_ID / CENSYS_API_SECRET not configured"
                if not censys_ok else ""
            ),
        ),
        "passive_fofa": _capability(
            available=True,
            configured=fofa_ok,
            reason="FOFA_EMAIL / FOFA_KEY not configured" if not fofa_ok else "",
        ),
        "passive_zoomeye": _capability(
            available=True,
            configured=zoomeye_ok,
            reason="ZOOMEYE_API_KEY not configured" if not zoomeye_ok else "",
        ),
        "report_pdf": _capability(
            available=pdf_available(),
            reason="" if pdf_available() else "reportlab extra is not installed",
        ),
        "report_xlsx": _capability(
            available=xlsx_available(),
            reason="" if xlsx_available() else "openpyxl extra is not installed",
        ),
        "llm_http": _capability(
            available=True,
            configured=_env_enabled("CYBERM4FIA_LLM_URL")
            or "CYBERM4FIA_LLM_URL" not in os.environ,
            reason="HTTP backend uses default local URL" if not _env_enabled("CYBERM4FIA_LLM_URL") else "",
        ),
        "llm_llama_cpp": _capability(
            available=llama_cpp_installed,
            configured=llm_model_path.exists(),
            reason=(
                ""
                if not llama_cpp_installed
                else (
                    ""
                    if llm_model_path.exists()
                    else f"model file missing at {llm_model_path}"
                )
            ) if llama_cpp_installed else "llama-cpp-python extra is not installed",
            extras={"model_path": str(llm_model_path)},
        ),
    }


def collect_scan_warnings(
    cfg: ScanConfig,
    *,
    capabilities: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Return operator-facing warnings for the selected scan config."""
    caps = capabilities or collect_capabilities()
    warnings: list[str] = []

    if cfg.breach and not caps["breach_hibp"]["configured"]:
        warnings.append(
            "HIBP_API_KEY not set; paid HIBP coverage is disabled and only the free XposedOrNot fallback will run."
        )
    if cfg.holehe and not caps["holehe"]["ready"]:
        warnings.append("Holehe is not available; email-to-site probes will be skipped.")
    if cfg.ghunt and not caps["ghunt"]["ready"]:
        warnings.append(
            "GHunt is not ready; install the extra and run `ghunt login` before using Google account enrichment."
        )
    if cfg.toutatis and not caps["toutatis"]["available"]:
        warnings.append("Toutatis is not available; Instagram enrichment will be skipped.")
    elif cfg.toutatis and caps["toutatis"]["available"] and not caps["toutatis"]["configured"]:
        warnings.append(
            "IG_SESSION_ID not set; Toutatis will run in public-only mode with reduced Instagram detail."
        )
    if cfg.browser_backend == "obscura" and not caps["obscura"]["ready"]:
        warnings.append("Obscura is not available; browser-rendered fallback checks will be skipped.")
    elif cfg.playwright and not caps["playwright"]["ready"]:
        warnings.append("Playwright is not available; browser-rendered fallback checks will be skipped.")
    if cfg.harvest_doc_urls and not caps["filetype_magika"]["ready"]:
        warnings.append("Magika is not available; document harvesting will rely on magic-byte detection only.")
    if cfg.gitleaks_paths and not caps["gitleaks"]["ready"]:
        warnings.append("Gitleaks is not available; local secret scans will be skipped.")
    if cfg.tor and not caps["tor_transport"]["ready"]:
        warnings.append("Tor/SOCKS transport is not available; install `aiohttp-socks` before using proxy routing.")
    if cfg.new_circuit_every and cfg.tor and not caps["tor_control"]["ready"]:
        warnings.append("Tor circuit rotation requires the `stem` extra and a reachable Tor control port.")
    if cfg.passive:
        passive_ready = any(
            caps[name]["configured"]
            for name in (
                "passive_shodan",
                "passive_censys",
                "passive_fofa",
                "passive_zoomeye",
            )
        )
        if not passive_ready:
            warnings.append(
                "No passive-provider API credentials are configured; only free passive sources will contribute data."
            )
    return warnings
