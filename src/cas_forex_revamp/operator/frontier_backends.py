"""Multi-provider Frontier AI model registry, HTTPS JSON-schema & Decisions API transports.

Prioritizes 8 frontier cloud models strictly ahead of #9 Qwen 3 0.6B (offline air-gapped fallback):
  1. claude-fable-5.2    -- Claude Fable 5.2 (Anthropic)
  2. claude-fable        -- Claude Fable (Anthropic)
  3. claude-5.5          -- Claude 5.5 (Anthropic)
  4. gemini-decision-1   -- Gemini Decision 1 (Google Decisions API, 150-250ms NAS100/US30 & Fast Scout)
  5. gemini-carbon       -- Gemini Carbon (Google Gemini)
  6. gemini-argon        -- Gemini Argon (Google Gemini)
  7. openai-astra        -- OpenAI Astra (OpenAI)
  8. deepseek-flash-1017 -- DeepSeek Flash 1017 (DeepSeek)
  9. qwen3:0.6b          -- Qwen 3 0.6B (Local Offline Air-Gapped Fallback ONLY)

Every backend implements :class:`cas_forex_revamp.operator.model.ModelBackend`, preserves
``SYSTEM_POLICY`` untouched, and routes outputs through ``ActualModelDecisionAdapter`` ->
``ForexMetaValveGate``. Import/construction performs no network or disk I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import ipaddress
import json
import re
import socket
import ssl
from threading import Lock
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest, decimal_text
from cas_forex_revamp.contracts.primitives import integer, utc_time

from .decisions import OperatorUnavailable
from .model import (
    InferenceReply,
    ModelBackend,
    ModelInvocation,
    ModelSpecification,
    OUTPUT_SCHEMA_ID,
    SYSTEM_POLICY,
)

ENV_AI_MODEL = "CAS_FOREX_AI_MODEL"
ENV_GEMINI_DECISION_SCOUT = "CAS_FOREX_GEMINI_DECISION_SCOUT"
ENV_DECISION_MIN_PROBABILITY = "CAS_FOREX_DECISION_MIN_PROBABILITY"
ENV_THINKING_DEPTH = "CAS_FOREX_THINKING_DEPTH"
VALID_THINKING_DEPTHS = ("AUTO", "LOW", "MEDIUM", "HIGH")

ENV_ANTHROPIC_API_KEY = "CAS_FOREX_ANTHROPIC_API_KEY"
ENV_GEMINI_API_KEY = "CAS_FOREX_GEMINI_API_KEY"
ENV_OPENAI_API_KEY = "CAS_FOREX_OPENAI_API_KEY"
ENV_DEEPSEEK_API_KEY = "CAS_FOREX_DEEPSEEK_API_KEY"
ENV_OLLAMA_FALLBACK_ENABLED = "CAS_FOREX_OLLAMA_FALLBACK_ENABLED"

ENV_ANTHROPIC_FABLE_5_2_MODEL_ID = "CAS_FOREX_ANTHROPIC_FABLE_5_2_MODEL_ID"
ENV_ANTHROPIC_FABLE_MODEL_ID = "CAS_FOREX_ANTHROPIC_FABLE_MODEL_ID"
ENV_ANTHROPIC_5_5_MODEL_ID = "CAS_FOREX_ANTHROPIC_5_5_MODEL_ID"
ENV_GEMINI_DECISION_1_MODEL_ID = "CAS_FOREX_GEMINI_DECISION_1_MODEL_ID"
ENV_GEMINI_CARBON_MODEL_ID = "CAS_FOREX_GEMINI_CARBON_MODEL_ID"
ENV_GEMINI_ARGON_MODEL_ID = "CAS_FOREX_GEMINI_ARGON_MODEL_ID"
ENV_OPENAI_ASTRA_MODEL_ID = "CAS_FOREX_OPENAI_ASTRA_MODEL_ID"
ENV_DEEPSEEK_FLASH_MODEL_ID = "CAS_FOREX_DEEPSEEK_FLASH_MODEL_ID"
ENV_OLLAMA_FALLBACK_MODEL_ID = "CAS_FOREX_OLLAMA_FALLBACK_MODEL_ID"

ALLOWED_FRONTIER_HOSTS = frozenset({
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.openai.com",
    "api.deepseek.com",
})
OLLAMA_LOOPBACK_ENDPOINT = "http://127.0.0.1:11434/api/chat"
MAX_PROVIDER_WIRE_BYTES = 262_144
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 25.0
DEFAULT_MIN_DECISION_PROBABILITY = Decimal("0.60")
_MODEL_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SENSITIVE_KEY_WORDS = frozenset({"password", "passwd", "token", "secret", "login", "credential", "api_key"})


class FrontierTransportError(OperatorUnavailable):
    """Raised when a frontier or offline fallback AI request fails closed."""


class FrontierConfigurationError(ContractError):
    """Raised on invalid model selection, host allowlist breach, or malformed provider settings."""


class _RedactedSecret:
    """In-memory credential holder whose repr/str never reveal its value."""

    __slots__ = ("_raw",)

    def __init__(self, raw: str) -> None:
        if not isinstance(raw, str) or not raw.strip() or any(ch in raw for ch in ("\r", "\n", "\x00")):
            raise FrontierConfigurationError("API credential must be a clean non-empty single-line string")
        self._raw = raw.strip()

    def reveal_for_header(self) -> str:
        return self._raw

    def __repr__(self) -> str:
        return "[REDACTED]"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __format__(self, _spec: str) -> str:
        return "[REDACTED]"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects on outbound AI API calls (anti-SSRF / key exfiltration guard)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        raise FrontierTransportError(f"HTTP redirect {code} refused for outbound AI request")

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        raise FrontierTransportError(f"HTTP redirect {code} refused for outbound AI request")

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


@dataclass(frozen=True, slots=True)
class FrontierModelCatalogEntry:
    rank: int
    model_id: str
    display_name: str
    provider: str
    provider_label: str
    endpoint_template: str
    allowed_host: str
    credential_env: str
    slug_env: str
    default_slug: str
    tier: str
    is_fallback: bool
    reasoning_policy: str
    latency_target_ms: int
    role_summary: str


FRONTIER_MODEL_CATALOG: tuple[FrontierModelCatalogEntry, ...] = (
    FrontierModelCatalogEntry(
        rank=1,
        model_id="claude-fable-5.2",
        display_name="Claude Fable 5.2",
        provider="anthropic",
        provider_label="Anthropic",
        endpoint_template="https://api.anthropic.com/v1/messages",
        allowed_host="api.anthropic.com",
        credential_env=ENV_ANTHROPIC_API_KEY,
        slug_env=ENV_ANTHROPIC_FABLE_5_2_MODEL_ID,
        default_slug="claude-fable-5-2",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=700,
        role_summary="Flagship Claude Fable 5.2 strategist (#1 priority ahead of Qwen fallback)",
    ),
    FrontierModelCatalogEntry(
        rank=2,
        model_id="claude-fable",
        display_name="Claude Fable",
        provider="anthropic",
        provider_label="Anthropic",
        endpoint_template="https://api.anthropic.com/v1/messages",
        allowed_host="api.anthropic.com",
        credential_env=ENV_ANTHROPIC_API_KEY,
        slug_env=ENV_ANTHROPIC_FABLE_MODEL_ID,
        default_slug="claude-fable-5",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=750,
        role_summary="Anthropic Claude Fable risk strategist (#2 priority ahead of Qwen fallback)",
    ),
    FrontierModelCatalogEntry(
        rank=3,
        model_id="claude-5.5",
        display_name="Claude 5.5",
        provider="anthropic",
        provider_label="Anthropic",
        endpoint_template="https://api.anthropic.com/v1/messages",
        allowed_host="api.anthropic.com",
        credential_env=ENV_ANTHROPIC_API_KEY,
        slug_env=ENV_ANTHROPIC_5_5_MODEL_ID,
        default_slug="claude-opus-5-5",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=800,
        role_summary="Anthropic 5.5 frontier analyst (#3 priority ahead of Qwen fallback)",
    ),
    FrontierModelCatalogEntry(
        rank=4,
        model_id="gemini-decision-1",
        display_name="Gemini Decision 1",
        provider="gemini_decision",
        provider_label="Google Gemini Decisions API",
        endpoint_template="https://generativelanguage.googleapis.com/v1beta/models/{slug}:decide",
        allowed_host="generativelanguage.googleapis.com",
        credential_env=ENV_GEMINI_API_KEY,
        slug_env=ENV_GEMINI_DECISION_1_MODEL_ID,
        default_slug="gemini-decision-1",
        tier="FRONTIER_FAST_DECISION",
        is_fallback=False,
        reasoning_policy="zero-output-token-decision",
        latency_target_ms=200,
        role_summary="150-250ms zero-output-token NAS100/US30 burst scalper & 18-market Fast Scout (#4)",
    ),
    FrontierModelCatalogEntry(
        rank=5,
        model_id="gemini-carbon",
        display_name="Gemini Carbon",
        provider="gemini",
        provider_label="Google Gemini",
        endpoint_template="https://generativelanguage.googleapis.com/v1beta/models/{slug}:generateContent",
        allowed_host="generativelanguage.googleapis.com",
        credential_env=ENV_GEMINI_API_KEY,
        slug_env=ENV_GEMINI_CARBON_MODEL_ID,
        default_slug="gemini-4-carbon",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=650,
        role_summary="Google Gemini Carbon fast quantitative reasoner (#5 priority)",
    ),
    FrontierModelCatalogEntry(
        rank=6,
        model_id="gemini-argon",
        display_name="Gemini Argon",
        provider="gemini",
        provider_label="Google Gemini",
        endpoint_template="https://generativelanguage.googleapis.com/v1beta/models/{slug}:generateContent",
        allowed_host="generativelanguage.googleapis.com",
        credential_env=ENV_GEMINI_API_KEY,
        slug_env=ENV_GEMINI_ARGON_MODEL_ID,
        default_slug="gemini-4-argon",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=650,
        role_summary="Google Gemini Argon precision execution model (#6 priority)",
    ),
    FrontierModelCatalogEntry(
        rank=7,
        model_id="openai-astra",
        display_name="OpenAI Astra",
        provider="openai",
        provider_label="OpenAI",
        endpoint_template="https://api.openai.com/v1/chat/completions",
        allowed_host="api.openai.com",
        credential_env=ENV_OPENAI_API_KEY,
        slug_env=ENV_OPENAI_ASTRA_MODEL_ID,
        default_slug="gpt-5.5-2026-04-23",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=700,
        role_summary="OpenAI Astra frontier tactical synthesizer (#7 priority)",
    ),
    FrontierModelCatalogEntry(
        rank=8,
        model_id="deepseek-flash-1017",
        display_name="DeepSeek Flash 1017",
        provider="deepseek",
        provider_label="DeepSeek",
        endpoint_template="https://api.deepseek.com/chat/completions",
        allowed_host="api.deepseek.com",
        credential_env=ENV_DEEPSEEK_API_KEY,
        slug_env=ENV_DEEPSEEK_FLASH_MODEL_ID,
        default_slug="deepseek-flash",
        tier="FRONTIER",
        is_fallback=False,
        reasoning_policy="structured-risk-first",
        latency_target_ms=550,
        role_summary="DeepSeek Flash 1017 rapid signal evaluator (#8 priority)",
    ),
    FrontierModelCatalogEntry(
        rank=9,
        model_id="qwen3:0.6b",
        display_name="Qwen 3 0.6B (Local Offline Air-Gapped Fallback ONLY)",
        provider="ollama",
        provider_label="Ollama v0.40.2 (Offline Fallback)",
        endpoint_template=OLLAMA_LOOPBACK_ENDPOINT,
        allowed_host="127.0.0.1",
        credential_env="",
        slug_env=ENV_OLLAMA_FALLBACK_MODEL_ID,
        default_slug="qwen3:0.6b",
        tier="OFFLINE_FALLBACK",
        is_fallback=True,
        reasoning_policy="disabled",
        latency_target_ms=1500,
        role_summary="Last-resort local CPU fallback when offline/air-gapped ONLY (#9 bottom rank)",
    ),
)

_CATALOG_BY_ID: dict[str, FrontierModelCatalogEntry] = {e.model_id: e for e in FRONTIER_MODEL_CATALOG}


def _truthy(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().lower() in ("1", "true", "yes", "on")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ContractError("duplicate JSON key in AI provider payload")
        out[k] = v
    return out


def _no_constant(value: str) -> None:
    raise ContractError(f"nonfinite JSON constant in AI provider payload: {value}")


def _decode_json_dict(raw: bytes, *, max_bytes: int = MAX_PROVIDER_WIRE_BYTES) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= max_bytes:
        raise FrontierTransportError("AI provider response empty or exceeded wire byte cap")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise FrontierTransportError("AI provider returned malformed UTF-8 JSON") from exc
    if type(doc) is not dict:
        raise FrontierTransportError("AI provider response must decode to a JSON object")
    return doc


def _validate_slug(raw_slug: str, field: str) -> str:
    cleaned = raw_slug.strip()
    if (
        not _MODEL_SLUG_RE.fullmatch(cleaned)
        or ".." in cleaned
        or "?" in cleaned
        or "#" in cleaned
        or "@" in cleaned
    ):
        raise FrontierConfigurationError(f"invalid {field} slug")
    return cleaned


def _validate_frontier_https_url(url: str, *, expected_host: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise FrontierConfigurationError(f"frontier AI endpoint must use https:// (got {parsed.scheme!r})")
    if parsed.username is not None or parsed.password is not None:
        raise FrontierConfigurationError("frontier AI endpoint must not carry embedded credentials")
    if parsed.hostname is None or parsed.hostname.lower() != expected_host:
        raise FrontierConfigurationError(f"frontier AI host {parsed.hostname!r} not in allowlist ({expected_host})")
    if parsed.hostname.lower() not in ALLOWED_FRONTIER_HOSTS:
        raise FrontierConfigurationError("frontier AI host outside allowlist")
    if parsed.port not in (None, 443):
        raise FrontierConfigurationError("frontier AI endpoint must use port 443")
    if parsed.query or parsed.fragment or ".." in parsed.path:
        raise FrontierConfigurationError("frontier AI endpoint must not contain query/fragment/traversal")
    return url


def _verify_public_dns(host: str, *, port: int = 443) -> None:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FrontierTransportError(f"DNS resolution failed for frontier host {host}: {type(exc).__name__}") from None
    if not infos:
        raise FrontierTransportError(f"DNS returned zero addresses for {host}")
    for info in infos:
        addr_raw = info[4][0].split("%", 1)[0]
        ip = ipaddress.ip_address(addr_raw)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise FrontierTransportError(f"refused non-public IP resolution for frontier host {host}")


FrontierHttpCallable = Callable[[str, dict[str, str], bytes, float, int], tuple[int, bytes]]


def default_frontier_https_post(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: float,
    max_wire_bytes: int,
    *,
    expected_host: str,
    resolve_dns: Callable[[str], None] | None = None,
) -> tuple[int, bytes]:
    """Execute one TLS 1.2+ no-redirect HTTPS POST to a pinned frontier AI endpoint."""
    safe_url = _validate_frontier_https_url(url, expected_host=expected_host)
    if resolve_dns is not None:
        resolve_dns(expected_host)
    else:
        _verify_public_dns(expected_host, port=443)

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _NoRedirectHandler(),
    )
    req = urllib.request.Request(safe_url, data=body, headers=dict(headers), method="POST")
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:  # nosec B310: verified https scheme and exact frontier host allowlist
            status = int(getattr(resp, "status", 200))
            raw = resp.read(max_wire_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise FrontierTransportError(f"frontier AI HTTP status {exc.code}") from None
    except FrontierTransportError:
        raise
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        raise FrontierTransportError(f"frontier AI connection error: {type(exc).__name__}") from None
    finally:
        req.headers.clear()
        req.unredirected_hdrs.clear()
    if len(raw) > max_wire_bytes:
        raise FrontierTransportError("frontier AI response exceeded byte limit")
    return status, raw


def default_ollama_loopback_post(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: float,
    max_wire_bytes: int,
) -> tuple[int, bytes]:
    """Execute one loopback-only Ollama v0.40.2 fallback POST without redirects."""
    parsed = urllib.parse.urlsplit(url)
    if url != OLLAMA_LOOPBACK_ENDPOINT or parsed.hostname != "127.0.0.1" or parsed.port != 11434:
        raise FrontierConfigurationError("Ollama fallback is restricted to 127.0.0.1:11434/api/chat")
    opener = urllib.request.build_opener(_NoRedirectHandler())
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:  # nosec B310: pinned loopback http://127.0.0.1:11434/api/chat endpoint
            status = int(getattr(resp, "status", 200))
            raw = resp.read(max_wire_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise FrontierTransportError(f"Ollama fallback HTTP status {exc.code}") from None
    except FrontierTransportError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FrontierTransportError(f"Ollama fallback unavailable: {type(exc).__name__}") from None
    if len(raw) > max_wire_bytes:
        raise FrontierTransportError("Ollama fallback response exceeded byte limit")
    return status, raw


def _strip_optional_json_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


def _count_bytes_tokens(invocation: ModelInvocation) -> int:
    byte_len = len(invocation.system_policy.encode("utf-8")) + len(invocation.packet_json.encode("utf-8"))
    return max(1, (byte_len + 3) // 4)


def _packet_metadata(invocation: ModelInvocation) -> dict[str, Any]:
    try:
        doc = json.loads(invocation.packet_json)
    except (ValueError, TypeError):
        return {"request_id": "req-unknown", "opportunity_set_id": "set-unknown", "source_state_id": "state-unknown", "choices": ["WAIT"], "evidence_ids": []}
    if not isinstance(doc, dict):
        return {"request_id": "req-unknown", "opportunity_set_id": "set-unknown", "source_state_id": "state-unknown", "choices": ["WAIT"], "evidence_ids": []}
    opts = doc.get("options") if isinstance(doc.get("options"), list) else []
    refs = [str(o.get("action_ref")) for o in opts if isinstance(o, dict) and o.get("action_ref")]
    ev_ids = [str(ev.get("evidence_id")) for ev in (doc.get("evidence") or []) if isinstance(ev, dict) and ev.get("evidence_id")]
    state = doc.get("state") if isinstance(doc.get("state"), dict) else {}
    return {
        "request_id": str(doc.get("request_id") or "req-unknown"),
        "opportunity_set_id": str(doc.get("opportunity_set_id") or "set-unknown"),
        "source_state_id": str(state.get("state_id") or "state-unknown"),
        "choices": ["WAIT", *refs],
        "evidence_ids": ev_ids,
    }


def _extract_gemini_decision_selection(
    doc: dict[str, Any],
    invocation: ModelInvocation,
    *,
    min_probability: Decimal,
) -> tuple[str, int, Decimal]:
    meta = _packet_metadata(invocation)
    choices = set(meta["choices"])
    head = doc
    if isinstance(doc.get("decisions"), list) and doc["decisions"] and isinstance(doc["decisions"][0], dict):
        head = doc["decisions"][0]
    raw_choice = str(head.get("choice") or head.get("selected_choice") or "WAIT").strip()
    prob_raw = head.get("probability")
    if prob_raw is None and isinstance(head.get("probabilities"), dict):
        prob_raw = head["probabilities"].get(raw_choice)
    try:
        prob = Decimal(str(prob_raw if prob_raw is not None else "0.50"))
    except Exception:
        prob = Decimal("0.50")
    if prob < Decimal("0.01"):
        prob = Decimal("0.01")
    elif prob > Decimal("0.99"):
        prob = Decimal("0.99")

    if raw_choice == "WAIT" or raw_choice not in choices or prob < min_probability:
        selected_ref = None
        reason_tag = "wait_none"
        note = "GeminiDecision1 held WAIT" if raw_choice == "WAIT" else f"prob {decimal_text(prob)} < gate {decimal_text(min_probability)}"
    else:
        selected_ref = raw_choice
        reason_tag = raw_choice
        note = f"GeminiDecision1 choice {raw_choice} prob={decimal_text(prob)}"

    ev_ids = meta["evidence_ids"][:4] or ["ev-market-snapshot"]
    selection_obj = {
        "request_id": meta["request_id"],
        "opportunity_set_id": meta["opportunity_set_id"],
        "source_state_id": meta["source_state_id"],
        "selected_action_ref": selected_ref,
        "reason": f"ID=0{reason_tag} ({note})"[:240],
        "evidence_ids": ev_ids,
    }
    return canonical_bytes(selection_obj).decode("utf-8"), 1, prob


def _extract_provider_text_and_usage(
    provider: str,
    doc: dict[str, Any],
    invocation: ModelInvocation,
    *,
    min_probability: Decimal,
) -> tuple[str, int, Decimal | None]:
    if provider == "gemini_decision":
        text, out_tok, prob = _extract_gemini_decision_selection(doc, invocation, min_probability=min_probability)
        return text, out_tok, prob

    if provider == "anthropic":
        blocks = doc.get("content")
        if type(blocks) is not list or not blocks:
            raise FrontierTransportError("Anthropic response missing content blocks")
        text = None
        for blk in blocks:
            if type(blk) is dict and blk.get("type") == "text" and isinstance(blk.get("text"), str):
                text = blk.get("text")
                break
        if text is None:
            for blk in blocks:
                if type(blk) is dict and isinstance(blk.get("text"), str):
                    text = blk.get("text")
                    break
        usage = doc.get("usage") if type(doc.get("usage")) is dict else {}
        out_tok = int(usage.get("output_tokens", max(1, len(str(text or "").encode("utf-8")) // 4)))
    elif provider == "gemini":
        cands = doc.get("candidates")
        if type(cands) is not list or not cands:
            raise FrontierTransportError("Gemini response missing candidates")
        content = cands[0].get("content") if type(cands[0]) is dict else None
        parts = content.get("parts") if type(content) is dict else None
        text = None
        if type(parts) is list:
            for part in parts:
                if type(part) is dict and not part.get("thought") and isinstance(part.get("text"), str):
                    text = part.get("text")
                    break
            if text is None:
                for part in reversed(parts):
                    if type(part) is dict and isinstance(part.get("text"), str):
                        text = part.get("text")
                        break
        meta = doc.get("usageMetadata") if type(doc.get("usageMetadata")) is dict else {}
        out_tok = int(meta.get("candidatesTokenCount", max(1, len(str(text or "").encode("utf-8")) // 4)))
    elif provider in ("openai", "deepseek"):
        choices = doc.get("choices")
        if type(choices) is not list or not choices:
            raise FrontierTransportError(f"{provider} response missing choices")
        msg = choices[0].get("message") if type(choices[0]) is dict else None
        text = msg.get("content") if type(msg) is dict else None
        usage = doc.get("usage") if type(doc.get("usage")) is dict else {}
        out_tok = int(usage.get("completion_tokens", max(1, len(str(text or "").encode("utf-8")) // 4)))
    elif provider == "ollama":
        msg = doc.get("message") if type(doc.get("message")) is dict else {}
        text = msg.get("content", doc.get("response"))
        out_tok = int(doc.get("eval_count", max(1, len(str(text or "").encode("utf-8")) // 4)))
    else:
        raise FrontierConfigurationError(f"unsupported provider {provider!r}")

    if not isinstance(text, str) or not text.strip():
        raise FrontierTransportError(f"{provider} returned empty selection text")
    return _strip_optional_json_fence(text), max(1, out_tok), None


def _build_provider_payload(
    entry: FrontierModelCatalogEntry,
    api_slug: str,
    invocation: ModelInvocation,
    secret: _RedactedSecret | None,
) -> tuple[str, dict[str, str], bytes]:
    max_tokens = invocation.budget.max_generated_tokens_per_call
    user_content = invocation.packet_json
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    effort = str(getattr(invocation.model, "reasoning_effort", "low") or "low").strip().lower()
    if entry.provider == "anthropic":
        if secret is None:
            raise FrontierTransportError(f"{entry.display_name} requires {entry.credential_env}")
        url = _validate_frontier_https_url(entry.endpoint_template, expected_host=entry.allowed_host)
        headers["x-api-key"] = secret.reveal_for_header()
        headers["anthropic-version"] = "2023-06-01"
        low_slug = api_slug.lower()
        is_legacy_claude = "-4-" in low_slug or low_slug.endswith("-4") or low_slug.startswith("claude-3")
        if is_legacy_claude:
            if effort in ("medium", "high"):
                think_budget = 2048 if effort == "medium" else 6144
                body_obj: dict[str, Any] = {
                    "model": api_slug,
                    "max_tokens": max(max_tokens, think_budget + 1024),
                    "thinking": {"type": "enabled", "budget_tokens": think_budget},
                    "system": invocation.system_policy,
                    "messages": [{"role": "user", "content": user_content}],
                }
            else:
                body_obj = {
                    "model": api_slug,
                    "max_tokens": max_tokens,
                    "temperature": 0,
                    "system": invocation.system_policy,
                    "messages": [{"role": "user", "content": user_content}],
                }
        else:
            ant_effort = effort if effort in ("low", "medium", "high") else "low"
            min_tok = 1024 if ant_effort == "low" else (4096 if ant_effort == "medium" else 8192)
            body_obj = {
                "model": api_slug,
                "max_tokens": max(max_tokens, min_tok),
                "thinking": {"type": "adaptive"},
                "output_config": {"effort": ant_effort},
                "system": invocation.system_policy,
                "messages": [{"role": "user", "content": user_content}],
            }
        return url, headers, canonical_bytes(body_obj)

    if entry.provider == "gemini_decision":
        if secret is None:
            raise FrontierTransportError(f"{entry.display_name} requires {entry.credential_env}")
        clean_slug = api_slug.removeprefix("models/")
        raw_url = entry.endpoint_template.format(slug=clean_slug)
        url = _validate_frontier_https_url(raw_url, expected_host=entry.allowed_host)
        headers["x-goog-api-key"] = secret.reveal_for_header()
        meta = _packet_metadata(invocation)
        body_obj = {
            "model": f"models/{clean_slug}",
            "choices": meta["choices"],
            "question": f"Select the highest-edge risk-compliant forex/index choice or WAIT for {meta['request_id']}.",
            "context_json": user_content,
            "zero_output_tokens": True,
        }
        return url, headers, canonical_bytes(body_obj)

    if entry.provider == "gemini":
        if secret is None:
            raise FrontierTransportError(f"{entry.display_name} requires {entry.credential_env}")
        clean_slug = api_slug.removeprefix("models/")
        raw_url = entry.endpoint_template.format(slug=clean_slug)
        url = _validate_frontier_https_url(raw_url, expected_host=entry.allowed_host)
        headers["x-goog-api-key"] = secret.reveal_for_header()
        gen_cfg: dict[str, Any] = {
            "temperature": 0,
            "maxOutputTokens": max_tokens,
            "responseMimeType": "application/json",
        }
        if effort in ("medium", "high"):
            gen_cfg["thinkingConfig"] = {"thinkingBudget": 2048 if effort == "medium" else 6144}
        body_obj = {
            "systemInstruction": {"parts": [{"text": invocation.system_policy}]},
            "contents": [{"role": "user", "parts": [{"text": user_content}]}],
            "generationConfig": gen_cfg,
        }
        return url, headers, canonical_bytes(body_obj)

    if entry.provider in ("openai", "deepseek"):
        if secret is None:
            raise FrontierTransportError(f"{entry.display_name} requires {entry.credential_env}")
        url = _validate_frontier_https_url(entry.endpoint_template, expected_host=entry.allowed_host)
        headers["Authorization"] = f"Bearer {secret.reveal_for_header()}"
        is_reasoning_openai = entry.provider == "openai" and api_slug.lower().startswith(("gpt-5", "o1", "o3", "o4"))
        if is_reasoning_openai:
            oai_effort = effort if effort in ("low", "medium", "high") else "low"
            body_obj = {
                "model": api_slug,
                "max_completion_tokens": max_tokens,
                "reasoning_effort": oai_effort,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": invocation.system_policy},
                    {"role": "user", "content": user_content},
                ],
            }
        else:
            body_obj = {
                "model": api_slug,
                "temperature": 0,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": invocation.system_policy},
                    {"role": "user", "content": user_content},
                ],
            }
            if effort in ("medium", "high"):
                body_obj["reasoning_effort"] = effort
        if invocation.seed is not None and entry.provider == "openai":
            body_obj["seed"] = invocation.seed
        return url, headers, canonical_bytes(body_obj)

    if entry.provider == "ollama":
        body_obj = {
            "model": api_slug,
            "stream": False,
            "think": False,
            "format": "json",
            "options": {"temperature": 0, "num_ctx": 8192, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": invocation.system_policy},
                {"role": "user", "content": user_content},
            ],
        }
        return OLLAMA_LOOPBACK_ENDPOINT, headers, canonical_bytes(body_obj)

    raise FrontierConfigurationError(f"unknown provider {entry.provider!r}")


def _build_gemini_fast_json_payload(
    *,
    clean_slug: str,
    system_text: str,
    user_text: str,
    max_tokens: int,
    secret: _RedactedSecret,
    allowed_host: str,
) -> tuple[str, dict[str, str], bytes]:
    raw_url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_slug}:generateContent"
    url = _validate_frontier_https_url(raw_url, expected_host=allowed_host)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-goog-api-key": secret.reveal_for_header(),
    }
    body_obj = {
        "systemInstruction": {"parts": [{"text": system_text}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": max(128, int(max_tokens)),
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }
    return url, headers, canonical_bytes(body_obj)


def _extract_gemini_cand_text(raw_doc: dict[str, Any]) -> str:
    cands = raw_doc.get("candidates")
    if type(cands) is not list or not cands:
        raise FrontierTransportError("Gemini response missing candidates")
    content = cands[0].get("content") if type(cands[0]) is dict else None
    parts = content.get("parts") if type(content) is dict else None
    text = None
    if type(parts) is list:
        for part in parts:
            if type(part) is dict and not part.get("thought") and isinstance(part.get("text"), str):
                text = part.get("text")
                break
        if text is None:
            for part in reversed(parts):
                if type(part) is dict and isinstance(part.get("text"), str):
                    text = part.get("text")
                    break
    if not isinstance(text, str) or not text.strip():
        raise FrontierTransportError("Gemini returned empty selection text")
    return _strip_optional_json_fence(text)


class FrontierReceiptVerifier:
    """Independently verifies that each FrontierChatBackend reply matches its recorded invocation."""

    def __init__(self) -> None:
        self._records: dict[str, tuple[str, str, str]] = {}
        self._lock = Lock()

    def record(self, reply: InferenceReply, invocation: ModelInvocation) -> None:
        inv_sha = content_digest(invocation)
        raw_sha = sha256(reply.raw_selection_json.encode("utf-8")).hexdigest()
        with self._lock:
            self._records[reply.receipt_id] = (inv_sha, reply.model.model_id, raw_sha)

    def verify(self, reply: InferenceReply, invocation: ModelInvocation) -> bool:
        expected_inv_sha = content_digest(invocation)
        expected_raw_sha = sha256(reply.raw_selection_json.encode("utf-8")).hexdigest()
        with self._lock:
            row = self._records.get(reply.receipt_id)
        return row == (expected_inv_sha, invocation.model.model_id, expected_raw_sha)


class FrontierChatBackend(ModelBackend):
    """Concrete :class:`ModelBackend` targeting one catalog model with no silent fallback."""

    def __init__(
        self,
        *,
        entry: FrontierModelCatalogEntry,
        api_slug: str,
        model_spec: ModelSpecification,
        secret: _RedactedSecret | None,
        verifier: FrontierReceiptVerifier,
        clock: Callable[[], datetime] | None = None,
        http_post: FrontierHttpCallable | None = None,
        resolve_dns: Callable[[str], None] | None = None,
        timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
        max_wire_bytes: int = MAX_PROVIDER_WIRE_BYTES,
        min_probability: Decimal = DEFAULT_MIN_DECISION_PROBABILITY,
    ) -> None:
        self._entry = entry
        self._api_slug = api_slug
        self._model_spec = model_spec
        self._secret = secret
        self._verifier = verifier
        self._clock = clock or _utc_now
        self._http_post = http_post
        self._resolve_dns = resolve_dns
        self._timeout = float(timeout_seconds)
        self._max_wire_bytes = integer(max_wire_bytes, "max_wire_bytes", minimum=1024)
        self._min_probability = min_probability
        self._seq = 0
        self._lock = Lock()
        self._decide_404: bool = False
        self.last_decision_probability: Decimal | None = None

    def __repr__(self) -> str:
        return (
            f"FrontierChatBackend(model_id={self._entry.model_id!r}, "
            f"provider={self._entry.provider!r}, key='[REDACTED]')"
        )

    def count_input_tokens(self, invocation: ModelInvocation) -> int:
        return _count_bytes_tokens(invocation)

    def _dispatch_http(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        if self._http_post is not None:
            return self._http_post(url, dict(headers), body, timeout, self._max_wire_bytes)
        if self._entry.provider == "ollama":
            return default_ollama_loopback_post(url, dict(headers), body, timeout, self._max_wire_bytes)
        return default_frontier_https_post(
            url,
            dict(headers),
            body,
            timeout,
            self._max_wire_bytes,
            expected_host=self._entry.allowed_host,
            resolve_dns=self._resolve_dns,
        )

    def infer(self, invocation: ModelInvocation) -> InferenceReply:
        if invocation.system_policy != SYSTEM_POLICY or invocation.output_schema_id != OUTPUT_SCHEMA_ID:
            raise ContractError("frontier backend requires canonical SYSTEM_POLICY and OUTPUT_SCHEMA_ID")
        if invocation.model != self._model_spec:
            raise ContractError("frontier backend model specification mismatch")

        started_at = utc_time(self._clock(), "started_at")
        input_tokens = self.count_input_tokens(invocation)
        timeout_s = min(self._timeout, float(invocation.budget.max_seconds_per_call))
        extract_provider = self._entry.provider
        if self._entry.provider == "gemini_decision":
            if self._secret is None:
                raise FrontierTransportError(f"{self._entry.display_name} requires {self._entry.credential_env}")
            clean_slug = self._api_slug.removeprefix("models/")
            status = 404
            raw = b""
            with self._lock:
                skip_decide = self._decide_404
            if clean_slug.startswith("gemini-decision") and not skip_decide:
                url, headers, body = _build_provider_payload(self._entry, self._api_slug, invocation, self._secret)
                try:
                    status, raw = self._dispatch_http(url, headers, body, min(timeout_s, 4.0))
                except FrontierTransportError as exc:
                    if "HTTP status 404" not in str(exc):
                        raise
                    status, raw = 404, b""
                finally:
                    headers.clear()
                if status == 404:
                    with self._lock:
                        self._decide_404 = True
            if status == 404 or not clean_slug.startswith("gemini-decision"):
                fb_candidates = (
                    ("gemini-2.5-flash", "gemini-3.8-flash")
                    if clean_slug == "gemini-decision-1"
                    else (clean_slug,)
                )
                for idx_fb, fb_slug in enumerate(fb_candidates):
                    fb_url, fb_hdrs, fb_body = _build_gemini_fast_json_payload(
                        clean_slug=fb_slug,
                        system_text=invocation.system_policy,
                        user_text=invocation.packet_json,
                        max_tokens=invocation.budget.max_generated_tokens_per_call,
                        secret=self._secret,
                        allowed_host=self._entry.allowed_host,
                    )
                    try:
                        status, raw = self._dispatch_http(fb_url, fb_hdrs, fb_body, timeout_s)
                    except FrontierTransportError as exc:
                        if idx_fb + 1 < len(fb_candidates) and "HTTP status 404" in str(exc):
                            status, raw = 404, b""
                            continue
                        raise
                    finally:
                        fb_hdrs.clear()
                    if status != 404 or idx_fb + 1 == len(fb_candidates):
                        break
                extract_provider = "gemini"
        else:
            url, headers, body = _build_provider_payload(self._entry, self._api_slug, invocation, self._secret)
            try:
                status, raw = self._dispatch_http(url, headers, body, timeout_s)
            finally:
                headers.clear()

        if status < 200 or status >= 300:
            raise FrontierTransportError(f"{self._entry.display_name} returned HTTP status {status}")

        doc = _decode_json_dict(raw, max_bytes=self._max_wire_bytes)
        selection_text, generated_tokens, prob = _extract_provider_text_and_usage(
            extract_provider, doc, invocation, min_probability=self._min_probability
        )
        self.last_decision_probability = prob
        completed_at = utc_time(self._clock(), "completed_at")
        if completed_at < started_at:
            completed_at = started_at

        with self._lock:
            self._seq += 1
            seq = self._seq
        inv_sha = content_digest(invocation)
        receipt_id = f"rcpt-{self._entry.provider}-{seq}-{inv_sha[:12]}"
        reply = InferenceReply(
            raw_selection_json=selection_text,
            receipt_id=receipt_id,
            invocation_sha256=inv_sha,
            model=self._model_spec,
            started_at=started_at,
            completed_at=completed_at,
            input_tokens=input_tokens,
            generated_tokens=generated_tokens,
        )
        self._verifier.record(reply, invocation)
        return reply


class FrontierModelRegistry:
    """Ordered 9-model AI catalog prioritizing Claude/Gemini Decision 1/Carbon/Argon/OpenAI/DeepSeek ahead of Qwen fallback."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str],
        clock: Callable[[], datetime] | None = None,
        http_post: FrontierHttpCallable | None = None,
        ollama_http_post: FrontierHttpCallable | None = None,
        resolve_dns: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(environ, Mapping):
            raise FrontierConfigurationError("environ must be a key-value Mapping")
        self._env = {
            k: str(v)
            for k, v in environ.items()
            if isinstance(k, str) and k.startswith("CAS_FOREX_") and isinstance(v, str)
        }
        self._clock = clock or _utc_now
        self._http_post = http_post
        self._ollama_http_post = ollama_http_post
        self._resolve_dns = resolve_dns
        self._verifier = FrontierReceiptVerifier()
        self._lock = Lock()
        self._secrets: dict[str, _RedactedSecret] = {}
        self._slugs: dict[str, str] = {}
        self._stats: dict[str, dict[str, Any]] = {}

        for env_key in (ENV_ANTHROPIC_API_KEY, ENV_GEMINI_API_KEY, ENV_OPENAI_API_KEY, ENV_DEEPSEEK_API_KEY):
            raw_val = self._env.get(env_key, "").strip()
            if raw_val:
                self._secrets[env_key] = _RedactedSecret(raw_val)

        for entry in FRONTIER_MODEL_CATALOG:
            raw_slug = self._env.get(entry.slug_env, "").strip() or entry.default_slug
            self._slugs[entry.model_id] = _validate_slug(raw_slug, entry.slug_env)
            self._stats[entry.model_id] = {"calls": 0, "last_latency_ms": None, "last_status": "IDLE"}

        self._ollama_fallback_enabled = _truthy(self._env.get(ENV_OLLAMA_FALLBACK_ENABLED))
        raw_prob = self._env.get(ENV_DECISION_MIN_PROBABILITY, "").strip()
        if raw_prob:
            try:
                self._min_probability = Decimal(raw_prob)
            except Exception as exc:
                raise FrontierConfigurationError("invalid CAS_FOREX_DECISION_MIN_PROBABILITY") from exc
            if not (Decimal("0.01") <= self._min_probability <= Decimal("0.99")):
                raise FrontierConfigurationError("CAS_FOREX_DECISION_MIN_PROBABILITY must be in 0.01..0.99")
        else:
            self._min_probability = DEFAULT_MIN_DECISION_PROBABILITY

        scout_env = self._env.get(ENV_GEMINI_DECISION_SCOUT, "").strip()
        self._fast_scout_enabled = _truthy(scout_env) if scout_env else (ENV_GEMINI_API_KEY in self._secrets)
        self._last_scout: dict[str, Any] | None = None

        requested = self._env.get(ENV_AI_MODEL, "").strip()
        if requested:
            if requested not in _CATALOG_BY_ID:
                raise FrontierConfigurationError(
                    f"unknown {ENV_AI_MODEL}={requested!r}; expected one of {[e.model_id for e in FRONTIER_MODEL_CATALOG]}"
                )
            self._active_model_id = requested
            self._explicit_selection = True
        else:
            self._explicit_selection = False
            self._active_model_id = self._pick_default_model_id()
        raw_depth = str(self._env.get(ENV_THINKING_DEPTH, "AUTO") or "AUTO").strip().upper()
        if raw_depth not in VALID_THINKING_DEPTHS:
            raise FrontierConfigurationError(
                f"{ENV_THINKING_DEPTH} must be one of {VALID_THINKING_DEPTHS}, got {raw_depth!r}"
            )
        self._thinking_depth: str = raw_depth
        self._thinking_depth_persist_cb: Any = None
        self._decide_404: bool = False
        self._last_effective_effort: str = "low"
        self._last_latency_ms: int | None = None

    def __repr__(self) -> str:
        with self._lock:
            active = self._active_model_id
        return f"FrontierModelRegistry(active_model={active!r}, secrets='[REDACTED]')"

    def _is_entry_ready(self, entry: FrontierModelCatalogEntry) -> bool:
        if entry.is_fallback:
            return self._ollama_fallback_enabled or (self._ollama_http_post is not None)
        return entry.credential_env in self._secrets

    def _pick_default_model_id(self) -> str:
        # Strictly evaluate ranks #1..#8 (frontier cloud providers) BEFORE rank #9 (qwen fallback).
        for entry in FRONTIER_MODEL_CATALOG:
            if not entry.is_fallback and self._is_entry_ready(entry):
                return entry.model_id
        if self._is_entry_ready(_CATALOG_BY_ID["qwen3:0.6b"]):
            return "qwen3:0.6b"
        return FRONTIER_MODEL_CATALOG[0].model_id  # claude-fable-5.2 (#1)

    @property
    def active_model_id(self) -> str:
        with self._lock:
            return self._active_model_id

    @property
    def active_entry(self) -> FrontierModelCatalogEntry:
        return _CATALOG_BY_ID[self.active_model_id]

    @property
    def verifier(self) -> FrontierReceiptVerifier:
        return self._verifier

    @property
    def fast_scout_enabled(self) -> bool:
        with self._lock:
            return self._fast_scout_enabled

    def set_fast_scout_enabled(self, enabled: bool) -> dict[str, Any]:
        with self._lock:
            self._fast_scout_enabled = bool(enabled)
        return self.catalog_snapshot()

    def is_model_ready(self, model_id: str | None = None) -> bool:
        target_id = self.active_model_id if model_id is None else model_id
        if target_id not in _CATALOG_BY_ID:
            return False
        return self._is_entry_ready(_CATALOG_BY_ID[target_id])

    @property
    def thinking_depth(self) -> str:
        with self._lock:
            return self._thinking_depth

    def bind_thinking_depth_persister(self, callback: Callable[[str], None] | None) -> None:
        with self._lock:
            self._thinking_depth_persist_cb = callback

    def set_thinking_depth(self, depth: str) -> dict[str, Any]:
        if not isinstance(depth, str) or depth.strip().upper() not in VALID_THINKING_DEPTHS:
            raise FrontierConfigurationError(
                f"thinking_depth must be one of {VALID_THINKING_DEPTHS}, got {depth!r}"
            )
        clean = depth.strip().upper()
        with self._lock:
            self._thinking_depth = clean
            cb = self._thinking_depth_persist_cb
        if cb is not None:
            cb(clean)
        return self.catalog_snapshot()

    def resolve_reasoning_effort(
        self,
        *,
        model_id: str | None = None,
        timeframe: str = "M1",
        regime: str = "TREND_IGNITION",
        symbol: str | None = None,
        is_pyramid_add: bool = False,
    ) -> str:
        target_id = self.active_model_id if model_id is None else model_id
        if target_id not in _CATALOG_BY_ID:
            raise FrontierConfigurationError(f"unknown AI model {target_id!r}")
        entry = _CATALOG_BY_ID[target_id]
        if entry.is_fallback or entry.provider == "gemini_decision":
            return "disabled" if entry.is_fallback else "low"
        with self._lock:
            mode = self._thinking_depth
        if mode in ("LOW", "MEDIUM", "HIGH"):
            return mode.lower()
        # AUTO 2-Speed Brain rule
        if is_pyramid_add or timeframe == "H1":
            return "high"
        if timeframe in ("50ms", "1s", "M1") and (symbol in ("NAS100", "US30") or regime == "TREND_IGNITION"):
            return "low"
        if timeframe in ("M5", "M15") or regime == "STRONG_TREND":
            return "medium"
        return "low"

    def model_spec(
        self,
        model_id: str | None = None,
        *,
        reasoning_effort: str | None = None,
    ) -> ModelSpecification:
        target_id = self.active_model_id if model_id is None else model_id
        if target_id not in _CATALOG_BY_ID:
            raise FrontierConfigurationError(f"unknown AI model {target_id!r}")
        entry = _CATALOG_BY_ID[target_id]
        slug = self._slugs[target_id]
        if entry.is_fallback:
            eff = "disabled"
        elif reasoning_effort is not None and str(reasoning_effort).strip().lower() in ("disabled", "low", "medium", "high"):
            eff = str(reasoning_effort).strip().lower()
        else:
            eff = self.resolve_reasoning_effort(model_id=target_id)
        artifact_sha = content_digest({
            "model_id": entry.model_id,
            "provider": entry.provider,
            "api_slug": slug,
            "rank": entry.rank,
            "tier": entry.tier,
            "system_policy_sha256": sha256(SYSTEM_POLICY.encode("utf-8")).hexdigest(),
        })
        spec_id = f"cas-{entry.model_id.replace(':', '-')}"
        return ModelSpecification(
            model_id=spec_id,
            artifact_sha256=artifact_sha,
            reasoning_effort=eff,
            prompt_version="frontier-v2",
        )

    def build_backend(
        self,
        model_id: str | None = None,
        *,
        reasoning_effort: str | None = None,
    ) -> tuple[ModelSpecification, FrontierChatBackend, FrontierReceiptVerifier]:
        target_id = self.active_model_id if model_id is None else model_id
        if target_id not in _CATALOG_BY_ID:
            raise FrontierConfigurationError(f"unknown AI model {target_id!r}")
        entry = _CATALOG_BY_ID[target_id]
        spec = self.model_spec(target_id, reasoning_effort=reasoning_effort)
        secret = self._secrets.get(entry.credential_env) if entry.credential_env else None
        transport = self._ollama_http_post if entry.provider == "ollama" else self._http_post
        backend = FrontierChatBackend(
            entry=entry,
            api_slug=self._slugs[target_id],
            model_spec=spec,
            secret=secret,
            verifier=self._verifier,
            clock=self._clock,
            http_post=transport,
            resolve_dns=self._resolve_dns,
            min_probability=self._min_probability,
        )
        return spec, backend, self._verifier

    def scout_opportunities(
        self,
        questions: list[dict[str, Any]],
        *,
        min_probability: Decimal | None = None,
    ) -> dict[str, Any]:
        """Batch-screen candidate markets in 150-250ms using Gemini Decision 1."""
        gate_prob = min_probability if min_probability is not None else self._min_probability
        entry = _CATALOG_BY_ID["gemini-decision-1"]
        secret = self._secrets.get(entry.credential_env)
        if not self._is_entry_ready(entry) or secret is None or not questions:
            summary = {
                "executed": False,
                "reason": "GEMINI_DECISION_KEY_UNSET" if secret is None else "NO_CANDIDATES",
                "wake_heavy_model": True,
                "best_market": None,
                "best_probability": None,
                "decisions": [],
            }
            with self._lock:
                self._last_scout = summary
            return summary

        def _post(u: str, h: dict[str, str], b: bytes, timeout_s: float = 8.0) -> tuple[int, bytes]:
            try:
                if self._http_post is not None:
                    return self._http_post(u, dict(h), b, timeout_s, MAX_PROVIDER_WIRE_BYTES)
                return default_frontier_https_post(
                    u, dict(h), b, timeout_s, MAX_PROVIDER_WIRE_BYTES,
                    expected_host=entry.allowed_host, resolve_dns=self._resolve_dns,
                )
            finally:
                h.clear()

        clean_slug = self._slugs["gemini-decision-1"].removeprefix("models/")
        t0 = _utc_now()
        status = 404
        raw = b""
        used_generate = False
        with self._lock:
            skip_decide = self._decide_404
        if clean_slug.startswith("gemini-decision") and not skip_decide:
            url = _validate_frontier_https_url(entry.endpoint_template.format(slug=clean_slug), expected_host=entry.allowed_host)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-goog-api-key": secret.reveal_for_header(),
            }
            body = canonical_bytes({
                "model": f"models/{clean_slug}",
                "batch_questions": questions[:1000],
                "zero_output_tokens": True,
            })
            try:
                status, raw = _post(url, headers, body, 4.0)
            except FrontierTransportError as exc:
                if "HTTP status 404" not in str(exc):
                    raise
                status, raw = 404, b""
            if status == 404:
                with self._lock:
                    self._decide_404 = True
        if status == 404 or not clean_slug.startswith("gemini-decision"):
            fb_candidates = (
                ("gemini-2.5-flash", "gemini-3.8-flash")
                if clean_slug == "gemini-decision-1"
                else (clean_slug,)
            )
            fb_sys = (
                "Screen candidate forex/index setups quickly and respond ONLY with valid JSON: "
                '{"decisions":[{"market":"SYMBOL","choice":"WAIT or exact choice","probability":"0.01-0.99"}]}.'
            )
            fb_user = canonical_bytes({"min_probability": decimal_text(gate_prob), "candidates": questions[:1000]}).decode("utf-8")
            for idx_fb, fb_slug in enumerate(fb_candidates):
                fb_url, fb_hdrs, fb_body = _build_gemini_fast_json_payload(
                    clean_slug=fb_slug,
                    system_text=fb_sys,
                    user_text=fb_user,
                    max_tokens=512,
                    secret=secret,
                    allowed_host=entry.allowed_host,
                )
                try:
                    status, raw = _post(fb_url, fb_hdrs, fb_body, 8.0)
                except FrontierTransportError as exc:
                    if idx_fb + 1 < len(fb_candidates) and "HTTP status 404" in str(exc):
                        status, raw = 404, b""
                        continue
                    raise
                used_generate = True
                if status != 404 or idx_fb + 1 == len(fb_candidates):
                    break

        latency_ms = max(1, int((_utc_now() - t0).total_seconds() * 1000))
        if status < 200 or status >= 300:
            raise FrontierTransportError(f"Gemini Decision 1 scout returned HTTP {status}")
        doc = _decode_json_dict(raw)
        if used_generate and "decisions" not in doc and "candidates" in doc:
            doc = _decode_json_dict(_extract_gemini_cand_text(doc).encode("utf-8"))
        raw_decisions = doc.get("decisions") if isinstance(doc.get("decisions"), list) else [doc]
        parsed: list[dict[str, Any]] = []
        best_prob = Decimal("0")
        best_market: str | None = None
        for idx, item in enumerate(raw_decisions):
            if not isinstance(item, dict):
                continue
            mkt = str(item.get("market") or (questions[idx].get("market") if idx < len(questions) else "UNKNOWN"))
            choice = str(item.get("choice") or "WAIT")
            try:
                prob = Decimal(str(item.get("probability", "0.50")))
            except Exception:
                prob = Decimal("0.50")
            if prob < Decimal("0.01"):
                prob = Decimal("0.01")
            elif prob > Decimal("0.99"):
                prob = Decimal("0.99")
            admitted = choice != "WAIT" and prob >= gate_prob
            parsed.append({
                "market": mkt,
                "choice": choice,
                "probability": decimal_text(prob),
                "admitted": admitted,
            })
            if admitted and prob > best_prob:
                best_prob = prob
                best_market = mkt

        self.record_call("gemini-decision-1", latency_ms=latency_ms, status="SCOUT_OK")
        summary = {
            "executed": True,
            "model_id": "gemini-decision-1",
            "latency_ms": latency_ms,
            "min_probability": decimal_text(gate_prob),
            "wake_heavy_model": best_market is not None,
            "best_market": best_market,
            "best_probability": decimal_text(best_prob) if best_market is not None else None,
            "decisions": parsed,
        }
        with self._lock:
            self._last_scout = summary
        return summary

    def record_call(
        self,
        model_id: str,
        *,
        latency_ms: int,
        status: str,
        reasoning_effort: str | None = None,
    ) -> None:
        if model_id not in _CATALOG_BY_ID:
            return
        clean_lat = max(0, int(latency_ms))
        with self._lock:
            st = self._stats[model_id]
            st["calls"] = int(st["calls"]) + 1
            st["last_latency_ms"] = clean_lat
            st["last_status"] = str(status)[:40]
            self._last_latency_ms = clean_lat
            if reasoning_effort is not None:
                self._last_effective_effort = str(reasoning_effort).lower()

    def select_model(self, model_id: str) -> dict[str, Any]:
        if not isinstance(model_id, str) or model_id.strip() not in _CATALOG_BY_ID:
            raise FrontierConfigurationError(f"unsupported AI model selection {model_id!r}")
        clean = model_id.strip()
        with self._lock:
            self._active_model_id = clean
            self._explicit_selection = True
        return self.catalog_snapshot()

    def catalog_snapshot(self) -> dict[str, Any]:
        with self._lock:
            active_id = self._active_model_id
            explicit = self._explicit_selection
            scout_enabled = self._fast_scout_enabled
            last_scout = dict(self._last_scout) if self._last_scout is not None else None
            stats_copy = {k: dict(v) for k, v in self._stats.items()}

        active_entry = _CATALOG_BY_ID[active_id]
        active_ready = self._is_entry_ready(active_entry)
        frontier_ready_count = sum(1 for e in FRONTIER_MODEL_CATALOG if not e.is_fallback and self._is_entry_ready(e))
        items: list[dict[str, Any]] = []
        for entry in FRONTIER_MODEL_CATALOG:
            st = stats_copy[entry.model_id]
            ready = self._is_entry_ready(entry)
            is_active = entry.model_id == active_id
            if is_active:
                availability = "ACTIVE_READY" if ready else ("OFFLINE_FALLBACK_DISABLED" if entry.is_fallback else "AWAITING_PROVIDER_KEY")
            else:
                availability = "READY" if ready else ("OFFLINE_FALLBACK_ONLY" if entry.is_fallback else "KEY_NOT_SET")
            items.append({
                "rank": entry.rank,
                "model_id": entry.model_id,
                "display_name": entry.display_name,
                "provider": entry.provider,
                "provider_label": entry.provider_label,
                "api_slug": self._slugs[entry.model_id],
                "tier": entry.tier,
                "is_fallback": entry.is_fallback,
                "latency_target_ms": entry.latency_target_ms,
                "active": is_active,
                "provider_ready": ready,
                "availability": availability,
                "role_summary": entry.role_summary,
                "calls": int(st["calls"]),
                "last_latency_ms": st["last_latency_ms"],
                "last_status": st["last_status"],
            })

        return {
            "schema": "cas-forex.ai-models/1",
            "active_model_id": active_id,
            "active_display_name": active_entry.display_name,
            "active_provider": active_entry.provider,
            "active_tier": active_entry.tier,
            "active_provider_ready": active_ready,
            "active_status": "READY" if active_ready else "AWAITING_PROVIDER_KEY",
            "selection_mode": "USER_SELECTED" if explicit else "PRIORITY_AUTO",
            "frontier_ahead_of_qwen": True,
            "frontier_configured_count": frontier_ready_count,
            "offline_fallback_enabled": self._ollama_fallback_enabled,
            "thinking_depth": self.thinking_depth,
            "valid_thinking_depths": list(VALID_THINKING_DEPTHS),
            "last_effective_effort": self._last_effective_effort,
            "last_latency_ms": self._last_latency_ms,
            "fast_scout_enabled": scout_enabled,
            "fast_scout_model_id": "gemini-decision-1",
            "fast_scout_ready": self._is_entry_ready(_CATALOG_BY_ID["gemini-decision-1"]),
            "min_decision_probability": decimal_text(self._min_probability),
            "last_scout": last_scout,
            "valve_required": True,
            "models": items,
        }


def assert_safe_ai_catalog_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Verify an AI model/trader payload contains zero banned secret field names or floats."""

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, float):
            raise FrontierConfigurationError(f"AI JSON payload must not contain floats ({path})")
        if isinstance(node, Mapping):
            for k, v in node.items():
                if not isinstance(k, str):
                    raise FrontierConfigurationError("AI JSON keys must be strings")
                lower = k.lower()
                if any(bad in lower for bad in _SENSITIVE_KEY_WORDS):
                    raise FrontierConfigurationError(f"forbidden sensitive key name in AI JSON payload: {k!r}")
                _walk(v, f"{path}.{k}")
        elif isinstance(node, (list, tuple)):
            for idx, item in enumerate(node):
                _walk(item, f"{path}[{idx}]")

    _walk(payload, "$")
    return dict(payload)
