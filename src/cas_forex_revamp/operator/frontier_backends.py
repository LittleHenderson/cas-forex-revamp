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

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import StrEnum
from hashlib import sha256
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
from threading import Lock
import time
from typing import Any, Callable, Mapping, TypeVar
import urllib.error
import urllib.parse
import urllib.request

from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest, decimal_text
from cas_forex_revamp.venue.live_market_stream import get_cached_tls12_ssl_context
from cas_forex_revamp.contracts.primitives import decimal_value, digest, integer, utc_time

from .decisions import OperatorUnavailable
from .model import (
    DurableModelExecutionGate,
    InferenceReply,
    LOCAL_ZERO_COST_MODELS,
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
ENV_EXPLAINER_MODEL_ID = "CAS_FOREX_EXPLAINER_MODEL_ID"
DEFAULT_EXPLAINER_MODEL_ID = "gemini-4-neon"
ENV_EXPLAINER_TTS_MODEL_ID = "CAS_FOREX_EXPLAINER_TTS_MODEL_ID"
DEFAULT_EXPLAINER_TTS_MODEL_ID = "gemini-3.8-flash-tts"
FALLBACK_EXPLAINER_TTS_MODEL_ID = "gemini-3.8-flash-lite-tts"

VALID_EXPLAINER_VOICES = ("Kore", "Puck", "Charon", "Fenrir", "Aoede")
ALLOWED_EXPLAINER_AUDIO_MIMES = frozenset({
    "audio/webm",
    "audio/ogg",
    "audio/wav",
    "audio/mp4",
    "audio/mpeg",
})
MAX_EXPLAINER_AUDIO_B64_CHARS = 2_000_000
MAX_EXPLAINER_RESPONSE_BYTES = 524_288
MAX_TTS_WIRE_BYTES = 4 * 1024 * 1024

EXPLAINER_SYSTEM_PROMPT = (
    "You are the read-only CAS Forex Voice & Text Explainer powered by Gemini 4 Neon. "
    "Give crisp, natural, spoken-friendly plain-English answers (2 to 6 clear sentences, "
    "avoiding markdown tables or raw code) grounded strictly in the live numbers inside `cockpit` "
    "and these verified CAS Forex architecture invariants: "
    "(1) Dual-Shield 80/12/8 Barbell: 80% regulated OANDA 1:50 safe-harbor reserve, 12% Hugo's Way "
    "MT5 primary sleeve, and 8% LHFX MT5 backup sleeve; "
    "(2) Leverage & Margin Safety: up to 1:500 on FX and 1:200 (100 contracts per lot) on NAS100/US30/SPX500 "
    "indices with a 1,000% minimum post-trade margin-level cushion; "
    "(3) Valve Gate: every trade/amendment is gated by the 161-parameter tks_meta_valve_controller "
    "(ForexMetaValveGate, threshold 0.55); "
    "(4) 3-Gear Auto-Adaptive Risk & Daily Quota: scales 1.00% Conservative ($500 soft / $1,000 hard quota) "
    "-> 2.50% Growth ($2,000 / $2,500) -> 5.00% Strong-Trend Runner ($2,000 / $3,000), auto-downshifting to "
    "Conservative on any loss streak >= 1 or >= 10% soft drawdown (20% hard max-drawdown lock); "
    "(5) Treasury & Parallel Tiers: 50%/50% Profit-Sweep Bank Vault (50% retained for trading, 50% reserved "
    "for owner bank sweep) plus 5 parallel simulated/live tier accounts; "
    "(6) Fast Protection & Burst Strategy: 50ms direct-MT5 spool burst scalping (NAS100 25-pt SL / 60-pt TP, "
    "US30 50-pt SL / 120-pt TP) with instant snap-to-breakeven, monotonic trailing stops, and anti-self-hedge blocking; "
    "(7) 5-Gate Real-Money LIVE Readiness: requires LIVE_CREDENTIALS_STAGED, OWNER_ED25519_LIVE_TICKETS, "
    "REAL_BARBELL_80_12_8_CUSTODY, VALVE_AND_DURABLE_JOURNALS, and TWO_KEY_LIVE_ARMED with phrase "
    "ARM_LIVE_REAL_MONEY_TRADING. "
    "You are strictly read-only and advisory: never claim to place trades or alter settings. "
    "If audio input is attached, transcribe what the owner asked into `spoken_question` and answer it in `answer`. "
    'Respond with valid JSON: {"spoken_question": "<transcribed question if audio attached else empty string>", '
    '"answer": "<spoken-friendly plain-English explanation under 160 words>"}.'
)

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

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retryable = bool(retryable)


class FrontierCircuitOpenError(FrontierTransportError):
    """Raised fast when a provider circuit breaker is OPEN or a HALF_OPEN probe is active."""

    def __init__(self, message: str, *, provider: str = "") -> None:
        super().__init__(message, status_code=None, retryable=False)
        self.provider = provider


class FrontierConfigurationError(ContractError):
    """Raised on invalid model selection, host allowlist breach, or malformed provider settings."""


class CircuitBreakerState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class FrontierOperationKind(StrEnum):
    READ_INFERENCE = "READ_INFERENCE"
    READ_SCOUT = "READ_SCOUT"
    READ_EXPLAINER = "READ_EXPLAINER"
    UNSAFE_WRITE = "UNSAFE_WRITE"


_IDEMPOTENT_READ_OPERATIONS = frozenset({
    FrontierOperationKind.READ_INFERENCE,
    FrontierOperationKind.READ_SCOUT,
    FrontierOperationKind.READ_EXPLAINER,
})
_HTTP_STATUS_RE = re.compile(r"\bHTTP(?:\s+status)?\s+(\d{3})\b")
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class CircuitBreakerConfig:
    failure_threshold: int = 3
    cooldown_seconds: Decimal = Decimal("30")

    def __post_init__(self) -> None:
        integer(self.failure_threshold, "failure_threshold", minimum=1)
        decimal_value(self.cooldown_seconds, "cooldown_seconds", positive=True)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: Decimal = Decimal("0.05")
    max_delay_seconds: Decimal = Decimal("0.50")

    def __post_init__(self) -> None:
        integer(self.max_attempts, "max_attempts", minimum=1)
        if self.max_attempts > 10:
            raise FrontierConfigurationError("max_attempts must be <= 10")
        decimal_value(self.base_delay_seconds, "base_delay_seconds", positive=False)
        decimal_value(self.max_delay_seconds, "max_delay_seconds", positive=False)
        if self.base_delay_seconds < 0 or self.max_delay_seconds < self.base_delay_seconds:
            raise FrontierConfigurationError("RetryPolicy requires 0 <= base_delay_seconds <= max_delay_seconds")


FRONTIER_PROVIDERS: tuple[str, ...] = (
    "anthropic",
    "gemini_decision",
    "gemini",
    "openai",
    "deepseek",
    "ollama",
)

# Exact integer pricing in micro-USD (1 USD = 1,000,000 micro-USD) per 1,000,000 units:
# (input_micro_usd_per_1m, output_micro_usd_per_1m). Local qwen3:0.6b fallback is strictly (0, 0).
MODEL_PRICING_MICRO_USD_PER_1M: dict[str, tuple[int, int]] = {
    "claude-fable-5.2": (3_000_000, 15_000_000),
    "claude-fable": (3_000_000, 15_000_000),
    "claude-5.5": (15_000_000, 75_000_000),
    "gemini-decision-1": (100_000, 400_000),
    "gemini-carbon": (1_250_000, 10_000_000),
    "gemini-argon": (300_000, 2_500_000),
    "openai-astra": (2_500_000, 10_000_000),
    "deepseek-flash-1017": (270_000, 1_100_000),
    "qwen3:0.6b": (0, 0),
}


def compute_call_cost_pico_usd(
    model_id: str,
    *,
    input_units: int,
    output_units: int,
    pricing_micro_usd_per_1m: Mapping[str, tuple[int, int]] | None = None,
) -> int:
    """Return exact integer pico-USD (10^-12 USD) for a call with zero float arithmetic."""
    table = pricing_micro_usd_per_1m if pricing_micro_usd_per_1m is not None else MODEL_PRICING_MICRO_USD_PER_1M
    if model_id not in table:
        raise FrontierConfigurationError(f"missing pricing entry for model {model_id!r}")
    in_rate, out_rate = table[model_id]
    in_u = integer(input_units, "input_units", minimum=0)
    out_u = integer(output_units, "output_units", minimum=0)
    in_r = integer(in_rate, "input_micro_usd_per_1m", minimum=0)
    out_r = integer(out_rate, "output_micro_usd_per_1m", minimum=0)
    return (in_u * in_r) + (out_u * out_r)


def pico_usd_to_micro_usd(pico_usd: int) -> int:
    clean_pico = integer(pico_usd, "pico_usd", minimum=0)
    return int((Decimal(clean_pico) / Decimal(1_000_000)).to_integral_value(rounding=ROUND_HALF_UP))


def pico_usd_to_decimal_text(pico_usd: int) -> str:
    clean_pico = integer(pico_usd, "pico_usd", minimum=0)
    return decimal_text(Decimal(clean_pico) / Decimal(1_000_000_000_000))


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
        raise FrontierTransportError(
            f"HTTP redirect {code} refused for outbound AI request",
            status_code=int(code),
            retryable=False,
        )

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        raise FrontierTransportError(
            f"HTTP redirect {code} refused for outbound AI request",
            status_code=int(code),
            retryable=False,
        )

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

    ctx = get_cached_tls12_ssl_context()
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
        code = int(exc.code)
        raise FrontierTransportError(
            f"frontier AI HTTP status {code}",
            status_code=code,
            retryable=(code == 429 or 500 <= code <= 599),
        ) from None
    except FrontierTransportError:
        raise
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        raise FrontierTransportError(
            f"frontier AI connection error: {type(exc).__name__}",
            retryable=True,
        ) from None
    finally:
        req.headers.clear()
        req.unredirected_hdrs.clear()
    if len(raw) > max_wire_bytes:
        raise FrontierTransportError("frontier AI response exceeded byte limit")
    return status, raw


OLLAMA_SUPERVISOR_AUTH_HEADER = "X-CAS-Ollama-Supervisor-Token"
OLLAMA_RECEIPT_DOMAIN = b"cas-forex-supervised-ollama-receipt-v1\x00"
OLLAMA_RECEIPT_ALGORITHMS = frozenset({"Ed25519", "HMAC-SHA256"})


def _is_ollama_model_id(model_id: str | None) -> bool:
    if not isinstance(model_id, str):
        return False
    low = model_id.strip().lower().removeprefix("models/")
    return low in LOCAL_ZERO_COST_MODELS or low in ("qwen3:0.6b", "qwen3-0.6b", "cas-qwen3-0.6b")


def reject_preexisting_ollama_listener(
    host: str = "127.0.0.1",
    port: int = 11434,
    *,
    timeout_seconds: float = 0.25,
) -> None:
    """Fail closed if a pre-existing foreign listener is already bound on (host, port)."""
    clean_port = integer(port, "port", minimum=1)
    if clean_port > 65535:
        raise FrontierConfigurationError("port must be in 1..65535")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(max(0.05, float(timeout_seconds)))
        rc = sock.connect_ex((host, clean_port))
    if rc == 0:
        raise FrontierConfigurationError(
            f"OLLAMA_PREEXISTING_FOREIGN_LISTENER: refused pre-existing listener at {host}:{clean_port}"
        )


def _hash_artifact_file(path: Path, label: str) -> str:
    if not isinstance(path, Path):
        raise FrontierTransportError(f"OLLAMA_ARTIFACT_INVALID_PATH: {label}")
    if path.is_symlink() or not path.is_file():
        raise FrontierTransportError(f"OLLAMA_ARTIFACT_MISSING_OR_SYMLINK: {label}")
    h = sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        raise FrontierTransportError(f"OLLAMA_ARTIFACT_READ_FAILED: {label} ({type(exc).__name__})") from None
    return h.hexdigest()


def _verify_pid_alive(pid: int, start_time: str) -> bool:
    if type(pid) is not int or pid <= 0:
        return False
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        if start_time.startswith("bootticks:"):
            expected_ticks = start_time[len("bootticks:"):].strip()
            try:
                raw = Path(f"/proc/{pid}/stat").read_bytes()
                end = raw.rfind(b")")
                if end <= 0:
                    return False
                fields = raw[end + 2:].split()
                actual_ticks = fields[19].decode("ascii")
                return hmac.compare_digest(actual_ticks, expected_ticks)
            except (OSError, IndexError, UnicodeDecodeError):
                return False
        return True
    # On Windows, confirm current process or query process liveness via kernel32.
    if pid == os.getpid():
        return True
    try:
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong(0)
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            return bool(ok and exit_code.value == 259)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return False


def _receipt_signing_payload(
    *,
    receipt_id: str,
    invocation_sha256: str,
    model_id: str,
    artifact_sha256: str,
    response_sha256: str,
    pid: int,
    start_time: str,
) -> bytes:
    body = {
        "artifact_sha256": artifact_sha256,
        "invocation_sha256": invocation_sha256,
        "model_id": model_id,
        "pid": pid,
        "receipt_id": receipt_id,
        "response_sha256": response_sha256,
        "start_time": start_time,
    }
    return OLLAMA_RECEIPT_DOMAIN + canonical_bytes(body)


class SupervisedOllamaReceiptSigner:
    """Independent supervisor-held receipt signer (NEVER passed to FrontierChatBackend)."""

    def __init__(
        self,
        *,
        algorithm: str = "Ed25519",
        signing_key: bytes,
        pid: int,
        start_time: str,
    ) -> None:
        if algorithm not in OLLAMA_RECEIPT_ALGORITHMS:
            raise FrontierConfigurationError(f"receipt algorithm must be one of {sorted(OLLAMA_RECEIPT_ALGORITHMS)}")
        if not isinstance(signing_key, (bytes, bytearray)):
            raise FrontierConfigurationError("signing_key must be bytes")
        raw_key = bytes(signing_key)
        if len(raw_key) < 32:
            raise FrontierConfigurationError("signing_key must be at least 32 bytes")
        if algorithm == "Ed25519" and len(raw_key) != 32:
            raise FrontierConfigurationError("Ed25519 private signing_key must be 32 raw seed bytes")
        self._algorithm = algorithm
        self._signing_key = raw_key
        self._pid = integer(pid, "pid", minimum=1)
        if not isinstance(start_time, str) or not start_time.strip():
            raise FrontierConfigurationError("start_time must be a non-empty string")
        self._start_time = start_time.strip()

    def __repr__(self) -> str:
        return f"SupervisedOllamaReceiptSigner(algorithm={self._algorithm!r}, pid={self._pid}, redacted=True)"

    def public_verify_key(self) -> bytes:
        if self._algorithm == "Ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            priv = Ed25519PrivateKey.from_private_bytes(self._signing_key)
            return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return self._signing_key

    def sign_receipt(
        self,
        *,
        receipt_id: str,
        invocation_sha256: str,
        model_id: str,
        artifact_sha256: str,
        response_sha256: str,
    ) -> dict[str, Any]:
        digest(invocation_sha256, "invocation_sha256")
        digest(artifact_sha256, "artifact_sha256")
        digest(response_sha256, "response_sha256")
        msg = _receipt_signing_payload(
            receipt_id=receipt_id,
            invocation_sha256=invocation_sha256,
            model_id=model_id,
            artifact_sha256=artifact_sha256,
            response_sha256=response_sha256,
            pid=self._pid,
            start_time=self._start_time,
        )
        if self._algorithm == "Ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            sig = Ed25519PrivateKey.from_private_bytes(self._signing_key).sign(msg)
        else:
            sig = hmac.new(self._signing_key, msg, sha256).digest()
        return {
            "algorithm": self._algorithm,
            "receipt_id": receipt_id,
            "invocation_sha256": invocation_sha256,
            "model_id": model_id,
            "artifact_sha256": artifact_sha256,
            "response_sha256": response_sha256,
            "pid": self._pid,
            "start_time": self._start_time,
            "signature_hex": sig.hex(),
        }


@dataclass(frozen=True, slots=True)
class SupervisedOllamaBinding:
    """Explicit supervised local Ollama handle binding process, artifacts, auth secret, and receipt key."""

    pid: int
    start_time: str
    executable_sha256: str
    model_manifest_sha256: str
    weights_sha256: str
    template_sha256: str
    tokenizer_sha256: str
    endpoint_url: str
    auth_secret: _RedactedSecret | str
    receipt_verify_key: bytes
    receipt_algorithm: str = "Ed25519"
    model_id: str = "qwen3:0.6b"
    executable_path: Path | None = None
    manifest_path: Path | None = None
    weights_path: Path | None = None
    template_path: Path | None = None
    tokenizer_path: Path | None = None
    process_verifier: Callable[["SupervisedOllamaBinding"], bool] | None = None
    artifact_verifier: Callable[["SupervisedOllamaBinding"], bool] | None = None
    listener_ownership_verifier: Callable[["SupervisedOllamaBinding"], bool] | None = None

    def __post_init__(self) -> None:
        integer(self.pid, "pid", minimum=1)
        if not isinstance(self.start_time, str) or not self.start_time.strip():
            raise FrontierConfigurationError("SupervisedOllamaBinding requires non-empty start_time")
        for field_name in (
            "executable_sha256",
            "model_manifest_sha256",
            "weights_sha256",
            "template_sha256",
            "tokenizer_sha256",
        ):
            digest(getattr(self, field_name), field_name)
        _validate_slug(self.model_id, "SupervisedOllamaBinding.model_id")
        if self.receipt_algorithm not in OLLAMA_RECEIPT_ALGORITHMS:
            raise FrontierConfigurationError(
                f"receipt_algorithm must be one of {sorted(OLLAMA_RECEIPT_ALGORITHMS)}"
            )
        if not isinstance(self.receipt_verify_key, (bytes, bytearray)):
            raise FrontierConfigurationError("receipt_verify_key must be bytes")
        vkey = bytes(self.receipt_verify_key)
        if self.receipt_algorithm == "Ed25519" and len(vkey) != 32:
            raise FrontierConfigurationError("Ed25519 receipt_verify_key must be 32 raw public key bytes")
        if self.receipt_algorithm == "HMAC-SHA256" and len(vkey) < 32:
            raise FrontierConfigurationError("HMAC-SHA256 receipt_verify_key must be at least 32 bytes")
        object.__setattr__(self, "receipt_verify_key", vkey)

        if isinstance(self.auth_secret, _RedactedSecret):
            raw_secret = self.auth_secret.reveal_for_header()
            sec_obj = self.auth_secret
        elif isinstance(self.auth_secret, str):
            raw_secret = self.auth_secret.strip()
            sec_obj = _RedactedSecret(raw_secret)
        else:
            raise FrontierConfigurationError("auth_secret must be a non-empty string or _RedactedSecret")
        if len(raw_secret) < 32:
            raise FrontierConfigurationError(
                "SupervisedOllamaBinding auth_secret must be at least 32 high-entropy characters"
            )
        object.__setattr__(self, "auth_secret", sec_obj)

        # Validate per-launch supervised endpoint; strictly forbid shared default 127.0.0.1:11434!
        if not isinstance(self.endpoint_url, str) or not self.endpoint_url.strip():
            raise FrontierConfigurationError("SupervisedOllamaBinding requires endpoint_url")
        ep = self.endpoint_url.strip()
        if ep.startswith("unix://"):
            sock_path_str = ep[len("unix://"):]
            if not sock_path_str or ".." in Path(sock_path_str).parts or not Path(sock_path_str).is_absolute():
                raise FrontierConfigurationError("unix:// Ollama endpoint must be an absolute normalized socket path")
        else:
            parsed = urllib.parse.urlsplit(ep)
            if (
                parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or parsed.port is None
                or parsed.path != "/api/chat"
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise FrontierConfigurationError(
                    "SupervisedOllamaBinding endpoint_url must be http://127.0.0.1:<dedicated_port>/api/chat or unix://<abs_path>"
                )
            if int(parsed.port) == 11434 or not (1024 <= int(parsed.port) <= 65535):
                raise FrontierConfigurationError(
                    "OLLAMA_SHARED_DEFAULT_PORT_FORBIDDEN: 127.0.0.1:11434 is forbidden; bind a dedicated supervised port"
                )

    def __repr__(self) -> str:
        return (
            f"SupervisedOllamaBinding(pid={self.pid}, model_id={self.model_id!r}, "
            f"endpoint_url={self.endpoint_url!r}, redacted=True)"
        )

    def auth_headers(self) -> dict[str, str]:
        sec = self.auth_secret
        raw = sec.reveal_for_header() if isinstance(sec, _RedactedSecret) else str(sec)
        return {OLLAMA_SUPERVISOR_AUTH_HEADER: raw}

    def artifact_digest(self) -> str:
        return content_digest({
            "endpoint_url": self.endpoint_url,
            "executable_sha256": self.executable_sha256,
            "model_id": self.model_id,
            "model_manifest_sha256": self.model_manifest_sha256,
            "pid": self.pid,
            "start_time": self.start_time,
            "template_sha256": self.template_sha256,
            "tokenizer_sha256": self.tokenizer_sha256,
            "weights_sha256": self.weights_sha256,
        })

    def verify_artifacts(self) -> None:
        if self.artifact_verifier is not None:
            if self.artifact_verifier(self) is not True:
                raise FrontierTransportError("OLLAMA_ARTIFACT_VERIFICATION_FAILED: supervised model artifacts rejected")
        path_checks = (
            ("executable", self.executable_path, self.executable_sha256),
            ("manifest", self.manifest_path, self.model_manifest_sha256),
            ("weights", self.weights_path, self.weights_sha256),
            ("template", self.template_path, self.template_sha256),
            ("tokenizer", self.tokenizer_path, self.tokenizer_sha256),
        )
        for label, fpath, expected_sha in path_checks:
            if fpath is not None:
                actual_sha = _hash_artifact_file(Path(fpath), label)
                if not hmac.compare_digest(actual_sha, expected_sha):
                    raise FrontierTransportError(
                        f"OLLAMA_ARTIFACT_HASH_MISMATCH: {label} digest mismatch"
                    )

    def verify_process_and_listener(self) -> None:
        if self.process_verifier is not None:
            if self.process_verifier(self) is not True:
                raise FrontierTransportError("OLLAMA_PROCESS_IDENTITY_MISMATCH: supervised process verification failed")
        elif not _verify_pid_alive(self.pid, self.start_time):
            raise FrontierTransportError(
                f"OLLAMA_PROCESS_IDENTITY_MISMATCH: bound pid {self.pid} is not active or start_time mismatched"
            )
        if self.listener_ownership_verifier is not None:
            if self.listener_ownership_verifier(self) is not True:
                raise FrontierTransportError(
                    "OLLAMA_FOREIGN_LISTENER_DETECTED: endpoint listener does not match supervised process"
                )
        if self.endpoint_url.startswith("unix://") and os.name == "posix":
            sock_path = Path(self.endpoint_url[len("unix://"):])
            try:
                st = sock_path.lstat()
            except OSError:
                raise FrontierTransportError("OLLAMA_UNIX_SOCKET_MISSING: bound socket unavailable") from None
            if (
                not stat.S_ISSOCK(st.st_mode)
                or st.st_uid != os.getuid()
                or (st.st_mode & 0o077) != 0
            ):
                raise FrontierTransportError(
                    "OLLAMA_UNIX_SOCKET_CUSTODY_FAILED: socket must be owner-only 0600"
                )

    def verify_binding(self) -> None:
        self.verify_process_and_listener()
        self.verify_artifacts()

    def is_bound_and_verified(self) -> bool:
        try:
            self.verify_binding()
            return True
        except Exception:
            return False


def verify_supervised_ollama_receipt(
    receipt: Mapping[str, Any] | None,
    *,
    binding: SupervisedOllamaBinding,
    reply: InferenceReply,
    invocation: ModelInvocation,
) -> bool:
    """Cryptographically verify an independently signed supervisor invocation receipt."""
    if not isinstance(receipt, Mapping):
        return False
    expected_inv_sha = content_digest(invocation)
    expected_resp_sha = sha256(reply.raw_selection_json.encode("utf-8")).hexdigest()
    if receipt.get("algorithm") != binding.receipt_algorithm:
        return False
    if receipt.get("receipt_id") != reply.receipt_id:
        return False
    if receipt.get("invocation_sha256") != expected_inv_sha or reply.invocation_sha256 != expected_inv_sha:
        return False
    if receipt.get("model_id") != invocation.model.model_id or reply.model.model_id != invocation.model.model_id:
        return False
    if (
        receipt.get("artifact_sha256") != invocation.model.artifact_sha256
        or reply.model.artifact_sha256 != invocation.model.artifact_sha256
    ):
        return False
    if receipt.get("response_sha256") != expected_resp_sha:
        return False
    if receipt.get("pid") != binding.pid or receipt.get("start_time") != binding.start_time:
        return False
    sig_hex = receipt.get("signature_hex")
    if not isinstance(sig_hex, str) or not sig_hex.strip():
        return False
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    msg = _receipt_signing_payload(
        receipt_id=reply.receipt_id,
        invocation_sha256=expected_inv_sha,
        model_id=invocation.model.model_id,
        artifact_sha256=invocation.model.artifact_sha256,
        response_sha256=expected_resp_sha,
        pid=binding.pid,
        start_time=binding.start_time,
    )
    if binding.receipt_algorithm == "Ed25519":
        if len(sig_bytes) != 64:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(binding.receipt_verify_key).verify(sig_bytes, msg)
            return True
        except Exception:
            return False
    expected_mac = hmac.new(binding.receipt_verify_key, msg, sha256).digest()
    return len(sig_bytes) == 32 and hmac.compare_digest(expected_mac, sig_bytes)


class _UnixSupervisedHttpConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, *, expected_pid: int, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path
        self._expected_pid = expected_pid

    def connect(self) -> None:
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise FrontierTransportError("Unix domain socket transport requires POSIX")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._socket_path)
            if hasattr(socket, "SO_PEERCRED"):
                creds = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if creds[0] != self._expected_pid or creds[1] != os.getuid():
                    raise FrontierTransportError(
                        "OLLAMA_FOREIGN_LISTENER_DETECTED: Unix socket peer PID/UID mismatch"
                    )
        except Exception:
            sock.close()
            raise
        self.sock = sock


class _LoopbackSupervisedHttpConnection(http.client.HTTPConnection):
    """Direct 127.0.0.1 TCP connection ignoring all ambient HTTP_PROXY/ALL_PROXY variables (Finding [14])."""

    def __init__(
        self,
        port: int,
        *,
        supervised_binding: SupervisedOllamaBinding,
        timeout: float,
    ) -> None:
        super().__init__("127.0.0.1", port=port, timeout=timeout)
        self._target_port = int(port)
        self._supervised_binding = supervised_binding

    def connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(("127.0.0.1", self._target_port))
            peer = sock.getpeername()
            peer_ip = str(peer[0]) if isinstance(peer, tuple) and len(peer) >= 2 else ""
            peer_port = int(peer[1]) if isinstance(peer, tuple) and len(peer) >= 2 else -1
            if peer_ip != "127.0.0.1" or peer_port != self._target_port:
                raise FrontierTransportError(
                    f"OLLAMA_NON_LOOPBACK_PEER_REFUSED: connected peer {peer_ip}:{peer_port} != 127.0.0.1:{self._target_port}",
                    retryable=False,
                )
            self._supervised_binding.verify_binding()
        except Exception:
            sock.close()
            raise
        self.sock = sock


def default_ollama_loopback_post(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: float,
    max_wire_bytes: int,
    *,
    supervised_binding: SupervisedOllamaBinding | None = None,
) -> tuple[int, bytes]:
    """Execute one authenticated POST strictly to a verified SupervisedOllamaBinding endpoint (zero proxy leak)."""
    if supervised_binding is None:
        raise FrontierConfigurationError(
            "OLLAMA_UNSUPERVISED_ENDPOINT_FORBIDDEN: unauthenticated 127.0.0.1:11434 fallback is forbidden; SupervisedOllamaBinding required"
        )
    supervised_binding.verify_binding()
    if url != supervised_binding.endpoint_url:
        raise FrontierConfigurationError(
            "Ollama fallback URL must exactly match SupervisedOllamaBinding.endpoint_url"
        )

    req_headers = dict(headers)
    req_headers.update(supervised_binding.auth_headers())

    if url.startswith("unix://"):
        sock_path = url[len("unix://"):]
        conn = _UnixSupervisedHttpConnection(sock_path, expected_pid=supervised_binding.pid, timeout=timeout_seconds)
        try:
            conn.request("POST", "/api/chat", body=body, headers=req_headers)
            resp = conn.getresponse()
            status = int(resp.status)
            raw = resp.read(max_wire_bytes + 1)
        except FrontierTransportError:
            raise
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            raise FrontierTransportError(
                f"Ollama supervised socket unavailable: {type(exc).__name__}",
                retryable=True,
            ) from None
        finally:
            req_headers.clear()
            conn.close()
        if len(raw) > max_wire_bytes:
            raise FrontierTransportError("Ollama fallback response exceeded byte limit")
        return status, raw

    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or int(parsed.port) == 11434
        or parsed.path != "/api/chat"
        or parsed.query
        or parsed.fragment
    ):
        req_headers.clear()
        raise FrontierConfigurationError(
            "Ollama fallback requires a dedicated supervised loopback endpoint (port 11434 forbidden)"
        )
    tcp_conn = _LoopbackSupervisedHttpConnection(
        int(parsed.port),
        supervised_binding=supervised_binding,
        timeout=timeout_seconds,
    )
    try:
        tcp_conn.request("POST", "/api/chat", body=body, headers=req_headers)
        resp = tcp_conn.getresponse()
        status = int(resp.status)
        if 300 <= status < 400:
            raise FrontierTransportError(
                f"Ollama supervised loopback redirect ({status}) is forbidden",
                status_code=status,
                retryable=False,
            )
        raw = resp.read(max_wire_bytes + 1)
        if status != 200:
            raise FrontierTransportError(
                f"Ollama fallback HTTP status {status}",
                status_code=status,
                retryable=(status == 429 or 500 <= status <= 599),
            )
    except FrontierConfigurationError:
        raise
    except FrontierTransportError:
        raise
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        raise FrontierTransportError(
            f"Ollama fallback unavailable: {type(exc).__name__}",
            retryable=True,
        ) from None
    finally:
        req_headers.clear()
        tcp_conn.close()
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
        if not prob.is_finite():
            raise ValueError("non-finite probability")
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
        cand_out = _safe_non_neg_int(usage.get("output_tokens"))
        out_tok = cand_out if cand_out is not None else max(1, len(str(text or "").encode("utf-8")) // 4)
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
        cand_out = _safe_non_neg_int(meta.get("candidatesTokenCount"))
        out_tok = cand_out if cand_out is not None else max(1, len(str(text or "").encode("utf-8")) // 4)
    elif provider in ("openai", "deepseek"):
        choices = doc.get("choices")
        if type(choices) is not list or not choices:
            raise FrontierTransportError(f"{provider} response missing choices")
        msg = choices[0].get("message") if type(choices[0]) is dict else None
        text = msg.get("content") if type(msg) is dict else None
        usage = doc.get("usage") if type(doc.get("usage")) is dict else {}
        cand_out = _safe_non_neg_int(usage.get("completion_tokens"))
        out_tok = cand_out if cand_out is not None else max(1, len(str(text or "").encode("utf-8")) // 4)
    elif provider == "ollama":
        msg = doc.get("message") if type(doc.get("message")) is dict else {}
        text = msg.get("content", doc.get("response"))
        cand_out = _safe_non_neg_int(doc.get("eval_count"))
        out_tok = cand_out if cand_out is not None else max(1, len(str(text or "").encode("utf-8")) // 4)
    else:
        raise FrontierConfigurationError(f"unsupported provider {provider!r}")

    if not isinstance(text, str) or not text.strip():
        raise FrontierTransportError(f"{provider} returned empty selection text")
    return _strip_optional_json_fence(text), max(1, out_tok), None


def _safe_non_neg_int(value: Any) -> int | None:
    if type(value) is int and value >= 0:
        return value
    return None


def _extract_provider_input_units(
    provider: str,
    doc: Mapping[str, Any],
    *,
    fallback_input_units: int,
) -> int:
    if provider == "anthropic":
        usage = doc.get("usage")
        if isinstance(usage, Mapping):
            base = _safe_non_neg_int(usage.get("input_tokens"))
            if base is not None:
                cache_create = _safe_non_neg_int(usage.get("cache_creation_input_tokens")) or 0
                cache_read = _safe_non_neg_int(usage.get("cache_read_input_tokens")) or 0
                return base + cache_create + cache_read
    elif provider in ("gemini", "gemini_decision"):
        meta = doc.get("usageMetadata")
        if isinstance(meta, Mapping):
            prompt_cnt = _safe_non_neg_int(meta.get("promptTokenCount"))
            if prompt_cnt is not None:
                return prompt_cnt
        if provider == "gemini_decision":
            usage = doc.get("usage")
            if isinstance(usage, Mapping):
                for key in ("input_tokens", "prompt_tokens"):
                    cnt = _safe_non_neg_int(usage.get(key))
                    if cnt is not None:
                        return cnt
    elif provider in ("openai", "deepseek"):
        usage = doc.get("usage")
        if isinstance(usage, Mapping):
            prompt_cnt = _safe_non_neg_int(usage.get("prompt_tokens"))
            if prompt_cnt is not None:
                return prompt_cnt
    elif provider == "ollama":
        prompt_cnt = _safe_non_neg_int(doc.get("prompt_eval_count"))
        if prompt_cnt is not None:
            return prompt_cnt
    return max(0, int(fallback_input_units))


def _extract_confirmed_provider_usage(
    provider: str,
    doc: Mapping[str, Any],
) -> tuple[int, int] | None:
    """Return provider-reported (input_tokens, output_tokens) ONLY when explicitly attested."""
    if provider == "anthropic":
        usage = doc.get("usage")
        if isinstance(usage, Mapping):
            in_tok = _safe_non_neg_int(usage.get("input_tokens"))
            out_tok = _safe_non_neg_int(usage.get("output_tokens"))
            if in_tok is not None and out_tok is not None:
                cache_create = _safe_non_neg_int(usage.get("cache_creation_input_tokens")) or 0
                cache_read = _safe_non_neg_int(usage.get("cache_read_input_tokens")) or 0
                return in_tok + cache_create + cache_read, out_tok
        return None
    if provider == "gemini":
        meta = doc.get("usageMetadata")
        if isinstance(meta, Mapping):
            in_tok = _safe_non_neg_int(meta.get("promptTokenCount"))
            cand_tok = _safe_non_neg_int(meta.get("candidatesTokenCount"))
            if in_tok is not None and cand_tok is not None:
                thought_tok = _safe_non_neg_int(meta.get("thoughtsTokenCount")) or 0
                return in_tok, cand_tok + thought_tok
        return None
    if provider == "gemini_decision":
        meta = doc.get("usageMetadata")
        if isinstance(meta, Mapping):
            in_tok = _safe_non_neg_int(meta.get("promptTokenCount"))
            if in_tok is not None:
                return in_tok, 0
        usage = doc.get("usage")
        if isinstance(usage, Mapping):
            for key in ("input_tokens", "prompt_tokens"):
                in_tok = _safe_non_neg_int(usage.get(key))
                if in_tok is not None:
                    return in_tok, 0
        return None
    if provider in ("openai", "deepseek"):
        usage = doc.get("usage")
        if isinstance(usage, Mapping):
            in_tok = _safe_non_neg_int(usage.get("prompt_tokens"))
            out_tok = _safe_non_neg_int(usage.get("completion_tokens"))
            if in_tok is not None and out_tok is not None:
                return in_tok, out_tok
        return None
    if provider == "ollama":
        in_tok = _safe_non_neg_int(doc.get("prompt_eval_count"))
        out_tok = _safe_non_neg_int(doc.get("eval_count"))
        if in_tok is not None and out_tok is not None:
            return in_tok, out_tok
        return None
    return None


def _effective_max_output_tokens(
    entry: FrontierModelCatalogEntry,
    api_slug: str,
    invocation: ModelInvocation,
) -> int:
    """Return the exact worst-case billable output tokens implied by the wire request."""
    max_tokens = int(invocation.budget.max_generated_tokens_per_call)
    effort = str(getattr(invocation.model, "reasoning_effort", "low") or "low").strip().lower()
    if entry.provider == "anthropic":
        low_slug = api_slug.lower()
        is_legacy_claude = "-4-" in low_slug or low_slug.endswith("-4") or low_slug.startswith("claude-3")
        if is_legacy_claude:
            if effort in ("medium", "high"):
                think_budget = 2048 if effort == "medium" else 6144
                return max(max_tokens, think_budget + 1024)
            return max_tokens
        ant_effort = effort if effort in ("low", "medium", "high") else "low"
        min_tok = 1024 if ant_effort == "low" else (4096 if ant_effort == "medium" else 8192)
        return max(max_tokens, min_tok)
    if entry.provider == "gemini_decision":
        return 0
    if entry.provider == "gemini":
        think_budget = 2048 if effort == "medium" else (6144 if effort == "high" else 256)
        return max_tokens + think_budget
    return max_tokens


def _is_retryable_http_status(status_code: int) -> bool:
    return status_code == 429 or 500 <= status_code <= 599


def _classify_transport_error(exc: FrontierTransportError) -> tuple[bool, int | None, bool]:
    """Return (retryable, status_code, availability_failure) for a FrontierTransportError."""
    if isinstance(exc, FrontierCircuitOpenError):
        return False, None, False
    if exc.status_code is not None:
        code = int(exc.status_code)
        if 300 <= code < 400:
            return False, code, False
        retryable = _is_retryable_http_status(code)
        return retryable, code, retryable
    if exc.retryable:
        return True, None, True
    msg = str(exc)
    if (
        "refused non-public IP" in msg
        or "HTTP redirect" in msg
        or "exceeded byte limit" in msg
        or "requires CAS_FOREX_" in msg
    ):
        return False, None, False
    m = _HTTP_STATUS_RE.search(msg)
    if m is not None:
        code = int(m.group(1))
        if 300 <= code < 400:
            return False, code, False
        retryable = _is_retryable_http_status(code)
        return retryable, code, retryable
    if "connection error" in msg or "unavailable" in msg:
        return True, None, True
    if "JSON" in msg or "missing" in msg or "empty" in msg or "non-JSON" in msg:
        return False, None, True
    return False, None, False


def _deterministic_jitter_seconds(
    *,
    provider: str,
    idempotency_key: str,
    attempt: int,
    base_delay: Decimal,
    max_delay: Decimal,
) -> Decimal:
    if base_delay <= 0 or max_delay <= 0:
        return Decimal("0")
    exp = min(max_delay, base_delay * (Decimal(2) ** max(0, attempt - 1)))
    digest_bytes = sha256(f"{provider}:{idempotency_key}:{attempt}".encode("utf-8")).digest()
    frac = Decimal(int.from_bytes(digest_bytes[:4], "big")) / Decimal(0xFFFFFFFF)
    delay = exp * (Decimal("0.5") + Decimal("0.5") * frac)
    return delay.quantize(Decimal("0.000001"))


@dataclass(slots=True)
class _ProviderBreakerSlot:
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    consecutive_failures: int = 0
    open_trips: int = 0
    opened_at: datetime | None = None
    cooldown_until: datetime | None = None
    half_open_in_flight: bool = False
    last_error: str | None = None


class ProviderCircuitBreaker:
    """Thread-safe per-provider circuit breaker (CLOSED -> OPEN -> HALF_OPEN)."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        config: CircuitBreakerConfig | None = None,
        providers: tuple[str, ...] = FRONTIER_PROVIDERS,
    ) -> None:
        self._clock = clock or _utc_now
        self._config = config or CircuitBreakerConfig()
        self._lock = Lock()
        self._slots: dict[str, _ProviderBreakerSlot] = {p: _ProviderBreakerSlot() for p in providers}

    def _slot(self, provider: str) -> _ProviderBreakerSlot:
        slot = self._slots.get(provider)
        if slot is None:
            slot = _ProviderBreakerSlot()
            self._slots[provider] = slot
        return slot

    def before_call(self, provider: str) -> bool:
        """Check breaker state before I/O. Returns True if caller holds the single HALF_OPEN probe."""
        with self._lock:
            now = utc_time(self._clock(), "circuit_clock")
            slot = self._slot(provider)
            if slot.state == CircuitBreakerState.CLOSED:
                return False
            if slot.state == CircuitBreakerState.OPEN:
                if slot.cooldown_until is not None and now < slot.cooldown_until:
                    raise FrontierCircuitOpenError(
                        f"provider {provider!r} circuit is OPEN until {slot.cooldown_until.isoformat()}",
                        provider=provider,
                    )
                slot.state = CircuitBreakerState.HALF_OPEN
                slot.half_open_in_flight = True
                return True
            if slot.half_open_in_flight:
                raise FrontierCircuitOpenError(
                    f"provider {provider!r} circuit HALF_OPEN probe already in flight",
                    provider=provider,
                )
            slot.half_open_in_flight = True
            return True

    def record_success(self, provider: str) -> None:
        with self._lock:
            slot = self._slot(provider)
            slot.state = CircuitBreakerState.CLOSED
            slot.consecutive_failures = 0
            slot.opened_at = None
            slot.cooldown_until = None
            slot.half_open_in_flight = False
            slot.last_error = None

    def record_failure(
        self,
        provider: str,
        *,
        reason: str,
        availability_failure: bool = True,
    ) -> None:
        with self._lock:
            now = utc_time(self._clock(), "circuit_clock")
            slot = self._slot(provider)
            was_half_open = slot.state == CircuitBreakerState.HALF_OPEN
            slot.half_open_in_flight = False
            slot.last_error = str(reason)[:160]
            if not was_half_open and not availability_failure:
                return
            slot.consecutive_failures += 1
            if was_half_open or slot.consecutive_failures >= self._config.failure_threshold:
                cooldown_us = int(
                    (self._config.cooldown_seconds * Decimal(1_000_000)).to_integral_value(rounding=ROUND_HALF_UP)
                )
                slot.state = CircuitBreakerState.OPEN
                slot.opened_at = now
                slot.cooldown_until = now + timedelta(microseconds=cooldown_us)
                slot.open_trips += 1

    def release_probe_on_abort(self, provider: str) -> None:
        with self._lock:
            slot = self._slot(provider)
            if slot.state == CircuitBreakerState.HALF_OPEN and slot.half_open_in_flight:
                slot.half_open_in_flight = False

    def state_of(self, provider: str) -> CircuitBreakerState:
        with self._lock:
            return self._slot(provider).state

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                provider: {
                    "state": slot.state.value,
                    "consecutive_failures": slot.consecutive_failures,
                    "open_trips": slot.open_trips,
                    "opened_at": slot.opened_at.isoformat() if slot.opened_at is not None else None,
                    "cooldown_until": slot.cooldown_until.isoformat() if slot.cooldown_until is not None else None,
                    "half_open_in_flight": slot.half_open_in_flight,
                    "last_error": slot.last_error,
                }
                for provider, slot in self._slots.items()
            }


def execute_resilient_frontier_call(
    *,
    operation_kind: FrontierOperationKind,
    provider: str,
    circuit_breaker: ProviderCircuitBreaker,
    retry_policy: RetryPolicy,
    clock: Callable[[], datetime],
    sleep: Callable[[float], None],
    budget_seconds: Decimal,
    idempotency_key: str,
    attempt_fn: Callable[[float], _T],
    manage_breaker: bool = True,
    is_probe_override: bool | None = None,
) -> _T:
    """Execute a frontier call with circuit breaker, bounded deterministic retry (READ_* only), and budget cap."""
    if not isinstance(operation_kind, FrontierOperationKind):
        raise FrontierConfigurationError(f"unsupported FrontierOperationKind {operation_kind!r}")
    decimal_value(budget_seconds, "budget_seconds", positive=True)

    if manage_breaker:
        is_probe = circuit_breaker.before_call(provider)
    else:
        is_probe = bool(is_probe_override)

    # Strict safety invariant: NEVER retry UNSAFE_WRITE or HALF_OPEN probes.
    if operation_kind not in _IDEMPOTENT_READ_OPERATIONS or is_probe:
        effective_max_attempts = 1
    else:
        effective_max_attempts = retry_policy.max_attempts

    start_now = utc_time(clock(), "resilient_start")
    budget_us = int((budget_seconds * Decimal(1_000_000)).to_integral_value(rounding=ROUND_HALF_UP))
    deadline = start_now + timedelta(microseconds=max(1, budget_us))
    breaker_settled = not manage_breaker
    last_exc: FrontierTransportError | None = None

    try:
        for attempt in range(1, effective_max_attempts + 1):
            now = utc_time(clock(), "resilient_attempt")
            rem_s = (deadline - now).total_seconds()
            if rem_s <= 0.0 and attempt > 1:
                break
            attempt_timeout = max(0.001, min(float(budget_seconds), rem_s if rem_s > 0.0 else float(budget_seconds)))
            try:
                result = attempt_fn(attempt_timeout)
            except FrontierTransportError as exc:
                last_exc = exc
                retryable, _, availability_failure = _classify_transport_error(exc)
                if retryable and attempt < effective_max_attempts:
                    delay_s = _deterministic_jitter_seconds(
                        provider=provider,
                        idempotency_key=idempotency_key,
                        attempt=attempt,
                        base_delay=retry_policy.base_delay_seconds,
                        max_delay=retry_policy.max_delay_seconds,
                    )
                    now_before_sleep = utc_time(clock(), "resilient_backoff")
                    rem_before_sleep = Decimal(str((deadline - now_before_sleep).total_seconds()))
                    if rem_before_sleep <= delay_s or rem_before_sleep <= Decimal("0"):
                        break
                    if delay_s > 0:
                        sleep(float(delay_s))
                    now_after_sleep = utc_time(clock(), "resilient_after_sleep")
                    if now_after_sleep >= deadline:
                        break
                    continue
                if manage_breaker:
                    circuit_breaker.record_failure(
                        provider,
                        reason=str(exc),
                        availability_failure=availability_failure,
                    )
                    breaker_settled = True
                raise
            except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
                wrapped = FrontierTransportError(
                    f"frontier AI connection error: {type(exc).__name__}",
                    retryable=True,
                )
                last_exc = wrapped
                if attempt < effective_max_attempts:
                    delay_s = _deterministic_jitter_seconds(
                        provider=provider,
                        idempotency_key=idempotency_key,
                        attempt=attempt,
                        base_delay=retry_policy.base_delay_seconds,
                        max_delay=retry_policy.max_delay_seconds,
                    )
                    now_before_sleep = utc_time(clock(), "resilient_backoff")
                    rem_before_sleep = Decimal(str((deadline - now_before_sleep).total_seconds()))
                    if rem_before_sleep <= delay_s or rem_before_sleep <= Decimal("0"):
                        break
                    if delay_s > 0:
                        sleep(float(delay_s))
                    now_after_sleep = utc_time(clock(), "resilient_after_sleep")
                    if now_after_sleep >= deadline:
                        break
                    continue
                if manage_breaker:
                    circuit_breaker.record_failure(
                        provider,
                        reason=str(wrapped),
                        availability_failure=True,
                    )
                    breaker_settled = True
                raise wrapped from None

            if manage_breaker:
                circuit_breaker.record_success(provider)
                breaker_settled = True
            return result

        final_exc = last_exc if last_exc is not None else FrontierTransportError("frontier call exceeded call budget", retryable=True)
        _, _, availability_failure = _classify_transport_error(final_exc)
        if manage_breaker and not breaker_settled:
            circuit_breaker.record_failure(
                provider,
                reason=str(final_exc),
                availability_failure=availability_failure,
            )
            breaker_settled = True
        raise final_exc
    finally:
        if manage_breaker and is_probe and not breaker_settled:
            circuit_breaker.release_probe_on_abort(provider)


def _build_provider_payload(
    entry: FrontierModelCatalogEntry,
    api_slug: str,
    invocation: ModelInvocation,
    secret: _RedactedSecret | None,
    *,
    supervised_ollama: SupervisedOllamaBinding | None = None,
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
        else:
            gen_cfg["thinkingConfig"] = {"thinkingBudget": 256}
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
        if supervised_ollama is None:
            raise FrontierConfigurationError(
                "OLLAMA_UNSUPERVISED_ENDPOINT_FORBIDDEN: SupervisedOllamaBinding required for local Ollama inference"
            )
        headers.update(supervised_ollama.auth_headers())
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
        return supervised_ollama.endpoint_url, headers, canonical_bytes(body_obj)

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
    """Verifies frontier replies and requires independent supervisor signatures for local Ollama fallback."""

    def __init__(self, *, supervised_ollama: SupervisedOllamaBinding | None = None) -> None:
        self._records: dict[str, tuple[str, str, str]] = {}
        self._supervised_receipts: dict[str, dict[str, Any]] = {}
        self._supervised_ollama: SupervisedOllamaBinding | None = supervised_ollama
        self._lock = Lock()

    def bind_supervised_ollama(self, binding: SupervisedOllamaBinding | None) -> None:
        if binding is not None and not isinstance(binding, SupervisedOllamaBinding):
            raise FrontierConfigurationError("binding must be SupervisedOllamaBinding or None")
        with self._lock:
            self._supervised_ollama = binding

    def submit_supervised_receipt(self, receipt: Mapping[str, Any]) -> None:
        """Register an untrusted supervisor-signed receipt candidate for independent cryptographic verification."""
        if not isinstance(receipt, Mapping):
            raise ContractError("supervised Ollama receipt must be a JSON object")
        rid = receipt.get("receipt_id")
        if not isinstance(rid, str) or not rid.strip():
            raise ContractError("supervised Ollama receipt missing receipt_id")
        with self._lock:
            self._supervised_receipts[rid.strip()] = dict(receipt)

    def record(self, reply: InferenceReply, invocation: ModelInvocation) -> None:
        if (
            _is_ollama_model_id(reply.model.model_id)
            or _is_ollama_model_id(invocation.model.model_id)
            or reply.receipt_id.startswith("rcpt-ollama")
        ):
            raise ContractError(
                "OLLAMA_SELF_RECORDED_RECEIPT_FORBIDDEN: local Ollama receipts must be signed by the independent supervisor"
            )
        inv_sha = content_digest(invocation)
        raw_sha = sha256(reply.raw_selection_json.encode("utf-8")).hexdigest()
        with self._lock:
            self._records[reply.receipt_id] = (inv_sha, reply.model.model_id, raw_sha)

    def verify(self, reply: InferenceReply, invocation: ModelInvocation) -> bool:
        if (
            _is_ollama_model_id(reply.model.model_id)
            or _is_ollama_model_id(invocation.model.model_id)
            or reply.receipt_id.startswith("rcpt-ollama")
        ):
            with self._lock:
                binding = self._supervised_ollama
                sup_receipt = self._supervised_receipts.get(reply.receipt_id)
            if binding is None or sup_receipt is None:
                return False
            return verify_supervised_ollama_receipt(
                sup_receipt,
                binding=binding,
                reply=reply,
                invocation=invocation,
            )
        expected_inv_sha = content_digest(invocation)
        expected_raw_sha = sha256(reply.raw_selection_json.encode("utf-8")).hexdigest()
        with self._lock:
            row = self._records.get(reply.receipt_id)
        return row == (expected_inv_sha, invocation.model.model_id, expected_raw_sha)


class FrontierChatBackend(ModelBackend):
    """Concrete :class:`ModelBackend` targeting one catalog model with per-attempt spend gating."""

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
        sleep: Callable[[float], None] | None = None,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        retry_policy: RetryPolicy | None = None,
        usage_recorder: Callable[[str, int, int], None] | None = None,
        execution_gate: DurableModelExecutionGate | None = None,
        supervised_ollama: SupervisedOllamaBinding | None = None,
    ) -> None:
        self._entry = entry
        self._api_slug = api_slug
        self._model_spec = model_spec
        self._secret = secret
        self._verifier = verifier
        self._clock = clock or _utc_now
        self._sleep = sleep or time.sleep
        self._http_post = http_post
        self._resolve_dns = resolve_dns
        self._timeout = float(timeout_seconds)
        self._max_wire_bytes = integer(max_wire_bytes, "max_wire_bytes", minimum=1024)
        self._min_probability = min_probability
        self._circuit_breaker = circuit_breaker if circuit_breaker is not None else ProviderCircuitBreaker(clock=self._clock)
        self._retry_policy = retry_policy if retry_policy is not None else RetryPolicy()
        self._usage_recorder = usage_recorder
        self._execution_gate = execution_gate if isinstance(execution_gate, DurableModelExecutionGate) else None
        self._supervised_ollama = supervised_ollama
        self._seq = 0
        self._lock = Lock()
        self._decide_404: bool = False
        self.last_decision_probability: Decimal | None = None

    @property
    def manages_per_attempt_gate(self) -> bool:
        return self._execution_gate is not None

    def __repr__(self) -> str:
        return (
            f"FrontierChatBackend(model_id={self._entry.model_id!r}, "
            f"provider={self._entry.provider!r}, key='[REDACTED]')"
        )

    def count_input_tokens(self, invocation: ModelInvocation) -> int:
        return _count_bytes_tokens(invocation)

    def _dispatch_http(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        try:
            if self._entry.provider == "ollama":
                if self._supervised_ollama is None:
                    raise FrontierConfigurationError(
                        "OLLAMA_UNSUPERVISED_ENDPOINT_FORBIDDEN: SupervisedOllamaBinding required"
                    )
                self._supervised_ollama.verify_binding()
                if url != self._supervised_ollama.endpoint_url:
                    raise FrontierConfigurationError(
                        "Ollama dispatch URL must match SupervisedOllamaBinding.endpoint_url"
                    )
                if self._http_post is not None:
                    return self._http_post(url, dict(headers), body, timeout, self._max_wire_bytes)
                return default_ollama_loopback_post(
                    url,
                    dict(headers),
                    body,
                    timeout,
                    self._max_wire_bytes,
                    supervised_binding=self._supervised_ollama,
                )
            if self._http_post is not None:
                return self._http_post(url, dict(headers), body, timeout, self._max_wire_bytes)
            return default_frontier_https_post(
                url,
                dict(headers),
                body,
                timeout,
                self._max_wire_bytes,
                expected_host=self._entry.allowed_host,
                resolve_dns=self._resolve_dns,
            )
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
            raise FrontierTransportError(
                f"frontier AI connection error: {type(exc).__name__}",
                retryable=True,
            ) from None

    def _dispatch_checked(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        status, raw = self._dispatch_http(url, headers, body, timeout)
        if status < 200 or status >= 300:
            retryable = _is_retryable_http_status(int(status))
            raise FrontierTransportError(
                f"{self._entry.display_name} returned HTTP status {status}",
                status_code=int(status),
                retryable=retryable,
            )
        return status, raw

    def _reserve_and_dispatch(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout: float,
        gate_model_id: str,
        request_id: str,
        inv_sha: str,
        input_bytes: int,
        max_output_tokens: int,
        attempt_counter: list[int],
        last_reservation: list[str | None],
    ) -> tuple[int, bytes]:
        attempt_counter[0] += 1
        res_id: str | None = None
        if self._execution_gate is not None:
            res = self._execution_gate.reserve_attempt(
                model_id=gate_model_id,
                request_id=request_id,
                route_kind="decision",
                attempt_number=attempt_counter[0],
                input_chars_or_tokens=input_bytes,
                max_output_tokens=max_output_tokens,
                input_is_tokens=False,
                invocation_sha256=inv_sha,
                now=self._clock(),
            )
            res_id = str(res["reservation_id"])
            last_reservation[0] = res_id
        try:
            return self._dispatch_checked(url, headers, body, timeout)
        except Exception as exc:
            if res_id is not None and self._execution_gate is not None:
                outcome = "TIMEOUT" if isinstance(exc, TimeoutError) or "Timeout" in str(exc) else "TRANSPORT_ERROR"
                self._execution_gate.settle_attempt(res_id, outcome=outcome, now=self._clock())
                last_reservation[0] = None
            raise

    def infer(self, invocation: ModelInvocation) -> InferenceReply:
        if invocation.system_policy != SYSTEM_POLICY or invocation.output_schema_id != OUTPUT_SCHEMA_ID:
            raise ContractError("frontier backend requires canonical SYSTEM_POLICY and OUTPUT_SCHEMA_ID")
        if invocation.model != self._model_spec:
            raise ContractError("frontier backend model specification mismatch")

        started_at = utc_time(self._clock(), "started_at")
        input_tokens = self.count_input_tokens(invocation)
        inv_sha = content_digest(invocation)
        in_bytes_total = len(invocation.system_policy.encode("utf-8")) + len(invocation.packet_json.encode("utf-8"))
        timeout_dec = min(
            Decimal(str(self._timeout)),
            Decimal(str(invocation.budget.max_seconds_per_call)),
        )
        if timeout_dec <= 0:
            timeout_dec = Decimal("0.001")

        # Validate credential / supervised local binding before opening/tripping circuit breaker.
        if self._entry.provider == "ollama":
            if self._supervised_ollama is None:
                raise FrontierConfigurationError(
                    "OLLAMA_UNSUPERVISED_ENDPOINT_FORBIDDEN: SupervisedOllamaBinding required before local fallback inference"
                )
            self._supervised_ollama.verify_binding()
        if self._entry.provider == "gemini_decision" and self._secret is None:
            raise FrontierTransportError(f"{self._entry.display_name} requires {self._entry.credential_env}")
        if self._entry.provider in ("anthropic", "gemini", "openai", "deepseek") and self._secret is None:
            raise FrontierTransportError(f"{self._entry.display_name} requires {self._entry.credential_env}")

        extract_provider = self._entry.provider
        is_probe = self._circuit_breaker.before_call(self._entry.provider)
        breaker_settled = False
        attempt_counter = [0]
        last_reservation: list[str | None] = [None]

        try:
            if self._entry.provider == "gemini_decision":
                clean_slug = self._api_slug.removeprefix("models/")
                status = 404
                raw = b""
                with self._lock:
                    skip_decide = self._decide_404
                if clean_slug.startswith("gemini-decision") and not skip_decide:
                    def _attempt_decide(t_out: float) -> tuple[int, bytes]:
                        u, hdrs, b = _build_provider_payload(self._entry, self._api_slug, invocation, self._secret)
                        try:
                            return self._reserve_and_dispatch(
                                url=u,
                                headers=hdrs,
                                body=b,
                                timeout=min(t_out, 4.0),
                                gate_model_id=self._entry.model_id,
                                request_id=invocation.session_id,
                                inv_sha=inv_sha,
                                input_bytes=in_bytes_total,
                                max_output_tokens=0,
                                attempt_counter=attempt_counter,
                                last_reservation=last_reservation,
                            )
                        finally:
                            hdrs.clear()

                    try:
                        status, raw = execute_resilient_frontier_call(
                            operation_kind=FrontierOperationKind.READ_INFERENCE,
                            provider=self._entry.provider,
                            circuit_breaker=self._circuit_breaker,
                            retry_policy=self._retry_policy,
                            clock=self._clock,
                            sleep=self._sleep,
                            budget_seconds=min(timeout_dec, Decimal("4")),
                            idempotency_key=f"{inv_sha}:decide",
                            attempt_fn=_attempt_decide,
                            manage_breaker=False,
                            is_probe_override=is_probe,
                        )
                    except FrontierTransportError as exc:
                        _, err_code, availability_failure = _classify_transport_error(exc)
                        if err_code == 404:
                            status, raw = 404, b""
                        else:
                            self._circuit_breaker.record_failure(
                                self._entry.provider,
                                reason=str(exc),
                                availability_failure=availability_failure,
                            )
                            breaker_settled = True
                            raise
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
                        def _attempt_fb(t_out: float, slug_choice: str = fb_slug) -> tuple[int, bytes]:
                            fb_url, fb_hdrs, fb_body = _build_gemini_fast_json_payload(
                                clean_slug=slug_choice,
                                system_text=invocation.system_policy,
                                user_text=invocation.packet_json,
                                max_tokens=invocation.budget.max_generated_tokens_per_call,
                                secret=self._secret,
                                allowed_host=self._entry.allowed_host,
                            )
                            try:
                                return self._reserve_and_dispatch(
                                    url=fb_url,
                                    headers=fb_hdrs,
                                    body=fb_body,
                                    timeout=t_out,
                                    gate_model_id=slug_choice,
                                    request_id=invocation.session_id,
                                    inv_sha=inv_sha,
                                    input_bytes=in_bytes_total,
                                    max_output_tokens=max(128, int(invocation.budget.max_generated_tokens_per_call)),
                                    attempt_counter=attempt_counter,
                                    last_reservation=last_reservation,
                                )
                            finally:
                                fb_hdrs.clear()

                        try:
                            status, raw = execute_resilient_frontier_call(
                                operation_kind=FrontierOperationKind.READ_INFERENCE,
                                provider=self._entry.provider,
                                circuit_breaker=self._circuit_breaker,
                                retry_policy=self._retry_policy,
                                clock=self._clock,
                                sleep=self._sleep,
                                budget_seconds=timeout_dec,
                                idempotency_key=f"{inv_sha}:fb:{fb_slug}",
                                attempt_fn=_attempt_fb,
                                manage_breaker=False,
                                is_probe_override=is_probe,
                            )
                        except FrontierTransportError as exc:
                            _, err_code, availability_failure = _classify_transport_error(exc)
                            if idx_fb + 1 < len(fb_candidates) and err_code == 404:
                                status, raw = 404, b""
                                continue
                            self._circuit_breaker.record_failure(
                                self._entry.provider,
                                reason=str(exc),
                                availability_failure=availability_failure,
                            )
                            breaker_settled = True
                            raise
                        if status != 404 or idx_fb + 1 == len(fb_candidates):
                            break
                    extract_provider = "gemini"
            else:
                eff_max_out = _effective_max_output_tokens(self._entry, self._api_slug, invocation)

                def _attempt_primary(t_out: float) -> tuple[int, bytes]:
                    u, hdrs, b = _build_provider_payload(
                        self._entry,
                        self._api_slug,
                        invocation,
                        self._secret,
                        supervised_ollama=self._supervised_ollama,
                    )
                    try:
                        return self._reserve_and_dispatch(
                            url=u,
                            headers=hdrs,
                            body=b,
                            timeout=t_out,
                            gate_model_id=self._entry.model_id,
                            request_id=invocation.session_id,
                            inv_sha=inv_sha,
                            input_bytes=in_bytes_total,
                            max_output_tokens=eff_max_out,
                            attempt_counter=attempt_counter,
                            last_reservation=last_reservation,
                        )
                    finally:
                        hdrs.clear()

                try:
                    status, raw = execute_resilient_frontier_call(
                        operation_kind=FrontierOperationKind.READ_INFERENCE,
                        provider=self._entry.provider,
                        circuit_breaker=self._circuit_breaker,
                        retry_policy=self._retry_policy,
                        clock=self._clock,
                        sleep=self._sleep,
                        budget_seconds=timeout_dec,
                        idempotency_key=inv_sha,
                        attempt_fn=_attempt_primary,
                        manage_breaker=False,
                        is_probe_override=is_probe,
                    )
                except FrontierTransportError as exc:
                    _, _, availability_failure = _classify_transport_error(exc)
                    self._circuit_breaker.record_failure(
                        self._entry.provider,
                        reason=str(exc),
                        availability_failure=availability_failure,
                    )
                    breaker_settled = True
                    raise

            try:
                doc = _decode_json_dict(raw, max_bytes=self._max_wire_bytes)
                selection_text, generated_tokens, prob = _extract_provider_text_and_usage(
                    extract_provider, doc, invocation, min_probability=self._min_probability
                )
            except FrontierTransportError as exc:
                if last_reservation[0] is not None and self._execution_gate is not None:
                    self._execution_gate.settle_attempt(
                        last_reservation[0],
                        outcome="PARSE_ERROR",
                        now=self._clock(),
                    )
                    last_reservation[0] = None
                self._circuit_breaker.record_failure(
                    self._entry.provider,
                    reason=str(exc),
                    availability_failure=True,
                )
                breaker_settled = True
                raise

            if last_reservation[0] is not None and self._execution_gate is not None:
                confirmed = _extract_confirmed_provider_usage(extract_provider, doc)
                if confirmed is not None:
                    self._execution_gate.settle_attempt(
                        last_reservation[0],
                        input_tokens=confirmed[0],
                        output_tokens=confirmed[1],
                        outcome="CONFIRMED_USAGE",
                        now=self._clock(),
                    )
                else:
                    self._execution_gate.settle_attempt(
                        last_reservation[0],
                        outcome="UNKNOWN",
                        now=self._clock(),
                    )
                last_reservation[0] = None

            self._circuit_breaker.record_success(self._entry.provider)
            breaker_settled = True
        finally:
            if last_reservation[0] is not None and self._execution_gate is not None:
                self._execution_gate.settle_attempt(
                    last_reservation[0],
                    outcome="UNKNOWN",
                    now=self._clock(),
                )
                last_reservation[0] = None
            if is_probe and not breaker_settled:
                self._circuit_breaker.release_probe_on_abort(self._entry.provider)

        metered_input_units = _extract_provider_input_units(
            extract_provider, doc, fallback_input_units=input_tokens
        )
        if self._usage_recorder is not None:
            self._usage_recorder(self._entry.model_id, metered_input_units, generated_tokens)

        self.last_decision_probability = prob
        completed_at = utc_time(self._clock(), "completed_at")
        if completed_at < started_at:
            completed_at = started_at

        if self._entry.provider == "ollama":
            sup_receipt = doc.get("cas_supervisor_receipt")
            if not isinstance(sup_receipt, Mapping) or not isinstance(sup_receipt.get("receipt_id"), str) or not sup_receipt["receipt_id"].strip():
                raise FrontierTransportError(
                    "OLLAMA_SUPERVISOR_RECEIPT_MISSING: local Ollama response lacks independently signed supervisor receipt"
                )
            receipt_id = str(sup_receipt["receipt_id"]).strip()
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
            # Submit untrusted supervisor receipt for independent cryptographic verification; NEVER self-record!
            self._verifier.submit_supervised_receipt(sup_receipt)
            return reply

        with self._lock:
            self._seq += 1
            seq = self._seq
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
        sleep: Callable[[float], None] | None = None,
        circuit_breaker_config: CircuitBreakerConfig | None = None,
        retry_policy: RetryPolicy | None = None,
        pricing_micro_usd_per_1m: Mapping[str, tuple[int, int]] | None = None,
        supervised_ollama: SupervisedOllamaBinding | None = None,
        execution_gate: DurableModelExecutionGate | None = None,
    ) -> None:
        if not isinstance(environ, Mapping):
            raise FrontierConfigurationError("environ must be a key-value Mapping")
        self._env = {
            k: str(v)
            for k, v in environ.items()
            if isinstance(k, str) and k.startswith("CAS_FOREX_") and isinstance(v, str)
        }
        self._clock = clock or _utc_now
        self._sleep = sleep or time.sleep
        self._http_post = http_post
        self._ollama_http_post = ollama_http_post
        self._resolve_dns = resolve_dns
        self._circuit_breaker_config = circuit_breaker_config or CircuitBreakerConfig()
        self._retry_policy = retry_policy or RetryPolicy()
        self._breakers = ProviderCircuitBreaker(
            clock=self._clock,
            config=self._circuit_breaker_config,
        )
        raw_pricing = pricing_micro_usd_per_1m if pricing_micro_usd_per_1m is not None else MODEL_PRICING_MICRO_USD_PER_1M
        self._pricing: dict[str, tuple[int, int]] = {}
        for entry in FRONTIER_MODEL_CATALOG:
            pair = raw_pricing.get(entry.model_id, MODEL_PRICING_MICRO_USD_PER_1M[entry.model_id])
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise FrontierConfigurationError(f"invalid pricing tuple for {entry.model_id!r}")
            self._pricing[entry.model_id] = (
                integer(pair[0], "input_micro_usd_per_1m", minimum=0),
                integer(pair[1], "output_micro_usd_per_1m", minimum=0),
            )
        if supervised_ollama is not None and not isinstance(supervised_ollama, SupervisedOllamaBinding):
            raise FrontierConfigurationError("supervised_ollama must be SupervisedOllamaBinding or None")
        self._supervised_ollama: SupervisedOllamaBinding | None = supervised_ollama
        self._execution_gate: DurableModelExecutionGate | None = (
            execution_gate if isinstance(execution_gate, DurableModelExecutionGate) else None
        )
        self._verifier = FrontierReceiptVerifier(supervised_ollama=self._supervised_ollama)
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
            self._stats[entry.model_id] = {
                "calls": 0,
                "last_latency_ms": None,
                "last_status": "IDLE",
                "input_units": 0,
                "output_units": 0,
                "spend_pico_usd": 0,
            }

        self._ollama_fallback_enabled = _truthy(self._env.get(ENV_OLLAMA_FALLBACK_ENABLED))
        raw_prob = self._env.get(ENV_DECISION_MIN_PROBABILITY, "").strip()
        if raw_prob:
            try:
                self._min_probability = Decimal(raw_prob)
                if not self._min_probability.is_finite():
                    raise ValueError("non-finite min_probability")
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
        raw_exp_model = (self._env.get(ENV_EXPLAINER_MODEL_ID, "").strip() or DEFAULT_EXPLAINER_MODEL_ID).removeprefix("models/")
        self._explainer_model_slug: str = _validate_slug(raw_exp_model, ENV_EXPLAINER_MODEL_ID)
        raw_tts_model = (self._env.get(ENV_EXPLAINER_TTS_MODEL_ID, "").strip() or DEFAULT_EXPLAINER_TTS_MODEL_ID).removeprefix("models/")
        self._explainer_tts_model_slug: str = _validate_slug(raw_tts_model, ENV_EXPLAINER_TTS_MODEL_ID)

    def __repr__(self) -> str:
        with self._lock:
            active = self._active_model_id
        return f"FrontierModelRegistry(active_model={active!r}, secrets='[REDACTED]')"

    def bind_execution_gate(self, gate: DurableModelExecutionGate | None) -> None:
        if gate is not None and not isinstance(gate, DurableModelExecutionGate):
            raise FrontierConfigurationError("gate must be DurableModelExecutionGate or None")
        with self._lock:
            self._execution_gate = gate

    def bind_supervised_ollama(self, binding: SupervisedOllamaBinding | None) -> None:
        if binding is not None and not isinstance(binding, SupervisedOllamaBinding):
            raise FrontierConfigurationError("binding must be SupervisedOllamaBinding or None")
        with self._lock:
            self._supervised_ollama = binding
        self._verifier.bind_supervised_ollama(binding)

    def _is_entry_ready(self, entry: FrontierModelCatalogEntry) -> bool:
        if entry.is_fallback:
            return (
                self._ollama_fallback_enabled
                and self._supervised_ollama is not None
                and self._supervised_ollama.is_bound_and_verified()
            )
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
        artifact_payload: dict[str, Any] = {
            "model_id": entry.model_id,
            "provider": entry.provider,
            "api_slug": slug,
            "rank": entry.rank,
            "tier": entry.tier,
            "system_policy_sha256": sha256(SYSTEM_POLICY.encode("utf-8")).hexdigest(),
        }
        if entry.is_fallback and self._supervised_ollama is not None:
            artifact_payload.update({
                "supervised_binding_sha256": self._supervised_ollama.artifact_digest(),
                "executable_sha256": self._supervised_ollama.executable_sha256,
                "model_manifest_sha256": self._supervised_ollama.model_manifest_sha256,
                "weights_sha256": self._supervised_ollama.weights_sha256,
                "template_sha256": self._supervised_ollama.template_sha256,
                "tokenizer_sha256": self._supervised_ollama.tokenizer_sha256,
                "pid": self._supervised_ollama.pid,
                "start_time": self._supervised_ollama.start_time,
            })
        artifact_sha = content_digest(artifact_payload)
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
        execution_gate: DurableModelExecutionGate | None = None,
    ) -> tuple[ModelSpecification, FrontierChatBackend, FrontierReceiptVerifier]:
        target_id = self.active_model_id if model_id is None else model_id
        if target_id not in _CATALOG_BY_ID:
            raise FrontierConfigurationError(f"unknown AI model {target_id!r}")
        entry = _CATALOG_BY_ID[target_id]
        spec = self.model_spec(target_id, reasoning_effort=reasoning_effort)
        secret = self._secrets.get(entry.credential_env) if entry.credential_env else None
        transport = self._ollama_http_post if entry.provider == "ollama" else self._http_post
        eff_gate = execution_gate if isinstance(execution_gate, DurableModelExecutionGate) else self._execution_gate
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
            sleep=self._sleep,
            circuit_breaker=self._breakers,
            retry_policy=self._retry_policy,
            usage_recorder=self._record_usage,
            execution_gate=eff_gate,
            supervised_ollama=self._supervised_ollama if entry.provider == "ollama" else None,
        )
        return spec, backend, self._verifier

    def scout_opportunities(
        self,
        questions: list[dict[str, Any]],
        *,
        min_probability: Decimal | None = None,
        execution_gate: DurableModelExecutionGate | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Batch-screen candidate markets in 150-250ms using Gemini Decision 1 with per-attempt spend gating."""
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

        eff_gate = execution_gate if isinstance(execution_gate, DurableModelExecutionGate) else self._execution_gate
        scout_attempt = [0]
        last_scout_res: list[str | None] = [None]

        clean_slug = self._slugs["gemini-decision-1"].removeprefix("models/")
        t0 = utc_time(self._clock(), "scout_start")
        status = 404
        raw = b""
        used_generate = False
        is_probe = self._breakers.before_call(entry.provider)
        breaker_settled = False
        scout_idem = content_digest({"questions": questions[:1000], "slug": clean_slug})
        scout_req_id = request_id.strip() if isinstance(request_id, str) and request_id.strip() else f"scout-{scout_idem[:16]}"

        def _post(
            u: str,
            h: dict[str, str],
            b: bytes,
            timeout_s: float = 8.0,
            *,
            gate_model_id: str = "gemini-decision-1",
            max_output_tokens: int = 0,
        ) -> tuple[int, bytes]:
            scout_attempt[0] += 1
            res_id: str | None = None
            try:
                if eff_gate is not None:
                    res = eff_gate.reserve_attempt(
                        model_id=gate_model_id,
                        request_id=scout_req_id,
                        route_kind="scout",
                        attempt_number=scout_attempt[0],
                        input_chars_or_tokens=len(b),
                        max_output_tokens=max_output_tokens,
                        input_is_tokens=False,
                        invocation_sha256=scout_idem,
                        now=self._clock(),
                    )
                    res_id = str(res["reservation_id"])
                    last_scout_res[0] = res_id
                try:
                    if self._http_post is not None:
                        st, resp_raw = self._http_post(u, dict(h), b, timeout_s, MAX_PROVIDER_WIRE_BYTES)
                    else:
                        st, resp_raw = default_frontier_https_post(
                            u, dict(h), b, timeout_s, MAX_PROVIDER_WIRE_BYTES,
                            expected_host=entry.allowed_host, resolve_dns=self._resolve_dns,
                        )
                except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
                    if res_id is not None and eff_gate is not None:
                        eff_gate.settle_attempt(
                            res_id,
                            outcome="TIMEOUT" if isinstance(exc, TimeoutError) else "TRANSPORT_ERROR",
                            now=self._clock(),
                        )
                        last_scout_res[0] = None
                    raise FrontierTransportError(
                        f"frontier AI connection error: {type(exc).__name__}",
                        retryable=True,
                    ) from None
                if st < 200 or st >= 300:
                    if res_id is not None and eff_gate is not None:
                        eff_gate.settle_attempt(res_id, outcome="HTTP_ERROR", now=self._clock())
                        last_scout_res[0] = None
                    raise FrontierTransportError(
                        f"Gemini Decision 1 returned HTTP status {st}",
                        status_code=int(st),
                        retryable=_is_retryable_http_status(int(st)),
                    )
                return st, resp_raw
            except FrontierTransportError:
                if res_id is not None and last_scout_res[0] == res_id and eff_gate is not None:
                    eff_gate.settle_attempt(res_id, outcome="TRANSPORT_ERROR", now=self._clock())
                    last_scout_res[0] = None
                raise
            finally:
                h.clear()

        try:
            with self._lock:
                skip_decide = self._decide_404
            if clean_slug.startswith("gemini-decision") and not skip_decide:
                url = _validate_frontier_https_url(entry.endpoint_template.format(slug=clean_slug), expected_host=entry.allowed_host)
                body = canonical_bytes({
                    "model": f"models/{clean_slug}",
                    "batch_questions": questions[:1000],
                    "zero_output_tokens": True,
                })

                def _attempt_scout_decide(t_out: float) -> tuple[int, bytes]:
                    headers = {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "x-goog-api-key": secret.reveal_for_header(),
                    }
                    return _post(url, headers, body, min(t_out, 4.0), gate_model_id="gemini-decision-1", max_output_tokens=0)

                try:
                    status, raw = execute_resilient_frontier_call(
                        operation_kind=FrontierOperationKind.READ_SCOUT,
                        provider=entry.provider,
                        circuit_breaker=self._breakers,
                        retry_policy=self._retry_policy,
                        clock=self._clock,
                        sleep=self._sleep,
                        budget_seconds=Decimal("4"),
                        idempotency_key=f"{scout_idem}:decide",
                        attempt_fn=_attempt_scout_decide,
                        manage_breaker=False,
                        is_probe_override=is_probe,
                    )
                except FrontierTransportError as exc:
                    _, err_code, availability_failure = _classify_transport_error(exc)
                    if err_code == 404:
                        status, raw = 404, b""
                    else:
                        self._breakers.record_failure(
                            entry.provider,
                            reason=str(exc),
                            availability_failure=availability_failure,
                        )
                        breaker_settled = True
                        raise
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
                    def _attempt_scout_fb(t_out: float, slug_choice: str = fb_slug) -> tuple[int, bytes]:
                        fb_url, fb_hdrs, fb_body = _build_gemini_fast_json_payload(
                            clean_slug=slug_choice,
                            system_text=fb_sys,
                            user_text=fb_user,
                            max_tokens=512,
                            secret=secret,
                            allowed_host=entry.allowed_host,
                        )
                        return _post(fb_url, fb_hdrs, fb_body, t_out, gate_model_id=slug_choice, max_output_tokens=512)

                    try:
                        status, raw = execute_resilient_frontier_call(
                            operation_kind=FrontierOperationKind.READ_SCOUT,
                            provider=entry.provider,
                            circuit_breaker=self._breakers,
                            retry_policy=self._retry_policy,
                            clock=self._clock,
                            sleep=self._sleep,
                            budget_seconds=Decimal("8"),
                            idempotency_key=f"{scout_idem}:fb:{fb_slug}",
                            attempt_fn=_attempt_scout_fb,
                            manage_breaker=False,
                            is_probe_override=is_probe,
                        )
                    except FrontierTransportError as exc:
                        _, err_code, availability_failure = _classify_transport_error(exc)
                        if idx_fb + 1 < len(fb_candidates) and err_code == 404:
                            status, raw = 404, b""
                            continue
                        self._breakers.record_failure(
                            entry.provider,
                            reason=str(exc),
                            availability_failure=availability_failure,
                        )
                        breaker_settled = True
                        raise
                    used_generate = True
                    if status != 404 or idx_fb + 1 == len(fb_candidates):
                        break

            try:
                outer_doc = _decode_json_dict(raw)
                if used_generate and "decisions" not in outer_doc and "candidates" in outer_doc:
                    doc = _decode_json_dict(_extract_gemini_cand_text(outer_doc).encode("utf-8"))
                else:
                    doc = outer_doc
                if "decisions" in doc and not isinstance(doc.get("decisions"), list):
                    raise FrontierTransportError("Gemini scout response 'decisions' must be a list")
                raw_decisions = doc.get("decisions") if isinstance(doc.get("decisions"), list) else [doc]
                parsed: list[dict[str, Any]] = []
                best_prob = Decimal("0")
                best_market: str | None = None
                for idx, item in enumerate(raw_decisions):
                    if not isinstance(item, dict):
                        continue
                    mkt = str(item.get("market") or (questions[idx].get("market") if idx < len(questions) else "UNKNOWN"))
                    choice = str(item.get("choice") or "WAIT")
                    raw_item_prob = item.get("probability", "0.50")
                    try:
                        prob = Decimal(str(raw_item_prob if raw_item_prob is not None else "0.50"))
                        if not prob.is_finite():
                            raise ValueError("non-finite probability")
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
            except FrontierTransportError as exc:
                if last_scout_res[0] is not None and eff_gate is not None:
                    eff_gate.settle_attempt(last_scout_res[0], outcome="PARSE_ERROR", now=self._clock())
                    last_scout_res[0] = None
                self._breakers.record_failure(
                    entry.provider,
                    reason=str(exc),
                    availability_failure=True,
                )
                breaker_settled = True
                raise

            if last_scout_res[0] is not None and eff_gate is not None:
                confirmed = _extract_confirmed_provider_usage(
                    "gemini" if used_generate else "gemini_decision",
                    outer_doc,
                )
                if confirmed is not None:
                    eff_gate.settle_attempt(
                        last_scout_res[0],
                        input_tokens=confirmed[0],
                        output_tokens=confirmed[1],
                        outcome="CONFIRMED_USAGE",
                        now=self._clock(),
                    )
                else:
                    eff_gate.settle_attempt(last_scout_res[0], outcome="UNKNOWN", now=self._clock())
                last_scout_res[0] = None

            self._breakers.record_success(entry.provider)
            breaker_settled = True
        finally:
            if last_scout_res[0] is not None and eff_gate is not None:
                eff_gate.settle_attempt(last_scout_res[0], outcome="UNKNOWN", now=self._clock())
                last_scout_res[0] = None
            if is_probe and not breaker_settled:
                self._breakers.release_probe_on_abort(entry.provider)

        t1 = utc_time(self._clock(), "scout_end")
        latency_ms = max(1, int((t1 - t0).total_seconds() * 1000))
        scout_in_fallback = max(1, (len(canonical_bytes({"questions": questions[:1000]})) + 3) // 4)
        scout_in_units = _extract_provider_input_units(
            "gemini" if used_generate else "gemini_decision",
            outer_doc,
            fallback_input_units=scout_in_fallback,
        )
        scout_out_units = 0
        if used_generate:
            umeta = outer_doc.get("usageMetadata") if isinstance(outer_doc.get("usageMetadata"), Mapping) else {}
            cand_cnt = _safe_non_neg_int(umeta.get("candidatesTokenCount"))
            scout_out_units = cand_cnt if cand_cnt is not None else max(1, len(raw) // 4)
        self._record_usage("gemini-decision-1", scout_in_units, scout_out_units)

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

    def _record_usage(
        self,
        model_id: str,
        input_units: int,
        output_units: int,
    ) -> None:
        """Record metered units and exact pico-USD spend without altering call counts."""
        if model_id not in _CATALOG_BY_ID:
            return
        in_u = integer(input_units, "input_units", minimum=0)
        out_u = integer(output_units, "output_units", minimum=0)
        pico = compute_call_cost_pico_usd(
            model_id,
            input_units=in_u,
            output_units=out_u,
            pricing_micro_usd_per_1m=self._pricing,
        )
        with self._lock:
            st = self._stats[model_id]
            st["input_units"] = int(st["input_units"]) + in_u
            st["output_units"] = int(st["output_units"]) + out_u
            st["spend_pico_usd"] = int(st["spend_pico_usd"]) + pico

    def record_call(
        self,
        model_id: str,
        *,
        latency_ms: int,
        status: str,
        reasoning_effort: str | None = None,
        input_units: int = 0,
        output_units: int = 0,
    ) -> None:
        if model_id not in _CATALOG_BY_ID:
            return
        clean_lat = max(0, int(latency_ms))
        in_u = integer(input_units, "input_units", minimum=0)
        out_u = integer(output_units, "output_units", minimum=0)
        pico = compute_call_cost_pico_usd(
            model_id,
            input_units=in_u,
            output_units=out_u,
            pricing_micro_usd_per_1m=self._pricing,
        ) if (in_u > 0 or out_u > 0) else 0
        with self._lock:
            st = self._stats[model_id]
            st["calls"] = int(st["calls"]) + 1
            st["last_latency_ms"] = clean_lat
            st["last_status"] = str(status)[:40]
            if in_u > 0 or out_u > 0:
                st["input_units"] = int(st["input_units"]) + in_u
                st["output_units"] = int(st["output_units"]) + out_u
                st["spend_pico_usd"] = int(st["spend_pico_usd"]) + pico
            self._last_latency_ms = clean_lat
            if reasoning_effort is not None:
                self._last_effective_effort = str(reasoning_effort).lower()

    def answer_explainer_question(
        self,
        question: str = "",
        *,
        context_summary: Mapping[str, Any] | None = None,
        audio_base64: str | None = None,
        audio_mime_type: str | None = None,
        execution_gate: DurableModelExecutionGate | None = None,
        preauthorized_reservation_id: str | None = None,
        epoch_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Read-only Explainer helper routed through DurableModelExecutionGate with zero trading authority."""
        if not isinstance(question, str):
            raise FrontierConfigurationError("question must be a string")
        clean_q = " ".join(question.replace("\r", " ").replace("\n", " ").strip().split())

        clean_audio_b64: str | None = None
        clean_audio_mime: str | None = None
        decoded_audio_bytes = 0
        if audio_base64 is not None and str(audio_base64).strip() != "":
            if not isinstance(audio_base64, str):
                raise FrontierConfigurationError("audio_base64 must be a string")
            compact_b64 = re.sub(r"\s+", "", audio_base64)
            if not compact_b64 or len(compact_b64) > MAX_EXPLAINER_AUDIO_B64_CHARS or not compact_b64.isascii():
                raise FrontierConfigurationError("audio_base64 must be 1..2000000 ASCII base64 characters")
            norm_b64 = compact_b64.replace("-", "+").replace("_", "/")
            pad_len = (-len(norm_b64)) % 4
            if pad_len:
                norm_b64 = norm_b64 + ("=" * pad_len)
            try:
                decoded_audio = base64.b64decode(norm_b64, validate=True)
            except ValueError as exc:
                raise FrontierConfigurationError("audio_base64 is not valid base64") from exc
            if not decoded_audio:
                raise FrontierConfigurationError("audio_base64 decoded to empty bytes")
            raw_mime = audio_mime_type if isinstance(audio_mime_type, str) and audio_mime_type.strip() else "audio/webm"
            base_mime = raw_mime.split(";", 1)[0].strip().lower()
            if base_mime not in ALLOWED_EXPLAINER_AUDIO_MIMES:
                raise FrontierConfigurationError(
                    f"audio_mime_type must be one of {sorted(ALLOWED_EXPLAINER_AUDIO_MIMES)}"
                )
            clean_audio_b64 = norm_b64
            clean_audio_mime = base_mime
            decoded_audio_bytes = len(decoded_audio)

        if clean_audio_b64 is None:
            if not clean_q or len(clean_q) > 500:
                raise FrontierConfigurationError("question must be 1..500 characters")
        elif len(clean_q) > 500:
            raise FrontierConfigurationError("question must be 0..500 characters when audio_base64 is attached")

        _epoch_abort_exc: list[BaseException | None] = [None]

        def _check_epoch_guard() -> None:
            if epoch_guard is None:
                return
            try:
                epoch_guard()
            except BaseException as exc_ep:
                _epoch_abort_exc[0] = exc_ep
                raise

        _check_epoch_guard()
        eff_gate = execution_gate if isinstance(execution_gate, DurableModelExecutionGate) else self._execution_gate
        aux_route = "transcription" if clean_audio_b64 is not None else "explainer"
        preauth_slot: list[str | None] = [
            preauthorized_reservation_id.strip()
            if isinstance(preauthorized_reservation_id, str) and preauthorized_reservation_id.strip()
            else None
        ]
        aux_attempt = [0]

        def _reserve_aux(
            *,
            model_id: str,
            max_output_tokens: int,
            input_bytes: int,
            audio_bytes: int,
            request_id: str,
        ) -> str | None:
            if eff_gate is None:
                return None
            aux_attempt[0] += 1
            if preauth_slot[0] is not None:
                rid = preauth_slot[0]
                preauth_slot[0] = None
                return rid
            res = eff_gate.authorize_auxiliary_call(
                route_kind=aux_route,
                model_id=model_id,
                max_output_tokens=max_output_tokens,
                input_bytes=input_bytes,
                audio_bytes=audio_bytes,
                request_id=request_id,
                attempt_number=aux_attempt[0],
                now=self._clock(),
            )
            return str(res["reservation_id"])

        summary_obj = dict(context_summary) if isinstance(context_summary, Mapping) else {}
        gemini_secret = self._secrets.get(ENV_GEMINI_API_KEY)
        has_gemini_key = gemini_secret is not None
        fallback_reason = "OFFLINE"

        # 1. Primary dedicated Voice/Text Explainer route: Gemini 4 Neon (independent of active_model_id & trading lock)
        if gemini_secret is not None:
            neon_slug = self._explainer_model_slug
            neon_display = "Gemini 4 Neon" if neon_slug == DEFAULT_EXPLAINER_MODEL_ID else neon_slug
            raw_url = f"https://generativelanguage.googleapis.com/v1beta/models/{neon_slug}:generateContent"
            url = _validate_frontier_https_url(raw_url, expected_host="generativelanguage.googleapis.com")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-goog-api-key": gemini_secret.reveal_for_header(),
            }
            prompt_q = clean_q if clean_q else "Transcribe the attached spoken question and answer it using the cockpit snapshot."
            pkt_str = canonical_bytes({"question": prompt_q, "cockpit": summary_obj}).decode("utf-8")
            user_parts: list[dict[str, Any]] = []
            if clean_audio_b64 is not None and clean_audio_mime is not None:
                user_parts.append({"inlineData": {"mimeType": clean_audio_mime, "data": clean_audio_b64}})
            user_parts.append({"text": pkt_str})
            body_bytes = canonical_bytes({
                "systemInstruction": {"parts": [{"text": EXPLAINER_SYSTEM_PROMPT}]},
                "contents": [{"role": "user", "parts": user_parts}],
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": 1536,
                    "responseMimeType": "application/json",
                    "thinkingConfig": {"thinkingLevel": "LOW"},
                },
            })
            neon_in_bytes = len(EXPLAINER_SYSTEM_PROMPT.encode("utf-8")) + len(pkt_str.encode("utf-8"))
            timeout_s = Decimal("25")
            neon_idem = content_digest({
                "model_id": neon_slug,
                "question": prompt_q,
                "pkt": pkt_str,
                "has_audio": clean_audio_b64 is not None,
            })
            last_neon_res: list[str | None] = [None]

            def _attempt_neon(t_out: float) -> tuple[int, bytes]:
                req_hdrs = dict(headers)
                res_id = _reserve_aux(
                    model_id=neon_slug,
                    max_output_tokens=1536 + 256,
                    input_bytes=neon_in_bytes,
                    audio_bytes=decoded_audio_bytes,
                    request_id=f"exp-{neon_idem[:16]}",
                )
                last_neon_res[0] = res_id
                try:
                    _check_epoch_guard()
                    try:
                        if self._http_post is not None:
                            st, resp_raw = self._http_post(url, dict(req_hdrs), body_bytes, t_out, MAX_EXPLAINER_RESPONSE_BYTES)
                        else:
                            st, resp_raw = default_frontier_https_post(
                                url,
                                dict(req_hdrs),
                                body_bytes,
                                t_out,
                                MAX_EXPLAINER_RESPONSE_BYTES,
                                expected_host="generativelanguage.googleapis.com",
                                resolve_dns=self._resolve_dns,
                            )
                    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
                        if res_id is not None and eff_gate is not None:
                            eff_gate.settle_attempt(
                                res_id,
                                outcome="TIMEOUT" if isinstance(exc, TimeoutError) else "TRANSPORT_ERROR",
                                now=self._clock(),
                            )
                            last_neon_res[0] = None
                        raise FrontierTransportError(
                            f"frontier AI connection error: {type(exc).__name__}",
                            retryable=True,
                        ) from None
                    if st < 200 or st >= 300:
                        if res_id is not None and eff_gate is not None:
                            eff_gate.settle_attempt(res_id, outcome="HTTP_ERROR", now=self._clock())
                            last_neon_res[0] = None
                        raise FrontierTransportError(
                            f"{neon_display} returned HTTP status {st}",
                            status_code=int(st),
                            retryable=_is_retryable_http_status(int(st)),
                        )
                    return st, resp_raw
                except FrontierTransportError:
                    if res_id is not None and last_neon_res[0] == res_id and eff_gate is not None:
                        eff_gate.settle_attempt(res_id, outcome="TRANSPORT_ERROR", now=self._clock())
                        last_neon_res[0] = None
                    raise
                finally:
                    req_hdrs.clear()

            try:
                status, raw = execute_resilient_frontier_call(
                    operation_kind=FrontierOperationKind.READ_EXPLAINER,
                    provider="gemini",
                    circuit_breaker=self._breakers,
                    retry_policy=self._retry_policy,
                    clock=self._clock,
                    sleep=self._sleep,
                    budget_seconds=timeout_s,
                    idempotency_key=neon_idem,
                    attempt_fn=_attempt_neon,
                    manage_breaker=True,
                )
                if 200 <= status < 300:
                    doc = _decode_json_dict(raw, max_bytes=MAX_EXPLAINER_RESPONSE_BYTES)
                    if last_neon_res[0] is not None and eff_gate is not None:
                        confirmed = _extract_confirmed_provider_usage("gemini", doc)
                        if confirmed is not None:
                            eff_gate.settle_attempt(
                                last_neon_res[0],
                                input_tokens=confirmed[0],
                                output_tokens=confirmed[1],
                                audio_bytes=0,
                                outcome="CONFIRMED_USAGE",
                                now=self._clock(),
                            )
                        else:
                            eff_gate.settle_attempt(last_neon_res[0], outcome="UNKNOWN", now=self._clock())
                        last_neon_res[0] = None
                    txt = _extract_gemini_cand_text(doc)
                    ans_text = txt
                    spoken_q = ""
                    try:
                        parsed_txt = json.loads(txt)
                        if isinstance(parsed_txt, Mapping):
                            if isinstance(parsed_txt.get("answer"), str):
                                ans_text = parsed_txt["answer"]
                            if isinstance(parsed_txt.get("spoken_question"), str):
                                spoken_q = " ".join(parsed_txt["spoken_question"].strip().split())[:500]
                    except (ValueError, TypeError):
                        ans_text = txt
                    ans_text = " ".join(str(ans_text).strip().split())[:2000]
                    if ans_text:
                        eff_q = spoken_q or clean_q or "Voice question"
                        out_neon: dict[str, Any] = {
                            "schema": "cas-forex.explainer-answer/1",
                            "question": eff_q,
                            "answer": ans_text,
                            "model_id": neon_slug,
                            "display_name": neon_display,
                            "source": "FRONTIER_READ_ONLY",
                            "read_only": True,
                            "advisory_only": True,
                            "voice_ready": True,
                        }
                        if spoken_q:
                            out_neon["spoken_question"] = spoken_q
                        return assert_safe_ai_catalog_payload(out_neon)
                fallback_reason = f"HTTP_{status}"
            except FrontierTransportError as exc_neon:
                if exc_neon.status_code is not None:
                    fallback_reason = f"HTTP_{exc_neon.status_code}"
                else:
                    fallback_reason = type(exc_neon).__name__
            except OperatorUnavailable:
                raise
            except Exception as exc_neon:
                if _epoch_abort_exc[0] is not None:
                    raise _epoch_abort_exc[0]
                fallback_reason = type(exc_neon).__name__
            finally:
                if last_neon_res[0] is not None and eff_gate is not None:
                    eff_gate.settle_attempt(last_neon_res[0], outcome="UNKNOWN", now=self._clock())
                    last_neon_res[0] = None
                headers.clear()

        # 2. Secondary fallback to configured active/alternate read-only model when Gemini 4 Neon is unconfigured or unavailable
        chosen_entry = self.active_entry
        if (
            chosen_entry.provider == "gemini_decision"
            or not self.is_model_ready(chosen_entry.model_id)
            or (has_gemini_key and chosen_entry.provider == "gemini" and self._slugs.get(chosen_entry.model_id) == self._explainer_model_slug)
        ):
            fallback_entry = None
            for cand in FRONTIER_MODEL_CATALOG:
                if (
                    cand.provider != "gemini_decision"
                    and not cand.is_fallback
                    and self.is_model_ready(cand.model_id)
                    and not (has_gemini_key and cand.provider == "gemini" and self._slugs.get(cand.model_id) == self._explainer_model_slug)
                ):
                    fallback_entry = cand
                    break
            if fallback_entry is not None:
                chosen_entry = fallback_entry

        secret = self._secrets.get(chosen_entry.credential_env) if chosen_entry.credential_env else None
        ready_for_call = (
            self._is_entry_ready(chosen_entry)
            and (chosen_entry.provider == "ollama" or secret is not None)
            and chosen_entry.provider != "gemini_decision"
            and not (has_gemini_key and chosen_entry.provider == "gemini" and fallback_reason != "OFFLINE")
        )

        eff_q_fallback = clean_q or "Voice question"
        if ready_for_call:
            api_slug = self._slugs[chosen_entry.model_id]
            from types import SimpleNamespace

            pkt = canonical_bytes({"question": eff_q_fallback, "cockpit": summary_obj}).decode("utf-8")
            inv = SimpleNamespace(
                model=SimpleNamespace(reasoning_effort="low"),
                system_policy=EXPLAINER_SYSTEM_PROMPT,
                packet_json=pkt,
                budget=SimpleNamespace(max_generated_tokens_per_call=768),
                seed=None,
            )
            fallback_reason = "LOCAL_READ_ONLY_FALLBACK"
            explainer_idem = content_digest({"model_id": chosen_entry.model_id, "question": clean_q, "pkt": pkt})
            sec_in_bytes = len(EXPLAINER_SYSTEM_PROMPT.encode("utf-8")) + len(pkt.encode("utf-8"))
            sec_max_out = _effective_max_output_tokens(chosen_entry, api_slug, inv)  # type: ignore[arg-type]
            last_exp_res: list[str | None] = [None]

            def _attempt_explainer(t_out: float) -> tuple[int, bytes]:
                if chosen_entry.provider == "ollama":
                    if self._supervised_ollama is None:
                        raise FrontierConfigurationError(
                            "OLLAMA_UNSUPERVISED_ENDPOINT_FORBIDDEN: SupervisedOllamaBinding required"
                        )
                    self._supervised_ollama.verify_binding()
                res_id = _reserve_aux(
                    model_id=chosen_entry.model_id,
                    max_output_tokens=sec_max_out,
                    input_bytes=sec_in_bytes,
                    audio_bytes=0,
                    request_id=f"exp-{explainer_idem[:16]}",
                )
                last_exp_res[0] = res_id
                u, hdrs, b = _build_provider_payload(
                    chosen_entry,
                    api_slug,
                    inv,  # type: ignore[arg-type]
                    secret,
                    supervised_ollama=self._supervised_ollama if chosen_entry.provider == "ollama" else None,
                )
                try:
                    _check_epoch_guard()
                    try:
                        if self._http_post is not None and chosen_entry.provider != "ollama":
                            st, resp_raw = self._http_post(u, dict(hdrs), b, t_out, MAX_PROVIDER_WIRE_BYTES)
                        elif chosen_entry.provider == "ollama":
                            if self._ollama_http_post is not None:
                                st, resp_raw = self._ollama_http_post(u, dict(hdrs), b, t_out, MAX_PROVIDER_WIRE_BYTES)
                            elif self._http_post is not None:
                                st, resp_raw = self._http_post(u, dict(hdrs), b, t_out, MAX_PROVIDER_WIRE_BYTES)
                            else:
                                st, resp_raw = default_ollama_loopback_post(
                                    u,
                                    dict(hdrs),
                                    b,
                                    t_out,
                                    MAX_PROVIDER_WIRE_BYTES,
                                    supervised_binding=self._supervised_ollama,
                                )
                        else:
                            st, resp_raw = default_frontier_https_post(
                                u,
                                dict(hdrs),
                                b,
                                t_out,
                                MAX_PROVIDER_WIRE_BYTES,
                                expected_host=chosen_entry.allowed_host,
                                resolve_dns=self._resolve_dns,
                            )
                    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
                        if res_id is not None and eff_gate is not None:
                            eff_gate.settle_attempt(
                                res_id,
                                outcome="TIMEOUT" if isinstance(exc, TimeoutError) else "TRANSPORT_ERROR",
                                now=self._clock(),
                            )
                            last_exp_res[0] = None
                        raise FrontierTransportError(
                            f"frontier AI connection error: {type(exc).__name__}",
                            retryable=True,
                        ) from None
                    if st < 200 or st >= 300:
                        if res_id is not None and eff_gate is not None:
                            eff_gate.settle_attempt(res_id, outcome="HTTP_ERROR", now=self._clock())
                            last_exp_res[0] = None
                        raise FrontierTransportError(
                            f"{chosen_entry.display_name} returned HTTP status {st}",
                            status_code=int(st),
                            retryable=_is_retryable_http_status(int(st)),
                        )
                    return st, resp_raw
                except FrontierTransportError:
                    if res_id is not None and last_exp_res[0] == res_id and eff_gate is not None:
                        eff_gate.settle_attempt(res_id, outcome="TRANSPORT_ERROR", now=self._clock())
                        last_exp_res[0] = None
                    raise
                finally:
                    hdrs.clear()

            try:
                status, raw = execute_resilient_frontier_call(
                    operation_kind=FrontierOperationKind.READ_EXPLAINER,
                    provider=chosen_entry.provider,
                    circuit_breaker=self._breakers,
                    retry_policy=self._retry_policy,
                    clock=self._clock,
                    sleep=self._sleep,
                    budget_seconds=Decimal("10"),
                    idempotency_key=explainer_idem,
                    attempt_fn=_attempt_explainer,
                    manage_breaker=True,
                )
                if 200 <= status < 300:
                    doc = _decode_json_dict(raw, max_bytes=MAX_PROVIDER_WIRE_BYTES)
                    if last_exp_res[0] is not None and eff_gate is not None:
                        confirmed = _extract_confirmed_provider_usage(chosen_entry.provider, doc)
                        if confirmed is not None:
                            eff_gate.settle_attempt(
                                last_exp_res[0],
                                input_tokens=confirmed[0],
                                output_tokens=confirmed[1],
                                outcome="CONFIRMED_USAGE",
                                now=self._clock(),
                            )
                        else:
                            eff_gate.settle_attempt(last_exp_res[0], outcome="UNKNOWN", now=self._clock())
                        last_exp_res[0] = None
                    txt, out_units, _ = _extract_provider_text_and_usage(
                        chosen_entry.provider, doc, inv, min_probability=self._min_probability  # type: ignore[arg-type]
                    )
                    in_fallback = max(1, (len(EXPLAINER_SYSTEM_PROMPT.encode("utf-8")) + len(pkt.encode("utf-8")) + 3) // 4)
                    in_units = _extract_provider_input_units(
                        chosen_entry.provider, doc, fallback_input_units=in_fallback
                    )
                    ans_text = txt
                    try:
                        parsed_txt = json.loads(txt)
                        if isinstance(parsed_txt, dict) and isinstance(parsed_txt.get("answer"), str):
                            ans_text = parsed_txt["answer"]
                    except (ValueError, TypeError):
                        ans_text = txt
                    ans_text = " ".join(str(ans_text).strip().split())[:2000]
                    if ans_text:
                        self._record_usage(chosen_entry.model_id, in_units, out_units)
                        return assert_safe_ai_catalog_payload({
                            "schema": "cas-forex.explainer-answer/1",
                            "question": eff_q_fallback,
                            "answer": ans_text,
                            "model_id": chosen_entry.model_id,
                            "display_name": chosen_entry.display_name,
                            "source": "FRONTIER_READ_ONLY",
                            "read_only": True,
                            "advisory_only": True,
                            "voice_ready": has_gemini_key,
                        })
            except FrontierTransportError as exc_exp:
                fallback_reason = type(exc_exp).__name__
            except OperatorUnavailable:
                raise
            except Exception as exc_exp:
                if _epoch_abort_exc[0] is not None:
                    raise _epoch_abort_exc[0]
                fallback_reason = type(exc_exp).__name__
            finally:
                if last_exp_res[0] is not None and eff_gate is not None:
                    eff_gate.settle_attempt(last_exp_res[0], outcome="UNKNOWN", now=self._clock())
                    last_exp_res[0] = None

        focus_txt = str(summary_obj.get("current_focus_status") or "Scanning all 20 markets under ForexMetaValveGate.")
        mode_txt = str(summary_obj.get("execution_mode") or "DEMO")
        broker_txt = str(summary_obj.get("active_broker") or "HUGOSWAY_MT5")
        fallback_ans = (
            f"Read-only status ({mode_txt} via {broker_txt}, model {chosen_entry.display_name}): "
            f"{focus_txt} Question noted: {eff_q_fallback}"
        )[:2000]
        return assert_safe_ai_catalog_payload({
            "schema": "cas-forex.explainer-answer/1",
            "question": eff_q_fallback,
            "answer": fallback_ans,
            "model_id": chosen_entry.model_id,
            "display_name": chosen_entry.display_name,
            "source": "LOCAL_READ_ONLY_FALLBACK" if (not ready_for_call and fallback_reason == "OFFLINE") else f"LOCAL_READ_ONLY_FALLBACK ({fallback_reason})",
            "read_only": True,
            "advisory_only": True,
            "voice_ready": has_gemini_key,
        })

    def synthesize_explainer_speech(
        self,
        text: str,
        *,
        voice_name: str = "Kore",
        execution_gate: DurableModelExecutionGate | None = None,
        preauthorized_reservation_id: str | None = None,
        epoch_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Synthesize spoken Explainer audio via Gemini TTS through DurableModelExecutionGate."""
        if not isinstance(text, str):
            raise FrontierConfigurationError("text must be a string")
        cleaned_text = " ".join(
            "".join(" " if (ord(c) < 32 or ord(c) == 127) else c for c in text).split()
        )
        if not cleaned_text or len(cleaned_text) > 1800:
            raise FrontierConfigurationError("text must be 1..1800 characters")
        clean_voice = voice_name.strip() if isinstance(voice_name, str) else ""
        if clean_voice not in VALID_EXPLAINER_VOICES:
            raise FrontierConfigurationError(f"voice_name must be one of {VALID_EXPLAINER_VOICES}")

        gemini_secret = self._secrets.get(ENV_GEMINI_API_KEY)
        if gemini_secret is None:
            return assert_safe_ai_catalog_payload({
                "schema": "cas-forex.explainer-tts/1",
                "ok": False,
                "fallback": "WEB_SPEECH",
                "reason": "GEMINI_API_KEY_UNCONFIGURED",
            })

        _tts_epoch_abort: list[BaseException | None] = [None]

        def _check_tts_epoch_guard() -> None:
            if epoch_guard is None:
                return
            try:
                epoch_guard()
            except BaseException as exc_ep:
                _tts_epoch_abort[0] = exc_ep
                raise

        _check_tts_epoch_guard()
        eff_gate = execution_gate if isinstance(execution_gate, DurableModelExecutionGate) else self._execution_gate
        preauth_slot: list[str | None] = [
            preauthorized_reservation_id.strip()
            if isinstance(preauthorized_reservation_id, str) and preauthorized_reservation_id.strip()
            else None
        ]
        tts_attempt = [0]
        tts_in_bytes = len(cleaned_text.encode("utf-8"))
        tts_max_out = max(1024, len(cleaned_text) * 4)

        candidates = [self._explainer_tts_model_slug]
        if FALLBACK_EXPLAINER_TTS_MODEL_ID not in candidates:
            candidates.append(FALLBACK_EXPLAINER_TTS_MODEL_ID)

        safe_reason = "TTS_UNAVAILABLE"
        for tts_slug in candidates:
            raw_url = f"https://generativelanguage.googleapis.com/v1beta/models/{tts_slug}:generateContent"
            url = _validate_frontier_https_url(raw_url, expected_host="generativelanguage.googleapis.com")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-goog-api-key": gemini_secret.reveal_for_header(),
            }
            body_bytes = canonical_bytes({
                "contents": [{"parts": [{"text": cleaned_text}]}],
                "generationConfig": {
                    "responseModalities": ["AUDIO"],
                    "speechConfig": {
                        "voiceConfig": {
                            "prebuiltVoiceConfig": {
                                "voiceName": clean_voice,
                            }
                        }
                    },
                },
            })
            tts_idem = content_digest({
                "tts_slug": tts_slug,
                "voice": clean_voice,
                "text": cleaned_text,
            })
            last_tts_res: list[str | None] = [None]

            def _attempt_tts(t_out: float) -> tuple[int, bytes]:
                _check_tts_epoch_guard()
                req_hdrs = dict(headers)
                res_id: str | None = None
                if eff_gate is not None:
                    tts_attempt[0] += 1
                    if preauth_slot[0] is not None:
                        res_id = preauth_slot[0]
                        preauth_slot[0] = None
                    else:
                        res = eff_gate.authorize_auxiliary_call(
                            route_kind="tts",
                            model_id=tts_slug,
                            max_output_tokens=tts_max_out,
                            input_bytes=tts_in_bytes,
                            audio_bytes=0,
                            request_id=f"tts-{tts_idem[:16]}",
                            attempt_number=tts_attempt[0],
                            now=self._clock(),
                        )
                        res_id = str(res["reservation_id"])
                    last_tts_res[0] = res_id
                try:
                    try:
                        if self._http_post is not None:
                            st, resp_raw = self._http_post(url, dict(req_hdrs), body_bytes, t_out, MAX_TTS_WIRE_BYTES)
                        else:
                            st, resp_raw = default_frontier_https_post(
                                url,
                                dict(req_hdrs),
                                body_bytes,
                                t_out,
                                MAX_TTS_WIRE_BYTES,
                                expected_host="generativelanguage.googleapis.com",
                                resolve_dns=self._resolve_dns,
                            )
                    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
                        if res_id is not None and eff_gate is not None:
                            eff_gate.settle_attempt(
                                res_id,
                                outcome="TIMEOUT" if isinstance(exc, TimeoutError) else "TRANSPORT_ERROR",
                                now=self._clock(),
                            )
                            last_tts_res[0] = None
                        raise FrontierTransportError(
                            f"frontier AI connection error: {type(exc).__name__}",
                            retryable=True,
                        ) from None
                    if st < 200 or st >= 300:
                        if res_id is not None and eff_gate is not None:
                            eff_gate.settle_attempt(res_id, outcome="HTTP_ERROR", now=self._clock())
                            last_tts_res[0] = None
                        raise FrontierTransportError(
                            f"Gemini TTS ({tts_slug}) returned HTTP status {st}",
                            status_code=int(st),
                            retryable=_is_retryable_http_status(int(st)),
                        )
                    return st, resp_raw
                except FrontierTransportError:
                    if res_id is not None and last_tts_res[0] == res_id and eff_gate is not None:
                        eff_gate.settle_attempt(res_id, outcome="TRANSPORT_ERROR", now=self._clock())
                        last_tts_res[0] = None
                    raise
                finally:
                    req_hdrs.clear()

            try:
                status, raw = execute_resilient_frontier_call(
                    operation_kind=FrontierOperationKind.READ_EXPLAINER,
                    provider="gemini",
                    circuit_breaker=self._breakers,
                    retry_policy=self._retry_policy,
                    clock=self._clock,
                    sleep=self._sleep,
                    budget_seconds=Decimal("25"),
                    idempotency_key=tts_idem,
                    attempt_fn=_attempt_tts,
                    manage_breaker=True,
                )
                if 200 <= status < 300:
                    doc = _decode_json_dict(raw, max_bytes=MAX_TTS_WIRE_BYTES)
                    if last_tts_res[0] is not None and eff_gate is not None:
                        confirmed = _extract_confirmed_provider_usage("gemini", doc)
                        if confirmed is not None:
                            eff_gate.settle_attempt(
                                last_tts_res[0],
                                input_tokens=confirmed[0],
                                output_tokens=confirmed[1],
                                outcome="CONFIRMED_USAGE",
                                now=self._clock(),
                            )
                        else:
                            eff_gate.settle_attempt(last_tts_res[0], outcome="UNKNOWN", now=self._clock())
                        last_tts_res[0] = None
                    cands = doc.get("candidates")
                    if isinstance(cands, list) and cands and isinstance(cands[0], Mapping):
                        content = cands[0].get("content")
                        parts = content.get("parts") if isinstance(content, Mapping) else None
                        if isinstance(parts, list):
                            for part in parts:
                                if not isinstance(part, Mapping):
                                    continue
                                inline = part.get("inlineData") or part.get("inline_data")
                                if not isinstance(inline, Mapping):
                                    continue
                                raw_b64 = inline.get("data")
                                raw_mime = (
                                    inline.get("mimeType")
                                    or inline.get("mime_type")
                                    or "audio/L16;codec=pcm;rate=24000"
                                )
                                if isinstance(raw_b64, str) and raw_b64.strip():
                                    audio_b64 = re.sub(r"\s+", "", raw_b64)
                                    mime_type = str(raw_mime).strip()[:120]
                                    rate_match = re.search(
                                        r"rate\s*=\s*([0-9]{4,6})", mime_type, flags=re.IGNORECASE
                                    )
                                    sample_rate = int(rate_match.group(1)) if rate_match else 24000
                                    if not (8000 <= sample_rate <= 96000):
                                        sample_rate = 24000
                                    return assert_safe_ai_catalog_payload({
                                        "schema": "cas-forex.explainer-tts/1",
                                        "ok": True,
                                        "model_id": tts_slug,
                                        "voice_name": clean_voice,
                                        "mime_type": mime_type,
                                        "sample_rate_hz": sample_rate,
                                        "audio_base64": audio_b64,
                                    })
                    safe_reason = "EMPTY_AUDIO_PAYLOAD"
                else:
                    safe_reason = f"HTTP_{status}"
            except FrontierTransportError as exc_tts:
                if exc_tts.status_code is not None:
                    safe_reason = f"HTTP_{exc_tts.status_code}"
                else:
                    safe_reason = type(exc_tts).__name__
            except OperatorUnavailable:
                raise
            except Exception as exc_tts:
                if _tts_epoch_abort[0] is not None:
                    raise _tts_epoch_abort[0]
                safe_reason = type(exc_tts).__name__
            finally:
                if last_tts_res[0] is not None and eff_gate is not None:
                    eff_gate.settle_attempt(last_tts_res[0], outcome="UNKNOWN", now=self._clock())
                    last_tts_res[0] = None
                headers.clear()

        return assert_safe_ai_catalog_payload({
            "schema": "cas-forex.explainer-tts/1",
            "ok": False,
            "fallback": "WEB_SPEECH",
            "reason": safe_reason,
        })

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
        breakers_snap = self._breakers.snapshot()

        active_entry = _CATALOG_BY_ID[active_id]
        active_ready = self._is_entry_ready(active_entry)
        frontier_ready_count = sum(1 for e in FRONTIER_MODEL_CATALOG if not e.is_fallback and self._is_entry_ready(e))
        items: list[dict[str, Any]] = []
        total_in_units = 0
        total_out_units = 0
        total_pico_usd = 0
        provider_acc: dict[str, dict[str, int]] = {
            p: {"input_units": 0, "output_units": 0, "spend_pico_usd": 0}
            for p in FRONTIER_PROVIDERS
        }

        for entry in FRONTIER_MODEL_CATALOG:
            st = stats_copy[entry.model_id]
            in_u = int(st["input_units"])
            out_u = int(st["output_units"])
            pico_u = int(st["spend_pico_usd"])
            total_in_units += in_u
            total_out_units += out_u
            total_pico_usd += pico_u
            p_acc = provider_acc.setdefault(
                entry.provider,
                {"input_units": 0, "output_units": 0, "spend_pico_usd": 0},
            )
            p_acc["input_units"] += in_u
            p_acc["output_units"] += out_u
            p_acc["spend_pico_usd"] += pico_u

            ready = self._is_entry_ready(entry)
            is_active = entry.model_id == active_id
            if is_active:
                availability = "ACTIVE_READY" if ready else ("OFFLINE_FALLBACK_DISABLED" if entry.is_fallback else "AWAITING_PROVIDER_KEY")
            else:
                availability = "READY" if ready else ("OFFLINE_FALLBACK_ONLY" if entry.is_fallback else "KEY_NOT_SET")
            cb_state = breakers_snap.get(entry.provider, {}).get("state", CircuitBreakerState.CLOSED.value)
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
                "input_units": in_u,
                "output_units": out_u,
                "total_units": in_u + out_u,
                "spend_micro_usd": pico_usd_to_micro_usd(pico_u),
                "spend_usd": pico_usd_to_decimal_text(pico_u),
                "circuit_state": cb_state,
            })

        provider_spend = {
            prov: {
                "input_units": p_acc["input_units"],
                "output_units": p_acc["output_units"],
                "total_units": p_acc["input_units"] + p_acc["output_units"],
                "spend_micro_usd": pico_usd_to_micro_usd(p_acc["spend_pico_usd"]),
                "spend_usd": pico_usd_to_decimal_text(p_acc["spend_pico_usd"]),
            }
            for prov, p_acc in provider_acc.items()
        }

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
            "offline_fallback_enabled": self._is_entry_ready(_CATALOG_BY_ID["qwen3:0.6b"]),
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
            "total_input_units": total_in_units,
            "total_output_units": total_out_units,
            "total_units": total_in_units + total_out_units,
            "total_spend_micro_usd": pico_usd_to_micro_usd(total_pico_usd),
            "total_spend_usd": pico_usd_to_decimal_text(total_pico_usd),
            "provider_spend": provider_spend,
            "circuit_breakers": breakers_snap,
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
