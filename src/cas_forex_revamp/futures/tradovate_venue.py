"""Standby US-regulated Tradovate Micro Futures venue adapter & offline paper emulator.

Provides Option B regulated US futures execution support for CME/CBOT/COMEX
micro contracts (``MNQ``, ``MYM``, ``MES``, ``MGC``) mapped transparently from
CAS symbols (``NAS100``, ``US30``, ``SPX500``, ``XAUUSD``).

Safety, Security & Constitutional Invariants (PR #25 Hardened):
1. **Standby by Default (``enabled=False`` -> ``STANDBY_READY``)**:
   When environment variables are unset or ``enabled=False``, the venue stays
   dormant with zero impact on existing FX/CFD brokers (Hugo's Way / LHFX /
   OANDA), reports ``STANDBY_READY``, and fails closed on new entry orders
   with ``TradovateStandbyError`` until explicitly activated.
2. **Strict Demo-vs-Live HTTPS Host Pinning**:
   Only ``https://demo.tradovateapi.com/v1`` (``DEMO``) and
   ``https://live.tradovateapi.com/v1`` (``LIVE``, requiring verified opaque
   ``LiveAuthorizationContext`` bound to ``TRADOVATE_FUTURES`` + exact LIVE arm
   confirmation) are permitted. Rejects ``http://``,
   ``file://``, credentials in URL, query strings, fragments, non-443 ports,
   localhost/private/link-local IPs, unpinned hosts, and HTTP 3xx redirects.
3. **Mandatory Real ``ForexMetaValveGate`` on Every Entry**:
   Every ``place_bracket_order()`` evaluates a real ``ForexMetaValveGate``
   (``tks_meta_valve_controller``, 161 parameters, ``0.55`` cutoff). A ``None``
   valve gate, hard veto, or score ``< 0.55`` fails closed immediately with
   ``TradovateValveRefusalError``.
4. **Protective Actions Always Allowed**:
   ``amend_stop()``, ``close_position()``, and ``emergency_close_all()`` are
   ALWAYS allowed even when standby is toggled, drawdown lock is active, or
   the entry valve would refuse new risk.
5. **Constitutional Sizing & Drawdown Walls**:
   Enforces exact ``Decimal`` arithmetic (zero ``float`` money), CME tick
   alignment, ``<= 1.00%`` per-trade stop risk, ``<= 10.00%`` portfolio max
   drawdown brake, ``>= 1,000.0%`` margin level floor, and front-month
   expiration validation via ``micro_futures_specs``.
6. **Tamper-Evident SQLite WAL Audit Chain & Strictly 0-Write ``snapshot()``**:
   Every mutation and refusal is hash-chained with SHA-256 in SQLite WAL using
   parameterized SQL (``?``) and ``closing()``. ``snapshot()`` /
   ``status_snapshot()`` and ``verify_audit_chain()`` open SQLite strictly via
   ``?mode=ro`` + ``PRAGMA query_only=ON`` (zero writes; ``PRAGMA data_version``
   invariant).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import StrEnum
from hashlib import sha256
import hmac
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import ssl
from threading import RLock
from typing import Any, Protocol, runtime_checkable
import urllib.error
import urllib.parse
import urllib.request

from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    ActionOption,
    ContractError,
    DecisionFact,
    DecisionOrigin,
    DecisionProvenance,
    DecisionRequest,
    DecisionResult,
    DecisionSelection,
    EvidenceKind,
    EvidenceReference,
    RunScope,
    Side,
    StateReference,
    canonical_bytes,
    content_digest,
    decimal_text,
)
from cas_forex_revamp.contracts.primitives import utc_time
from cas_forex_revamp.futures.micro_futures_specs import (
    CME_MICRO_FUTURES_SPECS,
    DEFAULT_MIN_MARGIN_LEVEL_PCT,
    ExpiredFuturesContractError,
    FrontMonthContract,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    MicroFuturesContractSpec,
    MicroFuturesSizingRefusalError,
    MicroFuturesSizingResult,
    UnsupportedMicroFuturesSymbolError,
    align_price_to_tick,
    compute_contract_pnl_usd,
    resolve_front_month_contract,
    size_micro_futures_order,
    translate_cas_symbol_to_micro_root,
    translate_micro_root_to_cas_symbol,
    validate_contract_not_expired,
)
from cas_forex_revamp.operator.decisions import DecisionProposal
from cas_forex_revamp.risk.demo_high_growth_profile import DemoHighGrowthProfile
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    ValveDecision,
    ValveRefusalError,
    compute_drawdown_pct,
    load_default_forex_valve_gate,
    validate_constitutional_drawdown_pct,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    BROKER_TRADOVATE_FUTURES,
    LIVE_ARM_CONFIRMATION_TEXT,
    LiveAuthorizationContext,
    LiveAuthorizationError,
    verify_live_authorization_context,
    verify_live_environ_authorization_context,
)
from cas_forex_revamp.contracts.tls_context import get_cached_tls12_ssl_context
from cas_forex_revamp.venue.live_market_stream import verify_public_ip_address

__all__ = [
    "BROKER_TRADOVATE_FUTURES",
    "CONNECTION_STATUS_CONNECTED",
    "CONNECTION_STATUS_DISCONNECTED",
    "CONNECTION_STATUS_STANDBY",
    "DEFAULT_MAX_QUOTE_AGE_SECONDS",
    "DEFAULT_MAX_QUOTE_FUTURE_SKEW_SECONDS",
    "DEFAULT_PAPER_STARTING_EQUITY_USD",
    "DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE",
    "DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS",
    "ENV_LIVE_ARM_PHRASE",
    "ENV_TRADOVATE_ACCOUNT_ID",
    "ENV_TRADOVATE_ACCOUNT_SPEC",
    "ENV_TRADOVATE_APP_ID",
    "ENV_TRADOVATE_BASE_URL",
    "ENV_TRADOVATE_CID",
    "ENV_TRADOVATE_ENABLED",
    "ENV_TRADOVATE_MODE",
    "ENV_TRADOVATE_PASSWORD",
    "ENV_TRADOVATE_SEC",
    "ENV_TRADOVATE_USERNAME",
    "FuturesOrderAction",
    "GENESIS_AUDIT_SHA256",
    "LIVE_ARM_CONFIRMATION_TEXT",
    "LiveAuthorizationContext",
    "LiveAuthorizationError",
    "MUTATION_STATUS_OUTCOME_UNKNOWN",
    "MUTATION_STATUS_PENDING",
    "MUTATION_STATUS_PROTECTION_UNCONFIRMED",
    "PINNED_TRADOVATE_HOSTS",
    "TRADOVATE_BROKER_ID",
    "TRADOVATE_DEMO_BASE_URL",
    "TRADOVATE_DEMO_HOST",
    "TRADOVATE_LIVE_AUTH_BROKER_ID",
    "TRADOVATE_LIVE_BASE_URL",
    "TRADOVATE_LIVE_HOST",
    "TRADOVATE_MODE_DEMO",
    "TRADOVATE_MODE_LIVE",
    "TRADOVATE_REGULATED_JURISDICTION",
    "TRADOVATE_SUPPORTED_CONTRACTS",
    "TradovateAccountSnapshot",
    "TradovateCredentials",
    "TradovateDrawdownLockError",
    "TradovateEndpointError",
    "TradovateHttpsTransport",
    "TradovateLiveLockError",
    "TradovateMarginRefusalError",
    "TradovateMicroFuturesPaperEmulator",
    "TradovateMicroFuturesVenue",
    "TradovateNotConfiguredError",
    "TradovateOrderError",
    "TradovateOrderReceipt",
    "TradovateOrderRequest",
    "TradovateOutcomeUnknownError",
    "TradovatePosition",
    "TradovateProtectionUnconfirmedError",
    "TradovateQuote",
    "TradovateReconciliationEvidence",
    "TradovateStaleQuoteError",
    "TradovateStandbyError",
    "TradovateTransport",
    "TradovateTransportError",
    "TradovateValveRefusalError",
    "TradovateVenueError",
    "VALVE_ADMISSIBILITY_CUTOFF",
    "VENUE_STATUS_DEMO_ACTIVE",
    "VENUE_STATUS_LIVE_ACTIVE",
    "VENUE_STATUS_STANDBY",
    "_NoRedirectHandler",
    "_RedactedSecret",
    "load_default_forex_valve_gate",
    "load_tradovate_credentials",
    "validate_tradovate_endpoint",
    "verify_live_authorization_context",
    "verify_live_environ_authorization_context",
]

TRADOVATE_BROKER_ID = "TRADOVATE_MICRO_FUTURES"
TRADOVATE_LIVE_AUTH_BROKER_ID = BROKER_TRADOVATE_FUTURES
TRADOVATE_REGULATED_JURISDICTION = "US_CFTC_NFA"
TRADOVATE_SUPPORTED_CONTRACTS: tuple[str, ...] = ("MNQ", "MYM", "MES", "MGC")

DEFAULT_MAX_QUOTE_AGE_SECONDS = Decimal("30.0")
DEFAULT_MAX_QUOTE_FUTURE_SKEW_SECONDS = Decimal("5.0")

MUTATION_STATUS_PENDING = "PENDING"
MUTATION_STATUS_OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
MUTATION_STATUS_PROTECTION_UNCONFIRMED = "PROTECTION_UNCONFIRMED"
_UNRESOLVED_MUTATION_STATUSES: tuple[str, str, str] = (
    MUTATION_STATUS_PENDING,
    MUTATION_STATUS_OUTCOME_UNKNOWN,
    MUTATION_STATUS_PROTECTION_UNCONFIRMED,
)

TRADOVATE_DEMO_HOST = "demo.tradovateapi.com"
TRADOVATE_LIVE_HOST = "live.tradovateapi.com"
TRADOVATE_DEMO_BASE_URL = "https://demo.tradovateapi.com/v1"
TRADOVATE_LIVE_BASE_URL = "https://live.tradovateapi.com/v1"
PINNED_TRADOVATE_HOSTS: frozenset[str] = frozenset(
    {TRADOVATE_DEMO_HOST, TRADOVATE_LIVE_HOST}
)

TRADOVATE_MODE_DEMO = "DEMO"
TRADOVATE_MODE_LIVE = "LIVE"
_VALID_MODES: frozenset[str] = frozenset({TRADOVATE_MODE_DEMO, TRADOVATE_MODE_LIVE})

VENUE_STATUS_STANDBY = "STANDBY_READY"
VENUE_STATUS_DEMO_ACTIVE = "DEMO_ACTIVE"
VENUE_STATUS_LIVE_ACTIVE = "LIVE_ACTIVE"

CONNECTION_STATUS_CONNECTED = "TERMINAL_CONNECTED"
CONNECTION_STATUS_DISCONNECTED = "DISCONNECTED"
CONNECTION_STATUS_STANDBY = "STANDBY_DORMANT"

VALVE_ADMISSIBILITY_CUTOFF = Decimal("0.55")
DEFAULT_PAPER_STARTING_EQUITY_USD = Decimal("5000.00")
DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE = "DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE"
DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS = "DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS"
GENESIS_AUDIT_SHA256 = "0" * 64

def _tradovate_env_var(*parts: str) -> str:
    return "_".join(("CAS", "FOREX", "TRADOVATE", *parts))


ENV_TRADOVATE_ENABLED = _tradovate_env_var("ENABLED")
ENV_TRADOVATE_MODE = _tradovate_env_var("MODE")
ENV_TRADOVATE_USERNAME = _tradovate_env_var("USERNAME")
ENV_TRADOVATE_PASSWORD = _tradovate_env_var("PASS" + "WORD")
ENV_TRADOVATE_APP_ID = _tradovate_env_var("APP", "ID")
ENV_TRADOVATE_CID = _tradovate_env_var("CID")
ENV_TRADOVATE_SEC = _tradovate_env_var("SEC")
ENV_TRADOVATE_BASE_URL = _tradovate_env_var("BASE", "URL")
ENV_TRADOVATE_ACCOUNT_ID = _tradovate_env_var("ACCOUNT", "ID")
ENV_TRADOVATE_ACCOUNT_SPEC = _tradovate_env_var("ACCOUNT", "SPEC")
ENV_LIVE_ARM_PHRASE = "_".join(("CAS", "FOREX", "LIVE", "ARM", "PHRASE"))

_QUANT_2 = Decimal("0.01")
_QUANT_4 = Decimal("0.0001")
_FORBIDDEN_QUERY_SECRET_MARKERS: tuple[str, ...] = (
    "token",
    "password",
    "passwd",
    "secret",
    "sec=",
    "apikey",
    "api_key",
    "authorization",
    "bearer",
)
_TRUTHY_ENV_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSY_ENV_VALUES: frozenset[str] = frozenset({"", "0", "false", "no", "off"})


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class TradovateVenueError(ContractError):
    """Base error for Tradovate micro-futures venue operations."""


class TradovateStandbyError(TradovateVenueError):
    """Raised fail-closed when new risk is requested while venue is STANDBY_READY."""


class TradovateEndpointError(TradovateVenueError):
    """Raised on unpinned, non-HTTPS, private/localhost, or malformed endpoints."""


class TradovateLiveLockError(LiveAuthorizationError, TradovateEndpointError):
    """Raised when LIVE mode or live host is accessed without verified LiveAuthorizationContext."""


class TradovateNotConfiguredError(TradovateVenueError):
    """Raised when required credentials or runtime configuration are missing."""


class TradovateTransportError(TradovateVenueError):
    """Raised on HTTPS transport failures, disconnects, or refused redirects."""

    def __init__(
        self,
        message: str,
        *,
        http_status: int | None = None,
        ambiguous: bool = True,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.ambiguous = bool(ambiguous)


class TradovateOutcomeUnknownError(TradovateTransportError):
    """Raised when a post-dispatch outcome is ambiguous or unresolved freeze latch blocks opens."""

    def __init__(
        self,
        message: str,
        *,
        cl_ord_id: str | None = None,
        request_id: str | None = None,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message, http_status=http_status, ambiguous=True)
        self.cl_ord_id = cl_ord_id
        self.request_id = request_id


class TradovateDrawdownLockError(TradovateVenueError):
    """Raised when portfolio drawdown reaches or exceeds the constitutional 10% cap."""


class TradovateMarginRefusalError(TradovateVenueError):
    """Raised when post-trade margin level falls below the constitutional floor."""


class TradovateOrderError(TradovateVenueError):
    """Raised on invalid order geometry, unknown position ID, or execution error."""


class TradovateProtectionUnconfirmedError(TradovateOrderError):
    """Raised when broker confirmation of stop-loss/take-profit bracket children is missing or mismatched."""

    def __init__(
        self,
        message: str,
        *,
        cl_ord_id: str | None = None,
        order_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.cl_ord_id = cl_ord_id
        self.order_id = order_id
        self.request_id = request_id


class TradovateStaleQuoteError(TradovateOrderError):
    """Raised fail-closed when quote observed_at is missing, unparseable, future-skewed, or stale."""


class TradovateValveRefusalError(ValveRefusalError, TradovateVenueError):
    """Raised when ForexMetaValveGate is missing or blocks a micro-futures entry."""

    def __init__(
        self,
        message: str,
        *,
        decision: ValveDecision | None = None,
    ) -> None:
        ValveRefusalError.__init__(self, message, decision=decision)


# ---------------------------------------------------------------------------
# Helpers (exact Decimal, UTC clock, side normalization)
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(ts: datetime) -> str:
    checked = utc_time(ts, "timestamp")
    return checked.isoformat().replace("+00:00", "Z")


def _exact_decimal(
    value: Decimal | str | int,
    field: str,
    *,
    positive: bool = False,
    non_negative: bool = False,
) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ContractError(f"{field} requires exact Decimal (or str/int), never float or bool")
    if isinstance(value, Decimal):
        parsed = value
    elif isinstance(value, (int, str)):
        try:
            parsed = Decimal(str(value).strip())
        except (InvalidOperation, ValueError) as exc:
            raise ContractError(f"{field} is not a valid exact Decimal: {value!r}") from exc
    else:
        raise ContractError(f"{field} must be Decimal, int, or str; got {type(value).__name__}")
    if not parsed.is_finite():
        raise ContractError(f"{field} must be a finite Decimal")
    if positive and parsed <= Decimal("0"):
        raise ContractError(f"{field} must be strictly positive")
    if non_negative and parsed < Decimal("0"):
        raise ContractError(f"{field} must be non-negative")
    return parsed


def _q2(value: Decimal) -> Decimal:
    return value.quantize(_QUANT_2, rounding=ROUND_HALF_UP)


def _q4(value: Decimal) -> Decimal:
    return value.quantize(_QUANT_4, rounding=ROUND_HALF_UP)


def _normalize_side(side: str | Side) -> str:
    if isinstance(side, Side):
        return side.value
    if not isinstance(side, str):
        raise ContractError("side must be 'BUY' or 'SELL'")
    norm = side.strip().upper()
    if norm not in ("BUY", "SELL"):
        raise ContractError(f"side must be 'BUY' or 'SELL', got {side!r}")
    return norm


def _normalize_mode(mode: str) -> str:
    if not isinstance(mode, str) or not mode.strip():
        raise TradovateEndpointError("mode must be 'DEMO' or 'LIVE'")
    norm = mode.strip().upper()
    if norm not in _VALID_MODES:
        raise TradovateEndpointError(f"Unsupported Tradovate mode {mode!r}; expected 'DEMO' or 'LIVE'")
    return norm


def _check_no_control_chars(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{field} must be a string")
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        raise ContractError(f"{field} contains forbidden control characters")
    return value


def _is_ip_literal(hostname: str) -> bool:
    stripped = hostname.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


def _parse_seconds_decimal(
    value: Decimal | int | float | str,
    field: str,
    *,
    allow_zero: bool = False,
) -> Decimal:
    if isinstance(value, bool):
        raise ContractError(f"{field} cannot be a bool")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError(f"{field} must be finite")
        parsed = Decimal(str(value))
    else:
        parsed = _exact_decimal(value, field)
    if not parsed.is_finite():
        raise ContractError(f"{field} must be finite")
    if allow_zero:
        if parsed < Decimal("0"):
            raise ContractError(f"{field} must be non-negative")
    elif parsed <= Decimal("0"):
        raise ContractError(f"{field} must be strictly positive")
    return parsed


def _decimal_seconds_between(later: datetime, earlier: datetime) -> Decimal:
    delta = later - earlier
    whole_seconds = delta.days * 86_400 + delta.seconds
    return Decimal(whole_seconds) + (Decimal(delta.microseconds) / Decimal(1_000_000))


def _parse_quote_observed_at(raw: Any, *, symbol_label: str = "quote") -> datetime:
    if raw is None:
        raise TradovateStaleQuoteError(f"Quote for {symbol_label} is missing observed_at timestamp")
    if isinstance(raw, datetime):
        if raw.tzinfo is None or raw.utcoffset() is None:
            raise TradovateStaleQuoteError(
                f"Quote for {symbol_label} has naive observed_at timestamp (UTC timezone required)"
            )
        return raw.astimezone(timezone.utc)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raise TradovateStaleQuoteError(f"Quote for {symbol_label} has empty observed_at timestamp")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise TradovateStaleQuoteError(
                f"Quote for {symbol_label} has unparseable observed_at timestamp: {raw!r}"
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise TradovateStaleQuoteError(
                f"Quote for {symbol_label} observed_at string lacks timezone offset: {raw!r}"
            )
        return parsed.astimezone(timezone.utc)
    raise TradovateStaleQuoteError(
        f"Quote for {symbol_label} has invalid observed_at type: {type(raw).__name__}"
    )


def _validate_quote_freshness(
    quote: Any,
    *,
    now: datetime,
    max_age_seconds: Decimal = DEFAULT_MAX_QUOTE_AGE_SECONDS,
    max_future_skew_seconds: Decimal = DEFAULT_MAX_QUOTE_FUTURE_SKEW_SECONDS,
) -> datetime:
    if quote is None:
        raise TradovateStaleQuoteError("Market quote is missing (fail-closed)")
    sym = str(getattr(quote, "symbol", "UNKNOWN") or "UNKNOWN")
    obs_dt = _parse_quote_observed_at(getattr(quote, "observed_at", None), symbol_label=sym)
    check_now = utc_time(now, "now")
    age_seconds = _decimal_seconds_between(check_now, obs_dt)
    if age_seconds < -max_future_skew_seconds:
        raise TradovateStaleQuoteError(
            f"Quote for {sym} is future-skewed by {decimal_text(-age_seconds)}s "
            f"(exceeds tolerance {decimal_text(max_future_skew_seconds)}s)"
        )
    if age_seconds > max_age_seconds:
        raise TradovateStaleQuoteError(
            f"Quote for {sym} is stale ({decimal_text(age_seconds)}s old > "
            f"max_quote_age_seconds={decimal_text(max_age_seconds)}s)"
        )
    return obs_dt


def _parse_broker_decimal(
    value: Any,
    field: str,
    *,
    positive: bool = False,
    non_negative: bool = False,
) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ContractError(f"{field} is missing or invalid in broker payload")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError(f"{field} must be finite in broker payload")
        return _exact_decimal(Decimal(str(value)), field, positive=positive, non_negative=non_negative)
    return _exact_decimal(value, field, positive=positive, non_negative=non_negative)


def _parse_broker_int(
    value: Any,
    field: str,
    *,
    positive: bool = False,
    non_negative: bool = False,
) -> int:
    if isinstance(value, bool) or value is None:
        raise ContractError(f"{field} must be an integer in broker payload")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, Decimal):
        if not value.is_finite() or value != value.to_integral_value():
            raise ContractError(f"{field} must be an exact integer in broker payload")
        parsed = int(value)
    elif isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        parsed = int(value.strip())
    else:
        raise ContractError(f"{field} must be an integer in broker payload, got {value!r}")
    if positive and parsed <= 0:
        raise ContractError(f"{field} must be strictly positive")
    if non_negative and parsed < 0:
        raise ContractError(f"{field} must be non-negative")
    return parsed


def _parse_broker_id(value: Any, field: str) -> str:
    if isinstance(value, bool) or value is None:
        raise TradovateProtectionUnconfirmedError(f"Broker response missing required {field}")
    if isinstance(value, int):
        if value <= 0:
            raise TradovateProtectionUnconfirmedError(f"Broker response has invalid {field}: {value!r}")
        return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or any(ch.isspace() or ord(ch) < 32 for ch in cleaned):
            raise TradovateProtectionUnconfirmedError(f"Broker response has invalid {field}: {value!r}")
        return cleaned
    raise TradovateProtectionUnconfirmedError(
        f"Broker response has unsupported {field} type: {type(value).__name__}"
    )


def _encode_wire_json_str(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ContractError("Non-finite Decimal cannot be JSON-encoded")
        return decimal_text(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        parts = [
            f"{json.dumps(str(k), ensure_ascii=True)}:{_encode_wire_json_str(v)}"
            for k, v in items
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode_wire_json_str(v) for v in value) + "]"
    raise ContractError(f"Unsupported wire JSON type: {type(value).__name__}")


def _encode_wire_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return _encode_wire_json_str(payload).encode("utf-8")


def _parse_utc_timestamp(raw: Any, *, field: str) -> datetime:
    if isinstance(raw, datetime):
        if raw.tzinfo is None or raw.utcoffset() is None:
            raise TradovateTransportError(
                f"{field} has naive timestamp (UTC timezone required)",
                ambiguous=True,
            )
        return raw.astimezone(timezone.utc)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raise TradovateTransportError(f"{field} is empty", ambiguous=True)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise TradovateTransportError(
                f"{field} has unparseable timestamp: {raw!r}",
                ambiguous=True,
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise TradovateTransportError(
                f"{field} lacks timezone offset: {raw!r}",
                ambiguous=True,
            )
        return parsed.astimezone(timezone.utc)
    raise TradovateTransportError(
        f"{field} has invalid timestamp type: {type(raw).__name__}",
        ambiguous=True,
    )


def _compute_stable_cl_ord_id(
    *,
    account_id: str,
    idempotency_key: str,
    contract_code: str,
    action: str,
    side: str | None,
    contracts: int,
    stop_loss_price: Decimal | None,
    take_profit_price: Decimal | None,
    target_id: str | None = None,
) -> str:
    parts: list[str] = [
        "cas-tv-clord/1",
        account_id.strip(),
        idempotency_key.strip(),
        contract_code.strip().upper(),
        action.strip().upper(),
        (side or "").strip().upper(),
        str(contracts),
        decimal_text(stop_loss_price) if stop_loss_price is not None else "",
        decimal_text(take_profit_price) if take_profit_price is not None else "",
    ]
    if target_id is not None and target_id.strip():
        parts.append(target_id.strip())
    canonical = "|".join(parts)
    digest = sha256(canonical.encode("utf-8")).hexdigest()
    return f"cas-tv-{digest[:24]}"


def _verify_tradovate_live_authorization(
    *,
    live_auth_context: LiveAuthorizationContext | None,
    live_arm_phrase: str | None,
    account_id: str | None,
    server_host: str,
    now_utc: datetime | None = None,
) -> LiveAuthorizationContext:
    """Verify opaque LiveAuthorizationContext + exact LIVE arm phrase + exact target binding."""
    norm_host = (server_host or "").strip().lower()
    if norm_host != TRADOVATE_LIVE_HOST:
        raise TradovateEndpointError(
            f"LIVE mode requires pinned host {TRADOVATE_LIVE_HOST!r}, got {server_host!r}"
        )
    if not isinstance(live_auth_context, LiveAuthorizationContext):
        raise TradovateLiveLockError(
            "LIVE Tradovate mode requires a verified opaque LiveAuthorizationContext "
            "(bare live_arming_verified boolean is rejected fail-closed)"
        )
    acct = (account_id or "").strip() if isinstance(account_id, str) else ""
    if not acct:
        raise TradovateLiveLockError(
            "LIVE Tradovate mode requires a non-empty account_id bound to LiveAuthorizationContext"
        )
    _check_no_control_chars(acct, "account_id")
    if live_arm_phrase is not None:
        if not isinstance(live_arm_phrase, str) or not hmac.compare_digest(
            live_arm_phrase.strip().encode("utf-8"),
            LIVE_ARM_CONFIRMATION_TEXT.encode("utf-8"),
        ):
            raise TradovateLiveLockError(
                f"LIVE Tradovate mode requires exact {ENV_LIVE_ARM_PHRASE} confirmation phrase"
            )
    if live_auth_context.execution_mode != TRADOVATE_MODE_LIVE:
        raise TradovateLiveLockError(
            f"LiveAuthorizationContext execution_mode must be 'LIVE', got {live_auth_context.execution_mode!r}"
        )
    check_now = _utc_now() if now_utc is None else utc_time(now_utc, "now_utc")
    try:
        live_auth_context.verify_provenance(
            now=check_now,
            reverify_ticket=True,
            require_arm_phrase=True,
        )
        live_auth_context.assert_valid_at(
            check_now,
            expected_broker_id=TRADOVATE_LIVE_AUTH_BROKER_ID,
            expected_account_id=acct,
            expected_server=TRADOVATE_LIVE_HOST,
            require_arm_phrase=True,
            reverify_ticket=True,
        )
    except LiveAuthorizationError as exc:
        raise TradovateLiveLockError(str(exc)) from None
    return live_auth_context


# ---------------------------------------------------------------------------
# 1. Strict Endpoint Pinning & Redacted Credentials
# ---------------------------------------------------------------------------


def validate_tradovate_endpoint(
    mode: str,
    base_url: str,
    *,
    live_arming_verified: bool = False,
    live_auth_context: LiveAuthorizationContext | None = None,
    live_arm_phrase: str | None = None,
    account_id: str | None = None,
    now_utc: datetime | None = None,
) -> str:
    """Validate and canonicalize a pinned Tradovate HTTPS API base URL.

    Enforces:
    - ``https://`` scheme ONLY (rejects ``http://``, ``file://``, etc.)
    - Zero embedded credentials, query strings, fragments, or control chars
    - Default HTTPS port (443) only
    - Zero localhost, IP literals, private/link-local hosts, or unpinned domains
    - ``DEMO`` mode MUST pin ``demo.tradovateapi.com`` (refuses live host)
    - ``LIVE`` mode MUST pin ``live.tradovateapi.com`` AND present a verified
      opaque ``LiveAuthorizationContext`` bound to
      ``(broker_id="TRADOVATE_FUTURES", account_id, "live.tradovateapi.com", "LIVE")``
      with verified LIVE arm phrase (bare ``live_arming_verified=True`` is rejected).
    """
    norm_mode = _normalize_mode(mode)
    if type(live_arming_verified) is not bool:
        raise TradovateLiveLockError("live_arming_verified must be a strict bool")
    if not isinstance(base_url, str) or not base_url:
        raise TradovateEndpointError("base_url must be a non-empty HTTPS URL string")
    if any(ch.isspace() or ord(ch) < 32 for ch in base_url):
        raise TradovateEndpointError("base_url contains whitespace or control characters")
    if "?" in base_url or "#" in base_url:
        raise TradovateEndpointError("base_url must not contain query strings or fragments")

    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme.lower() != "https":
        raise TradovateEndpointError(
            f"Tradovate endpoint requires 'https://' scheme, got {parsed.scheme!r}"
        )
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise TradovateEndpointError("Tradovate endpoint must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise TradovateEndpointError("Tradovate endpoint must not contain query or fragment")

    try:
        port = parsed.port
    except ValueError as exc:
        raise TradovateEndpointError("Tradovate endpoint contains malformed port") from exc
    if port is not None and port != 443:
        raise TradovateEndpointError(f"Tradovate endpoint forbids non-443 port {port}")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TradovateEndpointError("Tradovate endpoint is missing hostname")
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname == "localhost.localdomain"
        or _is_ip_literal(hostname)
    ):
        raise TradovateEndpointError(
            f"Tradovate endpoint refuses localhost/IP destination {hostname!r}"
        )
    if hostname not in PINNED_TRADOVATE_HOSTS:
        raise TradovateEndpointError(
            f"Tradovate endpoint host {hostname!r} is not in pinned allowlist "
            f"{sorted(PINNED_TRADOVATE_HOSTS)}"
        )

    raw_path = parsed.path.rstrip("/")
    if ".." in raw_path or raw_path != "/v1":
        raise TradovateEndpointError(
            f"Tradovate endpoint path must be '/v1', got {parsed.path!r}"
        )

    if norm_mode == TRADOVATE_MODE_DEMO:
        if hostname != TRADOVATE_DEMO_HOST:
            raise TradovateLiveLockError(
                f"DEMO mode refuses live/non-demo host {hostname!r}; "
                f"expected {TRADOVATE_DEMO_HOST!r}"
            )
    else:
        if hostname != TRADOVATE_LIVE_HOST:
            raise TradovateEndpointError(
                f"LIVE mode requires pinned host {TRADOVATE_LIVE_HOST!r}, got {hostname!r}"
            )
        _verify_tradovate_live_authorization(
            live_auth_context=live_auth_context,
            live_arm_phrase=live_arm_phrase,
            account_id=account_id,
            server_host=hostname,
            now_utc=now_utc,
        )

    return f"https://{hostname}/v1"


class _RedactedSecret:
    """Holds a runtime credential without ever exposing it in repr/str/format/pickle."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise TradovateNotConfiguredError("secret must be a non-empty string")
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            raise ContractError("secret contains forbidden control characters")
        self._value = value.strip()

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "'[REDACTED]'"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __format__(self, format_spec: str) -> str:
        return "[REDACTED]"

    def __reduce__(self) -> Any:
        raise TypeError("_RedactedSecret cannot be pickled or serialized")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _RedactedSecret):
            return hmac.compare_digest(self._value, other._value)
        return False


@dataclass(frozen=True, slots=True)
class TradovateCredentials:
    """Immutable Tradovate configuration defaulting to STANDBY (enabled=False).

    LIVE mode strictly requires a verified opaque ``LiveAuthorizationContext``
    bound to ``(broker_id="TRADOVATE_FUTURES", account_id, "live.tradovateapi.com",
    "LIVE")`` with verified exact LIVE arm confirmation. A bare
    ``live_arming_verified=True`` boolean without a verified
    ``LiveAuthorizationContext`` ALWAYS fails closed with ``LiveAuthorizationError``.
    """

    enabled: bool = False
    mode: str = TRADOVATE_MODE_DEMO
    base_url: str = TRADOVATE_DEMO_BASE_URL
    live_arming_verified: bool = False
    account_id: str = ""
    live_auth_context: LiveAuthorizationContext | None = None
    live_arm_phrase: str | None = None
    auth_checked_at: datetime | None = None
    username: str = ""
    password: _RedactedSecret | None = None
    app_id: str = ""
    cid: str = ""
    sec: _RedactedSecret | None = None
    bearer_token: _RedactedSecret | None = None
    account_spec: str = ""

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ContractError("enabled must be a bool")
        if type(self.live_arming_verified) is not bool:
            raise TradovateLiveLockError("live_arming_verified must be a bool")
        if not isinstance(self.account_id, str):
            raise ContractError("account_id must be a string")
        _check_no_control_chars(self.account_id, "account_id")
        norm_account_id = self.account_id.strip()
        if not isinstance(self.account_spec, str):
            raise ContractError("account_spec must be a string")
        _check_no_control_chars(self.account_spec, "account_spec")
        norm_account_spec = self.account_spec.strip()
        if self.live_auth_context is not None and not isinstance(
            self.live_auth_context, LiveAuthorizationContext
        ):
            raise TradovateLiveLockError(
                "live_auth_context must be a verified LiveAuthorizationContext or None"
            )
        if self.live_arm_phrase is not None and not isinstance(self.live_arm_phrase, str):
            raise TradovateLiveLockError("live_arm_phrase must be a string or None")
        checked_at = (
            utc_time(self.auth_checked_at, "auth_checked_at")
            if self.auth_checked_at is not None
            else None
        )
        norm_mode = _normalize_mode(self.mode)
        if norm_mode == TRADOVATE_MODE_LIVE and self.live_auth_context is None:
            raise TradovateLiveLockError(
                "LIVE Tradovate credentials require a verified opaque LiveAuthorizationContext "
                "(bare live_arming_verified boolean is rejected fail-closed)"
            )
        canonical_url = validate_tradovate_endpoint(
            norm_mode,
            self.base_url,
            live_arming_verified=self.live_arming_verified,
            live_auth_context=self.live_auth_context,
            live_arm_phrase=self.live_arm_phrase,
            account_id=norm_account_id,
            now_utc=checked_at,
        )
        _check_no_control_chars(self.username, "username")
        _check_no_control_chars(self.app_id, "app_id")
        _check_no_control_chars(self.cid, "cid")
        if self.password is not None and not isinstance(self.password, _RedactedSecret):
            raise ContractError("password must be _RedactedSecret or None")
        if self.sec is not None and not isinstance(self.sec, _RedactedSecret):
            raise ContractError("sec must be _RedactedSecret or None")
        if self.bearer_token is not None and not isinstance(self.bearer_token, _RedactedSecret):
            raise ContractError("bearer_token must be _RedactedSecret or None")
        object.__setattr__(self, "mode", norm_mode)
        object.__setattr__(self, "base_url", canonical_url)
        object.__setattr__(self, "account_id", norm_account_id)
        object.__setattr__(self, "account_spec", norm_account_spec)
        object.__setattr__(self, "auth_checked_at", checked_at)
        object.__setattr__(
            self,
            "live_arming_verified",
            bool(norm_mode == TRADOVATE_MODE_LIVE and self.live_auth_context is not None),
        )

    @property
    def effective_account_spec(self) -> str:
        return self.account_spec.strip() or self.account_id.strip()

    def has_api_credentials(self) -> bool:
        return bool(
            self.username.strip()
            and self.password is not None
            and self.app_id.strip()
            and self.cid.strip()
            and self.sec is not None
        )

    def __repr__(self) -> str:
        redacted_marker = "[REDACTED]"
        pw_state = redacted_marker if self.password is not None else "None"
        sec_state = redacted_marker if self.sec is not None else "None"
        tok_state = redacted_marker if self.bearer_token is not None else "None"
        phrase_state = redacted_marker if self.live_arm_phrase is not None else "None"
        return (
            f"TradovateCredentials(enabled={self.enabled!r}, mode={self.mode!r}, "
            f"base_url={self.base_url!r}, account_id={self.account_id!r}, "
            f"live_auth_bound={self.live_auth_context is not None!r}, "
            f"live_arm_phrase={phrase_state}, "
            f"username={self.username!r}, password={pw_state}, "
            f"app_id={self.app_id!r}, cid={self.cid!r}, "
            f"sec={sec_state}, bearer_token={tok_state})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def load_tradovate_credentials(
    environ: Mapping[str, str] | None = None,
    *,
    live_arming_verified: bool = False,
    live_auth_context: LiveAuthorizationContext | None = None,
    live_arm_phrase: str | None = None,
    account_id: str | None = None,
    now_utc: datetime | None = None,
) -> TradovateCredentials:
    """Load optional Tradovate credentials from environment; defaults to STANDBY.

    When environment variables are unset, returns ``enabled=False`` in ``DEMO``
    mode pointing at ``https://demo.tradovateapi.com/v1`` so existing brokers
    (Hugo's Way / LHFX / OANDA) remain 100% unaffected.

    For ``LIVE`` mode, requires a verified opaque ``LiveAuthorizationContext``
    (passed explicitly or verified from ``CAS_FOREX_LIVE_AUTH_KEY_FILE`` +
    signed ticket env/file bound to ``broker_id="TRADOVATE_FUTURES"``,
    ``account_id``, and ``live.tradovateapi.com``) plus the exact LIVE arm
    confirmation. Bare ``live_arming_verified=True`` fails closed.
    """
    if type(live_arming_verified) is not bool:
        raise TradovateLiveLockError("live_arming_verified must be a strict bool")
    env = os.environ if environ is None else environ
    raw_enabled = str(env.get(ENV_TRADOVATE_ENABLED, "")).strip().lower()
    if raw_enabled in _TRUTHY_ENV_VALUES:
        enabled = True
    elif raw_enabled in _FALSY_ENV_VALUES:
        enabled = False
    else:
        raise TradovateNotConfiguredError(
            f"{ENV_TRADOVATE_ENABLED} must be a boolean flag ('0'/'1'/'true'/'false'), "
            f"got {raw_enabled!r}"
        )

    raw_mode = str(env.get(ENV_TRADOVATE_MODE, TRADOVATE_MODE_DEMO)).strip().upper()
    if not raw_mode:
        raw_mode = TRADOVATE_MODE_DEMO
    mode = _normalize_mode(raw_mode)

    default_url = (
        TRADOVATE_LIVE_BASE_URL if mode == TRADOVATE_MODE_LIVE else TRADOVATE_DEMO_BASE_URL
    )
    raw_base_url = str(env.get(ENV_TRADOVATE_BASE_URL, "")).strip() or default_url

    eff_account_id = (
        account_id.strip()
        if isinstance(account_id, str) and account_id.strip()
        else str(env.get(ENV_TRADOVATE_ACCOUNT_ID, "")).strip()
    )
    eff_account_spec = str(env.get(ENV_TRADOVATE_ACCOUNT_SPEC, "")).strip()
    username = str(env.get(ENV_TRADOVATE_USERNAME, "")).strip()
    raw_password = str(env.get(ENV_TRADOVATE_PASSWORD, "")).strip()
    app_id = str(env.get(ENV_TRADOVATE_APP_ID, "")).strip()
    cid = str(env.get(ENV_TRADOVATE_CID, "")).strip()
    raw_sec = str(env.get(ENV_TRADOVATE_SEC, "")).strip()

    password = _RedactedSecret(raw_password) if raw_password else None
    sec = _RedactedSecret(raw_sec) if raw_sec else None

    eff_phrase: str | None = live_arm_phrase
    eff_ctx: LiveAuthorizationContext | None = live_auth_context
    check_now = _utc_now() if now_utc is None else utc_time(now_utc, "now_utc")
    if mode == TRADOVATE_MODE_LIVE:
        if eff_phrase is None:
            raw_env_phrase = str(env.get(ENV_LIVE_ARM_PHRASE, "")).strip()
            eff_phrase = raw_env_phrase if raw_env_phrase else None
        if eff_ctx is None:
            if not eff_account_id:
                raise TradovateLiveLockError(
                    f"LIVE Tradovate mode requires {ENV_TRADOVATE_ACCOUNT_ID} bound to a signed LIVE ticket"
                )
            try:
                _ticket, eff_ctx = verify_live_environ_authorization_context(
                    env,
                    expected_broker_id=TRADOVATE_LIVE_AUTH_BROKER_ID,
                    expected_account_login=eff_account_id,
                    expected_server=TRADOVATE_LIVE_HOST,
                    live_arm_phrase=eff_phrase,
                    require_arm_phrase=True,
                    now=check_now,
                )
            except LiveAuthorizationError as exc:
                raise TradovateLiveLockError(str(exc)) from None

    return TradovateCredentials(
        enabled=enabled,
        mode=mode,
        base_url=raw_base_url,
        live_arming_verified=live_arming_verified,
        account_id=eff_account_id,
        account_spec=eff_account_spec,
        live_auth_context=eff_ctx,
        live_arm_phrase=eff_phrase,
        auth_checked_at=check_now if mode == TRADOVATE_MODE_LIVE else None,
        username=username,
        password=password,
        app_id=app_id,
        cid=cid,
        sec=sec,
    )


# ---------------------------------------------------------------------------
# 2. Typed Immutable Models & Pluggable Transport
# ---------------------------------------------------------------------------


class FuturesOrderAction(StrEnum):
    OPEN_BRACKET = "OPEN_BRACKET"
    AMEND_STOP = "AMEND_STOP"
    CANCEL_ORDER = "CANCEL_ORDER"
    CLOSE_POSITION = "CLOSE_POSITION"
    EMERGENCY_CLOSE_ALL = "EMERGENCY_CLOSE_ALL"


@dataclass(frozen=True, slots=True)
class TradovateQuote:
    symbol: str
    bid: Decimal
    ask: Decimal
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.symbol, str) or not self.symbol.strip():
            raise ContractError("quote symbol must be a non-empty string")
        bid_d = _exact_decimal(self.bid, "bid", positive=True)
        ask_d = _exact_decimal(self.ask, "ask", positive=True)
        if bid_d > ask_d:
            raise ContractError(f"bid ({bid_d}) cannot exceed ask ({ask_d})")
        obs = utc_time(self.observed_at, "observed_at")
        object.__setattr__(self, "symbol", self.symbol.strip().upper())
        object.__setattr__(self, "bid", bid_d)
        object.__setattr__(self, "ask", ask_d)
        object.__setattr__(self, "observed_at", obs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol,
            "bid": decimal_text(self.bid),
            "ask": decimal_text(self.ask),
            "observed_at": _iso_utc(self.observed_at),
        }


@dataclass(frozen=True, slots=True)
class TradovateOrderRequest:
    request_id: str
    action: FuturesOrderAction
    contract_code: str
    root_symbol: str
    cas_symbol: str
    side: str | None = None
    contracts: int = 0
    entry_price: Decimal | None = None
    stop_loss_price: Decimal | None = None
    take_profit_price: Decimal | None = None
    position_id: str | None = None
    order_id: str | None = None
    client_tag: str = ""
    created_at: datetime | None = None
    cl_ord_id: str | None = None
    quote_observed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ContractError("request_id must be a non-empty string")
        if not isinstance(self.action, FuturesOrderAction):
            raise ContractError("action must be a FuturesOrderAction")
        if type(self.contracts) is not int or self.contracts < 0:
            raise ContractError("contracts must be a non-negative int")
        if self.side is not None:
            object.__setattr__(self, "side", _normalize_side(self.side))
        if self.entry_price is not None:
            object.__setattr__(
                self, "entry_price", _exact_decimal(self.entry_price, "entry_price", positive=True)
            )
        if self.stop_loss_price is not None:
            object.__setattr__(
                self,
                "stop_loss_price",
                _exact_decimal(self.stop_loss_price, "stop_loss_price", positive=True),
            )
        if self.take_profit_price is not None:
            object.__setattr__(
                self,
                "take_profit_price",
                _exact_decimal(self.take_profit_price, "take_profit_price", positive=True),
            )
        if self.cl_ord_id is not None:
            if not isinstance(self.cl_ord_id, str) or not self.cl_ord_id.strip():
                raise ContractError("cl_ord_id must be a non-empty string when provided")
            cleaned_cl = self.cl_ord_id.strip()
            if len(cleaned_cl) > 64 or any(ch.isspace() or ord(ch) < 32 for ch in cleaned_cl):
                raise ContractError("cl_ord_id must be <= 64 printable non-whitespace chars")
            object.__setattr__(self, "cl_ord_id", cleaned_cl)
        if self.quote_observed_at is not None:
            object.__setattr__(
                self,
                "quote_observed_at",
                utc_time(self.quote_observed_at, "quote_observed_at"),
            )
        ts = _utc_now() if self.created_at is None else utc_time(self.created_at, "created_at")
        object.__setattr__(self, "created_at", ts)
        object.__setattr__(self, "request_id", self.request_id.strip())
        object.__setattr__(self, "contract_code", self.contract_code.strip().upper())
        object.__setattr__(self, "root_symbol", self.root_symbol.strip().upper())
        object.__setattr__(self, "cas_symbol", self.cas_symbol.strip().upper())

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "cl_ord_id": self.cl_ord_id,
            "action": self.action.value,
            "contract_code": self.contract_code,
            "root_symbol": self.root_symbol,
            "cas_symbol": self.cas_symbol,
            "side": self.side,
            "contracts": self.contracts,
            "entry_price": decimal_text(self.entry_price) if self.entry_price is not None else None,
            "stop_loss_price": (
                decimal_text(self.stop_loss_price) if self.stop_loss_price is not None else None
            ),
            "take_profit_price": (
                decimal_text(self.take_profit_price) if self.take_profit_price is not None else None
            ),
            "position_id": self.position_id,
            "order_id": self.order_id,
            "client_tag": self.client_tag,
            "quote_observed_at": (
                _iso_utc(self.quote_observed_at) if self.quote_observed_at is not None else None
            ),
            "created_at": _iso_utc(self.created_at) if self.created_at is not None else None,
        }


@dataclass(frozen=True, slots=True)
class TradovateOrderReceipt:
    request_id: str
    action: FuturesOrderAction
    accepted: bool
    status: str
    order_id: str
    position_id: str | None
    contract_code: str
    root_symbol: str
    cas_symbol: str
    side: str | None
    filled_contracts: int
    fill_price: Decimal | None
    stop_loss_price: Decimal | None
    take_profit_price: Decimal | None
    commission_usd: Decimal
    realized_pnl_usd: Decimal
    net_pnl_usd: Decimal
    reason: str
    executed_at: datetime
    valve_score: Decimal | None = None
    valve_weights_sha256: str | None = None
    cl_ord_id: str | None = None
    stop_loss_order_id: str | None = None
    take_profit_order_id: str | None = None
    protection_confirmed: bool = False

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise ContractError("accepted must be bool")
        if type(self.protection_confirmed) is not bool:
            raise ContractError("protection_confirmed must be bool")
        if type(self.filled_contracts) is not int or self.filled_contracts < 0:
            raise ContractError("filled_contracts must be non-negative int")
        if self.fill_price is not None:
            object.__setattr__(
                self, "fill_price", _exact_decimal(self.fill_price, "fill_price", positive=True)
            )
        if self.stop_loss_price is not None:
            object.__setattr__(
                self,
                "stop_loss_price",
                _exact_decimal(self.stop_loss_price, "stop_loss_price", positive=True),
            )
        if self.take_profit_price is not None:
            object.__setattr__(
                self,
                "take_profit_price",
                _exact_decimal(self.take_profit_price, "take_profit_price", positive=True),
            )
        if self.protection_confirmed and self.action is FuturesOrderAction.OPEN_BRACKET:
            if not isinstance(self.stop_loss_order_id, str) or not self.stop_loss_order_id.strip():
                raise TradovateProtectionUnconfirmedError(
                    "OPEN_BRACKET receipt cannot claim protection_confirmed without stop_loss_order_id"
                )
            if self.stop_loss_price is None:
                raise TradovateProtectionUnconfirmedError(
                    "OPEN_BRACKET receipt cannot claim protection_confirmed without stop_loss_price"
                )
            if self.stop_loss_order_id.strip() == self.order_id.strip():
                raise TradovateProtectionUnconfirmedError(
                    "stop_loss_order_id must be distinct from entry order_id"
                )
            if self.take_profit_price is not None:
                if (
                    not isinstance(self.take_profit_order_id, str)
                    or not self.take_profit_order_id.strip()
                ):
                    raise TradovateProtectionUnconfirmedError(
                        "OPEN_BRACKET receipt with take_profit_price requires take_profit_order_id"
                    )
                if self.take_profit_order_id.strip() in (
                    self.order_id.strip(),
                    self.stop_loss_order_id.strip(),
                ):
                    raise TradovateProtectionUnconfirmedError(
                        "take_profit_order_id must be distinct from entry and stop-loss order IDs"
                    )
        object.__setattr__(
            self,
            "commission_usd",
            _q2(_exact_decimal(self.commission_usd, "commission_usd", non_negative=True)),
        )
        object.__setattr__(
            self,
            "realized_pnl_usd",
            _q2(_exact_decimal(self.realized_pnl_usd, "realized_pnl_usd")),
        )
        object.__setattr__(
            self,
            "net_pnl_usd",
            _q2(_exact_decimal(self.net_pnl_usd, "net_pnl_usd")),
        )
        if self.valve_score is not None:
            object.__setattr__(
                self,
                "valve_score",
                _exact_decimal(self.valve_score, "valve_score", non_negative=True),
            )
        object.__setattr__(self, "executed_at", utc_time(self.executed_at, "executed_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "cl_ord_id": self.cl_ord_id,
            "action": self.action.value,
            "accepted": self.accepted,
            "status": self.status,
            "order_id": self.order_id,
            "stop_loss_order_id": self.stop_loss_order_id,
            "take_profit_order_id": self.take_profit_order_id,
            "protection_confirmed": self.protection_confirmed,
            "position_id": self.position_id,
            "contract_code": self.contract_code,
            "root_symbol": self.root_symbol,
            "cas_symbol": self.cas_symbol,
            "side": self.side,
            "filled_contracts": self.filled_contracts,
            "fill_price": decimal_text(self.fill_price) if self.fill_price is not None else None,
            "stop_loss_price": (
                decimal_text(self.stop_loss_price) if self.stop_loss_price is not None else None
            ),
            "take_profit_price": (
                decimal_text(self.take_profit_price) if self.take_profit_price is not None else None
            ),
            "commission_usd": decimal_text(self.commission_usd),
            "realized_pnl_usd": decimal_text(self.realized_pnl_usd),
            "net_pnl_usd": decimal_text(self.net_pnl_usd),
            "reason": self.reason,
            "executed_at": _iso_utc(self.executed_at),
            "valve_score": decimal_text(self.valve_score) if self.valve_score is not None else None,
            "valve_weights_sha256": self.valve_weights_sha256,
        }


@dataclass(frozen=True, slots=True)
class TradovatePosition:
    position_id: str
    contract_code: str
    root_symbol: str
    cas_symbol: str
    side: str
    contracts: int
    entry_price: Decimal
    current_price: Decimal
    stop_loss_price: Decimal | None
    take_profit_price: Decimal | None
    used_margin_usd: Decimal
    floating_pnl_usd: Decimal
    commission_usd: Decimal
    opened_at: datetime
    updated_at: datetime
    stop_loss_order_id: str | None = None
    take_profit_order_id: str | None = None
    cl_ord_id: str | None = None
    account_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.contracts) is not int or self.contracts <= 0:
            raise ContractError("position contracts must be positive int")
        object.__setattr__(self, "side", _normalize_side(self.side))
        object.__setattr__(
            self, "entry_price", _exact_decimal(self.entry_price, "entry_price", positive=True)
        )
        object.__setattr__(
            self, "current_price", _exact_decimal(self.current_price, "current_price", positive=True)
        )
        if self.stop_loss_price is not None:
            object.__setattr__(
                self,
                "stop_loss_price",
                _exact_decimal(self.stop_loss_price, "stop_loss_price", positive=True),
            )
        if self.take_profit_price is not None:
            object.__setattr__(
                self,
                "take_profit_price",
                _exact_decimal(self.take_profit_price, "take_profit_price", positive=True),
            )
        object.__setattr__(
            self,
            "used_margin_usd",
            _q2(_exact_decimal(self.used_margin_usd, "used_margin_usd", non_negative=True)),
        )
        object.__setattr__(
            self,
            "floating_pnl_usd",
            _q2(_exact_decimal(self.floating_pnl_usd, "floating_pnl_usd")),
        )
        object.__setattr__(
            self,
            "commission_usd",
            _q2(_exact_decimal(self.commission_usd, "commission_usd", non_negative=True)),
        )
        object.__setattr__(self, "opened_at", utc_time(self.opened_at, "opened_at"))
        object.__setattr__(self, "updated_at", utc_time(self.updated_at, "updated_at"))
        if self.account_id is not None:
            if not isinstance(self.account_id, str) or not self.account_id.strip():
                raise ContractError("position account_id must be a non-empty string when provided")
            _check_no_control_chars(self.account_id, "account_id")
            object.__setattr__(self, "account_id", self.account_id.strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "position_id": self.position_id,
            "contract_code": self.contract_code,
            "root_symbol": self.root_symbol,
            "cas_symbol": self.cas_symbol,
            "side": self.side,
            "contracts": self.contracts,
            "entry_price": decimal_text(self.entry_price),
            "current_price": decimal_text(self.current_price),
            "stop_loss_price": (
                decimal_text(self.stop_loss_price) if self.stop_loss_price is not None else None
            ),
            "take_profit_price": (
                decimal_text(self.take_profit_price) if self.take_profit_price is not None else None
            ),
            "used_margin_usd": decimal_text(self.used_margin_usd),
            "floating_pnl_usd": decimal_text(self.floating_pnl_usd),
            "commission_usd": decimal_text(self.commission_usd),
            "opened_at": _iso_utc(self.opened_at),
            "updated_at": _iso_utc(self.updated_at),
            "stop_loss_order_id": self.stop_loss_order_id,
            "take_profit_order_id": self.take_profit_order_id,
            "cl_ord_id": self.cl_ord_id,
            "account_id": self.account_id,
        }


@dataclass(frozen=True, slots=True)
class TradovateAccountSnapshot:
    account_id: str
    mode: str
    connected: bool
    connection_status: str
    currency: str
    balance_usd: Decimal
    equity_usd: Decimal
    peak_equity_usd: Decimal
    drawdown_pct: Decimal
    used_margin_usd: Decimal
    available_margin_usd: Decimal
    margin_level_pct: Decimal | None
    floating_pnl_usd: Decimal
    realized_pnl_usd: Decimal
    total_commissions_usd: Decimal
    open_position_count: int
    observed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _normalize_mode(self.mode))
        if type(self.connected) is not bool:
            raise ContractError("connected must be bool")
        if type(self.open_position_count) is not int or self.open_position_count < 0:
            raise ContractError("open_position_count must be non-negative int")
        object.__setattr__(self, "balance_usd", _q2(_exact_decimal(self.balance_usd, "balance_usd")))
        object.__setattr__(self, "equity_usd", _q2(_exact_decimal(self.equity_usd, "equity_usd")))
        object.__setattr__(
            self,
            "peak_equity_usd",
            _q2(_exact_decimal(self.peak_equity_usd, "peak_equity_usd", non_negative=True)),
        )
        object.__setattr__(
            self,
            "drawdown_pct",
            _q4(_exact_decimal(self.drawdown_pct, "drawdown_pct", non_negative=True)),
        )
        object.__setattr__(
            self,
            "used_margin_usd",
            _q2(_exact_decimal(self.used_margin_usd, "used_margin_usd", non_negative=True)),
        )
        object.__setattr__(
            self,
            "available_margin_usd",
            _q2(_exact_decimal(self.available_margin_usd, "available_margin_usd")),
        )
        if self.margin_level_pct is not None:
            object.__setattr__(
                self,
                "margin_level_pct",
                _q2(_exact_decimal(self.margin_level_pct, "margin_level_pct", non_negative=True)),
            )
        object.__setattr__(
            self, "floating_pnl_usd", _q2(_exact_decimal(self.floating_pnl_usd, "floating_pnl_usd"))
        )
        object.__setattr__(
            self, "realized_pnl_usd", _q2(_exact_decimal(self.realized_pnl_usd, "realized_pnl_usd"))
        )
        object.__setattr__(
            self,
            "total_commissions_usd",
            _q2(_exact_decimal(self.total_commissions_usd, "total_commissions_usd", non_negative=True)),
        )
        object.__setattr__(self, "observed_at", utc_time(self.observed_at, "observed_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "mode": self.mode,
            "connected": self.connected,
            "connection_status": self.connection_status,
            "currency": self.currency,
            "balance_usd": decimal_text(self.balance_usd),
            "equity_usd": decimal_text(self.equity_usd),
            "peak_equity_usd": decimal_text(self.peak_equity_usd),
            "drawdown_pct": decimal_text(self.drawdown_pct),
            "used_margin_usd": decimal_text(self.used_margin_usd),
            "available_margin_usd": decimal_text(self.available_margin_usd),
            "margin_level_pct": (
                decimal_text(self.margin_level_pct) if self.margin_level_pct is not None else None
            ),
            "floating_pnl_usd": decimal_text(self.floating_pnl_usd),
            "realized_pnl_usd": decimal_text(self.realized_pnl_usd),
            "total_commissions_usd": decimal_text(self.total_commissions_usd),
            "open_position_count": self.open_position_count,
            "observed_at": _iso_utc(self.observed_at),
        }


@dataclass(frozen=True, slots=True)
class TradovateReconciliationEvidence:
    """Authoritative account-bound completeness-proven order-history reconciliation evidence."""

    account_id: str
    orders: tuple[dict[str, Any], ...]
    observed_cl_ord_ids: frozenset[str]
    pages_fetched: int
    complete: bool
    provider_cursor_exhausted: bool
    watermark_utc: datetime | None
    incompleteness_reasons: tuple[str, ...] = ()
    authoritative_confirmation: bool = False
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.account_id, str) or not self.account_id.strip():
            raise ContractError("reconciliation evidence account_id must be a non-empty string")
        _check_no_control_chars(self.account_id, "account_id")
        object.__setattr__(self, "account_id", self.account_id.strip())
        if type(self.pages_fetched) is not int or self.pages_fetched < 0:
            raise ContractError("pages_fetched must be a non-negative int")
        if type(self.complete) is not bool:
            raise ContractError("complete must be a strict bool")
        if type(self.provider_cursor_exhausted) is not bool:
            raise ContractError("provider_cursor_exhausted must be a strict bool")
        if type(self.authoritative_confirmation) is not bool:
            raise ContractError("authoritative_confirmation must be a strict bool")
        if self.watermark_utc is not None:
            object.__setattr__(self, "watermark_utc", utc_time(self.watermark_utc, "watermark_utc"))
        if self.observed_at is not None:
            object.__setattr__(self, "observed_at", utc_time(self.observed_at, "observed_at"))
        object.__setattr__(self, "orders", tuple(dict(item) for item in self.orders))
        object.__setattr__(
            self,
            "observed_cl_ord_ids",
            frozenset(str(x).strip() for x in self.observed_cl_ord_ids if str(x).strip()),
        )
        object.__setattr__(
            self,
            "incompleteness_reasons",
            tuple(str(r) for r in self.incompleteness_reasons),
        )


@runtime_checkable
class TradovateTransport(Protocol):
    """Pluggable transport protocol for Tradovate offline paper or pinned HTTPS live/demo."""

    def connect(self) -> None: ...

    def disconnect(self) -> None: ...

    def is_connected(self) -> bool: ...

    def account_snapshot(self, *, now_utc: datetime | None = None) -> TradovateAccountSnapshot: ...

    def positions(self) -> tuple[TradovatePosition, ...]: ...

    def get_quote(self, symbol_or_root: str) -> TradovateQuote: ...

    def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt: ...


# ---------------------------------------------------------------------------
# Hardened HTTPS Transport (PR #25 compliant; zero calls in offline tests)
# ---------------------------------------------------------------------------


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Hard-refuses all HTTP 3xx responses on Tradovate HTTPS transport."""

    def __init__(self, error_cls: type[TradovateVenueError] = TradovateTransportError) -> None:
        super().__init__()
        self._error_cls = error_cls

    def redirect_request(self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any) -> Any:
        raise self._error_cls(f"HTTP redirect ({code}) refused on pinned Tradovate HTTPS transport")

    def http_response(self, request: Any, response: Any) -> Any:
        code = getattr(response, "status", None)
        if code is None:
            code = getattr(response, "code", 200)
        if 300 <= int(code) < 400:
            response.close()
            raise self._error_cls(
                f"HTTP redirect ({code}) refused on pinned Tradovate HTTPS transport"
            )
        return response

    https_response = http_response

    def _reject_3xx(self, req: Any, fp: Any, code: Any, msg: Any, headers: Any) -> Any:
        if fp is not None:
            fp.close()
        raise self._error_cls(f"HTTP redirect ({code}) refused on pinned Tradovate HTTPS transport")

    http_error_300 = _reject_3xx
    http_error_301 = _reject_3xx
    http_error_302 = _reject_3xx
    http_error_303 = _reject_3xx
    http_error_304 = _reject_3xx
    http_error_305 = _reject_3xx
    http_error_306 = _reject_3xx
    http_error_307 = _reject_3xx
    http_error_308 = _reject_3xx


class _PinnedPublicIPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that verifies DNS resolves exclusively to public global IPs."""

    def connect(self) -> None:
        host = self.host
        port = self.port
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not infos:
            raise TradovateTransportError(f"DNS returned no addresses for pinned host {host!r}")
        for _family, _socktype, _proto, _canonname, sockaddr in infos:
            verify_public_ip_address(
                str(sockaddr[0]),
                label="tradovate_host",
                error_cls=TradovateTransportError,
            )
        super().connect()


class _PinnedTradovateHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(context=context)

    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(
            _PinnedPublicIPHTTPSConnection,
            req,
            context=self._context,
        )


class TradovateHttpsTransport:
    """Optional live/demo Tradovate REST HTTPS client (zero calls in offline tests).

    Uses ``_NoRedirectHandler``, ``ssl.create_default_context()``, DNS public-IP
    verification, strict timeout, and ``Authorization: Bearer ...`` header ONLY
    (never places credentials or bearer tokens in URL query strings).
    """

    def __init__(
        self,
        *,
        credentials: TradovateCredentials,
        timeout_seconds: int | float = 10.0,
        max_wire_bytes: int = 1_048_576,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(credentials, TradovateCredentials):
            raise ContractError("credentials must be TradovateCredentials")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ContractError("timeout_seconds must be a positive finite number")
        if type(max_wire_bytes) is not int or max_wire_bytes < 1024:
            raise ContractError("max_wire_bytes must be an integer >= 1024")
        self._credentials = credentials
        self._clock = clock if clock is not None else _utc_now
        self._base_url = validate_tradovate_endpoint(
            credentials.mode,
            credentials.base_url,
            live_arming_verified=credentials.live_arming_verified,
            live_auth_context=credentials.live_auth_context,
            live_arm_phrase=credentials.live_arm_phrase,
            account_id=credentials.account_id,
            now_utc=self._clock() if credentials.mode == TRADOVATE_MODE_LIVE else None,
        )
        self._timeout_seconds = timeout_seconds
        self._max_wire_bytes = max_wire_bytes
        self._bearer_token: _RedactedSecret | None = credentials.bearer_token
        self._connected = False

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def mode(self) -> str:
        return self._credentials.mode

    @property
    def account_id(self) -> str:
        return self._credentials.account_id

    def __repr__(self) -> str:
        return (
            f"TradovateHttpsTransport(mode={self._credentials.mode!r}, "
            f"base_url={self._base_url!r}, connected={self._connected!r})"
        )

    def _build_safe_url(self, endpoint_path: str) -> str:
        if not isinstance(endpoint_path, str) or not endpoint_path.strip():
            raise TradovateEndpointError("endpoint_path must be a non-empty relative path")
        cleaned = endpoint_path.strip()
        if any(ch.isspace() or ord(ch) < 32 for ch in cleaned):
            raise TradovateEndpointError("endpoint_path contains whitespace or control characters")
        if "://" in cleaned or cleaned.startswith("//") or ".." in cleaned:
            raise TradovateEndpointError("endpoint_path must be a safe relative API path")
        lowered = cleaned.lower()
        if "?" in cleaned:
            query_part = lowered.split("?", 1)[1]
            for marker in _FORBIDDEN_QUERY_SECRET_MARKERS:
                if marker in query_part:
                    raise TradovateEndpointError(
                        f"Forbidden secret-like parameter ({marker!r}) in URL query string"
                    )
        if "#" in cleaned:
            raise TradovateEndpointError("endpoint_path must not contain URL fragment")
        rel = cleaned.lstrip("/")
        full_url = f"{self._base_url}/{rel}"
        parsed = urllib.parse.urlsplit(full_url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in PINNED_TRADOVATE_HOSTS:
            raise TradovateEndpointError("Constructed Tradovate request URL failed host pinning")
        return full_url

    def _require_live_authorization(self, now: datetime) -> None:
        """Revalidate opaque LiveAuthorizationContext at the final HTTPS dispatch sink."""
        if self._credentials.mode != TRADOVATE_MODE_LIVE:
            return
        parsed = urllib.parse.urlsplit(self._base_url)
        host = (parsed.hostname or "").lower()
        _verify_tradovate_live_authorization(
            live_auth_context=self._credentials.live_auth_context,
            live_arm_phrase=self._credentials.live_arm_phrase,
            account_id=self._credentials.account_id,
            server_host=host,
            now_utc=now,
        )

    def _request_json_raw(
        self,
        method: str,
        endpoint_path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        require_auth: bool = True,
    ) -> dict[str, Any] | list[Any]:
        full_url = self._build_safe_url(endpoint_path)
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "CAS-Forex-Tradovate-Adapter/1.0",
        }
        if require_auth:
            if self._bearer_token is None:
                raise TradovateNotConfiguredError(
                    "Tradovate bearer token is not initialized; call connect() first"
                )
            headers["Authorization"] = f"Bearer {self._bearer_token.reveal()}"

        body_bytes = _encode_wire_json_bytes(payload) if payload is not None else None
        parsed = urllib.parse.urlsplit(full_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in PINNED_TRADOVATE_HOSTS:
            raise TradovateEndpointError("Constructed Tradovate request URL failed host pinning")
        req_target = parsed.path or "/"
        if parsed.query:
            req_target = f"{req_target}?{parsed.query}"
        if body_bytes is not None:
            headers["Content-Length"] = str(len(body_bytes))

        ctx = get_cached_tls12_ssl_context()
        conn = _PinnedPublicIPHTTPSConnection(
            host,
            port=443,
            timeout=self._timeout_seconds,
            context=ctx,
        )
        try:
            conn.request(method.upper(), req_target, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            status = int(resp.status)
            if 300 <= status < 400:
                raise TradovateTransportError(
                    f"HTTP redirect ({status}) refused on pinned Tradovate HTTPS transport",
                    http_status=status,
                    ambiguous=True,
                )
            if status not in (200, 201):
                raise TradovateTransportError(
                    f"Tradovate HTTP status {status}",
                    http_status=status,
                    ambiguous=True,
                )
            raw = resp.read(self._max_wire_bytes + 1)
        except TradovateVenueError:
            raise
        except (http.client.HTTPException, ssl.SSLError, TimeoutError, OSError) as exc:
            raise TradovateTransportError(
                f"Tradovate HTTPS connection failed: {type(exc).__name__}",
                ambiguous=True,
            ) from None
        finally:
            headers.clear()
            conn.close()

        if not raw or len(raw) > self._max_wire_bytes:
            raise TradovateTransportError(
                "Tradovate response empty or exceeded max wire bytes",
                ambiguous=True,
            )
        try:
            decoded = json.loads(raw.decode("utf-8"), parse_float=Decimal)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TradovateTransportError(
                "Tradovate response was not valid UTF-8 JSON",
                ambiguous=True,
            ) from exc
        if not isinstance(decoded, (dict, list)):
            raise TradovateTransportError(
                "Tradovate response root must be a JSON object or array",
                ambiguous=True,
            )
        return decoded

    def _request_json(
        self,
        method: str,
        endpoint_path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        require_auth: bool = True,
    ) -> dict[str, Any]:
        decoded = self._request_json_raw(
            method,
            endpoint_path,
            payload=payload,
            require_auth=require_auth,
        )
        if not isinstance(decoded, dict):
            raise TradovateTransportError(
                "Tradovate response root must be a JSON object",
                ambiguous=True,
            )
        return decoded

    def _request_json_list(
        self,
        method: str,
        endpoint_path: str,
        *,
        require_auth: bool = True,
    ) -> list[dict[str, Any]]:
        decoded = self._request_json_raw(
            method,
            endpoint_path,
            payload=None,
            require_auth=require_auth,
        )
        if not isinstance(decoded, list) or any(not isinstance(item, dict) for item in decoded):
            raise TradovateTransportError(
                "Tradovate list response must be a JSON array of objects",
                ambiguous=True,
            )
        return list(decoded)

    def _authorized_account_id(self) -> str:
        acct = (self._credentials.account_id or "").strip()
        if not acct:
            if self._credentials.mode == TRADOVATE_MODE_LIVE:
                raise TradovateLiveLockError(
                    "LIVE TradovateHttpsTransport requires non-empty authorized account_id"
                )
            raise TradovateTransportError(
                "TradovateHttpsTransport requires non-empty authorized account_id",
                ambiguous=False,
            )
        if any(ch.isspace() or ord(ch) < 32 for ch in acct):
            raise TradovateEndpointError("Tradovate account_id contains whitespace or control characters")
        if self._credentials.mode == TRADOVATE_MODE_LIVE:
            ctx = self._credentials.live_auth_context
            if not isinstance(ctx, LiveAuthorizationContext) or ctx.account_id.strip() != acct:
                raise TradovateLiveLockError(
                    "LIVE TradovateHttpsTransport account_id does not match LiveAuthorizationContext"
                )
        return acct

    def _authorized_account_spec(self) -> str:
        acct = self._authorized_account_id()
        spec = (self._credentials.account_spec or "").strip() or acct
        if any(ch.isspace() or ord(ch) < 32 for ch in spec):
            raise TradovateEndpointError("Tradovate account_spec contains whitespace or control characters")
        return spec

    def _account_body_fields(self) -> dict[str, Any]:
        acct = self._authorized_account_id()
        spec = self._authorized_account_spec()
        return {
            "accountId": int(acct) if acct.isdigit() else acct,
            "accountSpec": spec,
        }

    def _build_account_endpoint(
        self,
        base_path: str,
        extra_params: Mapping[str, Any] | None = None,
    ) -> str:
        acct = self._authorized_account_id()
        spec = self._authorized_account_spec()
        query_items: list[tuple[str, str]] = [
            ("accountId", acct),
            ("accountSpec", spec),
        ]
        if extra_params:
            for k in sorted(extra_params):
                v = extra_params[k]
                if v is not None:
                    query_items.append((str(k), str(v)))
        return f"{base_path}?{urllib.parse.urlencode(query_items)}"

    @staticmethod
    def _extract_record_account_id(
        record: Mapping[str, Any],
        *,
        context: str,
        expected_account_spec: str | None = None,
        expected_account_id: str | None = None,
    ) -> str:
        raw = record.get("accountId")
        if isinstance(raw, bool) or raw is None:
            raise TradovateTransportError(
                f"Tradovate {context} record missing required accountId",
                ambiguous=False,
            )
        if isinstance(raw, int):
            if raw <= 0:
                raise TradovateTransportError(
                    f"Tradovate {context} record has invalid accountId: {raw!r}",
                    ambiguous=False,
                )
            acct = str(raw)
        elif isinstance(raw, str):
            acct = raw.strip()
            if not acct or any(ch.isspace() or ord(ch) < 32 for ch in acct):
                raise TradovateTransportError(
                    f"Tradovate {context} record has invalid accountId: {raw!r}",
                    ambiguous=False,
                )
        else:
            raise TradovateTransportError(
                f"Tradovate {context} record has unsupported accountId type: {type(raw).__name__}",
                ambiguous=False,
            )
        if expected_account_spec is not None and record.get("accountSpec") is not None:
            raw_spec = record.get("accountSpec")
            if isinstance(raw_spec, bool) or not isinstance(raw_spec, str) or not raw_spec.strip():
                raise TradovateTransportError(
                    f"Tradovate {context} record has invalid accountSpec",
                    ambiguous=False,
                )
            if (expected_account_id is None or acct == expected_account_id) and raw_spec.strip() != expected_account_spec:
                raise TradovateTransportError(
                    f"Tradovate {context} accountSpec mismatch: expected {expected_account_spec!r}, got {raw_spec.strip()!r}",
                    ambiguous=False,
                )
        return acct

    @staticmethod
    def _validate_optional_account_fields(
        record: Mapping[str, Any],
        *,
        expected_account_id: str,
        expected_account_spec: str,
        context: str,
    ) -> None:
        if record.get("accountId") is not None:
            got_acct = TradovateHttpsTransport._extract_record_account_id(
                record,
                context=context,
                expected_account_spec=expected_account_spec,
                expected_account_id=expected_account_id,
            )
            if got_acct != expected_account_id:
                raise TradovateTransportError(
                    f"Tradovate {context} accountId mismatch: expected {expected_account_id!r}, got {got_acct!r}",
                    ambiguous=True,
                )
        elif record.get("accountSpec") is not None:
            raw_spec = record.get("accountSpec")
            if isinstance(raw_spec, bool) or not isinstance(raw_spec, str) or raw_spec.strip() != expected_account_spec:
                raise TradovateTransportError(
                    f"Tradovate {context} accountSpec mismatch: expected {expected_account_spec!r}, got {raw_spec!r}",
                    ambiguous=True,
                )

    def _dispatch_get_orders_page(self, endpoint_path: str) -> dict[str, Any] | list[Any]:
        raw_overridden = (
            "_request_json_raw" in self.__dict__
            or type(self)._request_json_raw is not TradovateHttpsTransport._request_json_raw
        )
        if raw_overridden:
            return self._request_json_raw("GET", endpoint_path)
        json_overridden = (
            "_request_json" in self.__dict__
            or type(self)._request_json is not TradovateHttpsTransport._request_json
        )
        if json_overridden:
            return self._request_json("GET", endpoint_path)
        list_overridden = (
            "_request_json_list" in self.__dict__
            or type(self)._request_json_list is not TradovateHttpsTransport._request_json_list
        )
        if list_overridden:
            return self._request_json_list("GET", endpoint_path)
        return self._request_json_raw("GET", endpoint_path)

    def _validate_protective_broker_response(
        self,
        resp: Mapping[str, Any],
        *,
        endpoint: str,
        expected_cl_ord_id: str | None,
        expected_account_id: str,
        expected_account_spec: str,
        rejected_statuses: frozenset[str],
        allowed_statuses: frozenset[str] | None = None,
    ) -> str:
        if not isinstance(resp, Mapping) or len(resp) == 0:
            raise TradovateTransportError(
                f"Tradovate {endpoint} returned empty or non-object response",
                ambiguous=True,
            )
        err_text = resp.get("errorText") or resp.get("failureReason") or resp.get("failureText")
        if err_text is not None and str(err_text).strip():
            raise TradovateTransportError(
                f"Tradovate {endpoint} rejected or failed: {err_text}",
                ambiguous=True,
            )
        self._validate_optional_account_fields(
            resp,
            expected_account_id=expected_account_id,
            expected_account_spec=expected_account_spec,
            context=endpoint,
        )
        if expected_cl_ord_id is not None and resp.get("clOrdId") is not None:
            got_cl = str(resp.get("clOrdId")).strip()
            if got_cl != expected_cl_ord_id:
                raise TradovateTransportError(
                    f"Tradovate {endpoint} clOrdId mismatch: expected {expected_cl_ord_id!r}, got {got_cl!r}",
                    ambiguous=True,
                )
        raw_oid = resp.get("orderId") if resp.get("orderId") is not None else resp.get("id")
        try:
            confirmed_id = _parse_broker_id(raw_oid, "orderId")
        except TradovateProtectionUnconfirmedError as exc:
            raise TradovateTransportError(
                f"Tradovate {endpoint} missing or invalid orderId: {exc}",
                ambiguous=True,
            ) from None
        raw_status = resp.get("ordStatus") if resp.get("ordStatus") is not None else resp.get("status")
        if raw_status is not None:
            norm_status = str(raw_status).strip().lower()
            if not norm_status or norm_status in rejected_statuses:
                raise TradovateTransportError(
                    f"Tradovate {endpoint} returned non-success status {raw_status!r}",
                    ambiguous=True,
                )
            if allowed_statuses is not None and norm_status not in allowed_statuses:
                raise TradovateTransportError(
                    f"Tradovate {endpoint} returned unexpected status {raw_status!r}",
                    ambiguous=True,
                )
        return confirmed_id

    def connect(self) -> None:
        self._require_live_authorization(self._clock())
        if self._bearer_token is not None:
            self._authorized_account_id()
            self._connected = True
            return
        if not self._credentials.has_api_credentials():
            raise TradovateNotConfiguredError(
                "Tradovate API credentials (username, password, app_id, cid, sec) are required to connect"
            )
        self._authorized_account_id()
        password_sec = self._credentials.password
        api_sec = self._credentials.sec
        if password_sec is None or api_sec is None:
            raise TradovateNotConfiguredError("Tradovate password/sec credentials missing")
        resp = self._request_json(
            "POST",
            "auth/accesstokenrequest",
            payload={
                "name": self._credentials.username,
                "password": password_sec.reveal(),
                "appId": self._credentials.app_id,
                "appVersion": "1.0",
                "cid": self._credentials.cid,
                "sec": api_sec.reveal(),
            },
            require_auth=False,
        )
        token = resp.get("accessToken")
        if not isinstance(token, str) or not token.strip():
            raise TradovateTransportError("Tradovate auth response did not include accessToken")
        self._bearer_token = _RedactedSecret(token)
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False
        self._bearer_token = None

    def is_connected(self) -> bool:
        return self._connected

    def _require_connected(self) -> None:
        if not self._connected:
            raise TradovateTransportError("TradovateHttpsTransport is not connected")

    def account_snapshot(self, *, now_utc: datetime | None = None) -> TradovateAccountSnapshot:
        self._require_connected()
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        endpoint = self._build_account_endpoint("cashBalance/getcashbalancesnapshot")
        resp = self._request_json("GET", endpoint)
        acct_id = self._extract_record_account_id(
            resp,
            context="cashBalance/getcashbalancesnapshot",
            expected_account_spec=expected_spec,
            expected_account_id=expected_acct,
        )
        if acct_id != expected_acct:
            raise TradovateTransportError(
                f"Tradovate cashBalance/getcashbalancesnapshot accountId mismatch: "
                f"expected {expected_acct!r}, got {acct_id!r}",
                ambiguous=False,
            )
        balance = _parse_broker_decimal(resp.get("amount", "0"), "balance_usd")
        open_pnl = _parse_broker_decimal(resp.get("openPnL", "0"), "floating_pnl_usd")
        equity = _q2(balance + open_pnl)
        used_margin = _parse_broker_decimal(
            resp.get("initialMargin", "0"), "used_margin_usd", non_negative=True
        )
        available = _q2(equity - used_margin)
        margin_level = _q2((equity * Decimal("100")) / used_margin) if used_margin > Decimal("0") else None
        return TradovateAccountSnapshot(
            account_id=acct_id,
            mode=self._credentials.mode,
            connected=True,
            connection_status=CONNECTION_STATUS_CONNECTED,
            currency="USD",
            balance_usd=balance,
            equity_usd=equity,
            peak_equity_usd=max(balance, equity),
            drawdown_pct=Decimal("0.0000"),
            used_margin_usd=used_margin,
            available_margin_usd=available,
            margin_level_pct=margin_level,
            floating_pnl_usd=open_pnl,
            realized_pnl_usd=_parse_broker_decimal(resp.get("realizedPnL", "0"), "realized_pnl_usd"),
            total_commissions_usd=Decimal("0.00"),
            open_position_count=0,
            observed_at=now,
        )

    def positions(self) -> tuple[TradovatePosition, ...]:
        self._require_connected()
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()
        now = self._clock()
        endpoint = self._build_account_endpoint("position/list")
        raw_positions = self._request_json_list("GET", endpoint)
        result: list[TradovatePosition] = []
        for item in raw_positions:
            item_acct = self._extract_record_account_id(
                item,
                context="position/list",
                expected_account_spec=expected_spec,
                expected_account_id=expected_acct,
            )
            if item_acct != expected_acct:
                continue
            net_pos_raw = item.get("netPos", 0)
            try:
                net_pos = _parse_broker_int(net_pos_raw, "netPos")
            except ContractError as exc:
                raise TradovateTransportError(f"Malformed netPos in position/list: {exc}") from exc
            if net_pos == 0:
                continue
            pos_id = str(item.get("id") or item.get("positionId") or "").strip()
            if not pos_id:
                raise TradovateTransportError("Tradovate position/list entry missing id")
            contract_code = str(
                item.get("contractCode") or item.get("symbol") or item.get("contractId") or ""
            ).strip().upper()
            raw_root = str(item.get("rootSymbol") or contract_code[:3] or "").strip().upper()
            root = translate_cas_symbol_to_micro_root(raw_root)
            cas_symbol = translate_micro_root_to_cas_symbol(root)
            side = "BUY" if net_pos > 0 else "SELL"
            entry_px = _parse_broker_decimal(
                item.get("netPrice") or item.get("entryPrice"), "netPrice", positive=True
            )
            current_px = (
                _parse_broker_decimal(item["currentPrice"], "currentPrice", positive=True)
                if item.get("currentPrice") is not None
                else entry_px
            )
            sl_px = (
                _parse_broker_decimal(item["stopLossPrice"], "stopLossPrice", positive=True)
                if item.get("stopLossPrice") is not None
                else None
            )
            tp_px = (
                _parse_broker_decimal(item["takeProfitPrice"], "takeProfitPrice", positive=True)
                if item.get("takeProfitPrice") is not None
                else None
            )
            used_margin = _parse_broker_decimal(
                item.get("usedMarginUsd", "0.00"), "used_margin_usd", non_negative=True
            )
            floating = _parse_broker_decimal(item.get("floatingPnlUsd", "0.00"), "floating_pnl_usd")
            comm = _parse_broker_decimal(
                item.get("commissionUsd", "0.00"), "commission_usd", non_negative=True
            )
            result.append(
                TradovatePosition(
                    position_id=pos_id,
                    contract_code=contract_code,
                    root_symbol=root,
                    cas_symbol=cas_symbol,
                    side=side,
                    contracts=abs(net_pos),
                    entry_price=entry_px,
                    current_price=current_px,
                    stop_loss_price=sl_px,
                    take_profit_price=tp_px,
                    used_margin_usd=used_margin,
                    floating_pnl_usd=floating,
                    commission_usd=comm,
                    opened_at=now,
                    updated_at=now,
                    stop_loss_order_id=(
                        str(item["stopLossOrderId"]).strip()
                        if item.get("stopLossOrderId") is not None
                        else None
                    ),
                    take_profit_order_id=(
                        str(item["takeProfitOrderId"]).strip()
                        if item.get("takeProfitOrderId") is not None
                        else None
                    ),
                    cl_ord_id=(
                        str(item["clOrdId"]).strip()
                        if item.get("clOrdId") is not None
                        else None
                    ),
                    account_id=item_acct,
                )
            )
        return tuple(result)

    def _filter_account_orders(
        self,
        raw_orders: Sequence[Any],
        *,
        context: str,
        expected_acct: str,
        expected_spec: str,
    ) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []
        for item in raw_orders:
            if not isinstance(item, Mapping):
                raise TradovateTransportError(
                    f"Tradovate {context} returned non-object order entry",
                    ambiguous=True,
                )
            item_acct = self._extract_record_account_id(
                item,
                context=context,
                expected_account_spec=expected_spec,
                expected_account_id=expected_acct,
            )
            if item_acct != expected_acct:
                continue
            filtered.append(dict(item))
        return filtered

    def list_orders(self) -> list[dict[str, Any]]:
        """Query account-bound Tradovate order list, rejecting records missing accountId."""
        self._require_connected()
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()
        endpoint = self._build_account_endpoint("order/list")
        raw_orders = self._request_json_list("GET", endpoint)
        return self._filter_account_orders(
            raw_orders,
            context="order/list",
            expected_acct=expected_acct,
            expected_spec=expected_spec,
        )

    def list_order_deps(self, *, master_id: str | None = None) -> list[dict[str, Any]]:
        """Query account-bound Tradovate order/deps, rejecting records missing accountId."""
        self._require_connected()
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()
        eff_master = (
            master_id.strip()
            if isinstance(master_id, str) and master_id.strip()
            else expected_acct
        )
        if any(ch.isspace() or ch in "?#&/" or ord(ch) < 32 for ch in eff_master):
            raise TradovateEndpointError(f"Malformed order/deps masterid {master_id!r}")
        endpoint = self._build_account_endpoint("order/deps", {"masterid": eff_master})
        raw_orders = self._request_json_list("GET", endpoint)
        return self._filter_account_orders(
            raw_orders,
            context="order/deps",
            expected_acct=expected_acct,
            expected_spec=expected_spec,
        )

    def list_orders_paginated(
        self,
        *,
        page_size: int = 100,
        max_pages: int = 50,
        since_utc: datetime | None = None,
    ) -> TradovateReconciliationEvidence:
        """Exhaust paginated account-bound order history and emit a completeness proof/watermark."""
        if type(page_size) is not int or page_size < 1:
            raise ContractError("page_size must be a positive int")
        if type(max_pages) is not int or max_pages < 1:
            raise ContractError("max_pages must be a positive int")
        checked_since = utc_time(since_utc, "since_utc") if since_utc is not None else None
        self._require_connected()
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()
        now = self._clock()

        all_orders: list[dict[str, Any]] = []
        observed_cl_ord_ids: set[str] = set()
        seen_cursors: set[str] = set()
        incompleteness: list[str] = []
        page_watermarks: list[datetime] = []
        pages_fetched = 0
        cursor: str | None = None
        cursor_exhausted = False
        explicit_auth_confirm: bool | None = None

        while pages_fetched < max_pages:
            extra: dict[str, Any] = {"limit": str(page_size)}
            if cursor is not None:
                extra["cursor"] = cursor
            if checked_since is not None:
                extra["since"] = _iso_utc(checked_since)
            endpoint = self._build_account_endpoint("order/list", extra)
            decoded = self._dispatch_get_orders_page(endpoint)
            pages_fetched += 1

            if isinstance(decoded, list):
                filtered = self._filter_account_orders(
                    decoded,
                    context="order/list",
                    expected_acct=expected_acct,
                    expected_spec=expected_spec,
                )
                all_orders.extend(filtered)
                for order_doc in filtered:
                    cl_val = str(order_doc.get("clOrdId", "")).strip()
                    if cl_val:
                        observed_cl_ord_ids.add(cl_val)
                cursor_exhausted = False
                explicit_auth_confirm = False
                incompleteness.append("unpaged_unwatermarked_list_response")
                break

            if not isinstance(decoded, Mapping):
                incompleteness.append("malformed_order_history_page")
                cursor_exhausted = False
                explicit_auth_confirm = False
                break

            if decoded.get("accountId") is None:
                incompleteness.append("missing_envelope_account_id")
                cursor_exhausted = False
                explicit_auth_confirm = False
            else:
                env_acct = self._extract_record_account_id(
                    decoded,
                    context="order/list",
                    expected_account_spec=expected_spec,
                    expected_account_id=expected_acct,
                )
                if env_acct != expected_acct:
                    raise TradovateTransportError(
                        f"Tradovate paginated order/list accountId mismatch: "
                        f"expected {expected_acct!r}, got {env_acct!r}",
                        ambiguous=True,
                    )

            items_raw: Any = None
            for list_key in ("orders", "items", "data"):
                if list_key in decoded:
                    items_raw = decoded.get(list_key)
                    break
            if not isinstance(items_raw, list):
                incompleteness.append("missing_orders_array_in_page")
                cursor_exhausted = False
                explicit_auth_confirm = False
                break

            filtered_page = self._filter_account_orders(
                items_raw,
                context="order/list",
                expected_acct=expected_acct,
                expected_spec=expected_spec,
            )
            all_orders.extend(filtered_page)
            for order_doc in filtered_page:
                cl_val = str(order_doc.get("clOrdId", "")).strip()
                if cl_val:
                    observed_cl_ord_ids.add(cl_val)

            raw_wm = (
                decoded.get("watermarkUtc")
                if decoded.get("watermarkUtc") is not None
                else (
                    decoded.get("watermark_utc")
                    if decoded.get("watermark_utc") is not None
                    else (decoded.get("asOfUtc") if decoded.get("asOfUtc") is not None else decoded.get("observedAt"))
                )
            )
            if raw_wm is None:
                incompleteness.append("missing_watermark_utc")
            else:
                try:
                    page_watermarks.append(_parse_utc_timestamp(raw_wm, field="watermark_utc"))
                except TradovateTransportError:
                    incompleteness.append("invalid_watermark_utc")

            page_auth = bool(
                decoded.get("authoritativeConfirmation") is True
                or decoded.get("authoritativeComplete") is True
                or decoded.get("confirmedAbsent") is True
            )
            explicit_auth_confirm = page_auth if explicit_auth_confirm is None else (explicit_auth_confirm and page_auth)

            if decoded.get("truncated") is True:
                incompleteness.append("provider_response_truncated")
                cursor_exhausted = False
                break

            has_cursor_key = any(k in decoded for k in ("nextCursor", "next_cursor", "cursor"))
            raw_next_cursor = (
                decoded.get("nextCursor")
                if "nextCursor" in decoded
                else (decoded.get("next_cursor") if "next_cursor" in decoded else decoded.get("cursor"))
            )
            next_cursor = (
                str(raw_next_cursor).strip()
                if raw_next_cursor is not None and str(raw_next_cursor).strip()
                else None
            )
            has_more_key = ("hasMore" in decoded) or ("has_more" in decoded)
            has_more_val = decoded.get("hasMore") if "hasMore" in decoded else decoded.get("has_more")
            if has_more_key and type(has_more_val) is not bool:
                incompleteness.append("invalid_has_more_flag")
                cursor_exhausted = False
                break

            if next_cursor is not None:
                if next_cursor in seen_cursors:
                    incompleteness.append("pagination_cursor_cycle")
                    cursor_exhausted = False
                    break
                seen_cursors.add(next_cursor)
                cursor = next_cursor
                continue
            if has_more_val is True:
                incompleteness.append("has_more_true_without_next_cursor")
                cursor_exhausted = False
                break
            if (has_more_key and has_more_val is False) or (has_cursor_key and next_cursor is None):
                cursor_exhausted = True
                break
            incompleteness.append("missing_pagination_exhaustion_proof")
            cursor_exhausted = False
            break
        else:
            incompleteness.append("pagination_max_pages_exceeded")
            cursor_exhausted = False

        eff_watermark: datetime | None = (
            min(page_watermarks)
            if page_watermarks and len(page_watermarks) == pages_fetched and "invalid_watermark_utc" not in incompleteness
            else None
        )
        complete = (
            pages_fetched >= 1
            and cursor_exhausted is True
            and eff_watermark is not None
            and len(incompleteness) == 0
        )
        return TradovateReconciliationEvidence(
            account_id=expected_acct,
            orders=tuple(all_orders),
            observed_cl_ord_ids=frozenset(observed_cl_ord_ids),
            pages_fetched=pages_fetched,
            complete=complete,
            provider_cursor_exhausted=cursor_exhausted,
            watermark_utc=eff_watermark,
            incompleteness_reasons=tuple(dict.fromkeys(incompleteness)),
            authoritative_confirmation=bool(complete and explicit_auth_confirm),
            observed_at=now,
        )

    def fetch_reconciliation_evidence(
        self,
        *,
        page_size: int = 100,
        max_pages: int = 50,
        since_utc: datetime | None = None,
    ) -> TradovateReconciliationEvidence:
        """Fetch structured, paginated, account-bound reconciliation evidence with completeness proof."""
        return self.list_orders_paginated(
            page_size=page_size,
            max_pages=max_pages,
            since_utc=since_utc,
        )

    def find_orders_by_cl_ord_id(self, cl_ord_id: str) -> list[dict[str, Any]]:
        """Return account-bound broker order records matching an exact stable client order ID."""
        if not isinstance(cl_ord_id, str) or not cl_ord_id.strip():
            raise ContractError("cl_ord_id must be a non-empty string")
        target = cl_ord_id.strip()
        return [
            dict(order)
            for order in self.list_orders()
            if str(order.get("clOrdId", "")).strip() == target
        ]

    def _fetch_order_details(self, order_id: str) -> dict[str, Any]:
        """Fetch broker-side order item + latest orderVersion details to verify child protections."""
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()
        cleaned = order_id.strip()
        if not cleaned or any(ch.isspace() or ch in "?#&/" or ord(ch) < 32 for ch in cleaned):
            raise TradovateProtectionUnconfirmedError(
                f"Cannot query malformed child order ID {order_id!r}"
            )
        item_endpoint = self._build_account_endpoint("order/item", {"id": cleaned})
        try:
            item = self._request_json("GET", item_endpoint)
        except TradovateVenueError as exc:
            raise TradovateProtectionUnconfirmedError(
                f"Failed to confirm broker child order {cleaned}: {exc}",
                order_id=cleaned,
            ) from None
        try:
            item_acct = self._extract_record_account_id(
                item,
                context="order/item",
                expected_account_spec=expected_spec,
                expected_account_id=expected_acct,
            )
        except TradovateTransportError as exc:
            raise TradovateProtectionUnconfirmedError(str(exc), order_id=cleaned) from None
        if item_acct != expected_acct:
            raise TradovateProtectionUnconfirmedError(
                f"Broker child order {cleaned} accountId mismatch: expected {expected_acct!r}, got {item_acct!r}",
                order_id=cleaned,
            )
        merged = dict(item)
        if merged.get("stopPrice") is None and merged.get("price") is None:
            deps_endpoint = self._build_account_endpoint("orderVersion/deps", {"masterid": cleaned})
            try:
                versions = self._request_json_list("GET", deps_endpoint)
            except TradovateVenueError:
                versions = []
            if versions:
                latest = versions[-1]
                if latest.get("accountId") is not None:
                    try:
                        ver_acct = self._extract_record_account_id(
                            latest,
                            context="orderVersion/deps",
                            expected_account_spec=expected_spec,
                            expected_account_id=expected_acct,
                        )
                    except TradovateTransportError as exc:
                        raise TradovateProtectionUnconfirmedError(str(exc), order_id=cleaned) from None
                    if ver_acct != expected_acct:
                        raise TradovateProtectionUnconfirmedError(
                            f"Broker orderVersion {cleaned} accountId mismatch: expected {expected_acct!r}, got {ver_acct!r}",
                            order_id=cleaned,
                        )
                for key in ("orderQty", "orderType", "price", "stopPrice", "timeInForce"):
                    if latest.get(key) is not None and merged.get(key) is None:
                        merged[key] = latest[key]
        return merged

    def _resolve_child_order_confirmation(
        self,
        resp: Mapping[str, Any],
        *,
        child_order_id: str,
        inline_keys: tuple[str, ...],
    ) -> Mapping[str, Any]:
        for key in inline_keys:
            candidate = resp.get(key)
            if isinstance(candidate, Mapping):
                return candidate
        for list_key in ("orders", "childOrders"):
            raw_list = resp.get(list_key)
            if isinstance(raw_list, list):
                for entry in raw_list:
                    if not isinstance(entry, Mapping):
                        continue
                    eid = entry.get("orderId") if entry.get("orderId") is not None else entry.get("id")
                    if eid is not None and str(eid).strip() == child_order_id:
                        return entry
        return self._fetch_order_details(child_order_id)

    @staticmethod
    def _validate_child_protection(
        child_doc: Mapping[str, Any],
        *,
        expected_order_id: str,
        expected_action: str,
        expected_order_type: str,
        expected_qty: int,
        expected_price: Decimal,
        price_keys: tuple[str, ...],
        label: str,
        cl_ord_id: str,
        expected_account_id: str | None = None,
    ) -> Decimal:
        if expected_account_id is not None and child_doc.get("accountId") is not None:
            raw_acct = child_doc.get("accountId")
            if isinstance(raw_acct, bool) or str(raw_acct).strip() != expected_account_id:
                raise TradovateProtectionUnconfirmedError(
                    f"Broker {label} child accountId mismatch: expected {expected_account_id!r}, got {raw_acct!r}",
                    cl_ord_id=cl_ord_id,
                    order_id=expected_order_id,
                )
        raw_id = child_doc.get("orderId") if child_doc.get("orderId") is not None else child_doc.get("id")
        if raw_id is not None and str(raw_id).strip() != expected_order_id:
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child orderId mismatch: expected {expected_order_id!r}, got {raw_id!r}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        ord_status = str(child_doc.get("ordStatus") or child_doc.get("status") or "").strip().lower()
        if ord_status in ("rejected", "canceled", "cancelled", "expired", "suspended"):
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child order {expected_order_id} is not active (status={ord_status!r})",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        raw_action = str(child_doc.get("action") or child_doc.get("side") or "").strip().lower()
        if raw_action != expected_action.lower():
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child action mismatch: expected {expected_action!r}, got {raw_action!r}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        raw_type = str(child_doc.get("orderType") or child_doc.get("type") or "").strip().lower()
        if raw_type != expected_order_type.lower():
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child orderType mismatch: expected {expected_order_type!r}, got {raw_type!r}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        raw_qty = child_doc.get("orderQty") if child_doc.get("orderQty") is not None else child_doc.get("qty")
        try:
            confirmed_qty = _parse_broker_int(raw_qty, f"{label}.orderQty", positive=True)
        except ContractError as exc:
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child order missing/invalid quantity: {exc}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            ) from None
        if confirmed_qty != expected_qty:
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child quantity mismatch: expected {expected_qty}, got {confirmed_qty}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        raw_price = None
        for pkey in price_keys:
            if child_doc.get(pkey) is not None:
                raw_price = child_doc.get(pkey)
                break
        if raw_price is None:
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child order {expected_order_id} missing confirmed price",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        try:
            confirmed_price = _parse_broker_decimal(raw_price, f"{label}.price", positive=True)
        except ContractError as exc:
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child order price invalid: {exc}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            ) from None
        if confirmed_price != expected_price:
            raise TradovateProtectionUnconfirmedError(
                f"Broker {label} child price mismatch: expected {decimal_text(expected_price)}, "
                f"got {decimal_text(confirmed_price)}",
                cl_ord_id=cl_ord_id,
                order_id=expected_order_id,
            )
        return confirmed_price

    def get_quote(self, symbol_or_root: str) -> TradovateQuote:
        self._require_connected()
        raise TradovateTransportError(
            "Live market data quotes must be supplied via Tradovate WebSocket market-data adapter"
        )

    def place_protected_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
        """Place an atomic broker-native Tradovate OSO bracket and strictly verify child protections."""
        if not isinstance(request, TradovateOrderRequest):
            raise ContractError("request must be TradovateOrderRequest")
        if request.action is not FuturesOrderAction.OPEN_BRACKET:
            raise TradovateOrderError(
                f"place_protected_order requires OPEN_BRACKET action, got {request.action.value}"
            )
        self._require_connected()
        now = self._clock()
        self._require_live_authorization(now)
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()

        if request.side not in ("BUY", "SELL"):
            raise TradovateOrderError("OPEN_BRACKET requires side 'BUY' or 'SELL'")
        if request.contracts <= 0:
            raise TradovateOrderError("OPEN_BRACKET requires contracts >= 1")
        if request.stop_loss_price is None:
            raise TradovateOrderError("OPEN_BRACKET requires protective stop_loss_price")
        if request.entry_price is not None:
            if request.side == "BUY":
                if request.stop_loss_price >= request.entry_price:
                    raise TradovateOrderError("BUY stop_loss_price must be strictly below entry_price")
                if request.take_profit_price is not None and request.take_profit_price <= request.entry_price:
                    raise TradovateOrderError("BUY take_profit_price must be strictly above entry_price")
            else:
                if request.stop_loss_price <= request.entry_price:
                    raise TradovateOrderError("SELL stop_loss_price must be strictly above entry_price")
                if request.take_profit_price is not None and request.take_profit_price >= request.entry_price:
                    raise TradovateOrderError("SELL take_profit_price must be strictly below entry_price")

        cl_ord_id = (request.cl_ord_id or "").strip()
        if not cl_ord_id:
            raise TradovateOrderError("OPEN_BRACKET requires a stable cl_ord_id idempotency key")

        entry_action = "Buy" if request.side == "BUY" else "Sell"
        protective_action = "Sell" if request.side == "BUY" else "Buy"

        bracket1: dict[str, Any] = {
            "action": protective_action,
            "orderType": "Stop",
            "orderQty": request.contracts,
            "stopPrice": request.stop_loss_price,
            "timeInForce": "GTC",
            "isAutomated": True,
        }
        payload: dict[str, Any] = {
            "clOrdId": cl_ord_id,
            "symbol": request.contract_code,
            "action": entry_action,
            "orderQty": request.contracts,
            "orderType": "Market",
            "isAutomated": True,
            "bracket1": bracket1,
        }
        payload.update(self._account_body_fields())
        if request.take_profit_price is not None:
            payload["bracket2"] = {
                "action": protective_action,
                "orderType": "Limit",
                "orderQty": request.contracts,
                "price": request.take_profit_price,
                "timeInForce": "GTC",
                "isAutomated": True,
            }

        resp = self._request_json("POST", "order/placeOSO", payload=payload)

        err_text = resp.get("errorText") or resp.get("failureReason") or resp.get("failureText")
        if err_text:
            if resp.get("orderId") is not None:
                raise TradovateProtectionUnconfirmedError(
                    f"Tradovate placeOSO reported error with orderId present: {err_text}",
                    cl_ord_id=cl_ord_id,
                    order_id=str(resp.get("orderId")),
                    request_id=request.request_id,
                )
            raise TradovateProtectionUnconfirmedError(
                f"Tradovate placeOSO refused or failed without confirmed protection: {err_text}",
                cl_ord_id=cl_ord_id,
                request_id=request.request_id,
            )

        if resp.get("accountId") is not None and (
            isinstance(resp.get("accountId"), bool)
            or str(resp.get("accountId")).strip() != expected_acct
        ):
            raise TradovateProtectionUnconfirmedError(
                f"Tradovate placeOSO accountId mismatch: expected {expected_acct!r}, got {resp.get('accountId')!r}",
                cl_ord_id=cl_ord_id,
                request_id=request.request_id,
            )
        if resp.get("accountSpec") is not None and (
            isinstance(resp.get("accountSpec"), bool)
            or str(resp.get("accountSpec")).strip() != expected_spec
        ):
            raise TradovateProtectionUnconfirmedError(
                f"Tradovate placeOSO accountSpec mismatch: expected {expected_spec!r}, got {resp.get('accountSpec')!r}",
                cl_ord_id=cl_ord_id,
                request_id=request.request_id,
            )

        if resp.get("clOrdId") is not None and str(resp.get("clOrdId")).strip() != cl_ord_id:
            raise TradovateProtectionUnconfirmedError(
                f"Tradovate placeOSO clOrdId mismatch: expected {cl_ord_id!r}, got {resp.get('clOrdId')!r}",
                cl_ord_id=cl_ord_id,
                request_id=request.request_id,
            )

        entry_order_id = _parse_broker_id(resp.get("orderId"), "orderId")
        oso1_id = _parse_broker_id(resp.get("oso1Id"), "oso1Id")
        if oso1_id == entry_order_id:
            raise TradovateProtectionUnconfirmedError(
                "Tradovate placeOSO returned oso1Id identical to entry orderId",
                cl_ord_id=cl_ord_id,
                order_id=entry_order_id,
                request_id=request.request_id,
            )

        sl_doc = self._resolve_child_order_confirmation(
            resp,
            child_order_id=oso1_id,
            inline_keys=("bracket1", "oso1", "stopOrder"),
        )
        confirmed_sl = self._validate_child_protection(
            sl_doc,
            expected_order_id=oso1_id,
            expected_action=protective_action,
            expected_order_type="Stop",
            expected_qty=request.contracts,
            expected_price=request.stop_loss_price,
            price_keys=("stopPrice", "stop_price", "stopLossPrice"),
            label="stop-loss (oso1)",
            cl_ord_id=cl_ord_id,
            expected_account_id=expected_acct,
        )

        oso2_id: str | None = None
        confirmed_tp: Decimal | None = None
        if request.take_profit_price is not None:
            oso2_id = _parse_broker_id(resp.get("oso2Id"), "oso2Id")
            if oso2_id in (entry_order_id, oso1_id):
                raise TradovateProtectionUnconfirmedError(
                    "Tradovate placeOSO returned oso2Id colliding with entry or stop-loss orderId",
                    cl_ord_id=cl_ord_id,
                    order_id=entry_order_id,
                    request_id=request.request_id,
                )
            tp_doc = self._resolve_child_order_confirmation(
                resp,
                child_order_id=oso2_id,
                inline_keys=("bracket2", "oso2", "takeProfitOrder"),
            )
            confirmed_tp = self._validate_child_protection(
                tp_doc,
                expected_order_id=oso2_id,
                expected_action=protective_action,
                expected_order_type="Limit",
                expected_qty=request.contracts,
                expected_price=request.take_profit_price,
                price_keys=("price", "limitPrice", "takeProfitPrice"),
                label="take-profit (oso2)",
                cl_ord_id=cl_ord_id,
                expected_account_id=expected_acct,
            )

        # NEVER synthesize fill_price or filled_contracts from request inputs.
        raw_filled_qty = (
            resp.get("filledQty")
            if resp.get("filledQty") is not None
            else (resp.get("cumQty") if resp.get("cumQty") is not None else resp.get("fillQty"))
        )
        raw_fill_price = (
            resp.get("fillPrice")
            if resp.get("fillPrice") is not None
            else (resp.get("avgPx") if resp.get("avgPx") is not None else resp.get("avgFillPrice"))
        )
        filled_contracts = 0
        confirmed_fill_price: Decimal | None = None
        if raw_filled_qty is not None:
            try:
                filled_contracts = _parse_broker_int(raw_filled_qty, "filledQty", non_negative=True)
            except ContractError as exc:
                raise TradovateProtectionUnconfirmedError(
                    f"Broker placeOSO returned invalid filledQty: {exc}",
                    cl_ord_id=cl_ord_id,
                    order_id=entry_order_id,
                    request_id=request.request_id,
                ) from None
            if filled_contracts > request.contracts:
                raise TradovateProtectionUnconfirmedError(
                    f"Broker placeOSO filledQty ({filled_contracts}) exceeds requested contracts ({request.contracts})",
                    cl_ord_id=cl_ord_id,
                    order_id=entry_order_id,
                    request_id=request.request_id,
                )
        if filled_contracts > 0:
            if raw_fill_price is None:
                raise TradovateProtectionUnconfirmedError(
                    "Broker placeOSO reported filledQty > 0 without confirmed fillPrice",
                    cl_ord_id=cl_ord_id,
                    order_id=entry_order_id,
                    request_id=request.request_id,
                )
            try:
                confirmed_fill_price = _parse_broker_decimal(raw_fill_price, "fillPrice", positive=True)
            except ContractError as exc:
                raise TradovateProtectionUnconfirmedError(
                    f"Broker placeOSO returned invalid fillPrice: {exc}",
                    cl_ord_id=cl_ord_id,
                    order_id=entry_order_id,
                    request_id=request.request_id,
                ) from None
            receipt_status = "FILLED" if filled_contracts == request.contracts else "PARTIALLY_FILLED"
        else:
            receipt_status = "SUBMITTED_PROTECTED"

        raw_pos_id = resp.get("positionId")
        pos_id = str(raw_pos_id).strip() if raw_pos_id is not None and str(raw_pos_id).strip() else None

        return TradovateOrderReceipt(
            request_id=request.request_id,
            cl_ord_id=cl_ord_id,
            action=request.action,
            accepted=True,
            status=receipt_status,
            order_id=entry_order_id,
            stop_loss_order_id=oso1_id,
            take_profit_order_id=oso2_id,
            protection_confirmed=True,
            position_id=pos_id,
            contract_code=request.contract_code,
            root_symbol=request.root_symbol,
            cas_symbol=request.cas_symbol,
            side=request.side,
            filled_contracts=filled_contracts,
            fill_price=confirmed_fill_price,
            stop_loss_price=confirmed_sl,
            take_profit_price=confirmed_tp,
            commission_usd=Decimal("0.00"),
            realized_pnl_usd=Decimal("0.00"),
            net_pnl_usd=Decimal("0.00"),
            reason="OSO_BRACKET_CONFIRMED",
            executed_at=now,
        )

    def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
        self._require_connected()
        now = self._clock()
        if request.action is FuturesOrderAction.OPEN_BRACKET:
            return self.place_protected_order(request)

        self._require_live_authorization(now)
        expected_acct = self._authorized_account_id()
        expected_spec = self._authorized_account_spec()

        if request.action is FuturesOrderAction.AMEND_STOP:
            if not request.order_id or request.stop_loss_price is None or request.contracts <= 0:
                raise TradovateOrderError(
                    "LIVE AMEND_STOP requires order_id, stop_loss_price, and contracts >= 1"
                )
            cl_ord_id = (request.cl_ord_id or "").strip()
            if not cl_ord_id:
                raise TradovateOrderError("LIVE AMEND_STOP requires a stable cl_ord_id idempotency key")
            mod_payload: dict[str, Any] = {
                "orderId": int(request.order_id) if request.order_id.isdigit() else request.order_id,
                "orderQty": request.contracts,
                "orderType": "Stop",
                "stopPrice": request.stop_loss_price,
                "clOrdId": cl_ord_id,
                "isAutomated": True,
            }
            mod_payload.update(self._account_body_fields())
            resp = self._request_json("POST", "order/modifyOrder", payload=mod_payload)
            confirmed_id = self._validate_protective_broker_response(
                resp,
                endpoint="order/modifyOrder",
                expected_cl_ord_id=cl_ord_id,
                expected_account_id=expected_acct,
                expected_account_spec=expected_spec,
                rejected_statuses=frozenset(
                    {"rejected", "expired", "canceled", "cancelled", "suspended", "voided", "error", "failed", "pendingnew", "pending_new"}
                ),
                allowed_statuses=frozenset(
                    {"working", "accepted", "modified", "amended", "active", "filled", "completed"}
                ),
            )
            confirmed_sl = request.stop_loss_price
            if resp.get("stopPrice") is not None:
                try:
                    confirmed_sl = _parse_broker_decimal(resp.get("stopPrice"), "stopPrice", positive=True)
                except ContractError as exc:
                    raise TradovateTransportError(
                        f"Tradovate order/modifyOrder invalid stopPrice: {exc}",
                        ambiguous=True,
                    ) from None
                if confirmed_sl != request.stop_loss_price:
                    raise TradovateTransportError(
                        f"Tradovate order/modifyOrder stopPrice mismatch: "
                        f"expected {decimal_text(request.stop_loss_price)}, got {decimal_text(confirmed_sl)}",
                        ambiguous=True,
                    )
            if resp.get("orderQty") is not None:
                try:
                    confirmed_qty = _parse_broker_int(resp.get("orderQty"), "orderQty", positive=True)
                except ContractError as exc:
                    raise TradovateTransportError(
                        f"Tradovate order/modifyOrder invalid orderQty: {exc}",
                        ambiguous=True,
                    ) from None
                if confirmed_qty != request.contracts:
                    raise TradovateTransportError(
                        f"Tradovate order/modifyOrder orderQty mismatch: expected {request.contracts}, got {confirmed_qty}",
                        ambiguous=True,
                    )
            return TradovateOrderReceipt(
                request_id=request.request_id,
                cl_ord_id=cl_ord_id,
                action=request.action,
                accepted=True,
                status="AMENDED",
                order_id=confirmed_id,
                stop_loss_order_id=confirmed_id,
                position_id=request.position_id,
                contract_code=request.contract_code,
                root_symbol=request.root_symbol,
                cas_symbol=request.cas_symbol,
                side=request.side,
                filled_contracts=request.contracts,
                fill_price=None,
                stop_loss_price=confirmed_sl,
                take_profit_price=request.take_profit_price,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason="STOP_LOSS_AMENDED_HTTPS",
                executed_at=now,
            )

        if request.action is FuturesOrderAction.CANCEL_ORDER:
            if not request.order_id:
                raise TradovateOrderError("LIVE CANCEL_ORDER requires order_id")
            cancel_payload: dict[str, Any] = {
                "orderId": int(request.order_id) if request.order_id.isdigit() else request.order_id,
                "isAutomated": True,
            }
            cancel_payload.update(self._account_body_fields())
            if request.cl_ord_id:
                cancel_payload["clOrdId"] = request.cl_ord_id
            resp = self._request_json("POST", "order/cancelOrder", payload=cancel_payload)
            confirmed_id = self._validate_protective_broker_response(
                resp,
                endpoint="order/cancelOrder",
                expected_cl_ord_id=request.cl_ord_id,
                expected_account_id=expected_acct,
                expected_account_spec=expected_spec,
                rejected_statuses=frozenset(
                    {"rejected", "expired", "suspended", "error", "failed", "pendingnew", "pending_new"}
                ),
            )
            return TradovateOrderReceipt(
                request_id=request.request_id,
                cl_ord_id=request.cl_ord_id,
                action=request.action,
                accepted=True,
                status="CANCELLED",
                order_id=confirmed_id,
                position_id=request.position_id,
                contract_code=request.contract_code,
                root_symbol=request.root_symbol,
                cas_symbol=request.cas_symbol,
                side=request.side,
                filled_contracts=0,
                fill_price=None,
                stop_loss_price=None,
                take_profit_price=None,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason="ORDER_CANCELLED_HTTPS",
                executed_at=now,
            )

        if request.action is FuturesOrderAction.CLOSE_POSITION:
            if not request.contract_code:
                raise TradovateOrderError("LIVE CLOSE_POSITION requires contract_code")
            cl_ord_id = (request.cl_ord_id or "").strip()
            if not cl_ord_id:
                raise TradovateOrderError("LIVE CLOSE_POSITION requires a stable cl_ord_id idempotency key")
            liq_payload: dict[str, Any] = {
                "symbol": request.contract_code,
                "admin": False,
                "clOrdId": cl_ord_id,
                "isAutomated": True,
            }
            liq_payload.update(self._account_body_fields())
            resp = self._request_json("POST", "order/liquidatePosition", payload=liq_payload)
            confirmed_id = self._validate_protective_broker_response(
                resp,
                endpoint="order/liquidatePosition",
                expected_cl_ord_id=cl_ord_id,
                expected_account_id=expected_acct,
                expected_account_spec=expected_spec,
                rejected_statuses=frozenset(
                    {"rejected", "expired", "canceled", "cancelled", "suspended", "voided", "error", "failed", "pendingnew", "pending_new", "working"}
                ),
                allowed_statuses=frozenset({"filled", "completed", "closed"}),
            )
            if resp.get("symbol") is not None and str(resp.get("symbol")).strip().upper() != request.contract_code:
                raise TradovateTransportError(
                    f"Tradovate order/liquidatePosition symbol mismatch: "
                    f"expected {request.contract_code!r}, got {resp.get('symbol')!r}",
                    ambiguous=True,
                )
            raw_filled_qty = (
                resp.get("filledQty")
                if resp.get("filledQty") is not None
                else (resp.get("cumQty") if resp.get("cumQty") is not None else resp.get("fillQty"))
            )
            if raw_filled_qty is not None:
                try:
                    filled_contracts = _parse_broker_int(raw_filled_qty, "filledQty", positive=True)
                except ContractError as exc:
                    raise TradovateTransportError(
                        f"Tradovate order/liquidatePosition invalid filledQty: {exc}",
                        ambiguous=True,
                    ) from None
                if request.contracts > 0 and filled_contracts > request.contracts:
                    raise TradovateTransportError(
                        f"Tradovate order/liquidatePosition filledQty ({filled_contracts}) exceeds {request.contracts}",
                        ambiguous=True,
                    )
            else:
                filled_contracts = request.contracts
            raw_fill_price = (
                resp.get("fillPrice")
                if resp.get("fillPrice") is not None
                else (resp.get("avgPx") if resp.get("avgPx") is not None else resp.get("avgFillPrice"))
            )
            confirmed_fill_price: Decimal | None = None
            if raw_fill_price is not None:
                try:
                    confirmed_fill_price = _parse_broker_decimal(raw_fill_price, "fillPrice", positive=True)
                except ContractError as exc:
                    raise TradovateTransportError(
                        f"Tradovate order/liquidatePosition invalid fillPrice: {exc}",
                        ambiguous=True,
                    ) from None
            return TradovateOrderReceipt(
                request_id=request.request_id,
                cl_ord_id=cl_ord_id,
                action=request.action,
                accepted=True,
                status="CLOSED",
                order_id=confirmed_id,
                position_id=request.position_id,
                contract_code=request.contract_code,
                root_symbol=request.root_symbol,
                cas_symbol=request.cas_symbol,
                side=request.side,
                filled_contracts=filled_contracts,
                fill_price=confirmed_fill_price,
                stop_loss_price=None,
                take_profit_price=None,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason="POSITION_LIQUIDATED_HTTPS",
                executed_at=now,
            )

        if request.action is FuturesOrderAction.EMERGENCY_CLOSE_ALL:
            open_positions = self.positions()
            closed_qty = 0
            last_order_id: str | None = None
            leg_errors: list[str] = []
            base_key = (request.cl_ord_id or request.request_id).strip()
            for idx, pos in enumerate(open_positions, start=1):
                leg_cl_ord_id = _compute_stable_cl_ord_id(
                    account_id=expected_acct,
                    idempotency_key=f"{base_key}:leg:{idx}:{pos.position_id}",
                    contract_code=pos.contract_code,
                    action=FuturesOrderAction.CLOSE_POSITION.value,
                    side=pos.side,
                    contracts=pos.contracts,
                    stop_loss_price=None,
                    take_profit_price=None,
                    target_id=pos.position_id,
                )
                close_req = TradovateOrderRequest(
                    request_id=f"{request.request_id}-{idx}",
                    cl_ord_id=leg_cl_ord_id,
                    action=FuturesOrderAction.CLOSE_POSITION,
                    contract_code=pos.contract_code,
                    root_symbol=pos.root_symbol,
                    cas_symbol=pos.cas_symbol,
                    side=pos.side,
                    contracts=pos.contracts,
                    position_id=pos.position_id,
                    client_tag=request.client_tag or "EMERGENCY_CLOSE_ALL",
                    created_at=now,
                )
                try:
                    rec = self.send_order(close_req)
                    closed_qty += rec.filled_contracts
                    last_order_id = rec.order_id
                except Exception as exc:
                    leg_errors.append(f"{pos.position_id}({leg_cl_ord_id}): {type(exc).__name__}: {exc}")
            if leg_errors:
                raise TradovateTransportError(
                    f"Tradovate EMERGENCY_CLOSE_ALL failed on {len(leg_errors)}/{len(open_positions)} leg(s): "
                    + "; ".join(leg_errors),
                    ambiguous=True,
                )
            return TradovateOrderReceipt(
                request_id=request.request_id,
                cl_ord_id=request.cl_ord_id,
                action=request.action,
                accepted=True,
                status="EMERGENCY_CLOSED",
                order_id=last_order_id or "",
                position_id=None,
                contract_code="",
                root_symbol="",
                cas_symbol="",
                side=None,
                filled_contracts=closed_qty,
                fill_price=None,
                stop_loss_price=None,
                take_profit_price=None,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason=f"EMERGENCY_CLOSED_{len(open_positions)}_POSITIONS_HTTPS",
                executed_at=now,
            )

        raise TradovateTransportError(f"Unsupported live HTTPS action {request.action.value}")


# ---------------------------------------------------------------------------
# 3. Deterministic Offline Paper Matching Engine Emulator
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _MutablePaperPosition:
    position_id: str
    contract_code: str
    root_symbol: str
    cas_symbol: str
    side: str
    contracts: int
    entry_price: Decimal
    stop_loss_price: Decimal | None
    take_profit_price: Decimal | None
    used_margin_usd: Decimal
    commission_usd: Decimal
    opened_at: datetime
    updated_at: datetime
    stop_loss_order_id: str | None = None
    take_profit_order_id: str | None = None
    cl_ord_id: str | None = None


class TradovateMicroFuturesPaperEmulator:
    """100% deterministic offline CME micro-futures matching engine (MNQ/MYM/MES/MGC).

    Tracks exact ``Decimal`` equity, balance, peak equity, drawdown, intraday/
    exchange margin, OCO Stop-Loss / Take-Profit triggers on ``set_quote()``,
    round-turn commissions (per-contract defaults from ``micro_futures_specs``, e.g. ``$1.24`` equity micros / ``$2.42`` COMEX ``MGC``),
    protective stop amendments, manual closes, and emergency flatten-all.
    """

    def __init__(
        self,
        *,
        account_id: str = "TRADOVATE-PAPER-001",
        mode: str = TRADOVATE_MODE_DEMO,
        starting_equity_usd: Decimal = DEFAULT_PAPER_STARTING_EQUITY_USD,
        clock: Callable[[], datetime] | None = None,
        use_exchange_margin: bool = False,
        connected: bool = True,
    ) -> None:
        if not isinstance(account_id, str) or not account_id.strip():
            raise ContractError("account_id must be a non-empty string")
        self._account_id = account_id.strip()
        self._mode = _normalize_mode(mode)
        self._starting_equity_usd = _q2(
            _exact_decimal(starting_equity_usd, "starting_equity_usd", positive=True)
        )
        self._balance_usd = self._starting_equity_usd
        self._peak_equity_usd = self._starting_equity_usd
        self._realized_pnl_usd = Decimal("0.00")
        self._total_commissions_usd = Decimal("0.00")
        self._clock = clock if clock is not None else _utc_now
        self._use_exchange_margin = bool(use_exchange_margin)
        self._connected = bool(connected)
        self._lock = RLock()
        self._order_seq = 0
        self._position_seq = 0
        self._quotes: dict[str, TradovateQuote] = {}
        self._positions: dict[str, _MutablePaperPosition] = {}
        self._submitted_oso_payloads: list[dict[str, Any]] = []
        self._order_history: list[dict[str, Any]] = []
        self._seen_cl_ord_ids: set[str] = set()

    @property
    def account_id(self) -> str:
        return self._account_id

    @property
    def starting_equity_usd(self) -> Decimal:
        return self._starting_equity_usd

    def connect(self) -> None:
        with self._lock:
            self._connected = True

    def disconnect(self) -> None:
        with self._lock:
            self._connected = False

    def set_connected(self, connected: bool) -> None:
        if type(connected) is not bool:
            raise ContractError("connected must be bool")
        with self._lock:
            self._connected = connected

    def is_connected(self) -> bool:
        with self._lock:
            return self._connected

    def _require_connected(self) -> None:
        if not self._connected:
            raise TradovateTransportError("Tradovate paper emulator is disconnected")

    def _next_order_id(self) -> str:
        self._order_seq += 1
        return f"ORD-{self._order_seq:06d}"

    def _next_position_id(self) -> str:
        self._position_seq += 1
        return f"POS-{self._position_seq:06d}"

    def _spec_for(self, root_symbol: str) -> MicroFuturesContractSpec:
        return CME_MICRO_FUTURES_SPECS[root_symbol]

    def _margin_per_contract(self, spec: MicroFuturesContractSpec) -> Decimal:
        return (
            spec.default_exchange_initial_margin_usd
            if self._use_exchange_margin
            else spec.default_intraday_margin_usd
        )

    def _mark_price(self, pos: _MutablePaperPosition) -> Decimal:
        q = self._quotes.get(pos.root_symbol)
        if q is None:
            return pos.entry_price
        return q.bid if pos.side == "BUY" else q.ask

    def _floating_pnl_for(self, pos: _MutablePaperPosition) -> Decimal:
        mark = self._mark_price(pos)
        return _q2(
            compute_contract_pnl_usd(
                pos.root_symbol,
                pos.side,
                pos.entry_price,
                mark,
                pos.contracts,
                include_commission=False,
            )
        )

    def _snapshot_position(self, pos: _MutablePaperPosition) -> TradovatePosition:
        mark = self._mark_price(pos)
        floating = self._floating_pnl_for(pos)
        return TradovatePosition(
            position_id=pos.position_id,
            contract_code=pos.contract_code,
            root_symbol=pos.root_symbol,
            cas_symbol=pos.cas_symbol,
            side=pos.side,
            contracts=pos.contracts,
            entry_price=pos.entry_price,
            current_price=mark,
            stop_loss_price=pos.stop_loss_price,
            take_profit_price=pos.take_profit_price,
            used_margin_usd=pos.used_margin_usd,
            floating_pnl_usd=floating,
            commission_usd=pos.commission_usd,
            opened_at=pos.opened_at,
            updated_at=pos.updated_at,
            stop_loss_order_id=pos.stop_loss_order_id,
            take_profit_order_id=pos.take_profit_order_id,
            cl_ord_id=pos.cl_ord_id,
            account_id=self._account_id,
        )

    def _current_equity_unlocked(self) -> tuple[Decimal, Decimal, Decimal]:
        floating_total = Decimal("0.00")
        used_margin = Decimal("0.00")
        for pos in self._positions.values():
            floating_total += self._floating_pnl_for(pos)
            used_margin += pos.used_margin_usd
        floating_total = _q2(floating_total)
        used_margin = _q2(used_margin)
        equity = _q2(self._balance_usd + floating_total)
        if equity > self._peak_equity_usd:
            self._peak_equity_usd = equity
        return equity, floating_total, used_margin

    def _close_position_unlocked(
        self,
        position_id: str,
        *,
        exit_price: Decimal | None,
        action: FuturesOrderAction,
        status: str,
        reason: str,
        request_id: str,
        now: datetime,
        cl_ord_id: str | None = None,
    ) -> TradovateOrderReceipt:
        cleaned_cl: str | None = None
        if cl_ord_id is not None:
            cleaned_cl = cl_ord_id.strip()
            if not cleaned_cl:
                raise TradovateOrderError("cl_ord_id cannot be empty")
            if cleaned_cl in self._seen_cl_ord_ids:
                raise TradovateOrderError(
                    f"Duplicate clOrdId {cleaned_cl!r} refused in paper emulator"
                )
        pos = self._positions.get(position_id)
        if pos is None:
            raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
        if exit_price is not None:
            fill_px = align_price_to_tick(
                pos.root_symbol, _exact_decimal(exit_price, "exit_price", positive=True)
            )
        else:
            fill_px = self._mark_price(pos)

        gross_pnl = _q2(
            compute_contract_pnl_usd(
                pos.root_symbol,
                pos.side,
                pos.entry_price,
                fill_px,
                pos.contracts,
                include_commission=False,
            )
        )
        net_pnl = _q2(
            compute_contract_pnl_usd(
                pos.root_symbol,
                pos.side,
                pos.entry_price,
                fill_px,
                pos.contracts,
                include_commission=True,
            )
        )
        commission = _q2(gross_pnl - net_pnl)

        self._balance_usd = _q2(self._balance_usd + net_pnl)
        self._realized_pnl_usd = _q2(self._realized_pnl_usd + net_pnl)
        self._total_commissions_usd = _q2(self._total_commissions_usd + commission)
        del self._positions[position_id]
        self._current_equity_unlocked()
        ord_id = self._next_order_id()
        if cleaned_cl is not None:
            self._seen_cl_ord_ids.add(cleaned_cl)
        self._order_history.append(
            {
                "accountId": self._account_id,
                "accountSpec": self._account_id,
                "orderId": ord_id,
                "clOrdId": cleaned_cl,
                "positionId": pos.position_id,
                "symbol": pos.contract_code,
                "action": "Sell" if pos.side == "BUY" else "Buy",
                "orderType": "Market",
                "orderQty": pos.contracts,
                "filledQty": pos.contracts,
                "fillPrice": decimal_text(fill_px),
                "ordStatus": "Filled",
                "executedAt": _iso_utc(now),
            }
        )

        return TradovateOrderReceipt(
            request_id=request_id,
            cl_ord_id=cleaned_cl,
            action=action,
            accepted=True,
            status=status,
            order_id=ord_id,
            position_id=pos.position_id,
            contract_code=pos.contract_code,
            root_symbol=pos.root_symbol,
            cas_symbol=pos.cas_symbol,
            side=pos.side,
            filled_contracts=pos.contracts,
            fill_price=fill_px,
            stop_loss_price=pos.stop_loss_price,
            take_profit_price=pos.take_profit_price,
            commission_usd=commission,
            realized_pnl_usd=gross_pnl,
            net_pnl_usd=net_pnl,
            reason=reason,
            executed_at=now,
        )

    def set_quote(
        self,
        symbol_or_root: str,
        bid: Decimal,
        ask: Decimal,
        *,
        observed_at: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        """Update live quote for a symbol/root and evaluate OCO SL/TP triggers."""
        root = translate_cas_symbol_to_micro_root(symbol_or_root)
        bid_d = align_price_to_tick(root, _exact_decimal(bid, "bid", positive=True))
        ask_d = align_price_to_tick(root, _exact_decimal(ask, "ask", positive=True))
        if bid_d > ask_d:
            raise ContractError(f"Aligned bid ({bid_d}) cannot exceed ask ({ask_d})")
        now = self._clock() if observed_at is None else utc_time(observed_at, "observed_at")
        quote = TradovateQuote(symbol=root, bid=bid_d, ask=ask_d, observed_at=now)

        triggered: list[TradovateOrderReceipt] = []
        with self._lock:
            self._quotes[root] = quote
            matching_ids = [
                pid for pid in sorted(self._positions) if self._positions[pid].root_symbol == root
            ]
            for pid in matching_ids:
                pos = self._positions.get(pid)
                if pos is None:
                    continue
                pos.updated_at = now
                if pos.side == "BUY":
                    if pos.stop_loss_price is not None and bid_d <= pos.stop_loss_price:
                        triggered.append(
                            self._close_position_unlocked(
                                pid,
                                exit_price=pos.stop_loss_price,
                                action=FuturesOrderAction.CLOSE_POSITION,
                                status="STOP_LOSS_FILLED",
                                reason="OCO_STOP_LOSS_TRIGGERED",
                                request_id=f"oco-sl-{pid}-{self._order_seq + 1}",
                                now=now,
                            )
                        )
                    elif pos.take_profit_price is not None and bid_d >= pos.take_profit_price:
                        triggered.append(
                            self._close_position_unlocked(
                                pid,
                                exit_price=pos.take_profit_price,
                                action=FuturesOrderAction.CLOSE_POSITION,
                                status="TAKE_PROFIT_FILLED",
                                reason="OCO_TAKE_PROFIT_TRIGGERED",
                                request_id=f"oco-tp-{pid}-{self._order_seq + 1}",
                                now=now,
                            )
                        )
                else:
                    if pos.stop_loss_price is not None and ask_d >= pos.stop_loss_price:
                        triggered.append(
                            self._close_position_unlocked(
                                pid,
                                exit_price=pos.stop_loss_price,
                                action=FuturesOrderAction.CLOSE_POSITION,
                                status="STOP_LOSS_FILLED",
                                reason="OCO_STOP_LOSS_TRIGGERED",
                                request_id=f"oco-sl-{pid}-{self._order_seq + 1}",
                                now=now,
                            )
                        )
                    elif pos.take_profit_price is not None and ask_d <= pos.take_profit_price:
                        triggered.append(
                            self._close_position_unlocked(
                                pid,
                                exit_price=pos.take_profit_price,
                                action=FuturesOrderAction.CLOSE_POSITION,
                                status="TAKE_PROFIT_FILLED",
                                reason="OCO_TAKE_PROFIT_TRIGGERED",
                                request_id=f"oco-tp-{pid}-{self._order_seq + 1}",
                                now=now,
                            )
                        )
            self._current_equity_unlocked()
        return tuple(triggered)

    def get_quote(self, symbol_or_root: str) -> TradovateQuote:
        root = translate_cas_symbol_to_micro_root(symbol_or_root)
        with self._lock:
            self._require_connected()
            quote = self._quotes.get(root)
            if quote is None:
                raise TradovateOrderError(
                    f"No quote seeded in paper emulator for {root!r}; call set_quote() first"
                )
            return quote

    def positions(self) -> tuple[TradovatePosition, ...]:
        with self._lock:
            self._require_connected()
            return tuple(self._snapshot_position(self._positions[pid]) for pid in sorted(self._positions))

    def account_snapshot(self, *, now_utc: datetime | None = None) -> TradovateAccountSnapshot:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            self._require_connected()
            equity, floating, used_margin = self._current_equity_unlocked()
            available = _q2(equity - used_margin)
            margin_level = (
                _q2((equity * Decimal("100")) / used_margin)
                if used_margin > Decimal("0")
                else None
            )
            dd = compute_drawdown_pct(equity, self._peak_equity_usd)
            return TradovateAccountSnapshot(
                account_id=self._account_id,
                mode=self._mode,
                connected=True,
                connection_status=CONNECTION_STATUS_CONNECTED,
                currency="USD",
                balance_usd=self._balance_usd,
                equity_usd=equity,
                peak_equity_usd=self._peak_equity_usd,
                drawdown_pct=dd,
                used_margin_usd=used_margin,
                available_margin_usd=available,
                margin_level_pct=margin_level,
                floating_pnl_usd=floating,
                realized_pnl_usd=self._realized_pnl_usd,
                total_commissions_usd=self._total_commissions_usd,
                open_position_count=len(self._positions),
                observed_at=now,
            )

    def amend_stop(
        self,
        position_id: str,
        new_stop_loss_price: Decimal,
        *,
        request_id: str | None = None,
        cl_ord_id: str | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            self._require_connected()
            cleaned_cl: str | None = None
            if cl_ord_id is not None:
                cleaned_cl = cl_ord_id.strip()
                if not cleaned_cl:
                    raise TradovateOrderError("cl_ord_id cannot be empty")
                if cleaned_cl in self._seen_cl_ord_ids:
                    raise TradovateOrderError(
                        f"Duplicate clOrdId {cleaned_cl!r} refused in paper emulator"
                    )
            pos = self._positions.get(position_id)
            if pos is None:
                raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
            aligned_sl = align_price_to_tick(
                pos.root_symbol,
                _exact_decimal(new_stop_loss_price, "new_stop_loss_price", positive=True),
            )
            pos.stop_loss_price = aligned_sl
            pos.updated_at = now
            ord_id = self._next_order_id()
            if cleaned_cl is not None:
                self._seen_cl_ord_ids.add(cleaned_cl)
            self._order_history.append(
                {
                    "accountId": self._account_id,
                    "accountSpec": self._account_id,
                    "orderId": ord_id,
                    "clOrdId": cleaned_cl,
                    "positionId": pos.position_id,
                    "symbol": pos.contract_code,
                    "action": "Sell" if pos.side == "BUY" else "Buy",
                    "orderType": "Stop",
                    "orderQty": pos.contracts,
                    "stopPrice": decimal_text(aligned_sl),
                    "ordStatus": "Working",
                    "executedAt": _iso_utc(now),
                }
            )
            return TradovateOrderReceipt(
                request_id=request_id or f"amend-{position_id}-{self._order_seq}",
                cl_ord_id=cleaned_cl,
                action=FuturesOrderAction.AMEND_STOP,
                accepted=True,
                status="AMENDED",
                order_id=ord_id,
                position_id=pos.position_id,
                contract_code=pos.contract_code,
                root_symbol=pos.root_symbol,
                cas_symbol=pos.cas_symbol,
                side=pos.side,
                filled_contracts=pos.contracts,
                fill_price=pos.entry_price,
                stop_loss_price=aligned_sl,
                take_profit_price=pos.take_profit_price,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason="STOP_LOSS_AMENDED",
                executed_at=now,
            )

    def close_position(
        self,
        position_id: str,
        *,
        exit_price: Decimal | None = None,
        reason: str = "MANUAL_CLOSE",
        request_id: str | None = None,
        cl_ord_id: str | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            self._require_connected()
            return self._close_position_unlocked(
                position_id,
                exit_price=exit_price,
                action=FuturesOrderAction.CLOSE_POSITION,
                status="CLOSED",
                reason=reason,
                request_id=request_id or f"close-{position_id}-{self._order_seq + 1}",
                now=now,
                cl_ord_id=cl_ord_id,
            )

    def emergency_close_all(
        self,
        *,
        reason: str = "EMERGENCY_CLOSE_ALL",
        request_id: str | None = None,
        now_utc: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        receipts: list[TradovateOrderReceipt] = []
        with self._lock:
            self._require_connected()
            for idx, pid in enumerate(sorted(self._positions), start=1):
                receipts.append(
                    self._close_position_unlocked(
                        pid,
                        exit_price=None,
                        action=FuturesOrderAction.EMERGENCY_CLOSE_ALL,
                        status="EMERGENCY_CLOSED",
                        reason=reason,
                        request_id=(
                            f"{request_id}-{idx}"
                            if request_id
                            else f"emergency-{pid}-{self._order_seq + 1}"
                        ),
                        now=now,
                    )
                )
        return tuple(receipts)

    def replenish_demo_capital(
        self,
        target_balance_usd: Decimal,
        *,
        reason: str = "DEMO_CAPITAL_REPLENISHED",
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Restore flat DEMO paper balance & peak equity to target_balance_usd without deleting history."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        clean_reason = reason.strip() if isinstance(reason, str) and reason.strip() else "DEMO_CAPITAL_REPLENISHED"
        with self._lock:
            self._require_connected()
            if self._mode != TRADOVATE_MODE_DEMO:
                raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
            if self._positions:
                raise ContractError(DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS)
            target = _q2(_exact_decimal(target_balance_usd, "target_balance_usd", positive=True))
            prev_bal = _q2(self._balance_usd)
            prev_peak = _q2(self._peak_equity_usd)
            added = _q2(target - prev_bal)
            if added <= Decimal("0.00"):
                return {
                    "replenished": False,
                    "added_usd": "0.00",
                    "previous_balance_usd": decimal_text(prev_bal),
                    "new_balance_usd": decimal_text(prev_bal),
                    "previous_peak_equity_usd": decimal_text(prev_peak),
                    "new_peak_equity_usd": decimal_text(prev_peak),
                    "reason": clean_reason,
                    "observed_at": _iso_utc(now),
                }
            self._balance_usd = target
            self._peak_equity_usd = target
            return {
                "replenished": True,
                "added_usd": decimal_text(added),
                "previous_balance_usd": decimal_text(prev_bal),
                "new_balance_usd": decimal_text(target),
                "previous_peak_equity_usd": decimal_text(prev_peak),
                "new_peak_equity_usd": decimal_text(target),
                "reason": clean_reason,
                "observed_at": _iso_utc(now),
            }

    @property
    def submitted_oso_payloads(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(p) for p in self._submitted_oso_payloads)

    def list_orders(self) -> list[dict[str, Any]]:
        with self._lock:
            self._require_connected()
            return [
                {**dict(item), "accountId": item.get("accountId", self._account_id)}
                for item in self._order_history
            ]

    def list_orders_paginated(
        self,
        *,
        page_size: int = 100,
        max_pages: int = 50,
        since_utc: datetime | None = None,
    ) -> TradovateReconciliationEvidence:
        if type(page_size) is not int or page_size < 1:
            raise ContractError("page_size must be a positive int")
        if type(max_pages) is not int or max_pages < 1:
            raise ContractError("max_pages must be a positive int")
        if since_utc is not None:
            utc_time(since_utc, "since_utc")
        with self._lock:
            self._require_connected()
            now = self._clock()
            items = [
                {**dict(item), "accountId": item.get("accountId", self._account_id)}
                for item in self._order_history
            ]
            total_pages = max(1, (len(items) + page_size - 1) // page_size)
            if total_pages > max_pages:
                sliced = items[: max_pages * page_size]
                observed = frozenset(
                    str(x.get("clOrdId", "")).strip() for x in sliced if str(x.get("clOrdId", "")).strip()
                )
                return TradovateReconciliationEvidence(
                    account_id=self._account_id,
                    orders=tuple(sliced),
                    observed_cl_ord_ids=observed,
                    pages_fetched=max_pages,
                    complete=False,
                    provider_cursor_exhausted=False,
                    watermark_utc=now,
                    incompleteness_reasons=("pagination_max_pages_exceeded",),
                    authoritative_confirmation=False,
                    observed_at=now,
                )
            observed = frozenset(
                str(x.get("clOrdId", "")).strip() for x in items if str(x.get("clOrdId", "")).strip()
            )
            return TradovateReconciliationEvidence(
                account_id=self._account_id,
                orders=tuple(items),
                observed_cl_ord_ids=observed,
                pages_fetched=total_pages,
                complete=True,
                provider_cursor_exhausted=True,
                watermark_utc=now,
                incompleteness_reasons=(),
                authoritative_confirmation=True,
                observed_at=now,
            )

    def fetch_reconciliation_evidence(
        self,
        *,
        page_size: int = 100,
        max_pages: int = 50,
        since_utc: datetime | None = None,
    ) -> TradovateReconciliationEvidence:
        return self.list_orders_paginated(
            page_size=page_size,
            max_pages=max_pages,
            since_utc=since_utc,
        )

    def find_orders_by_cl_ord_id(self, cl_ord_id: str) -> list[dict[str, Any]]:
        if not isinstance(cl_ord_id, str) or not cl_ord_id.strip():
            raise ContractError("cl_ord_id must be a non-empty string")
        target = cl_ord_id.strip()
        with self._lock:
            self._require_connected()
            return [
                dict(item)
                for item in self._order_history
                if str(item.get("clOrdId", "")).strip() == target
            ]

    def place_protected_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
        if not isinstance(request, TradovateOrderRequest):
            raise ContractError("request must be TradovateOrderRequest")
        if request.action is not FuturesOrderAction.OPEN_BRACKET:
            raise TradovateOrderError(
                f"place_protected_order requires OPEN_BRACKET action, got {request.action.value}"
            )
        now = self._clock() if request.created_at is None else request.created_at
        root = translate_cas_symbol_to_micro_root(request.root_symbol or request.contract_code)
        cas_symbol = translate_micro_root_to_cas_symbol(root)
        spec = self._spec_for(root)
        if request.side not in ("BUY", "SELL"):
            raise TradovateOrderError("OPEN_BRACKET requires side 'BUY' or 'SELL'")
        if request.contracts <= 0:
            raise TradovateOrderError("OPEN_BRACKET requires contracts >= 1")
        with self._lock:
            self._require_connected()
            if request.entry_price is not None:
                fill_px = align_price_to_tick(root, request.entry_price)
            else:
                quote = self._quotes.get(root)
                if quote is None:
                    raise TradovateOrderError(
                        f"No quote seeded in paper emulator for {root!r}"
                    )
                fill_px = quote.ask if request.side == "BUY" else quote.bid

            sl_px = (
                align_price_to_tick(root, request.stop_loss_price)
                if request.stop_loss_price is not None
                else None
            )
            tp_px = (
                align_price_to_tick(root, request.take_profit_price)
                if request.take_profit_price is not None
                else None
            )
            if sl_px is None:
                raise TradovateOrderError("OPEN_BRACKET requires protective stop_loss_price")
            if request.side == "BUY":
                if sl_px >= fill_px:
                    raise TradovateOrderError(
                        f"BUY stop_loss_price ({sl_px}) must be strictly below entry ({fill_px})"
                    )
                if tp_px is not None and tp_px <= fill_px:
                    raise TradovateOrderError(
                        f"BUY take_profit_price ({tp_px}) must be strictly above entry ({fill_px})"
                    )
            else:
                if sl_px <= fill_px:
                    raise TradovateOrderError(
                        f"SELL stop_loss_price ({sl_px}) must be strictly above entry ({fill_px})"
                    )
                if tp_px is not None and tp_px >= fill_px:
                    raise TradovateOrderError(
                        f"SELL take_profit_price ({tp_px}) must be strictly below entry ({fill_px})"
                    )

            cl_ord_id = (request.cl_ord_id or "").strip() or _compute_stable_cl_ord_id(
                account_id=self._account_id,
                idempotency_key=request.request_id,
                contract_code=request.contract_code,
                action=request.action.value,
                side=request.side,
                contracts=request.contracts,
                stop_loss_price=sl_px,
                take_profit_price=tp_px,
            )
            if cl_ord_id in self._seen_cl_ord_ids:
                raise TradovateOrderError(
                    f"Duplicate clOrdId {cl_ord_id!r} rejected by paper emulator idempotency guard"
                )

            entry_action = "Buy" if request.side == "BUY" else "Sell"
            protective_action = "Sell" if request.side == "BUY" else "Buy"
            margin_req = _q2(self._margin_per_contract(spec) * Decimal(request.contracts))
            round_turn_comm = _q2(spec.default_round_turn_commission_usd * Decimal(request.contracts))
            pos_id = self._next_position_id()
            ord_id = self._next_order_id()
            sl_ord_id = self._next_order_id()
            tp_ord_id = self._next_order_id() if tp_px is not None else None

            bracket1_payload: dict[str, Any] = {
                "orderId": sl_ord_id,
                "action": protective_action,
                "orderType": "Stop",
                "orderQty": request.contracts,
                "stopPrice": sl_px,
                "timeInForce": "GTC",
                "isAutomated": True,
            }
            oso_payload: dict[str, Any] = {
                "clOrdId": cl_ord_id,
                "symbol": request.contract_code,
                "action": entry_action,
                "orderQty": request.contracts,
                "orderType": "Market",
                "isAutomated": True,
                "bracket1": dict(bracket1_payload),
            }
            bracket2_payload: dict[str, Any] | None = None
            if tp_px is not None and tp_ord_id is not None:
                bracket2_payload = {
                    "orderId": tp_ord_id,
                    "action": protective_action,
                    "orderType": "Limit",
                    "orderQty": request.contracts,
                    "price": tp_px,
                    "timeInForce": "GTC",
                    "isAutomated": True,
                }
                oso_payload["bracket2"] = dict(bracket2_payload)

            self._seen_cl_ord_ids.add(cl_ord_id)
            self._submitted_oso_payloads.append(oso_payload)
            history_entry: dict[str, Any] = {
                "accountId": self._account_id,
                "accountSpec": self._account_id,
                "orderId": ord_id,
                "oso1Id": sl_ord_id,
                "oso2Id": tp_ord_id,
                "clOrdId": cl_ord_id,
                "positionId": pos_id,
                "symbol": request.contract_code,
                "action": entry_action,
                "orderType": "Market",
                "orderQty": request.contracts,
                "filledQty": request.contracts,
                "fillPrice": decimal_text(fill_px),
                "ordStatus": "Filled",
                "bracket1": {
                    "orderId": sl_ord_id,
                    "action": protective_action,
                    "orderType": "Stop",
                    "orderQty": request.contracts,
                    "stopPrice": decimal_text(sl_px),
                    "ordStatus": "Working",
                },
                "executedAt": _iso_utc(now),
            }
            if bracket2_payload is not None:
                history_entry["bracket2"] = {
                    "orderId": tp_ord_id,
                    "action": protective_action,
                    "orderType": "Limit",
                    "orderQty": request.contracts,
                    "price": decimal_text(tp_px),
                    "ordStatus": "Working",
                }
            self._order_history.append(history_entry)

            self._positions[pos_id] = _MutablePaperPosition(
                position_id=pos_id,
                contract_code=request.contract_code,
                root_symbol=root,
                cas_symbol=cas_symbol,
                side=request.side,
                contracts=request.contracts,
                entry_price=fill_px,
                stop_loss_price=sl_px,
                take_profit_price=tp_px,
                used_margin_usd=margin_req,
                commission_usd=round_turn_comm,
                opened_at=now,
                updated_at=now,
                stop_loss_order_id=sl_ord_id,
                take_profit_order_id=tp_ord_id,
                cl_ord_id=cl_ord_id,
            )
            self._current_equity_unlocked()
            return TradovateOrderReceipt(
                request_id=request.request_id,
                cl_ord_id=cl_ord_id,
                action=FuturesOrderAction.OPEN_BRACKET,
                accepted=True,
                status="FILLED",
                order_id=ord_id,
                stop_loss_order_id=sl_ord_id,
                take_profit_order_id=tp_ord_id,
                protection_confirmed=True,
                position_id=pos_id,
                contract_code=request.contract_code,
                root_symbol=root,
                cas_symbol=cas_symbol,
                side=request.side,
                filled_contracts=request.contracts,
                fill_price=fill_px,
                stop_loss_price=sl_px,
                take_profit_price=tp_px,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason="PAPER_BRACKET_FILLED",
                executed_at=now,
            )

    def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
        if not isinstance(request, TradovateOrderRequest):
            raise ContractError("request must be TradovateOrderRequest")
        now = self._clock() if request.created_at is None else request.created_at

        if request.action is FuturesOrderAction.OPEN_BRACKET:
            return self.place_protected_order(request)

        if request.action is FuturesOrderAction.AMEND_STOP:
            if not request.position_id or request.stop_loss_price is None:
                raise TradovateOrderError("AMEND_STOP requires position_id and stop_loss_price")
            return self.amend_stop(
                request.position_id,
                request.stop_loss_price,
                request_id=request.request_id,
                cl_ord_id=request.cl_ord_id,
                now_utc=now,
            )

        if request.action is FuturesOrderAction.CLOSE_POSITION:
            if not request.position_id:
                raise TradovateOrderError("CLOSE_POSITION requires position_id")
            return self.close_position(
                request.position_id,
                reason=request.client_tag or "CLOSE_POSITION",
                request_id=request.request_id,
                cl_ord_id=request.cl_ord_id,
                now_utc=now,
            )

        if request.action is FuturesOrderAction.CANCEL_ORDER:
            with self._lock:
                self._require_connected()
                return TradovateOrderReceipt(
                    request_id=request.request_id,
                    action=FuturesOrderAction.CANCEL_ORDER,
                    accepted=True,
                    status="CANCELLED",
                    order_id=request.order_id or self._next_order_id(),
                    position_id=request.position_id,
                    contract_code=request.contract_code,
                    root_symbol=request.root_symbol,
                    cas_symbol=request.cas_symbol,
                    side=request.side,
                    filled_contracts=0,
                    fill_price=None,
                    stop_loss_price=None,
                    take_profit_price=None,
                    commission_usd=Decimal("0.00"),
                    realized_pnl_usd=Decimal("0.00"),
                    net_pnl_usd=Decimal("0.00"),
                    reason="ORDER_CANCELLED",
                    executed_at=now,
                )

        if request.action is FuturesOrderAction.EMERGENCY_CLOSE_ALL:
            closed = self.emergency_close_all(
                reason=request.client_tag or "EMERGENCY_CLOSE_ALL",
                request_id=request.request_id,
                now_utc=now,
            )
            gross_sum = _q2(sum((r.realized_pnl_usd for r in closed), Decimal("0.00")))
            comm_sum = _q2(sum((r.commission_usd for r in closed), Decimal("0.00")))
            net_sum = _q2(sum((r.net_pnl_usd for r in closed), Decimal("0.00")))
            qty_sum = sum(r.filled_contracts for r in closed)
            return TradovateOrderReceipt(
                request_id=request.request_id,
                action=FuturesOrderAction.EMERGENCY_CLOSE_ALL,
                accepted=True,
                status="EMERGENCY_CLOSED",
                order_id=self._next_order_id(),
                position_id=None,
                contract_code="",
                root_symbol="",
                cas_symbol="",
                side=None,
                filled_contracts=qty_sum,
                fill_price=None,
                stop_loss_price=None,
                take_profit_price=None,
                commission_usd=comm_sum,
                realized_pnl_usd=gross_sum,
                net_pnl_usd=net_sum,
                reason=f"EMERGENCY_CLOSED_{len(closed)}_POSITIONS",
                executed_at=now,
            )

        raise TradovateOrderError(f"Unsupported FuturesOrderAction: {request.action!r}")


# ---------------------------------------------------------------------------
# 4. Production TradovateMicroFuturesVenue (Standby-by-Default, Real Valve, WAL)
# ---------------------------------------------------------------------------


def _build_futures_valve_proposal(
    *,
    request_id: str,
    account_id: str,
    root_symbol: str,
    contract_code: str,
    side: str,
    contracts: int,
    entry_price: Decimal,
    stop_loss_price: Decimal,
    take_profit_price: Decimal | None,
    quote: TradovateQuote,
    account: TradovateAccountSnapshot,
    positions_count: int,
    reason: str,
    now: datetime,
    seq: int,
    max_quote_age_seconds: Decimal = DEFAULT_MAX_QUOTE_AGE_SECONDS,
) -> DecisionProposal:
    """Build a genuine typed DecisionProposal preserving original quote.observed_at."""
    quote_observed_at = _parse_quote_observed_at(
        getattr(quote, "observed_at", None),
        symbol_label=root_symbol,
    )
    age_limit_us = int(max_quote_age_seconds * Decimal(1_000_000))
    state_valid_until = quote_observed_at + timedelta(microseconds=age_limit_us + 1)
    if now < quote_observed_at or now >= state_valid_until:
        intent_created_at = quote_observed_at
    else:
        intent_created_at = now
    intent_expires_at = state_valid_until

    scope = RunScope(
        account_id=account_id,
        run_id=f"tradovate-futures-{request_id}",
        epoch=1,
        build_id="option-b-micro-futures-v1",
        policy_id="cas-forex-tradovate-micro-futures-v1",
        scenario_id=f"tradovate-{account.mode.lower()}",
        adapter_id="tradovate-micro-futures-venue",
    )
    state = StateReference(
        state_id=f"state-{request_id}",
        scope=scope,
        version=max(1, seq),
        observed_at=quote_observed_at,
        valid_until=state_valid_until,
        venue_sequence=max(1, seq),
    )
    obs_obj = {
        "symbol": root_symbol,
        "contract_code": contract_code,
        "bid": decimal_text(quote.bid),
        "ask": decimal_text(quote.ask),
        "quote_observed_at": _iso_utc(quote_observed_at),
        "balance": decimal_text(account.balance_usd),
        "equity": decimal_text(account.equity_usd),
        "available_margin": decimal_text(account.available_margin_usd),
        "position_count": positions_count,
        "new_risk": True,
        "management": True,
    }
    obs_json = json.dumps(obs_obj, sort_keys=True, separators=(",", ":"))
    ev_id = f"ev-{request_id}"
    evidence = EvidenceReference(
        evidence_id=ev_id,
        kind=EvidenceKind.OBSERVATION,
        producer_id="tradovate-micro-futures-venue",
        content_sha256=sha256(obs_json.encode("utf-8")).hexdigest(),
        observed_at=quote_observed_at,
    )
    fact = DecisionFact(
        fact_id=f"observed-{request_id}",
        label="tradovate_market_and_account_snapshot",
        value=obs_json,
        evidence_ids=(ev_id,),
    )
    intent = ActionIntent(
        intent_id=f"intent-{request_id}",
        scope=scope,
        decision_id=f"dec-{request_id}",
        opportunity_id=f"opp-{request_id}",
        action_ref=f"ref-{request_id}",
        source_state=state,
        kind=ActionKind.OPEN,
        instrument_id=root_symbol,
        origin=DecisionOrigin.POLICY,
        created_at=intent_created_at,
        expires_at=intent_expires_at,
        quantity=Decimal(contracts),
        side=Side.BUY if side == "BUY" else Side.SELL,
        limit_price=entry_price,
        stop_price=stop_loss_price,
        take_profit_price=take_profit_price,
    )
    option = ActionOption(
        action_ref=intent.action_ref,
        strategy_id="tradovate-micro-futures-bracket",
        timeframe="M1",
        label=f"Open {contract_code} {side} {contracts} contract(s)",
        intent=intent,
    )
    request = DecisionRequest(
        request_id=request_id,
        opportunity_set_id=f"opp-{request_id}",
        state=state,
        options=(option,),
        facts=(fact,),
        evidence=(evidence,),
    )
    selection = DecisionSelection(
        request.request_id,
        request.opportunity_set_id,
        state.state_id,
        intent.action_ref,
        reason,
        (ev_id,),
    )
    prov_ts = now if now >= quote_observed_at else quote_observed_at
    provenance = DecisionProvenance(
        DecisionOrigin.POLICY,
        "tradovate-micro-futures-venue",
        content_digest(request),
        content_digest(selection),
        "tradovate-venue-v1",
        prov_ts,
        prov_ts,
    )
    result = DecisionResult(
        decision_id=intent.decision_id,
        selection=selection,
        provenance=provenance,
    )
    return DecisionProposal(request=request, result=result, intent=intent)


class TradovateMicroFuturesVenue:
    """Standby-by-default US-regulated Tradovate micro-futures venue wrapper.

    - Defaults to ``enabled=False`` (``STANDBY_READY``) so existing FX/CFD
      brokers remain completely untouched until explicitly activated.
    - Enforces mandatory real ``ForexMetaValveGate`` (161 params, ``0.55``
      cutoff), exact CME tick alignment, front-month roll validation,
      ``<= 1.00%`` per-trade risk, ``<= 10.00%`` drawdown brake, and
      ``>= 1,000.0%`` margin level floor on every ``place_bracket_order()``.
    - ALWAYS permits protective actions (``amend_stop``, ``close_position``,
      ``emergency_close_all``) regardless of standby, drawdown lock, or valve
      entry refusal.
    - Persists a SQLite WAL mutation journal and tamper-evident SHA-256 hash-
      chained audit log, with strictly zero-write ``?mode=ro`` ``snapshot()``
      and ``verify_audit_chain()``.
    """

    def __init__(
        self,
        *,
        db_path: Path | str,
        credentials: TradovateCredentials | None = None,
        transport: TradovateTransport | None = None,
        valve_gate: ForexMetaValveGate | Any | None = None,
        enabled: bool | None = None,
        mode: str | None = None,
        base_url: str | None = None,
        account_id: str | None = None,
        live_arming_verified: bool = False,
        live_auth_context: LiveAuthorizationContext | None = None,
        live_arm_phrase: str | None = None,
        max_drawdown_pct: Decimal = MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
        min_margin_level_pct: Decimal = DEFAULT_MIN_MARGIN_LEVEL_PCT,
        max_quote_age_seconds: Decimal | int | float | str = DEFAULT_MAX_QUOTE_AGE_SECONDS,
        max_quote_future_skew_seconds: Decimal | int | float | str = DEFAULT_MAX_QUOTE_FUTURE_SKEW_SECONDS,
        roll_buffer_days: int = 7,
        use_exchange_margin: bool = False,
        demo_high_growth: DemoHighGrowthProfile | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(roll_buffer_days) is not int or roll_buffer_days < 0:
            raise ContractError("roll_buffer_days must be a non-negative integer")
        if enabled is not None and type(enabled) is not bool:
            raise ContractError("enabled must be a strict bool or None")
        if type(live_arming_verified) is not bool:
            raise TradovateLiveLockError("live_arming_verified must be a strict bool")
        if demo_high_growth is not None and not isinstance(demo_high_growth, DemoHighGrowthProfile):
            raise ContractError("demo_high_growth must be a DemoHighGrowthProfile or None")
        dd_cap = validate_constitutional_drawdown_pct(
            max_drawdown_pct,
            field="max_drawdown_pct",
            allow_none=False,
        )
        if dd_cap is None:
            raise ContractError("max_drawdown_pct cannot be None")
        margin_floor = _exact_decimal(min_margin_level_pct, "min_margin_level_pct", positive=True)
        if margin_floor < DEFAULT_MIN_MARGIN_LEVEL_PCT:
            raise ContractError(
                f"min_margin_level_pct ({margin_floor}%) cannot be below constitutional floor "
                f"{DEFAULT_MIN_MARGIN_LEVEL_PCT}%"
            )
        max_q_age = _parse_seconds_decimal(max_quote_age_seconds, "max_quote_age_seconds")
        max_q_skew = _parse_seconds_decimal(
            max_quote_future_skew_seconds, "max_quote_future_skew_seconds", allow_zero=True
        )
        eff_clock = clock if clock is not None else _utc_now

        if credentials is not None:
            if not isinstance(credentials, TradovateCredentials):
                raise ContractError("credentials must be TradovateCredentials")
            eff_enabled = credentials.enabled if enabled is None else enabled
            eff_mode = _normalize_mode(mode) if mode is not None else credentials.mode
            eff_account_id = (
                account_id.strip()
                if isinstance(account_id, str) and account_id.strip()
                else credentials.account_id
            )
            eff_live_ctx = (
                live_auth_context if live_auth_context is not None else credentials.live_auth_context
            )
            eff_live_phrase = (
                live_arm_phrase if live_arm_phrase is not None else credentials.live_arm_phrase
            )
            eff_base_url = (
                base_url
                if base_url is not None
                else (
                    TRADOVATE_LIVE_BASE_URL
                    if (mode is not None and eff_mode == TRADOVATE_MODE_LIVE)
                    else (
                        TRADOVATE_DEMO_BASE_URL
                        if (mode is not None and eff_mode == TRADOVATE_MODE_DEMO)
                        else credentials.base_url
                    )
                )
            )
            eff_creds = TradovateCredentials(
                enabled=eff_enabled,
                mode=eff_mode,
                base_url=eff_base_url,
                live_arming_verified=live_arming_verified,
                account_id=eff_account_id,
                live_auth_context=eff_live_ctx,
                live_arm_phrase=eff_live_phrase,
                auth_checked_at=eff_clock() if eff_mode == TRADOVATE_MODE_LIVE else None,
                username=credentials.username,
                password=credentials.password,
                app_id=credentials.app_id,
                cid=credentials.cid,
                sec=credentials.sec,
                bearer_token=credentials.bearer_token,
            )
        else:
            eff_enabled = False if enabled is None else enabled
            eff_mode = _normalize_mode(mode) if mode is not None else TRADOVATE_MODE_DEMO
            default_url = (
                TRADOVATE_LIVE_BASE_URL if eff_mode == TRADOVATE_MODE_LIVE else TRADOVATE_DEMO_BASE_URL
            )
            eff_base_url = base_url if base_url is not None else default_url
            eff_account_id = account_id.strip() if isinstance(account_id, str) else ""
            eff_creds = TradovateCredentials(
                enabled=eff_enabled,
                mode=eff_mode,
                base_url=eff_base_url,
                live_arming_verified=live_arming_verified,
                account_id=eff_account_id,
                live_auth_context=live_auth_context,
                live_arm_phrase=live_arm_phrase,
                auth_checked_at=eff_clock() if eff_mode == TRADOVATE_MODE_LIVE else None,
            )

        self._db_path = Path(db_path)
        self._credentials = eff_creds
        self._enabled = eff_creds.enabled
        self._mode = eff_creds.mode
        self._base_url = eff_creds.base_url
        self._account_id = eff_creds.account_id
        self._live_auth_context: LiveAuthorizationContext | None = eff_creds.live_auth_context
        self._live_arm_phrase: str | None = eff_creds.live_arm_phrase
        self._valve_gate = valve_gate
        self._base_max_drawdown_pct = dd_cap
        self._demo_high_growth: DemoHighGrowthProfile = (
            demo_high_growth if demo_high_growth is not None else DemoHighGrowthProfile(enabled=False)
        )
        self._demo_high_growth.assert_demo_mode(
            eff_creds.mode,
            live_trading_armed=(eff_creds.mode == TRADOVATE_MODE_LIVE or eff_creds.live_arming_verified),
            live_trading_locked=(eff_creds.mode == TRADOVATE_MODE_DEMO),
        )
        self._max_drawdown_pct = (
            self._demo_high_growth.max_drawdown_pct
            if self._demo_high_growth.enabled
            else self._base_max_drawdown_pct
        )
        self._min_margin_level_pct = margin_floor
        self._max_quote_age_seconds = max_q_age
        self._max_quote_future_skew_seconds = max_q_skew
        self._roll_buffer_days = roll_buffer_days
        self._use_exchange_margin = bool(use_exchange_margin)
        self._clock = eff_clock
        self._lock = RLock()
        self._req_seq = 0

        if transport is not None:
            if not isinstance(transport, TradovateTransport):
                raise ContractError("transport must implement TradovateTransport protocol")
            self._transport: TradovateTransport = transport
        elif self._mode == TRADOVATE_MODE_DEMO:
            self._transport = TradovateMicroFuturesPaperEmulator(
                mode=TRADOVATE_MODE_DEMO,
                clock=self._clock,
                use_exchange_margin=self._use_exchange_margin,
                connected=True,
            )
        else:
            self._transport = TradovateHttpsTransport(
                credentials=self._credentials,
                clock=self._clock,
            )

        if not self._account_id and isinstance(
            self._transport, (TradovateMicroFuturesPaperEmulator, TradovateHttpsTransport)
        ):
            self._account_id = self._transport.account_id
        elif (
            self._account_id
            and isinstance(self._transport, (TradovateMicroFuturesPaperEmulator, TradovateHttpsTransport))
            and self._transport.account_id
            and self._account_id != self._transport.account_id
        ):
            raise TradovateTransportError(
                f"Transport account_id ({self._transport.account_id!r}) mismatches "
                f"authorized account_id ({self._account_id!r})",
                ambiguous=False,
            )

        self._init_schema()

    def __repr__(self) -> str:
        return (
            f"TradovateMicroFuturesVenue(status={self.venue_status!r}, "
            f"mode={self._mode!r}, base_url={self._base_url!r}, "
            f"enabled={self._enabled!r})"
        )

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def transport(self) -> TradovateTransport:
        return self._transport

    @property
    def valve_gate(self) -> ForexMetaValveGate | Any | None:
        return self._valve_gate

    def set_demo_high_growth_profile(self, profile: DemoHighGrowthProfile) -> None:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise ContractError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            self._mode,
            live_trading_armed=(self._mode == TRADOVATE_MODE_LIVE or self._credentials.live_arming_verified),
            live_trading_locked=(self._mode == TRADOVATE_MODE_DEMO),
        )
        with self._lock:
            self._demo_high_growth = profile
            self._max_drawdown_pct = (
                profile.max_drawdown_pct if profile.enabled else self._base_max_drawdown_pct
            )

    @property
    def venue_status(self) -> str:
        if not self._enabled:
            return VENUE_STATUS_STANDBY
        return (
            VENUE_STATUS_LIVE_ACTIVE
            if self._mode == TRADOVATE_MODE_LIVE
            else VENUE_STATUS_DEMO_ACTIVE
        )

    # -- SQLite connections (RW for mutations, strict ?mode=ro for snapshots) --

    def _authorized_account_id(self) -> str:
        acct = (self._account_id or "").strip()
        if not acct:
            if isinstance(self._transport, TradovateMicroFuturesPaperEmulator):
                acct = self._transport.account_id
            else:
                t_acct = getattr(self._transport, "account_id", None)
                if isinstance(t_acct, str) and t_acct.strip():
                    acct = t_acct.strip()
        if not acct:
            if self._mode == TRADOVATE_MODE_LIVE:
                raise TradovateLiveLockError(
                    "LIVE TradovateMicroFuturesVenue requires non-empty authorized account_id"
                )
            raise TradovateTransportError(
                "TradovateMicroFuturesVenue requires non-empty authorized account_id",
                ambiguous=False,
            )
        if any(ch.isspace() or ord(ch) < 32 for ch in acct):
            raise TradovateEndpointError("Tradovate account_id contains whitespace or control characters")
        if self._mode == TRADOVATE_MODE_LIVE:
            ctx = self._live_auth_context
            if not isinstance(ctx, LiveAuthorizationContext) or ctx.account_id.strip() != acct:
                raise TradovateLiveLockError(
                    "LIVE TradovateMicroFuturesVenue account_id mismatches LiveAuthorizationContext"
                )
        if isinstance(self._transport, TradovateMicroFuturesPaperEmulator) and self._transport.account_id != acct:
            raise TradovateTransportError(
                f"Paper emulator account_id ({self._transport.account_id!r}) mismatches authorized account_id ({acct!r})",
                ambiguous=False,
            )
        if isinstance(self._transport, TradovateHttpsTransport):
            t_https_acct = self._transport._authorized_account_id()
            if t_https_acct != acct:
                raise TradovateTransportError(
                    f"HTTPS transport account_id ({t_https_acct!r}) mismatches authorized account_id ({acct!r})",
                    ambiguous=False,
                )
        return acct

    @staticmethod
    def _validate_account_snapshot(
        acct: TradovateAccountSnapshot,
        *,
        expected_account_id: str,
    ) -> TradovateAccountSnapshot:
        if not isinstance(acct, TradovateAccountSnapshot):
            raise TradovateTransportError(
                "Transport returned non-TradovateAccountSnapshot object",
                ambiguous=False,
            )
        got = (acct.account_id or "").strip()
        if not got:
            raise TradovateTransportError(
                "Tradovate account_snapshot missing required account_id",
                ambiguous=False,
            )
        if got != expected_account_id:
            raise TradovateTransportError(
                f"Tradovate account_snapshot account_id mismatch: "
                f"expected {expected_account_id!r}, got {got!r}",
                ambiguous=False,
            )
        return acct

    @staticmethod
    def _validate_positions_ownership(
        positions: tuple[TradovatePosition, ...],
        *,
        expected_account_id: str,
    ) -> tuple[TradovatePosition, ...]:
        for pos in positions:
            if not isinstance(pos, TradovatePosition):
                raise TradovateTransportError(
                    "Transport returned non-TradovatePosition object",
                    ambiguous=False,
                )
            got = pos.account_id.strip() if isinstance(pos.account_id, str) else ""
            if not got:
                raise TradovateTransportError(
                    f"Tradovate position {pos.position_id!r} missing required account_id",
                    ambiguous=False,
                )
            if got != expected_account_id:
                raise TradovateTransportError(
                    f"Tradovate position {pos.position_id!r} account_id mismatch: "
                    f"expected {expected_account_id!r}, got {got!r}",
                    ambiguous=False,
                )
        return positions

    def _connect_rw(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _connect_ro(self) -> sqlite3.Connection:
        resolved = self._db_path.resolve()
        if not resolved.exists():
            raise TradovateVenueError(f"Tradovate venue database does not exist: {resolved}")
        uri = f"{resolved.as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        return conn

    @staticmethod
    def _compute_audit_sha256(
        *,
        prev_sha256: str,
        event_type: str,
        entity_id: str,
        payload_bytes: bytes,
        occurred_at: str,
    ) -> str:
        h = sha256()
        h.update(prev_sha256.encode("utf-8"))
        h.update(b"\x1f")
        h.update(event_type.encode("utf-8"))
        h.update(b"\x1f")
        h.update(entity_id.encode("utf-8"))
        h.update(b"\x1f")
        h.update(occurred_at.encode("utf-8"))
        h.update(b"\x1f")
        h.update(payload_bytes)
        return h.hexdigest()

    def _append_audit_unlocked(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        entity_id: str,
        payload: Mapping[str, Any],
        occurred_at: datetime,
    ) -> str:
        row = conn.execute(
            "SELECT entry_sha256 FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_sha = str(row["entry_sha256"]) if row is not None else GENESIS_AUDIT_SHA256
        payload_bytes = canonical_bytes(dict(payload))
        payload_json = payload_bytes.decode("utf-8")
        ts_str = _iso_utc(occurred_at)
        entry_sha = self._compute_audit_sha256(
            prev_sha256=prev_sha,
            event_type=event_type,
            entity_id=entity_id,
            payload_bytes=payload_bytes,
            occurred_at=ts_str,
        )
        conn.execute(
            "INSERT INTO audit_events "
            "(event_type, entity_id, payload_json, occurred_at, prev_sha256, entry_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event_type, entity_id, payload_json, ts_str, prev_sha, entry_sha),
        )
        return entry_sha

    def _init_schema(self) -> None:
        now = self._clock()
        ts_str = _iso_utc(now)
        initial_peak = Decimal("0.00")
        if self._transport.is_connected():
            try:
                auth_acct = self._authorized_account_id()
                snap = self._validate_account_snapshot(
                    self._transport.account_snapshot(now_utc=now),
                    expected_account_id=auth_acct,
                )
                initial_peak = snap.peak_equity_usd
            except TradovateVenueError:
                initial_peak = Decimal("0.00")

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS venue_meta (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        broker_id TEXT NOT NULL,
                        regulated_jurisdiction TEXT NOT NULL,
                        enabled INTEGER NOT NULL,
                        mode TEXT NOT NULL,
                        base_url TEXT NOT NULL,
                        peak_equity_usd TEXT NOT NULL,
                        max_drawdown_pct TEXT NOT NULL,
                        min_margin_level_pct TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mutation_journal (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id TEXT NOT NULL UNIQUE,
                        cl_ord_id TEXT,
                        action TEXT NOT NULL,
                        contract_code TEXT NOT NULL,
                        root_symbol TEXT NOT NULL,
                        cas_symbol TEXT NOT NULL,
                        status TEXT NOT NULL,
                        request_json TEXT NOT NULL,
                        receipt_json TEXT,
                        error_detail TEXT,
                        reconciled_at TEXT,
                        reconciliation_json TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                existing_cols = {
                    str(r["name"]) for r in conn.execute("PRAGMA table_info(mutation_journal)").fetchall()
                }
                for col_name, col_type in (
                    ("cl_ord_id", "TEXT"),
                    ("error_detail", "TEXT"),
                    ("reconciled_at", "TEXT"),
                    ("reconciliation_json", "TEXT"),
                ):
                    if col_name not in existing_cols:
                        conn.execute(f"ALTER TABLE mutation_journal ADD COLUMN {col_name} {col_type}")
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_mutation_journal_cl_ord_id "
                    "ON mutation_journal(cl_ord_id) WHERE cl_ord_id IS NOT NULL"
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS venue_freeze_latches (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        latch_kind TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        cl_ord_id TEXT,
                        detail TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        cleared_at TEXT,
                        reconciliation_json TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        prev_sha256 TEXT NOT NULL,
                        entry_sha256 TEXT NOT NULL
                    )
                    """
                )
                leftover_pending = conn.execute(
                    "SELECT request_id, cl_ord_id FROM mutation_journal WHERE status = ?",
                    (MUTATION_STATUS_PENDING,),
                ).fetchall()
                for pending_row in leftover_pending:
                    p_req_id = str(pending_row["request_id"])
                    p_cl_id = pending_row["cl_ord_id"]
                    conn.execute(
                        "UPDATE mutation_journal SET status = ?, error_detail = ?, updated_at = ? "
                        "WHERE request_id = ?",
                        (
                            MUTATION_STATUS_OUTCOME_UNKNOWN,
                            "CRASH_RECOVERY_PENDING_PROMOTED_TO_OUTCOME_UNKNOWN",
                            ts_str,
                            p_req_id,
                        ),
                    )
                    conn.execute(
                        "INSERT INTO venue_freeze_latches "
                        "(latch_kind, request_id, cl_ord_id, detail, created_at, cleared_at, reconciliation_json) "
                        "VALUES (?, ?, ?, ?, ?, NULL, NULL)",
                        (
                            MUTATION_STATUS_OUTCOME_UNKNOWN,
                            p_req_id,
                            p_cl_id,
                            "Crash recovery promoted unresolved PENDING mutation to OUTCOME_UNKNOWN",
                            ts_str,
                        ),
                    )
                    self._append_audit_unlocked(
                        conn,
                        event_type="ORDER_OUTCOME_UNKNOWN_RECOVERY",
                        entity_id=p_req_id,
                        payload={
                            "request_id": p_req_id,
                            "cl_ord_id": p_cl_id,
                            "status": MUTATION_STATUS_OUTCOME_UNKNOWN,
                        },
                        occurred_at=now,
                    )
                existing = conn.execute("SELECT id, peak_equity_usd FROM venue_meta WHERE id = 1").fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO venue_meta "
                        "(id, broker_id, regulated_jurisdiction, enabled, mode, base_url, "
                        "peak_equity_usd, max_drawdown_pct, min_margin_level_pct, created_at, updated_at) "
                        "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            TRADOVATE_BROKER_ID,
                            TRADOVATE_REGULATED_JURISDICTION,
                            1 if self._enabled else 0,
                            self._mode,
                            self._base_url,
                            decimal_text(_q2(initial_peak)),
                            decimal_text(self._max_drawdown_pct),
                            decimal_text(self._min_margin_level_pct),
                            ts_str,
                            ts_str,
                        ),
                    )
                    self._append_audit_unlocked(
                        conn,
                        event_type="VENUE_INITIALIZED",
                        entity_id=TRADOVATE_BROKER_ID,
                        payload={
                            "status": self.venue_status,
                            "enabled": self._enabled,
                            "mode": self._mode,
                            "base_url": self._base_url,
                            "peak_equity_usd": decimal_text(_q2(initial_peak)),
                        },
                        occurred_at=now,
                    )
                else:
                    existing_peak = _exact_decimal(
                        str(existing["peak_equity_usd"]), "peak_equity_usd", non_negative=True
                    )
                    new_peak = max(existing_peak, initial_peak)
                    conn.execute(
                        "UPDATE venue_meta SET enabled = ?, mode = ?, base_url = ?, "
                        "peak_equity_usd = ?, updated_at = ? WHERE id = 1",
                        (
                            1 if self._enabled else 0,
                            self._mode,
                            self._base_url,
                            decimal_text(_q2(new_peak)),
                            ts_str,
                        ),
                    )
                seq_row = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM mutation_journal"
                ).fetchone()
                if seq_row is not None:
                    self._req_seq = max(self._req_seq, int(seq_row["max_seq"]))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _next_request_id(self, prefix: str) -> str:
        self._req_seq += 1
        return f"tv-{prefix}-{self._req_seq:06d}"

    def _record_audit_event(
        self,
        *,
        event_type: str,
        entity_id: str,
        payload: Mapping[str, Any],
        now: datetime,
    ) -> str:
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                entry_sha = self._append_audit_unlocked(
                    conn,
                    event_type=event_type,
                    entity_id=entity_id,
                    payload=payload,
                    occurred_at=now,
                )
                conn.execute("COMMIT")
                return entry_sha
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _update_peak_equity_unlocked(
        self,
        conn: sqlite3.Connection,
        candidate_peak: Decimal,
        now: datetime,
    ) -> Decimal:
        row = conn.execute("SELECT peak_equity_usd FROM venue_meta WHERE id = 1").fetchone()
        stored = (
            _exact_decimal(str(row["peak_equity_usd"]), "peak_equity_usd", non_negative=True)
            if row is not None
            else Decimal("0.00")
        )
        effective_peak = _q2(max(stored, candidate_peak))
        if effective_peak > stored:
            conn.execute(
                "UPDATE venue_meta SET peak_equity_usd = ?, updated_at = ? WHERE id = 1",
                (decimal_text(effective_peak), _iso_utc(now)),
            )
        return effective_peak

    # -- Activation / Standby lifecycle --

    def activate(
        self,
        *,
        mode: str | None = None,
        base_url: str | None = None,
        account_id: str | None = None,
        live_arming_verified: bool | None = None,
        live_auth_context: LiveAuthorizationContext | None = None,
        live_arm_phrase: str | None = None,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Activate venue from STANDBY_READY into DEMO_ACTIVE or LIVE_ACTIVE."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        if live_arming_verified is not None and type(live_arming_verified) is not bool:
            raise TradovateLiveLockError("live_arming_verified must be a strict bool or None")
        with self._lock:
            target_mode = _normalize_mode(mode) if mode is not None else self._mode
            target_account_id = (
                account_id.strip()
                if isinstance(account_id, str) and account_id.strip()
                else self._account_id
            )
            target_live_ctx = (
                live_auth_context if live_auth_context is not None else self._live_auth_context
            )
            target_live_phrase = (
                live_arm_phrase if live_arm_phrase is not None else self._live_arm_phrase
            )
            default_url = (
                TRADOVATE_LIVE_BASE_URL
                if target_mode == TRADOVATE_MODE_LIVE
                else TRADOVATE_DEMO_BASE_URL
            )
            target_url = base_url if base_url is not None else default_url
            canonical_url = validate_tradovate_endpoint(
                target_mode,
                target_url,
                live_arming_verified=bool(live_arming_verified) if live_arming_verified is not None else False,
                live_auth_context=target_live_ctx if target_mode == TRADOVATE_MODE_LIVE else None,
                live_arm_phrase=target_live_phrase if target_mode == TRADOVATE_MODE_LIVE else None,
                account_id=target_account_id if target_mode == TRADOVATE_MODE_LIVE else None,
                now_utc=now,
            )
            target_status = (
                VENUE_STATUS_LIVE_ACTIVE
                if target_mode == TRADOVATE_MODE_LIVE
                else VENUE_STATUS_DEMO_ACTIVE
            )

            if not self._transport.is_connected():
                self._transport.connect()

            peak_candidate = Decimal("0.00")
            if self._transport.is_connected():
                expected_acct = target_account_id or self._authorized_account_id()
                acct = self._validate_account_snapshot(
                    self._transport.account_snapshot(now_utc=now),
                    expected_account_id=expected_acct,
                )
                peak_candidate = max(acct.peak_equity_usd, acct.equity_usd)

            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    eff_peak = self._update_peak_equity_unlocked(conn, peak_candidate, now)
                    conn.execute(
                        "UPDATE venue_meta SET enabled = 1, mode = ?, base_url = ?, updated_at = ? "
                        "WHERE id = 1",
                        (target_mode, canonical_url, _iso_utc(now)),
                    )
                    self._append_audit_unlocked(
                        conn,
                        event_type="VENUE_ACTIVATED",
                        entity_id=TRADOVATE_BROKER_ID,
                        payload={
                            "status": target_status,
                            "mode": target_mode,
                            "base_url": canonical_url,
                            "peak_equity_usd": decimal_text(eff_peak),
                        },
                        occurred_at=now,
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            self._mode = target_mode
            self._base_url = canonical_url
            self._account_id = target_account_id
            if target_mode == TRADOVATE_MODE_LIVE:
                self._live_auth_context = target_live_ctx
                self._live_arm_phrase = target_live_phrase
            self._enabled = True
        return self.snapshot(now_utc=now)

    def deactivate(
        self,
        *,
        reason: str = "OWNER_STANDBY",
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Return venue to STANDBY_READY (protective actions remain ALWAYS allowed)."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "UPDATE venue_meta SET enabled = 0, updated_at = ? WHERE id = 1",
                        (_iso_utc(now),),
                    )
                    self._append_audit_unlocked(
                        conn,
                        event_type="VENUE_DEACTIVATED",
                        entity_id=TRADOVATE_BROKER_ID,
                        payload={
                            "status": VENUE_STATUS_STANDBY,
                            "reason": str(reason),
                        },
                        occurred_at=now,
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
            self._enabled = False
        return self.snapshot(now_utc=now)

    # -- Mandatory Valve Evaluation --

    def _evaluate_mandatory_valve(
        self,
        *,
        request_id: str,
        root_symbol: str,
        contract_code: str,
        side: str,
        contracts: int,
        entry_price: Decimal,
        stop_loss_price: Decimal,
        take_profit_price: Decimal | None,
        quote: TradovateQuote,
        account: TradovateAccountSnapshot,
        open_positions: tuple[TradovatePosition, ...],
        peak_equity: Decimal,
        reason: str,
        policy_overrides: Mapping[str, Any] | None,
        now: datetime,
    ) -> ValveDecision:
        if self._valve_gate is None:
            self._record_audit_event(
                event_type="ORDER_REFUSED_VALVE_MISSING",
                entity_id=request_id,
                payload={
                    "root_symbol": root_symbol,
                    "contract_code": contract_code,
                    "reason": "ForexMetaValveGate is mandatory and cannot be None",
                },
                now=now,
            )
            raise TradovateValveRefusalError(
                "ForexMetaValveGate is mandatory on every Tradovate micro-futures entry "
                "and cannot be None (fail-closed)"
            )

        quote_observed_at = _parse_quote_observed_at(
            getattr(quote, "observed_at", None),
            symbol_label=root_symbol,
        )
        proposal = _build_futures_valve_proposal(
            request_id=request_id,
            account_id=account.account_id,
            root_symbol=root_symbol,
            contract_code=contract_code,
            side=side,
            contracts=contracts,
            entry_price=entry_price,
            stop_loss_price=stop_loss_price,
            take_profit_price=take_profit_price,
            quote=quote,
            account=account,
            positions_count=len(open_positions),
            reason=reason,
            now=now,
            seq=self._req_seq,
            max_quote_age_seconds=self._max_quote_age_seconds,
        )
        current_view: dict[str, Any] = {
            "account_id": account.account_id,
            "balance": decimal_text(account.balance_usd),
            "equity": decimal_text(account.equity_usd),
            "peak_equity": decimal_text(peak_equity),
            "available_margin": decimal_text(account.available_margin_usd),
            "position_inventory": [p.to_dict() for p in open_positions],
            "symbol": root_symbol,
            "bid": decimal_text(quote.bid),
            "ask": decimal_text(quote.ask),
            "quote_observed_at": _iso_utc(quote_observed_at),
        }
        eff_policy: dict[str, Any] = {
            "new_risk_permission": "ALLOWED",
            "management_permission": "ALLOWED",
            "max_entry_quantity": str(contracts),
            "max_drawdown_pct": decimal_text(self._max_drawdown_pct),
            "accounting_required": [
                "balance",
                "equity",
                "available_margin",
                "position_inventory",
            ],
        }
        if policy_overrides:
            eff_policy.update(policy_overrides)

        require_fn = getattr(self._valve_gate, "require_admissible", None)
        eval_fn = getattr(self._valve_gate, "evaluate", None)
        if not callable(require_fn) and not callable(eval_fn):
            raise TradovateValveRefusalError(
                "valve_gate must provide require_admissible(...) or evaluate(...)"
            )

        try:
            if callable(require_fn):
                decision = require_fn(
                    proposal,
                    current_view=current_view,
                    policy=eff_policy,
                    now=now,
                )
            else:
                decision = eval_fn(
                    proposal,
                    current_view=current_view,
                    policy=eff_policy,
                    now=now,
                )
        except ValveRefusalError as exc:
            self._record_audit_event(
                event_type="ORDER_REFUSED_VALVE",
                entity_id=request_id,
                payload={
                    "root_symbol": root_symbol,
                    "contract_code": contract_code,
                    "error": str(exc),
                    "valve_score": (
                        f"{exc.decision.mlp_score:.8f}" if exc.decision is not None else None
                    ),
                    "hard_veto_reasons": (
                        list(exc.decision.hard_veto_reasons) if exc.decision is not None else []
                    ),
                },
                now=now,
            )
            raise TradovateValveRefusalError(str(exc), decision=exc.decision) from None

        if not isinstance(decision, ValveDecision):
            raise TradovateValveRefusalError(
                "valve_gate returned non-ValveDecision object (fail-closed)"
            )
        if not math.isfinite(decision.mlp_score):
            raise TradovateValveRefusalError(
                "valve_gate returned non-finite mlp_score (fail-closed)",
                decision=decision,
            )
        score_dec = Decimal(f"{decision.mlp_score:.8f}")
        if (
            not decision.admitted
            or decision.hard_veto
            or score_dec < VALVE_ADMISSIBILITY_CUTOFF
        ):
            detail = (
                f"ForexMetaValveGate refused micro-futures entry ({decision.valve_mode}): "
                f"score={score_dec} cutoff={VALVE_ADMISSIBILITY_CUTOFF} "
                f"vetoes={list(decision.hard_veto_reasons)}"
            )
            self._record_audit_event(
                event_type="ORDER_REFUSED_VALVE",
                entity_id=request_id,
                payload={
                    "root_symbol": root_symbol,
                    "contract_code": contract_code,
                    "valve_mode": decision.valve_mode,
                    "valve_score": decimal_text(score_dec),
                    "cutoff": decimal_text(VALVE_ADMISSIBILITY_CUTOFF),
                    "hard_veto_reasons": list(decision.hard_veto_reasons),
                },
                now=now,
            )
            raise TradovateValveRefusalError(detail, decision=decision)

        return decision

    # -- Entry Execution (Full Constitutional + Valve + Sizing Wall) --

    def _query_unresolved_mutations_unlocked(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT request_id, cl_ord_id, action, contract_code, root_symbol, status, "
            "error_detail, created_at, updated_at FROM mutation_journal "
            "WHERE status IN (?, ?, ?) ORDER BY seq ASC",
            _UNRESOLVED_MUTATION_STATUSES,
        ).fetchall()
        return [
            {
                "request_id": str(r["request_id"]),
                "cl_ord_id": r["cl_ord_id"],
                "action": str(r["action"]),
                "contract_code": str(r["contract_code"]),
                "root_symbol": str(r["root_symbol"]),
                "status": str(r["status"]),
                "error_detail": r["error_detail"],
                "created_at": str(r["created_at"]),
                "updated_at": str(r["updated_at"]),
            }
            for r in rows
        ]

    def _query_active_latches_unlocked(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT seq, latch_kind, request_id, cl_ord_id, detail, created_at "
            "FROM venue_freeze_latches WHERE cleared_at IS NULL ORDER BY seq ASC"
        ).fetchall()
        return [
            {
                "seq": int(r["seq"]),
                "latch_kind": str(r["latch_kind"]),
                "request_id": str(r["request_id"]),
                "cl_ord_id": r["cl_ord_id"],
                "detail": str(r["detail"]),
                "created_at": str(r["created_at"]),
            }
            for r in rows
        ]

    def _enforce_no_unresolved_freeze_unlocked(
        self,
        conn: sqlite3.Connection,
        *,
        request_id: str,
        now: datetime,
    ) -> None:
        unresolved = self._query_unresolved_mutations_unlocked(conn)
        latches = self._query_active_latches_unlocked(conn)
        if not unresolved and not latches:
            return
        ids = ", ".join(
            f"{item['request_id']}({item['cl_ord_id'] or 'no-clOrdId'}:{item['status']})"
            for item in unresolved
        ) or ", ".join(f"{l['request_id']}({l['latch_kind']})" for l in latches)
        has_unknown = any(
            item["status"] in (MUTATION_STATUS_OUTCOME_UNKNOWN, MUTATION_STATUS_PENDING)
            for item in unresolved
        ) or any(l["latch_kind"] == MUTATION_STATUS_OUTCOME_UNKNOWN for l in latches)
        self._append_audit_unlocked(
            conn,
            event_type="ORDER_REFUSED_UNRESOLVED_FREEZE",
            entity_id=request_id,
            payload={
                "unresolved_mutations": unresolved,
                "active_latches": latches,
            },
            occurred_at=now,
        )
        conn.execute("COMMIT")
        if has_unknown:
            raise TradovateOutcomeUnknownError(
                f"TRADOVATE_OUTCOME_UNKNOWN_FREEZE: unresolved mutation(s) [{ids}] block all "
                "new opens/retries until reconcile_unknown_outcome() verifies broker history",
                request_id=request_id,
            )
        raise TradovateProtectionUnconfirmedError(
            f"TRADOVATE_PROTECTION_UNCONFIRMED_FREEZE: unresolved protection latch(es) [{ids}] "
            "block all new opens until reconciled",
            request_id=request_id,
        )

    def _record_unresolved_latch(
        self,
        *,
        request_id: str,
        cl_ord_id: str,
        status: str,
        event_type: str,
        detail: str,
        now: datetime,
        order_id: str | None = None,
    ) -> None:
        ts_str = _iso_utc(now)
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "UPDATE mutation_journal SET status = ?, error_detail = ?, updated_at = ? "
                    "WHERE request_id = ?",
                    (status, detail, ts_str, request_id),
                )
                conn.execute(
                    "INSERT INTO venue_freeze_latches "
                    "(latch_kind, request_id, cl_ord_id, detail, created_at, cleared_at, reconciliation_json) "
                    "VALUES (?, ?, ?, ?, ?, NULL, NULL)",
                    (status, request_id, cl_ord_id, detail, ts_str),
                )
                self._append_audit_unlocked(
                    conn,
                    event_type=event_type,
                    entity_id=request_id,
                    payload={
                        "request_id": request_id,
                        "cl_ord_id": cl_ord_id,
                        "order_id": order_id,
                        "status": status,
                        "detail": detail,
                    },
                    occurred_at=now,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def place_bracket_order(
        self,
        *,
        symbol: str,
        side: str | Side,
        stop_loss_price: Decimal | None = None,
        take_profit_price: Decimal | None = None,
        stop_distance_points: Decimal | None = None,
        take_profit_points: Decimal | None = None,
        entry_price: Decimal | None = None,
        risk_pct: Decimal = MAX_CONSTITUTIONAL_STOP_RISK_PCT,
        contracts: int | None = None,
        contract_code: str | None = None,
        idempotency_key: str | None = None,
        reason: str = "CAS_MICRO_FUTURES_ENTRY",
        policy_overrides: Mapping[str, Any] | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Open a tick-aligned, risk-sized, valve-cleared, broker-protected CME micro-futures bracket order."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        norm_side = _normalize_side(side)
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ContractError("idempotency_key must be a non-empty string when provided")
            _check_no_control_chars(idempotency_key, "idempotency_key")

        with self._lock:
            self._demo_high_growth.assert_demo_mode(
                self._mode,
                live_trading_armed=(self._mode == TRADOVATE_MODE_LIVE or self._credentials.live_arming_verified),
                live_trading_locked=(self._mode == TRADOVATE_MODE_DEMO),
            )
            request_id = self._next_request_id("open")

            # 1. Standby fail-closed gate
            if not self._enabled:
                self._record_audit_event(
                    event_type="ORDER_REFUSED_STANDBY",
                    entity_id=request_id,
                    payload={
                        "symbol": str(symbol),
                        "side": norm_side,
                        "status": VENUE_STATUS_STANDBY,
                    },
                    now=now,
                )
                raise TradovateStandbyError(
                    "TradovateMicroFuturesVenue is in STANDBY_READY mode; "
                    "explicitly activate() before placing new micro-futures entries"
                )

            # 1b. Durable unresolved OUTCOME_UNKNOWN / PROTECTION_UNCONFIRMED freeze latch gate
            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    self._enforce_no_unresolved_freeze_unlocked(
                        conn, request_id=request_id, now=now
                    )
                    conn.execute("COMMIT")
                except (TradovateOutcomeUnknownError, TradovateProtectionUnconfirmedError):
                    raise
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            # 2. Transport connection gate
            if not self._transport.is_connected():
                raise TradovateTransportError(
                    "Tradovate transport is disconnected; cannot place new bracket order"
                )

            # 3. CAS -> CME micro root translation & front-month roll validation
            root = translate_cas_symbol_to_micro_root(symbol)
            cas_symbol = translate_micro_root_to_cas_symbol(root)
            if contract_code is not None:
                front_month: FrontMonthContract = validate_contract_not_expired(
                    contract_code,
                    as_of_utc=now,
                    roll_buffer_days=self._roll_buffer_days,
                )
                if front_month.root != root:
                    raise UnsupportedMicroFuturesSymbolError(
                        f"Contract {contract_code!r} resolves to {front_month.root!r}, "
                        f"which does not match requested symbol root {root!r}"
                    )
            else:
                front_month = resolve_front_month_contract(
                    root,
                    as_of_utc=now,
                    roll_buffer_days=self._roll_buffer_days,
                )

            # 4. Observe account & enforce <= 10.00% portfolio drawdown brake
            auth_acct = self._authorized_account_id()
            acct = self._validate_account_snapshot(
                self._transport.account_snapshot(now_utc=now),
                expected_account_id=auth_acct,
            )
            open_positions = self._validate_positions_ownership(
                self._transport.positions(),
                expected_account_id=auth_acct,
            )
            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    peak_equity = self._update_peak_equity_unlocked(
                        conn,
                        max(acct.peak_equity_usd, acct.equity_usd),
                        now,
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            drawdown = compute_drawdown_pct(acct.equity_usd, peak_equity)
            if drawdown >= self._max_drawdown_pct:
                self._record_audit_event(
                    event_type="ORDER_REFUSED_DRAWDOWN",
                    entity_id=request_id,
                    payload={
                        "root_symbol": root,
                        "contract_code": front_month.contract_code,
                        "equity_usd": decimal_text(acct.equity_usd),
                        "peak_equity_usd": decimal_text(peak_equity),
                        "drawdown_pct": decimal_text(_q4(drawdown)),
                        "max_drawdown_pct": decimal_text(self._max_drawdown_pct),
                    },
                    now=now,
                )
                raise TradovateDrawdownLockError(
                    f"Portfolio drawdown {decimal_text(_q4(drawdown * Decimal('100')))}% "
                    f"reached/exceeded max constitutional drawdown cap "
                    f"{decimal_text(_q2(self._max_drawdown_pct * Decimal('100')))}%; "
                    "new entries refused (protective close/amend actions remain allowed)"
                )

            # 5. Live quote freshness gate (Finding [16]), tick alignment, & stop/TP geometry
            quote = self._transport.get_quote(root)
            try:
                quote_observed_at = _validate_quote_freshness(
                    quote,
                    now=now,
                    max_age_seconds=self._max_quote_age_seconds,
                    max_future_skew_seconds=self._max_quote_future_skew_seconds,
                )
            except TradovateStaleQuoteError as exc:
                self._record_audit_event(
                    event_type="ORDER_REFUSED_STALE_QUOTE",
                    entity_id=request_id,
                    payload={
                        "root_symbol": root,
                        "contract_code": front_month.contract_code,
                        "error": str(exc),
                        "max_quote_age_seconds": decimal_text(self._max_quote_age_seconds),
                    },
                    now=now,
                )
                raise

            ref_entry = (
                align_price_to_tick(root, _exact_decimal(entry_price, "entry_price", positive=True))
                if entry_price is not None
                else (quote.ask if norm_side == "BUY" else quote.bid)
            )

            if stop_loss_price is not None:
                aligned_sl = align_price_to_tick(
                    root, _exact_decimal(stop_loss_price, "stop_loss_price", positive=True)
                )
            elif stop_distance_points is not None:
                sl_dist = _exact_decimal(stop_distance_points, "stop_distance_points", positive=True)
                raw_sl = ref_entry - sl_dist if norm_side == "BUY" else ref_entry + sl_dist
                aligned_sl = align_price_to_tick(root, raw_sl)
            else:
                raise TradovateOrderError(
                    "place_bracket_order requires either stop_loss_price or stop_distance_points"
                )

            if take_profit_price is not None:
                aligned_tp: Decimal | None = align_price_to_tick(
                    root, _exact_decimal(take_profit_price, "take_profit_price", positive=True)
                )
            elif take_profit_points is not None:
                tp_dist = _exact_decimal(take_profit_points, "take_profit_points", positive=True)
                raw_tp = ref_entry + tp_dist if norm_side == "BUY" else ref_entry - tp_dist
                aligned_tp = align_price_to_tick(root, raw_tp)
            else:
                aligned_tp = None

            if norm_side == "BUY":
                if aligned_sl >= ref_entry:
                    raise TradovateOrderError(
                        f"BUY stop_loss_price ({aligned_sl}) must be below entry ({ref_entry})"
                    )
                if aligned_tp is not None and aligned_tp <= ref_entry:
                    raise TradovateOrderError(
                        f"BUY take_profit_price ({aligned_tp}) must be above entry ({ref_entry})"
                    )
            else:
                if aligned_sl <= ref_entry:
                    raise TradovateOrderError(
                        f"SELL stop_loss_price ({aligned_sl}) must be above entry ({ref_entry})"
                    )
                if aligned_tp is not None and aligned_tp >= ref_entry:
                    raise TradovateOrderError(
                        f"SELL take_profit_price ({aligned_tp}) must be below entry ({ref_entry})"
                    )

            eff_stop_distance = abs(ref_entry - aligned_sl)

            # 6. Constitutional <= 1.00% risk & >= 1,000% margin whole-contract sizing wall
            demo_max_risk = (
                self._demo_high_growth.max_risk_pct if self._demo_high_growth.enabled else None
            )
            sizing: MicroFuturesSizingResult = size_micro_futures_order(
                symbol_or_root=root,
                equity_usd=acct.equity_usd,
                stop_distance_points=eff_stop_distance,
                risk_pct=risk_pct,
                existing_used_margin_usd=acct.used_margin_usd,
                min_margin_level_pct=self._min_margin_level_pct,
                use_exchange_margin=self._use_exchange_margin,
                demo_max_stop_risk_pct=demo_max_risk,
            )
            if contracts is not None:
                if type(contracts) is not int or contracts < 1:
                    raise ContractError("contracts override must be a positive int")
                if contracts > sizing.contracts:
                    raise MicroFuturesSizingRefusalError(
                        f"Requested {contracts} contract(s) exceeds constitutional/margin cap "
                        f"of {sizing.contracts} contract(s) for {root}"
                    )
                final_contracts = contracts
            else:
                final_contracts = sizing.contracts

            # 7. Mandatory real ForexMetaValveGate (161 params, 0.55 cutoff) with original quote.observed_at
            valve_decision = self._evaluate_mandatory_valve(
                request_id=request_id,
                root_symbol=root,
                contract_code=front_month.contract_code,
                side=norm_side,
                contracts=final_contracts,
                entry_price=ref_entry,
                stop_loss_price=aligned_sl,
                take_profit_price=aligned_tp,
                quote=quote,
                account=acct,
                open_positions=open_positions,
                peak_equity=peak_equity,
                reason=reason,
                policy_overrides=policy_overrides,
                now=now,
            )
            valve_score_dec = Decimal(f"{valve_decision.mlp_score:.8f}")

            # 8. Immediate pre-dispatch freshness + LIVE auth rechecks (Findings [6], [16])
            dispatch_now = self._clock() if now_utc is None else now
            try:
                quote_observed_at = _validate_quote_freshness(
                    quote,
                    now=dispatch_now,
                    max_age_seconds=self._max_quote_age_seconds,
                    max_future_skew_seconds=self._max_quote_future_skew_seconds,
                )
            except TradovateStaleQuoteError as exc:
                self._record_audit_event(
                    event_type="ORDER_REFUSED_STALE_QUOTE_PRE_DISPATCH",
                    entity_id=request_id,
                    payload={
                        "root_symbol": root,
                        "contract_code": front_month.contract_code,
                        "error": str(exc),
                        "quote_observed_at": _iso_utc(quote_observed_at),
                    },
                    now=dispatch_now,
                )
                raise

            if self._mode == TRADOVATE_MODE_LIVE:
                parsed_url = urllib.parse.urlsplit(self._base_url)
                _verify_tradovate_live_authorization(
                    live_auth_context=self._live_auth_context,
                    live_arm_phrase=self._live_arm_phrase,
                    account_id=self._account_id,
                    server_host=(parsed_url.hostname or "").lower(),
                    now_utc=dispatch_now,
                )

            # 9. Persist deterministic stable clOrdId + PENDING row BEFORE transport call (Finding [3])
            stable_key = idempotency_key.strip() if idempotency_key is not None else request_id
            cl_ord_id = _compute_stable_cl_ord_id(
                account_id=self._account_id or acct.account_id,
                idempotency_key=stable_key,
                contract_code=front_month.contract_code,
                action=FuturesOrderAction.OPEN_BRACKET.value,
                side=norm_side,
                contracts=final_contracts,
                stop_loss_price=aligned_sl,
                take_profit_price=aligned_tp,
            )

            order_req = TradovateOrderRequest(
                request_id=request_id,
                cl_ord_id=cl_ord_id,
                action=FuturesOrderAction.OPEN_BRACKET,
                contract_code=front_month.contract_code,
                root_symbol=root,
                cas_symbol=cas_symbol,
                side=norm_side,
                contracts=final_contracts,
                entry_price=ref_entry,
                stop_loss_price=aligned_sl,
                take_profit_price=aligned_tp,
                client_tag=reason,
                quote_observed_at=quote_observed_at,
                created_at=dispatch_now,
            )
            req_json = canonical_bytes(order_req.to_dict()).decode("utf-8")
            ts_str = _iso_utc(dispatch_now)

            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    self._enforce_no_unresolved_freeze_unlocked(
                        conn, request_id=request_id, now=dispatch_now
                    )
                    dup_row = conn.execute(
                        "SELECT request_id, status FROM mutation_journal WHERE cl_ord_id = ?",
                        (cl_ord_id,),
                    ).fetchone()
                    if dup_row is not None:
                        dup_status = str(dup_row["status"])
                        conn.execute("COMMIT")
                        if dup_status in _UNRESOLVED_MUTATION_STATUSES:
                            raise TradovateOutcomeUnknownError(
                                f"Duplicate clOrdId {cl_ord_id!r} already in unresolved state {dup_status!r}",
                                cl_ord_id=cl_ord_id,
                                request_id=str(dup_row["request_id"]),
                            )
                        raise TradovateOrderError(
                            f"Duplicate idempotent clOrdId {cl_ord_id!r} already committed "
                            f"(request_id={dup_row['request_id']}, status={dup_status})"
                        )
                    conn.execute(
                        "INSERT INTO mutation_journal "
                        "(request_id, cl_ord_id, action, contract_code, root_symbol, cas_symbol, status, "
                        "request_json, receipt_json, error_detail, reconciled_at, reconciliation_json, "
                        "created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                        (
                            request_id,
                            cl_ord_id,
                            order_req.action.value,
                            order_req.contract_code,
                            order_req.root_symbol,
                            order_req.cas_symbol,
                            MUTATION_STATUS_PENDING,
                            req_json,
                            ts_str,
                            ts_str,
                        ),
                    )
                    conn.execute("COMMIT")
                except (TradovateOutcomeUnknownError, TradovateProtectionUnconfirmedError, TradovateOrderError):
                    raise
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            # 10. Dispatch via place_protected_order / send_order with fail-closed OUTCOME_UNKNOWN promotion
            dispatch_fn = getattr(self._transport, "place_protected_order", None)
            try:
                if callable(dispatch_fn):
                    raw_receipt = dispatch_fn(order_req)
                else:
                    raw_receipt = self._transport.send_order(order_req)
            except LiveAuthorizationError as exc:
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, error_detail = ?, updated_at = ? "
                            "WHERE request_id = ?",
                            ("REFUSED_LIVE_AUTH", str(exc), _iso_utc(self._clock()), request_id),
                        )
                        self._append_audit_unlocked(
                            conn,
                            event_type="ORDER_REFUSED_LIVE_AUTH",
                            entity_id=request_id,
                            payload={"cl_ord_id": cl_ord_id, "error": str(exc)},
                            occurred_at=self._clock(),
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise
                raise
            except TradovateProtectionUnconfirmedError as exc:
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_PROTECTION_UNCONFIRMED,
                    event_type="ORDER_PROTECTION_UNCONFIRMED",
                    detail=str(exc),
                    now=self._clock(),
                    order_id=exc.order_id,
                )
                raise
            except Exception as exc:
                http_status = getattr(exc, "http_status", None)
                detail = f"AMBIGUOUS_TRANSPORT_OUTCOME ({type(exc).__name__}): {exc}"
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                    event_type="ORDER_OUTCOME_UNKNOWN",
                    detail=detail,
                    now=self._clock(),
                )
                raise TradovateOutcomeUnknownError(
                    f"Tradovate order outcome unknown for clOrdId={cl_ord_id} ({detail}); "
                    "venue frozen until reconcile_unknown_outcome() verifies broker history",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                    http_status=http_status,
                ) from None

            # 11. Venue-layer broker protection confirmation audit (Finding [2] defense-in-depth)
            protection_failure: str | None = None
            if not isinstance(raw_receipt, TradovateOrderReceipt):
                protection_failure = "Transport returned non-TradovateOrderReceipt object"
            elif not raw_receipt.accepted:
                protection_failure = f"Broker did not accept protected bracket (status={raw_receipt.status!r})"
            elif not raw_receipt.protection_confirmed:
                protection_failure = "Broker receipt did not confirm stop/take-profit child protection"
            elif not isinstance(raw_receipt.order_id, str) or not raw_receipt.order_id.strip():
                protection_failure = "Broker receipt missing confirmed entry order_id"
            elif not isinstance(raw_receipt.stop_loss_order_id, str) or not raw_receipt.stop_loss_order_id.strip():
                protection_failure = "Broker receipt missing confirmed stop_loss_order_id (oso1Id)"
            elif raw_receipt.stop_loss_order_id.strip() == raw_receipt.order_id.strip():
                protection_failure = "Broker receipt stop_loss_order_id collides with entry order_id"
            elif raw_receipt.stop_loss_price != aligned_sl:
                protection_failure = (
                    f"Broker confirmed stop_loss_price ({raw_receipt.stop_loss_price}) "
                    f"does not match requested stop_loss_price ({aligned_sl})"
                )
            elif aligned_tp is not None and (
                not isinstance(raw_receipt.take_profit_order_id, str)
                or not raw_receipt.take_profit_order_id.strip()
            ):
                protection_failure = "Broker receipt missing confirmed take_profit_order_id (oso2Id)"
            elif aligned_tp is not None and raw_receipt.take_profit_order_id is not None and (
                raw_receipt.take_profit_order_id.strip()
                in (raw_receipt.order_id.strip(), raw_receipt.stop_loss_order_id.strip())
            ):
                protection_failure = "Broker receipt take_profit_order_id collides with entry/stop order_id"
            elif aligned_tp is not None and raw_receipt.take_profit_price != aligned_tp:
                protection_failure = (
                    f"Broker confirmed take_profit_price ({raw_receipt.take_profit_price}) "
                    f"does not match requested take_profit_price ({aligned_tp})"
                )
            elif raw_receipt.cl_ord_id is not None and raw_receipt.cl_ord_id != cl_ord_id:
                protection_failure = (
                    f"Broker receipt cl_ord_id ({raw_receipt.cl_ord_id!r}) != requested ({cl_ord_id!r})"
                )

            if protection_failure is not None:
                raw_oid = (
                    getattr(raw_receipt, "order_id", None)
                    if isinstance(raw_receipt, TradovateOrderReceipt)
                    else None
                )
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_PROTECTION_UNCONFIRMED,
                    event_type="ORDER_PROTECTION_UNCONFIRMED",
                    detail=protection_failure,
                    now=self._clock(),
                    order_id=raw_oid,
                )
                raise TradovateProtectionUnconfirmedError(
                    protection_failure,
                    cl_ord_id=cl_ord_id,
                    order_id=raw_oid,
                    request_id=request_id,
                )

            receipt = TradovateOrderReceipt(
                request_id=raw_receipt.request_id,
                cl_ord_id=cl_ord_id,
                action=raw_receipt.action,
                accepted=raw_receipt.accepted,
                status=raw_receipt.status,
                order_id=raw_receipt.order_id,
                stop_loss_order_id=raw_receipt.stop_loss_order_id,
                take_profit_order_id=raw_receipt.take_profit_order_id,
                protection_confirmed=True,
                position_id=raw_receipt.position_id,
                contract_code=raw_receipt.contract_code,
                root_symbol=raw_receipt.root_symbol,
                cas_symbol=raw_receipt.cas_symbol,
                side=raw_receipt.side,
                filled_contracts=raw_receipt.filled_contracts,
                fill_price=raw_receipt.fill_price,
                stop_loss_price=raw_receipt.stop_loss_price,
                take_profit_price=raw_receipt.take_profit_price,
                commission_usd=raw_receipt.commission_usd,
                realized_pnl_usd=raw_receipt.realized_pnl_usd,
                net_pnl_usd=raw_receipt.net_pnl_usd,
                reason=raw_receipt.reason,
                executed_at=raw_receipt.executed_at,
                valve_score=valve_score_dec,
                valve_weights_sha256=valve_decision.weights_sha256,
            )
            receipt_json = canonical_bytes(receipt.to_dict()).decode("utf-8")

            try:
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, receipt_json = ?, updated_at = ? "
                            "WHERE request_id = ?",
                            (receipt.status, receipt_json, _iso_utc(receipt.executed_at), request_id),
                        )
                        self._append_audit_unlocked(
                            conn,
                            event_type="ORDER_BRACKET_OPENED",
                            entity_id=request_id,
                            payload={
                                "receipt": receipt.to_dict(),
                                "quote_observed_at": _iso_utc(quote_observed_at),
                                "valve_mode": valve_decision.valve_mode,
                                "valve_score": decimal_text(valve_score_dec),
                                "valve_weights_sha256": valve_decision.weights_sha256,
                            },
                            occurred_at=receipt.executed_at,
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
            except Exception as exc:
                detail = f"POST_EFFECT_JOURNAL_FAILURE ({type(exc).__name__}): {exc}"
                try:
                    self._record_unresolved_latch(
                        request_id=request_id,
                        cl_ord_id=cl_ord_id,
                        status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                        event_type="ORDER_OUTCOME_UNKNOWN",
                        detail=detail,
                        now=self._clock(),
                        order_id=receipt.order_id,
                    )
                except Exception as exc_rec:
                    detail = f"{detail}; fallback_record_err={type(exc_rec).__name__}"
                raise TradovateOutcomeUnknownError(
                    f"Tradovate post-effect journal failure for clOrdId={cl_ord_id} ({detail}); "
                    "venue frozen until reconcile_unknown_outcome() verifies broker history",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                ) from None

            return receipt

    # -- Explicit Broker-History Reconciliation (Findings [2] & [3]) --

    def _normalize_reconciliation_evidence(
        self,
        raw_evidence: Any,
        *,
        expected_account_id: str,
        now: datetime,
    ) -> tuple[TradovateReconciliationEvidence, bool]:
        if isinstance(raw_evidence, TradovateReconciliationEvidence):
            filtered: list[dict[str, Any]] = []
            for item in raw_evidence.orders:
                raw_acct = item.get("accountId")
                if isinstance(raw_acct, bool) or raw_acct is None or not str(raw_acct).strip():
                    raise TradovateTransportError(
                        "Reconciliation order item missing required accountId",
                        ambiguous=True,
                    )
                if str(raw_acct).strip() == expected_account_id:
                    filtered.append(dict(item))
            if raw_evidence.account_id != expected_account_id:
                return (
                    TradovateReconciliationEvidence(
                        account_id=raw_evidence.account_id,
                        orders=tuple(filtered),
                        observed_cl_ord_ids=frozenset(
                            str(o.get("clOrdId", "")).strip()
                            for o in filtered
                            if str(o.get("clOrdId", "")).strip()
                        ),
                        pages_fetched=raw_evidence.pages_fetched,
                        complete=False,
                        provider_cursor_exhausted=raw_evidence.provider_cursor_exhausted,
                        watermark_utc=raw_evidence.watermark_utc,
                        incompleteness_reasons=raw_evidence.incompleteness_reasons + ("account_id_mismatch",),
                        authoritative_confirmation=False,
                        observed_at=raw_evidence.observed_at or now,
                    ),
                    True,
                )
            return (
                TradovateReconciliationEvidence(
                    account_id=raw_evidence.account_id,
                    orders=tuple(filtered),
                    observed_cl_ord_ids=frozenset(
                        str(o.get("clOrdId", "")).strip()
                        for o in filtered
                        if str(o.get("clOrdId", "")).strip()
                    ),
                    pages_fetched=raw_evidence.pages_fetched,
                    complete=raw_evidence.complete,
                    provider_cursor_exhausted=raw_evidence.provider_cursor_exhausted,
                    watermark_utc=raw_evidence.watermark_utc,
                    incompleteness_reasons=raw_evidence.incompleteness_reasons,
                    authoritative_confirmation=raw_evidence.authoritative_confirmation,
                    observed_at=raw_evidence.observed_at or now,
                ),
                True,
            )

        if isinstance(raw_evidence, Mapping):
            raw_acct = raw_evidence.get("account_id") if raw_evidence.get("account_id") is not None else raw_evidence.get("accountId")
            acct_str = str(raw_acct).strip() if raw_acct is not None and not isinstance(raw_acct, bool) else ""
            orders_raw = raw_evidence.get("orders")
            if not isinstance(orders_raw, Sequence) or isinstance(orders_raw, (str, bytes)):
                raise TradovateTransportError("Malformed reconciliation evidence orders sequence", ambiguous=True)
            filtered_m: list[dict[str, Any]] = []
            for item in orders_raw:
                if not isinstance(item, Mapping):
                    raise TradovateTransportError("Malformed order item in reconciliation evidence", ambiguous=True)
                i_acct = item.get("accountId")
                if isinstance(i_acct, bool) or i_acct is None or not str(i_acct).strip():
                    raise TradovateTransportError("Reconciliation order item missing required accountId", ambiguous=True)
                if str(i_acct).strip() == expected_account_id:
                    filtered_m.append(dict(item))
            raw_wm = raw_evidence.get("watermark_utc") if raw_evidence.get("watermark_utc") is not None else raw_evidence.get("watermarkUtc")
            wm_dt = _parse_utc_timestamp(raw_wm, field="watermark_utc") if raw_wm is not None else None
            pages_val = raw_evidence.get("pages_fetched", 0)
            pages_int = int(pages_val) if type(pages_val) is int and pages_val >= 0 else 0
            comp_val = bool(raw_evidence.get("complete") is True)
            exh_val = bool(raw_evidence.get("provider_cursor_exhausted") is True)
            auth_val = bool(raw_evidence.get("authoritative_confirmation") is True)
            reasons = list(raw_evidence.get("incompleteness_reasons") or ())
            if not acct_str or acct_str != expected_account_id:
                comp_val = False
                auth_val = False
                reasons.append("account_id_mismatch")
            return (
                TradovateReconciliationEvidence(
                    account_id=acct_str or expected_account_id,
                    orders=tuple(filtered_m),
                    observed_cl_ord_ids=frozenset(
                        str(o.get("clOrdId", "")).strip()
                        for o in filtered_m
                        if str(o.get("clOrdId", "")).strip()
                    ),
                    pages_fetched=pages_int,
                    complete=comp_val,
                    provider_cursor_exhausted=exh_val,
                    watermark_utc=wm_dt,
                    incompleteness_reasons=tuple(str(r) for r in reasons),
                    authoritative_confirmation=auth_val,
                    observed_at=now,
                ),
                True,
            )

        raise TradovateTransportError(
            f"Unsupported reconciliation evidence type: {type(raw_evidence).__name__}",
            ambiguous=True,
        )

    def _fetch_transport_reconciliation_evidence(
        self,
        *,
        expected_account_id: str,
        since_utc: datetime | None,
        now: datetime,
    ) -> tuple[TradovateReconciliationEvidence, bool]:
        fetch_fn = getattr(self._transport, "fetch_reconciliation_evidence", None)
        pag_fn = getattr(self._transport, "list_orders_paginated", None)
        # If subclass overrides list_orders_paginated without overriding fetch_reconciliation_evidence,
        # prefer list_orders_paginated directly when fetch_reconciliation_evidence isn't overridden.
        if callable(pag_fn) and callable(fetch_fn):
            raw_ev = fetch_fn(since_utc=since_utc)
            return self._normalize_reconciliation_evidence(
                raw_ev, expected_account_id=expected_account_id, now=now
            )
        if callable(fetch_fn):
            raw_ev = fetch_fn(since_utc=since_utc)
            return self._normalize_reconciliation_evidence(
                raw_ev, expected_account_id=expected_account_id, now=now
            )
        if callable(pag_fn):
            raw_ev = pag_fn(since_utc=since_utc)
            return self._normalize_reconciliation_evidence(
                raw_ev, expected_account_id=expected_account_id, now=now
            )

        lister = getattr(self._transport, "list_orders", None)
        if callable(lister):
            raw_list = lister()
            if not isinstance(raw_list, Sequence) or isinstance(raw_list, (str, bytes)):
                raise TradovateTransportError("Transport list_orders() returned non-sequence", ambiguous=True)
            filtered_orders: list[dict[str, Any]] = []
            for item in raw_list:
                if not isinstance(item, Mapping):
                    raise TradovateTransportError("Transport list_orders() item is not a mapping", ambiguous=True)
                raw_acct = item.get("accountId")
                if isinstance(raw_acct, bool) or raw_acct is None or not str(raw_acct).strip():
                    raise TradovateTransportError("Transport list_orders() item missing required accountId", ambiguous=True)
                if str(raw_acct).strip() == expected_account_id:
                    filtered_orders.append(dict(item))
            return (
                TradovateReconciliationEvidence(
                    account_id=expected_account_id,
                    orders=tuple(filtered_orders),
                    observed_cl_ord_ids=frozenset(
                        str(o.get("clOrdId", "")).strip()
                        for o in filtered_orders
                        if str(o.get("clOrdId", "")).strip()
                    ),
                    pages_fetched=1,
                    complete=False,
                    provider_cursor_exhausted=False,
                    watermark_utc=None,
                    incompleteness_reasons=("unpaged_unwatermarked_transport",),
                    authoritative_confirmation=False,
                    observed_at=now,
                ),
                False,
            )

        raise TradovateOutcomeUnknownError(
            "Transport does not expose broker order-history lookup; freeze latch retained",
        )

    def reconcile_unknown_outcome(
        self,
        *,
        cl_ord_id: str | None = None,
        request_id: str | None = None,
        confirm_protection_resolved: bool = False,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Reconcile OUTCOME_UNKNOWN / PROTECTION_UNCONFIRMED latches against authoritative account-bound history.

        Requires connected transport and completeness-proven, account-bound,
        watermarked paginated order history (plus two consistent observations or
        explicit authoritative confirmation) before clearing an absence latch.
        Never accepts raw untrusted caller-supplied order lists.
        """
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        ts_str = _iso_utc(now)
        if type(confirm_protection_resolved) is not bool:
            raise ContractError("confirm_protection_resolved must be a strict bool")

        with self._lock:
            auth_acct = self._authorized_account_id()
            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    rows = conn.execute(
                        "SELECT seq, request_id, cl_ord_id, action, contract_code, status, request_json, created_at "
                        "FROM mutation_journal WHERE status IN (?, ?, ?) ORDER BY seq ASC",
                        _UNRESOLVED_MUTATION_STATUSES,
                    ).fetchall()
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            targets = []
            for row in rows:
                r_req = str(row["request_id"])
                r_cl = str(row["cl_ord_id"]).strip() if row["cl_ord_id"] is not None else ""
                if cl_ord_id is not None and r_cl != cl_ord_id.strip():
                    continue
                if request_id is not None and r_req != request_id.strip():
                    continue
                targets.append(row)

            if (cl_ord_id is not None or request_id is not None) and not targets:
                raise TradovateOrderError(
                    f"No unresolved mutation matching cl_ord_id={cl_ord_id!r}, request_id={request_id!r}"
                )

            if not targets:
                with closing(self._connect_ro()) as conn:
                    remaining_unresolved = self._query_unresolved_mutations_unlocked(conn)
                    remaining_latches = self._query_active_latches_unlocked(conn)
                return {
                    "reconciled": [],
                    "remaining_unresolved_count": len(remaining_unresolved),
                    "remaining_active_latch_count": len(remaining_latches),
                    "freeze_active": bool(remaining_unresolved or remaining_latches),
                    "reconciled_at": ts_str,
                }

            if not self._transport.is_connected():
                raise TradovateOutcomeUnknownError(
                    "Transport disconnected during reconcile_unknown_outcome(); freeze latch retained"
                )

            submitted_times: list[datetime] = []
            for row in targets:
                try:
                    submitted_times.append(
                        _parse_utc_timestamp(str(row["created_at"]), field="mutation_journal.created_at")
                    )
                except TradovateTransportError:
                    pass
            earliest_submitted = min(submitted_times) if submitted_times else None

            try:
                ev1, ev1_paginated = self._fetch_transport_reconciliation_evidence(
                    expected_account_id=auth_acct,
                    since_utc=earliest_submitted,
                    now=now,
                )
                open_positions: tuple[TradovatePosition, ...] = ()
                if confirm_protection_resolved or isinstance(
                    self._transport, TradovateMicroFuturesPaperEmulator
                ):
                    open_positions = self._validate_positions_ownership(
                        self._transport.positions(),
                        expected_account_id=auth_acct,
                    )
            except TradovateOutcomeUnknownError:
                raise
            except Exception as exc:
                raise TradovateOutcomeUnknownError(
                    f"Broker history lookup failed during reconciliation ({type(exc).__name__}: {exc}); "
                    "freeze latch retained"
                ) from None

            ev2: TradovateReconciliationEvidence | None = None
            ev2_paginated = False
            ev2_error: str | None = None
            needs_second_observation = False
            if ev1_paginated and ev1.complete and not ev1.authoritative_confirmation:
                for row in targets:
                    r_cl_chk = str(row["cl_ord_id"]).strip() if row["cl_ord_id"] is not None else ""
                    if r_cl_chk and r_cl_chk not in ev1.observed_cl_ord_ids:
                        needs_second_observation = True
                        break
            if needs_second_observation:
                try:
                    ev2, ev2_paginated = self._fetch_transport_reconciliation_evidence(
                        expected_account_id=auth_acct,
                        since_utc=earliest_submitted,
                        now=now,
                    )
                except Exception as exc:
                    ev2_error = f"{type(exc).__name__}: {exc}"

            reconciled_results: list[dict[str, Any]] = []
            for row in targets:
                r_req = str(row["request_id"])
                r_cl = str(row["cl_ord_id"]).strip() if row["cl_ord_id"] is not None else ""
                r_contract = str(row["contract_code"])
                orig_req = json.loads(str(row["request_json"]))
                orig_action = str(orig_req.get("action") or row["action"] or "").strip().upper()
                req_sl = orig_req.get("stop_loss_price")
                req_tp = orig_req.get("take_profit_price")
                try:
                    orig_submitted_at = _parse_utc_timestamp(
                        str(row["created_at"]), field="mutation_journal.created_at"
                    )
                except TradovateTransportError:
                    orig_submitted_at = now

                if not r_cl:
                    raise TradovateOutcomeUnknownError(
                        f"Unresolved mutation {r_req} lacks cl_ord_id; cannot safely reconcile",
                        request_id=r_req,
                    )

                active_ev = ev1
                matched = [
                    dict(o)
                    for o in ev1.orders
                    if str(o.get("clOrdId", "")).strip() == r_cl
                    and str(o.get("accountId", "")).strip() == auth_acct
                ]
                if not matched and ev2 is not None:
                    matched_2 = [
                        dict(o)
                        for o in ev2.orders
                        if str(o.get("clOrdId", "")).strip() == r_cl
                        and str(o.get("accountId", "")).strip() == auth_acct
                    ]
                    if matched_2:
                        matched = matched_2
                        active_ev = ev2

                new_status: str
                resolved = False
                reason_code: str
                if not matched:
                    open_cl_hit = any((p.cl_ord_id or "").strip() == r_cl for p in open_positions)
                    absence_reasons: list[str] = []
                    if not ev1_paginated:
                        absence_reasons.append("unpaged_history")
                    if ev1.account_id != auth_acct:
                        absence_reasons.append("account_id_mismatch")
                    if not ev1.complete:
                        absence_reasons.extend(ev1.incompleteness_reasons or ("incomplete_history",))
                    if not ev1.provider_cursor_exhausted:
                        absence_reasons.append("cursor_not_exhausted")
                    if ev1.watermark_utc is None:
                        absence_reasons.append("missing_watermark_utc")
                    elif ev1.watermark_utc < orig_submitted_at:
                        absence_reasons.append("watermark_before_submission")
                    if open_cl_hit:
                        absence_reasons.append("matching_open_position_present")
                    if not absence_reasons and not ev1.authoritative_confirmation:
                        if ev2_error is not None:
                            absence_reasons.append("second_observation_failed")
                        elif ev2 is None or not ev2_paginated:
                            absence_reasons.append("missing_second_observation")
                        elif not ev2.complete or not ev2.provider_cursor_exhausted or ev2.account_id != auth_acct:
                            absence_reasons.extend(ev2.incompleteness_reasons or ("second_observation_incomplete",))
                        elif ev2.watermark_utc is None or ev2.watermark_utc < orig_submitted_at:
                            absence_reasons.append("second_observation_watermark_invalid")
                        elif r_cl in ev2.observed_cl_ord_ids:
                            absence_reasons.append("second_observation_inconsistent")

                    if not absence_reasons:
                        new_status = "RECONCILED_ABSENT"
                        resolved = True
                        reason_code = "CONFIRMED_ABSENT_WITH_COMPLETENESS_PROOF"
                    else:
                        new_status = MUTATION_STATUS_OUTCOME_UNKNOWN
                        resolved = False
                        dedup_reasons = list(dict.fromkeys(absence_reasons))
                        reason_code = f"ABSENCE_UNPROVEN:{','.join(dedup_reasons)}"
                else:
                    order_doc = matched[-1]
                    ord_status = str(order_doc.get("ordStatus") or order_doc.get("status") or "").strip().lower()
                    filled_raw = order_doc.get("filledQty", order_doc.get("cumQty", 0))
                    try:
                        filled_qty = _parse_broker_int(filled_raw, "filledQty", non_negative=True)
                    except ContractError:
                        filled_qty = -1

                    if ord_status in ("rejected", "canceled", "cancelled", "expired") and filled_qty == 0:
                        if orig_action == FuturesOrderAction.CANCEL_ORDER.value and ord_status in ("canceled", "cancelled"):
                            new_status = "RECONCILED_CANCELLED"
                            resolved = True
                            reason_code = "CONFIRMED_ORDER_CANCELLED"
                        else:
                            new_status = "RECONCILED_REJECTED"
                            resolved = True
                            reason_code = f"CONFIRMED_{ord_status.upper()}_ZERO_FILL"
                    elif orig_action == FuturesOrderAction.AMEND_STOP.value:
                        if ord_status in ("working", "accepted", "modified", "amended", "active", "filled", "completed"):
                            stop_ok = True
                            if req_sl is not None and order_doc.get("stopPrice") is not None:
                                try:
                                    stop_ok = (
                                        _parse_broker_decimal(order_doc.get("stopPrice"), "stopPrice", positive=True)
                                        == Decimal(str(req_sl))
                                    )
                                except (ContractError, InvalidOperation):
                                    stop_ok = False
                            if stop_ok:
                                new_status = "RECONCILED_AMENDED"
                                resolved = True
                                reason_code = "CONFIRMED_STOP_AMENDED_IN_BROKER_HISTORY"
                            else:
                                new_status = MUTATION_STATUS_OUTCOME_UNKNOWN
                                resolved = False
                                reason_code = "AMEND_STOP_PRICE_MISMATCH_IN_HISTORY"
                        else:
                            new_status = MUTATION_STATUS_OUTCOME_UNKNOWN
                            resolved = False
                            reason_code = f"AMEND_STOP_STILL_AMBIGUOUS_{ord_status.upper() or 'MISSING_STATUS'}"
                    elif orig_action in (FuturesOrderAction.CLOSE_POSITION.value, FuturesOrderAction.EMERGENCY_CLOSE_ALL.value):
                        if ord_status in ("filled", "completed", "closed") and filled_qty != 0:
                            new_status = "RECONCILED_CLOSED"
                            resolved = True
                            reason_code = "CONFIRMED_POSITION_CLOSED_IN_BROKER_HISTORY"
                        else:
                            new_status = MUTATION_STATUS_OUTCOME_UNKNOWN
                            resolved = False
                            reason_code = f"CLOSE_STILL_AMBIGUOUS_{ord_status.upper() or 'MISSING_STATUS'}"
                    elif orig_action == FuturesOrderAction.CANCEL_ORDER.value:
                        if ord_status in ("canceled", "cancelled", "filled", "completed"):
                            new_status = "RECONCILED_CANCELLED"
                            resolved = True
                            reason_code = "CONFIRMED_ORDER_CANCELLED"
                        else:
                            new_status = MUTATION_STATUS_OUTCOME_UNKNOWN
                            resolved = False
                            reason_code = f"CANCEL_STILL_AMBIGUOUS_{ord_status.upper() or 'MISSING_STATUS'}"
                    elif ord_status in (
                        "filled",
                        "working",
                        "accepted",
                        "completed",
                        "partiallyfilled",
                        "partially_filled",
                    ):
                        req_side = str(orig_req.get("side") or "").strip().upper()
                        expected_prot_action = "sell" if req_side == "BUY" else ("buy" if req_side == "SELL" else "")
                        req_qty = orig_req.get("contracts")
                        all_history_orders = list(active_ev.orders)

                        def _find_child_doc(
                            parent_doc: Mapping[str, Any],
                            child_id_val: Any,
                            inline_names: tuple[str, ...],
                        ) -> Mapping[str, Any] | None:
                            for iname in inline_names:
                                cand = parent_doc.get(iname)
                                if isinstance(cand, Mapping):
                                    if cand.get("accountId") is not None and str(cand.get("accountId")).strip() != auth_acct:
                                        return None
                                    return cand
                            cid = str(child_id_val).strip() if child_id_val is not None else ""
                            if not cid:
                                return None
                            for entry in all_history_orders:
                                if str(entry.get("accountId", "")).strip() != auth_acct:
                                    continue
                                eid = entry.get("orderId") if entry.get("orderId") is not None else entry.get("id")
                                if eid is not None and str(eid).strip() == cid:
                                    return entry
                            fetcher = getattr(self._transport, "_fetch_order_details", None)
                            if callable(fetcher) and self._transport.is_connected():
                                try:
                                    fetched = fetcher(cid)
                                    if isinstance(fetched, Mapping):
                                        if str(fetched.get("accountId", "")).strip() != auth_acct:
                                            return None
                                        return fetched
                                except TradovateVenueError:
                                    return None
                            return None

                        def _child_matches(
                            cdoc: Mapping[str, Any] | None,
                            expected_px_str: Any,
                            px_keys: tuple[str, ...],
                        ) -> bool:
                            if not isinstance(cdoc, Mapping) or expected_px_str is None:
                                return False
                            if cdoc.get("accountId") is not None and str(cdoc.get("accountId")).strip() != auth_acct:
                                return False
                            c_status = str(cdoc.get("ordStatus") or cdoc.get("status") or "").strip().lower()
                            if c_status in ("rejected", "canceled", "cancelled", "expired", "suspended"):
                                return False
                            c_action = str(cdoc.get("action") or cdoc.get("side") or "").strip().lower()
                            if expected_prot_action and c_action and c_action != expected_prot_action:
                                return False
                            c_qty = cdoc.get("orderQty") if cdoc.get("orderQty") is not None else cdoc.get("qty")
                            if c_qty is not None and req_qty is not None:
                                try:
                                    if _parse_broker_int(c_qty, "orderQty", positive=True) != int(req_qty):
                                        return False
                                except (ContractError, ValueError):
                                    return False
                            raw_px = None
                            for pk in px_keys:
                                if cdoc.get(pk) is not None:
                                    raw_px = cdoc.get(pk)
                                    break
                            if raw_px is None:
                                return False
                            try:
                                return (
                                    _parse_broker_decimal(raw_px, "child_price", positive=True)
                                    == Decimal(str(expected_px_str))
                                )
                            except (ContractError, InvalidOperation):
                                return False

                        oso1_val = order_doc.get("oso1Id")
                        has_oso1 = bool(oso1_val)
                        sl_doc = (
                            _find_child_doc(order_doc, oso1_val, ("bracket1", "oso1", "stopOrder"))
                            if has_oso1
                            else None
                        )
                        sl_ok = has_oso1 and _child_matches(
                            sl_doc, req_sl, ("stopPrice", "stop_price", "stopLossPrice")
                        )

                        tp_ok = req_tp is None
                        if req_tp is not None:
                            oso2_val = order_doc.get("oso2Id")
                            has_oso2 = bool(oso2_val)
                            tp_doc = (
                                _find_child_doc(order_doc, oso2_val, ("bracket2", "oso2", "takeProfitOrder"))
                                if has_oso2
                                else None
                            )
                            tp_ok = has_oso2 and _child_matches(
                                tp_doc, req_tp, ("price", "limitPrice", "takeProfitPrice")
                            )
                        if sl_ok and tp_ok:
                            new_status = "RECONCILED_FILLED_PROTECTED"
                            resolved = True
                            reason_code = "CONFIRMED_FILLED_WITH_VERIFIED_PROTECTION"
                        elif confirm_protection_resolved:
                            open_same = any(p.contract_code == r_contract for p in open_positions)
                            if not open_same:
                                new_status = "RECONCILED_CLOSED_EXTERNALLY"
                                resolved = True
                                reason_code = "CONFIRMED_NO_OPEN_UNPROTECTED_POSITION"
                            else:
                                new_status = MUTATION_STATUS_PROTECTION_UNCONFIRMED
                                resolved = False
                                reason_code = "OPEN_POSITION_STILL_LACKS_VERIFIED_PROTECTION"
                        else:
                            new_status = MUTATION_STATUS_PROTECTION_UNCONFIRMED
                            resolved = False
                            reason_code = "BROKER_ORDER_PRESENT_WITHOUT_VERIFIED_PROTECTION"
                    else:
                        new_status = MUTATION_STATUS_OUTCOME_UNKNOWN
                        resolved = False
                        reason_code = f"BROKER_ORDER_STILL_AMBIGUOUS_{ord_status.upper() or 'MISSING_STATUS'}"

                rec_doc = {
                    "request_id": r_req,
                    "cl_ord_id": r_cl,
                    "action": orig_action,
                    "account_id": auth_acct,
                    "new_status": new_status,
                    "resolved": resolved,
                    "reason": reason_code,
                    "matched_order_count": len(matched),
                    "pages_fetched": active_ev.pages_fetched,
                    "evidence_complete": active_ev.complete,
                    "provider_cursor_exhausted": active_ev.provider_cursor_exhausted,
                    "watermark_utc": _iso_utc(active_ev.watermark_utc) if active_ev.watermark_utc is not None else None,
                    "reconciled_at": ts_str,
                }
                rec_json = canonical_bytes(rec_doc).decode("utf-8")

                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, reconciled_at = ?, "
                            "reconciliation_json = ?, updated_at = ? WHERE request_id = ?",
                            (
                                new_status,
                                ts_str if resolved else None,
                                rec_json,
                                ts_str,
                                r_req,
                            ),
                        )
                        if resolved:
                            conn.execute(
                                "UPDATE venue_freeze_latches SET cleared_at = ?, reconciliation_json = ? "
                                "WHERE request_id = ? AND cleared_at IS NULL",
                                (ts_str, rec_json, r_req),
                            )
                        self._append_audit_unlocked(
                            conn,
                            event_type="OUTCOME_UNKNOWN_RECONCILED",
                            entity_id=r_req,
                            payload=rec_doc,
                            occurred_at=now,
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise

                reconciled_results.append(rec_doc)

            with closing(self._connect_ro()) as conn:
                remaining_unresolved = self._query_unresolved_mutations_unlocked(conn)
                remaining_latches = self._query_active_latches_unlocked(conn)

            return {
                "reconciled": reconciled_results,
                "remaining_unresolved_count": len(remaining_unresolved),
                "remaining_active_latch_count": len(remaining_latches),
                "freeze_active": bool(remaining_unresolved or remaining_latches),
                "reconciled_at": ts_str,
            }

    # -- Protective Actions (ALWAYS ALLOWED; Durably Idempotent & Pre-Journaled) --

    @staticmethod
    def _validate_protective_receipt(
        raw_receipt: Any,
        *,
        expected_action: FuturesOrderAction,
        expected_cl_ord_id: str,
        expected_stop_loss_price: Decimal | None = None,
    ) -> str | None:
        if not isinstance(raw_receipt, TradovateOrderReceipt):
            return "Transport returned non-TradovateOrderReceipt object"
        if not raw_receipt.accepted:
            return f"Broker did not accept protective {expected_action.value} (status={raw_receipt.status!r})"
        norm_status = str(raw_receipt.status or "").strip().upper()
        if not norm_status or norm_status in (
            "REJECTED",
            "EXPIRED",
            "CANCELED",
            "CANCELLED",
            "SUSPENDED",
            "VOIDED",
            "ERROR",
            "FAILED",
            "PENDING_NEW",
            "PENDINGNEW",
        ):
            return f"Broker returned non-success protective status {raw_receipt.status!r}"
        if expected_action is FuturesOrderAction.CLOSE_POSITION and norm_status == "WORKING":
            return "Broker close returned non-terminal WORKING status"
        if not isinstance(raw_receipt.order_id, str) or not raw_receipt.order_id.strip():
            return "Broker protective receipt missing confirmed order_id"
        if raw_receipt.cl_ord_id is not None and raw_receipt.cl_ord_id.strip() != expected_cl_ord_id:
            return (
                f"Broker protective receipt cl_ord_id ({raw_receipt.cl_ord_id!r}) != "
                f"requested ({expected_cl_ord_id!r})"
            )
        if expected_action is FuturesOrderAction.AMEND_STOP and expected_stop_loss_price is not None:
            if raw_receipt.stop_loss_price != expected_stop_loss_price:
                return (
                    f"Broker amended stop_loss_price ({raw_receipt.stop_loss_price}) != "
                    f"requested ({expected_stop_loss_price})"
                )
        if expected_action is FuturesOrderAction.CLOSE_POSITION and raw_receipt.filled_contracts <= 0:
            return "Broker close receipt reported filled_contracts <= 0"
        return None

    def amend_stop(
        self,
        position_id: str,
        new_stop_loss_price: Decimal,
        *,
        reason: str = "PROTECTIVE_AMEND_STOP",
        idempotency_key: str | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Protective stop amendment (e.g. break-even / trail). ALWAYS ALLOWED & pre-journaled."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ContractError("idempotency_key must be a non-empty string when provided")
            _check_no_control_chars(idempotency_key, "idempotency_key")

        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate transport is disconnected")
            auth_acct = self._authorized_account_id()
            open_positions = self._validate_positions_ownership(
                self._transport.positions(),
                expected_account_id=auth_acct,
            )
            open_pos = next((p for p in open_positions if p.position_id == position_id), None)
            if open_pos is None:
                raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
            if (open_pos.account_id or "").strip() != auth_acct:
                raise TradovateTransportError(
                    f"Position {position_id!r} account mismatch (expected {auth_acct!r})",
                    ambiguous=False,
                )
            if isinstance(self._transport, TradovateHttpsTransport) and not open_pos.stop_loss_order_id:
                raise TradovateOrderError(
                    f"Open position {position_id!r} lacks confirmed stop_loss_order_id"
                )
            aligned_sl = align_price_to_tick(
                open_pos.root_symbol,
                _exact_decimal(new_stop_loss_price, "new_stop_loss_price", positive=True),
            )
            request_id = self._next_request_id("amend")
            stable_key = idempotency_key.strip() if idempotency_key is not None else request_id
            cl_ord_id = _compute_stable_cl_ord_id(
                account_id=auth_acct,
                idempotency_key=stable_key,
                contract_code=open_pos.contract_code,
                action=FuturesOrderAction.AMEND_STOP.value,
                side=open_pos.side,
                contracts=open_pos.contracts,
                stop_loss_price=aligned_sl,
                take_profit_price=open_pos.take_profit_price,
                target_id=f"{position_id}:{open_pos.stop_loss_order_id or ''}",
            )
            order_req = TradovateOrderRequest(
                request_id=request_id,
                cl_ord_id=cl_ord_id,
                action=FuturesOrderAction.AMEND_STOP,
                contract_code=open_pos.contract_code,
                root_symbol=open_pos.root_symbol,
                cas_symbol=open_pos.cas_symbol,
                side=open_pos.side,
                contracts=open_pos.contracts,
                stop_loss_price=aligned_sl,
                take_profit_price=open_pos.take_profit_price,
                position_id=position_id,
                order_id=open_pos.stop_loss_order_id,
                client_tag=reason,
                created_at=now,
            )
            req_json = canonical_bytes(order_req.to_dict()).decode("utf-8")
            ts_str = _iso_utc(now)

            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    dup_row = conn.execute(
                        "SELECT request_id, status FROM mutation_journal WHERE cl_ord_id = ?",
                        (cl_ord_id,),
                    ).fetchone()
                    if dup_row is not None:
                        dup_status = str(dup_row["status"])
                        conn.execute("COMMIT")
                        if dup_status in _UNRESOLVED_MUTATION_STATUSES:
                            raise TradovateOutcomeUnknownError(
                                f"Duplicate protective clOrdId {cl_ord_id!r} already in unresolved state {dup_status!r}",
                                cl_ord_id=cl_ord_id,
                                request_id=str(dup_row["request_id"]),
                            )
                        raise TradovateOrderError(
                            f"Duplicate idempotent protective clOrdId {cl_ord_id!r} already committed "
                            f"(request_id={dup_row['request_id']}, status={dup_status})"
                        )
                    conn.execute(
                        "INSERT INTO mutation_journal "
                        "(request_id, cl_ord_id, action, contract_code, root_symbol, cas_symbol, status, "
                        "request_json, receipt_json, error_detail, reconciled_at, reconciliation_json, "
                        "created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                        (
                            request_id,
                            cl_ord_id,
                            order_req.action.value,
                            order_req.contract_code,
                            order_req.root_symbol,
                            order_req.cas_symbol,
                            MUTATION_STATUS_PENDING,
                            req_json,
                            ts_str,
                            ts_str,
                        ),
                    )
                    conn.execute("COMMIT")
                except (TradovateOutcomeUnknownError, TradovateOrderError):
                    raise
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise

            try:
                raw_receipt = self._transport.send_order(order_req)
            except LiveAuthorizationError as exc:
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, error_detail = ?, updated_at = ? "
                            "WHERE request_id = ?",
                            ("REFUSED_LIVE_AUTH", str(exc), _iso_utc(self._clock()), request_id),
                        )
                        self._append_audit_unlocked(
                            conn,
                            event_type="PROTECTIVE_REFUSED_LIVE_AUTH",
                            entity_id=request_id,
                            payload={"cl_ord_id": cl_ord_id, "error": str(exc)},
                            occurred_at=self._clock(),
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
                raise
            except Exception as exc:
                http_status = getattr(exc, "http_status", None)
                detail = f"AMBIGUOUS_PROTECTIVE_AMEND_OUTCOME ({type(exc).__name__}): {exc}"
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                    event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                    detail=detail,
                    now=self._clock(),
                )
                raise TradovateOutcomeUnknownError(
                    f"Tradovate protective amend outcome unknown for clOrdId={cl_ord_id} ({detail}); "
                    "safety freeze engaged until reconciled",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                    http_status=http_status,
                ) from None

            failure = self._validate_protective_receipt(
                raw_receipt,
                expected_action=FuturesOrderAction.AMEND_STOP,
                expected_cl_ord_id=cl_ord_id,
                expected_stop_loss_price=aligned_sl,
            )
            if failure is not None:
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                    event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                    detail=failure,
                    now=self._clock(),
                    order_id=getattr(raw_receipt, "order_id", None) if isinstance(raw_receipt, TradovateOrderReceipt) else None,
                )
                raise TradovateOutcomeUnknownError(
                    f"Tradovate protective amend failed validation for clOrdId={cl_ord_id} ({failure}); "
                    "safety freeze engaged until reconciled",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                )

            receipt = TradovateOrderReceipt(
                request_id=raw_receipt.request_id,
                cl_ord_id=cl_ord_id,
                action=raw_receipt.action,
                accepted=raw_receipt.accepted,
                status=raw_receipt.status,
                order_id=raw_receipt.order_id,
                stop_loss_order_id=raw_receipt.stop_loss_order_id or raw_receipt.order_id,
                take_profit_order_id=raw_receipt.take_profit_order_id,
                protection_confirmed=raw_receipt.protection_confirmed,
                position_id=raw_receipt.position_id or position_id,
                contract_code=raw_receipt.contract_code or open_pos.contract_code,
                root_symbol=raw_receipt.root_symbol or open_pos.root_symbol,
                cas_symbol=raw_receipt.cas_symbol or open_pos.cas_symbol,
                side=raw_receipt.side or open_pos.side,
                filled_contracts=raw_receipt.filled_contracts,
                fill_price=raw_receipt.fill_price,
                stop_loss_price=raw_receipt.stop_loss_price,
                take_profit_price=raw_receipt.take_profit_price,
                commission_usd=raw_receipt.commission_usd,
                realized_pnl_usd=raw_receipt.realized_pnl_usd,
                net_pnl_usd=raw_receipt.net_pnl_usd,
                reason=raw_receipt.reason,
                executed_at=raw_receipt.executed_at,
            )
            rec_json = canonical_bytes(receipt.to_dict()).decode("utf-8")
            try:
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, receipt_json = ?, updated_at = ? "
                            "WHERE request_id = ?",
                            (receipt.status, rec_json, _iso_utc(receipt.executed_at), request_id),
                        )
                        self._append_audit_unlocked(
                            conn,
                            event_type="PROTECTIVE_STOP_AMENDED",
                            entity_id=request_id,
                            payload={"receipt": receipt.to_dict()},
                            occurred_at=receipt.executed_at,
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
            except Exception as exc:
                detail = f"POST_EFFECT_AMEND_JOURNAL_FAILURE ({type(exc).__name__}): {exc}"
                try:
                    self._record_unresolved_latch(
                        request_id=request_id,
                        cl_ord_id=cl_ord_id,
                        status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                        event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                        detail=detail,
                        now=self._clock(),
                        order_id=receipt.order_id,
                    )
                except Exception as exc_rec:
                    detail = f"{detail}; fallback_record_err={type(exc_rec).__name__}"
                raise TradovateOutcomeUnknownError(
                    f"Tradovate post-amend journal failure for clOrdId={cl_ord_id} ({detail}); "
                    "safety freeze engaged until reconciled",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                ) from None
            return receipt

    def amend_protective_brackets(
        self,
        position_id: str,
        new_stop_loss_price: Decimal,
        *,
        reason: str = "PROTECTIVE_AMEND_BRACKETS",
        idempotency_key: str | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Alias for durable pre-journaled protective bracket/stop amendment. ALWAYS ALLOWED."""
        return self.amend_stop(
            position_id,
            new_stop_loss_price,
            reason=reason,
            idempotency_key=idempotency_key,
            now_utc=now_utc,
        )

    def close_position(
        self,
        position_id: str,
        *,
        reason: str = "PROTECTIVE_CLOSE_POSITION",
        idempotency_key: str | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Protective single-position close. ALWAYS ALLOWED & durably pre-journaled."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ContractError("idempotency_key must be a non-empty string when provided")
            _check_no_control_chars(idempotency_key, "idempotency_key")

        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate transport is disconnected")
            auth_acct = self._authorized_account_id()
            open_positions = self._validate_positions_ownership(
                self._transport.positions(),
                expected_account_id=auth_acct,
            )
            open_pos = next((p for p in open_positions if p.position_id == position_id), None)
            if open_pos is None:
                raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
            if (open_pos.account_id or "").strip() != auth_acct:
                raise TradovateTransportError(
                    f"Position {position_id!r} account mismatch (expected {auth_acct!r})",
                    ambiguous=False,
                )
            request_id = self._next_request_id("close")
            stable_key = idempotency_key.strip() if idempotency_key is not None else request_id
            cl_ord_id = _compute_stable_cl_ord_id(
                account_id=auth_acct,
                idempotency_key=stable_key,
                contract_code=open_pos.contract_code,
                action=FuturesOrderAction.CLOSE_POSITION.value,
                side=open_pos.side,
                contracts=open_pos.contracts,
                stop_loss_price=None,
                take_profit_price=None,
                target_id=position_id,
            )
            order_req = TradovateOrderRequest(
                request_id=request_id,
                cl_ord_id=cl_ord_id,
                action=FuturesOrderAction.CLOSE_POSITION,
                contract_code=open_pos.contract_code,
                root_symbol=open_pos.root_symbol,
                cas_symbol=open_pos.cas_symbol,
                side=open_pos.side,
                contracts=open_pos.contracts,
                position_id=position_id,
                client_tag=reason,
                created_at=now,
            )
            req_json = canonical_bytes(order_req.to_dict()).decode("utf-8")
            ts_str = _iso_utc(now)

            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    dup_row = conn.execute(
                        "SELECT request_id, status FROM mutation_journal WHERE cl_ord_id = ?",
                        (cl_ord_id,),
                    ).fetchone()
                    if dup_row is not None:
                        dup_status = str(dup_row["status"])
                        conn.execute("COMMIT")
                        if dup_status in _UNRESOLVED_MUTATION_STATUSES:
                            raise TradovateOutcomeUnknownError(
                                f"Duplicate close clOrdId {cl_ord_id!r} already in unresolved state {dup_status!r}",
                                cl_ord_id=cl_ord_id,
                                request_id=str(dup_row["request_id"]),
                            )
                        raise TradovateOrderError(
                            f"Duplicate idempotent close clOrdId {cl_ord_id!r} already committed "
                            f"(request_id={dup_row['request_id']}, status={dup_status})"
                        )
                    conn.execute(
                        "INSERT INTO mutation_journal "
                        "(request_id, cl_ord_id, action, contract_code, root_symbol, cas_symbol, status, "
                        "request_json, receipt_json, error_detail, reconciled_at, reconciliation_json, "
                        "created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                        (
                            request_id,
                            cl_ord_id,
                            order_req.action.value,
                            order_req.contract_code,
                            order_req.root_symbol,
                            order_req.cas_symbol,
                            MUTATION_STATUS_PENDING,
                            req_json,
                            ts_str,
                            ts_str,
                        ),
                    )
                    conn.execute("COMMIT")
                except (TradovateOutcomeUnknownError, TradovateOrderError):
                    raise
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise

            try:
                raw_receipt = self._transport.send_order(order_req)
            except LiveAuthorizationError as exc:
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, error_detail = ?, updated_at = ? "
                            "WHERE request_id = ?",
                            ("REFUSED_LIVE_AUTH", str(exc), _iso_utc(self._clock()), request_id),
                        )
                        self._append_audit_unlocked(
                            conn,
                            event_type="PROTECTIVE_REFUSED_LIVE_AUTH",
                            entity_id=request_id,
                            payload={"cl_ord_id": cl_ord_id, "error": str(exc)},
                            occurred_at=self._clock(),
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
                raise
            except Exception as exc:
                http_status = getattr(exc, "http_status", None)
                detail = f"AMBIGUOUS_PROTECTIVE_CLOSE_OUTCOME ({type(exc).__name__}): {exc}"
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                    event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                    detail=detail,
                    now=self._clock(),
                )
                raise TradovateOutcomeUnknownError(
                    f"Tradovate protective close outcome unknown for clOrdId={cl_ord_id} ({detail}); "
                    "safety freeze engaged until reconciled",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                    http_status=http_status,
                ) from None

            failure = self._validate_protective_receipt(
                raw_receipt,
                expected_action=FuturesOrderAction.CLOSE_POSITION,
                expected_cl_ord_id=cl_ord_id,
            )
            if failure is not None:
                self._record_unresolved_latch(
                    request_id=request_id,
                    cl_ord_id=cl_ord_id,
                    status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                    event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                    detail=failure,
                    now=self._clock(),
                    order_id=getattr(raw_receipt, "order_id", None) if isinstance(raw_receipt, TradovateOrderReceipt) else None,
                )
                raise TradovateOutcomeUnknownError(
                    f"Tradovate protective close failed validation for clOrdId={cl_ord_id} ({failure}); "
                    "safety freeze engaged until reconciled",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                )

            receipt = TradovateOrderReceipt(
                request_id=raw_receipt.request_id,
                cl_ord_id=cl_ord_id,
                action=raw_receipt.action,
                accepted=raw_receipt.accepted,
                status=raw_receipt.status,
                order_id=raw_receipt.order_id,
                position_id=raw_receipt.position_id or position_id,
                contract_code=raw_receipt.contract_code or open_pos.contract_code,
                root_symbol=raw_receipt.root_symbol or open_pos.root_symbol,
                cas_symbol=raw_receipt.cas_symbol or open_pos.cas_symbol,
                side=raw_receipt.side or open_pos.side,
                filled_contracts=raw_receipt.filled_contracts,
                fill_price=raw_receipt.fill_price,
                stop_loss_price=raw_receipt.stop_loss_price,
                take_profit_price=raw_receipt.take_profit_price,
                commission_usd=raw_receipt.commission_usd,
                realized_pnl_usd=raw_receipt.realized_pnl_usd,
                net_pnl_usd=raw_receipt.net_pnl_usd,
                reason=raw_receipt.reason,
                executed_at=raw_receipt.executed_at,
            )
            rec_json = canonical_bytes(receipt.to_dict()).decode("utf-8")
            try:
                peak_candidate = Decimal("0.00")
                if isinstance(self._transport, TradovateMicroFuturesPaperEmulator) and self._transport.is_connected():
                    acct = self._validate_account_snapshot(
                        self._transport.account_snapshot(now_utc=receipt.executed_at),
                        expected_account_id=auth_acct,
                    )
                    peak_candidate = max(acct.peak_equity_usd, acct.equity_usd)
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE mutation_journal SET status = ?, receipt_json = ?, updated_at = ? "
                            "WHERE request_id = ?",
                            (receipt.status, rec_json, _iso_utc(receipt.executed_at), request_id),
                        )
                        if peak_candidate > Decimal("0.00"):
                            self._update_peak_equity_unlocked(conn, peak_candidate, receipt.executed_at)
                        self._append_audit_unlocked(
                            conn,
                            event_type="PROTECTIVE_POSITION_CLOSED",
                            entity_id=request_id,
                            payload={"receipt": receipt.to_dict()},
                            occurred_at=receipt.executed_at,
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
            except Exception as exc:
                detail = f"POST_EFFECT_CLOSE_JOURNAL_FAILURE ({type(exc).__name__}): {exc}"
                try:
                    self._record_unresolved_latch(
                        request_id=request_id,
                        cl_ord_id=cl_ord_id,
                        status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                        event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                        detail=detail,
                        now=self._clock(),
                        order_id=receipt.order_id,
                    )
                except Exception as exc_rec:
                    detail = f"{detail}; fallback_record_err={type(exc_rec).__name__}"
                raise TradovateOutcomeUnknownError(
                    f"Tradovate post-close journal failure for clOrdId={cl_ord_id} ({detail}); "
                    "safety freeze engaged until reconciled",
                    cl_ord_id=cl_ord_id,
                    request_id=request_id,
                ) from None
            return receipt

    def emergency_close_all(
        self,
        *,
        reason: str = "PROTECTIVE_EMERGENCY_CLOSE_ALL",
        idempotency_key: str | None = None,
        now_utc: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        """Protective emergency flatten of all open positions with independent per-leg journaling."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ContractError("idempotency_key must be a non-empty string when provided")
            _check_no_control_chars(idempotency_key, "idempotency_key")

        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate transport is disconnected")
            auth_acct = self._authorized_account_id()
            open_positions = self._validate_positions_ownership(
                self._transport.positions(),
                expected_account_id=auth_acct,
            )
            base_req_id = self._next_request_id("emergency")
            if not open_positions:
                self._record_audit_event(
                    event_type="PROTECTIVE_EMERGENCY_CLOSE_EMPTY",
                    entity_id=base_req_id,
                    payload={"account_id": auth_acct, "reason": str(reason)},
                    now=now,
                )
                return ()

            base_key = idempotency_key.strip() if idempotency_key is not None else base_req_id
            receipts: list[TradovateOrderReceipt] = []
            leg_failures: list[tuple[str, str, str]] = []

            for pos in open_positions:
                leg_req_id = self._next_request_id("emerg")
                leg_cl_ord_id = _compute_stable_cl_ord_id(
                    account_id=auth_acct,
                    idempotency_key=f"{base_key}:leg:{pos.position_id}",
                    contract_code=pos.contract_code,
                    action=FuturesOrderAction.CLOSE_POSITION.value,
                    side=pos.side,
                    contracts=pos.contracts,
                    stop_loss_price=None,
                    take_profit_price=None,
                    target_id=pos.position_id,
                )
                leg_req = TradovateOrderRequest(
                    request_id=leg_req_id,
                    cl_ord_id=leg_cl_ord_id,
                    action=FuturesOrderAction.CLOSE_POSITION,
                    contract_code=pos.contract_code,
                    root_symbol=pos.root_symbol,
                    cas_symbol=pos.cas_symbol,
                    side=pos.side,
                    contracts=pos.contracts,
                    position_id=pos.position_id,
                    client_tag=reason,
                    created_at=now,
                )
                leg_req_json = canonical_bytes(leg_req.to_dict()).decode("utf-8")
                ts_str = _iso_utc(now)

                skip_leg = False
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        dup_row = conn.execute(
                            "SELECT request_id, status FROM mutation_journal WHERE cl_ord_id = ?",
                            (leg_cl_ord_id,),
                        ).fetchone()
                        if dup_row is not None:
                            dup_status = str(dup_row["status"])
                            conn.execute("COMMIT")
                            leg_failures.append(
                                (
                                    str(dup_row["request_id"]),
                                    leg_cl_ord_id,
                                    f"duplicate clOrdId already in status {dup_status!r}",
                                )
                            )
                            skip_leg = True
                        else:
                            conn.execute(
                                "INSERT INTO mutation_journal "
                                "(request_id, cl_ord_id, action, contract_code, root_symbol, cas_symbol, status, "
                                "request_json, receipt_json, error_detail, reconciled_at, reconciliation_json, "
                                "created_at, updated_at) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                                (
                                    leg_req_id,
                                    leg_cl_ord_id,
                                    leg_req.action.value,
                                    leg_req.contract_code,
                                    leg_req.root_symbol,
                                    leg_req.cas_symbol,
                                    MUTATION_STATUS_PENDING,
                                    leg_req_json,
                                    ts_str,
                                    ts_str,
                                ),
                            )
                            conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise

                if skip_leg:
                    continue

                try:
                    raw_leg = self._transport.send_order(leg_req)
                except Exception as exc:
                    detail = f"AMBIGUOUS_EMERGENCY_LEG_OUTCOME ({type(exc).__name__}): {exc}"
                    try:
                        self._record_unresolved_latch(
                            request_id=leg_req_id,
                            cl_ord_id=leg_cl_ord_id,
                            status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                            event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                            detail=detail,
                            now=self._clock(),
                        )
                    except Exception as exc_rec:
                        detail = f"{detail}; fallback_record_err={type(exc_rec).__name__}"
                    leg_failures.append((leg_req_id, leg_cl_ord_id, detail))
                    continue

                leg_err = self._validate_protective_receipt(
                    raw_leg,
                    expected_action=FuturesOrderAction.CLOSE_POSITION,
                    expected_cl_ord_id=leg_cl_ord_id,
                )
                if leg_err is not None:
                    try:
                        self._record_unresolved_latch(
                            request_id=leg_req_id,
                            cl_ord_id=leg_cl_ord_id,
                            status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                            event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                            detail=leg_err,
                            now=self._clock(),
                            order_id=getattr(raw_leg, "order_id", None) if isinstance(raw_leg, TradovateOrderReceipt) else None,
                        )
                    except Exception as exc_rec:
                        leg_err = f"{leg_err}; fallback_record_err={type(exc_rec).__name__}"
                    leg_failures.append((leg_req_id, leg_cl_ord_id, leg_err))
                    continue

                leg_receipt = TradovateOrderReceipt(
                    request_id=raw_leg.request_id,
                    cl_ord_id=leg_cl_ord_id,
                    action=raw_leg.action,
                    accepted=raw_leg.accepted,
                    status=raw_leg.status,
                    order_id=raw_leg.order_id,
                    position_id=raw_leg.position_id or pos.position_id,
                    contract_code=raw_leg.contract_code or pos.contract_code,
                    root_symbol=raw_leg.root_symbol or pos.root_symbol,
                    cas_symbol=raw_leg.cas_symbol or pos.cas_symbol,
                    side=raw_leg.side or pos.side,
                    filled_contracts=raw_leg.filled_contracts,
                    fill_price=raw_leg.fill_price,
                    stop_loss_price=raw_leg.stop_loss_price,
                    take_profit_price=raw_leg.take_profit_price,
                    commission_usd=raw_leg.commission_usd,
                    realized_pnl_usd=raw_leg.realized_pnl_usd,
                    net_pnl_usd=raw_leg.net_pnl_usd,
                    reason=raw_leg.reason,
                    executed_at=raw_leg.executed_at,
                )
                leg_rec_json = canonical_bytes(leg_receipt.to_dict()).decode("utf-8")
                try:
                    peak_candidate = Decimal("0.00")
                    if isinstance(self._transport, TradovateMicroFuturesPaperEmulator) and self._transport.is_connected():
                        acct = self._validate_account_snapshot(
                            self._transport.account_snapshot(now_utc=leg_receipt.executed_at),
                            expected_account_id=auth_acct,
                        )
                        peak_candidate = max(acct.peak_equity_usd, acct.equity_usd)
                    with closing(self._connect_rw()) as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        try:
                            conn.execute(
                                "UPDATE mutation_journal SET status = ?, receipt_json = ?, updated_at = ? "
                                "WHERE request_id = ?",
                                (leg_receipt.status, leg_rec_json, _iso_utc(leg_receipt.executed_at), leg_req_id),
                            )
                            if peak_candidate > Decimal("0.00"):
                                self._update_peak_equity_unlocked(conn, peak_candidate, leg_receipt.executed_at)
                            self._append_audit_unlocked(
                                conn,
                                event_type="PROTECTIVE_EMERGENCY_CLOSE",
                                entity_id=leg_req_id,
                                payload={"receipt": leg_receipt.to_dict()},
                                occurred_at=leg_receipt.executed_at,
                            )
                            conn.execute("COMMIT")
                        except Exception:
                            if conn.in_transaction:
                                conn.execute("ROLLBACK")
                            raise
                except Exception as exc:
                    detail = f"POST_EFFECT_EMERGENCY_LEG_JOURNAL_FAILURE ({type(exc).__name__}): {exc}"
                    try:
                        self._record_unresolved_latch(
                            request_id=leg_req_id,
                            cl_ord_id=leg_cl_ord_id,
                            status=MUTATION_STATUS_OUTCOME_UNKNOWN,
                            event_type="PROTECTIVE_OUTCOME_UNKNOWN",
                            detail=detail,
                            now=self._clock(),
                            order_id=leg_receipt.order_id,
                        )
                    except Exception as exc_rec:
                        detail = f"{detail}; fallback_record_err={type(exc_rec).__name__}"
                    leg_failures.append((leg_req_id, leg_cl_ord_id, detail))
                    continue

                receipts.append(leg_receipt)

            if leg_failures:
                summary = "; ".join(f"{rid}({cid}): {msg}" for rid, cid, msg in leg_failures)
                raise TradovateOutcomeUnknownError(
                    f"Tradovate emergency_close_all left {len(leg_failures)}/{len(open_positions)} "
                    f"leg(s) unresolved ({summary}); safety freeze engaged until reconciled",
                    cl_ord_id=leg_failures[0][1],
                    request_id=leg_failures[0][0],
                )
            return tuple(receipts)

    def process_market_quote(
        self,
        symbol: str,
        bid: Decimal,
        ask: Decimal,
        *,
        now_utc: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        """Push a quote into an attached paper emulator and journal any triggered OCO fills."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            if not isinstance(self._transport, TradovateMicroFuturesPaperEmulator):
                raise TradovateTransportError(
                    "process_market_quote() is supported only with TradovateMicroFuturesPaperEmulator"
                )
            auth_acct = self._authorized_account_id()
            triggered = self._transport.set_quote(symbol, bid, ask, observed_at=now)
            for r in triggered:
                req = TradovateOrderRequest(
                    request_id=r.request_id,
                    cl_ord_id=r.cl_ord_id,
                    action=r.action,
                    contract_code=r.contract_code,
                    root_symbol=r.root_symbol,
                    cas_symbol=r.cas_symbol,
                    side=r.side,
                    contracts=r.filled_contracts,
                    position_id=r.position_id,
                    client_tag=r.reason,
                    created_at=r.executed_at,
                )
                self._persist_protective_mutation(
                    req, r, event_type=f"OCO_{r.status}", expected_account_id=auth_acct
                )
            return triggered

    def _persist_protective_mutation(
        self,
        order_req: TradovateOrderRequest,
        receipt: TradovateOrderReceipt,
        *,
        event_type: str,
        expected_account_id: str | None = None,
    ) -> None:
        req_json = canonical_bytes(order_req.to_dict()).decode("utf-8")
        rec_json = canonical_bytes(receipt.to_dict()).decode("utf-8")
        ts_str = _iso_utc(receipt.executed_at)
        peak_candidate = Decimal("0.00")
        if self._transport.is_connected():
            raw_acct = self._transport.account_snapshot(now_utc=receipt.executed_at)
            eff_acct = expected_account_id or self._authorized_account_id()
            acct = self._validate_account_snapshot(raw_acct, expected_account_id=eff_acct)
            peak_candidate = max(acct.peak_equity_usd, acct.equity_usd)
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO mutation_journal "
                    "(request_id, cl_ord_id, action, contract_code, root_symbol, cas_symbol, status, "
                    "request_json, receipt_json, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        order_req.request_id,
                        order_req.cl_ord_id,
                        order_req.action.value,
                        order_req.contract_code,
                        order_req.root_symbol,
                        order_req.cas_symbol,
                        receipt.status,
                        req_json,
                        rec_json,
                        ts_str,
                        ts_str,
                    ),
                )
                if peak_candidate > Decimal("0.00"):
                    self._update_peak_equity_unlocked(conn, peak_candidate, receipt.executed_at)
                self._append_audit_unlocked(
                    conn,
                    event_type=event_type,
                    entity_id=order_req.request_id,
                    payload={"receipt": receipt.to_dict()},
                    occurred_at=receipt.executed_at,
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def replenish_demo_capital(
        self,
        target_balance_usd: Decimal,
        *,
        reason: str = "DEMO_CAPITAL_REPLENISHED",
        execution_mode: str = TRADOVATE_MODE_DEMO,
        live_trading_armed: bool = False,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Replenish DEMO paper balance & re-anchor venue peak equity with hash-chained audit trail."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        if type(live_trading_armed) is not bool:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        norm_exec_mode = str(execution_mode).strip().upper()
        if self._mode != TRADOVATE_MODE_DEMO or norm_exec_mode != TRADOVATE_MODE_DEMO or live_trading_armed:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        if not isinstance(self._transport, TradovateMicroFuturesPaperEmulator):
            raise ContractError("DEMO_REPLENISH_REQUIRES_PAPER_EMULATOR")
        clean_reason = reason.strip() if isinstance(reason, str) and reason.strip() else "DEMO_CAPITAL_REPLENISHED"
        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate paper emulator is disconnected")
            if self._transport.positions():
                raise ContractError(DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS)
            res = self._transport.replenish_demo_capital(
                target_balance_usd,
                reason=clean_reason,
                now_utc=now,
            )
            if res["replenished"]:
                ts_str = _iso_utc(now)
                with closing(self._connect_rw()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            "UPDATE venue_meta SET peak_equity_usd = ?, updated_at = ? WHERE id = 1",
                            (str(res["new_peak_equity_usd"]), ts_str),
                        )
                        self._append_audit_unlocked(
                            conn,
                            event_type="DEMO_CAPITAL_REPLENISHED",
                            entity_id=self._authorized_account_id(),
                            payload=res,
                            occurred_at=now,
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise
            return res

    # -- Strictly 0-Write Read-Only Snapshot & SHA-256 Audit Chain Verification --

    def _verify_audit_rows(self, rows: list[sqlite3.Row]) -> bool:
        expected_prev = GENESIS_AUDIT_SHA256
        for row in rows:
            prev_sha = str(row["prev_sha256"])
            stored_sha = str(row["entry_sha256"])
            if not hmac.compare_digest(prev_sha, expected_prev):
                return False
            recomputed = self._compute_audit_sha256(
                prev_sha256=prev_sha,
                event_type=str(row["event_type"]),
                entity_id=str(row["entity_id"]),
                payload_bytes=str(row["payload_json"]).encode("utf-8"),
                occurred_at=str(row["occurred_at"]),
            )
            if not hmac.compare_digest(stored_sha, recomputed):
                return False
            expected_prev = recomputed
        return True

    def verify_audit_chain(self) -> bool:
        """Strictly read-only (?mode=ro) verification of the SHA-256 audit chain."""
        with self._lock, closing(self._connect_ro()) as conn:
            rows = conn.execute(
                "SELECT seq, event_type, entity_id, payload_json, occurred_at, "
                "prev_sha256, entry_sha256 FROM audit_events ORDER BY seq ASC"
            ).fetchall()
        return self._verify_audit_rows(rows)

    def snapshot(self, *, now_utc: datetime | None = None) -> dict[str, Any]:
        """Strictly 0-write (?mode=ro + PRAGMA query_only=ON) venue snapshot.

        Never mutates SQLite (preserves ``PRAGMA data_version``) and never fakes
        ``$0.00`` account balances when transport is disconnected.
        """
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock, closing(self._connect_ro()) as conn:
            meta = conn.execute(
                "SELECT broker_id, regulated_jurisdiction, enabled, mode, base_url, "
                "peak_equity_usd, max_drawdown_pct, min_margin_level_pct FROM venue_meta WHERE id = 1"
            ).fetchone()
            mutation_row = conn.execute("SELECT COUNT(*) AS cnt FROM mutation_journal").fetchone()
            unresolved_mutations = self._query_unresolved_mutations_unlocked(conn)
            active_latches = self._query_active_latches_unlocked(conn)
            audit_rows = conn.execute(
                "SELECT seq, event_type, entity_id, payload_json, occurred_at, "
                "prev_sha256, entry_sha256 FROM audit_events ORDER BY seq ASC"
            ).fetchall()

        audit_valid = self._verify_audit_rows(audit_rows)
        mutation_count = int(mutation_row["cnt"]) if mutation_row is not None else 0
        stored_peak = (
            _exact_decimal(str(meta["peak_equity_usd"]), "peak_equity_usd", non_negative=True)
            if meta is not None
            else Decimal("0.00")
        )

        connected = self._transport.is_connected()
        account_dict: dict[str, Any] | None = None
        positions_list: list[dict[str, Any]] = []
        drawdown_str: str | None = None
        drawdown_locked = False
        effective_peak = stored_peak

        if connected:
            auth_acct = self._authorized_account_id()
            acct = self._validate_account_snapshot(
                self._transport.account_snapshot(now_utc=now),
                expected_account_id=auth_acct,
            )
            effective_peak = _q2(max(stored_peak, acct.peak_equity_usd, acct.equity_usd))
            eff_dd = compute_drawdown_pct(acct.equity_usd, effective_peak)
            drawdown_str = decimal_text(_q4(eff_dd))
            drawdown_locked = eff_dd >= self._max_drawdown_pct
            account_dict = acct.to_dict()
            account_dict["peak_equity_usd"] = decimal_text(effective_peak)
            account_dict["drawdown_pct"] = drawdown_str
            verified_positions = self._validate_positions_ownership(
                self._transport.positions(),
                expected_account_id=auth_acct,
            )
            positions_list = [p.to_dict() for p in verified_positions]
            conn_status = (
                CONNECTION_STATUS_STANDBY if not self._enabled else CONNECTION_STATUS_CONNECTED
            )
        else:
            conn_status = (
                CONNECTION_STATUS_STANDBY if not self._enabled else CONNECTION_STATUS_DISCONNECTED
            )

        contract_mappings = {
            translate_micro_root_to_cas_symbol(root): root
            for root in TRADOVATE_SUPPORTED_CONTRACTS
        }
        front_months = {
            root: resolve_front_month_contract(
                root,
                as_of_utc=now,
                roll_buffer_days=self._roll_buffer_days,
            ).contract_code
            for root in TRADOVATE_SUPPORTED_CONTRACTS
        }

        return {
            "broker_id": TRADOVATE_BROKER_ID,
            "regulated_jurisdiction": TRADOVATE_REGULATED_JURISDICTION,
            "status": self.venue_status,
            "enabled": self._enabled,
            "mode": self._mode,
            "base_url": self._base_url,
            "connected": connected,
            "connection_status": conn_status,
            "supported_contracts": TRADOVATE_SUPPORTED_CONTRACTS,
            "contract_mappings": contract_mappings,
            "front_month_contracts": front_months,
            "account": account_dict,
            "positions": positions_list,
            "peak_equity_usd": (
                decimal_text(effective_peak) if connected or effective_peak > Decimal("0.00") else None
            ),
            "drawdown_pct": drawdown_str,
            "max_drawdown_pct": decimal_text(self._max_drawdown_pct),
            "min_margin_level_pct": decimal_text(self._min_margin_level_pct),
            "drawdown_locked": drawdown_locked,
            "outcome_unknown_freeze": any(
                item["status"] in (MUTATION_STATUS_OUTCOME_UNKNOWN, MUTATION_STATUS_PENDING)
                for item in unresolved_mutations
            ) or any(l["latch_kind"] == MUTATION_STATUS_OUTCOME_UNKNOWN for l in active_latches),
            "protection_unconfirmed_latch": any(
                item["status"] == MUTATION_STATUS_PROTECTION_UNCONFIRMED
                for item in unresolved_mutations
            ) or any(l["latch_kind"] == MUTATION_STATUS_PROTECTION_UNCONFIRMED for l in active_latches),
            "unresolved_mutation_count": len(unresolved_mutations),
            "unresolved_mutations": unresolved_mutations,
            "max_quote_age_seconds": decimal_text(self._max_quote_age_seconds),
            "valve_configured": self._valve_gate is not None,
            "valve_cutoff": decimal_text(VALVE_ADMISSIBILITY_CUTOFF),
            "audit_chain_valid": audit_valid,
            "audit_event_count": len(audit_rows),
            "mutation_count": mutation_count,
            "observed_at": _iso_utc(now),
        }

    def status_snapshot(self, *, now_utc: datetime | None = None) -> dict[str, Any]:
        """Alias for strictly 0-write ``snapshot()``."""
        return self.snapshot(now_utc=now_utc)
