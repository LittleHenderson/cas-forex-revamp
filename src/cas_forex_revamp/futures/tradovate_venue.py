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
   ``https://live.tradovateapi.com/v1`` (``LIVE``, requiring explicit
   ``live_arming_verified=True``) are permitted. Rejects ``http://``,
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

from collections.abc import Callable, Mapping
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
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    ValveDecision,
    ValveRefusalError,
    compute_drawdown_pct,
    load_default_forex_valve_gate,
    validate_constitutional_drawdown_pct,
)
from cas_forex_revamp.venue.live_market_stream import verify_public_ip_address

__all__ = [
    "CONNECTION_STATUS_CONNECTED",
    "CONNECTION_STATUS_DISCONNECTED",
    "CONNECTION_STATUS_STANDBY",
    "DEFAULT_PAPER_STARTING_EQUITY_USD",
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
    "PINNED_TRADOVATE_HOSTS",
    "TRADOVATE_BROKER_ID",
    "TRADOVATE_DEMO_BASE_URL",
    "TRADOVATE_DEMO_HOST",
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
    "TradovatePosition",
    "TradovateQuote",
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
]

TRADOVATE_BROKER_ID = "TRADOVATE_MICRO_FUTURES"
TRADOVATE_REGULATED_JURISDICTION = "US_CFTC_NFA"
TRADOVATE_SUPPORTED_CONTRACTS: tuple[str, ...] = ("MNQ", "MYM", "MES", "MGC")

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
GENESIS_AUDIT_SHA256 = "0" * 64

ENV_TRADOVATE_ENABLED = "CAS_FOREX_TRADOVATE_ENABLED"
ENV_TRADOVATE_MODE = "CAS_FOREX_TRADOVATE_MODE"
ENV_TRADOVATE_USERNAME = "CAS_FOREX_TRADOVATE_USERNAME"
ENV_TRADOVATE_PASSWORD = "CAS_FOREX_TRADOVATE_PASSWORD"  # nosec B105: env var name constant, not a secret
ENV_TRADOVATE_APP_ID = "CAS_FOREX_TRADOVATE_APP_ID"
ENV_TRADOVATE_CID = "CAS_FOREX_TRADOVATE_CID"
ENV_TRADOVATE_SEC = "CAS_FOREX_TRADOVATE_SEC"  # nosec B105: env var name constant, not a secret
ENV_TRADOVATE_BASE_URL = "CAS_FOREX_TRADOVATE_BASE_URL"

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


class TradovateLiveLockError(TradovateEndpointError):
    """Raised when LIVE mode or live host is accessed without live arming clearance."""


class TradovateNotConfiguredError(TradovateVenueError):
    """Raised when required credentials or runtime configuration are missing."""


class TradovateTransportError(TradovateVenueError):
    """Raised on HTTPS transport failures, disconnects, or refused redirects."""


class TradovateDrawdownLockError(TradovateVenueError):
    """Raised when portfolio drawdown reaches or exceeds the constitutional 10% cap."""


class TradovateMarginRefusalError(TradovateVenueError):
    """Raised when post-trade margin level falls below the constitutional floor."""


class TradovateOrderError(TradovateVenueError):
    """Raised on invalid order geometry, unknown position ID, or execution error."""


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


# ---------------------------------------------------------------------------
# 1. Strict Endpoint Pinning & Redacted Credentials
# ---------------------------------------------------------------------------


def validate_tradovate_endpoint(
    mode: str,
    base_url: str,
    *,
    live_arming_verified: bool = False,
) -> str:
    """Validate and canonicalize a pinned Tradovate HTTPS API base URL.

    Enforces:
    - ``https://`` scheme ONLY (rejects ``http://``, ``file://``, etc.)
    - Zero embedded credentials, query strings, fragments, or control chars
    - Default HTTPS port (443) only
    - Zero localhost, IP literals, private/link-local hosts, or unpinned domains
    - ``DEMO`` mode MUST pin ``demo.tradovateapi.com`` (refuses live host)
    - ``LIVE`` mode MUST pin ``live.tradovateapi.com`` AND require
      ``live_arming_verified=True`` (otherwise raises ``TradovateLiveLockError``)
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
        if not live_arming_verified:
            raise TradovateLiveLockError(
                "LIVE Tradovate mode requires explicit live_arming_verified=True clearance"
            )
        if hostname != TRADOVATE_LIVE_HOST:
            raise TradovateEndpointError(
                f"LIVE mode requires pinned host {TRADOVATE_LIVE_HOST!r}, got {hostname!r}"
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
    """Immutable Tradovate configuration defaulting to STANDBY (enabled=False)."""

    enabled: bool = False
    mode: str = TRADOVATE_MODE_DEMO
    base_url: str = TRADOVATE_DEMO_BASE_URL
    live_arming_verified: bool = False
    username: str = ""
    password: _RedactedSecret | None = None
    app_id: str = ""
    cid: str = ""
    sec: _RedactedSecret | None = None
    bearer_token: _RedactedSecret | None = None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ContractError("enabled must be a bool")
        if type(self.live_arming_verified) is not bool:
            raise TradovateLiveLockError("live_arming_verified must be a bool")
        norm_mode = _normalize_mode(self.mode)
        canonical_url = validate_tradovate_endpoint(
            norm_mode,
            self.base_url,
            live_arming_verified=self.live_arming_verified,
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

    def has_api_credentials(self) -> bool:
        return bool(
            self.username.strip()
            and self.password is not None
            and self.app_id.strip()
            and self.cid.strip()
            and self.sec is not None
        )

    def __repr__(self) -> str:
        return (
            f"TradovateCredentials(enabled={self.enabled!r}, mode={self.mode!r}, "
            f"base_url={self.base_url!r}, live_arming_verified={self.live_arming_verified!r}, "
            f"username={self.username!r}, password={'[REDACTED]' if self.password is not None else None}, "
            f"app_id={self.app_id!r}, cid={self.cid!r}, "
            f"sec={'[REDACTED]' if self.sec is not None else None}, "
            f"bearer_token={'[REDACTED]' if self.bearer_token is not None else None})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def load_tradovate_credentials(
    environ: Mapping[str, str] | None = None,
    *,
    live_arming_verified: bool = False,
) -> TradovateCredentials:
    """Load optional Tradovate credentials from environment; defaults to STANDBY.

    When environment variables are unset, returns ``enabled=False`` in ``DEMO``
    mode pointing at ``https://demo.tradovateapi.com/v1`` so existing brokers
    (Hugo's Way / LHFX / OANDA) remain 100% unaffected.
    """
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

    username = str(env.get(ENV_TRADOVATE_USERNAME, "")).strip()
    raw_password = str(env.get(ENV_TRADOVATE_PASSWORD, "")).strip()
    app_id = str(env.get(ENV_TRADOVATE_APP_ID, "")).strip()
    cid = str(env.get(ENV_TRADOVATE_CID, "")).strip()
    raw_sec = str(env.get(ENV_TRADOVATE_SEC, "")).strip()

    password = _RedactedSecret(raw_password) if raw_password else None
    sec = _RedactedSecret(raw_sec) if raw_sec else None

    return TradovateCredentials(
        enabled=enabled,
        mode=mode,
        base_url=raw_base_url,
        live_arming_verified=live_arming_verified,
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
        ts = _utc_now() if self.created_at is None else utc_time(self.created_at, "created_at")
        object.__setattr__(self, "created_at", ts)
        object.__setattr__(self, "request_id", self.request_id.strip())
        object.__setattr__(self, "contract_code", self.contract_code.strip().upper())
        object.__setattr__(self, "root_symbol", self.root_symbol.strip().upper())
        object.__setattr__(self, "cas_symbol", self.cas_symbol.strip().upper())

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
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

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise ContractError("accepted must be bool")
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
            "action": self.action.value,
            "accepted": self.accepted,
            "status": self.status,
            "order_id": self.order_id,
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
        self._base_url = validate_tradovate_endpoint(
            credentials.mode,
            credentials.base_url,
            live_arming_verified=credentials.live_arming_verified,
        )
        self._timeout_seconds = timeout_seconds
        self._max_wire_bytes = max_wire_bytes
        self._clock = clock if clock is not None else _utc_now
        self._bearer_token: _RedactedSecret | None = credentials.bearer_token
        self._connected = False

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def mode(self) -> str:
        return self._credentials.mode

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

    def _request_json(
        self,
        method: str,
        endpoint_path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        require_auth: bool = True,
    ) -> dict[str, Any]:
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

        body_bytes = (
            json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
            if payload is not None
            else None
        )
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = urllib.request.build_opener(
            _PinnedTradovateHTTPSHandler(ctx),
            _NoRedirectHandler(error_cls=TradovateTransportError),
        )
        req = urllib.request.Request(full_url, data=body_bytes, headers=headers, method=method)
        try:
            with opener.open(req, timeout=self._timeout_seconds) as resp:  # nosec B310: strictly pinned https:// Tradovate host
                status = int(getattr(resp, "status", 200))
                if status not in (200, 201):
                    raise TradovateTransportError(f"Tradovate HTTP status {status}")
                raw = resp.read(self._max_wire_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise TradovateTransportError(f"Tradovate HTTP error {exc.code}") from None
        except TradovateVenueError:
            raise
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
            raise TradovateTransportError(
                f"Tradovate HTTPS connection failed: {type(exc).__name__}"
            ) from None
        finally:
            headers.clear()
            req.headers.clear()
            req.unredirected_hdrs.clear()

        if not raw or len(raw) > self._max_wire_bytes:
            raise TradovateTransportError("Tradovate response empty or exceeded max wire bytes")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TradovateTransportError("Tradovate response was not valid UTF-8 JSON") from exc
        if not isinstance(decoded, dict):
            raise TradovateTransportError("Tradovate response root must be a JSON object")
        return decoded

    def connect(self) -> None:
        if self._bearer_token is not None:
            self._connected = True
            return
        if not self._credentials.has_api_credentials():
            raise TradovateNotConfiguredError(
                "Tradovate API credentials (username, password, app_id, cid, sec) are required to connect"
            )
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
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        resp = self._request_json("GET", "cashBalance/getcashbalancesnapshot")
        balance = _exact_decimal(str(resp.get("amount", "0")), "balance_usd")
        open_pnl = _exact_decimal(str(resp.get("openPnL", "0")), "floating_pnl_usd")
        equity = _q2(balance + open_pnl)
        used_margin = _exact_decimal(str(resp.get("initialMargin", "0")), "used_margin_usd", non_negative=True)
        available = _q2(equity - used_margin)
        margin_level = _q2((equity * Decimal("100")) / used_margin) if used_margin > Decimal("0") else None
        return TradovateAccountSnapshot(
            account_id=str(resp.get("accountId", "TRADOVATE-LIVE")),
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
            realized_pnl_usd=_exact_decimal(str(resp.get("realizedPnL", "0")), "realized_pnl_usd"),
            total_commissions_usd=Decimal("0.00"),
            open_position_count=0,
            observed_at=now,
        )

    def positions(self) -> tuple[TradovatePosition, ...]:
        self._require_connected()
        return ()

    def get_quote(self, symbol_or_root: str) -> TradovateQuote:
        self._require_connected()
        raise TradovateTransportError(
            "Live market data quotes must be supplied via Tradovate WebSocket market-data adapter"
        )

    def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
        self._require_connected()
        now = self._clock()
        if request.action is FuturesOrderAction.OPEN_BRACKET:
            resp = self._request_json(
                "POST",
                "order/placeOSO",
                payload={
                    "symbol": request.contract_code,
                    "action": "Buy" if request.side == "BUY" else "Sell",
                    "orderQty": request.contracts,
                    "orderType": "Market",
                    "isAutomated": True,
                },
            )
            order_id = str(resp.get("orderId", request.request_id))
            return TradovateOrderReceipt(
                request_id=request.request_id,
                action=request.action,
                accepted=True,
                status="SUBMITTED",
                order_id=order_id,
                position_id=None,
                contract_code=request.contract_code,
                root_symbol=request.root_symbol,
                cas_symbol=request.cas_symbol,
                side=request.side,
                filled_contracts=request.contracts,
                fill_price=request.entry_price,
                stop_loss_price=request.stop_loss_price,
                take_profit_price=request.take_profit_price,
                commission_usd=Decimal("0.00"),
                realized_pnl_usd=Decimal("0.00"),
                net_pnl_usd=Decimal("0.00"),
                reason="SUBMITTED_HTTPS",
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


class TradovateMicroFuturesPaperEmulator:
    """100% deterministic offline CME micro-futures matching engine (MNQ/MYM/MES/MGC).

    Tracks exact ``Decimal`` equity, balance, peak equity, drawdown, intraday/
    exchange margin, OCO Stop-Loss / Take-Profit triggers on ``set_quote()``,
    round-turn commissions (``$1.24``/contract from ``micro_futures_specs``),
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
    ) -> TradovateOrderReceipt:
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

        return TradovateOrderReceipt(
            request_id=request_id,
            action=action,
            accepted=True,
            status=status,
            order_id=self._next_order_id(),
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
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            self._require_connected()
            pos = self._positions.get(position_id)
            if pos is None:
                raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
            aligned_sl = align_price_to_tick(
                pos.root_symbol,
                _exact_decimal(new_stop_loss_price, "new_stop_loss_price", positive=True),
            )
            pos.stop_loss_price = aligned_sl
            pos.updated_at = now
            return TradovateOrderReceipt(
                request_id=request_id or f"amend-{position_id}-{self._order_seq + 1}",
                action=FuturesOrderAction.AMEND_STOP,
                accepted=True,
                status="AMENDED",
                order_id=self._next_order_id(),
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

    def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
        if not isinstance(request, TradovateOrderRequest):
            raise ContractError("request must be TradovateOrderRequest")
        now = self._clock() if request.created_at is None else request.created_at

        if request.action is FuturesOrderAction.OPEN_BRACKET:
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

                margin_req = _q2(self._margin_per_contract(spec) * Decimal(request.contracts))
                round_turn_comm = _q2(spec.default_round_turn_commission_usd * Decimal(request.contracts))
                pos_id = self._next_position_id()
                ord_id = self._next_order_id()
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
                )
                self._current_equity_unlocked()
                return TradovateOrderReceipt(
                    request_id=request.request_id,
                    action=FuturesOrderAction.OPEN_BRACKET,
                    accepted=True,
                    status="FILLED",
                    order_id=ord_id,
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

        if request.action is FuturesOrderAction.AMEND_STOP:
            if not request.position_id or request.stop_loss_price is None:
                raise TradovateOrderError("AMEND_STOP requires position_id and stop_loss_price")
            return self.amend_stop(
                request.position_id,
                request.stop_loss_price,
                request_id=request.request_id,
                now_utc=now,
            )

        if request.action is FuturesOrderAction.CLOSE_POSITION:
            if not request.position_id:
                raise TradovateOrderError("CLOSE_POSITION requires position_id")
            return self.close_position(
                request.position_id,
                reason=request.client_tag or "CLOSE_POSITION",
                request_id=request.request_id,
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
) -> DecisionProposal:
    """Build a genuine typed DecisionProposal for ForexMetaValveGate evaluation."""
    valid_until = now + timedelta(seconds=120)
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
        observed_at=now,
        valid_until=valid_until,
        venue_sequence=max(1, seq),
    )
    obs_obj = {
        "symbol": root_symbol,
        "contract_code": contract_code,
        "bid": decimal_text(quote.bid),
        "ask": decimal_text(quote.ask),
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
        observed_at=now,
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
        created_at=now,
        expires_at=valid_until,
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
    provenance = DecisionProvenance(
        DecisionOrigin.POLICY,
        "tradovate-micro-futures-venue",
        content_digest(request),
        content_digest(selection),
        "tradovate-venue-v1",
        now,
        now,
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
        live_arming_verified: bool = False,
        max_drawdown_pct: Decimal = MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
        min_margin_level_pct: Decimal = DEFAULT_MIN_MARGIN_LEVEL_PCT,
        roll_buffer_days: int = 7,
        use_exchange_margin: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(roll_buffer_days) is not int or roll_buffer_days < 0:
            raise ContractError("roll_buffer_days must be a non-negative integer")
        if enabled is not None and type(enabled) is not bool:
            raise ContractError("enabled must be a strict bool or None")
        if type(live_arming_verified) is not bool:
            raise TradovateLiveLockError("live_arming_verified must be a strict bool")
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

        if credentials is not None:
            if not isinstance(credentials, TradovateCredentials):
                raise ContractError("credentials must be TradovateCredentials")
            eff_enabled = credentials.enabled if enabled is None else enabled
            eff_mode = _normalize_mode(mode) if mode is not None else credentials.mode
            eff_live_arm = live_arming_verified or credentials.live_arming_verified
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
                live_arming_verified=eff_live_arm,
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
            eff_creds = TradovateCredentials(
                enabled=eff_enabled,
                mode=eff_mode,
                base_url=eff_base_url,
                live_arming_verified=live_arming_verified,
            )

        self._db_path = Path(db_path)
        self._credentials = eff_creds
        self._enabled = eff_creds.enabled
        self._mode = eff_creds.mode
        self._base_url = eff_creds.base_url
        self._live_arming_verified = eff_creds.live_arming_verified
        self._valve_gate = valve_gate
        self._max_drawdown_pct = dd_cap
        self._min_margin_level_pct = margin_floor
        self._roll_buffer_days = roll_buffer_days
        self._use_exchange_margin = bool(use_exchange_margin)
        self._clock = clock if clock is not None else _utc_now
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
                snap = self._transport.account_snapshot(now_utc=now)
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
                        action TEXT NOT NULL,
                        contract_code TEXT NOT NULL,
                        root_symbol TEXT NOT NULL,
                        cas_symbol TEXT NOT NULL,
                        status TEXT NOT NULL,
                        request_json TEXT NOT NULL,
                        receipt_json TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
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
        live_arming_verified: bool | None = None,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Activate venue from STANDBY_READY into DEMO_ACTIVE or LIVE_ACTIVE."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        if live_arming_verified is not None and type(live_arming_verified) is not bool:
            raise TradovateLiveLockError("live_arming_verified must be a strict bool or None")
        with self._lock:
            target_mode = _normalize_mode(mode) if mode is not None else self._mode
            target_live_arm = (
                self._live_arming_verified
                if live_arming_verified is None
                else live_arming_verified
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
                live_arming_verified=target_live_arm,
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
                acct = self._transport.account_snapshot(now_utc=now)
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
            self._live_arming_verified = target_live_arm
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
        reason: str = "CAS_MICRO_FUTURES_ENTRY",
        policy_overrides: Mapping[str, Any] | None = None,
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Open a tick-aligned, risk-sized, valve-cleared CME micro-futures bracket order."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        norm_side = _normalize_side(side)

        with self._lock:
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
            acct = self._transport.account_snapshot(now_utc=now)
            open_positions = self._transport.positions()
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

            # 5. Live quote, tick alignment, & stop/TP geometry
            quote = self._transport.get_quote(root)
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
            sizing: MicroFuturesSizingResult = size_micro_futures_order(
                symbol_or_root=root,
                equity_usd=acct.equity_usd,
                stop_distance_points=eff_stop_distance,
                risk_pct=risk_pct,
                existing_used_margin_usd=acct.used_margin_usd,
                min_margin_level_pct=self._min_margin_level_pct,
                use_exchange_margin=self._use_exchange_margin,
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

            # 7. Mandatory real ForexMetaValveGate (161 params, 0.55 cutoff)
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

            # 8. Build request, journal PENDING, dispatch, commit receipt & audit chain
            order_req = TradovateOrderRequest(
                request_id=request_id,
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
                created_at=now,
            )
            req_json = canonical_bytes(order_req.to_dict()).decode("utf-8")
            ts_str = _iso_utc(now)

            with closing(self._connect_rw()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "INSERT INTO mutation_journal "
                        "(request_id, action, contract_code, root_symbol, cas_symbol, status, "
                        "request_json, receipt_json, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                        (
                            request_id,
                            order_req.action.value,
                            order_req.contract_code,
                            order_req.root_symbol,
                            order_req.cas_symbol,
                            "PENDING",
                            req_json,
                            ts_str,
                            ts_str,
                        ),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            raw_receipt = self._transport.send_order(order_req)
            receipt = TradovateOrderReceipt(
                request_id=raw_receipt.request_id,
                action=raw_receipt.action,
                accepted=raw_receipt.accepted,
                status=raw_receipt.status,
                order_id=raw_receipt.order_id,
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
                            "valve_mode": valve_decision.valve_mode,
                            "valve_score": decimal_text(valve_score_dec),
                            "valve_weights_sha256": valve_decision.weights_sha256,
                        },
                        occurred_at=receipt.executed_at,
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            return receipt

    # -- Protective Actions (ALWAYS ALLOWED regardless of standby/drawdown/valve) --

    def amend_stop(
        self,
        position_id: str,
        new_stop_loss_price: Decimal,
        *,
        reason: str = "PROTECTIVE_AMEND_STOP",
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Protective stop amendment (e.g. break-even / trail). ALWAYS ALLOWED."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate transport is disconnected")
            open_pos = next((p for p in self._transport.positions() if p.position_id == position_id), None)
            if open_pos is None:
                raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
            aligned_sl = align_price_to_tick(
                open_pos.root_symbol,
                _exact_decimal(new_stop_loss_price, "new_stop_loss_price", positive=True),
            )
            request_id = self._next_request_id("amend")
            order_req = TradovateOrderRequest(
                request_id=request_id,
                action=FuturesOrderAction.AMEND_STOP,
                contract_code=open_pos.contract_code,
                root_symbol=open_pos.root_symbol,
                cas_symbol=open_pos.cas_symbol,
                side=open_pos.side,
                contracts=open_pos.contracts,
                stop_loss_price=aligned_sl,
                position_id=position_id,
                client_tag=reason,
                created_at=now,
            )
            receipt = self._transport.send_order(order_req)
            self._persist_protective_mutation(order_req, receipt, event_type="PROTECTIVE_STOP_AMENDED")
            return receipt

    def close_position(
        self,
        position_id: str,
        *,
        reason: str = "PROTECTIVE_CLOSE_POSITION",
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        """Protective single-position close. ALWAYS ALLOWED."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate transport is disconnected")
            open_pos = next((p for p in self._transport.positions() if p.position_id == position_id), None)
            if open_pos is None:
                raise TradovateOrderError(f"Unknown open position_id: {position_id!r}")
            request_id = self._next_request_id("close")
            order_req = TradovateOrderRequest(
                request_id=request_id,
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
            receipt = self._transport.send_order(order_req)
            self._persist_protective_mutation(order_req, receipt, event_type="PROTECTIVE_POSITION_CLOSED")
            return receipt

    def emergency_close_all(
        self,
        *,
        reason: str = "PROTECTIVE_EMERGENCY_CLOSE_ALL",
        now_utc: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        """Protective emergency flatten of all open positions. ALWAYS ALLOWED."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            if not self._transport.is_connected():
                raise TradovateTransportError("Tradovate transport is disconnected")
            open_positions = self._transport.positions()
            receipts: list[TradovateOrderReceipt] = []
            if isinstance(self._transport, TradovateMicroFuturesPaperEmulator):
                base_req_id = self._next_request_id("emergency")
                receipts.extend(
                    self._transport.emergency_close_all(
                        reason=reason,
                        request_id=base_req_id,
                        now_utc=now,
                    )
                )
                for r in receipts:
                    req = TradovateOrderRequest(
                        request_id=r.request_id,
                        action=FuturesOrderAction.EMERGENCY_CLOSE_ALL,
                        contract_code=r.contract_code,
                        root_symbol=r.root_symbol,
                        cas_symbol=r.cas_symbol,
                        side=r.side,
                        contracts=r.filled_contracts,
                        position_id=r.position_id,
                        client_tag=reason,
                        created_at=now,
                    )
                    self._persist_protective_mutation(req, r, event_type="PROTECTIVE_EMERGENCY_CLOSE")
                if not receipts:
                    empty_req = TradovateOrderRequest(
                        request_id=base_req_id,
                        action=FuturesOrderAction.EMERGENCY_CLOSE_ALL,
                        contract_code="",
                        root_symbol="",
                        cas_symbol="",
                        client_tag=reason,
                        created_at=now,
                    )
                    empty_receipt = TradovateOrderReceipt(
                        request_id=base_req_id,
                        action=FuturesOrderAction.EMERGENCY_CLOSE_ALL,
                        accepted=True,
                        status="EMERGENCY_CLOSED",
                        order_id=f"ORD-EMPTY-{base_req_id}",
                        position_id=None,
                        contract_code="",
                        root_symbol="",
                        cas_symbol="",
                        side=None,
                        filled_contracts=0,
                        fill_price=None,
                        stop_loss_price=None,
                        take_profit_price=None,
                        commission_usd=Decimal("0.00"),
                        realized_pnl_usd=Decimal("0.00"),
                        net_pnl_usd=Decimal("0.00"),
                        reason="NO_OPEN_POSITIONS",
                        executed_at=now,
                    )
                    self._persist_protective_mutation(
                        empty_req, empty_receipt, event_type="PROTECTIVE_EMERGENCY_CLOSE"
                    )
            else:
                for pos in open_positions:
                    receipts.append(self.close_position(pos.position_id, reason=reason, now_utc=now))
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
            triggered = self._transport.set_quote(symbol, bid, ask, observed_at=now)
            for r in triggered:
                req = TradovateOrderRequest(
                    request_id=r.request_id,
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
                self._persist_protective_mutation(req, r, event_type=f"OCO_{r.status}")
            return triggered

    def _persist_protective_mutation(
        self,
        order_req: TradovateOrderRequest,
        receipt: TradovateOrderReceipt,
        *,
        event_type: str,
    ) -> None:
        req_json = canonical_bytes(order_req.to_dict()).decode("utf-8")
        rec_json = canonical_bytes(receipt.to_dict()).decode("utf-8")
        ts_str = _iso_utc(receipt.executed_at)
        peak_candidate = Decimal("0.00")
        if self._transport.is_connected():
            acct = self._transport.account_snapshot(now_utc=receipt.executed_at)
            peak_candidate = max(acct.peak_equity_usd, acct.equity_usd)
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO mutation_journal "
                    "(request_id, action, contract_code, root_symbol, cas_symbol, status, "
                    "request_json, receipt_json, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        order_req.request_id,
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
                conn.execute("ROLLBACK")
                raise

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
            acct = self._transport.account_snapshot(now_utc=now)
            effective_peak = _q2(max(stored_peak, acct.peak_equity_usd, acct.equity_usd))
            eff_dd = compute_drawdown_pct(acct.equity_usd, effective_peak)
            drawdown_str = decimal_text(_q4(eff_dd))
            drawdown_locked = eff_dd >= self._max_drawdown_pct
            account_dict = acct.to_dict()
            account_dict["peak_equity_usd"] = decimal_text(effective_peak)
            account_dict["drawdown_pct"] = drawdown_str
            positions_list = [p.to_dict() for p in self._transport.positions()]
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
