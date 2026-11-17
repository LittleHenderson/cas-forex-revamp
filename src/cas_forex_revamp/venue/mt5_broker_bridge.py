"""MetaTrader 5 demo-only broker bridge for CAS Forex Revamp (Phase 6).

Broker priority hierarchy (demo / practice accounts only):

1. ``HUGOSWAY_MT5`` -- PRIMARY MAIN. Hugo's Way ECN demo on MetaTrader 5, server
   ``Hugo demo PRO5`` (maximum leverage 1:500).
2. ``LHFX_MT5`` -- SECONDARY MT5. LHFX STP/ECN demo on MetaTrader 5, server
   ``LHFXSA-Demo`` (maximum leverage 1:500).
3. ``OANDA_PRACTICE`` -- TERTIARY REST FALLBACK. The existing
   :class:`OandaPracticePaperClient` pinned to ``https://api-fxpractice.oanda.com/v3``.

Why MetaTrader 5 (``MT5``) instead of MetaTrader 4 (``MT4``):

- MetaQuotes ships an official native ``MetaTrader5`` Python SDK (IPC to a running
  terminal: ``initialize``, ``login``, ``account_info``, ``symbol_info_tick``,
  ``copy_rates_from_pos``, ``positions_get``, ``order_send``). MT4 has no official
  Python API and needs third-party DLL/socket bridges.
- One platform covers both demo brokers: Hugo's Way (``Hugo demo PRO5``) and
  LHFX (``LHFXSA-Demo``) both run MT5 servers, so one Expert Advisor
  (``mt5/CasForexMt5Bridge.mq5``) and one Python transport serve both.
- MT5 offers 21 chart timeframes (MT4 offers 9), which matches the multi-timeframe
  candle stream used by the cockpit.
- MT5 exposes atomic trade actions -- ``TRADE_ACTION_DEAL`` (market deal),
  ``TRADE_ACTION_SLTP`` (protective stop amend on an existing position) and
  partial closes by position ticket -- which map one-to-one onto the CAS
  ``OPEN`` / ``AMEND_STOP`` / ``REDUCE`` / ``CLOSE`` intents.

Safety invariants:

- Importing this module and constructing every class in it is strictly inert: no
  network, disk, directory, thread, or subprocess side effects. The optional
  ``MetaTrader5`` SDK is imported lazily, only when a native transport connects.
- Credentials are read only from an explicitly passed environment ``Mapping`` (or
  the live process environment through ``from_process_env``); ``.env`` files are
  never read. Passwords are wrapped in :class:`_RedactedSecret` and never appear in
  ``repr``/``str``/logs/spool files.
- Live / real-money servers are hard-rejected with
  :class:`LiveBrokerEndpointForbiddenError` (``Hugo PRO5``, ``HugosWay-Live``,
  ``LHFXSA-Live``, any server containing ``live`` or ``real``, any server that is not
  explicitly a ``demo`` server, any MT5 account whose trade mode is not DEMO, and
  ``api-fxtrade.oanda.com``).
- 1:500 leverage never bypasses the ForexMetaValveGate (``tks_meta_valve_controller``,
  161 parameters, threshold 0.55): every venue ``execute`` call requires an admitted
  :class:`ValveDecision` produced by the same weights and bound to the same
  ``action_ref``. On top of the Valve, an exact ``Decimal`` margin check refuses any
  OPEN that would exceed free margin or push the post-trade margin level below a
  conservative floor (1000% by default, i.e. at most 50x effective leverage).
- Failover between brokers happens only while connecting. An order whose outcome is
  unknown is never re-sent to another broker.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation, localcontext
from hashlib import sha256
import importlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Protocol

from cas_forex_revamp.contracts import ActionKind, ContractError, Side, canonical_bytes, decimal_text, parse_decimal
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, utc_time
from cas_forex_revamp.valve.tks_meta_valve_controller import ForexMetaValveGate, ValveDecision, ValveRefusalError
from .external_paper_broker import (
    DEFAULT_OANDA_LIVE_BASE_URL,
    DEFAULT_OANDA_PRACTICE_BASE_URL,
    ENV_EXECUTION_MODE,
    ENV_LIVE_ARM_PHRASE,
    ENV_OANDA_LIVE_ACCOUNT_ID,
    ENV_OANDA_LIVE_TOKEN,
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    EXECUTION_MODES,
    EXPANDED_FX_PAIRS,
    REQUIRED_LIVE_ARM_PHRASE,
    BrokerAuditReceipt,
    LiveBrokerEndpointForbiddenError,
    OandaPracticePaperClient,
    assert_safe_json_numbers,
    resolve_execution_mode,
    strict_safe_json_loads,
)

__all__ = [
    "BROKER_HUGOSWAY_MT5",
    "BROKER_LHFX_MT5",
    "BROKER_OANDA_LIVE",
    "BROKER_OANDA_PRACTICE",
    "BROKER_PRIORITY",
    "BROKER_SPECS",
    "BrokerFailoverExhaustedError",
    "BrokerHierarchyRouter",
    "BrokerSpec",
    "LiveBrokerEndpointForbiddenError",
    "MT5_PLATFORM_NAME",
    "MT5_SPOOL_PROTOCOL",
    "MT5_TIMEFRAMES",
    "Mt5AccountSnapshot",
    "Mt5BridgeError",
    "Mt5Credentials",
    "Mt5ExecutionResult",
    "Mt5MarginCalculator",
    "Mt5MarginCheck",
    "Mt5MarginRefusalError",
    "Mt5NativePythonTransport",
    "Mt5NotConfiguredError",
    "Mt5OutcomeUnknownError",
    "Mt5OrderReceipt",
    "Mt5OrderRequest",
    "Mt5PaperBrokerVenue",
    "Mt5Position",
    "Mt5SpoolBridgeTransport",
    "Mt5SpoolPaperTerminalEmulator",
    "Mt5Tick",
    "Mt5Transport",
    "Mt5TransportError",
    "Mt5ValveClearanceError",
    "OandaPracticeFallbackVenue",
    "OrderIntent",
    "apply_verified_directory_mode",
    "load_mt5_credentials",
    "require_valve_clearance",
    "validate_demo_server",
    "validate_mt5_server_name",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform, broker and environment constants
# ---------------------------------------------------------------------------

MT5_PLATFORM_CODE = "MT5"
MT5_PLATFORM_NAME = "MetaTrader 5"
MT5_SPOOL_PROTOCOL = "cas-forex-mt5-spool/1"
MT5_CONTRACT_SIZE = Decimal("100000")
MT5_VOLUME_STEP = Decimal("0.01")
MT5_MIN_VOLUME = Decimal("0.01")
MT5_MAX_VOLUME_DEFAULT = Decimal("50")
MAX_DEMO_LEVERAGE = 500
DEFAULT_MIN_POST_TRADE_MARGIN_LEVEL_PCT = Decimal("1000")
DEFAULT_MAGIC = 20261116
MAX_SPOOL_FILE_BYTES = 262_144
GENESIS_SHA256 = "0" * 64

# MetaTrader 5 supports 21 chart timeframes (MetaTrader 4 supports 9).
MT5_TIMEFRAMES: tuple[str, ...] = (
    "M1", "M2", "M3", "M4", "M5", "M6", "M10", "M12", "M15", "M20", "M30",
    "H1", "H2", "H3", "H4", "H6", "H8", "H12", "D1", "W1", "MN1",
)

# Documented MetaTrader5 SDK constant values, used only when an injected SDK lacks them.
_SDK_DEFAULTS: dict[str, int] = {
    "TRADE_ACTION_DEAL": 1,
    "TRADE_ACTION_SLTP": 6,
    "ORDER_TYPE_BUY": 0,
    "ORDER_TYPE_SELL": 1,
    "ORDER_TIME_GTC": 0,
    "ORDER_FILLING_IOC": 1,
    "POSITION_TYPE_BUY": 0,
    "POSITION_TYPE_SELL": 1,
    "ACCOUNT_TRADE_MODE_DEMO": 0,
    "ACCOUNT_TRADE_MODE_REAL": 2,
    "TRADE_RETCODE_PLACED": 10008,
    "TRADE_RETCODE_DONE": 10009,
    "TRADE_RETCODE_DONE_PARTIAL": 10010,
}

ENV_PRIMARY_BROKER = "CAS_FOREX_PRIMARY_BROKER"
ENV_MT5_TRANSPORT_MODE = "CAS_FOREX_MT5_TRANSPORT_MODE"
ENV_MT5_SPOOL_DIR = "CAS_FOREX_MT5_SPOOL_DIR"
ENV_HUGOSWAY_MT5_LOGIN = "CAS_FOREX_HUGOSWAY_MT5_LOGIN"
ENV_HUGOSWAY_MT5_PASSWORD = "CAS_FOREX_HUGOSWAY_MT5_PASSWORD"  # nosec B105: environment variable name constant, not a secret value
ENV_HUGOSWAY_MT5_SERVER = "CAS_FOREX_HUGOSWAY_MT5_SERVER"
ENV_LHFX_MT5_LOGIN = "CAS_FOREX_LHFX_MT5_LOGIN"
ENV_LHFX_MT5_PASSWORD = "CAS_FOREX_LHFX_MT5_PASSWORD"  # nosec B105: environment variable name constant, not a secret value
ENV_LHFX_MT5_SERVER = "CAS_FOREX_LHFX_MT5_SERVER"

BROKER_HUGOSWAY_MT5 = "HUGOSWAY_MT5"
BROKER_LHFX_MT5 = "LHFX_MT5"
BROKER_OANDA_PRACTICE = "OANDA_PRACTICE"
BROKER_OANDA_LIVE = "OANDA_LIVE"
BROKER_PRIORITY: tuple[str, ...] = (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5, BROKER_OANDA_PRACTICE)
LIVE_BROKER_PRIORITY: tuple[str, ...] = (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5, BROKER_OANDA_LIVE)
_DEFAULT_LIVE_MT5_SERVERS: dict[str, str] = {
    BROKER_HUGOSWAY_MT5: "Hugo PRO5",
    BROKER_LHFX_MT5: "LHFXSA-Live",
}
_PINNED_LIVE_MT5_SERVERS: dict[str, frozenset[str]] = {
    BROKER_HUGOSWAY_MT5: frozenset({"hugo pro5", "hugopro5", "hugo-real", "hugosway-live"}),
    BROKER_LHFX_MT5: frozenset({"lhfxsa-live", "lhfx-live", "lhfxsa-real"}),
}

TRANSPORT_AUTO = "AUTO"
TRANSPORT_NATIVE_PYTHON = "NATIVE_PYTHON"
TRANSPORT_SPOOL_BRIDGE = "SPOOL_BRIDGE"
TRANSPORT_MODES: tuple[str, ...] = (TRANSPORT_AUTO, TRANSPORT_NATIVE_PYTHON, TRANSPORT_SPOOL_BRIDGE)

_LIVE_SERVER_TOKENS: tuple[str, ...] = ("live", "real", "fxtrade")
_EXPLICIT_LIVE_SERVERS = frozenset({
    "hugo pro5",
    "hugopro5",
    "hugosway-live",
    "hugos way-live",
    "hugosway live",
    "lhfxsa-live",
    "lhfx-live",
})
_LOGIN_RE = re.compile(r"^[0-9]{1,20}$")
_TICKET_RE = re.compile(r"^[0-9]{1,20}$")
_SPOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")
_ISO_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class Mt5BridgeError(ContractError):
    """Base error for the MetaTrader 5 broker bridge."""


class Mt5NotConfiguredError(Mt5BridgeError):
    """Raised when a broker in the hierarchy has no explicit runtime credentials/transport."""


class Mt5TransportError(Mt5BridgeError):
    """Sanitized transport failure; never carries credentials or raw terminal payloads."""


class Mt5OutcomeUnknownError(Mt5TransportError):
    """Raised when an order may have reached the broker but no receipt was observed (never resubmitted)."""


class Mt5MarginRefusalError(Mt5BridgeError):
    """Raised when an OPEN would exceed free margin or breach the post-trade margin-level floor."""


class BrokerFailoverExhaustedError(Mt5BridgeError):
    """Raised when no broker in the priority hierarchy could be activated."""


class Mt5ValveClearanceError(ValveRefusalError):
    """Raised when an order reaches a venue without a matching admitted ForexMetaValveGate decision."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return utc_time(value, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_iso(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not _ISO_UTC_RE.fullmatch(value):
        raise Mt5TransportError(f"{field} must be an ISO-8601 UTC timestamp ending in Z")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _wire_decimal(value: Any, field: str, *, positive: bool = False, allow_zero_as_none: bool = False) -> Decimal | None:
    """Parse a plain decimal *string* from a spool/wire document (never a float)."""
    if allow_zero_as_none and value in ("", "0", None):
        return None
    if not isinstance(value, str):
        raise Mt5TransportError(f"{field} must be a plain decimal string")
    try:
        parsed = parse_decimal(value, field)
    except ContractError as exc:
        raise Mt5TransportError(f"{field} is not a plain bounded decimal string") from exc
    if positive and parsed <= 0:
        raise Mt5TransportError(f"{field} must be positive")
    return parsed


def _sdk_decimal(value: Any, field: str) -> Decimal:
    """Convert an SDK float/int to an exact Decimal via its shortest round-trip repr."""
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise Mt5TransportError(f"MetaTrader5 SDK field {field} is not numeric")
    try:
        out = value if isinstance(value, Decimal) else Decimal(repr(value) if isinstance(value, float) else str(value))
    except InvalidOperation as exc:
        raise Mt5TransportError(f"MetaTrader5 SDK field {field} is not a finite number") from exc
    if not out.is_finite():
        raise Mt5TransportError(f"MetaTrader5 SDK field {field} is not finite")
    return out.normalize() if out != 0 else Decimal("0")


def _ticket_text(value: Any, field: str = "ticket") -> str:
    text = str(value) if type(value) is int else value
    if not isinstance(text, str) or not _TICKET_RE.fullmatch(text):
        raise Mt5TransportError(f"{field} must be a decimal integer string")
    return text


def _ascii_text(value: str, field: str, *, max_len: int = 64) -> str:
    if not isinstance(value, str) or len(value) > max_len or not value.isascii():
        raise ContractError(f"{field} must be ASCII text of at most {max_len} characters")
    if any(ch in value for ch in ("\r", "\n", "\x00", '"', "\\")):
        raise ContractError(f"{field} contains forbidden characters")
    return value


def _sha256_flat(doc: Mapping[str, str]) -> str:
    return sha256(canonical_bytes(dict(doc))).hexdigest()


def apply_verified_directory_mode(path: str | Path, dir_mode: int = 0o700) -> Path:
    """Apply a restrictive mode to an existing real directory (never a symlink or file).

    Used for the MT5 file spool so request/receipt JSON is private to the operator account.
    """
    target = Path(path)
    st = os.lstat(target)
    if not stat.S_ISDIR(st.st_mode):
        raise Mt5TransportError("spool path must be a real directory, not a file or symlink")
    os.chmod(target, dir_mode)  # nosec B103: owner-only 0o700 spool directory verified via lstat + S_ISDIR above
    return target


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError as cleanup_exc:
            logger.warning("MT5 spool temp cleanup failed for %s: %s", tmp.name, type(cleanup_exc).__name__)
        raise Mt5TransportError(f"atomic spool write failed for {path.name}: {type(exc).__name__}") from None


def _atomic_write_json(path: Path, doc: Mapping[str, Any]) -> None:
    assert_safe_json_numbers(dict(doc))
    raw = (json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _atomic_write_bytes(path, raw)


def _read_spool_json(path: Path, *, max_bytes: int = MAX_SPOOL_FILE_BYTES) -> Any:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise Mt5TransportError(f"spool file {path.name} unreadable: {type(exc).__name__}") from None
    if not stat.S_ISREG(st.st_mode):
        raise Mt5TransportError(f"spool file {path.name} must be a regular file")
    if st.st_size > max_bytes:
        raise Mt5TransportError(f"spool file {path.name} exceeds {max_bytes} bytes")
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return strict_safe_json_loads(raw, max_bytes=max_bytes)
    except ContractError as exc:
        raise Mt5TransportError(f"spool file {path.name} is not strict safe JSON: {exc}") from None


# ---------------------------------------------------------------------------
# Secrets, broker specs, server validation and credentials
# ---------------------------------------------------------------------------


class _RedactedSecret:
    """Holds a runtime credential without ever exposing it in repr/str/format/pickle."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise Mt5NotConfiguredError("secret must be a non-empty string")
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


@dataclass(frozen=True, slots=True)
class BrokerSpec:
    broker_id: str
    rank: int
    role: str
    label: str
    platform: str
    default_server: str | None
    max_leverage: int
    account_type: str
    login_env: str | None
    password_env: str | None
    server_env: str | None


BROKER_SPECS: dict[str, BrokerSpec] = {
    BROKER_HUGOSWAY_MT5: BrokerSpec(
        broker_id=BROKER_HUGOSWAY_MT5,
        rank=1,
        role="PRIMARY_MAIN",
        label="Hugo's Way",
        platform=MT5_PLATFORM_NAME,
        default_server="Hugo demo PRO5",
        max_leverage=500,
        account_type="ECN demo",
        login_env=ENV_HUGOSWAY_MT5_LOGIN,
        password_env=ENV_HUGOSWAY_MT5_PASSWORD,
        server_env=ENV_HUGOSWAY_MT5_SERVER,
    ),
    BROKER_LHFX_MT5: BrokerSpec(
        broker_id=BROKER_LHFX_MT5,
        rank=2,
        role="SECONDARY_MT5",
        label="LHFX",
        platform=MT5_PLATFORM_NAME,
        default_server="LHFXSA-Demo",
        max_leverage=500,
        account_type="STP/ECN demo",
        login_env=ENV_LHFX_MT5_LOGIN,
        password_env=ENV_LHFX_MT5_PASSWORD,
        server_env=ENV_LHFX_MT5_SERVER,
    ),
    BROKER_OANDA_PRACTICE: BrokerSpec(
        broker_id=BROKER_OANDA_PRACTICE,
        rank=3,
        role="TERTIARY_REST_FALLBACK",
        label="OANDA",
        platform="OANDA v20 REST",
        default_server=None,
        max_leverage=50,
        account_type="fxPractice",
        login_env=None,
        password_env=None,
        server_env=None,
    ),
    BROKER_OANDA_LIVE: BrokerSpec(
        broker_id=BROKER_OANDA_LIVE,
        rank=3,
        role="TERTIARY_REST_FALLBACK",
        label="OANDA",
        platform="OANDA v20 REST",
        default_server=DEFAULT_OANDA_LIVE_BASE_URL,
        max_leverage=50,
        account_type="fxTrade Live",
        login_env=None,
        password_env=None,
        server_env=None,
    ),
}


def validate_demo_server(broker_id: str, server: str) -> str:
    """Return the cleaned MT5 server name or hard-reject any live / non-demo server."""
    if not isinstance(server, str) or not server.strip():
        raise Mt5NotConfiguredError(f"{broker_id}: MT5 server name must be a non-empty string")
    cleaned = server.strip()
    if len(cleaned) > 64 or not cleaned.isascii() or any(ch in cleaned for ch in ("\r", "\n", "\x00", '"', "\\")):
        raise ContractError(f"{broker_id}: MT5 server name contains forbidden characters")
    low = cleaned.lower()
    compact = re.sub(r"[\s_]+", " ", low)
    if compact in _EXPLICIT_LIVE_SERVERS or any(tok in low for tok in _LIVE_SERVER_TOKENS):
        raise LiveBrokerEndpointForbiddenError(
            f"LIVE REAL-MONEY MT5 SERVER FORBIDDEN for {broker_id}: {cleaned!r} is hard-rejected; demo servers only"
        )
    if "demo" not in low:
        raise LiveBrokerEndpointForbiddenError(
            f"non-demo MT5 server {cleaned!r} refused for {broker_id}; only explicit demo servers are allowed"
        )
    return cleaned


def validate_mt5_server_name(
    broker_id: str,
    server: str,
    *,
    execution_mode: str = EXECUTION_MODE_DEMO,
    live_armed: bool = False,
) -> str:
    """Validate an MT5 server strictly against DEMO or two-key armed LIVE mode."""
    if execution_mode == EXECUTION_MODE_DEMO:
        return validate_demo_server(broker_id, server)
    if execution_mode != EXECUTION_MODE_LIVE or not live_armed:
        raise LiveBrokerEndpointForbiddenError("LIVE MT5 servers require explicit two-key LIVE arming")
    if not isinstance(server, str) or not server.strip():
        raise Mt5NotConfiguredError(f"{broker_id}: LIVE MT5 server name must be a non-empty string")
    cleaned = server.strip()
    if len(cleaned) > 64 or not cleaned.isascii() or any(ch in cleaned for ch in ("\r", "\n", "\x00", '"', "\\")):
        raise ContractError(f"{broker_id}: MT5 server name contains forbidden characters")
    low = cleaned.lower()
    if "demo" in low or "practice" in low:
        raise ContractError(f"demo/practice MT5 server {cleaned!r} refused for {broker_id} while LIVE mode is armed")
    compact = re.sub(r"[\s_]+", " ", low)
    allowed = _PINNED_LIVE_MT5_SERVERS.get(broker_id)
    if allowed is None:
        all_live = frozenset().union(*_PINNED_LIVE_MT5_SERVERS.values())
        if compact not in all_live:
            raise ContractError(f"unpinned LIVE MT5 server {cleaned!r} refused")
    elif compact not in allowed:
        raise ContractError(
            f"unpinned LIVE MT5 server {cleaned!r} refused for {broker_id}; allowed={sorted(allowed)}"
        )
    return cleaned


@dataclass(frozen=True, slots=True, repr=False)
class Mt5Credentials:
    broker_id: str
    login: int
    server: str
    password: _RedactedSecret | None = None
    execution_mode: str = EXECUTION_MODE_DEMO

    def __post_init__(self) -> None:
        if self.broker_id not in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            raise ContractError("Mt5Credentials only apply to MT5 brokers")
        if self.execution_mode not in EXECUTION_MODES:
            raise ContractError(f"execution_mode must be one of {EXECUTION_MODES}")
        if type(self.login) is not int or self.login <= 0:
            raise ContractError("MT5 login must be a positive integer")
        validate_mt5_server_name(
            self.broker_id,
            self.server,
            execution_mode=self.execution_mode,
            live_armed=(self.execution_mode == EXECUTION_MODE_LIVE),
        )
        if self.password is not None and not isinstance(self.password, _RedactedSecret):
            raise ContractError("MT5 password must be wrapped in _RedactedSecret")

    def __repr__(self) -> str:
        return (
            f"Mt5Credentials(broker_id={self.broker_id!r}, login='[MASKED]', "
            f"server={self.server!r}, password='[REDACTED]')"
        )

    def __str__(self) -> str:
        return self.__repr__()


def _env_get(environ: Mapping[str, str], name: str | None) -> str:
    if name is None:
        return ""
    raw = environ.get(name, "")
    if not isinstance(raw, str):
        raise ContractError(f"environment value {name} must be a string")
    return raw.strip()


def resolve_server(
    broker_id: str,
    environ: Mapping[str, str],
    *,
    execution_mode: str = EXECUTION_MODE_DEMO,
    live_armed: bool = False,
) -> str | None:
    spec = BROKER_SPECS[broker_id]
    if spec.server_env is None:
        return None
    default_srv = (
        _DEFAULT_LIVE_MT5_SERVERS[broker_id]
        if execution_mode == EXECUTION_MODE_LIVE
        else str(spec.default_server)
    )
    raw = _env_get(environ, spec.server_env)
    return validate_mt5_server_name(
        broker_id,
        raw or default_srv,
        execution_mode=execution_mode,
        live_armed=live_armed,
    )


def load_mt5_credentials(
    broker_id: str,
    environ: Mapping[str, str],
    *,
    password_required: bool = True,
    execution_mode: str | None = None,
    live_arm_phrase: str | None = None,
) -> Mt5Credentials | None:
    """Load MT5 credentials from an explicit runtime mapping (never a ``.env`` file).

    Returns ``None`` when the broker is simply not configured. Server names are validated
    strictly against the active execution mode (DEMO by default; two-key LIVE when armed).
    """
    if broker_id not in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
        raise ContractError(f"{broker_id} is not an MT5 broker")
    if not isinstance(environ, Mapping):
        raise ContractError("environ must be a key-value Mapping (never a .env file path)")
    mode, armed = resolve_execution_mode(
        environ, execution_mode=execution_mode, live_arm_phrase=live_arm_phrase
    )
    spec = BROKER_SPECS[broker_id]
    server = resolve_server(broker_id, environ, execution_mode=mode, live_armed=armed)
    login_raw = _env_get(environ, spec.login_env)
    password_raw = _env_get(environ, spec.password_env)
    if not login_raw and not password_raw:
        return None
    if not login_raw:
        raise Mt5NotConfiguredError(f"{spec.login_env} is required when {spec.password_env} is supplied")
    if not _LOGIN_RE.fullmatch(login_raw):
        raise Mt5NotConfiguredError(f"{spec.login_env} must be a numeric MT5 account login")
    if not password_raw and password_required:
        raise Mt5NotConfiguredError(f"{spec.login_env} and {spec.password_env} are required together")
    return Mt5Credentials(
        broker_id=broker_id,
        login=int(login_raw),
        server=str(server),
        password=_RedactedSecret(password_raw) if password_raw else None,
        execution_mode=mode,
    )


# ---------------------------------------------------------------------------
# Exact Decimal 1:500 margin calculator
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Mt5MarginCheck:
    symbol: str
    side: Side
    units: Decimal
    volume_lots: Decimal
    notional_account: Decimal
    required_margin: Decimal
    used_margin_after: Decimal
    free_margin_after: Decimal
    margin_level_after_pct: Decimal | None
    admitted: bool
    reason: str | None

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol,
            "side": self.side.value,
            "units": decimal_text(self.units),
            "volume_lots": decimal_text(self.volume_lots),
            "notional_account": decimal_text(self.notional_account),
            "required_margin": decimal_text(self.required_margin),
            "used_margin_after": decimal_text(self.used_margin_after),
            "free_margin_after": decimal_text(self.free_margin_after),
            "margin_level_after_pct": None if self.margin_level_after_pct is None else decimal_text(self.margin_level_after_pct),
            "admitted": self.admitted,
            "reason": self.reason,
        }


class Mt5MarginCalculator:
    """Exact ``Decimal`` margin math for MT5 Forex margin mode at a fixed leverage (default 1:500).

    MT5 Forex margin: ``margin = lots * contract_size * base_to_account_rate / leverage``.
    Required margin is rounded UP to the cent (conservative); margin level is rounded DOWN.
    """

    def __init__(
        self,
        *,
        leverage: int = MAX_DEMO_LEVERAGE,
        account_currency: str = "USD",
        contract_size: Decimal = MT5_CONTRACT_SIZE,
    ) -> None:
        if type(leverage) is not int or not (1 <= leverage <= MAX_DEMO_LEVERAGE):
            raise ContractError(f"leverage must be an integer in 1..{MAX_DEMO_LEVERAGE}")
        if not isinstance(account_currency, str) or not re.fullmatch(r"[A-Z]{3}", account_currency):
            raise ContractError("account_currency must be an ISO-4217 code")
        self.leverage = leverage
        self.account_currency = account_currency
        self.contract_size = decimal_value(contract_size, "contract_size", positive=True)

    @staticmethod
    def split_symbol(symbol: str) -> tuple[str, str]:
        if not isinstance(symbol, str) or symbol not in EXPANDED_FX_PAIRS:
            raise ContractError(f"unsupported MT5 symbol {symbol!r}; expected one of the 16 EXPANDED_FX_PAIRS")
        return symbol[:3], symbol[3:]

    def units_to_lots(self, units: Decimal) -> Decimal:
        decimal_value(units, "units", positive=True)
        with localcontext() as ctx:
            ctx.prec = 40
            lots = units / self.contract_size
        if lots < MT5_MIN_VOLUME or lots % MT5_VOLUME_STEP != 0:
            raise ContractError(
                f"units {decimal_text(units)} must map to a positive multiple of {MT5_VOLUME_STEP} lots "
                f"(1 lot = {decimal_text(self.contract_size)} base units)"
            )
        return lots.quantize(MT5_VOLUME_STEP)

    def lots_to_units(self, lots: Decimal) -> Decimal:
        decimal_value(lots, "lots", positive=True)
        with localcontext() as ctx:
            ctx.prec = 40
            return (lots * self.contract_size).normalize()

    @staticmethod
    def _quote(quotes: Mapping[str, tuple[Decimal, Decimal]], symbol: str) -> tuple[Decimal, Decimal]:
        pair = quotes.get(symbol)
        if pair is None:
            raise ContractError(f"missing quote for {symbol}")
        bid, ask = pair
        decimal_value(bid, f"{symbol} bid", positive=True)
        decimal_value(ask, f"{symbol} ask", positive=True)
        if ask < bid:
            raise ContractError(f"{symbol} quote is inverted (ask < bid)")
        return bid, ask

    def conversion_symbol(self, currency: str) -> str | None:
        """Return the EXPANDED_FX_PAIRS symbol needed to convert ``currency`` into the account currency."""
        if currency == self.account_currency:
            return None
        direct = f"{currency}{self.account_currency}"
        inverse = f"{self.account_currency}{currency}"
        if direct in EXPANDED_FX_PAIRS:
            return direct
        if inverse in EXPANDED_FX_PAIRS:
            return inverse
        raise ContractError(f"no conversion pair for {currency}->{self.account_currency}")

    def conversion_rate(self, currency: str, quotes: Mapping[str, tuple[Decimal, Decimal]]) -> Decimal:
        """Exact mid-price rate that converts one unit of ``currency`` into the account currency."""
        sym = self.conversion_symbol(currency)
        if sym is None:
            return Decimal("1")
        bid, ask = self._quote(quotes, sym)
        with localcontext() as ctx:
            ctx.prec = 40
            mid = (bid + ask) / 2
            return mid if sym.startswith(currency) else Decimal(1) / mid

    def required_symbols(self, symbol: str) -> tuple[str, ...]:
        base, quote = self.split_symbol(symbol)
        out = [symbol]
        if self.account_currency not in (base, quote):
            conv = self.conversion_symbol(base)
            if conv is not None and conv not in out:
                out.append(conv)
        return tuple(out)

    def notional_in_account(
        self, symbol: str, side: Side, units: Decimal, quotes: Mapping[str, tuple[Decimal, Decimal]]
    ) -> Decimal:
        base, quote = self.split_symbol(symbol)
        decimal_value(units, "units", positive=True)
        if not isinstance(side, Side):
            raise ContractError("side must be Side")
        with localcontext() as ctx:
            ctx.prec = 40
            if base == self.account_currency:
                return units
            if quote == self.account_currency:
                bid, ask = self._quote(quotes, symbol)
                return units * (ask if side is Side.BUY else bid)
            return units * self.conversion_rate(base, quotes)

    def required_margin(
        self, symbol: str, side: Side, units: Decimal, quotes: Mapping[str, tuple[Decimal, Decimal]]
    ) -> Decimal:
        notional = self.notional_in_account(symbol, side, units, quotes)
        with localcontext() as ctx:
            ctx.prec = 40
            return (notional / Decimal(self.leverage)).quantize(Decimal("0.01"), rounding=ROUND_CEILING)

    @staticmethod
    def margin_level_pct(equity: Decimal, used_margin: Decimal) -> Decimal | None:
        if used_margin <= 0:
            return None
        with localcontext() as ctx:
            ctx.prec = 40
            return (equity / used_margin * 100).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)

    def account_metrics(self, *, balance: Decimal, floating_pnl: Decimal, used_margin: Decimal) -> dict[str, Decimal | None]:
        decimal_value(balance, "balance")
        decimal_value(floating_pnl, "floating_pnl")
        decimal_value(used_margin, "used_margin")
        equity = balance + floating_pnl
        return {
            "equity": equity,
            "free_margin": equity - used_margin,
            "margin_level_pct": self.margin_level_pct(equity, used_margin),
        }

    def check_new_position(
        self,
        *,
        symbol: str,
        side: Side,
        units: Decimal,
        quotes: Mapping[str, tuple[Decimal, Decimal]],
        equity: Decimal,
        used_margin: Decimal,
        free_margin: Decimal,
        min_margin_level_pct: Decimal = DEFAULT_MIN_POST_TRADE_MARGIN_LEVEL_PCT,
    ) -> Mt5MarginCheck:
        lots = self.units_to_lots(units)
        notional = self.notional_in_account(symbol, side, units, quotes)
        required = self.required_margin(symbol, side, units, quotes)
        used_after = used_margin + required
        free_after = free_margin - required
        level_after = self.margin_level_pct(equity, used_after)
        reason: str | None = None
        if equity <= 0:
            reason = "NON_POSITIVE_EQUITY"
        elif free_after < 0:
            reason = "INSUFFICIENT_FREE_MARGIN"
        elif level_after is not None and level_after < min_margin_level_pct:
            reason = "POST_TRADE_MARGIN_LEVEL_BELOW_FLOOR"
        return Mt5MarginCheck(
            symbol=symbol,
            side=side,
            units=units,
            volume_lots=lots,
            notional_account=notional,
            required_margin=required,
            used_margin_after=used_after,
            free_margin_after=free_after,
            margin_level_after_pct=level_after,
            admitted=reason is None,
            reason=reason,
        )


# ---------------------------------------------------------------------------
# Order intents, wire records and account snapshots
# ---------------------------------------------------------------------------

_SUPPORTED_ORDER_KINDS = (ActionKind.OPEN, ActionKind.AMEND_STOP, ActionKind.REDUCE, ActionKind.CLOSE)


@dataclass(frozen=True, slots=True)
class OrderIntent:
    """Broker-neutral order intent (OPEN / AMEND_STOP / REDUCE / CLOSE) in exact base units."""

    order_id: str
    action_ref: str
    kind: ActionKind
    symbol: str
    quantity_units: Decimal | None = None
    side: Side | None = None
    stop_price: Decimal | None = None
    limit_price: Decimal | None = None
    position_ticket: str | None = None

    def __post_init__(self) -> None:
        identifier(self.order_id, "order_id")
        identifier(self.action_ref, "action_ref")
        if not isinstance(self.kind, ActionKind) or self.kind not in _SUPPORTED_ORDER_KINDS:
            raise ContractError("MT5 bridge v1 supports OPEN, AMEND_STOP, REDUCE and CLOSE only")
        Mt5MarginCalculator.split_symbol(self.symbol)
        if self.side is not None and not isinstance(self.side, Side):
            raise ContractError("side must be Side")
        for name in ("quantity_units", "stop_price", "limit_price"):
            value = getattr(self, name)
            if value is not None:
                decimal_value(value, name, positive=True)
        if self.position_ticket is not None and (not isinstance(self.position_ticket, str) or not _TICKET_RE.fullmatch(self.position_ticket)):
            raise ContractError("position_ticket must be a decimal MT5 ticket string")
        if self.kind is ActionKind.OPEN:
            if self.side is None or self.quantity_units is None:
                raise ContractError("OPEN requires side and exact quantity")
            if self.stop_price is None:
                raise ContractError("OPEN requires a protective stop (1:500 leverage never trades unprotected)")
            if self.position_ticket is not None:
                raise ContractError("OPEN must not target an existing position")
            if self.limit_price is not None:
                if self.side is Side.BUY and self.stop_price >= self.limit_price:
                    raise ContractError("BUY protective stop must be below the limit price")
                if self.side is Side.SELL and self.stop_price <= self.limit_price:
                    raise ContractError("SELL protective stop must be above the limit price")
        else:
            if self.position_ticket is None:
                raise ContractError(f"{self.kind.value} requires an exact position_ticket")
        if self.kind is ActionKind.AMEND_STOP:
            if self.stop_price is None or self.quantity_units is not None:
                raise ContractError("AMEND_STOP requires a replacement stop and no quantity")
        if self.kind is ActionKind.REDUCE and self.quantity_units is None:
            raise ContractError("REDUCE requires an exact quantity")

    @classmethod
    def from_action_intent(
        cls,
        intent: Any,
        *,
        symbol: str | None = None,
        position_ticket: str | None = None,
    ) -> "OrderIntent":
        """Translate a CAS ``ActionIntent`` (or duck-typed equivalent) into an MT5 order intent."""
        if intent is None:
            raise ContractError("a WAIT selection carries no order intent")
        kind = intent.kind if isinstance(intent.kind, ActionKind) else ActionKind(str(intent.kind))
        side_raw = getattr(intent, "side", None)
        side = None if side_raw is None else (side_raw if isinstance(side_raw, Side) else Side(str(side_raw)))
        quantity = getattr(intent, "quantity", None)
        if kind is ActionKind.AMEND_STOP:
            quantity = None
        return cls(
            order_id=str(intent.intent_id),
            action_ref=str(intent.action_ref),
            kind=kind,
            symbol=(symbol or str(intent.instrument_id)).upper(),
            quantity_units=quantity,
            side=side if kind is ActionKind.OPEN else None,
            stop_price=getattr(intent, "stop_price", None),
            limit_price=getattr(intent, "limit_price", None) if kind is ActionKind.OPEN else None,
            position_ticket=position_ticket if position_ticket is not None else (
                None if kind is ActionKind.OPEN else getattr(intent, "target_id", None)
            ),
        )

    def fingerprint(self) -> str:
        return sha256(canonical_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class Mt5Tick:
    symbol: str
    bid: Decimal
    ask: Decimal
    time_msc: str

    def __post_init__(self) -> None:
        Mt5MarginCalculator.split_symbol(self.symbol)
        decimal_value(self.bid, "bid", positive=True)
        decimal_value(self.ask, "ask", positive=True)
        if self.ask < self.bid:
            raise Mt5TransportError(f"{self.symbol} tick is inverted (ask < bid)")
        _ticket_text(self.time_msc, "time_msc")


@dataclass(frozen=True, slots=True)
class Mt5Position:
    ticket: str
    symbol: str
    side: Side
    volume_lots: Decimal
    price_open: Decimal
    stop_loss: Decimal | None
    profit: Decimal

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "ticket": self.ticket,
            "symbol": self.symbol,
            "side": self.side.value,
            "volume_lots": decimal_text(self.volume_lots),
            "price_open": decimal_text(self.price_open),
            "stop_loss": None if self.stop_loss is None else decimal_text(self.stop_loss),
            "profit": decimal_text(self.profit),
        }


@dataclass(frozen=True, slots=True)
class Mt5AccountSnapshot:
    server: str
    login: int
    currency: str
    balance: Decimal
    equity: Decimal
    margin: Decimal
    margin_free: Decimal
    leverage: int
    trade_mode: str

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "currency": self.currency,
            "balance": decimal_text(self.balance),
            "equity": decimal_text(self.equity),
            "margin": decimal_text(self.margin),
            "margin_free": decimal_text(self.margin_free),
            "leverage": f"1:{self.leverage}",
            "trade_mode": self.trade_mode,
        }


@dataclass(frozen=True, slots=True)
class Mt5OrderRequest:
    request_id: str
    action: str
    symbol: str
    side: Side
    volume_lots: Decimal | None
    price: Decimal | None
    stop_loss: Decimal | None
    position_ticket: str | None
    deviation_points: int
    magic: int
    comment: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not _SPOOL_ID_RE.fullmatch(self.request_id):
            raise ContractError("request_id must be a filename-safe identifier")
        if self.action not in ("OPEN", "AMEND_STOP", "REDUCE", "CLOSE"):
            raise ContractError("unsupported MT5 request action")
        Mt5MarginCalculator.split_symbol(self.symbol)
        if not isinstance(self.side, Side):
            raise ContractError("side must be Side")
        if self.action == "AMEND_STOP":
            if self.stop_loss is None or self.position_ticket is None:
                raise ContractError("AMEND_STOP request requires stop_loss and position_ticket")
        else:
            if self.volume_lots is None:
                raise ContractError("deal requests require volume_lots")
            decimal_value(self.volume_lots, "volume_lots", positive=True)
        if self.action in ("REDUCE", "CLOSE") and self.position_ticket is None:
            raise ContractError("REDUCE/CLOSE requests require position_ticket")
        if type(self.deviation_points) is not int or not (0 <= self.deviation_points <= 1000):
            raise ContractError("deviation_points must be an integer in 0..1000")
        if type(self.magic) is not int or not (0 < self.magic <= 2_147_483_647):
            raise ContractError("magic must be a positive 32-bit integer")
        _ascii_text(self.comment, "comment", max_len=31)
        utc_time(self.created_at, "created_at")

    def _core_dict(self) -> dict[str, str]:
        return {
            "protocol": MT5_SPOOL_PROTOCOL,
            "request_id": self.request_id,
            "action": self.action,
            "symbol": self.symbol,
            "side": self.side.value,
            "volume": "0" if self.volume_lots is None else decimal_text(self.volume_lots),
            "price": "0" if self.price is None else decimal_text(self.price),
            "sl": "0" if self.stop_loss is None else decimal_text(self.stop_loss),
            "tp": "0",
            "position_ticket": self.position_ticket or "0",
            "deviation_points": str(self.deviation_points),
            "magic": str(self.magic),
            "comment": self.comment,
            "created_at": _iso(self.created_at),
        }

    @property
    def request_sha256(self) -> str:
        return _sha256_flat(self._core_dict())

    def to_spool_dict(self) -> dict[str, str]:
        """Flat JSON object whose values are ALL strings (simple, exact parsing inside MQL5)."""
        doc = self._core_dict()
        doc["request_sha256"] = self.request_sha256
        return doc

    def to_native_request(self, sdk: Any) -> dict[str, Any]:
        """MetaTrader5 ``order_send`` payload. The SDK requires floats, converted only at this boundary."""
        const = _sdk_constants(sdk)
        if self.action == "AMEND_STOP":
            return {
                "action": const["TRADE_ACTION_SLTP"],
                "symbol": self.symbol,
                "position": int(str(self.position_ticket)),
                "sl": float(self.stop_loss),  # type: ignore[arg-type]
                "tp": 0.0,
                "magic": self.magic,
                "comment": self.comment,
            }
        payload: dict[str, Any] = {
            "action": const["TRADE_ACTION_DEAL"],
            "symbol": self.symbol,
            "volume": float(self.volume_lots),  # type: ignore[arg-type]
            "type": const["ORDER_TYPE_BUY"] if self.side is Side.BUY else const["ORDER_TYPE_SELL"],
            "deviation": self.deviation_points,
            "magic": self.magic,
            "comment": self.comment,
            "type_time": const["ORDER_TIME_GTC"],
            "type_filling": const["ORDER_FILLING_IOC"],
        }
        if self.price is not None:
            payload["price"] = float(self.price)
        if self.stop_loss is not None and self.action == "OPEN":
            payload["sl"] = float(self.stop_loss)
        if self.position_ticket is not None:
            payload["position"] = int(self.position_ticket)
        return payload


_RECEIPT_STATUSES = ("FILLED", "PARTIAL", "MODIFIED", "REJECTED", "UNKNOWN")


@dataclass(frozen=True, slots=True)
class Mt5OrderReceipt:
    request_id: str
    request_sha256: str
    status: str
    retcode: int
    position_ticket: str | None
    deal_ticket: str | None
    volume_lots: Decimal | None
    price: Decimal | None
    stop_loss: Decimal | None
    server: str
    observed_at: datetime
    transport: str
    message: str = ""

    def __post_init__(self) -> None:
        if self.status not in _RECEIPT_STATUSES:
            raise Mt5TransportError(f"unknown MT5 receipt status {self.status!r}")
        if type(self.retcode) is not int or self.retcode < 0:
            raise Mt5TransportError("retcode must be a non-negative integer")
        utc_time(self.observed_at, "observed_at")

    @property
    def accepted(self) -> bool:
        return self.status not in ("REJECTED", "UNKNOWN")

    def to_wire_dict(self) -> dict[str, Any]:
        out = {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "status": self.status,
            "retcode": self.retcode,
            "position_ticket": self.position_ticket,
            "deal_ticket": self.deal_ticket,
            "volume_lots": None if self.volume_lots is None else decimal_text(self.volume_lots),
            "price": None if self.price is None else decimal_text(self.price),
            "stop_loss": None if self.stop_loss is None else decimal_text(self.stop_loss),
            "server": self.server,
            "observed_at": _iso(self.observed_at),
            "transport": self.transport,
            "message": self.message,
        }
        assert_safe_json_numbers(out)
        return out


def _sdk_constants(sdk: Any) -> dict[str, int]:
    return {name: int(getattr(sdk, name, default)) for name, default in _SDK_DEFAULTS.items()}


def _status_for_retcode(retcode: int, action: str, const: Mapping[str, int]) -> str:
    if retcode in (const["TRADE_RETCODE_DONE"], const["TRADE_RETCODE_PLACED"]):
        return "MODIFIED" if action == "AMEND_STOP" else "FILLED"
    if retcode == const["TRADE_RETCODE_DONE_PARTIAL"]:
        return "PARTIAL"
    return "REJECTED"


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


class Mt5Transport(Protocol):
    transport_name: str

    def connect(self, credentials: Mt5Credentials) -> Mt5AccountSnapshot: ...

    def account_info(self) -> Mt5AccountSnapshot: ...

    def symbol_tick(self, symbol: str) -> Mt5Tick: ...

    def positions(self) -> tuple[Mt5Position, ...]: ...

    def send_order(self, request: Mt5OrderRequest) -> Mt5OrderReceipt: ...

    def shutdown(self) -> None: ...


def _sdk_field(row: Any, name: str) -> Any:
    try:
        return row[name]
    except (KeyError, IndexError, TypeError, ValueError):
        return getattr(row, name)


class Mt5NativePythonTransport:
    """Wraps the official ``MetaTrader5`` Python SDK (IPC to a locally running MT5 terminal).

    The SDK module is injectable for tests and imported lazily on ``connect`` otherwise, so
    importing/constructing this transport never touches the terminal.
    """

    transport_name = TRANSPORT_NATIVE_PYTHON

    def __init__(
        self,
        *,
        mt5_module: Any | None = None,
        timeout_ms: int = 10_000,
        max_leverage: int = MAX_DEMO_LEVERAGE,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(timeout_ms) is not int or not (100 <= timeout_ms <= 120_000):
            raise ContractError("timeout_ms must be an integer in 100..120000")
        self._mt5 = mt5_module
        self._timeout_ms = timeout_ms
        self._max_leverage = max_leverage
        self._clock = clock or _utc_now
        self._connected = False
        self._credentials: Mt5Credentials | None = None

    def __repr__(self) -> str:
        return f"Mt5NativePythonTransport(connected={self._connected}, sdk_injected={self._mt5 is not None})"

    def _sdk(self) -> Any:
        if self._mt5 is None:
            try:
                self._mt5 = importlib.import_module("MetaTrader5")
            except ImportError as exc:
                raise Mt5TransportError(
                    "MetaTrader5 Python SDK is not installed on this host; use SPOOL_BRIDGE transport instead"
                ) from exc
        return self._mt5

    def _last_error(self) -> str:
        sdk = self._sdk()
        fn = getattr(sdk, "last_error", None)
        if fn is None:
            return "unknown"
        try:
            err = fn()
        except Exception as exc:  # SDK failure while reading last_error must never mask the original failure
            return f"last_error unavailable ({type(exc).__name__})"
        if isinstance(err, tuple) and err:
            return str(err[0])
        return "unknown"

    def connect(self, credentials: Mt5Credentials) -> Mt5AccountSnapshot:
        if not isinstance(credentials, Mt5Credentials):
            raise ContractError("connect requires Mt5Credentials")
        validate_mt5_server_name(
            credentials.broker_id,
            credentials.server,
            execution_mode=credentials.execution_mode,
            live_armed=(credentials.execution_mode == EXECUTION_MODE_LIVE),
        )
        if credentials.password is None:
            raise Mt5NotConfiguredError(f"{credentials.broker_id}: native MT5 login requires a password")
        sdk = self._sdk()
        ok = sdk.initialize(
            login=credentials.login,
            password=credentials.password.reveal(),
            server=credentials.server,
            timeout=self._timeout_ms,
        )
        if not ok:
            raise Mt5TransportError(f"MetaTrader5.initialize failed (code {self._last_error()})")
        self._connected = True
        self._credentials = credentials
        try:
            if not sdk.login(
                credentials.login,
                password=credentials.password.reveal(),
                server=credentials.server,
                timeout=self._timeout_ms,
            ):
                raise Mt5TransportError(f"MetaTrader5.login failed (code {self._last_error()})")
            snap = self.account_info()
            if snap.login != credentials.login or snap.server.casefold() != credentials.server.casefold():
                raise Mt5TransportError("MT5 terminal is logged into a different account/server than configured")
        except Exception:
            self.shutdown()
            raise
        return snap

    def _require_connected(self) -> Any:
        if not self._connected:
            raise Mt5TransportError("native MT5 transport is not connected")
        return self._sdk()

    def account_info(self) -> Mt5AccountSnapshot:
        sdk = self._require_connected()
        info = sdk.account_info()
        if info is None:
            raise Mt5TransportError(f"MetaTrader5.account_info unavailable (code {self._last_error()})")
        const = _sdk_constants(sdk)
        trade_mode = int(_sdk_field(info, "trade_mode"))
        server = str(_sdk_field(info, "server"))
        expected_mode = self._credentials.execution_mode if self._credentials else EXECUTION_MODE_DEMO
        broker_id = self._credentials.broker_id if self._credentials else "MT5"
        if expected_mode == EXECUTION_MODE_DEMO:
            if trade_mode != const["ACCOUNT_TRADE_MODE_DEMO"]:
                self.shutdown()
                raise LiveBrokerEndpointForbiddenError("MT5 account trade mode is not DEMO; live/real accounts are forbidden")
            validate_demo_server(broker_id, server)
            trade_mode_label = "DEMO"
        else:
            if trade_mode != const["ACCOUNT_TRADE_MODE_REAL"]:
                self.shutdown()
                raise ContractError("LIVE execution mode requires ACCOUNT_TRADE_MODE_REAL; refusing DEMO/CONTEST account")
            validate_mt5_server_name(broker_id, server, execution_mode=EXECUTION_MODE_LIVE, live_armed=True)
            trade_mode_label = "REAL"
        leverage = int(_sdk_field(info, "leverage"))
        if leverage <= 0 or leverage > self._max_leverage:
            raise Mt5MarginRefusalError(f"MT5 account leverage 1:{leverage} exceeds the 1:{self._max_leverage} cap")
        return Mt5AccountSnapshot(
            server=server,
            login=int(_sdk_field(info, "login")),
            currency=str(_sdk_field(info, "currency")),
            balance=_sdk_decimal(_sdk_field(info, "balance"), "balance"),
            equity=_sdk_decimal(_sdk_field(info, "equity"), "equity"),
            margin=_sdk_decimal(_sdk_field(info, "margin"), "margin"),
            margin_free=_sdk_decimal(_sdk_field(info, "margin_free"), "margin_free"),
            leverage=leverage,
            trade_mode=trade_mode_label,
        )

    def symbol_tick(self, symbol: str) -> Mt5Tick:
        sdk = self._require_connected()
        Mt5MarginCalculator.split_symbol(symbol)
        select = getattr(sdk, "symbol_select", None)
        if select is not None and not select(symbol, True):
            raise Mt5TransportError(f"MetaTrader5.symbol_select failed for {symbol}")
        tick = sdk.symbol_info_tick(symbol)
        if tick is None:
            raise Mt5TransportError(f"MetaTrader5.symbol_info_tick unavailable for {symbol}")
        return Mt5Tick(
            symbol=symbol,
            bid=_sdk_decimal(_sdk_field(tick, "bid"), "bid"),
            ask=_sdk_decimal(_sdk_field(tick, "ask"), "ask"),
            time_msc=_ticket_text(int(_sdk_field(tick, "time_msc")), "time_msc"),
        )

    def copy_rates(self, symbol: str, timeframe: str, count: int) -> list[dict[str, str]]:
        sdk = self._require_connected()
        Mt5MarginCalculator.split_symbol(symbol)
        if timeframe not in MT5_TIMEFRAMES:
            raise ContractError(f"timeframe must be one of the 21 MT5 timeframes {MT5_TIMEFRAMES}")
        if type(count) is not int or not (1 <= count <= 5000):
            raise ContractError("count must be an integer in 1..5000")
        tf_const = getattr(sdk, f"TIMEFRAME_{timeframe}", None)
        if tf_const is None:
            raise Mt5TransportError(f"MetaTrader5 SDK lacks TIMEFRAME_{timeframe}")
        rows = sdk.copy_rates_from_pos(symbol, tf_const, 0, count)
        if rows is None:
            raise Mt5TransportError(f"MetaTrader5.copy_rates_from_pos unavailable for {symbol}")
        out: list[dict[str, str]] = []
        for row in rows:
            bar = {
                "time": _ticket_text(int(_sdk_field(row, "time")), "time"),
                "open": decimal_text(_sdk_decimal(_sdk_field(row, "open"), "open")),
                "high": decimal_text(_sdk_decimal(_sdk_field(row, "high"), "high")),
                "low": decimal_text(_sdk_decimal(_sdk_field(row, "low"), "low")),
                "close": decimal_text(_sdk_decimal(_sdk_field(row, "close"), "close")),
                "tick_volume": _ticket_text(int(_sdk_field(row, "tick_volume")), "tick_volume"),
            }
            if Decimal(bar["low"]) > Decimal(bar["high"]):
                raise Mt5TransportError(f"{symbol} {timeframe} bar has low > high")
            out.append(bar)
        return out

    def positions(self) -> tuple[Mt5Position, ...]:
        sdk = self._require_connected()
        rows = sdk.positions_get()
        if rows is None:
            raise Mt5TransportError(f"MetaTrader5.positions_get unavailable (code {self._last_error()})")
        const = _sdk_constants(sdk)
        out: list[Mt5Position] = []
        for row in rows:
            ptype = int(_sdk_field(row, "type"))
            if ptype not in (const["POSITION_TYPE_BUY"], const["POSITION_TYPE_SELL"]):
                raise Mt5TransportError("unknown MT5 position type")
            sl = _sdk_decimal(_sdk_field(row, "sl"), "sl")
            out.append(Mt5Position(
                ticket=_ticket_text(int(_sdk_field(row, "ticket"))),
                symbol=str(_sdk_field(row, "symbol")),
                side=Side.BUY if ptype == const["POSITION_TYPE_BUY"] else Side.SELL,
                volume_lots=_sdk_decimal(_sdk_field(row, "volume"), "volume"),
                price_open=_sdk_decimal(_sdk_field(row, "price_open"), "price_open"),
                stop_loss=None if sl == 0 else sl,
                profit=_sdk_decimal(_sdk_field(row, "profit"), "profit"),
            ))
        return tuple(out)

    def send_order(self, request: Mt5OrderRequest) -> Mt5OrderReceipt:
        sdk = self._require_connected()
        payload = request.to_native_request(sdk)
        result = sdk.order_send(payload)
        if result is None:
            raise Mt5OutcomeUnknownError(f"MetaTrader5.order_send returned no result (code {self._last_error()}); outcome UNKNOWN")
        const = _sdk_constants(sdk)
        retcode = int(_sdk_field(result, "retcode"))
        status = _status_for_retcode(retcode, request.action, const)
        deal = int(_sdk_field(result, "deal") or 0)
        order = int(_sdk_field(result, "order") or 0)
        volume = _sdk_decimal(_sdk_field(result, "volume") or 0, "volume")
        price = _sdk_decimal(_sdk_field(result, "price") or 0, "price")
        position_ticket = request.position_ticket
        if position_ticket is None and status != "REJECTED":
            position_ticket = _ticket_text(order or deal, "position_ticket") if (order or deal) else None
        comment = str(_sdk_field(result, "comment") or "")[:64]
        return Mt5OrderReceipt(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            status=status,
            retcode=retcode,
            position_ticket=position_ticket,
            deal_ticket=None if deal == 0 else _ticket_text(deal, "deal_ticket"),
            volume_lots=None if volume == 0 else volume,
            price=None if price == 0 else price,
            stop_loss=request.stop_loss,
            server=self._credentials.server if self._credentials else "",
            observed_at=self._clock(),
            transport=self.transport_name,
            message="".join(ch for ch in comment if ch.isascii() and ch.isprintable()),
        )

    def shutdown(self) -> None:
        if self._connected and self._mt5 is not None:
            try:
                self._mt5.shutdown()
            except Exception as exc:  # shutdown failures are logged, never silently swallowed
                logger.warning("MetaTrader5.shutdown failed: %s", type(exc).__name__)
        self._connected = False


class Mt5SpoolBridgeTransport:
    """Cross-platform atomic file-spool transport to ``mt5/CasForexMt5Bridge.mq5``.

    Protocol ``cas-forex-mt5-spool/1`` (all files ASCII JSON, all numbers as decimal strings):

    - ``order_request_<id>.json``  Python -> EA, flat object, every value a string, carries
      ``request_sha256`` (SHA-256 of the canonical JSON of the other fields).
    - ``order_receipt_<id>.json``  EA -> Python, flat object echoing ``request_id`` and
      ``request_sha256``; accepted receipts are appended to a SHA-256 hash-chained audit log.
    - ``market_ticks.json``        EA -> Python, account/tick/position snapshot.

    Every file is written to a dot-prefixed ``.tmp`` sibling first and then atomically renamed.
    Credentials are never written to the spool; the EA runs inside an already logged-in terminal
    and the Python side verifies the published login/server/DEMO trade mode instead.
    """

    transport_name = TRANSPORT_SPOOL_BRIDGE

    def __init__(
        self,
        spool_dir: str | Path,
        *,
        receipt_timeout_seconds: float = 15.0,
        poll_interval_seconds: float = 0.25,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        max_leverage: int = MAX_DEMO_LEVERAGE,
        max_file_bytes: int = MAX_SPOOL_FILE_BYTES,
    ) -> None:
        if not isinstance(spool_dir, (str, Path)) or not str(spool_dir).strip():
            raise Mt5NotConfiguredError("spool_dir must be a non-empty path")
        if not (0 < receipt_timeout_seconds <= 300) or not (0 < poll_interval_seconds <= 5):
            raise ContractError("receipt timeout must be in (0, 300] s and poll interval in (0, 5] s")
        self.spool_dir = Path(spool_dir)
        self._timeout = float(receipt_timeout_seconds)
        self._poll = float(poll_interval_seconds)
        self._sleep = sleep
        self._monotonic = monotonic
        self._max_leverage = max_leverage
        self._max_file_bytes = max_file_bytes
        self._credentials: Mt5Credentials | None = None

    def __repr__(self) -> str:
        return f"Mt5SpoolBridgeTransport(spool_dir={self.spool_dir.name!r}, connected={self._credentials is not None})"

    def prepare_spool_directory(self) -> Path:
        self.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return apply_verified_directory_mode(self.spool_dir, 0o700)

    def connect(self, credentials: Mt5Credentials) -> Mt5AccountSnapshot:
        if not isinstance(credentials, Mt5Credentials):
            raise ContractError("connect requires Mt5Credentials")
        validate_mt5_server_name(
            credentials.broker_id,
            credentials.server,
            execution_mode=credentials.execution_mode,
            live_armed=(credentials.execution_mode == EXECUTION_MODE_LIVE),
        )
        self.prepare_spool_directory()
        self._credentials = credentials
        try:
            snap = self.account_info()
            if snap.login != credentials.login or snap.server.casefold() != credentials.server.casefold():
                raise Mt5TransportError("MT5 EA is attached to a different account/server than configured")
        except Exception:
            self._credentials = None
            raise
        return snap

    def _require_connected(self) -> Mt5Credentials:
        if self._credentials is None:
            raise Mt5TransportError("spool MT5 transport is not connected")
        return self._credentials

    def _market_doc(self) -> dict[str, Any]:
        path = self.spool_dir / "market_ticks.json"
        try:
            doc = _read_spool_json(path, max_bytes=self._max_file_bytes)
        except FileNotFoundError:
            raise Mt5TransportError("market_ticks.json not published yet; is CasForexMt5Bridge EA running?") from None
        if type(doc) is not dict or doc.get("protocol") != MT5_SPOOL_PROTOCOL:
            raise Mt5TransportError("market_ticks.json protocol mismatch")
        creds = self._credentials
        expected_mode = creds.execution_mode if creds else EXECUTION_MODE_DEMO
        broker_id = creds.broker_id if creds else "MT5"
        reported_mode = doc.get("account_trade_mode")
        if expected_mode == EXECUTION_MODE_DEMO:
            if reported_mode != "DEMO":
                raise LiveBrokerEndpointForbiddenError("MT5 EA reports a non-DEMO account; live/real accounts are forbidden")
            validate_demo_server(broker_id, str(doc.get("server", "")))
        else:
            if reported_mode != "REAL":
                raise ContractError("LIVE execution mode requires MT5 EA account_trade_mode=REAL")
            validate_mt5_server_name(
                broker_id, str(doc.get("server", "")), execution_mode=EXECUTION_MODE_LIVE, live_armed=True
            )
        return doc

    def account_info(self) -> Mt5AccountSnapshot:
        doc = self._market_doc()
        acct = doc.get("account")
        if type(acct) is not dict:
            raise Mt5TransportError("market_ticks.json missing account object")
        login_raw = acct.get("login")
        if not isinstance(login_raw, str) or not _LOGIN_RE.fullmatch(login_raw):
            raise Mt5TransportError("account.login must be a decimal string")
        lev_raw = acct.get("leverage")
        if not isinstance(lev_raw, str) or not lev_raw.isdigit():
            raise Mt5TransportError("account.leverage must be a decimal string")
        leverage = int(lev_raw)
        if leverage <= 0 or leverage > self._max_leverage:
            raise Mt5MarginRefusalError(f"MT5 account leverage 1:{leverage} exceeds the 1:{self._max_leverage} demo cap")
        currency = acct.get("currency")
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            raise Mt5TransportError("account.currency must be an ISO-4217 code")
        return Mt5AccountSnapshot(
            server=str(doc["server"]),
            login=int(login_raw),
            currency=currency,
            balance=_wire_decimal(acct.get("balance"), "balance"),  # type: ignore[arg-type]
            equity=_wire_decimal(acct.get("equity"), "equity"),  # type: ignore[arg-type]
            margin=_wire_decimal(acct.get("margin"), "margin"),  # type: ignore[arg-type]
            margin_free=_wire_decimal(acct.get("margin_free"), "margin_free"),  # type: ignore[arg-type]
            leverage=leverage,
            trade_mode=str(doc.get("account_trade_mode", "DEMO")),
        )

    def symbol_tick(self, symbol: str) -> Mt5Tick:
        Mt5MarginCalculator.split_symbol(symbol)
        doc = self._market_doc()
        ticks = doc.get("ticks")
        if type(ticks) is not list:
            raise Mt5TransportError("market_ticks.json missing ticks list")
        for item in ticks:
            if type(item) is dict and item.get("symbol") == symbol:
                return Mt5Tick(
                    symbol=symbol,
                    bid=_wire_decimal(item.get("bid"), "bid", positive=True),  # type: ignore[arg-type]
                    ask=_wire_decimal(item.get("ask"), "ask", positive=True),  # type: ignore[arg-type]
                    time_msc=_ticket_text(item.get("time_msc"), "time_msc"),
                )
        raise Mt5TransportError(f"no published MT5 tick for {symbol}")

    def positions(self) -> tuple[Mt5Position, ...]:
        doc = self._market_doc()
        rows = doc.get("positions", [])
        if type(rows) is not list:
            raise Mt5TransportError("market_ticks.json positions must be a list")
        out: list[Mt5Position] = []
        for item in rows:
            if type(item) is not dict:
                raise Mt5TransportError("position entries must be objects")
            side_raw = item.get("side")
            if side_raw not in ("BUY", "SELL"):
                raise Mt5TransportError("position side must be BUY or SELL")
            out.append(Mt5Position(
                ticket=_ticket_text(item.get("ticket")),
                symbol=str(item.get("symbol")),
                side=Side(side_raw),
                volume_lots=_wire_decimal(item.get("volume"), "volume", positive=True),  # type: ignore[arg-type]
                price_open=_wire_decimal(item.get("price_open"), "price_open", positive=True),  # type: ignore[arg-type]
                stop_loss=_wire_decimal(item.get("sl", "0"), "sl", allow_zero_as_none=True),
                profit=_wire_decimal(item.get("profit", "0"), "profit"),  # type: ignore[arg-type]
            ))
        return tuple(out)

    def send_order(self, request: Mt5OrderRequest) -> Mt5OrderReceipt:
        creds = self._require_connected()
        doc = request.to_spool_dict()
        request_path = self.spool_dir / f"order_request_{request.request_id}.json"
        receipt_path = self.spool_dir / f"order_receipt_{request.request_id}.json"
        if request_path.exists() or receipt_path.exists():
            raise Mt5TransportError(f"request_id {request.request_id} already present in spool; never resubmitted")
        _atomic_write_json(request_path, doc)
        deadline = self._monotonic() + self._timeout
        while True:
            if receipt_path.exists():
                receipt = self._parse_receipt(receipt_path, request, creds)
                try:
                    receipt_path.unlink()
                except OSError as exc:
                    logger.warning("MT5 receipt cleanup failed for %s: %s", receipt_path.name, type(exc).__name__)
                return receipt
            if self._monotonic() >= deadline:
                raise Mt5OutcomeUnknownError(
                    f"no MT5 receipt for {request.request_id} within {self._timeout} s; outcome UNKNOWN (not resubmitted)"
                )
            self._sleep(self._poll)

    def _parse_receipt(self, path: Path, request: Mt5OrderRequest, creds: Mt5Credentials) -> Mt5OrderReceipt:
        doc = _read_spool_json(path, max_bytes=self._max_file_bytes)
        if type(doc) is not dict or doc.get("protocol") != MT5_SPOOL_PROTOCOL:
            raise Mt5TransportError("receipt protocol mismatch")
        if any(type(v) is not str for v in doc.values()):
            raise Mt5TransportError("receipt values must all be strings")
        if doc.get("request_id") != request.request_id or doc.get("request_sha256") != request.request_sha256:
            raise Mt5TransportError("receipt does not bind the exact request_id/request_sha256")
        reported_mode = doc.get("account_trade_mode")
        if creds.execution_mode == EXECUTION_MODE_DEMO:
            if reported_mode != "DEMO":
                raise LiveBrokerEndpointForbiddenError("MT5 receipt reports a non-DEMO account")
            server = validate_demo_server(creds.broker_id, doc.get("server", ""))
        else:
            if reported_mode != "REAL":
                raise ContractError("LIVE receipt requires account_trade_mode=REAL")
            server = validate_mt5_server_name(
                creds.broker_id, doc.get("server", ""), execution_mode=EXECUTION_MODE_LIVE, live_armed=True
            )
        if server.casefold() != creds.server.casefold():
            raise Mt5TransportError("receipt server does not match the configured MT5 server")
        retcode_raw = doc.get("retcode", "")
        if not retcode_raw.isdigit():
            raise Mt5TransportError("receipt retcode must be a decimal string")
        pos = doc.get("position_ticket", "0")
        deal = doc.get("deal_ticket", "0")
        return Mt5OrderReceipt(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            status=str(doc.get("status")),
            retcode=int(retcode_raw),
            position_ticket=None if pos in ("", "0") else _ticket_text(pos, "position_ticket"),
            deal_ticket=None if deal in ("", "0") else _ticket_text(deal, "deal_ticket"),
            volume_lots=_wire_decimal(doc.get("volume", "0"), "volume", allow_zero_as_none=True),
            price=_wire_decimal(doc.get("price", "0"), "price", allow_zero_as_none=True),
            stop_loss=_wire_decimal(doc.get("sl", "0"), "sl", allow_zero_as_none=True),
            server=server,
            observed_at=_parse_iso(doc.get("observed_at"), "observed_at"),
            transport=self.transport_name,
            message="".join(
                ch for ch in doc.get("message", "")[:64] if ch.isascii() and ch.isprintable() and ch not in ('"', "\\")
            ),
        )

    def shutdown(self) -> None:
        self._credentials = None


class Mt5SpoolPaperTerminalEmulator:
    """Offline, air-gapped twin of ``mt5/CasForexMt5Bridge.mq5`` for tests and rehearsals.

    It reads ``order_request_*.json`` from a spool directory, applies the same DEMO paper
    semantics as the EA (fills at ask/bid, protective-stop validation, partial/full closes,
    1:500 margin check), writes ``order_receipt_*.json`` and republishes ``market_ticks.json``.
    It never connects to any network, broker or terminal.
    """

    def __init__(
        self,
        spool_dir: str | Path,
        *,
        server: str,
        login: int,
        quotes: Mapping[str, tuple[Decimal, Decimal]],
        balance: Decimal = Decimal("10000"),
        currency: str = "USD",
        leverage: int = MAX_DEMO_LEVERAGE,
        trade_mode: str = "DEMO",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.spool_dir = Path(spool_dir)
        self.server = server
        self.login = login
        self.quotes: dict[str, tuple[Decimal, Decimal]] = dict(quotes)
        self.balance = balance
        self.currency = currency
        self.leverage = leverage
        self.trade_mode = trade_mode
        self._clock = clock or _utc_now
        self._calc = Mt5MarginCalculator(leverage=min(leverage, MAX_DEMO_LEVERAGE), account_currency=currency)
        self._positions: dict[str, dict[str, Any]] = {}
        self._next_ticket = 500_000_001
        self._next_deal = 700_000_001
        self.processed: list[str] = []

    def set_quote(self, symbol: str, bid: Decimal, ask: Decimal) -> None:
        self.quotes[symbol] = (bid, ask)

    def _floating(self) -> Decimal:
        total = Decimal("0")
        for pos in self._positions.values():
            total += self._pnl(pos, self._close_price(pos), pos["volume"])
        return total

    def _used_margin(self) -> Decimal:
        total = Decimal("0")
        for pos in self._positions.values():
            units = self._calc.lots_to_units(pos["volume"])
            total += self._calc.required_margin(pos["symbol"], pos["side"], units, self.quotes)
        return total

    def _close_price(self, pos: Mapping[str, Any]) -> Decimal:
        bid, ask = self.quotes[pos["symbol"]]
        return bid if pos["side"] is Side.BUY else ask

    def _pnl(self, pos: Mapping[str, Any], close_price: Decimal, lots: Decimal) -> Decimal:
        units = self._calc.lots_to_units(lots)
        direction = Decimal(1) if pos["side"] is Side.BUY else Decimal(-1)
        with localcontext() as ctx:
            ctx.prec = 40
            pnl_quote = (close_price - pos["price_open"]) * units * direction
            quote_ccy = pos["symbol"][3:]
            rate = self._calc.conversion_rate(quote_ccy, self.quotes) if quote_ccy != self.currency else Decimal(1)
            return (pnl_quote * rate).quantize(Decimal("0.01"))

    def publish_market(self) -> None:
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        floating = self._floating()
        used = self._used_margin()
        equity = self.balance + floating
        now = self._clock()
        time_msc = str(int(now.timestamp() * 1000))
        doc = {
            "protocol": MT5_SPOOL_PROTOCOL,
            "server": self.server,
            "account_trade_mode": self.trade_mode,
            "observed_at": _iso(now),
            "account": {
                "login": str(self.login),
                "currency": self.currency,
                "balance": decimal_text(self.balance),
                "equity": decimal_text(equity),
                "margin": decimal_text(used),
                "margin_free": decimal_text(equity - used),
                "leverage": str(self.leverage),
            },
            "ticks": [
                {"symbol": sym, "bid": decimal_text(bid), "ask": decimal_text(ask), "time_msc": time_msc}
                for sym, (bid, ask) in sorted(self.quotes.items())
            ],
            "positions": [
                {
                    "ticket": ticket,
                    "symbol": pos["symbol"],
                    "side": pos["side"].value,
                    "volume": decimal_text(pos["volume"]),
                    "price_open": decimal_text(pos["price_open"]),
                    "sl": "0" if pos["sl"] is None else decimal_text(pos["sl"]),
                    "profit": decimal_text(self._pnl(pos, self._close_price(pos), pos["volume"])),
                }
                for ticket, pos in sorted(self._positions.items())
            ],
        }
        _atomic_write_json(self.spool_dir / "market_ticks.json", doc)

    def _receipt(self, req: Mapping[str, str], status: str, retcode: int, **extra: str) -> dict[str, str]:
        out = {
            "protocol": MT5_SPOOL_PROTOCOL,
            "request_id": req["request_id"],
            "request_sha256": req["request_sha256"],
            "status": status,
            "retcode": str(retcode),
            "position_ticket": "0",
            "deal_ticket": "0",
            "volume": "0",
            "price": "0",
            "sl": "0",
            "server": self.server,
            "account_trade_mode": self.trade_mode,
            "observed_at": _iso(self._clock()),
            "message": "",
        }
        out.update(extra)
        return out

    def _deal_ticket(self) -> str:
        self._next_deal += 1
        return str(self._next_deal)

    def _execute(self, req: Mapping[str, str]) -> dict[str, str]:
        core = {k: v for k, v in req.items() if k != "request_sha256"}
        if req.get("protocol") != MT5_SPOOL_PROTOCOL or _sha256_flat(core) != req.get("request_sha256"):
            return self._receipt(req, "REJECTED", 10013, message="request hash mismatch")
        action = req["action"]
        symbol = req["symbol"]
        if symbol not in self.quotes:
            return self._receipt(req, "REJECTED", 10013, message="unknown symbol")
        bid, ask = self.quotes[symbol]
        sl = Decimal(req["sl"]) if req["sl"] != "0" else None
        if action == "OPEN":
            side = Side(req["side"])
            lots = Decimal(req["volume"])
            price = ask if side is Side.BUY else bid
            if sl is None or (side is Side.BUY and sl >= bid) or (side is Side.SELL and sl <= ask):
                return self._receipt(req, "REJECTED", 10016, message="invalid stops")
            units = self._calc.lots_to_units(lots)
            required = self._calc.required_margin(symbol, side, units, self.quotes)
            free = self.balance + self._floating() - self._used_margin()
            if required > free:
                return self._receipt(req, "REJECTED", 10019, message="no money")
            ticket = str(self._next_ticket)
            self._next_ticket += 1
            self._positions[ticket] = {"symbol": symbol, "side": side, "volume": lots, "price_open": price, "sl": sl}
            return self._receipt(
                req, "FILLED", 10009, position_ticket=ticket, deal_ticket=self._deal_ticket(),
                volume=decimal_text(lots), price=decimal_text(price), sl=decimal_text(sl),
            )
        ticket = req["position_ticket"]
        pos = self._positions.get(ticket)
        if pos is None or pos["symbol"] != symbol:
            return self._receipt(req, "REJECTED", 10036, message="position not found")
        if action == "AMEND_STOP":
            if sl is None or (pos["side"] is Side.BUY and sl >= bid) or (pos["side"] is Side.SELL and sl <= ask):
                return self._receipt(req, "REJECTED", 10016, message="invalid stops")
            pos["sl"] = sl
            return self._receipt(req, "MODIFIED", 10009, position_ticket=ticket, sl=decimal_text(sl))
        lots = Decimal(req["volume"])
        if action == "REDUCE" and not (Decimal("0") < lots < pos["volume"]):
            return self._receipt(req, "REJECTED", 10014, message="invalid reduce volume")
        if action == "CLOSE" and lots != pos["volume"]:
            return self._receipt(req, "REJECTED", 10014, message="close volume mismatch")
        price = self._close_price(pos)
        self.balance += self._pnl(pos, price, lots)
        if action == "CLOSE":
            del self._positions[ticket]
        else:
            pos["volume"] = pos["volume"] - lots
        return self._receipt(
            req, "FILLED", 10009, position_ticket=ticket, deal_ticket=self._deal_ticket(),
            volume=decimal_text(lots), price=decimal_text(price),
        )

    def process_pending(self) -> int:
        count = 0
        for path in sorted(self.spool_dir.glob("order_request_*.json")):
            req = _read_spool_json(path)
            if type(req) is not dict or any(type(v) is not str for v in req.values()):
                raise Mt5TransportError("emulator received a malformed request")
            receipt = self._execute(req)
            _atomic_write_json(self.spool_dir / f"order_receipt_{req['request_id']}.json", receipt)
            path.unlink()
            self.processed.append(req["request_id"])
            count += 1
        return count

    def sleep_hook(self, _seconds: float) -> None:
        """Drop-in replacement for ``time.sleep`` inside :class:`Mt5SpoolBridgeTransport` tests."""
        self.process_pending()
        self.publish_market()


# ---------------------------------------------------------------------------
# Valve clearance
# ---------------------------------------------------------------------------


def require_valve_clearance(order: OrderIntent, decision: Any, *, expected_weights_sha256: str) -> ValveDecision:
    """Refuse execution unless ``decision`` is an admitted ForexMetaValveGate decision for this order."""
    if not isinstance(decision, ValveDecision):
        raise Mt5ValveClearanceError("ForexMetaValveGate pre-clearance is mandatory before any MT5/OANDA execution")
    if not decision.admitted or decision.valve_mode != "ADMIT" or decision.hard_veto or not decision.mlp_admitted:
        raise Mt5ValveClearanceError(
            f"ForexMetaValveGate did not admit this order ({decision.valve_mode})", decision=decision
        )
    if decision.mlp_score < decision.threshold:
        raise Mt5ValveClearanceError("ForexMetaValveGate score below threshold", decision=decision)
    if decision.weights_sha256 != expected_weights_sha256:
        raise Mt5ValveClearanceError("ValveDecision was produced by different Valve weights", decision=decision)
    if decision.selected_action_ref != order.action_ref:
        raise Mt5ValveClearanceError("ValveDecision does not bind this order's action_ref", decision=decision)
    return decision


def _expected_valve_sha(valve_gate: ForexMetaValveGate | None, expected: str | None) -> str:
    if valve_gate is not None:
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("valve_gate must be a ForexMetaValveGate")
        sha = valve_gate.weights_sha256
        if expected is not None and expected != sha:
            raise ContractError("expected_valve_weights_sha256 does not match the supplied ForexMetaValveGate")
        return sha
    if expected is None:
        raise ContractError("a ForexMetaValveGate (or its weights SHA-256) is mandatory for every broker venue")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ContractError("expected_valve_weights_sha256 must be a lowercase SHA-256 digest")
    return expected


class _AuditChain:
    def __init__(self) -> None:
        self._records: list[BrokerAuditReceipt] = []

    @property
    def records(self) -> tuple[BrokerAuditReceipt, ...]:
        return tuple(self._records)

    @staticmethod
    def _record_sha(sequence: int, event_kind: str, observed_at: datetime, payload: dict[str, Any], previous: str) -> str:
        body = {
            "sequence": sequence,
            "event_kind": event_kind,
            "observed_at": _iso(observed_at),
            "payload": payload,
            "previous_sha256": previous,
        }
        return sha256(canonical_bytes(body)).hexdigest()

    def append(self, event_kind: str, observed_at: datetime, payload: dict[str, Any]) -> BrokerAuditReceipt:
        assert_safe_json_numbers(payload)
        previous = self._records[-1].record_sha256 if self._records else GENESIS_SHA256
        sequence = len(self._records) + 1
        record = BrokerAuditReceipt(
            sequence=sequence,
            event_kind=event_kind,
            observed_at=observed_at,
            payload=payload,
            previous_sha256=previous,
            record_sha256=self._record_sha(sequence, event_kind, observed_at, payload, previous),
        )
        self._records.append(record)
        return record

    def verify(self) -> bool:
        previous = GENESIS_SHA256
        for idx, rec in enumerate(self._records, start=1):
            if rec.sequence != idx or rec.previous_sha256 != previous:
                return False
            if rec.record_sha256 != self._record_sha(rec.sequence, rec.event_kind, rec.observed_at, rec.payload, rec.previous_sha256):
                return False
            previous = rec.record_sha256
        return True


# ---------------------------------------------------------------------------
# Venues
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Mt5ExecutionResult:
    broker_id: str
    order: OrderIntent
    request: Mt5OrderRequest | None
    receipt: Mt5OrderReceipt | None
    oanda_receipt: dict[str, Any] | None
    account_after: Mt5AccountSnapshot | None
    positions_after: tuple[Mt5Position, ...]
    margin_check: Mt5MarginCheck | None
    valve_mode: str
    audit_record: BrokerAuditReceipt

    @property
    def accepted(self) -> bool:
        if self.receipt is not None:
            return self.receipt.accepted
        return self.oanda_receipt is not None and self.oanda_receipt.get("status") in ("FILLED", "CREATED")


class Mt5PaperBrokerVenue:
    """Demo-only MT5 venue: translates OrderIntents into MT5 requests behind Valve + margin gates.

    Mirrors ``SealedLiveFeedPaperVenue`` / ``SQLiteVenue`` semantics: each executed intent yields an
    exact receipt, refreshed account equity and positions, and a SHA-256 hash-chained audit record.
    """

    def __init__(
        self,
        *,
        broker_id: str,
        credentials: Mt5Credentials,
        transport: Mt5Transport,
        valve_gate: ForexMetaValveGate | None = None,
        expected_valve_weights_sha256: str | None = None,
        margin_calculator: Mt5MarginCalculator | None = None,
        min_post_trade_margin_level_pct: Decimal = DEFAULT_MIN_POST_TRADE_MARGIN_LEVEL_PCT,
        max_volume_lots: Decimal = MT5_MAX_VOLUME_DEFAULT,
        deviation_points: int = 20,
        magic: int = DEFAULT_MAGIC,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if broker_id not in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            raise ContractError("Mt5PaperBrokerVenue serves HUGOSWAY_MT5 or LHFX_MT5 only")
        if not isinstance(credentials, Mt5Credentials) or credentials.broker_id != broker_id:
            raise ContractError("credentials must be Mt5Credentials for the same broker")
        self.broker_id = broker_id
        self._credentials = credentials
        self._transport = transport
        self._valve_sha = _expected_valve_sha(valve_gate, expected_valve_weights_sha256)
        self._calc = margin_calculator or Mt5MarginCalculator(leverage=BROKER_SPECS[broker_id].max_leverage)
        self._min_level = decimal_value(min_post_trade_margin_level_pct, "min_post_trade_margin_level_pct", positive=True)
        self._max_lots = decimal_value(max_volume_lots, "max_volume_lots", positive=True)
        self._deviation = deviation_points
        self._magic = magic
        self._clock = clock or _utc_now
        self._audit = _AuditChain()
        self._account: Mt5AccountSnapshot | None = None
        self._positions: tuple[Mt5Position, ...] = ()
        self._request_counter = 0

    def __repr__(self) -> str:
        return (
            f"Mt5PaperBrokerVenue(broker_id={self.broker_id!r}, server={self._credentials.server!r}, "
            f"transport={getattr(self._transport, 'transport_name', '?')!r}, connected={self._account is not None})"
        )

    @property
    def transport_name(self) -> str:
        return str(getattr(self._transport, "transport_name", "UNKNOWN"))

    @property
    def server(self) -> str:
        return self._credentials.server

    @property
    def account(self) -> Mt5AccountSnapshot | None:
        return self._account

    @property
    def positions(self) -> tuple[Mt5Position, ...]:
        return self._positions

    @property
    def audit_chain(self) -> tuple[BrokerAuditReceipt, ...]:
        return self._audit.records

    def verify_audit_chain(self) -> bool:
        return self._audit.verify()

    def connect(self) -> Mt5AccountSnapshot:
        snap = self._transport.connect(self._credentials)
        expected_trade_mode = "REAL" if self._credentials.execution_mode == EXECUTION_MODE_LIVE else "DEMO"
        if snap.trade_mode != expected_trade_mode:
            if expected_trade_mode == "DEMO":
                raise LiveBrokerEndpointForbiddenError("MT5 account is not a DEMO account")
            raise ContractError("LIVE MT5 venue requires account trade_mode=REAL")
        if snap.leverage > BROKER_SPECS[self.broker_id].max_leverage:
            raise Mt5MarginRefusalError("MT5 account leverage exceeds the 1:500 cap")
        if snap.currency != self._calc.account_currency:
            self._calc = Mt5MarginCalculator(leverage=self._calc.leverage, account_currency=snap.currency)
        self._account = snap
        self._positions = self._transport.positions()
        self._audit.append("MT5_CONNECTED", self._clock(), {
            "broker_id": self.broker_id,
            "transport": self.transport_name,
            "account": snap.to_wire_dict(),
            "valve_weights_sha256": self._valve_sha,
        })
        return snap

    def _next_request_id(self, order: OrderIntent) -> str:
        self._request_counter += 1
        digest = order.fingerprint()[:16]
        return f"{self.broker_id.lower()}-{self._request_counter:06d}-{digest}"

    def _quotes_for(self, symbol: str) -> dict[str, tuple[Decimal, Decimal]]:
        quotes: dict[str, tuple[Decimal, Decimal]] = {}
        for sym in self._calc.required_symbols(symbol):
            tick = self._transport.symbol_tick(sym)
            quotes[sym] = (tick.bid, tick.ask)
        return quotes

    def _position(self, ticket: str) -> Mt5Position:
        for pos in self._transport.positions():
            if pos.ticket == ticket:
                return pos
        raise Mt5BridgeError(f"MT5 position {ticket} not found on {self.broker_id}")

    def probe(self) -> Mt5AccountSnapshot:
        """Health probe: refresh account + positions; raises Mt5TransportError if the terminal is unreachable."""
        if self._account is None:
            raise Mt5TransportError(f"{self.broker_id} venue is not connected")
        account = self._transport.account_info()
        positions = self._transport.positions()
        self._account = account
        self._positions = positions
        return account

    def execute(
        self,
        order: OrderIntent,
        *,
        valve_decision: ValveDecision,
        quote_guard: Callable[[str, Mt5Tick], None] | None = None,
        margin_guard: Callable[[Mt5MarginCheck, Mt5AccountSnapshot], None] | None = None,
    ) -> Mt5ExecutionResult:
        """Valve clearance -> quotes -> ``quote_guard`` -> margin check -> ``margin_guard`` -> send.

        Every guard runs strictly before anything is sent, so a guard refusal is always safe to
        route elsewhere. A failure after sending raises :class:`Mt5OutcomeUnknownError`.
        """
        if not isinstance(order, OrderIntent):
            raise ContractError("execute requires an OrderIntent")
        if self._account is None:
            raise Mt5TransportError(f"{self.broker_id} venue is not connected")
        decision = require_valve_clearance(order, valve_decision, expected_weights_sha256=self._valve_sha)
        now = self._clock()
        margin_check: Mt5MarginCheck | None = None
        request_id = self._next_request_id(order)
        comment = f"cas-{order.kind.value.lower()}"[:31]
        if order.kind is ActionKind.OPEN:
            side = order.side
            units = order.quantity_units
            if side is None or units is None or order.stop_price is None:
                raise ContractError("OPEN requires side, quantity and protective stop")
            lots = self._calc.units_to_lots(units)
            if lots > self._max_lots:
                raise Mt5MarginRefusalError(f"OPEN volume {decimal_text(lots)} lots exceeds venue cap {decimal_text(self._max_lots)}")
            quotes = self._quotes_for(order.symbol)
            bid, ask = quotes[order.symbol]
            if quote_guard is not None:
                quote_guard(self.broker_id, Mt5Tick(symbol=order.symbol, bid=bid, ask=ask, time_msc="0"))
            if side is Side.BUY and order.stop_price >= bid:
                raise ContractError("BUY protective stop must be below the current bid")
            if side is Side.SELL and order.stop_price <= ask:
                raise ContractError("SELL protective stop must be above the current ask")
            price = ask if side is Side.BUY else bid
            if order.limit_price is not None:
                if side is Side.BUY and price > order.limit_price:
                    raise Mt5MarginRefusalError("current ask exceeds the BUY limit price; not sent")
                if side is Side.SELL and price < order.limit_price:
                    raise Mt5MarginRefusalError("current bid is below the SELL limit price; not sent")
            account = self._transport.account_info()
            margin_check = self._calc.check_new_position(
                symbol=order.symbol,
                side=side,
                units=units,
                quotes=quotes,
                equity=account.equity,
                used_margin=account.margin,
                free_margin=account.margin_free,
                min_margin_level_pct=self._min_level,
            )
            if not margin_check.admitted:
                self._audit.append("MT5_MARGIN_REFUSED", now, {
                    "broker_id": self.broker_id,
                    "order_id": order.order_id,
                    "margin_check": margin_check.to_wire_dict(),
                })
                raise Mt5MarginRefusalError(f"1:{self._calc.leverage} margin gate refused OPEN: {margin_check.reason}")
            if margin_guard is not None:
                margin_guard(margin_check, account)
            request = Mt5OrderRequest(
                request_id=request_id, action="OPEN", symbol=order.symbol, side=side, volume_lots=lots,
                price=price, stop_loss=order.stop_price, position_ticket=None,
                deviation_points=self._deviation, magic=self._magic, comment=comment, created_at=now,
            )
        else:
            ticket = str(order.position_ticket)
            pos = self._position(ticket)
            if pos.symbol != order.symbol:
                raise ContractError("order symbol does not match the MT5 position symbol")
            closing_side = Side.SELL if pos.side is Side.BUY else Side.BUY
            if order.kind is ActionKind.AMEND_STOP:
                tick = self._transport.symbol_tick(order.symbol)
                if quote_guard is not None:
                    quote_guard(self.broker_id, tick)
                stop = order.stop_price
                if stop is None:
                    raise ContractError("AMEND_STOP requires stop_price")
                if pos.side is Side.BUY and stop >= tick.bid:
                    raise ContractError("BUY position stop must stay below the current bid")
                if pos.side is Side.SELL and stop <= tick.ask:
                    raise ContractError("SELL position stop must stay above the current ask")
                request = Mt5OrderRequest(
                    request_id=request_id, action="AMEND_STOP", symbol=order.symbol, side=pos.side, volume_lots=None,
                    price=None, stop_loss=stop, position_ticket=ticket,
                    deviation_points=self._deviation, magic=self._magic, comment=comment, created_at=now,
                )
            else:
                if order.kind is ActionKind.CLOSE:
                    lots = pos.volume_lots
                    if order.quantity_units is not None and self._calc.units_to_lots(order.quantity_units) != lots:
                        raise ContractError("CLOSE quantity must equal the full MT5 position volume")
                else:
                    lots = self._calc.units_to_lots(order.quantity_units)  # type: ignore[arg-type]
                    if not lots < pos.volume_lots:
                        raise ContractError("REDUCE volume must be strictly below the open position volume")
                tick = self._transport.symbol_tick(order.symbol)
                if quote_guard is not None:
                    quote_guard(self.broker_id, tick)
                request = Mt5OrderRequest(
                    request_id=request_id, action=order.kind.value, symbol=order.symbol, side=closing_side,
                    volume_lots=lots, price=tick.bid if closing_side is Side.SELL else tick.ask, stop_loss=None,
                    position_ticket=ticket, deviation_points=self._deviation, magic=self._magic,
                    comment=comment, created_at=now,
                )
        try:
            receipt = self._transport.send_order(request)
        except Mt5OutcomeUnknownError:
            self._audit.append("MT5_OUTCOME_UNKNOWN", self._clock(), {
                "broker_id": self.broker_id, "order_id": order.order_id, "request": request.to_spool_dict(),
            })
            raise
        except (Mt5TransportError, OSError) as exc:
            self._audit.append("MT5_OUTCOME_UNKNOWN", self._clock(), {
                "broker_id": self.broker_id, "order_id": order.order_id, "request": request.to_spool_dict(),
            })
            raise Mt5OutcomeUnknownError(
                f"{self.broker_id} send failed after dispatch ({type(exc).__name__}); outcome UNKNOWN, never resubmitted"
            ) from None
        if receipt.request_id != request.request_id or receipt.request_sha256 != request.request_sha256:
            raise Mt5OutcomeUnknownError("receipt does not bind the submitted request; outcome UNKNOWN")
        if receipt.status == "UNKNOWN":
            self._audit.append("MT5_OUTCOME_UNKNOWN", self._clock(), {
                "broker_id": self.broker_id, "order_id": order.order_id, "receipt": receipt.to_wire_dict(),
            })
            raise Mt5OutcomeUnknownError(f"{self.broker_id} EA reported outcome UNKNOWN for {request.request_id}")
        self._account = self._transport.account_info()
        self._positions = self._transport.positions()
        record = self._audit.append("MT5_ORDER_RECEIPT", self._clock(), {
            "broker_id": self.broker_id,
            "order_id": order.order_id,
            "action_ref": order.action_ref,
            "kind": order.kind.value,
            "valve_mode": decision.valve_mode,
            "valve_weights_sha256": decision.weights_sha256,
            "request": request.to_spool_dict(),
            "receipt": receipt.to_wire_dict(),
            "margin_check": None if margin_check is None else margin_check.to_wire_dict(),
            "account_after": self._account.to_wire_dict(),
            "positions_after": [p.to_wire_dict() for p in self._positions],
        })
        return Mt5ExecutionResult(
            broker_id=self.broker_id,
            order=order,
            request=request,
            receipt=receipt,
            oanda_receipt=None,
            account_after=self._account,
            positions_after=self._positions,
            margin_check=margin_check,
            valve_mode=decision.valve_mode,
            audit_record=record,
        )

    def shutdown(self) -> None:
        self._transport.shutdown()
        self._account = None


class OandaPracticeFallbackVenue:
    """Tertiary REST fallback wrapping :class:`OandaPracticePaperClient` (practice host only).

    v1 supports Valve-cleared OPEN market orders with stop-loss-on-fill. Management actions are
    refused explicitly (never silently approximated) because the practice client exposes no
    position-close/amend endpoint.
    """

    broker_id = BROKER_OANDA_PRACTICE
    transport_name = "OANDA_REST"

    def __init__(
        self,
        *,
        client: OandaPracticePaperClient,
        valve_gate: ForexMetaValveGate | None = None,
        expected_valve_weights_sha256: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(client, OandaPracticePaperClient):
            raise ContractError("client must be OandaPracticePaperClient")
        self.broker_id = BROKER_OANDA_LIVE if client.execution_mode == EXECUTION_MODE_LIVE else BROKER_OANDA_PRACTICE
        self._client = client
        self._valve_sha = _expected_valve_sha(valve_gate, expected_valve_weights_sha256)
        self._clock = clock or _utc_now
        self._audit = _AuditChain()
        self._summary: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return f"OandaPracticeFallbackVenue(client={self._client!r}, connected={self._summary is not None})"

    @property
    def server(self) -> str:
        return self._client.base_url

    @property
    def client(self) -> OandaPracticePaperClient:
        return self._client

    @property
    def summary(self) -> dict[str, Any] | None:
        return self._summary

    @property
    def nav(self) -> Decimal | None:
        if self._summary is None:
            return None
        return parse_decimal(str(self._summary["nav"]), "nav")

    @property
    def margin_available(self) -> Decimal | None:
        if self._summary is None:
            return None
        return parse_decimal(str(self._summary["margin_available"]), "margin_available")

    @property
    def audit_chain(self) -> tuple[BrokerAuditReceipt, ...]:
        return self._audit.records

    def verify_audit_chain(self) -> bool:
        return self._audit.verify()

    def connect(self) -> dict[str, Any]:
        if not self._client.is_active:
            tok_env = ENV_OANDA_LIVE_TOKEN if self._client.execution_mode == EXECUTION_MODE_LIVE else ENV_OANDA_PRACTICE_TOKEN
            acct_env = (
                ENV_OANDA_LIVE_ACCOUNT_ID
                if self._client.execution_mode == EXECUTION_MODE_LIVE
                else ENV_OANDA_PRACTICE_ACCOUNT_ID
            )
            raise Mt5NotConfiguredError(f"OANDA fallback requires {tok_env} and {acct_env}")
        self._summary = self._client.fetch_account_summary(now=self._clock())
        self._audit.append("OANDA_CONNECTED", self._clock(), {"broker_id": self.broker_id, "summary": self._summary})
        return self._summary

    def execute(self, order: OrderIntent, *, valve_decision: ValveDecision) -> Mt5ExecutionResult:
        if self._summary is None:
            raise Mt5TransportError("OANDA practice fallback is not connected")
        decision = require_valve_clearance(order, valve_decision, expected_weights_sha256=self._valve_sha)
        if order.kind is not ActionKind.OPEN:
            raise Mt5BridgeError(f"{order.kind.value} is not supported on the OANDA practice fallback v1")
        receipt = self._client.submit_paper_market_order(
            symbol=order.symbol,
            side=order.side,  # type: ignore[arg-type]
            units=order.quantity_units,  # type: ignore[arg-type]
            client_order_id=order.order_id,
            stop_loss_price=order.stop_price,
            price_bound=order.limit_price,
            now=self._clock(),
        )
        record = self._audit.append("OANDA_ORDER_RECEIPT", self._clock(), {
            "broker_id": self.broker_id,
            "order_id": order.order_id,
            "action_ref": order.action_ref,
            "valve_mode": decision.valve_mode,
            "receipt": receipt,
        })
        return Mt5ExecutionResult(
            broker_id=self.broker_id,
            order=order,
            request=None,
            receipt=None,
            oanda_receipt=receipt,
            account_after=None,
            positions_after=(),
            margin_check=None,
            valve_mode=decision.valve_mode,
            audit_record=record,
        )

    def shutdown(self) -> None:
        self._summary = None


# ---------------------------------------------------------------------------
# Broker hierarchy router
# ---------------------------------------------------------------------------

TransportFactory = Callable[[str, str, Any], Mt5Transport]


def _spool_channel(broker_id: str) -> str:
    return broker_id.lower()


def build_default_mt5_transport(broker_id: str, mode: str, spool_root: str | None) -> Mt5Transport:
    """Pick the MT5 transport for ``mode``; evaluated only at activation time (never on import)."""
    if mode == TRANSPORT_NATIVE_PYTHON:
        return Mt5NativePythonTransport()
    if mode == TRANSPORT_SPOOL_BRIDGE:
        if not spool_root:
            raise Mt5NotConfiguredError(f"{ENV_MT5_SPOOL_DIR} is required for SPOOL_BRIDGE transport")
        return Mt5SpoolBridgeTransport(Path(spool_root) / _spool_channel(broker_id))
    if mode == TRANSPORT_AUTO:
        if os.name == "nt" and importlib.util.find_spec("MetaTrader5") is not None:
            return Mt5NativePythonTransport()
        if spool_root:
            return Mt5SpoolBridgeTransport(Path(spool_root) / _spool_channel(broker_id))
        raise Mt5NotConfiguredError(
            f"AUTO transport found neither the MetaTrader5 SDK nor {ENV_MT5_SPOOL_DIR}"
        )
    raise ContractError(f"unknown MT5 transport mode {mode!r}")


class BrokerHierarchyRouter:
    """Selects HUGOSWAY_MT5 -> LHFX_MT5 -> OANDA_PRACTICE (primary overridable) behind the Valve.

    Construction parses and validates configuration only (live servers raise immediately) and
    performs no I/O. ``activate`` connects brokers in priority order, failing over only on
    connection/configuration errors; a detected live account aborts activation outright.
    """

    def __init__(
        self,
        *,
        environ: Mapping[str, str],
        valve_gate: ForexMetaValveGate,
        transport_factory: TransportFactory | None = None,
        oanda_client_factory: Callable[[Mapping[str, str]], OandaPracticePaperClient] | None = None,
        oanda_base_url: str | None = None,
        execution_mode: str | None = None,
        live_arm_phrase: str | None = None,
        clock: Callable[[], datetime] | None = None,
        min_post_trade_margin_level_pct: Decimal = DEFAULT_MIN_POST_TRADE_MARGIN_LEVEL_PCT,
    ) -> None:
        if not isinstance(environ, Mapping):
            raise ContractError("environ must be a key-value Mapping (never a .env file path)")
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("BrokerHierarchyRouter requires a ForexMetaValveGate; 1:500 never bypasses the Valve")
        self._env = {k: v for k, v in environ.items() if isinstance(k, str) and k.startswith("CAS_FOREX_")}
        self.execution_mode, self._live_armed = resolve_execution_mode(
            self._env, execution_mode=execution_mode, live_arm_phrase=live_arm_phrase
        )
        if execution_mode is not None:
            self._env[ENV_EXECUTION_MODE] = self.execution_mode
        if live_arm_phrase is not None:
            self._env[ENV_LIVE_ARM_PHRASE] = live_arm_phrase
        self._oanda_broker_id = (
            BROKER_OANDA_LIVE if self.execution_mode == EXECUTION_MODE_LIVE else BROKER_OANDA_PRACTICE
        )
        default_oanda_url = (
            DEFAULT_OANDA_LIVE_BASE_URL if self.execution_mode == EXECUTION_MODE_LIVE else DEFAULT_OANDA_PRACTICE_BASE_URL
        )
        raw_oanda_url = default_oanda_url if oanda_base_url is None else oanda_base_url
        self._oanda_base_url = OandaPracticePaperClient.validate_mode_url(
            raw_oanda_url, execution_mode=self.execution_mode
        )
        self._valve_gate = valve_gate
        self._transport_factory = transport_factory or build_default_mt5_transport
        self._oanda_client_factory = oanda_client_factory
        self._clock = clock or _utc_now
        self._min_level = min_post_trade_margin_level_pct

        base_chain = LIVE_BROKER_PRIORITY if self.execution_mode == EXECUTION_MODE_LIVE else BROKER_PRIORITY
        primary = _env_get(self._env, ENV_PRIMARY_BROKER).upper() or BROKER_HUGOSWAY_MT5
        if self.execution_mode == EXECUTION_MODE_LIVE and primary == BROKER_OANDA_PRACTICE:
            primary = BROKER_OANDA_LIVE
        if primary not in base_chain:
            raise ContractError(f"{ENV_PRIMARY_BROKER} must be one of {base_chain}")
        mode = _env_get(self._env, ENV_MT5_TRANSPORT_MODE).upper() or TRANSPORT_AUTO
        if mode not in TRANSPORT_MODES:
            raise ContractError(f"{ENV_MT5_TRANSPORT_MODE} must be one of {TRANSPORT_MODES}")
        self.primary_broker = primary
        self.transport_mode = mode
        self._spool_root = _env_get(self._env, ENV_MT5_SPOOL_DIR) or None
        self.priority_order: tuple[str, ...] = (primary,) + tuple(b for b in base_chain if b != primary)

        self._servers: dict[str, str | None] = {
            b: resolve_server(b, self._env, execution_mode=self.execution_mode, live_armed=self._live_armed)
            for b in base_chain
        }
        self._credentials: dict[str, Mt5Credentials | None] = {
            b: load_mt5_credentials(
                b,
                self._env,
                password_required=(mode != TRANSPORT_SPOOL_BRIDGE),
                execution_mode=self.execution_mode,
                live_arm_phrase=(REQUIRED_LIVE_ARM_PHRASE if self._live_armed else None),
            )
            for b in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5)
        }
        tok_env = ENV_OANDA_LIVE_TOKEN if self.execution_mode == EXECUTION_MODE_LIVE else ENV_OANDA_PRACTICE_TOKEN
        acct_env = (
            ENV_OANDA_LIVE_ACCOUNT_ID if self.execution_mode == EXECUTION_MODE_LIVE else ENV_OANDA_PRACTICE_ACCOUNT_ID
        )
        tok = _env_get(self._env, tok_env)
        acct = _env_get(self._env, acct_env)
        if bool(tok) != bool(acct):
            raise Mt5NotConfiguredError(f"{tok_env} and {acct_env} are required together")
        self._oanda_configured = bool(tok and acct)
        self._status: dict[str, str] = {
            b: ("STANDBY" if self.is_configured(b) else "NOT_CONFIGURED") for b in base_chain
        }
        self._failures: dict[str, str] = {}
        self._active: Mt5PaperBrokerVenue | OandaPracticeFallbackVenue | None = None

    @classmethod
    def from_process_env(cls, *, valve_gate: ForexMetaValveGate, **kwargs: Any) -> "BrokerHierarchyRouter":
        """Read the live process environment only (``os.environ``); ``.env`` files are never parsed."""
        return cls(environ=dict(os.environ), valve_gate=valve_gate, **kwargs)

    def __repr__(self) -> str:
        return (
            f"BrokerHierarchyRouter(priority={self.priority_order!r}, mode={self.transport_mode!r}, "
            f"active={self.active_broker!r})"
        )

    @property
    def active_broker(self) -> str | None:
        return None if self._active is None else self._active.broker_id

    @property
    def active_venue(self) -> Mt5PaperBrokerVenue | OandaPracticeFallbackVenue | None:
        return self._active

    def is_configured(self, broker_id: str) -> bool:
        if broker_id in (BROKER_OANDA_PRACTICE, BROKER_OANDA_LIVE):
            return self._oanda_configured
        return self._credentials.get(broker_id) is not None

    def _build_venue(self, broker_id: str) -> Mt5PaperBrokerVenue | OandaPracticeFallbackVenue:
        if broker_id in (BROKER_OANDA_PRACTICE, BROKER_OANDA_LIVE):
            if self._oanda_client_factory is not None:
                client = self._oanda_client_factory(self._env)
                if client.execution_mode != self.execution_mode:
                    raise ContractError(
                        f"oanda_client_factory mode {client.execution_mode!r} does not match router mode {self.execution_mode!r}"
                    )
            else:
                client = OandaPracticePaperClient.from_runtime_env(
                    self._env,
                    base_url=self._oanda_base_url,
                    execution_mode=self.execution_mode,
                    live_arm_phrase=(REQUIRED_LIVE_ARM_PHRASE if self._live_armed else None),
                )
            return OandaPracticeFallbackVenue(client=client, valve_gate=self._valve_gate, clock=self._clock)
        creds = self._credentials[broker_id]
        if creds is None:
            raise Mt5NotConfiguredError(f"{broker_id} has no runtime credentials")
        transport = self._transport_factory(broker_id, self.transport_mode, self._spool_root)
        return Mt5PaperBrokerVenue(
            broker_id=broker_id,
            credentials=creds,
            transport=transport,
            valve_gate=self._valve_gate,
            clock=self._clock,
            min_post_trade_margin_level_pct=self._min_level,
        )

    def activate(self) -> str:
        if self._active is not None:
            return self._active.broker_id
        for broker_id in self.priority_order:
            if not self.is_configured(broker_id):
                self._status[broker_id] = "NOT_CONFIGURED"
                continue
            try:
                venue = self._build_venue(broker_id)
                venue.connect()
            except LiveBrokerEndpointForbiddenError:
                self._status[broker_id] = "LIVE_FORBIDDEN"
                raise
            except (ContractError, OSError) as exc:
                self._status[broker_id] = "FAILED"
                self._failures[broker_id] = type(exc).__name__
                logger.warning("broker %s activation failed (%s); failing over", broker_id, type(exc).__name__)
                continue
            self._status[broker_id] = "ACTIVE"
            self._active = venue
            return broker_id
        raise BrokerFailoverExhaustedError(
            "no broker in the HUGOSWAY_MT5 -> LHFX_MT5 -> OANDA_PRACTICE hierarchy could be activated"
        )

    def execute(self, order: OrderIntent, *, valve_decision: ValveDecision) -> Mt5ExecutionResult:
        """Execute on the active venue only. An order is never re-sent to another broker."""
        if self._active is None:
            raise Mt5TransportError("no active broker; call activate() first")
        return self._active.execute(order, valve_decision=valve_decision)

    def execute_proposal(
        self,
        proposal: Any,
        *,
        symbol: str | None = None,
        position_ticket: str | None = None,
        current_view: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> Mt5ExecutionResult:
        """Run ForexMetaValveGate FIRST; only an admitted proposal is translated and sent."""
        decision = self._valve_gate.require_admissible(proposal, current_view=current_view, policy=policy, now=now)
        order = OrderIntent.from_action_intent(proposal.intent, symbol=symbol, position_ticket=position_ticket)
        return self.execute(order, valve_decision=decision)

    def routing_snapshot(self) -> dict[str, Any]:
        """Secret-free, safe-JSON routing summary for the loopback cockpit ``/api/broker-routing``."""
        chain = []
        for rank, broker_id in enumerate(self.priority_order, start=1):
            spec = BROKER_SPECS[broker_id]
            acct_type = spec.account_type
            if self.execution_mode == EXECUTION_MODE_LIVE and broker_id == BROKER_HUGOSWAY_MT5:
                acct_type = "ECN live"
            elif self.execution_mode == EXECUTION_MODE_LIVE and broker_id == BROKER_LHFX_MT5:
                acct_type = "STP/ECN live"
            chain.append({
                "broker_id": broker_id,
                "priority": rank,
                "role": spec.role,
                "label": spec.label,
                "platform": spec.platform,
                "server": self._servers[broker_id] if spec.server_env else self._oanda_base_url,
                "account_type": acct_type,
                "max_leverage": f"1:{spec.max_leverage}",
                "configured": self.is_configured(broker_id),
                "status": self._status[broker_id],
                "failure": self._failures.get(broker_id),
            })
        snap = {
            "schema": "cas-forex.broker-routing/1",
            "platform": MT5_PLATFORM_NAME,
            "platform_code": MT5_PLATFORM_CODE,
            "execution_mode": self.execution_mode,
            "demo_only": self.execution_mode == EXECUTION_MODE_DEMO,
            "live_trading_locked": self.execution_mode == EXECUTION_MODE_DEMO,
            "live_trading_armed": self._live_armed,
            "primary_broker": self.primary_broker,
            "active_broker": self.active_broker,
            "transport_mode": self.transport_mode,
            "timeframes": len(MT5_TIMEFRAMES),
            "valve": {
                "controller": "tks_meta_valve_controller",
                "parameters": self._valve_gate.controller.parameter_count,
                "threshold": decimal_text(Decimal(str(self._valve_gate.controller.threshold))),
                "weights_sha256": self._valve_gate.weights_sha256,
                "required": True,
            },
            "margin": {
                "max_leverage": f"1:{MAX_DEMO_LEVERAGE}",
                "min_post_trade_margin_level_pct": decimal_text(self._min_level),
            },
            "chain": chain,
        }
        assert_safe_json_numbers(snap)
        return snap
