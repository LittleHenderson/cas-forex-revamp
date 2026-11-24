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

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
import hmac
import secrets
import sqlite3
import threading
import time
import uuid
from typing import Any, Protocol

from cas_forex_revamp.contracts import ActionKind, ContractError, Side, canonical_bytes, decimal_text, parse_decimal
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, utc_time
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    ValveDecision,
    ValveGrantError,
    ValveOrderGrant,
    ValveRefusalError,
    verify_and_consume_valve_order_grant,
)
from .live_auth_ticket import (
    LiveAuthTicketError,
    LiveAuthorizationContext,
    LiveAuthorizationError,
    build_live_authorization_context,
    verify_live_environ_authorization,
    verify_live_environ_authorization_context,
)
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
    OandaMutationJournal,
    OandaPracticePaperClient,
    assert_safe_json_numbers,
    resolve_execution_mode,
    strict_safe_json_loads,
)
from .live_market_stream import EXPANDED_MARKETS, INDEX_INSTRUMENTS

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
    "Mt5SnapshotIntegrityError",
    "Mt5SpoolBridgeTransport",
    "Mt5SpoolPaperTerminalEmulator",
    "STATUS_BROKER_OFFLINE",
    "SimMt5SpoolEa",
    "Mt5Tick",
    "Mt5Transport",
    "DEFAULT_OANDA_SUMMARY_MAX_AGE_SECONDS",
    "ENV_MT5_SPOOL_KEY_DIR",
    "ENV_VALVE_ADMISSION_KEY_FILE",
    "Mt5PostFillObservationError",
    "Mt5PreDispatchTransportError",
    "Mt5TransportError",
    "DEFAULT_WINDOWS_PORTABLE_SPOOL_DIR",
    "SpoolCustodyAce",
    "SpoolPathCustodyObservation",
    "VALVE_ADMISSION_PROTOCOL",
    "derive_spool_channel_key",
    "inspect_spool_path_custody",
    "compute_mt5_market_snapshot_hmac",
    "compute_mt5_order_history_hmac",
    "resolve_spool_key_dir",
    "sign_mt5_market_snapshot_doc",
    "sign_mt5_order_history_doc",
    "sign_spool_valve_admission",
    "spool_channel_key_id",
    "verify_spool_path_custody",
    "verify_spool_valve_admission",
    "ENV_INDEX_CONTRACT_SIZE",
    "ENV_SPX500_CONTRACT_SIZE",
    "ENV_NAS100_CONTRACT_SIZE",
    "ENV_US30_CONTRACT_SIZE",
    "MT5_SPX500_CONTRACT_SIZE_MULTI",
    "ENV_INDEX_LEVERAGE",
    "EXPANDED_MARKETS",
    "INDEX_INSTRUMENTS",
    "Mt5ValveClearanceError",
    "MANAGEMENT_ACTION_KINDS",
    "OandaPracticeFallbackVenue",
    "OrderIntent",
    "RISK_INCREASING_ACTION_KINDS",
    "RiskIncreasingOrderIntent",
    "RiskReducingOrderIntent",
    "normalize_market_symbol",
    "resolve_mt5_spool_dir",
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
MT5_SPOOL_PROTOCOL = "cas-forex-mt5-spool/2"
STATUS_BROKER_OFFLINE = "BROKER_OFFLINE"
MT5_CONTRACT_SIZE = Decimal("100000")
MT5_INDEX_CONTRACT_SIZE = Decimal("1")
MT5_SPX500_CONTRACT_SIZE_MULTI = Decimal("100")
MT5_GOLD_CONTRACT_SIZE = Decimal("100")
MT5_VOLUME_STEP = Decimal("0.01")
MT5_MIN_VOLUME = Decimal("0.01")
MT5_MAX_VOLUME_DEFAULT = Decimal("50")
MAX_DEMO_LEVERAGE = 500
DEFAULT_MT5_INDEX_LEVERAGE = 200
ENV_INDEX_LEVERAGE = "CAS_FOREX_INDEX_LEVERAGE"
ENV_INDEX_CONTRACT_SIZE = "CAS_FOREX_INDEX_CONTRACT_SIZE"
ENV_SPX500_CONTRACT_SIZE = "CAS_FOREX_SPX500_CONTRACT_SIZE"
ENV_NAS100_CONTRACT_SIZE = "CAS_FOREX_NAS100_CONTRACT_SIZE"
ENV_US30_CONTRACT_SIZE = "CAS_FOREX_US30_CONTRACT_SIZE"
DEFAULT_WINDOWS_PORTABLE_SPOOL_DIR = Path(r"D:\MetaTrader5\cas_forex_spool")
_INDEX_SYMBOL_ALIASES: dict[str, str] = {
    "NAS100": "NAS100",
    "USTEC": "NAS100",
    "US100": "NAS100",
    "NAS100USD": "NAS100",
    "NDX100": "NAS100",
    "US30": "US30",
    "DJ30": "US30",
    "WS30": "US30",
    "US30USD": "US30",
    "DJI30": "US30",
    "SPX500": "SPX500",
    "US500": "SPX500",
    "SP500": "SPX500",
    "SPX500USD": "SPX500",
    "US500CASH": "SPX500",
    "US500247": "SPX500",
    "XAUUSD": "XAUUSD",
    "GOLD": "XAUUSD",
    "GOLD247": "XAUUSD",
    "GOLDUSD": "XAUUSD",
    "XAUUSDUSD": "XAUUSD",
}


def normalize_market_symbol(raw: str) -> str:
    """Normalize broker suffixes (.ecn/.pro/.raw/.cash) & index aliases into EXPANDED_MARKETS."""
    if not isinstance(raw, str) or not raw.strip():
        raise ContractError("market symbol must be a non-empty string")
    cleaned = raw.strip().upper()
    for suffix in (".ECN", ".PRO", ".RAW", ".CASH", "_I", ".I", ".M"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    cleaned = re.sub(r"[^A-Z0-9]", "", cleaned)
    if cleaned in _INDEX_SYMBOL_ALIASES:
        return _INDEX_SYMBOL_ALIASES[cleaned]
    if cleaned in EXPANDED_FX_PAIRS:
        return cleaned
    raise ContractError(f"unsupported MT5 symbol {raw!r}; expected one of the {len(EXPANDED_MARKETS)} EXPANDED_MARKETS")


def resolve_mt5_spool_dir(environ: Mapping[str, str], *, is_windows: bool | None = None, default_dir: Path | None = None) -> str | None:
    """Resolve explicit CAS_FOREX_MT5_SPOOL_DIR or auto-discover staged D:\\MetaTrader5\\cas_forex_spool on Windows."""
    explicit = str(environ.get(ENV_MT5_SPOOL_DIR, "")).strip()
    if explicit:
        return explicit
    win = (os.name == "nt") if is_windows is None else is_windows
    if not win:
        return None
    has_mt5_cfg = bool(str(environ.get(ENV_HUGOSWAY_MT5_LOGIN, "")).strip() or str(environ.get(ENV_LHFX_MT5_LOGIN, "")).strip())
    candidate = default_dir if default_dir is not None else DEFAULT_WINDOWS_PORTABLE_SPOOL_DIR
    if has_mt5_cfg and candidate.is_dir():
        return str(candidate)
    return None
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
ENV_MT5_SPOOL_KEY_DIR = "CAS_FOREX_MT5_SPOOL_KEY_DIR"
ENV_VALVE_ADMISSION_KEY_FILE = "CAS_FOREX_VALVE_ADMISSION_KEY_FILE"  # nosec B105: environment variable name constant
DEFAULT_OANDA_SUMMARY_MAX_AGE_SECONDS = 15.0
VALVE_ADMISSION_PROTOCOL = "cas-forex-valve-admission/1"
MAX_VALVE_ADMISSION_TTL_SECONDS = 60
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
    BROKER_LHFX_MT5: "LHFXSA-Trade",
}
_PINNED_LIVE_MT5_SERVERS: dict[str, frozenset[str]] = {
    BROKER_HUGOSWAY_MT5: frozenset({"hugo pro5", "hugopro5", "hugo-real", "hugosway-real", "hugosway-live", "hugosway live"}),
    BROKER_LHFX_MT5: frozenset({"lhfxsa-live", "lhfx-live", "lhfxsa-real", "lhfxsa-trade", "lhfxsa trade", "lhfxsa live"}),
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


class Mt5PreDispatchTransportError(Mt5TransportError):
    """Explicit pre-dispatch connectivity/read failure strictly before order_send; failover-safe."""


class Mt5SnapshotIntegrityError(Mt5TransportError):
    """Raised when market_ticks.json fails HMAC, channel/login binding, monotonic sequence, or freshness."""


class Mt5SpoolReplayError(Mt5TransportError):
    """Raised when an MT5 spool request_id or monotonic_nonce is replayed."""


class Mt5PostFillObservationError(Mt5BridgeError):
    """Post-fill refresh/observation failure after confirmed execution; NEVER failover-safe."""


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


_WIN_TRUSTED_SYSTEM_SIDS = frozenset({
    "S-1-5-18",      # LOCAL SYSTEM
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-3-4",       # OWNER RIGHTS
})
_WIN_TRUSTED_ANCESTOR_OWNER_SIDS = _WIN_TRUSTED_SYSTEM_SIDS | frozenset({
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # NT SERVICE\TrustedInstaller
})
_WIN_BROAD_PRINCIPAL_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-32-545",  # BUILTIN\Users
    "S-1-5-11",      # Authenticated Users
    "S-1-5-7",       # Anonymous Logon
    "S-1-5-32-546",  # BUILTIN\Guests
    "S-1-5-4",       # Interactive
    "S-1-5-2",       # Network
})
_WIN_ACCESS_ALLOWED_ACE_TYPE = 0
_WIN_INHERITED_ACE_FLAG = 0x10
_WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_WIN_SE_DACL_PROTECTED = 0x1000
_WIN_ANCESTOR_DANGEROUS_MASK = 0x10000000 | 0x00080000 | 0x00040000 | 0x00000040  # GENERIC_ALL|WRITE_OWNER|WRITE_DAC|DELETE_CHILD
_WIN_EVERYONE_WRITE_MASK = _WIN_ANCESTOR_DANGEROUS_MASK | 0x40000000 | 0x00010000 | 0x00000002 | 0x00000004 | 0x00000100
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class SpoolCustodyAce:
    """Normalized Windows ACE entry for spool custody verification."""

    ace_type: int
    ace_flags: int
    access_mask: int
    sid: str

    @property
    def is_allow(self) -> bool:
        return self.ace_type == _WIN_ACCESS_ALLOWED_ACE_TYPE

    @property
    def is_inherited(self) -> bool:
        return bool(self.ace_flags & _WIN_INHERITED_ACE_FLAG)


@dataclass(frozen=True, slots=True)
class SpoolPathCustodyObservation:
    """Cross-platform filesystem custody observation (Win32 SID/DACL/reparse or POSIX mode/uid/symlink)."""

    path: str
    platform: str
    exists: bool
    is_dir: bool
    is_reg: bool
    is_reparse_or_symlink: bool
    owner_sid: str | None = None
    current_user_sid: str | None = None
    dacl_present: bool = True
    dacl_protected: bool = False
    aces: tuple[SpoolCustodyAce, ...] = ()
    posix_mode: int | None = None
    posix_uid: int | None = None
    current_uid: int | None = None


SpoolCustodyInspector = Callable[[Path], SpoolPathCustodyObservation]
_CACHED_WIN_USER_SID: str | None = None
_WIN32_API_LOCK = threading.Lock()
_WIN32_CUSTODY_API: dict[str, Any] | None = None


def _get_win32_custody_api() -> dict[str, Any]:
    """Lazily initialize and cache Win32 ctypes DLL handles, signatures, and structs once per process."""
    global _WIN32_CUSTODY_API
    cached = _WIN32_CUSTODY_API
    if cached is not None:
        return cached
    with _WIN32_API_LOCK:
        cached = _WIN32_CUSTODY_API
        if cached is not None:
            return cached
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class _TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", _SID_AND_ATTRIBUTES)]

        class _ACL_SIZE_INFO(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        class _ACE_HEADER(ctypes.Structure):
            _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]

        class _ACCESS_ALLOWED_ACE(ctypes.Structure):
            _fields_ = [("Header", _ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]

        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetFileAttributesW.restype = wintypes.DWORD
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]

        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)
        ]
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)
        ]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        advapi32.GetAclInformation.restype = wintypes.BOOL
        advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.GetAce.restype = wintypes.BOOL

        cached = {
            "ctypes": ctypes,
            "wintypes": wintypes,
            "advapi32": advapi32,
            "kernel32": kernel32,
            "_TOKEN_USER": _TOKEN_USER,
            "_ACL_SIZE_INFO": _ACL_SIZE_INFO,
            "_ACCESS_ALLOWED_ACE": _ACCESS_ALLOWED_ACE,
        }
        _WIN32_CUSTODY_API = cached
        return cached


def _win32_current_user_sid() -> str:
    global _CACHED_WIN_USER_SID
    if _CACHED_WIN_USER_SID is not None:
        return _CACHED_WIN_USER_SID
    api = _get_win32_custody_api()
    ctypes = api["ctypes"]
    wintypes = api["wintypes"]
    advapi32 = api["advapi32"]
    kernel32 = api["kernel32"]
    _TOKEN_USER = api["_TOKEN_USER"]

    tok = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
        raise Mt5TransportError("MT5_SPOOL_CUSTODY_VIOLATION: unable to query Windows process token")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(tok, 1, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise Mt5TransportError("MT5_SPOOL_CUSTODY_VIOLATION: empty Windows TokenUser buffer")
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(tok, 1, buf, needed.value, ctypes.byref(needed)):
            raise Mt5TransportError("MT5_SPOOL_CUSTODY_VIOLATION: GetTokenInformation failed")
        tu = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
        out = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(tu.User.Sid, ctypes.byref(out)):
            raise Mt5TransportError("MT5_SPOOL_CUSTODY_VIOLATION: ConvertSidToStringSidW failed")
        try:
            sid_str = str(out.value or "").strip()
        finally:
            kernel32.LocalFree(out)
        if not sid_str:
            raise Mt5TransportError("MT5_SPOOL_CUSTODY_VIOLATION: empty Windows owner SID")
        _CACHED_WIN_USER_SID = sid_str
        return sid_str
    finally:
        kernel32.CloseHandle(tok)


def _win32_apply_owner_only_dacl(path: Path) -> None:
    """Apply a protected explicit owner-only DACL (Owner + SYSTEM + Administrators, zero broad/inherited ACEs)."""
    owner_sid = _win32_current_user_sid()
    api = _get_win32_custody_api()
    ctypes = api["ctypes"]
    wintypes = api["wintypes"]
    advapi32 = api["advapi32"]
    kernel32 = api["kernel32"]

    is_dir = path.is_dir()
    flags = "OICI" if is_dir else ""
    sddl = f"D:P(A;{flags};FA;;;{owner_sid})(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
        raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: failed to build owner-only DACL for {path.name}")
    try:
        present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: GetSecurityDescriptorDacl failed for {path.name}")
        rc = advapi32.SetNamedSecurityInfoW(
            str(path), 1, 0x00000004 | 0x80000000, None, None, dacl, None
        )
        if rc != 0:
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: SetNamedSecurityInfoW failed ({rc}) for {path.name}")
    finally:
        kernel32.LocalFree(sd)


def _is_reparse_or_symlink(path: Path, st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) != 0:
        return True
    is_junc = getattr(path, "is_junction", None)
    return bool(callable(is_junc) and is_junc())


def inspect_spool_path_custody(path: Path) -> SpoolPathCustodyObservation:
    """Inspect real Win32 owner SID / DACL / reparse attributes (or POSIX uid / mode / symlink) on ``path``."""
    target = Path(path)
    if not os.path.lexists(target):
        return SpoolPathCustodyObservation(
            path=str(target), platform=os.name, exists=False, is_dir=False, is_reg=False, is_reparse_or_symlink=False
        )
    st = os.lstat(target)
    reparse_or_link = _is_reparse_or_symlink(target, st)
    if os.name == "nt":
        api = _get_win32_custody_api()
        ctypes = api["ctypes"]
        wintypes = api["wintypes"]
        advapi32 = api["advapi32"]
        kernel32 = api["kernel32"]
        _ACL_SIZE_INFO = api["_ACL_SIZE_INFO"]
        _ACCESS_ALLOWED_ACE = api["_ACCESS_ALLOWED_ACE"]

        attrs = kernel32.GetFileAttributesW(str(target))
        if attrs != 0xFFFFFFFF and (attrs & _WIN_FILE_ATTRIBUTE_REPARSE_POINT):
            reparse_or_link = True

        def _sid_str(psid: Any) -> str:
            if not psid:
                return ""
            out = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(out)):
                return ""
            try:
                return str(out.value or "").strip()
            finally:
                kernel32.LocalFree(out)

        owner_p = ctypes.c_void_p()
        dacl_p = ctypes.c_void_p()
        sd_p = ctypes.c_void_p()
        rc = advapi32.GetNamedSecurityInfoW(
            str(target), 1, 0x00000001 | 0x00000004,
            ctypes.byref(owner_p), None, ctypes.byref(dacl_p), None, ctypes.byref(sd_p),
        )
        if rc != 0:
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: GetNamedSecurityInfoW failed ({rc}) on {target}")
        try:
            owner_sid = _sid_str(owner_p.value)
            ctrl = wintypes.WORD()
            rev = wintypes.DWORD()
            protected = False
            if advapi32.GetSecurityDescriptorControl(sd_p, ctypes.byref(ctrl), ctypes.byref(rev)):
                protected = bool(ctrl.value & _WIN_SE_DACL_PROTECTED)
            dacl_present = bool(dacl_p.value)
            aces_list: list[SpoolCustodyAce] = []
            if dacl_present:
                info = _ACL_SIZE_INFO()
                if advapi32.GetAclInformation(dacl_p.value, ctypes.byref(info), ctypes.sizeof(info), 2):
                    for idx in range(info.AceCount):
                        p_ace = ctypes.c_void_p()
                        if advapi32.GetAce(dacl_p.value, idx, ctypes.byref(p_ace)):
                            ace_obj = ctypes.cast(p_ace, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
                            sid_addr = p_ace.value + _ACCESS_ALLOWED_ACE.SidStart.offset
                            aces_list.append(
                                SpoolCustodyAce(
                                    ace_type=int(ace_obj.Header.AceType),
                                    ace_flags=int(ace_obj.Header.AceFlags),
                                    access_mask=int(ace_obj.Mask),
                                    sid=_sid_str(sid_addr),
                                )
                            )
            return SpoolPathCustodyObservation(
                path=str(target),
                platform="nt",
                exists=True,
                is_dir=stat.S_ISDIR(st.st_mode),
                is_reg=stat.S_ISREG(st.st_mode),
                is_reparse_or_symlink=reparse_or_link,
                owner_sid=owner_sid,
                current_user_sid=_win32_current_user_sid(),
                dacl_present=dacl_present,
                dacl_protected=protected,
                aces=tuple(aces_list),
            )
        finally:
            kernel32.LocalFree(sd_p)

    cur_uid = os.geteuid() if hasattr(os, "geteuid") else None
    return SpoolPathCustodyObservation(
        path=str(target),
        platform="posix",
        exists=True,
        is_dir=stat.S_ISDIR(st.st_mode),
        is_reg=stat.S_ISREG(st.st_mode),
        is_reparse_or_symlink=reparse_or_link,
        posix_mode=stat.S_IMODE(st.st_mode),
        posix_uid=int(st.st_uid),
        current_uid=cur_uid,
    )


def _validate_single_custody_observation(obs: SpoolPathCustodyObservation, *, is_ancestor: bool) -> None:
    if not obs.exists:
        return
    if obs.is_reparse_or_symlink:
        raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: reparse point or symlink refused at {obs.path}")
    if is_ancestor and not obs.is_dir:
        raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: non-directory ancestor at {obs.path}")

    if obs.platform == "nt":
        cur_sid = (obs.current_user_sid or "").strip()
        owner_sid = (obs.owner_sid or "").strip()
        if not cur_sid or not owner_sid:
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: missing Windows owner SID on {obs.path}")
        if is_ancestor:
            allowed_owners = _WIN_TRUSTED_ANCESTOR_OWNER_SIDS | {cur_sid}
            if owner_sid not in allowed_owners:
                raise Mt5TransportError(
                    f"MT5_SPOOL_CUSTODY_VIOLATION: untrusted Windows ancestor owner SID {owner_sid} on {obs.path}"
                )
            if not obs.dacl_present:
                raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: NULL DACL on ancestor {obs.path}")
            allowed_principals = _WIN_TRUSTED_SYSTEM_SIDS | {cur_sid}
            for ace in obs.aces:
                if not ace.is_allow:
                    continue
                if ace.sid in allowed_principals:
                    continue
                if ace.sid == "S-1-1-0" and (ace.access_mask & _WIN_EVERYONE_WRITE_MASK):
                    raise Mt5TransportError(
                        f"MT5_SPOOL_CUSTODY_VIOLATION: Everyone write ACE on ancestor {obs.path}"
                    )
                if ace.access_mask & _WIN_ANCESTOR_DANGEROUS_MASK:
                    raise Mt5TransportError(
                        f"MT5_SPOOL_CUSTODY_VIOLATION: dangerous broad/foreign ACE ({ace.sid}) on ancestor {obs.path}"
                    )
            return

        # Spool root, channel, key dir, key file, nonce ledger, snapshot, request, receipt:
        allowed_obj_owners = {cur_sid} | ({"S-1-5-32-544", "S-1-5-18"} if cur_sid in ("S-1-5-32-544", "S-1-5-18") else set())
        if owner_sid not in allowed_obj_owners:
            raise Mt5TransportError(
                f"MT5_SPOOL_CUSTODY_VIOLATION: spool object owner SID {owner_sid} != process owner {cur_sid} on {obs.path}"
            )
        if not obs.dacl_present:
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: NULL DACL refused on spool object {obs.path}")
        allowed_principals = _WIN_TRUSTED_SYSTEM_SIDS | {cur_sid}
        for ace in obs.aces:
            if not ace.is_allow:
                continue
            if ace.sid in _WIN_BROAD_PRINCIPAL_SIDS or ace.sid not in allowed_principals:
                inh = "inherited " if ace.is_inherited else ""
                raise Mt5TransportError(
                    f"MT5_SPOOL_CUSTODY_VIOLATION: {inh}permissive/foreign Windows ACE ({ace.sid}) refused on {obs.path}"
                )
        return

    # POSIX custody checks
    mode = obs.posix_mode if obs.posix_mode is not None else 0
    if is_ancestor:
        if obs.current_uid is not None and obs.posix_uid is not None and obs.posix_uid not in (0, obs.current_uid):
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: untrusted POSIX ancestor uid on {obs.path}")
        if (mode & 0o002) and not (mode & stat.S_ISVTX):
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: world-writable non-sticky ancestor {obs.path}")
        return
    if obs.current_uid is not None and obs.posix_uid is not None and obs.posix_uid != obs.current_uid:
        raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: spool object uid mismatch on {obs.path}")
    if (mode & 0o077) != 0:
        raise Mt5TransportError(
            f"MT5_SPOOL_CUSTODY_VIOLATION: unsafe POSIX group/world permissions ({oct(mode)}) on {obs.path}"
        )


def verify_spool_path_custody(
    path: str | Path,
    *,
    expect_dir: bool | None = None,
    expect_file: bool | None = None,
    inspector: SpoolCustodyInspector | None = None,
    check_ancestors: bool = True,
) -> SpoolPathCustodyObservation:
    """Verify Windows SID/DACL/reparse (or POSIX uid/mode/symlink) custody across target and all ancestors (Finding [7])."""
    target = Path(path)
    inspect_fn = inspector or inspect_spool_path_custody
    if check_ancestors:
        for ancestor in reversed(target.parents):
            anc_obs = inspect_fn(ancestor)
            if anc_obs.exists:
                _validate_single_custody_observation(anc_obs, is_ancestor=True)
    obs = inspect_fn(target)
    if obs.exists:
        if expect_dir is True and not obs.is_dir:
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: expected directory at {target}")
        if expect_file is True and not obs.is_reg:
            raise Mt5TransportError(f"MT5_SPOOL_CUSTODY_VIOLATION: expected regular file at {target}")
        _validate_single_custody_observation(obs, is_ancestor=False)
    return obs


def _canonical_valve_admission_input(doc: Mapping[str, str]) -> str:
    """Canonical signed Valve admission message verified independently by EA and Emulator (Finding [7])."""
    fields = (
        "broker_channel",
        "account_login",
        "server",
        "execution_mode",
        "action",
        "symbol",
        "side",
        "volume",
        "sl",
        "tp",
        "position_ticket",
        "valve_decision_sha256",
        "valve_admission_expires_at",
    )
    return VALVE_ADMISSION_PROTOCOL + "|" + "|".join(str(doc.get(k, "")) for k in fields)


def _canonical_spool_request_hmac_input(doc: Mapping[str, str]) -> str:
    fields = (
        "protocol",
        "request_id",
        "monotonic_nonce",
        "issued_at",
        "expires_at",
        "broker_channel",
        "channel_key_id",
        "account_login",
        "server",
        "execution_mode",
        "valve_decision_sha256",
        "valve_admission_expires_at",
        "valve_admission_sig",
        "action",
        "symbol",
        "side",
        "volume",
        "price",
        "sl",
        "tp",
        "position_ticket",
        "deviation_points",
        "magic",
        "comment",
    )
    return "|".join(str(doc.get(k, "")) for k in fields)


def _canonical_spool_receipt_hmac_input(doc: Mapping[str, str]) -> str:
    fields = (
        "protocol",
        "request_id",
        "request_sha256",
        "monotonic_nonce",
        "status",
        "retcode",
        "position_ticket",
        "deal_ticket",
        "volume",
        "price",
        "sl",
        "tp",
        "account_trade_mode",
        "server",
        "observed_at",
        "message",
    )
    return "|".join(str(doc.get(k, "")) for k in fields)


def _spool_hmac_hex(key_bytes: bytes, message: str) -> str:
    return hmac.new(key_bytes, message.encode("utf-8"), sha256).hexdigest()


def _canonical_mt5_market_snapshot_input(doc: Mapping[str, Any]) -> str:
    """Build canonical pipe-delimited market snapshot string matching CasForexMt5Bridge.mq5 PublishMarket()."""
    for fld in (
        "protocol",
        "broker_channel",
        "channel_key_id",
        "execution_mode",
        "server",
        "account_trade_mode",
        "observed_at",
        "snapshot_seq",
    ):
        if type(doc.get(fld)) is not str:
            raise Mt5SnapshotIntegrityError(f"market_ticks.json {fld} must be a string")
    connected_val = doc.get("connected")
    if type(connected_val) is not bool:
        raise Mt5SnapshotIntegrityError("market_ticks.json connected must be a boolean")
    connected_str = "true" if connected_val else "false"
    acct = doc.get("account")
    if type(acct) is not dict:
        raise Mt5SnapshotIntegrityError("market_ticks.json account must be an object")
    for fld in ("login", "currency", "balance", "equity", "margin", "margin_free", "leverage"):
        if type(acct.get(fld)) is not str:
            raise Mt5SnapshotIntegrityError(f"market_ticks.json account.{fld} must be a string")
    ticks_raw = doc.get("ticks")
    if type(ticks_raw) is not list:
        raise Mt5SnapshotIntegrityError("market_ticks.json ticks must be a list")
    tick_parts: list[str] = []
    for item in ticks_raw:
        if type(item) is not dict:
            raise Mt5SnapshotIntegrityError("market_ticks.json tick entries must be objects")
        for fld in ("symbol", "bid", "ask", "time_msc"):
            if type(item.get(fld)) is not str:
                raise Mt5SnapshotIntegrityError(f"market_ticks.json tick.{fld} must be a string")
        tick_parts.append(f"{item['symbol']}:{item['bid']}:{item['ask']}:{item['time_msc']}")
    ticks_canon = ";".join(tick_parts)

    pos_raw = doc.get("positions")
    if type(pos_raw) is not list:
        raise Mt5SnapshotIntegrityError("market_ticks.json positions must be a list")
    pos_parts: list[str] = []
    for item in pos_raw:
        if type(item) is not dict:
            raise Mt5SnapshotIntegrityError("market_ticks.json position entries must be objects")
        for fld in ("ticket", "symbol", "side", "volume", "price_open", "sl", "tp", "profit"):
            if type(item.get(fld)) is not str:
                raise Mt5SnapshotIntegrityError(f"market_ticks.json position.{fld} must be a string")
        pos_parts.append(
            f"{item['ticket']}:{item['symbol']}:{item['side']}:{item['volume']}:"
            f"{item['price_open']}:{item['sl']}:{item['tp']}:{item['profit']}"
        )
    positions_canon = ";".join(pos_parts)

    ticks_sha = sha256(ticks_canon.encode("utf-8")).hexdigest()
    positions_sha = sha256(positions_canon.encode("utf-8")).hexdigest()
    return "|".join((
        doc["protocol"],
        doc["broker_channel"],
        doc["channel_key_id"],
        doc["execution_mode"],
        doc["server"],
        doc["account_trade_mode"],
        connected_str,
        doc["observed_at"],
        doc["snapshot_seq"],
        acct["login"],
        acct["currency"],
        acct["balance"],
        acct["equity"],
        acct["margin"],
        acct["margin_free"],
        acct["leverage"],
        ticks_sha,
        positions_sha,
    ))


def compute_mt5_market_snapshot_hmac(doc: Mapping[str, Any], *, channel_key: bytes) -> str:
    """Compute HMAC-SHA256 hex digest over canonical market_ticks.json fields."""
    if not isinstance(channel_key, (bytes, bytearray)) or len(channel_key) < 32:
        raise Mt5TransportError("channel_key must be >= 32 bytes")
    return _spool_hmac_hex(bytes(channel_key), _canonical_mt5_market_snapshot_input(doc))


def sign_mt5_market_snapshot_doc(
    doc: Mapping[str, Any],
    *,
    spool_dir: str | Path | None = None,
    key_dir: str | Path | None = None,
    broker_channel: str | None = None,
    channel_key: bytes | None = None,
    channel_key_id: str | None = None,
    snapshot_seq: int | str | None = None,
    observed_at: datetime | str | None = None,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> dict[str, Any]:
    """Return a copy of a market_ticks.json document signed with per-channel HMAC-SHA256."""
    out = dict(doc)
    out.setdefault("protocol", MT5_SPOOL_PROTOCOL)
    if "connected" not in out:
        out["connected"] = True
    out.setdefault("ticks", [])
    out.setdefault("positions", [])
    if broker_channel is not None and str(broker_channel).strip():
        ch = str(broker_channel).strip().lower()
    elif isinstance(out.get("broker_channel"), str) and out["broker_channel"].strip():
        ch = out["broker_channel"].strip().lower()
    elif spool_dir is not None and Path(spool_dir).name.lower() in ("hugosway_mt5", "lhfx_mt5"):
        ch = Path(spool_dir).name.lower()
    elif "lhfx" in str(out.get("server", "")).lower():
        ch = "lhfx_mt5"
    else:
        ch = "hugosway_mt5"
    if ch not in ("hugosway_mt5", "lhfx_mt5"):
        raise Mt5TransportError(f"unsupported MT5 broker channel {ch!r}")
    out["broker_channel"] = ch
    if channel_key is None:
        if spool_dir is None and key_dir is None:
            raise Mt5TransportError("sign_mt5_market_snapshot_doc requires spool_dir, key_dir, or channel_key")
        base_dir = Path(spool_dir) if spool_dir is not None else Path(key_dir or ".")
        master = _load_or_create_spool_hmac_key(base_dir, key_dir=key_dir, custody_inspector=custody_inspector)
        eff_key = derive_spool_channel_key(master, ch)
    else:
        eff_key = bytes(channel_key)
    eff_key_id = channel_key_id if channel_key_id is not None else spool_channel_key_id(eff_key, ch)
    out["channel_key_id"] = eff_key_id
    if "execution_mode" not in out or not isinstance(out.get("execution_mode"), str):
        out["execution_mode"] = EXECUTION_MODE_LIVE if out.get("account_trade_mode") == "REAL" else EXECUTION_MODE_DEMO
    if observed_at is not None:
        out["observed_at"] = observed_at if isinstance(observed_at, str) else _iso(observed_at)
    elif not isinstance(out.get("observed_at"), str) or not out["observed_at"].strip():
        out["observed_at"] = _iso(_utc_now())
    if snapshot_seq is not None:
        out["snapshot_seq"] = str(int(snapshot_seq))
    elif not isinstance(out.get("snapshot_seq"), str) or not str(out.get("snapshot_seq", "")).isdigit():
        out["snapshot_seq"] = "1"
    out["snapshot_hmac_sha256"] = compute_mt5_market_snapshot_hmac(out, channel_key=eff_key)
    return out


def _canonical_spool_order_history_hmac_input(doc: Mapping[str, Any]) -> str:
    """Canonical HMAC message for order_history.json matching mt5/CasForexMt5Bridge.mq5 PublishOrderHistory()."""
    for fld in (
        "protocol",
        "broker_channel",
        "channel_key_id",
        "execution_mode",
        "account_login",
        "server",
        "account_trade_mode",
        "observed_at",
    ):
        if type(doc.get(fld)) is not str:
            raise Mt5SnapshotIntegrityError(f"order_history.json {fld} must be a string")
    if type(doc.get("connected")) is not bool:
        raise Mt5SnapshotIntegrityError("order_history.json connected must be a boolean")
    if type(doc.get("complete")) is not bool:
        raise Mt5SnapshotIntegrityError("order_history.json complete must be a boolean")
    open_tickets = doc.get("open_position_tickets")
    if type(open_tickets) is not list or any(type(t) is not str or not t.isdigit() for t in open_tickets):
        raise Mt5SnapshotIntegrityError("order_history.json open_position_tickets must be a list of digit strings")
    orders = doc.get("orders")
    if type(orders) is not list:
        raise Mt5SnapshotIntegrityError("order_history.json orders must be a list")
    orders_parts: list[str] = []
    for item in orders:
        if type(item) is not dict:
            raise Mt5SnapshotIntegrityError("order_history.json order entries must be objects")
        for fld in ("order_ticket", "request_id", "symbol", "time_utc"):
            if type(item.get(fld)) is not str:
                raise Mt5SnapshotIntegrityError(f"order_history.json order.{fld} must be a string")
        orders_parts.append(
            f"{item['order_ticket']}:{item['request_id']}:{item['symbol']}:{item['time_utc']}"
        )
    deals = doc.get("deals")
    if type(deals) is not list:
        raise Mt5SnapshotIntegrityError("order_history.json deals must be a list")
    deals_parts: list[str] = []
    for item in deals:
        if type(item) is not dict:
            raise Mt5SnapshotIntegrityError("order_history.json deal entries must be objects")
        for fld in ("deal_ticket", "order_ticket", "request_id", "symbol", "time_utc"):
            if type(item.get(fld)) is not str:
                raise Mt5SnapshotIntegrityError(f"order_history.json deal.{fld} must be a string")
        deals_parts.append(
            f"{item['deal_ticket']}:{item['order_ticket']}:{item['request_id']}:{item['symbol']}:{item['time_utc']}"
        )
    open_sha = sha256(";".join(open_tickets).encode("utf-8")).hexdigest()
    orders_sha = sha256(";".join(orders_parts).encode("utf-8")).hexdigest()
    deals_sha = sha256(";".join(deals_parts).encode("utf-8")).hexdigest()
    conn_str = "true" if doc["connected"] else "false"
    comp_str = "true" if doc["complete"] else "false"
    return "|".join([
        doc["protocol"],
        doc["broker_channel"],
        doc["channel_key_id"],
        doc["execution_mode"],
        doc["account_login"],
        doc["server"],
        doc["account_trade_mode"],
        conn_str,
        comp_str,
        doc["observed_at"],
        open_sha,
        orders_sha,
        deals_sha,
    ])


def compute_mt5_order_history_hmac(doc: Mapping[str, Any], channel_key: bytes) -> str:
    """Compute per-channel HMAC-SHA256 hex digest over a spool order_history.json snapshot."""
    return _spool_hmac_hex(channel_key, _canonical_spool_order_history_hmac_input(doc))


def sign_mt5_order_history_doc(
    doc: Mapping[str, Any],
    *,
    spool_dir: str | Path | None = None,
    key_dir: str | Path | None = None,
    broker_channel: str | None = None,
    channel_key: bytes | None = None,
    channel_key_id: str | None = None,
    observed_at: datetime | str | None = None,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> dict[str, Any]:
    """Return a copy of an order_history.json document signed with per-channel HMAC-SHA256."""
    out = dict(doc)
    out.setdefault("protocol", MT5_SPOOL_PROTOCOL)
    if "connected" not in out:
        out["connected"] = True
    if "complete" not in out:
        out["complete"] = True
    out.setdefault("open_position_tickets", [])
    out.setdefault("orders", [])
    out.setdefault("deals", [])
    if broker_channel is not None and str(broker_channel).strip():
        ch = str(broker_channel).strip().lower()
    elif isinstance(out.get("broker_channel"), str) and out["broker_channel"].strip():
        ch = out["broker_channel"].strip().lower()
    elif spool_dir is not None and Path(spool_dir).name.lower() in ("hugosway_mt5", "lhfx_mt5"):
        ch = Path(spool_dir).name.lower()
    elif "lhfx" in str(out.get("server", "")).lower():
        ch = "lhfx_mt5"
    else:
        ch = "hugosway_mt5"
    if ch not in ("hugosway_mt5", "lhfx_mt5"):
        raise Mt5TransportError(f"unsupported MT5 broker channel {ch!r}")
    out["broker_channel"] = ch
    if channel_key is None:
        if spool_dir is None and key_dir is None:
            raise Mt5TransportError("sign_mt5_order_history_doc requires spool_dir, key_dir, or channel_key")
        base_dir = Path(spool_dir) if spool_dir is not None else Path(key_dir or ".")
        master = _load_or_create_spool_hmac_key(base_dir, key_dir=key_dir, custody_inspector=custody_inspector)
        eff_key = derive_spool_channel_key(master, ch)
    else:
        eff_key = bytes(channel_key)
    out["channel_key_id"] = channel_key_id if channel_key_id is not None else spool_channel_key_id(eff_key, ch)
    if "execution_mode" not in out or not isinstance(out.get("execution_mode"), str):
        out["execution_mode"] = EXECUTION_MODE_LIVE if out.get("account_trade_mode") == "REAL" else EXECUTION_MODE_DEMO
    if observed_at is not None:
        out["observed_at"] = observed_at if isinstance(observed_at, str) else _iso(observed_at)
    elif not isinstance(out.get("observed_at"), str) or not out["observed_at"].strip():
        out["observed_at"] = _iso(_utc_now())
    out["history_hmac_sha256"] = compute_mt5_order_history_hmac(out, channel_key=eff_key)
    return out


def derive_spool_channel_key(master_key: bytes, broker_channel: str) -> bytes:
    """Derive an isolated 32-byte per-channel HMAC key: HMAC-SHA256(master_key, f'channel:{broker_channel}')."""
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 32:
        raise Mt5TransportError("master spool HMAC key must be >= 32 bytes")
    ch = str(broker_channel or "").strip().lower()
    if ch not in ("hugosway_mt5", "lhfx_mt5"):
        raise Mt5TransportError(f"unsupported MT5 broker channel {broker_channel!r}")
    return hmac.new(bytes(master_key), f"channel:{ch}".encode("utf-8"), sha256).digest()


def spool_channel_key_id(channel_key: bytes, broker_channel: str) -> str:
    """Deterministic 16-hex key identifier bound to the derived per-channel key."""
    ch = str(broker_channel or "").strip().lower()
    if ch not in ("hugosway_mt5", "lhfx_mt5"):
        raise Mt5TransportError(f"unsupported MT5 broker channel {broker_channel!r}")
    return sha256(f"key-id:{ch}:".encode("utf-8") + bytes(channel_key)).hexdigest()[:16]


def _spool_meta_root(spool_dir: Path) -> Path:
    if spool_dir.name.lower() in ("hugosway_mt5", "lhfx_mt5"):
        return spool_dir.parent
    return spool_dir


def resolve_spool_key_dir(
    spool_dir: Path,
    *,
    key_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve isolated key storage directory (CAS_FOREX_MT5_SPOOL_KEY_DIR) or default meta root (Finding [7])."""
    if key_dir is not None and str(key_dir).strip():
        return Path(str(key_dir).strip())
    env_map = environ if environ is not None else os.environ
    env_val = str(env_map.get(ENV_MT5_SPOOL_KEY_DIR, "")).strip()
    if env_val:
        return Path(env_val)
    return _spool_meta_root(spool_dir)


def _spool_hmac_key_path(
    spool_dir: Path,
    *,
    key_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    return resolve_spool_key_dir(spool_dir, key_dir=key_dir, environ=environ) / ".spool_hmac.key"


def _valve_admission_key_path(
    spool_dir: Path,
    *,
    key_dir: str | Path | None = None,
    valve_key_file: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    if valve_key_file is not None and str(valve_key_file).strip():
        return Path(str(valve_key_file).strip())
    env_map = environ if environ is not None else os.environ
    env_val = str(env_map.get(ENV_VALVE_ADMISSION_KEY_FILE, "")).strip()
    if env_val:
        return Path(env_val)
    return resolve_spool_key_dir(spool_dir, key_dir=key_dir, environ=environ) / ".valve_admission.key"


def _load_or_create_secret_key_file(
    key_path: Path,
    *,
    label: str,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> bytes:
    parent = key_path.parent
    if not os.path.lexists(parent):
        verify_spool_path_custody(parent, inspector=custody_inspector, check_ancestors=True)
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        apply_verified_directory_mode(parent, 0o700, custody_inspector=custody_inspector, newly_created=True)
    else:
        verify_spool_path_custody(parent, expect_dir=True, inspector=custody_inspector, check_ancestors=True)
    if os.path.lexists(key_path):
        verify_spool_path_custody(key_path, expect_file=True, inspector=custody_inspector, check_ancestors=False)
        raw = key_path.read_bytes().strip()
        if len(raw) == 64:
            return bytes.fromhex(raw.decode("ascii"))
        if len(raw) >= 32:
            return raw
        raise Mt5TransportError(f"{label} shorter than 32 bytes")
    key_bytes = secrets.token_bytes(32)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(key_path, flags, 0o600)
    try:
        os.write(fd, (key_bytes.hex() + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(key_path, 0o600)  # nosec B103: owner-only 0o600 key file on verified regular fd
    elif os.name == "nt" and custody_inspector is None:
        _win32_apply_owner_only_dacl(key_path)
    verify_spool_path_custody(key_path, expect_file=True, inspector=custody_inspector, check_ancestors=False)
    return key_bytes


def _load_or_create_spool_hmac_key(
    spool_dir: Path,
    *,
    key_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> bytes:
    key_path = _spool_hmac_key_path(spool_dir, key_dir=key_dir, environ=environ)
    return _load_or_create_secret_key_file(
        key_path, label="Spool HMAC key", custody_inspector=custody_inspector
    )


def _load_or_create_valve_admission_key(
    spool_dir: Path,
    *,
    key_dir: str | Path | None = None,
    valve_key_file: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> bytes:
    vpath = _valve_admission_key_path(
        spool_dir, key_dir=key_dir, valve_key_file=valve_key_file, environ=environ
    )
    vkey = _load_or_create_secret_key_file(
        vpath, label="Valve admission key", custody_inspector=custody_inspector
    )
    spool_key_path = _spool_hmac_key_path(spool_dir, key_dir=key_dir, environ=environ)
    if os.path.lexists(spool_key_path):
        spool_master = _load_or_create_spool_hmac_key(
            spool_dir, key_dir=key_dir, environ=environ, custody_inspector=custody_inspector
        )
        if hmac.compare_digest(vkey, spool_master):
            raise Mt5TransportError(
                "MT5_SPOOL_CUSTODY_VIOLATION: valve admission key must be strictly distinct from spool HMAC key"
            )
    return vkey


def sign_spool_valve_admission(
    request: "Mt5OrderRequest",
    *,
    spool_dir: str | Path | None = None,
    key_dir: str | Path | None = None,
    valve_key_file: str | Path | None = None,
    valve_key_bytes: bytes | None = None,
    expires_at: datetime | None = None,
    environ: Mapping[str, str] | None = None,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> "Mt5OrderRequest":
    """Sign a short-lived Valve admission capability bound to exact order/risk/routing fields (Finding [7])."""
    import dataclasses as _dc

    if not _HEX64_RE.fullmatch(str(request.valve_decision_sha256 or "").lower()):
        raise Mt5ValveClearanceError("valve_decision_sha256 must be a 64-char hex digest before signing Valve admission")
    eff_issued = request.issued_at if request.issued_at is not None else request.created_at
    eff_exp = expires_at if expires_at is not None else (
        request.valve_admission_expires_at if request.valve_admission_expires_at is not None else (
            request.expires_at if request.expires_at is not None else (eff_issued + timedelta(seconds=30))
        )
    )
    eff_exp = utc_time(eff_exp, "valve_admission_expires_at")
    ttl = (eff_exp - eff_issued).total_seconds()
    if ttl <= 0 or ttl > MAX_VALVE_ADMISSION_TTL_SECONDS:
        raise Mt5ValveClearanceError(
            f"valve_admission_expires_at TTL must be in (0, {MAX_VALVE_ADMISSION_TTL_SECONDS}] seconds"
        )
    if valve_key_bytes is not None:
        vkey = bytes(valve_key_bytes)
        if len(vkey) < 32:
            raise Mt5TransportError("Valve admission key must be >= 32 bytes")
    else:
        if spool_dir is None and key_dir is None and valve_key_file is None:
            raise Mt5TransportError("sign_spool_valve_admission requires spool_dir, key_dir, valve_key_file, or valve_key_bytes")
        base_dir = Path(spool_dir) if spool_dir is not None else Path(key_dir or ".")
        vkey = _load_or_create_valve_admission_key(
            base_dir,
            key_dir=key_dir,
            valve_key_file=valve_key_file,
            environ=environ,
            custody_inspector=custody_inspector,
        )
    staged = _dc.replace(request, valve_admission_expires_at=eff_exp, valve_admission_sig="")
    sig = _spool_hmac_hex(vkey, _canonical_valve_admission_input(staged._core_dict()))
    return _dc.replace(staged, valve_admission_sig=sig)


def verify_spool_valve_admission(
    doc: Mapping[str, str],
    *,
    valve_key_bytes: bytes,
    now: datetime,
    spool_master_key: bytes | None = None,
) -> tuple[bool, str]:
    """Verify short-lived signed Valve admission against exact request fields and clock (Finding [7])."""
    if len(valve_key_bytes) < 32:
        return False, "valve admission key unavailable"
    if spool_master_key is not None and hmac.compare_digest(valve_key_bytes, spool_master_key):
        return False, "valve admission key equals spool key"
    dec_sha = str(doc.get("valve_decision_sha256", "")).lower()
    if not _HEX64_RE.fullmatch(dec_sha):
        return False, "missing or invalid valve_decision_sha256"
    actual_sig = str(doc.get("valve_admission_sig", "")).lower()
    if not _HEX64_RE.fullmatch(actual_sig):
        return False, "missing or invalid valve_admission_sig"
    raw_exp = str(doc.get("valve_admission_expires_at", ""))
    raw_iss = str(doc.get("issued_at", ""))
    try:
        exp_dt = _parse_iso(raw_exp, "valve_admission_expires_at")
        iss_dt = _parse_iso(raw_iss, "issued_at")
    except Mt5TransportError:
        return False, "invalid valve_admission_expires_at"
    check_now = utc_time(now, "now")
    if check_now > exp_dt:
        return False, "valve admission expired"
    ttl = (exp_dt - iss_dt).total_seconds()
    if ttl <= 0 or ttl > MAX_VALVE_ADMISSION_TTL_SECONDS:
        return False, "valve admission ttl exceeds bound"
    expected_sig = _spool_hmac_hex(valve_key_bytes, _canonical_valve_admission_input(doc))
    if not hmac.compare_digest(expected_sig, actual_sig):
        return False, "valve admission signature mismatch"
    return True, "ok"


class _SpoolReplayLedger:
    """Durable JSON replay & monotonic nonce ledger stored outside the terminal inbox directory."""

    def __init__(self, path: Path, *, custody_inspector: SpoolCustodyInspector | None = None) -> None:
        self.path = path
        self._custody_inspector = custody_inspector
        self._lock = threading.RLock()

    def load(self) -> tuple[int, list[str]]:
        with self._lock:
            if not os.path.lexists(self.path):
                return 0, []
            data = _read_spool_json(self.path, max_bytes=262_144, custody_inspector=self._custody_inspector)
            if type(data) is not dict:
                raise Mt5TransportError("corrupted MT5 spool replay ledger")
            nonce_raw = data.get("last_monotonic_nonce", "0")
            if type(nonce_raw) is not str or not nonce_raw.isdigit():
                raise Mt5TransportError("corrupted MT5 spool replay ledger nonce")
            last_nonce = int(nonce_raw)
            if last_nonce < 0:
                raise Mt5TransportError("corrupted MT5 spool replay ledger negative nonce")
            seen_raw = data.get("seen_request_ids", [])
            if type(seen_raw) is not list or any(type(x) is not str for x in seen_raw):
                raise Mt5TransportError("corrupted MT5 spool replay ledger seen_request_ids")
            return last_nonce, list(seen_raw[-2048:])

    def _persist_and_verify(
        self,
        *,
        nonce: int,
        seen: list[str],
        expected_request_id: str | None = None,
    ) -> None:
        _atomic_write_json(
            self.path,
            {"last_monotonic_nonce": str(nonce), "seen_request_ids": seen},
            custody_inspector=self._custody_inspector,
        )
        persisted_nonce, persisted_seen = self.load()
        if persisted_nonce != nonce:
            raise Mt5TransportError("MT5 replay ledger persistence verification failed (nonce mismatch)")
        if expected_request_id is not None and expected_request_id not in persisted_seen:
            raise Mt5TransportError("MT5 replay ledger persistence verification failed (request_id missing)")

    def next_nonce(self) -> int:
        with self._lock:
            last_nonce, seen = self.load()
            nxt = last_nonce + 1
            self._persist_and_verify(nonce=nxt, seen=seen[-512:])
            return nxt

    def verify_and_record(self, *, request_id: str, nonce: int) -> None:
        with self._lock:
            last_nonce, seen = self.load()
            seen_tail = seen[-512:]
            if nonce <= last_nonce or request_id in seen_tail:
                raise Mt5SpoolReplayError(
                    f"MT5 spool replay detected (request_id={request_id}, nonce={nonce} <= {last_nonce})"
                )
            seen_tail.append(request_id)
            self._persist_and_verify(
                nonce=nonce,
                seen=seen_tail[-512:],
                expected_request_id=request_id,
            )

    def verify_and_record_global_id(self, *, request_id: str) -> None:
        """Global cross-channel replay domain check on request_id (Finding [9])."""
        with self._lock:
            last_nonce, seen = self.load()
            if request_id in seen:
                raise Mt5SpoolReplayError(f"MT5 global replay domain duplicate request_id={request_id}")
            seen.append(request_id)
            self._persist_and_verify(
                nonce=last_nonce,
                seen=seen[-2048:],
                expected_request_id=request_id,
            )


def apply_verified_directory_mode(
    path: str | Path,
    dir_mode: int = 0o700,
    *,
    custody_inspector: SpoolCustodyInspector | None = None,
    newly_created: bool = False,
) -> Path:
    """Verify and harden an existing real directory across Windows SID/DACL/reparse and POSIX mode (Finding [7])."""
    target = Path(path)
    st = os.lstat(target)
    if _is_reparse_or_symlink(target, st) or not stat.S_ISDIR(st.st_mode):
        raise Mt5TransportError("spool path must be a real directory, not a file, junction, or symlink")
    if not newly_created:
        verify_spool_path_custody(target, expect_dir=True, inspector=custody_inspector, check_ancestors=True)
    if os.name == "posix":
        os.chmod(target, dir_mode)  # nosec B103: owner-only 0o700 spool directory verified via lstat + S_ISDIR above
    elif os.name == "nt" and custody_inspector is None:
        _win32_apply_owner_only_dacl(target)
    verify_spool_path_custody(target, expect_dir=True, inspector=custody_inspector, check_ancestors=True)
    return target


def _atomic_write_bytes(
    path: Path,
    data: bytes,
    *,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> None:
    verify_spool_path_custody(path.parent, expect_dir=True, inspector=custody_inspector, check_ancestors=True)
    if os.path.lexists(path):
        verify_spool_path_custody(path, expect_file=True, inspector=custody_inspector, check_ancestors=False)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(tmp, 0o600)  # nosec B103: owner-only 0o600 spool artifact
        elif os.name == "nt" and custody_inspector is None:
            _win32_apply_owner_only_dacl(tmp)
        if os.name == "nt":
            for attempt in range(5):
                try:
                    os.replace(tmp, path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.01)
        else:
            os.replace(tmp, path)
        if os.name == "posix":
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            except OSError:
                pass
            finally:
                os.close(dir_fd)
    except OSError as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError as cleanup_exc:
            logger.warning("MT5 spool temp cleanup failed for %s: %s", tmp.name, type(cleanup_exc).__name__)
        raise Mt5TransportError(f"atomic spool write failed for {path.name}: {type(exc).__name__}") from None


def _atomic_write_json(
    path: Path,
    doc: Mapping[str, Any],
    *,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> None:
    assert_safe_json_numbers(dict(doc))
    raw = (json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _atomic_write_bytes(path, raw, custody_inspector=custody_inspector)


def _read_spool_json(
    path: Path,
    *,
    max_bytes: int = MAX_SPOOL_FILE_BYTES,
    custody_inspector: SpoolCustodyInspector | None = None,
) -> Any:
    last_err: Exception | None = None
    for attempt in range(8):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            raise
        except PermissionError as exc:
            last_err = exc
            time.sleep(0.015)
            continue
        except OSError as exc:
            raise Mt5TransportError(f"spool file {path.name} unreadable: {type(exc).__name__}") from None
        if _is_reparse_or_symlink(path, st) or not stat.S_ISREG(st.st_mode):
            raise Mt5TransportError(f"spool file {path.name} must be a regular non-symlink file")
        verify_spool_path_custody(path, expect_file=True, inspector=custody_inspector, check_ancestors=False)
        if st.st_size > max_bytes:
            raise Mt5TransportError(f"spool file {path.name} exceeds {max_bytes} bytes")
        try:
            raw = path.read_bytes()
        except PermissionError as exc:
            last_err = exc
            time.sleep(0.015)
            continue
        except OSError as exc:
            raise Mt5TransportError(f"spool file {path.name} unreadable: {type(exc).__name__}") from None
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        try:
            return strict_safe_json_loads(raw, max_bytes=max_bytes)
        except ContractError as exc:
            last_err = exc
            if attempt < 7:
                time.sleep(0.015)
                continue
            raise Mt5TransportError(f"spool file {path.name} is not strict safe JSON: {exc}") from None
    raise Mt5TransportError(
        f"spool file {path.name} unreadable after retry: {type(last_err).__name__ if last_err else 'OSError'}"
    )


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
        default_server="Hugosway-Demo",
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
        default_server="LHFXSA-Trade",
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
    # LHFX hosts both Demo (ACCOUNT_TRADE_MODE_DEMO) and Real (ACCOUNT_TRADE_MODE_REAL) on unified LHFXSA-Trade;
    # runtime transports and ModeGuard strictly verify account trade mode on every snapshot and receipt.
    is_lhfx_unified_demo = broker_id == BROKER_LHFX_MT5 and compact in {"lhfxsa-trade", "lhfxsa trade"}
    if "demo" not in low and not is_lhfx_unified_demo:
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
    live_auth_ticket_json: str | None = None
    live_auth_context: LiveAuthorizationContext | None = None

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
        if self.execution_mode == EXECUTION_MODE_LIVE:
            if self.live_auth_context is None:
                raise LiveAuthorizationError(
                    f"LIVE Mt5Credentials for {self.broker_id} require a verified LiveAuthorizationContext"
                )
            if not isinstance(self.live_auth_context, LiveAuthorizationContext):
                raise LiveAuthorizationError("live_auth_context must be a verified LiveAuthorizationContext")
            self.live_auth_context.verify_provenance(reverify_ticket=True)
            if self.live_auth_context.broker_id.strip().upper() != self.broker_id.strip().upper():
                raise LiveAuthorizationError(
                    f"live_auth_context broker_id mismatch for {self.broker_id}"
                )
            if self.live_auth_context.account_id.strip() != str(self.login):
                raise LiveAuthorizationError(
                    f"live_auth_context account_id mismatch for {self.broker_id}"
                )
            if self.live_auth_context.server.strip().casefold() != self.server.strip().casefold():
                raise LiveAuthorizationError(
                    f"live_auth_context server mismatch for {self.broker_id}"
                )
            if self.live_auth_context.execution_mode != EXECUTION_MODE_LIVE:
                raise LiveAuthorizationError("live_auth_context execution_mode must be LIVE")
            if self.live_auth_ticket_json is not None:
                try:
                    parsed_tkt = json.loads(self.live_auth_ticket_json)
                except Exception as exc:
                    raise LiveAuthorizationError("invalid live_auth_ticket_json on Mt5Credentials") from exc
                canonical_tkt = json.dumps(
                    dict(parsed_tkt), ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                if not hmac.compare_digest(
                    sha256(canonical_tkt).hexdigest(), self.live_auth_context.ticket_sha256.lower()
                ):
                    raise LiveAuthorizationError("live_auth_ticket_json digest does not match live_auth_context")
        elif self.live_auth_context is not None:
            raise ContractError("live_auth_context is only valid when execution_mode=LIVE")

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
    now: datetime | None = None,
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
        environ, execution_mode=execution_mode, live_arm_phrase=live_arm_phrase, now=now
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
    live_ticket_json: str | None = None
    live_auth_ctx: LiveAuthorizationContext | None = None
    if mode == EXECUTION_MODE_LIVE:
        try:
            ticket_obj, live_auth_ctx = verify_live_environ_authorization_context(
                environ,
                expected_broker_id=broker_id,
                expected_account_login=login_raw,
                expected_server=str(server),
                live_arm_phrase=live_arm_phrase,
                require_arm_phrase=True,
                now=now,
            )
            live_ticket_json = json.dumps(ticket_obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        except LiveAuthTicketError as exc:
            raise LiveBrokerEndpointForbiddenError(f"{broker_id} LIVE ticket invalid: {exc}") from None
    return Mt5Credentials(
        broker_id=broker_id,
        login=int(login_raw),
        server=str(server),
        password=_RedactedSecret(password_raw) if password_raw else None,
        execution_mode=mode,
        live_auth_ticket_json=live_ticket_json,
        live_auth_context=live_auth_ctx,
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
        index_leverage: int = DEFAULT_MT5_INDEX_LEVERAGE,
        index_contract_size: Decimal = MT5_INDEX_CONTRACT_SIZE,
        gold_contract_size: Decimal = MT5_GOLD_CONTRACT_SIZE,
        symbol_contract_sizes: Mapping[str, Decimal] | None = None,
    ) -> None:
        if type(leverage) is not int or not (1 <= leverage <= MAX_DEMO_LEVERAGE):
            raise ContractError(f"leverage must be an integer in 1..{MAX_DEMO_LEVERAGE}")
        if type(index_leverage) is not int or not (1 <= index_leverage <= MAX_DEMO_LEVERAGE):
            raise ContractError(f"index_leverage must be an integer in 1..{MAX_DEMO_LEVERAGE}")
        if not isinstance(account_currency, str) or not re.fullmatch(r"[A-Z]{3}", account_currency):
            raise ContractError("account_currency must be an ISO-4217 code")
        self.leverage = leverage
        self.index_leverage = min(index_leverage, leverage)
        self.account_currency = account_currency
        self.contract_size = decimal_value(contract_size, "contract_size", positive=True)
        self.index_contract_size = decimal_value(index_contract_size, "index_contract_size", positive=True)
        self.gold_contract_size = decimal_value(gold_contract_size, "gold_contract_size", positive=True)
        parsed_overrides: dict[str, Decimal] = {}
        if symbol_contract_sizes is not None:
            if not isinstance(symbol_contract_sizes, Mapping):
                raise ContractError("symbol_contract_sizes must be a mapping when provided")
            for raw_sym, raw_val in symbol_contract_sizes.items():
                sym_name = normalize_market_symbol(str(raw_sym)) or str(raw_sym).strip().upper()
                if not sym_name:
                    raise ContractError("symbol_contract_sizes symbol name cannot be empty")
                parsed_overrides[sym_name] = decimal_value(
                    raw_val, f"symbol_contract_sizes[{sym_name}]", positive=True
                )
        self.symbol_contract_sizes: dict[str, Decimal] = parsed_overrides

    @staticmethod
    def split_symbol(symbol: str) -> tuple[str, str]:
        if not isinstance(symbol, str):
            raise ContractError("MT5 symbol must be a string")
        if symbol in INDEX_INSTRUMENTS:
            return symbol, "USD"
        if symbol in EXPANDED_FX_PAIRS:
            return symbol[:3], symbol[3:]
        raise ContractError(f"unsupported MT5 symbol {symbol!r}; expected one of the {len(EXPANDED_MARKETS)} EXPANDED_MARKETS")

    def contract_size_for(self, symbol: str | None) -> Decimal:
        norm_sym = normalize_market_symbol(symbol) if isinstance(symbol, str) else None
        lookup_sym = norm_sym or (symbol.strip().upper() if isinstance(symbol, str) else "")
        if lookup_sym and lookup_sym in self.symbol_contract_sizes:
            return self.symbol_contract_sizes[lookup_sym]
        if lookup_sym == "XAUUSD" or symbol == "XAUUSD":
            return self.gold_contract_size
        if lookup_sym == "SPX500" or symbol == "SPX500":
            if self.index_contract_size > Decimal("1") and self.index_contract_size < MT5_SPX500_CONTRACT_SIZE_MULTI:
                return MT5_SPX500_CONTRACT_SIZE_MULTI
            return self.index_contract_size
        return self.index_contract_size if lookup_sym in INDEX_INSTRUMENTS else self.contract_size

    def leverage_for(self, symbol: str | None) -> int:
        return self.index_leverage if symbol in INDEX_INSTRUMENTS else self.leverage

    def units_to_lots(self, units: Decimal, *, symbol: str | None = None) -> Decimal:
        decimal_value(units, "units", positive=True)
        csize = self.contract_size_for(symbol)
        with localcontext() as ctx:
            ctx.prec = 40
            lots = units / csize
        if lots < MT5_MIN_VOLUME or lots % MT5_VOLUME_STEP != 0:
            raise ContractError(
                f"units {decimal_text(units)} must map to a positive multiple of {MT5_VOLUME_STEP} lots "
                f"(1 lot = {decimal_text(csize)} base units)"
            )
        return lots.quantize(MT5_VOLUME_STEP)

    def lots_to_units(self, lots: Decimal, *, symbol: str | None = None) -> Decimal:
        decimal_value(lots, "lots", positive=True)
        csize = self.contract_size_for(symbol)
        with localcontext() as ctx:
            ctx.prec = 40
            return (lots * csize).normalize()

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
        lev = self.leverage_for(symbol)
        with localcontext() as ctx:
            ctx.prec = 40
            return (notional / Decimal(lev)).quantize(Decimal("0.01"), rounding=ROUND_CEILING)

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
        lots = self.units_to_lots(units, symbol=symbol)
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
    take_profit_price: Decimal | None = None

    def __post_init__(self) -> None:
        identifier(self.order_id, "order_id")
        identifier(self.action_ref, "action_ref")
        if not isinstance(self.kind, ActionKind) or self.kind not in _SUPPORTED_ORDER_KINDS:
            raise ContractError("MT5 bridge v1 supports OPEN, AMEND_STOP, REDUCE and CLOSE only")
        Mt5MarginCalculator.split_symbol(self.symbol)
        if self.side is not None and not isinstance(self.side, Side):
            raise ContractError("side must be Side")
        for name in ("quantity_units", "stop_price", "limit_price", "take_profit_price"):
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
            if self.take_profit_price is not None:
                if self.side is Side.BUY and (self.stop_price >= self.take_profit_price or (
                        self.limit_price is not None and self.limit_price >= self.take_profit_price)):
                    raise ContractError("BUY resting take_profit_price must exceed entry/limit and stop_price")
                if self.side is Side.SELL and (self.stop_price <= self.take_profit_price or (
                        self.limit_price is not None and self.limit_price <= self.take_profit_price)):
                    raise ContractError("SELL resting take_profit_price must sit below entry/limit and stop_price")
        else:
            if self.position_ticket is None:
                raise ContractError(f"{self.kind.value} requires an exact position_ticket")
        if self.kind is ActionKind.AMEND_STOP:
            if (self.stop_price is None and self.take_profit_price is None) or self.quantity_units is not None:
                raise ContractError("AMEND_STOP requires a replacement stop_price or take_profit_price and no quantity")
        if self.kind in (ActionKind.REDUCE, ActionKind.CLOSE) and self.take_profit_price is not None:
            raise ContractError(f"{self.kind.value} must not carry take_profit_price")
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
            symbol=normalize_market_symbol(symbol or str(intent.instrument_id)),
            quantity_units=quantity,
            side=side if kind is ActionKind.OPEN else None,
            stop_price=getattr(intent, "stop_price", None),
            limit_price=getattr(intent, "limit_price", None) if kind is ActionKind.OPEN else None,
            position_ticket=position_ticket if position_ticket is not None else (
                None if kind is ActionKind.OPEN else getattr(intent, "target_id", None)
            ),
            take_profit_price=getattr(intent, "take_profit_price", None) if kind in (ActionKind.OPEN, ActionKind.AMEND_STOP) else None,
        )

    def fingerprint(self) -> str:
        return sha256(canonical_bytes(self)).hexdigest()


RISK_INCREASING_ACTION_KINDS: frozenset[ActionKind] = frozenset({ActionKind.OPEN, ActionKind.ADD})
MANAGEMENT_ACTION_KINDS: frozenset[ActionKind] = frozenset({
    ActionKind.AMEND_STOP,
    ActionKind.REDUCE,
    ActionKind.CLOSE,
})


@dataclass(frozen=True, slots=True)
class RiskIncreasingOrderIntent:
    """Typed wrapper proving an order intent is strictly risk-increasing (OPEN)."""

    order: OrderIntent

    def __post_init__(self) -> None:
        if not isinstance(self.order, OrderIntent) or self.order.kind not in RISK_INCREASING_ACTION_KINDS:
            raise ContractError("RiskIncreasingOrderIntent requires an OPEN/ADD OrderIntent")


@dataclass(frozen=True, slots=True)
class RiskReducingOrderIntent:
    """Typed wrapper proving an order intent is strictly risk-reducing management (AMEND_STOP/REDUCE/CLOSE)."""

    order: OrderIntent

    def __post_init__(self) -> None:
        if not isinstance(self.order, OrderIntent) or self.order.kind not in MANAGEMENT_ACTION_KINDS:
            raise ContractError("RiskReducingOrderIntent requires an AMEND_STOP, REDUCE, or CLOSE OrderIntent")


def _unwrap_order_intent(order: OrderIntent | RiskIncreasingOrderIntent | RiskReducingOrderIntent) -> OrderIntent:
    if isinstance(order, (RiskIncreasingOrderIntent, RiskReducingOrderIntent)):
        return order.order
    if not isinstance(order, OrderIntent):
        raise ContractError("execute requires an OrderIntent")
    return order


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
    take_profit: Decimal | None = None

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "ticket": self.ticket,
            "symbol": self.symbol,
            "side": self.side.value,
            "volume_lots": decimal_text(self.volume_lots),
            "price_open": decimal_text(self.price_open),
            "stop_loss": None if self.stop_loss is None else decimal_text(self.stop_loss),
            "take_profit": None if self.take_profit is None else decimal_text(self.take_profit),
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
    connected: bool = True

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
            "connected": bool(self.connected),
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
    take_profit: Decimal | None = None
    monotonic_nonce: int = 1
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    broker_channel: str = "hugosway_mt5"
    channel_key_id: str = ""
    account_login: str = "0"
    server: str = ""
    execution_mode: str = EXECUTION_MODE_DEMO
    valve_decision_sha256: str = ""
    valve_admission_expires_at: datetime | None = None
    valve_admission_sig: str = "" 

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not _SPOOL_ID_RE.fullmatch(self.request_id):
            raise ContractError("request_id must be a filename-safe identifier")
        if self.action not in ("OPEN", "AMEND_STOP", "REDUCE", "CLOSE"):
            raise ContractError("unsupported MT5 request action")
        Mt5MarginCalculator.split_symbol(self.symbol)
        if not isinstance(self.side, Side):
            raise ContractError("side must be Side")
        if self.action == "AMEND_STOP":
            if (self.stop_loss is None and self.take_profit is None) or self.position_ticket is None:
                raise ContractError("AMEND_STOP request requires stop_loss or take_profit and position_ticket")
        else:
            if self.volume_lots is None:
                raise ContractError("deal requests require volume_lots")
            decimal_value(self.volume_lots, "volume_lots", positive=True)
        if self.take_profit is not None:
            decimal_value(self.take_profit, "take_profit", positive=True)
        if self.action in ("REDUCE", "CLOSE") and self.position_ticket is None:
            raise ContractError("REDUCE/CLOSE requests require position_ticket")
        if type(self.deviation_points) is not int or not (0 <= self.deviation_points <= 1000):
            raise ContractError("deviation_points must be an integer in 0..1000")
        if type(self.magic) is not int or not (0 < self.magic <= 2_147_483_647):
            raise ContractError("magic must be a positive 32-bit integer")
        _ascii_text(self.comment, "comment", max_len=31)
        utc_time(self.created_at, "created_at")

    def _core_dict(self) -> dict[str, str]:
        eff_issued = self.issued_at if self.issued_at is not None else self.created_at
        eff_expires = self.expires_at if self.expires_at is not None else (eff_issued + timedelta(seconds=30))
        return {
            "protocol": MT5_SPOOL_PROTOCOL,
            "request_id": self.request_id,
            "monotonic_nonce": str(self.monotonic_nonce),
            "issued_at": _iso(eff_issued),
            "expires_at": _iso(eff_expires),
            "broker_channel": self.broker_channel,
            "channel_key_id": self.channel_key_id,
            "account_login": self.account_login,
            "server": self.server,
            "execution_mode": self.execution_mode,
            "valve_decision_sha256": self.valve_decision_sha256,
            "valve_admission_expires_at": "" if self.valve_admission_expires_at is None else _iso(self.valve_admission_expires_at),
            "valve_admission_sig": self.valve_admission_sig,
            "action": self.action,
            "symbol": self.symbol,
            "side": self.side.value,
            "volume": "0" if self.volume_lots is None else decimal_text(self.volume_lots),
            "price": "0" if self.price is None else decimal_text(self.price),
            "sl": "0" if self.stop_loss is None else decimal_text(self.stop_loss),
            "tp": "0" if self.take_profit is None else decimal_text(self.take_profit),
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
                "sl": 0.0 if self.stop_loss is None else float(self.stop_loss),
                "tp": 0.0 if self.take_profit is None else float(self.take_profit),
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
        if self.take_profit is not None and self.action == "OPEN":
            payload["tp"] = float(self.take_profit)
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
    take_profit: Decimal | None = None

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
            "take_profit": None if self.take_profit is None else decimal_text(self.take_profit),
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

    def send_order(
        self,
        request: Mt5OrderRequest,
        *,
        valve_grant: ValveOrderGrant | None = None,
        require_risk_reducing: bool = False,
        now: datetime | None = None,
    ) -> Mt5OrderReceipt: ...

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
        if credentials.execution_mode == EXECUTION_MODE_LIVE:
            if credentials.live_auth_context is None:
                raise LiveAuthorizationError(
                    f"LIVE connect on {credentials.broker_id} refused: missing verified LiveAuthorizationContext"
                )
            credentials.live_auth_context.assert_valid_at(
                self._clock(),
                expected_broker_id=credentials.broker_id,
                expected_account_id=str(credentials.login),
                expected_server=credentials.server,
                require_arm_phrase=True,
                reverify_ticket=True,
            )
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
        snap_login = int(_sdk_field(info, "login"))
        if self._credentials is not None:
            if snap_login != self._credentials.login or server.casefold() != self._credentials.server.casefold():
                self.shutdown()
                if self._credentials.execution_mode == EXECUTION_MODE_LIVE:
                    raise LiveAuthorizationError(
                        "MT5 terminal account/server drifted from bound LIVE credentials; reconnect required"
                    )
                raise Mt5PreDispatchTransportError(
                    "MT5 terminal account/server drifted from bound credentials; reconnect required"
                )
        leverage = int(_sdk_field(info, "leverage"))
        if leverage <= 0 or leverage > self._max_leverage:
            raise Mt5MarginRefusalError(f"MT5 account leverage 1:{leverage} exceeds the 1:{self._max_leverage} cap")
        term_fn = getattr(sdk, "terminal_info", None)
        term_connected = True
        if callable(term_fn):
            tinfo = term_fn()
            if tinfo is None:
                term_connected = False
            else:
                term_connected = bool(getattr(tinfo, "connected", False))
        return Mt5AccountSnapshot(
            server=server,
            login=snap_login,
            currency=str(_sdk_field(info, "currency")),
            balance=_sdk_decimal(_sdk_field(info, "balance"), "balance"),
            equity=_sdk_decimal(_sdk_field(info, "equity"), "equity"),
            margin=_sdk_decimal(_sdk_field(info, "margin"), "margin"),
            margin_free=_sdk_decimal(_sdk_field(info, "margin_free"), "margin_free"),
            leverage=leverage,
            trade_mode=trade_mode_label,
            connected=term_connected,
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
            raw_tp = getattr(row, "tp", None) if not isinstance(row, Mapping) else row.get("tp")
            tp = Decimal("0") if raw_tp is None else _sdk_decimal(raw_tp, "tp")
            out.append(Mt5Position(
                ticket=_ticket_text(int(_sdk_field(row, "ticket"))),
                symbol=normalize_market_symbol(str(_sdk_field(row, "symbol"))),
                side=Side.BUY if ptype == const["POSITION_TYPE_BUY"] else Side.SELL,
                volume_lots=_sdk_decimal(_sdk_field(row, "volume"), "volume"),
                price_open=_sdk_decimal(_sdk_field(row, "price_open"), "price_open"),
                stop_loss=None if sl == 0 else sl,
                profit=_sdk_decimal(_sdk_field(row, "profit"), "profit"),
                take_profit=None if tp == 0 else tp,
            ))
        return tuple(out)

    def _assert_live_dispatch_authorized(self, *, now: datetime | None = None) -> None:
        creds = self._credentials
        if creds is None or creds.execution_mode != EXECUTION_MODE_LIVE:
            return
        if creds.live_auth_context is None:
            raise LiveAuthorizationError(
                f"LIVE dispatch on {creds.broker_id} refused: missing verified LiveAuthorizationContext"
            )
        if creds.live_auth_context.key_file_identity is None:
            raise LiveAuthorizationError(
                f"LIVE dispatch on {creds.broker_id} refused: LiveAuthorizationContext lacks verified key_file_identity"
            )
        check_now = self._clock() if now is None else utc_time(now, "now")
        creds.live_auth_context.verify_provenance(
            now=check_now,
            reverify_ticket=True,
            require_arm_phrase=True,
        )
        creds.live_auth_context.assert_valid_at(
            check_now,
            expected_broker_id=creds.broker_id,
            expected_account_id=str(creds.login),
            expected_server=creds.server,
            require_arm_phrase=True,
            reverify_ticket=True,
        )

    def _verify_terminal_binding_before_send(self, sdk: Any, creds: Mt5Credentials) -> Mt5AccountSnapshot:
        """Re-verify live MT5 terminal connection, login, server, and trade_mode immediately before order_send."""
        term_fn = getattr(sdk, "terminal_info", None)
        if callable(term_fn):
            tinfo = term_fn()
            if tinfo is None or getattr(tinfo, "connected", False) is not True:
                self.shutdown()
                raise Mt5PreDispatchTransportError(
                    f"MT5 terminal disconnected before order_send on {creds.broker_id}; shutdown & reconnect required"
                )
        try:
            snap = self.account_info()
        except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
            self.shutdown()
            raise
        except Exception as exc:
            self.shutdown()
            if isinstance(exc, Mt5PreDispatchTransportError):
                raise
            raise Mt5PreDispatchTransportError(
                f"MT5 terminal account rebind failed before order_send ({type(exc).__name__}); reconnect required"
            ) from None
        expected_trade_mode = "REAL" if creds.execution_mode == EXECUTION_MODE_LIVE else "DEMO"
        if not snap.connected:
            self.shutdown()
            raise Mt5PreDispatchTransportError(
                f"MT5 terminal reports connected=False before order_send on {creds.broker_id}; reconnect required"
            )
        if (
            snap.login != creds.login
            or snap.server.casefold() != creds.server.casefold()
            or snap.trade_mode != expected_trade_mode
        ):
            self.shutdown()
            if creds.execution_mode == EXECUTION_MODE_LIVE:
                raise LiveAuthorizationError(
                    "MT5 terminal account/server/mode drifted from LIVE target before order_send; reconnect required"
                )
            raise Mt5PreDispatchTransportError(
                "MT5 terminal account/server/mode drifted from target before order_send; reconnect required"
            )
        if creds.execution_mode == EXECUTION_MODE_LIVE and creds.live_auth_context is not None:
            if (
                str(snap.login) != creds.live_auth_context.account_id.strip()
                or snap.server.casefold() != creds.live_auth_context.server.strip().casefold()
            ):
                self.shutdown()
                raise LiveAuthorizationError(
                    "MT5 terminal account/server does not match verified LiveAuthorizationContext; reconnect required"
                )
        return snap

    def _raw_order_send(self, sdk: Any, payload: dict[str, Any]) -> Any:
        return sdk.order_send(payload)

    def send_order(
        self,
        request: Mt5OrderRequest,
        *,
        valve_grant: ValveOrderGrant | None = None,
        require_risk_reducing: bool = False,
        now: datetime | None = None,
    ) -> Mt5OrderReceipt:
        sdk = self._require_connected()
        creds = self._credentials
        if creds is None:
            raise Mt5TransportError("native MT5 transport has no bound credentials")
        check_now = self._clock() if now is None else utc_time(now, "now")
        self._assert_live_dispatch_authorized(now=check_now)
        self._verify_terminal_binding_before_send(sdk, creds)
        verify_and_consume_valve_order_grant(
            valve_grant,
            broker_id=creds.broker_id,
            account_id=str(creds.login),
            server=creds.server,
            execution_mode=creds.execution_mode,
            action_kind=request.action,
            symbol=request.symbol,
            side=request.side.value,
            volume=request.volume_lots,
            stop_loss=request.stop_loss,
            take_profit=request.take_profit,
            position_ticket=request.position_ticket,
            now=check_now,
            require_risk_reducing=require_risk_reducing,
        )
        payload = request.to_native_request(sdk)
        result = self._raw_order_send(sdk, payload)
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
            take_profit=request.take_profit,
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
        key_dir: str | Path | None = None,
        valve_admission_key_file: str | Path | None = None,
        custody_inspector: SpoolCustodyInspector | None = None,
        clock: Callable[[], datetime] | None = None,
        max_snapshot_age_seconds_demo: float = 15.0,
        max_snapshot_age_seconds_live: float = 5.0,
        max_tick_age_ms_demo: int = 60_000,
        max_tick_age_ms_live: int = 15_000,
        max_future_skew_seconds: float = 5.0,
    ) -> None:
        if not isinstance(spool_dir, (str, Path)) or not str(spool_dir).strip():
            raise Mt5NotConfiguredError("spool_dir must be a non-empty path")
        if not (0 < receipt_timeout_seconds <= 300) or not (0 < poll_interval_seconds <= 5):
            raise ContractError("receipt timeout must be in (0, 300] s and poll interval in (0, 5] s")
        if max_snapshot_age_seconds_demo <= 0 or max_snapshot_age_seconds_live <= 0 or max_future_skew_seconds < 0:
            raise ContractError("snapshot freshness bounds must be positive")
        if max_tick_age_ms_demo <= 0 or max_tick_age_ms_live <= 0:
            raise ContractError("tick freshness bounds must be positive")
        self.spool_dir = Path(spool_dir)
        self.key_dir = resolve_spool_key_dir(self.spool_dir, key_dir=key_dir)
        self.valve_key_file = _valve_admission_key_path(
            self.spool_dir, key_dir=self.key_dir, valve_key_file=valve_admission_key_file
        )
        self._custody_inspector = custody_inspector
        self._clock = clock or _utc_now
        self._max_snapshot_age_demo = float(max_snapshot_age_seconds_demo)
        self._max_snapshot_age_live = float(max_snapshot_age_seconds_live)
        self._max_tick_age_ms_demo = int(max_tick_age_ms_demo)
        self._max_tick_age_ms_live = int(max_tick_age_ms_live)
        self._max_future_skew_seconds = float(max_future_skew_seconds)
        self._timeout = float(receipt_timeout_seconds)
        self._poll = float(poll_interval_seconds)
        self._sleep = sleep
        self._monotonic = monotonic
        self._max_leverage = max_leverage
        self._max_file_bytes = max_file_bytes
        self._credentials: Mt5Credentials | None = None
        self._hmac_key: bytes | None = None
        self._nonce_ledger = _SpoolReplayLedger(
            _spool_meta_root(self.spool_dir) / f".{self.spool_dir.name}.outbound_nonce.json",
            custody_inspector=custody_inspector,
        )
        self._global_nonce_ledger = _SpoolReplayLedger(
            self.key_dir / ".global_outbound_nonce.json",
            custody_inspector=custody_inspector,
        )
        self._snapshot_seq_lock = threading.RLock()
        self._snapshot_seq_path = (
            _spool_meta_root(self.spool_dir) / f".{self.spool_dir.name}.snapshot_seq.json"
        )
        self._last_verified_seq: int | None = None
        self._last_verified_mac: str | None = None
        self._last_seq_file_sig: tuple[int, int, int, int, int] | None = None
        self._last_seq_custody_mono: float = 0.0
        self._seq_custody_recheck_seconds: float = 5.0
        self._prepared_nonces: dict[str, int] = {}

    def __repr__(self) -> str:
        return f"Mt5SpoolBridgeTransport(spool_dir={self.spool_dir.name!r}, connected={self._credentials is not None})"

    def _channel_for(self, creds: Mt5Credentials | None = None) -> str:
        eff = creds or self._credentials
        if eff is not None:
            return eff.broker_id.lower()
        name = self.spool_dir.name.lower()
        return name if name in ("hugosway_mt5", "lhfx_mt5") else "hugosway_mt5"

    def _channel_hmac_key_and_id(self, creds: Mt5Credentials | None = None) -> tuple[bytes, str]:
        master = self._hmac_key if self._hmac_key is not None else _load_or_create_spool_hmac_key(
            self.spool_dir, key_dir=self.key_dir, custody_inspector=self._custody_inspector
        )
        ch = self._channel_for(creds)
        ch_key = derive_spool_channel_key(master, ch)
        return ch_key, spool_channel_key_id(ch_key, ch)

    def prepare_spool_directory(self) -> Path:
        meta_root = _spool_meta_root(self.spool_dir)
        if os.path.lexists(meta_root):
            verify_spool_path_custody(meta_root, expect_dir=True, inspector=self._custody_inspector, check_ancestors=True)
        else:
            verify_spool_path_custody(meta_root, inspector=self._custody_inspector, check_ancestors=True)
            meta_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            apply_verified_directory_mode(meta_root, 0o700, custody_inspector=self._custody_inspector, newly_created=True)
        existed = os.path.lexists(self.spool_dir)
        if existed:
            apply_verified_directory_mode(self.spool_dir, 0o700, custody_inspector=self._custody_inspector, newly_created=False)
        else:
            self.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            apply_verified_directory_mode(self.spool_dir, 0o700, custody_inspector=self._custody_inspector, newly_created=True)
        self._hmac_key = _load_or_create_spool_hmac_key(
            self.spool_dir, key_dir=self.key_dir, custody_inspector=self._custody_inspector
        )
        return self.spool_dir

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
        ticket_file = self.spool_dir / "live_auth_ticket.json"
        if credentials.execution_mode == EXECUTION_MODE_DEMO:
            if os.path.lexists(ticket_file):
                ticket_file.unlink()
        elif credentials.live_auth_ticket_json:
            _atomic_write_bytes(
                ticket_file,
                credentials.live_auth_ticket_json.encode("ascii"),
                custody_inspector=self._custody_inspector,
            )
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

    def _assert_live_dispatch_authorized(self, creds: Mt5Credentials, *, now: datetime | None = None) -> None:
        if creds.execution_mode != EXECUTION_MODE_LIVE:
            return
        if creds.live_auth_context is None:
            raise LiveAuthorizationError(
                f"LIVE dispatch on {creds.broker_id} refused: missing verified LiveAuthorizationContext"
            )
        if creds.live_auth_context.key_file_identity is None:
            raise LiveAuthorizationError(
                f"LIVE dispatch on {creds.broker_id} refused: LiveAuthorizationContext lacks verified key_file_identity"
            )
        check_now = self._clock() if now is None else utc_time(now, "now")
        creds.live_auth_context.verify_provenance(
            now=check_now,
            reverify_ticket=True,
            require_arm_phrase=True,
        )
        creds.live_auth_context.assert_valid_at(
            check_now,
            expected_broker_id=creds.broker_id,
            expected_account_id=str(creds.login),
            expected_server=creds.server,
            require_arm_phrase=True,
            reverify_ticket=True,
        )

    @staticmethod
    def _lstat_sig(st: os.stat_result) -> tuple[int, int, int, int, int]:
        return (int(st.st_ino), int(st.st_size), int(st.st_mtime_ns), int(st.st_ctime_ns), int(st.st_mode))

    def _verify_and_record_snapshot_seq(self, seq_val: int, mac_hex: str) -> None:
        with self._snapshot_seq_lock:
            now_mono = self._monotonic()
            fast_verified = False
            if (
                self._custody_inspector is None
                and self._last_verified_seq is not None
                and self._last_verified_mac is not None
                and self._last_seq_file_sig is not None
                and (now_mono - self._last_seq_custody_mono) < self._seq_custody_recheck_seconds
            ):
                try:
                    st_seq = os.lstat(self._snapshot_seq_path)
                except OSError:
                    st_seq = None
                if (
                    st_seq is not None
                    and not _is_reparse_or_symlink(self._snapshot_seq_path, st_seq)
                    and stat.S_ISREG(st_seq.st_mode)
                    and self._lstat_sig(st_seq) == self._last_seq_file_sig
                ):
                    fast_verified = True

            if fast_verified:
                last_seq = int(self._last_verified_seq)  # type: ignore[arg-type]
                last_mac = str(self._last_verified_mac)
                if seq_val < last_seq:
                    raise Mt5SnapshotIntegrityError(
                        f"MT5 market snapshot_seq rollback rejected ({seq_val} < {last_seq})"
                    )
                if seq_val == last_seq:
                    if hmac.compare_digest(mac_hex, last_mac):
                        return
                    raise Mt5SnapshotIntegrityError(
                        f"MT5 market snapshot_seq={seq_val} equivocation rejected"
                    )
            else:
                if os.path.lexists(self._snapshot_seq_path):
                    state = _read_spool_json(
                        self._snapshot_seq_path,
                        max_bytes=65536,
                        custody_inspector=self._custody_inspector,
                    )
                    if type(state) is not dict:
                        raise Mt5SnapshotIntegrityError("corrupted MT5 consumer snapshot_seq ledger")
                    last_seq_raw = state.get("last_snapshot_seq")
                    last_mac = str(state.get("last_snapshot_hmac", "")).lower()
                    if type(last_seq_raw) is not str or not last_seq_raw.isdigit() or not _HEX64_RE.fullmatch(last_mac):
                        raise Mt5SnapshotIntegrityError("corrupted MT5 consumer snapshot_seq ledger fields")
                    last_seq = int(last_seq_raw)
                    if seq_val < last_seq:
                        raise Mt5SnapshotIntegrityError(
                            f"MT5 market snapshot_seq rollback rejected ({seq_val} < {last_seq})"
                        )
                    if seq_val == last_seq:
                        if hmac.compare_digest(mac_hex, last_mac):
                            if self._custody_inspector is None:
                                st_seq_disk = os.lstat(self._snapshot_seq_path)
                                self._last_verified_seq = last_seq
                                self._last_verified_mac = last_mac
                                self._last_seq_file_sig = self._lstat_sig(st_seq_disk)
                                self._last_seq_custody_mono = now_mono
                            return
                        raise Mt5SnapshotIntegrityError(
                            f"MT5 market snapshot_seq={seq_val} equivocation rejected"
                        )

            try:
                _atomic_write_json(
                    self._snapshot_seq_path,
                    {"last_snapshot_seq": str(seq_val), "last_snapshot_hmac": mac_hex},
                    custody_inspector=self._custody_inspector,
                )
                reread = _read_spool_json(
                    self._snapshot_seq_path,
                    max_bytes=65536,
                    custody_inspector=self._custody_inspector,
                )
                if (
                    type(reread) is not dict
                    or reread.get("last_snapshot_seq") != str(seq_val)
                    or not hmac.compare_digest(str(reread.get("last_snapshot_hmac", "")).lower(), mac_hex)
                ):
                    raise Mt5SnapshotIntegrityError("MT5 consumer snapshot_seq persistence verification failed")
            except Exception:
                self._last_verified_seq = None
                self._last_verified_mac = None
                self._last_seq_file_sig = None
                raise
            if self._custody_inspector is None:
                st_new = os.lstat(self._snapshot_seq_path)
                self._last_verified_seq = seq_val
                self._last_verified_mac = mac_hex
                self._last_seq_file_sig = self._lstat_sig(st_new)
                self._last_seq_custody_mono = self._monotonic()

    def _market_doc(self) -> dict[str, Any]:
        path = self.spool_dir / "market_ticks.json"
        try:
            doc = _read_spool_json(path, max_bytes=self._max_file_bytes, custody_inspector=self._custody_inspector)
        except FileNotFoundError:
            raise Mt5TransportError("market_ticks.json not published yet; is CasForexMt5Bridge EA running?") from None
        if type(doc) is not dict or doc.get("protocol") != MT5_SPOOL_PROTOCOL:
            raise Mt5SnapshotIntegrityError("market_ticks.json protocol mismatch")
        if type(doc.get("connected")) is not bool:
            raise Mt5SnapshotIntegrityError("market_ticks.json connected field must be a boolean")
        creds = self._credentials
        expected_channel = self._channel_for(creds)
        doc_channel = str(doc.get("broker_channel", "")).strip().lower()
        if doc_channel != expected_channel:
            raise Mt5SnapshotIntegrityError(
                f"market_ticks.json broker_channel mismatch ({doc_channel!r} != {expected_channel!r})"
            )
        channel_key, expected_key_id = self._channel_hmac_key_and_id(creds)
        if str(doc.get("channel_key_id", "")) != expected_key_id:
            raise Mt5SnapshotIntegrityError("market_ticks.json channel_key_id mismatch")
        actual_mac = str(doc.get("snapshot_hmac_sha256", "")).lower()
        if not _HEX64_RE.fullmatch(actual_mac):
            raise Mt5SnapshotIntegrityError("market_ticks.json missing or invalid snapshot_hmac_sha256")
        expected_mac = compute_mt5_market_snapshot_hmac(doc, channel_key=channel_key)
        if not hmac.compare_digest(expected_mac, actual_mac):
            raise Mt5SnapshotIntegrityError("market_ticks.json snapshot_hmac_sha256 verification failed")

        expected_mode = creds.execution_mode if creds else EXECUTION_MODE_DEMO
        broker_id = creds.broker_id if creds else "MT5"
        reported_mode = doc.get("account_trade_mode")
        doc_exec_mode = str(doc.get("execution_mode", "")).strip().upper()
        if expected_mode == EXECUTION_MODE_DEMO:
            if reported_mode != "DEMO" or doc_exec_mode != EXECUTION_MODE_DEMO:
                raise LiveBrokerEndpointForbiddenError("MT5 EA reports a non-DEMO account; live/real accounts are forbidden")
            validate_demo_server(broker_id, str(doc.get("server", "")))
        else:
            if reported_mode != "REAL" or doc_exec_mode != EXECUTION_MODE_LIVE:
                raise ContractError("LIVE execution mode requires MT5 EA account_trade_mode=REAL")
            validate_mt5_server_name(
                broker_id, str(doc.get("server", "")), execution_mode=EXECUTION_MODE_LIVE, live_armed=True
            )

        acct = doc.get("account")
        if type(acct) is not dict:
            raise Mt5SnapshotIntegrityError("market_ticks.json missing account object")
        login_raw = acct.get("login")
        if not isinstance(login_raw, str) or not _LOGIN_RE.fullmatch(login_raw):
            raise Mt5SnapshotIntegrityError("account.login must be a decimal string")
        if creds is not None:
            if login_raw.strip() != str(creds.login):
                raise Mt5SnapshotIntegrityError("market_ticks.json account.login does not match bound credentials")
            if str(doc.get("server", "")).strip().casefold() != creds.server.strip().casefold():
                raise Mt5SnapshotIntegrityError("market_ticks.json server does not match bound credentials")

        try:
            obs_dt = _parse_iso(doc.get("observed_at"), "observed_at")
        except Mt5TransportError as exc:
            raise Mt5SnapshotIntegrityError(str(exc)) from None
        now_dt = self._clock()
        age_sec = (now_dt - obs_dt).total_seconds()
        if age_sec < -self._max_future_skew_seconds:
            raise Mt5SnapshotIntegrityError("market_ticks.json observed_at exceeds max future clock skew")
        max_age = self._max_snapshot_age_live if expected_mode == EXECUTION_MODE_LIVE else self._max_snapshot_age_demo
        if age_sec > max_age:
            raise Mt5SnapshotIntegrityError(
                f"market_ticks.json observed_at is stale (age={age_sec:.2f}s > {max_age:.2f}s)"
            )

        seq_raw = doc.get("snapshot_seq")
        if type(seq_raw) is not str or not seq_raw.isdigit() or int(seq_raw) <= 0 or str(int(seq_raw)) != seq_raw:
            raise Mt5SnapshotIntegrityError("market_ticks.json snapshot_seq must be a positive decimal string")
        self._verify_and_record_snapshot_seq(int(seq_raw), actual_mac)
        return doc

    def _parse_account_from_doc(self, doc: Mapping[str, Any]) -> Mt5AccountSnapshot:
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
        connected = doc.get("connected", True)
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
            connected=connected,
        )

    def account_info(self) -> Mt5AccountSnapshot:
        return self._parse_account_from_doc(self._market_doc())

    @staticmethod
    def _extract_verified_tick(
        doc: Mapping[str, Any],
        symbol: str,
        *,
        require_fresh_tick: bool,
        now_ms: int,
        max_tick_age_ms: int,
        future_ms: int,
        ticks_by_norm: Mapping[str, Mapping[str, Any]],
    ) -> Mt5Tick:
        item = ticks_by_norm.get(symbol)
        if item is None:
            raise Mt5TransportError(f"no published MT5 tick for {symbol}")
        msc_raw = item.get("time_msc")
        if type(msc_raw) is not str or not msc_raw.isdigit() or int(msc_raw) <= 0:
            raise Mt5SnapshotIntegrityError(f"MT5 tick for {symbol} has invalid time_msc")
        tick_ms = int(msc_raw)
        if tick_ms > now_ms + future_ms:
            raise Mt5SnapshotIntegrityError(f"MT5 tick time_msc for {symbol} exceeds future skew")
        if require_fresh_tick and (now_ms - tick_ms) > max_tick_age_ms:
            raise Mt5SnapshotIntegrityError(
                f"MT5 tick for {symbol} is stale (age_ms={now_ms - tick_ms} > {max_tick_age_ms})"
            )
        return Mt5Tick(
            symbol=symbol,
            bid=_wire_decimal(item.get("bid"), "bid", positive=True),  # type: ignore[arg-type]
            ask=_wire_decimal(item.get("ask"), "ask", positive=True),  # type: ignore[arg-type]
            time_msc=msc_raw,
        )

    def _prepare_tick_snapshot(
        self,
        *,
        disconnect_label: str,
    ) -> tuple[dict[str, Any], dict[str, Mapping[str, Any]], int, int, int]:
        doc = self._market_doc()
        if doc.get("connected", True) is False:
            raise Mt5PreDispatchTransportError(
                f"MT5 terminal is disconnected for {disconnect_label}: {STATUS_BROKER_OFFLINE}"
            )
        ticks = doc.get("ticks")
        if type(ticks) is not list:
            raise Mt5TransportError("market_ticks.json missing ticks list")
        creds = self._credentials
        expected_mode = creds.execution_mode if creds else EXECUTION_MODE_DEMO
        max_tick_age_ms = self._max_tick_age_ms_live if expected_mode == EXECUTION_MODE_LIVE else self._max_tick_age_ms_demo
        now_ms = int(self._clock().timestamp() * 1000)
        future_ms = int(self._max_future_skew_seconds * 1000)
        ticks_by_norm: dict[str, Mapping[str, Any]] = {}
        for item in ticks:
            if type(item) is dict and isinstance(item.get("symbol"), str):
                norm_sym = normalize_market_symbol(item["symbol"])
                if norm_sym not in ticks_by_norm:
                    ticks_by_norm[norm_sym] = item
        return doc, ticks_by_norm, now_ms, max_tick_age_ms, future_ms

    def symbol_tick(self, symbol: str, *, require_fresh_tick: bool = True) -> Mt5Tick:
        Mt5MarginCalculator.split_symbol(symbol)
        doc, ticks_by_norm, now_ms, max_tick_age_ms, future_ms = self._prepare_tick_snapshot(disconnect_label=symbol)
        return self._extract_verified_tick(
            doc,
            symbol,
            require_fresh_tick=require_fresh_tick,
            now_ms=now_ms,
            max_tick_age_ms=max_tick_age_ms,
            future_ms=future_ms,
            ticks_by_norm=ticks_by_norm,
        )

    def symbol_ticks_batch(
        self,
        symbols: Sequence[str],
        *,
        require_fresh_tick: bool = True,
    ) -> tuple[dict[str, Mt5Tick], dict[str, str]]:
        """Verify market_ticks.json ONCE and extract/freshness-check all requested symbols."""
        req_syms = list(symbols)
        for sym in req_syms:
            Mt5MarginCalculator.split_symbol(sym)
        if not req_syms:
            return {}, {}
        doc, ticks_by_norm, now_ms, max_tick_age_ms, future_ms = self._prepare_tick_snapshot(
            disconnect_label=",".join(req_syms)
        )
        found: dict[str, Mt5Tick] = {}
        errors: dict[str, str] = {}
        for sym in req_syms:
            try:
                found[sym] = self._extract_verified_tick(
                    doc,
                    sym,
                    require_fresh_tick=require_fresh_tick,
                    now_ms=now_ms,
                    max_tick_age_ms=max_tick_age_ms,
                    future_ms=future_ms,
                    ticks_by_norm=ticks_by_norm,
                )
            except (ContractError, OSError) as exc_sym:
                errors[sym] = type(exc_sym).__name__
        return found, errors

    def read_index_candles(self, symbol: str) -> dict[str, list[dict[str, Any]]] | None:
        """Read optional broker-native M1/M5/H1 candle bars from market_candles.json if present."""
        cpath = self.spool_dir / "market_candles.json"
        if not cpath.is_file():
            return None
        try:
            doc = _read_spool_json(cpath, max_bytes=self._max_file_bytes)
        except Exception:
            return None
        markets = doc.get("markets")
        if not isinstance(markets, dict):
            return None
        entry = markets.get(symbol)
        if not isinstance(entry, dict):
            return None
        out: dict[str, list[dict[str, Any]]] = {}
        for tf_key in ("candles_m1", "candles_m5", "candles_h1"):
            rows = entry.get(tf_key)
            if isinstance(rows, list) and rows:
                clean_rows: list[dict[str, Any]] = []
                for r in rows[-48:]:
                    if isinstance(r, dict) and all(k in r for k in ("t", "o", "h", "l", "c")):
                        clean_rows.append({
                            "t": str(r["t"]),
                            "o": str(r["o"]),
                            "h": str(r["h"]),
                            "l": str(r["l"]),
                            "c": str(r["c"]),
                            "v": str(r.get("v", "1")),
                            "n": int(r.get("n", 1)),
                        })
                if clean_rows:
                    out[tf_key] = clean_rows
        return out or None

    @staticmethod
    def _parse_positions_from_doc(doc: Mapping[str, Any]) -> tuple[Mt5Position, ...]:
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
                symbol=normalize_market_symbol(str(item.get("symbol"))),
                side=Side(side_raw),
                volume_lots=_wire_decimal(item.get("volume"), "volume", positive=True),  # type: ignore[arg-type]
                price_open=_wire_decimal(item.get("price_open"), "price_open", positive=True),  # type: ignore[arg-type]
                stop_loss=_wire_decimal(item.get("sl", "0"), "sl", allow_zero_as_none=True),
                profit=_wire_decimal(item.get("profit", "0"), "profit"),  # type: ignore[arg-type]
                take_profit=_wire_decimal(item.get("tp", "0"), "tp", allow_zero_as_none=True),
            ))
        return tuple(out)

    def positions(self) -> tuple[Mt5Position, ...]:
        return self._parse_positions_from_doc(self._market_doc())

    def order_deal_history(self, login: int, server: str) -> dict[str, Any]:
        """Read and cryptographically verify signed order_history.json published by CasForexMt5Bridge.mq5."""
        creds = self._require_connected()
        if int(login) != int(creds.login) or str(server).casefold() != creds.server.casefold():
            raise Mt5SnapshotIntegrityError("order_deal_history account/server does not match bound credentials")
        path = self.spool_dir / "order_history.json"
        if not os.path.lexists(path):
            raise Mt5TransportError(f"{creds.broker_id} order_history.json is not present")
        doc = _read_spool_json(path, max_bytes=self._max_file_bytes, custody_inspector=self._custody_inspector)
        if type(doc) is not dict:
            raise Mt5SnapshotIntegrityError("order_history.json must be a JSON object")
        if doc.get("protocol") != MT5_SPOOL_PROTOCOL:
            raise Mt5SnapshotIntegrityError("order_history.json protocol mismatch")
        expected_channel = creds.broker_id.lower()
        if doc.get("broker_channel") != expected_channel:
            raise Mt5SnapshotIntegrityError(f"order_history.json channel mismatch for {creds.broker_id}")
        key, expected_key_id = self._channel_hmac_key_and_id(creds)
        if doc.get("channel_key_id") != expected_key_id:
            raise Mt5SnapshotIntegrityError("order_history.json channel_key_id mismatch")
        actual_mac = str(doc.get("history_hmac_sha256", "")).lower()
        if not _HEX64_RE.fullmatch(actual_mac):
            raise Mt5SnapshotIntegrityError("order_history.json missing or invalid history_hmac_sha256")
        expected_mac = compute_mt5_order_history_hmac(doc, key)
        if not hmac.compare_digest(expected_mac, actual_mac):
            raise Mt5SnapshotIntegrityError("order_history.json history_hmac_sha256 verification failed")
        if doc.get("execution_mode") != creds.execution_mode:
            raise LiveBrokerEndpointForbiddenError(
                f"order_history.json execution_mode {doc.get('execution_mode')!r} != {creds.execution_mode!r}"
            )
        expected_trade_mode = "DEMO" if creds.execution_mode == EXECUTION_MODE_DEMO else "REAL"
        if doc.get("account_trade_mode") != expected_trade_mode:
            raise LiveBrokerEndpointForbiddenError(
                f"order_history.json account_trade_mode {doc.get('account_trade_mode')!r} != {expected_trade_mode!r}"
            )
        doc_login = str(doc.get("account_login", ""))
        if not doc_login.isdigit() or int(doc_login) != int(creds.login):
            raise Mt5SnapshotIntegrityError("order_history.json account_login mismatch")
        doc_server_raw = str(doc.get("server", ""))
        if creds.execution_mode == EXECUTION_MODE_DEMO:
            srv_norm = validate_demo_server(creds.broker_id, doc_server_raw)
        else:
            srv_norm = validate_mt5_server_name(
                creds.broker_id, doc_server_raw, execution_mode=EXECUTION_MODE_LIVE, live_armed=True
            )
        if srv_norm.casefold() != creds.server.casefold():
            raise Mt5SnapshotIntegrityError("order_history.json server mismatch")
        try:
            obs = _parse_iso(doc.get("observed_at"), "observed_at")
        except ContractError as exc:
            raise Mt5SnapshotIntegrityError(str(exc)) from None
        now = self._clock()
        if (obs - now).total_seconds() > self._max_future_skew_seconds:
            raise Mt5SnapshotIntegrityError("order_history.json observed_at exceeds future clock skew")
        max_hist_age_s = 120.0 if creds.execution_mode == EXECUTION_MODE_DEMO else 30.0
        if (now - obs).total_seconds() > max_hist_age_s:
            raise Mt5SnapshotIntegrityError("order_history.json is stale")
        if doc.get("connected") is not True:
            raise Mt5TransportError(f"{creds.broker_id} order_history.json reports terminal disconnected")
        if doc.get("complete") is not True:
            raise Mt5SnapshotIntegrityError(f"{creds.broker_id} order_history.json reports incomplete history")
        return {
            "account_login": int(creds.login),
            "server": creds.server,
            "complete": True,
            "open_position_tickets": list(doc["open_position_tickets"]),
            "orders": list(doc["orders"]),
            "deals": list(doc["deals"]),
        }

    def account_and_positions(self) -> tuple[Mt5AccountSnapshot, tuple[Mt5Position, ...]]:
        """Read and verify market_ticks.json ONCE and return both account snapshot and open positions."""
        doc = self._market_doc()
        return self._parse_account_from_doc(doc), self._parse_positions_from_doc(doc)

    def prepare_request(self, request: Mt5OrderRequest) -> Mt5OrderRequest:
        creds = self._require_connected()
        import dataclasses as _dc
        _, expected_key_id = self._channel_hmac_key_and_id(creds)
        prebound = (
            request.issued_at is not None
            and request.expires_at is not None
            and request.server == creds.server
            and request.channel_key_id == expected_key_id
        )
        with self._nonce_ledger._lock:
            if prebound and self._prepared_nonces.get(request.request_id) == request.monotonic_nonce:
                return request
            nonce_val = self._nonce_ledger.next_nonce()
            self._prepared_nonces[request.request_id] = nonce_val
            if len(self._prepared_nonces) > 1024:
                oldest = next(iter(self._prepared_nonces))
                self._prepared_nonces.pop(oldest, None)
        if request.issued_at is not None and request.expires_at is not None and request.server == creds.server:
            return _dc.replace(
                request,
                monotonic_nonce=nonce_val,
                channel_key_id=request.channel_key_id or expected_key_id,
            )
        if request.issued_at is not None and request.expires_at is not None:
            eff_issued = request.issued_at
            eff_expires = request.expires_at
        else:
            mkt_doc = self._market_doc()
            obs_raw = mkt_doc.get("observed_at")
            term_now = _parse_iso(obs_raw, "observed_at") if isinstance(obs_raw, str) and obs_raw.strip() else _utc_now()
            eff_issued = request.issued_at if request.issued_at is not None else term_now
            eff_expires = request.expires_at if request.expires_at is not None else (eff_issued + timedelta(seconds=30))
        return _dc.replace(
            request,
            monotonic_nonce=nonce_val,
            issued_at=eff_issued,
            expires_at=eff_expires,
            broker_channel=creds.broker_id.lower(),
            channel_key_id=expected_key_id,
            account_login=str(creds.login),
            server=creds.server,
            execution_mode=creds.execution_mode,
        )

    def send_order(
        self,
        request: Mt5OrderRequest,
        *,
        valve_grant: ValveOrderGrant | None = None,
        require_risk_reducing: bool = False,
        now: datetime | None = None,
    ) -> Mt5OrderReceipt:
        creds = self._require_connected()
        check_now = self._clock() if now is None else utc_time(now, "now")
        self._assert_live_dispatch_authorized(creds, now=check_now)
        channel_key, expected_key_id = self._channel_hmac_key_and_id(creds)
        bound_req = self.prepare_request(request)
        if bound_req.channel_key_id != expected_key_id:
            raise Mt5TransportError("spool request channel_key_id mismatch")
        if not _HEX64_RE.fullmatch(str(bound_req.valve_admission_sig or "").lower()) or bound_req.valve_admission_expires_at is None:
            raise Mt5ValveClearanceError(
                "MT5 spool dispatch refused: missing short-lived signed Valve admission (valve_admission_sig)"
            )
        request_path = self.spool_dir / f"order_request_{bound_req.request_id}.json"
        receipt_path = self.spool_dir / f"order_receipt_{bound_req.request_id}.json"
        if request_path.exists() or receipt_path.exists():
            raise Mt5TransportError(f"request_id {bound_req.request_id} already present in spool; never resubmitted")
        verify_and_consume_valve_order_grant(
            valve_grant,
            broker_id=creds.broker_id,
            account_id=str(creds.login),
            server=creds.server,
            execution_mode=creds.execution_mode,
            action_kind=bound_req.action,
            symbol=bound_req.symbol,
            side=bound_req.side.value,
            volume=bound_req.volume_lots,
            stop_loss=bound_req.stop_loss,
            take_profit=bound_req.take_profit,
            position_ticket=bound_req.position_ticket,
            now=check_now,
            require_risk_reducing=require_risk_reducing,
        )
        doc = bound_req.to_spool_dict()
        doc["request_hmac_sha256"] = _spool_hmac_hex(channel_key, _canonical_spool_request_hmac_input(doc))
        _atomic_write_json(request_path, doc, custody_inspector=self._custody_inspector)
        deadline = self._monotonic() + self._timeout
        while True:
            if receipt_path.exists():
                receipt = self._parse_receipt(receipt_path, bound_req, creds, hmac_key=channel_key)
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

    def _parse_receipt(
        self,
        path: Path,
        request: Mt5OrderRequest,
        creds: Mt5Credentials,
        *,
        hmac_key: bytes | None = None,
    ) -> Mt5OrderReceipt:
        doc = _read_spool_json(path, max_bytes=self._max_file_bytes, custody_inspector=self._custody_inspector)
        if type(doc) is not dict or doc.get("protocol") != MT5_SPOOL_PROTOCOL:
            raise Mt5TransportError("receipt protocol mismatch")
        if any(type(v) is not str for v in doc.values()):
            raise Mt5TransportError("receipt values must all be strings")
        if doc.get("request_id") != request.request_id or doc.get("request_sha256") != request.request_sha256:
            raise Mt5TransportError("receipt does not bind the exact request_id/request_sha256")
        if str(doc.get("monotonic_nonce", "")) != str(request.monotonic_nonce):
            raise Mt5TransportError("receipt monotonic_nonce mismatch")
        if hmac_key is not None:
            key = hmac_key
        else:
            key, _ = self._channel_hmac_key_and_id(creds)
        expected_mac = _spool_hmac_hex(key, _canonical_spool_receipt_hmac_input(doc))
        actual_mac = str(doc.get("receipt_hmac_sha256", "")).lower()
        if len(actual_mac) != 64 or not hmac.compare_digest(expected_mac, actual_mac):
            raise Mt5TransportError("receipt HMAC-SHA256 verification failed")
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
            take_profit=_wire_decimal(doc.get("tp", "0"), "tp", allow_zero_as_none=True),
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
        max_volume_lots: Decimal = MT5_MAX_VOLUME_DEFAULT,
        clock: Callable[[], datetime] | None = None,
        broker_channel: str | None = None,
        execution_mode: str | None = None,
        key_dir: str | Path | None = None,
        valve_admission_key_file: str | Path | None = None,
        custody_inspector: SpoolCustodyInspector | None = None,
        connected: bool = True,
    ) -> None:
        if type(connected) is not bool:
            raise ContractError("connected must be a boolean")
        self.spool_dir = Path(spool_dir)
        self.server = server
        self.login = login
        self.quotes: dict[str, tuple[Decimal, Decimal]] = dict(quotes)
        self.balance = balance
        self.currency = currency
        self.leverage = leverage
        self.trade_mode = trade_mode
        if broker_channel is not None:
            self.broker_channel = broker_channel.strip().lower()
        elif self.spool_dir.name.lower() in ("hugosway_mt5", "lhfx_mt5"):
            self.broker_channel = self.spool_dir.name.lower()
        elif "lhfx" in str(server).lower():
            self.broker_channel = "lhfx_mt5"
        else:
            self.broker_channel = "hugosway_mt5"
        self.execution_mode = (
            execution_mode.strip().upper()
            if execution_mode is not None
            else (EXECUTION_MODE_LIVE if str(trade_mode).upper() == "REAL" else EXECUTION_MODE_DEMO)
        )
        self.key_dir = resolve_spool_key_dir(self.spool_dir, key_dir=key_dir)
        self.valve_key_file = _valve_admission_key_path(
            self.spool_dir, key_dir=self.key_dir, valve_key_file=valve_admission_key_file
        )
        self._custody_inspector = custody_inspector
        self._max_lots = decimal_value(max_volume_lots, "max_volume_lots", positive=True)
        self._clock = clock or _utc_now
        self._calc = Mt5MarginCalculator(leverage=min(leverage, MAX_DEMO_LEVERAGE), account_currency=currency)
        self._positions: dict[str, dict[str, Any]] = {}
        self._next_ticket = 500_000_001
        self._next_deal = 700_000_001
        self._history_orders: list[dict[str, str]] = []
        self._history_deals: list[dict[str, str]] = []
        self.processed: list[str] = []
        self._replay_ledger = _SpoolReplayLedger(
            _spool_meta_root(self.spool_dir) / f".{self.spool_dir.name}.emu_replay.json",
            custody_inspector=custody_inspector,
        )
        self._global_replay_ledger = _SpoolReplayLedger(
            _spool_meta_root(self.spool_dir) / ".global_emu_replay.json",
            custody_inspector=custody_inspector,
        )
        self._snapshot_seq_lock = threading.RLock()
        self._snapshot_seq_path = (
            _spool_meta_root(self.spool_dir) / f".{self.spool_dir.name}.emu_snapshot_seq.json"
        )
        self._replay_ledger_healthy: bool = True
        self.connected: bool = connected
        self._simulate_raw_zero_when_offline: bool = False
        self._has_connected_account: bool = bool(connected and balance > Decimal("0"))
        self._last_connected_balance: Decimal = balance if self._has_connected_account else Decimal("0.00")
        self._last_connected_equity: Decimal = balance if self._has_connected_account else Decimal("0.00")
        self._last_connected_margin: Decimal = Decimal("0.00")
        self._last_connected_margin_free: Decimal = balance if self._has_connected_account else Decimal("0.00")

    def set_connected(self, connected: bool, *, raw_zero_account: bool = False) -> None:
        if type(connected) is not bool:
            raise ContractError("connected must be a boolean")
        self.connected = connected
        self._simulate_raw_zero_when_offline = bool(raw_zero_account) if not connected else False

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
            units = self._calc.lots_to_units(pos["volume"], symbol=pos["symbol"])
            total += self._calc.required_margin(pos["symbol"], pos["side"], units, self.quotes)
        return total

    def _close_price(self, pos: Mapping[str, Any]) -> Decimal:
        bid, ask = self.quotes[pos["symbol"]]
        return bid if pos["side"] is Side.BUY else ask

    def _pnl(self, pos: Mapping[str, Any], close_price: Decimal, lots: Decimal) -> Decimal:
        units = self._calc.lots_to_units(lots, symbol=pos["symbol"])
        direction = Decimal(1) if pos["side"] is Side.BUY else Decimal(-1)
        with localcontext() as ctx:
            ctx.prec = 40
            pnl_quote = (close_price - pos["price_open"]) * units * direction
            _, quote_ccy = Mt5MarginCalculator.split_symbol(pos["symbol"])
            rate = self._calc.conversion_rate(quote_ccy, self.quotes) if quote_ccy != self.currency else Decimal(1)
            return (pnl_quote * rate).quantize(Decimal("0.01"))

    def _channel_hmac_key_and_id(self) -> tuple[bytes, bytes, str]:
        master = _load_or_create_spool_hmac_key(
            self.spool_dir, key_dir=self.key_dir, custody_inspector=self._custody_inspector
        )
        ch_key = derive_spool_channel_key(master, self.broker_channel)
        return master, ch_key, spool_channel_key_id(ch_key, self.broker_channel)

    def publish_market(self) -> None:
        existed = os.path.lexists(self.spool_dir)
        if existed:
            apply_verified_directory_mode(
                self.spool_dir, 0o700, custody_inspector=self._custody_inspector, newly_created=False
            )
        else:
            verify_spool_path_custody(self.spool_dir, inspector=self._custody_inspector, check_ancestors=True)
            self.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            apply_verified_directory_mode(
                self.spool_dir, 0o700, custody_inspector=self._custody_inspector, newly_created=True
            )
        _load_or_create_spool_hmac_key(self.spool_dir, key_dir=self.key_dir, custody_inspector=self._custody_inspector)
        _load_or_create_valve_admission_key(
            self.spool_dir,
            key_dir=self.key_dir,
            valve_key_file=self.valve_key_file,
            custody_inspector=self._custody_inspector,
        )
        floating = self._floating()
        used = self._used_margin()
        equity = self.balance + floating
        free = equity - used
        if self.connected:
            if self.balance > Decimal("0") or equity > Decimal("0") or self._has_connected_account:
                self._last_connected_balance = self.balance
                self._last_connected_equity = equity
                self._last_connected_margin = used
                self._last_connected_margin_free = free
                if self.balance > Decimal("0") or equity > Decimal("0"):
                    self._has_connected_account = True
            out_balance = self.balance
            out_equity = equity
            out_margin = used
            out_free = free
        elif self._simulate_raw_zero_when_offline or not self._has_connected_account:
            out_balance = Decimal("0.00")
            out_equity = Decimal("0.00")
            out_margin = Decimal("0.00")
            out_free = Decimal("0.00")
        else:
            out_balance = self._last_connected_balance
            out_equity = self._last_connected_equity
            out_margin = self._last_connected_margin
            out_free = self._last_connected_margin_free
        with self._snapshot_seq_lock:
            last_seq = 0
            if os.path.lexists(self._snapshot_seq_path):
                seq_state = _read_spool_json(
                    self._snapshot_seq_path,
                    max_bytes=65536,
                    custody_inspector=self._custody_inspector,
                )
                if type(seq_state) is not dict:
                    raise Mt5TransportError("corrupted emulator snapshot_seq ledger")
                seq_raw = seq_state.get("last_snapshot_seq", "0")
                if type(seq_raw) is not str or not seq_raw.isdigit():
                    raise Mt5TransportError("corrupted emulator snapshot_seq ledger value")
                last_seq = int(seq_raw)
            next_seq = last_seq + 1
            _atomic_write_json(
                self._snapshot_seq_path,
                {"last_snapshot_seq": str(next_seq)},
                custody_inspector=self._custody_inspector,
            )
            reread_seq = _read_spool_json(
                self._snapshot_seq_path,
                max_bytes=65536,
                custody_inspector=self._custody_inspector,
            )
            if type(reread_seq) is not dict or reread_seq.get("last_snapshot_seq") != str(next_seq):
                raise Mt5TransportError("emulator snapshot_seq persistence verification failed")

        _, channel_key, key_id = self._channel_hmac_key_and_id()
        eff_exec_mode = (
            EXECUTION_MODE_LIVE
            if str(self.trade_mode).upper() == "REAL"
            else (EXECUTION_MODE_DEMO if str(self.trade_mode).upper() == "DEMO" else self.execution_mode)
        )
        now = self._clock()
        time_msc = str(int(now.timestamp() * 1000))
        doc = {
            "protocol": MT5_SPOOL_PROTOCOL,
            "broker_channel": self.broker_channel,
            "channel_key_id": key_id,
            "execution_mode": eff_exec_mode,
            "snapshot_seq": str(next_seq),
            "connected": bool(self.connected),
            "server": self.server,
            "account_trade_mode": self.trade_mode,
            "observed_at": _iso(now),
            "account": {
                "login": str(self.login),
                "currency": self.currency,
                "balance": decimal_text(out_balance),
                "equity": decimal_text(out_equity),
                "margin": decimal_text(out_margin),
                "margin_free": decimal_text(out_free),
                "leverage": str(self.leverage),
            },
            "ticks": (
                [
                    {"symbol": sym, "bid": decimal_text(bid), "ask": decimal_text(ask), "time_msc": time_msc}
                    for sym, (bid, ask) in sorted(self.quotes.items())
                ]
                if self.connected
                else []
            ),
            "positions": (
                [
                    {
                        "ticket": ticket,
                        "symbol": pos["symbol"],
                        "side": pos["side"].value,
                        "volume": decimal_text(pos["volume"]),
                        "price_open": decimal_text(pos["price_open"]),
                        "sl": "0" if pos["sl"] is None else decimal_text(pos["sl"]),
                        "tp": "0" if pos.get("tp") is None else decimal_text(pos["tp"]),
                        "profit": decimal_text(self._pnl(pos, self._close_price(pos), pos["volume"])),
                    }
                    for ticket, pos in sorted(self._positions.items())
                ]
                if self.connected
                else []
            ),
        }
        doc["snapshot_hmac_sha256"] = compute_mt5_market_snapshot_hmac(doc, channel_key=channel_key)
        _atomic_write_json(self.spool_dir / "market_ticks.json", doc, custody_inspector=self._custody_inspector)

    def _receipt(
        self,
        req: Mapping[str, str],
        status: str,
        retcode: int,
        *,
        override_request_id: str | None = None,
        **extra: str,
    ) -> dict[str, str]:
        out = {
            "protocol": MT5_SPOOL_PROTOCOL,
            "request_id": override_request_id if override_request_id is not None else str(req.get("request_id", "")),
            "request_sha256": str(req.get("request_sha256", "")),
            "monotonic_nonce": str(req.get("monotonic_nonce", "0")),
            "status": status,
            "retcode": str(retcode),
            "position_ticket": "0",
            "deal_ticket": "0",
            "volume": "0",
            "price": "0",
            "sl": "0",
            "tp": "0",
            "server": self.server,
            "account_trade_mode": self.trade_mode,
            "observed_at": _iso(self._clock()),
            "message": "",
        }
        out.update(extra)
        _, channel_key, _ = self._channel_hmac_key_and_id()
        out["receipt_hmac_sha256"] = _spool_hmac_hex(channel_key, _canonical_spool_receipt_hmac_input(out))
        return out

    def _deal_ticket(self) -> str:
        self._next_deal += 1
        return str(self._next_deal)

    def _execute(self, req: Mapping[str, str], *, filename_request_id: str | None = None) -> dict[str, str]:
        req_id = str(req.get("request_id", ""))
        eff_rid = filename_request_id if filename_request_id is not None else req_id
        # 1. Exact filename-to-JSON request_id equality (Finding [9])
        if not req_id or (filename_request_id is not None and req_id != filename_request_id):
            return self._receipt(req, "REJECTED", 10013, override_request_id=eff_rid, message="request_id filename mismatch")
        # 2. Core SHA-256 integrity
        core = {k: v for k, v in req.items() if k not in ("request_sha256", "request_hmac_sha256")}
        if req.get("protocol") != MT5_SPOOL_PROTOCOL or _sha256_flat(core) != req.get("request_sha256"):
            return self._receipt(req, "REJECTED", 10013, message="request hash mismatch")
        # 3. Per-channel HMAC key & channel_key_id binding (Findings [7] & [9])
        master_key, channel_key, expected_key_id = self._channel_hmac_key_and_id()
        if str(req.get("channel_key_id", "")) != expected_key_id:
            return self._receipt(req, "REJECTED", 10017, message="channel_key_id mismatch")
        expected_mac = _spool_hmac_hex(channel_key, _canonical_spool_request_hmac_input(req))
        actual_mac = str(req.get("request_hmac_sha256", "")).lower()
        if len(actual_mac) != 64 or not hmac.compare_digest(expected_mac, actual_mac):
            return self._receipt(req, "REJECTED", 10013, message="request hmac mismatch")
        # 4. Full EA sink context binding (Finding [9]): channel, account_login, normalized server, execution_mode
        if str(req.get("broker_channel", "")).strip().lower() != self.broker_channel:
            return self._receipt(req, "REJECTED", 10017, message="broker_channel binding mismatch")
        if str(req.get("account_login", "")).strip() != str(self.login):
            return self._receipt(req, "REJECTED", 10017, message="account_login binding mismatch")
        if str(req.get("server", "")).strip().casefold() != self.server.strip().casefold():
            return self._receipt(req, "REJECTED", 10017, message="server binding mismatch")
        if str(req.get("execution_mode", "")).strip().upper() != self.execution_mode:
            return self._receipt(req, "REJECTED", 10017, message="execution_mode binding mismatch")
        # 5. Request TTL check (read-only, before nonce mutation)
        try:
            exp_dt = _parse_iso(req.get("expires_at"), "expires_at")
            if self._clock() > exp_dt:
                return self._receipt(req, "REJECTED", 10013, message="request expired")
        except Exception:
            return self._receipt(req, "REJECTED", 10013, message="invalid expires_at")
        # 6. Independent short-lived signed Valve admission verification (Finding [7])
        try:
            valve_key = _load_or_create_valve_admission_key(
                self.spool_dir,
                key_dir=self.key_dir,
                valve_key_file=self.valve_key_file,
                custody_inspector=self._custody_inspector,
            )
        except Exception:
            return self._receipt(req, "REJECTED", 10017, message="valve admission key unavailable")
        valve_ok, valve_reason = verify_spool_valve_admission(
            req, valve_key_bytes=valve_key, now=self._clock(), spool_master_key=master_key
        )
        if not valve_ok:
            return self._receipt(req, "REJECTED", 10017, message=valve_reason[:60])
        # 7. Per-channel monotonic nonce + global replay domain (Finding [9], fail-closed persistence)
        if not self._replay_ledger_healthy:
            return self._receipt(req, "REJECTED", 10013, message="replay ledger persistence failed")
        nonce_raw = str(req.get("monotonic_nonce", ""))
        if not nonce_raw.isdigit() or int(nonce_raw) <= 0:
            return self._receipt(req, "REJECTED", 10013, message="invalid monotonic_nonce")
        try:
            _, global_seen = self._global_replay_ledger.load()
            chan_nonce, chan_seen = self._replay_ledger.load()
        except (Mt5TransportError, OSError):
            self._replay_ledger_healthy = False
            return self._receipt(req, "REJECTED", 10013, message="replay ledger persistence failed")
        if int(nonce_raw) <= chan_nonce or req_id in chan_seen[-512:] or req_id in global_seen:
            return self._receipt(req, "REJECTED", 10013, message="replayed nonce or request_id")
        try:
            self._replay_ledger.verify_and_record(request_id=req_id, nonce=int(nonce_raw))
            self._global_replay_ledger.verify_and_record_global_id(request_id=req_id)
        except Mt5SpoolReplayError:
            return self._receipt(req, "REJECTED", 10013, message="replayed nonce or request_id")
        except (Mt5TransportError, OSError):
            self._replay_ledger_healthy = False
            return self._receipt(req, "REJECTED", 10013, message="replay ledger persistence failed")
        if not self.connected:
            return self._receipt(req, "REJECTED", 10031, message=STATUS_BROKER_OFFLINE)
        action = req["action"]
        symbol = req["symbol"]
        if symbol not in self.quotes:
            return self._receipt(req, "REJECTED", 10013, message="unknown symbol")
        bid, ask = self.quotes[symbol]
        sl = Decimal(req["sl"]) if req["sl"] != "0" else None
        tp = Decimal(req.get("tp", "0")) if req.get("tp", "0") != "0" else None
        if action == "OPEN":
            side = Side(req["side"])
            lots = Decimal(req["volume"])
            if lots <= Decimal("0") or lots > self._max_lots:
                return self._receipt(req, "REJECTED", 10014, message="invalid or oversized open volume")
            price = ask if side is Side.BUY else bid
            if sl is None or (side is Side.BUY and sl >= bid) or (side is Side.SELL and sl <= ask):
                return self._receipt(req, "REJECTED", 10016, message="invalid stops")
            if tp is not None and ((side is Side.BUY and tp <= ask) or (side is Side.SELL and tp >= bid)):
                return self._receipt(req, "REJECTED", 10016, message="invalid take profit")
            units = self._calc.lots_to_units(lots, symbol=symbol)
            required = self._calc.required_margin(symbol, side, units, self.quotes)
            free = self.balance + self._floating() - self._used_margin()
            if required > free:
                return self._receipt(req, "REJECTED", 10019, message="no money")
            ticket = str(self._next_ticket)
            self._next_ticket += 1
            deal_t = self._deal_ticket()
            t_utc = _iso(self._clock())
            req_comment = str(req.get("comment") or req_id)[:60]
            self._history_orders.append({
                "order_ticket": ticket, "request_id": req_comment, "symbol": symbol, "time_utc": t_utc,
            })
            self._history_deals.append({
                "deal_ticket": deal_t, "order_ticket": ticket, "request_id": req_comment, "symbol": symbol, "time_utc": t_utc,
            })
            self._positions[ticket] = {"symbol": symbol, "side": side, "volume": lots, "price_open": price, "sl": sl, "tp": tp}
            return self._receipt(
                req, "FILLED", 10009, position_ticket=ticket, deal_ticket=deal_t,
                volume=decimal_text(lots), price=decimal_text(price), sl=decimal_text(sl),
                tp="0" if tp is None else decimal_text(tp),
            )
        ticket = req["position_ticket"]
        pos = self._positions.get(ticket)
        if pos is None or pos["symbol"] != symbol:
            return self._receipt(req, "REJECTED", 10036, message="position not found")
        if action == "AMEND_STOP":
            eff_sl = sl if sl is not None else pos["sl"]
            eff_tp = tp if tp is not None else pos.get("tp")
            if eff_sl is None and eff_tp is None:
                return self._receipt(req, "REJECTED", 10016, message="missing stops")
            if eff_sl is not None and ((pos["side"] is Side.BUY and eff_sl >= bid) or (pos["side"] is Side.SELL and eff_sl <= ask)):
                return self._receipt(req, "REJECTED", 10016, message="invalid stops")
            if eff_tp is not None and ((pos["side"] is Side.BUY and eff_tp <= ask) or (pos["side"] is Side.SELL and eff_tp >= bid)):
                return self._receipt(req, "REJECTED", 10016, message="invalid take profit")
            pos["sl"] = eff_sl
            pos["tp"] = eff_tp
            return self._receipt(
                req, "MODIFIED", 10009, position_ticket=ticket,
                sl="0" if eff_sl is None else decimal_text(eff_sl),
                tp="0" if eff_tp is None else decimal_text(eff_tp),
            )
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
        deal_t = self._deal_ticket()
        ord_t = str(self._next_ticket)
        self._next_ticket += 1
        t_utc = _iso(self._clock())
        req_comment = str(req.get("comment") or req_id)[:60]
        self._history_orders.append({
            "order_ticket": ord_t, "request_id": req_comment, "symbol": symbol, "time_utc": t_utc,
        })
        self._history_deals.append({
            "deal_ticket": deal_t, "order_ticket": ord_t, "request_id": req_comment, "symbol": symbol, "time_utc": t_utc,
        })
        return self._receipt(
            req, "FILLED", 10009, position_ticket=ticket, deal_ticket=deal_t,
            volume=decimal_text(lots), price=decimal_text(price),
        )

    def process_pending(self) -> int:
        count = 0
        for path in sorted(self.spool_dir.glob("order_request_*.json")):
            fname = path.name
            filename_id = fname[len("order_request_"):-len(".json")]
            req = _read_spool_json(path, custody_inspector=self._custody_inspector)
            if type(req) is not dict or any(type(v) is not str for v in req.values()):
                raise Mt5TransportError("emulator received a malformed request")
            receipt = self._execute(req, filename_request_id=filename_id)
            _atomic_write_json(
                self.spool_dir / f"order_receipt_{filename_id}.json",
                receipt,
                custody_inspector=self._custody_inspector,
            )
            path.unlink()
            self.processed.append(filename_id)
            count += 1
        return count

    def publish_order_history(self, *, complete: bool = True, observed_at: datetime | None = None) -> dict[str, Any]:
        """Publish signed order_history.json for cryptographic reconciliation tests."""
        existed = os.path.lexists(self.spool_dir)
        if existed:
            apply_verified_directory_mode(
                self.spool_dir, 0o700, custody_inspector=self._custody_inspector, newly_created=False
            )
        else:
            verify_spool_path_custody(self.spool_dir, inspector=self._custody_inspector, check_ancestors=True)
            self.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            apply_verified_directory_mode(
                self.spool_dir, 0o700, custody_inspector=self._custody_inspector, newly_created=True
            )
        _, ch_key, key_id = self._channel_hmac_key_and_id()
        obs = self._clock() if observed_at is None else observed_at
        doc = sign_mt5_order_history_doc(
            {
                "protocol": MT5_SPOOL_PROTOCOL,
                "broker_channel": self.broker_channel,
                "channel_key_id": key_id,
                "execution_mode": self.execution_mode,
                "account_login": str(self.login),
                "server": self.server,
                "account_trade_mode": self.trade_mode,
                "connected": bool(self.connected),
                "complete": bool(self.connected and complete),
                "open_position_tickets": sorted(self._positions.keys()) if self.connected else [],
                "orders": list(self._history_orders) if self.connected else [],
                "deals": list(self._history_deals) if self.connected else [],
            },
            broker_channel=self.broker_channel,
            channel_key=ch_key,
            channel_key_id=key_id,
            observed_at=obs,
            custody_inspector=self._custody_inspector,
        )
        _atomic_write_json(self.spool_dir / "order_history.json", doc, custody_inspector=self._custody_inspector)
        return doc

    def sleep_hook(self, _seconds: float) -> None:
        """Drop-in replacement for ``time.sleep`` inside :class:`Mt5SpoolBridgeTransport` tests."""
        self.process_pending()
        self.publish_market()


SimMt5SpoolEa = Mt5SpoolPaperTerminalEmulator


# ---------------------------------------------------------------------------
# Valve clearance
# ---------------------------------------------------------------------------


def require_valve_clearance(
    order: OrderIntent,
    decision: Any,
    *,
    expected_weights_sha256: str,
    now: datetime | None = None,
    require_risk_reducing: bool = False,
) -> ValveDecision:
    """Refuse execution unless ``decision`` is a genuine gate-minted admitted ForexMetaValveGate decision bound to this order."""
    if not isinstance(decision, ValveDecision):
        raise Mt5ValveClearanceError("ForexMetaValveGate pre-clearance is mandatory before any MT5/OANDA execution")
    try:
        decision.verify_provenance(expected_weights_sha256=expected_weights_sha256, now=now)
    except ValveGrantError as exc:
        raise Mt5ValveClearanceError(str(exc), decision=decision) from None
    if not decision.admitted or decision.valve_mode != "ADMIT" or decision.hard_veto or not decision.mlp_admitted:
        raise Mt5ValveClearanceError(
            f"ForexMetaValveGate did not admit this order ({decision.valve_mode})", decision=decision
        )
    if decision.mlp_score < decision.threshold:
        raise Mt5ValveClearanceError("ForexMetaValveGate score below threshold", decision=decision)
    if decision.weights_sha256 != expected_weights_sha256:
        raise Mt5ValveClearanceError("ValveDecision was produced by different Valve weights", decision=decision)
    if require_risk_reducing and order.kind not in MANAGEMENT_ACTION_KINDS:
        raise Mt5ValveClearanceError(
            f"Management path refuses non-risk-reducing action {order.kind.value!r}", decision=decision
        )
    try:
        decision.assert_binds_order(
            action_ref=order.action_ref,
            action_kind=order.kind,
            symbol=order.symbol,
            side=order.side,
            quantity_units=order.quantity_units,
            stop_price=order.stop_price,
            take_profit_price=order.take_profit_price,
            limit_price=order.limit_price,
            position_ticket=order.position_ticket,
        )
    except ValveGrantError as exc:
        raise Mt5ValveClearanceError(str(exc), decision=decision) from None
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
    reconciliation_required: bool = False
    post_fill_refresh_error: str | None = None

    @property
    def accepted(self) -> bool:
        if self.receipt is not None:
            return self.receipt.accepted
        return self.oanda_receipt is not None and self.oanda_receipt.get("status") in (
            "FILLED", "CREATED", "MODIFIED", "CLOSED", "REDUCED"
        )


class Mt5MutationJournal:
    """Durable SQLite WAL pre-dispatch intent & reconciliation latch for MT5 orders/amendments (Finding [5])."""

    def __init__(self, db_path: str | Path | None = None, *, recover_on_open: bool = True) -> None:
        self._path = Path(db_path) if db_path is not None else None
        self._memory: dict[str, dict[str, str | None]] = {}
        self._initialized = False
        if self._path is not None and recover_on_open and self._path.exists():
            self.recover_pending_as_unknown()

    @property
    def db_path(self) -> Path | None:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        if self._path is None:
            raise ContractError("in-memory Mt5MutationJournal has no SQLite path")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if not self._initialized:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mt5_mutation_journal (
                    request_id TEXT PRIMARY KEY,
                    broker_id TEXT NOT NULL,
                    account_login INTEGER NOT NULL,
                    server TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    action_kind TEXT NOT NULL,
                    position_ticket TEXT,
                    semantic_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    order_ticket TEXT,
                    deal_ticket TEXT,
                    error_detail TEXT,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )
            self._initialized = True
        return conn

    def recover_pending_as_unknown(self, *, now_utc: str | None = None) -> int:
        ts_str = now_utc or _iso(_utc_now())
        if self._path is None:
            promoted = 0
            for row in self._memory.values():
                if row["status"] == "PENDING_DISPATCH":
                    row["status"] = "OUTCOME_UNKNOWN"
                    row["error_detail"] = row["error_detail"] or "RECOVERED_CRASH_LEFT_PENDING_DISPATCH"
                    row["updated_at_utc"] = ts_str
                    promoted += 1
            return promoted
        if not self._path.exists():
            return 0
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE mt5_mutation_journal "
                "SET status = 'OUTCOME_UNKNOWN', "
                "    error_detail = COALESCE(error_detail, 'RECOVERED_CRASH_LEFT_PENDING_DISPATCH'), "
                "    updated_at_utc = ? "
                "WHERE status = 'PENDING_DISPATCH'",
                (ts_str,),
            )
            promoted = int(cur.rowcount or 0)
            conn.commit()
            return promoted
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def unknown_mutations(
        self,
        *,
        broker_id: str | None = None,
        account_login: int | None = None,
        server: str | None = None,
        symbol: str | None = None,
        position_ticket: str | None = None,
        semantic_key: str | None = None,
    ) -> list[dict[str, Any]]:
        if self._path is None:
            out = [
                dict(v)
                for v in self._memory.values()
                if v["status"] in ("OUTCOME_UNKNOWN", "PENDING_DISPATCH")
            ]
        elif not self._path.exists():
            out = []
        else:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT request_id, broker_id, account_login, server, symbol, action_kind, "
                    "position_ticket, semantic_key, status, order_ticket, deal_ticket, error_detail, "
                    "created_at_utc, updated_at_utc "
                    "FROM mt5_mutation_journal "
                    "WHERE status IN ('OUTCOME_UNKNOWN', 'PENDING_DISPATCH') "
                    "ORDER BY created_at_utc ASC"
                ).fetchall()
            finally:
                conn.close()
            out = [
                {
                    "request_id": str(r[0]),
                    "broker_id": str(r[1]),
                    "account_login": int(r[2]),
                    "server": str(r[3]),
                    "symbol": str(r[4]),
                    "action_kind": str(r[5]),
                    "position_ticket": r[6],
                    "semantic_key": str(r[7]),
                    "status": str(r[8]),
                    "order_ticket": r[9],
                    "deal_ticket": r[10],
                    "error_detail": r[11],
                    "created_at_utc": str(r[12]),
                    "updated_at_utc": str(r[13]),
                }
                for r in rows
            ]
        matched: list[dict[str, Any]] = []
        for r in out:
            if broker_id is not None and r["broker_id"] != broker_id:
                continue
            if account_login is not None and int(r["account_login"]) != int(account_login):
                continue
            if server is not None and r["server"] != server:
                continue
            if symbol is None and position_ticket is None and semantic_key is None:
                matched.append(r)
            elif (
                (symbol is not None and r["symbol"] == symbol)
                or (position_ticket is not None and r.get("position_ticket") == position_ticket)
                or (semantic_key is not None and r.get("semantic_key") == semantic_key)
            ):
                matched.append(r)
        return matched

    def list_unresolved_mutations(self) -> list[dict[str, Any]]:
        """Enumerate ALL unresolved (OUTCOME_UNKNOWN / PENDING_DISPATCH) MT5 mutations across all venues & symbols."""
        return self.unknown_mutations(
            broker_id=None, account_login=None, server=None, symbol=None, position_ticket=None, semantic_key=None
        )

    def has_any_unresolved_mutation(self) -> bool:
        """True when ANY unresolved MT5 mutation exists across any broker, account, or symbol (Finding [1])."""
        return bool(self.list_unresolved_mutations())

    def require_global_clear(self, *, context: str = "NEW_RISK") -> None:
        """Fail closed if ANY unresolved mutation exists anywhere in the MT5 journal (Finding [1])."""
        frozen = self.list_unresolved_mutations()
        if frozen:
            ids = ", ".join(f"{x['broker_id']}:{x['symbol']}:{x['request_id']}({x['status']})" for x in frozen[:4])
            raise Mt5OutcomeUnknownError(
                f"BARBELL_UNRESOLVED_MUTATION_LATCH ({context}): unresolved MT5 mutation(s) [{ids}] "
                f"block all new-risk dispatches until reconciled"
            )

    def require_clear(
        self,
        *,
        broker_id: str | None = None,
        account_login: int | None = None,
        server: str | None = None,
        symbol: str | None = None,
        position_ticket: str | None = None,
        semantic_key: str | None = None,
    ) -> None:
        frozen = self.unknown_mutations(
            broker_id=broker_id,
            account_login=account_login,
            server=server,
            symbol=symbol,
            position_ticket=position_ticket,
            semantic_key=semantic_key,
        )
        if frozen:
            ids = ", ".join(f"{x['request_id']}({x['status']})" for x in frozen[:4])
            raise Mt5OutcomeUnknownError(
                f"MT5_OUTCOME_UNKNOWN_FREEZE: unresolved {broker_id} ({account_login}@{server}) mutation(s) "
                f"[{ids}] must be reconciled before new dispatches"
            )

    def record_pending(
        self,
        *,
        request_id: str,
        broker_id: str,
        account_login: int,
        server: str,
        symbol: str,
        action_kind: str,
        position_ticket: str | None,
        semantic_key: str,
        now_utc: str,
    ) -> None:
        is_risk_reducing = str(action_kind).upper() in ("CLOSE", "REDUCE", "AMEND_STOP")
        if self._path is None:
            if not is_risk_reducing:
                self.require_global_clear(context=str(action_kind))
            else:
                targeted = [
                    row
                    for row in self.unknown_mutations(
                        broker_id=broker_id, account_login=account_login, server=server
                    )
                    if row.get("semantic_key") == semantic_key
                    or (position_ticket is not None and row.get("position_ticket") == position_ticket)
                ]
                if targeted:
                    ids = ", ".join(f"{x['request_id']}({x['status']})" for x in targeted[:4])
                    raise Mt5OutcomeUnknownError(
                        f"MT5_OUTCOME_UNKNOWN_FREEZE: unresolved {broker_id} mutation(s) on target position [{ids}]"
                    )
            if request_id in self._memory:
                raise Mt5OutcomeUnknownError(
                    f"Duplicate MT5 request_id={request_id!r} (status={self._memory[request_id]['status']}); never resubmitted"
                )
            self._memory[request_id] = {
                "request_id": request_id,
                "broker_id": broker_id,
                "account_login": int(account_login),
                "server": server,
                "symbol": symbol,
                "action_kind": action_kind,
                "position_ticket": position_ticket,
                "semantic_key": semantic_key,
                "status": "PENDING_DISPATCH",
                "order_ticket": None,
                "deal_ticket": None,
                "error_detail": None,
                "created_at_utc": now_utc,
                "updated_at_utc": now_utc,
            }
            return
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not is_risk_reducing:
                frozen = conn.execute(
                    "SELECT request_id, status, broker_id, symbol FROM mt5_mutation_journal "
                    "WHERE status IN ('OUTCOME_UNKNOWN', 'PENDING_DISPATCH')",
                ).fetchall()
            else:
                frozen = conn.execute(
                    "SELECT request_id, status, broker_id, symbol FROM mt5_mutation_journal "
                    "WHERE broker_id = ? AND account_login = ? AND server = ? "
                    "AND status IN ('OUTCOME_UNKNOWN', 'PENDING_DISPATCH') "
                    "AND (semantic_key = ? OR (position_ticket IS NOT NULL AND position_ticket = ?))",
                    (broker_id, int(account_login), server, semantic_key, position_ticket or ""),
                ).fetchall()
            if frozen:
                conn.rollback()
                ids = ", ".join(f"{r[2]}:{r[3]}:{r[0]}({r[1]})" for r in frozen[:4])
                prefix = "BARBELL_UNRESOLVED_MUTATION_LATCH" if not is_risk_reducing else "MT5_OUTCOME_UNKNOWN_FREEZE"
                raise Mt5OutcomeUnknownError(
                    f"{prefix}: unresolved mutation(s) [{ids}] must be reconciled before new dispatches"
                )
            existing = conn.execute(
                "SELECT status FROM mt5_mutation_journal WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                conn.rollback()
                raise Mt5OutcomeUnknownError(
                    f"Duplicate MT5 request_id={request_id!r} (status={existing[0]}); never resubmitted"
                )
            conn.execute(
                "INSERT INTO mt5_mutation_journal ("
                "request_id, broker_id, account_login, server, symbol, action_kind, position_ticket, "
                "semantic_key, status, order_ticket, deal_ticket, error_detail, created_at_utc, updated_at_utc"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_DISPATCH', NULL, NULL, NULL, ?, ?)",
                (
                    request_id, broker_id, int(account_login), server, symbol, action_kind,
                    position_ticket, semantic_key, now_utc, now_utc,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def mark_outcome(
        self,
        *,
        request_id: str,
        status: str,
        now_utc: str,
        order_ticket: str | None = None,
        deal_ticket: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        if status not in ("CONFIRMED_FILLED", "CONFIRMED_REJECTED", "CONFIRMED_ABSENT", "OUTCOME_UNKNOWN"):
            raise ContractError(f"invalid MT5 journal status {status!r}")
        if self._path is None:
            row = self._memory.get(request_id)
            if row is not None:
                row["status"] = status
                row["order_ticket"] = order_ticket
                row["deal_ticket"] = deal_ticket
                row["error_detail"] = error_detail
                row["updated_at_utc"] = now_utc
            return
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE mt5_mutation_journal "
                "SET status = ?, order_ticket = ?, deal_ticket = ?, error_detail = ?, updated_at_utc = ? "
                "WHERE request_id = ?",
                (status, order_ticket, deal_ticket, error_detail, now_utc, request_id),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()


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
        mutation_journal: Mt5MutationJournal | None = None,
    ) -> None:
        if broker_id not in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            raise ContractError("Mt5PaperBrokerVenue serves HUGOSWAY_MT5 or LHFX_MT5 only")
        if not isinstance(credentials, Mt5Credentials) or credentials.broker_id != broker_id:
            raise ContractError("credentials must be Mt5Credentials for the same broker")
        self.broker_id = broker_id
        self._credentials = credentials
        self._transport = transport
        self._valve_gate: ForexMetaValveGate | None = valve_gate
        self._valve_sha = _expected_valve_sha(valve_gate, expected_valve_weights_sha256)
        self._calc = margin_calculator or Mt5MarginCalculator(leverage=BROKER_SPECS[broker_id].max_leverage)
        self._min_level = decimal_value(min_post_trade_margin_level_pct, "min_post_trade_margin_level_pct", positive=True)
        self._max_lots = decimal_value(max_volume_lots, "max_volume_lots", positive=True)
        self._deviation = deviation_points
        self._magic = magic
        self._clock = clock or _utc_now
        self._audit = _AuditChain()
        self._account: Mt5AccountSnapshot | None = None
        self._last_connected_account: Mt5AccountSnapshot | None = None
        self._positions: tuple[Mt5Position, ...] = ()
        self._request_counter = 0
        self._mutation_journal = mutation_journal if mutation_journal is not None else Mt5MutationJournal()
        if self._credentials.execution_mode == EXECUTION_MODE_LIVE and self._mutation_journal.db_path is None:
            raise ContractError(
                "MT5_LIVE_REQUIRES_DURABLE_MUTATION_JOURNAL: LIVE MT5 execution requires a persistent SQLite Mt5MutationJournal"
            )

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
    def is_offline(self) -> bool:
        return self._account is not None and not self._account.connected

    @property
    def last_connected_account(self) -> Mt5AccountSnapshot | None:
        return self._last_connected_account

    def _apply_account_snapshot(
        self,
        snap: Mt5AccountSnapshot,
        positions: tuple[Mt5Position, ...] | None = None,
    ) -> Mt5AccountSnapshot:
        if snap.connected:
            if snap.balance > Decimal("0") or snap.equity > Decimal("0") or self._last_connected_account is not None:
                self._last_connected_account = snap
            self._account = snap
            if positions is not None:
                self._positions = positions
            return snap
        if (
            self._last_connected_account is not None
            and snap.balance == Decimal("0")
            and snap.equity == Decimal("0")
            and (self._last_connected_account.balance > Decimal("0") or self._last_connected_account.equity > Decimal("0"))
        ):
            self._account = Mt5AccountSnapshot(
                server=snap.server,
                login=snap.login,
                currency=snap.currency,
                balance=self._last_connected_account.balance,
                equity=self._last_connected_account.equity,
                margin=self._last_connected_account.margin,
                margin_free=self._last_connected_account.margin_free,
                leverage=snap.leverage,
                trade_mode=snap.trade_mode,
                connected=False,
            )
        else:
            self._account = snap
        if positions:
            self._positions = positions
        return self._account

    @property
    def positions(self) -> tuple[Mt5Position, ...]:
        return self._positions

    @property
    def margin_calculator(self) -> Mt5MarginCalculator:
        return self._calc

    @property
    def min_margin_level_pct(self) -> Decimal:
        return self._min_level

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
            self._calc = Mt5MarginCalculator(
                leverage=self._calc.leverage,
                account_currency=snap.currency,
                contract_size=self._calc.contract_size,
                index_leverage=self._calc.index_leverage,
                index_contract_size=self._calc.index_contract_size,
                gold_contract_size=self._calc.gold_contract_size,
                symbol_contract_sizes=self._calc.symbol_contract_sizes,
            )
        applied = self._apply_account_snapshot(snap, self._transport.positions())
        self._audit.append("MT5_CONNECTED", self._clock(), {
            "broker_id": self.broker_id,
            "transport": self.transport_name,
            "account": applied.to_wire_dict(),
            "valve_weights_sha256": self._valve_sha,
        })
        return applied

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
        ap_fn = getattr(self._transport, "account_and_positions", None)
        if callable(ap_fn):
            account, positions = ap_fn()
        else:
            account = self._transport.account_info()
            positions = self._transport.positions()
        return self._apply_account_snapshot(account, positions)

    def execute(
        self,
        order: OrderIntent | RiskIncreasingOrderIntent | RiskReducingOrderIntent,
        *,
        valve_decision: ValveDecision | None = None,
        quote_guard: Callable[[str, Mt5Tick], None] | None = None,
        margin_guard: Callable[[Mt5MarginCheck, Mt5AccountSnapshot], None] | None = None,
        valve_grant: ValveOrderGrant | None = None,
        allowed_actions: frozenset[ActionKind] | None = None,
        require_risk_reducing: bool = False,
    ) -> Mt5ExecutionResult:
        """Valve clearance -> quotes -> ``quote_guard`` -> margin check -> ``margin_guard`` -> grant -> send.

        Every guard runs strictly before anything is sent, so a guard refusal is always safe to
        route elsewhere. A failure after sending raises :class:`Mt5OutcomeUnknownError`.
        """
        if isinstance(order, RiskReducingOrderIntent):
            require_risk_reducing = True
        order = _unwrap_order_intent(order)
        if allowed_actions is not None and order.kind not in allowed_actions:
            raise ContractError(
                f"{self.broker_id} refused action {order.kind.value!r}; allowed={[a.value for a in sorted(allowed_actions, key=lambda x: x.value)]}"
            )
        if require_risk_reducing and order.kind not in MANAGEMENT_ACTION_KINDS:
            raise ContractError(
                f"{self.broker_id} management path refused risk-increasing action {order.kind.value!r}"
            )
        if self._account is None:
            raise Mt5PreDispatchTransportError(f"{self.broker_id} venue is not connected")
        if self.is_offline:
            try:
                refreshed = self._transport.account_info()
                self._apply_account_snapshot(refreshed)
            except (Mt5TransportError, OSError) as exc:
                raise Mt5PreDispatchTransportError(
                    f"{self.broker_id} terminal is offline ({STATUS_BROKER_OFFLINE}): {type(exc).__name__}"
                ) from None
            if self.is_offline:
                raise Mt5PreDispatchTransportError(
                    f"{self.broker_id} terminal is offline and disconnected: {STATUS_BROKER_OFFLINE}"
                )
        now = self._clock()
        if valve_grant is not None and valve_decision is None:
            if not isinstance(valve_grant, ValveOrderGrant) or not valve_grant.risk_reducing or order.kind not in MANAGEMENT_ACTION_KINDS:
                raise Mt5ValveClearanceError(
                    "Non-protective execution requires an admitted ForexMetaValveGate ValveDecision"
                )
            decision: ValveDecision | None = None
            valve_mode_label = "PROTECTIVE_GRANT"
            valve_sha = valve_grant.decision_sha256
        else:
            decision = require_valve_clearance(
                order,
                valve_decision,
                expected_weights_sha256=self._valve_sha,
                now=now,
                require_risk_reducing=require_risk_reducing,
            )
            valve_mode_label = decision.valve_mode
            valve_sha = sha256(canonical_bytes(decision.to_dict())).hexdigest()
        if self._credentials.execution_mode == EXECUTION_MODE_LIVE:
            if self._credentials.live_auth_context is None:
                raise LiveAuthorizationError(
                    f"LIVE dispatch on {self.broker_id} refused: missing verified LiveAuthorizationContext"
                )
            self._credentials.live_auth_context.verify_provenance(
                now=now,
                reverify_ticket=True,
                require_arm_phrase=True,
            )
            self._credentials.live_auth_context.assert_valid_at(
                now,
                expected_broker_id=self.broker_id,
                expected_account_id=str(self._credentials.login),
                expected_server=self._credentials.server,
                require_arm_phrase=True,
                reverify_ticket=True,
            )
        margin_check: Mt5MarginCheck | None = None
        request_id = self._next_request_id(order)
        comment = f"cas-{request_id[-27:]}"[:31]
        v_channel = self.broker_id.lower()
        v_login = str(self._credentials.login)
        v_srv = self._credentials.server
        v_mode = self._credentials.execution_mode
        if order.kind is ActionKind.OPEN:
            side = order.side
            units = order.quantity_units
            if side is None or units is None or order.stop_price is None:
                raise ContractError("OPEN requires side, quantity and protective stop")
            lots = self._calc.units_to_lots(units, symbol=order.symbol)
            if lots > self._max_lots:
                raise Mt5MarginRefusalError(f"OPEN volume {decimal_text(lots)} lots exceeds venue cap {decimal_text(self._max_lots)}")
            try:
                quotes = self._quotes_for(order.symbol)
            except (Mt5PreDispatchTransportError, Mt5SnapshotIntegrityError, LiveAuthorizationError, LiveBrokerEndpointForbiddenError):
                raise
            except (Mt5TransportError, OSError) as exc:
                raise Mt5PreDispatchTransportError(
                    f"{self.broker_id} pre-dispatch quote read failed: {type(exc).__name__}"
                ) from None
            bid, ask = quotes[order.symbol]
            if quote_guard is not None:
                quote_guard(self.broker_id, Mt5Tick(symbol=order.symbol, bid=bid, ask=ask, time_msc="0"))
            if side is Side.BUY and order.stop_price >= bid:
                raise ContractError("BUY protective stop must be below the current bid")
            if side is Side.SELL and order.stop_price <= ask:
                raise ContractError("SELL protective stop must be above the current ask")
            if order.take_profit_price is not None:
                if side is Side.BUY and order.take_profit_price <= ask:
                    raise ContractError("BUY resting take_profit_price must be above the current ask")
                if side is Side.SELL and order.take_profit_price >= bid:
                    raise ContractError("SELL resting take_profit_price must be below the current bid")
            price = ask if side is Side.BUY else bid
            if order.limit_price is not None:
                if side is Side.BUY and price > order.limit_price:
                    raise Mt5MarginRefusalError("current ask exceeds the BUY limit price; not sent")
                if side is Side.SELL and price < order.limit_price:
                    raise Mt5MarginRefusalError("current bid is below the SELL limit price; not sent")
            try:
                account = self._apply_account_snapshot(self._transport.account_info())
            except (Mt5PreDispatchTransportError, Mt5SnapshotIntegrityError, LiveAuthorizationError, LiveBrokerEndpointForbiddenError):
                raise
            except (Mt5TransportError, OSError) as exc:
                raise Mt5PreDispatchTransportError(
                    f"{self.broker_id} pre-dispatch account_info read failed: {type(exc).__name__}"
                ) from None
            if not account.connected:
                raise Mt5PreDispatchTransportError(
                    f"{self.broker_id} terminal is offline and disconnected: {STATUS_BROKER_OFFLINE}"
                )
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
                take_profit=order.take_profit_price,
            valve_decision_sha256=valve_sha, broker_channel=v_channel, account_login=v_login, server=v_srv, execution_mode=v_mode)
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
                eff_stop = order.stop_price if order.stop_price is not None else pos.stop_loss
                eff_tp = order.take_profit_price if order.take_profit_price is not None else pos.take_profit
                if eff_stop is None and eff_tp is None:
                    raise ContractError("AMEND_STOP requires stop_price and/or take_profit_price")
                if eff_stop is not None:
                    if pos.side is Side.BUY and eff_stop >= tick.bid:
                        raise ContractError("BUY position stop must stay below the current bid")
                    if pos.side is Side.SELL and eff_stop <= tick.ask:
                        raise ContractError("SELL position stop must stay above the current ask")
                if eff_tp is not None:
                    if pos.side is Side.BUY and eff_tp <= tick.ask:
                        raise ContractError("BUY resting take_profit_price must stay above the current ask")
                    if pos.side is Side.SELL and eff_tp >= tick.bid:
                        raise ContractError("SELL resting take_profit_price must stay below the current bid")
                request = Mt5OrderRequest(
                    request_id=request_id, action="AMEND_STOP", symbol=order.symbol, side=pos.side, volume_lots=None,
                    price=None, stop_loss=eff_stop, position_ticket=ticket,
                    deviation_points=self._deviation, magic=self._magic, comment=comment, created_at=now,
                    take_profit=eff_tp,
                valve_decision_sha256=valve_sha, broker_channel=v_channel, account_login=v_login, server=v_srv, execution_mode=v_mode)
            else:
                if order.kind is ActionKind.CLOSE:
                    lots = pos.volume_lots
                    if order.quantity_units is not None and self._calc.units_to_lots(order.quantity_units, symbol=order.symbol) != lots:
                        raise ContractError("CLOSE quantity must equal the full MT5 position volume")
                else:
                    lots = self._calc.units_to_lots(order.quantity_units, symbol=order.symbol)  # type: ignore[arg-type]
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
                valve_decision_sha256=valve_sha, broker_channel=v_channel, account_login=v_login, server=v_srv, execution_mode=v_mode)
        if hasattr(self._transport, "prepare_request"):
            try:
                request = self._transport.prepare_request(request)
            except (Mt5PreDispatchTransportError, Mt5SnapshotIntegrityError, LiveAuthorizationError, LiveBrokerEndpointForbiddenError):
                raise
            except (Mt5TransportError, OSError) as exc:
                raise Mt5PreDispatchTransportError(
                    f"{self.broker_id} pre-dispatch request preparation failed: {type(exc).__name__}"
                ) from None
        if isinstance(self._transport, Mt5SpoolBridgeTransport):
            request = sign_spool_valve_admission(
                request,
                spool_dir=self._transport.spool_dir,
                key_dir=self._transport.key_dir,
                valve_key_file=self._transport.valve_key_file,
                expires_at=request.expires_at,
                custody_inspector=self._transport._custody_inspector,
            )
        grant_now = self._clock()
        if valve_grant is not None:
            eff_grant = valve_grant
        else:
            if self._valve_gate is None or decision is None:
                raise Mt5ValveClearanceError(
                    f"{self.broker_id} cannot mint single-use ValveOrderGrant without a bound ForexMetaValveGate"
                )
            eff_grant = self._valve_gate.issue_order_grant(
                decision,
                broker_id=self.broker_id,
                account_id=str(self._credentials.login),
                server=self._credentials.server,
                execution_mode=self._credentials.execution_mode,
                action_kind=request.action,
                symbol=request.symbol,
                side=request.side.value,
                volume=request.volume_lots,
                stop_loss=request.stop_loss,
                take_profit=request.take_profit,
                position_ticket=request.position_ticket,
                order_action_ref=order.action_ref,
                order_quantity_units=order.quantity_units,
                order_side=order.side,
                order_stop_price=order.stop_price,
                order_take_profit_price=order.take_profit_price,
                order_limit_price=order.limit_price,
                require_risk_reducing=require_risk_reducing,
                now=grant_now,
            )
        now_utc_str = _iso(grant_now)
        sem_key = (
            f"{order.kind.value}|{self.broker_id}|{self._credentials.login}|{self._credentials.server}|"
            f"{order.symbol}|{request.position_ticket or ''}"
        )
        self._mutation_journal.record_pending(
            request_id=request.request_id,
            broker_id=self.broker_id,
            account_login=int(self._credentials.login),
            server=self._credentials.server,
            symbol=order.symbol,
            action_kind=order.kind.value,
            position_ticket=request.position_ticket,
            semantic_key=sem_key,
            now_utc=now_utc_str,
        )
        try:
            receipt = self._transport.send_order(
                request,
                valve_grant=eff_grant,
                require_risk_reducing=require_risk_reducing,
                now=grant_now,
            )
        except (LiveAuthorizationError, ValveRefusalError, Mt5PreDispatchTransportError) as pre_exc:
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="CONFIRMED_ABSENT",
                now_utc=_iso(self._clock()),
                error_detail=type(pre_exc).__name__,
            )
            raise
        except Mt5OutcomeUnknownError as exc:
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="OUTCOME_UNKNOWN",
                now_utc=_iso(self._clock()),
                error_detail=str(exc)[:240],
            )
            self._audit.append("MT5_OUTCOME_UNKNOWN", self._clock(), {
                "broker_id": self.broker_id, "order_id": order.order_id, "request": request.to_spool_dict(),
            })
            raise
        except (Mt5TransportError, OSError) as exc:
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="OUTCOME_UNKNOWN",
                now_utc=_iso(self._clock()),
                error_detail=type(exc).__name__,
            )
            self._audit.append("MT5_OUTCOME_UNKNOWN", self._clock(), {
                "broker_id": self.broker_id, "order_id": order.order_id, "request": request.to_spool_dict(),
            })
            raise Mt5OutcomeUnknownError(
                f"{self.broker_id} send failed after dispatch ({type(exc).__name__}); outcome UNKNOWN, never resubmitted"
            ) from None
        if receipt.request_id != request.request_id or receipt.request_sha256 != request.request_sha256:
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="OUTCOME_UNKNOWN",
                now_utc=_iso(self._clock()),
                error_detail="RECEIPT_REQUEST_BINDING_MISMATCH",
            )
            raise Mt5OutcomeUnknownError("receipt does not bind the submitted request; outcome UNKNOWN")
        if receipt.status == "UNKNOWN":
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="OUTCOME_UNKNOWN",
                now_utc=_iso(self._clock()),
                error_detail="EA_REPORTED_UNKNOWN",
            )
            self._audit.append("MT5_OUTCOME_UNKNOWN", self._clock(), {
                "broker_id": self.broker_id, "order_id": order.order_id, "receipt": receipt.to_wire_dict(),
            })
            raise Mt5OutcomeUnknownError(f"{self.broker_id} EA reported outcome UNKNOWN for {request.request_id}")
        if receipt.status == "REJECTED" and receipt.position_ticket is None and receipt.deal_ticket is None:
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="CONFIRMED_REJECTED",
                now_utc=_iso(self._clock()),
                error_detail=str(receipt.message or receipt.retcode),
            )
        else:
            self._mutation_journal.mark_outcome(
                request_id=request.request_id,
                status="CONFIRMED_FILLED",
                now_utc=_iso(self._clock()),
                order_ticket=None if receipt.position_ticket is None else str(receipt.position_ticket),
                deal_ticket=None if receipt.deal_ticket is None else str(receipt.deal_ticket),
            )
        # Finding [4]: Separate confirmed dispatch outcome from post-fill account/position refresh.
        # Once a valid non-rejected receipt is committed as CONFIRMED_FILLED, post-fill refresh failures
        # must NEVER escape as failover-eligible transport errors or reroute the order to sibling venues.
        reconciliation_required = False
        refresh_errors: list[str] = []
        account_after: Mt5AccountSnapshot | None = None
        positions_after: tuple[Mt5Position, ...] = self._positions
        try:
            refreshed_account = self._transport.account_info()
            self._account = refreshed_account
            account_after = refreshed_account
        except Exception as exc:
            reconciliation_required = True
            refresh_errors.append(f"account_info:{type(exc).__name__}")
            logger.warning(
                "%s post-fill account_info refresh failed after confirmed receipt %s (%s); reconciliation required",
                self.broker_id,
                request.request_id,
                type(exc).__name__,
            )
        try:
            refreshed_positions = self._transport.positions()
            self._positions = refreshed_positions
            positions_after = refreshed_positions
        except Exception as exc:
            reconciliation_required = True
            refresh_errors.append(f"positions:{type(exc).__name__}")
            logger.warning(
                "%s post-fill positions refresh failed after confirmed receipt %s (%s); reconciliation required",
                self.broker_id,
                request.request_id,
                type(exc).__name__,
            )
        post_fill_err = ";".join(refresh_errors) if refresh_errors else None
        record = self._audit.append("MT5_ORDER_RECEIPT", self._clock(), {
            "broker_id": self.broker_id,
            "order_id": order.order_id,
            "action_ref": order.action_ref,
            "kind": order.kind.value,
            "valve_mode": valve_mode_label,
            "valve_weights_sha256": decision.weights_sha256,
            "request": request.to_spool_dict(),
            "receipt": receipt.to_wire_dict(),
            "margin_check": None if margin_check is None else margin_check.to_wire_dict(),
            "account_after": None if account_after is None else account_after.to_wire_dict(),
            "positions_after": [p.to_wire_dict() for p in positions_after],
            "reconciliation_required": reconciliation_required,
            "post_fill_refresh_error": post_fill_err,
        })
        return Mt5ExecutionResult(
            broker_id=self.broker_id,
            order=order,
            request=request,
            receipt=receipt,
            oanda_receipt=None,
            account_after=account_after,
            positions_after=positions_after,
            margin_check=margin_check,
            valve_mode=valve_mode_label,
            audit_record=record,
            reconciliation_required=reconciliation_required,
            post_fill_refresh_error=post_fill_err,
        )

    @property
    def mutation_journal(self) -> Mt5MutationJournal:
        return self._mutation_journal

    def reconcile_unknown_mutations(
        self,
        *,
        terminal_history_fn: Callable[[int, str], Mapping[str, Any]] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Reconcile MT5 OUTCOME_UNKNOWN / PENDING_DISPATCH latches strictly against verified terminal order/deal history."""
        ts_str = _iso(self._clock() if now is None else utc_time(now, "now"))
        login = int(self._credentials.login)
        srv = self._credentials.server
        unknowns = self._mutation_journal.unknown_mutations(
            broker_id=self.broker_id, account_login=login, server=srv
        )
        if not unknowns:
            return {"broker_id": self.broker_id, "checked": 0, "resolved": 0, "remaining_unknown": 0, "complete": True}
        hist_fn = terminal_history_fn or getattr(self._transport, "order_deal_history", None)
        if not callable(hist_fn):
            return {
                "broker_id": self.broker_id,
                "checked": len(unknowns),
                "resolved": 0,
                "remaining_unknown": len(unknowns),
                "complete": False,
                "reason": "NO_TERMINAL_HISTORY_SOURCE",
            }
        history = hist_fn(login, srv)
        if not isinstance(history, Mapping):
            return {
                "broker_id": self.broker_id,
                "checked": len(unknowns),
                "resolved": 0,
                "remaining_unknown": len(unknowns),
                "complete": False,
                "reason": "MALFORMED_TERMINAL_HISTORY",
            }
        exact_account_match = (
            int(history.get("account_login", -1)) == login
            and str(history.get("server", "")) == srv
            and bool(history.get("complete") is True)
            and isinstance(history.get("orders"), (list, tuple))
            and isinstance(history.get("deals"), (list, tuple))
        )
        matched_by_req: dict[str, tuple[str | None, str | None]] = {}
        if isinstance(history.get("orders"), (list, tuple)):
            for o in history["orders"]:
                if isinstance(o, Mapping):
                    rid = str(o.get("request_id") or "").strip()
                    if rid:
                        matched_by_req[rid] = (
                            None if o.get("order_ticket") is None else str(o["order_ticket"]),
                            None if o.get("deal_ticket") is None else str(o["deal_ticket"]),
                        )
        if isinstance(history.get("deals"), (list, tuple)):
            for d in history["deals"]:
                if isinstance(d, Mapping):
                    rid = str(d.get("request_id") or "").strip()
                    if rid:
                        prev = matched_by_req.get(rid, (None, None))
                        matched_by_req[rid] = (
                            prev[0] or (None if d.get("order_ticket") is None else str(d["order_ticket"])),
                            None if d.get("deal_ticket") is None else str(d["deal_ticket"]),
                        )
        has_open_tickets_field = isinstance(history.get("open_position_tickets"), (list, tuple))
        open_pos_set = {str(x) for x in (history.get("open_position_tickets") or [])}
        unmatched_sym_times: list[tuple[str, datetime | None]] = []
        for entry_list in (history.get("orders"), history.get("deals")):
            if isinstance(entry_list, (list, tuple)):
                for item in entry_list:
                    if not isinstance(item, Mapping):
                        continue
                    item_rid = str(item.get("request_id") or "").strip()
                    item_sym_raw = str(item.get("symbol") or "").strip()
                    if not item_sym_raw:
                        continue
                    try:
                        item_sym = normalize_market_symbol(item_sym_raw)
                    except ContractError:
                        item_sym = item_sym_raw.upper()
                    t_dt: datetime | None = None
                    raw_t = item.get("time_utc")
                    if isinstance(raw_t, str) and raw_t.strip():
                        try:
                            t_dt = _parse_iso(raw_t, "time_utc")
                        except ContractError:
                            t_dt = None
                    if not item_rid:
                        unmatched_sym_times.append((item_sym, t_dt))

        resolved = 0
        for row in unknowns:
            rid = str(row["request_id"])
            comment_key = f"cas-{rid[-27:]}"[:31]
            match_key = rid if rid in matched_by_req else (comment_key if comment_key in matched_by_req else None)
            if match_key is not None and int(history.get("account_login", -1)) == login and str(history.get("server", "")) == srv:
                ot, dt = matched_by_req[match_key]
                self._mutation_journal.mark_outcome(
                    request_id=rid, status="CONFIRMED_FILLED", now_utc=ts_str, order_ticket=ot, deal_ticket=dt
                )
                resolved += 1
            elif exact_account_match:
                action_k = str(row.get("action_kind") or "").upper()
                pos_tkt = str(row.get("position_ticket") or "").strip()
                if action_k in ("AMEND_STOP", "CLOSE", "REDUCE") and pos_tkt:
                    if has_open_tickets_field and pos_tkt in open_pos_set:
                        self._mutation_journal.mark_outcome(
                            request_id=rid,
                            status="OUTCOME_UNKNOWN",
                            now_utc=ts_str,
                            error_detail="TARGET_POSITION_STILL_OPEN_UNCONFIRMED",
                        )
                    else:
                        self._mutation_journal.mark_outcome(
                            request_id=rid,
                            status="CONFIRMED_ABSENT",
                            now_utc=ts_str,
                            error_detail=(
                                "RECONCILED_TARGET_POSITION_CLOSED_IN_EXACT_MT5_HISTORY"
                                if has_open_tickets_field
                                else "RECONCILED_ABSENT_IN_EXACT_MT5_HISTORY"
                            ),
                        )
                        resolved += 1
                else:
                    row_sym = str(row.get("symbol") or "").upper()
                    ambiguous_same_sym = False
                    try:
                        row_created = _parse_iso(row.get("created_at_utc"), "created_at_utc")
                    except ContractError:
                        row_created = None
                    if row_sym and row_created is not None:
                        win_lo = row_created - timedelta(seconds=60)
                        win_hi = row_created + timedelta(seconds=600)
                        for u_sym, u_dt in unmatched_sym_times:
                            if u_sym == row_sym and u_dt is not None and win_lo <= u_dt <= win_hi:
                                ambiguous_same_sym = True
                                break
                    if ambiguous_same_sym:
                        self._mutation_journal.mark_outcome(
                            request_id=rid,
                            status="OUTCOME_UNKNOWN",
                            now_utc=ts_str,
                            error_detail="AMBIGUOUS_UNMATCHED_SYMBOL_ORDER_IN_WINDOW",
                        )
                    else:
                        self._mutation_journal.mark_outcome(
                            request_id=rid,
                            status="CONFIRMED_ABSENT",
                            now_utc=ts_str,
                            error_detail="RECONCILED_ABSENT_IN_EXACT_MT5_HISTORY",
                        )
                        resolved += 1
            else:
                self._mutation_journal.mark_outcome(
                    request_id=rid,
                    status="OUTCOME_UNKNOWN",
                    now_utc=ts_str,
                    error_detail="RECONCILIATION_INCOMPLETE_OR_ACCOUNT_MISMATCH",
                )
        remaining = len(
            self._mutation_journal.unknown_mutations(broker_id=self.broker_id, account_login=login, server=srv)
        )
        return {
            "broker_id": self.broker_id,
            "checked": len(unknowns),
            "resolved": resolved,
            "remaining_unknown": remaining,
            "complete": exact_account_match,
        }

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
        summary_max_age_seconds: float = DEFAULT_OANDA_SUMMARY_MAX_AGE_SECONDS,
    ) -> None:
        if not isinstance(client, OandaPracticePaperClient):
            raise ContractError("OandaPracticeFallbackVenue requires an OandaPracticePaperClient")
        if not isinstance(summary_max_age_seconds, (int, float)) or isinstance(summary_max_age_seconds, bool) or summary_max_age_seconds <= 0:
            raise ContractError("summary_max_age_seconds must be a positive finite number")
        self.broker_id = BROKER_OANDA_LIVE if client.execution_mode == EXECUTION_MODE_LIVE else BROKER_OANDA_PRACTICE
        self._client = client
        self._valve_gate: ForexMetaValveGate | None = valve_gate
        self._valve_sha = _expected_valve_sha(valve_gate, expected_valve_weights_sha256)
        self._clock = clock or _utc_now
        self._audit = _AuditChain()
        self._summary: dict[str, Any] | None = None
        self._summary_observed_at: datetime | None = None
        self._summary_max_age_seconds = float(summary_max_age_seconds)
        self._positions: tuple[Mt5Position, ...] = ()
        self._open_trades: tuple[dict[str, Any], ...] = ()
        self._position_units: dict[str, Decimal] = {}
        self._calc = Mt5MarginCalculator(leverage=50)

    def __repr__(self) -> str:
        return f"OandaPracticeFallbackVenue(connected={self._summary is not None})"

    @property
    def server(self) -> str:
        return self._client.base_url

    @property
    def client(self) -> OandaPracticePaperClient:
        return self._client

    @property
    def mutation_journal(self) -> OandaMutationJournal:
        return self._client._mutation_journal

    @property
    def summary(self) -> dict[str, Any] | None:
        return self._summary

    @property
    def summary_observed_at(self) -> datetime | None:
        return self._summary_observed_at

    @property
    def summary_max_age_seconds(self) -> float:
        return self._summary_max_age_seconds

    def is_summary_fresh(self, *, now: datetime | None = None, max_age_seconds: float | None = None) -> bool:
        """Return True only when cached OANDA summary exists and observed_at is within the strict freshness TTL."""
        if self._summary is None or self._summary_observed_at is None:
            return False
        check_now = self._clock() if now is None else utc_time(now, "now")
        ttl = self._summary_max_age_seconds if max_age_seconds is None else float(max_age_seconds)
        if ttl <= 0:
            return False
        age = (check_now - self._summary_observed_at).total_seconds()
        return -5.0 <= age <= ttl

    def require_fresh_summary(self, *, now: datetime | None = None, max_age_seconds: float | None = None) -> dict[str, Any]:
        """Fail closed if OANDA account summary is missing or older than the freshness TTL (Finding [3])."""
        if not self.is_summary_fresh(now=now, max_age_seconds=max_age_seconds):
            raise Mt5TransportError(
                f"{self.broker_id} account summary missing or stale beyond freshness TTL; refusing admission"
            )
        return dict(self._summary)  # type: ignore[arg-type]

    def probe_account_summary(
        self,
        *,
        now: datetime | None = None,
        max_age_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Fetch a fresh OANDA NAV/margin summary with explicit observed_at & TTL enforcement (Finding [3])."""
        if not self._client.is_active:
            self._summary_observed_at = None
            raise Mt5TransportError(f"{self.broker_id} client is inactive")
        ts = self._clock() if now is None else utc_time(now, "now")
        ttl = self._summary_max_age_seconds if max_age_seconds is None else float(max_age_seconds)
        if ttl <= 0:
            raise ContractError("max_age_seconds must be positive")
        try:
            summary = self._client.fetch_account_summary(now=ts)
        except Exception:
            self._summary_observed_at = None
            raise
        if not isinstance(summary, Mapping) or "observed_at" not in summary:
            self._summary_observed_at = None
            raise Mt5TransportError(f"{self.broker_id} account summary missing observed_at")
        obs_dt = _parse_iso(summary["observed_at"], "observed_at")
        age = (ts - obs_dt).total_seconds()
        if age > ttl or age < -5.0:
            self._summary_observed_at = None
            raise Mt5TransportError(
                f"{self.broker_id} account summary stale (age={age:.2f}s > ttl={ttl:.2f}s); failing closed"
            )
        # Validate NAV and margin_available parse cleanly as Decimals
        parse_decimal(str(summary["nav"]), "nav")
        parse_decimal(str(summary["margin_available"]), "margin_available")
        self._summary = dict(summary)
        self._summary_observed_at = obs_dt
        return dict(summary)

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
        summary = self.probe_account_summary(now=self._clock())
        self._audit.append("OANDA_CONNECTED", self._clock(), {"broker_id": self.broker_id, "summary": summary})
        return summary

    def open_trades(self, *, now: datetime | None = None, refresh: bool = True) -> tuple[dict[str, Any], ...]:
        """Fetch and cache authoritative open OANDA trades (Finding [12])."""
        if self._summary is None:
            raise Mt5TransportError(f"{self.broker_id} venue is not connected")
        if refresh:
            ts = self._clock() if now is None else utc_time(now, "now")
            trades = self._client.fetch_open_trades(now=ts)
            positions: list[Mt5Position] = []
            units_map: dict[str, Decimal] = {}
            for tr in trades:
                tid = str(tr["trade_id"])
                sym = str(tr["symbol"])
                units_dec = parse_decimal(str(tr["units"]), "units")
                units_map[tid] = units_dec
                csize = self._calc.contract_size_for(sym)
                with localcontext() as ctx:
                    ctx.prec = 40
                    lots_dec = (units_dec / csize).normalize()
                positions.append(
                    Mt5Position(
                        ticket=tid,
                        symbol=sym,
                        side=Side(str(tr["side"])),
                        volume_lots=lots_dec,
                        price_open=parse_decimal(str(tr["price"]), "price"),
                        stop_loss=(
                            None
                            if tr.get("stop_loss_price") is None
                            else parse_decimal(str(tr["stop_loss_price"]), "stop_loss_price")
                        ),
                        profit=parse_decimal(str(tr["unrealized_pnl"]), "unrealized_pnl"),
                        take_profit=(
                            None
                            if tr.get("take_profit_price") is None
                            else parse_decimal(str(tr["take_profit_price"]), "take_profit_price")
                        ),
                    )
                )
            self._open_trades = tuple(dict(tr) for tr in trades)
            self._positions = tuple(positions)
            self._position_units = units_map
        return self._open_trades

    def positions(self, *, now: datetime | None = None, refresh: bool = True) -> tuple[Mt5Position, ...]:
        """Return open OANDA positions mapped to typed Mt5Position snapshots (Finding [12])."""
        if refresh:
            self.open_trades(now=now, refresh=True)
        return self._positions

    def position_units(self, ticket: str) -> Decimal | None:
        """Exact base units for an open OANDA trade_id (no lot-rounding loss)."""
        return self._position_units.get(str(ticket))

    def symbol_quote(self, symbol: str, *, now: datetime | None = None) -> tuple[Decimal, Decimal]:
        """Fetch a fresh (bid, ask) quote for ``symbol`` via OANDA pricing."""
        ts = self._clock() if now is None else utc_time(now, "now")
        norm = str(symbol).strip().upper()
        snap = self._client.fetch_pricing(pairs=(norm,), now=ts)
        for q in snap.quotes:
            if q.symbol == norm:
                return q.bid, q.ask
        raise Mt5TransportError(f"OANDA pricing missing quote for {norm}")

    def reconcile_unknown_mutations(self, *, now: datetime | None = None, max_pages: int = 50) -> dict[str, Any]:
        ts = self._clock() if now is None else utc_time(now, "now")
        return self._client.reconcile_unknown_mutations(now=ts, max_pages=max_pages)

    def execute(
        self,
        order: OrderIntent | RiskIncreasingOrderIntent | RiskReducingOrderIntent,
        *,
        valve_decision: ValveDecision | None = None,
        valve_grant: ValveOrderGrant | None = None,
        allowed_actions: frozenset[ActionKind] | None = None,
        require_risk_reducing: bool = False,
    ) -> Mt5ExecutionResult:
        if isinstance(order, RiskReducingOrderIntent):
            require_risk_reducing = True
        order = _unwrap_order_intent(order)
        if allowed_actions is not None and order.kind not in allowed_actions:
            raise ContractError(
                f"{self.broker_id} refused action {order.kind.value!r}; allowed={[a.value for a in sorted(allowed_actions, key=lambda x: x.value)]}"
            )
        if require_risk_reducing and order.kind not in MANAGEMENT_ACTION_KINDS:
            raise ContractError(
                f"{self.broker_id} management path refused risk-increasing action {order.kind.value!r}"
            )
        if self._summary is None:
            raise Mt5TransportError("OANDA practice fallback is not connected")
        now = self._clock()
        if valve_grant is not None and valve_decision is None:
            if not isinstance(valve_grant, ValveOrderGrant) or not valve_grant.risk_reducing or order.kind not in MANAGEMENT_ACTION_KINDS:
                raise Mt5ValveClearanceError(
                    "Non-protective OANDA execution requires an admitted ForexMetaValveGate ValveDecision"
                )
            decision: ValveDecision | None = None
            valve_mode_label = "PROTECTIVE_GRANT"
        else:
            decision = require_valve_clearance(
                order,
                valve_decision,
                expected_weights_sha256=self._valve_sha,
                now=now,
                require_risk_reducing=require_risk_reducing,
            )
            valve_mode_label = decision.valve_mode
        acct_id = str(self._client.account_id or "").strip()
        if not acct_id:
            raise Mt5TransportError(f"{self.broker_id} client has no bound account_id")

        def _mint_oanda_grant(
            *,
            action_kind: str,
            side: Side | None,
            volume: Decimal | str | None,
            stop_loss: Decimal | None,
            take_profit: Decimal | None,
            position_ticket: str | None,
            req_rr: bool,
        ) -> ValveOrderGrant:
            if valve_grant is not None:
                return valve_grant
            if self._valve_gate is None or decision is None:
                raise Mt5ValveClearanceError(
                    f"{self.broker_id} cannot mint single-use ValveOrderGrant without a bound ForexMetaValveGate"
                )
            return self._valve_gate.issue_order_grant(
                decision,
                broker_id=self._client.broker_id,
                account_id=acct_id,
                server=self._client.server_host,
                execution_mode=self._client.execution_mode,
                action_kind=action_kind,
                symbol=order.symbol,
                side=side,
                volume=volume,
                stop_loss=stop_loss,
                take_profit=take_profit,
                position_ticket=position_ticket,
                order_action_ref=order.action_ref,
                order_quantity_units=order.quantity_units,
                order_side=order.side,
                order_stop_price=order.stop_price,
                order_take_profit_price=order.take_profit_price,
                order_limit_price=order.limit_price,
                require_risk_reducing=req_rr,
                now=now,
            )

        if order.kind is ActionKind.AMEND_STOP:
            tid = str(order.position_ticket)
            grant = _mint_oanda_grant(
                action_kind="AMEND_STOP",
                side=None,
                volume=None,
                stop_loss=order.stop_price,
                take_profit=order.take_profit_price,
                position_ticket=tid,
                req_rr=True,
            )
            receipt = self._client.amend_trade_protection(
                trade_id=tid,
                stop_loss_price=order.stop_price,
                take_profit_price=order.take_profit_price,
                symbol=order.symbol,
                valve_grant=grant,
                now=now,
            )
        elif order.kind is ActionKind.OPEN:
            # Finding [3]: Ensure fresh OANDA NAV & margin summary immediately before new-risk OPEN.
            self.probe_account_summary(now=now)
            grant = _mint_oanda_grant(
                action_kind="OPEN",
                side=order.side,
                volume=order.quantity_units,
                stop_loss=order.stop_price,
                take_profit=order.take_profit_price,
                position_ticket=None,
                req_rr=False,
            )
            receipt = self._client.submit_paper_market_order(
                symbol=order.symbol,
                side=order.side,  # type: ignore[arg-type]
                units=order.quantity_units,  # type: ignore[arg-type]
                client_order_id=order.order_id,
                stop_loss_price=order.stop_price,
                take_profit_price=order.take_profit_price,
                price_bound=order.limit_price,
                valve_grant=grant,
                now=now,
            )
        elif order.kind in (ActionKind.CLOSE, ActionKind.REDUCE):
            # Finding [12]: Fetch current trade state and validate symbol/ticket/units before closing/reducing.
            tid = str(order.position_ticket)
            current_trades = self.open_trades(now=now, refresh=True)
            matched = next((tr for tr in current_trades if tr["trade_id"] == tid), None)
            if matched is None:
                raise Mt5BridgeError(f"OANDA open trade {tid} not found on {self.broker_id}")
            if matched["symbol"] != order.symbol:
                raise ContractError(f"OANDA trade {tid} symbol {matched['symbol']} does not match order {order.symbol}")
            open_units = parse_decimal(str(matched["units"]), "units")
            if order.kind is ActionKind.CLOSE:
                if order.quantity_units is not None and order.quantity_units != open_units:
                    raise ContractError("OANDA CLOSE quantity must equal full open trade units")
                close_units: Decimal | str = "ALL"
            else:
                if order.quantity_units is None or not (Decimal("0") < order.quantity_units < open_units):
                    raise ContractError("OANDA REDUCE quantity must be strictly positive and below open trade units")
                close_units = order.quantity_units
            grant = _mint_oanda_grant(
                action_kind=order.kind.value,
                side=None,
                volume=close_units,
                stop_loss=None,
                take_profit=None,
                position_ticket=tid,
                req_rr=True,
            )
            receipt = self._client.close_trade(
                trade_id=tid,
                units=close_units,
                client_order_id=order.order_id,
                symbol=order.symbol,
                action_kind=order.kind.value,
                valve_grant=grant,
                now=now,
            )
        else:
            raise Mt5BridgeError(f"{order.kind.value} is not supported on {self.broker_id}")

        # Finding [3] & [12]: Immediately refresh account summary (and positions on CLOSE/REDUCE) after mutation.
        # Never discard or reroute a confirmed mutation if post-mutation refresh fails; invalidate freshness TTL instead.
        reconciliation_required = False
        refresh_errors: list[str] = []
        try:
            self.probe_account_summary(now=self._clock())
        except Exception as exc:
            self._summary_observed_at = None
            reconciliation_required = True
            refresh_errors.append(f"summary:{type(exc).__name__}")
            logger.warning(
                "%s post-mutation summary refresh failed (%s); summary invalidated until reconciled",
                self.broker_id,
                type(exc).__name__,
            )
        positions_after: tuple[Mt5Position, ...] = self._positions
        if order.kind in (ActionKind.CLOSE, ActionKind.REDUCE):
            try:
                positions_after = self.positions(now=self._clock(), refresh=True)
            except Exception as exc:
                reconciliation_required = True
                refresh_errors.append(f"open_trades:{type(exc).__name__}")
        post_err = ";".join(refresh_errors) if refresh_errors else None
        record = self._audit.append("OANDA_ORDER_RECEIPT", self._clock(), {
            "broker_id": self.broker_id,
            "order_id": order.order_id,
            "action_ref": order.action_ref,
            "kind": order.kind.value,
            "valve_mode": valve_mode_label,
            "receipt": receipt,
            "reconciliation_required": reconciliation_required,
            "post_fill_refresh_error": post_err,
        })
        return Mt5ExecutionResult(
            broker_id=self.broker_id,
            order=order,
            request=None,
            receipt=None,
            oanda_receipt=receipt,
            account_after=None,
            positions_after=positions_after,
            margin_check=None,
            valve_mode=valve_mode_label,
            audit_record=record,
            reconciliation_required=reconciliation_required,
            post_fill_refresh_error=post_err,
        )

    def shutdown(self) -> None:
        self._summary = None
        self._summary_observed_at = None
        self._positions = ()
        self._open_trades = ()
        self._position_units = {}


# ---------------------------------------------------------------------------
# Broker hierarchy router
# ---------------------------------------------------------------------------

TransportFactory = Callable[[str, str, Any], Mt5Transport]


def _spool_channel(broker_id: str) -> str:
    return broker_id.lower()


def build_default_mt5_transport(
    broker_id: str,
    mode: str,
    spool_root: str | None,
    *,
    key_dir: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Mt5Transport:
    """Pick the MT5 transport for ``mode``; evaluated only at activation time (never on import)."""
    if mode == TRANSPORT_NATIVE_PYTHON:
        return Mt5NativePythonTransport(clock=clock)
    if mode == TRANSPORT_SPOOL_BRIDGE:
        if not spool_root:
            raise Mt5NotConfiguredError(f"{ENV_MT5_SPOOL_DIR} is required for SPOOL_BRIDGE transport")
        return Mt5SpoolBridgeTransport(Path(spool_root) / _spool_channel(broker_id), key_dir=key_dir, clock=clock)
    if mode == TRANSPORT_AUTO:
        if os.name == "nt" and importlib.util.find_spec("MetaTrader5") is not None:
            return Mt5NativePythonTransport(clock=clock)
        if spool_root:
            return Mt5SpoolBridgeTransport(Path(spool_root) / _spool_channel(broker_id), key_dir=key_dir, clock=clock)
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
        oanda_mutation_journal: OandaMutationJournal | None = None,
        mt5_mutation_journal: Mt5MutationJournal | None = None,
    ) -> None:
        if not isinstance(environ, Mapping):
            raise ContractError("environ must be a key-value Mapping (never a .env file path)")
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("BrokerHierarchyRouter requires a ForexMetaValveGate; 1:500 never bypasses the Valve")
        self._env = {k: v for k, v in environ.items() if isinstance(k, str) and k.startswith("CAS_FOREX_")}
        self.execution_mode, self._live_armed = resolve_execution_mode(
            self._env,
            execution_mode=execution_mode,
            live_arm_phrase=live_arm_phrase,
            now=(clock() if clock is not None else None),
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
        state_dir_env = _env_get(self._env, "CAS_FOREX_STATE_DIR")
        state_db = (Path(state_dir_env) / "cas_forex_state.sqlite3") if state_dir_env else None
        self._oanda_mutation_journal = (
            oanda_mutation_journal
            if oanda_mutation_journal is not None
            else (OandaMutationJournal(state_db) if state_db is not None else None)
        )
        self._mt5_mutation_journal = (
            mt5_mutation_journal
            if mt5_mutation_journal is not None
            else (Mt5MutationJournal(state_db) if state_db is not None else None)
        )

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
        self._spool_root = resolve_mt5_spool_dir(self._env)
        self._spool_key_dir = _env_get(self._env, ENV_MT5_SPOOL_KEY_DIR) or None
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
                now=self._clock() if clock is not None else None,
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
                    mutation_journal=self._oanda_mutation_journal,
                    clock=self._clock,
                )
            return OandaPracticeFallbackVenue(client=client, valve_gate=self._valve_gate, clock=self._clock)
        creds = self._credentials[broker_id]
        if creds is None:
            raise Mt5NotConfiguredError(f"{broker_id} has no runtime credentials")
        if self._transport_factory is build_default_mt5_transport:
            transport = build_default_mt5_transport(
                broker_id,
                self.transport_mode,
                self._spool_root,
                key_dir=self._spool_key_dir,
                clock=self._clock,
            )
        else:
            transport = self._transport_factory(broker_id, self.transport_mode, self._spool_root)
        raw_idx_lev = str(self._env.get(ENV_INDEX_LEVERAGE, "")).strip()
        if raw_idx_lev:
            try:
                idx_lev = int(raw_idx_lev)
            except ValueError as exc:
                raise ContractError(f"{ENV_INDEX_LEVERAGE} must be an integer in 1..{MAX_DEMO_LEVERAGE}") from exc
        else:
            idx_lev = DEFAULT_MT5_INDEX_LEVERAGE
        raw_idx_csize = str(self._env.get(ENV_INDEX_CONTRACT_SIZE, "")).strip()
        idx_csize = (
            decimal_value(parse_decimal(raw_idx_csize, ENV_INDEX_CONTRACT_SIZE), ENV_INDEX_CONTRACT_SIZE, positive=True)
            if raw_idx_csize
            else MT5_INDEX_CONTRACT_SIZE
        )
        sym_csizes: dict[str, Decimal] = {}
        for env_sym, env_var in (
            ("SPX500", ENV_SPX500_CONTRACT_SIZE),
            ("NAS100", ENV_NAS100_CONTRACT_SIZE),
            ("US30", ENV_US30_CONTRACT_SIZE),
        ):
            raw_sym_csize = str(self._env.get(env_var, "")).strip()
            if raw_sym_csize:
                sym_csizes[env_sym] = decimal_value(
                    parse_decimal(raw_sym_csize, env_var), env_var, positive=True
                )
        calc = Mt5MarginCalculator(
            leverage=BROKER_SPECS[broker_id].max_leverage,
            index_leverage=idx_lev,
            index_contract_size=idx_csize,
            symbol_contract_sizes=sym_csizes or None,
        )
        return Mt5PaperBrokerVenue(
            broker_id=broker_id,
            credentials=creds,
            transport=transport,
            valve_gate=self._valve_gate,
            margin_calculator=calc,
            clock=self._clock,
            min_post_trade_margin_level_pct=self._min_level,
            mutation_journal=self._mt5_mutation_journal,
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
            if isinstance(venue, Mt5PaperBrokerVenue) and venue.is_offline:
                self._status[broker_id] = STATUS_BROKER_OFFLINE
                self._failures[broker_id] = STATUS_BROKER_OFFLINE
                logger.warning("broker %s terminal disconnected (%s); failing over", broker_id, STATUS_BROKER_OFFLINE)
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
