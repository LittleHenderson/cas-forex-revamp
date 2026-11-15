"""External live FX quote feed, practice-only paper broker client, and sealed paper venue.

Phase 5 broker-feed overlay:
1. PublicLiveFxFeedClient: fetches real spot FX bid/ask quotes (EURUSD, GBPUSD, USDJPY)
   via Python stdlib urllib/ssl from Kraken public REST Ticker with ECB/Frankfurter
   reference cross-check, strict positive bid < ask & spread bounds, canonical JSON,
   raw wire SHA-256 receipts, and Node ui/src/wire.mjs safe-integer serialization
   (all nanosecond/64-bit integers serialized as str; all amounts/rates as plain decimal str).
2. OandaPracticePaperClient: optional paper-broker REST adapter strictly pinned to
   https://api-fxpractice.oanda.com/v3 (hard-refuses api-fxtrade.oanda.com and any
   non-practice/live host), activated ONLY when explicit runtime environment variables
   CAS_FOREX_OANDA_PRACTICE_TOKEN and CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID are supplied;
   never reads .env files and never logs or reprs headers/tokens.
3. SealedLiveFeedPaperVenue: wraps SQLiteVenue so live or sealed-captured external FX
   quotes drive market ticks, OPEN/AMEND_STOP/REDUCE/CLOSE paper fills, protective stops,
   and hash-chained SQLite broker audit receipts seamlessly with CoreCoordinator,
   OperatorSession, RehearsalWiring, ForexMetaValveGate, and DecisionReadService.

Importing and constructing every class in this module is strictly inert (no network,
file, directory, thread, or subprocess side effects).
"""
from __future__ import annotations

import argparse
import base64
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Context, Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR, localcontext
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import ssl
import time
from typing import Any, Iterator
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from cas_forex_revamp.composition.application import RuntimeConfig
from cas_forex_revamp.composition.assembly import InertSimulation
from cas_forex_revamp.composition.rehearsal import RehearsalWiring
from cas_forex_revamp.contracts import (
    AccountRunKey,
    AuthorizedCommand,
    CockpitProjection,
    ContractError,
    DecisionAdapter,
    DecisionOrigin,
    FenceReceipt,
    FenceRequest,
    Instrument,
    MarketObservation,
    Money,
    Side,
    VenueLookup,
    VenueReceipt,
    VenueSnapshot,
    canonical_bytes,
    content_digest,
    decimal_text,
    parse_decimal,
    to_wire,
)
from cas_forex_revamp.contracts.primitives import decimal_value, digest, identifier, integer, utc_time
from cas_forex_revamp.core import CoreCoordinator, InstrumentPolicy, OwnerVerifier, RiskPolicy, SQLiteStore
from cas_forex_revamp.operator.decisions import OperatorSession
from .faults import FaultSchedule
from .fixtures import VenueScenario
from .sqlite_venue import JournalCheckpoint, PRICE_QUANTUM, SQLiteVenue, VenueStorageError

KRAKEN_PUBLIC_TICKER_URL = "https://api.kraken.com/0/public/Ticker?pair=EURUSD,GBPUSD,USDJPY"
FRANKFURTER_ECB_URLS: tuple[str, ...] = (
    "https://api.frankfurter.dev/v1/latest?base=EUR&symbols=USD,GBP,JPY",
    "https://api.frankfurter.app/latest?from=EUR&to=USD,GBP,JPY",
)
ECB_DAILY_XML_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"

DEFAULT_OANDA_PRACTICE_BASE_URL = "https://api-fxpractice.oanda.com/v3"
ALLOWED_OANDA_PRACTICE_HOST = "api-fxpractice.oanda.com"
ENV_OANDA_PRACTICE_TOKEN = "CAS_FOREX_OANDA_PRACTICE_TOKEN"
ENV_OANDA_PRACTICE_ACCOUNT_ID = "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID"

SUPPORTED_FX_PAIRS: tuple[str, ...] = ("EURUSD", "GBPUSD", "USDJPY")
MAX_SAFE_JS_INTEGER = (1 << 53) - 1  # 9007199254740991
MAX_WIRE_RESPONSE_BYTES = 32_768
BROKER_AUDIT_APPLICATION_ID = 0x42524B52  # "BRKR"
BROKER_AUDIT_STORAGE_VERSION = 1

_DIGITS_RE = re.compile(r"^[0-9]{1,30}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

_PAIR_METADATA: dict[str, dict[str, Any]] = {
    "EURUSD": {
        "base": "EUR",
        "quote": "USD",
        "tick": Decimal("0.00001"),
        "min_price": Decimal("0.50"),
        "max_price": Decimal("2.50"),
        "kraken_keys": ("EURUSD", "ZEURZUSD", "EUR/USD", "ZEURUSD"),
        "oanda_instrument": "EUR_USD",
    },
    "GBPUSD": {
        "base": "GBP",
        "quote": "USD",
        "tick": Decimal("0.00001"),
        "min_price": Decimal("0.50"),
        "max_price": Decimal("3.00"),
        "kraken_keys": ("GBPUSD", "ZGBPZUSD", "GBP/USD", "ZGBPUSD"),
        "oanda_instrument": "GBP_USD",
    },
    "USDJPY": {
        "base": "USD",
        "quote": "JPY",
        "tick": Decimal("0.001"),
        "min_price": Decimal("50.0"),
        "max_price": Decimal("350.0"),
        "kraken_keys": ("USDJPY", "ZUSDZJPY", "USD/JPY", "ZUSDJPY"),
        "oanda_instrument": "USD_JPY",
    },
}

_FORBIDDEN_LIVE_HOST_TOKENS: tuple[str, ...] = (
    "api-fxtrade.oanda.com",
    "stream-fxtrade.oanda.com",
    "fxtrade",
)


class LiveBrokerEndpointForbiddenError(ContractError):
    """Raised unconditionally if a live/real-money or non-practice broker host is supplied."""


class PaperBrokerNotConfiguredError(ContractError):
    """Raised when optional OANDA practice credentials were not explicitly supplied at runtime."""


class PaperBrokerTransportError(ContractError):
    """Sanitized transport failure that strips all request/response headers and credentials."""


class LiveFeedVerificationError(ContractError):
    """Raised when live or captured external FX feed data fails schema, spread, or SHA-256 checks."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Hard-refuses HTTP redirects so requests never hop hosts or leak headers."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PaperBrokerTransportError(f"HTTP redirect ({code}) refused on external broker/feed transport")


class _RedactedSecret:
    """Holds a runtime credential without ever exposing it in repr/str/formatting."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise PaperBrokerNotConfiguredError("practice token must be a non-empty string")
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            raise ContractError("practice token contains forbidden control characters")
        self._value = value.strip()

    def reveal_for_header(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "'[REDACTED]'"

    def __str__(self) -> str:
        return "[REDACTED]"


def _ns_string(value: int | str, field: str = "epoch_ns") -> str:
    text = str(value) if type(value) is int else value
    if not isinstance(text, str) or not _DIGITS_RE.fullmatch(text):
        raise ContractError(f"{field} must be a decimal integer string")
    return text


def _parse_iso_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{field} must be a non-empty ISO-8601 UTC timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} is not a valid ISO-8601 timestamp") from exc
    return utc_time(parsed, field)


def _format_utc_micros(value: datetime, field: str = "timestamp") -> str:
    checked = utc_time(value, field)
    return checked.isoformat().replace("+00:00", "Z")


def assert_safe_json_numbers(value: Any, *, path: str = "$") -> None:
    """Enforce Node ui/src/wire.mjs Number.isSafeInteger invariants recursively."""
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int:
        if not (-MAX_SAFE_JS_INTEGER <= value <= MAX_SAFE_JS_INTEGER):
            raise ContractError(
                f"{path}: integer {value} exceeds JS Number.MAX_SAFE_INTEGER; serialize 64-bit/ns values as str"
            )
        return
    if isinstance(value, float):
        raise ContractError(f"{path}: float is forbidden in canonical JSON; serialize amounts/rates as decimal str")
    if type(value) in (list, tuple):
        for idx, item in enumerate(value):
            assert_safe_json_numbers(item, path=f"{path}[{idx}]")
        return
    if type(value) is dict:
        for k, v in value.items():
            if type(k) is not str:
                raise ContractError(f"{path}: JSON object keys must be str")
            assert_safe_json_numbers(v, path=f"{path}.{k}")
        return
    raise ContractError(f"{path}: unsupported safe-JSON value type {type(value).__name__}")


def strict_safe_json_loads(raw: str | bytes, *, max_bytes: int = 524_288) -> Any:
    """Python twin of Node ui/src/wire.mjs parseUniqueJSON: unique keys, safe ints only, no floats."""
    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise ContractError("JSON payload exceeds byte limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError("JSON payload must be valid UTF-8") from exc
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > max_bytes:
            raise ContractError("JSON payload exceeds byte limit")
        text = raw
    else:
        raise ContractError("JSON payload must be str or bytes")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ContractError(f"duplicate JSON key: {k}")
            out[k] = v
        return out

    def reject_float(token: str) -> Any:
        raise ContractError(f"raw JSON float {token!r} forbidden; use plain decimal string")

    def checked_int(token: str) -> int:
        val = int(token)
        if not (-MAX_SAFE_JS_INTEGER <= val <= MAX_SAFE_JS_INTEGER):
            raise ContractError(f"raw JSON integer {token!r} exceeds Number.MAX_SAFE_INTEGER; use str")
        return val

    def reject_constant(token: str) -> Any:
        raise ContractError(f"nonfinite JSON constant {token!r} is forbidden")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_float=reject_float,
            parse_int=checked_int,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("malformed JSON payload") from exc
    assert_safe_json_numbers(parsed)
    return parsed


def _parse_external_wire_json(raw_bytes: bytes, *, label: str) -> Any:
    """Parse external HTTPS JSON response using Decimal for numbers to prevent float drift."""
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LiveFeedVerificationError(f"{label}: wire bytes are not valid UTF-8") from exc

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise LiveFeedVerificationError(f"{label}: duplicate JSON key {k!r}")
            out[k] = v
        return out

    def reject_constant(token: str) -> Any:
        raise LiveFeedVerificationError(f"{label}: nonfinite JSON constant {token!r}")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_float=Decimal,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, InvalidOperation, RecursionError) as exc:
        raise LiveFeedVerificationError(f"{label}: malformed JSON wire payload") from exc


def _validate_https_public_url(url: str, *, label: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ContractError(f"{label} must be a non-empty HTTPS URL")
    parsed = urllib.parse.urlsplit(url.strip())
    host = (parsed.hostname or "").lower()
    if any(tok in host for tok in _FORBIDDEN_LIVE_HOST_TOKENS):
        raise LiveBrokerEndpointForbiddenError(f"live trading endpoint host {host!r} is strictly forbidden")
    if parsed.scheme != "https" or not host:
        raise ContractError(f"{label} requires an explicit https:// hostname URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ContractError(f"{label} must not embed credentials or URL fragments")
    return url.strip()


def _default_https_get(url: str, timeout_seconds: float, max_bytes: int) -> bytes:
    validated_url = _validate_https_public_url(url, label="feed_url")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(
        validated_url,
        method="GET",
        headers={
            "Accept": "application/json, application/xml;q=0.9, text/xml;q=0.8",
            "User-Agent": "CAS-Forex-Revamp-Phase5-PaperFeed/1.0",
        },
    )
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                raise LiveFeedVerificationError(f"unexpected HTTP status {status} from public feed")
            body = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise LiveFeedVerificationError(f"public feed HTTP error {exc.code}") from None
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        raise LiveFeedVerificationError(f"public feed transport failure: {type(exc).__name__}") from None
    if len(body) == 0:
        raise LiveFeedVerificationError("empty response body from public feed")
    if len(body) > max_bytes:
        raise LiveFeedVerificationError(f"public feed response exceeds {max_bytes} byte cap")
    return body


def default_spot_fx_instrument(symbol: str = "EURUSD", *, instrument_id: str | None = None) -> Instrument:
    """Create a typed v1 spot FX Instrument aligned to institutional pipette ticks."""
    norm = symbol.strip().upper()
    meta = _PAIR_METADATA.get(norm)
    if meta is None:
        raise ContractError(f"unsupported FX symbol {symbol!r}; expected one of {SUPPORTED_FX_PAIRS}")
    iid = instrument_id if instrument_id is not None else norm
    return Instrument(
        instrument_id=iid,
        symbol=norm,
        base_currency=meta["base"],
        quote_currency=meta["quote"],
        price_tick=meta["tick"],
        quantity_step=Decimal("1"),
        minimum_quantity=Decimal("1"),
    )


@dataclass(frozen=True, slots=True)
class EcbReferenceCrossCheck:
    source_url: str
    reference_date: str
    fetched_at_utc: datetime
    fetched_at_ns: str
    raw_wire_sha256: str
    raw_wire_bytes_len: int
    raw_wire_base64: str
    raw_wire_utf8: str
    reference_rates: dict[str, Decimal]
    deviations_bps: dict[str, Decimal]
    max_allowed_deviation_bps: Decimal
    verified: bool

    def __post_init__(self) -> None:
        _validate_https_public_url(self.source_url, label="ecb_source_url")
        if not isinstance(self.reference_date, str) or not _DATE_RE.fullmatch(self.reference_date):
            raise ContractError("ECB reference_date must be YYYY-MM-DD")
        utc_time(self.fetched_at_utc, "ecb fetched_at_utc")
        _ns_string(self.fetched_at_ns, "ecb fetched_at_ns")
        digest(self.raw_wire_sha256, "ecb raw_wire_sha256")
        integer(self.raw_wire_bytes_len, "ecb raw_wire_bytes_len", minimum=1)
        decimal_value(self.max_allowed_deviation_bps, "max_allowed_deviation_bps", positive=True)
        if type(self.verified) is not bool or not self.verified:
            raise LiveFeedVerificationError("ECB reference cross-check must be verified=True")
        for sym, rate in self.reference_rates.items():
            if sym not in _PAIR_METADATA:
                raise ContractError(f"unexpected ECB reference symbol {sym!r}")
            decimal_value(rate, f"reference_rates[{sym}]", positive=True)
        for sym, dev in self.deviations_bps.items():
            decimal_value(dev, f"deviations_bps[{sym}]")
            if dev < Decimal("0") or dev > self.max_allowed_deviation_bps:
                raise LiveFeedVerificationError(
                    f"ECB reference cross-check failed for {sym}: deviation {dev} bps > {self.max_allowed_deviation_bps} bps"
                )

    def verify_raw_wire(self) -> None:
        try:
            raw_bytes = base64.b64decode(self.raw_wire_base64.encode("ascii"), validate=True)
        except Exception as exc:
            raise LiveFeedVerificationError("invalid base64 in ECB reference receipt") from exc
        if len(raw_bytes) != self.raw_wire_bytes_len:
            raise LiveFeedVerificationError("ECB reference byte length mismatch")
        if sha256(raw_bytes).hexdigest() != self.raw_wire_sha256:
            raise LiveFeedVerificationError("ECB reference raw_wire_sha256 mismatch")
        if raw_bytes.decode("utf-8") != self.raw_wire_utf8:
            raise LiveFeedVerificationError("ECB reference raw_wire_utf8 mismatch")

    def to_wire_dict(self) -> dict[str, Any]:
        payload = {
            "source_url": self.source_url,
            "reference_date": self.reference_date,
            "fetched_at_utc": _format_utc_micros(self.fetched_at_utc, "fetched_at_utc"),
            "fetched_at_ns": self.fetched_at_ns,
            "raw_wire_sha256": self.raw_wire_sha256,
            "raw_wire_bytes_len": self.raw_wire_bytes_len,
            "raw_wire_base64": self.raw_wire_base64,
            "raw_wire_utf8": self.raw_wire_utf8,
            "reference_rates": {k: decimal_text(v) for k, v in sorted(self.reference_rates.items())},
            "deviations_bps": {k: decimal_text(v) for k, v in sorted(self.deviations_bps.items())},
            "max_allowed_deviation_bps": decimal_text(self.max_allowed_deviation_bps),
            "verified": self.verified,
        }
        assert_safe_json_numbers(payload, path="$.ecb_cross_check")
        return payload


@dataclass(frozen=True, slots=True)
class LiveFxQuote:
    symbol: str
    source_pair_key: str
    base_currency: str
    quote_currency: str
    bid: Decimal
    ask: Decimal
    mid: Decimal
    spread: Decimal
    spread_bps: Decimal
    observed_at: datetime
    observed_at_ns: str
    last_price: Decimal | None = None
    vwap_24h: Decimal | None = None
    trades_24h: str | None = None
    reference_mid: Decimal | None = None
    reference_deviation_bps: Decimal | None = None

    def __post_init__(self) -> None:
        if self.symbol not in _PAIR_METADATA:
            raise ContractError(f"unsupported FX quote symbol {self.symbol!r}")
        identifier(self.source_pair_key, "source_pair_key")
        meta = _PAIR_METADATA[self.symbol]
        if self.base_currency != meta["base"] or self.quote_currency != meta["quote"]:
            raise ContractError(f"currency pair mismatch for {self.symbol}")
        decimal_value(self.bid, f"{self.symbol}.bid", positive=True)
        decimal_value(self.ask, f"{self.symbol}.ask", positive=True)
        if self.bid >= self.ask:
            raise LiveFeedVerificationError(
                f"{self.symbol}: require strictly positive bid < ask, got bid={self.bid} ask={self.ask}"
            )
        if not (meta["min_price"] <= self.bid < self.ask <= meta["max_price"]):
            raise LiveFeedVerificationError(
                f"{self.symbol}: quote {self.bid}/{self.ask} outside sanity corridor [{meta['min_price']}, {meta['max_price']}]"
            )
        decimal_value(self.mid, f"{self.symbol}.mid", positive=True)
        decimal_value(self.spread, f"{self.symbol}.spread", positive=True)
        decimal_value(self.spread_bps, f"{self.symbol}.spread_bps", positive=True)
        if self.spread != self.ask - self.bid:
            raise LiveFeedVerificationError(f"{self.symbol}: spread does not equal ask - bid")
        utc_time(self.observed_at, f"{self.symbol}.observed_at")
        _ns_string(self.observed_at_ns, f"{self.symbol}.observed_at_ns")
        if self.last_price is not None:
            decimal_value(self.last_price, f"{self.symbol}.last_price", positive=True)
        if self.vwap_24h is not None:
            decimal_value(self.vwap_24h, f"{self.symbol}.vwap_24h", positive=True)
        if self.trades_24h is not None:
            _ns_string(self.trades_24h, f"{self.symbol}.trades_24h")
        if self.reference_mid is not None:
            decimal_value(self.reference_mid, f"{self.symbol}.reference_mid", positive=True)
        if self.reference_deviation_bps is not None:
            decimal_value(self.reference_deviation_bps, f"{self.symbol}.reference_deviation_bps")

    def to_wire_dict(self) -> dict[str, Any]:
        payload = {
            "symbol": self.symbol,
            "source_pair_key": self.source_pair_key,
            "base_currency": self.base_currency,
            "quote_currency": self.quote_currency,
            "bid": decimal_text(self.bid),
            "ask": decimal_text(self.ask),
            "mid": decimal_text(self.mid),
            "spread": decimal_text(self.spread),
            "spread_bps": decimal_text(self.spread_bps),
            "observed_at": _format_utc_micros(self.observed_at, "observed_at"),
            "observed_at_ns": self.observed_at_ns,
            "last_price": None if self.last_price is None else decimal_text(self.last_price),
            "vwap_24h": None if self.vwap_24h is None else decimal_text(self.vwap_24h),
            "trades_24h": self.trades_24h,
            "reference_mid": None if self.reference_mid is None else decimal_text(self.reference_mid),
            "reference_deviation_bps": (
                None if self.reference_deviation_bps is None else decimal_text(self.reference_deviation_bps)
            ),
        }
        assert_safe_json_numbers(payload, path=f"$.quotes.{self.symbol}")
        return payload


def _build_live_quote(
    *,
    symbol: str,
    source_pair_key: str,
    bid: Decimal,
    ask: Decimal,
    observed_at: datetime,
    observed_at_ns: str,
    max_spread_bps: Decimal,
    last_price: Decimal | None = None,
    vwap_24h: Decimal | None = None,
    trades_24h: str | None = None,
    reference_mid: Decimal | None = None,
    max_reference_deviation_bps: Decimal | None = None,
) -> LiveFxQuote:
    meta = _PAIR_METADATA[symbol]
    decimal_value(bid, f"{symbol}.bid", positive=True)
    decimal_value(ask, f"{symbol}.ask", positive=True)
    if bid >= ask:
        raise LiveFeedVerificationError(f"{symbol}: non-positive spread (bid={bid}, ask={ask})")
    with localcontext(Context(prec=80)):
        spread = ask - bid
        mid = ((bid + ask) / Decimal("2")).quantize(PRICE_QUANTUM, rounding=ROUND_FLOOR)
        spread_bps = ((spread / mid) * Decimal("10000")).quantize(Decimal("0.0001"), rounding=ROUND_CEILING)
        if spread_bps <= Decimal("0") or spread_bps > max_spread_bps:
            raise LiveFeedVerificationError(
                f"{symbol}: spread {spread_bps} bps exceeds max_spread_bps={max_spread_bps}"
            )
        ref_dev: Decimal | None = None
        if reference_mid is not None:
            ref_dev = ((abs(mid - reference_mid) / reference_mid) * Decimal("10000")).quantize(
                Decimal("0.0001"), rounding=ROUND_CEILING
            )
            if max_reference_deviation_bps is not None and ref_dev > max_reference_deviation_bps:
                raise LiveFeedVerificationError(
                    f"{symbol}: mid {mid} deviates {ref_dev} bps from ECB reference {reference_mid} "
                    f"(max {max_reference_deviation_bps} bps)"
                )
    return LiveFxQuote(
        symbol=symbol,
        source_pair_key=source_pair_key,
        base_currency=meta["base"],
        quote_currency=meta["quote"],
        bid=bid,
        ask=ask,
        mid=mid,
        spread=spread,
        spread_bps=spread_bps,
        observed_at=observed_at,
        observed_at_ns=observed_at_ns,
        last_price=last_price,
        vwap_24h=vwap_24h,
        trades_24h=trades_24h,
        reference_mid=reference_mid,
        reference_deviation_bps=ref_dev,
    )


def _parse_kraken_ticker_bytes(
    raw_bytes: bytes,
    *,
    pairs: tuple[str, ...],
    observed_at: datetime,
    observed_at_ns: str,
    max_spread_bps: Decimal,
    reference_rates: dict[str, Decimal] | None = None,
    max_reference_deviation_bps: Decimal | None = None,
) -> dict[str, LiveFxQuote]:
    doc = _parse_external_wire_json(raw_bytes, label="kraken_ticker")
    if type(doc) is not dict:
        raise LiveFeedVerificationError("Kraken ticker response must be a JSON object")
    errors = doc.get("error")
    if type(errors) is not list or len(errors) > 0:
        raise LiveFeedVerificationError(f"Kraken ticker reported error: {errors!r}")
    result = doc.get("result")
    if type(result) is not dict or not result:
        raise LiveFeedVerificationError("Kraken ticker result object is missing or empty")

    quotes: dict[str, LiveFxQuote] = {}
    for sym in pairs:
        meta = _PAIR_METADATA.get(sym)
        if meta is None:
            raise ContractError(f"unsupported FX pair {sym!r}")
        matched_key = next((k for k in meta["kraken_keys"] if k in result), None)
        if matched_key is None:
            raise LiveFeedVerificationError(f"Kraken ticker response missing requested pair {sym}")
        entry = result[matched_key]
        if type(entry) is not dict:
            raise LiveFeedVerificationError(f"Kraken pair entry {matched_key!r} is not an object")
        ask_arr = entry.get("a")
        bid_arr = entry.get("b")
        if type(ask_arr) is not list or not ask_arr or type(bid_arr) is not list or not bid_arr:
            raise LiveFeedVerificationError(f"Kraken pair {matched_key!r} missing bid/ask arrays")
        bid = parse_decimal(str(bid_arr[0]), f"{sym}.bid")
        ask = parse_decimal(str(ask_arr[0]), f"{sym}.ask")
        last_price = None
        if type(entry.get("c")) is list and entry["c"]:
            last_price = parse_decimal(str(entry["c"][0]), f"{sym}.last_price")
        vwap_24h = None
        if type(entry.get("p")) is list and len(entry["p"]) >= 2:
            vwap_24h = parse_decimal(str(entry["p"][1]), f"{sym}.vwap_24h")
        trades_24h = None
        if type(entry.get("t")) is list and len(entry["t"]) >= 2:
            trades_24h = _ns_string(str(int(entry["t"][1])), f"{sym}.trades_24h")
        ref_mid = None if reference_rates is None else reference_rates.get(sym)
        quotes[sym] = _build_live_quote(
            symbol=sym,
            source_pair_key=matched_key,
            bid=bid,
            ask=ask,
            observed_at=observed_at,
            observed_at_ns=observed_at_ns,
            max_spread_bps=max_spread_bps,
            last_price=last_price,
            vwap_24h=vwap_24h,
            trades_24h=trades_24h,
            reference_mid=ref_mid,
            max_reference_deviation_bps=max_reference_deviation_bps,
        )
    return quotes


def _parse_ecb_reference_bytes(raw_bytes: bytes) -> tuple[str, dict[str, Decimal]]:
    stripped = raw_bytes.lstrip()
    if stripped.startswith(b"<"):
        try:
            root = ET.fromstring(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ET.ParseError) as exc:
            raise LiveFeedVerificationError("malformed ECB XML reference payload") from exc
        ref_date = None
        eur_rates: dict[str, Decimal] = {}
        for elem in root.iter():
            if elem.attrib.get("time") and ref_date is None:
                ref_date = elem.attrib["time"]
            ccy = elem.attrib.get("currency")
            rate_txt = elem.attrib.get("rate")
            if ccy in ("USD", "GBP", "JPY") and rate_txt is not None:
                eur_rates[ccy] = parse_decimal(rate_txt, f"ECB.{ccy}")
        if ref_date is None or set(eur_rates) != {"USD", "GBP", "JPY"}:
            raise LiveFeedVerificationError("ECB XML missing date or USD/GBP/JPY rates")
    else:
        doc = _parse_external_wire_json(raw_bytes, label="ecb_frankfurter")
        if type(doc) is not dict:
            raise LiveFeedVerificationError("ECB Frankfurter payload must be a JSON object")
        ref_date = doc.get("date")
        base = doc.get("base", "EUR")
        rates_obj = doc.get("rates")
        if not isinstance(ref_date, str) or type(rates_obj) is not dict:
            raise LiveFeedVerificationError("ECB Frankfurter payload missing date or rates")
        if base == "EUR":
            for ccy in ("USD", "GBP", "JPY"):
                if ccy not in rates_obj:
                    raise LiveFeedVerificationError(f"ECB Frankfurter missing {ccy}")
            eur_rates = {
                ccy: parse_decimal(format(Decimal(str(rates_obj[ccy])), "f"), f"ECB.{ccy}")
                for ccy in ("USD", "GBP", "JPY")
            }
        elif base == "USD":
            for ccy in ("EUR", "GBP", "JPY"):
                if ccy not in rates_obj:
                    raise LiveFeedVerificationError(f"ECB Frankfurter USD-base missing {ccy}")
            with localcontext(Context(prec=80)):
                eur_per_usd = Decimal(str(rates_obj["EUR"]))
                gbp_per_usd = Decimal(str(rates_obj["GBP"]))
                jpy_per_usd = Decimal(str(rates_obj["JPY"]))
                if eur_per_usd <= 0 or gbp_per_usd <= 0 or jpy_per_usd <= 0:
                    raise LiveFeedVerificationError("nonpositive ECB Frankfurter rate")
                return ref_date, {
                    "EURUSD": (Decimal("1") / eur_per_usd).quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR),
                    "GBPUSD": (Decimal("1") / gbp_per_usd).quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR),
                    "USDJPY": jpy_per_usd.quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR),
                }
        else:
            raise LiveFeedVerificationError(f"unsupported ECB reference base currency {base!r}")

    with localcontext(Context(prec=80)):
        usd = eur_rates["USD"]
        gbp = eur_rates["GBP"]
        jpy = eur_rates["JPY"]
        if usd <= 0 or gbp <= 0 or jpy <= 0:
            raise LiveFeedVerificationError("nonpositive ECB reference rate")
        pair_refs = {
            "EURUSD": usd.quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR),
            "GBPUSD": (usd / gbp).quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR),
            "USDJPY": (jpy / usd).quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR),
        }
    return ref_date, pair_refs


@dataclass(frozen=True, slots=True)
class LiveFxFeedSnapshot:
    schema_version: str
    snapshot_id: str
    provider: str
    source_url: str
    fetched_at_utc: datetime
    fetched_at_ns: str
    raw_wire_sha256: str
    raw_wire_bytes_len: int
    raw_wire_base64: str
    raw_wire_utf8: str
    max_spread_bps: Decimal
    quotes: dict[str, LiveFxQuote]
    ecb_cross_check: EcbReferenceCrossCheck | None
    canonical_payload_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != "forex.live-fx-feed-snapshot/1.0":
            raise ContractError("unsupported live FX snapshot schema_version")
        identifier(self.snapshot_id, "snapshot_id")
        identifier(self.provider, "provider")
        _validate_https_public_url(self.source_url, label="source_url")
        utc_time(self.fetched_at_utc, "fetched_at_utc")
        _ns_string(self.fetched_at_ns, "fetched_at_ns")
        digest(self.raw_wire_sha256, "raw_wire_sha256")
        integer(self.raw_wire_bytes_len, "raw_wire_bytes_len", minimum=1)
        decimal_value(self.max_spread_bps, "max_spread_bps", positive=True)
        if not self.quotes or any(not isinstance(q, LiveFxQuote) for q in self.quotes.values()):
            raise ContractError("LiveFxFeedSnapshot requires at least one verified LiveFxQuote")
        digest(self.canonical_payload_sha256, "canonical_payload_sha256")

    def _unsigned_body_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "provider": self.provider,
            "source_url": self.source_url,
            "fetched_at_utc": _format_utc_micros(self.fetched_at_utc, "fetched_at_utc"),
            "fetched_at_ns": self.fetched_at_ns,
            "raw_wire_sha256": self.raw_wire_sha256,
            "raw_wire_bytes_len": self.raw_wire_bytes_len,
            "raw_wire_base64": self.raw_wire_base64,
            "raw_wire_utf8": self.raw_wire_utf8,
            "max_spread_bps": decimal_text(self.max_spread_bps),
            "quotes": {k: self.quotes[k].to_wire_dict() for k in sorted(self.quotes)},
            "ecb_cross_check": None if self.ecb_cross_check is None else self.ecb_cross_check.to_wire_dict(),
        }
        assert_safe_json_numbers(body)
        return body

    def to_wire_dict(self) -> dict[str, Any]:
        body = self._unsigned_body_dict()
        body["canonical_payload_sha256"] = self.canonical_payload_sha256
        assert_safe_json_numbers(body)
        return body

    def to_canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_wire_dict())

    def to_canonical_json(self, *, indent: int | None = None) -> str:
        wire_obj = self.to_wire_dict()
        assert_safe_json_numbers(wire_obj)
        if indent is None:
            return self.to_canonical_bytes().decode("utf-8")
        return json.dumps(wire_obj, ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False) + "\n"

    def verify_integrity(self) -> bool:
        try:
            raw_bytes = base64.b64decode(self.raw_wire_base64.encode("ascii"), validate=True)
        except Exception as exc:
            raise LiveFeedVerificationError("invalid raw_wire_base64 in LiveFxFeedSnapshot") from exc
        if len(raw_bytes) != self.raw_wire_bytes_len:
            raise LiveFeedVerificationError("raw_wire_bytes_len mismatch against decoded wire bytes")
        if sha256(raw_bytes).hexdigest() != self.raw_wire_sha256:
            raise LiveFeedVerificationError("raw_wire_sha256 mismatch against raw wire bytes")
        try:
            decoded_utf8 = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LiveFeedVerificationError("raw wire bytes are not valid UTF-8") from exc
        if decoded_utf8 != self.raw_wire_utf8:
            raise LiveFeedVerificationError("raw_wire_utf8 mismatch against raw wire bytes")

        ref_rates: dict[str, Decimal] | None = None
        max_ref_dev: Decimal | None = None
        if self.ecb_cross_check is not None:
            self.ecb_cross_check.verify_raw_wire()
            parsed_date, parsed_refs = _parse_ecb_reference_bytes(
                base64.b64decode(self.ecb_cross_check.raw_wire_base64.encode("ascii"), validate=True)
            )
            subset_refs = {k: parsed_refs[k] for k in self.ecb_cross_check.reference_rates if k in parsed_refs}
            if parsed_date != self.ecb_cross_check.reference_date or subset_refs != self.ecb_cross_check.reference_rates:
                raise LiveFeedVerificationError("ECB reference rates differ from signed ECB wire payload")
            ref_rates = subset_refs
            max_ref_dev = self.ecb_cross_check.max_allowed_deviation_bps

        if self.provider == "kraken-public-rest-ticker":
            reparsed = _parse_kraken_ticker_bytes(
                raw_bytes,
                pairs=tuple(sorted(self.quotes)),
                observed_at=self.fetched_at_utc,
                observed_at_ns=self.fetched_at_ns,
                max_spread_bps=self.max_spread_bps,
                reference_rates=ref_rates,
                max_reference_deviation_bps=max_ref_dev,
            )
            for sym, q in self.quotes.items():
                rq = reparsed[sym]
                if (q.bid, q.ask, q.mid, q.spread, q.spread_bps, q.source_pair_key) != (
                    rq.bid,
                    rq.ask,
                    rq.mid,
                    rq.spread,
                    rq.spread_bps,
                    rq.source_pair_key,
                ):
                    raise LiveFeedVerificationError(f"stored quote for {sym} differs from signed Kraken wire bytes")
        elif self.provider == "oanda-fxpractice-v3-pricing":
            reparsed = _parse_oanda_pricing_bytes(
                raw_bytes,
                pairs=tuple(sorted(self.quotes)),
                observed_at=self.fetched_at_utc,
                observed_at_ns=self.fetched_at_ns,
                max_spread_bps=self.max_spread_bps,
            )
            for sym, q in self.quotes.items():
                rq = reparsed[sym]
                if (q.bid, q.ask, q.mid, q.spread, q.spread_bps) != (rq.bid, rq.ask, rq.mid, rq.spread, rq.spread_bps):
                    raise LiveFeedVerificationError(f"stored quote for {sym} differs from signed OANDA practice bytes")
        else:
            raise LiveFeedVerificationError(f"unknown feed provider {self.provider!r}")

        expected_digest = content_digest(self._unsigned_body_dict())
        if expected_digest != self.canonical_payload_sha256:
            raise LiveFeedVerificationError("canonical_payload_sha256 mismatch")
        strict_safe_json_loads(self.to_canonical_bytes())
        return True

    def save_json(self, path: str | Path) -> Path:
        self.verify_integrity()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload_text = self.to_canonical_json(indent=2)
        strict_safe_json_loads(payload_text)
        target.write_bytes(payload_text.encode("utf-8"))
        return target

    @classmethod
    def from_json_bytes(cls, raw: bytes | str) -> "LiveFxFeedSnapshot":
        data = strict_safe_json_loads(raw)
        if type(data) is not dict:
            raise LiveFeedVerificationError("snapshot root must be a JSON object")
        try:
            quotes_raw = data["quotes"]
            if type(quotes_raw) is not dict or not quotes_raw:
                raise LiveFeedVerificationError("quotes map must be a non-empty object")
            quotes: dict[str, LiveFxQuote] = {}
            for sym, qd in quotes_raw.items():
                quotes[sym] = LiveFxQuote(
                    symbol=qd["symbol"],
                    source_pair_key=qd["source_pair_key"],
                    base_currency=qd["base_currency"],
                    quote_currency=qd["quote_currency"],
                    bid=parse_decimal(qd["bid"], f"{sym}.bid"),
                    ask=parse_decimal(qd["ask"], f"{sym}.ask"),
                    mid=parse_decimal(qd["mid"], f"{sym}.mid"),
                    spread=parse_decimal(qd["spread"], f"{sym}.spread"),
                    spread_bps=parse_decimal(qd["spread_bps"], f"{sym}.spread_bps"),
                    observed_at=_parse_iso_utc(qd["observed_at"], f"{sym}.observed_at"),
                    observed_at_ns=qd["observed_at_ns"],
                    last_price=None if qd["last_price"] is None else parse_decimal(qd["last_price"], f"{sym}.last_price"),
                    vwap_24h=None if qd["vwap_24h"] is None else parse_decimal(qd["vwap_24h"], f"{sym}.vwap_24h"),
                    trades_24h=qd["trades_24h"],
                    reference_mid=(
                        None if qd["reference_mid"] is None else parse_decimal(qd["reference_mid"], f"{sym}.reference_mid")
                    ),
                    reference_deviation_bps=(
                        None
                        if qd["reference_deviation_bps"] is None
                        else parse_decimal(qd["reference_deviation_bps"], f"{sym}.reference_deviation_bps")
                    ),
                )
            ecb_raw = data["ecb_cross_check"]
            ecb_obj = None
            if ecb_raw is not None:
                ecb_obj = EcbReferenceCrossCheck(
                    source_url=ecb_raw["source_url"],
                    reference_date=ecb_raw["reference_date"],
                    fetched_at_utc=_parse_iso_utc(ecb_raw["fetched_at_utc"], "ecb.fetched_at_utc"),
                    fetched_at_ns=ecb_raw["fetched_at_ns"],
                    raw_wire_sha256=ecb_raw["raw_wire_sha256"],
                    raw_wire_bytes_len=ecb_raw["raw_wire_bytes_len"],
                    raw_wire_base64=ecb_raw["raw_wire_base64"],
                    raw_wire_utf8=ecb_raw["raw_wire_utf8"],
                    reference_rates={
                        k: parse_decimal(v, f"ecb.rate.{k}") for k, v in ecb_raw["reference_rates"].items()
                    },
                    deviations_bps={
                        k: parse_decimal(v, f"ecb.dev.{k}") for k, v in ecb_raw["deviations_bps"].items()
                    },
                    max_allowed_deviation_bps=parse_decimal(
                        ecb_raw["max_allowed_deviation_bps"], "ecb.max_allowed_deviation_bps"
                    ),
                    verified=ecb_raw["verified"],
                )
            snap = cls(
                schema_version=data["schema_version"],
                snapshot_id=data["snapshot_id"],
                provider=data["provider"],
                source_url=data["source_url"],
                fetched_at_utc=_parse_iso_utc(data["fetched_at_utc"], "fetched_at_utc"),
                fetched_at_ns=data["fetched_at_ns"],
                raw_wire_sha256=data["raw_wire_sha256"],
                raw_wire_bytes_len=data["raw_wire_bytes_len"],
                raw_wire_base64=data["raw_wire_base64"],
                raw_wire_utf8=data["raw_wire_utf8"],
                max_spread_bps=parse_decimal(data["max_spread_bps"], "max_spread_bps"),
                quotes=quotes,
                ecb_cross_check=ecb_obj,
                canonical_payload_sha256=data["canonical_payload_sha256"],
            )
        except KeyError as exc:
            raise LiveFeedVerificationError(f"missing required field in LiveFxFeedSnapshot: {exc}") from exc
        snap.verify_integrity()
        return snap

    @classmethod
    def load_json(cls, path: str | Path) -> "LiveFxFeedSnapshot":
        return cls.from_json_bytes(Path(path).read_bytes())

    def to_market_observation(
        self,
        symbol: str,
        *,
        key: AccountRunKey,
        instrument_id: str,
        sequence: int,
        price_tick: Decimal | None = None,
        observed_at: datetime | None = None,
        available_at: datetime | None = None,
        event_id: str | None = None,
        align_to_tick: bool = True,
    ) -> MarketObservation:
        norm = symbol.strip().upper()
        quote = self.quotes.get(norm)
        if quote is None:
            raise ContractError(f"symbol {norm!r} not present in LiveFxFeedSnapshot")
        obs_time = self.fetched_at_utc if observed_at is None else utc_time(observed_at, "observed_at")
        avail_time = obs_time if available_at is None else utc_time(available_at, "available_at")
        bid, ask = quote.bid, quote.ask
        if price_tick is not None and align_to_tick:
            decimal_value(price_tick, "price_tick", positive=True)
            with localcontext(Context(prec=80)):
                bid = (bid / price_tick).to_integral_value(rounding=ROUND_FLOOR) * price_tick
                ask = (ask / price_tick).to_integral_value(rounding=ROUND_CEILING) * price_tick
                if bid <= Decimal("0") or bid >= ask:
                    raise LiveFeedVerificationError("tick alignment collapsed positive bid < ask invariant")
        eid = event_id if event_id is not None else f"live-{norm.lower()}-{self.raw_wire_sha256[:12]}-{sequence}"
        return MarketObservation(
            key=key,
            event_id=eid,
            instrument_id=instrument_id,
            sequence=sequence,
            observed_at=obs_time,
            available_at=avail_time,
            bid=bid,
            ask=ask,
        )


def _assemble_snapshot(
    *,
    provider: str,
    source_url: str,
    fetched_at_utc: datetime,
    fetched_at_ns: str,
    raw_bytes: bytes,
    max_spread_bps: Decimal,
    quotes: dict[str, LiveFxQuote],
    ecb_cross_check: EcbReferenceCrossCheck | None,
) -> LiveFxFeedSnapshot:
    raw_sha = sha256(raw_bytes).hexdigest()
    raw_b64 = base64.b64encode(raw_bytes).decode("ascii")
    raw_utf8 = raw_bytes.decode("utf-8")
    snap_id = f"livefx-{raw_sha[:24]}"
    temp = LiveFxFeedSnapshot(
        schema_version="forex.live-fx-feed-snapshot/1.0",
        snapshot_id=snap_id,
        provider=provider,
        source_url=source_url,
        fetched_at_utc=fetched_at_utc,
        fetched_at_ns=fetched_at_ns,
        raw_wire_sha256=raw_sha,
        raw_wire_bytes_len=len(raw_bytes),
        raw_wire_base64=raw_b64,
        raw_wire_utf8=raw_utf8,
        max_spread_bps=max_spread_bps,
        quotes=quotes,
        ecb_cross_check=ecb_cross_check,
        canonical_payload_sha256="0" * 64,
    )
    payload_sha = content_digest(temp._unsigned_body_dict())
    final = LiveFxFeedSnapshot(
        schema_version=temp.schema_version,
        snapshot_id=temp.snapshot_id,
        provider=temp.provider,
        source_url=temp.source_url,
        fetched_at_utc=temp.fetched_at_utc,
        fetched_at_ns=temp.fetched_at_ns,
        raw_wire_sha256=temp.raw_wire_sha256,
        raw_wire_bytes_len=temp.raw_wire_bytes_len,
        raw_wire_base64=temp.raw_wire_base64,
        raw_wire_utf8=temp.raw_wire_utf8,
        max_spread_bps=temp.max_spread_bps,
        quotes=temp.quotes,
        ecb_cross_check=temp.ecb_cross_check,
        canonical_payload_sha256=payload_sha,
    )
    final.verify_integrity()
    return final


class PublicLiveFxFeedClient:
    """Inert stdlib HTTPS client for Kraken spot FX quotes + ECB/Frankfurter reference cross-check."""

    def __init__(
        self,
        *,
        kraken_ticker_url: str = KRAKEN_PUBLIC_TICKER_URL,
        ecb_reference_urls: tuple[str, ...] = (*FRANKFURTER_ECB_URLS, ECB_DAILY_XML_URL),
        cross_check_ecb: bool = True,
        max_spread_bps: Decimal = Decimal("500"),
        max_reference_deviation_bps: Decimal = Decimal("500"),
        timeout_seconds: float = 10.0,
        max_wire_bytes: int = MAX_WIRE_RESPONSE_BYTES,
        transport: Callable[[str, float, int], bytes] | None = None,
    ) -> None:
        self.kraken_ticker_url = _validate_https_public_url(kraken_ticker_url, label="kraken_ticker_url")
        if type(ecb_reference_urls) is not tuple or (cross_check_ecb and not ecb_reference_urls):
            raise ContractError("ecb_reference_urls must be a non-empty tuple when cross_check_ecb=True")
        for url in ecb_reference_urls:
            _validate_https_public_url(url, label="ecb_reference_url")
        self.ecb_reference_urls = ecb_reference_urls
        if type(cross_check_ecb) is not bool:
            raise ContractError("cross_check_ecb must be bool")
        self.cross_check_ecb = cross_check_ecb
        self.max_spread_bps = decimal_value(max_spread_bps, "max_spread_bps", positive=True)
        self.max_reference_deviation_bps = decimal_value(
            max_reference_deviation_bps, "max_reference_deviation_bps", positive=True
        )
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ContractError("timeout_seconds must be in (0, 60]")
        self.timeout_seconds = float(timeout_seconds)
        integer(max_wire_bytes, "max_wire_bytes", minimum=256)
        if max_wire_bytes > 262_144:
            raise ContractError("max_wire_bytes must remain <= 262144 bytes")
        self.max_wire_bytes = max_wire_bytes
        self._transport = transport if transport is not None else _default_https_get

    def _fetch_ecb_reference(self, *, now_dt: datetime | None) -> tuple[str, bytes, datetime, str, str, dict[str, Decimal]]:
        last_err: Exception | None = None
        for url in self.ecb_reference_urls:
            try:
                raw_ecb = self._transport(url, self.timeout_seconds, self.max_wire_bytes)
                ecb_ns = str(time.time_ns()) if now_dt is None else str(int(now_dt.timestamp() * 1_000_000) * 1000)
                ecb_dt = datetime.now(timezone.utc) if now_dt is None else utc_time(now_dt, "now")
                ref_date, ref_rates = _parse_ecb_reference_bytes(raw_ecb)
                return url, raw_ecb, ecb_dt, ecb_ns, ref_date, ref_rates
            except Exception as exc:
                last_err = exc
        raise LiveFeedVerificationError(
            f"all configured ECB/Frankfurter reference endpoints failed ({type(last_err).__name__})"
        ) from None

    def fetch_live_quotes(
        self,
        *,
        pairs: tuple[str, ...] = SUPPORTED_FX_PAIRS,
        now: datetime | None = None,
    ) -> LiveFxFeedSnapshot:
        if type(pairs) is not tuple or not pairs or any(p not in _PAIR_METADATA for p in pairs):
            raise ContractError(f"pairs must be a non-empty subset tuple of {SUPPORTED_FX_PAIRS}")
        raw_kraken = self._transport(self.kraken_ticker_url, self.timeout_seconds, self.max_wire_bytes)
        if not isinstance(raw_kraken, bytes) or len(raw_kraken) == 0 or len(raw_kraken) > self.max_wire_bytes:
            raise LiveFeedVerificationError("Kraken transport returned empty or oversized wire bytes")
        fetched_dt = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        fetched_ns = str(time.time_ns()) if now is None else str(int(fetched_dt.timestamp() * 1_000_000) * 1000)

        ref_rates: dict[str, Decimal] | None = None
        ecb_receipt: EcbReferenceCrossCheck | None = None
        if self.cross_check_ecb:
            ecb_url, raw_ecb, ecb_dt, ecb_ns, ref_date, parsed_refs = self._fetch_ecb_reference(now_dt=now)
            ref_rates = {p: parsed_refs[p] for p in pairs}

        quotes = _parse_kraken_ticker_bytes(
            raw_kraken,
            pairs=pairs,
            observed_at=fetched_dt,
            observed_at_ns=fetched_ns,
            max_spread_bps=self.max_spread_bps,
            reference_rates=ref_rates,
            max_reference_deviation_bps=self.max_reference_deviation_bps if self.cross_check_ecb else None,
        )

        if self.cross_check_ecb and ref_rates is not None:
            devs = {
                p: quotes[p].reference_deviation_bps
                for p in pairs
                if quotes[p].reference_deviation_bps is not None
            }
            ecb_receipt = EcbReferenceCrossCheck(
                source_url=ecb_url,
                reference_date=ref_date,
                fetched_at_utc=ecb_dt,
                fetched_at_ns=ecb_ns,
                raw_wire_sha256=sha256(raw_ecb).hexdigest(),
                raw_wire_bytes_len=len(raw_ecb),
                raw_wire_base64=base64.b64encode(raw_ecb).decode("ascii"),
                raw_wire_utf8=raw_ecb.decode("utf-8"),
                reference_rates=ref_rates,
                deviations_bps=devs,
                max_allowed_deviation_bps=self.max_reference_deviation_bps,
                verified=True,
            )

        return _assemble_snapshot(
            provider="kraken-public-rest-ticker",
            source_url=self.kraken_ticker_url,
            fetched_at_utc=fetched_dt,
            fetched_at_ns=fetched_ns,
            raw_bytes=raw_kraken,
            max_spread_bps=self.max_spread_bps,
            quotes=quotes,
            ecb_cross_check=ecb_receipt,
        )

    def capture_to_file(
        self,
        path: str | Path,
        *,
        pairs: tuple[str, ...] = SUPPORTED_FX_PAIRS,
        now: datetime | None = None,
    ) -> LiveFxFeedSnapshot:
        snap = self.fetch_live_quotes(pairs=pairs, now=now)
        snap.save_json(path)
        return snap

    @staticmethod
    def load_and_verify(path: str | Path) -> LiveFxFeedSnapshot:
        return LiveFxFeedSnapshot.load_json(path)


def _parse_oanda_pricing_bytes(
    raw_bytes: bytes,
    *,
    pairs: tuple[str, ...],
    observed_at: datetime,
    observed_at_ns: str,
    max_spread_bps: Decimal,
) -> dict[str, LiveFxQuote]:
    doc = _parse_external_wire_json(raw_bytes, label="oanda_practice_pricing")
    if type(doc) is not dict or type(doc.get("prices")) is not list:
        raise LiveFeedVerificationError("OANDA practice pricing response missing prices list")
    by_inst: dict[str, dict[str, Any]] = {}
    for entry in doc["prices"]:
        if type(entry) is dict and isinstance(entry.get("instrument"), str):
            by_inst[entry["instrument"]] = entry

    quotes: dict[str, LiveFxQuote] = {}
    for sym in pairs:
        meta = _PAIR_METADATA[sym]
        oanda_inst = meta["oanda_instrument"]
        item = by_inst.get(oanda_inst)
        if item is None:
            raise LiveFeedVerificationError(f"OANDA practice pricing missing {oanda_inst}")
        bids = item.get("bids")
        asks = item.get("asks")
        if type(bids) is not list or not bids or type(asks) is not list or not asks:
            raise LiveFeedVerificationError(f"OANDA practice pricing {oanda_inst} missing bids/asks")
        bid = parse_decimal(str(bids[0]["price"]), f"{sym}.bid")
        ask = parse_decimal(str(asks[0]["price"]), f"{sym}.ask")
        q_obs = observed_at
        if isinstance(item.get("time"), str):
            ts_text = re.sub(r"(\.[0-9]{6})[0-9]+(Z|[+-][0-9]{2}:[0-9]{2})$", r"\1\2", item["time"])
            q_obs = _parse_iso_utc(ts_text, f"{sym}.time")
        quotes[sym] = _build_live_quote(
            symbol=sym,
            source_pair_key=oanda_inst,
            bid=bid,
            ask=ask,
            observed_at=q_obs,
            observed_at_ns=observed_at_ns,
            max_spread_bps=max_spread_bps,
        )
    return quotes


class OandaPracticePaperClient:
    """Optional OANDA v20 practice-only paper REST adapter.

    Security invariants:
    - Strictly pinned to https://api-fxpractice.oanda.com/v3.
    - Unconditionally rejects api-fxtrade.oanda.com, stream-fxtrade.oanda.com, HTTP, redirects,
      IP literals, embedded URL credentials, or any host != api-fxpractice.oanda.com.
    - Activated ONLY when explicit runtime env vars CAS_FOREX_OANDA_PRACTICE_TOKEN and
      CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID are supplied in the passed mapping.
    - Never reads .env files and never logs/prints/reprs headers or tokens.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_OANDA_PRACTICE_BASE_URL,
        environ: Mapping[str, str] | None = None,
        max_spread_bps: Decimal = Decimal("500"),
        timeout_seconds: float = 10.0,
        max_wire_bytes: int = MAX_WIRE_RESPONSE_BYTES,
        transport: Callable[[str, str, dict[str, str], bytes | None, float, int], bytes] | None = None,
    ) -> None:
        self.base_url = self.validate_practice_url(base_url)
        self.max_spread_bps = decimal_value(max_spread_bps, "max_spread_bps", positive=True)
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ContractError("timeout_seconds must be in (0, 60]")
        self.timeout_seconds = float(timeout_seconds)
        integer(max_wire_bytes, "max_wire_bytes", minimum=256)
        self.max_wire_bytes = max_wire_bytes
        self._transport = transport

        self._secret: _RedactedSecret | None = None
        self._account_id: str | None = None
        if environ is not None:
            if not isinstance(environ, Mapping):
                raise ContractError("environ must be a key-value Mapping (never a .env file path)")
            raw_tok = environ.get(ENV_OANDA_PRACTICE_TOKEN, "").strip()
            raw_acct = environ.get(ENV_OANDA_PRACTICE_ACCOUNT_ID, "").strip()
            if bool(raw_tok) != bool(raw_acct):
                raise PaperBrokerNotConfiguredError(
                    f"both {ENV_OANDA_PRACTICE_TOKEN} and {ENV_OANDA_PRACTICE_ACCOUNT_ID} are required together"
                )
            if raw_tok and raw_acct:
                identifier(raw_acct, "oanda_practice_account_id")
                self._secret = _RedactedSecret(raw_tok)
                self._account_id = raw_acct

    @classmethod
    def from_runtime_env(
        cls,
        environ: Mapping[str, str],
        *,
        base_url: str = DEFAULT_OANDA_PRACTICE_BASE_URL,
        transport: Callable[[str, str, dict[str, str], bytes | None, float, int], bytes] | None = None,
    ) -> "OandaPracticePaperClient":
        return cls(base_url=base_url, environ=environ, transport=transport)

    @property
    def is_active(self) -> bool:
        return self._secret is not None and self._account_id is not None

    @property
    def account_id(self) -> str | None:
        return self._account_id

    def __repr__(self) -> str:
        return (
            f"OandaPracticePaperClient(base_url={self.base_url!r}, "
            f"active={self.is_active}, token='[REDACTED]')"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @staticmethod
    def validate_practice_url(url: str) -> str:
        if not isinstance(url, str) or not url.strip():
            raise LiveBrokerEndpointForbiddenError("OANDA practice base URL must be a non-empty string")
        cleaned = url.strip().rstrip("/")
        parsed = urllib.parse.urlsplit(cleaned)
        host = (parsed.hostname or "").lower()
        if any(tok in host for tok in _FORBIDDEN_LIVE_HOST_TOKENS) or "live" in host:
            raise LiveBrokerEndpointForbiddenError(
                f"LIVE REAL-MONEY ENDPOINT FORBIDDEN: {host!r} is hard-rejected; only {ALLOWED_OANDA_PRACTICE_HOST} is allowed"
            )
        if parsed.scheme != "https":
            raise LiveBrokerEndpointForbiddenError("OANDA practice adapter requires https:// scheme")
        if host != ALLOWED_OANDA_PRACTICE_HOST:
            raise LiveBrokerEndpointForbiddenError(
                f"non-practice host {host!r} refused; strictly pinned to {ALLOWED_OANDA_PRACTICE_HOST}"
            )
        if parsed.port not in (None, 443):
            raise LiveBrokerEndpointForbiddenError("non-standard port refused on OANDA practice endpoint")
        if parsed.username or parsed.password or parsed.fragment:
            raise LiveBrokerEndpointForbiddenError("credentials and URL fragments are forbidden in OANDA URLs")
        if not (parsed.path == "/v3" or parsed.path.startswith("/v3/")):
            raise LiveBrokerEndpointForbiddenError("OANDA practice URL path must be rooted at /v3")
        return cleaned

    def _require_active(self) -> tuple[_RedactedSecret, str]:
        if self._secret is None or self._account_id is None:
            raise PaperBrokerNotConfiguredError(
                f"OandaPracticePaperClient is inactive; pass explicit runtime env vars "
                f"{ENV_OANDA_PRACTICE_TOKEN} and {ENV_OANDA_PRACTICE_ACCOUNT_ID}"
            )
        return self._secret, self._account_id

    def _request(self, method: str, relative_path: str, *, body_obj: dict[str, Any] | None = None) -> tuple[str, bytes]:
        secret, _ = self._require_active()
        full_url = self.validate_practice_url(f"{self.base_url}/{relative_path.lstrip('/')}")
        body_bytes = None if body_obj is None else canonical_bytes(body_obj)
        headers = {
            "Authorization": f"Bearer {secret.reveal_for_header()}",
            "Accept": "application/json",
            "Accept-Datetime-Format": "RFC3339",
            "User-Agent": "CAS-Forex-Revamp-Phase5-OandaPractice/1.0",
        }
        if body_bytes is not None:
            headers["Content-Type"] = "application/json"

        if self._transport is not None:
            try:
                raw = self._transport(method, full_url, dict(headers), body_bytes, self.timeout_seconds, self.max_wire_bytes)
            except LiveBrokerEndpointForbiddenError:
                raise
            except Exception as exc:
                raise PaperBrokerTransportError(f"OANDA practice transport error: {type(exc).__name__}") from None
            finally:
                headers.clear()
        else:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
                _NoRedirectHandler(),
            )
            req = urllib.request.Request(full_url, data=body_bytes, headers=headers, method=method)
            try:
                with opener.open(req, timeout=self.timeout_seconds) as resp:
                    status = getattr(resp, "status", 200)
                    if status not in (200, 201):
                        raise PaperBrokerTransportError(f"OANDA practice HTTP status {status}")
                    raw = resp.read(self.max_wire_bytes + 1)
            except urllib.error.HTTPError as exc:
                code = exc.code
                raise PaperBrokerTransportError(f"OANDA practice HTTP error {code}") from None
            except PaperBrokerTransportError:
                raise
            except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
                raise PaperBrokerTransportError(f"OANDA practice connection failed: {type(exc).__name__}") from None
            finally:
                headers.clear()
                req.headers.clear()
                req.unredirected_hdrs.clear()

        if not isinstance(raw, bytes) or len(raw) == 0 or len(raw) > self.max_wire_bytes:
            raise PaperBrokerTransportError("OANDA practice response empty or exceeded wire byte cap")
        return full_url, raw

    def fetch_pricing(
        self,
        *,
        pairs: tuple[str, ...] = SUPPORTED_FX_PAIRS,
        now: datetime | None = None,
    ) -> LiveFxFeedSnapshot:
        if type(pairs) is not tuple or not pairs or any(p not in _PAIR_METADATA for p in pairs):
            raise ContractError(f"pairs must be a non-empty subset tuple of {SUPPORTED_FX_PAIRS}")
        _, acct_id = self._require_active()
        inst_query = ",".join(_PAIR_METADATA[p]["oanda_instrument"] for p in pairs)
        full_url, raw = self._request("GET", f"accounts/{acct_id}/pricing?instruments={inst_query}")
        fetched_dt = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        fetched_ns = str(time.time_ns()) if now is None else str(int(fetched_dt.timestamp() * 1_000_000) * 1000)
        quotes = _parse_oanda_pricing_bytes(
            raw,
            pairs=pairs,
            observed_at=fetched_dt,
            observed_at_ns=fetched_ns,
            max_spread_bps=self.max_spread_bps,
        )
        return _assemble_snapshot(
            provider="oanda-fxpractice-v3-pricing",
            source_url=full_url,
            fetched_at_utc=fetched_dt,
            fetched_at_ns=fetched_ns,
            raw_bytes=raw,
            max_spread_bps=self.max_spread_bps,
            quotes=quotes,
            ecb_cross_check=None,
        )

    def fetch_account_summary(self, *, now: datetime | None = None) -> dict[str, Any]:
        _, acct_id = self._require_active()
        _, raw = self._request("GET", f"accounts/{acct_id}/summary")
        doc = _parse_external_wire_json(raw, label="oanda_practice_summary")
        acct = doc.get("account") if type(doc) is dict else None
        if type(acct) is not dict:
            raise PaperBrokerTransportError("OANDA practice summary missing account object")
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        receipt = {
            "provider": "oanda-fxpractice-v3",
            "account_id": str(acct.get("id", acct_id)),
            "currency": str(acct.get("currency", "USD")),
            "balance": decimal_text(parse_decimal(str(acct["balance"]), "balance")),
            "nav": decimal_text(parse_decimal(str(acct.get("NAV", acct["balance"])), "NAV")),
            "unrealized_pnl": decimal_text(parse_decimal(str(acct.get("unrealizedPL", "0")), "unrealizedPL")),
            "margin_available": decimal_text(parse_decimal(str(acct.get("marginAvailable", "0")), "marginAvailable")),
            "open_position_count": int(acct.get("openPositionCount", 0)),
            "last_transaction_id": str(acct.get("lastTransactionID", "0")),
            "observed_at": _format_utc_micros(ts, "observed_at"),
            "raw_wire_sha256": sha256(raw).hexdigest(),
        }
        assert_safe_json_numbers(receipt)
        return receipt

    def submit_paper_market_order(
        self,
        *,
        symbol: str,
        side: Side,
        units: Decimal,
        client_order_id: str,
        stop_loss_price: Decimal | None = None,
        price_bound: Decimal | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        _, acct_id = self._require_active()
        norm = symbol.strip().upper()
        if norm not in _PAIR_METADATA:
            raise ContractError(f"unsupported symbol {symbol!r}")
        if not isinstance(side, Side):
            raise ContractError("side must be Side.BUY or Side.SELL")
        decimal_value(units, "units", positive=True)
        identifier(client_order_id, "client_order_id")
        signed_units = decimal_text(units if side is Side.BUY else -units)
        order_spec: dict[str, Any] = {
            "type": "MARKET",
            "instrument": _PAIR_METADATA[norm]["oanda_instrument"],
            "units": signed_units,
            "timeInForce": "FOK",
            "positionFill": "DEFAULT",
            "clientExtensions": {"id": client_order_id},
        }
        if price_bound is not None:
            order_spec["priceBound"] = decimal_text(decimal_value(price_bound, "price_bound", positive=True))
        if stop_loss_price is not None:
            order_spec["stopLossOnFill"] = {
                "price": decimal_text(decimal_value(stop_loss_price, "stop_loss_price", positive=True))
            }
        _, raw = self._request("POST", f"accounts/{acct_id}/orders", body_obj={"order": order_spec})
        doc = _parse_external_wire_json(raw, label="oanda_practice_order")
        if type(doc) is not dict:
            raise PaperBrokerTransportError("malformed OANDA practice order response")
        fill_tx = doc.get("orderFillTransaction")
        create_tx = doc.get("orderCreateTransaction")
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        receipt = {
            "provider": "oanda-fxpractice-v3",
            "client_order_id": client_order_id,
            "instrument": order_spec["instrument"],
            "side": side.value,
            "requested_units": decimal_text(units),
            "status": "FILLED" if type(fill_tx) is dict else "CREATED",
            "create_transaction_id": None if type(create_tx) is not dict else str(create_tx.get("id", "")),
            "fill_transaction_id": None if type(fill_tx) is not dict else str(fill_tx.get("id", "")),
            "fill_price": (
                None
                if type(fill_tx) is not dict or "price" not in fill_tx
                else decimal_text(parse_decimal(str(fill_tx["price"]), "fill_price"))
            ),
            "last_transaction_id": str(doc.get("lastTransactionID", "0")),
            "observed_at": _format_utc_micros(ts, "observed_at"),
            "raw_wire_sha256": sha256(raw).hexdigest(),
        }
        assert_safe_json_numbers(receipt)
        return receipt


@dataclass(frozen=True, slots=True)
class BrokerAuditReceipt:
    sequence: int
    event_kind: str
    observed_at: datetime
    payload: dict[str, Any]
    previous_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        integer(self.sequence, "audit sequence", minimum=1)
        identifier(self.event_kind, "event_kind")
        utc_time(self.observed_at, "audit observed_at")
        assert_safe_json_numbers(self.payload, path="$.audit.payload")
        digest(self.previous_sha256, "previous_sha256")
        digest(self.record_sha256, "record_sha256")

    def to_wire_dict(self) -> dict[str, Any]:
        out = {
            "sequence": self.sequence,
            "event_kind": self.event_kind,
            "observed_at": _format_utc_micros(self.observed_at, "observed_at"),
            "payload": self.payload,
            "previous_sha256": self.previous_sha256,
            "record_sha256": self.record_sha256,
        }
        assert_safe_json_numbers(out)
        return out


class SealedLiveFeedPaperVenue:
    """Wraps SQLiteVenue so sealed/live external FX quotes drive paper execution and SQLite audit receipts."""

    def __init__(
        self,
        path: str | Path,
        *,
        audit_path: str | Path | None = None,
        faults: FaultSchedule | None = None,
        owner_close_verifier: Callable[[AuthorizedCommand, datetime], bool] | None = None,
        minimum_sequence: int = 0,
        checkpoint_anchor: JournalCheckpoint | None = None,
        paper_broker: OandaPracticePaperClient | None = None,
    ) -> None:
        self._venue = SQLiteVenue(
            path,
            faults=faults,
            owner_close_verifier=owner_close_verifier,
            minimum_sequence=minimum_sequence,
            checkpoint_anchor=checkpoint_anchor,
        )
        self.path = self._venue.path
        if audit_path is not None:
            self.audit_path = Path(audit_path)
        else:
            stem = self.path.name[: -len(".venue.sqlite3")]
            self.audit_path = self.path.with_name(f"{stem}.broker_audit.sqlite3")
        if not self.audit_path.name.endswith(".broker_audit.sqlite3") or self.audit_path == self.path:
            raise ContractError("use a dedicated *.broker_audit.sqlite3 path distinct from *.venue.sqlite3")
        if paper_broker is not None and not isinstance(paper_broker, OandaPracticePaperClient):
            raise ContractError("paper_broker must be OandaPracticePaperClient or None")
        self.paper_broker = paper_broker

    @property
    def sqlite_venue(self) -> SQLiteVenue:
        return self._venue

    @property
    def faults(self) -> FaultSchedule:
        return self._venue.faults

    @property
    def minimum_sequence(self) -> int:
        return self._venue.minimum_sequence

    @contextmanager
    def _audit_session(self, *, write: bool, initializing: bool = False) -> Iterator[sqlite3.Connection]:
        conn = None
        try:
            uri = self.audit_path.absolute().as_uri() + "?mode=rw"
            conn = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            if not initializing and conn.execute("PRAGMA application_id").fetchone()[0] != BROKER_AUDIT_APPLICATION_ID:
                raise VenueStorageError("file is not a compatible broker_audit.sqlite3 store")
            if write:
                conn.execute("PRAGMA synchronous=FULL")
            yield conn
        except sqlite3.Error as exc:
            raise VenueStorageError("broker audit storage unavailable") from exc
        finally:
            if conn is not None:
                if conn.in_transaction:
                    conn.rollback()
                conn.close()

    def _load_audit_chain(self, conn: sqlite3.Connection) -> tuple[list[BrokerAuditReceipt], dict[str, Any]]:
        rows = conn.execute(
            "SELECT sequence, event_kind, observed_at, payload_json, previous_sha256, record_sha256 "
            "FROM broker_audit ORDER BY sequence"
        ).fetchall()
        if not rows:
            raise VenueStorageError("broker audit store contains no genesis checkpoint")
        receipts: list[BrokerAuditReceipt] = []
        expected_prev = "0" * 64
        prev_seq = 0
        genesis_payload: dict[str, Any] | None = None
        for row in rows:
            seq = row["sequence"]
            if type(seq) is not int or seq != prev_seq + 1:
                raise VenueStorageError("corrupt broker audit sequence")
            payload = strict_safe_json_loads(row["payload_json"])
            obs_str = row["observed_at"]
            obs_dt = _parse_iso_utc(obs_str, "audit.observed_at")
            envelope = {
                "storage_version": BROKER_AUDIT_STORAGE_VERSION,
                "sequence": seq,
                "event_kind": row["event_kind"],
                "observed_at": obs_str,
                "previous_sha256": row["previous_sha256"],
                "payload": payload,
            }
            calc_sha = content_digest(envelope)
            if row["previous_sha256"] != expected_prev or calc_sha != row["record_sha256"]:
                raise VenueStorageError("broker audit hash-chain integrity mismatch")
            if seq == 1:
                if row["event_kind"] != "VENUE_AUDIT_GENESIS":
                    raise VenueStorageError("broker audit sequence 1 must be VENUE_AUDIT_GENESIS")
                genesis_payload = payload
            receipts.append(
                BrokerAuditReceipt(
                    sequence=seq,
                    event_kind=row["event_kind"],
                    observed_at=obs_dt,
                    payload=payload,
                    previous_sha256=row["previous_sha256"],
                    record_sha256=row["record_sha256"],
                )
            )
            expected_prev = row["record_sha256"]
            prev_seq = seq
        assert genesis_payload is not None
        return receipts, genesis_payload

    def _append_audit(self, event_kind: str, observed_at: datetime, payload: dict[str, Any]) -> BrokerAuditReceipt:
        assert_safe_json_numbers(payload, path="$.payload")
        obs_str = _format_utc_micros(observed_at, "observed_at")
        with self._audit_session(write=True) as conn:
            conn.execute("BEGIN IMMEDIATE")
            chain, _ = self._load_audit_chain(conn)
            seq = chain[-1].sequence + 1
            prev_sha = chain[-1].record_sha256
            envelope = {
                "storage_version": BROKER_AUDIT_STORAGE_VERSION,
                "sequence": seq,
                "event_kind": event_kind,
                "observed_at": obs_str,
                "previous_sha256": prev_sha,
                "payload": payload,
            }
            rec_sha = content_digest(envelope)
            conn.execute(
                "INSERT INTO broker_audit(sequence, event_kind, observed_at, payload_json, previous_sha256, record_sha256) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (seq, event_kind, obs_str, canonical_bytes(payload).decode("utf-8"), prev_sha, rec_sha),
            )
            conn.commit()
            return BrokerAuditReceipt(
                sequence=seq,
                event_kind=event_kind,
                observed_at=observed_at,
                payload=payload,
                previous_sha256=prev_sha,
                record_sha256=rec_sha,
            )

    def _registered_instruments(self) -> list[Instrument]:
        with self._audit_session(write=False) as conn:
            conn.execute("BEGIN")
            _, genesis = self._load_audit_chain(conn)
        return [
            Instrument(
                instrument_id=item["instrument_id"],
                symbol=item["symbol"],
                base_currency=item["base_currency"],
                quote_currency=item["quote_currency"],
                price_tick=parse_decimal(item["price_tick"], "price_tick"),
                quantity_step=parse_decimal(item["quantity_step"], "quantity_step"),
                minimum_quantity=parse_decimal(item["minimum_quantity"], "minimum_quantity"),
                quantity_unit=item["quantity_unit"],
            )
            for item in genesis["instruments"]
        ]

    def _latest_feed_binding(self) -> dict[str, str | None]:
        with self._audit_session(write=False) as conn:
            conn.execute("BEGIN")
            chain, _ = self._load_audit_chain(conn)
        for rec in reversed(chain):
            if rec.event_kind == "SEALED_FEED_SNAPSHOT_VERIFIED":
                return {
                    "snapshot_id": rec.payload["snapshot_id"],
                    "raw_wire_sha256": rec.payload["raw_wire_sha256"],
                    "canonical_payload_sha256": rec.payload["canonical_payload_sha256"],
                }
        return {"snapshot_id": None, "raw_wire_sha256": None, "canonical_payload_sha256": None}

    def initialize(
        self,
        key: AccountRunKey,
        *,
        opening_balance: Money,
        instruments: tuple[Instrument, ...],
        now: datetime,
        scenario: VenueScenario = VenueScenario(),
    ) -> VenueSnapshot:
        if self.audit_path.exists():
            raise VenueStorageError("broker audit store already exists; refusing accidental reset")
        snap = self._venue.initialize(
            key,
            opening_balance=opening_balance,
            instruments=instruments,
            now=now,
            scenario=scenario,
        )
        try:
            with self.audit_path.open("xb"):
                pass
        except OSError as exc:
            raise VenueStorageError("unable to create dedicated broker audit store") from exc
        obs_str = _format_utc_micros(now, "now")
        genesis_payload = {
            "key": to_wire(key),
            "opening_balance": to_wire(opening_balance),
            "scenario_id": scenario.scenario_id,
            "venue_genesis_snapshot_id": snap.snapshot_id,
            "instruments": [to_wire(inst) for inst in instruments],
        }
        assert_safe_json_numbers(genesis_payload)
        envelope = {
            "storage_version": BROKER_AUDIT_STORAGE_VERSION,
            "sequence": 1,
            "event_kind": "VENUE_AUDIT_GENESIS",
            "observed_at": obs_str,
            "previous_sha256": "0" * 64,
            "payload": genesis_payload,
        }
        rec_sha = content_digest(envelope)
        with self._audit_session(write=True, initializing=True) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"PRAGMA application_id={BROKER_AUDIT_APPLICATION_ID}")
            conn.execute(
                "CREATE TABLE broker_audit ("
                "sequence INTEGER PRIMARY KEY, "
                "event_kind TEXT NOT NULL, "
                "observed_at TEXT NOT NULL, "
                "payload_json TEXT NOT NULL, "
                "previous_sha256 TEXT NOT NULL, "
                "record_sha256 TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO broker_audit(sequence, event_kind, observed_at, payload_json, previous_sha256, record_sha256) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (1, "VENUE_AUDIT_GENESIS", obs_str, canonical_bytes(genesis_payload).decode("utf-8"), "0" * 64, rec_sha),
            )
            conn.commit()
        return snap

    def accept(self, command: AuthorizedCommand, *, now: datetime) -> VenueReceipt:
        receipt = self._venue.accept(command, now=now)
        binding = self._latest_feed_binding()
        self._append_audit(
            "PAPER_ORDER_ACCEPT",
            now,
            {
                "command_id": command.command_id,
                "kind": command.intent.kind.value,
                "instrument_id": command.intent.instrument_id,
                "side": None if command.intent.side is None else command.intent.side.value,
                "quantity": None if command.intent.quantity is None else decimal_text(command.intent.quantity),
                "limit_price": None if command.intent.limit_price is None else decimal_text(command.intent.limit_price),
                "stop_price": None if command.intent.stop_price is None else decimal_text(command.intent.stop_price),
                "risk_price_ceiling": (
                    None if command.risk_price_ceiling is None else decimal_text(command.risk_price_ceiling)
                ),
                "payload_sha256": command.payload_sha256,
                "venue_receipt_id": receipt.receipt_id,
                "venue_sequence": receipt.venue_sequence,
                "effect": receipt.effect.value,
                "position_id": receipt.position_id,
                "reason_code": receipt.reason_code,
                "feed_binding": binding,
            },
        )
        return receipt

    def advance_fence(self, request: FenceRequest, *, now: datetime) -> FenceReceipt:
        receipt = self._venue.advance_fence(request, now=now)
        self._append_audit(
            "FENCE_BARRIER_ADVANCE",
            now,
            {
                "barrier_id": receipt.barrier_id,
                "control": request.control.value,
                "generation": receipt.generation,
                "new_risk_allowed": receipt.new_risk_allowed,
                "management_allowed": receipt.management_allowed,
                "venue_sequence": receipt.venue_sequence,
                "applied": receipt.applied,
                "reason_code": receipt.reason_code,
            },
        )
        return receipt

    def lookup(self, key: AccountRunKey, command_id: str) -> VenueLookup:
        return self._venue.lookup(key, command_id)

    def snapshot(self, key: AccountRunKey, *, now: datetime) -> VenueSnapshot:
        return self._venue.snapshot(key, now=now)

    def receipt_history(self, key: AccountRunKey, command_id: str | None = None) -> tuple[VenueReceipt, ...]:
        return self._venue.receipt_history(key, command_id)

    def inspect_journal(self, key: AccountRunKey) -> tuple[JournalCheckpoint, ...]:
        return self._venue.inspect_journal(key)

    def inspect_audit_journal(self, key: AccountRunKey) -> tuple[BrokerAuditReceipt, ...]:
        with self._audit_session(write=False) as conn:
            conn.execute("BEGIN")
            chain, genesis = self._load_audit_chain(conn)
        if genesis["key"] != to_wire(key):
            raise ContractError("broker audit store belongs to a different account/run")
        return tuple(chain)

    def advance_market(self, observation: MarketObservation) -> VenueSnapshot:
        before_receipts = {r.receipt_id for r in self._venue.receipt_history(observation.key)}
        snap = self._venue.advance_market(observation)
        after_receipts = [
            r for r in self._venue.receipt_history(observation.key) if r.receipt_id not in before_receipts
        ]
        binding = self._latest_feed_binding()
        self._append_audit(
            "MARKET_TICK_AND_FILLS",
            observation.available_at,
            {
                "event_id": observation.event_id,
                "instrument_id": observation.instrument_id,
                "market_sequence": observation.sequence,
                "bid": decimal_text(observation.bid),
                "ask": decimal_text(observation.ask),
                "observation_sha256": content_digest(observation),
                "venue_snapshot_id": snap.snapshot_id,
                "venue_sequence": snap.sequence,
                "balance": decimal_text(snap.balance.amount),
                "equity": decimal_text(snap.equity.amount),
                "realized_pnl": decimal_text(snap.realized_pnl.amount),
                "open_pnl": decimal_text(snap.open_pnl.amount),
                "feed_binding": binding,
                "triggered_receipts": [
                    {
                        "receipt_id": r.receipt_id,
                        "command_id": r.command_id,
                        "effect": r.effect.value,
                        "venue_sequence": r.venue_sequence,
                        "position_id": r.position_id,
                        "reason_code": r.reason_code,
                        "filled": None if r.quantities is None else decimal_text(r.quantities.filled),
                        "remaining": None if r.quantities is None else decimal_text(r.quantities.remaining),
                    }
                    for r in after_receipts
                ],
            },
        )
        return snap

    def ingest_live_snapshot(
        self,
        feed_snapshot: LiveFxFeedSnapshot,
        *,
        key: AccountRunKey,
        symbols: tuple[str, ...] | None = None,
        now: datetime | None = None,
        align_to_tick: bool = True,
    ) -> VenueSnapshot:
        if not isinstance(feed_snapshot, LiveFxFeedSnapshot):
            raise ContractError("ingest_live_snapshot requires a typed LiveFxFeedSnapshot")
        feed_snapshot.verify_integrity()

        registered = self._registered_instruments()
        target_symbols = (
            {s.strip().upper() for s in symbols}
            if symbols is not None
            else set(feed_snapshot.quotes.keys())
        )
        matching_instruments = [
            inst for inst in registered if inst.symbol.upper() in target_symbols and inst.symbol.upper() in feed_snapshot.quotes
        ]
        if not matching_instruments:
            raise ContractError("no registered venue instruments match the supplied live FX snapshot symbols")

        base_now = feed_snapshot.fetched_at_utc if now is None else utc_time(now, "now")
        current_snap = self._venue.snapshot(key, now=base_now)

        self._append_audit(
            "SEALED_FEED_SNAPSHOT_VERIFIED",
            base_now,
            {
                "snapshot_id": feed_snapshot.snapshot_id,
                "provider": feed_snapshot.provider,
                "source_url": feed_snapshot.source_url,
                "feed_fetched_at_utc": _format_utc_micros(feed_snapshot.fetched_at_utc, "feed_fetched_at_utc"),
                "feed_fetched_at_ns": feed_snapshot.fetched_at_ns,
                "raw_wire_sha256": feed_snapshot.raw_wire_sha256,
                "canonical_payload_sha256": feed_snapshot.canonical_payload_sha256,
                "ecb_verified": bool(feed_snapshot.ecb_cross_check is not None and feed_snapshot.ecb_cross_check.verified),
                "quotes": {
                    sym: {"bid": decimal_text(q.bid), "ask": decimal_text(q.ask), "spread_bps": decimal_text(q.spread_bps)}
                    for sym, q in sorted(feed_snapshot.quotes.items())
                },
            },
        )

        latest_snap = current_snap
        for idx, inst in enumerate(matching_instruments):
            tick_time = base_now + timedelta(microseconds=idx)
            next_seq = latest_snap.sequence + 1
            obs = feed_snapshot.to_market_observation(
                inst.symbol.upper(),
                key=key,
                instrument_id=inst.instrument_id,
                sequence=next_seq,
                price_tick=inst.price_tick,
                observed_at=tick_time,
                available_at=tick_time,
                event_id=f"live-{inst.instrument_id.lower()}-{feed_snapshot.raw_wire_sha256[:10]}-{next_seq}",
                align_to_tick=align_to_tick,
            )
            latest_snap = self.advance_market(obs)
        return latest_snap

    def ingest_captured_file(
        self,
        path: str | Path,
        *,
        key: AccountRunKey,
        symbols: tuple[str, ...] | None = None,
        now: datetime | None = None,
        align_to_tick: bool = True,
    ) -> tuple[LiveFxFeedSnapshot, VenueSnapshot]:
        snap = LiveFxFeedSnapshot.load_json(path)
        venue_snap = self.ingest_live_snapshot(snap, key=key, symbols=symbols, now=now, align_to_tick=align_to_tick)
        return snap, venue_snap

    def poll_and_ingest_live_quotes(
        self,
        feed_client: PublicLiveFxFeedClient,
        *,
        key: AccountRunKey,
        pairs: tuple[str, ...] = SUPPORTED_FX_PAIRS,
        symbols: tuple[str, ...] | None = None,
        now: datetime | None = None,
        align_to_tick: bool = True,
    ) -> tuple[LiveFxFeedSnapshot, VenueSnapshot]:
        if not isinstance(feed_client, PublicLiveFxFeedClient):
            raise ContractError("poll_and_ingest_live_quotes requires PublicLiveFxFeedClient")
        live_snap = feed_client.fetch_live_quotes(pairs=pairs, now=now)
        venue_snap = self.ingest_live_snapshot(
            live_snap, key=key, symbols=symbols, now=now, align_to_tick=align_to_tick
        )
        return live_snap, venue_snap


def assemble_live_feed_paper_simulation(
    config: RuntimeConfig,
    *,
    policy: RiskPolicy,
    instruments: tuple[InstrumentPolicy, ...],
    decision_adapter: DecisionAdapter,
    clock: Callable[[], datetime],
    owner_verifier: OwnerVerifier | None = None,
    expected_origin: DecisionOrigin = DecisionOrigin.SCRIPTED,
    faults: FaultSchedule | None = None,
    max_decisions: int = 256,
    minimum_venue_sequence: int = 0,
    venue_checkpoint: JournalCheckpoint | None = None,
    valve_gate: object | None = None,
    paper_broker: OandaPracticePaperClient | None = None,
) -> InertSimulation:
    """Inert composition wiring CoreCoordinator, OperatorSession, RehearsalWiring, ForexMetaValveGate, and SealedLiveFeedPaperVenue."""
    if not isinstance(config, RuntimeConfig):
        raise TypeError("RuntimeConfig required")
    core_path = config.state_directory / "account.core.sqlite3"
    venue_path = config.state_directory / "account.venue.sqlite3"
    core: CoreCoordinator | None = None

    def verify_reviewed_close(command: AuthorizedCommand, now: datetime) -> bool:
        return core is not None and core.verify_owner_close(command, now)

    venue = SealedLiveFeedPaperVenue(
        venue_path,
        faults=faults,
        owner_close_verifier=verify_reviewed_close,
        minimum_sequence=minimum_venue_sequence,
        checkpoint_anchor=venue_checkpoint,
        paper_broker=paper_broker,
    )
    core = CoreCoordinator(
        scope=config.scope,
        store=SQLiteStore(core_path),
        venue=venue,
        policy=policy,
        instruments=instruments,
        owner_verifier=owner_verifier,
    )
    operator = OperatorSession(
        decision_adapter,
        current_state=lambda: core.current_state(config.scope.key, now=clock()),
        clock=clock,
        max_decisions=max_decisions,
    )
    wiring = RehearsalWiring(
        config,
        core=core,
        state_reader=core,
        venue=venue,
        operator=operator,
        clock=clock,
        expected_origin=expected_origin,
        valve_gate=valve_gate,
    )
    return InertSimulation(
        config,
        core,
        venue,
        operator,
        wiring,
        core_path,
        venue_path,
        CockpitProjection(config.scope),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture or verify sealed public FX quotes.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture", help="Fetch live Kraken + ECB FX quotes and seal to JSON.")
    cap.add_argument("--output", type=Path, required=True)
    cap.add_argument("--no-ecb", action="store_true")
    ver = sub.add_parser("verify", help="Verify a sealed LiveFxFeedSnapshot JSON file offline.")
    ver.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.cmd == "capture":
        client = PublicLiveFxFeedClient(cross_check_ecb=not args.no_ecb)
        snap = client.capture_to_file(args.output)
        summary = {
            "status": "CAPTURED_AND_VERIFIED",
            "output": str(args.output),
            "snapshot_id": snap.snapshot_id,
            "fetched_at_utc": _format_utc_micros(snap.fetched_at_utc),
            "raw_wire_sha256": snap.raw_wire_sha256,
            "canonical_payload_sha256": snap.canonical_payload_sha256,
            "quotes": {k: {"bid": decimal_text(q.bid), "ask": decimal_text(q.ask)} for k, q in sorted(snap.quotes.items())},
        }
        print(json.dumps(summary, sort_keys=True))
        return 0
    if args.cmd == "verify":
        snap = PublicLiveFxFeedClient.load_and_verify(args.input)
        summary = {
            "status": "VERIFIED",
            "snapshot_id": snap.snapshot_id,
            "raw_wire_sha256": snap.raw_wire_sha256,
            "canonical_payload_sha256": snap.canonical_payload_sha256,
        }
        print(json.dumps(summary, sort_keys=True))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
