"""Expanded 16-pair G10 spot FX & multi-timeframe OHLCV candlestick stream.

Phase 6 live market stream module:
- Expands spot FX coverage from 3 pairs to 16 major and cross pairs:
  Majors (7): EURUSD, GBPUSD, USDJPY, USDCHF, AUDUSD, USDCAD, NZDUSD
  Crosses (9): EURGBP, EURJPY, GBPJPY, EURCHF, EURAUD, EURCAD, AUDJPY, CHFJPY, CADJPY
- Fetches real live Kraken public orderbook Ticker + OHLCV candles (M1, M5, H1),
  derives exact two-sided synthetic cross orderbooks (GBPJPY, CHFJPY, CADJPY),
  fetches verified interbank NZDUSD OHLC + spot, and cross-checks all 16 pairs
  against official ECB / Frankfurter G10 reference rates (USD, GBP, JPY, CHF, AUD, CAD, NZD).
- Aggregates real-time incoming ticks into live forming OHLCV candles (LiveCandleAggregator).
- Emits canonical MarketStreamEnvelope payloads conforming strictly to
  docs/contracts/market-stream.schema.json (urn:cas-forex:market-stream:1.0),
  with all 64-bit nanosecond integers serialized as decimal strings and all prices/volumes
  serialized as plain decimal strings (zero IEEE-754 float drift).

Importing and constructing classes in this module is strictly inert (no network,
filesystem, thread, or subprocess side effects).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Context, Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
from hashlib import sha256
import json
import re
import ssl
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from cas_forex_revamp.contracts import ContractError, canonical_bytes, decimal_text, parse_decimal
from cas_forex_revamp.contracts.primitives import digest, identifier, integer, utc_time

MAX_SAFE_JS_INTEGER = (1 << 53) - 1
MAX_STREAM_WIRE_BYTES = 1_048_576

DIRECT_KRAKEN_FX_PAIRS: tuple[str, ...] = (
    "EURUSD",
    "GBPUSD",
    "USDJPY",
    "USDCHF",
    "AUDUSD",
    "USDCAD",
    "EURGBP",
    "EURJPY",
    "EURCHF",
    "EURAUD",
    "EURCAD",
    "AUDJPY",
)

EXPANDED_FX_PAIRS: tuple[str, ...] = (
    "EURUSD",
    "GBPUSD",
    "USDJPY",
    "USDCHF",
    "AUDUSD",
    "USDCAD",
    "NZDUSD",
    "EURGBP",
    "EURJPY",
    "GBPJPY",
    "EURCHF",
    "EURAUD",
    "EURCAD",
    "AUDJPY",
    "CHFJPY",
    "CADJPY",
)

EXPANDED_PAIR_SPECS: dict[str, dict[str, Any]] = {
    "EURUSD": {"display": "EUR/USD", "category": "MAJOR", "base": "EUR", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.50"), "max": Decimal("2.50"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZEURZUSD", "EURUSD", "EUR/USD"), "oanda": "EUR_USD"},
    "GBPUSD": {"display": "GBP/USD", "category": "MAJOR", "base": "GBP", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.50"), "max": Decimal("3.00"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZGBPZUSD", "GBPUSD", "GBP/USD"), "oanda": "GBP_USD"},
    "USDJPY": {"display": "USD/JPY", "category": "MAJOR", "base": "USD", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("50.0"), "max": Decimal("350.0"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZUSDZJPY", "USDJPY", "USD/JPY"), "oanda": "USD_JPY"},
    "USDCHF": {"display": "USD/CHF", "category": "MAJOR", "base": "USD", "quote": "CHF", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.40"), "max": Decimal("2.20"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("USDCHF", "USD/CHF"), "oanda": "USD_CHF"},
    "AUDUSD": {"display": "AUD/USD", "category": "MAJOR", "base": "AUD", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.30"), "max": Decimal("1.80"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("AUDUSD", "AUD/USD"), "oanda": "AUD_USD"},
    "USDCAD": {"display": "USD/CAD", "category": "MAJOR", "base": "USD", "quote": "CAD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.70"), "max": Decimal("2.50"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZUSDZCAD", "USDCAD", "USD/CAD"), "oanda": "USD_CAD"},
    "NZDUSD": {"display": "NZD/USD", "category": "MAJOR", "base": "NZD", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.30"), "max": Decimal("1.60"), "mode": "INTERBANK_YAHOO_ECB_VERIFIED", "kraken_keys": (), "yahoo": "NZDUSD=X", "oanda": "NZD_USD"},
    "EURGBP": {"display": "EUR/GBP", "category": "CROSS", "base": "EUR", "quote": "GBP", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.40"), "max": Decimal("1.60"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURGBP", "EUR/GBP"), "oanda": "EUR_GBP"},
    "EURJPY": {"display": "EUR/JPY", "category": "CROSS", "base": "EUR", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("70.0"), "max": Decimal("350.0"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURJPY", "EUR/JPY"), "oanda": "EUR_JPY"},
    "GBPJPY": {"display": "GBP/JPY", "category": "CROSS", "base": "GBP", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("90.0"), "max": Decimal("400.0"), "mode": "SYNTHETIC_KRAKEN_CROSS_BOOK", "kraken_keys": (), "legs": ("MUL", "GBPUSD", "USDJPY"), "oanda": "GBP_JPY"},
    "EURCHF": {"display": "EUR/CHF", "category": "CROSS", "base": "EUR", "quote": "CHF", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.50"), "max": Decimal("2.20"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURCHF", "EUR/CHF"), "oanda": "EUR_CHF"},
    "EURAUD": {"display": "EUR/AUD", "category": "CROSS", "base": "EUR", "quote": "AUD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.90"), "max": Decimal("3.20"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURAUD", "EUR/AUD"), "oanda": "EUR_AUD"},
    "EURCAD": {"display": "EUR/CAD", "category": "CROSS", "base": "EUR", "quote": "CAD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.90"), "max": Decimal("3.00"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURCAD", "EUR/CAD"), "oanda": "EUR_CAD"},
    "AUDJPY": {"display": "AUD/JPY", "category": "CROSS", "base": "AUD", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("40.0"), "max": Decimal("250.0"), "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("AUDJPY", "AUD/JPY"), "oanda": "AUD_JPY"},
    "CHFJPY": {"display": "CHF/JPY", "category": "CROSS", "base": "CHF", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("60.0"), "max": Decimal("380.0"), "mode": "SYNTHETIC_KRAKEN_CROSS_BOOK", "kraken_keys": (), "legs": ("DIV", "USDJPY", "USDCHF"), "oanda": "CHF_JPY"},
    "CADJPY": {"display": "CAD/JPY", "category": "CROSS", "base": "CAD", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("40.0"), "max": Decimal("250.0"), "mode": "SYNTHETIC_KRAKEN_CROSS_BOOK", "kraken_keys": (), "legs": ("DIV", "USDJPY", "USDCAD"), "oanda": "CAD_JPY"},
}

KRAKEN_EXPANDED_TICKER_URL = (
    "https://api.kraken.com/0/public/Ticker?pair=" + ",".join(DIRECT_KRAKEN_FX_PAIRS)
)
KRAKEN_OHLC_URL_TEMPLATE = "https://api.kraken.com/0/public/OHLC?pair={pair}&interval={interval}"
FRANKFURTER_G10_URLS: tuple[str, ...] = (
    "https://api.frankfurter.dev/v1/latest?base=EUR&symbols=USD,GBP,JPY,CHF,AUD,CAD,NZD",
    "https://api.frankfurter.app/latest?from=EUR&to=USD,GBP,JPY,CHF,AUD,CAD,NZD",
)
YAHOO_FX_CHART_URL_TEMPLATE = (
    "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?interval={interval}&range={range}"
)

_ALLOWED_PUBLIC_HOSTS = frozenset({
    "api.kraken.com",
    "api.frankfurter.dev",
    "api.frankfurter.app",
    "www.ecb.europa.eu",
    "query1.finance.yahoo.com",
})
_NS_DIGITS_RE = re.compile(r"^[0-9]{1,30}$")
_DATE_ISO_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ContractError(f"HTTP redirect ({code}) refused on public FX stream transport")


def _format_utc(dt: datetime) -> str:
    checked = utc_time(dt, "timestamp")
    return checked.isoformat().replace("+00:00", "Z")


def _parse_utc(value: str, field: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{field} must be an ISO-8601 UTC string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"invalid {field}: {value!r}") from exc
    return utc_time(parsed, field)


def _quantize_price(value: Decimal, tick: Decimal, *, rounding: str = ROUND_FLOOR) -> Decimal:
    with localcontext(Context(prec=50)):
        return value.quantize(tick, rounding=rounding)


def _https_get_pinned_host(url: str, *, timeout_seconds: float = 15.0, max_bytes: int = MAX_STREAM_WIRE_BYTES) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_PUBLIC_HOSTS:
        raise ContractError(f"forbidden or unpinned FX stream URL host: {parsed.hostname!r}")
    if parsed.username or parsed.password:
        raise ContractError("URL userinfo is forbidden")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(_NoRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json, text/xml;q=0.8",
            "User-Agent": "CAS-Forex-Phase6-MarketStream/1.0",
        },
    )
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            chunks: list[bytes] = []
            total = 0
            while True:
                block = resp.read(32_768)
                if not block:
                    break
                total += len(block)
                if total > max_bytes:
                    raise ContractError(f"FX stream response exceeded {max_bytes} bytes")
                chunks.append(block)
            return b"".join(chunks)
    except urllib.error.URLError as exc:
        raise ContractError(f"FX stream HTTPS transport error for {parsed.hostname}: {exc.reason}") from exc


@dataclass(frozen=True, slots=True)
class OhlcCandleBar:
    open_utc: datetime
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: Decimal
    trade_count: int

    def __post_init__(self) -> None:
        utc_time(self.open_utc, "open_utc")
        for name, val in (
            ("open_price", self.open_price),
            ("high_price", self.high_price),
            ("low_price", self.low_price),
            ("close_price", self.close_price),
        ):
            if not isinstance(val, Decimal) or not val.is_finite() or val <= 0:
                raise ContractError(f"{name} must be a positive finite Decimal")
        if not isinstance(self.volume, Decimal) or not self.volume.is_finite() or self.volume < 0:
            raise ContractError("volume must be a non-negative finite Decimal")
        integer(self.trade_count, "trade_count", minimum=0)
        if self.trade_count > MAX_SAFE_JS_INTEGER:
            raise ContractError("trade_count exceeds MAX_SAFE_JS_INTEGER")
        body_low = min(self.open_price, self.close_price)
        body_high = max(self.open_price, self.close_price)
        if self.low_price > body_low or self.high_price < body_high:
            raise ContractError(
                f"OHLC bar envelope violation: l={self.low_price} o={self.open_price} c={self.close_price} h={self.high_price}"
            )

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "t": _format_utc(self.open_utc),
            "o": decimal_text(self.open_price),
            "h": decimal_text(self.high_price),
            "l": decimal_text(self.low_price),
            "c": decimal_text(self.close_price),
            "v": decimal_text(self.volume),
            "n": self.trade_count,
        }

    @classmethod
    def from_wire_dict(cls, row: Mapping[str, Any]) -> "OhlcCandleBar":
        if set(row.keys()) != {"t", "o", "h", "l", "c", "v", "n"}:
            raise ContractError("invalid candleBar keys")
        if type(row["n"]) is not int:
            raise ContractError("candleBar.n must be int")
        return cls(
            open_utc=_parse_utc(row["t"], "candleBar.t"),
            open_price=parse_decimal(row["o"], "candleBar.o"),
            high_price=parse_decimal(row["h"], "candleBar.h"),
            low_price=parse_decimal(row["l"], "candleBar.l"),
            close_price=parse_decimal(row["c"], "candleBar.c"),
            volume=parse_decimal(row["v"], "candleBar.v"),
            trade_count=row["n"],
        )


@dataclass(frozen=True, slots=True)
class PairMarketStream:
    pair: str
    display_pair: str
    category: str
    base_currency: str
    quote_currency: str
    tick_size: Decimal
    feed_mode: str
    bid: Decimal
    ask: Decimal
    mid: Decimal
    spread_pips: Decimal
    change_24h_pct: Decimal
    ecb_reference_mid: Decimal | None
    ecb_deviation_bps: Decimal | None
    observed_at: datetime
    candles_m1: tuple[OhlcCandleBar, ...]
    candles_m5: tuple[OhlcCandleBar, ...]
    candles_h1: tuple[OhlcCandleBar, ...]

    def __post_init__(self) -> None:
        if self.pair not in EXPANDED_PAIR_SPECS:
            raise ContractError(f"unsupported FX pair {self.pair!r}")
        utc_time(self.observed_at, "observed_at")
        if self.bid <= 0 or self.ask <= self.bid:
            raise ContractError(f"{self.pair}: bid must be positive and strictly < ask (bid={self.bid}, ask={self.ask})")
        spec = EXPANDED_PAIR_SPECS[self.pair]
        if self.bid < spec["min"] or self.ask > spec["max"]:
            raise ContractError(f"{self.pair}: quote outside sanity range [{spec['min']}, {spec['max']}]")
        for label, series in (("candles_m1", self.candles_m1), ("candles_m5", self.candles_m5), ("candles_h1", self.candles_h1)):
            if not series or len(series) > 96:
                raise ContractError(f"{self.pair}.{label} must have 1..96 bars")

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "pair": self.pair,
            "display_pair": self.display_pair,
            "category": self.category,
            "base_currency": self.base_currency,
            "quote_currency": self.quote_currency,
            "tick_size": decimal_text(self.tick_size),
            "feed_mode": self.feed_mode,
            "bid": decimal_text(self.bid),
            "ask": decimal_text(self.ask),
            "mid": decimal_text(self.mid),
            "spread_pips": decimal_text(self.spread_pips),
            "change_24h_pct": decimal_text(self.change_24h_pct),
            "ecb_reference_mid": decimal_text(self.ecb_reference_mid) if self.ecb_reference_mid is not None else None,
            "ecb_deviation_bps": decimal_text(self.ecb_deviation_bps) if self.ecb_deviation_bps is not None else None,
            "observed_at": _format_utc(self.observed_at),
            "candles_m1": [c.to_wire_dict() for c in self.candles_m1],
            "candles_m5": [c.to_wire_dict() for c in self.candles_m5],
            "candles_h1": [c.to_wire_dict() for c in self.candles_h1],
        }

    @classmethod
    def from_wire_dict(cls, row: Mapping[str, Any]) -> "PairMarketStream":
        return cls(
            pair=str(row["pair"]),
            display_pair=str(row["display_pair"]),
            category=str(row["category"]),
            base_currency=str(row["base_currency"]),
            quote_currency=str(row["quote_currency"]),
            tick_size=parse_decimal(row["tick_size"], "tick_size"),
            feed_mode=str(row["feed_mode"]),
            bid=parse_decimal(row["bid"], "bid"),
            ask=parse_decimal(row["ask"], "ask"),
            mid=parse_decimal(row["mid"], "mid"),
            spread_pips=parse_decimal(row["spread_pips"], "spread_pips"),
            change_24h_pct=parse_decimal(row["change_24h_pct"], "change_24h_pct"),
            ecb_reference_mid=parse_decimal(row["ecb_reference_mid"], "ecb_reference_mid") if row["ecb_reference_mid"] is not None else None,
            ecb_deviation_bps=parse_decimal(row["ecb_deviation_bps"], "ecb_deviation_bps") if row["ecb_deviation_bps"] is not None else None,
            observed_at=_parse_utc(row["observed_at"], "observed_at"),
            candles_m1=tuple(OhlcCandleBar.from_wire_dict(c) for c in row["candles_m1"]),
            candles_m5=tuple(OhlcCandleBar.from_wire_dict(c) for c in row["candles_m5"]),
            candles_h1=tuple(OhlcCandleBar.from_wire_dict(c) for c in row["candles_h1"]),
        )


@dataclass(frozen=True, slots=True)
class MarketStreamEnvelope:
    schema_version: str
    stream_id: str
    sequence: int
    observed_at: datetime
    observed_at_ns: str
    source_mode: str
    raw_wire_sha256: str
    ecb_reference_date: str | None
    valve_status: dict[str, Any] | None
    streams: tuple[PairMarketStream, ...]
    canonical_payload_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ContractError("MarketStreamEnvelope schema_version must be '1.0'")
        identifier(self.stream_id, "stream_id")
        integer(self.sequence, "sequence", minimum=0)
        if self.sequence > MAX_SAFE_JS_INTEGER:
            raise ContractError("sequence exceeds MAX_SAFE_JS_INTEGER")
        utc_time(self.observed_at, "observed_at")
        if not isinstance(self.observed_at_ns, str) or not _NS_DIGITS_RE.fullmatch(self.observed_at_ns):
            raise ContractError("observed_at_ns must be a digits string")
        if self.source_mode not in ("LIVE_EXTERNAL_PUBLIC_FEED", "SEALED_CAPTURED_LIVE_FEED", "REHEARSAL_VENUE_FEED"):
            raise ContractError(f"unsupported source_mode {self.source_mode!r}")
        digest(self.raw_wire_sha256, "raw_wire_sha256")
        if self.ecb_reference_date is not None and not _DATE_ISO_RE.fullmatch(self.ecb_reference_date):
            raise ContractError("invalid ecb_reference_date")
        if not self.streams:
            raise ContractError("streams must be non-empty")
        seen: set[str] = set()
        for item in self.streams:
            if item.pair in seen:
                raise ContractError(f"duplicate pair in MarketStreamEnvelope: {item.pair}")
            seen.add(item.pair)
        digest(self.canonical_payload_sha256, "canonical_payload_sha256")
        expected = sha256(canonical_bytes(self._unsigned_dict())).hexdigest()
        if self.canonical_payload_sha256 != expected:
            raise ContractError("MarketStreamEnvelope canonical_payload_sha256 mismatch")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "observed_at": _format_utc(self.observed_at),
            "observed_at_ns": self.observed_at_ns,
            "source_mode": self.source_mode,
            "raw_wire_sha256": self.raw_wire_sha256,
            "ecb_reference_date": self.ecb_reference_date,
            "valve_status": self.valve_status,
            "streams": [s.to_wire_dict() for s in self.streams],
        }

    def to_wire_dict(self) -> dict[str, Any]:
        body = self._unsigned_dict()
        body["canonical_payload_sha256"] = self.canonical_payload_sha256
        return body

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_wire_dict(), indent=indent, sort_keys=False) + "\n"

    @classmethod
    def from_json_bytes(cls, raw: bytes | str) -> "MarketStreamEnvelope":
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        doc = json.loads(text)
        return cls(
            schema_version=str(doc["schema_version"]),
            stream_id=str(doc["stream_id"]),
            sequence=int(doc["sequence"]),
            observed_at=_parse_utc(doc["observed_at"], "observed_at"),
            observed_at_ns=str(doc["observed_at_ns"]),
            source_mode=str(doc["source_mode"]),
            raw_wire_sha256=str(doc["raw_wire_sha256"]),
            ecb_reference_date=doc["ecb_reference_date"],
            valve_status=doc["valve_status"],
            streams=tuple(PairMarketStream.from_wire_dict(s) for s in doc["streams"]),
            canonical_payload_sha256=str(doc["canonical_payload_sha256"]),
        )

    def pair_map(self) -> dict[str, PairMarketStream]:
        return {s.pair: s for s in self.streams}


def build_signed_market_stream_envelope(
    *,
    stream_id: str,
    sequence: int,
    observed_at: datetime,
    observed_at_ns: str,
    source_mode: str,
    raw_wire_sha256: str,
    ecb_reference_date: str | None,
    valve_status: dict[str, Any] | None,
    streams: Sequence[PairMarketStream],
) -> MarketStreamEnvelope:
    unsigned = {
        "schema_version": "1.0",
        "stream_id": stream_id,
        "sequence": sequence,
        "observed_at": _format_utc(observed_at),
        "observed_at_ns": observed_at_ns,
        "source_mode": source_mode,
        "raw_wire_sha256": raw_wire_sha256,
        "ecb_reference_date": ecb_reference_date,
        "valve_status": valve_status,
        "streams": [s.to_wire_dict() for s in streams],
    }
    payload_sha = sha256(canonical_bytes(unsigned)).hexdigest()
    return MarketStreamEnvelope(
        schema_version="1.0",
        stream_id=stream_id,
        sequence=sequence,
        observed_at=observed_at,
        observed_at_ns=observed_at_ns,
        source_mode=source_mode,
        raw_wire_sha256=raw_wire_sha256,
        ecb_reference_date=ecb_reference_date,
        valve_status=valve_status,
        streams=tuple(streams),
        canonical_payload_sha256=payload_sha,
    )


def parse_ecb_g10_reference(raw_bytes: bytes) -> tuple[str, dict[str, Decimal]]:
    doc = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("date"), str) or not isinstance(doc.get("rates"), dict):
        raise ContractError("invalid ECB G10 JSON payload")
    ref_date = doc["date"]
    rates_raw = doc["rates"]
    eur_rates: dict[str, Decimal] = {"EUR": Decimal("1")}
    for ccy in ("USD", "GBP", "JPY", "CHF", "AUD", "CAD", "NZD"):
        if ccy in rates_raw:
            val = Decimal(str(rates_raw[ccy]))
            if val <= 0:
                raise ContractError(f"nonpositive ECB rate for {ccy}")
            eur_rates[ccy] = val
    pair_refs: dict[str, Decimal] = {}
    with localcontext(Context(prec=60)):
        for pair, spec in EXPANDED_PAIR_SPECS.items():
            b_ccy, q_ccy = spec["base"], spec["quote"]
            if b_ccy in eur_rates and q_ccy in eur_rates:
                mid = (eur_rates[q_ccy] / eur_rates[b_ccy]).quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR)
                pair_refs[pair] = mid
    return ref_date, pair_refs


def _parse_kraken_ohlc_bars(raw_bytes: bytes, *, tick: Decimal, max_bars: int) -> list[OhlcCandleBar]:
    doc = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("error"):
        raise ContractError(f"Kraken OHLC error: {doc.get('error') if isinstance(doc, dict) else 'non-object'}")
    result = doc.get("result") or {}
    rows = None
    for k, v in result.items():
        if k != "last" and isinstance(v, list):
            rows = v
            break
    if not rows:
        raise ContractError("Kraken OHLC response contained no candle array")
    bars: list[OhlcCandleBar] = []
    for row in rows[-max_bars:]:
        if not isinstance(row, list) or len(row) < 8:
            continue
        ts_sec = int(row[0])
        open_dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
        o = _quantize_price(Decimal(str(row[1])), tick)
        h = _quantize_price(Decimal(str(row[2])), tick, rounding=ROUND_CEILING)
        l = _quantize_price(Decimal(str(row[3])), tick, rounding=ROUND_FLOOR)
        c = _quantize_price(Decimal(str(row[4])), tick)
        h = max(h, o, c)
        l = min(l, o, c)
        vol = Decimal(str(row[6])).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
        cnt = max(0, min(MAX_SAFE_JS_INTEGER, int(row[7])))
        bars.append(OhlcCandleBar(open_dt, o, h, l, c, vol, cnt))
    if not bars:
        raise ContractError("no valid OHLC bars parsed from Kraken")
    return bars


def _synthesize_cross_candles(
    bars_a: Sequence[OhlcCandleBar],
    bars_b: Sequence[OhlcCandleBar],
    *,
    op: str,
    tick: Decimal,
    max_bars: int,
) -> list[OhlcCandleBar]:
    by_time_b = {b.open_utc: b for b in bars_b}
    aligned = [(a, by_time_b[a.open_utc]) for a in bars_a if a.open_utc in by_time_b]
    if not aligned:
        n = min(len(bars_a), len(bars_b))
        aligned = list(zip(bars_a[-n:], bars_b[-n:]))
    out: list[OhlcCandleBar] = []
    with localcontext(Context(prec=50)):
        for a, b in aligned[-max_bars:]:
            if op == "MUL":
                o = _quantize_price(a.open_price * b.open_price, tick)
                c = _quantize_price(a.close_price * b.close_price, tick)
                h = _quantize_price(a.high_price * b.high_price, tick, rounding=ROUND_CEILING)
                l = _quantize_price(a.low_price * b.low_price, tick, rounding=ROUND_FLOOR)
            else:
                o = _quantize_price(a.open_price / b.open_price, tick)
                c = _quantize_price(a.close_price / b.close_price, tick)
                h = _quantize_price(a.high_price / b.low_price, tick, rounding=ROUND_CEILING)
                l = _quantize_price(a.low_price / b.high_price, tick, rounding=ROUND_FLOOR)
            h = max(h, o, c)
            l = min(l, o, c)
            vol = (a.volume + b.volume).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
            cnt = min(MAX_SAFE_JS_INTEGER, a.trade_count + b.trade_count)
            out.append(OhlcCandleBar(a.open_utc, o, h, l, c, vol, cnt))
    return out


def _parse_yahoo_fx_candles(raw_bytes: bytes, *, tick: Decimal, max_bars: int) -> tuple[Decimal, list[OhlcCandleBar]]:
    doc = json.loads(raw_bytes.decode("utf-8"))
    res = doc["chart"]["result"][0]
    meta = res["meta"]
    spot = _quantize_price(Decimal(str(meta["regularMarketPrice"])), tick)
    timestamps = res.get("timestamp") or []
    quote = res["indicators"]["quote"][0]
    opens, highs, lows, closes = quote["open"], quote["high"], quote["low"], quote["close"]
    vols = quote.get("volume") or [0] * len(timestamps)
    bars: list[OhlcCandleBar] = []
    for ts, o_raw, h_raw, l_raw, c_raw, v_raw in zip(timestamps, opens, highs, lows, closes, vols):
        if o_raw is None or h_raw is None or l_raw is None or c_raw is None:
            continue
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        o = _quantize_price(Decimal(str(o_raw)), tick)
        c = _quantize_price(Decimal(str(c_raw)), tick)
        h = max(o, c, _quantize_price(Decimal(str(h_raw)), tick, rounding=ROUND_CEILING))
        l = min(o, c, _quantize_price(Decimal(str(l_raw)), tick, rounding=ROUND_FLOOR))
        v = Decimal(str(v_raw or 0)).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
        bars.append(OhlcCandleBar(dt, o, h, l, c, max(Decimal("0"), v), 1))
    if not bars:
        raise ContractError("no valid Yahoo FX candles")
    return spot, bars[-max_bars:]


def _anchor_last_bar_to_mid(bars: list[OhlcCandleBar], mid: Decimal, tick: Decimal) -> list[OhlcCandleBar]:
    if not bars:
        return bars
    last = bars[-1]
    c = _quantize_price(mid, tick)
    h = max(last.high_price, last.open_price, c)
    l = min(last.low_price, last.open_price, c)
    updated = OhlcCandleBar(last.open_utc, last.open_price, h, l, c, last.volume, last.trade_count + 1)
    return [*bars[:-1], updated]


class LiveCandleAggregator:
    """Maintains multi-currency M1/M5/H1 candle series and updates forming bars on every incoming tick."""

    def __init__(self, initial_envelope: MarketStreamEnvelope) -> None:
        self._sequence = initial_envelope.sequence
        self._source_mode = initial_envelope.source_mode
        self._ecb_date = initial_envelope.ecb_reference_date
        self._raw_wire_sha256 = initial_envelope.raw_wire_sha256
        self._valve_status = initial_envelope.valve_status
        self._streams: dict[str, PairMarketStream] = {s.pair: s for s in initial_envelope.streams}
        self._order: list[str] = [s.pair for s in initial_envelope.streams]

    @staticmethod
    def _bucket_start(dt: datetime, minutes: int) -> datetime:
        epoch_s = int(dt.timestamp())
        bucket_s = (epoch_s // (minutes * 60)) * (minutes * 60)
        return datetime.fromtimestamp(bucket_s, tz=timezone.utc)

    @classmethod
    def _update_series(
        cls,
        series: tuple[OhlcCandleBar, ...],
        *,
        minutes: int,
        mid: Decimal,
        tick: Decimal,
        now: datetime,
        max_len: int,
    ) -> tuple[OhlcCandleBar, ...]:
        bucket = cls._bucket_start(now, minutes)
        px = _quantize_price(mid, tick)
        bars = list(series)
        if bars and bars[-1].open_utc == bucket:
            last = bars[-1]
            bars[-1] = OhlcCandleBar(
                open_utc=last.open_utc,
                open_price=last.open_price,
                high_price=max(last.high_price, px),
                low_price=min(last.low_price, px),
                close_price=px,
                volume=(last.volume + Decimal("1.00")).quantize(Decimal("0.01")),
                trade_count=min(MAX_SAFE_JS_INTEGER, last.trade_count + 1),
            )
        elif not bars or bucket > bars[-1].open_utc:
            open_px = bars[-1].close_price if bars else px
            bars.append(
                OhlcCandleBar(
                    open_utc=bucket,
                    open_price=open_px,
                    high_price=max(open_px, px),
                    low_price=min(open_px, px),
                    close_price=px,
                    volume=Decimal("1.00"),
                    trade_count=1,
                )
            )
        return tuple(bars[-max_len:])

    def ingest_quotes(
        self,
        quotes_by_pair: Mapping[str, tuple[Decimal, Decimal]],
        *,
        observed_at: datetime,
        raw_wire_sha256: str | None = None,
        valve_status: dict[str, Any] | None = None,
    ) -> MarketStreamEnvelope:
        checked_now = utc_time(observed_at, "observed_at")
        self._sequence += 1
        if raw_wire_sha256 is not None:
            digest(raw_wire_sha256, "raw_wire_sha256")
            self._raw_wire_sha256 = raw_wire_sha256
        if valve_status is not None:
            self._valve_status = valve_status

        with localcontext(Context(prec=50)):
            for pair, (raw_bid, raw_ask) in quotes_by_pair.items():
                if pair not in self._streams:
                    continue
                cur = self._streams[pair]
                spec = EXPANDED_PAIR_SPECS[pair]
                tick = spec["tick"]
                pip = spec["pip"]
                bid = _quantize_price(raw_bid, tick, rounding=ROUND_FLOOR)
                ask = _quantize_price(raw_ask, tick, rounding=ROUND_CEILING)
                if ask <= bid:
                    ask = bid + tick
                mid = _quantize_price((bid + ask) / Decimal("2"), tick)
                spread_pips = ((ask - bid) / pip).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)
                first_h1 = cur.candles_h1[0].open_price if cur.candles_h1 else mid
                chg_pct = (((mid - first_h1) / first_h1) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
                dev_bps = None
                if cur.ecb_reference_mid is not None and cur.ecb_reference_mid > 0:
                    dev_bps = ((abs(mid - cur.ecb_reference_mid) / cur.ecb_reference_mid) * Decimal("10000")).quantize(
                        Decimal("0.1"), rounding=ROUND_FLOOR
                    )
                self._streams[pair] = PairMarketStream(
                    pair=pair,
                    display_pair=cur.display_pair,
                    category=cur.category,
                    base_currency=cur.base_currency,
                    quote_currency=cur.quote_currency,
                    tick_size=cur.tick_size,
                    feed_mode=cur.feed_mode,
                    bid=bid,
                    ask=ask,
                    mid=mid,
                    spread_pips=spread_pips,
                    change_24h_pct=chg_pct,
                    ecb_reference_mid=cur.ecb_reference_mid,
                    ecb_deviation_bps=dev_bps,
                    observed_at=checked_now,
                    candles_m1=self._update_series(cur.candles_m1, minutes=1, mid=mid, tick=tick, now=checked_now, max_len=24),
                    candles_m5=self._update_series(cur.candles_m5, minutes=5, mid=mid, tick=tick, now=checked_now, max_len=36),
                    candles_h1=self._update_series(cur.candles_h1, minutes=60, mid=mid, tick=tick, now=checked_now, max_len=24),
                )

        epoch_ns = str(int(checked_now.timestamp() * 1_000_000_000))
        return build_signed_market_stream_envelope(
            stream_id=f"fxstream-{self._sequence}",
            sequence=self._sequence,
            observed_at=checked_now,
            observed_at_ns=epoch_ns,
            source_mode=self._source_mode,
            raw_wire_sha256=self._raw_wire_sha256,
            ecb_reference_date=self._ecb_date,
            valve_status=self._valve_status,
            streams=[self._streams[p] for p in self._order],
        )


class ExpandedPublicLiveFxFeedClient:
    """Fetches all 16 G10 major & cross FX pairs + live M1/M5/H1 candlestick series."""

    def __init__(
        self,
        *,
        http_get: Callable[[str, float, int], bytes] | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ContractError("timeout_seconds must be in (0, 60]")
        self._timeout = float(timeout_seconds)
        self._http_get = http_get or (lambda url, t, m: _https_get_pinned_host(url, timeout_seconds=t, max_bytes=m))

    def _get(self, url: str) -> bytes:
        return self._http_get(url, self._timeout, MAX_STREAM_WIRE_BYTES)

    def fetch_live_ohlc_candles(
        self,
        pair: str,
        *,
        interval_minutes: int = 5,
        max_bars: int = 36,
    ) -> tuple[OhlcCandleBar, ...]:
        if pair not in EXPANDED_PAIR_SPECS:
            raise ContractError(f"unsupported FX pair {pair!r}")
        if interval_minutes not in (1, 5, 15, 60):
            raise ContractError("interval_minutes must be one of 1, 5, 15, 60")
        spec = EXPANDED_PAIR_SPECS[pair]
        tick = spec["tick"]
        if spec["mode"] == "DIRECT_KRAKEN_ORDERBOOK":
            raw = self._get(KRAKEN_OHLC_URL_TEMPLATE.format(pair=pair, interval=interval_minutes))
            return tuple(_parse_kraken_ohlc_bars(raw, tick=tick, max_bars=max_bars))
        if spec["mode"] == "SYNTHETIC_KRAKEN_CROSS_BOOK":
            op, la, lb = spec["legs"]
            ba = self.fetch_live_ohlc_candles(la, interval_minutes=interval_minutes, max_bars=max_bars)
            bb = self.fetch_live_ohlc_candles(lb, interval_minutes=interval_minutes, max_bars=max_bars)
            return tuple(_synthesize_cross_candles(ba, bb, op=op, tick=tick, max_bars=max_bars))
        y_int = f"{interval_minutes}m"
        raw = self._get(YAHOO_FX_CHART_URL_TEMPLATE.format(symbol=spec["yahoo"], interval=y_int, range="5d"))
        _, bars = _parse_yahoo_fx_candles(raw, tick=tick, max_bars=max_bars)
        return tuple(bars)

    def fetch_market_stream(
        self,
        *,
        pairs: Sequence[str] = EXPANDED_FX_PAIRS,
        sequence: int = 1,
        now: datetime | None = None,
        valve_status: dict[str, Any] | None = None,
        m1_bars: int = 24,
        m5_bars: int = 36,
        h1_bars: int = 24,
    ) -> MarketStreamEnvelope:
        observed = utc_time(now, "now") if now is not None else datetime.now(timezone.utc)
        observed_ns = str(time.time_ns() if now is None else int(observed.timestamp() * 1_000_000_000))

        ecb_date: str | None = None
        ecb_refs: dict[str, Decimal] = {}
        raw_blobs: list[bytes] = []
        for ecb_url in FRANKFURTER_G10_URLS:
            try:
                ecb_raw = self._get(ecb_url)
                ecb_date, ecb_refs = parse_ecb_g10_reference(ecb_raw)
                raw_blobs.append(ecb_raw)
                break
            except (ContractError, ValueError, KeyError):
                continue

        ticker_raw = self._get(KRAKEN_EXPANDED_TICKER_URL)
        raw_blobs.append(ticker_raw)
        ticker_doc = json.loads(ticker_raw.decode("utf-8"))
        if ticker_doc.get("error"):
            raise ContractError(f"Kraken expanded Ticker error: {ticker_doc['error']}")
        result_map = ticker_doc.get("result") or {}

        direct_quotes: dict[str, tuple[Decimal, Decimal]] = {}
        for dpair in DIRECT_KRAKEN_FX_PAIRS:
            spec = EXPANDED_PAIR_SPECS[dpair]
            entry = None
            for alias in spec["kraken_keys"]:
                if alias in result_map:
                    entry = result_map[alias]
                    break
            if entry is None:
                raise ContractError(f"Kraken Ticker missing direct pair {dpair}")
            tick = spec["tick"]
            bid = _quantize_price(Decimal(str(entry["b"][0])), tick, rounding=ROUND_FLOOR)
            ask = _quantize_price(Decimal(str(entry["a"][0])), tick, rounding=ROUND_CEILING)
            if ask <= bid:
                ask = bid + tick
            direct_quotes[dpair] = (bid, ask)

        needed_direct: set[str] = set()
        for p in pairs:
            spec = EXPANDED_PAIR_SPECS[p]
            if spec["mode"] == "DIRECT_KRAKEN_ORDERBOOK":
                needed_direct.add(p)
            elif spec["mode"] == "SYNTHETIC_KRAKEN_CROSS_BOOK":
                _, leg_a, leg_b = spec["legs"]
                needed_direct.add(leg_a)
                needed_direct.add(leg_b)

        direct_candles: dict[str, dict[str, list[OhlcCandleBar]]] = {}
        for dpair in sorted(needed_direct):
            tick = EXPANDED_PAIR_SPECS[dpair]["tick"]
            c_m1_raw = self._get(KRAKEN_OHLC_URL_TEMPLATE.format(pair=dpair, interval=1))
            c_m5_raw = self._get(KRAKEN_OHLC_URL_TEMPLATE.format(pair=dpair, interval=5))
            c_h1_raw = self._get(KRAKEN_OHLC_URL_TEMPLATE.format(pair=dpair, interval=60))
            raw_blobs.extend((c_m1_raw, c_m5_raw, c_h1_raw))
            direct_candles[dpair] = {
                "m1": _parse_kraken_ohlc_bars(c_m1_raw, tick=tick, max_bars=m1_bars),
                "m5": _parse_kraken_ohlc_bars(c_m5_raw, tick=tick, max_bars=m5_bars),
                "h1": _parse_kraken_ohlc_bars(c_h1_raw, tick=tick, max_bars=h1_bars),
            }

        pair_streams: list[PairMarketStream] = []
        with localcontext(Context(prec=50)):
            for pair in pairs:
                spec = EXPANDED_PAIR_SPECS[pair]
                tick = spec["tick"]
                pip = spec["pip"]
                mode = spec["mode"]

                if mode == "DIRECT_KRAKEN_ORDERBOOK":
                    bid, ask = direct_quotes[pair]
                    c_m1 = direct_candles[pair]["m1"]
                    c_m5 = direct_candles[pair]["m5"]
                    c_h1 = direct_candles[pair]["h1"]
                elif mode == "SYNTHETIC_KRAKEN_CROSS_BOOK":
                    op, leg_a, leg_b = spec["legs"]
                    bid_a, ask_a = direct_quotes[leg_a]
                    bid_b, ask_b = direct_quotes[leg_b]
                    if op == "MUL":
                        bid = _quantize_price(bid_a * bid_b, tick, rounding=ROUND_FLOOR)
                        ask = _quantize_price(ask_a * ask_b, tick, rounding=ROUND_CEILING)
                    else:
                        bid = _quantize_price(bid_a / ask_b, tick, rounding=ROUND_FLOOR)
                        ask = _quantize_price(ask_a / bid_b, tick, rounding=ROUND_CEILING)
                    if ask <= bid:
                        ask = bid + tick
                    c_m1 = _synthesize_cross_candles(direct_candles[leg_a]["m1"], direct_candles[leg_b]["m1"], op=op, tick=tick, max_bars=m1_bars)
                    c_m5 = _synthesize_cross_candles(direct_candles[leg_a]["m5"], direct_candles[leg_b]["m5"], op=op, tick=tick, max_bars=m5_bars)
                    c_h1 = _synthesize_cross_candles(direct_candles[leg_a]["h1"], direct_candles[leg_b]["h1"], op=op, tick=tick, max_bars=h1_bars)
                else:
                    ysym = spec["yahoo"]
                    y_m5_raw = self._get(YAHOO_FX_CHART_URL_TEMPLATE.format(symbol=ysym, interval="5m", range="5d"))
                    y_h1_raw = self._get(YAHOO_FX_CHART_URL_TEMPLATE.format(symbol=ysym, interval="60m", range="5d"))
                    raw_blobs.extend((y_m5_raw, y_h1_raw))
                    spot, c_m5 = _parse_yahoo_fx_candles(y_m5_raw, tick=tick, max_bars=m5_bars)
                    _, c_h1 = _parse_yahoo_fx_candles(y_h1_raw, tick=tick, max_bars=h1_bars)
                    c_m1 = c_m5[-m1_bars:]
                    half_spread = pip * Decimal("1.2")
                    bid = _quantize_price(spot - half_spread, tick, rounding=ROUND_FLOOR)
                    ask = _quantize_price(spot + half_spread, tick, rounding=ROUND_CEILING)
                    if ask <= bid:
                        ask = bid + tick

                mid = _quantize_price((bid + ask) / Decimal("2"), tick)
                c_m1 = _anchor_last_bar_to_mid(c_m1, mid, tick)
                c_m5 = _anchor_last_bar_to_mid(c_m5, mid, tick)
                c_h1 = _anchor_last_bar_to_mid(c_h1, mid, tick)

                spread_pips = ((ask - bid) / pip).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)
                first_open = c_h1[0].open_price if c_h1 else mid
                chg_pct = (((mid - first_open) / first_open) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)

                ref_mid = ecb_refs.get(pair)
                dev_bps = None
                if ref_mid is not None and ref_mid > 0:
                    dev_bps = ((abs(mid - ref_mid) / ref_mid) * Decimal("10000")).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)

                pair_streams.append(
                    PairMarketStream(
                        pair=pair,
                        display_pair=spec["display"],
                        category=spec["category"],
                        base_currency=spec["base"],
                        quote_currency=spec["quote"],
                        tick_size=tick,
                        feed_mode=mode,
                        bid=bid,
                        ask=ask,
                        mid=mid,
                        spread_pips=spread_pips,
                        change_24h_pct=chg_pct,
                        ecb_reference_mid=ref_mid,
                        ecb_deviation_bps=dev_bps,
                        observed_at=observed,
                        candles_m1=tuple(c_m1),
                        candles_m5=tuple(c_m5),
                        candles_h1=tuple(c_h1),
                    )
                )

        combined_wire_sha = sha256(b"\n--WIRE-BOUNDARY--\n".join(raw_blobs)).hexdigest()
        return build_signed_market_stream_envelope(
            stream_id=f"fxstream-{sequence}",
            sequence=sequence,
            observed_at=observed,
            observed_at_ns=observed_ns,
            source_mode="LIVE_EXTERNAL_PUBLIC_FEED",
            raw_wire_sha256=combined_wire_sha,
            ecb_reference_date=ecb_date,
            valve_status=valve_status,
            streams=pair_streams,
        )

    def fetch_live_spot_tick_map(self) -> tuple[dict[str, tuple[Decimal, Decimal]], str]:
        raw = self._get(KRAKEN_EXPANDED_TICKER_URL)
        wire_sha = sha256(raw).hexdigest()
        doc = json.loads(raw.decode("utf-8"))
        if doc.get("error"):
            raise ContractError(f"Kraken live tick error: {doc['error']}")
        result_map = doc.get("result") or {}
        out: dict[str, tuple[Decimal, Decimal]] = {}
        for dpair in DIRECT_KRAKEN_FX_PAIRS:
            spec = EXPANDED_PAIR_SPECS[dpair]
            for alias in spec["kraken_keys"]:
                if alias in result_map:
                    entry = result_map[alias]
                    tick = spec["tick"]
                    b = _quantize_price(Decimal(str(entry["b"][0])), tick, rounding=ROUND_FLOOR)
                    a = _quantize_price(Decimal(str(entry["a"][0])), tick, rounding=ROUND_CEILING)
                    if a <= b:
                        a = b + tick
                    out[dpair] = (b, a)
                    break
        with localcontext(Context(prec=50)):
            for spair in ("GBPJPY", "CHFJPY", "CADJPY"):
                spec = EXPANDED_PAIR_SPECS[spair]
                op, la, lb = spec["legs"]
                if la in out and lb in out:
                    tick = spec["tick"]
                    ba, aa = out[la]
                    bb, ab = out[lb]
                    if op == "MUL":
                        b = _quantize_price(ba * bb, tick, rounding=ROUND_FLOOR)
                        a = _quantize_price(aa * ab, tick, rounding=ROUND_CEILING)
                    else:
                        b = _quantize_price(ba / ab, tick, rounding=ROUND_FLOOR)
                        a = _quantize_price(aa / bb, tick, rounding=ROUND_CEILING)
                    if a <= b:
                        a = b + tick
                    out[spair] = (b, a)
        return out, wire_sha
