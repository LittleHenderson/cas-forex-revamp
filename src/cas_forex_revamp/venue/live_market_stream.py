"""Expanded 16-pair G10 spot FX & multi-timeframe OHLCV candlestick stream.

Phase 6 live market stream module:
- Expands spot FX coverage from 3 pairs to 16 major and cross pairs:
  Majors (7): EURUSD, GBPUSD, USDJPY, USDCHF, AUDUSD, USDCAD, NZDUSD
  Crosses (9): EURGBP, EURJPY, GBPJPY, EURCHF, EURAUD, EURCAD, AUDJPY, CHFJPY, CADJPY
- Fetches real live Kraken public orderbook Ticker + OHLCV candles (M1, M5, H1),
  derives exact two-sided synthetic cross orderbooks (GBPJPY, CHFJPY, CADJPY),
  fetches verified interbank NZDUSD OHLC + spot, and cross-checks all 16 pairs
  against official ECB / Frankfurter G10 reference rates (USD, GBP, JPY, CHF, AUD, CAD, NZD).
- Fails closed when independent reference rates are unavailable, stale beyond
  max_reference_age_days, or breached on pair-specific deviation or spread ceilings.
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
from datetime import date, datetime, timezone
from decimal import Context, Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR, localcontext
from hashlib import sha256
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from cas_forex_revamp.contracts import ContractError, canonical_bytes, decimal_text, parse_decimal
from cas_forex_revamp.contracts.primitives import decimal_value, digest, identifier, integer, utc_time
from cas_forex_revamp.contracts.tls_context import (
    _TLS_CONTEXT_CACHE,
    _TLS_CONTEXT_CACHE_LOCK,
    get_cached_tls12_ssl_context,
)

MAX_SAFE_JS_INTEGER = (1 << 53) - 1
MAX_STREAM_WIRE_BYTES = 1_048_576
DEFAULT_MAX_REFERENCE_AGE_DAYS = 5

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

INDEX_INSTRUMENTS: tuple[str, ...] = ("NAS100", "US30", "SPX500", "XAUUSD")

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

PAIR_MAX_REFERENCE_DEVIATION_BPS: dict[str, Decimal] = {
    "EURUSD": Decimal("250"),
    "GBPUSD": Decimal("250"),
    "USDJPY": Decimal("300"),
    "USDCHF": Decimal("300"),
    "AUDUSD": Decimal("300"),
    "USDCAD": Decimal("250"),
    "NZDUSD": Decimal("300"),
    "EURGBP": Decimal("250"),
    "EURJPY": Decimal("350"),
    "GBPJPY": Decimal("350"),
    "EURCHF": Decimal("250"),
    "EURAUD": Decimal("350"),
    "EURCAD": Decimal("350"),
    "AUDJPY": Decimal("350"),
    "CHFJPY": Decimal("350"),
    "CADJPY": Decimal("350"),
}

PAIR_MAX_SPREAD_BPS: dict[str, Decimal] = {
    "EURUSD": Decimal("100"),
    "GBPUSD": Decimal("100"),
    "USDJPY": Decimal("300"),
    "USDCHF": Decimal("100"),
    "AUDUSD": Decimal("100"),
    "USDCAD": Decimal("100"),
    "NZDUSD": Decimal("100"),
    "EURGBP": Decimal("100"),
    "EURJPY": Decimal("300"),
    "GBPJPY": Decimal("350"),
    "EURCHF": Decimal("100"),
    "EURAUD": Decimal("200"),
    "EURCAD": Decimal("200"),
    "AUDJPY": Decimal("300"),
    "CHFJPY": Decimal("350"),
    "CADJPY": Decimal("350"),
}

EXPANDED_MARKETS: tuple[str, ...] = INDEX_INSTRUMENTS + EXPANDED_FX_PAIRS

EXPANDED_PAIR_SPECS: dict[str, dict[str, Any]] = {
    "EURUSD": {"display": "EUR/USD", "category": "MAJOR", "base": "EUR", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.50"), "max": Decimal("2.50"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["EURUSD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["EURUSD"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZEURZUSD", "EURUSD", "EUR/USD"), "oanda": "EUR_USD"},
    "GBPUSD": {"display": "GBP/USD", "category": "MAJOR", "base": "GBP", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.50"), "max": Decimal("3.00"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["GBPUSD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["GBPUSD"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZGBPZUSD", "GBPUSD", "GBP/USD"), "oanda": "GBP_USD"},
    "USDJPY": {"display": "USD/JPY", "category": "MAJOR", "base": "USD", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("50.0"), "max": Decimal("350.0"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["USDJPY"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["USDJPY"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZUSDZJPY", "USDJPY", "USD/JPY"), "oanda": "USD_JPY"},
    "USDCHF": {"display": "USD/CHF", "category": "MAJOR", "base": "USD", "quote": "CHF", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.40"), "max": Decimal("2.20"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["USDCHF"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["USDCHF"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("USDCHF", "USD/CHF"), "oanda": "USD_CHF"},
    "AUDUSD": {"display": "AUD/USD", "category": "MAJOR", "base": "AUD", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.30"), "max": Decimal("1.80"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["AUDUSD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["AUDUSD"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("AUDUSD", "AUD/USD"), "oanda": "AUD_USD"},
    "USDCAD": {"display": "USD/CAD", "category": "MAJOR", "base": "USD", "quote": "CAD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.70"), "max": Decimal("2.50"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["USDCAD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["USDCAD"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("ZUSDZCAD", "USDCAD", "USD/CAD"), "oanda": "USD_CAD"},
    "NZDUSD": {"display": "NZD/USD", "category": "MAJOR", "base": "NZD", "quote": "USD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.30"), "max": Decimal("1.60"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["NZDUSD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["NZDUSD"], "mode": "INTERBANK_YAHOO_ECB_VERIFIED", "kraken_keys": (), "yahoo": "NZDUSD=X", "oanda": "NZD_USD"},
    "EURGBP": {"display": "EUR/GBP", "category": "CROSS", "base": "EUR", "quote": "GBP", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.40"), "max": Decimal("1.60"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["EURGBP"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["EURGBP"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURGBP", "EUR/GBP"), "oanda": "EUR_GBP"},
    "EURJPY": {"display": "EUR/JPY", "category": "CROSS", "base": "EUR", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("70.0"), "max": Decimal("350.0"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["EURJPY"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["EURJPY"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURJPY", "EUR/JPY"), "oanda": "EUR_JPY"},
    "GBPJPY": {"display": "GBP/JPY", "category": "CROSS", "base": "GBP", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("90.0"), "max": Decimal("400.0"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["GBPJPY"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["GBPJPY"], "mode": "SYNTHETIC_KRAKEN_CROSS_BOOK", "kraken_keys": (), "legs": ("MUL", "GBPUSD", "USDJPY"), "oanda": "GBP_JPY"},
    "EURCHF": {"display": "EUR/CHF", "category": "CROSS", "base": "EUR", "quote": "CHF", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.50"), "max": Decimal("2.20"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["EURCHF"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["EURCHF"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURCHF", "EUR/CHF"), "oanda": "EUR_CHF"},
    "EURAUD": {"display": "EUR/AUD", "category": "CROSS", "base": "EUR", "quote": "AUD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.90"), "max": Decimal("3.20"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["EURAUD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["EURAUD"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURAUD", "EUR/AUD"), "oanda": "EUR_AUD"},
    "EURCAD": {"display": "EUR/CAD", "category": "CROSS", "base": "EUR", "quote": "CAD", "tick": Decimal("0.00001"), "pip": Decimal("0.0001"), "min": Decimal("0.90"), "max": Decimal("3.00"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["EURCAD"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["EURCAD"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("EURCAD", "EUR/CAD"), "oanda": "EUR_CAD"},
    "AUDJPY": {"display": "AUD/JPY", "category": "CROSS", "base": "AUD", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("40.0"), "max": Decimal("250.0"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["AUDJPY"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["AUDJPY"], "mode": "DIRECT_KRAKEN_ORDERBOOK", "kraken_keys": ("AUDJPY", "AUD/JPY"), "oanda": "AUD_JPY"},
    "CHFJPY": {"display": "CHF/JPY", "category": "CROSS", "base": "CHF", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("60.0"), "max": Decimal("380.0"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["CHFJPY"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["CHFJPY"], "mode": "SYNTHETIC_KRAKEN_CROSS_BOOK", "kraken_keys": (), "legs": ("DIV", "USDJPY", "USDCHF"), "oanda": "CHF_JPY"},
    "CADJPY": {"display": "CAD/JPY", "category": "CROSS", "base": "CAD", "quote": "JPY", "tick": Decimal("0.001"), "pip": Decimal("0.01"), "min": Decimal("40.0"), "max": Decimal("250.0"), "max_ref_dev_bps": PAIR_MAX_REFERENCE_DEVIATION_BPS["CADJPY"], "max_spread_bps": PAIR_MAX_SPREAD_BPS["CADJPY"], "mode": "SYNTHETIC_KRAKEN_CROSS_BOOK", "kraken_keys": (), "legs": ("DIV", "USDJPY", "USDCAD"), "oanda": "CAD_JPY"},
}

INDEX_MARKET_SPECS: dict[str, dict[str, Any]] = {
    "NAS100": {
        "display": "NAS100 / Nasdaq-100",
        "category": "US_INDEX",
        "base_currency": "NAS100",
        "quote_currency": "USD",
        "tick": Decimal("0.01"),
        "point": Decimal("1.0"),
        "min": Decimal("5000.00"),
        "max": Decimal("60000.00"),
        "max_ref_dev_bps": Decimal("150"),
        "max_spread_bps": Decimal("35"),
        "yahoo_paths": ("/v8/finance/chart/NQ=F", "/v8/finance/chart/%5ENDX"),
        "oanda": "NAS100_USD",
    },
    "US30": {
        "display": "US30 / Dow Jones 30",
        "category": "US_INDEX",
        "base_currency": "US30",
        "quote_currency": "USD",
        "tick": Decimal("0.01"),
        "point": Decimal("1.0"),
        "min": Decimal("10000.00"),
        "max": Decimal("100000.00"),
        "max_ref_dev_bps": Decimal("150"),
        "max_spread_bps": Decimal("35"),
        "yahoo_paths": ("/v8/finance/chart/YM=F", "/v8/finance/chart/%5EDJI"),
        "oanda": "US30_USD",
    },
    "SPX500": {
        "display": "SPX500 / S&P 500",
        "category": "US_INDEX",
        "base_currency": "SPX500",
        "quote_currency": "USD",
        "tick": Decimal("0.01"),
        "point": Decimal("1.0"),
        "min": Decimal("1500.00"),
        "max": Decimal("20000.00"),
        "max_ref_dev_bps": Decimal("150"),
        "max_spread_bps": Decimal("35"),
        "yahoo_paths": ("/v8/finance/chart/ES=F", "/v8/finance/chart/%5EGSPC"),
        "oanda": "SPX500_USD",
    },
    "XAUUSD": {
        "display": "XAU/USD · Spot Gold",
        "category": "US_INDEX",
        "base_currency": "XAU",
        "quote_currency": "USD",
        "tick": Decimal("0.01"),
        "point": Decimal("1.0"),
        "min": Decimal("800.00"),
        "max": Decimal("15000.00"),
        "max_ref_dev_bps": Decimal("150"),
        "max_spread_bps": Decimal("40"),
        "yahoo_paths": ("/v8/finance/chart/GC=F", "/v8/finance/chart/XAUUSD=X"),
        "oanda": "XAU_USD",
    },
}

KRAKEN_EXPANDED_TICKER_URL = (
    "https://api.kraken.com/0/public/Ticker?pair=" + ",".join(DIRECT_KRAKEN_FX_PAIRS)
)
KRAKEN_OHLC_URL_TEMPLATE = "https://api.kraken.com/0/public/OHLC?pair={pair}&interval={interval}"
FRANKFURTER_G10_URLS: tuple[str, ...] = (
    "https://api.frankfurter.dev/v1/latest?base=EUR&symbols=USD,GBP,JPY,CHF,AUD,CAD,NZD",
    "https://api.frankfurter.app/latest?from=EUR&to=USD,GBP,JPY,CHF,AUD,CAD,NZD",
)
ECB_DAILY_XML_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
YAHOO_FX_CHART_URL_TEMPLATE = (
    "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?interval={interval}&range={range}"
)

PINNED_PUBLIC_FEED_HOST_PATHS: dict[str, frozenset[str]] = {
    "api.kraken.com": frozenset({"/0/public/Ticker", "/0/public/OHLC"}),
    "www.ecb.europa.eu": frozenset({"/stats/eurofxref/eurofxref-daily.xml"}),
    "data-api.ecb.europa.eu": frozenset({"/service/data/EXR"}),
    "api.frankfurter.dev": frozenset({"/v1/latest"}),
    "api.frankfurter.app": frozenset({"/latest"}),
}
ALLOWED_PUBLIC_FEED_HOSTS: frozenset[str] = frozenset(PINNED_PUBLIC_FEED_HOST_PATHS.keys())
_YAHOO_INDEX_ENCODED_PATHS: frozenset[str] = frozenset({
    "/v8/finance/chart/%5ENDX",
    "/v8/finance/chart/NQ=F",
    "/v8/finance/chart/%5EDJI",
    "/v8/finance/chart/YM=F",
    "/v8/finance/chart/%5EGSPC",
    "/v8/finance/chart/ES=F",
    "/v8/finance/chart/GC=F",
    "/v8/finance/chart/XAUUSD=X",
})
_YAHOO_ALLOWED_CHART_PATHS: frozenset[str] = frozenset({"/v8/finance/chart/NZDUSD=X"}) | _YAHOO_INDEX_ENCODED_PATHS
_ALLOWED_PUBLIC_HOSTS: frozenset[str] = ALLOWED_PUBLIC_FEED_HOSTS | frozenset({"query1.finance.yahoo.com"})

_FORBIDDEN_LIVE_HOST_TOKENS: tuple[str, ...] = (
    "api-fxtrade.oanda.com",
    "stream-fxtrade.oanda.com",
    "fxtrade",
)
_ECB_DATA_API_EXR_PATH_RE = re.compile(r"^/service/data/EXR(?:/D\.[A-Z+]{0,64}\.EUR\.SP00\.A)?$")
_SAFE_QUERY_RE = re.compile(r"^[A-Za-z0-9_,=&.+:%-]*$")
_FORBIDDEN_PERCENT_ESCAPES = ("%2f", "%2e", "%5c", "%00", "%0d", "%0a", "%40", "%23")
_NUMERIC_HOST_RE = re.compile(r"^[0-9xXa-fA-F.]+$")
_NS_DIGITS_RE = re.compile(r"^[0-9]{1,30}$")
_DATE_ISO_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_XML_FORBIDDEN_DECL_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION|\[CDATA\[)", re.IGNORECASE)
_XML_CUSTOM_ENTITY_RE = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
_XML_ATTR_RE = re.compile(r"""\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Hard-refuses every HTTP 3xx status and never follows redirects."""

    def __init__(self, error_cls: type[ContractError] = ContractError) -> None:
        super().__init__()
        self._error_cls = error_cls

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise self._error_cls(f"HTTP redirect ({code}) refused on pinned public FX transport")

    def http_response(self, request, response):
        code = getattr(response, "status", None)
        if code is None:
            code = getattr(response, "code", 200)
        if 300 <= int(code) < 400:
            response.close()
            raise self._error_cls(f"HTTP redirect ({code}) refused on pinned public FX transport")
        return response

    https_response = http_response

    def _reject_3xx(self, req, fp, code, msg, headers):
        if fp is not None:
            fp.close()
        raise self._error_cls(f"HTTP redirect ({code}) refused on pinned public FX transport")

    http_error_300 = _reject_3xx
    http_error_301 = _reject_3xx
    http_error_302 = _reject_3xx
    http_error_303 = _reject_3xx
    http_error_304 = _reject_3xx
    http_error_305 = _reject_3xx
    http_error_306 = _reject_3xx
    http_error_307 = _reject_3xx
    http_error_308 = _reject_3xx


_NoRedirectHandler = NoRedirectHandler


def verify_public_ip_address(
    ip_text: str,
    *,
    label: str = "feed_host",
    error_cls: type[ContractError] = ContractError,
) -> None:
    """Reject loopback, private, link-local, multicast, unspecified, reserved, or non-global IPs."""
    if not isinstance(ip_text, str) or not ip_text or "%" in ip_text:
        raise error_cls(f"{label}: invalid or link-local scoped IP destination {ip_text!r}")
    stripped = ip_text.strip("[]")
    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise error_cls(f"{label}: malformed IP destination {ip_text!r}") from exc

    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [addr]
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        candidates.append(mapped)
    sixtofour = getattr(addr, "sixtofour", None)
    if sixtofour is not None:
        candidates.append(sixtofour)
    teredo = getattr(addr, "teredo", None)
    if teredo is not None:
        candidates.extend(teredo)

    for cand in candidates:
        if (
            cand.is_private
            or cand.is_loopback
            or cand.is_link_local
            or cand.is_multicast
            or cand.is_reserved
            or cand.is_unspecified
            or not cand.is_global
        ):
            raise error_cls(f"{label}: non-public IP destination {ip_text!r} is forbidden")


def _is_ip_literal_or_numeric_host(host: str) -> bool:
    stripped = host.strip("[]")
    if ":" in stripped:
        return True
    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        labels = stripped.split(".")
        if labels and labels[-1].isdigit():
            return True
        if _NUMERIC_HOST_RE.fullmatch(stripped) and any(ch.isdigit() for ch in stripped):
            return True
        return False
    return True


def validate_pinned_public_feed_url(
    url: str,
    *,
    label: str = "feed_url",
    allowed_hosts: frozenset[str] | None = None,
    allowed_paths_override: Mapping[str, frozenset[str]] | None = None,
    allow_yahoo_chart: bool = False,
    live_host_error_cls: type[ContractError] = ContractError,
) -> str:
    """Validate an HTTPS public FX feed URL against exact scheme, port 443, host, and path pinning."""
    if not isinstance(url, str) or not url.strip():
        raise ContractError(f"{label} must be a non-empty pinned HTTPS URL")
    cleaned = url.strip()
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 or ch == "\\" for ch in cleaned):
        raise ContractError(f"{label} contains forbidden whitespace, backslash, or control characters")

    parsed = urllib.parse.urlsplit(cleaned)
    raw_netloc_lower = parsed.netloc.lower()
    host_lower = (parsed.hostname or "").lower()
    if any(tok in host_lower or tok in raw_netloc_lower for tok in _FORBIDDEN_LIVE_HOST_TOKENS):
        raise live_host_error_cls(f"live trading endpoint host {host_lower!r} is strictly forbidden")

    if not cleaned.startswith("https://") or parsed.scheme != "https":
        raise ContractError(f"{label} requires an explicit canonical https:// URL")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ContractError(f"{label} must not embed credentials or userinfo")
    if parsed.fragment or "#" in cleaned:
        raise ContractError(f"{label} must not contain URL fragments")

    raw_hostname = parsed.hostname
    if not raw_hostname or raw_hostname != raw_hostname.lower():
        raise ContractError(f"{label} requires a canonical lowercase hostname")
    host = raw_hostname
    if "[" in parsed.netloc or "]" in parsed.netloc or _is_ip_literal_or_numeric_host(host):
        raise ContractError(f"{label} forbids IP literals and numeric hostnames ({host!r})")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ContractError(f"{label} specifies an invalid port") from exc
    if port not in (None, 443) or parsed.netloc not in (host, f"{host}:443"):
        raise ContractError(f"{label} must use canonical port 443 without nonstandard netloc formatting")

    permitted_hosts = (
        allowed_hosts
        if allowed_hosts is not None
        else (_ALLOWED_PUBLIC_HOSTS if allow_yahoo_chart else ALLOWED_PUBLIC_FEED_HOSTS)
    )
    if host not in permitted_hosts:
        raise ContractError(f"{label}: unpinned public FX feed host {host!r}")

    path = parsed.path
    allowed_yahoo_pct = allow_yahoo_chart and host == "query1.finance.yahoo.com" and path in _YAHOO_INDEX_ENCODED_PATHS
    if (
        not path.startswith("/")
        or "//" in path
        or ("%" in path and not allowed_yahoo_pct)
        or any(esc in path.lower() for esc in _FORBIDDEN_PERCENT_ESCAPES)
        or any(seg in (".", "..") for seg in path.split("/"))
    ):
        raise ContractError(f"{label}: non-canonical or traversal URL path {path!r}")

    if allowed_paths_override is not None and host in allowed_paths_override:
        if path not in allowed_paths_override[host]:
            raise ContractError(f"{label}: path {path!r} is not allowlisted for {host!r}")
    elif host == "data-api.ecb.europa.eu":
        if not _ECB_DATA_API_EXR_PATH_RE.fullmatch(path):
            raise ContractError(f"{label}: path {path!r} is not allowlisted for {host!r}")
    elif host == "query1.finance.yahoo.com":
        if not allow_yahoo_chart or path not in _YAHOO_ALLOWED_CHART_PATHS:
            raise ContractError(f"{label}: path {path!r} is not allowlisted for {host!r}")
    else:
        allowed_paths = PINNED_PUBLIC_FEED_HOST_PATHS.get(host, frozenset())
        if path not in allowed_paths:
            raise ContractError(f"{label}: path {path!r} is not allowlisted for {host!r}")

    if parsed.query:
        q_lower = parsed.query.lower()
        if any(esc in q_lower for esc in _FORBIDDEN_PERCENT_ESCAPES) or not _SAFE_QUERY_RE.fullmatch(parsed.query):
            raise ContractError(f"{label}: query string contains forbidden characters or percent-escapes")

    return cleaned


class _PinnedPublicHTTPSConnection(http.client.HTTPSConnection):
    """Resolves DNS once, rejects any non-global IP, and connects directly with pinned TLS SNI."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        context: ssl.SSLContext,
        ip_error_cls: type[ContractError] = ContractError,
        **kwargs: Any,
    ) -> None:
        super().__init__(host, port=port, context=context, **kwargs)
        self._tls_context = context
        self._ip_error_cls = ip_error_cls

    def connect(self) -> None:
        target_host = self.host
        target_port = self.port or 443
        try:
            infos = socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise urllib.error.URLError(exc) from exc
        if not infos:
            raise urllib.error.URLError(f"no DNS records resolved for {target_host!r}")
        for _family, _socktype, _proto, _canon, sockaddr in infos:
            verify_public_ip_address(str(sockaddr[0]), label=target_host, error_cls=self._ip_error_cls)

        family, socktype, proto, _canon, sockaddr = infos[0]
        raw_sock = socket.socket(family, socktype, proto)
        try:
            if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                raw_sock.settimeout(self.timeout)
            raw_sock.connect(sockaddr)
            self.sock = self._tls_context.wrap_socket(raw_sock, server_hostname=target_host)
        except Exception:
            raw_sock.close()
            raise


class PinnedPublicHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler binding TLS 1.2+, verified global-unicast DNS resolution, and SNI."""

    def __init__(
        self,
        *,
        context: ssl.SSLContext | None = None,
        ip_error_cls: type[ContractError] = ContractError,
    ) -> None:
        if context is None:
            context = get_cached_tls12_ssl_context()
        super().__init__(context=context)
        self._pinned_context = context
        self._ip_error_cls = ip_error_cls

    def https_open(self, req: urllib.request.Request):
        def _conn_factory(host: str, **kwargs: Any) -> _PinnedPublicHTTPSConnection:
            kwargs.pop("context", None)
            return _PinnedPublicHTTPSConnection(
                host,
                context=self._pinned_context,
                ip_error_cls=self._ip_error_cls,
                **kwargs,
            )

        return self.do_open(_conn_factory, req)


def build_pinned_public_opener(
    *,
    error_cls: type[ContractError] = ContractError,
) -> urllib.request.OpenerDirector:
    """Build a redirect-refusing, TLS 1.2+, public-IP-verified opener with no default redirect handler."""
    ctx = get_cached_tls12_ssl_context()
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(NoRedirectHandler(error_cls=error_cls))
    opener.add_handler(PinnedPublicHTTPSHandler(context=ctx, ip_error_cls=error_cls))
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


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


def _resolve_pair_limits(
    override: Decimal | Mapping[str, Decimal] | None,
    defaults: Mapping[str, Decimal],
    *,
    label: str,
) -> dict[str, Decimal]:
    resolved = dict(defaults)
    if override is None:
        return resolved
    if isinstance(override, Decimal):
        checked = decimal_value(override, label, positive=True)
        return {pair: checked for pair in resolved}
    if isinstance(override, Mapping):
        for pair, val in override.items():
            if pair not in EXPANDED_PAIR_SPECS:
                raise ContractError(f"{label}: unsupported FX pair {pair!r}")
            resolved[pair] = decimal_value(val, f"{label}[{pair}]", positive=True)
        return resolved
    raise ContractError(f"{label} must be a positive Decimal, pair Mapping, or None")


def validate_reference_date_freshness(
    ecb_reference_date: str | None,
    *,
    observed_at: datetime,
    max_reference_age_days: int = DEFAULT_MAX_REFERENCE_AGE_DAYS,
) -> date:
    """Fail closed with ContractError if ECB reference date is missing, invalid, future, or stale."""
    integer(max_reference_age_days, "max_reference_age_days", minimum=0)
    checked_obs = utc_time(observed_at, "observed_at")
    if not isinstance(ecb_reference_date, str) or not _DATE_ISO_RE.fullmatch(ecb_reference_date):
        raise ContractError("missing or invalid ecb_reference_date; venue-driving stream fails closed")
    try:
        ref_date = datetime.strptime(ecb_reference_date, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ContractError(f"invalid calendar ecb_reference_date {ecb_reference_date!r}") from exc

    age_days = (checked_obs.date() - ref_date).days
    if age_days < -1:
        raise ContractError(
            f"ECB reference date {ecb_reference_date} is in the future relative to {checked_obs.date().isoformat()}"
        )
    if age_days > max_reference_age_days:
        raise ContractError(
            f"ECB reference date {ecb_reference_date} exceeds max_reference_age_days={max_reference_age_days} "
            f"(age={age_days} days)"
        )
    return ref_date


def _https_get_pinned_host(
    url: str,
    *,
    timeout_seconds: float = 15.0,
    max_bytes: int = MAX_STREAM_WIRE_BYTES,
    retries: int = 2,
) -> bytes:
    validated_url = validate_pinned_public_feed_url(
        url,
        label="fx_stream_url",
        allow_yahoo_chart=True,
    )
    parsed = urllib.parse.urlsplit(validated_url)
    opener = build_pinned_public_opener(error_cls=ContractError)
    req = urllib.request.Request(
        validated_url,
        method="GET",
        headers={
            "Accept": "application/json, text/xml;q=0.8",
            "User-Agent": "CAS-Forex-Phase6-MarketStream/1.0",
        },
    )
    max_attempts = max(0, retries) + 1
    for attempt in range(max_attempts):
        try:
            with opener.open(req, timeout=timeout_seconds) as resp:
                status = getattr(resp, "status", 200)
                if status != 200:
                    raise ContractError(f"FX stream unexpected HTTP status {status} from {parsed.hostname}")
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
                body = b"".join(chunks)
                if not body:
                    raise ContractError(f"empty response body from {parsed.hostname}")
                return body
        except ContractError:
            raise
        except urllib.error.HTTPError as exc:
            raise ContractError(f"FX stream HTTPS transport error for {parsed.hostname}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
            if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, ContractError):
                raise exc.reason from exc
            if attempt + 1 >= max_attempts:
                reason = exc.reason if isinstance(exc, urllib.error.URLError) else type(exc).__name__
                raise ContractError(f"FX stream HTTPS transport error for {parsed.hostname}: {reason}") from exc
            time.sleep(0.2 * (2 ** attempt))
    raise ContractError(f"FX stream HTTPS transport error for {parsed.hostname}: exhausted retries")


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
        self.verify_digest()

    def _payload_without_digest_dict(self) -> dict[str, Any]:
        """Return the canonical envelope fields hashed by self-computed canonical_payload_sha256."""
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

    def verify_digest(self) -> None:
        """Verify the self-computed SHA-256 content digest (integrity checksum, not a cryptographic signature)."""
        expected = sha256(canonical_bytes(self._payload_without_digest_dict())).hexdigest()
        if self.canonical_payload_sha256 != expected:
            raise ContractError("MarketStreamEnvelope canonical_payload_sha256 mismatch")

    def to_wire_dict(self) -> dict[str, Any]:
        body = self._payload_without_digest_dict()
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


def build_market_stream_envelope(
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
    """Assemble a MarketStreamEnvelope with a self-computed canonical_payload_sha256 integrity digest."""
    body_without_digest = {
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
    payload_sha = sha256(canonical_bytes(body_without_digest)).hexdigest()
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


build_digest_market_stream_envelope = build_market_stream_envelope


def validate_market_stream_for_venue(
    envelope: MarketStreamEnvelope,
    *,
    now: datetime | None = None,
    max_reference_age_days: int = DEFAULT_MAX_REFERENCE_AGE_DAYS,
    max_reference_deviation_bps: Decimal | Mapping[str, Decimal] | None = None,
    max_spread_bps: Decimal | Mapping[str, Decimal] | None = None,
) -> None:
    """Enforce fail-closed reference presence, freshness, deviation ceilings, and spread limits."""
    if not isinstance(envelope, MarketStreamEnvelope):
        raise ContractError("validate_market_stream_for_venue requires MarketStreamEnvelope")
    envelope.verify_digest()

    validate_reference_date_freshness(
        envelope.ecb_reference_date,
        observed_at=envelope.observed_at,
        max_reference_age_days=max_reference_age_days,
    )
    if now is not None:
        validate_reference_date_freshness(
            envelope.ecb_reference_date,
            observed_at=utc_time(now, "now"),
            max_reference_age_days=max_reference_age_days,
        )

    dev_limits = _resolve_pair_limits(
        max_reference_deviation_bps,
        PAIR_MAX_REFERENCE_DEVIATION_BPS,
        label="max_reference_deviation_bps",
    )
    spread_limits = _resolve_pair_limits(
        max_spread_bps,
        PAIR_MAX_SPREAD_BPS,
        label="max_spread_bps",
    )

    with localcontext(Context(prec=50)):
        for ps in envelope.streams:
            if ps.bid <= Decimal("0") or ps.ask <= ps.bid:
                raise ContractError(f"{ps.pair}: non-positive or inverted spread (bid={ps.bid}, ask={ps.ask})")
            calc_mid = (ps.bid + ps.ask) / Decimal("2")
            if abs(ps.mid - calc_mid) > ps.tick_size:
                raise ContractError(f"{ps.pair}: mid {ps.mid} inconsistent with bid={ps.bid}, ask={ps.ask}")

            actual_spread_bps = ((ps.ask - ps.bid) / calc_mid) * Decimal("10000")
            pair_spread_cap = spread_limits[ps.pair]
            if actual_spread_bps <= Decimal("0") or actual_spread_bps > pair_spread_cap:
                raise ContractError(
                    f"{ps.pair}: spread {actual_spread_bps:.4f} bps exceeds pair max_spread_bps={pair_spread_cap}"
                )

            pip = EXPANDED_PAIR_SPECS[ps.pair]["pip"]
            expected_spread_pips = ((ps.ask - ps.bid) / pip).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)
            if abs(ps.spread_pips - expected_spread_pips) > Decimal("0.2"):
                raise ContractError(
                    f"{ps.pair}: spread_pips {ps.spread_pips} inconsistent with bid/ask ({expected_spread_pips})"
                )

            if ps.ecb_reference_mid is None or ps.ecb_reference_mid <= Decimal("0"):
                raise ContractError(f"{ps.pair}: missing independent ECB reference mid; failing closed")
            if ps.ecb_deviation_bps is None or ps.ecb_deviation_bps < Decimal("0"):
                raise ContractError(f"{ps.pair}: missing or negative ecb_deviation_bps; failing closed")

            actual_dev_bps = (abs(ps.mid - ps.ecb_reference_mid) / ps.ecb_reference_mid) * Decimal("10000")
            calc_mid_dev_bps = (abs(calc_mid - ps.ecb_reference_mid) / ps.ecb_reference_mid) * Decimal("10000")
            if abs(ps.ecb_deviation_bps - actual_dev_bps) > Decimal("1.0"):
                raise ContractError(
                    f"{ps.pair}: reported ecb_deviation_bps={ps.ecb_deviation_bps} inconsistent with "
                    f"actual deviation {actual_dev_bps:.4f} bps"
                )
            pair_dev_cap = dev_limits[ps.pair]
            if (
                actual_dev_bps > pair_dev_cap
                or calc_mid_dev_bps > pair_dev_cap
                or ps.ecb_deviation_bps > pair_dev_cap
            ):
                raise ContractError(
                    f"{ps.pair}: reference deviation {actual_dev_bps:.4f} bps exceeds "
                    f"pair max_reference_deviation_bps={pair_dev_cap}"
                )


def _parse_ecb_g10_xml(raw_bytes: bytes) -> tuple[str, dict[str, Decimal]]:
    """Entity-free parser for official ECB eurofxref daily XML across G10 currencies."""
    try:
        xml_text = raw_bytes.decode("utf-8").lstrip("\ufeff")
    except UnicodeDecodeError as exc:
        raise ContractError("malformed ECB G10 XML payload") from exc
    if _XML_FORBIDDEN_DECL_RE.search(xml_text) or _XML_CUSTOM_ENTITY_RE.search(xml_text):
        raise ContractError("forbidden DTD or entity declaration in ECB XML payload")

    ref_date: str | None = None
    eur_rates: dict[str, Decimal] = {"EUR": Decimal("1")}
    wanted_ccys = ("USD", "GBP", "JPY", "CHF", "AUD", "CAD", "NZD")
    stack: list[str] = []
    saw_root = False
    root_closed = False
    pos = 0
    n = len(xml_text)
    while pos < n:
        lt = xml_text.find("<", pos)
        if lt == -1:
            if ">" in xml_text[pos:] or xml_text[pos:].strip():
                raise ContractError("malformed ECB G10 XML payload")
            break
        between = xml_text[pos:lt]
        if ">" in between or (not stack and between.strip()):
            raise ContractError("malformed ECB G10 XML payload")
        if xml_text.startswith("<!--", lt):
            end = xml_text.find("-->", lt + 4)
            if end == -1:
                raise ContractError("malformed ECB G10 XML payload")
            pos = end + 3
            continue
        if xml_text.startswith("<?", lt):
            end = xml_text.find("?>", lt + 2)
            if end == -1:
                raise ContractError("malformed ECB G10 XML payload")
            pos = end + 2
            continue
        gt = xml_text.find(">", lt + 1)
        if gt == -1:
            raise ContractError("malformed ECB G10 XML payload")
        inner = xml_text[lt + 1:gt].strip()
        if not inner or "<" in inner:
            raise ContractError("malformed ECB G10 XML payload")
        if inner.startswith("/"):
            close_name = inner[1:].strip()
            if not stack or stack[-1] != close_name:
                raise ContractError("malformed ECB G10 XML payload")
            stack.pop()
            if not stack:
                root_closed = True
            pos = gt + 1
            continue
        if root_closed:
            raise ContractError("malformed ECB G10 XML payload")
        self_closing = inner.endswith("/")
        if self_closing:
            inner = inner[:-1].rstrip()
        name_m = re.match(r"^([A-Za-z_][A-Za-z0-9_.:-]*)", inner)
        if not name_m:
            raise ContractError("malformed ECB G10 XML payload")
        tag_name = name_m.group(1)
        attr_str = inner[name_m.end():]
        attrs: dict[str, str] = {}
        cursor = 0
        while cursor < len(attr_str):
            am = _XML_ATTR_RE.match(attr_str, cursor)
            if not am:
                if attr_str[cursor:].strip():
                    raise ContractError("malformed ECB G10 XML payload")
                break
            attrs[am.group(1)] = am.group(2) if am.group(2) is not None else am.group(3)
            cursor = am.end()
        if self_closing:
            if not stack:
                root_closed = True
        else:
            stack.append(tag_name)
        saw_root = True
        if tag_name.rsplit(":", 1)[-1] == "Cube":
            if attrs.get("time") and ref_date is None:
                ref_date = attrs["time"]
            ccy = attrs.get("currency")
            rate_txt = attrs.get("rate")
            if ccy in wanted_ccys and rate_txt is not None:
                val = parse_decimal(rate_txt, f"ECB.{ccy}")
                if val <= 0:
                    raise ContractError(f"nonpositive ECB rate for {ccy}")
                eur_rates[ccy] = val
        pos = gt + 1

    if not saw_root or stack or ref_date is None:
        raise ContractError("incomplete ECB G10 XML payload")
    return ref_date, eur_rates


def parse_ecb_g10_reference(raw_bytes: bytes) -> tuple[str, dict[str, Decimal]]:
    if not isinstance(raw_bytes, bytes) or not raw_bytes.strip():
        raise ContractError("empty ECB G10 reference payload")

    if raw_bytes.lstrip().startswith(b"<"):
        ref_date, eur_rates = _parse_ecb_g10_xml(raw_bytes)
    else:
        try:
            text = raw_bytes.decode("utf-8")
            doc = json.loads(
                text,
                parse_float=Decimal,
                parse_constant=lambda tok: (_ for _ in ()).throw(ContractError(f"nonfinite JSON constant {tok!r}")),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, InvalidOperation, RecursionError) as exc:
            raise ContractError("invalid ECB G10 JSON payload") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("date"), str) or not isinstance(doc.get("rates"), dict):
            raise ContractError("invalid ECB G10 JSON payload")
        if doc.get("base", "EUR") != "EUR":
            raise ContractError(f"unsupported ECB G10 base currency {doc.get('base')!r}")
        ref_date = doc["date"]
        rates_raw = doc["rates"]
        eur_rates = {"EUR": Decimal("1")}
        for ccy in ("USD", "GBP", "JPY", "CHF", "AUD", "CAD", "NZD"):
            if ccy in rates_raw:
                try:
                    val = Decimal(str(rates_raw[ccy]))
                except InvalidOperation as exc:
                    raise ContractError(f"invalid ECB rate for {ccy}") from exc
                if not val.is_finite() or val <= 0:
                    raise ContractError(f"nonpositive ECB rate for {ccy}")
                eur_rates[ccy] = val

    if not _DATE_ISO_RE.fullmatch(ref_date):
        raise ContractError(f"invalid ECB reference date {ref_date!r}")
    try:
        datetime.strptime(ref_date, "%Y-%m-%d")
    except ValueError as exc:
        raise ContractError(f"invalid ECB calendar date {ref_date!r}") from exc

    pair_refs: dict[str, Decimal] = {}
    with localcontext(Context(prec=60)):
        for pair, spec in EXPANDED_PAIR_SPECS.items():
            b_ccy, q_ccy = spec["base"], spec["quote"]
            if b_ccy in eur_rates and q_ccy in eur_rates:
                mid = (eur_rates[q_ccy] / eur_rates[b_ccy]).quantize(Decimal("0.00000001"), rounding=ROUND_FLOOR)
                pair_refs[pair] = mid
    if not pair_refs:
        raise ContractError("ECB G10 payload contained no usable FX reference rates")
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

    def __init__(
        self,
        initial_envelope: MarketStreamEnvelope,
        *,
        max_reference_age_days: int = DEFAULT_MAX_REFERENCE_AGE_DAYS,
        max_reference_deviation_bps: Decimal | Mapping[str, Decimal] | None = None,
        max_spread_bps: Decimal | Mapping[str, Decimal] | None = None,
    ) -> None:
        integer(max_reference_age_days, "max_reference_age_days", minimum=0)
        self._max_reference_age_days = max_reference_age_days
        self._dev_limits = _resolve_pair_limits(
            max_reference_deviation_bps,
            PAIR_MAX_REFERENCE_DEVIATION_BPS,
            label="max_reference_deviation_bps",
        )
        self._spread_limits = _resolve_pair_limits(
            max_spread_bps,
            PAIR_MAX_SPREAD_BPS,
            label="max_spread_bps",
        )
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
        next_raw_sha = self._raw_wire_sha256
        if raw_wire_sha256 is not None:
            digest(raw_wire_sha256, "raw_wire_sha256")
            next_raw_sha = raw_wire_sha256
        next_valve = self._valve_status if valve_status is None else valve_status

        enforce_ref = self._source_mode != "REHEARSAL_VENUE_FEED"
        if enforce_ref:
            validate_reference_date_freshness(
                self._ecb_date,
                observed_at=checked_now,
                max_reference_age_days=self._max_reference_age_days,
            )

        staged_streams = dict(self._streams)
        with localcontext(Context(prec=50)):
            for pair, (raw_bid, raw_ask) in quotes_by_pair.items():
                if pair not in staged_streams:
                    continue
                decimal_value(raw_bid, f"{pair}.bid", positive=True)
                decimal_value(raw_ask, f"{pair}.ask", positive=True)
                if raw_ask <= raw_bid:
                    raise ContractError(f"{pair}: non-positive spread in ingest_quotes (bid={raw_bid}, ask={raw_ask})")
                cur = staged_streams[pair]
                spec = EXPANDED_PAIR_SPECS[pair]
                tick = spec["tick"]
                pip = spec["pip"]
                bid = _quantize_price(raw_bid, tick, rounding=ROUND_FLOOR)
                ask = _quantize_price(raw_ask, tick, rounding=ROUND_CEILING)
                if ask <= bid:
                    raise ContractError(f"{pair}: quantized ask <= bid ({bid}/{ask})")
                mid = _quantize_price((bid + ask) / Decimal("2"), tick)
                calc_mid = (bid + ask) / Decimal("2")
                spread_bps = ((ask - bid) / calc_mid) * Decimal("10000")
                if spread_bps <= Decimal("0") or spread_bps > self._spread_limits[pair]:
                    raise ContractError(
                        f"{pair}: spread {spread_bps:.4f} bps exceeds pair max_spread_bps={self._spread_limits[pair]}"
                    )
                spread_pips = ((ask - bid) / pip).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)
                first_h1 = cur.candles_h1[0].open_price if cur.candles_h1 else mid
                chg_pct = (((mid - first_h1) / first_h1) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
                dev_bps = None
                if cur.ecb_reference_mid is not None and cur.ecb_reference_mid > 0:
                    exact_dev_bps = (abs(mid - cur.ecb_reference_mid) / cur.ecb_reference_mid) * Decimal("10000")
                    if enforce_ref and exact_dev_bps > self._dev_limits[pair]:
                        raise ContractError(
                            f"{pair}: reference deviation {exact_dev_bps:.4f} bps exceeds "
                            f"pair max_reference_deviation_bps={self._dev_limits[pair]}"
                        )
                    dev_bps = exact_dev_bps.quantize(Decimal("0.1"), rounding=ROUND_FLOOR)
                elif enforce_ref:
                    raise ContractError(f"{pair}: missing ECB reference mid for live stream aggregation")

                staged_streams[pair] = PairMarketStream(
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

        next_seq = self._sequence + 1
        epoch_ns = str(int(checked_now.timestamp() * 1_000_000_000))
        envelope = build_market_stream_envelope(
            stream_id=f"fxstream-{next_seq}",
            sequence=next_seq,
            observed_at=checked_now,
            observed_at_ns=epoch_ns,
            source_mode=self._source_mode,
            raw_wire_sha256=next_raw_sha,
            ecb_reference_date=self._ecb_date,
            valve_status=next_valve,
            streams=[staged_streams[p] for p in self._order],
        )
        if enforce_ref:
            validate_market_stream_for_venue(
                envelope,
                now=checked_now,
                max_reference_age_days=self._max_reference_age_days,
                max_reference_deviation_bps=self._dev_limits,
                max_spread_bps=self._spread_limits,
            )
        self._sequence = next_seq
        self._raw_wire_sha256 = next_raw_sha
        self._valve_status = next_valve
        self._streams = staged_streams
        return envelope


class ExpandedPublicLiveFxFeedClient:
    """Fetches all 16 G10 major & cross FX pairs + live M1/M5/H1 candlestick series with fail-closed reference checks."""

    def __init__(
        self,
        *,
        http_get: Callable[[str, float, int], bytes] | None = None,
        timeout_seconds: float = 15.0,
        reference_urls: tuple[str, ...] = FRANKFURTER_G10_URLS,
        max_reference_age_days: int = DEFAULT_MAX_REFERENCE_AGE_DAYS,
        max_reference_deviation_bps: Decimal | Mapping[str, Decimal] | None = None,
        max_spread_bps: Decimal | Mapping[str, Decimal] | None = None,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ContractError("timeout_seconds must be in (0, 60]")
        if type(reference_urls) is not tuple or not reference_urls:
            raise ContractError("reference_urls must be a non-empty tuple of pinned ECB/Frankfurter HTTPS URLs")
        ref_hosts = frozenset({"www.ecb.europa.eu", "data-api.ecb.europa.eu", "api.frankfurter.dev", "api.frankfurter.app"})
        validated_refs = tuple(
            validate_pinned_public_feed_url(u, label="reference_url", allowed_hosts=ref_hosts)
            for u in reference_urls
        )
        integer(max_reference_age_days, "max_reference_age_days", minimum=0)
        self._timeout = float(timeout_seconds)
        self.reference_urls = validated_refs
        self.max_reference_age_days = max_reference_age_days
        self.pair_max_reference_deviation_bps = _resolve_pair_limits(
            max_reference_deviation_bps,
            PAIR_MAX_REFERENCE_DEVIATION_BPS,
            label="max_reference_deviation_bps",
        )
        self.pair_max_spread_bps = _resolve_pair_limits(
            max_spread_bps,
            PAIR_MAX_SPREAD_BPS,
            label="max_spread_bps",
        )
        self._http_get = http_get or (lambda url, t, m: _https_get_pinned_host(url, timeout_seconds=t, max_bytes=m))

    def _get(self, url: str) -> bytes:
        validated = validate_pinned_public_feed_url(url, label="expanded_feed_url", allow_yahoo_chart=True)
        raw = self._http_get(validated, self._timeout, MAX_STREAM_WIRE_BYTES)
        if not isinstance(raw, bytes) or len(raw) == 0 or len(raw) > MAX_STREAM_WIRE_BYTES:
            raise ContractError("expanded FX feed transport returned empty or oversized wire bytes")
        return raw

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
        max_reference_age_days: int | None = None,
        max_reference_deviation_bps: Decimal | Mapping[str, Decimal] | None = None,
        max_spread_bps: Decimal | Mapping[str, Decimal] | None = None,
    ) -> MarketStreamEnvelope:
        if not pairs or any(p not in EXPANDED_PAIR_SPECS for p in pairs):
            raise ContractError("pairs must be a non-empty sequence of supported EXPANDED_FX_PAIRS")
        observed = utc_time(now, "now") if now is not None else datetime.now(timezone.utc)
        observed_ns = str(time.time_ns() if now is None else int(observed.timestamp() * 1_000_000_000))

        effective_max_age = self.max_reference_age_days if max_reference_age_days is None else max_reference_age_days
        integer(effective_max_age, "max_reference_age_days", minimum=0)
        dev_limits = (
            self.pair_max_reference_deviation_bps
            if max_reference_deviation_bps is None
            else _resolve_pair_limits(
                max_reference_deviation_bps,
                self.pair_max_reference_deviation_bps,
                label="max_reference_deviation_bps",
            )
        )
        spread_limits = (
            self.pair_max_spread_bps
            if max_spread_bps is None
            else _resolve_pair_limits(
                max_spread_bps,
                self.pair_max_spread_bps,
                label="max_spread_bps",
            )
        )

        ecb_date: str | None = None
        ecb_refs: dict[str, Decimal] = {}
        raw_blobs: list[bytes] = []
        last_ref_error: Exception | None = None
        for ecb_url in self.reference_urls:
            try:
                ecb_raw = self._get(ecb_url)
                cand_date, cand_refs = parse_ecb_g10_reference(ecb_raw)
                validate_reference_date_freshness(
                    cand_date,
                    observed_at=observed,
                    max_reference_age_days=effective_max_age,
                )
                if any(p not in cand_refs or cand_refs[p] <= Decimal("0") for p in pairs):
                    missing = [p for p in pairs if p not in cand_refs or cand_refs[p] <= Decimal("0")]
                    raise ContractError(f"ECB reference feed missing rates for {missing}")
                ecb_date = cand_date
                ecb_refs = cand_refs
                raw_blobs.append(ecb_raw)
                break
            except Exception as exc:
                last_ref_error = exc

        if ecb_date is None or not ecb_refs:
            detail = type(last_ref_error).__name__ if last_ref_error is not None else "no_reference_urls"
            if isinstance(last_ref_error, ContractError):
                raise ContractError(
                    f"all independent ECB/Frankfurter reference feeds failed or were stale ({last_ref_error})"
                ) from last_ref_error
            raise ContractError(
                f"all independent ECB/Frankfurter reference feeds failed ({detail}); failing closed"
            ) from last_ref_error

        ticker_raw = self._get(KRAKEN_EXPANDED_TICKER_URL)
        raw_blobs.append(ticker_raw)
        try:
            ticker_doc = json.loads(ticker_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractError("malformed Kraken expanded Ticker JSON") from exc
        if not isinstance(ticker_doc, dict) or ticker_doc.get("error"):
            raise ContractError(f"Kraken expanded Ticker error: {ticker_doc.get('error') if isinstance(ticker_doc, dict) else 'non-object'}")
        result_map = ticker_doc.get("result") or {}

        needed_direct: set[str] = set()
        for p in pairs:
            spec = EXPANDED_PAIR_SPECS[p]
            if spec["mode"] == "DIRECT_KRAKEN_ORDERBOOK":
                needed_direct.add(p)
            elif spec["mode"] == "SYNTHETIC_KRAKEN_CROSS_BOOK":
                _, leg_a, leg_b = spec["legs"]
                needed_direct.add(leg_a)
                needed_direct.add(leg_b)

        direct_quotes: dict[str, tuple[Decimal, Decimal]] = {}
        for dpair in sorted(needed_direct):
            spec = EXPANDED_PAIR_SPECS[dpair]
            entry = None
            for alias in spec["kraken_keys"]:
                if alias in result_map:
                    entry = result_map[alias]
                    break
            if entry is None:
                raise ContractError(f"Kraken Ticker missing direct pair {dpair}")
            tick = spec["tick"]
            raw_bid = parse_decimal(str(entry["b"][0]), f"{dpair}.bid")
            raw_ask = parse_decimal(str(entry["a"][0]), f"{dpair}.ask")
            if raw_bid <= Decimal("0") or raw_ask <= raw_bid:
                raise ContractError(f"Kraken Ticker {dpair} has non-positive spread (bid={raw_bid}, ask={raw_ask})")
            bid = _quantize_price(raw_bid, tick, rounding=ROUND_FLOOR)
            ask = _quantize_price(raw_ask, tick, rounding=ROUND_CEILING)
            if ask <= bid:
                raise ContractError(f"Kraken Ticker {dpair} quantized spread collapsed ({bid}/{ask})")
            direct_quotes[dpair] = (bid, ask)

        def _validate_quote_spread_and_ecb(
            pair_name: str,
            q_bid: Decimal,
            q_ask: Decimal,
            tick_step: Decimal,
        ) -> tuple[Decimal, Decimal]:
            q_mid = _quantize_price((q_bid + q_ask) / Decimal("2"), tick_step)
            q_calc_mid = (q_bid + q_ask) / Decimal("2")
            actual_spread_bps = ((q_ask - q_bid) / q_calc_mid) * Decimal("10000")
            if actual_spread_bps <= Decimal("0") or actual_spread_bps > spread_limits[pair_name]:
                raise ContractError(
                    f"{pair_name}: spread {actual_spread_bps:.4f} bps exceeds pair max_spread_bps={spread_limits[pair_name]}"
                )
            ref_mid = ecb_refs.get(pair_name)
            if ref_mid is None or ref_mid <= Decimal("0"):
                raise ContractError(f"{pair_name}: missing independent ECB reference rate; failing closed")
            exact_dev_bps = (abs(q_mid - ref_mid) / ref_mid) * Decimal("10000")
            calc_mid_dev_bps = (abs(q_calc_mid - ref_mid) / ref_mid) * Decimal("10000")
            if exact_dev_bps > dev_limits[pair_name] or calc_mid_dev_bps > dev_limits[pair_name]:
                raise ContractError(
                    f"{pair_name}: mid {q_mid} deviates {exact_dev_bps:.4f} bps from ECB reference {ref_mid} "
                    f"(pair max_reference_deviation_bps={dev_limits[pair_name]})"
                )
            return q_mid, exact_dev_bps.quantize(Decimal("0.1"), rounding=ROUND_FLOOR)

        # Fail fast on wide weekend Kraken spreads / reference deviations before issuing 36 OHLC & Yahoo GETs.
        prevalidated_quotes: dict[str, tuple[Decimal, Decimal, Decimal, Decimal]] = {}
        with localcontext(Context(prec=50)):
            for pair in pairs:
                spec = EXPANDED_PAIR_SPECS[pair]
                tick = spec["tick"]
                mode = spec["mode"]
                if mode == "DIRECT_KRAKEN_ORDERBOOK":
                    bid, ask = direct_quotes[pair]
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
                        raise ContractError(f"{pair}: synthetic cross book spread collapsed ({bid}/{ask})")
                else:
                    continue
                mid, dev_bps = _validate_quote_spread_and_ecb(pair, bid, ask, tick)
                prevalidated_quotes[pair] = (bid, ask, mid, dev_bps)

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
                    bid, ask, mid, dev_bps = prevalidated_quotes[pair]
                    c_m1 = direct_candles[pair]["m1"]
                    c_m5 = direct_candles[pair]["m5"]
                    c_h1 = direct_candles[pair]["h1"]
                elif mode == "SYNTHETIC_KRAKEN_CROSS_BOOK":
                    op, leg_a, leg_b = spec["legs"]
                    bid, ask, mid, dev_bps = prevalidated_quotes[pair]
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
                    if spot <= half_spread:
                        raise ContractError(f"{pair}: invalid spot price {spot}")
                    bid = _quantize_price(spot - half_spread, tick, rounding=ROUND_FLOOR)
                    ask = _quantize_price(spot + half_spread, tick, rounding=ROUND_CEILING)
                    if ask <= bid:
                        raise ContractError(f"{pair}: interbank spread collapsed ({bid}/{ask})")
                    mid, dev_bps = _validate_quote_spread_and_ecb(pair, bid, ask, tick)

                ref_mid = ecb_refs[pair]

                c_m1 = _anchor_last_bar_to_mid(c_m1, mid, tick)
                c_m5 = _anchor_last_bar_to_mid(c_m5, mid, tick)
                c_h1 = _anchor_last_bar_to_mid(c_h1, mid, tick)

                spread_pips = ((ask - bid) / pip).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)
                first_open = c_h1[0].open_price if c_h1 else mid
                chg_pct = (((mid - first_open) / first_open) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)

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
        envelope = build_market_stream_envelope(
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
        validate_market_stream_for_venue(
            envelope,
            now=observed,
            max_reference_age_days=effective_max_age,
            max_reference_deviation_bps=dev_limits,
            max_spread_bps=spread_limits,
        )
        return envelope

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
                    raw_bid = parse_decimal(str(entry["b"][0]), f"{dpair}.bid")
                    raw_ask = parse_decimal(str(entry["a"][0]), f"{dpair}.ask")
                    if raw_bid <= Decimal("0") or raw_ask <= raw_bid:
                        raise ContractError(f"Kraken live tick {dpair} has non-positive spread")
                    b = _quantize_price(raw_bid, tick, rounding=ROUND_FLOOR)
                    a = _quantize_price(raw_ask, tick, rounding=ROUND_CEILING)
                    if a <= b:
                        raise ContractError(f"Kraken live tick {dpair} quantized spread collapsed")
                    calc_mid = (b + a) / Decimal("2")
                    spread_bps = ((a - b) / calc_mid) * Decimal("10000")
                    if spread_bps > self.pair_max_spread_bps[dpair]:
                        raise ContractError(
                            f"Kraken live tick {dpair} spread {spread_bps:.4f} bps exceeds "
                            f"pair max_spread_bps={self.pair_max_spread_bps[dpair]}"
                        )
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
                        raise ContractError(f"Kraken synthetic live tick {spair} spread collapsed")
                    calc_mid = (b + a) / Decimal("2")
                    spread_bps = ((a - b) / calc_mid) * Decimal("10000")
                    if spread_bps > self.pair_max_spread_bps[spair]:
                        raise ContractError(
                            f"Kraken synthetic live tick {spair} spread {spread_bps:.4f} bps exceeds "
                            f"pair max_spread_bps={self.pair_max_spread_bps[spair]}"
                        )
                    out[spair] = (b, a)
        return out, wire_sha


class PublicUsIndexFeedClient:
    """Read-only pinned HTTPS reference feed for NAS100 (NDX/NQ) and US30 (DJI/YM).

    Uses PinnedPublicHTTPSHandler + NoRedirectHandler and returns a safe-JSON dict (no floats).
    """

    def __init__(
        self,
        *,
        transport: Callable[[str, float, int], bytes] | None = None,
        timeout_seconds: float = 10.0,
        max_wire_bytes: int = MAX_STREAM_WIRE_BYTES,
        clock: Callable[[], datetime] | None = None,
        max_candle_age_seconds: int = 300,
        max_quote_age_seconds: int = 300,
        max_future_skew_seconds: int = 30,
    ) -> None:
        self._transport = transport
        self._timeout = float(timeout_seconds)
        self._max_wire_bytes = integer(max_wire_bytes, "max_wire_bytes", minimum=1024)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_candle_age_seconds = integer(max_candle_age_seconds, "max_candle_age_seconds", minimum=1)
        self._max_quote_age_seconds = integer(max_quote_age_seconds, "max_quote_age_seconds", minimum=1)
        self._max_future_skew_seconds = integer(max_future_skew_seconds, "max_future_skew_seconds", minimum=0)

    def _get(self, url: str) -> bytes:
        safe_url = validate_pinned_public_feed_url(url, allow_yahoo_chart=True)
        if self._transport is not None:
            raw = self._transport(safe_url, self._timeout, self._max_wire_bytes)
            if not isinstance(raw, bytes) or len(raw) == 0 or len(raw) > self._max_wire_bytes:
                raise ContractError("index transport returned invalid payload size")
            return raw
        return _https_get_pinned_host(safe_url, timeout_seconds=self._timeout, max_bytes=self._max_wire_bytes)

    def _validate_provider_timestamps(
        self,
        *,
        sym: str,
        meta: Mapping[str, Any],
        candle_epochs: Sequence[int],
        received_dt: datetime,
    ) -> datetime:
        received_epoch = received_dt.timestamp()
        provider_dts: list[datetime] = []
        if candle_epochs:
            newest_epoch = candle_epochs[-1]
            candle_age = received_epoch - float(newest_epoch)
            if candle_age > float(self._max_candle_age_seconds):
                raise ContractError(
                    f"Yahoo index candle stream stale for {sym}: age={candle_age:.1f}s > {self._max_candle_age_seconds}s"
                )
            provider_dts.append(datetime.fromtimestamp(newest_epoch, tz=timezone.utc))
        if "regularMarketTime" in meta and meta.get("regularMarketTime") is not None:
            raw_rmt = meta.get("regularMarketTime")
            if isinstance(raw_rmt, bool):
                raise ContractError(f"Yahoo index regularMarketTime invalid for {sym}: {raw_rmt!r}")
            try:
                rmt_epoch = int(str(raw_rmt))
            except (TypeError, ValueError):
                raise ContractError(f"Yahoo index regularMarketTime invalid for {sym}: {raw_rmt!r}") from None
            if rmt_epoch <= 0:
                raise ContractError(f"Yahoo index regularMarketTime non-positive for {sym}: {rmt_epoch}")
            if float(rmt_epoch) > received_epoch + float(self._max_future_skew_seconds):
                raise ContractError(f"Yahoo index regularMarketTime is in the future for {sym}: {rmt_epoch}")
            quote_age = received_epoch - float(rmt_epoch)
            if quote_age > float(self._max_quote_age_seconds):
                raise ContractError(
                    f"Yahoo index regularMarketTime stale for {sym}: age={quote_age:.1f}s > {self._max_quote_age_seconds}s"
                )
            provider_dts.append(datetime.fromtimestamp(rmt_epoch, tz=timezone.utc))
        if not provider_dts:
            raise ContractError(f"Yahoo index response for {sym} missing provider timestamp (candle timestamp or regularMarketTime)")
        return min(provider_dts)

    def fetch_index_stream(self, *, sequence: int = 1) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        top_provider_dts: list[datetime] = []
        top_received_dts: list[datetime] = []
        for sym in INDEX_INSTRUMENTS:
            spec = INDEX_MARKET_SPECS[sym]
            tick = spec["tick"]
            last_exc: Exception | None = None
            chart_doc: dict[str, Any] | None = None
            received_dt: datetime | None = None
            for ypath in spec["yahoo_paths"]:
                url = f"https://query1.finance.yahoo.com{ypath}?interval=1m&range=1d"
                try:
                    raw = self._get(url)
                    received_dt = utc_time(self._clock(), "index received_at")
                    parsed = json.loads(raw.decode("utf-8"))
                    result_list = ((parsed.get("chart") or {}).get("result") or [])
                    if result_list and isinstance(result_list[0], dict):
                        chart_doc = result_list[0]
                        break
                except Exception as exc:
                    last_exc = exc
            if chart_doc is None or received_dt is None:
                raise ContractError(f"pinned reference feed unavailable for {sym}: {type(last_exc).__name__ if last_exc else 'empty'}")
            received_epoch = received_dt.timestamp()
            meta = chart_doc.get("meta") or {}
            timestamps = chart_doc.get("timestamp") or []
            quote_block = (((chart_doc.get("indicators") or {}).get("quote") or [{}])[0])
            opens = quote_block.get("open") or []
            highs = quote_block.get("high") or []
            lows = quote_block.get("low") or []
            closes = quote_block.get("close") or []
            vols = quote_block.get("volume") or []
            candles_m1: list[dict[str, Any]] = []
            candle_epochs: list[int] = []
            prev_ts_epoch: int | None = None
            ts_slice = timestamps[-60:]
            offset = len(timestamps) - len(ts_slice)
            for idx, ts_val in enumerate(ts_slice):
                if ts_val is None or isinstance(ts_val, bool):
                    if ts_val is not None:
                        raise ContractError(f"Yahoo index candle timestamp invalid for {sym}: {ts_val!r}")
                    continue
                try:
                    ts_epoch = int(str(ts_val))
                except (TypeError, ValueError):
                    raise ContractError(f"Yahoo index candle timestamp invalid for {sym}: {ts_val!r}") from None
                if ts_epoch <= 0:
                    raise ContractError(f"Yahoo index candle timestamp non-positive for {sym}: {ts_epoch}")
                if prev_ts_epoch is not None and ts_epoch < prev_ts_epoch:
                    raise ContractError(f"Yahoo index non-monotonic candle timestamps for {sym}: {ts_epoch} < {prev_ts_epoch}")
                if float(ts_epoch) > received_epoch + float(self._max_future_skew_seconds):
                    raise ContractError(f"Yahoo index future candle timestamp for {sym}: {ts_epoch}")
                prev_ts_epoch = ts_epoch
                abs_idx = offset + idx
                if abs_idx >= len(closes):
                    continue
                c_raw = closes[abs_idx]
                o_raw = opens[abs_idx] if abs_idx < len(opens) else c_raw
                h_raw = highs[abs_idx] if abs_idx < len(highs) else c_raw
                l_raw = lows[abs_idx] if abs_idx < len(lows) else c_raw
                v_raw = vols[abs_idx] if abs_idx < len(vols) else 0
                if None in (o_raw, h_raw, l_raw, c_raw):
                    continue
                t_iso = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                o_dec = Decimal(str(o_raw)).quantize(tick)
                h_dec = Decimal(str(h_raw)).quantize(tick)
                l_dec = Decimal(str(l_raw)).quantize(tick)
                c_dec = Decimal(str(c_raw)).quantize(tick)
                v_dec = Decimal(str(v_raw or 0)).quantize(Decimal("0.01"))
                candle_epochs.append(ts_epoch)
                candles_m1.append({
                    "t": t_iso,
                    "o": decimal_text(o_dec),
                    "h": decimal_text(max(h_dec, o_dec, c_dec)),
                    "l": decimal_text(min(l_dec, o_dec, c_dec)),
                    "c": decimal_text(c_dec),
                    "v": decimal_text(max(Decimal("0"), v_dec)),
                    "n": 1,
                })
            prov_obs_dt = self._validate_provider_timestamps(
                sym=sym,
                meta=meta,
                candle_epochs=candle_epochs,
                received_dt=received_dt,
            )
            prov_obs_str = prov_obs_dt.isoformat().replace("+00:00", "Z")
            recv_str = received_dt.isoformat().replace("+00:00", "Z")
            top_provider_dts.append(prov_obs_dt)
            top_received_dts.append(received_dt)
            raw_mid = meta.get("regularMarketPrice") or (candles_m1[-1]["c"] if candles_m1 else None)
            if raw_mid is None:
                raise ContractError(f"index price missing for {sym}")
            mid = Decimal(str(raw_mid)).quantize(tick)
            if not (spec["min"] <= mid <= spec["max"]):
                raise ContractError(f"index reference price for {sym} out of bounds: {mid}")
            half_spread = (
                Decimal("0.25") if sym == "SPX500"
                else (Decimal("0.30") if sym == "XAUUSD" else (Decimal("1.25") if sym == "NAS100" else Decimal("2.00")))
            )
            bid = (mid - half_spread).quantize(tick)
            ask = (mid + half_spread).quantize(tick)
            rows.append({
                "pair": sym,
                "display_pair": spec["display"],
                "category": "US_INDEX",
                "base_currency": spec["base_currency"],
                "quote_currency": "USD",
                "tick_size": decimal_text(tick),
                "feed_mode": "PINNED_INDEX_REFERENCE_FEED",
                "bid": decimal_text(bid),
                "ask": decimal_text(ask),
                "mid": decimal_text(mid),
                "spread_points": decimal_text(ask - bid),
                "provider_observed_at": prov_obs_str,
                "received_at": recv_str,
                "observed_at": prov_obs_str,
                "candles_m1": candles_m1,
                "candles_m5": candles_m1[-12:],
                "candles_h1": candles_m1[-2:],
            })
        top_prov_str = min(top_provider_dts).isoformat().replace("+00:00", "Z")
        top_recv_str = max(top_received_dts).isoformat().replace("+00:00", "Z")
        return {
            "schema": "cas-forex.index-stream/1",
            "sequence": int(sequence),
            "provider_observed_at": top_prov_str,
            "received_at": top_recv_str,
            "observed_at": top_prov_str,
            "instruments": list(INDEX_INSTRUMENTS),
            "markets": rows,
        }
