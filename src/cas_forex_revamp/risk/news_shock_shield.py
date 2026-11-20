"""High-Impact Economic Calendar News Shock Shield for CAS Forex Revamp.

Offline-first, deterministic news blackout controller that pauses new entries
(`OPEN_NEW`, `ADD_POSITION`) around scheduled high-impact macroeconomic
releases (CPI, NFP, FOMC, ECB, BOE, BOJ, GDP, PPI, PCE, Retail Sales, Rate
Decisions) while unconditionally permitting protective risk-management actions
(`AMEND_STOP`, `MOVE_BREAKEVEN`, `TRAIL_STOP`, `CLOSE_POSITION`,
`EMERGENCY_CLOSE_ALL`).
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import re
import threading
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_PRE_MINUTES: int = 5
DEFAULT_POST_MINUTES: int = 5
MAX_CALENDAR_PAYLOAD_BYTES: int = 2 * 1024 * 1024  # 2 MiB exact cap
MAX_CALENDAR_EVENTS: int = 25_000

RED_FLAG_CATEGORIES: frozenset[str] = frozenset(
    {
        "CPI",
        "NFP",
        "FOMC",
        "ECB",
        "BOE",
        "BOJ",
        "GDP",
        "PPI",
        "PCE",
        "RETAIL_SALES",
        "RATE_DECISION",
    }
)

KNOWN_FX_CURRENCIES: frozenset[str] = frozenset(
    {
        "USD",
        "EUR",
        "GBP",
        "JPY",
        "CHF",
        "AUD",
        "CAD",
        "NZD",
        "SEK",
        "NOK",
        "DKK",
        "SGD",
        "HKD",
        "MXN",
        "ZAR",
        "TRY",
        "PLN",
        "CZK",
        "HUF",
        "CNY",
        "CNH",
        "INR",
        "BRL",
        "KRW",
        "TWD",
        "THB",
        "IDR",
        "MYR",
        "PHP",
        "ILS",
        "SAR",
        "AED",
        "CLP",
        "COP",
        "PEN",
        "RON",
        "BGN",
        "ISK",
    }
)

VALID_CALENDAR_CURRENCIES: frozenset[str] = KNOWN_FX_CURRENCIES | frozenset({"ALL"})

# Canonical instrument aliases -> currency exposures.
_INDEX_AND_COMMODITY_EXPOSURES: dict[str, tuple[str, frozenset[str]]] = {
    # US Equity Indices (USD)
    "NAS100": ("NAS100", frozenset({"USD"})),
    "USTEC": ("NAS100", frozenset({"USD"})),
    "US100": ("NAS100", frozenset({"USD"})),
    "NDX": ("NAS100", frozenset({"USD"})),
    "NDX100": ("NAS100", frozenset({"USD"})),
    "NAS100USD": ("NAS100", frozenset({"USD"})),
    "NAS100CASH": ("NAS100", frozenset({"USD"})),
    "USTECH": ("NAS100", frozenset({"USD"})),
    "USTECH100": ("NAS100", frozenset({"USD"})),
    "NASDAQ": ("NAS100", frozenset({"USD"})),
    "NASDAQ100": ("NAS100", frozenset({"USD"})),
    "US30": ("US30", frozenset({"USD"})),
    "DJ30": ("US30", frozenset({"USD"})),
    "DJI30": ("US30", frozenset({"USD"})),
    "DJI": ("US30", frozenset({"USD"})),
    "WS30": ("US30", frozenset({"USD"})),
    "US30USD": ("US30", frozenset({"USD"})),
    "US30CASH": ("US30", frozenset({"USD"})),
    "DOW30": ("US30", frozenset({"USD"})),
    "SPX500": ("SPX500", frozenset({"USD"})),
    "US500": ("SPX500", frozenset({"USD"})),
    "SP500": ("SPX500", frozenset({"USD"})),
    "SPX": ("SPX500", frozenset({"USD"})),
    "SPX500USD": ("SPX500", frozenset({"USD"})),
    "US500CASH": ("SPX500", frozenset({"USD"})),
    "SP500CASH": ("SPX500", frozenset({"USD"})),
    "US2000": ("US2000", frozenset({"USD"})),
    "RUS2000": ("US2000", frozenset({"USD"})),
    "SMALLCAP2000": ("US2000", frozenset({"USD"})),
    "DXY": ("DXY", frozenset({"USD"})),
    "USDX": ("DXY", frozenset({"USD"})),
    # Metals & Energy (USD)
    "XAUUSD": ("XAUUSD", frozenset({"USD"})),
    "GOLD": ("XAUUSD", frozenset({"USD"})),
    "XAU": ("XAUUSD", frozenset({"USD"})),
    "XAGUSD": ("XAGUSD", frozenset({"USD"})),
    "SILVER": ("XAGUSD", frozenset({"USD"})),
    "XAG": ("XAGUSD", frozenset({"USD"})),
    "WTI": ("WTI", frozenset({"USD"})),
    "WTIUSD": ("WTI", frozenset({"USD"})),
    "USOIL": ("WTI", frozenset({"USD"})),
    "USOILUSD": ("WTI", frozenset({"USD"})),
    "BRENT": ("BRENT", frozenset({"USD"})),
    "UKOIL": ("BRENT", frozenset({"USD"})),
    # European Equity Indices (EUR)
    "GER40": ("GER40", frozenset({"EUR"})),
    "DAX40": ("GER40", frozenset({"EUR"})),
    "DAX": ("GER40", frozenset({"EUR"})),
    "DE40": ("GER40", frozenset({"EUR"})),
    "DE30": ("GER40", frozenset({"EUR"})),
    "GER30": ("GER40", frozenset({"EUR"})),
    "GER40EUR": ("GER40", frozenset({"EUR"})),
    "EU50": ("EU50", frozenset({"EUR"})),
    "EUR50": ("EU50", frozenset({"EUR"})),
    "STOXX50": ("EU50", frozenset({"EUR"})),
    "FRA40": ("FRA40", frozenset({"EUR"})),
    "CAC40": ("FRA40", frozenset({"EUR"})),
    "ESP35": ("ESP35", frozenset({"EUR"})),
    "ITA40": ("ITA40", frozenset({"EUR"})),
    # UK Equity Indices (GBP)
    "UK100": ("UK100", frozenset({"GBP"})),
    "FTSE100": ("UK100", frozenset({"GBP"})),
    "FTSE": ("UK100", frozenset({"GBP"})),
    "UK100GBP": ("UK100", frozenset({"GBP"})),
    # Japanese Equity Indices (JPY)
    "JP225": ("JP225", frozenset({"JPY"})),
    "JPN225": ("JP225", frozenset({"JPY"})),
    "NIKKEI": ("JP225", frozenset({"JPY"})),
    "NIKKEI225": ("JP225", frozenset({"JPY"})),
    "NI225": ("JP225", frozenset({"JPY"})),
    "JP225JPY": ("JP225", frozenset({"JPY"})),
    "JP225USD": ("JP225USD", frozenset({"JPY", "USD"})),
    # Other Regional Indices
    "AU200": ("AU200", frozenset({"AUD"})),
    "AUS200": ("AU200", frozenset({"AUD"})),
    "ASX200": ("AU200", frozenset({"AUD"})),
    "CH20": ("CH20", frozenset({"CHF"})),
    "SMI20": ("CH20", frozenset({"CHF"})),
    "SWI20": ("CH20", frozenset({"CHF"})),
    "CA60": ("CA60", frozenset({"CAD"})),
    "TSX60": ("CA60", frozenset({"CAD"})),
    "CN50": ("CN50", frozenset({"CNY"})),
    "CHINA50": ("CN50", frozenset({"CNY"})),
    "HK50": ("HK50", frozenset({"HKD", "CNY"})),
    "HSI": ("HK50", frozenset({"HKD", "CNY"})),
}

_BROKER_SUFFIX_RE = re.compile(r"(=X|\.(CASH|PRO|RAW|ECN|STD|MINI|MICRO))$")
_SEPARATOR_RE = re.compile(r"[\s/_.-]+")
_KRAKEN_FX_RE = re.compile(r"^Z([A-Z]{3})Z([A-Z]{3})$")
_ISO_TZ_RE = re.compile(r"(Z|[+-]\d{2}:\d{2})$", re.IGNORECASE)

_IMPACT_RANK: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


class NewsCalendarParseError(ValueError):
    """Raised when an economic calendar JSON payload or file fails strict validation."""


class NewsImpact(str, Enum):
    """Macroeconomic event impact severity."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return _IMPACT_RANK[self.value]

    def __lt__(self, other: object) -> bool:
        if isinstance(other, NewsImpact):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, NewsImpact):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, NewsImpact):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, NewsImpact):
            return self.rank >= other.rank
        return NotImplemented


class TradeActionType(str, Enum):
    """Execution action classification for news shock gating."""

    OPEN_NEW = "OPEN_NEW"
    ADD_POSITION = "ADD_POSITION"
    AMEND_STOP = "AMEND_STOP"
    MOVE_BREAKEVEN = "MOVE_BREAKEVEN"
    TRAIL_STOP = "TRAIL_STOP"
    CLOSE_POSITION = "CLOSE_POSITION"
    EMERGENCY_CLOSE_ALL = "EMERGENCY_CLOSE_ALL"

    @property
    def is_protective(self) -> bool:
        return self in PROTECTIVE_ACTIONS

    @property
    def is_entry(self) -> bool:
        return self in ENTRY_ACTIONS


PROTECTIVE_ACTIONS: frozenset[TradeActionType] = frozenset(
    {
        TradeActionType.AMEND_STOP,
        TradeActionType.MOVE_BREAKEVEN,
        TradeActionType.TRAIL_STOP,
        TradeActionType.CLOSE_POSITION,
        TradeActionType.EMERGENCY_CLOSE_ALL,
    }
)

ENTRY_ACTIONS: frozenset[TradeActionType] = frozenset(
    {
        TradeActionType.OPEN_NEW,
        TradeActionType.ADD_POSITION,
    }
)


def _require_utc_datetime(value: datetime, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a datetime instance")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC (naive datetime rejected)")
    return value.astimezone(timezone.utc)


def _format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_category(category: str) -> str:
    return re.sub(r"[\s/-]+", "_", category.strip().upper())


@dataclass(frozen=True)
class EconomicEvent:
    """Immutable scheduled macroeconomic event."""

    event_id: str
    title: str
    currency: str
    impact: NewsImpact
    scheduled_utc: datetime
    category: str
    source: str

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise ValueError("event_id must be a non-empty string")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("title must be a non-empty string")
        if not isinstance(self.currency, str) or not self.currency.strip():
            raise ValueError("currency must be a non-empty string")
        norm_ccy = self.currency.strip().upper()
        if norm_ccy not in VALID_CALENDAR_CURRENCIES:
            raise ValueError(f"Unsupported currency code: {self.currency!r}")
        if not isinstance(self.impact, NewsImpact):
            raise ValueError(f"impact must be a NewsImpact enum, got {type(self.impact).__name__}")
        utc_dt = _require_utc_datetime(self.scheduled_utc, field_name="scheduled_utc")
        if not isinstance(self.category, str) or not self.category.strip():
            raise ValueError("category must be a non-empty string")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("source must be a non-empty string")

        object.__setattr__(self, "event_id", self.event_id.strip())
        object.__setattr__(self, "title", self.title.strip())
        object.__setattr__(self, "currency", norm_ccy)
        object.__setattr__(self, "scheduled_utc", utc_dt)
        object.__setattr__(self, "category", _normalize_category(self.category))
        object.__setattr__(self, "source", self.source.strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "title": self.title,
            "currency": self.currency,
            "impact": self.impact.value,
            "scheduled_utc": _format_utc(self.scheduled_utc),
            "category": self.category,
            "source": self.source,
        }


@dataclass(frozen=True)
class NewsShieldDecision:
    """Immutable gate decision produced by NewsShockShield."""

    allowed: bool
    reason_code: str
    action: TradeActionType
    symbol: str
    blocking_events: tuple[EconomicEvent, ...]
    resume_at_utc: datetime | None
    evaluated_at_utc: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.action, TradeActionType):
            raise ValueError("action must be a TradeActionType")
        utc_eval = _require_utc_datetime(self.evaluated_at_utc, field_name="evaluated_at_utc")
        object.__setattr__(self, "evaluated_at_utc", utc_eval)
        if self.resume_at_utc is not None:
            utc_resume = _require_utc_datetime(self.resume_at_utc, field_name="resume_at_utc")
            object.__setattr__(self, "resume_at_utc", utc_resume)
        object.__setattr__(self, "blocking_events", tuple(self.blocking_events))

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "action": self.action.value,
            "symbol": self.symbol,
            "blocking_events": [ev.to_dict() for ev in self.blocking_events],
            "resume_at_utc": _format_utc(self.resume_at_utc) if self.resume_at_utc is not None else None,
            "evaluated_at_utc": _format_utc(self.evaluated_at_utc),
        }


@dataclass(frozen=True)
class NewsCalendar:
    """Validated immutable calendar snapshot loaded from offline JSON or transport."""

    events: tuple[EconomicEvent, ...]
    generated_at_utc: datetime | None
    source: str
    payload_sha256: str

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[EconomicEvent]:
        return iter(self.events)


@runtime_checkable
class CalendarTransport(Protocol):
    """Pluggable transport protocol for supplying raw calendar JSON strings/bytes."""

    def fetch_calendar_json(self) -> str | bytes:
        """Return raw UTF-8 JSON calendar payload."""


def validate_https_calendar_url(url: str) -> str:
    """Validate an optional remote calendar URL against SSRF & plaintext rules.

    Purely offline validation (performs zero network or DNS calls):
    - Requires strict ``https://`` scheme
    - Rejects embedded credentials, localhost, ``.local``/``.internal`` hosts,
      and loopback/private/link-local/reserved/multicast IP literals.
    """
    if not isinstance(url, str) or not url.strip():
        raise NewsCalendarParseError("Calendar URL must be a non-empty string")
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise NewsCalendarParseError("Calendar URL must use https:// scheme only")
    if parsed.username is not None or parsed.password is not None:
        raise NewsCalendarParseError("Calendar URL must not embed credentials")
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise NewsCalendarParseError("Calendar URL must include a valid hostname")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith((".local", ".internal", ".localhost")):
        raise NewsCalendarParseError(f"Calendar URL host rejected by SSRF guard: {hostname!r}")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise NewsCalendarParseError(f"Calendar URL IP rejected by SSRF guard: {hostname!r}")
    return cleaned


def _resolve_symbol_internal(symbol: str) -> tuple[str, frozenset[str], bool]:
    """Return ``(normalized_symbol, currencies, is_known)`` for an instrument string."""
    if not isinstance(symbol, str) or not symbol.strip():
        return ("", frozenset(), False)

    raw = symbol.strip().upper()
    stripped_suffix = _BROKER_SUFFIX_RE.sub("", raw)
    compact = _SEPARATOR_RE.sub("", stripped_suffix)

    if compact in _INDEX_AND_COMMODITY_EXPOSURES:
        canonical, ccys = _INDEX_AND_COMMODITY_EXPOSURES[compact]
        return (canonical, ccys, True)

    kraken_match = _KRAKEN_FX_RE.match(compact)
    if kraken_match is not None:
        base, quote = kraken_match.group(1), kraken_match.group(2)
        if base in KNOWN_FX_CURRENCIES and quote in KNOWN_FX_CURRENCIES and base != quote:
            return (f"{base}{quote}", frozenset({base, quote}), True)

    # Explicit precious-metal cross like XAUEUR / XAGEUR
    if len(compact) == 6 and compact[:3] in {"XAU", "XAG"} and compact[3:] in KNOWN_FX_CURRENCIES:
        return (compact, frozenset({compact[3:]}), True)

    # Standard 6-letter FX pair (e.g., EURUSD, EUR_USD, GBP/JPY, USD-CAD)
    if len(compact) == 6:
        base, quote = compact[:3], compact[3:]
        if base in KNOWN_FX_CURRENCIES and quote in KNOWN_FX_CURRENCIES and base != quote:
            return (f"{base}{quote}", frozenset({base, quote}), True)

    return (compact or raw, frozenset(), False)


def normalize_symbol(symbol: str) -> str:
    """Normalize a market instrument symbol to its canonical uppercase identifier."""
    canonical, _, _ = _resolve_symbol_internal(symbol)
    return canonical


def currencies_for_symbol(
    symbol: str,
    *,
    strict_unknown_symbol: bool = False,
) -> frozenset[str]:
    """Return the set of ISO currency codes exposed to ``symbol``.

    Unknown symbols never raise: when ``strict_unknown_symbol=False`` (default),
    logs an ``UNKNOWN_SYMBOL`` warning and returns an empty frozenset; when
    ``strict_unknown_symbol=True``, logs a warning and conservatively treats
    the symbol as USD-sensitive (``frozenset({"USD"})``).
    """
    _, currencies, is_known = _resolve_symbol_internal(symbol)
    if is_known:
        return currencies
    logger.warning(
        "UNKNOWN_SYMBOL: %r not in currency exposure map (strict_unknown_symbol=%s)",
        symbol,
        strict_unknown_symbol,
    )
    if strict_unknown_symbol:
        return frozenset({"USD"})
    return frozenset()


def _parse_strict_utc_timestamp(raw_value: Any, *, field_name: str) -> datetime:
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise NewsCalendarParseError(f"{field_name} must be a non-empty ISO-8601 UTC timestamp string")
    text = raw_value.strip()
    if "T" not in text and "t" not in text and " " not in text:
        raise NewsCalendarParseError(f"{field_name} must include time and timezone offset: {text!r}")
    if _ISO_TZ_RE.search(text) is None:
        raise NewsCalendarParseError(
            f"{field_name} must include explicit 'Z' or numeric UTC offset (naive timestamp rejected): {text!r}"
        )
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise NewsCalendarParseError(f"Invalid ISO-8601 timestamp for {field_name}: {text!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise NewsCalendarParseError(f"{field_name} must be timezone-aware UTC: {text!r}")
    return parsed.astimezone(timezone.utc)


def _parse_impact(raw_value: Any) -> NewsImpact:
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise NewsCalendarParseError("impact must be one of LOW, MEDIUM, HIGH")
    normalized = raw_value.strip().upper()
    try:
        return NewsImpact(normalized)
    except ValueError as exc:
        raise NewsCalendarParseError(f"Invalid impact level: {raw_value!r}") from exc


def _parse_currency(raw_value: Any) -> str:
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise NewsCalendarParseError("currency must be a valid 3-letter ISO code or 'ALL'")
    normalized = raw_value.strip().upper()
    if normalized not in VALID_CALENDAR_CURRENCIES:
        raise NewsCalendarParseError(f"Invalid or unsupported calendar currency: {raw_value!r}")
    return normalized


def _parse_event_dict(item: Any, *, index: int, default_source: str) -> EconomicEvent:
    if not isinstance(item, dict):
        raise NewsCalendarParseError(f"Calendar event at index {index} must be a JSON object")

    for req_key in ("event_id", "title", "currency", "impact", "scheduled_utc"):
        if req_key not in item:
            raise NewsCalendarParseError(f"Calendar event at index {index} missing required field {req_key!r}")

    event_id = item["event_id"]
    if not isinstance(event_id, str) or not event_id.strip():
        raise NewsCalendarParseError(f"Calendar event at index {index} has invalid event_id")

    title = item["title"]
    if not isinstance(title, str) or not title.strip():
        raise NewsCalendarParseError(f"Calendar event at index {index} has invalid title")

    currency = _parse_currency(item["currency"])
    impact = _parse_impact(item["impact"])
    scheduled_utc = _parse_strict_utc_timestamp(
        item["scheduled_utc"],
        field_name=f"events[{index}].scheduled_utc",
    )

    if "category" in item:
        raw_cat = item["category"]
        if not isinstance(raw_cat, str) or not raw_cat.strip():
            raise NewsCalendarParseError(f"Calendar event at index {index} has invalid category")
        category = _normalize_category(raw_cat)
    else:
        category = "ECONOMIC_RELEASE"

    if "source" in item:
        raw_src = item["source"]
        if not isinstance(raw_src, str) or not raw_src.strip():
            raise NewsCalendarParseError(f"Calendar event at index {index} has invalid source")
        source = raw_src.strip()
    else:
        source = default_source

    try:
        return EconomicEvent(
            event_id=event_id,
            title=title,
            currency=currency,
            impact=impact,
            scheduled_utc=scheduled_utc,
            category=category,
            source=source,
        )
    except ValueError as exc:
        raise NewsCalendarParseError(f"Calendar event at index {index} invalid: {exc}") from exc


def load_calendar_json(raw_json: str | bytes) -> NewsCalendar:
    """Strictly validate and parse an offline economic calendar JSON payload.

    Accepts either:
    - A JSON object: ``{"events": [...], "generated_at_utc": "...Z", "source": "..."}``
    - A JSON array of event objects: ``[{...}, ...]``

    Raises ``NewsCalendarParseError`` on malformed JSON, payloads > 2 MiB,
    naive timestamps, invalid currency/impact values, or duplicate event IDs.
    """
    if isinstance(raw_json, bytes):
        raw_bytes = raw_json
        if len(raw_bytes) > MAX_CALENDAR_PAYLOAD_BYTES:
            raise NewsCalendarParseError(
                f"Calendar payload size {len(raw_bytes)} bytes exceeds limit of {MAX_CALENDAR_PAYLOAD_BYTES} bytes"
            )
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NewsCalendarParseError("Calendar payload is not valid UTF-8") from exc
    elif isinstance(raw_json, str):
        raw_bytes = raw_json.encode("utf-8")
        if len(raw_bytes) > MAX_CALENDAR_PAYLOAD_BYTES:
            raise NewsCalendarParseError(
                f"Calendar payload size {len(raw_bytes)} bytes exceeds limit of {MAX_CALENDAR_PAYLOAD_BYTES} bytes"
            )
        text = raw_json
    else:
        raise NewsCalendarParseError(f"Expected str or bytes for calendar JSON, got {type(raw_json).__name__}")

    if not text.strip():
        raise NewsCalendarParseError("Calendar JSON payload is empty")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NewsCalendarParseError(f"Malformed calendar JSON: {exc}") from exc

    generated_at_utc: datetime | None = None
    default_source = "offline_json"

    if isinstance(parsed, dict):
        if "events" not in parsed or not isinstance(parsed["events"], list):
            raise NewsCalendarParseError("Calendar JSON object must contain an 'events' list")
        raw_events = parsed["events"]
        if "source" in parsed and parsed["source"] is not None:
            if not isinstance(parsed["source"], str) or not parsed["source"].strip():
                raise NewsCalendarParseError("Calendar top-level 'source' must be a non-empty string")
            default_source = parsed["source"].strip()
        ts_field = (
            "generated_at_utc"
            if "generated_at_utc" in parsed
            else ("updated_at_utc" if "updated_at_utc" in parsed else None)
        )
        if ts_field is not None and parsed[ts_field] is not None:
            generated_at_utc = _parse_strict_utc_timestamp(parsed[ts_field], field_name=ts_field)
    elif isinstance(parsed, list):
        raw_events = parsed
    else:
        raise NewsCalendarParseError("Calendar JSON root must be an object or a list of events")

    if len(raw_events) > MAX_CALENDAR_EVENTS:
        raise NewsCalendarParseError(
            f"Calendar event count {len(raw_events)} exceeds maximum of {MAX_CALENDAR_EVENTS}"
        )

    events: list[EconomicEvent] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(raw_events):
        ev = _parse_event_dict(item, index=idx, default_source=default_source)
        if ev.event_id in seen_ids:
            raise NewsCalendarParseError(f"Duplicate event_id in calendar payload: {ev.event_id!r}")
        seen_ids.add(ev.event_id)
        events.append(ev)

    events.sort(key=lambda e: (e.scheduled_utc, e.event_id))
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return NewsCalendar(
        events=tuple(events),
        generated_at_utc=generated_at_utc,
        source=default_source,
        payload_sha256=digest,
    )


def load_calendar_file(path: str | Path) -> NewsCalendar:
    """Strictly load and validate an economic calendar JSON file from disk."""
    file_path = Path(path)
    try:
        stat = file_path.stat()
    except OSError as exc:
        raise NewsCalendarParseError(f"Unable to access calendar file {str(file_path)!r}: {exc}") from exc
    if not file_path.is_file():
        raise NewsCalendarParseError(f"Calendar path is not a regular file: {str(file_path)!r}")
    if stat.st_size > MAX_CALENDAR_PAYLOAD_BYTES:
        raise NewsCalendarParseError(
            f"Calendar file size {stat.st_size} bytes exceeds limit of {MAX_CALENDAR_PAYLOAD_BYTES} bytes"
        )
    try:
        raw_bytes = file_path.read_bytes()
    except OSError as exc:
        raise NewsCalendarParseError(f"Unable to read calendar file {str(file_path)!r}: {exc}") from exc
    return load_calendar_json(raw_bytes)


class NewsShockShield:
    """Deterministic High-Impact Economic Calendar News Shock Shield.

    Safety invariants:
    1. Protective actions (`AMEND_STOP`, `MOVE_BREAKEVEN`, `TRAIL_STOP`,
       `CLOSE_POSITION`, `EMERGENCY_CLOSE_ALL`) are ALWAYS allowed, even at the
       exact peak second of a red-flag release or when the calendar is stale.
    2. Entry actions (`OPEN_NEW`, `ADD_POSITION`) are paused inclusively across
       ``[scheduled_utc - pre_minutes, scheduled_utc + post_minutes]`` for any
       event with ``impact >= min_impact`` whose currency matches the symbol's
       exposure (or ``currency == "ALL"``).
    3. Zero ambient network calls in default offline mode.
    """

    def __init__(
        self,
        events: NewsCalendar | Sequence[EconomicEvent] = (),
        *,
        pre_minutes: int = DEFAULT_PRE_MINUTES,
        post_minutes: int = DEFAULT_POST_MINUTES,
        min_impact: NewsImpact = NewsImpact.HIGH,
        strict_unknown_symbol: bool = False,
        fail_closed_on_stale_calendar: bool = False,
        max_calendar_age_hours: float = 24.0,
        calendar_updated_at_utc: datetime | None = None,
        tracked_categories: Collection[str] | None = None,
        transport: CalendarTransport | None = None,
    ) -> None:
        if isinstance(pre_minutes, bool) or not isinstance(pre_minutes, int) or pre_minutes < 0:
            raise ValueError("pre_minutes must be a non-negative integer")
        if isinstance(post_minutes, bool) or not isinstance(post_minutes, int) or post_minutes < 0:
            raise ValueError("post_minutes must be a non-negative integer")
        if not isinstance(min_impact, NewsImpact):
            raise ValueError("min_impact must be a NewsImpact enum")
        if isinstance(max_calendar_age_hours, bool) or max_calendar_age_hours <= 0:
            raise ValueError("max_calendar_age_hours must be > 0")

        self._lock = threading.RLock()
        self._pre_minutes = pre_minutes
        self._post_minutes = post_minutes
        self._pre_delta = timedelta(minutes=pre_minutes)
        self._post_delta = timedelta(minutes=post_minutes)
        self._min_impact = min_impact
        self._strict_unknown_symbol = bool(strict_unknown_symbol)
        self._fail_closed_on_stale_calendar = bool(fail_closed_on_stale_calendar)
        self._max_calendar_age = timedelta(hours=float(max_calendar_age_hours))
        self._tracked_categories: frozenset[str] | None = (
            frozenset(_normalize_category(c) for c in tracked_categories)
            if tracked_categories is not None
            else None
        )
        self._transport = transport

        if isinstance(events, NewsCalendar):
            loaded_events = events.events
            inherited_updated_at = events.generated_at_utc
        else:
            raw_list = list(events)
            for ev in raw_list:
                if not isinstance(ev, EconomicEvent):
                    raise TypeError(f"Expected EconomicEvent, got {type(ev).__name__}")
            loaded_events = tuple(sorted(raw_list, key=lambda e: (e.scheduled_utc, e.event_id)))
            inherited_updated_at = None

        resolved_updated_at = (
            calendar_updated_at_utc if calendar_updated_at_utc is not None else inherited_updated_at
        )
        self._calendar_updated_at_utc: datetime | None = (
            _require_utc_datetime(resolved_updated_at, field_name="calendar_updated_at_utc")
            if resolved_updated_at is not None
            else None
        )
        self._events: tuple[EconomicEvent, ...] = loaded_events

    @classmethod
    def from_json(
        cls,
        raw_json: str | bytes,
        **kwargs: Any,
    ) -> NewsShockShield:
        """Create a NewsShockShield directly from a validated calendar JSON payload."""
        calendar = load_calendar_json(raw_json)
        return cls(calendar, **kwargs)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        **kwargs: Any,
    ) -> NewsShockShield:
        """Create a NewsShockShield directly from a validated offline calendar JSON file."""
        calendar = load_calendar_file(path)
        return cls(calendar, **kwargs)

    @property
    def pre_minutes(self) -> int:
        return self._pre_minutes

    @property
    def post_minutes(self) -> int:
        return self._post_minutes

    @property
    def min_impact(self) -> NewsImpact:
        return self._min_impact

    @property
    def strict_unknown_symbol(self) -> bool:
        return self._strict_unknown_symbol

    @property
    def fail_closed_on_stale_calendar(self) -> bool:
        return self._fail_closed_on_stale_calendar

    @property
    def calendar_updated_at_utc(self) -> datetime | None:
        with self._lock:
            return self._calendar_updated_at_utc

    @property
    def events(self) -> tuple[EconomicEvent, ...]:
        with self._lock:
            return self._events

    def refresh_from_transport(
        self,
        transport: CalendarTransport | None = None,
        *,
        now_utc: datetime | None = None,
    ) -> NewsCalendar:
        """Load and validate a fresh calendar from an injected offline/pluggable transport."""
        active_transport = transport if transport is not None else self._transport
        if active_transport is None:
            raise NewsCalendarParseError("No CalendarTransport configured for refresh")
        eval_utc = (
            _require_utc_datetime(now_utc, field_name="now_utc")
            if now_utc is not None
            else datetime.now(timezone.utc)
        )
        raw_payload = active_transport.fetch_calendar_json()
        calendar = load_calendar_json(raw_payload)
        updated_at = calendar.generated_at_utc if calendar.generated_at_utc is not None else eval_utc
        with self._lock:
            self._events = calendar.events
            self._calendar_updated_at_utc = updated_at
        return calendar

    def _is_calendar_stale(self, eval_utc: datetime, updated_at: datetime | None) -> bool:
        if not self._fail_closed_on_stale_calendar:
            return False
        if updated_at is None:
            return True
        return (eval_utc - updated_at) > self._max_calendar_age

    def _event_matches_filter(self, event: EconomicEvent) -> bool:
        if event.impact < self._min_impact:
            return False
        if self._tracked_categories is not None and event.category not in self._tracked_categories:
            return False
        return True

    def _event_affects_currencies(
        self,
        event: EconomicEvent,
        exposed_currencies: frozenset[str],
    ) -> bool:
        if event.currency == "ALL":
            return True
        return event.currency in exposed_currencies

    def evaluate(
        self,
        symbol: str,
        action: TradeActionType,
        now_utc: datetime | None = None,
    ) -> NewsShieldDecision:
        """Evaluate whether ``action`` on ``symbol`` is permitted at ``now_utc``."""
        if not isinstance(action, TradeActionType):
            raise TypeError(f"action must be a TradeActionType enum, got {type(action).__name__}")

        eval_utc = (
            _require_utc_datetime(now_utc, field_name="now_utc")
            if now_utc is not None
            else datetime.now(timezone.utc)
        )

        normalized_symbol, resolved_ccys, is_known = _resolve_symbol_internal(symbol)
        display_symbol = normalized_symbol or (symbol.strip().upper() if isinstance(symbol, str) else "")

        # CRITICAL SAFETY INVARIANT: Protective stop/breakeven/trail/close actions
        # are unconditionally allowed, even at the exact second of CPI/FOMC/NFP
        # or during a stale-calendar fail-closed state.
        if action in PROTECTIVE_ACTIONS:
            return NewsShieldDecision(
                allowed=True,
                reason_code="PROTECTIVE_ACTION_ALWAYS_ALLOWED",
                action=action,
                symbol=display_symbol,
                blocking_events=(),
                resume_at_utc=None,
                evaluated_at_utc=eval_utc,
            )

        if not is_known:
            exposed_ccys = currencies_for_symbol(
                symbol,
                strict_unknown_symbol=self._strict_unknown_symbol,
            )
        else:
            exposed_ccys = resolved_ccys

        with self._lock:
            current_events = self._events
            updated_at = self._calendar_updated_at_utc

        blocking: list[EconomicEvent] = []
        for event in current_events:
            if not self._event_matches_filter(event):
                continue
            if not self._event_affects_currencies(event, exposed_ccys):
                continue
            window_start = event.scheduled_utc - self._pre_delta
            window_end = event.scheduled_utc + self._post_delta
            if window_start <= eval_utc <= window_end:
                blocking.append(event)

        if blocking:
            blocking.sort(key=lambda e: (e.scheduled_utc, e.event_id))
            resume_at = max(e.scheduled_utc + self._post_delta for e in blocking)
            return NewsShieldDecision(
                allowed=False,
                reason_code="NEW_ENTRY_PAUSED_NEWS_WINDOW",
                action=action,
                symbol=display_symbol,
                blocking_events=tuple(blocking),
                resume_at_utc=resume_at,
                evaluated_at_utc=eval_utc,
            )

        if self._is_calendar_stale(eval_utc, updated_at):
            return NewsShieldDecision(
                allowed=False,
                reason_code="CALENDAR_STALE_FAIL_CLOSED",
                action=action,
                symbol=display_symbol,
                blocking_events=(),
                resume_at_utc=None,
                evaluated_at_utc=eval_utc,
            )

        if not is_known:
            return NewsShieldDecision(
                allowed=True,
                reason_code="UNKNOWN_SYMBOL",
                action=action,
                symbol=display_symbol,
                blocking_events=(),
                resume_at_utc=None,
                evaluated_at_utc=eval_utc,
            )

        return NewsShieldDecision(
            allowed=True,
            reason_code="ALLOWED_NO_ACTIVE_NEWS",
            action=action,
            symbol=display_symbol,
            blocking_events=(),
            resume_at_utc=None,
            evaluated_at_utc=eval_utc,
        )

    def make_pre_slice_guard(
        self,
        *,
        action: TradeActionType = TradeActionType.OPEN_NEW,
        clock: Callable[[], datetime] | None = None,
        default_symbol: str | None = None,
    ) -> Callable[[Any], tuple[bool, str]]:
        """Build a zero-coupling ``pre_slice_guard`` callback for SmartExecutionPlanner.

        Accepts any slice object exposing ``.symbol`` (or a mapping with ``"symbol"``,
        or a symbol string) and returns ``(decision.allowed, decision.reason_code)``.
        """
        if not isinstance(action, TradeActionType):
            raise TypeError(f"action must be a TradeActionType enum, got {type(action).__name__}")

        def _guard(slice_obj: Any) -> tuple[bool, str]:
            sym: str | None = None
            if hasattr(slice_obj, "symbol"):
                sym = getattr(slice_obj, "symbol")
            elif isinstance(slice_obj, Mapping) and "symbol" in slice_obj:
                sym = str(slice_obj["symbol"])
            elif isinstance(slice_obj, str):
                sym = slice_obj
            if not sym:
                sym = default_symbol or ""
            now = clock() if clock is not None else datetime.now(timezone.utc)
            decision = self.evaluate(symbol=sym, action=action, now_utc=now)
            return (decision.allowed, decision.reason_code)

        return _guard

    def shield_status_snapshot(
        self,
        symbols: Sequence[str],
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Return a read-only, side-effect-free plain-English status & countdown snapshot."""
        eval_utc = (
            _require_utc_datetime(now_utc, field_name="now_utc")
            if now_utc is not None
            else datetime.now(timezone.utc)
        )

        with self._lock:
            current_events = self._events
            updated_at = self._calendar_updated_at_utc

        is_stale = self._is_calendar_stale(eval_utc, updated_at)
        symbol_reports: dict[str, dict[str, Any]] = {}
        paused_news_symbols: list[str] = []
        paused_stale_symbols: list[str] = []
        upcoming_by_event_id: dict[str, dict[str, Any]] = {}

        for raw_sym in symbols:
            decision = self.evaluate(symbol=raw_sym, action=TradeActionType.OPEN_NEW, now_utc=eval_utc)
            normalized_sym, resolved_ccys, is_known = _resolve_symbol_internal(raw_sym)
            exposed_ccys = (
                resolved_ccys
                if is_known
                else (frozenset({"USD"}) if self._strict_unknown_symbol else frozenset())
            )

            next_upcoming: dict[str, Any] | None = None
            for ev in current_events:
                if not self._event_matches_filter(ev):
                    continue
                if not self._event_affects_currencies(ev, exposed_ccys):
                    continue
                b_start = ev.scheduled_utc - self._pre_delta
                b_end = ev.scheduled_utc + self._post_delta
                if b_start > eval_utc:
                    seconds_to_start = int((b_start - eval_utc).total_seconds())
                    seconds_to_event = int((ev.scheduled_utc - eval_utc).total_seconds())
                    ev_entry = {
                        "event_id": ev.event_id,
                        "title": ev.title,
                        "currency": ev.currency,
                        "impact": ev.impact.value,
                        "category": ev.category,
                        "source": ev.source,
                        "scheduled_utc": _format_utc(ev.scheduled_utc),
                        "blackout_starts_at_utc": _format_utc(b_start),
                        "blackout_ends_at_utc": _format_utc(b_end),
                        "seconds_until_blackout_start": seconds_to_start,
                        "seconds_until_event": seconds_to_event,
                    }
                    if next_upcoming is None:
                        next_upcoming = ev_entry

                    if ev.event_id not in upcoming_by_event_id:
                        upcoming_by_event_id[ev.event_id] = {
                            **ev_entry,
                            "affected_symbols": [raw_sym],
                        }
                    else:
                        if raw_sym not in upcoming_by_event_id[ev.event_id]["affected_symbols"]:
                            upcoming_by_event_id[ev.event_id]["affected_symbols"].append(raw_sym)

            seconds_until_resume: int | None = None
            if decision.resume_at_utc is not None:
                seconds_until_resume = max(0, int((decision.resume_at_utc - eval_utc).total_seconds()))

            if not decision.allowed and decision.reason_code == "NEW_ENTRY_PAUSED_NEWS_WINDOW":
                paused_news_symbols.append(raw_sym)
                titles = ", ".join(ev.title for ev in decision.blocking_events)
                resume_str = _format_utc(decision.resume_at_utc) if decision.resume_at_utc is not None else "unknown"
                plain_status = (
                    f"New entries paused for {raw_sym} due to {titles}. "
                    f"Resumes at {resume_str} ({seconds_until_resume} seconds remaining). "
                    "Protective stop and close actions remain active."
                )
            elif not decision.allowed and decision.reason_code == "CALENDAR_STALE_FAIL_CLOSED":
                paused_stale_symbols.append(raw_sym)
                plain_status = (
                    f"New entries paused for {raw_sym} because the economic calendar is out of date. "
                    "Protective stop and close actions remain active."
                )
            elif decision.reason_code == "UNKNOWN_SYMBOL":
                plain_status = (
                    f"New entries allowed for {raw_sym} with an unknown-symbol warning. "
                    "Protective stop and close actions remain active."
                )
            else:
                if next_upcoming is not None:
                    plain_status = (
                        f"New entries clear for {raw_sym}. Next high-impact pause is {next_upcoming['title']} "
                        f"in {next_upcoming['seconds_until_blackout_start']} seconds "
                        f"(starts {next_upcoming['blackout_starts_at_utc']}). "
                        "Protective stop and close actions remain active."
                    )
                else:
                    plain_status = (
                        f"New entries clear for {raw_sym} with no upcoming high-impact pauses scheduled. "
                        "Protective stop and close actions remain active."
                    )

            symbol_reports[raw_sym] = {
                "normalized_symbol": normalized_sym or raw_sym.strip().upper(),
                "currencies": sorted(exposed_ccys),
                "new_entries_allowed": decision.allowed,
                "protective_actions_allowed": True,
                "reason_code": decision.reason_code,
                "plain_english_status": plain_status,
                "active_blocking_events": [ev.to_dict() for ev in decision.blocking_events],
                "resume_at_utc": _format_utc(decision.resume_at_utc) if decision.resume_at_utc is not None else None,
                "seconds_until_resume": seconds_until_resume,
                "next_upcoming_event": next_upcoming,
            }

        upcoming_blackouts = sorted(
            upcoming_by_event_id.values(),
            key=lambda item: (item["seconds_until_blackout_start"], item["event_id"]),
        )

        if paused_news_symbols:
            overall_status = "PAUSED_NEWS_WINDOW"
            plain_summary = (
                f"New entries are currently paused for {', '.join(paused_news_symbols)} due to active "
                "high-impact economic news. All protective stop and close actions remain fully active."
            )
        elif paused_stale_symbols:
            overall_status = "PAUSED_STALE_CALENDAR"
            plain_summary = (
                f"New entries are paused for {', '.join(paused_stale_symbols)} because the economic "
                "calendar is stale. All protective stop and close actions remain fully active."
            )
        else:
            overall_status = "CLEAR"
            plain_summary = (
                f"All {len(symbols)} monitored markets are clear for new entries. "
                "All protective stop and close actions remain fully active."
            )

        return {
            "evaluated_at_utc": _format_utc(eval_utc),
            "pre_minutes": self._pre_minutes,
            "post_minutes": self._post_minutes,
            "min_impact": self._min_impact.value,
            "calendar_updated_at_utc": _format_utc(updated_at) if updated_at is not None else None,
            "calendar_stale": is_stale,
            "fail_closed_on_stale_calendar": self._fail_closed_on_stale_calendar,
            "protective_actions_always_allowed": True,
            "overall_status": overall_status,
            "plain_english_summary": plain_summary,
            "symbols": symbol_reports,
            "upcoming_blackouts": upcoming_blackouts,
        }


__all__ = [
    "CalendarTransport",
    "DEFAULT_POST_MINUTES",
    "DEFAULT_PRE_MINUTES",
    "ENTRY_ACTIONS",
    "EconomicEvent",
    "KNOWN_FX_CURRENCIES",
    "MAX_CALENDAR_EVENTS",
    "MAX_CALENDAR_PAYLOAD_BYTES",
    "NewsCalendar",
    "NewsCalendarParseError",
    "NewsImpact",
    "NewsShieldDecision",
    "NewsShockShield",
    "PROTECTIVE_ACTIONS",
    "RED_FLAG_CATEGORIES",
    "TradeActionType",
    "VALID_CALENDAR_CURRENCIES",
    "currencies_for_symbol",
    "load_calendar_file",
    "load_calendar_json",
    "normalize_symbol",
    "validate_https_calendar_url",
]
