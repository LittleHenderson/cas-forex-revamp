"""Smart Order Slicing & Spread-Aware Limit Execution for CAS Forex Revamp (Phase 8).

Clear Street-inspired institutional execution layer adapted for CAS Forex:
- ``SINGLE_MARKET``: direct single-slice market passthrough when spread is within bounds.
- ``TWAP_SLICED``: time-weighted average price child slicing with exact ``Decimal``
  ``ROUND_FLOOR`` to ``0.01``-lot increments, guaranteeing total planned lots are
  strictly ``<=`` requested lot/risk budget (never rounding up above risk budget;
  honest refusal via ``SliceRefusalError`` when budget yields ``< 0.01`` lots).
- ``PULLBACK_LIMIT``: spread-aware passive/pullback limit pricing inside/near the
  bid-ask spread (``NAS100`` default max spread ``2.50`` pts, ``US30`` ``5.00`` pts,
  ``XAUUSD`` ``0.80`` pts, FX pairs), with adverse slippage collar and TTL expiry
  so stale unfilled limits cancel safely instead of chasing runaway candles.

Mandatory safety & constitutional invariants (zero bypasses):
1. ``ForexMetaValveGate`` (``tks_meta_valve_controller``, 161 parameters, ``0.55``
   admissibility cutoff) is REQUIRED and evaluated before EVERY SINGLE child slice.
   A ``None`` valve gate fails closed immediately; any slice scoring ``< 0.55`` or
   receiving a hard veto aborts all remaining slices with ``VALVE_REFUSAL``.
2. Post-trade margin level floor ``>= 1000.0%`` verified via ``Mt5MarginCalculator``
   before every child slice (tracking cumulative margin across slices).
3. Live spread guard (``SPREAD_GUARD_EXCEEDED``) and adverse slippage collar
   (``SLIPPAGE_COLLAR_EXCEEDED``) evaluated before every child slice.
4. Optional ``pre_slice_guard`` callback hook (e.g., ``NewsShockShield``) evaluated
   before every child slice with zero hard coupling.
5. Untouched CAS Forex SL/TP/BE/Trail protection parameters preserved on every slice.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation, localcontext
from enum import StrEnum
from hashlib import sha256
import json
from typing import Any

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
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, integer, utc_time
from cas_forex_revamp.operator.decisions import DecisionProposal
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    ValveDecision,
    ValveRefusalError,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    MT5_MIN_VOLUME,
    MT5_VOLUME_STEP,
    Mt5MarginCalculator,
    Mt5MarginCheck,
    normalize_market_symbol,
)

__all__ = [
    "AccountMarginState",
    "ChildSlice",
    "DEFAULT_INSIDE_SPREAD_FRACTION",
    "DEFAULT_LIMIT_TTL_SECONDS",
    "DEFAULT_MAX_SPREAD_POINTS",
    "ExecutionPlan",
    "ExecutionRefusalError",
    "ExecutionStyle",
    "ExecutionValveRefusalError",
    "InstrumentExecutionProfile",
    "LOT_STEP",
    "MIN_LOT_SIZE",
    "MIN_POST_TRADE_MARGIN_LEVEL_PCT",
    "ParentOrderRequest",
    "ProtectionParameters",
    "QuoteSnapshot",
    "RefusalReason",
    "SliceExecutionRecord",
    "SliceOutcome",
    "SliceRefusalError",
    "SmartExecutionPlanner",
    "SmartExecutionReport",
    "SmartSliceExecutor",
    "VALVE_ADMISSIBILITY_CUTOFF",
    "VenueSliceFill",
    "default_instrument_profile",
    "default_protection_parameters",
    "load_default_forex_valve_gate",
]

VALVE_ADMISSIBILITY_CUTOFF: float = 0.55
MIN_POST_TRADE_MARGIN_LEVEL_PCT: Decimal = Decimal("1000.0")
MIN_LOT_SIZE: Decimal = MT5_MIN_VOLUME
LOT_STEP: Decimal = MT5_VOLUME_STEP
DEFAULT_LIMIT_TTL_SECONDS: int = 15
DEFAULT_INSIDE_SPREAD_FRACTION: Decimal = Decimal("0.25")
_VWAP_QUANT = Decimal("0.000001")

DEFAULT_MAX_SPREAD_POINTS: dict[str, Decimal] = {
    "NAS100": Decimal("2.50"),
    "US30": Decimal("5.00"),
    "SPX500": Decimal("1.50"),
    "XAUUSD": Decimal("0.80"),
}
_DEFAULT_FX_MAX_SPREAD_PIPS = Decimal("2.50")
_DEFAULT_JPY_MAX_SPREAD_PIPS = Decimal("3.00")


class ExecutionStyle(StrEnum):
    SINGLE_MARKET = "SINGLE_MARKET"
    TWAP_SLICED = "TWAP_SLICED"
    PULLBACK_LIMIT = "PULLBACK_LIMIT"


class SliceOutcome(StrEnum):
    FILLED = "FILLED"
    EXPIRED = "EXPIRED"
    REFUSED = "REFUSED"
    ABORTED = "ABORTED"
    CANCELLED = "CANCELLED"


class RefusalReason(StrEnum):
    VALVE_MISSING = "VALVE_MISSING"
    VALVE_REFUSAL = "VALVE_REFUSAL"
    MARGIN_FLOOR_BREACH = "MARGIN_FLOOR_BREACH"
    INSUFFICIENT_FREE_MARGIN = "INSUFFICIENT_FREE_MARGIN"
    NON_POSITIVE_EQUITY = "NON_POSITIVE_EQUITY"
    SPREAD_GUARD_EXCEEDED = "SPREAD_GUARD_EXCEEDED"
    SLIPPAGE_COLLAR_EXCEEDED = "SLIPPAGE_COLLAR_EXCEEDED"
    PRE_SLICE_GUARD_BLOCKED = "PRE_SLICE_GUARD_BLOCKED"
    LIMIT_TTL_EXPIRED = "LIMIT_TTL_EXPIRED"
    SUB_MINIMUM_LOT_SIZE = "SUB_MINIMUM_LOT_SIZE"
    VENUE_REJECTED = "VENUE_REJECTED"


class ExecutionRefusalError(ContractError):
    """Raised when a smart execution plan or slice is refused by a safety gate."""

    def __init__(
        self,
        message: str,
        *,
        reason: str = RefusalReason.VENUE_REJECTED,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = str(reason)
        self.details = dict(details) if details is not None else {}


class SliceRefusalError(ExecutionRefusalError):
    """Raised when lot/risk-budget slicing cannot produce a valid >= 0.01 lot schedule."""

    def __init__(
        self,
        message: str,
        *,
        reason: str = RefusalReason.SUB_MINIMUM_LOT_SIZE,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message, reason=reason, details=details)


class ExecutionValveRefusalError(ValveRefusalError, ExecutionRefusalError):
    """Raised when ForexMetaValveGate is missing or blocks execution (subclass of both)."""

    def __init__(
        self,
        message: str,
        *,
        reason: str = RefusalReason.VALVE_REFUSAL,
        decision: ValveDecision | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        ValveRefusalError.__init__(self, message, decision=decision)
        self.reason = str(reason)
        self.details = dict(details) if details is not None else {}


def _to_decimal(
    value: Decimal | str | int,
    field_name: str,
    *,
    positive: bool = False,
    non_negative: bool = False,
) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ContractError(f"{field_name} requires exact Decimal (or str/int), never float or bool")
    if isinstance(value, Decimal):
        parsed = value
    else:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ContractError(f"{field_name} is not a valid Decimal") from exc
    decimal_value(parsed, field_name, positive=positive)
    if non_negative and parsed < Decimal("0"):
        raise ContractError(f"{field_name} must be non-negative")
    return parsed


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _noop_sleeper(_seconds: float) -> None:
    return None


def _fmt_score(score: float | None) -> str | None:
    if score is None:
        return None
    val = round(float(score), 8)
    if val == 0.0:
        val = 0.0
    return f"{val:.8f}"


def _iso_utc(ts: datetime) -> str:
    return utc_time(ts, "timestamp").isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ProtectionParameters:
    """Untouched CAS Forex SL / TP / Breakeven / Trailing Stop parameters."""

    sl_distance: Decimal
    tp_distance: Decimal
    be_trigger: Decimal
    be_offset: Decimal
    trail_activation: Decimal
    trail_distance: Decimal

    def __post_init__(self) -> None:
        _to_decimal(self.sl_distance, "sl_distance", positive=True)
        _to_decimal(self.tp_distance, "tp_distance", positive=True)
        _to_decimal(self.be_trigger, "be_trigger", non_negative=True)
        _to_decimal(self.be_offset, "be_offset", non_negative=True)
        _to_decimal(self.trail_activation, "trail_activation", non_negative=True)
        _to_decimal(self.trail_distance, "trail_distance", positive=True)

    def compute_levels(self, entry_price: Decimal, side: Side, tick_size: Decimal) -> tuple[Decimal, Decimal]:
        """Compute exact protective stop-loss and take-profit prices anchored to entry_price."""
        _to_decimal(entry_price, "entry_price", positive=True)
        _to_decimal(tick_size, "tick_size", positive=True)
        if not isinstance(side, Side):
            raise ContractError("side must be Side")
        if side is Side.BUY:
            sl = (entry_price - self.sl_distance).quantize(tick_size, rounding=ROUND_FLOOR)
            tp = (entry_price + self.tp_distance).quantize(tick_size, rounding=ROUND_CEILING)
            if sl <= Decimal("0") or sl >= entry_price or tp <= entry_price:
                raise ExecutionRefusalError(
                    f"Invalid BUY protection geometry around {decimal_text(entry_price)}",
                    reason=RefusalReason.VENUE_REJECTED,
                )
            return sl, tp
        sl = (entry_price + self.sl_distance).quantize(tick_size, rounding=ROUND_CEILING)
        tp = (entry_price - self.tp_distance).quantize(tick_size, rounding=ROUND_FLOOR)
        if tp <= Decimal("0") or sl <= entry_price or tp >= entry_price:
            raise ExecutionRefusalError(
                f"Invalid SELL protection geometry around {decimal_text(entry_price)}",
                reason=RefusalReason.VENUE_REJECTED,
            )
        return sl, tp

    def to_dict(self) -> dict[str, str]:
        return {
            "sl_distance": decimal_text(self.sl_distance),
            "tp_distance": decimal_text(self.tp_distance),
            "be_trigger": decimal_text(self.be_trigger),
            "be_offset": decimal_text(self.be_offset),
            "trail_activation": decimal_text(self.trail_activation),
            "trail_distance": decimal_text(self.trail_distance),
        }


def default_protection_parameters(symbol: str) -> ProtectionParameters:
    """Return canonical untouched CAS Forex SL/TP/BE/Trail parameters for symbol."""
    norm = normalize_market_symbol(symbol)
    if norm == "NAS100":
        return ProtectionParameters(
            sl_distance=Decimal("25.00"),
            tp_distance=Decimal("60.00"),
            be_trigger=Decimal("10.00"),
            be_offset=Decimal("1.50"),
            trail_activation=Decimal("20.00"),
            trail_distance=Decimal("12.00"),
        )
    if norm == "US30":
        return ProtectionParameters(
            sl_distance=Decimal("50.00"),
            tp_distance=Decimal("120.00"),
            be_trigger=Decimal("20.00"),
            be_offset=Decimal("3.00"),
            trail_activation=Decimal("40.00"),
            trail_distance=Decimal("24.00"),
        )
    if norm == "SPX500":
        return ProtectionParameters(
            sl_distance=Decimal("10.00"),
            tp_distance=Decimal("24.00"),
            be_trigger=Decimal("4.00"),
            be_offset=Decimal("0.50"),
            trail_activation=Decimal("8.00"),
            trail_distance=Decimal("5.00"),
        )
    if norm == "XAUUSD":
        return ProtectionParameters(
            sl_distance=Decimal("12.00"),
            tp_distance=Decimal("30.00"),
            be_trigger=Decimal("5.00"),
            be_offset=Decimal("0.80"),
            trail_activation=Decimal("10.00"),
            trail_distance=Decimal("6.00"),
        )
    point = Decimal("0.01") if norm.endswith("JPY") else Decimal("0.0001")
    return ProtectionParameters(
        sl_distance=point * Decimal("25"),
        tp_distance=point * Decimal("55"),
        be_trigger=point * Decimal("8"),
        be_offset=point * Decimal("1"),
        trail_activation=point * Decimal("15"),
        trail_distance=point * Decimal("10"),
    )


@dataclass(frozen=True, slots=True)
class InstrumentExecutionProfile:
    symbol: str
    tick_size: Decimal
    point_size: Decimal
    max_spread_points: Decimal
    default_max_slippage_points: Decimal
    protection: ProtectionParameters

    def __post_init__(self) -> None:
        norm = normalize_market_symbol(self.symbol)
        if norm != self.symbol:
            object.__setattr__(self, "symbol", norm)
        _to_decimal(self.tick_size, "tick_size", positive=True)
        _to_decimal(self.point_size, "point_size", positive=True)
        _to_decimal(self.max_spread_points, "max_spread_points", positive=True)
        _to_decimal(self.default_max_slippage_points, "default_max_slippage_points", non_negative=True)
        if not isinstance(self.protection, ProtectionParameters):
            raise ContractError("protection must be ProtectionParameters")


def default_instrument_profile(symbol: str) -> InstrumentExecutionProfile:
    """Return canonical execution profile (tick, point, spread ceiling, slippage collar, SL/TP/BE/Trail)."""
    norm = normalize_market_symbol(symbol)
    protection = default_protection_parameters(norm)
    if norm == "NAS100":
        return InstrumentExecutionProfile(
            symbol=norm,
            tick_size=Decimal("0.01"),
            point_size=Decimal("1.00"),
            max_spread_points=DEFAULT_MAX_SPREAD_POINTS["NAS100"],
            default_max_slippage_points=Decimal("3.00"),
            protection=protection,
        )
    if norm == "US30":
        return InstrumentExecutionProfile(
            symbol=norm,
            tick_size=Decimal("0.01"),
            point_size=Decimal("1.00"),
            max_spread_points=DEFAULT_MAX_SPREAD_POINTS["US30"],
            default_max_slippage_points=Decimal("6.00"),
            protection=protection,
        )
    if norm == "SPX500":
        return InstrumentExecutionProfile(
            symbol=norm,
            tick_size=Decimal("0.01"),
            point_size=Decimal("1.00"),
            max_spread_points=DEFAULT_MAX_SPREAD_POINTS["SPX500"],
            default_max_slippage_points=Decimal("2.00"),
            protection=protection,
        )
    if norm == "XAUUSD":
        return InstrumentExecutionProfile(
            symbol=norm,
            tick_size=Decimal("0.01"),
            point_size=Decimal("1.00"),
            max_spread_points=DEFAULT_MAX_SPREAD_POINTS["XAUUSD"],
            default_max_slippage_points=Decimal("1.50"),
            protection=protection,
        )
    if norm.endswith("JPY"):
        return InstrumentExecutionProfile(
            symbol=norm,
            tick_size=Decimal("0.001"),
            point_size=Decimal("0.01"),
            max_spread_points=_DEFAULT_JPY_MAX_SPREAD_PIPS,
            default_max_slippage_points=Decimal("3.00"),
            protection=protection,
        )
    return InstrumentExecutionProfile(
        symbol=norm,
        tick_size=Decimal("0.00001"),
        point_size=Decimal("0.0001"),
        max_spread_points=_DEFAULT_FX_MAX_SPREAD_PIPS,
        default_max_slippage_points=Decimal("2.50"),
        protection=protection,
    )


@dataclass(frozen=True, slots=True)
class QuoteSnapshot:
    symbol: str
    bid: Decimal
    ask: Decimal
    timestamp_utc: datetime

    def __post_init__(self) -> None:
        norm = normalize_market_symbol(self.symbol)
        if norm != self.symbol:
            object.__setattr__(self, "symbol", norm)
        _to_decimal(self.bid, "bid", positive=True)
        _to_decimal(self.ask, "ask", positive=True)
        if self.ask < self.bid:
            raise ContractError(f"Inverted quote for {self.symbol}: ask < bid")
        utc_time(self.timestamp_utc, "timestamp_utc")

    @property
    def spread_raw(self) -> Decimal:
        return self.ask - self.bid

    @property
    def mid(self) -> Decimal:
        with localcontext() as ctx:
            ctx.prec = 40
            return (self.bid + self.ask) / Decimal("2")

    def spread_points(self, point_size: Decimal) -> Decimal:
        _to_decimal(point_size, "point_size", positive=True)
        with localcontext() as ctx:
            ctx.prec = 40
            return (self.ask - self.bid) / point_size

    def reference_price(self, side: Side) -> Decimal:
        if not isinstance(side, Side):
            raise ContractError("side must be Side")
        return self.ask if side is Side.BUY else self.bid


@dataclass(frozen=True, slots=True)
class AccountMarginState:
    account_id: str
    balance: Decimal
    equity: Decimal
    used_margin: Decimal
    free_margin: Decimal
    peak_equity: Decimal | None = None
    position_inventory: tuple[str, ...] = ()
    extra_quotes: Mapping[str, tuple[Decimal, Decimal]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        identifier(self.account_id, "account_id")
        _to_decimal(self.balance, "balance")
        _to_decimal(self.equity, "equity")
        _to_decimal(self.used_margin, "used_margin", non_negative=True)
        _to_decimal(self.free_margin, "free_margin")
        if self.peak_equity is not None:
            _to_decimal(self.peak_equity, "peak_equity", positive=True)
        if not isinstance(self.position_inventory, tuple):
            object.__setattr__(self, "position_inventory", tuple(self.position_inventory))


@dataclass(frozen=True, slots=True)
class ParentOrderRequest:
    parent_order_id: str
    symbol: str
    side: Side
    total_lots: Decimal
    style: ExecutionStyle = ExecutionStyle.SINGLE_MARKET
    slice_count: int = 1
    interval_seconds: int = 0
    max_spread_points: Decimal | None = None
    max_slippage_points: Decimal | None = None
    inside_spread_fraction: Decimal = DEFAULT_INSIDE_SPREAD_FRACTION
    pullback_points: Decimal = Decimal("0")
    limit_ttl_seconds: int = DEFAULT_LIMIT_TTL_SECONDS
    protection: ProtectionParameters | None = None
    reason: str = "Policy-compliant CAS Forex smart execution order."
    policy_overrides: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        identifier(self.parent_order_id, "parent_order_id")
        norm = normalize_market_symbol(self.symbol)
        if norm != self.symbol:
            object.__setattr__(self, "symbol", norm)
        if not isinstance(self.side, Side):
            raise ContractError("side must be Side")
        _to_decimal(self.total_lots, "total_lots", non_negative=True)
        if not isinstance(self.style, ExecutionStyle):
            raise ContractError("style must be ExecutionStyle")
        integer(self.slice_count, "slice_count", minimum=1)
        integer(self.interval_seconds, "interval_seconds", minimum=0)
        integer(self.limit_ttl_seconds, "limit_ttl_seconds", minimum=1)
        if self.max_spread_points is not None:
            _to_decimal(self.max_spread_points, "max_spread_points", positive=True)
        if self.max_slippage_points is not None:
            _to_decimal(self.max_slippage_points, "max_slippage_points", non_negative=True)
        frac = _to_decimal(self.inside_spread_fraction, "inside_spread_fraction", non_negative=True)
        if frac > Decimal("0.5"):
            raise ContractError("inside_spread_fraction must be in [0, 0.5] to stay passive/mid or better")
        _to_decimal(self.pullback_points, "pullback_points", non_negative=True)
        if self.protection is not None and not isinstance(self.protection, ProtectionParameters):
            raise ContractError("protection must be ProtectionParameters")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContractError("reason must be non-empty text")


@dataclass(frozen=True, slots=True)
class ChildSlice:
    parent_order_id: str
    slice_id: str
    slice_index: int
    total_slices: int
    symbol: str
    side: Side
    style: ExecutionStyle
    volume_lots: Decimal
    quantity_units: Decimal
    scheduled_at: datetime
    expires_at: datetime
    reference_price: Decimal
    target_limit_price: Decimal | None
    stop_loss_price: Decimal
    take_profit_price: Decimal
    protection: ProtectionParameters
    max_spread_points: Decimal
    max_slippage_points: Decimal

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_order_id": self.parent_order_id,
            "slice_id": self.slice_id,
            "slice_index": self.slice_index,
            "total_slices": self.total_slices,
            "symbol": self.symbol,
            "side": self.side.value,
            "style": self.style.value,
            "volume_lots": decimal_text(self.volume_lots),
            "quantity_units": decimal_text(self.quantity_units),
            "scheduled_at": _iso_utc(self.scheduled_at),
            "expires_at": _iso_utc(self.expires_at),
            "reference_price": decimal_text(self.reference_price),
            "target_limit_price": None if self.target_limit_price is None else decimal_text(self.target_limit_price),
            "stop_loss_price": decimal_text(self.stop_loss_price),
            "take_profit_price": decimal_text(self.take_profit_price),
            "protection": self.protection.to_dict(),
            "max_spread_points": decimal_text(self.max_spread_points),
            "max_slippage_points": decimal_text(self.max_slippage_points),
        }


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    parent_order_id: str
    symbol: str
    side: Side
    style: ExecutionStyle
    requested_lots: Decimal
    planned_lots: Decimal
    reference_quote: QuoteSnapshot
    slices: tuple[ChildSlice, ...]
    protection: ProtectionParameters
    reason: str
    plan_sha256: str
    policy_overrides: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_order_id": self.parent_order_id,
            "symbol": self.symbol,
            "side": self.side.value,
            "style": self.style.value,
            "requested_lots": decimal_text(self.requested_lots),
            "planned_lots": decimal_text(self.planned_lots),
            "reference_quote": {
                "symbol": self.reference_quote.symbol,
                "bid": decimal_text(self.reference_quote.bid),
                "ask": decimal_text(self.reference_quote.ask),
                "timestamp_utc": _iso_utc(self.reference_quote.timestamp_utc),
            },
            "slices": [s.to_dict() for s in self.slices],
            "protection": self.protection.to_dict(),
            "reason": self.reason,
            "plan_sha256": self.plan_sha256,
        }


@dataclass(frozen=True, slots=True)
class VenueSliceFill:
    filled: bool
    fill_price: Decimal | None = None
    filled_lots: Decimal = Decimal("0")
    broker_order_id: str | None = None
    expired: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.fill_price is not None:
            _to_decimal(self.fill_price, "fill_price", positive=True)
        _to_decimal(self.filled_lots, "filled_lots", non_negative=True)
        if self.filled and (self.fill_price is None or self.filled_lots <= Decimal("0")):
            raise ContractError("A filled VenueSliceFill requires positive fill_price and filled_lots")


@dataclass(frozen=True, slots=True)
class SliceExecutionRecord:
    slice_id: str
    slice_index: int
    symbol: str
    side: Side
    style: ExecutionStyle
    requested_lots: Decimal
    filled_lots: Decimal
    outcome: SliceOutcome
    refusal_reason: str | None
    detail: str | None
    executed_at: datetime
    quote_bid: Decimal | None
    quote_ask: Decimal | None
    spread_points: Decimal | None
    target_limit_price: Decimal | None
    fill_price: Decimal | None
    slippage_points: Decimal | None
    stop_loss_price: Decimal
    take_profit_price: Decimal
    protection: ProtectionParameters
    valve_admitted: bool | None
    valve_score: float | None
    valve_mode: str | None
    valve_veto_reasons: tuple[str, ...]
    valve_weights_sha256: str | None
    margin_required: Decimal | None
    post_trade_margin_level_pct: Decimal | None
    broker_order_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "slice_index": self.slice_index,
            "symbol": self.symbol,
            "side": self.side.value,
            "style": self.style.value,
            "requested_lots": decimal_text(self.requested_lots),
            "filled_lots": decimal_text(self.filled_lots),
            "outcome": self.outcome.value,
            "refusal_reason": self.refusal_reason,
            "detail": self.detail,
            "executed_at": _iso_utc(self.executed_at),
            "quote_bid": None if self.quote_bid is None else decimal_text(self.quote_bid),
            "quote_ask": None if self.quote_ask is None else decimal_text(self.quote_ask),
            "spread_points": None if self.spread_points is None else decimal_text(self.spread_points),
            "target_limit_price": None if self.target_limit_price is None else decimal_text(self.target_limit_price),
            "fill_price": None if self.fill_price is None else decimal_text(self.fill_price),
            "slippage_points": None if self.slippage_points is None else decimal_text(self.slippage_points),
            "stop_loss_price": decimal_text(self.stop_loss_price),
            "take_profit_price": decimal_text(self.take_profit_price),
            "protection": self.protection.to_dict(),
            "valve_admitted": self.valve_admitted,
            "valve_score": _fmt_score(self.valve_score),
            "valve_mode": self.valve_mode,
            "valve_veto_reasons": list(self.valve_veto_reasons),
            "valve_weights_sha256": self.valve_weights_sha256,
            "margin_required": None if self.margin_required is None else decimal_text(self.margin_required),
            "post_trade_margin_level_pct": (
                None if self.post_trade_margin_level_pct is None else decimal_text(self.post_trade_margin_level_pct)
            ),
            "broker_order_id": self.broker_order_id,
        }


@dataclass(frozen=True, slots=True)
class SmartExecutionReport:
    parent_order_id: str
    plan_sha256: str
    symbol: str
    side: Side
    style: ExecutionStyle
    requested_lots: Decimal
    planned_lots: Decimal
    filled_lots: Decimal
    vwap_fill_price: Decimal | None
    average_spread_points: Decimal | None
    filled_slice_count: int
    total_slice_count: int
    aborted: bool
    abort_reason: str | None
    slice_records: tuple[SliceExecutionRecord, ...]
    protection: ProtectionParameters
    completed_at: datetime
    report_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_order_id": self.parent_order_id,
            "plan_sha256": self.plan_sha256,
            "symbol": self.symbol,
            "side": self.side.value,
            "style": self.style.value,
            "requested_lots": decimal_text(self.requested_lots),
            "planned_lots": decimal_text(self.planned_lots),
            "filled_lots": decimal_text(self.filled_lots),
            "vwap_fill_price": None if self.vwap_fill_price is None else decimal_text(self.vwap_fill_price),
            "average_spread_points": (
                None if self.average_spread_points is None else decimal_text(self.average_spread_points)
            ),
            "filled_slice_count": self.filled_slice_count,
            "total_slice_count": self.total_slice_count,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "slice_records": [r.to_dict() for r in self.slice_records],
            "protection": self.protection.to_dict(),
            "completed_at": _iso_utc(self.completed_at),
            "report_sha256": self.report_sha256,
        }


class SmartExecutionPlanner:
    """Deterministic Clear Street-style planner for SINGLE_MARKET, TWAP_SLICED, and PULLBACK_LIMIT."""

    def __init__(
        self,
        *,
        margin_calculator: Mt5MarginCalculator | None = None,
        profiles: Mapping[str, InstrumentExecutionProfile] | None = None,
    ) -> None:
        self.margin_calculator = margin_calculator if margin_calculator is not None else Mt5MarginCalculator()
        self._profiles: dict[str, InstrumentExecutionProfile] = {}
        if profiles is not None:
            for sym, prof in profiles.items():
                self._profiles[normalize_market_symbol(sym)] = prof

    def profile_for(self, symbol: str) -> InstrumentExecutionProfile:
        norm = normalize_market_symbol(symbol)
        if norm in self._profiles:
            return self._profiles[norm]
        return default_instrument_profile(norm)

    @staticmethod
    def lots_from_risk_budget(
        *,
        risk_budget_usd: Decimal,
        sl_distance_points: Decimal,
        value_per_lot_per_point: Decimal,
    ) -> Decimal:
        """Convert exact USD risk budget to floored 0.01-lot volume; refuse honestly if < 0.01."""
        budget = _to_decimal(risk_budget_usd, "risk_budget_usd", positive=True)
        sl_pts = _to_decimal(sl_distance_points, "sl_distance_points", positive=True)
        val_pt = _to_decimal(value_per_lot_per_point, "value_per_lot_per_point", positive=True)
        with localcontext() as ctx:
            ctx.prec = 40
            raw_lots = budget / (sl_pts * val_pt)
            floored = raw_lots.quantize(LOT_STEP, rounding=ROUND_FLOOR)
        if floored < MIN_LOT_SIZE:
            raise SliceRefusalError(
                f"Risk budget {decimal_text(budget)} yields {decimal_text(raw_lots.quantize(_VWAP_QUANT, rounding=ROUND_FLOOR))} lots (< {decimal_text(MIN_LOT_SIZE)} minimum)",
                reason=RefusalReason.SUB_MINIMUM_LOT_SIZE,
                details={
                    "risk_budget_usd": decimal_text(budget),
                    "raw_lots": decimal_text(raw_lots.quantize(_VWAP_QUANT, rounding=ROUND_FLOOR)),
                    "min_lot_size": decimal_text(MIN_LOT_SIZE),
                },
            )
        return floored

    @staticmethod
    def split_lots_floor(total_lots: Decimal, slice_count: int) -> tuple[Decimal, ...]:
        """Split total_lots across up to slice_count child slices using ROUND_FLOOR to 0.01 lots.

        Guarantees:
        - Every slice is a positive multiple of 0.01 lots (>= 0.01).
        - Sum of all child slices is strictly <= total_lots (never rounds up above budget).
        - Raises SliceRefusalError if total_lots floors below 0.01 lots.
        """
        budget = _to_decimal(total_lots, "total_lots", non_negative=True)
        integer(slice_count, "slice_count", minimum=1)
        floored_total = budget.quantize(LOT_STEP, rounding=ROUND_FLOOR)
        if floored_total < MIN_LOT_SIZE:
            raise SliceRefusalError(
                f"Requested total_lots {decimal_text(budget)} floors to {decimal_text(floored_total)} (< {decimal_text(MIN_LOT_SIZE)} minimum)",
                reason=RefusalReason.SUB_MINIMUM_LOT_SIZE,
                details={
                    "requested_lots": decimal_text(budget),
                    "floored_lots": decimal_text(floored_total),
                },
            )
        total_steps = int((floored_total / LOT_STEP).to_integral_value(rounding=ROUND_FLOOR))
        effective_slices = min(slice_count, total_steps)
        base_steps, rem_steps = divmod(total_steps, effective_slices)
        slices = tuple(
            (Decimal(base_steps + (1 if idx < rem_steps else 0)) * LOT_STEP).quantize(LOT_STEP)
            for idx in range(effective_slices)
        )
        planned_sum = sum(slices, Decimal("0"))
        if planned_sum > budget or any(lot < MIN_LOT_SIZE for lot in slices):
            raise SliceRefusalError(
                "Internal slicing invariant breach: child lot sum exceeded requested budget",
                reason=RefusalReason.SUB_MINIMUM_LOT_SIZE,
            )
        return slices

    def compute_pullback_limit_price(
        self,
        symbol: str,
        side: Side,
        quote: QuoteSnapshot,
        *,
        inside_spread_fraction: Decimal = DEFAULT_INSIDE_SPREAD_FRACTION,
        pullback_points: Decimal = Decimal("0"),
        max_spread_points: Decimal | None = None,
    ) -> Decimal:
        """Compute spread-aware passive/pullback limit entry price inside or near bid-ask."""
        profile = self.profile_for(symbol)
        if quote.symbol != profile.symbol:
            raise ContractError(f"Quote symbol {quote.symbol} does not match order symbol {profile.symbol}")
        if not isinstance(side, Side):
            raise ContractError("side must be Side")
        frac = _to_decimal(inside_spread_fraction, "inside_spread_fraction", non_negative=True)
        if frac > Decimal("0.5"):
            raise ContractError("inside_spread_fraction must be in [0, 0.5]")
        pb_pts = _to_decimal(pullback_points, "pullback_points", non_negative=True)
        eff_max_spread = (
            _to_decimal(max_spread_points, "max_spread_points", positive=True)
            if max_spread_points is not None
            else profile.max_spread_points
        )
        live_spread_pts = quote.spread_points(profile.point_size)
        if live_spread_pts > eff_max_spread:
            raise ExecutionRefusalError(
                f"{profile.symbol} spread {decimal_text(live_spread_pts)} exceeds max {decimal_text(eff_max_spread)} points",
                reason=RefusalReason.SPREAD_GUARD_EXCEEDED,
                details={
                    "symbol": profile.symbol,
                    "spread_points": decimal_text(live_spread_pts),
                    "max_spread_points": decimal_text(eff_max_spread),
                },
            )
        with localcontext() as ctx:
            ctx.prec = 40
            pb_raw = pb_pts * profile.point_size
            if side is Side.BUY:
                raw_limit = quote.bid + (quote.spread_raw * frac) - pb_raw
                limit_price = raw_limit.quantize(profile.tick_size, rounding=ROUND_FLOOR)
                if limit_price > quote.ask:
                    limit_price = quote.ask.quantize(profile.tick_size, rounding=ROUND_FLOOR)
            else:
                raw_limit = quote.ask - (quote.spread_raw * frac) + pb_raw
                limit_price = raw_limit.quantize(profile.tick_size, rounding=ROUND_CEILING)
                if limit_price < quote.bid:
                    limit_price = quote.bid.quantize(profile.tick_size, rounding=ROUND_CEILING)
        if limit_price <= Decimal("0"):
            raise ExecutionRefusalError(
                f"Computed non-positive pullback limit price for {profile.symbol}",
                reason=RefusalReason.VENUE_REJECTED,
            )
        return limit_price

    def plan(
        self,
        request: ParentOrderRequest,
        quote: QuoteSnapshot,
        *,
        now_utc: datetime | None = None,
        enforce_spread_guard: bool = True,
    ) -> ExecutionPlan:
        """Build an immutable, SHA-256-digested child slice ExecutionPlan."""
        if not isinstance(request, ParentOrderRequest):
            raise ContractError("request must be ParentOrderRequest")
        if not isinstance(quote, QuoteSnapshot):
            raise ContractError("quote must be QuoteSnapshot")
        profile = self.profile_for(request.symbol)
        if quote.symbol != profile.symbol:
            raise ContractError(f"Quote symbol {quote.symbol} does not match order symbol {profile.symbol}")

        start_ts = utc_time(now_utc, "now_utc") if now_utc is not None else quote.timestamp_utc
        protection = request.protection if request.protection is not None else profile.protection
        eff_max_spread = (
            request.max_spread_points if request.max_spread_points is not None else profile.max_spread_points
        )
        eff_max_slippage = (
            request.max_slippage_points
            if request.max_slippage_points is not None
            else profile.default_max_slippage_points
        )

        spread_pts = quote.spread_points(profile.point_size)
        if enforce_spread_guard and spread_pts > eff_max_spread:
            raise ExecutionRefusalError(
                f"{profile.symbol} spread {decimal_text(spread_pts)} exceeds max {decimal_text(eff_max_spread)} points",
                reason=RefusalReason.SPREAD_GUARD_EXCEEDED,
                details={
                    "symbol": profile.symbol,
                    "spread_points": decimal_text(spread_pts),
                    "max_spread_points": decimal_text(eff_max_spread),
                },
            )

        requested_slice_count = 1 if request.style is ExecutionStyle.SINGLE_MARKET else request.slice_count
        slice_lots = self.split_lots_floor(request.total_lots, requested_slice_count)
        planned_lots = sum(slice_lots, Decimal("0"))

        target_limit: Decimal | None = None
        if request.style is ExecutionStyle.PULLBACK_LIMIT:
            target_limit = self.compute_pullback_limit_price(
                profile.symbol,
                request.side,
                quote,
                inside_spread_fraction=request.inside_spread_fraction,
                pullback_points=request.pullback_points,
                max_spread_points=eff_max_spread if enforce_spread_guard else Decimal("1000000"),
            )

        ref_price = quote.reference_price(request.side)
        anchor_price = target_limit if target_limit is not None else ref_price
        sl_price, tp_price = protection.compute_levels(anchor_price, request.side, profile.tick_size)

        interval = request.interval_seconds if request.style is not ExecutionStyle.SINGLE_MARKET else 0
        total_slices = len(slice_lots)
        children: list[ChildSlice] = []
        for idx, lots in enumerate(slice_lots):
            scheduled = start_ts + timedelta(seconds=interval * idx)
            expires = scheduled + timedelta(seconds=request.limit_ttl_seconds)
            units = self.margin_calculator.lots_to_units(lots, symbol=profile.symbol)
            slice_id = f"{request.parent_order_id}-s{idx + 1:03d}"
            identifier(slice_id, "slice_id")
            children.append(
                ChildSlice(
                    parent_order_id=request.parent_order_id,
                    slice_id=slice_id,
                    slice_index=idx,
                    total_slices=total_slices,
                    symbol=profile.symbol,
                    side=request.side,
                    style=request.style,
                    volume_lots=lots,
                    quantity_units=units,
                    scheduled_at=scheduled,
                    expires_at=expires,
                    reference_price=ref_price,
                    target_limit_price=target_limit,
                    stop_loss_price=sl_price,
                    take_profit_price=tp_price,
                    protection=protection,
                    max_spread_points=eff_max_spread,
                    max_slippage_points=eff_max_slippage,
                )
            )

        slices_tuple = tuple(children)
        canonical_payload = {
            "parent_order_id": request.parent_order_id,
            "symbol": profile.symbol,
            "side": request.side.value,
            "style": request.style.value,
            "requested_lots": decimal_text(request.total_lots),
            "planned_lots": decimal_text(planned_lots),
            "reference_quote": {
                "symbol": quote.symbol,
                "bid": decimal_text(quote.bid),
                "ask": decimal_text(quote.ask),
                "timestamp_utc": _iso_utc(quote.timestamp_utc),
            },
            "protection": protection.to_dict(),
            "slices": [s.to_dict() for s in slices_tuple],
        }
        plan_sha = sha256(canonical_bytes(canonical_payload)).hexdigest()
        return ExecutionPlan(
            parent_order_id=request.parent_order_id,
            symbol=profile.symbol,
            side=request.side,
            style=request.style,
            requested_lots=request.total_lots,
            planned_lots=planned_lots,
            reference_quote=quote,
            slices=slices_tuple,
            protection=protection,
            reason=request.reason,
            plan_sha256=plan_sha,
            policy_overrides=dict(request.policy_overrides) if request.policy_overrides is not None else None,
        )


def _build_child_slice_proposal(
    *,
    child: ChildSlice,
    live_quote: QuoteSnapshot,
    account: AccountMarginState,
    effective_free_margin: Decimal,
    entry_limit_price: Decimal | None,
    stop_loss_price: Decimal,
    take_profit_price: Decimal,
    reason: str,
) -> DecisionProposal:
    """Construct a genuine typed DecisionProposal for ForexMetaValveGate evaluation."""
    observed_at = live_quote.timestamp_utc
    ttl_seconds = max(60, int((child.expires_at - child.scheduled_at).total_seconds()) + 30)
    valid_until = observed_at + timedelta(seconds=ttl_seconds)

    scope = RunScope(
        account_id=account.account_id,
        run_id=f"smart-exec-{child.parent_order_id}",
        epoch=1,
        build_id="phase8-smart-exec",
        policy_id="cas-forex-smart-execution-v1",
        scenario_id=f"slice-{child.style.value.lower()}",
        adapter_id="smart-slice-executor",
    )
    state = StateReference(
        state_id=f"state-{child.slice_id}",
        scope=scope,
        version=child.slice_index + 1,
        observed_at=observed_at,
        valid_until=valid_until,
        venue_sequence=child.slice_index + 1,
    )
    obs_obj = {
        "symbol": child.symbol,
        "bid": decimal_text(live_quote.bid),
        "ask": decimal_text(live_quote.ask),
        "balance": decimal_text(account.balance),
        "equity": decimal_text(account.equity),
        "available_margin": decimal_text(effective_free_margin),
        "position_count": len(account.position_inventory),
        "new_risk": True,
        "management": True,
    }
    obs_json = json.dumps(obs_obj, sort_keys=True, separators=(",", ":"))
    ev_id = f"ev-{child.slice_id}"
    evidence = EvidenceReference(
        evidence_id=ev_id,
        kind=EvidenceKind.OBSERVATION,
        producer_id="smart-slice-executor",
        content_sha256=sha256(obs_json.encode("utf-8")).hexdigest(),
        observed_at=observed_at,
    )
    fact = DecisionFact(
        fact_id=f"observed-{child.slice_id}",
        label="slice_market_and_account_snapshot",
        value=obs_json,
        evidence_ids=(ev_id,),
    )
    intent = ActionIntent(
        intent_id=f"intent-{child.slice_id}",
        scope=scope,
        decision_id=f"dec-{child.slice_id}",
        opportunity_id=f"opp-{child.parent_order_id}",
        action_ref=f"ref-{child.slice_id}",
        source_state=state,
        kind=ActionKind.OPEN,
        instrument_id=child.symbol,
        origin=DecisionOrigin.POLICY,
        created_at=observed_at,
        expires_at=valid_until,
        quantity=child.quantity_units,
        side=child.side,
        limit_price=entry_limit_price,
        stop_price=stop_loss_price,
        take_profit_price=take_profit_price,
    )
    option = ActionOption(
        action_ref=intent.action_ref,
        strategy_id=f"smart-{child.style.value.lower()}",
        timeframe="M1",
        label=f"Child slice {child.slice_index + 1}/{child.total_slices} {child.symbol} {child.side.value}",
        intent=intent,
    )
    request = DecisionRequest(
        request_id=f"req-{child.slice_id}",
        opportunity_set_id=f"opp-{child.parent_order_id}",
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
        "smart-slice-executor",
        content_digest(request),
        content_digest(selection),
        "smart-exec-v1",
        observed_at,
        observed_at,
    )
    result = DecisionResult(
        decision_id=intent.decision_id,
        selection=selection,
        provenance=provenance,
    )
    return DecisionProposal(request=request, result=result, intent=intent)


def _default_paper_submitter(
    child: ChildSlice,
    live_quote: QuoteSnapshot,
    _decision: ValveDecision,
    *,
    now: datetime,
) -> VenueSliceFill:
    """Deterministic paper fill model used when caller does not supply a custom venue callback."""
    if child.style is ExecutionStyle.PULLBACK_LIMIT:
        if child.target_limit_price is None or now >= child.expires_at:
            return VenueSliceFill(
                filled=False,
                expired=True,
                reason=RefusalReason.LIMIT_TTL_EXPIRED,
            )
        if child.side is Side.BUY and live_quote.ask <= child.target_limit_price:
            return VenueSliceFill(
                filled=True,
                fill_price=child.target_limit_price,
                filled_lots=child.volume_lots,
                broker_order_id=f"sim-{child.slice_id}",
            )
        if child.side is Side.SELL and live_quote.bid >= child.target_limit_price:
            return VenueSliceFill(
                filled=True,
                fill_price=child.target_limit_price,
                filled_lots=child.volume_lots,
                broker_order_id=f"sim-{child.slice_id}",
            )
        return VenueSliceFill(
            filled=False,
            expired=True,
            reason=RefusalReason.LIMIT_TTL_EXPIRED,
        )
    return VenueSliceFill(
        filled=True,
        fill_price=live_quote.reference_price(child.side),
        filled_lots=child.volume_lots,
        broker_order_id=f"sim-{child.slice_id}",
    )


class SmartSliceExecutor:
    """Executes child slices while enforcing Valve, Margin >= 1000%, Spread, Slippage, and Pre-Slice Guard."""

    def __init__(
        self,
        *,
        valve_gate: ForexMetaValveGate | Any | None,
        margin_calculator: Mt5MarginCalculator | None = None,
        min_margin_level_pct: Decimal = MIN_POST_TRADE_MARGIN_LEVEL_PCT,
        pre_slice_guard: Callable[[ChildSlice], tuple[bool, str]] | None = None,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
        profiles: Mapping[str, InstrumentExecutionProfile] | None = None,
        event_callback: Callable[[SliceExecutionRecord], None] | None = None,
    ) -> None:
        if valve_gate is None:
            raise ExecutionValveRefusalError(
                "ForexMetaValveGate is mandatory and cannot be None (VALVE_MISSING)",
                reason=RefusalReason.VALVE_MISSING,
            )
        if not callable(getattr(valve_gate, "evaluate", None)):
            raise ExecutionValveRefusalError(
                "valve_gate must provide an evaluate(...) method returning ValveDecision (VALVE_MISSING)",
                reason=RefusalReason.VALVE_MISSING,
            )
        floor = _to_decimal(min_margin_level_pct, "min_margin_level_pct", positive=True)
        if floor < MIN_POST_TRADE_MARGIN_LEVEL_PCT:
            raise ContractError(
                f"min_margin_level_pct cannot be below constitutional floor {decimal_text(MIN_POST_TRADE_MARGIN_LEVEL_PCT)}%"
            )
        self.valve_gate = valve_gate
        self.margin_calculator = margin_calculator if margin_calculator is not None else Mt5MarginCalculator()
        self.min_margin_level_pct = floor
        self.pre_slice_guard = pre_slice_guard
        self._clock = clock if clock is not None else _utc_now
        self._sleeper = sleeper if sleeper is not None else _noop_sleeper
        self._event_callback = event_callback
        self._profiles: dict[str, InstrumentExecutionProfile] = {}
        if profiles is not None:
            for sym, prof in profiles.items():
                self._profiles[normalize_market_symbol(sym)] = prof

    def _profile_for(self, symbol: str) -> InstrumentExecutionProfile:
        norm = normalize_market_symbol(symbol)
        if norm in self._profiles:
            return self._profiles[norm]
        return default_instrument_profile(norm)

    def _evaluate_valve_mandatory(
        self,
        proposal: DecisionProposal,
        *,
        current_view: dict[str, Any],
        policy: dict[str, Any],
        now: datetime,
    ) -> tuple[bool, ValveDecision | None, str]:
        if self.valve_gate is None:
            raise ExecutionValveRefusalError(
                "ForexMetaValveGate is mandatory and cannot be None (VALVE_MISSING)",
                reason=RefusalReason.VALVE_MISSING,
            )
        decision = self.valve_gate.evaluate(
            proposal,
            current_view=current_view,
            policy=policy,
            now=now,
        )
        if not isinstance(decision, ValveDecision):
            return False, None, "Valve returned non-ValveDecision response"
        eff_cutoff = max(VALVE_ADMISSIBILITY_CUTOFF, float(decision.threshold))
        admitted = bool(
            decision.admitted
            and (not decision.hard_veto)
            and float(decision.mlp_score) >= eff_cutoff
        )
        if admitted:
            return True, decision, "ADMIT"
        if decision.hard_veto_reasons:
            detail = f"Valve refused ({decision.valve_mode}): {','.join(decision.hard_veto_reasons)}"
        else:
            detail = f"Valve refused ({decision.valve_mode}): score={decision.mlp_score:.6f}<{eff_cutoff:.6f}"
        return False, decision, detail

    def execute(
        self,
        plan: ExecutionPlan,
        *,
        account_state: AccountMarginState | Callable[[], AccountMarginState],
        quote_provider: QuoteSnapshot | Callable[[ChildSlice, datetime], QuoteSnapshot],
        submit_slice: Callable[[ChildSlice, QuoteSnapshot, ValveDecision], VenueSliceFill] | None = None,
        policy: Mapping[str, Any] | None = None,
        pre_slice_guard: Callable[[ChildSlice], tuple[bool, str]] | None = None,
    ) -> SmartExecutionReport:
        """Execute every child slice in plan sequentially under mandatory Valve, Margin, Spread & Slippage gates."""
        if self.valve_gate is None:
            raise ExecutionValveRefusalError(
                "ForexMetaValveGate is mandatory and cannot be None (VALVE_MISSING)",
                reason=RefusalReason.VALVE_MISSING,
            )
        if not isinstance(plan, ExecutionPlan):
            raise ContractError("plan must be ExecutionPlan")

        profile = self._profile_for(plan.symbol)
        static_account = isinstance(account_state, AccountMarginState)
        cumulative_required_margin = Decimal("0")

        guards: list[Callable[[ChildSlice], tuple[bool, str]]] = []
        if self.pre_slice_guard is not None:
            guards.append(self.pre_slice_guard)
        if pre_slice_guard is not None and pre_slice_guard is not self.pre_slice_guard:
            guards.append(pre_slice_guard)

        records: list[SliceExecutionRecord] = []
        aborted = False
        abort_reason: str | None = None

        for child in plan.slices:
            now = utc_time(self._clock(), "clock")
            if aborted:
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.ABORTED,
                    refusal_reason=abort_reason,
                    detail=f"Aborted after prior slice refusal ({abort_reason})",
                    executed_at=now,
                    quote_bid=None,
                    quote_ask=None,
                    spread_points=None,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=None,
                    stop_loss_price=child.stop_loss_price,
                    take_profit_price=child.take_profit_price,
                    protection=child.protection,
                    valve_admitted=None,
                    valve_score=None,
                    valve_mode=None,
                    valve_veto_reasons=(),
                    valve_weights_sha256=None,
                    margin_required=None,
                    post_trade_margin_level_pct=None,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            if child.slice_index > 0 and child.scheduled_at > now:
                wait_seconds = (child.scheduled_at - now).total_seconds()
                if wait_seconds > 0:
                    self._sleeper(wait_seconds)
                    now = utc_time(self._clock(), "clock")

            # 1. Optional pre_slice_guard hook (e.g., NewsShockShield)
            guard_blocked = False
            guard_detail = ""
            for guard in guards:
                allowed, guard_msg = guard(child)
                if not allowed:
                    guard_blocked = True
                    guard_detail = str(guard_msg) if guard_msg else "Blocked by pre_slice_guard"
                    break
            if guard_blocked:
                aborted = True
                abort_reason = RefusalReason.PRE_SLICE_GUARD_BLOCKED
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.REFUSED,
                    refusal_reason=RefusalReason.PRE_SLICE_GUARD_BLOCKED,
                    detail=guard_detail,
                    executed_at=now,
                    quote_bid=None,
                    quote_ask=None,
                    spread_points=None,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=None,
                    stop_loss_price=child.stop_loss_price,
                    take_profit_price=child.take_profit_price,
                    protection=child.protection,
                    valve_admitted=None,
                    valve_score=None,
                    valve_mode=None,
                    valve_veto_reasons=(),
                    valve_weights_sha256=None,
                    margin_required=None,
                    post_trade_margin_level_pct=None,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            # 2. Fetch live quote & check TTL (for PULLBACK_LIMIT), Spread Guard, and Slippage Collar
            live_quote = (
                quote_provider
                if isinstance(quote_provider, QuoteSnapshot)
                else quote_provider(child, now)
            )
            if not isinstance(live_quote, QuoteSnapshot) or live_quote.symbol != child.symbol:
                raise ContractError(f"quote_provider must return QuoteSnapshot for {child.symbol}")

            live_spread_pts = live_quote.spread_points(profile.point_size)

            if child.style is ExecutionStyle.PULLBACK_LIMIT and now >= child.expires_at:
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.EXPIRED,
                    refusal_reason=RefusalReason.LIMIT_TTL_EXPIRED,
                    detail="Limit slice expired before fill; cancelled safely without chasing",
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=None,
                    stop_loss_price=child.stop_loss_price,
                    take_profit_price=child.take_profit_price,
                    protection=child.protection,
                    valve_admitted=None,
                    valve_score=None,
                    valve_mode=None,
                    valve_veto_reasons=(),
                    valve_weights_sha256=None,
                    margin_required=None,
                    post_trade_margin_level_pct=None,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            if live_spread_pts > child.max_spread_points:
                aborted = True
                abort_reason = RefusalReason.SPREAD_GUARD_EXCEEDED
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.REFUSED,
                    refusal_reason=RefusalReason.SPREAD_GUARD_EXCEEDED,
                    detail=(
                        f"{child.symbol} live spread {decimal_text(live_spread_pts)} "
                        f"> max {decimal_text(child.max_spread_points)} points"
                    ),
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=None,
                    stop_loss_price=child.stop_loss_price,
                    take_profit_price=child.take_profit_price,
                    protection=child.protection,
                    valve_admitted=None,
                    valve_score=None,
                    valve_mode=None,
                    valve_veto_reasons=(),
                    valve_weights_sha256=None,
                    margin_required=None,
                    post_trade_margin_level_pct=None,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            with localcontext() as ctx:
                ctx.prec = 40
                if child.side is Side.BUY:
                    adverse_slip_pts = (live_quote.ask - child.reference_price) / profile.point_size
                else:
                    adverse_slip_pts = (child.reference_price - live_quote.bid) / profile.point_size

            if adverse_slip_pts > child.max_slippage_points:
                aborted = True
                abort_reason = RefusalReason.SLIPPAGE_COLLAR_EXCEEDED
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.REFUSED,
                    refusal_reason=RefusalReason.SLIPPAGE_COLLAR_EXCEEDED,
                    detail=(
                        f"{child.symbol} adverse drift {decimal_text(adverse_slip_pts)} "
                        f"> max slippage collar {decimal_text(child.max_slippage_points)} points"
                    ),
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=adverse_slip_pts,
                    stop_loss_price=child.stop_loss_price,
                    take_profit_price=child.take_profit_price,
                    protection=child.protection,
                    valve_admitted=None,
                    valve_score=None,
                    valve_mode=None,
                    valve_veto_reasons=(),
                    valve_weights_sha256=None,
                    margin_required=None,
                    post_trade_margin_level_pct=None,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            # Compute exact untouched SL/TP anchored to this slice's entry/limit price
            slice_anchor = (
                child.target_limit_price
                if child.target_limit_price is not None
                else live_quote.reference_price(child.side)
            )
            slice_sl, slice_tp = child.protection.compute_levels(slice_anchor, child.side, profile.tick_size)

            # 3. Post-trade margin level floor check (>= 1000.0%) via Mt5MarginCalculator
            acct = account_state if static_account else account_state()
            if not isinstance(acct, AccountMarginState):
                raise ContractError("account_state must be AccountMarginState")
            eff_used_margin = acct.used_margin + (cumulative_required_margin if static_account else Decimal("0"))
            eff_free_margin = acct.free_margin - (cumulative_required_margin if static_account else Decimal("0"))
            quotes_map: dict[str, tuple[Decimal, Decimal]] = dict(acct.extra_quotes)
            quotes_map[child.symbol] = (live_quote.bid, live_quote.ask)

            margin_check: Mt5MarginCheck = self.margin_calculator.check_new_position(
                symbol=child.symbol,
                side=child.side,
                units=child.quantity_units,
                quotes=quotes_map,
                equity=acct.equity,
                used_margin=eff_used_margin,
                free_margin=eff_free_margin,
                min_margin_level_pct=self.min_margin_level_pct,
            )
            if not margin_check.admitted:
                if margin_check.reason == "POST_TRADE_MARGIN_LEVEL_BELOW_FLOOR":
                    margin_refusal = RefusalReason.MARGIN_FLOOR_BREACH
                elif margin_check.reason == "INSUFFICIENT_FREE_MARGIN":
                    margin_refusal = RefusalReason.INSUFFICIENT_FREE_MARGIN
                else:
                    margin_refusal = RefusalReason.NON_POSITIVE_EQUITY
                aborted = True
                abort_reason = margin_refusal
                lvl_text = (
                    "None"
                    if margin_check.margin_level_after_pct is None
                    else f"{decimal_text(margin_check.margin_level_after_pct)}%"
                )
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.REFUSED,
                    refusal_reason=margin_refusal,
                    detail=(
                        f"Post-trade margin check failed ({margin_check.reason}): "
                        f"level={lvl_text}, floor={decimal_text(self.min_margin_level_pct)}%"
                    ),
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=adverse_slip_pts,
                    stop_loss_price=slice_sl,
                    take_profit_price=slice_tp,
                    protection=child.protection,
                    valve_admitted=None,
                    valve_score=None,
                    valve_mode=None,
                    valve_veto_reasons=(),
                    valve_weights_sha256=None,
                    margin_required=margin_check.required_margin,
                    post_trade_margin_level_pct=margin_check.margin_level_after_pct,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            # 4. MANDATORY ForexMetaValveGate evaluation BEFORE executing child slice
            proposal = _build_child_slice_proposal(
                child=child,
                live_quote=live_quote,
                account=acct,
                effective_free_margin=eff_free_margin,
                entry_limit_price=child.target_limit_price,
                stop_loss_price=slice_sl,
                take_profit_price=slice_tp,
                reason=plan.reason,
            )
            eff_peak = acct.peak_equity if acct.peak_equity is not None else max(acct.balance, acct.equity)
            current_view: dict[str, Any] = {
                "account_id": acct.account_id,
                "balance": decimal_text(acct.balance),
                "equity": decimal_text(acct.equity),
                "peak_equity": decimal_text(eff_peak),
                "available_margin": decimal_text(eff_free_margin),
                "position_inventory": list(acct.position_inventory),
            }
            eff_policy: dict[str, Any] = {
                "new_risk_permission": "ALLOWED",
                "management_permission": "ALLOWED",
                "max_entry_quantity": decimal_text(
                    max(child.quantity_units, self.margin_calculator.lots_to_units(plan.planned_lots, symbol=plan.symbol))
                ),
                "accounting_required": ["balance", "equity", "available_margin", "position_inventory"],
            }
            if plan.policy_overrides:
                eff_policy.update(plan.policy_overrides)
            if policy:
                eff_policy.update(policy)

            valve_ok, valve_dec, valve_detail = self._evaluate_valve_mandatory(
                proposal,
                current_view=current_view,
                policy=eff_policy,
                now=now,
            )
            if not valve_ok or valve_dec is None:
                aborted = True
                abort_reason = RefusalReason.VALVE_REFUSAL
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.REFUSED,
                    refusal_reason=RefusalReason.VALVE_REFUSAL,
                    detail=valve_detail,
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=adverse_slip_pts,
                    stop_loss_price=slice_sl,
                    take_profit_price=slice_tp,
                    protection=child.protection,
                    valve_admitted=False,
                    valve_score=None if valve_dec is None else valve_dec.mlp_score,
                    valve_mode=None if valve_dec is None else valve_dec.valve_mode,
                    valve_veto_reasons=() if valve_dec is None else valve_dec.hard_veto_reasons,
                    valve_weights_sha256=None if valve_dec is None else valve_dec.weights_sha256,
                    margin_required=margin_check.required_margin,
                    post_trade_margin_level_pct=margin_check.margin_level_after_pct,
                    broker_order_id=None,
                )
                records.append(rec)
                if self._event_callback is not None:
                    self._event_callback(rec)
                continue

            # 5. Submit approved child slice to venue
            if submit_slice is not None:
                fill = submit_slice(child, live_quote, valve_dec)
            else:
                fill = _default_paper_submitter(child, live_quote, valve_dec, now=now)

            if not isinstance(fill, VenueSliceFill):
                raise ContractError("submit_slice must return VenueSliceFill")

            if fill.filled and fill.fill_price is not None and fill.filled_lots > Decimal("0"):
                if fill.filled_lots > child.volume_lots:
                    raise ExecutionRefusalError(
                        f"Venue reported overfill {decimal_text(fill.filled_lots)} > slice {decimal_text(child.volume_lots)}",
                        reason=RefusalReason.VENUE_REJECTED,
                    )
                cumulative_required_margin += margin_check.required_margin
                with localcontext() as ctx:
                    ctx.prec = 40
                    if child.side is Side.BUY:
                        realized_slip_pts = (fill.fill_price - child.reference_price) / profile.point_size
                    else:
                        realized_slip_pts = (child.reference_price - fill.fill_price) / profile.point_size
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=fill.filled_lots,
                    outcome=SliceOutcome.FILLED,
                    refusal_reason=None,
                    detail="Filled under ForexMetaValveGate and margin clearance",
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=fill.fill_price,
                    slippage_points=realized_slip_pts,
                    stop_loss_price=slice_sl,
                    take_profit_price=slice_tp,
                    protection=child.protection,
                    valve_admitted=True,
                    valve_score=valve_dec.mlp_score,
                    valve_mode=valve_dec.valve_mode,
                    valve_veto_reasons=valve_dec.hard_veto_reasons,
                    valve_weights_sha256=valve_dec.weights_sha256,
                    margin_required=margin_check.required_margin,
                    post_trade_margin_level_pct=margin_check.margin_level_after_pct,
                    broker_order_id=fill.broker_order_id,
                )
            elif fill.expired:
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.EXPIRED,
                    refusal_reason=fill.reason or RefusalReason.LIMIT_TTL_EXPIRED,
                    detail="Stale limit slice expired without chasing",
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=adverse_slip_pts,
                    stop_loss_price=slice_sl,
                    take_profit_price=slice_tp,
                    protection=child.protection,
                    valve_admitted=True,
                    valve_score=valve_dec.mlp_score,
                    valve_mode=valve_dec.valve_mode,
                    valve_veto_reasons=valve_dec.hard_veto_reasons,
                    valve_weights_sha256=valve_dec.weights_sha256,
                    margin_required=margin_check.required_margin,
                    post_trade_margin_level_pct=margin_check.margin_level_after_pct,
                    broker_order_id=fill.broker_order_id,
                )
            else:
                aborted = True
                abort_reason = fill.reason or RefusalReason.VENUE_REJECTED
                rec = SliceExecutionRecord(
                    slice_id=child.slice_id,
                    slice_index=child.slice_index,
                    symbol=child.symbol,
                    side=child.side,
                    style=child.style,
                    requested_lots=child.volume_lots,
                    filled_lots=Decimal("0"),
                    outcome=SliceOutcome.REFUSED,
                    refusal_reason=abort_reason,
                    detail=f"Venue rejected slice: {abort_reason}",
                    executed_at=now,
                    quote_bid=live_quote.bid,
                    quote_ask=live_quote.ask,
                    spread_points=live_spread_pts,
                    target_limit_price=child.target_limit_price,
                    fill_price=None,
                    slippage_points=adverse_slip_pts,
                    stop_loss_price=slice_sl,
                    take_profit_price=slice_tp,
                    protection=child.protection,
                    valve_admitted=True,
                    valve_score=valve_dec.mlp_score,
                    valve_mode=valve_dec.valve_mode,
                    valve_veto_reasons=valve_dec.hard_veto_reasons,
                    valve_weights_sha256=valve_dec.weights_sha256,
                    margin_required=margin_check.required_margin,
                    post_trade_margin_level_pct=margin_check.margin_level_after_pct,
                    broker_order_id=fill.broker_order_id,
                )

            records.append(rec)
            if self._event_callback is not None:
                self._event_callback(rec)

        filled_records = [r for r in records if r.outcome is SliceOutcome.FILLED and r.fill_price is not None]
        filled_lots = sum((r.filled_lots for r in filled_records), Decimal("0"))
        vwap_fill: Decimal | None = None
        avg_spread: Decimal | None = None
        if filled_lots > Decimal("0"):
            with localcontext() as ctx:
                ctx.prec = 40
                weighted_px = sum(
                    (r.fill_price * r.filled_lots for r in filled_records if r.fill_price is not None),
                    Decimal("0"),
                )
                vwap_fill = (weighted_px / filled_lots).quantize(_VWAP_QUANT, rounding=ROUND_HALF_UP)
                weighted_sp = sum(
                    (r.spread_points * r.filled_lots for r in filled_records if r.spread_points is not None),
                    Decimal("0"),
                )
                avg_spread = (weighted_sp / filled_lots).quantize(_VWAP_QUANT, rounding=ROUND_HALF_UP)

        completed_at = utc_time(self._clock(), "clock")
        records_tuple = tuple(records)
        report_payload = {
            "parent_order_id": plan.parent_order_id,
            "plan_sha256": plan.plan_sha256,
            "symbol": plan.symbol,
            "side": plan.side.value,
            "style": plan.style.value,
            "requested_lots": decimal_text(plan.requested_lots),
            "planned_lots": decimal_text(plan.planned_lots),
            "filled_lots": decimal_text(filled_lots),
            "vwap_fill_price": None if vwap_fill is None else decimal_text(vwap_fill),
            "average_spread_points": None if avg_spread is None else decimal_text(avg_spread),
            "filled_slice_count": len(filled_records),
            "total_slice_count": len(records_tuple),
            "aborted": aborted,
            "abort_reason": abort_reason,
            "slice_records": [r.to_dict() for r in records_tuple],
            "protection": plan.protection.to_dict(),
            "completed_at": _iso_utc(completed_at),
        }
        report_sha = sha256(canonical_bytes(report_payload)).hexdigest()
        return SmartExecutionReport(
            parent_order_id=plan.parent_order_id,
            plan_sha256=plan.plan_sha256,
            symbol=plan.symbol,
            side=plan.side,
            style=plan.style,
            requested_lots=plan.requested_lots,
            planned_lots=plan.planned_lots,
            filled_lots=filled_lots,
            vwap_fill_price=vwap_fill,
            average_spread_points=avg_spread,
            filled_slice_count=len(filled_records),
            total_slice_count=len(records_tuple),
            aborted=aborted,
            abort_reason=abort_reason,
            slice_records=records_tuple,
            protection=plan.protection,
            completed_at=completed_at,
            report_sha256=report_sha,
        )
