"""Immutable proposal, authorization, control and independent venue records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from .primitives import (
    AccountRunKey, ActionKind, CommandState, ContractError, ControlKind, DecisionOrigin,
    EffectState, Money, RunScope, Side, StateReference, decimal_value, digest, identifier,
    integer, utc_time,
)


@dataclass(frozen=True, slots=True)
class Instrument:
    instrument_id: str
    symbol: str
    base_currency: str
    quote_currency: str
    price_tick: Decimal
    quantity_step: Decimal
    minimum_quantity: Decimal
    quantity_unit: str = "BASE_UNITS"

    def __post_init__(self) -> None:
        identifier(self.instrument_id, "instrument_id")
        identifier(self.symbol, "symbol")
        Money(Decimal("0"), self.base_currency)
        Money(Decimal("0"), self.quote_currency)
        for field in ("price_tick", "quantity_step", "minimum_quantity"):
            decimal_value(getattr(self, field), field, positive=True)
        if self.quantity_unit != "BASE_UNITS":
            raise ContractError("v1 quantity is explicit base units, not implicit lots")


@dataclass(frozen=True, slots=True)
class ActionIntent:
    intent_id: str
    scope: RunScope
    decision_id: str
    opportunity_id: str
    action_ref: str
    source_state: StateReference
    kind: ActionKind
    instrument_id: str
    origin: DecisionOrigin
    created_at: datetime
    expires_at: datetime
    quantity: Decimal | None = None
    side: Side | None = None
    target_id: str | None = None
    target_version: int | None = None
    limit_price: Decimal | None = None
    stop_price: Decimal | None = None
    take_profit_price: Decimal | None = None

    def __post_init__(self) -> None:
        for field in ("intent_id", "decision_id", "opportunity_id", "action_ref", "instrument_id"):
            identifier(getattr(self, field), field)
        if not isinstance(self.scope, RunScope) or not isinstance(self.source_state, StateReference):
            raise ContractError("intent requires typed scope and source_state")
        if self.source_state.scope != self.scope:
            raise ContractError("intent and source state must bind the same scope")
        if not isinstance(self.kind, ActionKind) or not isinstance(self.origin, DecisionOrigin):
            raise ContractError("intent kind/origin require shared enums")
        utc_time(self.created_at, "created_at")
        utc_time(self.expires_at, "expires_at")
        if not self.source_state.observed_at <= self.created_at < self.expires_at <= self.source_state.valid_until:
            raise ContractError("intent lifetime must fit its source observation lifetime")
        if self.quantity is not None:
            decimal_value(self.quantity, "quantity", positive=True)
        if self.side is not None and not isinstance(self.side, Side):
            raise ContractError("side must use Side")
        for field in ("limit_price", "stop_price", "take_profit_price"):
            value = getattr(self, field)
            if value is not None:
                decimal_value(value, field, positive=True)
        if self.target_id is not None:
            identifier(self.target_id, "target_id")
        if self.target_version is not None:
            integer(self.target_version, "target_version")
        if self.kind in (ActionKind.OPEN, ActionKind.ADD, ActionKind.REDUCE, ActionKind.CLOSE) and self.quantity is None:
            raise ContractError("quantity-changing actions require exact positive quantity")
        if self.kind is ActionKind.OPEN:
            if self.side is None or self.target_id is not None or self.target_version is not None:
                raise ContractError("OPEN requires side and has no existing target")
        elif self.target_id is None or self.target_version is None:
            raise ContractError("management/ADD requires exact target and version")
        if self.kind in (ActionKind.AMEND_STOP, ActionKind.CANCEL_ORDER) and self.quantity is not None:
            raise ContractError("non-quantity action must not carry a quantity")
        if self.kind is ActionKind.AMEND_STOP and self.stop_price is None and self.take_profit_price is None:
            raise ContractError("AMEND_STOP requires the exact replacement stop")
        if self.kind in (ActionKind.CANCEL_ORDER, ActionKind.REDUCE, ActionKind.CLOSE) and self.take_profit_price is not None:
            raise ContractError("non-entry action must not carry take_profit_price")


@dataclass(frozen=True, slots=True)
class AuthorizedCommand:
    """Core-owned record. Type construction alone does not grant authority."""

    command_id: str
    intent: ActionIntent
    payload_sha256: str
    reservation_id: str
    authority_id: str
    dispatch_generation: int
    writer_id: str
    # Core-selected upper execution price for a new-risk reservation. SELL limit
    # prices remain lower bounds; this separate envelope caps either side.
    # None is serializable for old/rejected records, never permission to fill.
    risk_price_ceiling: Decimal | None = None

    def __post_init__(self) -> None:
        for field in ("command_id", "reservation_id", "authority_id", "writer_id"):
            identifier(getattr(self, field), field)
        if not isinstance(self.intent, ActionIntent):
            raise ContractError("intent must be ActionIntent")
        digest(self.payload_sha256, "payload_sha256")
        integer(self.dispatch_generation, "dispatch_generation")
        if self.risk_price_ceiling is not None:
            decimal_value(self.risk_price_ceiling, "risk_price_ceiling", positive=True)
            if self.intent.kind not in (ActionKind.OPEN, ActionKind.ADD):
                raise ContractError("only new-risk commands carry an execution price ceiling")


@dataclass(frozen=True, slots=True)
class CommandView:
    command_id: str
    payload_sha256: str
    state: CommandState
    last_venue_receipt_id: str | None
    reservation_held: bool
    reason_code: str | None = None

    def __post_init__(self) -> None:
        identifier(self.command_id, "command_id")
        digest(self.payload_sha256, "payload_sha256")
        if not isinstance(self.state, CommandState) or type(self.reservation_held) is not bool:
            raise ContractError("invalid command view state/reservation flag")
        if self.last_venue_receipt_id is not None:
            identifier(self.last_venue_receipt_id, "last_venue_receipt_id")
        if self.reason_code is not None:
            identifier(self.reason_code, "reason_code")


@dataclass(frozen=True, slots=True)
class FenceRequest:
    key: AccountRunKey
    barrier_id: str
    control: ControlKind
    owner_request_id: str
    expected_generation: int
    next_generation: int
    requested_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.key, AccountRunKey) or not isinstance(self.control, ControlKind):
            raise ContractError("fence requires a stable account/run key and control kind")
        identifier(self.barrier_id, "barrier_id")
        identifier(self.owner_request_id, "owner_request_id")
        integer(self.expected_generation, "expected_generation")
        integer(self.next_generation, "next_generation")
        if self.next_generation != self.expected_generation + 1:
            raise ContractError("a serialized fence must advance exactly one generation")
        utc_time(self.requested_at, "requested_at")


@dataclass(frozen=True, slots=True)
class FenceReceipt:
    key: AccountRunKey
    barrier_id: str
    generation: int
    new_risk_allowed: bool
    management_allowed: bool
    venue_sequence: int
    observed_at: datetime
    applied: bool
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, AccountRunKey):
            raise ContractError("fence receipt requires AccountRunKey")
        identifier(self.barrier_id, "barrier_id")
        integer(self.generation, "generation")
        integer(self.venue_sequence, "venue_sequence")
        utc_time(self.observed_at, "observed_at")
        if any(type(x) is not bool for x in (self.new_risk_allowed, self.management_allowed, self.applied)):
            raise ContractError("fence state flags require booleans")
        if self.reason_code is not None:
            identifier(self.reason_code, "reason_code")


@dataclass(frozen=True, slots=True)
class QuantityReport:
    """Cumulative quantities at one venue sequence, never event deltas."""

    ordered: Decimal
    filled: Decimal
    cancelled: Decimal
    rejected: Decimal
    remaining: Decimal

    def __post_init__(self) -> None:
        decimal_value(self.ordered, "ordered", positive=True)
        for field in ("filled", "cancelled", "rejected", "remaining"):
            value = decimal_value(getattr(self, field), field)
            if value < 0:
                raise ContractError("quantity report buckets must be nonnegative")
        # Addition precision is explicitly set by the codec/consumer arithmetic policy.
        # Integer coefficient comparison below avoids ambient Decimal context rounding.
        scale = max(0, *(-getattr(self, n).as_tuple().exponent for n in ("ordered", "filled", "cancelled", "rejected", "remaining")))
        def coefficient(value: Decimal) -> int:
            parts = value.as_tuple()
            digits = int("".join(str(x) for x in parts.digits))
            return (-digits if parts.sign else digits) * 10 ** (parts.exponent + scale)
        if coefficient(self.ordered) != sum(coefficient(getattr(self, n)) for n in ("filled", "cancelled", "rejected", "remaining")):
            raise ContractError("ordered quantity must equal filled + cancelled + rejected + remaining")


@dataclass(frozen=True, slots=True)
class VenueReceipt:
    key: AccountRunKey
    receipt_id: str
    command_id: str
    payload_sha256: str
    effect: EffectState
    venue_sequence: int
    dispatch_generation: int
    observed_at: datetime
    quantities: QuantityReport | None = None
    position_id: str | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, AccountRunKey) or not isinstance(self.effect, EffectState):
            raise ContractError("receipt requires typed key/effect")
        for field in ("receipt_id", "command_id"):
            identifier(getattr(self, field), field)
        digest(self.payload_sha256, "payload_sha256")
        integer(self.venue_sequence, "venue_sequence")
        integer(self.dispatch_generation, "dispatch_generation")
        utc_time(self.observed_at, "observed_at")
        for field in ("position_id", "reason_code"):
            if getattr(self, field) is not None:
                identifier(getattr(self, field), field)
        q = self.quantities
        if q is not None and not isinstance(q, QuantityReport):
            raise ContractError("quantities must be QuantityReport")
        if self.effect in (EffectState.FILLED, EffectState.PARTIALLY_FILLED) and q is None:
            raise ContractError("a fill requires observed quantities")
        if q is not None:
            if self.effect is EffectState.ACKNOWLEDGED and (q.filled != 0 or q.remaining != q.ordered):
                raise ContractError("ACK is not a fill or reservation release")
            if self.effect is EffectState.FILLED and q.filled != q.ordered:
                raise ContractError("FILLED requires the entire ordered quantity")
            if self.effect is EffectState.PARTIALLY_FILLED and not (0 < q.filled < q.ordered and q.remaining > 0):
                raise ContractError("PARTIALLY_FILLED requires an open remainder")
            if self.effect is EffectState.CANCELLED and not (q.cancelled > 0 and q.remaining == 0):
                raise ContractError("CANCELLED requires a cancelled remainder and no open quantity")
            if self.effect is EffectState.REJECTED and not (q.rejected > 0 and q.remaining == 0):
                raise ContractError("REJECTED requires a rejected remainder and no open quantity")
