"""Read projections carry uncertainty; they do not confer execution permission."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from .commands import CommandView, FenceReceipt, VenueReceipt
from .decisions import DecisionResult, ids
from .primitives import AccountRunKey, ContractError, Money, Permissions, RunScope, SCHEMA_VERSION, Side, decimal_value, identifier, integer, utc_time


class RecoveryState(StrEnum):
    UNOBSERVED = "UNOBSERVED"
    RECONCILING = "RECONCILING"
    COHERENT = "COHERENT"
    UNRESOLVED = "UNRESOLVED"
    QUARANTINED = "QUARANTINED"


class LookupState(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class MarketObservation:
    key: AccountRunKey
    event_id: str
    instrument_id: str
    sequence: int
    observed_at: datetime
    available_at: datetime
    bid: Decimal
    ask: Decimal

    def __post_init__(self) -> None:
        if not isinstance(self.key, AccountRunKey):
            raise ContractError("market observation requires AccountRunKey")
        identifier(self.event_id, "event_id")
        identifier(self.instrument_id, "instrument_id")
        integer(self.sequence, "sequence")
        utc_time(self.observed_at, "observed_at")
        utc_time(self.available_at, "available_at")
        if self.available_at < self.observed_at:
            raise ContractError("market information cannot be available before its observation")
        decimal_value(self.bid, "bid", positive=True)
        decimal_value(self.ask, "ask", positive=True)
        if self.bid > self.ask:
            raise ContractError("synthetic bid must not exceed ask")


@dataclass(frozen=True, slots=True)
class PositionView:
    position_id: str
    version: int
    instrument_id: str
    side: Side
    quantity: Decimal
    entry_price: Decimal
    stop_price: Decimal | None = None

    def __post_init__(self) -> None:
        for field in ("position_id", "instrument_id"):
            identifier(getattr(self, field), field)
        integer(self.version, "version")
        if not isinstance(self.side, Side):
            raise ContractError("position side must use Side")
        decimal_value(self.quantity, "quantity")
        if self.quantity < 0:
            raise ContractError("position quantity must be nonnegative; side carries direction")
        decimal_value(self.entry_price, "entry_price", positive=True)
        if self.stop_price is not None:
            decimal_value(self.stop_price, "stop_price", positive=True)


@dataclass(frozen=True, slots=True)
class VenueSnapshot:
    key: AccountRunKey
    snapshot_id: str
    sequence: int
    observed_at: datetime
    fence: FenceReceipt
    balance: Money
    equity: Money
    realized_pnl: Money
    open_pnl: Money
    positions: tuple[PositionView, ...]
    open_command_ids: tuple[str, ...]
    market: tuple[MarketObservation, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.snapshot_id, "snapshot_id")
        integer(self.sequence, "sequence")
        utc_time(self.observed_at, "observed_at")
        if not isinstance(self.key, AccountRunKey) or not isinstance(self.fence, FenceReceipt) or self.fence.key != self.key:
            raise ContractError("snapshot/fence require the same stable account/run key")
        if self.fence.venue_sequence > self.sequence or self.fence.observed_at > self.observed_at:
            raise ContractError("snapshot cannot precede its included fence observation")
        if any(not isinstance(x, Money) for x in (self.balance, self.equity, self.realized_pnl, self.open_pnl)):
            raise ContractError("venue accounting requires typed money")
        if len({x.currency for x in (self.balance, self.equity, self.realized_pnl, self.open_pnl)}) != 1:
            raise ContractError("snapshot accounting must use one explicit account currency")
        if type(self.positions) is not tuple or any(not isinstance(x, PositionView) for x in self.positions):
            raise ContractError("positions must be an immutable tuple")
        ids(tuple(x.position_id for x in self.positions), "position_ids")
        ids(self.open_command_ids, "open_command_ids")
        if type(self.market) is not tuple or any(not isinstance(x, MarketObservation) or x.key != self.key for x in self.market):
            raise ContractError("market observations must match the snapshot account/run")
        if any(x.available_at > self.observed_at for x in self.market):
            raise ContractError("snapshot must not contain information from its future")


@dataclass(frozen=True, slots=True)
class VenueLookup:
    key: AccountRunKey
    command_id: str
    state: LookupState
    observed_sequence: int | None
    receipt: VenueReceipt | None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, AccountRunKey) or not isinstance(self.state, LookupState):
            raise ContractError("lookup requires typed key/state")
        identifier(self.command_id, "command_id")
        if self.observed_sequence is not None:
            integer(self.observed_sequence, "observed_sequence")
        if self.state is LookupState.FOUND:
            if not isinstance(self.receipt, VenueReceipt) or self.receipt.key != self.key or self.receipt.command_id != self.command_id:
                raise ContractError("FOUND requires the exact independently read venue receipt")
            if self.observed_sequence is None or self.receipt.venue_sequence > self.observed_sequence:
                raise ContractError("FOUND must bind a read cursor covering its receipt")
        elif self.receipt is not None:
            raise ContractError("non-FOUND lookup cannot claim a receipt")
        if self.state is LookupState.NOT_FOUND and self.observed_sequence is None:
            raise ContractError("NOT_FOUND requires a successful independent journal cursor")
        if self.reason_code is not None:
            identifier(self.reason_code, "reason_code")


@dataclass(frozen=True, slots=True)
class CockpitProjection:
    """Unknown money is None; offline/unobserved does not imply flat or stopped."""

    scope: RunScope
    recovery: RecoveryState = RecoveryState.UNOBSERVED
    permissions: Permissions = Permissions()
    observed_at: datetime | None = None
    state_id: str | None = None
    balance: Money | None = None
    equity: Money | None = None
    realized_pnl: Money | None = None
    open_pnl: Money | None = None
    positions: tuple[PositionView, ...] | None = None
    commands: tuple[CommandView, ...] = ()
    last_decision: DecisionResult | None = None
    unresolved_command_ids: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION
    admissions_enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.scope, RunScope) or not isinstance(self.recovery, RecoveryState) or not isinstance(self.permissions, Permissions):
            raise ContractError("cockpit requires typed scope/recovery/permissions")
        if self.schema_version != SCHEMA_VERSION or type(self.admissions_enabled) is not bool:
            raise ContractError("unsupported cockpit schema or admissions flag")
        if self.observed_at is not None:
            utc_time(self.observed_at, "observed_at")
        if self.state_id is not None:
            identifier(self.state_id, "state_id")
        for field in ("balance", "equity", "realized_pnl", "open_pnl"):
            if getattr(self, field) is not None and not isinstance(getattr(self, field), Money):
                raise ContractError(f"{field} requires Money or explicit unknown")
        if self.positions is not None and (type(self.positions) is not tuple or any(not isinstance(x, PositionView) for x in self.positions)):
            raise ContractError("positions require an immutable tuple or explicit unknown")
        if type(self.commands) is not tuple or any(not isinstance(x, CommandView) for x in self.commands):
            raise ContractError("commands require an immutable tuple")
        if self.last_decision is not None and not isinstance(self.last_decision, DecisionResult):
            raise ContractError("last_decision requires DecisionResult or explicit unknown")
        ids(self.unresolved_command_ids, "unresolved_command_ids")
        if self.admissions_enabled and (self.recovery is not RecoveryState.COHERENT or self.state_id is None or self.observed_at is None or self.permissions.confirmed_barrier_id is None):
            raise ContractError("admissions cannot be enabled from unobserved/incoherent state")
