"""Explicit independently durable disconnected venue. Imports/constructors are inert."""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Context, Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
from pathlib import Path
import sqlite3
from typing import Callable, Iterator

from cas_forex_revamp.contracts import (
    AccountRunKey, ActionKind, AuthorizedCommand, ContractError, ControlKind,
    DecisionOrigin, EffectState, FenceReceipt, FenceRequest, Instrument, LookupState,
    MarketObservation, Money, QuantityReport, Side, VenueLookup, VenueReceipt,
    VenueSnapshot, assert_command_integrity, canonical_bytes, content_digest,
    decimal_text, parse_decimal, to_wire,
)
from cas_forex_revamp.contracts.primitives import decimal_value, digest, identifier, integer, utc_time
from . import _wire
from .faults import FaultSchedule, SimulatedInterruption
from .fixtures import VenueScenario

ZERO = Decimal("0")
PRICE_QUANTUM = Decimal("0.000000000001")
APPLICATION_ID = 0x56454E55
STORAGE_VERSION = 1


class VenueStorageError(RuntimeError):
    """Missing/unavailable/corrupt/incompatible store; never equivalent to flat."""


class IdentityConflict(ContractError):
    """A durable business identity was reused with different immutable content."""


@dataclass(frozen=True, slots=True)
class JournalCheckpoint:
    sequence: int
    operation: str
    observed_at: datetime
    state_sha256: str
    previous_sha256: str
    checkpoint_sha256: str

    def __post_init__(self) -> None:
        integer(self.sequence, "checkpoint sequence", minimum=1)
        identifier(self.operation, "checkpoint operation")
        utc_time(self.observed_at, "checkpoint observed_at")
        for value in (self.state_sha256, self.previous_sha256, self.checkpoint_sha256):
            digest(value, "checkpoint digest")


class SQLiteVenue:
    def __init__(self, path: str | Path, *, faults: FaultSchedule | None = None,
                 owner_close_verifier: Callable[[AuthorizedCommand, datetime], bool] | None = None,
                 minimum_sequence: int = 0, checkpoint_anchor: JournalCheckpoint | None = None) -> None:
        self.path = Path(path)
        if not self.path.name.endswith(".venue.sqlite3"):
            raise ContractError("use a dedicated *.venue.sqlite3 path, never the core store")
        self.faults = faults if faults is not None else FaultSchedule()
        # Trusted core-owned extension; an OWNER_REVIEWED enum alone grants nothing.
        self.owner_close_verifier = owner_close_verifier
        self.minimum_sequence = integer(minimum_sequence, "minimum_sequence")
        if checkpoint_anchor is not None and not isinstance(checkpoint_anchor, JournalCheckpoint):
            raise ContractError("trusted checkpoint anchor must be JournalCheckpoint")
        self.checkpoint_anchor = checkpoint_anchor

    def initialize(self, key: AccountRunKey, *, opening_balance: Money,
                   instruments: tuple[Instrument, ...], now: datetime,
                   scenario: VenueScenario = VenueScenario()) -> VenueSnapshot:
        """Explicit one-time synthetic account creation; existing files are preserved."""
        utc_time(now, "now")
        if not isinstance(key, AccountRunKey) or not isinstance(opening_balance, Money):
            raise ContractError("typed account/run and opening balance required")
        if opening_balance.amount < 0 or not isinstance(scenario, VenueScenario):
            raise ContractError("nonnegative opening balance and typed scenario required")
        if type(instruments) is not tuple or not instruments or any(not isinstance(x, Instrument) for x in instruments):
            raise ContractError("at least one typed synthetic instrument required")
        if len({x.instrument_id for x in instruments}) != len(instruments):
            raise ContractError("duplicate instrument")
        if any(x.quote_currency != opening_balance.currency for x in instruments):
            raise ContractError("v1 requires quote currency equal to account currency")
        with localcontext(Context(prec=80)):
            if opening_balance.amount % scenario.money_quantum != 0:
                raise ContractError("opening balance must align to money quantum")
            for instrument in instruments:
                if instrument.minimum_quantity % instrument.quantity_step != 0:
                    raise ContractError("instrument minimum must align to quantity step")
                if scenario.fill_limit_per_order is not None and scenario.fill_limit_per_order % instrument.quantity_step != 0:
                    raise ContractError("fill limit must align to every instrument step")
        genesis = FenceReceipt(key, "venue-genesis", 0, False, False, 1, now, True)
        state = {
            "storage_version": STORAGE_VERSION, "key": to_wire(key), "sequence": 1,
            "last_at": to_wire(now), "currency": opening_balance.currency,
            "opening_balance": decimal_text(opening_balance.amount), "realized": "0",
            "instruments": {x.instrument_id: to_wire(x) for x in instruments},
            "scenario": to_wire(scenario), "fence": to_wire(genesis), "barriers": {},
            "owner_requests": {}, "commands": {}, "positions": {}, "position_updated_at": {},
            "position_protection_at": {}, "market": {},
            "market_events": {}, "last_market_sequence": -1,
        }
        # Exclusive creation prevents accidental reset. Interrupted genesis stays on disk.
        try:
            with self.path.open("xb"):
                pass
        except OSError as exc:
            raise VenueStorageError("venue creation refused; existing/missing-parent/unwritable path") from exc
        with self._session(write=True, initializing=True) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute("CREATE TABLE checkpoints (sequence INTEGER PRIMARY KEY, document TEXT NOT NULL, sha256 TEXT NOT NULL)")
            self._save(connection, state, "initialize", now, "0" * 64)
            self.faults.hit("initialize.before_commit")
            connection.commit()
            self.faults.hit("initialize.after_commit")
        with localcontext(Context(prec=80)):
            return self._snapshot(state, now)

    @contextmanager
    def _session(self, *, write: bool, initializing: bool = False) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            # Existing-only rw permits SQLite hot-journal recovery after process death.
            # Read operations do not append application checkpoints.
            uri = self.path.absolute().as_uri() + "?mode=rw"
            connection = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            if not initializing and connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
                raise VenueStorageError("file is not a compatible independent venue store")
            if write:
                connection.execute("PRAGMA synchronous=FULL")
            with localcontext(Context(prec=80)):
                yield connection
        except sqlite3.Error as exc:
            raise VenueStorageError("venue storage unavailable; outcome remains unconfirmed") from exc
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    def _load(self, connection: sqlite3.Connection) -> tuple[dict, str]:
        row = connection.execute("SELECT sequence, document, sha256 FROM checkpoints ORDER BY sequence DESC LIMIT 1").fetchone()
        if row is None:
            raise VenueStorageError("venue has no committed genesis; no empty-account fallback")
        if row["sequence"] < self.minimum_sequence:
            raise VenueStorageError("venue cursor is below trusted recovery floor")
        if self.checkpoint_anchor is not None:
            anchored = connection.execute("SELECT sha256 FROM checkpoints WHERE sequence = ?",
                (self.checkpoint_anchor.sequence,)).fetchone()
            if anchored is None or anchored["sha256"] != self.checkpoint_anchor.checkpoint_sha256:
                raise VenueStorageError("venue does not contain the trusted recovery anchor")
        try:
            document = _wire.loads(row["document"])
            if content_digest(document) != row["sha256"]:
                raise ValueError("checkpoint digest mismatch")
            state = document["state"]
            if state["storage_version"] != STORAGE_VERSION:
                raise ValueError("unsupported venue storage version")
            if state["sequence"] != row["sequence"] or document["sequence"] != row["sequence"]:
                raise ValueError("cursor mismatch")
            if state["key"] != document["key"]:
                raise ValueError("namespace mismatch")
            _wire.key(state["key"])
            _wire.fence(state["fence"])
            utc_time(_wire.time(state["last_at"]), "stored clock")
            expected, previous_sequence = "0" * 64, 0
            for checkpoint in connection.execute("SELECT sequence, document, sha256 FROM checkpoints ORDER BY sequence"):
                saved = _wire.loads(checkpoint["document"])
                if (content_digest(saved) != checkpoint["sha256"]
                        or saved["previous_sha256"] != expected or saved["key"] != state["key"]
                        or saved["sequence"] != checkpoint["sequence"]
                        or saved["state"]["sequence"] != checkpoint["sequence"]
                        or checkpoint["sequence"] <= previous_sequence):
                    raise ValueError("broken/corrupt checkpoint history")
                expected, previous_sequence = checkpoint["sha256"], checkpoint["sequence"]
            self._validate_state(state)
            self.minimum_sequence = max(self.minimum_sequence, state["sequence"])
            return state, row["sha256"]
        except (ValueError, TypeError, KeyError) as exc:
            raise VenueStorageError("corrupt or incompatible venue checkpoint; no reset performed") from exc

    @staticmethod
    def _validate_state(state: dict) -> None:
        key = _wire.key(state["key"])
        last_at = _wire.time(state["last_at"])
        current_fence = _wire.fence(state["fence"])
        if current_fence.key != key or current_fence.venue_sequence > state["sequence"] or current_fence.observed_at > last_at:
            raise ValueError("fence is outside the account checkpoint")
        Money(parse_decimal(state["opening_balance"]), state["currency"])
        Money(parse_decimal(state["realized"]), state["currency"])
        for instrument_id, value in state["instruments"].items():
            instrument = _wire.instrument(value)
            if instrument.instrument_id != instrument_id or instrument.quote_currency != state["currency"]:
                raise ValueError("instrument identity/currency mismatch")
        for position_id, value in state["positions"].items():
            position = _wire.position(value)
            if position.position_id != position_id or position.instrument_id not in state["instruments"]:
                raise ValueError("position identity mismatch")
            if _wire.time(state["position_updated_at"][position_id]) > last_at:
                raise ValueError("position update lies after checkpoint")
            protection_at = state.get("position_protection_at", {}).get(position_id)
            if protection_at is not None:
                utc_time(_wire.time(protection_at), "protection effective time")
                if _wire.time(protection_at) > last_at:
                    raise ValueError("protection effective time lies after checkpoint")
        for instrument_id, value in state["market"].items():
            quote = _wire.market(value)
            if quote.instrument_id != instrument_id or quote.key != key or quote.available_at > last_at:
                raise ValueError("quote is outside its checkpoint")
        sequences = set()
        for command_id, order in state["commands"].items():
            if order["command_id"] != command_id or not order["receipts"]:
                raise ValueError("order identity or receipts missing")
            if order["command"] is not None:
                if content_digest(order["command"]["intent"]) != order["payload_sha256"]:
                    raise ValueError("stored command payload binding is broken")
                if order["command"].get("risk_price_ceiling") != order.get("risk_price_ceiling"):
                    raise ValueError("stored execution ceiling differs from authorized command")
            ceiling = order.get("risk_price_ceiling")
            if ceiling is not None:
                decimal_value(parse_decimal(ceiling), "stored risk price ceiling", positive=True)
                if order["kind"] not in (ActionKind.OPEN.value, ActionKind.ADD.value):
                    raise ValueError("non-risk command carries a risk price ceiling")
            previous = 0
            for raw in order["receipts"]:
                receipt = _wire.receipt(raw)
                if (receipt.command_id != command_id or receipt.key != key
                        or receipt.payload_sha256 != order["payload_sha256"]
                        or not previous < receipt.venue_sequence <= state["sequence"]
                        or receipt.observed_at > last_at or receipt.venue_sequence in sequences):
                    raise ValueError("receipt identity/cursor binding is broken")
                previous = receipt.venue_sequence
                sequences.add(previous)
            final = _wire.receipt(order["receipts"][-1])
            if order["ordered"] is not None:
                quantities = QuantityReport(*(parse_decimal(order[n]) for n in (
                    "ordered", "filled", "cancelled", "rejected", "remaining")))
                if quantities != final.quantities or order["pending"] != (quantities.remaining > 0):
                    raise ValueError("order remainder differs from independent receipt")
                filled = ZERO
                for fill in order["fills"]:
                    quantity = decimal_value(parse_decimal(fill["quantity"]), "fill quantity", positive=True)
                    price = decimal_value(parse_decimal(fill["price"]), "fill price", positive=True)
                    if ceiling is not None and price > parse_decimal(ceiling):
                        raise ValueError("new-risk fill exceeded its authorized execution ceiling")
                    if fill["venue_sequence"] not in {r["venue_sequence"] for r in order["receipts"]}:
                        raise ValueError("fill has no supporting receipt")
                    filled += quantity
                if filled != quantities.filled:
                    raise ValueError("observed fill history differs from cumulative receipt")
            elif order["pending"] or order["fills"]:
                raise ValueError("non-quantity command cannot contain pending quantity/fills")

    @staticmethod
    def _save(connection: sqlite3.Connection, state: dict, operation: str, now: datetime, previous: str) -> None:
        document = {"sequence": state["sequence"], "key": state["key"], "operation": operation,
                    "observed_at": to_wire(now), "previous_sha256": previous, "state": state}
        connection.execute("INSERT INTO checkpoints(sequence, document, sha256) VALUES(?, ?, ?)",
            (state["sequence"], canonical_bytes(document).decode("utf-8"), content_digest(document)))

    @staticmethod
    def _key(state: dict, key: AccountRunKey) -> None:
        if not isinstance(key, AccountRunKey) or state["key"] != to_wire(key):
            raise ContractError("venue store belongs to a different account/run")

    @staticmethod
    def _clock(state: dict, now: datetime) -> None:
        utc_time(now, "now")
        if now < _wire.time(state["last_at"]):
            raise ContractError("venue clock cannot move backwards")

    @staticmethod
    def _tick(state: dict) -> int:
        state["sequence"] += 1
        return state["sequence"]

    def _write(self, operation: str, key: AccountRunKey, now: datetime, apply):
        utc_time(now, "now")
        with self._session(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            state, previous = self._load(connection)
            self._key(state, key)
            before = state["sequence"]
            result = apply(state)
            if state["sequence"] != before:
                state["last_at"] = to_wire(now)
                self._snapshot(state, now)  # Fail before commit if public accounting is invalid.
                self._save(connection, state, operation, now, previous)
                self.faults.hit(f"{operation}.before_commit")
                connection.commit()
                self.minimum_sequence = max(self.minimum_sequence, state["sequence"])
                self.faults.hit(f"{operation}.after_commit")
            else:
                connection.commit()
            return result

    def accept(self, command: AuthorizedCommand, *, now: datetime) -> VenueReceipt:
        assert_command_integrity(command)
        if command.command_id.startswith("venue-stop-"):
            raise ContractError("venue-stop- command namespace is reserved for observed protective fills")
        intent = command.intent

        def apply(state):
            existing = state["commands"].get(command.command_id)
            if existing is not None:
                if (existing["payload_sha256"] != command.payload_sha256
                        or existing.get("risk_price_ceiling") != to_wire(command.risk_price_ceiling)):
                    raise IdentityConflict("command identity already binds a different payload or execution ceiling")
                return _wire.receipt(existing["receipts"][-1])
            self._clock(state, now)
            order = {
                "command_id": command.command_id, "command": to_wire(command),
                "payload_sha256": command.payload_sha256, "generation": command.dispatch_generation,
                "risk_price_ceiling": to_wire(command.risk_price_ceiling),
                "kind": intent.kind.value, "instrument_id": intent.instrument_id, "side": to_wire(intent.side),
                "target_id": intent.target_id, "target_version": intent.target_version,
                "position_id": ("position-" + content_digest({"key": state["key"], "command_id": command.command_id}))
                    if intent.kind is ActionKind.OPEN else (None if intent.kind is ActionKind.CANCEL_ORDER else intent.target_id),
                "ordered": None if intent.quantity is None else decimal_text(intent.quantity),
                "filled": "0", "cancelled": "0", "rejected": "0",
                "remaining": None if intent.quantity is None else decimal_text(intent.quantity),
                "limit_price": to_wire(intent.limit_price), "stop_price": to_wire(intent.stop_price),
                "accepted_at": to_wire(now), "accepted_sequence": state["sequence"] + 1,
                "plan_index": 0, "receipts": [], "fills": [], "pending": False,
            }
            reason = self._admission_reason(state, command, now)
            state["commands"][command.command_id] = order
            if reason is not None:
                if order["ordered"] is not None:
                    order["rejected"], order["remaining"] = order["ordered"], "0"
                return self._receipt(state, order, EffectState.REJECTED, now, reason)
            if intent.kind is ActionKind.CANCEL_ORDER:
                target = state["commands"][intent.target_id]
                self._terminate(state, target, EffectState.CANCELLED, now, "CANCEL_REQUEST_APPLIED")
                return self._receipt(state, order, EffectState.APPLIED, now)
            if intent.kind is ActionKind.AMEND_STOP:
                position = state["positions"][intent.target_id]
                position["stop_price"] = decimal_text(intent.stop_price)
                position["version"] += 1
                state["position_updated_at"][intent.target_id] = to_wire(now)
                state.setdefault("position_protection_at", {})[intent.target_id] = to_wire(now)
                return self._receipt(state, order, EffectState.APPLIED, now)
            if intent.kind is not ActionKind.OPEN:
                position = state["positions"][intent.target_id]
                order["side"] = position["side"] if intent.kind is ActionKind.ADD else (
                    Side.SELL.value if position["side"] == Side.BUY.value else Side.BUY.value)
            order["pending"] = True
            return self._receipt(state, order, EffectState.ACKNOWLEDGED, now)

        return self._write("accept", intent.scope.key, now, apply)

    def _admission_reason(self, state: dict, command: AuthorizedCommand, now: datetime) -> str | None:
        intent, fence = command.intent, state["fence"]
        if command.dispatch_generation != fence["generation"]:
            return "STALE_DISPATCH_GENERATION"
        if not intent.created_at <= now < intent.expires_at:
            return "STALE_OR_FUTURE_INTENT"
        if intent.source_state.venue_sequence > state["sequence"]:
            return "FUTURE_SOURCE_CURSOR"
        new_risk = intent.kind in (ActionKind.OPEN, ActionKind.ADD)
        if new_risk and command.risk_price_ceiling is None:
            return "RISK_PRICE_CEILING_REQUIRED"
        if new_risk and not fence["new_risk_allowed"]:
            return "NEW_RISK_DISABLED"
        if not new_risk and not fence["management_allowed"]:
            reviewed_close = (
                intent.kind is ActionKind.CLOSE and intent.origin is DecisionOrigin.OWNER_REVIEWED
                and self.owner_close_verifier is not None
                and self.owner_close_verifier(command, now) is True
            )
            if not reviewed_close:
                return "MANAGEMENT_DISABLED"
        value = state["instruments"].get(intent.instrument_id)
        if value is None:
            return "UNKNOWN_INSTRUMENT"
        instrument = _wire.instrument(value)
        if new_risk and command.risk_price_ceiling % instrument.price_tick != 0:
            return "INVALID_RISK_PRICE_CEILING_TICK"
        if intent.quantity is not None and (intent.quantity < instrument.minimum_quantity or intent.quantity % instrument.quantity_step != 0):
            return "INVALID_QUANTITY_GEOMETRY"
        for price in (intent.limit_price, intent.stop_price):
            if price is not None and price % instrument.price_tick != 0:
                return "INVALID_PRICE_TICK"
        if intent.kind is ActionKind.CANCEL_ORDER and any(
                x is not None for x in (intent.side, intent.limit_price, intent.stop_price)):
            return "UNSUPPORTED_ACTION_GEOMETRY"
        if intent.kind is ActionKind.AMEND_STOP and (intent.side is not None or intent.limit_price is not None):
            return "UNSUPPORTED_ACTION_GEOMETRY"
        if intent.kind in (ActionKind.CLOSE, ActionKind.REDUCE) and intent.stop_price is not None:
            return "UNSUPPORTED_ACTION_GEOMETRY"
        plan = self._plan(state, command.command_id)
        if plan.get("reject_on_accept"):
            return "SCENARIO_REJECTION"
        for quota in plan.get("fill_quantities", []):
            if parse_decimal(quota) % instrument.quantity_step != 0:
                raise ContractError("fixture quota does not align to instrument quantity step")
        if intent.quantity is not None and sum(o["pending"] for o in state["commands"].values()) >= 128:
            return "OPEN_COMMAND_CAPACITY"
        if intent.kind is ActionKind.OPEN:
            occupied = {pid for pid, p in state["positions"].items() if parse_decimal(p["quantity"]) > 0}
            occupied.update(o["position_id"] for o in state["commands"].values()
                            if o["pending"] and o["kind"] == ActionKind.OPEN.value)
            if len(occupied) >= 128:
                return "POSITION_CAPACITY"
            return None
        if intent.kind is ActionKind.CANCEL_ORDER:
            order = state["commands"].get(intent.target_id)
            if order is None or not order["pending"] or order["remaining"] is None:
                return "NO_OPEN_TARGET_ORDER"
            if order["instrument_id"] != intent.instrument_id:
                return "TARGET_INSTRUMENT_MISMATCH"
            if order["receipts"][-1]["venue_sequence"] != intent.target_version:
                return "STALE_TARGET_VERSION"
            return None
        position = state["positions"].get(intent.target_id)
        if position is None or parse_decimal(position["quantity"]) <= 0:
            return "NO_OPEN_TARGET_POSITION"
        if position["instrument_id"] != intent.instrument_id:
            return "TARGET_INSTRUMENT_MISMATCH"
        if position["version"] != intent.target_version:
            return "STALE_TARGET_VERSION"
        if intent.kind is not ActionKind.AMEND_STOP and any(
                order["pending"] and order["position_id"] == intent.target_id for order in state["commands"].values()):
            return "TARGET_BUSY"
        if intent.kind in (ActionKind.REDUCE, ActionKind.CLOSE):
            if intent.quantity > parse_decimal(position["quantity"]):
                return "CLOSE_QUANTITY_EXCEEDS_POSITION"
            if intent.kind is ActionKind.CLOSE and intent.quantity != parse_decimal(position["quantity"]):
                return "CLOSE_REQUIRES_EXACT_POSITION_QUANTITY"
            if intent.side is not None and intent.side.value == position["side"]:
                return "CLOSE_SIDE_MISMATCH"
        elif intent.kind is ActionKind.ADD and intent.side is not None and intent.side.value != position["side"]:
            return "ADD_SIDE_MISMATCH"
        return None

    @staticmethod
    def _plan(state: dict, command_id: str) -> dict:
        return dict(state["scenario"]["order_plans"]).get(command_id, {})

    def _receipt(self, state: dict, order: dict, effect: EffectState, now: datetime,
                 reason: str | None = None) -> VenueReceipt:
        sequence = self._tick(state)
        quantities = None if order["ordered"] is None else QuantityReport(*(
            parse_decimal(order[name]) for name in ("ordered", "filled", "cancelled", "rejected", "remaining")))
        receipt = VenueReceipt(_wire.key(state["key"]), f"venue-receipt-{sequence}",
            order["command_id"], order["payload_sha256"], effect, sequence,
            order["generation"], now, quantities, order["position_id"], reason)
        order["receipts"].append(to_wire(receipt))
        return receipt

    def _terminate(self, state: dict, order: dict, effect: EffectState, now: datetime, reason: str) -> VenueReceipt:
        bucket = "cancelled" if effect is EffectState.CANCELLED else "rejected"
        order[bucket] = decimal_text(parse_decimal(order[bucket]) + parse_decimal(order["remaining"]))
        order["remaining"], order["pending"] = "0", False
        return self._receipt(state, order, effect, now, reason)

    def advance_fence(self, request: FenceRequest, *, now: datetime) -> FenceReceipt:
        if not isinstance(request, FenceRequest):
            raise ContractError("typed fence request required")
        request_hash = content_digest(request)

        def apply(state):
            existing = state["barriers"].get(request.barrier_id)
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise IdentityConflict("barrier identity already binds different content")
                return _wire.fence(existing["receipt"])
            if request.owner_request_id in state["owner_requests"]:
                raise IdentityConflict("owner control request already binds a different barrier")
            self._clock(state, now)
            current, reason = state["fence"], None
            if request.requested_at > now:
                reason = "FUTURE_CONTROL_REQUEST"
            elif request.expected_generation != current["generation"]:
                reason = "GENERATION_CONFLICT"
            risk, management, generation = current["new_risk_allowed"], current["management_allowed"], current["generation"]
            if reason is None:
                generation = request.next_generation
                if request.control is ControlKind.PAUSE_NEW_RISK:
                    risk = False
                elif request.control is ControlKind.STOP_AUTOMATION:
                    risk, management = False, False
                elif request.control is ControlKind.RESUME_NEW_RISK:
                    risk = True
                elif request.control is ControlKind.RESUME_MANAGEMENT:
                    management = True
            receipt = FenceReceipt(request.key, request.barrier_id, generation, risk, management,
                                   self._tick(state), now, reason is None, reason)
            state["barriers"][request.barrier_id] = {
                "request_hash": request_hash, "request": to_wire(request), "receipt": to_wire(receipt)}
            state["owner_requests"][request.owner_request_id] = request.barrier_id
            if receipt.applied:
                state["fence"] = to_wire(receipt)
            return receipt

        return self._write("advance_fence", request.key, now, apply)

    def lookup(self, key: AccountRunKey, command_id: str) -> VenueLookup:
        identifier(command_id, "command_id")
        try:
            self.faults.hit("lookup.unavailable")
        except SimulatedInterruption:
            return VenueLookup(key, command_id, LookupState.UNKNOWN, None, None, "OBSERVATION_UNAVAILABLE")
        with self._session(write=False) as connection:
            connection.execute("BEGIN")
            state, _ = self._load(connection)
            self._key(state, key)
            order = state["commands"].get(command_id)
            if order is None:
                return VenueLookup(key, command_id, LookupState.NOT_FOUND, state["sequence"], None)
            return VenueLookup(key, command_id, LookupState.FOUND, state["sequence"], _wire.receipt(order["receipts"][-1]))

    def snapshot(self, key: AccountRunKey, *, now: datetime) -> VenueSnapshot:
        with self._session(write=False) as connection:
            connection.execute("BEGIN")
            state, _ = self._load(connection)
            self._key(state, key)
            self._clock(state, now)
            return self._snapshot(state, now)

    def _money(self, state: dict, value: Decimal) -> Money:
        quantum = parse_decimal(state["scenario"]["money_quantum"])
        return Money(value.quantize(quantum, rounding=ROUND_FLOOR), state["currency"])

    def _snapshot(self, state: dict, now: datetime) -> VenueSnapshot:
        positions = tuple(_wire.position(p) for _, p in sorted(state["positions"].items()) if parse_decimal(p["quantity"]) > 0)
        open_pnl = ZERO
        for position in positions:
            quote = state["market"].get(position.instrument_id)
            if quote is None:
                raise VenueStorageError("open position is missing its supporting synthetic quote")
            mark = parse_decimal(quote["bid"] if position.side is Side.BUY else quote["ask"])
            direction = Decimal("1") if position.side is Side.BUY else Decimal("-1")
            open_pnl += (mark - position.entry_price) * position.quantity * direction
        realized = parse_decimal(state["realized"])
        balance = parse_decimal(state["opening_balance"]) + realized
        balance_money, open_money = self._money(state, balance), self._money(state, open_pnl)
        key = _wire.key(state["key"])
        return VenueSnapshot(key, "snapshot-" + content_digest({"key": state["key"],
            "sequence": state["sequence"], "observed_at": now}), state["sequence"], now,
            _wire.fence(state["fence"]), balance_money,
            self._money(state, balance_money.amount + open_money.amount), self._money(state, realized),
            open_money, positions, tuple(o["command_id"] for o in sorted(state["commands"].values(),
                key=lambda item: item["accepted_sequence"]) if o["pending"]),
            tuple(_wire.market(m) for _, m in sorted(state["market"].items())))

    def advance_market(self, observation: MarketObservation) -> VenueSnapshot:
        if not isinstance(observation, MarketObservation):
            raise ContractError("typed synthetic observation required")
        observation_hash = content_digest(observation)

        def apply(state):
            previous = state["market_events"].get(observation.event_id)
            if previous is not None:
                if previous != observation_hash:
                    raise IdentityConflict("market event identity already binds different content")
                return self._snapshot(state, _wire.time(state["last_at"]))
            self._clock(state, observation.available_at)
            if observation.sequence <= state["last_market_sequence"]:
                raise ContractError("market sequence must strictly increase across this account/run")
            instrument_data = state["instruments"].get(observation.instrument_id)
            if instrument_data is None:
                raise ContractError("market instrument was not registered at initialization")
            instrument = _wire.instrument(instrument_data)
            if observation.bid % instrument.price_tick != 0 or observation.ask % instrument.price_tick != 0:
                raise ContractError("market prices must align to instrument tick")
            previous_quote = state["market"].get(observation.instrument_id)
            if previous_quote is not None and observation.observed_at < _wire.time(previous_quote["observed_at"]):
                raise ContractError("market observed time cannot move backwards for an instrument")
            state["market_events"][observation.event_id] = observation_hash
            state["market"][observation.instrument_id] = to_wire(observation)
            state["last_market_sequence"] = observation.sequence
            self._tick(state)
            self._trigger_stops(state, observation)
            for order in sorted(list(state["commands"].values()), key=lambda o: o["accepted_sequence"]):
                if not order["pending"] or order["instrument_id"] != observation.instrument_id:
                    continue
                if observation.observed_at < _wire.time(order["accepted_at"]):
                    continue  # A late historical quote cannot execute a later order.
                price = observation.ask if order["side"] == Side.BUY.value else observation.bid
                if order["kind"] in (ActionKind.OPEN.value, ActionKind.ADD.value):
                    ceiling = order.get("risk_price_ceiling")
                    if ceiling is None or price > parse_decimal(ceiling):
                        # Includes historical unbounded pending commands: do not upgrade,
                        # clamp price, consume a quota, or fabricate a terminal receipt.
                        continue
                if order["limit_price"] is not None:
                    limit = parse_decimal(order["limit_price"])
                    if (order["side"] == Side.BUY.value and price > limit) or (order["side"] == Side.SELL.value and price < limit):
                        continue
                plan = self._plan(state, order["command_id"])
                quotas, index = plan.get("fill_quantities", []), order["plan_index"]
                if index >= len(quotas) and plan.get("terminal") is not None:
                    self._terminate(state, order, EffectState(plan["terminal"]), observation.available_at, "SCENARIO_REMAINDER_TERMINATED")
                    continue
                quantity = parse_decimal(quotas[index]) if index < len(quotas) else parse_decimal(order["remaining"])
                order["plan_index"] += 1
                quantity = min(quantity, parse_decimal(order["remaining"]))
                cap = state["scenario"]["fill_limit_per_order"]
                if cap is not None:
                    quantity = min(quantity, parse_decimal(cap))
                if quantity > 0:
                    self._fill(state, order, quantity, price, observation)
            self._trigger_stops(state, observation)  # A new fill may already cross its resting stop.
            return self._snapshot(state, observation.available_at)

        return self._write("advance_market", observation.key, observation.available_at, apply)

    def _fill(self, state: dict, order: dict, quantity: Decimal, price: Decimal,
              observation: MarketObservation) -> None:
        now = observation.available_at
        if order["kind"] in (ActionKind.OPEN.value, ActionKind.ADD.value):
            ceiling = order.get("risk_price_ceiling")
            if ceiling is None or price > parse_decimal(ceiling):
                raise VenueStorageError("new-risk execution lacks its reserved price bound; no commit")
        position_id = order["position_id"]
        position = state["positions"].get(position_id)
        if order["kind"] in (ActionKind.OPEN.value, ActionKind.ADD.value):
            if position is None:
                position = {"position_id": position_id, "version": 0, "instrument_id": order["instrument_id"],
                    "side": order["side"], "quantity": "0", "entry_price": decimal_text(price), "stop_price": order["stop_price"]}
                state["positions"][position_id] = position
                # Protection was accepted with the order, not at delayed readback time.
                state.setdefault("position_protection_at", {})[position_id] = order["accepted_at"]
            old_quantity = parse_decimal(position["quantity"])
            total_quantity = old_quantity + quantity
            decimal_value(total_quantity, "position quantity", positive=True)
            average = (parse_decimal(position["entry_price"]) * old_quantity + price * quantity) / total_quantity
            rounding = ROUND_CEILING if position["side"] == Side.BUY.value else ROUND_FLOOR
            position["entry_price"] = decimal_text(average.quantize(PRICE_QUANTUM, rounding=rounding))
            position["quantity"] = decimal_text(total_quantity)
            if (order["kind"] == ActionKind.ADD.value and parse_decimal(order["filled"]) == 0
                    and position["version"] == order["target_version"] and order["stop_price"] is not None):
                position["stop_price"] = order["stop_price"]
                state.setdefault("position_protection_at", {})[position_id] = order["accepted_at"]
        else:
            if position is None or quantity > parse_decimal(position["quantity"]):
                raise VenueStorageError("reserved close target is missing or would reverse; no commit")
            self._realize(state, position, quantity, price)
        position["version"] += 1
        state["position_updated_at"][position_id] = to_wire(now)
        order["filled"] = decimal_text(parse_decimal(order["filled"]) + quantity)
        order["remaining"] = decimal_text(parse_decimal(order["remaining"]) - quantity)
        order["pending"] = parse_decimal(order["remaining"]) > 0
        observed = self._receipt(state, order, EffectState.PARTIALLY_FILLED if order["pending"] else EffectState.FILLED, now)
        order["fills"].append({"quantity": decimal_text(quantity), "price": decimal_text(price),
            "side": order["side"], "observed_at": to_wire(now), "venue_sequence": observed.venue_sequence,
            "market_event_id": observation.event_id, "market_observed_at": to_wire(observation.observed_at)})

    def _realize(self, state: dict, position: dict, quantity: Decimal, price: Decimal) -> None:
        direction = Decimal("1") if position["side"] == Side.BUY.value else Decimal("-1")
        pnl = self._money(state, (price - parse_decimal(position["entry_price"])) * quantity * direction)
        state["realized"] = decimal_text(parse_decimal(state["realized"]) + pnl.amount)
        position["quantity"] = decimal_text(parse_decimal(position["quantity"]) - quantity)

    def _trigger_stops(self, state: dict, observation: MarketObservation) -> None:
        # Resting protective effects survive Pause/Stop, and can fill through gaps.
        for position_id, position in sorted(state["positions"].items()):
            if position["instrument_id"] != observation.instrument_id or position["stop_price"] is None:
                continue
            # Receipt availability is not protection causality. Plain fills/reductions
            # never move this protection clock; a later amendment still excludes old quotes.
            # Old checkpoints lack the new stamp: preserve their recorded conservative
            # bound instead of inventing an earlier effective time.
            effective_at = state.setdefault("position_protection_at", {}).setdefault(
                position_id, state["position_updated_at"][position_id])
            if observation.observed_at < _wire.time(effective_at):
                continue
            quantity = parse_decimal(position["quantity"])
            if quantity <= 0:
                continue
            stop = parse_decimal(position["stop_price"])
            is_long = position["side"] == Side.BUY.value
            price = observation.bid if is_long else observation.ask
            if (is_long and price > stop) or (not is_long and price < stop):
                continue
            for pending in list(state["commands"].values()):
                if pending["pending"] and pending["position_id"] == position_id:
                    self._terminate(state, pending, EffectState.CANCELLED, observation.available_at, "PROTECTIVE_STOP_CANCELLED_REMAINDER")
            identity = {"key": state["key"], "position_id": position_id, "position_version": position["version"],
                        "market_event_id": observation.event_id, "kind": "VENUE_PROTECTIVE_STOP"}
            command_id = "venue-stop-" + content_digest(identity)
            order = {"command_id": command_id, "command": None, "payload_sha256": content_digest(identity),
                "generation": state["fence"]["generation"], "kind": "VENUE_PROTECTIVE_STOP",
                "instrument_id": position["instrument_id"], "side": Side.SELL.value if is_long else Side.BUY.value,
                "target_id": position_id, "target_version": position["version"], "position_id": position_id,
                "ordered": decimal_text(quantity), "filled": decimal_text(quantity), "cancelled": "0",
                "rejected": "0", "remaining": "0", "pending": False,
                "accepted_at": to_wire(observation.available_at), "accepted_sequence": state["sequence"] + 1,
                "limit_price": None, "stop_price": None, "plan_index": 0, "trigger": identity, "receipts": [], "fills": []}
            self._realize(state, position, quantity, price)
            position["version"] += 1
            state["position_updated_at"][position_id] = to_wire(observation.available_at)
            state["commands"][command_id] = order
            observed = self._receipt(state, order, EffectState.FILLED, observation.available_at, "VENUE_PROTECTIVE_STOP")
            order["fills"].append({"quantity": decimal_text(quantity), "price": decimal_text(price),
                "side": order["side"], "observed_at": to_wire(observation.available_at),
                "venue_sequence": observed.venue_sequence, "market_event_id": observation.event_id,
                "market_observed_at": to_wire(observation.observed_at)})

    def receipt_history(self, key: AccountRunKey, command_id: str | None = None) -> tuple[VenueReceipt, ...]:
        """Independent cumulative receipts, including venue-originated protective stops."""
        if command_id is not None:
            identifier(command_id, "command_id")
        with self._session(write=False) as connection:
            connection.execute("BEGIN")
            state, _ = self._load(connection)
            self._key(state, key)
            return tuple(sorted((_wire.receipt(receipt) for order in state["commands"].values()
                if command_id is None or order["command_id"] == command_id
                for receipt in order["receipts"]), key=lambda r: r.venue_sequence))

    def inspect_journal(self, key: AccountRunKey) -> tuple[JournalCheckpoint, ...]:
        """Verify the entire local hash chain. Integrity, not external anchoring."""
        with self._session(write=False) as connection:
            connection.execute("BEGIN")
            state, _ = self._load(connection)
            self._key(state, key)
            expected, last_sequence, result = "0" * 64, 0, []
            try:
                for row in connection.execute("SELECT sequence, document, sha256 FROM checkpoints ORDER BY sequence"):
                    document = _wire.loads(row["document"])
                    if (content_digest(document) != row["sha256"] or document["previous_sha256"] != expected
                            or document["key"] != state["key"] or document["sequence"] != row["sequence"]
                            or row["sequence"] <= last_sequence):
                        raise ValueError("journal integrity mismatch")
                    result.append(JournalCheckpoint(row["sequence"], document["operation"],
                        _wire.time(document["observed_at"]), content_digest(document["state"]), expected, row["sha256"]))
                    expected, last_sequence = row["sha256"], row["sequence"]
            except (ValueError, KeyError, TypeError) as exc:
                raise VenueStorageError("corrupt/incompatible journal; no repair was attempted") from exc
            return tuple(result)





