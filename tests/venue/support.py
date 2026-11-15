from __future__ import annotations
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import os
from pathlib import Path

from cas_forex_revamp.contracts import (
    AccountRunKey, ActionIntent, ActionKind, AuthorizedCommand, ControlKind, DecisionOrigin,
    FenceRequest, Instrument, MarketObservation, Money, RunScope, Side, StateReference, intent_digest,
)
from cas_forex_revamp.venue import FaultSchedule, SQLiteVenue, VenueScenario

D = Decimal
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
KEY = AccountRunKey("synthetic-account", "continuous-run")
SCOPE = RunScope(KEY.account_id, KEY.run_id, 1, "fixture-build", "fixture-policy", "fixture-scenario", "scripted")
INSTRUMENT = Instrument("EURUSD", "EUR/USD", "EUR", "USD", D("0.0001"), D("1"), D("1"))


def at(seconds=0):
    return START + timedelta(seconds=seconds)


def command(name="entry", *, generation=2, kind=ActionKind.OPEN, quantity="10", side=None,
            target=None, version=None, stop=None, limit=None, scope=SCOPE,
            origin=DecisionOrigin.SCRIPTED, created=None, expires=None, ceiling="2"):
    if kind in (ActionKind.AMEND_STOP, ActionKind.CANCEL_ORDER):
        quantity = None
    if kind is ActionKind.OPEN and side is None:
        side = Side.BUY
    state = StateReference("source-state", scope, 0, START, at(86400), 0)
    intent = ActionIntent("intent-" + name, scope, "decision-" + name, "opportunity-" + name,
        "action-" + name, state, kind, INSTRUMENT.instrument_id, origin, created or START,
        expires or at(3600), None if quantity is None else D(quantity), side, target, version,
        None if limit is None else D(limit), None if stop is None else D(stop))
    return AuthorizedCommand(name, intent, intent_digest(intent), "reservation-" + name,
                             "authority-" + name, generation, "core-writer",
                             D(ceiling) if kind in (ActionKind.OPEN, ActionKind.ADD) and ceiling is not None else None)


def fence(kind, generation, *, name=None, seconds=0):
    name = name or f"barrier-{generation + 1}"
    return FenceRequest(KEY, name, kind, "owner-" + name, generation, generation + 1, at(seconds))


def market(sequence, *, bid="1.1000", ask="1.1002", seconds=None, event_id=None):
    timestamp = at(sequence * 10 if seconds is None else seconds)
    return MarketObservation(KEY, event_id or f"market-{sequence}", INSTRUMENT.instrument_id,
                             sequence, timestamp, timestamp, D(bid), D(ask))


def initialized(path: Path, scenario=VenueScenario(), **kwargs):
    venue = SQLiteVenue(path, **kwargs)
    venue.initialize(KEY, opening_balance=Money(D("10000.00"), "USD"),
                     instruments=(INSTRUMENT,), now=START, scenario=scenario)
    venue.advance_fence(fence(ControlKind.RESUME_NEW_RISK, 0), now=START)
    venue.advance_fence(fence(ControlKind.RESUME_MANAGEMENT, 1), now=START)
    return venue


class CrashAtBoundary(FaultSchedule):
    def __init__(self, boundary):
        super().__init__()
        self.boundary = boundary

    def hit(self, point):
        if point == self.boundary:
            os._exit(73)  # Deliberate child process death without cleanup or unwinding.


def crash_child(path, operation, argument, now, boundary):
    venue = SQLiteVenue(path, faults=CrashAtBoundary(boundary))
    if operation == "advance_market":
        venue.advance_market(argument)
    elif operation == "advance_fence":
        venue.advance_fence(argument, now=now)
    else:
        venue.accept(argument, now=now)
