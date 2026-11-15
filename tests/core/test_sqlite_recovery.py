"""Authored tests with TWO real new SQLite implementations. Runtime NOT_RUN.

These tests do not import the legacy Forex runtime. They require the approved
execution route and do not substitute for process-kill/power-loss verification.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.contracts import (
    ActionIntent, ActionKind, CommandState, ControlKind, DecisionOrigin,
    EffectState, FenceRequest, Instrument, LookupState, MarketObservation,
    Money, RunScope, Side, content_digest,
)
from cas_forex_revamp.core import CoreCoordinator, InstrumentPolicy, OutcomeUnknown, OwnerApproval, RiskPolicy, SQLiteStore
from cas_forex_revamp.venue import SQLiteVenue, VenueScenario


class OwnerFixture:
    def __init__(self, scope):
        self.scope = scope
        self.command_ids = {}

    def verify(self, subject, *, now):
        control = isinstance(subject, FenceRequest)
        return OwnerApproval(subject.owner_request_id if control else "review-" + subject.intent_id,
                             self.scope, content_digest(subject), now, now + timedelta(seconds=15),
                             None if control else self.command_ids[subject.intent_id])


class SQLiteRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.now = datetime(2026, 10, 10, 22, 0, tzinfo=timezone.utc)
        self.scope = RunScope("integration-account", "integration-run", 1, "build-1", "policy", "scenario", "scripted")
        self.instrument = Instrument("eurusd", "EURUSD", "EUR", "USD", D("0.0001"), D(1), D(1))
        self.venue = SQLiteVenue(self.directory / "account.venue.sqlite3")
        self.owner = OwnerFixture(self.scope)
        self.core = self.make_core()
        self.venue.initialize(self.scope.key, opening_balance=Money(D(100), "USD"),
                              instruments=(self.instrument,), now=self.now,
                              scenario=VenueScenario(fill_limit_per_order=D(2)))
        self.market(1)
        self.core.initialize(create=True)
        self.core.reconcile(self.scope.key, now=self.now)
        self.control(ControlKind.PAUSE_NEW_RISK)
        self.control(ControlKind.RESUME_NEW_RISK)
        self.control(ControlKind.RESUME_MANAGEMENT)

    def make_core(self):
        core = CoreCoordinator(scope=self.scope, store=SQLiteStore(self.directory / "account.core.sqlite3"),
                               venue=self.venue, policy=RiskPolicy("USD", D(20)),
                               instruments=(InstrumentPolicy(self.instrument, D(2)),), owner_verifier=self.owner)
        self.venue.owner_close_verifier = core.verify_owner_close
        return core

    def market(self, sequence, *, bid=D(1), ask=D(1), observed_at=None):
        return self.venue.advance_market(MarketObservation(self.scope.key, "market-" + str(sequence),
                                                         "eurusd", sequence, observed_at or self.now, self.now, bid, ask))

    def control(self, kind):
        fence = self.venue.snapshot(self.scope.key, now=self.now).fence
        request = FenceRequest(self.scope.key, "barrier-" + str(fence.generation + 1), kind,
                               "owner-" + str(fence.generation + 1), fence.generation, fence.generation + 1, self.now)
        receipt = self.core.control(request, now=self.now)
        self.core.reconcile(self.scope.key, now=self.now)
        return receipt

    def intent(self, name, *, kind=ActionKind.OPEN, quantity=D(5), target=None, version=None,
               origin=DecisionOrigin.SCRIPTED):
        state = self.core.current_state(self.scope.key, now=self.now)
        return ActionIntent(name, self.scope, "decision-" + name, "opportunity", "action-" + name,
                            state, kind, "eurusd", origin, self.now, self.now + timedelta(seconds=10),
                            quantity, Side.BUY if kind is ActionKind.OPEN else None, target, version,
                            D(1) if kind in (ActionKind.OPEN, ActionKind.ADD) else None)

    def test_lost_committed_reply_reopen_then_observe_independent_fill(self):
        self.core.admit(self.intent("entry"), command_id="entry", now=self.now)
        self.venue.faults.arm("accept.after_commit")
        with self.assertRaises(OutcomeUnknown):
            self.core.dispatch_next(self.scope.key, now=self.now)
        receipt_id = self.venue.lookup(self.scope.key, "entry").receipt.receipt_id
        self.venue = SQLiteVenue(self.directory / "account.venue.sqlite3")  # Reopen, never initialize/reset.
        self.scope = replace(self.scope, epoch=2, build_id="build-2")
        self.owner = OwnerFixture(self.scope)
        self.core = self.make_core()
        self.core.initialize()
        state = self.core.reconcile(self.scope.key, now=self.now)
        self.assertEqual(state.commands[0].last_venue_receipt_id, receipt_id)
        self.assertFalse(state.admissions_enabled)
        self.assertTrue(state.commands[0].reservation_held)
        self.assertIsNone(self.core.dispatch_next(self.scope.key, now=self.now))
        self.now += timedelta(seconds=1)
        self.market(2)
        state = self.core.reconcile(self.scope.key, now=self.now)
        self.assertEqual(state.positions[0].quantity, D(2))
        self.assertEqual(self.core.reservations(self.scope.key)[0].reserved_notional, D(6))
        self.assertEqual(len(self.venue.receipt_history(self.scope.key, "entry")), 2)

    def test_partial_fill_then_cancel_conserves_original_and_cancel_receipts(self):
        self.core.admit(self.intent("entry"), command_id="entry", now=self.now)
        self.core.dispatch_next(self.scope.key, now=self.now)
        self.now += timedelta(seconds=1)
        self.market(2)
        self.core.reconcile(self.scope.key, now=self.now)
        version = self.venue.lookup(self.scope.key, "entry").receipt.venue_sequence
        cancellation = self.intent("cancel", kind=ActionKind.CANCEL_ORDER, quantity=None,
                                   target="entry", version=version)
        self.assertEqual(self.core.admit(cancellation, command_id="cancel", now=self.now).state, CommandState.QUEUED)
        self.core.dispatch_next(self.scope.key, now=self.now)
        state = self.core.reconcile(self.scope.key, now=self.now)
        entry, cancel = self.core.reservations(self.scope.key)
        self.assertEqual(entry.receipt.effect, EffectState.CANCELLED)
        self.assertEqual((entry.receipt.quantities.filled, entry.receipt.quantities.cancelled), (D(2), D(3)))
        self.assertEqual(cancel.receipt.effect, EffectState.APPLIED)
        self.assertFalse(entry.reservation_held or cancel.reservation_held)
        self.assertEqual(state.positions[0].quantity, D(2))

    def test_failed_precommit_submission_retires_only_after_new_fence(self):
        self.core.admit(self.intent("entry"), command_id="entry", now=self.now)
        self.venue.faults.arm("accept.before_commit")
        with self.assertRaises(OutcomeUnknown):
            self.core.dispatch_next(self.scope.key, now=self.now)
        self.assertEqual(self.venue.lookup(self.scope.key, "entry").state, LookupState.NOT_FOUND)
        self.core.reconcile(self.scope.key, now=self.now)
        self.assertTrue(self.core.reservations(self.scope.key)[0].reservation_held)
        self.control(ControlKind.PAUSE_NEW_RISK)
        self.assertFalse(self.core.reservations(self.scope.key)[0].reservation_held)
        self.assertIsNone(self.core.dispatch_next(self.scope.key, now=self.now))

    def test_owner_close_read_only_verifier_under_real_venue_write_lock(self):
        self.core.admit(self.intent("entry", quantity=D(2)), command_id="entry", now=self.now)
        self.core.dispatch_next(self.scope.key, now=self.now)
        self.now += timedelta(seconds=1)
        self.market(2)
        state = self.core.reconcile(self.scope.key, now=self.now)
        position = state.positions[0]
        self.control(ControlKind.STOP_AUTOMATION)
        close = self.intent("close", kind=ActionKind.CLOSE, quantity=D(2), target=position.position_id,
                            version=position.version, origin=DecisionOrigin.OWNER_REVIEWED)
        self.owner.command_ids[close.intent_id] = "close"
        self.assertEqual(self.core.admit(close, command_id="close", now=self.now).state, CommandState.QUEUED)
        self.core.dispatch_next(self.scope.key, now=self.now)
        self.assertEqual(self.venue.lookup(self.scope.key, "close").receipt.effect, EffectState.ACKNOWLEDGED)
        self.now += timedelta(seconds=1)
        self.market(3)
        state = self.core.reconcile(self.scope.key, now=self.now)
        self.assertEqual(state.positions, ())
        self.assertFalse(state.admissions_enabled)

    def reopen(self):
        self.venue = SQLiteVenue(self.directory / "account.venue.sqlite3")
        self.scope = replace(self.scope, epoch=self.scope.epoch + 1, build_id="reopened-build")
        self.owner = OwnerFixture(self.scope)
        self.core = self.make_core()
        self.core.initialize()
        self.core.reconcile(self.scope.key, now=self.now)

    def assert_blocked_then_partial_then_reopen(self, command_id, *, quantity, prior_position_quantity):
        original = self.venue.lookup(self.scope.key, command_id).receipt
        self.now += timedelta(seconds=1)
        self.market(10, bid=D(3), ask=D(3))
        self.core.reconcile(self.scope.key, now=self.now)
        record = next(x for x in self.core.reservations(self.scope.key) if x.command.command_id == command_id)
        self.assertEqual(record.receipt, original)
        self.assertEqual(record.reserved_notional, quantity * D(2))
        self.assertEqual(record.command.risk_price_ceiling, D(2))
        self.assertEqual(record.receipt.quantities.filled, D(0))
        self.now += timedelta(seconds=1)
        self.market(11)
        projection = self.core.reconcile(self.scope.key, now=self.now)
        record = next(x for x in self.core.reservations(self.scope.key) if x.command.command_id == command_id)
        self.assertEqual(record.receipt.quantities.filled, D(2))
        self.assertEqual(record.reserved_notional, (quantity - D(2)) * D(2))
        self.assertEqual(projection.positions[0].quantity, prior_position_quantity + D(2))
        self.assertEqual(projection.positions[0].side, Side.SELL)
        history = self.venue.receipt_history(self.scope.key, command_id)
        self.reopen()
        self.now += timedelta(seconds=1)
        self.market(12, bid=D(3), ask=D(3))
        projection = self.core.reconcile(self.scope.key, now=self.now)
        record = next(x for x in self.core.reservations(self.scope.key) if x.command.command_id == command_id)
        self.assertTrue(record.reservation_held)
        self.assertEqual(record.reserved_notional, (quantity - D(2)) * D(2))
        self.assertEqual(self.venue.receipt_history(self.scope.key, command_id), history)
        self.assertEqual(projection.positions[0].quantity, prior_position_quantity + D(2))
        self.assertFalse(projection.admissions_enabled)
        self.assertIsNone(self.core.dispatch_next(self.scope.key, now=self.now))

    def test_short_open_above_ceiling_retains_twenty_then_partial_reservation_after_restart(self):
        intent = replace(self.intent("short", quantity=D(10)), side=Side.SELL)
        self.assertEqual(self.core.admit(intent, command_id="short", now=self.now).state, CommandState.QUEUED)
        self.core.dispatch_next(self.scope.key, now=self.now)
        self.assert_blocked_then_partial_then_reopen("short", quantity=D(10), prior_position_quantity=D(0))

    def test_short_add_with_inherited_side_retains_remainder_after_restart(self):
        entry = replace(self.intent("short", quantity=D(2)), side=Side.SELL)
        self.core.admit(entry, command_id="short", now=self.now)
        self.core.dispatch_next(self.scope.key, now=self.now)
        self.now += timedelta(seconds=1)
        self.market(2)
        position = self.core.reconcile(self.scope.key, now=self.now).positions[0]
        add = self.intent("add", kind=ActionKind.ADD, quantity=D(4), target=position.position_id, version=position.version)
        self.assertIsNone(add.side)
        self.assertEqual(self.core.admit(add, command_id="add", now=self.now).state, CommandState.QUEUED)
        self.core.dispatch_next(self.scope.key, now=self.now)
        self.assert_blocked_then_partial_then_reopen("add", quantity=D(4), prior_position_quantity=D(2))

    def test_delayed_eligible_quote_fills_and_triggers_stop_in_one_venue_commit(self):
        self.market(2, bid=D("1.10"), ask=D("1.10"))
        self.core.reconcile(self.scope.key, now=self.now)
        entry = replace(self.intent("protected", quantity=D(2)), limit_price=D("1.10"), stop_price=D("1.09"))
        self.assertEqual(self.core.admit(entry, command_id="protected", now=self.now).state, CommandState.QUEUED)
        self.core.dispatch_next(self.scope.key, now=self.now)
        observed_at = self.now + timedelta(seconds=1)
        self.now += timedelta(seconds=2)
        snapshot = self.market(3, bid=D("1.07"), ask=D("1.0702"), observed_at=observed_at)
        self.assertEqual(snapshot.positions, ())
        entry_receipt = self.venue.lookup(self.scope.key, "protected").receipt
        self.assertEqual(entry_receipt.effect, EffectState.FILLED)
        self.assertEqual(entry_receipt.quantities.filled, D(2))
        stops = [x for x in self.venue.receipt_history(self.scope.key) if x.command_id.startswith("venue-stop-")]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0].quantities.filled, D(2))
        self.assertEqual(stops[0].observed_at, entry_receipt.observed_at)
        self.assertGreater(stops[0].venue_sequence, entry_receipt.venue_sequence)
        state = self.core.reconcile(self.scope.key, now=self.now)
        self.assertEqual(state.positions, ())
        self.assertFalse(self.core.reservations(self.scope.key)[0].reservation_held)

