"""Authored core fault tests. NOT_RUN pending the approved AWS execution route.

ReferenceVenue is a small independently maintained in-memory oracle. It is not
the production venue, an actual model, or proof of process/disk durability.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from pathlib import Path
import json
import sqlite3
import tempfile
import threading
import unittest

from cas_forex_revamp.contracts import (
    ActionIntent, ActionKind, CommandState, ContractError, ControlKind, DecisionOrigin, EffectState,
    FenceReceipt, FenceRequest, Instrument, LookupState, MarketObservation, Money,
    PositionView, QuantityReport, RecoveryState, RunScope, Side, VenueLookup,
    VenueReceipt, VenueSnapshot, content_digest,
)
from cas_forex_revamp.core import (
    AdmissionDenied, CoreCoordinator, CoreError, EvidenceConflict, IdentityConflict,
    InstrumentPolicy, OutcomeUnknown, OwnerApproval, RiskPolicy, SQLiteStore, StaleWriter,
)
from cas_forex_revamp.core.policy import upward

D = Decimal
NOW = datetime(2026, 10, 10, 21, 0, tzinfo=timezone.utc)
SCOPE = RunScope("account", "run", 1, "build", "policy", "scenario", "scripted")
INSTRUMENT = Instrument("eurusd", "EURUSD", "EUR", "USD", D("0.01"), D("1"), D("1"))


class AuthenticatedOwnerFixture:
    """TEST ONLY: composition must not install this always-approving verifier."""

    def __init__(self, scope=SCOPE):
        self.scope = scope
        self.reviewed_commands = {}

    def verify(self, subject, *, now):
        is_control = isinstance(subject, FenceRequest)
        command_id = None if is_control else self.reviewed_commands.get(subject.intent_id)
        return OwnerApproval(subject.owner_request_id if is_control else "review-" + subject.intent_id,
                             self.scope, content_digest(subject), now, now + timedelta(seconds=60), command_id)


class ReferenceVenue:
    def __init__(self, key=SCOPE.key):
        self.key = key
        self.sequence = 0
        self.fence = FenceReceipt(key, "initial", 0, False, False, 0, NOW, True)
        self.commands = {}
        self.receipts = {}
        self.positions = {}
        self.accept_calls = 0
        self.before_accept = None
        self.after_accept = None
        self.owner_close_verifier = None
        self.lookup_unknown = False
        self.quote = MarketObservation(key, "quote", "eurusd", 0, NOW, NOW, D("1"), D("1"))

    def _receipt(self, command, effect, now, quantities=None, position_id=None):
        self.sequence += 1
        receipt = VenueReceipt(self.key, "r-" + str(self.sequence), command.command_id,
                               command.payload_sha256, effect, self.sequence,
                               command.dispatch_generation, now, quantities, position_id)
        self.receipts[command.command_id] = receipt
        return receipt

    def accept(self, command, *, now):
        self.accept_calls += 1
        if self.before_accept:
            hook, self.before_accept = self.before_accept, None
            hook()
        if command.command_id in self.commands:
            if self.commands[command.command_id].payload_sha256 != command.payload_sha256:
                raise ValueError("oracle identity conflict")
            return self.receipts[command.command_id]
        self.commands[command.command_id] = command
        intent = command.intent
        risk = intent.kind in (ActionKind.OPEN, ActionKind.ADD)
        reviewed = (intent.kind is ActionKind.CLOSE and intent.origin is DecisionOrigin.OWNER_REVIEWED
                    and self.owner_close_verifier is not None and self.owner_close_verifier(command, now))
        allowed = self.fence.new_risk_allowed if risk else (self.fence.management_allowed or reviewed)
        if command.dispatch_generation != self.fence.generation or not allowed:
            q = None if intent.quantity is None else QuantityReport(intent.quantity, D(0), D(0), intent.quantity, D(0))
            result = self._receipt(command, EffectState.REJECTED, now, q)
        elif intent.kind is ActionKind.CANCEL_ORDER:
            old = self.receipts[intent.target_id]
            if old.venue_sequence != intent.target_version or old.quantities.remaining <= 0:
                result = self._receipt(command, EffectState.REJECTED, now)
            else:
                q = old.quantities
                self._receipt(self.commands[intent.target_id], EffectState.CANCELLED, now,
                              replace(q, cancelled=q.cancelled + q.remaining, remaining=D(0)), old.position_id)
                result = self._receipt(command, EffectState.APPLIED, now)
        elif intent.kind is ActionKind.AMEND_STOP:
            p = self.positions[intent.target_id]
            self.positions[p.position_id] = replace(p, version=p.version + 1, stop_price=intent.stop_price)
            result = self._receipt(command, EffectState.APPLIED, now, position_id=p.position_id)
        else:
            result = self._receipt(command, EffectState.ACKNOWLEDGED, now,
                                   QuantityReport(intent.quantity, D(0), D(0), D(0), intent.quantity),
                                   "p-" + command.command_id if intent.kind is ActionKind.OPEN else intent.target_id)
        if self.after_accept:
            hook, self.after_accept = self.after_accept, None
            hook()
        return result

    def fill(self, command_id, cumulative, *, cancelled=D(0), now=NOW):
        c = self.commands[command_id]
        old = self.receipts[command_id]
        q = old.quantities
        delta = cumulative - q.filled
        position_id = old.position_id
        previous = self.positions.get(position_id)
        if c.intent.kind is ActionKind.OPEN:
            self.positions[position_id] = PositionView(position_id, (previous.version + 1) if previous else 1,
                                                       c.intent.instrument_id, c.intent.side, cumulative, D(1))
        else:
            quantity = previous.quantity + delta if c.intent.kind is ActionKind.ADD else previous.quantity - delta
            self.positions[position_id] = replace(previous, version=previous.version + 1, quantity=quantity)
        remaining = q.ordered - cumulative - cancelled
        effect = EffectState.CANCELLED if cancelled else (EffectState.FILLED if remaining == 0 else EffectState.PARTIALLY_FILLED)
        return self._receipt(c, effect, now, QuantityReport(q.ordered, cumulative, cancelled, D(0), remaining), position_id)

    def advance_fence(self, request, *, now):
        if request.expected_generation != self.fence.generation:
            return replace(self.fence, applied=False, reason_code="GENERATION_CONFLICT")
        risk, manage = self.fence.new_risk_allowed, self.fence.management_allowed
        if request.control is ControlKind.STOP_AUTOMATION:
            risk, manage = False, False
        elif request.control is ControlKind.PAUSE_NEW_RISK:
            risk = False
        elif request.control is ControlKind.RESUME_NEW_RISK:
            risk = True
        else:
            manage = True
        self.sequence += 1
        self.fence = FenceReceipt(self.key, request.barrier_id, request.next_generation,
                                  risk, manage, self.sequence, now, True)
        return self.fence

    def lookup(self, key, command_id):
        if self.lookup_unknown:
            return VenueLookup(key, command_id, LookupState.UNKNOWN, None, None)
        receipt = self.receipts.get(command_id)
        return VenueLookup(key, command_id, LookupState.FOUND if receipt else LookupState.NOT_FOUND,
                           self.sequence, receipt)

    def snapshot(self, key, *, now):
        return VenueSnapshot(key, "snapshot-" + str(self.sequence), self.sequence, now, self.fence,
                             Money(D(100), "USD"), Money(D(100), "USD"), Money(D(0), "USD"), Money(D(0), "USD"),
                             tuple(p for p in self.positions.values() if p.quantity > 0),
                             tuple(k for k, r in self.receipts.items() if r.quantities and r.quantities.remaining > 0),
                             (self.quote,))


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "core.sqlite"
        self.venue = ReferenceVenue()
        self.owner = AuthenticatedOwnerFixture()
        self.core = self.construct()
        self.core.initialize(create=True)
        self.core.reconcile(SCOPE.key, now=NOW)
        self.control(ControlKind.PAUSE_NEW_RISK)
        self.control(ControlKind.RESUME_NEW_RISK)
        self.control(ControlKind.RESUME_MANAGEMENT)

    def construct(self, scope=SCOPE, *, owner=True):
        core = CoreCoordinator(scope=scope, store=SQLiteStore(self.path), venue=self.venue,
                               policy=RiskPolicy("USD", D(20)),
                               instruments=(InstrumentPolicy(INSTRUMENT, D(2)),),
                               owner_verifier=self.owner if owner else None)
        self.venue.owner_close_verifier = core.verify_owner_close
        return core

    def control(self, kind, *, core=None, reconcile=True):
        core = core or self.core
        generation = self.venue.fence.generation
        request = FenceRequest(core.scope.key, "barrier-" + str(generation + 1), kind,
                               "owner-" + str(generation + 1), generation, generation + 1, NOW)
        result = core.control(request, now=NOW)
        if reconcile:
            core.reconcile(core.scope.key, now=NOW)
        return result

    def intent(self, name="i1", quantity="5", *, kind=ActionKind.OPEN, target=None,
               version=None, origin=DecisionOrigin.SCRIPTED, core=None, stop_price=None):
        core = core or self.core
        state = core.current_state(core.scope.key, now=NOW)
        return ActionIntent(name, core.scope, "decision-" + name, "opportunity", "action-" + name,
                            state, kind, "eurusd", origin, NOW, NOW + timedelta(seconds=20),
                            D(quantity) if quantity is not None else None,
                            Side.BUY if kind is ActionKind.OPEN else None, target, version,
                            D(1) if kind in (ActionKind.OPEN, ActionKind.ADD) else None,
                            stop_price=stop_price)

    def submit(self, name="i1", quantity="5"):
        intent = self.intent(name, quantity)
        self.assertEqual(self.core.admit(intent, command_id=name, now=NOW).state, CommandState.QUEUED)
        self.core.dispatch_next(SCOPE.key, now=NOW)
        self.core.reconcile(SCOPE.key, now=NOW)
        return intent

    def position(self):
        self.submit()
        self.venue.fill("i1", D(5))
        self.core.reconcile(SCOPE.key, now=NOW)
        return self.venue.positions["p-i1"]

    def test_construction_is_inert(self):
        fresh = Path(self.temp.name) / "not-created.sqlite"
        CoreCoordinator(scope=SCOPE, store=SQLiteStore(fresh), venue=self.venue,
                        policy=RiskPolicy("USD", D(20)), instruments=(InstrumentPolicy(INSTRUMENT, D(2)),))
        self.assertFalse(fresh.exists())

    def test_duplicate_same_payload_returns_one_command_and_reservation(self):
        intent = self.intent()
        one = self.core.admit(intent, command_id="one", now=NOW)
        two = self.core.admit(intent, command_id="one", now=NOW)
        self.assertEqual(one, two)
        self.assertEqual(len(self.core.reservations(SCOPE.key)), 1)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].reserved_notional, D(10))

    def test_same_command_changed_payload_conflicts(self):
        intent = self.intent()
        self.core.admit(intent, command_id="one", now=NOW)
        with self.assertRaises(IdentityConflict):
            self.core.admit(replace(intent, quantity=D(6)), command_id="one", now=NOW)

    def test_same_intent_cannot_get_another_command_id(self):
        intent = self.intent()
        self.core.admit(intent, command_id="one", now=NOW)
        with self.assertRaises(IdentityConflict):
            self.core.admit(intent, command_id="two", now=NOW)

    def test_duplicate_threads_reserve_once(self):
        intent = self.intent()
        gate = threading.Barrier(2)
        def admit():
            gate.wait()
            return self.core.admit(intent, command_id="same", now=NOW)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: admit(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(sum(x.reserved_notional for x in self.core.reservations(SCOPE.key)), D(10))

    def test_distinct_threads_cannot_overbook_stale_context(self):
        first = self.intent("first", "6")
        second = replace(first, intent_id="second", decision_id="decision-second", action_ref="second")
        gate = threading.Barrier(2)
        def admit(item):
            gate.wait()
            return self.core.admit(item, command_id=item.intent_id, now=NOW)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(admit, (first, second)))
        self.assertEqual(sum(x.state is CommandState.QUEUED for x in results), 1)

    def test_current_context_still_checks_aggregate_reserved_capacity(self):
        self.core.admit(self.intent("first", "6"), command_id="first", now=NOW)
        rejected = self.core.admit(self.intent("second", "5"), command_id="second", now=NOW)
        self.assertEqual(rejected.reason_code, "GROSS_NOTIONAL_CAPACITY")

    def test_atomic_rollback_leaves_neither_identity_nor_reservation(self):
        original = self.core.store.event
        def fail(*args, **kwargs):
            raise OSError("simulated disk failure")
        self.core.store.event = fail
        with self.assertRaises(OSError):
            self.core.admit(self.intent(), command_id="one", now=NOW)
        self.core.store.event = original
        self.assertEqual(self.core.reservations(SCOPE.key), ())

    def test_ack_is_not_fill_and_releases_nothing(self):
        self.submit()
        record = self.core.reservations(SCOPE.key)[0]
        self.assertEqual(record.receipt.effect, EffectState.ACKNOWLEDGED)
        self.assertEqual(record.reserved_notional, D(10))
        self.assertTrue(record.reservation_held)
        self.assertEqual(self.core.inspect(SCOPE.key, now=NOW).positions, ())

    def test_partial_fill_converts_only_observed_exposure(self):
        self.submit()
        self.venue.fill("i1", D(2))
        projection = self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(projection.positions[0].quantity, D(2))
        self.assertEqual(self.core.reservations(SCOPE.key)[0].reserved_notional, D(6))
        self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].reserved_notional, D(6))

    def test_mixed_terminal_result_preserves_buckets(self):
        self.submit()
        self.venue.fill("i1", D(2), cancelled=D(3))
        self.core.reconcile(SCOPE.key, now=NOW)
        record = self.core.reservations(SCOPE.key)[0]
        self.assertEqual(record.receipt.quantities.filled, D(2))
        self.assertEqual(record.receipt.quantities.cancelled, D(3))
        self.assertFalse(record.reservation_held)
        self.assertEqual(record.receipt.effect, EffectState.CANCELLED)

    def test_cancel_uses_receipt_version_and_observes_both_commands(self):
        self.submit()
        old = self.venue.receipts["i1"]
        cancel = self.intent("cancel", None, kind=ActionKind.CANCEL_ORDER, target="i1", version=old.venue_sequence)
        self.assertEqual(self.core.admit(cancel, command_id="cancel", now=NOW).state, CommandState.QUEUED)
        self.core.dispatch_next(SCOPE.key, now=NOW)
        self.core.reconcile(SCOPE.key, now=NOW)
        original, cancellation = self.core.reservations(SCOPE.key)
        self.assertEqual(original.receipt.effect, EffectState.CANCELLED)
        self.assertEqual(cancellation.receipt.effect, EffectState.APPLIED)
        self.assertFalse(original.reservation_held or cancellation.reservation_held)

    def test_stale_cancellation_version_is_rejected(self):
        self.submit()
        cancel = self.intent("cancel", None, kind=ActionKind.CANCEL_ORDER, target="i1", version=0)
        self.assertEqual(self.core.admit(cancel, command_id="cancel", now=NOW).reason_code, "ORDER_VERSION_NOT_CURRENT")

    def test_close_reservation_excludes_concurrent_target_mutation(self):
        position = self.position()
        one = self.intent("close-one", "5", kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual(self.core.admit(one, command_id="close-one", now=NOW).state, CommandState.QUEUED)
        two = self.intent("close-two", "5", kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual(self.core.admit(two, command_id="close-two", now=NOW).reason_code, "TARGET_ALREADY_RESERVED")

    def test_close_cannot_reverse_or_hide_partial_close(self):
        position = self.position()
        oversized = self.intent("large", "6", kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual(self.core.admit(oversized, command_id="large", now=NOW).reason_code, "INSUFFICIENT_CLOSEABLE_QUANTITY")
        partial = self.intent("partial", "4", kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual(self.core.admit(partial, command_id="partial", now=NOW).reason_code, "CLOSE_REQUIRES_EXACT_POSITION_QUANTITY")

    def test_pause_preserves_separate_management_but_does_not_cancel_pending(self):
        self.submit()
        result = self.control(ControlKind.PAUSE_NEW_RISK)
        self.assertFalse(result.new_risk_allowed)
        self.assertTrue(result.management_allowed)
        self.venue.fill("i1", D(5))
        projection = self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(projection.positions[0].quantity, D(5))

    def test_stop_has_no_hidden_close(self):
        self.position()
        result = self.control(ControlKind.STOP_AUTOMATION)
        self.assertFalse(result.new_risk_allowed or result.management_allowed)
        self.assertEqual(self.core.inspect(SCOPE.key, now=NOW).positions[0].quantity, D(5))

    def test_reviewed_close_can_pass_stopped_automation_without_resuming(self):
        position = self.position()
        self.control(ControlKind.STOP_AUTOMATION)
        intent = self.intent("reviewed", "5", kind=ActionKind.CLOSE, target=position.position_id,
                             version=position.version, origin=DecisionOrigin.OWNER_REVIEWED)
        self.owner.reviewed_commands[intent.intent_id] = "reviewed-command"
        self.assertEqual(self.core.admit(intent, command_id="reviewed-command", now=NOW).state, CommandState.QUEUED)
        self.core.dispatch_next(SCOPE.key, now=NOW)
        self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(self.venue.receipts["reviewed-command"].effect, EffectState.ACKNOWLEDGED)
        self.assertFalse(self.venue.fence.management_allowed or self.venue.fence.new_risk_allowed)

    def test_owner_enum_without_exact_reviewed_command_does_not_authorize(self):
        position = self.position()
        self.control(ControlKind.STOP_AUTOMATION)
        intent = self.intent("forged", "5", kind=ActionKind.CLOSE, target=position.position_id,
                             version=position.version, origin=DecisionOrigin.OWNER_REVIEWED)
        result = self.core.admit(intent, command_id="forged", now=NOW)
        self.assertEqual(result.reason_code, "OWNER_COMMAND_MISMATCH")

    def test_no_default_owner_verifier(self):
        core = self.construct(owner=False)
        core.initialize()
        core.reconcile(SCOPE.key, now=NOW)
        with self.assertRaises(AdmissionDenied):
            self.control(ControlKind.STOP_AUTOMATION, core=core)

    def test_lost_ack_reply_preserves_identity_and_reservation_across_epoch(self):
        intent = self.intent()
        self.core.admit(intent, command_id="lost", now=NOW)
        def lost_reply():
            raise ConnectionError("simulated lost reply")
        self.venue.after_accept = lost_reply
        with self.assertRaises(OutcomeUnknown):
            self.core.dispatch_next(SCOPE.key, now=NOW)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].reserved_notional, D(10))
        new_scope = replace(SCOPE, epoch=2, build_id="build-2")
        self.owner.scope = new_scope
        core = self.construct(new_scope)
        core.initialize()
        projection = core.reconcile(new_scope.key, now=NOW)
        self.assertFalse(projection.admissions_enabled)
        self.assertEqual(projection.commands[0].last_venue_receipt_id, self.venue.receipts["lost"].receipt_id)
        self.assertIsNone(core.dispatch_next(new_scope.key, now=NOW))
        self.assertEqual(self.venue.accept_calls, 1)
        with self.assertRaises(StaleWriter):
            self.core.current_state(SCOPE.key, now=NOW)

    def test_preaccept_crash_not_found_does_not_authorize_resend(self):
        self.core.admit(self.intent(), command_id="unknown", now=NOW)
        def fail_before():
            raise ConnectionError("before venue acceptance")
        self.venue.before_accept = fail_before
        with self.assertRaises(OutcomeUnknown):
            self.core.dispatch_next(SCOPE.key, now=NOW)
        projection = self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(projection.recovery, RecoveryState.UNRESOLVED)
        self.assertTrue(projection.commands[0].reservation_held)
        self.assertIsNone(self.core.dispatch_next(SCOPE.key, now=NOW))
        self.control(ControlKind.PAUSE_NEW_RISK)
        record = self.core.reservations(SCOPE.key)[0]
        self.assertEqual(record.reason_code, "ABSENT_AFTER_NEWER_FENCE")
        self.assertFalse(record.reservation_held)
        self.assertEqual(self.venue.accept_calls, 1)

    def test_pause_race_rejects_old_dispatch_generation_at_venue(self):
        self.core.admit(self.intent(), command_id="racing", now=NOW)
        self.venue.before_accept = lambda: self.control(ControlKind.PAUSE_NEW_RISK, reconcile=False)
        view = self.core.dispatch_next(SCOPE.key, now=NOW)
        self.assertTrue(view.reservation_held)
        self.core.reconcile(SCOPE.key, now=NOW)
        record = self.core.reservations(SCOPE.key)[0]
        self.assertEqual(record.receipt.effect, EffectState.REJECTED)
        self.assertFalse(record.reservation_held)

    def test_unknown_lookup_blocks_new_admissions_without_erasing_ack(self):
        self.submit()
        self.venue.lookup_unknown = True
        projection = self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(projection.recovery, RecoveryState.UNRESOLVED)
        self.assertTrue(projection.commands[0].reservation_held)
        self.assertFalse(projection.admissions_enabled)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].receipt.effect, EffectState.ACKNOWLEDGED)

    def test_same_sequence_changed_receipt_quarantines(self):
        self.submit()
        self.venue.receipts["i1"] = replace(self.venue.receipts["i1"], reason_code="changed")
        with self.assertRaises(EvidenceConflict):
            self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(self.core.inspect(SCOPE.key, now=NOW).recovery, RecoveryState.QUARANTINED)
        self.assertTrue(self.core.reservations(SCOPE.key)[0].reservation_held)

    def test_receipt_hash_mismatch_is_never_observed_as_success(self):
        self.submit()
        self.venue.receipts["i1"] = replace(self.venue.receipts["i1"], payload_sha256="0" * 64)
        with self.assertRaises(EvidenceConflict):
            self.core.reconcile(SCOPE.key, now=NOW)

    def test_missing_old_receipt_at_new_cursor_is_quarantined(self):
        self.submit()
        del self.venue.receipts["i1"]
        self.venue.sequence += 1
        with self.assertRaises(EvidenceConflict):
            self.core.reconcile(SCOPE.key, now=NOW)

    def test_stale_model_reply_is_denied_after_reconciliation(self):
        stale = self.intent()
        self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(self.core.admit(stale, command_id="stale", now=NOW).reason_code, "SOURCE_STATE_CHANGED")

    def test_expired_intent_is_denied(self):
        intent = self.intent()
        result = self.core.admit(intent, command_id="late", now=NOW + timedelta(seconds=21))
        self.assertEqual(result.reason_code, "INTENT_EXPIRED_OR_FUTURE")

    def test_missing_store_is_not_recreated_by_reopen(self):
        missing = SQLiteStore(Path(self.temp.name) / "missing.sqlite")
        with self.assertRaises(sqlite3.OperationalError):
            missing.initialize()
        self.assertFalse(missing.path.exists())

    def test_empty_existing_store_is_not_initialized_by_reopen(self):
        path = Path(self.temp.name) / "empty.sqlite"
        path.touch()
        with self.assertRaises(CoreError):
            SQLiteStore(path).initialize()

    def test_explicit_create_cannot_overwrite_an_existing_empty_file(self):
        path = Path(self.temp.name) / "preserved-empty.sqlite"
        path.touch()
        with self.assertRaisesRegex(CoreError, "ALREADY_EXISTS"):
            SQLiteStore(path).initialize(create=True)
        self.assertEqual(path.read_bytes(), b"")

    def test_create_cannot_reset_existing_store(self):
        self.submit()
        with self.assertRaises(CoreError):
            self.core.initialize(create=True)
        self.assertEqual(len(self.core.reservations(SCOPE.key)), 1)

    def test_corrupt_account_json_never_becomes_empty_account(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE accounts SET record='{' ")
        with self.assertRaises(CoreError):
            self.core.inspect(SCOPE.key, now=NOW)
        with self.assertRaises(CoreError):
            self.core.initialize()

    def test_schema_mismatch_is_not_migrated_or_reset(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE metadata SET value='future/99' WHERE name='schema'")
        with self.assertRaises(CoreError):
            self.core.initialize()

    def test_scope_change_without_epoch_increase_is_blocked(self):
        core = self.construct(replace(SCOPE, build_id="older-build"))
        with self.assertRaises(CoreError):
            core.initialize()

    def test_quantity_step_rejects_instead_of_silently_rounding(self):
        result = self.core.admit(self.intent(quantity="1.5"), command_id="fraction", now=NOW)
        self.assertEqual(result.reason_code, "QUANTITY_STEP_OR_MINIMUM")

    def test_notional_rounding_does_not_depend_on_ambient_precision(self):
        with localcontext() as ctx:
            ctx.prec = 4
            self.assertEqual(upward(D("123456.000001"), D("0.01")), D("123456.01"))

    def test_unknown_fence_readback_cannot_confirm_control(self):
        original = self.venue.snapshot
        def fail_snapshot(*args, **kwargs):
            raise ConnectionError("readback unavailable")
        self.venue.snapshot = fail_snapshot
        with self.assertRaises(OutcomeUnknown):
            self.control(ControlKind.STOP_AUTOMATION)
        self.venue.snapshot = original
        self.assertFalse(self.core.inspect(SCOPE.key, now=NOW).admissions_enabled)
        projection = self.core.reconcile(SCOPE.key, now=NOW)
        self.assertFalse(projection.admissions_enabled)
        self.assertFalse(self.venue.fence.management_allowed)

    def test_checkpoint_detects_complete_core_file_rollback(self):
        before = self.path.read_bytes()
        self.submit()
        high_water = self.core.checkpoint(SCOPE.key)
        self.path.write_bytes(before)  # Isolated temporary test DB only.
        restarted = self.construct()
        with self.assertRaisesRegex(CoreError, "CHECKPOINT_ROLLBACK"):
            restarted.initialize(expected_checkpoint=high_water)

    def test_command_row_loss_is_detected_from_admission_count(self):
        self.submit()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM commands")  # Deliberate corruption of a test DB.
        with self.assertRaisesRegex(CoreError, "ADMISSION_COUNT"):
            self.core.reservations(SCOPE.key)

    def test_valid_json_record_corruption_is_detected_by_checksum(self):
        import json
        with sqlite3.connect(self.path) as db:
            raw = db.execute("SELECT record FROM accounts").fetchone()[0]
            value = json.loads(raw)
            value["revision"] += 1
            db.execute("UPDATE accounts SET record=?", (json.dumps(value),))
        with self.assertRaisesRegex(CoreError, "CHECKSUM"):
            self.core.inspect(SCOPE.key, now=NOW)

    def test_receipt_sequence_regression_never_rewinds_cumulative_fill(self):
        self.submit()
        old = self.venue.receipts["i1"]
        self.venue.fill("i1", D(2))
        self.core.reconcile(SCOPE.key, now=NOW)
        self.venue.receipts["i1"] = old
        self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].receipt.quantities.filled, D(2))
        self.assertEqual(self.core.reservations(SCOPE.key)[0].reserved_notional, D(6))

    def test_partial_open_reserves_its_materialized_target(self):
        self.submit()
        self.venue.fill("i1", D(2))
        self.core.reconcile(SCOPE.key, now=NOW)
        position = self.venue.positions["p-i1"]
        close = self.intent("close", "2", kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual(self.core.admit(close, command_id="close", now=NOW).reason_code, "TARGET_ALREADY_RESERVED")
        amend = self.intent("amend", None, kind=ActionKind.AMEND_STOP,
                            target=position.position_id, version=position.version, stop_price=D("0.90"))
        self.assertEqual(self.core.admit(amend, command_id="amend", now=NOW).reason_code, "TARGET_ALREADY_RESERVED")

    def test_reopen_observation_does_not_restore_permissions(self):
        from cas_forex_revamp.contracts import NewRiskPermission
        core = self.construct()
        core.initialize()
        projection = core.reconcile(SCOPE.key, now=NOW)
        self.assertFalse(projection.admissions_enabled)
        self.assertEqual(projection.permissions.new_risk, NewRiskPermission.UNKNOWN)
        with self.assertRaisesRegex(AdmissionDenied, "FRESH_FENCE_REQUIRED"):
            self.control(ControlKind.RESUME_NEW_RISK, core=core)

    def test_exact_control_retry_does_not_advance_generation(self):
        generation = self.venue.fence.generation
        request = FenceRequest(SCOPE.key, "idempotent", ControlKind.PAUSE_NEW_RISK,
                               "idempotent-owner", generation, generation + 1, NOW)
        one = self.core.control(request, now=NOW)
        two = self.core.control(request, now=NOW)
        self.assertEqual(one, two)
        self.assertEqual(self.venue.fence.generation, generation + 1)

    def test_barrier_identity_cannot_change_control_kind(self):
        generation = self.venue.fence.generation
        request = FenceRequest(SCOPE.key, "immutable", ControlKind.PAUSE_NEW_RISK,
                               "immutable-owner", generation, generation + 1, NOW)
        self.core.control(request, now=NOW)
        with self.assertRaises(IdentityConflict):
            self.core.control(replace(request, control=ControlKind.RESUME_NEW_RISK), now=NOW)

    def test_crash_after_dispatch_claim_remains_attempted_on_reopen(self):
        class ProcessDeath(BaseException):
            pass
        def die():
            raise ProcessDeath()
        self.core.admit(self.intent(), command_id="crash", now=NOW)
        self.venue.before_accept = die
        with self.assertRaises(ProcessDeath):
            self.core.dispatch_next(SCOPE.key, now=NOW)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].state, CommandState.SUBMITTED)
        core = self.construct()
        core.initialize()
        projection = core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(projection.recovery, RecoveryState.UNRESOLVED)
        self.assertTrue(projection.commands[0].reservation_held)
        self.assertIsNone(core.dispatch_next(SCOPE.key, now=NOW))

    def test_venue_cursor_regression_is_quarantined(self):
        self.submit()
        self.venue.sequence -= 1
        with self.assertRaises(EvidenceConflict):
            self.core.reconcile(SCOPE.key, now=NOW)

    def test_stale_market_does_not_get_freshness_from_new_snapshot_time(self):
        later = NOW + timedelta(seconds=60)
        self.core.reconcile(SCOPE.key, now=later)
        state = self.core.current_state(SCOPE.key, now=later)
        intent = replace(self.intent_from_state(state), created_at=later, expires_at=later + timedelta(seconds=10))
        self.assertEqual(self.core.admit(intent, command_id="stale-market", now=later).reason_code, "MARKET_STALE")

    @staticmethod
    def intent_from_state(state):
        return ActionIntent("at-state", state.scope, "decision-state", "opportunity", "action-state",
                            state, ActionKind.OPEN, "eurusd", DecisionOrigin.SCRIPTED,
                            state.observed_at, state.valid_until, D(1), Side.BUY, limit_price=D(1))

    def test_quantity_release_waits_for_coherent_snapshot(self):
        self.submit()
        self.venue.fill("i1", D(2))
        original = self.venue.snapshot
        count = 0
        def changing(key, *, now):
            nonlocal count
            count += 1
            if count == 2:
                self.venue.sequence += 1
            return original(key, now=now)
        self.venue.snapshot = changing
        result = self.core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(result.recovery, RecoveryState.UNRESOLVED)
        self.assertEqual(self.core.reservations(SCOPE.key)[0].reserved_notional, D(10))

    def test_read_snapshot_is_read_only_and_exposes_verified_prefix(self):
        self.submit()
        before = self.core.checkpoint(SCOPE.key)
        snapshot = self.core.read_snapshot(SCOPE.key)
        after = self.core.checkpoint(SCOPE.key)
        self.assertEqual(before, after)
        self.assertEqual(snapshot.event_sha256, snapshot.events[-1].event_sha256)
        self.assertEqual(snapshot.event_sequence, snapshot.events[-1].sequence)
        self.assertEqual(snapshot.account.snapshot.sequence, self.venue.sequence)
        self.assertEqual(snapshot.commands[0].command.command_id, "i1")

    def test_changed_event_prefix_is_detected_without_reconciliation(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE events SET payload='{}' WHERE sequence=1")
        with self.assertRaisesRegex(CoreError, "EVENT_PREFIX_CORRUPT"):
            self.core.read_snapshot(SCOPE.key)

    def test_open_ceiling_is_core_selected_and_rejected_command_has_none(self):
        self.core.admit(replace(self.intent(), side=Side.SELL), command_id="short", now=NOW)
        record = self.core.reservations(SCOPE.key)[0]
        self.assertEqual(record.command.risk_price_ceiling, D(2))
        self.assertEqual(record.reservation_price, D(2))
        self.assertEqual(record.reserved_notional, D(10))
        self.core.admit(self.intent("too-large", "10"), command_id="rejected", now=NOW)
        self.assertIsNone(self.core.reservations(SCOPE.key)[1].command.risk_price_ceiling)

    def test_add_carries_ceiling_and_management_has_none(self):
        position = self.position()
        add = self.intent("add", "2", kind=ActionKind.ADD, target=position.position_id, version=position.version)
        self.assertEqual(self.core.admit(add, command_id="add", now=NOW).state, CommandState.QUEUED)
        self.assertEqual(self.core.reservations(SCOPE.key)[1].command.risk_price_ceiling, D(2))
        self.core.dispatch_next(SCOPE.key, now=NOW)
        self.core.reconcile(SCOPE.key, now=NOW)
        version = self.venue.receipts["add"].venue_sequence
        cancel = self.intent("cancel", None, kind=ActionKind.CANCEL_ORDER, target="add", version=version)
        self.assertEqual(self.core.admit(cancel, command_id="cancel", now=NOW).state, CommandState.QUEUED)
        self.assertIsNone(self.core.reservations(SCOPE.key)[2].command.risk_price_ceiling)

    def test_full_authorized_command_is_immutable_in_storage(self):
        self.core.admit(self.intent(), command_id="immutable", now=NOW)
        record = self.core.reservations(SCOPE.key)[0]
        for change in ({"risk_price_ceiling": D(3)}, {"authority_id": "different-authority"},
                       {"writer_id": "different-writer"}, {"reservation_id": "different-reservation"},
                       {"dispatch_generation": record.command.dispatch_generation + 1}):
            with self.subTest(change=change), self.assertRaisesRegex(IdentityConflict, "AUTHORIZED_COMMAND_CONFLICT"):
                with self.core.store.transaction() as db:
                    self.core.store.save_command(db, replace(record, command=replace(record.command, **change)))
        self.assertEqual(self.core.reservations(SCOPE.key)[0], record)

    def legacy_record_without_ceiling(self, command_id):
        # TEST-ONLY older serialized row fixture. Keep its original-shape checksum;
        # never use production mutation APIs to rewrite an authorized command.
        from cas_forex_revamp.core.storage import encode
        with sqlite3.connect(self.path) as db:
            raw = json.loads(db.execute("SELECT record FROM commands WHERE command_id=?", (command_id,)).fetchone()[0])
            del raw["command"]["risk_price_ceiling"]
            db.execute("UPDATE commands SET record=?,record_sha256=? WHERE command_id=?",
                       (encode(raw), content_digest(raw), command_id))

    def test_never_attempted_legacy_missing_ceiling_retires_without_submission(self):
        self.core.admit(self.intent(), command_id="legacy", now=NOW)
        self.legacy_record_without_ceiling("legacy")
        view = self.core.dispatch_next(SCOPE.key, now=NOW)
        self.assertEqual(view.reason_code, "MISSING_EXECUTION_PRICE_CEILING")
        self.assertEqual(view.state, CommandState.REJECTED)
        self.assertFalse(view.reservation_held)
        self.assertEqual(self.venue.accept_calls, 0)

    def test_dispatch_rejects_reservation_amount_mismatch(self):
        self.core.admit(self.intent(), command_id="bad-reserve", now=NOW)
        record = self.core.reservations(SCOPE.key)[0]
        with self.core.store.transaction() as db:
            self.core.store.save_command(db, replace(record, reserved_notional=D(1)))
        self.assertEqual(self.core.dispatch_next(SCOPE.key, now=NOW).reason_code, "EXECUTION_PRICE_RESERVATION_MISMATCH")
        self.assertEqual(self.venue.accept_calls, 0)

    def test_dispatch_rejects_changed_policy_without_rewriting_command(self):
        self.core.admit(self.intent(), command_id="old-policy", now=NOW)
        self.core.instruments["eurusd"] = InstrumentPolicy(INSTRUMENT, D("1.50"))
        self.assertEqual(self.core.dispatch_next(SCOPE.key, now=NOW).reason_code, "EXECUTION_PRICE_RESERVATION_MISMATCH")
        self.assertEqual(self.core.reservations(SCOPE.key)[0].command.risk_price_ceiling, D(2))
        self.assertEqual(self.venue.accept_calls, 0)

    def test_attempted_legacy_missing_ceiling_remains_reconcilable_on_reopen(self):
        self.submit("legacy")
        self.legacy_record_without_ceiling("legacy")
        core = self.construct()
        core.initialize()
        core.reconcile(SCOPE.key, now=NOW)
        record = core.reservations(SCOPE.key)[0]
        self.assertTrue(record.attempted and record.reservation_held)
        self.assertIsNone(record.command.risk_price_ceiling)
        self.assertEqual(record.reserved_notional, D(10))
        self.assertIsNone(core.dispatch_next(SCOPE.key, now=NOW))
        self.assertEqual(self.venue.accept_calls, 1)
        self.venue.fill("legacy", D(2))
        core.reconcile(SCOPE.key, now=NOW)
        self.assertEqual(core.reservations(SCOPE.key)[0].reserved_notional, D(6))

    def test_exact_reviewed_close_does_not_dispatch_an_unrelated_queued_command(self):
        position = self.position()
        self.core.admit(self.intent("unrelated", "1"), command_id="unrelated", now=NOW)
        close = self.intent("reviewed", "5", kind=ActionKind.CLOSE, target=position.position_id,
                            version=position.version, origin=DecisionOrigin.OWNER_REVIEWED)
        self.owner.reviewed_commands[close.intent_id] = "reviewed"
        self.assertEqual(self.core.admit(close, command_id="reviewed", now=NOW).state, CommandState.QUEUED)
        view = self.core.dispatch_command(SCOPE.key, "reviewed", now=NOW)
        self.assertEqual(view.command_id, "reviewed")
        self.assertIn("reviewed", self.venue.commands)
        self.assertNotIn("unrelated", self.venue.commands)
        self.assertEqual(self.core.reservations(SCOPE.key)[1].state, CommandState.QUEUED)
        calls = self.venue.accept_calls
        self.assertEqual(self.core.dispatch_command(SCOPE.key, "reviewed", now=NOW), view)
        self.assertIsNone(self.core.dispatch_command(SCOPE.key, "absent", now=NOW))
        self.assertEqual(self.venue.accept_calls, calls)

    def test_exact_dispatch_preserves_unresolved_attempt_gate(self):
        self.core.admit(self.intent("first", "1"), command_id="first", now=NOW)
        self.core.admit(self.intent("second", "1"), command_id="second", now=NOW)
        def lost_reply():
            raise TimeoutError("test-only lost reply")
        self.venue.after_accept = lost_reply
        with self.assertRaises(OutcomeUnknown):
            self.core.dispatch_command(SCOPE.key, "first", now=NOW)
        self.assertIsNone(self.core.dispatch_command(SCOPE.key, "second", now=NOW))
        self.assertEqual(self.core.dispatch_command(SCOPE.key, "first", now=NOW).state, CommandState.UNRESOLVED)
        self.assertNotIn("second", self.venue.commands)
        self.assertEqual(self.venue.accept_calls, 1)


class CoreIntentFixtureTests(unittest.TestCase):
    """Test-only helper regressions; deliberately do not inherit CoreTests."""

    # Reuse setup/helpers, not any original test methods or TestCase subclass.
    setUp = CoreTests.setUp
    construct = CoreTests.construct
    control = CoreTests.control
    intent = CoreTests.intent

    def test_explicit_stop_reaches_action_intent_construction(self):
        stop = D("0.900")
        intent = self.intent("amend", None, kind=ActionKind.AMEND_STOP,
                             target="position", version=1, stop_price=stop)
        self.assertIsInstance(intent, ActionIntent)
        self.assertIs(intent.stop_price, stop)
        self.assertEqual(intent.kind, ActionKind.AMEND_STOP)
        self.assertIsNone(intent.quantity)
        self.assertIsNone(intent.limit_price)

    def test_omitted_stop_still_rejects_amend_stop(self):
        with self.assertRaisesRegex(ContractError, "^AMEND_STOP requires the exact replacement stop$"):
            self.intent("amend", None, kind=ActionKind.AMEND_STOP,
                        target="position", version=1)

    def test_explicit_none_stop_still_rejects_amend_stop(self):
        with self.assertRaisesRegex(ContractError, "^AMEND_STOP requires the exact replacement stop$"):
            self.intent("amend", None, kind=ActionKind.AMEND_STOP,
                        target="position", version=1, stop_price=None)

    def test_invalid_stop_still_uses_production_validation(self):
        invalid_stops = (D("0"), D("-0.90"), D("NaN"), D("Infinity"),
                         D("1e18"), D("0.0000000000001"), 0.9, "0.90")
        for stop in invalid_stops:
            with self.subTest(stop=repr(stop)):
                with self.assertRaisesRegex(ContractError, "^stop_price "):
                    self.intent("amend", None, kind=ActionKind.AMEND_STOP,
                                target="position", version=1, stop_price=stop)

    def test_omitted_stop_preserves_existing_helper_defaults(self):
        for kind in (ActionKind.OPEN, ActionKind.ADD, ActionKind.REDUCE,
                     ActionKind.CLOSE, ActionKind.CANCEL_ORDER):
            with self.subTest(kind=kind):
                quantity = None if kind is ActionKind.CANCEL_ORDER else "5"
                target = None if kind is ActionKind.OPEN else "position"
                version = None if kind is ActionKind.OPEN else 1
                intent = self.intent(kind=kind, quantity=quantity, target=target, version=version)
                self.assertIsNone(intent.stop_price)
                self.assertEqual(intent.limit_price,
                                 D(1) if kind in (ActionKind.OPEN, ActionKind.ADD) else None)
                self.assertEqual(intent.quantity, D(quantity) if quantity is not None else None)
                self.assertEqual(intent.side, Side.BUY if kind is ActionKind.OPEN else None)


if __name__ == "__main__":
    unittest.main()
