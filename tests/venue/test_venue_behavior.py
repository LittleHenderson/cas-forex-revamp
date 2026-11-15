"""Authored behavioral tests. NOT_RUN until bounded AWS execution is approved."""
from __future__ import annotations
from dataclasses import replace
from decimal import localcontext
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cas_forex_revamp.contracts import (
    ActionKind, ContractError, ControlKind, DecisionOrigin, EffectState, LookupState, Side, intent_digest,
)
from cas_forex_revamp.venue import IdentityConflict, OrderPlan, SQLiteVenue, VenueScenario
from .support import D, KEY, START, SCOPE, at, command, fence, initialized, market


class VenueBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "account.venue.sqlite3"

    def assertQuantities(self, receipt, *, ordered, filled, cancelled=0, rejected=0, remaining=0):
        q = receipt.quantities
        self.assertIsNotNone(q)
        expected = tuple(Fraction(str(x)) for x in (ordered, filled, cancelled, rejected, remaining))
        observed = tuple(Fraction(str(x)) for x in (q.ordered, q.filled, q.cancelled, q.rejected, q.remaining))
        self.assertEqual(expected, observed)
        self.assertEqual(observed[0], sum(observed[1:]))  # Independent rational oracle.

    def test_constructor_is_inert_and_genesis_permissions_are_denied(self):
        venue = SQLiteVenue(self.path)
        self.assertFalse(self.path.exists())
        from cas_forex_revamp.contracts import Money
        from .support import INSTRUMENT
        snap = venue.initialize(KEY, opening_balance=Money(D("100"), "USD"), instruments=(INSTRUMENT,), now=START)
        self.assertFalse(snap.fence.new_risk_allowed)
        self.assertFalse(snap.fence.management_allowed)
        self.assertEqual((), snap.positions)
        rejected = venue.accept(command(generation=0), now=START)
        self.assertEqual("NEW_RISK_DISABLED", rejected.reason_code)
        self.assertQuantities(rejected, ordered=10, filled=0, rejected=10)

    def test_ack_partial_full_restart_and_independent_accounting(self):
        venue = initialized(self.path, VenueScenario(order_plans=(("entry", OrderPlan((D("4"), D("6")))),)))
        ack = venue.accept(command(), now=START)
        self.assertEqual(EffectState.ACKNOWLEDGED, ack.effect)
        self.assertQuantities(ack, ordered=10, filled=0, remaining=10)
        self.assertEqual((), venue.snapshot(KEY, now=START).positions)
        partial = venue.advance_market(market(1))
        self.assertEqual(ack.position_id, partial.positions[0].position_id)
        self.assertEqual(1, partial.positions[0].version)
        self.assertQuantities(venue.lookup(KEY, "entry").receipt, ordered=10, filled=4, remaining=6)
        venue = SQLiteVenue(self.path)
        complete = venue.advance_market(market(2))
        self.assertEqual(D("10"), complete.positions[0].quantity)
        self.assertEqual(2, complete.positions[0].version)
        self.assertQuantities(venue.lookup(KEY, "entry").receipt, ordered=10, filled=10)
        # Independent expected spread cost: 10 * (1.1000 - 1.1002) = -.002,
        # rounded down to one cent = -.01. ACK never changed balance/exposure.
        self.assertEqual(D("-0.01"), complete.open_pnl.amount)
        self.assertEqual(D("9999.99"), complete.equity.amount)
        self.assertEqual(3, len(venue.receipt_history(KEY, "entry")))

    def test_same_identity_returns_latest_receipt_changed_payload_conflicts(self):
        venue = initialized(self.path)
        original = command()
        ack = venue.accept(original, now=START)
        self.assertEqual(ack, venue.accept(replace(original, writer_id="other-writer"), now=START))
        venue.advance_market(market(1))
        filled = venue.lookup(KEY, "entry").receipt
        self.assertEqual(filled, venue.accept(original, now=at(99999)))
        with self.assertRaises(IdentityConflict):
            venue.accept(command(quantity="11"), now=at(10))
        with self.assertRaises(ContractError):
            venue.accept(replace(command("bad-hash"), payload_sha256="0" * 64), now=at(10))
        self.assertEqual(LookupState.NOT_FOUND, venue.lookup(KEY, "bad-hash").state)
        # Recovery uses stable key; a different build cannot rewrite old identity.
        with self.assertRaises(IdentityConflict):
            venue.accept(command(scope=replace(SCOPE, epoch=2, build_id="new-build")), now=at(10))

    def test_partial_cancel_updates_both_command_identities_atomically(self):
        venue = initialized(self.path, VenueScenario(fill_limit_per_order=D("4")))
        ack = venue.accept(command(), now=START)
        venue.advance_market(market(1))
        stale = command("cancel-old", kind=ActionKind.CANCEL_ORDER, target="entry", version=ack.venue_sequence)
        self.assertEqual("STALE_TARGET_VERSION", venue.accept(stale, now=at(10)).reason_code)
        latest = venue.lookup(KEY, "entry").receipt
        cancel = command("cancel", kind=ActionKind.CANCEL_ORDER, target="entry", version=latest.venue_sequence)
        applied = venue.accept(cancel, now=at(10))
        self.assertEqual(EffectState.APPLIED, applied.effect)
        terminal = venue.lookup(KEY, "entry").receipt
        self.assertEqual(EffectState.CANCELLED, terminal.effect)
        self.assertLess(terminal.venue_sequence, applied.venue_sequence)
        self.assertQuantities(terminal, ordered=10, filled=4, cancelled=6)
        later = venue.advance_market(market(2))
        self.assertEqual(D("4"), later.positions[0].quantity)
        self.assertEqual((), later.open_command_ids)
        self.assertEqual(applied, SQLiteVenue(self.path).accept(cancel, now=at(20)))

    def test_rejection_plans_are_durable_and_conserve_partial_fills(self):
        scenario = VenueScenario(order_plans=(
            ("denied", OrderPlan(reject_on_accept=True)),
            ("entry", OrderPlan((D("4"),), EffectState.REJECTED)),
        ))
        venue = initialized(self.path, scenario)
        denied = venue.accept(command("denied"), now=START)
        self.assertEqual(EffectState.REJECTED, denied.effect)
        venue.accept(command(), now=START)
        venue.advance_market(market(1))
        venue.advance_market(market(2))
        remainder = venue.lookup(KEY, "entry").receipt
        self.assertEqual(EffectState.REJECTED, remainder.effect)
        self.assertQuantities(remainder, ordered=10, filled=4, rejected=6)
        self.assertEqual(D("4"), venue.snapshot(KEY, now=at(20)).positions[0].quantity)

    def test_pause_stop_and_close_remain_distinct(self):
        venue = initialized(self.path)
        venue.accept(command(), now=START)
        pause = venue.advance_fence(fence(ControlKind.PAUSE_NEW_RISK, 2), now=START)
        self.assertFalse(pause.new_risk_allowed)
        self.assertTrue(pause.management_allowed)
        self.assertEqual("STALE_DISPATCH_GENERATION", venue.accept(command("stale-writer"), now=START).reason_code)
        self.assertEqual("NEW_RISK_DISABLED", venue.accept(command("paused", generation=3), now=START).reason_code)
        opened = venue.advance_market(market(1))  # Already accepted entry can still fill.
        position = opened.positions[0]
        stopped = venue.advance_fence(fence(ControlKind.STOP_AUTOMATION, 3, seconds=10), now=at(10))
        self.assertFalse(stopped.management_allowed)
        self.assertEqual(D("10"), venue.snapshot(KEY, now=at(10)).positions[0].quantity)
        close = command("close", generation=4, kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual("MANAGEMENT_DISABLED", venue.accept(close, now=at(10)).reason_code)
        # An enum alone cannot cross stopped management.
        owner = command("owner-spoof", generation=4, kind=ActionKind.CLOSE, target=position.position_id,
                        version=position.version, origin=DecisionOrigin.OWNER_REVIEWED)
        self.assertEqual("MANAGEMENT_DISABLED", venue.accept(owner, now=at(10)).reason_code)
        venue.advance_fence(fence(ControlKind.RESUME_MANAGEMENT, 4, seconds=10), now=at(10))
        allowed = command("close-fresh", generation=5, kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual(EffectState.ACKNOWLEDGED, venue.accept(allowed, now=at(10)).effect)
        self.assertEqual((), venue.advance_market(market(2)).positions)

    def test_reduce_add_amend_and_exact_close_cannot_reverse(self):
        venue = initialized(self.path)
        venue.accept(command(), now=START)
        position = venue.advance_market(market(1)).positions[0]
        add = command("add", kind=ActionKind.ADD, quantity="2", target=position.position_id, version=position.version)
        venue.accept(add, now=at(10))
        competing = command("competing-close", kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
        self.assertEqual("TARGET_BUSY", venue.accept(competing, now=at(10)).reason_code)
        position = venue.advance_market(market(2)).positions[0]
        self.assertEqual(D("12"), position.quantity)
        amend = command("amend", kind=ActionKind.AMEND_STOP, target=position.position_id, version=position.version, stop="1.0900")
        self.assertEqual(EffectState.APPLIED, venue.accept(amend, now=at(20)).effect)
        current = venue.snapshot(KEY, now=at(20)).positions[0]
        stale = command("stale-reduce", kind=ActionKind.REDUCE, quantity="4", target=position.position_id, version=position.version)
        self.assertEqual("STALE_TARGET_VERSION", venue.accept(stale, now=at(20)).reason_code)
        reduce = command("reduce", kind=ActionKind.REDUCE, quantity="4", target=current.position_id, version=current.version)
        venue.accept(reduce, now=at(20))
        current = venue.advance_market(market(3, bid="1.1100", ask="1.1102")).positions[0]
        self.assertEqual(D("8"), current.quantity)
        too_big = command("over-close", kind=ActionKind.CLOSE, quantity="9", target=current.position_id, version=current.version)
        self.assertEqual("CLOSE_QUANTITY_EXCEEDS_POSITION", venue.accept(too_big, now=at(30)).reason_code)
        close = command("final", kind=ActionKind.CLOSE, quantity="8", target=current.position_id, version=current.version)
        venue.accept(close, now=at(30))
        final = venue.advance_market(market(4, bid="1.1100", ask="1.1102"))
        self.assertEqual((), final.positions)
        self.assertEqual(D("0.10"), final.realized_pnl.amount)  # floor(.0392) + floor(.0784)
        self.assertEqual(D("10000.10"), final.balance.amount)

    def test_stop_gap_has_receipt_and_survives_automation_stop(self):
        venue = initialized(self.path, VenueScenario(fill_limit_per_order=D("4")))
        venue.accept(command(stop="1.0900"), now=START)
        venue.advance_market(market(1))
        venue.advance_fence(fence(ControlKind.STOP_AUTOMATION, 2, seconds=10), now=at(10))
        final = venue.advance_market(market(2, bid="1.0700", ask="1.0702"))
        self.assertEqual((), final.positions)
        self.assertQuantities(venue.lookup(KEY, "entry").receipt, ordered=10, filled=4, cancelled=6)
        stops = [r for r in venue.receipt_history(KEY) if r.reason_code == "VENUE_PROTECTIVE_STOP"]
        self.assertEqual(1, len(stops))
        self.assertQuantities(stops[0], ordered=4, filled=4)
        self.assertEqual(D("-0.13"), final.realized_pnl.amount)  # Gap fill at 1.0700, not stop 1.0900.

    def test_market_replay_identity_clock_limit_and_context_boundaries(self):
        venue = initialized(self.path)
        venue.accept(command(limit="1.1000"), now=START)
        blocked = venue.advance_market(market(1))
        self.assertEqual((), blocked.positions)
        filled = venue.advance_market(market(2, bid="1.0997", ask="1.0999"))
        before = len(venue.inspect_journal(KEY))
        replay = venue.advance_market(market(1))
        self.assertEqual(filled.sequence, replay.sequence)
        self.assertEqual(before, len(venue.inspect_journal(KEY)))
        with self.assertRaises(IdentityConflict):
            venue.advance_market(market(2, bid="1.0998", ask="1.0999"))
        with self.assertRaises(ContractError):
            venue.advance_market(market(3, seconds=5))
        with self.assertRaises(ContractError):
            venue.snapshot(KEY, now=at(5))
        with self.assertRaises(ContractError):
            venue.lookup(replace(KEY, run_id="wrong-run"), "entry")
        # Ambient arithmetic precision cannot change the venue's public arithmetic.
        with localcontext() as context:
            context.prec = 3
            self.assertEqual(filled.equity, venue.snapshot(KEY, now=at(20)).equity)

    def test_short_marking_and_stale_expired_geometry_rejections(self):
        venue = initialized(self.path)
        venue.accept(command(side=Side.SELL), now=START)
        opened = venue.advance_market(market(1))
        self.assertEqual(Side.SELL, opened.positions[0].side)
        self.assertEqual(D("-0.01"), opened.open_pnl.amount)
        for bad, reason in (
            (command("expired", expires=at(1)), "STALE_OR_FUTURE_INTENT"),
            (command("quantity", quantity="1.5"), "INVALID_QUANTITY_GEOMETRY"),
            (command("tick", limit="1.10001"), "INVALID_PRICE_TICK"),
        ):
            self.assertEqual(reason, venue.accept(bad, now=at(10)).reason_code)

    def test_fence_identity_conflict_and_failed_compare_do_not_change_permissions(self):
        venue = initialized(self.path)
        request = fence(ControlKind.PAUSE_NEW_RISK, 2)
        applied = venue.advance_fence(request, now=START)
        self.assertEqual(applied, venue.advance_fence(request, now=START))
        with self.assertRaises(IdentityConflict):
            venue.advance_fence(replace(request, control=ControlKind.STOP_AUTOMATION), now=START)
        mismatch = venue.advance_fence(fence(ControlKind.STOP_AUTOMATION, 0, name="bad-cas"), now=START)
        self.assertFalse(mismatch.applied)
        self.assertEqual(applied, venue.snapshot(KEY, now=START).fence)
        self.assertEqual(applied, SQLiteVenue(self.path).snapshot(KEY, now=START).fence)

    def test_delayed_historical_quote_cannot_fill_a_later_order(self):
        venue = initialized(self.path)
        venue.accept(command(), now=at(20))
        historical = replace(market(1, seconds=10), available_at=at(30))
        snap = venue.advance_market(historical)
        self.assertEqual((), snap.positions)
        self.assertEqual(EffectState.ACKNOWLEDGED, venue.lookup(KEY, "entry").receipt.effect)
        self.assertEqual(D("10"), venue.advance_market(market(2, seconds=40)).positions[0].quantity)

    def test_zero_quota_and_cancelled_plan_are_real_pending_then_terminal(self):
        venue = initialized(self.path, VenueScenario(order_plans=(
            ("entry", OrderPlan((D("0"), D("4")), EffectState.CANCELLED)),)))
        venue.accept(command(), now=START)
        first = venue.advance_market(market(1))
        self.assertEqual((), first.positions)
        self.assertEqual(EffectState.ACKNOWLEDGED, venue.lookup(KEY, "entry").receipt.effect)
        venue.advance_market(market(2))
        venue.advance_market(market(3))
        self.assertQuantities(venue.lookup(KEY, "entry").receipt, ordered=10, filled=4, cancelled=6)

    def test_amending_stop_on_partial_position_survives_remaining_entry_fills(self):
        venue = initialized(self.path, VenueScenario(fill_limit_per_order=D("4")))
        venue.accept(command(stop="1.0800"), now=START)
        partial = venue.advance_market(market(1)).positions[0]
        amendment = command("protect-partial", kind=ActionKind.AMEND_STOP,
                            target=partial.position_id, version=partial.version, stop="1.0950")
        self.assertEqual(EffectState.APPLIED, venue.accept(amendment, now=at(10)).effect)
        after_fill = venue.advance_market(market(2)).positions[0]
        self.assertEqual(D("8"), after_fill.quantity)
        self.assertEqual(D("1.0950"), after_fill.stop_price)
        final = venue.advance_market(market(3, bid="1.0900", ask="1.0902"))
        self.assertEqual((), final.positions)
        original = venue.lookup(KEY, "entry").receipt
        self.assertQuantities(original, ordered=10, filled=8, cancelled=2)
