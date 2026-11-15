"""CV-02/CV-03 source regressions. Runtime status: NOT_RUN."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sqlite3
import unittest

from cas_forex_revamp.contracts import ActionKind, EffectState, Side, content_digest, to_wire
from cas_forex_revamp.venue import IdentityConflict, OrderPlan, SQLiteVenue, VenueScenario
from .support import D, KEY, START, at, command, initialized, market


class VenueReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "review.venue.sqlite3"

    def checkpoint(self, path=None):
        connection = sqlite3.connect(path or self.path)
        try:
            row = connection.execute("SELECT sequence, document FROM checkpoints ORDER BY sequence DESC LIMIT 1").fetchone()
            return row[0], json.loads(row[1])
        finally:
            connection.close()

    def test_delayed_eligible_buy_and_sell_entries_trigger_stop_in_same_step(self):
        for side, bid, ask, stop in ((Side.BUY, "1.0700", "1.0702", "1.0900"),
                                      (Side.SELL, "1.1200", "1.1202", "1.1100")):
            with self.subTest(side=side):
                path = Path(self.directory.name) / (side.value + ".venue.sqlite3")
                venue = initialized(path)
                accepted = venue.accept(command(side=side, limit="1.1000", stop=stop), now=START)
                quote = replace(market(1, bid=bid, ask=ask, seconds=10), available_at=at(20))
                result = venue.advance_market(quote)
                self.assertEqual((), result.positions)
                self.assertEqual((), result.open_command_ids)
                receipts = venue.receipt_history(KEY)
                entry = venue.lookup(KEY, "entry").receipt
                stops = [r for r in receipts if r.reason_code == "VENUE_PROTECTIVE_STOP"]
                self.assertEqual(EffectState.FILLED, entry.effect)
                self.assertEqual(D("10"), entry.quantities.filled)
                self.assertEqual(1, len(stops))
                self.assertEqual(D("10"), stops[0].quantities.filled)
                self.assertEqual(accepted.position_id, stops[0].position_id)
                self.assertEqual(at(20), entry.observed_at)
                self.assertEqual(at(20), stops[0].observed_at)
                self.assertLess(entry.venue_sequence, stops[0].venue_sequence)
                _, saved = self.checkpoint(path)
                for order in saved["state"]["commands"].values():
                    for fill in order["fills"]:
                        self.assertEqual(to_wire(at(10)), fill["market_observed_at"])
                        self.assertEqual(to_wire(at(20)), fill["observed_at"])
                        self.assertEqual(quote.event_id, fill["market_event_id"])
                restarted = SQLiteVenue(path)
                replay = restarted.advance_market(quote)
                self.assertEqual(result, replay)
                self.assertEqual(receipts, restarted.receipt_history(KEY))

    def test_delayed_partial_entry_cancels_remainder_and_stops_filled_quantity_atomically(self):
        venue = initialized(self.path, VenueScenario(fill_limit_per_order=D("4")))
        venue.accept(command(limit="1.1000", stop="1.0900"), now=START)
        quote = replace(market(1, bid="1.0700", ask="1.0702", seconds=10), available_at=at(20))
        result = venue.advance_market(quote)
        self.assertEqual((), result.positions)
        self.assertEqual((), result.open_command_ids)
        recovered = SQLiteVenue(self.path)
        original = recovered.lookup(KEY, "entry").receipt
        self.assertEqual(EffectState.CANCELLED, original.effect)
        self.assertEqual((D("10"), D("4"), D("6"), D("0"), D("0")),
            (original.quantities.ordered, original.quantities.filled, original.quantities.cancelled,
             original.quantities.rejected, original.quantities.remaining))
        stops = [r for r in recovered.receipt_history(KEY) if r.reason_code == "VENUE_PROTECTIVE_STOP"]
        self.assertEqual(1, len(stops))
        self.assertEqual(D("4"), stops[0].quantities.filled)
        self.assertEqual(at(20), stops[0].observed_at)

    def test_delayed_add_with_new_stop_protects_the_entire_position_in_same_step(self):
        venue = initialized(self.path)
        venue.accept(command(), now=START)
        position = venue.advance_market(market(1, seconds=10)).positions[0]
        added = venue.accept(command("add", kind=ActionKind.ADD, quantity="5", limit="1.1000",
            stop="1.0900", target=position.position_id, version=position.version), now=at(20))
        quote = replace(market(2, bid="1.0700", ask="1.0702", seconds=25), available_at=at(30))
        result = venue.advance_market(quote)
        self.assertEqual((), result.positions)
        self.assertEqual((), result.open_command_ids)
        self.assertEqual(D("5"), venue.lookup(KEY, "add").receipt.quantities.filled)
        stops = [r for r in SQLiteVenue(self.path).receipt_history(KEY)
                 if r.reason_code == "VENUE_PROTECTIVE_STOP"]
        self.assertEqual(1, len(stops))
        self.assertEqual(D("15"), stops[0].quantities.filled)
        self.assertEqual(added.position_id, stops[0].position_id)
        self.assertEqual(at(30), stops[0].observed_at)

    def test_quote_before_later_amendment_cannot_trigger_that_amendment(self):
        venue = initialized(self.path)
        venue.accept(command(stop="1.0500"), now=START)
        first = replace(market(1, seconds=10), available_at=at(20))
        position = venue.advance_market(first).positions[0]
        amendment = command("protect", kind=ActionKind.AMEND_STOP, target=position.position_id,
                            version=position.version, stop="1.0900")
        venue.accept(amendment, now=at(30))
        old = replace(market(2, bid="1.0800", ask="1.0802", seconds=25), available_at=at(40))
        self.assertEqual(D("10"), venue.advance_market(old).positions[0].quantity)
        self.assertFalse(any(r.reason_code == "VENUE_PROTECTIVE_STOP" for r in venue.receipt_history(KEY)))
        current = replace(market(3, bid="1.0800", ask="1.0802", seconds=35), available_at=at(50))
        self.assertEqual((), venue.advance_market(current).positions)
        stop = next(r for r in venue.receipt_history(KEY) if r.reason_code == "VENUE_PROTECTIVE_STOP")
        self.assertEqual(at(50), stop.observed_at)

    def test_same_event_fill_does_not_bypass_a_newer_partial_position_amendment(self):
        venue = initialized(self.path, VenueScenario(order_plans=(("entry", OrderPlan((D("4"), D("6")))),)))
        venue.accept(command(stop="1.0500"), now=START)
        position = venue.advance_market(market(1, seconds=10)).positions[0]
        venue.accept(command("protect", kind=ActionKind.AMEND_STOP, target=position.position_id,
                             version=position.version, stop="1.0900"), now=at(20))
        # This quote is eligible for the old entry remainder but predates the amendment.
        delayed = replace(market(2, bid="1.0800", ask="1.0802", seconds=15), available_at=at(30))
        position = venue.advance_market(delayed).positions[0]
        self.assertEqual(D("10"), position.quantity)
        self.assertEqual(D("1.0900"), position.stop_price)
        self.assertFalse(any(r.reason_code == "VENUE_PROTECTIVE_STOP" for r in venue.receipt_history(KEY)))
        later = replace(market(3, bid="1.0800", ask="1.0802", seconds=25), available_at=at(40))
        self.assertEqual((), venue.advance_market(later).positions)

    def test_short_open_ceiling_preserves_quota_and_remainder_across_restart(self):
        venue = initialized(self.path, VenueScenario(order_plans=(("entry", OrderPlan((D("4"), D("6")))),)))
        accepted = venue.accept(command(side=Side.SELL, limit="1", ceiling="2"), now=START)
        high = venue.advance_market(market(1, bid="3", ask="3.0002"))
        self.assertEqual((), high.positions)
        self.assertEqual(("entry",), high.open_command_ids)
        self.assertEqual(accepted, venue.lookup(KEY, "entry").receipt)
        partial = venue.advance_market(market(2, bid="1.5", ask="1.5002"))
        self.assertEqual(D("4"), partial.positions[0].quantity)  # First quota was not consumed.
        last = venue.lookup(KEY, "entry").receipt
        self.assertEqual(D("6"), last.quantities.remaining)
        venue = SQLiteVenue(self.path)
        blocked = venue.advance_market(market(3, bid="3.1", ask="3.1002"))
        self.assertEqual(D("4"), blocked.positions[0].quantity)
        self.assertEqual(last, venue.lookup(KEY, "entry").receipt)
        final = venue.advance_market(market(4, bid="2", ask="2.0002"))
        self.assertEqual(D("10"), final.positions[0].quantity)
        self.assertEqual(D("1.8"), final.positions[0].entry_price)
        self.assertLessEqual(final.positions[0].quantity * final.positions[0].entry_price, D("20"))
        self.assertEqual(EffectState.FILLED, venue.lookup(KEY, "entry").receipt.effect)
        _, saved = self.checkpoint()
        fills = saved["state"]["commands"]["entry"]["fills"]
        self.assertEqual([D("1.5"), D("2")], [D(f["price"]) for f in fills])

    def test_short_add_ceiling_survives_partial_fill_and_restart(self):
        venue = initialized(self.path, VenueScenario(order_plans=(("add", OrderPlan((D("4"), D("6")))),)))
        venue.accept(command(side=Side.SELL, limit="1", ceiling="2"), now=START)
        position = venue.advance_market(market(1, bid="1.2", ask="1.2002")).positions[0]
        add = command("add", kind=ActionKind.ADD, quantity="10", limit="1", ceiling="2",
                      target=position.position_id, version=position.version)
        accepted = venue.accept(add, now=at(10))
        self.assertEqual(D("10"), venue.advance_market(market(2, bid="3", ask="3.0002")).positions[0].quantity)
        self.assertEqual(accepted, venue.lookup(KEY, "add").receipt)
        self.assertEqual(D("14"), venue.advance_market(market(3, bid="1.5", ask="1.5002")).positions[0].quantity)
        partial = venue.lookup(KEY, "add").receipt
        self.assertEqual(D("6"), partial.quantities.remaining)
        venue = SQLiteVenue(self.path)
        self.assertEqual(D("14"), venue.advance_market(market(4, bid="3", ask="3.0002")).positions[0].quantity)
        self.assertEqual(partial, venue.lookup(KEY, "add").receipt)
        self.assertEqual(D("20"), venue.advance_market(market(5, bid="2", ask="2.0002")).positions[0].quantity)
        _, saved = self.checkpoint()
        fills = saved["state"]["commands"]["add"]["fills"]
        self.assertEqual([D("4"), D("6")], [D(f["quantity"]) for f in fills])
        self.assertEqual([D("1.5"), D("2")], [D(f["price"]) for f in fills])
        self.assertLessEqual(sum(D(f["quantity"]) * D(f["price"]) for f in fills), D("20"))

    def test_buy_ceiling_blocks_actual_ask_without_clamping(self):
        venue = initialized(self.path)
        accepted = venue.accept(command(ceiling="2"), now=START)
        self.assertEqual((), venue.advance_market(market(1, bid="2", ask="2.0002")).positions)
        self.assertEqual(accepted, venue.lookup(KEY, "entry").receipt)
        final = venue.advance_market(market(2, bid="1.9998", ask="2"))
        self.assertEqual(D("2"), final.positions[0].entry_price)
        self.assertEqual(D("10"), final.positions[0].quantity)

    def test_missing_or_off_tick_ceiling_rejects_and_ceiling_rebinding_conflicts(self):
        venue = initialized(self.path)
        missing = venue.accept(command("missing", ceiling=None), now=START)
        self.assertEqual(EffectState.REJECTED, missing.effect)
        self.assertEqual("RISK_PRICE_CEILING_REQUIRED", missing.reason_code)
        self.assertEqual(D("10"), missing.quantities.rejected)
        invalid = venue.accept(command("off-tick", ceiling="2.00001"), now=START)
        self.assertEqual("INVALID_RISK_PRICE_CEILING_TICK", invalid.reason_code)
        original = venue.accept(command(ceiling="2"), now=START)
        with self.assertRaises(IdentityConflict):
            SQLiteVenue(self.path).accept(command(ceiling="3"), now=START)
        self.assertEqual(original, venue.accept(command(ceiling="2.00"), now=START))
        with self.assertRaises(IdentityConflict):
            venue.accept(command("missing", ceiling="2"), now=START)

    def test_historical_pending_without_ceiling_can_be_read_and_cancelled_but_not_filled(self):
        venue = initialized(self.path)
        accepted = venue.accept(command(), now=START)
        sequence, document = self.checkpoint()
        # Materialize the earlier optional-field storage format in an isolated fixture.
        # This is a real SQLite record, not a mocked lookup or success receipt.
        order = document["state"]["commands"]["entry"]
        order.pop("risk_price_ceiling")
        order["command"].pop("risk_price_ceiling")
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE checkpoints SET document=?, sha256=? WHERE sequence=?",
                (json.dumps(document, sort_keys=True, separators=(",", ":")), content_digest(document), sequence))
            connection.commit()
        finally:
            connection.close()
        venue = SQLiteVenue(self.path)
        self.assertEqual(accepted, venue.lookup(KEY, "entry").receipt)
        self.assertEqual((), venue.advance_market(market(1)).positions)
        self.assertEqual(accepted, venue.lookup(KEY, "entry").receipt)
        with self.assertRaises(IdentityConflict):
            venue.accept(command(), now=at(10))
        cancelled = venue.accept(command("cancel", kind=ActionKind.CANCEL_ORDER,
            target="entry", version=accepted.venue_sequence), now=at(10))
        self.assertEqual(EffectState.APPLIED, cancelled.effect)
        terminal = venue.lookup(KEY, "entry").receipt
        self.assertEqual(D("10"), terminal.quantities.cancelled)
        self.assertEqual(D("0"), terminal.quantities.filled)
