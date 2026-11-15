"""Actual SQLite/process failure schedules, authored but NOT_RUN."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import multiprocessing
from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
import sqlite3
from threading import Barrier
import unittest

from cas_forex_revamp.contracts import ActionKind, ControlKind, EffectState, LookupState, Money
from cas_forex_revamp.venue import (
    FaultSchedule, SimulatedInterruption, SQLiteVenue, VenueScenario, VenueStorageError,
)
from .support import D, INSTRUMENT, KEY, START, at, command, crash_child, fence, initialized, market


class VenueRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "account.venue.sqlite3"

    def test_lost_accept_ack_unknown_read_and_restart_preserve_committed_truth(self):
        faults = FaultSchedule()
        venue = initialized(self.path, faults=faults)
        faults.arm("accept.after_commit")
        with self.assertRaises(SimulatedInterruption):
            venue.accept(command(), now=START)
        faults.arm("lookup.unavailable")
        uncertain = venue.lookup(KEY, "entry")
        self.assertEqual(LookupState.UNKNOWN, uncertain.state)
        self.assertIsNone(uncertain.receipt)
        self.assertIsNone(uncertain.observed_sequence)
        recovered = SQLiteVenue(self.path)
        readback = recovered.lookup(KEY, "entry")
        self.assertEqual(LookupState.FOUND, readback.state)
        self.assertEqual(EffectState.ACKNOWLEDGED, readback.receipt.effect)
        before = recovered.snapshot(KEY, now=START).sequence
        self.assertEqual(readback.receipt, recovered.accept(command(), now=START))
        self.assertEqual(before, recovered.snapshot(KEY, now=START).sequence)
        self.assertEqual(D("10"), recovered.advance_market(market(1)).positions[0].quantity)

    def test_before_commit_rolls_back_every_effect_and_identity(self):
        faults = FaultSchedule()
        venue = initialized(self.path, faults=faults)
        before = venue.snapshot(KEY, now=START)
        faults.arm("accept.before_commit")
        with self.assertRaises(SimulatedInterruption):
            venue.accept(command(), now=START)
        recovered = SQLiteVenue(self.path)
        self.assertEqual(LookupState.NOT_FOUND, recovered.lookup(KEY, "entry").state)
        self.assertEqual(before, recovered.snapshot(KEY, now=START))
        self.assertEqual(EffectState.ACKNOWLEDGED, recovered.accept(command(), now=START).effect)

    def test_lost_fill_reply_is_not_a_second_fill_on_replay(self):
        faults = FaultSchedule()
        venue = initialized(self.path, faults=faults)
        venue.accept(command(), now=START)
        faults.arm("advance_market.after_commit")
        with self.assertRaises(SimulatedInterruption):
            venue.advance_market(market(1))
        recovered = SQLiteVenue(self.path)
        complete = recovered.lookup(KEY, "entry").receipt
        self.assertEqual(D("10"), complete.quantities.filled)
        replay = recovered.advance_market(market(1))
        self.assertEqual(D("10"), replay.positions[0].quantity)
        self.assertEqual(2, len(recovered.receipt_history(KEY, "entry")))

    def test_cancel_atomicity_under_before_and_after_commit_interruptions(self):
        faults = FaultSchedule()
        venue = initialized(self.path, VenueScenario(fill_limit_per_order=D("4")), faults=faults)
        venue.accept(command(), now=START)
        venue.advance_market(market(1))
        partial = venue.lookup(KEY, "entry").receipt
        cancel = command("cancel", kind=ActionKind.CANCEL_ORDER, target="entry", version=partial.venue_sequence)
        faults.arm("accept.before_commit")
        with self.assertRaises(SimulatedInterruption):
            venue.accept(cancel, now=at(10))
        self.assertEqual(partial, venue.lookup(KEY, "entry").receipt)
        self.assertEqual(LookupState.NOT_FOUND, venue.lookup(KEY, "cancel").state)
        faults.arm("accept.after_commit")
        with self.assertRaises(SimulatedInterruption):
            venue.accept(cancel, now=at(10))
        recovered = SQLiteVenue(self.path)
        self.assertEqual(EffectState.APPLIED, recovered.lookup(KEY, "cancel").receipt.effect)
        original = recovered.lookup(KEY, "entry").receipt
        self.assertEqual(D("4"), original.quantities.filled)
        self.assertEqual(D("6"), original.quantities.cancelled)
        self.assertEqual(EffectState.CANCELLED, original.effect)

    def test_lost_fence_reply_requires_independent_matching_readback(self):
        faults = FaultSchedule()
        venue = initialized(self.path, faults=faults)
        request = fence(ControlKind.PAUSE_NEW_RISK, 2)
        faults.arm("advance_fence.after_commit")
        with self.assertRaises(SimulatedInterruption):
            venue.advance_fence(request, now=START)
        observed = SQLiteVenue(self.path).snapshot(KEY, now=START).fence
        self.assertEqual(request.barrier_id, observed.barrier_id)
        self.assertEqual(request.next_generation, observed.generation)
        self.assertTrue(observed.applied)
        self.assertFalse(observed.new_risk_allowed)
        self.assertTrue(observed.management_allowed)
        self.assertEqual(observed, venue.advance_fence(request, now=START))

    def test_real_sqlite_write_rejection_rolls_back_without_not_found_fabrication(self):
        venue = initialized(self.path)
        before = venue.snapshot(KEY, now=START)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE TRIGGER deny_checkpoint BEFORE INSERT ON checkpoints "
                               "BEGIN SELECT RAISE(ABORT, 'deliberate write rejection'); END")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(VenueStorageError):
            venue.accept(command(), now=START)
        self.assertEqual(before, venue.snapshot(KEY, now=START))
        self.assertEqual(LookupState.NOT_FOUND, venue.lookup(KEY, "entry").state)
        # This is a real SQLite write error, explicitly not a physical disk-full claim.

    def test_real_exclusive_lock_read_failure_never_becomes_empty_or_not_found(self):
        venue = initialized(self.path)
        writer = sqlite3.connect(self.path)
        try:
            writer.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(VenueStorageError):
                venue.lookup(KEY, "absent")
            with self.assertRaises(VenueStorageError):
                venue.snapshot(KEY, now=START)
        finally:
            writer.rollback()
            writer.close()
        self.assertEqual(LookupState.NOT_FOUND, venue.lookup(KEY, "absent").state)

    def test_missing_corrupt_incompatible_and_reinitialization_fail_closed(self):
        missing = SQLiteVenue(self.path)
        with self.assertRaises(VenueStorageError):
            missing.lookup(KEY, "entry")
        self.assertFalse(self.path.exists())
        self.path.write_bytes(b"not a sqlite database")
        with self.assertRaises(VenueStorageError):
            missing.snapshot(KEY, now=START)
        with self.assertRaises(VenueStorageError):
            missing.initialize(KEY, opening_balance=Money(D("100"), "USD"), instruments=(INSTRUMENT,), now=START)
        self.assertEqual(b"not a sqlite database", self.path.read_bytes())
        foreign = Path(self.directory.name) / "core-renamed.venue.sqlite3"
        connection = sqlite3.connect(foreign)
        connection.execute("CREATE TABLE core_commands(id TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaises(VenueStorageError):
            SQLiteVenue(foreign).lookup(KEY, "entry")

    def test_checkpoint_corruption_is_detected_and_preserved(self):
        venue = initialized(self.path)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE checkpoints SET document = '{}' WHERE sequence = (SELECT MAX(sequence) FROM checkpoints)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(VenueStorageError):
            venue.lookup(KEY, "entry")
        with self.assertRaises(VenueStorageError):
            venue.accept(command(), now=START)

    def test_complete_file_rollback_is_detected_with_independent_cursor_or_anchor(self):
        venue = initialized(self.path)
        stale = Path(self.directory.name) / "stale.venue.sqlite3"
        shutil.copyfile(self.path, stale)  # Deliberate isolated stale backup fixture.
        venue.accept(command(), now=START)
        venue.advance_market(market(1))
        snapshot = venue.snapshot(KEY, now=at(10))
        anchor = venue.inspect_journal(KEY)[-1]
        with self.assertRaises(VenueStorageError):
            SQLiteVenue(stale, minimum_sequence=snapshot.sequence).snapshot(KEY, now=at(10))
        with self.assertRaises(VenueStorageError):
            SQLiteVenue(stale, checkpoint_anchor=anchor).lookup(KEY, "entry")
        self.assertEqual(LookupState.FOUND, SQLiteVenue(self.path, checkpoint_anchor=anchor).lookup(KEY, "entry").state)
        # Without an independently held floor/anchor, a self-consistent old file is
        # indistinguishable from its genuine earlier state. No stronger claim is made.

    def test_simultaneous_duplicate_submission_commits_one_identity(self):
        initialized(self.path)
        barrier = Barrier(4)
        def submit(_):
            barrier.wait(timeout=5)
            return SQLiteVenue(self.path).accept(command(), now=START)
        with ThreadPoolExecutor(max_workers=4) as pool:
            receipts = list(pool.map(submit, range(4)))
        self.assertTrue(all(r == receipts[0] for r in receipts))
        self.assertEqual(1, len(SQLiteVenue(self.path).receipt_history(KEY)))

    def test_concurrent_close_reservations_do_not_reverse_position(self):
        venue = initialized(self.path)
        venue.accept(command(), now=START)
        position = venue.advance_market(market(1)).positions[0]
        barrier = Barrier(2)
        def close(name):
            barrier.wait(timeout=5)
            request = command(name, kind=ActionKind.CLOSE, target=position.position_id, version=position.version)
            return SQLiteVenue(self.path).accept(request, now=at(10))
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(close, ("close-one", "close-two")))
        self.assertEqual(1, sum(r.effect is EffectState.ACKNOWLEDGED for r in receipts))
        self.assertEqual(1, sum(r.reason_code == "TARGET_BUSY" for r in receipts))
        self.assertEqual((), venue.advance_market(market(2)).positions)

    def test_accept_and_pause_race_has_a_serialized_result(self):
        venue = initialized(self.path)
        barrier = Barrier(2)
        def submit():
            barrier.wait(timeout=5)
            return SQLiteVenue(self.path).accept(command(), now=START)
        def pause():
            barrier.wait(timeout=5)
            return SQLiteVenue(self.path).advance_fence(fence(ControlKind.PAUSE_NEW_RISK, 2), now=START)
        with ThreadPoolExecutor(max_workers=2) as pool:
            submitted, paused = pool.submit(submit), pool.submit(pause)
            receipt, control = submitted.result(), paused.result()
        self.assertTrue(control.applied)
        if receipt.effect is EffectState.ACKNOWLEDGED:
            self.assertLess(receipt.venue_sequence, control.venue_sequence)
        else:
            self.assertEqual("STALE_DISPATCH_GENERATION", receipt.reason_code)
            self.assertGreater(receipt.venue_sequence, control.venue_sequence)
        late = venue.accept(command("released-old-writer"), now=START)
        self.assertEqual("STALE_DISPATCH_GENERATION", late.reason_code)

    def runKilledChild(self, operation, argument, now, boundary):
        process = multiprocessing.get_context("spawn").Process(
            target=crash_child, args=(str(self.path), operation, argument, now, boundary))
        process.start()
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            self.fail("isolated crash fixture exceeded its process bound")
        self.assertEqual(73, process.exitcode)

    def test_process_death_before_accept_commit_leaves_no_identity(self):
        initialized(self.path)
        self.runKilledChild("accept", command(), START, "accept.before_commit")
        readback = SQLiteVenue(self.path).lookup(KEY, "entry")
        self.assertEqual(LookupState.NOT_FOUND, readback.state)

    def test_process_death_after_accept_commit_preserves_identity(self):
        initialized(self.path)
        self.runKilledChild("accept", command(), START, "accept.after_commit")
        recovered = SQLiteVenue(self.path)
        self.assertEqual(EffectState.ACKNOWLEDGED, recovered.lookup(KEY, "entry").receipt.effect)
        self.assertEqual(D("10"), recovered.advance_market(market(1)).positions[0].quantity)

    def test_process_death_before_market_commit_rolls_back_position_and_receipt(self):
        venue = initialized(self.path)
        accepted = venue.accept(command(), now=START)
        self.runKilledChild("advance_market", market(1), at(10), "advance_market.before_commit")
        recovered = SQLiteVenue(self.path)
        self.assertEqual(accepted, recovered.lookup(KEY, "entry").receipt)
        self.assertEqual((), recovered.snapshot(KEY, now=START).positions)

    def test_process_death_after_market_commit_preserves_fill_without_core(self):
        venue = initialized(self.path)
        venue.accept(command(), now=START)
        self.runKilledChild("advance_market", market(1), at(10), "advance_market.after_commit")
        recovered = SQLiteVenue(self.path)
        self.assertEqual(EffectState.FILLED, recovered.lookup(KEY, "entry").receipt.effect)
        self.assertEqual(D("10"), recovered.snapshot(KEY, now=at(10)).positions[0].quantity)
        self.assertEqual(D("10"), recovered.advance_market(market(1)).positions[0].quantity)

    def test_corrupted_earlier_checkpoint_blocks_current_reads_and_writes(self):
        venue = initialized(self.path)
        venue.accept(command(), now=START)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE checkpoints SET document = '{}' WHERE sequence = 1")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(VenueStorageError):
            venue.lookup(KEY, "entry")
        with self.assertRaises(VenueStorageError):
            venue.accept(command("later"), now=START)
