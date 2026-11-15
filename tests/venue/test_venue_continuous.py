"""One evolving venue trajectory; this is not integrated A or actual-model B proof."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cas_forex_revamp.contracts import ActionKind, ControlKind, EffectState
from cas_forex_revamp.venue import FaultSchedule, SimulatedInterruption, SQLiteVenue, VenueScenario
from .support import D, KEY, START, at, command, fence, initialized, market


class ContinuousVenueRehearsalTests(unittest.TestCase):
    def test_entry_uncertainty_pause_restart_partial_exit_stop_resume_close(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "continuous.venue.sqlite3"
            faults = FaultSchedule()
            venue = initialized(path, VenueScenario(fill_limit_per_order=D("4")), faults=faults)
            faults.arm("accept.after_commit")
            with self.assertRaises(SimulatedInterruption):
                venue.accept(command(), now=START)
            venue.advance_market(market(1))
            paused = venue.advance_fence(fence(ControlKind.PAUSE_NEW_RISK, 2, seconds=10), now=at(10))
            venue = SQLiteVenue(path)  # New independent process object; no implicit resume.
            observed = venue.snapshot(KEY, now=at(10))
            self.assertEqual(paused, observed.fence)
            self.assertEqual(D("4"), observed.positions[0].quantity)
            partial = venue.lookup(KEY, "entry").receipt
            cancel = command("cancel", generation=3, kind=ActionKind.CANCEL_ORDER,
                             target="entry", version=partial.venue_sequence)
            venue.accept(cancel, now=at(10))
            terminal = venue.lookup(KEY, "entry").receipt
            self.assertEqual(D("4"), terminal.quantities.filled)
            self.assertEqual(D("6"), terminal.quantities.cancelled)
            position = venue.snapshot(KEY, now=at(10)).positions[0]
            reduce = command("reduce", generation=3, kind=ActionKind.REDUCE, quantity="2",
                             target=position.position_id, version=position.version)
            venue.accept(reduce, now=at(10))
            after_reduce = venue.advance_market(market(2, bid="1.1050", ask="1.1052"))
            self.assertEqual(D("2"), after_reduce.positions[0].quantity)
            venue.advance_fence(fence(ControlKind.STOP_AUTOMATION, 3, seconds=20), now=at(20))
            stopped = venue.snapshot(KEY, now=at(20))
            self.assertEqual(D("2"), stopped.positions[0].quantity)
            self.assertFalse(stopped.fence.management_allowed)
            resumed = venue.advance_fence(fence(ControlKind.RESUME_MANAGEMENT, 4, seconds=20), now=at(20))
            self.assertFalse(resumed.new_risk_allowed)
            position = stopped.positions[0]
            close = command("close", generation=5, kind=ActionKind.CLOSE, quantity="2",
                            target=position.position_id, version=position.version)
            venue.accept(close, now=at(20))
            final = venue.advance_market(market(3, bid="1.1060", ask="1.1062"))
            self.assertEqual((), final.positions)
            self.assertEqual((), final.open_command_ids)
            self.assertEqual(EffectState.FILLED, venue.lookup(KEY, "close").receipt.effect)
            self.assertEqual(D("0.01"), final.realized_pnl.amount)  # floor(.0096) + floor(.0116)
            self.assertFalse(final.fence.new_risk_allowed)
            self.assertGreater(len(venue.inspect_journal(KEY)), 10)
