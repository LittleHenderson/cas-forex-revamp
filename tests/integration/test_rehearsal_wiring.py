"""Authored integration boundaries. NOT_RUN until the approved compute route."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock

from cas_forex_revamp.composition import RuntimeConfig
from cas_forex_revamp.composition.rehearsal import RehearsalWiring
from cas_forex_revamp.contracts import (
    ContractError, ControlKind, DecisionOrigin, FenceReceipt, FenceRequest, RunScope,
)


class RehearsalWiringTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 10, 20, 0, tzinfo=timezone.utc)
        self.scope = RunScope("synthetic-1", "continuous-a-1", 1,
                              "build-a-1", "policy-a-1", "scenario-a-1", "venue-a-1")
        self.core = Mock()
        self.venue = Mock()
        self.operator = Mock()
        self.clock = Mock(return_value=self.now)
        self.config = RuntimeConfig(self.scope, Path.cwd() / "synthetic-unused")
        self.wiring = RehearsalWiring(self.config, core=self.core, state_reader=self.core,
                                     venue=self.venue, operator=self.operator, clock=self.clock)

    def test_construction_calls_no_port_or_clock(self):
        for dependency in (self.core, self.venue, self.operator, self.clock):
            self.assertEqual(dependency.mock_calls, [])

    def test_outbox_failure_is_not_retried(self):
        self.core.dispatch_next.side_effect = OSError("reply unavailable")
        with self.assertRaises(OSError):
            self.wiring.dispatch_once()
        self.core.dispatch_next.assert_called_once_with(self.scope.key, now=self.now)
        self.venue.accept.assert_not_called()

    def test_later_resume_cannot_confirm_an_earlier_pause(self):
        request = FenceRequest(self.scope.key, "pause-1", ControlKind.PAUSE_NEW_RISK,
                               "owner-1", 1, 2, self.now)
        returned = FenceReceipt(self.scope.key, "pause-1", 2, False, True, 4, self.now, True)
        newer = FenceReceipt(self.scope.key, "resume-2", 3, True, True, 5,
                             self.now + timedelta(seconds=1), True)
        self.core.control.return_value = returned
        self.venue.snapshot.return_value = Mock(fence=newer)
        observation = self.wiring.control(request)
        self.assertFalse(observation.confirmed)
        self.assertEqual(observation.observed, newer)
        self.core.control.assert_called_once()

    def test_wrong_run_control_cannot_reach_core(self):
        other = RunScope("synthetic-2", "continuous-a-1", 1,
                         "build-a-1", "policy-a-1", "scenario-a-1", "venue-a-1")
        request = FenceRequest(other.key, "pause-1", ControlKind.PAUSE_NEW_RISK,
                               "owner-1", 1, 2, self.now)
        with self.assertRaises(ContractError):
            self.wiring.control(request)
        self.core.control.assert_not_called()

    def test_replay_cannot_impersonate_required_actual_model_branch(self):
        with self.assertRaises(ContractError):
            RehearsalWiring(self.config, core=self.core, state_reader=self.core,
                            venue=self.venue, operator=self.operator, clock=self.clock,
                            expected_origin=DecisionOrigin.REPLAY)
