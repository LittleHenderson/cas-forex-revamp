"""Authored composition check; execution remains NOT_RUN pending approved compute."""

from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from cas_forex_revamp.composition import RuntimeConfig, compose_inert
from cas_forex_revamp.contracts import ManagementPermission, NewRiskPermission, RunScope


class InertCompositionTests(TestCase):
    def test_composition_starts_nothing_and_invents_no_account_state(self):
        # Use an explicit path only; the directory is intentionally never created.
        config = RuntimeConfig(RunScope("account-1", "run-1", 1, "build-1", "policy-1", "scenario-1", "venue-1"),
                               Path.cwd() / "must-not-be-created")
        with patch("builtins.open", side_effect=AssertionError("unexpected file IO")), \
             patch("pathlib.Path.mkdir", side_effect=AssertionError("unexpected mkdir")), \
             patch("socket.socket", side_effect=AssertionError("unexpected socket")), \
             patch("subprocess.Popen", side_effect=AssertionError("unexpected subprocess")), \
             patch("threading.Thread.start", side_effect=AssertionError("unexpected worker")):
            app = compose_inert(config)
        self.assertFalse(app.workers_started)
        self.assertFalse(app.core_attached or app.venue_attached or app.operator_attached)
        self.assertFalse(app.initial_projection.admissions_enabled)
        self.assertEqual(app.initial_projection.permissions.new_risk, NewRiskPermission.UNKNOWN)
        self.assertEqual(app.initial_projection.permissions.management, ManagementPermission.UNKNOWN)
        self.assertIsNone(app.initial_projection.balance)
        self.assertIsNone(app.initial_projection.positions)
