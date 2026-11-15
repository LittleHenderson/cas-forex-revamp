"""Concrete lane construction check, authored and NOT_RUN."""

from decimal import Decimal
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from cas_forex_revamp.composition import RuntimeConfig
from cas_forex_revamp.composition.assembly import assemble_inert_simulation
from cas_forex_revamp.composition.synthetic_fixture import continuous_a_fixture
from cas_forex_revamp.core import InstrumentPolicy, RiskPolicy


class ConcreteAssemblyTests(TestCase):
    def test_attaching_real_lanes_does_not_initialize_or_call_clock_or_adapter(self):
        fixture = continuous_a_fixture()
        config = RuntimeConfig(fixture.scope, Path.cwd() / "must-not-be-created")
        clock = Mock()
        adapter = Mock()
        with patch("sqlite3.connect", side_effect=AssertionError("unexpected database")), \
             patch("pathlib.Path.mkdir", side_effect=AssertionError("unexpected directory")), \
             patch("socket.socket", side_effect=AssertionError("unexpected network")), \
             patch("subprocess.Popen", side_effect=AssertionError("unexpected subprocess")), \
             patch("threading.Thread.start", side_effect=AssertionError("unexpected worker")):
            assembled = assemble_inert_simulation(
                config, policy=RiskPolicy("USD", Decimal("100000")),
                instruments=(InstrumentPolicy(fixture.instruments[0], Decimal("2")),),
                decision_adapter=adapter, clock=clock,
            )
        self.assertFalse(assembled.initialization_performed_by_composition)
        self.assertFalse(assembled.workers_started_by_composition)
        self.assertFalse(assembled.initial_projection.admissions_enabled)
        self.assertIsNone(assembled.initial_projection.positions)
        self.assertNotEqual(assembled.core_path, assembled.venue_path)
        self.assertIsNone(assembled.core.owner_verifier)
        clock.assert_not_called()
        self.assertEqual(adapter.mock_calls, [])
