"""Actual durable/process acceptance tests, authored and NOT_RUN."""

from dataclasses import replace
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase

from cas_forex_revamp.composition.continuous_driver import (
    SyntheticClock, _assemble, prepare_phase, resume_phase, run_two_processes,
)
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from cas_forex_revamp.composition.synthetic_fixture import continuous_a_fixture
from cas_forex_revamp.contracts import CommandState, ContractError, EffectState


class DurableContinuousTests(TestCase):
    def test_one_continuous_ledger_across_two_real_python_processes(self):
        with TemporaryDirectory() as directory:
            result = run_two_processes(Path(directory).resolve())
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(len(result['checks']), 16)
            self.assertEqual(result['scope']['epoch'], 2)
            self.assertFalse(result['actual_model'])

    def test_process_death_after_venue_commit_retains_effect_and_reservation(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            child = subprocess.run([sys.executable, '-m',
                                    'cas_forex_revamp.composition.continuous_driver',
                                    'kill-after-accept', str(root)], timeout=60,
                                   capture_output=True, text=True)
            self.assertEqual(child.returncode, 73, child.stderr)
            fixture = continuous_a_fixture()
            clock = SyntheticClock(fixture.market[0].available_at)
            app, _, _ = _assemble(root, replace(fixture.scope, epoch=2), clock)
            app.core.initialize()
            before = app.core.read_snapshot(fixture.scope.key).commands[0]
            self.assertEqual(before.state, CommandState.SUBMITTED)
            self.assertTrue(before.reservation_held)
            receipt = app.venue.lookup(fixture.scope.key, fixture.entry_command_id).receipt
            self.assertEqual(receipt.effect, EffectState.ACKNOWLEDGED)
            app.wiring.observe()
            self.assertIsNone(app.wiring.dispatch_once())
            self.assertEqual(len(app.venue.receipt_history(fixture.scope.key, fixture.entry_command_id)), 1)

    def test_missing_core_on_restart_is_not_created(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prepare_phase(root)
            core_path = root / 'account.core.sqlite3'
            # Rename only the test's newly-created temporary store; never old sources.
            core_path.rename(root / 'held.core.sqlite3')
            with self.assertRaises((sqlite3.Error, ContractError, RuntimeError)):
                resume_phase(root)
            self.assertFalse(core_path.exists())

    def test_existing_evidence_file_is_never_overwritten_by_create(self):
        with TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'account.evidence.sqlite3'
            path.write_bytes(b'corrupt-preserved-fixture')
            journal = EvidenceJournal(path, continuous_a_fixture().scope.key)
            with self.assertRaises(FileExistsError):
                journal.initialize(create=True)
            self.assertEqual(path.read_bytes(), b'corrupt-preserved-fixture')
