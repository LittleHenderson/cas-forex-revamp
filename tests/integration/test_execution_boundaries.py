"""Approved-route tests of combined bootstrap/test time and child environment."""
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from approved_test_driver import stage_a_deadline


class ExecutionBudgets(unittest.TestCase):
    def config(self):
        return dict(t0_utc='2026-10-10T21:00:00Z', work_deadline_utc='2026-10-11T00:40:00Z',
                    bootstrap_started_utc='2026-10-10T21:12:00Z', stage_a_deadline_utc='2026-10-10T23:12:00Z')

    def test_original_bootstrap_start_limits_later_test_stage(self):
        self.assertEqual(stage_a_deadline(self.config()),
                         datetime(2026, 10, 10, 23, 12, tzinfo=timezone.utc).timestamp())

    def test_fresh_120_minutes_at_test_start_cannot_extend_bootstrap_budget(self):
        cfg = self.config()
        cfg['stage_a_deadline_utc'] = '2026-10-10T23:12:01Z'
        with self.assertRaises(RuntimeError):
            stage_a_deadline(cfg)

    def test_late_bootstrap_cannot_extend_global_window(self):
        cfg = self.config()
        cfg['bootstrap_started_utc'] = '2026-10-10T23:00:00Z'
        cfg['stage_a_deadline_utc'] = '2026-10-11T01:00:00Z'
        with self.assertRaises(RuntimeError):
            stage_a_deadline(cfg)

    def test_missing_original_bootstrap_timestamp_fails_closed(self):
        cfg = self.config()
        del cfg['bootstrap_started_utc']
        with self.assertRaises(KeyError):
            stage_a_deadline(cfg)
