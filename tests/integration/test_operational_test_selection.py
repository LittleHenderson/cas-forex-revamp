"""Future tests of complete group selection and the original clock. NOT_RUN."""
from datetime import datetime, timezone
import unittest
from operational_test_group import exact_json, original_test_deadline, require_complete


class OperationalTestSelection(unittest.TestCase):
    def clock(self):
        return {'model_window': {}, 'model_calls': 0, 'retry_calls': 0,
                'bootstrap_started_utc': '2030-01-01T00:00:00Z',
                'test_deadline_utc': '2030-01-01T02:00:00Z'}

    def test_subset_and_duplicate_cannot_pass_frozen_inventory(self):
        for actual in (['a'], ['a', 'b', 'b'], ['a', 'b', 'extra']):
            with self.assertRaises(RuntimeError): require_complete(actual, ['a', 'b'])

    def test_order_does_not_hide_or_add_test_ids(self):
        require_complete(['b', 'a'], ['a', 'b'])

    def test_test_window_cannot_restart_at_subprocess_start(self):
        record = self.clock()
        record['test_deadline_utc'] = '2030-01-01T02:00:01Z'
        with self.assertRaises(RuntimeError):
            original_test_deadline(record, now=datetime(2030, 1, 1, 1, tzinfo=timezone.utc))

    def test_deadline_is_exclusive(self):
        with self.assertRaises(RuntimeError):
            original_test_deadline(self.clock(), now=datetime(2030, 1, 1, 2, tzinfo=timezone.utc))

    def test_duplicate_clock_field_cannot_override_original(self):
        with self.assertRaises(RuntimeError): exact_json(b'{"test_deadline_utc":"a","test_deadline_utc":"b"}')
