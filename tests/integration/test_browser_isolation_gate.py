"""AUTHORED/NOT_RUN. Pure receipt checks; no process, service or browser."""
import json
from hashlib import sha256
from datetime import datetime
import unittest
from approved_browser_stage import observed_isolation


class BrowserIsolationGateTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {'t0_utc': '2026-10-10T22:30:00Z', 'work_deadline_utc': '2026-10-11T02:10:00Z'}
        self.receipt = dict(observed_utc='2026-10-10T22:40:00Z', interfaces=['lo'],
            uid=1001, capabilities=0, host_paths_inaccessible=True, deadline_utc=self.cfg['work_deadline_utc'])
        self.now = datetime.fromisoformat('2026-10-10T22:41:00+00:00').timestamp()

    def call(self):
        return observed_isolation(json.dumps(self.receipt).encode(), self.cfg, uid=1001, now=self.now)

    def test_actual_observation_hash_is_bound(self):
        self.assertEqual(self.call(), sha256(json.dumps(self.receipt).encode()).hexdigest())

    def test_future_or_previous_run_observation_rejected(self):
        for at in ('2026-10-10T22:42:00Z', '2026-10-10T22:29:00Z'):
            self.receipt['observed_utc'] = at
            with self.assertRaises(RuntimeError): self.call()

    def test_wrong_uid_network_or_deadline_rejected(self):
        for key, value in [('uid', 0), ('interfaces', ['lo', 'eth0']), ('deadline_utc', '2026-10-11T03:10:00Z')]:
            original = self.receipt[key]; self.receipt[key] = value
            with self.assertRaises(RuntimeError): self.call()
            self.receipt[key] = original

    def test_false_is_not_a_capability_count(self):
        self.receipt['capabilities'] = False
        with self.assertRaises(RuntimeError): self.call()
