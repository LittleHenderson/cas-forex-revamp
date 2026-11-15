"""AUTHORED/NOT_RUN. Tiny synthetic receipt reservations; zero HTTP/model calls."""
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from cas_forex_revamp.contracts import ContractError,RunScope
from cas_forex_revamp.composition.r6_budget import ModelWindow,SharedBudgetModelStore
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from r6_development_fixture import Clock


class SharedBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.clock=Clock();self.elapsed=[0]
        self.window=ModelWindow(absolute_deadline=self.clock()+timedelta(hours=4),clock=self.clock,monotonic=lambda:self.elapsed[0])
        self.scope=RunScope('development','development-run',1,'dev','dev','dev','dev')
        self.journal=EvidenceJournal(self.root/'anchor.evidence.sqlite3',self.scope.key);self.journal.initialize(create=True)
        self.store=SharedBudgetModelStore(self.root/'model.model-evidence.sqlite3',run_id='development-run',deadline=self.window.end)
        self.store.bind_window(self.window);self.store.bind_journal(self.journal,self.scope,self.clock)
        self.store.initialize(create=True);self.store.retain_window(now=self.clock())

    def reserve(self,index,phase='probe',operation='generation'):
        return self.store.begin_http(phase=phase,operation=operation,invocation_sha256=f'{index:064x}',
            body_sha256='b'*64,timeout_seconds=60 if phase=='probe' else 120,now=self.clock())

    def test_acceptance_cannot_skip_probes(self):
        with self.assertRaises(ContractError):self.reserve(1,'acceptance')

    def test_two_plus_thirty_share_total_limit(self):
        self.reserve(1);self.reserve(2)
        for i in range(3,33):self.reserve(i,'acceptance')
        with self.assertRaises(ContractError):self.reserve(33,'acceptance')
        self.assertEqual(sum(x['kind']=='MODEL_HTTP_ATTEMPT' for x in self.store.records()),32)

    def test_unknown_spent_attempt_cannot_retry(self):
        self.reserve(1)
        with self.assertRaises(ContractError):self.reserve(1)

    def test_phase_switch_cannot_reuse_identity(self):
        self.reserve(1);self.reserve(2)
        with self.assertRaises(ContractError):self.reserve(1,'acceptance')

    def test_monotonic_expiry_cannot_be_hidden_by_wall_clock(self):
        self.elapsed[0]=5390
        with self.assertRaises(ContractError):self.reserve(1)

    def test_backward_wall_clock_rejected(self):
        self.clock.advance(-1)
        with self.assertRaises(ContractError):self.reserve(1)

    def test_reopen_requires_same_original_window_and_checkpoint(self):
        self.reserve(1);checkpoint=self.store.checkpoint()
        new=SharedBudgetModelStore(self.store.path,run_id='development-run',deadline=self.window.end)
        new.bind_window(self.window);new.bind_journal(self.journal,self.scope,self.clock)
        new.initialize(expected_checkpoint=checkpoint)
        with self.assertRaises(ContractError):
            new.begin_http(phase='probe',operation='generation',invocation_sha256=f'{1:064x}',body_sha256='b'*64,timeout_seconds=60,now=self.clock())

    def test_render_spends_time_but_not_generation_count(self):
        self.reserve(1,operation='render');self.reserve(1)
        self.assertEqual(sum(x['kind']=='MODEL_HTTP_ATTEMPT' and x['payload']['operation']=='generation' for x in self.store.records()),1)
