"""Actual separate-store source tests. All await the approved execution route."""
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.contracts import (ContractError, ControlKind, content_digest)
from cas_forex_revamp.composition.continuous_driver import (_assemble, _control, _propose, _admit, SyntheticClock)
from cas_forex_revamp.composition.read_service import DecisionReadService, read_scope
from cas_forex_revamp.composition.ui_service import ScopedUIService
from cas_forex_revamp.composition.synthetic_fixture import continuous_a_fixture
from cas_forex_revamp.rpa.read_binding import bind_decision_read


class ReadAndUIIntegration(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fixture = continuous_a_fixture()
        self.clock = SyntheticClock(self.fixture.started_at)
        self.app, self.owner, self.journal = _assemble(self.root, self.fixture.scope, self.clock)
        self.journal.initialize(create=True)
        self.app.venue.initialize(self.fixture.scope.key, opening_balance=self.fixture.opening_balance,
            instruments=self.fixture.instruments, now=self.clock(), scenario=self.fixture.venue_scenario)
        self.app.core.initialize(create=True)
        self.clock.now = self.fixture.market[0].available_at
        self.app.wiring.advance_market(self.fixture.market[0])
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.STOP_AUTOMATION, 'test-start-stop')
        schema = (Path(__file__).resolve().parents[2] / 'docs/contracts/decision-read.schema.json').read_bytes()
        self.reader = DecisionReadService(scope=self.fixture.scope, core=self.app.core, venue=self.app.venue,
            journal=self.journal, clock=self.clock, schema_bytes=schema, schema_sha256=sha256(schema).hexdigest(),
            instruments=self.fixture.instruments)
        self.service = ScopedUIService(app=self.app, owner=self.owner, journal=self.journal,
                                       reader=self.reader, clock=self.clock)

    def _proposal(self):
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.RESUME_NEW_RISK, 'test-resume')
        return _propose(self.app, self.journal, self.clock, 'test-decision')

    def _open(self):
        proposal = self._proposal()
        _admit(self.app, self.journal, self.clock, proposal, self.fixture.entry_command_id)
        self.app.wiring.dispatch_once()
        for quote in self.fixture.market[1:3]:
            self.clock.now = quote.available_at
            self.app.wiring.advance_market(quote)
        return self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).positions[0]

    def test_reads_do_not_change_any_durable_prefix(self):
        before = (self.app.core.read_snapshot(self.fixture.scope.key), self.app.venue.inspect_journal(self.fixture.scope.key), self.journal.records())
        self.service.readBoot()
        self.service.readCockpit()
        self.service.readDecisionRead()
        after = (self.app.core.read_snapshot(self.fixture.scope.key), self.app.venue.inspect_journal(self.fixture.scope.key), self.journal.records())
        self.assertEqual(before, after)

    def test_actual_scripted_decision_binds_exact_catalog(self):
        self._proposal()
        bundle = self.reader.read()
        anchor_id = bundle['anchor']['anchor_id']
        result = bind_decision_read(json.dumps(bundle['envelope']), now=self.clock(),
            expected_scope_sha256=content_digest(read_scope(self.fixture.scope)), schema_sha256=self.reader.schema_sha256,
            schema_validator=self.reader.validator, anchor_reader=lambda: self.reader.anchor(anchor_id),
            semantic_validator=self.reader.validate_bound)
        self.assertTrue(result.source_bound)
        self.assertEqual(bundle['envelope']['decisions'][0]['origin']['kind'], 'scripted')
        reference = bundle['envelope']['decisions'][0]['status_event_ref']
        record = self.service.resolveEvidence(dict(anchor_id=anchor_id, reference=reference))
        self.assertEqual(content_digest(record['record']), reference['record_sha256'])

    def test_rehashed_import_cannot_replace_retained_producer_read(self):
        bundle = self.reader.read()
        envelope = bundle['envelope']
        envelope['coverage']['reasons'].append('forged')
        envelope['domain_digest'] = content_digest({k: v for k, v in envelope.items() if k != 'domain_digest'})
        with self.assertRaises(ContractError):
            self.reader.validate_bound(envelope, self.reader.anchor(bundle['anchor']['anchor_id']))

    def test_catalog_rejects_changed_version_and_expiry(self):
        bundle = self.reader.read()
        reference = dict(bundle['envelope']['current_state']['permissions']['fence_ref'])
        reference['record_version'] += 1
        with self.assertRaises(ContractError):
            self.reader.resolve(bundle['anchor']['anchor_id'], reference)
        self.clock.now += timedelta(seconds=16)
        with self.assertRaises(ContractError):
            self.reader.anchor(bundle['anchor']['anchor_id'])

    def test_venue_change_without_reconcile_invalidates_current_claim(self):
        self.clock.now = self.fixture.market[1].available_at
        self.app.venue.advance_market(self.fixture.market[1])
        bundle = self.reader.read()
        self.assertFalse(bundle['anchor']['reconciliation_confirmed'])
        self.assertEqual(bundle['envelope']['current_state']['permissions']['new_risk'], 'UNKNOWN')
        self.assertIsNone(self.service.readCockpit()['positions'])

    def test_control_prepare_grants_nothing_and_exact_read_confirms(self):
        before = self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).fence
        request = self.service.prepareControl(dict(request_id='owner-pause', scope=self.service.readBoot()['scope'],
            control='PAUSE_NEW_RISK', expected_generation=before.generation))
        self.assertEqual(self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).fence, before)
        outcome = self.service.requestControl(request)
        receipt = self.service.readControl(request)
        self.assertEqual(outcome['status'], 'ACCEPTED')
        self.assertEqual(receipt['barrier_id'], request['barrier_id'])
        self.assertEqual(receipt['generation'], request['next_generation'])
        sequence = self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).sequence
        self.assertEqual(self.service.requestControl(request), outcome)
        self.assertEqual(sequence, self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).sequence)

    def test_unprepared_control_and_wrong_scope_rejected(self):
        boot = self.service.readBoot()
        request = self.service.prepareControl(dict(request_id='owner-stop', scope=boot['scope'],
            control='STOP_AUTOMATION', expected_generation=boot['fence_generation']))
        request['barrier_id'] = 'forged-barrier'
        with self.assertRaises(ContractError):
            self.service.requestControl(request)
        boot['scope']['epoch'] += 1
        with self.assertRaises(ContractError):
            self.service.prepareControl(dict(request_id='wrong', scope=boot['scope'],
                control='STOP_AUTOMATION', expected_generation=1))

    def test_lost_response_attempt_is_not_resubmitted(self):
        boot = self.service.readBoot()
        request = self.service.prepareControl(dict(request_id='lost-stop', scope=boot['scope'],
            control='STOP_AUTOMATION', expected_generation=boot['fence_generation']))
        self.service._start('lost-stop', request)
        before = self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).sequence
        self.assertEqual(self.service.requestControl(request)['status'], 'UNKNOWN')
        self.assertEqual(before, self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).sequence)

    def test_reviewed_close_while_stopped_does_not_resume_or_double_dispatch(self):
        position = self._open()
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.STOP_AUTOMATION, 'stop-before-close')
        state = self.app.core.current_state(self.fixture.scope.key, now=self.clock())
        preview = self.service.prepareClose(dict(owner_request_id='owner-close-1', command_id='reviewed-close-1',
            scope=self.service.readBoot()['scope'], source_state_id=state.state_id,
            position_id=position.position_id, position_version=position.version, quantity=str(position.quantity), quantity_unit='BASE_UNITS'))
        self.assertEqual(len(self.app.venue.receipt_history(self.fixture.scope.key, 'reviewed-close-1')), 0)
        request = {k: preview[k] for k in ('preview_id', 'owner_request_id', 'command_id', 'scope', 'intent_sha256')}
        outcome = self.service.requestReviewedClose(request)
        self.assertEqual(outcome['status'], 'ACCEPTED')
        self.assertEqual(self.service.requestReviewedClose(request), outcome)
        self.assertEqual(len(self.app.venue.receipt_history(self.fixture.scope.key, 'reviewed-close-1')), 1)
        fence = self.app.venue.snapshot(self.fixture.scope.key, now=self.clock()).fence
        self.assertFalse(fence.new_risk_allowed)
        self.assertFalse(fence.management_allowed)

    def test_close_preview_does_not_refresh_expired_authority(self):
        position = self._open()
        state = self.app.core.current_state(self.fixture.scope.key, now=self.clock())
        preview = self.service.prepareClose(dict(owner_request_id='expired-close', command_id='expired-close-command',
            scope=self.service.readBoot()['scope'], source_state_id=state.state_id,
            position_id=position.position_id, position_version=position.version, quantity=str(position.quantity), quantity_unit='BASE_UNITS'))
        self.clock.now = state.valid_until
        request = {k: preview[k] for k in ('preview_id', 'owner_request_id', 'command_id', 'scope', 'intent_sha256')}
        with self.assertRaises(ContractError):
            self.service.requestReviewedClose(request)


if __name__ == '__main__':
    unittest.main()
