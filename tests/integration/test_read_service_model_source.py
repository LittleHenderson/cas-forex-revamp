"""Fake-reader regression cases only; no actual model or private input.

AUTHORED/NOT_RUN until an independent isolated runner records execution.
The fixtures exercise source projection and the disconnected simulator only.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from cas_forex_revamp.contracts import ContractError, ControlKind, content_digest
from cas_forex_revamp.composition.continuous_driver import (
    _assemble, _control, _propose, _request, SyntheticClock)
from cas_forex_revamp.composition.continuous_model_driver import run_trajectory
from cas_forex_revamp.composition.read_service import DecisionReadService, wire
from cas_forex_revamp.composition.synthetic_fixture import continuous_a_fixture

# Public fixtures; importing TestCase classes would duplicate existing test IDs.
from test_model_trajectory import FakeAdapter, NOW, case, fake_reader


class ModelSourceProjectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.fixture = continuous_a_fixture()
        self.clock = SyntheticClock(self.fixture.started_at)
        self.app, self.owner, self.journal = _assemble(self.root, self.fixture.scope, self.clock)
        self.journal.initialize(create=True)
        self.app.venue.initialize(self.fixture.scope.key, opening_balance=self.fixture.opening_balance,
            instruments=self.fixture.instruments, now=self.clock(), scenario=self.fixture.venue_scenario)
        self.app.core.initialize(create=True)
        self.clock.now = self.fixture.market[0].available_at
        self.app.wiring.advance_market(self.fixture.market[0])
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.STOP_AUTOMATION, 'source-test-stop')
        _control(self.app, self.owner, self.journal, self.clock, ControlKind.RESUME_NEW_RISK, 'source-test-risk')
        schema = (Path(__file__).resolve().parents[2] / 'docs/contracts/decision-read.schema.json').read_bytes()
        self.reader = DecisionReadService(scope=self.fixture.scope, core=self.app.core, venue=self.app.venue,
            journal=self.journal, clock=self.clock, schema_bytes=schema, schema_sha256=sha256(schema).hexdigest(),
            instruments=self.fixture.instruments, model_reader=fake_reader)

    def record_fake_model(self):
        request, observation = _request(self.app, self.clock, 'fake-model-source')
        result = FakeAdapter().decide(request)
        result = replace(result, provenance=replace(result.provenance,
            started_at=self.clock(), completed_at=self.clock()))
        self.journal.append('input-fake-model-source', 'DECISION_INPUT', self.fixture.scope,
            {'request': request, 'observation': observation}, now=self.clock())
        self.journal.append('decision-fake-model-source', 'DECISION', self.fixture.scope,
            {'request': request, 'result': result, 'core_cursor': self.app.core.checkpoint(self.fixture.scope.key)},
            now=self.clock())
        return wire(request), wire(result)

    def reject_source(self, source):
        self.reader.model_reader = Mock(return_value=source)
        with self.assertRaises(ContractError):
            self.reader.read()
        with self.assertRaises(ContractError):
            self.reader.read_cockpit()
        self.assertEqual(self.reader._issued, {})

    def test_missing_reader_rejected(self):
        self.record_fake_model()
        self.reader.model_reader = None
        with self.assertRaises(ContractError):
            self.reader.read()

    def test_none_evidence_cannot_become_scripted(self):
        self.record_fake_model()
        self.reject_source(None)

    def test_empty_evidence_cannot_become_scripted(self):
        self.record_fake_model()
        self.reject_source({})

    def test_other_falsey_evidence_rejected(self):
        self.record_fake_model()
        for source in (False, 0, [], ''):
            with self.subTest(source=source):
                self.reject_source(source)

    def test_each_required_field_must_exist(self):
        self.record_fake_model()
        for field in ('receipt', 'sources', 'invocation_sha256', 'budget', 'latency_ms'):
            source = fake_reader(None, None)
            del source[field]
            with self.subTest(field=field):
                self.reject_source(source)

    def test_receipt_and_sources_have_record_shapes(self):
        self.record_fake_model()
        for field, invalid in (('receipt', None), ('receipt', {}), ('receipt', True),
                               ('sources', None), ('sources', {}), ('sources', [None]),
                               ('sources', [{}])):
            source = fake_reader(None, None)
            source[field] = invalid
            with self.subTest(field=field, invalid=invalid):
                self.reject_source(source)

    def test_invocation_digest_is_lowercase_sha256(self):
        self.record_fake_model()
        for invalid in (None, True, 'b' * 63, 'B' * 64, 'z' * 64):
            source = fake_reader(None, None)
            source['invocation_sha256'] = invalid
            with self.subTest(invalid=invalid):
                self.reject_source(source)

    def test_budget_rejects_bad_shape_values_and_booleans(self):
        self.record_fake_model()
        valid = wire(fake_reader(None, None)['budget'])
        malformed = [None, True, {}, {**valid, 'extra': 1}]
        malformed += [{**valid, 'max_calls': value} for value in (0, -1, True, '32')]
        malformed += [{**valid, 'max_seconds_per_call': valid['max_total_seconds'] + 1}]
        for invalid in malformed:
            source = fake_reader(None, None)
            source['budget'] = invalid
            with self.subTest(invalid=invalid):
                self.reject_source(source)

    def test_latency_rejects_negative_boolean_and_noninteger(self):
        self.record_fake_model()
        for invalid in (None, -1, True, '0', 0.5):
            source = fake_reader(None, None)
            source['latency_ms'] = invalid
            with self.subTest(invalid=invalid):
                self.reject_source(source)

    def test_valid_fake_evidence_retains_actual_origin_and_catalog_bindings(self):
        self.record_fake_model()
        bundle = self.reader.read()
        origin = bundle['envelope']['decisions'][0]['origin']
        self.assertEqual(origin['kind'], 'actual-inference')
        self.assertEqual(origin['invocation_sha256'], 'b' * 64)
        self.assertEqual(origin['model_artifact_sha256'], 'a' * 64)
        self.assertEqual(origin['latency_ms'], 0)
        anchor = bundle['anchor']['anchor_id']
        self.assertIsNotNone(self.reader.resolve(anchor, origin['inference_receipt']))
        self.assertIsNotNone(self.reader.resolve(anchor, origin['budget_receipt']))
        self.reader.validate_bound(bundle['envelope'], self.reader.anchor(anchor))

    def test_wire_budget_and_optional_fields_preserved_without_input_mutation(self):
        request, result = self.record_fake_model()
        source = wire(fake_reader(None, None))
        source['requested_reasoning'] = 'test-only'
        source['transport'] = {'FAKE_TEST_ONLY': True}
        before = deepcopy(source)
        self.reader.model_reader = Mock(return_value=source)
        retained = self.reader._decision_source(request, result)
        self.assertEqual(source, before)
        self.assertEqual(retained, source)
        self.assertIsNot(retained, source)
        source['receipt']['changed_after_return'] = True
        self.assertNotIn('changed_after_return', retained['receipt'])

    def test_scripted_origin_never_calls_model_reader(self):
        _propose(self.app, self.journal, self.clock, 'scripted-control')
        self.reader.model_reader = Mock(side_effect=AssertionError('must not read model evidence'))
        bundle = self.reader.read()
        origin = bundle['envelope']['decisions'][0]['origin']
        self.assertEqual(origin['kind'], 'scripted')
        self.assertIsNone(origin['model_id'])
        self.assertIsNone(origin['inference_receipt']['record_id'])
        self.reader.model_reader.assert_not_called()

    def test_scripted_selection_digest_still_required(self):
        _propose(self.app, self.journal, self.clock, 'scripted-control')
        entry = next(item for item in self.journal.records() if item.kind == 'DECISION')
        result = deepcopy(entry.payload['result'])
        result['selection']['rationale'] = 'changed'
        with self.assertRaises(ContractError):
            self.reader._decision_source(entry.payload['request'], result)

    def test_actual_request_digest_still_required(self):
        request, result = self.record_fake_model()
        request['request_id'] = 'changed-request'
        with self.assertRaises(ContractError):
            self.reader._decision_source(request, result)

    def test_unknown_provenance_origin_rejected(self):
        request, result = self.record_fake_model()
        result['provenance']['origin'] = 'UNKNOWN'
        with self.assertRaises(ContractError):
            self.reader._decision_source(request, result)


class ModelSourceTrajectoryTests(unittest.TestCase):
    def test_missing_evidence_fails_before_verified_claim_or_venue_admission(self):
        for source in (None, {}):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve() / 'trajectory'
                rows, _ = run_trajectory(case(), directory=root, execution_id='fake-b-rejection',
                    build_id='test-build', adapter=FakeAdapter(), model_store=None,
                    model_reader=lambda request, result: source, clock=lambda: NOW)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['error_type'], 'ContractError')
                self.assertFalse(rows[0]['actual_receipt_verified'])
                self.assertFalse(rows[0]['venue_changed'])
                self.assertNotIn('receipt_id', rows[0])
                self.assertNotIn('inference_source_sha256', rows[0])
                bundle = json.loads((root / 'decision-read.json').read_text())
                self.assertEqual(bundle['envelope']['decisions'], [])

    def test_valid_fake_reader_keeps_existing_trajectory_software_control(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'trajectory'
            rows, _ = run_trajectory(case(), directory=root, execution_id='fake-b-control',
                build_id='test-build', adapter=FakeAdapter(), model_store=None,
                model_reader=fake_reader, clock=lambda: NOW)
            self.assertEqual([row['error_type'] for row in rows], [None, None])
            self.assertEqual([row['effect'] for row in rows], ['FILLED', 'FILLED'])
            bundle = json.loads((root / 'decision-read.json').read_text())
            self.assertTrue(all(decision['origin']['kind'] == 'actual-inference'
                                for decision in bundle['envelope']['decisions']))
