"""Public artificial integration vectors, AUTHORED / NOT_RUN.

The fake resolver/provider below only exercise source wiring. They are not
authenticated observations, private scoring, filesystem isolation or runtime
receipts and must never be installed as production authority providers.
"""
import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest.mock import patch

from authority_component.consumer import PublicCustodyConsumer
from authority_component.source.evidence_types import Blocked, canonical, content_digest, decode, raw_digest, RELEASE_DIGESTS, FREEZE_COMPONENTS
from authority_component.release_gate import require_release_enabled


class SyntheticAuthorityOnly:
    def __init__(self): self.calls = []
    def authenticate(self, **kwargs): self.calls.append(('authenticate', deepcopy(kwargs)))
    def verify_semantics(self, **kwargs): self.calls.append(('semantics', deepcopy(kwargs)))
    def verify_complete_scoring(self, **kwargs): self.calls.append(('scoring', deepcopy(kwargs)))
    def verify_redaction(self, **kwargs): self.calls.append(('redaction', deepcopy(kwargs)))


class PublicFixture:
    def __init__(self):
        self.records = {}; self.guards = 0; self.reads = 0
        self.provider = SyntheticAuthorityOnly()
        self.t0 = datetime(2030, 1, 1, tzinfo=timezone.utc)
        stamp = lambda m: (self.t0+timedelta(minutes=m)).isoformat().replace('+00:00', 'Z')
        self.stamp = stamp; self.now = self.t0+timedelta(minutes=111)
        self.clock = {'model_window': {'started_at': stamp(110), 'deadline': stamp(200),
            'total_generation_limit': 32, 'probe_limit': 2, 'acceptance_limit': 30,
            'includes': ['startup', 'render', 'tokenize', 'probes', 'acceptance', 'export', 'shutdown']},
            'model_calls': 32, 'retry_calls': 0, 'bootstrap_started_utc': stamp(0), 'test_deadline_utc': stamp(120)}
        refs = {name: self.add(name, {'artificial_descriptor': name}) for name in RELEASE_DIGESTS}
        self.binding = {'run_id': 'public-fixture', 'epoch': 1, 'config_sha256': '1'*64,
            'source_manifest_sha256': '2'*64, 'asset_manifest_sha256': '3'*64,
            'custody_public_manifest_sha256': refs['custody_manifest_sha256']['sha256'],
            'issuer_binding_sha256': refs['issuer_binding_sha256']['sha256'],
            'observer_binding_sha256': refs['trusted_observer_binding_sha256']['sha256'],
            'source_test_observer_binding_sha256': '4'*64, 'original_clock_record': deepcopy(self.clock),
            't0_utc': stamp(0), 'work_deadline_utc': stamp(220)}
        guest = {name: self.add('guest-'+name, {'public_fake': name}) for name in
                 ('authorization', 'case_review', 'source_review', 'stop_proof', 'egress')}
        for name, key in (('separate_execution_authorization_sha256', 'authorization'),
                          ('accepted_private_mapping_sha256', 'case_review'),
                          ('independent_review_attestation_sha256', 'source_review')):
            refs[name] = guest[key]
        refs['stop_egress_deadline_proofs_sha256'] = self.add('stop', {
            'stop_proof_sha256': guest['stop_proof']['sha256'], 'egress_sha256': guest['egress']['sha256'],
            'work_deadline_utc': stamp(220)})
        refs['original_clock_and_budget_binding_sha256'] = self.add('clock', self.clock)
        components = {name: self.add('component-'+name, {'public_fake': name}) for name in FREEZE_COMPONENTS}
        hashes = {name: ref['sha256'] for name, ref in components.items()}
        refs['complete_freeze_manifest_sha256'] = self.add('freeze', {
            **{k:self.binding[k] for k in ('config_sha256', 'source_manifest_sha256', 'asset_manifest_sha256')},
            'bound_components': hashes, 'component_records': components})
        # In this wiring test the fake authority alone accepts this minimal
        # artificial observation; it is deliberately not a B08 isolation receipt.
        observed = {'observed_at_utc': stamp(110), 'expires_at_utc': stamp(199)}
        refs['role_read_isolation_receipt_sha256'] = self.add('observation', observed)
        report = self.add('original-source-test-report', {'status': 'PASS',
            'finished_utc': (self.t0+timedelta(minutes=109)).isoformat(),
            'original_bootstrap_started_utc': stamp(0), 'test_deadline_utc': stamp(120)})
        self.completion = {'format': 'forex.observed-source-test-completion/1', 'run_id': 'public-fixture',
            'epoch': 1, 'observer_binding_sha256': '4'*64, 'source_manifest_sha256': '2'*64,
            'config_sha256': '1'*64, 'original_clock_record_content_sha256': content_digest(self.clock),
            'completed_at_utc': stamp(109), 'original_source_test_report': report,
            'observation_evidence': self.add('independent-artificial-capture', {'synthetic_only': True})}
        self.selection = {'format': 'forex.independent-release-selection/2',
            **{k:deepcopy(v) for k,v in self.binding.items() if k != 'custody_public_manifest_sha256'},
            'release_id': 'public-release', 'freeze_reviewer_binding_sha256': '5'*64,
            'expected_release_bindings': {**{k:v['sha256'] for k,v in refs.items()}, 'run_id': 'public-fixture', 'epoch': 1},
            'publishers': {k:'6'*64 for k in refs}, 'references': refs, 'guest_evidence': guest,
            'freeze_components': hashes, 'independently_validated_observed_roles': observed,
            'source_test_completion': self.add('completion', self.completion)}

    def add(self, name, value):
        raw = canonical(value)
        ref = {'path': '/opt/cas-forex/public-fixture/'+name+'.json', 'bytes': len(raw), 'sha256': raw_digest(raw)}
        self.records[ref['path']] = raw
        return ref

    def guard(self): self.guards += 1

    def resolver(self, base, *, require_remaining):
        fixture = self
        class MemoryResolver:
            def read(self, ref):
                require_remaining(); fixture.reads += 1
                raw = fixture.records[ref['path']]
                if len(raw) != ref['bytes'] or raw_digest(raw) != ref['sha256']: raise Blocked('PIN_MISMATCH')
                return raw, decode(raw)
        return MemoryResolver()

    def consumer(self, *, default_authority=False, guard=None):
        with patch('authority_component.consumer.ProtectedResolver', side_effect=self.resolver):
            return PublicCustodyConsumer(selected_base='/opt/cas-forex/public-fixture', binding=self.binding,
                require_remaining=self.guard if guard is None else guard,
                authority=None if default_authority else self.provider)

    def draft(self, consumer=None):
        return (consumer or self.consumer()).release_draft(selection_reference=self.add('selection', self.selection),
            selection_authority_sha256='7'*64, release_id='public-release', issued_at_utc=self.stamp(110),
            not_before_utc=self.stamp(110), expires_at_utc=self.stamp(198), now=self.now)

    def aggregate_selection(self):
        retained = self.add('retained-artificial-bundle', {'synthetic_only': True})
        ids = ['public-synthetic-step-'+str(n) for n in range(30)]
        report = {'format': 'forex.independent-terminal-score/1', 'run_id': 'public-fixture', 'epoch': 1,
            'lifecycle': 'ABORTED', 'source_freeze_manifest_sha256': '2'*64,
            'custody_public_manifest_sha256': self.binding['custody_public_manifest_sha256'],
            'retained_evaluation_bundle_sha256': retained['sha256'], 'accepted_private_mapping_sha256': '9'*64,
            'mandatory_step_ids': ids, 'mandatory_assertion_ids': ['public-synthetic-assertion'],
            'steps': [{'step_id':i,'attempt_id':None,'outcome':'INCOMPLETE','independent_evidence_receipt':None} for i in ids],
            'assertions': [{'assertion_id':'public-synthetic-assertion','outcome':'INCOMPLETE','independent_evidence_receipt':None}],
            'generation_attempts': [], 'broad_failure_codes': ['CUSTODY_GATE']}
        body = {'format':'forex.stage-b-public-aggregate/1','run_id':'public-fixture',
            'source_freeze_manifest_sha256':'2'*64,'custody_public_manifest_sha256':self.binding['custody_public_manifest_sha256'],
            'retained_evaluation_bundle_sha256':retained['sha256'],'status':'BLOCKED',
            'generation_attempts_spent':0,'mandatory_steps_accounted':0,'mandatory_steps_incomplete':30,
            'all_mandatory_assertions_passed':False,'broad_failure_codes':['CUSTODY_GATE']}
        approval = {'format':'forex.independent-aggregate-redaction/1','reviewer_binding_sha256':'c'*64,
            'run_id':'public-fixture','final_or_aborted':True,'retained_evaluation_bundle_sha256':retained['sha256'],
            'approved_aggregate_body_sha256':content_digest(body),'independent_complete_scoring_accepted':False}
        selection = {k:deepcopy(report[k]) for k in ('run_id','epoch','source_freeze_manifest_sha256',
            'custody_public_manifest_sha256','retained_evaluation_bundle_sha256','accepted_private_mapping_sha256',
            'mandatory_step_ids','mandatory_assertion_ids')}
        selection.update(format='forex.independent-aggregate-selection/1',
            report_reference=self.add('terminal-artificial-report',report), retained_bundle_reference=retained,
            scorer_binding_sha256='a'*64, custody_binding_sha256='b'*64, public_run_id='public-fixture',
            reviewer_binding_sha256='c'*64, redaction_receipt_reference=self.add('artificial-redaction',approval))
        return selection, body, approval


class PublicConsumerWiring(unittest.TestCase):
    def test_constructor_is_inert(self):
        fixture = PublicFixture(); fixture.consumer()
        self.assertEqual((fixture.guards, fixture.reads, fixture.provider.calls), (0, 0, []))

    def test_missing_original_guard_rejected(self):
        fixture = PublicFixture()
        with self.assertRaisesRegex(Blocked, 'ORIGINAL_DEADLINE_GUARD_REQUIRED'):
            PublicCustodyConsumer(selected_base='/opt/cas-forex/public-fixture', binding=fixture.binding, require_remaining=None)

    def test_boolean_guard_rejected_before_read(self):
        fixture = PublicFixture()
        with self.assertRaisesRegex(Blocked, 'ORIGINAL_DEADLINE_GUARD_PROTOCOL'):
            fixture.draft(fixture.consumer(guard=lambda: True))
        self.assertEqual(fixture.reads, 0)

    def test_missing_provider_rejects_even_structurally_valid_selection(self):
        fixture = PublicFixture()
        with self.assertRaisesRegex(Blocked, 'AUTHENTICATION_PROVIDER_UNIMPLEMENTED'):
            fixture.draft(fixture.consumer(default_authority=True))

    def test_source02_late_window_delegated_without_clock_reset(self):
        fixture = PublicFixture(); result = fixture.draft()
        self.assertEqual(result['format'], 'forex.disabled-release-draft/1')
        self.assertEqual(result['release']['expires_at_utc'], fixture.stamp(198))
        completions = [row for kind,row in fixture.provider.calls if kind == 'semantics' and row['purpose'] == 'source-test-completion']
        self.assertTrue(completions)
        self.assertEqual(completions[0]['dependencies']['original_clock_record'], fixture.clock)
        self.assertGreater(fixture.guards, fixture.reads)

    def test_v1_selection_is_not_upgraded(self):
        fixture = PublicFixture(); fixture.selection['format'] = 'forex.independent-release-selection/1'
        with self.assertRaises(Blocked): fixture.draft()

    def test_completion_additions_are_required(self):
        for name in ('source_test_completion', 'source_test_observer_binding_sha256'):
            fixture = PublicFixture(); fixture.selection.pop(name)
            with self.subTest(name=name), self.assertRaises(Blocked): fixture.draft()

    def test_source_test_observer_cannot_be_substituted(self):
        fixture = PublicFixture(); fixture.selection['source_test_observer_binding_sha256'] = '8'*64
        with self.assertRaisesRegex(Blocked, 'PIN_MISMATCH'): fixture.draft()

    def test_source_or_configuration_cannot_be_substituted(self):
        for name in ('source_manifest_sha256', 'config_sha256', 'asset_manifest_sha256'):
            fixture = PublicFixture(); fixture.selection[name] = '8'*64
            with self.subTest(name=name), self.assertRaisesRegex(Blocked, 'PIN_MISMATCH'): fixture.draft()

    def test_other_run_or_boolean_epoch_rejected(self):
        for name,value in (('run_id','other-public-fixture'), ('epoch',True)):
            fixture = PublicFixture(); fixture.selection[name] = value
            with self.subTest(name=name), self.assertRaisesRegex(Blocked, 'PIN_MISMATCH'): fixture.draft()

    def test_original_clock_equality_required(self):
        fixture = PublicFixture(); fixture.selection['original_clock_record']['retry_calls'] = 1
        with self.assertRaisesRegex(Blocked, 'PIN_MISMATCH'): fixture.draft()

    def test_completion_after_model_start_rejected_by_reviewed_validator(self):
        fixture = PublicFixture(); fixture.completion['completed_at_utc'] = fixture.stamp(112)
        fixture.selection['source_test_completion'] = fixture.add('completion', fixture.completion)
        with self.assertRaisesRegex(Blocked, 'TIME_BUDGET'): fixture.draft()

    def test_binding_copied_before_caller_mutation(self):
        fixture = PublicFixture(); consumer = fixture.consumer()
        fixture.binding['original_clock_record']['retry_calls'] = 99
        self.assertEqual(fixture.draft(consumer)['format'], 'forex.disabled-release-draft/1')

    def test_provider_input_mutation_rejected(self):
        fixture = PublicFixture()
        class Mutator(SyntheticAuthorityOnly):
            def verify_semantics(self, **kwargs): kwargs['record']['run_id'] = 'mutated'
        fixture.provider = Mutator()
        with self.assertRaisesRegex(Blocked, 'AUTHORITY_MUTATED_INPUT'): fixture.draft()

    def test_expired_original_window_rejected_before_read(self):
        fixture = PublicFixture(); fixture.now = fixture.t0+timedelta(minutes=200)
        with self.assertRaisesRegex(Blocked, 'TIME_BUDGET'): fixture.draft()
        self.assertEqual(fixture.reads, 0)

    def test_original_guard_expiry_after_authentication_is_preserved(self):
        fixture = PublicFixture()
        def expires():
            fixture.guards += 1
            if fixture.provider.calls: raise Blocked('ORIGINAL_GUARD_EXPIRED')
        with self.assertRaisesRegex(Blocked, 'ORIGINAL_GUARD_EXPIRED'): fixture.draft(fixture.consumer(guard=expires))

    def test_issuance_and_publication_unconditionally_disabled(self):
        fixture = PublicFixture(); consumer = fixture.consumer()
        for method in (consumer.issue, consumer.publish):
            with self.assertRaises(Blocked): method(enabled=True)
        self.assertEqual(fixture.reads, 0)

    def test_b09_model_entrypoint_gate_precedes_configuration_and_work(self):
        root = Path(__file__).resolve().parents[2]
        tree = ast.parse((root/'approved_model_driver.py').read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        self.assertIsInstance(main.body[0], ast.ImportFrom)
        self.assertEqual(main.body[0].module, 'authority_component.release_gate')
        self.assertEqual(main.body[1].value.func.id, 'require_release_enabled')
        with self.assertRaisesRegex(RuntimeError, 'B09_RELEASE_DISABLED'): require_release_enabled()

    def test_aggregate_remains_disabled_and_preserves_incomplete_denominator(self):
        fixture = PublicFixture(); selected, body, _ = fixture.aggregate_selection()
        result = fixture.consumer().aggregate_draft(selection_reference=fixture.add('aggregate-selection', selected),
            selection_authority_sha256='d'*64, now=fixture.now)
        self.assertEqual(result['format'], 'forex.disabled-aggregate-draft/1')
        self.assertEqual(result['aggregate'], {**body,'independent_redaction_receipt_sha256':selected['redaction_receipt_reference']['sha256']})
        self.assertTrue(any(kind=='scoring' for kind,_ in fixture.provider.calls))
        self.assertTrue(any(kind=='redaction' for kind,_ in fixture.provider.calls))

    def test_wrong_redaction_body_rejected(self):
        fixture = PublicFixture(); selected, _, approval = fixture.aggregate_selection()
        approval['approved_aggregate_body_sha256'] = 'f'*64
        selected['redaction_receipt_reference'] = fixture.add('artificial-redaction', approval)
        with self.assertRaises(Blocked):
            fixture.consumer().aggregate_draft(selection_reference=fixture.add('aggregate-selection',selected),
                selection_authority_sha256='d'*64, now=fixture.now)

    def test_aggregate_selection_cannot_add_diagnostic_field(self):
        fixture = PublicFixture(); selected, _, _ = fixture.aggregate_selection()
        selected['private_diagnostic'] = 'public-synthetic-only'
        with self.assertRaises(Blocked):
            fixture.consumer().aggregate_draft(selection_reference=fixture.add('aggregate-selection',selected),
                selection_authority_sha256='d'*64, now=fixture.now)

    def test_aggregate_without_authentication_is_blocked(self):
        fixture = PublicFixture(); selected, _, _ = fixture.aggregate_selection()
        with self.assertRaisesRegex(Blocked, 'AUTHENTICATION_PROVIDER_UNIMPLEMENTED'):
            fixture.consumer(default_authority=True).aggregate_draft(selection_reference=fixture.add('aggregate-selection',selected),
                selection_authority_sha256='d'*64, now=fixture.now)
