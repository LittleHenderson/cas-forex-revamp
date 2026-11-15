"""Public synthetic caller tests. Authored only; not execution evidence."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from cas_forex_operational_contracts import common
from cas_forex_revamp.composition.operational_source_bootstrap import SourceCompletionBootstrap
from cas_forex_revamp.composition.operational_test_clock import OriginalPairedStampReader
from tests.integration import test_completion_run as public


DOMAIN = {'boot_id': '00000000-0000-0000-0000-000000000001',
          'time_namespace_inode': 42, 'clock_id': 'CLOCK_BOOTTIME'}


def source_fixture():
    f = public.Fixture()
    old = f.binding['original_window_sha256']
    f.clock = {'format': 'forex.original-source-test-clock/1',
               'bootstrap_started_utc': public.stamp(0)['utc'],
               'test_deadline_utc': public.stamp(170)['utc']}
    new = common.digest(common.canonical_bytes(f.clock))
    # Public unit-only fixture rebinding; no real protected record is touched.
    def replace(value, before, after):
        return common.decode_canonical(common.canonical_bytes(value).replace(
            before.encode(), after.encode()))
    for name in ('binding', 'publishers', 'selection'):
        setattr(f, name, replace(getattr(f, name), old, new))
    old_publisher = f.publisher_hash
    f.publisher_hash = common.digest(common.canonical_bytes(f.publishers))
    f.selection = replace(f.selection, old_publisher, f.publisher_hash)
    f.selection['original_clock_ref'] = f.ref('EXTERNAL_RELEASE_EVIDENCE',
        'release-evidence:original_clock_and_budget_binding_sha256',
        raw=common.canonical_bytes(f.clock))
    f.selection_use = f.ref('COMPLETION_SELECTION', 'completion-selection',
                            raw=common.canonical_bytes(f.selection))
    return f


class PublicBindings:
    def __init__(self, fixture):
        self.f = fixture; self.resolver = fixture; self.order = []
        self.fail_verify = False; self.fail_publish = False; self.change_receipt = False
        self.reject_gate = False
    def execution_gate(self):
        if self.reject_gate: raise RuntimeError('public gate withdrawn')
    def authenticate_selection(self, selection, *, now): pass
    def observer_publish(self, raw, **kwargs):
        return self.f.publish(raw, publisher='public-observer', **kwargs)
    def custody_publish(self, raw, **kwargs):
        return self.f.publish(raw, publisher='public-custody', **kwargs)
    def receipt(self, report_use, observation_use):
        report = common.decode_canonical(self.f.rows[report_use['reference']['sha256']])
        return common.canonical_bytes({'format': 'forex.observed-source-test-completion/2',
            'binding': self.f.binding, 'selection_ref': self.f.selection_use,
            'observer_id': 'public-observer', 'verifier_id': 'public-verifier',
            'verifier_component_sha256': '9'*64,
            'original_clock_record_content_sha256': common.digest(common.canonical_bytes(self.f.clock)),
            'completed_at_utc': report['finished_utc'], 'original_source_test_report': report_use,
            'observation_evidence': observation_use,
            'group_reports_sha256': common.digest(common.canonical_bytes(report['group_reports']))})
    def verify_completion(self, report_use, observation_use, *, now):
        self.order.append('verify')
        if self.fail_verify: raise RuntimeError('public independent rejection')
        return self.receipt(report_use, observation_use)
    def publish_completion(self, report_use, observation_use, *, now):
        self.order.append('publish')
        if self.fail_publish: raise RuntimeError('public publication unavailable')
        raw = self.receipt(report_use, observation_use)
        if self.change_receipt:
            body = common.decode_canonical(raw); body['completed_at_utc'] = public.stamp(15)['utc']
            raw = common.canonical_bytes(body)
        return self.f.ref('SOURCE_TEST_COMPLETION', 'source-test-completion', raw=raw), raw


def caller(f, b):
    return SourceCompletionBootstrap(bindings=b, wire_arguments={
        'original_clock_raw': common.canonical_bytes(f.clock),
        'work_started_utc': public.stamp(0)['utc'],
        'work_deadline_utc': public.stamp(13200)['utc'],
        'clock_domain': DOMAIN, 'clock_anchor_stamp': public.stamp(0),
        'completion_selection': f.selection, 'selection_use': f.selection_use,
        'publishers': f.publishers, 'capture_sink': object(),
        'custody_publisher_id': 'public-custody', 'environment': {},
        'environment_profile_sha256': 'b'*64, 'parser_component_sha256': 'c'*64,
        'parser_schema_sha256': {
            'forex.python-framework-report/2': 'd'*64,
            'forex.node-tap-report/1': 'e'*64,
            'forex.node-version-report/1': 'f'*64}})


class CallerTests(unittest.TestCase):
    def setUp(self):
        self.f = source_fixture(); self.b = PublicBindings(self.f)
        # Real wire_source_completion and CompletionRun are called. Only native
        # observation and the clock are public fakes; custody doubles cannot
        # establish independent acceptance or cryptographic authorization.
        self.clock = patch('cas_forex_authority.authentication.LinuxOriginalClock',
            return_value=SimpleNamespace(observe=lambda: (DOMAIN, self.f.now())))
        self.observer = patch('cas_forex_measurement.completion.CompletionObserver.observe',
            side_effect=lambda selection, *, group: self.f.observe(selection, group=group))
        self.clock.start(); self.observer.start()
        self.addCleanup(self.clock.stop); self.addCleanup(self.observer.stop)
    def test_constructor_does_not_wire_run_verify_or_publish(self):
        c = caller(self.f, self.b)
        self.assertEqual(c.state, 'NEW'); self.assertEqual(self.f.called, [])
        self.assertEqual(self.b.order, [])
    def test_real_wire_runs_thirteen_then_verifies_publishes_and_reads_back(self):
        c = caller(self.f, self.b); outcome = c.execute()
        self.assertEqual(self.f.called, list(public.GROUPS))
        self.assertEqual(self.b.order, ['verify', 'publish'])
        self.assertEqual(c.state, 'SOURCE_COMPLETION_PUBLISHED')
        self.assertEqual(outcome.receipt_raw, c.verified_receipt_raw)
        self.assertEqual(common.decode_canonical(outcome.receipt_raw)['completed_at_utc'],
                         public.stamp(14)['utc'])
    def test_caller_cannot_repeat_after_success(self):
        c = caller(self.f, self.b); c.execute()
        with self.assertRaises(common.ContractError): c.execute()
        self.assertEqual(len(self.f.called), 13)
    def test_failed_group_never_reaches_verifier(self):
        self.f.fail = 'core'; c = caller(self.f, self.b)
        with self.assertRaises(common.ContractError): c.execute()
        self.assertEqual(self.f.called, ['contracts', 'core'])
        self.assertEqual(self.b.order, []); self.assertEqual(c.state, 'INCOMPLETE')
    def test_independent_rejection_retains_run_but_publishes_no_receipt(self):
        self.b.fail_verify = True; c = caller(self.f, self.b)
        with self.assertRaises(RuntimeError): c.execute()
        self.assertIsNotNone(c.retained_result)
        self.assertIsNone(c.published_receipt_use_raw)
        self.assertEqual(self.b.order, ['verify'])
    def test_publication_failure_retains_exact_verified_body(self):
        self.b.fail_publish = True; c = caller(self.f, self.b)
        with self.assertRaises(RuntimeError): c.execute()
        self.assertIsNotNone(c.verified_receipt_raw)
        self.assertIsNone(c.published_receipt_use_raw)
    def test_reverification_cannot_change_completed_time(self):
        self.b.change_receipt = True; c = caller(self.f, self.b)
        with self.assertRaises(common.ContractError): c.execute()
        self.assertEqual(c.state, 'INCOMPLETE')
    def test_final_receipt_readback_substitution_is_rejected(self):
        real = self.f.resolve
        def resolve(use, **kwargs):
            if use['reference']['record_kind'] == 'SOURCE_TEST_COMPLETION': return b'{}'
            return real(use, **kwargs)
        self.f.resolve = resolve; c = caller(self.f, self.b)
        with self.assertRaises(common.ContractError): c.execute()
        self.assertIsNotNone(c.published_receipt_use_raw)
    def test_missing_permission_prevents_wire_and_every_test(self):
        self.b.reject_gate = True; c = caller(self.f, self.b)
        with self.assertRaises(RuntimeError): c.execute()
        self.assertEqual(self.f.called, [])
    def test_failed_attempt_cannot_retry_with_repaired_provider(self):
        self.b.fail_verify = True; c = caller(self.f, self.b)
        with self.assertRaises(RuntimeError): c.execute()
        self.b.fail_verify = False
        with self.assertRaises(common.ContractError): c.execute()
        self.assertEqual(len(self.f.called), 13)


class SourceOnlyClockTests(unittest.TestCase):
    def reader(self, *, anchor=60, current=90, **kwargs):
        original = {'format': 'forex.original-source-test-clock/1',
            'bootstrap_started_utc': public.stamp(30)['utc'],
            'test_deadline_utc': public.stamp(7230)['utc']}
        raw = common.canonical_bytes(original)
        parameters = dict(original_clock_raw=raw, expected_window_sha256=common.digest(raw),
            work_started_utc=public.stamp(0)['utc'], work_deadline_utc=public.stamp(13200)['utc'],
            clock_domain=DOMAIN, clock_anchor_stamp=public.stamp(anchor),
            clock=SimpleNamespace(observe=lambda: (DOMAIN, public.stamp(current))))
        parameters.update(kwargs)
        return OriginalPairedStampReader(**parameters)
    def test_truthful_anchor_after_bootstrap_never_needs_preboot_ticks(self):
        self.assertEqual(self.reader().read_stamp(), public.stamp(90))
    def test_raw_reader_checks_time_without_any_authority_callback(self):
        self.assertEqual(self.reader(current=7000).read_stamp(), public.stamp(7000))
    def test_anchor_cannot_be_in_future_of_observation(self):
        with self.assertRaises(common.ContractError): self.reader(anchor=100).read_stamp()
    def test_old_work_start_parameter_cannot_stand_in_for_new_actual_anchor(self):
        with self.assertRaises(common.ContractError):
            self.reader(clock_anchor_stamp=None, work_start_stamp=public.stamp(0))
    def test_exact_original_test_deadline_is_expired(self):
        with self.assertRaises(common.ContractError): self.reader(current=7230).read_stamp()
    def test_reconstructing_reader_does_not_reset_expired_window(self):
        for unused in range(2):
            with self.assertRaises(common.ContractError): self.reader(current=7300).read_stamp()
    def test_new_anchor_cannot_precede_original_global_start(self):
        with self.assertRaises(common.ContractError): self.reader(anchor=-1)
    def test_deadline_is_paired_from_actual_anchor_without_backdating(self):
        reader = self.reader()
        self.assertEqual(reader.original_deadline, public.stamp(7230))
    def test_returned_deadline_is_detached(self):
        reader = self.reader(); value = reader.original_deadline
        value['boottime_ns'] = 1
        self.assertEqual(reader.original_deadline, public.stamp(7230))
