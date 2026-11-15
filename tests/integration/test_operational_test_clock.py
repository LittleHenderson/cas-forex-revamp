"""Public clock regressions only. Authored/NOT_RUN; no deployment evidence."""
import copy
from datetime import datetime, timedelta, timezone
import unittest

from cas_forex_operational_contracts import common
from cas_forex_revamp.composition.operational_test_clock import OriginalTestClock, OriginalTestClockReference


BASE = datetime(2030, 1, 1, tzinfo=timezone.utc)
DOMAIN = {'boot_id': '00000000-0000-0000-0000-000000000001',
          'time_namespace_inode': 42, 'clock_id': 'CLOCK_BOOTTIME'}
ANCHOR_NS = 200000000000


def text(seconds):
    return (BASE + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def stamp(seconds, *, ticks=None):
    return {'utc': text(seconds),
            'boottime_ns': ANCHOR_NS + int(seconds * 1000000000) if ticks is None else ticks}


def original(*, bootstrap=60, test_end=7260, model_start=7300):
    return {'model_calls': 32, 'retry_calls': 0,
            'bootstrap_started_utc': text(bootstrap), 'test_deadline_utc': text(test_end),
            'model_window': {'started_at': text(model_start),
                'deadline': text(min(model_start + 5400, 13200)),
                'total_generation_limit': 32, 'probe_limit': 2, 'acceptance_limit': 30,
                'includes': ['startup', 'render', 'tokenize', 'probes', 'acceptance', 'export', 'shutdown']}}


class PublicClock:
    def __init__(self):
        self.domain, self.current, self.reads = copy.deepcopy(DOMAIN), stamp(600), 0

    def observe(self):
        self.reads += 1
        return copy.deepcopy(self.domain), copy.deepcopy(self.current)


def guard(clock, *, body=None, gate=lambda: None, **overrides):
    raw = common.canonical_bytes(original() if body is None else body)
    args = dict(original_clock_raw=raw, expected_window_sha256=common.digest(raw),
        work_started_utc=text(0), work_deadline_utc=text(13200),
        clock_domain=DOMAIN, work_start_stamp=stamp(0), clock=clock, execution_gate=gate)
    args.update(overrides)
    return OriginalTestClock(**args)


class OriginalTestClockTests(unittest.TestCase):
    def test_constructor_neither_observes_nor_checks_runtime_permission(self):
        clock = PublicClock()
        def forbidden():
            raise AssertionError('constructor must be inert')
        value = guard(clock, gate=forbidden)
        self.assertEqual(clock.reads, 0)
        self.assertFalse(value.failed)

    def test_source_tests_can_run_after_method_180_seconds_without_new_budget(self):
        clock = PublicClock(); clock.current = stamp(900)
        self.assertEqual(guard(clock).now(), stamp(900))

    def test_original_test_endpoint_limits_remaining_time(self):
        clock = PublicClock(); clock.current = stamp(7000)
        self.assertEqual(guard(clock).remaining(), 260)

    def test_earlier_model_start_limits_test_phase(self):
        clock = PublicClock(); clock.current = stamp(3500)
        value = guard(clock, body=original(model_start=3600))
        self.assertEqual(value.remaining(), 100)
        clock.current = stamp(3600)
        with self.assertRaises(common.ContractError):
            value.now()

    def test_global_deadline_can_cap_existing_model_window(self):
        clock = PublicClock(); clock.current = stamp(7000)
        self.assertEqual(guard(clock, body=original(model_start=9000)).remaining(), 260)

    def test_exact_test_deadline_is_expired(self):
        clock = PublicClock(); clock.current = stamp(7260)
        with self.assertRaises(common.ContractError):
            guard(clock).now()

    def test_reconstructing_object_cannot_restart_original_window(self):
        clock = PublicClock(); clock.current = stamp(7300)
        for _ in range(2):
            with self.assertRaises(common.ContractError):
                guard(clock).now()

    def test_before_original_bootstrap_is_rejected(self):
        clock = PublicClock(); clock.current = stamp(59)
        with self.assertRaises(common.ContractError):
            guard(clock).now()

    def test_mismatched_original_content_pin_is_rejected(self):
        with self.assertRaises(common.ContractError):
            guard(PublicClock(), expected_window_sha256='0' * 64)

    def test_actual_anchor_cannot_be_relabelled_as_work_start(self):
        with self.assertRaises(common.ContractError):
            guard(PublicClock(), work_start_stamp=stamp(60))

    def test_different_global_allowance_is_rejected(self):
        with self.assertRaises(common.ContractError):
            guard(PublicClock(), work_deadline_utc=text(14000))

    def test_oversized_original_test_window_is_rejected(self):
        with self.assertRaises(common.ContractError):
            guard(PublicClock(), body=original(test_end=7261))

    def test_different_current_domain_is_terminal(self):
        clock = PublicClock(); value = guard(clock)
        clock.domain['time_namespace_inode'] += 1
        with self.assertRaises(common.ContractError):
            value.now()
        clock.domain = copy.deepcopy(DOMAIN)
        with self.assertRaises(common.ContractError):
            value.now()
        self.assertEqual(clock.reads, 1)

    def test_utc_and_boottime_disagreement_is_rejected(self):
        clock = PublicClock(); clock.current = stamp(600, ticks=ANCHOR_NS + 602000000000)
        with self.assertRaises(common.ContractError):
            guard(clock).now()

    def test_utc_rollback_is_rejected_even_with_advancing_ticks(self):
        clock = PublicClock(); value = guard(clock); value.now()
        clock.current = stamp(599.9, ticks=ANCHOR_NS + 600100000000)
        with self.assertRaises(common.ContractError):
            value.now()

    def test_boottime_rollback_is_rejected_even_with_advancing_utc(self):
        clock = PublicClock(); value = guard(clock); value.now()
        clock.current = stamp(600.1, ticks=ANCHOR_NS + 599900000000)
        with self.assertRaises(common.ContractError):
            value.now()

    def test_expired_boottime_is_not_hidden_by_a_utc_rounding_difference(self):
        clock = PublicClock(); clock.current = stamp(7259.9, ticks=ANCHOR_NS + 7260000000000)
        with self.assertRaises(common.ContractError):
            guard(clock).now()

    def test_gate_loss_after_observation_is_terminal(self):
        clock = PublicClock(); calls = []
        def gate():
            calls.append(1)
            return None if len(calls) == 1 else False
        value = guard(clock, gate=gate)
        with self.assertRaises(common.ContractError):
            value.now()
        self.assertTrue(value.failed)
        self.assertEqual(clock.reads, 1)

    def test_gate_loss_before_observation_performs_no_clock_read(self):
        clock = PublicClock()
        with self.assertRaises(common.ContractError):
            guard(clock, gate=lambda: False).now()
        self.assertEqual(clock.reads, 0)

    def test_returned_stamp_cannot_mutate_guard_history(self):
        clock = PublicClock(); value = guard(clock)
        returned = value.now(); returned['boottime_ns'] = 99999999999999999
        clock.current = stamp(601)
        self.assertEqual(value.now(), stamp(601))

    def test_domain_constructor_input_cannot_mutate_expected_identity(self):
        clock = PublicClock(); selected = copy.deepcopy(DOMAIN)
        value = guard(clock, clock_domain=selected)
        selected['time_namespace_inode'] += 1
        self.assertEqual(value.now(), stamp(600))


class ClockReferenceTests(unittest.TestCase):
    def fixture(self, *, tagged=False):
        # Reuse only public shapes. This fake resolver asserts no authentication.
        from tests.integration.test_completion_run import Fixture
        fixture = Fixture(); clock = PublicClock(); value = guard(clock)
        binding = copy.deepcopy(fixture.binding)
        binding['original_window_sha256'] = common.digest(value.original_clock_raw)
        publishers = copy.deepcopy(fixture.publishers); publishers['binding'] = binding
        body = common.decode_canonical(value.original_clock_raw)
        if tagged:
            body['format'] = 'forex.release-evidence-original_clock_and_budget_binding_sha256/1'
        raw = common.canonical_bytes(body)
        use = fixture.ref('EXTERNAL_RELEASE_EVIDENCE',
            'release-evidence:original_clock_and_budget_binding_sha256', raw=raw)
        use['reference']['binding'] = binding
        use['reference']['publisher_selection_sha256'] = common.digest(common.canonical_bytes(publishers))
        adapter = OriginalTestClockReference(selected_use=use, publishers=publishers,
            resolver=fixture, guard=value)
        return fixture, clock, value, use, adapter

    def test_exact_original_bytes_match_the_selected_original_content(self):
        fixture, clock, value, use, adapter = self.fixture()
        self.assertIsNone(adapter(use, stamp(600)))

    def test_tagged_reference_retains_a_different_record_hash_from_original_content(self):
        fixture, clock, value, use, adapter = self.fixture(tagged=True)
        self.assertNotEqual(use['reference']['sha256'], common.digest(value.original_clock_raw))
        self.assertIsNone(adapter(use, stamp(600)))

    def test_changed_registration_is_not_the_selected_clock_reference(self):
        fixture, clock, value, use, adapter = self.fixture()
        changed = copy.deepcopy(use); changed['registration_sha256'] = 'b' * 64
        with self.assertRaises(common.ContractError):
            adapter(changed, stamp(600))

    def test_resolver_byte_substitution_does_not_pass_from_a_matching_shape(self):
        fixture, clock, value, use, adapter = self.fixture()
        fixture.rows[use['reference']['sha256']] = common.canonical_bytes(original(test_end=7200))
        with self.assertRaises(common.ContractError):
            adapter(use, stamp(600))

    def test_expiry_during_resolution_is_not_accepted_on_old_time(self):
        fixture, clock, value, use, adapter = self.fixture()
        resolve = fixture.resolve
        def late(*args, **kwargs):
            raw = resolve(*args, **kwargs); clock.current = stamp(7260); return raw
        fixture.resolve = late
        with self.assertRaises(common.ContractError):
            adapter(use, stamp(600))
