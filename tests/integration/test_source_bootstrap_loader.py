"""Public bootstrap-boundary regressions. All authored tests are NOT_RUN."""
import copy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import source_test_bootstrap as entry
from operational_test_group import original_test_deadline, utc


def config():
    key = bytes(32)
    pin = {'path': '/public/value', 'bytes': 1, 'sha256': 'a'*64}
    result = {k: copy.deepcopy(pin) for k in ('source_manifest', 'completion_material',
                                             'completion_selection', 'original_clock')}
    result.update(format='forex.source-test-bootstrap/1', execution_mode='STAGE_A_ONLY',
        model_launch_allowed=False, model_inference_calls_limit=0, stage_b_status='BLOCKED',
        source_directory='/public/source', capture_directory='/public/capture',
        approval_path='/public/approval', public_keys={entry.sha(key): key.hex()},
        custody_config={}, selection_use={}, clock_domain={}, clock_anchor_stamp={},
        work_started_utc='2030-01-01T00:00:00.000000Z',
        work_deadline_utc='2030-01-01T03:40:00.000000Z', environment={},
        environment_profile_sha256=entry.sha(entry.canonical({})),
        parser_component_sha256='b'*64, parser_schema_sha256={
            'forex.python-framework-report/2': 'c'*64,
            'forex.node-tap-report/1': 'd'*64,
            'forex.node-version-report/1': 'e'*64},
        attempt_directory={'path': '/public/attempts', 'device': 1, 'inode': 2,
                           'uid': 1000, 'gid': 1000, 'mode': 0o700})
    return result


class LoaderShapeTests(unittest.TestCase):
    def test_exact_parser_schema_mapping_constructs_real_observer(self):
        from cas_forex_measurement.completion import CompletionObserver
        value = entry.validate_config(config())
        selected = value['parser_schema_sha256']
        observer = CompletionObserver(resolver=None, publishers={},
            publish_record=lambda *a, **k: None, guard=None,
            original_clock_verifier=lambda *a, **k: None,
            environment={}, environment_profile_sha256=entry.sha(entry.canonical({})),
            process_capture=None, observer_id='public-observer',
            parser_component_sha256=value['parser_component_sha256'],
            authenticate_selection=lambda *a, **k: None,
            parser_schema_sha256=selected)
        self.assertEqual(observer.parser_schema_sha256, selected)
        selected['forex.node-tap-report/1'] = 'f'*64
        self.assertEqual(observer.parser_schema_sha256['forex.node-tap-report/1'], 'd'*64)
    def test_scalar_parser_schema_hash_is_rejected(self):
        value = config(); value['parser_schema_sha256'] = 'c'*64
        with self.assertRaisesRegex(entry.BootstrapUnavailable, 'PARSER_SCHEMA_FORMATS'):
            entry.validate_config(value)
    def test_missing_report_schema_is_rejected_for_each_format(self):
        for report_format in config()['parser_schema_sha256']:
            with self.subTest(report_format=report_format):
                value = config(); del value['parser_schema_sha256'][report_format]
                with self.assertRaisesRegex(entry.BootstrapUnavailable, 'PARSER_SCHEMA_FORMATS'):
                    entry.validate_config(value)
    def test_extra_or_wrong_report_format_is_rejected(self):
        for report_format in ('forex.python-framework-report/1', 'unexpected'):
            with self.subTest(report_format=report_format):
                value = config(); value['parser_schema_sha256'][report_format] = 'c'*64
                with self.assertRaisesRegex(entry.BootstrapUnavailable, 'PARSER_SCHEMA_FORMATS'):
                    entry.validate_config(value)
    def test_nonmapping_parser_schemas_are_rejected(self):
        for supplied in (None, False, [], [('forex.node-tap-report/1', 'c'*64)]):
            with self.subTest(supplied=supplied):
                value = config(); value['parser_schema_sha256'] = supplied
                with self.assertRaisesRegex(entry.BootstrapUnavailable, 'PARSER_SCHEMA_FORMATS'):
                    entry.validate_config(value)
    def test_each_report_schema_requires_exact_lowercase_sha256(self):
        for report_format in config()['parser_schema_sha256']:
            for supplied in (None, False, 1, {}, 'C'*64, 'c'*63, 'c'*64+'\n', 'g'*64):
                with self.subTest(report_format=report_format, supplied=supplied):
                    value = config(); value['parser_schema_sha256'][report_format] = supplied
                    with self.assertRaisesRegex(entry.BootstrapUnavailable, 'PARSER_SCHEMA_HASH'):
                        entry.validate_config(value)
    def test_python_driver_accepts_source_clock_without_model_fields(self):
        record = {'format': 'forex.original-source-test-clock/1',
            'bootstrap_started_utc': '2030-01-01T00:00:00Z',
            'test_deadline_utc': '2030-01-01T02:00:00Z'}
        self.assertEqual(original_test_deadline(record, now=utc('2030-01-01T01:00:00Z')),
                         utc(record['test_deadline_utc']))
    def test_python_driver_rejects_extra_model_fields_in_source_clock(self):
        record = {'format': 'forex.original-source-test-clock/1', 'model_calls': 32,
            'bootstrap_started_utc': '2030-01-01T00:00:00Z',
            'test_deadline_utc': '2030-01-01T02:00:00Z'}
        with self.assertRaises(RuntimeError):
            original_test_deadline(record, now=utc('2030-01-01T01:00:00Z'))
    def test_python_source_clock_cannot_reset_original_deadline(self):
        record = {'format': 'forex.original-source-test-clock/1',
            'bootstrap_started_utc': '2030-01-01T00:00:00Z',
            'test_deadline_utc': '2030-01-01T02:00:00Z'}
        with self.assertRaises(RuntimeError):
            original_test_deadline(record, now=utc(record['test_deadline_utc']))
    def test_closed_public_config_accepts_zero_model_only(self):
        self.assertEqual(entry.validate_config(config()), config())
    def test_unknown_module_field_is_rejected(self):
        value = config(); value['module'] = 'arbitrary'
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_true_model_permission_is_rejected(self):
        value = config(); value['model_launch_allowed'] = True
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_boolean_zero_call_limit_is_rejected(self):
        value = config(); value['model_inference_calls_limit'] = False
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_private_key_field_is_rejected(self):
        value = config(); value['private_key'] = 'public-test-placeholder'
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_public_key_hash_mismatch_is_rejected(self):
        value = config(); value['public_keys'] = {'a'*64: bytes(32).hex()}
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_inherited_pythonpath_is_not_an_allowed_child_environment(self):
        value = config(); value['environment'] = {'PYTHONPATH': '/arbitrary'}
        value['environment_profile_sha256'] = entry.sha(entry.canonical(value['environment']))
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_environment_hash_substitution_is_rejected(self):
        value = config(); value['environment']['TZ'] = 'UTC'
        with self.assertRaises(entry.BootstrapUnavailable): entry.validate_config(value)
    def test_duplicate_json_member_is_rejected(self):
        with self.assertRaises(entry.BootstrapUnavailable): entry.decode(b'{"x":1,"x":2}')
    def test_float_json_is_rejected(self):
        with self.assertRaises(entry.BootstrapUnavailable): entry.decode(b'{"x":1.5}')
    def test_canonical_bytes_are_required_for_config(self):
        with self.assertRaises(entry.BootstrapUnavailable): entry.decode(b'{ "x":1 }')
    def test_existing_readable_manifest_json_can_be_decoded(self):
        self.assertEqual(entry.decode(b'{ "x":1 }', canonical_required=False), {'x': 1})
    def test_parent_escape_is_rejected(self):
        for path in ('../x', 'a/../x', '/absolute', 'a//b', 'a\\b'):
            with self.assertRaises(entry.BootstrapUnavailable): entry.relative(path)
    def test_absolute_path_alias_is_rejected(self):
        for path in ('relative', '/a/../b', '/a//b', '/a/./b'):
            with self.assertRaises(entry.BootstrapUnavailable): entry.absolute(path)
    def test_private_or_credential_member_names_are_excluded_before_read(self):
        for path in ('.aws/config', 'source/.env.local', 'stage-b-sealed/cases.json', 'source/private.key'):
            with self.assertRaises(entry.BootstrapUnavailable): entry.relative(path)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.c = config()
        self.c['clock_domain'] = {'boot_id': '00000000-0000-0000-0000-000000000001'}
        self.c['clock_anchor_stamp'] = {'utc': '2030-01-01T00:01:00.000000Z', 'boottime_ns': 10}
        self.raw = entry.canonical(self.c); self.manifest = b'public-manifest'; self.clock = b'public-clock'
        self.subject = {'pid': 111, 'start_ticks': 22, 'uid': 1000}
        self.supervisor = {'pid': 222, 'start_ticks': 33, 'uid': 0}
        self.receipt = {'format': 'forex.source-test-launch-approval/2',
            'decision': 'ALLOW_SOURCE_TESTS_ONCE', 'invocation_id': 'public-attempt-0001',
            'config_sha256': entry.sha(self.raw), 'source_manifest_sha256': entry.sha(self.manifest),
            'original_clock_sha256': entry.sha(self.clock), 'clock_domain': self.c['clock_domain'],
            'clock_anchor_stamp': self.c['clock_anchor_stamp'],
            'work_started_utc': self.c['work_started_utc'], 'work_deadline_utc': self.c['work_deadline_utc'],
            'subject': self.subject, 'supervisor': self.supervisor,
            'observed_at_utc': '2030-01-01T00:01:01.000000Z'}
        self.namespace_state = {'device': 4, 'inode': 4026531837,
                                'uid_map_hex': b'         0          0 4294967295\n'.hex()}
        self.namespace_observation = {'subject': self.subject, 'thread_id': 111,
            'boot_id': self.c['clock_domain']['boot_id'], 'state': self.namespace_state}
        self.receipt['host_user_namespace_proof'] = {
            'format': 'forex.source-test-host-user-namespace/1',
            'boot_id': self.c['clock_domain']['boot_id'],
            'observed_at_utc': self.receipt['observed_at_utc'],
            'host_init': {'process': {'pid': 1, 'start_ticks': 1, 'uid': 0},
                          'state': copy.deepcopy(self.namespace_state)},
            'supervisor': {'process': self.supervisor, 'state': copy.deepcopy(self.namespace_state)},
            'subject': {'process': self.subject, 'state': copy.deepcopy(self.namespace_state)}}
        self.gate = entry.RootSelectedExecutionGate(config_raw=self.raw, config_identity=('config',),
            config_path='/public/config', config=self.c, source_manifest_raw=self.manifest,
            original_clock_raw=self.clock,
            clock=lambda: {'utc': '2030-01-01T00:01:02.000000Z', 'boottime_ns': 12})
        def read(path, **kwargs):
            return (self.raw, ('config',)) if path == '/public/config' else (entry.canonical(self.receipt), ('approval',))
        self.read = patch.object(entry, 'protected_read', side_effect=read)
        self.pid = patch.object(entry.os, 'getpid', return_value=111)
        self.identity = patch.object(entry, 'process_identity',
            side_effect=lambda pid: self.subject if pid == 111 else self.supervisor)
        self.namespace = patch.object(entry, 'observe_current_user_namespace', return_value=self.namespace_observation)
        for p in (self.read, self.pid, self.identity, self.namespace): p.start(); self.addCleanup(p.stop)
    def test_constructing_gate_reads_and_approves_nothing(self):
        self.assertIsNone(self.gate.receipt_raw)
    def test_exact_external_per_process_receipt_is_retained(self):
        self.assertIsNone(self.gate())
        self.assertEqual(self.gate.receipt_raw, entry.canonical(self.receipt))
    def test_self_asserted_config_without_external_receipt_fails(self):
        with patch.object(entry, 'protected_read', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError): self.gate()
        self.assertTrue(self.gate.failed)
    def test_another_process_receipt_is_rejected(self):
        self.receipt['subject'] = {'pid': 333, 'start_ticks': 22, 'uid': 1000}
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_nonroot_approver_is_rejected(self):
        self.receipt['supervisor'] = {'pid': 222, 'start_ticks': 33, 'uid': 1000}
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_mapped_namespace_root_is_not_host_approval(self):
        with patch.object(entry, 'observe_current_user_namespace',
                          side_effect=entry.BootstrapUnavailable('namespace mismatch')):
            with self.assertRaises(entry.BootstrapUnavailable): self.gate()
        self.assertTrue(self.gate.failed)
    def test_legacy_receipt_without_namespace_proof_is_rejected(self):
        self.receipt['format'] = 'forex.source-test-launch-approval/1'
        del self.receipt['host_user_namespace_proof']
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
        self.assertTrue(self.gate.failed)
    def test_changed_own_namespace_during_gate_is_terminal(self):
        changed = copy.deepcopy(self.namespace_observation)
        changed['state']['inode'] += 1
        with patch.object(entry, 'observe_current_user_namespace',
                          side_effect=[self.namespace_observation, changed]):
            with self.assertRaises(entry.BootstrapUnavailable): self.gate()
        self.assertTrue(self.gate.failed)
    def test_proof_for_another_boot_is_rejected(self):
        self.receipt['host_user_namespace_proof']['boot_id'] = '00000000-0000-0000-0000-000000000002'
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_proof_subject_start_time_must_match_current_process(self):
        self.receipt['host_user_namespace_proof']['subject']['process'] = {
            **self.subject, 'start_ticks': self.subject['start_ticks'] + 1}
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_dead_supervisor_is_rejected(self):
        with patch.object(entry, 'process_identity', side_effect=ProcessLookupError):
            with self.assertRaises(ProcessLookupError): self.gate()
    def test_changed_source_hash_is_rejected(self):
        self.receipt['source_manifest_sha256'] = '0'*64
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_future_approval_observation_is_rejected(self):
        self.receipt['observed_at_utc'] = '2030-01-01T00:02:00.000000Z'
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_replaced_receipt_is_terminal(self):
        self.gate(); self.receipt['invocation_id'] = 'public-attempt-0002'
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
        self.receipt['invocation_id'] = 'public-attempt-0001'
        with self.assertRaises(entry.BootstrapUnavailable): self.gate()
    def test_clock_failure_does_not_refresh_authority(self):
        self.gate.clock = lambda: (_ for _ in ()).throw(RuntimeError('clock unavailable'))
        with self.assertRaises(RuntimeError): self.gate()
        self.assertTrue(self.gate.failed)
    def test_contention_fails_without_wait(self):
        self.gate.lock.acquire()
        try:
            with self.assertRaises(entry.BootstrapUnavailable): self.gate()
        finally: self.gate.lock.release()
        self.assertTrue(self.gate.failed)


class AttemptTests(unittest.TestCase):
    def test_durable_attempt_cannot_be_reused_or_deleted_by_failure(self):
        # Future Linux test uses only its own temporary retained fixture.
        with tempfile.TemporaryDirectory() as directory:
            info = os.stat(directory)
            c = {'attempt_directory': {'path': directory, 'device': info.st_dev, 'inode': info.st_ino,
                                      'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o700}}
            receipt = entry.canonical({'invocation_id': 'public-attempt-0001', 'subject': {'pid': 1}})
            class Gate:
                receipt_raw = receipt
                config_raw = b'public-config'
                def __call__(self): pass
            gate = Gate(); entry.claim_source_attempt(c, gate)
            path = Path(directory, 'source-test-attempt-public-attempt-0001.json')
            before = path.read_bytes()
            with self.assertRaises(FileExistsError): entry.claim_source_attempt(c, gate)
            self.assertEqual(path.read_bytes(), before)
    def test_changed_attempt_directory_identity_prevents_write(self):
        with tempfile.TemporaryDirectory() as directory:
            info = os.stat(directory)
            c = {'attempt_directory': {'path': directory, 'device': info.st_dev, 'inode': info.st_ino + 1,
                                      'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o700}}
            gate = SimpleNamespace(receipt_raw=b'{}')
            class Gate:
                receipt_raw = entry.canonical({'invocation_id': 'public-attempt-0001'})
                def __call__(self): pass
            with self.assertRaises(entry.BootstrapUnavailable): entry.claim_source_attempt(c, Gate())
            self.assertEqual(list(Path(directory).iterdir()), [])
