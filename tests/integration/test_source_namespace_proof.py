"""Public namespace-proof regressions, AUTHORED/NOT_RUN; no real proof fixtures."""
import copy
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import source_test_bootstrap as entry
import source_test_namespace_observer as producer

class BoundedNativeReadTests(unittest.TestCase):
    def test_short_reads_are_joined_through_actual_eof(self):
        class ShortReader:
            def __init__(self):self.parts=iter([b'0 0 ',b'4294967295\n',b''])
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,maximum):return next(self.parts)
        for function in (entry._bounded_proc_bytes,producer._read):
            with patch('builtins.open',return_value=ShortReader()):
                self.assertEqual(function('/public/proc-fixture',256),b'0 0 4294967295\n')
    def test_tail_past_maximum_is_rejected(self):
        for function in (entry._bounded_proc_bytes,producer._read):
            with patch('builtins.open',return_value=io.BytesIO(b'x'*257)):
                with self.assertRaises(RuntimeError):function('/public/proc-fixture',256)
    def test_empty_native_value_is_rejected(self):
        for function in (entry._bounded_proc_bytes,producer._read):
            with patch('builtins.open',return_value=io.BytesIO(b'')):
                with self.assertRaises(RuntimeError):function('/public/proc-fixture',256)


BOOT='00000000-0000-0000-0000-000000000001'
DOMAIN={'boot_id':BOOT,'time_namespace_inode':42,'clock_id':'CLOCK_BOOTTIME'}
STAMP={'utc':'2030-01-01T00:00:02.000000Z','boottime_ns':2_000_000_000}
MAP=b'         0          0 4294967295\n'
STATE={'device':4,'inode':4026531837,'uid_map_hex':MAP.hex()}
SUBJECT={'pid':111,'start_ticks':22,'uid':1000}
SUPERVISOR={'pid':222,'start_ticks':33,'uid':0}
INIT={'pid':1,'start_ticks':1,'uid':0}

def fixture():
    receipt={'subject':dict(SUBJECT),'supervisor':dict(SUPERVISOR),
             'clock_domain':dict(DOMAIN),'observed_at_utc':STAMP['utc']}
    proof={'format':'forex.source-test-host-user-namespace/1','boot_id':BOOT,
           'observed_at_utc':STAMP['utc'],
           'host_init':{'process':dict(INIT),'state':dict(STATE)},
           'supervisor':{'process':dict(SUPERVISOR),'state':dict(STATE)},
           'subject':{'process':dict(SUBJECT),'state':dict(STATE)}}
    observed={'subject':dict(SUBJECT),'thread_id':111,'boot_id':BOOT,'state':dict(STATE)}
    return receipt,proof,observed

class ProofBindingTests(unittest.TestCase):
    def setUp(self):self.receipt,self.proof,self.observed=fixture()
    def check(self):
        return entry.require_initial_user_namespace(self.proof,receipt=self.receipt,observed=self.observed)
    def test_exact_authenticated_container_and_current_state_match(self):
        self.assertIsNone(self.check())  # Pure comparison; not an authority receipt.
    def test_same_inode_on_different_device_is_rejected(self):
        self.observed['state']['device']+=1
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_current_namespace_change_is_rejected(self):
        self.observed['state']['inode']+=1
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_subject_reuse_with_different_start_ticks_is_rejected(self):
        self.proof['subject']['process']['start_ticks']+=1
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_wrong_supervisor_is_rejected(self):
        self.proof['supervisor']['process']['pid']+=1
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_host_reference_requires_root_pid_one(self):
        for key,value in (('pid',2),('uid',1000)):
            receipt,proof,observed=fixture();proof['host_init']['process'][key]=value
            with self.assertRaises(entry.BootstrapUnavailable):
                entry.require_initial_user_namespace(proof,receipt=receipt,observed=observed)
    def test_mapped_namespace_uid_map_is_rejected(self):
        for label in ('host_init','supervisor','subject'):
            receipt,proof,observed=fixture()
            proof[label]['state']['uid_map_hex']=b'0 1000 1\n'.hex()
            with self.assertRaises(entry.BootstrapUnavailable):
                entry.require_initial_user_namespace(proof,receipt=receipt,observed=observed)
    def test_stale_boot_observation_is_rejected(self):
        self.proof['boot_id']='00000000-0000-0000-0000-000000000002'
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_proof_time_must_be_exact_receipt_observation(self):
        self.proof['observed_at_utc']='2030-01-01T00:00:01.000000Z'
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_extra_proof_or_state_fields_are_rejected(self):
        self.proof['verified']=True
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
        del self.proof['verified'];self.proof['subject']['state']['verified']=True
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_boolean_identity_is_not_integer_observation(self):
        self.proof['host_init']['process']['pid']=True
        with self.assertRaises(entry.BootstrapUnavailable):self.check()
    def test_partial_or_malformed_uid_map_evidence_is_rejected(self):
        for value in ('', '0', 'GG', 'ff'*257, None):
            receipt,proof,observed=fixture();proof['subject']['state']['uid_map_hex']=value
            with self.assertRaises(entry.BootstrapUnavailable):
                entry.require_initial_user_namespace(proof,receipt=receipt,observed=observed)

class NativeSelfObservationTests(unittest.TestCase):
    def setUp(self):
        self.paths=[]
        def read(path,maximum):
            self.paths.append(path)
            if path=='/proc/thread-self/uid_map':return MAP
            if path=='/proc/sys/kernel/random/boot_id':return (BOOT+'\n').encode()
            raise AssertionError('Unexpected non-self native read: '+path)
        def stat(path):
            self.paths.append(path)
            if path!='/proc/thread-self/ns/user':raise AssertionError('Unexpected namespace read: '+path)
            return SimpleNamespace(st_dev=4,st_ino=4026531837)
        patches=[patch.object(entry.sys,'platform','linux'),patch.object(entry.os,'getpid',return_value=111),
                 patch.object(entry.os,'getuid',return_value=1000),patch.object(entry.os,'geteuid',return_value=1000),
                 patch.object(entry.threading,'get_native_id',return_value=111),
                 patch.object(entry,'process_identity',return_value=dict(SUBJECT)),
                 patch.object(entry,'_bounded_proc_bytes',side_effect=read),
                 patch.object(entry.os,'stat',side_effect=stat)]
        for p in patches:p.start();self.addCleanup(p.stop)
    def test_self_observation_never_dereferences_other_user_namespace(self):
        self.assertEqual(entry.observe_current_user_namespace(),fixture()[2])
        self.assertTrue(self.paths)
        self.assertFalse(any('/proc/1/' in p or '/proc/222/' in p for p in self.paths))
    def test_permission_failure_is_propagated_without_fallback(self):
        with patch.object(entry.os,'stat',side_effect=PermissionError):
            with self.assertRaises(PermissionError):entry.observe_current_user_namespace()
    def test_namespace_switch_during_map_read_is_rejected(self):
        with patch.object(entry.os,'stat',side_effect=[
                SimpleNamespace(st_dev=4,st_ino=1),SimpleNamespace(st_dev=4,st_ino=2)]):
            with self.assertRaises(entry.BootstrapUnavailable):entry.observe_current_user_namespace()
    def test_process_change_during_local_observation_is_rejected(self):
        with patch.object(entry,'process_identity',side_effect=[dict(SUBJECT),{**SUBJECT,'start_ticks':23}]):
            with self.assertRaises(entry.BootstrapUnavailable):entry.observe_current_user_namespace()
    def test_effective_uid_difference_is_rejected(self):
        with patch.object(entry.os,'geteuid',return_value=0):
            with self.assertRaises(entry.BootstrapUnavailable):entry.observe_current_user_namespace()
    def test_nonidentity_map_is_rejected_before_receipt_trust(self):
        with patch.object(entry,'_bounded_proc_bytes',return_value=b'0 1000 1\n'):
            with self.assertRaises(entry.BootstrapUnavailable):entry.observe_current_user_namespace()

class RootProducerTests(unittest.TestCase):
    def setUp(self):
        self.rows={1:{'process':dict(INIT),'state':dict(STATE)},
                   222:{'process':dict(SUPERVISOR),'state':dict(STATE)},
                   111:{'process':dict(SUBJECT),'state':dict(STATE)}}
        self.clock_start={'utc':'2030-01-01T00:00:01.000000Z','boottime_ns':1_000_000_000}
        patches=[patch.object(producer.sys,'platform','linux'),
                 patch.object(producer.os,'getuid',return_value=0),patch.object(producer.os,'geteuid',return_value=0),
                 patch.object(producer.os,'getpid',return_value=222),
                 patch.object(producer,'_process',return_value=dict(SUPERVISOR)),
                 patch.object(producer,'_row',side_effect=lambda pid:copy.deepcopy(self.rows[pid])),
                 patch.object(producer,'_observe',side_effect=[(dict(DOMAIN),dict(self.clock_start)),(dict(DOMAIN),dict(STAMP))])]
        for p in patches:p.start();self.addCleanup(p.stop)
    def observe(self):
        return producer.observe_host_user_namespace(subject=SUBJECT,supervisor=SUPERVISOR,
            clock_domain=DOMAIN,clock_anchor_stamp={'utc':'2030-01-01T00:00:00.000000Z','boottime_ns':0})
    def test_producer_observation_matches_consumer_shape(self):
        proof=self.observe();receipt,unused,observed=fixture()
        self.assertIsNone(entry.require_initial_user_namespace(proof,receipt=receipt,observed=observed))
    def test_nonroot_producer_cannot_assert_host_proof(self):
        with patch.object(producer.os,'getuid',return_value=1000):
            with self.assertRaises(RuntimeError):self.observe()
    def test_producer_requires_exact_selected_supervisor(self):
        with patch.object(producer,'_process',return_value={**SUPERVISOR,'start_ticks':34}):
            with self.assertRaises(RuntimeError):self.observe()
    def test_host_and_subject_namespace_mismatch_blocks_production(self):
        self.rows[111]['state']['inode']+=1
        with self.assertRaises(RuntimeError):self.observe()
    def test_second_native_read_change_blocks_production(self):
        reads=[copy.deepcopy(self.rows[p]) for p in (1,222,111,1,222,111)]
        reads[-1]['process']['start_ticks']+=1
        with patch.object(producer,'_row',side_effect=reads):
            with self.assertRaises(RuntimeError):self.observe()
    def test_boot_change_during_root_observation_blocks_production(self):
        changed={**DOMAIN,'boot_id':'00000000-0000-0000-0000-000000000002'}
        with patch.object(producer,'_observe',side_effect=[(DOMAIN,self.clock_start),(changed,STAMP)]):
            with self.assertRaises(RuntimeError):self.observe()
    def test_slow_root_observation_cannot_create_proof(self):
        late={'utc':'2030-01-01T00:00:03.000000Z','boottime_ns':3_000_000_000}
        with patch.object(producer,'_observe',side_effect=[(DOMAIN,self.clock_start),(DOMAIN,late)]):
            with self.assertRaises(RuntimeError):self.observe()
    def test_native_permission_error_is_never_converted_to_success(self):
        with patch.object(producer,'_row',side_effect=PermissionError):
            with self.assertRaises(PermissionError):self.observe()

