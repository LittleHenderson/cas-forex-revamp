"""Source-authored public regressions. NOT_RUN during preparation."""
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'source_runtime'))
import launch_common as c
import source_runtime_common as s

import source_test_launcher as launcher
import source_test_namespace_observer as observer

class NamespaceReceiptTests(unittest.TestCase):
    def fixture(self):
        subject={'pid':300,'start_ticks':900,'uid':62000}
        config={'original_clock':{'path':'/clock','bytes':1,'sha256':'a'*64},
            'clock_domain':{'boot_id':'selected'},'clock_anchor_stamp':{'utc':'2030-01-01T00:00:01.000000Z','boottime_ns':100},
            'work_started_utc':'2030-01-01T00:00:00Z','work_deadline_utc':'2030-01-01T03:40:00Z'}
        proof={'observed_at_utc':'2030-01-01T00:00:02.000000Z','public_fixture':True}
        return subject,config,proof
    def receipt(self,subject,config,proof):
        def identity(pid):return subject if pid==300 else {'pid':pid,'start_ticks':30,'uid':0}
        with patch.object(c,'process_identity',side_effect=identity),patch.object(c,'pinned',return_value=(b'original',None)),patch.object(observer,'observe_host_user_namespace',return_value=proof):
            return launcher.approval_receipt(b'config',config,{'subject':subject},b'manifest',c)
    def test_receipt_uses_v2(self):
        self.assertEqual(self.receipt(*self.fixture())['format'],'forex.source-test-launch-approval/2')
    def test_exact_root_observation_retained(self):
        subject,config,proof=self.fixture();receipt=self.receipt(subject,config,proof)
        self.assertEqual(receipt['host_user_namespace_proof'],proof)
    def test_receipt_time_is_actual_observation_time(self):
        subject,config,proof=self.fixture();receipt=self.receipt(subject,config,proof)
        self.assertEqual(receipt['observed_at_utc'],proof['observed_at_utc'])
    def test_pid_reuse_cannot_produce_receipt(self):
        subject,config,proof=self.fixture()
        with patch.object(c,'process_identity',return_value={**subject,'start_ticks':901}):
            with self.assertRaises(RuntimeError):launcher.approval_receipt(b'config',config,{'subject':subject},b'manifest',c)
    def test_root_workload_cannot_produce_receipt(self):
        subject,config,proof=self.fixture();subject['uid']=0
        with patch.object(c,'process_identity',return_value=subject):
            with self.assertRaises(RuntimeError):launcher.approval_receipt(b'config',config,{'subject':subject},b'manifest',c)
    def test_failed_native_observer_cannot_be_relabelled(self):
        subject,config,proof=self.fixture()
        with patch.object(c,'process_identity',return_value=subject),patch.object(c,'pinned',return_value=(b'x',None)),patch.object(observer,'observe_host_user_namespace',side_effect=PermissionError):
            with self.assertRaises(PermissionError):launcher.approval_receipt(b'config',config,{'subject':subject},b'manifest',c)
    def test_boolean_zero_model_limit_rejected(self):
        with self.assertRaises(RuntimeError):c.guards({'execution_mode':'STAGE_A_ONLY','model_launch_allowed':False,
                                                       'model_inference_calls_limit':False,'stage_b_status':'BLOCKED'})

