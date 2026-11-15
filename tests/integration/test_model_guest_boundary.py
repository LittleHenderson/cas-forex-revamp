"""AUTHORED/NOT_RUN. No subprocess, Linux mount change, inference or cloud call."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from model_guest_boundary import PHASES, PhaseGate, config_contract, load
from approved_model_launcher import launch_argv


def configuration():
    return dict(schema='forex.stage-b-guest/1', execution_mode='STAGE_B_ONLY', run_id='fx-b-'+'a'*16,
        model_launch_allowed=True, model_inference_calls_limit=32, u1_inference_calls_limit=0,
        source_directory='/opt/cas-forex/fx-b-'+'a'*16+'/source', models_directory='/opt/cas-forex/fx-b-'+'a'*16+'/models',
        state_directory='/var/lib/cas-forex-fx-b-'+'a'*16, t0_utc='2030-01-01T00:00:00Z',
        bootstrap_started_utc='2030-01-01T00:01:00Z', test_deadline_utc='2030-01-01T02:01:00Z',
        work_deadline_utc='2030-01-01T03:40:00Z', seed=7, files=[{'path':'placeholder'}], role_files=[{}]*8,
        isolation=dict(channel_id='development-channel',issuer_binding_sha256='a'*64,observer_binding_sha256='b'*64,
            boot_id='00000000-0000-0000-0000-000000000001',
            authority_path='/opt/cas-forex/fx-b-'+'a'*16+'/authority.json',
            release_path='/opt/cas-forex/fx-b-'+'a'*16+'/release.json',
            probe_paths=['/opt/cas-forex/fx-b-'+'a'*16+'/development-'+str(i) for i in range(5)]))


class GuestBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.cfg=configuration(); self.now=datetime(2030,1,1,0,2,tzinfo=timezone.utc)

    def test_new_identity_accepts_only_configuration_shape(self):
        self.assertEqual(config_contract(self.cfg,now=self.now)[1].hour,3)

    def test_a_identity_cannot_be_repurposed(self):
        self.cfg['run_id']='fx-20261010-8e1a63c5'
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_missing_isolation_blocks_before_role_start(self):
        del self.cfg['isolation']
        with self.assertRaises(RuntimeError):config_contract(self.cfg,now=self.now)

    def test_external_authority_cannot_escape_selected_run(self):
        self.cfg['isolation']['authority_path']='/tmp/development-authority.json'
        with self.assertRaises(RuntimeError):config_contract(self.cfg,now=self.now)

    def test_self_verified_isolation_flag_is_not_configuration(self):
        self.cfg['isolation']['verified']=True
        with self.assertRaises(RuntimeError):config_contract(self.cfg,now=self.now)

    def test_time_extension_rejected(self):
        self.cfg['work_deadline_utc']='2030-01-01T03:41:00Z'
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_restarted_test_clock_rejected(self):
        self.cfg['test_deadline_utc']='2030-01-01T02:02:00Z'
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_u1_cannot_borrow_acceptance_calls(self):
        self.cfg['u1_inference_calls_limit']=1
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_bool_is_not_u1_zero_budget(self):
        self.cfg['u1_inference_calls_limit']=False
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_more_model_calls_rejected(self):
        self.cfg['model_inference_calls_limit']=35
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_missing_offset_rejected(self):
        self.cfg['t0_utc']='2030-01-01T00:00:00'
        with self.assertRaises(RuntimeError): config_contract(self.cfg,now=self.now)

    def test_duplicate_receipt_fields_rejected(self):
        with self.assertRaises(RuntimeError): load(b'{"approved":false,"approved":true}')

    def test_nonfinite_receipt_fields_rejected(self):
        with self.assertRaises(RuntimeError): load(b'{"value":NaN}')

    def test_launcher_enforces_namespace_and_group_shutdown(self):
        argv=launch_argv(self.cfg,'/opt/config.json','a'*64,60)
        for value in ('PrivateNetwork=yes','NoNewPrivileges=yes','KillMode=control-group','Restart=no','RuntimeMaxSec=60','ProtectSystem=strict'):
            self.assertIn('--property='+value,argv)
        self.assertIn(self.cfg['source_directory']+'/approved_model_driver.py',argv)

    def test_launcher_cannot_start_after_deadline(self):
        with self.assertRaises(RuntimeError): launch_argv(self.cfg,'/opt/config.json','a'*64,0)

    def test_phase_gate_checks_exact_budget_and_monotonic_time(self):
        elapsed=[0]
        gate=PhaseGate(self.cfg,'probe',clock=lambda:self.now,monotonic=lambda:elapsed[0])
        budget=SimpleNamespace(**dict(zip(('max_calls','max_input_tokens_per_call','max_generated_tokens_per_call','max_seconds_per_call','max_total_seconds'),PHASES['probe'])))
        invocation=SimpleNamespace(budget=budget,model=SimpleNamespace(model_id='qwen3:0.6b',reasoning_effort='disabled'),seed=7)
        gate(invocation)
        elapsed[0]=600
        with self.assertRaises(RuntimeError): gate(invocation)

    def test_phase_gate_rejects_changed_seed(self):
        gate=PhaseGate(self.cfg,'probe',clock=lambda:self.now)
        budget=SimpleNamespace(**dict(zip(('max_calls','max_input_tokens_per_call','max_generated_tokens_per_call','max_seconds_per_call','max_total_seconds'),PHASES['probe'])))
        invocation=SimpleNamespace(budget=budget,model=SimpleNamespace(model_id='qwen3:0.6b',reasoning_effort='disabled'),seed=8)
        with self.assertRaises(RuntimeError): gate(invocation)
