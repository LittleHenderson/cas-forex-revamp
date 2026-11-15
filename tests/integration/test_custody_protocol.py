"""AUTHORED/NOT_RUN. Visible synthetic fixtures; no sealed data or OS changes."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.contracts import ContractError,content_digest
from cas_forex_revamp.composition.custody_protocol import (
    contract,envelope,validate_message,validate_release,ReleaseLedger,public_aggregate)
from cas_forex_revamp.composition.role_channel import unpack_json

NOW=datetime(2030,1,1,tzinfo=timezone.utc)
H='a'*64


def binding():
    return {'run_id':'development-run','channel_id':'development-channel','epoch':1,
            'scope_sha256':H,'release_receipt_sha256':H,'expires_at_utc':'2030-01-01T01:00:00Z'}


def frame():
    packet={'schema':'forex.current-decision-packet/2','request_id':'development-request',
        'opportunity_set_id':'development-opportunity','source_state_id':'development-state','state':{},
        'options':[],'facts':[],'evidence':[],'exact_request_sha256':H}
    p={'delivery_id':'development-delivery','opportunity_set_id':packet['opportunity_set_id'],
        'current_packet':packet,'current_packet_sha256':content_digest(packet),
        'source_state_reference_sha256':content_digest({}),
        'current_policy_binding_sha256':H,'current_context_binding_sha256':H,
        'current_venue_readback_sha256':H,'current_evidence_bundle_sha256':H}
    return envelope('CURRENT_FRAME',p,binding=binding(),request_id=packet['request_id'],sequence=1,now=NOW)


def release():
    r={k: H if t=='sha256' else 'development-'+k if t=='opaque_id' else 1 if t=='positive_integer'
       else '2030-01-01T00:00:00Z' for k,t in contract('release')['required_receipt_fields'].items()}
    r.update(format='forex.custody-release-receipt/2',expires_at_utc='2030-01-01T01:00:00Z')
    expected={k:v for k,v in r.items() if k not in {'format','release_id','issued_at_utc','not_before_utc','expires_at_utc'}}
    return r,expected


class CurrentProtocolTests(unittest.TestCase):
    def check(self,value):return validate_message(value,binding=binding(),now=NOW)
    def test_current_packet_shape_is_accepted(self):self.assertEqual(self.check(frame())['kind'],'CURRENT_FRAME')
    def test_future_schedule_rejected_even_after_rehash(self):
        f=frame();f['payload']['schedule']=[];f['payload_sha256']=content_digest(f['payload'])
        with self.assertRaises(ContractError):self.check(f)
    def test_future_packet_field_rejected(self):
        f=frame();f['payload']['current_packet']['expected_state']={}
        f['payload']['current_packet_sha256']=content_digest(f['payload']['current_packet']);f['payload_sha256']=content_digest(f['payload'])
        with self.assertRaises(ContractError):self.check(f)
    def test_wrong_scope_rejected(self):
        f=frame();f['scope_sha256']='b'*64
        with self.assertRaises(ContractError):self.check(f)
    def test_boolean_sequence_rejected(self):
        f=frame();f['sequence']=True
        with self.assertRaises(ContractError):self.check(f)
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ContractError):unpack_json(b'{"kind":"CURRENT_FRAME","kind":"DECISION_RESULT"}')
    def test_expired_frame_rejected(self):
        f=frame();f['expires_at_utc']='2029-12-31T23:59:59Z'
        with self.assertRaises(ContractError):self.check(f)
    def test_changed_payload_rejected(self):
        f=frame();f['payload']['current_context_binding_sha256']='c'*64
        with self.assertRaises(ContractError):self.check(f)
    def test_complete_null_result_is_not_wait(self):
        p={k:H for k in contract('channel')['message_kinds']['DECISION_RESULT']['required_payload_fields']}
        p.update(generation_attempt_id='development-attempt',generation_http_id='development-http',result_status='COMPLETE',selection=None)
        with self.assertRaises(ContractError):envelope('DECISION_RESULT',p,binding=binding(),request_id='development-request',sequence=2,now=NOW)
    def test_unknown_result_retains_outcome_with_null_selection(self):
        p={k:H for k in contract('channel')['message_kinds']['DECISION_RESULT']['required_payload_fields']}
        p.update(generation_attempt_id='development-attempt',generation_http_id='development-http',result_status='UNKNOWN',selection=None,
            raw_response_receipt_sha256=None,transport_capture_receipt_sha256=None,token_usage_receipt_sha256=None,
            pending_window_completion_receipt_sha256=None,current_state_readback_sha256=None)
        self.assertEqual(envelope('DECISION_RESULT',p,binding=binding(),request_id='development-request',sequence=2,now=NOW)['payload']['result_status'],'UNKNOWN')


class ReleaseTests(unittest.TestCase):
    def test_all_external_bindings_required(self):
        r,e=release();e.pop('approved_topology_sha256')
        with self.assertRaises(ContractError):validate_release(r,expected=e,now=NOW,deadline=NOW+timedelta(hours=2))
    def test_release_cannot_extend_clock(self):
        r,e=release()
        with self.assertRaises(ContractError):validate_release(r,expected=e,now=NOW,deadline=NOW+timedelta(minutes=30))
    def test_null_observer_cannot_grant_release(self):
        r,e=release();r['role_read_isolation_receipt_sha256']=None
        with self.assertRaises(ContractError):validate_release(r,expected=e,now=NOW,deadline=NOW+timedelta(hours=2))
    def test_boolean_epoch_rejected(self):
        r,e=release();r['epoch']=True
        with self.assertRaises(ContractError):validate_release(r,expected=e,now=NOW,deadline=NOW+timedelta(hours=2))
    def test_consumption_survives_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d).resolve()/'development.custody.sqlite3';a=ReleaseLedger(path);a.initialize();r,_=release();a.consume(r)
            with self.assertRaises(ContractError):ReleaseLedger(path).consume(r)
    def test_unknown_delivery_cannot_be_resent(self):
        with tempfile.TemporaryDirectory() as d:
            a=ReleaseLedger(Path(d).resolve()/'development.custody.sqlite3');a.initialize();r,_=release();a.consume(r)
            self.assertIsNone(a.expose('delivery',frame()))
            with self.assertRaises(ContractError):a.expose('delivery',frame())
    def test_exact_duplicate_only_recovers_saved_ack(self):
        with tempfile.TemporaryDirectory() as d:
            a=ReleaseLedger(Path(d).resolve()/'development.custody.sqlite3');a.initialize();r,_=release();a.consume(r)
            a.expose('delivery',frame());a.acknowledge('delivery',{'outcome':'UNKNOWN'})
            self.assertEqual(a.expose('delivery',frame()),{'outcome':'UNKNOWN'})
    def test_changed_duplicate_keeps_original(self):
        with tempfile.TemporaryDirectory() as d:
            a=ReleaseLedger(Path(d).resolve()/'development.custody.sqlite3');a.initialize();r,_=release();a.consume(r)
            a.expose('delivery',frame());a.acknowledge('delivery',{'outcome':'UNKNOWN'})
            changed=frame();changed['sequence']=2
            with self.assertRaises(ContractError):a.expose('delivery',changed)
            self.assertEqual(a.expose('delivery',frame()),{'outcome':'UNKNOWN'})


class AggregateTests(unittest.TestCase):
    def value(self):
        return dict(format='forex.stage-b-public-aggregate/1',run_id='development-run',source_freeze_manifest_sha256=H,
            custody_public_manifest_sha256=H,status='INCOMPLETE',broad_failure_codes=['EVIDENCE_UNAVAILABLE'],
            generation_attempts_spent=0,mandatory_steps_accounted=0,mandatory_steps_incomplete=30,
            all_mandatory_assertions_passed=False,retained_evaluation_bundle_sha256=H,independent_redaction_receipt_sha256=H)
    def approve(self,v):return content_digest({k:x for k,x in v.items() if k!='independent_redaction_receipt_sha256'})
    def test_active_run_feedback_denied(self):
        v=self.value()
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=False)
    def test_extra_per_step_field_denied(self):
        v=self.value();v['private_step_id']='development-step'
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=True)
    def test_unapproved_aggregate_change_denied(self):
        v=self.value();pin=self.approve(v);v['generation_attempts_spent']=1
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=pin,final=True)
    def test_unknown_error_text_denied(self):
        v=self.value();v['broad_failure_codes']=['private exception']
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=True)
    def test_boolean_attempt_count_denied(self):
        v=self.value();v['generation_attempts_spent']=True
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=True)
    def test_approved_final_aggregate_allowed(self):
        v=self.value();self.assertEqual(public_aggregate(v,approved_digest=self.approve(v),final=True),v)
    def test_partial_scoring_cannot_claim_all_passed(self):
        v=self.value();v['all_mandatory_assertions_passed']=True
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=True)
    def test_accept_requires_all_32_spent_generations(self):
        v=self.value();v.update(status='ACCEPT',mandatory_steps_accounted=30,mandatory_steps_incomplete=0,
            all_mandatory_assertions_passed=True,broad_failure_codes=[],generation_attempts_spent=31)
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=True)
    def test_accept_cannot_hide_a_failure_code(self):
        v=self.value();v.update(status='ACCEPT',mandatory_steps_accounted=30,mandatory_steps_incomplete=0,
            all_mandatory_assertions_passed=True,generation_attempts_spent=32)
        with self.assertRaises(ContractError):public_aggregate(v,approved_digest=self.approve(v),final=True)
