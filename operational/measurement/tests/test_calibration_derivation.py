"""Synthetic pure-decoder negative controls, not authenticated or OS evidence."""
from copy import deepcopy
import socket
import struct
from types import SimpleNamespace
import unittest
from cas_forex_operational_contracts.common import canonical_bytes,decode_canonical,ContractError
from cas_forex_measurement.calibration import public_packet,public_fixture_key
from cas_forex_measurement.decoder import CaptureDeriver
from support import reference,stamp


class PublicGraph:
    def __init__(self):
        self.subject={'boot_id':'00000000-0000-4000-8000-000000000001','pid':23,'parent_pid':22,'start_ticks':2,'uid':1000,'gid':1000}
        self.selected={'values':{'controller':self.subject,'calibration':{'expected_peer':self.subject}}}
        self.values={};self.derived={};self.ops=[]
        fixture=canonical_bytes({'case_kind':'POSITIVE_INERT','public_only':True});fixture_ref=self.put(fixture,'PUBLIC_FIXTURE')
        self.expectation={'case_id':'public-case','case_kind':'POSITIVE_INERT','slot_id':'public-slot','fixture_ref':fixture_ref,'receiver_component_sha256':'a'*64}
        key=public_fixture_key(fixture,'public-key');app,frame=public_packet(key=key,channel_id='public-channel',value=decode_canonical(fixture),kind='POSITIVE_INERT')
        self.app,self.frame=app,frame
        self.batch=reference(b'public synthetic batch','TRUSTED_CAPTURE_BATCH')
        descriptor={'fd':8,'object_type':'SOCKET','device':1,'inode':8,'access_flags':2,'close_on_exec':True,'selected_target_id':'public-left'}
        send={'exchange_id':'public-case-exchange-1','sender':self.subject,'socket_descriptor':descriptor,'frame_ref':self.put(frame),
              'application_ref':self.put(app),'ancillary_sent':[],'return_value':len(frame),'errno':0}
        ancillary=canonical_bytes([{'level':socket.SOL_SOCKET,'type':socket.SCM_CREDENTIALS,'hex':struct.pack('3i',23,1000,1000).hex()}])
        recv={'exchange_id':send['exchange_id'],'receiver':self.subject,'socket_descriptor':dict(descriptor,fd=9,inode=9,selected_target_id='public-right'),
              'data_ref':self.put(frame),'ancillary_raw_ref':self.put(ancillary),'msg_flags':0,'return_value':len(frame),'errno':0,
              'ucred':{'pid':23,'uid':1000,'gid':1000},'delivered_descriptors':[]}
        self.add('SEND',send);self.add('RECV',recv)
        for gate in ('ANCILLARY','PEER_CREDENTIALS','FRAME','MAC','CHANNEL_ID','SEQUENCE','VERDICT','EXPOSURE'):
            self.add('VERIFIER_GATE',{'exchange_id':send['exchange_id'],'receiver_component_sha256':'a'*64,'instance_id':'public-verifier',
                'channel_instance_id':'public-channel','key_operation_id':'public-key','gate':gate,'input_refs':[],
                'outcome':'ACCEPTED_INERT' if gate in ('VERDICT','EXPOSURE') else 'CHECK_PASS',
                'sequence_before':0,'sequence_after':1 if gate in ('SEQUENCE','VERDICT','EXPOSURE') else 0,
                'handler_entries_before':0,'handler_entries_after':0,'receiver_closed':False})
    def put(self,raw,kind='NATIVE_CAPTURE_BYTES'):
        ref=reference(raw,kind);self.values[ref['sha256']]=raw;return ref
    def add(self,kind,data):
        self.ops.append({'operation_index':len(self.ops)+1,'kind':kind,'data':data,'started':stamp(),'finished':stamp(),'_batch':self.batch})
    def operations(self,kind):return [x for x in self.ops if x['kind']==kind]
    def bytes(self,ref):return self.values[ref['sha256']]
    def raw(self,ref,*unused):return self.bytes(ref)
    def derive(self,kind,value):
        ref=self.put(canonical_bytes(value),kind);self.derived[ref['sha256']]=deepcopy(value);return ref
    def deriver(self):
        d=CaptureDeriver(self)
        # Tests isolate byte normalization only. This explicitly bypasses identity
        # acquisition, so these test objects cannot constitute a production graph.
        d.process_identity=lambda subject:deepcopy(subject)
        return d


class CalibrationDerivationTests(unittest.TestCase):
    def test_actual_byte_mac_is_recomputed(self):
        graph=PublicGraph();payload=graph.deriver().calibration_case(graph.expectation)
        trace=graph.derived[payload['exchanges'][0]['verifier_trace_ref']['sha256']]
        self.assertTrue(trace['mac_valid']);self.assertTrue(trace['frame_valid'])
    def test_missing_receive_is_not_intended_negative(self):
        graph=PublicGraph();graph.ops=[x for x in graph.ops if x['kind']!='RECV']
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
    def test_received_frame_substitution_is_rejected(self):
        graph=PublicGraph();graph.operations('RECV')[0]['data']['data_ref']=graph.put(b'other-frame')
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
    def test_claimed_credentials_must_match_ancillary_bytes(self):
        graph=PublicGraph();graph.operations('RECV')[0]['data']['ucred']['pid']=24
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
    def test_exposure_cannot_precede_verdict(self):
        graph=PublicGraph();graph.ops[-1]['operation_index']=graph.ops[-2]['operation_index']-1
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
    def test_success_label_cannot_hide_changed_application_mac(self):
        graph=PublicGraph();packet=decode_canonical(graph.app);packet['mac']='0'*64
        app=canonical_bytes(packet);frame=struct.pack('!II',len(app),0)+app
        send=graph.operations('SEND')[0]['data'];recv=graph.operations('RECV')[0]['data']
        send.update(application_ref=graph.put(app),frame_ref=graph.put(frame),return_value=len(frame));recv.update(data_ref=graph.put(frame),return_value=len(frame))
        payload=graph.deriver().calibration_case(graph.expectation)
        trace=graph.derived[payload['exchanges'][0]['verifier_trace_ref']['sha256']]
        self.assertFalse(trace['mac_valid'])
    def test_unobserved_mac_gate_is_rejected(self):
        graph=PublicGraph();graph.ops=[x for x in graph.ops if x['kind']!='VERIFIER_GATE' or x['data']['gate']!='MAC']
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
    def test_duplicate_actual_verdict_is_rejected(self):
        graph=PublicGraph();graph.ops.append(deepcopy(graph.ops[-2]))
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
    def test_delivered_fd_requires_actual_close(self):
        graph=PublicGraph();recv=graph.operations('RECV')[0]['data']
        ancillary=decode_canonical(graph.bytes(recv['ancillary_raw_ref']))
        ancillary.append({'level':socket.SOL_SOCKET,'type':socket.SCM_RIGHTS,'hex':struct.pack('i',12).hex()})
        recv['ancillary_raw_ref']=graph.put(canonical_bytes(ancillary));recv['delivered_descriptors']=[dict(recv['socket_descriptor'],fd=12,selected_target_id='delivered-right')]
        with self.assertRaises(ContractError):graph.deriver().calibration_case(graph.expectation)
