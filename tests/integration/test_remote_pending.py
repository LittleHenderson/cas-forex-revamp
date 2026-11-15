"""AUTHORED/NOT_RUN. Independent synthetic event/response ordering oracle."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import unittest

from cas_forex_revamp.composition.remote_pending import remote_ordering


def stamp(n):return {'clock_id':'development-clock','monotonic_ns':n,
    'utc':(datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(microseconds=n)).isoformat()}


def source():
    effect={'payload':{'event_result':{'before':{'v':1},'after':{'v':2}},'declared':{'type':'MARKET'},
        'timing':{'application_started':stamp(3),'application_completed':stamp(4)}}}
    w={'receipt_id':'development-window','payload':{'before_response_ready':False,'after_response_ready':False,
        'error_type':None,'started':stamp(2),'completed':stamp(5),'after_check':stamp(6)}}
    observation={**effect['payload']['event_result'],'declared':effect['payload']['declared'],
        'started_at':stamp(2)['utc'],'completed_at':stamp(5)['utc'],'transport_receipt_id':'development-window'}
    t={'request_sent':{'payload':{'submitted':stamp(1)}},'response_capture':{'payload':{'first_bytes':{'before_recv':stamp(8)}}},
       'windows':[w],'remote':{'applied':[effect],'completion':{'payload':{'applied_count':1,'declared_count':1}}}}
    return [observation],t


class RemotePendingOrderingTests(unittest.TestCase):
    def test_separate_actual_application_fits_socket_window(self):
        obs,t=source();self.assertTrue(remote_ordering(obs,t))
    def test_response_ready_before_ack_cannot_pass(self):
        obs,t=source();t['windows'][0]['payload']['after_response_ready']=True
        self.assertFalse(remote_ordering(obs,t))
    def test_source_mutation_before_full_send_cannot_pass(self):
        obs,t=source();t['remote']['applied'][0]['payload']['timing']['application_started']=stamp(0)
        self.assertFalse(remote_ordering(obs,t))
    def test_unapplied_remaining_event_cannot_disappear(self):
        obs,t=source();t['remote']['completion']['payload']['declared_count']=2
        self.assertFalse(remote_ordering(obs,t))
    def test_missing_controller_completion_is_incomplete(self):
        obs,t=source();t['remote']['completion']=None;self.assertFalse(remote_ordering(obs,t))
    def test_callback_return_after_response_is_not_pending_success(self):
        obs,t=source();t['response_capture']['payload']['first_bytes']['before_recv']=stamp(4)
        self.assertFalse(remote_ordering(obs,t))
    def test_changed_effect_is_rejected(self):
        obs,t=source();obs[0]['after']={'v':99};self.assertFalse(remote_ordering(obs,t))
    def test_controller_clock_namespace_mismatch_is_rejected(self):
        obs,t=source();t['remote']['applied'][0]['payload']['timing']['application_started']['clock_id']='other'
        self.assertFalse(remote_ordering(obs,t))
