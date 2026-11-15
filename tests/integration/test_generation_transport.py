"""AUTHORED/NOT_RUN. Fake socket/store; no network or actual-model claim."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from hashlib import sha256
import json
from threading import Event,Thread
import unittest

from cas_forex_revamp.contracts import ContractError,canonical_bytes,content_digest
from cas_forex_revamp.operator.ollama_backend import ChatHttpRequest,ENDPOINT
from cas_forex_revamp.operator.token_preflight import EvidenceExchange
from cas_forex_revamp.composition.generation_transport import (
    GenerationClient,PendingChangeBridge,pending_ordering,verify_generation_transport,http_bytes)


class Clock:
    def __init__(self):self.value=0
    def now(self):
        self.value+=1;return datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(microseconds=self.value)
    def monotonic(self):
        self.value+=1;return self.value/1000000
    def ns(self):
        self.value+=1;return self.value*1000


class MemoryStore:
    def __init__(self):self.rows=[];self.deadline=datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(minutes=5)
    def append(self,identity,kind,payload,*,now):
        if any(r['receipt_id']==identity for r in self.rows):raise ContractError('development duplicate')
        r={'receipt_id':identity,'kind':kind,'sequence':len(self.rows)+1,
            'recorded_at':now.isoformat(),'payload':json.loads(canonical_bytes(payload))}
        self.rows.append(r);return deepcopy(r)
    def begin_http(self,*,phase,operation,invocation_sha256,body_sha256,timeout_seconds,now):
        return self.append(operation+'-attempt-'+invocation_sha256,'MODEL_HTTP_ATTEMPT',
            dict(phase=phase,operation=operation,invocation_sha256=invocation_sha256,
                 body_sha256=body_sha256,requested_timeout_seconds=timeout_seconds),now=now)
    def records(self):return deepcopy(self.rows)
    def resolve(self,identity):
        for r in self.rows:
            if r['receipt_id']==identity:return deepcopy(r)
        raise ContractError('development missing record')


class FakeSocket:
    def __init__(self,*,response_on_send=False,chunk=7):
        body=b'{"done":true}'
        self.response=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        self.sent=bytearray();self.available=False;self.response_on_send=response_on_send
        self.chunk=chunk;self.closed=False;self.pause=None;self.release=None;self.failed_send=False
    def setblocking(self,value):pass
    def connect_ex(self,address):
        if address!=('127.0.0.1',11434):raise AssertionError('unexpected endpoint')
        return 0
    def getsockopt(self,*args):return 0
    def send(self,data):
        if self.pause is not None:
            pause,self.pause=self.pause,None;pause.set()
            if not self.release.wait(2):raise TimeoutError('development barrier')
        if self.failed_send:return 0
        n=min(self.chunk,len(data));self.sent.extend(data[:n])
        if self.response_on_send:self.available=True
        return n
    def recv(self,size):
        result=self.response[:size];self.response=self.response[size:];return result
    def close(self):self.closed=True
    def select(self,read,write,failed,timeout):
        if write:return [],write,[]
        if read and (self.available or timeout>0):return read,[],[]
        return [],[],[]


class GenerationTransportTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock();self.store=MemoryStore();self.bridge=PendingChangeBridge()
        self.request_hash=content_digest({'development':'request'})
        self.invocation={'request_sha256':self.request_hash,'development_fixture':True}
        self.key=content_digest(self.invocation)
        self.request=ChatHttpRequest(ENDPOINT,b'{"development":true}',60,65536,self.store.deadline)
        self.events=[{'type':'CONTEXT_CHANGE','development_index':i} for i in range(3)]
        self.applied=[]

    def apply(self,event):
        self.applied.append(event)
        return {'before':{'development':len(self.applied)-1},'after':{'development':len(self.applied)}}

    def exchange(self,sock,plan=None):
        client=GenerationClient(store=self.store,phase='probe',invocation_sha256=self.key,
            request_sha256=self.request_hash,clock=self.clock.now,pending=plan,
            socket_factory=lambda *args:sock,select_fn=sock.select,
            monotonic=self.clock.monotonic,monotonic_ns=self.clock.ns)
        exchange=EvidenceExchange(self.store,phase='probe',clock=self.clock.now,execution_gate=lambda invocation:None)
        return exchange.post(self.invocation,self.request,operation='generation',client=client)

    def complete(self,sock=None,apply=None):
        sock=sock or FakeSocket()
        with self.bridge.register(self.request_hash,events=self.events,apply=apply or self.apply) as plan:
            self.exchange(sock,self.bridge.claim(self.request_hash))
        return plan,verify_generation_transport(self.store,self.key)

    def test_success_binds_full_wire_before_changes(self):
        sock=FakeSocket();plan,observed=self.complete(sock)
        self.assertEqual(bytes(sock.sent),http_bytes(self.request.body))
        self.assertEqual(self.applied,self.events)
        self.assertTrue(pending_ordering(plan.observations,observed))
        self.assertTrue(sock.closed)

    def test_pause_after_reservation_before_send_cannot_trigger_changes(self):
        sock=FakeSocket();entered=Event();sock.pause=entered;sock.release=Event();errors=[]
        with self.bridge.register(self.request_hash,events=self.events,apply=self.apply) as plan:
            selected=self.bridge.claim(self.request_hash)
            def call():
                try:self.exchange(sock,selected)
                except Exception as exc:errors.append(exc)
            thread=Thread(target=call);thread.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertEqual(self.applied,[])
                self.assertEqual([r['kind'] for r in self.store.records()],['MODEL_HTTP_ATTEMPT'])
            finally:sock.release.set();thread.join(2)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.assertTrue(pending_ordering(plan.observations,verify_generation_transport(self.store,self.key)))

    def test_response_wins_before_first_event(self):
        plan,observed=self.complete(FakeSocket(response_on_send=True))
        self.assertEqual(self.applied,[]);self.assertEqual(plan.observations,[])
        self.assertFalse(pending_ordering(plan.observations,observed))
        self.assertTrue(observed['windows'][0]['payload']['before_response_ready'])

    def test_response_arriving_during_change_fails_and_stops_remaining_changes(self):
        sock=FakeSocket()
        def during(event):
            result=self.apply(event);sock.available=True;return result
        plan,observed=self.complete(sock,during)
        self.assertEqual(len(self.applied),1)
        self.assertFalse(pending_ordering(plan.observations,observed))
        self.assertTrue(observed['windows'][0]['payload']['after_response_ready'])

    def test_callback_failure_does_not_retry_or_pass(self):
        def fail(event):raise ValueError('development change failure')
        plan,observed=self.complete(apply=fail)
        self.assertFalse(pending_ordering(plan.observations,observed))
        self.assertEqual(observed['windows'][0]['payload']['error_type'],'ValueError')
        self.assertEqual(sum(r['kind']=='MODEL_HTTP_ATTEMPT' for r in self.store.records()),1)

    def test_interrupted_send_keeps_reservation_without_submission_receipt(self):
        sock=FakeSocket();sock.failed_send=True
        with self.assertRaises(ConnectionError):self.exchange(sock)
        self.assertFalse(any(r['kind']=='MODEL_TRANSPORT_REQUEST_SENT' for r in self.store.records()))
        with self.assertRaises(ContractError):self.exchange(FakeSocket())
        self.assertEqual(sum(r['kind']=='MODEL_HTTP_ATTEMPT' for r in self.store.records()),1)

    def test_sent_bytes_must_cover_complete_wire(self):
        self.complete()
        next(r for r in self.store.rows if r['kind']=='MODEL_TRANSPORT_REQUEST_SENT')['payload']['sent_bytes']-=1
        with self.assertRaises(ContractError):verify_generation_transport(self.store,self.key)

    def test_response_raw_bytes_are_bound_independently(self):
        self.complete()
        next(r for r in self.store.rows if r['kind']=='MODEL_TRANSPORT_RESPONSE_CAPTURE')['payload']['response']['body_sha256']='0'*64
        with self.assertRaises(ContractError):verify_generation_transport(self.store,self.key)

    def test_missing_sent_observation_cannot_use_old_exchange_start(self):
        self.complete();self.store.rows=[r for r in self.store.rows if r['kind']!='MODEL_TRANSPORT_REQUEST_SENT']
        with self.assertRaises(ContractError):verify_generation_transport(self.store,self.key)

    def test_response_before_submission_rejected(self):
        self.complete()
        sent=next(r for r in self.store.rows if r['kind']=='MODEL_TRANSPORT_REQUEST_SENT')['payload']['submitted']
        capture=next(r for r in self.store.rows if r['kind']=='MODEL_TRANSPORT_RESPONSE_CAPTURE')['payload']
        capture['first_bytes']['before_recv']=deepcopy(sent)
        with self.assertRaises(ContractError):verify_generation_transport(self.store,self.key)

    def test_event_before_submission_fails_reconstructed_order(self):
        plan,observed=self.complete();stamp=observed['request_sent']['payload']['submitted']
        observed['windows'][0]['payload']['started']=deepcopy(stamp)
        self.assertFalse(pending_ordering(plan.observations,observed))

    def test_changed_runtime_event_cannot_keep_a_true_label(self):
        plan,observed=self.complete();changed=deepcopy(plan.observations);changed[0]['after']={'development':'changed'}
        self.assertFalse(pending_ordering(changed,observed))

    def test_missing_final_event_is_incomplete(self):
        plan,observed=self.complete()
        self.assertFalse(pending_ordering(plan.observations[:-1],observed))

    def test_monotonic_clock_identity_cannot_be_mixed(self):
        plan,observed=self.complete();observed['windows'][0]['payload']['after_check']['clock_id']='other-transport'
        self.assertFalse(pending_ordering(plan.observations,observed))

    def test_same_plan_cannot_be_claimed_twice(self):
        with self.bridge.register(self.request_hash,events=self.events,apply=self.apply):
            self.bridge.claim(self.request_hash)
            with self.assertRaises(ContractError):self.bridge.claim(self.request_hash)

    def test_active_plan_cannot_attach_to_another_request(self):
        with self.bridge.register(self.request_hash,events=self.events,apply=self.apply):
            with self.assertRaises(ContractError):self.bridge.claim('f'*64)

    def test_plan_cannot_be_registered_again_after_failure(self):
        with self.bridge.register(self.request_hash,events=self.events,apply=self.apply):pass
        with self.assertRaises(ContractError):
            with self.bridge.register(self.request_hash,events=self.events,apply=self.apply):pass

    def test_no_pending_plan_has_no_fixture_mutation(self):
        self.exchange(FakeSocket());observed=verify_generation_transport(self.store,self.key)
        self.assertEqual(observed['windows'],[]);self.assertEqual(self.applied,[])
        self.assertFalse(pending_ordering([],observed))
