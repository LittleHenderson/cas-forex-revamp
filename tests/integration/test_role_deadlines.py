"""AUTHORED/NOT_RUN. Deterministic fake peers/clocks; no processes or sockets."""
from datetime import datetime,timedelta,timezone
import hashlib
import hmac
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open,patch

from cas_forex_revamp.contracts import ContractError,canonical_bytes
from cas_forex_revamp.composition.role_channel import RoleChannel
from cas_forex_revamp.composition.remote_model_ports import RemoteGenerationClient,RemoteObservedPorts

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))

MODULE='cas_forex_revamp.composition.role_channel'


class FakeClock:
    def __init__(self):self.elapsed=0.;self.wall_offset=0.
    def now(self):return datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(seconds=self.elapsed+self.wall_offset)
    def mono(self):return 100.+self.elapsed
    def advance(self,seconds):self.elapsed+=seconds


class TimedPeer:
    def __init__(self,clock):
        self.clock=clock;self.timeout=None;self.timeouts=[];self.closed=False
        self.outgoing=[];self.incoming=[];self.send_cost=0.;self.receive_cost=0.;self.receive_calls=0
        self.ignore_timeout=False
    def setsockopt(self,*args):pass
    def settimeout(self,seconds):self.timeout=seconds;self.timeouts.append(seconds)
    def close(self):self.closed=True
    def wait(self,cost):
        if not self.ignore_timeout and cost>=self.timeout:
            self.clock.advance(self.timeout);raise TimeoutError('synthetic stalled peer')
        self.clock.advance(cost)
    def send(self,data):
        self.wait(self.send_cost);self.outgoing.append(data);return len(data)
    def recvmsg(self,*args):
        self.receive_calls+=1
        self.wait(self.receive_cost if self.incoming else 99999.)
        data=self.incoming.pop(0)
        return data,[(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,
                     struct.pack('3i',101,os.geteuid(),os.getegid()))],0,None
    def response(self,value,sequence=1):
        body={'channel_id':'synthetic','sequence':sequence,'method':'RETURN','value':{'ok':True,'value':value}}
        raw=canonical_bytes({'body':body,'mac':hmac.new(b'k'*32,canonical_bytes(body),hashlib.sha256).hexdigest()})
        self.incoming.extend(struct.pack('!II',len(raw),offset)+raw[offset:offset+32768]
                             for offset in range(0,len(raw),32768))


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.clock=FakeClock();self.peer=TimedPeer(self.clock)
        mono=patch(MODULE+'.time.monotonic',self.clock.mono);mono.start();self.addCleanup(mono.stop)
        opened=patch(MODULE+'.open',mock_open(read_data='101 (synthetic) '+' '.join(['0']*19+['1'])))
        opened.start();self.addCleanup(opened.stop)
        self.channel=RoleChannel(self.peer,key=b'k'*32,channel_id='synthetic',peer_pid=101,
            peer_start_ticks=1,deadline=self.clock.now()+timedelta(minutes=90),clock=self.clock.now)

    def bind(self,seconds=2):self.channel.begin_invocation('synthetic-delivery',self.clock.now()+timedelta(seconds=seconds))

    def test_stalled_peer_uses_invocation_not_model_window(self):
        self.bind();self.peer.send_cost=.25
        with self.assertRaises(TimeoutError):self.channel.call('DUE_EVENT',{})
        self.assertAlmostEqual(self.clock.elapsed,2.)
        self.assertTrue(self.channel.closed);self.assertTrue(self.peer.closed)
        self.assertLessEqual(max(self.peer.timeouts[-3:]),2.)

    def test_send_and_receive_share_one_original_budget(self):
        self.bind();self.peer.send_cost=1.25;self.peer.receive_cost=1.25;self.peer.response(True)
        with self.assertRaises(TimeoutError):self.channel.call('GATE',{})
        self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_each_send_fragment_keeps_original_deadline(self):
        self.bind();self.peer.send_cost=.75
        with self.assertRaises(TimeoutError):self.channel.send('LARGE',{'value':'x'*100000})
        self.assertEqual(len(self.peer.outgoing),2);self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_each_receive_fragment_keeps_original_deadline(self):
        self.bind();self.peer.response('x'*100000);self.peer.receive_cost=.75
        with self.assertRaises(TimeoutError):self.channel.receive()
        self.assertEqual(self.peer.receive_calls,3);self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_late_complete_response_is_rejected_even_if_peer_ignores_timeout(self):
        self.bind();self.peer.response(True);self.peer.receive_cost=3.;self.peer.ignore_timeout=True
        with self.assertRaises(TimeoutError):self.channel.call('GATE',{})
        self.assertTrue(self.channel.closed)

    def test_utc_rollback_cannot_extend_monotonic_invocation_limit(self):
        self.bind();self.clock.wall_offset=-3600.
        with self.assertRaises(TimeoutError):self.channel.call('DUE_EVENT',{})
        self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_utc_forward_jump_expires_before_send(self):
        self.bind();self.clock.wall_offset=3.
        with self.assertRaises(TimeoutError):self.channel.send('GATE',{})
        self.assertEqual(self.peer.outgoing,[])

    def test_expired_channel_cannot_start_failure_reporting_rpc(self):
        self.bind()
        with self.assertRaises(TimeoutError):self.channel.call('DUE_EVENT',{})
        count=len(self.peer.outgoing);elapsed=self.clock.elapsed
        with self.assertRaises(ContractError):self.channel.call('OUTCOME',{})
        self.assertEqual(len(self.peer.outgoing),count);self.assertEqual(self.clock.elapsed,elapsed)

    def test_nested_rpc_limit_cannot_extend_outer_invocation(self):
        self.bind()
        with self.assertRaises(TimeoutError):
            with self.channel.bounded(until=self.clock.mono()+100):self.channel.call('GATE',{})
        self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_exact_generation_monotonic_limit_shortens_rpc(self):
        self.bind(120)
        with self.assertRaises(TimeoutError):
            with self.channel.bounded(until=self.clock.mono()+.5):self.channel.call('DUE_EVENT',{})
        self.assertAlmostEqual(self.clock.elapsed,.5)

    def test_next_rpc_does_not_reset_invocation_budget(self):
        self.bind();self.peer.response(True);self.peer.receive_cost=1.25
        self.assertTrue(self.channel.call('GATE',{}))
        with self.assertRaises(TimeoutError):self.channel.call('STORE_RECORDS',{})
        self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_active_invocation_cannot_be_rebound(self):
        self.bind()
        with self.assertRaises(ContractError):self.channel.begin_invocation('other',self.clock.now()+timedelta(seconds=120))
        self.assertEqual(self.channel.invocation_deadline,self.clock.now()+timedelta(seconds=2))

    def test_completed_invocation_allows_distinct_next_frame(self):
        self.bind();self.peer.response(True);self.assertTrue(self.channel.call('GATE',{}))
        self.channel.finish_invocation('synthetic-delivery')
        self.channel.begin_invocation('next',self.clock.now()+timedelta(seconds=3))
        self.assertFalse(self.channel.closed)

    def test_remote_pending_ack_stall_uses_original_transport_deadline(self):
        self.bind(120);self.peer.response(True)  # GENERATION_SUBMITTED acknowledgement only
        self.channel.custody_binding={};self.channel.accept_public=lambda message,binding:message
        rows=[]
        store=SimpleNamespace(run_id='synthetic',
            resolve=lambda receipt_id:{'sha256':'a'*64,'payload':{'body_sha256':'b'*64}},
            append=lambda *args,**kwargs:rows.append(args))
        client=RemoteGenerationClient(channel=self.channel,request_id='synthetic-request',store=store,phase='probe',
            invocation_sha256='c'*64,request_sha256='d'*64,clock=self.clock.now,
            monotonic=self.clock.mono,monotonic_ns=lambda:int(self.clock.mono()*1e9),select_fn=lambda *args:([],[],[]))
        with patch('cas_forex_revamp.composition.remote_model_ports.envelope',return_value={'synthetic':True}):
            with self.assertRaises(TimeoutError):client.pending_changes(object(),self.clock.mono()+.5)
        self.assertAlmostEqual(self.clock.elapsed,.5);self.assertTrue(self.channel.closed)
        self.assertEqual(len(self.peer.outgoing),2)  # no retry or failure RPC

    def test_remote_preflight_inherits_controller_deadline(self):
        from cas_forex_revamp.operator.ollama_backend import ChatHttpRequest,ENDPOINT
        self.bind(2);ports=object.__new__(RemoteObservedPorts)
        ports.channel=self.channel;ports.store=SimpleNamespace(deadline=self.channel.deadline);ports._deadlines={}
        captured=[]
        ports.preflight=SimpleNamespace(count=lambda inv,req,pin:captured.append(req) or 12)
        request=ChatHttpRequest(ENDPOINT,b'{}',120,65536,self.channel.deadline)
        self.assertEqual(ports.count({'synthetic':True},request,None),12)
        self.assertEqual(captured[0].absolute_deadline,self.channel.invocation_deadline)
        self.assertEqual(list(ports._deadlines.values()),[self.channel.invocation_deadline])

    def test_controller_stall_retains_unknown_without_channel_retry(self):
        from cas_forex_revamp.composition.isolated_controller import IsolatedController
        self.bind();outcomes=[];owner=object.__new__(IsolatedController)
        owner.channel=self.channel;owner.active={'synthetic':True};owner.guard_roles=lambda:None
        owner.store=SimpleNamespace(records=lambda:[]);owner.outcome=lambda value:outcomes.append(value)
        with self.assertRaises(TimeoutError):owner.exchange_until({'PREFLIGHT_READY'})
        self.assertEqual([v['status'] for v in outcomes],['UNKNOWN'])
        self.assertEqual(self.peer.outgoing,[]);self.assertTrue(self.channel.closed)
        self.assertAlmostEqual(self.clock.elapsed,2.)

    def test_shutdown_send_is_bounded_without_an_active_invocation(self):
        from cas_forex_revamp.composition.isolated_controller import IsolatedController
        owner=object.__new__(IsolatedController);owner.channel=self.channel;owner.clock=self.clock.now
        owner.child=SimpleNamespace(poll=lambda:None);self.peer.send_cost=99999.
        with patch('approved_model_driver.stop_group') as stop_group:
            owner.close();stop_group.assert_called_once_with(owner.child)
        self.assertAlmostEqual(self.clock.elapsed,.25);self.assertTrue(self.channel.closed)

    def test_closed_channel_cleanup_does_not_wait_again(self):
        from cas_forex_revamp.composition.isolated_controller import IsolatedController
        self.channel.close();owner=object.__new__(IsolatedController)
        owner.channel=self.channel;owner.clock=self.clock.now;owner.child=SimpleNamespace(poll=lambda:None)
        with patch('approved_model_driver.stop_group') as stop_group:
            owner.close();stop_group.assert_called_once_with(owner.child)
        self.assertEqual(self.clock.elapsed,0.)


@unittest.skipUnless(sys.platform=='linux','approved Linux test route required')
class LinuxSocketDeadlineTests(unittest.TestCase):
    def test_actual_stalled_socketpair_exits_within_short_invocation(self):
        # Authored only. This would exercise a real private local socket on the
        # approved test route; it is not actual workload/custody isolation proof.
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        text=Path('/proc/self/stat').read_text();ticks=int(text[text.rfind(')')+2:].split()[19])
        channel=RoleChannel(left,key=b'x'*32,channel_id='public-test-stall',peer_pid=os.getpid(),
            peer_start_ticks=ticks,deadline=datetime.now(timezone.utc)+timedelta(minutes=90))
        channel.begin_invocation('public-test-frame',datetime.now(timezone.utc)+timedelta(seconds=.2))
        outcomes=[]
        def exchange():
            try:channel.call('DUE_EVENT',{})
            except Exception as exc:outcomes.append(exc)
        worker=threading.Thread(target=exchange,daemon=True);started=time.monotonic()
        try:
            worker.start();worker.join(1.5)
            self.assertFalse(worker.is_alive(),'stalled peer escaped invocation budget')
            self.assertEqual(len(outcomes),1);self.assertIsInstance(outcomes[0],TimeoutError)
            self.assertTrue(channel.closed);self.assertLess(time.monotonic()-started,1.5)
        finally:
            channel.close();right.close();worker.join(.5)
