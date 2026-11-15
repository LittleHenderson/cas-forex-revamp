"""AUTHORED/NOT_RUN. Synthetic packets; no socket/role/kernel launch."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib
import hmac
import os
import socket
import struct
from types import SimpleNamespace
import unittest

from cas_forex_revamp.contracts import ContractError,canonical_bytes,content_digest
from cas_forex_revamp.composition.role_channel import RoleChannel,MAX_MESSAGE
from cas_forex_revamp.composition.isolated_controller import IsolatedController


class FakePacketSocket:
    def __init__(self):self.packets=[];self.sender=101
    def setsockopt(self,*args):pass
    def close(self):pass
    def send(self,data):self.packets.append(data);return len(data)
    def recvmsg(self,*args):
        data=self.packets.pop(0)
        credentials=struct.pack('3i',self.sender,os.geteuid(),os.getegid())
        return data,[(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,credentials)],0,None


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.sock=FakePacketSocket();self.key=b'k'*32
        self.channel=RoleChannel(self.sock,key=self.key,channel_id='development-channel',peer_pid=101,
            peer_start_ticks=1,deadline=datetime.now(timezone.utc)+timedelta(minutes=1))
        self.channel._remaining=lambda:None
    def test_fragmented_large_message_retains_exact_bytes(self):
        self.channel.send('DEVELOPMENT',{'data':'x'*100000})
        self.assertGreater(len(self.sock.packets),1)
        self.assertEqual(self.channel.receive(),('DEVELOPMENT',{'data':'x'*100000}))
    def test_wrong_actual_sender_is_rejected(self):
        self.channel.send('DEVELOPMENT',{});self.sock.sender=102
        with self.assertRaises(ContractError):self.channel.receive()
    def test_reordered_fragments_are_rejected(self):
        self.channel.send('DEVELOPMENT',{'data':'x'*100000})
        self.sock.packets[0],self.sock.packets[1]=self.sock.packets[1],self.sock.packets[0]
        with self.assertRaises(ContractError):self.channel.receive()
    def test_mac_mutation_is_rejected(self):
        self.channel.send('DEVELOPMENT',{'data':'abc'})
        self.sock.packets[0]=self.sock.packets[0].replace(b'abc',b'abd')
        with self.assertRaises(ContractError):self.channel.receive()
    def test_replayed_transport_sequence_is_rejected(self):
        self.channel.send('DEVELOPMENT',{});again=list(self.sock.packets)
        self.channel.receive();self.sock.packets=again
        with self.assertRaises(ContractError):self.channel.receive()
    def test_peer_has_no_arbitrary_file_descriptor_route(self):
        self.channel.send('DEVELOPMENT',{})
        receive=self.sock.recvmsg
        def bad(*args):
            data,anc,flags,addr=receive(*args)
            return data,anc+[(socket.SOL_SOCKET,999,b'')],flags,addr
        self.sock.recvmsg=bad
        with self.assertRaises(ContractError):self.channel.receive()
    def test_oversized_frame_is_rejected_before_receive_allocation(self):
        self.sock.packets=[struct.pack('!II',MAX_MESSAGE+1,0)+b'x']
        with self.assertRaises(ContractError):self.channel.receive()


class EvidenceReadIsolationTests(unittest.TestCase):
    def setUp(self):
        self.inv={'visible_development_request':True};self.key=content_digest(self.inv)
        self.rows=[{'receipt_id':'token-proof-'+self.key,'kind':'MODEL_TOKEN_PREFLIGHT'},
                   {'receipt_id':'controller-event-0-'+self.key,'kind':'MODEL_CONTROLLER_PENDING_APPLIED'},
                   {'receipt_id':'inference-'+'b'*64,'kind':'MODEL_INFERENCE_RECEIPT'}]
        self.owner=object.__new__(IsolatedController);self.owner.active=self.inv
        self.owner.guard_roles=lambda:None
        self.owner.store=SimpleNamespace(records=lambda:self.rows,resolve=lambda key:next(r for r in self.rows if r['receipt_id']==key))
    def test_records_exclude_controller_events_and_other_requests(self):
        self.assertEqual(self.owner._handle('STORE_RECORDS',{}),self.rows[:1])
    def test_known_controller_receipt_id_still_cannot_be_read(self):
        with self.assertRaises(ContractError):self.owner._handle('STORE_RESOLVE',{'receipt_id':self.rows[1]['receipt_id']})
    def test_prior_request_receipt_cannot_be_read(self):
        with self.assertRaises(ContractError):self.owner._handle('STORE_RESOLVE',{'receipt_id':self.rows[2]['receipt_id']})
    def test_query_cannot_select_a_database_path(self):
        with self.assertRaises(ContractError):self.owner._handle('STORE_RECORDS',{'path':'development-only'})
    def test_runner_cannot_append_a_controller_effect(self):
        with self.assertRaises(ContractError):self.owner._handle('STORE_APPEND',{'receipt_id':'controller-event-0-'+self.key,
            'kind':'MODEL_CONTROLLER_PENDING_APPLIED','payload':{},'now':'2030-01-01T00:00:00Z'})
    def test_unknown_rpc_has_no_fallback(self):
        with self.assertRaises(RuntimeError):self.owner._handle('OPEN_FILE',{'path':'development-only'})
