"""Future bounded-transport tests using public byte fixtures. NOT_RUN."""
import copy
import socket
import struct
import unittest
from unittest.mock import patch
from cas_forex_operational_contracts import common
from custody_runtime.completion_transport import endpoint_selection, receive_frame, send_frame, FrameBudget, _ancillary_reject


def endpoint():
    return {'path':'/public-fixture/source.sock','device':1,'inode':2,'uid':1000,'gid':1000,'mode':0o600,
        'peer_pid':10,'peer_uid':1000,'peer_gid':1000,'peer_start_ticks':20,'boot_id':'public-boot',
        'maximum_frame_bytes':4096,'timeout_ms':1000,'maximum_registry_entries':256}


class Budget:
    def remaining(self):return 1


class ByteSocket:
    def __init__(self, raw, chunk=3):self.raw=raw;self.chunk=chunk;self.sent=b'';self.shutdowns=[]
    def settimeout(self, value):self.timeout=value
    def recvmsg(self,size,ancillary,flags=0):
        amount=min(size,self.chunk);value=self.raw[:amount];self.raw=self.raw[amount:]
        return value,[],0,None
    def send(self,raw):self.sent+=raw[:self.chunk];return len(raw[:self.chunk])
    def shutdown(self,how):self.shutdowns.append(how)


class CompletionTransportTests(unittest.TestCase):
    def test_selected_endpoint_is_detached(self):
        original=endpoint();selected=endpoint_selection(original);original['peer_pid']=99
        self.assertEqual(selected['peer_pid'],10)

    def test_boolean_peer_identity_is_rejected(self):
        value=endpoint();value['peer_pid']=True
        with self.assertRaises(common.ContractError):endpoint_selection(value)

    def test_socket_path_cannot_use_parent_traversal(self):
        value=endpoint();value['path']='/public/../source.sock'
        with self.assertRaises(common.ContractError):endpoint_selection(value)

    def test_frame_cap_cannot_be_widened(self):
        value=endpoint();value['maximum_frame_bytes']=common.MAX_OBJECT+1
        with self.assertRaises(common.ContractError):endpoint_selection(value)

    def test_unknown_endpoint_authority_flag_is_rejected(self):
        value=endpoint();value['approved']=True
        with self.assertRaises(common.ContractError):endpoint_selection(value)

    def test_fragmented_exact_frame_and_eof(self):
        raw=common.canonical_bytes({'public':'value'});stream=ByteSocket(struct.pack('!I',len(raw))+raw)
        self.assertEqual(receive_frame(stream,maximum=4096,budget=Budget()),raw)

    def test_short_body_cannot_be_complete(self):
        with self.assertRaises(common.ContractError):receive_frame(ByteSocket(struct.pack('!I',5)+b'{}'),maximum=4096,budget=Budget())

    def test_extra_bytes_cannot_be_second_message(self):
        with self.assertRaises(common.ContractError):receive_frame(ByteSocket(struct.pack('!I',2)+b'{}x'),maximum=4096,budget=Budget())

    def test_oversize_rejected_before_body_read(self):
        with self.assertRaises(common.ContractError):receive_frame(ByteSocket(struct.pack('!I',4097)),maximum=4096,budget=Budget())

    def test_noncanonical_record_is_not_accepted(self):
        raw=b'{ "x": 1 }'
        with self.assertRaises(common.ContractError):receive_frame(ByteSocket(struct.pack('!I',len(raw))+raw),maximum=4096,budget=Budget())

    def test_write_handles_partial_sends_and_half_closes(self):
        stream=ByteSocket(b'');send_frame(stream,b'{}',maximum=4096,budget=Budget())
        self.assertEqual(stream.sent,struct.pack('!I',2)+b'{}');self.assertEqual(stream.shutdowns,[socket.SHUT_WR])

    def test_received_descriptors_closed_before_rejection(self):
        with patch('custody_runtime.completion_transport.os.close') as close:
            with self.assertRaises(common.ContractError):_ancillary_reject([(socket.SOL_SOCKET,socket.SCM_RIGHTS,struct.pack('2i',44,45))],0)
            self.assertEqual([c.args[0] for c in close.call_args_list],[44,45])

    def test_truncation_is_rejected(self):
        with self.assertRaises(common.ContractError):_ancillary_reject([],socket.MSG_CTRUNC)

    def test_original_monotonic_deadline_beats_long_transport_timeout(self):
        now={'utc':'2030-01-01T00:00:01.000000Z','boottime_ns':1_000_000_000}
        end={'utc':'2030-01-01T00:00:02.000000Z','boottime_ns':2_000_000_000}
        with patch('custody_runtime.completion_transport.time.monotonic',return_value=0):
            budget=FrameBudget(clock=lambda:copy.deepcopy(now),deadline=end,timeout_ms=120000)
            self.assertEqual(budget.remaining(),1)
            now['boottime_ns']=2_000_000_000
            with self.assertRaises(common.ContractError):budget.remaining()

    def test_clock_regression_is_rejected(self):
        values=iter([{'utc':'2030-01-01T00:00:02.000000Z','boottime_ns':2},
                     {'utc':'2030-01-01T00:00:01.000000Z','boottime_ns':1}])
        with patch('custody_runtime.completion_transport.time.monotonic',return_value=0):
            budget=FrameBudget(clock=lambda:next(values),deadline={'utc':'2030-01-01T00:00:10.000000Z','boottime_ns':10000000000},timeout_ms=10000)
            budget.remaining()
            with self.assertRaises(common.ContractError):budget.remaining()
