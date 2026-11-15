"""AUTHORED/NOT_RUN. Public descriptor-cleanup regressions for approved Linux tests.

Fake records isolate rejection ordering; three cases use real socketpair/
SCM_RIGHTS truncation when eventually run. Peer/deadline guards are stubbed
only in these focused fixtures. These tests establish no role isolation.
"""
import array
from datetime import datetime, timedelta, timezone
import errno
import os
import socket
import struct
import sys
import unittest
from unittest.mock import patch

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.role_channel import RoleChannel

MODULE = "cas_forex_revamp.composition.role_channel"


def close_if_open(fd):
    try:
        os.close(fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise


def rights(fds, suffix=b""):
    return (socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array("i", fds).tobytes() + suffix)


class FakeReceiver:
    def __init__(self, packet):
        self.packet = packet
        self.closed = False
        self.returned = False

    def setsockopt(self, *args):
        pass

    def close(self):
        self.closed = True

    def recvmsg(self, *args):
        self.returned = True
        return self.packet


class CapturingReceiver:
    """Record only delivered descriptor integers, then give the real result back."""
    def __init__(self, connection, data_limit, ancillary_limit):
        self.connection = connection
        self.data_limit = data_limit
        self.ancillary_limit = ancillary_limit
        self.delivered = []
        self.flags = 0
        self.closed = False

    def setsockopt(self, *args):
        self.connection.setsockopt(*args)

    def close(self):
        self.closed = True
        self.connection.close()

    def recvmsg(self, data_limit, ancillary_limit):
        answer = self.connection.recvmsg(self.data_limit, self.ancillary_limit)
        self.flags = answer[2]
        for level, kind, raw in answer[1]:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array("i")
                fds.frombytes(raw[:len(raw) - len(raw) % fds.itemsize])
                self.delivered.extend(fds)
        return answer


class DescriptorFixture:
    def make_channel(self, receiver):
        channel = RoleChannel(
            receiver, key=b"p" * 32, channel_id="public-cleanup-fixture",
            peer_pid=os.getpid(), peer_start_ticks=1,
            deadline=datetime.now(timezone.utc) + timedelta(seconds=10),
        )
        # Cleanup tests do not claim to test /proc identity or deadline policies.
        channel._remaining = lambda: None
        self.addCleanup(channel.close)
        return channel

    def new_delivered(self, count):
        original, writer = os.pipe()
        self.addCleanup(close_if_open, original)
        self.addCleanup(close_if_open, writer)
        delivered = [os.dup(original) for _ in range(count)]
        for fd in delivered:
            self.addCleanup(close_if_open, fd)
        return delivered

    def credentials(self, raw=None):
        if raw is None:
            raw = struct.pack("3i", os.getpid(), os.geteuid(), os.getegid())
        return (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, raw)

    def assert_closed_fds(self, fds):
        for fd in fds:
            with self.subTest(fd=fd):
                with self.assertRaises(OSError) as caught:
                    os.fstat(fd)
                self.assertEqual(caught.exception.errno, errno.EBADF)

    def reject(self, ancillary, flags=0, expected=ContractError):
        receiver = FakeReceiver((b"public-packet", ancillary, flags, None))
        channel = self.make_channel(receiver)
        with self.assertRaises(expected):
            channel.receive()
        self.assertTrue(receiver.closed)
        self.assertTrue(channel.closed)
        self.assertEqual(channel.recv_seq, 0)
        return channel


@unittest.skipUnless(sys.platform == "linux", "Linux ancillary descriptor contract")
class DescriptorCleanupTests(DescriptorFixture, unittest.TestCase):
    def test_data_truncation_closes_delivered_rights(self):
        fds = self.new_delivered(2)
        self.reject([self.credentials(), rights(fds)], socket.MSG_TRUNC)
        self.assert_closed_fds(fds)

    def test_ancillary_truncation_closes_delivered_rights(self):
        fds = self.new_delivered(2)
        self.reject([self.credentials(), rights(fds)], socket.MSG_CTRUNC)
        self.assert_closed_fds(fds)

    def test_both_truncation_flags_close_all_rights_blocks(self):
        fds = self.new_delivered(3)
        self.reject([rights(fds[:1]), self.credentials(), rights(fds[1:])],
                    socket.MSG_TRUNC | socket.MSG_CTRUNC)
        self.assert_closed_fds(fds)

    def test_malformed_credential_before_rights_cannot_skip_cleanup(self):
        fds = self.new_delivered(2)
        self.reject([self.credentials(b"x"), rights(fds)], expected=struct.error)
        self.assert_closed_fds(fds)

    def test_wrong_credentials_and_multiple_rights_blocks_are_rejected(self):
        fds = self.new_delivered(3)
        bad = self.credentials(struct.pack("3i", os.getpid() + 1, os.geteuid(), os.getegid()))
        self.reject([bad, rights(fds[:1]), rights(fds[1:])])
        self.assert_closed_fds(fds)

    def test_late_fragment_closes_rights_before_deadline_failure(self):
        fds = self.new_delivered(2)
        receiver = FakeReceiver((b"public-packet", [self.credentials(), rights(fds)], 0, None))
        channel = self.make_channel(receiver)

        def remaining():
            if receiver.returned:
                raise TimeoutError("public late-receive fixture")

        channel._remaining = remaining
        with self.assertRaises(TimeoutError):
            channel.receive()
        self.assert_closed_fds(fds)
        self.assertTrue(channel.closed)
        self.assertEqual(channel.recv_seq, 0)

    def test_one_close_error_does_not_skip_later_blocks_or_allow_receive(self):
        fds = self.new_delivered(3)
        real_close = os.close
        attempts = []

        def failing_close(fd):
            attempts.append(fd)
            if fd == fds[0]:
                raise OSError(errno.EIO, "public close-failure fixture")
            return real_close(fd)

        # The first descriptor deliberately remains open in this injected
        # failure. Fixture cleanup closes it; the channel must never succeed.
        with patch(MODULE + ".os.close", side_effect=failing_close):
            self.reject([rights(fds[:1]), self.credentials(), rights(fds[1:])])
        self.assertEqual(attempts, fds)
        self.assert_closed_fds(fds[1:])
        os.fstat(fds[0])

    def test_untruncated_descriptor_transfer_is_still_rejected_and_closed(self):
        fds = self.new_delivered(2)
        self.reject([self.credentials(), rights(fds)])
        self.assert_closed_fds(fds)

    def test_complete_descriptor_prefix_is_closed_despite_trailing_bytes(self):
        fds = self.new_delivered(2)
        self.reject([self.credentials(), rights(fds, b"x")], socket.MSG_CTRUNC)
        self.assert_closed_fds(fds)


@unittest.skipUnless(sys.platform == "linux", "Linux real socketpair/SCM_RIGHTS")
class KernelDeliveryCleanupTests(DescriptorFixture, unittest.TestCase):
    def exercise_delivery(self, data_limit, ancillary_limit, expected_flags):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        receiver = CapturingReceiver(left, data_limit, ancillary_limit)
        channel = self.make_channel(receiver)
        original, writer = os.pipe()
        self.addCleanup(close_if_open, original)
        self.addCleanup(close_if_open, writer)
        payload = b"public-packet-longer-than-one-byte"
        # Kernel installs distinct receiver descriptors for repeated sender fd.
        sent = right.sendmsg([payload], [rights([original] * 8)])
        self.assertEqual(sent, len(payload))
        try:
            with self.assertRaises(ContractError):
                channel.receive()
            self.assertEqual(receiver.flags & expected_flags, expected_flags)
            self.assertGreater(len(receiver.delivered), 0)
            self.assert_closed_fds(receiver.delivered)
            self.assertTrue(channel.closed)
            self.assertTrue(receiver.closed)
            self.assertEqual(channel.recv_seq, 0)
            # Receiver cleanup must not close the sender's original descriptor.
            os.fstat(original)
        finally:
            for fd in receiver.delivered:
                close_if_open(fd)

    def short_ancillary_limit(self):
        return (socket.CMSG_SPACE(struct.calcsize("3i"))
                + socket.CMSG_SPACE(array.array("i").itemsize))

    def test_real_data_truncation_with_delivered_rights(self):
        self.exercise_delivery(1, 1024, socket.MSG_TRUNC)

    def test_real_ancillary_truncation_with_delivered_rights(self):
        self.exercise_delivery(32776, self.short_ancillary_limit(), socket.MSG_CTRUNC)

    def test_real_combined_truncation_with_delivered_rights(self):
        self.exercise_delivery(1, self.short_ancillary_limit(),
                               socket.MSG_TRUNC | socket.MSG_CTRUNC)

