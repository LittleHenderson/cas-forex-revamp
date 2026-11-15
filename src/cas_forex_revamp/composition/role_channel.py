"""Bounded inherited Unix packet channel, exact peer credentials and MAC.

No endpoint/path/principal is accepted from an imported frame. A parent creates
one private socketpair before custody reads. Keys exist only in those processes;
the model child never inherits the channel or bootstrap descriptor.
"""
import array
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
import re
import socket
import struct
import time

from ..contracts import ContractError, canonical_bytes

MAX_MESSAGE = 8388608


def need(ok, why):
    if not ok:
        raise ContractError(why)


def discard_received_rights(ancillary):
    """Close every delivered descriptor before validating any packet fields.

    recvmsg has already installed these descriptors in this process. Closing
    the socket does not close them. Attempt all closes even if one reports an
    error; never retry a descriptor number that could already have been freed.
    The channel still rejects all SCM_RIGHTS, including empty/truncated blocks.
    """
    failed = False
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds = array.array('i')
            fds.frombytes(raw[:len(raw) - len(raw) % fds.itemsize])
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
    need(not failed, 'received descriptor cleanup unavailable')


def unpack_json(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            need(k not in result, 'duplicate channel key'); result[k] = v
        return result
    def bad(_):
        raise ContractError('nonfinite channel number')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=bad)


class RoleChannel:
    def __init__(self, connection, *, key, channel_id, peer_pid, peer_start_ticks,
                 deadline, clock=lambda: datetime.now(timezone.utc)):
        need(type(key) is bytes and len(key) == 32 and type(peer_pid) is int and peer_pid > 0,
             'externally bound private peer required')
        self.socket, self.key, self.channel_id = connection, key, channel_id
        self.peer_pid, self.peer_start_ticks = peer_pid, peer_start_ticks
        self.deadline, self.clock = deadline, clock
        self.send_seq = self.recv_seq = 0
        self.public_sequence = 0
        self.closed = False
        self._invocation = None
        self._bounds = []
        self.until = time.monotonic() + (deadline - clock()).total_seconds()
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

    def close(self):
        if not self.closed:
            self.closed = True
            self.socket.close()

    def begin_invocation(self, identity, deadline):
        need(not self.closed and self._invocation is None, 'invocation cannot reset an active channel deadline')
        deadline = min(deadline, self.deadline)
        until = min(self.until, time.monotonic() + (deadline-self.clock()).total_seconds())
        self._invocation = (identity, deadline, until)
        try:self._remaining()
        except Exception:
            self.close();raise

    @property
    def invocation_deadline(self):
        need(self._invocation is not None, 'original invocation deadline required')
        return self._invocation[1]

    def finish_invocation(self, identity):
        need(self._invocation is not None and self._invocation[0] == identity, 'wrong invocation completion')
        self._remaining()
        self._invocation = None

    @contextmanager
    def bounded(self, *, deadline=None, until=None):
        """Nested bounds only shorten waits; no fragment/RPC gets a fresh budget."""
        need(not self.closed, 'channel closed after failed or unknown exchange')
        utc_limit = self.deadline if deadline is None else min(self.deadline, deadline)
        monotonic_limit = min(self.until, time.monotonic() + (utc_limit-self.clock()).total_seconds())
        if until is not None:
            need(type(until) in (int,float) and math.isfinite(until), 'finite monotonic bound required')
            monotonic_limit = min(monotonic_limit, until)
        self._bounds.append((utc_limit,monotonic_limit))
        try:
            self._remaining()
            yield
            self._remaining()
        except Exception:
            # Never perform an error-report RPC on a possibly incomplete frame.
            self.close()
            raise
        finally:self._bounds.pop()

    def _remaining(self):
        need(not self.closed, 'channel closed after failed or unknown exchange')
        limits=[(self.deadline,self.until),*self._bounds]
        if self._invocation is not None:limits.append(self._invocation[1:])
        def remaining():
            now,mono=self.clock(),time.monotonic()
            left=min(min((utc-now).total_seconds(),end-mono) for utc,end in limits)
            if left<=0:raise TimeoutError('channel original deadline exhausted')
            return left
        remaining()
        with open('/proc/'+str(self.peer_pid)+'/stat', encoding='utf-8') as handle:text=handle.read()
        need(int(text[text.rfind(')')+2:].split()[19]) == self.peer_start_ticks,
             'channel peer identity changed')
        self.socket.settimeout(remaining())

    def send(self, method, value, *, deadline=None, until=None):
        with self.bounded(deadline=deadline,until=until):
            self._send(method,value)

    def _send(self, method, value):
        self._remaining()
        need(type(method) is str and re.fullmatch('[A-Z_]{1,40}', method), 'bounded method required')
        self.send_seq += 1
        body = {'channel_id': self.channel_id, 'sequence': self.send_seq, 'method': method, 'value': value}
        raw = canonical_bytes(body)
        packet = canonical_bytes({'body': body, 'mac': hmac.new(self.key, raw, hashlib.sha256).hexdigest()})
        need(len(packet) <= MAX_MESSAGE, 'channel message too large')
        # Separate bounded packets preserve credentials on EVERY fragment.
        for offset in range(0,len(packet),32768):
            self._remaining();part=packet[offset:offset+32768]
            frame=struct.pack('!II',len(packet),offset)+part
            need(self.socket.send(frame)==len(frame),'partial local channel packet')
            self._remaining()

    def _read(self):
        answer = bytearray()
        size=None
        while size is None or len(answer) < size:
            self._remaining()
            data, ancillary, flags, _ = self.socket.recvmsg(32776, 1024)
            discard_received_rights(ancillary)
            need(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'truncated channel record')
            credentials = []
            rejected = False
            for level, kind, raw in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    credentials.append(struct.unpack('3i', raw))
                else:
                    rejected = True
            self._remaining()  # close any received descriptors even on a late fragment
            need(not rejected and len(credentials) == 1 and credentials[0] ==
                 (self.peer_pid, os.geteuid(), os.getegid()), 'channel peer credentials differ')
            need(len(data)>8, 'channel closed without a complete outcome')
            total,offset=struct.unpack('!II',data[:8])
            need(0<total<=MAX_MESSAGE and (size is None or size==total) and offset==len(answer),
                 'channel fragment identity differs')
            size=total;answer.extend(data[8:]);need(len(answer)<=size,'channel fragment overflow')
        return bytes(answer)

    def receive(self, *, deadline=None, until=None):
        with self.bounded(deadline=deadline,until=until):
            return self._receive()

    def _receive(self):
        packet = unpack_json(self._read())
        need(type(packet) is dict and set(packet) == {'body', 'mac'}, 'unknown channel envelope')
        body = packet['body']
        need(type(body) is dict and set(body) == {'channel_id', 'sequence', 'method', 'value'}
             and body['channel_id'] == self.channel_id and type(body['sequence']) is int
             and body['sequence'] == self.recv_seq + 1, 'channel sequence or identity differs')
        need(type(packet['mac']) is str and hmac.compare_digest(packet['mac'],
             hmac.new(self.key, canonical_bytes(body), hashlib.sha256).hexdigest()), 'channel MAC differs')
        self.recv_seq += 1
        return body['method'], body['value']

    def call(self, method, value, *, deadline=None, until=None):
        with self.bounded(deadline=deadline,until=until):
            self.send(method, value)
            returned, data = self.receive()
            need(returned == 'RETURN', 'unexpected channel response')
            need(type(data) is dict and set(data) == {'ok', 'value'}, 'unknown response fields')
            need(data['ok'] is True, 'remote operation failed; retained evidence required')
            return data['value']

    def reply(self, value):
        self.send('RETURN', {'ok': True, 'value': value})

    def accept_public(self, message, binding):
        from .custody_protocol import validate_message
        validate_message(message,binding=binding,now=self.clock())
        need(message['sequence']>self.public_sequence,'stale public channel sequence')
        self.public_sequence=message['sequence']
        return message
