"""Explicit-call-only, bounded stdlib HTTP/1.1 transport for loopback Ollama.

No proxy, DNS, TLS, redirects, retry, environment lookup or service startup.
Network I/O happens only in post(). The guest supervisor still must stop the
model process at the approved absolute deadline; closing HTTP is not that proof.
"""
from __future__ import annotations

from datetime import datetime, timezone
import errno
import re
import select
import socket
import time

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.contracts.primitives import utc_time
from .ollama_backend import ENDPOINT, ChatHttpRequest, ChatHttpResponse


class StdlibLoopbackClient:
    def post(self, request: ChatHttpRequest) -> ChatHttpResponse:
        if not isinstance(request, ChatHttpRequest) or request.endpoint != ENDPOINT:
            raise ContractError("transport requires the fixed loopback chat endpoint")
        if type(request.body) is not bytes or not 0 < len(request.body) <= 1114112:
            raise ContractError("request body exceeds the transport bound")
        if type(request.timeout_seconds) is not int or not 0 < request.timeout_seconds <= 5400:
            raise ContractError("transport timeout must be a bounded positive integer")
        if type(request.response_byte_limit) is not int or not 0 < request.response_byte_limit <= 65536:
            raise ContractError("response ceiling exceeds the reviewed bound")
        utc_time(request.absolute_deadline, "absolute_deadline")
        remaining = min(request.timeout_seconds,
                        (request.absolute_deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining <= 0:
            raise TimeoutError("absolute model window expired")
        deadline = time.monotonic() + remaining
        headers = ("POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n"
                   "Content-Type: application/json\r\nAccept: application/json\r\n"
                   "Accept-Encoding: identity\r\nConnection: close\r\n"
                   f"Content-Length: {len(request.body)}\r\n\r\n").encode("ascii")
        wire = headers + request.body
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.setblocking(False)
            status = connection.connect_ex(("127.0.0.1", 11434))
            in_progress = {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                           getattr(errno, "WSAEWOULDBLOCK", 10035)}
            if status not in in_progress:
                raise ConnectionError("loopback connection failed")
            self._ready(connection, deadline, write=True)
            if connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                raise ConnectionError("loopback connection failed")
            offset = 0
            while offset < len(wire):
                self._ready(connection, deadline, write=True)
                try:
                    sent = connection.send(memoryview(wire)[offset:])
                except BlockingIOError:
                    continue
                if sent <= 0:
                    raise ConnectionError("loopback request interrupted")
                offset += sent
            reader = _Reader(connection, deadline, self._ready)
            header = reader.until(b"\r\n\r\n", 16384)
            status_code, fields = _headers(header)
            if fields.get("content-encoding", "identity").lower() != "identity":
                raise ContractError("compressed model responses are unsupported")
            length, transfer = fields.get("content-length"), fields.get("transfer-encoding")
            if length is not None and transfer is not None:
                raise ContractError("ambiguous HTTP message framing")
            maximum = request.response_byte_limit
            if transfer is not None:
                if transfer.lower() != "chunked":
                    raise ContractError("unsupported transfer encoding")
                body = bytearray()
                while True:
                    size_text = reader.until(b"\r\n", 32)
                    if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size_text):
                        raise ContractError("invalid or extended HTTP chunk length")
                    size = int(size_text, 16)
                    if size == 0:
                        if reader.until(b"\r\n", 4096) != b"":
                            raise ContractError("HTTP trailers are unsupported")
                        break
                    if len(body) + size > maximum:
                        raise ContractError("model response exceeds byte ceiling")
                    body.extend(reader.exact(size))
                    if reader.exact(2) != b"\r\n":
                        raise ContractError("invalid HTTP chunk terminator")
                result = bytes(body)
            elif length is not None:
                if not re.fullmatch(r"[0-9]{1,8}", length) or int(length) > maximum:
                    raise ContractError("invalid or excessive content length")
                result = reader.exact(int(length))
            else:
                result = reader.to_eof(maximum)
            if time.monotonic() >= deadline:
                raise TimeoutError("model HTTP deadline exceeded")
            return ChatHttpResponse(status_code, fields.get("content-type", ""), result)
        finally:
            connection.close()

    @staticmethod
    def _ready(connection, deadline, *, write=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("model HTTP deadline exceeded")
        readable, writable, failed = select.select([] if write else [connection],
            [connection] if write else [], [connection], remaining)
        if failed:
            raise ConnectionError("loopback socket failed")
        if not (writable if write else readable):
            raise TimeoutError("model HTTP deadline exceeded")


class _Reader:
    def __init__(self, connection, deadline, ready):
        self.connection, self.deadline, self.ready = connection, deadline, ready
        self.buffer = bytearray()

    def receive(self):
        while True:
            self.ready(self.connection, self.deadline)
            try:
                return self.connection.recv(4096)
            except BlockingIOError:
                continue

    def until(self, delimiter, maximum):
        while True:
            end = self.buffer.find(delimiter)
            if end >= 0:
                if end > maximum:
                    raise ContractError("HTTP header/line bound exceeded")
                result = bytes(self.buffer[:end])
                del self.buffer[:end + len(delimiter)]
                return result
            if len(self.buffer) > maximum + len(delimiter):
                raise ContractError("HTTP header/line bound exceeded")
            chunk = self.receive()
            if not chunk:
                raise ConnectionError("incomplete HTTP response")
            self.buffer.extend(chunk)

    def exact(self, length):
        while len(self.buffer) < length:
            chunk = self.receive()
            if not chunk:
                raise ConnectionError("incomplete HTTP body")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def to_eof(self, maximum):
        result = bytearray(self.buffer)
        self.buffer.clear()
        while True:
            if len(result) > maximum:
                raise ContractError("model response exceeds byte ceiling")
            chunk = self.receive()
            if not chunk:
                return bytes(result)
            if len(result) + len(chunk) > maximum:
                raise ContractError("model response exceeds byte ceiling")
            result.extend(chunk)


def _headers(raw):
    try:
        lines = raw.decode("ascii").split("\r\n")
    except UnicodeError as exc:
        raise ContractError("HTTP headers must be bounded ASCII") from exc
    match = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?", lines[0])
    if match is None or not 200 <= int(match[1]) <= 599:
        raise ContractError("invalid or interim HTTP status")
    fields = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z0-9-]+", name):
            raise ContractError("malformed HTTP header")
        name = name.lower()
        if name in fields or any(ord(c) < 32 and c != "\t" for c in value):
            raise ContractError("duplicate or invalid HTTP header")
        fields[name] = value.strip()
    return int(match[1]), fields
