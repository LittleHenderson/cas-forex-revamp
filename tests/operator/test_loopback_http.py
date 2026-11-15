"""Socket-free transport tests using explicit fakes. NOT_RUN."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import unittest

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.operator.loopback_http import StdlibLoopbackClient
from cas_forex_revamp.operator.ollama_backend import ENDPOINT, ChatHttpRequest


class FakeSocket:
    def __init__(self, response):
        self.response = bytearray(response)
        self.sent = bytearray()
        self.closed = False
        self.address = None
    def setblocking(self, value):
        assert value is False
    def connect_ex(self, address):
        self.address = address
        return 0
    def getsockopt(self, *args):
        return 0
    def send(self, data):
        n = min(23, len(data))
        self.sent.extend(data[:n])
        return n
    def recv(self, maximum):
        result = bytes(self.response[:min(7, maximum)])
        del self.response[:len(result)]
        return result
    def close(self):
        self.closed = True


def wire(**changes):
    values = dict(endpoint=ENDPOINT, body=b"{}", timeout_seconds=5, response_byte_limit=32,
                  absolute_deadline=datetime.now(timezone.utc) + timedelta(seconds=10))
    values.update(changes)
    return ChatHttpRequest(**values)


class LoopbackTransportTests(unittest.TestCase):
    def invoke(self, response, request=None):
        sock = FakeSocket(response)
        with patch("cas_forex_revamp.operator.loopback_http.socket.socket", return_value=sock), \
             patch("cas_forex_revamp.operator.loopback_http.select.select", side_effect=lambda r, w, x, t: (r, w, [])):
            try:
                result = StdlibLoopbackClient().post(request or wire())
            finally:
                self.assertTrue(sock.closed)
        self.assertEqual(sock.address, ("127.0.0.1", 11434))
        self.assertIn(b"Connection: close\r\n", sock.sent)
        return result

    def test_content_length_and_partial_socket_reads(self):
        result = self.invoke(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
        self.assertEqual(result.body, b"{}")
        self.assertEqual(result.status, 200)

    def test_bounded_chunked_and_eof_bodies(self):
        for raw in (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}"):
            self.assertEqual(self.invoke(raw).body, b"{}")

    def test_ambiguous_framing_and_excessive_body_rejected(self):
        for raw in (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nabc"):
            with self.assertRaises(ContractError):
                self.invoke(raw)

    def test_truncated_body_is_unknown_error(self):
        with self.assertRaises(ConnectionError):
            self.invoke(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}")

    def test_wrong_endpoint_or_expired_window_never_creates_socket(self):
        with patch("cas_forex_revamp.operator.loopback_http.socket.socket") as factory:
            with self.assertRaises(ContractError):
                StdlibLoopbackClient().post(wire(endpoint="http://example.invalid/api/chat"))
            with self.assertRaises(TimeoutError):
                StdlibLoopbackClient().post(wire(absolute_deadline=datetime.now(timezone.utc) - timedelta(seconds=1)))
            factory.assert_not_called()

    def test_timeout_closes_connection_without_retry(self):
        sock = FakeSocket(b"")
        with patch("cas_forex_revamp.operator.loopback_http.socket.socket", return_value=sock) as factory, \
             patch("cas_forex_revamp.operator.loopback_http.select.select", return_value=([], [], [])):
            with self.assertRaises(TimeoutError):
                StdlibLoopbackClient().post(wire())
            self.assertTrue(sock.closed)
            factory.assert_called_once()
