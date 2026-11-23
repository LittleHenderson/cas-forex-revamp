"""Loopback-only Authenticated HTTP & SSE Cockpit Bridge Server for CAS Forex 01 Operate.

Security & Honesty Invariants:
- Binds EXCLUSIVELY to a loopback IP address (127.0.0.1 / ::1); hard-refuses 0.0.0.0 or external NICs.
- Validates loopback client peer IP, exact literal loopback `Host` (`127.0.0.1:<port>` / `[::1]:<port>`),
  and exact loopback `Origin` / `Sec-Fetch-Site` BEFORE reading any request body (defeating DNS rebinding & CSRF).
- Enforces an absolute monotonic pre-auth wall-clock deadline and cumulative 16 KiB byte budget across BOTH
  `raw_requestline` and all HTTP headers before `BaseHTTPRequestHandler` reads the first byte (Finding [14]).
- Never places or accepts the owner primary bearer secret in URLs or stdout; `bootstrap_url` and `POST /api/pair-code`
  mint single-use, 120-second pairing nonces exchanged via `POST /api/pair-exchange` for least-privilege
  `DEVICE_READ_AND_EXPLAINER` tokens (Finding [2]).
- Dedicated owner-only loopback emergency listener (`emergency_base_url`) guarantees `PAUSE_NEW_RISK`,
  `STOP_AUTOMATION`, and `EMERGENCY_CLOSE_ALL` remain reachable even when all ordinary slots are saturated (Finding [14]).
- Routes `/api/explainer-ask` and `/api/explainer-tts` through `DurableModelExecutionGate` (Finding [8]).
- Serves static UI & contract files strictly within the pinned repository root (resolves and blocks .. traversal).
- Emits strict Content-Security-Policy (default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self').
- Importing and constructing LoopbackCockpitServer is strictly inert until .start() is called.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
import io
import selectors
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import inspect
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import tempfile
import threading
import time
from typing import Any
import urllib.parse

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.state_store import (
    create_owner_only_file_atomic,
    open_verified_directory_fd,
    verify_and_read_owner_only_file,
)
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from cas_forex_revamp.operator.decisions import OperatorUnavailable
from cas_forex_revamp.operator.frontier_backends import assert_safe_ai_catalog_payload
from cas_forex_revamp.composition.autonomous_trader import build_enriched_compounding_payload
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.risk.demo_high_growth_profile import (
    DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE,
    DemoHighGrowthProfile,
    DemoHighGrowthProfileStore,
    resolve_demo_high_growth_profile_from_environ,
)
from cas_forex_revamp.treasury.compounding_controller import (
    CompoundingControllerError,
    OwnerKeyRequiredError as CompoundingOwnerKeyRequiredError,
)
from cas_forex_revamp.valve.aggression_dial import (
    AggressionDialError,
    AggressionDialStore,
    HIGH_RISK_MIN_BPS,
    HighRiskConfirmationRequiredError,
    OwnerKeyRequiredError,
)


class _SessionRevokedError(Exception):
    """Raised when a session epoch is revoked prior to commit."""


class _PreAuthBodyTimeoutError(TimeoutError):
    """Raised when a pre-authenticated request body exceeds its monotonic wall-clock deadline."""


class _PreAuthBodyTooLargeError(ValueError):
    """Raised when a pre-authenticated request body exceeds the strict 4096-byte budget."""


class RotationPendingDrainError(ContractError):
    """Raised when a revoked-epoch commit lease is still active past the rotation drain window."""

    def __init__(self, message: str, *, payload: dict[str, Any]) -> None:
        super().__init__(message)
        self.status_payload = dict(payload)


class _EpochGuardedOfframpClient:
    """Enforce fresh session-epoch verification immediately before external offramp conversion/withdrawal calls (Finding [12])."""

    def __init__(self, inner: Any, epoch_guard: Callable[[], None]) -> None:
        self._inner = inner
        self._epoch_guard = epoch_guard

    def convert_to_usd(self, *args: Any, **kwargs: Any) -> Any:
        self._epoch_guard()
        return self._inner.convert_to_usd(*args, **kwargs)

    def withdraw_usd_to_linked_bank_ach(self, *args: Any, **kwargs: Any) -> Any:
        self._epoch_guard()
        return self._inner.withdraw_usd_to_linked_bank_ach(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _EpochGuardedModelGate:
    """Enforce fresh session-epoch verification immediately before external auxiliary model/TTS dispatch (Finding [12])."""

    def __init__(self, inner: Any, epoch_guard: Callable[[], None]) -> None:
        self._inner = inner
        self._epoch_guard = epoch_guard

    def authorize_auxiliary_call(self, *args: Any, **kwargs: Any) -> Any:
        self._epoch_guard()
        return self._inner.authorize_auxiliary_call(*args, **kwargs)

    def admit_scout_call(self, *args: Any, **kwargs: Any) -> Any:
        self._epoch_guard()
        return self._inner.admit_scout_call(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._epoch_guard()
        return self._inner(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


LIVE_DIAL_CONFIRM_PHRASE = "CONFIRM_LIVE_HIGH_RISK_DIAL"


def build_aggression_high_risk_confirmation(
    scope_id: str,
    action: str,
    *,
    tier_id: str | None = None,
    target_bps: int | None = None,
    ai_ceiling_bps: int | None = None,
    preset: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Build canonical exact-target confirmation binding for LIVE/unknown aggression-dial mutations (Finding [17])."""
    clean_scope = str(scope_id or "dual-shield-barbell").strip() or "dual-shield-barbell"
    clean_action = str(action or "").strip().upper()
    clean_tier = str(tier_id).strip().upper() if tier_id is not None and str(tier_id).strip() else None
    clean_preset = str(preset).strip().upper() if preset is not None and str(preset).strip() else None
    clean_bps = int(target_bps) if target_bps is not None else None
    clean_ceil = int(ai_ceiling_bps) if ai_ceiling_bps is not None else None
    phrase = (
        f"{LIVE_DIAL_CONFIRM_PHRASE}|scope={clean_scope}|action={clean_action}"
        f"|tier={clean_tier or '-'}|bps={clean_bps if clean_bps is not None else '-'}"
        f"|ceiling={clean_ceil if clean_ceil is not None else '-'}|preset={clean_preset or '-'}"
    )
    doc: dict[str, Any] = {
        "phrase": LIVE_DIAL_CONFIRM_PHRASE,
        "scope": clean_scope,
        "action": clean_action,
        "tier_id": clean_tier,
        "target_bps": clean_bps,
        "ai_ceiling_bps": clean_ceil,
        "preset": clean_preset,
    }
    return doc, phrase


def _verify_bound_aggression_confirmation(
    body: Mapping[str, Any],
    *,
    expected_doc: Mapping[str, Any],
    expected_phrase: str,
) -> bool:
    raw_phrase = body.get("confirmation_phrase")
    if isinstance(raw_phrase, str) and raw_phrase.strip():
        return hmac.compare_digest(raw_phrase.strip().encode("utf-8"), expected_phrase.encode("utf-8"))
    raw_obj = body.get("high_risk_confirmation")
    if not isinstance(raw_obj, Mapping):
        return False
    if str(raw_obj.get("phrase") or "").strip() != LIVE_DIAL_CONFIRM_PHRASE:
        return False
    if str(raw_obj.get("scope") or "").strip() != str(expected_doc["scope"]):
        return False
    if str(raw_obj.get("action") or "").strip().upper() != str(expected_doc["action"]):
        return False
    exp_tier = expected_doc.get("tier_id")
    got_tier_raw = raw_obj.get("tier_id")
    got_tier = str(got_tier_raw).strip().upper() if got_tier_raw is not None and str(got_tier_raw).strip() else None
    if got_tier != exp_tier:
        return False
    exp_preset = expected_doc.get("preset")
    got_preset_raw = raw_obj.get("preset")
    got_preset = (
        str(got_preset_raw).strip().upper()
        if got_preset_raw is not None and str(got_preset_raw).strip()
        else None
    )
    if got_preset != exp_preset:
        return False
    exp_bps = expected_doc.get("target_bps")
    got_bps = raw_obj.get("target_bps", raw_obj.get("bps"))
    if exp_bps is None:
        if got_bps is not None:
            return False
    else:
        if type(got_bps) is bool or not isinstance(got_bps, int) or int(got_bps) != int(exp_bps):
            return False
    exp_ceil = expected_doc.get("ai_ceiling_bps")
    got_ceil = raw_obj.get("ai_ceiling_bps", raw_obj.get("ceiling_bps"))
    if exp_ceil is None:
        if got_ceil is not None:
            return False
    else:
        if type(got_ceil) is bool or not isinstance(got_ceil, int) or int(got_ceil) != int(exp_ceil):
            return False
    return True


_COCKPIT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_PAIR_CODE_RE = re.compile(r"^pair-[A-Za-z0-9_-]{24,80}$")
MAX_HTTP_HEADER_BYTES = 16384
MAX_HTTP_HEADER_COUNT = 64
MAX_PRE_AUTH_BODY_BYTES = 4096
DEFAULT_PRE_AUTH_BODY_DEADLINE_SECONDS = 3.0
DEFAULT_MAX_PRE_AUTH_BODY_READERS = 2
MAX_TRACKED_PRE_AUTH_KEYS = 256
MAX_EMERGENCY_PENDING_SOCKETS = 64
MAX_EMERGENCY_HEADER_BYTES = 8192
DEFAULT_EMERGENCY_HEADER_DEADLINE_SECONDS = 1.0

SESSION_SCOPE_OWNER_FULL = "OWNER_FULL_CONTROL"
SESSION_SCOPE_DEVICE_READ_EXPLAINER = "DEVICE_READ_AND_EXPLAINER"
PAIR_CODE_TTL_SECONDS = 120
DEVICE_SESSION_TTL_SECONDS = 43200
MAX_ACTIVE_PAIRING_CODES = 8
MAX_ACTIVE_DEVICE_SESSIONS = 16
PAIR_EXCHANGE_WINDOW_SECONDS = 60.0
MAX_PAIR_EXCHANGE_ATTEMPTS_PER_WINDOW = 10
DEFAULT_FAST_ENTRY_SCAN_INTERVAL_SECONDS = 5.0
DEFAULT_FAST_ENTRY_SCAN_OPEN_INTERVAL_SECONDS = 15.0
DEFAULT_FAST_ERROR_LOG_COOLDOWN_SECONDS = 60.0

_DEVICE_ALLOWED_POST_ROUTES: frozenset[str] = frozenset({
    "/api/explainer-ask",
    "/api/explainer-tts",
})

_EMERGENCY_CHANNEL_POST_ROUTES: frozenset[str] = frozenset({
    "/api/ai-overseer-action",
    "/api/ai-trader-control",
    "/api/prepare-control",
    "/api/request-control",
    "/api/prepare-close",
    "/api/request-reviewed-close",
})


@dataclass(slots=True)
class _PairingCodeRecord:
    code_sha256: str
    epoch: str
    created_mono: float
    expires_mono: float
    expires_at_iso: str


@dataclass(slots=True)
class _DeviceSessionRecord:
    token_sha256: str
    epoch: str
    created_mono: float
    expires_mono: float
    expires_at_iso: str


def _is_valid_generated_cockpit_token(raw: str) -> bool:
    """Validate that a cockpit bearer matches generated high-entropy urlsafe base64 format (Finding [2])."""
    if not isinstance(raw, str) or not _COCKPIT_TOKEN_RE.match(raw):
        return False
    unique_chars = len(set(raw))
    if unique_chars < 16:
        return False
    length = float(len(raw))
    counts: dict[str, int] = {}
    for ch in raw:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return entropy >= 3.5


class _DeadlineRFile:
    """Wrap socket rfile with ONE cumulative pre-auth wall-clock deadline and byte cap across request-line + headers (Finding [14])."""

    def __init__(
        self,
        sock: socket.socket,
        raw_rfile: Any,
        *,
        deadline: float,
        max_bytes: int,
        mono_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sock = sock
        self._raw = raw_rfile
        self._deadline = deadline
        self._max_bytes = max_bytes
        self._mono = mono_clock
        self._total_read = 0
        self.header_deadline_exceeded = False
        self.header_size_exceeded = False

    def readline(self, limit: int = -1) -> bytes:
        chunks = bytearray()
        has_peek = callable(getattr(self._raw, "peek", None))
        while True:
            rem = self._deadline - self._mono()
            if rem <= 0:
                self.header_deadline_exceeded = True
                raise TimeoutError("absolute pre-auth HTTP deadline exceeded")
            budget = self._max_bytes - self._total_read
            if budget <= 0:
                self.header_size_exceeded = True
                raise ValueError("HTTP pre-auth byte limit exceeded")
            max_more = budget + 1 if limit < 0 else min(limit - len(chunks), budget + 1)
            if max_more <= 0:
                break
            self._sock.settimeout(max(0.001, rem))
            if has_peek:
                try:
                    peeked = self._raw.peek(1)
                except (TimeoutError, socket.timeout):
                    self.header_deadline_exceeded = True
                    raise TimeoutError("absolute pre-auth HTTP deadline exceeded") from None
                if not peeked:
                    break
                nl_pos = peeked.find(b"\n")
                take = min(max_more, nl_pos + 1 if nl_pos >= 0 else len(peeked))
                part = self._raw.read(take)
            else:
                try:
                    part = self._raw.readline(max_more)
                except (TimeoutError, socket.timeout):
                    self.header_deadline_exceeded = True
                    raise TimeoutError("absolute pre-auth HTTP deadline exceeded") from None
            if not part:
                break
            chunks.extend(part)
            self._total_read += len(part)
            if self._total_read > self._max_bytes:
                self.header_size_exceeded = True
                raise ValueError("HTTP pre-auth byte limit exceeded")
            if self._mono() > self._deadline:
                self.header_deadline_exceeded = True
                raise TimeoutError("absolute pre-auth HTTP deadline exceeded")
            if part.endswith(b"\n") or (limit >= 0 and len(chunks) >= limit):
                break
        return bytes(chunks)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def _canonical_pre_auth_principal(peer_ip: str) -> str:
    """Canonicalize IPv4 127.0.0.0/8, IPv6 ::1, and IPv4-mapped ::ffff:127.0.0.0/104 to 'loopback' (Finding [11])."""
    if not isinstance(peer_ip, str):
        return "unknown"
    clean = peer_ip.strip()
    if not clean:
        return "unknown"
    if "%" in clean:
        clean = clean.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return "unknown"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        return "loopback"
    return addr.compressed


def _is_loopback_peer_ip(peer_ip: str) -> bool:
    return _canonical_pre_auth_principal(peer_ip) == "loopback"


class _BoundedPreAuthRateTracker:
    """Bounded OrderedDict LRU + expiry pruner + global token bucket for pre-auth admission (Finding [11])."""

    def __init__(
        self,
        *,
        per_principal_limit: int,
        global_limit: int,
        window_seconds: float,
        max_keys: int = MAX_TRACKED_PRE_AUTH_KEYS,
    ) -> None:
        self._peer_limit = max(1, int(per_principal_limit))
        self._global_limit = max(1, int(global_limit))
        self._window = max(0.5, float(window_seconds))
        self._max_keys = max(1, int(max_keys))
        self.per_key: OrderedDict[str, list[float]] = OrderedDict()
        self.global_times: deque[float] = deque()

    def prune(self, now_m: float) -> None:
        cutoff = now_m - self._window
        while self.global_times and self.global_times[0] < cutoff:
            self.global_times.popleft()
        for key in list(self.per_key.keys()):
            kept = [t for t in self.per_key[key] if t >= cutoff]
            if kept:
                self.per_key[key] = kept
            else:
                self.per_key.pop(key, None)

    def is_rate_limited(self, principal: str, now_m: float) -> bool:
        self.prune(now_m)
        if len(self.global_times) >= self._global_limit:
            return True
        existing = self.per_key.get(principal)
        if existing is not None and len(existing) >= self._peer_limit:
            return True
        return False

    def record_admitted(self, principal: str, now_m: float) -> None:
        self.global_times.append(now_m)
        bucket = self.per_key.get(principal)
        if bucket is None:
            self.per_key[principal] = [now_m]
        else:
            bucket.append(now_m)
            self.per_key.move_to_end(principal)
        while len(self.per_key) > self._max_keys:
            self.per_key.popitem(last=False)

    def try_consume(self, principal: str, now_m: float) -> bool:
        if self.is_rate_limited(principal, now_m):
            return False
        self.record_admitted(principal, now_m)
        return True


class _ExclusiveThreadingHTTPServer(HTTPServer):
    """Bounded loopback HTTP server preventing SO_REUSEADDR hijacking and pre-auth alias/map exhaustion (Findings [8], [11], [14])."""

    allow_reuse_address = False
    request_queue_size = 64

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        ordinary_slots: int = 16,
        peer_rate_limit_per_window: int = 256,
        global_rate_limit_per_window: int | None = None,
        peer_rate_window_seconds: float = 10.0,
        max_tracked_keys: int = MAX_TRACKED_PRE_AUTH_KEYS,
        mono_clock: Callable[[], float] = time.monotonic,
        thread_name_prefix: str = "cas-cockpit-worker",
    ) -> None:
        self._ordinary_slots = max(1, int(ordinary_slots))
        self._ordinary_conn_sem = threading.BoundedSemaphore(self._ordinary_slots)
        self._peer_rate_limit = max(1, int(peer_rate_limit_per_window))
        eff_global = self._peer_rate_limit if global_rate_limit_per_window is None else max(1, int(global_rate_limit_per_window))
        self._global_rate_limit = eff_global
        self._peer_rate_window = max(0.5, float(peer_rate_window_seconds))
        self._mono = mono_clock
        self._slot_lock = threading.Lock()
        self._rate_tracker = _BoundedPreAuthRateTracker(
            per_principal_limit=self._peer_rate_limit,
            global_limit=self._global_rate_limit,
            window_seconds=self._peer_rate_window,
            max_keys=max_tracked_keys,
        )
        self._peer_conn_times: OrderedDict[str, list[float]] = self._rate_tracker.per_key
        self._global_conn_times: deque[float] = self._rate_tracker.global_times
        self._active_workers = 0
        self._peak_workers = 0
        self._rejected_pre_auth = 0
        self._executor = ThreadPoolExecutor(
            max_workers=self._ordinary_slots,
            thread_name_prefix=thread_name_prefix,
        )
        if ":" in str(server_address[0]):
            self.address_family = socket.AF_INET6
        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def _reject_raw_socket(self, request: Any, status_line: bytes, body: bytes) -> None:
        with self._slot_lock:
            self._rejected_pre_auth += 1
        try:
            if isinstance(request, socket.socket):
                request.settimeout(0.25)
                payload = (
                    status_line
                    + b"\r\nContent-Type: application/json; charset=utf-8\r\n"
                    + b"Connection: close\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                request.sendall(payload)
        except OSError as exc:
            _drop_err = str(exc)
        self.shutdown_request(request)

    def process_request(self, request: Any, client_address: Any) -> None:
        raw_ip = str(client_address[0]) if isinstance(client_address, tuple) and client_address else "unknown"
        principal = _canonical_pre_auth_principal(raw_ip)
        now_m = self._mono()
        with self._slot_lock:
            rate_exceeded = self._rate_tracker.is_rate_limited(principal, now_m)
        if rate_exceeded:
            self._reject_raw_socket(
                request,
                b"HTTP/1.1 429 Too Many Requests",
                b'{"error": "Pre-auth connection rate limit exceeded"}\n',
            )
            return

        # Capacity check BEFORE recording tracking state so capacity-rejected sockets allocate zero map entries (Finding [11])
        if not self._ordinary_conn_sem.acquire(blocking=False):
            self._reject_raw_socket(
                request,
                b"HTTP/1.1 503 Service Unavailable",
                b'{"error": "Cockpit connection pool full"}\n',
            )
            return

        sem = self._ordinary_conn_sem
        with self._slot_lock:
            if not self._rate_tracker.try_consume(principal, now_m):
                rate_race_exceeded = True
            else:
                rate_race_exceeded = False
                self._active_workers += 1
                if self._active_workers > self._peak_workers:
                    self._peak_workers = self._active_workers
        if rate_race_exceeded:
            sem.release()
            self._reject_raw_socket(
                request,
                b"HTTP/1.1 429 Too Many Requests",
                b'{"error": "Pre-auth connection rate limit exceeded"}\n',
            )
            return

        def _worker() -> None:
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                try:
                    self.shutdown_request(request)
                finally:
                    with self._slot_lock:
                        self._active_workers = max(0, self._active_workers - 1)
                    sem.release()

        try:
            self._executor.submit(_worker)
        except RuntimeError:
            with self._slot_lock:
                self._active_workers = max(0, self._active_workers - 1)
            sem.release()
            self.shutdown_request(request)

    def server_close(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        finally:
            super().server_close()


class _PrefixedRawIO(io.RawIOBase):
    """Drain pre-read selector bytes before delegating remaining reads to the underlying blocking socket."""

    def __init__(self, prefix: bytes, raw_sock: socket.socket) -> None:
        super().__init__()
        self._prefix = memoryview(prefix)
        self._pos = 0
        self._sock = raw_sock

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int | None:
        if self._pos < len(self._prefix):
            mv = memoryview(b).cast("B")
            take = min(len(mv), len(self._prefix) - self._pos)
            mv[:take] = self._prefix[self._pos : self._pos + take]
            self._pos += take
            return take
        return self._sock.recv_into(b)


class _PrefixedSocket:
    """Socket wrapper replaying validated HTTP headers + partial body bytes into BaseHTTPRequestHandler (Finding [10])."""

    def __init__(self, raw_sock: socket.socket, prefix: bytes) -> None:
        self._raw_sock = raw_sock
        self._raw_io = _PrefixedRawIO(prefix, raw_sock)

    @property
    def raw_socket(self) -> socket.socket:
        return self._raw_sock

    def makefile(self, mode: str = "r", buffering: int | None = None, *args: Any, **kwargs: Any) -> Any:
        if "r" in mode and "b" in mode:
            buf_sz = buffering if isinstance(buffering, int) and buffering > 0 else io.DEFAULT_BUFFER_SIZE
            return io.BufferedReader(self._raw_io, buffer_size=buf_sz)
        return self._raw_sock.makefile(mode, buffering, *args, **kwargs)  # type: ignore[arg-type]

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        if flags == 0:
            buf = bytearray(max(1, int(bufsize)))
            n = self._raw_io.readinto(buf)
            if not n:
                return b""
            return bytes(buf[:n])
        return self._raw_sock.recv(bufsize, flags)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        if flags == 0:
            mv = memoryview(buffer).cast("B")
            target = mv[:nbytes] if nbytes > 0 else mv
            n = self._raw_io.readinto(target)
            return 0 if n is None else int(n)
        return self._raw_sock.recv_into(buffer, nbytes, flags)

    def send(self, data: bytes, flags: int = 0) -> int:
        return self._raw_sock.send(data, flags)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        self._raw_sock.sendall(data, flags)

    def settimeout(self, value: float | None) -> None:
        self._raw_sock.settimeout(value)

    def gettimeout(self) -> float | None:
        return self._raw_sock.gettimeout()

    def setblocking(self, flag: bool) -> None:
        self._raw_sock.setblocking(flag)

    def setsockopt(self, *args: Any, **kwargs: Any) -> None:
        self._raw_sock.setsockopt(*args, **kwargs)

    def getsockopt(self, *args: Any, **kwargs: Any) -> Any:
        return self._raw_sock.getsockopt(*args, **kwargs)

    def getsockname(self) -> Any:
        return self._raw_sock.getsockname()

    def getpeername(self) -> Any:
        return self._raw_sock.getpeername()

    def fileno(self) -> int:
        return self._raw_sock.fileno()

    def shutdown(self, how: int) -> None:
        self._raw_sock.shutdown(how)

    def close(self) -> None:
        self._raw_sock.close()


def _unwrap_socket(conn: Any) -> socket.socket | None:
    if isinstance(conn, socket.socket):
        return conn
    inner = getattr(conn, "raw_socket", None)
    return inner if isinstance(inner, socket.socket) else None


@dataclass(slots=True)
class _PendingEmergencyConn:
    sock: socket.socket
    client_address: tuple[str, int]
    deadline_mono: float
    buf: bytearray
    is_unix_ipc: bool = False


class _EmergencyAdmissionHTTPServer(HTTPServer):
    """Nonblocking selector-gated emergency listener reserving 100% of worker slots for authenticated owner requests (Finding [10])."""

    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        emergency_slots: int = 4,
        max_pending_sockets: int = MAX_EMERGENCY_PENDING_SOCKETS,
        max_header_bytes: int = MAX_EMERGENCY_HEADER_BYTES,
        header_deadline_seconds: float = DEFAULT_EMERGENCY_HEADER_DEADLINE_SECONDS,
        expected_host_fn: Callable[[], str],
        expected_origin_fn: Callable[[], str],
        verify_owner_bearer_fn: Callable[[str], tuple[bool, bool]],
        on_auth_failure: Callable[[], None],
        on_pre_auth_timeout: Callable[[], None],
        unix_socket_path: str | Path | None = None,
        mono_clock: Callable[[], float] = time.monotonic,
        thread_name_prefix: str = "cas-cockpit-emerg",
    ) -> None:
        self._emergency_slots = max(1, int(emergency_slots))
        self._worker_sem = threading.BoundedSemaphore(self._emergency_slots)
        self._max_pending_sockets = max(4, min(int(max_pending_sockets), MAX_EMERGENCY_PENDING_SOCKETS))
        self._max_header_bytes = max(512, min(int(max_header_bytes), MAX_EMERGENCY_HEADER_BYTES))
        self._header_deadline_seconds = min(
            DEFAULT_EMERGENCY_HEADER_DEADLINE_SECONDS,
            max(0.05, float(header_deadline_seconds)),
        )
        self._expected_host_fn = expected_host_fn
        self._expected_origin_fn = expected_origin_fn
        self._verify_owner_bearer_fn = verify_owner_bearer_fn
        self._on_auth_failure = on_auth_failure
        self._on_pre_auth_timeout = on_pre_auth_timeout
        self._mono = mono_clock
        self._state_lock = threading.Lock()
        self._active_workers = 0
        self._peak_workers = 0
        self._rejected_pre_auth = 0
        self._shutdown_requested = False
        self._loop_done = threading.Event()
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        self._unix_sock: socket.socket | None = None
        self._unix_path: Path | None = None
        self._executor = ThreadPoolExecutor(
            max_workers=self._emergency_slots,
            thread_name_prefix=thread_name_prefix,
        )
        if ":" in str(server_address[0]):
            self.address_family = socket.AF_INET6
        super().__init__(server_address, RequestHandlerClass)
        self.socket.setblocking(False)
        if unix_socket_path is not None and str(unix_socket_path).strip():
            self._bind_unix_ipc_socket(Path(str(unix_socket_path).strip()))

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def _bind_unix_ipc_socket(self, raw_path: Path) -> None:
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise ContractError("Emergency Unix domain IPC socket is supported on POSIX only")
        if not raw_path.is_absolute() or ".." in raw_path.parts:
            raise ContractError(f"Emergency Unix socket path must be absolute without '..': {raw_path}")
        parent_verified, dir_fd = open_verified_directory_fd(
            raw_path.parent, create=True, label="emergency IPC directory"
        )
        try:
            sock_path = parent_verified / raw_path.name
            if dir_fd is not None:
                try:
                    st_old = os.lstat(raw_path.name, dir_fd=dir_fd)
                except FileNotFoundError:
                    st_old = None
                if st_old is not None:
                    import stat as _stat_mod
                    if not _stat_mod.S_ISSOCK(st_old.st_mode) or st_old.st_uid != os.geteuid():
                        raise ContractError(f"Refusing to unlink non-socket or foreign emergency IPC path: {sock_path}")
                    os.unlink(raw_path.name, dir_fd=dir_fd)
        finally:
            if dir_fd is not None:
                os.close(dir_fd)
        usock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        prev_umask = os.umask(0o177)
        try:
            usock.bind(str(sock_path))
            os.chmod(sock_path, 0o600)
            usock.listen(16)
            usock.setblocking(False)
        except Exception:
            usock.close()
            raise
        finally:
            os.umask(prev_umask)
        self._unix_sock = usock
        self._unix_path = sock_path

    @property
    def unix_socket_path(self) -> Path | None:
        return self._unix_path

    def _reject_pending_socket(
        self,
        sock: socket.socket,
        status_line: bytes,
        body: bytes,
        *,
        extra_header: bytes = b"",
    ) -> None:
        with self._state_lock:
            self._rejected_pre_auth += 1
        payload = (
            status_line
            + b"\r\nContent-Type: application/json; charset=utf-8\r\n"
            + b"Connection: close\r\n"
            + extra_header
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        try:
            sock.setblocking(True)
            sock.settimeout(0.15)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
        except OSError as exc:
            _ign = str(exc)
        try:
            sock.setblocking(False)
            for _ in range(4):
                if not sock.recv(4096):
                    break
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _validate_pre_auth_header_block(
        self,
        raw_head: bytes,
        *,
        is_unix_ipc: bool,
    ) -> tuple[bool, bytes, bytes, bytes]:
        """Validate HTTP request line, header count, Host, Origin/Sec-Fetch-Site, and owner primary bearer in memory."""
        try:
            text = raw_head.decode("iso-8859-1")
        except UnicodeDecodeError:
            return False, b"HTTP/1.1 400 Bad Request", b'{"error": "Malformed HTTP header encoding"}\n', b""
        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return False, b"HTTP/1.1 400 Bad Request", b'{"error": "Empty HTTP request line"}\n', b""
        req_parts = lines[0].split()
        if len(req_parts) != 3 or not req_parts[2].startswith("HTTP/1."):
            return False, b"HTTP/1.1 400 Bad Request", b'{"error": "Malformed HTTP request line"}\n', b""
        method = req_parts[0].upper()
        if method not in ("GET", "POST"):
            return False, b"HTTP/1.1 405 Method Not Allowed", b'{"error": "Method not allowed on emergency channel"}\n', b""

        hdr_lines = lines[1:]
        if len(hdr_lines) > MAX_HTTP_HEADER_COUNT:
            return False, b"HTTP/1.1 431 Request Header Fields Too Large", b'{"error": "Too many HTTP headers"}\n', b""

        headers_multi: dict[str, list[str]] = {}
        for hline in hdr_lines:
            if not hline:
                continue
            if hline[0] in (" ", "\t") or ":" not in hline:
                return False, b"HTTP/1.1 400 Bad Request", b'{"error": "Malformed HTTP header line"}\n', b""
            hk, hv = hline.split(":", 1)
            hk_clean = hk.strip().lower()
            if not hk_clean or any(ch.isspace() for ch in hk_clean):
                return False, b"HTTP/1.1 400 Bad Request", b'{"error": "Invalid HTTP header name"}\n', b""
            headers_multi.setdefault(hk_clean, []).append(hv.strip())

        exp_host = self._expected_host_fn()
        exp_origin = self._expected_origin_fn()
        hosts = headers_multi.get("host", [])
        allowed_hosts = {exp_host, "localhost"} if is_unix_ipc else {exp_host}
        if len(hosts) != 1 or hosts[0] not in allowed_hosts:
            return False, b"HTTP/1.1 403 Forbidden", b'{"error": "Invalid or foreign Host header"}\n', b""

        origins = headers_multi.get("origin", [])
        if len(origins) > 1:
            return False, b"HTTP/1.1 403 Forbidden", b'{"error": "Multiple Origin headers forbidden"}\n', b""
        if len(origins) == 1 and origins[0] != exp_origin:
            return False, b"HTTP/1.1 403 Forbidden", b'{"error": "Cross-origin loopback request forbidden"}\n', b""

        sec_sites = [s.lower() for s in headers_multi.get("sec-fetch-site", [])]
        if len(sec_sites) > 1:
            return False, b"HTTP/1.1 403 Forbidden", b'{"error": "Multiple Sec-Fetch-Site headers forbidden"}\n', b""
        if len(sec_sites) == 1 and sec_sites[0] not in ("same-origin", "none"):
            return False, b"HTTP/1.1 403 Forbidden", b'{"error": "Cross-site browser request forbidden"}\n', b""

        auth_vals = headers_multi.get("authorization", [])
        www_hdr = b'WWW-Authenticate: Bearer realm="cas-forex-cockpit"\r\n'
        if len(auth_vals) != 1 or not auth_vals[0].startswith("Bearer "):
            self._on_auth_failure()
            return False, b"HTTP/1.1 401 Unauthorized", b'{"error": "Authentication required"}\n', www_hdr
        cand_tok = auth_vals[0][7:].strip()
        if not cand_tok:
            self._on_auth_failure()
            return False, b"HTTP/1.1 401 Unauthorized", b'{"error": "Authentication required"}\n', www_hdr

        is_owner, is_device = self._verify_owner_bearer_fn(cand_tok)
        if is_owner:
            return True, b"", b"", b""
        if is_device:
            return (
                False,
                b"HTTP/1.1 403 Forbidden",
                b'{"error": "Owner primary session required; paired device sessions are read-only"}\n',
                b"",
            )
        self._on_auth_failure()
        return False, b"HTTP/1.1 401 Unauthorized", b'{"error": "Authentication required"}\n', www_hdr

    def _dispatch_authenticated(self, prefixed: _PrefixedSocket, client_address: tuple[str, int]) -> None:
        def _worker() -> None:
            try:
                self.finish_request(prefixed, client_address)  # type: ignore[arg-type]
            except Exception:
                self.handle_error(prefixed, client_address)  # type: ignore[arg-type]
            finally:
                try:
                    self.shutdown_request(prefixed)  # type: ignore[arg-type]
                finally:
                    with self._state_lock:
                        self._active_workers = max(0, self._active_workers - 1)
                    self._worker_sem.release()

        with self._state_lock:
            self._active_workers += 1
            if self._active_workers > self._peak_workers:
                self._peak_workers = self._active_workers
        try:
            self._executor.submit(_worker)
        except RuntimeError:
            with self._state_lock:
                self._active_workers = max(0, self._active_workers - 1)
            self._worker_sem.release()
            self.shutdown_request(prefixed)  # type: ignore[arg-type]

    def shutdown_request(self, request: Any) -> None:
        raw = _unwrap_socket(request)
        if raw is not None:
            try:
                raw.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                raw.close()
            except OSError:
                pass
        else:
            super().shutdown_request(request)

    def serve_forever(self, poll_interval: float = 0.05) -> None:
        self._loop_done.clear()
        pending: OrderedDict[int, _PendingEmergencyConn] = OrderedDict()
        sel = selectors.DefaultSelector()
        try:
            sel.register(self.socket, selectors.EVENT_READ, data=("accept_tcp", None))
            sel.register(self._wake_r, selectors.EVENT_READ, data=("wake", None))
            if self._unix_sock is not None:
                sel.register(self._unix_sock, selectors.EVENT_READ, data=("accept_unix", None))

            while not self._shutdown_requested:
                now_m = self._mono()
                if pending:
                    soonest = min(p.deadline_mono - now_m for p in pending.values())
                    wait_s = max(0.001, min(poll_interval, soonest))
                else:
                    wait_s = poll_interval

                try:
                    events = sel.select(timeout=wait_s)
                except OSError:
                    if self._shutdown_requested:
                        break
                    continue

                for key, _mask in events:
                    kind, tag_fd = key.data
                    if kind == "wake":
                        try:
                            while self._wake_r.recv(256):
                                pass
                        except BlockingIOError:
                            pass
                        except OSError:
                            pass
                        continue

                    if kind in ("accept_tcp", "accept_unix"):
                        listener = self.socket if kind == "accept_tcp" else self._unix_sock
                        if listener is None:
                            continue
                        is_unix = kind == "accept_unix"
                        for _ in range(32):
                            try:
                                conn, raw_addr = listener.accept()
                            except BlockingIOError:
                                break
                            except OSError:
                                break
                            if is_unix:
                                eff_addr = ("127.0.0.1", 0)
                            else:
                                peer_ip = str(raw_addr[0]) if isinstance(raw_addr, tuple) and raw_addr else ""
                                if not _is_loopback_peer_ip(peer_ip):
                                    self._reject_pending_socket(
                                        conn,
                                        b"HTTP/1.1 403 Forbidden",
                                        b'{"error": "Loopback clients only"}\n',
                                    )
                                    continue
                                eff_addr = (peer_ip, int(raw_addr[1]) if len(raw_addr) > 1 else 0)

                            try:
                                conn.setblocking(False)
                                fd_num = conn.fileno()
                            except OSError:
                                try:
                                    conn.close()
                                except OSError:
                                    pass
                                continue

                            # Evict oldest unauthenticated pending socket when table reaches 64 so owner can NEVER be blocked
                            while len(pending) >= self._max_pending_sockets:
                                _, evicted = pending.popitem(last=False)
                                try:
                                    sel.unregister(evicted.sock)
                                except Exception as exc_unreg:
                                    _u = str(exc_unreg)
                                self._on_pre_auth_timeout()
                                self._reject_pending_socket(
                                    evicted.sock,
                                    b"HTTP/1.1 408 Request Timeout",
                                    b'{"error": "Emergency pre-auth pending queue evicted slow socket"}\n',
                                )

                            rec = _PendingEmergencyConn(
                                sock=conn,
                                client_address=eff_addr,
                                deadline_mono=self._mono() + self._header_deadline_seconds,
                                buf=bytearray(),
                                is_unix_ipc=is_unix,
                            )
                            try:
                                sel.register(conn, selectors.EVENT_READ, data=("pending", fd_num))
                                pending[fd_num] = rec
                            except Exception:
                                try:
                                    conn.close()
                                except OSError:
                                    pass
                        continue

                    if kind == "pending":
                        p_conn = pending.get(tag_fd)
                        if p_conn is None:
                            continue
                        try:
                            chunk = p_conn.sock.recv(4096)
                        except BlockingIOError:
                            continue
                        except OSError:
                            pending.pop(tag_fd, None)
                            try:
                                sel.unregister(p_conn.sock)
                            except Exception as exc_u2:
                                _u2 = str(exc_u2)
                            try:
                                p_conn.sock.close()
                            except OSError:
                                pass
                            continue

                        if not chunk:
                            pending.pop(tag_fd, None)
                            try:
                                sel.unregister(p_conn.sock)
                            except Exception as exc_u3:
                                _u3 = str(exc_u3)
                            try:
                                p_conn.sock.close()
                            except OSError:
                                pass
                            continue

                        p_conn.buf.extend(chunk)
                        hdr_end = p_conn.buf.find(b"\r\n\r\n")
                        if hdr_end == -1:
                            if len(p_conn.buf) > self._max_header_bytes:
                                pending.pop(tag_fd, None)
                                try:
                                    sel.unregister(p_conn.sock)
                                except Exception as exc_u4:
                                    _u4 = str(exc_u4)
                                self._reject_pending_socket(
                                    p_conn.sock,
                                    b"HTTP/1.1 431 Request Header Fields Too Large",
                                    b'{"error": "Emergency pre-auth HTTP headers exceed 8 KiB limit"}\n',
                                )
                            continue

                        pending.pop(tag_fd, None)
                        try:
                            sel.unregister(p_conn.sock)
                        except Exception as exc_u5:
                            _u5 = str(exc_u5)

                        if hdr_end + 4 > self._max_header_bytes:
                            self._reject_pending_socket(
                                p_conn.sock,
                                b"HTTP/1.1 431 Request Header Fields Too Large",
                                b'{"error": "Emergency pre-auth HTTP headers exceed 8 KiB limit"}\n',
                            )
                            continue

                        ok_env, st_line, err_body, extra_hdr = self._validate_pre_auth_header_block(
                            bytes(p_conn.buf[:hdr_end]),
                            is_unix_ipc=p_conn.is_unix_ipc,
                        )
                        if not ok_env:
                            self._reject_pending_socket(
                                p_conn.sock,
                                st_line,
                                err_body,
                                extra_header=extra_hdr,
                            )
                            continue

                        if not self._worker_sem.acquire(blocking=False):
                            self._reject_pending_socket(
                                p_conn.sock,
                                b"HTTP/1.1 503 Service Unavailable",
                                b'{"error": "Authenticated emergency worker pool busy"}\n',
                            )
                            continue

                        try:
                            p_conn.sock.setblocking(True)
                            p_conn.sock.settimeout(5.0)
                        except OSError:
                            self._worker_sem.release()
                            try:
                                p_conn.sock.close()
                            except OSError:
                                pass
                            continue

                        prefixed = _PrefixedSocket(p_conn.sock, bytes(p_conn.buf))
                        self._dispatch_authenticated(prefixed, p_conn.client_address)

                # Enforce strict monotonic <=1.0s pre-auth header deadline across all pending sockets
                sweep_now = self._mono()
                for fd_exp in [fk for fk, pv in pending.items() if sweep_now >= pv.deadline_mono]:
                    exp_conn = pending.pop(fd_exp, None)
                    if exp_conn is None:
                        continue
                    try:
                        sel.unregister(exp_conn.sock)
                    except Exception as exc_u6:
                        _u6 = str(exc_u6)
                    self._on_pre_auth_timeout()
                    self._reject_pending_socket(
                        exp_conn.sock,
                        b"HTTP/1.1 408 Request Timeout",
                        b'{"error": "Emergency pre-auth header deadline exceeded"}\n',
                    )
        finally:
            for rem_conn in list(pending.values()):
                try:
                    sel.unregister(rem_conn.sock)
                except Exception as exc_u7:
                    _u7 = str(exc_u7)
                try:
                    rem_conn.sock.close()
                except OSError:
                    pass
            pending.clear()
            try:
                sel.close()
            except Exception as exc_sc:
                _sc = str(exc_sc)
            self._loop_done.set()

    def shutdown(self) -> None:
        self._shutdown_requested = True
        try:
            self._wake_w.send(b"x")
        except OSError:
            pass
        self._loop_done.wait(timeout=3.0)

    def server_close(self) -> None:
        self._shutdown_requested = True
        try:
            self._wake_w.send(b"x")
        except OSError:
            pass
        for ws in (self._wake_r, self._wake_w):
            try:
                ws.close()
            except OSError:
                pass
        if self._unix_sock is not None:
            try:
                self._unix_sock.close()
            except OSError:
                pass
            self._unix_sock = None
        if self._unix_path is not None:
            try:
                self._unix_path.unlink()
            except OSError:
                pass
            self._unix_path = None
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        finally:
            super().server_close()

def _roll_mt5_index_bars(
    prev_bars: Any,
    bucket_iso: str,
    mid_px: Any,
    _dec_txt: Any,
    limit: int = 48,
    *,
    max_stitch_gap_seconds: int = 120,
) -> list[dict[str, Any]]:
    """Append or update the latest OHLC candle bucket without stitching across stale gaps/jumps."""
    from decimal import Decimal

    bars: list[dict[str, Any]] = []
    if isinstance(prev_bars, list):
        for row in prev_bars:
            if isinstance(row, Mapping) and all(k in row for k in ("t", "o", "h", "l", "c")):
                bars.append({
                    "t": str(row["t"]),
                    "o": str(row["o"]),
                    "h": str(row["h"]),
                    "l": str(row["l"]),
                    "c": str(row["c"]),
                    "v": str(row.get("v", "1")),
                    "n": int(row.get("n", 1)),
                })
    if bars and bars[-1].get("t") == bucket_iso:
        last = bars[-1]
        hi = max(Decimal(str(last["h"])), mid_px)
        lo = min(Decimal(str(last["l"])), mid_px)
        last["h"] = _dec_txt(hi)
        last["l"] = _dec_txt(lo)
        last["c"] = _dec_txt(mid_px)
        last["v"] = _dec_txt(Decimal(str(last.get("v", "1"))) + Decimal("1"))
        last["n"] = int(last.get("n", 1)) + 1
    else:
        o_dec = mid_px
        if bars:
            prev_bar = bars[-1]
            try:
                prev_dt = datetime.fromisoformat(str(prev_bar["t"]).replace("Z", "+00:00"))
                new_dt = datetime.fromisoformat(str(bucket_iso).replace("Z", "+00:00"))
                prev_c = Decimal(str(prev_bar["c"]))
                gap_s = (new_dt - prev_dt).total_seconds()
                price_jump_ratio = abs(mid_px - prev_c) / max(abs(prev_c), Decimal("1"))
                if 0.0 < gap_s <= float(max_stitch_gap_seconds) and price_jump_ratio <= Decimal("0.015"):
                    o_dec = prev_c
            except (ValueError, TypeError, InvalidOperation):
                o_dec = mid_px
        bars.append({
            "t": bucket_iso,
            "o": _dec_txt(o_dec),
            "h": _dec_txt(max(o_dec, mid_px)),
            "l": _dec_txt(min(o_dec, mid_px)),
            "c": _dec_txt(mid_px),
            "v": "1",
            "n": 1,
        })
    return bars[-limit:]


def _build_mt5_index_snapshot_from_router(
    router: Any,
    prev_stream: dict[str, Any] | None = None,
    *,
    poll_cache: dict[str, dict[str, Any]] | None = None,
    log_throttle: dict[tuple[str, str, str], tuple[float, int]] | None = None,
    mono_clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any] | None, dict[str, tuple[Any, Any]]]:
    """Read NAS100/US30 quotes from active MT5 bridge transports and format an index stream payload."""
    from datetime import datetime, timezone
    from cas_forex_revamp.contracts import decimal_text as _dec_txt
    from cas_forex_revamp.venue.live_market_stream import INDEX_INSTRUMENTS

    now_mono = mono_clock()

    def _emit_tick_skip(broker_key: str, sym: str, err_name: str) -> None:
        if log_throttle is None:
            print(f"[ai-fast] Tick skipped for {sym}: {err_name}")
            return
        tkey = (broker_key, sym, err_name)
        prev_log = log_throttle.get(tkey)
        if prev_log is None or (now_mono - prev_log[0]) >= 60.0:
            suppressed = 0 if prev_log is None else prev_log[1]
            suffix = f" (suppressed {suppressed} repeats)" if suppressed > 0 else ""
            print(f"[ai-fast] Tick skipped for {sym}: {err_name}{suffix}")
            log_throttle[tkey] = (now_mono, 0)
        else:
            log_throttle[tkey] = (prev_log[0], prev_log[1] + 1)

    mt5_q: dict[str, tuple[Any, Any]] = {}
    mt5_src_broker: dict[str, str] = {}
    pending_skips: list[tuple[str, str, str]] = []
    for broker_id, venue in router.venues.items():
        if hasattr(venue, "_transport") and venue.account is not None:
            tr = venue._transport
            broker_key = str(broker_id)
            file_sig: tuple[int, int, int] | None = None
            if poll_cache is not None and hasattr(tr, "spool_dir"):
                try:
                    st_mt = os.lstat(Path(tr.spool_dir) / "market_ticks.json")
                    file_sig = (int(st_mt.st_ino), int(st_mt.st_size), int(st_mt.st_mtime_ns))
                except OSError:
                    file_sig = None
            cached = poll_cache.get(broker_key) if poll_cache is not None else None
            cache_hit = False
            if cached is not None:
                age_s = now_mono - float(cached.get("checked_mono", 0.0))
                has_fresh_ticks = bool(cached.get("ticks"))
                if not has_fresh_ticks:
                    err_ttl = 5.0 if bool(getattr(venue, "is_offline", False)) else 2.0
                    cache_hit = 0.0 <= age_s < err_ttl
                elif file_sig is not None and cached.get("file_sig") == file_sig:
                    cache_hit = 0.0 <= age_s < 1.0
            if cache_hit and cached is not None:
                batch_ticks = dict(cached.get("ticks") or {})
                err_map = dict(cached.get("errors") or {})
            else:
                batch_ticks = {}
                err_map: dict[str, str] = {}
                batch_fn = getattr(tr, "symbol_ticks_batch", None)
                if callable(batch_fn):
                    try:
                        batch_ticks, err_map = batch_fn(INDEX_INSTRUMENTS)
                    except (ContractError, OSError) as exc_batch:
                        err_name = type(exc_batch).__name__
                        err_map = {sym: err_name for sym in INDEX_INSTRUMENTS}
                else:
                    for sym in INDEX_INSTRUMENTS:
                        try:
                            batch_ticks[sym] = tr.symbol_tick(sym)
                        except (ContractError, OSError) as exc_sym:
                            err_map[sym] = type(exc_sym).__name__
                if poll_cache is not None:
                    poll_cache[broker_key] = {
                        "file_sig": file_sig,
                        "checked_mono": now_mono,
                        "ticks": dict(batch_ticks),
                        "errors": dict(err_map),
                    }
            got_tick = False
            for sym in INDEX_INSTRUMENTS:
                if sym in batch_ticks:
                    tk = batch_ticks[sym]
                    mt5_q[sym] = (tk.bid, tk.ask)
                    mt5_src_broker[sym] = broker_key
                    got_tick = True
                elif sym in err_map:
                    pending_skips.append((broker_key, sym, err_map[sym]))
            if got_tick and hasattr(router, "_status") and router._status.get(broker_id) == "DISCONNECTED":
                router._status[broker_id] = "ACTIVE"
    for broker_key, sym, err_name in pending_skips:
        if sym not in mt5_q:
            _emit_tick_skip(broker_key, sym, err_name)
    if not mt5_q:
        return None, {}
    now_dt = datetime.now(timezone.utc)
    obs_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    b_m1 = now_dt.strftime("%Y-%m-%dT%H:%M:00Z")
    b_m5 = now_dt.replace(minute=(now_dt.minute // 5) * 5, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:00Z")
    b_h1 = now_dt.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")
    prev_by_pair: dict[str, Mapping[str, Any]] = {}
    if isinstance(prev_stream, Mapping) and isinstance(prev_stream.get("markets"), list):
        for row in prev_stream["markets"]:
            if isinstance(row, Mapping) and isinstance(row.get("pair"), str):
                prev_by_pair[row["pair"]] = row
    _DISP = {"NAS100": "NAS100 / NDX", "US30": "US30 / DJIA", "SPX500": "SPX500 / S&P 500", "XAUUSD": "XAU/USD · Gold"}
    _TICK = {"NAS100": "0.25", "US30": "0.25", "SPX500": "0.01", "XAUUSD": "0.01"}
    needed_candle_syms = [
        sym_idx
        for sym_idx in INDEX_INSTRUMENTS
        if sym_idx in mt5_q
        and not (
            isinstance(prev_by_pair.get(sym_idx, {}).get("candles_m1"), list)
            and len(prev_by_pair[sym_idx]["candles_m1"]) >= 2
            and isinstance(prev_by_pair.get(sym_idx, {}).get("candles_m5"), list)
            and len(prev_by_pair[sym_idx]["candles_m5"]) >= 2
            and isinstance(prev_by_pair.get(sym_idx, {}).get("candles_h1"), list)
            and len(prev_by_pair[sym_idx]["candles_h1"]) >= 2
        )
    ]
    native_cache: dict[str, dict[str, list[dict[str, Any]]]] = {}
    if needed_candle_syms:
        for venue in router.venues.values():
            tr = getattr(venue, "_transport", None)
            rc_fn = getattr(tr, "read_index_candles", None)
            if callable(rc_fn):
                for sym_idx in needed_candle_syms:
                    if sym_idx not in native_cache:
                        got_c = rc_fn(sym_idx)
                        if isinstance(got_c, dict):
                            native_cache[sym_idx] = got_c
    idx_rows = []
    for sym_idx in INDEX_INSTRUMENTS:
        if sym_idx in mt5_q:
            b_px, a_px = mt5_q[sym_idx]
            mid_px = (b_px + a_px) / 2
            prev_row = prev_by_pair.get(sym_idx, {})
            nat = native_cache.get(sym_idx, {})
            p_m1 = prev_row.get("candles_m1") if isinstance(prev_row.get("candles_m1"), list) and len(prev_row["candles_m1"]) >= 2 else (nat.get("candles_m1") or prev_row.get("candles_m1"))
            p_m5 = prev_row.get("candles_m5") if isinstance(prev_row.get("candles_m5"), list) and len(prev_row["candles_m5"]) >= 2 else (nat.get("candles_m5") or prev_row.get("candles_m5"))
            p_h1 = prev_row.get("candles_h1") if isinstance(prev_row.get("candles_h1"), list) and len(prev_row["candles_h1"]) >= 2 else (nat.get("candles_h1") or prev_row.get("candles_h1"))
            idx_rows.append({
                "pair": sym_idx,
                "display_pair": _DISP.get(sym_idx, f"{sym_idx} / USD"),
                "category": "US_INDEX",
                "tick_size": _TICK.get(sym_idx, "0.25"),
                "bid": _dec_txt(b_px),
                "ask": _dec_txt(a_px),
                "mid": _dec_txt(mid_px),
                "spread_points": _dec_txt(a_px - b_px),
                "observed_at": obs_iso,
                "feed_mode": "MT5_DIRECT_SPOOL_50MS",
                "source_provider": f"MT5_BROKER:{mt5_src_broker.get(sym_idx, 'MT5')}",
                "source_broker_id": mt5_src_broker.get(sym_idx, "MT5"),
                "is_independent_public": False,
                "candles_m1": _roll_mt5_index_bars(p_m1, b_m1, mid_px, _dec_txt, max_stitch_gap_seconds=120),
                "candles_m5": _roll_mt5_index_bars(p_m5, b_m5, mid_px, _dec_txt, max_stitch_gap_seconds=600),
                "candles_h1": _roll_mt5_index_bars(p_h1, b_h1, mid_px, _dec_txt, max_stitch_gap_seconds=7200),
            })
    if not idx_rows:
        return None, mt5_q
    unique_src = sorted(set(mt5_src_broker.values()))
    top_broker = unique_src[0] if len(unique_src) == 1 else "MULTI_MT5"
    prev_seq = int(prev_stream.get("sequence", 0)) if isinstance(prev_stream, Mapping) else 0
    return {
        "schema": "cas-forex.index-stream/1",
        "sequence": prev_seq + 1,
        "observed_at": obs_iso,
        "feed_mode": "MT5_DIRECT_SPOOL_50MS",
        "source_provider": "MT5_DIRECT_SPOOL_50MS",
        "source_broker_id": top_broker,
        "is_independent_public": False,
        "instruments": list(INDEX_INSTRUMENTS),
        "markets": idx_rows,
    }, mt5_q


def stamp_public_index_provenance(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Validate & stamp explicit independent-public provenance on PublicUsIndexFeedClient snapshots (Finding [5])."""
    if not isinstance(doc, Mapping):
        raise ContractError("public index stream must be a mapping")
    feed_mode = str(doc.get("feed_mode") or "PUBLIC_US_INDEX_FEED").strip()
    if (
        "MT5" in feed_mode.upper()
        or doc.get("is_independent_public") is False
        or doc.get("source_broker_id") is not None
    ):
        raise ContractError("Refusing to label broker/MT5 index stream as independent public reference")
    top_obs = str(doc.get("observed_at") or "").strip()
    if not top_obs:
        raise ContractError("public index stream missing observed_at")
    src_prov = str(doc.get("source_provider") or feed_mode or "PUBLIC_US_INDEX_FEED").strip()
    if "MT5" in src_prov.upper() or src_prov.upper() in ("HUGOSWAY_MT5", "LHFX_MT5"):
        raise ContractError(f"Forbidden MT5 source_provider {src_prov!r} on public index stream")
    out = dict(doc)
    out["source_provider"] = src_prov
    out["source_broker_id"] = None
    out["is_independent_public"] = True
    rows_out: list[dict[str, Any]] = []
    for raw_row in doc.get("markets") or ():
        if not isinstance(raw_row, Mapping):
            continue
        if (
            raw_row.get("is_independent_public") is False
            or raw_row.get("source_broker_id") is not None
            or "MT5" in str(raw_row.get("feed_mode") or "").upper()
        ):
            raise ContractError("Refusing broker-derived row inside public index stream")
        r_copy = dict(raw_row)
        r_copy["source_provider"] = str(raw_row.get("source_provider") or src_prov)
        r_copy["source_broker_id"] = None
        r_copy["is_independent_public"] = True
        r_copy["observed_at"] = str(raw_row.get("observed_at") or top_obs)
        rows_out.append(r_copy)
    out["markets"] = rows_out
    return out


def build_public_index_reference_map(
    public_doc: Mapping[str, Any] | None,
    symbols: Any,
) -> dict[str, dict[str, Any]]:
    """Extract provenance-preserving independent public index quotes; rejects any MT5/broker-derived data (Finding [5])."""
    from cas_forex_revamp.contracts import parse_decimal as _parse_dec

    if not isinstance(public_doc, Mapping):
        return {}
    if (
        public_doc.get("is_independent_public") is not True
        or public_doc.get("source_broker_id") is not None
        or "MT5" in str(public_doc.get("feed_mode") or "").upper()
    ):
        return {}
    top_obs = str(public_doc.get("observed_at") or "").strip()
    top_prov = str(public_doc.get("source_provider") or public_doc.get("feed_mode") or "PUBLIC_US_INDEX_FEED").strip()
    if not top_obs or "MT5" in top_prov.upper() or top_prov.upper() in ("HUGOSWAY_MT5", "LHFX_MT5"):
        return {}
    wanted = {str(s) for s in symbols}
    out: dict[str, dict[str, Any]] = {}
    for row in public_doc.get("markets") or ():
        if not isinstance(row, Mapping):
            continue
        sym = str(row.get("pair") or "")
        if sym not in wanted or "bid" not in row or "ask" not in row:
            continue
        if (
            row.get("is_independent_public") is not True
            or row.get("source_broker_id") is not None
            or "MT5" in str(row.get("feed_mode") or "").upper()
        ):
            continue
        row_prov = str(row.get("source_provider") or top_prov).strip()
        row_obs = str(row.get("observed_at") or top_obs).strip()
        if not row_obs or "MT5" in row_prov.upper() or row_prov.upper() in ("HUGOSWAY_MT5", "LHFX_MT5"):
            continue
        out[sym] = {
            "bid": _parse_dec(str(row["bid"]), "bid"),
            "ask": _parse_dec(str(row["ask"]), "ask"),
            "source_provider": row_prov,
            "source_broker_id": None,
            "is_independent_public": True,
            "observed_at": row_obs,
        }
    return out


MAX_HTTP_RPC_BYTES = 262_144
MAX_EXPLAINER_AUDIO_RPC_BYTES = 2_200_000
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
_FORBIDDEN_ROUTING_KEY_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "token",
    "secret",
    "login",
    "credential",
    "api_key",
)
STRICT_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'"
)

_KNOWN_METRICS_ROUTES: frozenset[str] = frozenset({
    "/",
    "/ui",
    "/ui/",
    "/ui/index.html",
    "/api/health",
    "/api/market-stream",
    "/api/broker-routing",
    "/api/ai-models",
    "/api/ai-trader",
    "/api/treasury",
    "/api/audit-verify",
    "/api/metrics",
    "/api/parallel-tiers",
    "/api/index-stream",
    "/api/market-events",
    "/api/boot",
    "/api/cockpit",
    "/api/decision-read",
    "/api/select-ai-model",
    "/api/thinking-depth",
    "/api/treasury-config",
    "/api/treasury-action",
    "/api/ai-overseer-action",
    "/api/ai-trader-control",
    "/api/resolve-evidence",
    "/api/prepare-control",
    "/api/request-control",
    "/api/read-control",
    "/api/prepare-close",
    "/api/request-reviewed-close",
    "/api/read-command",
    "/api/explainer-ask",
    "/api/explainer-tts",
    "/api/pair-code",
    "/api/pair-revoke",
    "/api/pair-exchange",
    "/api/auth-session",
    "/api/rotate-token",
    "/api/treasury-prepare",
    "/api/ai-model-select",
    "/api/aggression-dial",
    "/api/compounding",
    "/api/option-b-demo",
    "/api/demo-high-growth-profile",
})

_CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".svg": "image/svg+xml",
}


def validate_public_origin(raw: str | None) -> tuple[str | None, str | None]:
    """Validate optional HTTPS reverse-proxy origin for Phone/Cloud TLS access."""
    if raw is None or not str(raw).strip():
        return None, None
    cleaned = str(raw).strip().rstrip("/")
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ContractError("public_origin must use clean https://hostname")
    if parsed.port not in (None, 443) or parsed.path or parsed.query or parsed.fragment:
        raise ContractError("public_origin must not contain path, query, fragment, or non-443 port")
    return cleaned, parsed.netloc


class _CockpitSecret:
    """Holds per-launch bearer secret without exposing it in repr/str/tracebacks."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or len(value) < 32:
            raise ContractError("cockpit auth secret requires at least 32 characters of entropy")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "'[REDACTED]'"

    def __str__(self) -> str:
        return "[REDACTED]"


def safe_broker_routing_payload(payload: Any, *, path: str = "$") -> Any:
    """Validate that a broker routing payload is secret-free, float-free, safe-integer JSON."""
    if payload is None or type(payload) in (str, bool):
        return payload
    if type(payload) is int:
        if not (-MAX_SAFE_JSON_INTEGER <= payload <= MAX_SAFE_JSON_INTEGER):
            raise ContractError(f"{path}: integer exceeds Number.MAX_SAFE_INTEGER")
        return payload
    if type(payload) in (list, tuple):
        return [safe_broker_routing_payload(item, path=f"{path}[{idx}]") for idx, item in enumerate(payload)]
    if type(payload) is dict:
        out: dict[str, Any] = {}
        for key, value in payload.items():
            if type(key) is not str:
                raise ContractError(f"{path}: object keys must be strings")
            lowered = key.lower()
            if any(tok in lowered for tok in _FORBIDDEN_ROUTING_KEY_TOKENS):
                raise ContractError(f"{path}: credential-like key {key!r} is forbidden in broker routing payloads")
            out[key] = safe_broker_routing_payload(value, path=f"{path}.{key}")
        return out
    raise ContractError(f"{path}: unsupported broker routing value type {type(payload).__name__}")


def validate_loopback_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise ContractError("loopback host must be a non-empty string")
    normalized = "127.0.0.1" if host.strip() == "localhost" else host.strip()
    try:
        addr = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise ContractError(f"cockpit server host must be a literal loopback IP, got {host!r}") from exc
    if not addr.is_loopback or addr.is_unspecified:
        raise ContractError(f"non-loopback bind address forbidden: {host!r}")
    return str(addr)


class LoopbackCockpitServer:
    """Inert-until-started authenticated loopback HTTP/SSE server for CAS Forex Operate UI."""

    def __init__(
        self,
        *,
        repo_root: str | Path,
        host: str = "127.0.0.1",
        port: int = 0,
        emergency_port: int = 0,
        ui_service: Any | None = None,
        market_stream_reader: Callable[[], dict[str, Any] | None] | None = None,
        broker_router_reader: Callable[[], dict[str, Any] | None] | None = None,
        ai_model_registry: Any | None = None,
        autonomous_trader: Any | None = None,
        index_stream_reader: Callable[[], dict[str, Any] | None] | None = None,
        profit_vault: Any | None = None,
        parallel_tiers: Any | None = None,
        aggression_dial: Any | None = None,
        compounding_controller: Any | None = None,
        option_b_demo: Any | None = None,
        demo_high_growth_store: DemoHighGrowthProfileStore | None = None,
        phase8_bridge: Any | None = None,
        owner_recovery: Any | None = None,
        model_execution_gate: Any | None = None,
        auth_token: str | None = None,
        token_file: str | Path | None = None,
        public_origin: str | None = None,
        withdrawal_provider_verifier: Callable[[str, str], Mapping[str, Any]] | None = None,
        max_ordinary_connections: int = 16,
        max_emergency_connections: int = 4,
        header_deadline_seconds: float = 3.0,
        pre_auth_timeout_seconds: float | None = None,
        pre_auth_body_deadline_seconds: float = DEFAULT_PRE_AUTH_BODY_DEADLINE_SECONDS,
        max_pre_auth_body_readers: int = DEFAULT_MAX_PRE_AUTH_BODY_READERS,
        rotation_drain_timeout_seconds: float = 5.0,
        pre_auth_conn_rate_limit: int = 256,
        global_pre_auth_rate_limit: int | None = None,
        emergency_unix_socket: str | Path | None = None,
        emergency_header_deadline_seconds: float = DEFAULT_EMERGENCY_HEADER_DEADLINE_SECONDS,
        mono_clock: Callable[[], float] | None = None,
    ) -> None:
        self._host = validate_loopback_host(host)
        if type(port) is not int or not (0 <= port <= 65535):
            raise ContractError("port must be an integer in 0..65535")
        if type(emergency_port) is not int or not (0 <= emergency_port <= 65535):
            raise ContractError("emergency_port must be an integer in 0..65535")
        self._port = port
        self._emergency_port_cfg = emergency_port
        self._repo_root = Path(repo_root).resolve()
        self._ui_dir = (self._repo_root / "ui").resolve()
        self._contracts_dir = (self._repo_root / "docs" / "contracts").resolve()
        self._ui_service = ui_service
        self._market_stream_reader = market_stream_reader
        if broker_router_reader is not None and not callable(broker_router_reader):
            raise ContractError("broker_router_reader must be callable")
        self._broker_router_reader = broker_router_reader
        if index_stream_reader is not None and not callable(index_stream_reader):
            raise ContractError("index_stream_reader must be callable")
        self._ai_model_registry = ai_model_registry
        self._autonomous_trader = autonomous_trader
        self._index_stream_reader = index_stream_reader
        self._profit_vault = profit_vault
        self._parallel_tiers = parallel_tiers
        inferred_dial = aggression_dial
        if inferred_dial is None and autonomous_trader is not None:
            inferred_dial = getattr(autonomous_trader, "aggression_dial", None) or getattr(
                autonomous_trader, "_aggression_dial", None
            )
        if inferred_dial is None and parallel_tiers is not None:
            inferred_dial = getattr(parallel_tiers, "aggression_dial", None) or getattr(
                parallel_tiers, "_aggression_dial", None
            )
        self._aggression_dial = inferred_dial
        inferred_comp = compounding_controller
        if inferred_comp is None and autonomous_trader is not None:
            inferred_comp = getattr(autonomous_trader, "compounding_controller", None) or getattr(
                autonomous_trader, "_compounding_controller", None
            )
        self._compounding_controller = inferred_comp
        self._option_b_demo = option_b_demo
        self._demo_high_growth_store: DemoHighGrowthProfileStore | None = demo_high_growth_store
        inferred_p8 = phase8_bridge
        if inferred_p8 is None and autonomous_trader is not None:
            inferred_p8 = getattr(autonomous_trader, "phase8_bridge", None) or getattr(
                autonomous_trader, "_phase8_bridge", None
            )
        self._phase8_bridge = inferred_p8
        self._owner_recovery = owner_recovery or (
            getattr(autonomous_trader, "_owner_verifier", None) if autonomous_trader is not None else None
        )
        inferred_gate = None
        if autonomous_trader is not None:
            cand_gate = getattr(autonomous_trader, "_execution_gate", None)
            if cand_gate is not None and (
                callable(getattr(cand_gate, "authorize_auxiliary_call", None))
                or callable(getattr(cand_gate, "admit_scout_call", None))
            ):
                inferred_gate = cand_gate
        self._model_gate = model_execution_gate if model_execution_gate is not None else inferred_gate
        if (
            self._model_gate is not None
            and self._ai_model_registry is not None
            and callable(getattr(self._ai_model_registry, "bind_execution_gate", None))
        ):
            self._ai_model_registry.bind_execution_gate(self._model_gate)

        self._httpd: _ExclusiveThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._emergency_httpd: _EmergencyAdmissionHTTPServer | None = None
        self._emergency_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sse_cond = threading.Condition()
        self._sse_version = 0
        self._last_routing_error: str | None = None
        self._withdrawal_provider_verifier = withdrawal_provider_verifier
        self._max_ordinary_connections = max(1, int(max_ordinary_connections))
        self._max_emergency_connections = max(1, int(max_emergency_connections))
        eff_deadline = header_deadline_seconds if pre_auth_timeout_seconds is None else pre_auth_timeout_seconds
        self._header_deadline_seconds = max(0.05, float(eff_deadline))
        self._pre_auth_body_deadline_seconds = min(
            DEFAULT_PRE_AUTH_BODY_DEADLINE_SECONDS, max(0.05, float(pre_auth_body_deadline_seconds))
        )
        self._max_pre_auth_body_readers = max(1, min(int(max_pre_auth_body_readers), max(1, self._max_ordinary_connections // 2)))
        self._rotation_drain_timeout_seconds = max(0.0, float(rotation_drain_timeout_seconds))
        self._pre_auth_conn_rate_limit = max(1, int(pre_auth_conn_rate_limit))
        self._global_pre_auth_rate_limit = (
            self._pre_auth_conn_rate_limit
            if global_pre_auth_rate_limit is None
            else max(1, int(global_pre_auth_rate_limit))
        )
        self._emergency_unix_socket_cfg = (
            Path(str(emergency_unix_socket).strip())
            if emergency_unix_socket is not None and str(emergency_unix_socket).strip()
            else None
        )
        self._emergency_header_deadline_seconds = min(
            DEFAULT_EMERGENCY_HEADER_DEADLINE_SECONDS,
            max(0.05, float(emergency_header_deadline_seconds)),
        )
        self._mono = mono_clock or time.monotonic
        self._auth_lock = threading.RLock()
        self._auth_cond = threading.Condition(self._auth_lock)
        self._explicit_in_memory_auth_token: _CockpitSecret | None = None
        if auth_token is not None:
            if not isinstance(auth_token, str) or not auth_token.strip():
                raise ContractError("auth_token must be a non-empty string when supplied")
            self._explicit_in_memory_auth_token = _CockpitSecret(auth_token.strip())
        self._auth_secret: _CockpitSecret | None = None
        self._session_epoch: str | None = None
        self._revoked_epochs: set[str] = set()
        self._inflight_commits: dict[str, int] = {}
        self._pairing_codes: dict[str, _PairingCodeRecord] = {}
        self._device_sessions: dict[str, _DeviceSessionRecord] = {}
        self._pair_exchange_tracker = _BoundedPreAuthRateTracker(
            per_principal_limit=MAX_PAIR_EXCHANGE_ATTEMPTS_PER_WINDOW,
            global_limit=MAX_PAIR_EXCHANGE_ATTEMPTS_PER_WINDOW * 2,
            window_seconds=PAIR_EXCHANGE_WINDOW_SECONDS,
            max_keys=MAX_TRACKED_PRE_AUTH_KEYS,
        )
        self._pair_exchange_attempts: OrderedDict[str, list[float]] = self._pair_exchange_tracker.per_key
        self._worker_sem = threading.BoundedSemaphore(self._max_ordinary_connections)
        self._pre_auth_body_sem = threading.BoundedSemaphore(self._max_pre_auth_body_readers)
        self._emergency_sem = threading.BoundedSemaphore(self._max_emergency_connections)
        self._sse_sem = threading.BoundedSemaphore(4)
        self._sockets_lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        self._metrics_lock = threading.Lock()
        self._started_mono: float | None = None
        self._requests_total = 0
        self._auth_failures_total = 0
        self._pre_auth_timeouts_total = 0
        self._sse_active_clients = 0
        self._sse_events_sent_total = 0
        self._sse_heartbeats_sent_total = 0
        self._route_counts: dict[str, int] = {}
        if token_file is not None and str(token_file).strip():
            tf_raw = str(token_file).strip()
            tf_path = Path(tf_raw)
            if not tf_path.is_absolute() or ".." in tf_path.parts:
                raise ContractError(f"token_file must be an absolute path without '..': {tf_raw!r}")
            self._token_file: Path | None = tf_path
        else:
            self._token_file = None
        self._public_origin, self._public_host = validate_public_origin(public_origin)

    def __repr__(self) -> str:
        return (
            f"LoopbackCockpitServer(host={self._host!r}, started={self._httpd is not None}, "
            f"auth_token='[REDACTED]')"
        )

    @property
    def bound_port(self) -> int:
        if self._httpd is None:
            raise ContractError("server has not been started")
        return int(self._httpd.server_address[1])

    @property
    def emergency_port(self) -> int:
        if self._emergency_httpd is None:
            raise ContractError("server has not been started")
        return int(self._emergency_httpd.server_address[1])

    @property
    def expected_host_header(self) -> str:
        port = self.bound_port
        return f"[{self._host}]:{port}" if ":" in self._host else f"{self._host}:{port}"

    @property
    def emergency_expected_host_header(self) -> str:
        port = self.emergency_port
        return f"[{self._host}]:{port}" if ":" in self._host else f"{self._host}:{port}"

    @property
    def base_url(self) -> str:
        return f"http://{self.expected_host_header}"

    @property
    def emergency_base_url(self) -> str:
        return f"http://{self.emergency_expected_host_header}"

    @property
    def emergency_unix_socket_path(self) -> Path | None:
        if self._emergency_httpd is None:
            return None
        return self._emergency_httpd.unix_socket_path

    @property
    def pre_auth_timeouts_total(self) -> int:
        with self._metrics_lock:
            return int(self._pre_auth_timeouts_total)

    @property
    def auth_token(self) -> str:
        with self._auth_lock:
            if self._httpd is None or self._auth_secret is None:
                raise ContractError("server has not been started")
            return self._auth_secret.reveal()

    @property
    def session_epoch(self) -> str:
        with self._auth_lock:
            if self._httpd is None or self._session_epoch is None:
                raise ContractError("server has not been started")
            return self._session_epoch

    def auth_headers(self) -> dict[str, str]:
        """Convenience header mapping (`Authorization: Bearer <token>`) for authenticated local owner clients."""
        return {"Authorization": f"Bearer {self.auth_token}"}

    def _prune_ephemeral_auth_unlocked(self, now_m: float) -> None:
        expired_codes = [
            k for k, rec in self._pairing_codes.items()
            if now_m >= rec.expires_mono or rec.epoch != self._session_epoch
        ]
        for k in expired_codes:
            self._pairing_codes.pop(k, None)
        expired_sessions = [
            k for k, rec in self._device_sessions.items()
            if now_m >= rec.expires_mono or rec.epoch != self._session_epoch
        ]
        for k in expired_sessions:
            self._device_sessions.pop(k, None)

    def mint_pairing_code(
        self,
        *,
        ttl_seconds: int = PAIR_CODE_TTL_SECONDS,
        base_origin: str | None = None,
    ) -> dict[str, Any]:
        """Mint a single-use, short-lived pairing nonce (NEVER exposing the owner primary bearer in URLs)."""
        if type(ttl_seconds) is not int or not (10 <= ttl_seconds <= PAIR_CODE_TTL_SECONDS):
            raise ContractError(f"pairing ttl_seconds must be in 10..{PAIR_CODE_TTL_SECONDS}")
        with self._auth_lock:
            if self._httpd is None or self._auth_secret is None or self._session_epoch is None:
                raise ContractError("server has not been started")
            now_m = self._mono()
            self._prune_ephemeral_auth_unlocked(now_m)
            while len(self._pairing_codes) >= MAX_ACTIVE_PAIRING_CODES:
                oldest_key = min(self._pairing_codes, key=lambda k: self._pairing_codes[k].created_mono)
                self._pairing_codes.pop(oldest_key, None)
            pair_code = "pair-" + secrets.token_urlsafe(24)
            code_sha = sha256(pair_code.encode("utf-8")).hexdigest()
            exp_iso = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self._pairing_codes[code_sha] = _PairingCodeRecord(
                code_sha256=code_sha,
                epoch=self._session_epoch,
                created_mono=now_m,
                expires_mono=now_m + float(ttl_seconds),
                expires_at_iso=exp_iso,
            )
            eff_origin = base_origin or self._public_origin or self.base_url
            quoted = urllib.parse.quote(pair_code, safe="")
            return {
                "pair_code": pair_code,
                "pairing_url": f"{eff_origin}/ui/index.html?pair_code={quoted}",
                "expires_at": exp_iso,
                "ttl_seconds": int(ttl_seconds),
                "scope": SESSION_SCOPE_DEVICE_READ_EXPLAINER,
            }

    def revoke_pairing(
        self,
        *,
        pair_code: str | None = None,
        revoke_sessions: bool = True,
        exclude_sock: socket.socket | None = None,
    ) -> dict[str, Any]:
        """Immediately revoke active pairing code(s) and optionally paired device sessions."""
        close_socks = False
        with self._auth_cond:
            now_m = self._mono()
            self._prune_ephemeral_auth_unlocked(now_m)
            if pair_code is not None and str(pair_code).strip():
                target_sha = sha256(str(pair_code).strip().encode("utf-8")).hexdigest()
                revoked_codes = 1 if self._pairing_codes.pop(target_sha, None) is not None else 0
            else:
                revoked_codes = len(self._pairing_codes)
                self._pairing_codes.clear()
            revoked_sessions = 0
            if revoke_sessions:
                revoked_sessions = len(self._device_sessions)
                if revoked_sessions > 0:
                    close_socks = True
                self._device_sessions.clear()
            self._auth_cond.notify_all()
        self.notify_stream_updated()
        if close_socks:
            self._close_active_sockets(exclude_sock=exclude_sock)
        return {
            "ok": True,
            "revoked_codes": int(revoked_codes),
            "revoked_sessions": int(revoked_sessions),
        }

    def exchange_pairing_code(
        self,
        pair_code: str,
        *,
        peer_key: str = "127.0.0.1",
    ) -> tuple[int, dict[str, Any]]:
        """Atomically exchange a single-use pairing code for a least-privilege device bearer token."""
        canon_peer = _canonical_pre_auth_principal(peer_key)
        now_m = self._mono()
        with self._auth_cond:
            if not self._pair_exchange_tracker.try_consume(canon_peer, now_m):
                return int(HTTPStatus.TOO_MANY_REQUESTS), {"error": "Too many pairing exchange attempts"}

            if (
                self._stop_event.is_set()
                or self._httpd is None
                or self._session_epoch is None
                or not isinstance(pair_code, str)
                or not _PAIR_CODE_RE.match(pair_code.strip())
            ):
                return int(HTTPStatus.UNAUTHORIZED), {"error": "Invalid, expired, or already-used pairing code"}

            self._prune_ephemeral_auth_unlocked(now_m)
            cand_sha = sha256(pair_code.strip().encode("utf-8")).hexdigest()
            matched_key: str | None = None
            for k_sha in list(self._pairing_codes.keys()):
                if hmac.compare_digest(k_sha, cand_sha):
                    matched_key = k_sha
            if matched_key is None:
                return int(HTTPStatus.UNAUTHORIZED), {"error": "Invalid, expired, or already-used pairing code"}
            rec = self._pairing_codes.pop(matched_key)
            if now_m >= rec.expires_mono or rec.epoch != self._session_epoch:
                return int(HTTPStatus.UNAUTHORIZED), {"error": "Invalid, expired, or already-used pairing code"}

            while len(self._device_sessions) >= MAX_ACTIVE_DEVICE_SESSIONS:
                oldest_s = min(self._device_sessions, key=lambda k: self._device_sessions[k].created_mono)
                self._device_sessions.pop(oldest_s, None)

            dev_tok = "casdev-" + secrets.token_urlsafe(32)
            dev_sha = sha256(dev_tok.encode("utf-8")).hexdigest()
            exp_iso = (
                datetime.now(timezone.utc) + timedelta(seconds=DEVICE_SESSION_TTL_SECONDS)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self._device_sessions[dev_sha] = _DeviceSessionRecord(
                token_sha256=dev_sha,
                epoch=self._session_epoch,
                created_mono=now_m,
                expires_mono=now_m + float(DEVICE_SESSION_TTL_SECONDS),
                expires_at_iso=exp_iso,
            )
            return int(HTTPStatus.OK), {
                "session_token": dev_tok,
                "session_scope": SESSION_SCOPE_DEVICE_READ_EXPLAINER,
                "owner_controls_allowed": False,
                "session_epoch": self._session_epoch,
                "expires_at": exp_iso,
            }

    @property
    def bootstrap_url(self) -> str:
        """Ephemeral single-use `?pair_code=` URL (NEVER embeds the primary owner bearer token)."""
        return str(self.mint_pairing_code(ttl_seconds=PAIR_CODE_TTL_SECONDS, base_origin=self.base_url)["pairing_url"])

    def _register_socket(self, sock: socket.socket) -> None:
        with self._sockets_lock:
            self._active_sockets.add(sock)

    def _unregister_socket(self, sock: socket.socket) -> None:
        with self._sockets_lock:
            self._active_sockets.discard(sock)

    def _close_active_sockets(self, *, exclude_sock: socket.socket | None = None) -> None:
        with self._sockets_lock:
            socks = [s for s in self._active_sockets if s is not exclude_sock]
            if exclude_sock is not None and exclude_sock in self._active_sockets:
                self._active_sockets = {exclude_sock}
            else:
                self._active_sockets.clear()
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _verify_token_unlocked(self, bearer_token: str, captured_epoch: str, *, allow_device_scope: bool = False) -> bool:
        if (
            self._stop_event.is_set()
            or self._httpd is None
            or captured_epoch in self._revoked_epochs
            or self._auth_secret is None
            or self._session_epoch != captured_epoch
        ):
            return False
        if hmac.compare_digest(bearer_token.encode("utf-8"), self._auth_secret.reveal().encode("utf-8")):
            return True
        if not allow_device_scope:
            return False
        now_m = self._mono()
        self._prune_ephemeral_auth_unlocked(now_m)
        cand_sha = sha256(bearer_token.encode("utf-8")).hexdigest()
        for k_sha, rec in self._device_sessions.items():
            if hmac.compare_digest(k_sha, cand_sha) and rec.epoch == captured_epoch and now_m < rec.expires_mono:
                return True
        return False

    def _verify_emergency_owner_bearer(self, candidate: str) -> tuple[bool, bool]:
        """Constant-time pre-worker check returning (is_owner, is_device) for _EmergencyAdmissionHTTPServer."""
        if not isinstance(candidate, str) or not candidate:
            return False, False
        with self._auth_lock:
            secret = self._auth_secret
            epoch = self._session_epoch or ""
            if secret is None or self._stop_event.is_set() or not epoch or epoch in self._revoked_epochs:
                return False, False
            expected_owner = secret.reveal().encode("utf-8")
            now_m = self._mono()
            self._prune_ephemeral_auth_unlocked(now_m)
            dev_snapshot = list(self._device_sessions.items())
        if hmac.compare_digest(candidate.encode("utf-8"), expected_owner):
            return True, False
        cand_sha = sha256(candidate.encode("utf-8")).hexdigest()
        for k_sha, rec in dev_snapshot:
            if hmac.compare_digest(k_sha, cand_sha) and rec.epoch == epoch and now_m < rec.expires_mono:
                return False, True
        return False, False

    def _verify_commit_epoch(
        self,
        bearer_token: str | None,
        captured_epoch: str,
        *,
        allow_device_scope: bool = False,
    ) -> bool:
        if not bearer_token or not captured_epoch:
            return False
        with self._auth_cond:
            return self._verify_token_unlocked(bearer_token, captured_epoch, allow_device_scope=allow_device_scope)

    def _assert_epoch_active(
        self,
        bearer_token: str | None,
        captured_epoch: str,
        *,
        allow_device_scope: bool = False,
    ) -> None:
        """Atomic pre-effect epoch recheck aborting external side effects if session was rotated/revoked (Finding [12])."""
        if not self._verify_commit_epoch(
            bearer_token, captured_epoch, allow_device_scope=allow_device_scope
        ):
            raise _SessionRevokedError("session epoch revoked prior to external effect")

    @contextmanager
    def _commit_lease(
        self,
        bearer_token: str | None,
        captured_epoch: str,
        *,
        hold_lock: bool = True,
        allow_device_scope: bool = False,
    ):
        """Acquire a revocable commit lease verified at commit time; rotation drains active leases before returning (Finding [10], [12])."""
        if not bearer_token or not captured_epoch:
            raise _SessionRevokedError("missing bearer or epoch")
        with self._auth_cond:
            if not self._verify_token_unlocked(bearer_token, captured_epoch, allow_device_scope=allow_device_scope):
                raise _SessionRevokedError("session epoch revoked or bearer mismatch")
            self._inflight_commits[captured_epoch] = self._inflight_commits.get(captured_epoch, 0) + 1
            if hold_lock:
                try:
                    yield captured_epoch
                finally:
                    rem = self._inflight_commits.get(captured_epoch, 1) - 1
                    if rem <= 0:
                        self._inflight_commits.pop(captured_epoch, None)
                    else:
                        self._inflight_commits[captured_epoch] = rem
                    self._auth_cond.notify_all()
                return
        try:
            yield captured_epoch
        finally:
            with self._auth_cond:
                rem = self._inflight_commits.get(captured_epoch, 1) - 1
                if rem <= 0:
                    self._inflight_commits.pop(captured_epoch, None)
                else:
                    self._inflight_commits[captured_epoch] = rem
                self._auth_cond.notify_all()

    def _write_token_file(self, tok_value: str) -> None:
        if self._token_file is None:
            return
        create_owner_only_file_atomic(
            self._token_file.parent,
            self._token_file.name,
            (tok_value + "\n").encode("utf-8"),
            replace_existing=True,
            label="cockpit file",
        )

    def _load_or_init_auth_token(self) -> None:
        """Mint and atomically persist a brand-new high-entropy bearer on EVERY launch (Finding [15])."""
        if self._token_file is not None:
            parent_path, dir_fd = open_verified_directory_fd(
                self._token_file.parent, create=True, label="cockpit directory"
            )
            try:
                fname = self._token_file.name
                exists = False
                if os.name == "posix" and dir_fd is not None:
                    try:
                        os.lstat(fname, dir_fd=dir_fd)
                        exists = True
                    except FileNotFoundError:
                        exists = False
                else:
                    exists = os.path.lexists(self._token_file)
                prev_raw: str | None = None
                if exists:
                    raw_bytes, _ = verify_and_read_owner_only_file(
                        parent_path, fname, dir_fd=dir_fd, label="cockpit file", max_bytes=256
                    )
                    prev_raw = raw_bytes.decode("utf-8").strip()
                    if not _is_valid_generated_cockpit_token(prev_raw):
                        raise ContractError(
                            "Refusing malformed or low-entropy pre-existing cockpit token file (expected generated 43+ char high-entropy token)"
                        )
                fresh_val = secrets.token_urlsafe(32)
                while prev_raw is not None and hmac.compare_digest(fresh_val.encode("utf-8"), prev_raw.encode("utf-8")):
                    fresh_val = secrets.token_urlsafe(32)
                new_tok = _CockpitSecret(fresh_val)
                new_epoch = "epoch-" + secrets.token_hex(16)
                create_owner_only_file_atomic(
                    parent_path,
                    fname,
                    (new_tok.reveal() + "\n").encode("utf-8"),
                    dir_fd=dir_fd,
                    replace_existing=exists,
                    label="cockpit file",
                )
                with self._auth_cond:
                    if self._session_epoch is not None:
                        self._revoked_epochs.add(self._session_epoch)
                    self._auth_secret = new_tok
                    self._session_epoch = new_epoch
                    self._pairing_codes.clear()
                    self._device_sessions.clear()
                    if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                        self._ui_service.rotate_adapter_session(new_epoch)
                return
            finally:
                if dir_fd is not None:
                    os.close(dir_fd)
        if self._explicit_in_memory_auth_token is not None:
            new_epoch = "epoch-" + secrets.token_hex(16)
            with self._auth_cond:
                if self._session_epoch is not None:
                    self._revoked_epochs.add(self._session_epoch)
                self._auth_secret = _CockpitSecret(self._explicit_in_memory_auth_token.reveal())
                self._session_epoch = new_epoch
                self._pairing_codes.clear()
                self._device_sessions.clear()
                if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                    self._ui_service.rotate_adapter_session(new_epoch)
            return
        self.rotate_auth_token()

    def rotate_auth_token_detailed(
        self,
        *,
        expected_bearer: str | None = None,
        expected_epoch: str | int | None = None,
        exclude_sock: socket.socket | None = None,
        drain_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Atomic compare-and-rotate bearer + epoch under single _auth_cond critical section (Finding [12])."""
        with self._auth_cond:
            if expected_epoch is not None or expected_bearer is not None:
                exp_ep_str = str(expected_epoch) if expected_epoch is not None else None
                epoch_ok = (
                    exp_ep_str is None
                    or (
                        self._session_epoch is not None
                        and self._session_epoch == exp_ep_str
                        and exp_ep_str not in self._revoked_epochs
                    )
                )
                bearer_ok = (
                    expected_bearer is None
                    or (
                        self._auth_secret is not None
                        and isinstance(expected_bearer, str)
                        and bool(expected_bearer)
                        and hmac.compare_digest(
                            expected_bearer.encode("utf-8"),
                            self._auth_secret.reveal().encode("utf-8"),
                        )
                    )
                )
                if self._stop_event.is_set() or not epoch_ok or not bearer_ok:
                    return {
                        "status": "STALE_ROTATE_EPOCH",
                        "rotated": False,
                        "stale_epoch": True,
                        "old_epoch_revoked": True,
                        "rotation_complete": False,
                        "active_old_leases": 0,
                        "session_epoch": self._session_epoch or "",
                    }
            old_epoch = self._session_epoch
            if old_epoch is not None:
                self._revoked_epochs.add(old_epoch)
            prev_tok = self._auth_secret.reveal() if self._auth_secret is not None else None
            fresh_val = secrets.token_urlsafe(32)
            while prev_tok is not None and hmac.compare_digest(fresh_val.encode("utf-8"), prev_tok.encode("utf-8")):
                fresh_val = secrets.token_urlsafe(32)
            new_tok = _CockpitSecret(fresh_val)
            new_epoch = "epoch-" + secrets.token_hex(16)
            self._auth_secret = new_tok
            self._session_epoch = new_epoch
            self._pairing_codes.clear()
            self._device_sessions.clear()
            if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                self._ui_service.rotate_adapter_session(new_epoch)
            if self._token_file is not None:
                self._write_token_file(new_tok.reveal())
            self._auth_cond.notify_all()
        self.notify_stream_updated()
        self._close_active_sockets(exclude_sock=exclude_sock)
        eff_drain = (
            self._rotation_drain_timeout_seconds
            if drain_timeout_seconds is None
            else max(0.0, float(drain_timeout_seconds))
        )
        drain_deadline = time.monotonic() + eff_drain
        with self._auth_cond:
            while (
                sum(cnt for ep, cnt in self._inflight_commits.items() if ep != self._session_epoch and cnt > 0) > 0
                and time.monotonic() < drain_deadline
            ):
                self._auth_cond.wait(timeout=min(0.05, max(0.005, drain_deadline - time.monotonic())))
            active_old = sum(
                cnt for ep, cnt in self._inflight_commits.items() if ep != self._session_epoch and cnt > 0
            )
        return {
            "new_token": new_tok.reveal(),
            "rotated": True,
            "stale_epoch": False,
            "session_epoch": new_epoch,
            "old_epoch_revoked": True,
            "rotation_complete": active_old == 0,
            "active_old_leases": int(active_old),
            "status": "ROTATED" if active_old == 0 else "ROTATION_PENDING_DRAIN",
        }

    def rotate_auth_token(
        self,
        *,
        exclude_sock: socket.socket | None = None,
        drain_timeout_seconds: float | None = None,
        require_drained: bool = False,
    ) -> str:
        """Rotate per-launch bearer secret + session_epoch, revoking prior epoch, pairing codes & device sessions."""
        info = self.rotate_auth_token_detailed(
            exclude_sock=exclude_sock,
            drain_timeout_seconds=drain_timeout_seconds,
        )
        if require_drained and not bool(info["rotation_complete"]):
            raise RotationPendingDrainError(
                f"Token rotation revoked prior epoch, but {info['active_old_leases']} old-epoch lease(s) have not yet drained",
                payload={
                    "ok": False,
                    "status": "ROTATION_PENDING_DRAIN",
                    "old_epoch_revoked": True,
                    "rotation_complete": False,
                    "active_old_leases": int(info["active_old_leases"]),
                    "session_epoch": str(info["session_epoch"]),
                },
            )
        return str(info["new_token"])

    def notify_stream_updated(self) -> None:
        with self._sse_cond:
            self._sse_version += 1
            self._sse_cond.notify_all()

    def _record_request(self, route: str) -> None:
        bucket = route if route in _KNOWN_METRICS_ROUTES else "__other__"
        if bucket == "/api/rotate-token":
            bucket = "/api/rotate"
        with self._metrics_lock:
            self._requests_total += 1
            self._route_counts[bucket] = self._route_counts.get(bucket, 0) + 1

    def _record_auth_failure(self) -> None:
        with self._metrics_lock:
            self._auth_failures_total += 1

    def _record_pre_auth_timeout(self) -> None:
        with self._metrics_lock:
            self._pre_auth_timeouts_total += 1

    def _record_sse_client(self, delta: int) -> None:
        with self._metrics_lock:
            self._sse_active_clients = max(0, self._sse_active_clients + int(delta))

    def _record_sse_emit(self, *, events: int = 0, heartbeats: int = 0) -> None:
        with self._metrics_lock:
            if events > 0:
                self._sse_events_sent_total += int(events)
            if heartbeats > 0:
                self._sse_heartbeats_sent_total += int(heartbeats)

    def _snapshot_metrics(self) -> dict[str, Any]:
        with self._metrics_lock:
            started = self._started_mono
            requests_total = int(self._requests_total)
            auth_failures_total = int(self._auth_failures_total)
            sse_active_clients = int(self._sse_active_clients)
            sse_events_sent_total = int(self._sse_events_sent_total)
            sse_heartbeats_sent_total = int(self._sse_heartbeats_sent_total)
            route_counts = {str(k): int(v) for k, v in sorted(self._route_counts.items())}
        with self._sse_cond:
            sse_version = int(self._sse_version)
        uptime_seconds = int(max(0, int(time.monotonic() - started))) if started is not None else 0
        payload: dict[str, Any] = {
            "schema": "cas-forex.cockpit-metrics/1",
            "uptime_seconds": uptime_seconds,
            "requests_total": requests_total,
            "auth_failures_total": auth_failures_total,
            "sse_version": sse_version,
            "sse_active_clients": sse_active_clients,
            "sse_events_sent_total": sse_events_sent_total,
            "sse_heartbeats_sent_total": sse_heartbeats_sent_total,
            "route_counts": route_counts,
            "components": {
                "ui_service": self._ui_service is not None,
                "market_stream": self._market_stream_reader is not None or (
                    self._ui_service is not None and hasattr(self._ui_service, "readMarketStream")
                ),
                "broker_routing": self._broker_router_reader is not None,
                "ai_model_registry": self._ai_model_registry is not None,
                "autonomous_trader": self._autonomous_trader is not None,
                "profit_vault": self._profit_vault is not None,
                "parallel_tiers": self._parallel_tiers is not None,
                "aggression_dial": self._aggression_dial is not None,
            },
        }
        if self._autonomous_trader is not None:
            try:
                if callable(getattr(self._autonomous_trader, "metrics_summary", None)):
                    msum = self._autonomous_trader.metrics_summary()
                else:
                    msum = self._autonomous_trader.status_snapshot()
                payload["trader_summary"] = {
                    "governance_mode": str(msum.get("governance_mode", "")),
                    "effective_status": str(msum.get("effective_status", "")),
                    "cycle_count": int(msum.get("cycle_count", 0)),
                    "veto_count": int(msum.get("veto_count", 0)),
                }
            except Exception as exc:
                self._last_routing_error = type(exc).__name__
        if self._parallel_tiers is not None:
            try:
                ptsnap = self._parallel_tiers.snapshot()
                payload["parallel_tiers_summary"] = {
                    "tier_count": int(ptsnap.get("tier_count", 0)),
                }
            except Exception as exc:
                self._last_routing_error = type(exc).__name__
        if self._profit_vault is not None:
            try:
                vsnap = self._profit_vault.snapshot()
                payload["vault_summary"] = {
                    "auto_sweep_enabled": bool(vsnap.get("auto_sweep_enabled", False)),
                    "preferred_rail": str(vsnap.get("preferred_rail", "")),
                }
            except Exception as exc:
                self._last_routing_error = type(exc).__name__
        return assert_safe_ai_catalog_payload(payload)

    def _read_stream_payload(self) -> dict[str, Any] | None:
        if self._market_stream_reader is not None:
            return self._market_stream_reader()
        if self._ui_service is not None and hasattr(self._ui_service, "readMarketStream"):
            return self._ui_service.readMarketStream()
        return None

    def _read_broker_routing(self) -> dict[str, Any] | None:
        if self._broker_router_reader is None:
            return None
        payload = self._broker_router_reader()
        if payload is None:
            return None
        if type(payload) is not dict:
            raise ContractError("broker routing payload must be a JSON object")
        return safe_broker_routing_payload(payload)

    def _resolve_aggression_live_mode_fail_closed(self) -> tuple[bool, str]:
        """Require positive proof of DEMO + not live_armed; treat any error or missing routing state as LIVE_OR_UNKNOWN (Finding [17])."""
        if self._broker_router_reader is not None:
            try:
                routing = self._read_broker_routing()
            except Exception as exc_rt:
                self._last_routing_error = type(exc_rt).__name__
                return True, "LIVE_OR_UNKNOWN"
            if not isinstance(routing, Mapping):
                return True, "LIVE_OR_UNKNOWN"
            raw_em = routing.get("execution_mode")
            if not isinstance(raw_em, str) or not raw_em.strip():
                return True, "LIVE_OR_UNKNOWN"
            em_up = raw_em.strip().upper()
            lr = routing.get("live_readiness") if isinstance(routing.get("live_readiness"), Mapping) else {}
            live_armed = bool(routing.get("live_trading_armed", False)) or bool(lr.get("live_armed", False))
            if em_up == "DEMO" and not live_armed:
                return False, "DEMO"
            if em_up == "LIVE" or live_armed:
                return True, "LIVE"
            return True, "LIVE_OR_UNKNOWN"

        if self._autonomous_trader is not None:
            router_obj = getattr(self._autonomous_trader, "_router", None)
            if router_obj is not None:
                try:
                    raw_r_em = getattr(router_obj, "execution_mode", None)
                    r_armed = bool(getattr(router_obj, "_live_armed", False))
                    if isinstance(raw_r_em, str) and raw_r_em.strip().upper() == "DEMO" and not r_armed:
                        return False, "DEMO"
                    if isinstance(raw_r_em, str) and raw_r_em.strip().upper() == "LIVE":
                        return True, "LIVE"
                except Exception as exc_r2:
                    self._last_routing_error = type(exc_r2).__name__
                    return True, "LIVE_OR_UNKNOWN"

        return True, "LIVE_OR_UNKNOWN"

    def _read_aggression_dial_snapshot(self, *, owner_controls_allowed: bool = True) -> dict[str, Any] | None:
        if self._aggression_dial is None:
            return None
        is_live_or_unk, _ = self._resolve_aggression_live_mode_fail_closed()
        execution_mode = "LIVE" if is_live_or_unk else "DEMO"

        regime = "NEUTRAL"
        consec = 0
        dd_dec = Decimal("0")
        vs_dec = Decimal("0.60")
        if self._autonomous_trader is not None:
            try:
                if callable(getattr(self._autonomous_trader, "dial_context_summary", None)):
                    dctx = self._autonomous_trader.dial_context_summary()
                    raw_reg = str(dctx.get("last_regime") or "").strip().upper()
                    if raw_reg:
                        regime = raw_reg
                    consec = max(0, int(dctx.get("consecutive_losses", 0) or 0))
                    raw_dd = dctx.get("drawdown_pct")
                    if raw_dd not in (None, ""):
                        parsed_dd = Decimal(str(raw_dd))
                        if parsed_dd.is_finite() and parsed_dd >= Decimal("0"):
                            dd_dec = parsed_dd.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
                    raw_vs = dctx.get("last_valve_score")
                    if raw_vs not in (None, ""):
                        parsed_vs = Decimal(str(raw_vs))
                        if parsed_vs.is_finite():
                            vs_dec = min(
                                Decimal("1.00"),
                                max(Decimal("0.00"), parsed_vs.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
                            )
                else:
                    tsnap = self._autonomous_trader.status_snapshot()
                    if isinstance(tsnap, Mapping):
                        raw_reg = str(tsnap.get("last_regime") or "").strip().upper()
                        if raw_reg:
                            regime = raw_reg
                        dq = tsnap.get("daily_quota")
                        if isinstance(dq, Mapping):
                            consec = max(0, int(dq.get("consecutive_losses", 0) or 0))
                        ad_sub = tsnap.get("aggression_dial")
                        if isinstance(ad_sub, Mapping) and ad_sub.get("drawdown_pct") not in (None, ""):
                            parsed_dd = Decimal(str(ad_sub["drawdown_pct"]))
                            if parsed_dd.is_finite() and parsed_dd >= Decimal("0"):
                                dd_dec = parsed_dd.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
                        raw_vs = tsnap.get("last_valve_score")
                        if raw_vs not in (None, ""):
                            parsed_vs = Decimal(str(raw_vs))
                            if parsed_vs.is_finite():
                                vs_dec = min(
                                    Decimal("1.00"),
                                    max(Decimal("0.00"), parsed_vs.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
                                )
            except (InvalidOperation, ValueError, TypeError, Exception) as exc_tr:
                self._last_routing_error = type(exc_tr).__name__

        doc = dict(
            self._aggression_dial.snapshot(
                regime=regime,
                consecutive_losses=consec,
                drawdown_pct=dd_dec,
                valve_score=vs_dec,
                owner_controls_allowed=bool(owner_controls_allowed),
            )
        )
        doc["live_mode"] = execution_mode == "LIVE"
        doc["execution_mode"] = execution_mode
        doc["connected"] = True
        doc["audit_verified"] = bool(self._aggression_dial.verify_audit_chain())
        return assert_safe_ai_catalog_payload(doc)

    @staticmethod
    def _parse_strict_decimal_field(raw: Any, field_name: str) -> Decimal:
        if isinstance(raw, (bool, float)) or not isinstance(raw, (str, int, Decimal)):
            raise ContractError(f"{field_name} must be a Decimal string or integer (never float or boolean)")
        txt = str(raw).strip()
        if not txt:
            raise ContractError(f"{field_name} must not be empty")
        try:
            parsed = Decimal(txt)
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ContractError(f"{field_name} is not a valid Decimal") from exc
        if not parsed.is_finite():
            raise ContractError(f"{field_name} must be finite")
        return parsed

    def _read_compounding_snapshot(
        self,
        *,
        owner_controls_allowed: bool = True,
        session_scope: str = SESSION_SCOPE_OWNER_FULL,
    ) -> dict[str, Any] | None:
        if self._autonomous_trader is not None and callable(
            getattr(self._autonomous_trader, "compounding_snapshot", None)
        ):
            snap = self._autonomous_trader.compounding_snapshot(
                owner_controls_allowed=owner_controls_allowed,
                session_scope=session_scope,
            )
            if snap is not None:
                return snap
        if self._compounding_controller is None:
            return None
        execution_mode = "DEMO"
        try:
            routing = self._read_broker_routing()
            if isinstance(routing, Mapping) and str(routing.get("execution_mode") or "").strip().upper() == "LIVE":
                execution_mode = "LIVE"
        except Exception as exc_rt:
            self._last_routing_error = type(exc_rt).__name__
        return build_enriched_compounding_payload(
            compounding_controller=self._compounding_controller,
            phase8_bridge=self._phase8_bridge,
            current_equity_usd=None,
            owner_controls_allowed=owner_controls_allowed,
            session_scope=session_scope,
            execution_mode=execution_mode,
        )

    def _read_option_b_demo_snapshot(
        self,
        *,
        owner_controls_allowed: bool,
        session_scope: str,
    ) -> dict[str, Any] | None:
        if self._option_b_demo is None:
            return None
        raw = self._option_b_demo.snapshot()
        if not isinstance(raw, Mapping):
            return None
        snap = dict(raw)
        snap["owner_controls_allowed"] = bool(owner_controls_allowed)
        snap["session_scope"] = str(session_scope)
        return assert_safe_ai_catalog_payload(snap)

    def _read_demo_high_growth_snapshot(
        self,
        *,
        owner_controls_allowed: bool,
        session_scope: str,
    ) -> dict[str, Any] | None:
        if self._demo_high_growth_store is None:
            return None
        is_live_or_unk, mode_lbl = self._resolve_aggression_live_mode_fail_closed()
        exec_mode = "DEMO" if (not is_live_or_unk and mode_lbl == "DEMO") else mode_lbl
        snap = self._demo_high_growth_store.snapshot(
            execution_mode=exec_mode,
            owner_controls_allowed=bool(owner_controls_allowed) and (exec_mode == "DEMO"),
            session_scope=session_scope,
        )
        return assert_safe_ai_catalog_payload(snap)

    def _apply_demo_high_growth_profile_to_components(self, profile: DemoHighGrowthProfile) -> None:
        is_live_or_unk, _ = self._resolve_aggression_live_mode_fail_closed()
        exec_mode = "LIVE" if is_live_or_unk else "DEMO"
        profile.assert_demo_mode(
            exec_mode,
            live_trading_armed=is_live_or_unk,
            live_trading_locked=not is_live_or_unk,
        )
        if self._autonomous_trader is not None and callable(
            getattr(self._autonomous_trader, "set_demo_high_growth_profile", None)
        ):
            self._autonomous_trader.set_demo_high_growth_profile(profile)
        if self._option_b_demo is not None and callable(
            getattr(self._option_b_demo, "set_demo_high_growth_profile", None)
        ):
            self._option_b_demo.set_demo_high_growth_profile(
                profile,
                execution_mode=exec_mode,
                live_trading_armed=is_live_or_unk,
                live_trading_locked=not is_live_or_unk,
            )
        if self._parallel_tiers is not None and callable(
            getattr(self._parallel_tiers, "set_demo_high_growth_profile", None)
        ):
            self._parallel_tiers.set_demo_high_growth_profile(
                profile,
                execution_mode=exec_mode,
                live_trading_armed=is_live_or_unk,
                live_trading_locked=not is_live_or_unk,
            )
        if self._compounding_controller is not None and callable(
            getattr(self._compounding_controller, "set_demo_high_growth_profile", None)
        ):
            self._compounding_controller.set_demo_high_growth_profile(
                profile,
                execution_mode=exec_mode,
                live_trading_armed=is_live_or_unk,
                live_trading_locked=not is_live_or_unk,
            )
            if profile.enabled and profile.compounding_100pct and self._autonomous_trader is None:
                self._compounding_controller.set_compounding_mode(
                    "FULL_COMPOUND_100",
                    owner_controls_allowed=True,
                    actor="demo-high-growth-profile",
                )
        if self._phase8_bridge is not None and callable(
            getattr(self._phase8_bridge, "set_demo_high_growth_profile", None)
        ):
            self._phase8_bridge.set_demo_high_growth_profile(
                profile,
                execution_mode=exec_mode,
                live_trading_armed=is_live_or_unk,
                live_trading_locked=not is_live_or_unk,
            )
        if self._profit_vault is not None and self._autonomous_trader is None:
            if profile.enabled and profile.compounding_100pct:
                self._profit_vault.set_config(sweep_ratio=Decimal("0.00"), auto_sweep_enabled=True)
            elif not profile.enabled:
                self._profit_vault.set_config(sweep_ratio=Decimal("0.50"), auto_sweep_enabled=True)

    def _resolve_static_path(self, raw_path: str) -> Path | None:
        clean = urllib.parse.unquote(raw_path.split("?", 1)[0].split("#", 1)[0])
        if clean in ("/", "/ui", "/ui/"):
            clean = "/ui/index.html"
        if "\x00" in clean or "\\" in clean:
            return None
        rel = clean.lstrip("/")
        candidate = (self._repo_root / rel).resolve()
        allowed_roots = (self._ui_dir, self._contracts_dir)
        if not any(candidate.is_relative_to(root) for root in allowed_roots):
            return None
        if not candidate.is_file() or candidate.is_symlink():
            return None
        if candidate.suffix.lower() not in _CONTENT_TYPES:
            return None
        return candidate

    def _authorize_auxiliary_gate_fallback(
        self,
        *,
        route_kind: str,
        model_id: str,
        max_output_tokens: int,
        input_bytes: int = 0,
        audio_bytes: int = 0,
    ) -> dict[str, Any] | None:
        gate = self._model_gate
        if gate is None:
            return None
        auth_fn = getattr(gate, "authorize_auxiliary_call", None)
        if callable(auth_fn):
            return auth_fn(
                route_kind=route_kind,
                model_id=model_id,
                max_output_tokens=max_output_tokens,
                input_bytes=input_bytes,
                audio_bytes=audio_bytes,
            )
        scout_fn = getattr(gate, "admit_scout_call", None)
        if callable(scout_fn):
            return scout_fn(
                model_id=model_id,
                request_id=f"{route_kind}-{secrets.token_hex(8)}",
            )
        return None

    def start(self) -> str:
        if self._httpd is not None:
            return self.base_url
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            _emergency_channel = False

            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def _pre_auth_budget(self) -> float:
                if self._emergency_channel:
                    return min(outer._header_deadline_seconds, 1.5)
                return outer._header_deadline_seconds

            def _send_security_headers(
                self,
                content_type: str,
                content_length: int | None = None,
                *,
                extra_headers: list[tuple[str, str]] | None = None,
            ) -> None:
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Security-Policy", STRICT_CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                if extra_headers:
                    for hk, hv in extra_headers:
                        self.send_header(hk, hv)
                if content_length is not None:
                    self.send_header("Content-Length", str(content_length))

            def _write_json(
                self,
                status: HTTPStatus,
                payload: Any,
                *,
                extra_headers: list[tuple[str, str]] | None = None,
            ) -> None:
                body = (json.dumps(payload, sort_keys=False) + "\n").encode("utf-8")
                self.send_response(int(status))
                self._send_security_headers(
                    "application/json; charset=utf-8",
                    len(body),
                    extra_headers=extra_headers,
                )
                self.send_header("Connection", "close")
                try:
                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                    pass
                self.close_connection = True

            def _allowed_hosts_and_origins(self) -> tuple[set[str], set[str]]:
                if self._emergency_channel:
                    return {outer.emergency_expected_host_header, "localhost"}, {outer.emergency_base_url}
                allowed_hosts = {outer.expected_host_header}
                allowed_origins = {outer.base_url}
                if outer._public_host and outer._public_origin:
                    allowed_hosts.add(outer._public_host)
                    allowed_origins.add(outer._public_origin)
                return allowed_hosts, allowed_origins

            def _enforce_loopback_envelope(self) -> bool:
                """Pre-body check: peer IP, exact literal loopback Host, and exact loopback Origin."""
                try:
                    peer_ip = ipaddress.ip_address(str(self.client_address[0]))
                except ValueError:
                    peer_ip = None
                if peer_ip is None or not peer_ip.is_loopback or peer_ip.is_unspecified:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Loopback clients only"})
                    return False

                allowed_hosts, allowed_origins = self._allowed_hosts_and_origins()
                hosts = self.headers.get_all("Host") or []
                if len(hosts) != 1 or hosts[0].strip() not in allowed_hosts:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Invalid or foreign Host header"})
                    return False

                origins = self.headers.get_all("Origin") or []
                if len(origins) > 1:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Multiple Origin headers forbidden"})
                    return False
                if len(origins) == 1 and origins[0].strip() not in allowed_origins:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Cross-origin loopback request forbidden"})
                    return False

                sec_sites = [s.strip().lower() for s in (self.headers.get_all("Sec-Fetch-Site") or [])]
                if len(sec_sites) > 1:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Multiple Sec-Fetch-Site headers forbidden"})
                    return False
                if len(sec_sites) == 1 and sec_sites[0] not in ("same-origin", "none"):
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Cross-site browser request forbidden"})
                    return False
                return True

            def setup(self) -> None:
                super().setup()
                self.requestline = ""
                self.request_version = "HTTP/1.1"
                self.command = ""
                self._orig_rfile = self.rfile
                self._pre_auth_rfile: _DeadlineRFile | None = None
                raw_conn = _unwrap_socket(self.connection)
                if raw_conn is not None:
                    raw_conn.settimeout(min(self._pre_auth_budget(), 5.0))
                    outer._register_socket(raw_conn)

            def handle_one_request(self) -> None:
                wrapped: _DeadlineRFile | None = None
                timeout_counted = False
                if isinstance(self.connection, socket.socket):
                    wrapped = _DeadlineRFile(
                        self.connection,
                        self._orig_rfile,
                        deadline=outer._mono() + self._pre_auth_budget(),
                        max_bytes=MAX_HTTP_HEADER_BYTES,
                        mono_clock=outer._mono,
                    )
                    self._pre_auth_rfile = wrapped
                    self.rfile = wrapped  # type: ignore[assignment]
                try:
                    super().handle_one_request()
                except TimeoutError:
                    timeout_counted = True
                    outer._record_pre_auth_timeout()
                    self.close_connection = True
                except ValueError:
                    if wrapped is not None and wrapped.header_size_exceeded:
                        try:
                            self._write_json(
                                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                                {"error": "Pre-auth HTTP request line and headers exceed 16 KiB limit"},
                            )
                        except OSError:
                            pass
                    self.close_connection = True
                finally:
                    if wrapped is not None and wrapped.header_deadline_exceeded and not timeout_counted:
                        outer._record_pre_auth_timeout()
                    self.rfile = self._orig_rfile  # type: ignore[assignment]
                    self._pre_auth_rfile = None

            def parse_request(self) -> bool:
                if isinstance(self.connection, socket.socket):
                    if self._pre_auth_rfile is None:
                        self._pre_auth_rfile = _DeadlineRFile(
                            self.connection,
                            self._orig_rfile,
                            deadline=outer._mono() + self._pre_auth_budget(),
                            max_bytes=MAX_HTTP_HEADER_BYTES,
                            mono_clock=outer._mono,
                        )
                    self.rfile = self._pre_auth_rfile  # type: ignore[assignment]
                    try:
                        ok = super().parse_request()
                    except TimeoutError:
                        self.close_connection = True
                        return False
                    except ValueError:
                        if self._pre_auth_rfile is not None and self._pre_auth_rfile.header_size_exceeded:
                            try:
                                self._write_json(
                                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                                    {"error": "Pre-auth HTTP request line and headers exceed 16 KiB limit"},
                                )
                            except OSError:
                                pass
                        self.close_connection = True
                        return False
                    finally:
                        self.rfile = self._orig_rfile  # type: ignore[assignment]
                        try:
                            self.connection.settimeout(5.0)
                        except OSError as exc:
                            _to_err = str(exc)
                    if not ok:
                        return False
                    if len(self.headers) > MAX_HTTP_HEADER_COUNT:
                        self._write_json(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, {"error": "Too many HTTP headers"})
                        return False
                    return True
                return super().parse_request()

            def finish(self) -> None:
                try:
                    super().finish()
                finally:
                    raw_conn = _unwrap_socket(self.connection)
                    if raw_conn is not None:
                        outer._unregister_socket(raw_conn)

            def _check_auth_scoped(self, *, is_post: bool) -> tuple[bool, bool, str, str, str, str | None]:
                """Constant-time bearer check returning (authed, supplied, epoch, candidate, scope, expires_at)."""
                with outer._auth_lock:
                    secret = outer._auth_secret
                    epoch = outer._session_epoch or ""
                    if secret is None or outer._stop_event.is_set() or not epoch:
                        return False, False, "", "", "", None
                    expected_owner_bytes = secret.reveal().encode("utf-8")
                    now_m = outer._mono()
                    outer._prune_ephemeral_auth_unlocked(now_m)
                    dev_snapshot = list(outer._device_sessions.items())

                auth_hdrs = self.headers.get_all("Authorization") or []
                if len(auth_hdrs) > 1:
                    return False, True, epoch, "", "", None
                if len(auth_hdrs) == 1:
                    raw_auth = auth_hdrs[0].strip()
                    if not raw_auth.startswith("Bearer "):
                        return False, True, epoch, "", "", None
                    candidate = raw_auth[7:].strip()
                    if not candidate:
                        return False, True, epoch, "", "", None
                    if is_post:
                        origins = self.headers.get_all("Origin") or []
                        _, allowed_origins = self._allowed_hosts_and_origins()
                        if len(origins) == 1 and origins[0].strip() not in allowed_origins:
                            return False, True, epoch, "", "", None
                    if hmac.compare_digest(candidate.encode("utf-8"), expected_owner_bytes):
                        return True, True, epoch, candidate, SESSION_SCOPE_OWNER_FULL, None
                    if self._emergency_channel:
                        return False, True, epoch, "", "", None
                    cand_sha = sha256(candidate.encode("utf-8")).hexdigest()
                    matched_rec: _DeviceSessionRecord | None = None
                    for k_sha, rec in dev_snapshot:
                        if hmac.compare_digest(k_sha, cand_sha) and rec.epoch == epoch and now_m < rec.expires_mono:
                            matched_rec = rec
                    if matched_rec is not None:
                        return (
                            True,
                            True,
                            epoch,
                            candidate,
                            SESSION_SCOPE_DEVICE_READ_EXPLAINER,
                            matched_rec.expires_at_iso,
                        )
                    return False, True, epoch, "", "", None

                return False, bool(self.headers.get_all("Cookie")), epoch, "", "", None

            def _reject_unauthorized(self, message: str = "Authentication required") -> None:
                outer._record_auth_failure()
                self._write_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": message},
                    extra_headers=[("WWW-Authenticate", 'Bearer realm="cas-forex-cockpit"')],
                )

            def _drain_small_request_body(self, *, max_bytes: int = MAX_PRE_AUTH_BODY_BYTES) -> None:
                """Drain small bounded request bodies before early 403/4xx writes so HTTP/1.1 proxies avoid TCP RST."""
                if self.headers.get("Transfer-Encoding") is not None:
                    return
                raw_len = self.headers.get("Content-Length")
                if raw_len is None:
                    return
                raw_s = str(raw_len).strip()
                if not raw_s.isascii() or not raw_s.isdigit():
                    return
                length = int(raw_s)
                if length <= 0 or length > max_bytes:
                    return
                raw_sock = _unwrap_socket(self.connection)
                prev_to: float | None = None
                if raw_sock is not None:
                    try:
                        prev_to = raw_sock.gettimeout()
                        raw_sock.settimeout(0.25)
                    except OSError as exc_to:
                        _drain_to_err = type(exc_to).__name__
                        prev_to = None
                try:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(remaining, 4096))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                except OSError as exc_drain:
                    _drain_err = type(exc_drain).__name__
                finally:
                    if raw_sock is not None and prev_to is not None:
                        try:
                            raw_sock.settimeout(prev_to)
                        except OSError as exc_rst:
                            _drain_rst_err = type(exc_rst).__name__

            def _reject_insufficient_scope(self) -> None:
                outer._record_auth_failure()
                self._write_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Owner primary bearer required for privileged control",
                        "required_scope": SESSION_SCOPE_OWNER_FULL,
                    },
                )

            def _read_pre_auth_json_body(self, *, max_bytes: int = MAX_PRE_AUTH_BODY_BYTES) -> Any:
                """Read pre-auth JSON body under an absolute monotonic deadline and <=4096-byte budget (Finding [11])."""
                if self.headers.get("Transfer-Encoding") is not None:
                    raise ContractError("Transfer-Encoding is forbidden on pre-authenticated endpoints")
                raw_len = self.headers.get("Content-Length")
                if raw_len is None or not str(raw_len).strip().isdigit():
                    raise ContractError("Content-Length header required")
                cap = min(int(max_bytes), MAX_PRE_AUTH_BODY_BYTES)
                length = int(str(raw_len).strip())
                if length < 0 or length > cap:
                    raise _PreAuthBodyTooLargeError(f"Pre-authenticated body exceeds {cap}-byte limit")
                abs_deadline = outer._mono() + outer._pre_auth_body_deadline_seconds
                chunks = bytearray()
                if callable(getattr(self.rfile, "peek", None)):
                    buffered = bytes(self.rfile.peek(length))
                    if buffered:
                        take_n = min(length, len(buffered))
                        chunks.extend(self.rfile.read(take_n))
                raw_sock = self.connection if isinstance(self.connection, socket.socket) else None
                while len(chunks) < length:
                    rem = abs_deadline - outer._mono()
                    if rem <= 0.0:
                        if raw_sock is not None:
                            raw_sock.settimeout(1.0)
                        outer._record_pre_auth_timeout()
                        self.close_connection = True
                        raise _PreAuthBodyTimeoutError("Pre-authenticated request body deadline exceeded")
                    need = min(length - len(chunks), 1024)
                    try:
                        if raw_sock is not None:
                            raw_sock.settimeout(rem)
                            part = raw_sock.recv(need)
                        else:
                            part = self.rfile.read(need)
                    except (TimeoutError, socket.timeout):
                        if raw_sock is not None:
                            raw_sock.settimeout(1.0)
                        outer._record_pre_auth_timeout()
                        self.close_connection = True
                        raise _PreAuthBodyTimeoutError(
                            "Pre-authenticated request body deadline exceeded"
                        ) from None
                    if not part:
                        raise ContractError("Unexpected EOF while reading pre-authenticated request body")
                    chunks.extend(part)
                    if len(chunks) > cap:
                        raise _PreAuthBodyTooLargeError(f"Pre-authenticated body exceeds {cap}-byte limit")
                if raw_sock is not None:
                    raw_sock.settimeout(5.0)
                if len(chunks) != length:
                    raise ContractError("incomplete HTTP request body")

                def _reject_non_finite_pre(token: str) -> Any:
                    raise ContractError(f"non-finite JSON constant {token!r} forbidden")

                return json.loads(bytes(chunks).decode("utf-8"), parse_constant=_reject_non_finite_pre)

            def _read_json_body(self, *, max_bytes: int = MAX_HTTP_RPC_BYTES) -> Any:
                raw_len = self.headers.get("Content-Length")
                if raw_len is None:
                    raise ContractError("Content-Length header required")
                length = int(raw_len)
                if length < 0 or length > max_bytes:
                    raise ContractError("RPC payload exceeds byte limit")
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ContractError("incomplete HTTP request body")

                def _reject_non_finite(token: str) -> Any:
                    raise ContractError(f"non-finite JSON constant {token!r} forbidden")

                return json.loads(data.decode("utf-8"), parse_constant=_reject_non_finite)

            def _read_optional_json_body(self, *, max_bytes: int = MAX_HTTP_RPC_BYTES) -> dict[str, Any]:
                raw_len = self.headers.get("Content-Length")
                if raw_len is None or int(raw_len) == 0:
                    return {}
                parsed = self._read_json_body(max_bytes=max_bytes)
                if type(parsed) is not dict:
                    raise ContractError("JSON object required")
                return parsed

            def do_GET(self) -> None:
                sem = outer._emergency_sem if self._emergency_channel else outer._worker_sem
                if not sem.acquire(blocking=False):
                    self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Cockpit worker capacity reached"})
                    return
                try:
                    self._handle_get()
                finally:
                    sem.release()

            def _handle_get(self) -> None:
                if not self._enforce_loopback_envelope():
                    return
                parsed = urllib.parse.urlsplit(self.path)
                route = parsed.path
                outer._record_request(route)

                if self._emergency_channel and route != "/api/health":
                    self._write_json(
                        HTTPStatus.FORBIDDEN,
                        {"error": "Emergency channel accepts owner safety controls and /api/health only"},
                    )
                    return

                if route == "/api/health":
                    if parsed.query:
                        qmap_h = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        if "token" in qmap_h or "pair_code" in qmap_h:
                            self._reject_unauthorized()
                            return
                    authed, supplied, epoch, _, scope, _ = self._check_auth_scoped(is_post=False)
                    if supplied and not authed:
                        if self._emergency_channel:
                            self._reject_insufficient_scope()
                        else:
                            self._reject_unauthorized()
                        return
                    if not authed:
                        self._write_json(HTTPStatus.OK, {"status": "OK", "auth_required": True, "authenticated": False})
                        return
                    self._write_json(HTTPStatus.OK, {
                        "status": "OK",
                        "auth_required": True,
                        "authenticated": True,
                        "session_epoch": epoch,
                        "bridge_attached": outer._ui_service is not None,
                        "stream_available": outer._read_stream_payload() is not None,
                    })
                    return

                if route == "/api" or route.startswith("/api/"):
                    if parsed.query:
                        qmap_api = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        if "token" in qmap_api or "pair_code" in qmap_api:
                            self._reject_unauthorized()
                            return
                    authed, _, initial_epoch, supplied_tok, auth_scope, auth_exp = self._check_auth_scoped(is_post=False)
                    if not authed:
                        self._reject_unauthorized()
                        return
                    if route == "/api/auth-session":
                        self._write_json(HTTPStatus.OK, {
                            "authenticated": True,
                            "session_scope": auth_scope,
                            "owner_controls_allowed": auth_scope == SESSION_SCOPE_OWNER_FULL,
                            "session_epoch": initial_epoch,
                            "expires_at": auth_exp,
                        })
                        return
                    if route == "/api/market-stream":
                        try:
                            stream = outer._read_stream_payload()
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Market stream unavailable"})
                        else:
                            if stream is None:
                                self._write_json(HTTPStatus.NOT_FOUND, {"error": "Market stream not configured"})
                            else:
                                self._write_json(HTTPStatus.OK, stream)
                        return
                    if route == "/api/broker-routing":
                        try:
                            routing = outer._read_broker_routing()
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Broker routing unavailable"})
                        else:
                            if routing is None:
                                self._write_json(HTTPStatus.NOT_FOUND, {"error": "Broker routing not configured"})
                            else:
                                self._write_json(HTTPStatus.OK, routing)
                        return
                    if route == "/api/ai-models":
                        if outer._ai_model_registry is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "AI model registry not configured"})
                            return
                        try:
                            cat = assert_safe_ai_catalog_payload(outer._ai_model_registry.catalog_snapshot())
                            self._write_json(HTTPStatus.OK, cat)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "AI catalog unavailable"})
                        return
                    if route == "/api/ai-trader":
                        if outer._autonomous_trader is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Autonomous AI trader not attached"})
                            return
                        try:
                            snap = assert_safe_ai_catalog_payload(outer._autonomous_trader.status_snapshot())
                            self._write_json(HTTPStatus.OK, snap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Autonomous AI snapshot unavailable"})
                        return
                    if route == "/api/treasury":
                        if outer._profit_vault is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Profit Sweep Vault not configured"})
                            return
                        try:
                            vsnap = assert_safe_ai_catalog_payload(outer._profit_vault.snapshot())
                            self._write_json(HTTPStatus.OK, vsnap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Treasury snapshot unavailable"})
                        return
                    if route == "/api/audit-verify":
                        if outer._profit_vault is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Profit Sweep Vault not configured"})
                            return
                        try:
                            audit_report = assert_safe_ai_catalog_payload(outer._profit_vault.verify_audit_chain())
                            self._write_json(HTTPStatus.OK, audit_report)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Vault audit verification unavailable"})
                        return
                    if route == "/api/metrics":
                        try:
                            metrics = outer._snapshot_metrics()
                            self._write_json(HTTPStatus.OK, metrics)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Cockpit metrics unavailable"})
                        return
                    if route == "/api/parallel-tiers":
                        if outer._parallel_tiers is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Parallel Tier Engine not configured"})
                            return
                        try:
                            ptsnap = assert_safe_ai_catalog_payload(outer._parallel_tiers.snapshot())
                            self._write_json(HTTPStatus.OK, ptsnap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Parallel tiers unavailable"})
                        return
                    if route == "/api/aggression-dial":
                        if outer._aggression_dial is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Aggression dial store not configured"})
                            return
                        try:
                            adsnap = outer._read_aggression_dial_snapshot(
                                owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL)
                            )
                            if adsnap is None:
                                self._write_json(HTTPStatus.NOT_FOUND, {"error": "Aggression dial store not configured"})
                            else:
                                self._write_json(HTTPStatus.OK, adsnap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(
                                HTTPStatus.INTERNAL_SERVER_ERROR,
                                {"error": "Aggression dial snapshot unavailable"},
                            )
                        return
                    if route == "/api/compounding":
                        try:
                            comp_snap = outer._read_compounding_snapshot(
                                owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL),
                                session_scope=auth_scope,
                            )
                            if comp_snap is None:
                                self._write_json(
                                    HTTPStatus.NOT_FOUND,
                                    {"error": "Compounding controller not configured"},
                                )
                            else:
                                self._write_json(HTTPStatus.OK, comp_snap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(
                                HTTPStatus.INTERNAL_SERVER_ERROR,
                                {"error": "Compounding snapshot unavailable"},
                            )
                        return
                    if route == "/api/option-b-demo":
                        try:
                            ob_snap = outer._read_option_b_demo_snapshot(
                                owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL),
                                session_scope=auth_scope,
                            )
                            if ob_snap is None:
                                self._write_json(
                                    HTTPStatus.NOT_FOUND,
                                    {"error": "Option B paper demo runner not configured"},
                                )
                            else:
                                self._write_json(HTTPStatus.OK, ob_snap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(
                                HTTPStatus.INTERNAL_SERVER_ERROR,
                                {"error": "Option B paper demo snapshot unavailable"},
                            )
                        return
                    if route == "/api/demo-high-growth-profile":
                        try:
                            dhg_snap = outer._read_demo_high_growth_snapshot(
                                owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL),
                                session_scope=auth_scope,
                            )
                            if dhg_snap is None:
                                self._write_json(
                                    HTTPStatus.NOT_FOUND,
                                    {"error": "DEMO high-growth profile store not configured"},
                                )
                            else:
                                self._write_json(HTTPStatus.OK, dhg_snap)
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(
                                HTTPStatus.INTERNAL_SERVER_ERROR,
                                {"error": "DEMO high-growth profile snapshot unavailable"},
                            )
                        return
                    if route == "/api/index-stream":
                        try:
                            idx_snap = outer._index_stream_reader() if outer._index_stream_reader is not None else None
                            if idx_snap is None:
                                stream_fallback = outer._read_stream_payload()
                                if isinstance(stream_fallback, dict):
                                    from cas_forex_revamp.venue.live_market_stream import INDEX_INSTRUMENTS as _IDX_SYMS
                                    idx_rows = [
                                        m for m in (stream_fallback.get("markets") or [])
                                        if isinstance(m, dict) and m.get("pair") in _IDX_SYMS
                                    ]
                                    if idx_rows:
                                        idx_snap = {
                                            "schema": "cas-forex.index-stream/1",
                                            "sequence": int(stream_fallback.get("sequence") or 1),
                                            "observed_at": stream_fallback.get("observed_at"),
                                            "feed_mode": "SYNTHESIZED_FROM_MARKET_STREAM",
                                            "markets": idx_rows,
                                        }
                            if idx_snap is None:
                                self._write_json(HTTPStatus.NOT_FOUND, {"error": "Index stream not configured"})
                            else:
                                self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(idx_snap))
                        except Exception as exc:
                            outer._last_routing_error = type(exc).__name__
                            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Index stream unavailable"})
                        return
                    if route == "/api/market-events":
                        if not outer._sse_sem.acquire(blocking=False):
                            self._write_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "SSE subscriber limit reached"})
                            return
                        outer._worker_sem.release()
                        reacquire_worker = True
                        sse_client_recorded = False
                        try:
                            self.send_response(int(HTTPStatus.OK))
                            self._send_security_headers("text/event-stream; charset=utf-8")
                            self.send_header("Connection", "keep-alive")
                            self.end_headers()
                            seen_ver = -1
                            last_emit_mono = 0.0
                            last_models_json = ""
                            last_models_mono = 0.0
                            last_treasury_json = ""
                            last_treasury_mono = 0.0
                            last_parallel_tiers_json = ""
                            last_parallel_tiers_mono = 0.0
                            last_aggression_dial_json = ""
                            last_aggression_dial_mono = 0.0
                            last_compounding_json = ""
                            last_compounding_mono = 0.0
                            last_option_b_json = ""
                            last_option_b_mono = 0.0
                            last_dhg_json = ""
                            last_dhg_mono = 0.0
                            outer._record_sse_client(1)
                            sse_client_recorded = True
                            try:
                                while not outer._stop_event.is_set():
                                    if not outer._verify_commit_epoch(supplied_tok, initial_epoch, allow_device_scope=True):
                                        break
                                    if last_emit_mono > 0.0:
                                        since_emit = time.monotonic() - last_emit_mono
                                        if since_emit < 0.25:
                                            outer._stop_event.wait(0.25 - since_emit)
                                            if outer._stop_event.is_set() or not outer._verify_commit_epoch(
                                                supplied_tok, initial_epoch, allow_device_scope=True
                                            ):
                                                break
                                    with outer._sse_cond:
                                        if outer._sse_version == seen_ver:
                                            outer._sse_cond.wait(timeout=1.5)
                                        cur_ver = outer._sse_version
                                    if outer._stop_event.is_set() or not outer._verify_commit_epoch(
                                        supplied_tok, initial_epoch, allow_device_scope=True
                                    ):
                                        break
                                    if cur_ver != seen_ver:
                                        seen_ver = cur_ver
                                        now_mono = time.monotonic()
                                        emitted_events = 0
                                        try:
                                            snap = outer._read_stream_payload()
                                            if snap is not None:
                                                frame = f"event: market\ndata: {json.dumps(snap, sort_keys=False)}\n\n".encode("utf-8")
                                                self.wfile.write(frame)
                                                emitted_events += 1
                                        except Exception as exc:
                                            outer._last_routing_error = type(exc).__name__
                                            eframe = f"event: error\ndata: {json.dumps({'source': 'market', 'error': 'Market stream unavailable'})}\n\n".encode("utf-8")
                                            self.wfile.write(eframe)
                                            emitted_events += 1
                                        if outer._index_stream_reader is not None:
                                            try:
                                                isnap = outer._index_stream_reader()
                                                if isnap is not None:
                                                    safe_isnap = assert_safe_ai_catalog_payload(isnap)
                                                    iframe = f"event: index_stream\ndata: {json.dumps(safe_isnap, sort_keys=False)}\n\n".encode("utf-8")
                                                    self.wfile.write(iframe)
                                                    emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'index_stream', 'error': 'Index stream unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._autonomous_trader is not None:
                                            try:
                                                tsnap = assert_safe_ai_catalog_payload(outer._autonomous_trader.status_snapshot())
                                                tframe = f"event: ai_trader\ndata: {json.dumps(tsnap, sort_keys=False)}\n\n".encode("utf-8")
                                                self.wfile.write(tframe)
                                                emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'ai_trader', 'error': 'Autonomous AI snapshot unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._ai_model_registry is not None:
                                            try:
                                                csnap = assert_safe_ai_catalog_payload(outer._ai_model_registry.catalog_snapshot())
                                                cjson = json.dumps(csnap, sort_keys=False)
                                                if not last_models_json or cjson != last_models_json or (now_mono - last_models_mono) >= 1.0:
                                                    last_models_json = cjson
                                                    last_models_mono = now_mono
                                                    cframe = f"event: ai_models\ndata: {cjson}\n\n".encode("utf-8")
                                                    self.wfile.write(cframe)
                                                    emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'ai_models', 'error': 'AI catalog unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._profit_vault is not None:
                                            try:
                                                vsnap = assert_safe_ai_catalog_payload(outer._profit_vault.snapshot())
                                                vjson = json.dumps(vsnap, sort_keys=False)
                                                if not last_treasury_json or vjson != last_treasury_json or (now_mono - last_treasury_mono) >= 1.0:
                                                    last_treasury_json = vjson
                                                    last_treasury_mono = now_mono
                                                    vframe = f"event: treasury\ndata: {vjson}\n\n".encode("utf-8")
                                                    self.wfile.write(vframe)
                                                    emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'treasury', 'error': 'Treasury snapshot unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._parallel_tiers is not None:
                                            try:
                                                ptsnap = assert_safe_ai_catalog_payload(outer._parallel_tiers.snapshot())
                                                ptjson = json.dumps(ptsnap, sort_keys=False)
                                                if not last_parallel_tiers_json or ptjson != last_parallel_tiers_json or (now_mono - last_parallel_tiers_mono) >= 1.0:
                                                    last_parallel_tiers_json = ptjson
                                                    last_parallel_tiers_mono = now_mono
                                                    ptframe = f"event: parallel_tiers\ndata: {ptjson}\n\n".encode("utf-8")
                                                    self.wfile.write(ptframe)
                                                    emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'parallel_tiers', 'error': 'Parallel tiers unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._aggression_dial is not None:
                                            try:
                                                adsnap = outer._read_aggression_dial_snapshot(
                                                    owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL)
                                                )
                                                if adsnap is not None:
                                                    adjson = json.dumps(adsnap, sort_keys=False)
                                                    if (
                                                        not last_aggression_dial_json
                                                        or adjson != last_aggression_dial_json
                                                        or (now_mono - last_aggression_dial_mono) >= 1.0
                                                    ):
                                                        last_aggression_dial_json = adjson
                                                        last_aggression_dial_mono = now_mono
                                                        adframe = f"event: aggression_dial\ndata: {adjson}\n\n".encode("utf-8")
                                                        self.wfile.write(adframe)
                                                        emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'aggression_dial', 'error': 'Aggression dial snapshot unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if (
                                            outer._compounding_controller is not None
                                            or getattr(outer._autonomous_trader, "compounding_controller", None)
                                            is not None
                                        ):
                                            try:
                                                cpsnap = outer._read_compounding_snapshot(
                                                    owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL),
                                                    session_scope=auth_scope,
                                                )
                                                if cpsnap is not None:
                                                    cpjson = json.dumps(cpsnap, sort_keys=False)
                                                    if (
                                                        not last_compounding_json
                                                        or cpjson != last_compounding_json
                                                        or (now_mono - last_compounding_mono) >= 1.0
                                                    ):
                                                        last_compounding_json = cpjson
                                                        last_compounding_mono = now_mono
                                                        cpframe = f"event: compounding\ndata: {cpjson}\n\n".encode("utf-8")
                                                        self.wfile.write(cpframe)
                                                        emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'compounding', 'error': 'Compounding snapshot unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._option_b_demo is not None:
                                            try:
                                                obsnap = outer._read_option_b_demo_snapshot(
                                                    owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL),
                                                    session_scope=auth_scope,
                                                )
                                                if obsnap is not None:
                                                    objson = json.dumps(obsnap, sort_keys=False)
                                                    if (
                                                        not last_option_b_json
                                                        or objson != last_option_b_json
                                                        or (now_mono - last_option_b_mono) >= 1.0
                                                    ):
                                                        last_option_b_json = objson
                                                        last_option_b_mono = now_mono
                                                        obframe = f"event: option_b_demo\ndata: {objson}\n\n".encode("utf-8")
                                                        self.wfile.write(obframe)
                                                        emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'option_b_demo', 'error': 'Option B paper demo snapshot unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if outer._demo_high_growth_store is not None:
                                            try:
                                                dhgsnap = outer._read_demo_high_growth_snapshot(
                                                    owner_controls_allowed=(auth_scope == SESSION_SCOPE_OWNER_FULL),
                                                    session_scope=auth_scope,
                                                )
                                                if dhgsnap is not None:
                                                    dhgjson = json.dumps(dhgsnap, sort_keys=False)
                                                    if (
                                                        not last_dhg_json
                                                        or dhgjson != last_dhg_json
                                                        or (now_mono - last_dhg_mono) >= 1.0
                                                    ):
                                                        last_dhg_json = dhgjson
                                                        last_dhg_mono = now_mono
                                                        dhgframe = f"event: demo_high_growth_profile\ndata: {dhgjson}\n\n".encode("utf-8")
                                                        self.wfile.write(dhgframe)
                                                        emitted_events += 1
                                            except Exception as exc:
                                                outer._last_routing_error = type(exc).__name__
                                                eframe = f"event: error\ndata: {json.dumps({'source': 'demo_high_growth_profile', 'error': 'DEMO high-growth profile snapshot unavailable'})}\n\n".encode("utf-8")
                                                self.wfile.write(eframe)
                                                emitted_events += 1
                                        if emitted_events > 0:
                                            outer._record_sse_emit(events=emitted_events)
                                        last_emit_mono = now_mono
                                        self.wfile.flush()
                                    else:
                                        self.wfile.write(b": heartbeat\n\n")
                                        self.wfile.flush()
                                        outer._record_sse_emit(heartbeats=1)
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                pass
                            self.close_connection = True
                        finally:
                            if sse_client_recorded:
                                outer._record_sse_client(-1)
                            outer._sse_sem.release()
                            if reacquire_worker:
                                outer._worker_sem.acquire(blocking=True)
                        return
                    if route in ("/api/boot", "/api/cockpit", "/api/decision-read"):
                        if outer._ui_service is None:
                            self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "ScopedUIService not attached"})
                            return
                        try:
                            if route == "/api/boot":
                                out = outer._ui_service.readBoot()
                            elif route == "/api/cockpit":
                                out = outer._ui_service.readCockpit()
                            else:
                                out = outer._ui_service.readDecisionRead()
                            self._write_json(HTTPStatus.OK, out)
                        except Exception as exc:
                            self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                        return
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "Unknown API endpoint"})
                    return

                # Finding [2]: NEVER accept `?token=` in URLs; only clean static URLs or `?pair_code=<nonce>` on UI entry!
                if parsed.query:
                    qmap = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    if "token" in qmap or "auth_token" in qmap or "bearer" in qmap:
                        self._reject_unauthorized("Bearer tokens in URL query strings are forbidden; use single-use pair_code")
                        return
                    if "pair_code" in qmap:
                        if (
                            route not in ("/", "/ui", "/ui/", "/ui/index.html")
                            or len(qmap["pair_code"]) != 1
                            or not _PAIR_CODE_RE.match(qmap["pair_code"][0].strip())
                        ):
                            self._reject_unauthorized("Invalid pairing URL")
                            return

                static_file = outer._resolve_static_path(self.path)
                if static_file is None:
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                    return
                raw = static_file.read_bytes()
                ctype = _CONTENT_TYPES[static_file.suffix.lower()]
                self.send_response(int(HTTPStatus.OK))
                self._send_security_headers(ctype, len(raw))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                route = urllib.parse.urlsplit(self.path).path
                if self._emergency_channel:
                    sem = outer._emergency_sem
                else:
                    is_emergency = route in ("/api/ai-overseer-action", "/api/ai-trader-control", "/api/request-control")
                    sem = outer._emergency_sem if is_emergency else outer._worker_sem
                if not sem.acquire(blocking=False):
                    self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Cockpit POST capacity reached"})
                    return
                try:
                    self._handle_post(route)
                finally:
                    sem.release()

            def _handle_post(self, route: str) -> None:
                if not self._enforce_loopback_envelope():
                    return
                outer._record_request(route)

                if self._emergency_channel and route not in _EMERGENCY_CHANNEL_POST_ROUTES:
                    self._write_json(
                        HTTPStatus.FORBIDDEN,
                        {"error": "Emergency channel accepts owner safety controls only"},
                    )
                    return

                # Pre-bearer single-use pairing code exchange with bounded pre-auth admission & monotonic body deadline (Finding [2], [11])
                if route == "/api/pair-exchange":
                    if not outer._pre_auth_body_sem.acquire(blocking=False):
                        self.close_connection = True
                        self._write_json(
                            HTTPStatus.TOO_MANY_REQUESTS,
                            {"error": "Pre-authenticated pairing exchange capacity reached"},
                        )
                        return
                    try:
                        body = self._read_pre_auth_json_body(max_bytes=MAX_PRE_AUTH_BODY_BYTES)
                        if type(body) is not dict or not isinstance(body.get("pair_code"), str):
                            raise ContractError("pair_code field required")
                        raw_peer = str(self.client_address[0]) if self.client_address else "127.0.0.1"
                        peer_k = _canonical_pre_auth_principal(raw_peer)
                        st_code, resp_doc = outer.exchange_pairing_code(body["pair_code"], peer_key=peer_k)
                        if st_code == int(HTTPStatus.UNAUTHORIZED):
                            outer._record_auth_failure()
                        self._write_json(HTTPStatus(st_code), resp_doc)
                    except _PreAuthBodyTimeoutError as exc_to:
                        self.close_connection = True
                        try:
                            self._write_json(HTTPStatus.REQUEST_TIMEOUT, {"error": str(exc_to)})
                        except OSError:
                            pass
                    except _PreAuthBodyTooLargeError as exc_lg:
                        self.close_connection = True
                        self._write_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(exc_lg)})
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    finally:
                        outer._pre_auth_body_sem.release()
                    return

                authed, supplied, auth_epoch, supplied_tok, auth_scope, _ = self._check_auth_scoped(is_post=True)
                if not authed:
                    if self._emergency_channel and supplied:
                        self._reject_insufficient_scope()
                    else:
                        self._reject_unauthorized()
                    return

                # Enforce strict least-privilege separation: paired devices CANNOT invoke owner controls (Finding [2])
                if auth_scope != SESSION_SCOPE_OWNER_FULL and route not in _DEVICE_ALLOWED_POST_ROUTES:
                    self._drain_small_request_body(max_bytes=MAX_PRE_AUTH_BODY_BYTES)
                    self._reject_insufficient_scope()
                    return

                if route == "/api/pair-code":
                    try:
                        body_opt = self._read_optional_json_body(max_bytes=4096)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        _, allowed_origins = self._allowed_hosts_and_origins()
                        origins = self.headers.get_all("Origin") or []
                        req_origin = origins[0].strip() if len(origins) == 1 and origins[0].strip() in allowed_origins else None
                        ttl_req = int(body_opt.get("ttl_seconds", PAIR_CODE_TTL_SECONDS))
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            minted = outer.mint_pairing_code(
                                ttl_seconds=ttl_req,
                                base_origin=req_origin or outer._public_origin or outer.base_url,
                            )
                        self._write_json(HTTPStatus.OK, minted)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/pair-revoke":
                    try:
                        body_opt = self._read_optional_json_body(max_bytes=4096)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        raw_pc = body_opt.get("pair_code")
                        if raw_pc is not None and not isinstance(raw_pc, str):
                            raise ContractError("pair_code must be a string or null")
                        rev_sess = bool(body_opt.get("revoke_sessions", True))
                        cur_sock = self.connection if isinstance(self.connection, socket.socket) else None
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            rev_res = outer.revoke_pairing(
                                pair_code=raw_pc,
                                revoke_sessions=rev_sess,
                                exclude_sock=cur_sock,
                            )
                        self._write_json(HTTPStatus.OK, rev_res)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/rotate-token":
                    try:
                        _ = self._read_optional_json_body(max_bytes=4096)
                        cur_sock = _unwrap_socket(self.connection)
                        rot_info = outer.rotate_auth_token_detailed(
                            expected_bearer=supplied_tok,
                            expected_epoch=auth_epoch,
                            exclude_sock=cur_sock,
                        )
                        if rot_info.get("stale_epoch") or not bool(rot_info.get("rotated", True)):
                            self._reject_unauthorized("Session epoch already rotated or revoked")
                            return
                        if not bool(rot_info["rotation_complete"]):
                            self._write_json(
                                HTTPStatus.CONFLICT,
                                {
                                    "ok": False,
                                    "status": "ROTATION_PENDING_DRAIN",
                                    "old_epoch_revoked": True,
                                    "rotation_complete": False,
                                    "active_old_leases": int(rot_info["active_old_leases"]),
                                    "session_epoch": str(rot_info["session_epoch"]),
                                },
                            )
                        else:
                            self._write_json(
                                HTTPStatus.OK,
                                {
                                    "ok": True,
                                    "status": "ROTATED",
                                    "old_epoch_revoked": True,
                                    "rotation_complete": True,
                                    "active_old_leases": 0,
                                    "session_epoch": str(rot_info["session_epoch"]),
                                },
                            )
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route in ("/api/select-ai-model", "/api/ai-model-select"):
                    if outer._ai_model_registry is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "AI model registry not configured"})
                        return
                    try:
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict or "model_id" not in body:
                            raise ContractError("model_id field required")
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            if "fast_scout_enabled" in body:
                                outer._ai_model_registry.set_fast_scout_enabled(bool(body["fast_scout_enabled"]))
                            if "thinking_depth" in body and body["thinking_depth"] is not None:
                                outer._ai_model_registry.set_thinking_depth(str(body["thinking_depth"]))
                            updated = assert_safe_ai_catalog_payload(outer._ai_model_registry.select_model(str(body["model_id"])))
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, updated)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/aggression-dial":
                    if outer._aggression_dial is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Aggression dial store not configured"})
                        return
                    req_conf_doc: dict[str, Any] | None = None
                    req_conf_phrase: str | None = None
                    routing_mode_lbl = "LIVE_OR_UNKNOWN"
                    try:
                        body = self._read_json_body(max_bytes=16384)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict:
                            raise ContractError("JSON object required")
                        is_live_or_unk, routing_mode_lbl = outer._resolve_aggression_live_mode_fail_closed()
                        if "live_mode" in body and type(body["live_mode"]) is not bool:
                            raise ContractError("live_mode must be a boolean")
                        live_mode_flag = bool(is_live_or_unk) or bool(body.get("live_mode", False))
                        raw_hrc = body.get("high_risk_confirmed", False)
                        if type(raw_hrc) is not bool:
                            raise ContractError("high_risk_confirmed must be a boolean")
                        actor_str = str(body.get("actor") or "cockpit-owner").strip() or "cockpit-owner"

                        raw_action = str(body.get("action") or "").strip().upper()
                        if not raw_action:
                            if "preset" in body:
                                raw_action = "APPLY_TIER_PRESET"
                            elif "tier_id" in body:
                                raw_action = "SET_TIER_RISK_BPS"
                            elif "master_risk_bps" in body or "risk_bps" in body:
                                raw_action = "SET_MASTER_RISK_BPS"
                            elif (
                                "ai_discretion_enabled" in body
                                or "enabled" in body
                                or "auto_shift_enabled" in body
                            ):
                                raw_action = "SET_AI_DISCRETION"
                            elif "ai_discretion_ceiling_bps" in body or "ceiling_bps" in body:
                                raw_action = "SET_AI_DISCRETION_CEILING"

                        dial_scope_id = str(getattr(outer._aggression_dial, "scope_id", "dual-shield-barbell"))

                        def _enforce_bound_live_dial_confirm(
                            canon_act: str,
                            *,
                            tier_id: str | None = None,
                            target_bps: Any = None,
                            ai_ceiling_bps: Any = None,
                            preset: Any = None,
                            requires_confirm: bool,
                        ) -> bool:
                            nonlocal req_conf_doc, req_conf_phrase
                            if not live_mode_flag:
                                return bool(raw_hrc)
                            t_bps_int = int(target_bps) if isinstance(target_bps, int) and type(target_bps) is not bool else None
                            c_bps_int = int(ai_ceiling_bps) if isinstance(ai_ceiling_bps, int) and type(ai_ceiling_bps) is not bool else None
                            req_conf_doc, req_conf_phrase = build_aggression_high_risk_confirmation(
                                dial_scope_id,
                                canon_act,
                                tier_id=tier_id,
                                target_bps=t_bps_int,
                                ai_ceiling_bps=c_bps_int,
                                preset=None if preset is None else str(preset),
                            )
                            has_explicit_binding = (
                                "confirmation_phrase" in body or "high_risk_confirmation" in body
                            )
                            must_bind = True
                            if requires_confirm:
                                if not raw_hrc:
                                    raise HighRiskConfirmationRequiredError(
                                        f"High-risk confirmation required in {routing_mode_lbl} mode for {canon_act}"
                                    )
                                if must_bind and not _verify_bound_aggression_confirmation(
                                    body, expected_doc=req_conf_doc, expected_phrase=req_conf_phrase
                                ):
                                    raise HighRiskConfirmationRequiredError(
                                        f"Exact target-bound high-risk confirmation required in {routing_mode_lbl} mode for {canon_act}"
                                    )
                                return True
                            if routing_mode_lbl == "LIVE_OR_UNKNOWN":
                                if not raw_hrc or not _verify_bound_aggression_confirmation(
                                    body, expected_doc=req_conf_doc, expected_phrase=req_conf_phrase
                                ):
                                    raise HighRiskConfirmationRequiredError(
                                        f"Routing state unavailable ({routing_mode_lbl}); bound confirmation required for {canon_act}"
                                    )
                                return True
                            if has_explicit_binding and not _verify_bound_aggression_confirmation(
                                body, expected_doc=req_conf_doc, expected_phrase=req_conf_phrase
                            ):
                                raise HighRiskConfirmationRequiredError(
                                    f"Bound high-risk confirmation does not match requested {canon_act} parameters"
                                )
                            return bool(raw_hrc)

                        with outer._commit_lease(supplied_tok, auth_epoch):
                            if raw_action == "SET_MASTER_RISK_BPS":
                                bps_val = (
                                    body["master_risk_bps"]
                                    if "master_risk_bps" in body
                                    else body.get("risk_bps")
                                )
                                ai_disc = (
                                    body["ai_discretion_enabled"]
                                    if "ai_discretion_enabled" in body
                                    else body.get("auto_shift_enabled")
                                )
                                ceil_val = (
                                    body["ai_discretion_ceiling_bps"]
                                    if "ai_discretion_ceiling_bps" in body
                                    else body.get("ceiling_bps")
                                )
                                need_hr = (
                                    (isinstance(bps_val, int) and type(bps_val) is not bool and bps_val >= HIGH_RISK_MIN_BPS)
                                    or (isinstance(ceil_val, int) and type(ceil_val) is not bool and ceil_val >= HIGH_RISK_MIN_BPS)
                                )
                                eff_hrc = _enforce_bound_live_dial_confirm(
                                    "SET_MASTER_RISK_BPS",
                                    target_bps=bps_val,
                                    ai_ceiling_bps=ceil_val,
                                    requires_confirm=need_hr,
                                )
                                outer._aggression_dial.set_master_risk_bps(
                                    bps_val,
                                    ai_discretion_enabled=ai_disc,
                                    ai_discretion_ceiling_bps=ceil_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=eff_hrc,
                                    owner_controls_allowed=True,
                                    actor=actor_str,
                                )
                            elif raw_action in ("SET_AI_DISCRETION", "TOGGLE_AI_DISCRETION"):
                                if "ai_discretion_enabled" in body:
                                    en_val = body["ai_discretion_enabled"]
                                elif "enabled" in body:
                                    en_val = body["enabled"]
                                elif "auto_shift_enabled" in body:
                                    en_val = body["auto_shift_enabled"]
                                else:
                                    cur_snap = outer._aggression_dial.snapshot()
                                    en_val = not bool(cur_snap["ai_discretion_enabled"])
                                ceil_val = (
                                    body["ai_discretion_ceiling_bps"]
                                    if "ai_discretion_ceiling_bps" in body
                                    else body.get("ceiling_bps")
                                )
                                need_hr = isinstance(ceil_val, int) and type(ceil_val) is not bool and ceil_val >= HIGH_RISK_MIN_BPS
                                eff_hrc = _enforce_bound_live_dial_confirm(
                                    "SET_AI_DISCRETION",
                                    ai_ceiling_bps=ceil_val,
                                    requires_confirm=need_hr,
                                )
                                outer._aggression_dial.set_ai_discretion(
                                    en_val,
                                    ceiling_bps=ceil_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=eff_hrc,
                                    owner_controls_allowed=True,
                                    actor=actor_str,
                                )
                            elif raw_action == "SET_AI_DISCRETION_CEILING":
                                ceil_val = (
                                    body["ai_discretion_ceiling_bps"]
                                    if "ai_discretion_ceiling_bps" in body
                                    else body.get("ceiling_bps")
                                )
                                if ceil_val is None:
                                    raise AggressionDialError("ai_discretion_ceiling_bps or ceiling_bps required")
                                if "ai_discretion_enabled" in body:
                                    en_cur = body["ai_discretion_enabled"]
                                elif "enabled" in body:
                                    en_cur = body["enabled"]
                                else:
                                    en_cur = bool(outer._aggression_dial.snapshot()["ai_discretion_enabled"])
                                need_hr = isinstance(ceil_val, int) and type(ceil_val) is not bool and ceil_val >= HIGH_RISK_MIN_BPS
                                eff_hrc = _enforce_bound_live_dial_confirm(
                                    "SET_AI_DISCRETION_CEILING",
                                    ai_ceiling_bps=ceil_val,
                                    requires_confirm=need_hr,
                                )
                                outer._aggression_dial.set_ai_discretion(
                                    en_cur,
                                    ceiling_bps=ceil_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=eff_hrc,
                                    owner_controls_allowed=True,
                                    actor=actor_str,
                                )
                            elif raw_action == "SET_TIER_RISK_BPS":
                                tid_raw = body.get("tier_id")
                                t_bps_raw = body.get("risk_bps")
                                need_hr = isinstance(t_bps_raw, int) and type(t_bps_raw) is not bool and t_bps_raw >= HIGH_RISK_MIN_BPS
                                eff_hrc = _enforce_bound_live_dial_confirm(
                                    "SET_TIER_RISK_BPS",
                                    tier_id=None if tid_raw is None else str(tid_raw),
                                    target_bps=t_bps_raw,
                                    requires_confirm=need_hr,
                                )
                                outer._aggression_dial.set_tier_risk_bps(
                                    tid_raw,
                                    t_bps_raw,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=eff_hrc,
                                    owner_controls_allowed=True,
                                    actor=actor_str,
                                )
                            elif raw_action in (
                                "APPLY_TIER_PRESET",
                                "SYNC_ALL_TO_MASTER",
                                "SYNC_MASTER",
                                "APPLY_STAGGER_PRESET",
                            ):
                                if raw_action in ("SYNC_ALL_TO_MASTER", "SYNC_MASTER") and "preset" not in body:
                                    preset_val: Any = "SYNC_MASTER"
                                elif raw_action == "APPLY_STAGGER_PRESET" and "preset" not in body:
                                    preset_val = "STAGGER_SAFE_TO_EXTREME"
                                else:
                                    preset_val = body.get("preset")
                                cur_master = int(outer._aggression_dial.snapshot()["master_risk_bps"])
                                p_up = str(preset_val or "").strip().upper()
                                need_hr = (
                                    p_up == "STAGGER_SAFE_TO_EXTREME"
                                    or (p_up in ("SYNC_MASTER", "SYNC_ALL_TO_MASTER") and cur_master >= HIGH_RISK_MIN_BPS)
                                )
                                eff_hrc = _enforce_bound_live_dial_confirm(
                                    "APPLY_TIER_PRESET",
                                    preset=preset_val,
                                    requires_confirm=need_hr,
                                )
                                outer._aggression_dial.apply_tier_preset(
                                    preset_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=eff_hrc,
                                    owner_controls_allowed=True,
                                    actor=actor_str,
                                )
                            else:
                                raise AggressionDialError(f"Unsupported aggression-dial action {raw_action!r}")
                            updated_dial = outer._read_aggression_dial_snapshot(owner_controls_allowed=True)
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, updated_dial)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except HighRiskConfirmationRequiredError as exc:
                        err_doc: dict[str, Any] = {
                            "error": str(exc),
                            "code": "HIGH_RISK_CONFIRMATION_REQUIRED",
                            "live_mode": True,
                            "routing_mode": routing_mode_lbl,
                            "high_risk_min_bps": HIGH_RISK_MIN_BPS,
                        }
                        if req_conf_doc is not None:
                            err_doc["required_confirmation"] = req_conf_doc
                        if req_conf_phrase is not None:
                            err_doc["required_confirmation_phrase"] = req_conf_phrase
                        self._write_json(HTTPStatus.CONFLICT, err_doc)
                    except OwnerKeyRequiredError:
                        self._reject_insufficient_scope()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/compounding":
                    has_comp = outer._compounding_controller is not None or (
                        outer._autonomous_trader is not None
                        and getattr(outer._autonomous_trader, "compounding_controller", None) is not None
                    )
                    if not has_comp:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Compounding controller not configured"})
                        return
                    try:
                        body = self._read_json_body(max_bytes=16384)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if auth_scope != SESSION_SCOPE_OWNER_FULL:
                            self._reject_insufficient_scope()
                            return
                        if type(body) is not dict:
                            raise ContractError("JSON object required")
                        raw_act = body.get("action")
                        if not isinstance(raw_act, str) or not raw_act.strip():
                            raise ContractError("action field required")
                        act_norm = raw_act.strip().upper()
                        actor_str = "cockpit-owner"
                        if "actor" in body and body["actor"] is not None:
                            if not isinstance(body["actor"], str) or not body["actor"].strip():
                                raise ContractError("actor must be a non-empty string")
                            actor_str = body["actor"].strip()

                        if act_norm in ("SET_MODE", "TOGGLE_FULL_100"):
                            allowed_keys = {
                                "action",
                                "mode",
                                "custom_sweep_ratio",
                                "custom_vault_ratio",
                                "compounding_target_usd",
                                "house_money_target_usd",
                                "post_target_vault_ratio",
                                "auto_enable_vault_at_target",
                                "starting_principal_usd",
                                "actor",
                            }
                            extra_keys = sorted(set(body.keys()) - allowed_keys)
                            if extra_keys:
                                raise ContractError(
                                    f"Unexpected additional properties in POST /api/compounding: {extra_keys}"
                                )
                            custom_ratio_dec: Decimal | None = None
                            if body.get("custom_sweep_ratio") is not None and body.get("custom_vault_ratio") is not None:
                                r1 = outer._parse_strict_decimal_field(body["custom_sweep_ratio"], "custom_sweep_ratio")
                                r2 = outer._parse_strict_decimal_field(body["custom_vault_ratio"], "custom_vault_ratio")
                                if r1 != r2:
                                    raise ContractError("custom_sweep_ratio and custom_vault_ratio conflict")
                                custom_ratio_dec = r1
                            elif body.get("custom_sweep_ratio") is not None:
                                custom_ratio_dec = outer._parse_strict_decimal_field(
                                    body["custom_sweep_ratio"], "custom_sweep_ratio"
                                )
                            elif body.get("custom_vault_ratio") is not None:
                                custom_ratio_dec = outer._parse_strict_decimal_field(
                                    body["custom_vault_ratio"], "custom_vault_ratio"
                                )

                            comp_target_dec = (
                                outer._parse_strict_decimal_field(
                                    body["compounding_target_usd"], "compounding_target_usd"
                                )
                                if body.get("compounding_target_usd") is not None
                                else None
                            )
                            hm_target_dec = (
                                outer._parse_strict_decimal_field(
                                    body["house_money_target_usd"], "house_money_target_usd"
                                )
                                if body.get("house_money_target_usd") is not None
                                else None
                            )
                            post_ratio_dec = (
                                outer._parse_strict_decimal_field(
                                    body["post_target_vault_ratio"], "post_target_vault_ratio"
                                )
                                if body.get("post_target_vault_ratio") is not None
                                else None
                            )
                            auto_en_val: bool | None = None
                            if "auto_enable_vault_at_target" in body and body["auto_enable_vault_at_target"] is not None:
                                if type(body["auto_enable_vault_at_target"]) is not bool:
                                    raise ContractError("auto_enable_vault_at_target must be a boolean")
                                auto_en_val = body["auto_enable_vault_at_target"]
                            req_principal_dec = (
                                outer._parse_strict_decimal_field(
                                    body["starting_principal_usd"], "starting_principal_usd"
                                )
                                if body.get("starting_principal_usd") is not None
                                else None
                            )

                            with outer._commit_lease(supplied_tok, auth_epoch):
                                cur_snap = outer._read_compounding_snapshot(
                                    owner_controls_allowed=True,
                                    session_scope=SESSION_SCOPE_OWNER_FULL,
                                )
                                if cur_snap is None:
                                    raise ContractError("Compounding controller not configured")
                                if req_principal_dec is not None:
                                    cur_prin = Decimal(str(cur_snap["starting_principal_usd"]))
                                    if req_principal_dec.quantize(Decimal("0.01")) != cur_prin:
                                        raise CompoundingControllerError(
                                            "starting_principal_usd is immutable after initialization"
                                        )
                                if "mode" in body and body["mode"] is not None:
                                    if not isinstance(body["mode"], str) or not body["mode"].strip():
                                        raise ContractError("mode must be a non-empty string")
                                    mode_str = body["mode"].strip().upper()
                                elif act_norm == "TOGGLE_FULL_100":
                                    mode_str = (
                                        "BALANCED_SPLIT_50_50"
                                        if str(cur_snap.get("mode")) == "FULL_COMPOUND_100"
                                        else "FULL_COMPOUND_100"
                                    )
                                else:
                                    raise ContractError("mode field required for set_mode")

                                if outer._autonomous_trader is not None and callable(
                                    getattr(outer._autonomous_trader, "set_compounding_mode", None)
                                ) and getattr(outer._autonomous_trader, "compounding_controller", None) is not None:
                                    updated_comp = outer._autonomous_trader.set_compounding_mode(
                                        mode_str,
                                        compounding_target_usd=comp_target_dec,
                                        house_money_target_usd=hm_target_dec,
                                        custom_vault_ratio=custom_ratio_dec,
                                        post_target_vault_ratio=post_ratio_dec,
                                        auto_enable_vault_at_target=auto_en_val,
                                        owner_controls_allowed=True,
                                        actor=actor_str,
                                    )
                                else:
                                    outer._compounding_controller.set_compounding_mode(
                                        mode_str,
                                        compounding_target_usd=comp_target_dec,
                                        house_money_target_usd=hm_target_dec,
                                        custom_vault_ratio=custom_ratio_dec,
                                        post_target_vault_ratio=post_ratio_dec,
                                        auto_enable_vault_at_target=auto_en_val,
                                        owner_controls_allowed=True,
                                        actor=actor_str,
                                    )
                                    updated_comp = outer._read_compounding_snapshot(
                                        owner_controls_allowed=True,
                                        session_scope=SESSION_SCOPE_OWNER_FULL,
                                    )
                                    if outer._profit_vault is not None and updated_comp is not None:
                                        eff_r = Decimal(str(updated_comp["effective_vault_sweep_ratio"]))
                                        outer._profit_vault.set_config(sweep_ratio=eff_r, auto_sweep_enabled=True)

                        elif act_norm in ("ACKNOWLEDGE_PRINCIPAL_WITHDRAWN", "ACK_PRINCIPAL_WITHDRAWN"):
                            allowed_ack_keys = {
                                "action",
                                "amount_usd",
                                "post_withdrawal_equity_usd",
                                "note",
                                "actor",
                            }
                            extra_ack = sorted(set(body.keys()) - allowed_ack_keys)
                            if extra_ack:
                                raise ContractError(
                                    f"Unexpected additional properties in POST /api/compounding: {extra_ack}"
                                )
                            amt_dec = (
                                outer._parse_strict_decimal_field(body["amount_usd"], "amount_usd")
                                if body.get("amount_usd") is not None
                                else None
                            )
                            post_eq_dec = (
                                outer._parse_strict_decimal_field(
                                    body["post_withdrawal_equity_usd"], "post_withdrawal_equity_usd"
                                )
                                if body.get("post_withdrawal_equity_usd") is not None
                                else None
                            )
                            raw_note = body.get("note")
                            if raw_note is not None:
                                if (
                                    not isinstance(raw_note, str)
                                    or len(raw_note) > 240
                                    or any(ch in raw_note for ch in ("\x00", "\r", "\n"))
                                ):
                                    raise ContractError("note must be a clean string of at most 240 characters")
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                if outer._autonomous_trader is not None and callable(
                                    getattr(outer._autonomous_trader, "acknowledge_principal_withdrawn", None)
                                ) and getattr(outer._autonomous_trader, "compounding_controller", None) is not None:
                                    updated_comp = outer._autonomous_trader.acknowledge_principal_withdrawn(
                                        amt_dec,
                                        owner_controls_allowed=True,
                                        actor=actor_str,
                                        post_withdrawal_equity_usd=post_eq_dec,
                                        note=raw_note,
                                    )
                                else:
                                    cur_snap = outer._read_compounding_snapshot(
                                        owner_controls_allowed=True,
                                        session_scope=SESSION_SCOPE_OWNER_FULL,
                                    )
                                    if cur_snap is None:
                                        raise ContractError("Compounding controller not configured")
                                    eff_amt = amt_dec
                                    if eff_amt is None:
                                        sugg = Decimal(str(cur_snap["suggested_principal_pullout_usd"]))
                                        eff_amt = (
                                            sugg
                                            if sugg > Decimal("0.00")
                                            else Decimal(str(cur_snap["starting_principal_usd"]))
                                        )
                                    outer._compounding_controller.acknowledge_principal_withdrawn(
                                        eff_amt,
                                        owner_controls_allowed=True,
                                        actor=actor_str,
                                        post_withdrawal_equity_usd=post_eq_dec,
                                    )
                                    updated_comp = outer._read_compounding_snapshot(
                                        owner_controls_allowed=True,
                                        session_scope=SESSION_SCOPE_OWNER_FULL,
                                    )
                        else:
                            raise ContractError(f"Unsupported compounding action {raw_act!r}")

                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, updated_comp)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except (OwnerKeyRequiredError, CompoundingOwnerKeyRequiredError):
                        self._reject_insufficient_scope()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/option-b-demo":
                    if outer._option_b_demo is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Option B paper demo runner not configured"})
                        return
                    try:
                        body = self._read_json_body(max_bytes=16384)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if auth_scope != SESSION_SCOPE_OWNER_FULL:
                            self._reject_insufficient_scope()
                            return
                        if type(body) is not dict:
                            raise ContractError("JSON object required")
                        raw_act = body.get("action")
                        if not isinstance(raw_act, str) or not raw_act.strip():
                            raise ContractError("action field required")
                        act_norm = raw_act.strip().upper()
                        raw_reason = body.get("reason")
                        clean_reason: str | None = None
                        if raw_reason is not None:
                            if (
                                not isinstance(raw_reason, str)
                                or not raw_reason.strip()
                                or len(raw_reason.strip()) > 160
                                or any(ch in raw_reason for ch in ("\x00", "\r", "\n"))
                            ):
                                raise ContractError("reason must be a clean string of at most 160 characters")
                            clean_reason = raw_reason.strip()
                        action_result: dict[str, Any]
                        if act_norm == "CLOSE_POSITION":
                            extra_keys = sorted(set(body.keys()) - {"action", "position_id", "reason"})
                            if extra_keys:
                                raise ContractError(f"Unexpected additional properties in POST /api/option-b-demo: {extra_keys}")
                            raw_pid = body.get("position_id")
                            if not isinstance(raw_pid, str) or not raw_pid.strip() or len(raw_pid.strip()) > 120:
                                raise ContractError("position_id must be a non-empty string")
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                receipt = outer._option_b_demo.close_position(
                                    raw_pid.strip(),
                                    reason=clean_reason or "OPTION_B_OWNER_CLOSE",
                                )
                                snap = outer._read_option_b_demo_snapshot(
                                    owner_controls_allowed=True,
                                    session_scope=SESSION_SCOPE_OWNER_FULL,
                                )
                            action_result = {
                                "ok": True,
                                "action": "CLOSE_POSITION",
                                "receipt": receipt.to_dict() if hasattr(receipt, "to_dict") else {"order_id": getattr(receipt, "order_id", "")},
                                "snapshot": snap,
                            }
                        elif act_norm == "EMERGENCY_CLOSE_ALL":
                            extra_keys = sorted(set(body.keys()) - {"action", "reason"})
                            if extra_keys:
                                raise ContractError(f"Unexpected additional properties in POST /api/option-b-demo: {extra_keys}")
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                receipts = outer._option_b_demo.emergency_close_all(
                                    reason=clean_reason or "OPTION_B_OWNER_EMERGENCY_FLATTEN",
                                )
                                snap = outer._read_option_b_demo_snapshot(
                                    owner_controls_allowed=True,
                                    session_scope=SESSION_SCOPE_OWNER_FULL,
                                )
                            action_result = {
                                "ok": True,
                                "action": "EMERGENCY_CLOSE_ALL",
                                "closed_count": len(receipts),
                                "snapshot": snap,
                            }
                        elif act_norm == "MIRROR_SIGNAL":
                            allowed_mirror = {
                                "action",
                                "symbol",
                                "side",
                                "stop_distance_points",
                                "take_profit_points",
                                "risk_pct",
                                "reason",
                            }
                            extra_keys = sorted(set(body.keys()) - allowed_mirror)
                            if extra_keys:
                                raise ContractError(f"Unexpected additional properties in POST /api/option-b-demo: {extra_keys}")
                            raw_sym = body.get("symbol")
                            raw_side = body.get("side")
                            if not isinstance(raw_sym, str) or not raw_sym.strip():
                                raise ContractError("symbol must be a non-empty string")
                            if not isinstance(raw_side, str) or raw_side.strip().upper() not in ("BUY", "SELL"):
                                raise ContractError("side must be BUY or SELL")
                            stop_pts = outer._parse_strict_decimal_field(
                                body.get("stop_distance_points"), "stop_distance_points"
                            )
                            tp_pts = outer._parse_strict_decimal_field(
                                body.get("take_profit_points"), "take_profit_points"
                            )
                            risk_pct = (
                                outer._parse_strict_decimal_field(body.get("risk_pct"), "risk_pct")
                                if body.get("risk_pct") is not None
                                else outer._option_b_demo.default_risk_pct
                            )
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                mirror_res = outer._option_b_demo.mirror_entry_signal(
                                    symbol=raw_sym.strip().upper(),
                                    side=raw_side.strip().upper(),
                                    stop_distance_points=stop_pts,
                                    take_profit_points=tp_pts,
                                    risk_pct=risk_pct,
                                    reason=clean_reason or "OPTION_B_OWNER_MIRROR_SIGNAL",
                                )
                                snap = outer._read_option_b_demo_snapshot(
                                    owner_controls_allowed=True,
                                    session_scope=SESSION_SCOPE_OWNER_FULL,
                                )
                            action_result = {
                                "ok": True,
                                "action": "MIRROR_SIGNAL",
                                "result": mirror_res,
                                "snapshot": snap,
                            }
                        else:
                            raise ContractError(f"Unsupported Option B demo action {raw_act!r}")
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(action_result))
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except OwnerKeyRequiredError:
                        self._reject_insufficient_scope()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/demo-high-growth-profile":
                    if outer._demo_high_growth_store is None:
                        self._drain_small_request_body(max_bytes=16384)
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "DEMO high-growth profile store not configured"})
                        return
                    try:
                        body = self._read_json_body(max_bytes=16384)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if auth_scope != SESSION_SCOPE_OWNER_FULL:
                            self._reject_insufficient_scope()
                            return
                        if type(body) is not dict:
                            raise ContractError("JSON object required")
                        is_live_or_unk, _ = outer._resolve_aggression_live_mode_fail_closed()
                        cur_prof = outer._demo_high_growth_store.profile()
                        candidate = DemoHighGrowthProfile.from_wire_dict(body, base=cur_prof)
                        if is_live_or_unk and candidate.enabled:
                            self._write_json(
                                HTTPStatus.FORBIDDEN,
                                {
                                    "error": DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE,
                                    "code": DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE,
                                },
                            )
                            return
                        exec_mode = "LIVE" if is_live_or_unk else "DEMO"
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            outer._demo_high_growth_store.update(
                                candidate,
                                execution_mode=exec_mode,
                                live_trading_armed=is_live_or_unk,
                                live_trading_locked=not is_live_or_unk,
                            )
                            outer._apply_demo_high_growth_profile_to_components(candidate)
                            snap = outer._read_demo_high_growth_snapshot(
                                owner_controls_allowed=True,
                                session_scope=SESSION_SCOPE_OWNER_FULL,
                            )
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(snap))
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except OwnerKeyRequiredError:
                        self._reject_insufficient_scope()
                    except ContractError as exc:
                        err_s = str(exc)
                        if DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE in err_s:
                            self._write_json(
                                HTTPStatus.FORBIDDEN,
                                {"error": err_s, "code": DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE},
                            )
                        else:
                            self._write_json(HTTPStatus.BAD_REQUEST, {"error": err_s})
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/thinking-depth":
                    if outer._ai_model_registry is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "AI model registry not configured"})
                        return
                    try:
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict or "thinking_depth" not in body:
                            raise ContractError("thinking_depth field required")
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            updated = assert_safe_ai_catalog_payload(
                                outer._ai_model_registry.set_thinking_depth(str(body["thinking_depth"]))
                            )
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, updated)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/treasury-config":
                    if outer._profit_vault is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Profit Sweep Vault not configured"})
                        return
                    try:
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict:
                            raise ContractError("JSON object required")
                        from decimal import Decimal as _Dec
                        ratio_v = _Dec(str(body["sweep_ratio"])) if body.get("sweep_ratio") is not None else None
                        auto_v = bool(body["auto_sweep_enabled"]) if "auto_sweep_enabled" in body else None
                        rail_v = str(body["preferred_rail"]) if body.get("preferred_rail") is not None else None
                        init_cap_v = (
                            _Dec(str(body["initial_capital_usd"]))
                            if body.get("initial_capital_usd") is not None
                            else None
                        )
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            updated = outer._profit_vault.set_config(
                                sweep_ratio=ratio_v,
                                auto_sweep_enabled=auto_v,
                                preferred_rail=rail_v,
                                initial_capital_usd=init_cap_v,
                            )
                            if outer._autonomous_trader is not None and (
                                init_cap_v is not None or ratio_v is not None or auto_v is not None
                            ):
                                outer._autonomous_trader.sync_session_profit_to_vault()
                                updated = outer._profit_vault.snapshot()
                            updated = assert_safe_ai_catalog_payload(updated)
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, updated)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/treasury-prepare":
                    if outer._profit_vault is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Profit Sweep Vault not configured"})
                        return
                    try:
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict or "action" not in body or "amount_usd" not in body:
                            raise ContractError("action and amount_usd fields required")
                        act_p = str(body["action"]).strip().upper()
                        from decimal import Decimal as _Dec
                        req_id_p = str(body.get("owner_request_id") or f"treasury-prep-{secrets.token_hex(6)}")
                        reason_p = str(body.get("reason") or "Owner treasury disbursement")
                        ttl_p = int(body.get("ttl_seconds", 900))
                        if act_p in ("REQUEST_BROKER_2FA_WITHDRAWAL", "BROKER_2FA_WITHDRAWAL"):
                            dest_lbl = str(body.get("destination_bank_label") or body.get("destination_bank_id") or "OWNER_LINKED_BANK")
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                prep = outer._profit_vault.prepare_broker_2fa_withdrawal(
                                    broker_id=str(body.get("broker_id") or "HUGOSWAY_MT5"),
                                    amount_usd=_Dec(str(body["amount_usd"])),
                                    owner_request_id=req_id_p,
                                    reason=reason_p,
                                    destination_bank_label=dest_lbl,
                                    ttl_seconds=ttl_p,
                                )
                        elif act_p in ("EXECUTE_OFFRAMP_ACH", "OFFRAMP_ACH_PAYOUT"):
                            from cas_forex_revamp.treasury.profit_sweep import CoinbaseOfframpClient, KrakenOfframpClient
                            rail_p = str(body.get("rail") or "COINBASE_ACH").strip().upper()
                            cb_p = CoinbaseOfframpClient.from_environ(os.environ) if rail_p == "COINBASE_ACH" else None
                            krk_p = KrakenOfframpClient.from_environ(os.environ) if rail_p == "KRAKEN_ACH" else None
                            dest_override = str(body["destination_bank_id"]).strip() if body.get("destination_bank_id") else None
                            conv_amt = _Dec(str(body["convert_amount"])) if body.get("convert_amount") is not None else None
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                prep = outer._profit_vault.prepare_offramp_ach_payout(
                                    rail=rail_p,
                                    amount_usd=_Dec(str(body["amount_usd"])),
                                    owner_request_id=req_id_p,
                                    reason=reason_p,
                                    coinbase_client=cb_p,
                                    kraken_client=krk_p,
                                    destination_bank_id=dest_override,
                                    convert_from_currency=body.get("convert_from_currency"),
                                    convert_amount=conv_amt,
                                    coinbase_source_account_uuid=body.get("coinbase_source_account_uuid"),
                                    coinbase_usd_account_uuid=body.get("coinbase_usd_account_uuid"),
                                    kraken_pair=str(body.get("kraken_pair") or "USDCUSD"),
                                    idempotency_key=body.get("idempotency_key"),
                                    retry_transfer_id=body.get("retry_transfer_id"),
                                    ttl_seconds=ttl_p,
                                )
                        else:
                            raise ContractError(f"unsupported treasury prepare action {act_p!r}")
                        self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(prep))
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/treasury-action":
                    if outer._profit_vault is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Profit Sweep Vault not configured"})
                        return
                    try:
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict or "action" not in body:
                            raise ContractError("action field required")
                        if outer._owner_recovery is None:
                            raise ContractError("OWNER_RECOVERY_VERIFIER_NOT_CONFIGURED")
                        act = str(body["action"]).strip().upper()
                        from decimal import Decimal as _Dec
                        req_id = str(body.get("owner_request_id") or "treasury-op-1")
                        reason = str(body.get("reason") or "Owner treasury disbursement")
                        rec_tok = body.get("recovery_token") or body.get("owner_authorization")
                        if act == "REQUEST_BROKER_2FA_WITHDRAWAL":
                            dest_lbl = str(body.get("destination_bank_label") or body.get("destination_bank_id") or "OWNER_LINKED_BANK")
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                res = outer._profit_vault.request_broker_2fa_withdrawal(
                                    broker_id=str(body.get("broker_id") or "HUGOSWAY_MT5"),
                                    amount_usd=_Dec(str(body["amount_usd"])),
                                    owner_request_id=req_id,
                                    reason=reason,
                                    verifier=outer._owner_recovery,
                                    recovery_token=str(rec_tok or ""),
                                    destination_bank_label=dest_lbl,
                                    intent_id=body.get("intent_id"),
                                    intent_sha256=body.get("intent_sha256"),
                                )
                        elif act == "CONFIRM_BROKER_2FA_WITHDRAWAL":
                            def _epoch_guard_2fa() -> None:
                                outer._assert_epoch_active(supplied_tok, auth_epoch)

                            raw_pv = outer._withdrawal_provider_verifier

                            def _guarded_pv(b_id: str, tx_id: str) -> Mapping[str, Any]:
                                _epoch_guard_2fa()
                                if raw_pv is None:
                                    raise ContractError("withdrawal_provider_verifier not configured")
                                out_pv = raw_pv(b_id, tx_id)
                                _epoch_guard_2fa()
                                return out_pv

                            with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=False):
                                _epoch_guard_2fa()
                                confirm_fn = outer._profit_vault.confirm_broker_2fa_withdrawal
                                confirm_kwargs: dict[str, Any] = {
                                    "transfer_id": str(body["transfer_id"]),
                                    "provider_tx_id": str(body["provider_tx_id"]),
                                    "owner_request_id": req_id,
                                    "verifier": outer._owner_recovery,
                                    "recovery_token": str(rec_tok or ""),
                                    "provider_verifier": None if raw_pv is None else _guarded_pv,
                                }
                                if "epoch_guard" in inspect.signature(confirm_fn).parameters:
                                    confirm_kwargs["epoch_guard"] = _epoch_guard_2fa
                                res = confirm_fn(**confirm_kwargs)
                        elif act == "EXECUTE_OFFRAMP_ACH":
                            from cas_forex_revamp.treasury.profit_sweep import CoinbaseOfframpClient, KrakenOfframpClient
                            rail_name = str(body.get("rail") or "COINBASE_ACH").strip().upper()
                            raw_cb = CoinbaseOfframpClient.from_environ(os.environ) if rail_name == "COINBASE_ACH" else None
                            raw_krk = KrakenOfframpClient.from_environ(os.environ) if rail_name == "KRAKEN_ACH" else None
                            conv_amt = _Dec(str(body["convert_amount"])) if body.get("convert_amount") is not None else None

                            def _epoch_guard_ach() -> None:
                                outer._assert_epoch_active(supplied_tok, auth_epoch)

                            cb = None if raw_cb is None else _EpochGuardedOfframpClient(raw_cb, _epoch_guard_ach)
                            krk = None if raw_krk is None else _EpochGuardedOfframpClient(raw_krk, _epoch_guard_ach)
                            with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=False):
                                _epoch_guard_ach()
                                ach_fn = outer._profit_vault.execute_offramp_ach_payout
                                ach_kwargs: dict[str, Any] = {
                                    "rail": rail_name,
                                    "amount_usd": _Dec(str(body["amount_usd"])),
                                    "owner_request_id": req_id,
                                    "reason": reason,
                                    "verifier": outer._owner_recovery,
                                    "recovery_token": str(rec_tok or ""),
                                    "coinbase_client": cb,
                                    "kraken_client": krk,
                                    "convert_from_currency": body.get("convert_from_currency"),
                                    "convert_amount": conv_amt,
                                    "coinbase_source_account_uuid": body.get("coinbase_source_account_uuid"),
                                    "coinbase_usd_account_uuid": body.get("coinbase_usd_account_uuid"),
                                    "kraken_pair": str(body.get("kraken_pair") or "USDCUSD"),
                                    "idempotency_key": body.get("idempotency_key"),
                                    "retry_transfer_id": body.get("retry_transfer_id"),
                                    "intent_id": body.get("intent_id"),
                                    "intent_sha256": body.get("intent_sha256"),
                                }
                                if "epoch_guard" in inspect.signature(ach_fn).parameters:
                                    ach_kwargs["epoch_guard"] = _epoch_guard_ach
                                res = ach_fn(**ach_kwargs)
                        else:
                            raise ContractError(f"unsupported treasury action {act!r}")
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(res))
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        code = HTTPStatus.FORBIDDEN if "OWNER_RECOVERY" in str(exc) else HTTPStatus.BAD_REQUEST
                        self._write_json(code, {"error": str(exc)})
                    return

                if route == "/api/explainer-ask":
                    if outer._ai_model_registry is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "AI model registry not configured"})
                        return
                    try:
                        body = self._read_json_body(max_bytes=MAX_EXPLAINER_AUDIO_RPC_BYTES)
                        if type(body) is not dict:
                            raise ContractError("JSON object body required")
                        raw_q = body.get("question")
                        raw_audio = body.get("audio_base64")
                        raw_mime = body.get("audio_mime_type")
                        has_audio = isinstance(raw_audio, str) and bool(raw_audio.strip())
                        if raw_q is None and has_audio:
                            raw_q = ""
                        if not isinstance(raw_q, str) or (not raw_q.strip() and not has_audio):
                            raise ContractError("question field required")
                        if raw_audio is not None and not isinstance(raw_audio, str):
                            raise ContractError("audio_base64 must be a string")
                        if raw_mime is not None and not isinstance(raw_mime, str):
                            raise ContractError("audio_mime_type must be a string")

                        with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=False, allow_device_scope=True):
                            ctx_summary: dict[str, Any] = {}
                            if outer._broker_router_reader is not None:
                                try:
                                    raw_r = outer._broker_router_reader()
                                    if isinstance(raw_r, Mapping):
                                        r_doc = safe_broker_routing_payload(dict(raw_r))
                                        exec_m = str(r_doc.get("execution_mode") or "DEMO")
                                        act_b = str(r_doc.get("active_broker") or "HUGOSWAY_MT5")
                                        ctx_summary["execution_mode"] = exec_m
                                        ctx_summary["active_broker"] = act_b
                                        ds = r_doc.get("dual_shield") if isinstance(r_doc.get("dual_shield"), Mapping) else {}
                                        alloc = ds.get("allocation") if isinstance(ds.get("allocation"), Mapping) else {}
                                        bb = ds.get("barbell") if isinstance(ds.get("barbell"), Mapping) else {}
                                        sh = ds.get("safe_harbor") if isinstance(ds.get("safe_harbor"), Mapping) else {}
                                        vlv = r_doc.get("valve") if isinstance(r_doc.get("valve"), Mapping) else {}
                                        lr = r_doc.get("live_readiness") if isinstance(r_doc.get("live_readiness"), Mapping) else {}
                                        ctx_summary["broker_routing"] = {
                                            "execution_mode": exec_m,
                                            "live_armed": bool(lr.get("live_armed", r_doc.get("live_trading_armed", False))),
                                            "active_broker": act_b,
                                            "chain": [
                                                {
                                                    "broker_id": str(c.get("broker_id", "")),
                                                    "status": str(c.get("status", "")),
                                                    "role": str(c.get("role", "")),
                                                    "server": str(c.get("server", "")),
                                                    "max_leverage": str(c.get("max_leverage", "")),
                                                }
                                                for c in (r_doc.get("chain") or [])
                                                if isinstance(c, Mapping)
                                            ],
                                            "total_equity": alloc.get("total_equity"),
                                            "peak_equity": alloc.get("peak_equity"),
                                            "drawdown_pct": alloc.get("drawdown_pct"),
                                            "venues": [
                                                {
                                                    "broker_id": str(v.get("broker_id", "")),
                                                    "equity": str(v.get("equity", "0")),
                                                    "target_share": str(v.get("target_share", "0")),
                                                    "actual_share": str(v.get("actual_share", "0")),
                                                }
                                                for v in (alloc.get("venues") or [])
                                                if isinstance(v, Mapping)
                                            ],
                                            "barbell": {
                                                "max_stop_loss_equity_risk_pct": bb.get("max_stop_loss_equity_risk_pct"),
                                                "max_drawdown_pct": bb.get("max_drawdown_pct"),
                                                "demo_virtual_sleeve": bb.get("demo_virtual_sleeve"),
                                            },
                                            "valve": {
                                                "controller": vlv.get("controller"),
                                                "parameters": vlv.get("parameters"),
                                                "threshold": vlv.get("threshold"),
                                            },
                                            "live_readiness": {
                                                "all_gates_ready": bool(lr.get("all_gates_ready", False)),
                                                "gates": [
                                                    {
                                                        "id": str(g.get("id", "")),
                                                        "step": int(g.get("step", idx + 1)),
                                                        "title": str(g.get("title", "")),
                                                        "passed": bool(g.get("passed", False)),
                                                        "detail": str(g.get("detail", "")),
                                                    }
                                                    for idx, g in enumerate(lr.get("gates") or [])
                                                    if isinstance(g, Mapping)
                                                ],
                                            },
                                            "recent_degradations": list(sh.get("recent_degradations") or [])[-3:],
                                        }
                                except Exception as exc_ctx:
                                    outer._last_routing_error = type(exc_ctx).__name__

                            if outer._autonomous_trader is not None:
                                try:
                                    t_doc = outer._autonomous_trader.status_snapshot()
                                    ctx_summary["current_focus_symbol"] = t_doc.get("current_focus_symbol")
                                    ctx_summary["current_focus_status"] = t_doc.get("current_focus_status")
                                    ctx_summary["cycle_count"] = t_doc.get("cycle_count")
                                    ctx_summary["market_sessions"] = t_doc.get("market_sessions")
                                    dq = t_doc.get("daily_quota") if isinstance(t_doc.get("daily_quota"), Mapping) else {}
                                    ctx_summary["ai_trader"] = {
                                        "governance_mode": t_doc.get("governance_mode"),
                                        "active_model_id": t_doc.get("active_model_id"),
                                        "fast_scout_enabled": t_doc.get("fast_scout_enabled"),
                                        "cycle_count": t_doc.get("cycle_count"),
                                        "veto_count": t_doc.get("veto_count"),
                                        "current_focus_symbol": t_doc.get("current_focus_symbol"),
                                        "current_focus_status": t_doc.get("current_focus_status"),
                                        "last_action": t_doc.get("last_action"),
                                        "last_symbol": t_doc.get("last_symbol"),
                                        "last_reason": t_doc.get("last_reason"),
                                        "risk_gear": t_doc.get("risk_gear"),
                                        "banked_session": t_doc.get("banked_session"),
                                        "daily_quota": {
                                            "status": dq.get("status"),
                                            "realized_net_pnl_usd": dq.get("realized_net_pnl_usd"),
                                            "closed_trades": dq.get("closed_trades"),
                                            "win_count": dq.get("win_count"),
                                            "loss_count": dq.get("loss_count"),
                                            "consecutive_losses": dq.get("consecutive_losses"),
                                            "soft_quota_usd": dq.get("soft_quota_usd"),
                                            "hard_quota_usd": dq.get("hard_quota_usd"),
                                            "max_daily_loss_usd": dq.get("max_daily_loss_usd"),
                                        },
                                        "open_positions": [
                                            {
                                                "broker_id": p_item.get("broker_id"),
                                                "symbol": p_item.get("symbol"),
                                                "side": p_item.get("side"),
                                                "volume_lots": p_item.get("volume_lots"),
                                                "entry_price": p_item.get("entry_price"),
                                                "stop_loss": p_item.get("stop_loss"),
                                                "take_profit": p_item.get("take_profit"),
                                                "profit": p_item.get("profit"),
                                                "protection_stage": p_item.get("protection_stage"),
                                            }
                                            for p_item in (t_doc.get("open_positions") or [])
                                            if isinstance(p_item, Mapping)
                                        ],
                                        "recent_actions": [
                                            {
                                                k_act: r_act.get(k_act)
                                                for k_act in (
                                                    "observed_at",
                                                    "action",
                                                    "kind",
                                                    "symbol",
                                                    "executed_on",
                                                    "regime",
                                                    "reason",
                                                    "detail",
                                                )
                                                if k_act in r_act
                                            }
                                            for r_act in list(t_doc.get("recent_actions") or [])[:5]
                                            if isinstance(r_act, Mapping)
                                        ],
                                        "market_sessions": t_doc.get("market_sessions"),
                                    }
                                except Exception as exc_ctx:
                                    outer._last_routing_error = type(exc_ctx).__name__

                            if outer._profit_vault is not None:
                                try:
                                    v_doc = outer._profit_vault.snapshot()
                                    if isinstance(v_doc, Mapping):
                                        ctx_summary["treasury"] = {
                                            "total_realized_profit_usd": str(v_doc.get("total_realized_profit_usd", "0")),
                                            "bank_sweep_reserved_usd": str(v_doc.get("bank_sweep_reserved_usd", "0")),
                                            "retained_trading_usd": str(v_doc.get("retained_trading_usd", "0")),
                                            "pending_confirmation_usd": str(
                                                v_doc.get("pending_confirmation_usd")
                                                or v_doc.get("pending_2fa_confirmation_usd")
                                                or v_doc.get("pending_disbursement_usd")
                                                or "0"
                                            ),
                                            "disbursed_to_bank_usd": str(v_doc.get("disbursed_to_bank_usd", "0")),
                                            "confirmed_settled_disbursed_usd": str(v_doc.get("confirmed_settled_disbursed_usd", "0")),
                                            "pending_or_unconfirmed_transfers_usd": str(v_doc.get("pending_or_unconfirmed_transfers_usd", "0")),
                                        }
                                except Exception as exc_ctx:
                                    outer._last_routing_error = type(exc_ctx).__name__

                            if outer._parallel_tiers is not None:
                                try:
                                    pt_doc = outer._parallel_tiers.snapshot()
                                    if isinstance(pt_doc, Mapping):
                                        ctx_summary["parallel_tiers"] = [
                                            {
                                                "tier_id": str(t_item.get("tier_id", "")),
                                                "label": str(t_item.get("label", "")),
                                                "starting_equity_usd": str(
                                                    t_item.get("starting_equity_usd")
                                                    or t_item.get("starting_capital_usd")
                                                    or "0"
                                                ),
                                                "current_equity_usd": str(
                                                    t_item.get("current_equity_usd")
                                                    or t_item.get("equity_usd")
                                                    or "0"
                                                ),
                                                "bank_vault_usd": str(
                                                    t_item.get("bank_vault_usd")
                                                    or t_item.get("bank_sweep_reserved_usd")
                                                    or "0"
                                                ),
                                                "net_gain_pct": str(
                                                    t_item.get("net_gain_pct")
                                                    or t_item.get("growth_pct")
                                                    or "0"
                                                ),
                                                "closed_trades": int(t_item.get("closed_trades", 0) or 0),
                                                "win_count": int(t_item.get("win_count", 0) or 0),
                                                "status": str(
                                                    t_item.get("status")
                                                    or (
                                                        "IN_TRADE"
                                                        if int(t_item.get("open_positions", 0) or 0) > 0
                                                        else (t_item.get("last_skip_reason") or "READY")
                                                    )
                                                ),
                                            }
                                            for t_item in (pt_doc.get("tiers") or [])
                                            if isinstance(t_item, Mapping)
                                        ]
                                except Exception as exc_ctx:
                                    outer._last_routing_error = type(exc_ctx).__name__

                            def _epoch_guard_ask() -> None:
                                outer._assert_epoch_active(supplied_tok, auth_epoch, allow_device_scope=True)

                            safe_ctx = assert_safe_ai_catalog_payload(ctx_summary)
                            _epoch_guard_ask()
                            from cas_forex_revamp.operator.frontier_backends import DurableModelExecutionGate as _DMEG
                            ask_fn = outer._ai_model_registry.answer_explainer_question
                            ask_params = inspect.signature(ask_fn).parameters
                            has_ask_ep = "epoch_guard" in ask_params
                            guarded_ask_gate = (
                                None
                                if outer._model_gate is None
                                else (
                                    outer._model_gate
                                    if (has_ask_ep and isinstance(outer._model_gate, _DMEG))
                                    else _EpochGuardedModelGate(outer._model_gate, _epoch_guard_ask)
                                )
                            )
                            if "execution_gate" in ask_params:
                                ask_kw: dict[str, Any] = {
                                    "question": raw_q,
                                    "context_summary": safe_ctx,
                                    "audio_base64": raw_audio,
                                    "audio_mime_type": raw_mime,
                                    "execution_gate": guarded_ask_gate,
                                }
                                if has_ask_ep:
                                    ask_kw["epoch_guard"] = _epoch_guard_ask
                                ans_doc = ask_fn(**ask_kw)
                            else:
                                est_audio_bytes = (len(raw_audio.strip()) * 3) // 4 if isinstance(raw_audio, str) and has_audio else 0
                                est_input_bytes = len(raw_q.encode("utf-8")) + len(json.dumps(safe_ctx).encode("utf-8"))
                                exp_model = str(getattr(outer._ai_model_registry, "_explainer_model_slug", "gemini-4-neon"))
                                outer._authorize_auxiliary_gate_fallback(
                                    route_kind="transcription" if has_audio else "explainer",
                                    model_id=exp_model,
                                    max_output_tokens=1024,
                                    input_bytes=est_input_bytes,
                                    audio_bytes=est_audio_bytes,
                                )
                                _epoch_guard_ask()
                                ans_doc = ask_fn(
                                    question=raw_q,
                                    context_summary=safe_ctx,
                                    audio_base64=raw_audio,
                                    audio_mime_type=raw_mime,
                                )
                        self._write_json(HTTPStatus.OK, ans_doc)
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except OperatorUnavailable as exc:
                        self._write_json(
                            HTTPStatus.TOO_MANY_REQUESTS,
                            {"error": str(exc), "code": "MODEL_BUDGET_EXHAUSTED"},
                        )
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route == "/api/explainer-tts":
                    try:
                        body = self._read_json_body()
                        if type(body) is not dict or not isinstance(body.get("text"), str):
                            raise ContractError("text field required")
                        raw_voice = body.get("voice_name")
                        if raw_voice is None or (isinstance(raw_voice, str) and not raw_voice.strip()):
                            clean_voice = "Kore"
                        elif isinstance(raw_voice, str):
                            clean_voice = raw_voice.strip()
                        else:
                            raise ContractError("voice_name must be a string")
                        with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=False, allow_device_scope=True):
                            if outer._ai_model_registry is None:
                                tts_doc = {
                                    "schema": "cas-forex.explainer-tts/1",
                                    "ok": False,
                                    "fallback": "WEB_SPEECH",
                                    "reason": "AI_REGISTRY_NOT_ATTACHED",
                                }
                            else:
                                def _epoch_guard_tts() -> None:
                                    outer._assert_epoch_active(supplied_tok, auth_epoch, allow_device_scope=True)

                                _epoch_guard_tts()
                                from cas_forex_revamp.operator.frontier_backends import DurableModelExecutionGate as _DMEG
                                tts_fn = outer._ai_model_registry.synthesize_explainer_speech
                                tts_params = inspect.signature(tts_fn).parameters
                                has_tts_ep = "epoch_guard" in tts_params
                                guarded_tts_gate = (
                                    None
                                    if outer._model_gate is None
                                    else (
                                        outer._model_gate
                                        if (has_tts_ep and isinstance(outer._model_gate, _DMEG))
                                        else _EpochGuardedModelGate(outer._model_gate, _epoch_guard_tts)
                                    )
                                )
                                if "execution_gate" in tts_params:
                                    tts_kw: dict[str, Any] = {
                                        "voice_name": clean_voice,
                                        "execution_gate": guarded_tts_gate,
                                    }
                                    if has_tts_ep:
                                        tts_kw["epoch_guard"] = _epoch_guard_tts
                                    tts_doc = tts_fn(body["text"], **tts_kw)
                                else:
                                    tts_model = str(
                                        getattr(outer._ai_model_registry, "_explainer_tts_model_slug", "gemini-2.5-flash-preview-tts")
                                    )
                                    outer._authorize_auxiliary_gate_fallback(
                                        route_kind="tts",
                                        model_id=tts_model,
                                        max_output_tokens=2048,
                                        input_bytes=len(body["text"].encode("utf-8")),
                                    )
                                    _epoch_guard_tts()
                                    tts_doc = tts_fn(
                                        body["text"],
                                        voice_name=clean_voice,
                                    )
                        self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(tts_doc))
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except OperatorUnavailable as exc:
                        self._write_json(
                            HTTPStatus.TOO_MANY_REQUESTS,
                            {"error": str(exc), "code": "MODEL_BUDGET_EXHAUSTED"},
                        )
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if route in ("/api/ai-overseer-action", "/api/ai-trader-control"):
                    try:
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict or not isinstance(body.get("action"), str):
                            raise ContractError("action field required")
                        act = body["action"].strip().upper()
                        reason = str(body.get("reason") or f"Overseer {act}")
                        if act == "TOGGLE_FAST_SCOUT":
                            if outer._ai_model_registry is None:
                                raise ContractError("AI model registry not configured")
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                enabled = bool(body.get("enabled", not outer._ai_model_registry.fast_scout_enabled))
                                res = assert_safe_ai_catalog_payload(outer._ai_model_registry.set_fast_scout_enabled(enabled))
                            outer.notify_stream_updated()
                            self._write_json(HTTPStatus.OK, res)
                            return
                        if outer._autonomous_trader is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Autonomous AI trader not attached"})
                            return
                        hold_sync = act != "EMERGENCY_CLOSE_ALL"
                        with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=hold_sync):
                            if act == "PAUSE_NEW_RISK":
                                res = outer._autonomous_trader.pause_new_risk(reason=reason)
                            elif act == "RESUME_AUTONOMOUS":
                                res = outer._autonomous_trader.resume_autonomous(reason=reason)
                            elif act == "STOP_AUTOMATION":
                                res = outer._autonomous_trader.stop_automation(reason=reason)
                            elif act == "SET_RISK_GEAR":
                                gear_val = str(body.get("risk_gear") or "").strip().upper()
                                res = outer._autonomous_trader.set_risk_gear_mode(gear_val, reason=reason)
                            elif act == "ADVANCE_RECOVERY_SESSION":
                                res = outer._autonomous_trader.advance_recovery_session(reason=reason)
                            elif act == "SET_SESSION_CADENCE":
                                cad_val = str(body.get("session_cadence") or body.get("cadence") or "").strip().upper()
                                res = outer._autonomous_trader.set_session_cadence(cad_val, reason=reason)
                            elif act == "EMERGENCY_CLOSE_ALL":
                                res = outer._autonomous_trader.emergency_close_all(reason=reason)
                            elif act in ("REARM_DRAWDOWN", "UNLOCK_QUOTA_SESSION"):
                                req_id = str(body.get("owner_request_id") or "overseer-unlock-1")
                                rec_tok = body.get("recovery_token")
                                new_pk = body.get("new_peak_equity")
                                from decimal import Decimal as _Dec
                                pk_val = _Dec(str(new_pk)) if new_pk is not None else None
                                res = outer._autonomous_trader.rearm_and_unlock(
                                    owner_request_id=req_id,
                                    reason=reason,
                                    recovery_token=None if rec_tok is None else str(rec_tok),
                                    unlock_recovery_token=None if body.get("unlock_recovery_token") is None else str(body.get("unlock_recovery_token")),
                                    new_peak_equity=pk_val,
                                )
                            elif act == "UPDATE_QUOTA_TARGETS":
                                req_id = str(body.get("owner_request_id") or "overseer-quota-1")
                                rec_tok = body.get("recovery_token")
                                res = outer._autonomous_trader.quota_store.update_targets(
                                    soft_quota_usd=body.get("soft_quota_usd"),
                                    hard_quota_usd=body.get("hard_quota_usd"),
                                    daily_quota_pct=body.get("daily_quota_pct"),
                                    quota_mode=body.get("quota_mode"),
                                    owner_request_id=req_id,
                                    recovery_token=None if rec_tok is None else str(rec_tok),
                                )
                                res = assert_safe_ai_catalog_payload(res)
                            else:
                                raise ContractError(f"unsupported overseer action {act!r}")
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(res))
                    except _SessionRevokedError:
                        self._reject_unauthorized()
                    except Exception as exc:
                        code = HTTPStatus.FORBIDDEN if "OWNER_RECOVERY" in str(exc) else HTTPStatus.BAD_REQUEST
                        self._write_json(code, {"error": str(exc)})
                    return

                if outer._ui_service is None:
                    self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "ScopedUIService not attached"})
                    return
                dispatch = {
                    "/api/resolve-evidence": outer._ui_service.resolveEvidence,
                    "/api/prepare-control": outer._ui_service.prepareControl,
                    "/api/request-control": outer._ui_service.requestControl,
                    "/api/read-control": outer._ui_service.readControl,
                    "/api/prepare-close": outer._ui_service.prepareClose,
                    "/api/request-reviewed-close": outer._ui_service.requestReviewedClose,
                    "/api/read-command": lambda body: outer._ui_service.readCommand(body["command_id"]),
                }
                fn = dispatch.get(route)
                if fn is None:
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "Unknown RPC endpoint"})
                    return
                try:
                    body = self._read_json_body()
                    if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                        self._reject_unauthorized()
                        return
                    with outer._commit_lease(supplied_tok, auth_epoch):
                        result = fn(body)
                    self._write_json(HTTPStatus.OK, result)
                except _SessionRevokedError:
                    self._reject_unauthorized()
                except Exception as exc:
                    self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        class _EmergencyHandler(_Handler):
            _emergency_channel = True

        self._stop_event.clear()
        self._started_mono = time.monotonic()
        self._load_or_init_auth_token()
        self._httpd = _ExclusiveThreadingHTTPServer(
            (self._host, self._port),
            _Handler,
            ordinary_slots=self._max_ordinary_connections,
            peer_rate_limit_per_window=self._pre_auth_conn_rate_limit,
            global_rate_limit_per_window=self._global_pre_auth_rate_limit,
            mono_clock=self._mono,
            thread_name_prefix="cas-cockpit-worker",
        )
        self._httpd.request_queue_size = 32
        try:
            self._emergency_httpd = _EmergencyAdmissionHTTPServer(
                (self._host, self._emergency_port_cfg),
                _EmergencyHandler,
                emergency_slots=self._max_emergency_connections,
                max_pending_sockets=MAX_EMERGENCY_PENDING_SOCKETS,
                max_header_bytes=MAX_EMERGENCY_HEADER_BYTES,
                header_deadline_seconds=self._emergency_header_deadline_seconds,
                expected_host_fn=lambda: self.emergency_expected_host_header,
                expected_origin_fn=lambda: self.emergency_base_url,
                verify_owner_bearer_fn=self._verify_emergency_owner_bearer,
                on_auth_failure=self._record_auth_failure,
                on_pre_auth_timeout=self._record_pre_auth_timeout,
                unix_socket_path=self._emergency_unix_socket_cfg,
                mono_clock=self._mono,
                thread_name_prefix="cas-cockpit-emerg",
            )
            self._emergency_httpd.request_queue_size = 32
        except Exception:
            self._httpd.server_close()
            self._httpd = None
            raise
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="cas-forex-cockpit-http", daemon=True)
        self._emergency_thread = threading.Thread(
            target=self._emergency_httpd.serve_forever,
            name="cas-forex-cockpit-emerg-http",
            daemon=True,
        )
        self._thread.start()
        self._emergency_thread.start()
        return self.base_url

    def stop(self) -> None:
        self._stop_event.set()
        with self._auth_lock:
            self._auth_secret = None
            self._session_epoch = None
            self._pairing_codes.clear()
            self._device_sessions.clear()
            if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                self._ui_service.rotate_adapter_session()
        with self._sse_cond:
            self._sse_cond.notify_all()
        self._close_active_sockets()
        if self._emergency_httpd is not None:
            self._emergency_httpd.shutdown()
            self._emergency_httpd.server_close()
            self._emergency_httpd = None
        if self._emergency_thread is not None:
            self._emergency_thread.join(timeout=5.0)
            self._emergency_thread = None
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if self._phase8_bridge is not None and callable(getattr(self._phase8_bridge, "close", None)):
            try:
                self._phase8_bridge.close(timeout=2.0, drain=True)
            except Exception as exc_p8s:
                self._last_routing_error = type(exc_p8s).__name__
        if self._autonomous_trader is not None and callable(getattr(self._autonomous_trader, "close", None)):
            try:
                self._autonomous_trader.close(timeout=2.0, drain=True)
            except Exception as exc_trs:
                self._last_routing_error = type(exc_trs).__name__


def write_live_auth_ticket_bundle_atomic(
    ticket_path: str | Path,
    bundle: Mapping[str, Any],
) -> Path:
    """Write a LIVE auth ticket bundle relative to a verified owner-only parent fd without following symlinks (Finding [7])."""
    if not isinstance(ticket_path, (str, Path)):
        raise ContractError("LIVE auth ticket output path must be a string or Path")
    raw_txt = str(ticket_path).strip()
    if not raw_txt or "\x00" in raw_txt:
        raise ContractError("LIVE auth ticket output path must be non-empty without NUL bytes")
    expanded = Path(os.path.expanduser(raw_txt))
    if ".." in expanded.parts:
        raise ContractError(f"Refusing parent-traversal '..' in LIVE auth ticket output: {expanded}")
    if not expanded.is_absolute():
        expanded = Path(os.getcwd()) / expanded
    fname = expanded.name
    if not fname or fname in (".", ".."):
        raise ContractError(f"Invalid LIVE auth ticket output filename: {expanded}")

    parent_verified, dir_fd = open_verified_directory_fd(
        expanded.parent,
        create=False,
        label="LIVE auth ticket output parent",
    )
    try:
        payload_bytes = (json.dumps(dict(bundle), indent=2, sort_keys=True) + "\n").encode("utf-8")
        create_owner_only_file_atomic(
            parent_verified,
            fname,
            payload_bytes,
            dir_fd=dir_fd,
            replace_existing=True,
            label="LIVE auth ticket output",
        )
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return parent_verified / fname


def load_dotenv_file(path: str | Path) -> dict[str, str]:
    """Parse KEY=VALUE lines from an explicit CLI ``--env-file`` (never called automatically on import)."""
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ContractError(f"env file must be a regular non-symlink file: {resolved}")
    loaded: dict[str, str] = {}
    for lineno, raw_line in enumerate(resolved.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ContractError(f"{resolved.name}:{lineno}: expected KEY=VALUE line")
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        if not key.isascii() or not key.replace("_", "").isalnum():
            raise ContractError(f"{resolved.name}:{lineno}: invalid env var name {key!r}")
        loaded[key] = val
    return loaded


def _feed_option_b_demo_from_index_stream(
    option_b_demo: Any | None,
    idx_stream: Mapping[str, Any] | None,
) -> int:
    """Feed verified NAS100/US30/SPX500/XAUUSD quotes into Option B Paper Demo without calling AI inference."""
    if option_b_demo is None or not isinstance(idx_stream, Mapping):
        return 0
    markets = idx_stream.get("markets")
    if not isinstance(markets, list):
        return 0
    fed = 0
    for row in markets:
        if not isinstance(row, Mapping):
            continue
        pair = str(row.get("pair") or "").strip().upper()
        if pair not in ("NAS100", "US30", "SPX500", "XAUUSD"):
            continue
        raw_bid = row.get("bid")
        raw_ask = row.get("ask")
        if raw_bid is None or raw_ask is None:
            continue
        try:
            bid_d = Decimal(str(raw_bid))
            ask_d = Decimal(str(raw_ask))
            if bid_d <= Decimal("0") or ask_d < bid_d:
                continue
            option_b_demo.ingest_spot_quote(pair, bid_d, ask_d)
            fed += 1
        except Exception as exc_ob:
            print(f"[option-b] Quote feed skipped for {pair} ({type(exc_ob).__name__}).")
    return fed


def _poll_index_and_fx_once(
    *,
    router: Any,
    feed_client: Any,
    index_client: Any,
    trader: Any,
    autonomous_ai: bool,
    stream_lock: threading.Lock,
    latest_stream: list[dict[str, Any] | None],
    latest_public_index_stream: list[dict[str, Any] | None],
    latest_mt5_index_stream: list[dict[str, Any] | None],
    poll_mt5_cache: dict[str, dict[str, Any]],
    poll_log_throttle: dict[tuple[str, str, str], tuple[float, int]],
    poll_state: dict[str, Any],
    base_wait: float,
    now_mono: float,
    notify_updated: Callable[[], Any] | None = None,
    option_b_demo: Any | None = None,
) -> None:
    """Run one background poll tick keeping index reference refresh independent of FX errors.

    Phase A always refreshes MT5 + public US index snapshots so Kraken FX spread spikes
    (e.g. wide overnight USDJPY spreads) never freeze ``PUBLIC_US_INDEX_FEED`` past 60s.
    Phase B polls the 16-pair FX feed with independent exponential backoff up to 60s.
    """
    with stream_lock:
        prev_mt5_idx = latest_mt5_index_stream[0]
        prev_pub_idx = latest_public_index_stream[0]
    mt5_idx_snap: dict[str, Any] | None = None
    try:
        mt5_idx_snap, _ = _build_mt5_index_snapshot_from_router(
            router,
            prev_stream=prev_mt5_idx,
            poll_cache=poll_mt5_cache,
            log_throttle=poll_log_throttle,
        )
    except Exception as exc_mt5_idx:
        if type(exc_mt5_idx).__name__ in ("LiveBrokerEndpointForbiddenError", "LiveAuthorizationError"):
            raise
        print(f"[feed] MT5 index poll skipped ({type(exc_mt5_idx).__name__}).")

    pub_idx_snap = prev_pub_idx
    pub_idx_updated = False
    if index_client is not None:
        try:
            pub_idx_snap = stamp_public_index_provenance(index_client.fetch_index_stream())
            pub_idx_updated = True
        except Exception as exc_idx:
            print(f"[feed] Index poll skipped ({type(exc_idx).__name__}).")

    if pub_idx_updated or mt5_idx_snap is not None:
        with stream_lock:
            if pub_idx_updated:
                latest_public_index_stream[0] = pub_idx_snap
            if mt5_idx_snap is not None:
                latest_mt5_index_stream[0] = mt5_idx_snap
        if option_b_demo is not None:
            _feed_option_b_demo_from_index_stream(
                option_b_demo,
                mt5_idx_snap if mt5_idx_snap is not None else pub_idx_snap,
            )
        if notify_updated is not None:
            notify_updated()

    # End of Phase A index refresh; Phase B polls 16-pair FX stream below
    if feed_client is not None and now_mono >= float(poll_state.get("next_fx_poll_mono", 0.0)):
        try:
            env_stream = feed_client.fetch_market_stream().to_wire_dict()
            with stream_lock:
                latest_stream[0] = env_stream
                cur_mt5_idx = latest_mt5_index_stream[0]
                cur_pub_idx = latest_public_index_stream[0]
            idx_stream = cur_mt5_idx if cur_mt5_idx is not None else cur_pub_idx
            if autonomous_ai:
                try:
                    trader.run_cycle(env_stream, index_stream=idx_stream)
                except Exception as exc_ai:
                    msg_ai = " ".join(str(exc_ai).split())[:140]
                    print(f"[ai] Standard cycle skipped ({type(exc_ai).__name__}: {msg_ai}).")
            if notify_updated is not None:
                notify_updated()
            poll_state["consecutive_feed_errors"] = 0
            poll_state["next_fx_poll_mono"] = 0.0
        except Exception as exc:
            errs = int(poll_state.get("consecutive_feed_errors", 0)) + 1
            poll_state["consecutive_feed_errors"] = errs
            fx_backoff = max(base_wait, min(60.0, base_wait * (2 ** min(errs - 1, 2))))
            poll_state["next_fx_poll_mono"] = now_mono + fx_backoff
            print(f"[feed] Poll skipped ({type(exc).__name__}); keeping last verified snapshot.")


def _run_fast_tick_iteration(
    *,
    router: Any,
    trader: Any,
    parallel_tiers: Any | None = None,
    stream_lock: threading.Lock,
    latest_mt5_index_stream: list[dict[str, Any] | None],
    fast_poll_cache: dict[str, dict[str, Any]],
    fast_log_throttle: dict[tuple[str, str, str], tuple[float, int]],
    fast_state: dict[str, Any],
    idle_scan_interval_s: float = DEFAULT_FAST_ENTRY_SCAN_INTERVAL_SECONDS,
    open_scan_interval_s: float = DEFAULT_FAST_ENTRY_SCAN_OPEN_INTERVAL_SECONDS,
    error_log_cooldown_s: float = DEFAULT_FAST_ERROR_LOG_COOLDOWN_SECONDS,
    now_mono: float | None = None,
    mono_clock: Callable[[], float] = time.monotonic,
    notify_updated: Callable[[], Any] | None = None,
    log_fn: Callable[[str], None] = print,
) -> None:
    """Run one 50ms stop-protection iteration while throttling entry-scan AI inference calls."""
    try:
        with stream_lock:
            prev_idx = latest_mt5_index_stream[0]
        mt5_idx_snap, mt5_q = _build_mt5_index_snapshot_from_router(
            router,
            prev_stream=prev_idx,
            poll_cache=fast_poll_cache,
            log_throttle=fast_log_throttle,
            mono_clock=mono_clock,
        )
        if mt5_q:
            if mt5_idx_snap is not None:
                with stream_lock:
                    latest_mt5_index_stream[0] = mt5_idx_snap
            has_open = (
                trader.has_open_positions_fast()
                if callable(getattr(trader, "has_open_positions_fast", None))
                else True
            )
            cur_m = float(now_mono) if now_mono is not None else mono_clock()
            last_cycle_m = fast_state.get("last_fast_cycle_mono")
            scan_interval = open_scan_interval_s if has_open else idle_scan_interval_s
            due = last_cycle_m is None or (cur_m - float(last_cycle_m)) >= scan_interval
            if due and trader._inference_lock.acquire(blocking=False):
                try:
                    trader.run_fast_tick_cycle(mt5_quotes=mt5_q)
                finally:
                    fast_state["last_fast_cycle_mono"] = mono_clock()
                    trader._inference_lock.release()
            elif has_open:
                # Non-blocking 50ms stop protection even between entry scans or during HTTP inference
                trader.evaluate_fast_protection(quotes=mt5_q)
                if parallel_tiers is not None:
                    parallel_tiers.process_tick(quotes=mt5_q, signal=None)
            if notify_updated is not None:
                notify_updated()
    except Exception as exc_ft:
        cur_err_m = float(now_mono) if now_mono is not None else mono_clock()
        fast_state["last_fast_cycle_mono"] = cur_err_m
        msg_ft = " ".join(str(exc_ft).split())[:140]
        err_key = (type(exc_ft).__name__, msg_ft)
        err_map: dict[tuple[str, str], tuple[float, int]] = fast_state.setdefault("err_throttle", {})
        prev_emit, suppressed = err_map.get(err_key, (None, 0))
        if prev_emit is None or (cur_err_m - prev_emit) >= error_log_cooldown_s:
            sup_note = f" (suppressed {suppressed} repeated)" if suppressed > 0 else ""
            err_map[err_key] = (cur_err_m, 0)
            if len(err_map) > 128:
                oldest_ek = next(iter(err_map))
                err_map.pop(oldest_ek, None)
            log_fn(f"[ai-fast] Fast tick skipped ({type(exc_ft).__name__}: {msg_ft}){sup_note}.")
        else:
            err_map[err_key] = (prev_emit, suppressed + 1)


def run_cockpit_cli(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    repo_root: str | Path | None = None,
) -> int:
    """Explicit 1-command launcher for LoopbackCockpitServer + DualShieldBrokerRouter (DEMO or two-key LIVE)."""
    ap = argparse.ArgumentParser(description="CAS Forex Revamp Cockpit & Dual-Shield Broker Launcher")
    ap.add_argument("--env-file", type=Path, default=None, help="Optional KEY=VALUE file with CAS_FOREX_* settings")
    ap.add_argument("--host", default="127.0.0.1", help="Loopback bind IP (127.0.0.1 or ::1)")
    ap.add_argument("--port", type=int, default=8787, help="Loopback port (0 picks an ephemeral port)")
    ap.add_argument("--emergency-port", type=int, default=0, help="Dedicated owner-only loopback emergency port (0 picks ephemeral)")
    ap.add_argument("--poll-seconds", type=int, default=15, help="Live 18-market poll interval in seconds (0=disable)")
    ap.add_argument("--fast-tick-ms", type=int, default=50, help="Direct MT5 fast-tick interval in ms for NAS100/US30 (0=disable)")
    ap.add_argument("--no-autonomous-ai", dest="autonomous_ai", action="store_false", default=True, help="Disable continuous autonomous AI trading loop")
    ap.add_argument("--state-dir", type=Path, default=None, help="Owner-only (0o700) persistent SQLite WAL state directory")
    ap.add_argument("--activate-brokers", action="store_true", help="Attempt live/demo connection to configured brokers")
    ap.add_argument("--print-check-only", action="store_true", help="Validate config/routing/AI catalog, print JSON, and exit")
    ap.add_argument("--mint-recovery-token", action="store_true", help="Mint a single-use OwnerRecoveryVerifier token and exit")
    ap.add_argument("--recovery-scope", default="UNLOCK_QUOTA_SESSION", help="Scope for --mint-recovery-token")
    ap.add_argument("--target-ref", "--recovery-target-ref", dest="target_ref", default="*", help="Exact target_ref / intent_sha256 for --mint-recovery-token (required for TREASURY_SWEEP)")
    ap.add_argument("--recovery-ttl-seconds", type=int, default=900, help="TTL for --mint-recovery-token (30..900s)")
    ap.add_argument("--mint-live-auth-ticket", action="store_true", help="Mint signed LiveAuthorizationTicket bundle from env and exit")
    ap.add_argument("--live-ticket-ttl-seconds", type=int, default=3600, help="TTL for --mint-live-auth-ticket (60..86400s)")
    args = ap.parse_args(argv)
    if args.poll_seconds < 0 or args.poll_seconds > 3600:
        raise ContractError("--poll-seconds must be in 0..3600")
    if args.fast_tick_ms < 0 or args.fast_tick_ms > 5000:
        raise ContractError("--fast-tick-ms must be in 0..5000")

    root = Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[3]
    merged: dict[str, str] = dict(os.environ if environ is None else environ)
    if args.env_file is not None:
        merged.update(load_dotenv_file(args.env_file))

    from cas_forex_revamp.composition.autonomous_trader import (
        AutonomousAiTrader,
        DEFAULT_LIVE_AI_INFERENCE_COOLDOWN_SECONDS,
        ENV_AI_INFERENCE_COOLDOWN_SECONDS,
        ENV_RISK_GEAR_MODE,
        MAX_AI_INFERENCE_COOLDOWN_SECONDS,
    )
    from cas_forex_revamp.composition.state_store import initialize_shared_runtime_state
    from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
    from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
    from cas_forex_revamp.venue.live_auth_ticket import LiveAuthorizationError
    from cas_forex_revamp.venue.mt5_broker_bridge import LiveBrokerEndpointForbiddenError
    from cas_forex_revamp.venue.live_market_stream import (
        EXPANDED_MARKETS,
        ExpandedPublicLiveFxFeedClient,
        PublicUsIndexFeedClient,
    )
    from cas_forex_revamp.venue.mt5_broker_bridge import (
        BROKER_HUGOSWAY_MT5,
        BROKER_LHFX_MT5,
        BROKER_OANDA_LIVE,
        ENV_HUGOSWAY_MT5_LOGIN,
        ENV_HUGOSWAY_MT5_SERVER,
        ENV_LHFX_MT5_LOGIN,
        ENV_LHFX_MT5_SERVER,
        resolve_mt5_spool_dir,
    )

    tmp_state_holder: tempfile.TemporaryDirectory[str] | None = None
    explicit_sdir = args.state_dir
    if explicit_sdir is None and not str(merged.get("CAS_FOREX_STATE_DIR", "")).strip() and args.print_check_only:
        tmp_state_holder = tempfile.TemporaryDirectory(prefix="cas_fx_check_state_")
        explicit_sdir = Path(tmp_state_holder.name)

    runtime_state = initialize_shared_runtime_state(merged, explicit_state_dir=explicit_sdir)
    if args.mint_recovery_token:
        tok = runtime_state.owner_recovery.mint_token(
            action_scope=args.recovery_scope,
            target_ref=args.target_ref,
            ttl_seconds=args.recovery_ttl_seconds,
        )
        print(json.dumps({
            "status": "RECOVERY_TOKEN_MINTED",
            "scope": args.recovery_scope.upper(),
            "target_ref": str(args.target_ref).strip() or "*",
            "recovery_token": tok,
        }))
        return 0
    if args.mint_live_auth_ticket:
        from cas_forex_revamp.venue.live_auth_ticket import (
            ENV_LIVE_AUTH_KEY_FILE,
            ENV_LIVE_AUTH_TICKET_FILE,
            mint_live_authorization_bundle,
            provision_live_auth_key,
        )
        key_p = Path(merged.get(ENV_LIVE_AUTH_KEY_FILE) or (runtime_state.state_dir / ".live_auth.key"))
        provision_live_auth_key(key_p)
        targets: list[tuple[str, str | int, str]] = []
        if merged.get(ENV_HUGOSWAY_MT5_LOGIN):
            targets.append((BROKER_HUGOSWAY_MT5, merged[ENV_HUGOSWAY_MT5_LOGIN], merged.get(ENV_HUGOSWAY_MT5_SERVER, "Hugo PRO5")))
        if merged.get(ENV_LHFX_MT5_LOGIN):
            targets.append((BROKER_LHFX_MT5, merged[ENV_LHFX_MT5_LOGIN], merged.get(ENV_LHFX_MT5_SERVER, "LHFXSA-Trade")))
        if merged.get("CAS_FOREX_OANDA_LIVE_ACCOUNT_ID"):
            targets.append((BROKER_OANDA_LIVE, merged["CAS_FOREX_OANDA_LIVE_ACCOUNT_ID"], "api-fxtrade.oanda.com"))
        bundle = mint_live_authorization_bundle(key_file=key_p, targets=targets, ttl_seconds=args.live_ticket_ttl_seconds)
        t_out_raw = merged.get(ENV_LIVE_AUTH_TICKET_FILE) or (runtime_state.state_dir / "live_auth_bundle.json")
        t_out = write_live_auth_ticket_bundle_atomic(t_out_raw, bundle)
        print(json.dumps({"status": "LIVE_TICKET_MINTED", "key_file": str(key_p), "ticket_file": str(t_out), "brokers": [t[0] for t in targets]}))
        return 0

    gate = runtime_state.valve_gate
    from cas_forex_revamp.contracts import parse_decimal as _parse_dec
    stream_lock = threading.Lock()
    latest_public_index_stream: list[dict[str, Any] | None] = [None]
    latest_mt5_index_stream: list[dict[str, Any] | None] = [None]

    def _read_index_ref(symbols: Any) -> dict[str, dict[str, Any]]:
        with stream_lock:
            pub_doc = latest_public_index_stream[0]
        return build_public_index_reference_map(pub_doc, symbols)

    router = DualShieldBrokerRouter(
        environ=merged,
        valve_gate=gate,
        peak_equity_store=runtime_state.peak_equity_store,
        index_reference_source=_read_index_ref,
        oanda_mutation_journal=runtime_state.oanda_mutation_journal,
        mt5_mutation_journal=runtime_state.mt5_mutation_journal,
    )
    merged_ai = dict(merged)
    if not str(merged_ai.get("CAS_FOREX_THINKING_DEPTH", "")).strip():
        merged_ai["CAS_FOREX_THINKING_DEPTH"] = runtime_state.initial_thinking_depth
    registry = FrontierModelRegistry(environ=merged_ai)

    def _persist_thinking_depth(mode: str) -> None:
        td_tmp = runtime_state.thinking_depth_path.with_suffix(".tmp")
        td_tmp.write_text(json.dumps({"thinking_depth": mode}) + "\n", encoding="utf-8")
        os.replace(td_tmp, runtime_state.thinking_depth_path)

    registry.bind_thinking_depth_persister(_persist_thinking_depth)
    quota_store = runtime_state.quota_store
    from decimal import Decimal
    raw_init_cap_cli = str(merged.get("CAS_FOREX_INITIAL_CAPITAL_USD", "")).strip()
    cli_init_cap = Decimal(raw_init_cap_cli) if raw_init_cap_cli else None
    if (
        cli_init_cap is not None
        and runtime_state.profit_vault is not None
        and runtime_state.profit_vault.configured_initial_capital_usd() is None
    ):
        runtime_state.profit_vault.set_config(initial_capital_usd=cli_init_cap)
    aggression_dial = AggressionDialStore(
        runtime_state.state_dir / "aggression_dial.sqlite3",
        scope_id="dual-shield-barbell",
    )
    if runtime_state.parallel_tiers is not None and callable(
        getattr(runtime_state.parallel_tiers, "bind_aggression_dial", None)
    ):
        runtime_state.parallel_tiers.bind_aggression_dial(aggression_dial)
    ai_cooldown_s = DEFAULT_LIVE_AI_INFERENCE_COOLDOWN_SECONDS
    if ENV_AI_INFERENCE_COOLDOWN_SECONDS in merged:
        raw_cd = str(merged[ENV_AI_INFERENCE_COOLDOWN_SECONDS]).strip()
        if not raw_cd:
            raise ContractError(f"Invalid empty {ENV_AI_INFERENCE_COOLDOWN_SECONDS}")
        try:
            ai_cooldown_s = float(raw_cd)
        except ValueError as exc_cd:
            raise ContractError(f"Invalid {ENV_AI_INFERENCE_COOLDOWN_SECONDS}={raw_cd!r}") from exc_cd
        if (
            not math.isfinite(ai_cooldown_s)
            or ai_cooldown_s < 0.0
            or ai_cooldown_s > MAX_AI_INFERENCE_COOLDOWN_SECONDS
        ):
            raise ContractError(
                f"Invalid {ENV_AI_INFERENCE_COOLDOWN_SECONDS}={raw_cd!r}: must be in 0..{int(MAX_AI_INFERENCE_COOLDOWN_SECONDS)}"
            )
    is_live_boot = (
        str(getattr(router, "execution_mode", "DEMO")).strip().upper() != "DEMO"
    ) or bool(getattr(router, "_live_armed", False))
    init_dhg_env = resolve_demo_high_growth_profile_from_environ(
        merged,
        execution_mode=router.execution_mode,
        live_trading_armed=is_live_boot,
        live_trading_locked=not is_live_boot,
    )
    demo_high_growth_store = DemoHighGrowthProfileStore(
        runtime_state.state_dir / "demo_high_growth_profile.json",
        initial_profile=init_dhg_env,
        execution_mode=router.execution_mode,
        live_trading_armed=is_live_boot,
        live_trading_locked=not is_live_boot,
    )
    active_dhg = demo_high_growth_store.profile()
    if active_dhg.enabled:
        router.set_demo_high_growth_profile(active_dhg)
        if callable(getattr(gate, "set_demo_high_growth_profile", None)):
            gate.set_demo_high_growth_profile(
                active_dhg,
                execution_mode=router.execution_mode,
                live_trading_armed=is_live_boot,
                live_trading_locked=not is_live_boot,
            )
        if runtime_state.parallel_tiers is not None and callable(
            getattr(runtime_state.parallel_tiers, "set_demo_high_growth_profile", None)
        ):
            runtime_state.parallel_tiers.set_demo_high_growth_profile(
                active_dhg,
                execution_mode=router.execution_mode,
                live_trading_armed=is_live_boot,
                live_trading_locked=not is_live_boot,
            )
    trader = AutonomousAiTrader(
        router=router,
        model_registry=registry,
        valve_gate=gate,
        quota_store=quota_store,
        peak_equity_store=runtime_state.peak_equity_store,
        owner_verifier=runtime_state.owner_recovery,
        execution_gate=runtime_state.model_gate,
        fast_tick_ms=args.fast_tick_ms,
        profit_vault=runtime_state.profit_vault,
        parallel_tiers=runtime_state.parallel_tiers,
        aggression_dial=aggression_dial,
        risk_gear_mode=merged.get(ENV_RISK_GEAR_MODE),
        risk_gear_path=runtime_state.state_dir / "risk_gear.json",
        ai_inference_cooldown_seconds=ai_cooldown_s,
        initial_capital_usd=cli_init_cap,
        demo_high_growth=active_dhg,
        state_dir=runtime_state.state_dir,
    )
    if not args.autonomous_ai:
        trader.stop_automation(reason="CLI launched with --no-autonomous-ai")
    if args.activate_brokers:
        router.activate_all()
        if callable(getattr(router, "reconcile_unknown_mutations", None)) and router.has_any_unresolved_mutation():
            try:
                rec_startup = router.reconcile_unknown_mutations()
                print(
                    f"[reconcile] Startup reconciliation: checked={rec_startup.get('checked', 0)} "
                    f"resolved={rec_startup.get('resolved', 0)} remaining={rec_startup.get('remaining_unknown', 0)}"
                )
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                raise
            except Exception as exc_rec:
                print(f"[reconcile] Startup reconciliation skipped ({type(exc_rec).__name__}).")

    routing_summary = safe_broker_routing_payload(router.routing_snapshot())
    cat_snap = assert_safe_ai_catalog_payload(registry.catalog_snapshot())
    routing_summary.update({
        "markets_supported": len(EXPANDED_MARKETS),
        "state_directory": str(runtime_state.state_dir),
        "portable_mt5_spool": resolve_mt5_spool_dir(merged),
        "ai_model_selected": cat_snap["active_model_id"],
        "ai_model_status": cat_snap["active_status"],
        "ai_catalog_order": [m["model_id"] for m in cat_snap["models"]],
        "fast_scout_enabled": cat_snap["fast_scout_enabled"],
        "fast_tick_ms": int(args.fast_tick_ms),
        "autonomous_trader_ready": bool(args.autonomous_ai),
        "aggression_dial_master_bps": int(aggression_dial.snapshot()["master_risk_bps"]),
        "daily_quota": assert_safe_ai_catalog_payload(quota_store.snapshot()),
    })
    safe_broker_routing_payload(routing_summary)
    if args.print_check_only:
        print(json.dumps(routing_summary, indent=2))
        trader.close()
        if tmp_state_holder is not None:
            tmp_state_holder.cleanup()
        return 0

    fixture_path = root / "docs" / "contracts" / "initial-market-stream.json"
    latest_stream: list[dict[str, Any] | None] = [
        json.loads(fixture_path.read_text(encoding="utf-8")) if fixture_path.is_file() else None
    ]
    feed_client = ExpandedPublicLiveFxFeedClient() if args.poll_seconds > 0 else None
    index_client = PublicUsIndexFeedClient() if args.poll_seconds > 0 else None
    if feed_client is not None:
        try:
            env_stream = feed_client.fetch_market_stream()
            latest_stream[0] = env_stream.to_wire_dict()
        except Exception as exc:
            print(f"[feed] Initial live quote fetch skipped ({type(exc).__name__}); using sealed fixture until next poll.")
    if index_client is not None:
        try:
            latest_public_index_stream[0] = stamp_public_index_provenance(index_client.fetch_index_stream())
        except Exception as exc:
            print(f"[feed] Initial index fetch skipped ({type(exc).__name__}); awaiting MT5 ticks.")
    mt5_idx_init, _ = _build_mt5_index_snapshot_from_router(router, prev_stream=latest_mt5_index_stream[0])
    if mt5_idx_init is not None:
        latest_mt5_index_stream[0] = mt5_idx_init

    def _read_stream() -> dict[str, Any] | None:
        with stream_lock:
            return latest_stream[0]

    def _read_index_stream() -> dict[str, Any] | None:
        with stream_lock:
            return latest_mt5_index_stream[0] if latest_mt5_index_stream[0] is not None else latest_public_index_stream[0]

    if callable(getattr(registry, "bind_execution_gate", None)):
        registry.bind_execution_gate(runtime_state.model_gate)
    option_b_demo = OptionBPaperDemoRunner(
        db_path=runtime_state.state_dir / "option_b_paper_demo.sqlite3",
        valve_gate=gate,
        demo_high_growth=active_dhg,
    )
    trader.bind_option_b_demo(option_b_demo)
    if active_dhg.enabled:
        trader.set_demo_high_growth_profile(active_dhg)
    _feed_option_b_demo_from_index_stream(option_b_demo, _read_index_stream())
    srv = LoopbackCockpitServer(
        repo_root=root,
        host=args.host,
        port=args.port,
        emergency_port=args.emergency_port,
        market_stream_reader=_read_stream,
        broker_router_reader=router.routing_snapshot,
        ai_model_registry=registry,
        autonomous_trader=trader,
        index_stream_reader=_read_index_stream,
        profit_vault=runtime_state.profit_vault,
        parallel_tiers=runtime_state.parallel_tiers,
        aggression_dial=aggression_dial,
        option_b_demo=option_b_demo,
        demo_high_growth_store=demo_high_growth_store,
        owner_recovery=runtime_state.owner_recovery,
        model_execution_gate=runtime_state.model_gate,
        token_file=str(merged.get("CAS_FOREX_COCKPIT_TOKEN_FILE", "")).strip() or None,
        public_origin=str(merged.get("CAS_FOREX_PUBLIC_ORIGIN", "")).strip() or None,
    )
    srv.start()
    stop_flag = threading.Event()

    def _poll_loop() -> None:
        poll_mt5_cache: dict[str, dict[str, Any]] = {}
        poll_log_throttle: dict[tuple[str, str, str], tuple[float, int]] = {}
        base_wait = float(args.poll_seconds)
        poll_state: dict[str, Any] = {"consecutive_feed_errors": 0, "next_fx_poll_mono": 0.0}
        last_reconcile_mono = 0.0
        while not stop_flag.wait(base_wait):
            if callable(getattr(router, "reconcile_unknown_mutations", None)) and router.has_any_unresolved_mutation():
                now_rec_mono = time.monotonic()
                if (now_rec_mono - last_reconcile_mono) >= 30.0:
                    last_reconcile_mono = now_rec_mono
                    try:
                        rec_bg = router.reconcile_unknown_mutations()
                        if int(rec_bg.get("resolved", 0)) > 0:
                            print(
                                f"[reconcile] Periodic reconciliation: resolved={rec_bg.get('resolved', 0)} "
                                f"remaining={rec_bg.get('remaining_unknown', 0)}"
                            )
                            srv.notify_stream_updated()
                    except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                        raise
                    except Exception as exc_rec_bg:
                        print(f"[reconcile] Periodic reconciliation skipped ({type(exc_rec_bg).__name__}).")
            if callable(getattr(router, "try_reconnect_oanda", None)):
                try:
                    if router.try_reconnect_oanda():
                        srv.notify_stream_updated()
                except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                    raise
                except Exception as exc_or:
                    print(f"[broker] OANDA reconnect check skipped ({type(exc_or).__name__}).")
            if feed_client is None and index_client is None:
                break
            _poll_index_and_fx_once(
                router=router,
                feed_client=feed_client,
                index_client=index_client,
                trader=trader,
                autonomous_ai=bool(args.autonomous_ai),
                stream_lock=stream_lock,
                latest_stream=latest_stream,
                latest_public_index_stream=latest_public_index_stream,
                latest_mt5_index_stream=latest_mt5_index_stream,
                poll_mt5_cache=poll_mt5_cache,
                poll_log_throttle=poll_log_throttle,
                poll_state=poll_state,
                base_wait=base_wait,
                now_mono=time.monotonic(),
                notify_updated=srv.notify_stream_updated,
                option_b_demo=option_b_demo,
            )

    def _fast_tick_loop() -> None:
        interval = max(0.05, float(args.fast_tick_ms) / 1000.0)
        fast_poll_cache: dict[str, dict[str, Any]] = {}
        fast_log_throttle: dict[tuple[str, str, str], tuple[float, int]] = {}
        fast_state: dict[str, Any] = {}
        while not stop_flag.wait(interval):
            if not args.autonomous_ai:
                continue
            _run_fast_tick_iteration(
                router=router,
                trader=trader,
                parallel_tiers=runtime_state.parallel_tiers,
                stream_lock=stream_lock,
                latest_mt5_index_stream=latest_mt5_index_stream,
                fast_poll_cache=fast_poll_cache,
                fast_log_throttle=fast_log_throttle,
                fast_state=fast_state,
                notify_updated=srv.notify_stream_updated,
            )

    poller = threading.Thread(target=_poll_loop, name="cas-forex-feed-poll", daemon=True)
    fast_poller = threading.Thread(target=_fast_tick_loop, name="cas-forex-mt5-50ms", daemon=True)
    # SAFETY INVARIANT: Start 50ms stop-protection thread FIRST with zero ledger I/O ahead of it!
    if args.fast_tick_ms > 0 and args.autonomous_ai and router.venues:
        fast_poller.start()
    if args.poll_seconds > 0 and feed_client is not None:
        poller.start()
    if args.autonomous_ai and runtime_state.profit_vault is not None:
        threading.Thread(
            target=lambda: trader._attempt_startup_vault_sync_post_protection(trader._now()),
            name="cas-forex-boot-vault-sync",
            daemon=True,
        ).start()

    print(f"CAS Forex Cockpit Execution Mode : {router.execution_mode} (live_armed={routing_summary['live_trading_armed']})")
    for row in routing_summary["chain"]:
        print(f"  [{row['priority']}] {row['broker_id']} ({row['server']}) configured={row['configured']} status={row['status']}")
    create_owner_only_file_atomic(
        runtime_state.state_dir,
        "cockpit_emergency.json",
        (json.dumps({"emergency_base_url": srv.emergency_base_url, "base_url": srv.base_url}) + "\n").encode("utf-8"),
        replace_existing=True,
        label="cockpit emergency endpoint file",
    )
    print(f"Open Cockpit Pairing URL (120s)  : {srv.bootstrap_url}")
    print(f"Local Owner Emergency Channel    : {srv.emergency_base_url}")
    print("Press Ctrl+C to stop cleanly.")
    try:
        while not stop_flag.wait(1.0):
            continue
    except KeyboardInterrupt:
        print("\nShutting down CAS Forex Cockpit...")
    finally:
        stop_flag.set()
        srv.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cockpit_cli())
