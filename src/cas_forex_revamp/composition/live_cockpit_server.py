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
from collections.abc import Callable, Mapping
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
from cas_forex_revamp.valve.aggression_dial import (
    AggressionDialError,
    AggressionDialStore,
    HIGH_RISK_MIN_BPS,
    HighRiskConfirmationRequiredError,
    OwnerKeyRequiredError,
)


class _SessionRevokedError(Exception):
    """Raised when a session epoch is revoked prior to commit."""


_COCKPIT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_PAIR_CODE_RE = re.compile(r"^pair-[A-Za-z0-9_-]{24,80}$")
MAX_HTTP_HEADER_BYTES = 16384
MAX_HTTP_HEADER_COUNT = 64

SESSION_SCOPE_OWNER_FULL = "OWNER_FULL_CONTROL"
SESSION_SCOPE_DEVICE_READ_EXPLAINER = "DEVICE_READ_AND_EXPLAINER"
PAIR_CODE_TTL_SECONDS = 120
DEVICE_SESSION_TTL_SECONDS = 43200
MAX_ACTIVE_PAIRING_CODES = 8
MAX_ACTIVE_DEVICE_SESSIONS = 16
PAIR_EXCHANGE_WINDOW_SECONDS = 60.0
MAX_PAIR_EXCHANGE_ATTEMPTS_PER_WINDOW = 10

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
            self._sock.settimeout(min(rem, 0.10))
            if has_peek:
                try:
                    peeked = self._raw.peek(1)
                except (TimeoutError, socket.timeout):
                    if self._mono() >= self._deadline:
                        self.header_deadline_exceeded = True
                        raise TimeoutError("absolute pre-auth HTTP deadline exceeded") from None
                    continue
                if not peeked:
                    break
                nl_pos = peeked.find(b"\n")
                take = min(max_more, nl_pos + 1 if nl_pos >= 0 else len(peeked))
                part = self._raw.read(take)
            else:
                try:
                    part = self._raw.readline(max_more)
                except (TimeoutError, socket.timeout):
                    if self._mono() >= self._deadline:
                        self.header_deadline_exceeded = True
                        raise TimeoutError("absolute pre-auth HTTP deadline exceeded") from None
                    continue
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


class _ExclusiveThreadingHTTPServer(HTTPServer):
    """Bounded loopback HTTP server preventing SO_REUSEADDR hijacking and pre-auth slot exhaustion (Findings [8], [14])."""

    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        ordinary_slots: int = 16,
        peer_rate_limit_per_window: int = 256,
        peer_rate_window_seconds: float = 10.0,
        thread_name_prefix: str = "cas-cockpit-worker",
    ) -> None:
        self._ordinary_slots = max(1, int(ordinary_slots))
        self._ordinary_conn_sem = threading.BoundedSemaphore(self._ordinary_slots)
        self._peer_rate_limit = max(1, int(peer_rate_limit_per_window))
        self._peer_rate_window = max(0.5, float(peer_rate_window_seconds))
        self._slot_lock = threading.Lock()
        self._peer_conn_times: dict[str, list[float]] = {}
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
        peer_ip = str(client_address[0]) if isinstance(client_address, tuple) and client_address else "unknown"
        now_m = time.monotonic()
        with self._slot_lock:
            cutoff = now_m - self._peer_rate_window
            hist = [t for t in self._peer_conn_times.get(peer_ip, ()) if t >= cutoff]
            if len(hist) >= self._peer_rate_limit:
                self._peer_conn_times[peer_ip] = hist
                rate_exceeded = True
            else:
                hist.append(now_m)
                self._peer_conn_times[peer_ip] = hist
                rate_exceeded = False
        if rate_exceeded:
            self._reject_raw_socket(
                request,
                b"HTTP/1.1 429 Too Many Requests",
                b'{"error": "Pre-auth connection rate limit exceeded"}\n',
            )
            return

        # Finding [14]: unauthenticated sockets NEVER acquire emergency capacity!
        if not self._ordinary_conn_sem.acquire(blocking=False):
            self._reject_raw_socket(
                request,
                b"HTTP/1.1 503 Service Unavailable",
                b'{"error": "Cockpit connection pool full"}\n',
            )
            return

        sem = self._ordinary_conn_sem
        with self._slot_lock:
            self._active_workers += 1
            if self._active_workers > self._peak_workers:
                self._peak_workers = self._active_workers

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


def _roll_mt5_index_bars(prev_bars: Any, bucket_iso: str, mid_px: Any, _dec_txt: Any, limit: int = 48) -> list[dict[str, Any]]:
    """Append or update the latest OHLC candle bucket for MT5-driven index streams."""
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
        o_dec = Decimal(str(bars[-1]["c"])) if bars else mid_px
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
) -> tuple[dict[str, Any] | None, dict[str, tuple[Any, Any]]]:
    """Read NAS100/US30 quotes from active MT5 bridge transports and format an index stream payload."""
    from datetime import datetime, timezone
    from cas_forex_revamp.contracts import decimal_text as _dec_txt
    from cas_forex_revamp.venue.live_market_stream import INDEX_INSTRUMENTS

    mt5_q: dict[str, tuple[Any, Any]] = {}
    for broker_id, venue in router.venues.items():
        if hasattr(venue, "_transport") and venue.account is not None:
            got_tick = False
            for sym in INDEX_INSTRUMENTS:
                try:
                    tk = venue._transport.symbol_tick(sym)
                    mt5_q[sym] = (tk.bid, tk.ask)
                    got_tick = True
                except (ContractError, OSError) as exc_sym:
                    print(f"[ai-fast] Tick skipped for {sym}: {type(exc_sym).__name__}")
            if got_tick and hasattr(router, "_status") and router._status.get(broker_id) == "DISCONNECTED":
                router._status[broker_id] = "ACTIVE"
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
    native_cache: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for venue in router.venues.values():
        tr = getattr(venue, "_transport", None)
        rc_fn = getattr(tr, "read_index_candles", None)
        if callable(rc_fn):
            for sym_idx in INDEX_INSTRUMENTS:
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
                "candles_m1": _roll_mt5_index_bars(p_m1, b_m1, mid_px, _dec_txt),
                "candles_m5": _roll_mt5_index_bars(p_m5, b_m5, mid_px, _dec_txt),
                "candles_h1": _roll_mt5_index_bars(p_h1, b_h1, mid_px, _dec_txt),
            })
    if not idx_rows:
        return None, mt5_q
    prev_seq = int(prev_stream.get("sequence", 0)) if isinstance(prev_stream, Mapping) else 0
    return {
        "schema": "cas-forex.index-stream/1",
        "sequence": prev_seq + 1,
        "observed_at": obs_iso,
        "feed_mode": "MT5_DIRECT_SPOOL_50MS",
        "instruments": list(INDEX_INSTRUMENTS),
        "markets": idx_rows,
    }, mt5_q


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
        owner_recovery: Any | None = None,
        model_execution_gate: Any | None = None,
        token_file: str | Path | None = None,
        public_origin: str | None = None,
        withdrawal_provider_verifier: Callable[[str, str], Mapping[str, Any]] | None = None,
        max_ordinary_connections: int = 16,
        max_emergency_connections: int = 4,
        header_deadline_seconds: float = 3.0,
        pre_auth_timeout_seconds: float | None = None,
        pre_auth_conn_rate_limit: int = 256,
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
        self._emergency_httpd: _ExclusiveThreadingHTTPServer | None = None
        self._emergency_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sse_cond = threading.Condition()
        self._sse_version = 0
        self._last_routing_error: str | None = None
        self._withdrawal_provider_verifier = withdrawal_provider_verifier
        self._max_ordinary_connections = max(1, int(max_ordinary_connections))
        self._max_emergency_connections = max(1, int(max_emergency_connections))
        eff_deadline = header_deadline_seconds if pre_auth_timeout_seconds is None else pre_auth_timeout_seconds
        self._header_deadline_seconds = max(0.1, float(eff_deadline))
        self._pre_auth_conn_rate_limit = max(1, int(pre_auth_conn_rate_limit))
        self._mono = mono_clock or time.monotonic
        self._auth_lock = threading.RLock()
        self._auth_cond = threading.Condition(self._auth_lock)
        self._auth_secret: _CockpitSecret | None = None
        self._session_epoch: str | None = None
        self._revoked_epochs: set[str] = set()
        self._inflight_commits: dict[str, int] = {}
        self._pairing_codes: dict[str, _PairingCodeRecord] = {}
        self._device_sessions: dict[str, _DeviceSessionRecord] = {}
        self._pair_exchange_attempts: dict[str, list[float]] = {}
        self._worker_sem = threading.BoundedSemaphore(self._max_ordinary_connections)
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
        now_m = self._mono()
        with self._auth_cond:
            cutoff = now_m - PAIR_EXCHANGE_WINDOW_SECONDS
            hist = [t for t in self._pair_exchange_attempts.get(peer_key, ()) if t >= cutoff]
            if len(hist) >= MAX_PAIR_EXCHANGE_ATTEMPTS_PER_WINDOW:
                self._pair_exchange_attempts[peer_key] = hist
                return int(HTTPStatus.TOO_MANY_REQUESTS), {"error": "Too many pairing exchange attempts"}
            hist.append(now_m)
            self._pair_exchange_attempts[peer_key] = hist

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

    @contextmanager
    def _commit_lease(
        self,
        bearer_token: str | None,
        captured_epoch: str,
        *,
        hold_lock: bool = True,
        allow_device_scope: bool = False,
    ):
        """Acquire a revocable commit lease verified at commit time; rotation drains active leases before returning (Finding [10])."""
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
                if exists:
                    raw_bytes, _ = verify_and_read_owner_only_file(
                        parent_path, fname, dir_fd=dir_fd, label="cockpit file", max_bytes=256
                    )
                    raw = raw_bytes.decode("utf-8").strip()
                    if not _is_valid_generated_cockpit_token(raw):
                        raise ContractError(
                            "Refusing malformed or low-entropy pre-existing cockpit token file (expected generated 43+ char high-entropy token)"
                        )
                    new_epoch = "epoch-" + secrets.token_hex(16)
                    with self._auth_cond:
                        self._auth_secret = _CockpitSecret(raw)
                        self._session_epoch = new_epoch
                        self._pairing_codes.clear()
                        self._device_sessions.clear()
                        if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                            self._ui_service.rotate_adapter_session(new_epoch)
                    return
                new_tok = _CockpitSecret(secrets.token_urlsafe(32))
                new_epoch = "epoch-" + secrets.token_hex(16)
                create_owner_only_file_atomic(
                    parent_path,
                    fname,
                    (new_tok.reveal() + "\n").encode("utf-8"),
                    dir_fd=dir_fd,
                    replace_existing=False,
                    label="cockpit file",
                )
                with self._auth_cond:
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
        self.rotate_auth_token()

    def rotate_auth_token(self, *, exclude_sock: socket.socket | None = None) -> str:
        """Rotate per-launch bearer secret + session_epoch, revoking prior epoch, pairing codes & device sessions."""
        with self._auth_cond:
            old_epoch = self._session_epoch
            if old_epoch is not None:
                self._revoked_epochs.add(old_epoch)
            new_tok = _CockpitSecret(secrets.token_urlsafe(32))
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
        if old_epoch is not None:
            drain_deadline = time.monotonic() + 5.0
            with self._auth_cond:
                while self._inflight_commits.get(old_epoch, 0) > 0 and time.monotonic() < drain_deadline:
                    self._auth_cond.wait(timeout=0.05)
        return new_tok.reveal()

    def notify_stream_updated(self) -> None:
        with self._sse_cond:
            self._sse_version += 1
            self._sse_cond.notify_all()

    def _record_request(self, route: str) -> None:
        bucket = route if route in _KNOWN_METRICS_ROUTES else "__other__"
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
                tsnap = self._autonomous_trader.status_snapshot()
                payload["trader_summary"] = {
                    "governance_mode": str(tsnap.get("governance_mode", "")),
                    "effective_status": str(tsnap.get("effective_status", "")),
                    "cycle_count": int(tsnap.get("cycle_count", 0)),
                    "veto_count": int(tsnap.get("veto_count", 0)),
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

    def _read_aggression_dial_snapshot(self, *, owner_controls_allowed: bool = True) -> dict[str, Any] | None:
        if self._aggression_dial is None:
            return None
        execution_mode = "DEMO"
        try:
            routing = self._read_broker_routing()
            if isinstance(routing, Mapping):
                raw_em = str(routing.get("execution_mode") or "DEMO").strip().upper()
                if raw_em == "LIVE":
                    execution_mode = "LIVE"
        except Exception as exc_rt:
            self._last_routing_error = type(exc_rt).__name__

        regime = "NEUTRAL"
        consec = 0
        dd_dec = Decimal("0")
        vs_dec = Decimal("0.60")
        if self._autonomous_trader is not None:
            try:
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
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                self.close_connection = True

            def _allowed_hosts_and_origins(self) -> tuple[set[str], set[str]]:
                if self._emergency_channel:
                    return {outer.emergency_expected_host_header}, {outer.emergency_base_url}
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
                if isinstance(self.connection, socket.socket):
                    self.connection.settimeout(min(self._pre_auth_budget(), 5.0))
                    outer._register_socket(self.connection)

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
                    if isinstance(self.connection, socket.socket):
                        outer._unregister_socket(self.connection)

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

            def _reject_insufficient_scope(self) -> None:
                outer._record_auth_failure()
                self._write_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Owner primary bearer required for privileged control",
                        "required_scope": SESSION_SCOPE_OWNER_FULL,
                    },
                )

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

                # Pre-bearer single-use pairing code exchange (Finding [2])
                if route == "/api/pair-exchange":
                    try:
                        body = self._read_json_body(max_bytes=4096)
                        if type(body) is not dict or not isinstance(body.get("pair_code"), str):
                            raise ContractError("pair_code field required")
                        peer_k = str(self.client_address[0]) if self.client_address else "127.0.0.1"
                        st_code, resp_doc = outer.exchange_pairing_code(body["pair_code"], peer_key=peer_k)
                        if st_code == int(HTTPStatus.UNAUTHORIZED):
                            outer._record_auth_failure()
                        self._write_json(HTTPStatus(st_code), resp_doc)
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
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
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        cur_sock = self.connection if isinstance(self.connection, socket.socket) else None
                        outer.rotate_auth_token(exclude_sock=cur_sock)
                        self._write_json(HTTPStatus.OK, {"ok": True, "session_epoch": outer.session_epoch})
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
                    try:
                        body = self._read_json_body(max_bytes=16384)
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict:
                            raise ContractError("JSON object required")
                        exec_mode_str = "DEMO"
                        try:
                            routing_doc = outer._read_broker_routing()
                            if isinstance(routing_doc, Mapping):
                                exec_mode_str = str(routing_doc.get("execution_mode") or "DEMO").strip().upper()
                        except Exception as exc_rt:
                            outer._last_routing_error = type(exc_rt).__name__
                        if "live_mode" in body and type(body["live_mode"]) is not bool:
                            raise ContractError("live_mode must be a boolean")
                        live_mode_flag = (exec_mode_str == "LIVE") or bool(body.get("live_mode", False))
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
                                outer._aggression_dial.set_master_risk_bps(
                                    bps_val,
                                    ai_discretion_enabled=ai_disc,
                                    ai_discretion_ceiling_bps=ceil_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=raw_hrc,
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
                                outer._aggression_dial.set_ai_discretion(
                                    en_val,
                                    ceiling_bps=ceil_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=raw_hrc,
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
                                outer._aggression_dial.set_ai_discretion(
                                    en_cur,
                                    ceiling_bps=ceil_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=raw_hrc,
                                    owner_controls_allowed=True,
                                    actor=actor_str,
                                )
                            elif raw_action == "SET_TIER_RISK_BPS":
                                outer._aggression_dial.set_tier_risk_bps(
                                    body.get("tier_id"),
                                    body.get("risk_bps"),
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=raw_hrc,
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
                                outer._aggression_dial.apply_tier_preset(
                                    preset_val,
                                    live_mode=live_mode_flag,
                                    high_risk_confirmed=raw_hrc,
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
                        self._write_json(
                            HTTPStatus.CONFLICT,
                            {
                                "error": str(exc),
                                "code": "HIGH_RISK_CONFIRMATION_REQUIRED",
                                "live_mode": True,
                                "high_risk_min_bps": HIGH_RISK_MIN_BPS,
                            },
                        )
                    except OwnerKeyRequiredError:
                        self._reject_insufficient_scope()
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
                            with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=False):
                                res = outer._profit_vault.confirm_broker_2fa_withdrawal(
                                    transfer_id=str(body["transfer_id"]),
                                    provider_tx_id=str(body["provider_tx_id"]),
                                    owner_request_id=req_id,
                                    verifier=outer._owner_recovery,
                                    recovery_token=str(rec_tok or ""),
                                    provider_verifier=outer._withdrawal_provider_verifier,  # type: ignore[arg-type]
                                )
                        elif act == "EXECUTE_OFFRAMP_ACH":
                            from cas_forex_revamp.treasury.profit_sweep import CoinbaseOfframpClient, KrakenOfframpClient
                            rail_name = str(body.get("rail") or "COINBASE_ACH").strip().upper()
                            cb = CoinbaseOfframpClient.from_environ(os.environ) if rail_name == "COINBASE_ACH" else None
                            krk = KrakenOfframpClient.from_environ(os.environ) if rail_name == "KRAKEN_ACH" else None
                            conv_amt = _Dec(str(body["convert_amount"])) if body.get("convert_amount") is not None else None
                            with outer._commit_lease(supplied_tok, auth_epoch, hold_lock=False):
                                res = outer._profit_vault.execute_offramp_ach_payout(
                                    rail=rail_name,
                                    amount_usd=_Dec(str(body["amount_usd"])),
                                    owner_request_id=req_id,
                                    reason=reason,
                                    verifier=outer._owner_recovery,
                                    recovery_token=str(rec_tok or ""),
                                    coinbase_client=cb,
                                    kraken_client=krk,
                                    convert_from_currency=body.get("convert_from_currency"),
                                    convert_amount=conv_amt,
                                    coinbase_source_account_uuid=body.get("coinbase_source_account_uuid"),
                                    coinbase_usd_account_uuid=body.get("coinbase_usd_account_uuid"),
                                    kraken_pair=str(body.get("kraken_pair") or "USDCUSD"),
                                    idempotency_key=body.get("idempotency_key"),
                                    retry_transfer_id=body.get("retry_transfer_id"),
                                    intent_id=body.get("intent_id"),
                                    intent_sha256=body.get("intent_sha256"),
                                )
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

                            safe_ctx = assert_safe_ai_catalog_payload(ctx_summary)
                            ask_fn = outer._ai_model_registry.answer_explainer_question
                            ask_params = inspect.signature(ask_fn).parameters
                            if "execution_gate" in ask_params:
                                ans_doc = ask_fn(
                                    question=raw_q,
                                    context_summary=safe_ctx,
                                    audio_base64=raw_audio,
                                    audio_mime_type=raw_mime,
                                    execution_gate=outer._model_gate,
                                )
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
                                tts_fn = outer._ai_model_registry.synthesize_explainer_speech
                                tts_params = inspect.signature(tts_fn).parameters
                                if "execution_gate" in tts_params:
                                    tts_doc = tts_fn(
                                        body["text"],
                                        voice_name=clean_voice,
                                        execution_gate=outer._model_gate,
                                    )
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
            thread_name_prefix="cas-cockpit-worker",
        )
        self._httpd.request_queue_size = 32
        try:
            self._emergency_httpd = _ExclusiveThreadingHTTPServer(
                (self._host, self._emergency_port_cfg),
                _EmergencyHandler,
                ordinary_slots=self._max_emergency_connections,
                peer_rate_limit_per_window=max(64, self._pre_auth_conn_rate_limit),
                thread_name_prefix="cas-cockpit-emerg",
            )
            self._emergency_httpd.request_queue_size = 16
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

    from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader, ENV_RISK_GEAR_MODE
    from cas_forex_revamp.composition.state_store import initialize_shared_runtime_state
    from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
    from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
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
        t_out = Path(merged.get(ENV_LIVE_AUTH_TICKET_FILE) or (runtime_state.state_dir / "live_auth_bundle.json"))
        t_out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"status": "LIVE_TICKET_MINTED", "key_file": str(key_p), "ticket_file": str(t_out), "brokers": [t[0] for t in targets]}))
        return 0

    gate = runtime_state.valve_gate
    from cas_forex_revamp.contracts import parse_decimal as _parse_dec
    stream_lock = threading.Lock()
    latest_index_stream: list[dict[str, Any] | None] = [None]

    def _read_index_ref(symbols: Any) -> dict[str, tuple[Any, Any]]:
        with stream_lock:
            doc = latest_index_stream[0]
        if not isinstance(doc, dict):
            return {}
        out: dict[str, tuple[Any, Any]] = {}
        wanted = set(symbols)
        for row in doc.get("markets") or ():
            sym = row.get("pair")
            if sym in wanted and "bid" in row and "ask" in row:
                out[sym] = (_parse_dec(str(row["bid"])), _parse_dec(str(row["ask"])))
        return out

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
        initial_capital_usd=cli_init_cap,
    )
    if not args.autonomous_ai:
        trader.stop_automation(reason="CLI launched with --no-autonomous-ai")
    if args.activate_brokers:
        router.activate_all()

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
            latest_index_stream[0] = index_client.fetch_index_stream()
        except Exception as exc:
            print(f"[feed] Initial index fetch skipped ({type(exc).__name__}); awaiting MT5 ticks.")
    mt5_idx_init, _ = _build_mt5_index_snapshot_from_router(router, prev_stream=latest_index_stream[0])
    if mt5_idx_init is not None:
        latest_index_stream[0] = mt5_idx_init

    def _read_stream() -> dict[str, Any] | None:
        with stream_lock:
            return latest_stream[0]

    def _read_index_stream() -> dict[str, Any] | None:
        with stream_lock:
            return latest_index_stream[0]

    if callable(getattr(registry, "bind_execution_gate", None)):
        registry.bind_execution_gate(runtime_state.model_gate)
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
        owner_recovery=runtime_state.owner_recovery,
        model_execution_gate=runtime_state.model_gate,
        token_file=str(merged.get("CAS_FOREX_COCKPIT_TOKEN_FILE", "")).strip() or None,
        public_origin=str(merged.get("CAS_FOREX_PUBLIC_ORIGIN", "")).strip() or None,
    )
    srv.start()
    stop_flag = threading.Event()

    def _poll_loop() -> None:
        while not stop_flag.wait(float(args.poll_seconds)):
            if feed_client is None:
                break
            try:
                env_stream = feed_client.fetch_market_stream().to_wire_dict()
                with stream_lock:
                    prev_idx = latest_index_stream[0]
                mt5_idx_snap, _ = _build_mt5_index_snapshot_from_router(router, prev_stream=prev_idx)
                idx_stream = mt5_idx_snap if mt5_idx_snap is not None else prev_idx
                if mt5_idx_snap is None and index_client is not None:
                    try:
                        idx_stream = index_client.fetch_index_stream()
                    except Exception as exc_idx:
                        print(f"[feed] Index poll skipped ({type(exc_idx).__name__}).")
                with stream_lock:
                    latest_stream[0] = env_stream
                    latest_index_stream[0] = idx_stream
                if args.autonomous_ai:
                    try:
                        trader.run_cycle(env_stream, index_stream=idx_stream)
                    except Exception as exc_ai:
                        msg_ai = " ".join(str(exc_ai).split())[:140]
                        print(f"[ai] Standard cycle skipped ({type(exc_ai).__name__}: {msg_ai}).")
                srv.notify_stream_updated()
            except Exception as exc:
                print(f"[feed] Poll skipped ({type(exc).__name__}); keeping last verified snapshot.")

    def _fast_tick_loop() -> None:
        interval = max(0.05, float(args.fast_tick_ms) / 1000.0)
        while not stop_flag.wait(interval):
            if not args.autonomous_ai:
                continue
            try:
                with stream_lock:
                    prev_idx = latest_index_stream[0]
                mt5_idx_snap, mt5_q = _build_mt5_index_snapshot_from_router(router, prev_stream=prev_idx)
                if mt5_q:
                    if mt5_idx_snap is not None:
                        with stream_lock:
                            latest_index_stream[0] = mt5_idx_snap
                    if trader._inference_lock.acquire(blocking=False):
                        try:
                            trader.run_fast_tick_cycle(mt5_quotes=mt5_q)
                        finally:
                            trader._inference_lock.release()
                    else:
                        # Non-blocking 50ms stop protection even during 3-8s deep-thinking HTTP inference
                        trader.evaluate_fast_protection(quotes=mt5_q)
                        runtime_state.parallel_tiers.process_tick(quotes=mt5_q, signal=None)
                    srv.notify_stream_updated()
            except Exception as exc_ft:
                msg_ft = " ".join(str(exc_ft).split())[:140]
                print(f"[ai-fast] Fast tick skipped ({type(exc_ft).__name__}: {msg_ft}).")

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
