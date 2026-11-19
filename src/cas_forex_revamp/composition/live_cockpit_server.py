"""Loopback-only Authenticated HTTP & SSE Cockpit Bridge Server for CAS Forex 01 Operate.

Security & Honesty Invariants:
- Binds EXCLUSIVELY to a loopback IP address (127.0.0.1 / ::1); hard-refuses 0.0.0.0 or external NICs.
- Validates loopback client peer IP, exact literal loopback `Host` (`127.0.0.1:<port>` / `[::1]:<port>`),
  and exact loopback `Origin` / `Sec-Fetch-Site` BEFORE reading any request body (defeating DNS rebinding & CSRF).
- Generates a fresh `secrets.token_urlsafe(32)` bearer/cookie secret + `session_epoch` per `.start()` (and on
  `.rotate_auth_token()`), rotating `ScopedUIService.rotate_adapter_session` so prior prepared operations invalidate.
- Enforces constant-time `hmac.compare_digest` authentication on all state, stream, SSE, routing, and RPC `/api/*`
  routes; supports `GET /?token=<token>` / `GET /ui/index.html?token=<token>` setting an `HttpOnly; SameSite=Strict;
  Path=/api` session cookie for strict-CSP browser `EventSource` and `fetch` calls.
- Serves static UI & contract files strictly within the pinned repository root (resolves and blocks .. traversal).
- Emits strict Content-Security-Policy (default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self').
- Importing and constructing LoopbackCockpitServer is strictly inert until .start() is called.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
import os
import hmac
from http import HTTPStatus
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import math
import re
import socket
import ipaddress
import json
from pathlib import Path
import secrets
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
from cas_forex_revamp.operator.frontier_backends import assert_safe_ai_catalog_payload

class _SessionRevokedError(Exception):
    """Raised when a session epoch is revoked prior to commit."""


_COCKPIT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
MAX_HTTP_HEADER_BYTES = 16384
MAX_HTTP_HEADER_COUNT = 64


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
    """Wrap socket rfile with an absolute header-read wall-clock deadline and cumulative byte ceiling (Finding [8])."""

    def __init__(self, sock: socket.socket, raw_rfile: Any, *, deadline: float, max_bytes: int) -> None:
        self._sock = sock
        self._raw = raw_rfile
        self._deadline = deadline
        self._max_bytes = max_bytes
        self._total_read = 0
        self.header_deadline_exceeded = False
        self.header_size_exceeded = False

    def readline(self, limit: int = -1) -> bytes:
        rem = self._deadline - time.monotonic()
        if rem <= 0:
            self.header_deadline_exceeded = True
            raise TimeoutError("absolute HTTP header deadline exceeded")
        self._sock.settimeout(min(rem, 1.0))
        budget = self._max_bytes - self._total_read
        if budget <= 0:
            self.header_size_exceeded = True
            raise ValueError("HTTP header byte limit exceeded")
        eff_limit = budget + 1 if limit < 0 else min(limit, budget + 1)
        try:
            line = self._raw.readline(eff_limit)
        except (TimeoutError, socket.timeout):
            if time.monotonic() >= self._deadline:
                self.header_deadline_exceeded = True
                raise TimeoutError("absolute HTTP header deadline exceeded") from None
            rem2 = self._deadline - time.monotonic()
            if rem2 <= 0:
                self.header_deadline_exceeded = True
                raise TimeoutError("absolute HTTP header deadline exceeded") from None
            self._sock.settimeout(rem2)
            line = self._raw.readline(eff_limit)
        self._total_read += len(line)
        if self._total_read > self._max_bytes:
            self.header_size_exceeded = True
            raise ValueError("HTTP header byte limit exceeded")
        if time.monotonic() > self._deadline:
            self.header_deadline_exceeded = True
            raise TimeoutError("absolute HTTP header deadline exceeded")
        return line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class _ExclusiveThreadingHTTPServer(HTTPServer):
    """Bounded loopback HTTP server preventing SO_REUSEADDR hijacking and pre-auth thread exhaustion (Finding [8])."""

    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        ordinary_slots: int = 16,
        emergency_slots: int = 4,
    ) -> None:
        self._ordinary_slots = max(1, int(ordinary_slots))
        self._emergency_slots = max(1, int(emergency_slots))
        self._ordinary_conn_sem = threading.BoundedSemaphore(self._ordinary_slots)
        self._emergency_conn_sem = threading.BoundedSemaphore(self._emergency_slots)
        self._slot_lock = threading.Lock()
        self._conn_slot_kind: dict[int, str] = {}
        self._active_workers = 0
        self._peak_workers = 0
        self._rejected_pre_auth = 0
        self._executor = ThreadPoolExecutor(
            max_workers=self._ordinary_slots + self._emergency_slots,
            thread_name_prefix="cas-cockpit-worker",
        )
        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def slot_kind_for(self, request: socket.socket) -> str:
        with self._slot_lock:
            return self._conn_slot_kind.get(id(request), "ordinary")

    def process_request(self, request: Any, client_address: Any) -> None:
        if self._ordinary_conn_sem.acquire(blocking=False):
            slot_kind = "ordinary"
            sem = self._ordinary_conn_sem
        elif self._emergency_conn_sem.acquire(blocking=False):
            slot_kind = "emergency_probe"
            sem = self._emergency_conn_sem
        else:
            with self._slot_lock:
                self._rejected_pre_auth += 1
            try:
                if isinstance(request, socket.socket):
                    request.settimeout(0.25)
                    request.sendall(
                        b"HTTP/1.1 503 Service Unavailable\r\n"
                        b"Content-Type: application/json; charset=utf-8\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 43\r\n\r\n"
                        b"{\"error\": \"Cockpit connection pool full\"}\n"
                    )
            except OSError as exc:
                _drop_err = str(exc)  # best-effort 503 before pre-auth close
            self.shutdown_request(request)
            return

        with self._slot_lock:
            self._conn_slot_kind[id(request)] = slot_kind
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
                        self._conn_slot_kind.pop(id(request), None)
                        self._active_workers = max(0, self._active_workers - 1)
                    sem.release()

        try:
            self._executor.submit(_worker)
        except RuntimeError:
            with self._slot_lock:
                self._conn_slot_kind.pop(id(request), None)
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
        ui_service: Any | None = None,
        market_stream_reader: Callable[[], dict[str, Any] | None] | None = None,
        broker_router_reader: Callable[[], dict[str, Any] | None] | None = None,
        ai_model_registry: Any | None = None,
        autonomous_trader: Any | None = None,
        index_stream_reader: Callable[[], dict[str, Any] | None] | None = None,
        profit_vault: Any | None = None,
        parallel_tiers: Any | None = None,
        owner_recovery: Any | None = None,
        token_file: str | Path | None = None,
        public_origin: str | None = None,
        withdrawal_provider_verifier: Callable[[str, str], Mapping[str, Any]] | None = None,
        max_ordinary_connections: int = 16,
        max_emergency_connections: int = 4,
        header_deadline_seconds: float = 3.0,
    ) -> None:
        self._host = validate_loopback_host(host)
        if type(port) is not int or not (0 <= port <= 65535):
            raise ContractError("port must be an integer in 0..65535")
        self._port = port
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
        self._owner_recovery = owner_recovery or (
            getattr(autonomous_trader, "_owner_verifier", None) if autonomous_trader is not None else None
        )
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sse_cond = threading.Condition()
        self._sse_version = 0
        self._last_routing_error: str | None = None
        self._withdrawal_provider_verifier = withdrawal_provider_verifier
        self._max_ordinary_connections = max(1, int(max_ordinary_connections))
        self._max_emergency_connections = max(1, int(max_emergency_connections))
        self._header_deadline_seconds = max(0.2, float(header_deadline_seconds))
        self._auth_lock = threading.RLock()
        self._auth_cond = threading.Condition(self._auth_lock)
        self._auth_secret: _CockpitSecret | None = None
        self._session_epoch: str | None = None
        self._revoked_epochs: set[str] = set()
        self._inflight_commits: dict[str, int] = {}
        self._worker_sem = threading.BoundedSemaphore(self._max_ordinary_connections)
        self._emergency_sem = threading.BoundedSemaphore(self._max_emergency_connections)
        self._sse_sem = threading.BoundedSemaphore(4)
        self._sockets_lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        # Finding [2]: preserve un-resolved Path so symlink/parent custody checks run BEFORE any open!
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
    def expected_host_header(self) -> str:
        port = self.bound_port
        return f"[{self._host}]:{port}" if ":" in self._host else f"{self._host}:{port}"

    @property
    def base_url(self) -> str:
        return f"http://{self.expected_host_header}"

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
        """Convenience header mapping (`Authorization: Bearer <token>`) for authenticated local clients."""
        return {"Authorization": f"Bearer {self.auth_token}"}

    @property
    def bootstrap_url(self) -> str:
        """Loopback browser bootstrap URL exchanging `?token=` for an HttpOnly `/api` cookie."""
        return f"{self.base_url}/ui/index.html?token={self.auth_token}"

    def _register_socket(self, sock: socket.socket) -> None:
        with self._sockets_lock:
            self._active_sockets.add(sock)

    def _unregister_socket(self, sock: socket.socket) -> None:
        with self._sockets_lock:
            self._active_sockets.discard(sock)

    def _close_active_sockets(self) -> None:
        with self._sockets_lock:
            socks = list(self._active_sockets)
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

    def _verify_commit_epoch(self, bearer_token: str | None, captured_epoch: str) -> bool:
        if not bearer_token or not captured_epoch:
            return False
        with self._auth_cond:
            if self._stop_event.is_set() or self._httpd is None:
                return False
            if captured_epoch in self._revoked_epochs:
                return False
            if self._auth_secret is None or self._session_epoch != captured_epoch:
                return False
            return hmac.compare_digest(bearer_token.encode("utf-8"), self._auth_secret.reveal().encode("utf-8"))

    @contextmanager
    def _commit_lease(self, bearer_token: str | None, captured_epoch: str, *, hold_lock: bool = True):
        """Acquire a revocable commit lease verified at commit time; rotation drains active leases before returning (Finding [10])."""
        if not bearer_token or not captured_epoch:
            raise _SessionRevokedError("missing bearer or epoch")
        with self._auth_cond:
            if (
                self._stop_event.is_set()
                or self._httpd is None
                or captured_epoch in self._revoked_epochs
                or self._auth_secret is None
                or self._session_epoch != captured_epoch
                or not hmac.compare_digest(bearer_token.encode("utf-8"), self._auth_secret.reveal().encode("utf-8"))
            ):
                raise _SessionRevokedError("session epoch revoked or bearer mismatch")
            self._inflight_commits[captured_epoch] = self._inflight_commits.get(captured_epoch, 0) + 1
            if hold_lock:
                # Hold auth_lock strictly across short in-memory/SQLite state commits so rotation cannot interleave
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
        # Non-blocking lease for external network I/O routes: tracked for deterministic rotation drain
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
                        if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                            self._ui_service.rotate_adapter_session(new_epoch)
                    return
                # Missing: generate new secret and create exclusively relative to verified parent dir_fd
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
                    if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                        self._ui_service.rotate_adapter_session(new_epoch)
                return
            finally:
                if dir_fd is not None:
                    os.close(dir_fd)
        self.rotate_auth_token()

    def rotate_auth_token(self) -> str:
        """Rotate per-launch bearer secret + session_epoch, revoking prior epoch and draining active commits (Finding [10])."""
        with self._auth_cond:
            old_epoch = self._session_epoch
            if old_epoch is not None:
                self._revoked_epochs.add(old_epoch)
            new_tok = _CockpitSecret(secrets.token_urlsafe(32))
            new_epoch = "epoch-" + secrets.token_hex(16)
            self._auth_secret = new_tok
            self._session_epoch = new_epoch
            if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                self._ui_service.rotate_adapter_session(new_epoch)
            if self._token_file is not None:
                self._write_token_file(new_tok.reveal())
            self._auth_cond.notify_all()
        self.notify_stream_updated()
        self._close_active_sockets()
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

    def start(self) -> str:
        if self._httpd is not None:
            return self.base_url
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                return

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

            def _enforce_loopback_envelope(self) -> bool:
                """Pre-body check: peer IP, exact literal loopback Host, and exact loopback Origin."""
                try:
                    peer_ip = ipaddress.ip_address(str(self.client_address[0]))
                except ValueError:
                    peer_ip = None
                if peer_ip is None or not peer_ip.is_loopback or peer_ip.is_unspecified:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Loopback clients only"})
                    return False

                allowed_hosts = {outer.expected_host_header}
                allowed_origins = {outer.base_url}
                if outer._public_host and outer._public_origin:
                    allowed_hosts.add(outer._public_host)
                    allowed_origins.add(outer._public_origin)
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

                sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
                if sec_site and sec_site not in ("same-origin", "none"):
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Cross-site browser request forbidden"})
                    return False
                return True

            def setup(self) -> None:
                super().setup()
                self._slot_kind = (
                    self.server.slot_kind_for(self.connection)
                    if hasattr(self.server, "slot_kind_for")
                    else "ordinary"
                )
                if isinstance(self.connection, socket.socket):
                    self.connection.settimeout(min(outer._header_deadline_seconds, 5.0))
                    outer._register_socket(self.connection)

            def parse_request(self) -> bool:
                if isinstance(self.connection, socket.socket):
                    hdr_budget = (
                        min(1.0, outer._header_deadline_seconds)
                        if getattr(self, "_slot_kind", "ordinary") == "emergency_probe"
                        else outer._header_deadline_seconds
                    )
                    orig_rfile = self.rfile
                    wrapped = _DeadlineRFile(
                        self.connection,
                        orig_rfile,
                        deadline=time.monotonic() + hdr_budget,
                        max_bytes=MAX_HTTP_HEADER_BYTES,
                    )
                    self.rfile = wrapped  # type: ignore[assignment]
                    try:
                        ok = super().parse_request()
                    except TimeoutError:
                        self.close_connection = True
                        return False
                    except ValueError:
                        self.close_connection = True
                        return False
                    finally:
                        self.rfile = orig_rfile
                        try:
                            self.connection.settimeout(5.0)
                        except OSError as exc:
                            _to_err = str(exc)  # socket already closed
                    if not ok:
                        return False
                    if len(self.headers) > MAX_HTTP_HEADER_COUNT:
                        self._write_json(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, {"error": "Too many HTTP headers"})
                        return False
                    if getattr(self, "_slot_kind", "ordinary") == "emergency_probe":
                        req_route = urllib.parse.urlsplit(self.path).path
                        if not (
                            str(self.command).upper() == "POST"
                            and req_route in ("/api/ai-overseer-action", "/api/request-control")
                        ):
                            self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Ordinary cockpit connection slots full; emergency capacity reserved"})
                            return False
                    return True
                return super().parse_request()

            def finish(self) -> None:
                try:
                    super().finish()
                finally:
                    if isinstance(self.connection, socket.socket):
                        outer._unregister_socket(self.connection)

            def _check_auth(self, *, is_post: bool) -> tuple[bool, bool, str, str]:
                """Bearer-only constant-time check returning (authed, supplied, epoch, candidate_token)."""
                with outer._auth_lock:
                    secret = outer._auth_secret
                    epoch = outer._session_epoch or ""
                if secret is None or outer._stop_event.is_set():
                    return False, False, "", ""
                expected_bytes = secret.reveal().encode("utf-8")

                auth_hdrs = self.headers.get_all("Authorization") or []
                if len(auth_hdrs) > 1:
                    return False, True, epoch, ""
                if len(auth_hdrs) == 1:
                    raw_auth = auth_hdrs[0].strip()
                    if not raw_auth.startswith("Bearer "):
                        return False, True, epoch, ""
                    candidate = raw_auth[7:].strip()
                    if not candidate:
                        return False, True, epoch, ""
                    if is_post:
                        origins = self.headers.get_all("Origin") or []
                        allowed_origins = {outer.base_url} | ({outer._public_origin} if outer._public_origin else set())
                        if len(origins) == 1 and origins[0].strip() not in allowed_origins:
                            return False, True, epoch, ""
                    ok = hmac.compare_digest(candidate.encode("utf-8"), expected_bytes)
                    return ok, True, epoch, candidate

                return False, bool(self.headers.get_all("Cookie")), epoch, "" 

            def _reject_unauthorized(self) -> None:
                self._write_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "Authentication required"},
                    extra_headers=[("WWW-Authenticate", 'Bearer realm="cas-forex-cockpit"')],
                )

            def _read_json_body(self) -> Any:
                raw_len = self.headers.get("Content-Length")
                if raw_len is None:
                    raise ContractError("Content-Length header required")
                length = int(raw_len)
                if length < 0 or length > MAX_HTTP_RPC_BYTES:
                    raise ContractError("RPC payload exceeds 256 KiB limit")
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ContractError("incomplete HTTP request body")
                return json.loads(data.decode("utf-8"))

            def do_GET(self) -> None:
                if not outer._worker_sem.acquire(blocking=False):
                    self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Cockpit worker capacity reached"})
                    return
                try:
                    self._handle_get()
                finally:
                    outer._worker_sem.release()

            def _handle_get(self) -> None:
                if not self._enforce_loopback_envelope():
                    return
                parsed = urllib.parse.urlsplit(self.path)
                route = parsed.path

                if route == "/api/health":
                    authed, supplied, epoch, _ = self._check_auth(is_post=False)
                    if supplied and not authed:
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
                    authed, _, initial_epoch, supplied_tok = self._check_auth(is_post=False)
                    if not authed:
                        self._reject_unauthorized()
                        return
                    if route == "/api/market-stream":
                        stream = outer._read_stream_payload()
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
                            return
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
                        else:
                            self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(outer._profit_vault.snapshot()))
                        return
                    if route == "/api/parallel-tiers":
                        if outer._parallel_tiers is None:
                            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Parallel Tier Engine not configured"})
                        else:
                            self._write_json(HTTPStatus.OK, assert_safe_ai_catalog_payload(outer._parallel_tiers.snapshot()))
                        return
                    if route == "/api/index-stream":
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
                            self._write_json(HTTPStatus.OK, idx_snap)
                        return
                    if route == "/api/market-events":
                        if not outer._sse_sem.acquire(blocking=False):
                            self._write_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "SSE subscriber limit reached"})
                            return
                        outer._worker_sem.release()
                        reacquire_worker = True
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
                            try:
                                while not outer._stop_event.is_set():
                                    if not outer._verify_commit_epoch(supplied_tok, initial_epoch):
                                        break
                                    if last_emit_mono > 0.0:
                                        since_emit = time.monotonic() - last_emit_mono
                                        if since_emit < 0.25:
                                            outer._stop_event.wait(0.25 - since_emit)
                                            if outer._stop_event.is_set() or not outer._verify_commit_epoch(supplied_tok, initial_epoch):
                                                break
                                    with outer._sse_cond:
                                        if outer._sse_version == seen_ver:
                                            outer._sse_cond.wait(timeout=1.5)
                                        cur_ver = outer._sse_version
                                    if outer._stop_event.is_set() or not outer._verify_commit_epoch(supplied_tok, initial_epoch):
                                        break
                                    if cur_ver != seen_ver:
                                        seen_ver = cur_ver
                                        now_mono = time.monotonic()
                                        snap = outer._read_stream_payload()
                                        if snap is not None:
                                            frame = f"event: market\ndata: {json.dumps(snap, sort_keys=False)}\n\n".encode("utf-8")
                                            self.wfile.write(frame)
                                        if outer._index_stream_reader is not None:
                                            isnap = outer._index_stream_reader()
                                            if isnap is not None:
                                                safe_isnap = assert_safe_ai_catalog_payload(isnap)
                                                iframe = f"event: index_stream\ndata: {json.dumps(safe_isnap, sort_keys=False)}\n\n".encode("utf-8")
                                                self.wfile.write(iframe)
                                        if outer._autonomous_trader is not None:
                                            tsnap = assert_safe_ai_catalog_payload(outer._autonomous_trader.status_snapshot())
                                            tframe = f"event: ai_trader\ndata: {json.dumps(tsnap, sort_keys=False)}\n\n".encode("utf-8")
                                            self.wfile.write(tframe)
                                        if outer._ai_model_registry is not None:
                                            csnap = assert_safe_ai_catalog_payload(outer._ai_model_registry.catalog_snapshot())
                                            cjson = json.dumps(csnap, sort_keys=False)
                                            if not last_models_json or cjson != last_models_json or (now_mono - last_models_mono) >= 1.0:
                                                last_models_json = cjson
                                                last_models_mono = now_mono
                                                cframe = f"event: ai_models\ndata: {cjson}\n\n".encode("utf-8")
                                                self.wfile.write(cframe)
                                        if outer._profit_vault is not None:
                                            vsnap = assert_safe_ai_catalog_payload(outer._profit_vault.snapshot())
                                            vjson = json.dumps(vsnap, sort_keys=False)
                                            if not last_treasury_json or vjson != last_treasury_json or (now_mono - last_treasury_mono) >= 1.0:
                                                last_treasury_json = vjson
                                                last_treasury_mono = now_mono
                                                vframe = f"event: treasury\ndata: {vjson}\n\n".encode("utf-8")
                                                self.wfile.write(vframe)
                                        if outer._parallel_tiers is not None:
                                            ptsnap = assert_safe_ai_catalog_payload(outer._parallel_tiers.snapshot())
                                            ptframe = f"event: parallel_tiers\ndata: {json.dumps(ptsnap, sort_keys=False)}\n\n".encode("utf-8")
                                            self.wfile.write(ptframe)
                                        last_emit_mono = now_mono
                                        self.wfile.flush()
                                    else:
                                        self.wfile.write(b": heartbeat\n\n")
                                        self.wfile.flush()
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                pass
                            self.close_connection = True
                        finally:
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

                if parsed.query:
                    qmap = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    if "token" in qmap:
                        if route not in ("/", "/ui", "/ui/", "/ui/index.html") or len(qmap["token"]) != 1:
                            self._reject_unauthorized()
                            return
                        with outer._auth_lock:
                            secret = outer._auth_secret
                        if secret is None or not hmac.compare_digest(
                            qmap["token"][0].encode("utf-8"),
                            secret.reveal().encode("utf-8"),
                        ):
                            self._reject_unauthorized()
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
                is_emergency = route in ("/api/ai-overseer-action", "/api/request-control")
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
                authed, _, auth_epoch, supplied_tok = self._check_auth(is_post=True)
                if not authed:
                    self._reject_unauthorized()
                    return
                if route == "/api/select-ai-model":
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
                        with outer._commit_lease(supplied_tok, auth_epoch):
                            updated = assert_safe_ai_catalog_payload(
                                outer._profit_vault.set_config(
                                    sweep_ratio=ratio_v, auto_sweep_enabled=auto_v, preferred_rail=rail_v
                                )
                            )
                        outer.notify_stream_updated()
                        self._write_json(HTTPStatus.OK, updated)
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
                            with outer._commit_lease(supplied_tok, auth_epoch):
                                res = outer._profit_vault.request_broker_2fa_withdrawal(
                                    broker_id=str(body.get("broker_id") or "HUGOSWAY_MT5"),
                                    amount_usd=_Dec(str(body["amount_usd"])),
                                    owner_request_id=req_id,
                                    reason=reason,
                                    verifier=outer._owner_recovery,
                                    recovery_token=str(rec_tok or ""),
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
                        body = self._read_json_body()
                        if not outer._verify_commit_epoch(supplied_tok, auth_epoch):
                            self._reject_unauthorized()
                            return
                        if type(body) is not dict or not isinstance(body.get("question"), str):
                            raise ContractError("question field required")
                        ctx_summary: dict[str, Any] = {}
                        if outer._broker_router_reader is not None:
                            try:
                                r_doc = outer._broker_router_reader()
                                if isinstance(r_doc, Mapping):
                                    ctx_summary["execution_mode"] = str(r_doc.get("execution_mode") or "DEMO")
                                    ctx_summary["active_broker"] = str(r_doc.get("active_broker") or "HUGOSWAY_MT5")
                            except Exception as exc_ctx:
                                outer._last_routing_error = type(exc_ctx).__name__
                        if outer._autonomous_trader is not None:
                            try:
                                t_doc = outer._autonomous_trader.status_snapshot()
                                ctx_summary["current_focus_symbol"] = t_doc.get("current_focus_symbol")
                                ctx_summary["current_focus_status"] = t_doc.get("current_focus_status")
                                ctx_summary["cycle_count"] = t_doc.get("cycle_count")
                                ctx_summary["market_sessions"] = t_doc.get("market_sessions")
                            except Exception as exc_ctx:
                                outer._last_routing_error = type(exc_ctx).__name__
                        ans_doc = outer._ai_model_registry.answer_explainer_question(
                            question=body["question"],
                            context_summary=ctx_summary,
                        )
                        self._write_json(HTTPStatus.OK, ans_doc)
                    except Exception as exc:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if route == "/api/ai-overseer-action":
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

        self._stop_event.clear()
        self._load_or_init_auth_token()
        self._httpd = _ExclusiveThreadingHTTPServer(
            (self._host, self._port),
            _Handler,
            ordinary_slots=self._max_ordinary_connections,
            emergency_slots=self._max_emergency_connections,
        )
        self._httpd.request_queue_size = 32
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="cas-forex-cockpit-http", daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        self._stop_event.set()
        with self._auth_lock:
            self._auth_secret = None
            self._session_epoch = None
            if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                self._ui_service.rotate_adapter_session()
        with self._sse_cond:
            self._sse_cond.notify_all()
        self._close_active_sockets()
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
    ap.add_argument("--poll-seconds", type=int, default=15, help="Live 18-market poll interval in seconds (0=disable)")
    ap.add_argument("--fast-tick-ms", type=int, default=50, help="Direct MT5 fast-tick interval in ms for NAS100/US30 (0=disable)")
    ap.add_argument("--no-autonomous-ai", dest="autonomous_ai", action="store_false", default=True, help="Disable continuous autonomous AI trading loop")
    ap.add_argument("--state-dir", type=Path, default=None, help="Owner-only (0o700) persistent SQLite WAL state directory")
    ap.add_argument("--activate-brokers", action="store_true", help="Attempt live/demo connection to configured brokers")
    ap.add_argument("--print-check-only", action="store_true", help="Validate config/routing/AI catalog, print JSON, and exit")
    ap.add_argument("--mint-recovery-token", action="store_true", help="Mint a single-use OwnerRecoveryVerifier token and exit")
    ap.add_argument("--recovery-scope", default="UNLOCK_QUOTA_SESSION", help="Scope for --mint-recovery-token")
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
            ttl_seconds=args.recovery_ttl_seconds,
        )
        print(json.dumps({"status": "RECOVERY_TOKEN_MINTED", "scope": args.recovery_scope.upper(), "recovery_token": tok}))
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
        risk_gear_mode=merged.get(ENV_RISK_GEAR_MODE),
        risk_gear_path=runtime_state.state_dir / "risk_gear.json",
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

    srv = LoopbackCockpitServer(
        repo_root=root,
        host=args.host,
        port=args.port,
        market_stream_reader=_read_stream,
        broker_router_reader=router.routing_snapshot,
        ai_model_registry=registry,
        autonomous_trader=trader,
        index_stream_reader=_read_index_stream,
        profit_vault=runtime_state.profit_vault,
        parallel_tiers=runtime_state.parallel_tiers,
        owner_recovery=runtime_state.owner_recovery,
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
    if args.poll_seconds > 0 and feed_client is not None:
        poller.start()
    if args.fast_tick_ms > 0 and args.autonomous_ai and router.venues:
        fast_poller.start()

    print(f"CAS Forex Cockpit Execution Mode : {router.execution_mode} (live_armed={routing_summary['live_trading_armed']})")
    for row in routing_summary["chain"]:
        print(f"  [{row['priority']}] {row['broker_id']} ({row['server']}) configured={row['configured']} status={row['status']}")
    print(f"Open Authenticated UI            : {srv.bootstrap_url}")
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
