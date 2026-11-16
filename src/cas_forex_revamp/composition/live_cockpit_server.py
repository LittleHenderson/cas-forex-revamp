"""Loopback-only HTTP & SSE Cockpit Bridge Server for CAS Forex 01 Operate.

Security & Honesty Invariants:
- Binds EXCLUSIVELY to a loopback IP address (127.0.0.1 / ::1); hard-refuses 0.0.0.0 or external NICs.
- Serves static UI & contract files strictly within the pinned repository root (resolves and blocks .. traversal).
- Emits strict Content-Security-Policy (default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self').
- Exposes read-only market-stream JSON (/api/market-stream) + Server-Sent Events (/api/market-events) and
  optional ScopedUIService JSON RPC endpoints with bounded 256 KiB request payloads.
- Exposes an optional read-only, secret-free broker routing summary (/api/broker-routing) for the
  MetaTrader 5 Hugo's Way / LHFX / OANDA practice dual-shield hierarchy, served only to loopback
  clients and refused (HTTP 500, generic message) if the payload ever carries credential-like keys
  or non-safe JSON numbers.
- Importing and constructing LoopbackCockpitServer is strictly inert until .start() is called.
"""
from __future__ import annotations

from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import threading
from typing import Any
import urllib.parse

from cas_forex_revamp.contracts import ContractError

MAX_HTTP_RPC_BYTES = 262_144
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
_FORBIDDEN_ROUTING_KEY_TOKENS: tuple[str, ...] = ("password", "passwd", "token", "secret", "login", "credential", "api_key")
STRICT_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'"
)

_CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


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
    """Inert-until-started loopback HTTP/SSE server for CAS Forex Operate UI."""

    def __init__(
        self,
        *,
        repo_root: str | Path,
        host: str = "127.0.0.1",
        port: int = 0,
        ui_service: Any | None = None,
        market_stream_reader: Callable[[], dict[str, Any] | None] | None = None,
        broker_router_reader: Callable[[], dict[str, Any] | None] | None = None,
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
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sse_cond = threading.Condition()
        self._sse_version = 0
        self._last_routing_error: str | None = None

    @property
    def bound_port(self) -> int:
        if self._httpd is None:
            raise ContractError("server has not been started")
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self.bound_port}"

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

            def _send_security_headers(self, content_type: str, content_length: int | None = None) -> None:
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Security-Policy", STRICT_CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.send_header("Cache-Control", "no-store")
                if content_length is not None:
                    self.send_header("Content-Length", str(content_length))

            def _write_json(self, status: HTTPStatus, payload: Any) -> None:
                body = (json.dumps(payload, sort_keys=False) + "\n").encode("utf-8")
                self.send_response(int(status))
                self._send_security_headers("application/json; charset=utf-8", len(body))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

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
                parsed = urllib.parse.urlsplit(self.path)
                route = parsed.path
                if route == "/api/health":
                    self._write_json(HTTPStatus.OK, {
                        "status": "OK",
                        "bridge_attached": outer._ui_service is not None,
                        "stream_available": outer._read_stream_payload() is not None,
                    })
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
                        client_ip = ipaddress.ip_address(str(self.client_address[0]))
                    except ValueError:
                        client_ip = None
                    if client_ip is None or not client_ip.is_loopback:
                        self._write_json(HTTPStatus.FORBIDDEN, {"error": "Loopback clients only"})
                        return
                    try:
                        routing = outer._read_broker_routing()
                    except Exception as exc:  # never echo reader internals; report a generic refusal
                        outer._last_routing_error = type(exc).__name__
                        self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Broker routing unavailable"})
                        return
                    if routing is None:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Broker routing not configured"})
                    else:
                        self._write_json(HTTPStatus.OK, routing)
                    return
                if route == "/api/market-events":
                    self.send_response(int(HTTPStatus.OK))
                    self._send_security_headers("text/event-stream; charset=utf-8")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    seen_ver = -1
                    try:
                        while not outer._stop_event.is_set():
                            with outer._sse_cond:
                                if outer._sse_version == seen_ver:
                                    outer._sse_cond.wait(timeout=2.0)
                                cur_ver = outer._sse_version
                            if outer._stop_event.is_set():
                                break
                            if cur_ver != seen_ver:
                                seen_ver = cur_ver
                                snap = outer._read_stream_payload()
                                if snap is not None:
                                    frame = f"event: market\ndata: {json.dumps(snap, sort_keys=False)}\n\n".encode("utf-8")
                                    self.wfile.write(frame)
                                    self.wfile.flush()
                            else:
                                self.wfile.write(b": heartbeat\n\n")
                                self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return
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
                if outer._ui_service is None:
                    self._write_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "ScopedUIService not attached"})
                    return
                route = urllib.parse.urlsplit(self.path).path
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
                    result = fn(body)
                    self._write_json(HTTPStatus.OK, result)
                except Exception as exc:
                    self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        self._stop_event.clear()
        self._httpd = ThreadingHTTPServer((self._host, self._port), _Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="cas-forex-cockpit-http", daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        self._stop_event.set()
        with self._sse_cond:
            self._sse_cond.notify_all()
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
