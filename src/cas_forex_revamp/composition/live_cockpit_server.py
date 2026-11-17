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
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import secrets
import threading
from typing import Any
import urllib.parse

from cas_forex_revamp.contracts import ContractError

MAX_HTTP_RPC_BYTES = 262_144
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
AUTH_COOKIE_NAME = "cas_cockpit_auth"  # nosec B105: HTTP cookie name constant, not a secret value
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
        self._auth_lock = threading.RLock()
        self._auth_secret: _CockpitSecret | None = None
        self._session_epoch: str | None = None

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

    def rotate_auth_token(self) -> str:
        """Rotate per-launch bearer/cookie secret + session_epoch, invalidating prior prepared operations."""
        with self._auth_lock:
            new_tok = _CockpitSecret(secrets.token_urlsafe(32))
            new_epoch = "epoch-" + secrets.token_hex(16)
            self._auth_secret = new_tok
            self._session_epoch = new_epoch
            if self._ui_service is not None and callable(getattr(self._ui_service, "rotate_adapter_session", None)):
                self._ui_service.rotate_adapter_session(new_epoch)
        self.notify_stream_updated()
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

                hosts = self.headers.get_all("Host") or []
                if len(hosts) != 1 or hosts[0].strip() != outer.expected_host_header:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Invalid or foreign Host header"})
                    return False

                origins = self.headers.get_all("Origin") or []
                if len(origins) > 1:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Multiple Origin headers forbidden"})
                    return False
                if len(origins) == 1 and origins[0].strip() != outer.base_url:
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Cross-origin loopback request forbidden"})
                    return False

                sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
                if sec_site and sec_site not in ("same-origin", "none"):
                    self._write_json(HTTPStatus.FORBIDDEN, {"error": "Cross-site browser request forbidden"})
                    return False
                return True

            def _check_auth(self, *, is_post: bool) -> tuple[bool, bool, str]:
                """Return (authenticated, credential_supplied, session_epoch) via constant-time comparison."""
                with outer._auth_lock:
                    secret = outer._auth_secret
                    epoch = outer._session_epoch or ""
                if secret is None:
                    return False, False, ""
                expected_bytes = secret.reveal().encode("utf-8")

                auth_hdrs = self.headers.get_all("Authorization") or []
                if len(auth_hdrs) > 1:
                    return False, True, epoch
                if len(auth_hdrs) == 1:
                    raw_auth = auth_hdrs[0].strip()
                    if not raw_auth.startswith("Bearer "):
                        return False, True, epoch
                    candidate = raw_auth[7:].strip()
                    if not candidate:
                        return False, True, epoch
                    ok = hmac.compare_digest(candidate.encode("utf-8"), expected_bytes)
                    return ok, True, epoch

                cookie_hdrs = self.headers.get_all("Cookie") or []
                if cookie_hdrs:
                    jar = http_cookies.SimpleCookie()
                    try:
                        for raw_c in cookie_hdrs:
                            jar.load(raw_c)
                    except http_cookies.CookieError:
                        return False, True, epoch
                    morsel = jar.get(AUTH_COOKIE_NAME)
                    if morsel is not None:
                        cand_cookie = morsel.value
                        if is_post:
                            origins = self.headers.get_all("Origin") or []
                            if len(origins) != 1 or origins[0].strip() != outer.base_url:
                                return False, True, epoch
                        ok = hmac.compare_digest(cand_cookie.encode("utf-8"), expected_bytes)
                        return ok, True, epoch

                return False, False, epoch

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
                if not self._enforce_loopback_envelope():
                    return
                parsed = urllib.parse.urlsplit(self.path)
                route = parsed.path

                if route == "/api/health":
                    authed, supplied, epoch = self._check_auth(is_post=False)
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
                    authed, _, initial_epoch = self._check_auth(is_post=False)
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
                    if route == "/api/market-events":
                        self.send_response(int(HTTPStatus.OK))
                        self._send_security_headers("text/event-stream; charset=utf-8")
                        self.send_header("Connection", "keep-alive")
                        self.end_headers()
                        seen_ver = -1
                        try:
                            while not outer._stop_event.is_set():
                                with outer._auth_lock:
                                    active_epoch = outer._session_epoch
                                if active_epoch != initial_epoch:
                                    break
                                with outer._sse_cond:
                                    if outer._sse_version == seen_ver:
                                        outer._sse_cond.wait(timeout=2.0)
                                    cur_ver = outer._sse_version
                                if outer._stop_event.is_set():
                                    break
                                with outer._auth_lock:
                                    if outer._session_epoch != initial_epoch:
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
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "Unknown API endpoint"})
                    return

                extra_cookie_headers: list[tuple[str, str]] = []
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
                        cookie_val = f"{AUTH_COOKIE_NAME}={secret.reveal()}; HttpOnly; SameSite=Strict; Path=/api"
                        extra_cookie_headers.append(("Set-Cookie", cookie_val))

                static_file = outer._resolve_static_path(self.path)
                if static_file is None:
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                    return
                raw = static_file.read_bytes()
                ctype = _CONTENT_TYPES[static_file.suffix.lower()]
                self.send_response(int(HTTPStatus.OK))
                self._send_security_headers(ctype, len(raw), extra_headers=extra_cookie_headers)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                if not self._enforce_loopback_envelope():
                    return
                authed, _, _ = self._check_auth(is_post=True)
                if not authed:
                    self._reject_unauthorized()
                    return
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
        self.rotate_auth_token()
        self._httpd = ThreadingHTTPServer((self._host, self._port), _Handler)
        self._httpd.daemon_threads = True
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
    ap.add_argument("--poll-seconds", type=int, default=15, help="Live 16-pair FX poll interval in seconds (0=disable)")
    ap.add_argument("--activate-brokers", action="store_true", help="Attempt live/demo connection to configured brokers")
    ap.add_argument("--print-check-only", action="store_true", help="Validate config/routing, print JSON, and exit")
    args = ap.parse_args(argv)
    if args.poll_seconds < 0 or args.poll_seconds > 3600:
        raise ContractError("--poll-seconds must be in 0..3600")

    root = Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[3]
    merged: dict[str, str] = dict(os.environ if environ is None else environ)
    if args.env_file is not None:
        merged.update(load_dotenv_file(args.env_file))

    from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
    from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
    from cas_forex_revamp.venue.live_market_stream import ExpandedPublicLiveFxFeedClient

    gate = load_default_forex_valve_gate()
    router = DualShieldBrokerRouter(environ=merged, valve_gate=gate)
    if args.activate_brokers:
        router.activate_all()

    routing_summary = safe_broker_routing_payload(router.routing_snapshot())
    if args.print_check_only:
        print(json.dumps(routing_summary, indent=2))
        return 0

    fixture_path = root / "docs" / "contracts" / "initial-market-stream.json"
    stream_lock = threading.Lock()
    latest_stream: list[dict[str, Any] | None] = [
        json.loads(fixture_path.read_text(encoding="utf-8")) if fixture_path.is_file() else None
    ]
    feed_client = ExpandedPublicLiveFxFeedClient() if args.poll_seconds > 0 else None
    if feed_client is not None:
        try:
            env_stream = feed_client.fetch_market_stream()
            latest_stream[0] = env_stream.to_wire_dict()
        except Exception as exc:
            print(f"[feed] Initial live quote fetch skipped ({type(exc).__name__}); using sealed fixture until next poll.")

    def _read_stream() -> dict[str, Any] | None:
        with stream_lock:
            return latest_stream[0]

    srv = LoopbackCockpitServer(
        repo_root=root,
        host=args.host,
        port=args.port,
        market_stream_reader=_read_stream,
        broker_router_reader=router.routing_snapshot,
    )
    srv.start()
    stop_flag = threading.Event()

    def _poll_loop() -> None:
        while not stop_flag.wait(float(args.poll_seconds)):
            if feed_client is None:
                break
            try:
                env_stream = feed_client.fetch_market_stream()
                with stream_lock:
                    latest_stream[0] = env_stream.to_wire_dict()
                srv.notify_stream_updated()
            except Exception as exc:
                print(f"[feed] Poll skipped ({type(exc).__name__}); keeping last verified snapshot.")

    poller = threading.Thread(target=_poll_loop, name="cas-forex-feed-poll", daemon=True)
    if args.poll_seconds > 0 and feed_client is not None:
        poller.start()

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
