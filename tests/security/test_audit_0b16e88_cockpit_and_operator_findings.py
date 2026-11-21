"""Regression tests for PR #31 Security Audit (0b16e88) Lane C findings: [5], [11], [12], [13], [14], [15], [17]."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import http.client
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
from typing import Any
import unittest
from unittest import mock

from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.composition.live_cockpit_server import (
    LIVE_DIAL_CONFIRM_PHRASE,
    LoopbackCockpitServer,
    _build_mt5_index_snapshot_from_router,
    build_aggression_high_risk_confirmation,
    build_public_index_reference_map,
    stamp_public_index_provenance,
)
from cas_forex_revamp.composition.state_store import (
    ensure_secure_state_directory,
    initialize_shared_runtime_state,
    open_verified_directory_fd,
    open_verified_sqlite_connection,
    verify_non_symlink_sqlite_target,
)
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.operator.frontier_backends import (
    FrontierConfigurationError,
    FrontierModelRegistry,
    FrontierTransportError,
    SupervisedOllamaBinding,
    default_ollama_loopback_post,
)
from cas_forex_revamp.treasury.compounding_controller import (
    CompoundingAndMilestoneController,
    CompoundingControllerError,
)
from cas_forex_revamp.treasury.profit_sweep import ProfitSweepVault

REPO_ROOT = Path(__file__).resolve().parents[2]


def _http_json(
    port: int,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body_obj: Any = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any]]:
    req_hdrs = dict(headers or {})
    payload: bytes | None = None
    if body_obj is not None:
        payload = json.dumps(body_obj).encode("utf-8")
        req_hdrs.setdefault("Content-Type", "application/json")
        req_hdrs["Content-Length"] = str(len(payload))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=payload, headers=req_hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        doc = json.loads(raw.decode("utf-8")) if raw else {}
        return int(resp.status), doc
    finally:
        conn.close()


class Audit0b16e88CockpitAndOperatorFindingsTests(unittest.TestCase):
    """Security regression suite covering Lane C findings [5], [11], [12], [13], [14], [15], [17]."""

    def test_finding_05_index_provenance_strictly_separates_public_and_mt5_streams(self) -> None:
        class _FakeMt5Transport:
            def symbol_tick(self, symbol: str) -> Any:
                if symbol == "NAS100":
                    return SimpleNamespace(bid=Decimal("21000.00"), ask=Decimal("21001.50"))
                return SimpleNamespace(bid=Decimal("44000.00"), ask=Decimal("44002.00"))

        fake_venue = SimpleNamespace(_transport=_FakeMt5Transport(), account=SimpleNamespace(login=7001))
        fake_router = SimpleNamespace(
            venues={"HUGOSWAY_MT5": fake_venue},
            _status={"HUGOSWAY_MT5": "ACTIVE"},
        )

        mt5_doc, mt5_quotes = _build_mt5_index_snapshot_from_router(fake_router)
        self.assertIsNotNone(mt5_doc)
        if mt5_doc is None:
            self.fail('mt5_doc must not be None')
        self.assertIn("NAS100", mt5_quotes)
        self.assertEqual(mt5_doc["feed_mode"], "MT5_DIRECT_SPOOL_50MS")
        self.assertIs(mt5_doc["is_independent_public"], False)
        self.assertEqual(mt5_doc["source_broker_id"], "HUGOSWAY_MT5")
        self.assertEqual(mt5_doc["source_provider"], "MT5_DIRECT_SPOOL_50MS")
        for mrow in mt5_doc["markets"]:
            self.assertIs(mrow["is_independent_public"], False)
            self.assertEqual(mrow["source_broker_id"], "HUGOSWAY_MT5")

        # MT5 stream MUST NEVER be accepted as an independent public reference stream
        with self.assertRaises(ContractError):
            stamp_public_index_provenance(mt5_doc)
        self.assertEqual(build_public_index_reference_map(mt5_doc, ("NAS100", "US30")), {})

        # Genuine independent public feed stamps explicit provenance and builds the 6-key router reference map
        raw_public = {
            "schema": "cas-forex.index-stream/1",
            "feed_mode": "YAHOO_STOOQ_PUBLIC",
            "observed_at": "2026-11-21T12:00:00Z",
            "markets": [
                {"pair": "NAS100", "bid": "21005.25", "ask": "21006.25"},
                {"pair": "US30", "bid": "44010.00", "ask": "44012.00"},
            ],
        }
        stamped_pub = stamp_public_index_provenance(raw_public)
        self.assertIs(stamped_pub["is_independent_public"], True)
        self.assertIsNone(stamped_pub["source_broker_id"])
        self.assertEqual(stamped_pub["source_provider"], "YAHOO_STOOQ_PUBLIC")

        ref_map = build_public_index_reference_map(stamped_pub, ("NAS100",))
        self.assertEqual(set(ref_map.keys()), {"NAS100"})
        nas_ref = ref_map["NAS100"]
        self.assertEqual(
            set(nas_ref.keys()),
            {"bid", "ask", "source_provider", "source_broker_id", "is_independent_public", "observed_at"},
        )
        self.assertEqual(nas_ref["bid"], Decimal("21005.25"))
        self.assertEqual(nas_ref["ask"], Decimal("21006.25"))
        self.assertEqual(nas_ref["source_provider"], "YAHOO_STOOQ_PUBLIC")
        self.assertIsNone(nas_ref["source_broker_id"])
        self.assertIs(nas_ref["is_independent_public"], True)
        self.assertEqual(nas_ref["observed_at"], "2026-11-21T12:00:00Z")

    def test_finding_11_pre_auth_body_monotonic_deadline_size_budget_and_admission_cap(self) -> None:
        # 1. Slow trickle on /api/pair-exchange cannot renew deadline beyond pre_auth_body_deadline_seconds
        srv_fast = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            pre_auth_body_deadline_seconds=0.30,
            max_pre_auth_body_readers=2,
        )
        srv_fast.start()
        self.addCleanup(srv_fast.stop)

        t0 = time.monotonic()
        raw_resp = b""
        with socket.create_connection(("127.0.0.1", srv_fast.bound_port), timeout=3.0) as trickle_sock:
            req_head = (
                f"POST /api/pair-exchange HTTP/1.1\r\nHost: 127.0.0.1:{srv_fast.bound_port}\r\n".encode("ascii")
                + b"Content-Type: application/json\r\nContent-Length: 160\r\n\r\n"
                + b'{"pair_code":"'
            )
            trickle_sock.sendall(req_head)
            for _ in range(4):
                time.sleep(0.05)
                if select.select([trickle_sock], [], [], 0.0)[0]:
                    break
                try:
                    trickle_sock.sendall(b"a")
                except OSError:
                    break
            trickle_sock.settimeout(1.5)
            while True:
                try:
                    chunk = trickle_sock.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                raw_resp += chunk
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 1.5)
        self.assertIn(b"408", raw_resp.splitlines()[0] if raw_resp else b"")
        self.assertIn(b"deadline exceeded", raw_resp)

        st_met, met = _http_json(srv_fast.bound_port, "GET", "/api/metrics", headers=srv_fast.auth_headers())
        self.assertEqual(st_met, 200)
        self.assertGreaterEqual(int(srv_fast._pre_auth_timeouts_total), 1)

        # 2. Oversize Content-Length (> 4096) rejected immediately with 413
        with socket.create_connection(("127.0.0.1", srv_fast.bound_port), timeout=2.0) as big_sock:
            big_sock.sendall(
                f"POST /api/pair-exchange HTTP/1.1\r\nHost: 127.0.0.1:{srv_fast.bound_port}\r\n".encode("ascii")
                + b"Content-Type: application/json\r\nContent-Length: 4097\r\n\r\n"
            )
            big_resp = big_sock.recv(4096)
        self.assertIn(b"413", big_resp.splitlines()[0] if big_resp else b"")

        # 3. Pre-auth admission semaphore caps concurrent pre-auth body reads at 2; owner cockpit stays responsive
        srv_cap = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            pre_auth_body_deadline_seconds=1.5,
            max_pre_auth_body_readers=2,
            max_ordinary_connections=8,
        )
        srv_cap.start()
        self.addCleanup(srv_cap.stop)

        held_socks: list[socket.socket] = []
        try:
            for _ in range(2):
                s = socket.create_connection(("127.0.0.1", srv_cap.bound_port), timeout=2.0)
                held_socks.append(s)
                s.sendall(
                    f"POST /api/pair-exchange HTTP/1.1\r\nHost: 127.0.0.1:{srv_cap.bound_port}\r\n".encode("ascii")
                    + b"Content-Type: application/json\r\nContent-Length: 80\r\n\r\n{"
                )
            time.sleep(0.08)

            # 3rd concurrent pre-auth body request gets immediate 429 PRE_AUTH_BUSY
            st_third, doc_third = _http_json(
                srv_cap.bound_port,
                "POST",
                "/api/pair-exchange",
                body_obj={"pairing_code": "pair-" + "x" * 28},
                timeout=2.0,
            )
            self.assertEqual(st_third, 429)
            self.assertIn("capacity", str(doc_third.get("error", "")))

            # Authenticated owner requests succeed immediately without worker starvation
            t_owner = time.monotonic()
            st_health, _ = _http_json(srv_cap.bound_port, "GET", "/api/health", headers=srv_cap.auth_headers(), timeout=1.5)
            st_cockpit, _ = _http_json(srv_cap.bound_port, "GET", "/api/metrics", headers=srv_cap.auth_headers(), timeout=1.5)
            self.assertEqual(st_health, 200)
            self.assertEqual(st_cockpit, 200)
            self.assertLess(time.monotonic() - t_owner, 0.8)
        finally:
            for s in held_socks:
                try:
                    s.close()
                except OSError:
                    pass

    def test_finding_12_token_rotation_pending_drain_409_and_epoch_guard_aborts_provider_effects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tok_file = root / "cockpit.token"
            provider_http_calls = [0]
            entered_route = threading.Event()
            release_route = threading.Event()

            synth_gem_val = "AIzaSy" + secrets.token_urlsafe(24)

            def _fake_frontier_post(
                url: str,
                headers: dict[str, str],
                body: bytes,
                timeout_s: float,
                max_bytes: int,
            ) -> tuple[int, bytes]:
                provider_http_calls[0] += 1
                resp_doc = {
                    "candidates": [{"content": {"parts": [{"text": '{"answer":"should never execute"}'}]}}]
                }
                return 200, json.dumps(resp_doc).encode("utf-8")

            real_reg = FrontierModelRegistry(
                environ={"CAS_FOREX_GEMINI_API_KEY": synth_gem_val},
                http_post=_fake_frontier_post,
            )

            class _SlowPreEffectRegistry:
                def answer_explainer_question(
                    self,
                    question: str = "",
                    *,
                    context_summary: Any = None,
                    audio_base64: str | None = None,
                    audio_mime_type: str | None = None,
                    execution_gate: Any = None,
                    epoch_guard: Any = None,
                ) -> dict[str, Any]:
                    entered_route.set()
                    release_route.wait(timeout=3.0)
                    return real_reg.answer_explainer_question(
                        question=question,
                        context_summary=context_summary,
                        audio_base64=audio_base64,
                        audio_mime_type=audio_mime_type,
                        execution_gate=execution_gate,
                        epoch_guard=epoch_guard,
                    )

            # Also configure treasury vault + slow recovery verifier to test treasury epoch_guard
            vault = ProfitSweepVault(
                root / "vault.sqlite3",
                scope_id="dual-shield-barbell",
                initial_capital_usd=Decimal("1000.00"),
                clock=lambda: datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc),
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                token_file=tok_file,
                ai_model_registry=_SlowPreEffectRegistry(),
                profit_vault=vault,
                rotation_drain_timeout_seconds=0.10,
            )
            srv.start()
            self.addCleanup(srv.stop)

            old_headers = srv.auth_headers()
            worker_res: list[tuple[int, dict[str, Any]]] = []

            def _run_slow_explainer() -> None:
                try:
                    res_pair = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/explainer-ask",
                        headers=old_headers,
                        body_obj={"question": "What is current drawdown?"},
                        timeout=5.0,
                    )
                    worker_res.append(res_pair)
                except OSError:
                    worker_res.append((0, {"socket_closed": True}))

            th = threading.Thread(target=_run_slow_explainer, daemon=True)
            th.start()
            self.assertTrue(entered_route.wait(timeout=2.0))

            # Rotate while old-epoch lease is still running -> MUST return 409 ROTATION_PENDING_DRAIN (never false 200!)
            st_rot1, rot1 = _http_json(
                srv.bound_port,
                "POST",
                "/api/rotate-token",
                headers=old_headers,
                body_obj={},
                timeout=3.0,
            )
            self.assertEqual(st_rot1, 409)
            self.assertIs(rot1.get("ok"), False)
            self.assertEqual(rot1.get("status"), "ROTATION_PENDING_DRAIN")
            self.assertIs(rot1.get("old_epoch_revoked"), True)
            self.assertIs(rot1.get("rotation_complete"), False)
            self.assertGreaterEqual(int(rot1.get("active_old_leases", 0)), 1)

            # Release slow worker -> epoch_guard MUST abort BEFORE _fake_frontier_post runs!
            release_route.set()
            th.join(timeout=3.0)
            self.assertEqual(provider_http_calls[0], 0)
            self.assertTrue(len(worker_res) == 1)
            if worker_res[0][0] != 0:
                self.assertEqual(worker_res[0][0], 401)
                self.assertEqual(worker_res[0][1].get("code"), "SESSION_EPOCH_REVOKED")

            # Once old-epoch lease has drained, rotating with new token succeeds with 200 ROTATED & active_old_leases == 0
            new_tok = tok_file.read_text(encoding="utf-8").strip()
            st_rot2, rot2 = _http_json(
                srv.bound_port,
                "POST",
                "/api/rotate-token",
                headers={"Authorization": f"Bearer {new_tok}"},
                body_obj={},
                timeout=3.0,
            )
            self.assertEqual(st_rot2, 200)
            self.assertIs(rot2.get("ok"), True)
            self.assertEqual(rot2.get("status"), "ROTATED")
            self.assertIs(rot2.get("rotation_complete"), True)
            self.assertEqual(int(rot2.get("active_old_leases", -1)), 0)

    def test_finding_13_child_symlink_and_unsafe_directory_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside_target = root / "outside_victim.sqlite3"
            outside_target.write_bytes(b"")
            state_dir = root / "state_dir"
            state_dir.mkdir()

            # Attempt to plant a real child symlink or Windows directory junction; also test deterministic lstat/reparse detection
            planted_link = state_dir / "compounding.sqlite3"
            real_link_created = False
            try:
                os.symlink(outside_target, planted_link)
                real_link_created = True
            except OSError:
                if os.name == "nt":
                    junc_target = root / "outside_dir"
                    junc_target.mkdir(exist_ok=True)
                    junc_link = state_dir / "planted_junction"
                    proc = subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(junc_link), str(junc_target)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if proc.returncode == 0 and junc_link.exists():
                        real_link_created = True

            if real_link_created:
                with self.assertRaises(ContractError):
                    ensure_secure_state_directory(state_dir)
                with self.assertRaises(ContractError):
                    initialize_shared_runtime_state({}, explicit_state_dir=state_dir)
                if planted_link.exists() or os.path.lexists(planted_link):
                    with self.assertRaises(CompoundingControllerError):
                        CompoundingAndMilestoneController(planted_link)
                self.assertEqual(outside_target.read_bytes(), b"")

            # Deterministic cross-platform check: simulated child symlink/reparse on compounding.sqlite3 & sidecar
            clean_dir = root / "clean_state"
            ensure_secure_state_directory(clean_dir)
            db_path = clean_dir / "compounding.sqlite3"
            wal_path = clean_dir / "compounding.sqlite3-wal"
            db_path.write_bytes(b"")
            if os.name == "posix":
                os.chmod(db_path, 0o600)

            with mock.patch(
                "cas_forex_revamp.composition.state_store._is_symlink_or_reparse",
                side_effect=lambda p, *_a, **_kw: Path(p).name.startswith("compounding.sqlite3"),
            ):
                with self.assertRaises(ContractError):
                    verify_non_symlink_sqlite_target(db_path)
                with self.assertRaises(ContractError):
                    open_verified_sqlite_connection(db_path)
                with self.assertRaises(CompoundingControllerError):
                    CompoundingAndMilestoneController(db_path)
                with self.assertRaises(ContractError):
                    ensure_secure_state_directory(clean_dir)

            # Sidecar symlink (-wal) is also rejected fail-closed before SQLite touches it
            wal_path.write_bytes(b"")
            if os.name == "posix":
                os.chmod(wal_path, 0o600)
            with mock.patch(
                "cas_forex_revamp.composition.state_store._is_symlink_or_reparse",
                side_effect=lambda p, *_a, **_kw: Path(p).name == "compounding.sqlite3-wal",
            ):
                with self.assertRaises(ContractError):
                    verify_non_symlink_sqlite_target(db_path)
            wal_path.unlink()
            db_path.unlink()

            # On POSIX, initially group/world-writable state directory (0o777) MUST be rejected before fchmod
            if os.name == "posix":
                unsafe_dir = root / "world_writable_state"
                unsafe_dir.mkdir(mode=0o777)
                os.chmod(unsafe_dir, 0o777)
                with self.assertRaises(ContractError):
                    open_verified_directory_fd(unsafe_dir, create=False, label="state directory")

            # Normal verified state_dir + CompoundingAndMilestoneController works cleanly with zero Path.resolve() symlink follow
            ctrl = CompoundingAndMilestoneController(db_path, starting_principal_usd=Decimal("500.00"))
            snap = ctrl.snapshot(current_equity_usd=Decimal("525.00"))
            self.assertEqual(Decimal(str(snap["current_equity_usd"])), Decimal("525.00"))

    def test_finding_14_supervised_ollama_loopback_bypasses_ambient_http_proxy_and_verifies_peer(self) -> None:
        proxy_hits: list[bytes] = []
        ollama_headers: list[str] = []

        proxy_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_srv.bind(("127.0.0.1", 0))
        proxy_srv.listen(4)
        proxy_port = int(proxy_srv.getsockname()[1])

        ollama_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ollama_srv.bind(("127.0.0.1", 0))
        ollama_srv.listen(4)
        ollama_port = int(ollama_srv.getsockname()[1])

        stop_evt = threading.Event()

        def _proxy_loop() -> None:
            proxy_srv.settimeout(0.1)
            while not stop_evt.is_set():
                try:
                    conn, _ = proxy_srv.accept()
                except OSError:
                    continue
                with conn:
                    conn.settimeout(0.5)
                    try:
                        proxy_hits.append(conn.recv(4096))
                    except OSError:
                        proxy_hits.append(b"<accepted>")

        def _ollama_loop() -> None:
            ollama_srv.settimeout(0.1)
            while not stop_evt.is_set():
                try:
                    conn, _ = ollama_srv.accept()
                except OSError:
                    continue
                with conn:
                    conn.settimeout(1.0)
                    buf = bytearray()
                    while b"\r\n\r\n" not in buf:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        buf.extend(chunk)
                    if not buf:
                        continue
                    head_bytes, rest = bytes(buf).split(b"\r\n\r\n", 1)
                    head_txt = head_bytes.decode("latin-1")
                    ollama_headers.append(head_txt)
                    clen = 0
                    for line in head_txt.split("\r\n")[1:]:
                        if line.lower().startswith("content-length:"):
                            clen = int(line.split(":", 1)[1].strip())
                    body_buf = bytearray(rest)
                    while len(body_buf) < clen:
                        c2 = conn.recv(4096)
                        if not c2:
                            break
                        body_buf.extend(c2)
                    resp_body = b'{"message":{"content":"direct-loopback-ok"}}'
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                        + resp_body
                    )

        t_proxy = threading.Thread(target=_proxy_loop, daemon=True)
        t_ollama = threading.Thread(target=_ollama_loop, daemon=True)
        t_proxy.start()
        t_ollama.start()

        def _cleanup_listeners() -> None:
            stop_evt.set()
            for s in (proxy_srv, ollama_srv):
                try:
                    s.close()
                except OSError:
                    pass
            t_proxy.join(timeout=1.0)
            t_ollama.join(timeout=1.0)

        self.addCleanup(_cleanup_listeners)

        sup_secret = secrets.token_urlsafe(32)
        dummy_sha = "a" * 64
        binding = SupervisedOllamaBinding(
            pid=os.getpid(),
            start_time="2026-11-21T12:00:00Z",
            executable_sha256=dummy_sha,
            model_manifest_sha256=dummy_sha,
            weights_sha256=dummy_sha,
            template_sha256=dummy_sha,
            tokenizer_sha256=dummy_sha,
            endpoint_url=f"http://127.0.0.1:{ollama_port}/api/chat",
            auth_secret=sup_secret,
            receipt_verify_key=b"k" * 32,
            process_verifier=lambda _b: True,
            artifact_verifier=lambda _b: True,
            listener_ownership_verifier=lambda _b: True,
        )

        proxy_url = f"http://127.0.0.1:{proxy_port}"
        env_patch = {
            "HTTP_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
            "all_proxy": proxy_url,
            "NO_PROXY": "",
            "no_proxy": "",
        }
        with mock.patch.dict(os.environ, env_patch, clear=False):
            st, raw = default_ollama_loopback_post(
                binding.endpoint_url,
                {"Content-Type": "application/json"},
                b'{"model":"qwen3:0.6b","prompt":"confidential-strategy"}',
                3.0,
                65536,
                supervised_binding=binding,
            )

        self.assertEqual(st, 200)
        self.assertIn(b"direct-loopback-ok", raw)
        self.assertEqual(proxy_hits, [])
        self.assertEqual(len(ollama_headers), 1)
        self.assertIn(f"X-CAS-Ollama-Supervisor-Token: {sup_secret}", ollama_headers[0])

        # Verify post-connect binding failure aborts BEFORE sending supervisor bearer or prompt over socket
        checks = [0]

        def _fail_on_connect_recheck(_b: SupervisedOllamaBinding) -> bool:
            checks[0] += 1
            return checks[0] == 1

        hijacked_binding = SupervisedOllamaBinding(
            pid=os.getpid(),
            start_time="2026-11-21T12:00:00Z",
            executable_sha256=dummy_sha,
            model_manifest_sha256=dummy_sha,
            weights_sha256=dummy_sha,
            template_sha256=dummy_sha,
            tokenizer_sha256=dummy_sha,
            endpoint_url=f"http://127.0.0.1:{ollama_port}/api/chat",
            auth_secret=sup_secret,
            receipt_verify_key=b"k" * 32,
            process_verifier=lambda _b: True,
            artifact_verifier=lambda _b: True,
            listener_ownership_verifier=_fail_on_connect_recheck,
        )
        ollama_headers.clear()
        with self.assertRaises((FrontierConfigurationError, FrontierTransportError)):
            default_ollama_loopback_post(
                hijacked_binding.endpoint_url,
                {"Content-Type": "application/json"},
                b'{"model":"qwen3:0.6b"}',
                3.0,
                65536,
                supervised_binding=hijacked_binding,
            )
        self.assertEqual(ollama_headers, [])

    def test_finding_15_per_launch_bearer_rotated_across_restarts_and_sessions_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tok_file = root / "cockpit.token"

            dial15 = AggressionDialStore(root / "dial15.sqlite3")
            srv1 = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=tok_file, aggression_dial=dial15)
            srv1.start()
            tok1 = srv1.auth_token
            self.assertEqual(tok_file.read_text(encoding="utf-8").strip(), tok1)

            # Mint and exchange a paired device session under launch #1
            st_mint, mint_doc = _http_json(
                srv1.bound_port,
                "POST",
                "/api/pair-code",
                headers=srv1.auth_headers(),
                body_obj={},
            )
            self.assertEqual(st_mint, 200)
            st_ex, ex_doc = _http_json(
                srv1.bound_port,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": mint_doc["pair_code"]},
            )
            self.assertEqual(st_ex, 200)
            dev_tok1 = str(ex_doc.get("device_token") or ex_doc.get("session_token") or ex_doc.get("token"))

            st_ok, _ = _http_json(
                srv1.bound_port,
                "GET",
                "/api/aggression-dial",
                headers={"Authorization": f"Bearer {dev_tok1}"},
            )
            self.assertEqual(st_ok, 200)
            srv1.stop()

            # Restart launch #2 pointing at the SAME token_file -> MUST mint brand-new bearer & reject prior tokens
            srv2 = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=tok_file, aggression_dial=dial15)
            srv2.start()
            self.addCleanup(srv2.stop)
            tok2 = srv2.auth_token
            self.assertNotEqual(tok2, tok1)
            self.assertEqual(tok_file.read_text(encoding="utf-8").strip(), tok2)

            st_stale_owner, _ = _http_json(
                srv2.bound_port,
                "GET",
                "/api/aggression-dial",
                headers={"Authorization": f"Bearer {tok1}"},
            )
            self.assertEqual(st_stale_owner, 401)

            st_stale_dev, _ = _http_json(
                srv2.bound_port,
                "GET",
                "/api/aggression-dial",
                headers={"Authorization": f"Bearer {dev_tok1}"},
            )
            self.assertEqual(st_stale_dev, 401)

            st_fresh, _ = _http_json(
                srv2.bound_port,
                "GET",
                "/api/aggression-dial",
                headers={"Authorization": f"Bearer {tok2}"},
            )
            self.assertEqual(st_fresh, 200)

            # Malformed pre-existing token file MUST still fail closed rather than silently overwriting corrupted custody
            bad_tok_file = root / "corrupt.token"
            bad_tok_file.write_text("short-low-entropy\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(bad_tok_file, 0o600)
            srv_corrupt = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=bad_tok_file)
            with self.assertRaises(ContractError):
                srv_corrupt.start()

            # Explicit in-memory auth_token without token_file remains supported for test harnesses
            explicit_tok = secrets.token_urlsafe(32)
            srv_mem = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, auth_token=explicit_tok)
            srv_mem.start()
            self.addCleanup(srv_mem.stop)
            self.assertEqual(srv_mem.auth_token, explicit_tok)

    def test_finding_17_routing_state_read_failure_fails_closed_with_target_bound_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            def _raise_routing_err() -> dict[str, Any]:
                raise RuntimeError("routing state sqlite locked")

            for idx, reader in enumerate(
                (
                    _raise_routing_err,
                    lambda: None,  # type: ignore[return-value]
                    lambda: {},
                    None,
                )
            ):
                dial = AggressionDialStore(root / f"dial_err_{idx}.sqlite3")
                srv = LoopbackCockpitServer(
                    repo_root=REPO_ROOT,
                    port=0,
                    broker_router_reader=reader,
                    aggression_dial=dial,
                )
                srv.start()
                try:
                    st_get, doc_get = _http_json(srv.bound_port, "GET", "/api/aggression-dial", headers=srv.auth_headers())
                    self.assertEqual(st_get, 200)
                    self.assertIs(doc_get["live_mode"], True)
                    self.assertIn(doc_get["execution_mode"], ("LIVE", "LIVE_OR_UNKNOWN"))

                    # Even < 80 bps without bound confirmation fails closed in LIVE_OR_UNKNOWN
                    st_55, err_55 = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/aggression-dial",
                        headers=srv.auth_headers(),
                        body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 55},
                    )
                    self.assertEqual(st_55, 409)
                    self.assertEqual(err_55["code"], "HIGH_RISK_CONFIRMATION_REQUIRED")
                    self.assertIn("LIVE_OR_UNKNOWN", str(err_55.get("error", "")))

                    # Unbound high_risk_confirmed=True boolean is REJECTED
                    st_unbound, _ = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/aggression-dial",
                        headers=srv.auth_headers(),
                        body_obj={
                            "action": "SET_TIER_RISK_BPS",
                            "tier_id": "TIER_5_300",
                            "risk_bps": 95,
                            "high_risk_confirmed": True,
                        },
                    )
                    self.assertEqual(st_unbound, 409)

                    # Confirmation bound to DIFFERENT target_bps or tier_id is REJECTED
                    wrong_doc, wrong_phrase = build_aggression_high_risk_confirmation(
                        dial.scope_id,
                        "SET_TIER_RISK_BPS",
                        tier_id="TIER_5_300",
                        target_bps=85,
                    )
                    st_mismatch, _ = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/aggression-dial",
                        headers=srv.auth_headers(),
                        body_obj={
                            "action": "SET_TIER_RISK_BPS",
                            "tier_id": "TIER_5_300",
                            "risk_bps": 95,
                            "high_risk_confirmed": True,
                            "high_risk_confirmation": wrong_doc,
                        },
                    )
                    self.assertEqual(st_mismatch, 409)
                    self.assertIn(LIVE_DIAL_CONFIRM_PHRASE, wrong_phrase)

                    # Exact target-bound confirmation succeeds
                    exact_doc, exact_phrase = build_aggression_high_risk_confirmation(
                        dial.scope_id,
                        "SET_TIER_RISK_BPS",
                        tier_id="TIER_5_300",
                        target_bps=95,
                    )
                    st_ok_doc, ok_doc = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/aggression-dial",
                        headers=srv.auth_headers(),
                        body_obj={
                            "action": "SET_TIER_RISK_BPS",
                            "tier_id": "TIER_5_300",
                            "risk_bps": 95,
                            "high_risk_confirmed": True,
                            "high_risk_confirmation": exact_doc,
                        },
                    )
                    self.assertEqual(st_ok_doc, 200)
                    self.assertEqual(ok_doc["tiers_by_id"]["TIER_5_300"]["risk_bps"], 95)

                    # Exact target-bound confirmation_phrase also succeeds for master risk bps
                    _, master_phrase = build_aggression_high_risk_confirmation(
                        dial.scope_id,
                        "SET_MASTER_RISK_BPS",
                        target_bps=55,
                    )
                    st_ok_ph, ok_ph = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/aggression-dial",
                        headers=srv.auth_headers(),
                        body_obj={
                            "action": "SET_MASTER_RISK_BPS",
                            "risk_bps": 55,
                            "high_risk_confirmed": True,
                            "confirmation_phrase": master_phrase,
                        },
                    )
                    self.assertEqual(st_ok_ph, 200)
                    self.assertEqual(ok_ph["master_risk_bps"], 55)
                finally:
                    srv.stop()

            # Positive DEMO proof (execution_mode=="DEMO" and not live_armed) permits normal DEMO edits
            demo_dial = AggressionDialStore(root / "dial_demo.sqlite3")
            srv_demo = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=lambda: {"execution_mode": "DEMO", "live_trading_armed": False},
                aggression_dial=demo_dial,
            )
            srv_demo.start()
            self.addCleanup(srv_demo.stop)
            st_demo, doc_demo = _http_json(
                srv_demo.bound_port,
                "POST",
                "/api/aggression-dial",
                headers=srv_demo.auth_headers(),
                body_obj={"action": "SET_MASTER_RISK_BPS", "risk_bps": 90},
            )
            self.assertEqual(st_demo, 200)
            self.assertEqual(doc_demo["master_risk_bps"], 90)
            self.assertEqual(doc_demo["execution_mode"], "DEMO")


if __name__ == "__main__":
    unittest.main()
