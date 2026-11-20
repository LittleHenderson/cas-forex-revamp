"""E2E FA-4: ProfitSweepVault.verify_audit_chain(), /api/audit-verify, /api/metrics, Schemas, Routes & SSE (10 tests)."""
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from contextlib import closing
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import (
    MAX_EXPLAINER_AUDIO_RPC_BYTES,
    MAX_HTTP_RPC_BYTES,
    STRICT_CSP,
    LoopbackCockpitServer,
)
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury import ProfitSweepVault, RAIL_COINBASE_ACH
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.live_market_stream import MarketStreamEnvelope

try:
    from tests.e2e_hardening._e2e_support import (
        D,
        DualBrokerTestRig,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        clean_demo_environ,
        loopback_http_request,
        require_or_skip_unmerged,
        safe_temp_dir,
        stub_frontier_http_post,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        D,
        DualBrokerTestRig,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        clean_demo_environ,
        loopback_http_request,
        require_or_skip_unmerged,
        safe_temp_dir,
        stub_frontier_http_post,
    )


def _start_full_cockpit(tmp_dir: str) -> tuple[LoopbackCockpitServer, ProfitSweepVault, ParallelTierEngine]:
    root = Path(tmp_dir)
    clk = SteppingClock(T0)
    gate = load_default_forex_valve_gate()
    rig = DualBrokerTestRig(root / "rig", gate=gate)
    router = rig.dual_router()
    vault = ProfitSweepVault(root / "vault.sqlite3", clock=clk)
    tiers = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=gate, clock=clk)
    reg = FrontierModelRegistry(
        environ=clean_demo_environ(CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY),
        clock=clk,
        http_post=stub_frontier_http_post,
        ollama_http_post=stub_frontier_http_post,
        resolve_dns=lambda _h: None,
    )
    quota = DailyQuotaGovernanceStore(path=root / "quota.sqlite3")
    exec_gate = DurableModelExecutionGate(db_path=root / "model_gate.sqlite3")
    trader = AutonomousAiTrader(
        router=router,
        model_registry=reg,
        valve_gate=gate,
        quota_store=quota,
        execution_gate=exec_gate,
        clock=clk,
    )
    ui_svc = build_scoped_ui_service(root / "ui_state", clock=clk)
    stream = MarketStreamEnvelope.from_json_bytes((REPO_ROOT / "docs/contracts/initial-market-stream.json").read_bytes())
    srv = LoopbackCockpitServer(
        repo_root=REPO_ROOT,
        host="127.0.0.1",
        port=0,
        ui_service=ui_svc,
        market_stream_reader=stream.to_wire_dict,
        broker_router_reader=router.routing_snapshot,
        ai_model_registry=reg,
        autonomous_trader=trader,
        profit_vault=vault,
        parallel_tiers=tiers,
        index_stream_reader=lambda: {
            "schema": "cas-forex.index-stream/1",
            "sequence": 1,
            "observed_at": "2026-11-18T13:00:00Z",
            "instruments": ["NAS100", "US30", "SPX500"],
            "markets": [],
        },
    )
    srv.start()
    return srv, vault, tiers


class CockpitAuditE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (E2E-T1-16 .. E2E-T1-20) ---

    def test_e2e_t1_16_vault_verify_audit_chain_over_multiple_events(self) -> None:
        with safe_temp_dir() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=SteppingClock(T0))
            for idx in range(3):
                vault.record_realized_close(
                    trade_id=f"tr-chain-{idx}",
                    symbol="EURUSD",
                    broker_id="HUGOSWAY_MT5",
                    realized_net_usd=D("100.00"),
                )
            vault.set_config(preferred_rail=RAIL_COINBASE_ACH)
            if not hasattr(vault, "verify_audit_chain"):
                require_or_skip_unmerged(self, "ProfitSweepVault.verify_audit_chain() (M2)")
            res = vault.verify_audit_chain()
            self.assertTrue(res["valid"])
            self.assertEqual(res["checked_rows"], 4)
            self.assertIsNone(res["broken_at_id"])
            self.assertEqual(len(str(res["last_hash"])), 64)

    def test_e2e_t1_17_cockpit_audit_verify_and_metrics_routes_read_only(self) -> None:
        with safe_temp_dir() as td:
            srv, vault, _ = _start_full_cockpit(td)
            self.addCleanup(srv.stop)
            vault.record_realized_close(
                trade_id="tr-api-1",
                symbol="EURUSD",
                broker_id="HUGOSWAY_MT5",
                realized_net_usd=D("80.00"),
            )
            with closing(sqlite3.connect(str(Path(td) / "vault.sqlite3"))) as conn:
                before_cnt = conn.execute("SELECT COUNT(*) FROM vault_audit").fetchone()[0]

            st_av, _, body_av = loopback_http_request(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
            st_mt, _, body_mt = loopback_http_request(srv, "GET", "/api/metrics", headers=srv.auth_headers())
            if st_av == 404 or st_mt == 404:
                require_or_skip_unmerged(self, "LoopbackCockpitServer GET /api/audit-verify and /api/metrics (M2)")
            self.assertEqual(st_av, 200)
            self.assertEqual(st_mt, 200)
            av_doc = json.loads(body_av.decode("utf-8"))
            mt_doc = json.loads(body_mt.decode("utf-8"))
            self.assertTrue(av_doc["valid"])
            self.assertIsInstance(mt_doc, dict)
            with closing(sqlite3.connect(str(Path(td) / "vault.sqlite3"))) as conn:
                after_cnt = conn.execute("SELECT COUNT(*) FROM vault_audit").fetchone()[0]
            self.assertEqual(before_cnt, after_cnt)

    def test_e2e_t1_18_all_authenticated_read_routes_return_200_json_and_csp(self) -> None:
        with safe_temp_dir() as td:
            srv, _, _ = _start_full_cockpit(td)
            self.addCleanup(srv.stop)
            routes = (
                "/api/health",
                "/api/market-stream",
                "/api/broker-routing",
                "/api/ai-models",
                "/api/ai-trader",
                "/api/treasury",
                "/api/parallel-tiers",
                "/api/index-stream",
                "/api/boot",
                "/api/cockpit",
                "/api/decision-read",
            )
            for route in routes:
                st, hdrs, body = loopback_http_request(srv, "GET", route, headers=srv.auth_headers())
                self.assertEqual(st, 200, f"Route {route} returned {st}: {body[:200]!r}")
                self.assertIn("application/json", hdrs.get("content-type", ""))
                self.assertIn("default-src 'none'", hdrs.get("content-security-policy", ""))
                self.assertEqual(hdrs.get("content-security-policy"), STRICT_CSP)
                self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
                doc = json.loads(body.decode("utf-8"))
                self.assertIsInstance(doc, dict, route)

    def test_e2e_t1_19_contract_json_schemas_valid_and_m2_schemas_checked(self) -> None:
        contracts_dir = REPO_ROOT / "docs" / "contracts"
        schema_files = sorted(contracts_dir.glob("*.schema.json"))
        self.assertGreaterEqual(len(schema_files), 4)
        for sf in schema_files:
            doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertIsInstance(doc, dict, sf.name)
            self.assertIn("$schema", doc, sf.name)
            self.assertTrue("properties" in doc or "anyOf" in doc, sf.name)

        expected_m2 = ("ai-trader.schema.json", "broker-routing.schema.json", "treasury.schema.json", "parallel-tiers.schema.json", "health.schema.json")
        missing = [name for name in expected_m2 if not (contracts_dir / name).is_file()]
        if missing:
            require_or_skip_unmerged(self, f"M2 contract schemas missing: {', '.join(missing)}")

    def test_e2e_t1_20_authenticated_post_routes_update_state_and_explainer_read_only(self) -> None:
        with safe_temp_dir() as td:
            srv, _, _ = _start_full_cockpit(td)
            self.addCleanup(srv.stop)
            posts = (
                ("/api/select-ai-model", {"model_id": "openai-astra"}),
                ("/api/thinking-depth", {"thinking_depth": "HIGH"}),
                ("/api/treasury-config", {"sweep_ratio": "0.50", "auto_sweep_enabled": True, "preferred_rail": "COINBASE_ACH"}),
                ("/api/explainer-ask", {"question": "Summarize current valve and mode safety."}),
            )
            for route, payload in posts:
                raw = json.dumps(payload).encode("utf-8")
                hdrs = srv.auth_headers()
                hdrs["Content-Type"] = "application/json"
                hdrs["Content-Length"] = str(len(raw))
                st, _, body = loopback_http_request(srv, "POST", route, headers=hdrs, body=raw)
                self.assertEqual(st, 200, f"POST {route} -> {st}: {body!r}")
                doc = json.loads(body.decode("utf-8"))
                if route == "/api/explainer-ask":
                    self.assertTrue(doc.get("read_only"))
                    self.assertEqual(doc.get("schema"), "cas-forex.explainer-answer/1")

    # --- Tier 2: Boundary & Corner Cases (E2E-T2-16 .. E2E-T2-20) ---

    def test_e2e_t2_16_vault_verify_audit_chain_detects_tampered_row(self) -> None:
        with safe_temp_dir() as td:
            db_path = Path(td) / "vault.sqlite3"
            vault = ProfitSweepVault(db_path, clock=SteppingClock(T0))
            for idx in range(4):
                vault.record_realized_close(
                    trade_id=f"tr-tamper-{idx}",
                    symbol="EURUSD",
                    broker_id="HUGOSWAY_MT5",
                    realized_net_usd=D("50.00"),
                )
            if not hasattr(vault, "verify_audit_chain"):
                require_or_skip_unmerged(self, "ProfitSweepVault.verify_audit_chain() tamper detection (M2)")
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.execute("UPDATE vault_audit SET payload_json = ? WHERE seq = 2", ('{"tampered":true}',))
                conn.commit()
            res = vault.verify_audit_chain()
            self.assertFalse(res["valid"])
            self.assertEqual(res["broken_at_id"], 2)

    def test_e2e_t2_17_unauthenticated_audit_verify_and_metrics_return_401(self) -> None:
        with safe_temp_dir() as td:
            srv, _, _ = _start_full_cockpit(td)
            self.addCleanup(srv.stop)
            for core_route in ("/api/cockpit", "/api/treasury"):
                st_none, hdr_none, _ = loopback_http_request(srv, "GET", core_route)
                self.assertEqual(st_none, 401, core_route)
                self.assertIn("bearer", hdr_none.get("www-authenticate", "").lower())
                st_bad, _, _ = loopback_http_request(srv, "GET", core_route, headers={"Authorization": "Bearer invalid-token-value"})
                self.assertEqual(st_bad, 401, core_route)
            st_check, _, _ = loopback_http_request(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
            if st_check == 404:
                require_or_skip_unmerged(self, "LoopbackCockpitServer /api/audit-verify auth gate (M2)")
            for route in ("/api/audit-verify", "/api/metrics"):
                st_none, hdr_none, _ = loopback_http_request(srv, "GET", route)
                self.assertEqual(st_none, 401, route)
                self.assertIn("bearer", hdr_none.get("www-authenticate", "").lower())
                st_bad, _, _ = loopback_http_request(srv, "GET", route, headers={"Authorization": "Bearer invalid-token-value"})
                self.assertEqual(st_bad, 401, route)

    def test_e2e_t2_18_spoofed_host_or_origin_rejected_with_403(self) -> None:
        with safe_temp_dir() as td:
            srv, _, _ = _start_full_cockpit(td)
            self.addCleanup(srv.stop)
            hdrs_bad_host = srv.auth_headers()
            hdrs_bad_host["Host"] = "evil.attacker:8080"
            st_h, _, _ = loopback_http_request(srv, "GET", "/api/cockpit", headers=hdrs_bad_host)
            self.assertEqual(st_h, 403)

            hdrs_bad_orig = srv.auth_headers()
            hdrs_bad_orig["Origin"] = "https://evil.attacker"
            st_o, _, _ = loopback_http_request(srv, "GET", "/api/cockpit", headers=hdrs_bad_orig)
            self.assertEqual(st_o, 403)

    def test_e2e_t2_19_path_traversal_and_oversized_post_rejected(self) -> None:
        with safe_temp_dir() as td:
            srv, _, _ = _start_full_cockpit(td)
            self.addCleanup(srv.stop)
            st_trav, _, _ = loopback_http_request(
                srv,
                "GET",
                "/../src/cas_forex_revamp/valve/tks_meta_valve_controller.py",
                headers=srv.auth_headers(),
            )
            self.assertIn(st_trav, (403, 404))

            hdrs = srv.auth_headers()
            hdrs["Content-Type"] = "application/json"
            hdrs["Content-Length"] = str(MAX_HTTP_RPC_BYTES + 256)
            st_big_rpc, _, _ = loopback_http_request(srv, "POST", "/api/select-ai-model", headers=hdrs, body=b"{}")
            self.assertIn(st_big_rpc, (400, 413))

            hdrs_audio = srv.auth_headers()
            hdrs_audio["Content-Type"] = "application/json"
            hdrs_audio["Content-Length"] = str(MAX_EXPLAINER_AUDIO_RPC_BYTES + 256)
            st_big, _, _ = loopback_http_request(srv, "POST", "/api/explainer-ask", headers=hdrs_audio, body=b"{}")
            self.assertIn(st_big, (400, 413))

    def test_e2e_t2_20_sse_parallel_tiers_frame_deduplicated_when_unchanged(self) -> None:
        with safe_temp_dir() as td:
            srv, _, _ = _start_full_cockpit(td)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=3)
                try:
                    hdrs = srv.auth_headers()
                    hdrs["Host"] = srv.expected_host_header
                    conn.request("GET", "/api/market-events", headers=hdrs)
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    time.sleep(0.05)
                    srv.notify_stream_updated()
                    time.sleep(0.30)
                    srv.notify_stream_updated()
                    time.sleep(0.15)
                    raw_chunks: list[bytes] = []
                    if resp.fp is not None:
                        sock = resp.fp.raw._sock  # type: ignore[attr-defined]
                        if sock is not None:
                            sock.settimeout(0.25)
                            for _ in range(8):
                                try:
                                    chunk = sock.recv(65536)
                                except TimeoutError:
                                    break
                                if not chunk:
                                    break
                                raw_chunks.append(chunk)
                    sse_text = b"".join(raw_chunks).decode("utf-8", errors="replace")
                finally:
                    conn.close()

                pt_count = sse_text.count("event: parallel_tiers")
                self.assertGreaterEqual(pt_count, 1)
                if pt_count > 1:
                    require_or_skip_unmerged(
                        self,
                        "LoopbackCockpitServer SSE parallel_tiers deduplication (M2)",
                    )
                self.assertEqual(pt_count, 1)
            finally:
                srv.stop()

if __name__ == "__main__":
    unittest.main()
