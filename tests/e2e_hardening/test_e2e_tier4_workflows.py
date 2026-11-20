"""E2E Tier 4: Real-World Multi-Step DEMO Operator Workflows (6 tests: E2E-T4-01 .. E2E-T4-06)."""
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
import json
from pathlib import Path
from contextlib import closing
import sqlite3
from types import SimpleNamespace
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cas_forex_revamp.composition.live_cockpit_server import STRICT_CSP, LoopbackCockpitServer
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.composition.trend_regime import REGIME_STRONG_TREND
from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.contracts.primitives import RunScope
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry, FrontierTransportError
from cas_forex_revamp.treasury import CoinbaseOfframpClient, OfframpSecurityError, ProfitSweepVault, RAIL_COINBASE_ACH
from cas_forex_revamp.valve.tks_meta_valve_controller import PeakEquityStore, load_default_forex_valve_gate
from cas_forex_revamp.venue.mt5_broker_bridge import BROKER_HUGOSWAY_MT5, OrderIntent

try:
    from tests.e2e_hardening._e2e_support import (
        D,
        DualBrokerTestRig,
        QUOTES_20,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        build_valve_proposal,
        clean_demo_environ,
        default_policy,
        default_view,
        loopback_http_request,
        require_or_skip_unmerged,
        safe_temp_dir,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        D,
        DualBrokerTestRig,
        QUOTES_20,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        build_valve_proposal,
        clean_demo_environ,
        default_policy,
        default_view,
        loopback_http_request,
        require_or_skip_unmerged,
        safe_temp_dir,
    )


def _ephemeral_ec_pem(path: Path) -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    if hasattr(Path, "chmod"):
        path.chmod(0o600)  # nosec B103: owner-only 0o600 test key


class Tier4WorkflowsE2ETests(unittest.TestCase):
    def test_e2e_t4_01_full_demo_five_tier_trade_lifecycle_to_vault_and_cockpit(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            root = Path(td)
            clk = SteppingClock(T0)
            eng = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=gate, clock=clk)
            open_snap = eng.process_tick(
                quotes=QUOTES_20,
                signal={"symbol": "EURUSD", "side": "BUY", "stop_price": "1.09510", "take_profit_price": "1.10500", "regime": REGIME_STRONG_TREND},
                now=T0,
            )
            by_id = {r["tier_id"]: r for r in open_snap["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 1)
            self.assertEqual(by_id["TIER_5_300"]["open_positions"], 0)
            self.assertEqual(by_id["TIER_5_300"]["last_skip_reason"], "LOT_FLOOR_RISK_EXCEEDED")

            win_q = dict(QUOTES_20)
            win_q["EURUSD"] = (D("1.10520"), D("1.10530"))
            eng.process_tick(quotes=win_q, signal=None, now=T0 + timedelta(minutes=2))
            vault = eng._vaults["TIER_1_CURRENT"]

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                parallel_tiers=eng,
                profit_vault=vault,
                broker_router_reader=lambda: {"schema": "cas-forex.broker-routing/2", "execution_mode": "DEMO", "demo_only": True, "live_trading_locked": True, "chain": []},
            )
            srv.start()
            self.addCleanup(srv.stop)

            st_pt, _, body_pt = loopback_http_request(srv, "GET", "/api/parallel-tiers", headers=srv.auth_headers())
            st_tr, _, body_tr = loopback_http_request(srv, "GET", "/api/treasury", headers=srv.auth_headers())
            st_br, _, body_br = loopback_http_request(srv, "GET", "/api/broker-routing", headers=srv.auth_headers())
            self.assertEqual(st_pt, 200)
            self.assertEqual(st_tr, 200)
            self.assertEqual(st_br, 200)
            pt_doc = json.loads(body_pt.decode("utf-8"))
            tr_doc = json.loads(body_tr.decode("utf-8"))
            br_doc = json.loads(body_br.decode("utf-8"))
            self.assertTrue(br_doc["demo_only"])
            self.assertGreater(Decimal(tr_doc["bank_sweep_reserved_usd"]), Decimal("0"))
            self.assertEqual(pt_doc["tier_count"], 5)

            st_av, _, body_av = loopback_http_request(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
            if st_av == 404:
                require_or_skip_unmerged(self, "Workflow 1 /api/audit-verify integrated check (M2)")
            self.assertEqual(st_av, 200)
            self.assertTrue(json.loads(body_av.decode("utf-8"))["valid"])

    def test_e2e_t4_02_drawdown_breach_refusal_protective_close_and_owner_rearm(self) -> None:
        with safe_temp_dir() as td:
            root = Path(td)
            wf_scope = RunScope("acct-wf2", "wf2", 1, "b1", "p1", "s1", "a1")
            peak_store = PeakEquityStore(root / "peak.sqlite3")
            peak_store.observe_equity(f"{wf_scope.account_id}:{wf_scope.run_id}", current_equity=D("10000"), opening_balance=D("10000"), now=T0)
            peak_store.observe_equity(f"{wf_scope.account_id}:{wf_scope.run_id}", current_equity=D("8950"), now=T0 + timedelta(seconds=10))
            gate = load_default_forex_valve_gate(peak_equity_store=peak_store)

            dd_view = default_view(balance="8950", equity="8950", available_margin="8950")
            dd_view["peak_equity"] = "10000"
            open_prop = build_valve_proposal(kind=ActionKind.OPEN, observed_at=T0 + timedelta(seconds=10))
            open_prop.request.state.scope = wf_scope
            dec_refused = gate.evaluate(open_prop, current_view=dd_view, policy=default_policy(), now=T0 + timedelta(seconds=11))
            self.assertFalse(dec_refused.admitted)
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", dec_refused.hard_veto_reasons)

            amend_prop = build_valve_proposal(
                order_id="ord-wf2-amend",
                action_ref="act-wf2-amend",
                kind=ActionKind.AMEND_STOP,
                limit_price=None,
                stop_price=D("1.09800"),
                take_profit_price=D("1.11000"),
                target_id="pos-wf2-1",
                observed_at=T0 + timedelta(seconds=10),
            )
            self.assertTrue(gate.evaluate(amend_prop, current_view=dd_view, policy=default_policy(), now=T0 + timedelta(seconds=11)).admitted)

            close_prop = build_valve_proposal(
                order_id="ord-wf2-close",
                action_ref="act-wf2-close",
                kind=ActionKind.CLOSE,
                stop_price=None,
                take_profit_price=None,
                target_id="pos-wf2-1",
                observed_at=T0 + timedelta(seconds=10),
            )
            self.assertTrue(gate.evaluate(close_prop, current_view=dd_view, policy=default_policy(), now=T0 + timedelta(seconds=11)).admitted)

            rearm_verifier = SimpleNamespace(
                verify_drawdown_rearm=lambda *, scope_id, request_id, new_peak_equity, now: (
                    scope_id == f"{wf_scope.account_id}:{wf_scope.run_id}" and request_id == "owner-rearm-wf2" and new_peak_equity == D("8950")
                )
            )
            peak_store.rearm_after_drawdown(
                f"{wf_scope.account_id}:{wf_scope.run_id}",
                new_peak_equity=D("8950"),
                owner_verifier=rearm_verifier,
                owner_request_id="owner-rearm-wf2",
                now=T0 + timedelta(seconds=12),
            )
            rearmed_view = default_view(balance="8950", equity="8950", available_margin="8950")
            rearmed_view["peak_equity"] = "8950"
            self.assertTrue(gate.evaluate(open_prop, current_view=rearmed_view, policy=default_policy(), now=T0 + timedelta(seconds=13)).admitted)

            # Also verify ParallelTierEngine refusal handling under M1 gate
            eng = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=gate, clock=SteppingClock(T0))
            eng._peak_store.observe_equity("tier:TIER_1_CURRENT", current_equity=D("400000"), opening_balance=D("400000"), now=T0)
            try:
                eng.process_tick(
                    quotes=QUOTES_20,
                    signal={"symbol": "EURUSD", "side": "BUY", "stop_price": "1.09510", "take_profit_price": "1.11000", "regime": REGIME_STRONG_TREND},
                    now=T0 + timedelta(seconds=15),
                )
            except AttributeError as exc:
                if "refusal_reason" in str(exc):
                    require_or_skip_unmerged(self, "Workflow 2 ParallelTierEngine L694 refusal handling (M1)")
                raise

    def test_e2e_t4_03_mt5_spool_demo_trade_and_freeze_failover_to_oanda_offset(self) -> None:
        with safe_temp_dir() as td:
            rig = DualBrokerTestRig(td)
            router = rig.dual_router()
            router.activate()
            order = OrderIntent(
                order_id="ord-wf3-01",
                action_ref="act-wf3-01",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                take_profit_price=D("1.11000"),
            )
            prop = build_valve_proposal(order_id=order.order_id, action_ref=order.action_ref, stop_price=order.stop_price, take_profit_price=order.take_profit_price)
            dec = rig.gate.require_admissible(prop, current_view=default_view(), policy=default_policy(), now=T0 + timedelta(seconds=1))
            res = router.execute_open(order, valve_decision=dec)
            self.assertEqual(res.executed_on, BROKER_HUGOSWAY_MT5)

            # Simulate frozen HUGOSWAY_MT5 terminal by removing market.json snapshot
            market_file = Path(td) / "hugosway_mt5" / "market_ticks.json"
            if market_file.exists():
                market_file.unlink()
            frozen = router.detect_frozen_positions(BROKER_HUGOSWAY_MT5)
            self.assertIsNotNone(frozen)
            self.assertEqual(len(frozen), 1)
            plan = router.plan_protective_offsets(BROKER_HUGOSWAY_MT5)
            self.assertIsNotNone(plan)
            self.assertTrue(plan.delta_neutral)
            self.assertTrue(plan.fully_funded)

    def test_e2e_t4_04_frontier_model_selection_failure_and_read_only_explainer(self) -> None:
        def flaky_http(url: str, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int):
            return 503, b'{"error":{"message":"upstream busy"}}'

        with safe_temp_dir() as td:
            reg = FrontierModelRegistry(
                environ=clean_demo_environ(
                    CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY,
                    CAS_FOREX_OPENAI_API_KEY=SYNTH_API_KEY,
                    CAS_FOREX_OLLAMA_FALLBACK_ENABLED="1",
                ),
                clock=SteppingClock(T0),
                http_post=flaky_http,
                ollama_http_post=flaky_http,
                resolve_dns=lambda _h: None,
            )
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, ai_model_registry=reg)
            srv.start()
            self.addCleanup(srv.stop)

            sel_raw = json.dumps({"model_id": "openai-astra"}).encode("utf-8")
            hdrs = srv.auth_headers()
            hdrs["Content-Type"] = "application/json"
            hdrs["Content-Length"] = str(len(sel_raw))
            st_sel, _, body_sel = loopback_http_request(srv, "POST", "/api/select-ai-model", headers=hdrs, body=sel_raw)
            self.assertEqual(st_sel, 200)
            self.assertEqual(json.loads(body_sel.decode("utf-8"))["active_model_id"], "openai-astra")

            ask_raw = json.dumps({"question": "Explain active safety gate"}).encode("utf-8")
            hdrs["Content-Length"] = str(len(ask_raw))
            st_ask, _, body_ask = loopback_http_request(srv, "POST", "/api/explainer-ask", headers=hdrs, body=ask_raw)
            self.assertEqual(st_ask, 200)
            ask_doc = json.loads(body_ask.decode("utf-8"))
            self.assertTrue(ask_doc["read_only"])
            self.assertNotIn(SYNTH_API_KEY, json.dumps(ask_doc))

            snap_cb = reg.catalog_snapshot()
            if not (
                "circuit_breakers" in snap_cb
                and "provider_spend" in snap_cb
                and "total_spend_micro_usd" in snap_cb
            ):
                require_or_skip_unmerged(self, "Workflow 4 Frontier circuit breaker / spend metering (M3)")

    def test_e2e_t4_05_treasury_fifty_percent_sweep_idempotent_ach_and_tamper_detection(self) -> None:
        with safe_temp_dir() as td:
            root = Path(td)
            pem_p = root / "cb_ec.pem"
            _ephemeral_ec_pem(pem_p)
            clk = SteppingClock(T0)
            db_path = root / "vault.sqlite3"
            vault = ProfitSweepVault(db_path, clock=clk)
            for idx in range(3):
                vault.record_realized_close(
                    trade_id=f"tr-wf5-{idx}",
                    symbol="EURUSD",
                    broker_id=BROKER_HUGOSWAY_MT5,
                    realized_net_usd=D("100.00"),
                )
            self.assertEqual(vault.bank_sweep_reserved_usd(), D("150.00"))
            cb = CoinbaseOfframpClient(
                key_name="organizations/org-e2e/apiKeys/key-e2e",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-e2e-01",
                http_call=lambda m, u, h, b, t: (200, json.dumps({"id": "cb-wf5-01"}).encode("utf-8")),
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=clk,
            )
            rec = OwnerRecoveryVerifier(db_path=db_path, clock=clk)
            tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-wf5-1",
                reason="Workflow 5 payout",
                verifier=rec,
                recovery_token=tok1,
                coinbase_client=cb,
                idempotency_key="e2e-ach-001",
            )
            self.assertEqual(out["provider_tx_id"], "cb-wf5-01")
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-wf5-2",
                    reason="Duplicate key replay",
                    verifier=rec,
                    recovery_token=tok2,
                    coinbase_client=cb,
                    idempotency_key="e2e-ach-001",
                )

            if not hasattr(vault, "verify_audit_chain"):
                require_or_skip_unmerged(self, "Workflow 5 ProfitSweepVault.verify_audit_chain() (M2)")
            self.assertTrue(vault.verify_audit_chain()["valid"])
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.execute("UPDATE vault_audit SET payload_json = ? WHERE seq = 2", ('{"corrupt":1}',))
                conn.commit()
            tamper_res = vault.verify_audit_chain()
            self.assertFalse(tamper_res["valid"])
            self.assertEqual(tamper_res["broken_at_id"], 2)

    def test_e2e_t4_06_cold_start_cockpit_auth_rotation_and_security_audit(self) -> None:
        with safe_temp_dir() as td:
            root = Path(td)
            tok_file = root / "cockpit.token"
            ui_svc = build_scoped_ui_service(root / "ui_state", clock=SteppingClock(T0))
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                ui_service=ui_svc,
                token_file=tok_file,
            )
            srv.start()
            self.addCleanup(srv.stop)

            st_health, _, body_health = loopback_http_request(srv, "GET", "/api/health")
            self.assertEqual(st_health, 200)
            self.assertFalse(json.loads(body_health.decode("utf-8"))["authenticated"])

            st_unauth, _, _ = loopback_http_request(srv, "GET", "/api/cockpit")
            self.assertEqual(st_unauth, 401)

            old_headers = srv.auth_headers()
            st_ok, _, _ = loopback_http_request(srv, "GET", "/api/cockpit", headers=old_headers)
            self.assertEqual(st_ok, 200)

            srv.rotate_auth_token()
            st_old, _, _ = loopback_http_request(srv, "GET", "/api/cockpit", headers=old_headers)
            self.assertEqual(st_old, 401)
            st_new, _, _ = loopback_http_request(srv, "GET", "/api/cockpit", headers=srv.auth_headers())
            self.assertEqual(st_new, 200)

            st_ui, hdr_ui, _ = loopback_http_request(srv, "GET", f"/ui/index.html?token={srv.auth_token}")
            self.assertEqual(st_ui, 200)
            self.assertEqual(hdr_ui.get("content-security-policy"), STRICT_CSP)


if __name__ == "__main__":
    unittest.main()
