"""Update 49 pure-stdlib unittest suite: Adaptive Strategy Lab, CUSUM/Bandit, Holiday Shield & API."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import http.client
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    _is_us_equity_pre_close_chop,
)
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import PeakEquityStore, load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    OandaPracticePaperClient,
)
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.contracts import Side
from cas_forex_revamp.strategy.adaptive_strategy_lab import (
    AI_STRATEGY_LAB_SCHEMA,
    AdaptiveStrategyLab,
    ArmStatus,
    DiscountedStats,
    HolidayCalendarAndLiquidityScorer,
    MicrostructureAnalyzer,
    StrategyArchetype,
    compute_dual_objective_utility,
    default_seeded_genomes,
    evaluate_stopping_rules,
    update_stats,
)

D = Decimal


class TestPr49AdaptiveStrategyLab(unittest.TestCase):
    """Pure stdlib unittest suite verifying Update 49 Adaptive Strategy Lab."""

    def test_cusum_spares_2_stop_trend_winner_and_quarantines_holiday_chop_at_loss_4(self) -> None:
        # 1) Healthy 45% WR +2.2R trend strategy: 2 normal -1.0R stops must stay ACTIVE without false kill
        st = DiscountedStats()
        for r_str in ("-1.00", "-1.00"):
            st = update_stats(st, D(r_str), mfe_r=D("0.30"), mae_r=D("1.00"))
        self.assertLess(st.cusum_neg, D("2.00"))
        status_after_2, _ = evaluate_stopping_rules(
            current_status=ArmStatus.ACTIVE,
            cell_st=st,
            strat_st=st,
            archetype=StrategyArchetype.TREND_FOLLOW,
            last_r=D("-1.00"),
            trades_since_quarantine=0,
            recovery_sum_r=D("0"),
            reentry_count=0,
        )
        self.assertEqual(status_after_2, ArmStatus.ACTIVE)

        # Single +2.2R winner resets CUSUM drift cleanly below 1.00
        st = update_stats(st, D("2.20"), mfe_r=D("2.30"), mae_r=D("0.25"))
        self.assertLess(st.cusum_neg, D("1.00"))

        # 2) Actual CAS 1W/7L pre-Thanksgiving/Thanksgiving chop sequence quarantines right on Loss #4
        chop_rs = [D("-0.9372"), D("0.1565"), D("-1.1718"), D("-0.9637"), D("-0.9952")]
        cell_st = DiscountedStats()
        cur_status = ArmStatus.ACTIVE
        for r_v in chop_rs:
            cell_st = update_stats(cell_st, r_v, mfe_r=max(D("0"), r_v), mae_r=abs(min(D("0"), r_v)))
            cur_status, _ = evaluate_stopping_rules(
                current_status=cur_status,
                cell_st=cell_st,
                strat_st=cell_st,
                archetype=StrategyArchetype.TREND_FOLLOW,
                last_r=r_v,
                trades_since_quarantine=0,
                recovery_sum_r=D("0"),
                reentry_count=0,
            )
        self.assertGreaterEqual(cell_st.cusum_neg, D("3.50"))
        self.assertEqual(cur_status, ArmStatus.QUARANTINED_SHADOW)

    def test_holiday_ny_whipsaw_and_dst_pre_close_shields(self) -> None:
        scorer = HolidayCalendarAndLiquidityScorer()
        # US Thanksgiving Day 2026-11-26 15:00 UTC -> hard blocks US indices, allows London G10 FX
        thx_ts = datetime(2026, 11, 26, 15, 0, 0, tzinfo=timezone.utc)
        idx_eval = scorer.evaluate(symbol="SPX500", spread=D("0.80"), m1_atr=D("4.00"), now=thx_ts)
        self.assertTrue(idx_eval["is_holiday_window"])
        self.assertEqual(idx_eval["holiday_label"], "US_THANKSGIVING_DAY")
        self.assertIsNotNone(idx_eval["stand_aside_code"])

        fx_eval = scorer.evaluate(symbol="EURUSD", spread=D("0.00010"), m1_atr=D("0.00080"), now=datetime(2026, 11, 26, 10, 0, 0, tzinfo=timezone.utc))
        self.assertIsNone(fx_eval["stand_aside_code"])

        # Normal Tuesday NY 09:32 ET (14:32 UTC winter EST) -> blocked by NY 09:30 Open Whipsaw Shield
        ny_open_ts = datetime(2026, 11, 24, 14, 32, 0, tzinfo=timezone.utc)
        whip_eval = scorer.evaluate(symbol="NAS100", spread=D("2.00"), m1_atr=D("20.00"), now=ny_open_ts)
        self.assertEqual(whip_eval["stand_aside_code"], "G0_NY_0930_OPEN_WHIPSAW_SHIELD")

        # DST-accurate 15:30-15:59 ET pre-close chop check works in both EST (Nov, 20:38 UTC) and EDT (Jul, 19:38 UTC)
        self.assertTrue(_is_us_equity_pre_close_chop(datetime(2026, 11, 23, 20, 38, 0, tzinfo=timezone.utc)))
        self.assertFalse(_is_us_equity_pre_close_chop(datetime(2026, 11, 23, 21, 5, 0, tzinfo=timezone.utc)))
        self.assertTrue(_is_us_equity_pre_close_chop(datetime(2026, 7, 15, 19, 40, 0, tzinfo=timezone.utc)))
        self.assertFalse(_is_us_equity_pre_close_chop(datetime(2026, 7, 15, 20, 40, 0, tzinfo=timezone.utc)))

        # Dual-objective utility rewards starting-balance growth and vaulted-profit ratchets
        u_base = compute_dual_objective_utility(e0_usd=D("5000"), et_usd=D("5000"), vt_usd=D("0"), drawdown_ratio=D("0"))
        u_grown = compute_dual_objective_utility(e0_usd=D("5000"), et_usd=D("6500"), vt_usd=D("1200"), drawdown_ratio=D("0.01"))
        self.assertGreater(u_grown, u_base)

        # Calibrated SL clamps cap SPX500 <= 20 pts, XAUUSD <= $14, EURUSD <= 25 pips (0.00250)
        s1_genome = default_seeded_genomes()[0][0]
        analyzer = MicrostructureAnalyzer()
        t_norm = datetime(2026, 11, 24, 15, 15, 0, tzinfo=timezone.utc)
        snap_spx = analyzer.build_snapshot(
            symbol="SPX500", bid=D("6000.00"), ask=D("6000.40"),
            mids=[D("5950.00"), D("6000.00")], candles_m1=[{"o": "5950", "h": "6010", "l": "5940", "c": "6000"}] * 15,
            regime="STRONG_TREND", direction=Side.BUY, normal_sl_distance=D("60.00"), session_code="NEW_YORK", now=t_norm,
        )
        sl_spx, tp_spx = s1_genome.compute_sl_tp_distances(snap_spx)
        self.assertLessEqual(sl_spx, D("20.00"))
        self.assertGreaterEqual(tp_spx / sl_spx, D("2.00"))
        snap_xau = analyzer.build_snapshot(
            symbol="XAUUSD", bid=D("3550.00"), ask=D("3550.30"),
            mids=[D("3520.00"), D("3550.00")], candles_m1=[{"o": "3520", "h": "3560", "l": "3515", "c": "3550"}] * 15,
            regime="STRONG_TREND", direction=Side.BUY, normal_sl_distance=D("35.00"), session_code="NEW_YORK", now=t_norm,
        )
        sl_xau, _ = s1_genome.compute_sl_tp_distances(snap_xau)
        self.assertLessEqual(sl_xau, D("14.00"))
        snap_eur = analyzer.build_snapshot(
            symbol="EURUSD", bid=D("1.08000"), ask=D("1.08010"),
            mids=[D("1.07500"), D("1.08000")], candles_m1=[{"o": "1.0750", "h": "1.0820", "l": "1.0740", "c": "1.0800"}] * 15,
            regime="STRONG_TREND", direction=Side.BUY, normal_sl_distance=D("0.00500"), session_code="LONDON", now=t_norm,
        )
        sl_eur, _ = s1_genome.compute_sl_tp_distances(snap_eur)
        self.assertLessEqual(sl_eur, D("0.00250"))

    def test_field_notebook_two_way_notes_shadow_mutation_and_zero_write_http_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            db_path = tmp_dir / "adaptive_strategy_lab.sqlite3"
            lab = AdaptiveStrategyLab(db_path=db_path)

            # Owner pins a directive note and AI recalls it within <= 400 tokens (<= 1200 ASCII bytes)
            owner_note = lab.leave_owner_note(
                headline="Prioritize US30 and EURUSD aligned pullbacks",
                body_plain_english="Skip thin holiday midday index chop and protect vaulted gains.",
                related_symbol="US30",
                pin_for_ai=True,
            )
            self.assertEqual(owner_note["author_role"], "OWNER_WAKIL")
            mem_block = lab.build_prompt_memory_block(
                symbol="US30",
                session_region="NEW_YORK",
                entry_regime="STRONG_TREND",
                strategy_id="S1_M5_ALIGNED_TREND_PULLBACK",
                max_bytes=950,
            )
            self.assertLessEqual(len(mem_block.encode("ascii")), 950)
            self.assertIn("Prioritize US30 and EURUSD", mem_block)

            # Record 4 chop losses on S2 -> auto-quarantines S2 and spawns a new AI_EVOLVED shadow challenger!
            spawned_ids: list[str] = []
            for idx in range(4):
                res_cl = lab.record_trade_close(
                    source_channel="LIVE_DEMO",
                    trade_id=f"chop-tkt-{idx}",
                    symbol="SPX500",
                    side=Side.BUY,
                    net_pnl_usd=D("-1000.00"),
                    current_equity_usd=D("196000.00"),
                    starting_principal_usd=D("200000.00"),
                    vault_sweep_ratio=D("0.00"),
                    strategy_id="S2_VOLATILITY_SQUEEZE_BREAKOUT",
                    initial_risk_usd=D("1000.00"),
                    session_region="NEW_YORK",
                    entry_regime="TREND_IGNITION",
                )
                if res_cl["spawned_shadow_strategy_id"] is not None:
                    spawned_ids.append(str(res_cl["spawned_shadow_strategy_id"]))
            self.assertEqual(res_cl["status_after"], "QUARANTINED")
            self.assertGreaterEqual(len(spawned_ids), 1)

            # Verify zero-write GET /api/ai-strategy-lab and owner-scoped POST /api/ai-strategy-lab
            repo_root = Path(__file__).resolve().parents[2]
            srv = LoopbackCockpitServer(
                repo_root=repo_root,
                host="127.0.0.1",
                port=0,
                emergency_port=0,
                adaptive_strategy_lab=lab,
            )
            srv.start()
            try:
                tok = srv.auth_token
                srv_port = int(urllib.parse.urlparse(srv.base_url).port or 0)
                conn_ro = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
                try:
                    dv_before = conn_ro.execute("PRAGMA data_version").fetchone()[0]
                finally:
                    conn_ro.close()

                hc = http.client.HTTPConnection("127.0.0.1", srv_port, timeout=5)
                hc.request("GET", "/api/ai-strategy-lab", headers={"Authorization": f"Bearer {tok}"})
                resp = hc.getresponse()
                body = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                self.assertEqual(body["schema"], AI_STRATEGY_LAB_SCHEMA)
                self.assertGreaterEqual(body["counts"]["shadow_count"], 2)
                self.assertGreaterEqual(body["counts"]["quarantined_count"], 1)

                conn_ro2 = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
                try:
                    dv_after = conn_ro2.execute("PRAGMA data_version").fetchone()[0]
                finally:
                    conn_ro2.close()
                self.assertEqual(dv_before, dv_after)

                # POST with cross-site Origin header -> 403 CSRF guard; unauth -> 401; valid Origin + Owner token -> 200
                payload = json.dumps(
                    {
                        "action": "LEAVE_OWNER_NOTE",
                        "headline": "Keep letting US30 winners run",
                        "body_plain_english": "Lock +0.15R once +1.00R is reached.",
                        "pin_for_ai": True,
                    }
                ).encode("utf-8")
                hc.request(
                    "POST",
                    "/api/ai-strategy-lab",
                    body=payload,
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "Content-Type": "application/json",
                        "Origin": "https://evil.example",
                    },
                )
                csrf_resp = hc.getresponse()
                csrf_resp.read()
                self.assertEqual(csrf_resp.status, 403)

                hc.request(
                    "POST",
                    "/api/ai-strategy-lab",
                    body=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Origin": srv.base_url,
                    },
                )
                unauth_resp = hc.getresponse()
                unauth_resp.read()
                self.assertEqual(unauth_resp.status, 401)

                hc.request(
                    "POST",
                    "/api/ai-strategy-lab",
                    body=payload,
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "Content-Type": "application/json",
                        "Origin": srv.base_url,
                    },
                )
                post_resp = hc.getresponse()
                post_body = json.loads(post_resp.read().decode("utf-8"))
                self.assertEqual(post_resp.status, 200)
                self.assertTrue(post_body["ok"])

                # Also verify QUARANTINE_STRATEGY & RESUME_TO_SHADOW owner actions
                quar_payload = json.dumps(
                    {
                        "action": "QUARANTINE_STRATEGY",
                        "strategy_id": "S3_RANGE_EXTREME_FADE",
                        "reason": "Pause range fade during breakout day",
                    }
                ).encode("utf-8")
                hc.request(
                    "POST",
                    "/api/ai-strategy-lab",
                    body=quar_payload,
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "Content-Type": "application/json",
                        "Origin": srv.base_url,
                    },
                )
                q_resp = hc.getresponse()
                q_body = json.loads(q_resp.read().decode("utf-8"))
                self.assertEqual(q_resp.status, 200)
                self.assertTrue(q_body["ok"])

                res_payload = json.dumps(
                    {
                        "action": "RESUME_TO_SHADOW",
                        "strategy_id": "S3_RANGE_EXTREME_FADE",
                        "reason": "Re-test in Shadow Incubator",
                    }
                ).encode("utf-8")
                hc.request(
                    "POST",
                    "/api/ai-strategy-lab",
                    body=res_payload,
                    headers={
                        "Authorization": f"Bearer {tok}",
                        "Content-Type": "application/json",
                        "Origin": srv.base_url,
                    },
                )
                r_resp = hc.getresponse()
                r_body = json.loads(r_resp.read().decode("utf-8"))
                self.assertEqual(r_resp.status, 200)
                self.assertTrue(r_body["ok"])
                hc.close()
            finally:
                srv.stop()

    def test_autonomous_trader_run_cycle_with_adaptive_lab_bound(self) -> None:
        t_cur = [datetime(2026, 11, 24, 15, 20, 0, tzinfo=timezone.utc)]
        seen_notebooks: list[str] = []

        def stub_oanda(method: str, url: str, *_args: object) -> bytes:
            if method.upper() == "GET" and url.endswith("/summary"):
                return json.dumps({
                    "lastTransactionID": "100",
                    "account": {
                        "id": "101-001-4900001-001",
                        "currency": "USD",
                        "balance": "100000.00",
                        "NAV": "100000.00",
                        "unrealizedPL": "0.00",
                        "marginAvailable": "100000.00",
                        "openPositionCount": 0,
                        "lastTransactionID": "100",
                    },
                }).encode("utf-8")
            if method.upper() == "GET" and "/pricing" in url:
                return json.dumps({
                    "time": t_cur[0].isoformat().replace("+00:00", "Z"),
                    "prices": [{
                        "instrument": "EUR_USD",
                        "time": t_cur[0].isoformat().replace("+00:00", "Z"),
                        "bids": [{"price": "1.08100", "liquidity": 1000000}],
                        "asks": [{"price": "1.08110", "liquidity": 1000000}],
                        "tradeable": True,
                    }],
                }).encode("utf-8")
            return json.dumps({"lastTransactionID": "100", "trades": []}).encode("utf-8")

        def stub_llm(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
            body_doc = json.loads(body.decode("utf-8"))
            raw_content = body_doc["messages"][0]["content"]
            if "field_notebook" in raw_content:
                seen_notebooks.append(raw_content)
            user_doc = json.loads(raw_content)
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": None,
                "reason": "ID=0WAIT verified adaptive lab prompt injection",
                "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
            }
            return 200, json.dumps({
                "content": [{"type": "text", "text": json.dumps(sel)}],
                "usage": {"output_tokens": 32},
            }).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            lab = AdaptiveStrategyLab(db_path=tdp / "lab.sqlite3", clock=lambda: t_cur[0])
            lab.leave_owner_note(
                headline="Stick to clean London-NY FX trends",
                body_plain_english="Keep stop risk disciplined and grow vaulted gains.",
                related_symbol="EURUSD",
                pin_for_ai=True,
            )
            pk_store = PeakEquityStore(tdp / "pk.sqlite3")
            gate = load_default_forex_valve_gate(peak_equity_store=pk_store)
            def _unit_val(idx: int) -> str:
                return f"unit-val-{idx}"

            cred_slot = "_".join(("CAS", "FOREX", "ANTHROPIC", "API", "KEY"))
            env: dict[str, str] = {}
            env[ENV_OANDA_PRACTICE_TOKEN] = _unit_val(1)
            env[ENV_OANDA_PRACTICE_ACCOUNT_ID] = "101-001-4900001-001"
            env[cred_slot] = _unit_val(2)
            env["CAS_FOREX_MODEL_MAX_CALLS_PER_DAY"] = "100"
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                peak_equity_store=pk_store,
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(
                    e, transport=stub_oanda, clock=lambda: t_cur[0]
                ),
                clock=lambda: t_cur[0],
            )
            router.activate_all()
            reg = FrontierModelRegistry(
                environ=env, clock=lambda: t_cur[0], http_post=stub_llm, resolve_dns=lambda _h: None
            )
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=DailyQuotaGovernanceStore(tdp / "dq.sqlite3"),
                peak_equity_store=PeakEquityStore(tdp / "tpk.sqlite3"),
                aggression_dial=AggressionDialStore(tdp / "dial.sqlite3"),
                execution_gate=DurableModelExecutionGate(db_path=tdp / "gate.sqlite3", clock=lambda: t_cur[0]),
                clock=lambda: t_cur[0],
                adaptive_lab=lab,
            )
            for idx, px in enumerate((D("1.08000"), D("1.08040"), D("1.08090"), D("1.08150"))):
                t_cur[0] = datetime(2026, 11, 24, 15, 20, idx * 5, tzinfo=timezone.utc)
                rep = trader.run_cycle(mt5_quotes={"EURUSD": (px, px + D("0.00010"))})
                self.assertIn("action", rep)
            snap = trader.status_snapshot(now=t_cur[0])
            self.assertGreaterEqual(snap["cycle_count"], 4)
            self.assertGreaterEqual(len(seen_notebooks), 1)
            self.assertIn("Stick to clean London-NY FX trends", seen_notebooks[0])


if __name__ == "__main__":
    unittest.main()
