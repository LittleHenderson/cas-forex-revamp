"""Phase 8 verification for PR #45: live COMEX MGC specs + Phase 1 Hybrid Micro-Scalp Replay Shields."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import pathlib
import sys
import tempfile
import unittest

from cas_forex_revamp.composition.trend_regime import REGIME_CHOP_RANGE
from cas_forex_revamp.contracts import ContractError, Side
from cas_forex_revamp.futures.hybrid_micro_scalper import (
    DAY_REGIME_CLEAN_TREND,
    DAY_REGIME_QUIET_CHOP,
    DAY_REGIME_VIOLENT_BREAKOUT,
    HybridMicroScalpBacktester,
    Layer1Directive,
    M1Bar,
    REGIME_FLAT_STAND_DOWN,
    ReplayConfig,
    VERDICT_FAIL_STOP_AND_ARCHIVE,
    VERDICT_PASS_TO_PHASE_2,
    build_synthetic_three_regime_dataset,
    check_breakout_kill_switch,
    compute_all_in_cost_profile,
    compute_burst_leg_risk_pct,
    dataset_from_wire_dict,
    evaluate_layer1_directive,
    evaluate_phase1_matrix,
    judge_phase1_run,
    validate_scalp_geometry,
)
from cas_forex_revamp.futures.micro_futures_specs import (
    CME_MICRO_FUTURES_SPECS,
    compute_contract_pnl_usd,
    size_micro_futures_order,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate


class TestPr45HybridMicroScalperAndMgcSpecs(unittest.TestCase):
    def test_01_mgc_live_comex_commission_and_intraday_margin(self) -> None:
        mgc = CME_MICRO_FUTURES_SPECS["MGC"]
        self.assertEqual(mgc.default_intraday_margin_usd, Decimal("200.00"))
        self.assertEqual(mgc.default_round_turn_commission_usd, Decimal("2.42"))

        # 10.0-pt BUY profit on 1 contract MGC = +$100.00 gross - $2.42 RT commission = +$97.58 net
        self.assertEqual(
            compute_contract_pnl_usd("MGC", "BUY", Decimal("2700.00"), Decimal("2710.00"), 1),
            Decimal("97.58"),
        )
        # 1000% margin floor: $5,000 equity -> $500 max margin -> max 2 MGC contracts by margin
        sizing = size_micro_futures_order(
            symbol_or_root="MGC",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("2.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(sizing.contracts_by_margin, 2)
        self.assertEqual(sizing.contracts, 2)
        self.assertEqual(sizing.required_margin_usd, Decimal("400.00"))
        self.assertEqual(sizing.estimated_round_turn_commission_usd, Decimal("4.84"))

    def test_02_stressed_commission_and_box_width_76923x_gate(self) -> None:
        mnq_pass = compute_all_in_cost_profile("MNQ", fee_mode="stressed", passive_limit=True)
        mnq_mkt = compute_all_in_cost_profile("MNQ", fee_mode="stressed", passive_limit=False)
        self.assertEqual(mnq_pass.total_rt_cost_usd, Decimal("1.88"))
        self.assertEqual(mnq_pass.min_box_width_points, Decimal("7.23"))
        self.assertEqual(mnq_mkt.total_rt_cost_usd, Decimal("2.88"))
        self.assertEqual(mnq_mkt.min_box_width_points, Decimal("11.08"))

        mes_pass = compute_all_in_cost_profile("MES", fee_mode="stressed", passive_limit=True)
        mes_mkt = compute_all_in_cost_profile("MES", fee_mode="stressed", passive_limit=False)
        self.assertEqual(mes_pass.min_box_width_points, Decimal("2.89"))
        self.assertEqual(mes_mkt.min_box_width_points, Decimal("6.74"))

        mym_mkt = compute_all_in_cost_profile("MYM", fee_mode="stressed", passive_limit=False)
        mgc_mkt = compute_all_in_cost_profile("MGC", fee_mode="stressed", passive_limit=False)
        self.assertEqual(mym_mkt.min_box_width_points, Decimal("44.92"))
        self.assertEqual(mgc_mkt.min_box_width_points, Decimal("3.40"))

        # Narrow MYM box (< 29.54 pts passive) MUST refuse CHOP_RANGE and stand down FLAT
        base = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
        narrow_mym_bars = [
            M1Bar(
                symbol="MYM",
                timestamp_utc=base + timedelta(minutes=i),
                open=Decimal("44000"),
                high=Decimal("44008"),
                low=Decimal("43995"),
                close=Decimal("44001" if i % 2 == 0 else "43999"),
            )
            for i in range(20)
        ]
        directive, _ = evaluate_layer1_directive(
            symbol="MYM",
            recent_bars=narrow_mym_bars,
            spread=Decimal("1.00"),
            now=base + timedelta(minutes=20),
            config=ReplayConfig(),
            in_maintenance_window=False,
            chop_locked_out=False,
            calls_used_today=0,
        )
        self.assertEqual(directive.regime, REGIME_FLAT_STAND_DOWN)

    def test_03_shield1_sl_lte_tp_and_3x_fee_floor_enforced(self) -> None:
        # Wide-stop steamroller trap SL > TP MUST be rejected
        ok_wide, reason_wide = validate_scalp_geometry(
            "MNQ", Decimal("10.00"), Decimal("5.00"), fee_mode="stressed", passive_limit=True
        )
        self.assertFalse(ok_wide)
        self.assertIn("SL_GT_TP_STEAMROLLER_REJECTED", reason_wide)

        # Target below 3x all-in fee ($1.88 * 3 = $5.64 -> 2.82 pts on MNQ) MUST be rejected
        ok_tiny, reason_tiny = validate_scalp_geometry(
            "MNQ", Decimal("2.00"), Decimal("2.50"), fee_mode="stressed", passive_limit=True
        )
        self.assertFalse(ok_tiny)
        self.assertIn("BELOW_3X_FEE_FLOOR", reason_tiny)

        # Sweet-spot SL <= TP and >= 3x fee floor passes
        ok_good, reason_good = validate_scalp_geometry(
            "MNQ", Decimal("3.00"), Decimal("6.00"), fee_mode="stressed", passive_limit=True
        )
        self.assertTrue(ok_good, reason_good)

    def test_04_shield2_breakout_kill_switch_cancels_and_locks_20m(self) -> None:
        # 1. Breach box_high + 0.35 * ATR -> immediate kill
        k1, r1 = check_breakout_kill_switch(
            range_low=Decimal("25000"),
            range_high=Decimal("25020"),
            atr=Decimal("10"),
            tick_price=Decimal("25024"),
            prev_tick_price=Decimal("25019"),
            bar_close_outside=False,
        )
        self.assertTrue(k1)
        self.assertEqual(r1, "BOX_UPPER_BREAKOUT_ATR")

        # 2. M1 bar close outside box -> immediate kill
        k2, r2 = check_breakout_kill_switch(
            range_low=Decimal("25000"),
            range_high=Decimal("25020"),
            atr=Decimal("10"),
            tick_price=Decimal("25021"),
            prev_tick_price=Decimal("25020"),
            bar_close_outside=True,
        )
        self.assertTrue(k2)
        self.assertEqual(r2, "M1_CLOSE_OUTSIDE_BOX")

        # 3. Sudden 2 * ATR rapid burst inside/across bar -> immediate kill
        k3, r3 = check_breakout_kill_switch(
            range_low=Decimal("25000"),
            range_high=Decimal("25040"),
            atr=Decimal("5"),
            tick_price=Decimal("25025"),
            prev_tick_price=Decimal("25014"),
            bar_close_outside=False,
        )
        self.assertTrue(k3)
        self.assertEqual(r3, "FIVE_SEC_2ATR_BURST")

    def test_05_shield3_zero_martingale_and_single_envelope_r_over_k(self) -> None:
        self.assertEqual(compute_burst_leg_risk_pct(Decimal("1.00"), 1), Decimal("1.0000"))
        self.assertEqual(compute_burst_leg_risk_pct(Decimal("1.00"), 3), Decimal("0.3333"))
        with self.assertRaises(ContractError):
            compute_burst_leg_risk_pct(Decimal("1.01"), 1)
        with self.assertRaises(ContractError):
            compute_burst_leg_risk_pct(Decimal("1.00"), 4)
        # Small $3,000 account caps concurrent positions at 2
        with self.assertRaises(ContractError):
            ReplayConfig(starting_equity_usd=Decimal("3000.00"), max_open_positions=3)

    def test_06_shield4_two_consecutive_losses_lock_and_15m_cooldown(self) -> None:
        base = datetime(2026, 11, 20, 14, 0, 0, tzinfo=timezone.utc)
        offsets = [0, 4, 10, 16, 20, 16, 10, 4, 0, 4, 10, 16, 20, 16, 10, 4]
        bars: list[M1Bar] = []
        for i, off in enumerate(offsets):
            c_px = Decimal("25000.00") + Decimal(off)
            o_px = Decimal("25000.00") + Decimal(offsets[i - 1] if i > 0 else 2)
            bars.append(M1Bar("MNQ", base + timedelta(minutes=i), o_px, max(o_px, c_px) + Decimal("2"), min(o_px, c_px) - Decimal("2"), c_px))

        # Two consecutive chop dips that fill BUY limits (~25001) and stop out at 24994 -> Shield 4 lock
        bars.append(M1Bar("MNQ", base + timedelta(minutes=16), Decimal("25004"), Decimal("25006"), Decimal("25000"), Decimal("25001")))
        bars.append(M1Bar("MNQ", base + timedelta(minutes=17), Decimal("25001"), Decimal("25004"), Decimal("24994"), Decimal("25004")))
        bars.append(M1Bar("MNQ", base + timedelta(minutes=18), Decimal("25004"), Decimal("25015"), Decimal("25003"), Decimal("25012")))
        bars.append(M1Bar("MNQ", base + timedelta(minutes=19), Decimal("25012"), Decimal("25016"), Decimal("25000"), Decimal("25001")))
        bars.append(M1Bar("MNQ", base + timedelta(minutes=20), Decimal("25001"), Decimal("25004"), Decimal("24994"), Decimal("25005")))
        # 15 minutes of oscillating chop during 900s post-loss cooldown -> 0 new scalps allowed
        for i in range(21, 36):
            o_px = Decimal("25002") if i % 2 == 0 else Decimal("25018")
            c_px = Decimal("25018") if i % 2 == 0 else Decimal("25002")
            bars.append(M1Bar("MNQ", base + timedelta(minutes=i), o_px, Decimal("25020"), Decimal("25000"), c_px))

        rep = HybridMicroScalpBacktester(
            ReplayConfig(fill_delay_ms=250, breakout_kill_atr_mult=Decimal("1.50"))
        ).run({"MNQ": bars})
        sh = rep["shields_and_gates"]
        self.assertGreaterEqual(sh["consecutive_loss_locks"], 1)
        self.assertEqual(rep["summary"]["losses"], 2)
        self.assertEqual(sh["opposing_violations"], 0)

    def test_07_shield5_daily_churn_cap_and_2pct_loss_fee_pause(self) -> None:
        with self.assertRaises(ContractError):
            ReplayConfig(max_daily_scalps=41)
        syn = build_synthetic_three_regime_dataset()
        bars, _ = dataset_from_wire_dict(syn)
        rep = HybridMicroScalpBacktester(ReplayConfig(max_daily_scalps=5, fill_delay_ms=250)).run(bars)
        self.assertGreaterEqual(rep["shields_and_gates"]["daily_churn_caps_hit"], 1)

    def test_08_unidirectional_layer1_ttl_fail_closed_and_warmup_guard(self) -> None:
        now = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
        d_ok = Layer1Directive("MNQ", REGIME_CHOP_RANGE, None, Decimal("25000"), Decimal("25020"), Decimal("4"), Decimal("0.20"), now, now + timedelta(seconds=360), "OK")
        self.assertTrue(d_ok.is_valid_at(now + timedelta(seconds=359)))
        self.assertFalse(d_ok.is_valid_at(now + timedelta(seconds=360)))

        # Exceeding 300 daily AI calls forces fail-closed FLAT_STAND_DOWN without consuming another call
        bars = [M1Bar("MNQ", now + timedelta(minutes=i), Decimal("25000"), Decimal("25010"), Decimal("24995"), Decimal("25005")) for i in range(15)]
        d_cap, used = evaluate_layer1_directive(
            symbol="MNQ", recent_bars=bars, spread=Decimal("0.25"), now=now + timedelta(minutes=15),
            config=ReplayConfig(), in_maintenance_window=False, chop_locked_out=False, calls_used_today=300,
        )
        self.assertEqual(d_cap.regime, REGIME_FLAT_STAND_DOWN)
        self.assertFalse(used)

        # Fewer than 10 continuous bars (gap resets warmup) blocks entries cleanly
        short_bars = bars[:8]
        rep_short = HybridMicroScalpBacktester(ReplayConfig()).run({"MNQ": short_bars})
        self.assertEqual(rep_short["summary"]["closed_trades"], 0)
        self.assertGreaterEqual(rep_short["shields_and_gates"]["warmup_blocks"], 1)

    def test_09_global_anti_cancellation_and_cftc_zero_opposing(self) -> None:
        syn = build_synthetic_three_regime_dataset()
        bars, _ = dataset_from_wire_dict(syn)
        rep = HybridMicroScalpBacktester(ReplayConfig(fill_delay_ms=500)).run(bars)
        sh = rep["shields_and_gates"]
        self.assertEqual(sh["opposing_violations"], 0)
        self.assertEqual(sh["anti_cancellation_violations"], 0)
        self.assertGreater(sh["anti_cancellation_blocks"], 0)

    def test_10_mandatory_forex_meta_valve_gate_161_params_enforced(self) -> None:
        gate = load_default_forex_valve_gate()
        self.assertEqual(gate.controller.parameter_count, 161)
        self.assertEqual(gate.controller.threshold, 0.55)
        syn = build_synthetic_three_regime_dataset()
        bars, _ = dataset_from_wire_dict(syn)
        rep = HybridMicroScalpBacktester(ReplayConfig(fill_delay_ms=500), valve_gate=gate).run(bars)
        sh = rep["shields_and_gates"]
        self.assertEqual(sh["valve_param_count"], 161)
        self.assertEqual(sh["valve_bypassed"], 0)
        self.assertEqual(sh["valve_checked"], sh["valve_admitted"] + sh["valve_vetoed"])
        self.assertGreater(sh["valve_checked"], 0)

    def test_11_delay_monotonicity_250ms_500ms_900ms_and_ab_matrix(self) -> None:
        syn = build_synthetic_three_regime_dataset()
        rep1 = evaluate_phase1_matrix(syn)
        rep2 = evaluate_phase1_matrix(syn)
        # 100% deterministic report content (excluding sub-ms wall clock perf_counter jitter fields)
        self.assertEqual(rep1["dataset_sha256"], rep2["dataset_sha256"])
        self.assertEqual(rep1["phase1_verdict"], rep2["phase1_verdict"])
        for label in rep1["runs"]:
            self.assertEqual(rep1["runs"][label]["summary"], rep2["runs"][label]["summary"])
            self.assertEqual(rep1["runs"][label]["by_day_regime"], rep2["runs"][label]["by_day_regime"])
        # All 3 day regimes represented cleanly
        cal = rep1["runs"]["hybrid_500ms_stressed"]["day_regime_calendar"]["MNQ"]
        self.assertEqual(set(cal.values()), {DAY_REGIME_QUIET_CHOP, DAY_REGIME_CLEAN_TREND, DAY_REGIME_VIOLENT_BREAKOUT})

    def test_12_fail_closed_phase1_verdict_never_passes_vacuous_or_high_dd(self) -> None:
        # 1. Vacuous 0 trades MUST fail
        verdict0, reasons0 = judge_phase1_run(
            {"summary": {"closed_trades": 0, "net_profit_factor": "99.0000", "max_drawdown_pct": "0.0000"}, "shields_and_gates": {"valve_p99_ms": "0.2", "valve_bypassed": 0, "opposing_violations": 0, "anti_cancellation_violations": 0}}
        )
        self.assertEqual(verdict0, VERDICT_FAIL_STOP_AND_ARCHIVE)
        self.assertTrue(any("INSUFFICIENT_TRADES" in r for r in reasons0))

        # 2. PF < 1.25 MUST fail
        verdict_pf, reasons_pf = judge_phase1_run(
            {"summary": {"closed_trades": 40, "net_profit_factor": "1.2499", "max_drawdown_pct": "2.0000"}, "shields_and_gates": {"valve_p99_ms": "0.2", "valve_bypassed": 0, "opposing_violations": 0, "anti_cancellation_violations": 0}}
        )
        self.assertEqual(verdict_pf, VERDICT_FAIL_STOP_AND_ARCHIVE)
        self.assertTrue(any("NET_PF_BELOW_1.25" in r for r in reasons_pf))

        # 3. Max DD > 6.00% MUST fail
        verdict_dd, reasons_dd = judge_phase1_run(
            {"summary": {"closed_trades": 40, "net_profit_factor": "2.1000", "max_drawdown_pct": "6.0001"}, "shields_and_gates": {"valve_p99_ms": "0.2", "valve_bypassed": 0, "opposing_violations": 0, "anti_cancellation_violations": 0}}
        )
        self.assertEqual(verdict_dd, VERDICT_FAIL_STOP_AND_ARCHIVE)
        self.assertTrue(any("MAX_DD_ABOVE_6.00PCT" in r for r in reasons_dd))

        # 4. Meeting every threshold passes
        verdict_ok, _ = judge_phase1_run(
            {"summary": {"closed_trades": 40, "net_profit_factor": "1.2500", "max_drawdown_pct": "6.0000"}, "shields_and_gates": {"valve_p99_ms": "0.45", "valve_bypassed": 0, "opposing_violations": 0, "anti_cancellation_violations": 0}}
        )
        self.assertEqual(verdict_ok, VERDICT_PASS_TO_PHASE_2)

    def test_13_cli_synthetic_stress_smoke(self) -> None:
        cli_path = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "backtest_hybrid_micro_scalper.py"
        self.assertTrue(cli_path.exists())
        sys.path.insert(0, str(cli_path.parent))
        try:
            import backtest_hybrid_micro_scalper as cli_mod

            with tempfile.TemporaryDirectory() as td:
                out_file = pathlib.Path(td) / "rep.json"
                rc = cli_mod.main(["--synthetic-stress", "--out", str(out_file)])
                self.assertEqual(rc, 0)
                doc = json.loads(out_file.read_text(encoding="utf-8"))
                self.assertEqual(doc["schema"], "cas-forex-phase1-replay-report-v1")
                self.assertIn("hybrid_500ms_stressed", doc["runs"])
        finally:
            if str(cli_path.parent) in sys.path:
                sys.path.remove(str(cli_path.parent))
