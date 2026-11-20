"""Tests for Trading Aggression Dial (20..100 bps = 0.20%..1.00% in 0.01% steps) & 5-Tier Controls."""

from __future__ import annotations

import ast
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.composition.parallel_tiers import DEFAULT_PARALLEL_TIER_SPECS
from cas_forex_revamp.valve.aggression_dial import (
    ACCESS_MODE_DEVICE_READ_AND_EXPLAINER,
    ACCESS_MODE_OWNER_FULL_CONTROL,
    AGGRESSION_ANCHOR_KNOTS,
    AGGRESSION_BPS_PROFILES,
    AGGRESSION_DIAL_SCHEMA,
    AggressionDialError,
    AggressionDialStore,
    AggressionProfile,
    DEFAULT_MASTER_RISK_BPS,
    DEFAULT_TIER_CAPITALS,
    HIGH_RISK_MIN_BPS,
    HighRiskConfirmationRequiredError,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    MAX_RISK_BPS,
    MIN_CONSTITUTIONAL_VALVE_PROB,
    MIN_RISK_BPS,
    OwnerKeyRequiredError,
    PRESET_ALL_BALANCED,
    PRESET_ALL_SAFE,
    PRESET_STAGGER_SAFE_TO_EXTREME,
    PRESET_STAGGER_SAFE_TO_HIGH,
    PRESET_SYNC_MASTER,
    REFERENCE_CAPITAL_CENTS,
    STAGGER_SAFE_TO_HIGH_BPS,
    div_round_half_up,
    profile_for_risk_bps,
    resolve_effective_params,
    scale_cents_from_300k,
    scale_usd_from_300k,
    unbreakable_guardrails,
    validate_constitutional_drawdown_pct,
    validate_constitutional_signal_prob,
    validate_constitutional_stop_risk_pct,
    zone_label_and_css_for_bps,
)

EXPECTED_ANCHOR_KNOTS = {
    20: ("Safe", "dial-lvl-1", 1, 78, 150000, 75000),
    40: ("Steady", "dial-lvl-3", 2, 72, 300000, 150000),
    60: ("Balanced", "dial-lvl-5", 3, 66, 450000, 250000),
    85: ("Risky", "dial-lvl-8", 5, 59, 750000, 475000),
    95: ("High Risk", "dial-lvl-10", 6, 55, 1000000, 600000),
    100: ("Extreme High Risk", "dial-lvl-11", 8, 55, 1500000, 850000),
}


class _FixedClock:
    def __init__(self) -> None:
        self._now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self._now
        self._now = current + timedelta(seconds=1)
        return current


class AggressionDialTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "aggression_dial.sqlite3"
        self.clock = _FixedClock()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_constants_6_anchor_knots_and_81_single_bp_steps(self) -> None:
        self.assertEqual(MIN_RISK_BPS, 20)
        self.assertEqual(MAX_RISK_BPS, 100)
        self.assertEqual(DEFAULT_MASTER_RISK_BPS, 60)
        self.assertEqual(HIGH_RISK_MIN_BPS, 80)
        self.assertEqual(MAX_CONSTITUTIONAL_STOP_RISK_PCT, Decimal("1.00"))
        self.assertEqual(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, Decimal("0.10"))
        self.assertEqual(MIN_CONSTITUTIONAL_VALVE_PROB, Decimal("0.55"))
        self.assertEqual(len(AGGRESSION_ANCHOR_KNOTS), 6)
        self.assertEqual(tuple(sorted(AGGRESSION_BPS_PROFILES.keys())), tuple(range(20, 101)))
        self.assertEqual(len(AGGRESSION_BPS_PROFILES), 81)

        # Verify all 6 anchor knots hit exact values
        for bps, (lbl, css, trades, prob_bp, goal_c, loss_c) in EXPECTED_ANCHOR_KNOTS.items():
            prof = profile_for_risk_bps(bps)
            self.assertEqual(prof.risk_bps, bps)
            self.assertEqual(prof.label, lbl)
            self.assertEqual(prof.css_class, css)
            self.assertEqual(prof.max_open_trades, trades)
            self.assertEqual(prof.prob_bp, prob_bp)
            self.assertEqual(prof.min_signal_prob, Decimal(prob_bp) / Decimal("100"))
            self.assertEqual(prof.ref_300k_goal_cents, goal_c)
            self.assertEqual(prof.ref_300k_loss_cents, loss_c)
            self.assertEqual(prof.scaled_goal_cents(Decimal("300000.00")), goal_c)
            self.assertEqual(prof.scaled_loss_brake_cents(Decimal("300000.00")), loss_c)

        # Verify monotonicity & constitutional invariants across ALL 81 steps (20..100)
        prev = AGGRESSION_BPS_PROFILES[20]
        for bps in range(20, 101):
            cur = AGGRESSION_BPS_PROFILES[bps]
            self.assertEqual(cur.risk_pct, (Decimal(bps) / Decimal("100")).quantize(Decimal("0.01")))
            self.assertLessEqual(cur.risk_pct, MAX_CONSTITUTIONAL_STOP_RISK_PCT)
            self.assertGreaterEqual(cur.min_signal_prob, MIN_CONSTITUTIONAL_VALVE_PROB)
            self.assertGreaterEqual(cur.ref_300k_goal_cents, prev.ref_300k_goal_cents)
            self.assertGreaterEqual(cur.ref_300k_loss_cents, prev.ref_300k_loss_cents)
            self.assertGreaterEqual(cur.max_open_trades, prev.max_open_trades)
            self.assertLessEqual(cur.prob_bp, prev.prob_bp)
            prev = cur

        # Verify zone label & CSS class boundaries
        zone_checks = [
            (20, "Safe", "dial-lvl-1"),
            (29, "Safe", "dial-lvl-1"),
            (30, "Calm", "dial-lvl-2"),
            (39, "Calm", "dial-lvl-2"),
            (40, "Steady", "dial-lvl-3"),
            (49, "Steady", "dial-lvl-3"),
            (50, "Moderate", "dial-lvl-4"),
            (59, "Moderate", "dial-lvl-4"),
            (60, "Balanced", "dial-lvl-5"),
            (69, "Balanced", "dial-lvl-5"),
            (70, "Active", "dial-lvl-6"),
            (74, "Active", "dial-lvl-6"),
            (75, "Bold", "dial-lvl-7"),
            (79, "Bold", "dial-lvl-7"),
            (80, "Risky", "dial-lvl-8"),
            (89, "Risky", "dial-lvl-8"),
            (90, "High Risk", "dial-lvl-10"),
            (95, "High Risk", "dial-lvl-10"),
            (96, "Extreme High Risk", "dial-lvl-11"),
            (100, "Extreme High Risk", "dial-lvl-11"),
        ]
        for bps, expected_lbl, expected_css in zone_checks:
            self.assertEqual(zone_label_and_css_for_bps(bps), (expected_lbl, expected_css))

    def test_constitutional_ceilings_fail_closed(self) -> None:
        with self.assertRaises(AggressionDialError):
            validate_constitutional_stop_risk_pct(Decimal("1.01"))
        with self.assertRaises(AggressionDialError):
            validate_constitutional_stop_risk_pct(Decimal("2.00"))
        with self.assertRaises(AggressionDialError):
            validate_constitutional_drawdown_pct(Decimal("0.1001"))
        with self.assertRaises(AggressionDialError):
            validate_constitutional_signal_prob(Decimal("0.54"))
        with self.assertRaises(AggressionDialError):
            AggressionProfile(
                risk_bps=100,
                label="Illegal Over-Risk",
                css_class="dial-lvl-11",
                risk_pct=Decimal("1.01"),
                max_open_trades=8,
                prob_bp=55,
                min_signal_prob=Decimal("0.55"),
                ref_300k_goal_cents=1500000,
                ref_300k_loss_cents=850000,
            )
        with self.assertRaises(AggressionDialError):
            AggressionProfile(
                risk_bps=100,
                label="Illegal Sub-Valve",
                css_class="dial-lvl-11",
                risk_pct=Decimal("1.00"),
                max_open_trades=8,
                prob_bp=54,
                min_signal_prob=Decimal("0.54"),
                ref_300k_goal_cents=1500000,
                ref_300k_loss_cents=850000,
            )

    def test_405_exact_tier_step_combinations_and_parallel_tiers_match(self) -> None:
        expected_tiers = {
            spec.tier_id: spec.starting_capital_usd for spec in DEFAULT_PARALLEL_TIER_SPECS
        }
        self.assertEqual(dict(DEFAULT_TIER_CAPITALS), expected_tiers)
        self.assertEqual(len(DEFAULT_TIER_CAPITALS), 5)

        # Spot-check exact penny outputs at 100 bps (1.00% Extreme High Risk) & 21 bps (0.21%)
        p100 = profile_for_risk_bps(100)
        self.assertEqual(p100.scaled_goal_usd(Decimal("300000.00")), Decimal("15000.00"))
        self.assertEqual(p100.scaled_loss_brake_usd(Decimal("300000.00")), Decimal("8500.00"))
        self.assertEqual(p100.scaled_goal_usd(Decimal("6000.00")), Decimal("300.00"))
        self.assertEqual(p100.scaled_loss_brake_usd(Decimal("6000.00")), Decimal("170.00"))
        self.assertEqual(p100.scaled_goal_usd(Decimal("3000.00")), Decimal("150.00"))
        self.assertEqual(p100.scaled_loss_brake_usd(Decimal("3000.00")), Decimal("85.00"))
        self.assertEqual(p100.scaled_goal_usd(Decimal("1000.00")), Decimal("50.00"))
        self.assertEqual(p100.scaled_loss_brake_usd(Decimal("1000.00")), Decimal("28.33"))
        self.assertEqual(p100.scaled_goal_usd(Decimal("300.00")), Decimal("15.00"))
        self.assertEqual(p100.scaled_loss_brake_usd(Decimal("300.00")), Decimal("8.50"))

        p21 = profile_for_risk_bps(21)
        self.assertEqual(p21.risk_pct, Decimal("0.21"))
        self.assertEqual(p21.ref_300k_goal_cents, 150000 + div_round_half_up(150000 * 1, 20))
        self.assertEqual(p21.ref_300k_loss_cents, 75000 + div_round_half_up(75000 * 1, 20))

        # Exhaustively verify all 81 bps steps x 5 tiers = 405 exact combinations
        checked = 0
        for bps in range(MIN_RISK_BPS, MAX_RISK_BPS + 1):
            prof = AGGRESSION_BPS_PROFILES[bps]
            for tid, cap in DEFAULT_TIER_CAPITALS.items():
                resolved = resolve_effective_params(bps, cap, ai_discretion_enabled=False)
                cap_cents = int(cap * 100)
                exp_goal_c = (
                    prof.ref_300k_goal_cents * cap_cents + REFERENCE_CAPITAL_CENTS // 2
                ) // REFERENCE_CAPITAL_CENTS
                exp_loss_c = (
                    prof.ref_300k_loss_cents * cap_cents + REFERENCE_CAPITAL_CENTS // 2
                ) // REFERENCE_CAPITAL_CENTS
                exp_risk_c = (cap_cents * bps + 5_000) // 10_000

                self.assertEqual(resolved["session_goal_cents"], exp_goal_c, f"bps={bps} {tid}")
                self.assertEqual(resolved["daily_loss_brake_cents"], exp_loss_c, f"bps={bps} {tid}")
                self.assertEqual(resolved["risk_per_trade_cents"], exp_risk_c, f"bps={bps} {tid}")
                self.assertEqual(
                    scale_cents_from_300k(prof.ref_300k_goal_cents, cap_cents),
                    exp_goal_c,
                )
                self.assertEqual(
                    scale_usd_from_300k(prof.ref_300k_goal_usd, cap),
                    Decimal(resolved["session_goal_usd"]),
                )
                self.assertLessEqual(Decimal(resolved["risk_pct"]), MAX_CONSTITUTIONAL_STOP_RISK_PCT)
                self.assertLessEqual(
                    Decimal(resolved["max_drawdown_pct"]),
                    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
                )
                self.assertGreaterEqual(
                    Decimal(resolved["min_signal_prob"]),
                    MIN_CONSTITUTIONAL_VALVE_PROB,
                )
                checked += 1
        self.assertEqual(checked, 405)

    def test_sync_and_presets_and_persistence(self) -> None:
        store = AggressionDialStore(self.db_path, now_fn=self.clock)
        snap = store.snapshot()
        self.assertEqual(snap["schema"], AGGRESSION_DIAL_SCHEMA)
        self.assertEqual(snap["min_risk_bps"], 20)
        self.assertEqual(snap["max_risk_bps"], 100)
        self.assertEqual(snap["master_risk_bps"], 60)
        self.assertEqual(snap["master_risk_pct"], "0.60")
        self.assertTrue(snap["ai_discretion_enabled"])
        self.assertEqual(snap["ai_discretion_ceiling_bps"], 100)
        self.assertTrue(snap["auto_shift_enabled"])
        self.assertEqual(len(snap["anchor_knots"]), 6)
        self.assertEqual(len(snap["bps_catalog"]), 81)
        self.assertEqual(len(snap["tiers"]), 5)
        for t in snap["tiers"]:
            self.assertEqual(t["risk_bps"], 60)

        # Master to 73 bps (0.73% Active), sync all 5 tiers
        store.set_master_risk_bps(73, actor="wakil")
        snap = store.sync_all_tiers_to_master(actor="wakil")
        self.assertEqual(snap["master_risk_bps"], 73)
        self.assertEqual(snap["master_risk_pct"], "0.73")
        for t in snap["tiers"]:
            self.assertEqual(t["risk_bps"], 73)

        # Stagger Safe -> Extreme ($300k=25, $6k=45, $3k=65, $1k=85, $300=100)
        snap = store.apply_stagger_preset(live_mode=False, actor="wakil")
        for tid, expected_bps in STAGGER_SAFE_TO_HIGH_BPS.items():
            self.assertEqual(snap["tiers_by_id"][tid]["risk_bps"], expected_bps)
        self.assertEqual(snap["tiers_by_id"]["TIER_1_CURRENT"]["risk_bps"], 25)
        self.assertEqual(snap["tiers_by_id"]["TIER_4_6000"]["risk_bps"], 45)
        self.assertEqual(snap["tiers_by_id"]["TIER_3_3000"]["risk_bps"], 65)
        self.assertEqual(snap["tiers_by_id"]["TIER_2_1000"]["risk_bps"], 85)
        self.assertEqual(snap["tiers_by_id"]["TIER_5_300"]["risk_bps"], 100)
        self.assertEqual(snap["tiers_by_id"]["TIER_5_300"]["session_goal_usd"], "15.00")
        self.assertEqual(snap["tiers_by_id"]["TIER_5_300"]["daily_loss_brake_usd"], "8.50")

        # Alias STAGGER_SAFE_TO_EXTREME works identically
        store.apply_tier_preset(PRESET_ALL_SAFE, actor="wakil")
        snap_ext = store.apply_tier_preset(
            PRESET_STAGGER_SAFE_TO_EXTREME,
            live_mode=False,
            actor="wakil",
        )
        self.assertEqual(snap_ext["tiers_by_id"]["TIER_5_300"]["risk_bps"], 100)

        # Re-open store from disk: persisted state MUST survive intact
        reopened = AggressionDialStore(self.db_path, now_fn=self.clock)
        snap2 = reopened.snapshot()
        for tid, expected_bps in STAGGER_SAFE_TO_HIGH_BPS.items():
            self.assertEqual(snap2["tiers_by_id"][tid]["risk_bps"], expected_bps)

        # ALL_BALANCED preset -> 60 bps
        snap3 = reopened.apply_tier_preset(PRESET_ALL_BALANCED, actor="wakil")
        for t in snap3["tiers"]:
            self.assertEqual(t["risk_bps"], 60)

        # ALL_SAFE preset -> 20 bps
        snap4 = reopened.apply_tier_preset(PRESET_ALL_SAFE, actor="wakil")
        for t in snap4["tiers"]:
            self.assertEqual(t["risk_bps"], 20)

        # SYNC_MASTER preset restores all 5 to master (73 bps)
        snap5 = reopened.apply_tier_preset(PRESET_SYNC_MASTER, actor="wakil")
        for t in snap5["tiers"]:
            self.assertEqual(t["risk_bps"], 73)

        self.assertTrue(reopened.verify_audit_chain())

    def test_ai_discretion_in_bps_downshifts_and_boosts_within_ceiling(self) -> None:
        # 1. Drawdown >= 8% -> min(bps, 20) (0.20% Safe)
        r_dd8 = resolve_effective_params(
            100,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            regime="STRONG_TREND",
            drawdown_pct=Decimal("0.08"),
            valve_score=Decimal("0.85"),
        )
        self.assertEqual(r_dd8["effective_risk_bps"], 20)
        self.assertEqual(r_dd8["effective_risk_pct"], "0.20")
        self.assertEqual(r_dd8["effective_label"], "Safe")
        self.assertEqual(r_dd8["ai_discretion_direction"], "DOWN")
        self.assertEqual(r_dd8["ai_discretion_reason"], "DRAWDOWN_BRAKE_8PCT")

        # 2. Drawdown >= 5% or consecutive_losses >= 2 -> min(bps, 30) (0.30% Calm)
        r_dd5 = resolve_effective_params(
            85,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            regime="STRONG_TREND",
            drawdown_pct=Decimal("0.05"),
        )
        self.assertEqual(r_dd5["effective_risk_bps"], 30)
        self.assertEqual(r_dd5["effective_label"], "Calm")
        # Must NOT step UP if owner chose 22 bps
        r_dd5_low = resolve_effective_params(
            22,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            drawdown_pct=Decimal("0.06"),
        )
        self.assertEqual(r_dd5_low["effective_risk_bps"], 22)

        r_loss2 = resolve_effective_params(
            95,
            Decimal("3000.00"),
            ai_discretion_enabled=True,
            regime="STRONG_TREND",
            consecutive_losses=2,
        )
        self.assertEqual(r_loss2["effective_risk_bps"], 30)
        self.assertEqual(r_loss2["ai_discretion_reason"], "CONSECUTIVE_LOSSES_2PLUS")

        # 3. consecutive_losses == 1 or CHOP_RANGE -> min(bps, 40) (0.40% Steady)
        r_loss1 = resolve_effective_params(
            75,
            Decimal("3000.00"),
            ai_discretion_enabled=True,
            regime="TREND_IGNITION",
            consecutive_losses=1,
        )
        self.assertEqual(r_loss1["effective_risk_bps"], 40)
        self.assertEqual(r_loss1["ai_discretion_reason"], "CONSECUTIVE_LOSS_1")

        r_chop = resolve_effective_params(
            88,
            Decimal("6000.00"),
            ai_discretion_enabled=True,
            regime="CHOP_RANGE",
        )
        self.assertEqual(r_chop["effective_risk_bps"], 40)
        self.assertEqual(r_chop["ai_discretion_reason"], "CHOP_RANGE")
        r_chop_low = resolve_effective_params(
            25,
            Decimal("6000.00"),
            ai_discretion_enabled=True,
            regime="CHOP_RANGE",
        )
        self.assertEqual(r_chop_low["effective_risk_bps"], 25)

        # 4. TREND_IGNITION (0 losses, <5% DD) -> min(ceiling_bps, max(bps, 85))
        r_ti = resolve_effective_params(
            60,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            ai_discretion_ceiling_bps=100,
            regime="TREND_IGNITION",
            consecutive_losses=0,
            drawdown_pct=Decimal("0.02"),
        )
        self.assertEqual(r_ti["effective_risk_bps"], 85)
        self.assertEqual(r_ti["effective_risk_pct"], "0.85")
        self.assertEqual(r_ti["effective_label"], "Risky")
        self.assertEqual(r_ti["ai_discretion_direction"], "UP")
        self.assertEqual(r_ti["ai_discretion_reason"], "TREND_IGNITION_BOOST")

        # Owner already at 91 bps in TREND_IGNITION -> holds 91 (max(91, 85))
        r_ti_91 = resolve_effective_params(
            91,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            ai_discretion_ceiling_bps=100,
            regime="TREND_IGNITION",
        )
        self.assertEqual(r_ti_91["effective_risk_bps"], 91)

        # 5. STRONG_TREND -> 95 (valve < 0.72) or 100 (valve >= 0.72)
        r_st95 = resolve_effective_params(
            60,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            ai_discretion_ceiling_bps=100,
            regime="STRONG_TREND",
            valve_score=Decimal("0.68"),
        )
        self.assertEqual(r_st95["effective_risk_bps"], 95)
        self.assertEqual(r_st95["effective_label"], "High Risk")
        self.assertEqual(r_st95["ai_discretion_reason"], "STRONG_TREND_BOOST")

        r_st100 = resolve_effective_params(
            60,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            ai_discretion_ceiling_bps=100,
            regime="STRONG_TREND",
            valve_score=Decimal("0.72"),
        )
        self.assertEqual(r_st100["effective_risk_bps"], 100)
        self.assertEqual(r_st100["effective_risk_pct"], "1.00")
        self.assertEqual(r_st100["effective_label"], "Extreme High Risk")
        self.assertEqual(r_st100["max_open_trades"], 8)
        self.assertEqual(r_st100["ai_discretion_reason"], "STRONG_TREND_HIGH_VALVE_EXTREME")

        # Ceiling clamp: ceiling_bps=88 caps STRONG_TREND+0.85 at 88 bps
        r_clamped = resolve_effective_params(
            60,
            Decimal("300000.00"),
            ai_discretion_enabled=True,
            ai_discretion_ceiling_bps=88,
            regime="STRONG_TREND",
            valve_score=Decimal("0.85"),
        )
        self.assertEqual(r_clamped["effective_risk_bps"], 88)
        self.assertLessEqual(Decimal(r_clamped["risk_pct"]), MAX_CONSTITUTIONAL_STOP_RISK_PCT)

    def test_manual_lock_holds_strictly_at_owner_risk_bps(self) -> None:
        res_down = resolve_effective_params(
            100,
            Decimal("300000.00"),
            ai_discretion_enabled=False,
            regime="CHOP_RANGE",
            consecutive_losses=5,
            drawdown_pct=Decimal("0.15"),
        )
        self.assertEqual(res_down["effective_risk_bps"], 100)
        self.assertEqual(res_down["ai_discretion_reason"], "MANUAL_LOCK")
        self.assertFalse(res_down["ai_discretion_shifted"])

        res_up = resolve_effective_params(
            37,
            Decimal("300000.00"),
            ai_discretion_enabled=False,
            regime="STRONG_TREND",
            valve_score=Decimal("0.90"),
        )
        self.assertEqual(res_up["effective_risk_bps"], 37)
        self.assertEqual(res_up["effective_risk_pct"], "0.37")
        self.assertEqual(res_up["ai_discretion_reason"], "MANUAL_LOCK")

        store = AggressionDialStore(self.db_path, now_fn=self.clock)
        store.set_ai_discretion(False, actor="wakil")
        store.set_master_risk_bps(97, live_mode=False, actor="wakil")
        snap = store.snapshot(
            regime="CHOP_RANGE",
            consecutive_losses=4,
            drawdown_pct=Decimal("0.12"),
        )
        self.assertFalse(snap["ai_discretion_enabled"])
        self.assertFalse(snap["auto_shift_enabled"])
        self.assertEqual(snap["effective_risk_bps"], 97)
        self.assertEqual(snap["effective_label"], "Extreme High Risk")
        self.assertEqual(snap["ai_discretion_reason"], "MANUAL_LOCK")

    def test_live_mode_high_risk_confirmation_gate_80_to_100_bps(self) -> None:
        store = AggressionDialStore(
            self.db_path,
            initial_ai_discretion_ceiling_bps=79,
            now_fn=self.clock,
        )

        # DEMO mode: 80..100 bps and ceiling 100 allowed with zero confirmation friction
        for bps in (80, 85, 95, 100):
            snap = store.set_master_risk_bps(bps, live_mode=False, high_risk_confirmed=False)
            self.assertEqual(snap["master_risk_bps"], bps)
        snap_ai = store.set_ai_discretion(
            True,
            ceiling_bps=100,
            live_mode=False,
            high_risk_confirmed=False,
        )
        self.assertEqual(snap_ai["ai_discretion_ceiling_bps"], 100)

        # Reset to 60 & ceiling 79
        store.set_master_risk_bps(60, ai_discretion_ceiling_bps=79, live_mode=True)

        # LIVE mode: 20..79 bps allowed without extra confirmation
        for bps in (20, 40, 60, 79):
            snap = store.set_master_risk_bps(bps, live_mode=True, high_risk_confirmed=False)
            self.assertEqual(snap["master_risk_bps"], bps)

        # LIVE mode: 80..100 bps & ceiling >= 80 MUST raise HighRiskConfirmationRequiredError
        before_audit = store.snapshot()["audit_count"]
        for bps in (80, 85, 95, 100):
            with self.assertRaises(HighRiskConfirmationRequiredError):
                store.set_master_risk_bps(bps, live_mode=True, high_risk_confirmed=False)
            with self.assertRaises(HighRiskConfirmationRequiredError):
                store.set_tier_risk_bps("TIER_5_300", bps, live_mode=True, high_risk_confirmed=False)
            with self.assertRaises(HighRiskConfirmationRequiredError):
                store.set_ai_discretion(
                    True,
                    ceiling_bps=bps,
                    live_mode=True,
                    high_risk_confirmed=False,
                )

        with self.assertRaises(HighRiskConfirmationRequiredError):
            store.apply_tier_preset(
                PRESET_STAGGER_SAFE_TO_HIGH,
                live_mode=True,
                high_risk_confirmed=False,
            )

        # Zero DB mutation occurred on rejected requests
        self.assertEqual(store.snapshot()["audit_count"], before_audit)
        self.assertEqual(store.snapshot()["master_risk_bps"], 79)

        # With high_risk_confirmed=True in LIVE mode, 80..100 bps & ceiling 100 succeed
        snap = store.set_master_risk_bps(100, live_mode=True, high_risk_confirmed=True)
        self.assertEqual(snap["master_risk_bps"], 100)
        snap = store.set_ai_discretion(
            True,
            ceiling_bps=100,
            live_mode=True,
            high_risk_confirmed=True,
        )
        self.assertEqual(snap["ai_discretion_ceiling_bps"], 100)

        with self.assertRaises(HighRiskConfirmationRequiredError):
            store.sync_all_tiers_to_master(live_mode=True, high_risk_confirmed=False)
        snap = store.sync_all_tiers_to_master(live_mode=True, high_risk_confirmed=True)
        self.assertEqual(snap["tiers_by_id"]["TIER_1_CURRENT"]["risk_bps"], 100)

        snap = store.apply_stagger_preset(live_mode=True, high_risk_confirmed=True)
        self.assertEqual(snap["tiers_by_id"]["TIER_5_300"]["risk_bps"], 100)
        self.assertTrue(store.verify_audit_chain())

    def test_paired_read_only_device_cannot_mutate_controls(self) -> None:
        store = AggressionDialStore(self.db_path, now_fn=self.clock)
        initial_audit = store.snapshot()["audit_count"]

        with self.assertRaises(OwnerKeyRequiredError):
            store.set_master_risk_bps(40, owner_controls_allowed=False, actor="paired-ipad")
        with self.assertRaises(OwnerKeyRequiredError):
            store.set_ai_discretion(False, owner_controls_allowed=False, actor="paired-ipad")
        with self.assertRaises(OwnerKeyRequiredError):
            store.set_auto_shift(False, owner_controls_allowed=False, actor="paired-ipad")
        with self.assertRaises(OwnerKeyRequiredError):
            store.set_tier_risk_bps("TIER_5_300", 85, owner_controls_allowed=False, actor="paired-ipad")
        with self.assertRaises(OwnerKeyRequiredError):
            store.sync_all_tiers_to_master(owner_controls_allowed=False, actor="paired-ipad")
        with self.assertRaises(OwnerKeyRequiredError):
            store.apply_stagger_preset(owner_controls_allowed=False, actor="paired-ipad")
        with self.assertRaises(OwnerKeyRequiredError):
            store.apply_tier_preset(
                PRESET_ALL_SAFE,
                owner_controls_allowed=False,
                actor="paired-ipad",
            )

        snap_ro = store.snapshot(owner_controls_allowed=False)
        self.assertFalse(snap_ro["owner_controls_allowed"])
        self.assertEqual(snap_ro["access_mode"], ACCESS_MODE_DEVICE_READ_AND_EXPLAINER)
        self.assertEqual(snap_ro["audit_count"], initial_audit)
        self.assertEqual(snap_ro["master_risk_bps"], 60)

        snap_owner = store.snapshot(owner_controls_allowed=True)
        self.assertTrue(snap_owner["owner_controls_allowed"])
        self.assertEqual(snap_owner["access_mode"], ACCESS_MODE_OWNER_FULL_CONTROL)

    def test_unbreakable_guardrails_at_100_bps_and_immutability(self) -> None:
        res = resolve_effective_params(100, Decimal("300000.00"), ai_discretion_enabled=False)
        g = res["guardrails"]
        self.assertTrue(g["valve_required"])
        self.assertEqual(g["valve_controller"], "tks_meta_valve_controller")
        self.assertEqual(g["valve_parameters"], 161)
        self.assertEqual(g["valve_cutoff"], "0.55")
        self.assertEqual(g["min_signal_prob"], "0.55")
        self.assertEqual(g["max_constitutional_stop_risk_pct"], "1.00")
        self.assertEqual(g["max_constitutional_drawdown_pct"], "0.10")
        self.assertEqual(g["min_margin_level_pct"], "1000.0")
        self.assertEqual(g["lot_floor"], "0.01")
        self.assertEqual(g["lot_rounding"], "ROUND_FLOOR")
        self.assertEqual(g["fast_stop_protection_ms"], 50)
        self.assertEqual(g["max_drawdown_brake_pct"], "10.00")

        # Mutating caller copy cannot weaken future guardrail calls
        g["valve_required"] = False
        g["valve_cutoff"] = "0.00"
        fresh = unbreakable_guardrails()
        self.assertTrue(fresh["valve_required"])
        self.assertEqual(fresh["valve_cutoff"], "0.55")

    def test_snapshot_and_verify_audit_chain_are_strictly_zero_write(self) -> None:
        store = AggressionDialStore(self.db_path, now_fn=self.clock)
        store.set_master_risk_bps(63, actor="wakil")

        with closing(sqlite3.connect(str(self.db_path))) as observer:
            dv_before = observer.execute("PRAGMA data_version").fetchone()[0]
            rows_before = observer.execute("SELECT COUNT(*) FROM dial_audit").fetchone()[0]

            s1 = store.snapshot()
            s2 = store.snapshot(
                regime="STRONG_TREND",
                valve_score=Decimal("0.75"),
            )
            s3 = store.snapshot(
                regime="CHOP_RANGE",
                consecutive_losses=2,
                drawdown_pct=Decimal("0.09"),
            )
            chain_ok = store.verify_audit_chain()

            dv_after = observer.execute("PRAGMA data_version").fetchone()[0]
            rows_after = observer.execute("SELECT COUNT(*) FROM dial_audit").fetchone()[0]

        self.assertTrue(chain_ok)
        self.assertEqual(dv_before, dv_after)
        self.assertEqual(rows_before, rows_after)
        self.assertEqual(s1["audit_count"], rows_before)
        self.assertEqual(s1["effective_risk_bps"], 63)
        self.assertEqual(s2["effective_risk_bps"], 100)
        self.assertEqual(s2["effective_label"], "Extreme High Risk")
        self.assertEqual(s3["effective_risk_bps"], 20)
        self.assertEqual(s3["effective_label"], "Safe")

    def test_sha256_audit_chain_detects_tampering(self) -> None:
        store = AggressionDialStore(self.db_path, now_fn=self.clock)
        store.set_master_risk_bps(44, actor="wakil")
        store.set_tier_risk_bps("TIER_5_300", 100, actor="wakil")
        self.assertTrue(store.verify_audit_chain())

        with closing(sqlite3.connect(str(self.db_path))) as conn:
            conn.execute(
                "UPDATE dial_audit SET actor = ? WHERE seq = 2",
                ("tampered_actor",),
            )
            conn.commit()

        self.assertFalse(store.verify_audit_chain())

    def test_strict_input_validation_rejects_bad_types_and_ranges(self) -> None:
        store = AggressionDialStore(self.db_path, now_fn=self.clock)

        for bad_bps in (0, 19, 101, -5, True, False, 60.0, "60", None):
            with self.assertRaises(AggressionDialError):
                store.set_master_risk_bps(bad_bps)  # type: ignore[arg-type]
            with self.assertRaises(AggressionDialError):
                resolve_effective_params(bad_bps, Decimal("1000.00"))  # type: ignore[arg-type]

        # Reject float money/drawdown/valve_score
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(60, 300000.0)  # type: ignore[arg-type]
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(60, Decimal("300000.00"), drawdown_pct=0.05)  # type: ignore[arg-type]
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(60, Decimal("300000.00"), valve_score=0.72)  # type: ignore[arg-type]
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(60, Decimal("300000.00"), valve_score=Decimal("1.01"))
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(
                60,
                Decimal("300000.00"),
                ai_discretion_enabled=True,
                auto_shift_enabled=False,
            )
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(60, Decimal("-100.00"))
        with self.assertRaises(AggressionDialError):
            resolve_effective_params(60, Decimal("NaN"))

        # Reject unknown tier & preset & empty actor
        with self.assertRaises(AggressionDialError):
            store.set_tier_risk_bps("TIER_UNKNOWN", 60)
        with self.assertRaises(AggressionDialError):
            store.apply_tier_preset("BOGUS_PRESET")
        with self.assertRaises(AggressionDialError):
            store.set_master_risk_bps(60, actor="   ")

    def test_source_hygiene_zero_assert_zero_crlf_zero_bom(self) -> None:
        src_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "cas_forex_revamp"
            / "valve"
            / "aggression_dial.py"
        )
        raw = src_path.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM detected")
        self.assertNotIn(b"\r", raw, "CRLF/CR line endings detected")

        tree = ast.parse(raw.decode("utf-8"), filename=str(src_path))
        assert_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        self.assertEqual(assert_nodes, [], "Bandit B101: assert statements prohibited in src/")


if __name__ == "__main__":
    unittest.main()
