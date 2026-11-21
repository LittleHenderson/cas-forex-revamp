"""Unit tests for CompoundingAndMilestoneController (PR #28)."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.treasury.compounding_controller import (
    COMPOUNDING_CONTROLLER_SCHEMA,
    CompoundingAndMilestoneController,
    CompoundingControllerError,
    CompoundingMode,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    MIN_MARGIN_LEVEL_PCT,
    OwnerKeyRequiredError,
    STATUS_BUILDING_TOWARD_PRINCIPAL,
    STATUS_COMPOUNDING_TO_DOUBLE,
    STATUS_HOUSE_MONEY_READY,
    STATUS_PLAYING_ON_HOUSE_MONEY,
    compute_effective_vault_sweep_ratio,
)


def _assert_no_floats_recursive(obj: object, path: str = "root") -> None:
    if isinstance(obj, float):
        raise AssertionError(f"Unexpected float at {path}: {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _assert_no_floats_recursive(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for idx, v in enumerate(obj):
            _assert_no_floats_recursive(v, f"{path}[{idx}]")


class TestCompoundingAndMilestoneController(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self.db_path = self.tmp_path / "compounding.sqlite3"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_5000_compounding_lifecycle_to_house_money_and_withdrawal(self) -> None:
        t0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
            mode=CompoundingMode.FULL_COMPOUND_100,
            now_utc=t0,
        )

        # 1. Underwater ($4,200.00)
        ev_under = ctrl.evaluate_milestones(Decimal("4200.00"))
        self.assertEqual(ev_under.house_money_status, STATUS_BUILDING_TOWARD_PRINCIPAL)
        self.assertFalse(ev_under.house_money_ready)
        self.assertEqual(ev_under.suggested_principal_pullout_usd, Decimal("0.00"))
        self.assertEqual(ev_under.progress_to_house_money_pct, Decimal("0.00"))
        self.assertEqual(ev_under.remaining_to_house_money_usd, Decimal("5800.00"))
        self.assertEqual(ev_under.effective_vault_sweep_ratio, Decimal("0.00"))

        # 2. At starting principal ($5,000.00)
        ev_start = ctrl.evaluate_milestones(Decimal("5000.00"))
        self.assertEqual(ev_start.house_money_status, STATUS_COMPOUNDING_TO_DOUBLE)
        self.assertFalse(ev_start.house_money_ready)
        self.assertEqual(ev_start.suggested_principal_pullout_usd, Decimal("0.00"))
        self.assertEqual(ev_start.progress_to_house_money_pct, Decimal("0.00"))
        self.assertEqual(ev_start.remaining_to_house_money_usd, Decimal("5000.00"))
        self.assertEqual(ev_start.effective_vault_sweep_ratio, Decimal("0.00"))

        # 3. Halfway to double ($7,500.00): still 100% compounding (0.00 vault ratio)
        ev_mid = ctrl.evaluate_milestones(Decimal("7500.00"))
        self.assertEqual(ev_mid.house_money_status, STATUS_COMPOUNDING_TO_DOUBLE)
        self.assertFalse(ev_mid.house_money_ready)
        self.assertEqual(ev_mid.suggested_principal_pullout_usd, Decimal("0.00"))
        self.assertEqual(ev_mid.progress_to_house_money_pct, Decimal("50.00"))
        self.assertEqual(ev_mid.remaining_to_house_money_usd, Decimal("2500.00"))
        self.assertEqual(ev_mid.effective_vault_sweep_ratio, Decimal("0.00"))

        # 4. Doubled ($10,000.00): House-Money Ready + auto-transition to 0.50 vault ratio
        ev_double = ctrl.evaluate_milestones(Decimal("10000.00"))
        self.assertEqual(ev_double.house_money_status, STATUS_HOUSE_MONEY_READY)
        self.assertTrue(ev_double.house_money_ready)
        self.assertEqual(ev_double.suggested_principal_pullout_usd, Decimal("5000.00"))
        self.assertEqual(ev_double.progress_to_house_money_pct, Decimal("100.00"))
        self.assertEqual(ev_double.remaining_to_house_money_usd, Decimal("0.00"))
        self.assertEqual(ev_double.effective_vault_sweep_ratio, Decimal("0.50"))

        # 5. Owner pulls original $5,000.00 principal -> PLAYING_ON_HOUSE_MONEY
        t1 = datetime(2026, 11, 20, 14, 30, 0, tzinfo=timezone.utc)
        state = ctrl.acknowledge_principal_withdrawn(
            Decimal("5000.00"),
            owner_controls_allowed=True,
            actor="owner:wakil",
            post_withdrawal_equity_usd=Decimal("5000.00"),
            now_utc=t1,
        )
        self.assertTrue(state.principal_withdrawn)
        self.assertEqual(state.principal_withdrawn_usd, Decimal("5000.00"))
        self.assertEqual(state.principal_withdrawn_at_utc, "2026-11-20T14:30:00Z")

        ev_house = ctrl.evaluate_milestones(Decimal("5000.00"))
        self.assertEqual(ev_house.house_money_status, STATUS_PLAYING_ON_HOUSE_MONEY)
        self.assertFalse(ev_house.house_money_ready)
        self.assertEqual(ev_house.suggested_principal_pullout_usd, Decimal("0.00"))
        self.assertEqual(ev_house.progress_to_house_money_pct, Decimal("100.00"))
        self.assertEqual(ev_house.remaining_to_house_money_usd, Decimal("0.00"))
        self.assertTrue(ctrl.verify_audit_chain())

        # Re-open persisted controller and confirm state survives restart
        ctrl_reopened = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
        )
        snap = ctrl_reopened.snapshot()
        self.assertEqual(snap["house_money_status"], STATUS_PLAYING_ON_HOUSE_MONEY)
        self.assertTrue(snap["principal_withdrawn"])
        self.assertEqual(snap["principal_withdrawn_usd"], "5000.00")
        self.assertTrue(snap["audit_chain_valid"])

    def test_unbreakable_recovery_invariant_across_all_modes(self) -> None:
        principal = Decimal("5000.00")
        for mode, custom_ratio, above_expected in (
            (CompoundingMode.FULL_COMPOUND_100, Decimal("0.00"), Decimal("0.00")),
            (CompoundingMode.BALANCED_SPLIT_50_50, Decimal("0.00"), Decimal("0.50")),
            (CompoundingMode.CUSTOM_SPLIT, Decimal("0.35"), Decimal("0.35")),
        ):
            db = self.tmp_path / f"recovery_{mode.value}.sqlite3"
            ctrl = CompoundingAndMilestoneController(
                db,
                starting_principal_usd=principal,
                mode=mode,
                custom_vault_ratio=custom_ratio,
            )
            # Strictly below principal -> ALWAYS 0.00
            self.assertEqual(
                ctrl.effective_vault_sweep_ratio(Decimal("0.00")), Decimal("0.00")
            )
            self.assertEqual(
                ctrl.effective_vault_sweep_ratio(Decimal("4999.99")), Decimal("0.00")
            )
            # Exactly at principal -> ALWAYS 0.00
            self.assertEqual(
                ctrl.effective_vault_sweep_ratio(Decimal("5000.00")), Decimal("0.00")
            )
            # Above principal ($5,000.01) -> mode-defined ratio
            self.assertEqual(
                ctrl.effective_vault_sweep_ratio(Decimal("5000.01")), above_expected
            )

    def test_configurable_compounding_target_and_auto_vault_toggle(self) -> None:
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
            mode=CompoundingMode.FULL_COMPOUND_100,
            compounding_target_usd=Decimal("25000.00"),
            house_money_target_usd=Decimal("10000.00"),
            post_target_vault_ratio=Decimal("0.40"),
            auto_enable_vault_at_target=True,
        )

        # At $10,000: House-Money ready, but still below $25,000 compounding target -> 0.00 sweep
        ev10k = ctrl.evaluate_milestones(Decimal("10000.00"))
        self.assertTrue(ev10k.house_money_ready)
        self.assertEqual(ev10k.effective_vault_sweep_ratio, Decimal("0.00"))

        # At $24,999.99: still 0.00
        self.assertEqual(
            ctrl.effective_vault_sweep_ratio(Decimal("24999.99")), Decimal("0.00")
        )
        # At $25,000.00: transitions cleanly to post_target_vault_ratio (0.40)
        self.assertEqual(
            ctrl.effective_vault_sweep_ratio(Decimal("25000.00")), Decimal("0.40")
        )

        # Disable auto_enable_vault_at_target -> stays 0.00 even at $30,000.00
        ctrl.set_compounding_mode(
            CompoundingMode.FULL_COMPOUND_100,
            auto_enable_vault_at_target=False,
            owner_controls_allowed=True,
        )
        self.assertEqual(
            ctrl.effective_vault_sweep_ratio(Decimal("30000.00")), Decimal("0.00")
        )

    def test_milestone_ladder_5k_and_300k_barbell(self) -> None:
        ctrl_5k = CompoundingAndMilestoneController(
            self.tmp_path / "m5k.sqlite3",
            starting_principal_usd=Decimal("5000.00"),
        )
        ev = ctrl_5k.evaluate_milestones(Decimal("10000.00"))
        targets_5k = [(m.key, m.label, m.target_usd, m.reached) for m in ev.milestones]
        self.assertEqual(
            targets_5k,
            [
                ("HOUSE_MONEY_2X", "2x House Money", Decimal("10000.00"), True),
                ("ACCELERATOR_5X", "5x Accelerator", Decimal("25000.00"), False),
                ("GROWTH_10X", "10x Growth", Decimal("50000.00"), False),
                ("INSTITUTIONAL_50X", "50x Institutional Income Tier", Decimal("250000.00"), False),
            ],
        )
        self.assertIsNotNone(ev.next_milestone)
        self.assertEqual(ev.next_milestone.key, "ACCELERATOR_5X")
        self.assertEqual(ev.next_milestone.remaining_usd, Decimal("15000.00"))
        self.assertEqual(ev.next_milestone.progress_pct, Decimal("25.00"))

        # $300,000.00 practice barbell support
        ctrl_300k = CompoundingAndMilestoneController(
            self.tmp_path / "m300k.sqlite3",
            starting_principal_usd=Decimal("300000.00"),
        )
        ev_300k = ctrl_300k.evaluate_milestones(Decimal("600000.00"))
        self.assertTrue(ev_300k.house_money_ready)
        self.assertEqual(ev_300k.suggested_principal_pullout_usd, Decimal("300000.00"))
        self.assertEqual(
            [m.target_usd for m in ev_300k.milestones],
            [
                Decimal("600000.00"),
                Decimal("1500000.00"),
                Decimal("3000000.00"),
                Decimal("15000000.00"),
            ],
        )

    def test_dynamic_sizing_scaling_matrix(self) -> None:
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
            mode=CompoundingMode.FULL_COMPOUND_100,
        )
        expected_matrix = [
            (Decimal("5000.00"), Decimal("0.60"), Decimal("30.00")),
            (Decimal("5000.00"), Decimal("0.85"), Decimal("42.50")),
            (Decimal("5000.00"), Decimal("1.00"), Decimal("50.00")),
            (Decimal("10000.00"), Decimal("0.60"), Decimal("60.00")),
            (Decimal("10000.00"), Decimal("0.85"), Decimal("85.00")),
            (Decimal("10000.00"), Decimal("1.00"), Decimal("100.00")),
            (Decimal("25000.00"), Decimal("0.60"), Decimal("150.00")),
            (Decimal("25000.00"), Decimal("0.85"), Decimal("212.50")),
            (Decimal("25000.00"), Decimal("1.00"), Decimal("250.00")),
            (Decimal("50000.00"), Decimal("0.60"), Decimal("300.00")),
            (Decimal("50000.00"), Decimal("0.85"), Decimal("425.00")),
            (Decimal("50000.00"), Decimal("1.00"), Decimal("500.00")),
        ]
        for equity, risk_pct, expected_usd in expected_matrix:
            budget = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=equity,
                risk_pct=risk_pct,
                open_pyramid_count=1,
                max_open_trades=4,
                daily_loss_remaining_usd=Decimal("5000.00"),
                drawdown_pct=Decimal("0.02"),
                margin_level_pct=Decimal("1500.0"),
            )
            self.assertTrue(budget.allowed, f"failed for {equity} @ {risk_pct}%")
            self.assertEqual(budget.reason_code, "APPROVED")
            self.assertEqual(budget.per_trade_risk_usd, expected_usd)
            self.assertEqual(budget.remaining_pyramid_slots, 3)
            self.assertEqual(budget.max_total_open_risk_usd, expected_usd * Decimal("4"))

        # Daily loss remaining clamps per-trade and total open risk cleanly
        clamped = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("10000.00"),
            risk_pct=Decimal("0.85"),
            open_pyramid_count=0,
            max_open_trades=3,
            daily_loss_remaining_usd=Decimal("50.00"),
            drawdown_pct=Decimal("0.01"),
        )
        self.assertTrue(clamped.allowed)
        self.assertEqual(clamped.per_trade_risk_usd, Decimal("50.00"))
        self.assertEqual(clamped.max_total_open_risk_usd, Decimal("50.00"))

    def test_pr25_constitutional_refusals_fail_closed(self) -> None:
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
        )
        self.assertEqual(MAX_CONSTITUTIONAL_STOP_RISK_PCT, Decimal("1.00"))
        self.assertEqual(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, Decimal("0.10"))
        self.assertEqual(MIN_MARGIN_LEVEL_PCT, Decimal("1000.0"))

        # > 1.00% risk_pct refused fail-closed
        over_risk = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("10000.00"),
            risk_pct=Decimal("1.01"),
            open_pyramid_count=0,
            max_open_trades=3,
            daily_loss_remaining_usd=Decimal("1000.00"),
            drawdown_pct=Decimal("0.00"),
        )
        self.assertFalse(over_risk.allowed)
        self.assertEqual(over_risk.reason_code, "CONSTITUTIONAL_STOP_RISK_EXCEEDED")
        self.assertEqual(over_risk.per_trade_risk_usd, Decimal("0.00"))

        # <= 0% risk_pct refused
        zero_risk = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("10000.00"),
            risk_pct=Decimal("0.00"),
        )
        self.assertFalse(zero_risk.allowed)
        self.assertEqual(zero_risk.reason_code, "NON_POSITIVE_RISK_PCT")

        # >= 10.00% (0.10) drawdown refused fail-closed
        for dd in (Decimal("0.10"), Decimal("0.15")):
            dd_res = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("9000.00"),
                risk_pct=Decimal("0.85"),
                drawdown_pct=dd,
            )
            self.assertFalse(dd_res.allowed)
            self.assertEqual(dd_res.reason_code, "CONSTITUTIONAL_DRAWDOWN_LIMIT_REACHED")
            self.assertEqual(dd_res.per_trade_risk_usd, Decimal("0.00"))

        # Just below 10.00% (0.0999) still allowed
        dd_ok = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("9000.00"),
            risk_pct=Decimal("0.85"),
            drawdown_pct=Decimal("0.0999"),
        )
        self.assertTrue(dd_ok.allowed)

        # Margin level < 1000.0% refused fail-closed
        low_margin = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("10000.00"),
            risk_pct=Decimal("0.85"),
            margin_level_pct=Decimal("999.9"),
        )
        self.assertFalse(low_margin.allowed)
        self.assertEqual(low_margin.reason_code, "CONSTITUTIONAL_MARGIN_LEVEL_BREACH")

        # open_pyramid_count >= max_open_trades refused
        full_slots = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("10000.00"),
            risk_pct=Decimal("0.85"),
            open_pyramid_count=3,
            max_open_trades=3,
        )
        self.assertFalse(full_slots.allowed)
        self.assertEqual(full_slots.reason_code, "MAX_PYRAMID_SLOTS_REACHED")
        self.assertEqual(full_slots.remaining_pyramid_slots, 0)

        # daily_loss_remaining_usd <= 0 refused
        no_daily = ctrl.compute_compounding_sizing_budget(
            current_equity_usd=Decimal("10000.00"),
            risk_pct=Decimal("0.85"),
            daily_loss_remaining_usd=Decimal("0.00"),
        )
        self.assertFalse(no_daily.allowed)
        self.assertEqual(no_daily.reason_code, "DAILY_LOSS_BUDGET_EXHAUSTED")

        # max_open_trades outside 1..8 raises CompoundingControllerError
        with self.assertRaises(CompoundingControllerError):
            ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("10000.00"),
                risk_pct=Decimal("0.85"),
                max_open_trades=0,
            )
        with self.assertRaises(CompoundingControllerError):
            ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("10000.00"),
                risk_pct=Decimal("0.85"),
                max_open_trades=9,
            )

    def test_owner_key_required_on_read_only_tablets(self) -> None:
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
        )
        before = ctrl.snapshot()

        with self.assertRaises(OwnerKeyRequiredError):
            ctrl.set_compounding_mode(
                CompoundingMode.BALANCED_SPLIT_50_50,
                owner_controls_allowed=False,
                actor="tablet-readonly",
            )

        with self.assertRaises(OwnerKeyRequiredError):
            ctrl.acknowledge_principal_withdrawn(
                Decimal("5000.00"),
                owner_controls_allowed=False,
                actor="tablet-readonly",
            )

        # Non-bool truthy values must also be denied
        with self.assertRaises(OwnerKeyRequiredError):
            ctrl.set_compounding_mode(
                CompoundingMode.BALANCED_SPLIT_50_50,
                owner_controls_allowed=1,  # type: ignore[arg-type]
            )

        after = ctrl.snapshot()
        self.assertEqual(before["mode"], after["mode"])
        self.assertEqual(before["audit_entry_count"], after["audit_entry_count"])
        self.assertFalse(after["principal_withdrawn"])

    def test_strict_decimal_and_boundary_validation(self) -> None:
        with self.assertRaises(CompoundingControllerError):
            CompoundingAndMilestoneController(
                self.db_path,
                starting_principal_usd=5000.0,  # type: ignore[arg-type]
            )
        with self.assertRaises(CompoundingControllerError):
            CompoundingAndMilestoneController(
                ":memory:",
                starting_principal_usd=Decimal("5000.00"),
            )
        with self.assertRaises(CompoundingControllerError):
            CompoundingAndMilestoneController(
                self.db_path,
                starting_principal_usd=Decimal("5000.00"),
                custom_vault_ratio=Decimal("0.51"),
            )
        with self.assertRaises(CompoundingControllerError):
            CompoundingAndMilestoneController(
                self.db_path,
                starting_principal_usd=Decimal("5000.00"),
                compounding_target_usd=Decimal("5000.00"),
            )

        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
        )
        with self.assertRaises(CompoundingControllerError):
            ctrl.compute_compounding_sizing_budget(
                current_equity_usd=10000.0,  # type: ignore[arg-type]
                risk_pct=Decimal("0.85"),
            )
        with self.assertRaises(CompoundingControllerError):
            ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("10000.00"),
                risk_pct=0.85,  # type: ignore[arg-type]
            )
        with self.assertRaises(CompoundingControllerError):
            ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("NaN"),
                risk_pct=Decimal("0.85"),
            )
        with self.assertRaises(CompoundingControllerError):
            compute_effective_vault_sweep_ratio(
                mode=CompoundingMode.CUSTOM_SPLIT,
                starting_principal_usd=Decimal("5000.00"),
                current_equity_usd=Decimal("8000.00"),
                compounding_target_usd=Decimal("10000.00"),
                custom_vault_ratio=Decimal("0.75"),
            )

    def test_snapshot_strictly_zero_write_mode_ro_data_version_invariant(self) -> None:
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
            mode=CompoundingMode.FULL_COMPOUND_100,
        )
        ctrl.record_equity_checkpoint(Decimal("7500.00"), actor="broker-sync")

        with closing(sqlite3.connect(str(self.db_path), timeout=5.0)) as obs:
            v_before = obs.execute("PRAGMA data_version").fetchone()[0]

            snap_default = ctrl.snapshot()
            snap_override = ctrl.snapshot(current_equity_usd=Decimal("10000.00"))
            chain_ok = ctrl.verify_audit_chain()
            _ = ctrl.evaluate_milestones(Decimal("8000.00"))
            _ = ctrl.effective_vault_sweep_ratio(Decimal("8000.00"))
            _ = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=Decimal("8000.00"),
                risk_pct=Decimal("0.85"),
            )

            v_after = obs.execute("PRAGMA data_version").fetchone()[0]

        self.assertEqual(v_before, v_after, "read-only snapshot/queries MUST NOT mutate data_version")
        self.assertTrue(chain_ok)
        self.assertEqual(snap_default["schema"], COMPOUNDING_CONTROLLER_SCHEMA)
        self.assertEqual(snap_default["current_equity_usd"], "7500.00")
        self.assertEqual(snap_default["progress_to_house_money_pct"], "50.00")
        self.assertEqual(snap_default["effective_vault_sweep_ratio"], "0.00")
        self.assertEqual(snap_default["retained_compounding_ratio"], "1.00")
        self.assertTrue(snap_default["audit_chain_valid"])

        self.assertEqual(snap_override["current_equity_usd"], "10000.00")
        self.assertTrue(snap_override["house_money_ready"])
        self.assertEqual(snap_override["house_money_status"], STATUS_HOUSE_MONEY_READY)
        self.assertEqual(snap_override["suggested_principal_pullout_usd"], "5000.00")
        self.assertEqual(snap_override["effective_vault_sweep_ratio"], "0.50")

        # Zero floats anywhere in snapshot JSON
        _assert_no_floats_recursive(snap_default)
        _assert_no_floats_recursive(snap_override)
        roundtrip = json.loads(json.dumps(snap_override))
        self.assertEqual(roundtrip["schema"], COMPOUNDING_CONTROLLER_SCHEMA)

    def test_sha256_audit_chain_tamper_detection(self) -> None:
        # Subcase A: payload tampering
        db_a = self.tmp_path / "tamper_payload.sqlite3"
        ctrl_a = CompoundingAndMilestoneController(db_a, starting_principal_usd=Decimal("5000.00"))
        ctrl_a.set_compounding_mode(CompoundingMode.BALANCED_SPLIT_50_50, owner_controls_allowed=True)
        ctrl_a.acknowledge_principal_withdrawn(Decimal("5000.00"), owner_controls_allowed=True)
        self.assertTrue(ctrl_a.verify_audit_chain())

        with closing(sqlite3.connect(str(db_a))) as conn:
            conn.execute(
                "UPDATE compounding_audit SET payload_json = ? WHERE seq = ?",
                ('{"tampered":true}', 2),
            )
            conn.commit()
        self.assertFalse(ctrl_a.verify_audit_chain())
        self.assertFalse(ctrl_a.snapshot()["audit_chain_valid"])

        # Subcase B: trailing row deletion (caught via sqlite_sequence high-water mark)
        db_b = self.tmp_path / "tamper_tail_delete.sqlite3"
        ctrl_b = CompoundingAndMilestoneController(db_b, starting_principal_usd=Decimal("5000.00"))
        ctrl_b.set_compounding_mode(CompoundingMode.CUSTOM_SPLIT, custom_vault_ratio=Decimal("0.25"))
        self.assertTrue(ctrl_b.verify_audit_chain())

        with closing(sqlite3.connect(str(db_b))) as conn:
            conn.execute("DELETE FROM compounding_audit WHERE seq = 2")
            conn.commit()
        self.assertFalse(ctrl_b.verify_audit_chain())

        # Subcase C: total audit wipe while config exists
        db_c = self.tmp_path / "tamper_wipe.sqlite3"
        ctrl_c = CompoundingAndMilestoneController(db_c, starting_principal_usd=Decimal("5000.00"))
        with closing(sqlite3.connect(str(db_c))) as conn:
            conn.execute("DELETE FROM compounding_audit")
            conn.commit()
        self.assertFalse(ctrl_c.verify_audit_chain())

    def test_thread_safety_concurrent_reads_and_writes(self) -> None:
        ctrl = CompoundingAndMilestoneController(
            self.db_path,
            starting_principal_usd=Decimal("5000.00"),
        )

        def _worker(idx: int) -> bool:
            equity = Decimal("5000.00") + Decimal(idx * 100)
            ctrl.record_equity_checkpoint(equity, actor=f"worker-{idx}")
            snap = ctrl.snapshot()
            budget = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=equity,
                risk_pct=Decimal("0.85"),
            )
            return bool(snap["audit_chain_valid"] and budget.allowed)

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(_worker, range(12)))

        self.assertTrue(all(results))
        self.assertTrue(ctrl.verify_audit_chain())
        self.assertEqual(ctrl.snapshot()["audit_entry_count"], 13)

    def test_source_hygiene_zero_assert_zero_float_zero_crlf_zero_bom(self) -> None:
        src_file = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "cas_forex_revamp"
            / "treasury"
            / "compounding_controller.py"
        )
        raw = src_file.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM forbidden")
        self.assertNotIn(b"\r", raw, "CRLF/CR forbidden")

        text = raw.decode("utf-8")
        tree = ast.parse(text, filename=str(src_file))
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, ast.Assert, "assert statements forbidden in src/")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(
                    node.func.id,
                    {"float", "eval", "exec"},
                    f"forbidden builtin call {node.func.id}() in src/",
                )


if __name__ == "__main__":
    unittest.main()
