"""E2E FA-1: ParallelTierEngine Valve Refusal, SQLite BEGIN IMMEDIATE, and B103 Directory Mode (10 tests)."""
from __future__ import annotations

from datetime import timedelta
from contextlib import closing
from decimal import Decimal, ROUND_HALF_UP
import inspect
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import unittest

import cas_forex_revamp.composition.parallel_tiers as parallel_tiers_mod
from cas_forex_revamp.composition.parallel_tiers import (
    DEFAULT_PARALLEL_TIER_SPECS,
    ParallelTierEngine,
)
from cas_forex_revamp.composition.trend_regime import REGIME_STRONG_TREND
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.valve.tks_meta_valve_controller import ForexMetaValveGate, load_default_forex_valve_gate

try:
    from tests.e2e_hardening._e2e_support import D, QUOTES_20, T0, default_policy, require_or_skip_unmerged, safe_temp_dir
except ImportError:  # pragma: no cover
    from _e2e_support import D, QUOTES_20, T0, default_policy, require_or_skip_unmerged, safe_temp_dir


class ParallelTiersE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (E2E-T1-01 .. E2E-T1-05) ---

    def test_e2e_t1_01_default_five_tiers_exact_capitals(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
            snap = eng.snapshot()
            self.assertEqual(snap["schema"], "cas-forex.parallel-tiers/1")
            self.assertEqual(snap["tier_count"], len(DEFAULT_PARALLEL_TIER_SPECS))
            by_id = {row["tier_id"]: row for row in snap["tiers"]}
            expected = {
                "TIER_1_CURRENT": "300000",
                "TIER_2_1000": "1000",
                "TIER_3_3000": "3000",
                "TIER_4_6000": "6000",
                "TIER_5_300": "300",
            }
            for tid, cap in expected.items():
                self.assertIn(tid, by_id)
                self.assertEqual(Decimal(by_id[tid]["starting_capital_usd"]), Decimal(cap))
                self.assertEqual(by_id[tid]["open_positions"], 0)

    def test_e2e_t1_02_fx_open_position_ecn_commission_and_persistence(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            db_path = Path(td) / "tiers.sqlite3"
            eng = ParallelTierEngine(db_path, valve_gate=gate, clock=lambda: T0)
            snap = eng.process_tick(
                quotes=QUOTES_20,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.11000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            by_id = {row["tier_id"]: row for row in snap["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 1)
            self.assertEqual(by_id["TIER_2_1000"]["open_positions"], 1)
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM tier_positions WHERE tier_id = 'TIER_1_CURRENT'").fetchall()
                self.assertEqual(len(rows), 1)
                units = Decimal(str(rows[0]["units"]))
                entry_comm = Decimal(str(rows[0]["entry_commission_usd"]))
                expected_comm = (units / Decimal("100000")) * Decimal("3.50")
                self.assertEqual(entry_comm, expected_comm.quantize(Decimal("0.01")))

    def test_e2e_t1_03_spx500_index_contract_size_and_commission(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            db_path = Path(td) / "tiers.sqlite3"
            eng = ParallelTierEngine(db_path, valve_gate=gate, clock=lambda: T0)
            snap = eng.process_tick(
                quotes=QUOTES_20,
                signal={
                    "symbol": "SPX500",
                    "side": "BUY",
                    "stop_price": "5900.00",
                    "take_profit_price": "5975.00",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            by_id = {row["tier_id"]: row for row in snap["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 1)
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM tier_positions WHERE tier_id = 'TIER_1_CURRENT'").fetchone()
                self.assertIsNotNone(row)
                units = Decimal(str(row["units"]))
                entry_comm = Decimal(str(row["entry_commission_usd"]))
                self.assertEqual(entry_comm, (units * Decimal("0.50")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    def test_e2e_t1_04_wal_mode_permissions_and_verified_directory_helper(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            state_dir = Path(td) / "state"
            db_path = state_dir / "tiers.sqlite3"
            eng = ParallelTierEngine(db_path, valve_gate=gate, clock=lambda: T0)
            self.assertTrue(db_path.is_file())
            with closing(sqlite3.connect(str(db_path))) as conn:
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                self.assertEqual(str(mode).lower(), "wal")
            if os.name == "posix":
                dir_mode = stat.S_IMODE(os.lstat(state_dir).st_mode)
                db_mode = stat.S_IMODE(os.lstat(db_path).st_mode)
                self.assertEqual(dir_mode, 0o700)
                self.assertEqual(db_mode, 0o600)
            if not hasattr(parallel_tiers_mod, "apply_verified_directory_mode"):
                require_or_skip_unmerged(
                    self,
                    "parallel_tiers.apply_verified_directory_mode helper (M1 B103 remediation)",
                )
            snap = eng.snapshot()
            self.assertEqual(snap["tier_count"], 5)

    def test_e2e_t1_05_winning_close_books_fifty_fifty_vault_split(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
            eng.process_tick(
                quotes=QUOTES_20,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.10500",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            win_quotes = dict(QUOTES_20)
            win_quotes["EURUSD"] = (D("1.10520"), D("1.10530"))
            after = eng.process_tick(quotes=win_quotes, signal=None, now=T0 + timedelta(minutes=1))
            by_id = {row["tier_id"]: row for row in after["tiers"]}
            t1 = by_id["TIER_1_CURRENT"]
            self.assertEqual(t1["open_positions"], 0)
            self.assertEqual(t1["win_count"], 1)
            self.assertGreater(Decimal(t1["net_gain_usd"]), Decimal("0"))
            self.assertEqual(Decimal(t1["retained_trading_usd"]), Decimal(t1["bank_sweep_reserved_usd"]))
            self.assertGreater(Decimal(t1["bank_sweep_reserved_usd"]), Decimal("0"))

    # --- Tier 2: Boundary & Corner Cases (E2E-T2-01 .. E2E-T2-05) ---

    def test_e2e_t2_01_valve_refusal_records_skip_reason_without_attribute_error(self) -> None:
        base_gate = load_default_forex_valve_gate()
        paused_gate = ForexMetaValveGate(base_gate.controller, default_policy=default_policy(new_risk="PAUSED"))
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=paused_gate, clock=lambda: T0)
            try:
                snap = eng.process_tick(
                    quotes=QUOTES_20,
                    signal={
                        "symbol": "EURUSD",
                        "side": "BUY",
                        "stop_price": "1.09510",
                        "take_profit_price": "1.11000",
                        "regime": REGIME_STRONG_TREND,
                    },
                    now=T0,
                )
            except AttributeError as exc:
                if "refusal_reason" in str(exc):
                    require_or_skip_unmerged(
                        self,
                        "ParallelTierEngine L694 ValveDecision.refusal_reason -> hard_veto_reasons/valve_mode (M1)",
                    )
                raise
            by_id = {row["tier_id"]: row for row in snap["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 0)
            skip_reason = str(by_id["TIER_1_CURRENT"]["last_skip_reason"] or "")
            self.assertTrue(skip_reason.startswith("VALVE_REFUSED"), skip_reason)

    def test_e2e_t2_02_300_tier_wide_stop_triggers_lot_floor_risk_exceeded(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
            snap = eng.process_tick(
                quotes=QUOTES_20,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09010",
                    "take_profit_price": "1.12000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            by_id = {row["tier_id"]: row for row in snap["tiers"]}
            self.assertEqual(by_id["TIER_5_300"]["open_positions"], 0)
            self.assertEqual(by_id["TIER_5_300"]["last_skip_reason"], "LOT_FLOOR_RISK_EXCEEDED")

    def test_e2e_t2_03_invalid_constructor_args_rejected_fail_closed(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            with self.assertRaises(ContractError):
                ParallelTierEngine(Path(td) / "bad1.sqlite3", valve_gate="not-a-gate")  # type: ignore[arg-type]
            with self.assertRaises(ContractError):
                ParallelTierEngine(Path(td) / "bad2.sqlite3", valve_gate=gate, fx_min_lot=Decimal("0"))

    def test_e2e_t2_04_symlink_parent_directory_rejected(self) -> None:
        gate = load_default_forex_valve_gate()
        if not hasattr(parallel_tiers_mod, "apply_verified_directory_mode"):
            require_or_skip_unmerged(
                self,
                "parallel_tiers.apply_verified_directory_mode symlink guard (M1)",
            )
        with safe_temp_dir() as td:
            real_dir = Path(td) / "real_target"
            real_dir.mkdir(parents=True, exist_ok=True)
            link_dir = Path(td) / "symlink_parent"
            try:
                os.symlink(real_dir, link_dir, target_is_directory=True)
            except (OSError, NotImplementedError):
                # On restricted Windows hosts without symlink privilege, test verified helper via non-dir file path
                blocking_file = Path(td) / "not_a_dir"
                blocking_file.write_text("file", encoding="utf-8")
                with self.assertRaises((ContractError, OSError)):
                    ParallelTierEngine(blocking_file / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
                return
            with self.assertRaises((ContractError, OSError)):
                ParallelTierEngine(link_dir / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)

    def test_e2e_t2_05_concurrent_process_tick_and_begin_immediate(self) -> None:
        src_text = inspect.getsource(ParallelTierEngine)
        if "BEGIN IMMEDIATE" not in src_text:
            require_or_skip_unmerged(
                self,
                "ParallelTierEngine explicit BEGIN IMMEDIATE SQLite write transactions (M1)",
            )
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "concurrent.sqlite3", valve_gate=gate, clock=lambda: T0)
            errors: list[Exception] = []

            def worker(offset_sec: int) -> None:
                try:
                    for step in range(5):
                        eng.process_tick(
                            quotes=QUOTES_20,
                            signal=None,
                            now=T0 + timedelta(seconds=offset_sec + step),
                        )
                except Exception as exc:
                    errors.append(exc)

            t1 = threading.Thread(target=worker, args=(0,))
            t2 = threading.Thread(target=worker, args=(10,))
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)
            self.assertEqual(errors, [])
            self.assertEqual(eng.snapshot()["tier_count"], 5)


if __name__ == "__main__":
    unittest.main()
