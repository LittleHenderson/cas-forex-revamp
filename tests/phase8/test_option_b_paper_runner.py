"""Unit & integration regression tests for Option B $5,000.00 Paper Demo Runner (PR #38)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.composition.option_b_paper_runner import (
    OPTION_B_DEFAULT_STARTING_EQUITY_USD,
    OPTION_B_DEMO_SCHEMA,
    OptionBPaperDemoRunner,
)
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.futures.tradovate_venue import TradovateLiveLockError
from cas_forex_revamp.valve import ForexMetaValveGate
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision


class _StubValveGate:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls = 0

    def evaluate(self, proposal, *, current_view=None, policy=None, now=None) -> ValveDecision:
        self.calls += 1
        return ValveDecision(
            admitted=self.allowed,
            valve_mode="ADMITTED" if self.allowed else "MLP_SCORE_VETO",
            mlp_score=0.91 if self.allowed else 0.12,
            threshold=0.55,
            mlp_admitted=self.allowed,
            hard_veto=not self.allowed,
            hard_veto_reasons=() if self.allowed else ("TEST_VETO",),
            features={},
            weights_sha256="a" * 64,
            request_id=proposal.request.request_id,
            selected_action_ref=proposal.result.selection.selected_action_ref,
        )


class OptionBPaperDemoRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)
        self.clock_now = datetime(2026, 11, 22, 23, 0, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _clock(self) -> datetime:
        return self.clock_now

    def _advance(self, seconds: int) -> datetime:
        self.clock_now = self.clock_now + timedelta(seconds=seconds)
        return self.clock_now

    def _make_runner(
        self,
        *,
        valve=None,
        starting_equity_usd: Decimal = OPTION_B_DEFAULT_STARTING_EQUITY_USD,
        db_name: str = "option_b_demo.sqlite3",
    ) -> OptionBPaperDemoRunner:
        return OptionBPaperDemoRunner(
            db_path=self.tmp_dir / db_name,
            valve_gate=valve if valve is not None else ForexMetaValveGate(),
            starting_equity_usd=starting_equity_usd,
            clock=self._clock,
        )

    def test_01_live_mode_and_constitutional_ceilings_are_hard_rejected(self) -> None:
        with self.assertRaises(TradovateLiveLockError):
            OptionBPaperDemoRunner(
                db_path=self.tmp_dir / "bad_live.sqlite3",
                valve_gate=_StubValveGate(),
                mode="LIVE",
                clock=self._clock,
            )
        with self.assertRaises(ContractError):
            OptionBPaperDemoRunner(
                db_path=self.tmp_dir / "bad_risk.sqlite3",
                valve_gate=_StubValveGate(),
                max_stop_loss_risk_pct=Decimal("1.01"),
                clock=self._clock,
            )
        with self.assertRaises(ContractError):
            OptionBPaperDemoRunner(
                db_path=self.tmp_dir / "bad_dd.sqlite3",
                valve_gate=_StubValveGate(),
                max_drawdown_pct=Decimal("0.1001"),
                clock=self._clock,
            )

    def test_02_initial_5k_snapshot_and_zero_write_invariance(self) -> None:
        runner = self._make_runner(valve=_StubValveGate())
        conn = sqlite3.connect(str(runner.db_path))
        try:
            v_before = conn.execute("PRAGMA data_version").fetchone()[0]
        finally:
            conn.close()

        snap = runner.snapshot()
        self.assertEqual(snap["schema"], OPTION_B_DEMO_SCHEMA)
        self.assertEqual(snap["mode"], "DEMO")
        self.assertEqual(snap["status"], "PAPER_DEMO_ACTIVE")
        self.assertIs(snap["paper_demo_only"], True)
        self.assertEqual(snap["real_money_at_risk_usd"], "0.00")
        self.assertIs(snap["tradovate_signup_required"], False)
        self.assertEqual(snap["starting_equity_usd"], "5000.00")
        self.assertEqual(snap["equity_usd"], "5000.00")
        self.assertEqual(snap["house_money_target_usd"], "10000.00")
        self.assertEqual(len(snap["supported_contracts"]), 4)
        roots = [c["root_symbol"] for c in snap["supported_contracts"]]
        self.assertEqual(set(roots), {"MNQ", "MYM", "MES", "MGC"})
        self.assertIs(snap["audit_chain_valid"], True)

        conn2 = sqlite3.connect(str(runner.db_path))
        try:
            v_after = conn2.execute("PRAGMA data_version").fetchone()[0]
        finally:
            conn2.close()
        self.assertEqual(v_before, v_after)

    def test_03_live_quote_ingestion_mirrors_entry_and_oco_take_profit_updates_50pct_vault(self) -> None:
        valve = _StubValveGate(allowed=True)
        runner = self._make_runner(valve=valve)

        # Non-futures FX quote is safely ignored
        self.assertEqual(runner.ingest_spot_quote("EURUSD", Decimal("1.09700"), Decimal("1.09704")), ())

        # Feed live NAS100 quote -> maps to MNQ ($2/pt)
        runner.ingest_spot_quote("NAS100", Decimal("25000.00"), Decimal("25001.00"))
        self._advance(1)
        res = runner.mirror_entry_signal(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("20.00"),
            take_profit_points=Decimal("60.00"),
            risk_pct=Decimal("0.85"),
        )
        self.assertTrue(res["executed"], res)
        self.assertEqual(res["root_symbol"], "MNQ")
        self.assertEqual(res["contracts"], 1)
        self.assertGreaterEqual(valve.calls, 1)

        snap_open = runner.snapshot()
        self.assertEqual(len(snap_open["open_positions"]), 1)

        # Price rallies past TP (+60 pts -> +$120 gross on 1 MNQ) -> OCO TP fills!
        self._advance(5)
        closed = runner.ingest_spot_quote("NAS100", Decimal("25065.00"), Decimal("25066.00"))
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0].status, "TAKE_PROFIT_FILLED")

        snap_after = runner.snapshot()
        self.assertEqual(snap_after["closed_trades"], 1)
        self.assertEqual(snap_after["win_count"], 1)
        self.assertEqual(snap_after["loss_count"], 0)
        self.assertEqual(snap_after["win_rate_pct"], "100.00")
        self.assertGreater(Decimal(snap_after["balance_usd"]), Decimal("5000.00"))
        self.assertGreater(Decimal(snap_after["vault_50pct_reserved_usd"]), Decimal("0.00"))
        self.assertEqual(
            Decimal(snap_after["vault_50pct_reserved_usd"]) + Decimal(snap_after["retained_compounding_usd"]),
            Decimal(snap_after["balance_usd"]) - Decimal("5000.00"),
        )

    def test_04_valve_veto_blocks_paper_entry_cleanly(self) -> None:
        valve = _StubValveGate(allowed=False)
        runner = self._make_runner(valve=valve)
        runner.ingest_spot_quote("US30", Decimal("48000.00"), Decimal("48002.00"))
        self._advance(1)
        res = runner.mirror_entry_signal(
            symbol="US30",
            side="BUY",
            stop_distance_points=Decimal("40.00"),
            take_profit_points=Decimal("100.00"),
            risk_pct=Decimal("0.85"),
        )
        self.assertFalse(res["executed"])
        self.assertIn("Valve", res["status"])
        self.assertEqual(len(runner.snapshot()["open_positions"]), 0)

    def test_05_restart_durability_preserves_balance_wins_and_closed_trades(self) -> None:
        valve = _StubValveGate(allowed=True)
        runner1 = self._make_runner(valve=valve, db_name="durable.sqlite3")
        runner1.ingest_spot_quote("XAUUSD", Decimal("3550.00"), Decimal("3550.40"))
        self._advance(1)
        entry = runner1.mirror_entry_signal(
            symbol="XAUUSD",
            side="BUY",
            stop_distance_points=Decimal("4.00"),
            take_profit_points=Decimal("12.00"),
            risk_pct=Decimal("0.85"),
        )
        self.assertTrue(entry["executed"], entry)
        self._advance(4)
        runner1.ingest_spot_quote("XAUUSD", Decimal("3565.00"), Decimal("3565.40"))
        snap1 = runner1.snapshot()
        self.assertEqual(snap1["win_count"], 1)

        # Brand new runner instance pointing at same SQLite DB simulates cockpit restart
        self._advance(10)
        runner2 = self._make_runner(valve=valve, db_name="durable.sqlite3")
        snap2 = runner2.snapshot()
        self.assertEqual(snap2["starting_equity_usd"], "5000.00")
        self.assertEqual(snap2["balance_usd"], snap1["balance_usd"])
        self.assertEqual(snap2["equity_usd"], snap1["equity_usd"])
        self.assertEqual(snap2["win_count"], 1)
        self.assertEqual(snap2["closed_trades"], 1)
        self.assertEqual(len(snap2["recent_closed_trades"]), 1)
        self.assertEqual(snap2["vault_50pct_reserved_usd"], snap1["vault_50pct_reserved_usd"])

    def test_06_house_money_milestone_and_schema_contract_fields(self) -> None:
        runner = self._make_runner(valve=_StubValveGate(allowed=True))
        snap = runner.snapshot()
        schema_path = Path(__file__).resolve().parents[2] / "docs/contracts/option-b-demo.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        for req_key in schema["required"]:
            self.assertIn(req_key, snap, f"Missing required schema key: {req_key}")
        self.assertEqual(set(snap.keys()), set(schema["properties"].keys()))


    def test_07_oco_stop_loss_loss_accounting_and_max_open_positions_guard(self) -> None:
        valve = _StubValveGate(allowed=True)
        runner = self._make_runner(valve=valve, db_name="sl_test.sqlite3")
        runner.ingest_spot_quote("NAS100", Decimal("25000.00"), Decimal("25001.00"))
        self._advance(1)
        r1 = runner.mirror_entry_signal(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("20.00"),
            take_profit_points=Decimal("60.00"),
            risk_pct=Decimal("0.85"),
            max_open_positions=1,
        )
        self.assertTrue(r1["executed"], r1)
        # Second entry blocked by max_open_positions=1
        self._advance(1)
        r2 = runner.mirror_entry_signal(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("20.00"),
            take_profit_points=Decimal("60.00"),
            risk_pct=Decimal("0.85"),
            max_open_positions=1,
        )
        self.assertFalse(r2["executed"])
        self.assertEqual(r2["status"], "MAX_OPEN_POSITIONS")

        # Price drops through SL (-20 pts -> -$40 gross + commission)
        self._advance(5)
        closed = runner.ingest_spot_quote("NAS100", Decimal("24970.00"), Decimal("24971.00"))
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0].status, "STOP_LOSS_FILLED")
        snap = runner.snapshot()
        self.assertEqual(snap["loss_count"], 1)
        self.assertEqual(snap["win_count"], 0)
        self.assertLess(Decimal(snap["balance_usd"]), Decimal("5000.00"))
        self.assertEqual(snap["vault_50pct_reserved_usd"], "0.00")

    def test_08_full_jsonschema_validation_across_initial_open_and_closed_states(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed locally")
        schema_path = Path(__file__).resolve().parents[2] / "docs/contracts/option-b-demo.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)

        runner = self._make_runner(valve=_StubValveGate(allowed=True), db_name="schema_full.sqlite3")
        self.assertEqual(list(validator.iter_errors(runner.snapshot())), [])

        runner.ingest_spot_quote("SPX500", Decimal("6900.00"), Decimal("6900.50"))
        self._advance(1)
        res = runner.mirror_entry_signal(
            symbol="SPX500",
            side="BUY",
            stop_distance_points=Decimal("8.00"),
            take_profit_points=Decimal("20.00"),
            risk_pct=Decimal("0.85"),
        )
        self.assertTrue(res["executed"], res)
        self.assertEqual(list(validator.iter_errors(runner.snapshot())), [])

        self._advance(5)
        runner.ingest_spot_quote("SPX500", Decimal("6925.00"), Decimal("6925.50"))
        self.assertEqual(list(validator.iter_errors(runner.snapshot())), [])


if __name__ == "__main__":
    unittest.main()
