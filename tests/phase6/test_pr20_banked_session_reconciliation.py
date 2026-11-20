"""PR #20 verification tests:
1. Pre-PR19 session profit gap reconciliation & legacy sweep_events ALTER TABLE migration.
2. Multi-day two-session accumulation (Day 1 +$100 + Day 2 +$300 -> $300 session / $400 lifetime, zero cross-day bleed).
3. Append-only downward corrections (+$4,852.73 -> +$4,640.06 -> -$150.00) & oscillation (+$300 -> +$100 -> +$300)
   with unbroken SHA-256 vault_audit hash chain.
4. Strictly read-only status_snapshot() (0 SQLite writes, PRAGMA data_version unchanged) vs explicit
   sync_session_profit_to_vault() write path, honest accounting_basis metadata, and 17:00 NY rollover UTC.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    FOCUS_MODE_RESEARCH_RESPITE,
    OPERATING_MODE_ACTIVE_TRADING,
    AutonomousAiTrader,
    _next_ny_session_rollover_utc,
)
from cas_forex_revamp.contracts import canonical_bytes
from cas_forex_revamp.operator.frontier_backends import (
    FrontierModelRegistry,
    assert_safe_ai_catalog_payload,
)
from cas_forex_revamp.treasury import ProfitSweepVault
from cas_forex_revamp.valve.daily_quota import (
    QUOTA_STATUS_LOCKED,
    DailyQuotaGovernanceStore,
    session_date_for,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import ENV_EXECUTION_MODE, EXECUTION_MODE_DEMO
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
)

GATE = load_default_forex_valve_gate()
T_DAY1 = datetime(2026, 11, 19, 18, 0, 0, tzinfo=timezone.utc)  # 13:00 EST -> session 2026-11-19
T_DAY2 = datetime(2026, 11, 20, 1, 15, 0, tzinfo=timezone.utc)  # 20:15 EST Nov 19 -> session 2026-11-20


def _verify_vault_audit_chain(tc: unittest.TestCase, db_file: Path) -> int:
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT prev_sha256, entry_sha256, scope_id, event_type, payload_json, created_at "
            "FROM vault_audit ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()
    expected_prev = "0" * 64
    for r in rows:
        tc.assertEqual(str(r["prev_sha256"]), expected_prev)
        recomputed = sha256(
            f"{r['prev_sha256']}|{r['scope_id']}|{r['event_type']}|".encode("utf-8")
            + str(r["payload_json"]).encode("utf-8")
            + f"|{r['created_at']}".encode("utf-8")
        ).hexdigest()
        tc.assertEqual(str(r["entry_sha256"]), recomputed)
        expected_prev = recomputed
    return len(rows)


class Pr20BankedSessionReconciliationTests(unittest.TestCase):
    def test_pre_pr19_gap_reconciliation_and_legacy_schema_backfill(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_file = Path(td) / "legacy_vault.sqlite3"
            # Create legacy sweep_events table without session_date column
            conn = sqlite3.connect(str(db_file))
            try:
                conn.execute(
                    """
                    CREATE TABLE sweep_events (
                        trade_id TEXT NOT NULL,
                        scope_id TEXT NOT NULL,
                        symbol TEXT NOT NULL,
                        broker_id TEXT NOT NULL,
                        realized_net_usd_text TEXT NOT NULL,
                        retained_trading_usd_text TEXT NOT NULL,
                        bank_sweep_usd_text TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        PRIMARY KEY (scope_id, trade_id)
                    )
                    """
                )
                conn.execute(
                    "INSERT INTO sweep_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "post-pr19-win-1",
                        "default",
                        "NAS100",
                        BROKER_HUGOSWAY_MT5,
                        "1332.15",
                        "666.07",
                        "666.08",
                        "2026-11-20T01:05:00Z",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            vault = ProfitSweepVault(db_file, clock=lambda: T_DAY2)
            self.assertEqual(vault.session_totals("2026-11-20")["realized_net_usd"], "1332.15")

            rec1 = vault.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("4640.06"),
                occurred_at="2026-11-20T01:16:00Z",
            )
            self.assertIsNotNone(rec1)
            if rec1 is not None:
                self.assertEqual(rec1["total_realized_profit_usd"], "4640.06")
                self.assertEqual(rec1["bank_sweep_reserved_usd"], "2320.03")
                self.assertEqual(rec1["retained_trading_usd"], "2320.03")

            # Repeat call is a strict no-op
            self.assertIsNone(
                vault.reconcile_session_realized_profit(
                    session_date="2026-11-20",
                    session_realized_net_usd=Decimal("4640.06"),
                    occurred_at=T_DAY2,
                )
            )
            self.assertGreaterEqual(_verify_vault_audit_chain(self, db_file), 1)

    def test_two_session_accumulation_zero_cross_day_bleed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_a = Path(td) / "vault_a.sqlite3"
            vault_a = ProfitSweepVault(db_a, clock=lambda: T_DAY1)
            self.assertEqual(session_date_for(T_DAY1), "2026-11-19")
            self.assertEqual(session_date_for(T_DAY2), "2026-11-20")

            # Day 1 (+$100.00 via record_realized_close + reconcile check)
            vault_a.record_realized_close(
                trade_id="d1-t1",
                symbol="EURUSD",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("100.00"),
                occurred_at=T_DAY1,
                session_date="2026-11-19",
            )
            self.assertIsNone(
                vault_a.reconcile_session_realized_profit(
                    session_date="2026-11-19",
                    session_realized_net_usd=Decimal("100.00"),
                    occurred_at=T_DAY1,
                )
            )

            # Day 2 (+$300.00 via reconcile_session_realized_profit) -> MUST NOT subtract Day 1's $100!
            out_d2 = vault_a.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("300.00"),
                occurred_at=T_DAY2,
            )
            self.assertIsNotNone(out_d2)
            s_d1 = vault_a.session_totals("2026-11-19")
            s_d2 = vault_a.session_totals("2026-11-20")
            self.assertEqual(s_d1["realized_net_usd"], "100")
            self.assertEqual(s_d1["bank_sweep_usd"], "50")
            self.assertEqual(s_d2["realized_net_usd"], "300")
            self.assertEqual(s_d2["bank_sweep_usd"], "150")
            self.assertEqual(s_d2["retained_trading_usd"], "150")

            life_a = vault_a.snapshot()
            self.assertEqual(life_a["total_realized_profit_usd"], "400")
            self.assertEqual(life_a["bank_sweep_reserved_usd"], "200")
            self.assertEqual(life_a["retained_trading_usd"], "200")

            # Also verify when Day 1 was reconciled via SESSION_SYNC_ and Day 2 mixes trade + sync
            db_b = Path(td) / "vault_b.sqlite3"
            vault_b = ProfitSweepVault(db_b, clock=lambda: T_DAY1)
            vault_b.reconcile_session_realized_profit(
                session_date="2026-11-19",
                session_realized_net_usd=Decimal("100.00"),
                occurred_at=T_DAY1,
            )
            vault_b.record_realized_close(
                trade_id="d2-part",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("120.00"),
                occurred_at=T_DAY2,
                session_date="2026-11-20",
            )
            vault_b.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("300.00"),
                occurred_at=T_DAY2,
            )
            life_b = vault_b.snapshot()
            self.assertEqual(vault_b.session_totals("2026-11-20")["realized_net_usd"], "300")
            self.assertEqual(vault_b.session_totals("2026-11-20")["bank_sweep_usd"], "150")
            self.assertEqual(life_b["total_realized_profit_usd"], "400")
            self.assertEqual(life_b["bank_sweep_reserved_usd"], "200")
            self.assertEqual(life_b["retained_trading_usd"], "200")

    def test_downward_correction_full_reversal_and_oscillation_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # 1. Peak +$4,852.73 -> -$212.67 pullback to +$4,640.06 -> reversal below $0 (-$150.00)
            db_down = Path(td) / "vault_down.sqlite3"
            vault = ProfitSweepVault(db_down, clock=lambda: T_DAY2)
            r_peak = vault.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("4852.73"),
                occurred_at=T_DAY2,
            )
            self.assertIsNotNone(r_peak)
            if r_peak is not None:
                self.assertEqual(r_peak["total_realized_profit_usd"], "4852.73")
                self.assertEqual(r_peak["bank_sweep_reserved_usd"], "2426.37")
                self.assertEqual(r_peak["retained_trading_usd"], "2426.36")

            r_pullback = vault.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("4640.06"),
                occurred_at=T_DAY2,
            )
            self.assertIsNotNone(r_pullback)
            if r_pullback is not None:
                self.assertEqual(r_pullback["total_realized_profit_usd"], "4640.06")
                self.assertEqual(r_pullback["bank_sweep_reserved_usd"], "2320.03")
                self.assertEqual(r_pullback["retained_trading_usd"], "2320.03")

            r_neg = vault.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("-150.00"),
                occurred_at=T_DAY2,
            )
            self.assertIsNotNone(r_neg)
            if r_neg is not None:
                self.assertEqual(r_neg["total_realized_profit_usd"], "-150")
                self.assertEqual(r_neg["bank_sweep_reserved_usd"], "0")
                self.assertEqual(r_neg["retained_trading_usd"], "-150")
            self.assertEqual(vault.session_totals("2026-11-20")["bank_sweep_usd"], "0")
            self.assertEqual(_verify_vault_audit_chain(self, db_down), 3)

            # 2. Oscillation +$300 -> +$100 -> +$300 with state-exact idempotency
            db_osc = Path(td) / "vault_osc.sqlite3"
            v_osc = ProfitSweepVault(db_osc, clock=lambda: T_DAY2)
            s_300_a = v_osc.reconcile_session_realized_profit(
                session_date="2026-11-20", session_realized_net_usd=Decimal("300.00"), occurred_at=T_DAY2
            )
            self.assertIsNotNone(s_300_a)
            self.assertEqual(v_osc.snapshot()["bank_sweep_reserved_usd"], "150")
            self.assertIsNone(
                v_osc.reconcile_session_realized_profit(
                    session_date="2026-11-20", session_realized_net_usd=Decimal("300.00"), occurred_at=T_DAY2
                )
            )

            s_100 = v_osc.reconcile_session_realized_profit(
                session_date="2026-11-20", session_realized_net_usd=Decimal("100.00"), occurred_at=T_DAY2
            )
            self.assertIsNotNone(s_100)
            self.assertEqual(v_osc.snapshot()["total_realized_profit_usd"], "100")
            self.assertEqual(v_osc.snapshot()["bank_sweep_reserved_usd"], "50")

            s_300_b = v_osc.reconcile_session_realized_profit(
                session_date="2026-11-20", session_realized_net_usd=Decimal("300.00"), occurred_at=T_DAY2
            )
            self.assertIsNotNone(s_300_b)
            self.assertEqual(v_osc.snapshot()["total_realized_profit_usd"], "300")
            self.assertEqual(v_osc.snapshot()["bank_sweep_reserved_usd"], "150")
            self.assertEqual(v_osc.snapshot()["retained_trading_usd"], "150")
            self.assertIsNone(
                v_osc.reconcile_session_realized_profit(
                    session_date="2026-11-20", session_realized_net_usd=Decimal("300.00"), occurred_at=T_DAY2
                )
            )
            self.assertEqual(_verify_vault_audit_chain(self, db_osc), 3)

    def test_status_snapshot_strictly_read_only_and_explicit_sync_write_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            router = DualShieldBrokerRouter(
                environ={ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO},
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("224000"),
                    BROKER_HUGOSWAY_MT5: Decimal("33600"),
                    BROKER_LHFX_MT5: Decimal("22400"),
                },
                clock=lambda: T_DAY2,
            )
            quota_db = root / "quota.sqlite3"
            quota = DailyQuotaGovernanceStore(
                path=quota_db,
                soft_quota_usd=Decimal("2000"),
                hard_quota_usd=Decimal("3000"),
                max_loss_usd=Decimal("5000"),
            )
            quota.observe_day_start(Decimal("280000.00"), now=T_DAY2)
            for idx in range(6):
                quota.record_realized_trade(
                    Decimal("600.00"), symbol="NAS100", ticket=f"w-{idx}", now=T_DAY2
                )
            quota.record_realized_trade(
                Decimal("1252.73"), symbol="NAS100", ticket="w-6", now=T_DAY2
            )
            for idx, loss_amt in enumerate((Decimal("-80.00"), Decimal("-60.00"), Decimal("-72.67"))):
                quota.record_realized_trade(
                    loss_amt, symbol="US30", ticket=f"l-{idx}", now=T_DAY2
                )

            vault_db = root / "vault.sqlite3"
            vault = ProfitSweepVault(vault_db, clock=lambda: T_DAY2)
            vault.record_realized_close(
                trade_id="w-6",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("1332.15"),
                occurred_at=T_DAY2,
                session_date="2026-11-20",
            )

            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T_DAY2,
            )

            obs_conn = sqlite3.connect(str(vault_db))
            try:
                se_before = int(obs_conn.execute("SELECT COUNT(*) FROM sweep_events").fetchone()[0])
                au_before = int(obs_conn.execute("SELECT COUNT(*) FROM vault_audit").fetchone()[0])
                dv_before = int(obs_conn.execute("PRAGMA data_version").fetchone()[0])

                # Repeated status_snapshot() calls MUST perform ZERO SQLite writes!
                for _ in range(3):
                    ro_snap = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_DAY2))

                se_after = int(obs_conn.execute("SELECT COUNT(*) FROM sweep_events").fetchone()[0])
                au_after = int(obs_conn.execute("SELECT COUNT(*) FROM vault_audit").fetchone()[0])
                dv_after = int(obs_conn.execute("PRAGMA data_version").fetchone()[0])
                self.assertEqual(se_after, se_before)
                self.assertEqual(au_after, au_before)
                self.assertEqual(dv_after, dv_before)
                self.assertEqual(ro_snap["banked_session"]["vault_total_realized_usd"], "1332.15")
                self.assertEqual(
                    ro_snap["banked_session"]["accounting_basis"],
                    "INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT",
                )
                self.assertEqual(ro_snap["banked_session"]["confirmed_bank_payouts_usd"], "0")

                # Explicit write method sync_session_profit_to_vault() reconciles cleanly
                sync_res = trader.sync_session_profit_to_vault(now=T_DAY2)
                self.assertIsNotNone(sync_res)
                se_synced = int(obs_conn.execute("SELECT COUNT(*) FROM sweep_events").fetchone()[0])
                au_synced = int(obs_conn.execute("SELECT COUNT(*) FROM vault_audit").fetchone()[0])
                dv_synced = int(obs_conn.execute("PRAGMA data_version").fetchone()[0])
                self.assertEqual(se_synced, se_before + 1)
                self.assertEqual(au_synced, au_before + 1)
                self.assertGreater(dv_synced, dv_before)
            finally:
                obs_conn.close()

            snap = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_DAY2))
            self.assertEqual(snap["daily_quota"]["status"], QUOTA_STATUS_LOCKED)
            self.assertEqual(snap["bank_sweep_reserved_usd"], "2320.03")

            bs = snap["banked_session"]
            self.assertEqual(bs["schema"], "cas-forex.banked-session/1")
            self.assertEqual(bs["accounting_basis"], "INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT")
            self.assertEqual(bs["session_date"], "2026-11-20")
            self.assertEqual(bs["banked_net_pnl_usd"], "4640.06")
            self.assertEqual(bs["peak_realized_pnl_usd"], "4852.73")
            self.assertTrue(bs["ratchet_armed"])
            self.assertEqual(bs["closed_trades"], 10)
            self.assertEqual(bs["win_count"], 7)
            self.assertEqual(bs["loss_count"], 3)
            self.assertEqual(bs["vault_total_realized_usd"], "4640.06")
            self.assertEqual(bs["vault_swept_50pct_usd"], "2320.03")
            self.assertEqual(bs["session_vault_reserved_50pct_usd"], "2320.03")
            self.assertEqual(bs["vault_retained_50pct_usd"], "2320.03")
            self.assertEqual(bs["confirmed_bank_payouts_usd"], "0")
            self.assertTrue(bs["profits_locked_for_session"])
            self.assertEqual(bs["operating_mode"], FOCUS_MODE_RESEARCH_RESPITE)
            self.assertEqual(bs["session_rollover_label"], "17:00 America/New_York (14:00 Pacific)")
            self.assertEqual(bs["next_session_opens_utc"], "2026-11-20T22:00:00Z")

            self.assertEqual(
                _next_ny_session_rollover_utc(datetime(2026, 11, 20, 18, 0, 0, tzinfo=timezone.utc)),
                "2026-11-20T22:00:00Z",
            )
            t_new_sess = datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc)
            snap_new = assert_safe_ai_catalog_payload(trader.status_snapshot(now=t_new_sess))
            self.assertEqual(snap_new["banked_session"]["session_date"], "2026-11-21")
            self.assertEqual(snap_new["banked_session"]["banked_net_pnl_usd"], "0")
            self.assertEqual(snap_new["banked_session"]["session_vault_reserved_50pct_usd"], "0")
            self.assertEqual(snap_new["banked_session"]["vault_swept_50pct_usd"], "2320.03")
            self.assertFalse(snap_new["banked_session"]["profits_locked_for_session"])
            self.assertEqual(snap_new["banked_session"]["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)
            self.assertEqual(snap_new["banked_session"]["next_session_opens_utc"], "2026-11-21T22:00:00Z")


if __name__ == "__main__":
    unittest.main()
