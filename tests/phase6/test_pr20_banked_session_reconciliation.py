"""PR #20 verification tests:
1. Pre-PR19 session profit gap reconciliation in ProfitSweepVault:
   1332.15 in vault + 4640.06 in daily_quota -> reconciles exact 3307.91 gap ->
   total_realized_profit_usd == "4640.06", bank_sweep_reserved_usd == "2320.03",
   retained_trading_usd == "2320.03", strict no-op on repeat calls, and exact
   incremental sweep on further session profit growth.
2. AutonomousAiTrader.status_snapshot()["banked_session"] wire contract, automatic
   session vault reconciliation, and assert_safe_ai_catalog_payload compliance.
3. Exact next_session_opens_utc computation across 17:00 America/New_York rollover.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
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
T_SESSION_20 = datetime(2026, 11, 20, 1, 15, 0, tzinfo=timezone.utc)  # 20:15 NY Nov 19 -> session 2026-11-20


class Pr20BankedSessionReconciliationTests(unittest.TestCase):
    def test_pre_pr19_gap_reconciliation_idempotency_and_incremental_growth(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=lambda: T_SESSION_20)
            sdate = session_date_for(T_SESSION_20)
            self.assertEqual(sdate, "2026-11-20")

            # Seed pre-existing post-PR19 partial trade ($1,332.15)
            vault.record_realized_close(
                trade_id="post-pr19-win-1",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("1332.15"),
                occurred_at=T_SESSION_20,
            )
            pre = vault.snapshot()
            self.assertEqual(pre["total_realized_profit_usd"], "1332.15")

            # Reconcile against $4,640.06 session net P&L -> sweeps exact $3,307.91 gap
            rec1 = vault.reconcile_session_realized_profit(
                session_date=sdate,
                session_realized_net_usd=Decimal("4640.06"),
                occurred_at="2026-11-20T01:16:00Z",
            )
            self.assertIsNotNone(rec1)
            if rec1 is not None:
                self.assertEqual(rec1["total_realized_profit_usd"], "4640.06")
                self.assertEqual(rec1["bank_sweep_reserved_usd"], "2320.03")
                self.assertEqual(rec1["retained_trading_usd"], "2320.03")
                sync_rows = [
                    r for r in rec1["recent_sweeps"] if r["trade_id"] == "SESSION_SYNC_2026-11-20_464006"
                ]
                self.assertEqual(len(sync_rows), 1)
                self.assertEqual(sync_rows[0]["realized_net_usd"], "3307.91")
                self.assertEqual(sync_rows[0]["symbol"], "SESSION_BASKET")
                self.assertEqual(sync_rows[0]["broker_id"], "DUAL_SHIELD_BARBELL")

            # Calling again with identical $4,640.06 is a strict no-op (returns None)
            rec_dup = vault.reconcile_session_realized_profit(
                session_date=sdate,
                session_realized_net_usd=Decimal("4640.06"),
                occurred_at=T_SESSION_20,
            )
            self.assertIsNone(rec_dup)
            self.assertEqual(vault.snapshot()["total_realized_profit_usd"], "4640.06")

            # Incremental growth to $5,040.06 (+$400.00) sweeps ONLY the $400.00 delta
            rec_inc = vault.reconcile_session_realized_profit(
                session_date=sdate,
                session_realized_net_usd=Decimal("5040.06"),
                occurred_at=T_SESSION_20,
            )
            self.assertIsNotNone(rec_inc)
            if rec_inc is not None:
                self.assertEqual(rec_inc["total_realized_profit_usd"], "5040.06")
                self.assertEqual(rec_inc["bank_sweep_reserved_usd"], "2520.03")
                self.assertEqual(rec_inc["retained_trading_usd"], "2520.03")
            conn_a = sqlite3.connect(str(Path(td) / "vault.sqlite3"))
            try:
                audit_rows = conn_a.execute(
                    "SELECT prev_sha256, entry_sha256 FROM vault_audit ORDER BY seq ASC"
                ).fetchall()
            finally:
                conn_a.close()
            self.assertEqual(len(audit_rows), 3)
            self.assertEqual(audit_rows[0][0], "0" * 64)
            self.assertEqual(audit_rows[1][0], audit_rows[0][1])
            self.assertEqual(audit_rows[2][0], audit_rows[1][1])

    def test_status_snapshot_banked_session_wire_block_and_ny_rollover_utc(self) -> None:
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
                clock=lambda: T_SESSION_20,
            )
            quota = DailyQuotaGovernanceStore(
                path=root / "quota.sqlite3",
                soft_quota_usd=Decimal("2000"),
                hard_quota_usd=Decimal("3000"),
                max_loss_usd=Decimal("5000"),
            )
            quota.observe_day_start(Decimal("279141.70"), now=T_SESSION_20)
            # Simulate 7 wins & 3 losses netting +$4,640.06 with peak +$4,852.73
            for idx in range(6):
                quota.record_realized_trade(
                    Decimal("600.00"), symbol="NAS100", ticket=f"w-{idx}", now=T_SESSION_20
                )
            quota.record_realized_trade(
                Decimal("1252.73"), symbol="NAS100", ticket="w-6", now=T_SESSION_20
            )
            for idx, loss_amt in enumerate((Decimal("-80.00"), Decimal("-60.00"), Decimal("-72.67"))):
                quota.record_realized_trade(
                    loss_amt, symbol="US30", ticket=f"l-{idx}", now=T_SESSION_20
                )

            vault = ProfitSweepVault(root / "vault.sqlite3", clock=lambda: T_SESSION_20)
            vault.record_realized_close(
                trade_id="w-6",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("1332.15"),
                occurred_at=T_SESSION_20,
            )

            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T_SESSION_20,
            )
            snap = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_SESSION_20))
            self.assertEqual(snap["daily_quota"]["status"], QUOTA_STATUS_LOCKED)
            self.assertEqual(snap["bank_sweep_reserved_usd"], "2320.03")

            bs = snap["banked_session"]
            expected_keys = {
                "schema",
                "session_date",
                "banked_net_pnl_usd",
                "realized_pnl_pct",
                "peak_realized_pnl_usd",
                "protected_profit_floor_usd",
                "ratchet_armed",
                "closed_trades",
                "win_count",
                "loss_count",
                "vault_total_realized_usd",
                "vault_swept_50pct_usd",
                "vault_retained_50pct_usd",
                "profits_locked_for_session",
                "operating_mode",
                "session_rollover_label",
                "next_session_opens_utc",
            }
            self.assertEqual(set(bs.keys()), expected_keys)
            self.assertEqual(bs["schema"], "cas-forex.banked-session/1")
            self.assertEqual(bs["session_date"], "2026-11-20")
            self.assertEqual(bs["banked_net_pnl_usd"], "4640.06")
            self.assertEqual(bs["peak_realized_pnl_usd"], "4852.73")
            self.assertTrue(bs["ratchet_armed"])
            self.assertEqual(bs["closed_trades"], 10)
            self.assertEqual(bs["win_count"], 7)
            self.assertEqual(bs["loss_count"], 3)
            self.assertEqual(bs["vault_total_realized_usd"], "4640.06")
            self.assertEqual(bs["vault_swept_50pct_usd"], "2320.03")
            self.assertEqual(bs["vault_retained_50pct_usd"], "2320.03")
            self.assertTrue(bs["profits_locked_for_session"])
            self.assertEqual(bs["operating_mode"], FOCUS_MODE_RESEARCH_RESPITE)
            self.assertEqual(bs["session_rollover_label"], "17:00 America/New_York (14:00 Pacific)")
            # At 2026-11-20T01:15:00Z (20:15 EST Nov 19), next 17:00 NY is 2026-11-20 17:00 EST = 2026-11-20T22:00:00Z
            self.assertEqual(bs["next_session_opens_utc"], "2026-11-20T22:00:00Z")

            # Before 17:00 NY on Nov 20 (e.g. 2026-11-20T18:00:00Z = 13:00 EST), next 17:00 NY is still 2026-11-20T22:00:00Z
            self.assertEqual(
                _next_ny_session_rollover_utc(datetime(2026, 11, 20, 18, 0, 0, tzinfo=timezone.utc)),
                "2026-11-20T22:00:00Z",
            )
            # Exactly at 17:00 NY on Nov 20 (2026-11-20T22:00:00Z), new session opens & next rollover advances to Nov 21
            t_new_sess = datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc)
            snap_new = assert_safe_ai_catalog_payload(trader.status_snapshot(now=t_new_sess))
            self.assertEqual(snap_new["banked_session"]["session_date"], "2026-11-21")
            self.assertEqual(snap_new["banked_session"]["banked_net_pnl_usd"], "0")
            self.assertFalse(snap_new["banked_session"]["profits_locked_for_session"])
            self.assertEqual(snap_new["banked_session"]["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)
            self.assertEqual(snap_new["banked_session"]["next_session_opens_utc"], "2026-11-21T22:00:00Z")


if __name__ == "__main__":
    unittest.main()
