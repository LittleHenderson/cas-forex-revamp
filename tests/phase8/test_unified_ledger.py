"""Phase 8 tests for Item 1: UnifiedRealTimeLedger (SQLite WAL, Clear Street style)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.ledger import (
    DEFAULT_PRINCIPAL_USD,
    INTERNAL_ACCOUNTING_LABEL,
    DailySessionStatus,
    DisbursementStatus,
    LedgerMode,
    RegionalSession,
    UnifiedRealTimeLedger,
    regional_session_for,
    trading_date_for,
)

T_DAY1_ASIA = datetime(2026, 11, 19, 2, 30, 0, tzinfo=timezone.utc)
T_DAY1_LONDON = datetime(2026, 11, 19, 9, 15, 0, tzinfo=timezone.utc)
T_DAY1_NY = datetime(2026, 11, 19, 15, 45, 0, tzinfo=timezone.utc)
T_DAY1_LATE = datetime(2026, 11, 19, 23, 55, 0, tzinfo=timezone.utc)
T_DAY2_EARLY = datetime(2026, 11, 20, 0, 5, 0, tzinfo=timezone.utc)
T_DAY2_NY = datetime(2026, 11, 20, 14, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _DummyExecEvent:
    event_id: str
    symbol: str
    broker_id: str
    realized_pnl_usd: Decimal
    timestamp_utc: str


def _table_row_counts(db_path: Path) -> dict[str, int]:
    conn = sqlite3.connect(str(db_path))
    try:
        return {
            "ledger_meta": int(conn.execute("SELECT COUNT(*) FROM ledger_meta").fetchone()[0]),
            "realized_trades": int(conn.execute("SELECT COUNT(*) FROM realized_trades").fetchone()[0]),
            "disbursements": int(conn.execute("SELECT COUNT(*) FROM disbursements").fetchone()[0]),
            "daily_sessions": int(conn.execute("SELECT COUNT(*) FROM daily_sessions").fetchone()[0]),
            "audit_events": int(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]),
        }
    finally:
        conn.close()


class UnifiedRealTimeLedgerTests(unittest.TestCase):
    def test_multi_session_isolation_and_lifetime_sum(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "ledger.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=DEFAULT_PRINCIPAL_USD,
                initial_equity_usd=DEFAULT_PRINCIPAL_USD,
                clock=lambda: T_DAY1_NY,
            )

            s1 = ledger.record_realized_trade(
                trade_id="t-day1-1",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("100.00"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s1.session_date, "2026-11-19")
            self.assertEqual(s1.daily_realized_pnl_usd, Decimal("100.00"))
            self.assertEqual(s1.lifetime_realized_pnl_usd, Decimal("100.00"))
            self.assertEqual(s1.settled_equity_usd, Decimal("300100.00"))
            self.assertEqual(s1.bank_vault_reserved_usd, Decimal("50.00"))
            self.assertEqual(s1.accounting_label, INTERNAL_ACCOUNTING_LABEL)

            s2 = ledger.record_realized_trade(
                trade_id="t-day2-1",
                symbol="US30",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("300.00"),
                occurred_at=T_DAY2_NY,
            )
            self.assertEqual(s2.session_date, "2026-11-20")
            self.assertEqual(s2.daily_realized_pnl_usd, Decimal("300.00"))
            self.assertEqual(s2.lifetime_realized_pnl_usd, Decimal("400.00"))
            self.assertEqual(s2.settled_equity_usd, Decimal("300400.00"))
            self.assertEqual(s2.net_surplus_above_principal_usd, Decimal("400.00"))
            self.assertEqual(s2.bank_vault_reserved_usd, Decimal("200.00"))

            # Day 1 remains strictly isolated at $100.00 while lifetime is $400.00
            day1_snap = ledger.snapshot(now_utc=T_DAY1_NY)
            self.assertEqual(day1_snap.daily_realized_pnl_usd, Decimal("100.00"))
            self.assertEqual(day1_snap.lifetime_realized_pnl_usd, Decimal("400.00"))
            self.assertEqual(
                ledger.session_summary("2026-11-19")["realized_pnl_usd"], Decimal("100.00")
            )
            self.assertEqual(
                ledger.session_summary("2026-11-20")["realized_pnl_usd"], Decimal("300.00")
            )
            self.assertTrue(ledger.verify_audit_chain())

    def test_regional_session_classification_and_pnl_breakdown(self) -> None:
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 21, 59, 59, tzinfo=timezone.utc)),
            RegionalSession.NEW_YORK,
        )
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 22, 0, 0, tzinfo=timezone.utc)),
            RegionalSession.ASIA,
        )
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 0, 0, 0, tzinfo=timezone.utc)),
            RegionalSession.ASIA,
        )
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 6, 59, 59, tzinfo=timezone.utc)),
            RegionalSession.ASIA,
        )
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 7, 0, 0, tzinfo=timezone.utc)),
            RegionalSession.LONDON,
        )
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 11, 59, 59, tzinfo=timezone.utc)),
            RegionalSession.LONDON,
        )
        self.assertEqual(
            regional_session_for(datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)),
            RegionalSession.NEW_YORK,
        )

        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "regional.sqlite3"
            ledger = UnifiedRealTimeLedger(db, clock=lambda: T_DAY1_ASIA)

            ledger.record_realized_trade(
                trade_id="t-asia",
                symbol="USD_JPY",
                broker_id="lhfx-mt5",
                realized_pnl_usd=Decimal("120.50"),
                occurred_at=T_DAY1_ASIA,
            )
            ledger.record_realized_trade(
                trade_id="t-london",
                symbol="EUR_USD",
                broker_id="lhfx-mt5",
                realized_pnl_usd=Decimal("-40.25"),
                occurred_at=T_DAY1_LONDON,
            )
            ledger.record_realized_trade(
                trade_id="t-ny",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("219.75"),
                occurred_at=T_DAY1_NY,
            )
            ledger.record_realized_trade(
                trade_id="t-day2-asia",
                symbol="USD_JPY",
                broker_id="lhfx-mt5",
                realized_pnl_usd=Decimal("80.00"),
                occurred_at=T_DAY2_EARLY,
            )

            day1 = ledger.snapshot(now_utc=T_DAY1_NY)
            self.assertEqual(day1.daily_asia_pnl_usd, Decimal("120.50"))
            self.assertEqual(day1.daily_london_pnl_usd, Decimal("-40.25"))
            self.assertEqual(day1.daily_new_york_pnl_usd, Decimal("219.75"))
            self.assertEqual(day1.daily_realized_pnl_usd, Decimal("300.00"))
            self.assertEqual(day1.lifetime_asia_pnl_usd, Decimal("200.50"))
            self.assertEqual(day1.lifetime_london_pnl_usd, Decimal("-40.25"))
            self.assertEqual(day1.lifetime_new_york_pnl_usd, Decimal("219.75"))
            self.assertEqual(day1.lifetime_realized_pnl_usd, Decimal("380.00"))
            self.assertEqual(day1.daily_regional_pnl()[RegionalSession.LONDON], Decimal("-40.25"))
            self.assertEqual(day1.lifetime_regional_pnl()[RegionalSession.ASIA], Decimal("200.50"))

    def test_downward_adjustment_and_bounce_back_no_double_count_no_negative_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "bounce.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("300000.00"),
                clock=lambda: T_DAY1_NY,
            )

            s_300 = ledger.reconcile_session_realized_pnl(
                session_date="2026-11-19",
                target_session_realized_pnl_usd=Decimal("300.00"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s_300.daily_realized_pnl_usd, Decimal("300.00"))
            self.assertEqual(s_300.lifetime_realized_pnl_usd, Decimal("300.00"))
            self.assertEqual(s_300.bank_vault_reserved_usd, Decimal("150.00"))

            # Downward adjustment: $300 -> $100
            s_100 = ledger.reconcile_session_realized_pnl(
                session_date="2026-11-19",
                target_session_realized_pnl_usd=Decimal("100.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=5),
            )
            self.assertEqual(s_100.daily_realized_pnl_usd, Decimal("100.00"))
            self.assertEqual(s_100.lifetime_realized_pnl_usd, Decimal("100.00"))
            self.assertEqual(s_100.bank_vault_reserved_usd, Decimal("50.00"))
            audit_before_noop = s_100.audit_event_count

            # Idempotent repeat at $100 does not write duplicate adjustment
            s_100_again = ledger.reconcile_session_realized_pnl(
                session_date="2026-11-19",
                target_session_realized_pnl_usd=Decimal("100.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=6),
            )
            self.assertEqual(s_100_again.audit_event_count, audit_before_noop)
            self.assertEqual(s_100_again.bank_vault_reserved_usd, Decimal("50.00"))

            # Dip underwater to -$150.00 -> reserve clamps at $0.00, never negative
            s_neg = ledger.reconcile_session_realized_pnl(
                session_date="2026-11-19",
                target_session_realized_pnl_usd=Decimal("-150.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertEqual(s_neg.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(s_neg.settled_equity_usd, Decimal("299850.00"))
            self.assertEqual(s_neg.bank_vault_reserved_usd, Decimal("0.00"))
            self.assertEqual(s_neg.vault_sweep_target_usd, Decimal("0.00"))

            # Bounce back to $300.00 -> exact $300.00 net, $150.00 reserve, zero double-count
            s_back = ledger.reconcile_session_realized_pnl(
                session_date="2026-11-19",
                target_session_realized_pnl_usd=Decimal("300.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=15),
            )
            self.assertEqual(s_back.mode, LedgerMode.IN_SURPLUS)
            self.assertEqual(s_back.daily_realized_pnl_usd, Decimal("300.00"))
            self.assertEqual(s_back.lifetime_realized_pnl_usd, Decimal("300.00"))
            self.assertEqual(s_back.settled_equity_usd, Decimal("300300.00"))
            self.assertEqual(s_back.bank_vault_reserved_usd, Decimal("150.00"))
            self.assertTrue(ledger.verify_audit_chain())

    def test_principal_hwm_recovery_zero_reserve_and_50pct_surplus_above_principal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "hwm.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("295000.00"),
                clock=lambda: T_DAY1_NY,
            )

            s0 = ledger.snapshot(now_utc=T_DAY1_NY)
            self.assertEqual(s0.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(s0.principal_shortfall_usd, Decimal("5000.00"))
            self.assertEqual(s0.net_surplus_above_principal_usd, Decimal("0.00"))
            self.assertEqual(s0.bank_vault_reserved_usd, Decimal("0.00"))

            # Profit +$3,000 -> still underwater at $298,000 -> reserve MUST stay $0.00
            s1 = ledger.record_realized_trade(
                trade_id="rec-1",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("3000.00"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s1.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(s1.settled_equity_usd, Decimal("298000.00"))
            self.assertEqual(s1.principal_shortfall_usd, Decimal("2000.00"))
            self.assertEqual(s1.vault_sweep_target_usd, Decimal("0.00"))
            self.assertEqual(s1.bank_vault_reserved_usd, Decimal("0.00"))

            # Profit +$4,000 -> total realized +$7,000, settled equity $302,000 -> ONLY $2,000 surplus above principal!
            s2 = ledger.record_realized_trade(
                trade_id="rec-2",
                symbol="US30",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("4000.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertEqual(s2.mode, LedgerMode.IN_SURPLUS)
            self.assertEqual(s2.settled_equity_usd, Decimal("302000.00"))
            self.assertEqual(s2.principal_shortfall_usd, Decimal("0.00"))
            self.assertEqual(s2.net_surplus_above_principal_usd, Decimal("2000.00"))
            self.assertEqual(s2.vault_sweep_target_usd, Decimal("1000.00"))
            self.assertEqual(s2.bank_vault_reserved_usd, Decimal("1000.00"))
            self.assertEqual(s2.retained_trading_surplus_usd, Decimal("1000.00"))
            self.assertEqual(s2.deployable_trading_equity_usd, Decimal("301000.00"))
            self.assertEqual(s2.accounting_label, INTERNAL_ACCOUNTING_LABEL)

    def test_pending_and_non_settled_disbursements_never_inflate_equity_or_exit_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "disb.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("295000.00"),
                clock=lambda: T_DAY1_NY,
            )

            for tid, st, amt in [
                ("tx-pending", DisbursementStatus.PENDING, Decimal("3000.00")),
                ("tx-submitted", DisbursementStatus.SUBMITTED, Decimal("3000.00")),
                ("tx-unknown", DisbursementStatus.UNKNOWN, Decimal("2000.00")),
                ("tx-failed", DisbursementStatus.FAILED, Decimal("4000.00")),
                ("tx-cancelled", DisbursementStatus.CANCELLED, Decimal("4000.00")),
            ]:
                ledger.record_disbursement(
                    transfer_id=tid,
                    amount_usd=amt,
                    status=st,
                    rail="COINBASE_ACH",
                    occurred_at=T_DAY1_NY,
                )

            snap = ledger.snapshot(now_utc=T_DAY1_NY)
            self.assertEqual(snap.confirmed_settled_disbursed_usd, Decimal("0.00"))
            self.assertEqual(snap.pending_transfers_usd, Decimal("8000.00"))
            self.assertEqual(snap.failed_cancelled_transfers_usd, Decimal("8000.00"))
            self.assertEqual(snap.settled_equity_usd, Decimal("295000.00"))
            self.assertEqual(snap.effective_equity_usd, Decimal("295000.00"))
            self.assertEqual(snap.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(snap.bank_vault_reserved_usd, Decimal("0.00"))

            # Settling only $3,000 brings settled equity to $298,000 -> STILL RECOVERY_MODE
            snap_partial = ledger.update_disbursement_status(
                transfer_id="tx-pending",
                status=DisbursementStatus.SETTLED,
                provider_tx_id="cb-tx-001",
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertEqual(snap_partial.confirmed_settled_disbursed_usd, Decimal("3000.00"))
            self.assertEqual(snap_partial.pending_transfers_usd, Decimal("5000.00"))
            self.assertEqual(snap_partial.settled_equity_usd, Decimal("298000.00"))
            self.assertEqual(snap_partial.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(snap_partial.bank_vault_reserved_usd, Decimal("0.00"))

            # Settling second $3,000 brings settled equity to $301,000 -> NOW IN_SURPLUS
            snap_settled = ledger.update_disbursement_status(
                transfer_id="tx-submitted",
                status=DisbursementStatus.SETTLED,
                provider_tx_id="cb-tx-002",
                occurred_at=T_DAY1_NY + timedelta(minutes=20),
            )
            self.assertEqual(snap_settled.confirmed_settled_disbursed_usd, Decimal("6000.00"))
            self.assertEqual(snap_settled.pending_transfers_usd, Decimal("2000.00"))
            self.assertEqual(snap_settled.settled_equity_usd, Decimal("301000.00"))
            self.assertEqual(snap_settled.mode, LedgerMode.IN_SURPLUS)
            self.assertEqual(snap_settled.net_surplus_above_principal_usd, Decimal("1000.00"))
            self.assertEqual(snap_settled.vault_sweep_target_usd, Decimal("500.00"))
            # $6,000 already settled exceeds $500 target, so remaining un-disbursed reserve is $0.00
            self.assertEqual(snap_settled.bank_vault_reserved_usd, Decimal("0.00"))

            # Cannot revert a terminal SETTLED disbursement
            with self.assertRaises(ContractError):
                ledger.update_disbursement_status(
                    transfer_id="tx-pending",
                    status=DisbursementStatus.FAILED,
                )
            self.assertTrue(ledger.verify_audit_chain())

    def test_disbursement_debit_broker_equity_lifecycle_and_failed_refund(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "debit_disb.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("300000.00"),
                clock=lambda: T_DAY1_NY,
            )
            ledger.record_realized_trade(
                trade_id="win-10k",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("10000.00"),
                occurred_at=T_DAY1_NY,
            )
            # Initiate $5,000 withdrawal debited from broker
            s_pend = ledger.record_disbursement(
                transfer_id="wd-1",
                amount_usd=Decimal("5000.00"),
                status=DisbursementStatus.PENDING,
                debit_broker_equity=True,
                occurred_at=T_DAY1_NY + timedelta(minutes=5),
            )
            self.assertEqual(s_pend.broker_equity_usd, Decimal("305000.00"))
            self.assertEqual(s_pend.confirmed_settled_disbursed_usd, Decimal("0.00"))
            self.assertEqual(s_pend.pending_transfers_usd, Decimal("5000.00"))
            self.assertEqual(s_pend.settled_equity_usd, Decimal("305000.00"))

            # Settle $5,000 -> total settled wealth restored to $310,000, remaining vault reserve $0.00
            s_set = ledger.update_disbursement_status(
                transfer_id="wd-1",
                status=DisbursementStatus.SETTLED,
                provider_tx_id="bank-wire-1",
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertEqual(s_set.broker_equity_usd, Decimal("305000.00"))
            self.assertEqual(s_set.confirmed_settled_disbursed_usd, Decimal("5000.00"))
            self.assertEqual(s_set.settled_equity_usd, Decimal("310000.00"))
            self.assertEqual(s_set.vault_sweep_target_usd, Decimal("5000.00"))
            self.assertEqual(s_set.bank_vault_reserved_usd, Decimal("0.00"))

            # Failed debited withdrawal refunds broker cash
            ledger.record_disbursement(
                transfer_id="wd-fail",
                amount_usd=Decimal("2000.00"),
                status=DisbursementStatus.PENDING,
                debit_broker_equity=True,
                occurred_at=T_DAY1_NY + timedelta(minutes=15),
            )
            s_fail = ledger.update_disbursement_status(
                transfer_id="wd-fail",
                status=DisbursementStatus.FAILED,
                occurred_at=T_DAY1_NY + timedelta(minutes=20),
            )
            self.assertEqual(s_fail.broker_equity_usd, Decimal("305000.00"))
            self.assertEqual(s_fail.failed_cancelled_transfers_usd, Decimal("2000.00"))
            self.assertEqual(s_fail.settled_equity_usd, Decimal("310000.00"))

    def test_peak_equity_drawdown_and_70pct_profit_floor_research_respite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "respite.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("300000.00"),
                profit_floor_activation_usd=Decimal("250.00"),
                profit_floor_ratio=Decimal("0.70"),
                clock=lambda: T_DAY1_NY,
            )

            s1 = ledger.record_realized_trade(
                trade_id="pf-1",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("1000.00"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s1.peak_equity_usd, Decimal("301000.00"))
            self.assertEqual(s1.drawdown_usd, Decimal("0.00"))
            self.assertEqual(s1.daily_peak_pnl_usd, Decimal("1000.00"))
            self.assertTrue(s1.daily_profit_floor_armed)
            self.assertEqual(s1.daily_profit_floor_usd, Decimal("700.00"))
            self.assertFalse(s1.research_respite_active)
            self.assertEqual(s1.session_status, DailySessionStatus.ACTIVE_TRADING)
            self.assertTrue(s1.new_risk_allowed)

            # Give back $200 -> daily P&L $800 > $700 floor -> still active
            s2 = ledger.record_realized_trade(
                trade_id="pf-2",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("-200.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=5),
            )
            self.assertFalse(s2.research_respite_active)
            self.assertEqual(s2.drawdown_usd, Decimal("200.00"))

            # Give back $150 -> daily P&L $650 <= $700 floor -> RESEARCH_RESPITE
            s3 = ledger.record_realized_trade(
                trade_id="pf-3",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("-150.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertTrue(s3.research_respite_active)
            self.assertEqual(s3.session_status, DailySessionStatus.RESEARCH_RESPITE)
            self.assertFalse(s3.new_risk_allowed)
            self.assertEqual(s3.peak_equity_usd, Decimal("301000.00"))
            self.assertEqual(s3.drawdown_usd, Decimal("350.00"))
            self.assertEqual(s3.drawdown_pct, Decimal("0.12"))

            # Next day rollover clears daily respite while preserving peak equity & drawdown
            s_next = ledger.snapshot(now_utc=T_DAY2_EARLY)
            self.assertFalse(s_next.research_respite_active)
            self.assertEqual(s_next.session_status, DailySessionStatus.ACTIVE_TRADING)
            self.assertTrue(s_next.new_risk_allowed)
            self.assertEqual(s_next.peak_equity_usd, Decimal("301000.00"))
            self.assertEqual(s_next.drawdown_usd, Decimal("350.00"))

    def test_bidirectional_same_day_loss_lock_carryover_surplus_to_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "carry_s2r.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("300600.00"),
                daily_max_loss_usd=Decimal("500.00"),
                clock=lambda: T_DAY1_NY,
            )

            # Trigger loss lock while IN_SURPLUS ($300,600 -> $300,100)
            s1 = ledger.record_realized_trade(
                trade_id="s2r-1",
                symbol="US30",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("-500.00"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s1.mode, LedgerMode.IN_SURPLUS)
            self.assertTrue(s1.daily_loss_locked)
            self.assertEqual(s1.loss_lock_origin_mode, LedgerMode.IN_SURPLUS)
            self.assertFalse(s1.loss_lock_carried_over)
            self.assertEqual(s1.session_status, DailySessionStatus.DAILY_LOSS_LOCKED)
            self.assertFalse(s1.new_risk_allowed)

            # Additional same-day loss pushes equity below $300,000 into RECOVERY_MODE
            s2 = ledger.record_realized_trade(
                trade_id="s2r-2",
                symbol="US30",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("-300.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=5),
            )
            self.assertEqual(s2.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(s2.settled_equity_usd, Decimal("299800.00"))
            self.assertEqual(s2.bank_vault_reserved_usd, Decimal("0.00"))
            self.assertTrue(s2.daily_loss_locked)
            self.assertEqual(s2.loss_lock_origin_mode, LedgerMode.IN_SURPLUS)
            self.assertTrue(s2.loss_lock_carried_over)
            self.assertEqual(s2.session_status, DailySessionStatus.DAILY_LOSS_LOCKED)
            self.assertFalse(s2.new_risk_allowed)

            # Next UTC trading day automatically resets daily lock
            s_day2 = ledger.snapshot(now_utc=T_DAY2_EARLY)
            self.assertEqual(s_day2.mode, LedgerMode.RECOVERY_MODE)
            self.assertFalse(s_day2.daily_loss_locked)
            self.assertTrue(s_day2.new_risk_allowed)

            # Explicit owner unlock clears Day 1 lock and logs audit event
            s_unlocked = ledger.unlock_daily_loss_lock(
                owner_request_id="owner-req-001",
                reason="Reviewed stop-out logs; owner resuming Day 1",
                session_date="2026-11-19",
                now_utc=T_DAY1_NY + timedelta(minutes=30),
            )
            self.assertFalse(s_unlocked.daily_loss_locked)
            self.assertTrue(s_unlocked.new_risk_allowed)
            self.assertTrue(ledger.verify_audit_chain())

    def test_bidirectional_same_day_loss_lock_carryover_recovery_to_surplus(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # Subcase A: trade win crosses back above $300,000.00 on same trading day
            db_a = Path(td) / "carry_r2s_trade.sqlite3"
            ledger_a = UnifiedRealTimeLedger(
                db_a,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("299800.00"),
                daily_max_loss_usd=Decimal("500.00"),
                clock=lambda: T_DAY1_NY,
            )
            s1 = ledger_a.record_realized_trade(
                trade_id="r2s-loss",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("-500.00"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s1.mode, LedgerMode.RECOVERY_MODE)
            self.assertTrue(s1.daily_loss_locked)
            self.assertEqual(s1.loss_lock_origin_mode, LedgerMode.RECOVERY_MODE)

            # Residual winning close pushes settled equity to $300,300.00 (IN_SURPLUS) same day
            s2 = ledger_a.record_realized_trade(
                trade_id="r2s-win",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("1000.00"),
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertEqual(s2.mode, LedgerMode.IN_SURPLUS)
            self.assertEqual(s2.settled_equity_usd, Decimal("300300.00"))
            self.assertTrue(s2.daily_loss_locked)
            self.assertEqual(s2.loss_lock_origin_mode, LedgerMode.RECOVERY_MODE)
            self.assertTrue(s2.loss_lock_carried_over)
            self.assertEqual(s2.session_status, DailySessionStatus.DAILY_LOSS_LOCKED)
            self.assertFalse(s2.new_risk_allowed)

            # Subcase B: consecutive losses lock in RECOVERY_MODE, then SETTLED payout crosses into IN_SURPLUS
            db_b = Path(td) / "carry_r2s_disb.sqlite3"
            ledger_b = UnifiedRealTimeLedger(
                db_b,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("299500.00"),
                daily_max_loss_usd=Decimal("2000.00"),
                max_consecutive_losses=3,
                clock=lambda: T_DAY1_NY,
            )
            for idx in range(3):
                ledger_b.record_realized_trade(
                    trade_id=f"consec-{idx}",
                    symbol="EUR_USD",
                    broker_id="lhfx-mt5",
                    realized_pnl_usd=Decimal("-50.00"),
                    occurred_at=T_DAY1_NY + timedelta(minutes=idx),
                )
            s_locked = ledger_b.snapshot(now_utc=T_DAY1_NY + timedelta(minutes=4))
            self.assertEqual(s_locked.mode, LedgerMode.RECOVERY_MODE)
            self.assertTrue(s_locked.daily_loss_locked)
            self.assertEqual(s_locked.daily_consecutive_losses, 3)

            s_crossed = ledger_b.record_disbursement(
                transfer_id="tx-cross-surplus",
                amount_usd=Decimal("1000.00"),
                status=DisbursementStatus.SETTLED,
                occurred_at=T_DAY1_NY + timedelta(minutes=10),
            )
            self.assertEqual(s_crossed.mode, LedgerMode.IN_SURPLUS)
            self.assertEqual(s_crossed.settled_equity_usd, Decimal("300350.00"))
            self.assertTrue(s_crossed.daily_loss_locked)
            self.assertEqual(s_crossed.loss_lock_origin_mode, LedgerMode.RECOVERY_MODE)
            self.assertTrue(s_crossed.loss_lock_carried_over)
            self.assertFalse(s_crossed.new_risk_allowed)
            self.assertTrue(ledger_b.verify_audit_chain())

    def test_strictly_zero_write_snapshot_across_day_rollover_and_readonly_connection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "zero_write.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("300000.00"),
                clock=lambda: T_DAY1_LATE,
            )
            ledger.record_realized_trade(
                trade_id="zw-1",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("250.00"),
                occurred_at=T_DAY1_LATE,
            )

            observer = sqlite3.connect(str(db))
            try:
                dv_before = observer.execute("PRAGMA data_version").fetchone()[0]
                counts_before = _table_row_counts(db)
                mtime_before = db.stat().st_mtime_ns
                wal_path = Path(f"{db}-wal")
                wal_size_before = wal_path.stat().st_size if wal_path.exists() else -1

                # Cross midnight UTC rollover & distant missing day reads
                snap_day2 = ledger.snapshot(now_utc=T_DAY2_EARLY)
                snap_future = ledger.snapshot(
                    now_utc=datetime(2026, 11, 25, 14, 0, 0, tzinfo=timezone.utc)
                )
                summary_missing = ledger.session_summary("2026-11-25")
                chain_ok = ledger.verify_audit_chain()

                # Separate read_only=True instance succeeds on reads and refuses writes
                ro_ledger = UnifiedRealTimeLedger(db, read_only=True)
                ro_snap = ro_ledger.snapshot(now_utc=T_DAY2_EARLY)
                self.assertEqual(ro_snap.session_date, "2026-11-20")
                self.assertEqual(ro_snap.daily_realized_pnl_usd, Decimal("0.00"))
                self.assertEqual(ro_snap.lifetime_realized_pnl_usd, Decimal("250.00"))
                self.assertTrue(ro_ledger.verify_audit_chain())
                with self.assertRaises(ContractError):
                    ro_ledger.record_realized_trade(
                        trade_id="should-fail",
                        symbol="NAS100",
                        broker_id="hugosway-mt5",
                        realized_pnl_usd=Decimal("10.00"),
                        occurred_at=T_DAY2_EARLY,
                    )

                dv_after = observer.execute("PRAGMA data_version").fetchone()[0]
                counts_after = _table_row_counts(db)
                mtime_after = db.stat().st_mtime_ns
                wal_size_after = wal_path.stat().st_size if wal_path.exists() else -1
            finally:
                observer.close()

            self.assertEqual(dv_before, dv_after)
            self.assertEqual(counts_before, counts_after)
            self.assertEqual(mtime_before, mtime_after)
            self.assertEqual(wal_size_before, wal_size_after)
            self.assertEqual(snap_day2.session_date, "2026-11-20")
            self.assertEqual(snap_day2.daily_realized_pnl_usd, Decimal("0.00"))
            self.assertEqual(snap_day2.lifetime_realized_pnl_usd, Decimal("250.00"))
            self.assertEqual(snap_future.session_date, "2026-11-25")
            self.assertEqual(summary_missing["realized_pnl_usd"], Decimal("0.00"))
            self.assertTrue(chain_ok)

    def test_idempotency_trade_id_event_id_and_execution_event_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "idem.sqlite3"
            ledger = UnifiedRealTimeLedger(db, clock=lambda: T_DAY1_NY)

            s1 = ledger.record_realized_trade(
                trade_id="t-001",
                event_id="ev-001",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("125.50"),
                occurred_at=T_DAY1_NY,
            )
            # Duplicate trade_id with new event_id -> ignored safely
            s2 = ledger.record_realized_trade(
                trade_id="t-001",
                event_id="ev-002",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("125.50"),
                occurred_at=T_DAY1_NY,
            )
            # New trade_id with duplicate event_id -> ignored safely
            s3 = ledger.record_realized_trade(
                trade_id="t-002",
                event_id="ev-001",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("125.50"),
                occurred_at=T_DAY1_NY,
            )
            self.assertEqual(s1.lifetime_realized_pnl_usd, Decimal("125.50"))
            self.assertEqual(s2.lifetime_realized_pnl_usd, Decimal("125.50"))
            self.assertEqual(s3.lifetime_realized_pnl_usd, Decimal("125.50"))
            self.assertEqual(s3.audit_event_count, s1.audit_event_count)
            self.assertEqual(len(ledger.list_trades()), 1)

            # Bridge ExecutionEvent object & idempotent replay (ignores non-realized FILL/AMEND_STOP)
            s_open_noop = ledger.record_execution_event(
                {
                    "event_id": "bus-open-1",
                    "event_type": "FILL",
                    "symbol": "XAUUSD",
                    "broker_id": "lhfx-mt5",
                    "realized_pnl_usd": Decimal("0.00"),
                    "timestamp_utc": "2026-11-19T15:55:00Z",
                }
            )
            self.assertEqual(len(ledger.list_trades()), 1)
            self.assertEqual(s_open_noop.lifetime_realized_pnl_usd, Decimal("125.50"))

            ev = _DummyExecEvent(
                event_id="bus-ev-100",
                symbol="XAUUSD",
                broker_id="lhfx-mt5",
                realized_pnl_usd=Decimal("74.50"),
                timestamp_utc="2026-11-19T16:00:00Z",
            )
            s4 = ledger.record_execution_event(ev)
            s5 = ledger.record_execution_event(ev)
            self.assertEqual(s4.lifetime_realized_pnl_usd, Decimal("200.00"))
            self.assertEqual(s5.lifetime_realized_pnl_usd, Decimal("200.00"))
            self.assertEqual(len(ledger.list_trades()), 2)
            rec = ledger.get_trade("bus-ev-100")
            self.assertIsNotNone(rec)
            self.assertEqual(rec.realized_pnl_usd, Decimal("74.50"))

    def test_sha256_audit_chain_verification_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "audit.sqlite3"
            ledger = UnifiedRealTimeLedger(db, clock=lambda: T_DAY1_NY)
            ledger.record_realized_trade(
                trade_id="aud-1",
                symbol="NAS100",
                broker_id="hugosway-mt5",
                realized_pnl_usd=Decimal("400.00"),
                occurred_at=T_DAY1_NY,
            )
            ledger.record_disbursement(
                transfer_id="aud-tx-1",
                amount_usd=Decimal("100.00"),
                status=DisbursementStatus.PENDING,
                occurred_at=T_DAY1_NY + timedelta(minutes=1),
            )
            ledger.update_disbursement_status(
                transfer_id="aud-tx-1",
                status=DisbursementStatus.SETTLED,
                provider_tx_id="bank-99",
                occurred_at=T_DAY1_NY + timedelta(minutes=2),
            )
            self.assertTrue(ledger.verify_audit_chain())

            # Tamper with payload_json of row 2
            conn = sqlite3.connect(str(db))
            try:
                orig_payload = conn.execute(
                    "SELECT payload_json FROM audit_events WHERE seq = 2"
                ).fetchone()[0]
                conn.execute(
                    "UPDATE audit_events SET payload_json = ? WHERE seq = 2",
                    (orig_payload.replace("400", "9999"),),
                )
                conn.commit()
            finally:
                conn.close()
            self.assertFalse(ledger.verify_audit_chain())

            # Restore payload_json -> valid again, then tamper with prev_sha256
            conn = sqlite3.connect(str(db))
            try:
                conn.execute(
                    "UPDATE audit_events SET payload_json = ? WHERE seq = 2",
                    (orig_payload,),
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(ledger.verify_audit_chain())

            conn = sqlite3.connect(str(db))
            try:
                conn.execute(
                    "UPDATE audit_events SET prev_sha256 = ? WHERE seq = 3",
                    ("f" * 64,),
                )
                conn.commit()
            finally:
                conn.close()
            self.assertFalse(ledger.verify_audit_chain())

    def test_strict_validation_and_thread_safety(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "threads.sqlite3"
            ledger = UnifiedRealTimeLedger(
                db,
                principal_usd=Decimal("300000.00"),
                initial_equity_usd=Decimal("300000.00"),
                clock=lambda: T_DAY1_NY,
            )

            # Reject float P&L, naive datetime, invalid session date
            with self.assertRaises(ContractError):
                ledger.record_realized_trade(
                    trade_id="bad-float",
                    symbol="NAS100",
                    broker_id="hugosway-mt5",
                    realized_pnl_usd=100.0,  # type: ignore[arg-type]
                    occurred_at=T_DAY1_NY,
                )
            with self.assertRaises(ContractError):
                ledger.record_realized_trade(
                    trade_id="bad-tz",
                    symbol="NAS100",
                    broker_id="hugosway-mt5",
                    realized_pnl_usd=Decimal("10.00"),
                    occurred_at=datetime(2026, 11, 19, 15, 0, 0),
                )
            with self.assertRaises(ContractError):
                ledger.session_summary("2026-02-30")

            # Concurrent writers + readers across 8 threads
            def _worker(i: int) -> Decimal:
                snap = ledger.record_realized_trade(
                    trade_id=f"mt-{i:03d}",
                    symbol="NAS100",
                    broker_id="hugosway-mt5",
                    realized_pnl_usd=Decimal("10.25"),
                    occurred_at=T_DAY1_NY + timedelta(seconds=i),
                )
                _ = ledger.snapshot(now_utc=T_DAY1_NY + timedelta(seconds=i))
                return snap.settled_equity_usd

            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(_worker, range(40)))

            final = ledger.snapshot(now_utc=T_DAY1_NY)
            self.assertEqual(final.lifetime_realized_pnl_usd, Decimal("410.00"))
            self.assertEqual(final.settled_equity_usd, Decimal("300410.00"))
            self.assertEqual(final.bank_vault_reserved_usd, Decimal("205.00"))
            self.assertEqual(final.daily_closed_trades, 40)
            self.assertEqual(trading_date_for(T_DAY1_NY), "2026-11-19")
            self.assertTrue(ledger.verify_audit_chain())
            self.assertEqual(final.to_dict()["bank_vault_reserved_usd"], "205")


if __name__ == "__main__":
    unittest.main()
