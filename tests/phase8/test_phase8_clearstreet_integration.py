"""End-to-end integration tests for Phase 8 Clear Street Items 1-4.

Covers:
- Scenario A: Normal Entry -> Real ForexMetaValveGate + 1000% Margin Slicing ->
  ExecutionEventBus FILL + TP_HIT -> UnifiedRealTimeLedger ($0.00 reserve in
  RECOVERY_MODE, 50% surplus reserve in IN_SURPLUS, SHA-256 audit chain, 0-write
  snapshot across midnight UTC rollover).
- Scenario B: Red-Flag USD CPI News Shock blocking SmartSliceExecutor new entry
  slices (0 slices executed) while protective actions (AMEND_STOP, MOVE_BREAKEVEN,
  TRAIL_STOP, CLOSE_POSITION, EMERGENCY_CLOSE_ALL) remain unconditionally allowed
  and publish through ExecutionEventBus in <50ms even while a 400ms slow ledger
  subscriber lags and a UI subscriber raises RuntimeError.
- Scenario C: Inadmissible valve score (<0.55) aborting slicing cleanly, pending
  bank transfers never prematurely exiting RECOVERY_MODE, and bidirectional
  same-day loss-lock carryover across the $300,000.00 principal boundary.
- Scenario D: Mt5PositionDiffEmitter -> ExecutionEventBus -> UnifiedRealTimeLedger
  full lifecycle with SSE reconnect replay and zero-duplicate re-poll idempotency.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from cas_forex_revamp.contracts import Side
from cas_forex_revamp.execution import (
    AccountMarginState,
    ExecutionStyle,
    ParentOrderRequest,
    QuoteSnapshot,
    RefusalReason,
    SliceOutcome,
    SmartExecutionPlanner,
    SmartSliceExecutor,
    VenueSliceFill,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.ledger import (
    DisbursementStatus,
    INTERNAL_ACCOUNTING_LABEL,
    LedgerMode,
    UnifiedRealTimeLedger,
)
from cas_forex_revamp.risk import (
    EconomicEvent,
    NewsImpact,
    NewsShockShield,
    TradeActionType,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision
from cas_forex_revamp.venue.execution_event_bus import (
    ExecutionEvent,
    ExecutionEventBus,
    ExecutionEventType,
    Mt5PositionDiffEmitter,
    SubscriberLane,
)


def _utc(year: int, month: int, day: int, hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _usd_cpi_event(scheduled_utc: datetime) -> EconomicEvent:
    return EconomicEvent(
        event_id="usd-cpi-2026-11-20",
        title="US Consumer Price Index (CPI) YoY",
        currency="USD",
        impact=NewsImpact.HIGH,
        scheduled_utc=scheduled_utc,
        category="CPI",
        source="offline_calendar_fixture",
    )


def _sqlite_data_version_and_counts(db_path: Path) -> tuple[int, dict[str, int]]:
    uri = f"{db_path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as conn:
        conn.execute("PRAGMA query_only=ON")
        data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        counts = {
            t: int(conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0])
            for t in tables
        }
        return data_version, counts


class _RefuseSecondSliceValve:
    """Deterministic valve wrapper delegating slice 1 to real gate and refusing slice 2 (<0.55)."""

    def __init__(self) -> None:
        self._real_gate = load_default_forex_valve_gate()
        self.calls = 0

    def evaluate(self, proposal, *, current_view, policy, now):
        self.calls += 1
        real_decision = self._real_gate.evaluate(
            proposal,
            current_view=current_view,
            policy=policy,
            now=now,
        )
        if self.calls == 1:
            return real_decision
        return replace(
            real_decision,
            admitted=False,
            valve_mode="REFUSE_INADMISSIBLE_SCORE",
            mlp_score=0.41,
            threshold=0.55,
            mlp_admitted=False,
            hard_veto=False,
            hard_veto_reasons=(),
        )


class Phase8ClearStreetIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cas_phase8_int_")
        self._tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_scenario_a_normal_entry_slice_fill_to_ledger_and_zero_write_rollover(self) -> None:
        """Scenario A: News allowed -> Real Valve + 1000% Margin Slice -> EventBus -> Ledger -> 0-write rollover."""
        cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        entry_time = _utc(2026, 11, 20, 14, 0, 0)  # 30 minutes after CPI (outside 5m blackout)
        tp_time = _utc(2026, 11, 20, 14, 15, 0)
        tp2_time = _utc(2026, 11, 20, 15, 0, 0)
        next_day_utc = _utc(2026, 11, 21, 0, 5, 0)

        shield = NewsShockShield(events=(_usd_cpi_event(cpi_time),))
        entry_decision = shield.evaluate("NAS100", TradeActionType.OPEN_NEW, now_utc=entry_time)
        self.assertTrue(entry_decision.allowed)
        self.assertEqual(entry_decision.blocking_events, ())

        db_path = self._tmp_dir / "scenario_a_ledger.sqlite3"
        ledger = UnifiedRealTimeLedger(
            db_path,
            principal_usd=Decimal("300000.00"),
            initial_equity_usd=Decimal("299500.00"),
            clock=lambda: entry_time,
        )

        # Verify starting state is RECOVERY_MODE with $0.00 bank vault reserve
        start_snap = ledger.snapshot(now_utc=entry_time)
        self.assertEqual(start_snap.mode, LedgerMode.RECOVERY_MODE)
        self.assertEqual(start_snap.settled_equity_usd, Decimal("299500.00"))
        self.assertEqual(start_snap.bank_vault_reserved_usd, Decimal("0.00"))
        self.assertEqual(start_snap.accounting_label, INTERNAL_ACCOUNTING_LABEL)

        real_valve = load_default_forex_valve_gate()
        planner = SmartExecutionPlanner()
        quote = QuoteSnapshot(
            symbol="NAS100",
            bid=Decimal("21000.00"),
            ask=Decimal("21001.26"),
            timestamp_utc=entry_time,
        )
        parent_req = ParentOrderRequest(
            parent_order_id="ord-nas100-scen-a",
            symbol="NAS100",
            side=Side.BUY,
            total_lots=Decimal("0.06"),
            style=ExecutionStyle.TWAP_SLICED,
            slice_count=3,
            interval_seconds=5,
            reason="Phase 8 Scenario A trend breakout entry",
        )
        plan = planner.plan(parent_req, quote, now_utc=entry_time)
        self.assertEqual(len(plan.slices), 3)
        self.assertEqual(sum(s.volume_lots for s in plan.slices), Decimal("0.06"))

        account_state = AccountMarginState(
            account_id="acct-clearstreet-a",
            balance=Decimal("299500.00"),
            equity=Decimal("299500.00"),
            used_margin=Decimal("0.00"),
            free_margin=Decimal("299500.00"),
            peak_equity=Decimal("300000.00"),
        )

        current_clock = [entry_time]
        published_events: list[ExecutionEvent] = []
        ledger_updates_done = threading.Event()
        ledger_received: list[str] = []

        with ExecutionEventBus() as bus:
            def _on_ledger_event(ev: ExecutionEvent) -> None:
                ledger.record_execution_event(ev)
                ledger_received.append(ev.event_id)
                if ev.event_id == "evt-scen-a-tp-surplus":
                    ledger_updates_done.set()

            bus.subscribe(_on_ledger_event, lane=SubscriberLane.LEDGER_ASYNC, name="unified-ledger")

            def _emit_slice_fill(rec) -> None:
                if rec.outcome is SliceOutcome.FILLED:
                    ev = ExecutionEvent(
                        event_id=f"fill-{rec.slice_id}",
                        event_type=ExecutionEventType.FILL,
                        broker_id="HUGOSWAY_MT5",
                        symbol=rec.symbol,
                        order_id=rec.broker_order_id or rec.slice_id,
                        position_ticket=f"pos-{rec.slice_index}",
                        side=rec.side,
                        quantity_lots=rec.filled_lots,
                        price=rec.fill_price,
                        realized_pnl_usd=Decimal("0.00"),
                        timestamp_utc=rec.executed_at.isoformat().replace("+00:00", "Z"),
                    )
                    published_events.append(bus.publish(ev))

            executor = SmartSliceExecutor(
                valve_gate=real_valve,
                pre_slice_guard=shield.make_pre_slice_guard(
                    action=TradeActionType.OPEN_NEW,
                    clock=lambda: current_clock[0],
                ),
                clock=lambda: current_clock[0],
                sleeper=lambda secs: current_clock.__setitem__(
                    0, current_clock[0] + timedelta(seconds=secs)
                ),
                event_callback=_emit_slice_fill,
            )

            report = executor.execute(
                plan,
                account_state=account_state,
                quote_provider=lambda child, now: QuoteSnapshot(
                    symbol="NAS100",
                    bid=Decimal("21000.00"),
                    ask=Decimal("21001.26"),
                    timestamp_utc=now,
                ),
                submit_slice=lambda child, live_q, now: VenueSliceFill(
                    filled=True,
                    fill_price=live_q.ask,
                    filled_lots=child.volume_lots,
                    broker_order_id=f"brk-{child.slice_id}",
                ),
            )

            self.assertFalse(report.aborted)
            self.assertEqual(report.filled_slice_count, 3)
            self.assertEqual(report.filled_lots, Decimal("0.06"))
            for rec in report.slice_records:
                self.assertEqual(rec.outcome, SliceOutcome.FILLED)
                self.assertTrue(rec.valve_admitted)
                self.assertGreaterEqual(rec.valve_score, 0.55)
                self.assertGreaterEqual(rec.post_trade_margin_level_pct, Decimal("1000.0"))
                self.assertEqual(rec.protection.sl_distance, Decimal("25.00"))
                self.assertEqual(rec.protection.tp_distance, Decimal("60.00"))

            # First TP_HIT: +$300.00 -> settled equity $299,800.00 (still RECOVERY_MODE, $0.00 vault reserve)
            bus.publish(
                ExecutionEvent(
                    event_id="evt-scen-a-tp-recovery",
                    event_type=ExecutionEventType.TP_HIT,
                    broker_id="HUGOSWAY_MT5",
                    symbol="NAS100",
                    order_id="brk-ord-nas100-scen-a-s1",
                    position_ticket="pos-1",
                    side=Side.BUY,
                    quantity_lots=Decimal("0.02"),
                    price=Decimal("21061.26"),
                    realized_pnl_usd=Decimal("300.00"),
                    timestamp_utc=tp_time.isoformat().replace("+00:00", "Z"),
                )
            )
            self.assertTrue(bus.flush(timeout=5.0))

            mid_snap = ledger.snapshot(now_utc=tp_time)
            self.assertEqual(mid_snap.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(mid_snap.settled_equity_usd, Decimal("299800.00"))
            self.assertEqual(mid_snap.net_surplus_above_principal_usd, Decimal("0.00"))
            self.assertEqual(mid_snap.bank_vault_reserved_usd, Decimal("0.00"))

            # Second TP_HIT: +$1,200.00 -> settled equity $301,000.00 (IN_SURPLUS by $1,000.00 -> 50% = $500.00)
            bus.publish(
                ExecutionEvent(
                    event_id="evt-scen-a-tp-surplus",
                    event_type=ExecutionEventType.TP_HIT,
                    broker_id="HUGOSWAY_MT5",
                    symbol="NAS100",
                    order_id="brk-ord-nas100-scen-a-s2",
                    position_ticket="pos-2",
                    side=Side.BUY,
                    quantity_lots=Decimal("0.04"),
                    price=Decimal("21061.26"),
                    realized_pnl_usd=Decimal("1200.00"),
                    timestamp_utc=tp2_time.isoformat().replace("+00:00", "Z"),
                )
            )
            self.assertTrue(ledger_updates_done.wait(timeout=5.0))
            self.assertTrue(bus.flush(timeout=5.0))

        self.assertEqual(len(published_events), 3)
        self.assertIn("evt-scen-a-tp-recovery", ledger_received)
        self.assertIn("evt-scen-a-tp-surplus", ledger_received)

        surplus_snap = ledger.snapshot(now_utc=tp2_time)
        self.assertEqual(surplus_snap.mode, LedgerMode.IN_SURPLUS)
        self.assertEqual(surplus_snap.settled_equity_usd, Decimal("301000.00"))
        self.assertEqual(surplus_snap.net_surplus_above_principal_usd, Decimal("1000.00"))
        self.assertEqual(surplus_snap.bank_vault_reserved_usd, Decimal("500.00"))
        self.assertEqual(surplus_snap.retained_trading_surplus_usd, Decimal("500.00"))
        self.assertEqual(surplus_snap.accounting_label, INTERNAL_ACCOUNTING_LABEL)
        self.assertTrue(ledger.verify_audit_chain())

        # Strictly 0-write snapshot across midnight UTC day rollover
        dv_before, counts_before = _sqlite_data_version_and_counts(db_path)
        mtime_before = os.stat(db_path).st_mtime_ns
        rollover_snap = ledger.snapshot(now_utc=next_day_utc)
        dv_after, counts_after = _sqlite_data_version_and_counts(db_path)
        mtime_after = os.stat(db_path).st_mtime_ns

        self.assertEqual(rollover_snap.session_date, "2026-11-21")
        self.assertEqual(rollover_snap.daily_realized_pnl_usd, Decimal("0.00"))
        self.assertEqual(rollover_snap.lifetime_realized_pnl_usd, Decimal("1500.00"))
        self.assertEqual(dv_before, dv_after)
        self.assertEqual(counts_before, counts_after)
        self.assertEqual(mtime_before, mtime_after)

    def test_scenario_b_cpi_shock_blocks_new_slices_but_allows_fast_protective_stops(self) -> None:
        """Scenario B: CPI blocks new slices (0 filled); protective stop/close allowed & <50ms publish with 400ms slow ledger."""
        cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        shield = NewsShockShield(events=(_usd_cpi_event(cpi_time),))

        # 1. New NAS100 entry blocked by NewsShockShield pre_slice_guard -> 0 slices executed
        planner = SmartExecutionPlanner()
        quote = QuoteSnapshot(
            symbol="NAS100",
            bid=Decimal("21000.00"),
            ask=Decimal("21001.20"),
            timestamp_utc=cpi_time,
        )
        plan = planner.plan(
            ParentOrderRequest(
                parent_order_id="ord-nas100-cpi-blocked",
                symbol="NAS100",
                side=Side.BUY,
                total_lots=Decimal("0.04"),
                style=ExecutionStyle.TWAP_SLICED,
                slice_count=2,
                interval_seconds=5,
            ),
            quote,
            now_utc=cpi_time,
        )
        submit_calls = 0

        def _should_not_submit(child, live_q, now):
            nonlocal submit_calls
            submit_calls += 1
            return VenueSliceFill(filled=True, fill_price=live_q.ask, filled_lots=child.volume_lots)

        executor = SmartSliceExecutor(
            valve_gate=load_default_forex_valve_gate(),
            pre_slice_guard=shield.make_pre_slice_guard(
                action=TradeActionType.OPEN_NEW,
                clock=lambda: cpi_time,
            ),
            clock=lambda: cpi_time,
        )
        report = executor.execute(
            plan,
            account_state=AccountMarginState(
                account_id="acct-clearstreet-b",
                balance=Decimal("300000.00"),
                equity=Decimal("300000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("300000.00"),
            ),
            quote_provider=quote,
            submit_slice=_should_not_submit,
        )
        self.assertTrue(report.aborted)
        self.assertEqual(report.abort_reason, RefusalReason.PRE_SLICE_GUARD_BLOCKED)
        self.assertEqual(report.filled_lots, Decimal("0"))
        self.assertEqual(report.filled_slice_count, 0)
        self.assertEqual(submit_calls, 0)
        self.assertIn("NEW_ENTRY_PAUSED_NEWS_WINDOW", report.slice_records[0].detail)

        # 2. Protective actions are UNCONDITIONALLY ALLOWED at the exact second of CPI
        for action in (
            TradeActionType.AMEND_STOP,
            TradeActionType.MOVE_BREAKEVEN,
            TradeActionType.TRAIL_STOP,
            TradeActionType.CLOSE_POSITION,
            TradeActionType.EMERGENCY_CLOSE_ALL,
        ):
            dec = shield.evaluate("NAS100", action, now_utc=cpi_time)
            self.assertTrue(dec.allowed, f"{action} must be allowed during CPI")
            self.assertEqual(dec.reason_code, "PROTECTIVE_ACTION_ALWAYS_ALLOWED")

        # 3. Publish AMEND_STOP + CLOSE_MANUAL via ExecutionEventBus in <50ms despite 400ms slow ledger + raising UI
        threads_before = set(threading.enumerate())
        critical_seen: list[str] = []
        slow_ledger_seen: list[str] = []

        with ExecutionEventBus() as bus:
            bus.subscribe(
                lambda ev: critical_seen.append(ev.event_id),
                lane=SubscriberLane.CRITICAL_PROTECTION,
                name="stop-protector",
            )

            def _slow_ledger(ev: ExecutionEvent) -> None:
                time.sleep(0.40)
                slow_ledger_seen.append(ev.event_id)

            def _failing_ui(ev: ExecutionEvent) -> None:
                raise RuntimeError("simulated dashboard SSE socket disconnect")

            bus.subscribe(_slow_ledger, lane=SubscriberLane.LEDGER_ASYNC, name="slow-ledger")
            bus.subscribe(_failing_ui, lane=SubscriberLane.UI_SSE_ASYNC, name="broken-ui")

            amend_ev = ExecutionEvent(
                event_id="evt-cpi-amend-be",
                event_type=ExecutionEventType.AMEND_STOP,
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                order_id="ord-open-1",
                position_ticket="ticket-open-1",
                side=Side.BUY,
                quantity_lots=Decimal("0.02"),
                price=Decimal("21020.00"),
                stop_loss=Decimal("21001.26"),
                realized_pnl_usd=Decimal("0.00"),
                timestamp_utc=cpi_time.isoformat().replace("+00:00", "Z"),
                reason="MOVE_BREAKEVEN during CPI shock",
            )
            close_ev = ExecutionEvent(
                event_id="evt-cpi-close-pos",
                event_type=ExecutionEventType.CLOSE_MANUAL,
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                order_id="ord-open-1",
                position_ticket="ticket-open-1",
                side=Side.BUY,
                quantity_lots=Decimal("0.02"),
                price=Decimal("21015.00"),
                realized_pnl_usd=Decimal("137.40"),
                timestamp_utc=cpi_time.isoformat().replace("+00:00", "Z"),
                reason="CLOSE_POSITION during CPI shock",
            )

            t0 = time.perf_counter()
            bus.publish(amend_ev)
            bus.publish(close_ev)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            # Publish + inline CRITICAL_PROTECTION must return well under 50ms even with 400ms slow ledger!
            self.assertLess(elapsed_ms, 50.0, f"publish took {elapsed_ms:.2f}ms >= 50ms")
            self.assertEqual(critical_seen, ["evt-cpi-amend-be", "evt-cpi-close-pos"])

            self.assertTrue(bus.flush(timeout=5.0))
            metrics = bus.metrics()
            self.assertEqual(metrics["published_count"], 2)
            self.assertGreaterEqual(metrics["subscriber_errors"], 2)
            self.assertEqual(slow_ledger_seen, ["evt-cpi-amend-be", "evt-cpi-close-pos"])

        # Confirm zero leaked daemon threads after context exit
        leaked = [t for t in threading.enumerate() if t not in threads_before and t.is_alive()]
        self.assertEqual(leaked, [], f"Leaked threads after bus shutdown: {leaked}")

    def test_scenario_c_valve_refusal_pending_transfer_and_bidirectional_loss_lock_carryover(self) -> None:
        """Scenario C: Inadmissible valve aborts slice 2; pending transfer stays RECOVERY_MODE; bidirectional $300k loss-lock carryover."""
        t0 = _utc(2026, 11, 20, 14, 0, 0)

        # 1. Inadmissible valve score (<0.55) aborts slicing immediately on slice 2 (slice 3 never executed)
        planner = SmartExecutionPlanner()
        quote = QuoteSnapshot(
            symbol="NAS100",
            bid=Decimal("21000.00"),
            ask=Decimal("21001.20"),
            timestamp_utc=t0,
        )
        plan = planner.plan(
            ParentOrderRequest(
                parent_order_id="ord-nas100-valve-refuse",
                symbol="NAS100",
                side=Side.BUY,
                total_lots=Decimal("0.06"),
                style=ExecutionStyle.TWAP_SLICED,
                slice_count=3,
                interval_seconds=0,
            ),
            quote,
            now_utc=t0,
        )
        valve = _RefuseSecondSliceValve()
        executor = SmartSliceExecutor(valve_gate=valve, clock=lambda: t0)
        submitted_slices: list[int] = []
        report = executor.execute(
            plan,
            account_state=AccountMarginState(
                account_id="acct-clearstreet-c",
                balance=Decimal("299500.00"),
                equity=Decimal("299500.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("299500.00"),
            ),
            quote_provider=quote,
            submit_slice=lambda child, live_q, now: (
                submitted_slices.append(child.slice_index)
                or VenueSliceFill(filled=True, fill_price=live_q.ask, filled_lots=child.volume_lots)
            ),
        )
        self.assertTrue(report.aborted)
        self.assertEqual(report.abort_reason, RefusalReason.VALVE_REFUSAL)
        self.assertEqual(submitted_slices, [0])
        self.assertEqual(report.filled_slice_count, 1)
        self.assertEqual(report.filled_lots, Decimal("0.02"))
        self.assertEqual(report.slice_records[1].outcome, SliceOutcome.REFUSED)
        self.assertEqual(report.slice_records[1].refusal_reason, RefusalReason.VALVE_REFUSAL)
        self.assertEqual(report.slice_records[2].outcome, SliceOutcome.ABORTED)

        # 2. Pending bank transfer NEVER prematurely exits RECOVERY_MODE; only SETTLED counts
        db_pending = self._tmp_dir / "scenario_c_pending.sqlite3"
        led_pending = UnifiedRealTimeLedger(
            db_pending,
            principal_usd=Decimal("300000.00"),
            initial_equity_usd=Decimal("295000.00"),
            clock=lambda: t0,
        )
        for idx, st in enumerate(
            (
                DisbursementStatus.PENDING,
                DisbursementStatus.SUBMITTED,
                DisbursementStatus.UNKNOWN,
                DisbursementStatus.FAILED,
            ),
            start=1,
        ):
            snap = led_pending.record_disbursement(
                transfer_id=f"tx-unsettled-{idx}",
                amount_usd=Decimal("10000.00"),
                status=st,
                occurred_at=t0 + timedelta(minutes=idx),
            )
            self.assertEqual(snap.mode, LedgerMode.RECOVERY_MODE)
            self.assertEqual(snap.settled_equity_usd, Decimal("295000.00"))
            self.assertEqual(snap.confirmed_settled_disbursed_usd, Decimal("0.00"))
            self.assertEqual(snap.bank_vault_reserved_usd, Decimal("0.00"))

        snap_pre = led_pending.snapshot(now_utc=t0 + timedelta(minutes=10))
        self.assertEqual(snap_pre.pending_transfers_usd, Decimal("30000.00"))
        self.assertEqual(snap_pre.failed_cancelled_transfers_usd, Decimal("10000.00"))

        # Settling tx-unsettled-1 ($10,000.00) now counts toward confirmed_settled_disbursed_usd -> $305,000.00 IN_SURPLUS
        snap_settled = led_pending.update_disbursement_status(
            transfer_id="tx-unsettled-1",
            status=DisbursementStatus.SETTLED,
            provider_tx_id="wire-confirmed-001",
            occurred_at=t0 + timedelta(minutes=15),
        )
        self.assertEqual(snap_settled.mode, LedgerMode.IN_SURPLUS)
        self.assertEqual(snap_settled.confirmed_settled_disbursed_usd, Decimal("10000.00"))
        self.assertEqual(snap_settled.settled_equity_usd, Decimal("305000.00"))
        self.assertEqual(snap_settled.pending_transfers_usd, Decimal("20000.00"))
        self.assertEqual(snap_settled.vault_sweep_target_usd, Decimal("2500.00"))
        self.assertEqual(snap_settled.bank_vault_reserved_usd, Decimal("0.00"))
        self.assertTrue(led_pending.verify_audit_chain())

        # 3a. Bidirectional same-day loss-lock carryover: IN_SURPLUS -> RECOVERY_MODE
        db_s2r = self._tmp_dir / "scenario_c_lock_s2r.sqlite3"
        led_s2r = UnifiedRealTimeLedger(
            db_s2r,
            principal_usd=Decimal("300000.00"),
            initial_equity_usd=Decimal("300300.00"),
            daily_max_loss_usd=Decimal("500.00"),
            clock=lambda: t0,
        )
        snap_locked_s2r = led_s2r.record_realized_trade(
            trade_id="tr-loss-cross-down",
            symbol="NAS100",
            broker_id="HUGOSWAY_MT5",
            realized_pnl_usd=Decimal("-600.00"),
            occurred_at=t0 + timedelta(minutes=1),
        )
        self.assertEqual(snap_locked_s2r.mode, LedgerMode.RECOVERY_MODE)
        self.assertTrue(snap_locked_s2r.daily_loss_locked)
        self.assertFalse(snap_locked_s2r.new_risk_allowed)
        self.assertTrue(snap_locked_s2r.loss_lock_carried_over)
        self.assertEqual(snap_locked_s2r.loss_lock_origin_mode, LedgerMode.IN_SURPLUS)

        # 3b. Bidirectional same-day loss-lock carryover: RECOVERY_MODE -> IN_SURPLUS
        db_r2s = self._tmp_dir / "scenario_c_lock_r2s.sqlite3"
        led_r2s = UnifiedRealTimeLedger(
            db_r2s,
            principal_usd=Decimal("300000.00"),
            initial_equity_usd=Decimal("299900.00"),
            daily_max_loss_usd=Decimal("500.00"),
            clock=lambda: t0,
        )
        snap_locked_rec = led_r2s.record_realized_trade(
            trade_id="tr-loss-in-recovery",
            symbol="NAS100",
            broker_id="HUGOSWAY_MT5",
            realized_pnl_usd=Decimal("-600.00"),
            occurred_at=t0 + timedelta(minutes=1),
        )
        self.assertEqual(snap_locked_rec.mode, LedgerMode.RECOVERY_MODE)
        self.assertTrue(snap_locked_rec.daily_loss_locked)
        # Even if an already-open position closes positive pushing equity >= $300,000.00 same day, lock MUST carry over!
        snap_crossed_up = led_r2s.record_realized_trade(
            trade_id="tr-recovery-cross-up",
            symbol="NAS100",
            broker_id="HUGOSWAY_MT5",
            realized_pnl_usd=Decimal("1000.00"),
            occurred_at=t0 + timedelta(minutes=5),
        )
        self.assertEqual(snap_crossed_up.mode, LedgerMode.IN_SURPLUS)
        self.assertEqual(snap_crossed_up.settled_equity_usd, Decimal("300300.00"))
        self.assertTrue(snap_crossed_up.daily_loss_locked)
        self.assertFalse(snap_crossed_up.new_risk_allowed)
        self.assertTrue(snap_crossed_up.loss_lock_carried_over)
        self.assertEqual(snap_crossed_up.loss_lock_origin_mode, LedgerMode.RECOVERY_MODE)
        self.assertTrue(led_r2s.verify_audit_chain())

    def test_scenario_d_mt5_diff_emitter_to_eventbus_sse_replay_and_ledger_idempotency(self) -> None:
        """Scenario D: Mt5PositionDiffEmitter -> ExecutionEventBus (SSE + replay) -> UnifiedRealTimeLedger."""
        t1 = _utc(2026, 11, 20, 8, 10, 0)  # LONDON session
        t2 = _utc(2026, 11, 20, 8, 15, 0)
        t3 = _utc(2026, 11, 20, 8, 25, 0)

        db_path = self._tmp_dir / "scenario_d_ledger.sqlite3"
        ledger = UnifiedRealTimeLedger(
            db_path,
            principal_usd=Decimal("300000.00"),
            initial_equity_usd=Decimal("300000.00"),
            clock=lambda: t1,
        )

        with ExecutionEventBus() as bus:
            bus.subscribe(
                lambda ev: ledger.record_execution_event(ev),
                lane=SubscriberLane.LEDGER_ASYNC,
                name="ledger-sub",
            )
            emitter = Mt5PositionDiffEmitter(bus)

            # Poll 1: New position opens -> FILL
            pos_open = {
                "ticket": "88001",
                "symbol": "US30",
                "side": "BUY",
                "volume_lots": Decimal("0.05"),
                "price_open": Decimal("43000.00"),
                "stop_loss": Decimal("42950.00"),
                "take_profit": Decimal("43120.00"),
                "profit": Decimal("0.00"),
            }
            ev1 = emitter.process_snapshot([pos_open], timestamp_utc=t1.isoformat().replace("+00:00", "Z"))
            self.assertEqual(len(ev1), 1)
            self.assertEqual(ev1[0].event_type, ExecutionEventType.FILL)

            # Duplicate poll -> 0 events
            self.assertEqual(
                emitter.process_snapshot([pos_open], timestamp_utc=t1.isoformat().replace("+00:00", "Z")),
                (),
            )

            # Poll 2: Move stop to breakeven -> AMEND_STOP
            pos_be = dict(pos_open, stop_loss=Decimal("43000.00"))
            ev2 = emitter.process_snapshot([pos_be], timestamp_utc=t2.isoformat().replace("+00:00", "Z"))
            self.assertEqual(len(ev2), 1)
            self.assertEqual(ev2[0].event_type, ExecutionEventType.AMEND_STOP)

            # Poll 3: Position closes at TP -> TP_HIT (+$600.00)
            ev3 = emitter.process_snapshot(
                [],
                market_prices={"US30": Decimal("43120.00")},
                close_hints={"88001": {"realized_pnl_usd": Decimal("600.00"), "price": Decimal("43120.00")}},
                timestamp_utc=t3.isoformat().replace("+00:00", "Z"),
            )
            self.assertEqual(len(ev3), 1)
            self.assertEqual(ev3[0].event_type, ExecutionEventType.TP_HIT)

            self.assertTrue(bus.flush(timeout=5.0))

            # Verify SSE replay buffer & frame formatting from seq_id=1
            replayed = bus.events_since(1)
            self.assertEqual([e.event_type for e in replayed], [ExecutionEventType.AMEND_STOP, ExecutionEventType.TP_HIT])
            frames = bus.sse_frames_since(0)
            self.assertEqual(len(frames), 3)
            for frame in frames:
                self.assertTrue(frame.startswith("id: "))
                self.assertTrue(frame.endswith("\n\n"))

        snap = ledger.snapshot(now_utc=t3)
        self.assertEqual(snap.mode, LedgerMode.IN_SURPLUS)
        self.assertEqual(snap.daily_closed_trades, 1)
        self.assertEqual(snap.daily_london_pnl_usd, Decimal("600.00"))
        self.assertEqual(snap.settled_equity_usd, Decimal("300600.00"))
        self.assertEqual(snap.bank_vault_reserved_usd, Decimal("300.00"))
        self.assertTrue(ledger.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
