"""Phase 8 Live Trading Bridge unit & integration tests.

Covers:
1. Fail-closed construction (`valve_gate=None` -> `Phase8BridgeValveError`), broker/input
   validation, and protective-only enforcement on `dispatch_protective_action()`.
2. Normal entries across `HUGOSWAY_MT5` (`NAS100`, `XAUUSD`), `LHFX_MT5` (`US30`), and
   `OANDA` / `OANDA_PRACTICE` / `OANDA_LIVE` (`EUR_USD`) passing:
   NewsShockShield -> CompoundingAndMilestoneController -> real 161-param
   `load_default_forex_valve_gate()` (`0.55` cutoff) -> SmartExecutionPlanner Spread Guard,
   including dynamic compounded dollar risk budget scaling (`$5,000 -> $42.50`, `$10,000 -> $85.00`).
3. Red-flag `CPI` news blocks `OPEN_NEW` and `ADD_POSITION` with
   `NEW_ENTRY_PAUSED_NEWS_WINDOW` + exact `news_resume_at_utc`, while all 5 protective actions
   (`AMEND_STOP`, `MOVE_BREAKEVEN`, `TRAIL_STOP`, `CLOSE_POSITION`, `EMERGENCY_CLOSE_ALL`)
   succeed unconditionally in `< 50ms` even with a `400ms`-sleeping + raising `LEDGER_ASYNC`
   subscriber!
4. Clean fail-closed refusals: blown-out spread (`SPREAD_GUARD_EXCEEDED`), inadmissible valve
   (both real `ForexMetaValveGate` veto and `< 0.55` score refusal), `risk_pct > 1.00%`,
   `drawdown_pct >= 10.00%`, pyramid slot cap, and exhausted daily loss budget.
5. `$5,000.00 -> $10,000.00` realized fill progression across `HUGOSWAY_MT5`, `LHFX_MT5`,
   and `OANDA` with duplicate `event_id` idempotency triggering
   `HOUSE_MONEY_READY_TO_PULL_PRINCIPAL` and persisting asynchronously to
   `UnifiedRealTimeLedger` with a valid SHA-256 audit chain.
6. Strictly 0-write `bridge_snapshot()` across midnight UTC rollover (`PRAGMA data_version`
   and row-count invariant on BOTH Ledger and Compounding SQLite databases).
7. Clean thread shutdown (`0` leaked threads) and source hygiene (`0` `assert`, `0` `float()`
   on money, `0` CRLF/CR, `0` BOM).
"""

from __future__ import annotations

import ast
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from cas_forex_revamp.composition.phase8_live_bridge import (
    BRIDGE_SNAPSHOT_SCHEMA,
    MIN_MARGIN_LEVEL_PCT,
    Phase8BridgeError,
    Phase8BridgeValveError,
    Phase8LiveTradingBridge,
    PreEntryBridgeDecision,
    ProtectiveActionResult,
    SUPPORTED_BROKERS,
)
from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    ActionOption,
    DecisionFact,
    DecisionOrigin,
    DecisionProvenance,
    DecisionRequest,
    DecisionResult,
    DecisionSelection,
    EvidenceKind,
    EvidenceReference,
    RunScope,
    Side,
    StateReference,
    content_digest,
    decimal_text,
)
from cas_forex_revamp.operator.decisions import DecisionProposal
from cas_forex_revamp.execution.smart_execution import (
    AccountMarginState,
    QuoteSnapshot,
    RefusalReason,
    SmartExecutionPlanner,
    SmartSliceExecutor,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.ledger.unified_ledger import UnifiedRealTimeLedger
from cas_forex_revamp.risk.news_shock_shield import (
    EconomicEvent,
    NewsImpact,
    NewsShockShield,
    TradeActionType,
)
from cas_forex_revamp.treasury.compounding_controller import (
    COMPOUNDING_CONTROLLER_SCHEMA,
    CompoundingAndMilestoneController,
    CompoundingMode,
    STATUS_COMPOUNDING_TO_DOUBLE,
    STATUS_HOUSE_MONEY_READY,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision
from cas_forex_revamp.venue.execution_event_bus import (
    ExecutionEvent,
    ExecutionEventBus,
    ExecutionEventType,
    SubscriberLane,
)
from cas_forex_revamp.venue.mt5_broker_bridge import normalize_market_symbol


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


def _make_admissible_proposal(
    *,
    symbol: str,
    side: Side,
    quantity_units: Decimal,
    quote: QuoteSnapshot,
    account: AccountMarginState,
    now_utc: datetime,
    sl_distance: Decimal,
    tp_distance: Decimal,
    stale_seconds: int | None = None,
    req_suffix: str = "001",
) -> DecisionProposal:
    norm = normalize_market_symbol(symbol)
    observed_at = (
        now_utc - timedelta(seconds=stale_seconds)
        if stale_seconds is not None
        else now_utc
    )
    valid_until = (
        now_utc - timedelta(seconds=10)
        if stale_seconds is not None
        else now_utc + timedelta(seconds=120)
    )
    ref_price = quote.reference_price(side)
    if side is Side.BUY:
        sl_price = ref_price - sl_distance
        tp_price = ref_price + tp_distance
    else:
        sl_price = ref_price + sl_distance
        tp_price = ref_price - tp_distance

    scope = RunScope(
        account_id=account.account_id,
        run_id=f"p8-bridge-run-{req_suffix}",
        epoch=1,
        build_id="phase8-live-bridge-test",
        policy_id="cas-forex-phase8-bridge-v1",
        scenario_id=f"entry-{norm.lower()}",
        adapter_id="phase8-live-bridge",
    )
    state = StateReference(
        state_id=f"state-{norm.lower()}-{req_suffix}",
        scope=scope,
        version=1,
        observed_at=observed_at,
        valid_until=valid_until,
        venue_sequence=1,
    )
    obs_obj = {
        "symbol": norm,
        "bid": decimal_text(quote.bid),
        "ask": decimal_text(quote.ask),
        "balance": decimal_text(account.balance),
        "equity": decimal_text(account.equity),
        "available_margin": decimal_text(account.free_margin),
        "position_count": len(account.position_inventory),
        "new_risk": True,
        "management": True,
    }
    obs_json = json.dumps(obs_obj, sort_keys=True, separators=(",", ":"))
    ev_id = f"ev-{norm.lower()}-{req_suffix}"
    evidence = EvidenceReference(
        evidence_id=ev_id,
        kind=EvidenceKind.OBSERVATION,
        producer_id="phase8-live-bridge-test",
        content_sha256=sha256(obs_json.encode("utf-8")).hexdigest(),
        observed_at=observed_at,
    )
    fact = DecisionFact(
        fact_id=f"observed-{norm.lower()}-{req_suffix}",
        label="bridge_market_and_account_snapshot",
        value=obs_json,
        evidence_ids=(ev_id,),
    )
    intent = ActionIntent(
        intent_id=f"intent-{norm.lower()}-{req_suffix}",
        scope=scope,
        decision_id=f"dec-{norm.lower()}-{req_suffix}",
        opportunity_id=f"opp-{norm.lower()}-{req_suffix}",
        action_ref=f"ref-{norm.lower()}-{req_suffix}",
        source_state=state,
        kind=ActionKind.OPEN,
        instrument_id=norm,
        origin=DecisionOrigin.POLICY,
        created_at=observed_at,
        expires_at=valid_until,
        quantity=quantity_units,
        side=side,
        limit_price=None,
        stop_price=sl_price,
        take_profit_price=tp_price,
    )
    option = ActionOption(
        action_ref=intent.action_ref,
        strategy_id="phase8-trend-entry",
        timeframe="M5",
        label=f"{norm} {side.value} trend entry",
        intent=intent,
    )
    request = DecisionRequest(
        request_id=f"req-{norm.lower()}-{req_suffix}",
        opportunity_set_id=f"opp-{norm.lower()}-{req_suffix}",
        state=state,
        options=(option,),
        facts=(fact,),
        evidence=(evidence,),
    )
    selection = DecisionSelection(
        request.request_id,
        request.opportunity_set_id,
        state.state_id,
        intent.action_ref,
        f"Policy-compliant Phase 8 entry for {norm}",
        (ev_id,),
    )
    provenance = DecisionProvenance(
        DecisionOrigin.POLICY,
        "phase8-live-bridge-test",
        content_digest(request),
        content_digest(selection),
        "phase8-bridge-v1",
        observed_at,
        observed_at,
    )
    result = DecisionResult(
        decision_id=intent.decision_id,
        selection=selection,
        provenance=provenance,
    )
    return DecisionProposal(request=request, result=result, intent=intent)


class _LowScoreValveGate:
    """Deterministic valve double returning an inadmissible score (< 0.55)."""

    weights_sha256 = "b" * 64

    def evaluate(self, proposal, *, current_view=None, policy=None, now=None) -> ValveDecision:
        return ValveDecision(
            admitted=False,
            valve_mode="MLP_SCORE_VETO",
            mlp_score=0.41,
            threshold=0.55,
            mlp_admitted=False,
            hard_veto=False,
            hard_veto_reasons=(),
            features={"missing_accounting_ratio": 0.0},
            weights_sha256=self.weights_sha256,
            request_id=proposal.request.request_id,
            selected_action_ref=proposal.result.selection.selected_action_ref,
        )


class Phase8LiveTradingBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cas_phase8_bridge_")
        self._tmp_dir = Path(self._tmp.name)
        self.cpi_time = _utc(2026, 11, 20, 13, 30, 0)
        self.calm_time = _utc(2026, 11, 20, 14, 0, 0)  # 30m after CPI
        self.real_valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_stack(
        self,
        *,
        name: str = "default",
        valve_gate=None,
        principal_usd: Decimal = Decimal("5000.00"),
        initial_equity_usd: Decimal | None = None,
        attach_compounding: bool = True,
        events: tuple[EconomicEvent, ...] | None = None,
    ) -> tuple[
        Phase8LiveTradingBridge,
        UnifiedRealTimeLedger,
        ExecutionEventBus,
        CompoundingAndMilestoneController | None,
        Path,
        Path,
    ]:
        ledger_db = self._tmp_dir / f"{name}_ledger.sqlite3"
        comp_db = self._tmp_dir / f"{name}_compounding.sqlite3"
        init_eq = principal_usd if initial_equity_usd is None else initial_equity_usd
        ledger = UnifiedRealTimeLedger(
            ledger_db,
            principal_usd=principal_usd,
            initial_equity_usd=init_eq,
            clock=lambda: self.calm_time,
        )
        comp = (
            CompoundingAndMilestoneController(
                comp_db,
                starting_principal_usd=principal_usd,
                mode=CompoundingMode.FULL_COMPOUND_100,
                now_utc=self.calm_time,
            )
            if attach_compounding
            else None
        )
        shield = NewsShockShield(
            events=(_usd_cpi_event(self.cpi_time),) if events is None else events
        )
        planner = SmartExecutionPlanner()
        gate = self.real_valve if valve_gate is None else valve_gate
        executor = SmartSliceExecutor(valve_gate=gate)
        bus = ExecutionEventBus()
        bridge = Phase8LiveTradingBridge(
            gate,
            ledger=ledger,
            event_bus=bus,
            news_shield=shield,
            smart_planner=planner,
            smart_executor=executor,
            compounding_controller=comp,
        )
        return bridge, ledger, bus, comp, ledger_db, comp_db

    # 1. Fail-closed construction & input hygiene
    def test_fail_closed_when_valve_missing_and_invalid_inputs_rejected(self) -> None:
        ledger = UnifiedRealTimeLedger(
            self._tmp_dir / "fail_closed_ledger.sqlite3",
            principal_usd=Decimal("5000.00"),
            clock=lambda: self.calm_time,
        )
        shield = NewsShockShield(events=())
        planner = SmartExecutionPlanner()
        executor = SmartSliceExecutor(valve_gate=self.real_valve)
        with ExecutionEventBus() as bus:
            with self.assertRaises(Phase8BridgeValveError):
                Phase8LiveTradingBridge(
                    None,
                    ledger=ledger,
                    event_bus=bus,
                    news_shield=shield,
                    smart_planner=planner,
                    smart_executor=executor,
                )

            with self.assertRaises(Phase8BridgeValveError):
                Phase8LiveTradingBridge(
                    object(),
                    ledger=ledger,
                    event_bus=bus,
                    news_shield=shield,
                    smart_planner=planner,
                    smart_executor=executor,
                )

        bridge, _, _, _, _, _ = self._build_stack(name="invalid_inputs")
        with bridge:
            nas_quote = QuoteSnapshot(
                symbol="NAS100",
                bid=Decimal("20500.00"),
                ask=Decimal("20501.25"),
                timestamp_utc=self.calm_time,
            )
            acct = AccountMarginState(
                account_id="acct-5k",
                balance=Decimal("5000.00"),
                equity=Decimal("5000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("5000.00"),
                peak_equity=Decimal("5000.00"),
            )
            prop = _make_admissible_proposal(
                symbol="NAS100",
                side=Side.BUY,
                quantity_units=Decimal("1.00"),
                quote=nas_quote,
                account=acct,
                now_utc=self.calm_time,
                sl_distance=Decimal("25.00"),
                tp_distance=Decimal("60.00"),
            )
            # Unsupported broker fails closed
            with self.assertRaises(Phase8BridgeError):
                bridge.evaluate_pre_entry(
                    broker_id="UNKNOWN_BROKER",
                    symbol="NAS100",
                    side="BUY",
                    equity_usd=Decimal("5000.00"),
                    stop_distance_points=Decimal("25.00"),
                    risk_pct=Decimal("0.85"),
                    quote=nas_quote,
                    account_state=acct,
                    proposal=prop,
                    now_utc=self.calm_time,
                )
            # Float money fails closed
            with self.assertRaises(Phase8BridgeError):
                bridge.evaluate_pre_entry(
                    broker_id="HUGOSWAY_MT5",
                    symbol="NAS100",
                    side="BUY",
                    equity_usd=5000.0,  # type: ignore[arg-type]
                    stop_distance_points=Decimal("25.00"),
                    risk_pct=Decimal("0.85"),
                    quote=nas_quote,
                    account_state=acct,
                    proposal=prop,
                    now_utc=self.calm_time,
                )
            # Protective dispatch refuses entry actions fail-closed
            for non_protective in (TradeActionType.OPEN_NEW, TradeActionType.ADD_POSITION):
                with self.assertRaises(Phase8BridgeError):
                    bridge.dispatch_protective_action(
                        broker_id="HUGOSWAY_MT5",
                        symbol="NAS100",
                        action=non_protective,
                        order_id="ord-1",
                        position_ticket="tkt-1",
                        side="BUY",
                        quantity_lots=Decimal("0.10"),
                        price=Decimal("20500.00"),
                        now_utc=self.calm_time,
                    )

    # 2. Normal HUGOSWAY_MT5 NAS100, LHFX_MT5 US30, and OANDA EUR_USD entries passing all 4 gates
    def test_normal_entries_pass_all_four_gates_across_brokers_and_compounding_scale(self) -> None:
        self.assertEqual(self.real_valve.controller.parameter_count, 161)
        self.assertEqual(self.real_valve.controller.threshold, 0.55)

        bridge, _, _, _, _, _ = self._build_stack(name="normal_entries")
        with bridge:
            acct_5k = AccountMarginState(
                account_id="acct-live-5k",
                balance=Decimal("5000.00"),
                equity=Decimal("5000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("5000.00"),
                peak_equity=Decimal("5000.00"),
            )

            # A. HUGOSWAY_MT5 NAS100 at $5,000 equity, 0.85% risk -> $42.50 budget, 25pt SL -> 1.70 lots
            nas_quote = QuoteSnapshot(
                symbol="NAS100",
                bid=Decimal("20500.00"),
                ask=Decimal("20501.25"),
                timestamp_utc=self.calm_time,
            )
            nas_prop = _make_admissible_proposal(
                symbol="NAS100",
                side=Side.BUY,
                quantity_units=Decimal("1.00"),
                quote=nas_quote,
                account=acct_5k,
                now_utc=self.calm_time,
                sl_distance=Decimal("25.00"),
                tp_distance=Decimal("60.00"),
                req_suffix="nas5k",
            )
            nas_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=nas_quote,
                account_state=acct_5k,
                proposal=nas_prop,
                now_utc=self.calm_time,
            )
            self.assertIsInstance(nas_dec, PreEntryBridgeDecision)
            self.assertTrue(nas_dec.allowed)
            self.assertEqual(nas_dec.reason_code, "ENTRY_ADMITTED")
            self.assertEqual(nas_dec.broker_id, "HUGOSWAY_MT5")
            self.assertEqual(nas_dec.symbol, "NAS100")
            self.assertIsNotNone(nas_dec.valve_score)
            self.assertGreaterEqual(nas_dec.valve_score, 0.55)
            self.assertEqual(nas_dec.risk_budget_usd, Decimal("42.50"))
            self.assertIsNone(nas_dec.news_resume_at_utc)
            self.assertIsNotNone(nas_dec.execution_plan)
            self.assertEqual(nas_dec.execution_plan.planned_lots, Decimal("1.70"))
            self.assertEqual(len(nas_dec.execution_plan.plan_sha256), 64)

            # B. Compounded scaling: $10,000 equity at 0.85% risk -> $85.00 budget -> 3.40 lots
            acct_10k = AccountMarginState(
                account_id="acct-live-10k",
                balance=Decimal("10000.00"),
                equity=Decimal("10000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("10000.00"),
                peak_equity=Decimal("10000.00"),
            )
            nas_prop_10k = _make_admissible_proposal(
                symbol="NAS100",
                side=Side.BUY,
                quantity_units=Decimal("3.00"),
                quote=nas_quote,
                account=acct_10k,
                now_utc=self.calm_time,
                sl_distance=Decimal("25.00"),
                tp_distance=Decimal("60.00"),
                req_suffix="nas10k",
            )
            nas_dec_10k = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("10000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=nas_quote,
                account_state=acct_10k,
                proposal=nas_prop_10k,
                now_utc=self.calm_time,
            )
            self.assertTrue(nas_dec_10k.allowed)
            self.assertEqual(nas_dec_10k.risk_budget_usd, Decimal("85.00"))
            self.assertEqual(nas_dec_10k.execution_plan.planned_lots, Decimal("3.40"))
            self.assertEqual(nas_dec_10k.house_money_status, STATUS_HOUSE_MONEY_READY)

            # C. LHFX_MT5 US30 entry
            us30_quote = QuoteSnapshot(
                symbol="US30",
                bid=Decimal("43200.00"),
                ask=Decimal("43203.00"),
                timestamp_utc=self.calm_time,
            )
            us30_prop = _make_admissible_proposal(
                symbol="US30",
                side=Side.SELL,
                quantity_units=Decimal("0.80"),
                quote=us30_quote,
                account=acct_5k,
                now_utc=self.calm_time,
                sl_distance=Decimal("50.00"),
                tp_distance=Decimal("120.00"),
                req_suffix="us30",
            )
            us30_dec = bridge.evaluate_pre_entry(
                broker_id="LHFX_MT5",
                symbol="US30",
                side="SELL",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("50.00"),
                risk_pct=Decimal("0.85"),
                quote=us30_quote,
                account_state=acct_5k,
                proposal=us30_prop,
                now_utc=self.calm_time,
            )
            self.assertTrue(us30_dec.allowed)
            self.assertEqual(us30_dec.broker_id, "LHFX_MT5")
            self.assertEqual(us30_dec.symbol, "US30")
            self.assertEqual(us30_dec.risk_budget_usd, Decimal("42.50"))
            self.assertEqual(us30_dec.execution_plan.planned_lots, Decimal("0.85"))

            # D. OANDA EUR_USD entry
            eur_quote = QuoteSnapshot(
                symbol="EUR_USD",
                bid=Decimal("1.08500"),
                ask=Decimal("1.08512"),
                timestamp_utc=self.calm_time,
            )
            eur_prop = _make_admissible_proposal(
                symbol="EUR_USD",
                side=Side.BUY,
                quantity_units=Decimal("10000"),
                quote=eur_quote,
                account=acct_5k,
                now_utc=self.calm_time,
                sl_distance=Decimal("0.00150"),
                tp_distance=Decimal("0.00350"),
                req_suffix="eurusd",
            )
            for oanda_broker in ("OANDA", "OANDA_PRACTICE", "OANDA_LIVE"):
                eur_dec = bridge.evaluate_pre_entry(
                    broker_id=oanda_broker,
                    symbol="EUR_USD",
                    side="BUY",
                    equity_usd=Decimal("5000.00"),
                    stop_distance_points=Decimal("15.0"),
                    risk_pct=Decimal("0.85"),
                    quote=eur_quote,
                    account_state=acct_5k,
                    proposal=eur_prop,
                    now_utc=self.calm_time,
                )
                self.assertTrue(eur_dec.allowed, f"Expected admission for {oanda_broker}")
                self.assertEqual(eur_dec.broker_id, oanda_broker)
                self.assertEqual(eur_dec.symbol, "EURUSD")
                self.assertEqual(eur_dec.risk_budget_usd, Decimal("42.50"))
                # $42.50 / (15 pips * $10/pip/lot) = 0.2833 -> ROUND_FLOOR 0.28 lots
                self.assertEqual(eur_dec.execution_plan.planned_lots, Decimal("0.28"))

    # 3. Red-flag CPI blocks OPEN_NEW & ADD_POSITION while protective actions finish < 50ms
    def test_red_flag_cpi_blocks_entries_while_protective_actions_succeed_under_50ms(self) -> None:
        bridge, _, bus, _, _, _ = self._build_stack(name="cpi_shock")
        critical_events: list[ExecutionEvent] = []
        slow_calls: list[str] = []

        def _critical_handler(ev: ExecutionEvent) -> None:
            critical_events.append(ev)

        def _slow_ledger_subscriber(ev: ExecutionEvent) -> None:
            slow_calls.append(ev.event_id)
            time.sleep(0.40)

        def _failing_ledger_subscriber(ev: ExecutionEvent) -> None:
            raise RuntimeError(f"Simulated LEDGER_ASYNC failure on {ev.event_id}")

        with bridge:
            bus.subscribe(
                _critical_handler,
                lane=SubscriberLane.CRITICAL_PROTECTION,
                name="critical-stop-manager",
            )
            bus.subscribe(
                _slow_ledger_subscriber,
                lane=SubscriberLane.LEDGER_ASYNC,
                name="slow-400ms-ledger",
            )
            bus.subscribe(
                _failing_ledger_subscriber,
                lane=SubscriberLane.LEDGER_ASYNC,
                name="raising-ledger",
            )

            nas_quote = QuoteSnapshot(
                symbol="NAS100",
                bid=Decimal("20500.00"),
                ask=Decimal("20501.20"),
                timestamp_utc=self.cpi_time,
            )
            acct = AccountMarginState(
                account_id="acct-cpi",
                balance=Decimal("5000.00"),
                equity=Decimal("5000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("5000.00"),
                peak_equity=Decimal("5000.00"),
            )
            prop = _make_admissible_proposal(
                symbol="NAS100",
                side=Side.BUY,
                quantity_units=Decimal("1.00"),
                quote=nas_quote,
                account=acct,
                now_utc=self.cpi_time,
                sl_distance=Decimal("25.00"),
                tp_distance=Decimal("60.00"),
                req_suffix="cpi",
            )

            expected_resume = self.cpi_time + timedelta(minutes=5)

            # OPEN_NEW blocked at exact CPI release timestamp
            open_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=nas_quote,
                account_state=acct,
                proposal=prop,
                open_pyramid_count=0,
                now_utc=self.cpi_time,
            )
            self.assertFalse(open_dec.allowed)
            self.assertEqual(open_dec.reason_code, "NEW_ENTRY_PAUSED_NEWS_WINDOW")
            self.assertEqual(open_dec.news_resume_at_utc, expected_resume)
            self.assertIsNone(open_dec.execution_plan)

            # ADD_POSITION (open_pyramid_count > 0) ALSO blocked during CPI window
            add_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=nas_quote,
                account_state=acct,
                proposal=prop,
                open_pyramid_count=1,
                now_utc=self.cpi_time,
            )
            self.assertFalse(add_dec.allowed)
            self.assertEqual(add_dec.reason_code, "NEW_ENTRY_PAUSED_NEWS_WINDOW")
            self.assertEqual(add_dec.news_resume_at_utc, expected_resume)

            # ALL 5 protective actions MUST succeed in < 50ms even at the EXACT second of CPI
            # while the 400ms-sleeping + raising LEDGER_ASYNC subscribers are attached!
            protective_actions = (
                TradeActionType.AMEND_STOP,
                TradeActionType.MOVE_BREAKEVEN,
                TradeActionType.TRAIL_STOP,
                TradeActionType.CLOSE_POSITION,
                TradeActionType.EMERGENCY_CLOSE_ALL,
            )
            for idx, prot_action in enumerate(protective_actions):
                t0 = time.perf_counter()
                res = bridge.dispatch_protective_action(
                    broker_id="HUGOSWAY_MT5",
                    symbol="NAS100",
                    action=prot_action,
                    order_id=f"ord-cpi-{idx}",
                    position_ticket=f"tkt-cpi-{idx}",
                    side="BUY",
                    quantity_lots=Decimal("0.50"),
                    price=Decimal("20500.00"),
                    stop_loss=Decimal("20501.50"),
                    take_profit=Decimal("20560.00"),
                    reason=f"CPI protection {prot_action.value}",
                    now_utc=self.cpi_time,
                )
                wall_ms = (time.perf_counter() - t0) * 1000.0
                self.assertIsInstance(res, ProtectiveActionResult)
                self.assertTrue(res.allowed)
                self.assertEqual(res.news_shield_reason, "PROTECTIVE_ACTION_ALWAYS_ALLOWED")
                self.assertTrue(res.is_new_event)
                self.assertLess(
                    res.elapsed_ms,
                    Decimal("50.000"),
                    f"{prot_action.value} took {res.elapsed_ms}ms (>= 50ms)",
                )
                self.assertLess(
                    wall_ms,
                    50.0,
                    f"{prot_action.value} wall-clock took {wall_ms:.2f}ms (>= 50ms)",
                )

            # All 5 protective actions reached CRITICAL_PROTECTION synchronously
            self.assertEqual(len(critical_events), 5)
            # Clean shutdown without draining the deliberate 5 * 400ms slow sleep
            bridge.close(timeout=2.0, drain=False)

    # 4. Wide spread, inadmissible valve, risk > 1.00%, drawdown >= 10.00%, pyramid cap
    def test_refusal_gates_spread_valve_risk_drawdown_and_pyramid_cap(self) -> None:
        bridge, _, _, _, _, _ = self._build_stack(name="refusal_gates")
        with bridge:
            acct = AccountMarginState(
                account_id="acct-refuse",
                balance=Decimal("5000.00"),
                equity=Decimal("5000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("5000.00"),
                peak_equity=Decimal("5000.00"),
            )
            good_quote = QuoteSnapshot(
                symbol="NAS100",
                bid=Decimal("20500.00"),
                ask=Decimal("20501.20"),
                timestamp_utc=self.calm_time,
            )
            wide_quote = QuoteSnapshot(
                symbol="NAS100",
                bid=Decimal("20500.00"),
                ask=Decimal("20525.00"),  # 25 pts spread >> 6.0 max
                timestamp_utc=self.calm_time,
            )
            good_prop = _make_admissible_proposal(
                symbol="NAS100",
                side=Side.BUY,
                quantity_units=Decimal("1.00"),
                quote=good_quote,
                account=acct,
                now_utc=self.calm_time,
                sl_distance=Decimal("25.00"),
                tp_distance=Decimal("60.00"),
                req_suffix="good",
            )

            # A. Wide spread refused cleanly
            wide_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=wide_quote,
                account_state=acct,
                proposal=good_prop,
                now_utc=self.calm_time,
            )
            self.assertFalse(wide_dec.allowed)
            self.assertEqual(wide_dec.reason_code, RefusalReason.SPREAD_GUARD_EXCEEDED.value)
            self.assertIsNone(wide_dec.execution_plan)

            # B. Real ForexMetaValveGate refusal (stale state proposal)
            stale_prop = _make_admissible_proposal(
                symbol="NAS100",
                side=Side.BUY,
                quantity_units=Decimal("1.00"),
                quote=good_quote,
                account=acct,
                now_utc=self.calm_time,
                sl_distance=Decimal("25.00"),
                tp_distance=Decimal("60.00"),
                stale_seconds=600,
                req_suffix="stale",
            )
            stale_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=good_quote,
                account_state=acct,
                proposal=stale_prop,
                now_utc=self.calm_time,
            )
            self.assertFalse(stale_dec.allowed)
            self.assertEqual(stale_dec.reason_code, RefusalReason.VALVE_REFUSAL.value)
            self.assertIsNone(stale_dec.execution_plan)

            # C. Constitutional risk_pct > 1.00% refused fail-closed
            over_risk_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("1.01"),
                quote=good_quote,
                account_state=acct,
                proposal=good_prop,
                now_utc=self.calm_time,
            )
            self.assertFalse(over_risk_dec.allowed)
            self.assertEqual(over_risk_dec.reason_code, "CONSTITUTIONAL_STOP_RISK_EXCEEDED")
            self.assertEqual(over_risk_dec.risk_budget_usd, Decimal("0.00"))
            self.assertIsNone(over_risk_dec.execution_plan)

            # D. Constitutional drawdown >= 10.00% refused fail-closed
            for dd in (Decimal("0.10"), Decimal("0.125")):
                dd_dec = bridge.evaluate_pre_entry(
                    broker_id="LHFX_MT5",
                    symbol="NAS100",
                    side="BUY",
                    equity_usd=Decimal("5000.00"),
                    stop_distance_points=Decimal("25.00"),
                    risk_pct=Decimal("0.85"),
                    quote=good_quote,
                    account_state=acct,
                    proposal=good_prop,
                    drawdown_pct=dd,
                    now_utc=self.calm_time,
                )
                self.assertFalse(dd_dec.allowed)
                self.assertEqual(dd_dec.reason_code, "CONSTITUTIONAL_DRAWDOWN_LIMIT_REACHED")
                self.assertIsNone(dd_dec.execution_plan)

            # E. Pyramid slot cap & exhausted daily loss refused
            pyr_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=good_quote,
                account_state=acct,
                proposal=good_prop,
                open_pyramid_count=3,
                max_open_trades=3,
                now_utc=self.calm_time,
            )
            self.assertFalse(pyr_dec.allowed)
            self.assertEqual(pyr_dec.reason_code, "MAX_PYRAMID_SLOTS_REACHED")

            daily_dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=good_quote,
                account_state=acct,
                proposal=good_prop,
                daily_loss_remaining_usd=Decimal("0.00"),
                now_utc=self.calm_time,
            )
            self.assertFalse(daily_dec.allowed)
            self.assertEqual(daily_dec.reason_code, "DAILY_LOSS_BUDGET_EXHAUSTED")

        # F. Low-score (< 0.55) valve refusal verified cleanly
        low_bridge, _, _, _, _, _ = self._build_stack(
            name="low_valve",
            valve_gate=_LowScoreValveGate(),
        )
        with low_bridge:
            low_dec = low_bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("0.85"),
                quote=good_quote,
                account_state=acct,
                proposal=good_prop,
                now_utc=self.calm_time,
            )
            self.assertFalse(low_dec.allowed)
            self.assertEqual(low_dec.reason_code, RefusalReason.VALVE_REFUSAL.value)
            self.assertEqual(low_dec.valve_score, 0.41)
            self.assertIsNone(low_dec.execution_plan)

    # 5. $5,000 -> $10,000 realized fill progression triggers HOUSE_MONEY_READY_TO_PULL_PRINCIPAL
    def test_5k_to_10k_realized_fill_progression_triggers_house_money_ready(self) -> None:
        bridge, ledger, _, comp, _, _ = self._build_stack(
            name="house_money_5k_10k",
            principal_usd=Decimal("5000.00"),
            initial_equity_usd=Decimal("5000.00"),
        )
        with bridge:
            # Opening FILL ($0 realized) -> still building/at principal
            r_open = bridge.record_broker_fill_or_close(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                event_type=ExecutionEventType.FILL,
                event_id="evt-open-001",
                order_id="ord-001",
                position_ticket="tkt-001",
                side="BUY",
                quantity_lots=Decimal("1.50"),
                price=Decimal("20500.00"),
                realized_pnl_usd=Decimal("0.00"),
                now_utc=self.calm_time,
            )
            self.assertTrue(r_open["accepted"])
            self.assertTrue(r_open["is_new_event"])
            self.assertEqual(r_open["ledger_dispatch_lane"], SubscriberLane.LEDGER_ASYNC.value)
            self.assertFalse(r_open["house_money_ready"])

            # Close 1: HUGOSWAY_MT5 NAS100 +$2,000.00 -> $7,000.00 (COMPOUNDING_TO_DOUBLE)
            r1 = bridge.record_broker_fill_or_close(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                event_type=ExecutionEventType.TP_HIT,
                event_id="evt-tp-001",
                order_id="ord-001",
                position_ticket="tkt-001",
                side="BUY",
                quantity_lots=Decimal("1.50"),
                price=Decimal("20580.00"),
                realized_pnl_usd=Decimal("2000.00"),
                current_equity_usd=Decimal("7000.00"),
                now_utc=self.calm_time + timedelta(minutes=10),
            )
            self.assertTrue(r1["is_new_event"])
            self.assertEqual(r1["house_money_status"], STATUS_COMPOUNDING_TO_DOUBLE)
            self.assertFalse(r1["house_money_ready"])

            # Duplicate event_id replay is strictly idempotent (is_new_event=False)
            r1_dup = bridge.record_broker_fill_or_close(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                event_type=ExecutionEventType.TP_HIT,
                event_id="evt-tp-001",
                order_id="ord-001",
                position_ticket="tkt-001",
                side="BUY",
                quantity_lots=Decimal("1.50"),
                price=Decimal("20580.00"),
                realized_pnl_usd=Decimal("2000.00"),
                current_equity_usd=Decimal("7000.00"),
                now_utc=self.calm_time + timedelta(minutes=10),
            )
            self.assertFalse(r1_dup["is_new_event"])
            self.assertEqual(r1_dup["seq_id"], r1["seq_id"])

            # Close 2: LHFX_MT5 US30 +$1,500.00 -> $8,500.00
            r2 = bridge.record_broker_fill_or_close(
                broker_id="LHFX_MT5",
                symbol="US30",
                event_type=ExecutionEventType.TP_HIT,
                event_id="evt-tp-002",
                order_id="ord-002",
                position_ticket="tkt-002",
                side="SELL",
                quantity_lots=Decimal("1.00"),
                price=Decimal("43050.00"),
                realized_pnl_usd=Decimal("1500.00"),
                current_equity_usd=Decimal("8500.00"),
                now_utc=self.calm_time + timedelta(minutes=25),
            )
            self.assertTrue(r2["is_new_event"])
            self.assertEqual(r2["house_money_status"], STATUS_COMPOUNDING_TO_DOUBLE)
            self.assertFalse(r2["house_money_ready"])

            # Close 3: OANDA EUR_USD +$1,500.00 -> $10,000.00 (HOUSE_MONEY_READY_TO_PULL_PRINCIPAL!)
            self.assertTrue(bridge.flush(timeout=5.0))
            r3 = bridge.record_broker_fill_or_close(
                broker_id="OANDA",
                symbol="EUR_USD",
                event_type=ExecutionEventType.TP_HIT,
                event_id="evt-tp-003",
                order_id="ord-003",
                position_ticket="tkt-003",
                side="BUY",
                quantity_lots=Decimal("0.50"),
                price=Decimal("1.09100"),
                realized_pnl_usd=Decimal("1500.00"),
                now_utc=self.calm_time + timedelta(minutes=40),
            )
            self.assertTrue(r3["is_new_event"])
            self.assertEqual(r3["evaluated_equity_usd"], "10000.00")
            self.assertEqual(r3["house_money_status"], STATUS_HOUSE_MONEY_READY)
            self.assertTrue(r3["house_money_ready"])
            self.assertEqual(r3["suggested_principal_pullout_usd"], "5000.00")

            # Flush LEDGER_ASYNC and confirm UnifiedRealTimeLedger persisted exact $10,000.00
            self.assertTrue(bridge.flush(timeout=5.0))
            ledger_snap = ledger.snapshot(now_utc=self.calm_time + timedelta(minutes=45))
            self.assertEqual(ledger_snap.effective_equity_usd, Decimal("10000.00"))
            self.assertEqual(ledger_snap.lifetime_realized_pnl_usd, Decimal("5000.00"))
            self.assertEqual(len(ledger.list_trades()), 3)
            self.assertTrue(ledger.verify_audit_chain())
            self.assertIsNotNone(comp)
            self.assertTrue(comp.verify_audit_chain())

    # 6. Strictly 0-write bridge_snapshot() across midnight UTC rollover
    def test_bridge_snapshot_zero_writes_across_midnight_utc_rollover(self) -> None:
        bridge, _, _, _, ledger_db, comp_db = self._build_stack(
            name="zero_write_rollover",
            principal_usd=Decimal("5000.00"),
            initial_equity_usd=Decimal("5000.00"),
        )
        day1_late = _utc(2026, 11, 20, 23, 55, 0)
        day2_early = _utc(2026, 11, 21, 0, 5, 0)

        with bridge:
            bridge.record_broker_fill_or_close(
                broker_id="HUGOSWAY_MT5",
                symbol="NAS100",
                event_type=ExecutionEventType.TP_HIT,
                event_id="evt-rollover-001",
                order_id="ord-roll-001",
                position_ticket="tkt-roll-001",
                side="BUY",
                quantity_lots=Decimal("1.00"),
                price=Decimal("20550.00"),
                realized_pnl_usd=Decimal("750.00"),
                now_utc=day1_late,
            )
            self.assertTrue(bridge.flush(timeout=5.0))

            ledger_ver_before, ledger_counts_before = _sqlite_data_version_and_counts(ledger_db)
            comp_ver_before, comp_counts_before = _sqlite_data_version_and_counts(comp_db)

            snap = bridge.bridge_snapshot(
                symbols=("NAS100", "US30", "XAUUSD", "EUR_USD"),
                now_utc=day2_early,
            )

            ledger_ver_after, ledger_counts_after = _sqlite_data_version_and_counts(ledger_db)
            comp_ver_after, comp_counts_after = _sqlite_data_version_and_counts(comp_db)

            self.assertEqual(ledger_ver_before, ledger_ver_after)
            self.assertEqual(ledger_counts_before, ledger_counts_after)
            self.assertEqual(comp_ver_before, comp_ver_after)
            self.assertEqual(comp_counts_before, comp_counts_after)

            self.assertEqual(snap["schema"], BRIDGE_SNAPSHOT_SCHEMA)
            self.assertEqual(snap["supported_brokers"], sorted(SUPPORTED_BROKERS))
            self.assertEqual(snap["ledger"]["session_date"], "2026-11-21")
            self.assertEqual(Decimal(snap["ledger"]["effective_equity_usd"]), Decimal("5750.00"))
            self.assertEqual(snap["compounding"]["schema"], COMPOUNDING_CONTROLLER_SCHEMA)
            self.assertEqual(snap["compounding"]["current_equity_usd"], "5750.00")
            self.assertEqual(snap["compounding"]["house_money_status"], STATUS_COMPOUNDING_TO_DOUBLE)
            self.assertIn("news_shield", snap)
            self.assertIn("event_bus", snap)
            self.assertGreaterEqual(snap["event_bus"]["published_count"], 1)

    # 7. Clean thread shutdown (0 leaked threads) & source hygiene (0 assert, 0 float, 0 CRLF, 0 BOM)
    def test_clean_thread_shutdown_and_source_hygiene(self) -> None:
        baseline_threads = {t.ident for t in threading.enumerate() if t.is_alive()}

        bridge, _, _, _, _, _ = self._build_stack(name="thread_hygiene")
        with bridge:
            bridge.record_broker_fill_or_close(
                broker_id="OANDA_PRACTICE",
                symbol="EUR_USD",
                event_type=ExecutionEventType.FILL,
                event_id="evt-thread-001",
                order_id="ord-th-001",
                position_ticket="tkt-th-001",
                side="BUY",
                quantity_lots=Decimal("0.10"),
                price=Decimal("1.08510"),
                realized_pnl_usd=Decimal("0.00"),
                now_utc=self.calm_time,
            )
            self.assertTrue(bridge.flush(timeout=5.0))

        # Idempotent close & zero leaked threads
        self.assertTrue(bridge.close(timeout=2.0, drain=True))
        after_threads = {t.ident for t in threading.enumerate() if t.is_alive()}
        leaked = after_threads - baseline_threads
        self.assertEqual(leaked, set(), f"Leaked background threads: {leaked}")

        # Source hygiene on src/cas_forex_revamp/composition/phase8_live_bridge.py
        repo_root = Path(__file__).resolve().parents[2]
        bridge_src = repo_root / "src" / "cas_forex_revamp" / "composition" / "phase8_live_bridge.py"
        raw = bridge_src.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM detected")
        self.assertNotIn(b"\r", raw, "CR/CRLF line endings detected in source")
        tree = ast.parse(raw.decode("utf-8"))
        asserts = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        float_calls = [
            n.lineno
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "float"
        ]
        self.assertEqual(asserts, [], f"Bandit B101 assert statements found at lines {asserts}")
        self.assertEqual(float_calls, [], f"float() calls found at lines {float_calls}")

    # 8. XAUUSD entry and standalone mode (compounding_controller=None) still enforce ceilings
    def test_xauusd_and_standalone_bridge_without_compounding_controller(self) -> None:
        bridge, _, _, comp, ledger_db, _ = self._build_stack(
            name="standalone_xau",
            attach_compounding=False,
        )
        self.assertIsNone(comp)
        with bridge:
            acct = AccountMarginState(
                account_id="acct-xau-5k",
                balance=Decimal("5000.00"),
                equity=Decimal("5000.00"),
                used_margin=Decimal("0.00"),
                free_margin=Decimal("5000.00"),
                peak_equity=Decimal("5000.00"),
            )
            xau_quote = QuoteSnapshot(
                symbol="XAUUSD",
                bid=Decimal("2650.00"),
                ask=Decimal("2650.35"),
                timestamp_utc=self.calm_time,
            )
            xau_prop = _make_admissible_proposal(
                symbol="XAUUSD",
                side=Side.BUY,
                quantity_units=Decimal("8.00"),
                quote=xau_quote,
                account=acct,
                now_utc=self.calm_time,
                sl_distance=Decimal("5.00"),
                tp_distance=Decimal("15.00"),
                req_suffix="xau5k",
            )
            dec = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="XAUUSD",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("5.00"),
                risk_pct=Decimal("0.85"),
                quote=xau_quote,
                account_state=acct,
                proposal=xau_prop,
                now_utc=self.calm_time,
            )
            self.assertTrue(dec.allowed)
            self.assertEqual(dec.symbol, "XAUUSD")
            self.assertEqual(dec.risk_budget_usd, Decimal("42.50"))
            # $42.50 / (5 pts * $100/lot/pt) = 0.085 -> ROUND_FLOOR 0.08 lots
            self.assertEqual(dec.execution_plan.planned_lots, Decimal("0.08"))
            self.assertIsNone(dec.house_money_status)

            # Constitutional >1.00% risk still refused fail-closed even without compounding controller
            bad_risk = bridge.evaluate_pre_entry(
                broker_id="HUGOSWAY_MT5",
                symbol="XAUUSD",
                side="BUY",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("5.00"),
                risk_pct=Decimal("1.05"),
                quote=xau_quote,
                account_state=acct,
                proposal=xau_prop,
                now_utc=self.calm_time,
            )
            self.assertFalse(bad_risk.allowed)
            self.assertEqual(bad_risk.reason_code, "CONSTITUTIONAL_STOP_RISK_EXCEEDED")

            ver_before, counts_before = _sqlite_data_version_and_counts(ledger_db)
            snap = bridge.bridge_snapshot(symbols=("XAUUSD",), now_utc=self.calm_time)
            ver_after, counts_after = _sqlite_data_version_and_counts(ledger_db)
            self.assertEqual(ver_before, ver_after)
            self.assertEqual(counts_before, counts_after)
            self.assertIsNone(snap["compounding"])

    # 9. Constitutional 1,000% minimum margin level enforced with and without compounding
    def test_constitutional_1000pct_margin_level_enforced_with_and_without_compounding(self) -> None:
        self.assertEqual(MIN_MARGIN_LEVEL_PCT, Decimal("1000.0"))
        nas_quote = QuoteSnapshot(
            symbol="NAS100",
            bid=Decimal("20500.00"),
            ask=Decimal("20501.25"),
            timestamp_utc=self.calm_time,
        )
        # 5000 / 600 = 833.33% < 1000.0% -> MUST REFUSE
        breached_acct = AccountMarginState(
            account_id="acct-margin-breach",
            balance=Decimal("5000.00"),
            equity=Decimal("5000.00"),
            used_margin=Decimal("600.00"),
            free_margin=Decimal("4400.00"),
            peak_equity=Decimal("5000.00"),
        )
        # 5000 / 500 = 1000.0% >= 1000.0% -> MUST ADMIT
        exact_floor_acct = AccountMarginState(
            account_id="acct-margin-floor",
            balance=Decimal("5000.00"),
            equity=Decimal("5000.00"),
            used_margin=Decimal("500.00"),
            free_margin=Decimal("4500.00"),
            peak_equity=Decimal("5000.00"),
        )

        for attach in (True, False):
            bridge, _, _, _, _, _ = self._build_stack(
                name=f"margin_floor_{attach}",
                attach_compounding=attach,
            )
            with bridge:
                prop_breach = _make_admissible_proposal(
                    symbol="NAS100",
                    side=Side.BUY,
                    quantity_units=Decimal("1.00"),
                    quote=nas_quote,
                    account=breached_acct,
                    now_utc=self.calm_time,
                    sl_distance=Decimal("25.00"),
                    tp_distance=Decimal("60.00"),
                    req_suffix=f"mbreach{int(attach)}",
                )
                dec_breach = bridge.evaluate_pre_entry(
                    broker_id="HUGOSWAY_MT5",
                    symbol="NAS100",
                    side="BUY",
                    equity_usd=Decimal("5000.00"),
                    stop_distance_points=Decimal("25.00"),
                    risk_pct=Decimal("0.85"),
                    quote=nas_quote,
                    account_state=breached_acct,
                    proposal=prop_breach,
                    now_utc=self.calm_time,
                )
                self.assertFalse(dec_breach.allowed)
                self.assertEqual(dec_breach.reason_code, "CONSTITUTIONAL_MARGIN_LEVEL_BREACH")
                self.assertEqual(dec_breach.risk_budget_usd, Decimal("0.00"))
                self.assertIsNone(dec_breach.execution_plan)

                # Exact 1,000.0% margin floor passes cleanly
                prop_floor = _make_admissible_proposal(
                    symbol="NAS100",
                    side=Side.BUY,
                    quantity_units=Decimal("1.00"),
                    quote=nas_quote,
                    account=exact_floor_acct,
                    now_utc=self.calm_time,
                    sl_distance=Decimal("25.00"),
                    tp_distance=Decimal("60.00"),
                    req_suffix=f"mfloor{int(attach)}",
                )
                dec_floor = bridge.evaluate_pre_entry(
                    broker_id="HUGOSWAY_MT5",
                    symbol="NAS100",
                    side="BUY",
                    equity_usd=Decimal("5000.00"),
                    stop_distance_points=Decimal("25.00"),
                    risk_pct=Decimal("0.85"),
                    quote=nas_quote,
                    account_state=exact_floor_acct,
                    proposal=prop_floor,
                    now_utc=self.calm_time,
                )
                self.assertTrue(dec_floor.allowed)
                self.assertEqual(dec_floor.reason_code, "ENTRY_ADMITTED")
                self.assertEqual(dec_floor.risk_budget_usd, Decimal("42.50"))
                self.assertIsNotNone(dec_floor.execution_plan)

                # Mapping account_state: explicit margin_level_pct < 1000.0 and derived used_margin
                for bad_map in (
                    {
                        "account_id": "acct-map-1",
                        "balance": "5000.00",
                        "equity": "5000.00",
                        "free_margin": "4400.00",
                        "position_inventory": [],
                        "margin_level_pct": Decimal("999.9"),
                    },
                    {
                        "account_id": "acct-map-2",
                        "balance": "5000.00",
                        "equity": "5000.00",
                        "used_margin": Decimal("600.00"),
                        "free_margin": "4400.00",
                        "position_inventory": [],
                    },
                ):
                    dec_map = bridge.evaluate_pre_entry(
                        broker_id="HUGOSWAY_MT5",
                        symbol="NAS100",
                        side="BUY",
                        equity_usd=Decimal("5000.00"),
                        stop_distance_points=Decimal("25.00"),
                        risk_pct=Decimal("0.85"),
                        quote=nas_quote,
                        account_state=bad_map,
                        proposal=prop_breach,
                        now_utc=self.calm_time,
                    )
                    self.assertFalse(dec_map.allowed)
                    self.assertEqual(dec_map.reason_code, "CONSTITUTIONAL_MARGIN_LEVEL_BREACH")

                # Negative used_margin fails closed with Phase8BridgeError
                with self.assertRaises(Phase8BridgeError):
                    bridge.evaluate_pre_entry(
                        broker_id="HUGOSWAY_MT5",
                        symbol="NAS100",
                        side="BUY",
                        equity_usd=Decimal("5000.00"),
                        stop_distance_points=Decimal("25.00"),
                        risk_pct=Decimal("0.85"),
                        quote=nas_quote,
                        account_state={
                            "account_id": "acct-neg",
                            "balance": "5000.00",
                            "equity": "5000.00",
                            "used_margin": Decimal("-10.00"),
                            "free_margin": "5000.00",
                            "position_inventory": [],
                        },
                        proposal=prop_breach,
                        now_utc=self.calm_time,
                    )


if __name__ == "__main__":
    unittest.main()
