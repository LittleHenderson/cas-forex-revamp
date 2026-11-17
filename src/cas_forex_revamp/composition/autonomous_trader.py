"""Continuous dual-cadence Autonomous AI Trader coordinator behind ForexMetaValveGate.

Removes fragile, emotional human decision-making from execution:
- Evaluates 18 markets (NAS100, US30 + 16 FX pairs) with resting broker SL + TP.
- Supports 50ms direct MT5 fast-tick burst scalping for NAS100/US30 while blocking slow
  15s public-fallback micro-scalps and wide-spread setups.
- Automatically snaps SL to breakeven and trails SL strictly monotonically in profit.
- Optionally uses Gemini Decision 1 (150-250ms) as a Fast Scout before waking heavier models.
- Gates EVERY AI proposal through ActualModelDecisionAdapter -> ForexMetaValveGate ->
  PeakEquityStore -> DailyQuotaGovernanceStore ($500-$1,000 quota lock & loss circuit) ->
  BarbellCapitalPolicy -> DualShieldBrokerRouter.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal, localcontext
from hashlib import sha256
import json
import logging
from pathlib import Path
import sqlite3
from threading import RLock
import time
from typing import Any, Callable, Mapping

from cas_forex_revamp.contracts import (
    ActionIntent,
    ActionKind,
    ActionOption,
    ContractError,
    DecisionFact,
    DecisionOrigin,
    DecisionRequest,
    Environment,
    EvidenceKind,
    EvidenceReference,
    InferenceBudget,
    RunScope,
    Side,
    StateReference,
    canonical_bytes,
    content_digest,
    decimal_text,
)
from cas_forex_revamp.contracts.primitives import decimal_value, utc_time
from cas_forex_revamp.operator.frontier_backends import (
    FrontierModelRegistry,
    FrontierTransportError,
    assert_safe_ai_catalog_payload,
)
from cas_forex_revamp.operator.model import ActualModelDecisionAdapter, ModelInvocation
from cas_forex_revamp.valve.daily_quota import (
    DailyQuotaGovernanceStore,
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_LOSS_TRIPPED,
    QUOTA_STATUS_SOFT,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    PeakEquityStore,
    ValveDecision,
    ValveRefusalError,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.live_market_stream import EXPANDED_MARKETS, INDEX_INSTRUMENTS
from cas_forex_revamp.venue.mt5_broker_bridge import (
    MT5_MIN_VOLUME,
    MT5_VOLUME_STEP,
    Mt5PaperBrokerVenue,
    OandaPracticeFallbackVenue,
    OrderIntent,
)

logger = logging.getLogger(__name__)

GOVERNANCE_ACTIVE = "ACTIVE"
GOVERNANCE_PAUSED_NEW_RISK = "PAUSED_NEW_RISK"
GOVERNANCE_STOPPED = "STOPPED"
GOVERNANCE_MODES = (GOVERNANCE_ACTIVE, GOVERNANCE_PAUSED_NEW_RISK, GOVERNANCE_STOPPED)

FEED_MT5_FAST_SPOOL = "MT5_DIRECT_SPOOL_50MS"
FEED_PUBLIC_FALLBACK = "PUBLIC_15S_FALLBACK"
GENESIS_SHA256 = "0" * 64


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def _tick_size(symbol: str) -> Decimal:
    if symbol in INDEX_INSTRUMENTS:
        return Decimal("0.01")
    if symbol.endswith("JPY"):
        return Decimal("0.001")
    return Decimal("0.00001")


def _point_unit(symbol: str) -> Decimal:
    if symbol in INDEX_INSTRUMENTS:
        return Decimal("1.00")
    if symbol.endswith("JPY"):
        return Decimal("0.01")
    return Decimal("0.0001")


def _default_protection_params(symbol: str, risk_multiplier: Decimal) -> dict[str, Decimal]:
    if symbol == "NAS100":
        be_trig, be_off = Decimal("10.00"), Decimal("1.50")
        trail_act, trail_dist = Decimal("20.00"), Decimal("12.00")
        sl_dist, tp_dist = Decimal("25.00"), Decimal("60.00")
    elif symbol == "US30":
        be_trig, be_off = Decimal("20.00"), Decimal("3.00")
        trail_act, trail_dist = Decimal("40.00"), Decimal("24.00")
        sl_dist, tp_dist = Decimal("50.00"), Decimal("120.00")
    else:
        pt = _point_unit(symbol)
        be_trig, be_off = pt * Decimal("8"), pt * Decimal("1")
        trail_act, trail_dist = pt * Decimal("15"), pt * Decimal("10")
        sl_dist, tp_dist = pt * Decimal("25"), pt * Decimal("55")
    if risk_multiplier < Decimal("1") and risk_multiplier > Decimal("0"):
        trail_dist = max(_tick_size(symbol), (trail_dist * Decimal("0.60")).quantize(_tick_size(symbol), rounding=ROUND_HALF_UP))
    return {
        "be_trigger": be_trig,
        "be_offset": be_off,
        "trail_activation": trail_act,
        "trail_distance": trail_dist,
        "sl_distance": sl_dist,
        "tp_distance": tp_dist,
    }


def _compute_ema(values: list[Decimal], period: int) -> Decimal | None:
    if len(values) < period:
        return None
    k = Decimal("2") / Decimal(period + 1)
    one_minus_k = Decimal("1") - k
    ema = values[0]
    for v in values[1:]:
        ema = v * k + ema * one_minus_k
    return ema


class AutonomousAiTrader:
    """Dual-cadence Valve-gated autonomous trading engine with Human-as-Overseer governance."""

    def __init__(
        self,
        *,
        router: DualShieldBrokerRouter,
        model_registry: FrontierModelRegistry,
        valve_gate: ForexMetaValveGate,
        quota_store: DailyQuotaGovernanceStore | None = None,
        peak_equity_store: PeakEquityStore | None = None,
        scope: RunScope | None = None,
        journal_path: str | Path | None = None,
        owner_verifier: Any | None = None,
        fast_tick_ms: int = 50,
        clock: Callable[[], datetime] | None = None,
        execution_gate: Callable[[ModelInvocation], None] | None = None,
        protection_overrides: Mapping[str, Mapping[str, Decimal]] | None = None,
    ) -> None:
        if not isinstance(router, DualShieldBrokerRouter):
            raise ContractError("AutonomousAiTrader requires a DualShieldBrokerRouter")
        if not isinstance(model_registry, FrontierModelRegistry):
            raise ContractError("AutonomousAiTrader requires a FrontierModelRegistry")
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("AutonomousAiTrader requires a ForexMetaValveGate")
        if type(fast_tick_ms) is not int or not (0 <= fast_tick_ms <= 5000):
            raise ContractError("fast_tick_ms must be an integer in 0..5000")

        self._router = router
        self._registry = model_registry
        self._valve_gate = valve_gate
        self._quota = quota_store or DailyQuotaGovernanceStore()
        self._peak_store = peak_equity_store or valve_gate.peak_equity_store
        self._owner_verifier = owner_verifier
        self._fast_tick_ms = fast_tick_ms
        self._clock = clock or _utc_now
        self._execution_gate = execution_gate or (lambda _inv: None)
        self._journal_path = Path(journal_path) if journal_path is not None else None
        self._scope = scope or RunScope(
            account_id="dual-shield-barbell",
            run_id="auto-ai-session",
            epoch=1,
            build_id="phase6-autonomous-ai-v1",
            policy_id="barbell-1pct-valve-v1",
            scenario_id="live-market-loop",
            adapter_id="autonomous-ai-trader",
        )
        self._protection_overrides = {str(k): dict(v) for k, v in (protection_overrides or {}).items()}
        self._lock = RLock()
        self._governance_mode = GOVERNANCE_ACTIVE
        self._governance_reason = "Autonomous AI loop initialized under ForexMetaValveGate."
        self._cycle_seq = 0
        self._venue_seq = 1
        self._veto_count = 0
        self._last_cycle_ms = 0
        self._last_cadence = f"{fast_tick_ms}ms_FAST_TICK" if fast_tick_ms > 0 else "STANDARD"
        self._last_reason = "Awaiting market cycle evaluation."
        self._last_action = "WAIT"
        self._last_symbol: str | None = None
        self._last_valve_score: str | None = None
        self._last_scout: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._tick_history: dict[str, deque[tuple[Decimal, Decimal]]] = {
            sym: deque(maxlen=64) for sym in EXPANDED_MARKETS
        }
        self._peak_favorable: dict[str, Decimal] = {}
        self._protection_stage: dict[str, str] = {}
        self._open_position_meta: dict[str, dict[str, Any]] = {}
        self._recent_actions: deque[dict[str, Any]] = deque(maxlen=12)
        self._journal_initialized = False

    def _connect_journal(self) -> sqlite3.Connection | None:
        if self._journal_path is None:
            return None
        self._journal_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._journal_path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if not self._journal_initialized:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_trader_cycles (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    cycle_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    symbol TEXT,
                    valve_score TEXT,
                    payload_json TEXT NOT NULL,
                    prev_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL
                )
                """
            )
            self._journal_initialized = True
        return conn

    def _append_journal_cycle(self, report: Mapping[str, Any]) -> None:
        conn = self._connect_journal()
        if conn is None:
            return
        try:
            conn.execute("BEGIN IMMEDIATE")
            prev = conn.execute("SELECT record_sha256 FROM ai_trader_cycles ORDER BY seq DESC LIMIT 1").fetchone()
            prev_sha = str(prev[0]) if prev is not None else GENESIS_SHA256
            payload_str = canonical_bytes(dict(report)).decode("utf-8")
            rec_sha = sha256(
                canonical_bytes({"prev": prev_sha, "payload": payload_str})
            ).hexdigest()
            conn.execute(
                """
                INSERT INTO ai_trader_cycles (
                    cycle_id, observed_at, model_id, action, symbol, valve_score,
                    payload_json, prev_sha256, record_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(report["cycle_id"]),
                    str(report["observed_at"]),
                    str(report["model_id"]),
                    str(report["action"]),
                    report.get("symbol"),
                    report.get("valve_score"),
                    payload_str,
                    prev_sha,
                    rec_sha,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    @property
    def quota_store(self) -> DailyQuotaGovernanceStore:
        return self._quota

    @property
    def governance_mode(self) -> str:
        with self._lock:
            return self._governance_mode

    def _protection_cfg(self, symbol: str, risk_multiplier: Decimal) -> dict[str, Decimal]:
        cfg = _default_protection_params(symbol, risk_multiplier)
        if symbol in self._protection_overrides:
            for k, v in self._protection_overrides[symbol].items():
                if k in cfg:
                    cfg[k] = Decimal(v)
        return cfg

    def _make_valve_request_and_clear(
        self,
        *,
        intent: ActionIntent,
        strategy_id: str,
        timeframe: str,
        label: str,
        reason: str,
        bid: Decimal,
        ask: Decimal,
        total_eq: Decimal,
        peak_eq: Decimal,
        position_side: Side | None = None,
        now: datetime,
    ) -> ValveDecision:
        ev_id = f"ev-{self._cycle_seq}-{intent.instrument_id.lower()}"
        fact_payload: dict[str, Any] = {
            "new_risk": self._governance_mode == GOVERNANCE_ACTIVE,
            "management": self._governance_mode != GOVERNANCE_STOPPED,
            "equity": decimal_text(total_eq),
            "peak_equity": decimal_text(peak_eq),
            "bid": decimal_text(bid),
            "ask": decimal_text(ask),
        }
        if position_side is not None:
            fact_payload["position_side"] = position_side.value
        fact = DecisionFact(
            fact_id=f"observed-{self._cycle_seq}",
            label="Observed market and account state",
            value=canonical_bytes(fact_payload).decode("utf-8"),
            evidence_ids=(ev_id,),
        )
        ev = EvidenceReference(
            evidence_id=ev_id,
            kind=EvidenceKind.OBSERVATION,
            producer_id="autonomous-ai-trader",
            content_sha256=content_digest(fact_payload),
            observed_at=now,
        )
        option = ActionOption(intent.action_ref, strategy_id, timeframe, label, intent)
        req = DecisionRequest(
            request_id=f"auto-req-{self._cycle_seq}-{intent.action_ref}",
            opportunity_set_id=f"auto-set-{self._cycle_seq}",
            state=intent.source_state,
            options=(option,),
            facts=(fact,),
            evidence=(ev,),
        )
        # Lightweight proposal object bound to the exact AI / deterministic protection intent
        from cas_forex_revamp.contracts import DecisionProvenance, DecisionResult, DecisionSelection

        sel = DecisionSelection(
            request_id=req.request_id,
            opportunity_set_id=req.opportunity_set_id,
            source_state_id=req.state.state_id,
            selected_action_ref=intent.action_ref,
            reason=f"ID=0{intent.action_ref} {reason}"[:240],
            evidence_ids=(ev_id,),
        )
        res = DecisionResult(
            decision_id=f"auto-dec-{self._cycle_seq}-{intent.action_ref}",
            selection=sel,
            provenance=DecisionProvenance(
                origin=DecisionOrigin.OWNER_REVIEWED if intent.origin is DecisionOrigin.OWNER_REVIEWED else DecisionOrigin.ACTUAL_MODEL,
                adapter_id="autonomous-ai-trader",
                request_sha256=content_digest(req),
                response_sha256=content_digest(sel),
                prompt_version="frontier-v2",
                started_at=now,
                completed_at=now,
                model_id=None if intent.origin is DecisionOrigin.OWNER_REVIEWED else self._registry.active_entry.model_id,
                model_artifact_sha256=None if intent.origin is DecisionOrigin.OWNER_REVIEWED else self._registry.model_spec().artifact_sha256,
                inference_receipt_id=None if intent.origin is DecisionOrigin.OWNER_REVIEWED else f"auto-rcpt-{self._cycle_seq}",
            ),
        )

        class _ProposalBox:
            __slots__ = ("request", "result", "intent")

            def __init__(self, r: DecisionRequest, d: DecisionResult, i: ActionIntent) -> None:
                self.request = r
                self.result = d
                self.intent = i

        current_view = self._build_valve_view(
            total_eq=total_eq,
            peak_eq=peak_eq,
            new_risk_permission="ALLOWED" if self._governance_mode == GOVERNANCE_ACTIVE else "PAUSED",
            management_permission="STOPPED" if self._governance_mode == GOVERNANCE_STOPPED else "ALLOWED",
        )
        return self._valve_gate.require_admissible(
            _ProposalBox(req, res, intent), current_view=current_view, now=now
        )

    def _build_valve_view(
        self,
        *,
        total_eq: Decimal,
        peak_eq: Decimal,
        new_risk_permission: str,
        management_permission: str,
    ) -> dict[str, Any]:
        bal_sum = Decimal("0")
        free_sum = Decimal("0")
        inventory: list[dict[str, Any]] = []
        has_venue_acct = False
        for broker_id, venue in self._router.venues.items():
            if isinstance(venue, Mt5PaperBrokerVenue) and venue.account is not None:
                has_venue_acct = True
                bal_sum += venue.account.balance
                free_sum += venue.account.margin_free
                for pos in venue.positions:
                    inventory.append({
                        "broker_id": broker_id,
                        "ticket": pos.ticket,
                        "symbol": pos.symbol,
                        "side": pos.side.value,
                        "volume_lots": decimal_text(pos.volume_lots),
                    })
            elif isinstance(venue, OandaPracticeFallbackVenue):
                has_venue_acct = True
                bal_sum += venue.nav or Decimal("0")
                free_sum += venue.margin_available or Decimal("0")
        balance_val = bal_sum if has_venue_acct and bal_sum > Decimal("0") else total_eq
        margin_val = free_sum if has_venue_acct else total_eq
        return {
            "balance": decimal_text(balance_val),
            "equity": decimal_text(total_eq),
            "peak_equity": decimal_text(peak_eq),
            "available_margin": decimal_text(margin_val),
            "position_inventory": json.dumps(inventory, sort_keys=True),
            "scope_id": "dual-shield-barbell",
            "policy": {
                "new_risk_permission": new_risk_permission,
                "management_permission": management_permission,
                "max_entry_quantity": "10000000",
                "max_drawdown_pct": decimal_text(self._router.barbell.max_drawdown_pct),
            },
        }

    def _now(self, now: datetime | None = None) -> datetime:
        return utc_time(self._clock(), "now") if now is None else utc_time(now, "now")

    def _build_state_ref(self, now: datetime) -> StateReference:
        self._venue_seq += 1
        return StateReference(
            state_id=f"state-auto-{self._cycle_seq}-{self._venue_seq}",
            scope=self._scope,
            version=self._venue_seq,
            observed_at=now,
            valid_until=now + timedelta(seconds=30),
            venue_sequence=self._venue_seq,
        )

    def evaluate_fast_protection(
        self,
        *,
        quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Instant Snap-to-Breakeven & Monotonic Trailing Stop across all open MT5 positions."""
        ts = self._now(now)
        actions: list[dict[str, Any]] = []
        with self._lock:
            if self._governance_mode == GOVERNANCE_STOPPED:
                return actions
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            peak_eq = self._router.peak_equity() or total_eq
            _, _, risk_mult = self._quota.evaluate_new_risk(ActionKind.OPEN, now=ts, starting_equity=total_eq)
            if risk_mult <= Decimal("0"):
                risk_mult = Decimal("0.50")

            for broker_id, venue in list(self._router.venues.items()):
                if not isinstance(venue, Mt5PaperBrokerVenue) or venue.account is None:
                    continue
                try:
                    venue.probe()
                except Exception as exc:
                    logger.warning("fast protection probe failed for %s: %s", broker_id, type(exc).__name__)
                    continue

                live_tickets = {p.ticket for p in venue.positions}
                for stale_tkt in [
                    t for t, meta in self._open_position_meta.items()
                    if meta.get("broker_id") == broker_id and t not in live_tickets
                ]:
                    self._open_position_meta.pop(stale_tkt, None)

                for pos in venue.positions:
                    sym = pos.symbol
                    if quotes and sym in quotes:
                        bid, ask = quotes[sym]
                    else:
                        try:
                            tick = venue._transport.symbol_tick(sym)
                            bid, ask = tick.bid, tick.ask
                        except Exception as exc:
                            logger.debug("symbol_tick unavailable for %s on %s: %s", sym, broker_id, type(exc).__name__)
                            continue
                    cfg = self._protection_cfg(sym, risk_mult)
                    t_sz = _tick_size(sym)
                    current_price = bid if pos.side is Side.BUY else ask
                    prev_peak = self._peak_favorable.get(pos.ticket, pos.price_open)
                    peak = max(prev_peak, current_price) if pos.side is Side.BUY else min(prev_peak, current_price)
                    self._peak_favorable[pos.ticket] = peak
                    excursion = (peak - pos.price_open) if pos.side is Side.BUY else (pos.price_open - peak)

                    stage = self._protection_stage.get(pos.ticket, "INITIAL_SL")
                    candidate_sl: Decimal | None = None
                    new_stage = stage

                    if excursion >= cfg["be_trigger"]:
                        be_sl = (
                            (pos.price_open + cfg["be_offset"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                            if pos.side is Side.BUY
                            else (pos.price_open - cfg["be_offset"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                        )
                        if pos.side is Side.BUY and be_sl < bid - t_sz and (pos.stop_loss is None or be_sl > pos.stop_loss):
                            candidate_sl = be_sl
                            new_stage = "BREAKEVEN_LOCKED"
                        elif pos.side is Side.SELL and be_sl > ask + t_sz and (pos.stop_loss is None or be_sl < pos.stop_loss):
                            candidate_sl = be_sl
                            new_stage = "BREAKEVEN_LOCKED"

                    if excursion >= cfg["trail_activation"]:
                        trail_sl = (
                            (peak - cfg["trail_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                            if pos.side is Side.BUY
                            else (peak + cfg["trail_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                        )
                        if pos.side is Side.BUY and trail_sl < bid - t_sz:
                            floor_sl = candidate_sl if candidate_sl is not None else pos.stop_loss
                            if floor_sl is None or trail_sl > floor_sl:
                                candidate_sl = trail_sl
                                new_stage = "TRAILING_ACTIVE"
                        elif pos.side is Side.SELL and trail_sl > ask + t_sz:
                            ceil_sl = candidate_sl if candidate_sl is not None else pos.stop_loss
                            if ceil_sl is None or trail_sl < ceil_sl:
                                candidate_sl = trail_sl
                                new_stage = "TRAILING_ACTIVE"

                    self._open_position_meta[pos.ticket] = {
                        "ticket": pos.ticket,
                        "broker_id": broker_id,
                        "symbol": sym,
                        "side": pos.side.value,
                        "volume_lots": decimal_text(pos.volume_lots),
                        "entry_price": decimal_text(pos.price_open),
                        "stop_loss": None if pos.stop_loss is None else decimal_text(pos.stop_loss),
                        "take_profit": None if pos.take_profit is None else decimal_text(pos.take_profit),
                        "profit": decimal_text(pos.profit),
                        "protection_stage": stage,
                    }

                    if candidate_sl is None:
                        continue

                    self._cycle_seq += 1
                    st_ref = self._build_state_ref(ts)
                    action_ref = f"protect-{pos.ticket}-{self._cycle_seq}"
                    intent = ActionIntent(
                        intent_id=f"intent-{action_ref}",
                        scope=self._scope,
                        decision_id=f"dec-{action_ref}",
                        opportunity_id=f"opp-{sym.lower()}-{self._cycle_seq}",
                        action_ref=action_ref,
                        source_state=st_ref,
                        kind=ActionKind.AMEND_STOP,
                        instrument_id=sym,
                        origin=DecisionOrigin.ACTUAL_MODEL,
                        created_at=ts,
                        expires_at=st_ref.valid_until,
                        target_id=pos.ticket,
                        target_version=1,
                        stop_price=candidate_sl,
                        take_profit_price=pos.take_profit,
                    )
                    try:
                        dec = self._make_valve_request_and_clear(
                            intent=intent,
                            strategy_id="fast-protection-trail",
                            timeframe="50ms",
                            label=f"{new_stage} SL->{decimal_text(candidate_sl)}",
                            reason=f"Instant {new_stage} tightening SL to {decimal_text(candidate_sl)}",
                            bid=bid,
                            ask=ask,
                            total_eq=total_eq,
                            peak_eq=peak_eq,
                            position_side=pos.side,
                            now=ts,
                        )
                        order = OrderIntent.from_action_intent(intent, symbol=sym, position_ticket=pos.ticket)
                        self._router.execute_management(broker_id, order, valve_decision=dec)
                        self._protection_stage[pos.ticket] = new_stage
                        self._open_position_meta[pos.ticket]["stop_loss"] = decimal_text(candidate_sl)
                        self._open_position_meta[pos.ticket]["protection_stage"] = new_stage
                        actions.append({
                            "ticket": pos.ticket,
                            "broker_id": broker_id,
                            "symbol": sym,
                            "stage": new_stage,
                            "new_stop_loss": decimal_text(candidate_sl),
                            "take_profit": None if pos.take_profit is None else decimal_text(pos.take_profit),
                            "valve_score": decimal_text(Decimal(f"{dec.mlp_score:.8f}")),
                        })
                    except Exception as exc:
                        self._veto_count += 1
                        logger.warning("fast protection AMEND_STOP refused for %s: %s", pos.ticket, type(exc).__name__)
        return actions

    def _collect_market_quotes(
        self,
        stream_envelope: Mapping[str, Any] | None,
        index_stream: Mapping[str, Any] | None,
        mt5_quotes: Mapping[str, tuple[Decimal, Decimal]] | None,
    ) -> dict[str, dict[str, Any]]:
        markets: dict[str, dict[str, Any]] = {}
        if isinstance(stream_envelope, Mapping):
            for item in stream_envelope.get("streams") or []:
                if isinstance(item, Mapping) and isinstance(item.get("pair"), str):
                    markets[item["pair"]] = dict(item)
        if isinstance(index_stream, Mapping):
            for item in index_stream.get("markets") or []:
                if isinstance(item, Mapping) and isinstance(item.get("pair"), str):
                    markets[item["pair"]] = dict(item)
        if mt5_quotes:
            for sym, (bid, ask) in mt5_quotes.items():
                self._tick_history.setdefault(sym, deque(maxlen=64)).append((bid, ask))
                if sym not in markets:
                    markets[sym] = {
                        "pair": sym,
                        "bid": decimal_text(bid),
                        "ask": decimal_text(ask),
                        "candles_m1": [],
                    }
                else:
                    markets[sym]["bid"] = decimal_text(bid)
                    markets[sym]["ask"] = decimal_text(ask)
        return markets

    def _detect_candidate_setup(
        self,
        markets: Mapping[str, Mapping[str, Any]],
        *,
        fast_tick: bool,
    ) -> tuple[str, Side, Decimal, Decimal, str] | None:
        # Prioritize NAS100 & US30 first when momentum burst exceeds spread filter cleanly
        ordered_syms = list(INDEX_INSTRUMENTS) + [s for s in markets if s not in INDEX_INSTRUMENTS]
        for sym in ordered_syms:
            info = markets.get(sym)
            if not info:
                continue
            try:
                bid = Decimal(str(info["bid"]))
                ask = Decimal(str(info["ask"]))
            except (KeyError, ValueError, TypeError, ArithmeticError) as exc:
                logger.debug("skipping malformed market quote for %s: %s", sym, type(exc).__name__)
                continue
            if ask <= bid:
                continue
            spread = ask - bid
            params = self._protection_cfg(sym, Decimal("1"))

            # 1) Fast-tick momentum burst detection on direct MT5 ticks
            hist = list(self._tick_history.get(sym, ()))
            if len(hist) >= 3:
                mids = [(b + a) / Decimal("2") for b, a in hist[-5:]]
                burst = mids[-1] - mids[0]
                expected_min_burst = spread * Decimal("3") if sym in INDEX_INSTRUMENTS else spread * Decimal("4")
                if abs(burst) >= expected_min_burst and spread <= params["sl_distance"] * Decimal("0.25"):
                    side = Side.BUY if burst > Decimal("0") else Side.SELL
                    return sym, side, bid, ask, f"50ms burst delta={decimal_text(burst)} > spread-gate={decimal_text(expected_min_burst)}"

            if fast_tick and sym not in INDEX_INSTRUMENTS:
                continue

            # 2) M1 EMA trend setup when candles are available
            candles = info.get("candles_m1") or []
            if len(candles) >= 5:
                closes = [Decimal(str(c["c"])) for c in candles[-20:] if isinstance(c, Mapping) and "c" in c]
                if len(closes) >= 5:
                    fast_ema = _compute_ema(closes[-5:], 3)
                    slow_ema = _compute_ema(closes, min(len(closes), 14))
                    if fast_ema is not None and slow_ema is not None and spread <= params["sl_distance"] * Decimal("0.25"):
                        diff = fast_ema - slow_ema
                        threshold = _tick_size(sym) * (Decimal("50") if sym in INDEX_INSTRUMENTS else Decimal("3"))
                        if abs(diff) >= threshold:
                            side = Side.BUY if diff > Decimal("0") else Side.SELL
                            return sym, side, bid, ask, f"EMA fast-slow delta={decimal_text(diff)}"
        return None

    def _compute_quantity(
        self,
        *,
        symbol: str,
        side: Side,
        bid: Decimal,
        ask: Decimal,
        sl_price: Decimal,
        total_equity: Decimal,
        risk_multiplier: Decimal,
        quotes_map: Mapping[str, tuple[Decimal, Decimal]],
    ) -> Decimal:
        entry = ask if side is Side.BUY else bid
        stop_dist = abs(entry - sl_price)
        if stop_dist <= Decimal("0") or total_equity <= Decimal("0"):
            raise ContractError("non-positive stop distance or equity for sizing")
        budget = self._router.barbell.max_stop_risk_amount(total_equity) * risk_multiplier
        csize = Decimal("1") if symbol in INDEX_INSTRUMENTS else Decimal("100000")
        step_units = csize * MT5_VOLUME_STEP
        with localcontext() as ctx:
            ctx.prec = 40
            raw_units = budget / stop_dist
            # Also honor the active MT5 venue's post-trade margin level floor (>= 1000%) & barbell sleeve cap.
            for bid_id in self._router.priority_order:
                venue = self._router.venues.get(bid_id)
                if isinstance(venue, Mt5PaperBrokerVenue) and venue.account is not None and symbol in quotes_map:
                    acct = venue.account
                    min_ml = getattr(venue, "min_margin_level_pct", Decimal("1000"))
                    max_used_ml = (acct.equity * Decimal("100")) / max(min_ml, Decimal("100"))
                    sleeve_lim = self._router.barbell.share_for(bid_id) * total_equity
                    rem_margin = min(
                        max(Decimal("0"), max_used_ml - acct.margin),
                        max(Decimal("0"), sleeve_lim - acct.margin),
                        max(Decimal("0"), acct.margin_free),
                    ) * Decimal("0.95")
                    one_step_margin = venue._calc.required_margin(symbol, side, step_units, quotes_map)
                    if one_step_margin > Decimal("0"):
                        max_margin_units = (rem_margin / one_step_margin) * step_units
                        raw_units = min(raw_units, max_margin_units)
                    break
            steps = (raw_units / step_units).to_integral_value(rounding=ROUND_FLOOR)
        qty = max(csize * MT5_MIN_VOLUME, steps * step_units)
        # Verify exact Barbell stop risk never breaches 1.00% cap
        while qty > csize * MT5_MIN_VOLUME:
            risk = self._router.barbell.stop_loss_risk(
                symbol=symbol, units=qty, entry_price=entry, stop_price=sl_price, quotes=quotes_map
            )
            if risk <= budget:
                break
            qty -= step_units
        return qty.normalize()

    def record_closed_pnl(
        self,
        pnl_usd: Decimal,
        *,
        symbol: str,
        ticket: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        equities = self._router.equities()
        total_eq = self._router.barbell.total_equity(equities)
        with self._lock:
            self._open_position_meta.pop(ticket, None)
            snap = self._quota.record_realized_trade(
                pnl_usd, symbol=symbol, ticket=ticket, starting_equity=total_eq, now=ts
            )
            if not snap["new_risk_allowed"]:
                self._governance_reason = str(snap["lock_reason"] or snap["status"])
        return snap

    def run_fast_tick_cycle(
        self,
        *,
        mt5_quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        feed_source: str = FEED_MT5_FAST_SPOOL,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """50ms direct-MT5-spool fast burst cycle (blocks slow 15s public-fallback micro-scalps)."""
        if feed_source != FEED_MT5_FAST_SPOOL:
            with self._lock:
                self._veto_count += 1
                self._last_action = "VETOED"
                self._last_reason = f"SLOW_PUBLIC_FEED_SCALP_BLOCKED ({feed_source})"
            return {
                "schema": "cas-forex.ai-cycle/1",
                "cycle_id": f"cycle-{self._cycle_seq}",
                "observed_at": _iso(self._now(now)),
                "model_id": self._registry.active_model_id,
                "cadence": "FAST_TICK_BLOCKED",
                "action": "VETOED",
                "symbol": None,
                "reason": self._last_reason,
                "valve_score": self._last_valve_score,
                "protection_updates": [],
            }
        return self.run_cycle(None, mt5_quotes=mt5_quotes, fast_tick=True, now=now)

    def run_cycle(
        self,
        stream_envelope: Mapping[str, Any] | None = None,
        *,
        index_stream: Mapping[str, Any] | None = None,
        mt5_quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        fast_tick: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Run one deterministic + AI decision cycle behind ForexMetaValveGate & DailyQuotaLock."""
        t0_ns = time.monotonic_ns()
        ts = self._now(now)
        with self._lock:
            self._cycle_seq += 1
            cycle_id = f"cycle-{self._cycle_seq}"
            self._last_cadence = f"{self._fast_tick_ms}ms_FAST_TICK" if fast_tick else "STANDARD_18_MARKETS"

            # 1) Always run instant snap-to-breakeven & trailing stop first
            prot_updates = self.evaluate_fast_protection(quotes=mt5_quotes, now=ts)

            markets = self._collect_market_quotes(stream_envelope, index_stream, mt5_quotes)
            quotes_map = {
                s: (Decimal(str(m["bid"])), Decimal(str(m["ask"])))
                for s, m in markets.items()
                if "bid" in m and "ask" in m
            }
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            peak_eq = self._router.peak_equity() or total_eq
            self._quota.observe_day_start(total_eq, now=ts)

            # 2) Governance & Daily Quota / Loss Circuit Gate before evaluating new OPENs
            allowed, quota_veto, risk_mult = self._quota.evaluate_new_risk(
                ActionKind.OPEN, now=ts, starting_equity=total_eq
            )
            if self._governance_mode != GOVERNANCE_ACTIVE or not allowed:
                wait_reason = (
                    quota_veto if not allowed else f"Overseer governance is {self._governance_mode}"
                )
                if not allowed:
                    self._veto_count += 1
                self._last_action = "WAIT"
                self._last_symbol = None
                self._last_reason = str(wait_reason)
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": self._registry.active_model_id,
                    "cadence": self._last_cadence,
                    "action": "WAIT",
                    "symbol": None,
                    "reason": str(wait_reason),
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report

            # 3) Check market opportunity setup across 18 markets
            setup = self._detect_candidate_setup(markets, fast_tick=fast_tick)
            if setup is None:
                self._last_action = "WAIT"
                self._last_symbol = None
                self._last_reason = "No risk-compliant momentum or trend setup clears spread gate."
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": self._registry.active_model_id,
                    "cadence": self._last_cadence,
                    "action": "WAIT",
                    "symbol": None,
                    "reason": self._last_reason,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report

            sym, side, bid, ask, setup_note = setup
            params = self._protection_cfg(sym, risk_mult)
            t_sz = _tick_size(sym)
            entry_ref = ask if side is Side.BUY else bid
            if side is Side.BUY:
                sl_price = (bid - params["sl_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                tp_price = (ask + params["tp_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
            else:
                sl_price = (ask + params["sl_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                tp_price = (bid - params["tp_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)

            qty = self._compute_quantity(
                symbol=sym,
                side=side,
                bid=bid,
                ask=ask,
                sl_price=sl_price,
                total_equity=total_eq,
                risk_multiplier=risk_mult,
                quotes_map=quotes_map,
            )
            st_ref = self._build_state_ref(ts)
            action_ref = f"ai-open-{sym.lower()}-{self._cycle_seq}"
            intent = ActionIntent(
                intent_id=f"intent-{action_ref}",
                scope=self._scope,
                decision_id=f"dec-{action_ref}",
                opportunity_id=f"opp-{action_ref}",
                action_ref=action_ref,
                source_state=st_ref,
                kind=ActionKind.OPEN,
                instrument_id=sym,
                origin=DecisionOrigin.ACTUAL_MODEL,
                created_at=ts,
                expires_at=st_ref.valid_until,
                quantity=qty,
                side=side,
                limit_price=entry_ref,
                stop_price=sl_price,
                take_profit_price=tp_price,
            )

            # 4) Optional Gemini Decision 1 Fast Scout gate before waking heavy models
            active_id = self._registry.active_model_id
            if (
                self._registry.fast_scout_enabled
                and active_id != "gemini-decision-1"
                and self._registry.is_model_ready("gemini-decision-1")
            ):
                scout_q = [{
                    "market": sym,
                    "side": side.value,
                    "spread": decimal_text(ask - bid),
                    "setup": setup_note,
                    "choices": ["WAIT", action_ref],
                }]
                scout = self._registry.scout_opportunities(scout_q)
                self._last_scout = scout
                if scout.get("executed") and not scout.get("wake_heavy_model"):
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = f"Gemini Decision 1 Fast Scout held WAIT on {sym}"
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": "gemini-decision-1",
                        "cadence": self._last_cadence,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report

            # 5) Invoke active Frontier (or last-resort offline fallback) model through ActualModelDecisionAdapter
            ev_id = f"ev-{cycle_id}-{sym.lower()}"
            fact_obj = {
                "new_risk": True,
                "management": True,
                "equity": decimal_text(total_eq),
                "peak_equity": decimal_text(peak_eq),
                "bid": decimal_text(bid),
                "ask": decimal_text(ask),
                "signal": setup_note,
                "sl": decimal_text(sl_price),
                "tp": decimal_text(tp_price),
            }
            req = DecisionRequest(
                request_id=f"req-{cycle_id}",
                opportunity_set_id=f"set-{cycle_id}",
                state=st_ref,
                options=(ActionOption(action_ref, "ai-momentum-tp-sl", "50ms" if fast_tick else "M1", f"{side.value} {sym} {setup_note}"[:200], intent),),
                facts=(DecisionFact(f"observed-{cycle_id}", "Observed market and barbell equity", canonical_bytes(fact_obj).decode("utf-8"), (ev_id,)),),
                evidence=(EvidenceReference(ev_id, EvidenceKind.OBSERVATION, "autonomous-ai-trader", content_digest(fact_obj), ts),),
            )

            spec, backend, verifier = self._registry.build_backend(active_id)
            adapter = ActualModelDecisionAdapter(
                adapter_id=f"adapter-{active_id.replace(':', '-')}",
                model=spec,
                budget=InferenceBudget(
                    max_calls=1,
                    max_input_tokens_per_call=16_384,
                    max_generated_tokens_per_call=512,
                    max_seconds_per_call=25,
                    max_total_seconds=25,
                ),
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=self._execution_gate,
                clock=self._clock,
            )
            try:
                dec_result = adapter.decide(req)
            except FrontierTransportError as exc:
                self._veto_count += 1
                self._last_error = str(exc)
                self._registry.record_call(active_id, latency_ms=max(1, (time.monotonic_ns() - t0_ns) // 1_000_000), status="TRANSPORT_ERROR")
                raise

            call_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
            self._registry.record_call(active_id, latency_ms=call_ms, status="OK")

            chosen_ref = dec_result.selection.selected_action_ref
            if chosen_ref is None:
                self._last_action = "WAIT"
                self._last_symbol = sym
                self._last_reason = dec_result.selection.reason
                self._last_cycle_ms = call_ms
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": active_id,
                    "cadence": self._last_cadence,
                    "action": "WAIT",
                    "symbol": sym,
                    "reason": self._last_reason,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report

            # 6) Pass AI DecisionSelection through ForexMetaValveGate before router execution
            class _ModelProposal:
                __slots__ = ("request", "result", "intent")

                def __init__(self, r: DecisionRequest, d: Any, i: ActionIntent) -> None:
                    self.request = r
                    self.result = d
                    self.intent = i

            current_view = self._build_valve_view(
                total_eq=total_eq,
                peak_eq=peak_eq,
                new_risk_permission="ALLOWED",
                management_permission="ALLOWED",
            )
            try:
                valve_dec = self._valve_gate.require_admissible(
                    _ModelProposal(req, dec_result, intent), current_view=current_view, now=ts
                )
            except ValveRefusalError:
                self._veto_count += 1
                self._last_action = "VALVE_VETOED"
                self._last_symbol = sym
                self._last_reason = f"ForexMetaValveGate vetoed {active_id} proposal on {sym}"
                raise

            order = OrderIntent.from_action_intent(intent, symbol=sym)
            exec_res = self._router.execute_open(order, valve_decision=valve_dec)
            ticket = (
                exec_res.result.receipt.position_ticket
                if exec_res.result.receipt is not None and exec_res.result.receipt.position_ticket
                else ((exec_res.result.oanda_receipt or {}).get("fill_transaction_id") or action_ref)
            )
            fill_px = (
                exec_res.result.receipt.price
                if exec_res.result.receipt is not None and exec_res.result.receipt.price is not None
                else entry_ref
            )
            self._open_position_meta[str(ticket)] = {
                "ticket": str(ticket),
                "broker_id": exec_res.executed_on,
                "symbol": sym,
                "side": side.value,
                "volume_lots": decimal_text(exec_res.result.receipt.volume_lots) if exec_res.result.receipt and exec_res.result.receipt.volume_lots else "1",
                "entry_price": decimal_text(fill_px),
                "stop_loss": decimal_text(sl_price),
                "take_profit": decimal_text(tp_price),
                "profit": "0",
                "protection_stage": "INITIAL_SL",
            }
            self._peak_favorable[str(ticket)] = fill_px
            self._protection_stage[str(ticket)] = "INITIAL_SL"

            v_score_str = decimal_text(Decimal(f"{valve_dec.mlp_score:.8f}"))
            self._last_valve_score = v_score_str
            self._last_action = f"OPEN_{side.value}"
            self._last_symbol = sym
            self._last_reason = f"{dec_result.selection.reason} [exec={exec_res.executed_on} SL={decimal_text(sl_price)} TP={decimal_text(tp_price)}]"
            self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
            entry_log = {
                "cycle_id": cycle_id,
                "observed_at": _iso(ts),
                "model_id": active_id,
                "action": self._last_action,
                "symbol": sym,
                "executed_on": exec_res.executed_on,
                "ticket": str(ticket),
                "stop_loss": decimal_text(sl_price),
                "take_profit": decimal_text(tp_price),
                "valve_score": v_score_str,
                "reason": self._last_reason[:200],
            }
            self._recent_actions.appendleft(entry_log)
            report = {
                "schema": "cas-forex.ai-cycle/1",
                **entry_log,
                "cadence": self._last_cadence,
                "protection_updates": prot_updates,
            }
            self._append_journal_cycle(report)
            return report

    def pause_new_risk(self, *, reason: str = "Overseer paused new entries", now: datetime | None = None) -> dict[str, Any]:
        with self._lock:
            self._governance_mode = GOVERNANCE_PAUSED_NEW_RISK
            self._governance_reason = str(reason)[:240]
        return self.status_snapshot(now=now)

    def resume_autonomous(self, *, reason: str = "Overseer resumed autonomous loop", now: datetime | None = None) -> dict[str, Any]:
        ts = self._now(now)
        with self._lock:
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            allowed, veto_code, _ = self._quota.evaluate_new_risk(ActionKind.OPEN, now=ts, starting_equity=total_eq)
            if not allowed:
                self._governance_mode = GOVERNANCE_PAUSED_NEW_RISK
                self._governance_reason = f"Cannot resume while {veto_code} is active"
            else:
                self._governance_mode = GOVERNANCE_ACTIVE
                self._governance_reason = str(reason)[:240]
        return self.status_snapshot(now=ts)

    def stop_automation(self, *, reason: str = "Overseer stopped autonomous loop", now: datetime | None = None) -> dict[str, Any]:
        with self._lock:
            self._governance_mode = GOVERNANCE_STOPPED
            self._governance_reason = str(reason)[:240]
        return self.status_snapshot(now=now)

    def emergency_close_all(self, *, reason: str = "Overseer reviewed emergency close all", now: datetime | None = None) -> dict[str, Any]:
        ts = self._now(now)
        closed_tickets: list[str] = []
        with self._lock:
            self._governance_mode = GOVERNANCE_PAUSED_NEW_RISK
            self._governance_reason = str(reason)[:240]
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            peak_eq = self._router.peak_equity() or total_eq
            for broker_id, venue in list(self._router.venues.items()):
                if not isinstance(venue, Mt5PaperBrokerVenue) or venue.account is None:
                    continue
                venue.probe()
                for pos in venue.positions:
                    self._cycle_seq += 1
                    st_ref = self._build_state_ref(ts)
                    tick = venue._transport.symbol_tick(pos.symbol)
                    units = venue._calc.lots_to_units(pos.volume_lots, symbol=pos.symbol)
                    action_ref = f"overseer-close-{pos.ticket}-{self._cycle_seq}"
                    intent = ActionIntent(
                        intent_id=f"intent-{action_ref}",
                        scope=self._scope,
                        decision_id=f"dec-{action_ref}",
                        opportunity_id=f"opp-{action_ref}",
                        action_ref=action_ref,
                        source_state=st_ref,
                        kind=ActionKind.CLOSE,
                        instrument_id=pos.symbol,
                        origin=DecisionOrigin.OWNER_REVIEWED,
                        created_at=ts,
                        expires_at=st_ref.valid_until,
                        quantity=units,
                        side=Side.SELL if pos.side is Side.BUY else Side.BUY,
                        target_id=pos.ticket,
                        target_version=1,
                    )
                    dec = self._make_valve_request_and_clear(
                        intent=intent,
                        strategy_id="overseer-emergency-close",
                        timeframe="M1",
                        label=f"Close {pos.ticket}",
                        reason=reason,
                        bid=tick.bid,
                        ask=tick.ask,
                        total_eq=total_eq,
                        peak_eq=peak_eq,
                        position_side=pos.side,
                        now=ts,
                    )
                    order = OrderIntent.from_action_intent(intent, symbol=pos.symbol, position_ticket=pos.ticket)
                    self._router.execute_management(broker_id, order, valve_decision=dec)
                    self._quota.record_realized_trade(
                        pos.profit, symbol=pos.symbol, ticket=pos.ticket, starting_equity=total_eq, now=ts
                    )
                    self._open_position_meta.pop(pos.ticket, None)
                    closed_tickets.append(pos.ticket)
        snap = self.status_snapshot(now=ts)
        snap["closed_tickets"] = closed_tickets
        return assert_safe_ai_catalog_payload(snap)

    def rearm_and_unlock(
        self,
        *,
        owner_request_id: str,
        reason: str,
        new_peak_equity: Decimal | None = None,
        owner_verifier: Any | None = None,
        fence_request: Any | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        with self._lock:
            verifier = owner_verifier or self._owner_verifier
            if new_peak_equity is not None and verifier is not None:
                self._router.rearm_drawdown(
                    new_peak_equity=new_peak_equity,
                    owner_verifier=verifier,
                    owner_request_id=owner_request_id,
                    fence_request=fence_request,
                    now=ts,
                )
            self._quota.unlock_session(owner_request_id=owner_request_id, reason=reason, now=ts)
            self._governance_mode = GOVERNANCE_ACTIVE
            self._governance_reason = f"Re-armed & unlocked ({owner_request_id})"
        return self.status_snapshot(now=ts)

    def status_snapshot(self, *, now: datetime | None = None) -> dict[str, Any]:
        ts = self._now(now)
        with self._lock:
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            quota_snap = self._quota.snapshot(now=ts, starting_equity=total_eq if total_eq > 0 else None)
            cat_snap = self._registry.catalog_snapshot()
            payload = {
                "schema": "cas-forex.ai-trader/1",
                "human_role": "OVERSEER_ONLY",
                "governance_mode": self._governance_mode,
                "governance_reason": self._governance_reason,
                "effective_status": (
                    quota_snap["status"]
                    if quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_LOSS_TRIPPED)
                    else self._governance_mode
                ),
                "fast_tick_ms": int(self._fast_tick_ms),
                "cadence": self._last_cadence,
                "markets_evaluated": len(EXPANDED_MARKETS),
                "watchlist_markets": list(EXPANDED_MARKETS),
                "active_model_id": cat_snap["active_model_id"],
                "active_display_name": cat_snap["active_display_name"],
                "active_model_status": cat_snap["active_status"],
                "fast_scout_enabled": cat_snap["fast_scout_enabled"],
                "fast_scout_ready": cat_snap["fast_scout_ready"],
                "cycle_count": int(self._cycle_seq),
                "last_cycle_ms": int(self._last_cycle_ms),
                "last_action": self._last_action,
                "last_symbol": self._last_symbol,
                "last_reason": self._last_reason,
                "last_valve_score": self._last_valve_score,
                "veto_count": int(self._veto_count),
                "valve_controller": "tks_meta_valve_controller",
                "valve_parameters": int(self._valve_gate.controller.parameter_count),
                "valve_threshold": decimal_text(Decimal(f"{self._valve_gate.controller.threshold:.2f}")),
                "daily_quota": quota_snap,
                "open_positions": [dict(v) for v in self._open_position_meta.values()],
                "recent_actions": list(self._recent_actions),
                "observed_at": _iso(ts),
            }
            return assert_safe_ai_catalog_payload(payload)
