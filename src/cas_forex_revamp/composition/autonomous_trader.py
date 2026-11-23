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
from decimal import InvalidOperation, ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal, localcontext
from hashlib import sha256
import json
import logging
from pathlib import Path
import re
import sqlite3
from threading import RLock
import time
from typing import Any, Callable, Mapping, Sequence

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
from cas_forex_revamp.operator.model import ActualModelDecisionAdapter, DurableModelExecutionGate, ModelInvocation
from cas_forex_revamp.composition.phase8_live_bridge import Phase8LiveTradingBridge
from cas_forex_revamp.execution.smart_execution import (
    QuoteSnapshot,
    RefusalReason as SmartRefusalReason,
    SmartExecutionPlanner,
    SmartSliceExecutor,
)
from cas_forex_revamp.ledger.unified_ledger import UnifiedRealTimeLedger
from cas_forex_revamp.risk.news_shock_shield import (
    NewsShockShield,
    TradeActionType,
)
from cas_forex_revamp.treasury.compounding_controller import (
    CompoundingAndMilestoneController,
    CompoundingControllerError,
    CompoundingMode,
    OwnerKeyRequiredError as CompoundingOwnerKeyRequiredError,
)
from cas_forex_revamp.treasury.profit_sweep import ENV_INITIAL_CAPITAL_USD
from cas_forex_revamp.venue.execution_event_bus import (
    ExecutionEventBus,
    ExecutionEventType,
)
from cas_forex_revamp.valve.aggression_dial import (
    AggressionDialStore,
    MIN_CONSTITUTIONAL_VALVE_PROB,
    REFERENCE_CAPITAL_USD,
    resolve_effective_params as resolve_dial_effective_params,
)
from cas_forex_revamp.valve.daily_quota import (
    DailyQuotaGovernanceStore,
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_LOSS_TRIPPED,
    QUOTA_STATUS_PROFIT_FLOOR_LOCKED,
    QUOTA_STATUS_SOFT,
    SESSION_CADENCE_AUTO,
    forex_session_label_for_utc,
    format_pacific_timestamp,
    friendly_broker_label,
    session_date_for,
    session_period_info_for,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    PeakEquityStore,
    ValveDecision,
    ValveRefusalError,
    compute_drawdown_pct,
)
from cas_forex_revamp.composition.trend_regime import (
    MAX_PYRAMID_LEGS,
    PyramidLegSnapshot,
    REGIME_CHOP_RANGE,
    REGIME_SPREAD_SPIKE,
    REGIME_STRONG_TREND,
    REGIME_TREND_IGNITION,
    TrendRegimeDetector,
    evaluate_correlation_cap,
    evaluate_house_money_pyramid_leg,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.live_auth_ticket import LiveAuthorizationError
from cas_forex_revamp.venue.live_market_stream import EXPANDED_MARKETS, INDEX_INSTRUMENTS
from cas_forex_revamp.venue.mt5_broker_bridge import (
    MT5_CONTRACT_SIZE,
    MT5_GOLD_CONTRACT_SIZE,
    MT5_INDEX_CONTRACT_SIZE,
    MT5_MAX_VOLUME_DEFAULT,
    MT5_MIN_VOLUME,
    MT5_VOLUME_STEP,
    Mt5BridgeError,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    LiveBrokerEndpointForbiddenError,
    OandaPracticeFallbackVenue,
    OrderIntent,
)

logger = logging.getLogger(__name__)

GOVERNANCE_ACTIVE = "ACTIVE"
GOVERNANCE_PAUSED_NEW_RISK = "PAUSED_NEW_RISK"
GOVERNANCE_STOPPED = "STOPPED"
GOVERNANCE_MODES = (GOVERNANCE_ACTIVE, GOVERNANCE_PAUSED_NEW_RISK, GOVERNANCE_STOPPED)

FOCUS_MODE_RESEARCH_RESPITE = "RESEARCH_RESPITE"
OPERATING_MODE_ACTIVE_TRADING = "ACTIVE_TRADING"

CAPITAL_STATUS_RECOVERY_MODE = "RECOVERY_MODE"
CAPITAL_STATUS_AT_PRINCIPAL = "AT_PRINCIPAL"
CAPITAL_STATUS_IN_SURPLUS = "IN_SURPLUS"
DEFAULT_DEMO_3BROKER_CAPITAL_USD = Decimal("300000.00")
DEFAULT_STARTUP_VAULT_RETRY_COOLDOWN_SECONDS = 5.0

FEED_MT5_FAST_SPOOL = "MT5_DIRECT_SPOOL_50MS"
FEED_PUBLIC_FALLBACK = "PUBLIC_15S_FALLBACK"
GENESIS_SHA256 = "0" * 64

ENV_RISK_GEAR_MODE = "CAS_FOREX_RISK_GEAR_MODE"
RISK_GEAR_CONSERVATIVE = "CONSERVATIVE"
RISK_GEAR_AUTO_ADAPTIVE = "AUTO_ADAPTIVE"
RISK_GEAR_AGGRESSIVE = "AGGRESSIVE"
VALID_RISK_GEAR_MODES = (
    RISK_GEAR_CONSERVATIVE,
    RISK_GEAR_AUTO_ADAPTIVE,
    RISK_GEAR_AGGRESSIVE,
)

ACTIVE_GEAR_CONSERVATIVE = "CONSERVATIVE"
ACTIVE_GEAR_GROWTH = "GROWTH"
ACTIVE_GEAR_STRONG_TREND_RUNNER = "STRONG_TREND_RUNNER"

MAX_CONSTITUTIONAL_STOP_RISK_PCT = Decimal("1.00")
MAX_CONSTITUTIONAL_DRAWDOWN_PCT = Decimal("0.10")
SOFT_DRAWDOWN_DOWNSHIFT_PCT = Decimal("0.05")

COMPOUNDING_MONITORED_SYMBOLS: tuple[str, ...] = ("NAS100", "US30", "XAUUSD", "EUR_USD")
COMPOUNDING_BROKER_LABELS: tuple[str, ...] = ("Hugo's Way", "LHFX", "OANDA")
_PHASE8_SUPPORTED_BROKERS: frozenset[str] = frozenset(
    {"HUGOSWAY_MT5", "LHFX_MT5", "OANDA", "OANDA_PRACTICE", "OANDA_LIVE"}
)


def _enrich_milestone_dict(item: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(item)
    raw_mult = out.get("multiplier", "2")
    try:
        mult_int = int(Decimal(str(raw_mult)))
    except (InvalidOperation, ValueError, TypeError):
        mult_int = 2
    out["multiple"] = max(1, mult_int)
    return out


def build_enriched_compounding_payload(
    *,
    compounding_controller: CompoundingAndMilestoneController,
    phase8_bridge: Phase8LiveTradingBridge | None = None,
    fallback_news_shield: NewsShockShield | None = None,
    current_equity_usd: Decimal | None = None,
    owner_controls_allowed: bool = True,
    session_scope: str = "OWNER_FULL_CONTROL",
    execution_mode: str = "DEMO",
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Build strictly 0-write enriched compounding + milestone + Phase 8 bridge snapshot."""
    ts = utc_time(now_utc, "now_utc") if now_utc is not None else datetime.now(timezone.utc)
    eff_scope = (
        "DEVICE_READ_AND_EXPLAINER"
        if str(session_scope or "").strip().upper() == "DEVICE_READ_AND_EXPLAINER"
        else "OWNER_FULL_CONTROL"
    )
    eff_owner = bool(owner_controls_allowed) and (eff_scope == "OWNER_FULL_CONTROL")
    eff_exec = "LIVE" if str(execution_mode or "DEMO").strip().upper() == "LIVE" else "DEMO"

    safe_eq_override = (
        max(Decimal("0.00"), current_equity_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        if current_equity_usd is not None
        else None
    )
    doc = dict(compounding_controller.snapshot(current_equity_usd=safe_eq_override))
    doc["milestones"] = [
        _enrich_milestone_dict(m) for m in (doc.get("milestones") or []) if isinstance(m, Mapping)
    ]
    raw_next = doc.get("next_milestone")
    doc["next_milestone"] = _enrich_milestone_dict(raw_next) if isinstance(raw_next, Mapping) else None

    shield = phase8_bridge.news_shield if phase8_bridge is not None else (fallback_news_shield or NewsShockShield())
    news_doc = shield.shield_status_snapshot(COMPOUNDING_MONITORED_SYMBOLS, now_utc=ts)

    p8_summary: dict[str, Any] | None = None
    if phase8_bridge is not None:
        eval_eq_dec = Decimal(str(doc["current_equity_usd"]))
        raw_b = phase8_bridge.bridge_snapshot(
            symbols=COMPOUNDING_MONITORED_SYMBOLS,
            current_equity_usd=eval_eq_dec,
            now_utc=ts,
        )
        bus_raw = raw_b.get("event_bus") if isinstance(raw_b.get("event_bus"), Mapping) else {}
        workers_map = bus_raw.get("async_workers") if isinstance(bus_raw.get("async_workers"), Mapping) else {}
        lanes_raw = (
            bus_raw.get("subscriber_errors_by_lane")
            if isinstance(bus_raw.get("subscriber_errors_by_lane"), Mapping)
            else {}
        )
        clean_bus = {
            "published_count": int(bus_raw.get("published_count", 0)),
            "deduped_count": int(bus_raw.get("deduped_count", 0)),
            "dropped_events": int(bus_raw.get("dropped_events", 0)),
            "subscriber_errors": int(bus_raw.get("subscriber_errors", 0)),
            "last_seq_id": int(bus_raw.get("last_seq_id", 0)),
            "replay_buffer_len": int(bus_raw.get("replay_buffer_len", 0)),
            "replay_buffer_maxlen": int(bus_raw.get("replay_buffer_maxlen", 10000)),
            "active_subscribers": int(bus_raw.get("active_subscribers", 0)),
            "subscriber_errors_by_lane": {
                "CRITICAL_PROTECTION": int(lanes_raw.get("CRITICAL_PROTECTION", 0)),
                "LEDGER_ASYNC": int(lanes_raw.get("LEDGER_ASYNC", 0)),
                "UI_SSE_ASYNC": int(lanes_raw.get("UI_SSE_ASYNC", 0)),
            },
            "async_workers": [
                {
                    "subscriber_id": str(w.get("subscriber_id", "")),
                    "name": str(w.get("name", "")),
                    "lane": str(w.get("lane", "LEDGER_ASYNC")),
                    "queue_depth": int(w.get("queue_depth", 0)),
                    "queue_maxsize": int(w.get("queue_maxsize", 1024)),
                    "in_flight": int(w.get("in_flight", 0)),
                    "delivered_count": int(w.get("delivered_count", 0)),
                    "dropped_count": int(w.get("dropped_count", 0)),
                    "error_count": int(w.get("error_count", 0)),
                    "last_error": None if w.get("last_error") is None else str(w.get("last_error")),
                    "alive": bool(w.get("alive", False)),
                }
                for w in workers_map.values()
                if isinstance(w, Mapping)
            ],
            "closed": bool(bus_raw.get("closed", False)),
        }
        p8_summary = {
            "schema": str(raw_b["schema"]),
            "as_of_utc": str(raw_b["as_of_utc"]),
            "supported_brokers": [str(b) for b in (raw_b.get("supported_brokers") or [])],
            "valve_weights_sha256": str(raw_b["valve_weights_sha256"]),
            "event_bus": clean_bus,
            "ledger": dict(raw_b["ledger"]),
        }

    doc["owner_controls_allowed"] = eff_owner
    doc["session_scope"] = eff_scope
    doc["access_mode"] = eff_scope
    doc["execution_mode"] = eff_exec
    doc["live_mode"] = eff_exec == "LIVE"
    doc["connected"] = True
    doc["brokers"] = list(COMPOUNDING_BROKER_LABELS)
    doc["news_shield"] = news_doc
    doc["phase8_bridge"] = p8_summary
    return assert_safe_ai_catalog_payload(doc)


def resolve_adaptive_risk_and_quota(
    *,
    owner_gear_mode: str,
    regime: str,
    drawdown_pct: Decimal,
    consecutive_losses: int,
    owner_max_risk_pct: Decimal,
    owner_max_drawdown_pct: Decimal,
    owner_soft_quota_usd: Decimal,
    owner_hard_quota_usd: Decimal,
) -> dict[str, Any]:
    """Resolve active Risk Gear & Dynamic Daily Profit Quota strictly inside constitutional ceilings.

    Constitutional safety invariants (immutable upper bounds):
    - Per-trade stop-loss risk can NEVER exceed 1.00% of equity (`MAX_CONSTITUTIONAL_STOP_RISK_PCT`).
    - Maximum drawdown cutoff can NEVER exceed 10.00% (`MAX_CONSTITUTIONAL_DRAWDOWN_PCT = 0.10`).
    - Configuration may only tighten (lower) these bounds, never weaken them.
    - Higher gears adjust selectivity, allocation, and daily profit quota strictly within [0.50%, 1.00%]:
      1. Conservative (CHOP_RANGE / loss streak / drawdown >= 5%): 0.50% risk, $500 soft / $1,000 hard.
      2. Growth (TREND_IGNITION, 0 losses, drawdown < 5%): 0.75% risk, $2,000 soft / $2,500 hard.
      3. Strong-Trend Runner / Aggressive (STRONG_TREND, 0 losses, drawdown < 5%): 1.00% risk, $2,000 soft / $3,000 hard.
    """
    mode = str(owner_gear_mode or RISK_GEAR_AUTO_ADAPTIVE).strip().upper()
    if mode not in VALID_RISK_GEAR_MODES:
        raise ContractError(f"owner_gear_mode must be one of {VALID_RISK_GEAR_MODES}")
    max_risk = decimal_value(owner_max_risk_pct, "owner_max_risk_pct", positive=True)
    if max_risk > MAX_CONSTITUTIONAL_STOP_RISK_PCT:
        raise ContractError(
            f"owner_max_risk_pct {decimal_text(max_risk)}% exceeds immutable constitutional 1.00% stop-risk ceiling"
        )
    max_dd = decimal_value(owner_max_drawdown_pct, "owner_max_drawdown_pct", positive=True)
    if max_dd > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
        raise ContractError(
            f"owner_max_drawdown_pct {decimal_text(max_dd)} exceeds immutable constitutional 0.10 (10.00%) drawdown ceiling"
        )
    if isinstance(drawdown_pct, bool) or not isinstance(drawdown_pct, Decimal) or not drawdown_pct.is_finite():
        raise ContractError("drawdown_pct must be a finite Decimal")
    if drawdown_pct < Decimal("0"):
        raise ContractError("drawdown_pct must be non-negative")
    dd = decimal_value(drawdown_pct.quantize(Decimal("0.0000000001"), rounding=ROUND_CEILING), "drawdown_pct")
    hard_cap = decimal_value(owner_hard_quota_usd, "owner_hard_quota_usd", positive=True)
    soft_cap = decimal_value(owner_soft_quota_usd, "owner_soft_quota_usd", positive=True)
    consec = max(0, int(consecutive_losses))
    reg = str(regime or REGIME_CHOP_RANGE).strip().upper()
    eff_soft_dd = min(SOFT_DRAWDOWN_DOWNSHIFT_PCT, max_dd)

    if mode == RISK_GEAR_CONSERVATIVE:
        active_gear = ACTIVE_GEAR_CONSERVATIVE
        target_risk = Decimal("0.50")
        target_soft = Decimal("500")
        target_hard = Decimal("1000")
        reason = "Owner selected Conservative Gear (0.50% risk · $500/$1,000 quota · 1.00%/10.00% cap)."
    elif mode == RISK_GEAR_AGGRESSIVE:
        active_gear = ACTIVE_GEAR_STRONG_TREND_RUNNER
        target_risk = Decimal("1.00")
        target_soft = Decimal("2000")
        target_hard = Decimal("3000")
        reason = "Owner selected Aggressive Gear (1.00% constitutional stop cap · $2,000/$3,000 quota)."
    else:
        if dd >= eff_soft_dd:
            active_gear = ACTIVE_GEAR_CONSERVATIVE
            target_risk = Decimal("0.50")
            target_soft = Decimal("500")
            target_hard = Decimal("1000")
            dd_pct_disp = (dd * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
            soft_pct_disp = (eff_soft_dd * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
            reason = (
                f"Auto-downshifted to Conservative Gear (drawdown {decimal_text(dd_pct_disp)}% >= {decimal_text(soft_pct_disp)}% soft floor)."
            )
        elif consec >= 1:
            active_gear = ACTIVE_GEAR_CONSERVATIVE
            target_risk = Decimal("0.50")
            target_soft = Decimal("500")
            target_hard = Decimal("1000")
            reason = f"Auto-downshifted to Conservative Gear (loss streak {consec} >= 1 · 0.50% risk)."
        elif reg == REGIME_STRONG_TREND:
            active_gear = ACTIVE_GEAR_STRONG_TREND_RUNNER
            target_risk = Decimal("1.00")
            target_soft = Decimal("2000")
            target_hard = Decimal("3000")
            reason = "Strong-Trend Runner Gear active (0 loss streak: 1.00% constitutional cap · $2,000/$3,000 quota)."
        elif reg == REGIME_TREND_IGNITION:
            active_gear = ACTIVE_GEAR_GROWTH
            target_risk = Decimal("0.75")
            target_soft = Decimal("2000")
            target_hard = Decimal("2500")
            reason = "Growth Gear active on Trend Ignition (0 loss streak: 0.75% risk · $2,000/$2,500 quota)."
        else:
            active_gear = ACTIVE_GEAR_CONSERVATIVE
            target_risk = Decimal("0.50")
            target_soft = Decimal("500")
            target_hard = Decimal("1000")
            reason = f"Conservative Gear active in {reg} regime (0.50% risk · $500/$1,000 quota)."

    eff_risk = min(target_risk, max_risk, MAX_CONSTITUTIONAL_STOP_RISK_PCT)
    eff_hard = min(target_hard, hard_cap)
    eff_soft = min(target_soft, eff_hard)
    # Also respect owner_soft_quota_usd ceiling when owner configured a tighter soft target in Conservative mode
    if soft_cap < eff_soft and mode == RISK_GEAR_CONSERVATIVE:
        eff_soft = soft_cap
    with localcontext() as ctx:
        ctx.prec = 40
        scale = (eff_risk / max_risk).quantize(Decimal("0.0001"), rounding=ROUND_FLOOR)
    if scale > Decimal("1"):
        scale = Decimal("1")
    if scale < Decimal("0.01"):
        scale = Decimal("0.01")

    return {
        "owner_mode": mode,
        "active_gear": active_gear,
        "effective_risk_pct": decimal_text(eff_risk),
        "owner_max_risk_pct": decimal_text(max_risk),
        "risk_scale_factor": decimal_text(scale),
        "effective_soft_quota_usd": decimal_text(eff_soft),
        "effective_hard_quota_usd": decimal_text(eff_hard),
        "owner_hard_quota_usd": decimal_text(hard_cap),
        "soft_drawdown_downshift_pct": decimal_text(eff_soft_dd),
        "owner_max_drawdown_pct": decimal_text(max_dd),
        "reason": reason[:240],
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def _next_ny_session_rollover_utc(now_utc: datetime) -> str:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    ts = utc_time(now_utc, "now")
    try:
        ny_tz: Any = ZoneInfo("America/New_York")
    except ZoneInfoNotFoundError:
        ny_tz = timezone(timedelta(hours=-5))
    local_ny = ts.astimezone(ny_tz)
    cand_ny = datetime(local_ny.year, local_ny.month, local_ny.day, 17, 0, 0, tzinfo=ny_tz)
    if local_ny >= cand_ny:
        nxt_d = local_ny.date() + timedelta(days=1)
        cand_ny = datetime(nxt_d.year, nxt_d.month, nxt_d.day, 17, 0, 0, tzinfo=ny_tz)
    return cand_ny.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def compute_market_sessions_status(now_utc: datetime, *, mt5_tick_fresh: bool = False) -> dict[str, Any]:
    """Compute UTC open/closed status for Forex 24/5, major sessions, and US Indices/Gold."""
    ts = now_utc.astimezone(timezone.utc) if now_utc.tzinfo is not None else now_utc.replace(tzinfo=timezone.utc)
    wd = ts.weekday()  # 0=Mon..6=Sun
    hr = ts.hour
    mn = ts.minute
    forex_open = (wd in (0, 1, 2, 3)) or (wd == 6 and hr >= 22) or (wd == 4 and hr < 22)

    sessions = [
        {"id": "sydney", "label": "Sydney", "window_utc": "22:00-07:00 UTC", "open": bool(forex_open and (hr >= 22 or hr < 7))},
        {"id": "tokyo", "label": "Tokyo", "window_utc": "00:00-09:00 UTC", "open": bool(forex_open and (0 <= hr < 9))},
        {"id": "london", "label": "London", "window_utc": "07:00-16:00 UTC", "open": bool(forex_open and (7 <= hr < 16))},
        {"id": "new_york", "label": "New York", "window_utc": "12:00-21:00 UTC", "open": bool(forex_open and (12 <= hr < 21))},
        {"id": "london_ny_overlap", "label": "London-NY Overlap", "window_utc": "12:00-16:00 UTC", "open": bool(forex_open and (12 <= hr < 16))},
    ]
    if not forex_open:
        us_status = "WEEKEND_CLOSED"
        us_label = "Weekend Closed"
    elif hr == 21:
        us_status = "DAILY_BREAK"
        us_label = "Daily Break 21:00-22:00 UTC"
    elif (hr == 14 and mn >= 30) or (15 <= hr < 21):
        us_status = "CASH_OPEN"
        us_label = "Wall Street Cash OPEN 14:30-21:00 UTC"
    else:
        us_status = "EXTENDED_OPEN"
        us_label = "Extended Hours OPEN"

    return {
        "utc_time": ts.strftime("%H:%M UTC"),
        "forex_24_5_open": bool(forex_open),
        "forex_label": "FOREX 24/5 OPEN" if forex_open else "WEEKEND CLOSED",
        "us_indices_status": us_status,
        "us_indices_label": us_label,
        "mt5_tick_fresh": bool(mt5_tick_fresh),
        "sessions": sessions,
    }


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
        profit_vault: Any | None = None,
        parallel_tiers: Any | None = None,
        aggression_dial: AggressionDialStore | None = None,
        risk_gear_mode: str | None = None,
        risk_gear_path: str | Path | None = None,
        initial_capital_usd: Decimal | None = None,
        startup_vault_retry_cooldown_seconds: float = DEFAULT_STARTUP_VAULT_RETRY_COOLDOWN_SECONDS,
        compounding_controller: CompoundingAndMilestoneController | None = None,
        phase8_bridge: Phase8LiveTradingBridge | None = None,
        state_dir: str | Path | None = None,
    ) -> None:
        if not isinstance(router, DualShieldBrokerRouter):
            raise ContractError("AutonomousAiTrader requires a DualShieldBrokerRouter")
        if not isinstance(model_registry, FrontierModelRegistry):
            raise ContractError("AutonomousAiTrader requires a FrontierModelRegistry")
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("AutonomousAiTrader requires a ForexMetaValveGate")
        if type(fast_tick_ms) is not int or not (0 <= fast_tick_ms <= 5000):
            raise ContractError("fast_tick_ms must be an integer in 0..5000")
        if aggression_dial is not None and not isinstance(aggression_dial, AggressionDialStore):
            raise ContractError("aggression_dial must be an AggressionDialStore or None")
        if compounding_controller is not None and not isinstance(
            compounding_controller, CompoundingAndMilestoneController
        ):
            raise ContractError("compounding_controller must be a CompoundingAndMilestoneController or None")
        if phase8_bridge is not None and not isinstance(phase8_bridge, Phase8LiveTradingBridge):
            raise ContractError("phase8_bridge must be a Phase8LiveTradingBridge or None")

        self._router = router
        self._registry = model_registry
        self._valve_gate = valve_gate
        self._quota = quota_store or DailyQuotaGovernanceStore()
        self._peak_store = peak_equity_store or valve_gate.peak_equity_store
        self._owner_verifier = owner_verifier
        self._fast_tick_ms = fast_tick_ms
        self._clock = clock or _utc_now
        if router.barbell.max_stop_loss_equity_risk_pct > MAX_CONSTITUTIONAL_STOP_RISK_PCT:
            raise ContractError(
                f"router max_stop_loss_equity_risk_pct {decimal_text(router.barbell.max_stop_loss_equity_risk_pct)}% "
                "exceeds immutable constitutional 1.00% ceiling"
            )
        if router.barbell.max_drawdown_pct > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
            raise ContractError(
                f"router max_drawdown_pct {decimal_text(router.barbell.max_drawdown_pct)} "
                "exceeds immutable constitutional 0.10 (10.00%) ceiling"
            )
        if execution_gate is None or not callable(execution_gate):
            raise ContractError(
                "AutonomousAiTrader requires an explicit execution_gate (DurableModelExecutionGate); no-op fallback is forbidden"
            )
        self._execution_gate = execution_gate
        if isinstance(execution_gate, DurableModelExecutionGate) and hasattr(model_registry, "bind_execution_gate"):
            model_registry.bind_execution_gate(execution_gate)
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
        self._profit_vault = profit_vault
        self._parallel_tiers = parallel_tiers
        self._aggression_dial: AggressionDialStore | None = aggression_dial
        self._last_dial_skip_reason: str | None = None
        self._risk_gear_path = Path(risk_gear_path) if risk_gear_path is not None else None
        init_gear = RISK_GEAR_AUTO_ADAPTIVE
        if risk_gear_mode is not None and str(risk_gear_mode).strip():
            cand_g = str(risk_gear_mode).strip().upper()
            if cand_g not in VALID_RISK_GEAR_MODES:
                raise ContractError(f"risk_gear_mode must be one of {VALID_RISK_GEAR_MODES}")
            init_gear = cand_g
        elif self._risk_gear_path is not None and self._risk_gear_path.is_file() and not self._risk_gear_path.is_symlink():
            try:
                saved_g = str(json.loads(self._risk_gear_path.read_text(encoding="utf-8")).get("risk_gear_mode", "")).strip().upper()
                if saved_g in VALID_RISK_GEAR_MODES:
                    init_gear = saved_g
            except (OSError, ValueError, TypeError):
                init_gear = RISK_GEAR_AUTO_ADAPTIVE
        self._risk_gear_mode = init_gear
        self._last_risk_gear: dict[str, Any] | None = None
        self._lock = RLock()
        self._inference_lock = RLock()
        self._trend_detector = TrendRegimeDetector()
        self._last_regime = REGIME_TREND_IGNITION
        self._last_effective_effort = "low"
        self._last_pyramid_leg = False
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
        self._last_evaluated_symbol: str | None = None
        self._last_evaluated_regime: str | None = None
        self._top_watch_symbol: str | None = None
        self._current_focus_status: str | None = None
        self._last_valve_score: str | None = None
        self._last_scout: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_quota_status: str = ""
        self._last_consec_losses: int = 0
        self._last_drawdown_pct: Decimal = Decimal("0")
        self._tick_history: dict[str, deque[tuple[Decimal, Decimal]]] = {
            sym: deque(maxlen=64) for sym in EXPANDED_MARKETS
        }
        self._peak_favorable: dict[str, Decimal] = {}
        self._protection_stage: dict[str, str] = {}
        self._open_position_meta: dict[str, dict[str, Any]] = {}
        self._recent_actions: deque[dict[str, Any]] = deque(maxlen=12)
        self._journal_initialized = False
        self._startup_vault_synced = self._profit_vault is None
        self._startup_vault_retry_cooldown_seconds = max(0.0, float(startup_vault_retry_cooldown_seconds))
        self._startup_vault_next_retry_at: datetime | None = None
        self._last_vault_sync_error: str | None = None
        self._cached_vault_init_cap: Decimal | None = None
        self._cached_settled_disbursed_usd: Decimal = Decimal("0.00")
        self._cold_offline_baseline_eq: dict[tuple[str, ...], Decimal] = {}
        self._explicit_initial_capital_usd: Decimal | None = (
            decimal_value(Decimal(initial_capital_usd), "initial_capital_usd", positive=True).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            if initial_capital_usd is not None
            else None
        )
        from cas_forex_revamp.composition.state_store import (
            ensure_secure_state_directory,
            verify_non_symlink_sqlite_target,
        )

        if self._journal_path is not None:
            self._journal_path = verify_non_symlink_sqlite_target(
                self._journal_path, create_parent=True, label="AI trader cycle journal DB"
            )

        self._state_dir: Path | None = (
            ensure_secure_state_directory(state_dir) if state_dir is not None else None
        )
        resolved_comp = compounding_controller
        resolved_bridge = phase8_bridge
        if self._state_dir is not None:
            boot_ts = self._now()
            boot_principal = self._resolve_initial_capital_usd(allow_vault_io=True) or Decimal("5000.00")
            if resolved_comp is None:
                comp_db_target = verify_non_symlink_sqlite_target(
                    self._state_dir / "compounding.sqlite3",
                    create_parent=False,
                    label="compounding SQLite DB",
                )
                resolved_comp = CompoundingAndMilestoneController(
                    comp_db_target,
                    starting_principal_usd=boot_principal,
                    mode=CompoundingMode.BALANCED_SPLIT_50_50,
                    scope_id=self._scope.account_id,
                    now_utc=boot_ts,
                )
            if resolved_bridge is None:
                p8_db_target = verify_non_symlink_sqlite_target(
                    self._state_dir / "phase8_unified_ledger.sqlite3",
                    create_parent=False,
                    label="phase8 unified ledger DB",
                )
                p8_ledger = UnifiedRealTimeLedger(
                    p8_db_target,
                    scope_id=self._scope.account_id,
                    principal_usd=boot_principal,
                    sweep_ratio=Decimal("0.50"),
                    clock=self._clock,
                )
                resolved_bridge = Phase8LiveTradingBridge(
                    self._valve_gate,
                    ledger=p8_ledger,
                    event_bus=ExecutionEventBus(),
                    news_shield=NewsShockShield(),
                    smart_planner=SmartExecutionPlanner(),
                    smart_executor=SmartSliceExecutor(valve_gate=self._valve_gate, clock=self._clock),
                    compounding_controller=resolved_comp,
                )
        if (
            resolved_bridge is not None
            and resolved_comp is not None
            and resolved_bridge.compounding_controller is None
        ):
            resolved_bridge._compounding_controller = resolved_comp
        self._compounding_controller: CompoundingAndMilestoneController | None = resolved_comp
        self._phase8_bridge: Phase8LiveTradingBridge | None = resolved_bridge
        self._fallback_news_shield = NewsShockShield()

    @property
    def compounding_controller(self) -> CompoundingAndMilestoneController | None:
        return self._compounding_controller

    @property
    def phase8_bridge(self) -> Phase8LiveTradingBridge | None:
        return self._phase8_bridge

    @property
    def aggression_dial(self) -> AggressionDialStore | None:
        return self._aggression_dial

    def bind_compounding_controller(self, controller: CompoundingAndMilestoneController | None) -> None:
        if controller is not None and not isinstance(controller, CompoundingAndMilestoneController):
            raise ContractError("controller must be a CompoundingAndMilestoneController or None")
        with self._lock:
            self._compounding_controller = controller
            if self._phase8_bridge is not None:
                self._phase8_bridge._compounding_controller = controller

    def bind_phase8_bridge(self, bridge: Phase8LiveTradingBridge | None) -> None:
        if bridge is not None and not isinstance(bridge, Phase8LiveTradingBridge):
            raise ContractError("bridge must be a Phase8LiveTradingBridge or None")
        with self._lock:
            self._phase8_bridge = bridge
            if bridge is not None and self._compounding_controller is not None and bridge.compounding_controller is None:
                bridge._compounding_controller = self._compounding_controller

    def close(self, timeout: float = 2.0, *, drain: bool = True) -> bool:
        """Cleanly shut down Phase8LiveTradingBridge / ExecutionEventBus worker threads (0 leaked threads)."""
        bridge = self._phase8_bridge
        if bridge is None:
            return True
        return bridge.close(timeout=timeout, drain=drain)

    shutdown = close

    def _resolve_phase8_broker_id(self, candidate: str | None = None) -> str:
        raw = str(candidate or "").strip().upper()
        if raw in _PHASE8_SUPPORTED_BROKERS:
            return raw
        active_brk = str(getattr(self._router, "active_broker_id", "") or "").strip().upper()
        if active_brk in _PHASE8_SUPPORTED_BROKERS:
            return active_brk
        for b_id in self._router.priority_order:
            cand = str(b_id or "").strip().upper()
            if cand in _PHASE8_SUPPORTED_BROKERS:
                return cand
        return "HUGOSWAY_MT5"

    def _has_connected_broker_equity_unlocked(self) -> bool:
        for venue in self._router.venues.values():
            if isinstance(venue, Mt5PaperBrokerVenue):
                if venue.account is not None and not getattr(venue, "is_offline", False):
                    return True
            elif isinstance(venue, OandaPracticeFallbackVenue):
                oanda_off = (
                    callable(getattr(self._router, "is_broker_offline", None))
                    and self._router.is_broker_offline(venue.broker_id)
                )
                if not oanda_off and (venue.summary is not None or venue.nav is not None):
                    return True
        return False

    def _compounding_starting_principal_ro(self) -> Decimal | None:
        ctrl = self._compounding_controller
        if ctrl is None:
            return None
        try:
            snap = ctrl.snapshot()
            return Decimal(str(snap["starting_principal_usd"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        except Exception as exc_cp:
            logger.debug("compounding principal read skipped: %s", type(exc_cp).__name__)
            return None

    def _sync_vault_sweep_ratio_for_write(self, economic_equity_usd: Decimal) -> Decimal | None:
        """Synchronize ProfitSweepVault sweep_ratio from CompoundingAndMilestoneController strictly on write paths."""
        ctrl = self._compounding_controller
        vault = self._profit_vault
        if ctrl is None or vault is None or not hasattr(vault, "set_config"):
            return None
        safe_eq = max(Decimal("0.00"), economic_equity_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        eff_ratio = ctrl.effective_vault_sweep_ratio(safe_eq)
        try:
            v_cur = vault.snapshot() if hasattr(vault, "snapshot") else {}
            cur_ratio = Decimal(str(v_cur.get("sweep_ratio", "0.50"))).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            cur_auto = bool(v_cur.get("auto_sweep_enabled", True))
            if cur_ratio != eff_ratio or not cur_auto:
                vault.set_config(sweep_ratio=eff_ratio, auto_sweep_enabled=True)
        except Exception as exc_vs:
            logger.warning("compounding->vault sweep_ratio sync skipped: %s", type(exc_vs).__name__)
        return eff_ratio

    def _live_economic_equity_for_compounding(self) -> tuple[Decimal | None, Decimal, str]:
        v_snap = self._read_vault_snapshot_outside_lock()
        with self._lock:
            eq_bundle = self._router_equity_bundle_unlocked()
            total_eq = eq_bundle["total_eq"]
            has_live = self._has_connected_broker_equity_unlocked() or total_eq > Decimal("0")
            ps = self._principal_surplus_metrics(
                total_eq,
                v_snap=v_snap,
                equities=eq_bundle["equities"],
                offline_brokers=eq_bundle["offline_brokers"],
            )
            econ_eq = ps["economic_equity_usd"]
            if ps.get("cold_offline_unknown") and econ_eq < ps["principal_usd"]:
                econ_eq = max(
                    Decimal("0.00"),
                    (ps["principal_usd"] + ps["net_surplus_usd"]).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    ),
                )
            exec_mode = "LIVE" if str(self._router.execution_mode).upper() == "LIVE" else "DEMO"
        return (econ_eq if has_live else None), econ_eq, exec_mode

    def compounding_snapshot(
        self,
        *,
        owner_controls_allowed: bool = True,
        session_scope: str = "OWNER_FULL_CONTROL",
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Return strictly 0-write compounding, House-Money, and Phase 8 bridge snapshot."""
        ctrl = self._compounding_controller
        if ctrl is None:
            return None
        ts = self._now(now)
        live_eq_opt, _, exec_mode = self._live_economic_equity_for_compounding()
        return build_enriched_compounding_payload(
            compounding_controller=ctrl,
            phase8_bridge=self._phase8_bridge,
            fallback_news_shield=self._fallback_news_shield,
            current_equity_usd=live_eq_opt,
            owner_controls_allowed=owner_controls_allowed,
            session_scope=session_scope,
            execution_mode=exec_mode,
            now_utc=ts,
        )

    def set_compounding_mode(
        self,
        mode: CompoundingMode | str,
        *,
        compounding_target_usd: Decimal | None = None,
        house_money_target_usd: Decimal | None = None,
        custom_vault_ratio: Decimal | None = None,
        post_target_vault_ratio: Decimal | None = None,
        auto_enable_vault_at_target: bool | None = None,
        owner_controls_allowed: bool = True,
        actor: str = "cockpit-owner",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Owner-gated compounding mode mutation; syncs ProfitSweepVault sweep_ratio immediately."""
        ctrl = self._compounding_controller
        if ctrl is None:
            raise ContractError("CompoundingAndMilestoneController is not attached")
        ts = self._now(now)
        ctrl.set_compounding_mode(
            mode,
            compounding_target_usd=compounding_target_usd,
            house_money_target_usd=house_money_target_usd,
            custom_vault_ratio=custom_vault_ratio,
            post_target_vault_ratio=post_target_vault_ratio,
            auto_enable_vault_at_target=auto_enable_vault_at_target,
            owner_controls_allowed=owner_controls_allowed,
            actor=actor,
            now_utc=ts,
        )
        live_eq_opt, econ_eq, _ = self._live_economic_equity_for_compounding()
        eval_eq = live_eq_opt if live_eq_opt is not None else Decimal(str(ctrl.snapshot()["current_equity_usd"]))
        self._sync_vault_sweep_ratio_for_write(eval_eq if eval_eq >= Decimal("0") else econ_eq)
        snap = self.compounding_snapshot(
            owner_controls_allowed=owner_controls_allowed,
            session_scope="OWNER_FULL_CONTROL" if owner_controls_allowed else "DEVICE_READ_AND_EXPLAINER",
            now=ts,
        )
        if snap is None:
            raise ContractError("Compounding snapshot unavailable")
        return snap

    def acknowledge_principal_withdrawn(
        self,
        amount_usd: Decimal | None = None,
        *,
        owner_controls_allowed: bool = True,
        actor: str = "cockpit-owner",
        post_withdrawal_equity_usd: Decimal | None = None,
        note: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Owner-gated House-Money original principal pull-out acknowledgment."""
        ctrl = self._compounding_controller
        if ctrl is None:
            raise ContractError("CompoundingAndMilestoneController is not attached")
        if not owner_controls_allowed:
            raise CompoundingOwnerKeyRequiredError(
                "Owner key required: acknowledge_principal_withdrawn is forbidden for read-only devices"
            )
        if note is not None:
            if not isinstance(note, str) or len(note) > 240 or any(ch in note for ch in ("\x00", "\r", "\n")):
                raise CompoundingControllerError("note must be a clean string of at most 240 characters")
        ts = self._now(now)
        resolved_amt = amount_usd
        if resolved_amt is None:
            cur_snap = self.compounding_snapshot(owner_controls_allowed=True, now=ts) or ctrl.snapshot()
            sugg = Decimal(str(cur_snap["suggested_principal_pullout_usd"]))
            resolved_amt = sugg if sugg > Decimal("0.00") else Decimal(str(cur_snap["starting_principal_usd"]))
        ctrl.acknowledge_principal_withdrawn(
            resolved_amt,
            owner_controls_allowed=owner_controls_allowed,
            actor=actor,
            post_withdrawal_equity_usd=post_withdrawal_equity_usd,
            now_utc=ts,
        )
        snap = self.compounding_snapshot(
            owner_controls_allowed=owner_controls_allowed,
            session_scope="OWNER_FULL_CONTROL",
            now=ts,
        )
        if snap is None:
            raise ContractError("Compounding snapshot unavailable")
        return snap

    def _connect_journal(self) -> sqlite3.Connection | None:
        if self._journal_path is None:
            return None
        from cas_forex_revamp.composition.state_store import open_verified_sqlite_connection

        conn = open_verified_sqlite_connection(
            self._journal_path,
            read_only=False,
            timeout=10.0,
            create_parent=True,
            label="AI trader cycle journal DB",
        )
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

    @property
    def aggression_dial(self) -> AggressionDialStore | None:
        with self._lock:
            return self._aggression_dial

    def bind_aggression_dial(self, store: AggressionDialStore | None) -> None:
        if store is not None and not isinstance(store, AggressionDialStore):
            raise ContractError("aggression_dial must be an AggressionDialStore or None")
        with self._lock:
            self._aggression_dial = store

    def _read_dial_snapshot_outside_lock(self) -> dict[str, Any] | None:
        with self._lock:
            dial = self._aggression_dial
        if dial is None:
            return None
        return dial.snapshot()

    def _router_equity_bundle_unlocked(self) -> dict[str, Any]:
        equities = self._router.equities()
        total_eq = self._router.barbell.total_equity(equities)
        if (
            callable(getattr(self._router, "is_broker_offline", None))
            and hasattr(self._router, "priority_order")
        ):
            offline_ids = [
                b for b in self._router.priority_order if self._router.is_broker_offline(b)
            ]
            offline_set = set(offline_ids)
            venues_map = self._router.venues if hasattr(self._router, "venues") else {}
            online_eq_map = {
                b: val
                for b, val in equities.items()
                if b not in offline_set and (b in venues_map or val > Decimal("0"))
            }
        else:
            offline_ids = (
                list(self._router.offline_brokers())
                if callable(getattr(self._router, "offline_brokers", None))
                else []
            )
            online_eq_map = (
                self._router.online_equities()
                if callable(getattr(self._router, "online_equities", None))
                else dict(equities)
            )
        online_total_eq = self._router.barbell.total_equity(online_eq_map)
        if callable(getattr(self._router, "effective_drawdown_state", None)):
            eff_dd_eq, eff_dd_peak, eff_dd_pct = self._router.effective_drawdown_state(
                equities=equities, offline_brokers=offline_ids
            )
        else:
            eff_dd_eq = total_eq
            eff_dd_peak = self._router.peak_equity() or total_eq
            eff_dd_pct = (
                compute_drawdown_pct(eff_dd_eq, eff_dd_peak)
                if (eff_dd_peak is not None and eff_dd_peak > Decimal("0"))
                else Decimal("0")
            )
        if callable(getattr(self._router, "effective_drawdown_scope_id", None)):
            eff_dd_scope = str(
                self._router.effective_drawdown_scope_id(
                    equities=equities, offline_brokers=offline_ids
                )
                or "dual-shield-barbell"
            )
        else:
            eff_dd_scope = "dual-shield-barbell"
        self._last_drawdown_pct = eff_dd_pct
        return {
            "equities": equities,
            "total_eq": total_eq,
            "online_equities": online_eq_map,
            "online_total_eq": online_total_eq,
            "offline_brokers": offline_ids,
            "eff_dd_eq": eff_dd_eq,
            "eff_dd_peak": eff_dd_peak if eff_dd_peak is not None else eff_dd_eq,
            "eff_dd_scope": eff_dd_scope,
        }

    def has_open_positions_fast(self) -> bool:
        """Lock-minimal check used by the 50ms loop to skip redundant idle WAIT cycles."""
        with self._lock:
            if self._open_position_meta:
                return True
        venues_map = getattr(self._router, "venues", None)
        if isinstance(venues_map, Mapping):
            for venue in venues_map.values():
                if isinstance(venue, Mt5PaperBrokerVenue) and bool(venue.positions):
                    return True
        return False

    def metrics_summary(self) -> dict[str, Any]:
        """Lightweight 0-broker-I/O trader summary for /api/metrics."""
        with self._lock:
            q_status = self._last_quota_status
            if not q_status and hasattr(self._quota, "peek_snapshot"):
                q_snap = self._quota.peek_snapshot(now=self._now())
                q_status = str(q_snap.get("status", ""))
                self._last_quota_status = q_status
                self._last_consec_losses = max(0, int(q_snap.get("consecutive_losses", 0) or 0))
            eff_status = (
                q_status
                if q_status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED, QUOTA_STATUS_LOSS_TRIPPED)
                else self._governance_mode
            )
            return {
                "governance_mode": str(self._governance_mode),
                "effective_status": str(eff_status),
                "cycle_count": int(self._cycle_seq),
                "veto_count": int(self._veto_count),
            }

    def dial_context_summary(self) -> dict[str, Any]:
        """Lightweight 0-broker-I/O context summary for /api/aggression-dial."""
        with self._lock:
            q_status = self._last_quota_status
            consec = int(self._last_consec_losses)
            if not q_status and hasattr(self._quota, "peek_snapshot"):
                q_snap = self._quota.peek_snapshot(now=self._now())
                q_status = str(q_snap.get("status", ""))
                consec = max(0, int(q_snap.get("consecutive_losses", 0) or 0))
                self._last_quota_status = q_status
                self._last_consec_losses = consec
            return {
                "last_regime": str(self._last_regime or "NEUTRAL"),
                "consecutive_losses": consec,
                "drawdown_pct": decimal_text(self._last_drawdown_pct),
                "last_valve_score": self._last_valve_score,
            }

    @staticmethod
    def _format_offline_broker_notice(offline_ids: list[str], online_eq_q: Decimal) -> str | None:
        if not offline_ids:
            return None
        labels: list[str] = []
        for b in offline_ids:
            lbl = friendly_broker_label(b)
            if lbl not in labels:
                labels.append(lbl)
        names_text = ", ".join(labels)
        verb = "is" if len(labels) == 1 else "are"
        return (
            f"{names_text} {verb} temporarily offline — disconnected account equity is excluded from "
            f"trading loss and drawdown checks (verified online funds: ${decimal_text(online_eq_q)}; "
            f"not a trading loss)."
        )

    _build_offline_broker_notice = _format_offline_broker_notice

    def _resolve_master_dial_summary_unlocked(
        self,
        *,
        regime: str,
        total_eq: Decimal,
        peak_eq: Decimal,
        quota_snap: Mapping[str, Any],
        raw_dial: Mapping[str, Any] | None,
        dd_curr_eq: Decimal | None = None,
    ) -> dict[str, Any] | None:
        if raw_dial is None:
            return None
        cap_base = (
            total_eq
            if total_eq > Decimal("0")
            else (self._explicit_initial_capital_usd or REFERENCE_CAPITAL_USD)
        )
        eff_curr = dd_curr_eq if dd_curr_eq is not None else total_eq
        raw_dd = (
            compute_drawdown_pct(eff_curr, peak_eq)
            if (peak_eq > Decimal("0") and eff_curr > Decimal("0"))
            else Decimal("0")
        )
        dd_q = max(Decimal("0"), raw_dd.quantize(Decimal("0.000001"), rounding=ROUND_CEILING))
        consec = max(0, int(quota_snap.get("consecutive_losses", 0) or 0))
        v_score_dec = Decimal("0.60")
        if self._last_valve_score not in (None, ""):
            try:
                parsed_vs = Decimal(str(self._last_valve_score))
                if parsed_vs.is_finite():
                    v_score_dec = min(
                        Decimal("1.00"),
                        max(Decimal("0.00"), parsed_vs.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)),
                    )
            except (InvalidOperation, ValueError, TypeError):
                v_score_dec = Decimal("0.60")
        clean_reg = str(regime or self._last_regime or REGIME_TREND_IGNITION).strip().upper() or REGIME_TREND_IGNITION
        eff = resolve_dial_effective_params(
            int(raw_dial["master_risk_bps"]),
            cap_base,
            ai_discretion_enabled=bool(raw_dial["ai_discretion_enabled"]),
            ai_discretion_ceiling_bps=int(raw_dial["ai_discretion_ceiling_bps"]),
            regime=clean_reg,
            consecutive_losses=consec,
            drawdown_pct=dd_q,
            valve_score=v_score_dec,
        )
        return {
            "schema": "cas-forex.aggression-dial-summary/1",
            "scope_id": str(raw_dial["scope_id"]),
            "master_risk_bps": int(eff["requested_risk_bps"]),
            "master_risk_pct": str(eff["requested_risk_pct"]),
            "effective_risk_bps": int(eff["effective_risk_bps"]),
            "effective_risk_pct": str(eff["effective_risk_pct"]),
            "effective_label": str(eff["effective_label"]),
            "css_class": str(eff["css_class"]),
            "ai_discretion_enabled": bool(eff["ai_discretion_enabled"]),
            "ai_discretion_ceiling_bps": int(eff["ai_discretion_ceiling_bps"]),
            "ai_discretion_reason": str(eff["ai_discretion_reason"]),
            "ai_discretion_shifted": bool(eff["ai_discretion_shifted"]),
            "ai_discretion_direction": str(eff["ai_discretion_direction"]),
            "capital_usd": str(eff["capital_usd"]),
            "risk_per_trade_usd": str(eff["risk_per_trade_usd"]),
            "max_open_trades": int(eff["max_open_trades"]),
            "min_signal_prob": str(eff["min_signal_prob"]),
            "session_goal_usd": str(eff["session_goal_usd"]),
            "soft_goal_usd": str(eff["soft_goal_usd"]),
            "daily_loss_brake_usd": str(eff["daily_loss_brake_usd"]),
            "max_drawdown_pct": str(eff["max_drawdown_pct"]),
            "regime": str(eff["regime"]),
            "consecutive_losses": int(eff["consecutive_losses"]),
            "drawdown_pct": str(eff["drawdown_pct"]),
            "valve_score": str(eff["valve_score"]),
            "audit_count": int(raw_dial["audit_count"]),
            "audit_head_sha256": str(raw_dial["audit_head_sha256"]),
        }

    @property
    def risk_gear_mode(self) -> str:
        with self._lock:
            return self._risk_gear_mode

    def _resolve_risk_gear(
        self,
        *,
        regime: str,
        total_eq: Decimal,
        peak_eq: Decimal,
        quota_snap: Mapping[str, Any],
    ) -> dict[str, Any]:
        dd_pct = compute_drawdown_pct(total_eq, peak_eq) if (peak_eq > Decimal("0") and total_eq > Decimal("0")) else Decimal("0")
        consec = int(quota_snap.get("consecutive_losses", 0) or 0)
        owner_soft = Decimal(str(quota_snap.get("soft_quota_usd", "500")))
        owner_hard = Decimal(str(quota_snap.get("hard_quota_usd", "1000")))
        resolved = resolve_adaptive_risk_and_quota(
            owner_gear_mode=self._risk_gear_mode,
            regime=regime,
            drawdown_pct=dd_pct,
            consecutive_losses=consec,
            owner_max_risk_pct=self._router.barbell.max_stop_loss_equity_risk_pct,
            owner_max_drawdown_pct=self._router.barbell.max_drawdown_pct,
            owner_soft_quota_usd=owner_soft,
            owner_hard_quota_usd=owner_hard,
        )
        self._last_risk_gear = resolved
        return resolved

    def set_risk_gear_mode(
        self,
        mode: str,
        *,
        reason: str = "Overseer updated risk gear mode",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        clean = str(mode or "").strip().upper()
        if clean not in VALID_RISK_GEAR_MODES:
            raise ContractError(f"risk_gear must be one of {VALID_RISK_GEAR_MODES}")
        ts = self._now(now)
        with self._lock:
            self._risk_gear_mode = clean
            if self._risk_gear_path is not None and not self._risk_gear_path.is_symlink():
                try:
                    self._risk_gear_path.parent.mkdir(parents=True, exist_ok=True)
                    self._risk_gear_path.write_text(
                        json.dumps({"risk_gear_mode": clean, "updated_at": _iso(ts)}) + "\n",
                        encoding="utf-8",
                    )
                except OSError as exc:
                    logger.warning("Failed to persist risk_gear_mode: %s", type(exc).__name__)
            self._recent_actions.append({
                "observed_at": _iso(ts),
                "kind": "SET_RISK_GEAR",
                "symbol": None,
                "detail": f"Risk gear mode set to {clean} ({reason})",
            })
        return self.status_snapshot(now=ts)

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
        scope_id: str | None = None,
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
            scope_id=scope_id,
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
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        bal_sum = Decimal("0")
        free_sum = Decimal("0")
        inventory: list[dict[str, Any]] = []
        has_venue_acct = False
        for broker_id, venue in self._router.venues.items():
            if isinstance(venue, Mt5PaperBrokerVenue) and venue.account is not None:
                if getattr(venue, "is_offline", False):
                    continue
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
                if callable(getattr(self._router, "is_broker_offline", None)) and self._router.is_broker_offline(broker_id):
                    continue
                has_venue_acct = True
                bal_sum += venue.nav or Decimal("0")
                free_sum += venue.margin_available or Decimal("0")
                if venue.summary is not None and callable(getattr(venue, "positions", None)):
                    for pos in venue.positions(refresh=False):
                        inventory.append({
                            "broker_id": broker_id,
                            "ticket": pos.ticket,
                            "symbol": pos.symbol,
                            "side": pos.side.value,
                            "volume_lots": decimal_text(pos.volume_lots),
                        })
        balance_val = bal_sum if has_venue_acct and bal_sum > Decimal("0") else total_eq
        margin_val = free_sum if has_venue_acct else total_eq
        router_dd = self._router.barbell.max_drawdown_pct
        if router_dd > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
            raise ContractError(
                f"router max_drawdown_pct {decimal_text(router_dd)} exceeds immutable constitutional 0.10 ceiling"
            )
        eff_dd_cap = min(router_dd, MAX_CONSTITUTIONAL_DRAWDOWN_PCT)
        return {
            "balance": decimal_text(balance_val),
            "equity": decimal_text(total_eq),
            "peak_equity": decimal_text(peak_eq),
            "available_margin": decimal_text(margin_val),
            "position_inventory": json.dumps(inventory, sort_keys=True),
            "scope_id": str(scope_id).strip() if (isinstance(scope_id, str) and scope_id.strip()) else "dual-shield-barbell",
            "policy": {
                "new_risk_permission": new_risk_permission,
                "management_permission": management_permission,
                "max_entry_quantity": "10000000",
                "max_drawdown_pct": decimal_text(eff_dd_cap),
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

    def _estimate_broker_closed_pnl(
        self,
        meta: Mapping[str, Any],
        *,
        venue: Mt5PaperBrokerVenue,
        quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
    ) -> Decimal:
        raw_profit = meta.get("profit")
        pnl_dec = Decimal("0")
        if raw_profit is not None and str(raw_profit).strip() != "":
            try:
                parsed = Decimal(str(raw_profit).strip())
                if parsed.is_finite():
                    pnl_dec = parsed
            except (ValueError, TypeError, ArithmeticError):
                pnl_dec = Decimal("0")

        if pnl_dec == Decimal("0"):
            sym = str(meta.get("symbol") or "").strip()
            side_str = str(meta.get("side") or "").strip().upper()
            raw_entry = meta.get("entry_price")
            raw_sl = meta.get("stop_loss")
            raw_lots = meta.get("volume_lots", "1")
            try:
                entry_px = (
                    Decimal(str(raw_entry).strip())
                    if raw_entry is not None and str(raw_entry).strip() != ""
                    else None
                )
                exit_px: Decimal | None = None
                if quotes is not None and sym in quotes:
                    q_bid, q_ask = quotes[sym]
                    exit_px = Decimal(str(q_bid)) if side_str == Side.BUY.value else Decimal(str(q_ask))
                else:
                    try:
                        tick = venue._transport.symbol_tick(sym)
                        exit_px = tick.bid if side_str == Side.BUY.value else tick.ask
                    except Exception as exc:
                        logger.debug("closed ticket %s tick fallback unavailable: %s", sym, type(exc).__name__)
                        exit_px = None
                if exit_px is None and raw_sl is not None and str(raw_sl).strip() != "":
                    exit_px = Decimal(str(raw_sl).strip())
                lots_dec = (
                    Decimal(str(raw_lots).strip())
                    if raw_lots is not None and str(raw_lots).strip() != ""
                    else Decimal("0")
                )
                if (
                    entry_px is not None
                    and exit_px is not None
                    and entry_px.is_finite()
                    and exit_px.is_finite()
                    and entry_px > Decimal("0")
                    and exit_px > Decimal("0")
                    and lots_dec.is_finite()
                    and lots_dec > Decimal("0")
                    and side_str in (Side.BUY.value, Side.SELL.value)
                ):
                    units = venue.margin_calculator.lots_to_units(lots_dec, symbol=sym)
                    diff = (exit_px - entry_px) if side_str == Side.BUY.value else (entry_px - exit_px)
                    conv = Decimal("1")
                    try:
                        _, q_ccy = venue.margin_calculator.split_symbol(sym)
                        if q_ccy != venue.margin_calculator.account_currency:
                            if quotes is not None:
                                conv = venue.margin_calculator.conversion_rate(q_ccy, quotes)
                            elif sym.startswith(venue.margin_calculator.account_currency) and exit_px > Decimal("0"):
                                conv = Decimal("1") / exit_px
                    except (ContractError, ArithmeticError, ValueError, TypeError):
                        conv = Decimal("1")
                    pnl_dec = diff * units * conv
            except (ContractError, ValueError, TypeError, ArithmeticError):
                pnl_dec = Decimal("0")

        return pnl_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def protect_open_positions(
        self,
        *,
        quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Protect open MT5 positions (50ms breakeven/trail & broker SL/TP close accounting)."""
        return self.evaluate_fast_protection(quotes=quotes, now=now)

    def _fast_in_recovery_mode_unlocked(
        self,
        total_eq: Decimal,
        *,
        equities: Mapping[str, Decimal] | None = None,
        offline_brokers: Sequence[str] | None = None,
    ) -> tuple[bool, Decimal | None]:
        """Zero-SQLite in-memory principal check for the 50ms stop-protection hot path."""
        ps_fast = self._principal_surplus_metrics(
            total_eq,
            equities=equities,
            offline_brokers=offline_brokers,
        )
        return bool(ps_fast["in_recovery_mode"]), ps_fast["configured_initial_capital_usd"]

    def evaluate_fast_protection(
        self,
        *,
        quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        now: datetime | None = None,
        _out_equity_bundle: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Instant Snap-to-Breakeven & Monotonic Trailing Stop across all open MT5 positions (0 vault SQLite I/O on hot path)."""
        ts = self._now(now)
        actions: list[dict[str, Any]] = []
        deferred_vault_closes: list[tuple[str, str, str, Decimal, str, Decimal, Decimal | None]] = []
        deferred_p8_protections: list[
            tuple[str, str, TradeActionType, str, str, Side, Decimal, Decimal, Decimal, Decimal | None, str]
        ] = []
        deferred_p8_closes: list[
            tuple[str, str, ExecutionEventType, str, Side, Decimal, Decimal, Decimal, Decimal]
        ] = []
        had_stale_close = False
        with self._lock:
            if self._governance_mode == GOVERNANCE_STOPPED:
                return actions
            eq_bundle_fast = self._router_equity_bundle_unlocked()
            if _out_equity_bundle is not None:
                _out_equity_bundle.update(eq_bundle_fast)
            equities = eq_bundle_fast["equities"]
            total_eq = eq_bundle_fast["total_eq"]
            eff_dd_eq_fast = eq_bundle_fast["eff_dd_eq"]
            peak_eq = eq_bundle_fast["eff_dd_peak"]
            in_rec_fast, fast_init_cap = self._fast_in_recovery_mode_unlocked(
                total_eq,
                equities=equities,
                offline_brokers=eq_bundle_fast["offline_brokers"],
            )
            _, _, risk_mult = self._quota.evaluate_new_risk(
                ActionKind.OPEN,
                now=ts,
                starting_equity=total_eq,
                in_recovery_mode=in_rec_fast,
            )
            if risk_mult <= Decimal("0"):
                risk_mult = Decimal("0.50")

            for broker_id, venue in list(self._router.venues.items()):
                if not isinstance(venue, Mt5PaperBrokerVenue) or venue.account is None:
                    continue
                already_synced = isinstance(self._router, DualShieldBrokerRouter) and isinstance(
                    venue._transport, Mt5SpoolBridgeTransport
                )
                if not already_synced:
                    try:
                        venue.probe()
                    except Exception as exc:
                        logger.warning("fast protection probe failed for %s: %s", broker_id, type(exc).__name__)
                        continue
                if getattr(venue, "is_offline", False):
                    continue

                for pos in venue.positions:
                    if pos.ticket in self._open_position_meta:
                        self._open_position_meta[pos.ticket]["profit"] = decimal_text(pos.profit)

                # 1. PROTECT OPEN POSITIONS FIRST (zero ledger/vault calls ahead of SL tightening)
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

                    prev_meta = self._open_position_meta.get(pos.ticket, {})
                    self._open_position_meta[pos.ticket] = {
                        **prev_meta,
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
                            total_eq=eff_dd_eq_fast,
                            peak_eq=peak_eq,
                            position_side=pos.side,
                            scope_id=eq_bundle_fast.get("eff_dd_scope"),
                            now=ts,
                        )
                        order = OrderIntent.from_action_intent(intent, symbol=sym, position_ticket=pos.ticket)
                        self._router.execute_management(broker_id, order, valve_decision=dec)
                        self._protection_stage[pos.ticket] = new_stage
                        self._open_position_meta[pos.ticket]["stop_loss"] = decimal_text(candidate_sl)
                        self._open_position_meta[pos.ticket]["protection_stage"] = new_stage
                        if self._phase8_bridge is not None:
                            p8_act = (
                                TradeActionType.MOVE_BREAKEVEN
                                if new_stage == "BREAKEVEN_LOCKED"
                                else TradeActionType.TRAIL_STOP
                            )
                            deferred_p8_protections.append((
                                broker_id,
                                sym,
                                p8_act,
                                str(intent.intent_id),
                                str(pos.ticket),
                                pos.side,
                                pos.volume_lots,
                                current_price,
                                candidate_sl,
                                pos.take_profit,
                                f"Instant {new_stage} SL->{decimal_text(candidate_sl)}",
                            ))
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

                # 2. Record broker-closed stale tickets into quota AFTER open positions are protected
                live_tickets = {p.ticket for p in venue.positions}
                for stale_tkt in [
                    t for t, meta in self._open_position_meta.items()
                    if meta.get("broker_id") == broker_id and t not in live_tickets
                ]:
                    meta = self._open_position_meta.get(stale_tkt)
                    if isinstance(meta, Mapping):
                        sym_closed = str(meta.get("symbol") or "").strip()
                        if sym_closed:
                            pnl_dec = self._estimate_broker_closed_pnl(
                                meta, venue=venue, quotes=quotes
                            )
                            safe_ticket = re.sub(r"[^A-Za-z0-9_.-]", "-", str(stale_tkt))[:64]
                            if not safe_ticket or not safe_ticket[0].isalnum():
                                safe_ticket = f"tkt-{safe_ticket}"[:64]
                            try:
                                eq_map_post = self._router.equities()
                                eq_post = self._router.barbell.total_equity(eq_map_post)
                                in_rec_post, cap_post = self._fast_in_recovery_mode_unlocked(
                                    eq_post, equities=eq_map_post
                                )
                                q_closed = self._quota.record_realized_trade(
                                    pnl_dec,
                                    symbol=sym_closed,
                                    ticket=safe_ticket,
                                    trade_id=safe_ticket,
                                    broker_id=broker_id,
                                    starting_equity=eq_post if eq_post > Decimal("0") else None,
                                    now=ts,
                                    in_recovery_mode=in_rec_post,
                                )
                                had_stale_close = True
                                if self._phase8_bridge is not None:
                                    raw_side_c = str(meta.get("side") or "BUY").strip().upper()
                                    side_c = Side.SELL if raw_side_c == Side.SELL.value else Side.BUY
                                    try:
                                        lots_c = max(Decimal("0.01"), Decimal(str(meta.get("volume_lots", "0.01"))))
                                    except (InvalidOperation, ValueError, TypeError):
                                        lots_c = Decimal("0.01")
                                    try:
                                        px_c = max(Decimal("0.00"), Decimal(str(meta.get("entry_price", "1"))))
                                    except (InvalidOperation, ValueError, TypeError):
                                        px_c = Decimal("1.00")
                                    ev_t_c = ExecutionEventType.TP_HIT if pnl_dec > Decimal("0") else ExecutionEventType.SL_HIT
                                    deferred_p8_closes.append((
                                        broker_id,
                                        sym_closed,
                                        ev_t_c,
                                        safe_ticket,
                                        side_c,
                                        lots_c,
                                        px_c,
                                        pnl_dec,
                                        eq_post,
                                    ))
                                if pnl_dec > Decimal("0"):
                                    deferred_vault_closes.append((
                                        safe_ticket,
                                        sym_closed,
                                        broker_id,
                                        pnl_dec,
                                        str(q_closed.get("session_date", "")),
                                        eq_post,
                                        cap_post if cap_post is not None else fast_init_cap,
                                    ))
                                if q_closed["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                                    self._current_focus_status = (
                                        f"RESEARCH_RESPITE: Profits Banked ({q_closed['realized_net_pnl_usd']} USD · "
                                        f"Floor {q_closed['protected_profit_floor_usd']} USD) · "
                                        f"Observing {self._top_watch_symbol or '20 MARKETS'}"
                                    )
                            except ContractError as exc:
                                logger.warning(
                                    "fast protection close accounting skipped for %s: %s",
                                    safe_ticket,
                                    type(exc).__name__,
                                )
                    self._open_position_meta.pop(stale_tkt, None)
                    self._peak_favorable.pop(stale_tkt, None)
                    self._protection_stage.pop(stale_tkt, None)

        # 3. OUTSIDE self._lock: dispatch Phase 8 protective/close events & flush closed-trade vault sweeps
        if self._phase8_bridge is not None and (deferred_p8_protections or deferred_p8_closes):
            for (
                brk_p,
                sym_p,
                act_p,
                oid_p,
                tkt_p,
                side_p,
                lots_p,
                px_p,
                sl_p,
                tp_p,
                rsn_p,
            ) in deferred_p8_protections:
                try:
                    self._phase8_bridge.dispatch_protective_action(
                        broker_id=self._resolve_phase8_broker_id(brk_p),
                        symbol=sym_p,
                        action=act_p,
                        order_id=oid_p,
                        position_ticket=tkt_p,
                        side=side_p,
                        quantity_lots=lots_p,
                        price=px_p,
                        stop_loss=sl_p,
                        take_profit=tp_p,
                        reason=rsn_p,
                        now_utc=ts,
                    )
                except Exception as exc_p8p:
                    logger.warning("phase8 protective dispatch skipped for %s: %s", tkt_p, type(exc_p8p).__name__)
            for brk_c, sym_c, evt_c, tkt_c, side_c, lots_c, px_c, pnl_c, eq_c in deferred_p8_closes:
                try:
                    self._phase8_bridge.record_broker_fill_or_close(
                        broker_id=self._resolve_phase8_broker_id(brk_c),
                        symbol=sym_c,
                        event_type=evt_c,
                        event_id=f"close-{tkt_c}-{int(ts.timestamp() * 1000)}",
                        order_id=f"ord-{tkt_c}",
                        position_ticket=tkt_c,
                        side=side_c,
                        quantity_lots=lots_c,
                        price=px_c,
                        realized_pnl_usd=pnl_c,
                        current_equity_usd=eq_c if eq_c > Decimal("0") else None,
                        now_utc=ts,
                    )
                except Exception as exc_p8c:
                    logger.warning("phase8 close publish skipped for %s: %s", tkt_c, type(exc_p8c).__name__)
        if had_stale_close and self._profit_vault is not None:
            try:
                comp_cap = self._compounding_starting_principal_ro()
                for t_id, sym_c, brk_c, pnl_c, sdate_c, eq_c, cap_c in deferred_vault_closes:
                    eff_cap_c = cap_c if cap_c is not None else comp_cap
                    econ_eq_c = eq_c + self._cached_settled_disbursed_usd
                    self._sync_vault_sweep_ratio_for_write(econ_eq_c)
                    self._profit_vault.record_realized_close(
                        trade_id=t_id,
                        symbol=sym_c,
                        broker_id=brk_c,
                        realized_net_usd=pnl_c,
                        occurred_at=ts,
                        session_date=sdate_c,
                        total_equity_usd=eq_c,
                        initial_capital_usd=eff_cap_c,
                    )
                self.sync_session_profit_to_vault(now=ts)
            except Exception as exc_vsync:
                with self._lock:
                    self._last_vault_sync_error = type(exc_vsync).__name__
                logger.warning("fast protection post-lock vault sync deferred: %s", type(exc_vsync).__name__)
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
        online_eq_map = (
            self._router.online_equities()
            if callable(getattr(self._router, "online_equities", None))
            else self._router.equities()
        )
        eff_eq = (
            self._router.barbell.effective_total_equity(online_eq_map)
            if hasattr(self._router.barbell, "effective_total_equity")
            else total_equity
        )
        if (
            eff_eq <= Decimal("0")
            and callable(getattr(self._router, "offline_brokers", None))
            and self._router.offline_brokers()
        ):
            raise ContractError("no online verified broker equity available for sizing")
        sizing_equity = min(total_equity, eff_eq) if eff_eq > Decimal("0") else total_equity
        constitutional_max_budget = (sizing_equity * MAX_CONSTITUTIONAL_STOP_RISK_PCT) / Decimal("100")
        budget = min(
            self._router.barbell.max_stop_risk_amount(sizing_equity) * risk_multiplier,
            constitutional_max_budget,
        )
        active_mt5: tuple[str, Mt5PaperBrokerVenue] | None = None
        first_mt5: Mt5PaperBrokerVenue | None = None
        for bid_id in self._router.priority_order:
            venue = self._router.venues.get(bid_id)
            if isinstance(venue, Mt5PaperBrokerVenue):
                if first_mt5 is None:
                    first_mt5 = venue
                if venue.account is not None and not getattr(venue, "is_offline", False) and active_mt5 is None:
                    active_mt5 = (bid_id, venue)
        calc_venue = active_mt5[1] if active_mt5 is not None else first_mt5
        if calc_venue is not None:
            csize = calc_venue.margin_calculator.contract_size_for(symbol)
        else:
            csize = (
                MT5_GOLD_CONTRACT_SIZE
                if symbol == "XAUUSD"
                else (MT5_INDEX_CONTRACT_SIZE if symbol in INDEX_INSTRUMENTS else MT5_CONTRACT_SIZE)
            )
        step_units = csize * MT5_VOLUME_STEP
        max_units_cap = csize * MT5_MAX_VOLUME_DEFAULT
        with localcontext() as ctx:
            ctx.prec = 40
            raw_units = min(budget / stop_dist, max_units_cap)
            # Also honor the active MT5 venue's max_lots cap, margin level floor (>= 1000%), & barbell sleeve cap.
            if active_mt5 is not None and symbol in quotes_map:
                bid_id, venue = active_mt5
                acct = venue.account
                if acct is not None:
                    v_max_lots = getattr(venue, "_max_lots", MT5_MAX_VOLUME_DEFAULT)
                    raw_units = min(raw_units, v_max_lots * csize)
                    min_ml = venue.min_margin_level_pct
                    max_used_ml = (acct.equity * Decimal("100")) / max(min_ml, Decimal("100"))
                    sleeve_lim = self._router.barbell.share_for(bid_id) * sizing_equity
                    rem_margin = min(
                        max(Decimal("0"), max_used_ml - acct.margin),
                        max(Decimal("0"), sleeve_lim - acct.margin),
                        max(Decimal("0"), acct.margin_free),
                    ) * Decimal("0.95")
                    one_step_margin = venue.margin_calculator.required_margin(symbol, side, step_units, quotes_map)
                    if one_step_margin > Decimal("0"):
                        max_margin_units = (rem_margin / one_step_margin) * step_units
                        raw_units = min(raw_units, max_margin_units)
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

    def _assess_setup_and_pyramid(
        self,
        markets: Mapping[str, Mapping[str, Any]],
        *,
        quotes_map: Mapping[str, tuple[Decimal, Decimal]],
        total_eq: Decimal,
        deployable_eq: Decimal,
        risk_mult: Decimal,
        fast_tick: bool,
        allow_cold_open: bool,
        peak_eq: Decimal | None = None,
        quota_snap: Mapping[str, Any] | None = None,
        raw_dial: Mapping[str, Any] | None = None,
    ) -> tuple[str, Side, Decimal, Decimal, str, str, bool, str | None, int] | None:
        """Scan watchlist with TrendRegimeDetector, House-Money ADD pyramiding, and correlation cap."""
        self._last_dial_skip_reason = None
        ordered_syms = list(INDEX_INSTRUMENTS) + [s for s in markets if s not in INDEX_INSTRUMENTS]
        open_meta_list = list(self._open_position_meta.values())
        best_ratio = Decimal("-1")
        best_sym: str | None = None
        best_reg: str | None = None
        dial_cap_block: str | None = None
        for sym in ordered_syms:
            info = markets.get(sym)
            if not info:
                continue
            try:
                bid = Decimal(str(info["bid"]))
                ask = Decimal(str(info["ask"]))
            except (KeyError, ValueError, TypeError, ArithmeticError):
                continue
            if ask <= bid:
                continue
            spread = ask - bid
            params = self._protection_cfg(sym, max(risk_mult, Decimal("0.50")))
            hist = list(self._tick_history.get(sym, ()))
            if len(hist) < 3:
                if fast_tick and sym not in INDEX_INSTRUMENTS:
                    continue
                continue
            mids = [(b + a) / Decimal("2") for b, a in hist[-50:]]
            regime_res = self._trend_detector.classify(
                mids=mids,
                spread=spread,
                normal_sl_distance=params["sl_distance"],
            )
            move_ratio = abs(mids[-1] - mids[0]) / max(spread, Decimal("0.000000001"))
            if move_ratio > best_ratio:
                best_ratio = move_ratio
                best_sym = sym
                best_reg = regime_res.regime
            if regime_res.regime in (REGIME_SPREAD_SPIKE, REGIME_CHOP_RANGE) or regime_res.direction is None:
                # Preserve direct 3-tick fast-ignition burst detection when mids delta >= 3x spread
                tail_mids = mids[-5:]
                burst = tail_mids[-1] - tail_mids[0]
                exp_min = spread * Decimal("3") if sym in INDEX_INSTRUMENTS else spread * Decimal("4")
                if not (abs(burst) >= exp_min and spread <= params["sl_distance"] * Decimal("0.25")):
                    continue
                side = Side.BUY if burst > Decimal("0") else Side.SELL
                regime_name = REGIME_TREND_IGNITION
                setup_note = f"50ms burst delta={decimal_text(burst)} > spread-gate={decimal_text(exp_min)}"
            else:
                side = regime_res.direction
                regime_name = regime_res.regime
                setup_note = regime_res.reason

            if any(m.get("symbol") == sym and m.get("side") != side.value for m in open_meta_list):
                continue

            cand_dial = (
                self._resolve_master_dial_summary_unlocked(
                    regime=regime_name,
                    total_eq=deployable_eq if deployable_eq > Decimal("0") else total_eq,
                    peak_eq=peak_eq if peak_eq is not None else total_eq,
                    quota_snap=quota_snap or {},
                    raw_dial=raw_dial,
                    dd_curr_eq=total_eq,
                )
                if raw_dial is not None
                else None
            )
            if cand_dial is not None:
                max_open_cap = int(cand_dial["max_open_trades"])
                if len(open_meta_list) >= max_open_cap:
                    dial_cap_block = (
                        f"DIAL_MAX_OPEN_TRADES_REACHED ({len(open_meta_list)}>={max_open_cap} "
                        f"at {cand_dial['effective_risk_pct']}% {cand_dial['effective_label']})"
                    )
                    continue

            matching = [
                m for m in open_meta_list
                if m.get("symbol") == sym and m.get("side") == side.value
            ]
            if matching:
                if len(matching) >= MAX_PYRAMID_LEGS:
                    continue
                if regime_name not in (REGIME_STRONG_TREND, REGIME_TREND_IGNITION):
                    continue
                t_sz = _tick_size(sym)
                entry_ref = ask if side is Side.BUY else bid
                sl_px = (
                    (bid - params["sl_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                    if side is Side.BUY
                    else (ask + params["sl_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                )
                cand_qty = self._compute_quantity(
                    symbol=sym,
                    side=side,
                    bid=bid,
                    ask=ask,
                    sl_price=sl_px,
                    total_equity=deployable_eq,
                    risk_multiplier=risk_mult if risk_mult > Decimal("0") else Decimal("0.50"),
                    quotes_map=quotes_map,
                )
                _, q_ccy = self._router.barbell._calc.split_symbol(sym)
                conv = self._router.barbell._calc.conversion_rate(q_ccy, quotes_map) if quotes_map else Decimal("1")
                legs = [
                    PyramidLegSnapshot(
                        ticket=str(m["ticket"]),
                        symbol=sym,
                        side=side,
                        units=Decimal(str(m.get("volume_lots", "1"))) * (
                            Decimal("1") if sym in INDEX_INSTRUMENTS else Decimal("100000")
                        ),
                        entry_price=Decimal(str(m["entry_price"])),
                        stop_loss=Decimal(str(m["stop_loss"])) if m.get("stop_loss") else None,
                        protection_stage=str(m.get("protection_stage", "INITIAL_SL")),
                    )
                    for m in matching
                ]
                pyr = evaluate_house_money_pyramid_leg(
                    symbol=sym,
                    side=side,
                    regime=regime_name,
                    existing_legs=legs,
                    new_leg_entry=entry_ref,
                    new_leg_stop=sl_px,
                    new_leg_units=cand_qty,
                    quote_to_usd=conv,
                )
                if not pyr.allowed:
                    continue
                self._last_evaluated_symbol = sym
                self._last_evaluated_regime = regime_name
                self._top_watch_symbol = best_sym or sym
                return (
                    sym,
                    side,
                    bid,
                    ask,
                    f"{setup_note} [{pyr.reason}]",
                    regime_name,
                    True,
                    str(matching[0]["ticket"]),
                    len(matching) + 1,
                )

            if not allow_cold_open:
                continue
            corr_ok, _ = evaluate_correlation_cap(
                candidate_symbol=sym,
                candidate_side=side,
                open_positions=open_meta_list,
                is_pyramid_add=False,
            )
            if not corr_ok:
                continue
            if fast_tick and sym not in INDEX_INSTRUMENTS and abs(mids[-1] - mids[-min(len(mids), 5)]) < spread * Decimal("4"):
                continue
            self._last_evaluated_symbol = sym
            self._last_evaluated_regime = regime_name
            self._top_watch_symbol = best_sym or sym
            return sym, side, bid, ask, setup_note, regime_name, False, None, 1
        if best_sym is not None:
            self._top_watch_symbol = best_sym
            self._last_evaluated_symbol = best_sym
            self._last_evaluated_regime = best_reg
            if best_reg in (
                REGIME_TREND_IGNITION,
                REGIME_STRONG_TREND,
                REGIME_CHOP_RANGE,
                REGIME_SPREAD_SPIKE,
            ):
                self._last_regime = str(best_reg)
        self._last_dial_skip_reason = dial_cap_block
        return None

    def _read_vault_snapshot_outside_lock(self) -> Mapping[str, Any]:
        if self._profit_vault is None:
            return {}
        try:
            v_data = self._profit_vault.snapshot()
            with self._lock:
                raw_ic = v_data.get("initial_capital_usd")
                self._cached_vault_init_cap = (
                    Decimal(str(raw_ic)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    if raw_ic not in (None, "")
                    else None
                )
                self._cached_settled_disbursed_usd = Decimal(
                    str(v_data.get("confirmed_settled_disbursed_usd", "0") or "0")
                ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            return v_data
        except Exception as exc_vs:
            logger.debug("profit vault snapshot skipped: %s", type(exc_vs).__name__)
            return {}

    def _resolve_initial_capital_usd(
        self,
        v_snap: Mapping[str, Any] | None = None,
        *,
        allow_vault_io: bool = True,
    ) -> Decimal | None:
        if self._profit_vault is not None:
            if v_snap is not None and v_snap.get("initial_capital_usd") not in (None, ""):
                return Decimal(str(v_snap["initial_capital_usd"])).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
            if self._cached_vault_init_cap is not None:
                return self._cached_vault_init_cap
            if allow_vault_io and v_snap is None and hasattr(self._profit_vault, "configured_initial_capital_usd"):
                try:
                    v_cfg = self._profit_vault.configured_initial_capital_usd()
                    if v_cfg is not None:
                        self._cached_vault_init_cap = v_cfg
                        return v_cfg
                except Exception as exc_vcfg:
                    logger.debug("vault initial capital lookup skipped: %s", type(exc_vcfg).__name__)
        if self._explicit_initial_capital_usd is not None:
            return self._explicit_initial_capital_usd
        raw_env_cap = str(self._router._env.get(ENV_INITIAL_CAPITAL_USD, "")).strip()
        if raw_env_cap:
            try:
                parsed_cap = Decimal(raw_env_cap)
                if parsed_cap.is_finite() and parsed_cap > Decimal("0"):
                    return parsed_cap.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            except (ValueError, ArithmeticError):
                pass
        configured_count = sum(
            1
            for b_id in self._router.priority_order
            if self._router.is_configured(b_id) or b_id in self._router.venues
        )
        if self._router.execution_mode == "DEMO" and configured_count == 3:
            return DEFAULT_DEMO_3BROKER_CAPITAL_USD
        if self._router.execution_mode == "LIVE":
            if self._router._initial_peak_equity is not None and self._router._initial_peak_equity > Decimal("0"):
                return self._router._initial_peak_equity.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            bal_sum = Decimal("0.00")
            for venue in self._router.venues.values():
                if isinstance(venue, Mt5PaperBrokerVenue) and venue.account is not None:
                    bal_sum += venue.account.balance
                elif isinstance(venue, OandaPracticeFallbackVenue) and venue.nav is not None:
                    bal_sum += venue.nav
            if bal_sum > Decimal("0.00"):
                return bal_sum.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return None

    def _principal_surplus_metrics(
        self,
        total_eq: Decimal,
        *,
        v_snap: Mapping[str, Any] | None = None,
        equities: Mapping[str, Decimal] | None = None,
        offline_brokers: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        v_data: Mapping[str, Any] = v_snap if v_snap is not None else {}
        settled_disbursed_usd = (
            Decimal(str(v_data.get("confirmed_settled_disbursed_usd", "0") or "0")).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            if v_snap is not None
            else self._cached_settled_disbursed_usd
        )
        offline_ids = (
            list(offline_brokers)
            if offline_brokers is not None
            else (
                list(self._router.offline_brokers())
                if callable(getattr(self._router, "offline_brokers", None))
                else []
            )
        )
        eq_lookup: Mapping[str, Decimal] = (
            equities
            if equities is not None
            else (self._router.equities() if offline_ids else {})
        )
        cold_unknown = tuple(
            sorted(b for b in offline_ids if eq_lookup.get(b, Decimal("0")) <= Decimal("0"))
        )
        if not cold_unknown and self._cold_offline_baseline_eq:
            self._cold_offline_baseline_eq.clear()
        eff_init_cap = self._resolve_initial_capital_usd(v_data, allow_vault_io=False)
        eq_q = total_eq.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        economic_eq = (eq_q + settled_disbursed_usd).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if eff_init_cap is not None:
            principal_usd = eff_init_cap
            if cold_unknown and economic_eq < principal_usd:
                baseline_online = self._cold_offline_baseline_eq.setdefault(cold_unknown, economic_eq)
                online_delta = (economic_eq - baseline_online).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                net_surplus = online_delta
                with localcontext() as ctx:
                    ctx.prec = 28
                    net_surplus_pct = (
                        ((net_surplus / principal_usd) * Decimal("100")).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                        if principal_usd > Decimal("0")
                        else Decimal("0.00")
                    )
                if online_delta < Decimal("0.00"):
                    capital_status = CAPITAL_STATUS_RECOVERY_MODE
                    deficit_usd = (-online_delta).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                else:
                    capital_status = CAPITAL_STATUS_AT_PRINCIPAL
                    deficit_usd = Decimal("0.00")
            else:
                net_surplus = (economic_eq - principal_usd).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                with localcontext() as ctx:
                    ctx.prec = 28
                    net_surplus_pct = (
                        ((net_surplus / principal_usd) * Decimal("100")).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                        if principal_usd > Decimal("0")
                        else Decimal("0.00")
                    )
                if net_surplus < Decimal("0.00"):
                    capital_status = CAPITAL_STATUS_RECOVERY_MODE
                    deficit_usd = (-net_surplus).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                elif net_surplus > Decimal("0.00"):
                    capital_status = CAPITAL_STATUS_IN_SURPLUS
                    deficit_usd = Decimal("0.00")
                else:
                    capital_status = CAPITAL_STATUS_AT_PRINCIPAL
                    deficit_usd = Decimal("0.00")
        else:
            fallback_base = self._router._initial_peak_equity if self._router._initial_peak_equity else eq_q
            principal_usd = Decimal(fallback_base).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            net_surplus = (economic_eq - principal_usd).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            with localcontext() as ctx:
                ctx.prec = 28
                net_surplus_pct = (
                    ((net_surplus / principal_usd) * Decimal("100")).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    )
                    if principal_usd > Decimal("0")
                    else Decimal("0.00")
                )
            capital_status = (
                CAPITAL_STATUS_IN_SURPLUS if net_surplus > Decimal("0.00") else CAPITAL_STATUS_AT_PRINCIPAL
            )
            deficit_usd = Decimal("0.00")
        return {
            "configured_initial_capital_usd": eff_init_cap,
            "principal_usd": principal_usd,
            "current_total_equity_usd": eq_q,
            "economic_equity_usd": economic_eq,
            "net_surplus_usd": net_surplus,
            "net_surplus_pct": net_surplus_pct,
            "deficit_to_principal_usd": deficit_usd,
            "capital_status": capital_status,
            "in_recovery_mode": capital_status == CAPITAL_STATUS_RECOVERY_MODE,
            "vault_sweeps_paused_for_recovery": capital_status != CAPITAL_STATUS_IN_SURPLUS,
            "cold_offline_unknown": bool(cold_unknown),
        }

    def sync_session_profit_to_vault(self, *, now: datetime | None = None) -> dict[str, Any] | None:
        """Explicit write-path reconciliation of current session realized net P&L into ProfitSweepVault (never holds self._lock across vault I/O)."""
        if self._profit_vault is None or not hasattr(self._profit_vault, "reconcile_session_realized_profit"):
            with self._lock:
                self._startup_vault_synced = True
            return None
        ts = self._now(now)
        v_snap = self._read_vault_snapshot_outside_lock()
        with self._lock:
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            ps = self._principal_surplus_metrics(total_eq, v_snap=v_snap, equities=equities)
            dq_snap = self._quota.snapshot(
                now=ts,
                starting_equity=total_eq if total_eq > Decimal("0") else None,
                in_recovery_mode=bool(ps["in_recovery_mode"]),
            )
            sdate = str(dq_snap.get("session_date", "")).strip()
            sess_net = Decimal(str(dq_snap.get("realized_net_pnl_usd", "0")))
            init_cap_arg = ps["configured_initial_capital_usd"]
            econ_eq_sync = ps["economic_equity_usd"]
        if not sdate:
            return None
        if init_cap_arg is None:
            init_cap_arg = self._compounding_starting_principal_ro()
        self._sync_vault_sweep_ratio_for_write(econ_eq_sync)
        res = self._profit_vault.reconcile_session_realized_profit(
            session_date=sdate,
            session_realized_net_usd=sess_net,
            occurred_at=ts,
            total_equity_usd=total_eq,
            initial_capital_usd=init_cap_arg,
        )
        if isinstance(res, Mapping):
            with self._lock:
                raw_ic = res.get("initial_capital_usd")
                self._cached_vault_init_cap = (
                    Decimal(str(raw_ic)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    if raw_ic not in (None, "")
                    else None
                )
                self._cached_settled_disbursed_usd = Decimal(
                    str(res.get("confirmed_settled_disbursed_usd", "0") or "0")
                ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        with self._lock:
            self._startup_vault_synced = True
            self._startup_vault_next_retry_at = None
            self._last_vault_sync_error = None
        return res

    def _attempt_startup_vault_sync_post_protection(self, ts: datetime) -> None:
        """Fault-isolated startup vault sync executed OUTSIDE self._lock ONLY AFTER open-position stop protection."""
        if self._profit_vault is None or not hasattr(self._profit_vault, "reconcile_session_realized_profit"):
            with self._lock:
                self._startup_vault_synced = True
            return
        with self._lock:
            if self._startup_vault_synced:
                return
            if self._startup_vault_next_retry_at is not None and ts < self._startup_vault_next_retry_at:
                return
        try:
            self.sync_session_profit_to_vault(now=ts)
        except Exception as exc_sync:
            retry_at = ts + timedelta(seconds=self._startup_vault_retry_cooldown_seconds)
            with self._lock:
                self._startup_vault_synced = False
                self._startup_vault_next_retry_at = retry_at
                self._last_vault_sync_error = type(exc_sync).__name__
            logger.warning(
                "post-protection startup vault sync deferred (%s); next retry at %s",
                type(exc_sync).__name__,
                _iso(retry_at),
            )

    def record_closed_pnl(
        self,
        pnl_usd: Decimal,
        *,
        symbol: str,
        ticket: str,
        broker_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        v_snap = self._read_vault_snapshot_outside_lock()
        with self._lock:
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            popped_meta = self._open_position_meta.pop(ticket, None)
            active_brk = getattr(self._router, "active_broker_id", None)
            eff_broker = (
                str(broker_id).strip()
                if (broker_id is not None and str(broker_id).strip())
                else (
                    str(popped_meta.get("broker_id")).strip()
                    if (isinstance(popped_meta, Mapping) and popped_meta.get("broker_id"))
                    else (str(active_brk).strip() if active_brk else "DUAL_SHIELD")
                )
            )
            ps = self._principal_surplus_metrics(total_eq, v_snap=v_snap)
            snap = self._quota.record_realized_trade(
                pnl_usd,
                symbol=symbol,
                ticket=ticket,
                trade_id=ticket,
                broker_id=eff_broker,
                starting_equity=total_eq,
                now=ts,
                in_recovery_mode=bool(ps["in_recovery_mode"]),
            )
            if snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                self._current_focus_status = (
                    f"RESEARCH_RESPITE: Profits Banked ({snap['realized_net_pnl_usd']} USD · "
                    f"Floor {snap['protected_profit_floor_usd']} USD) · "
                    f"Observing {self._top_watch_symbol or '20 MARKETS'}"
                )
            if not snap["new_risk_allowed"]:
                self._governance_reason = str(snap["lock_reason"] or snap["status"])
            init_cap_arg = ps["configured_initial_capital_usd"]
            econ_eq_closed = ps["economic_equity_usd"]
            has_live_eq_closed = self._has_connected_broker_equity_unlocked() or total_eq > Decimal("0")
        if self._phase8_bridge is not None:
            try:
                raw_side_rc = (
                    str(popped_meta.get("side") or "BUY").strip().upper()
                    if isinstance(popped_meta, Mapping)
                    else "BUY"
                )
                side_rc = Side.SELL if raw_side_rc == Side.SELL.value else Side.BUY
                raw_lots_rc = popped_meta.get("volume_lots", "0.01") if isinstance(popped_meta, Mapping) else "0.01"
                raw_px_rc = popped_meta.get("entry_price", "1.00") if isinstance(popped_meta, Mapping) else "1.00"
                self._phase8_bridge.record_broker_fill_or_close(
                    broker_id=self._resolve_phase8_broker_id(eff_broker),
                    symbol=symbol,
                    event_type=ExecutionEventType.CLOSE_MANUAL,
                    event_id=f"rcpnl-{ticket}-{int(ts.timestamp() * 1000)}",
                    order_id=f"ord-{ticket}",
                    position_ticket=str(ticket),
                    side=side_rc,
                    quantity_lots=max(Decimal("0.01"), Decimal(str(raw_lots_rc))),
                    price=max(Decimal("0.00"), Decimal(str(raw_px_rc))),
                    realized_pnl_usd=pnl_usd,
                    current_equity_usd=econ_eq_closed if has_live_eq_closed else None,
                    now_utc=ts,
                )
            except Exception as exc_p8rc:
                logger.warning("record_closed_pnl phase8 publish skipped for %s: %s", ticket, type(exc_p8rc).__name__)
        if self._profit_vault is not None:
            try:
                if init_cap_arg is None:
                    init_cap_arg = self._compounding_starting_principal_ro()
                self._sync_vault_sweep_ratio_for_write(econ_eq_closed)
                self._profit_vault.record_realized_close(
                    trade_id=ticket,
                    symbol=symbol,
                    broker_id=eff_broker,
                    realized_net_usd=pnl_usd,
                    occurred_at=ts,
                    session_date=str(snap.get("session_date", "")),
                    total_equity_usd=total_eq,
                    initial_capital_usd=init_cap_arg,
                )
                self.sync_session_profit_to_vault(now=ts)
            except Exception as exc_vsync:
                with self._lock:
                    self._last_vault_sync_error = type(exc_vsync).__name__
                logger.warning("record_closed_pnl vault sync deferred for %s: %s", ticket, type(exc_vsync).__name__)
        return snap

    def _observe_markets_readonly(
        self,
        markets: Mapping[str, Mapping[str, Any]],
    ) -> tuple[str | None, str | None]:
        ordered_syms = list(INDEX_INSTRUMENTS) + [s for s in markets if s not in INDEX_INSTRUMENTS]
        best_ratio = Decimal("-1")
        best_sym: str | None = None
        best_reg: str | None = None
        for sym in ordered_syms:
            info = markets.get(sym)
            if not info:
                continue
            try:
                bid = Decimal(str(info["bid"]))
                ask = Decimal(str(info["ask"]))
            except (KeyError, ValueError, TypeError, ArithmeticError):
                continue
            if ask <= bid:
                continue
            spread = ask - bid
            hist = list(self._tick_history.get(sym, ()))
            if len(hist) < 3:
                if best_sym is None:
                    best_sym = sym
                    best_reg = "OBSERVING"
                continue
            params = self._protection_cfg(sym, Decimal("0.50"))
            mids = [(b + a) / Decimal("2") for b, a in hist[-50:]]
            reg_res = self._trend_detector.classify(
                mids=mids,
                spread=spread,
                normal_sl_distance=params["sl_distance"],
            )
            move_ratio = abs(mids[-1] - mids[0]) / max(spread, Decimal("0.000000001"))
            if move_ratio > best_ratio:
                best_ratio = move_ratio
                best_sym = sym
                best_reg = reg_res.regime
        if best_sym is not None:
            self._top_watch_symbol = best_sym
            self._last_evaluated_symbol = best_sym
            if best_reg is not None:
                self._last_evaluated_regime = best_reg
        return best_sym, best_reg

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

    def run_once(
        self,
        stream_envelope: Mapping[str, Any] | None = None,
        *,
        index_stream: Mapping[str, Any] | None = None,
        mt5_quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        fast_tick: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Alias for ``run_cycle`` executing one protection-first deterministic + AI cycle."""
        return self.run_cycle(
            stream_envelope,
            index_stream=index_stream,
            mt5_quotes=mt5_quotes,
            fast_tick=fast_tick,
            now=now,
        )

    def run_cycle(
        self,
        stream_envelope: Mapping[str, Any] | None = None,
        *,
        index_stream: Mapping[str, Any] | None = None,
        mt5_quotes: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        fast_tick: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Run one deterministic + AI decision cycle with non-blocking 50ms stop protection & 2-speed brain."""
        t0_ns = time.monotonic_ns()
        ts = self._now(now)

        # Phase 1a: Open-position stop protection ALWAYS executes FIRST with zero vault I/O!
        fast_bundle: dict[str, Any] = {}
        prot_updates = self.evaluate_fast_protection(
            quotes=mt5_quotes, now=ts, _out_equity_bundle=fast_bundle
        )
        # Phase 1b (OUTSIDE self._lock): throttled 60s OANDA self-heal, startup vault sync, vault & dial reads
        if not fast_tick and callable(getattr(self._router, "try_reconnect_oanda", None)):
            try:
                self._router.try_reconnect_oanda(now=ts)
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                raise
            except Exception as exc_oa:
                logger.warning("background OANDA reconnect skipped: %s", type(exc_oa).__name__)
        self._attempt_startup_vault_sync_post_protection(ts)
        v_snap_cyc = self._read_vault_snapshot_outside_lock()
        raw_dial_cyc = self._read_dial_snapshot_outside_lock()
        pending_disb_cyc = Decimal(str(v_snap_cyc.get("pending_disbursement_usd", "0") or "0"))

        with self._lock:
            self._cycle_seq += 1
            cycle_id = f"cycle-{self._cycle_seq}"
            self._last_cadence = f"{self._fast_tick_ms}ms_FAST_TICK" if fast_tick else f"STANDARD_{len(EXPANDED_MARKETS)}_MARKETS"
            markets = self._collect_market_quotes(stream_envelope, index_stream, mt5_quotes)
            quotes_map = {
                s: (Decimal(str(m["bid"])), Decimal(str(m["ask"])))
                for s, m in markets.items()
                if "bid" in m and "ask" in m
            }
            eq_bundle_cyc = (
                fast_bundle if (fast_bundle and not prot_updates) else self._router_equity_bundle_unlocked()
            )
            equities = eq_bundle_cyc["equities"]
            total_eq = eq_bundle_cyc["total_eq"]
            online_total_eq_cyc = eq_bundle_cyc["online_total_eq"]
            eff_dd_eq_cyc = eq_bundle_cyc["eff_dd_eq"]
            peak_eq = eq_bundle_cyc["eff_dd_peak"]
            ps_cyc = self._principal_surplus_metrics(
                total_eq,
                v_snap=v_snap_cyc,
                equities=equities,
                offline_brokers=eq_bundle_cyc["offline_brokers"],
            )
            in_rec_cyc = bool(ps_cyc["in_recovery_mode"])
            deployable_eq = (
                max(Decimal("0"), online_total_eq_cyc - pending_disb_cyc)
                if self._profit_vault is not None
                else online_total_eq_cyc
            )
            self._quota.observe_day_start(total_eq, now=ts, in_recovery_mode=in_rec_cyc)

            allowed, quota_veto, risk_mult = self._quota.evaluate_new_risk(
                ActionKind.OPEN, now=ts, starting_equity=total_eq, in_recovery_mode=in_rec_cyc
            )
            q_snap = self._quota.snapshot(
                now=ts,
                starting_equity=total_eq if total_eq > 0 else None,
                in_recovery_mode=in_rec_cyc,
            )
            quota_status = q_snap["status"]
            self._last_quota_status = str(quota_status)
            self._last_consec_losses = max(0, int(q_snap.get("consecutive_losses", 0) or 0))
            if quota_status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                obs_sym, obs_reg = self._observe_markets_readonly(markets)
                top_sym = obs_sym or self._top_watch_symbol
                respite_status = (
                    f"RESEARCH_RESPITE: Profits Banked ({q_snap['realized_net_pnl_usd']} USD · "
                    f"Floor {q_snap['protected_profit_floor_usd']} USD) · Observing {top_sym or '20 MARKETS'}"
                )
                self._current_focus_status = respite_status
                self._last_action = FOCUS_MODE_RESEARCH_RESPITE
                self._last_symbol = obs_sym
                self._last_reason = respite_status
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                if self._parallel_tiers is not None and quotes_map:
                    self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                respite_note = {
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "kind": FOCUS_MODE_RESEARCH_RESPITE,
                    "action": FOCUS_MODE_RESEARCH_RESPITE,
                    "symbol": obs_sym,
                    "regime": obs_reg,
                    "reason": respite_status[:200],
                    "detail": respite_status[:200],
                }
                self._recent_actions.appendleft(respite_note)
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": self._registry.active_model_id,
                    "cadence": self._last_cadence,
                    "operating_mode": FOCUS_MODE_RESEARCH_RESPITE,
                    "respite_mode": True,
                    "action": FOCUS_MODE_RESEARCH_RESPITE,
                    "symbol": obs_sym,
                    "reason": respite_status,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report

            strong_runner_eligible = False

            pre_dial = self._resolve_master_dial_summary_unlocked(
                regime=self._last_regime,
                total_eq=online_total_eq_cyc if online_total_eq_cyc > Decimal("0") else total_eq,
                peak_eq=peak_eq,
                quota_snap=q_snap,
                raw_dial=raw_dial_cyc,
                dd_curr_eq=eff_dd_eq_cyc,
            )
            realized_today_pre = Decimal(str(q_snap.get("realized_net_pnl_usd", "0")))
            dial_pre_veto: str | None = None
            if pre_dial is not None:
                pre_loss_brake = Decimal(str(pre_dial["daily_loss_brake_usd"]))
                pre_goal_usd = Decimal(str(pre_dial["session_goal_usd"]))
                if realized_today_pre <= -pre_loss_brake:
                    dial_pre_veto = (
                        f"DIAL_DAILY_LOSS_BRAKE (${decimal_text(realized_today_pre)} <= "
                        f"-${decimal_text(pre_loss_brake)})"
                    )
                elif realized_today_pre >= pre_goal_usd and not strong_runner_eligible:
                    dial_pre_veto = (
                        f"DIAL_SESSION_GOAL_REACHED (${decimal_text(realized_today_pre)} >= "
                        f"${decimal_text(pre_goal_usd)})"
                    )

            if self._governance_mode != GOVERNANCE_ACTIVE or not allowed or dial_pre_veto is not None:
                wait_reason = (
                    dial_pre_veto
                    if dial_pre_veto is not None
                    else (quota_veto if not allowed else f"Overseer governance is {self._governance_mode}")
                )
                if not allowed or dial_pre_veto is not None:
                    self._veto_count += 1
                self._last_action = "WAIT"
                self._last_symbol = None
                self._last_reason = str(wait_reason)
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                if self._parallel_tiers is not None and quotes_map:
                    self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
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

            setup = self._assess_setup_and_pyramid(
                markets,
                quotes_map=quotes_map,
                total_eq=eff_dd_eq_cyc,
                deployable_eq=deployable_eq,
                risk_mult=Decimal("0.50") if strong_runner_eligible else risk_mult,
                fast_tick=fast_tick,
                allow_cold_open=allowed,
                peak_eq=peak_eq,
                quota_snap=q_snap,
                raw_dial=raw_dial_cyc,
            )
            if setup is None:
                if self._last_dial_skip_reason is not None:
                    self._veto_count += 1
                self._last_action = "WAIT"
                self._last_symbol = None
                self._last_reason = (
                    self._last_dial_skip_reason
                    if self._last_dial_skip_reason is not None
                    else (
                        str(quota_veto)
                        if strong_runner_eligible
                        else "No risk-compliant momentum or trend setup clears spread/regime gate."
                    )
                )
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                if self._parallel_tiers is not None and quotes_map:
                    self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
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

            sym, side, bid, ask, setup_note, regime_name, is_pyramid_add, parent_ticket, leg_index = setup
            quota_full = self._quota.snapshot(
                now=ts,
                starting_equity=total_eq if total_eq > 0 else None,
                in_recovery_mode=in_rec_cyc,
            )
            gear_info = self._resolve_risk_gear(
                regime=regime_name, total_eq=eff_dd_eq_cyc, peak_eq=peak_eq, quota_snap=quota_full
            )
            dial_eff = self._resolve_master_dial_summary_unlocked(
                regime=regime_name,
                total_eq=online_total_eq_cyc if online_total_eq_cyc > Decimal("0") else total_eq,
                peak_eq=peak_eq,
                quota_snap=quota_full,
                raw_dial=raw_dial_cyc,
                dd_curr_eq=eff_dd_eq_cyc,
            )
            realized_today = Decimal(str(quota_full.get("realized_net_pnl_usd", "0")))
            if dial_eff is not None:
                dial_soft_q = Decimal(str(dial_eff["soft_goal_usd"]))
                dial_hard_q = Decimal(str(dial_eff["session_goal_usd"]))
                dial_loss_b = Decimal(str(dial_eff["daily_loss_brake_usd"]))
                if realized_today <= -dial_loss_b or (realized_today >= dial_hard_q and not strong_runner_eligible):
                    self._veto_count += 1
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = (
                        f"DIAL_DAILY_LOSS_BRAKE (${decimal_text(realized_today)} <= -${decimal_text(dial_loss_b)})"
                        if realized_today <= -dial_loss_b
                        else f"DIAL_SESSION_GOAL_REACHED (${decimal_text(realized_today)} >= ${decimal_text(dial_hard_q)})"
                    )
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    if self._parallel_tiers is not None and quotes_map:
                        self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": self._registry.active_model_id,
                        "cadence": self._last_cadence,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report
                base_mult = (
                    Decimal("0.50")
                    if (strong_runner_eligible or realized_today >= dial_soft_q)
                    else Decimal("1.00")
                )
                dial_risk_pct = min(
                    Decimal(str(dial_eff["effective_risk_pct"])),
                    self._router.barbell.max_stop_loss_equity_risk_pct,
                    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
                )
                with localcontext() as ctx:
                    ctx.prec = 40
                    dial_scale = (
                        dial_risk_pct / self._router.barbell.max_stop_loss_equity_risk_pct
                    ).quantize(Decimal("0.0001"), rounding=ROUND_FLOOR)
                if self._risk_gear_mode == RISK_GEAR_CONSERVATIVE:
                    dial_scale = min(dial_scale, Decimal(gear_info["risk_scale_factor"]))
                eff_mult = max(
                    Decimal("0.05"),
                    (base_mult * dial_scale).quantize(Decimal("0.0001"), rounding=ROUND_FLOOR),
                )
            else:
                gear_soft_q = Decimal(gear_info["effective_soft_quota_usd"])
                gear_hard_q = Decimal(gear_info["effective_hard_quota_usd"])
                if realized_today >= gear_hard_q and not strong_runner_eligible:
                    self._veto_count += 1
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = f"DYNAMIC_GEAR_QUOTA_REACHED ({gear_info['active_gear']}: ${decimal_text(realized_today)} >= ${decimal_text(gear_hard_q)})"
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    if self._parallel_tiers is not None and quotes_map:
                        self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": self._registry.active_model_id,
                        "cadence": self._last_cadence,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report
                base_mult = Decimal("0.50") if (strong_runner_eligible or realized_today >= gear_soft_q) else risk_mult
                gear_scale = Decimal(gear_info["risk_scale_factor"])
                eff_mult = max(Decimal("0.05"), (base_mult * gear_scale).quantize(Decimal("0.0001"), rounding=ROUND_FLOOR))
            params = self._protection_cfg(sym, eff_mult)
            t_sz = _tick_size(sym)
            spread = max(t_sz, ask - bid)
            entry_ref = ask if side is Side.BUY else bid
            if side is Side.BUY:
                sl_price = (bid - params["sl_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                tp_price = (ask + params["tp_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
            else:
                sl_price = (ask + params["sl_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
                tp_price = (bid - params["tp_distance"]).quantize(t_sz, rounding=ROUND_HALF_UP)
            # Bounded slippage collar so normal 2-5s tick movement during LLM reasoning does not
            # abort valid setups while capping worst-case fill slippage & stop-loss dollar risk.
            slip_collar = min(
                abs(entry_ref - sl_price) * Decimal("0.25"),
                max(spread * Decimal("3"), entry_ref * Decimal("0.0010")),
            )
            if side is Side.BUY:
                limit_ref = (entry_ref + slip_collar).quantize(t_sz, rounding=ROUND_HALF_UP)
                if limit_ref >= tp_price:
                    limit_ref = entry_ref
            else:
                limit_ref = max(t_sz, (entry_ref - slip_collar).quantize(t_sz, rounding=ROUND_HALF_UP))
                if limit_ref <= tp_price:
                    limit_ref = entry_ref

            qty = self._compute_quantity(
                symbol=sym,
                side=side,
                bid=limit_ref if side is Side.SELL else bid,
                ask=limit_ref if side is Side.BUY else ask,
                sl_price=sl_price,
                total_equity=deployable_eq,
                risk_multiplier=eff_mult,
                quotes_map=quotes_map,
            )
            st_ref = self._build_state_ref(ts)
            act_prefix = "add" if is_pyramid_add else "open"
            action_ref = f"ai-{act_prefix}-{sym.lower()}-{self._cycle_seq}"
            req_kind = ActionKind.ADD if is_pyramid_add else ActionKind.OPEN
            intent = ActionIntent(
                intent_id=f"intent-{action_ref}",
                scope=self._scope,
                decision_id=f"dec-{action_ref}",
                opportunity_id=f"opp-{action_ref}",
                action_ref=action_ref,
                source_state=st_ref,
                kind=req_kind,
                instrument_id=sym,
                origin=DecisionOrigin.ACTUAL_MODEL,
                created_at=ts,
                expires_at=st_ref.valid_until,
                quantity=qty,
                side=side,
                limit_price=None if is_pyramid_add else limit_ref,
                stop_price=sl_price,
                take_profit_price=tp_price,
                target_id=parent_ticket if is_pyramid_add else None,
                target_version=1 if is_pyramid_add else None,
            )

            active_id = self._registry.active_model_id
            req_timeframe = "H1" if is_pyramid_add else ("50ms" if fast_tick else ("M5" if regime_name == REGIME_STRONG_TREND else "M1"))
            eff_depth = self._registry.resolve_reasoning_effort(
                model_id=active_id,
                timeframe=req_timeframe,
                regime=regime_name,
                symbol=sym,
                is_pyramid_add=is_pyramid_add,
            )
            self._last_regime = regime_name
            self._last_effective_effort = eff_depth
            self._last_pyramid_leg = is_pyramid_add

            if self._phase8_bridge is not None:
                p8_news_act = TradeActionType.ADD_POSITION if is_pyramid_add else TradeActionType.OPEN_NEW
                p8_news_pre = self._phase8_bridge.news_shield.evaluate(sym, p8_news_act, now_utc=ts)
                p8_prof_pre = self._phase8_bridge.smart_planner.profile_for(sym)
                q_pre = QuoteSnapshot(symbol=sym, bid=bid, ask=ask, timestamp_utc=ts)
                p8_pre_block: str | None = None
                if not p8_news_pre.allowed:
                    p8_pre_block = p8_news_pre.reason_code
                elif q_pre.spread_points(p8_prof_pre.point_size) > p8_prof_pre.max_spread_points:
                    p8_pre_block = SmartRefusalReason.SPREAD_GUARD_EXCEEDED.value
                if p8_pre_block is not None:
                    self._veto_count += 1
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = f"PHASE8_PRE_ENTRY_BLOCKED:{p8_pre_block}"
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    if self._parallel_tiers is not None and quotes_map:
                        self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": active_id,
                        "cadence": self._last_cadence,
                        "thinking_depth": eff_depth,
                        "regime": regime_name,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report

            if hasattr(self._router, "check_open_eligibility"):
                elig_ok, elig_reason = self._router.check_open_eligibility(
                    sym, equities=equities, peak_equity=peak_eq
                )
                if not elig_ok:
                    self._veto_count += 1
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = f"PRE_INFERENCE_ELIGIBILITY_BLOCKED: {elig_reason}"
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    if self._parallel_tiers is not None and quotes_map:
                        self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": active_id,
                        "cadence": self._last_cadence,
                        "thinking_depth": eff_depth,
                        "regime": regime_name,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report

            run_scout = bool(
                self._registry.fast_scout_enabled
                and active_id != "gemini-decision-1"
                and self._registry.is_model_ready("gemini-decision-1")
                and not is_pyramid_add
            )
            scout_q: list[dict[str, Any]] | None = None
            if run_scout:
                scout_q = [{
                    "market": sym,
                    "side": side.value,
                    "spread": decimal_text(ask - bid),
                    "setup": setup_note,
                    "choices": ["WAIT", action_ref],
                }]
            exec_gate_ref = self._execution_gate
            registry_ref = self._registry

        # Phase 1.5 (OUTSIDE self._lock!): Gemini Decision 1 Fast Scout HTTP check never blocks UI reads or 50ms stops
        scout: dict[str, Any] | None = None
        if run_scout and scout_q is not None:
            with self._inference_lock:
                try:
                    if isinstance(exec_gate_ref, DurableModelExecutionGate):
                        scout = registry_ref.scout_opportunities(
                            scout_q,
                            execution_gate=exec_gate_ref,
                            request_id=cycle_id,
                        )
                    else:
                        if hasattr(exec_gate_ref, "admit_scout_call"):
                            exec_gate_ref.admit_scout_call(model_id="gemini-decision-1", request_id=cycle_id, now=ts)
                        else:
                            scout_spec, _, _ = registry_ref.build_backend("gemini-decision-1")
                            scout_inv = ModelInvocation(
                                request_sha256=content_digest(scout_q),
                                model=scout_spec,
                                session_id=f"scout-{cycle_id}",
                                system_policy=SYSTEM_POLICY,
                                packet_json=canonical_bytes({"scout": scout_q}).decode("utf-8"),
                                budget=InferenceBudget(
                                    max_calls=1, max_input_tokens_per_call=4096, max_generated_tokens_per_call=64,
                                    max_seconds_per_call=10, max_total_seconds=10,
                                ),
                            )
                            exec_gate_ref(scout_inv)
                        scout = registry_ref.scout_opportunities(scout_q)
                except FrontierTransportError as scout_exc:
                    with self._lock:
                        registry_ref.record_call(
                            "gemini-decision-1",
                            latency_ms=max(1, (time.monotonic_ns() - t0_ns) // 1_000_000),
                            status="SCOUT_DEGRADED",
                        )
                    scout = {
                        "executed": False,
                        "reason": f"SCOUT_DEGRADED:{type(scout_exc).__name__}",
                        "wake_heavy_model": True,
                        "best_market": None,
                        "best_probability": None,
                        "decisions": [],
                    }

        with self._lock:
            if scout is not None:
                self._last_scout = scout
            if self._governance_mode != GOVERNANCE_ACTIVE:
                self._last_action = "WAIT"
                self._last_symbol = sym
                self._last_reason = f"Aborted post-scout: governance shifted to {self._governance_mode}"
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": active_id,
                    "cadence": self._last_cadence,
                    "thinking_depth": eff_depth,
                    "regime": regime_name,
                    "action": "WAIT",
                    "symbol": sym,
                    "reason": self._last_reason,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report
            if scout is not None and scout.get("executed") and not scout.get("wake_heavy_model"):
                self._last_action = "WAIT"
                self._last_symbol = sym
                self._last_reason = f"Gemini Decision 1 Fast Scout held WAIT on {sym}"
                self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                if self._parallel_tiers is not None and quotes_map:
                    self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": active_id,
                    "cadence": self._last_cadence,
                    "thinking_depth": eff_depth,
                    "regime": regime_name,
                    "action": "WAIT",
                    "symbol": sym,
                    "reason": self._last_reason,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report

            ev_id = f"ev-{cycle_id}-{sym.lower()}"
            fact_obj = {
                "new_risk": True,
                "management": True,
                "equity": decimal_text(total_eq),
                "peak_equity": decimal_text(peak_eq),
                "deployable_equity": decimal_text(deployable_eq),
                "bid": decimal_text(bid),
                "ask": decimal_text(ask),
                "signal": setup_note,
                "regime": regime_name,
                "pyramid_leg": leg_index,
                "thinking_depth": eff_depth,
                "sl": decimal_text(sl_price),
                "tp": decimal_text(tp_price),
            }
            req = DecisionRequest(
                request_id=f"req-{cycle_id}",
                opportunity_set_id=f"set-{cycle_id}",
                state=st_ref,
                options=(
                    ActionOption(
                        action_ref,
                        "ai-pyramid-runner" if is_pyramid_add else "ai-momentum-tp-sl",
                        req_timeframe,
                        f"{req_kind.value} {side.value} {sym} {setup_note}"[:200],
                        intent,
                    ),
                ),
                facts=(DecisionFact(f"observed-{cycle_id}", "Observed market and barbell equity", canonical_bytes(fact_obj).decode("utf-8"), (ev_id,)),),
                evidence=(EvidenceReference(ev_id, EvidenceKind.OBSERVATION, "autonomous-ai-trader", content_digest(fact_obj), ts),),
            )
            max_gen = 12288 if eff_depth == "high" else (6144 if eff_depth == "medium" else 2048)
            spec, backend, verifier = self._registry.build_backend(
                active_id,
                reasoning_effort=eff_depth,
                execution_gate=self._execution_gate if isinstance(self._execution_gate, DurableModelExecutionGate) else None,
            )
            adapter = ActualModelDecisionAdapter(
                adapter_id=f"adapter-{active_id.replace(':', '-')}",
                model=spec,
                budget=InferenceBudget(
                    max_calls=1,
                    max_input_tokens_per_call=16_384,
                    max_generated_tokens_per_call=max_gen,
                    max_seconds_per_call=25,
                    max_total_seconds=25,
                ),
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=self._execution_gate,
                clock=self._clock,
            )

        # Phase 2 (OUTSIDE self._lock!): non-blocking 50ms stop protection remains free while AI thinks
        with self._inference_lock:
            try:
                dec_result = adapter.decide(req)
            except FrontierTransportError as exc:
                with self._lock:
                    self._veto_count += 1
                    self._last_error = str(exc)
                    self._registry.record_call(
                        active_id,
                        latency_ms=max(1, (time.monotonic_ns() - t0_ns) // 1_000_000),
                        status="TRANSPORT_ERROR",
                        reasoning_effort=eff_depth,
                    )
                raise

        # Phase 3 (re-acquire self._lock): verify governance still active -> Valve -> dual-shield execution
        call_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
        with self._lock:
            self._registry.record_call(active_id, latency_ms=call_ms, status="OK", reasoning_effort=eff_depth)
            if self._governance_mode != GOVERNANCE_ACTIVE:
                self._last_action = "WAIT"
                self._last_symbol = sym
                self._last_reason = f"Aborted post-inference: governance shifted to {self._governance_mode}"
                self._last_cycle_ms = call_ms
                return {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": active_id,
                    "cadence": self._last_cadence,
                    "thinking_depth": eff_depth,
                    "regime": regime_name,
                    "action": "WAIT",
                    "symbol": sym,
                    "reason": self._last_reason,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }

            chosen_ref = dec_result.selection.selected_action_ref
            if chosen_ref is None:
                self._last_action = "WAIT"
                self._last_symbol = sym
                self._last_reason = dec_result.selection.reason
                self._last_cycle_ms = call_ms
                if self._parallel_tiers is not None and quotes_map:
                    self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                report = {
                    "schema": "cas-forex.ai-cycle/1",
                    "cycle_id": cycle_id,
                    "observed_at": _iso(ts),
                    "model_id": active_id,
                    "cadence": self._last_cadence,
                    "thinking_depth": eff_depth,
                    "regime": regime_name,
                    "action": "WAIT",
                    "symbol": sym,
                    "reason": self._last_reason,
                    "valve_score": self._last_valve_score,
                    "protection_updates": prot_updates,
                }
                self._append_journal_cycle(report)
                return report

            class _ModelProposal:
                __slots__ = ("request", "result", "intent")

                def __init__(self, r: DecisionRequest, d: Any, i: ActionIntent) -> None:
                    self.request = r
                    self.result = d
                    self.intent = i

            eq_bundle_post = self._router_equity_bundle_unlocked()
            equities = eq_bundle_post["equities"]
            total_eq = eq_bundle_post["total_eq"]
            current_view = self._build_valve_view(
                total_eq=eq_bundle_post["eff_dd_eq"],
                peak_eq=eq_bundle_post["eff_dd_peak"],
                new_risk_permission="ALLOWED",
                management_permission="ALLOWED",
                scope_id=eq_bundle_post.get("eff_dd_scope"),
            )
            proposal_box = _ModelProposal(req, dec_result, intent)
            if self._phase8_bridge is not None:
                p8_prof_post = self._phase8_bridge.smart_planner.profile_for(sym)
                q_post = QuoteSnapshot(symbol=sym, bid=bid, ask=ask, timestamp_utc=ts)
                stop_dist_pts_post = max(
                    Decimal("0.01"),
                    abs(limit_ref - sl_price) / p8_prof_post.point_size,
                )
                eff_risk_pct_post = min(
                    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
                    max(
                        Decimal("0.01"),
                        (self._router.barbell.max_stop_loss_equity_risk_pct * eff_mult).quantize(
                            Decimal("0.0001"), rounding=ROUND_FLOOR
                        ),
                    ),
                )
                open_pyr_post = sum(
                    1
                    for m in self._open_position_meta.values()
                    if m.get("symbol") == sym and m.get("side") == side.value
                )
                max_open_post = min(
                    8,
                    max(
                        1,
                        int(dial_eff["max_open_trades"])
                        if (dial_eff is not None and "max_open_trades" in dial_eff)
                        else MAX_PYRAMID_LEGS,
                    ),
                )
                max_loss_cap_post = (
                    Decimal(str(dial_eff["daily_loss_brake_usd"]))
                    if dial_eff is not None
                    else Decimal(str(quota_full.get("max_daily_loss_usd", "1000.00") or "1000.00"))
                )
                daily_rem_post = max_loss_cap_post + realized_today
                curr_dd_post = (
                    compute_drawdown_pct(eq_bundle_post["eff_dd_eq"], eq_bundle_post["eff_dd_peak"])
                    if (eq_bundle_post["eff_dd_peak"] > Decimal("0") and eq_bundle_post["eff_dd_eq"] > Decimal("0"))
                    else Decimal("0.00")
                )
                p8_view_post = {k: v for k, v in current_view.items() if k != "policy"}
                p8_view_post["policy"] = {
                    "new_risk_permission": "ALLOWED",
                    "management_permission": "ALLOWED",
                    "max_drawdown_pct": current_view["policy"]["max_drawdown_pct"],
                }
                p8_dec = self._phase8_bridge.evaluate_pre_entry(
                    broker_id=self._resolve_phase8_broker_id(getattr(self._router, "active_broker_id", None)),
                    symbol=sym,
                    side=side,
                    equity_usd=deployable_eq,
                    stop_distance_points=stop_dist_pts_post,
                    risk_pct=eff_risk_pct_post,
                    quote=q_post,
                    account_state=p8_view_post,
                    proposal=proposal_box,
                    open_pyramid_count=open_pyr_post,
                    max_open_trades=max_open_post,
                    daily_loss_remaining_usd=daily_rem_post,
                    drawdown_pct=curr_dd_post,
                    now_utc=ts,
                )
                if not p8_dec.allowed and p8_dec.reason_code != SmartRefusalReason.VALVE_REFUSAL.value:
                    self._veto_count += 1
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = f"PHASE8_PRE_ENTRY_BLOCKED:{p8_dec.reason_code}"
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    if self._parallel_tiers is not None and quotes_map:
                        self._parallel_tiers.process_tick(quotes=quotes_map, signal=None, now=ts)
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": active_id,
                        "cadence": self._last_cadence,
                        "thinking_depth": eff_depth,
                        "regime": regime_name,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report
            try:
                valve_dec = self._valve_gate.require_admissible(
                    proposal_box, current_view=current_view, now=ts
                )
            except ValveRefusalError:
                self._veto_count += 1
                self._last_action = "VALVE_VETOED"
                self._last_symbol = sym
                self._last_reason = f"ForexMetaValveGate vetoed {active_id} {req_kind.value} proposal on {sym}"
                raise

            if dial_eff is not None:
                min_prob_req = max(
                    MIN_CONSTITUTIONAL_VALVE_PROB,
                    Decimal(str(dial_eff["min_signal_prob"])),
                )
                obs_prob = Decimal(f"{valve_dec.mlp_score:.8f}")
                if obs_prob < min_prob_req:
                    self._veto_count += 1
                    self._last_valve_score = decimal_text(obs_prob)
                    self._last_action = "WAIT"
                    self._last_symbol = sym
                    self._last_reason = (
                        f"DIAL_MIN_SIGNAL_PROB (mlp_score={valve_dec.mlp_score:.4f} < "
                        f"{min_prob_req} at {dial_eff['effective_risk_pct']}% {dial_eff['effective_label']})"
                    )
                    self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)
                    if self._parallel_tiers is not None and quotes_map:
                        self._parallel_tiers.process_tick(
                            quotes=quotes_map,
                            signal={
                                "symbol": sym,
                                "side": side.value,
                                "stop_price": decimal_text(sl_price),
                                "take_profit_price": decimal_text(tp_price),
                                "regime": regime_name,
                            },
                            now=ts,
                        )
                    report = {
                        "schema": "cas-forex.ai-cycle/1",
                        "cycle_id": cycle_id,
                        "observed_at": _iso(ts),
                        "model_id": active_id,
                        "cadence": self._last_cadence,
                        "thinking_depth": eff_depth,
                        "regime": regime_name,
                        "action": "WAIT",
                        "symbol": sym,
                        "reason": self._last_reason,
                        "valve_score": self._last_valve_score,
                        "protection_updates": prot_updates,
                    }
                    self._append_journal_cycle(report)
                    return report

            # Execute protected broker leg via OrderIntent(OPEN) bound to ADD/OPEN ValveDecision
            broker_order = OrderIntent(
                order_id=str(intent.intent_id),
                action_ref=str(intent.action_ref),
                kind=ActionKind.OPEN,
                symbol=sym,
                quantity_units=qty,
                side=side,
                stop_price=sl_price,
                limit_price=limit_ref,
                take_profit_price=tp_price,
            )
            exec_res = self._router.execute_open(broker_order, valve_decision=valve_dec)
            if exec_res.result.receipt is not None and not exec_res.result.receipt.accepted:
                raise Mt5BridgeError(
                    f"{exec_res.executed_on} rejected OPEN {sym} "
                    f"(retcode={exec_res.result.receipt.retcode}: {exec_res.result.receipt.message})"
                )
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
                "leg_index": leg_index,
                "pyramid_parent_ticket": parent_ticket,
                "regime": regime_name,
                "thinking_depth": eff_depth,
            }
            self._peak_favorable[str(ticket)] = fill_px
            self._protection_stage[str(ticket)] = "INITIAL_SL"
            if self._phase8_bridge is not None:
                try:
                    filled_lots_p8 = (
                        exec_res.result.receipt.volume_lots
                        if (exec_res.result.receipt is not None and exec_res.result.receipt.volume_lots)
                        else Decimal("0.01")
                    )
                    self._phase8_bridge.record_broker_fill_or_close(
                        broker_id=self._resolve_phase8_broker_id(exec_res.executed_on),
                        symbol=sym,
                        event_type=ExecutionEventType.FILL,
                        event_id=f"fill-{cycle_id}-{ticket}",
                        order_id=str(intent.intent_id),
                        position_ticket=str(ticket),
                        side=side,
                        quantity_lots=filled_lots_p8,
                        price=fill_px,
                        realized_pnl_usd=Decimal("0.00"),
                        current_equity_usd=total_eq if total_eq > Decimal("0") else None,
                        now_utc=ts,
                    )
                except Exception as exc_p8f:
                    logger.warning("phase8 open fill publish skipped for %s: %s", ticket, type(exc_p8f).__name__)

            v_score_str = decimal_text(Decimal(f"{valve_dec.mlp_score:.8f}"))
            self._last_valve_score = v_score_str
            self._last_action = f"{req_kind.value}_{side.value}"
            self._last_symbol = sym
            self._last_reason = (
                f"{dec_result.selection.reason} [exec={exec_res.executed_on} "
                f"leg={leg_index} depth={eff_depth} SL={decimal_text(sl_price)} TP={decimal_text(tp_price)}]"
            )
            self._last_cycle_ms = max(1, (time.monotonic_ns() - t0_ns) // 1_000_000)

            if self._parallel_tiers is not None and quotes_map:
                self._parallel_tiers.process_tick(
                    quotes=quotes_map,
                    signal={
                        "symbol": sym,
                        "side": side.value,
                        "stop_price": decimal_text(sl_price),
                        "take_profit_price": decimal_text(tp_price),
                        "regime": regime_name,
                    },
                    now=ts,
                )

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
                "leg_index": leg_index,
                "pyramid_parent_ticket": parent_ticket,
                "regime": regime_name,
                "thinking_depth": eff_depth,
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
            ps_res = self._principal_surplus_metrics(total_eq)
            allowed, veto_code, _ = self._quota.evaluate_new_risk(
                ActionKind.OPEN,
                now=ts,
                starting_equity=total_eq,
                in_recovery_mode=bool(ps_res["in_recovery_mode"]),
            )
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
        close_errors: list[Exception] = []
        deferred_em_vault: list[tuple[str, str, str, Decimal, str, Decimal, Decimal | None]] = []
        deferred_em_p8: list[tuple[str, str, str, Side, Decimal, Decimal, Decimal, Decimal]] = []
        v_snap_em = self._read_vault_snapshot_outside_lock()
        with self._lock:
            self._governance_mode = GOVERNANCE_PAUSED_NEW_RISK
            self._governance_reason = str(reason)[:240]
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            peak_eq = self._router.peak_equity() or total_eq
            for broker_id, venue in list(self._router.venues.items()):
                if isinstance(venue, Mt5PaperBrokerVenue):
                    if venue.account is None:
                        continue
                    try:
                        venue.probe()
                        open_positions = tuple(venue.positions)
                    except Exception as exc_probe:
                        close_errors.append(exc_probe)
                        continue
                    for pos in open_positions:
                        try:
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
                            eq_em_after = self._router.barbell.total_equity(self._router.equities())
                            ps_em = self._principal_surplus_metrics(eq_em_after, v_snap=v_snap_em)
                            q_em = self._quota.record_realized_trade(
                                pos.profit,
                                symbol=pos.symbol,
                                ticket=pos.ticket,
                                trade_id=pos.ticket,
                                broker_id=broker_id,
                                starting_equity=eq_em_after,
                                now=ts,
                                in_recovery_mode=bool(ps_em["in_recovery_mode"]),
                            )
                            if pos.profit > Decimal("0"):
                                deferred_em_vault.append((
                                    pos.ticket,
                                    pos.symbol,
                                    broker_id,
                                    pos.profit,
                                    str(q_em.get("session_date", "")),
                                    eq_em_after,
                                    ps_em["configured_initial_capital_usd"],
                                ))
                            if self._phase8_bridge is not None:
                                em_px = tick.bid if pos.side is Side.BUY else tick.ask
                                deferred_em_p8.append((
                                    broker_id,
                                    pos.symbol,
                                    str(pos.ticket),
                                    pos.side,
                                    pos.volume_lots,
                                    em_px,
                                    pos.profit,
                                    eq_em_after,
                                ))
                            self._open_position_meta.pop(pos.ticket, None)
                            closed_tickets.append(pos.ticket)
                        except Exception as exc_close:
                            close_errors.append(exc_close)
                elif isinstance(venue, OandaPracticeFallbackVenue):
                    if venue.summary is None:
                        continue
                    try:
                        oanda_positions = tuple(venue.positions(now=ts, refresh=True))
                    except Exception as exc_oprobe:
                        close_errors.append(exc_oprobe)
                        continue
                    for pos in oanda_positions:
                        try:
                            self._cycle_seq += 1
                            st_ref = self._build_state_ref(ts)
                            exact_units = venue.position_units(pos.ticket) if callable(getattr(venue, "position_units", None)) else None
                            if exact_units is None or exact_units <= Decimal("0"):
                                csize = (
                                    MT5_GOLD_CONTRACT_SIZE
                                    if pos.symbol == "XAUUSD"
                                    else (MT5_INDEX_CONTRACT_SIZE if pos.symbol in INDEX_INSTRUMENTS else MT5_CONTRACT_SIZE)
                                )
                                exact_units = (pos.volume_lots * csize).normalize()
                            try:
                                o_bid, o_ask = venue.symbol_quote(pos.symbol, now=ts)
                            except Exception:
                                fallback_px = pos.price_open if pos.price_open > Decimal("0") else Decimal("1")
                                o_bid, o_ask = fallback_px, fallback_px
                            action_ref = f"overseer-close-oanda-{pos.ticket}-{self._cycle_seq}"
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
                                quantity=exact_units,
                                side=Side.SELL if pos.side is Side.BUY else Side.BUY,
                                target_id=pos.ticket,
                                target_version=1,
                            )
                            dec = self._make_valve_request_and_clear(
                                intent=intent,
                                strategy_id="overseer-emergency-close",
                                timeframe="M1",
                                label=f"Close OANDA {pos.ticket}",
                                reason=reason,
                                bid=o_bid,
                                ask=o_ask,
                                total_eq=total_eq,
                                peak_eq=peak_eq,
                                position_side=pos.side,
                                now=ts,
                            )
                            order = OrderIntent.from_action_intent(intent, symbol=pos.symbol, position_ticket=pos.ticket)
                            exec_res = self._router.execute_management(broker_id, order, valve_decision=dec)
                            realized_pnl = pos.profit
                            o_rcpt = exec_res.oanda_receipt if isinstance(exec_res.oanda_receipt, Mapping) else None
                            if o_rcpt is not None:
                                for pnl_key in ("realized_pnl", "pl"):
                                    raw_pl = o_rcpt.get(pnl_key)
                                    if raw_pl is not None and str(raw_pl).strip():
                                        try:
                                            parsed_pl = Decimal(str(raw_pl))
                                            if parsed_pl.is_finite():
                                                realized_pnl = parsed_pl
                                                break
                                        except (InvalidOperation, ValueError, TypeError):
                                            logger.debug("Ignored non-decimal OANDA realized_pnl field %r", pnl_key)
                            eq_em_after = self._router.barbell.total_equity(self._router.equities())
                            ps_em = self._principal_surplus_metrics(eq_em_after, v_snap=v_snap_em)
                            q_em = self._quota.record_realized_trade(
                                realized_pnl,
                                symbol=pos.symbol,
                                ticket=pos.ticket,
                                trade_id=pos.ticket,
                                broker_id=broker_id,
                                starting_equity=eq_em_after,
                                now=ts,
                                in_recovery_mode=bool(ps_em["in_recovery_mode"]),
                            )
                            if realized_pnl > Decimal("0"):
                                deferred_em_vault.append((
                                    pos.ticket,
                                    pos.symbol,
                                    broker_id,
                                    realized_pnl,
                                    str(q_em.get("session_date", "")),
                                    eq_em_after,
                                    ps_em["configured_initial_capital_usd"],
                                ))
                            if self._phase8_bridge is not None:
                                em_opx = o_bid if pos.side is Side.BUY else o_ask
                                deferred_em_p8.append((
                                    broker_id,
                                    pos.symbol,
                                    str(pos.ticket),
                                    pos.side,
                                    pos.volume_lots,
                                    em_opx,
                                    realized_pnl,
                                    eq_em_after,
                                ))
                            self._open_position_meta.pop(pos.ticket, None)
                            closed_tickets.append(pos.ticket)
                        except Exception as exc_oclose:
                            close_errors.append(exc_oclose)
        if deferred_em_p8 and self._phase8_bridge is not None:
            for brk_e, sym_e, tkt_e, side_e, lots_e, px_e, pnl_e, eq_e in deferred_em_p8:
                try:
                    norm_b = self._resolve_phase8_broker_id(brk_e)
                    self._phase8_bridge.dispatch_protective_action(
                        broker_id=norm_b,
                        symbol=sym_e,
                        action=TradeActionType.EMERGENCY_CLOSE_ALL,
                        order_id=f"em-ord-{tkt_e}",
                        position_ticket=tkt_e,
                        side=side_e,
                        quantity_lots=lots_e,
                        price=px_e,
                        reason=str(reason)[:200],
                        now_utc=ts,
                    )
                    self._phase8_bridge.record_broker_fill_or_close(
                        broker_id=norm_b,
                        symbol=sym_e,
                        event_type=ExecutionEventType.CLOSE_MANUAL,
                        event_id=f"em-close-{tkt_e}-{int(ts.timestamp() * 1000)}",
                        order_id=f"em-ord-{tkt_e}",
                        position_ticket=tkt_e,
                        side=side_e,
                        quantity_lots=lots_e,
                        price=px_e,
                        realized_pnl_usd=pnl_e,
                        current_equity_usd=eq_e if eq_e > Decimal("0") else None,
                        now_utc=ts,
                    )
                except Exception as exc_emp8:
                    logger.warning("emergency_close_all phase8 publish skipped for %s: %s", tkt_e, type(exc_emp8).__name__)
        if closed_tickets and self._profit_vault is not None:
            try:
                comp_cap_em = self._compounding_starting_principal_ro()
                for t_id, sym_e, brk_e, pnl_e, sdate_e, eq_e, cap_e in deferred_em_vault:
                    eff_cap_e = cap_e if cap_e is not None else comp_cap_em
                    self._sync_vault_sweep_ratio_for_write(eq_e + self._cached_settled_disbursed_usd)
                    self._profit_vault.record_realized_close(
                        trade_id=t_id,
                        symbol=sym_e,
                        broker_id=brk_e,
                        realized_net_usd=pnl_e,
                        occurred_at=ts,
                        session_date=sdate_e,
                        total_equity_usd=eq_e,
                        initial_capital_usd=eff_cap_e,
                    )
                self.sync_session_profit_to_vault(now=ts)
            except Exception as exc_vsync:
                with self._lock:
                    self._last_vault_sync_error = type(exc_vsync).__name__
                logger.warning("emergency_close_all post-lock vault sync deferred: %s", type(exc_vsync).__name__)
        if close_errors:
            raise close_errors[0]
        snap = self.status_snapshot(now=ts)
        snap["closed_tickets"] = closed_tickets
        return assert_safe_ai_catalog_payload(snap)

    def rearm_and_unlock(
        self,
        *,
        owner_request_id: str,
        reason: str,
        recovery_token: str | None = None,
        unlock_recovery_token: str | None = None,
        new_peak_equity: Decimal | None = None,
        owner_verifier: Any | None = None,
        fence_request: Any | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        with self._lock:
            verifier = owner_verifier or self._owner_verifier
            if verifier is None:
                raise ContractError("OWNER_RECOVERY_VERIFIER_REQUIRED: rearm_and_unlock requires an OwnerRecoveryVerifier")
            if new_peak_equity is not None:
                if hasattr(verifier, "verify_and_consume") and fence_request is None:
                    if not isinstance(recovery_token, str) or not recovery_token.strip():
                        raise ContractError("OWNER_RECOVERY_TOKEN_REQUIRED: single-use token required to re-arm drawdown")
                    verifier.verify_and_consume(
                        recovery_token,
                        expected_scope="REARM_DRAWDOWN",
                        target_ref=self._router._drawdown_scope_id,
                        owner_request_id=owner_request_id,
                        now=ts,
                    )
                    self._router.rearm_drawdown(
                        new_peak_equity=new_peak_equity,
                        owner_verifier=lambda _req, _now: True,
                        owner_request_id=owner_request_id,
                        fence_request=fence_request,
                        now=ts,
                    )
                else:
                    self._router.rearm_drawdown(
                        new_peak_equity=new_peak_equity,
                        owner_verifier=verifier,
                        owner_request_id=owner_request_id,
                        fence_request=fence_request,
                        now=ts,
                    )
                eq_unl = self._router.barbell.total_equity(self._router.equities())
                in_rec_unl = bool(self._principal_surplus_metrics(eq_unl)["in_recovery_mode"])
                if unlock_recovery_token is not None:
                    self._quota.unlock_session(
                        owner_request_id=f"{owner_request_id}-q",
                        reason=reason,
                        recovery_verifier=verifier,
                        recovery_token=unlock_recovery_token,
                        now=ts,
                        in_recovery_mode=in_rec_unl,
                    )
            else:
                eq_unl = self._router.barbell.total_equity(self._router.equities())
                in_rec_unl = bool(self._principal_surplus_metrics(eq_unl)["in_recovery_mode"])
                self._quota.unlock_session(
                    owner_request_id=owner_request_id,
                    reason=reason,
                    recovery_verifier=verifier,
                    recovery_token=recovery_token,
                    now=ts,
                    in_recovery_mode=in_rec_unl,
                )
            self._governance_mode = GOVERNANCE_ACTIVE
            self._governance_reason = f"Re-armed & unlocked ({owner_request_id})"
        return self.status_snapshot(now=ts)

    def advance_recovery_session(
        self,
        *,
        reason: str = "Owner recovery leg advance",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Advance to a fresh recovery leg (#leg2+) while below starting principal, capping giveback at <=30%."""
        ts = self._now(now)
        v_snap_adv = self._read_vault_snapshot_outside_lock()
        with self._lock:
            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            ps = self._principal_surplus_metrics(total_eq, v_snap=v_snap_adv)
            if ps["capital_status"] != CAPITAL_STATUS_RECOVERY_MODE:
                raise ContractError(
                    f"Recovery session advance is only permitted in RECOVERY_MODE "
                    f"(current capital_status={ps['capital_status']})"
                )
            leg_snap = self._quota.advance_recovery_leg(
                reason=reason,
                in_recovery_mode=True,
                now=ts,
            )
            self._recent_actions.appendleft({
                "observed_at": _iso(ts),
                "kind": "ADVANCE_RECOVERY_SESSION",
                "action": "ADVANCE_RECOVERY_SESSION",
                "symbol": None,
                "reason": str(reason)[:200],
                "detail": (
                    f"Advanced recovery leg to {leg_snap['session_date']} "
                    f"(max_loss_cap=${leg_snap['max_daily_loss_usd']})"
                ),
            })
        return self.status_snapshot(now=ts)

    def set_session_cadence(
        self,
        cadence: str,
        *,
        reason: str = "Owner cadence update",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Update session rollover cadence (AUTO, REGIONAL_RECOVERY / REGIONAL_8H, or DAILY_NY)."""
        ts = self._now(now)
        with self._lock:
            self._quota.set_session_cadence(cadence, now=ts)
            eff_cad = self._quota.session_cadence
            self._recent_actions.appendleft({
                "observed_at": _iso(ts),
                "kind": "SET_SESSION_CADENCE",
                "action": "SET_SESSION_CADENCE",
                "symbol": None,
                "reason": str(reason)[:200],
                "detail": f"Session cadence set to {eff_cad} ({reason})",
            })
        return self.status_snapshot(now=ts)

    @staticmethod
    def _is_synthetic_sync_trade(trade_id: str | None, symbol: str | None) -> bool:
        tid = str(trade_id or "").strip()
        sym = str(symbol or "").strip()
        return (not sym) or tid.startswith("SESSION_SYNC_") or sym == "SESSION_BASKET"

    @staticmethod
    def _entry_matches_active_session(entry_skey: str, active_sdate: str, occurred_utc: str) -> bool:
        if not active_sdate:
            return False
        if entry_skey == active_sdate:
            return True
        if active_sdate.endswith("-ASIA") and len(active_sdate) == 15 and entry_skey == active_sdate[:-5]:
            try:
                anchor_dt = datetime.fromisoformat(f"{active_sdate[:-5]}T00:00:00+00:00")
                occ_dt = datetime.fromisoformat(occurred_utc.replace("Z", "+00:00"))
                return (anchor_dt - timedelta(hours=2)) <= occ_dt < (anchor_dt + timedelta(hours=7))
            except ValueError:
                return False
        return False

    @staticmethod
    def _aggregate_pnl_by_market(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        buckets: dict[str, dict[str, Any]] = {}
        for e in entries:
            sym = str(e["symbol"])
            pnl = Decimal(str(e["realized_pnl_usd"]))
            occ_utc = str(e["occurred_at_utc"])
            occ_pac = str(e["occurred_at_pacific"])
            sess_lbl = str(e["session_label"])
            b = buckets.get(sym)
            if b is None:
                buckets[sym] = {
                    "symbol": sym,
                    "pnl_dec": pnl,
                    "trade_count": 1,
                    "win_count": 1 if pnl > Decimal("0") else 0,
                    "loss_count": 1 if pnl < Decimal("0") else 0,
                    "last_occurred_at_utc": occ_utc,
                    "last_occurred_at_pacific": occ_pac,
                    "last_session_label": sess_lbl,
                }
            else:
                b["pnl_dec"] += pnl
                b["trade_count"] += 1
                if pnl > Decimal("0"):
                    b["win_count"] += 1
                elif pnl < Decimal("0"):
                    b["loss_count"] += 1
                if occ_utc > str(b["last_occurred_at_utc"]):
                    b["last_occurred_at_utc"] = occ_utc
                    b["last_occurred_at_pacific"] = occ_pac
                    b["last_session_label"] = sess_lbl
        return [
            {
                "symbol": str(item["symbol"]),
                "realized_pnl_usd": decimal_text(item["pnl_dec"]),
                "trade_count": int(item["trade_count"]),
                "win_count": int(item["win_count"]),
                "loss_count": int(item["loss_count"]),
                "last_occurred_at_utc": str(item["last_occurred_at_utc"]),
                "last_occurred_at_pacific": str(item["last_occurred_at_pacific"]),
                "last_session_label": str(item["last_session_label"]),
            }
            for item in sorted(
                buckets.values(),
                key=lambda x: (-Decimal(x["pnl_dec"]), str(x["symbol"])),
            )
        ]

    @staticmethod
    def _aggregate_pnl_by_broker(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        buckets: dict[str, dict[str, Any]] = {}
        for e in entries:
            brk = str(e["broker_id"])
            brk_lbl = str(e.get("broker_label") or friendly_broker_label(brk))
            pnl = Decimal(str(e["realized_pnl_usd"]))
            occ_utc = str(e["occurred_at_utc"])
            occ_pac = str(e["occurred_at_pacific"])
            sess_lbl = str(e["session_label"])
            b = buckets.get(brk)
            if b is None:
                buckets[brk] = {
                    "broker_id": brk,
                    "broker_label": brk_lbl,
                    "pnl_dec": pnl,
                    "trade_count": 1,
                    "win_count": 1 if pnl > Decimal("0") else 0,
                    "loss_count": 1 if pnl < Decimal("0") else 0,
                    "last_occurred_at_utc": occ_utc,
                    "last_occurred_at_pacific": occ_pac,
                    "last_session_label": sess_lbl,
                }
            else:
                b["pnl_dec"] += pnl
                b["trade_count"] += 1
                if pnl > Decimal("0"):
                    b["win_count"] += 1
                elif pnl < Decimal("0"):
                    b["loss_count"] += 1
                if occ_utc > str(b["last_occurred_at_utc"]):
                    b["last_occurred_at_utc"] = occ_utc
                    b["last_occurred_at_pacific"] = occ_pac
                    b["last_session_label"] = sess_lbl
        return [
            {
                "broker_id": str(item["broker_id"]),
                "broker_label": str(item["broker_label"]),
                "realized_pnl_usd": decimal_text(item["pnl_dec"]),
                "trade_count": int(item["trade_count"]),
                "win_count": int(item["win_count"]),
                "loss_count": int(item["loss_count"]),
                "last_occurred_at_utc": str(item["last_occurred_at_utc"]),
                "last_occurred_at_pacific": str(item["last_occurred_at_pacific"]),
                "last_session_label": str(item["last_session_label"]),
            }
            for item in sorted(
                buckets.values(),
                key=lambda x: (-Decimal(x["pnl_dec"]), str(x["broker_id"])),
            )
        ]

    @staticmethod
    def _fmt_signed_usd(raw_dec_str: str) -> str:
        val = Decimal(str(raw_dec_str))
        txt = decimal_text(abs(val))
        if val > Decimal("0"):
            return f"+${txt}"
        if val < Decimal("0"):
            return f"-${txt}"
        return f"${txt}"

    def _build_provenance_and_live_status_unlocked(
        self,
        *,
        quota_closed_rows: Sequence[Mapping[str, Any]],
        v_snap: Mapping[str, Any],
        sdate_curr: str,
        quota_snap: Mapping[str, Any],
        open_positions_list: Sequence[Mapping[str, Any]],
        locked_for_session: bool,
    ) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
        # 1. Live Trading Status Banner
        n_open = len(open_positions_list)
        open_syms = list(
            dict.fromkeys(str(p.get("symbol")) for p in open_positions_list if p.get("symbol"))
        )
        dq_status = str(quota_snap.get("status", ""))
        if n_open > 0 and self._governance_mode == GOVERNANCE_ACTIVE:
            state_code = "TRADING_NOW_OPEN_POSITIONS"
            headline = (
                f"TRADING NOW \u2014 {n_open} OPEN POSITION"
                f"{'S' if n_open != 1 else ''}: {', '.join(open_syms)}"
            )
            is_trading = True
        elif locked_for_session or dq_status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
            state_code = "PAUSED_RESEARCH_RESPITE"
            headline = "PAUSED \u2014 RESEARCH RESPITE (PROFIT LOCKED)"
            is_trading = False
        elif dq_status == QUOTA_STATUS_LOSS_TRIPPED:
            state_code = "PAUSED_SAFETY_LOCK"
            headline = "PAUSED \u2014 SAFETY LOCK"
            is_trading = False
        elif self._governance_mode != GOVERNANCE_ACTIVE:
            state_code = "STOPPED_OR_PAUSED"
            headline = f"PAUSED \u2014 {self._governance_mode}"
            is_trading = False
        else:
            state_code = "ACTIVE_SCANNING_MARKETS"
            headline = "ACTIVE \u2014 SCANNING MARKETS (0 OPEN TRADES)"
            is_trading = True

        live_trading_status: dict[str, Any] = {
            "state_code": state_code,
            "headline": headline,
            "is_currently_trading": is_trading,
            "has_open_positions": n_open > 0,
            "open_positions_count": n_open,
            "open_symbols": open_syms,
        }

        # 2. Merge real closed trades from quota events + profit_vault trade_sweeps (0 synthetic rows)
        seen_ids: set[str] = set()
        vault_broker_by_tid: dict[str, str] = {}
        for sw_map in (v_snap.get("trade_sweeps") or []):
            if isinstance(sw_map, Mapping) and sw_map.get("trade_id") and sw_map.get("broker_id"):
                vault_broker_by_tid[str(sw_map["trade_id"])] = str(sw_map["broker_id"])

        merged_closed: list[dict[str, Any]] = []
        for q_row in quota_closed_rows:
            sym = q_row.get("symbol")
            tid = q_row.get("trade_id")
            if self._is_synthetic_sync_trade(tid, sym):
                continue
            tid_s = str(tid or f"qt-{q_row.get('seq', 0)}")
            if tid_s in seen_ids:
                continue
            seen_ids.add(tid_s)
            occ_utc = str(q_row["occurred_at_utc"])
            skey_s = str(
                q_row.get("session_key")
                or session_date_for(datetime.fromisoformat(occ_utc.replace("Z", "+00:00")))
            )
            raw_brk = q_row.get("broker_id") or vault_broker_by_tid.get(tid_s) or "DUAL_SHIELD"
            brk_s = str(raw_brk)
            merged_closed.append({
                "trade_id": tid_s,
                "symbol": str(sym),
                "broker_id": brk_s,
                "broker_label": friendly_broker_label(brk_s),
                "realized_pnl_usd": str(q_row["realized_pnl_usd"]),
                "occurred_at_utc": occ_utc,
                "occurred_at_pacific": str(q_row.get("occurred_at_pacific") or format_pacific_timestamp(occ_utc)),
                "session_label": str(q_row.get("session_label") or forex_session_label_for_utc(occ_utc)),
                "session_key": skey_s,
            })

        for sw in (v_snap.get("trade_sweeps") or []):
            if not isinstance(sw, Mapping):
                continue
            tid_sw = str(sw.get("trade_id") or "").strip()
            sym_sw = str(sw.get("symbol") or "").strip()
            if self._is_synthetic_sync_trade(tid_sw, sym_sw) or not tid_sw:
                continue
            if tid_sw in seen_ids:
                continue
            seen_ids.add(tid_sw)
            occ_utc = str(sw["occurred_at"])
            raw_sdate = sw.get("session_date")
            if raw_sdate:
                skey_sw = str(raw_sdate)
            else:
                try:
                    skey_sw = session_date_for(datetime.fromisoformat(occ_utc.replace("Z", "+00:00")))
                except ValueError:
                    skey_sw = occ_utc[:10]
            brk_sw = str(sw.get("broker_id") or "DUAL_SHIELD")
            merged_closed.append({
                "trade_id": tid_sw,
                "symbol": sym_sw,
                "broker_id": brk_sw,
                "broker_label": str(sw.get("broker_label") or friendly_broker_label(brk_sw)),
                "realized_pnl_usd": str(sw["realized_net_usd"]),
                "occurred_at_utc": occ_utc,
                "occurred_at_pacific": str(sw.get("occurred_at_pacific") or format_pacific_timestamp(occ_utc)),
                "session_label": str(sw.get("session_label") or forex_session_label_for_utc(occ_utc)),
                "session_key": skey_sw,
            })

        merged_closed.sort(key=lambda item: (str(item["occurred_at_utc"]), str(item["trade_id"])), reverse=True)
        entries_50 = merged_closed[:50]

        session_entries = [
            e
            for e in merged_closed
            if self._entry_matches_active_session(str(e["session_key"]), sdate_curr, str(e["occurred_at_utc"]))
        ]
        session_by_market = self._aggregate_pnl_by_market(session_entries)
        lifetime_by_market = self._aggregate_pnl_by_market(merged_closed)
        session_by_broker = self._aggregate_pnl_by_broker(session_entries)
        lifetime_by_broker = self._aggregate_pnl_by_broker(merged_closed)

        if session_entries:
            mkt_parts = [
                f"{m['symbol']} ({self._fmt_signed_usd(m['realized_pnl_usd'])})"
                for m in session_by_market[:6]
            ]
            brk_parts = [
                f"{b['broker_label']} ({self._fmt_signed_usd(b['realized_pnl_usd'])})"
                for b in session_by_broker[:3]
            ]
            latest_s = session_entries[0]
            summary_str = (
                f"{' \u00b7 '.join(mkt_parts)} \u00b7 {' / '.join(brk_parts)} \u00b7 "
                f"{latest_s['session_label']} \u00b7 "
                f"{latest_s['occurred_at_pacific']} ({latest_s['occurred_at_utc']})"
            )[:500]
        else:
            summary_str = "No closed trades in current session yet"

        realized_pnl_ledger: dict[str, Any] = {
            "entries": entries_50,
            "session_by_market": session_by_market,
            "lifetime_by_market": lifetime_by_market,
            "session_by_broker": session_by_broker,
            "lifetime_by_broker": lifetime_by_broker,
            "session_provenance_summary": summary_str,
        }

        # 3. Last Real Trade (closed trade OR real executed open/add fill in _recent_actions; never synthetic)
        candidates: list[tuple[str, int, dict[str, Any]]] = []
        for ce in entries_50:
            candidates.append((
                str(ce["occurred_at_utc"]),
                2,
                {
                    "trade_id": str(ce["trade_id"]),
                    "symbol": str(ce["symbol"]),
                    "broker_id": str(ce["broker_id"]),
                    "broker_label": str(ce["broker_label"]),
                    "action": "CLOSE",
                    "realized_pnl_usd": str(ce["realized_pnl_usd"]),
                    "occurred_at_utc": str(ce["occurred_at_utc"]),
                    "occurred_at_pacific": str(ce["occurred_at_pacific"]),
                    "session_label": str(ce["session_label"]),
                },
            ))
        for act in self._recent_actions:
            if not isinstance(act, Mapping):
                continue
            tkt_a = act.get("ticket")
            sym_a = act.get("symbol")
            brk_a = act.get("executed_on")
            act_name = str(act.get("action") or "").strip()
            obs_a = str(act.get("observed_at") or "").strip()
            if (
                not tkt_a
                or not sym_a
                or not brk_a
                or not act_name
                or not obs_a
                or self._is_synthetic_sync_trade(str(tkt_a), str(sym_a))
                or str(tkt_a) in seen_ids
            ):
                continue
            brk_a_str = str(brk_a)
            candidates.append((
                obs_a,
                1,
                {
                    "trade_id": str(tkt_a),
                    "symbol": str(sym_a),
                    "broker_id": brk_a_str,
                    "broker_label": friendly_broker_label(brk_a_str),
                    "action": act_name,
                    "realized_pnl_usd": None,
                    "occurred_at_utc": obs_a,
                    "occurred_at_pacific": format_pacific_timestamp(obs_a),
                    "session_label": forex_session_label_for_utc(obs_a),
                },
            ))

        last_trade: dict[str, Any] | None = None
        if candidates:
            candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
            last_trade = candidates[0][2]

        return live_trading_status, last_trade, realized_pnl_ledger

    def status_snapshot(self, *, now: datetime | None = None) -> dict[str, Any]:
        ts = self._now(now)
        v_snap = self._read_vault_snapshot_outside_lock()
        raw_dial_snap = self._read_dial_snapshot_outside_lock()
        pending_disb = Decimal(str(v_snap.get("pending_disbursement_usd", "0") or "0"))
        with self._lock:
            eq_bundle_snap = self._router_equity_bundle_unlocked()
            equities = eq_bundle_snap["equities"]
            total_eq = eq_bundle_snap["total_eq"]
            online_total_eq_snap = eq_bundle_snap["online_total_eq"]
            offline_ids_snap = eq_bundle_snap["offline_brokers"]
            eff_dd_eq_snap = eq_bundle_snap["eff_dd_eq"]
            eff_dd_peak_snap = eq_bundle_snap["eff_dd_peak"]
            ps = self._principal_surplus_metrics(
                total_eq,
                v_snap=v_snap,
                equities=equities,
                offline_brokers=offline_ids_snap,
            )
            in_rec_snap = bool(ps["in_recovery_mode"])
            if hasattr(self._quota, "peek_snapshot"):
                quota_snap = self._quota.peek_snapshot(
                    now=ts,
                    starting_equity=total_eq if total_eq > 0 else None,
                    in_recovery_mode=in_rec_snap,
                )
            else:
                quota_snap = self._quota.snapshot(
                    now=ts,
                    starting_equity=total_eq if total_eq > 0 else None,
                )
            quota_closed_rows = (
                self._quota.recent_closed_trades(limit=200)
                if hasattr(self._quota, "recent_closed_trades")
                else []
            )
            self._last_quota_status = str(quota_snap.get("status", ""))
            self._last_consec_losses = max(0, int(quota_snap.get("consecutive_losses", 0) or 0))
            sdate_curr = str(quota_snap.get("session_date", ""))
        sess_vault_reserved = "0"
        if self._profit_vault is not None and v_snap:
            try:
                if sdate_curr and hasattr(self._profit_vault, "session_totals"):
                    sess_vault_reserved = str(
                        self._profit_vault.session_totals(sdate_curr).get("bank_sweep_usd", "0")
                    )
                else:
                    sess_vault_reserved = str(v_snap.get("bank_sweep_reserved_usd", "0"))
            except Exception as exc_st:
                logger.warning("profit vault session_totals skipped: %s", type(exc_st).__name__)
                sess_vault_reserved = "0"
        with self._lock:
            deployable_eq_val = (
                max(Decimal("0"), online_total_eq_snap - pending_disb)
                if (self._profit_vault is not None and v_snap)
                else online_total_eq_snap
            )
            online_eq_q_snap = online_total_eq_snap.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            offline_notice_snap = self._format_offline_broker_notice(offline_ids_snap, online_eq_q_snap)
            cad_mode = str(quota_snap.get("session_cadence", SESSION_CADENCE_AUTO))
            pinfo = session_period_info_for(ts, session_cadence=cad_mode, in_recovery_mode=in_rec_snap)
            dq_status = str(quota_snap.get("status", ""))
            locked_for_session = dq_status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED)
            operating_mode_val = (
                FOCUS_MODE_RESEARCH_RESPITE
                if locked_for_session
                else OPERATING_MODE_ACTIVE_TRADING
            )
            open_positions_list = [dict(v) for v in self._open_position_meta.values()]
            live_trading_status, last_trade, realized_pnl_ledger = (
                self._build_provenance_and_live_status_unlocked(
                    quota_closed_rows=quota_closed_rows,
                    v_snap=v_snap,
                    sdate_curr=sdate_curr,
                    quota_snap=quota_snap,
                    open_positions_list=open_positions_list,
                    locked_for_session=locked_for_session,
                )
            )
            banked_session = {
                "schema": "cas-forex.banked-session/1",
                "accounting_basis": "INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT",
                "session_date": sdate_curr,
                "initial_capital_usd": decimal_text(ps["principal_usd"]),
                "current_total_equity_usd": decimal_text(ps["current_total_equity_usd"]),
                "net_surplus_usd": decimal_text(ps["net_surplus_usd"]),
                "net_surplus_pct": decimal_text(ps["net_surplus_pct"]),
                "deficit_to_principal_usd": decimal_text(ps["deficit_to_principal_usd"]),
                "capital_status": str(ps["capital_status"]),
                "vault_sweeps_paused_for_recovery": bool(ps["vault_sweeps_paused_for_recovery"]),
                "session_cadence": cad_mode,
                "active_region_window": str(pinfo["active_region_window"]),
                "active_session_leg": int(quota_snap.get("active_session_leg", 1)),
                "can_advance_recovery_session": bool(
                    ps["capital_status"] == CAPITAL_STATUS_RECOVERY_MODE and locked_for_session
                ),
                "banked_net_pnl_usd": str(quota_snap.get("realized_net_pnl_usd", "0")),
                "realized_pnl_pct": str(quota_snap.get("realized_pnl_pct", "0")),
                "peak_realized_pnl_usd": str(quota_snap.get("peak_realized_pnl_usd", "0")),
                "protected_profit_floor_usd": str(quota_snap.get("protected_profit_floor_usd", "0")),
                "ratchet_armed": bool(quota_snap.get("ratchet_armed", False)),
                "closed_trades": int(quota_snap.get("closed_trades", 0)),
                "win_count": int(quota_snap.get("win_count", 0)),
                "loss_count": int(quota_snap.get("loss_count", 0)),
                "vault_total_realized_usd": str(v_snap.get("total_realized_profit_usd", "0")),
                "vault_swept_50pct_usd": str(v_snap.get("bank_sweep_reserved_usd", "0")),
                "session_vault_reserved_50pct_usd": sess_vault_reserved,
                "vault_retained_50pct_usd": str(v_snap.get("retained_trading_usd", "0")),
                "confirmed_bank_payouts_usd": str(v_snap.get("confirmed_settled_disbursed_usd", "0")),
                "pending_unconfirmed_transfers_usd": str(v_snap.get("pending_or_unconfirmed_transfers_usd", "0")),
                "profits_locked_for_session": bool(locked_for_session),
                "operating_mode": operating_mode_val,
                "session_rollover_label": str(pinfo["session_rollover_label"]),
                "next_session_opens_utc": str(pinfo["next_session_opens_utc"]),
                "session_provenance_summary": str(realized_pnl_ledger["session_provenance_summary"]),
                "session_by_market": list(realized_pnl_ledger["session_by_market"]),
                "session_by_broker": list(realized_pnl_ledger["session_by_broker"]),
                "offline_brokers": list(offline_ids_snap),
                "offline_broker_notice": offline_notice_snap,
                "online_equity_usd": decimal_text(online_eq_q_snap),
                "equity_incomplete_brokers_offline": len(offline_ids_snap) > 0,
            }
            cat_snap = self._registry.catalog_snapshot()
            payload = {
                "schema": "cas-forex.ai-trader/1",
                "human_role": "OVERSEER_ONLY",
                "governance_mode": self._governance_mode,
                "governance_reason": self._governance_reason,
                "effective_status": (
                    quota_snap["status"]
                    if quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED, QUOTA_STATUS_LOSS_TRIPPED)
                    else self._governance_mode
                ),
                "respite_mode": quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED),
                "operating_mode": operating_mode_val,
                "live_trading_status": live_trading_status,
                "last_trade": last_trade,
                "realized_pnl_ledger": realized_pnl_ledger,
                "banked_session": banked_session,
                "fast_tick_ms": int(self._fast_tick_ms),
                "cadence": self._last_cadence,
                "markets_evaluated": len(EXPANDED_MARKETS),
                "watchlist_markets": list(EXPANDED_MARKETS),
                "active_model_id": cat_snap["active_model_id"],
                "active_display_name": cat_snap["active_display_name"],
                "active_model_status": cat_snap["active_status"],
                "thinking_depth": cat_snap.get("thinking_depth", "AUTO"),
                "valid_thinking_depths": cat_snap.get("valid_thinking_depths", ["AUTO", "LOW", "MEDIUM", "HIGH"]),
                "last_effective_effort": self._last_effective_effort,
                "last_latency_ms": cat_snap.get("last_latency_ms"),
                "last_regime": self._last_regime,
                "last_pyramid_leg": self._last_pyramid_leg,
                "deployable_equity_usd": decimal_text(deployable_eq_val),
                "bank_sweep_reserved_usd": str(v_snap.get("bank_sweep_reserved_usd", "0")),
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
                "risk_gear": self._resolve_risk_gear(
                    regime=self._last_regime,
                    total_eq=eff_dd_eq_snap,
                    peak_eq=eff_dd_peak_snap,
                    quota_snap=quota_snap,
                ),
                "open_positions": open_positions_list,
                "active_working_markets": sorted({
                    str(v.get("symbol"))
                    for v in self._open_position_meta.values()
                    if v.get("symbol")
                }),
                "recent_actions": list(self._recent_actions),
                "observed_at": _iso(ts),
            }
            open_vals = list(self._open_position_meta.values())
            in_respite_snap = quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED)
            if in_respite_snap:
                top_obs = self._top_watch_symbol or self._last_evaluated_symbol
                focus_sym = str(top_obs or EXPANDED_MARKETS[0])
                focus_status = (
                    f"RESEARCH_RESPITE: Profits Banked ({quota_snap['realized_net_pnl_usd']} USD · "
                    f"Floor {quota_snap['protected_profit_floor_usd']} USD) · Observing {top_obs or '20 MARKETS'}"
                )
            elif open_vals:
                first_pos = open_vals[0]
                focus_sym = str(first_pos.get("symbol") or "NAS100")
                focus_side = str(first_pos.get("side") or "BUY")
                focus_stage = str(first_pos.get("protection_stage") or "INITIAL_SL")
                focus_status = f"IN TRADE: {focus_sym} ({focus_side} · {focus_stage})"
            elif self._last_symbol is not None and self._last_action not in ("WAIT", "VETOED", FOCUS_MODE_RESEARCH_RESPITE):
                focus_sym = str(self._last_symbol)
                focus_status = f"AI EXECUTING: {focus_sym} ({self._last_action})"
            elif self._last_evaluated_symbol is not None:
                focus_sym = str(self._last_evaluated_symbol)
                reg_lbl = str(self._last_evaluated_regime or self._last_regime or "SCANNING")
                focus_status = f"AI EVALUATING: {focus_sym} ({reg_lbl})"
            else:
                focus_sym = str(self._top_watch_symbol or EXPANDED_MARKETS[0])
                focus_status = f"SCANNING {len(EXPANDED_MARKETS)} MARKETS · Top Watch: {focus_sym}"
            self._current_focus_status = focus_status
            payload["current_focus_symbol"] = focus_sym
            payload["current_focus_status"] = focus_status
            payload["market_sessions"] = compute_market_sessions_status(
                ts,
                mt5_tick_fresh=bool(self._cycle_seq > 0 and self._last_cadence.endswith("FAST_TICK")),
            )
            if raw_dial_snap is not None:
                payload["aggression_dial"] = self._resolve_master_dial_summary_unlocked(
                    regime=self._last_regime,
                    total_eq=online_total_eq_snap if online_total_eq_snap > Decimal("0") else total_eq,
                    peak_eq=eff_dd_peak_snap,
                    quota_snap=quota_snap,
                    raw_dial=raw_dial_snap,
                    dd_curr_eq=eff_dd_eq_snap,
                )
            return assert_safe_ai_catalog_payload(payload)
