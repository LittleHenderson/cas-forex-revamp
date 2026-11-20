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
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal, localcontext
from hashlib import sha256
import json
import logging
from pathlib import Path
import re
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
    QUOTA_STATUS_PROFIT_FLOOR_LOCKED,
    QUOTA_STATUS_SOFT,
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

SOFT_DRAWDOWN_DOWNSHIFT_PCT = Decimal("0.10")


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
    """Resolve active Risk Gear & Dynamic Daily Profit Quota strictly inside owner ceilings.

    Safety invariants:
    - The AI can NEVER raise its own safety ceiling above owner_max_risk_pct,
      owner_max_drawdown_pct, or owner_hard_quota_usd.
    - AUTO_ADAPTIVE scales across three owner-bounded gears:
      1. Conservative (CHOP_RANGE / loss streak / drawdown >= 10%): 1.00% risk, $500 soft / $1,000 hard.
      2. Growth (TREND_IGNITION, 0 losses, drawdown < 10%): 2.50% risk, $2,000 soft / $2,500 hard.
      3. Strong-Trend Runner (STRONG_TREND, 0 losses, drawdown < 10%): 5.00% risk, $2,000 soft / $3,000 hard.
    """
    mode = str(owner_gear_mode or RISK_GEAR_AUTO_ADAPTIVE).strip().upper()
    if mode not in VALID_RISK_GEAR_MODES:
        raise ContractError(f"owner_gear_mode must be one of {VALID_RISK_GEAR_MODES}")
    max_risk = decimal_value(owner_max_risk_pct, "owner_max_risk_pct", positive=True)
    max_dd = decimal_value(owner_max_drawdown_pct, "owner_max_drawdown_pct", positive=True)
    if isinstance(drawdown_pct, bool) or not isinstance(drawdown_pct, Decimal) or not drawdown_pct.is_finite():
        raise ContractError("drawdown_pct must be a finite Decimal")
    if drawdown_pct < Decimal("0"):
        raise ContractError("drawdown_pct must be non-negative")
    dd = decimal_value(drawdown_pct.quantize(Decimal("0.0000000001"), rounding=ROUND_CEILING), "drawdown_pct")
    hard_cap = decimal_value(owner_hard_quota_usd, "owner_hard_quota_usd", positive=True)
    soft_cap = decimal_value(owner_soft_quota_usd, "owner_soft_quota_usd", positive=True)
    consec = max(0, int(consecutive_losses))
    reg = str(regime or REGIME_CHOP_RANGE).strip().upper()

    if mode == RISK_GEAR_CONSERVATIVE:
        active_gear = ACTIVE_GEAR_CONSERVATIVE
        target_risk = Decimal("1.00")
        target_soft = Decimal("500")
        target_hard = Decimal("1000")
        reason = "Owner selected Conservative Gear (1.00% risk · $500/$1,000 daily quota)."
    elif mode == RISK_GEAR_AGGRESSIVE:
        active_gear = ACTIVE_GEAR_STRONG_TREND_RUNNER
        target_risk = Decimal("5.00")
        target_soft = Decimal("2000")
        target_hard = Decimal("3000")
        reason = "Owner selected Aggressive Gear (up to 5.00% risk · $2,000/$3,000 daily quota under Valve ceiling)."
    else:
        if dd >= SOFT_DRAWDOWN_DOWNSHIFT_PCT:
            active_gear = ACTIVE_GEAR_CONSERVATIVE
            target_risk = Decimal("1.00")
            target_soft = Decimal("500")
            target_hard = Decimal("1000")
            dd_pct_disp = (dd * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
            reason = (
                f"Auto-downshifted to Conservative Gear (drawdown {decimal_text(dd_pct_disp)}% >= 10% soft floor)."
            )
        elif consec >= 1:
            active_gear = ACTIVE_GEAR_CONSERVATIVE
            target_risk = Decimal("1.00")
            target_soft = Decimal("500")
            target_hard = Decimal("1000")
            reason = f"Auto-downshifted to Conservative Gear (loss streak {consec} >= 1)."
        elif reg == REGIME_STRONG_TREND:
            active_gear = ACTIVE_GEAR_STRONG_TREND_RUNNER
            target_risk = Decimal("5.00")
            target_soft = Decimal("2000")
            target_hard = Decimal("3000")
            reason = "Strong-Trend Runner Gear active (0 loss streak, <10% drawdown: up to 5.00% risk · $2,000/$3,000 quota)."
        elif reg == REGIME_TREND_IGNITION:
            active_gear = ACTIVE_GEAR_GROWTH
            target_risk = Decimal("2.50")
            target_soft = Decimal("2000")
            target_hard = Decimal("2500")
            reason = "Growth Gear active on Trend Ignition (0 loss streak, <10% drawdown: 2.50% risk · $2,000/$2,500 quota)."
        else:
            active_gear = ACTIVE_GEAR_CONSERVATIVE
            target_risk = Decimal("1.00")
            target_soft = Decimal("500")
            target_hard = Decimal("1000")
            reason = f"Conservative Gear active in {reg} regime (1.00% risk · $500/$1,000 quota)."

    eff_risk = min(target_risk, max_risk)
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
        "soft_drawdown_downshift_pct": decimal_text(SOFT_DRAWDOWN_DOWNSHIFT_PCT),
        "owner_max_drawdown_pct": decimal_text(max_dd),
        "reason": reason,
    }


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
        risk_gear_mode: str | None = None,
        risk_gear_path: str | Path | None = None,
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
        if execution_gate is None or not callable(execution_gate):
            raise ContractError(
                "AutonomousAiTrader requires an explicit execution_gate (DurableModelExecutionGate); no-op fallback is forbidden"
            )
        self._execution_gate = execution_gate
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

                for pos in venue.positions:
                    if pos.ticket in self._open_position_meta:
                        self._open_position_meta[pos.ticket]["profit"] = decimal_text(pos.profit)

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
                                q_closed = self._quota.record_realized_trade(
                                    pnl_dec,
                                    symbol=sym_closed,
                                    ticket=safe_ticket,
                                    starting_equity=total_eq if total_eq > Decimal("0") else None,
                                    now=ts,
                                )
                                if pnl_dec > Decimal("0") and self._profit_vault is not None:
                                    self._profit_vault.record_realized_close(
                                        trade_id=safe_ticket,
                                        symbol=sym_closed,
                                        broker_id=broker_id,
                                        realized_net_usd=pnl_dec,
                                        occurred_at=ts,
                                    )
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
        eff_eq = (
            self._router.barbell.effective_total_equity(self._router.equities())
            if hasattr(self._router.barbell, "effective_total_equity")
            else total_equity
        )
        sizing_equity = min(total_equity, eff_eq) if eff_eq > Decimal("0") else total_equity
        budget = self._router.barbell.max_stop_risk_amount(sizing_equity) * risk_multiplier
        active_mt5: tuple[str, Mt5PaperBrokerVenue] | None = None
        first_mt5: Mt5PaperBrokerVenue | None = None
        for bid_id in self._router.priority_order:
            venue = self._router.venues.get(bid_id)
            if isinstance(venue, Mt5PaperBrokerVenue):
                if first_mt5 is None:
                    first_mt5 = venue
                if venue.account is not None and active_mt5 is None:
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
    ) -> tuple[str, Side, Decimal, Decimal, str, str, bool, str | None, int] | None:
        """Scan watchlist with TrendRegimeDetector, House-Money ADD pyramiding, and correlation cap."""
        ordered_syms = list(INDEX_INSTRUMENTS) + [s for s in markets if s not in INDEX_INSTRUMENTS]
        open_meta_list = list(self._open_position_meta.values())
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
        return None

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
            if self._profit_vault is not None:
                self._profit_vault.record_realized_close(
                    trade_id=ticket,
                    symbol=symbol,
                    broker_id="DUAL_SHIELD",
                    realized_net_usd=pnl_usd,
                    occurred_at=ts,
                )
            if snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                self._current_focus_status = (
                    f"RESEARCH_RESPITE: Profits Banked ({snap['realized_net_pnl_usd']} USD · "
                    f"Floor {snap['protected_profit_floor_usd']} USD) · "
                    f"Observing {self._top_watch_symbol or '20 MARKETS'}"
                )
            if not snap["new_risk_allowed"]:
                self._governance_reason = str(snap["lock_reason"] or snap["status"])
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

        # Phase 1 (under self._lock): fast stop protection + market/setup/pyramid planning
        with self._lock:
            self._cycle_seq += 1
            cycle_id = f"cycle-{self._cycle_seq}"
            self._last_cadence = f"{self._fast_tick_ms}ms_FAST_TICK" if fast_tick else f"STANDARD_{len(EXPANDED_MARKETS)}_MARKETS"

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
            deployable_eq = self._profit_vault.deployable_equity(total_eq) if self._profit_vault is not None else total_eq
            self._quota.observe_day_start(total_eq, now=ts)

            allowed, quota_veto, risk_mult = self._quota.evaluate_new_risk(
                ActionKind.OPEN, now=ts, starting_equity=total_eq
            )
            q_snap = self._quota.snapshot(now=ts, starting_equity=total_eq if total_eq > 0 else None)
            quota_status = q_snap["status"]
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

            if self._governance_mode != GOVERNANCE_ACTIVE or not allowed:
                wait_reason = quota_veto if not allowed else f"Overseer governance is {self._governance_mode}"
                if not allowed:
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
                total_eq=total_eq,
                deployable_eq=deployable_eq,
                risk_mult=Decimal("0.50") if strong_runner_eligible else risk_mult,
                fast_tick=fast_tick,
                allow_cold_open=allowed,
            )
            if setup is None:
                self._last_action = "WAIT"
                self._last_symbol = None
                self._last_reason = (
                    str(quota_veto)
                    if strong_runner_eligible
                    else "No risk-compliant momentum or trend setup clears spread/regime gate."
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
            quota_full = self._quota.snapshot(now=ts, starting_equity=total_eq if total_eq > 0 else None)
            gear_info = self._resolve_risk_gear(
                regime=regime_name, total_eq=total_eq, peak_eq=peak_eq, quota_snap=quota_full
            )
            realized_today = Decimal(str(quota_full.get("realized_net_pnl_usd", "0")))
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

            if (
                self._registry.fast_scout_enabled
                and active_id != "gemini-decision-1"
                and self._registry.is_model_ready("gemini-decision-1")
                and not is_pyramid_add
            ):
                scout_q = [{
                    "market": sym,
                    "side": side.value,
                    "spread": decimal_text(ask - bid),
                    "setup": setup_note,
                    "choices": ["WAIT", action_ref],
                }]
                try:
                    if hasattr(self._execution_gate, "admit_scout_call"):
                        self._execution_gate.admit_scout_call(model_id="gemini-decision-1", request_id=cycle_id, now=ts)
                    else:
                        scout_spec, _, _ = self._registry.build_backend("gemini-decision-1")
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
                        self._execution_gate(scout_inv)
                    scout = self._registry.scout_opportunities(scout_q)
                except FrontierTransportError as scout_exc:
                    self._registry.record_call(
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
                self._last_scout = scout
                if scout.get("executed") and not scout.get("wake_heavy_model"):
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
            spec, backend, verifier = self._registry.build_backend(active_id, reasoning_effort=eff_depth)
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

            equities = self._router.equities()
            total_eq = self._router.barbell.total_equity(equities)
            peak_eq = self._router.peak_equity() or total_eq
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
                self._last_reason = f"ForexMetaValveGate vetoed {active_id} {req_kind.value} proposal on {sym}"
                raise

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
                    if pos.profit > Decimal("0") and self._profit_vault is not None:
                        self._profit_vault.record_realized_close(
                            trade_id=pos.ticket,
                            symbol=pos.symbol,
                            broker_id=broker_id,
                            realized_net_usd=pos.profit,
                            occurred_at=ts,
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
                if unlock_recovery_token is not None:
                    self._quota.unlock_session(
                        owner_request_id=f"{owner_request_id}-q",
                        reason=reason,
                        recovery_verifier=verifier,
                        recovery_token=unlock_recovery_token,
                        now=ts,
                    )
            else:
                self._quota.unlock_session(
                    owner_request_id=owner_request_id,
                    reason=reason,
                    recovery_verifier=verifier,
                    recovery_token=recovery_token,
                    now=ts,
                )
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
                    if quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED, QUOTA_STATUS_LOSS_TRIPPED)
                    else self._governance_mode
                ),
                "respite_mode": quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED),
                "operating_mode": (
                    FOCUS_MODE_RESEARCH_RESPITE
                    if quota_snap["status"] in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED)
                    else OPERATING_MODE_ACTIVE_TRADING
                ),
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
                "deployable_equity_usd": decimal_text(
                    self._profit_vault.deployable_equity(total_eq) if self._profit_vault is not None else total_eq
                ),
                "bank_sweep_reserved_usd": (
                    self._profit_vault.snapshot()["bank_sweep_reserved_usd"] if self._profit_vault is not None else "0"
                ),
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
                    total_eq=total_eq,
                    peak_eq=self._router.peak_equity() or total_eq,
                    quota_snap=quota_snap,
                ),
                "open_positions": [dict(v) for v in self._open_position_meta.values()],
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
            return assert_safe_ai_catalog_payload(payload)
