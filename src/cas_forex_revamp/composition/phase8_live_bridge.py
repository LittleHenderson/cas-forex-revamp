"""Phase 8 Live Trading Bridge wiring Clear Street modules and Compounding/House-Money.

Unifies:
- :class:`NewsShockShield` (5m pre/post red-flag entry pause; protective actions ALWAYS allowed)
- :class:`CompoundingAndMilestoneController` (optional; exact Decimal compounding, House-Money
  milestone ladder, constitutional ``<= 1.00%`` risk & ``<= 10.00%`` drawdown enforcement)
- :class:`ForexMetaValveGate` (mandatory fail-closed ``161``-parameter neural valve gate)
- :class:`SmartExecutionPlanner` / :class:`SmartSliceExecutor` (spread guard & exact sizing)
- :class:`ExecutionEventBus` (priority-isolated ``CRITICAL_PROTECTION`` vs ``LEDGER_ASYNC``)
- :class:`UnifiedRealTimeLedger` (asynchronous realized trade accounting & 0-write snapshots)

Supported brokers: ``HUGOSWAY_MT5``, ``LHFX_MT5``, ``OANDA`` (including
``OANDA_PRACTICE`` and ``OANDA_LIVE``).

Safety invariants:
- Fail-closed if ``valve_gate`` is ``None`` (:class:`Phase8BridgeValveError`).
- Ledger writes run strictly on ``SubscriberLane.LEDGER_ASYNC`` and NEVER block
  ``CRITICAL_PROTECTION`` dispatch (``< 50ms`` even if async subscribers stall or raise).
- Protective actions (``AMEND_STOP``, ``MOVE_BREAKEVEN``, ``TRAIL_STOP``,
  ``CLOSE_POSITION``, ``EMERGENCY_CLOSE_ALL``) are ALWAYS permitted even at the exact
  second of red-flag CPI/FOMC/NFP/ECB/BoE/BoJ releases.
- ``bridge_snapshot()`` performs strictly ZERO SQLite writes across midnight UTC rollovers.
- Zero ``assert`` statements; zero ``float()`` on monetary values; clean thread shutdown.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
import threading
import time
from typing import Any

from cas_forex_revamp.contracts import ContractError, Side, decimal_text
from cas_forex_revamp.execution.smart_execution import (
    AccountMarginState,
    ExecutionPlan,
    ExecutionRefusalError,
    ExecutionStyle,
    ParentOrderRequest,
    QuoteSnapshot,
    RefusalReason,
    SliceRefusalError,
    SmartExecutionPlanner,
    SmartSliceExecutor,
)
from cas_forex_revamp.ledger.unified_ledger import UnifiedRealTimeLedger
from cas_forex_revamp.risk.news_shock_shield import (
    NewsShockShield,
    TradeActionType,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    ValveDecision,
    ValveRefusalError,
)
from cas_forex_revamp.venue.execution_event_bus import (
    ExecutionEvent,
    ExecutionEventBus,
    ExecutionEventType,
    SubscriberLane,
)
from cas_forex_revamp.venue.mt5_broker_bridge import normalize_market_symbol

__all__ = [
    "BRIDGE_SNAPSHOT_SCHEMA",
    "MAX_CONSTITUTIONAL_DRAWDOWN_PCT",
    "MAX_CONSTITUTIONAL_STOP_RISK_PCT",
    "MIN_MARGIN_LEVEL_PCT",
    "Phase8BridgeError",
    "Phase8BridgeValveError",
    "Phase8LiveTradingBridge",
    "PreEntryBridgeDecision",
    "ProtectiveActionResult",
    "SUPPORTED_BROKERS",
]

BRIDGE_SNAPSHOT_SCHEMA = "cas-forex.phase8-live-bridge/1"
MAX_CONSTITUTIONAL_STOP_RISK_PCT = Decimal("1.00")
MAX_CONSTITUTIONAL_DRAWDOWN_PCT = Decimal("0.10")
MIN_MARGIN_LEVEL_PCT = Decimal("1000.0")

SUPPORTED_BROKERS: frozenset[str] = frozenset(
    {
        "HUGOSWAY_MT5",
        "LHFX_MT5",
        "OANDA",
        "OANDA_PRACTICE",
        "OANDA_LIVE",
    }
)

_REALIZING_EVENT_TYPES: frozenset[ExecutionEventType] = frozenset(
    {
        ExecutionEventType.SL_HIT,
        ExecutionEventType.TP_HIT,
        ExecutionEventType.CLOSE_MANUAL,
    }
)


class Phase8BridgeError(ContractError):
    """Base contract error raised by :class:`Phase8LiveTradingBridge`."""


class Phase8BridgeValveError(Phase8BridgeError):
    """Raised fail-closed when the mandatory :class:`ForexMetaValveGate` is missing or invalid."""


def _require_decimal(
    value: Any,
    field: str,
    *,
    allow_none: bool = False,
    positive: bool = False,
    non_negative: bool = False,
) -> Decimal | None:
    if value is None:
        if allow_none:
            return None
        raise Phase8BridgeError(f"{field} is required and must be a finite Decimal")
    if isinstance(value, bool) or isinstance(value, float):
        raise Phase8BridgeError(f"{field} must be Decimal, int, or decimal string, never float or bool")
    if isinstance(value, Decimal):
        dec = value
    elif isinstance(value, int):
        dec = Decimal(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise Phase8BridgeError(f"{field} must be a non-empty decimal string")
        try:
            dec = Decimal(cleaned)
        except InvalidOperation as exc:
            raise Phase8BridgeError(f"{field} is not a valid Decimal: {value!r}") from exc
    else:
        raise Phase8BridgeError(f"{field} must be a finite Decimal, got {type(value).__name__}")
    if not dec.is_finite():
        raise Phase8BridgeError(f"{field} must be finite")
    if positive and dec <= Decimal("0"):
        raise Phase8BridgeError(f"{field} must be > 0")
    if non_negative and dec < Decimal("0"):
        raise Phase8BridgeError(f"{field} must be >= 0")
    return dec


def _require_int(value: Any, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise Phase8BridgeError(f"{field} must be an int, got {type(value).__name__}")
    if value < minimum:
        raise Phase8BridgeError(f"{field} must be >= {minimum}")
    return value


def _normalize_broker_id(broker_id: Any) -> str:
    if not isinstance(broker_id, str) or not broker_id.strip():
        raise Phase8BridgeError("broker_id must be a non-empty string")
    normalized = broker_id.strip().upper()
    if normalized not in SUPPORTED_BROKERS:
        raise Phase8BridgeError(
            f"Unsupported broker_id {broker_id!r}; expected one of {sorted(SUPPORTED_BROKERS)}"
        )
    return normalized


def _normalize_side(side: Side | str) -> Side:
    if isinstance(side, Side):
        return side
    if not isinstance(side, str) or not side.strip():
        raise Phase8BridgeError("side must be Side or non-empty string")
    cleaned = side.strip().upper()
    if cleaned in {"BUY", "LONG"}:
        return Side.BUY
    if cleaned in {"SELL", "SHORT"}:
        return Side.SELL
    raise Phase8BridgeError(f"Unsupported side {side!r}; expected BUY/SELL/LONG/SHORT")


def _normalize_utc(value: datetime | None, field: str = "now_utc") -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise Phase8BridgeError(f"{field} must be a timezone-aware datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise Phase8BridgeError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_event_type(event_type: ExecutionEventType | str) -> ExecutionEventType:
    if isinstance(event_type, ExecutionEventType):
        return event_type
    if isinstance(event_type, str) and event_type.strip():
        try:
            return ExecutionEventType(event_type.strip().upper())
        except ValueError as exc:
            raise Phase8BridgeError(f"Unsupported event_type {event_type!r}") from exc
    raise Phase8BridgeError(f"event_type must be ExecutionEventType, got {type(event_type).__name__}")


def _extract_house_money_status(snapshot_obj: Any) -> tuple[str | None, bool | None, str | None]:
    if snapshot_obj is None:
        return None, None, None
    data = snapshot_obj.to_dict() if hasattr(snapshot_obj, "to_dict") and callable(snapshot_obj.to_dict) else snapshot_obj
    if isinstance(data, Mapping):
        status = data.get("house_money_status")
        ready = data.get("house_money_ready")
        pullout = data.get("suggested_principal_pullout_usd")
        pullout_str = decimal_text(pullout) if isinstance(pullout, Decimal) else (None if pullout is None else str(pullout))
        return (
            None if status is None else str(status),
            None if ready is None else bool(ready),
            pullout_str,
        )
    status = getattr(data, "house_money_status", None)
    ready = getattr(data, "house_money_ready", None)
    pullout = getattr(data, "suggested_principal_pullout_usd", None)
    pullout_str = decimal_text(pullout) if isinstance(pullout, Decimal) else (None if pullout is None else str(pullout))
    return (
        None if status is None else str(status),
        None if ready is None else bool(ready),
        pullout_str,
    )


def _derive_margin_level_pct(
    account_state: AccountMarginState | Mapping[str, Any],
    *,
    equity_usd: Decimal,
) -> Decimal | None:
    """Derive exact Decimal margin level (%) from account_state, rejecting negative used_margin."""
    if isinstance(account_state, AccountMarginState):
        used_m = _require_decimal(
            account_state.used_margin, "used_margin", non_negative=True
        )
        if used_m is None or used_m == Decimal("0"):
            return None
        acct_eq = _require_decimal(account_state.equity, "account_state.equity")
        if acct_eq is None or acct_eq <= Decimal("0"):
            return Decimal("0.0")
        return (acct_eq * Decimal("100")) / used_m

    if isinstance(account_state, Mapping):
        if "used_margin" in account_state and account_state["used_margin"] is not None:
            used_m = _require_decimal(
                account_state["used_margin"], "used_margin", non_negative=True
            )
        else:
            used_m = None
        if (
            "margin_level_pct" in account_state
            and account_state["margin_level_pct"] is not None
        ):
            return _require_decimal(
                account_state["margin_level_pct"],
                "margin_level_pct",
                non_negative=True,
            )
        if used_m is not None and used_m > Decimal("0"):
            raw_eq = account_state.get("equity", equity_usd)
            acct_eq = _require_decimal(raw_eq, "account_state.equity")
            if acct_eq is None or acct_eq <= Decimal("0"):
                return Decimal("0.0")
            return (acct_eq * Decimal("100")) / used_m
        return None

    raise Phase8BridgeError(
        f"account_state must be AccountMarginState or Mapping, got {type(account_state).__name__}"
    )


def _value_per_lot_per_point(
    symbol_norm: str,
    quote: QuoteSnapshot,
    planner: SmartExecutionPlanner,
) -> Decimal:
    profile = planner.profile_for(symbol_norm)
    contract_size = planner.margin_calculator.contract_size_for(symbol_norm)
    raw_value = contract_size * profile.point_size
    if symbol_norm in {"NAS100", "US30", "SPX500", "XAUUSD"}:
        return raw_value
    quote_ccy = symbol_norm[3:]
    if quote_ccy == "USD":
        return raw_value
    if symbol_norm[:3] == "USD":
        mid = quote.mid()
        return (raw_value / mid).quantize(Decimal("0.0001"), rounding=ROUND_FLOOR)
    return raw_value


@dataclass(frozen=True, slots=True)
class PreEntryBridgeDecision:
    """Immutable pre-entry gating decision across News, Compounding, Valve, and Spread Guard."""

    allowed: bool
    reason_code: str
    broker_id: str
    symbol: str
    valve_score: float | None
    risk_budget_usd: Decimal
    news_resume_at_utc: datetime | None
    execution_plan: ExecutionPlan | None
    house_money_status: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "broker_id": self.broker_id,
            "symbol": self.symbol,
            "valve_score": self.valve_score,
            "risk_budget_usd": decimal_text(self.risk_budget_usd),
            "news_resume_at_utc": (
                None if self.news_resume_at_utc is None else _iso_utc(self.news_resume_at_utc)
            ),
            "execution_plan": (
                None if self.execution_plan is None else self.execution_plan.to_dict()
            ),
            "house_money_status": self.house_money_status,
        }


@dataclass(frozen=True, slots=True)
class ProtectiveActionResult:
    """Immutable receipt returned when a protective stop/close action is dispatched."""

    allowed: bool
    reason_code: str
    broker_id: str
    symbol: str
    action: TradeActionType
    event: ExecutionEvent
    is_new_event: bool
    elapsed_ms: Decimal
    news_shield_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "broker_id": self.broker_id,
            "symbol": self.symbol,
            "action": self.action.value,
            "event": self.event.to_dict(),
            "is_new_event": self.is_new_event,
            "elapsed_ms": decimal_text(self.elapsed_ms),
            "news_shield_reason": self.news_shield_reason,
        }


class Phase8LiveTradingBridge:
    """Thread-safe live bridge wiring Phase 8 Clear Street modules + Compounding Controller."""

    def __init__(
        self,
        valve_gate: ForexMetaValveGate | Any | None,
        *,
        ledger: UnifiedRealTimeLedger,
        event_bus: ExecutionEventBus,
        news_shield: NewsShockShield,
        smart_planner: SmartExecutionPlanner,
        smart_executor: SmartSliceExecutor,
        compounding_controller: Any | None = None,
    ) -> None:
        if valve_gate is None or not callable(getattr(valve_gate, "evaluate", None)):
            raise Phase8BridgeValveError(
                "Phase8LiveTradingBridge requires a non-None ForexMetaValveGate with callable evaluate()."
            )
        if ledger is None:
            raise Phase8BridgeError("ledger is required")
        if event_bus is None:
            raise Phase8BridgeError("event_bus is required")
        if news_shield is None:
            raise Phase8BridgeError("news_shield is required")
        if smart_planner is None:
            raise Phase8BridgeError("smart_planner is required")
        if smart_executor is None:
            raise Phase8BridgeError("smart_executor is required")

        self._valve_gate = valve_gate
        self._ledger = ledger
        self._event_bus = event_bus
        self._news_shield = news_shield
        self._smart_planner = smart_planner
        self._smart_executor = smart_executor
        self._compounding_controller = compounding_controller

        self._lock = threading.RLock()
        self._closed = False
        self._sequence = 0

        self._ledger_subscriber_id = self._event_bus.subscribe(
            self._on_ledger_event,
            lane=SubscriberLane.LEDGER_ASYNC,
            name="phase8-bridge-ledger-async",
        )

    @property
    def ledger_subscriber_id(self) -> str:
        return self._ledger_subscriber_id

    @property
    def valve_gate(self) -> Any:
        return self._valve_gate

    @property
    def ledger(self) -> UnifiedRealTimeLedger:
        return self._ledger

    @property
    def event_bus(self) -> ExecutionEventBus:
        return self._event_bus

    @property
    def news_shield(self) -> NewsShockShield:
        return self._news_shield

    @property
    def smart_planner(self) -> SmartExecutionPlanner:
        return self._smart_planner

    @property
    def smart_executor(self) -> SmartSliceExecutor:
        return self._smart_executor

    @property
    def compounding_controller(self) -> Any | None:
        return self._compounding_controller

    def __enter__(self) -> Phase8LiveTradingBridge:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close(timeout=2.0, drain=True)

    def _next_seq(self) -> int:
        with self._lock:
            self._sequence += 1
            return self._sequence

    def _on_ledger_event(self, event: ExecutionEvent) -> None:
        self._ledger.record_execution_event(event)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for asynchronous ledger/UI subscribers to drain queued events."""
        return self._event_bus.flush(timeout=timeout)

    def shutdown(self, timeout: float = 2.0, *, drain: bool = True) -> bool:
        """Unsubscribe ledger listener and cleanly shut down the ExecutionEventBus threads."""
        with self._lock:
            if self._closed:
                return True
            self._closed = True
            sub_id = self._ledger_subscriber_id
        try:
            self._event_bus.unsubscribe(sub_id, timeout=timeout, drain=drain)
        except Exception:
            pass
        return self._event_bus.shutdown(timeout=timeout, drain=drain)

    def close(self, timeout: float = 2.0, *, drain: bool = True) -> bool:
        """Alias for :meth:`shutdown`."""
        return self.shutdown(timeout=timeout, drain=drain)

    def _read_house_money_status(self, equity_usd: Decimal) -> tuple[str | None, bool | None, str | None]:
        if self._compounding_controller is None:
            return None, None, None
        safe_equity = equity_usd if equity_usd >= Decimal("0.00") else Decimal("0.00")
        snap = self._compounding_controller.snapshot(current_equity_usd=safe_equity)
        return _extract_house_money_status(snap)

    def _build_valve_view_and_policy(
        self,
        *,
        account_state: Any,
        equity_usd: Decimal,
        proposal: Any,
        max_entry_units: Decimal | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        policy_override: Mapping[str, Any] | None = None
        if isinstance(account_state, AccountMarginState):
            eff_peak = (
                account_state.peak_equity
                if account_state.peak_equity is not None
                else max(account_state.balance, account_state.equity)
            )
            current_view: dict[str, Any] = {
                "account_id": account_state.account_id,
                "balance": decimal_text(account_state.balance),
                "equity": decimal_text(account_state.equity),
                "peak_equity": decimal_text(eff_peak),
                "available_margin": decimal_text(account_state.free_margin),
                "position_inventory": list(account_state.position_inventory),
            }
        elif isinstance(account_state, Mapping):
            current_view = dict(account_state)
            if "available_margin" not in current_view and "free_margin" in current_view:
                current_view["available_margin"] = current_view["free_margin"]
            if isinstance(current_view.get("policy"), Mapping):
                policy_override = current_view["policy"]
        else:
            raise Phase8BridgeError(
                f"account_state must be AccountMarginState or Mapping, got {type(account_state).__name__}"
            )

        eff_policy: dict[str, Any] = {
            "new_risk_permission": "ALLOWED",
            "management_permission": "ALLOWED",
            "accounting_required": [
                "balance",
                "equity",
                "available_margin",
                "position_inventory",
            ],
        }
        if max_entry_units is not None and max_entry_units > Decimal("0"):
            eff_policy["max_entry_quantity"] = decimal_text(max_entry_units)
        if policy_override is not None:
            eff_policy.update(policy_override)
        return current_view, eff_policy

    def evaluate_pre_entry(
        self,
        *,
        broker_id: str,
        symbol: str,
        side: Side | str,
        equity_usd: Decimal,
        stop_distance_points: Decimal,
        risk_pct: Decimal,
        quote: QuoteSnapshot,
        account_state: AccountMarginState | Mapping[str, Any],
        proposal: Any,
        open_pyramid_count: int = 0,
        max_open_trades: int = 3,
        daily_loss_remaining_usd: Decimal = Decimal("1000.00"),
        drawdown_pct: Decimal = Decimal("0.00"),
        now_utc: datetime | None = None,
    ) -> PreEntryBridgeDecision:
        """Evaluate an entry or pyramid add through News -> Compounding -> Valve -> Spread Guard."""
        norm_broker = _normalize_broker_id(broker_id)
        norm_symbol = normalize_market_symbol(symbol)
        norm_side = _normalize_side(side)
        equity_dec = _require_decimal(equity_usd, "equity_usd")
        stop_pts_dec = _require_decimal(stop_distance_points, "stop_distance_points", positive=True)
        risk_pct_dec = _require_decimal(risk_pct, "risk_pct")
        open_pyr = _require_int(open_pyramid_count, "open_pyramid_count", minimum=0)
        max_trades = _require_int(max_open_trades, "max_open_trades", minimum=1)
        daily_rem_dec = _require_decimal(daily_loss_remaining_usd, "daily_loss_remaining_usd")
        dd_pct_dec = _require_decimal(drawdown_pct, "drawdown_pct", non_negative=True)
        eval_utc = _normalize_utc(now_utc, "now_utc")

        if not isinstance(quote, QuoteSnapshot):
            raise Phase8BridgeError("quote must be a QuoteSnapshot")
        if quote.symbol != norm_symbol:
            raise Phase8BridgeError(
                f"quote symbol {quote.symbol} does not match order symbol {norm_symbol}"
            )

        if (
            equity_dec is None
            or stop_pts_dec is None
            or risk_pct_dec is None
            or daily_rem_dec is None
            or dd_pct_dec is None
        ):
            raise Phase8BridgeError("Required numeric entry arguments must not be None")

        house_money_status, _, _ = self._read_house_money_status(equity_dec)

        # Step 1: NewsShockShield (OPEN_NEW or ADD_POSITION when pyramiding)
        news_action = (
            TradeActionType.ADD_POSITION if open_pyr > 0 else TradeActionType.OPEN_NEW
        )
        news_decision = self._news_shield.evaluate(symbol, news_action, now_utc=eval_utc)
        if not news_decision.allowed:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=news_decision.reason_code,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=Decimal("0.00"),
                news_resume_at_utc=news_decision.resume_at_utc,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        # Step 2: CompoundingAndMilestoneController & constitutional risk/drawdown caps
        if risk_pct_dec <= Decimal("0"):
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code="NON_POSITIVE_RISK_PCT",
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=Decimal("0.00"),
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )
        if risk_pct_dec > MAX_CONSTITUTIONAL_STOP_RISK_PCT:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code="CONSTITUTIONAL_STOP_RISK_EXCEEDED",
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=Decimal("0.00"),
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )
        if dd_pct_dec >= MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code="CONSTITUTIONAL_DRAWDOWN_LIMIT_REACHED",
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=Decimal("0.00"),
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )
        if equity_dec <= Decimal("0"):
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.NON_POSITIVE_EQUITY.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=Decimal("0.00"),
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        margin_level_pct = _derive_margin_level_pct(
            account_state, equity_usd=equity_dec
        )
        if margin_level_pct is not None and margin_level_pct < MIN_MARGIN_LEVEL_PCT:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code="CONSTITUTIONAL_MARGIN_LEVEL_BREACH",
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=Decimal("0.00"),
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        if self._compounding_controller is not None:
            budget = self._compounding_controller.compute_compounding_sizing_budget(
                current_equity_usd=equity_dec,
                risk_pct=risk_pct_dec,
                open_pyramid_count=open_pyr,
                max_open_trades=max_trades,
                daily_loss_remaining_usd=daily_rem_dec,
                drawdown_pct=dd_pct_dec,
                margin_level_pct=margin_level_pct,
            )
            house_money_status = str(budget.house_money_status)
            if not budget.allowed:
                return PreEntryBridgeDecision(
                    allowed=False,
                    reason_code=str(budget.reason_code),
                    broker_id=norm_broker,
                    symbol=norm_symbol,
                    valve_score=None,
                    risk_budget_usd=Decimal("0.00"),
                    news_resume_at_utc=None,
                    execution_plan=None,
                    house_money_status=house_money_status,
                )
            risk_budget_usd = _require_decimal(
                budget.per_trade_risk_usd, "per_trade_risk_usd", non_negative=True
            )
            if risk_budget_usd is None or risk_budget_usd <= Decimal("0"):
                return PreEntryBridgeDecision(
                    allowed=False,
                    reason_code="ZERO_RISK_BUDGET",
                    broker_id=norm_broker,
                    symbol=norm_symbol,
                    valve_score=None,
                    risk_budget_usd=Decimal("0.00"),
                    news_resume_at_utc=None,
                    execution_plan=None,
                    house_money_status=house_money_status,
                )
        else:
            if open_pyr >= max_trades:
                return PreEntryBridgeDecision(
                    allowed=False,
                    reason_code="MAX_PYRAMID_SLOTS_REACHED",
                    broker_id=norm_broker,
                    symbol=norm_symbol,
                    valve_score=None,
                    risk_budget_usd=Decimal("0.00"),
                    news_resume_at_utc=None,
                    execution_plan=None,
                    house_money_status=house_money_status,
                )
            if daily_rem_dec <= Decimal("0"):
                return PreEntryBridgeDecision(
                    allowed=False,
                    reason_code="DAILY_LOSS_BUDGET_EXHAUSTED",
                    broker_id=norm_broker,
                    symbol=norm_symbol,
                    valve_score=None,
                    risk_budget_usd=Decimal("0.00"),
                    news_resume_at_utc=None,
                    execution_plan=None,
                    house_money_status=house_money_status,
                )
            raw_budget = (equity_dec * risk_pct_dec / Decimal("100")).quantize(
                Decimal("0.01"), rounding=ROUND_FLOOR
            )
            risk_budget_usd = min(raw_budget, daily_rem_dec)
            if risk_budget_usd <= Decimal("0"):
                return PreEntryBridgeDecision(
                    allowed=False,
                    reason_code="ZERO_RISK_BUDGET",
                    broker_id=norm_broker,
                    symbol=norm_symbol,
                    valve_score=None,
                    risk_budget_usd=Decimal("0.00"),
                    news_resume_at_utc=None,
                    execution_plan=None,
                    house_money_status=house_money_status,
                )

        # Pre-compute lot budget for valve sizing ceiling (spread checked in Step 4)
        val_per_lot_pt = _value_per_lot_per_point(norm_symbol, quote, self._smart_planner)
        sized_lots: Decimal | None = None
        budget_units: Decimal | None = None
        try:
            sized_lots = self._smart_planner.lots_from_risk_budget(
                risk_budget_usd=risk_budget_usd,
                sl_distance_points=stop_pts_dec,
                value_per_lot_per_point=val_per_lot_pt,
            )
            budget_units = self._smart_planner.margin_calculator.lots_to_units(
                sized_lots, symbol=norm_symbol
            )
        except SliceRefusalError:
            sized_lots = None
            budget_units = None

        # Step 3: Mandatory REAL ForexMetaValveGate evaluation (fail-closed)
        if proposal is None:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.VALVE_REFUSAL.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        current_view, eff_policy = self._build_valve_view_and_policy(
            account_state=account_state,
            equity_usd=equity_dec,
            proposal=proposal,
            max_entry_units=budget_units,
        )
        try:
            valve_decision = self._valve_gate.evaluate(
                proposal,
                current_view=current_view,
                policy=eff_policy,
                now=eval_utc,
            )
        except ValveRefusalError as exc:
            err_score = None if exc.decision is None else exc.decision.mlp_score
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.VALVE_REFUSAL.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=err_score,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )
        except Exception:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.VALVE_REFUSAL.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=None,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        if (
            not isinstance(valve_decision, ValveDecision)
            or not valve_decision.admitted
            or valve_decision.mlp_score < valve_decision.threshold
        ):
            score_val = (
                valve_decision.mlp_score
                if isinstance(valve_decision, ValveDecision)
                else None
            )
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.VALVE_REFUSAL.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=score_val,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        # Step 4: SmartExecutionPlanner spread guard & immutable ExecutionPlan
        profile = self._smart_planner.profile_for(norm_symbol)
        spread_pts = quote.spread_points(profile.point_size)
        if spread_pts > profile.max_spread_points:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.SPREAD_GUARD_EXCEEDED.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=valve_decision.mlp_score,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        if sized_lots is None:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=RefusalReason.SUB_MINIMUM_LOT_SIZE.value,
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=valve_decision.mlp_score,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        sl_distance_price = stop_pts_dec * profile.point_size
        protection = replace(profile.protection, sl_distance=sl_distance_price)
        order_seq = self._next_seq()
        parent_req = ParentOrderRequest(
            parent_order_id=f"p8-{norm_broker.lower()}-{norm_symbol.lower()}-{order_seq:06d}",
            symbol=norm_symbol,
            side=norm_side,
            total_lots=sized_lots,
            style=ExecutionStyle.SINGLE_MARKET,
            slice_count=1,
            protection=protection,
            reason=f"Phase8LiveTradingBridge admitted {norm_broker} {norm_symbol} {norm_side.value}",
        )
        try:
            plan = self._smart_planner.plan(
                parent_req,
                quote,
                now_utc=eval_utc,
                enforce_spread_guard=True,
            )
        except ExecutionRefusalError as exc:
            return PreEntryBridgeDecision(
                allowed=False,
                reason_code=str(exc.reason),
                broker_id=norm_broker,
                symbol=norm_symbol,
                valve_score=valve_decision.mlp_score,
                risk_budget_usd=risk_budget_usd,
                news_resume_at_utc=None,
                execution_plan=None,
                house_money_status=house_money_status,
            )

        return PreEntryBridgeDecision(
            allowed=True,
            reason_code="ENTRY_ADMITTED",
            broker_id=norm_broker,
            symbol=norm_symbol,
            valve_score=valve_decision.mlp_score,
            risk_budget_usd=risk_budget_usd,
            news_resume_at_utc=None,
            execution_plan=plan,
            house_money_status=house_money_status,
        )

    def dispatch_protective_action(
        self,
        *,
        broker_id: str,
        symbol: str,
        action: TradeActionType,
        order_id: str,
        position_ticket: str,
        side: Side | str,
        quantity_lots: Decimal,
        price: Decimal,
        stop_loss: Decimal | None = None,
        take_profit: Decimal | None = None,
        reason: str = "",
        now_utc: datetime | None = None,
    ) -> ProtectiveActionResult:
        """Unconditionally dispatch a protective stop/close action on CRITICAL_PROTECTION (<50ms)."""
        if not isinstance(action, TradeActionType):
            raise Phase8BridgeError(
                f"action must be TradeActionType, got {type(action).__name__}"
            )
        if not action.is_protective:
            raise Phase8BridgeError(
                f"dispatch_protective_action only accepts protective actions, got {action.value}"
            )

        norm_broker = _normalize_broker_id(broker_id)
        norm_symbol = normalize_market_symbol(symbol)
        norm_side = _normalize_side(side)
        qty_dec = _require_decimal(quantity_lots, "quantity_lots", non_negative=True)
        price_dec = _require_decimal(price, "price", non_negative=True)
        sl_dec = _require_decimal(stop_loss, "stop_loss", allow_none=True, non_negative=True)
        tp_dec = _require_decimal(take_profit, "take_profit", allow_none=True, non_negative=True)
        if not isinstance(order_id, str):
            raise Phase8BridgeError("order_id must be a string")
        if not isinstance(position_ticket, str):
            raise Phase8BridgeError("position_ticket must be a string")
        if not isinstance(reason, str):
            raise Phase8BridgeError("reason must be a string")
        if qty_dec is None or price_dec is None:
            raise Phase8BridgeError("quantity_lots and price are required")

        eval_utc = _normalize_utc(now_utc, "now_utc")
        t0_ns = time.perf_counter_ns()

        # Protective actions are ALWAYS allowed even at the exact second of CPI/FOMC/NFP.
        news_decision = self._news_shield.evaluate(symbol, action, now_utc=eval_utc)

        if action in {
            TradeActionType.AMEND_STOP,
            TradeActionType.MOVE_BREAKEVEN,
            TradeActionType.TRAIL_STOP,
        }:
            ev_type = ExecutionEventType.AMEND_STOP
        else:
            ev_type = ExecutionEventType.CLOSE_MANUAL

        seq_num = self._next_seq()
        ticket_part = position_ticket.strip() or order_id.strip() or "all"
        event_id = f"prot-{norm_broker.lower()}-{action.value.lower()}-{ticket_part}-{seq_num:06d}"
        eff_reason = reason.strip() if reason.strip() else f"Protective {action.value}"

        ev = ExecutionEvent(
            event_id=event_id,
            event_type=ev_type,
            broker_id=norm_broker,
            symbol=norm_symbol,
            order_id=order_id,
            position_ticket=position_ticket,
            side=norm_side.value,
            quantity_lots=qty_dec,
            price=price_dec,
            realized_pnl_usd=Decimal("0.00"),
            timestamp_utc=_iso_utc(eval_utc),
            stop_loss=sl_dec,
            take_profit=tp_dec,
            reason=eff_reason,
        )
        stamped, is_new = self._event_bus.publish_idempotent(ev)
        elapsed_ns = time.perf_counter_ns() - t0_ns
        elapsed_ms = (Decimal(elapsed_ns) / Decimal("1000000")).quantize(
            Decimal("0.001"), rounding=ROUND_FLOOR
        )

        return ProtectiveActionResult(
            allowed=True,
            reason_code=f"PROTECTIVE_{action.value}_DISPATCHED",
            broker_id=norm_broker,
            symbol=norm_symbol,
            action=action,
            event=stamped,
            is_new_event=is_new,
            elapsed_ms=elapsed_ms,
            news_shield_reason=news_decision.reason_code,
        )

    def record_broker_fill_or_close(
        self,
        *,
        broker_id: str,
        symbol: str,
        event_type: ExecutionEventType | str,
        event_id: str,
        order_id: str,
        position_ticket: str,
        side: Side | str,
        quantity_lots: Decimal,
        price: Decimal,
        realized_pnl_usd: Decimal = Decimal("0.00"),
        current_equity_usd: Decimal | None = None,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Publish an idempotent broker fill/close asynchronously and evaluate House-Money status."""
        norm_broker = _normalize_broker_id(broker_id)
        norm_symbol = normalize_market_symbol(symbol)
        norm_type = _normalize_event_type(event_type)
        if not isinstance(event_id, str) or not event_id.strip():
            raise Phase8BridgeError("event_id must be a non-empty string")
        if not isinstance(order_id, str):
            raise Phase8BridgeError("order_id must be a string")
        if not isinstance(position_ticket, str):
            raise Phase8BridgeError("position_ticket must be a string")

        norm_side = _normalize_side(side)
        qty_dec = _require_decimal(quantity_lots, "quantity_lots", non_negative=True)
        price_dec = _require_decimal(price, "price", non_negative=True)
        pnl_dec = _require_decimal(realized_pnl_usd, "realized_pnl_usd")
        equity_override = _require_decimal(
            current_equity_usd, "current_equity_usd", allow_none=True
        )
        if qty_dec is None or price_dec is None or pnl_dec is None:
            raise Phase8BridgeError("quantity_lots, price, and realized_pnl_usd are required")

        eval_utc = _normalize_utc(now_utc, "now_utc")
        ev = ExecutionEvent(
            event_id=event_id.strip(),
            event_type=norm_type,
            broker_id=norm_broker,
            symbol=norm_symbol,
            order_id=order_id,
            position_ticket=position_ticket,
            side=norm_side.value,
            quantity_lots=qty_dec,
            price=price_dec,
            realized_pnl_usd=pnl_dec,
            timestamp_utc=_iso_utc(eval_utc),
        )
        pre_publish_equity: Decimal | None = None
        if equity_override is None and self._compounding_controller is not None:
            pre_publish_equity = self._ledger.snapshot(now_utc=eval_utc).effective_equity_usd

        stamped, is_new = self._event_bus.publish_idempotent(ev)

        eval_equity = equity_override
        if eval_equity is None and pre_publish_equity is not None:
            is_realizing = norm_type in _REALIZING_EVENT_TYPES or (
                norm_type in {ExecutionEventType.FILL, ExecutionEventType.PARTIAL_FILL}
                and pnl_dec != Decimal("0")
            )
            if is_new and is_realizing:
                eval_equity = pre_publish_equity + pnl_dec
            else:
                eval_equity = pre_publish_equity

        house_money_status: str | None = None
        house_money_ready: bool | None = None
        suggested_pullout: str | None = None
        if self._compounding_controller is not None and eval_equity is not None:
            house_money_status, house_money_ready, suggested_pullout = (
                self._read_house_money_status(eval_equity)
            )

        return {
            "accepted": True,
            "is_new_event": is_new,
            "event_id": stamped.event_id,
            "seq_id": stamped.seq_id,
            "event_type": stamped.event_type.value,
            "broker_id": stamped.broker_id,
            "symbol": stamped.symbol,
            "order_id": stamped.order_id,
            "position_ticket": stamped.position_ticket,
            "side": stamped.side,
            "quantity_lots": decimal_text(stamped.quantity_lots),
            "price": decimal_text(stamped.price),
            "realized_pnl_usd": decimal_text(stamped.realized_pnl_usd),
            "timestamp_utc": stamped.timestamp_utc,
            "payload_sha256": stamped.payload_sha256,
            "ledger_dispatch_lane": SubscriberLane.LEDGER_ASYNC.value,
            "evaluated_equity_usd": (
                None
                if eval_equity is None
                else format(eval_equity.quantize(Decimal("0.01")), "f")
            ),
            "house_money_status": house_money_status,
            "house_money_ready": house_money_ready,
            "suggested_principal_pullout_usd": suggested_pullout,
        }

    def bridge_snapshot(
        self,
        symbols: Sequence[str] = ("NAS100", "US30", "XAUUSD", "EUR_USD"),
        current_equity_usd: Decimal | None = None,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Return a strictly 0-write aggregated snapshot of News, EventBus, Ledger, and Compounding."""
        eval_utc = _normalize_utc(now_utc, "now_utc")
        equity_override = _require_decimal(
            current_equity_usd, "current_equity_usd", allow_none=True
        )

        news_snap = self._news_shield.shield_status_snapshot(symbols, now_utc=eval_utc)
        bus_metrics = self._event_bus.metrics()
        ledger_snap = self._ledger.snapshot(now_utc=eval_utc)

        compounding_snap: dict[str, Any] | None = None
        if self._compounding_controller is not None:
            eff_equity = (
                equity_override
                if equity_override is not None
                else ledger_snap.effective_equity_usd
            )
            raw_comp = self._compounding_controller.snapshot(
                current_equity_usd=eff_equity
            )
            if hasattr(raw_comp, "to_dict") and callable(raw_comp.to_dict):
                compounding_snap = raw_comp.to_dict()
            elif isinstance(raw_comp, Mapping):
                compounding_snap = dict(raw_comp)
            else:
                compounding_snap = {"raw": str(raw_comp)}

        return {
            "schema": BRIDGE_SNAPSHOT_SCHEMA,
            "as_of_utc": _iso_utc(eval_utc),
            "supported_brokers": sorted(SUPPORTED_BROKERS),
            "valve_weights_sha256": getattr(self._valve_gate, "weights_sha256", None),
            "news_shield": news_snap,
            "event_bus": bus_metrics,
            "ledger": ledger_snap.to_dict(),
            "compounding": compounding_snap,
        }
