"""Trading Aggression Dial (20..100 bps = 0.20%..1.00% in 0.01% steps) & Section B.5 5-Tier Controls.

Provides exact integer-bp / integer-cent / Decimal proportional scaling across all 81
single-unit positions (0.20%, 0.21%, 0.22%, ..., 1.00%) and all 5 Section B.5 parallel
account tiers ($300,000, $6,000, $3,000, $1,000, $300) = 405 exact tier-step combinations,
harmonized with PR #25 constitutional ceilings:
  - MAX_CONSTITUTIONAL_STOP_RISK_PCT = Decimal("1.00") (MAX_RISK_BPS = 100, <= 1.00%)
  - MAX_CONSTITUTIONAL_DRAWDOWN_PCT  = Decimal("0.10") (<= 10.00% portfolio drawdown)
  - MIN_CONSTITUTIONAL_VALVE_PROB    = Decimal("0.55") (ForexMetaValveGate floor)
  - Owner primary key enforcement (OWNER_FULL_CONTROL vs DEVICE_READ_AND_EXPLAINER)

Supports AI Discretion over the Master Trading Aggression Dial (shifting dynamically UP
in confirmed Trends / Strong Trends and DOWN in Chop / Losses / Drawdown, strictly
clamped to 20..ai_discretion_ceiling_bps and never breaching constitutional ceilings)
plus Manual Lock (ai_discretion_enabled=False), durable SQLite WAL persistence with a
tamper-evident SHA-256 audit chain, strictly zero-write read-only snapshots (?mode=ro
+ PRAGMA query_only=ON), and LIVE-mode high-risk confirmation gating (>= 80 bps / 0.80%).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import sqlite3
from threading import RLock
from types import MappingProxyType
from typing import Any

from cas_forex_revamp.contracts import ContractError, canonical_bytes
from cas_forex_revamp.contracts.primitives import identifier, utc_time

AGGRESSION_DIAL_SCHEMA = "cas-forex.aggression-dial/1"
REFERENCE_CAPITAL_USD = Decimal("300000.00")
REFERENCE_CAPITAL_CENTS = 30_000_000

MIN_RISK_BPS = 20
MAX_RISK_BPS = 100
DEFAULT_MASTER_RISK_BPS = 60
HIGH_RISK_MIN_BPS = 80
DEFAULT_AI_DISCRETION_ENABLED = True
DEFAULT_AI_DISCRETION_CEILING_BPS = MAX_RISK_BPS
DEFAULT_AUTO_SHIFT_ENABLED = DEFAULT_AI_DISCRETION_ENABLED
SOFT_GOAL_RATIO = Decimal("0.70")
GENESIS_AUDIT_SHA256 = "0" * 64

MAX_CONSTITUTIONAL_STOP_RISK_PCT = Decimal("1.00")
MAX_CONSTITUTIONAL_DRAWDOWN_PCT = Decimal("0.10")
MIN_CONSTITUTIONAL_VALVE_PROB = Decimal("0.55")
STRONG_TREND_EXTREME_VALVE_SCORE = Decimal("0.72")

ACCESS_MODE_OWNER_FULL_CONTROL = "OWNER_FULL_CONTROL"
ACCESS_MODE_DEVICE_READ_AND_EXPLAINER = "DEVICE_READ_AND_EXPLAINER"

PRESET_SYNC_MASTER = "SYNC_MASTER"
PRESET_SYNC_ALL_TO_MASTER = "SYNC_ALL_TO_MASTER"
PRESET_STAGGER_SAFE_TO_HIGH = "STAGGER_SAFE_TO_HIGH"
PRESET_STAGGER_SAFE_TO_EXTREME = "STAGGER_SAFE_TO_EXTREME"
PRESET_ALL_BALANCED = "ALL_BALANCED"
PRESET_ALL_SAFE = "ALL_SAFE"
VALID_TIER_PRESETS: tuple[str, ...] = (
    PRESET_SYNC_MASTER,
    PRESET_SYNC_ALL_TO_MASTER,
    PRESET_STAGGER_SAFE_TO_HIGH,
    PRESET_STAGGER_SAFE_TO_EXTREME,
    PRESET_ALL_BALANCED,
    PRESET_ALL_SAFE,
)

DEFAULT_TIER_ORDER: tuple[str, ...] = (
    "TIER_1_CURRENT",
    "TIER_4_6000",
    "TIER_3_3000",
    "TIER_2_1000",
    "TIER_5_300",
)

DEFAULT_TIER_CAPITALS: Mapping[str, Decimal] = MappingProxyType(
    {
        "TIER_1_CURRENT": Decimal("300000.00"),
        "TIER_2_1000": Decimal("1000.00"),
        "TIER_3_3000": Decimal("3000.00"),
        "TIER_4_6000": Decimal("6000.00"),
        "TIER_5_300": Decimal("300.00"),
    }
)

DEFAULT_TIER_LABELS: Mapping[str, str] = MappingProxyType(
    {
        "TIER_1_CURRENT": "Current Barbell ($300,000)",
        "TIER_2_1000": "Tier $1,000 Starter",
        "TIER_3_3000": "Tier $3,000 Growth",
        "TIER_4_6000": "Tier $6,000 Accelerator",
        "TIER_5_300": "Tier $300 Micro Challenge",
    }
)

STAGGER_SAFE_TO_HIGH_BPS: Mapping[str, int] = MappingProxyType(
    {
        "TIER_1_CURRENT": 25,
        "TIER_4_6000": 45,
        "TIER_3_3000": 65,
        "TIER_2_1000": 85,
        "TIER_5_300": 100,
    }
)
STAGGER_SAFE_TO_EXTREME_BPS: Mapping[str, int] = STAGGER_SAFE_TO_HIGH_BPS

_UNBREAKABLE_GUARDRAILS_DATA: Mapping[str, Any] = MappingProxyType(
    {
        "valve_required": True,
        "valve_controller": "tks_meta_valve_controller",
        "valve_parameters": 161,
        "valve_cutoff": "0.55",
        "min_signal_prob": "0.55",
        "max_constitutional_stop_risk_pct": "1.00",
        "max_constitutional_drawdown_pct": "0.10",
        "min_margin_level_pct": "1000.0",
        "lot_floor": "0.01",
        "lot_rounding": "ROUND_FLOOR",
        "fast_stop_protection_ms": 50,
        "max_drawdown_brake_pct": "10.00",
    }
)

_ACTOR_MAX_LEN = 120
_REGIME_MAX_LEN = 64


class AggressionDialError(ContractError):
    """Raised when an aggression dial configuration or input is invalid."""


class HighRiskConfirmationRequiredError(AggressionDialError):
    """Raised in LIVE mode when requesting risk_bps >= 80 (0.80%..1.00%) without confirmation."""


class OwnerKeyRequiredError(AggressionDialError):
    """Raised when a paired read-only device attempts to mutate aggression controls."""


@dataclass(frozen=True)
class AnchorKnot:
    """Exact integer anchor knot for piecewise-linear risk_bps interpolation."""

    risk_bps: int
    label: str
    max_open_trades: int
    prob_bp: int
    ref_300k_goal_cents: int
    ref_300k_loss_cents: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_bps": self.risk_bps,
            "risk_pct": format(bps_to_pct_decimal(self.risk_bps), "f"),
            "label": self.label,
            "max_open_trades": self.max_open_trades,
            "prob_bp": self.prob_bp,
            "min_signal_prob": format(bps_to_pct_decimal(self.prob_bp), "f"),
            "ref_300k_goal_cents": self.ref_300k_goal_cents,
            "ref_300k_loss_cents": self.ref_300k_loss_cents,
            "ref_300k_goal_usd": format(cents_to_usd_decimal(self.ref_300k_goal_cents), "f"),
            "ref_300k_loss_usd": format(cents_to_usd_decimal(self.ref_300k_loss_cents), "f"),
        }


AGGRESSION_ANCHOR_KNOTS: tuple[AnchorKnot, ...] = (
    AnchorKnot(20, "Safe", 1, 78, 150000, 75000),
    AnchorKnot(40, "Steady", 2, 72, 300000, 150000),
    AnchorKnot(60, "Balanced", 3, 66, 450000, 250000),
    AnchorKnot(85, "Risky", 5, 59, 750000, 475000),
    AnchorKnot(95, "High Risk", 6, 55, 1000000, 600000),
    AnchorKnot(100, "Extreme High Risk", 8, 55, 1500000, 850000),
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def div_round_half_up(num: int, den: int) -> int:
    """Exact integer half-up division for positive integers, matching JS BigInt."""
    if isinstance(num, bool) or not isinstance(num, int) or num < 0:
        raise AggressionDialError("div_round_half_up numerator must be a non-negative int")
    if isinstance(den, bool) or not isinstance(den, int) or den <= 0:
        raise AggressionDialError("div_round_half_up denominator must be a positive int")
    return (num + den // 2) // den


def _validate_risk_bps(value: Any, field: str = "risk_bps") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AggressionDialError(
            f"{field} must be an integer between {MIN_RISK_BPS} and {MAX_RISK_BPS}"
        )
    if value < MIN_RISK_BPS or value > MAX_RISK_BPS:
        raise AggressionDialError(
            f"{field} must be between {MIN_RISK_BPS} and {MAX_RISK_BPS} (got {value})"
        )
    return value


def _validate_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise AggressionDialError(f"{field} must be a boolean")
    return value


def _validate_decimal(
    value: Any,
    field: str,
    *,
    positive: bool = False,
    non_negative: bool = False,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, Decimal):
        raise AggressionDialError(f"{field} must be an exact Decimal (no float/bool)")
    if not value.is_finite():
        raise AggressionDialError(f"{field} must be a finite Decimal")
    if positive and value <= Decimal("0"):
        raise AggressionDialError(f"{field} must be > 0")
    if non_negative and value < Decimal("0"):
        raise AggressionDialError(f"{field} must be >= 0")
    return value


def _validate_non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AggressionDialError(f"{field} must be a non-negative integer")
    if value < 0:
        raise AggressionDialError(f"{field} must be >= 0")
    return value


def _validate_actor(actor: Any) -> str:
    if not isinstance(actor, str):
        raise AggressionDialError("actor must be a non-empty string")
    cleaned = actor.strip()
    if not cleaned or len(cleaned) > _ACTOR_MAX_LEN:
        raise AggressionDialError(f"actor must be 1..{_ACTOR_MAX_LEN} characters")
    return cleaned


def _validate_regime(regime: Any) -> str:
    if not isinstance(regime, str):
        raise AggressionDialError("regime must be a non-empty string")
    cleaned = regime.strip().upper()
    if not cleaned or len(cleaned) > _REGIME_MAX_LEN:
        raise AggressionDialError(f"regime must be 1..{_REGIME_MAX_LEN} characters")
    return cleaned


def _validate_valve_score(valve_score: Any) -> Decimal:
    val = _validate_decimal(valve_score, "valve_score", non_negative=True)
    if val > Decimal("1.00"):
        raise AggressionDialError(f"valve_score must be in [0.00, 1.00] (got {val})")
    return val


def _q2(value: Decimal) -> Decimal:
    with localcontext() as ctx:
        ctx.prec = 28
        return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def bps_to_pct_decimal(bps: int) -> Decimal:
    """Convert integer basis-point-style hundredths (e.g. 60 -> Decimal('0.60'))."""
    if isinstance(bps, bool) or not isinstance(bps, int) or bps < 0:
        raise AggressionDialError("bps must be a non-negative integer")
    with localcontext() as ctx:
        ctx.prec = 28
        return (Decimal(bps) / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def cents_to_usd_decimal(cents: int) -> Decimal:
    """Convert integer USD cents to exact 2-decimal-place Decimal dollars."""
    if isinstance(cents, bool) or not isinstance(cents, int) or cents < 0:
        raise AggressionDialError("cents must be a non-negative integer")
    with localcontext() as ctx:
        ctx.prec = 28
        return (Decimal(cents) / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def usd_to_cents_int(amount_usd: Decimal, field: str = "capital_usd") -> int:
    """Convert a positive Decimal USD figure to exact integer cents (ROUND_HALF_UP)."""
    val = _q2(_validate_decimal(amount_usd, field, positive=True))
    return int((val * Decimal("100")).to_integral_exact())


def validate_constitutional_stop_risk_pct(risk_pct: Decimal) -> Decimal:
    """Fail-closed validation that per-trade stop risk <= MAX_CONSTITUTIONAL_STOP_RISK_PCT (1.00%)."""
    val = _validate_decimal(risk_pct, "risk_pct", positive=True)
    if val > MAX_CONSTITUTIONAL_STOP_RISK_PCT:
        raise AggressionDialError(
            f"Constitutional ceiling violation: risk_pct {val}% exceeds "
            f"MAX_CONSTITUTIONAL_STOP_RISK_PCT ({MAX_CONSTITUTIONAL_STOP_RISK_PCT}%)"
        )
    return val


def validate_constitutional_drawdown_pct(max_drawdown_pct: Decimal) -> Decimal:
    """Fail-closed validation that max drawdown ceiling <= MAX_CONSTITUTIONAL_DRAWDOWN_PCT (0.10)."""
    val = _validate_decimal(max_drawdown_pct, "max_drawdown_pct", positive=True)
    if val > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
        raise AggressionDialError(
            f"Constitutional ceiling violation: max_drawdown_pct {val} exceeds "
            f"MAX_CONSTITUTIONAL_DRAWDOWN_PCT ({MAX_CONSTITUTIONAL_DRAWDOWN_PCT})"
        )
    return val


def validate_constitutional_signal_prob(min_signal_prob: Decimal) -> Decimal:
    """Fail-closed validation that min_signal_prob stays in [0.55, 1.00]."""
    val = _validate_decimal(min_signal_prob, "min_signal_prob", positive=True)
    if val < MIN_CONSTITUTIONAL_VALVE_PROB or val > Decimal("1.00"):
        raise AggressionDialError(
            f"Constitutional ceiling violation: min_signal_prob {val} must be in "
            f"[{MIN_CONSTITUTIONAL_VALVE_PROB}, 1.00]"
        )
    return val


def unbreakable_guardrails(*, min_signal_prob: Decimal | None = None) -> dict[str, Any]:
    """Return a fresh copy of the unbreakable safety guardrails active at all risk_bps 20..100."""
    out = dict(_UNBREAKABLE_GUARDRAILS_DATA)
    if min_signal_prob is not None:
        validated_prob = validate_constitutional_signal_prob(min_signal_prob)
        out["min_signal_prob"] = format(validated_prob, "f")
    return out


def zone_label_and_css_for_bps(risk_bps: int) -> tuple[str, str]:
    """Map any risk_bps (20..100) to its exact human zone label and strict-CSP CSS class."""
    bps = _validate_risk_bps(risk_bps, "risk_bps")
    if bps <= 29:
        return ("Safe", "dial-lvl-1")
    if bps <= 39:
        return ("Calm", "dial-lvl-2")
    if bps <= 49:
        return ("Steady", "dial-lvl-3")
    if bps <= 59:
        return ("Moderate", "dial-lvl-4")
    if bps <= 69:
        return ("Balanced", "dial-lvl-5")
    if bps <= 74:
        return ("Active", "dial-lvl-6")
    if bps <= 79:
        return ("Bold", "dial-lvl-7")
    if bps <= 89:
        return ("Risky", "dial-lvl-8")
    if bps <= 95:
        return ("High Risk", "dial-lvl-10")
    return ("Extreme High Risk", "dial-lvl-11")


def scale_cents_from_300k(ref_300k_cents: int, tier_cap_cents: int) -> int:
    """Exact integer half-up tier scaling matching JS BigInt bit-for-bit."""
    if isinstance(ref_300k_cents, bool) or not isinstance(ref_300k_cents, int) or ref_300k_cents <= 0:
        raise AggressionDialError("ref_300k_cents must be a positive integer")
    if isinstance(tier_cap_cents, bool) or not isinstance(tier_cap_cents, int) or tier_cap_cents <= 0:
        raise AggressionDialError("tier_cap_cents must be a positive integer")
    return (ref_300k_cents * tier_cap_cents + REFERENCE_CAPITAL_CENTS // 2) // REFERENCE_CAPITAL_CENTS


def scale_usd_from_300k(ref_300k_usd: Decimal, capital_usd: Decimal) -> Decimal:
    """Scale a $300,000.00 reference dollar figure proportionally to any tier capital."""
    ref_cents = usd_to_cents_int(ref_300k_usd, "ref_300k_usd")
    cap_cents = usd_to_cents_int(capital_usd, "capital_usd")
    return cents_to_usd_decimal(scale_cents_from_300k(ref_cents, cap_cents))


def _exact_pct_from_300k_cents(ref_cents: int) -> Decimal:
    with localcontext() as ctx:
        ctx.prec = 28
        if (ref_cents * 100) % 300000 == 0:
            return (Decimal(ref_cents) / Decimal("300000")).quantize(
                Decimal("0.01"),
                rounding=ROUND_HALF_UP,
            )
        if (ref_cents * 1000) % 300000 == 0:
            return (Decimal(ref_cents) / Decimal("300000")).quantize(
                Decimal("0.001"),
                rounding=ROUND_HALF_UP,
            )
        return (Decimal(ref_cents) / Decimal("300000")).quantize(
            Decimal("0.0001"),
            rounding=ROUND_HALF_UP,
        )


@dataclass(frozen=True)
class AggressionProfile:
    """Immutable exact-integer / exact-Decimal aggression profile for any risk_bps in 20..100."""

    risk_bps: int
    label: str
    css_class: str
    risk_pct: Decimal
    max_open_trades: int
    prob_bp: int
    min_signal_prob: Decimal
    ref_300k_goal_cents: int
    ref_300k_loss_cents: int
    soft_goal_ratio: Decimal = SOFT_GOAL_RATIO

    def __post_init__(self) -> None:
        _validate_risk_bps(self.risk_bps, "risk_bps")
        if not isinstance(self.label, str) or not self.label.strip():
            raise AggressionDialError("label must be a non-empty string")
        validate_constitutional_stop_risk_pct(self.risk_pct)
        if isinstance(self.max_open_trades, bool) or not isinstance(self.max_open_trades, int):
            raise AggressionDialError("max_open_trades must be a positive integer")
        if self.max_open_trades < 1:
            raise AggressionDialError("max_open_trades must be >= 1")
        if isinstance(self.prob_bp, bool) or not isinstance(self.prob_bp, int) or self.prob_bp < 55:
            raise AggressionDialError("prob_bp must be an integer >= 55")
        validate_constitutional_signal_prob(self.min_signal_prob)
        if isinstance(self.ref_300k_goal_cents, bool) or not isinstance(
            self.ref_300k_goal_cents, int
        ) or self.ref_300k_goal_cents <= 0:
            raise AggressionDialError("ref_300k_goal_cents must be a positive integer")
        if isinstance(self.ref_300k_loss_cents, bool) or not isinstance(
            self.ref_300k_loss_cents, int
        ) or self.ref_300k_loss_cents <= 0:
            raise AggressionDialError("ref_300k_loss_cents must be a positive integer")
        ratio = _validate_decimal(self.soft_goal_ratio, "soft_goal_ratio", positive=True)
        if ratio > Decimal("1.00"):
            raise AggressionDialError("soft_goal_ratio must be <= 1.00")

    @property
    def ref_300k_goal_usd(self) -> Decimal:
        return cents_to_usd_decimal(self.ref_300k_goal_cents)

    @property
    def ref_300k_loss_usd(self) -> Decimal:
        return cents_to_usd_decimal(self.ref_300k_loss_cents)

    @property
    def goal_pct(self) -> Decimal:
        return _exact_pct_from_300k_cents(self.ref_300k_goal_cents)

    @property
    def loss_pct(self) -> Decimal:
        return _exact_pct_from_300k_cents(self.ref_300k_loss_cents)

    @property
    def high_risk_zone(self) -> bool:
        return self.risk_bps >= HIGH_RISK_MIN_BPS

    @property
    def extreme_high_risk_zone(self) -> bool:
        return self.risk_bps >= 96

    def scaled_goal_cents(self, capital_usd: Decimal) -> int:
        return scale_cents_from_300k(self.ref_300k_goal_cents, usd_to_cents_int(capital_usd))

    def scaled_loss_brake_cents(self, capital_usd: Decimal) -> int:
        return scale_cents_from_300k(self.ref_300k_loss_cents, usd_to_cents_int(capital_usd))

    def scaled_goal_usd(self, capital_usd: Decimal) -> Decimal:
        return cents_to_usd_decimal(self.scaled_goal_cents(capital_usd))

    def scaled_loss_brake_usd(self, capital_usd: Decimal) -> Decimal:
        return cents_to_usd_decimal(self.scaled_loss_brake_cents(capital_usd))

    def scaled_soft_goal_usd(self, capital_usd: Decimal) -> Decimal:
        goal_cents = self.scaled_goal_cents(capital_usd)
        soft_cents = div_round_half_up(goal_cents * 70, 100)
        return cents_to_usd_decimal(soft_cents)

    def scaled_risk_per_trade_cents(self, capital_usd: Decimal) -> int:
        cap_cents = usd_to_cents_int(capital_usd)
        return div_round_half_up(cap_cents * self.risk_bps, 10_000)

    def scaled_risk_per_trade_usd(self, capital_usd: Decimal) -> Decimal:
        return cents_to_usd_decimal(self.scaled_risk_per_trade_cents(capital_usd))

    def to_catalog_dict(self) -> dict[str, Any]:
        return {
            "risk_bps": self.risk_bps,
            "risk_pct": format(self.risk_pct, "f"),
            "label": self.label,
            "css_class": self.css_class,
            "max_open_trades": self.max_open_trades,
            "prob_bp": self.prob_bp,
            "min_signal_prob": format(self.min_signal_prob, "f"),
            "ref_300k_goal_cents": self.ref_300k_goal_cents,
            "ref_300k_loss_cents": self.ref_300k_loss_cents,
            "ref_300k_goal_usd": format(self.ref_300k_goal_usd, "f"),
            "ref_300k_loss_usd": format(self.ref_300k_loss_usd, "f"),
            "goal_pct": format(self.goal_pct, "f"),
            "loss_pct": format(self.loss_pct, "f"),
            "soft_goal_ratio": format(self.soft_goal_ratio, "f"),
            "high_risk_zone": self.high_risk_zone,
            "extreme_high_risk_zone": self.extreme_high_risk_zone,
        }


def _build_profile_for_bps(risk_bps: int) -> AggressionProfile:
    bps = _validate_risk_bps(risk_bps, "risk_bps")
    k0 = AGGRESSION_ANCHOR_KNOTS[0]
    k1 = AGGRESSION_ANCHOR_KNOTS[-1]
    for idx in range(len(AGGRESSION_ANCHOR_KNOTS) - 1):
        left = AGGRESSION_ANCHOR_KNOTS[idx]
        right = AGGRESSION_ANCHOR_KNOTS[idx + 1]
        if left.risk_bps <= bps <= right.risk_bps:
            k0 = left
            k1 = right
            break

    dx = bps - k0.risk_bps
    span = k1.risk_bps - k0.risk_bps
    goal_300k_cents = k0.ref_300k_goal_cents + div_round_half_up(
        (k1.ref_300k_goal_cents - k0.ref_300k_goal_cents) * dx,
        span,
    )
    loss_300k_cents = k0.ref_300k_loss_cents + div_round_half_up(
        (k1.ref_300k_loss_cents - k0.ref_300k_loss_cents) * dx,
        span,
    )
    prob_bp = k0.prob_bp - div_round_half_up((k0.prob_bp - k1.prob_bp) * dx, span)
    if prob_bp < 55:
        prob_bp = 55
    max_open_trades = k0.max_open_trades + div_round_half_up(
        (k1.max_open_trades - k0.max_open_trades) * dx,
        span,
    )
    label, css_class = zone_label_and_css_for_bps(bps)

    return AggressionProfile(
        risk_bps=bps,
        label=label,
        css_class=css_class,
        risk_pct=bps_to_pct_decimal(bps),
        max_open_trades=max_open_trades,
        prob_bp=prob_bp,
        min_signal_prob=bps_to_pct_decimal(prob_bp),
        ref_300k_goal_cents=goal_300k_cents,
        ref_300k_loss_cents=loss_300k_cents,
        soft_goal_ratio=SOFT_GOAL_RATIO,
    )


AGGRESSION_BPS_PROFILES: Mapping[int, AggressionProfile] = MappingProxyType(
    {bps: _build_profile_for_bps(bps) for bps in range(MIN_RISK_BPS, MAX_RISK_BPS + 1)}
)


def profile_for_risk_bps(risk_bps: int) -> AggressionProfile:
    """Return the exact precomputed AggressionProfile for any risk_bps in 20..100."""
    return AGGRESSION_BPS_PROFILES[_validate_risk_bps(risk_bps, "risk_bps")]


def _resolve_discretion_flag(
    ai_discretion_enabled: bool | None,
    auto_shift_enabled: bool | None,
    default: bool = DEFAULT_AI_DISCRETION_ENABLED,
) -> bool:
    if ai_discretion_enabled is not None and auto_shift_enabled is not None:
        a = _validate_bool(ai_discretion_enabled, "ai_discretion_enabled")
        b = _validate_bool(auto_shift_enabled, "auto_shift_enabled")
        if a != b:
            raise AggressionDialError(
                "Conflicting ai_discretion_enabled and auto_shift_enabled flags"
            )
        return a
    if ai_discretion_enabled is not None:
        return _validate_bool(ai_discretion_enabled, "ai_discretion_enabled")
    if auto_shift_enabled is not None:
        return _validate_bool(auto_shift_enabled, "auto_shift_enabled")
    return default


def _enforce_owner_controls(owner_controls_allowed: bool, action: str) -> None:
    allowed = _validate_bool(owner_controls_allowed, "owner_controls_allowed")
    if not allowed:
        raise OwnerKeyRequiredError(
            f"Owner Key Required ({ACCESS_MODE_OWNER_FULL_CONTROL}) to perform {action}; "
            f"paired session is {ACCESS_MODE_DEVICE_READ_AND_EXPLAINER}"
        )


def _enforce_live_high_risk_gate(
    *,
    risk_bps: int,
    live_mode: bool,
    high_risk_confirmed: bool,
    context: str,
) -> None:
    _validate_bool(live_mode, "live_mode")
    _validate_bool(high_risk_confirmed, "high_risk_confirmed")
    if live_mode and risk_bps >= HIGH_RISK_MIN_BPS and not high_risk_confirmed:
        pct = format(bps_to_pct_decimal(risk_bps), "f")
        raise HighRiskConfirmationRequiredError(
            f"LIVE mode requires explicit high_risk_confirmed=True for {pct}% "
            f"({risk_bps} bps, {context})"
        )


def resolve_effective_params(
    risk_bps: int,
    capital_usd: Decimal,
    *,
    auto_shift_enabled: bool | None = None,
    ai_discretion_enabled: bool | None = None,
    ai_discretion_ceiling_bps: int = DEFAULT_AI_DISCRETION_CEILING_BPS,
    regime: str = "TREND_IGNITION",
    consecutive_losses: int = 0,
    drawdown_pct: Decimal = Decimal("0"),
    valve_score: Decimal = Decimal("0.60"),
) -> dict[str, Any]:
    """Resolve effective aggression parameters and unbreakable guardrails for any risk_bps (20..100).

    When ai_discretion_enabled=True (alias auto_shift_enabled=True):
      - drawdown_pct >= 8%: min(bps, 20) (0.20% Safe)
      - drawdown_pct >= 5% or consecutive_losses >= 2: min(bps, 30) (0.30% Calm)
      - consecutive_losses == 1 or regime == "CHOP_RANGE": min(bps, 40) (0.40% Steady)
      - regime == "TREND_IGNITION" (0 losses, < 5% DD): min(ceiling_bps, max(bps, 85)) (0.85% Risky)
      - regime == "STRONG_TREND" (0 losses, < 5% DD):
          - if valve_score >= 0.72: min(ceiling_bps, 100) (1.00% Extreme High Risk)
          - else: min(ceiling_bps, max(bps, 95)) (0.95% High Risk)
      - Strictly clamped within 20..ai_discretion_ceiling_bps (<= 100 bps = 1.00%).

    When ai_discretion_enabled=False (Manual Lock):
      - AI cannot move the dial up or down; stays strictly pinned to owner's exact risk_bps.

    Unbreakable safety guardrails and PR #25 constitutional ceilings (risk_pct <= 1.00%,
    max_drawdown_pct <= 10.00%, min_signal_prob >= 0.55) are unconditionally enforced.
    """
    chosen_bps = _validate_risk_bps(risk_bps, "risk_bps")
    cap_val = _q2(_validate_decimal(capital_usd, "capital_usd", positive=True))
    discretion = _resolve_discretion_flag(ai_discretion_enabled, auto_shift_enabled)
    ceiling_bps = _validate_risk_bps(ai_discretion_ceiling_bps, "ai_discretion_ceiling_bps")
    norm_regime = _validate_regime(regime)
    losses = _validate_non_negative_int(consecutive_losses, "consecutive_losses")
    dd = _validate_decimal(drawdown_pct, "drawdown_pct", non_negative=True)
    v_score = _validate_valve_score(valve_score)

    effective_bps = chosen_bps
    shift_reasons: list[str] = []
    discretion_reason = "MANUAL_LOCK"

    if discretion:
        if dd >= Decimal("0.08"):
            effective_bps = min(chosen_bps, 20)
            shift_reasons.append("DRAWDOWN_BRAKE_8PCT")
            discretion_reason = "DRAWDOWN_BRAKE_8PCT"
        elif dd >= Decimal("0.05") or losses >= 2:
            effective_bps = min(chosen_bps, 30)
            if dd >= Decimal("0.05"):
                shift_reasons.append("DRAWDOWN_BRAKE_5PCT")
            if losses >= 2:
                shift_reasons.append("CONSECUTIVE_LOSSES_2PLUS")
            discretion_reason = (
                "DRAWDOWN_BRAKE_5PCT" if dd >= Decimal("0.05") else "CONSECUTIVE_LOSSES_2PLUS"
            )
        elif losses == 1 or norm_regime == "CHOP_RANGE":
            effective_bps = min(chosen_bps, 40)
            if losses == 1:
                shift_reasons.append("CONSECUTIVE_LOSS_1")
            if norm_regime == "CHOP_RANGE":
                shift_reasons.append("CHOP_RANGE")
            discretion_reason = "CONSECUTIVE_LOSS_1" if losses == 1 else "CHOP_RANGE"
        elif norm_regime == "TREND_IGNITION":
            effective_bps = min(ceiling_bps, max(chosen_bps, 85))
            shift_reasons.append("TREND_IGNITION")
            discretion_reason = (
                "TREND_IGNITION_BOOST" if effective_bps > chosen_bps else "TREND_IGNITION_HOLD"
            )
        elif norm_regime == "STRONG_TREND":
            if v_score >= STRONG_TREND_EXTREME_VALVE_SCORE:
                effective_bps = min(ceiling_bps, MAX_RISK_BPS)
                shift_reasons.append("STRONG_TREND_HIGH_VALVE")
                discretion_reason = "STRONG_TREND_HIGH_VALVE_EXTREME"
            else:
                effective_bps = min(ceiling_bps, max(chosen_bps, 95))
                shift_reasons.append("STRONG_TREND")
                discretion_reason = (
                    "STRONG_TREND_BOOST" if effective_bps > chosen_bps else "STRONG_TREND_HOLD"
                )
        else:
            effective_bps = min(ceiling_bps, chosen_bps)
            discretion_reason = (
                "CEILING_CLAMP" if effective_bps < chosen_bps else "OWNER_BPS_HOLD"
            )

        if effective_bps < MIN_RISK_BPS:
            effective_bps = MIN_RISK_BPS
        if effective_bps > ceiling_bps:
            effective_bps = ceiling_bps
    else:
        effective_bps = chosen_bps
        discretion_reason = "MANUAL_LOCK"

    requested_profile = AGGRESSION_BPS_PROFILES[chosen_bps]
    effective_profile = AGGRESSION_BPS_PROFILES[effective_bps]

    validate_constitutional_stop_risk_pct(effective_profile.risk_pct)
    validate_constitutional_signal_prob(effective_profile.min_signal_prob)

    goal_cents = effective_profile.scaled_goal_cents(cap_val)
    loss_cents = effective_profile.scaled_loss_brake_cents(cap_val)
    risk_cents = effective_profile.scaled_risk_per_trade_cents(cap_val)
    session_goal = cents_to_usd_decimal(goal_cents)
    soft_goal = effective_profile.scaled_soft_goal_usd(cap_val)
    loss_brake = cents_to_usd_decimal(loss_cents)
    risk_per_trade = cents_to_usd_decimal(risk_cents)

    if effective_bps > chosen_bps:
        direction = "UP"
    elif effective_bps < chosen_bps:
        direction = "DOWN"
    else:
        direction = "HOLD"

    return {
        "requested_risk_bps": chosen_bps,
        "requested_risk_pct": format(requested_profile.risk_pct, "f"),
        "requested_label": requested_profile.label,
        "effective_risk_bps": effective_bps,
        "effective_risk_pct": format(effective_profile.risk_pct, "f"),
        "effective_label": effective_profile.label,
        "label": effective_profile.label,
        "css_class": effective_profile.css_class,
        "ai_discretion_enabled": discretion,
        "ai_discretion_ceiling_bps": ceiling_bps,
        "ai_discretion_reason": discretion_reason,
        "ai_discretion_shifted": effective_bps != chosen_bps,
        "ai_discretion_direction": direction,
        "auto_shift_enabled": discretion,
        "auto_shifted": effective_bps != chosen_bps,
        "shift_reasons": shift_reasons,
        "regime": norm_regime,
        "valve_score": format(v_score, "f"),
        "consecutive_losses": losses,
        "drawdown_pct": format(dd, "f"),
        "capital_usd": format(cap_val, "f"),
        "risk_bps": effective_bps,
        "risk_pct": format(effective_profile.risk_pct, "f"),
        "risk_per_trade_cents": risk_cents,
        "risk_per_trade_usd": format(risk_per_trade, "f"),
        "max_open_trades": effective_profile.max_open_trades,
        "prob_bp": effective_profile.prob_bp,
        "min_signal_prob": format(effective_profile.min_signal_prob, "f"),
        "session_goal_cents": goal_cents,
        "session_goal_usd": format(session_goal, "f"),
        "soft_goal_usd": format(soft_goal, "f"),
        "soft_goal_ratio": format(effective_profile.soft_goal_ratio, "f"),
        "daily_loss_brake_cents": loss_cents,
        "daily_loss_brake_usd": format(loss_brake, "f"),
        "goal_pct": format(effective_profile.goal_pct, "f"),
        "loss_pct": format(effective_profile.loss_pct, "f"),
        "max_drawdown_pct": format(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, "f"),
        "high_risk_zone": effective_profile.high_risk_zone,
        "extreme_high_risk_zone": effective_profile.extreme_high_risk_zone,
        "guardrails": unbreakable_guardrails(min_signal_prob=effective_profile.min_signal_prob),
    }


def _compute_audit_sha256(
    *,
    prev_sha256: str,
    scope_id: str,
    action: str,
    actor: str,
    payload_bytes: bytes,
    occurred_at: str,
) -> str:
    h = sha256()
    h.update(prev_sha256.encode("utf-8"))
    h.update(b"\x1f")
    h.update(scope_id.encode("utf-8"))
    h.update(b"\x1f")
    h.update(action.encode("utf-8"))
    h.update(b"\x1f")
    h.update(actor.encode("utf-8"))
    h.update(b"\x1f")
    h.update(occurred_at.encode("utf-8"))
    h.update(b"\x1f")
    h.update(payload_bytes)
    return h.hexdigest()


class AggressionDialStore:
    """Thread-safe SQLite WAL store for Master & Section B.5 5-Tier Aggression Dials (20..100 bps).

    - Supports all 81 exact single-unit steps (0.20%..1.00% in 0.01% increments) and AI
      Discretion over the Master Dial (ai_discretion_enabled + ai_discretion_ceiling_bps).
    - All writes run under an RLock inside BEGIN IMMEDIATE transactions with parameterized
      SQL (?) and append a SHA-256 hash-chained row into ``dial_audit``.
    - Paired read-only devices (``owner_controls_allowed=False``) are rejected fail-closed
      with ``OwnerKeyRequiredError`` on every mutating operation.
    - ``snapshot()`` and ``verify_audit_chain()`` open the database strictly read-only
      (``?mode=ro`` URI + ``PRAGMA query_only=ON``), guaranteeing zero writes and an
      invariant ``PRAGMA data_version``.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        scope_id: str = "default",
        initial_master_risk_bps: int = DEFAULT_MASTER_RISK_BPS,
        initial_auto_shift_enabled: bool | None = None,
        initial_ai_discretion_enabled: bool | None = None,
        initial_ai_discretion_ceiling_bps: int = DEFAULT_AI_DISCRETION_CEILING_BPS,
        initial_tier_risk_bps: Mapping[str, int] | None = None,
        tier_capitals: Mapping[str, Decimal] | None = None,
        tier_labels: Mapping[str, str] | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._db_path = Path(db_path)
        self._scope_id = identifier(scope_id, "scope_id")
        self._now = now_fn if now_fn is not None else _utc_now
        self._lock = RLock()

        master_bps = _validate_risk_bps(initial_master_risk_bps, "initial_master_risk_bps")
        ai_discretion = _resolve_discretion_flag(
            initial_ai_discretion_enabled,
            initial_auto_shift_enabled,
            default=DEFAULT_AI_DISCRETION_ENABLED,
        )
        ceiling_bps = _validate_risk_bps(
            initial_ai_discretion_ceiling_bps,
            "initial_ai_discretion_ceiling_bps",
        )

        raw_capitals = DEFAULT_TIER_CAPITALS if tier_capitals is None else tier_capitals
        if not raw_capitals:
            raise AggressionDialError("tier_capitals must contain at least one tier")

        validated_capitals: dict[str, Decimal] = {}
        for tid, cap in raw_capitals.items():
            clean_tid = identifier(tid, "tier_id")
            validated_capitals[clean_tid] = _q2(
                _validate_decimal(cap, f"capital[{clean_tid}]", positive=True)
            )
        self._tier_capitals: Mapping[str, Decimal] = MappingProxyType(validated_capitals)

        raw_labels = DEFAULT_TIER_LABELS if tier_labels is None else tier_labels
        validated_labels: dict[str, str] = {}
        for tid in validated_capitals:
            lbl = str(raw_labels.get(tid, DEFAULT_TIER_LABELS.get(tid, tid))).strip()
            validated_labels[tid] = lbl or tid
        self._tier_labels: Mapping[str, str] = MappingProxyType(validated_labels)

        ordered_ids = [tid for tid in DEFAULT_TIER_ORDER if tid in validated_capitals]
        for tid in validated_capitals:
            if tid not in ordered_ids:
                ordered_ids.append(tid)
        self._tier_order: tuple[str, ...] = tuple(ordered_ids)

        validated_tier_bps: dict[str, int] = {
            tid: DEFAULT_MASTER_RISK_BPS for tid in self._tier_order
        }
        if initial_tier_risk_bps is not None:
            for tid, bps in initial_tier_risk_bps.items():
                if tid not in validated_capitals:
                    raise AggressionDialError(f"Unknown tier_id in initial_tier_risk_bps: {tid!r}")
                validated_tier_bps[tid] = _validate_risk_bps(bps, f"initial_tier_risk_bps[{tid}]")

        self._init_schema(
            initial_master_risk_bps=master_bps,
            initial_ai_discretion_enabled=ai_discretion,
            initial_ai_discretion_ceiling_bps=ceiling_bps,
            initial_tier_risk_bps=validated_tier_bps,
        )

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def scope_id(self) -> str:
        return self._scope_id

    @staticmethod
    def resolve_effective_params(
        risk_bps: int,
        capital_usd: Decimal,
        *,
        auto_shift_enabled: bool | None = None,
        ai_discretion_enabled: bool | None = None,
        ai_discretion_ceiling_bps: int = DEFAULT_AI_DISCRETION_CEILING_BPS,
        regime: str = "TREND_IGNITION",
        consecutive_losses: int = 0,
        drawdown_pct: Decimal = Decimal("0"),
        valve_score: Decimal = Decimal("0.60"),
    ) -> dict[str, Any]:
        return resolve_effective_params(
            risk_bps,
            capital_usd,
            auto_shift_enabled=auto_shift_enabled,
            ai_discretion_enabled=ai_discretion_enabled,
            ai_discretion_ceiling_bps=ai_discretion_ceiling_bps,
            regime=regime,
            consecutive_losses=consecutive_losses,
            drawdown_pct=drawdown_pct,
            valve_score=valve_score,
        )

    def _connect_rw(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _connect_ro(self) -> sqlite3.Connection:
        resolved = self._db_path.resolve()
        if not resolved.exists():
            raise AggressionDialError(f"AggressionDialStore database does not exist: {resolved}")
        uri = f"{resolved.as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        return conn

    def _append_audit_locked(
        self,
        conn: sqlite3.Connection,
        *,
        action: str,
        actor: str,
        payload: Mapping[str, Any],
        occurred_at: str,
    ) -> str:
        last_row = conn.execute(
            "SELECT entry_sha256 FROM dial_audit WHERE scope_id = ? ORDER BY seq DESC LIMIT 1",
            (self._scope_id,),
        ).fetchone()
        prev_sha = GENESIS_AUDIT_SHA256 if last_row is None else str(last_row["entry_sha256"])
        payload_bytes = canonical_bytes(dict(payload))
        payload_json = payload_bytes.decode("utf-8")
        entry_sha = _compute_audit_sha256(
            prev_sha256=prev_sha,
            scope_id=self._scope_id,
            action=action,
            actor=actor,
            payload_bytes=payload_bytes,
            occurred_at=occurred_at,
        )
        conn.execute(
            "INSERT INTO dial_audit "
            "(scope_id, action, actor, payload_json, occurred_at, prev_sha256, entry_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._scope_id, action, actor, payload_json, occurred_at, prev_sha, entry_sha),
        )
        return entry_sha

    def _init_schema(
        self,
        *,
        initial_master_risk_bps: int,
        initial_ai_discretion_enabled: bool,
        initial_ai_discretion_ceiling_bps: int,
        initial_tier_risk_bps: Mapping[str, int],
    ) -> None:
        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dial_state (
                        scope_id TEXT PRIMARY KEY,
                        master_risk_bps INTEGER NOT NULL,
                        auto_shift_enabled INTEGER NOT NULL,
                        ai_discretion_enabled INTEGER NOT NULL DEFAULT 1,
                        ai_discretion_ceiling_bps INTEGER NOT NULL DEFAULT 100,
                        updated_at TEXT NOT NULL,
                        updated_by TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dial_tiers (
                        scope_id TEXT NOT NULL,
                        tier_id TEXT NOT NULL,
                        risk_bps INTEGER NOT NULL,
                        capital_usd TEXT NOT NULL,
                        label TEXT NOT NULL,
                        ai_discretion_enabled INTEGER NOT NULL DEFAULT 1,
                        updated_at TEXT NOT NULL,
                        updated_by TEXT NOT NULL,
                        PRIMARY KEY (scope_id, tier_id)
                    )
                    """
                )
                tier_cols = {
                    str(r["name"])
                    for r in conn.execute("PRAGMA table_info(dial_tiers)").fetchall()
                }
                if "ai_discretion_enabled" not in tier_cols:
                    conn.execute(
                        "ALTER TABLE dial_tiers "
                        "ADD COLUMN ai_discretion_enabled INTEGER NOT NULL DEFAULT 1"
                    )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dial_audit (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        scope_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        prev_sha256 TEXT NOT NULL,
                        entry_sha256 TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_dial_audit_scope_seq "
                    "ON dial_audit (scope_id, seq)"
                )

                existing_master = conn.execute(
                    "SELECT scope_id FROM dial_state WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()

                if existing_master is None:
                    flag_int = 1 if initial_ai_discretion_enabled else 0
                    conn.execute(
                        "INSERT INTO dial_state "
                        "(scope_id, master_risk_bps, auto_shift_enabled, ai_discretion_enabled, "
                        "ai_discretion_ceiling_bps, updated_at, updated_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            self._scope_id,
                            initial_master_risk_bps,
                            flag_int,
                            flag_int,
                            initial_ai_discretion_ceiling_bps,
                            now_iso,
                            "system_init",
                        ),
                    )
                    for tid in self._tier_order:
                        conn.execute(
                            "INSERT INTO dial_tiers "
                            "(scope_id, tier_id, risk_bps, capital_usd, label, ai_discretion_enabled, updated_at, updated_by) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                self._scope_id,
                                tid,
                                initial_tier_risk_bps[tid],
                                format(self._tier_capitals[tid], "f"),
                                self._tier_labels[tid],
                                flag_int,
                                now_iso,
                                "system_init",
                            ),
                        )
                    self._append_audit_locked(
                        conn,
                        action="INIT",
                        actor="system_init",
                        payload={
                            "master_risk_bps": initial_master_risk_bps,
                            "ai_discretion_enabled": initial_ai_discretion_enabled,
                            "ai_discretion_ceiling_bps": initial_ai_discretion_ceiling_bps,
                            "auto_shift_enabled": initial_ai_discretion_enabled,
                            "tier_risk_bps": {
                                tid: initial_tier_risk_bps[tid] for tid in self._tier_order
                            },
                        },
                        occurred_at=now_iso,
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        try:
            if os.name == "posix":
                os.chmod(self._db_path, 0o600)
        except OSError:
            pass

    def set_master_risk_bps(
        self,
        risk_bps: int,
        *,
        auto_shift_enabled: bool | None = None,
        ai_discretion_enabled: bool | None = None,
        ai_discretion_ceiling_bps: int | None = None,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Update the master aggression risk_bps (20..100 = 0.20%..1.00%) and AI discretion."""
        _enforce_owner_controls(owner_controls_allowed, "set_master_risk_bps")
        validated_bps = _validate_risk_bps(risk_bps, "risk_bps")
        clean_actor = _validate_actor(actor)
        discretion_override: bool | None = None
        if ai_discretion_enabled is not None or auto_shift_enabled is not None:
            discretion_override = _resolve_discretion_flag(
                ai_discretion_enabled,
                auto_shift_enabled,
            )
        validated_ceiling: int | None = None
        if ai_discretion_ceiling_bps is not None:
            validated_ceiling = _validate_risk_bps(
                ai_discretion_ceiling_bps,
                "ai_discretion_ceiling_bps",
            )

        _enforce_live_high_risk_gate(
            risk_bps=validated_bps,
            live_mode=live_mode,
            high_risk_confirmed=high_risk_confirmed,
            context="master dial",
        )
        if validated_ceiling is not None:
            _enforce_live_high_risk_gate(
                risk_bps=validated_ceiling,
                live_mode=live_mode,
                high_risk_confirmed=high_risk_confirmed,
                context="ai_discretion_ceiling_bps",
            )

        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT master_risk_bps, ai_discretion_enabled, ai_discretion_ceiling_bps "
                    "FROM dial_state WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()
                if cur is None:
                    raise AggressionDialError(
                        f"Missing dial_state row for scope {self._scope_id!r}"
                    )
                prev_bps = int(cur["master_risk_bps"])
                prev_discretion = bool(int(cur["ai_discretion_enabled"]))
                prev_ceiling = int(cur["ai_discretion_ceiling_bps"])
                new_discretion = (
                    prev_discretion if discretion_override is None else discretion_override
                )
                new_ceiling = prev_ceiling if validated_ceiling is None else validated_ceiling
                flag_int = 1 if new_discretion else 0

                conn.execute(
                    "UPDATE dial_state SET master_risk_bps = ?, auto_shift_enabled = ?, "
                    "ai_discretion_enabled = ?, ai_discretion_ceiling_bps = ?, "
                    "updated_at = ?, updated_by = ? WHERE scope_id = ?",
                    (
                        validated_bps,
                        flag_int,
                        flag_int,
                        new_ceiling,
                        now_iso,
                        clean_actor,
                        self._scope_id,
                    ),
                )
                self._append_audit_locked(
                    conn,
                    action="SET_MASTER_RISK_BPS",
                    actor=clean_actor,
                    payload={
                        "previous_risk_bps": prev_bps,
                        "new_risk_bps": validated_bps,
                        "previous_ai_discretion_enabled": prev_discretion,
                        "ai_discretion_enabled": new_discretion,
                        "previous_ai_discretion_ceiling_bps": prev_ceiling,
                        "ai_discretion_ceiling_bps": new_ceiling,
                        "auto_shift_enabled": new_discretion,
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def set_ai_discretion(
        self,
        enabled: bool,
        *,
        ceiling_bps: int | None = None,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Enable or disable AI Discretion over the Master Dial and optional ceiling (20..100 bps)."""
        _enforce_owner_controls(owner_controls_allowed, "set_ai_discretion")
        clean_enabled = _validate_bool(enabled, "enabled")
        clean_actor = _validate_actor(actor)
        _validate_bool(live_mode, "live_mode")
        _validate_bool(high_risk_confirmed, "high_risk_confirmed")
        validated_ceiling: int | None = None
        if ceiling_bps is not None:
            validated_ceiling = _validate_risk_bps(ceiling_bps, "ceiling_bps")

        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT ai_discretion_enabled, ai_discretion_ceiling_bps "
                    "FROM dial_state WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()
                if cur is None:
                    raise AggressionDialError(
                        f"Missing dial_state row for scope {self._scope_id!r}"
                    )
                prev_enabled = bool(int(cur["ai_discretion_enabled"]))
                prev_ceiling = int(cur["ai_discretion_ceiling_bps"])
                target_ceiling = prev_ceiling if validated_ceiling is None else validated_ceiling

                if clean_enabled:
                    _enforce_live_high_risk_gate(
                        risk_bps=target_ceiling,
                        live_mode=live_mode,
                        high_risk_confirmed=high_risk_confirmed,
                        context="ai_discretion_ceiling_bps",
                    )

                flag_int = 1 if clean_enabled else 0
                conn.execute(
                    "UPDATE dial_state SET auto_shift_enabled = ?, ai_discretion_enabled = ?, "
                    "ai_discretion_ceiling_bps = ?, updated_at = ?, updated_by = ? "
                    "WHERE scope_id = ?",
                    (flag_int, flag_int, target_ceiling, now_iso, clean_actor, self._scope_id),
                )
                self._append_audit_locked(
                    conn,
                    action="SET_AI_DISCRETION",
                    actor=clean_actor,
                    payload={
                        "previous_ai_discretion_enabled": prev_enabled,
                        "ai_discretion_enabled": clean_enabled,
                        "previous_ai_discretion_ceiling_bps": prev_ceiling,
                        "ai_discretion_ceiling_bps": target_ceiling,
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def set_auto_shift(
        self,
        enabled: bool,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Backwards-compatible alias for set_ai_discretion(enabled)."""
        return self.set_ai_discretion(
            enabled,
            live_mode=live_mode,
            high_risk_confirmed=high_risk_confirmed,
            owner_controls_allowed=owner_controls_allowed,
            actor=actor,
        )

    def set_tier_risk_bps(
        self,
        tier_id: str,
        risk_bps: int,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Set an individual Section B.5 tier's risk_bps (20..100 = 0.20%..1.00%)."""
        _enforce_owner_controls(owner_controls_allowed, f"set_tier_risk_bps({tier_id})")
        if not isinstance(tier_id, str) or tier_id not in self._tier_capitals:
            raise AggressionDialError(f"Unknown tier_id: {tier_id!r}")
        validated_bps = _validate_risk_bps(risk_bps, "risk_bps")
        clean_actor = _validate_actor(actor)
        _enforce_live_high_risk_gate(
            risk_bps=validated_bps,
            live_mode=live_mode,
            high_risk_confirmed=high_risk_confirmed,
            context=f"tier {tier_id}",
        )

        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT risk_bps FROM dial_tiers WHERE scope_id = ? AND tier_id = ?",
                    (self._scope_id, tier_id),
                ).fetchone()
                if cur is None:
                    raise AggressionDialError(f"Missing dial_tiers row for {tier_id!r}")
                prev_bps = int(cur["risk_bps"])
                conn.execute(
                    "UPDATE dial_tiers SET risk_bps = ?, updated_at = ?, updated_by = ? "
                    "WHERE scope_id = ? AND tier_id = ?",
                    (validated_bps, now_iso, clean_actor, self._scope_id, tier_id),
                )
                self._append_audit_locked(
                    conn,
                    action="SET_TIER_RISK_BPS",
                    actor=clean_actor,
                    payload={
                        "tier_id": tier_id,
                        "previous_risk_bps": prev_bps,
                        "new_risk_bps": validated_bps,
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def set_tier_ai_discretion(
        self,
        tier_id: str,
        enabled: bool,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Enable or disable AI Discretion on an individual Section B.5 tier."""
        _enforce_owner_controls(owner_controls_allowed, f"set_tier_ai_discretion({tier_id})")
        if not isinstance(tier_id, str) or tier_id not in self._tier_capitals:
            raise AggressionDialError(
                f"Unknown tier_id {tier_id!r}; expected one of {list(self._tier_order)}"
            )
        clean_enabled = _validate_bool(enabled, "enabled")
        clean_actor = _validate_actor(actor)
        _validate_bool(live_mode, "live_mode")
        _validate_bool(high_risk_confirmed, "high_risk_confirmed")

        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                master_cur = conn.execute(
                    "SELECT ai_discretion_ceiling_bps FROM dial_state WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()
                if master_cur is None:
                    raise AggressionDialError(
                        f"Missing dial_state row for scope {self._scope_id!r}"
                    )
                ceiling_bps = int(master_cur["ai_discretion_ceiling_bps"])
                if clean_enabled:
                    _enforce_live_high_risk_gate(
                        risk_bps=ceiling_bps,
                        live_mode=live_mode,
                        high_risk_confirmed=high_risk_confirmed,
                        context=f"tier {tier_id} ai_discretion_ceiling_bps",
                    )
                cur = conn.execute(
                    "SELECT ai_discretion_enabled FROM dial_tiers WHERE scope_id = ? AND tier_id = ?",
                    (self._scope_id, tier_id),
                ).fetchone()
                if cur is None:
                    raise AggressionDialError(f"Missing dial_tiers row for {tier_id!r}")
                prev_enabled = bool(int(cur["ai_discretion_enabled"]))
                flag_int = 1 if clean_enabled else 0
                conn.execute(
                    "UPDATE dial_tiers SET ai_discretion_enabled = ?, updated_at = ?, updated_by = ? "
                    "WHERE scope_id = ? AND tier_id = ?",
                    (flag_int, now_iso, clean_actor, self._scope_id, tier_id),
                )
                self._append_audit_locked(
                    conn,
                    action="SET_TIER_AI_DISCRETION",
                    actor=clean_actor,
                    payload={
                        "tier_id": tier_id,
                        "previous_ai_discretion_enabled": prev_enabled,
                        "ai_discretion_enabled": clean_enabled,
                        "ai_discretion_ceiling_bps": ceiling_bps,
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def set_all_tiers_ai_discretion(
        self,
        enabled: bool,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Enable or disable AI Discretion across all 5 Section B.5 tiers simultaneously."""
        _enforce_owner_controls(owner_controls_allowed, "set_all_tiers_ai_discretion")
        clean_enabled = _validate_bool(enabled, "enabled")
        clean_actor = _validate_actor(actor)
        _validate_bool(live_mode, "live_mode")
        _validate_bool(high_risk_confirmed, "high_risk_confirmed")

        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                master_cur = conn.execute(
                    "SELECT ai_discretion_ceiling_bps FROM dial_state WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()
                if master_cur is None:
                    raise AggressionDialError(
                        f"Missing dial_state row for scope {self._scope_id!r}"
                    )
                ceiling_bps = int(master_cur["ai_discretion_ceiling_bps"])
                if clean_enabled:
                    _enforce_live_high_risk_gate(
                        risk_bps=ceiling_bps,
                        live_mode=live_mode,
                        high_risk_confirmed=high_risk_confirmed,
                        context="all_tiers ai_discretion_ceiling_bps",
                    )
                flag_int = 1 if clean_enabled else 0
                conn.execute(
                    "UPDATE dial_tiers SET ai_discretion_enabled = ?, updated_at = ?, updated_by = ? "
                    "WHERE scope_id = ?",
                    (flag_int, now_iso, clean_actor, self._scope_id),
                )
                self._append_audit_locked(
                    conn,
                    action="SET_ALL_TIERS_AI_DISCRETION",
                    actor=clean_actor,
                    payload={
                        "ai_discretion_enabled": clean_enabled,
                        "tier_ai_discretion": {tid: clean_enabled for tid in self._tier_order},
                        "ai_discretion_ceiling_bps": ceiling_bps,
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def sync_all_tiers_to_master(
        self,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Set all 5 Section B.5 tiers to the current master_risk_bps."""
        _enforce_owner_controls(owner_controls_allowed, "sync_all_tiers_to_master")
        clean_actor = _validate_actor(actor)
        _validate_bool(live_mode, "live_mode")
        _validate_bool(high_risk_confirmed, "high_risk_confirmed")
        now_iso = _iso_utc(self._now())

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT master_risk_bps, ai_discretion_enabled FROM dial_state WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()
                if cur is None:
                    raise AggressionDialError(
                        f"Missing dial_state row for scope {self._scope_id!r}"
                    )
                master_bps = int(cur["master_risk_bps"])
                master_ai_int = int(cur["ai_discretion_enabled"])
                _enforce_live_high_risk_gate(
                    risk_bps=master_bps,
                    live_mode=live_mode,
                    high_risk_confirmed=high_risk_confirmed,
                    context="sync_all_tiers_to_master",
                )
                conn.execute(
                    "UPDATE dial_tiers SET risk_bps = ?, ai_discretion_enabled = ?, updated_at = ?, updated_by = ? "
                    "WHERE scope_id = ?",
                    (master_bps, master_ai_int, now_iso, clean_actor, self._scope_id),
                )
                self._append_audit_locked(
                    conn,
                    action="SYNC_ALL_TIERS_TO_MASTER",
                    actor=clean_actor,
                    payload={
                        "master_risk_bps": master_bps,
                        "tier_risk_bps": {tid: master_bps for tid in self._tier_order},
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def apply_stagger_preset(
        self,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Apply the Safe-to-Extreme stagger preset ($300k=25,$6k=45,$3k=65,$1k=85,$300=100 bps)."""
        return self.apply_tier_preset(
            PRESET_STAGGER_SAFE_TO_HIGH,
            live_mode=live_mode,
            high_risk_confirmed=high_risk_confirmed,
            owner_controls_allowed=owner_controls_allowed,
            actor=actor,
        )

    def apply_tier_preset(
        self,
        preset: str,
        *,
        live_mode: bool = False,
        high_risk_confirmed: bool = False,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
    ) -> dict[str, Any]:
        """Apply a named tier preset: SYNC_MASTER, STAGGER_SAFE_TO_HIGH/EXTREME, ALL_BALANCED, ALL_SAFE."""
        _enforce_owner_controls(owner_controls_allowed, f"apply_tier_preset({preset})")
        if not isinstance(preset, str):
            raise AggressionDialError("preset must be a string")
        norm_preset = preset.strip().upper()
        if norm_preset not in VALID_TIER_PRESETS:
            raise AggressionDialError(
                f"Unknown tier preset {preset!r}; expected one of {VALID_TIER_PRESETS}"
            )
        if norm_preset in (PRESET_SYNC_MASTER, PRESET_SYNC_ALL_TO_MASTER):
            return self.sync_all_tiers_to_master(
                live_mode=live_mode,
                high_risk_confirmed=high_risk_confirmed,
                owner_controls_allowed=owner_controls_allowed,
                actor=actor,
            )

        clean_actor = _validate_actor(actor)
        _validate_bool(live_mode, "live_mode")
        _validate_bool(high_risk_confirmed, "high_risk_confirmed")

        target_bps: dict[str, int] = {}
        if norm_preset in (PRESET_STAGGER_SAFE_TO_HIGH, PRESET_STAGGER_SAFE_TO_EXTREME):
            for tid in self._tier_order:
                target_bps[tid] = STAGGER_SAFE_TO_HIGH_BPS.get(tid, DEFAULT_MASTER_RISK_BPS)
        elif norm_preset == PRESET_ALL_BALANCED:
            for tid in self._tier_order:
                target_bps[tid] = 60
        elif norm_preset == PRESET_ALL_SAFE:
            for tid in self._tier_order:
                target_bps[tid] = 20

        max_target = max(target_bps.values())
        _enforce_live_high_risk_gate(
            risk_bps=max_target,
            live_mode=live_mode,
            high_risk_confirmed=high_risk_confirmed,
            context=f"preset {norm_preset}",
        )

        now_iso = _iso_utc(self._now())
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for tid, bps in target_bps.items():
                    conn.execute(
                        "UPDATE dial_tiers SET risk_bps = ?, updated_at = ?, updated_by = ? "
                        "WHERE scope_id = ? AND tier_id = ?",
                        (bps, now_iso, clean_actor, self._scope_id, tid),
                    )
                self._append_audit_locked(
                    conn,
                    action="APPLY_TIER_PRESET",
                    actor=clean_actor,
                    payload={
                        "preset": norm_preset,
                        "tier_risk_bps": target_bps,
                        "live_mode": live_mode,
                        "high_risk_confirmed": high_risk_confirmed,
                    },
                    occurred_at=now_iso,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.snapshot(owner_controls_allowed=owner_controls_allowed)

    def snapshot(
        self,
        *,
        regime: str = "NEUTRAL",
        consecutive_losses: int = 0,
        drawdown_pct: Decimal = Decimal("0"),
        valve_score: Decimal = Decimal("0.60"),
        owner_controls_allowed: bool = True,
        tier_contexts: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Strictly zero-write read-only snapshot (?mode=ro + PRAGMA query_only=ON).

        Never modifies SQLite state, preserving PRAGMA data_version and file mtime.
        """
        norm_regime = _validate_regime(regime)
        losses = _validate_non_negative_int(consecutive_losses, "consecutive_losses")
        dd = _validate_decimal(drawdown_pct, "drawdown_pct", non_negative=True)
        v_score = _validate_valve_score(valve_score)
        owner_ok = _validate_bool(owner_controls_allowed, "owner_controls_allowed")

        with self._lock, closing(self._connect_ro()) as conn:
            master_row = conn.execute(
                "SELECT master_risk_bps, auto_shift_enabled, ai_discretion_enabled, "
                "ai_discretion_ceiling_bps, updated_at, updated_by "
                "FROM dial_state WHERE scope_id = ?",
                (self._scope_id,),
            ).fetchone()
            if master_row is None:
                raise AggressionDialError(
                    f"Missing dial_state row for scope {self._scope_id!r}"
                )

            tier_rows = conn.execute(
                "SELECT tier_id, risk_bps, ai_discretion_enabled, capital_usd, label, updated_at, updated_by "
                "FROM dial_tiers WHERE scope_id = ?",
                (self._scope_id,),
            ).fetchall()

            audit_meta = conn.execute(
                "SELECT COUNT(*) AS cnt FROM dial_audit WHERE scope_id = ?",
                (self._scope_id,),
            ).fetchone()
            audit_head = conn.execute(
                "SELECT entry_sha256 FROM dial_audit WHERE scope_id = ? ORDER BY seq DESC LIMIT 1",
                (self._scope_id,),
            ).fetchone()

        master_bps = int(master_row["master_risk_bps"])
        ai_discretion_enabled = bool(int(master_row["ai_discretion_enabled"]))
        ai_discretion_ceiling = int(master_row["ai_discretion_ceiling_bps"])
        master_capital = self._tier_capitals.get("TIER_1_CURRENT", REFERENCE_CAPITAL_USD)
        master_effective = resolve_effective_params(
            master_bps,
            master_capital,
            ai_discretion_enabled=ai_discretion_enabled,
            ai_discretion_ceiling_bps=ai_discretion_ceiling,
            regime=norm_regime,
            consecutive_losses=losses,
            drawdown_pct=dd,
            valve_score=v_score,
        )

        row_map = {str(r["tier_id"]): r for r in tier_rows}
        tiers_list: list[dict[str, Any]] = []
        tiers_by_id: dict[str, dict[str, Any]] = {}
        ordered_keys = list(self._tier_order) + [
            k for k in sorted(row_map) if k not in self._tier_order
        ]

        for tid in ordered_keys:
            row = row_map.get(tid)
            if row is None:
                continue
            t_bps = int(row["risk_bps"])
            try:
                t_cap = _q2(Decimal(str(row["capital_usd"])))
            except InvalidOperation as exc:
                raise AggressionDialError(f"Corrupted capital_usd for tier {tid!r}") from exc
            row_keys = set(row.keys())
            t_ai_disc = (
                bool(int(row["ai_discretion_enabled"]))
                if "ai_discretion_enabled" in row_keys and row["ai_discretion_enabled"] is not None
                else ai_discretion_enabled
            )
            t_ctx = tier_contexts.get(tid) if isinstance(tier_contexts, Mapping) else None
            t_reg = norm_regime
            t_losses = losses
            t_dd = dd
            t_vs = v_score
            if isinstance(t_ctx, Mapping):
                if t_ctx.get("regime"):
                    t_reg = _validate_regime(str(t_ctx["regime"]))
                if "consecutive_losses" in t_ctx and t_ctx["consecutive_losses"] is not None:
                    t_losses = _validate_non_negative_int(int(t_ctx["consecutive_losses"]), "consecutive_losses")
                if "drawdown_pct" in t_ctx and t_ctx["drawdown_pct"] is not None:
                    t_dd = _validate_decimal(t_ctx["drawdown_pct"], "drawdown_pct", non_negative=True)
                if "valve_score" in t_ctx and t_ctx["valve_score"] is not None:
                    t_vs = _validate_valve_score(t_ctx["valve_score"])
            t_effective = resolve_effective_params(
                t_bps,
                t_cap,
                ai_discretion_enabled=t_ai_disc,
                ai_discretion_ceiling_bps=ai_discretion_ceiling,
                regime=t_reg,
                consecutive_losses=t_losses,
                drawdown_pct=t_dd,
                valve_score=t_vs,
            )
            t_chosen_prof = AGGRESSION_BPS_PROFILES[t_bps]
            entry = {
                "tier_id": tid,
                "label": str(row["label"]),
                "capital_usd": format(t_cap, "f"),
                "risk_bps": t_bps,
                "chosen_risk_pct": format(t_chosen_prof.risk_pct, "f"),
                "chosen_label": t_chosen_prof.label,
                "ai_discretion_enabled": t_ai_disc,
                "ai_discretion_ceiling_bps": ai_discretion_ceiling,
                "ai_discretion_shifted": bool(t_effective["ai_discretion_shifted"]),
                "ai_discretion_direction": str(t_effective["ai_discretion_direction"]),
                "effective_risk_bps": t_effective["effective_risk_bps"],
                "effective_risk_pct": t_effective["effective_risk_pct"],
                "effective_label": t_effective["effective_label"],
                "level_label": t_effective["label"],
                "ai_discretion_reason": t_effective["ai_discretion_reason"],
                "css_class": t_effective["css_class"],
                "risk_pct": t_effective["risk_pct"],
                "risk_per_trade_usd": t_effective["risk_per_trade_usd"],
                "max_open_trades": t_effective["max_open_trades"],
                "min_signal_prob": t_effective["min_signal_prob"],
                "session_goal_usd": t_effective["session_goal_usd"],
                "soft_goal_usd": t_effective["soft_goal_usd"],
                "daily_loss_brake_usd": t_effective["daily_loss_brake_usd"],
                "updated_at": str(row["updated_at"]),
                "updated_by": str(row["updated_by"]),
                "effective": t_effective,
            }
            tiers_list.append(entry)
            tiers_by_id[tid] = entry

        bps_catalog = [
            AGGRESSION_BPS_PROFILES[bps].to_catalog_dict()
            for bps in range(MIN_RISK_BPS, MAX_RISK_BPS + 1)
        ]
        access_mode = (
            ACCESS_MODE_OWNER_FULL_CONTROL
            if owner_ok
            else ACCESS_MODE_DEVICE_READ_AND_EXPLAINER
        )

        return {
            "schema": AGGRESSION_DIAL_SCHEMA,
            "scope_id": self._scope_id,
            "min_risk_bps": MIN_RISK_BPS,
            "max_risk_bps": MAX_RISK_BPS,
            "high_risk_min_bps": HIGH_RISK_MIN_BPS,
            "owner_controls_allowed": owner_ok,
            "access_mode": access_mode,
            "master_risk_bps": master_bps,
            "master_risk_pct": format(bps_to_pct_decimal(master_bps), "f"),
            "effective_risk_bps": master_effective["effective_risk_bps"],
            "effective_risk_pct": master_effective["effective_risk_pct"],
            "effective_label": master_effective["effective_label"],
            "css_class": master_effective["css_class"],
            "ai_discretion_enabled": ai_discretion_enabled,
            "ai_discretion_ceiling_bps": ai_discretion_ceiling,
            "ai_discretion_reason": master_effective["ai_discretion_reason"],
            "auto_shift_enabled": ai_discretion_enabled,
            "master": {
                "risk_bps": master_bps,
                "risk_pct": format(bps_to_pct_decimal(master_bps), "f"),
                "effective_risk_bps": master_effective["effective_risk_bps"],
                "effective_risk_pct": master_effective["effective_risk_pct"],
                "effective_label": master_effective["effective_label"],
                "css_class": master_effective["css_class"],
                "ai_discretion_enabled": ai_discretion_enabled,
                "ai_discretion_ceiling_bps": ai_discretion_ceiling,
                "ai_discretion_reason": master_effective["ai_discretion_reason"],
                "auto_shift_enabled": ai_discretion_enabled,
                "updated_at": str(master_row["updated_at"]),
                "updated_by": str(master_row["updated_by"]),
                "effective": master_effective,
            },
            "tiers": tiers_list,
            "tiers_by_id": tiers_by_id,
            "anchor_knots": [k.to_dict() for k in AGGRESSION_ANCHOR_KNOTS],
            "bps_catalog": bps_catalog,
            "guardrails": unbreakable_guardrails(
                min_signal_prob=Decimal(master_effective["min_signal_prob"])
            ),
            "audit_count": int(audit_meta["cnt"]) if audit_meta is not None else 0,
            "audit_head_sha256": (
                str(audit_head["entry_sha256"]) if audit_head is not None else GENESIS_AUDIT_SHA256
            ),
        }

    def verify_audit_chain(self) -> bool:
        """Strictly read-only verification of the SHA-256 hash chain in dial_audit."""
        with self._lock, closing(self._connect_ro()) as conn:
            rows = conn.execute(
                "SELECT seq, scope_id, action, actor, payload_json, occurred_at, "
                "prev_sha256, entry_sha256 FROM dial_audit WHERE scope_id = ? ORDER BY seq ASC",
                (self._scope_id,),
            ).fetchall()

        if not rows:
            return False

        expected_prev = GENESIS_AUDIT_SHA256
        for row in rows:
            prev_sha = str(row["prev_sha256"])
            stored_sha = str(row["entry_sha256"])
            if not hmac.compare_digest(prev_sha, expected_prev):
                return False
            payload_text = str(row["payload_json"])
            try:
                json.loads(payload_text)
            except (ValueError, TypeError):
                return False
            recomputed = _compute_audit_sha256(
                prev_sha256=prev_sha,
                scope_id=str(row["scope_id"]),
                action=str(row["action"]),
                actor=str(row["actor"]),
                payload_bytes=payload_text.encode("utf-8"),
                occurred_at=str(row["occurred_at"]),
            )
            if not hmac.compare_digest(stored_sha, recomputed):
                return False
            expected_prev = recomputed
        return True


__all__ = [
    "ACCESS_MODE_DEVICE_READ_AND_EXPLAINER",
    "ACCESS_MODE_OWNER_FULL_CONTROL",
    "AGGRESSION_ANCHOR_KNOTS",
    "AGGRESSION_BPS_PROFILES",
    "AGGRESSION_DIAL_SCHEMA",
    "AggressionDialError",
    "AggressionDialStore",
    "AggressionProfile",
    "AnchorKnot",
    "DEFAULT_AI_DISCRETION_CEILING_BPS",
    "DEFAULT_AI_DISCRETION_ENABLED",
    "DEFAULT_AUTO_SHIFT_ENABLED",
    "DEFAULT_MASTER_RISK_BPS",
    "DEFAULT_TIER_CAPITALS",
    "DEFAULT_TIER_LABELS",
    "DEFAULT_TIER_ORDER",
    "GENESIS_AUDIT_SHA256",
    "HIGH_RISK_MIN_BPS",
    "HighRiskConfirmationRequiredError",
    "MAX_CONSTITUTIONAL_DRAWDOWN_PCT",
    "MAX_CONSTITUTIONAL_STOP_RISK_PCT",
    "MAX_RISK_BPS",
    "MIN_CONSTITUTIONAL_VALVE_PROB",
    "MIN_RISK_BPS",
    "OwnerKeyRequiredError",
    "PRESET_ALL_BALANCED",
    "PRESET_ALL_SAFE",
    "PRESET_STAGGER_SAFE_TO_EXTREME",
    "PRESET_STAGGER_SAFE_TO_HIGH",
    "PRESET_SYNC_ALL_TO_MASTER",
    "PRESET_SYNC_MASTER",
    "REFERENCE_CAPITAL_CENTS",
    "REFERENCE_CAPITAL_USD",
    "SOFT_GOAL_RATIO",
    "STAGGER_SAFE_TO_EXTREME_BPS",
    "STAGGER_SAFE_TO_HIGH_BPS",
    "STRONG_TREND_EXTREME_VALVE_SCORE",
    "VALID_TIER_PRESETS",
    "bps_to_pct_decimal",
    "cents_to_usd_decimal",
    "div_round_half_up",
    "profile_for_risk_bps",
    "resolve_effective_params",
    "scale_cents_from_300k",
    "scale_usd_from_300k",
    "unbreakable_guardrails",
    "usd_to_cents_int",
    "validate_constitutional_drawdown_pct",
    "validate_constitutional_signal_prob",
    "validate_constitutional_stop_risk_pct",
    "zone_label_and_css_for_bps",
]
