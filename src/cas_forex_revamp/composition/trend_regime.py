"""Deterministic trend regime classifier, House-Money trend pyramiding, and USD/Index correlation guard."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
from typing import Any

from cas_forex_revamp.contracts import ContractError, Side, decimal_text
from cas_forex_revamp.contracts.primitives import decimal_value
from cas_forex_revamp.venue.live_market_stream import INDEX_INSTRUMENTS
from cas_forex_revamp.venue.mt5_broker_bridge import normalize_market_symbol

REGIME_TREND_IGNITION = "TREND_IGNITION"
REGIME_STRONG_TREND = "STRONG_TREND"
REGIME_CHOP_RANGE = "CHOP_RANGE"
REGIME_SPREAD_SPIKE = "SPREAD_SPIKE"
VALID_REGIMES = (
    REGIME_TREND_IGNITION,
    REGIME_STRONG_TREND,
    REGIME_CHOP_RANGE,
    REGIME_SPREAD_SPIKE,
)

MAX_PYRAMID_LEGS = 3
BREAKEVEN_LOCKED_STAGES = frozenset({"BREAKEVEN_LOCKED", "TRAILING_PROFIT"})

CORRELATION_POSITIVE_THRESHOLD = Decimal("0.45")
CORRELATION_NEGATIVE_THRESHOLD = Decimal("-0.45")
CORRELATION_MIN_RETURN_SAMPLES = 6
CORRELATED_OFFSET_BLOCKED_CODE = "CORRELATED_OFFSET_BLOCKED"

_MICRO_TO_CAS_CORR_MAP: dict[str, str] = {
    "MNQ": "NAS100",
    "MES": "SPX500",
    "MYM": "US30",
    "MGC": "XAUUSD",
}

# Cold-start structural correlation priors (used ONLY when live rolling return correlation is unavailable).
# Gold (XAUUSD) vs US equity indices intentionally has NO fixed prior so live rolling returns decide dynamically.
_STRUCTURAL_CORRELATION_PRIORS: dict[frozenset[str], Decimal] = {
    # Positively correlated US equity indices
    frozenset({"NAS100", "SPX500"}): Decimal("0.85"),
    frozenset({"NAS100", "US30"}): Decimal("0.85"),
    frozenset({"SPX500", "US30"}): Decimal("0.85"),
    # Positively correlated FX pairs
    frozenset({"EURUSD", "GBPUSD"}): Decimal("0.75"),
    frozenset({"AUDUSD", "NZDUSD"}): Decimal("0.75"),
    frozenset({"EURUSD", "AUDUSD"}): Decimal("0.75"),
    frozenset({"GBPUSD", "AUDUSD"}): Decimal("0.75"),
    frozenset({"EURUSD", "NZDUSD"}): Decimal("0.75"),
    frozenset({"GBPUSD", "NZDUSD"}): Decimal("0.75"),
    frozenset({"EURJPY", "GBPJPY"}): Decimal("0.75"),
    frozenset({"AUDJPY", "CADJPY"}): Decimal("0.75"),
    frozenset({"EURJPY", "AUDJPY"}): Decimal("0.75"),
    frozenset({"GBPJPY", "AUDJPY"}): Decimal("0.75"),
    frozenset({"USDJPY", "CADJPY"}): Decimal("0.75"),
    # Negatively correlated FX pairs (opposite-direction USD legs -> same-side positions offset each other)
    frozenset({"EURUSD", "USDCHF"}): Decimal("-0.75"),
    frozenset({"GBPUSD", "USDCHF"}): Decimal("-0.75"),
    frozenset({"AUDUSD", "USDCAD"}): Decimal("-0.75"),
    frozenset({"NZDUSD", "USDCAD"}): Decimal("-0.75"),
    frozenset({"EURUSD", "USDCAD"}): Decimal("-0.75"),
    frozenset({"GBPUSD", "USDCAD"}): Decimal("-0.75"),
    frozenset({"AUDUSD", "USDCHF"}): Decimal("-0.75"),
    frozenset({"NZDUSD", "USDCHF"}): Decimal("-0.75"),
    frozenset({"EURCHF", "USDCHF"}): Decimal("-0.75"),
}

_USD_BASKET_SYMBOLS = frozenset({
    "EURUSD",
    "GBPUSD",
    "USDJPY",
    "USDCHF",
    "AUDUSD",
    "USDCAD",
    "NZDUSD",
})


def _normalize_correlation_symbol(raw: str) -> str:
    txt = str(raw or "").strip().upper()
    if not txt:
        return ""
    if txt in _MICRO_TO_CAS_CORR_MAP:
        return _MICRO_TO_CAS_CORR_MAP[txt]
    norm = str(normalize_market_symbol(txt) or txt).strip().upper()
    return _MICRO_TO_CAS_CORR_MAP.get(norm, norm)


def _extract_positive_decimals(values: Sequence[Any], max_points: int) -> list[Decimal]:
    out: list[Decimal] = []
    tail = list(values)[-max_points:] if len(values) > max_points else list(values)
    for item in tail:
        dec: Decimal | None = None
        try:
            dec = item if isinstance(item, Decimal) else Decimal(str(item))
        except (InvalidOperation, ValueError, TypeError):
            dec = None
        if dec is not None and dec.is_finite() and dec > Decimal("0"):
            out.append(dec)
    return out


def _lookup_price_series(
    price_history: Mapping[str, Sequence[Any]] | None,
    raw_symbol: str,
    norm_symbol: str,
) -> Sequence[Any] | None:
    if not price_history:
        return None
    for key in (raw_symbol, norm_symbol):
        if key and key in price_history:
            return price_history[key]
    for key, seq in price_history.items():
        if _normalize_correlation_symbol(key) == norm_symbol:
            return seq
    return None


def compute_rolling_return_correlation(
    series_a: Sequence[Any],
    series_b: Sequence[Any],
    *,
    min_returns: int = CORRELATION_MIN_RETURN_SAMPLES,
    max_points: int = 50,
) -> Decimal | None:
    """Compute exact Decimal Pearson correlation over trailing percentage returns, or ``None`` if insufficient/flat."""
    if type(min_returns) is not int or min_returns < 2:
        raise ContractError("min_returns must be an int >= 2")
    if type(max_points) is not int or max_points <= min_returns:
        raise ContractError("max_points must exceed min_returns")
    da = _extract_positive_decimals(series_a, max_points)
    db = _extract_positive_decimals(series_b, max_points)
    n = min(len(da), len(db), max_points)
    if n < min_returns + 1:
        return None
    da = da[-n:]
    db = db[-n:]
    with localcontext() as ctx:
        ctx.prec = 40
        rets_a = [(da[i] - da[i - 1]) / da[i - 1] for i in range(1, n)]
        rets_b = [(db[i] - db[i - 1]) / db[i - 1] for i in range(1, n)]
        cnt = Decimal(len(rets_a))
        mean_a = sum(rets_a) / cnt
        mean_b = sum(rets_b) / cnt
        diffs_a = [x - mean_a for x in rets_a]
        diffs_b = [y - mean_b for y in rets_b]
        cov = sum(x * y for x, y in zip(diffs_a, diffs_b))
        var_a = sum(x * x for x in diffs_a)
        var_b = sum(y * y for y in diffs_b)
        if var_a <= Decimal("0") or var_b <= Decimal("0"):
            return None
        denom = (var_a * var_b).sqrt()
        if denom <= Decimal("0"):
            return None
        raw_r = cov / denom
        clamped = max(Decimal("-1"), min(Decimal("1"), raw_r))
        return clamped.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)


def compute_ema(values: Sequence[Decimal], period: int) -> Decimal | None:
    """Compute exact Decimal EMA over ``values`` using period ``period`` (progressive warmup when short)."""
    if type(period) is not int or period <= 0:
        raise ContractError("EMA period must be a positive integer")
    if not values:
        return None
    eff_period = min(period, len(values))
    with localcontext() as ctx:
        ctx.prec = 40
        alpha = Decimal("2") / Decimal(eff_period + 1)
        one_minus = Decimal("1") - alpha
        ema = Decimal(values[0])
        for item in values[1:]:
            ema = (Decimal(item) * alpha) + (ema * one_minus)
        return ema.quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class RegimeAssessment:
    """Deterministic classification of current tick-stream market regime."""

    regime: str
    direction: Side | None
    ema_9: Decimal
    ema_21: Decimal
    ema_50: Decimal
    spread: Decimal
    spread_to_sl_ratio: Decimal
    momentum_delta: Decimal
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "regime": self.regime,
            "direction": None if self.direction is None else self.direction.value,
            "ema_9": decimal_text(self.ema_9),
            "ema_21": decimal_text(self.ema_21),
            "ema_50": decimal_text(self.ema_50),
            "spread": decimal_text(self.spread),
            "spread_to_sl_ratio": decimal_text(self.spread_to_sl_ratio),
            "momentum_delta": decimal_text(self.momentum_delta),
            "reason": self.reason,
        }


class TrendRegimeDetector:
    """Classify markets into TREND_IGNITION, STRONG_TREND, CHOP_RANGE, or SPREAD_SPIKE."""

    def __init__(
        self,
        *,
        max_spread_sl_ratio: Decimal = Decimal("0.25"),
        strong_ema_sep_spread_mult: Decimal = Decimal("1.5"),
        ignition_burst_spread_mult: Decimal = Decimal("3.0"),
    ) -> None:
        self.max_spread_sl_ratio = decimal_value(max_spread_sl_ratio, "max_spread_sl_ratio", positive=True)
        self.strong_ema_sep_spread_mult = decimal_value(
            strong_ema_sep_spread_mult, "strong_ema_sep_spread_mult", positive=True
        )
        self.ignition_burst_spread_mult = decimal_value(
            ignition_burst_spread_mult, "ignition_burst_spread_mult", positive=True
        )

    def classify(
        self,
        *,
        mids: Sequence[Decimal],
        spread: Decimal,
        normal_sl_distance: Decimal,
    ) -> RegimeAssessment:
        decimal_value(spread, "spread", positive=True)
        decimal_value(normal_sl_distance, "normal_sl_distance", positive=True)
        if not mids:
            raise ContractError("mids must contain at least one mid-price sample")

        last = Decimal(mids[-1])
        ema_9 = compute_ema(mids, 9) or last
        ema_21 = compute_ema(mids, 21) or last
        ema_50 = compute_ema(mids, 50) or last
        tail = mids[-5:] if len(mids) >= 5 else mids
        delta = Decimal(tail[-1]) - Decimal(tail[0])

        with localcontext() as ctx:
            ctx.prec = 40
            spread_ratio = (spread / normal_sl_distance).quantize(Decimal('0.00000001'), rounding=ROUND_HALF_UP)
            sep_9_21 = (ema_9 - ema_21).quantize(Decimal('0.00000001'), rounding=ROUND_HALF_UP)
            sep_21_50 = (ema_21 - ema_50).quantize(Decimal('0.00000001'), rounding=ROUND_HALF_UP)

        if spread_ratio > self.max_spread_sl_ratio:
            return RegimeAssessment(
                regime=REGIME_SPREAD_SPIKE,
                direction=None,
                ema_9=ema_9,
                ema_21=ema_21,
                ema_50=ema_50,
                spread=spread,
                spread_to_sl_ratio=spread_ratio,
                momentum_delta=delta,
                reason=f"Spread {decimal_text(spread)} exceeds {decimal_text(self.max_spread_sl_ratio)} of SL distance",
            )

        up_stacked = ema_9 > ema_21 and ema_21 >= ema_50 and last >= ema_9
        down_stacked = ema_9 < ema_21 and ema_21 <= ema_50 and last <= ema_9
        sep_thresh = spread * self.strong_ema_sep_spread_mult
        burst_thresh = spread * self.ignition_burst_spread_mult

        if len(mids) >= 6 and up_stacked and sep_9_21 >= sep_thresh and sep_21_50 > Decimal("0") and delta > Decimal("0"):
            return RegimeAssessment(
                regime=REGIME_STRONG_TREND,
                direction=Side.BUY,
                ema_9=ema_9,
                ema_21=ema_21,
                ema_50=ema_50,
                spread=spread,
                spread_to_sl_ratio=spread_ratio,
                momentum_delta=delta,
                reason=f"Bullish EMA 9>21>50 alignment (sep={decimal_text(sep_9_21)}, delta={decimal_text(delta)})",
            )
        if len(mids) >= 6 and down_stacked and (-sep_9_21) >= sep_thresh and sep_21_50 < Decimal("0") and delta < Decimal("0"):
            return RegimeAssessment(
                regime=REGIME_STRONG_TREND,
                direction=Side.SELL,
                ema_9=ema_9,
                ema_21=ema_21,
                ema_50=ema_50,
                spread=spread,
                spread_to_sl_ratio=spread_ratio,
                momentum_delta=delta,
                reason=f"Bearish EMA 9<21<50 alignment (sep={decimal_text(-sep_9_21)}, delta={decimal_text(delta)})",
            )

        if abs(delta) >= burst_thresh:
            side = Side.BUY if delta > Decimal("0") else Side.SELL
            return RegimeAssessment(
                regime=REGIME_TREND_IGNITION,
                direction=side,
                ema_9=ema_9,
                ema_21=ema_21,
                ema_50=ema_50,
                spread=spread,
                spread_to_sl_ratio=spread_ratio,
                momentum_delta=delta,
                reason=f"Fast momentum ignition delta={decimal_text(delta)} >= {decimal_text(burst_thresh)}",
            )

        if up_stacked and sep_9_21 >= spread:
            return RegimeAssessment(
                regime=REGIME_TREND_IGNITION,
                direction=Side.BUY,
                ema_9=ema_9,
                ema_21=ema_21,
                ema_50=ema_50,
                spread=spread,
                spread_to_sl_ratio=spread_ratio,
                momentum_delta=delta,
                reason="EMA 9>21 bullish ignition",
            )
        if down_stacked and (-sep_9_21) >= spread:
            return RegimeAssessment(
                regime=REGIME_TREND_IGNITION,
                direction=Side.SELL,
                ema_9=ema_9,
                ema_21=ema_21,
                ema_50=ema_50,
                spread=spread,
                spread_to_sl_ratio=spread_ratio,
                momentum_delta=delta,
                reason="EMA 9<21 bearish ignition",
            )

        return RegimeAssessment(
            regime=REGIME_CHOP_RANGE,
            direction=None,
            ema_9=ema_9,
            ema_21=ema_21,
            ema_50=ema_50,
            spread=spread,
            spread_to_sl_ratio=spread_ratio,
            momentum_delta=delta,
            reason="Flat or compressed EMA separation (chop/range filter active)",
        )


@dataclass(frozen=True)
class PyramidLegSnapshot:
    """Open leg geometry & protection stage for House-Money pyramiding checks."""

    ticket: str
    symbol: str
    side: Side
    units: Decimal
    entry_price: Decimal
    stop_loss: Decimal | None
    protection_stage: str


@dataclass(frozen=True)
class PyramidEligibility:
    """Auditable outcome of House-Money scale-in verification."""

    allowed: bool
    reason: str
    leg_index: int
    existing_locked_usd: Decimal
    new_leg_sl_risk_usd: Decimal
    net_floor_usd: Decimal

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "leg_index": self.leg_index,
            "existing_locked_usd": decimal_text(self.existing_locked_usd),
            "new_leg_sl_risk_usd": decimal_text(self.new_leg_sl_risk_usd),
            "net_floor_usd": decimal_text(self.net_floor_usd),
        }


def _locked_leg_floor_usd(leg: PyramidLegSnapshot, *, quote_to_usd: Decimal) -> tuple[bool, Decimal]:
    if leg.stop_loss is None or leg.protection_stage not in BREAKEVEN_LOCKED_STAGES:
        return False, Decimal("0")
    with localcontext() as ctx:
        ctx.prec = 40
        if leg.side is Side.BUY:
            if leg.stop_loss < leg.entry_price:
                return False, Decimal("0")
            locked_quote = (leg.stop_loss - leg.entry_price) * leg.units
        else:
            if leg.stop_loss > leg.entry_price:
                return False, Decimal("0")
            locked_quote = (leg.entry_price - leg.stop_loss) * leg.units
        return True, locked_quote * quote_to_usd


def evaluate_house_money_pyramid_leg(
    *,
    symbol: str,
    side: Side,
    regime: str,
    existing_legs: Sequence[PyramidLegSnapshot],
    new_leg_entry: Decimal,
    new_leg_stop: Decimal,
    new_leg_units: Decimal,
    quote_to_usd: Decimal = Decimal("1"),
    max_legs: int = MAX_PYRAMID_LEGS,
) -> PyramidEligibility:
    """Verify House-Money invariant: ADD <= 3 legs ONLY when earlier legs lock profit >= new SL risk."""
    if not existing_legs:
        return PyramidEligibility(False, "NO_BASE_LEG_FOR_ADD", 0, Decimal("0"), Decimal("0"), Decimal("0"))
    if len(existing_legs) >= max_legs:
        return PyramidEligibility(
            False,
            f"PYRAMID_MAX_LEGS_REACHED ({len(existing_legs)}/{max_legs})",
            len(existing_legs),
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
        )
    if regime not in (REGIME_STRONG_TREND, REGIME_TREND_IGNITION):
        return PyramidEligibility(
            False,
            f"PYRAMID_REGIME_BLOCKED ({regime})",
            len(existing_legs) + 1,
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
        )

    decimal_value(new_leg_entry, "new_leg_entry", positive=True)
    decimal_value(new_leg_stop, "new_leg_stop", positive=True)
    decimal_value(new_leg_units, "new_leg_units", positive=True)
    decimal_value(quote_to_usd, "quote_to_usd", positive=True)

    total_locked = Decimal("0")
    for leg in existing_legs:
        if leg.symbol != symbol or leg.side is not side:
            return PyramidEligibility(
                False, "PYRAMID_LEG_MISMATCH", len(existing_legs) + 1, Decimal("0"), Decimal("0"), Decimal("0")
            )
        locked_ok, leg_floor = _locked_leg_floor_usd(leg, quote_to_usd=quote_to_usd)
        if not locked_ok:
            return PyramidEligibility(
                False,
                f"PRIOR_LEG_NOT_BREAKEVEN_LOCKED ({leg.ticket}: {leg.protection_stage})",
                len(existing_legs) + 1,
                total_locked,
                Decimal("0"),
                Decimal("0"),
            )
        total_locked += leg_floor

    with localcontext() as ctx:
        ctx.prec = 40
        if side is Side.BUY and new_leg_stop >= new_leg_entry:
            return PyramidEligibility(False, "BUY_ADD_STOP_ABOVE_ENTRY", len(existing_legs) + 1, total_locked, Decimal("0"), total_locked)
        if side is Side.SELL and new_leg_stop <= new_leg_entry:
            return PyramidEligibility(False, "SELL_ADD_STOP_BELOW_ENTRY", len(existing_legs) + 1, total_locked, Decimal("0"), total_locked)
        new_risk = abs(new_leg_entry - new_leg_stop) * new_leg_units * quote_to_usd
        net_floor = total_locked - new_risk

    if net_floor < Decimal("0"):
        return PyramidEligibility(
            False,
            f"HOUSE_MONEY_DEFICIT (locked=${decimal_text(total_locked)} < new_risk=${decimal_text(new_risk)})",
            len(existing_legs) + 1,
            total_locked,
            new_risk,
            net_floor,
        )

    return PyramidEligibility(
        True,
        f"HOUSE_MONEY_PYRAMID_ADMITTED (leg {len(existing_legs) + 1}/{max_legs}, net_floor=${decimal_text(net_floor)})",
        len(existing_legs) + 1,
        total_locked,
        new_risk,
        net_floor,
    )


def usd_directional_bucket(symbol: str, side: Side) -> str | None:
    """Return normalized USD directional exposure bucket or ``INDEX`` / ``CROSS``."""
    if symbol in INDEX_INSTRUMENTS:
        return f"US_INDEX_{side.value}"
    if symbol in _USD_BASKET_SYMBOLS:
        if symbol.startswith("USD"):
            usd_dir = "LONG_USD" if side is Side.BUY else "SHORT_USD"
        else:
            usd_dir = "SHORT_USD" if side is Side.BUY else "LONG_USD"
        return usd_dir
    return f"FX_CROSS_{symbol[:3]}"


def evaluate_cross_market_offset_guard(
    *,
    candidate_symbol: str,
    candidate_side: Side,
    open_positions: Sequence[Mapping[str, Any]],
    price_history: Mapping[str, Sequence[Any]] | None = None,
    is_pyramid_add: bool = False,
    positive_threshold: Decimal = CORRELATION_POSITIVE_THRESHOLD,
    negative_threshold: Decimal = CORRELATION_NEGATIVE_THRESHOLD,
) -> tuple[bool, str]:
    """Block concurrent self-canceling offsetting entries across live-correlated or structurally paired markets."""
    if is_pyramid_add or not open_positions:
        return True, "CORRELATED_OFFSET_CLEAR"
    cand_raw = str(candidate_symbol or "")
    cand_norm = _normalize_correlation_symbol(cand_raw)
    if not cand_norm:
        return True, "CORRELATED_OFFSET_CLEAR"
    cand_series = _lookup_price_series(price_history, cand_raw, cand_norm)

    for pos in open_positions:
        pos_raw = str(pos.get("symbol") or "")
        pos_side = str(pos.get("side") or "").strip().upper()
        if pos_side not in ("BUY", "SELL"):
            continue
        pos_norm = _normalize_correlation_symbol(pos_raw)
        if not pos_norm:
            continue
        if cand_norm == pos_norm:
            if candidate_side.value != pos_side:
                return (
                    False,
                    f"{CORRELATED_OFFSET_BLOCKED_CODE} ({cand_norm} {candidate_side.value} opposes open {pos_norm} {pos_side} on same market)",
                )
            continue

        corr_r: Decimal | None = None
        corr_src = "prior"
        if cand_series is not None:
            pos_series = _lookup_price_series(price_history, pos_raw, pos_norm)
            if pos_series is not None:
                corr_r = compute_rolling_return_correlation(cand_series, pos_series)
                if corr_r is not None:
                    corr_src = "live"
        if corr_r is None:
            corr_r = _STRUCTURAL_CORRELATION_PRIORS.get(frozenset({cand_norm, pos_norm}))
            corr_src = "prior"
        if corr_r is None:
            continue

        if corr_r >= positive_threshold and candidate_side.value != pos_side:
            return (
                False,
                f"{CORRELATED_OFFSET_BLOCKED_CODE} ({cand_norm} {candidate_side.value} opposes open {pos_norm} {pos_side} with {corr_src} r={corr_r:+.4f} >= +{decimal_text(positive_threshold)})",
            )
        if corr_r <= negative_threshold and candidate_side.value == pos_side:
            return (
                False,
                f"{CORRELATED_OFFSET_BLOCKED_CODE} ({cand_norm} {candidate_side.value} offsets open {pos_norm} {pos_side} with {corr_src} r={corr_r:+.4f} <= {decimal_text(negative_threshold)})",
            )
    return True, "CORRELATED_OFFSET_CLEAR"


def evaluate_correlation_cap(
    *,
    candidate_symbol: str,
    candidate_side: Side,
    open_positions: Sequence[Mapping[str, Any]],
    price_history: Mapping[str, Sequence[Any]] | None = None,
    is_pyramid_add: bool = False,
    max_bucket_symbols: int = 2,
    max_total_positions: int = 6,
) -> tuple[bool, str]:
    """Prevent self-canceling offsetting exposure and redundant correlated USD/Index risk across open positions."""
    if len(open_positions) >= max_total_positions:
        return False, f"CORRELATION_MAX_POSITIONS ({len(open_positions)}/{max_total_positions})"
    if is_pyramid_add:
        return True, "CORRELATION_PYRAMID_ALLOWED"
    offset_ok, offset_reason = evaluate_cross_market_offset_guard(
        candidate_symbol=candidate_symbol,
        candidate_side=candidate_side,
        open_positions=open_positions,
        price_history=price_history,
        is_pyramid_add=False,
    )
    if not offset_ok:
        return False, offset_reason
    bucket = usd_directional_bucket(candidate_symbol, candidate_side)
    bucket_symbols: set[str] = set()
    for pos in open_positions:
        sym = str(pos.get("symbol") or "")
        s_raw = str(pos.get("side") or "BUY")
        if s_raw not in ("BUY", "SELL"):
            continue
        pos_side = Side(s_raw)
        if usd_directional_bucket(sym, pos_side) == bucket:
            bucket_symbols.add(sym)
    if candidate_symbol not in bucket_symbols and len(bucket_symbols) >= max_bucket_symbols:
        return False, f"CORRELATION_CAP_EXCEEDED ({bucket}: {', '.join(sorted(bucket_symbols))})"
    return True, f"CORRELATION_CLEAR ({bucket})"
