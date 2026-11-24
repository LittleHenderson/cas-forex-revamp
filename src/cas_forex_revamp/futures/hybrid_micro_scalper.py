"""Phase 1 Offline Deterministic Hybrid Micro-Scalping & Sideways Pivot Replay Engine.

Strictly offline / practice simulation ($0.00 real money, zero live order routing).
Models Two-Layer Hybrid orchestration:
- Layer 1 Async Strategist (2-5 min cadence, <= 300 calls/day, 360s TTL, fail-closed FLAT)
- Layer 2 Local 50ms-100ms Math + <1ms 161-parameter ForexMetaValveGate + 5 Anti-Breakout Shields
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, localcontext
from hashlib import sha256
import json
import time
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence

from cas_forex_revamp.composition.trend_regime import (
    REGIME_CHOP_RANGE,
    REGIME_SPREAD_SPIKE,
    REGIME_STRONG_TREND,
    REGIME_TREND_IGNITION,
    TrendRegimeDetector,
    compute_ema,
    evaluate_cross_market_offset_guard,
)
from cas_forex_revamp.contracts import ContractError, Side, canonical_bytes, decimal_text
from cas_forex_revamp.contracts.primitives import utc_time
from cas_forex_revamp.futures.micro_futures_specs import (
    CME_MICRO_FUTURES_SPECS,
    MicroFuturesSizingRefusalError,
    align_price_to_tick,
    get_contract_spec,
    resolve_front_month_contract,
    size_micro_futures_order,
)
from cas_forex_revamp.futures.tradovate_venue import (
    TradovateAccountSnapshot,
    TradovatePosition,
    TradovateQuote,
    _build_futures_valve_proposal,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    PeakEquityStore,
    compute_drawdown_pct,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.live_market_stream import _https_get_pinned_host, validate_pinned_public_feed_url

REGIME_FLAT_STAND_DOWN: Final[str] = "FLAT_STAND_DOWN"
DAY_REGIME_QUIET_CHOP: Final[str] = "QUIET_CHOP"
DAY_REGIME_CLEAN_TREND: Final[str] = "CLEAN_TREND"
DAY_REGIME_VIOLENT_BREAKOUT: Final[str] = "VIOLENT_BREAKOUT"

VERDICT_PASS_TO_PHASE_2: Final[str] = "PASS_TO_PHASE_2"
VERDICT_FAIL_STOP_AND_ARCHIVE: Final[str] = "FAIL_STOP_AND_ARCHIVE"

_ZERO: Final[Decimal] = Decimal("0")
_CENT: Final[Decimal] = Decimal("0.01")
_FOUR_DP: Final[Decimal] = Decimal("0.0001")
_ONE_HUNDRED: Final[Decimal] = Decimal("100")

ALLOWED_DELAYS_MS: Final[tuple[int, ...]] = (250, 500, 900)
ALLOWED_FEE_MODES: Final[frozenset[str]] = frozenset({"stressed", "standard"})
ALLOWED_ENGINE_MODES: Final[frozenset[str]] = frozenset({"hybrid", "swing_only"})
SUPPORTED_MICRO_ROOTS: Final[tuple[str, ...]] = ("MNQ", "MES", "MYM", "MGC")

DEFAULT_YAHOO_FUTURES_SYMBOLS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "MNQ": "NQ=F",
        "MES": "ES=F",
        "MYM": "YM=F",
        "MGC": "GC=F",
    }
)

STRESSED_ROUND_TURN_COMMISSION_USD: Final[Mapping[str, Decimal]] = MappingProxyType(
    {
        "MNQ": Decimal("1.88"),
        "MES": Decimal("1.88"),
        "MYM": Decimal("1.92"),
        "MGC": Decimal("2.42"),
    }
)


def _q2(value: Decimal) -> Decimal:
    return value.quantize(_CENT, rounding=ROUND_HALF_UP)


def _q4(value: Decimal) -> Decimal:
    return value.quantize(_FOUR_DP, rounding=ROUND_HALF_UP)


def _to_decimal_or_none(raw: Any) -> Decimal | None:
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, Decimal):
        return raw if raw.is_finite() else None
    try:
        dec = Decimal(str(raw))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return dec if dec.is_finite() else None


def _require_dec(value: Any, name: str, *, allow_zero: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float) or not isinstance(value, Decimal):
        raise ContractError(f"{name} must be an exact Decimal, got {type(value).__name__}")
    if not value.is_finite():
        raise ContractError(f"{name} must be finite")
    if value < _ZERO or (not allow_zero and value == _ZERO):
        raise ContractError(f"{name} must be positive (allow_zero={allow_zero}), got {value}")
    return value


def ceil_to_tick(root: str, distance: Decimal) -> Decimal:
    """Round a strictly non-negative point distance up to a whole tick multiple."""
    spec = get_contract_spec(root)
    exact = _require_dec(distance, "distance", allow_zero=True)
    if exact == _ZERO:
        return Decimal("0")
    with localcontext() as ctx:
        ctx.prec = 28
        ticks = (exact / spec.tick_size).to_integral_value(rounding=ROUND_CEILING)
        return (ticks * spec.tick_size).quantize(spec.tick_size)


@dataclass(frozen=True)
class CostProfile:
    """Exact Tradovate round-turn fee, spread/slippage, and box-width thresholds per contract."""

    root: str
    fee_mode: str
    passive_limit: bool
    commission_usd: Decimal
    spread_slip_usd: Decimal
    total_rt_cost_usd: Decimal
    cost_points: Decimal
    min_box_width_points: Decimal
    min_tp_points: Decimal


def get_round_turn_commission_usd(root_or_symbol: str, *, fee_mode: str = "stressed") -> Decimal:
    """Return exact 1-contract round-turn commission+exchange+NFA USD fee for fee_mode."""
    spec = get_contract_spec(root_or_symbol)
    if fee_mode not in ALLOWED_FEE_MODES:
        raise ContractError(f"Unsupported fee_mode {fee_mode!r}")
    if fee_mode == "stressed":
        return STRESSED_ROUND_TURN_COMMISSION_USD[spec.root]
    return spec.default_round_turn_commission_usd


def compute_all_in_cost_profile(
    root_or_symbol: str,
    *,
    fee_mode: str = "stressed",
    passive_limit: bool = True,
    min_box_cost_multiple: Decimal = Decimal("7.6923"),
    min_tp_cost_multiple: Decimal = Decimal("3.00"),
) -> CostProfile:
    """Compute exact round-turn fee cost and minimum sideways box width / TP floors."""
    spec = get_contract_spec(root_or_symbol)
    comm = get_round_turn_commission_usd(spec.root, fee_mode=fee_mode)
    if not isinstance(passive_limit, bool):
        raise ContractError("passive_limit must be bool")
    _require_dec(min_box_cost_multiple, "min_box_cost_multiple")
    _require_dec(min_tp_cost_multiple, "min_tp_cost_multiple")
    spread_slip_usd = Decimal("0.00") if passive_limit else _q2(Decimal("2") * spec.tick_value_usd)
    total_rt_usd = _q2(comm + spread_slip_usd)
    with localcontext() as ctx:
        ctx.prec = 28
        cost_points = (total_rt_usd / spec.point_value_usd).quantize(_FOUR_DP, rounding=ROUND_HALF_UP)
        raw_box_pts = min_box_cost_multiple * (total_rt_usd / spec.point_value_usd)
        min_box_pts = raw_box_pts.quantize(_CENT, rounding=ROUND_HALF_UP)
        raw_tp_pts = min_tp_cost_multiple * (total_rt_usd / spec.point_value_usd)
        min_tp_pts = ceil_to_tick(spec.root, raw_tp_pts)
    return CostProfile(
        root=spec.root,
        fee_mode=fee_mode,
        passive_limit=passive_limit,
        commission_usd=comm,
        spread_slip_usd=spread_slip_usd,
        total_rt_cost_usd=total_rt_usd,
        cost_points=cost_points,
        min_box_width_points=min_box_pts,
        min_tp_points=min_tp_pts,
    )


@dataclass(frozen=True)
class M1Bar:
    """Validated 1-minute OHLC bar using exact Decimal prices and UTC timestamps."""

    symbol: str
    timestamp_utc: datetime
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: int = 0

    def __post_init__(self) -> None:
        spec = get_contract_spec(self.symbol)
        ts = utc_time(self.timestamp_utc, "timestamp_utc")
        o_d = align_price_to_tick(spec.root, _require_dec(self.open, "open"))
        h_d = align_price_to_tick(spec.root, _require_dec(self.high, "high"))
        l_d = align_price_to_tick(spec.root, _require_dec(self.low, "low"))
        c_d = align_price_to_tick(spec.root, _require_dec(self.close, "close"))
        hi = max(o_d, h_d, l_d, c_d)
        lo = min(o_d, h_d, l_d, c_d)
        if type(self.volume) is not int or self.volume < 0:
            raise ContractError(f"volume must be non-negative int, got {self.volume!r}")
        object.__setattr__(self, "symbol", spec.root)
        object.__setattr__(self, "timestamp_utc", ts)
        object.__setattr__(self, "open", o_d)
        object.__setattr__(self, "high", hi)
        object.__setattr__(self, "low", lo)
        object.__setattr__(self, "close", c_d)

    @property
    def range_points(self) -> Decimal:
        return self.high - self.low

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol,
            "ts": self.timestamp_utc.isoformat().replace("+00:00", "Z"),
            "o": decimal_text(self.open),
            "h": decimal_text(self.high),
            "l": decimal_text(self.low),
            "c": decimal_text(self.close),
            "v": self.volume,
        }

    @classmethod
    def from_dict(cls, symbol: str, row: Mapping[str, Any]) -> "M1Bar":
        ts_raw = row.get("ts") or row.get("timestamp_utc") or row.get("time")
        if isinstance(ts_raw, (int, float)) and not isinstance(ts_raw, bool):
            ts = datetime.fromtimestamp(int(ts_raw), tz=timezone.utc)
        elif isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        else:
            raise ContractError(f"Invalid M1Bar timestamp: {ts_raw!r}")
        o_raw = row.get("o") if row.get("o") is not None else row.get("open")
        h_raw = row.get("h") if row.get("h") is not None else row.get("high")
        l_raw = row.get("l") if row.get("l") is not None else row.get("low")
        c_raw = row.get("c") if row.get("c") is not None else row.get("close")
        v_raw = row.get("v") if row.get("v") is not None else row.get("volume", 0)
        vol = int(v_raw) if isinstance(v_raw, (int, float)) and not isinstance(v_raw, bool) and int(v_raw) >= 0 else 0
        o_dec = _to_decimal_or_none(o_raw)
        h_dec = _to_decimal_or_none(h_raw)
        l_dec = _to_decimal_or_none(l_raw)
        c_dec = _to_decimal_or_none(c_raw)
        if o_dec is None or h_dec is None or l_dec is None or c_dec is None:
            raise ContractError(f"M1Bar has non-finite OHLC values: {row!r}")
        return cls(symbol=symbol, timestamp_utc=ts, open=o_dec, high=h_dec, low=l_dec, close=c_dec, volume=vol)


def _parse_yahoo_bar(root: str, ts_val: Any, o_val: Any, h_val: Any, l_val: Any, c_val: Any, v_val: Any) -> M1Bar | None:
    if isinstance(ts_val, bool) or not isinstance(ts_val, (int, float)):
        return None
    o_d = _to_decimal_or_none(o_val)
    h_d = _to_decimal_or_none(h_val)
    l_d = _to_decimal_or_none(l_val)
    c_d = _to_decimal_or_none(c_val)
    if o_d is None or h_d is None or l_d is None or c_d is None:
        return None
    if min(o_d, h_d, l_d, c_d) <= _ZERO:
        return None
    vol = int(v_val) if isinstance(v_val, (int, float)) and not isinstance(v_val, bool) and int(v_val) >= 0 else 0
    return M1Bar(
        symbol=root,
        timestamp_utc=datetime.fromtimestamp(int(ts_val), tz=timezone.utc),
        open=o_d,
        high=h_d,
        low=l_d,
        close=c_d,
        volume=vol,
    )


def fetch_real_cme_m1_dataset(
    *,
    roots: Sequence[str] = SUPPORTED_MICRO_ROOTS,
    range_window: str = "7d",
    interval: str = "1m",
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Fetch real 1-minute CME/COMEX/CBOT futures bars via pinned HTTPS host validation."""
    symbols_out: dict[str, list[dict[str, Any]]] = {}
    spans: dict[str, dict[str, Any]] = {}
    for raw_root in roots:
        spec = get_contract_spec(raw_root)
        root = spec.root
        ysym = DEFAULT_YAHOO_FUTURES_SYMBOLS[root]
        url = f"https://query1.finance.yahoo.com/v8/finance/chart/{ysym}?interval={interval}&range={range_window}"
        safe_url = validate_pinned_public_feed_url(url, label=f"cme_m1_{root}", allow_yahoo_chart=True)
        raw_bytes = _https_get_pinned_host(safe_url, timeout_seconds=timeout_seconds, max_bytes=4_194_304)
        parsed = json.loads(raw_bytes.decode("utf-8"))
        res_list = (parsed.get("chart") or {}).get("result") or []
        if not res_list or not isinstance(res_list[0], dict):
            raise ContractError(f"Pinned Yahoo chart feed returned no result for {root} ({ysym})")
        chart_doc = res_list[0]
        timestamps = chart_doc.get("timestamp") or []
        qblock = ((chart_doc.get("indicators") or {}).get("quote") or [{}])[0]
        opens = qblock.get("open") or []
        highs = qblock.get("high") or []
        lows = qblock.get("low") or []
        closes = qblock.get("close") or []
        vols = qblock.get("volume") or []
        bars_map: dict[int, M1Bar] = {}
        limit = min(len(timestamps), len(opens), len(highs), len(lows), len(closes))
        for i in range(limit):
            v_raw = vols[i] if i < len(vols) else 0
            bar = _parse_yahoo_bar(root, timestamps[i], opens[i], highs[i], lows[i], closes[i], v_raw)
            if bar is not None:
                bars_map[int(bar.timestamp_utc.timestamp())] = bar
        ordered_bars = [bars_map[k] for k in sorted(bars_map)]
        if not ordered_bars:
            raise ContractError(f"Zero valid M1 bars parsed for {root} ({ysym})")
        symbols_out[root] = [b.to_dict() for b in ordered_bars]
        spans[root] = {
            "yahoo_symbol": ysym,
            "bars": len(ordered_bars),
            "start_utc": ordered_bars[0].timestamp_utc.isoformat().replace("+00:00", "Z"),
            "end_utc": ordered_bars[-1].timestamp_utc.isoformat().replace("+00:00", "Z"),
            "utc_days": sorted({b.timestamp_utc.strftime("%Y-%m-%d") for b in ordered_bars}),
        }
    core_payload: dict[str, Any] = {
        "schema": "cas-forex-phase1-cme-m1-v1",
        "source": "query1.finance.yahoo.com",
        "interval": interval,
        "range": range_window,
        "symbols": symbols_out,
        "meta": spans,
    }
    core_payload["dataset_sha256"] = sha256(canonical_bytes(core_payload)).hexdigest()
    return core_payload


def dataset_from_wire_dict(doc: Mapping[str, Any]) -> tuple[dict[str, list[M1Bar]], str]:
    """Validate and deserialize a canonical dataset dict into sorted unique symbol -> list[M1Bar]."""
    raw_syms = doc.get("symbols")
    if not isinstance(raw_syms, Mapping) or not raw_syms:
        raise ContractError("Dataset missing non-empty 'symbols' mapping")
    out: dict[str, list[M1Bar]] = {}
    norm_wire: dict[str, list[dict[str, Any]]] = {}
    for sym, rows in sorted(raw_syms.items()):
        spec = get_contract_spec(sym)
        if not isinstance(rows, Sequence):
            raise ContractError(f"Dataset rows for {sym} must be a sequence")
        dedup: dict[datetime, M1Bar] = {}
        for row in rows:
            b = M1Bar.from_dict(spec.root, row)
            dedup[b.timestamp_utc] = b
        bars = [dedup[k] for k in sorted(dedup)]
        out[spec.root] = bars
        norm_wire[spec.root] = [b.to_dict() for b in bars]
    dataset_sha = sha256(canonical_bytes(norm_wire)).hexdigest()
    return out, dataset_sha


def build_synthetic_three_regime_dataset() -> dict[str, Any]:
    """Build deterministic 3-regime stress dataset (QUIET_CHOP, CLEAN_TREND, VIOLENT_BREAKOUT)."""
    specs = {
        "MNQ": (Decimal("25000.00"), Decimal("2.00"), Decimal("14.00"), Decimal("4.50")),
        "MES": (Decimal("6000.00"), Decimal("0.50"), Decimal("4.50"), Decimal("1.50")),
        "MYM": (Decimal("44000.00"), Decimal("1.00"), Decimal("8.00"), Decimal("3.00")),
        "MGC": (Decimal("2700.00"), Decimal("0.20"), Decimal("2.40"), Decimal("0.80")),
    }
    symbols_out: dict[str, list[dict[str, Any]]] = {r: [] for r in specs}
    day_starts = [
        ("2026-11-16", 14, DAY_REGIME_QUIET_CHOP),
        ("2026-11-17", 14, DAY_REGIME_CLEAN_TREND),
        ("2026-11-18", 14, DAY_REGIME_VIOLENT_BREAKOUT),
    ]
    for root, (anchor, bar_body, chop_amp, trend_step) in specs.items():
        tick = CME_MICRO_FUTURES_SPECS[root].tick_size
        for day_str, start_hour, archetype in day_starts:
            y, m, d = (int(p) for p in day_str.split("-"))
            base_dt = datetime(y, m, d, start_hour, 0, 0, tzinfo=timezone.utc)
            price = anchor
            for idx in range(120):
                ts = base_dt + timedelta(minutes=idx)
                if archetype == DAY_REGIME_QUIET_CHOP:
                    offsets = (0, 2, 5, 7, 5, 2, 0, -2, -5, -7, -5, -2)
                    phase = idx % 12
                    o_px = align_price_to_tick(root, anchor + (chop_amp * Decimal(offsets[phase])) / Decimal("7"))
                    c_px = align_price_to_tick(root, anchor + (chop_amp * Decimal(offsets[(phase + 1) % 12])) / Decimal("7"))
                    pad = max(tick * Decimal("2"), chop_amp / Decimal("8"))
                elif archetype == DAY_REGIME_CLEAN_TREND:
                    step = -trend_step * Decimal("0.45") if (idx % 9) in (3, 6) else trend_step
                    o_px = align_price_to_tick(root, price)
                    c_px = align_price_to_tick(root, price + step)
                    pad = max(tick * Decimal("2"), trend_step * Decimal("0.55"))
                    price = c_px
                elif idx < 75:
                    offsets = (0, 3, 5, 3, 0, -3, -5, -3)
                    phase = idx % 8
                    o_px = align_price_to_tick(root, anchor + (chop_amp * Decimal(offsets[phase])) / Decimal("8"))
                    c_px = align_price_to_tick(root, anchor + (chop_amp * Decimal(offsets[(phase + 1) % 8])) / Decimal("8"))
                    pad = tick
                    price = c_px
                else:
                    burst = chop_amp * Decimal("3.2") if (idx % 5) != 2 else -chop_amp * Decimal("2.4")
                    o_px = align_price_to_tick(root, price)
                    c_px = align_price_to_tick(root, price + burst)
                    pad = max(tick * Decimal("4"), abs(burst) * Decimal("0.25"))
                    price = c_px
                h_px = max(o_px, c_px) + pad
                l_px = min(o_px, c_px) - pad
                bar = M1Bar(symbol=root, timestamp_utc=ts, open=o_px, high=h_px, low=l_px, close=c_px, volume=100)
                symbols_out[root].append(bar.to_dict())
    payload: dict[str, Any] = {
        "schema": "cas-forex-phase1-synthetic-stress-v1",
        "source": "deterministic-synthetic-3regime",
        "interval": "1m",
        "range": "3d",
        "symbols": symbols_out,
    }
    payload["dataset_sha256"] = sha256(canonical_bytes(symbols_out)).hexdigest()
    return payload


@dataclass(frozen=True)
class ReplayConfig:
    """Immutable configuration for a deterministic Phase 1 replay run."""

    starting_equity_usd: Decimal = Decimal("5000.00")
    total_risk_pct: Decimal = Decimal("1.00")
    max_split_legs_k: int = 3
    max_open_positions: int | None = None
    fill_delay_ms: int = 500
    fee_mode: str = "stressed"
    engine_mode: str = "hybrid"
    max_daily_scalps: int = 25
    daily_scalp_loss_fee_cap_pct: Decimal = Decimal("2.00")
    min_box_cost_multiple: Decimal = Decimal("7.6923")
    min_tp_cost_multiple: Decimal = Decimal("3.00")
    breakout_kill_atr_mult: Decimal = Decimal("0.35")
    burst_kill_atr_mult: Decimal = Decimal("2.00")
    breakout_lockout_seconds: int = 1200
    consecutive_loss_lock_count: int = 2
    post_loss_cooldown_seconds: int = 900
    layer1_cadence_seconds: int = 180
    layer1_ttl_seconds: int = 360
    layer1_max_calls_per_day: int = 300
    min_warmup_m1_bars: int = 10
    min_warmup_ticks: int = 30
    min_warmup_span_seconds: int = 60
    max_drawdown_pct: Decimal = Decimal("0.10")
    phase1_pass_min_pf: Decimal = Decimal("1.25")
    phase1_pass_max_dd_pct: Decimal = Decimal("6.00")
    phase1_min_closed_trades: int = 10
    max_contracts_per_order: int = 20

    def __post_init__(self) -> None:
        _require_dec(self.starting_equity_usd, "starting_equity_usd")
        _require_dec(self.total_risk_pct, "total_risk_pct")
        if self.total_risk_pct > Decimal("1.00"):
            raise ContractError(f"total_risk_pct {self.total_risk_pct}% exceeds constitutional 1.00% limit")
        if type(self.max_split_legs_k) is not int or not (1 <= self.max_split_legs_k <= 3):
            raise ContractError(f"max_split_legs_k must be int in 1..3, got {self.max_split_legs_k!r}")
        cap_pos = 2 if self.starting_equity_usd <= Decimal("3000.00") else 4
        eff_max_pos = cap_pos if self.max_open_positions is None else self.max_open_positions
        if type(eff_max_pos) is not int or not (1 <= eff_max_pos <= cap_pos):
            raise ContractError(
                f"max_open_positions must be int in 1..{cap_pos} for equity ${self.starting_equity_usd}, got {eff_max_pos!r}"
            )
        object.__setattr__(self, "max_open_positions", eff_max_pos)
        if type(self.fill_delay_ms) is not int or self.fill_delay_ms not in ALLOWED_DELAYS_MS:
            raise ContractError(f"fill_delay_ms must be one of {ALLOWED_DELAYS_MS}, got {self.fill_delay_ms!r}")
        if self.fee_mode not in ALLOWED_FEE_MODES:
            raise ContractError(f"fee_mode must be one of {ALLOWED_FEE_MODES}, got {self.fee_mode!r}")
        if self.engine_mode not in ALLOWED_ENGINE_MODES:
            raise ContractError(f"engine_mode must be one of {ALLOWED_ENGINE_MODES}, got {self.engine_mode!r}")
        if type(self.max_daily_scalps) is not int or not (1 <= self.max_daily_scalps <= 40):
            raise ContractError(f"max_daily_scalps must be int in 1..40, got {self.max_daily_scalps!r}")
        _require_dec(self.daily_scalp_loss_fee_cap_pct, "daily_scalp_loss_fee_cap_pct")
        _require_dec(self.min_box_cost_multiple, "min_box_cost_multiple")
        _require_dec(self.min_tp_cost_multiple, "min_tp_cost_multiple")
        _require_dec(self.breakout_kill_atr_mult, "breakout_kill_atr_mult")
        _require_dec(self.burst_kill_atr_mult, "burst_kill_atr_mult")
        if type(self.consecutive_loss_lock_count) is not int or self.consecutive_loss_lock_count != 2:
            raise ContractError("consecutive_loss_lock_count must be 2")
        if type(self.layer1_max_calls_per_day) is not int or not (1 <= self.layer1_max_calls_per_day <= 300):
            raise ContractError("layer1_max_calls_per_day must be <= 300")
        if self.min_warmup_m1_bars < 10 or self.min_warmup_ticks < 30 or self.min_warmup_span_seconds < 60:
            raise ContractError("Warmup floors must satisfy >= 10 M1 bars, >= 30 ticks, >= 60s span")
        _require_dec(self.max_drawdown_pct, "max_drawdown_pct")
        if self.max_drawdown_pct > Decimal("0.10"):
            raise ContractError("max_drawdown_pct cannot exceed 0.10")


@dataclass(frozen=True)
class Layer1Directive:
    """Layer 1 Async Strategist directive with explicit TTL and fail-closed defaults."""

    symbol: str
    regime: str
    bias: Side | None
    range_low: Decimal
    range_high: Decimal
    atr: Decimal
    efficiency_ratio: Decimal
    issued_at: datetime
    expires_at: datetime
    reason: str

    def is_valid_at(self, now: datetime) -> bool:
        return self.regime not in (REGIME_FLAT_STAND_DOWN, REGIME_SPREAD_SPIKE) and now < self.expires_at


@dataclass
class PendingLimitOrder:
    order_id: str
    symbol: str
    side: Side
    strategy_kind: str
    limit_price: Decimal
    stop_loss_price: Decimal
    take_profit_price: Decimal
    stop_distance_points: Decimal
    take_profit_points: Decimal
    contracts: int
    commission_usd: Decimal
    risk_pct_used: Decimal
    submitted_at: datetime
    active_at: datetime
    expires_at: datetime
    range_low: Decimal
    range_high: Decimal
    valve_decision_digest: str


@dataclass
class OpenSimPosition:
    position_id: str
    symbol: str
    contract_code: str
    side: Side
    strategy_kind: str
    contracts: int
    entry_price: Decimal
    stop_loss_price: Decimal
    take_profit_price: Decimal
    initial_stop_distance_points: Decimal
    commission_usd: Decimal
    margin_usd: Decimal
    opened_at: datetime
    protection_stage: str = "INITIAL"
    range_low: Decimal = _ZERO
    range_high: Decimal = _ZERO
    peak_favorable_price: Decimal = _ZERO


@dataclass(frozen=True)
class ClosedSimTrade:
    position_id: str
    symbol: str
    day_utc: str
    day_regime: str
    strategy_kind: str
    side: str
    contracts: int
    entry_price: Decimal
    exit_price: Decimal
    gross_pnl_usd: Decimal
    commission_usd: Decimal
    net_pnl_usd: Decimal
    exit_reason: str
    opened_at: str
    closed_at: str


def compute_burst_leg_risk_pct(total_risk_pct: Decimal, legs_k: int) -> Decimal:
    """Split a single trade risk envelope R_total across K <= 3 micro-legs (R_total / K)."""
    _require_dec(total_risk_pct, "total_risk_pct")
    if total_risk_pct > Decimal("1.00"):
        raise ContractError(f"total_risk_pct {total_risk_pct}% exceeds 1.00% constitutional ceiling")
    if type(legs_k) is not int or not (1 <= legs_k <= 3):
        raise ContractError(f"legs_k must be int in 1..3, got {legs_k!r}")
    with localcontext() as ctx:
        ctx.prec = 28
        per_leg = (total_risk_pct / Decimal(legs_k)).quantize(_FOUR_DP, rounding=ROUND_FLOOR)
    if per_leg <= _ZERO:
        raise ContractError("Per-leg risk_pct quantized to zero")
    return per_leg


def validate_scalp_geometry(
    root_or_symbol: str,
    stop_distance_points: Decimal,
    take_profit_points: Decimal,
    *,
    fee_mode: str = "stressed",
    passive_limit: bool = True,
    min_tp_cost_multiple: Decimal = Decimal("3.00"),
) -> tuple[bool, str]:
    """Shield 1: strictly require SL <= TP and net TP >= 3x all-in fee cost (zero steamroller traps)."""
    spec = get_contract_spec(root_or_symbol)
    stop_d = _require_dec(stop_distance_points, "stop_distance_points")
    tp_d = _require_dec(take_profit_points, "take_profit_points")
    if stop_d > tp_d:
        return False, f"SL_GT_TP_STEAMROLLER_REJECTED:{stop_d}>{tp_d}"
    cost_prof = compute_all_in_cost_profile(
        spec.root,
        fee_mode=fee_mode,
        passive_limit=passive_limit,
        min_tp_cost_multiple=min_tp_cost_multiple,
    )
    gross_tp_usd = tp_d * spec.point_value_usd
    req_usd = min_tp_cost_multiple * cost_prof.total_rt_cost_usd
    if gross_tp_usd < req_usd:
        return False, f"BELOW_3X_FEE_FLOOR:{decimal_text(_q2(gross_tp_usd))}<{decimal_text(_q2(req_usd))}"
    return True, "OK"


def check_breakout_kill_switch(
    *,
    range_low: Decimal,
    range_high: Decimal,
    atr: Decimal,
    tick_price: Decimal,
    prev_tick_price: Decimal | None,
    bar_close_outside: bool,
    breakout_atr_mult: Decimal = Decimal("0.35"),
    burst_atr_mult: Decimal = Decimal("2.00"),
) -> tuple[bool, str]:
    """Shield 2: <50ms Layer-2 breakout kill-switch downgrading CHOP_RANGE -> FLAT_STAND_DOWN."""
    if atr <= _ZERO:
        return False, "NO_ATR"
    buf = breakout_atr_mult * atr
    if tick_price > (range_high + buf):
        return True, "BOX_UPPER_BREAKOUT_ATR"
    if tick_price < (range_low - buf):
        return True, "BOX_LOWER_BREAKOUT_ATR"
    if bar_close_outside:
        return True, "M1_CLOSE_OUTSIDE_BOX"
    if prev_tick_price is not None and abs(tick_price - prev_tick_price) >= (burst_atr_mult * atr):
        return True, "FIVE_SEC_2ATR_BURST"
    return False, "IN_BOX"


def _compute_atr_from_bars(bars: Sequence[M1Bar], root: str, period: int = 14) -> Decimal:
    spec = get_contract_spec(root)
    if len(bars) < 2:
        return spec.tick_size * Decimal("4")
    window = bars[-min(len(bars), period + 1) :]
    trs: list[Decimal] = []
    for idx in range(1, len(window)):
        cur = window[idx]
        prev_c = window[idx - 1].close
        trs.append(max(cur.high - cur.low, abs(cur.high - prev_c), abs(cur.low - prev_c)))
    avg_tr = sum(trs, _ZERO) / Decimal(len(trs))
    return max(spec.tick_size * Decimal("2"), align_price_to_tick(root, avg_tr))


def _compute_efficiency_ratio(closes: Sequence[Decimal]) -> Decimal:
    if len(closes) < 3:
        return Decimal("0")
    net_move = abs(closes[-1] - closes[0])
    path_sum = sum((abs(closes[i] - closes[i - 1]) for i in range(1, len(closes))), _ZERO)
    if path_sum <= _ZERO:
        return Decimal("0")
    return (net_move / path_sum).quantize(_FOUR_DP, rounding=ROUND_HALF_UP)


def evaluate_layer1_directive(
    *,
    symbol: str,
    recent_bars: Sequence[M1Bar],
    spread: Decimal,
    now: datetime,
    config: ReplayConfig,
    in_maintenance_window: bool,
    chop_locked_out: bool,
    calls_used_today: int,
) -> tuple[Layer1Directive, bool]:
    """Run Layer 1 strategist over recent M1 bars; returns (directive, consumed_ai_call)."""
    expires_at = now + timedelta(seconds=config.layer1_ttl_seconds)
    if calls_used_today >= config.layer1_max_calls_per_day:
        return (
            Layer1Directive(symbol, REGIME_FLAT_STAND_DOWN, None, _ZERO, _ZERO, _ZERO, _ZERO, now, expires_at, "DAILY_AI_CALL_CAP_REACHED"),
            False,
        )
    if in_maintenance_window or len(recent_bars) < config.min_warmup_m1_bars:
        return (
            Layer1Directive(symbol, REGIME_FLAT_STAND_DOWN, None, _ZERO, _ZERO, _ZERO, _ZERO, now, expires_at, "MAINTENANCE_OR_WARMUP_FLAT"),
            False,
        )

    atr = _compute_atr_from_bars(recent_bars, symbol, period=14)
    tail_bars = recent_bars[-min(len(recent_bars), 20) :]
    box_bars = recent_bars[-min(len(recent_bars), 15) :]
    mids = [b.close for b in tail_bars]
    range_low = min(b.low for b in box_bars)
    range_high = max(b.high for b in box_bars)
    box_width = range_high - range_low
    er = _compute_efficiency_ratio([b.close for b in box_bars])
    normal_sl = max(CME_MICRO_FUTURES_SPECS[symbol].tick_size * Decimal("4"), atr)
    assess = TrendRegimeDetector().classify(mids=mids, spread=spread, normal_sl_distance=normal_sl)

    if assess.regime == REGIME_SPREAD_SPIKE:
        return Layer1Directive(symbol, REGIME_FLAT_STAND_DOWN, None, range_low, range_high, atr, er, now, expires_at, "SPREAD_SPIKE_STAND_DOWN"), True

    if assess.regime in (REGIME_STRONG_TREND, REGIME_TREND_IGNITION) and er >= Decimal("0.38"):
        return Layer1Directive(symbol, assess.regime, assess.direction, range_low, range_high, atr, er, now, expires_at, assess.reason), True

    if config.engine_mode == "hybrid" and not chop_locked_out:
        passive_prof = compute_all_in_cost_profile(
            symbol,
            fee_mode=config.fee_mode,
            passive_limit=True,
            min_box_cost_multiple=config.min_box_cost_multiple,
            min_tp_cost_multiple=config.min_tp_cost_multiple,
        )
        if er <= Decimal("0.35") and box_width >= passive_prof.min_box_width_points:
            return (
                Layer1Directive(
                    symbol, REGIME_CHOP_RANGE, None, range_low, range_high, atr, er, now, expires_at, f"VALID_CHOP_BOX_{decimal_text(box_width)}pts"
                ),
                True,
            )

    return Layer1Directive(symbol, REGIME_FLAT_STAND_DOWN, None, range_low, range_high, atr, er, now, expires_at, "NO_TREND_OR_BOX_TOO_NARROW"), True


def classify_utc_day_regimes(bars: Sequence[M1Bar]) -> dict[str, str]:
    """Label each UTC day in a symbol bar stream as QUIET_CHOP, CLEAN_TREND, or VIOLENT_BREAKOUT."""
    by_day: dict[str, list[M1Bar]] = {}
    for b in bars:
        by_day.setdefault(b.timestamp_utc.strftime("%Y-%m-%d"), []).append(b)
    labels: dict[str, str] = {}
    for day_key, dbars in sorted(by_day.items()):
        if len(dbars) < 3:
            labels[day_key] = DAY_REGIME_QUIET_CHOP
            continue
        ranges = sorted(b.range_points for b in dbars)
        med_range = ranges[len(ranges) // 2]
        max_range = ranges[-1]
        shock_ratio = (max_range / med_range) if med_range > _ZERO else Decimal("1")
        er = _compute_efficiency_ratio([b.close for b in dbars])
        if shock_ratio >= Decimal("4.5") and er >= Decimal("0.20"):
            labels[day_key] = DAY_REGIME_VIOLENT_BREAKOUT
        elif er >= Decimal("0.28"):
            labels[day_key] = DAY_REGIME_CLEAN_TREND
        else:
            labels[day_key] = DAY_REGIME_QUIET_CHOP
    return labels


def _expand_bar_to_subticks(bar: M1Bar) -> tuple[Decimal, ...]:
    mid_hl = align_price_to_tick(bar.symbol, (bar.high + bar.low) / Decimal("2"))
    if bar.close >= bar.open:
        return (
            bar.open,
            bar.low,
            mid_hl,
            bar.high,
            align_price_to_tick(bar.symbol, (bar.high + bar.close) / Decimal("2")),
            bar.close,
        )
    return (
        bar.open,
        bar.high,
        mid_hl,
        bar.low,
        align_price_to_tick(bar.symbol, (bar.low + bar.close) / Decimal("2")),
        bar.close,
    )


def _is_us_maintenance_deadzone(now: datetime) -> bool:
    hhmm = (now.hour * 100) + now.minute
    return 2050 <= hhmm <= 2205


@dataclass
class _SymbolRuntime:
    continuous_bars: deque[M1Bar] = field(default_factory=lambda: deque(maxlen=64))
    mid_history: list[Decimal] = field(default_factory=list)
    warmup_ticks: int = 0
    warmup_first_ts: datetime | None = None
    last_bar_ts: datetime | None = None
    last_tick_price: Decimal | None = None
    last_l1_eval_at: datetime | None = None
    directive: Layer1Directive | None = None
    breakout_lockout_until: datetime | None = None
    loss_cooldown_until: datetime | None = None
    consecutive_scalp_losses: int = 0
    pending_limits: list[PendingLimitOrder] = field(default_factory=list)
    force_l1_wakeup: bool = False


class HybridMicroScalpBacktester:
    """Deterministic sub-bar event simulator implementing the Two-Layer Hybrid architecture."""

    def __init__(
        self,
        config: ReplayConfig | None = None,
        *,
        valve_gate: ForexMetaValveGate | None = None,
    ) -> None:
        self.config = config if config is not None else ReplayConfig()
        self.valve_gate = valve_gate if valve_gate is not None else load_default_forex_valve_gate()

    def _compute_latency_slippage(self, root: str, bar_range: Decimal) -> Decimal:
        spec = get_contract_spec(root)
        raw_drift = (bar_range / Decimal("60000")) * Decimal(self.config.fill_delay_ms) * Decimal("3")
        floor_ticks = _ZERO
        if self.config.fill_delay_ms >= 900:
            floor_ticks = spec.tick_size * Decimal("2")
        elif self.config.fill_delay_ms >= 500:
            floor_ticks = spec.tick_size
        return ceil_to_tick(root, max(raw_drift, floor_ticks))

    def _compute_passive_penetration_needed(self, root: str, bar_range: Decimal) -> Decimal:
        spec = get_contract_spec(root)
        if self.config.fill_delay_ms <= 250:
            return _ZERO
        if self.config.fill_delay_ms <= 500:
            return spec.tick_size
        return spec.tick_size * Decimal("2")

    @staticmethod
    def _advance_protection(pos: OpenSimPosition, ref_px: Decimal, atr_est: Decimal) -> None:
        """Advance conservative true-breakeven and trailing profit stops in one shared path."""
        spec = CME_MICRO_FUTURES_SPECS[pos.symbol]
        is_buy = pos.side == Side.BUY
        if pos.peak_favorable_price == _ZERO or (is_buy and ref_px > pos.peak_favorable_price) or (not is_buy and ref_px < pos.peak_favorable_price):
            pos.peak_favorable_price = ref_px
        fav_pts = (ref_px - pos.entry_price) if is_buy else (pos.entry_price - ref_px)
        be_trigger = max(pos.initial_stop_distance_points, spec.tick_size * Decimal("2"))
        if fav_pts >= be_trigger:
            fee_cover = ceil_to_tick(pos.symbol, (pos.commission_usd / Decimal(pos.contracts)) / spec.point_value_usd)
            raw_be = (pos.entry_price + fee_cover) if is_buy else max(spec.tick_size, pos.entry_price - fee_cover)
            be_floor = align_price_to_tick(pos.symbol, raw_be)
            better_be = (be_floor > pos.stop_loss_price and be_floor < ref_px) if is_buy else (be_floor < pos.stop_loss_price and be_floor > ref_px)
            if better_be:
                pos.stop_loss_price = be_floor
                pos.protection_stage = "BREAKEVEN_LOCKED"
        if pos.strategy_kind == "TREND" and fav_pts >= (pos.initial_stop_distance_points * Decimal("1.5")):
            raw_trail = (ref_px - (atr_est * Decimal("1.2"))) if is_buy else max(spec.tick_size, ref_px + (atr_est * Decimal("1.2")))
            trail = align_price_to_tick(pos.symbol, raw_trail)
            better_tr = (trail > pos.stop_loss_price and trail < ref_px) if is_buy else (trail < pos.stop_loss_price and trail > ref_px)
            if better_tr:
                pos.stop_loss_price = trail
                pos.protection_stage = "TRAILING_PROFIT"

    def _check_valve(
        self,
        *,
        req_seq: int,
        root: str,
        contract_code: str,
        side: Side,
        contracts: int,
        entry_price: Decimal,
        stop_loss_price: Decimal,
        take_profit_price: Decimal,
        bid: Decimal,
        ask: Decimal,
        balance: Decimal,
        equity: Decimal,
        peak_equity: Decimal,
        used_margin: Decimal,
        open_positions: Sequence[OpenSimPosition],
        reason: str,
        now: datetime,
        valve_latencies_ms: list[float],
        peak_store: PeakEquityStore,
    ) -> tuple[bool, str]:
        drawdown_pct = compute_drawdown_pct(equity, peak_equity).quantize(_FOUR_DP, rounding=ROUND_HALF_UP)
        avail_margin = max(_ZERO, equity - used_margin)
        acct = TradovateAccountSnapshot(
            account_id="PHASE1-REPLAY",
            mode="DEMO",
            connected=True,
            connection_status="PAPER_OK",
            currency="USD",
            balance_usd=balance,
            equity_usd=equity,
            peak_equity_usd=peak_equity,
            drawdown_pct=drawdown_pct,
            used_margin_usd=used_margin,
            available_margin_usd=avail_margin,
            margin_level_pct=None,
            floating_pnl_usd=_q2(equity - balance),
            realized_pnl_usd=_q2(balance - self.config.starting_equity_usd),
            total_commissions_usd=Decimal("0.00"),
            open_position_count=len(open_positions),
            observed_at=now,
        )
        quote = TradovateQuote(symbol=root, bid=bid, ask=ask, observed_at=now)
        req_id = f"p1-{req_seq:08d}"
        proposal = _build_futures_valve_proposal(
            request_id=req_id,
            account_id="PHASE1-REPLAY",
            root_symbol=root,
            contract_code=contract_code,
            side=side.value,
            contracts=contracts,
            entry_price=entry_price,
            stop_loss_price=stop_loss_price,
            take_profit_price=take_profit_price,
            quote=quote,
            account=acct,
            positions_count=len(open_positions),
            reason=reason,
            now=now,
            seq=req_seq,
        )
        inv = [
            TradovatePosition(
                position_id=p.position_id,
                contract_code=p.contract_code,
                root_symbol=p.symbol,
                cas_symbol=CME_MICRO_FUTURES_SPECS[p.symbol].cas_symbol,
                side=p.side.value,
                contracts=p.contracts,
                entry_price=p.entry_price,
                current_price=entry_price if p.symbol == root else p.entry_price,
                stop_loss_price=p.stop_loss_price,
                take_profit_price=p.take_profit_price,
                used_margin_usd=p.margin_usd,
                floating_pnl_usd=Decimal("0.00"),
                commission_usd=p.commission_usd,
                opened_at=p.opened_at,
                updated_at=now,
            ).to_dict()
            for p in open_positions
        ]
        current_view = {
            "account_id": "PHASE1-REPLAY",
            "balance": decimal_text(balance),
            "equity": decimal_text(equity),
            "peak_equity": decimal_text(peak_equity),
            "available_margin": decimal_text(avail_margin),
            "position_inventory": inv,
            "symbol": root,
            "bid": decimal_text(bid),
            "ask": decimal_text(ask),
            "quote_observed_at": now.isoformat().replace("+00:00", "Z"),
        }
        policy = {
            "new_risk_permission": "ALLOWED",
            "management_permission": "ALLOWED",
            "max_entry_quantity": str(contracts),
            "max_drawdown_pct": decimal_text(self.config.max_drawdown_pct),
            "accounting_required": ["balance", "equity", "available_margin", "position_inventory"],
        }
        peak_store.observe_equity("PHASE1-REPLAY", current_equity=equity, opening_balance=self.config.starting_equity_usd, now=now)
        t0 = time.perf_counter_ns()
        decision = self.valve_gate.evaluate(proposal, current_view=current_view, policy=policy, now=now)
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        valve_latencies_ms.append(dt_ms)
        return decision.admitted, decision.bound_intent_digest

    def run(self, bars_by_symbol: Mapping[str, Sequence[M1Bar]]) -> dict[str, Any]:
        """Run complete deterministic replay over real/synthetic M1 bars across symbols."""
        if not bars_by_symbol:
            raise ContractError("bars_by_symbol cannot be empty")
        day_regimes: dict[str, dict[str, str]] = {}
        timeline: list[tuple[datetime, int, str, int, int, Decimal, M1Bar]] = []
        sym_order = {sym: idx for idx, sym in enumerate(sorted(bars_by_symbol))}
        for raw_sym, sym_bars in sorted(bars_by_symbol.items()):
            root = get_contract_spec(raw_sym).root
            sorted_bars = sorted(sym_bars, key=lambda b: b.timestamp_utc)
            day_regimes[root] = classify_utc_day_regimes(sorted_bars)
            for b_idx, bar in enumerate(sorted_bars):
                for t_idx, t_px in enumerate(_expand_bar_to_subticks(bar)):
                    timeline.append((bar.timestamp_utc + timedelta(seconds=t_idx * 10), sym_order[raw_sym], root, b_idx, t_idx, t_px, bar))
        timeline.sort(key=lambda item: (item[0], item[1], item[4]))

        cfg = self.config
        balance = cfg.starting_equity_usd
        peak_equity = cfg.starting_equity_usd
        max_dd_pct = _FOUR_DP * _ZERO
        peak_store = PeakEquityStore()
        peak_store.observe_equity("PHASE1-REPLAY", current_equity=balance, opening_balance=balance)

        runtimes: dict[str, _SymbolRuntime] = {get_contract_spec(s).root: _SymbolRuntime() for s in bars_by_symbol}
        last_mid_by_symbol: dict[str, Decimal] = {}
        open_positions: list[OpenSimPosition] = []
        closed_trades: list[ClosedSimTrade] = []
        counters: dict[str, int] = {
            "layer1_calls": 0,
            "breakout_kills": 0,
            "consecutive_loss_locks": 0,
            "daily_churn_caps_hit": 0,
            "daily_loss_fee_caps_hit": 0,
            "anti_cancellation_blocks": 0,
            "opposing_blocks": 0,
            "missed_passive_fills": 0,
            "warmup_blocks": 0,
            "warmup_resets": 0,
            "sizing_refusals": 0,
            "drawdown_brake_blocks": 0,
            "valve_checked": 0,
            "valve_admitted": 0,
            "valve_vetoed": 0,
            "valve_bypassed": 0,
            "opposing_violations": 0,
            "anti_cancellation_violations": 0,
        }
        valve_latencies_ms: list[float] = []
        req_seq = 0
        pos_seq = 0
        ord_seq = 0

        current_day: str | None = None
        daily_ai_calls = 0
        daily_scalps = 0
        daily_scalp_losses_and_fees = Decimal("0.00")
        day_start_equity = cfg.starting_equity_usd
        daily_scalp_paused = False
        drawdown_locked = False

        def _compute_equity() -> Decimal:
            fl = _ZERO
            for p in open_positions:
                px = last_mid_by_symbol.get(p.symbol, p.entry_price)
                delta = (px - p.entry_price) if p.side == Side.BUY else (p.entry_price - px)
                fl += delta * CME_MICRO_FUTURES_SPECS[p.symbol].point_value_usd * Decimal(p.contracts)
            return _q2(balance + fl)

        def _close_position(pos: OpenSimPosition, exit_px: Decimal, reason: str, closed_at: datetime) -> None:
            nonlocal balance, daily_scalp_losses_and_fees, daily_scalp_paused
            spec_p = CME_MICRO_FUTURES_SPECS[pos.symbol]
            delta = (exit_px - pos.entry_price) if pos.side == Side.BUY else (pos.entry_price - exit_px)
            gross = _q2(delta * spec_p.point_value_usd * Decimal(pos.contracts))
            comm = _q2(pos.commission_usd)
            net = _q2(gross - comm)
            balance = _q2(balance + net)
            day_utc = closed_at.strftime("%Y-%m-%d")
            d_reg = day_regimes.get(pos.symbol, {}).get(day_utc, DAY_REGIME_QUIET_CHOP)
            closed_trades.append(
                ClosedSimTrade(
                    position_id=pos.position_id,
                    symbol=pos.symbol,
                    day_utc=day_utc,
                    day_regime=d_reg,
                    strategy_kind=pos.strategy_kind,
                    side=pos.side.value,
                    contracts=pos.contracts,
                    entry_price=pos.entry_price,
                    exit_price=exit_px,
                    gross_pnl_usd=gross,
                    commission_usd=comm,
                    net_pnl_usd=net,
                    exit_reason=reason,
                    opened_at=pos.opened_at.isoformat().replace("+00:00", "Z"),
                    closed_at=closed_at.isoformat().replace("+00:00", "Z"),
                )
            )
            rt_sym = runtimes[pos.symbol]
            if pos.strategy_kind == "SCALP":
                if net < _ZERO:
                    daily_scalp_losses_and_fees = _q2(daily_scalp_losses_and_fees + abs(net))
                    rt_sym.consecutive_scalp_losses += 1
                    if rt_sym.consecutive_scalp_losses >= cfg.consecutive_loss_lock_count:
                        rt_sym.loss_cooldown_until = closed_at + timedelta(seconds=cfg.post_loss_cooldown_seconds)
                        counters["consecutive_loss_locks"] += 1
                else:
                    rt_sym.consecutive_scalp_losses = 0
                loss_cap_usd = _q2(day_start_equity * cfg.daily_scalp_loss_fee_cap_pct / _ONE_HUNDRED)
                if daily_scalp_losses_and_fees >= loss_cap_usd:
                    if not daily_scalp_paused:
                        counters["daily_loss_fee_caps_hit"] += 1
                    daily_scalp_paused = True

        for tick_ts, _s_ord, root, _b_idx, t_idx, mid_px, bar in timeline:
            day_key = tick_ts.strftime("%Y-%m-%d")
            if current_day != day_key:
                current_day = day_key
                daily_ai_calls = 0
                daily_scalps = 0
                daily_scalp_losses_and_fees = Decimal("0.00")
                day_start_equity = _compute_equity()
                daily_scalp_paused = False

            spec = CME_MICRO_FUTURES_SPECS[root]
            rt = runtimes[root]
            prev_tick = rt.last_tick_price
            rt.last_tick_price = mid_px
            last_mid_by_symbol[root] = mid_px

            if t_idx == 0:
                if rt.last_bar_ts is not None and (bar.timestamp_utc - rt.last_bar_ts).total_seconds() > 180:
                    rt.continuous_bars.clear()
                    rt.mid_history.clear()
                    rt.warmup_ticks = 0
                    rt.warmup_first_ts = None
                    rt.directive = None
                    rt.pending_limits.clear()
                    counters["warmup_resets"] += 1
                rt.last_bar_ts = bar.timestamp_utc
                rt.continuous_bars.append(bar)
                rt.mid_history.append(bar.close)
                if len(rt.mid_history) > 120:
                    rt.mid_history = rt.mid_history[-120:]

            if rt.warmup_first_ts is None:
                rt.warmup_first_ts = tick_ts
            rt.warmup_ticks += 1

            bar_atr_est = _compute_atr_from_bars(list(rt.continuous_bars), root, period=14)
            is_spike = bar.range_points >= (Decimal("4") * bar_atr_est) and len(rt.continuous_bars) >= cfg.min_warmup_m1_bars
            half_spread = (spec.tick_size * Decimal("2")) if is_spike else _ZERO
            bid = align_price_to_tick(root, mid_px - half_spread)
            ask = align_price_to_tick(root, mid_px + spec.tick_size + half_spread)
            spread = ask - bid
            slip_pts = self._compute_latency_slippage(root, bar.range_points)
            pen_needed = self._compute_passive_penetration_needed(root, bar.range_points)

            # 1. Open positions SL/TP/true-BE defense (conservative SL-first order)
            surviving: list[OpenSimPosition] = []
            for pos in open_positions:
                if pos.symbol != root:
                    surviving.append(pos)
                    continue
                is_buy = pos.side == Side.BUY
                ref_px = bid if is_buy else ask
                sl_hit = (ref_px <= pos.stop_loss_price) if is_buy else (ref_px >= pos.stop_loss_price)
                tp_hit = (ref_px >= pos.take_profit_price) if is_buy else (ref_px <= pos.take_profit_price)
                if sl_hit:
                    raw_exit = (pos.stop_loss_price - slip_pts) if is_buy else (pos.stop_loss_price + slip_pts)
                    _close_position(pos, max(spec.tick_size, align_price_to_tick(root, raw_exit)), "STOP_LOSS_FILLED", tick_ts)
                    continue
                if tp_hit:
                    _close_position(pos, pos.take_profit_price, "TAKE_PROFIT_FILLED", tick_ts)
                    continue
                self._advance_protection(pos, ref_px, bar_atr_est)
                surviving.append(pos)
            open_positions = surviving

            equity_now = _compute_equity()
            if equity_now > peak_equity:
                peak_equity = equity_now
            dd_now_pct = compute_drawdown_pct(equity_now, peak_equity) * _ONE_HUNDRED
            if dd_now_pct > max_dd_pct:
                max_dd_pct = _q4(dd_now_pct)
            if (dd_now_pct / _ONE_HUNDRED) >= cfg.max_drawdown_pct:
                drawdown_locked = True

            # 2. Shield #2: <50ms Breakout Kill-Switch
            active_dir = rt.directive
            if active_dir is not None and active_dir.regime == REGIME_CHOP_RANGE:
                bar_close_out = (t_idx == 5) and (bar.close > active_dir.range_high or bar.close < active_dir.range_low)
                killed, _kr = check_breakout_kill_switch(
                    range_low=active_dir.range_low,
                    range_high=active_dir.range_high,
                    atr=active_dir.atr,
                    tick_price=mid_px,
                    prev_tick_price=prev_tick,
                    bar_close_outside=bar_close_out,
                    breakout_atr_mult=cfg.breakout_kill_atr_mult,
                    burst_atr_mult=cfg.burst_kill_atr_mult,
                )
                if killed:
                    counters["breakout_kills"] += 1
                    rt.pending_limits.clear()
                    rt.breakout_lockout_until = tick_ts + timedelta(seconds=cfg.breakout_lockout_seconds)
                    rt.directive = Layer1Directive(
                        root, REGIME_FLAT_STAND_DOWN, None, active_dir.range_low, active_dir.range_high, active_dir.atr, active_dir.efficiency_ratio, tick_ts, tick_ts, "LAYER2_BREAKOUT_KILL_DOWNGRADE"
                    )
                    rt.force_l1_wakeup = True

            # 3. Pending passive limit fills (delayed by cfg.fill_delay_ms)
            next_pending: list[PendingLimitOrder] = []
            for p_ord in rt.pending_limits:
                if tick_ts >= p_ord.expires_at:
                    counters["missed_passive_fills"] += 1
                    continue
                if tick_ts < p_ord.active_at:
                    next_pending.append(p_ord)
                    continue
                touched = (ask <= (p_ord.limit_price - pen_needed)) if p_ord.side == Side.BUY else (bid >= (p_ord.limit_price + pen_needed))
                if not touched:
                    next_pending.append(p_ord)
                    continue
                if daily_scalp_paused or daily_scalps >= cfg.max_daily_scalps or len(open_positions) >= (cfg.max_open_positions or 4):
                    continue
                if any(op.symbol == root and op.side != p_ord.side for op in open_positions):
                    counters["opposing_blocks"] += 1
                    continue
                open_meta = [{"symbol": op.symbol, "side": op.side.value} for op in open_positions]
                corr_ok, _ = evaluate_cross_market_offset_guard(
                    candidate_symbol=root,
                    candidate_side=p_ord.side,
                    open_positions=open_meta,
                    price_history={s: r.mid_history for s, r in runtimes.items()},
                    is_pyramid_add=False,
                )
                if not corr_ok:
                    counters["anti_cancellation_blocks"] += 1
                    continue
                pos_seq += 1
                daily_scalps += 1
                used_m = spec.default_intraday_margin_usd * Decimal(p_ord.contracts)
                fm = resolve_front_month_contract(root, as_of_utc=tick_ts)
                open_positions.append(
                    OpenSimPosition(
                        position_id=f"pos-{pos_seq:08d}",
                        symbol=root,
                        contract_code=fm.contract_code,
                        side=p_ord.side,
                        strategy_kind=p_ord.strategy_kind,
                        contracts=p_ord.contracts,
                        entry_price=p_ord.limit_price,
                        stop_loss_price=p_ord.stop_loss_price,
                        take_profit_price=p_ord.take_profit_price,
                        initial_stop_distance_points=p_ord.stop_distance_points,
                        commission_usd=p_ord.commission_usd,
                        margin_usd=used_m,
                        opened_at=tick_ts,
                        range_low=p_ord.range_low,
                        range_high=p_ord.range_high,
                        peak_favorable_price=p_ord.limit_price,
                    )
                )
            rt.pending_limits = next_pending

            for idx_a in range(len(open_positions)):
                for idx_b in range(idx_a + 1, len(open_positions)):
                    if open_positions[idx_a].symbol == open_positions[idx_b].symbol and open_positions[idx_a].side != open_positions[idx_b].side:
                        counters["opposing_violations"] += 1

            # 4. Warmup & Layer 1 evaluation
            warm_span = 0.0 if rt.warmup_first_ts is None else (tick_ts - rt.warmup_first_ts).total_seconds()
            warm_ok = len(rt.continuous_bars) >= cfg.min_warmup_m1_bars and rt.warmup_ticks >= cfg.min_warmup_ticks and warm_span >= cfg.min_warmup_span_seconds
            in_maint = _is_us_maintenance_deadzone(tick_ts)

            need_l1 = (
                rt.last_l1_eval_at is None
                or (tick_ts - rt.last_l1_eval_at).total_seconds() >= cfg.layer1_cadence_seconds
                or (rt.force_l1_wakeup and (rt.last_l1_eval_at is None or (tick_ts - rt.last_l1_eval_at).total_seconds() >= 15))
            )
            if t_idx == 0 and need_l1 and warm_ok:
                chop_locked = (
                    (rt.breakout_lockout_until is not None and tick_ts < rt.breakout_lockout_until)
                    or (rt.loss_cooldown_until is not None and tick_ts < rt.loss_cooldown_until)
                    or daily_scalp_paused
                    or (daily_scalps >= cfg.max_daily_scalps)
                )
                l1_dir, used_call = evaluate_layer1_directive(
                    symbol=root,
                    recent_bars=list(rt.continuous_bars),
                    spread=spread,
                    now=tick_ts,
                    config=cfg,
                    in_maintenance_window=in_maint,
                    chop_locked_out=chop_locked,
                    calls_used_today=daily_ai_calls,
                )
                rt.directive = l1_dir
                rt.last_l1_eval_at = tick_ts
                rt.force_l1_wakeup = False
                if used_call:
                    daily_ai_calls += 1
                    counters["layer1_calls"] += 1

            if drawdown_locked:
                continue
            if not warm_ok or in_maint:
                if t_idx == 0 and len(rt.continuous_bars) > 0 and not warm_ok:
                    counters["warmup_blocks"] += 1
                continue
            if rt.directive is None or not rt.directive.is_valid_at(tick_ts) or len(open_positions) >= (cfg.max_open_positions or 4):
                continue

            directive = rt.directive
            used_margin_total = sum((p.margin_usd for p in open_positions), _ZERO)

            # 5A. Trend-Following + House-Money Pyramiding
            if directive.regime in (REGIME_STRONG_TREND, REGIME_TREND_IGNITION) and directive.bias is not None:
                same_sym = [p for p in open_positions if p.symbol == root]
                if any(p.side != directive.bias for p in same_sym):
                    counters["opposing_blocks"] += 1
                    continue
                if len(same_sym) >= cfg.max_split_legs_k or (same_sym and not all(p.protection_stage in ("BREAKEVEN_LOCKED", "TRAILING_PROFIT") for p in same_sym)):
                    continue
                ema9 = compute_ema([b.close for b in list(rt.continuous_bars)[-20:]], 9) or mid_px
                is_buy_dir = directive.bias == Side.BUY
                trig_ok = ((mid_px >= ema9) if not same_sym else (mid_px > same_sym[-1].entry_price)) if is_buy_dir else ((mid_px <= ema9) if not same_sym else (mid_px < same_sym[-1].entry_price))
                if not trig_ok or t_idx not in (1, 3):
                    continue

                mkt_cost = compute_all_in_cost_profile(root, fee_mode=cfg.fee_mode, passive_limit=False, min_tp_cost_multiple=cfg.min_tp_cost_multiple)
                sl_pts = ceil_to_tick(root, max(spec.tick_size * Decimal("6"), directive.atr * Decimal("1.5"), mkt_cost.min_tp_points / Decimal("2")))
                tp_pts = ceil_to_tick(root, sl_pts * Decimal("2"))
                geom_ok, _ = validate_scalp_geometry(root, sl_pts, tp_pts, fee_mode=cfg.fee_mode, passive_limit=False, min_tp_cost_multiple=cfg.min_tp_cost_multiple)
                if not geom_ok:
                    continue

                open_meta = [{"symbol": op.symbol, "side": op.side.value} for op in open_positions]
                corr_ok, _ = evaluate_cross_market_offset_guard(
                    candidate_symbol=root,
                    candidate_side=directive.bias,
                    open_positions=open_meta,
                    price_history={s: r.mid_history for s, r in runtimes.items()},
                    is_pyramid_add=len(same_sym) > 0,
                )
                if not corr_ok:
                    counters["anti_cancellation_blocks"] += 1
                    continue

                leg_risk = compute_burst_leg_risk_pct(cfg.total_risk_pct, cfg.max_split_legs_k if cfg.engine_mode == "hybrid" else 1)
                try:
                    sizing = size_micro_futures_order(
                        symbol_or_root=root,
                        equity_usd=equity_now,
                        stop_distance_points=sl_pts,
                        risk_pct=leg_risk,
                        existing_used_margin_usd=used_margin_total,
                        max_contracts=cfg.max_contracts_per_order,
                    )
                except MicroFuturesSizingRefusalError:
                    counters["sizing_refusals"] += 1
                    continue

                entry_px = align_price_to_tick(root, (ask + slip_pts) if is_buy_dir else max(spec.tick_size, bid - slip_pts))
                sl_px = align_price_to_tick(root, (entry_px - sl_pts) if is_buy_dir else (entry_px + sl_pts))
                tp_px = align_price_to_tick(root, (entry_px + tp_pts) if is_buy_dir else max(spec.tick_size, entry_px - tp_pts))
                if sl_px <= _ZERO or tp_px <= _ZERO:
                    continue

                req_seq += 1
                fm = resolve_front_month_contract(root, as_of_utc=tick_ts)
                counters["valve_checked"] += 1
                admitted, _ = self._check_valve(
                    req_seq=req_seq, root=root, contract_code=fm.contract_code, side=directive.bias,
                    contracts=sizing.contracts, entry_price=entry_px, stop_loss_price=sl_px, take_profit_price=tp_px,
                    bid=bid, ask=ask, balance=balance, equity=equity_now, peak_equity=peak_equity,
                    used_margin=used_margin_total, open_positions=open_positions,
                    reason=f"PHASE1_{directive.regime}_{directive.bias.value}", now=tick_ts,
                    valve_latencies_ms=valve_latencies_ms, peak_store=peak_store,
                )
                if not admitted:
                    counters["valve_vetoed"] += 1
                    continue
                counters["valve_admitted"] += 1
                pos_seq += 1
                open_positions.append(
                    OpenSimPosition(
                        position_id=f"pos-{pos_seq:08d}", symbol=root, contract_code=fm.contract_code, side=directive.bias,
                        strategy_kind="TREND", contracts=sizing.contracts, entry_price=entry_px, stop_loss_price=sl_px,
                        take_profit_price=tp_px, initial_stop_distance_points=sl_pts,
                        commission_usd=_q2(mkt_cost.commission_usd * Decimal(sizing.contracts)),
                        margin_usd=sizing.required_margin_usd, opened_at=tick_ts, peak_favorable_price=entry_px,
                    )
                )
                continue

            # 5B. Sideways Sequential CHOP_RANGE Passive Limit Scalper (Hybrid only)
            if cfg.engine_mode != "hybrid" or directive.regime != REGIME_CHOP_RANGE:
                continue
            if daily_scalp_paused or daily_scalps >= cfg.max_daily_scalps:
                if daily_scalps >= cfg.max_daily_scalps:
                    counters["daily_churn_caps_hit"] += 1
                continue
            if (rt.breakout_lockout_until is not None and tick_ts < rt.breakout_lockout_until) or (rt.loss_cooldown_until is not None and tick_ts < rt.loss_cooldown_until):
                continue
            if any(p.symbol == root for p in open_positions) or rt.pending_limits:
                continue

            box_w = directive.range_high - directive.range_low
            pass_cost = compute_all_in_cost_profile(
                root, fee_mode=cfg.fee_mode, passive_limit=True, min_box_cost_multiple=cfg.min_box_cost_multiple, min_tp_cost_multiple=cfg.min_tp_cost_multiple
            )
            if box_w < pass_cost.min_box_width_points:
                continue

            if mid_px <= directive.range_low + (box_w * Decimal("0.20")):
                cand_side = Side.BUY
                limit_px = align_price_to_tick(root, directive.range_low + (box_w * Decimal("0.12")))
                target_px = align_price_to_tick(root, directive.range_high - (box_w * Decimal("0.15")))
                tp_pts = target_px - limit_px
                sl_pts = min(tp_pts, ceil_to_tick(root, max(spec.tick_size * Decimal("2"), directive.atr * Decimal("0.35")) + (limit_px - directive.range_low)))
                sl_px = align_price_to_tick(root, limit_px - sl_pts)
            elif mid_px >= directive.range_high - (box_w * Decimal("0.20")):
                cand_side = Side.SELL
                limit_px = align_price_to_tick(root, directive.range_high - (box_w * Decimal("0.12")))
                target_px = align_price_to_tick(root, directive.range_low + (box_w * Decimal("0.15")))
                tp_pts = limit_px - target_px
                sl_pts = min(tp_pts, ceil_to_tick(root, max(spec.tick_size * Decimal("2"), directive.atr * Decimal("0.35")) + (directive.range_high - limit_px)))
                sl_px = align_price_to_tick(root, limit_px + sl_pts)
            else:
                continue

            if sl_pts <= _ZERO or tp_pts <= _ZERO or sl_px <= _ZERO or target_px <= _ZERO:
                continue
            geom_ok, _ = validate_scalp_geometry(root, sl_pts, tp_pts, fee_mode=cfg.fee_mode, passive_limit=True, min_tp_cost_multiple=cfg.min_tp_cost_multiple)
            if not geom_ok:
                continue

            open_meta = [{"symbol": op.symbol, "side": op.side.value} for op in open_positions]
            corr_ok, _ = evaluate_cross_market_offset_guard(
                candidate_symbol=root,
                candidate_side=cand_side,
                open_positions=open_meta,
                price_history={s: r.mid_history for s, r in runtimes.items()},
                is_pyramid_add=False,
            )
            if not corr_ok:
                counters["anti_cancellation_blocks"] += 1
                continue

            leg_risk = compute_burst_leg_risk_pct(cfg.total_risk_pct, cfg.max_split_legs_k)
            try:
                sizing = size_micro_futures_order(
                    symbol_or_root=root,
                    equity_usd=equity_now,
                    stop_distance_points=sl_pts,
                    risk_pct=leg_risk,
                    existing_used_margin_usd=used_margin_total,
                    max_contracts=cfg.max_contracts_per_order,
                )
            except MicroFuturesSizingRefusalError:
                counters["sizing_refusals"] += 1
                continue

            req_seq += 1
            fm = resolve_front_month_contract(root, as_of_utc=tick_ts)
            counters["valve_checked"] += 1
            admitted, dec_digest = self._check_valve(
                req_seq=req_seq, root=root, contract_code=fm.contract_code, side=cand_side,
                contracts=sizing.contracts, entry_price=limit_px, stop_loss_price=sl_px, take_profit_price=target_px,
                bid=bid, ask=ask, balance=balance, equity=equity_now, peak_equity=peak_equity,
                used_margin=used_margin_total, open_positions=open_positions,
                reason=f"PHASE1_CHOP_SCALP_{cand_side.value}", now=tick_ts,
                valve_latencies_ms=valve_latencies_ms, peak_store=peak_store,
            )
            if not admitted:
                counters["valve_vetoed"] += 1
                continue
            counters["valve_admitted"] += 1
            ord_seq += 1
            rt.pending_limits.append(
                PendingLimitOrder(
                    order_id=f"lim-{ord_seq:08d}", symbol=root, side=cand_side, strategy_kind="SCALP",
                    limit_price=limit_px, stop_loss_price=sl_px, take_profit_price=target_px,
                    stop_distance_points=sl_pts, take_profit_points=tp_pts, contracts=sizing.contracts,
                    commission_usd=_q2(pass_cost.commission_usd * Decimal(sizing.contracts)),
                    risk_pct_used=leg_risk, submitted_at=tick_ts,
                    active_at=tick_ts + timedelta(milliseconds=cfg.fill_delay_ms),
                    expires_at=tick_ts + timedelta(seconds=120),
                    range_low=directive.range_low, range_high=directive.range_high,
                    valve_decision_digest=dec_digest,
                )
            )

        if timeline:
            end_ts = timeline[-1][0]
            for pos in open_positions:
                _close_position(pos, last_mid_by_symbol.get(pos.symbol, pos.entry_price), "END_OF_REPLAY_FLATTEN", end_ts)
            open_positions.clear()

        final_equity = balance
        if final_equity > peak_equity:
            peak_equity = final_equity
        final_dd = compute_drawdown_pct(final_equity, peak_equity) * _ONE_HUNDRED
        if final_dd > max_dd_pct:
            max_dd_pct = _q4(final_dd)

        return self._summarize(
            closed_trades=closed_trades,
            final_equity=final_equity,
            max_dd_pct=max_dd_pct,
            counters=counters,
            valve_latencies_ms=valve_latencies_ms,
            day_regimes=day_regimes,
            drawdown_locked=drawdown_locked,
        )

    def _summarize(
        self,
        *,
        closed_trades: Sequence[ClosedSimTrade],
        final_equity: Decimal,
        max_dd_pct: Decimal,
        counters: Mapping[str, int],
        valve_latencies_ms: Sequence[float],
        day_regimes: Mapping[str, Mapping[str, str]],
        drawdown_locked: bool,
    ) -> dict[str, Any]:
        def _bucket_stats(trades: Sequence[ClosedSimTrade]) -> dict[str, Any]:
            gross_win = sum((t.net_pnl_usd for t in trades if t.net_pnl_usd > _ZERO), Decimal("0.00"))
            gross_loss = sum((abs(t.net_pnl_usd) for t in trades if t.net_pnl_usd < _ZERO), Decimal("0.00"))
            fees = sum((t.commission_usd for t in trades), Decimal("0.00"))
            net_total = sum((t.net_pnl_usd for t in trades), Decimal("0.00"))
            wins = sum(1 for t in trades if t.net_pnl_usd > _ZERO)
            losses = sum(1 for t in trades if t.net_pnl_usd < _ZERO)
            n = len(trades)
            wr = _q2((Decimal(wins) * _ONE_HUNDRED) / Decimal(n)) if n > 0 else Decimal("0.00")
            if gross_loss > _ZERO:
                pf = _q4(gross_win / gross_loss)
            elif gross_win > _ZERO:
                pf = Decimal("99.9999")
            else:
                pf = Decimal("0.0000")
            return {
                "closed_trades": n,
                "wins": wins,
                "losses": losses,
                "win_rate_pct": decimal_text(wr),
                "net_win_usd": decimal_text(_q2(gross_win)),
                "net_loss_usd": decimal_text(_q2(gross_loss)),
                "total_fees_usd": decimal_text(_q2(fees)),
                "net_pnl_usd": decimal_text(_q2(net_total)),
                "net_profit_factor": decimal_text(pf),
            }

        overall = _bucket_stats(closed_trades)
        sorted_lat = sorted(valve_latencies_ms)
        if sorted_lat:
            p50 = sorted_lat[len(sorted_lat) // 2]
            p99 = sorted_lat[min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.99))]
            lat_max = sorted_lat[-1]
        else:
            p50 = 0.0
            p99 = 0.0
            lat_max = 0.0

        cfg = self.config
        return {
            "config": {
                "starting_equity_usd": decimal_text(cfg.starting_equity_usd),
                "total_risk_pct": decimal_text(cfg.total_risk_pct),
                "max_split_legs_k": cfg.max_split_legs_k,
                "max_open_positions": cfg.max_open_positions,
                "fill_delay_ms": cfg.fill_delay_ms,
                "fee_mode": cfg.fee_mode,
                "engine_mode": cfg.engine_mode,
                "max_daily_scalps": cfg.max_daily_scalps,
            },
            "summary": {
                **overall,
                "ending_equity_usd": decimal_text(_q2(final_equity)),
                "max_drawdown_pct": decimal_text(_q4(max_dd_pct)),
                "drawdown_locked": drawdown_locked,
            },
            "strategy_breakdown": {
                "scalp": _bucket_stats([t for t in closed_trades if t.strategy_kind == "SCALP"]),
                "trend": _bucket_stats([t for t in closed_trades if t.strategy_kind == "TREND"]),
            },
            "by_symbol": {root: _bucket_stats([t for t in closed_trades if t.symbol == root]) for root in sorted(day_regimes)},
            "by_day_regime": {
                reg: _bucket_stats([t for t in closed_trades if t.day_regime == reg])
                for reg in (DAY_REGIME_QUIET_CHOP, DAY_REGIME_CLEAN_TREND, DAY_REGIME_VIOLENT_BREAKOUT)
            },
            "day_regime_calendar": {k: dict(v) for k, v in day_regimes.items()},
            "shields_and_gates": {
                **counters,
                "valve_p50_ms": decimal_text(Decimal(f"{p50:.6f}")),
                "valve_p99_ms": decimal_text(Decimal(f"{p99:.6f}")),
                "valve_max_ms": decimal_text(Decimal(f"{lat_max:.6f}")),
                "valve_threshold": decimal_text(Decimal(str(self.valve_gate.controller.threshold))),
                "valve_param_count": self.valve_gate.controller.parameter_count,
                "valve_weights_sha256": self.valve_gate.weights_sha256,
            },
        }


def judge_phase1_run(run_report: Mapping[str, Any], *, config: ReplayConfig | None = None) -> tuple[str, list[str]]:
    """Apply fail-closed Phase 1 promotion gate: Net PF >= 1.25 AND Max DD <= 6.00% at 500ms."""
    cfg = config if config is not None else ReplayConfig()
    summary = run_report.get("summary") or {}
    shields = run_report.get("shields_and_gates") or {}
    reasons: list[str] = []

    n_trades = int(summary.get("closed_trades", 0))
    net_pf = Decimal(str(summary.get("net_profit_factor", "0.0000")))
    max_dd = Decimal(str(summary.get("max_drawdown_pct", "100.0000")))
    p99_ms = Decimal(str(shields.get("valve_p99_ms", "999.0")))
    bypassed = int(shields.get("valve_bypassed", 1))
    opp_viol = int(shields.get("opposing_violations", 1))
    corr_viol = int(shields.get("anti_cancellation_violations", 1))

    if n_trades < cfg.phase1_min_closed_trades:
        reasons.append(f"INSUFFICIENT_TRADES:{n_trades}<{cfg.phase1_min_closed_trades}")
    if net_pf < cfg.phase1_pass_min_pf:
        reasons.append(f"NET_PF_BELOW_1.25:{decimal_text(net_pf)}")
    if max_dd > cfg.phase1_pass_max_dd_pct:
        reasons.append(f"MAX_DD_ABOVE_6.00PCT:{decimal_text(max_dd)}")
    p50_ms = Decimal(str(shields.get("valve_p50_ms", "0.0")))
    if p50_ms >= Decimal("5.0") or p99_ms < Decimal("0.0"):
        reasons.append(f"VALVE_MEDIAN_STALL_GE_5MS:{decimal_text(p50_ms)}")
    if bypassed != 0:
        reasons.append(f"VALVE_BYPASSED:{bypassed}")
    if opp_viol != 0:
        reasons.append(f"OPPOSING_VIOLATIONS:{opp_viol}")
    if corr_viol != 0:
        reasons.append(f"ANTI_CANCELLATION_VIOLATIONS:{corr_viol}")

    if reasons:
        return VERDICT_FAIL_STOP_AND_ARCHIVE, reasons
    return VERDICT_PASS_TO_PHASE_2, ["ALL_PHASE1_HARD_GATES_PASSED"]


def evaluate_phase1_matrix(
    dataset_doc: Mapping[str, Any],
    *,
    starting_equity_usd: Decimal = Decimal("5000.00"),
    valve_gate: ForexMetaValveGate | None = None,
) -> dict[str, Any]:
    """Execute full Phase 1 offline replay matrix across 250/500/900ms, stressed/standard fees, Hybrid vs Swing-Only."""
    bars_by_symbol, dataset_sha = dataset_from_wire_dict(dataset_doc)
    gate = valve_gate if valve_gate is not None else load_default_forex_valve_gate()

    matrix_specs = [
        ("hybrid_250ms_stressed", 250, "stressed", "hybrid"),
        ("hybrid_500ms_stressed", 500, "stressed", "hybrid"),
        ("hybrid_900ms_stressed", 900, "stressed", "hybrid"),
        ("swing_only_250ms_stressed", 250, "stressed", "swing_only"),
        ("swing_only_500ms_stressed", 500, "stressed", "swing_only"),
        ("swing_only_900ms_stressed", 900, "stressed", "swing_only"),
        ("hybrid_500ms_standard", 500, "standard", "hybrid"),
    ]
    runs: dict[str, dict[str, Any]] = {}
    for label, delay_ms, fee_mode, engine_mode in matrix_specs:
        cfg = ReplayConfig(
            starting_equity_usd=starting_equity_usd,
            fill_delay_ms=delay_ms,
            fee_mode=fee_mode,
            engine_mode=engine_mode,
        )
        runs[label] = HybridMicroScalpBacktester(cfg, valve_gate=gate).run(bars_by_symbol)

    primary = runs["hybrid_500ms_stressed"]
    swing_500 = runs["swing_only_500ms_stressed"]
    verdict, reasons = judge_phase1_run(primary)
    beats_swing = Decimal(primary["summary"]["net_pnl_usd"]) > Decimal(swing_500["summary"]["net_pnl_usd"])

    out: dict[str, Any] = {
        "schema": "cas-forex-phase1-replay-report-v1",
        "dataset_schema": str(dataset_doc.get("schema", "")),
        "dataset_source": str(dataset_doc.get("source", "")),
        "dataset_sha256": dataset_sha,
        "bar_counts": {k: len(v) for k, v in sorted(bars_by_symbol.items())},
        "primary_gate_scenario": "hybrid_500ms_stressed",
        "phase1_verdict": verdict,
        "phase1_reasons": reasons,
        "beats_swing_only_at_500ms": beats_swing,
        "runs": runs,
    }
    out["report_sha256"] = sha256(canonical_bytes(out)).hexdigest()
    return out
