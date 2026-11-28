"""Update 49: Self-Learning AI Strategy Lab, Two-Way Field Notebook, CUSUM Lifecycle & Shadow Synthesizer.

Pure-stdlib implementation (`decimal.Decimal` prec=40, SQLite WAL + `?mode=ro` read path,
pure deterministic Decimal arithmetic and zero SQLite I/O on the 50ms stop-protection path).
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR, ROUND_HALF_UP, localcontext
from enum import StrEnum
from hashlib import sha256
import json
import logging
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ContractError, Side, canonical_bytes, decimal_text
from cas_forex_revamp.contracts.primitives import utc_time
from cas_forex_revamp.venue.live_market_stream import EXPANDED_MARKETS, INDEX_INSTRUMENTS

logger = logging.getLogger(__name__)

AI_STRATEGY_LAB_SCHEMA = "cas-forex.ai-strategy-lab/1"
GENESIS_SHA256 = "0" * 64
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")

_PREC = 40
_ZERO = Decimal("0")
_ONE = Decimal("1")
_TWO = Decimal("2")
_HALF = Decimal("0.5")
_Q4 = Decimal("0.0001")
_Q2 = Decimal("0.01")

LAMBDA_DECAY = Decimal("0.94")
SIGMA2_FLOOR = Decimal("0.25")
PRIOR_SIGMA2 = Decimal("2.25")
PF_EPS = Decimal("0.50")
MAE_EPS = Decimal("0.05")
MFE_CAPTURE_MIN = Decimal("0.25")

CUSUM_REF_K = Decimal("-0.05")
CUSUM_GAIN_CAP = Decimal("2.50")
CUSUM_WARN = Decimal("2.00")
CUSUM_QUARANTINE = Decimal("3.50")
CUSUM_RECOVERY_FLOOR = Decimal("1.00")
CUSUM_DECOMM = Decimal("7.50")
PH_TOLERANCE = Decimal("0.10")
PH_ALARM = Decimal("4.00")
CATASTROPHIC_R = Decimal("-2.50")

SHADOW_MIN_TRADES = 30
SHADOW_MIN_SESSIONS = 2
SHADOW_Z_LCB = Decimal("1.2816")
SHADOW_TAIL_C = Decimal("1.00")
SHADOW_MIN_PF = Decimal("1.25")
SHADOW_MIN_MFE_CAP = Decimal("0.35")
SHADOW_MIN_ERATIO = Decimal("1.15")
SHADOW_MAX_DD_R = Decimal("8.00")
QUARANTINE_MIN_RECOVERY = 10
QUARANTINE_MAX_TRADES = 25
MAX_REENTRIES = 2

M_STRAT = Decimal("6.0")
M_REGIME = Decimal("5.0")
M_SESSION = Decimal("4.0")
KAPPA_UCB = Decimal("0.85")
KAPPA_LCB = Decimal("1.00")
KELLY_FULL_REF = Decimal("0.15")
RISK_MIN_MULT = Decimal("0.35")
RISK_MAX_MULT = Decimal("1.00")

OMEGA_VAULT = Decimal("0.40")
KAPPA_VAULT = Decimal("1.00")
GAMMA_DD = Decimal("25.0")
DD_FREE = Decimal("0.02")
GAMMA_REC = Decimal("0.50")
LOGISTIC_SCALE = Decimal("0.5513288954")

MAX_FIELD_NOTES_RETENTION = 500
MAX_SHADOW_TRADES_RETENTION = 1500
MAX_SHADOW_STRATEGIES = 16


class StrategyArchetype(StrEnum):
    TREND_FOLLOW = "TREND_FOLLOW"
    MEAN_REVERT = "MEAN_REVERT"
    VOL_BREAKOUT = "VOL_BREAKOUT"


class ArmStatus(StrEnum):
    INCUBATING_SHADOW = "SHADOW_INCUBATING"
    ACTIVE = "ACTIVE"
    QUARANTINED_SHADOW = "QUARANTINED"
    DECOMMISSIONED = "DECOMMISSIONED"


BETA_PRIORS: dict[StrategyArchetype, tuple[Decimal, Decimal]] = {
    StrategyArchetype.TREND_FOLLOW: (Decimal("4.0"), Decimal("6.0")),
    StrategyArchetype.MEAN_REVERT: (Decimal("5.8"), Decimal("4.2")),
    StrategyArchetype.VOL_BREAKOUT: (Decimal("3.5"), Decimal("6.5")),
}

_SL_CLAMPS: dict[str, tuple[Decimal, Decimal]] = {
    "NAS100": (Decimal("18.00"), Decimal("45.00")),
    "US30": (Decimal("35.00"), Decimal("90.00")),
    "SPX500": (Decimal("8.00"), Decimal("20.00")),
    "XAUUSD": (Decimal("4.00"), Decimal("14.00")),
}


def _d(val: Decimal | int | str, name: str = "value") -> Decimal:
    if isinstance(val, (bool, float)) or val is None:
        raise ContractError(f"{name} must be exact Decimal/int/str, not {type(val).__name__}")
    try:
        dec = val if isinstance(val, Decimal) else Decimal(str(val).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ContractError(f"{name} invalid Decimal: {val!r}") from exc
    if not dec.is_finite():
        raise ContractError(f"{name} must be finite")
    return dec


def _clamp(val: Decimal, lo: Decimal, hi: Decimal) -> Decimal:
    return lo if val < lo else (hi if val > hi else val)


def _q2_str(val: Decimal) -> str:
    return str(val.quantize(_Q2, rounding=ROUND_HALF_UP))


def _q4_str(val: Decimal) -> str:
    return str(val.quantize(_Q4, rounding=ROUND_HALF_UP))


def _ascii_clean(text: str, *, max_len: int) -> str:
    cleaned = "".join(ch if 32 <= ord(ch) <= 126 else " " for ch in str(text or ""))
    collapsed = " ".join(cleaned.split()).strip()
    if not collapsed:
        return "-"
    return collapsed[:max_len]


def _iso_utc(ts: datetime) -> str:
    u = utc_time(ts, "ts")
    return u.strftime("%Y-%m-%dT%H:%M:%SZ")


def _nth_weekday_of_month(year: int, month: int, weekday: int, n: int) -> date:
    first = date(year, month, 1)
    offset = (weekday - first.weekday()) % 7
    return first + timedelta(days=offset + 7 * (n - 1))


def _last_weekday_of_month(year: int, month: int, weekday: int) -> date:
    nxt = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    last = nxt - timedelta(days=1)
    offset = (last.weekday() - weekday) % 7
    return last - timedelta(days=offset)


def _easter_sunday(year: int) -> date:
    """Anonymous Gregorian Gauss-Meeus algorithm for Good Friday holiday detection."""
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l_val = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l_val) // 451
    month = (h + l_val - 7 * m + 114) // 31
    day = ((h + l_val - 7 * m + 114) % 31) + 1
    return date(year, month, day)


def us_eastern_datetime(ts: datetime) -> tuple[datetime, bool]:
    """Pure-stdlib deterministic America/New_York converter (returns aware ET datetime, is_dst)."""
    u = utc_time(ts, "ts")
    dst_start_day = _nth_weekday_of_month(u.year, 3, 6, 2)  # 2nd Sunday March 07:00 UTC
    dst_end_day = _nth_weekday_of_month(u.year, 11, 6, 1)   # 1st Sunday November 06:00 UTC
    dst_start_utc = datetime(u.year, 3, dst_start_day.day, 7, 0, 0, tzinfo=timezone.utc)
    dst_end_utc = datetime(u.year, 11, dst_end_day.day, 6, 0, 0, tzinfo=timezone.utc)
    is_dst = dst_start_utc <= u < dst_end_utc
    offset = timezone(timedelta(hours=-4 if is_dst else -5))
    return u.astimezone(offset), is_dst


def us_pacific_text(ts: datetime) -> str:
    u = utc_time(ts, "ts")
    _, is_dst = us_eastern_datetime(u)
    offset = timezone(timedelta(hours=-7 if is_dst else -8))
    label = "PDT" if is_dst else "PST"
    return f"{u.astimezone(offset).strftime('%Y-%m-%d %H:%M:%S')} {label}"


def uk_london_datetime(ts: datetime) -> datetime:
    """Pure-stdlib deterministic Europe/London converter."""
    u = utc_time(ts, "ts")
    bst_start_day = _last_weekday_of_month(u.year, 3, 6)
    bst_end_day = _last_weekday_of_month(u.year, 10, 6)
    bst_start_utc = datetime(u.year, 3, bst_start_day.day, 1, 0, 0, tzinfo=timezone.utc)
    bst_end_utc = datetime(u.year, 10, bst_end_day.day, 1, 0, 0, tzinfo=timezone.utc)
    is_bst = bst_start_utc <= u < bst_end_utc
    return u.astimezone(timezone(timedelta(hours=1 if is_bst else 0)))


def is_us_equity_pre_close_chop_ny(ts: datetime) -> bool:
    """DST-accurate 15:30-15:59 America/New_York Wall Street MOC pre-close chop filter."""
    et_dt, _ = us_eastern_datetime(ts)
    return et_dt.weekday() < 5 and et_dt.hour == 15 and et_dt.minute >= 30


def _observed_fixed_holiday(year: int, month: int, day: int) -> date:
    raw = date(year, month, day)
    if raw.weekday() == 5:
        return raw - timedelta(days=1)
    if raw.weekday() == 6:
        return raw + timedelta(days=1)
    return raw


def us_market_holidays_for_year(year: int) -> dict[date, str]:
    holidays: dict[date, str] = {
        _observed_fixed_holiday(year, 1, 1): "US_NEW_YEARS_DAY",
        _nth_weekday_of_month(year, 1, 0, 3): "US_MLK_DAY",
        _nth_weekday_of_month(year, 2, 0, 3): "US_PRESIDENTS_DAY",
        _easter_sunday(year) - timedelta(days=2): "GOOD_FRIDAY",
        _last_weekday_of_month(year, 5, 0): "US_MEMORIAL_DAY",
        _observed_fixed_holiday(year, 6, 19): "US_JUNETEENTH",
        _observed_fixed_holiday(year, 7, 4): "US_INDEPENDENCE_DAY",
        _nth_weekday_of_month(year, 9, 0, 1): "US_LABOR_DAY",
        _nth_weekday_of_month(year, 11, 3, 4): "US_THANKSGIVING_DAY",
        _observed_fixed_holiday(year, 12, 25): "US_CHRISTMAS_DAY",
    }
    return holidays


def instrument_class_for(symbol: str) -> str:
    sym = str(symbol or "").strip().upper()
    if sym in ("NAS100", "US30", "SPX500", "MNQ", "MYM", "MES"):
        return "US_INDEX"
    if sym in ("XAUUSD", "MGC"):
        return "METALS"
    if sym in ("EURUSD", "GBPUSD", "USDJPY", "USDCHF", "AUDUSD", "USDCAD", "NZDUSD"):
        return "FX_MAJOR"
    return "FX_CROSS"


def tick_size_for(symbol: str) -> Decimal:
    sym = str(symbol or "").strip().upper()
    if sym == "NAS100":
        return Decimal("0.25")
    if sym == "US30":
        return Decimal("1.00")
    if sym == "SPX500":
        return Decimal("0.10")
    if sym == "XAUUSD":
        return Decimal("0.01")
    if sym.endswith("JPY"):
        return Decimal("0.001")
    return Decimal("0.00001")


def sl_clamp_for(symbol: str) -> tuple[Decimal, Decimal]:
    sym = str(symbol or "").strip().upper()
    if sym in _SL_CLAMPS:
        return _SL_CLAMPS[sym]
    if sym.endswith("JPY"):
        return (Decimal("0.08"), Decimal("0.32"))
    return (Decimal("0.0008"), Decimal("0.0025"))


# ---------------------------------------------------------------------------
# Pure-Decimal Statistical & Bandit Engine (Mathematician Spec + PH Sign Fix)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiscountedStats:
    n_trades: int = 0
    win_count: int = 0
    loss_count: int = 0
    s0: Decimal = _ZERO
    s1: Decimal = _ZERO
    s2: Decimal = _ZERO
    sw: Decimal = _ZERO
    q2: Decimal = _ZERO
    sgp: Decimal = _ZERO
    sgl: Decimal = _ZERO
    smfe: Decimal = _ZERO
    smae: Decimal = _ZERO
    scap_num: Decimal = _ZERO
    scap_den: Decimal = _ZERO
    cusum_neg: Decimal = _ZERO
    ph_sum: Decimal = _ZERO
    ph_max: Decimal = _ZERO
    raw_sum_r: Decimal = _ZERO
    raw_sum_r2: Decimal = _ZERO
    raw_gp: Decimal = _ZERO
    raw_gl: Decimal = _ZERO
    cum_r: Decimal = _ZERO
    peak_cum_r: Decimal = _ZERO
    max_dd_r: Decimal = _ZERO

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_trades": self.n_trades,
            "win_count": self.win_count,
            "loss_count": self.loss_count,
            "s0": str(self.s0),
            "s1": str(self.s1),
            "s2": str(self.s2),
            "sw": str(self.sw),
            "q2": str(self.q2),
            "sgp": str(self.sgp),
            "sgl": str(self.sgl),
            "smfe": str(self.smfe),
            "smae": str(self.smae),
            "scap_num": str(self.scap_num),
            "scap_den": str(self.scap_den),
            "cusum_neg": str(self.cusum_neg),
            "ph_sum": str(self.ph_sum),
            "ph_max": str(self.ph_max),
            "raw_sum_r": str(self.raw_sum_r),
            "raw_sum_r2": str(self.raw_sum_r2),
            "raw_gp": str(self.raw_gp),
            "raw_gl": str(self.raw_gl),
            "cum_r": str(self.cum_r),
            "peak_cum_r": str(self.peak_cum_r),
            "max_dd_r": str(self.max_dd_r),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> DiscountedStats:
        if not isinstance(raw, Mapping):
            return cls()
        return cls(
            n_trades=int(raw.get("n_trades", 0)),
            win_count=int(raw.get("win_count", 0)),
            loss_count=int(raw.get("loss_count", 0)),
            s0=_d(raw.get("s0", "0")),
            s1=_d(raw.get("s1", "0")),
            s2=_d(raw.get("s2", "0")),
            sw=_d(raw.get("sw", "0")),
            q2=_d(raw.get("q2", "0")),
            sgp=_d(raw.get("sgp", "0")),
            sgl=_d(raw.get("sgl", "0")),
            smfe=_d(raw.get("smfe", "0")),
            smae=_d(raw.get("smae", "0")),
            scap_num=_d(raw.get("scap_num", "0")),
            scap_den=_d(raw.get("scap_den", "0")),
            cusum_neg=_d(raw.get("cusum_neg", "0")),
            ph_sum=_d(raw.get("ph_sum", "0")),
            ph_max=_d(raw.get("ph_max", "0")),
            raw_sum_r=_d(raw.get("raw_sum_r", "0")),
            raw_sum_r2=_d(raw.get("raw_sum_r2", "0")),
            raw_gp=_d(raw.get("raw_gp", "0")),
            raw_gl=_d(raw.get("raw_gl", "0")),
            cum_r=_d(raw.get("cum_r", "0")),
            peak_cum_r=_d(raw.get("peak_cum_r", "0")),
            max_dd_r=_d(raw.get("max_dd_r", "0")),
        )


def update_stats(
    st: DiscountedStats,
    r_val: Decimal,
    *,
    mfe_r: Decimal = _ZERO,
    mae_r: Decimal = _ZERO,
    lam: Decimal = LAMBDA_DECAY,
) -> DiscountedStats:
    r = _d(r_val, "r_val")
    mfe = max(_ZERO, _d(mfe_r, "mfe_r"))
    mae = max(MAE_EPS, _d(mae_r, "mae_r"))
    with localcontext() as ctx:
        ctx.prec = _PREC
        lam2 = lam * lam
        n = st.n_trades + 1
        w_cnt = st.win_count + (1 if r > _ZERO else 0)
        l_cnt = st.loss_count + (1 if r <= _ZERO else 0)
        s0 = lam * st.s0 + _ONE
        s1 = lam * st.s1 + r
        s2 = lam * st.s2 + r * r
        sw = lam * st.sw + (_ONE if r > _ZERO else _ZERO)
        q2 = lam2 * st.q2 + _ONE
        sgp = lam * st.sgp + (r if r > _ZERO else _ZERO)
        sgl = lam * st.sgl + (-r if r < _ZERO else _ZERO)
        smfe = lam * st.smfe + mfe
        smae = lam * st.smae + mae
        if mfe >= MFE_CAPTURE_MIN:
            scap_num = lam * st.scap_num + (r if r > _ZERO else _ZERO)
            scap_den = lam * st.scap_den + mfe
        else:
            scap_num = lam * st.scap_num
            scap_den = lam * st.scap_den

        r_cap = min(CUSUM_GAIN_CAP, r)
        cusum_neg = max(_ZERO, st.cusum_neg + (CUSUM_REF_K - r_cap))

        prev_mean = (st.raw_sum_r / Decimal(st.n_trades)) if st.n_trades > 0 else _ZERO
        raw_sum_r = st.raw_sum_r + r
        raw_sum_r2 = st.raw_sum_r2 + r * r
        ph_sum = st.ph_sum + (r_cap - prev_mean + PH_TOLERANCE)
        ph_max = max(st.ph_max, ph_sum)

        cum_r = st.cum_r + r
        peak_cum_r = max(st.peak_cum_r, cum_r)
        max_dd_r = max(st.max_dd_r, peak_cum_r - cum_r)
        return DiscountedStats(
            n_trades=n,
            win_count=w_cnt,
            loss_count=l_cnt,
            s0=s0,
            s1=s1,
            s2=s2,
            sw=sw,
            q2=q2,
            sgp=sgp,
            sgl=sgl,
            smfe=smfe,
            smae=smae,
            scap_num=scap_num,
            scap_den=scap_den,
            cusum_neg=cusum_neg,
            ph_sum=ph_sum,
            ph_max=ph_max,
            raw_sum_r=raw_sum_r,
            raw_sum_r2=raw_sum_r2,
            raw_gp=st.raw_gp + (r if r > _ZERO else _ZERO),
            raw_gl=st.raw_gl + (-r if r < _ZERO else _ZERO),
            cum_r=cum_r,
            peak_cum_r=peak_cum_r,
            max_dd_r=max_dd_r,
        )


def derived_metrics(st: DiscountedStats, archetype: StrategyArchetype) -> dict[str, Decimal]:
    alpha0, beta0 = BETA_PRIORS[archetype]
    with localcontext() as ctx:
        ctx.prec = _PREC
        if st.s0 <= _ZERO:
            return {
                "e_r": _ZERO,
                "n_eff": _ZERO,
                "var_r": PRIOR_SIGMA2,
                "pf": _ONE,
                "eb_wr": alpha0 / (alpha0 + beta0),
                "mfe_capture": _ZERO,
                "e_ratio": _ONE,
                "ph_stat": _ZERO,
            }
        e_r = st.s1 / st.s0
        n_eff = (st.s0 * st.s0) / st.q2
        denom_corr = (st.s0 * st.s0) - st.q2
        if denom_corr > _ZERO:
            raw_v = (st.s2 / st.s0) - (e_r * e_r)
            var_r = max(SIGMA2_FLOOR, ((st.s0 * st.s0) / denom_corr) * max(_ZERO, raw_v))
        else:
            var_r = PRIOR_SIGMA2
        pf = (st.sgp + PF_EPS) / (st.sgl + PF_EPS)
        eb_wr = (st.sw + alpha0) / (st.s0 + alpha0 + beta0)
        mfe_cap = (st.scap_num / st.scap_den) if st.scap_den > _ZERO else _ZERO
        e_ratio = (st.smfe / st.smae) if st.smae > _ZERO else _ONE
        ph_stat = max(_ZERO, st.ph_max - st.ph_sum)
        return {
            "e_r": e_r,
            "n_eff": n_eff,
            "var_r": var_r,
            "pf": pf,
            "eb_wr": eb_wr,
            "mfe_capture": mfe_cap,
            "e_ratio": e_ratio,
            "ph_stat": ph_stat,
        }


def hierarchical_shrinkage(
    *,
    strat_st: DiscountedStats,
    reg_st: DiscountedStats,
    cell_st: DiscountedStats,
    archetype: StrategyArchetype,
) -> tuple[Decimal, Decimal, Decimal]:
    m_strat = derived_metrics(strat_st, archetype)
    m_reg = derived_metrics(reg_st, archetype)
    m_cell = derived_metrics(cell_st, archetype)
    with localcontext() as ctx:
        ctx.prec = _PREC
        mu_strat = strat_st.s1 / (strat_st.s0 + M_STRAT)
        mu_reg = (reg_st.s1 + M_REGIME * mu_strat) / (reg_st.s0 + M_REGIME)
        mu_cell = (cell_st.s1 + M_SESSION * mu_reg) / (cell_st.s0 + M_SESSION)

        var_strat = (strat_st.s0 * m_strat["var_r"] + M_STRAT * PRIOR_SIGMA2) / (strat_st.s0 + M_STRAT)
        var_reg = (reg_st.s0 * m_reg["var_r"] + M_REGIME * var_strat) / (reg_st.s0 + M_REGIME)
        var_cell = (cell_st.s0 * m_cell["var_r"] + M_SESSION * var_reg) / (cell_st.s0 + M_SESSION)
        return mu_cell, max(SIGMA2_FLOOR, var_cell), m_cell["n_eff"]


def compute_ucb_lcb(
    *,
    mu_cell: Decimal,
    var_cell: Decimal,
    n_eff_cell: Decimal,
    n_tot_active: Decimal,
    cycle_arm_seed: str | None = None,
) -> dict[str, Decimal]:
    with localcontext() as ctx:
        ctx.prec = _PREC
        se = (var_cell / (n_eff_cell + M_SESSION)).sqrt()
        ln_tot = max(_TWO, n_tot_active).ln()
        ucb = mu_cell + KAPPA_UCB * se * ln_tot.sqrt()
        lcb = mu_cell - KAPPA_LCB * se
        ts_score = mu_cell
        if cycle_arm_seed is not None:
            digest = sha256(cycle_arm_seed.encode("utf-8")).digest()
            k = (int.from_bytes(digest[:8], "big") % 9998) + 1
            u = Decimal(k) / Decimal("9999")
            z_ts = LOGISTIC_SCALE * (u / (_ONE - u)).ln()
            ts_score = mu_cell + z_ts * se
        return {"se": se, "ucb": ucb, "lcb": lcb, "ts_score": ts_score}


def evaluate_shadow_graduation(
    st: DiscountedStats,
    *,
    archetype: StrategyArchetype,
    distinct_sessions: int,
    distinct_days: int,
) -> tuple[bool, str, Decimal]:
    if st.n_trades < SHADOW_MIN_TRADES:
        return False, f"SHADOW_N_BELOW_MIN ({st.n_trades}/{SHADOW_MIN_TRADES})", _ZERO
    if distinct_sessions < SHADOW_MIN_SESSIONS and distinct_days < 2:
        return False, "SHADOW_INSUFFICIENT_REGIME_BREADTH", _ZERO
    with localcontext() as ctx:
        ctx.prec = _PREC
        n_dec = Decimal(st.n_trades)
        mean_r = st.raw_sum_r / n_dec
        var_r = max(
            SIGMA2_FLOOR,
            ((st.raw_sum_r2 / n_dec) - mean_r * mean_r) * (n_dec / Decimal(max(1, st.n_trades - 1))),
        )
        se = (var_r / n_dec).sqrt()
        lcb_grad = mean_r - (SHADOW_Z_LCB * se) - (SHADOW_TAIL_C / n_dec)
        raw_pf = (st.raw_gp / st.raw_gl) if st.raw_gl > _ZERO else Decimal("99")
        m = derived_metrics(st, archetype)
        if lcb_grad <= _ZERO:
            return False, f"SHADOW_LCB_NONPOSITIVE ({lcb_grad.quantize(_Q4)})", lcb_grad
        if raw_pf < SHADOW_MIN_PF:
            return False, f"SHADOW_PF_LOW ({raw_pf.quantize(_Q4)})", lcb_grad
        if m["mfe_capture"] < SHADOW_MIN_MFE_CAP or m["e_ratio"] < SHADOW_MIN_ERATIO:
            return False, f"SHADOW_EXCURSION_WEAK (cap={m['mfe_capture'].quantize(_Q4)}, er={m['e_ratio'].quantize(_Q4)})", lcb_grad
        if st.max_dd_r > SHADOW_MAX_DD_R or st.cusum_neg >= CUSUM_WARN:
            return False, f"SHADOW_DD_OR_CUSUM_HIGH (dd={st.max_dd_r.quantize(_Q2)}R)", lcb_grad
        return True, "SHADOW_GRADUATED_TO_ACTIVE", lcb_grad


def evaluate_stopping_rules(
    *,
    current_status: ArmStatus,
    cell_st: DiscountedStats,
    strat_st: DiscountedStats,
    archetype: StrategyArchetype,
    last_r: Decimal,
    trades_since_quarantine: int,
    recovery_sum_r: Decimal,
    reentry_count: int,
    distinct_sessions: int = 2,
    distinct_days: int = 2,
) -> tuple[ArmStatus, str]:
    m_cell = derived_metrics(cell_st, archetype)
    with localcontext() as ctx:
        ctx.prec = _PREC
        se_strat = (derived_metrics(strat_st, archetype)["var_r"] / max(_ONE, strat_st.s0 + M_STRAT)).sqrt()
        mu_strat = strat_st.s1 / (strat_st.s0 + M_STRAT)
        ucb_strat = mu_strat + KAPPA_UCB * se_strat * max(_TWO, strat_st.s0).ln().sqrt()

        if current_status is ArmStatus.DECOMMISSIONED:
            return ArmStatus.DECOMMISSIONED, "ALREADY_DECOMMISSIONED"

        if current_status is ArmStatus.INCUBATING_SHADOW:
            if (strat_st.n_trades >= 45 and ucb_strat < _ZERO) or strat_st.cusum_neg >= Decimal("6.00"):
                return ArmStatus.DECOMMISSIONED, "SHADOW_INCUBATION_FAILED"
            ok, reason, _ = evaluate_shadow_graduation(
                strat_st, archetype=archetype, distinct_sessions=distinct_sessions, distinct_days=distinct_days
            )
            return (ArmStatus.ACTIVE, reason) if ok else (ArmStatus.INCUBATING_SHADOW, reason)

        if strat_st.n_trades >= 15 and strat_st.cusum_neg >= CUSUM_DECOMM and ucb_strat < Decimal("0.05"):
            return ArmStatus.DECOMMISSIONED, f"GLOBAL_CUSUM_DECOMMISSION (C={strat_st.cusum_neg.quantize(_Q4)})"

        if current_status is ArmStatus.ACTIVE:
            if last_r <= CATASTROPHIC_R:
                return ArmStatus.QUARANTINED_SHADOW, f"CATASTROPHIC_TAIL_STOP ({last_r.quantize(_Q2)}R)"
            if cell_st.cusum_neg >= CUSUM_QUARANTINE:
                return ArmStatus.QUARANTINED_SHADOW, f"CELL_CUSUM_QUARANTINE (C={cell_st.cusum_neg.quantize(_Q4)})"
            if m_cell["ph_stat"] >= PH_ALARM and m_cell["e_r"] < _ZERO:
                return ArmStatus.QUARANTINED_SHADOW, f"CELL_PAGE_HINKLEY_DRIFT (PH={m_cell['ph_stat'].quantize(_Q4)})"
            return ArmStatus.ACTIVE, "ACTIVE_HEALTHY"

        if trades_since_quarantine >= QUARANTINE_MIN_RECOVERY:
            rec_mean = recovery_sum_r / Decimal(trades_since_quarantine)
            if cell_st.cusum_neg <= CUSUM_RECOVERY_FLOOR and m_cell["e_r"] >= Decimal("0.15") and rec_mean >= Decimal("0.20"):
                if reentry_count >= MAX_REENTRIES:
                    return ArmStatus.DECOMMISSIONED, "MAX_REENTRIES_EXCEEDED"
                return ArmStatus.ACTIVE, "SHADOW_RECOVERY_PROMOTED"
        if trades_since_quarantine >= QUARANTINE_MAX_TRADES:
            rec_mean = recovery_sum_r / Decimal(max(1, trades_since_quarantine))
            if cell_st.cusum_neg >= Decimal("4.50") or rec_mean < _ZERO:
                return ArmStatus.DECOMMISSIONED, "QUARANTINE_RECOVERY_EXHAUSTED"
        return ArmStatus.QUARANTINED_SHADOW, f"QUARANTINE_COOLOFF ({trades_since_quarantine}/{QUARANTINE_MIN_RECOVERY})"


def compute_risk_weight_multiplier(
    *,
    status: ArmStatus,
    mu_cell: Decimal,
    var_cell: Decimal,
    se_cell: Decimal,
    mfe_capture: Decimal,
    mfe_sample_weight: Decimal,
    cusum_neg: Decimal,
    drawdown_ratio: Decimal,
    is_live_mode: bool,
) -> Decimal:
    if status is not ArmStatus.ACTIVE:
        return Decimal("0.00")
    with localcontext() as ctx:
        ctx.prec = _PREC
        mu_adj = max(_ZERO, mu_cell - _HALF * se_cell)
        second_moment = var_cell + (mu_cell * mu_cell)
        kelly_raw = (mu_adj / second_moment) if second_moment > _ZERO else _ZERO
        u_kelly = min(_ONE, kelly_raw / KELLY_FULL_REF)
        q_mfe = _clamp(mfe_capture / Decimal("0.45"), Decimal("0.70"), _ONE) if mfe_sample_weight >= Decimal("5") else Decimal("0.85")
        if cusum_neg <= CUSUM_WARN:
            psi_cusum = _ONE
        else:
            frac = min(_ONE, (cusum_neg - CUSUM_WARN) / (CUSUM_QUARANTINE - CUSUM_WARN))
            psi_cusum = max(RISK_MIN_MULT, _ONE - _HALF * frac)
        d_soft = Decimal("0.05") if is_live_mode else Decimal("0.15")
        d_max = Decimal("0.10") if is_live_mode else Decimal("0.30")
        if drawdown_ratio <= d_soft:
            psi_dd = _ONE
        else:
            dd_frac = min(_ONE, (drawdown_ratio - d_soft) / (d_max - d_soft))
            psi_dd = max(RISK_MIN_MULT, _ONE - Decimal("0.65") * dd_frac)
        raw_w = (RISK_MIN_MULT + Decimal("0.65") * u_kelly * q_mfe) * psi_cusum * psi_dd
        return _clamp(raw_w, RISK_MIN_MULT, RISK_MAX_MULT).quantize(_Q2, rounding=ROUND_HALF_UP)


def compute_dual_objective_utility(
    *,
    e0_usd: Decimal,
    et_usd: Decimal,
    vt_usd: Decimal,
    drawdown_ratio: Decimal,
) -> Decimal:
    e0, et, vt = _d(e0_usd, "e0"), _d(et_usd, "et"), max(_ZERO, _d(vt_usd, "vt"))
    if e0 <= _ZERO or et <= _ZERO:
        raise ContractError("Equity values must be strictly positive")
    dd = max(_ZERO, _d(drawdown_ratio, "dd"))
    with localcontext() as ctx:
        ctx.prec = _PREC
        ratio = et / e0
        growth = (_ONE - OMEGA_VAULT) * ratio.ln()
        vault = OMEGA_VAULT * (_ONE + (vt / (KAPPA_VAULT * e0))).ln()
        dd_pen = GAMMA_DD * (max(_ZERO, dd - DD_FREE) ** 2)
        rec_pen = GAMMA_REC * max(_ZERO, (e0 / et).ln())
        return (growth + vault - dd_pen - rec_pen).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)


def expected_marginal_utility_score(
    *,
    mu_cell: Decimal,
    var_cell: Decimal,
    ucb_cell: Decimal,
    risk_frac: Decimal,
    user_cap_frac: Decimal,
    e0_usd: Decimal,
    et_usd: Decimal,
    vt_usd: Decimal,
    sweep_ratio: Decimal,
    drawdown_ratio: Decimal,
) -> Decimal:
    with localcontext() as ctx:
        ctx.prec = _PREC
        eff_sweep = _ZERO if et_usd <= e0_usd else _clamp(sweep_ratio, _ZERO, Decimal("0.50"))
        retain = _ONE - eff_sweep
        rec_weight = (_ONE - OMEGA_VAULT) + (GAMMA_REC if et_usd < e0_usd else _ZERO)
        second_moment = var_cell + (mu_cell * mu_cell)
        du_eq = rec_weight * (
            risk_frac * retain * mu_cell
            - _HALF * ((risk_frac * retain) ** 2) * second_moment
        )
        du_vault = OMEGA_VAULT * (et_usd / (KAPPA_VAULT * e0_usd + max(_ZERO, vt_usd))) * eff_sweep * risk_frac * max(_ZERO, mu_cell)
        du_dd = GAMMA_DD * (risk_frac ** 2) * var_cell * max(_ZERO, drawdown_ratio - DD_FREE)
        du_total = du_eq + du_vault - du_dd
        norm_util_r = du_total / max(Decimal("0.0001"), user_cap_frac)
        explore_r = (_ONE - OMEGA_VAULT) * (ucb_cell - mu_cell)
        return (norm_util_r + explore_r).quantize(_Q4, rounding=ROUND_HALF_UP)


# ---------------------------------------------------------------------------
# Microstructure, Holiday/Whipsaw Shield (G0), & Declarative StrategyGenome
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HolidayCalendarAndLiquidityScorer:
    """Air-gapped deterministic US/UK holiday, opening-whipsaw, & dead-tape scorer (G0)."""

    def evaluate(
        self,
        *,
        symbol: str,
        spread: Decimal,
        m1_atr: Decimal | None,
        now: datetime,
    ) -> dict[str, Any]:
        u = utc_time(now, "now")
        et_dt, _ = us_eastern_datetime(u)
        uk_dt = uk_london_datetime(u)
        cls = instrument_class_for(symbol)
        holidays = us_market_holidays_for_year(et_dt.year)
        et_date = et_dt.date()

        holiday_label: str | None = holidays.get(et_date)
        # Black Friday early close (day after Thanksgiving) & Christmas Eve / July 3
        thanksgiving = _nth_weekday_of_month(et_dt.year, 11, 3, 4)
        is_black_friday_drain = (et_date == thanksgiving + timedelta(days=1)) and (
            et_dt.hour > 12 or (et_dt.hour == 12 and et_dt.minute >= 15)
        )
        is_thanksgiving_eve_drain = (et_date == thanksgiving - timedelta(days=1)) and (
            et_dt.hour > 13 or (et_dt.hour == 13 and et_dt.minute >= 30)
        )
        if holiday_label is None and is_black_friday_drain:
            holiday_label = "US_BLACK_FRIDAY_EARLY_CLOSE"

        # Session classification
        hr_utc = u.hour
        if 12 <= hr_utc < 16:
            session_region = "LONDON_NY_OVERLAP"
            base_liq = Decimal("1.00")
        elif 16 <= hr_utc < 21:
            session_region = "NEW_YORK"
            base_liq = Decimal("0.85")
        elif 7 <= hr_utc < 12:
            session_region = "LONDON"
            base_liq = Decimal("0.68") if cls == "US_INDEX" else Decimal("0.88")
        else:
            session_region = "ASIA"
            base_liq = Decimal("0.48") if cls == "US_INDEX" else Decimal("0.72")

        stand_aside_code: str | None = None
        # 1. Rollover dead zone 16:45-17:15 ET
        if (et_dt.hour == 16 and et_dt.minute >= 45) or (et_dt.hour == 17 and et_dt.minute < 15):
            stand_aside_code = "G0_ROLLOVER_DEAD_ZONE"
            base_liq = Decimal("0.15")
        # 2. US MOC pre-close chop 15:30-15:59 ET on US indices
        elif cls == "US_INDEX" and et_dt.weekday() < 5 and et_dt.hour == 15 and et_dt.minute >= 30:
            stand_aside_code = "G0_US_MOC_PRE_CLOSE_CHOP"
            base_liq = Decimal("0.30")
        # 3. Full US holiday gate
        elif holiday_label is not None and holiday_label != "US_BLACK_FRIDAY_EARLY_CLOSE":
            if cls == "US_INDEX":
                stand_aside_code = f"G0_HOLIDAY_CLOSED:{holiday_label}"
                base_liq = Decimal("0.20")
            elif cls == "METALS" and (et_dt.hour > 12 or (et_dt.hour == 12 and et_dt.minute >= 30)):
                stand_aside_code = f"G0_HOLIDAY_METALS_THIN:{holiday_label}"
                base_liq = Decimal("0.25")
            else:
                base_liq = (base_liq * Decimal("0.60")).quantize(_Q2, rounding=ROUND_HALF_UP)
        elif is_black_friday_drain and cls in ("US_INDEX", "METALS"):
            stand_aside_code = "G0_BLACK_FRIDAY_EARLY_CLOSE"
            base_liq = Decimal("0.25")
        elif is_thanksgiving_eve_drain and cls == "US_INDEX":
            base_liq = (base_liq * Decimal("0.55")).quantize(_Q2, rounding=ROUND_HALF_UP)

        # 4. NY 09:25-09:44:59 ET Cash-Open Whipsaw Shield (Indices & Gold)
        in_ny_open_whipsaw = (
            et_dt.weekday() < 5
            and cls in ("US_INDEX", "METALS")
            and ((et_dt.hour == 9 and 25 <= et_dt.minute <= 44))
        )
        if stand_aside_code is None and in_ny_open_whipsaw:
            stand_aside_code = "G0_NY_0930_OPEN_WHIPSAW_SHIELD"

        # 5. London 07:55-08:14 UK Opening Whipsaw window flag (used by S4)
        in_london_open_drive_window = uk_dt.weekday() < 5 and (
            (uk_dt.hour == 8 and uk_dt.minute >= 15) or (uk_dt.hour == 9) or (uk_dt.hour == 10 and uk_dt.minute <= 15)
        )
        in_ny_open_drive_window = et_dt.weekday() < 5 and (
            (et_dt.hour == 9 and et_dt.minute >= 45) or (et_dt.hour == 10) or (et_dt.hour == 11 and et_dt.minute <= 15)
        )

        # Spread-to-ATR penalty
        eff_atr = m1_atr if (m1_atr is not None and m1_atr > _ZERO) else max(spread * Decimal("4"), tick_size_for(symbol))
        sp_atr = (spread / eff_atr).quantize(_Q4, rounding=ROUND_HALF_UP)
        if sp_atr > Decimal("0.35"):
            pen = max(Decimal("0.25"), _ONE - (sp_atr - Decimal("0.35")))
            liq = (base_liq * pen).quantize(_Q4, rounding=ROUND_HALF_UP)
        else:
            liq = base_liq.quantize(_Q4, rounding=ROUND_HALF_UP)

        return {
            "session_region": session_region,
            "session_liquidity_score": _clamp(liq, Decimal("0.05"), _ONE),
            "is_holiday_window": holiday_label is not None,
            "holiday_label": holiday_label,
            "stand_aside_code": stand_aside_code,
            "in_ny_open_drive_window": in_ny_open_drive_window,
            "in_london_open_drive_window": in_london_open_drive_window,
            "spread_to_atr_ratio": sp_atr,
        }


@dataclass(frozen=True, slots=True)
class MarketMicrostructureSnapshot:
    symbol: str
    instrument_class: str
    bid: Decimal
    ask: Decimal
    spread: Decimal
    m1_atr: Decimal
    m5_atr: Decimal
    efficiency_ratio: Decimal
    chop_index: Decimal
    bb_z_score: Decimal
    in_squeeze: bool
    or15_breakout_side: Side | None
    session_code: str
    session_region: str
    session_liquidity_score: Decimal
    is_holiday_window: bool
    holiday_label: str | None
    stand_aside_code: str | None
    in_ny_open_drive_window: bool
    in_london_open_drive_window: bool
    regime: str
    direction: Side | None
    ema_9: Decimal
    ema_21: Decimal
    ema_50: Decimal
    htf_aligned_buy: bool
    htf_aligned_sell: bool
    spread_to_sl_ratio: Decimal
    spread_to_atr_ratio: Decimal
    ema_stretch_sl_mult: Decimal


class MicrostructureAnalyzer:
    """Builds UTC-aligned M1/M5 bars + KER, CHOP, Bollinger/Keltner squeeze, and OR15 signals."""

    def __init__(self, scorer: HolidayCalendarAndLiquidityScorer | None = None) -> None:
        self._scorer = scorer or HolidayCalendarAndLiquidityScorer()

    @staticmethod
    def _compute_ema(values: Sequence[Decimal], period: int) -> Decimal:
        if not values:
            return _ZERO
        eff_p = min(max(1, period), len(values))
        k = _TWO / Decimal(eff_p + 1)
        one_k = _ONE - k
        ema = values[0]
        for v in values[1:]:
            ema = v * k + ema * one_k
        return ema

    @staticmethod
    def compute_efficiency_ratio(prices: Sequence[Decimal], window: int = 14) -> Decimal:
        seq = list(prices)[-max(3, window):]
        if len(seq) < 3:
            return Decimal("0.4500")
        with localcontext() as ctx:
            ctx.prec = _PREC
            net_disp = abs(seq[-1] - seq[0])
            path_sum = sum((abs(seq[i] - seq[i - 1]) for i in range(1, len(seq))), _ZERO)
            if path_sum <= _ZERO:
                return _ZERO
            return _clamp(net_disp / path_sum, _ZERO, _ONE).quantize(_Q4, rounding=ROUND_HALF_UP)

    @staticmethod
    def compute_choppiness_index(
        highs: Sequence[Decimal],
        lows: Sequence[Decimal],
        closes: Sequence[Decimal],
        *,
        fallback_er: Decimal,
    ) -> Decimal:
        n = min(14, len(closes))
        if n < 5 or len(highs) < n or len(lows) < n:
            return ((_ONE - fallback_er) * Decimal("100")).quantize(_Q2, rounding=ROUND_HALF_UP)
        with localcontext() as ctx:
            ctx.prec = _PREC
            h_tail = list(highs)[-n:]
            l_tail = list(lows)[-n:]
            c_tail = list(closes)[-n:]
            sum_tr = h_tail[0] - l_tail[0]
            for i in range(1, n):
                tr = max(
                    h_tail[i] - l_tail[i],
                    abs(h_tail[i] - c_tail[i - 1]),
                    abs(l_tail[i] - c_tail[i - 1]),
                )
                sum_tr += max(_ZERO, tr)
            span = max(h_tail) - min(l_tail)
            if span <= _ZERO or sum_tr <= _ZERO:
                return Decimal("65.00")
            raw_chop = Decimal("100") * ((sum_tr / span).ln() / Decimal(n).ln())
            return _clamp(raw_chop, _ZERO, Decimal("100")).quantize(_Q2, rounding=ROUND_HALF_UP)

    @staticmethod
    def _extract_m1_bars(candles_m1: Sequence[Mapping[str, Any]] | None) -> list[tuple[Decimal, Decimal, Decimal, Decimal]]:
        bars: list[tuple[Decimal, Decimal, Decimal, Decimal]] = []
        if not isinstance(candles_m1, Sequence) or isinstance(candles_m1, (str, bytes)):
            return bars
        for b in list(candles_m1)[-120:]:
            if not isinstance(b, Mapping):
                continue
            try:
                o_px = _d(b.get("o") if b.get("o") is not None else b.get("open", b.get("c")))
                h_px = _d(b.get("h") if b.get("h") is not None else b.get("high", o_px))
                l_px = _d(b.get("l") if b.get("l") is not None else b.get("low", o_px))
                c_px = _d(b.get("c") if b.get("c") is not None else b.get("close", o_px))
            except ContractError:
                continue
            if l_px <= _ZERO or h_px < l_px:
                continue
            mid = (h_px + l_px) / _TWO
            if mid > _ZERO and (h_px - l_px) > mid * Decimal("0.025"):
                continue
            bars.append((o_px, h_px, l_px, c_px))
        return bars

    @staticmethod
    def _aggregate_m5(m1_bars: Sequence[tuple[Decimal, Decimal, Decimal, Decimal]]) -> list[tuple[Decimal, Decimal, Decimal, Decimal]]:
        out: list[tuple[Decimal, Decimal, Decimal, Decimal]] = []
        n = len(m1_bars)
        idx = 0
        while idx < n:
            chunk = m1_bars[idx : idx + 5]
            o_px = chunk[0][0]
            h_px = max(x[1] for x in chunk)
            l_px = min(x[2] for x in chunk)
            c_px = chunk[-1][3]
            out.append((o_px, h_px, l_px, c_px))
            idx += 5
        return out

    def build_snapshot(
        self,
        *,
        symbol: str,
        bid: Decimal,
        ask: Decimal,
        mids: Sequence[Decimal],
        candles_m1: Sequence[Mapping[str, Any]] | None,
        regime: str,
        direction: Side | None,
        normal_sl_distance: Decimal,
        session_code: str,
        now: datetime,
    ) -> MarketMicrostructureSnapshot:
        spread = max(tick_size_for(symbol), ask - bid)
        m1_bars = self._extract_m1_bars(candles_m1)
        m5_bars = self._aggregate_m5(m1_bars) if len(m1_bars) >= 10 else []

        if len(m5_bars) >= 6:
            series_c = [x[3] for x in m5_bars]
            series_h = [x[1] for x in m5_bars]
            series_l = [x[2] for x in m5_bars]
        elif len(m1_bars) >= 5:
            series_c = [x[3] for x in m1_bars]
            series_h = [x[1] for x in m1_bars]
            series_l = [x[2] for x in m1_bars]
        else:
            series_c = list(mids) if mids else [(bid + ask) / _TWO]
            series_h = series_c
            series_l = series_c

        er = self.compute_efficiency_ratio(series_c, window=14)
        chop = self.compute_choppiness_index(series_h, series_l, series_c, fallback_er=er)

        if len(m1_bars) >= 3:
            m1_atr = sum((x[1] - x[2] for x in m1_bars[-14:]), _ZERO) / Decimal(min(14, len(m1_bars)))
        else:
            m1_atr = max(spread * Decimal("4"), normal_sl_distance * Decimal("0.35"))
        if len(m5_bars) >= 3:
            m5_atr = sum((x[1] - x[2] for x in m5_bars[-14:]), _ZERO) / Decimal(min(14, len(m5_bars)))
        else:
            m5_atr = m1_atr * Decimal("2.00")

        ema_9 = self._compute_ema(series_c, 9)
        ema_21 = self._compute_ema(series_c, 21)
        ema_50 = self._compute_ema(series_c, 50)
        htf_buy = ema_9 >= ema_21 and ema_21 >= ema_50
        htf_sell = ema_9 <= ema_21 and ema_21 <= ema_50

        # Bollinger Z-score & Squeeze detection
        with localcontext() as ctx:
            ctx.prec = _PREC
            tail20 = series_c[-20:] if len(series_c) >= 6 else series_c
            mean20 = sum(tail20, _ZERO) / Decimal(len(tail20))
            var20 = sum(((x - mean20) ** 2 for x in tail20), _ZERO) / Decimal(max(1, len(tail20)))
            sd20 = max(tick_size_for(symbol), var20.sqrt())
            last_mid = (bid + ask) / _TWO
            bb_z = ((last_mid - mean20) / sd20).quantize(_Q4, rounding=ROUND_HALF_UP)
            kc_half = Decimal("1.50") * max(tick_size_for(symbol), m5_atr if m5_bars else m1_atr)
            in_squeeze = (Decimal("2.00") * sd20) <= kc_half

        # Opening-range 15-bar breakout proxy
        or15_side: Side | None = None
        if len(m1_bars) >= 16:
            prior15_h = max(x[1] for x in m1_bars[-16:-1])
            prior15_l = min(x[2] for x in m1_bars[-16:-1])
            buf = m1_atr * Decimal("0.20")
            if last_mid > prior15_h + buf:
                or15_side = Side.BUY
            elif last_mid < prior15_l - buf:
                or15_side = Side.SELL

        liq_eval = self._scorer.evaluate(symbol=symbol, spread=spread, m1_atr=m1_atr, now=now)
        eff_sl = max(tick_size_for(symbol), normal_sl_distance)
        sp_sl = (spread / eff_sl).quantize(_Q4, rounding=ROUND_HALF_UP)
        if direction is Side.BUY:
            stretch = ((ask - ema_21) / eff_sl).quantize(_Q4, rounding=ROUND_HALF_UP)
        elif direction is Side.SELL:
            stretch = ((ema_21 - bid) / eff_sl).quantize(_Q4, rounding=ROUND_HALF_UP)
        else:
            stretch = (abs(last_mid - ema_21) / eff_sl).quantize(_Q4, rounding=ROUND_HALF_UP)

        return MarketMicrostructureSnapshot(
            symbol=symbol,
            instrument_class=instrument_class_for(symbol),
            bid=bid,
            ask=ask,
            spread=spread,
            m1_atr=m1_atr,
            m5_atr=m5_atr,
            efficiency_ratio=er,
            chop_index=chop,
            bb_z_score=bb_z,
            in_squeeze=in_squeeze,
            or15_breakout_side=or15_side,
            session_code=_ascii_clean(session_code or liq_eval["session_region"], max_len=32),
            session_region=str(liq_eval["session_region"]),
            session_liquidity_score=liq_eval["session_liquidity_score"],
            is_holiday_window=bool(liq_eval["is_holiday_window"]),
            holiday_label=liq_eval["holiday_label"],
            stand_aside_code=liq_eval["stand_aside_code"],
            in_ny_open_drive_window=bool(liq_eval["in_ny_open_drive_window"]),
            in_london_open_drive_window=bool(liq_eval["in_london_open_drive_window"]),
            regime=regime,
            direction=direction,
            ema_9=ema_9,
            ema_21=ema_21,
            ema_50=ema_50,
            htf_aligned_buy=htf_buy,
            htf_aligned_sell=htf_sell,
            spread_to_sl_ratio=sp_sl,
            spread_to_atr_ratio=liq_eval["spread_to_atr_ratio"],
            ema_stretch_sl_mult=stretch,
        )


@dataclass(frozen=True, slots=True)
class StrategyGenome:
    """Declarative, zero-eval/exec strategy rule-gene configuration."""

    strategy_id: str
    display_name: str
    version: int
    origin: str  # CORE_BASELINE | AI_EVOLVED
    archetype: StrategyArchetype
    direction_mode: str  # MOMENTUM | FADE
    entry_trigger: str  # EMA_PULLBACK | SQUEEZE_BREAKOUT | RANGE_EXTREME_FADE | OPEN_RANGE_DRIVE
    target_markets: tuple[str, ...]
    preferred_regimes: tuple[str, ...]
    allowed_sessions: tuple[str, ...]
    ker_min: Decimal
    ker_max: Decimal
    chop_min: Decimal
    chop_max: Decimal
    min_liquidity_score: Decimal
    max_spread_sl_ratio: Decimal
    max_ema_stretch_sl_mult: Decimal
    bb_z_threshold: Decimal
    sl_atr_mult: Decimal
    rr_target: Decimal
    derisk_trigger_r: Decimal
    derisk_stop_r: Decimal
    be_trigger_r: Decimal
    be_lock_r: Decimal
    trail_activate_r: Decimal
    trail_dist_r: Decimal
    allow_pyramiding: bool
    hypothesis_plain_english: str

    def blueprint_summary(self) -> str:
        return _ascii_clean(
            f"{self.entry_trigger} | KER {self.ker_min}..{self.ker_max} | CHOP {self.chop_min}..{self.chop_max} "
            f"| SL {self.sl_atr_mult}xATR | DeRisk +{self.derisk_trigger_r}R->-{abs(self.derisk_stop_r)}R "
            f"| BE +{self.be_trigger_r}R | TP {self.rr_target}R",
            max_len=240,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "display_name": self.display_name,
            "version": self.version,
            "origin": self.origin,
            "archetype": self.archetype.value,
            "direction_mode": self.direction_mode,
            "entry_trigger": self.entry_trigger,
            "target_markets": list(self.target_markets),
            "preferred_regimes": list(self.preferred_regimes),
            "allowed_sessions": list(self.allowed_sessions),
            "ker_min": str(self.ker_min),
            "ker_max": str(self.ker_max),
            "chop_min": str(self.chop_min),
            "chop_max": str(self.chop_max),
            "min_liquidity_score": str(self.min_liquidity_score),
            "max_spread_sl_ratio": str(self.max_spread_sl_ratio),
            "max_ema_stretch_sl_mult": str(self.max_ema_stretch_sl_mult),
            "bb_z_threshold": str(self.bb_z_threshold),
            "sl_atr_mult": str(self.sl_atr_mult),
            "rr_target": str(self.rr_target),
            "derisk_trigger_r": str(self.derisk_trigger_r),
            "derisk_stop_r": str(self.derisk_stop_r),
            "be_trigger_r": str(self.be_trigger_r),
            "be_lock_r": str(self.be_lock_r),
            "trail_activate_r": str(self.trail_activate_r),
            "trail_dist_r": str(self.trail_dist_r),
            "allow_pyramiding": self.allow_pyramiding,
            "hypothesis_plain_english": self.hypothesis_plain_english,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StrategyGenome:
        return cls(
            strategy_id=str(raw["strategy_id"]),
            display_name=str(raw["display_name"]),
            version=int(raw.get("version", 1)),
            origin=str(raw.get("origin", "CORE_BASELINE")),
            archetype=StrategyArchetype(str(raw["archetype"])),
            direction_mode=str(raw["direction_mode"]),
            entry_trigger=str(raw["entry_trigger"]),
            target_markets=tuple(str(x) for x in raw["target_markets"]),
            preferred_regimes=tuple(str(x) for x in raw["preferred_regimes"]),
            allowed_sessions=tuple(str(x) for x in raw["allowed_sessions"]),
            ker_min=_d(raw["ker_min"]),
            ker_max=_d(raw["ker_max"]),
            chop_min=_d(raw["chop_min"]),
            chop_max=_d(raw["chop_max"]),
            min_liquidity_score=_d(raw["min_liquidity_score"]),
            max_spread_sl_ratio=_d(raw["max_spread_sl_ratio"]),
            max_ema_stretch_sl_mult=_d(raw["max_ema_stretch_sl_mult"]),
            bb_z_threshold=_d(raw["bb_z_threshold"]),
            sl_atr_mult=_d(raw["sl_atr_mult"]),
            rr_target=_d(raw["rr_target"]),
            derisk_trigger_r=_d(raw["derisk_trigger_r"]),
            derisk_stop_r=_d(raw["derisk_stop_r"]),
            be_trigger_r=_d(raw["be_trigger_r"]),
            be_lock_r=_d(raw["be_lock_r"]),
            trail_activate_r=_d(raw["trail_activate_r"]),
            trail_dist_r=_d(raw["trail_dist_r"]),
            allow_pyramiding=bool(raw.get("allow_pyramiding", True)),
            hypothesis_plain_english=str(raw.get("hypothesis_plain_english", "Declarative strategy playbook")),
        )

    def evaluate_signal(self, snap: MarketMicrostructureSnapshot) -> tuple[Side | None, str]:
        if snap.stand_aside_code is not None:
            return None, snap.stand_aside_code
        if snap.symbol not in self.target_markets:
            return None, "MARKET_OUT_OF_SCOPE"
        if snap.session_region not in self.allowed_sessions:
            return None, "SESSION_OUT_OF_SCOPE"
        if snap.session_liquidity_score < self.min_liquidity_score:
            return None, "LIQUIDITY_BELOW_MIN"
        if snap.spread_to_sl_ratio > self.max_spread_sl_ratio:
            return None, "SPREAD_TO_SL_HIGH"
        if not (self.ker_min <= snap.efficiency_ratio <= self.ker_max):
            return None, "KER_OUT_OF_BAND"
        if not (self.chop_min <= snap.chop_index <= self.chop_max):
            return None, "CHOP_OUT_OF_BAND"

        if self.entry_trigger == "EMA_PULLBACK":
            if snap.regime not in self.preferred_regimes or snap.direction is None:
                return None, "REGIME_NOT_ALIGNED"
            if snap.direction is Side.BUY and not snap.htf_aligned_buy:
                return None, "HTF_NOT_BULLISH"
            if snap.direction is Side.SELL and not snap.htf_aligned_sell:
                return None, "HTF_NOT_BEARISH"
            if snap.ema_stretch_sl_mult > self.max_ema_stretch_sl_mult:
                return None, "EMA_STRETCH_EXCEEDED"
            return snap.direction, f"{self.strategy_id}: aligned pullback (KER={snap.efficiency_ratio})"

        if self.entry_trigger == "SQUEEZE_BREAKOUT":
            if snap.direction is None:
                return None, "NO_BREAKOUT_DIRECTION"
            if not (snap.in_squeeze or abs(snap.bb_z_score) >= self.bb_z_threshold):
                return None, "NO_VOL_SQUEEZE_RELEASE"
            if snap.ema_stretch_sl_mult > self.max_ema_stretch_sl_mult:
                return None, "BREAKOUT_OVEREXTENDED"
            return snap.direction, f"{self.strategy_id}: volatility expansion (z={snap.bb_z_score})"

        if self.entry_trigger == "RANGE_EXTREME_FADE":
            if snap.spread_to_atr_ratio > Decimal("0.12"):
                return None, "FADE_SPREAD_TOO_WIDE"
            if snap.bb_z_score >= self.bb_z_threshold:
                return Side.SELL, f"{self.strategy_id}: range upper-band rejection (z={snap.bb_z_score}, KER={snap.efficiency_ratio})"
            if snap.bb_z_score <= -self.bb_z_threshold:
                return Side.BUY, f"{self.strategy_id}: range lower-band rejection (z={snap.bb_z_score}, KER={snap.efficiency_ratio})"
            return None, "NOT_AT_RANGE_EXTREME"

        if self.entry_trigger == "OPEN_RANGE_DRIVE":
            if not (snap.in_ny_open_drive_window or snap.in_london_open_drive_window):
                return None, "OUTSIDE_OPENING_DRIVE_WINDOW"
            cand_side = snap.or15_breakout_side or snap.direction
            if cand_side is None:
                return None, "NO_OR15_DRIVE"
            if snap.ema_stretch_sl_mult > self.max_ema_stretch_sl_mult:
                return None, "OR15_OVEREXTENDED"
            return cand_side, f"{self.strategy_id}: post-whipsaw opening drive ({snap.session_region})"

        return None, "UNKNOWN_TRIGGER"

    def compute_sl_tp_distances(self, snap: MarketMicrostructureSnapshot) -> tuple[Decimal, Decimal]:
        t_sz = tick_size_for(snap.symbol)
        min_sl, max_sl = sl_clamp_for(snap.symbol)
        base_atr = snap.m5_atr if snap.m5_atr > _ZERO else snap.m1_atr * Decimal("2.00")
        raw_sl = (base_atr * self.sl_atr_mult).quantize(t_sz, rounding=ROUND_HALF_UP)
        sl_dist = max(t_sz, _clamp(raw_sl, min_sl, max_sl).quantize(t_sz, rounding=ROUND_HALF_UP))
        tp_dist = max(t_sz * Decimal("2"), (sl_dist * self.rr_target).quantize(t_sz, rounding=ROUND_HALF_UP))
        return sl_dist, tp_dist


def default_seeded_genomes() -> tuple[tuple[StrategyGenome, ArmStatus], ...]:
    all_mkts = tuple(EXPANDED_MARKETS)
    fx_only = tuple(m for m in EXPANDED_MARKETS if m not in INDEX_INSTRUMENTS)
    all_sess = ("ASIA", "LONDON", "LONDON_NY_OVERLAP", "NEW_YORK")
    return (
        (
            StrategyGenome(
                strategy_id="S1_M5_ALIGNED_TREND_PULLBACK",
                display_name="M5 Aligned Trend Pullback",
                version=1,
                origin="CORE_BASELINE",
                archetype=StrategyArchetype.TREND_FOLLOW,
                direction_mode="MOMENTUM",
                entry_trigger="EMA_PULLBACK",
                target_markets=all_mkts,
                preferred_regimes=("STRONG_TREND", "TREND_IGNITION"),
                allowed_sessions=all_sess,
                ker_min=Decimal("0.35"),
                ker_max=Decimal("1.00"),
                chop_min=Decimal("0.00"),
                chop_max=Decimal("55.00"),
                min_liquidity_score=Decimal("0.45"),
                max_spread_sl_ratio=Decimal("0.15"),
                max_ema_stretch_sl_mult=Decimal("0.60"),
                bb_z_threshold=Decimal("1.80"),
                sl_atr_mult=Decimal("1.35"),
                rr_target=Decimal("2.40"),
                derisk_trigger_r=Decimal("0.60"),
                derisk_stop_r=Decimal("-0.40"),
                be_trigger_r=Decimal("0.90"),
                be_lock_r=Decimal("0.15"),
                trail_activate_r=Decimal("1.35"),
                trail_dist_r=Decimal("0.75"),
                allow_pyramiding=True,
                hypothesis_plain_english="Enters M5/M15 aligned trend pullbacks without chasing stretched candle tops.",
            ),
            ArmStatus.ACTIVE,
        ),
        (
            StrategyGenome(
                strategy_id="S2_VOLATILITY_SQUEEZE_BREAKOUT",
                display_name="Volatility Squeeze Expansion",
                version=1,
                origin="CORE_BASELINE",
                archetype=StrategyArchetype.VOL_BREAKOUT,
                direction_mode="MOMENTUM",
                entry_trigger="SQUEEZE_BREAKOUT",
                target_markets=all_mkts,
                preferred_regimes=("STRONG_TREND", "TREND_IGNITION"),
                allowed_sessions=("LONDON", "LONDON_NY_OVERLAP", "NEW_YORK"),
                ker_min=Decimal("0.30"),
                ker_max=Decimal("1.00"),
                chop_min=Decimal("0.00"),
                chop_max=Decimal("60.00"),
                min_liquidity_score=Decimal("0.55"),
                max_spread_sl_ratio=Decimal("0.14"),
                max_ema_stretch_sl_mult=Decimal("0.70"),
                bb_z_threshold=Decimal("1.85"),
                sl_atr_mult=Decimal("1.25"),
                rr_target=Decimal("2.50"),
                derisk_trigger_r=Decimal("0.65"),
                derisk_stop_r=Decimal("-0.35"),
                be_trigger_r=Decimal("0.95"),
                be_lock_r=Decimal("0.15"),
                trail_activate_r=Decimal("1.40"),
                trail_dist_r=Decimal("0.75"),
                allow_pyramiding=True,
                hypothesis_plain_english="Captures clean volatility-compression breakouts during liquid London and NY hours.",
            ),
            ArmStatus.ACTIVE,
        ),
        (
            StrategyGenome(
                strategy_id="S3_RANGE_EXTREME_FADE",
                display_name="Verified Chop Range Extreme Fade",
                version=1,
                origin="CORE_BASELINE",
                archetype=StrategyArchetype.MEAN_REVERT,
                direction_mode="FADE",
                entry_trigger="RANGE_EXTREME_FADE",
                target_markets=all_mkts,
                preferred_regimes=("CHOP_RANGE", "TREND_IGNITION"),
                allowed_sessions=all_sess,
                ker_min=Decimal("0.00"),
                ker_max=Decimal("0.25"),
                chop_min=Decimal("56.00"),
                chop_max=Decimal("100.00"),
                min_liquidity_score=Decimal("0.50"),
                max_spread_sl_ratio=Decimal("0.10"),
                max_ema_stretch_sl_mult=Decimal("2.50"),
                bb_z_threshold=Decimal("2.00"),
                sl_atr_mult=Decimal("1.10"),
                rr_target=Decimal("1.50"),
                derisk_trigger_r=Decimal("0.50"),
                derisk_stop_r=Decimal("-0.40"),
                be_trigger_r=Decimal("0.75"),
                be_lock_r=Decimal("0.12"),
                trail_activate_r=Decimal("1.10"),
                trail_dist_r=Decimal("0.50"),
                allow_pyramiding=False,
                hypothesis_plain_english="Fades 2-sigma extremes ONLY when low KER and high CHOP confirm sideways rangebound markets.",
            ),
            ArmStatus.ACTIVE,
        ),
        (
            StrategyGenome(
                strategy_id="S4_NY_LONDON_OPENING_RANGE_DRIVE",
                display_name="Post-Whipsaw Opening Range Drive",
                version=1,
                origin="CORE_BASELINE",
                archetype=StrategyArchetype.VOL_BREAKOUT,
                direction_mode="MOMENTUM",
                entry_trigger="OPEN_RANGE_DRIVE",
                target_markets=all_mkts,
                preferred_regimes=("STRONG_TREND", "TREND_IGNITION"),
                allowed_sessions=("LONDON", "LONDON_NY_OVERLAP", "NEW_YORK"),
                ker_min=Decimal("0.35"),
                ker_max=Decimal("1.00"),
                chop_min=Decimal("0.00"),
                chop_max=Decimal("58.00"),
                min_liquidity_score=Decimal("0.65"),
                max_spread_sl_ratio=Decimal("0.14"),
                max_ema_stretch_sl_mult=Decimal("0.75"),
                bb_z_threshold=Decimal("1.60"),
                sl_atr_mult=Decimal("1.30"),
                rr_target=Decimal("2.50"),
                derisk_trigger_r=Decimal("0.60"),
                derisk_stop_r=Decimal("-0.35"),
                be_trigger_r=Decimal("0.90"),
                be_lock_r=Decimal("0.15"),
                trail_activate_r=Decimal("1.35"),
                trail_dist_r=Decimal("0.70"),
                allow_pyramiding=True,
                hypothesis_plain_english="Waits out the first 15 minutes of London and NY opening whipsaws, then rides the confirmed drive.",
            ),
            ArmStatus.ACTIVE,
        ),
        (
            StrategyGenome(
                strategy_id="S5_FX_G10_PRECISION_PULLBACK_V1",
                display_name="G10 FX Tight-Spread Trend Challenger",
                version=1,
                origin="AI_EVOLVED",
                archetype=StrategyArchetype.TREND_FOLLOW,
                direction_mode="MOMENTUM",
                entry_trigger="EMA_PULLBACK",
                target_markets=fx_only,
                preferred_regimes=("STRONG_TREND", "TREND_IGNITION"),
                allowed_sessions=("ASIA", "LONDON", "LONDON_NY_OVERLAP"),
                ker_min=Decimal("0.42"),
                ker_max=Decimal("1.00"),
                chop_min=Decimal("0.00"),
                chop_max=Decimal("48.00"),
                min_liquidity_score=Decimal("0.60"),
                max_spread_sl_ratio=Decimal("0.10"),
                max_ema_stretch_sl_mult=Decimal("0.45"),
                bb_z_threshold=Decimal("1.80"),
                sl_atr_mult=Decimal("1.25"),
                rr_target=Decimal("2.30"),
                derisk_trigger_r=Decimal("0.55"),
                derisk_stop_r=Decimal("-0.35"),
                be_trigger_r=Decimal("0.85"),
                be_lock_r=Decimal("0.15"),
                trail_activate_r=Decimal("1.25"),
                trail_dist_r=Decimal("0.65"),
                allow_pyramiding=False,
                hypothesis_plain_english="Dedicated 16-pair G10 Forex pullback specialist incubating live to end currency-pair starvation.",
            ),
            ArmStatus.INCUBATING_SHADOW,
        ),
    )


@dataclass(frozen=True, slots=True)
class StrategyCandidateDecision:
    allowed: bool
    strategy_id: str | None
    display_name: str | None
    symbol: str | None
    side: Side | None
    regime: str | None
    risk_weight_multiplier: Decimal
    sl_distance: Decimal | None
    tp_distance: Decimal | None
    derisk_trigger_r: Decimal
    derisk_stop_r: Decimal
    be_trigger_r: Decimal
    be_lock_r: Decimal
    trail_activate_r: Decimal
    trail_dist_r: Decimal
    allow_pyramiding: bool
    setup_note: str
    utility_score: Decimal
    snapshot: MarketMicrostructureSnapshot | None


# ---------------------------------------------------------------------------
# SQLite WAL Persistent Store & Real-Time Adaptive Strategy Lab
# ---------------------------------------------------------------------------

_LAB_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA journal_size_limit = 8388608;

CREATE TABLE IF NOT EXISTS strategy_registry (
    strategy_id TEXT PRIMARY KEY,
    genome_json TEXT NOT NULL,
    status TEXT NOT NULL,
    retired_by TEXT NULL,
    retirement_reason_code TEXT NULL,
    retirement_reason_text TEXT NULL,
    strat_stats_json TEXT NOT NULL,
    cell_stats_json TEXT NOT NULL,
    net_pnl_usd TEXT NOT NULL DEFAULT '0.00',
    starting_balance_contrib_usd TEXT NOT NULL DEFAULT '0.00',
    vaulted_profit_contrib_usd TEXT NOT NULL DEFAULT '0.00',
    shadow_net_pnl_usd TEXT NOT NULL DEFAULT '0.00',
    shadow_sessions_json TEXT NOT NULL DEFAULT '[]',
    shadow_days_json TEXT NOT NULL DEFAULT '[]',
    trades_since_quarantine INTEGER NOT NULL DEFAULT 0,
    recovery_sum_r TEXT NOT NULL DEFAULT '0.0000',
    reentry_count INTEGER NOT NULL DEFAULT 0,
    sim_valve_checks INTEGER NOT NULL DEFAULT 0,
    sim_valve_passes INTEGER NOT NULL DEFAULT 0,
    created_at_utc TEXT NOT NULL,
    promoted_at_utc TEXT NOT NULL,
    quarantined_at_utc TEXT NULL,
    cooldown_until_utc TEXT NULL,
    last_trade_at_utc TEXT NULL,
    updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_field_notes (
    seq_no INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id TEXT NOT NULL UNIQUE,
    observed_at_utc TEXT NOT NULL,
    observed_at_pacific TEXT NOT NULL,
    author_role TEXT NOT NULL,
    note_category TEXT NOT NULL,
    headline TEXT NOT NULL,
    body_plain_english TEXT NOT NULL,
    related_strategy_id TEXT NULL,
    related_symbol TEXT NULL,
    related_ticket TEXT NULL,
    session_region TEXT NULL,
    entry_regime TEXT NULL,
    lesson_tags TEXT NULL,
    impact_pnl_usd TEXT NULL,
    realized_r TEXT NULL,
    pinned_by_owner INTEGER NOT NULL DEFAULT 0,
    acknowledged_by_ai INTEGER NOT NULL DEFAULT 0,
    prev_sha256 TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS strategy_trade_attribution (
    attr_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    trade_uid TEXT NOT NULL UNIQUE,
    source_channel TEXT NOT NULL,
    strategy_id TEXT NOT NULL,
    symbol TEXT NOT NULL,
    side TEXT NOT NULL,
    session_region TEXT NOT NULL,
    entry_regime TEXT NOT NULL,
    net_pnl_usd TEXT NOT NULL,
    realized_r TEXT NOT NULL,
    peak_mfe_r TEXT NOT NULL,
    worst_mae_r TEXT NOT NULL,
    starting_balance_delta_usd TEXT NOT NULL,
    vaulted_profit_delta_usd TEXT NOT NULL,
    closed_at_utc TEXT NOT NULL,
    prev_sha256 TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL UNIQUE
);
"""


class AdaptiveStrategyLab:
    """Closed-loop self-learning strategy lifecycle engine, two-way Field Notebook & Shadow Incubator."""

    def __init__(
        self,
        *,
        db_path: str | Path,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._db_path = Path(str(db_path))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._analyzer = MicrostructureAnalyzer()

        # In-memory mirrors for O(1) zero-I/O fast paths & prompt recall
        self._genomes: dict[str, StrategyGenome] = {}
        self._statuses: dict[str, ArmStatus] = {}
        self._strat_stats: dict[str, DiscountedStats] = {}
        self._cell_stats: dict[str, dict[str, DiscountedStats]] = {}
        self._meta: dict[str, dict[str, Any]] = {}
        self._notes_cache: deque[dict[str, Any]] = deque(maxlen=200)
        self._notes_total: int = 0
        self._audit_head_sha256: str = GENESIS_SHA256
        self._attr_head_sha256: str = GENESIS_SHA256
        self._vetoed_proposals_total: int = 0

        # Active live/demo ticket excursion telemetry (0 SQLite I/O on 50ms path)
        self._active_tickets: dict[str, dict[str, Any]] = {}
        # Open simulated shadow positions: key = (strategy_id, symbol)
        self._shadow_open: dict[tuple[str, str], dict[str, Any]] = {}
        self._shadow_trades_total: int = 0
        self._last_shadow_eval_mono_s: int = 0
        self._evolved_seq: int = 1

        self._bootstrap_db()

    def _now(self, now: datetime | None = None) -> datetime:
        return utc_time(now or self._clock(), "now")

    def _connect_rw(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _connect_ro(self) -> sqlite3.Connection | None:
        if not self._db_path.is_file():
            return None
        uri = f"file:{self._db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _bootstrap_db(self) -> None:
        now = self._now()
        now_iso = _iso_utc(now)
        with self._lock:
            conn = self._connect_rw()
            try:
                conn.executescript(_LAB_DDL)
                existing_rows = conn.execute("SELECT * FROM strategy_registry").fetchall()
                existing_ids = {str(r["strategy_id"]) for r in existing_rows}
                for genome, init_status in default_seeded_genomes():
                    if genome.strategy_id not in existing_ids:
                        conn.execute(
                            """
                            INSERT INTO strategy_registry (
                                strategy_id, genome_json, status, strat_stats_json, cell_stats_json,
                                created_at_utc, promoted_at_utc, updated_at_utc
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                genome.strategy_id,
                                json.dumps(genome.to_dict(), sort_keys=True),
                                init_status.value,
                                json.dumps(DiscountedStats().to_dict(), sort_keys=True),
                                "{}",
                                now_iso,
                                now_iso,
                                now_iso,
                            ),
                        )
                note_cnt_row = conn.execute("SELECT COUNT(*) AS c FROM ai_field_notes").fetchone()
                if note_cnt_row is not None and int(note_cnt_row["c"]) == 0:
                    self._insert_note_tx(
                        conn,
                        now=now,
                        author_role="AI_STRATEGIST",
                        note_category="MARKET_SHIFT",
                        headline="Update 49 Self-Learning Strategy Lab Initialized",
                        body_plain_english=(
                            "Seeded S1..S4 multi-regime playbooks with US Holiday and NY 09:30 whipsaw shields, "
                            "Two-Step +0.60R profit ratchet, 20-market FX+Index ranking, and S5 G10 FX shadow challenger."
                        ),
                        related_strategy_id="S1_M5_ALIGNED_TREND_PULLBACK",
                        related_symbol=None,
                        related_ticket=None,
                        session_region="GLOBAL",
                        entry_regime="STRONG_TREND",
                        lesson_tags="LAB_BOOT",
                        impact_pnl_usd=None,
                        realized_r=None,
                        pinned_by_owner=False,
                    )
                conn.commit()
            finally:
                conn.close()
            self._reload_cache_from_ro()

    def _reload_cache_from_ro(self) -> None:
        conn = self._connect_ro()
        if conn is None:
            return
        try:
            rows = conn.execute("SELECT * FROM strategy_registry ORDER BY strategy_id ASC").fetchall()
            self._genomes.clear()
            self._statuses.clear()
            self._strat_stats.clear()
            self._cell_stats.clear()
            self._meta.clear()
            shadow_total = 0
            for r in rows:
                sid = str(r["strategy_id"])
                genome = StrategyGenome.from_dict(json.loads(str(r["genome_json"])))
                st_enum = ArmStatus(str(r["status"]))
                s_stats = DiscountedStats.from_dict(json.loads(str(r["strat_stats_json"])))
                raw_cells = json.loads(str(r["cell_stats_json"]) or "{}")
                c_map = {str(k): DiscountedStats.from_dict(v) for k, v in raw_cells.items()}
                self._genomes[sid] = genome
                self._statuses[sid] = st_enum
                self._strat_stats[sid] = s_stats
                self._cell_stats[sid] = c_map
                if st_enum is ArmStatus.INCUBATING_SHADOW:
                    shadow_total += s_stats.n_trades
                self._meta[sid] = {
                    "retired_by": r["retired_by"],
                    "retirement_reason_code": r["retirement_reason_code"],
                    "retirement_reason_text": r["retirement_reason_text"],
                    "net_pnl_usd": _d(r["net_pnl_usd"]),
                    "starting_balance_contrib_usd": _d(r["starting_balance_contrib_usd"]),
                    "vaulted_profit_contrib_usd": _d(r["vaulted_profit_contrib_usd"]),
                    "shadow_net_pnl_usd": _d(r["shadow_net_pnl_usd"]),
                    "shadow_sessions": set(json.loads(str(r["shadow_sessions_json"]) or "[]")),
                    "shadow_days": set(json.loads(str(r["shadow_days_json"]) or "[]")),
                    "trades_since_quarantine": int(r["trades_since_quarantine"]),
                    "recovery_sum_r": _d(r["recovery_sum_r"]),
                    "reentry_count": int(r["reentry_count"]),
                    "sim_valve_checks": int(r["sim_valve_checks"]),
                    "sim_valve_passes": int(r["sim_valve_passes"]),
                    "created_at_utc": str(r["created_at_utc"]),
                    "promoted_at_utc": str(r["promoted_at_utc"]),
                    "quarantined_at_utc": r["quarantined_at_utc"],
                    "cooldown_until_utc": r["cooldown_until_utc"],
                    "last_trade_at_utc": r["last_trade_at_utc"],
                }
            self._shadow_trades_total = shadow_total
            cnt_row = conn.execute("SELECT COUNT(*) AS c FROM ai_field_notes").fetchone()
            self._notes_total = int(cnt_row["c"]) if cnt_row is not None else 0
            note_rows = conn.execute(
                "SELECT * FROM ai_field_notes ORDER BY seq_no DESC LIMIT 100"
            ).fetchall()
            self._notes_cache.clear()
            for nr in note_rows:
                self._notes_cache.append(dict(nr))
            self._audit_head_sha256 = (
                str(note_rows[0]["entry_sha256"]) if note_rows else GENESIS_SHA256
            )
            attr_row = conn.execute(
                "SELECT entry_sha256 FROM strategy_trade_attribution ORDER BY attr_seq DESC LIMIT 1"
            ).fetchone()
            self._attr_head_sha256 = (
                str(attr_row["entry_sha256"]) if attr_row is not None else GENESIS_SHA256
            )
        finally:
            conn.close()

    def _insert_note_tx(
        self,
        conn: sqlite3.Connection,
        *,
        now: datetime,
        author_role: str,
        note_category: str,
        headline: str,
        body_plain_english: str,
        related_strategy_id: str | None,
        related_symbol: str | None,
        related_ticket: str | None,
        session_region: str | None,
        entry_regime: str | None,
        lesson_tags: str | None,
        impact_pnl_usd: Decimal | None,
        realized_r: Decimal | None,
        pinned_by_owner: bool,
    ) -> dict[str, Any]:
        last_row = conn.execute(
            "SELECT seq_no, entry_sha256 FROM ai_field_notes ORDER BY seq_no DESC LIMIT 1"
        ).fetchone()
        prev_h = str(last_row["entry_sha256"]) if last_row is not None else GENESIS_SHA256
        next_seq = (int(last_row["seq_no"]) + 1) if last_row is not None else 1
        note_id = f"note-{next_seq:06d}"
        obs_utc = _iso_utc(now)
        obs_pac = us_pacific_text(now)
        clean_head = _ascii_clean(headline, max_len=120)
        clean_body = _ascii_clean(body_plain_english, max_len=500)
        pnl_txt = _q2_str(impact_pnl_usd) if impact_pnl_usd is not None else None
        r_txt = _q4_str(realized_r) if realized_r is not None else None
        payload = {
            "note_id": note_id,
            "observed_at_utc": obs_utc,
            "author_role": author_role,
            "note_category": note_category,
            "headline": clean_head,
            "body_plain_english": clean_body,
            "related_strategy_id": related_strategy_id,
            "related_symbol": related_symbol,
            "related_ticket": related_ticket,
            "impact_pnl_usd": pnl_txt,
            "pinned_by_owner": bool(pinned_by_owner),
            "prev_sha256": prev_h,
        }
        entry_h = sha256(canonical_bytes(payload)).hexdigest()
        conn.execute(
            """
            INSERT INTO ai_field_notes (
                note_id, observed_at_utc, observed_at_pacific, author_role, note_category,
                headline, body_plain_english, related_strategy_id, related_symbol, related_ticket,
                session_region, entry_regime, lesson_tags, impact_pnl_usd, realized_r,
                pinned_by_owner, acknowledged_by_ai, prev_sha256, entry_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                note_id,
                obs_utc,
                obs_pac,
                author_role,
                note_category,
                clean_head,
                clean_body,
                related_strategy_id,
                related_symbol,
                related_ticket,
                session_region,
                entry_regime,
                lesson_tags,
                pnl_txt,
                r_txt,
                1 if pinned_by_owner else 0,
                1 if author_role == "AI_STRATEGIST" else 0,
                prev_h,
                entry_h,
            ),
        )
        # Bounded FIFO pruning keeping pinned owner directives intact
        total_c = int(conn.execute("SELECT COUNT(*) AS c FROM ai_field_notes").fetchone()["c"])
        if total_c > MAX_FIELD_NOTES_RETENTION:
            excess = total_c - MAX_FIELD_NOTES_RETENTION
            conn.execute(
                """
                DELETE FROM ai_field_notes WHERE seq_no IN (
                    SELECT seq_no FROM ai_field_notes
                    WHERE pinned_by_owner = 0
                    ORDER BY seq_no ASC LIMIT ?
                )
                """,
                (excess,),
            )
        return {
            "note_id": note_id,
            "seq_no": next_seq,
            "observed_at_utc": obs_utc,
            "observed_at_pacific": obs_pac,
            "author_role": author_role,
            "note_category": note_category,
            "headline": clean_head,
            "body_plain_english": clean_body,
            "related_strategy_id": related_strategy_id,
            "related_symbol": related_symbol,
            "related_ticket": related_ticket,
            "impact_pnl_usd": pnl_txt,
            "pinned_by_owner": bool(pinned_by_owner),
            "acknowledged_by_ai": author_role == "AI_STRATEGIST",
            "entry_sha256": entry_h,
        }

    # -----------------------------------------------------------------------
    # Candidate Tournament & O(1) Prompt Memory Injection
    # -----------------------------------------------------------------------

    def rank_market_candidates(
        self,
        *,
        markets: Mapping[str, Mapping[str, Any]],
        tick_history: Mapping[str, Sequence[tuple[Decimal, Decimal]]],
        regime_classifier: Callable[[Sequence[Decimal], Decimal, Decimal], Any],
        default_sl_lookup: Callable[[str], Decimal],
        starting_balance_usd: Decimal,
        current_equity_usd: Decimal,
        vaulted_profit_usd: Decimal,
        sweep_ratio: Decimal,
        drawdown_ratio: Decimal,
        user_risk_cap_pct: Decimal,
        is_live_mode: bool,
        session_code: str,
        cycle_id: str,
        now: datetime | None = None,
    ) -> list[StrategyCandidateDecision]:
        """Evaluate all 20 markets across all ACTIVE strategies and return best-first ranked candidates."""
        ts = self._now(now)
        e0 = max(Decimal("1.00"), starting_balance_usd)
        et = max(Decimal("1.00"), current_equity_usd)
        user_cap_frac = max(Decimal("0.0001"), user_risk_cap_pct / Decimal("100"))

        with self._lock:
            active_sids = [sid for sid, st in self._statuses.items() if st is ArmStatus.ACTIVE]
            if not active_sids:
                return []
            n_tot_active = max(
                _TWO,
                sum((self._strat_stats[sid].s0 for sid in active_sids), _ZERO),
            )
            decisions: list[StrategyCandidateDecision] = []

            for sym, info in markets.items():
                if not isinstance(info, Mapping):
                    continue
                try:
                    bid = _d(info["bid"], "bid")
                    ask = _d(info["ask"], "ask")
                except (KeyError, ContractError):
                    continue
                if ask <= bid or bid <= _ZERO:
                    continue
                spread = ask - bid
                hist = list(tick_history.get(sym, ()))
                mids = [(b + a) / _TWO for b, a in hist[-50:] if a >= b and (b + a) > _ZERO]
                if len(mids) < 3:
                    raw_bars = info.get("candles_m1") or ()
                    mids = [
                        _d(b.get("c"))
                        for b in list(raw_bars)[-30:]
                        if isinstance(b, Mapping) and b.get("c") is not None
                    ]
                if len(mids) < 3:
                    continue
                norm_sl = default_sl_lookup(sym)
                reg_res = regime_classifier(mids, spread, norm_sl)
                snap = self._analyzer.build_snapshot(
                    symbol=sym,
                    bid=bid,
                    ask=ask,
                    mids=mids,
                    candles_m1=info.get("candles_m1"),
                    regime=str(reg_res.regime),
                    direction=reg_res.direction,
                    normal_sl_distance=norm_sl,
                    session_code=session_code,
                    now=ts,
                )
                if snap.stand_aside_code is not None:
                    continue

                for sid in active_sids:
                    genome = self._genomes[sid]
                    cand_side, note = genome.evaluate_signal(snap)
                    if cand_side is None:
                        continue
                    strat_st = self._strat_stats[sid]
                    cells = self._cell_stats.get(sid, {})
                    reg_id = f"REG:{snap.regime}"
                    cell_id = f"CELL:{snap.regime}:{snap.session_region}"
                    reg_st = cells.get(reg_id, DiscountedStats())
                    cell_st = cells.get(cell_id, DiscountedStats())
                    mu_cell, var_cell, n_eff_cell = hierarchical_shrinkage(
                        strat_st=strat_st,
                        reg_st=reg_st,
                        cell_st=cell_st,
                        archetype=genome.archetype,
                    )
                    bounds = compute_ucb_lcb(
                        mu_cell=mu_cell,
                        var_cell=var_cell,
                        n_eff_cell=n_eff_cell,
                        n_tot_active=n_tot_active,
                        cycle_arm_seed=f"{cycle_id}:{sid}:{sym}",
                    )
                    if bounds["ucb"] <= _ZERO:
                        continue
                    m_cell = derived_metrics(cell_st, genome.archetype)
                    w_mult = compute_risk_weight_multiplier(
                        status=ArmStatus.ACTIVE,
                        mu_cell=mu_cell,
                        var_cell=var_cell,
                        se_cell=bounds["se"],
                        mfe_capture=m_cell["mfe_capture"],
                        mfe_sample_weight=cell_st.s0,
                        cusum_neg=cell_st.cusum_neg,
                        drawdown_ratio=drawdown_ratio,
                        is_live_mode=is_live_mode,
                    )
                    if w_mult <= _ZERO:
                        continue
                    util_score = expected_marginal_utility_score(
                        mu_cell=mu_cell,
                        var_cell=var_cell,
                        ucb_cell=bounds["ucb"],
                        risk_frac=w_mult * user_cap_frac,
                        user_cap_frac=user_cap_frac,
                        e0_usd=e0,
                        et_usd=et,
                        vt_usd=vaulted_profit_usd,
                        sweep_ratio=sweep_ratio,
                        drawdown_ratio=drawdown_ratio,
                    )
                    # Add microstructure quality bonus so clean high-KER / tight-spread setups rank ahead
                    fit_bonus = (
                        snap.session_liquidity_score * Decimal("0.15")
                        + (
                            (Decimal("1.00") - snap.efficiency_ratio) * Decimal("0.10")
                            if genome.direction_mode == "FADE"
                            else snap.efficiency_ratio * Decimal("0.15")
                        )
                        - snap.spread_to_sl_ratio * Decimal("0.25")
                    ).quantize(_Q4, rounding=ROUND_HALF_UP)
                    total_score = (util_score + fit_bonus).quantize(_Q4, rounding=ROUND_HALF_UP)
                    sl_dist, tp_dist = genome.compute_sl_tp_distances(snap)
                    eff_regime = (
                        snap.regime
                        if snap.regime in ("STRONG_TREND", "TREND_IGNITION")
                        else "TREND_IGNITION"
                    )
                    decisions.append(
                        StrategyCandidateDecision(
                            allowed=True,
                            strategy_id=sid,
                            display_name=genome.display_name,
                            symbol=sym,
                            side=cand_side,
                            regime=eff_regime,
                            risk_weight_multiplier=w_mult,
                            sl_distance=sl_dist,
                            tp_distance=tp_dist,
                            derisk_trigger_r=genome.derisk_trigger_r,
                            derisk_stop_r=genome.derisk_stop_r,
                            be_trigger_r=genome.be_trigger_r,
                            be_lock_r=genome.be_lock_r,
                            trail_activate_r=genome.trail_activate_r,
                            trail_dist_r=genome.trail_dist_r,
                            allow_pyramiding=genome.allow_pyramiding,
                            setup_note=note,
                            utility_score=total_score,
                            snapshot=snap,
                        )
                    )

            decisions.sort(key=lambda d: (d.utility_score, d.risk_weight_multiplier), reverse=True)
            return decisions

    def build_prompt_memory_block(
        self,
        *,
        symbol: str,
        session_region: str,
        entry_regime: str,
        strategy_id: str | None = None,
        max_bytes: int = 1200,
    ) -> str:
        """O(1) pure-ASCII prompt recall (<= 400 tokens, 0 SQLite queries, >= 2 cautionary slots)."""
        with self._lock:
            scored_all: list[tuple[int, dict[str, Any]]] = []
            for n in self._notes_cache:
                sc = 0
                if bool(n.get("pinned_by_owner")):
                    sc += 100
                if n.get("related_symbol") == symbol:
                    sc += 40
                if n.get("session_region") == session_region:
                    sc += 25
                if n.get("entry_regime") == entry_regime:
                    sc += 20
                if strategy_id and n.get("related_strategy_id") == strategy_id:
                    sc += 15
                imp = n.get("impact_pnl_usd")
                is_neg = isinstance(imp, str) and imp.startswith("-")
                if is_neg:
                    sc += 22
                scored_all.append((sc, n))

            scored_all.sort(key=lambda x: (x[0], int(x[1].get("seq_no", 0))), reverse=True)
            neg_notes = [n for _, n in scored_all if isinstance(n.get("impact_pnl_usd"), str) and str(n.get("impact_pnl_usd")).startswith("-")][:2]
            picked_ids = {str(n["note_id"]) for n in neg_notes}
            picked = list(neg_notes)
            for _, n in scored_all:
                if len(picked) >= 5:
                    break
                nid = str(n["note_id"])
                if nid not in picked_ids:
                    picked.append(n)
                    picked_ids.add(nid)

            lines = ["FIELD_NOTES:"]
            for idx, n in enumerate(picked, 1):
                role = "OWNER" if n.get("author_role") == "OWNER_WAKIL" else "AI"
                sym_lbl = n.get("related_symbol") or "ALL"
                lines.append(
                    _ascii_clean(
                        f"{idx}.[{role}|{sym_lbl}] {n.get('headline', '')}: {n.get('body_plain_english', '')}",
                        max_len=190,
                    )
                )
            active_summaries: list[str] = []
            for sid, st in self._statuses.items():
                if st is ArmStatus.ACTIVE:
                    s_st = self._strat_stats[sid]
                    m = derived_metrics(s_st, self._genomes[sid].archetype)
                    active_summaries.append(
                        f"{sid}(N={s_st.n_trades},PF={m['pf'].quantize(_Q2)},Exp={m['e_r'].quantize(_Q2)}R)"
                    )
            if active_summaries:
                lines.append("ACTIVE_STRATEGIES: " + ", ".join(active_summaries[:4]))
            text = "\n".join(lines)
            enc = text.encode("ascii", errors="ignore")[:max_bytes]
            return enc.decode("ascii")

    # -----------------------------------------------------------------------
    # 50ms Excursion Tracking & Post-Trade Learning / Mutation
    # -----------------------------------------------------------------------

    def register_open_trade(
        self,
        *,
        ticket: str,
        strategy_id: str,
        symbol: str,
        side: Side,
        entry_price: Decimal,
        initial_sl_distance: Decimal,
        risk_budget_usd: Decimal,
        snapshot: MarketMicrostructureSnapshot | None,
        now: datetime | None = None,
    ) -> None:
        ts = self._now(now)
        with self._lock:
            eff_sid = strategy_id if strategy_id in self._genomes else "S1_M5_ALIGNED_TREND_PULLBACK"
            genome = self._genomes[eff_sid]
            self._active_tickets[str(ticket)] = {
                "strategy_id": eff_sid,
                "symbol": symbol,
                "side": side,
                "entry_price": entry_price,
                "initial_sl_distance": max(tick_size_for(symbol), initial_sl_distance),
                "risk_budget_usd": max(Decimal("1.00"), risk_budget_usd),
                "peak_mfe_r": _ZERO,
                "worst_mae_r": _ZERO,
                "derisk_trigger_r": genome.derisk_trigger_r,
                "derisk_stop_r": genome.derisk_stop_r,
                "be_trigger_r": genome.be_trigger_r,
                "be_lock_r": genome.be_lock_r,
                "trail_activate_r": genome.trail_activate_r,
                "trail_dist_r": genome.trail_dist_r,
                "session_region": snapshot.session_region if snapshot else "NEW_YORK",
                "entry_regime": snapshot.regime if snapshot else "STRONG_TREND",
                "efficiency_ratio": snapshot.efficiency_ratio if snapshot else Decimal("0.50"),
                "chop_index": snapshot.chop_index if snapshot else Decimal("45.00"),
                "is_holiday_window": snapshot.is_holiday_window if snapshot else False,
                "ema_stretch_sl_mult": snapshot.ema_stretch_sl_mult if snapshot else _ZERO,
                "opened_at_utc": _iso_utc(ts),
            }

    def protection_profile_for_ticket(self, ticket: str) -> dict[str, Decimal] | None:
        with self._lock:
            info = self._active_tickets.get(str(ticket))
            if info is None:
                return None
            return {
                "derisk_trigger_r": info["derisk_trigger_r"],
                "derisk_stop_r": info["derisk_stop_r"],
                "be_trigger_r": info["be_trigger_r"],
                "be_lock_r": info["be_lock_r"],
                "trail_activate_r": info["trail_activate_r"],
                "trail_dist_r": info["trail_dist_r"],
            }

    def on_open_position_tick_fast(
        self,
        *,
        ticket: str,
        side: Side,
        entry_price: Decimal,
        initial_sl_distance: Decimal,
        bid: Decimal,
        ask: Decimal,
    ) -> None:
        """Zero-SQLite-I/O 50ms MFE/MAE excursion tracker."""
        sl_d = initial_sl_distance if initial_sl_distance > _ZERO else Decimal("1")
        curr_px = bid if side is Side.BUY else ask
        fav = (curr_px - entry_price) if side is Side.BUY else (entry_price - curr_px)
        r_now = fav / sl_d
        with self._lock:
            rec = self._active_tickets.get(str(ticket))
            if rec is None:
                return
            if r_now > rec["peak_mfe_r"]:
                rec["peak_mfe_r"] = r_now
            if r_now < _ZERO and (-r_now) > rec["worst_mae_r"]:
                rec["worst_mae_r"] = -r_now

    def record_trade_close(
        self,
        *,
        source_channel: str,
        trade_id: str,
        symbol: str,
        side: Side,
        net_pnl_usd: Decimal,
        current_equity_usd: Decimal,
        starting_principal_usd: Decimal,
        vault_sweep_ratio: Decimal,
        strategy_id: str | None = None,
        initial_risk_usd: Decimal | None = None,
        session_region: str | None = None,
        entry_regime: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Persist post-trade attribution, write AI Field Note, update CUSUM/Bandit, and spawn shadow mutants if needed."""
        ts = self._now(now)
        ts_iso = _iso_utc(ts)
        trade_uid = _ascii_clean(f"{source_channel}:{trade_id}", max_len=96)

        with self._lock:
            popped = self._active_tickets.pop(str(trade_id), None)
            eff_sid = (
                strategy_id
                if (strategy_id and strategy_id in self._genomes)
                else (str(popped["strategy_id"]) if popped else "S1_M5_ALIGNED_TREND_PULLBACK")
            )
            if eff_sid not in self._genomes:
                eff_sid = "S1_M5_ALIGNED_TREND_PULLBACK"
            genome = self._genomes[eff_sid]

            risk_usd = (
                initial_risk_usd
                if (initial_risk_usd is not None and initial_risk_usd > _ZERO)
                else (
                    popped["risk_budget_usd"]
                    if popped is not None
                    else max(Decimal("25.00"), starting_principal_usd * Decimal("0.01"))
                )
            )
            r_mult = (net_pnl_usd / risk_usd).quantize(_Q4, rounding=ROUND_HALF_UP)
            peak_mfe_r = (
                popped["peak_mfe_r"]
                if popped is not None
                else (max(_ZERO, r_mult) if r_mult > _ZERO else Decimal("0.20"))
            )
            worst_mae_r = (
                popped["worst_mae_r"]
                if popped is not None
                else (abs(r_mult) if r_mult < _ZERO else Decimal("0.15"))
            )
            sess_reg = session_region or (str(popped["session_region"]) if popped else "NEW_YORK")
            reg_name = entry_regime or (str(popped["entry_regime"]) if popped else "STRONG_TREND")
            er_val = popped["efficiency_ratio"] if popped else Decimal("0.45")
            chop_val = popped["chop_index"] if popped else Decimal("50.00")
            stretch_val = popped["ema_stretch_sl_mult"] if popped else _ZERO

            # Dual-objective split (Starting Balance vs Vaulted Profits)
            e0 = max(Decimal("1.00"), starting_principal_usd)
            et = max(Decimal("0.01"), current_equity_usd)
            if net_pnl_usd <= _ZERO or et <= e0 or vault_sweep_ratio <= _ZERO:
                vault_delta = _ZERO
                bal_delta = net_pnl_usd
            else:
                surplus = max(_ZERO, et - e0)
                eligible = min(net_pnl_usd, surplus)
                vault_delta = (eligible * _clamp(vault_sweep_ratio, _ZERO, _HALF)).quantize(_Q2, rounding=ROUND_HALF_UP)
                bal_delta = net_pnl_usd - vault_delta

            tags, lesson_head, lesson_body = self._synthesize_lesson(
                strategy_id=eff_sid,
                symbol=symbol,
                side=side,
                r_mult=r_mult,
                net_pnl_usd=net_pnl_usd,
                peak_mfe_r=peak_mfe_r,
                er_val=er_val,
                chop_val=chop_val,
                stretch_val=stretch_val,
                bal_delta=bal_delta,
                vault_delta=vault_delta,
            )

            conn = self._connect_rw()
            try:
                dup = conn.execute(
                    "SELECT attr_seq FROM strategy_trade_attribution WHERE trade_uid = ?",
                    (trade_uid,),
                ).fetchone()
                if dup is not None:
                    return {"already_recorded": True, "strategy_id": eff_sid}

                # Update strategy & cell stats (only main LIVE_DEMO channel drives global CUSUM retirement so 5 parallel tiers don't 5x-count a single trade!)
                old_status = self._statuses[eff_sid]
                strat_st = self._strat_stats[eff_sid]
                cells = dict(self._cell_stats.get(eff_sid, {}))
                reg_id = f"REG:{reg_name}"
                cell_id = f"CELL:{reg_name}:{sess_reg}"

                should_advance_bandit = source_channel in ("LIVE_DEMO", "SHADOW_INCUBATOR", "OPTION_B")
                if should_advance_bandit:
                    strat_st = update_stats(strat_st, r_mult, mfe_r=peak_mfe_r, mae_r=worst_mae_r)
                    cells[reg_id] = update_stats(cells.get(reg_id, DiscountedStats()), r_mult, mfe_r=peak_mfe_r, mae_r=worst_mae_r)
                    cells[cell_id] = update_stats(cells.get(cell_id, DiscountedStats()), r_mult, mfe_r=peak_mfe_r, mae_r=worst_mae_r)

                meta = dict(self._meta[eff_sid])
                if source_channel == "SHADOW_INCUBATOR":
                    meta["shadow_net_pnl_usd"] = meta["shadow_net_pnl_usd"] + net_pnl_usd
                    meta["shadow_sessions"].add(sess_reg)
                    meta["shadow_days"].add(ts_iso[:10])
                    if old_status is ArmStatus.QUARANTINED_SHADOW:
                        meta["trades_since_quarantine"] = int(meta["trades_since_quarantine"]) + 1
                        meta["recovery_sum_r"] = meta["recovery_sum_r"] + r_mult
                else:
                    meta["net_pnl_usd"] = meta["net_pnl_usd"] + net_pnl_usd
                    meta["starting_balance_contrib_usd"] = meta["starting_balance_contrib_usd"] + bal_delta
                    meta["vaulted_profit_contrib_usd"] = meta["vaulted_profit_contrib_usd"] + vault_delta
                meta["last_trade_at_utc"] = ts_iso

                new_status = old_status
                trans_reason = "ACTIVE_HEALTHY"
                if should_advance_bandit:
                    new_status, trans_reason = evaluate_stopping_rules(
                        current_status=old_status,
                        cell_st=cells.get(cell_id, strat_st),
                        strat_st=strat_st,
                        archetype=genome.archetype,
                        last_r=r_mult,
                        trades_since_quarantine=int(meta["trades_since_quarantine"]),
                        recovery_sum_r=meta["recovery_sum_r"],
                        reentry_count=int(meta["reentry_count"]),
                        distinct_sessions=max(1, len(meta["shadow_sessions"])),
                        distinct_days=max(1, len(meta["shadow_days"])),
                    )

                if new_status is not old_status:
                    if new_status in (ArmStatus.QUARANTINED_SHADOW, ArmStatus.DECOMMISSIONED):
                        meta["retired_by"] = "AI_SELF_AUDIT"
                        meta["retirement_reason_code"] = _ascii_clean(trans_reason.split()[0], max_len=60).upper()
                        meta["retirement_reason_text"] = _ascii_clean(
                            f"AI retired {genome.display_name} ({trans_reason}) after {symbol} {r_mult}R to protect starting balance.",
                            max_len=260,
                        )
                        meta["quarantined_at_utc"] = ts_iso
                        meta["cooldown_until_utc"] = _iso_utc(ts + timedelta(hours=12))
                        meta["trades_since_quarantine"] = 0
                        meta["recovery_sum_r"] = _ZERO
                    elif new_status is ArmStatus.ACTIVE:
                        meta["promoted_at_utc"] = ts_iso
                        if old_status is ArmStatus.QUARANTINED_SHADOW:
                            meta["reentry_count"] = int(meta["reentry_count"]) + 1

                # Mark unacknowledged pinned owner notes as acknowledged once incorporated
                conn.execute(
                    "UPDATE ai_field_notes SET acknowledged_by_ai = 1 WHERE acknowledged_by_ai = 0 AND author_role = 'OWNER_WAKIL'"
                )

                # Persist attribution row
                last_attr = conn.execute(
                    "SELECT entry_sha256 FROM strategy_trade_attribution ORDER BY attr_seq DESC LIMIT 1"
                ).fetchone()
                prev_attr_h = str(last_attr["entry_sha256"]) if last_attr is not None else GENESIS_SHA256
                attr_payload = {
                    "trade_uid": trade_uid,
                    "source_channel": source_channel,
                    "strategy_id": eff_sid,
                    "symbol": symbol,
                    "side": side.value,
                    "net_pnl_usd": _q2_str(net_pnl_usd),
                    "realized_r": _q4_str(r_mult),
                    "starting_balance_delta_usd": _q2_str(bal_delta),
                    "vaulted_profit_delta_usd": _q2_str(vault_delta),
                    "closed_at_utc": ts_iso,
                    "prev_sha256": prev_attr_h,
                }
                attr_h = sha256(canonical_bytes(attr_payload)).hexdigest()
                conn.execute(
                    """
                    INSERT INTO strategy_trade_attribution (
                        trade_uid, source_channel, strategy_id, symbol, side, session_region,
                        entry_regime, net_pnl_usd, realized_r, peak_mfe_r, worst_mae_r,
                        starting_balance_delta_usd, vaulted_profit_delta_usd, closed_at_utc,
                        prev_sha256, entry_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trade_uid,
                        source_channel,
                        eff_sid,
                        symbol,
                        side.value,
                        sess_reg,
                        reg_name,
                        _q2_str(net_pnl_usd),
                        _q4_str(r_mult),
                        _q4_str(peak_mfe_r),
                        _q4_str(worst_mae_r),
                        _q2_str(bal_delta),
                        _q2_str(vault_delta),
                        ts_iso,
                        prev_attr_h,
                        attr_h,
                    ),
                )

                # Write post-trade Field Note
                if source_channel in ("LIVE_DEMO", "OPTION_B") or new_status is not old_status:
                    self._insert_note_tx(
                        conn,
                        now=ts,
                        author_role="AI_STRATEGIST",
                        note_category="TRADE_LESSON",
                        headline=lesson_head,
                        body_plain_english=lesson_body,
                        related_strategy_id=eff_sid,
                        related_symbol=symbol,
                        related_ticket=str(trade_id),
                        session_region=sess_reg,
                        entry_regime=reg_name,
                        lesson_tags=tags,
                        impact_pnl_usd=net_pnl_usd,
                        realized_r=r_mult,
                        pinned_by_owner=False,
                    )

                if new_status is not old_status:
                    cat = (
                        "STRATEGY_PROMOTED"
                        if new_status is ArmStatus.ACTIVE
                        else "STRATEGY_QUARANTINED"
                    )
                    self._insert_note_tx(
                        conn,
                        now=ts,
                        author_role="AI_STRATEGIST",
                        note_category=cat,
                        headline=f"{genome.display_name} -> {new_status.value}",
                        body_plain_english=meta.get("retirement_reason_text")
                        or f"Strategy graduated to {new_status.value} ({trans_reason}).",
                        related_strategy_id=eff_sid,
                        related_symbol=symbol,
                        related_ticket=str(trade_id),
                        session_region=sess_reg,
                        entry_regime=reg_name,
                        lesson_tags=trans_reason,
                        impact_pnl_usd=net_pnl_usd,
                        realized_r=r_mult,
                        pinned_by_owner=False,
                    )

                conn.execute(
                    """
                    UPDATE strategy_registry SET
                        status = ?, retired_by = ?, retirement_reason_code = ?, retirement_reason_text = ?,
                        strat_stats_json = ?, cell_stats_json = ?,
                        net_pnl_usd = ?, starting_balance_contrib_usd = ?, vaulted_profit_contrib_usd = ?,
                        shadow_net_pnl_usd = ?, shadow_sessions_json = ?, shadow_days_json = ?,
                        trades_since_quarantine = ?, recovery_sum_r = ?, reentry_count = ?,
                        promoted_at_utc = ?, quarantined_at_utc = ?, cooldown_until_utc = ?,
                        last_trade_at_utc = ?, updated_at_utc = ?
                    WHERE strategy_id = ?
                    """,
                    (
                        new_status.value,
                        meta["retired_by"],
                        meta["retirement_reason_code"],
                        meta["retirement_reason_text"],
                        json.dumps(strat_st.to_dict(), sort_keys=True),
                        json.dumps({k: v.to_dict() for k, v in cells.items()}, sort_keys=True),
                        _q2_str(meta["net_pnl_usd"]),
                        _q2_str(meta["starting_balance_contrib_usd"]),
                        _q2_str(meta["vaulted_profit_contrib_usd"]),
                        _q2_str(meta["shadow_net_pnl_usd"]),
                        json.dumps(sorted(meta["shadow_sessions"])),
                        json.dumps(sorted(meta["shadow_days"])),
                        int(meta["trades_since_quarantine"]),
                        _q4_str(meta["recovery_sum_r"]),
                        int(meta["reentry_count"]),
                        str(meta["promoted_at_utc"]),
                        meta["quarantined_at_utc"],
                        meta["cooldown_until_utc"],
                        ts_iso,
                        ts_iso,
                        eff_sid,
                    ),
                )

                # Real-Time Strategy Synthesizer: spawn mutated shadow variant when quarantined or negative lesson repeats
                spawned_id: str | None = None
                if (
                    new_status in (ArmStatus.QUARANTINED_SHADOW, ArmStatus.DECOMMISSIONED)
                    or (r_mult <= Decimal("-0.80") and strat_st.cusum_neg >= CUSUM_WARN)
                ):
                    spawned_id = self._spawn_shadow_variant_tx(
                        conn, parent=genome, lesson_tags=tags, trigger_symbol=symbol, now=ts
                    )

                conn.commit()
            finally:
                conn.close()

            self._reload_cache_from_ro()
            return {
                "already_recorded": False,
                "strategy_id": eff_sid,
                "status_before": old_status.value,
                "status_after": new_status.value,
                "transition_reason": trans_reason,
                "realized_r": _q4_str(r_mult),
                "starting_balance_delta_usd": _q2_str(bal_delta),
                "vaulted_profit_delta_usd": _q2_str(vault_delta),
                "spawned_shadow_strategy_id": spawned_id,
            }

    @staticmethod
    def _synthesize_lesson(
        *,
        strategy_id: str,
        symbol: str,
        side: Side,
        r_mult: Decimal,
        net_pnl_usd: Decimal,
        peak_mfe_r: Decimal,
        er_val: Decimal,
        chop_val: Decimal,
        stretch_val: Decimal,
        bal_delta: Decimal,
        vault_delta: Decimal,
    ) -> tuple[str, str, str]:
        if r_mult > _ZERO:
            tag = "CLEAN_RUNNER" if r_mult >= _ONE else "CONTROLLED_WIN"
            head = f"{symbol} {side.value} won +${_q2_str(net_pnl_usd)} (+{_q2_str(r_mult)}R)"
            body = (
                f"{strategy_id} captured +{_q2_str(r_mult)}R (peak +{_q2_str(peak_mfe_r)}R, KER={_q2_str(er_val)}). "
                f"Added +${_q2_str(bal_delta)} to starting balance and +${_q2_str(vault_delta)} to vaulted profits."
            )
            return tag, head, body
        if peak_mfe_r >= Decimal("0.60"):
            tag = "WINNER_GIVEBACK"
            head = f"{symbol} {side.value} gave back +{_q2_str(peak_mfe_r)}R into {_q2_str(r_mult)}R"
            body = (
                f"Reached +{_q2_str(peak_mfe_r)}R before reversing (${_q2_str(net_pnl_usd)}). "
                f"Tightening Two-Step de-risk trigger on shadow challenger to lock gains earlier."
            )
            return tag, head, body
        if er_val < Decimal("0.28") or chop_val >= Decimal("58.00"):
            tag = "HIGH_CHOP"
            head = f"{symbol} {side.value} stopped in chop (KER={_q2_str(er_val)}, CHOP={_q2_str(chop_val)})"
            body = (
                f"Low directional efficiency ({_q2_str(er_val)}) caused whipsaw (${_q2_str(net_pnl_usd)}). "
                f"Raising minimum KER filter and routing sideways tape to Range Extreme Fade."
            )
            return tag, head, body
        if stretch_val > Decimal("0.50"):
            tag = "TOP_CHASE"
            head = f"{symbol} {side.value} pullback entry too shallow (stretch={_q2_str(stretch_val)}xSL)"
            body = (
                f"Entered {_q2_str(stretch_val)}xSL away from EMA21 (${_q2_str(net_pnl_usd)}). "
                f"Tightening pullback stretch collar on evolved shadow strategy."
            )
            return tag, head, body
        tag = "NORMAL_STOP"
        head = f"{symbol} {side.value} controlled stop (${_q2_str(net_pnl_usd)}, {_q2_str(r_mult)}R)"
        body = (
            f"{strategy_id} took bounded {_q2_str(r_mult)}R stop on {symbol}; "
            f"monitoring CUSUM drift while preserving risk discipline."
        )
        return tag, head, body

    def _spawn_shadow_variant_tx(
        self,
        conn: sqlite3.Connection,
        *,
        parent: StrategyGenome,
        lesson_tags: str,
        trigger_symbol: str,
        now: datetime,
    ) -> str | None:
        shadow_cnt = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM strategy_registry WHERE status = ?",
                (ArmStatus.INCUBATING_SHADOW.value,),
            ).fetchone()["c"]
        )
        if shadow_cnt >= MAX_SHADOW_STRATEGIES:
            return None
        self._evolved_seq += 1
        base_ker = parent.ker_min
        base_stretch = parent.max_ema_stretch_sl_mult
        base_derisk = parent.derisk_trigger_r
        base_be = parent.be_trigger_r
        base_sl_mult = parent.sl_atr_mult
        direction_mode = parent.direction_mode
        trigger = parent.entry_trigger
        arch = parent.archetype

        if "WINNER_GIVEBACK" in lesson_tags:
            base_derisk = max(Decimal("0.45"), parent.derisk_trigger_r - Decimal("0.10"))
            base_be = max(Decimal("0.70"), parent.be_trigger_r - Decimal("0.10"))
            rationale = f"Tightened de-risk ratchet to +{base_derisk}R and BE to +{base_be}R after {trigger_symbol} giveback."
        elif "HIGH_CHOP" in lesson_tags:
            if parent.direction_mode == "MOMENTUM":
                base_ker = min(Decimal("0.55"), parent.ker_min + Decimal("0.08"))
                rationale = f"Raised trend efficiency floor KER>={base_ker} to reject {trigger_symbol} sideways chop."
            else:
                rationale = f"Tightened range-fade z-score filter on {trigger_symbol} chop."
        elif "TOP_CHASE" in lesson_tags:
            base_stretch = max(Decimal("0.30"), parent.max_ema_stretch_sl_mult - Decimal("0.15"))
            rationale = f"Tightened EMA21 pullback collar to {base_stretch}xSL after {trigger_symbol} stretch loss."
        else:
            base_sl_mult = min(Decimal("1.90"), parent.sl_atr_mult + Decimal("0.15"))
            rationale = f"Calibrated ATR stop buffer to {base_sl_mult}xATR for {trigger_symbol} volatility."

        digest = sha256(f"{parent.strategy_id}:{lesson_tags}:{base_ker}:{base_stretch}:{base_derisk}:{base_sl_mult}".encode("utf-8")).hexdigest()[:8]
        new_id = f"AI_EVOLVED_{digest.upper()}"
        exists = conn.execute("SELECT 1 FROM strategy_registry WHERE strategy_id = ?", (new_id,)).fetchone()
        if exists is not None:
            return None

        child = StrategyGenome(
            strategy_id=new_id,
            display_name=_ascii_clean(f"AI Evolved {parent.display_name[:36]} ({digest[:4].upper()})", max_len=90),
            version=parent.version + 1,
            origin="AI_EVOLVED",
            archetype=arch,
            direction_mode=direction_mode,
            entry_trigger=trigger,
            target_markets=parent.target_markets,
            preferred_regimes=parent.preferred_regimes,
            allowed_sessions=parent.allowed_sessions,
            ker_min=base_ker,
            ker_max=parent.ker_max,
            chop_min=parent.chop_min,
            chop_max=parent.chop_max,
            min_liquidity_score=min(Decimal("0.75"), parent.min_liquidity_score + Decimal("0.05")),
            max_spread_sl_ratio=parent.max_spread_sl_ratio,
            max_ema_stretch_sl_mult=base_stretch,
            bb_z_threshold=parent.bb_z_threshold,
            sl_atr_mult=base_sl_mult,
            rr_target=parent.rr_target,
            derisk_trigger_r=base_derisk,
            derisk_stop_r=parent.derisk_stop_r,
            be_trigger_r=base_be,
            be_lock_r=parent.be_lock_r,
            trail_activate_r=max(base_be + Decimal("0.20"), parent.trail_activate_r),
            trail_dist_r=parent.trail_dist_r,
            allow_pyramiding=parent.allow_pyramiding,
            hypothesis_plain_english=_ascii_clean(rationale, max_len=260),
        )
        now_iso = _iso_utc(now)
        conn.execute(
            """
            INSERT INTO strategy_registry (
                strategy_id, genome_json, status, strat_stats_json, cell_stats_json,
                created_at_utc, promoted_at_utc, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                child.strategy_id,
                json.dumps(child.to_dict(), sort_keys=True),
                ArmStatus.INCUBATING_SHADOW.value,
                json.dumps(DiscountedStats().to_dict(), sort_keys=True),
                "{}",
                now_iso,
                now_iso,
                now_iso,
            ),
        )
        self._insert_note_tx(
            conn,
            now=now,
            author_role="AI_STRATEGIST",
            note_category="STRATEGY_SHADOW_CREATED",
            headline=f"Designed new shadow strategy {child.strategy_id}",
            body_plain_english=child.hypothesis_plain_english,
            related_strategy_id=child.strategy_id,
            related_symbol=trigger_symbol,
            related_ticket=None,
            session_region="GLOBAL",
            entry_regime="STRONG_TREND",
            lesson_tags=lesson_tags,
            impact_pnl_usd=None,
            realized_r=None,
            pinned_by_owner=False,
        )
        return child.strategy_id

    # -----------------------------------------------------------------------
    # Real-Time Zero-Risk Shadow Paper Incubator (Live Tick + Spread/Fee Model)
    # -----------------------------------------------------------------------

    def process_shadow_tick(
        self,
        *,
        markets: Mapping[str, Mapping[str, Any]],
        tick_history: Mapping[str, Sequence[tuple[Decimal, Decimal]]],
        regime_classifier: Callable[[Sequence[Decimal], Decimal, Decimal], Any],
        default_sl_lookup: Callable[[str], Decimal],
        now: datetime | None = None,
    ) -> int:
        """Advance all SHADOW_INCUBATING & QUARANTINED strategies on live ticks with realistic costs."""
        ts = self._now(now)
        epoch_s = int(ts.timestamp())
        with self._lock:
            if epoch_s == self._last_shadow_eval_mono_s:
                return 0
            self._last_shadow_eval_mono_s = epoch_s
            shadow_sids = [
                sid
                for sid, st in self._statuses.items()
                if st in (ArmStatus.INCUBATING_SHADOW, ArmStatus.QUARANTINED_SHADOW)
            ]
            if not shadow_sids:
                return 0

            closed_events: list[dict[str, Any]] = []
            # 1. Manage open shadow positions
            for key in list(self._shadow_open.keys()):
                sid, sym = key
                pos = self._shadow_open[key]
                info = markets.get(sym)
                if not isinstance(info, Mapping):
                    continue
                try:
                    bid = _d(info["bid"])
                    ask = _d(info["ask"])
                except (KeyError, ContractError):
                    continue
                if ask <= bid:
                    continue
                spread = ask - bid
                slip = max(tick_size_for(sym) * _HALF, spread * Decimal("0.15"))
                side: Side = pos["side"]
                sl_d: Decimal = pos["sl_distance"]
                entry_px: Decimal = pos["entry_price"]
                exit_px_now = (bid - slip) if side is Side.BUY else (ask + slip)
                fav = (exit_px_now - entry_px) if side is Side.BUY else (entry_px - exit_px_now)
                r_now = fav / sl_d
                if r_now > pos["peak_mfe_r"]:
                    pos["peak_mfe_r"] = r_now
                if r_now < _ZERO and (-r_now) > pos["worst_mae_r"]:
                    pos["worst_mae_r"] = -r_now

                genome = self._genomes.get(sid)
                if genome is not None:
                    if pos["peak_mfe_r"] >= genome.derisk_trigger_r and pos["sl_r"] < genome.derisk_stop_r:
                        pos["sl_r"] = genome.derisk_stop_r
                    if pos["peak_mfe_r"] >= genome.be_trigger_r and pos["sl_r"] < genome.be_lock_r:
                        pos["sl_r"] = genome.be_lock_r
                    if pos["peak_mfe_r"] >= genome.trail_activate_r:
                        cand_trail = pos["peak_mfe_r"] - genome.trail_dist_r
                        if cand_trail > pos["sl_r"]:
                            pos["sl_r"] = cand_trail

                hit_tp = r_now >= pos["tp_r"]
                hit_sl = r_now <= pos["sl_r"]
                if hit_tp or hit_sl:
                    gross_r = pos["tp_r"] if hit_tp else pos["sl_r"]
                    sim_risk_usd = Decimal("50.00")  # 1.00% of $5,000 reference shadow sleeve
                    comm_usd = Decimal("2.48")       # realistic round-turn fee + slippage haircut
                    net_usd = (gross_r * sim_risk_usd) - comm_usd
                    self._shadow_open.pop(key, None)
                    closed_events.append(
                        {
                            "sid": sid,
                            "sym": sym,
                            "side": side,
                            "net_usd": net_usd,
                            "risk_usd": sim_risk_usd,
                            "session_region": pos["session_region"],
                            "entry_regime": pos["entry_regime"],
                            "trade_id": pos["shadow_id"],
                        }
                    )

            # 2. Evaluate new shadow entries (at most 2 open per shadow strategy)
            for sym, info in list(markets.items())[:20]:
                if not isinstance(info, Mapping):
                    continue
                try:
                    bid = _d(info["bid"])
                    ask = _d(info["ask"])
                except (KeyError, ContractError):
                    continue
                if ask <= bid:
                    continue
                spread = ask - bid
                hist = list(tick_history.get(sym, ()))
                mids = [(b + a) / _TWO for b, a in hist[-50:] if a >= b and (b + a) > _ZERO]
                if len(mids) < 5:
                    continue
                norm_sl = default_sl_lookup(sym)
                reg_res = regime_classifier(mids, spread, norm_sl)
                snap = self._analyzer.build_snapshot(
                    symbol=sym,
                    bid=bid,
                    ask=ask,
                    mids=mids,
                    candles_m1=info.get("candles_m1"),
                    regime=str(reg_res.regime),
                    direction=reg_res.direction,
                    normal_sl_distance=norm_sl,
                    session_code="",
                    now=ts,
                )
                if snap.stand_aside_code is not None:
                    continue
                for sid in shadow_sids:
                    if (sid, sym) in self._shadow_open:
                        continue
                    open_for_sid = sum(1 for k_sid, _ in self._shadow_open if k_sid == sid)
                    if open_for_sid >= 2:
                        continue
                    genome = self._genomes[sid]
                    cand_side, _ = genome.evaluate_signal(snap)
                    if cand_side is None:
                        continue
                    self._meta[sid]["sim_valve_checks"] = int(self._meta[sid]["sim_valve_checks"]) + 1
                    if snap.spread_to_sl_ratio > Decimal("0.20"):
                        continue
                    self._meta[sid]["sim_valve_passes"] = int(self._meta[sid]["sim_valve_passes"]) + 1
                    sl_dist, tp_dist = genome.compute_sl_tp_distances(snap)
                    slip = max(tick_size_for(sym) * _HALF, spread * Decimal("0.15"))
                    entry_px = (ask + slip) if cand_side is Side.BUY else (bid - slip)
                    self._shadow_open[(sid, sym)] = {
                        "shadow_id": f"shd-{sid[-6:]}-{sym}-{epoch_s}",
                        "side": cand_side,
                        "entry_price": entry_px,
                        "sl_distance": sl_dist,
                        "sl_r": Decimal("-1.00"),
                        "tp_r": (tp_dist / sl_dist).quantize(_Q4, rounding=ROUND_HALF_UP),
                        "peak_mfe_r": _ZERO,
                        "worst_mae_r": _ZERO,
                        "session_region": snap.session_region,
                        "entry_regime": snap.regime,
                    }

        for ev in closed_events:
            self.record_trade_close(
                source_channel="SHADOW_INCUBATOR",
                trade_id=ev["trade_id"],
                symbol=ev["sym"],
                side=ev["side"],
                net_pnl_usd=ev["net_usd"],
                current_equity_usd=Decimal("5000.00"),
                starting_principal_usd=Decimal("5000.00"),
                vault_sweep_ratio=_ZERO,
                strategy_id=ev["sid"],
                initial_risk_usd=ev["risk_usd"],
                session_region=ev["session_region"],
                entry_regime=ev["entry_regime"],
                now=ts,
            )
        return len(closed_events)

    # -----------------------------------------------------------------------
    # Owner Commands (Two-Way Notes & Manual Strategy Governance)
    # -----------------------------------------------------------------------

    def leave_owner_note(
        self,
        *,
        headline: str,
        body_plain_english: str,
        related_strategy_id: str | None = None,
        related_symbol: str | None = None,
        pin_for_ai: bool = True,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        if not isinstance(headline, str) or not (1 <= len(headline.strip()) <= 120):
            raise ContractError("headline must be 1..120 characters")
        if not isinstance(body_plain_english, str) or not (1 <= len(body_plain_english.strip()) <= 500):
            raise ContractError("body_plain_english must be 1..500 characters")
        if related_strategy_id is not None and not SAFE_ID_RE.match(str(related_strategy_id)):
            raise ContractError("related_strategy_id invalid")
        with self._lock:
            conn = self._connect_rw()
            try:
                note = self._insert_note_tx(
                    conn,
                    now=ts,
                    author_role="OWNER_WAKIL",
                    note_category="OWNER_DIRECTIVE",
                    headline=headline,
                    body_plain_english=body_plain_english,
                    related_strategy_id=related_strategy_id,
                    related_symbol=_ascii_clean(related_symbol, max_len=16).upper() if related_symbol else None,
                    related_ticket=None,
                    session_region="GLOBAL",
                    entry_regime="STRONG_TREND",
                    lesson_tags="OWNER_DIRECTIVE",
                    impact_pnl_usd=None,
                    realized_r=None,
                    pinned_by_owner=bool(pin_for_ai),
                )
                conn.commit()
            finally:
                conn.close()
            self._reload_cache_from_ro()
            return note

    def quarantine_strategy(
        self,
        *,
        strategy_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        ts_iso = _iso_utc(ts)
        if not SAFE_ID_RE.match(str(strategy_id or "")):
            raise ContractError("Invalid strategy_id")
        clean_reason = _ascii_clean(reason, max_len=240)
        with self._lock:
            if strategy_id not in self._genomes:
                raise ContractError(f"Unknown strategy_id: {strategy_id}")
            conn = self._connect_rw()
            try:
                conn.execute(
                    """
                    UPDATE strategy_registry SET
                        status = ?, retired_by = 'OWNER_MANUAL',
                        retirement_reason_code = 'OWNER_MANUAL_QUARANTINE',
                        retirement_reason_text = ?,
                        quarantined_at_utc = ?, cooldown_until_utc = ?, updated_at_utc = ?
                    WHERE strategy_id = ?
                    """,
                    (
                        ArmStatus.QUARANTINED_SHADOW.value,
                        clean_reason,
                        ts_iso,
                        _iso_utc(ts + timedelta(hours=24)),
                        ts_iso,
                        strategy_id,
                    ),
                )
                note = self._insert_note_tx(
                    conn,
                    now=ts,
                    author_role="OWNER_WAKIL",
                    note_category="STRATEGY_QUARANTINED",
                    headline=f"Owner quarantined {strategy_id}",
                    body_plain_english=clean_reason,
                    related_strategy_id=strategy_id,
                    related_symbol=None,
                    related_ticket=None,
                    session_region="GLOBAL",
                    entry_regime="STRONG_TREND",
                    lesson_tags="OWNER_QUARANTINE",
                    impact_pnl_usd=None,
                    realized_r=None,
                    pinned_by_owner=False,
                )
                conn.commit()
            finally:
                conn.close()
            self._reload_cache_from_ro()
            return note

    def resume_to_shadow(
        self,
        *,
        strategy_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = self._now(now)
        ts_iso = _iso_utc(ts)
        if not SAFE_ID_RE.match(str(strategy_id or "")):
            raise ContractError("Invalid strategy_id")
        clean_reason = _ascii_clean(reason, max_len=240)
        with self._lock:
            if strategy_id not in self._genomes:
                raise ContractError(f"Unknown strategy_id: {strategy_id}")
            conn = self._connect_rw()
            try:
                conn.execute(
                    """
                    UPDATE strategy_registry SET
                        status = ?, trades_since_quarantine = 0, recovery_sum_r = '0.0000',
                        updated_at_utc = ?
                    WHERE strategy_id = ?
                    """,
                    (ArmStatus.INCUBATING_SHADOW.value, ts_iso, strategy_id),
                )
                note = self._insert_note_tx(
                    conn,
                    now=ts,
                    author_role="OWNER_WAKIL",
                    note_category="STRATEGY_SHADOW_CREATED",
                    headline=f"Moved {strategy_id} back to Shadow Incubator",
                    body_plain_english=clean_reason,
                    related_strategy_id=strategy_id,
                    related_symbol=None,
                    related_ticket=None,
                    session_region="GLOBAL",
                    entry_regime="STRONG_TREND",
                    lesson_tags="RESUME_SHADOW",
                    impact_pnl_usd=None,
                    realized_r=None,
                    pinned_by_owner=False,
                )
                conn.commit()
            finally:
                conn.close()
            self._reload_cache_from_ro()
            return note

    def acknowledge_note(self, *, note_id: str) -> dict[str, Any]:
        if not SAFE_ID_RE.match(str(note_id or "")):
            raise ContractError("Invalid note_id")
        with self._lock:
            conn = self._connect_rw()
            try:
                cur = conn.execute(
                    "UPDATE ai_field_notes SET acknowledged_by_ai = 1 WHERE note_id = ?",
                    (note_id,),
                )
                if cur.rowcount == 0:
                    raise ContractError(f"Unknown note_id: {note_id}")
                conn.commit()
            finally:
                conn.close()
            self._reload_cache_from_ro()
            return {"note_id": note_id, "acknowledged": True}

    def record_valve_veto(self) -> None:
        with self._lock:
            self._vetoed_proposals_total += 1

    # -----------------------------------------------------------------------
    # Zero-Write Read Snapshot (`GET /api/ai-strategy-lab` via `?mode=ro`)
    # -----------------------------------------------------------------------

    def snapshot(
        self,
        *,
        execution_mode: str = "DEMO",
        effective_stop_risk_ceiling_pct: Decimal = Decimal("5.00"),
        starting_balance_usd: Decimal = Decimal("200000.00"),
        current_online_equity_usd: Decimal = Decimal("200000.00"),
        total_ledger_net_pnl_usd: Decimal = _ZERO,
        news_shock_shield_active: bool = True,
        owner_controls_allowed: bool = True,
        session_scope: str = "OWNER_FULL_CONTROL",
        notes_limit: int = 25,
        include_decommissioned: bool = True,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Zero-write snapshot strictly opening SQLite with `?mode=ro` (or reading clean in-memory cache)."""
        ts = self._now(now)
        clamped_limit = max(1, min(100, int(notes_limit)))
        clean_mode = "LIVE" if str(execution_mode).strip().upper() == "LIVE" else "DEMO"
        eff_cap = Decimal("1.00") if clean_mode == "LIVE" else effective_stop_risk_ceiling_pct

        # Verify zero-write read against ?mode=ro without touching mtime or PRAGMA data_version
        ro_conn = self._connect_ro()
        if ro_conn is not None:
            try:
                ro_conn.execute("SELECT COUNT(*) FROM strategy_registry").fetchone()
            finally:
                ro_conn.close()

        with self._lock:
            open_by_strat: dict[str, int] = {}
            for rec in self._active_tickets.values():
                s_id = str(rec.get("strategy_id", ""))
                open_by_strat[s_id] = open_by_strat.get(s_id, 0) + 1

            active_list: list[dict[str, Any]] = []
            shadow_list: list[dict[str, Any]] = []
            quar_list: list[dict[str, Any]] = []

            tot_net = _ZERO
            tot_bal = _ZERO
            tot_vault = _ZERO
            n_tot_active = max(
                _TWO,
                sum(
                    (self._strat_stats[s].s0 for s, st in self._statuses.items() if st is ArmStatus.ACTIVE),
                    _ZERO,
                ),
            )

            for sid, genome in sorted(self._genomes.items()):
                st_enum = self._statuses[sid]
                s_st = self._strat_stats[sid]
                meta = self._meta[sid]
                m = derived_metrics(s_st, genome.archetype)
                tot_net += meta["net_pnl_usd"]
                tot_bal += meta["starting_balance_contrib_usd"]
                tot_vault += meta["vaulted_profit_contrib_usd"]

                wr_pct = (
                    (Decimal(s_st.win_count) * Decimal("100") / Decimal(s_st.n_trades))
                    if s_st.n_trades > 0
                    else (m["eb_wr"] * Decimal("100"))
                )
                raw_pf = (s_st.raw_gp / s_st.raw_gl) if s_st.raw_gl > _ZERO else m["pf"]

                if st_enum is ArmStatus.ACTIVE:
                    mu_c, var_c, neff_c = hierarchical_shrinkage(
                        strat_st=s_st, reg_st=s_st, cell_st=s_st, archetype=genome.archetype
                    )
                    b_c = compute_ucb_lcb(
                        mu_cell=mu_c, var_cell=var_c, n_eff_cell=neff_c, n_tot_active=n_tot_active
                    )
                    w_mult = compute_risk_weight_multiplier(
                        status=ArmStatus.ACTIVE,
                        mu_cell=mu_c,
                        var_cell=var_c,
                        se_cell=b_c["se"],
                        mfe_capture=m["mfe_capture"],
                        mfe_sample_weight=s_st.s0,
                        cusum_neg=s_st.cusum_neg,
                        drawdown_ratio=_ZERO,
                        is_live_mode=(clean_mode == "LIVE"),
                    )
                    active_list.append(
                        {
                            "strategy_id": sid,
                            "display_name": genome.display_name,
                            "version": genome.version,
                            "origin": genome.origin,
                            "status": "ACTIVE",
                            "archetype": genome.archetype.value,
                            "target_markets": list(genome.target_markets),
                            "preferred_regimes": list(genome.preferred_regimes),
                            "blueprint_summary": genome.blueprint_summary(),
                            "risk_profile": {
                                "risk_weight_multiplier": _q2_str(w_mult),
                                "max_stop_risk_pct": _q2_str((eff_cap * w_mult).quantize(_Q2, rounding=ROUND_FLOOR)),
                                "min_valve_score": "0.55",
                                "allow_pyramiding": genome.allow_pyramiding,
                            },
                            "metrics": {
                                "closed_trades": s_st.n_trades,
                                "win_count": s_st.win_count,
                                "loss_count": s_st.loss_count,
                                "win_rate_pct": _q2_str(wr_pct),
                                "r_expectancy": _q4_str(m["e_r"]),
                                "profit_factor": _q2_str(raw_pf),
                                "cusum_drift": _q4_str(s_st.cusum_neg),
                                "max_drawdown_r": _q2_str(s_st.max_dd_r),
                            },
                            "attribution": {
                                "net_pnl_usd": _q2_str(meta["net_pnl_usd"]),
                                "starting_balance_contribution_usd": _q2_str(meta["starting_balance_contrib_usd"]),
                                "vaulted_profit_contribution_usd": _q2_str(meta["vaulted_profit_contrib_usd"]),
                                "open_positions_count": open_by_strat.get(sid, 0),
                                "last_trade_at_utc": meta["last_trade_at_utc"],
                            },
                            "promoted_at_utc": meta["promoted_at_utc"],
                            "status_reason": genome.hypothesis_plain_english[:200],
                        }
                    )
                elif st_enum is ArmStatus.INCUBATING_SHADOW:
                    ok_grad, grad_reason, _ = evaluate_shadow_graduation(
                        s_st,
                        archetype=genome.archetype,
                        distinct_sessions=len(meta["shadow_sessions"]),
                        distinct_days=len(meta["shadow_days"]),
                    )
                    prog_raw = min(
                        Decimal("100.00"),
                        (Decimal(s_st.n_trades) * Decimal("100") / Decimal(SHADOW_MIN_TRADES)).quantize(_Q2, rounding=ROUND_HALF_UP),
                    )
                    prog_bucket = int(min(100, max(0, int((prog_raw / Decimal("5")).to_integral_value(rounding=ROUND_HALF_UP)) * 5)))
                    v_checks = int(meta["sim_valve_checks"])
                    v_pass_pct = (
                        (Decimal(int(meta["sim_valve_passes"])) * Decimal("100") / Decimal(v_checks))
                        if v_checks > 0
                        else Decimal("100.00")
                    )
                    shadow_list.append(
                        {
                            "strategy_id": sid,
                            "display_name": genome.display_name,
                            "version": genome.version,
                            "origin": genome.origin,
                            "status": "SHADOW_INCUBATING",
                            "archetype": genome.archetype.value,
                            "hypothesis_plain_english": genome.hypothesis_plain_english[:280],
                            "target_markets": list(genome.target_markets),
                            "preferred_regimes": list(genome.preferred_regimes),
                            "blueprint_summary": genome.blueprint_summary(),
                            "shadow_metrics": {
                                "shadow_trades": s_st.n_trades,
                                "shadow_win_count": s_st.win_count,
                                "shadow_loss_count": s_st.loss_count,
                                "shadow_win_rate_pct": _q2_str(wr_pct),
                                "shadow_r_expectancy": _q4_str(m["e_r"]),
                                "shadow_profit_factor": _q2_str(raw_pf),
                                "shadow_net_pnl_usd": _q2_str(meta["shadow_net_pnl_usd"]),
                                "shadow_max_drawdown_r": _q2_str(s_st.max_dd_r),
                                "simulated_valve_pass_rate_pct": _q2_str(v_pass_pct),
                            },
                            "graduation": {
                                "required_trades": SHADOW_MIN_TRADES,
                                "completed_trades": s_st.n_trades,
                                "required_min_profit_factor": _q2_str(SHADOW_MIN_PF),
                                "required_min_r_expectancy": "0.15",
                                "required_max_drawdown_r": _q2_str(SHADOW_MAX_DD_R),
                                "progress_pct": _q2_str(prog_raw),
                                "progress_bucket": prog_bucket,
                                "ready_for_promotion": ok_grad,
                                "blocking_reason": None if ok_grad else grad_reason[:200],
                            },
                            "created_at_utc": meta["created_at_utc"],
                            "last_shadow_trade_at_utc": meta["last_trade_at_utc"],
                        }
                    )
                else:
                    if st_enum is ArmStatus.DECOMMISSIONED and not include_decommissioned:
                        continue
                    quar_list.append(
                        {
                            "strategy_id": sid,
                            "display_name": genome.display_name,
                            "version": genome.version,
                            "origin": genome.origin,
                            "status": st_enum.value,
                            "archetype": genome.archetype.value,
                            "retired_by": meta["retired_by"] or "AI_SELF_AUDIT",
                            "retirement_reason_code": meta["retirement_reason_code"] or "CUSUM_QUARANTINE",
                            "retirement_reason_plain_english": (
                                meta["retirement_reason_text"]
                                or "Retired automatically by AI self-audit to protect starting capital."
                            )[:280],
                            "final_metrics": {
                                "closed_trades": s_st.n_trades,
                                "win_rate_pct": _q2_str(wr_pct),
                                "r_expectancy": _q4_str(m["e_r"]),
                                "net_pnl_usd": _q2_str(meta["net_pnl_usd"]),
                                "starting_balance_contribution_usd": _q2_str(meta["starting_balance_contrib_usd"]),
                                "vaulted_profit_contribution_usd": _q2_str(meta["vaulted_profit_contrib_usd"]),
                                "max_drawdown_r": _q2_str(s_st.max_dd_r),
                            },
                            "quarantined_at_utc": meta["quarantined_at_utc"] or meta["created_at_utc"],
                            "cooldown_until_utc": meta["cooldown_until_utc"],
                        }
                    )

            notes_out: list[dict[str, Any]] = []
            for nr in list(self._notes_cache)[:clamped_limit]:
                notes_out.append(
                    {
                        "note_id": str(nr["note_id"]),
                        "seq_no": int(nr["seq_no"]),
                        "observed_at_utc": str(nr["observed_at_utc"]),
                        "observed_at_pacific": str(nr["observed_at_pacific"]),
                        "author_role": str(nr["author_role"]),
                        "note_category": str(nr["note_category"]),
                        "headline": str(nr["headline"]),
                        "body_plain_english": str(nr["body_plain_english"]),
                        "related_strategy_id": nr["related_strategy_id"],
                        "related_symbol": nr["related_symbol"],
                        "related_ticket": nr["related_ticket"],
                        "impact_pnl_usd": nr["impact_pnl_usd"],
                        "pinned_by_owner": bool(nr["pinned_by_owner"]),
                        "acknowledged_by_ai": bool(nr["acknowledged_by_ai"]),
                        "entry_sha256": str(nr["entry_sha256"]),
                    }
                )

            if current_online_equity_usd < starting_balance_usd:
                cap_status = "RECOVERY_MODE"
            elif current_online_equity_usd == starting_balance_usd:
                cap_status = "AT_PRINCIPAL"
            else:
                cap_status = "IN_SURPLUS"

            unattr_legacy = total_ledger_net_pnl_usd - tot_net
            return {
                "schema": AI_STRATEGY_LAB_SCHEMA,
                "observed_at_utc": _iso_utc(ts),
                "observed_at_pacific": us_pacific_text(ts),
                "execution_mode": clean_mode,
                "accounting_basis": "INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT",
                "session_scope": str(session_scope),
                "owner_controls_allowed": bool(owner_controls_allowed),
                "governance_safety": {
                    "valve_controller": "tks_meta_valve_controller",
                    "valve_parameters": 161,
                    "valve_threshold": "0.55",
                    "all_intents_valve_gated": True,
                    "news_shock_shield_active": bool(news_shock_shield_active),
                    "correlated_offset_guard_threshold": "0.45",
                    "single_broker_equity_sizing": True,
                    "live_constitutional_ceilings": {
                        "max_stop_risk_pct": "1.00",
                        "max_drawdown_pct": "10.00",
                        "auto_replenish_allowed_in_live": False,
                    },
                    "effective_stop_risk_ceiling_pct": _q2_str(eff_cap),
                    "owner_controls_allowed": bool(owner_controls_allowed),
                    "audit_head_sha256": self._audit_head_sha256,
                    "audit_entry_count": self._notes_total,
                },
                "capital_attribution_summary": {
                    "starting_balance_usd": _q2_str(starting_balance_usd),
                    "current_online_equity_usd": _q2_str(current_online_equity_usd),
                    "capital_status": cap_status,
                    "vault_sweeps_paused_for_recovery": cap_status != "IN_SURPLUS",
                    "total_strategy_net_pnl_usd": _q2_str(tot_net),
                    "total_starting_balance_contribution_usd": _q2_str(tot_bal),
                    "total_vaulted_profit_contribution_usd": _q2_str(tot_vault),
                    "unattributed_legacy_pnl_usd": _q2_str(unattr_legacy),
                },
                "counts": {
                    "active_count": len(active_list),
                    "shadow_count": len(shadow_list),
                    "quarantined_count": len(quar_list),
                    "field_notes_total": self._notes_total,
                    "shadow_trades_total": self._shadow_trades_total,
                    "vetoed_proposals_total": self._vetoed_proposals_total,
                },
                "active_strategies": active_list[:32],
                "shadow_strategies": shadow_list[:32],
                "quarantined_strategies": quar_list[:64],
                "field_notes": notes_out,
            }
