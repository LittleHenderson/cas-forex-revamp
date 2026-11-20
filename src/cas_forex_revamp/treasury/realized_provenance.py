"""Pure, zero-write Broker-Attributed Realized P/L Provenance & Live Trading Status Engine.

Provides deterministic, exact-Decimal attribution of realized profit/loss sweeps by:
- Broker account (LHFX, Hugo's Way, OANDA, etc.)
- Market / symbol (NAS100, US30, XAUUSD, FX pairs)
- Global Forex trading session (Asia / Tokyo–Sydney, London, New York / US)
- Dual exact timestamps (Pacific Time via America/Los_Angeles + UTC)

Synthetic internal reconciliation rows (SESSION_SYNC, SESSION_BASKET,
DUAL_SHIELD_BARBELL, RECONCILIATION, PORTFOLIO_RECONCILE) are excluded from
real trade attribution and last-trade stamps while remaining transparently
reconciled in exact Decimal totals.

Security & hygiene invariants:
- Pure in-memory computation: zero database writes, zero network calls, zero shell/eval.
- Exact Decimal arithmetic only: floats and booleans are rejected on money fields.
- Strict UTC validation on all timestamps.
- Zero ``assert`` statements (Bandit B101 compliant).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.contracts.primitives import decimal_value, utc_time

PROVENANCE_SCHEMA = "cas-forex.realized-provenance/1"

SESSION_ASIA = "ASIA"
SESSION_LONDON = "LONDON"
SESSION_NEW_YORK = "NEW_YORK"

SESSION_LABELS: dict[str, str] = {
    SESSION_ASIA: "Asia / Tokyo–Sydney",
    SESSION_LONDON: "London",
    SESSION_NEW_YORK: "New York / US",
}
_CANONICAL_SESSION_ORDER: tuple[str, ...] = (
    SESSION_ASIA,
    SESSION_LONDON,
    SESSION_NEW_YORK,
)

STATE_TRADING_NOW = "TRADING_NOW"
STATE_ACTIVE_SCANNING = "ACTIVE_SCANNING"
STATE_PAUSED_RESEARCH_RESPITE = "PAUSED_RESEARCH_RESPITE"
STATE_PAUSED_SAFETY_LOCK = "PAUSED_SAFETY_LOCK"

_MONTH_ABBR: tuple[str, ...] = (
    "",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)

_SYNTHETIC_EXACT_TOKENS: frozenset[str] = frozenset({
    "SESSION_SYNC",
    "SESSION_BASKET",
    "RECONCILIATION",
    "PORTFOLIO_RECONCILE",
    "PORTFOLIO_RECONCILIATION",
    "DUAL_SHIELD_BARBELL",
    "INTERNAL_SYNC",
    "SYSTEM_RECONCILE",
    "SYSTEM_SYNC",
    "SYNTHETIC",
    "SYNTHETIC_SYNC",
    "BALANCE_ADJUSTMENT",
    "ADJUSTMENT",
    "BASKET",
    "ALL_MARKETS",
    "PORTFOLIO",
    "NONE",
    "N/A",
})

_SYNTHETIC_PREFIXES: tuple[str, ...] = (
    "SESSION_SYNC",
    "SESSION_BASKET",
    "RECONCIL",
    "PORTFOLIO_RECONCIL",
    "INTERNAL_SYNC",
    "SYSTEM_SYNC",
    "SYSTEM_RECONCIL",
    "SYNTHETIC",
    "BALANCE_ADJUST",
)

_SAFETY_LOCK_STATES: frozenset[str] = frozenset({
    "DAILY_LOSS_CIRCUIT_TRIPPED",
    "LOSS_CIRCUIT_TRIPPED",
    "SAFETY_LOCK",
    "PAUSED_SAFETY_LOCK",
    "STOPPED",
    "EMERGENCY_STOPPED",
    "DRAWDOWN_LOCKED",
    "PAUSED_NEW_RISK",
})

_RESEARCH_RESPITE_STATES: frozenset[str] = frozenset({
    "RESEARCH_RESPITE",
    "PAUSED_RESEARCH_RESPITE",
    "DAILY_QUOTA_LOCKED",
    "PROFIT_FLOOR_LOCKED",
})


def _nth_sunday_day(year: int, month: int, n: int) -> int:
    """Return the day-of-month (1..31) for the n-th Sunday of the given year/month."""
    first_weekday = datetime(year, month, 1).weekday()  # Mon=0 .. Sun=6
    days_until_sunday = (6 - first_weekday) % 7
    return 1 + days_until_sunday + (n - 1) * 7


class _PacificFallbackTz(tzinfo):
    """Deterministic US Pacific (PST/PDT) tzinfo used ONLY if IANA tzdata is absent.

    Follows the US Energy Policy Act of 2005 rule:
    - PDT (UTC-07:00) begins on the 2nd Sunday of March at 02:00 PST (10:00 UTC).
    - PST (UTC-08:00) resumes on the 1st Sunday of November at 02:00 PDT (09:00 UTC).
    """

    _PST_OFFSET = timedelta(hours=-8)
    _PDT_OFFSET = timedelta(hours=-7)
    _ZERO = timedelta(0)
    _ONE_HOUR = timedelta(hours=1)

    def _is_dst_utc(self, dt_utc: datetime) -> bool:
        year = dt_utc.year
        dst_start_utc = datetime(
            year, 3, _nth_sunday_day(year, 3, 2), 10, 0, 0, tzinfo=timezone.utc
        )
        dst_end_utc = datetime(
            year, 11, _nth_sunday_day(year, 11, 1), 9, 0, 0, tzinfo=timezone.utc
        )
        return dst_start_utc <= dt_utc < dst_end_utc

    def fromutc(self, dt: datetime) -> datetime:
        if dt.tzinfo is not self:
            raise ValueError("dt.tzinfo is not self")
        probe_utc = dt.replace(tzinfo=timezone.utc)
        year = probe_utc.year
        dst_end_utc = datetime(
            year, 11, _nth_sunday_day(year, 11, 1), 9, 0, 0, tzinfo=timezone.utc
        )
        in_dst = self._is_dst_utc(probe_utc)
        offset = self._PDT_OFFSET if in_dst else self._PST_OFFSET
        local_dt = dt + offset
        if dst_end_utc <= probe_utc < dst_end_utc + self._ONE_HOUR:
            return local_dt.replace(fold=1)
        return local_dt

    def utcoffset(self, dt: datetime | None) -> timedelta:
        if dt is None:
            return self._PST_OFFSET
        year = dt.year
        start_local = datetime(year, 3, _nth_sunday_day(year, 3, 2), 2, 0, 0)
        end_local = datetime(year, 11, _nth_sunday_day(year, 11, 1), 2, 0, 0)
        naive = dt.replace(tzinfo=None)
        if start_local <= naive < end_local:
            if end_local - self._ONE_HOUR <= naive < end_local and getattr(dt, "fold", 0) == 1:
                return self._PST_OFFSET
            return self._PDT_OFFSET
        return self._PST_OFFSET

    def dst(self, dt: datetime | None) -> timedelta:
        return self._ONE_HOUR if self.utcoffset(dt) == self._PDT_OFFSET else self._ZERO

    def tzname(self, dt: datetime | None) -> str:
        return "PDT" if self.utcoffset(dt) == self._PDT_OFFSET else "PST"


_PACIFIC_FALLBACK_TZ = _PacificFallbackTz()


def _pacific_zone() -> tzinfo:
    try:
        return ZoneInfo("America/Los_Angeles")
    except ZoneInfoNotFoundError:
        return _PACIFIC_FALLBACK_TZ


def _coerce_utc_datetime(value: datetime | str, field: str = "ts_utc") -> datetime:
    """Strictly validate and return a timezone-aware UTC datetime."""
    if isinstance(value, datetime):
        return utc_time(value, field)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ContractError(f"{field} must be a non-empty ISO-8601 UTC timestamp")
        iso_candidate = f"{raw[:-1]}+00:00" if raw.endswith(("Z", "z")) else raw
        try:
            parsed = datetime.fromisoformat(iso_candidate)
        except ValueError as exc:
            raise ContractError(f"{field} must be a valid ISO-8601 UTC timestamp") from exc
        return utc_time(parsed, field)
    raise ContractError(f"{field} must be a UTC datetime or ISO-8601 UTC string")


def _parse_money_decimal(value: Any, field: str) -> Decimal:
    """Parse an exact finite Decimal money value, strictly forbidding float and bool."""
    if isinstance(value, (bool, float)):
        raise ContractError(f"{field} forbids float/bool values; supply Decimal or string")
    if isinstance(value, Decimal):
        return decimal_value(value, field)
    if isinstance(value, int):
        return decimal_value(Decimal(value), field)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ContractError(f"{field} must be a non-empty decimal string")
        try:
            dec = Decimal(raw)
        except InvalidOperation as exc:
            raise ContractError(f"{field} is not a valid decimal string: {value!r}") from exc
        return decimal_value(dec, field)
    raise ContractError(f"{field} requires Decimal, int, or decimal string")


def _format_usd_decimal(value: Decimal) -> str:
    """Format an exact Decimal USD amount with zero rounding and at least 2 decimal places."""
    val = decimal_value(value, "usd_amount")
    if val == Decimal("0"):
        return "0.00"
    with localcontext() as ctx:
        ctx.prec = 40
        normalized = val.normalize()
        exp = normalized.as_tuple().exponent
        if isinstance(exp, int) and exp < -2:
            return format(normalized, "f")
        return format(val.quantize(Decimal("0.01")), "f")


def _format_iso_utc(ts_utc: datetime) -> str:
    return utc_time(ts_utc, "ts_utc").isoformat().replace("+00:00", "Z")


def _norm_token(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().upper().replace("-", "_").replace(" ", "_")


_SYNTHETIC_SUBSTRINGS: tuple[str, ...] = (
    "SESSION_SYNC",
    "SESSION_BASKET",
    "RECONCILIATION",
    "PORTFOLIO_RECONCIL",
)


def _is_synthetic_token(token: str) -> bool:
    if not token:
        return False
    if token in _SYNTHETIC_EXACT_TOKENS:
        return True
    for prefix in _SYNTHETIC_PREFIXES:
        if token.startswith(prefix):
            return True
    for marker in _SYNTHETIC_SUBSTRINGS:
        if marker in token:
            return True
    return False


def format_broker_label(broker_id: str) -> str:
    """Map an internal broker identifier to an owner-friendly display name."""
    if not isinstance(broker_id, str):
        return "Unknown Broker"
    raw = broker_id.strip()
    if not raw:
        return "Unknown Broker"

    norm = _norm_token(raw)
    if norm == "LHFX" or norm.startswith("LHFX_") or norm.startswith("LHFXSA"):
        return "LHFX"
    if (
        norm in {"HUGOSWAY", "HUGOS_WAY", "HUGO_WAY", "HUGOSWAY_MT5", "HUGO_PRO5"}
        or norm.startswith("HUGOSWAY_")
        or norm.startswith("HUGOS_WAY_")
        or norm.startswith("HUGO_WAY_")
        or norm.startswith("HUGOS")
    ):
        return "Hugo's Way"
    if norm == "OANDA" or norm.startswith("OANDA_"):
        return "OANDA"
    if _is_synthetic_token(norm):
        return "Internal Reconciliation"
    if norm in {"DUAL_SHIELD", "DUAL_SHIELD_ROUTER"}:
        return "Dual Shield"
    return raw


def is_synthetic_sweep(row: Mapping[str, Any]) -> bool:
    """Return True if a sweep row is a synthetic sync/reconciliation entry rather than a real trade."""
    if not isinstance(row, Mapping):
        raise ContractError("sweep row must be a Mapping")

    if row.get("is_synthetic") is True or row.get("synthetic") is True:
        return True

    trade_token = _norm_token(row.get("trade_id", ""))
    symbol_token = _norm_token(row.get("symbol", ""))
    broker_token = _norm_token(row.get("broker_id", ""))

    if not symbol_token:
        return True
    if _is_synthetic_token(trade_token):
        return True
    if _is_synthetic_token(symbol_token):
        return True
    if _is_synthetic_token(broker_token):
        return True
    return False


def classify_trading_session(ts_utc: datetime | str) -> dict[str, str]:
    """Classify a UTC timestamp into the 3-region CAS Forex session schedule.

    Windows (contiguous 24h UTC):
    - ASIA:     22:00 <= hour or hour < 07:00 UTC -> "Asia / Tokyo–Sydney"
    - LONDON:   07:00 <= hour < 12:00 UTC         -> "London"
    - NEW_YORK: 12:00 <= hour < 22:00 UTC         -> "New York / US"
    """
    ts = _coerce_utc_datetime(ts_utc, "ts_utc")
    hour = ts.hour
    if hour >= 22 or hour < 7:
        session_id = SESSION_ASIA
    elif 7 <= hour < 12:
        session_id = SESSION_LONDON
    else:
        session_id = SESSION_NEW_YORK
    return {
        "session_id": session_id,
        "session_label": SESSION_LABELS[session_id],
    }


def format_dual_timestamp(
    ts_utc: datetime | str,
    *,
    pacific_tz: tzinfo | None = None,
) -> dict[str, str]:
    """Format an exact UTC timestamp into both Pacific Time (America/Los_Angeles) and UTC."""
    ts = _coerce_utc_datetime(ts_utc, "ts_utc")
    tz = _pacific_zone() if pacific_tz is None else pacific_tz
    local_dt = ts.astimezone(tz)

    hour24 = local_dt.hour
    ampm = "AM" if hour24 < 12 else "PM"
    hour12 = hour24 % 12
    if hour12 == 0:
        hour12 = 12

    time_pt = f"{hour12}:{local_dt.minute:02d}:{local_dt.second:02d} {ampm} PT"
    date_pt = f"{local_dt.year:04d}-{local_dt.month:02d}-{local_dt.day:02d}"
    month_name = _MONTH_ABBR[local_dt.month]
    local_display = f"{month_name} {local_dt.day}, {local_dt.year} · {time_pt}"
    utc_display = (
        f"{ts.year:04d}-{ts.month:02d}-{ts.day:02d} "
        f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d} UTC"
    )
    tz_abbr = local_dt.tzname() or ("PDT" if local_dt.utcoffset() == timedelta(hours=-7) else "PST")

    return {
        "occurred_at_utc": _format_iso_utc(ts),
        "local_display": local_display,
        "utc_display": utc_display,
        "date_pt": date_pt,
        "time_pt": time_pt,
        "tz_abbr": tz_abbr,
    }


def _dedup_preserve_order(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _build_live_trading_status(
    open_positions: Sequence[Mapping[str, Any]],
    *,
    operating_mode: str,
    governance_mode: str,
    effective_status: str,
) -> dict[str, Any]:
    if not isinstance(open_positions, Sequence) or isinstance(open_positions, (str, bytes)):
        raise ContractError("open_positions must be a sequence of mappings")

    raw_markets: list[str] = []
    raw_brokers: list[str] = []
    for idx, pos in enumerate(open_positions):
        if not isinstance(pos, Mapping):
            raise ContractError(f"open_positions[{idx}] must be a Mapping")
        sym = str(pos.get("symbol") or pos.get("instrument") or "").strip().upper()
        if sym:
            raw_markets.append(sym)
        brk_raw = str(pos.get("broker_id") or pos.get("broker") or "").strip()
        if brk_raw:
            raw_brokers.append(format_broker_label(brk_raw))

    open_count = len(open_positions)
    open_markets = _dedup_preserve_order(raw_markets)
    open_brokers = _dedup_preserve_order(raw_brokers)
    is_trading = open_count > 0

    op_norm = _norm_token(operating_mode)
    gov_norm = _norm_token(governance_mode)
    eff_norm = _norm_token(effective_status)

    if is_trading:
        state_code = STATE_TRADING_NOW
        noun = "OPEN TRADE" if open_count == 1 else "OPEN TRADES"
        if open_markets:
            headline = f"TRADING NOW — {open_count} {noun}: {', '.join(open_markets)}"
        else:
            headline = f"TRADING NOW — {open_count} {noun}"
    elif (
        eff_norm in _SAFETY_LOCK_STATES
        or gov_norm in _SAFETY_LOCK_STATES
        or op_norm in _SAFETY_LOCK_STATES
    ):
        state_code = STATE_PAUSED_SAFETY_LOCK
        headline = "PAUSED — SAFETY LOCK ACTIVE (0 OPEN TRADES)"
    elif op_norm in _RESEARCH_RESPITE_STATES or eff_norm in _RESEARCH_RESPITE_STATES:
        state_code = STATE_PAUSED_RESEARCH_RESPITE
        headline = "PAUSED — RESEARCH RESPITE (PROFITS BANKED, OBSERVING MARKETS)"
    else:
        state_code = STATE_ACTIVE_SCANNING
        headline = "ACTIVE — SCANNING MARKETS (0 OPEN TRADES)"

    return {
        "is_currently_trading": is_trading,
        "state_code": state_code,
        "headline": headline,
        "open_position_count": open_count,
        "open_markets": open_markets,
        "open_brokers": open_brokers,
    }


def _ordered_sessions(session_ids: set[str]) -> list[str]:
    return [SESSION_LABELS[sid] for sid in _CANONICAL_SESSION_ORDER if sid in session_ids]


def build_realized_provenance(
    sweeps: Sequence[Mapping[str, Any]],
    *,
    open_positions: Sequence[Mapping[str, Any]] = (),
    operating_mode: str = "ACTIVE_TRADING",
    governance_mode: str = "ACTIVE",
    effective_status: str = "ACTIVE",
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Build a pure, zero-write, exact-Decimal realized P/L provenance snapshot."""
    if not isinstance(sweeps, Sequence) or isinstance(sweeps, (str, bytes)):
        raise ContractError("sweeps must be a sequence of mappings")

    as_of_dt = (
        datetime.now(timezone.utc)
        if now_utc is None
        else _coerce_utc_datetime(now_utc, "now_utc")
    )
    as_of_dual = format_dual_timestamp(as_of_dt)
    as_of_sess = classify_trading_session(as_of_dt)

    live_status = _build_live_trading_status(
        open_positions,
        operating_mode=operating_mode,
        governance_mode=governance_mode,
        effective_status=effective_status,
    )

    real_records: list[tuple[datetime, int, Decimal, dict[str, Any]]] = []
    real_total = Decimal("0")
    synthetic_total = Decimal("0")
    synthetic_count = 0

    for idx, row in enumerate(sweeps):
        if not isinstance(row, Mapping):
            raise ContractError(f"sweeps[{idx}] must be a Mapping")

        raw_net = (
            row["realized_net_usd"]
            if "realized_net_usd" in row
            else row.get("realized_net_usd_text")
        )
        net_dec = _parse_money_decimal(raw_net, f"sweeps[{idx}].realized_net_usd")

        raw_ts = row.get("occurred_at")
        if raw_ts is None:
            raw_ts = row.get("occurred_at_utc")
        occ_dt = _coerce_utc_datetime(raw_ts, f"sweeps[{idx}].occurred_at")

        if is_synthetic_sweep(row):
            synthetic_total += net_dec
            synthetic_count += 1
            continue

        raw_trade_id = str(row.get("trade_id") or "").strip()
        if not raw_trade_id:
            raise ContractError(f"sweeps[{idx}].trade_id must be a non-empty string")
        symbol = str(row.get("symbol") or "").strip().upper()
        broker_id = str(row.get("broker_id") or "").strip().upper() or "UNKNOWN"
        broker_label = format_broker_label(broker_id)

        dual = format_dual_timestamp(occ_dt)
        sess = classify_trading_session(occ_dt)

        raw_retained = (
            row["retained_trading_usd"]
            if "retained_trading_usd" in row and row["retained_trading_usd"] is not None
            else row.get("retained_trading_usd_text")
        )
        raw_bank = (
            row["bank_sweep_usd"]
            if "bank_sweep_usd" in row and row["bank_sweep_usd"] is not None
            else row.get("bank_sweep_usd_text")
        )
        retained_dec = (
            _parse_money_decimal(raw_retained, f"sweeps[{idx}].retained_trading_usd")
            if raw_retained is not None
            else Decimal("0")
        )
        bank_dec = (
            _parse_money_decimal(raw_bank, f"sweeps[{idx}].bank_sweep_usd")
            if raw_bank is not None
            else Decimal("0")
        )

        real_total += net_dec
        entry: dict[str, Any] = {
            "trade_id": raw_trade_id,
            "symbol": symbol,
            "broker_id": broker_id,
            "broker_label": broker_label,
            "realized_net_usd": _format_usd_decimal(net_dec),
            "retained_trading_usd": _format_usd_decimal(retained_dec),
            "bank_sweep_usd": _format_usd_decimal(bank_dec),
            "occurred_at_utc": dual["occurred_at_utc"],
            "local_display": dual["local_display"],
            "utc_display": dual["utc_display"],
            "date_pt": dual["date_pt"],
            "time_pt": dual["time_pt"],
            "session_id": sess["session_id"],
            "session_label": sess["session_label"],
        }
        real_records.append((occ_dt, idx, net_dec, entry))

    # Newest first; tie-break deterministically by reverse input index.
    real_records.sort(key=lambda item: (item[0], item[1]), reverse=True)
    realized_entries = [item[3] for item in real_records]

    last_real_trade: dict[str, Any] | None = None
    if realized_entries:
        newest = realized_entries[0]
        last_real_trade = {
            "trade_id": newest["trade_id"],
            "symbol": newest["symbol"],
            "broker_id": newest["broker_id"],
            "broker_label": newest["broker_label"],
            "realized_net_usd": newest["realized_net_usd"],
            "occurred_at_utc": newest["occurred_at_utc"],
            "local_display": newest["local_display"],
            "utc_display": newest["utc_display"],
            "date_pt": newest["date_pt"],
            "time_pt": newest["time_pt"],
            "session_id": newest["session_id"],
            "session_label": newest["session_label"],
        }

    market_acc: dict[str, dict[str, Any]] = {}
    broker_acc: dict[str, dict[str, Any]] = {}
    session_acc: dict[str, dict[str, Any]] = {}

    for _occ_dt, _idx, net_dec, entry in real_records:
        sym = entry["symbol"]
        brk_id = entry["broker_id"]
        brk_lbl = entry["broker_label"]
        sid = entry["session_id"]
        slbl = entry["session_label"]
        is_win = 1 if net_dec > Decimal("0") else 0
        is_loss = 1 if net_dec < Decimal("0") else 0

        # By market (entries are already newest-first, so first seen is newest)
        m_bucket = market_acc.get(sym)
        if m_bucket is None:
            m_bucket = {
                "symbol": sym,
                "total_dec": Decimal("0"),
                "trade_count": 0,
                "win_count": 0,
                "loss_count": 0,
                "brokers": set(),
                "session_ids": set(),
                "last_occurred_at_utc": entry["occurred_at_utc"],
                "last_local_display": entry["local_display"],
                "last_session_label": slbl,
            }
            market_acc[sym] = m_bucket
        m_bucket["total_dec"] += net_dec
        m_bucket["trade_count"] += 1
        m_bucket["win_count"] += is_win
        m_bucket["loss_count"] += is_loss
        m_bucket["brokers"].add(brk_lbl)
        m_bucket["session_ids"].add(sid)

        # By broker
        b_bucket = broker_acc.get(brk_id)
        if b_bucket is None:
            b_bucket = {
                "broker_id": brk_id,
                "broker_label": brk_lbl,
                "total_dec": Decimal("0"),
                "trade_count": 0,
                "win_count": 0,
                "loss_count": 0,
                "markets": set(),
                "session_ids": set(),
                "last_occurred_at_utc": entry["occurred_at_utc"],
                "last_local_display": entry["local_display"],
                "last_session_label": slbl,
            }
            broker_acc[brk_id] = b_bucket
        b_bucket["total_dec"] += net_dec
        b_bucket["trade_count"] += 1
        b_bucket["win_count"] += is_win
        b_bucket["loss_count"] += is_loss
        b_bucket["markets"].add(sym)
        b_bucket["session_ids"].add(sid)

        # By session
        s_bucket = session_acc.get(sid)
        if s_bucket is None:
            s_bucket = {
                "session_id": sid,
                "session_label": slbl,
                "total_dec": Decimal("0"),
                "trade_count": 0,
                "win_count": 0,
                "loss_count": 0,
                "markets": set(),
                "brokers": set(),
                "last_occurred_at_utc": entry["occurred_at_utc"],
                "last_local_display": entry["local_display"],
            }
            session_acc[sid] = s_bucket
        s_bucket["total_dec"] += net_dec
        s_bucket["trade_count"] += 1
        s_bucket["win_count"] += is_win
        s_bucket["loss_count"] += is_loss
        s_bucket["markets"].add(sym)
        s_bucket["brokers"].add(brk_lbl)

    by_market = [
        {
            "symbol": b["symbol"],
            "total_realized_usd": _format_usd_decimal(b["total_dec"]),
            "trade_count": b["trade_count"],
            "win_count": b["win_count"],
            "loss_count": b["loss_count"],
            "brokers": sorted(b["brokers"]),
            "sessions": _ordered_sessions(b["session_ids"]),
            "last_occurred_at_utc": b["last_occurred_at_utc"],
            "last_local_display": b["last_local_display"],
            "last_session_label": b["last_session_label"],
        }
        for b in sorted(
            market_acc.values(),
            key=lambda item: (-item["total_dec"].copy_abs(), item["symbol"]),
        )
    ]

    by_broker = [
        {
            "broker_id": b["broker_id"],
            "broker_label": b["broker_label"],
            "total_realized_usd": _format_usd_decimal(b["total_dec"]),
            "trade_count": b["trade_count"],
            "win_count": b["win_count"],
            "loss_count": b["loss_count"],
            "markets": sorted(b["markets"]),
            "sessions": _ordered_sessions(b["session_ids"]),
            "last_occurred_at_utc": b["last_occurred_at_utc"],
            "last_local_display": b["last_local_display"],
            "last_session_label": b["last_session_label"],
        }
        for b in sorted(
            broker_acc.values(),
            key=lambda item: (-item["total_dec"].copy_abs(), item["broker_label"], item["broker_id"]),
        )
    ]

    by_session = [
        {
            "session_id": session_acc[sid]["session_id"],
            "session_label": session_acc[sid]["session_label"],
            "total_realized_usd": _format_usd_decimal(session_acc[sid]["total_dec"]),
            "trade_count": session_acc[sid]["trade_count"],
            "win_count": session_acc[sid]["win_count"],
            "loss_count": session_acc[sid]["loss_count"],
            "markets": sorted(session_acc[sid]["markets"]),
            "brokers": sorted(session_acc[sid]["brokers"]),
            "last_occurred_at_utc": session_acc[sid]["last_occurred_at_utc"],
            "last_local_display": session_acc[sid]["last_local_display"],
        }
        for sid in _CANONICAL_SESSION_ORDER
        if sid in session_acc
    ]

    combined_total = real_total + synthetic_total

    return {
        "schema": PROVENANCE_SCHEMA,
        "as_of_utc": as_of_dual["occurred_at_utc"],
        "as_of_local_display": as_of_dual["local_display"],
        "as_of_session_id": as_of_sess["session_id"],
        "as_of_session_label": as_of_sess["session_label"],
        "live_trading_status": live_status,
        "last_real_trade": last_real_trade,
        "realized_entries": realized_entries,
        "by_market": by_market,
        "by_broker": by_broker,
        "by_session": by_session,
        "totals": {
            "real_trade_realized_usd": _format_usd_decimal(real_total),
            "synthetic_adjustment_usd": _format_usd_decimal(synthetic_total),
            "combined_total_realized_usd": _format_usd_decimal(combined_total),
            "real_trade_count": len(realized_entries),
            "synthetic_row_count": synthetic_count,
        },
    }


__all__ = [
    "PROVENANCE_SCHEMA",
    "SESSION_ASIA",
    "SESSION_LONDON",
    "SESSION_NEW_YORK",
    "SESSION_LABELS",
    "STATE_TRADING_NOW",
    "STATE_ACTIVE_SCANNING",
    "STATE_PAUSED_RESEARCH_RESPITE",
    "STATE_PAUSED_SAFETY_LOCK",
    "format_broker_label",
    "is_synthetic_sweep",
    "classify_trading_session",
    "format_dual_timestamp",
    "build_realized_provenance",
]
