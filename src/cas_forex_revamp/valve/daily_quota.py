"""Durable Daily Profit Quota Lock ($500-$1,000 or % compounding) & Loss Circuit Breaker.

Persists per-session-day (or per-regional-recovery-window) state into SQLite WAL (when ``path``
is supplied) or scoped in-memory history. Inert on construction (zero I/O in ``__init__``).
Strictly vetoes new ``OPEN`` / ``ADD`` entries once session profit reaches hard quota
(``DAILY_QUOTA_LOCKED``) or trailing floor (``PROFIT_FLOOR_LOCKED``) or loss / consecutive-loss
limits trip (``DAILY_LOSS_CIRCUIT_TRIPPED``), while always permitting protective ``AMEND_STOP``,
``REDUCE``, ``CLOSE``, and ``WAIT``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, localcontext
from hashlib import sha256
import logging
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cas_forex_revamp.contracts import ActionKind, ContractError, canonical_bytes, decimal_text
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, integer, utc_time

logger = logging.getLogger(__name__)

ENV_DAILY_SOFT_QUOTA_USD = "CAS_FOREX_DAILY_SOFT_QUOTA_USD"
ENV_DAILY_HARD_QUOTA_USD = "CAS_FOREX_DAILY_HARD_QUOTA_USD"
ENV_DAILY_QUOTA_PCT = "CAS_FOREX_DAILY_QUOTA_PCT"
ENV_DAILY_QUOTA_MODE = "CAS_FOREX_DAILY_QUOTA_MODE"
ENV_DAILY_MAX_LOSS_USD = "CAS_FOREX_DAILY_MAX_LOSS_USD"
ENV_DAILY_MAX_LOSS_PCT = "CAS_FOREX_DAILY_MAX_LOSS_PCT"
ENV_MAX_CONSECUTIVE_LOSSES = "CAS_FOREX_MAX_CONSECUTIVE_LOSSES"
ENV_PROFIT_RATCHET_ACTIVATION_RATIO = "CAS_FOREX_PROFIT_RATCHET_ACTIVATION_RATIO"
ENV_PROFIT_RATCHET_FLOOR_RATIO = "CAS_FOREX_PROFIT_RATCHET_FLOOR_RATIO"
ENV_SESSION_CADENCE = "CAS_FOREX_SESSION_CADENCE"

DEFAULT_PROFIT_RATCHET_ACTIVATION_RATIO = Decimal("0.50")
DEFAULT_PROFIT_RATCHET_FLOOR_RATIO = Decimal("0.70")
DEFAULT_RECOVERY_LEG_GIVEBACK_RATIO = Decimal("0.30")
MIN_RECOVERY_LEG_LOSS_FLOOR_USD = Decimal("250.00")

SESSION_CADENCE_AUTO = "AUTO"
SESSION_CADENCE_DAILY_NY = "DAILY_NY"
SESSION_CADENCE_REGIONAL_RECOVERY = "REGIONAL_RECOVERY"
SESSION_CADENCE_REGIONAL_8H = "REGIONAL_8H"
VALID_SESSION_CADENCES = (
    SESSION_CADENCE_AUTO,
    SESSION_CADENCE_DAILY_NY,
    SESSION_CADENCE_REGIONAL_RECOVERY,
    SESSION_CADENCE_REGIONAL_8H,
)

QUOTA_STATUS_OPEN = "OPEN"
QUOTA_STATUS_SOFT = "SOFT_QUOTA_REACHED"
QUOTA_STATUS_LOCKED = "DAILY_QUOTA_LOCKED"
QUOTA_STATUS_PROFIT_FLOOR_LOCKED = "PROFIT_FLOOR_LOCKED"
QUOTA_STATUS_LOSS_TRIPPED = "DAILY_LOSS_CIRCUIT_TRIPPED"
VALID_QUOTA_STATUSES = (
    QUOTA_STATUS_OPEN,
    QUOTA_STATUS_SOFT,
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_PROFIT_FLOOR_LOCKED,
    QUOTA_STATUS_LOSS_TRIPPED,
)

QUOTA_MODES = ("USD", "PCT", "COMPOUND_CAPPED")
GENESIS_SHA256 = "0" * 64


BROKER_FRIENDLY_LABELS: dict[str, str] = {
    "LHFX_MT5": "LHFX",
    "LHFX": "LHFX",
    "HUGOSWAY_MT5": "Hugo's Way",
    "HUGOSWAY": "Hugo's Way",
    "OANDA_PRACTICE": "OANDA",
    "OANDA_LIVE": "OANDA",
    "OANDA": "OANDA",
    "DUAL_SHIELD": "Dual-Shield Barbell",
    "DUAL_SHIELD_BARBELL": "Dual-Shield Barbell",
}


def friendly_broker_label(broker_id: str | None) -> str:
    """Map canonical broker_id to owner-facing account label ('LHFX', 'Hugo\'s Way', 'OANDA')."""
    raw = str(broker_id or "").strip()
    if not raw:
        return "Unknown Broker"
    upper = raw.upper()
    if upper in BROKER_FRIENDLY_LABELS:
        return BROKER_FRIENDLY_LABELS[upper]
    if "LHFX" in upper:
        return "LHFX"
    if "HUGO" in upper:
        return "Hugo's Way"
    if "OANDA" in upper:
        return "OANDA"
    return raw


def _ny_zone():
    try:
        return ZoneInfo("America/New_York")
    except ZoneInfoNotFoundError:
        logger.warning("America/New_York tzdata unavailable; falling back to UTC-05:00 session boundary")
        return timezone(timedelta(hours=-5))


def _la_zone():
    try:
        return ZoneInfo("America/Los_Angeles")
    except ZoneInfoNotFoundError:
        logger.warning("America/Los_Angeles tzdata unavailable; falling back to PST UTC-08:00")
        return timezone(timedelta(hours=-8), name="PST")


def _coerce_utc_datetime(dt_or_iso: datetime | str | None) -> datetime:
    if dt_or_iso is None:
        return datetime.now(timezone.utc)
    if isinstance(dt_or_iso, datetime):
        return utc_time(dt_or_iso, "dt_or_iso")
    if isinstance(dt_or_iso, str) and dt_or_iso.strip():
        raw = dt_or_iso.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    raise ContractError("dt_or_iso must be a UTC datetime, ISO-8601 string, or None")


def forex_session_label_for_utc(dt_or_iso: datetime | str | None) -> str:
    """Return exact global Forex market session label for a UTC datetime or ISO-8601 string."""
    ts = _coerce_utc_datetime(dt_or_iso)
    h = ts.hour
    if h >= 22 or h < 7:
        return "Asia / Tokyo\u2013Sydney"
    if 7 <= h < 12:
        return "London"
    return "New York / US"


def format_pacific_timestamp(dt_or_iso: datetime | str | None) -> str:
    """Format a UTC datetime or ISO-8601 string in America/Los_Angeles (e.g. '2026-11-19 16:46:41 PST')."""
    ts = _coerce_utc_datetime(dt_or_iso)
    local_pt = ts.astimezone(_la_zone())
    abbr = local_pt.tzname() or "PT"
    return f"{local_pt.strftime('%Y-%m-%d %H:%M:%S')} {abbr}"


def session_date_for(now: datetime | None = None, *, rollover_hour_ny: int = 17) -> str:
    """Compute canonical trading session date (``YYYY-MM-DD``) rolling over at 17:00 New York time."""
    ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    local_dt = ts.astimezone(_ny_zone())
    shifted = local_dt + timedelta(hours=24 - rollover_hour_ny)
    return shifted.date().isoformat()


def next_ny_rollover_utc(now: datetime | None = None, *, rollover_hour_ny: int = 17) -> str:
    """Return exact next 17:00 America/New_York session open timestamp in ISO-8601 UTC."""
    ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    ny_tz = _ny_zone()
    local_ny = ts.astimezone(ny_tz)
    cand_ny = datetime(local_ny.year, local_ny.month, local_ny.day, rollover_hour_ny, 0, 0, tzinfo=ny_tz)
    if local_ny >= cand_ny:
        nxt_d = local_ny.date() + timedelta(days=1)
        cand_ny = datetime(nxt_d.year, nxt_d.month, nxt_d.day, rollover_hour_ny, 0, 0, tzinfo=ny_tz)
    return cand_ny.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def regional_session_window_for(now: datetime | None = None) -> dict[str, str]:
    """Compute contiguous 24h Global Forex Region window (ASIA 22-07Z, LONDON 07-12Z, NY 12-22Z)."""
    ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    h = ts.hour
    if h >= 22 or h < 7:
        anchor = (ts + timedelta(hours=2)).strftime("%Y-%m-%d")
        return {
            "period_key": f"{anchor}-ASIA",
            "region_code": "ASIA",
            "active_region_window": "ASIA (22:00–07:00 UTC / 14:00–23:00 PT)",
            "next_session_opens_utc": f"{anchor}T07:00:00Z",
            "session_rollover_label": "London Session 07:00 UTC (23:00 PT)",
        }
    if 7 <= h < 12:
        dstr = ts.strftime("%Y-%m-%d")
        return {
            "period_key": f"{dstr}-LONDON",
            "region_code": "LONDON",
            "active_region_window": "LONDON (07:00–12:00 UTC / 23:00–04:00 PT)",
            "next_session_opens_utc": f"{dstr}T12:00:00Z",
            "session_rollover_label": "New York Session 12:00 UTC (04:00 PT)",
        }
    dstr = ts.strftime("%Y-%m-%d")
    return {
        "period_key": f"{dstr}-NY",
        "region_code": "NY",
        "active_region_window": "NEW_YORK (12:00–22:00 UTC / 04:00–14:00 PT)",
        "next_session_opens_utc": f"{dstr}T22:00:00Z",
        "session_rollover_label": "Asia Session 22:00 UTC (14:00 PT)",
    }


def session_period_info_for(
    now: datetime | None = None,
    *,
    session_cadence: str = SESSION_CADENCE_AUTO,
    in_recovery_mode: bool = False,
) -> dict[str, Any]:
    """Resolve effective session period key, active region window, and next rollover UTC."""
    ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    cad = str(session_cadence or SESSION_CADENCE_AUTO).strip().upper()
    if cad not in VALID_SESSION_CADENCES:
        raise ContractError(f"session_cadence must be one of {VALID_SESSION_CADENCES}")
    use_regional = cad in (SESSION_CADENCE_REGIONAL_RECOVERY, SESSION_CADENCE_REGIONAL_8H) or (
        cad == SESSION_CADENCE_AUTO and bool(in_recovery_mode)
    )
    if use_regional:
        reg = regional_session_window_for(ts)
        return {
            **reg,
            "session_cadence": cad,
            "uses_regional_windows": True,
        }
    return {
        "period_key": session_date_for(ts),
        "region_code": "DAILY_NY",
        "active_region_window": "DAILY_NY (17:00 America/New_York)",
        "next_session_opens_utc": next_ny_rollover_utc(ts),
        "session_rollover_label": "17:00 America/New_York (14:00 Pacific)",
        "session_cadence": cad,
        "uses_regional_windows": False,
    }


def _q2(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


class DailyQuotaGovernanceStore:
    """Thread-safe durable daily/regional profit target lock & session loss circuit breaker."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        scope_id: str = "dual-shield-barbell",
        soft_quota_usd: Decimal = Decimal("500.00"),
        hard_quota_usd: Decimal = Decimal("1000.00"),
        daily_quota_pct: Decimal | None = None,
        quota_mode: str = "USD",
        max_loss_usd: Decimal = Decimal("500.00"),
        max_loss_pct: Decimal | None = Decimal("0.03"),
        max_consecutive_losses: int = 3,
        ratchet_activation_ratio: Decimal = DEFAULT_PROFIT_RATCHET_ACTIVATION_RATIO,
        ratchet_floor_ratio: Decimal = DEFAULT_PROFIT_RATCHET_FLOOR_RATIO,
        session_cadence: str = SESSION_CADENCE_AUTO,
        owner_verifier: Any | None = None,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._scope_id = identifier(scope_id, "scope_id")
        self._lock = RLock()
        self._initialized = False
        self._meta_loaded = False
        self._owner_verifier = owner_verifier
        self._days: dict[str, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._soft_quota_usd = decimal_value(Decimal(soft_quota_usd), "soft_quota_usd", positive=True)
        self._hard_quota_usd = decimal_value(Decimal(hard_quota_usd), "hard_quota_usd", positive=True)
        if self._soft_quota_usd > self._hard_quota_usd:
            raise ContractError("daily soft_quota_usd cannot exceed daily hard_quota_usd")
        self._daily_quota_pct = (
            decimal_value(Decimal(daily_quota_pct), "daily_quota_pct", positive=True)
            if daily_quota_pct is not None
            else None
        )
        if self._daily_quota_pct is not None and self._daily_quota_pct >= Decimal("1"):
            raise ContractError("daily_quota_pct must be strictly below 1.0 (100%)")
        mode_norm = str(quota_mode).strip().upper()
        if mode_norm not in QUOTA_MODES:
            raise ContractError(f"quota_mode must be one of {QUOTA_MODES}")
        self._quota_mode = mode_norm
        self._max_loss_usd = decimal_value(Decimal(max_loss_usd), "max_loss_usd", positive=True)
        self._max_loss_pct = (
            decimal_value(Decimal(max_loss_pct), "max_loss_pct", positive=True)
            if max_loss_pct is not None
            else None
        )
        if self._max_loss_pct is not None and self._max_loss_pct >= Decimal("1"):
            raise ContractError("max_loss_pct must be strictly below 1.0")
        self._max_consecutive_losses = integer(max_consecutive_losses, "max_consecutive_losses", minimum=1)
        act_r = decimal_value(Decimal(ratchet_activation_ratio), "ratchet_activation_ratio", positive=True)
        if act_r > Decimal("1"):
            raise ContractError("ratchet_activation_ratio must be in (0, 1]")
        flr_r = decimal_value(Decimal(ratchet_floor_ratio), "ratchet_floor_ratio", positive=True)
        if flr_r >= Decimal("1"):
            raise ContractError("ratchet_floor_ratio must be strictly in (0, 1)")
        self._ratchet_activation_ratio = act_r
        self._ratchet_floor_ratio = flr_r
        cad_norm = str(session_cadence or SESSION_CADENCE_AUTO).strip().upper()
        if cad_norm not in VALID_SESSION_CADENCES:
            raise ContractError(f"session_cadence must be one of {VALID_SESSION_CADENCES}")
        self._session_cadence = cad_norm
        self._explicit_cadence_arg = cad_norm != SESSION_CADENCE_AUTO
        self._active_period_base: str | None = None
        self._active_leg: int = 1
        self._leg_max_loss_cap_usd: Decimal | None = None
        self._unlocked_day_key: str | None = None
        self._unlocked_day_pnl_usd: Decimal = Decimal("0.00")

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
        *,
        path: str | Path | None = None,
        scope_id: str = "dual-shield-barbell",
    ) -> "DailyQuotaGovernanceStore":
        if not isinstance(environ, Mapping):
            raise ContractError("environ must be a Mapping")
        soft_raw = str(environ.get(ENV_DAILY_SOFT_QUOTA_USD, "")).strip() or "500.00"
        hard_raw = str(environ.get(ENV_DAILY_HARD_QUOTA_USD, "")).strip() or "1000.00"
        pct_raw = str(environ.get(ENV_DAILY_QUOTA_PCT, "")).strip()
        mode_raw = str(environ.get(ENV_DAILY_QUOTA_MODE, "")).strip() or ("COMPOUND_CAPPED" if pct_raw else "USD")
        mloss_raw = str(environ.get(ENV_DAILY_MAX_LOSS_USD, "")).strip() or "500.00"
        mlpct_raw = str(environ.get(ENV_DAILY_MAX_LOSS_PCT, "")).strip() or "0.03"
        consec_raw = str(environ.get(ENV_MAX_CONSECUTIVE_LOSSES, "")).strip() or "3"
        act_raw = str(environ.get(ENV_PROFIT_RATCHET_ACTIVATION_RATIO, "")).strip() or "0.50"
        flr_raw = str(environ.get(ENV_PROFIT_RATCHET_FLOOR_RATIO, "")).strip() or "0.70"
        cad_raw = str(environ.get(ENV_SESSION_CADENCE, "")).strip().upper() or SESSION_CADENCE_AUTO
        try:
            soft = Decimal(soft_raw)
            hard = Decimal(hard_raw)
            qpct = Decimal(pct_raw) if pct_raw else None
            mloss = Decimal(mloss_raw)
            mlpct = Decimal(mlpct_raw) if mlpct_raw else None
            consec = int(consec_raw)
            act_ratio = Decimal(act_raw)
            flr_ratio = Decimal(flr_raw)
        except Exception as exc:
            raise ContractError("invalid daily quota environment configuration") from exc
        return cls(
            path=path,
            scope_id=scope_id,
            soft_quota_usd=soft,
            hard_quota_usd=hard,
            daily_quota_pct=qpct,
            quota_mode=mode_raw,
            max_loss_usd=mloss,
            max_loss_pct=mlpct,
            max_consecutive_losses=consec,
            ratchet_activation_ratio=act_ratio,
            ratchet_floor_ratio=flr_ratio,
            session_cadence=cad_raw,
        )

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def session_cadence(self) -> str:
        with self._lock:
            return self._session_cadence

    def _connect(self) -> sqlite3.Connection:
        if self._path is None:
            raise ContractError("in-memory DailyQuotaGovernanceStore has no SQLite path")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if not self._initialized:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_quota_sessions (
                    session_key TEXT PRIMARY KEY,
                    session_date TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    starting_equity TEXT NOT NULL,
                    realized_net_pnl_usd TEXT NOT NULL,
                    peak_realized_pnl_usd TEXT NOT NULL DEFAULT '0',
                    closed_trades INTEGER NOT NULL,
                    win_count INTEGER NOT NULL,
                    loss_count INTEGER NOT NULL,
                    consecutive_losses INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    lock_reason TEXT,
                    updated_at TEXT NOT NULL,
                    max_loss_override_usd TEXT
                )
                """
            )
            existing_cols = {
                str(col_row[1])
                for col_row in conn.execute("PRAGMA table_info(daily_quota_sessions)").fetchall()
            }
            if "peak_realized_pnl_usd" not in existing_cols:
                conn.execute(
                    "ALTER TABLE daily_quota_sessions ADD COLUMN peak_realized_pnl_usd TEXT NOT NULL DEFAULT '0'"
                )
            if "max_loss_override_usd" not in existing_cols:
                conn.execute(
                    "ALTER TABLE daily_quota_sessions ADD COLUMN max_loss_override_usd TEXT"
                )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_quota_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_key TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    delta_pnl_usd TEXT NOT NULL,
                    status_after TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    prev_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    symbol TEXT,
                    trade_id TEXT,
                    broker_id TEXT
                )
                """
            )
            ev_cols = {
                str(r[1])
                for r in conn.execute("PRAGMA table_info(daily_quota_events)").fetchall()
            }
            if "symbol" not in ev_cols:
                conn.execute("ALTER TABLE daily_quota_events ADD COLUMN symbol TEXT")
            if "trade_id" not in ev_cols:
                conn.execute("ALTER TABLE daily_quota_events ADD COLUMN trade_id TEXT")
            if "broker_id" not in ev_cols:
                conn.execute("ALTER TABLE daily_quota_events ADD COLUMN broker_id TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_quota_meta (
                    scope_id TEXT PRIMARY KEY,
                    session_cadence TEXT NOT NULL,
                    active_period_base TEXT,
                    active_leg INTEGER NOT NULL DEFAULT 1,
                    leg_max_loss_cap_usd TEXT,
                    updated_at TEXT NOT NULL,
                    unlocked_day_key TEXT,
                    unlocked_day_pnl_usd TEXT
                )
                """
            )
            meta_cols = {
                str(r[1])
                for r in conn.execute("PRAGMA table_info(daily_quota_meta)").fetchall()
            }
            if "unlocked_day_key" not in meta_cols:
                conn.execute("ALTER TABLE daily_quota_meta ADD COLUMN unlocked_day_key TEXT")
            if "unlocked_day_pnl_usd" not in meta_cols:
                conn.execute("ALTER TABLE daily_quota_meta ADD COLUMN unlocked_day_pnl_usd TEXT")
            self._initialized = True
        if not self._meta_loaded:
            self._load_meta_from_conn(conn)
            self._meta_loaded = True
        return conn

    @staticmethod
    def _select_meta_row_static(conn: sqlite3.Connection, scope_id: str, *, has_unlock_cols: bool) -> Any:
        if has_unlock_cols:
            return conn.execute(
                "SELECT session_cadence, active_period_base, active_leg, leg_max_loss_cap_usd, "
                "unlocked_day_key, unlocked_day_pnl_usd "
                "FROM daily_quota_meta WHERE scope_id = ?",
                (scope_id,),
            ).fetchone()
        return conn.execute(
            "SELECT session_cadence, active_period_base, active_leg, leg_max_loss_cap_usd, NULL, NULL "
            "FROM daily_quota_meta WHERE scope_id = ?",
            (scope_id,),
        ).fetchone()

    def _load_meta_from_conn(self, conn: sqlite3.Connection) -> None:
        tables = {
            str(r[0])
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "daily_quota_meta" not in tables:
            return
        mcols = {str(c[1]) for c in conn.execute("PRAGMA table_info(daily_quota_meta)").fetchall()}
        has_unl = "unlocked_day_key" in mcols and "unlocked_day_pnl_usd" in mcols
        mrow = self._select_meta_row_static(conn, self._scope_id, has_unlock_cols=has_unl)
        if mrow is None:
            return
        saved_cad = str(mrow[0] or "").strip().upper()
        if not self._explicit_cadence_arg and saved_cad in VALID_SESSION_CADENCES:
            self._session_cadence = saved_cad
        self._active_period_base = str(mrow[1]) if mrow[1] not in (None, "") else None
        self._active_leg = max(1, int(mrow[2] or 1))
        self._leg_max_loss_cap_usd = (
            Decimal(str(mrow[3])) if mrow[3] not in (None, "") else None
        )
        self._unlocked_day_key = str(mrow[4]) if mrow[4] not in (None, "") else None
        self._unlocked_day_pnl_usd = (
            Decimal(str(mrow[5])) if mrow[5] not in (None, "") else Decimal("0.00")
        )

    def _persist_meta(self, conn: sqlite3.Connection, ts_str: str) -> None:
        conn.execute(
            """
            INSERT INTO daily_quota_meta (
                scope_id, session_cadence, active_period_base, active_leg,
                leg_max_loss_cap_usd, updated_at, unlocked_day_key, unlocked_day_pnl_usd
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_id) DO UPDATE SET
                session_cadence = excluded.session_cadence,
                active_period_base = excluded.active_period_base,
                active_leg = excluded.active_leg,
                leg_max_loss_cap_usd = excluded.leg_max_loss_cap_usd,
                updated_at = excluded.updated_at,
                unlocked_day_key = excluded.unlocked_day_key,
                unlocked_day_pnl_usd = excluded.unlocked_day_pnl_usd
            """,
            (
                self._scope_id,
                self._session_cadence,
                self._active_period_base,
                int(self._active_leg),
                None if self._leg_max_loss_cap_usd is None else decimal_text(self._leg_max_loss_cap_usd),
                ts_str,
                self._unlocked_day_key,
                decimal_text(self._unlocked_day_pnl_usd),
            ),
        )

    def _resolve_session_target(
        self,
        ts: datetime,
        *,
        in_recovery_mode: bool = False,
        cadence_override: str | None = None,
        active_base_override: str | None = None,
        active_leg_override: int | None = None,
        leg_cap_override: Decimal | None = None,
    ) -> tuple[str, dict[str, Any], int, Decimal | None]:
        cad = cadence_override if cadence_override is not None else self._session_cadence
        pinfo = session_period_info_for(ts, session_cadence=cad, in_recovery_mode=in_recovery_mode)
        base_key = str(pinfo["period_key"])
        act_base = active_base_override if active_base_override is not None else self._active_period_base
        act_leg = active_leg_override if active_leg_override is not None else self._active_leg
        leg_cap = leg_cap_override if leg_cap_override is not None else self._leg_max_loss_cap_usd
        if act_base == base_key and act_leg > 1:
            return f"{base_key}#leg{act_leg}", pinfo, act_leg, leg_cap
        return base_key, pinfo, 1, None

    def set_session_cadence(
        self,
        cadence: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        clean = str(cadence or "").strip().upper()
        if clean not in VALID_SESSION_CADENCES:
            raise ContractError(f"session_cadence must be one of {VALID_SESSION_CADENCES}")
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        with self._lock:
            self._session_cadence = clean
            self._explicit_cadence_arg = True
            if self._path is not None:
                conn = self._connect()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    self._persist_meta(conn, ts_str)
                    conn.commit()
                except Exception:
                    if conn.in_transaction:
                        conn.rollback()
                    raise
                finally:
                    conn.close()
        return self.peek_snapshot(now=ts)

    def advance_recovery_leg(
        self,
        *,
        reason: str,
        in_recovery_mode: bool = True,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Advance to a fresh recovery leg (#leg2, #leg3, ...) after a locked green leg, capping giveback at <=30%."""
        if not isinstance(reason, str) or not reason.strip():
            raise ContractError("advance_recovery_leg requires a non-empty reason")
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        with self._lock:
            if self._path is None:
                sdate, pinfo, cur_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                cur_row = self._load_or_init_row(
                    sdate, starting_equity=None, ts_str=ts_str, max_loss_override=leg_cap
                )
                cur_status = str(cur_row["status"])
                if cur_status == QUOTA_STATUS_LOSS_TRIPPED:
                    raise ContractError(
                        "DAILY_LOSS_CIRCUIT_TRIPPED cannot be bypassed via recovery leg advance; owner recovery token required"
                    )
                if cur_status not in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                    raise ContractError(
                        f"Recovery leg advance requires DAILY_QUOTA_LOCKED or PROFIT_FLOOR_LOCKED, got {cur_status}"
                    )
                new_leg_cap = self._compute_next_leg_loss_cap(cur_row)
                base_key = str(pinfo["period_key"])
                next_leg = cur_leg + 1
                next_sdate = f"{base_key}#leg{next_leg}"
                self._active_period_base = base_key
                self._active_leg = next_leg
                self._leg_max_loss_cap_usd = new_leg_cap
                start_eq = Decimal(str(cur_row["starting_equity"]))
                next_row = self._load_or_init_row(
                    next_sdate,
                    starting_equity=start_eq if start_eq > Decimal("0") else None,
                    ts_str=ts_str,
                    max_loss_override=new_leg_cap,
                )
                next_row["max_loss_override_usd"] = decimal_text(new_leg_cap)
                return self._format_snapshot(
                    next_row, session_cadence=self._session_cadence, active_leg=next_leg
                )

            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                sdate, pinfo, cur_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                cur_row = self._load_or_init_row(
                    sdate, starting_equity=None, ts_str=ts_str, conn=conn, max_loss_override=leg_cap
                )
                cur_status = str(cur_row["status"])
                if cur_status == QUOTA_STATUS_LOSS_TRIPPED:
                    raise ContractError(
                        "DAILY_LOSS_CIRCUIT_TRIPPED cannot be bypassed via recovery leg advance; owner recovery token required"
                    )
                if cur_status not in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                    raise ContractError(
                        f"Recovery leg advance requires DAILY_QUOTA_LOCKED or PROFIT_FLOOR_LOCKED, got {cur_status}"
                    )
                new_leg_cap = self._compute_next_leg_loss_cap(cur_row)
                base_key = str(pinfo["period_key"])
                next_leg = cur_leg + 1
                next_sdate = f"{base_key}#leg{next_leg}"
                self._active_period_base = base_key
                self._active_leg = next_leg
                self._leg_max_loss_cap_usd = new_leg_cap
                self._persist_meta(conn, ts_str)
                start_eq = Decimal(str(cur_row["starting_equity"]))
                next_row = self._load_or_init_row(
                    next_sdate,
                    starting_equity=start_eq if start_eq > Decimal("0") else None,
                    ts_str=ts_str,
                    conn=conn,
                    max_loss_override=new_leg_cap,
                )
                next_row["max_loss_override_usd"] = decimal_text(new_leg_cap)
                next_row["updated_at"] = ts_str
                self._save_row_and_event(
                    next_row,
                    event_kind=f"ADVANCE_RECOVERY_LEG:{next_leg}",
                    delta_pnl_usd="0",
                    conn=conn,
                )
                conn.commit()
                return self._format_snapshot(
                    next_row, session_cadence=self._session_cadence, active_leg=next_leg
                )
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def _compute_next_leg_loss_cap(self, prior_row: Mapping[str, Any]) -> Decimal:
        start_eq = Decimal(str(prior_row["starting_equity"]))
        start_pos = start_eq if start_eq > Decimal("0") else None
        _, _, configured_max_loss = self._effective_targets(start_pos)
        prior_pnl = max(Decimal("0.00"), Decimal(str(prior_row["realized_net_pnl_usd"])))
        giveback_30 = _q2(prior_pnl * DEFAULT_RECOVERY_LEG_GIVEBACK_RATIO)
        return min(configured_max_loss, max(MIN_RECOVERY_LEG_LOSS_FLOOR_USD, giveback_30))

    def _effective_targets(
        self,
        starting_equity: Decimal | None,
        *,
        max_loss_override: Decimal | None = None,
    ) -> tuple[Decimal, Decimal, Decimal]:
        with self._lock:
            soft = self._soft_quota_usd
            hard = self._hard_quota_usd
            qpct = self._daily_quota_pct
            mode = self._quota_mode
            max_loss = self._max_loss_usd
            max_loss_pct = self._max_loss_pct

        if starting_equity is not None and starting_equity > Decimal("0"):
            if mode in ("PCT", "COMPOUND_CAPPED") and qpct is not None:
                pct_hard = _q2(starting_equity * qpct)
                if mode == "PCT":
                    hard = max(Decimal("1.00"), pct_hard)
                else:
                    hard = max(Decimal("1.00"), min(hard, pct_hard))
                soft = max(Decimal("0.50"), _q2(hard * Decimal("0.50")))
            if max_loss_pct is not None:
                pct_loss = _q2(starting_equity * max_loss_pct)
                max_loss = max(Decimal("1.00"), min(max_loss, pct_loss))
        if max_loss_override is not None and max_loss_override > Decimal("0"):
            max_loss = min(max_loss, _q2(max_loss_override))
        return soft, hard, max_loss

    @staticmethod
    def _row_loss_override(row: Mapping[str, Any]) -> Decimal | None:
        raw_ov = row.get("max_loss_override_usd")
        if raw_ov in (None, ""):
            return None
        try:
            dec = Decimal(str(raw_ov))
            return dec if dec > Decimal("0") else None
        except Exception:
            return None

    def _ratchet_metrics(self, row: Mapping[str, Any], soft: Decimal) -> tuple[Decimal, Decimal, bool, Decimal]:
        pnl = Decimal(str(row["realized_net_pnl_usd"]))
        raw_peak = Decimal(str(row.get("peak_realized_pnl_usd", "0")))
        peak_pnl = _q2(max(raw_peak, pnl, Decimal("0")))
        activation_usd = _q2(soft * self._ratchet_activation_ratio)
        if peak_pnl >= activation_usd:
            return peak_pnl, activation_usd, True, _q2(peak_pnl * self._ratchet_floor_ratio)
        return peak_pnl, activation_usd, False, Decimal("0.00")

    def _compute_status(self, row: Mapping[str, Any]) -> tuple[str, str | None]:
        start_eq = Decimal(str(row["starting_equity"])) if Decimal(str(row["starting_equity"])) > 0 else None
        soft, hard, max_loss = self._effective_targets(
            start_eq, max_loss_override=self._row_loss_override(row)
        )
        pnl = Decimal(str(row["realized_net_pnl_usd"]))
        consec = int(row["consecutive_losses"])
        peak_pnl, _, ratchet_armed, protected_floor_usd = self._ratchet_metrics(row, soft)
        if pnl >= hard:
            return QUOTA_STATUS_LOCKED, f"Daily profit quota reached ({decimal_text(pnl)} >= {decimal_text(hard)} USD)"
        if ratchet_armed and pnl <= protected_floor_usd:
            return (
                QUOTA_STATUS_PROFIT_FLOOR_LOCKED,
                f"Protected daily profit floor locked ({decimal_text(pnl)} <= {decimal_text(protected_floor_usd)} USD from {decimal_text(peak_pnl)} USD peak)",
            )
        if pnl <= -max_loss:
            return QUOTA_STATUS_LOSS_TRIPPED, f"Daily max loss reached ({decimal_text(pnl)} <= -{decimal_text(max_loss)} USD)"
        if consec >= self._max_consecutive_losses:
            return QUOTA_STATUS_LOSS_TRIPPED, f"Consecutive losses reached limit ({consec} >= {self._max_consecutive_losses})"
        if pnl >= soft:
            return QUOTA_STATUS_SOFT, f"Daily soft quota reached ({decimal_text(pnl)} >= {decimal_text(soft)} USD); risk halved"
        return QUOTA_STATUS_OPEN, None

    @staticmethod
    def _trading_day_roots(ts: datetime) -> tuple[str, str]:
        ny_d = session_date_for(ts)
        reg_p = regional_session_window_for(ts)["period_key"]
        reg_d = reg_p.rsplit("-", 1)[0]
        return ny_d, reg_d

    @staticmethod
    def _matches_trading_day(session_date: str, d1: str, d2: str) -> bool:
        for d in (d1, d2):
            if session_date == d or session_date.startswith(f"{d}-") or session_date.startswith(f"{d}#"):
                return True
        return False

    @staticmethod
    def _select_day_rows_static(
        conn: sqlite3.Connection,
        scope_id: str,
        d1: str,
        d2: str,
        *,
        has_peak: bool,
        has_ov: bool,
    ) -> list[Any]:
        params = (scope_id, d1, f"{d1}-%", f"{d1}#%", d2, f"{d2}-%", f"{d2}#%")
        if has_peak and has_ov:
            return conn.execute(
                "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
                "peak_realized_pnl_usd, closed_trades, win_count, loss_count, consecutive_losses, "
                "status, lock_reason, updated_at, max_loss_override_usd "
                "FROM daily_quota_sessions "
                "WHERE scope_id = ? AND ("
                "session_date = ? OR session_date LIKE ? OR session_date LIKE ? "
                "OR session_date = ? OR session_date LIKE ? OR session_date LIKE ?"
                ") ORDER BY updated_at ASC, session_key ASC",
                params,
            ).fetchall()
        if has_peak:
            return conn.execute(
                "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
                "peak_realized_pnl_usd, closed_trades, win_count, loss_count, consecutive_losses, "
                "status, lock_reason, updated_at, NULL "
                "FROM daily_quota_sessions "
                "WHERE scope_id = ? AND ("
                "session_date = ? OR session_date LIKE ? OR session_date LIKE ? "
                "OR session_date = ? OR session_date LIKE ? OR session_date LIKE ?"
                ") ORDER BY updated_at ASC, session_key ASC",
                params,
            ).fetchall()
        return conn.execute(
            "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
            "'0', closed_trades, win_count, loss_count, consecutive_losses, "
            "status, lock_reason, updated_at, NULL "
            "FROM daily_quota_sessions "
            "WHERE scope_id = ? AND ("
            "session_date = ? OR session_date LIKE ? OR session_date LIKE ? "
            "OR session_date = ? OR session_date LIKE ? OR session_date LIKE ?"
            ") ORDER BY updated_at ASC, session_key ASC",
            params,
        ).fetchall()

    def _collect_trading_day_rows(
        self,
        ts: datetime,
        *,
        conn: sqlite3.Connection | None,
        has_peak: bool = True,
        has_ov: bool = True,
    ) -> list[dict[str, Any]]:
        d1, d2 = self._trading_day_roots(ts)
        if conn is None:
            matched = [
                dict(r)
                for r in self._days.values()
                if r.get("scope_id") == self._scope_id
                and self._matches_trading_day(str(r.get("session_date", "")), d1, d2)
            ]
            matched.sort(key=lambda item: (str(item.get("updated_at", "")), str(item.get("session_key", ""))))
            return matched
        raw_rows = self._select_day_rows_static(
            conn, self._scope_id, d1, d2, has_peak=has_peak, has_ov=has_ov
        )
        out: list[dict[str, Any]] = []
        for db_row in raw_rows:
            loaded_pnl = Decimal(str(db_row[4]))
            loaded_peak = _q2(max(Decimal(str(db_row[5] or "0")), loaded_pnl, Decimal("0")))
            out.append({
                "session_key": str(db_row[0]),
                "session_date": str(db_row[1]),
                "scope_id": str(db_row[2]),
                "starting_equity": str(db_row[3]),
                "realized_net_pnl_usd": str(db_row[4]),
                "peak_realized_pnl_usd": decimal_text(loaded_peak),
                "closed_trades": int(db_row[6]),
                "win_count": int(db_row[7]),
                "loss_count": int(db_row[8]),
                "consecutive_losses": int(db_row[9]),
                "status": str(db_row[10]),
                "lock_reason": db_row[11],
                "updated_at": str(db_row[12]),
                "max_loss_override_usd": None if db_row[13] in (None, "") else str(db_row[13]),
            })
        return out

    def _apply_trading_day_loss_overlay(
        self,
        ts: datetime,
        active_row: Mapping[str, Any],
        *,
        conn: sqlite3.Connection | None,
        has_peak: bool = True,
        has_ov: bool = True,
        unlocked_day_override: str | None = None,
        unlocked_pnl_override: Decimal | None = None,
    ) -> dict[str, Any]:
        """Enforce trading-day-wide loss-circuit carryover across $300k daily<->regional cadence switches."""
        out = dict(active_row)
        cur_status = str(out["status"])
        if cur_status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
            return out

        d1, d2 = self._trading_day_roots(ts)
        day_rows = self._collect_trading_day_rows(ts, conn=conn, has_peak=has_peak, has_ov=has_ov)
        active_key = str(out["session_key"])
        merged: list[dict[str, Any]] = []
        replaced = False
        for r in day_rows:
            if str(r["session_key"]) == active_key:
                merged.append(dict(out))
                replaced = True
            else:
                merged.append(r)
        if not replaced:
            merged.append(dict(out))
        merged.sort(key=lambda item: (str(item.get("updated_at", "")), str(item.get("session_key", ""))))

        # 1. Any row on this trading day in DAILY_LOSS_CIRCUIT_TRIPPED locks the entire trading day
        for r in merged:
            if str(r["status"]) == QUOTA_STATUS_LOSS_TRIPPED:
                out["status"] = QUOTA_STATUS_LOSS_TRIPPED
                out["lock_reason"] = (
                    r.get("lock_reason")
                    or f"Trading-day loss circuit active from {r.get('session_date')}"
                )
                out["consecutive_losses"] = max(
                    int(out["consecutive_losses"]), int(r["consecutive_losses"])
                )
                return out

        # 2. Combined net realized P&L across the day's rows <= -day_max_loss
        day_pnl = sum((Decimal(str(r["realized_net_pnl_usd"])) for r in merged), Decimal("0.00"))
        unl_day = unlocked_day_override if unlocked_day_override is not None else self._unlocked_day_key
        unl_pnl = unlocked_pnl_override if unlocked_pnl_override is not None else self._unlocked_day_pnl_usd
        baseline_pnl = unl_pnl if (unl_day is not None and unl_day in (d1, d2)) else Decimal("0.00")
        net_since_unlock = _q2(day_pnl - baseline_pnl)

        start_candidates = [
            Decimal(str(r["starting_equity"]))
            for r in merged
            if Decimal(str(r["starting_equity"])) > Decimal("0")
        ]
        day_start_eq = max(start_candidates) if start_candidates else None
        _, _, day_max_loss = self._effective_targets(day_start_eq, max_loss_override=None)
        if net_since_unlock <= -day_max_loss:
            out["status"] = QUOTA_STATUS_LOSS_TRIPPED
            out["lock_reason"] = (
                f"Trading-day combined max loss reached ({decimal_text(net_since_unlock)} <= -{decimal_text(day_max_loss)} USD)"
            )
            return out

        # 3. Trailing consecutive losses across non-profit-locked rows of the trading day
        trailing_consec = 0
        for r in merged:
            r_st = str(r["status"])
            if r_st in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED):
                trailing_consec = 0
            elif int(r["closed_trades"]) == 0:
                continue
            elif int(r["win_count"]) > 0:
                trailing_consec = int(r["consecutive_losses"])
            else:
                trailing_consec += int(r["consecutive_losses"])

        if trailing_consec >= self._max_consecutive_losses:
            out["status"] = QUOTA_STATUS_LOSS_TRIPPED
            out["consecutive_losses"] = trailing_consec
            out["lock_reason"] = (
                f"Trading-day consecutive losses reached limit ({trailing_consec} >= {self._max_consecutive_losses})"
            )
        return out

    @staticmethod
    def _select_session_row_static(
        conn: sqlite3.Connection,
        session_key: str,
        *,
        has_peak: bool,
        has_ov: bool,
    ) -> Any:
        if has_peak and has_ov:
            return conn.execute(
                "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
                "peak_realized_pnl_usd, closed_trades, win_count, loss_count, consecutive_losses, "
                "status, lock_reason, updated_at, max_loss_override_usd "
                "FROM daily_quota_sessions WHERE session_key = ?",
                (session_key,),
            ).fetchone()
        if has_peak:
            return conn.execute(
                "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
                "peak_realized_pnl_usd, closed_trades, win_count, loss_count, consecutive_losses, "
                "status, lock_reason, updated_at, NULL "
                "FROM daily_quota_sessions WHERE session_key = ?",
                (session_key,),
            ).fetchone()
        return conn.execute(
            "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
            "'0', closed_trades, win_count, loss_count, consecutive_losses, "
            "status, lock_reason, updated_at, NULL "
            "FROM daily_quota_sessions WHERE session_key = ?",
            (session_key,),
        ).fetchone()

    def _find_legacy_asia_seed(
        self,
        session_date: str,
        *,
        conn: sqlite3.Connection | None = None,
        has_peak_col: bool = True,
        has_override_col: bool = True,
    ) -> dict[str, Any] | None:
        """Carry live Asia row YYYY-MM-DD into YYYY-MM-DD-ASIA when updated inside [22:00Z, 07:00Z)."""
        if not (session_date.endswith("-ASIA") and len(session_date) == 15):
            return None
        anchor_str = session_date[:-5]
        try:
            anchor_dt = datetime.fromisoformat(f"{anchor_str}T00:00:00+00:00")
        except ValueError:
            return None
        asia_start = anchor_dt - timedelta(hours=2)
        asia_end = anchor_dt + timedelta(hours=7)
        legacy_key = f"{self._scope_id}:{anchor_str}"
        target_key = f"{self._scope_id}:{session_date}"

        if conn is None:
            cand = self._days.get(legacy_key)
            if cand is None:
                return None
            try:
                upd_dt = datetime.fromisoformat(str(cand["updated_at"]).replace("Z", "+00:00"))
            except ValueError:
                return None
            if not (asia_start <= upd_dt < asia_end):
                return None
            cloned = dict(cand)
            cloned["session_key"] = target_key
            cloned["session_date"] = session_date
            return cloned

        db_row = self._select_session_row_static(
            conn, legacy_key, has_peak=has_peak_col, has_ov=has_override_col
        )
        if db_row is None:
            return None
        try:
            upd_dt = datetime.fromisoformat(str(db_row[12]).replace("Z", "+00:00"))
        except ValueError:
            return None
        if not (asia_start <= upd_dt < asia_end):
            return None
        loaded_pnl = Decimal(str(db_row[4]))
        loaded_peak = _q2(max(Decimal(str(db_row[5] or "0")), loaded_pnl, Decimal("0")))
        return {
            "session_key": target_key,
            "session_date": session_date,
            "scope_id": str(db_row[2]),
            "starting_equity": str(db_row[3]),
            "realized_net_pnl_usd": str(db_row[4]),
            "peak_realized_pnl_usd": decimal_text(loaded_peak),
            "closed_trades": int(db_row[6]),
            "win_count": int(db_row[7]),
            "loss_count": int(db_row[8]),
            "consecutive_losses": int(db_row[9]),
            "status": str(db_row[10]),
            "lock_reason": db_row[11],
            "updated_at": str(db_row[12]),
            "max_loss_override_usd": None if db_row[13] in (None, "") else str(db_row[13]),
        }

    def _load_or_init_row(
        self,
        session_date: str,
        *,
        starting_equity: Decimal | None,
        ts_str: str,
        conn: sqlite3.Connection | None = None,
        max_loss_override: Decimal | None = None,
    ) -> dict[str, Any]:
        key = f"{self._scope_id}:{session_date}"
        ov_str = None if max_loss_override is None else decimal_text(_q2(max_loss_override))
        if conn is None:
            row = self._days.get(key)
            if row is None:
                seeded = self._find_legacy_asia_seed(session_date, conn=None)
                if seeded is not None:
                    self._days[key] = seeded
                    return seeded
                start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
                row = {
                    "session_key": key,
                    "session_date": session_date,
                    "scope_id": self._scope_id,
                    "starting_equity": start_val,
                    "realized_net_pnl_usd": "0",
                    "peak_realized_pnl_usd": "0",
                    "closed_trades": 0,
                    "win_count": 0,
                    "loss_count": 0,
                    "consecutive_losses": 0,
                    "status": QUOTA_STATUS_OPEN,
                    "lock_reason": None,
                    "updated_at": ts_str,
                    "max_loss_override_usd": ov_str,
                }
                self._days[key] = row
            else:
                if Decimal(str(row["starting_equity"])) <= 0 and starting_equity is not None and starting_equity > 0:
                    row["starting_equity"] = decimal_text(_q2(starting_equity))
                if ov_str is not None and row.get("max_loss_override_usd") in (None, ""):
                    row["max_loss_override_usd"] = ov_str
            return row

        db_row = conn.execute(
            "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
            "peak_realized_pnl_usd, closed_trades, win_count, loss_count, consecutive_losses, "
            "status, lock_reason, updated_at, max_loss_override_usd "
            "FROM daily_quota_sessions WHERE session_key = ?",
            (key,),
        ).fetchone()
        if db_row is None:
            seeded = self._find_legacy_asia_seed(session_date, conn=conn)
            if seeded is not None:
                row = seeded
            else:
                start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
                row = {
                    "session_key": key,
                    "session_date": session_date,
                    "scope_id": self._scope_id,
                    "starting_equity": start_val,
                    "realized_net_pnl_usd": "0",
                    "peak_realized_pnl_usd": "0",
                    "closed_trades": 0,
                    "win_count": 0,
                    "loss_count": 0,
                    "consecutive_losses": 0,
                    "status": QUOTA_STATUS_OPEN,
                    "lock_reason": None,
                    "updated_at": ts_str,
                    "max_loss_override_usd": ov_str,
                }
            conn.execute(
                """
                INSERT INTO daily_quota_sessions (
                    session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd,
                    peak_realized_pnl_usd, closed_trades, win_count, loss_count, consecutive_losses,
                    status, lock_reason, updated_at, max_loss_override_usd
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    session_date,
                    self._scope_id,
                    row["starting_equity"],
                    row["realized_net_pnl_usd"],
                    row["peak_realized_pnl_usd"],
                    row["closed_trades"],
                    row["win_count"],
                    row["loss_count"],
                    row["consecutive_losses"],
                    row["status"],
                    row["lock_reason"],
                    row["updated_at"],
                    row.get("max_loss_override_usd"),
                ),
            )
            return row
        loaded_pnl = Decimal(str(db_row[4]))
        loaded_peak = _q2(max(Decimal(str(db_row[5] or "0")), loaded_pnl, Decimal("0")))
        row = {
            "session_key": db_row[0],
            "session_date": db_row[1],
            "scope_id": db_row[2],
            "starting_equity": db_row[3],
            "realized_net_pnl_usd": db_row[4],
            "peak_realized_pnl_usd": decimal_text(loaded_peak),
            "closed_trades": int(db_row[6]),
            "win_count": int(db_row[7]),
            "loss_count": int(db_row[8]),
            "consecutive_losses": int(db_row[9]),
            "status": db_row[10],
            "lock_reason": db_row[11],
            "updated_at": db_row[12],
            "max_loss_override_usd": None if db_row[13] in (None, "") else str(db_row[13]),
        }
        if Decimal(str(row["starting_equity"])) <= 0 and starting_equity is not None and starting_equity > 0:
            row["starting_equity"] = decimal_text(_q2(starting_equity))
            conn.execute(
                "UPDATE daily_quota_sessions SET starting_equity = ? WHERE session_key = ?",
                (row["starting_equity"], key),
            )
        if ov_str is not None and row.get("max_loss_override_usd") in (None, ""):
            row["max_loss_override_usd"] = ov_str
            conn.execute(
                "UPDATE daily_quota_sessions SET max_loss_override_usd = ? WHERE session_key = ?",
                (ov_str, key),
            )
        return row

    def _save_row_and_event(
        self,
        row: dict[str, Any],
        *,
        event_kind: str,
        delta_pnl_usd: str,
        conn: sqlite3.Connection | None,
        symbol: str | None = None,
        trade_id: str | None = None,
        broker_id: str | None = None,
    ) -> None:
        if conn is None:
            self._days[row["session_key"]] = dict(row)
            if event_kind in ("CLOSED_TRADE", "REALIZED_TRADE"):
                self._events.append({
                    "seq": len(self._events) + 1,
                    "session_key": str(row["session_key"]),
                    "event_kind": event_kind,
                    "delta_pnl_usd": delta_pnl_usd,
                    "status_after": str(row["status"]),
                    "observed_at": str(row["updated_at"]),
                    "symbol": symbol,
                    "trade_id": trade_id,
                    "broker_id": broker_id,
                })
            return
        prev = conn.execute("SELECT event_sha256 FROM daily_quota_events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_sha = str(prev[0]) if prev is not None else GENESIS_SHA256
        ev_payload: dict[str, Any] = {
            "session_key": row["session_key"],
            "event_kind": event_kind,
            "delta_pnl_usd": delta_pnl_usd,
            "status_after": row["status"],
            "observed_at": row["updated_at"],
            "prev_sha256": prev_sha,
        }
        if symbol is not None:
            ev_payload["symbol"] = symbol
        if trade_id is not None:
            ev_payload["trade_id"] = trade_id
        if broker_id is not None:
            ev_payload["broker_id"] = broker_id
        ev_sha = sha256(canonical_bytes(ev_payload)).hexdigest()
        conn.execute(
            """
            UPDATE daily_quota_sessions SET
                starting_equity = ?, realized_net_pnl_usd = ?, peak_realized_pnl_usd = ?,
                closed_trades = ?, win_count = ?, loss_count = ?, consecutive_losses = ?,
                status = ?, lock_reason = ?, updated_at = ?, max_loss_override_usd = ?
            WHERE session_key = ?
            """,
            (
                row["starting_equity"],
                row["realized_net_pnl_usd"],
                row.get("peak_realized_pnl_usd", "0"),
                row["closed_trades"],
                row["win_count"],
                row["loss_count"],
                row["consecutive_losses"],
                row["status"],
                row["lock_reason"],
                row["updated_at"],
                row.get("max_loss_override_usd"),
                row["session_key"],
            ),
        )
        conn.execute(
            """
            INSERT INTO daily_quota_events (
                session_key, event_kind, delta_pnl_usd, status_after, observed_at,
                prev_sha256, event_sha256, symbol, trade_id, broker_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["session_key"],
                event_kind,
                delta_pnl_usd,
                row["status"],
                row["updated_at"],
                prev_sha,
                ev_sha,
                symbol,
                trade_id,
                broker_id,
            ),
        )

    def observe_day_start(
        self,
        starting_equity: Decimal,
        *,
        now: datetime | None = None,
        in_recovery_mode: bool = False,
    ) -> dict[str, Any]:
        decimal_value(starting_equity, "starting_equity", positive=True)
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        with self._lock:
            if self._path is None:
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                row = self._load_or_init_row(
                    sdate, starting_equity=starting_equity, ts_str=ts_str, max_loss_override=leg_cap
                )
                eff_row = self._apply_trading_day_loss_overlay(ts, row, conn=None)
                return self._format_snapshot(eff_row, session_cadence=self._session_cadence, active_leg=act_leg)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                row = self._load_or_init_row(
                    sdate, starting_equity=starting_equity, ts_str=ts_str, conn=conn, max_loss_override=leg_cap
                )
                eff_row = self._apply_trading_day_loss_overlay(ts, row, conn=conn)
                conn.commit()
                return self._format_snapshot(eff_row, session_cadence=self._session_cadence, active_leg=act_leg)
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    observe_equity = observe_day_start

    def record_realized_trade(
        self,
        pnl_usd: Decimal,
        *,
        symbol: str | None = None,
        ticket: str | None = None,
        trade_id: str | None = None,
        broker_id: str | None = None,
        starting_equity: Decimal | None = None,
        now: datetime | None = None,
        in_recovery_mode: bool = False,
    ) -> dict[str, Any]:
        pnl_dec = decimal_value(pnl_usd, "pnl_usd")
        clean_sym = (
            identifier(str(symbol).strip(), "symbol")
            if (symbol is not None and str(symbol).strip())
            else None
        )
        raw_tid = (
            str(trade_id).strip()
            if (trade_id is not None and str(trade_id).strip())
            else (str(ticket).strip() if (ticket is not None and str(ticket).strip()) else "")
        )
        clean_tid = identifier(raw_tid, "trade_id") if raw_tid else None
        clean_brk = (
            identifier(str(broker_id).strip(), "broker_id")
            if (broker_id is not None and str(broker_id).strip())
            else None
        )
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        delta_txt = decimal_text(_q2(pnl_dec))
        with self._lock:
            if self._path is None:
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                row = self._load_or_init_row(
                    sdate, starting_equity=starting_equity, ts_str=ts_str, max_loss_override=leg_cap
                )
                self._apply_trade(row, pnl_dec, ts_str)
                overlaid = self._apply_trading_day_loss_overlay(ts, row, conn=None)
                if overlaid["status"] == QUOTA_STATUS_LOSS_TRIPPED and row["status"] != QUOTA_STATUS_LOSS_TRIPPED:
                    row["status"] = QUOTA_STATUS_LOSS_TRIPPED
                    row["lock_reason"] = overlaid["lock_reason"]
                    row["consecutive_losses"] = overlaid["consecutive_losses"]
                self._save_row_and_event(
                    row,
                    event_kind="CLOSED_TRADE",
                    delta_pnl_usd=delta_txt,
                    conn=None,
                    symbol=clean_sym,
                    trade_id=clean_tid,
                    broker_id=clean_brk,
                )
                return self._format_snapshot(overlaid, session_cadence=self._session_cadence, active_leg=act_leg)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                row = self._load_or_init_row(
                    sdate, starting_equity=starting_equity, ts_str=ts_str, conn=conn, max_loss_override=leg_cap
                )
                self._apply_trade(row, pnl_dec, ts_str)
                overlaid = self._apply_trading_day_loss_overlay(ts, row, conn=conn)
                if overlaid["status"] == QUOTA_STATUS_LOSS_TRIPPED and row["status"] != QUOTA_STATUS_LOSS_TRIPPED:
                    row["status"] = QUOTA_STATUS_LOSS_TRIPPED
                    row["lock_reason"] = overlaid["lock_reason"]
                    row["consecutive_losses"] = overlaid["consecutive_losses"]
                self._save_row_and_event(
                    row,
                    event_kind="CLOSED_TRADE",
                    delta_pnl_usd=delta_txt,
                    conn=conn,
                    symbol=clean_sym,
                    trade_id=clean_tid,
                    broker_id=clean_brk,
                )
                conn.commit()
                return self._format_snapshot(overlaid, session_cadence=self._session_cadence, active_leg=act_leg)
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    record_closed_trade = record_realized_trade

    @staticmethod
    def _select_closed_events_static(
        conn: sqlite3.Connection,
        scope_prefix: str,
        limit: int,
        *,
        has_prov_cols: bool,
    ) -> list[Any]:
        if has_prov_cols:
            return conn.execute(
                "SELECT seq, session_key, delta_pnl_usd, status_after, observed_at, "
                "symbol, trade_id, broker_id "
                "FROM daily_quota_events "
                "WHERE session_key LIKE ? AND event_kind IN ('CLOSED_TRADE', 'REALIZED_TRADE') "
                "ORDER BY seq DESC LIMIT ?",
                (scope_prefix, limit),
            ).fetchall()
        return conn.execute(
            "SELECT seq, session_key, delta_pnl_usd, status_after, observed_at, "
            "NULL, NULL, NULL "
            "FROM daily_quota_events "
            "WHERE session_key LIKE ? AND event_kind IN ('CLOSED_TRADE', 'REALIZED_TRADE') "
            "ORDER BY seq DESC LIMIT ?",
            (scope_prefix, limit),
        ).fetchall()

    def recent_closed_trades(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """Strictly read-only query (?mode=ro, 0 SQLite writes) returning newest closed trade events."""
        lim = max(1, min(500, integer(limit, "limit", minimum=1)))
        prefix = f"{self._scope_id}:"
        with self._lock:
            if self._path is None:
                out_mem: list[dict[str, Any]] = []
                for ev in reversed(self._events):
                    skey = str(ev.get("session_key", ""))
                    if not skey.startswith(prefix):
                        continue
                    sdate_part = skey[len(prefix):]
                    obs_utc = str(ev["observed_at"])
                    brk_val = ev.get("broker_id")
                    out_mem.append({
                        "seq": int(ev["seq"]),
                        "session_key": sdate_part,
                        "scoped_session_key": skey,
                        "trade_id": ev.get("trade_id"),
                        "symbol": ev.get("symbol"),
                        "broker_id": brk_val,
                        "broker_label": None if brk_val in (None, "") else friendly_broker_label(str(brk_val)),
                        "realized_pnl_usd": str(ev["delta_pnl_usd"]),
                        "status_after": str(ev["status_after"]),
                        "occurred_at_utc": obs_utc,
                        "occurred_at_pacific": format_pacific_timestamp(obs_utc),
                        "session_label": forex_session_label_for_utc(obs_utc),
                    })
                    if len(out_mem) >= lim:
                        break
                return out_mem

            if not self._path.is_file():
                return []

            ro_uri = f"{self._path.resolve().as_uri()}?mode=ro"
            conn = sqlite3.connect(ro_uri, uri=True, timeout=5.0, isolation_level=None)
            try:
                tables = {
                    str(r[0])
                    for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                }
                if "daily_quota_events" not in tables:
                    return []
                ev_cols = {
                    str(c[1])
                    for c in conn.execute("PRAGMA table_info(daily_quota_events)").fetchall()
                }
                has_prov = {"symbol", "trade_id", "broker_id"}.issubset(ev_cols)
                rows = self._select_closed_events_static(
                    conn, f"{prefix}%", lim, has_prov_cols=has_prov
                )
                out_db: list[dict[str, Any]] = []
                for r in rows:
                    skey = str(r[1])
                    sdate_part = skey[len(prefix):] if skey.startswith(prefix) else skey
                    obs_utc = str(r[4])
                    brk_db = None if r[7] in (None, "") else str(r[7])
                    out_db.append({
                        "seq": int(r[0]),
                        "session_key": sdate_part,
                        "scoped_session_key": skey,
                        "trade_id": None if r[6] in (None, "") else str(r[6]),
                        "symbol": None if r[5] in (None, "") else str(r[5]),
                        "broker_id": brk_db,
                        "broker_label": None if brk_db is None else friendly_broker_label(brk_db),
                        "realized_pnl_usd": str(r[2]),
                        "status_after": str(r[3]),
                        "occurred_at_utc": obs_utc,
                        "occurred_at_pacific": format_pacific_timestamp(obs_utc),
                        "session_label": forex_session_label_for_utc(obs_utc),
                    })
                return out_db
            finally:
                conn.close()

    def _apply_trade(self, row: dict[str, Any], pnl_dec: Decimal, ts_str: str) -> None:
        new_pnl = _q2(Decimal(str(row["realized_net_pnl_usd"])) + pnl_dec)
        prev_peak = Decimal(str(row.get("peak_realized_pnl_usd", "0")))
        new_peak = _q2(max(prev_peak, new_pnl, Decimal("0")))
        row["realized_net_pnl_usd"] = decimal_text(new_pnl)
        row["peak_realized_pnl_usd"] = decimal_text(new_peak)
        row["closed_trades"] = int(row["closed_trades"]) + 1
        if pnl_dec >= Decimal("0"):
            row["win_count"] = int(row["win_count"]) + 1
            row["consecutive_losses"] = 0
        else:
            row["loss_count"] = int(row["loss_count"]) + 1
            row["consecutive_losses"] = int(row["consecutive_losses"]) + 1
        row["updated_at"] = ts_str
        # Respect locked/floor-locked/tripped hysteresis once triggered unless explicitly unlocked or daily gain hits hard quota.
        prev_status = row["status"]
        new_status, new_reason = self._compute_status(row)
        if prev_status == QUOTA_STATUS_LOCKED:
            row["status"] = QUOTA_STATUS_LOCKED
        elif prev_status == QUOTA_STATUS_PROFIT_FLOOR_LOCKED and new_status != QUOTA_STATUS_LOCKED:
            row["status"] = QUOTA_STATUS_PROFIT_FLOOR_LOCKED
        elif prev_status == QUOTA_STATUS_LOSS_TRIPPED and new_status != QUOTA_STATUS_LOCKED:
            row["status"] = QUOTA_STATUS_LOSS_TRIPPED
        else:
            row["status"] = new_status
            row["lock_reason"] = new_reason

    def evaluate_new_risk(
        self,
        kind: ActionKind,
        *,
        now: datetime | None = None,
        starting_equity: Decimal | None = None,
        in_recovery_mode: bool = False,
    ) -> tuple[bool, str | None, Decimal]:
        if kind not in (ActionKind.OPEN, ActionKind.ADD):
            return True, None, Decimal("1")
        snap = self.peek_snapshot(now=now, starting_equity=starting_equity, in_recovery_mode=in_recovery_mode)
        status = snap["status"]
        if status == QUOTA_STATUS_LOCKED:
            return False, QUOTA_STATUS_LOCKED, Decimal("0")
        if status == QUOTA_STATUS_PROFIT_FLOOR_LOCKED:
            lock_rsn = str(snap.get("lock_reason") or QUOTA_STATUS_PROFIT_FLOOR_LOCKED)
            return False, lock_rsn, Decimal("0")
        if status == QUOTA_STATUS_LOSS_TRIPPED:
            return False, QUOTA_STATUS_LOSS_TRIPPED, Decimal("0")
        if status == QUOTA_STATUS_SOFT:
            return True, None, Decimal("0.50")
        return True, None, Decimal("1")

    def bind_owner_verifier(self, owner_verifier: Any) -> None:
        with self._lock:
            self._owner_verifier = owner_verifier

    def _require_owner_recovery(
        self,
        *,
        action_scope: str,
        owner_request_id: str,
        recovery_verifier: Any | None,
        recovery_token: str | None,
        now: datetime,
    ) -> None:
        verifier = recovery_verifier if recovery_verifier is not None else self._owner_verifier
        if verifier is None:
            raise ContractError("OWNER_RECOVERY_VERIFIER_REQUIRED: unlock/target changes require an OwnerRecoveryVerifier")
        if not isinstance(recovery_token, str) or not recovery_token.strip():
            raise ContractError("OWNER_RECOVERY_TOKEN_REQUIRED: single-use owner recovery token missing")
        if hasattr(verifier, "verify_and_consume"):
            verifier.verify_and_consume(
                recovery_token,
                expected_scope=action_scope,
                target_ref=self._scope_id,
                owner_request_id=owner_request_id,
                now=now,
            )
            return
        if callable(verifier):
            if verifier(action_scope, owner_request_id, recovery_token, now) is not True:
                raise ContractError("OWNER_RECOVERY_VERIFICATION_REFUSED")
            return
        raise ContractError("invalid recovery_verifier supplied to DailyQuotaGovernanceStore")

    def unlock_session(
        self,
        *,
        owner_request_id: str,
        reason: str,
        recovery_verifier: Any | None = None,
        recovery_token: str | None = None,
        now: datetime | None = None,
        in_recovery_mode: bool = False,
    ) -> dict[str, Any]:
        identifier(owner_request_id, "owner_request_id")
        if not isinstance(reason, str) or not reason.strip():
            raise ContractError("unlock_session requires an explicit reason")
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        self._require_owner_recovery(
            action_scope="UNLOCK_QUOTA_SESSION",
            owner_request_id=owner_request_id,
            recovery_verifier=recovery_verifier,
            recovery_token=recovery_token,
            now=ts,
        )
        ts_str = ts.isoformat().replace("+00:00", "Z")
        d1, d2 = self._trading_day_roots(ts)
        with self._lock:
            if self._path is None:
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                day_pnl = Decimal("0.00")
                for d_row in self._days.values():
                    if d_row.get("scope_id") == self._scope_id and self._matches_trading_day(
                        str(d_row.get("session_date", "")), d1, d2
                    ):
                        day_pnl += Decimal(str(d_row["realized_net_pnl_usd"]))
                        if str(d_row["status"]) == QUOTA_STATUS_LOSS_TRIPPED or int(d_row["consecutive_losses"]) > 0:
                            d_row["status"] = QUOTA_STATUS_OPEN
                            d_row["consecutive_losses"] = 0
                            d_row["lock_reason"] = f"OWNER_UNLOCKED:{owner_request_id}"
                            d_row["updated_at"] = ts_str
                self._unlocked_day_key = d1
                self._unlocked_day_pnl_usd = _q2(day_pnl)
                row = self._load_or_init_row(
                    sdate, starting_equity=None, ts_str=ts_str, max_loss_override=leg_cap
                )
                row["status"] = QUOTA_STATUS_OPEN
                row["consecutive_losses"] = 0
                row["lock_reason"] = f"OWNER_UNLOCKED:{owner_request_id}"
                row["updated_at"] = ts_str
                return self._format_snapshot(row, session_cadence=self._session_cadence, active_leg=act_leg)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts, in_recovery_mode=in_recovery_mode
                )
                day_rows = self._collect_trading_day_rows(ts, conn=conn)
                day_pnl = sum((Decimal(str(r["realized_net_pnl_usd"])) for r in day_rows), Decimal("0.00"))
                for r in day_rows:
                    if str(r["status"]) == QUOTA_STATUS_LOSS_TRIPPED or int(r["consecutive_losses"]) > 0:
                        r["status"] = QUOTA_STATUS_OPEN
                        r["consecutive_losses"] = 0
                        r["lock_reason"] = f"OWNER_UNLOCKED:{owner_request_id}"
                        r["updated_at"] = ts_str
                        self._save_row_and_event(
                            r, event_kind=f"OWNER_UNLOCK:{owner_request_id}", delta_pnl_usd="0", conn=conn
                        )
                self._unlocked_day_key = d1
                self._unlocked_day_pnl_usd = _q2(day_pnl)
                self._persist_meta(conn, ts_str)
                row = self._load_or_init_row(
                    sdate, starting_equity=None, ts_str=ts_str, conn=conn, max_loss_override=leg_cap
                )
                if str(row["lock_reason"] or "") != f"OWNER_UNLOCKED:{owner_request_id}":
                    row["status"] = QUOTA_STATUS_OPEN
                    row["consecutive_losses"] = 0
                    row["lock_reason"] = f"OWNER_UNLOCKED:{owner_request_id}"
                    row["updated_at"] = ts_str
                    self._save_row_and_event(
                        row, event_kind=f"OWNER_UNLOCK:{owner_request_id}", delta_pnl_usd="0", conn=conn
                    )
                conn.commit()
                return self._format_snapshot(row, session_cadence=self._session_cadence, active_leg=act_leg)
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def update_targets(
        self,
        *,
        soft_quota_usd: Decimal | None = None,
        hard_quota_usd: Decimal | None = None,
        daily_quota_pct: Decimal | None = None,
        quota_mode: str | None = None,
        owner_request_id: str | None = None,
        recovery_verifier: Any | None = None,
        recovery_token: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        req_id = identifier(owner_request_id or "quota-target-update", "owner_request_id")
        self._require_owner_recovery(
            action_scope="UPDATE_QUOTA_TARGETS",
            owner_request_id=req_id,
            recovery_verifier=recovery_verifier,
            recovery_token=recovery_token,
            now=ts,
        )
        with self._lock:
            nxt_soft = self._soft_quota_usd if soft_quota_usd is None else decimal_value(Decimal(soft_quota_usd), "soft_quota_usd", positive=True)
            nxt_hard = self._hard_quota_usd if hard_quota_usd is None else decimal_value(Decimal(hard_quota_usd), "hard_quota_usd", positive=True)
            if nxt_soft > nxt_hard:
                raise ContractError("soft_quota_usd cannot exceed hard_quota_usd")
            nxt_mode = self._quota_mode if quota_mode is None else str(quota_mode).strip().upper()
            if nxt_mode not in QUOTA_MODES:
                raise ContractError(f"quota_mode must be one of {QUOTA_MODES}")
            self._soft_quota_usd = nxt_soft
            self._hard_quota_usd = nxt_hard
            self._quota_mode = nxt_mode
            if daily_quota_pct is not None:
                dp = decimal_value(Decimal(daily_quota_pct), "daily_quota_pct", positive=True)
                if dp >= Decimal("1"):
                    raise ContractError("daily_quota_pct must be < 1")
                self._daily_quota_pct = dp
        return self.snapshot(now=now)

    def _format_snapshot(
        self,
        row: Mapping[str, Any],
        *,
        session_cadence: str | None = None,
        active_leg: int = 1,
    ) -> dict[str, Any]:
        start_eq = Decimal(str(row["starting_equity"]))
        start_pos = start_eq if start_eq > Decimal("0") else None
        soft, hard, max_loss = self._effective_targets(
            start_pos, max_loss_override=self._row_loss_override(row)
        )
        pnl = Decimal(str(row["realized_net_pnl_usd"]))
        with localcontext() as ctx:
            ctx.prec = 28
            pnl_pct = Decimal("0") if start_pos is None else (pnl / start_pos * Decimal("100")).quantize(Decimal("0.01"))
            progress_pct = Decimal("0") if hard <= Decimal("0") else max(Decimal("0"), min(Decimal("100"), (pnl / hard * Decimal("100")).quantize(Decimal("0.1"))))
        status = str(row["status"])
        peak_pnl, activation_usd, ratchet_armed, protected_floor_usd = self._ratchet_metrics(row, soft)
        risk_mult = (
            Decimal("0")
            if status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_PROFIT_FLOOR_LOCKED, QUOTA_STATUS_LOSS_TRIPPED)
            else (Decimal("0.50") if status == QUOTA_STATUS_SOFT else Decimal("1"))
        )
        eff_cad = session_cadence if session_cadence is not None else self._session_cadence
        return {
            "schema": "cas-forex.daily-quota/1",
            "session_date": str(row["session_date"]),
            "scope_id": str(row["scope_id"]),
            "status": status,
            "new_risk_allowed": status in (QUOTA_STATUS_OPEN, QUOTA_STATUS_SOFT),
            "lock_reason": row["lock_reason"],
            "quota_mode": self._quota_mode,
            "session_cadence": eff_cad,
            "active_session_leg": max(1, int(active_leg)),
            "starting_equity_usd": decimal_text(start_eq),
            "realized_net_pnl_usd": decimal_text(pnl),
            "peak_realized_pnl_usd": decimal_text(peak_pnl),
            "ratchet_armed": bool(ratchet_armed),
            "ratchet_activation_usd": decimal_text(activation_usd),
            "protected_profit_floor_usd": decimal_text(protected_floor_usd),
            "realized_pnl_pct": decimal_text(pnl_pct),
            "soft_quota_usd": decimal_text(soft),
            "hard_quota_usd": decimal_text(hard),
            "daily_quota_pct": None if self._daily_quota_pct is None else decimal_text(self._daily_quota_pct),
            "quota_progress_pct": decimal_text(progress_pct),
            "risk_multiplier": decimal_text(risk_mult),
            "max_daily_loss_usd": decimal_text(max_loss),
            "closed_trades": int(row["closed_trades"]),
            "win_count": int(row["win_count"]),
            "loss_count": int(row["loss_count"]),
            "consecutive_losses": int(row["consecutive_losses"]),
            "max_consecutive_losses": int(self._max_consecutive_losses),
            "updated_at": str(row["updated_at"]),
        }

    def peek_snapshot(
        self,
        *,
        now: datetime | None = None,
        starting_equity: Decimal | None = None,
        in_recovery_mode: bool = False,
    ) -> dict[str, Any]:
        """Strictly read-only snapshot (0 SQLite DDL/DML writes; PRAGMA data_version unchanged)."""
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        with self._lock:
            eff_cad = self._session_cadence
            eff_base = self._active_period_base
            eff_leg = self._active_leg
            eff_cap = self._leg_max_loss_cap_usd

            if self._path is None:
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts,
                    in_recovery_mode=in_recovery_mode,
                    cadence_override=eff_cad,
                    active_base_override=eff_base,
                    active_leg_override=eff_leg,
                    leg_cap_override=eff_cap,
                )
                key = f"{self._scope_id}:{sdate}"
                mem_row = self._days.get(key)
                if mem_row is not None:
                    mem_row = dict(mem_row)
                    if Decimal(str(mem_row["starting_equity"])) <= 0 and starting_equity is not None and starting_equity > 0:
                        mem_row["starting_equity"] = decimal_text(_q2(starting_equity))
                else:
                    mem_row = self._find_legacy_asia_seed(sdate, conn=None)
                if mem_row is None:
                    start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
                    mem_row = {
                        "session_key": key,
                        "session_date": sdate,
                        "scope_id": self._scope_id,
                        "starting_equity": start_val,
                        "realized_net_pnl_usd": "0",
                        "peak_realized_pnl_usd": "0",
                        "closed_trades": 0,
                        "win_count": 0,
                        "loss_count": 0,
                        "consecutive_losses": 0,
                        "status": QUOTA_STATUS_OPEN,
                        "lock_reason": None,
                        "updated_at": ts_str,
                        "max_loss_override_usd": None if leg_cap is None else decimal_text(_q2(leg_cap)),
                    }
                overlaid_mem = self._apply_trading_day_loss_overlay(ts, mem_row, conn=None)
                return self._format_snapshot(overlaid_mem, session_cadence=eff_cad, active_leg=act_leg)

            if not self._path.is_file():
                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts,
                    in_recovery_mode=in_recovery_mode,
                    cadence_override=eff_cad,
                    active_base_override=eff_base,
                    active_leg_override=eff_leg,
                    leg_cap_override=eff_cap,
                )
                start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
                ephemeral = {
                    "session_key": f"{self._scope_id}:{sdate}",
                    "session_date": sdate,
                    "scope_id": self._scope_id,
                    "starting_equity": start_val,
                    "realized_net_pnl_usd": "0",
                    "peak_realized_pnl_usd": "0",
                    "closed_trades": 0,
                    "win_count": 0,
                    "loss_count": 0,
                    "consecutive_losses": 0,
                    "status": QUOTA_STATUS_OPEN,
                    "lock_reason": None,
                    "updated_at": ts_str,
                    "max_loss_override_usd": None if leg_cap is None else decimal_text(_q2(leg_cap)),
                }
                return self._format_snapshot(ephemeral, session_cadence=eff_cad, active_leg=act_leg)

            ro_uri = f"{self._path.resolve().as_uri()}?mode=ro"
            conn = sqlite3.connect(ro_uri, uri=True, timeout=5.0, isolation_level=None)
            try:
                tables = {
                    str(r[0])
                    for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                }
                eff_unl_day = self._unlocked_day_key
                eff_unl_pnl = self._unlocked_day_pnl_usd
                if not self._meta_loaded and "daily_quota_meta" in tables:
                    mcols = {str(c[1]) for c in conn.execute("PRAGMA table_info(daily_quota_meta)").fetchall()}
                    has_unl = "unlocked_day_key" in mcols and "unlocked_day_pnl_usd" in mcols
                    mrow = self._select_meta_row_static(conn, self._scope_id, has_unlock_cols=has_unl)
                    if mrow is not None:
                        saved_cad = str(mrow[0] or "").strip().upper()
                        if not self._explicit_cadence_arg and saved_cad in VALID_SESSION_CADENCES:
                            eff_cad = saved_cad
                        eff_base = str(mrow[1]) if mrow[1] not in (None, "") else None
                        eff_leg = max(1, int(mrow[2] or 1))
                        eff_cap = Decimal(str(mrow[3])) if mrow[3] not in (None, "") else None
                        eff_unl_day = str(mrow[4]) if mrow[4] not in (None, "") else None
                        eff_unl_pnl = Decimal(str(mrow[5])) if mrow[5] not in (None, "") else Decimal("0.00")

                sdate, _, act_leg, leg_cap = self._resolve_session_target(
                    ts,
                    in_recovery_mode=in_recovery_mode,
                    cadence_override=eff_cad,
                    active_base_override=eff_base,
                    active_leg_override=eff_leg,
                    leg_cap_override=eff_cap,
                )
                key = f"{self._scope_id}:{sdate}"
                db_dict: dict[str, Any] | None = None
                has_peak = True
                has_ov = True
                if "daily_quota_sessions" in tables:
                    cols = {
                        str(c[1])
                        for c in conn.execute("PRAGMA table_info(daily_quota_sessions)").fetchall()
                    }
                    has_peak = "peak_realized_pnl_usd" in cols
                    has_ov = "max_loss_override_usd" in cols
                    db_row = self._select_session_row_static(
                        conn, key, has_peak=has_peak, has_ov=has_ov
                    )
                    if db_row is not None:
                        loaded_pnl = Decimal(str(db_row[4]))
                        loaded_peak = _q2(max(Decimal(str(db_row[5] or "0")), loaded_pnl, Decimal("0")))
                        db_dict = {
                            "session_key": db_row[0],
                            "session_date": db_row[1],
                            "scope_id": db_row[2],
                            "starting_equity": db_row[3],
                            "realized_net_pnl_usd": db_row[4],
                            "peak_realized_pnl_usd": decimal_text(loaded_peak),
                            "closed_trades": int(db_row[6]),
                            "win_count": int(db_row[7]),
                            "loss_count": int(db_row[8]),
                            "consecutive_losses": int(db_row[9]),
                            "status": db_row[10],
                            "lock_reason": db_row[11],
                            "updated_at": db_row[12],
                            "max_loss_override_usd": None if db_row[13] in (None, "") else str(db_row[13]),
                        }
                        if Decimal(str(db_dict["starting_equity"])) <= 0 and starting_equity is not None and starting_equity > 0:
                            db_dict["starting_equity"] = decimal_text(_q2(starting_equity))
                        if leg_cap is not None and db_dict.get("max_loss_override_usd") in (None, ""):
                            db_dict["max_loss_override_usd"] = decimal_text(_q2(leg_cap))
                    else:
                        db_dict = self._find_legacy_asia_seed(
                            sdate, conn=conn, has_peak_col=has_peak, has_override_col=has_ov
                        )

                if db_dict is None:
                    start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
                    db_dict = {
                        "session_key": key,
                        "session_date": sdate,
                        "scope_id": self._scope_id,
                        "starting_equity": start_val,
                        "realized_net_pnl_usd": "0",
                        "peak_realized_pnl_usd": "0",
                        "closed_trades": 0,
                        "win_count": 0,
                        "loss_count": 0,
                        "consecutive_losses": 0,
                        "status": QUOTA_STATUS_OPEN,
                        "lock_reason": None,
                        "updated_at": ts_str,
                        "max_loss_override_usd": None if leg_cap is None else decimal_text(_q2(leg_cap)),
                    }
                if "daily_quota_sessions" in tables:
                    db_dict = self._apply_trading_day_loss_overlay(
                        ts,
                        db_dict,
                        conn=conn,
                        has_peak=has_peak,
                        has_ov=has_ov,
                        unlocked_day_override=eff_unl_day,
                        unlocked_pnl_override=eff_unl_pnl,
                    )
                return self._format_snapshot(db_dict, session_cadence=eff_cad, active_leg=act_leg)
            finally:
                conn.close()

    def snapshot(
        self,
        *,
        now: datetime | None = None,
        starting_equity: Decimal | None = None,
        in_recovery_mode: bool = False,
    ) -> dict[str, Any]:
        """Strictly read-only session quota snapshot (PURE SELECT ONLY; 0 SQLite writes across rollovers)."""
        return self.peek_snapshot(
            now=now,
            starting_equity=starting_equity,
            in_recovery_mode=in_recovery_mode,
        )
