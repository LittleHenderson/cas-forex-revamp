"""Durable Daily Profit Quota Lock ($500-$1,000 or % compounding) & Loss Circuit Breaker.

Persists per-session-day state into SQLite WAL (when ``path`` is supplied) or scoped in-memory
history. Inert on construction (zero I/O in ``__init__``). Strictly vetoes new ``OPEN`` / ``ADD``
entries once daily profit reaches hard quota (``DAILY_QUOTA_LOCKED``) or loss / consecutive-loss
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

QUOTA_STATUS_OPEN = "OPEN"
QUOTA_STATUS_SOFT = "SOFT_QUOTA_REACHED"
QUOTA_STATUS_LOCKED = "DAILY_QUOTA_LOCKED"
QUOTA_STATUS_LOSS_TRIPPED = "DAILY_LOSS_CIRCUIT_TRIPPED"

QUOTA_MODES = ("USD", "PCT", "COMPOUND_CAPPED")
GENESIS_SHA256 = "0" * 64


def _ny_zone():
    try:
        return ZoneInfo("America/New_York")
    except ZoneInfoNotFoundError:
        logger.warning("America/New_York tzdata unavailable; falling back to UTC-05:00 session boundary")
        return timezone(timedelta(hours=-5))


def session_date_for(now: datetime | None = None, *, rollover_hour_ny: int = 17) -> str:
    """Compute canonical trading session date (``YYYY-MM-DD``) rolling over at 17:00 New York time."""
    ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    local_dt = ts.astimezone(_ny_zone())
    shifted = local_dt + timedelta(hours=24 - rollover_hour_ny)
    return shifted.date().isoformat()


def _q2(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


class DailyQuotaGovernanceStore:
    """Thread-safe durable daily profit target lock & daily loss circuit breaker."""

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
        owner_verifier: Any | None = None,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._scope_id = identifier(scope_id, "scope_id")
        self._lock = RLock()
        self._initialized = False
        self._owner_verifier = owner_verifier
        self._days: dict[str, dict[str, Any]] = {}
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
        try:
            soft = Decimal(soft_raw)
            hard = Decimal(hard_raw)
            qpct = Decimal(pct_raw) if pct_raw else None
            mloss = Decimal(mloss_raw)
            mlpct = Decimal(mlpct_raw) if mlpct_raw else None
            consec = int(consec_raw)
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
        )

    @property
    def path(self) -> Path | None:
        return self._path

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
                    closed_trades INTEGER NOT NULL,
                    win_count INTEGER NOT NULL,
                    loss_count INTEGER NOT NULL,
                    consecutive_losses INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    lock_reason TEXT,
                    updated_at TEXT NOT NULL
                )
                """
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
                    event_sha256 TEXT NOT NULL
                )
                """
            )
            self._initialized = True
        return conn

    def _effective_targets(self, starting_equity: Decimal | None) -> tuple[Decimal, Decimal, Decimal]:
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
        return soft, hard, max_loss

    def _compute_status(self, row: Mapping[str, Any]) -> tuple[str, str | None]:
        start_eq = Decimal(str(row["starting_equity"])) if Decimal(str(row["starting_equity"])) > 0 else None
        soft, hard, max_loss = self._effective_targets(start_eq)
        pnl = Decimal(str(row["realized_net_pnl_usd"]))
        consec = int(row["consecutive_losses"])
        if pnl >= hard:
            return QUOTA_STATUS_LOCKED, f"Daily profit quota reached ({decimal_text(pnl)} >= {decimal_text(hard)} USD)"
        if pnl <= -max_loss:
            return QUOTA_STATUS_LOSS_TRIPPED, f"Daily max loss reached ({decimal_text(pnl)} <= -{decimal_text(max_loss)} USD)"
        if consec >= self._max_consecutive_losses:
            return QUOTA_STATUS_LOSS_TRIPPED, f"Consecutive losses reached limit ({consec} >= {self._max_consecutive_losses})"
        if pnl >= soft:
            return QUOTA_STATUS_SOFT, f"Daily soft quota reached ({decimal_text(pnl)} >= {decimal_text(soft)} USD); risk halved"
        return QUOTA_STATUS_OPEN, None

    def _load_or_init_row(
        self,
        session_date: str,
        *,
        starting_equity: Decimal | None,
        ts_str: str,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        key = f"{self._scope_id}:{session_date}"
        if conn is None:
            row = self._days.get(key)
            if row is None:
                start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
                row = {
                    "session_key": key,
                    "session_date": session_date,
                    "scope_id": self._scope_id,
                    "starting_equity": start_val,
                    "realized_net_pnl_usd": "0",
                    "closed_trades": 0,
                    "win_count": 0,
                    "loss_count": 0,
                    "consecutive_losses": 0,
                    "status": QUOTA_STATUS_OPEN,
                    "lock_reason": None,
                    "updated_at": ts_str,
                }
                self._days[key] = row
            elif Decimal(str(row["starting_equity"])) <= 0 and starting_equity is not None and starting_equity > 0:
                row["starting_equity"] = decimal_text(_q2(starting_equity))
            return row

        db_row = conn.execute(
            "SELECT session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd, "
            "closed_trades, win_count, loss_count, consecutive_losses, status, lock_reason, updated_at "
            "FROM daily_quota_sessions WHERE session_key = ?",
            (key,),
        ).fetchone()
        if db_row is None:
            start_val = decimal_text(_q2(starting_equity)) if starting_equity is not None else "0"
            row = {
                "session_key": key,
                "session_date": session_date,
                "scope_id": self._scope_id,
                "starting_equity": start_val,
                "realized_net_pnl_usd": "0",
                "closed_trades": 0,
                "win_count": 0,
                "loss_count": 0,
                "consecutive_losses": 0,
                "status": QUOTA_STATUS_OPEN,
                "lock_reason": None,
                "updated_at": ts_str,
            }
            conn.execute(
                """
                INSERT INTO daily_quota_sessions (
                    session_key, session_date, scope_id, starting_equity, realized_net_pnl_usd,
                    closed_trades, win_count, loss_count, consecutive_losses, status, lock_reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key, session_date, self._scope_id, row["starting_equity"], "0",
                    0, 0, 0, 0, QUOTA_STATUS_OPEN, None, ts_str,
                ),
            )
            return row
        row = {
            "session_key": db_row[0],
            "session_date": db_row[1],
            "scope_id": db_row[2],
            "starting_equity": db_row[3],
            "realized_net_pnl_usd": db_row[4],
            "closed_trades": int(db_row[5]),
            "win_count": int(db_row[6]),
            "loss_count": int(db_row[7]),
            "consecutive_losses": int(db_row[8]),
            "status": db_row[9],
            "lock_reason": db_row[10],
            "updated_at": db_row[11],
        }
        if Decimal(str(row["starting_equity"])) <= 0 and starting_equity is not None and starting_equity > 0:
            row["starting_equity"] = decimal_text(_q2(starting_equity))
            conn.execute(
                "UPDATE daily_quota_sessions SET starting_equity = ? WHERE session_key = ?",
                (row["starting_equity"], key),
            )
        return row

    def _save_row_and_event(
        self,
        row: dict[str, Any],
        *,
        event_kind: str,
        delta_pnl_usd: str,
        conn: sqlite3.Connection | None,
    ) -> None:
        if conn is None:
            self._days[row["session_key"]] = dict(row)
            return
        prev = conn.execute("SELECT event_sha256 FROM daily_quota_events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_sha = str(prev[0]) if prev is not None else GENESIS_SHA256
        ev_payload = {
            "session_key": row["session_key"],
            "event_kind": event_kind,
            "delta_pnl_usd": delta_pnl_usd,
            "status_after": row["status"],
            "observed_at": row["updated_at"],
            "prev_sha256": prev_sha,
        }
        ev_sha = sha256(canonical_bytes(ev_payload)).hexdigest()
        conn.execute(
            """
            UPDATE daily_quota_sessions SET
                starting_equity = ?, realized_net_pnl_usd = ?, closed_trades = ?, win_count = ?,
                loss_count = ?, consecutive_losses = ?, status = ?, lock_reason = ?, updated_at = ?
            WHERE session_key = ?
            """,
            (
                row["starting_equity"], row["realized_net_pnl_usd"], row["closed_trades"], row["win_count"],
                row["loss_count"], row["consecutive_losses"], row["status"], row["lock_reason"],
                row["updated_at"], row["session_key"],
            ),
        )
        conn.execute(
            """
            INSERT INTO daily_quota_events (
                session_key, event_kind, delta_pnl_usd, status_after, observed_at, prev_sha256, event_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["session_key"], event_kind, delta_pnl_usd, row["status"],
                row["updated_at"], prev_sha, ev_sha,
            ),
        )

    def observe_day_start(self, starting_equity: Decimal, *, now: datetime | None = None) -> dict[str, Any]:
        decimal_value(starting_equity, "starting_equity", positive=True)
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        sdate = session_date_for(ts)
        with self._lock:
            if self._path is None:
                row = self._load_or_init_row(sdate, starting_equity=starting_equity, ts_str=ts_str)
                return self._format_snapshot(row)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._load_or_init_row(sdate, starting_equity=starting_equity, ts_str=ts_str, conn=conn)
                conn.commit()
                return self._format_snapshot(row)
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def record_realized_trade(
        self,
        pnl_usd: Decimal,
        *,
        symbol: str,
        ticket: str,
        starting_equity: Decimal | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        pnl_dec = decimal_value(pnl_usd, "pnl_usd")
        identifier(symbol, "symbol")
        identifier(ticket, "ticket")
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        sdate = session_date_for(ts)
        with self._lock:
            if self._path is None:
                row = self._load_or_init_row(sdate, starting_equity=starting_equity, ts_str=ts_str)
                self._apply_trade(row, pnl_dec, ts_str)
                return self._format_snapshot(row)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._load_or_init_row(sdate, starting_equity=starting_equity, ts_str=ts_str, conn=conn)
                self._apply_trade(row, pnl_dec, ts_str)
                self._save_row_and_event(row, event_kind="REALIZED_TRADE", delta_pnl_usd=decimal_text(_q2(pnl_dec)), conn=conn)
                conn.commit()
                return self._format_snapshot(row)
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def _apply_trade(self, row: dict[str, Any], pnl_dec: Decimal, ts_str: str) -> None:
        new_pnl = _q2(Decimal(str(row["realized_net_pnl_usd"])) + pnl_dec)
        row["realized_net_pnl_usd"] = decimal_text(new_pnl)
        row["closed_trades"] = int(row["closed_trades"]) + 1
        if pnl_dec >= Decimal("0"):
            row["win_count"] = int(row["win_count"]) + 1
            row["consecutive_losses"] = 0
        else:
            row["loss_count"] = int(row["loss_count"]) + 1
            row["consecutive_losses"] = int(row["consecutive_losses"]) + 1
        row["updated_at"] = ts_str
        # Respect locked/tripped hysteresis once triggered unless explicitly unlocked or daily gain hits hard quota.
        prev_status = row["status"]
        new_status, new_reason = self._compute_status(row)
        if prev_status == QUOTA_STATUS_LOCKED:
            row["status"] = QUOTA_STATUS_LOCKED
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
    ) -> tuple[bool, str | None, Decimal]:
        if kind not in (ActionKind.OPEN, ActionKind.ADD):
            return True, None, Decimal("1")
        snap = self.snapshot(now=now, starting_equity=starting_equity)
        status = snap["status"]
        if status == QUOTA_STATUS_LOCKED:
            return False, QUOTA_STATUS_LOCKED, Decimal("0")
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
        sdate = session_date_for(ts)
        with self._lock:
            if self._path is None:
                row = self._load_or_init_row(sdate, starting_equity=None, ts_str=ts_str)
                row["status"] = QUOTA_STATUS_OPEN
                row["consecutive_losses"] = 0
                row["lock_reason"] = f"OWNER_UNLOCKED:{owner_request_id}"
                row["updated_at"] = ts_str
                return self._format_snapshot(row)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._load_or_init_row(sdate, starting_equity=None, ts_str=ts_str, conn=conn)
                row["status"] = QUOTA_STATUS_OPEN
                row["consecutive_losses"] = 0
                row["lock_reason"] = f"OWNER_UNLOCKED:{owner_request_id}"
                row["updated_at"] = ts_str
                self._save_row_and_event(row, event_kind=f"OWNER_UNLOCK:{owner_request_id}", delta_pnl_usd="0", conn=conn)
                conn.commit()
                return self._format_snapshot(row)
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

    def _format_snapshot(self, row: Mapping[str, Any]) -> dict[str, Any]:
        start_eq = Decimal(str(row["starting_equity"]))
        start_pos = start_eq if start_eq > Decimal("0") else None
        soft, hard, max_loss = self._effective_targets(start_pos)
        pnl = Decimal(str(row["realized_net_pnl_usd"]))
        with localcontext() as ctx:
            ctx.prec = 28
            pnl_pct = Decimal("0") if start_pos is None else (pnl / start_pos * Decimal("100")).quantize(Decimal("0.01"))
            progress_pct = Decimal("0") if hard <= Decimal("0") else max(Decimal("0"), min(Decimal("100"), (pnl / hard * Decimal("100")).quantize(Decimal("0.1"))))
        status = str(row["status"])
        risk_mult = Decimal("0") if status in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_LOSS_TRIPPED) else (Decimal("0.50") if status == QUOTA_STATUS_SOFT else Decimal("1"))
        return {
            "schema": "cas-forex.daily-quota/1",
            "session_date": str(row["session_date"]),
            "scope_id": str(row["scope_id"]),
            "status": status,
            "new_risk_allowed": status in (QUOTA_STATUS_OPEN, QUOTA_STATUS_SOFT),
            "lock_reason": row["lock_reason"],
            "quota_mode": self._quota_mode,
            "starting_equity_usd": decimal_text(start_eq),
            "realized_net_pnl_usd": decimal_text(pnl),
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

    def snapshot(self, *, now: datetime | None = None, starting_equity: Decimal | None = None) -> dict[str, Any]:
        ts = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        sdate = session_date_for(ts)
        with self._lock:
            if self._path is None:
                row = self._load_or_init_row(sdate, starting_equity=starting_equity, ts_str=ts_str)
                return self._format_snapshot(row)
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._load_or_init_row(sdate, starting_equity=starting_equity, ts_str=ts_str, conn=conn)
                conn.commit()
                return self._format_snapshot(row)
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
