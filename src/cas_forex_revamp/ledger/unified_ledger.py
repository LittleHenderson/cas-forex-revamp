"""Unified Single Real-Time Ledger (SQLite WAL) for CAS Forex Revamp.

Unifies realized trade closes, multi-session & regional (ASIA/LONDON/NEW_YORK) P&L,
the $300,000.00 principal high-water mark (RECOVERY_MODE vs IN_SURPLUS), internal
50%/50% Bank Vault sweep reserves, confirmed vs pending bank disbursements, peak
equity & drawdown tracking, the 70% daily profit-protection floor (RESEARCH_RESPITE),
bidirectional same-day loss-lock carryover across the principal threshold, and a
tamper-evident SHA-256 hash-chained audit log inside one atomic SQLite database.

Key safety invariants:
- Exact Decimal arithmetic everywhere; floats/NaN/Inf are strictly rejected.
- Strictly zero-write ``snapshot(now_utc=None)`` via read-only SQLite URI
  (``?mode=ro`` + ``PRAGMA query_only = ON``), leaving ``PRAGMA data_version``,
  file mtime, and table row counts unchanged across midnight UTC rollovers.
- Internal 50%/50% Bank Vault reserve remains strictly $0.00 in RECOVERY_MODE and
  only accrues on realized net surplus ABOVE principal_usd once IN_SURPLUS.
- Only disbursements with status == "SETTLED" count toward confirmed settled
  disbursements and effective settled equity; PENDING/SUBMITTED/UNKNOWN/FAILED/
  CANCELLED transfers never inflate equity or exit RECOVERY_MODE.
- Same-day daily loss lock carries over bidirectionally across the principal
  threshold until explicit owner unlock or the next UTC trading day.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, ROUND_HALF_UP, localcontext
from enum import StrEnum
from hashlib import sha256
import hmac
import os
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ContractError, canonical_bytes, decimal_text
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, integer, utc_time

SCHEMA_NAME = "cas-forex.unified-ledger/1"
DEFAULT_PRINCIPAL_USD = Decimal("300000.00")
DEFAULT_SWEEP_RATIO = Decimal("0.50")
DEFAULT_DAILY_MAX_LOSS_USD = Decimal("500.00")
DEFAULT_MAX_CONSECUTIVE_LOSSES = 3
DEFAULT_PROFIT_FLOOR_ACTIVATION_USD = Decimal("250.00")
DEFAULT_PROFIT_FLOOR_RATIO = Decimal("0.70")
INTERNAL_ACCOUNTING_LABEL = "Internal Accounting Figure \u2014 Not a Confirmed Bank Payout"
GENESIS_AUDIT_SHA256 = "0" * 64

_SESSION_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_SAFE_TEXT_MAX = 240


class LedgerMode(StrEnum):
    """Capital position relative to the $300,000.00 principal high-water mark."""

    RECOVERY_MODE = "RECOVERY_MODE"
    IN_SURPLUS = "IN_SURPLUS"


class RegionalSession(StrEnum):
    """UTC regional FX/index trading session buckets."""

    ASIA = "ASIA"  # 22:00-07:00Z
    LONDON = "LONDON"  # 07:00-12:00Z
    NEW_YORK = "NEW_YORK"  # 12:00-22:00Z


class DailySessionStatus(StrEnum):
    """Daily risk governance state for new entries."""

    ACTIVE_TRADING = "ACTIVE_TRADING"
    RESEARCH_RESPITE = "RESEARCH_RESPITE"
    DAILY_LOSS_LOCKED = "DAILY_LOSS_LOCKED"


class DisbursementStatus(StrEnum):
    """Bank payout lifecycle states; ONLY SETTLED counts toward effective equity."""

    SETTLED = "SETTLED"
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    UNKNOWN = "UNKNOWN"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


PENDING_DISBURSEMENT_STATUSES: frozenset[DisbursementStatus] = frozenset(
    {
        DisbursementStatus.PENDING,
        DisbursementStatus.SUBMITTED,
        DisbursementStatus.UNKNOWN,
    }
)
FAILED_CANCELLED_DISBURSEMENT_STATUSES: frozenset[DisbursementStatus] = frozenset(
    {
        DisbursementStatus.FAILED,
        DisbursementStatus.CANCELLED,
    }
)
UNSETTLED_DISBURSEMENT_STATUSES: frozenset[DisbursementStatus] = (
    PENDING_DISBURSEMENT_STATUSES | FAILED_CANCELLED_DISBURSEMENT_STATUSES
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _q2(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _iso_utc(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value: datetime | str, field: str) -> datetime:
    if isinstance(value, datetime):
        return utc_time(value, field)
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ContractError(f"{field} must be a valid ISO-8601 UTC timestamp") from exc
        return utc_time(parsed, field)
    raise ContractError(f"{field} must be a UTC datetime or ISO-8601 UTC string")


def _validate_session_date(value: str) -> str:
    if not isinstance(value, str) or not _SESSION_DATE_RE.fullmatch(value.strip()):
        raise ContractError("session_date must be a YYYY-MM-DD string")
    clean = value.strip()
    try:
        date.fromisoformat(clean)
    except ValueError as exc:
        raise ContractError("session_date must be a valid calendar date") from exc
    return clean


def _parse_regional_session(value: RegionalSession | str) -> RegionalSession:
    if isinstance(value, RegionalSession):
        return value
    if not isinstance(value, str):
        raise ContractError("regional_session must be a RegionalSession or string")
    norm = value.strip().upper()
    try:
        return RegionalSession(norm)
    except ValueError as exc:
        raise ContractError(f"unsupported regional_session {value!r}") from exc


def _parse_disbursement_status(value: DisbursementStatus | str) -> DisbursementStatus:
    if isinstance(value, DisbursementStatus):
        return value
    if not isinstance(value, str):
        raise ContractError("status must be a DisbursementStatus or string")
    norm = value.strip().upper()
    try:
        return DisbursementStatus(norm)
    except ValueError as exc:
        raise ContractError(f"unsupported disbursement status {value!r}") from exc


def _sanitize_note(note: str | None) -> str | None:
    if note is None:
        return None
    if not isinstance(note, str):
        raise ContractError("note must be a string or None")
    cleaned = " ".join(note.replace("\r", " ").replace("\n", " ").split())
    return cleaned[:_SAFE_TEXT_MAX] if cleaned else None


def _ensure_owner_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)  # nosec B103: owner-only directory permissions


def _ensure_owner_file(path: Path) -> None:
    if os.name == "posix" and path.exists():
        os.chmod(path, 0o600)  # nosec B103: owner-only SQLite ledger file


def trading_date_for(now_utc: datetime | None = None) -> str:
    """Return canonical UTC trading date (YYYY-MM-DD), rolling over at 00:00Z."""
    ts = _utc_now() if now_utc is None else utc_time(now_utc, "now_utc")
    return ts.date().isoformat()


def regional_session_for(now_utc: datetime | None = None) -> RegionalSession:
    """Map a UTC timestamp into ASIA (22:00-07:00Z), LONDON (07:00-12:00Z), or NEW_YORK (12:00-22:00Z)."""
    ts = _utc_now() if now_utc is None else utc_time(now_utc, "now_utc")
    hour = ts.hour
    if hour >= 22 or hour < 7:
        return RegionalSession.ASIA
    if 7 <= hour < 12:
        return RegionalSession.LONDON
    return RegionalSession.NEW_YORK


@dataclass(frozen=True, slots=True)
class RealizedTradeRecord:
    """Immutable realized trade close or reconciliation adjustment record."""

    trade_id: str
    event_id: str
    scope_id: str
    session_date: str
    regional_session: RegionalSession
    symbol: str
    broker_id: str
    realized_pnl_usd: Decimal
    occurred_at: str
    is_adjustment: bool = False
    note: str | None = None


@dataclass(frozen=True, slots=True)
class DisbursementRecord:
    """Immutable bank payout/transfer tracking record."""

    transfer_id: str
    scope_id: str
    amount_usd: Decimal
    status: DisbursementStatus
    rail: str
    destination_bank_id: str
    provider_tx_id: str | None
    debit_broker_equity: bool
    created_at: str
    updated_at: str
    settled_at: str | None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class LedgerSnapshot:
    """Immutable read-only point-in-time snapshot of the UnifiedRealTimeLedger."""

    schema: str
    scope_id: str
    as_of_utc: str
    session_date: str
    regional_session: RegionalSession
    mode: LedgerMode
    session_status: DailySessionStatus
    new_risk_allowed: bool
    principal_usd: Decimal
    initial_equity_usd: Decimal
    broker_equity_usd: Decimal
    confirmed_settled_disbursed_usd: Decimal
    pending_transfers_usd: Decimal
    failed_cancelled_transfers_usd: Decimal
    settled_equity_usd: Decimal
    effective_equity_usd: Decimal
    net_surplus_above_principal_usd: Decimal
    principal_shortfall_usd: Decimal
    sweep_ratio: Decimal
    vault_sweep_target_usd: Decimal
    bank_vault_reserved_usd: Decimal
    retained_trading_surplus_usd: Decimal
    deployable_trading_equity_usd: Decimal
    accounting_label: str
    lifetime_realized_pnl_usd: Decimal
    daily_realized_pnl_usd: Decimal
    daily_peak_pnl_usd: Decimal
    daily_profit_floor_armed: bool
    daily_profit_floor_usd: Decimal
    research_respite_active: bool
    daily_loss_locked: bool
    loss_lock_reason: str | None
    loss_lock_origin_mode: LedgerMode | None
    loss_lock_carried_over: bool
    daily_closed_trades: int
    daily_win_count: int
    daily_loss_count: int
    daily_consecutive_losses: int
    daily_asia_pnl_usd: Decimal
    daily_london_pnl_usd: Decimal
    daily_new_york_pnl_usd: Decimal
    lifetime_asia_pnl_usd: Decimal
    lifetime_london_pnl_usd: Decimal
    lifetime_new_york_pnl_usd: Decimal
    peak_equity_usd: Decimal
    drawdown_usd: Decimal
    drawdown_pct: Decimal
    audit_event_count: int
    last_audit_sha256: str

    def daily_regional_pnl(self) -> dict[RegionalSession, Decimal]:
        """Return per-region realized P&L for the snapshot's session_date."""
        return {
            RegionalSession.ASIA: self.daily_asia_pnl_usd,
            RegionalSession.LONDON: self.daily_london_pnl_usd,
            RegionalSession.NEW_YORK: self.daily_new_york_pnl_usd,
        }

    def lifetime_regional_pnl(self) -> dict[RegionalSession, Decimal]:
        """Return lifetime per-region realized P&L across all sessions."""
        return {
            RegionalSession.ASIA: self.lifetime_asia_pnl_usd,
            RegionalSession.LONDON: self.lifetime_london_pnl_usd,
            RegionalSession.NEW_YORK: self.lifetime_new_york_pnl_usd,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to JSON-compatible dictionary with exact Decimal strings."""
        return {
            "schema": self.schema,
            "scope_id": self.scope_id,
            "as_of_utc": self.as_of_utc,
            "session_date": self.session_date,
            "regional_session": self.regional_session.value,
            "mode": self.mode.value,
            "session_status": self.session_status.value,
            "new_risk_allowed": self.new_risk_allowed,
            "principal_usd": decimal_text(self.principal_usd),
            "initial_equity_usd": decimal_text(self.initial_equity_usd),
            "broker_equity_usd": decimal_text(self.broker_equity_usd),
            "confirmed_settled_disbursed_usd": decimal_text(self.confirmed_settled_disbursed_usd),
            "pending_transfers_usd": decimal_text(self.pending_transfers_usd),
            "failed_cancelled_transfers_usd": decimal_text(self.failed_cancelled_transfers_usd),
            "settled_equity_usd": decimal_text(self.settled_equity_usd),
            "effective_equity_usd": decimal_text(self.effective_equity_usd),
            "net_surplus_above_principal_usd": decimal_text(self.net_surplus_above_principal_usd),
            "principal_shortfall_usd": decimal_text(self.principal_shortfall_usd),
            "sweep_ratio": decimal_text(self.sweep_ratio),
            "vault_sweep_target_usd": decimal_text(self.vault_sweep_target_usd),
            "bank_vault_reserved_usd": decimal_text(self.bank_vault_reserved_usd),
            "retained_trading_surplus_usd": decimal_text(self.retained_trading_surplus_usd),
            "deployable_trading_equity_usd": decimal_text(self.deployable_trading_equity_usd),
            "accounting_label": self.accounting_label,
            "lifetime_realized_pnl_usd": decimal_text(self.lifetime_realized_pnl_usd),
            "daily_realized_pnl_usd": decimal_text(self.daily_realized_pnl_usd),
            "daily_peak_pnl_usd": decimal_text(self.daily_peak_pnl_usd),
            "daily_profit_floor_armed": self.daily_profit_floor_armed,
            "daily_profit_floor_usd": decimal_text(self.daily_profit_floor_usd),
            "research_respite_active": self.research_respite_active,
            "daily_loss_locked": self.daily_loss_locked,
            "loss_lock_reason": self.loss_lock_reason,
            "loss_lock_origin_mode": (
                None if self.loss_lock_origin_mode is None else self.loss_lock_origin_mode.value
            ),
            "loss_lock_carried_over": self.loss_lock_carried_over,
            "daily_closed_trades": self.daily_closed_trades,
            "daily_win_count": self.daily_win_count,
            "daily_loss_count": self.daily_loss_count,
            "daily_consecutive_losses": self.daily_consecutive_losses,
            "daily_regional_pnl_usd": {
                "ASIA": decimal_text(self.daily_asia_pnl_usd),
                "LONDON": decimal_text(self.daily_london_pnl_usd),
                "NEW_YORK": decimal_text(self.daily_new_york_pnl_usd),
            },
            "lifetime_regional_pnl_usd": {
                "ASIA": decimal_text(self.lifetime_asia_pnl_usd),
                "LONDON": decimal_text(self.lifetime_london_pnl_usd),
                "NEW_YORK": decimal_text(self.lifetime_new_york_pnl_usd),
            },
            "peak_equity_usd": decimal_text(self.peak_equity_usd),
            "drawdown_usd": decimal_text(self.drawdown_usd),
            "drawdown_pct": decimal_text(self.drawdown_pct),
            "audit_event_count": self.audit_event_count,
            "last_audit_sha256": self.last_audit_sha256,
        }


class UnifiedRealTimeLedger:
    """Thread-safe, SQLite WAL-backed single real-time ledger for CAS Forex Revamp."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        scope_id: str = "dual-shield-barbell",
        principal_usd: Decimal = DEFAULT_PRINCIPAL_USD,
        initial_equity_usd: Decimal | None = None,
        sweep_ratio: Decimal = DEFAULT_SWEEP_RATIO,
        daily_max_loss_usd: Decimal = DEFAULT_DAILY_MAX_LOSS_USD,
        max_consecutive_losses: int = DEFAULT_MAX_CONSECUTIVE_LOSSES,
        profit_floor_activation_usd: Decimal = DEFAULT_PROFIT_FLOOR_ACTIVATION_USD,
        profit_floor_ratio: Decimal = DEFAULT_PROFIT_FLOOR_RATIO,
        clock: Callable[[], datetime] | None = None,
        owner_verifier: Any | None = None,
        read_only: bool = False,
    ) -> None:
        self._db_path = Path(db_path)
        self._scope_id = identifier(scope_id, "scope_id")
        self._lock = RLock()
        self._clock: Callable[[], datetime] = clock or _utc_now
        self._owner_verifier = owner_verifier
        self._read_only = bool(read_only)

        p_usd = _q2(decimal_value(principal_usd, "principal_usd", positive=True))
        init_eq = (
            p_usd
            if initial_equity_usd is None
            else _q2(decimal_value(initial_equity_usd, "initial_equity_usd"))
        )
        if init_eq < Decimal("0.00"):
            raise ContractError("initial_equity_usd cannot be negative")
        sw_ratio = decimal_value(sweep_ratio, "sweep_ratio")
        if sw_ratio < Decimal("0") or sw_ratio > Decimal("0.90"):
            raise ContractError("sweep_ratio must be in [0, 0.90]")
        max_loss = _q2(decimal_value(daily_max_loss_usd, "daily_max_loss_usd", positive=True))
        max_consec = integer(max_consecutive_losses, "max_consecutive_losses", minimum=1)
        act_usd = _q2(
            decimal_value(profit_floor_activation_usd, "profit_floor_activation_usd", positive=True)
        )
        flr_ratio = decimal_value(profit_floor_ratio, "profit_floor_ratio", positive=True)
        if flr_ratio >= Decimal("1"):
            raise ContractError("profit_floor_ratio must be strictly in (0, 1)")

        self._default_principal_usd = p_usd
        self._default_initial_equity_usd = init_eq
        self._default_sweep_ratio = sw_ratio
        self._default_daily_max_loss_usd = max_loss
        self._default_max_consecutive_losses = max_consec
        self._default_profit_floor_activation_usd = act_usd
        self._default_profit_floor_ratio = flr_ratio

        if not self._read_only:
            self._init_schema()

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def scope_id(self) -> str:
        return self._scope_id

    @property
    def read_only(self) -> bool:
        return self._read_only

    def _now(self) -> datetime:
        return utc_time(self._clock(), "clock")

    def _connect_rw(self) -> sqlite3.Connection:
        if self._read_only:
            raise ContractError("UnifiedRealTimeLedger is opened in read_only mode; writes are forbidden")
        _ensure_owner_dir(self._db_path.parent)
        conn = sqlite3.connect(str(self._db_path), timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _connect_ro(self) -> sqlite3.Connection:
        resolved = self._db_path.resolve()
        if not resolved.exists():
            raise ContractError(f"UnifiedRealTimeLedger database does not exist: {resolved}")
        uri = f"{resolved.as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=15.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ledger_meta (
                        scope_id TEXT PRIMARY KEY,
                        principal_usd TEXT NOT NULL,
                        initial_equity_usd TEXT NOT NULL,
                        peak_equity_usd TEXT NOT NULL,
                        sweep_ratio TEXT NOT NULL,
                        daily_max_loss_usd TEXT NOT NULL,
                        max_consecutive_losses INTEGER NOT NULL,
                        profit_floor_activation_usd TEXT NOT NULL,
                        profit_floor_ratio TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS realized_trades (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        scope_id TEXT NOT NULL,
                        trade_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        session_date TEXT NOT NULL,
                        regional_session TEXT NOT NULL,
                        symbol TEXT NOT NULL,
                        broker_id TEXT NOT NULL,
                        realized_pnl_usd TEXT NOT NULL,
                        is_adjustment INTEGER NOT NULL DEFAULT 0,
                        note TEXT,
                        occurred_at TEXT NOT NULL,
                        UNIQUE(scope_id, trade_id),
                        UNIQUE(scope_id, event_id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_realized_trades_scope_session
                    ON realized_trades(scope_id, session_date)
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS disbursements (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        scope_id TEXT NOT NULL,
                        transfer_id TEXT NOT NULL,
                        amount_usd TEXT NOT NULL,
                        status TEXT NOT NULL,
                        rail TEXT NOT NULL,
                        destination_bank_id TEXT NOT NULL,
                        provider_tx_id TEXT,
                        debit_broker_equity INTEGER NOT NULL DEFAULT 0,
                        note TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        settled_at TEXT,
                        UNIQUE(scope_id, transfer_id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS daily_sessions (
                        scope_id TEXT NOT NULL,
                        session_date TEXT NOT NULL,
                        realized_pnl_usd TEXT NOT NULL,
                        peak_pnl_usd TEXT NOT NULL,
                        closed_trades INTEGER NOT NULL DEFAULT 0,
                        win_count INTEGER NOT NULL DEFAULT 0,
                        loss_count INTEGER NOT NULL DEFAULT 0,
                        consecutive_losses INTEGER NOT NULL DEFAULT 0,
                        research_respite_active INTEGER NOT NULL DEFAULT 0,
                        daily_loss_locked INTEGER NOT NULL DEFAULT 0,
                        loss_lock_reason TEXT,
                        loss_lock_origin_mode TEXT,
                        loss_lock_crossed_threshold INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (scope_id, session_date)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        scope_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        prev_sha256 TEXT NOT NULL,
                        entry_sha256 TEXT NOT NULL
                    )
                    """
                )
                existing_meta = conn.execute(
                    "SELECT scope_id FROM ledger_meta WHERE scope_id = ?",
                    (self._scope_id,),
                ).fetchone()
                if existing_meta is None:
                    ts = _iso_utc(self._now())
                    peak_init = max(self._default_initial_equity_usd, Decimal("0.00"))
                    conn.execute(
                        """
                        INSERT INTO ledger_meta (
                            scope_id, principal_usd, initial_equity_usd, peak_equity_usd,
                            sweep_ratio, daily_max_loss_usd, max_consecutive_losses,
                            profit_floor_activation_usd, profit_floor_ratio,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self._scope_id,
                            decimal_text(self._default_principal_usd),
                            decimal_text(self._default_initial_equity_usd),
                            decimal_text(peak_init),
                            decimal_text(self._default_sweep_ratio),
                            decimal_text(self._default_daily_max_loss_usd),
                            self._default_max_consecutive_losses,
                            decimal_text(self._default_profit_floor_activation_usd),
                            decimal_text(self._default_profit_floor_ratio),
                            ts,
                            ts,
                        ),
                    )
                    self._append_audit(
                        conn,
                        event_type="LEDGER_INITIALIZED",
                        entity_id=self._scope_id,
                        payload={
                            "principal_usd": decimal_text(self._default_principal_usd),
                            "initial_equity_usd": decimal_text(self._default_initial_equity_usd),
                            "sweep_ratio": decimal_text(self._default_sweep_ratio),
                            "daily_max_loss_usd": decimal_text(self._default_daily_max_loss_usd),
                            "max_consecutive_losses": self._default_max_consecutive_losses,
                            "profit_floor_activation_usd": decimal_text(
                                self._default_profit_floor_activation_usd
                            ),
                            "profit_floor_ratio": decimal_text(self._default_profit_floor_ratio),
                        },
                        occurred_at=ts,
                    )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        _ensure_owner_file(self._db_path)

    def _compute_audit_sha256(
        self,
        *,
        prev_sha256: str,
        scope_id: str,
        event_type: str,
        entity_id: str,
        payload_bytes: bytes,
        occurred_at: str,
    ) -> str:
        prefix = f"{prev_sha256}|{scope_id}|{event_type}|{entity_id}|".encode("utf-8")
        suffix = f"|{occurred_at}".encode("utf-8")
        return sha256(prefix + payload_bytes + suffix).hexdigest()

    def _append_audit(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        entity_id: str,
        payload: Mapping[str, Any],
        occurred_at: str,
    ) -> str:
        prev_row = conn.execute(
            "SELECT entry_sha256 FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_sha = str(prev_row["entry_sha256"]) if prev_row is not None else GENESIS_AUDIT_SHA256
        payload_bytes = canonical_bytes(dict(payload))
        entry_sha = self._compute_audit_sha256(
            prev_sha256=prev_sha,
            scope_id=self._scope_id,
            event_type=event_type,
            entity_id=entity_id,
            payload_bytes=payload_bytes,
            occurred_at=occurred_at,
        )
        conn.execute(
            """
            INSERT INTO audit_events (
                scope_id, event_type, entity_id, payload_json, occurred_at, prev_sha256, entry_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._scope_id,
                event_type,
                entity_id,
                payload_bytes.decode("utf-8"),
                occurred_at,
                prev_sha,
                entry_sha,
            ),
        )
        return entry_sha

    def _load_meta_row(self, conn: sqlite3.Connection) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM ledger_meta WHERE scope_id = ?",
            (self._scope_id,),
        ).fetchone()
        if row is None:
            raise ContractError(f"ledger metadata missing for scope_id={self._scope_id!r}")
        return row

    def _aggregate_capital_state(
        self,
        conn: sqlite3.Connection,
        meta: sqlite3.Row,
    ) -> dict[str, Any]:
        principal_usd = _q2(Decimal(str(meta["principal_usd"])))
        initial_equity_usd = _q2(Decimal(str(meta["initial_equity_usd"])))
        stored_peak_usd = _q2(Decimal(str(meta["peak_equity_usd"])))
        sweep_ratio = Decimal(str(meta["sweep_ratio"]))

        lifetime_pnl = Decimal("0.00")
        lifetime_regional: dict[RegionalSession, Decimal] = {
            RegionalSession.ASIA: Decimal("0.00"),
            RegionalSession.LONDON: Decimal("0.00"),
            RegionalSession.NEW_YORK: Decimal("0.00"),
        }
        trade_rows = conn.execute(
            "SELECT regional_session, realized_pnl_usd FROM realized_trades WHERE scope_id = ?",
            (self._scope_id,),
        ).fetchall()
        for r in trade_rows:
            amt = _q2(Decimal(str(r["realized_pnl_usd"])))
            lifetime_pnl += amt
            reg = _parse_regional_session(str(r["regional_session"]))
            lifetime_regional[reg] += amt

        confirmed_settled = Decimal("0.00")
        pending_transfers = Decimal("0.00")
        failed_cancelled = Decimal("0.00")
        debited_by_transfers = Decimal("0.00")

        disb_rows = conn.execute(
            "SELECT amount_usd, status, debit_broker_equity FROM disbursements WHERE scope_id = ?",
            (self._scope_id,),
        ).fetchall()
        for r in disb_rows:
            amt = _q2(Decimal(str(r["amount_usd"])))
            st = _parse_disbursement_status(str(r["status"]))
            debit_flag = bool(int(r["debit_broker_equity"]))
            if st == DisbursementStatus.SETTLED:
                confirmed_settled += amt
            elif st in PENDING_DISBURSEMENT_STATUSES:
                pending_transfers += amt
            elif st in FAILED_CANCELLED_DISBURSEMENT_STATUSES:
                failed_cancelled += amt
            if debit_flag and st not in FAILED_CANCELLED_DISBURSEMENT_STATUSES:
                debited_by_transfers += amt

        broker_equity_usd = _q2(initial_equity_usd + lifetime_pnl - debited_by_transfers)
        settled_equity_usd = _q2(broker_equity_usd + confirmed_settled)

        if settled_equity_usd < principal_usd:
            mode = LedgerMode.RECOVERY_MODE
            net_surplus = Decimal("0.00")
            principal_shortfall = _q2(principal_usd - settled_equity_usd)
            vault_sweep_target = Decimal("0.00")
            bank_vault_reserved = Decimal("0.00")
            retained_trading_surplus = Decimal("0.00")
        else:
            mode = LedgerMode.IN_SURPLUS
            net_surplus = _q2(settled_equity_usd - principal_usd)
            principal_shortfall = Decimal("0.00")
            with localcontext() as ctx:
                ctx.prec = 40
                vault_sweep_target = _q2(net_surplus * sweep_ratio)
            bank_vault_reserved = max(Decimal("0.00"), _q2(vault_sweep_target - confirmed_settled))
            retained_trading_surplus = _q2(net_surplus - vault_sweep_target)

        deployable_trading_equity = max(
            Decimal("0.00"), _q2(broker_equity_usd - bank_vault_reserved)
        )
        peak_equity_usd = max(stored_peak_usd, settled_equity_usd, Decimal("0.00"))
        drawdown_usd = max(Decimal("0.00"), _q2(peak_equity_usd - settled_equity_usd))
        if peak_equity_usd <= Decimal("0.00"):
            drawdown_pct = Decimal("0.00")
        else:
            with localcontext() as ctx:
                ctx.prec = 40
                drawdown_pct = _q2((drawdown_usd / peak_equity_usd) * Decimal("100"))

        return {
            "principal_usd": principal_usd,
            "initial_equity_usd": initial_equity_usd,
            "sweep_ratio": sweep_ratio,
            "lifetime_realized_pnl_usd": _q2(lifetime_pnl),
            "lifetime_regional": lifetime_regional,
            "confirmed_settled_disbursed_usd": _q2(confirmed_settled),
            "pending_transfers_usd": _q2(pending_transfers),
            "failed_cancelled_transfers_usd": _q2(failed_cancelled),
            "broker_equity_usd": broker_equity_usd,
            "settled_equity_usd": settled_equity_usd,
            "mode": mode,
            "net_surplus_above_principal_usd": net_surplus,
            "principal_shortfall_usd": principal_shortfall,
            "vault_sweep_target_usd": vault_sweep_target,
            "bank_vault_reserved_usd": bank_vault_reserved,
            "retained_trading_surplus_usd": retained_trading_surplus,
            "deployable_trading_equity_usd": deployable_trading_equity,
            "peak_equity_usd": peak_equity_usd,
            "drawdown_usd": drawdown_usd,
            "drawdown_pct": drawdown_pct,
        }

    def _update_peak_if_higher(
        self,
        conn: sqlite3.Connection,
        *,
        current_peak: Decimal,
        settled_equity_usd: Decimal,
        ts: str,
    ) -> Decimal:
        if settled_equity_usd > current_peak:
            new_peak = _q2(settled_equity_usd)
            conn.execute(
                "UPDATE ledger_meta SET peak_equity_usd = ?, updated_at = ? WHERE scope_id = ?",
                (decimal_text(new_peak), ts, self._scope_id),
            )
            return new_peak
        return current_peak

    def _apply_session_pnl_transition(
        self,
        conn: sqlite3.Connection,
        *,
        meta: sqlite3.Row,
        session_date: str,
        pnl_delta: Decimal,
        is_adjustment: bool,
        mode_before: LedgerMode,
        mode_after: LedgerMode,
        ts: str,
    ) -> dict[str, Any]:
        max_loss = _q2(Decimal(str(meta["daily_max_loss_usd"])))
        max_consec = int(meta["max_consecutive_losses"])
        act_usd = _q2(Decimal(str(meta["profit_floor_activation_usd"])))
        flr_ratio = Decimal(str(meta["profit_floor_ratio"]))

        row = conn.execute(
            "SELECT * FROM daily_sessions WHERE scope_id = ? AND session_date = ?",
            (self._scope_id, session_date),
        ).fetchone()
        if row is None:
            prev_pnl = Decimal("0.00")
            prev_peak = Decimal("0.00")
            closed_trades = 0
            win_count = 0
            loss_count = 0
            consec_losses = 0
            respite_active = False
            loss_locked = False
            lock_reason: str | None = None
            origin_mode: LedgerMode | None = None
            crossed_threshold = False
        else:
            prev_pnl = _q2(Decimal(str(row["realized_pnl_usd"])))
            prev_peak = _q2(Decimal(str(row["peak_pnl_usd"])))
            closed_trades = int(row["closed_trades"])
            win_count = int(row["win_count"])
            loss_count = int(row["loss_count"])
            consec_losses = int(row["consecutive_losses"])
            respite_active = bool(int(row["research_respite_active"]))
            loss_locked = bool(int(row["daily_loss_locked"]))
            lock_reason = None if row["loss_lock_reason"] is None else str(row["loss_lock_reason"])
            origin_mode = (
                None
                if row["loss_lock_origin_mode"] is None
                else LedgerMode(str(row["loss_lock_origin_mode"]))
            )
            crossed_threshold = bool(int(row["loss_lock_crossed_threshold"]))

        new_pnl = _q2(prev_pnl + pnl_delta)
        new_peak = max(prev_peak, new_pnl, Decimal("0.00"))
        if not is_adjustment:
            closed_trades += 1
            if pnl_delta >= Decimal("0.00"):
                win_count += 1
                consec_losses = 0
            else:
                loss_count += 1
                consec_losses += 1

        # 70% daily profit-protection floor (RESEARCH_RESPITE)
        if new_peak >= act_usd:
            with localcontext() as ctx:
                ctx.prec = 40
                floor_usd = _q2(new_peak * flr_ratio)
            if new_pnl <= floor_usd:
                respite_active = True

        # Bidirectional same-day loss-lock trigger & carryover across $300,000.00 threshold
        if loss_locked:
            if (origin_mode is not None and mode_after != origin_mode) or (
                mode_before != mode_after
            ):
                crossed_threshold = True
        else:
            if new_pnl <= -max_loss:
                loss_locked = True
                origin_mode = mode_before
                lock_reason = (
                    f"Daily max loss breached ({decimal_text(new_pnl)} <= "
                    f"-{decimal_text(max_loss)} USD)"
                )
                if mode_after != origin_mode:
                    crossed_threshold = True
            elif consec_losses >= max_consec:
                loss_locked = True
                origin_mode = mode_before
                lock_reason = (
                    f"Consecutive losses limit reached ({consec_losses} >= {max_consec})"
                )
                if mode_after != origin_mode:
                    crossed_threshold = True

        conn.execute(
            """
            INSERT INTO daily_sessions (
                scope_id, session_date, realized_pnl_usd, peak_pnl_usd,
                closed_trades, win_count, loss_count, consecutive_losses,
                research_respite_active, daily_loss_locked, loss_lock_reason,
                loss_lock_origin_mode, loss_lock_crossed_threshold, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_id, session_date) DO UPDATE SET
                realized_pnl_usd = excluded.realized_pnl_usd,
                peak_pnl_usd = excluded.peak_pnl_usd,
                closed_trades = excluded.closed_trades,
                win_count = excluded.win_count,
                loss_count = excluded.loss_count,
                consecutive_losses = excluded.consecutive_losses,
                research_respite_active = excluded.research_respite_active,
                daily_loss_locked = excluded.daily_loss_locked,
                loss_lock_reason = excluded.loss_lock_reason,
                loss_lock_origin_mode = excluded.loss_lock_origin_mode,
                loss_lock_crossed_threshold = excluded.loss_lock_crossed_threshold,
                updated_at = excluded.updated_at
            """,
            (
                self._scope_id,
                session_date,
                decimal_text(new_pnl),
                decimal_text(new_peak),
                closed_trades,
                win_count,
                loss_count,
                consec_losses,
                1 if respite_active else 0,
                1 if loss_locked else 0,
                lock_reason,
                None if origin_mode is None else origin_mode.value,
                1 if crossed_threshold else 0,
                ts,
            ),
        )
        return {
            "daily_realized_pnl_usd": new_pnl,
            "daily_peak_pnl_usd": new_peak,
            "research_respite_active": respite_active,
            "daily_loss_locked": loss_locked,
            "loss_lock_origin_mode": None if origin_mode is None else origin_mode.value,
            "loss_lock_crossed_threshold": crossed_threshold,
        }

    def record_realized_trade(
        self,
        *,
        trade_id: str,
        symbol: str,
        broker_id: str,
        realized_pnl_usd: Decimal,
        occurred_at: datetime | None = None,
        event_id: str | None = None,
        session_date: str | None = None,
        regional_session: RegionalSession | str | None = None,
        is_adjustment: bool = False,
        note: str | None = None,
    ) -> LedgerSnapshot:
        """Atomically record a realized trade close or adjustment (idempotent by trade_id / event_id)."""
        tid = identifier(trade_id, "trade_id")
        eid = tid if event_id is None else identifier(event_id, "event_id")
        sym = identifier(symbol, "symbol")
        brk = identifier(broker_id, "broker_id")
        pnl_q = _q2(decimal_value(realized_pnl_usd, "realized_pnl_usd"))
        occ_dt = self._now() if occurred_at is None else utc_time(occurred_at, "occurred_at")
        ts = _iso_utc(occ_dt)
        eff_sdate = (
            trading_date_for(occ_dt)
            if session_date is None
            else _validate_session_date(session_date)
        )
        eff_reg = (
            regional_session_for(occ_dt)
            if regional_session is None
            else _parse_regional_session(regional_session)
        )
        clean_note = _sanitize_note(note)

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                dup = conn.execute(
                    "SELECT 1 FROM realized_trades WHERE scope_id = ? AND (trade_id = ? OR event_id = ?)",
                    (self._scope_id, tid, eid),
                ).fetchone()
                if dup is not None:
                    conn.execute("ROLLBACK")
                else:
                    meta = self._load_meta_row(conn)
                    before = self._aggregate_capital_state(conn, meta)
                    conn.execute(
                        """
                        INSERT INTO realized_trades (
                            scope_id, trade_id, event_id, session_date, regional_session,
                            symbol, broker_id, realized_pnl_usd, is_adjustment, note, occurred_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self._scope_id,
                            tid,
                            eid,
                            eff_sdate,
                            eff_reg.value,
                            sym,
                            brk,
                            decimal_text(pnl_q),
                            1 if is_adjustment else 0,
                            clean_note,
                            ts,
                        ),
                    )
                    after = self._aggregate_capital_state(conn, meta)
                    self._update_peak_if_higher(
                        conn,
                        current_peak=_q2(Decimal(str(meta["peak_equity_usd"]))),
                        settled_equity_usd=after["settled_equity_usd"],
                        ts=ts,
                    )
                    day_state = self._apply_session_pnl_transition(
                        conn,
                        meta=meta,
                        session_date=eff_sdate,
                        pnl_delta=pnl_q,
                        is_adjustment=bool(is_adjustment),
                        mode_before=before["mode"],
                        mode_after=after["mode"],
                        ts=ts,
                    )
                    self._append_audit(
                        conn,
                        event_type=(
                            "REALIZED_ADJUSTMENT_RECORDED"
                            if is_adjustment
                            else "REALIZED_TRADE_RECORDED"
                        ),
                        entity_id=tid,
                        payload={
                            "trade_id": tid,
                            "event_id": eid,
                            "session_date": eff_sdate,
                            "regional_session": eff_reg.value,
                            "symbol": sym,
                            "broker_id": brk,
                            "realized_pnl_usd": decimal_text(pnl_q),
                            "mode_before": before["mode"].value,
                            "mode_after": after["mode"].value,
                            "settled_equity_usd": decimal_text(after["settled_equity_usd"]),
                            "bank_vault_reserved_usd": decimal_text(
                                after["bank_vault_reserved_usd"]
                            ),
                            "daily_loss_locked": day_state["daily_loss_locked"],
                            "research_respite_active": day_state["research_respite_active"],
                        },
                        occurred_at=ts,
                    )
                    conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return self.snapshot(now_utc=occ_dt, session_date=eff_sdate)

    def reconcile_session_realized_pnl(
        self,
        *,
        session_date: str,
        target_session_realized_pnl_usd: Decimal,
        occurred_at: datetime | None = None,
        symbol: str = "SESSION_BASKET",
        broker_id: str = "UNIFIED_LEDGER",
        regional_session: RegionalSession | str | None = None,
        note: str | None = None,
    ) -> LedgerSnapshot:
        """Idempotently reconcile a session's realized P&L upward, downward, or on bounce-back."""
        sdate = _validate_session_date(session_date)
        target_q = _q2(
            decimal_value(target_session_realized_pnl_usd, "target_session_realized_pnl_usd")
        )
        sym = identifier(symbol, "symbol")
        brk = identifier(broker_id, "broker_id")
        occ_dt = self._now() if occurred_at is None else utc_time(occurred_at, "occurred_at")
        ts = _iso_utc(occ_dt)
        eff_reg = (
            regional_session_for(occ_dt)
            if regional_session is None
            else _parse_regional_session(regional_session)
        )
        clean_note = _sanitize_note(note)

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    "SELECT realized_pnl_usd FROM realized_trades WHERE scope_id = ? AND session_date = ?",
                    (self._scope_id, sdate),
                ).fetchall()
                current_session_pnl = Decimal("0.00")
                for r in rows:
                    current_session_pnl += _q2(Decimal(str(r["realized_pnl_usd"])))

                delta = _q2(target_q - current_session_pnl)
                if delta == Decimal("0.00"):
                    conn.execute("ROLLBACK")
                else:
                    meta = self._load_meta_row(conn)
                    before = self._aggregate_capital_state(conn, meta)
                    prefix = f"SESSION_RECON_{sdate}_"
                    cnt_row = conn.execute(
                        "SELECT COUNT(*) AS cnt FROM realized_trades WHERE scope_id = ? AND trade_id LIKE ?",
                        (self._scope_id, f"{prefix}%"),
                    ).fetchone()
                    seq_n = (int(cnt_row["cnt"]) if cnt_row is not None else 0) + 1
                    cents_int = int((target_q * Decimal("100")).to_integral_value())
                    cents_tag = f"M{abs(cents_int)}" if cents_int < 0 else str(cents_int)
                    recon_id = f"{prefix}{seq_n:04d}_{cents_tag}"

                    conn.execute(
                        """
                        INSERT INTO realized_trades (
                            scope_id, trade_id, event_id, session_date, regional_session,
                            symbol, broker_id, realized_pnl_usd, is_adjustment, note, occurred_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            self._scope_id,
                            recon_id,
                            recon_id,
                            sdate,
                            eff_reg.value,
                            sym,
                            brk,
                            decimal_text(delta),
                            clean_note,
                            ts,
                        ),
                    )
                    after = self._aggregate_capital_state(conn, meta)
                    self._update_peak_if_higher(
                        conn,
                        current_peak=_q2(Decimal(str(meta["peak_equity_usd"]))),
                        settled_equity_usd=after["settled_equity_usd"],
                        ts=ts,
                    )
                    day_state = self._apply_session_pnl_transition(
                        conn,
                        meta=meta,
                        session_date=sdate,
                        pnl_delta=delta,
                        is_adjustment=True,
                        mode_before=before["mode"],
                        mode_after=after["mode"],
                        ts=ts,
                    )
                    self._append_audit(
                        conn,
                        event_type="SESSION_PNL_RECONCILED",
                        entity_id=recon_id,
                        payload={
                            "trade_id": recon_id,
                            "session_date": sdate,
                            "target_session_realized_pnl_usd": decimal_text(target_q),
                            "delta_usd": decimal_text(delta),
                            "mode_before": before["mode"].value,
                            "mode_after": after["mode"].value,
                            "settled_equity_usd": decimal_text(after["settled_equity_usd"]),
                            "bank_vault_reserved_usd": decimal_text(
                                after["bank_vault_reserved_usd"]
                            ),
                            "daily_loss_locked": day_state["daily_loss_locked"],
                            "research_respite_active": day_state["research_respite_active"],
                        },
                        occurred_at=ts,
                    )
                    conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return self.snapshot(now_utc=occ_dt, session_date=sdate)

    def record_execution_event(self, event: Any) -> LedgerSnapshot:
        """Idempotently ingest a broker ExecutionEvent (duck-typed for ExecutionEventBus)."""
        if isinstance(event, Mapping):
            raw_eid = event.get("event_id")
            raw_sym = event.get("symbol")
            raw_brk = event.get("broker_id")
            raw_pnl = event.get("realized_pnl_usd")
            raw_ts = event.get("timestamp_utc")
            raw_type = event.get("event_type")
        else:
            raw_eid = getattr(event, "event_id", None)
            raw_sym = getattr(event, "symbol", None)
            raw_brk = getattr(event, "broker_id", None)
            raw_pnl = getattr(event, "realized_pnl_usd", None)
            raw_ts = getattr(event, "timestamp_utc", None)
            raw_type = getattr(event, "event_type", None)

        if raw_eid is None or raw_sym is None or raw_brk is None or raw_pnl is None:
            raise ContractError(
                "execution event must supply event_id, symbol, broker_id, and realized_pnl_usd"
            )
        occ_dt = (
            self._now() if raw_ts is None else _parse_utc_timestamp(raw_ts, "timestamp_utc")
        )
        pnl_dec = decimal_value(raw_pnl, "realized_pnl_usd")
        if raw_type is not None:
            ev_type = str(getattr(raw_type, "value", raw_type)).strip().upper()
            if ev_type in {"CANCELLED", "AMEND_STOP", "REJECTED"}:
                return self.snapshot(now_utc=occ_dt)
            if ev_type in {"FILL", "PARTIAL_FILL"} and pnl_dec == Decimal("0"):
                return self.snapshot(now_utc=occ_dt)
        return self.record_realized_trade(
            trade_id=str(raw_eid),
            event_id=str(raw_eid),
            symbol=str(raw_sym),
            broker_id=str(raw_brk),
            realized_pnl_usd=pnl_dec,
            occurred_at=occ_dt,
        )

    def record_disbursement(
        self,
        *,
        transfer_id: str,
        amount_usd: Decimal,
        status: DisbursementStatus | str = DisbursementStatus.PENDING,
        rail: str = "BROKER_2FA_MANUAL",
        destination_bank_id: str = "OWNER_LINKED_BANK",
        provider_tx_id: str | None = None,
        debit_broker_equity: bool = False,
        occurred_at: datetime | None = None,
        note: str | None = None,
    ) -> LedgerSnapshot:
        """Record a bank disbursement transfer. ONLY status == SETTLED counts toward settled equity."""
        tid = identifier(transfer_id, "transfer_id")
        amt_q = _q2(decimal_value(amount_usd, "amount_usd", positive=True))
        st = _parse_disbursement_status(status)
        rail_id = identifier(rail, "rail")
        dest_id = identifier(destination_bank_id, "destination_bank_id")
        ptx = None if provider_tx_id is None else identifier(provider_tx_id, "provider_tx_id")
        occ_dt = self._now() if occurred_at is None else utc_time(occurred_at, "occurred_at")
        ts = _iso_utc(occ_dt)
        settled_ts = ts if st == DisbursementStatus.SETTLED else None
        clean_note = _sanitize_note(note)
        sdate = trading_date_for(occ_dt)

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT amount_usd, status FROM disbursements WHERE scope_id = ? AND transfer_id = ?",
                    (self._scope_id, tid),
                ).fetchone()
                if existing is not None:
                    ex_amt = _q2(Decimal(str(existing["amount_usd"])))
                    ex_st = _parse_disbursement_status(str(existing["status"]))
                    if ex_amt == amt_q and ex_st == st:
                        conn.execute("ROLLBACK")
                    else:
                        conn.execute("ROLLBACK")
                        raise ContractError(
                            f"transfer_id {tid!r} already exists with amount={decimal_text(ex_amt)} status={ex_st.value}"
                        )
                else:
                    meta = self._load_meta_row(conn)
                    before = self._aggregate_capital_state(conn, meta)
                    conn.execute(
                        """
                        INSERT INTO disbursements (
                            scope_id, transfer_id, amount_usd, status, rail,
                            destination_bank_id, provider_tx_id, debit_broker_equity,
                            note, created_at, updated_at, settled_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self._scope_id,
                            tid,
                            decimal_text(amt_q),
                            st.value,
                            rail_id,
                            dest_id,
                            ptx,
                            1 if debit_broker_equity else 0,
                            clean_note,
                            ts,
                            ts,
                            settled_ts,
                        ),
                    )
                    after = self._aggregate_capital_state(conn, meta)
                    self._update_peak_if_higher(
                        conn,
                        current_peak=_q2(Decimal(str(meta["peak_equity_usd"]))),
                        settled_equity_usd=after["settled_equity_usd"],
                        ts=ts,
                    )
                    self._mark_loss_lock_threshold_cross_if_needed(
                        conn,
                        session_date=sdate,
                        mode_before=before["mode"],
                        mode_after=after["mode"],
                        ts=ts,
                    )
                    self._append_audit(
                        conn,
                        event_type="DISBURSEMENT_RECORDED",
                        entity_id=tid,
                        payload={
                            "transfer_id": tid,
                            "amount_usd": decimal_text(amt_q),
                            "status": st.value,
                            "rail": rail_id,
                            "destination_bank_id": dest_id,
                            "provider_tx_id": ptx,
                            "debit_broker_equity": bool(debit_broker_equity),
                            "mode_before": before["mode"].value,
                            "mode_after": after["mode"].value,
                            "settled_equity_usd": decimal_text(after["settled_equity_usd"]),
                            "confirmed_settled_disbursed_usd": decimal_text(
                                after["confirmed_settled_disbursed_usd"]
                            ),
                            "pending_transfers_usd": decimal_text(after["pending_transfers_usd"]),
                        },
                        occurred_at=ts,
                    )
                    conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return self.snapshot(now_utc=occ_dt, session_date=sdate)

    def update_disbursement_status(
        self,
        *,
        transfer_id: str,
        status: DisbursementStatus | str,
        provider_tx_id: str | None = None,
        occurred_at: datetime | None = None,
        note: str | None = None,
    ) -> LedgerSnapshot:
        """Transition a disbursement status (e.g. PENDING -> SETTLED or FAILED/CANCELLED)."""
        tid = identifier(transfer_id, "transfer_id")
        new_st = _parse_disbursement_status(status)
        ptx = None if provider_tx_id is None else identifier(provider_tx_id, "provider_tx_id")
        occ_dt = self._now() if occurred_at is None else utc_time(occurred_at, "occurred_at")
        ts = _iso_utc(occ_dt)
        clean_note = _sanitize_note(note)
        sdate = trading_date_for(occ_dt)

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM disbursements WHERE scope_id = ? AND transfer_id = ?",
                    (self._scope_id, tid),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise ContractError(f"unknown transfer_id {tid!r}")
                cur_st = _parse_disbursement_status(str(row["status"]))
                if cur_st == DisbursementStatus.SETTLED and new_st != DisbursementStatus.SETTLED:
                    conn.execute("ROLLBACK")
                    raise ContractError(
                        f"cannot revert terminal SETTLED disbursement {tid!r} to {new_st.value}"
                    )
                if cur_st == new_st and (ptx is None or ptx == row["provider_tx_id"]):
                    conn.execute("ROLLBACK")
                else:
                    meta = self._load_meta_row(conn)
                    before = self._aggregate_capital_state(conn, meta)
                    eff_ptx = ptx if ptx is not None else row["provider_tx_id"]
                    eff_note = clean_note if clean_note is not None else row["note"]
                    settled_ts = (
                        str(row["settled_at"])
                        if row["settled_at"] is not None
                        else (ts if new_st == DisbursementStatus.SETTLED else None)
                    )
                    conn.execute(
                        """
                        UPDATE disbursements
                        SET status = ?, provider_tx_id = ?, note = ?, updated_at = ?, settled_at = ?
                        WHERE scope_id = ? AND transfer_id = ?
                        """,
                        (new_st.value, eff_ptx, eff_note, ts, settled_ts, self._scope_id, tid),
                    )
                    after = self._aggregate_capital_state(conn, meta)
                    self._update_peak_if_higher(
                        conn,
                        current_peak=_q2(Decimal(str(meta["peak_equity_usd"]))),
                        settled_equity_usd=after["settled_equity_usd"],
                        ts=ts,
                    )
                    self._mark_loss_lock_threshold_cross_if_needed(
                        conn,
                        session_date=sdate,
                        mode_before=before["mode"],
                        mode_after=after["mode"],
                        ts=ts,
                    )
                    self._append_audit(
                        conn,
                        event_type="DISBURSEMENT_STATUS_UPDATED",
                        entity_id=tid,
                        payload={
                            "transfer_id": tid,
                            "status_before": cur_st.value,
                            "status_after": new_st.value,
                            "provider_tx_id": eff_ptx,
                            "mode_before": before["mode"].value,
                            "mode_after": after["mode"].value,
                            "settled_equity_usd": decimal_text(after["settled_equity_usd"]),
                            "confirmed_settled_disbursed_usd": decimal_text(
                                after["confirmed_settled_disbursed_usd"]
                            ),
                            "pending_transfers_usd": decimal_text(after["pending_transfers_usd"]),
                        },
                        occurred_at=ts,
                    )
                    conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return self.snapshot(now_utc=occ_dt, session_date=sdate)

    def _mark_loss_lock_threshold_cross_if_needed(
        self,
        conn: sqlite3.Connection,
        *,
        session_date: str,
        mode_before: LedgerMode,
        mode_after: LedgerMode,
        ts: str,
    ) -> None:
        if mode_before == mode_after:
            return
        row = conn.execute(
            "SELECT daily_loss_locked FROM daily_sessions WHERE scope_id = ? AND session_date = ?",
            (self._scope_id, session_date),
        ).fetchone()
        if row is not None and bool(int(row["daily_loss_locked"])):
            conn.execute(
                """
                UPDATE daily_sessions
                SET loss_lock_crossed_threshold = 1, updated_at = ?
                WHERE scope_id = ? AND session_date = ?
                """,
                (ts, self._scope_id, session_date),
            )

    def unlock_daily_loss_lock(
        self,
        *,
        owner_request_id: str,
        reason: str,
        session_date: str | None = None,
        now_utc: datetime | None = None,
        clear_research_respite: bool = False,
        recovery_verifier: Any | None = None,
        recovery_token: str | None = None,
    ) -> LedgerSnapshot:
        """Explicit owner unlock for same-day loss lock (and optionally RESEARCH_RESPITE)."""
        req_id = identifier(owner_request_id, "owner_request_id")
        clean_reason = _sanitize_note(reason)
        if not clean_reason:
            raise ContractError("unlock_daily_loss_lock requires a non-empty reason")
        ts_dt = self._now() if now_utc is None else utc_time(now_utc, "now_utc")
        ts = _iso_utc(ts_dt)
        sdate = (
            trading_date_for(ts_dt)
            if session_date is None
            else _validate_session_date(session_date)
        )

        verifier = recovery_verifier if recovery_verifier is not None else self._owner_verifier
        if verifier is not None:
            if not isinstance(recovery_token, str) or not recovery_token.strip():
                raise ContractError(
                    "OWNER_RECOVERY_TOKEN_REQUIRED: single-use owner recovery token missing"
                )
            if hasattr(verifier, "verify_and_consume"):
                verifier.verify_and_consume(
                    recovery_token,
                    expected_scope="UNLOCK_LEDGER_LOSS_LOCK",
                    target_ref=self._scope_id,
                    owner_request_id=req_id,
                    now=ts_dt,
                )
            elif callable(verifier):
                if verifier("UNLOCK_LEDGER_LOSS_LOCK", req_id, recovery_token, ts_dt) is not True:
                    raise ContractError("OWNER_RECOVERY_VERIFICATION_REFUSED")
            else:
                raise ContractError("invalid recovery_verifier supplied to UnifiedRealTimeLedger")

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM daily_sessions WHERE scope_id = ? AND session_date = ?",
                    (self._scope_id, sdate),
                ).fetchone()
                if row is not None:
                    new_respite = (
                        0 if clear_research_respite else int(row["research_respite_active"])
                    )
                    conn.execute(
                        """
                        UPDATE daily_sessions
                        SET daily_loss_locked = 0,
                            loss_lock_reason = ?,
                            loss_lock_origin_mode = NULL,
                            loss_lock_crossed_threshold = 0,
                            consecutive_losses = 0,
                            research_respite_active = ?,
                            updated_at = ?
                        WHERE scope_id = ? AND session_date = ?
                        """,
                        (
                            f"OWNER_UNLOCKED:{req_id}",
                            new_respite,
                            ts,
                            self._scope_id,
                            sdate,
                        ),
                    )
                self._append_audit(
                    conn,
                    event_type="OWNER_UNLOCK_DAILY_LOCK",
                    entity_id=req_id,
                    payload={
                        "owner_request_id": req_id,
                        "session_date": sdate,
                        "reason": clean_reason,
                        "clear_research_respite": bool(clear_research_respite),
                    },
                    occurred_at=ts,
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return self.snapshot(now_utc=ts_dt, session_date=sdate)

    def snapshot(
        self,
        now_utc: datetime | None = None,
        *,
        session_date: str | None = None,
    ) -> LedgerSnapshot:
        """Strictly zero-write read-only snapshot (mode=ro URI + PRAGMA query_only=ON)."""
        ts_dt = self._now() if now_utc is None else utc_time(now_utc, "now_utc")
        ts = _iso_utc(ts_dt)
        sdate = (
            trading_date_for(ts_dt)
            if session_date is None
            else _validate_session_date(session_date)
        )
        reg_now = regional_session_for(ts_dt)

        with self._lock, closing(self._connect_ro()) as conn:
            meta = self._load_meta_row(conn)
            cap = self._aggregate_capital_state(conn, meta)

            day_row = conn.execute(
                "SELECT * FROM daily_sessions WHERE scope_id = ? AND session_date = ?",
                (self._scope_id, sdate),
            ).fetchone()

            daily_reg: dict[RegionalSession, Decimal] = {
                RegionalSession.ASIA: Decimal("0.00"),
                RegionalSession.LONDON: Decimal("0.00"),
                RegionalSession.NEW_YORK: Decimal("0.00"),
            }
            day_trade_rows = conn.execute(
                "SELECT regional_session, realized_pnl_usd FROM realized_trades "
                "WHERE scope_id = ? AND session_date = ?",
                (self._scope_id, sdate),
            ).fetchall()
            daily_trade_sum = Decimal("0.00")
            for r in day_trade_rows:
                amt = _q2(Decimal(str(r["realized_pnl_usd"])))
                daily_trade_sum += amt
                daily_reg[_parse_regional_session(str(r["regional_session"]))] += amt

            act_usd = _q2(Decimal(str(meta["profit_floor_activation_usd"])))
            flr_ratio = Decimal(str(meta["profit_floor_ratio"]))

            if day_row is None:
                daily_pnl = _q2(daily_trade_sum)
                daily_peak = max(daily_pnl, Decimal("0.00"))
                daily_closed = 0
                daily_wins = 0
                daily_losses = 0
                daily_consec = 0
                respite_active = False
                loss_locked = False
                loss_lock_reason: str | None = None
                origin_mode: LedgerMode | None = None
                crossed_threshold = False
            else:
                daily_pnl = _q2(Decimal(str(day_row["realized_pnl_usd"])))
                daily_peak = _q2(Decimal(str(day_row["peak_pnl_usd"])))
                daily_closed = int(day_row["closed_trades"])
                daily_wins = int(day_row["win_count"])
                daily_losses = int(day_row["loss_count"])
                daily_consec = int(day_row["consecutive_losses"])
                respite_active = bool(int(day_row["research_respite_active"]))
                loss_locked = bool(int(day_row["daily_loss_locked"]))
                loss_lock_reason = (
                    None
                    if day_row["loss_lock_reason"] is None
                    else str(day_row["loss_lock_reason"])
                )
                origin_mode = (
                    None
                    if day_row["loss_lock_origin_mode"] is None
                    else LedgerMode(str(day_row["loss_lock_origin_mode"]))
                )
                crossed_threshold = bool(int(day_row["loss_lock_crossed_threshold"]))

            floor_armed = daily_peak >= act_usd
            if floor_armed:
                with localcontext() as ctx:
                    ctx.prec = 40
                    daily_floor = _q2(daily_peak * flr_ratio)
            else:
                daily_floor = Decimal("0.00")

            mode: LedgerMode = cap["mode"]
            loss_lock_carried_over = bool(
                loss_locked
                and (crossed_threshold or (origin_mode is not None and mode != origin_mode))
            )

            if loss_locked:
                session_status = DailySessionStatus.DAILY_LOSS_LOCKED
                new_risk_allowed = False
            elif respite_active:
                session_status = DailySessionStatus.RESEARCH_RESPITE
                new_risk_allowed = False
            else:
                session_status = DailySessionStatus.ACTIVE_TRADING
                new_risk_allowed = True

            audit_meta = conn.execute(
                "SELECT COUNT(*) AS cnt FROM audit_events WHERE scope_id = ?",
                (self._scope_id,),
            ).fetchone()
            audit_count = int(audit_meta["cnt"]) if audit_meta is not None else 0
            last_audit = conn.execute(
                "SELECT entry_sha256 FROM audit_events WHERE scope_id = ? ORDER BY seq DESC LIMIT 1",
                (self._scope_id,),
            ).fetchone()
            last_sha = (
                str(last_audit["entry_sha256"])
                if last_audit is not None
                else GENESIS_AUDIT_SHA256
            )

            return LedgerSnapshot(
                schema=SCHEMA_NAME,
                scope_id=self._scope_id,
                as_of_utc=ts,
                session_date=sdate,
                regional_session=reg_now,
                mode=mode,
                session_status=session_status,
                new_risk_allowed=new_risk_allowed,
                principal_usd=cap["principal_usd"],
                initial_equity_usd=cap["initial_equity_usd"],
                broker_equity_usd=cap["broker_equity_usd"],
                confirmed_settled_disbursed_usd=cap["confirmed_settled_disbursed_usd"],
                pending_transfers_usd=cap["pending_transfers_usd"],
                failed_cancelled_transfers_usd=cap["failed_cancelled_transfers_usd"],
                settled_equity_usd=cap["settled_equity_usd"],
                effective_equity_usd=cap["settled_equity_usd"],
                net_surplus_above_principal_usd=cap["net_surplus_above_principal_usd"],
                principal_shortfall_usd=cap["principal_shortfall_usd"],
                sweep_ratio=cap["sweep_ratio"],
                vault_sweep_target_usd=cap["vault_sweep_target_usd"],
                bank_vault_reserved_usd=cap["bank_vault_reserved_usd"],
                retained_trading_surplus_usd=cap["retained_trading_surplus_usd"],
                deployable_trading_equity_usd=cap["deployable_trading_equity_usd"],
                accounting_label=INTERNAL_ACCOUNTING_LABEL,
                lifetime_realized_pnl_usd=cap["lifetime_realized_pnl_usd"],
                daily_realized_pnl_usd=daily_pnl,
                daily_peak_pnl_usd=daily_peak,
                daily_profit_floor_armed=floor_armed,
                daily_profit_floor_usd=daily_floor,
                research_respite_active=respite_active,
                daily_loss_locked=loss_locked,
                loss_lock_reason=loss_lock_reason,
                loss_lock_origin_mode=origin_mode,
                loss_lock_carried_over=loss_lock_carried_over,
                daily_closed_trades=daily_closed,
                daily_win_count=daily_wins,
                daily_loss_count=daily_losses,
                daily_consecutive_losses=daily_consec,
                daily_asia_pnl_usd=_q2(daily_reg[RegionalSession.ASIA]),
                daily_london_pnl_usd=_q2(daily_reg[RegionalSession.LONDON]),
                daily_new_york_pnl_usd=_q2(daily_reg[RegionalSession.NEW_YORK]),
                lifetime_asia_pnl_usd=_q2(cap["lifetime_regional"][RegionalSession.ASIA]),
                lifetime_london_pnl_usd=_q2(cap["lifetime_regional"][RegionalSession.LONDON]),
                lifetime_new_york_pnl_usd=_q2(cap["lifetime_regional"][RegionalSession.NEW_YORK]),
                peak_equity_usd=cap["peak_equity_usd"],
                drawdown_usd=cap["drawdown_usd"],
                drawdown_pct=cap["drawdown_pct"],
                audit_event_count=audit_count,
                last_audit_sha256=last_sha,
            )

    def session_summary(self, session_date: str) -> dict[str, Decimal]:
        """Read-only per-session realized and regional P&L breakdown (0 writes)."""
        sdate = _validate_session_date(session_date)
        with self._lock, closing(self._connect_ro()) as conn:
            rows = conn.execute(
                "SELECT regional_session, realized_pnl_usd FROM realized_trades "
                "WHERE scope_id = ? AND session_date = ?",
                (self._scope_id, sdate),
            ).fetchall()
            total = Decimal("0.00")
            asia = Decimal("0.00")
            london = Decimal("0.00")
            ny = Decimal("0.00")
            for r in rows:
                amt = _q2(Decimal(str(r["realized_pnl_usd"])))
                total += amt
                reg = _parse_regional_session(str(r["regional_session"]))
                if reg == RegionalSession.ASIA:
                    asia += amt
                elif reg == RegionalSession.LONDON:
                    london += amt
                else:
                    ny += amt
        return {
            "realized_pnl_usd": _q2(total),
            "asia_pnl_usd": _q2(asia),
            "london_pnl_usd": _q2(london),
            "new_york_pnl_usd": _q2(ny),
        }

    def list_trades(self, *, session_date: str | None = None) -> tuple[RealizedTradeRecord, ...]:
        """Read-only query returning realized trades ordered by insertion seq."""
        with self._lock, closing(self._connect_ro()) as conn:
            if session_date is None:
                rows = conn.execute(
                    "SELECT * FROM realized_trades WHERE scope_id = ? ORDER BY seq ASC",
                    (self._scope_id,),
                ).fetchall()
            else:
                sdate = _validate_session_date(session_date)
                rows = conn.execute(
                    "SELECT * FROM realized_trades WHERE scope_id = ? AND session_date = ? ORDER BY seq ASC",
                    (self._scope_id, sdate),
                ).fetchall()
            return tuple(
                RealizedTradeRecord(
                    trade_id=str(r["trade_id"]),
                    event_id=str(r["event_id"]),
                    scope_id=str(r["scope_id"]),
                    session_date=str(r["session_date"]),
                    regional_session=_parse_regional_session(str(r["regional_session"])),
                    symbol=str(r["symbol"]),
                    broker_id=str(r["broker_id"]),
                    realized_pnl_usd=_q2(Decimal(str(r["realized_pnl_usd"]))),
                    occurred_at=str(r["occurred_at"]),
                    is_adjustment=bool(int(r["is_adjustment"])),
                    note=None if r["note"] is None else str(r["note"]),
                )
                for r in rows
            )

    def get_trade(self, trade_id: str) -> RealizedTradeRecord | None:
        """Read-only lookup for a single realized trade by trade_id."""
        tid = identifier(trade_id, "trade_id")
        with self._lock, closing(self._connect_ro()) as conn:
            r = conn.execute(
                "SELECT * FROM realized_trades WHERE scope_id = ? AND trade_id = ?",
                (self._scope_id, tid),
            ).fetchone()
            if r is None:
                return None
            return RealizedTradeRecord(
                trade_id=str(r["trade_id"]),
                event_id=str(r["event_id"]),
                scope_id=str(r["scope_id"]),
                session_date=str(r["session_date"]),
                regional_session=_parse_regional_session(str(r["regional_session"])),
                symbol=str(r["symbol"]),
                broker_id=str(r["broker_id"]),
                realized_pnl_usd=_q2(Decimal(str(r["realized_pnl_usd"]))),
                occurred_at=str(r["occurred_at"]),
                is_adjustment=bool(int(r["is_adjustment"])),
                note=None if r["note"] is None else str(r["note"]),
            )

    def list_disbursements(
        self,
        *,
        status: DisbursementStatus | str | None = None,
    ) -> tuple[DisbursementRecord, ...]:
        """Read-only query returning disbursements ordered by insertion seq."""
        with self._lock, closing(self._connect_ro()) as conn:
            if status is None:
                rows = conn.execute(
                    "SELECT * FROM disbursements WHERE scope_id = ? ORDER BY seq ASC",
                    (self._scope_id,),
                ).fetchall()
            else:
                st = _parse_disbursement_status(status)
                rows = conn.execute(
                    "SELECT * FROM disbursements WHERE scope_id = ? AND status = ? ORDER BY seq ASC",
                    (self._scope_id, st.value),
                ).fetchall()
            return tuple(
                DisbursementRecord(
                    transfer_id=str(r["transfer_id"]),
                    scope_id=str(r["scope_id"]),
                    amount_usd=_q2(Decimal(str(r["amount_usd"]))),
                    status=_parse_disbursement_status(str(r["status"])),
                    rail=str(r["rail"]),
                    destination_bank_id=str(r["destination_bank_id"]),
                    provider_tx_id=(
                        None if r["provider_tx_id"] is None else str(r["provider_tx_id"])
                    ),
                    debit_broker_equity=bool(int(r["debit_broker_equity"])),
                    created_at=str(r["created_at"]),
                    updated_at=str(r["updated_at"]),
                    settled_at=None if r["settled_at"] is None else str(r["settled_at"]),
                    note=None if r["note"] is None else str(r["note"]),
                )
                for r in rows
            )

    def get_disbursement(self, transfer_id: str) -> DisbursementRecord | None:
        """Read-only lookup for a single disbursement by transfer_id."""
        tid = identifier(transfer_id, "transfer_id")
        with self._lock, closing(self._connect_ro()) as conn:
            r = conn.execute(
                "SELECT * FROM disbursements WHERE scope_id = ? AND transfer_id = ?",
                (self._scope_id, tid),
            ).fetchone()
            if r is None:
                return None
            return DisbursementRecord(
                transfer_id=str(r["transfer_id"]),
                scope_id=str(r["scope_id"]),
                amount_usd=_q2(Decimal(str(r["amount_usd"]))),
                status=_parse_disbursement_status(str(r["status"])),
                rail=str(r["rail"]),
                destination_bank_id=str(r["destination_bank_id"]),
                provider_tx_id=None if r["provider_tx_id"] is None else str(r["provider_tx_id"]),
                debit_broker_equity=bool(int(r["debit_broker_equity"])),
                created_at=str(r["created_at"]),
                updated_at=str(r["updated_at"]),
                settled_at=None if r["settled_at"] is None else str(r["settled_at"]),
                note=None if r["note"] is None else str(r["note"]),
            )

    def verify_audit_chain(self) -> bool:
        """Read-only verification of the tamper-evident SHA-256 hash chain in audit_events."""
        with self._lock, closing(self._connect_ro()) as conn:
            rows = conn.execute(
                "SELECT seq, scope_id, event_type, entity_id, payload_json, occurred_at, "
                "prev_sha256, entry_sha256 FROM audit_events ORDER BY seq ASC"
            ).fetchall()

        expected_prev = GENESIS_AUDIT_SHA256
        for r in rows:
            prev_sha = str(r["prev_sha256"])
            stored_sha = str(r["entry_sha256"])
            if not hmac.compare_digest(prev_sha, expected_prev):
                return False
            recomputed = self._compute_audit_sha256(
                prev_sha256=prev_sha,
                scope_id=str(r["scope_id"]),
                event_type=str(r["event_type"]),
                entity_id=str(r["entity_id"]),
                payload_bytes=str(r["payload_json"]).encode("utf-8"),
                occurred_at=str(r["occurred_at"]),
            )
            if not hmac.compare_digest(stored_sha, recomputed):
                return False
            expected_prev = recomputed
        return True
