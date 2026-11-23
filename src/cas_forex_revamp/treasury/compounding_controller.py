"""100% Compounding Mode, House-Money Milestone Engine, and Dynamic Pyramid Risk Budget Controller.

Provides exact-Decimal treasury compounding policy, House-Money milestone tracking,
PR #25 constitutional risk-budget enforcement, and tamper-evident SHA-256 audit logging
backed by SQLite WAL with strictly zero-write ``?mode=ro`` snapshots.

Security & hygiene invariants:
- Exact ``Decimal`` arithmetic only: floats, booleans, NaN, and Infinity are rejected on
  every monetary, percentage, and ratio boundary.
- Unbreakable recovery invariant: whenever ``current_equity_usd <= starting_principal_usd``,
  the effective Bank Vault sweep ratio is ALWAYS ``Decimal("0.00")`` regardless of mode.
- PR #25 Finding [2] read-only device enforcement: mutating compounding modes/targets or
  acknowledging principal withdrawal requires ``owner_controls_allowed=True`` (otherwise
  raises ``OwnerKeyRequiredError``).
- PR #25 Finding [5] constitutional risk ceilings: per-trade stop-loss risk ``<= 1.00%``,
  drawdown cutoff ``< 10.00%`` (refused at ``>= 0.10``), margin level ``>= 1000.0%``, and
  open pyramid cap strictly bounded within ``1..8``.
- Strictly zero-write ``?mode=ro`` SQLite URI connections for ``snapshot()``,
  ``verify_audit_chain()``, ``evaluate_milestones()``, ``effective_vault_sweep_ratio()``,
  and ``compute_compounding_sizing_budget()`` (``PRAGMA data_version`` invariant).
- Zero ``assert`` statements (Bandit B101 compliant), zero network/shell/eval/pickle.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP
from enum import StrEnum
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ContractError, canonical_bytes
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, utc_time
from cas_forex_revamp.risk.demo_high_growth_profile import DemoHighGrowthProfile

COMPOUNDING_CONTROLLER_SCHEMA = "cas-forex.compounding-controller/1"
DEFAULT_SCOPE_ID = "default"
GENESIS_AUDIT_SHA256 = "0" * 64

MAX_CONSTITUTIONAL_STOP_RISK_PCT = Decimal("1.00")
MAX_CONSTITUTIONAL_DRAWDOWN_PCT = Decimal("0.10")
MIN_MARGIN_LEVEL_PCT = Decimal("1000.0")

MIN_VAULT_SWEEP_RATIO = Decimal("0.00")
MAX_VAULT_SWEEP_RATIO = Decimal("0.50")
DEFAULT_POST_TARGET_VAULT_RATIO = Decimal("0.50")

MIN_OPEN_TRADES_CAP = 1
MAX_OPEN_TRADES_CAP = 8

STATUS_BUILDING_TOWARD_PRINCIPAL = "BUILDING_TOWARD_PRINCIPAL"
STATUS_COMPOUNDING_TO_DOUBLE = "COMPOUNDING_TO_DOUBLE"
STATUS_HOUSE_MONEY_READY = "HOUSE_MONEY_READY_TO_PULL_PRINCIPAL"
STATUS_PLAYING_ON_HOUSE_MONEY = "PLAYING_ON_HOUSE_MONEY"

MILESTONE_LADDER_SPECS: tuple[tuple[str, str, Decimal], ...] = (
    ("HOUSE_MONEY_2X", "2x House Money", Decimal("2")),
    ("ACCELERATOR_5X", "5x Accelerator", Decimal("5")),
    ("GROWTH_10X", "10x Growth", Decimal("10")),
    ("INSTITUTIONAL_50X", "50x Institutional Income Tier", Decimal("50")),
)

_QUANT_10DP = Decimal("0.0000000001")
_QUANT_2DP = Decimal("0.01")
_QUANT_1DP = Decimal("0.1")
_HUNDRED = Decimal("100")
_ZERO_2DP = Decimal("0.00")
_ONE_2DP = Decimal("1.00")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")


class CompoundingControllerError(ContractError):
    """Raised when compounding configuration, inputs, or storage invariants are violated."""


class OwnerKeyRequiredError(CompoundingControllerError):
    """Raised when a read-only device attempts an owner-only compounding or withdrawal action."""


class CompoundingMode(StrEnum):
    """Treasury compounding allocation mode."""

    FULL_COMPOUND_100 = "FULL_COMPOUND_100"
    BALANCED_SPLIT_50_50 = "BALANCED_SPLIT_50_50"
    CUSTOM_SPLIT = "CUSTOM_SPLIT"


@dataclass(frozen=True, slots=True)
class MilestoneProgress:
    """Exact progress toward one tier in the compounding milestone ladder."""

    key: str
    label: str
    multiplier: Decimal
    target_usd: Decimal
    reached: bool
    remaining_usd: Decimal
    progress_pct: Decimal

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "multiplier": str(self.multiplier),
            "target_usd": _fmt_2dp(self.target_usd),
            "reached": self.reached,
            "remaining_usd": _fmt_2dp(self.remaining_usd),
            "progress_pct": _fmt_2dp(self.progress_pct),
        }


@dataclass(frozen=True, slots=True)
class CompoundingPolicyState:
    """Persisted compounding configuration and principal withdrawal state."""

    scope_id: str
    mode: CompoundingMode
    starting_principal_usd: Decimal
    compounding_target_usd: Decimal
    house_money_target_usd: Decimal
    post_target_vault_ratio: Decimal
    custom_vault_ratio: Decimal
    auto_enable_vault_at_target: bool
    principal_withdrawn: bool
    principal_withdrawn_usd: Decimal
    principal_withdrawn_at_utc: str | None
    last_equity_usd: Decimal
    updated_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "mode": self.mode.value,
            "starting_principal_usd": _fmt_2dp(self.starting_principal_usd),
            "compounding_target_usd": _fmt_2dp(self.compounding_target_usd),
            "house_money_target_usd": _fmt_2dp(self.house_money_target_usd),
            "post_target_vault_ratio": _fmt_2dp(self.post_target_vault_ratio),
            "custom_vault_ratio": _fmt_2dp(self.custom_vault_ratio),
            "auto_enable_vault_at_target": self.auto_enable_vault_at_target,
            "principal_withdrawn": self.principal_withdrawn,
            "principal_withdrawn_usd": _fmt_2dp(self.principal_withdrawn_usd),
            "principal_withdrawn_at_utc": self.principal_withdrawn_at_utc,
            "last_equity_usd": _fmt_2dp(self.last_equity_usd),
            "updated_at_utc": self.updated_at_utc,
        }


@dataclass(frozen=True, slots=True)
class HouseMoneyEvaluation:
    """Exact House-Money milestone evaluation for a given live equity value."""

    starting_principal_usd: Decimal
    current_equity_usd: Decimal
    house_money_target_usd: Decimal
    house_money_ready: bool
    house_money_status: str
    suggested_principal_pullout_usd: Decimal
    progress_to_house_money_pct: Decimal
    remaining_to_house_money_usd: Decimal
    effective_vault_sweep_ratio: Decimal
    principal_withdrawn: bool
    principal_withdrawn_usd: Decimal
    milestones: tuple[MilestoneProgress, ...]
    next_milestone: MilestoneProgress | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "starting_principal_usd": _fmt_2dp(self.starting_principal_usd),
            "current_equity_usd": _fmt_2dp(self.current_equity_usd),
            "house_money_target_usd": _fmt_2dp(self.house_money_target_usd),
            "house_money_ready": self.house_money_ready,
            "house_money_status": self.house_money_status,
            "suggested_principal_pullout_usd": _fmt_2dp(self.suggested_principal_pullout_usd),
            "progress_to_house_money_pct": _fmt_2dp(self.progress_to_house_money_pct),
            "remaining_to_house_money_usd": _fmt_2dp(self.remaining_to_house_money_usd),
            "effective_vault_sweep_ratio": _fmt_2dp(self.effective_vault_sweep_ratio),
            "principal_withdrawn": self.principal_withdrawn,
            "principal_withdrawn_usd": _fmt_2dp(self.principal_withdrawn_usd),
            "milestones": [m.to_dict() for m in self.milestones],
            "next_milestone": self.next_milestone.to_dict() if self.next_milestone is not None else None,
        }


@dataclass(frozen=True, slots=True)
class CompoundingSizingBudget:
    """Dynamic compounded pyramid risk-budget decision enforced against PR #25 ceilings."""

    allowed: bool
    reason_code: str
    per_trade_risk_usd: Decimal
    remaining_pyramid_slots: int
    max_total_open_risk_usd: Decimal
    effective_vault_sweep_ratio: Decimal
    house_money_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "per_trade_risk_usd": _fmt_2dp(self.per_trade_risk_usd),
            "remaining_pyramid_slots": self.remaining_pyramid_slots,
            "max_total_open_risk_usd": _fmt_2dp(self.max_total_open_risk_usd),
            "effective_vault_sweep_ratio": _fmt_2dp(self.effective_vault_sweep_ratio),
            "house_money_status": self.house_money_status,
        }


def _utc_now(now_utc: datetime | None = None) -> datetime:
    if now_utc is None:
        return datetime.now(timezone.utc)
    return utc_time(now_utc, "now_utc")


def _iso_utc(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def _fmt_2dp(value: Decimal) -> str:
    return format(value.quantize(_QUANT_2DP, rounding=ROUND_HALF_UP), "f")


def _fmt_1dp(value: Decimal) -> str:
    return format(value.quantize(_QUANT_1DP, rounding=ROUND_HALF_UP), "f")


def _require_decimal(
    value: Any,
    field: str,
    *,
    allow_zero: bool = True,
    allow_negative: bool = False,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, Decimal):
        raise CompoundingControllerError(f"{field} must be a finite Decimal (never float or bool)")
    try:
        validated = decimal_value(value, field)
    except ContractError as exc:
        raise CompoundingControllerError(str(exc)) from exc
    if not allow_negative and validated < Decimal("0"):
        raise CompoundingControllerError(f"{field} must be >= 0")
    if not allow_zero and validated <= Decimal("0"):
        raise CompoundingControllerError(f"{field} must be > 0")
    return validated


def _require_drawdown_pct(value: Any, field: str = "drawdown_pct") -> Decimal:
    """Validate a non-negative drawdown fraction, rounding sub-10dp repeating divisions conservatively UP."""
    if isinstance(value, bool) or not isinstance(value, Decimal) or not value.is_finite():
        raise CompoundingControllerError(f"{field} must be a finite Decimal (never float or bool)")
    if value < Decimal("0"):
        raise CompoundingControllerError(f"{field} must be >= 0")
    if value.copy_abs() >= Decimal("1e18"):
        raise CompoundingControllerError(f"{field} exceeds the v1 magnitude/12-decimal-place boundary")
    quantized = value.quantize(_QUANT_10DP, rounding=ROUND_CEILING) if value > Decimal("0") else Decimal("0")
    try:
        return decimal_value(quantized, field)
    except ContractError as exc:
        raise CompoundingControllerError(str(exc)) from exc


def _require_usd(value: Any, field: str, *, positive: bool = False) -> Decimal:
    dec = _require_decimal(value, field, allow_zero=not positive, allow_negative=False)
    return dec.quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)


def _require_ratio(value: Any, field: str) -> Decimal:
    dec = _require_decimal(value, field, allow_zero=True, allow_negative=False)
    if dec < MIN_VAULT_SWEEP_RATIO or dec > MAX_VAULT_SWEEP_RATIO:
        raise CompoundingControllerError(
            f"{field} must be within [{MIN_VAULT_SWEEP_RATIO}, {MAX_VAULT_SWEEP_RATIO}], got {dec}"
        )
    return dec.quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)


def _require_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise CompoundingControllerError(f"{field} must be a bool")
    return value


def _require_int(value: Any, field: str, *, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int:
        raise CompoundingControllerError(f"{field} must be an int")
    if value < minimum:
        raise CompoundingControllerError(f"{field} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise CompoundingControllerError(f"{field} must be <= {maximum}")
    return value


def _require_mode(mode: CompoundingMode | str) -> CompoundingMode:
    if isinstance(mode, CompoundingMode):
        return mode
    if type(mode) is str:
        try:
            return CompoundingMode(mode)
        except ValueError as exc:
            raise CompoundingControllerError(f"unsupported compounding mode: {mode!r}") from exc
    raise CompoundingControllerError("mode must be a CompoundingMode or valid mode string")


def _require_actor(actor: Any) -> str:
    if type(actor) is not str or not _ACTOR_RE.fullmatch(actor):
        raise CompoundingControllerError("actor must be a bounded non-empty identifier")
    return actor


def _require_owner_controls(owner_controls_allowed: Any, action: str) -> None:
    if owner_controls_allowed is not True:
        raise OwnerKeyRequiredError(
            f"owner key authorization required for {action} (read-only device denied)"
        )


def _parse_stored_decimal(raw: Any, field: str) -> Decimal:
    if type(raw) is not str:
        raise CompoundingControllerError(f"corrupt stored {field}: expected text")
    try:
        return _require_decimal(Decimal(raw), field, allow_zero=True, allow_negative=False)
    except (InvalidOperation, CompoundingControllerError) as exc:
        raise CompoundingControllerError(f"corrupt stored {field}: {raw!r}") from exc


def _audit_hash(
    *,
    seq: int,
    prev_sha256: str,
    scope_id: str,
    event_type: str,
    actor: str,
    payload_json: str,
    created_at: str,
) -> str:
    envelope = {
        "seq": seq,
        "prev_sha256": prev_sha256,
        "scope_id": scope_id,
        "event_type": event_type,
        "actor": actor,
        "payload_json": payload_json,
        "created_at": created_at,
    }
    return sha256(canonical_bytes(envelope)).hexdigest()


def compute_effective_vault_sweep_ratio(
    *,
    mode: CompoundingMode,
    starting_principal_usd: Decimal,
    current_equity_usd: Decimal,
    compounding_target_usd: Decimal,
    post_target_vault_ratio: Decimal = DEFAULT_POST_TARGET_VAULT_RATIO,
    custom_vault_ratio: Decimal = _ZERO_2DP,
    auto_enable_vault_at_target: bool = True,
) -> Decimal:
    """Compute exact effective Bank Vault sweep ratio enforcing the unbreakable recovery invariant."""
    valid_mode = _require_mode(mode)
    principal = _require_usd(starting_principal_usd, "starting_principal_usd", positive=True)
    equity = _require_usd(current_equity_usd, "current_equity_usd", positive=False)
    target = _require_usd(compounding_target_usd, "compounding_target_usd", positive=True)
    post_ratio = _require_ratio(post_target_vault_ratio, "post_target_vault_ratio")
    custom_ratio = _require_ratio(custom_vault_ratio, "custom_vault_ratio")
    auto_enable = _require_bool(auto_enable_vault_at_target, "auto_enable_vault_at_target")

    # UNBREAKABLE RECOVERY INVARIANT: $0.00 vaulted whenever at or below starting principal.
    if equity <= principal:
        return _ZERO_2DP

    if valid_mode is CompoundingMode.FULL_COMPOUND_100:
        if equity < target:
            return _ZERO_2DP
        return post_ratio if auto_enable else _ZERO_2DP

    if valid_mode is CompoundingMode.BALANCED_SPLIT_50_50:
        return MAX_VAULT_SWEEP_RATIO

    return custom_ratio


class CompoundingAndMilestoneController:
    """SQLite WAL-backed 100% Compounding, House-Money Milestone, and Pyramid Risk Controller."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        starting_principal_usd: Decimal = Decimal("5000.00"),
        mode: CompoundingMode | str = CompoundingMode.FULL_COMPOUND_100,
        compounding_target_usd: Decimal | None = None,
        house_money_target_usd: Decimal | None = None,
        post_target_vault_ratio: Decimal = DEFAULT_POST_TARGET_VAULT_RATIO,
        custom_vault_ratio: Decimal = _ZERO_2DP,
        auto_enable_vault_at_target: bool = True,
        scope_id: str = DEFAULT_SCOPE_ID,
        now_utc: datetime | None = None,
        demo_high_growth: DemoHighGrowthProfile | None = None,
    ) -> None:
        if not isinstance(db_path, (str, Path)):
            raise CompoundingControllerError("db_path must be a filesystem path")
        raw_path = str(db_path).strip()
        if not raw_path or raw_path == ":memory:" or raw_path.startswith("file:"):
            raise CompoundingControllerError("db_path must be a concrete on-disk SQLite file path")
        from cas_forex_revamp.composition.state_store import verify_non_symlink_sqlite_target

        try:
            self.db_path = verify_non_symlink_sqlite_target(
                raw_path, create_parent=True, label="compounding SQLite DB"
            )
        except ContractError as exc:
            raise CompoundingControllerError(str(exc)) from exc

        try:
            self.scope_id = identifier(scope_id, "scope_id")
        except ContractError as exc:
            raise CompoundingControllerError(str(exc)) from exc

        principal = _require_usd(starting_principal_usd, "starting_principal_usd", positive=True)
        resolved_mode = _require_mode(mode)
        default_double = (principal * Decimal("2")).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)

        comp_target = (
            default_double
            if compounding_target_usd is None
            else _require_usd(compounding_target_usd, "compounding_target_usd", positive=True)
        )
        if comp_target <= principal:
            raise CompoundingControllerError(
                "compounding_target_usd must be strictly greater than starting_principal_usd"
            )

        hm_target = (
            default_double
            if house_money_target_usd is None
            else _require_usd(house_money_target_usd, "house_money_target_usd", positive=True)
        )
        if hm_target <= principal:
            raise CompoundingControllerError(
                "house_money_target_usd must be strictly greater than starting_principal_usd"
            )

        post_ratio = _require_ratio(post_target_vault_ratio, "post_target_vault_ratio")
        custom_ratio = _require_ratio(custom_vault_ratio, "custom_vault_ratio")
        auto_enable = _require_bool(auto_enable_vault_at_target, "auto_enable_vault_at_target")
        init_ts = _iso_utc(_utc_now(now_utc))

        if demo_high_growth is not None and not isinstance(demo_high_growth, DemoHighGrowthProfile):
            raise CompoundingControllerError("demo_high_growth must be a DemoHighGrowthProfile or None")
        self._demo_high_growth: DemoHighGrowthProfile = (
            demo_high_growth if demo_high_growth is not None else DemoHighGrowthProfile(enabled=False)
        )
        self._lock = RLock()
        self._init_db(
            principal=principal,
            mode=resolved_mode,
            compounding_target_usd=comp_target,
            house_money_target_usd=hm_target,
            post_target_vault_ratio=post_ratio,
            custom_vault_ratio=custom_ratio,
            auto_enable_vault_at_target=auto_enable,
            created_at=init_ts,
        )

    def set_demo_high_growth_profile(
        self,
        profile: DemoHighGrowthProfile,
        *,
        execution_mode: Any = "DEMO",
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
    ) -> None:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise CompoundingControllerError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            execution_mode,
            live_trading_armed=live_trading_armed,
            live_trading_locked=live_trading_locked,
        )
        with self._lock:
            self._demo_high_growth = profile

    def _effective_max_stop_risk_pct(self) -> Decimal:
        with self._lock:
            return self._demo_high_growth.effective_stop_risk_ceiling_pct()

    def _effective_max_drawdown_pct(self) -> Decimal:
        with self._lock:
            return self._demo_high_growth.effective_drawdown_ceiling_pct()

    def _connect_rw(self) -> sqlite3.Connection:
        from cas_forex_revamp.composition.state_store import open_verified_sqlite_connection

        try:
            conn = open_verified_sqlite_connection(
                self.db_path,
                read_only=False,
                timeout=5.0,
                create_parent=True,
                label="compounding SQLite DB",
            )
        except ContractError as exc:
            raise CompoundingControllerError(str(exc)) from exc
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except Exception:
            conn.close()
            raise

    def _connect_ro(self) -> sqlite3.Connection:
        from cas_forex_revamp.composition.state_store import open_verified_sqlite_connection

        try:
            conn = open_verified_sqlite_connection(
                self.db_path,
                read_only=True,
                timeout=5.0,
                create_parent=False,
                label="compounding SQLite DB",
            )
        except ContractError as exc:
            raise CompoundingControllerError(str(exc)) from exc
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except Exception:
            conn.close()
            raise

    def _init_db(
        self,
        *,
        principal: Decimal,
        mode: CompoundingMode,
        compounding_target_usd: Decimal,
        house_money_target_usd: Decimal,
        post_target_vault_ratio: Decimal,
        custom_vault_ratio: Decimal,
        auto_enable_vault_at_target: bool,
        created_at: str,
    ) -> None:
        with self._lock, closing(self._connect_rw()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS compounding_config (
                    scope_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    starting_principal_usd_text TEXT NOT NULL,
                    compounding_target_usd_text TEXT NOT NULL,
                    house_money_target_usd_text TEXT NOT NULL,
                    post_target_vault_ratio_text TEXT NOT NULL,
                    custom_vault_ratio_text TEXT NOT NULL,
                    auto_enable_vault_at_target INTEGER NOT NULL,
                    principal_withdrawn INTEGER NOT NULL,
                    principal_withdrawn_usd_text TEXT NOT NULL,
                    principal_withdrawn_at_utc TEXT,
                    last_equity_usd_text TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS compounding_audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    prev_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT scope_id FROM compounding_config WHERE scope_id = ?",
                    (self.scope_id,),
                ).fetchone()
                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO compounding_config (
                            scope_id,
                            mode,
                            starting_principal_usd_text,
                            compounding_target_usd_text,
                            house_money_target_usd_text,
                            post_target_vault_ratio_text,
                            custom_vault_ratio_text,
                            auto_enable_vault_at_target,
                            principal_withdrawn,
                            principal_withdrawn_usd_text,
                            principal_withdrawn_at_utc,
                            last_equity_usd_text,
                            updated_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self.scope_id,
                            mode.value,
                            _fmt_2dp(principal),
                            _fmt_2dp(compounding_target_usd),
                            _fmt_2dp(house_money_target_usd),
                            _fmt_2dp(post_target_vault_ratio),
                            _fmt_2dp(custom_vault_ratio),
                            1 if auto_enable_vault_at_target else 0,
                            0,
                            _fmt_2dp(_ZERO_2DP),
                            None,
                            _fmt_2dp(principal),
                            created_at,
                        ),
                    )
                    self._append_audit_in_tx(
                        conn,
                        event_type="CONTROLLER_INITIALIZED",
                        actor="system",
                        payload={
                            "mode": mode.value,
                            "starting_principal_usd": _fmt_2dp(principal),
                            "compounding_target_usd": _fmt_2dp(compounding_target_usd),
                            "house_money_target_usd": _fmt_2dp(house_money_target_usd),
                            "post_target_vault_ratio": _fmt_2dp(post_target_vault_ratio),
                            "custom_vault_ratio": _fmt_2dp(custom_vault_ratio),
                            "auto_enable_vault_at_target": auto_enable_vault_at_target,
                        },
                        created_at=created_at,
                    )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def _append_audit_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        created_at: str,
    ) -> str:
        tail = conn.execute(
            "SELECT seq, entry_sha256 FROM compounding_audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if tail is None:
            next_seq = 1
            prev_sha = GENESIS_AUDIT_SHA256
        else:
            next_seq = int(tail["seq"]) + 1
            prev_sha = str(tail["entry_sha256"])

        payload_json = canonical_bytes(payload).decode("utf-8")
        entry_sha = _audit_hash(
            seq=next_seq,
            prev_sha256=prev_sha,
            scope_id=self.scope_id,
            event_type=event_type,
            actor=actor,
            payload_json=payload_json,
            created_at=created_at,
        )
        conn.execute(
            """
            INSERT INTO compounding_audit (
                seq,
                prev_sha256,
                entry_sha256,
                scope_id,
                event_type,
                actor,
                payload_json,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                next_seq,
                prev_sha,
                entry_sha,
                self.scope_id,
                event_type,
                actor,
                payload_json,
                created_at,
            ),
        )
        return entry_sha

    def _row_to_state(self, row: sqlite3.Row) -> CompoundingPolicyState:
        return CompoundingPolicyState(
            scope_id=str(row["scope_id"]),
            mode=_require_mode(str(row["mode"])),
            starting_principal_usd=_parse_stored_decimal(
                row["starting_principal_usd_text"], "starting_principal_usd_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            compounding_target_usd=_parse_stored_decimal(
                row["compounding_target_usd_text"], "compounding_target_usd_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            house_money_target_usd=_parse_stored_decimal(
                row["house_money_target_usd_text"], "house_money_target_usd_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            post_target_vault_ratio=_parse_stored_decimal(
                row["post_target_vault_ratio_text"], "post_target_vault_ratio_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            custom_vault_ratio=_parse_stored_decimal(
                row["custom_vault_ratio_text"], "custom_vault_ratio_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            auto_enable_vault_at_target=bool(int(row["auto_enable_vault_at_target"])),
            principal_withdrawn=bool(int(row["principal_withdrawn"])),
            principal_withdrawn_usd=_parse_stored_decimal(
                row["principal_withdrawn_usd_text"], "principal_withdrawn_usd_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            principal_withdrawn_at_utc=(
                str(row["principal_withdrawn_at_utc"])
                if row["principal_withdrawn_at_utc"] is not None
                else None
            ),
            last_equity_usd=_parse_stored_decimal(
                row["last_equity_usd_text"], "last_equity_usd_text"
            ).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP),
            updated_at_utc=str(row["updated_at_utc"]),
        )

    def _load_state(self, conn: sqlite3.Connection) -> CompoundingPolicyState:
        row = conn.execute(
            "SELECT * FROM compounding_config WHERE scope_id = ?",
            (self.scope_id,),
        ).fetchone()
        if row is None:
            raise CompoundingControllerError(
                f"compounding_config missing for scope_id={self.scope_id!r}"
            )
        return self._row_to_state(row)

    def _evaluate_for_state(
        self,
        state: CompoundingPolicyState,
        current_equity_usd: Decimal,
    ) -> HouseMoneyEvaluation:
        equity = _require_usd(current_equity_usd, "current_equity_usd", positive=False)
        principal = state.starting_principal_usd
        hm_target = state.house_money_target_usd

        effective_ratio = compute_effective_vault_sweep_ratio(
            mode=state.mode,
            starting_principal_usd=principal,
            current_equity_usd=equity,
            compounding_target_usd=state.compounding_target_usd,
            post_target_vault_ratio=state.post_target_vault_ratio,
            custom_vault_ratio=state.custom_vault_ratio,
            auto_enable_vault_at_target=state.auto_enable_vault_at_target,
        )

        if state.principal_withdrawn:
            house_money_status = STATUS_PLAYING_ON_HOUSE_MONEY
            house_money_ready = False
            suggested_pullout = _ZERO_2DP
            progress_pct = Decimal("100.00")
            remaining_usd = _ZERO_2DP
        elif equity >= hm_target:
            house_money_status = STATUS_HOUSE_MONEY_READY
            house_money_ready = True
            unwithdrawn = principal - state.principal_withdrawn_usd
            suggested_pullout = (
                unwithdrawn.quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)
                if unwithdrawn > _ZERO_2DP
                else _ZERO_2DP
            )
            progress_pct = Decimal("100.00")
            remaining_usd = _ZERO_2DP
        elif equity < principal:
            house_money_status = STATUS_BUILDING_TOWARD_PRINCIPAL
            house_money_ready = False
            suggested_pullout = _ZERO_2DP
            progress_pct = _ZERO_2DP
            remaining_usd = (hm_target - equity).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)
        else:
            house_money_status = STATUS_COMPOUNDING_TO_DOUBLE
            house_money_ready = False
            suggested_pullout = _ZERO_2DP
            gain_needed = hm_target - principal
            gain_achieved = equity - principal
            raw_pct = (gain_achieved * _HUNDRED) / gain_needed
            clamped_pct = min(Decimal("100.00"), max(_ZERO_2DP, raw_pct))
            progress_pct = clamped_pct.quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)
            remaining_usd = (hm_target - equity).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)

        milestones_list: list[MilestoneProgress] = []
        next_milestone: MilestoneProgress | None = None
        for key, label, mult in MILESTONE_LADDER_SPECS:
            tier_target = (
                hm_target
                if key == "HOUSE_MONEY_2X"
                else (principal * mult).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)
            )
            reached = (equity >= tier_target) or (
                key == "HOUSE_MONEY_2X" and state.principal_withdrawn
            )
            if reached:
                tier_remaining = _ZERO_2DP
                tier_pct = Decimal("100.00")
            else:
                tier_remaining = (tier_target - equity).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)
                if equity <= principal:
                    tier_pct = _ZERO_2DP
                else:
                    span = tier_target - principal
                    raw_tier_pct = ((equity - principal) * _HUNDRED) / span
                    tier_pct = min(Decimal("100.00"), max(_ZERO_2DP, raw_tier_pct)).quantize(
                        _QUANT_2DP, rounding=ROUND_HALF_UP
                    )
            item = MilestoneProgress(
                key=key,
                label=label,
                multiplier=mult,
                target_usd=tier_target,
                reached=reached,
                remaining_usd=tier_remaining,
                progress_pct=tier_pct,
            )
            milestones_list.append(item)
            if not reached and next_milestone is None:
                next_milestone = item

        return HouseMoneyEvaluation(
            starting_principal_usd=principal,
            current_equity_usd=equity,
            house_money_target_usd=hm_target,
            house_money_ready=house_money_ready,
            house_money_status=house_money_status,
            suggested_principal_pullout_usd=suggested_pullout,
            progress_to_house_money_pct=progress_pct,
            remaining_to_house_money_usd=remaining_usd,
            effective_vault_sweep_ratio=effective_ratio,
            principal_withdrawn=state.principal_withdrawn,
            principal_withdrawn_usd=state.principal_withdrawn_usd,
            milestones=tuple(milestones_list),
            next_milestone=next_milestone,
        )

    def _verify_audit_in_conn(self, conn: sqlite3.Connection) -> tuple[bool, int]:
        try:
            rows = conn.execute(
                """
                SELECT seq, prev_sha256, entry_sha256, scope_id, event_type, actor, payload_json, created_at
                FROM compounding_audit
                ORDER BY seq ASC
                """
            ).fetchall()
            cfg_count_row = conn.execute("SELECT COUNT(*) AS c FROM compounding_config").fetchone()
            cfg_count = int(cfg_count_row["c"]) if cfg_count_row is not None else 0
            has_seq_tbl = (
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'"
                ).fetchone()
                is not None
            )
            seq_row = (
                conn.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name = 'compounding_audit'"
                ).fetchone()
                if has_seq_tbl
                else None
            )
        except sqlite3.Error:
            return (False, 0)

        if len(rows) == 0:
            if cfg_count > 0:
                return (False, 0)
            if seq_row is not None and int(seq_row["seq"]) > 0:
                return (False, 0)
            return (True, 0)

        expected_seq = 1
        last_hash = GENESIS_AUDIT_SHA256

        for row in rows:
            seq = row["seq"]
            if type(seq) is not int or seq != expected_seq:
                return (False, len(rows))

            prev_sha = row["prev_sha256"]
            entry_sha = row["entry_sha256"]
            row_scope = row["scope_id"]
            event_type = row["event_type"]
            actor = row["actor"]
            payload_json = row["payload_json"]
            created_at = row["created_at"]

            if (
                type(prev_sha) is not str
                or type(entry_sha) is not str
                or not _SHA256_HEX_RE.fullmatch(prev_sha)
                or not _SHA256_HEX_RE.fullmatch(entry_sha)
                or prev_sha != last_hash
                or type(row_scope) is not str
                or not row_scope
                or type(event_type) is not str
                or not event_type
                or type(actor) is not str
                or not actor
                or type(payload_json) is not str
                or type(created_at) is not str
                or not created_at
            ):
                return (False, len(rows))

            try:
                json.loads(payload_json)
            except (TypeError, ValueError):
                return (False, len(rows))

            expected_entry_sha = _audit_hash(
                seq=seq,
                prev_sha256=prev_sha,
                scope_id=row_scope,
                event_type=event_type,
                actor=actor,
                payload_json=payload_json,
                created_at=created_at,
            )
            if entry_sha != expected_entry_sha:
                return (False, len(rows))

            last_hash = entry_sha
            expected_seq += 1

        if seq_row is not None:
            raw_highwater = seq_row["seq"]
            if type(raw_highwater) is not int or raw_highwater != len(rows):
                return (False, len(rows))

        return (True, len(rows))

    def get_policy_state(self) -> CompoundingPolicyState:
        """Read current persisted compounding policy state via strictly zero-write ``?mode=ro``."""
        with self._lock, closing(self._connect_ro()) as conn:
            return self._load_state(conn)

    def effective_vault_sweep_ratio(self, current_equity_usd: Decimal) -> Decimal:
        """Return exact effective Bank Vault sweep ratio for ``current_equity_usd`` (zero-write)."""
        equity = _require_usd(current_equity_usd, "current_equity_usd", positive=False)
        with self._lock, closing(self._connect_ro()) as conn:
            state = self._load_state(conn)
        return compute_effective_vault_sweep_ratio(
            mode=state.mode,
            starting_principal_usd=state.starting_principal_usd,
            current_equity_usd=equity,
            compounding_target_usd=state.compounding_target_usd,
            post_target_vault_ratio=state.post_target_vault_ratio,
            custom_vault_ratio=state.custom_vault_ratio,
            auto_enable_vault_at_target=state.auto_enable_vault_at_target,
        )

    def evaluate_milestones(self, current_equity_usd: Decimal) -> HouseMoneyEvaluation:
        """Evaluate House-Money status and milestone ladder for ``current_equity_usd`` (zero-write)."""
        equity = _require_usd(current_equity_usd, "current_equity_usd", positive=False)
        with self._lock, closing(self._connect_ro()) as conn:
            state = self._load_state(conn)
        return self._evaluate_for_state(state, equity)

    def set_compounding_mode(
        self,
        mode: CompoundingMode | str,
        *,
        compounding_target_usd: Decimal | None = None,
        house_money_target_usd: Decimal | None = None,
        custom_vault_ratio: Decimal | None = None,
        post_target_vault_ratio: Decimal | None = None,
        auto_enable_vault_at_target: bool | None = None,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
        now_utc: datetime | None = None,
    ) -> CompoundingPolicyState:
        """Update compounding mode and/or targets. Enforces OwnerKeyRequiredError on read-only devices."""
        _require_owner_controls(owner_controls_allowed, "set_compounding_mode")
        resolved_mode = _require_mode(mode)
        valid_actor = _require_actor(actor)
        ts = _iso_utc(_utc_now(now_utc))

        if custom_vault_ratio is not None:
            validated_custom_ratio: Decimal | None = _require_ratio(
                custom_vault_ratio, "custom_vault_ratio"
            )
        else:
            validated_custom_ratio = None

        if post_target_vault_ratio is not None:
            validated_post_ratio: Decimal | None = _require_ratio(
                post_target_vault_ratio, "post_target_vault_ratio"
            )
        else:
            validated_post_ratio = None

        if auto_enable_vault_at_target is not None:
            validated_auto_enable: bool | None = _require_bool(
                auto_enable_vault_at_target, "auto_enable_vault_at_target"
            )
        else:
            validated_auto_enable = None

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_state(conn)
                new_comp_target = (
                    current.compounding_target_usd
                    if compounding_target_usd is None
                    else _require_usd(compounding_target_usd, "compounding_target_usd", positive=True)
                )
                if new_comp_target <= current.starting_principal_usd:
                    raise CompoundingControllerError(
                        "compounding_target_usd must be strictly greater than starting_principal_usd"
                    )

                new_hm_target = (
                    current.house_money_target_usd
                    if house_money_target_usd is None
                    else _require_usd(house_money_target_usd, "house_money_target_usd", positive=True)
                )
                if new_hm_target <= current.starting_principal_usd:
                    raise CompoundingControllerError(
                        "house_money_target_usd must be strictly greater than starting_principal_usd"
                    )

                new_custom_ratio = (
                    current.custom_vault_ratio
                    if validated_custom_ratio is None
                    else validated_custom_ratio
                )
                new_post_ratio = (
                    current.post_target_vault_ratio
                    if validated_post_ratio is None
                    else validated_post_ratio
                )
                new_auto_enable = (
                    current.auto_enable_vault_at_target
                    if validated_auto_enable is None
                    else validated_auto_enable
                )

                conn.execute(
                    """
                    UPDATE compounding_config
                    SET mode = ?,
                        compounding_target_usd_text = ?,
                        house_money_target_usd_text = ?,
                        post_target_vault_ratio_text = ?,
                        custom_vault_ratio_text = ?,
                        auto_enable_vault_at_target = ?,
                        updated_at_utc = ?
                    WHERE scope_id = ?
                    """,
                    (
                        resolved_mode.value,
                        _fmt_2dp(new_comp_target),
                        _fmt_2dp(new_hm_target),
                        _fmt_2dp(new_post_ratio),
                        _fmt_2dp(new_custom_ratio),
                        1 if new_auto_enable else 0,
                        ts,
                        self.scope_id,
                    ),
                )
                self._append_audit_in_tx(
                    conn,
                    event_type="COMPOUNDING_MODE_UPDATED",
                    actor=valid_actor,
                    payload={
                        "previous_mode": current.mode.value,
                        "mode": resolved_mode.value,
                        "compounding_target_usd": _fmt_2dp(new_comp_target),
                        "house_money_target_usd": _fmt_2dp(new_hm_target),
                        "post_target_vault_ratio": _fmt_2dp(new_post_ratio),
                        "custom_vault_ratio": _fmt_2dp(new_custom_ratio),
                        "auto_enable_vault_at_target": new_auto_enable,
                    },
                    created_at=ts,
                )
                updated = self._load_state(conn)
                conn.execute("COMMIT")
                return updated
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def acknowledge_principal_withdrawn(
        self,
        amount_usd: Decimal,
        *,
        owner_controls_allowed: bool = True,
        actor: str = "owner",
        post_withdrawal_equity_usd: Decimal | None = None,
        now_utc: datetime | None = None,
    ) -> CompoundingPolicyState:
        """Record owner-confirmed original principal pull-out. Enforces OwnerKeyRequiredError."""
        _require_owner_controls(owner_controls_allowed, "acknowledge_principal_withdrawn")
        pullout = _require_usd(amount_usd, "amount_usd", positive=True)
        valid_actor = _require_actor(actor)
        ts = _iso_utc(_utc_now(now_utc))
        post_equity = (
            None
            if post_withdrawal_equity_usd is None
            else _require_usd(post_withdrawal_equity_usd, "post_withdrawal_equity_usd", positive=False)
        )

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_state(conn)
                new_withdrawn_total = (current.principal_withdrawn_usd + pullout).quantize(
                    _QUANT_2DP, rounding=ROUND_HALF_UP
                )
                fully_withdrawn = new_withdrawn_total >= current.starting_principal_usd
                withdrawn_at = (
                    current.principal_withdrawn_at_utc
                    if current.principal_withdrawn_at_utc is not None
                    else (ts if fully_withdrawn else None)
                )
                next_equity = current.last_equity_usd if post_equity is None else post_equity

                conn.execute(
                    """
                    UPDATE compounding_config
                    SET principal_withdrawn = ?,
                        principal_withdrawn_usd_text = ?,
                        principal_withdrawn_at_utc = ?,
                        last_equity_usd_text = ?,
                        updated_at_utc = ?
                    WHERE scope_id = ?
                    """,
                    (
                        1 if fully_withdrawn else 0,
                        _fmt_2dp(new_withdrawn_total),
                        withdrawn_at,
                        _fmt_2dp(next_equity),
                        ts,
                        self.scope_id,
                    ),
                )
                self._append_audit_in_tx(
                    conn,
                    event_type="PRINCIPAL_WITHDRAWAL_ACKNOWLEDGED",
                    actor=valid_actor,
                    payload={
                        "amount_usd": _fmt_2dp(pullout),
                        "cumulative_principal_withdrawn_usd": _fmt_2dp(new_withdrawn_total),
                        "starting_principal_usd": _fmt_2dp(current.starting_principal_usd),
                        "principal_withdrawn": fully_withdrawn,
                        "last_equity_usd": _fmt_2dp(next_equity),
                    },
                    created_at=ts,
                )
                updated = self._load_state(conn)
                conn.execute("COMMIT")
                return updated
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def record_equity_checkpoint(
        self,
        current_equity_usd: Decimal,
        *,
        actor: str = "system",
        now_utc: datetime | None = None,
    ) -> CompoundingPolicyState:
        """Persist latest observed account equity with hash-chained audit entry."""
        equity = _require_usd(current_equity_usd, "current_equity_usd", positive=False)
        valid_actor = _require_actor(actor)
        ts = _iso_utc(_utc_now(now_utc))

        with self._lock, closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_state(conn)
                conn.execute(
                    """
                    UPDATE compounding_config
                    SET last_equity_usd_text = ?,
                        updated_at_utc = ?
                    WHERE scope_id = ?
                    """,
                    (_fmt_2dp(equity), ts, self.scope_id),
                )
                self._append_audit_in_tx(
                    conn,
                    event_type="EQUITY_CHECKPOINT_RECORDED",
                    actor=valid_actor,
                    payload={
                        "previous_equity_usd": _fmt_2dp(current.last_equity_usd),
                        "current_equity_usd": _fmt_2dp(equity),
                    },
                    created_at=ts,
                )
                updated = self._load_state(conn)
                conn.execute("COMMIT")
                return updated
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def compute_compounding_sizing_budget(
        self,
        current_equity_usd: Decimal,
        risk_pct: Decimal,
        open_pyramid_count: int = 0,
        max_open_trades: int = 3,
        daily_loss_remaining_usd: Decimal = Decimal("1000.00"),
        drawdown_pct: Decimal = _ZERO_2DP,
        *,
        margin_level_pct: Decimal | None = None,
    ) -> CompoundingSizingBudget:
        """Compute dynamic compounded pyramid dollar risk budget enforcing PR #25 ceilings.

        Strictly zero-write (uses ``?mode=ro``).
        """
        equity = _require_usd(current_equity_usd, "current_equity_usd", positive=False)
        req_risk_pct = _require_decimal(risk_pct, "risk_pct", allow_zero=True, allow_negative=True)
        open_count = _require_int(open_pyramid_count, "open_pyramid_count", minimum=0)
        max_trades = _require_int(
            max_open_trades,
            "max_open_trades",
            minimum=MIN_OPEN_TRADES_CAP,
            maximum=MAX_OPEN_TRADES_CAP,
        )
        daily_rem = _require_decimal(
            daily_loss_remaining_usd,
            "daily_loss_remaining_usd",
            allow_zero=True,
            allow_negative=True,
        )
        dd_pct = _require_drawdown_pct(drawdown_pct, "drawdown_pct")
        margin_pct = (
            None
            if margin_level_pct is None
            else _require_decimal(margin_level_pct, "margin_level_pct", allow_zero=True, allow_negative=False)
        )

        with self._lock, closing(self._connect_ro()) as conn:
            state = self._load_state(conn)
        evaluation = self._evaluate_for_state(state, equity)
        remaining_slots = max(0, max_trades - open_count)

        def _deny(reason_code: str) -> CompoundingSizingBudget:
            return CompoundingSizingBudget(
                allowed=False,
                reason_code=reason_code,
                per_trade_risk_usd=_ZERO_2DP,
                remaining_pyramid_slots=remaining_slots,
                max_total_open_risk_usd=_ZERO_2DP,
                effective_vault_sweep_ratio=evaluation.effective_vault_sweep_ratio,
                house_money_status=evaluation.house_money_status,
            )

        if req_risk_pct <= Decimal("0"):
            return _deny("NON_POSITIVE_RISK_PCT")

        if req_risk_pct > self._effective_max_stop_risk_pct():
            return _deny("CONSTITUTIONAL_STOP_RISK_EXCEEDED")

        if equity <= _ZERO_2DP:
            return _deny("NON_POSITIVE_EQUITY")

        if dd_pct >= self._effective_max_drawdown_pct():
            return _deny("CONSTITUTIONAL_DRAWDOWN_LIMIT_REACHED")

        if margin_pct is not None and margin_pct < MIN_MARGIN_LEVEL_PCT:
            return _deny("CONSTITUTIONAL_MARGIN_LEVEL_BREACH")

        if open_count >= max_trades:
            return _deny("MAX_PYRAMID_SLOTS_REACHED")

        if daily_rem <= Decimal("0"):
            return _deny("DAILY_LOSS_BUDGET_EXHAUSTED")

        daily_rem_2dp = daily_rem.quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)
        raw_per_trade = ((equity * req_risk_pct) / _HUNDRED).quantize(
            _QUANT_2DP, rounding=ROUND_HALF_UP
        )
        per_trade_risk = min(raw_per_trade, daily_rem_2dp)
        if per_trade_risk <= _ZERO_2DP:
            return _deny("DAILY_LOSS_BUDGET_EXHAUSTED")

        raw_total_open = (raw_per_trade * Decimal(max_trades)).quantize(
            _QUANT_2DP, rounding=ROUND_HALF_UP
        )
        max_total_open = min(raw_total_open, daily_rem_2dp)

        return CompoundingSizingBudget(
            allowed=True,
            reason_code="APPROVED",
            per_trade_risk_usd=per_trade_risk,
            remaining_pyramid_slots=remaining_slots,
            max_total_open_risk_usd=max_total_open,
            effective_vault_sweep_ratio=evaluation.effective_vault_sweep_ratio,
            house_money_status=evaluation.house_money_status,
        )

    def verify_audit_chain(self) -> bool:
        """Verify SHA-256 hash-chained ``compounding_audit`` log integrity (strictly zero-write)."""
        with self._lock, closing(self._connect_ro()) as conn:
            valid, _ = self._verify_audit_in_conn(conn)
            return valid

    def snapshot(self, current_equity_usd: Decimal | None = None) -> dict[str, Any]:
        """Return strictly zero-write ``?mode=ro`` snapshot matching ``cas-forex.compounding-controller/1``."""
        override_equity = (
            None
            if current_equity_usd is None
            else _require_usd(current_equity_usd, "current_equity_usd", positive=False)
        )
        with self._lock, closing(self._connect_ro()) as conn:
            state = self._load_state(conn)
            audit_valid, audit_count = self._verify_audit_in_conn(conn)

        equity = state.last_equity_usd if override_equity is None else override_equity
        evaluation = self._evaluate_for_state(state, equity)
        effective_ratio = evaluation.effective_vault_sweep_ratio
        retained_ratio = (_ONE_2DP - effective_ratio).quantize(_QUANT_2DP, rounding=ROUND_HALF_UP)

        return {
            "schema": COMPOUNDING_CONTROLLER_SCHEMA,
            "scope_id": state.scope_id,
            "mode": state.mode.value,
            "starting_principal_usd": _fmt_2dp(state.starting_principal_usd),
            "current_equity_usd": _fmt_2dp(equity),
            "compounding_target_usd": _fmt_2dp(state.compounding_target_usd),
            "house_money_target_usd": _fmt_2dp(state.house_money_target_usd),
            "auto_enable_vault_at_target": state.auto_enable_vault_at_target,
            "post_target_vault_ratio": _fmt_2dp(state.post_target_vault_ratio),
            "custom_vault_ratio": _fmt_2dp(state.custom_vault_ratio),
            "effective_vault_sweep_ratio": _fmt_2dp(effective_ratio),
            "retained_compounding_ratio": _fmt_2dp(retained_ratio),
            "underwater": equity < state.starting_principal_usd,
            "at_or_below_principal": equity <= state.starting_principal_usd,
            "recovery_invariant_active": equity <= state.starting_principal_usd,
            "house_money_ready": evaluation.house_money_ready,
            "house_money_status": evaluation.house_money_status,
            "suggested_principal_pullout_usd": _fmt_2dp(evaluation.suggested_principal_pullout_usd),
            "progress_to_house_money_pct": _fmt_2dp(evaluation.progress_to_house_money_pct),
            "remaining_to_house_money_usd": _fmt_2dp(evaluation.remaining_to_house_money_usd),
            "principal_withdrawn": state.principal_withdrawn,
            "principal_withdrawn_usd": _fmt_2dp(state.principal_withdrawn_usd),
            "principal_withdrawn_at_utc": state.principal_withdrawn_at_utc,
            "milestones": [m.to_dict() for m in evaluation.milestones],
            "next_milestone": (
                evaluation.next_milestone.to_dict()
                if evaluation.next_milestone is not None
                else None
            ),
            "constitutional_ceilings": {
                "max_stop_risk_pct": _fmt_2dp(MAX_CONSTITUTIONAL_STOP_RISK_PCT),
                "max_drawdown_pct": _fmt_2dp(MAX_CONSTITUTIONAL_DRAWDOWN_PCT),
                "min_margin_level_pct": _fmt_1dp(MIN_MARGIN_LEVEL_PCT),
                "min_open_trades": MIN_OPEN_TRADES_CAP,
                "max_open_trades": MAX_OPEN_TRADES_CAP,
            },
            "audit_chain_valid": audit_valid,
            "audit_entry_count": audit_count,
            "updated_at_utc": state.updated_at_utc,
        }


__all__ = [
    "COMPOUNDING_CONTROLLER_SCHEMA",
    "CompoundingAndMilestoneController",
    "CompoundingControllerError",
    "CompoundingMode",
    "CompoundingPolicyState",
    "CompoundingSizingBudget",
    "DEFAULT_POST_TARGET_VAULT_RATIO",
    "DEFAULT_SCOPE_ID",
    "GENESIS_AUDIT_SHA256",
    "HouseMoneyEvaluation",
    "MAX_CONSTITUTIONAL_DRAWDOWN_PCT",
    "MAX_CONSTITUTIONAL_STOP_RISK_PCT",
    "MAX_OPEN_TRADES_CAP",
    "MAX_VAULT_SWEEP_RATIO",
    "MILESTONE_LADDER_SPECS",
    "MIN_MARGIN_LEVEL_PCT",
    "MIN_OPEN_TRADES_CAP",
    "MIN_VAULT_SWEEP_RATIO",
    "MilestoneProgress",
    "OwnerKeyRequiredError",
    "STATUS_BUILDING_TOWARD_PRINCIPAL",
    "STATUS_COMPOUNDING_TO_DOUBLE",
    "STATUS_HOUSE_MONEY_READY",
    "STATUS_PLAYING_ON_HOUSE_MONEY",
    "compute_effective_vault_sweep_ratio",
]
