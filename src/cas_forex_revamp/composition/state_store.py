"""Durable owner-only shared SQLite WAL state directory (`[3]`) & single-use OwnerRecoveryVerifier (`[10]`)."""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ContractError, canonical_bytes
from cas_forex_revamp.contracts.primitives import identifier, utc_time
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.operator.frontier_backends import ENV_THINKING_DEPTH, VALID_THINKING_DEPTHS
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.profit_sweep import (
    DEFAULT_SWEEP_RATIO,
    ENV_PROFIT_SWEEP_AUTO_ENABLED,
    ENV_PROFIT_SWEEP_PREFERRED_RAIL,
    ENV_PROFIT_SWEEP_RATIO,
    ProfitSweepVault,
    RAIL_BROKER_2FA_MANUAL,
    VALID_PAYOUT_RAILS,
)
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
    load_default_forex_valve_gate,
)

ENV_STATE_DIR = "CAS_FOREX_STATE_DIR"
ENV_MODEL_MAX_CALLS_PER_DAY = "CAS_FOREX_MODEL_MAX_CALLS_PER_DAY"
ENV_MODEL_MAX_DAILY_SPEND_USD = "CAS_FOREX_MODEL_MAX_DAILY_SPEND_USD"
DEFAULT_WINDOWS_STATE_DIR = r"D:\MetaTrader5\cas_forex_state"
VALID_RECOVERY_SCOPES = frozenset({"UNLOCK_QUOTA_SESSION", "REARM_DRAWDOWN", "UPDATE_QUOTA_TARGETS", "TREASURY_SWEEP"})
MAX_RECOVERY_TTL_SECONDS = 900


def _is_symlink_or_reparse(path: Path, st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) != 0:
        return True
    is_junc = getattr(path, "is_junction", None)
    return bool(callable(is_junc) and is_junc())


def ensure_secure_state_directory(state_dir: str | Path) -> Path:
    """Create and verify a non-symlink owner-only (`0o700`) persistent state directory."""
    if not isinstance(state_dir, (str, Path)) or not str(state_dir).strip():
        raise ContractError(f"{ENV_STATE_DIR} / --state-dir must be a non-empty path")
    target = Path(str(state_dir).strip())
    if os.path.lexists(target):
        st = os.lstat(target)
        if _is_symlink_or_reparse(target, st) or not stat.S_ISDIR(st.st_mode):
            raise ContractError(f"Refusing non-directory or symlink state_dir: {target}")
    else:
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        st = os.lstat(target)
        if _is_symlink_or_reparse(target, st) or not stat.S_ISDIR(st.st_mode):
            raise ContractError(f"Created state_dir is invalid: {target}")
    if os.name == "posix":
        os.chmod(target, 0o700)  # nosec B103: verified non-symlink S_ISDIR via lstat before setting owner-only 0o700
        verified = os.lstat(target)
        if (verified.st_mode & 0o077) != 0:
            raise ContractError("state_dir permissions must forbid group/other access")
    return target.resolve(strict=True)


def resolve_state_dir(
    environ: Mapping[str, str] | None = None,
    *,
    explicit_state_dir: str | Path | None = None,
    allow_windows_default: bool = True,
) -> Path:
    raw = str(explicit_state_dir).strip() if explicit_state_dir is not None else ""
    if not raw and environ is not None:
        raw = str(environ.get(ENV_STATE_DIR, "")).strip()
    if not raw and allow_windows_default and os.name == "nt":
        raw = DEFAULT_WINDOWS_STATE_DIR
    if not raw:
        raise ContractError(
            f"Persistent owner-only state directory required: pass --state-dir or set {ENV_STATE_DIR}"
        )
    return ensure_secure_state_directory(raw)


def _load_or_create_recovery_key(key_path: Path) -> bytes:
    if os.path.lexists(key_path):
        st = os.lstat(key_path)
        if _is_symlink_or_reparse(key_path, st) or not stat.S_ISREG(st.st_mode):
            raise ContractError(f"Refusing symlink or non-regular owner recovery key: {key_path}")
        if os.name == "posix" and (st.st_mode & 0o077) != 0:
            raise ContractError("Owner recovery key has unsafe group/world permissions")
        raw = key_path.read_bytes().strip()
        key = bytes.fromhex(raw.decode("ascii")) if len(raw) == 64 else raw
        if len(key) < 32:
            raise ContractError("Owner recovery key shorter than 32 bytes")
        return key
    key = secrets.token_bytes(32)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(key_path, flags, 0o600)
    try:
        os.write(fd, (key.hex() + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(key_path, 0o600)  # nosec B103: owner-only 0o600 recovery key on regular file
    return key


class OwnerRecoveryVerifier:
    """Single-use, expiring, scope-bound HMAC recovery verifier stored transactionally in SQLite."""

    def __init__(
        self,
        *,
        db_path: str | Path,
        key_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._db_path = Path(db_path)
        self._key_path = Path(key_path) if key_path is not None else (self._db_path.parent / ".owner_recovery.key")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if not self._initialized:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_recovery_tokens (
                    token_id TEXT PRIMARY KEY,
                    action_scope TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    issued_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    hmac_sha256 TEXT NOT NULL,
                    consumed_at_utc TEXT,
                    consumed_by TEXT
                )
                """
            )
            self._initialized = True
        return conn

    def mint_token(
        self,
        *,
        action_scope: str,
        target_ref: str = "*",
        ttl_seconds: int = 900,
        now: datetime | None = None,
    ) -> str:
        scope = action_scope.strip().upper()
        if scope not in VALID_RECOVERY_SCOPES:
            raise ContractError(f"action_scope must be one of {sorted(VALID_RECOVERY_SCOPES)}")
        if type(ttl_seconds) is not int or not (30 <= ttl_seconds <= MAX_RECOVERY_TTL_SECONDS):
            raise ContractError(f"recovery ttl_seconds must be in 30..{MAX_RECOVERY_TTL_SECONDS}")
        ref_clean = target_ref.strip() or "*"
        ts = utc_time(self._clock(), "clock") if now is None else utc_time(now, "now")
        exp = ts + timedelta(seconds=ttl_seconds)
        issued_str = ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires_str = exp.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        token_id = "rec-" + secrets.token_hex(12)
        with self._lock:
            key = _load_or_create_recovery_key(self._key_path)
            msg = f"cas-forex-owner-recovery/1|{token_id}|{scope}|{ref_clean}|{issued_str}|{expires_str}"
            sig = hmac.new(key, msg.encode("utf-8"), sha256).hexdigest()
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO owner_recovery_tokens (
                        token_id, action_scope, target_ref, issued_at_utc, expires_at_utc, hmac_sha256, consumed_at_utc, consumed_by
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (token_id, scope, ref_clean, issued_str, expires_str, sig),
                )
                conn.commit()
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        payload = {
            "protocol": "cas-forex-owner-recovery/1",
            "token_id": token_id,
            "action_scope": scope,
            "target_ref": ref_clean,
            "issued_at_utc": issued_str,
            "expires_at_utc": expires_str,
            "hmac_sha256": sig,
        }
        b64 = base64.urlsafe_b64encode(canonical_bytes(payload)).decode("ascii").rstrip("=")
        return f"casrx1.{b64}"

    def _decode_token(self, raw_token: str) -> dict[str, str]:
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise ContractError("OWNER_RECOVERY_TOKEN_REQUIRED: missing owner recovery token")
        text = raw_token.strip()
        if text.startswith("casrx1."):
            b64 = text[7:]
            b64 += "=" * (-len(b64) % 4)
            try:
                obj = json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
            except Exception as exc:
                raise ContractError("OWNER_RECOVERY_TOKEN_MALFORMED") from exc
        else:
            try:
                obj = json.loads(text)
            except Exception as exc:
                raise ContractError("OWNER_RECOVERY_TOKEN_MALFORMED") from exc
        if type(obj) is not dict or obj.get("protocol") != "cas-forex-owner-recovery/1":
            raise ContractError("OWNER_RECOVERY_TOKEN_PROTOCOL_INVALID")
        return {str(k): str(v) for k, v in obj.items()}

    def verify_and_consume(
        self,
        raw_token: str,
        *,
        expected_scope: str,
        target_ref: str | None = None,
        owner_request_id: str,
        now: datetime | None = None,
    ) -> dict[str, str]:
        identifier(owner_request_id, "owner_request_id")
        scope = expected_scope.strip().upper()
        if scope not in VALID_RECOVERY_SCOPES:
            raise ContractError(f"unsupported recovery scope {expected_scope!r}")
        fields = self._decode_token(raw_token)
        if fields.get("action_scope") != scope:
            raise ContractError("OWNER_RECOVERY_SCOPE_MISMATCH: token scope does not match action")
        tok_target = fields.get("target_ref", "*")
        if target_ref is not None and tok_target != "*" and tok_target != target_ref.strip():
            raise ContractError("OWNER_RECOVERY_TARGET_MISMATCH: token bound to a different target")
        token_id = fields.get("token_id", "")
        issued_str = fields.get("issued_at_utc", "")
        expires_str = fields.get("expires_at_utc", "")
        actual_sig = fields.get("hmac_sha256", "").lower()
        exp_dt = utc_time(datetime.fromisoformat(expires_str.replace("Z", "+00:00")), "expires_at_utc")
        iss_dt = utc_time(datetime.fromisoformat(issued_str.replace("Z", "+00:00")), "issued_at_utc")
        ts = utc_time(self._clock(), "clock") if now is None else utc_time(now, "now")
        if ts < iss_dt - timedelta(seconds=30) or ts > exp_dt:
            raise ContractError("OWNER_RECOVERY_TOKEN_EXPIRED")
        with self._lock:
            key = _load_or_create_recovery_key(self._key_path)
            msg = f"cas-forex-owner-recovery/1|{token_id}|{scope}|{tok_target}|{issued_str}|{expires_str}"
            expected_sig = hmac.new(key, msg.encode("utf-8"), sha256).hexdigest()
            if len(actual_sig) != 64 or not hmac.compare_digest(expected_sig, actual_sig):
                raise ContractError("OWNER_RECOVERY_SIGNATURE_INVALID")
            ts_str = ts.isoformat().replace("+00:00", "Z")
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    """
                    UPDATE owner_recovery_tokens
                       SET consumed_at_utc = ?, consumed_by = ?
                     WHERE token_id = ?
                       AND action_scope = ?
                       AND hmac_sha256 = ?
                       AND consumed_at_utc IS NULL
                    """,
                    (ts_str, owner_request_id, token_id, scope, expected_sig),
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    raise ContractError("OWNER_RECOVERY_TOKEN_UNKNOWN_OR_REPLAYED")
                conn.commit()
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        return {"token_id": token_id, "action_scope": scope, "consumed_by": owner_request_id, "consumed_at_utc": ts_str}


@dataclass(slots=True)
class SharedRuntimeState:
    state_dir: Path
    db_path: Path
    peak_equity_store: PeakEquityStore
    quota_store: DailyQuotaGovernanceStore
    model_gate: DurableModelExecutionGate
    owner_recovery: OwnerRecoveryVerifier
    valve_gate: ForexMetaValveGate
    profit_vault: ProfitSweepVault
    parallel_tiers: ParallelTierEngine
    thinking_depth_path: Path
    initial_thinking_depth: str


def initialize_shared_runtime_state(
    environ: Mapping[str, str],
    *,
    explicit_state_dir: str | Path | None = None,
    scope_id: str = "dual-shield-barbell",
    max_drawdown_pct: Decimal = DEFAULT_MAX_DRAWDOWN_PCT,
    clock: Any | None = None,
) -> SharedRuntimeState:
    """Initialize verified SQLite WAL shared state + recovery verifier inside `state_dir` (fail closed)."""
    sdir = resolve_state_dir(environ, explicit_state_dir=explicit_state_dir)
    db_path = sdir / "cas_forex_state.sqlite3"
    if os.path.lexists(db_path):
        st = os.lstat(db_path)
        if _is_symlink_or_reparse(db_path, st) or not stat.S_ISREG(st.st_mode):
            raise ContractError(f"Refusing symlink or non-regular state DB: {db_path}")

    # Integrity check before wiring components
    conn = sqlite3.connect(str(db_path), timeout=10.0, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        row = conn.execute("PRAGMA quick_check").fetchone()
        if row is None or str(row[0]).lower() != "ok":
            raise ContractError(f"State SQLite integrity check failed: {row}")
    finally:
        conn.close()
    if os.name == "posix" and db_path.exists():
        os.chmod(db_path, 0o600)  # nosec B103: owner-only 0o600 SQLite state database verified non-symlink

    owner_recovery = OwnerRecoveryVerifier(db_path=db_path, key_path=sdir / ".owner_recovery.key", clock=clock)
    peak_store = PeakEquityStore(db_path)
    valve_gate = load_default_forex_valve_gate(max_drawdown_pct=max_drawdown_pct, peak_equity_store=peak_store)
    quota_store = DailyQuotaGovernanceStore.from_environ(environ, path=db_path, scope_id=scope_id)
    quota_store.bind_owner_verifier(owner_recovery)

    raw_calls = str(environ.get(ENV_MODEL_MAX_CALLS_PER_DAY, "")).strip()
    max_calls = int(raw_calls) if raw_calls.isdigit() and int(raw_calls) > 0 else 5000
    raw_spend = str(environ.get(ENV_MODEL_MAX_DAILY_SPEND_USD, "")).strip()
    max_spend = Decimal(raw_spend) if raw_spend else Decimal("25.00")
    model_gate = DurableModelExecutionGate(
        db_path,
        max_calls_per_day=max_calls,
        max_daily_spend_usd=max_spend,
        scope_id=scope_id,
        clock=clock,
    )
    raw_ratio = str(environ.get(ENV_PROFIT_SWEEP_RATIO, "")).strip()
    sweep_ratio = Decimal(raw_ratio) if raw_ratio else DEFAULT_SWEEP_RATIO
    raw_auto = str(environ.get(ENV_PROFIT_SWEEP_AUTO_ENABLED, "true")).strip().lower()
    auto_sweep = raw_auto not in ("0", "false", "no", "off")
    raw_rail = str(environ.get(ENV_PROFIT_SWEEP_PREFERRED_RAIL, RAIL_BROKER_2FA_MANUAL)).strip().upper()
    if raw_rail not in VALID_PAYOUT_RAILS:
        raw_rail = RAIL_BROKER_2FA_MANUAL

    profit_vault = ProfitSweepVault(
        sdir / "profit_vault.sqlite3",
        scope_id=scope_id,
        sweep_ratio=sweep_ratio,
        auto_sweep_enabled=auto_sweep,
        preferred_rail=raw_rail,
        clock=clock,
    )
    parallel_tiers = ParallelTierEngine(
        sdir / "parallel_tiers.sqlite3",
        valve_gate=valve_gate,
        sweep_ratio=sweep_ratio,
        clock=clock,
    )
    td_path = sdir / "thinking_depth.json"
    env_td = str(environ.get(ENV_THINKING_DEPTH, "")).strip().upper()
    if env_td in VALID_THINKING_DEPTHS:
        init_td = env_td
    elif td_path.is_file() and not td_path.is_symlink():
        try:
            saved_td = str(json.loads(td_path.read_text(encoding="utf-8")).get("thinking_depth", "AUTO")).strip().upper()
            init_td = saved_td if saved_td in VALID_THINKING_DEPTHS else "AUTO"
        except (OSError, ValueError, TypeError):
            init_td = "AUTO"
    else:
        init_td = "AUTO"

    return SharedRuntimeState(
        state_dir=sdir,
        db_path=db_path,
        peak_equity_store=peak_store,
        quota_store=quota_store,
        model_gate=model_gate,
        owner_recovery=owner_recovery,
        valve_gate=valve_gate,
        profit_vault=profit_vault,
        parallel_tiers=parallel_tiers,
        thinking_depth_path=td_path,
        initial_thinking_depth=init_td,
    )
