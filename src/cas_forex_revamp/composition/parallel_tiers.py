"""Section B.5: 5-Tier Parallel Account Engine ($300, $1,000, $3,000, $6,000, $300,000).

All 5 isolated account tiers subscribe to the single live 50ms market stream and single
AI decision signal (zero extra AI API cost), enforcing exact bid/ask fills, realistic ECN
commissions, 1:500 FX / 1:200 Index margin checks, ROUND_FLOOR 0.01 lot sizing with honest
LOT_FLOOR_RISK_EXCEEDED vetoes when 0.01 lot exceeds 1.00% stop risk, independent
ForexMetaValveGate admission, PeakEquityStore drawdown protection, DailyQuotaGovernanceStore,
50%/50% ProfitSweepVault accumulation, and House-Money trend pyramiding.
"""
from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR, ROUND_HALF_UP, localcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import stat
from threading import RLock
from typing import Any
import uuid

from cas_forex_revamp.composition.trend_regime import (
    PyramidLegSnapshot,
    TrendRegimeDetector,
    evaluate_cross_market_offset_guard,
    evaluate_house_money_pyramid_leg,
)
from datetime import timedelta
from cas_forex_revamp.contracts import (
    ActionKind,
    ActionOption,
    ContractError,
    DecisionFact,
    DecisionOrigin,
    DecisionProvenance,
    DecisionRequest,
    DecisionResult,
    DecisionSelection,
    EvidenceKind,
    EvidenceReference,
    RunScope,
    Side,
    StateReference,
    canonical_bytes,
    content_digest,
    decimal_text,
)
from cas_forex_revamp.contracts.commands import ActionIntent
from cas_forex_revamp.contracts.primitives import decimal_value, parse_decimal, utc_time
from cas_forex_revamp.operator.decisions import DecisionProposal
from cas_forex_revamp.risk.demo_high_growth_profile import (
    DEMO_HIGH_GROWTH_BE_SCALE,
    DEMO_HIGH_GROWTH_DAILY_GOAL_PCT,
    DEMO_HIGH_GROWTH_DAILY_LOSS_BRAKE_PCT,
    DEMO_HIGH_GROWTH_TRAIL_SCALE,
    DemoHighGrowthProfile,
)
from cas_forex_revamp.treasury.profit_sweep import ProfitSweepVault
from cas_forex_revamp.valve.aggression_dial import (
    AggressionDialStore,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    MIN_CONSTITUTIONAL_VALVE_PROB,
    resolve_effective_params as resolve_dial_effective_params,
)
from cas_forex_revamp.valve.daily_quota import (
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_LOSS_TRIPPED,
    DailyQuotaGovernanceStore,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
)
from cas_forex_revamp.venue.dual_shield_router import BarbellCapitalPolicy
from cas_forex_revamp.venue.live_market_stream import INDEX_INSTRUMENTS
from cas_forex_revamp.venue.mt5_broker_bridge import (
    MT5_MIN_VOLUME,
    MT5_VOLUME_STEP,
    Mt5MarginCalculator,
)


DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE = "DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE"
DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS = "DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS"
logger = logging.getLogger(__name__)

DEFAULT_PARALLEL_TIER_AUTO_REPLENISH_FLOOR_PCT = Decimal("0.70")
_GENESIS_REPLENISH_SHA256 = "0" * 64


def _normalize_tier_floor_ratio(raw: object) -> tuple[Decimal, Decimal]:
    """Normalize replenishment floor into (ratio in [0.10, 0.99], display_pct in [10.00, 99.00])."""
    if isinstance(raw, bool):
        raise ContractError("auto_replenish_floor_pct must not be bool")
    try:
        dec = Decimal(str(raw).strip()) if not isinstance(raw, Decimal) else raw
    except (InvalidOperation, ValueError) as exc:
        raise ContractError("auto_replenish_floor_pct must be a finite decimal") from exc
    if not dec.is_finite() or dec <= Decimal("0"):
        raise ContractError("auto_replenish_floor_pct must be positive")
    if Decimal("0.10") <= dec <= Decimal("0.99"):
        return dec.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP), (
            dec * Decimal("100")
        ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if Decimal("10.00") <= dec <= Decimal("99.00"):
        return (dec / Decimal("100")).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP), (
            dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        )
    raise ContractError(
        "auto_replenish_floor_pct must be between 0.10 and 0.99 (or 10.00 and 99.00 percent)"
    )


class _DemoAutoReplenishRearmVerifier:
    """Scoped verifier permitting PeakEquityStore reset ONLY for verified DEMO auto-replenishment."""

    def __init__(
        self,
        *,
        expected_scope_id: str,
        expected_request_id: str,
        expected_peak: Decimal,
        execution_mode: str,
        live_trading_armed: bool,
    ) -> None:
        self._scope_id = expected_scope_id
        self._request_id = expected_request_id
        self._peak = expected_peak
        self._execution_mode = str(execution_mode or "").strip().upper()
        self._live_armed = bool(live_trading_armed)

    def verify_drawdown_rearm(
        self,
        *,
        scope_id: str,
        request_id: str,
        new_peak_equity: Decimal,
        now: datetime,
    ) -> bool:
        del now
        if self._execution_mode != "DEMO" or self._live_armed:
            return False
        return (
            scope_id == self._scope_id
            and request_id == self._request_id
            and request_id.startswith("DEMO_CAPITAL_REPLENISHED_")
            and Decimal(new_peak_equity) == self._peak
        )


@dataclass(frozen=True)
class ParallelTierSpec:
    tier_id: str
    label: str
    starting_capital_usd: Decimal
    color_class: str


DEFAULT_PARALLEL_TIER_SPECS: tuple[ParallelTierSpec, ...] = (
    ParallelTierSpec("TIER_1_CURRENT", "Current Barbell ($300,000)", Decimal("300000.00"), "tier-300k"),
    ParallelTierSpec("TIER_2_1000", "Tier $1,000 Starter", Decimal("1000.00"), "tier-1000"),
    ParallelTierSpec("TIER_3_3000", "Tier $3,000 Growth", Decimal("3000.00"), "tier-3000"),
    ParallelTierSpec("TIER_4_6000", "Tier $6,000 Accelerator", Decimal("6000.00"), "tier-6000"),
    ParallelTierSpec("TIER_5_300", "Tier $300 Micro Challenge", Decimal("300.00"), "tier-300"),
)

ECN_FX_COMMISSION_PER_LOT_ROUND_TURN = Decimal("7.00")
ECN_INDEX_COMMISSION_PER_CONTRACT_ROUND_TURN = Decimal("1.00")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_positive_signal_decimal(raw: Any, field: str) -> Decimal:
    if isinstance(raw, Decimal):
        return decimal_value(raw, field, positive=True)
    if isinstance(raw, str):
        return decimal_value(parse_decimal(raw.strip(), field), field, positive=True)
    raise ContractError(f"{field} requires a positive Decimal or plain decimal string")


def _tick_size(symbol: str) -> Decimal:
    if symbol in INDEX_INSTRUMENTS:
        return Decimal("0.01")
    if symbol.endswith("JPY"):
        return Decimal("0.001")
    return Decimal("0.00001")


def _is_symlink_or_reparse(path: Path, st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    if getattr(st, "st_reparse_tag", 0) != 0:
        return True
    return hasattr(path, "is_junction") and bool(path.is_junction())


def apply_verified_directory_mode(path: str | Path, dir_mode: int = 0o755) -> Path:
    """Verify target is a real non-symlink directory via os.lstat before applying restrictive permissions."""
    if (dir_mode & 0o022) != 0:
        raise ContractError(f"directory mode {oct(dir_mode)} must not grant group or other write permissions")
    target = Path(path)
    st = os.lstat(target)
    if _is_symlink_or_reparse(target, st) or not stat.S_ISDIR(st.st_mode):
        raise ContractError(f"parallel-tier directory path must be a real directory, not a file or symlink: {target}")
    os.chmod(target, dir_mode)  # nosec B103: owner-only verified directory mode after lstat + S_ISDIR
    return target


def apply_verified_regular_file_mode(path: str | Path, file_mode: int = 0o600) -> Path:
    """Verify target is a real non-symlink regular file via os.lstat before applying restrictive permissions."""
    if (file_mode & 0o066) != 0:
        raise ContractError(f"file mode {oct(file_mode)} must not grant group or other read/write permissions")
    target = Path(path)
    st = os.lstat(target)
    if _is_symlink_or_reparse(target, st) or not stat.S_ISREG(st.st_mode):
        raise ContractError(f"parallel-tier file path must be a real regular file, not a directory or symlink: {target}")
    os.chmod(target, file_mode)  # nosec B103: owner-only verified regular file mode after lstat + S_ISREG
    return target


class _TierProposal:
    """Typed CAS DecisionProposal wrapper presenting ``request``, ``result``, and ``intent`` to ForexMetaValveGate."""

    def __init__(
        self,
        *,
        scope: RunScope,
        state_ref: StateReference,
        req_id: str,
        opp_set_id: str,
        dec_id: str,
        intent: ActionIntent,
        view_facts: Mapping[str, Any],
        observed_at: datetime,
        reason: str,
    ) -> None:
        ev_id = f"ev-{req_id}"
        self.intent = intent
        ev = EvidenceReference(
            evidence_id=ev_id,
            kind=EvidenceKind.OBSERVATION,
            producer_id="parallel-tier-engine",
            content_sha256=content_digest(dict(view_facts)),
            observed_at=observed_at,
        )
        fact = DecisionFact(
            fact_id=f"fact-{req_id}",
            label="Observed tier state",
            value=canonical_bytes(dict(view_facts)).decode("utf-8"),
            evidence_ids=(ev_id,),
        )
        opt = ActionOption(intent.action_ref, "parallel-tier-mirror", "50ms", f"{intent.kind.value} {intent.instrument_id}", intent)
        self.request = DecisionRequest(
            request_id=req_id,
            opportunity_set_id=opp_set_id,
            state=state_ref,
            options=(opt,),
            facts=(fact,),
            evidence=(ev,),
        )
        sel = DecisionSelection(
            request_id=req_id,
            opportunity_set_id=opp_set_id,
            source_state_id=state_ref.state_id,
            selected_action_ref=intent.action_ref,
            reason=reason[:240],
            evidence_ids=(ev_id,),
        )
        self.result = DecisionResult(
            decision_id=dec_id,
            selection=sel,
            provenance=DecisionProvenance(
                origin=DecisionOrigin.ACTUAL_MODEL,
                adapter_id="parallel-tier-mirror",
                request_sha256=content_digest(self.request),
                response_sha256=content_digest(sel),
                prompt_version="frontier-v2",
                started_at=observed_at,
                completed_at=observed_at,
                model_id="parallel-tier-mirror",
                model_artifact_sha256=content_digest({"tier_mirror": scope.scenario_id}),
                inference_receipt_id=f"rcpt-{req_id}",
            ),
        )


class ParallelTierEngine:
    """Simultaneous 5-tier parallel account simulator backed by SQLite WAL and ForexMetaValveGate."""

    def __init__(
        self,
        db_path: Path,
        *,
        valve_gate: ForexMetaValveGate,
        specs: Sequence[ParallelTierSpec] = DEFAULT_PARALLEL_TIER_SPECS,
        barbell_policy: BarbellCapitalPolicy | None = None,
        sweep_ratio: Decimal = Decimal("0.50"),
        fx_min_lot: Decimal = MT5_MIN_VOLUME,
        index_min_lot: Decimal = MT5_MIN_VOLUME,
        aggression_dial: AggressionDialStore | None = None,
        demo_high_growth: DemoHighGrowthProfile | None = None,
        auto_replenish_enabled: bool | None = None,
        auto_replenish_floor_pct: Decimal | str | int | None = None,
        execution_mode: str = "DEMO",
        live_trading_armed: bool = False,
        clock: Callable[[], datetime] | None = None,
        telegram_notifier: Any | None = None,
        adaptive_lab: Any | None = None,
    ) -> None:
        if not isinstance(db_path, Path):
            db_path = Path(str(db_path))
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("valve_gate must be a ForexMetaValveGate")
        if aggression_dial is not None and not isinstance(aggression_dial, AggressionDialStore):
            raise ContractError("aggression_dial must be an AggressionDialStore or None")
        if demo_high_growth is not None and not isinstance(demo_high_growth, DemoHighGrowthProfile):
            raise ContractError("demo_high_growth must be a DemoHighGrowthProfile or None")
        if auto_replenish_enabled is not None and type(auto_replenish_enabled) is not bool:
            raise ContractError("auto_replenish_enabled must be bool or None")
        if type(live_trading_armed) is not bool:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        if str(execution_mode or "").strip().upper() != "DEMO" or live_trading_armed:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        init_ratio, init_pct = _normalize_tier_floor_ratio(
            DEFAULT_PARALLEL_TIER_AUTO_REPLENISH_FLOOR_PCT
            if auto_replenish_floor_pct is None
            else auto_replenish_floor_pct
        )
        self._auto_replenish_enabled_override = auto_replenish_enabled
        self._auto_replenish_floor_override = (
            (init_ratio, init_pct) if auto_replenish_floor_pct is not None else None
        )
        self._auto_replenish_enabled: bool = (
            True if auto_replenish_enabled is None else auto_replenish_enabled
        )
        self._auto_replenish_floor_ratio: Decimal = init_ratio
        self._auto_replenish_floor_pct: Decimal = init_pct
        db_path.parent.mkdir(parents=True, exist_ok=True)
        apply_verified_directory_mode(db_path.parent, dir_mode=0o700)
        self.db_path = db_path
        self._valve = valve_gate
        self._specs = tuple(specs)
        self._policy = barbell_policy or BarbellCapitalPolicy()
        self._calc = Mt5MarginCalculator(leverage=500, index_leverage=200)
        self._fx_min_lot = decimal_value(fx_min_lot, "fx_min_lot", positive=True)
        self._index_min_lot = decimal_value(index_min_lot, "index_min_lot", positive=True)
        self._clock = clock or _utc_now
        self._telegram_notifier = telegram_notifier
        self._adaptive_lab = adaptive_lab
        self._lock = RLock()
        self._regime = TrendRegimeDetector()
        self._peak_store = PeakEquityStore(db_path)
        self._aggression_dial: AggressionDialStore | None = aggression_dial
        self._last_signal_regime: str = "NEUTRAL"
        self._last_signal_valve_score: Decimal = Decimal("0.60")
        self._default_sweep_ratio = decimal_value(sweep_ratio, "sweep_ratio")
        self._demo_high_growth: DemoHighGrowthProfile = (
            demo_high_growth if demo_high_growth is not None else DemoHighGrowthProfile(enabled=False)
        )
        self._demo_high_growth.assert_demo_mode("DEMO", live_trading_armed=False, live_trading_locked=True)
        eff_sweep = self._demo_high_growth.effective_sweep_ratio(self._default_sweep_ratio)
        self._quotas: dict[str, DailyQuotaGovernanceStore] = {}
        self._vaults: dict[str, ProfitSweepVault] = {}
        self._tier_symbol_loss_cooldown_until: dict[tuple[str, str], datetime] = {}
        self._mid_history: dict[str, deque[Decimal]] = {}
        self._init_db(sweep_ratio=eff_sweep)
        self._auto_replenish_eligible_tiers_unlocked(now=self._clock(), trigger="STARTUP")
        if self._demo_high_growth.enabled:
            for q_store in self._quotas.values():
                if callable(getattr(q_store, "set_demo_high_growth_profile", None)):
                    q_store.set_demo_high_growth_profile(
                        self._demo_high_growth,
                        execution_mode="DEMO",
                        live_trading_armed=False,
                        live_trading_locked=True,
                    )

    @property
    def aggression_dial(self) -> AggressionDialStore | None:
        with self._lock:
            return self._aggression_dial

    def bind_adaptive_strategy_lab(self, lab: Any | None) -> None:
        with self._lock:
            self._adaptive_lab = lab

    def bind_aggression_dial(self, store: AggressionDialStore | None) -> None:
        if store is not None and not isinstance(store, AggressionDialStore):
            raise ContractError("aggression_dial must be an AggressionDialStore or None")
        with self._lock:
            self._aggression_dial = store

    def bind_telegram_notifier(self, notifier: Any | None) -> None:
        """Attach optional read-only Telegram alert notifier without altering execution flow."""
        self._telegram_notifier = notifier

    def set_demo_high_growth_profile(
        self,
        profile: DemoHighGrowthProfile,
        *,
        execution_mode: Any = "DEMO",
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
    ) -> None:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise ContractError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            execution_mode,
            live_trading_armed=live_trading_armed,
            live_trading_locked=live_trading_locked,
        )
        with self._lock:
            self._demo_high_growth = profile
            eff_ratio = profile.effective_sweep_ratio(self._default_sweep_ratio)
            for vault in self._vaults.values():
                vault.set_config(sweep_ratio=eff_ratio)
            for q_store in self._quotas.values():
                if callable(getattr(q_store, "set_demo_high_growth_profile", None)):
                    q_store.set_demo_high_growth_profile(
                        profile,
                        execution_mode=execution_mode,
                        live_trading_armed=live_trading_armed,
                        live_trading_locked=live_trading_locked,
                    )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _connect_ro(self) -> sqlite3.Connection:
        ro_uri = f"{self.db_path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(ro_uri, uri=True, timeout=5.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA query_only=ON")
            return conn
        except Exception:
            conn.close()
            raise

    def _init_db(self, *, sweep_ratio: Decimal) -> None:
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tier_accounts (
                        tier_id TEXT PRIMARY KEY,
                        label TEXT NOT NULL,
                        color_class TEXT NOT NULL,
                        starting_capital_usd TEXT NOT NULL,
                        balance_usd TEXT NOT NULL,
                        equity_usd TEXT NOT NULL,
                        peak_equity_usd TEXT NOT NULL,
                        realized_net_usd TEXT NOT NULL,
                        win_count INTEGER NOT NULL,
                        loss_count INTEGER NOT NULL,
                        gross_profit_usd TEXT NOT NULL,
                        gross_loss_usd TEXT NOT NULL,
                        last_skip_reason TEXT,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tier_positions (
                        ticket TEXT PRIMARY KEY,
                        tier_id TEXT NOT NULL,
                        symbol TEXT NOT NULL,
                        side TEXT NOT NULL,
                        units TEXT NOT NULL,
                        entry_price TEXT NOT NULL,
                        stop_loss TEXT NOT NULL,
                        take_profit TEXT,
                        initial_stop_loss TEXT,
                        peak_favorable TEXT NOT NULL,
                        protection_stage TEXT NOT NULL,
                        entry_commission_usd TEXT NOT NULL,
                        leg_index INTEGER NOT NULL,
                        opened_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tier_closed_trades (
                        trade_id TEXT PRIMARY KEY,
                        tier_id TEXT NOT NULL,
                        symbol TEXT NOT NULL,
                        side TEXT NOT NULL,
                        units TEXT NOT NULL,
                        entry_price TEXT NOT NULL,
                        exit_price TEXT NOT NULL,
                        commission_usd TEXT NOT NULL,
                        net_pnl_usd TEXT NOT NULL,
                        close_reason TEXT NOT NULL,
                        opened_at TEXT NOT NULL,
                        closed_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tier_equity_history (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        tier_id TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        equity_usd TEXT NOT NULL,
                        growth_pct TEXT NOT NULL
                    )
                    """
                )
                cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(tier_accounts)").fetchall()}
                if "color_class" not in cols:
                    conn.execute("ALTER TABLE tier_accounts ADD COLUMN color_class TEXT NOT NULL DEFAULT 'tier-300k'")
                    if "color_token" in cols:
                        conn.execute("UPDATE tier_accounts SET color_class = color_token")
                if "replenishment_count" not in cols:
                    conn.execute("ALTER TABLE tier_accounts ADD COLUMN replenishment_count INTEGER NOT NULL DEFAULT 0")
                if "cumulative_replenished_usd" not in cols:
                    conn.execute("ALTER TABLE tier_accounts ADD COLUMN cumulative_replenished_usd TEXT NOT NULL DEFAULT '0.00'")
                if "last_replenished_at" not in cols:
                    conn.execute("ALTER TABLE tier_accounts ADD COLUMN last_replenished_at TEXT")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tier_engine_meta (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        auto_replenish_enabled INTEGER NOT NULL DEFAULT 1,
                        auto_replenish_floor_pct TEXT NOT NULL DEFAULT '70.00',
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tier_replenishment_events (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        tier_id TEXT NOT NULL,
                        event_kind TEXT NOT NULL,
                        trigger_source TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        previous_balance_usd TEXT NOT NULL,
                        added_usd TEXT NOT NULL,
                        new_balance_usd TEXT NOT NULL,
                        new_peak_equity_usd TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        prev_sha256 TEXT NOT NULL,
                        event_sha256 TEXT NOT NULL
                    )
                    """
                )
                ts_meta = _iso(self._clock())
                meta_row = conn.execute(
                    "SELECT auto_replenish_enabled, auto_replenish_floor_pct FROM tier_engine_meta WHERE id = 1"
                ).fetchone()
                if meta_row is None:
                    conn.execute(
                        "INSERT INTO tier_engine_meta(id, auto_replenish_enabled, auto_replenish_floor_pct, updated_at) VALUES (1, ?, ?, ?)",
                        (
                            1 if self._auto_replenish_enabled else 0,
                            f"{self._auto_replenish_floor_pct:.2f}",
                            ts_meta,
                        ),
                    )
                else:
                    if self._auto_replenish_enabled_override is None:
                        self._auto_replenish_enabled = bool(int(meta_row["auto_replenish_enabled"]))
                    if self._auto_replenish_floor_override is None:
                        r_m, p_m = _normalize_tier_floor_ratio(meta_row["auto_replenish_floor_pct"])
                        self._auto_replenish_floor_ratio = r_m
                        self._auto_replenish_floor_pct = p_m
                    if (
                        self._auto_replenish_enabled_override is not None
                        or self._auto_replenish_floor_override is not None
                    ):
                        conn.execute(
                            "UPDATE tier_engine_meta SET auto_replenish_enabled = ?, auto_replenish_floor_pct = ?, updated_at = ? WHERE id = 1",
                            (
                                1 if self._auto_replenish_enabled else 0,
                                f"{self._auto_replenish_floor_pct:.2f}",
                                ts_meta,
                            ),
                        )
                pos_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(tier_positions)").fetchall()}
                if "initial_stop_loss" not in pos_cols:
                    conn.execute("ALTER TABLE tier_positions ADD COLUMN initial_stop_loss TEXT")
                    conn.execute(
                        "UPDATE tier_positions SET initial_stop_loss = stop_loss WHERE initial_stop_loss IS NULL AND protection_stage = 'INITIAL_SL'"
                    )
                ts = _iso(self._clock())
                for spec in self._specs:
                    row = conn.execute("SELECT tier_id FROM tier_accounts WHERE tier_id = ?", (spec.tier_id,)).fetchone()
                    if row is None:
                        start_txt = decimal_text(spec.starting_capital_usd)
                        conn.execute(
                            """
                            INSERT INTO tier_accounts(
                                tier_id, label, color_class, starting_capital_usd, balance_usd,
                                equity_usd, peak_equity_usd, realized_net_usd, win_count, loss_count,
                                gross_profit_usd, gross_loss_usd, last_skip_reason, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, '0', 0, 0, '0', '0', NULL, ?)
                            """,
                            (spec.tier_id, spec.label, spec.color_class, start_txt, start_txt, start_txt, start_txt, ts),
                        )
                        conn.execute(
                            "INSERT INTO tier_equity_history(tier_id, observed_at, equity_usd, growth_pct) VALUES (?, ?, ?, '0')",
                            (spec.tier_id, ts, start_txt),
                        )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        vault_db = self.db_path.parent / f"{self.db_path.stem}_vault.sqlite3"
        for spec in self._specs:
            scope = f"tier:{spec.tier_id}"
            self._peak_store.observe_equity(
                scope,
                current_equity=spec.starting_capital_usd,
                opening_balance=spec.starting_capital_usd,
                now=self._clock(),
            )
            self._quotas[spec.tier_id] = DailyQuotaGovernanceStore(
                path=self.db_path,
                scope_id=scope,
                quota_mode="PCT",
                daily_quota_pct=Decimal("0.025"),
                soft_quota_usd=Decimal("500"),
                hard_quota_usd=Decimal("1000"),
                max_loss_pct=Decimal("0.03"),
            )
            self._vaults[spec.tier_id] = ProfitSweepVault(
                vault_db, scope_id=scope, sweep_ratio=sweep_ratio, clock=self._clock
            )
        if self.db_path.exists():
            apply_verified_regular_file_mode(self.db_path, file_mode=0o600)

    def _entry_commission(self, symbol: str, units: Decimal) -> Decimal:
        csize = self._calc.contract_size_for(symbol)
        with localcontext() as ctx:
            ctx.prec = 40
            lots = units / csize
            rt = ECN_INDEX_COMMISSION_PER_CONTRACT_ROUND_TURN if symbol in INDEX_INSTRUMENTS else ECN_FX_COMMISSION_PER_LOT_ROUND_TURN
            return (lots * rt * Decimal("0.5")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def _compute_tier_quantity(
        self,
        *,
        tier_id: str,
        symbol: str,
        side: Side,
        entry_price: Decimal,
        stop_loss: Decimal,
        deployable_equity: Decimal,
        free_margin: Decimal,
        quotes: Mapping[str, tuple[Decimal, Decimal]],
        risk_multiplier: Decimal,
        tier_risk_pct: Decimal | None = None,
    ) -> tuple[Decimal | None, str | None]:
        stop_dist = abs(entry_price - stop_loss)
        if stop_dist <= Decimal("0") or deployable_equity <= Decimal("0"):
            return None, "ZERO_STOP_OR_EQUITY"

        csize = self._calc.contract_size_for(symbol)
        min_lot = self._index_min_lot if symbol in INDEX_INSTRUMENTS else self._fx_min_lot
        min_units = csize * min_lot
        step_units = csize * MT5_VOLUME_STEP
        with self._lock:
            dhg = self._demo_high_growth
        if dhg.enabled:
            dhg_ceil = dhg.effective_stop_risk_ceiling_pct()
            policy_cap = ((deployable_equity * dhg_ceil) / Decimal("100")).quantize(
                Decimal("0.01"), rounding=ROUND_FLOOR
            )
            eff_pct = dhg.target_risk_pct if tier_risk_pct is None else min(tier_risk_pct, dhg_ceil)
            base_budget = min((deployable_equity * eff_pct) / Decimal("100"), policy_cap)
        else:
            policy_cap = self._policy.max_stop_risk_amount(deployable_equity)
            if tier_risk_pct is not None:
                clamped_pct = min(
                    tier_risk_pct,
                    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
                    self._policy.max_stop_loss_equity_risk_pct,
                )
                base_budget = min((deployable_equity * clamped_pct) / Decimal("100"), policy_cap)
            else:
                base_budget = policy_cap
        budget = base_budget * risk_multiplier

        _, quote_ccy = Mt5MarginCalculator.split_symbol(symbol)
        rate = self._calc.conversion_rate(quote_ccy, quotes)

        with localcontext() as ctx:
            ctx.prec = 40
            raw_units = budget / (stop_dist * rate)
            one_step_margin = self._calc.required_margin(symbol, side, step_units, quotes)
            if one_step_margin > Decimal("0"):
                max_margin_units = ((free_margin * Decimal("0.90")) / one_step_margin) * step_units
                raw_units = min(raw_units, max_margin_units)
            steps = (raw_units / step_units).to_integral_value(rounding=ROUND_FLOOR)
            candidate_units = steps * step_units

        if candidate_units < min_units:
            return None, "LOT_FLOOR_RISK_EXCEEDED"

        # Double-check conservative stop risk on floored lot never exceeds 1.00% budget
        exact_risk = self._policy.stop_loss_risk(
            symbol=symbol, units=candidate_units, entry_price=entry_price, stop_price=stop_loss, quotes=quotes
        )
        if exact_risk > budget:
            return None, "LOT_FLOOR_RISK_EXCEEDED"
        return candidate_units.normalize(), None

    def process_tick(
        self,
        *,
        quotes: Mapping[str, tuple[Decimal, Decimal]],
        signal: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Advance all 5 tiers over a single 50ms market snapshot and optional AI entry/pyramid signal."""
        ts_dt = utc_time(now or self._clock(), "now")
        ts = _iso(ts_dt)

        validated_quotes: dict[str, tuple[Decimal, Decimal]] = {}
        for q_sym, q_pair in quotes.items():
            if not isinstance(q_pair, (tuple, list)) or len(q_pair) != 2:
                raise ContractError(f"quotes[{q_sym!r}] must be a (bid, ask) pair")
            q_bid = decimal_value(q_pair[0], f"quotes[{q_sym}].bid", positive=True)
            q_ask = decimal_value(q_pair[1], f"quotes[{q_sym}].ask", positive=True)
            if q_ask < q_bid:
                raise ContractError(f"quotes[{q_sym}] has ask < bid")
            validated_quotes[q_sym] = (q_bid, q_ask)
        quotes = validated_quotes

        sig_sym = ""
        sig_side: Side | None = None
        sig_sl: Decimal | None = None
        sig_tp: Decimal | None = None
        sig_regime = "TREND_IGNITION"
        if signal is not None:
            if not isinstance(signal, Mapping):
                raise ContractError("signal must be a mapping")
            sig_sym = str(signal.get("symbol") or "")
            raw_side = signal.get("side")
            side_text = "BUY" if raw_side is None else str(raw_side)
            try:
                sig_side = Side(side_text)
            except ValueError as exc:
                raise ContractError(f"invalid signal side {raw_side!r}") from exc
            if sig_sym in quotes:
                sig_sl = _parse_positive_signal_decimal(signal.get("stop_price"), "signal.stop_price")
                raw_tp = signal.get("take_profit_price")
                sig_tp = _parse_positive_signal_decimal(raw_tp, "signal.take_profit_price") if raw_tp is not None else None
                sig_regime = str(signal.get("regime") or "TREND_IGNITION")
                self._last_signal_regime = sig_regime
                raw_sig_vs = signal.get("valve_score")
                if raw_sig_vs is not None and not isinstance(raw_sig_vs, bool):
                    try:
                        parsed_sig_vs: Decimal | None = Decimal(str(raw_sig_vs))
                    except (InvalidOperation, ValueError, TypeError):
                        parsed_sig_vs = None
                    if (
                        parsed_sig_vs is not None
                        and parsed_sig_vs.is_finite()
                        and Decimal("0") <= parsed_sig_vs <= Decimal("1")
                    ):
                        self._last_signal_valve_score = parsed_sig_vs

        dial_store = self.aggression_dial
        dial_snap = dial_store.snapshot() if dial_store is not None else None
        dial_tiers_map = (
            dial_snap.get("tiers_by_id", {})
            if isinstance(dial_snap, Mapping) and isinstance(dial_snap.get("tiers_by_id"), Mapping)
            else {}
        )

        with self._lock:
            tiers_post_close_check: list[str] = []
            with closing(self._connect()) as conn:
                for q_sym, (q_bid, q_ask) in quotes.items():
                    self._mid_history.setdefault(q_sym, deque(maxlen=64)).append((q_bid + q_ask) / Decimal("2"))
                for spec in self._specs:
                    tid = spec.tier_id
                    raw_tier_dial = dial_tiers_map.get(tid)
                    tier_eff: dict[str, Any] | None = None
                    pending_closes: list[tuple[str, str, str, Decimal, Decimal]] = []
                    open_unrealized = Decimal("0")
                    used_margin = Decimal("0")
                    balance = Decimal("0")

                    # Tx 1: Atomic close / fast-protection updates for this tier (never spans external DB stores)
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        acct = conn.execute("SELECT * FROM tier_accounts WHERE tier_id = ?", (tid,)).fetchone()
                        if acct is None:
                            conn.execute("ROLLBACK")
                            continue
                        balance = Decimal(str(acct["balance_usd"]))
                        positions = conn.execute("SELECT * FROM tier_positions WHERE tier_id = ?", (tid,)).fetchall()

                        # 1. Mark-to-market, fast protection, and SL/TP exits on real bid/ask
                        for pos in positions:
                            sym = str(pos["symbol"])
                            if sym not in quotes:
                                continue
                            bid, ask = quotes[sym]
                            side = Side(str(pos["side"]))
                            units = Decimal(str(pos["units"]))
                            entry_p = Decimal(str(pos["entry_price"]))
                            sl_p = Decimal(str(pos["stop_loss"]))
                            tp_p = Decimal(str(pos["take_profit"])) if pos["take_profit"] is not None else None
                            exit_px = bid if side is Side.BUY else ask

                            # Check resting SL/TP trigger first
                            hit_reason: str | None = None
                            fill_exit = exit_px
                            if side is Side.BUY:
                                if exit_px <= sl_p:
                                    hit_reason = "STOP_LOSS"
                                    fill_exit = min(exit_px, sl_p)
                                elif tp_p is not None and exit_px >= tp_p:
                                    hit_reason = "TAKE_PROFIT"
                                    fill_exit = tp_p
                            else:
                                if exit_px >= sl_p:
                                    hit_reason = "STOP_LOSS"
                                    fill_exit = max(exit_px, sl_p)
                                elif tp_p is not None and exit_px <= tp_p:
                                    hit_reason = "TAKE_PROFIT"
                                    fill_exit = tp_p

                            _, q_ccy = Mt5MarginCalculator.split_symbol(sym)
                            conv = self._calc.conversion_rate(q_ccy, quotes)

                            if hit_reason is not None:
                                with localcontext() as ctx:
                                    ctx.prec = 40
                                    raw_pnl = ((fill_exit - entry_p) if side is Side.BUY else (entry_p - fill_exit)) * units * conv
                                    exit_comm = self._entry_commission(sym, units)
                                    entry_comm = Decimal(str(pos["entry_commission_usd"]))
                                    total_comm = entry_comm + exit_comm
                                    net_pnl = (raw_pnl - exit_comm).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

                                balance = balance + net_pnl
                                conn.execute("DELETE FROM tier_positions WHERE ticket = ?", (str(pos["ticket"]),))
                                conn.execute(
                                    """
                                    INSERT INTO tier_closed_trades(
                                        trade_id, tier_id, symbol, side, units, entry_price, exit_price,
                                        commission_usd, net_pnl_usd, close_reason, opened_at, closed_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    (
                                        f"ttr-{uuid.uuid4().hex[:14]}",
                                        tid,
                                        sym,
                                        side.value,
                                        decimal_text(units),
                                        decimal_text(entry_p),
                                        decimal_text(fill_exit),
                                        decimal_text(total_comm),
                                        decimal_text(net_pnl),
                                        hit_reason,
                                        str(pos["opened_at"]),
                                        ts,
                                    ),
                                )
                                win_inc = 1 if net_pnl >= Decimal("0") else 0
                                loss_inc = 0 if net_pnl >= Decimal("0") else 1
                                gp = Decimal(str(acct["gross_profit_usd"])) + (net_pnl if net_pnl > 0 else Decimal("0"))
                                gl = Decimal(str(acct["gross_loss_usd"])) + ((-net_pnl) if net_pnl < 0 else Decimal("0"))
                                rl = Decimal(str(acct["realized_net_usd"])) + net_pnl
                                conn.execute(
                                    """
                                    UPDATE tier_accounts SET balance_usd = ?, realized_net_usd = ?,
                                        win_count = win_count + ?, loss_count = loss_count + ?,
                                        gross_profit_usd = ?, gross_loss_usd = ?, updated_at = ?
                                    WHERE tier_id = ?
                                    """,
                                    (
                                        decimal_text(balance),
                                        decimal_text(rl),
                                        win_inc,
                                        loss_inc,
                                        decimal_text(gp),
                                        decimal_text(gl),
                                        ts,
                                        tid,
                                    ),
                                )
                                if (
                                    net_pnl < Decimal("0")
                                    and self._demo_high_growth.enabled
                                    and self._demo_high_growth.post_loss_cooldown_seconds > 0
                                ):
                                    self._tier_symbol_loss_cooldown_until[(tid, sym)] = ts_dt + timedelta(
                                        seconds=self._demo_high_growth.post_loss_cooldown_seconds
                                    )
                                pending_closes.append((f"{tid}:{pos['ticket']}", sym, str(pos["ticket"]), net_pnl, balance))
                                acct = conn.execute("SELECT * FROM tier_accounts WHERE tier_id = ?", (tid,)).fetchone()
                                continue

                            # Fast protection: Snap-to-Breakeven & Monotonic Trailing Stop
                            prev_peak = Decimal(str(pos["peak_favorable"]))
                            cur_px = bid if side is Side.BUY else ask
                            peak = max(prev_peak, cur_px) if side is Side.BUY else min(prev_peak, cur_px)
                            excursion = (peak - entry_p) if side is Side.BUY else (entry_p - peak)
                            t_sz = _tick_size(sym)
                            raw_init_sl = pos["initial_stop_loss"] if "initial_stop_loss" in pos.keys() else None
                            if raw_init_sl is not None:
                                init_sl_dist = abs(entry_p - Decimal(str(raw_init_sl)))
                            elif str(pos["protection_stage"]) == "INITIAL_SL":
                                init_sl_dist = abs(entry_p - sl_p)
                            else:
                                init_sl_dist = Decimal("0")
                            be_trig = Decimal("10.00") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("120")
                            be_off = Decimal("1.50") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("10")
                            trail_act = Decimal("22.00") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("220")
                            trail_dist = Decimal("14.00") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("140")
                            if self._demo_high_growth.enabled and self._demo_high_growth.let_winners_run:
                                be_trig = (be_trig * DEMO_HIGH_GROWTH_BE_SCALE).quantize(t_sz, rounding=ROUND_HALF_UP)
                                trail_act = (trail_act * DEMO_HIGH_GROWTH_TRAIL_SCALE).quantize(t_sz, rounding=ROUND_HALF_UP)
                                trail_dist = (trail_dist * DEMO_HIGH_GROWTH_TRAIL_SCALE).quantize(t_sz, rounding=ROUND_HALF_UP)
                                if init_sl_dist > Decimal("0"):
                                    be_trig = max(be_trig, (init_sl_dist * Decimal("1.00")).quantize(t_sz, rounding=ROUND_HALF_UP))
                                    be_off = max(be_off, (init_sl_dist * Decimal("0.15")).quantize(t_sz, rounding=ROUND_HALF_UP))
                                    trail_act = max(trail_act, (init_sl_dist * Decimal("1.50")).quantize(t_sz, rounding=ROUND_HALF_UP))
                                    trail_dist = max(trail_dist, (init_sl_dist * Decimal("0.75")).quantize(t_sz, rounding=ROUND_HALF_UP))
                            elif init_sl_dist > Decimal("0"):
                                be_trig = max(be_trig, (init_sl_dist * Decimal("0.54")).quantize(t_sz, rounding=ROUND_HALF_UP))
                                trail_act = max(trail_act, (init_sl_dist * Decimal("1.00")).quantize(t_sz, rounding=ROUND_HALF_UP))

                            new_sl = sl_p
                            new_stage = str(pos["protection_stage"])
                            if excursion >= be_trig:
                                cand_be = (entry_p + be_off if side is Side.BUY else entry_p - be_off).quantize(t_sz, rounding=ROUND_HALF_UP)
                                if side is Side.BUY and cand_be < bid - t_sz and cand_be > new_sl:
                                    new_sl = cand_be
                                    new_stage = "BREAKEVEN_LOCKED"
                                elif side is Side.SELL and cand_be > ask + t_sz and cand_be < new_sl:
                                    new_sl = cand_be
                                    new_stage = "BREAKEVEN_LOCKED"
                            if excursion >= trail_act:
                                cand_tr = (peak - trail_dist if side is Side.BUY else peak + trail_dist).quantize(t_sz, rounding=ROUND_HALF_UP)
                                if side is Side.BUY and cand_tr < bid - t_sz and cand_tr > new_sl:
                                    new_sl = cand_tr
                                    new_stage = "TRAILING_PROFIT"
                                elif side is Side.SELL and cand_tr > ask + t_sz and cand_tr < new_sl:
                                    new_sl = cand_tr
                                    new_stage = "TRAILING_PROFIT"
                            if new_sl != sl_p or peak != prev_peak or new_stage != str(pos["protection_stage"]):
                                conn.execute(
                                    "UPDATE tier_positions SET stop_loss = ?, peak_favorable = ?, protection_stage = ? WHERE ticket = ?",
                                    (decimal_text(new_sl), decimal_text(peak), new_stage, str(pos["ticket"])),
                                )

                            with localcontext() as ctx:
                                ctx.prec = 40
                                upnl = (
                                    ((cur_px - entry_p) if side is Side.BUY else (entry_p - cur_px)) * units * conv
                                ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                            open_unrealized += upnl
                            used_margin += self._calc.required_margin(sym, side, units, quotes)

                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise

                    # Propagate committed closes to external stores outside any write transaction on self.db_path
                    for close_trade_id, close_sym, close_ticket, net_pnl, post_balance in pending_closes:
                        self._vaults[tid].record_realized_close(
                            trade_id=close_trade_id,
                            symbol=close_sym,
                            broker_id=tid,
                            realized_net_usd=net_pnl,
                            occurred_at=ts_dt,
                        )
                        self._quotas[tid].record_realized_trade(
                            net_pnl, symbol=close_sym, ticket=close_ticket, starting_equity=post_balance, now=ts_dt
                        )

                    equity = balance + open_unrealized
                    if equity > Decimal("0"):
                        self._quotas[tid].observe_day_start(equity, now=ts_dt)
                    pk_val = self._peak_store.observe_equity(
                        f"tier:{tid}", current_equity=equity, opening_balance=spec.starting_capital_usd, now=ts_dt
                    )
                    deployable = self._vaults[tid].deployable_equity(equity)
                    free_margin = max(Decimal("0"), equity - used_margin)

                    # 2. Evaluate optional entry or House-Money ADD signal per tier independently (outside write tx)
                    has_signal_quote = False
                    skip_reason: str | None = None
                    pending_entry: tuple[Any, ...] | None = None
                    entry_comm = Decimal("0")
                    if signal is not None and sig_side is not None:
                        sym = sig_sym
                        side = sig_side
                        if sym in quotes:
                            if sig_sl is None:
                                raise ContractError("signal.stop_price is required")
                            has_signal_quote = True
                            bid, ask = quotes[sym]
                            entry_px = ask if side is Side.BUY else bid
                            sl_p = sig_sl
                            tp_p = sig_tp
                            regime = sig_regime

                            existing_rows = conn.execute(
                                "SELECT * FROM tier_positions WHERE tier_id = ? AND symbol = ? AND side = ? ORDER BY leg_index ASC",
                                (tid, sym, side.value),
                            ).fetchall()
                            total_open_cnt = int(
                                conn.execute("SELECT COUNT(*) FROM tier_positions WHERE tier_id = ?", (tid,)).fetchone()[0]
                            )
                            is_add = len(existing_rows) > 0
                            req_kind = ActionKind.ADD if is_add else ActionKind.OPEN

                            if isinstance(raw_tier_dial, Mapping) and "risk_bps" in raw_tier_dial:
                                t_ai_enabled = bool(
                                    raw_tier_dial.get(
                                        "ai_discretion_enabled",
                                        dial_snap.get("ai_discretion_enabled", True) if isinstance(dial_snap, Mapping) else True,
                                    )
                                )
                                t_ai_ceiling = int(
                                    raw_tier_dial.get(
                                        "ai_discretion_ceiling_bps",
                                        dial_snap.get("ai_discretion_ceiling_bps", 100) if isinstance(dial_snap, Mapping) else 100,
                                    )
                                )
                                t_dd_live = (
                                    max(Decimal("0"), (pk_val - equity) / pk_val)
                                    if pk_val > Decimal("0")
                                    else Decimal("0")
                                )
                                t_q_pre = self._quotas[tid].snapshot(now=ts_dt, starting_equity=equity)
                                t_consec_live = max(0, int(t_q_pre.get("consecutive_losses", 0)))
                                tier_eff = resolve_dial_effective_params(
                                    int(raw_tier_dial["risk_bps"]),
                                    spec.starting_capital_usd,
                                    ai_discretion_enabled=t_ai_enabled,
                                    ai_discretion_ceiling_bps=t_ai_ceiling,
                                    regime=regime or self._last_signal_regime,
                                    consecutive_losses=t_consec_live,
                                    drawdown_pct=t_dd_live,
                                    valve_score=self._last_signal_valve_score,
                                )
                            tier_risk_pct_val: Decimal | None = None
                            tier_min_prob_val: Decimal | None = None
                            dhg_active = self._demo_high_growth
                            if dhg_active.enabled:
                                tier_risk_pct_val = (
                                    dhg_active.max_risk_pct
                                    if regime == "STRONG_TREND"
                                    else dhg_active.target_risk_pct
                                )
                                tier_min_prob_val = (
                                    max(MIN_CONSTITUTIONAL_VALVE_PROB, Decimal(str(tier_eff["min_signal_prob"])))
                                    if tier_eff is not None
                                    else MIN_CONSTITUTIONAL_VALVE_PROB
                                )
                                tier_max_trades = (
                                    max(3, int(tier_eff["max_open_trades"]) if tier_eff is not None else 5)
                                    if dhg_active.pyramiding_enabled
                                    else 1
                                )
                                tier_goal_usd = (equity * DEMO_HIGH_GROWTH_DAILY_GOAL_PCT).quantize(
                                    Decimal("0.01"), rounding=ROUND_HALF_UP
                                )
                                tier_soft_usd = (tier_goal_usd * Decimal("0.70")).quantize(
                                    Decimal("0.01"), rounding=ROUND_HALF_UP
                                )
                                tier_loss_brake_usd = (equity * DEMO_HIGH_GROWTH_DAILY_LOSS_BRAKE_PCT).quantize(
                                    Decimal("0.01"), rounding=ROUND_HALF_UP
                                )
                                q_snap = self._quotas[tid].snapshot(now=ts_dt, starting_equity=equity)
                                q_pnl = Decimal(str(q_snap["realized_net_pnl_usd"]))
                                q_consec = int(q_snap["consecutive_losses"])
                                q_max_consec = int(q_snap["max_consecutive_losses"])
                                dhg_cd_until = (
                                    self._tier_symbol_loss_cooldown_until.get((tid, sym))
                                    if (not is_add and dhg_active.post_loss_cooldown_seconds > 0)
                                    else None
                                )
                                if dhg_cd_until is not None and ts_dt < dhg_cd_until:
                                    rem_s = max(1, int((dhg_cd_until - ts_dt).total_seconds()))
                                    allowed_q = False
                                    q_reason = f"DEMO_POST_LOSS_COOLDOWN ({sym}: {rem_s}s remaining)"
                                    q_mult = Decimal("0")
                                elif q_pnl <= -tier_loss_brake_usd:
                                    allowed_q = False
                                    q_reason = f"DAILY_LOSS_BRAKE ({decimal_text(q_pnl)}<=-{decimal_text(tier_loss_brake_usd)})"
                                    q_mult = Decimal("0")
                                elif q_consec >= q_max_consec:
                                    allowed_q = False
                                    q_reason = QUOTA_STATUS_LOSS_TRIPPED
                                    q_mult = Decimal("0")
                                elif q_pnl >= tier_goal_usd and not (is_add and regime == "STRONG_TREND"):
                                    allowed_q = False
                                    q_reason = f"SESSION_GOAL_REACHED ({decimal_text(q_pnl)}>={decimal_text(tier_goal_usd)})"
                                    q_mult = Decimal("0")
                                elif total_open_cnt >= tier_max_trades:
                                    allowed_q = False
                                    q_reason = f"MAX_OPEN_TRADES_REACHED ({total_open_cnt}>={tier_max_trades})"
                                    q_mult = Decimal("0")
                                elif q_pnl >= tier_goal_usd and is_add and regime == "STRONG_TREND":
                                    allowed_q = True
                                    q_reason = None
                                    q_mult = Decimal("0.50")
                                elif q_pnl >= tier_soft_usd:
                                    allowed_q = True
                                    q_reason = None
                                    q_mult = Decimal("0.75")
                                else:
                                    allowed_q = True
                                    q_reason = None
                                    q_mult = Decimal("1.00")
                            elif tier_eff is not None:
                                tier_risk_pct_val = Decimal(str(tier_eff["risk_pct"]))
                                tier_min_prob_val = max(
                                    MIN_CONSTITUTIONAL_VALVE_PROB,
                                    Decimal(str(tier_eff["min_signal_prob"])),
                                )
                                tier_max_trades = int(tier_eff["max_open_trades"])
                                tier_goal_usd = Decimal(str(tier_eff["session_goal_usd"]))
                                tier_soft_usd = Decimal(str(tier_eff["soft_goal_usd"]))
                                tier_loss_brake_usd = Decimal(str(tier_eff["daily_loss_brake_usd"]))
                                q_snap = self._quotas[tid].snapshot(now=ts_dt, starting_equity=equity)
                                q_pnl = Decimal(str(q_snap["realized_net_pnl_usd"]))
                                q_consec = int(q_snap["consecutive_losses"])
                                q_max_consec = int(q_snap["max_consecutive_losses"])
                                if q_pnl <= -tier_loss_brake_usd:
                                    allowed_q = False
                                    q_reason = f"DAILY_LOSS_BRAKE ({decimal_text(q_pnl)}<=-{decimal_text(tier_loss_brake_usd)})"
                                    q_mult = Decimal("0")
                                elif q_consec >= q_max_consec:
                                    allowed_q = False
                                    q_reason = QUOTA_STATUS_LOSS_TRIPPED
                                    q_mult = Decimal("0")
                                elif q_pnl >= tier_goal_usd and not (is_add and regime == "STRONG_TREND"):
                                    allowed_q = False
                                    q_reason = f"SESSION_GOAL_REACHED ({decimal_text(q_pnl)}>={decimal_text(tier_goal_usd)})"
                                    q_mult = Decimal("0")
                                elif total_open_cnt >= tier_max_trades:
                                    allowed_q = False
                                    q_reason = f"MAX_OPEN_TRADES_REACHED ({total_open_cnt}>={tier_max_trades})"
                                    q_mult = Decimal("0")
                                elif q_pnl >= tier_goal_usd and is_add and regime == "STRONG_TREND":
                                    allowed_q = True
                                    q_reason = None
                                    q_mult = Decimal("0.50")
                                elif q_pnl >= tier_soft_usd:
                                    allowed_q = True
                                    q_reason = None
                                    q_mult = Decimal("0.50")
                                else:
                                    allowed_q = True
                                    q_reason = None
                                    q_mult = Decimal("1.00")
                            else:
                                allowed_q, q_reason, q_mult = self._quotas[tid].evaluate_new_risk(
                                    req_kind, now=ts_dt, starting_equity=equity
                                )
                                # Strong-trend runner override on ADD when daily profit quota is locked (never bypass loss circuit)
                                if not allowed_q and q_reason == QUOTA_STATUS_LOCKED and is_add and regime == "STRONG_TREND":
                                    q_snap = self._quotas[tid].snapshot(now=ts_dt, starting_equity=equity)
                                    q_pnl = Decimal(str(q_snap["realized_net_pnl_usd"]))
                                    q_max_loss = Decimal(str(q_snap["max_daily_loss_usd"]))
                                    q_consec = int(q_snap["consecutive_losses"])
                                    q_max_consec = int(q_snap["max_consecutive_losses"])
                                    if q_pnl <= -q_max_loss or q_consec >= q_max_consec:
                                        q_reason = QUOTA_STATUS_LOSS_TRIPPED
                                    else:
                                        allowed_q = True
                                        q_mult = Decimal("0.50")

                            corr_block_reason: str | None = None
                            if allowed_q and not is_add:
                                tier_open_rows = [
                                    {"symbol": str(r["symbol"]), "side": str(r["side"])}
                                    for r in conn.execute(
                                        "SELECT symbol, side FROM tier_positions WHERE tier_id = ?",
                                        (tid,),
                                    ).fetchall()
                                ]
                                corr_ok, corr_reason = evaluate_cross_market_offset_guard(
                                    candidate_symbol=sym,
                                    candidate_side=side,
                                    open_positions=tier_open_rows,
                                    price_history=self._mid_history,
                                    is_pyramid_add=False,
                                )
                                if not corr_ok:
                                    corr_block_reason = corr_reason

                            if not allowed_q:
                                if q_reason and q_reason.startswith("MAX_OPEN_TRADES_REACHED"):
                                    skip_reason = q_reason
                                else:
                                    skip_reason = f"DAILY_QUOTA ({q_reason})"
                            elif corr_block_reason is not None:
                                skip_reason = corr_block_reason
                            else:
                                qty, sz_err = self._compute_tier_quantity(
                                    tier_id=tid,
                                    symbol=sym,
                                    side=side,
                                    entry_price=entry_px,
                                    stop_loss=sl_p,
                                    deployable_equity=deployable,
                                    free_margin=free_margin,
                                    quotes=quotes,
                                    risk_multiplier=q_mult,
                                    tier_risk_pct=tier_risk_pct_val,
                                )
                                if qty is None:
                                    skip_reason = sz_err or "SIZING_SKIP"
                                else:
                                    if is_add:
                                        legs = [
                                            PyramidLegSnapshot(
                                                ticket=str(r["ticket"]),
                                                symbol=str(r["symbol"]),
                                                side=Side(str(r["side"])),
                                                units=Decimal(str(r["units"])),
                                                entry_price=Decimal(str(r["entry_price"])),
                                                stop_loss=Decimal(str(r["stop_loss"])),
                                                protection_stage=str(r["protection_stage"]),
                                            )
                                            for r in existing_rows
                                        ]
                                        _, q_ccy = Mt5MarginCalculator.split_symbol(sym)
                                        conv = self._calc.conversion_rate(q_ccy, quotes)
                                        conv_q = conv.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP).normalize()
                                        if conv_q <= Decimal("0"):
                                            conv_q = Decimal("0.000001")
                                        pyr = evaluate_house_money_pyramid_leg(
                                            symbol=sym,
                                            side=side,
                                            regime=regime,
                                            existing_legs=legs,
                                            new_leg_entry=entry_px,
                                            new_leg_stop=sl_p,
                                            new_leg_units=qty,
                                            quote_to_usd=conv_q,
                                        )
                                        if not pyr.allowed:
                                            skip_reason = f"PYRAMID_BLOCKED ({pyr.reason})"
                                    if skip_reason is None:
                                        inv_json = json.dumps([
                                            {
                                                "ticket": str(r["ticket"]),
                                                "symbol": str(r["symbol"]),
                                                "volume": str(r["units"]),
                                            }
                                            for r in conn.execute("SELECT * FROM tier_positions WHERE tier_id = ?", (tid,)).fetchall()
                                        ])
                                        t_view = {
                                            "balance": decimal_text(balance),
                                            "equity": decimal_text(equity),
                                            "available_margin": decimal_text(free_margin),
                                            "position_inventory": inv_json,
                                            "peak_equity": decimal_text(pk_val),
                                            "max_drawdown_pct": decimal_text(
                                                self._demo_high_growth.effective_drawdown_ceiling_pct()
                                            ),
                                            "current_market": [
                                                {
                                                    "instrument_id": sym,
                                                    "bid": decimal_text(bid),
                                                    "ask": decimal_text(ask),
                                                }
                                            ],
                                        }
                                        uid = uuid.uuid4().hex[:10]
                                        act_ref = f"tier-{tid.lower()}-{uid}"
                                        req_id = f"tr-{uid}"
                                        opp_set_id = f"topp-{uid}"
                                        dec_id = f"tdec-{uid}"
                                        t_scope = RunScope(
                                            account_id=tid,
                                            run_id="parallel-tiers",
                                            epoch=1,
                                            build_id="phase6-parallel-tiers-v1",
                                            policy_id="barbell-1pct-valve-v1",
                                            scenario_id="shadow-5tier",
                                            adapter_id="parallel-tier-mirror",
                                        )
                                        st_ref = StateReference(
                                            state_id=f"tstate-{uid}",
                                            scope=t_scope,
                                            version=1,
                                            observed_at=ts_dt,
                                            valid_until=ts_dt + timedelta(seconds=30),
                                            venue_sequence=1,
                                        )
                                        parent_tkt = str(existing_rows[0]["ticket"]) if is_add else None
                                        intent = ActionIntent(
                                            intent_id=f"ti-{uid}",
                                            scope=t_scope,
                                            decision_id=dec_id,
                                            opportunity_id=opp_set_id,
                                            action_ref=act_ref,
                                            source_state=st_ref,
                                            kind=req_kind,
                                            instrument_id=sym,
                                            origin=DecisionOrigin.ACTUAL_MODEL,
                                            created_at=ts_dt,
                                            expires_at=st_ref.valid_until,
                                            quantity=qty,
                                            side=side,
                                            limit_price=None,
                                            stop_price=sl_p,
                                            take_profit_price=tp_p,
                                            target_id=parent_tkt,
                                            target_version=1 if parent_tkt is not None else None,
                                        )
                                        prop = _TierProposal(
                                            scope=t_scope,
                                            state_ref=st_ref,
                                            req_id=req_id,
                                            opp_set_id=opp_set_id,
                                            dec_id=dec_id,
                                            intent=intent,
                                            view_facts={"new_risk": True, "management": True, "equity": decimal_text(equity), "peak_equity": decimal_text(pk_val), "bid": decimal_text(bid), "ask": decimal_text(ask)},
                                            observed_at=ts_dt,
                                            reason=f"ID=0{act_ref} {regime}",
                                        )
                                        dec = self._valve.evaluate(prop, current_view=t_view, now=ts_dt)
                                        if not dec.admitted:
                                            refusal_detail = (
                                                ",".join(dec.hard_veto_reasons)
                                                if dec.hard_veto_reasons
                                                else f"{dec.valve_mode}:mlp_score={dec.mlp_score:.6f}<{dec.threshold:.6f}"
                                            )
                                            skip_reason = f"VALVE_REFUSED ({refusal_detail})"
                                        elif (
                                            tier_min_prob_val is not None
                                            and Decimal(f"{dec.mlp_score:.8f}") < tier_min_prob_val
                                        ):
                                            skip_reason = (
                                                f"DIAL_MIN_SIGNAL_PROB (mlp_score={dec.mlp_score:.4f}<{tier_min_prob_val})"
                                            )
                                        else:
                                            entry_comm = self._entry_commission(sym, qty)
                                            new_ticket = f"{tid}-{uuid.uuid4().hex[:10]}"
                                            pending_entry = (
                                                new_ticket,
                                                tid,
                                                sym,
                                                side.value,
                                                decimal_text(qty),
                                                decimal_text(entry_px),
                                                decimal_text(sl_p),
                                                None if tp_p is None else decimal_text(tp_p),
                                                decimal_text(sl_p),
                                                decimal_text(entry_px),
                                                decimal_text(entry_comm),
                                                len(existing_rows) + 1,
                                                ts,
                                            )

                    # Tx 2: Atomic entry insert + skip reason + MTM account update + equity history
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        if pending_entry is not None:
                            balance = balance - entry_comm
                            equity = balance + open_unrealized
                            conn.execute(
                                """
                                INSERT INTO tier_positions(
                                    ticket, tier_id, symbol, side, units, entry_price,
                                    stop_loss, take_profit, initial_stop_loss, peak_favorable, protection_stage,
                                    entry_commission_usd, leg_index, opened_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'INITIAL_SL', ?, ?, ?)
                                """,
                                pending_entry,
                            )
                        if has_signal_quote:
                            conn.execute("UPDATE tier_accounts SET last_skip_reason = ? WHERE tier_id = ?", (skip_reason, tid))

                        with localcontext() as ctx:
                            ctx.prec = 40
                            growth_pct = (((equity - spec.starting_capital_usd) / spec.starting_capital_usd) * Decimal("100")).quantize(
                                Decimal("0.01"), rounding=ROUND_HALF_UP
                            )
                        conn.execute(
                            "UPDATE tier_accounts SET balance_usd = ?, equity_usd = ?, peak_equity_usd = ?, updated_at = ? WHERE tier_id = ?",
                            (decimal_text(balance), decimal_text(equity), decimal_text(pk_val), ts, tid),
                        )
                        last_h = conn.execute(
                            "SELECT equity_usd FROM tier_equity_history WHERE tier_id = ? ORDER BY seq DESC LIMIT 1",
                            (tid,),
                        ).fetchone()
                        if last_h is None or Decimal(str(last_h["equity_usd"])) != equity:
                            conn.execute(
                                "INSERT INTO tier_equity_history(tier_id, observed_at, equity_usd, growth_pct) VALUES (?, ?, ?, ?)",
                                (tid, ts, decimal_text(equity), decimal_text(growth_pct)),
                            )
                        if pending_closes:
                            tiers_post_close_check.append(tid)
                        conn.execute("COMMIT")
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
            for tid_chk in tiers_post_close_check:
                self._maybe_auto_replenish_tier_unlocked(tid_chk, now=ts_dt, trigger="POST_CLOSE")
        return self.snapshot()

    def _replenish_single_tier_unlocked(
        self,
        tid: str,
        *,
        min_ratio_threshold: Decimal | None,
        trigger: str,
        reason: str,
        now: datetime,
        refuse_if_open: bool,
    ) -> dict[str, Any]:
        spec_map = {s.tier_id: s for s in self._specs}
        if tid not in spec_map:
            raise ContractError(f"Unknown tier_id: {tid!r}")
        ts_dt = utc_time(now, "now")
        ts = _iso(ts_dt)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                open_cnt = int(
                    conn.execute("SELECT COUNT(*) FROM tier_positions WHERE tier_id = ?", (tid,)).fetchone()[0]
                )
                if open_cnt > 0:
                    conn.execute("ROLLBACK")
                    if refuse_if_open:
                        raise ContractError(
                            f"{DEMO_REPLENISH_REQUIRES_FLAT_POSITIONS}: {tid} has {open_cnt} open positions"
                        )
                    return {
                        "tier_id": tid,
                        "replenished": False,
                        "skipped_reason": "OPEN_POSITIONS",
                        "added_usd": "0.00",
                    }
                acct = conn.execute("SELECT * FROM tier_accounts WHERE tier_id = ?", (tid,)).fetchone()
                if acct is None:
                    conn.execute("ROLLBACK")
                    raise ContractError(f"Missing tier account: {tid}")
                start_v = Decimal(str(acct["starting_capital_usd"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                cur_bal = Decimal(str(acct["balance_usd"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                if min_ratio_threshold is not None:
                    floor_usd = (start_v * min_ratio_threshold).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    if cur_bal > floor_usd:
                        conn.execute("ROLLBACK")
                        return {
                            "tier_id": tid,
                            "replenished": False,
                            "skipped_reason": "ABOVE_FLOOR",
                            "added_usd": "0.00",
                        }
                if cur_bal >= start_v:
                    conn.execute("ROLLBACK")
                    return {
                        "tier_id": tid,
                        "replenished": False,
                        "skipped_reason": "AT_OR_ABOVE_STARTING_CAPITAL",
                        "added_usd": "0.00",
                    }
                added = (start_v - cur_bal).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                prev_cnt = int(acct["replenishment_count"]) if "replenishment_count" in acct.keys() else 0
                prev_cum = (
                    Decimal(str(acct["cumulative_replenished_usd"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    if "cumulative_replenished_usd" in acct.keys()
                    else Decimal("0.00")
                )
                new_cnt = prev_cnt + 1
                new_cum = (prev_cum + added).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                start_txt = decimal_text(start_v)
                conn.execute(
                    """
                    UPDATE tier_accounts
                    SET balance_usd = ?,
                        equity_usd = ?,
                        peak_equity_usd = ?,
                        last_skip_reason = NULL,
                        replenishment_count = ?,
                        cumulative_replenished_usd = ?,
                        last_replenished_at = ?,
                        updated_at = ?
                    WHERE tier_id = ?
                    """,
                    (start_txt, start_txt, start_txt, new_cnt, f"{new_cum:.2f}", ts, ts, tid),
                )
                conn.execute(
                    "INSERT INTO tier_equity_history(tier_id, observed_at, equity_usd, growth_pct) VALUES (?, ?, ?, '0.00')",
                    (tid, ts, start_txt),
                )
                prev_row = conn.execute(
                    "SELECT event_sha256 FROM tier_replenishment_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_sha = str(prev_row[0]) if prev_row is not None else _GENESIS_REPLENISH_SHA256
                ev_payload = {
                    "tier_id": tid,
                    "event_kind": "DEMO_CAPITAL_REPLENISHED",
                    "trigger": trigger,
                    "reason": reason,
                    "previous_balance_usd": f"{cur_bal:.2f}",
                    "added_usd": f"{added:.2f}",
                    "new_balance_usd": start_txt,
                    "new_peak_equity_usd": start_txt,
                    "observed_at": ts,
                    "prev_sha256": prev_sha,
                }
                ev_sha = sha256(canonical_bytes(ev_payload)).hexdigest()
                conn.execute(
                    """
                    INSERT INTO tier_replenishment_events (
                        tier_id, event_kind, trigger_source, reason, previous_balance_usd,
                        added_usd, new_balance_usd, new_peak_equity_usd, observed_at, prev_sha256, event_sha256
                    ) VALUES (?, 'DEMO_CAPITAL_REPLENISHED', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (tid, trigger, reason, f"{cur_bal:.2f}", f"{added:.2f}", start_txt, start_txt, ts, prev_sha, ev_sha),
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        scope = f"tier:{tid}"
        req_id = f"DEMO_CAPITAL_REPLENISHED_{tid}_{new_cnt}_{uuid.uuid4().hex[:8]}"
        self._peak_store.rearm_after_drawdown(
            scope,
            new_peak_equity=start_v,
            owner_verifier=_DemoAutoReplenishRearmVerifier(
                expected_scope_id=scope,
                expected_request_id=req_id,
                expected_peak=start_v,
                execution_mode="DEMO",
                live_trading_armed=False,
            ),
            owner_request_id=req_id,
            now=ts_dt,
        )
        q_store = self._quotas.get(tid)
        if q_store is not None:
            q_snap = q_store.peek_snapshot(now=ts_dt)
            if str(q_snap.get("status", "")) in (QUOTA_STATUS_LOCKED, QUOTA_STATUS_LOSS_TRIPPED):
                tok = f"demo-replenish-{uuid.uuid4().hex[:12]}"
                q_store.unlock_session(
                    owner_request_id=req_id,
                    reason=f"DEMO_CAPITAL_REPLENISHED:{trigger}:{reason}",
                    recovery_verifier=lambda sc, rid, tkn, _n: (
                        sc == "UNLOCK_QUOTA_SESSION" and rid == req_id and tkn == tok
                    ),
                    recovery_token=tok,
                    now=ts_dt,
                )
        for c_key in [k for k in self._tier_symbol_loss_cooldown_until if k[0] == tid]:
            self._tier_symbol_loss_cooldown_until.pop(c_key, None)
        if self._telegram_notifier is not None:
            try:
                self._telegram_notifier.notify_demo_replenished(
                    lane=tid,
                    previous_balance_usd=f"{cur_bal:.2f}",
                    added_usd=f"{added:.2f}",
                    new_balance_usd=start_txt,
                    trigger=trigger,
                )
            except Exception as exc_tg:
                logger.warning("Telegram tier replenish notification skipped for %s: %s", tid, type(exc_tg).__name__)
        return {
            "tier_id": tid,
            "replenished": True,
            "previous_balance_usd": f"{cur_bal:.2f}",
            "added_usd": f"{added:.2f}",
            "new_balance_usd": start_txt,
            "replenishment_count": new_cnt,
            "cumulative_replenished_usd": f"{new_cum:.2f}",
            "trigger": trigger,
            "reason": reason,
            "observed_at": ts,
        }

    def _maybe_auto_replenish_tier_unlocked(
        self,
        tid: str,
        *,
        now: datetime,
        trigger: str,
    ) -> dict[str, Any] | None:
        if not self._auto_replenish_enabled:
            return None
        res = self._replenish_single_tier_unlocked(
            tid,
            min_ratio_threshold=self._auto_replenish_floor_ratio,
            trigger=trigger,
            reason=f"AUTO_FLOOR_{self._auto_replenish_floor_pct:.2f}PCT",
            now=now,
            refuse_if_open=False,
        )
        return res if res.get("replenished") else None

    def _auto_replenish_eligible_tiers_unlocked(
        self,
        *,
        now: datetime,
        trigger: str,
    ) -> list[dict[str, Any]]:
        if not self._auto_replenish_enabled:
            return []
        events: list[dict[str, Any]] = []
        for spec in self._specs:
            ev = self._maybe_auto_replenish_tier_unlocked(spec.tier_id, now=now, trigger=trigger)
            if ev is not None:
                events.append(ev)
        return events

    def replenish_tier(
        self,
        tier_id: str,
        *,
        reason: str = "OWNER_REPLENISH_TIER",
        execution_mode: str = "DEMO",
        live_trading_armed: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Replenish a flat DEMO parallel tier back to its exact starting capital without deleting trades."""
        if type(live_trading_armed) is not bool:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        if str(execution_mode or "").strip().upper() != "DEMO" or live_trading_armed:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        ts_dt = self._clock() if now is None else utc_time(now, "now")
        clean_reason = reason.strip() if isinstance(reason, str) and reason.strip() else "OWNER_REPLENISH_TIER"
        with self._lock:
            return self._replenish_single_tier_unlocked(
                str(tier_id).strip(),
                min_ratio_threshold=None,
                trigger="OWNER_REPLENISH",
                reason=clean_reason,
                now=ts_dt,
                refuse_if_open=True,
            )

    def replenish_all_tiers(
        self,
        *,
        reason: str = "OWNER_REPLENISH_ALL_TIERS",
        execution_mode: str = "DEMO",
        live_trading_armed: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Replenish every flat DEMO tier below 100% of starting capital while preserving trade history."""
        if type(live_trading_armed) is not bool:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        if str(execution_mode or "").strip().upper() != "DEMO" or live_trading_armed:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        ts_dt = self._clock() if now is None else utc_time(now, "now")
        clean_reason = reason.strip() if isinstance(reason, str) and reason.strip() else "OWNER_REPLENISH_ALL_TIERS"
        with self._lock:
            results: list[dict[str, Any]] = []
            skipped_open: list[str] = []
            for spec in self._specs:
                r = self._replenish_single_tier_unlocked(
                    spec.tier_id,
                    min_ratio_threshold=None,
                    trigger="OWNER_REPLENISH_ALL",
                    reason=clean_reason,
                    now=ts_dt,
                    refuse_if_open=False,
                )
                results.append(r)
                if r.get("skipped_reason") == "OPEN_POSITIONS":
                    skipped_open.append(spec.tier_id)
            return {
                "ok": True,
                "results": results,
                "replenished_count": sum(1 for x in results if x.get("replenished")),
                "skipped_open_tiers": skipped_open,
                "observed_at": _iso(ts_dt),
            }

    def set_auto_replenish(
        self,
        *,
        enabled: bool,
        floor_pct: Decimal | str | int | None = None,
        reason: str = "OWNER_SET_AUTO_REPLENISH",
        execution_mode: str = "DEMO",
        live_trading_armed: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Configure DEMO-only automatic tier replenishment floor and trigger immediate check if enabled."""
        if type(enabled) is not bool:
            raise ContractError("enabled must be a strict bool")
        if type(live_trading_armed) is not bool:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        if str(execution_mode or "").strip().upper() != "DEMO" or live_trading_armed:
            raise ContractError(DEMO_AUTO_REPLENISH_FORBIDDEN_IN_LIVE_MODE)
        ts_dt = self._clock() if now is None else utc_time(now, "now")
        ts = _iso(ts_dt)
        clean_reason = reason.strip() if isinstance(reason, str) and reason.strip() else "OWNER_SET_AUTO_REPLENISH"
        with self._lock:
            if floor_pct is not None:
                ratio, pct = _normalize_tier_floor_ratio(floor_pct)
                self._auto_replenish_floor_ratio = ratio
                self._auto_replenish_floor_pct = pct
            self._auto_replenish_enabled = enabled
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "UPDATE tier_engine_meta SET auto_replenish_enabled = ?, auto_replenish_floor_pct = ?, updated_at = ? WHERE id = 1",
                        (
                            1 if self._auto_replenish_enabled else 0,
                            f"{self._auto_replenish_floor_pct:.2f}",
                            ts,
                        ),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
            repl_events = (
                self._auto_replenish_eligible_tiers_unlocked(now=ts_dt, trigger="CONFIG_UPDATE")
                if enabled
                else []
            )
            return {
                "ok": True,
                "auto_replenish_enabled": bool(self._auto_replenish_enabled),
                "auto_replenish_floor_pct": f"{self._auto_replenish_floor_pct:.2f}",
                "replenished_events": repl_events,
                "reason": clean_reason,
                "observed_at": ts,
            }

    def tier_dial_contexts(self, *, now: datetime | None = None) -> dict[str, dict[str, Any]]:
        """Read-only per-tier drawdown and consecutive-loss context for live AggressionDial snapshots."""
        ts_dt = self._clock() if now is None else now
        out_ctx: dict[str, dict[str, Any]] = {}
        with self._lock, closing(self._connect_ro()) as conn:
            for spec in self._specs:
                tid = spec.tier_id
                acct = conn.execute(
                    "SELECT equity_usd, peak_equity_usd FROM tier_accounts WHERE tier_id = ?",
                    (tid,),
                ).fetchone()
                if acct is None:
                    continue
                eq_v = Decimal(str(acct["equity_usd"]))
                pk_v = Decimal(str(acct["peak_equity_usd"]))
                dd_v = max(Decimal("0"), (pk_v - eq_v) / pk_v) if pk_v > Decimal("0") else Decimal("0")
                q_s = self._quotas[tid].snapshot(now=ts_dt, starting_equity=eq_v)
                out_ctx[tid] = {
                    "drawdown_pct": dd_v.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP),
                    "consecutive_losses": max(0, int(q_s.get("consecutive_losses", 0))),
                }
        return out_ctx

    def snapshot(self) -> dict[str, Any]:
        dial_store = self.aggression_dial
        dial_snap = dial_store.snapshot() if dial_store is not None else None
        dial_tiers_map = (
            dial_snap.get("tiers_by_id", {})
            if isinstance(dial_snap, Mapping) and isinstance(dial_snap.get("tiers_by_id"), Mapping)
            else {}
        )
        with self._lock, closing(self._connect_ro()) as conn:
            meta_row = conn.execute(
                "SELECT auto_replenish_enabled, auto_replenish_floor_pct FROM tier_engine_meta WHERE id = 1"
            ).fetchone()
            snap_auto_enabled = (
                bool(int(meta_row["auto_replenish_enabled"]))
                if meta_row is not None
                else self._auto_replenish_enabled
            )
            if meta_row is not None:
                snap_floor_ratio, snap_floor_pct = _normalize_tier_floor_ratio(
                    meta_row["auto_replenish_floor_pct"]
                )
            else:
                snap_floor_ratio, snap_floor_pct = (
                    self._auto_replenish_floor_ratio,
                    self._auto_replenish_floor_pct,
                )
            total_repl_cnt = 0
            total_repl_cum = Decimal("0.00")
            tiers: list[dict[str, Any]] = []
            series: dict[str, list[dict[str, Any]]] = {}
            for spec in self._specs:
                tid = spec.tier_id
                acct = conn.execute("SELECT * FROM tier_accounts WHERE tier_id = ?", (tid,)).fetchone()
                if acct is None:
                    continue
                start_v = Decimal(str(acct["starting_capital_usd"]))
                eq_v = Decimal(str(acct["equity_usd"]))
                pk_v = Decimal(str(acct["peak_equity_usd"]))
                with localcontext() as ctx:
                    ctx.prec = 40
                    growth_pct = (((eq_v - start_v) / start_v) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    dd_pct = (
                        (((pk_v - eq_v) / pk_v) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                        if pk_v > Decimal("0") and eq_v < pk_v
                        else Decimal("0.00")
                    )
                wins = int(acct["win_count"])
                losses = int(acct["loss_count"])
                total_tr = wins + losses
                win_rate = (
                    (Decimal(wins) / Decimal(total_tr) * Decimal("100")).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
                    if total_tr > 0
                    else Decimal("0.0")
                )
                gp = Decimal(str(acct["gross_profit_usd"]))
                gl = Decimal(str(acct["gross_loss_usd"]))
                pf = "INF" if (gp > 0 and gl == 0) else (decimal_text((gp / gl).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)) if gl > 0 else "0.00")
                open_cnt = int(conn.execute("SELECT COUNT(*) FROM tier_positions WHERE tier_id = ?", (tid,)).fetchone()[0])
                v_snap = self._vaults[tid].snapshot()
                tier_item: dict[str, Any] = {
                    "tier_id": tid,
                    "label": str(acct["label"]),
                    "color_class": str(acct["color_class"]),
                    "starting_capital_usd": decimal_text(start_v),
                    "balance_usd": str(acct["balance_usd"]),
                    "equity_usd": decimal_text(eq_v),
                    "net_gain_usd": decimal_text((eq_v - start_v).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                    "growth_pct": decimal_text(growth_pct),
                    "peak_equity_usd": decimal_text(pk_v),
                    "drawdown_pct": decimal_text(dd_pct),
                    "open_positions": open_cnt,
                    "closed_trades": total_tr,
                    "win_count": wins,
                    "loss_count": losses,
                    "win_rate_pct": decimal_text(win_rate),
                    "profit_factor": pf,
                    "bank_sweep_reserved_usd": v_snap["bank_sweep_reserved_usd"],
                    "retained_trading_usd": v_snap["retained_trading_usd"],
                    "replenishment_count": (
                        int(acct["replenishment_count"])
                        if "replenishment_count" in acct.keys()
                        else 0
                    ),
                    "cumulative_replenished_usd": (
                        str(acct["cumulative_replenished_usd"])
                        if "cumulative_replenished_usd" in acct.keys()
                        else "0.00"
                    ),
                    "last_replenished_at": (
                        acct["last_replenished_at"]
                        if "last_replenished_at" in acct.keys()
                        else None
                    ),
                    "auto_replenish_floor_usd": decimal_text(
                        (start_v * snap_floor_ratio).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    ),
                    "last_skip_reason": acct["last_skip_reason"],
                    "updated_at": str(acct["updated_at"]),
                }
                total_repl_cnt += int(tier_item["replenishment_count"])
                total_repl_cum += Decimal(str(tier_item["cumulative_replenished_usd"]))
                raw_td = dial_tiers_map.get(tid)
                if isinstance(raw_td, Mapping) and "risk_bps" in raw_td:
                    td_ai_en = bool(
                        raw_td.get(
                            "ai_discretion_enabled",
                            dial_snap.get("ai_discretion_enabled", True) if isinstance(dial_snap, Mapping) else True,
                        )
                    )
                    td_ai_ceil = int(
                        raw_td.get(
                            "ai_discretion_ceiling_bps",
                            dial_snap.get("ai_discretion_ceiling_bps", 100) if isinstance(dial_snap, Mapping) else 100,
                        )
                    )
                    td_dd = (
                        max(Decimal("0"), (pk_v - eq_v) / pk_v)
                        if pk_v > Decimal("0")
                        else Decimal("0")
                    )
                    td_q_snap = self._quotas[tid].snapshot(now=self._clock(), starting_equity=eq_v)
                    td_consec = max(0, int(td_q_snap.get("consecutive_losses", 0)))
                    td_eff = resolve_dial_effective_params(
                        int(raw_td["risk_bps"]),
                        start_v,
                        ai_discretion_enabled=td_ai_en,
                        ai_discretion_ceiling_bps=td_ai_ceil,
                        regime=self._last_signal_regime,
                        consecutive_losses=td_consec,
                        drawdown_pct=td_dd,
                        valve_score=self._last_signal_valve_score,
                    )
                    tier_item["aggression_dial"] = {
                        "tier_id": tid,
                        "risk_bps": int(td_eff["requested_risk_bps"]),
                        "risk_pct": str(td_eff["risk_pct"]),
                        "ai_discretion_enabled": td_ai_en,
                        "ai_discretion_ceiling_bps": td_ai_ceil,
                        "ai_discretion_reason": str(td_eff["ai_discretion_reason"]),
                        "ai_discretion_shifted": bool(td_eff["ai_discretion_shifted"]),
                        "ai_discretion_direction": str(td_eff["ai_discretion_direction"]),
                        "effective_risk_bps": int(td_eff["effective_risk_bps"]),
                        "effective_risk_pct": str(td_eff["effective_risk_pct"]),
                        "effective_label": str(td_eff["effective_label"]),
                        "css_class": str(td_eff["css_class"]),
                        "risk_per_trade_usd": str(td_eff["risk_per_trade_usd"]),
                        "max_open_trades": int(td_eff["max_open_trades"]),
                        "min_signal_prob": str(td_eff["min_signal_prob"]),
                        "session_goal_usd": str(td_eff["session_goal_usd"]),
                        "soft_goal_usd": str(td_eff["soft_goal_usd"]),
                        "daily_loss_brake_usd": str(td_eff["daily_loss_brake_usd"]),
                        "updated_at": str(raw_td["updated_at"]),
                        "updated_by": str(raw_td["updated_by"]),
                    }
                tiers.append(tier_item)
                hist_rows = conn.execute(
                    "SELECT observed_at, equity_usd, growth_pct FROM tier_equity_history WHERE tier_id = ? ORDER BY seq ASC",
                    (tid,),
                ).fetchall()
                series[tid] = [
                    {
                        "observed_at": str(r["observed_at"]),
                        "equity_usd": str(r["equity_usd"]),
                        "growth_pct": str(r["growth_pct"]),
                    }
                    for r in hist_rows[-120:]
                ]
            out: dict[str, Any] = {
                "schema": "cas-forex.parallel-tiers/1",
                "tier_count": len(tiers),
                "auto_replenish_enabled": snap_auto_enabled,
                "auto_replenish_floor_pct": f"{snap_floor_pct:.2f}",
                "total_replenishment_count": total_repl_cnt,
                "total_cumulative_replenished_usd": f"{total_repl_cum:.2f}",
                "tiers": tiers,
                "growth_series": series,
            }
            if isinstance(dial_snap, Mapping):
                out["aggression_dial"] = {
                    "schema": str(dial_snap["schema"]),
                    "scope_id": str(dial_snap["scope_id"]),
                    "master_risk_bps": int(dial_snap["master_risk_bps"]),
                    "master_risk_pct": str(dial_snap["master_risk_pct"]),
                    "ai_discretion_enabled": bool(dial_snap["ai_discretion_enabled"]),
                    "ai_discretion_ceiling_bps": int(dial_snap["ai_discretion_ceiling_bps"]),
                    "audit_count": int(dial_snap["audit_count"]),
                    "audit_head_sha256": str(dial_snap["audit_head_sha256"]),
                }
            return out
