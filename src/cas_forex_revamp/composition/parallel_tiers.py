"""Section B.5: 5-Tier Parallel Account Engine ($300, $1,000, $3,000, $6,000, $300,000).

All 5 isolated account tiers subscribe to the single live 50ms market stream and single
AI decision signal (zero extra AI API cost), enforcing exact bid/ask fills, realistic ECN
commissions, 1:500 FX / 1:200 Index margin checks, ROUND_FLOOR 0.01 lot sizing with honest
LOT_FLOOR_RISK_EXCEEDED vetoes when 0.01 lot exceeds 1.00% stop risk, independent
ForexMetaValveGate admission, PeakEquityStore drawdown protection, DailyQuotaGovernanceStore,
50%/50% ProfitSweepVault accumulation, and House-Money trend pyramiding.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_UP, localcontext
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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(db_path, Path):
            db_path = Path(str(db_path))
        if not isinstance(valve_gate, ForexMetaValveGate):
            raise ContractError("valve_gate must be a ForexMetaValveGate")
        if aggression_dial is not None and not isinstance(aggression_dial, AggressionDialStore):
            raise ContractError("aggression_dial must be an AggressionDialStore or None")
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
        self._lock = RLock()
        self._regime = TrendRegimeDetector()
        self._peak_store = PeakEquityStore(db_path)
        self._aggression_dial: AggressionDialStore | None = aggression_dial
        self._quotas: dict[str, DailyQuotaGovernanceStore] = {}
        self._vaults: dict[str, ProfitSweepVault] = {}
        self._init_db(sweep_ratio=sweep_ratio)

    @property
    def aggression_dial(self) -> AggressionDialStore | None:
        with self._lock:
            return self._aggression_dial

    def bind_aggression_dial(self, store: AggressionDialStore | None) -> None:
        if store is not None and not isinstance(store, AggressionDialStore):
            raise ContractError("aggression_dial must be an AggressionDialStore or None")
        with self._lock:
            self._aggression_dial = store

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

        dial_store = self.aggression_dial
        dial_snap = dial_store.snapshot() if dial_store is not None else None
        dial_tiers_map = (
            dial_snap.get("tiers_by_id", {})
            if isinstance(dial_snap, Mapping) and isinstance(dial_snap.get("tiers_by_id"), Mapping)
            else {}
        )

        with self._lock, closing(self._connect()) as conn:
            for spec in self._specs:
                tid = spec.tier_id
                raw_tier_dial = dial_tiers_map.get(tid)
                tier_eff: dict[str, Any] | None = (
                    resolve_dial_effective_params(
                        int(raw_tier_dial["risk_bps"]),
                        spec.starting_capital_usd,
                        ai_discretion_enabled=False,
                    )
                    if isinstance(raw_tier_dial, Mapping) and "risk_bps" in raw_tier_dial
                    else None
                )
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
                            pending_closes.append((f"{tid}:{pos['ticket']}", sym, str(pos["ticket"]), net_pnl, balance))
                            acct = conn.execute("SELECT * FROM tier_accounts WHERE tier_id = ?", (tid,)).fetchone()
                            continue

                        # Fast protection: Snap-to-Breakeven & Monotonic Trailing Stop
                        prev_peak = Decimal(str(pos["peak_favorable"]))
                        cur_px = bid if side is Side.BUY else ask
                        peak = max(prev_peak, cur_px) if side is Side.BUY else min(prev_peak, cur_px)
                        excursion = (peak - entry_p) if side is Side.BUY else (entry_p - peak)
                        t_sz = _tick_size(sym)
                        be_trig = Decimal("10.00") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("120")
                        be_off = Decimal("1.50") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("10")
                        trail_act = Decimal("22.00") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("220")
                        trail_dist = Decimal("14.00") if sym in INDEX_INSTRUMENTS else t_sz * Decimal("140")

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

                        tier_risk_pct_val: Decimal | None = None
                        tier_min_prob_val: Decimal | None = None
                        if tier_eff is not None:
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

                        if not allowed_q:
                            if q_reason and q_reason.startswith("MAX_OPEN_TRADES_REACHED"):
                                skip_reason = q_reason
                            else:
                                skip_reason = f"DAILY_QUOTA ({q_reason})"
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
                                        "max_drawdown_pct": decimal_text(DEFAULT_MAX_DRAWDOWN_PCT),
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
                                stop_loss, take_profit, peak_favorable, protection_stage,
                                entry_commission_usd, leg_index, opened_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'INITIAL_SL', ?, ?, ?)
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
                    conn.execute("COMMIT")
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        dial_store = self.aggression_dial
        dial_snap = dial_store.snapshot() if dial_store is not None else None
        dial_tiers_map = (
            dial_snap.get("tiers_by_id", {})
            if isinstance(dial_snap, Mapping) and isinstance(dial_snap.get("tiers_by_id"), Mapping)
            else {}
        )
        with self._lock, closing(self._connect_ro()) as conn:
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
                    "last_skip_reason": acct["last_skip_reason"],
                    "updated_at": str(acct["updated_at"]),
                }
                raw_td = dial_tiers_map.get(tid)
                if isinstance(raw_td, Mapping) and "risk_bps" in raw_td:
                    td_eff = resolve_dial_effective_params(
                        int(raw_td["risk_bps"]),
                        start_v,
                        ai_discretion_enabled=False,
                    )
                    tier_item["aggression_dial"] = {
                        "tier_id": tid,
                        "risk_bps": int(td_eff["requested_risk_bps"]),
                        "risk_pct": str(td_eff["risk_pct"]),
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
