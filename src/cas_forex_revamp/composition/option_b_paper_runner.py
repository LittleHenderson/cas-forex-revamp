"""Option B $5,000.00 US-Regulated CME Micro Futures Paper Demo Runner.

Runs a strictly paper-only ($0.00 real money, 0 Tradovate credentials, 0 external
network calls) $5,000.00 Micro Futures simulation (MNQ, MYM, MES, MGC) driven by
the live NAS100, US30, SPX500, and XAUUSD prices already observed by the 24/7
cockpit server.

Every simulated entry passes through :class:`TradovateMicroFuturesVenue` with
mandatory :class:`ForexMetaValveGate` (161 weights, 0.55 cutoff) and immutable
constitutional walls (<= 1.00% stop-loss risk, <= 10.00% hard drawdown brake).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any

from cas_forex_revamp.composition.state_store import open_verified_sqlite_connection
from cas_forex_revamp.contracts import ContractError, decimal_text
from cas_forex_revamp.venue.dual_shield_router import (
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    compute_drawdown_pct,
)
from cas_forex_revamp.contracts.primitives import utc_time
from cas_forex_revamp.futures.micro_futures_specs import (
    CME_MICRO_FUTURES_SPECS,
    MicroFuturesError,
    resolve_front_month_contract,
    translate_cas_symbol_to_micro_root,
    translate_micro_root_to_cas_symbol,
)
from cas_forex_revamp.futures.tradovate_venue import (
    DEFAULT_PAPER_STARTING_EQUITY_USD,
    TRADOVATE_MODE_DEMO,
    TRADOVATE_SUPPORTED_CONTRACTS,
    TradovateLiveLockError,
    TradovateMicroFuturesPaperEmulator,
    TradovateMicroFuturesVenue,
    TradovateOrderReceipt,
    TradovateVenueError,
)
from cas_forex_revamp.valve import ForexMetaValveGate

OPTION_B_DEMO_SCHEMA = "cas-forex.option-b-demo/1"
OPTION_B_DEMO_ACCOUNT_ID = "OPTION-B-PAPER-5K"
OPTION_B_DEFAULT_STARTING_EQUITY_USD = DEFAULT_PAPER_STARTING_EQUITY_USD
OPTION_B_HOUSE_MONEY_MULTIPLIER = Decimal("2")
OPTION_B_VAULT_SWEEP_RATIO = Decimal("0.50")
OPTION_B_MAX_OPEN_POSITIONS_CEILING = 8
OPTION_B_RECENT_TRADES_LIMIT = 20
OPTION_B_RECENT_EVENTS_LIMIT = 25

_CAS_TO_MICRO_SUPPORTED: frozenset[str] = frozenset({"NAS100", "US30", "SPX500", "XAUUSD"})
_PENNY = Decimal("0.01")
_PCT4 = Decimal("0.0001")
_DD_10DP = Decimal("0.0000000001")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _q2(value: Decimal) -> Decimal:
    return value.quantize(_PENNY, rounding=ROUND_HALF_UP)


def _q4(value: Decimal) -> Decimal:
    return value.quantize(_PCT4, rounding=ROUND_HALF_UP)


def _q10_ceil(value: Decimal) -> Decimal:
    return value.quantize(_DD_10DP, rounding=ROUND_CEILING) if value > Decimal("0") else Decimal("0")


def _usd_text(value: Decimal) -> str:
    return f"{_q2(value):.2f}"


def _exact_decimal(
    value: object,
    field_name: str,
    *,
    positive: bool = False,
    non_negative: bool = False,
) -> Decimal:
    if isinstance(value, bool):
        raise ContractError(f"{field_name} must be a Decimal or numeric string, not bool")
    if isinstance(value, Decimal):
        dec = value
    elif isinstance(value, (int, str)):
        raw = str(value).strip()
        if not raw:
            raise ContractError(f"{field_name} must not be empty")
        try:
            dec = Decimal(raw)
        except InvalidOperation as exc:
            raise ContractError(f"{field_name} is not a valid decimal: {raw!r}") from exc
    else:
        raise ContractError(f"{field_name} must be a Decimal, int, or decimal string")
    if not dec.is_finite():
        raise ContractError(f"{field_name} must be finite")
    if positive and dec <= Decimal("0"):
        raise ContractError(f"{field_name} must be positive")
    if non_negative and dec < Decimal("0"):
        raise ContractError(f"{field_name} must be non-negative")
    return dec


def _iso_utc(dt: datetime) -> str:
    return utc_time(dt, "timestamp").strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_cas_symbol(symbol: object) -> str | None:
    if not isinstance(symbol, str):
        return None
    cleaned = symbol.strip().upper().replace("/", "").replace("_", "")
    if cleaned in _CAS_TO_MICRO_SUPPORTED:
        return cleaned
    if cleaned in TRADOVATE_SUPPORTED_CONTRACTS:
        return translate_micro_root_to_cas_symbol(cleaned)
    return None


class OptionBPaperDemoRunner:
    """Durable $5,000.00 CME Micro Futures paper-simulation runner for the 24/7 cockpit.

    Strictly locked to paper demo mode ($0.00 real money, 0 Tradovate credentials).
    Survives cockpit restarts by persisting cumulative balance, peak equity,
    closed trades, 50% Profit Vault reserve, and $10,000.00 House-Money progress
    in a symlink-verified SQLite WAL database.
    """

    def __init__(
        self,
        *,
        db_path: str | Path,
        venue_db_path: str | Path | None = None,
        valve_gate: ForexMetaValveGate | Any,
        starting_equity_usd: Decimal = OPTION_B_DEFAULT_STARTING_EQUITY_USD,
        account_id: str = OPTION_B_DEMO_ACCOUNT_ID,
        mode: str = TRADOVATE_MODE_DEMO,
        max_drawdown_pct: Decimal = MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
        max_stop_loss_risk_pct: Decimal = MAX_CONSTITUTIONAL_STOP_RISK_PCT,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        norm_mode = str(mode or "").strip().upper()
        if norm_mode != TRADOVATE_MODE_DEMO:
            raise TradovateLiveLockError(
                "OptionBPaperDemoRunner is strictly paper-demo only ($0.00 real money); LIVE mode is forbidden"
            )
        if valve_gate is None:
            raise ContractError("OptionBPaperDemoRunner requires an active ForexMetaValveGate")
        if not isinstance(account_id, str) or not account_id.strip():
            raise ContractError("account_id must be a non-empty string")

        self._account_id = account_id.strip()
        self._clock = clock if clock is not None else _utc_now
        self._lock = RLock()
        self._db_path = Path(db_path)
        self._venue_db_path = (
            Path(venue_db_path)
            if venue_db_path is not None
            else self._db_path.with_name(f"{self._db_path.stem}_venue.sqlite3")
        )
        self._initial_starting_equity_usd = _q2(
            _exact_decimal(starting_equity_usd, "starting_equity_usd", positive=True)
        )
        self._max_drawdown_pct = _exact_decimal(
            max_drawdown_pct, "max_drawdown_pct", positive=True
        )
        if self._max_drawdown_pct > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
            raise ContractError(
                "CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED: max_drawdown_pct cannot exceed 0.10 (10.00%)"
            )
        self._max_stop_loss_risk_pct = _exact_decimal(
            max_stop_loss_risk_pct, "max_stop_loss_risk_pct", positive=True
        )
        if self._max_stop_loss_risk_pct > MAX_CONSTITUTIONAL_STOP_RISK_PCT:
            raise ContractError(
                "CONSTITUTIONAL_STOP_RISK_CEILING_EXCEEDED: max_stop_loss_risk_pct cannot exceed 1.00%"
            )

        self._house_money_target_usd = _q2(
            self._initial_starting_equity_usd * OPTION_B_HOUSE_MONEY_MULTIPLIER
        )
        self._last_quotes: dict[str, dict[str, str]] = {}

        now = self._clock()
        restored = self._init_ledger_and_load_state(now)

        restored_balance = restored["last_balance_usd"]
        restored_peak = restored["peak_equity_usd"]
        emulator_start = (
            restored_balance
            if restored_balance > Decimal("0.00")
            else self._initial_starting_equity_usd
        )

        self._emulator = TradovateMicroFuturesPaperEmulator(
            account_id=self._account_id,
            mode=TRADOVATE_MODE_DEMO,
            starting_equity_usd=emulator_start,
            clock=self._clock,
            connected=True,
        )
        self._venue = TradovateMicroFuturesVenue(
            db_path=self._venue_db_path,
            transport=self._emulator,
            valve_gate=valve_gate,
            account_id=self._account_id,
            mode=TRADOVATE_MODE_DEMO,
            enabled=False,
            max_drawdown_pct=self._max_drawdown_pct,
            clock=self._clock,
        )
        self._venue.activate(mode=TRADOVATE_MODE_DEMO, now_utc=now)
        if restored_peak > emulator_start:
            self._ensure_peak_at_least(restored_peak, now)

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def venue_db_path(self) -> Path:
        return self._venue_db_path

    @property
    def venue(self) -> TradovateMicroFuturesVenue:
        return self._venue

    @property
    def emulator(self) -> TradovateMicroFuturesPaperEmulator:
        return self._emulator

    def _connect_rw(self) -> sqlite3.Connection:
        conn = open_verified_sqlite_connection(
            self._db_path,
            read_only=False,
            create_parent=True,
            label="Option B Paper Demo SQLite DB",
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _connect_ro(self) -> sqlite3.Connection:
        conn = open_verified_sqlite_connection(
            self._db_path,
            read_only=True,
            create_parent=False,
            label="Option B Paper Demo SQLite DB",
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _init_ledger_and_load_state(self, now: datetime) -> dict[str, Any]:
        ts = _iso_utc(now)
        start_s = _usd_text(self._initial_starting_equity_usd)
        target_s = _usd_text(self._house_money_target_usd)
        with closing(self._connect_rw()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS option_b_meta (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        account_id TEXT NOT NULL,
                        starting_equity_usd TEXT NOT NULL,
                        last_balance_usd TEXT NOT NULL,
                        peak_equity_usd TEXT NOT NULL,
                        total_realized_pnl_usd TEXT NOT NULL,
                        total_commissions_usd TEXT NOT NULL,
                        vault_50pct_reserved_usd TEXT NOT NULL,
                        retained_compounding_usd TEXT NOT NULL,
                        win_count INTEGER NOT NULL,
                        loss_count INTEGER NOT NULL,
                        house_money_target_usd TEXT NOT NULL,
                        house_money_reached_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS option_b_closed_trades (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        trade_id TEXT NOT NULL UNIQUE,
                        cas_symbol TEXT NOT NULL,
                        root_symbol TEXT NOT NULL,
                        contract_code TEXT NOT NULL,
                        side TEXT NOT NULL,
                        contracts INTEGER NOT NULL,
                        exit_price TEXT NOT NULL,
                        realized_pnl_usd TEXT NOT NULL,
                        commission_usd TEXT NOT NULL,
                        net_pnl_usd TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        closed_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS option_b_events (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        cas_symbol TEXT NOT NULL,
                        root_symbol TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        occurred_at TEXT NOT NULL
                    )
                    """
                )
                row = conn.execute(
                    "SELECT starting_equity_usd, last_balance_usd, peak_equity_usd, "
                    "total_realized_pnl_usd, total_commissions_usd, vault_50pct_reserved_usd, "
                    "retained_compounding_usd, win_count, loss_count, house_money_target_usd, "
                    "house_money_reached_at FROM option_b_meta WHERE id = 1"
                ).fetchone()
                if row is None:
                    conn.execute(
                        """
                        INSERT INTO option_b_meta (
                            id, account_id, starting_equity_usd, last_balance_usd, peak_equity_usd,
                            total_realized_pnl_usd, total_commissions_usd, vault_50pct_reserved_usd,
                            retained_compounding_usd, win_count, loss_count, house_money_target_usd,
                            house_money_reached_at, created_at, updated_at
                        ) VALUES (1, ?, ?, ?, ?, '0.00', '0.00', '0.00', '0.00', 0, 0, ?, NULL, ?, ?)
                        """,
                        (self._account_id, start_s, start_s, start_s, target_s, ts, ts),
                    )
                    res = {
                        "starting_equity_usd": self._initial_starting_equity_usd,
                        "last_balance_usd": self._initial_starting_equity_usd,
                        "peak_equity_usd": self._initial_starting_equity_usd,
                    }
                else:
                    self._initial_starting_equity_usd = _q2(
                        _exact_decimal(row["starting_equity_usd"], "starting_equity_usd", positive=True)
                    )
                    self._house_money_target_usd = _q2(
                        _exact_decimal(row["house_money_target_usd"], "house_money_target_usd", positive=True)
                    )
                    res = {
                        "starting_equity_usd": self._initial_starting_equity_usd,
                        "last_balance_usd": _q2(
                            _exact_decimal(row["last_balance_usd"], "last_balance_usd", non_negative=True)
                        ),
                        "peak_equity_usd": _q2(
                            _exact_decimal(row["peak_equity_usd"], "peak_equity_usd", positive=True)
                        ),
                    }
                conn.execute("COMMIT")
                return res
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _ensure_peak_at_least(self, peak_usd: Decimal, now: datetime) -> None:
        ts = _iso_utc(now)
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT peak_equity_usd FROM option_b_meta WHERE id = 1").fetchone()
                cur_peak = _q2(_exact_decimal(row["peak_equity_usd"], "peak_equity_usd", positive=True))
                if peak_usd > cur_peak:
                    conn.execute(
                        "UPDATE option_b_meta SET peak_equity_usd = ?, updated_at = ? WHERE id = 1",
                        (_usd_text(_q2(peak_usd)), ts),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _record_event_unlocked(
        self,
        conn,
        *,
        event_type: str,
        cas_symbol: str,
        root_symbol: str,
        detail: str,
        now: datetime,
    ) -> None:
        conn.execute(
            """
            INSERT INTO option_b_events (event_type, cas_symbol, root_symbol, detail, occurred_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(event_type)[:48], str(cas_symbol)[:16], str(root_symbol)[:16], str(detail)[:240], _iso_utc(now)),
        )
        conn.execute(
            """
            DELETE FROM option_b_events
            WHERE seq NOT IN (
                SELECT seq FROM option_b_events ORDER BY seq DESC LIMIT ?
            )
            """,
            (OPTION_B_RECENT_EVENTS_LIMIT * 2,),
        )

    def _record_closed_receipts_unlocked(
        self,
        receipts: tuple[TradovateOrderReceipt, ...],
        *,
        now: datetime,
    ) -> None:
        if not receipts:
            return
        acct = self._emulator.account_snapshot(now_utc=now)
        ts = _iso_utc(now)
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT starting_equity_usd, last_balance_usd, peak_equity_usd, "
                    "total_realized_pnl_usd, total_commissions_usd, win_count, loss_count, "
                    "house_money_target_usd, house_money_reached_at FROM option_b_meta WHERE id = 1"
                ).fetchone()
                starting = _q2(_exact_decimal(row["starting_equity_usd"], "starting_equity_usd", positive=True))
                peak = _q2(_exact_decimal(row["peak_equity_usd"], "peak_equity_usd", positive=True))
                total_realized = _q2(_exact_decimal(row["total_realized_pnl_usd"], "total_realized_pnl_usd"))
                total_comm = _q2(_exact_decimal(row["total_commissions_usd"], "total_commissions_usd", non_negative=True))
                wins = int(row["win_count"])
                losses = int(row["loss_count"])
                hm_target = _q2(_exact_decimal(row["house_money_target_usd"], "house_money_target_usd", positive=True))
                hm_reached = row["house_money_reached_at"]

                for r in receipts:
                    trade_id = r.request_id
                    existing = conn.execute(
                        "SELECT 1 FROM option_b_closed_trades WHERE trade_id = ?",
                        (trade_id,),
                    ).fetchone()
                    if existing is not None:
                        continue
                    exit_px = decimal_text(_q2(r.fill_price)) if r.fill_price is not None else "0.00"
                    realized = _q2(r.realized_pnl_usd)
                    comm = _q2(r.commission_usd)
                    net = _q2(r.net_pnl_usd)
                    total_realized = _q2(total_realized + net)
                    total_comm = _q2(total_comm + comm)
                    if net >= Decimal("0.00"):
                        wins += 1
                    else:
                        losses += 1
                    conn.execute(
                        """
                        INSERT INTO option_b_closed_trades (
                            trade_id, cas_symbol, root_symbol, contract_code, side, contracts,
                            exit_price, realized_pnl_usd, commission_usd, net_pnl_usd,
                            status, reason, closed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            trade_id,
                            r.cas_symbol,
                            r.root_symbol,
                            r.contract_code,
                            str(r.side or "CLOSE"),
                            int(r.filled_contracts),
                            exit_px,
                            _usd_text(realized),
                            _usd_text(comm),
                            _usd_text(net),
                            r.status,
                            r.reason,
                            _iso_utc(r.executed_at),
                        ),
                    )
                    self._record_event_unlocked(
                        conn,
                        event_type=r.status,
                        cas_symbol=r.cas_symbol,
                        root_symbol=r.root_symbol,
                        detail=f"{r.contract_code} x{r.filled_contracts} net {_usd_text(net)} USD ({r.reason})",
                        now=now,
                    )

                new_balance = _q2(acct.balance_usd)
                new_equity = _q2(acct.equity_usd)
                new_peak = _q2(max(peak, acct.peak_equity_usd, new_balance, new_equity))
                surplus = max(Decimal("0.00"), _q2(new_balance - starting))
                vault_reserved = _q2(surplus * OPTION_B_VAULT_SWEEP_RATIO)
                retained = _q2(surplus - vault_reserved)
                if hm_reached is None and new_equity >= hm_target:
                    hm_reached = ts

                conn.execute(
                    """
                    UPDATE option_b_meta
                    SET last_balance_usd = ?,
                        peak_equity_usd = ?,
                        total_realized_pnl_usd = ?,
                        total_commissions_usd = ?,
                        vault_50pct_reserved_usd = ?,
                        retained_compounding_usd = ?,
                        win_count = ?,
                        loss_count = ?,
                        house_money_reached_at = ?,
                        updated_at = ?
                    WHERE id = 1
                    """,
                    (
                        _usd_text(new_balance),
                        _usd_text(new_peak),
                        _usd_text(total_realized),
                        _usd_text(total_comm),
                        _usd_text(vault_reserved),
                        _usd_text(retained),
                        wins,
                        losses,
                        hm_reached,
                        ts,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def ingest_spot_quote(
        self,
        symbol: str,
        bid: Decimal | str | int,
        ask: Decimal | str | int,
        *,
        now_utc: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        """Feed a live cockpit quote into Option B Paper Demo and evaluate OCO SL/TP."""
        cas_sym = _normalize_cas_symbol(symbol)
        if cas_sym is None:
            return ()
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        bid_d = _exact_decimal(bid, "bid", positive=True)
        ask_d = _exact_decimal(ask, "ask", positive=True)
        if bid_d > ask_d:
            raise ContractError(f"Option B quote bid ({bid_d}) cannot exceed ask ({ask_d})")
        root = translate_cas_symbol_to_micro_root(cas_sym)

        with self._lock:
            triggered = self._venue.process_market_quote(
                cas_sym,
                bid_d,
                ask_d,
                now_utc=now,
            )
            mid_d = _q2((bid_d + ask_d) / Decimal("2"))
            self._last_quotes[root] = {
                "cas_symbol": cas_sym,
                "root_symbol": root,
                "bid": decimal_text(bid_d),
                "ask": decimal_text(ask_d),
                "mid": decimal_text(mid_d),
                "observed_at": _iso_utc(now),
            }
            if triggered:
                self._record_closed_receipts_unlocked(triggered, now=now)
            else:
                acct = self._emulator.account_snapshot(now_utc=now)
                if acct.equity_usd > self._initial_starting_equity_usd:
                    self._ensure_peak_at_least(acct.equity_usd, now)
            return triggered

    def mirror_entry_signal(
        self,
        *,
        symbol: str,
        side: str,
        stop_distance_points: Decimal | str | int,
        take_profit_points: Decimal | str | int,
        risk_pct: Decimal | str | int = MAX_CONSTITUTIONAL_STOP_RISK_PCT,
        max_open_positions: int = 4,
        reason: str = "CAS_OPTION_B_PAPER_MIRROR",
        policy_overrides: Mapping[str, Any] | None = None,
        now_utc: datetime | None = None,
    ) -> dict[str, Any]:
        """Attempt a valve-cleared, constitutionally-sized Option B paper entry."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        cas_sym = _normalize_cas_symbol(symbol)
        if cas_sym is None:
            return {"executed": False, "status": "UNSUPPORTED_SYMBOL", "symbol": str(symbol)}
        root = translate_cas_symbol_to_micro_root(cas_sym)

        risk_d = _exact_decimal(risk_pct, "risk_pct", positive=True)
        if risk_d > self._max_stop_loss_risk_pct:
            raise ContractError(
                f"Option B stop-loss risk_pct {risk_d}% exceeds constitutional ceiling {self._max_stop_loss_risk_pct}%"
            )
        if type(max_open_positions) is not int or not (1 <= max_open_positions <= OPTION_B_MAX_OPEN_POSITIONS_CEILING):
            raise ContractError(
                f"max_open_positions must be int in 1..{OPTION_B_MAX_OPEN_POSITIONS_CEILING}"
            )
        stop_pts = _exact_decimal(stop_distance_points, "stop_distance_points", positive=True)
        tp_pts = _exact_decimal(take_profit_points, "take_profit_points", positive=True)

        with self._lock:
            open_pos = self._emulator.positions()
            if len(open_pos) >= max_open_positions:
                detail = f"Max open micro-futures positions reached ({len(open_pos)}/{max_open_positions})"
                self._log_event("ENTRY_SKIPPED_MAX_POSITIONS", cas_sym, root, detail, now)
                return {"executed": False, "status": "MAX_OPEN_POSITIONS", "detail": detail}

            snap_acct = self._emulator.account_snapshot(now_utc=now)
            durable_peak = self._read_durable_peak_unlocked()
            eff_peak = max(durable_peak, snap_acct.peak_equity_usd, snap_acct.equity_usd)
            dd = _q10_ceil(compute_drawdown_pct(snap_acct.equity_usd, eff_peak))
            if dd >= self._max_drawdown_pct:
                detail = f"Hard drawdown brake active ({decimal_text(_q4(dd * Decimal('100')))}% >= 10.00%)"
                self._log_event("ENTRY_BLOCKED_DRAWDOWN", cas_sym, root, detail, now)
                return {"executed": False, "status": "DRAWDOWN_LOCKED", "detail": detail}

            try:
                receipt = self._venue.place_bracket_order(
                    symbol=cas_sym,
                    side=side,
                    stop_distance_points=stop_pts,
                    take_profit_points=tp_pts,
                    risk_pct=risk_d,
                    reason=reason,
                    policy_overrides=policy_overrides,
                    now_utc=now,
                )
            except (TradovateVenueError, MicroFuturesError, ContractError) as exc:
                detail = str(exc)[:240]
                self._log_event("ENTRY_REFUSED", cas_sym, root, detail, now)
                return {
                    "executed": False,
                    "status": type(exc).__name__,
                    "detail": detail,
                }

            self._log_event(
                "ENTRY_FILLED",
                cas_sym,
                root,
                f"{receipt.side} {receipt.filled_contracts} {receipt.contract_code} @ "
                f"{decimal_text(receipt.fill_price or Decimal('0'))} "
                f"(SL {decimal_text(receipt.stop_loss_price or Decimal('0'))} / "
                f"TP {decimal_text(receipt.take_profit_price or Decimal('0'))})",
                now,
            )
            return {
                "executed": True,
                "status": receipt.status,
                "order_id": receipt.order_id,
                "position_id": receipt.position_id,
                "contract_code": receipt.contract_code,
                "root_symbol": receipt.root_symbol,
                "cas_symbol": receipt.cas_symbol,
                "contracts": receipt.filled_contracts,
                "fill_price": decimal_text(receipt.fill_price) if receipt.fill_price is not None else None,
                "stop_loss_price": decimal_text(receipt.stop_loss_price) if receipt.stop_loss_price is not None else None,
                "take_profit_price": decimal_text(receipt.take_profit_price) if receipt.take_profit_price is not None else None,
            }

    def close_position(
        self,
        position_id: str,
        *,
        reason: str = "OPTION_B_MANUAL_CLOSE",
        now_utc: datetime | None = None,
    ) -> TradovateOrderReceipt:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            receipt = self._venue.close_position(position_id, reason=reason, now_utc=now)
            self._record_closed_receipts_unlocked((receipt,), now=now)
            return receipt

    def emergency_close_all(
        self,
        *,
        reason: str = "OPTION_B_EMERGENCY_FLATTEN",
        now_utc: datetime | None = None,
    ) -> tuple[TradovateOrderReceipt, ...]:
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            receipts = self._venue.emergency_close_all(reason=reason, now_utc=now)
            if receipts:
                self._record_closed_receipts_unlocked(receipts, now=now)
            return receipts

    def _log_event(
        self,
        event_type: str,
        cas_symbol: str,
        root_symbol: str,
        detail: str,
        now: datetime,
    ) -> None:
        with closing(self._connect_rw()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._record_event_unlocked(
                    conn,
                    event_type=event_type,
                    cas_symbol=cas_symbol,
                    root_symbol=root_symbol,
                    detail=detail,
                    now=now,
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _read_durable_peak_unlocked(self) -> Decimal:
        with closing(self._connect_ro()) as conn:
            row = conn.execute("SELECT peak_equity_usd FROM option_b_meta WHERE id = 1").fetchone()
            if row is None:
                return self._initial_starting_equity_usd
            return _q2(_exact_decimal(row["peak_equity_usd"], "peak_equity_usd", positive=True))

    def snapshot(
        self,
        *,
        now_utc: datetime | None = None,
        owner_controls_allowed: bool = False,
        session_scope: str = "UNBOUND",
    ) -> dict[str, Any]:
        """Strictly 0-write (?mode=ro + PRAGMA query_only=ON) Option B Paper Demo snapshot."""
        now = self._clock() if now_utc is None else utc_time(now_utc, "now_utc")
        with self._lock:
            with closing(self._connect_ro()) as conn:
                meta = conn.execute(
                    "SELECT account_id, starting_equity_usd, last_balance_usd, peak_equity_usd, "
                    "total_realized_pnl_usd, total_commissions_usd, vault_50pct_reserved_usd, "
                    "retained_compounding_usd, win_count, loss_count, house_money_target_usd, "
                    "house_money_reached_at, updated_at FROM option_b_meta WHERE id = 1"
                ).fetchone()
                trade_rows = conn.execute(
                    "SELECT trade_id, cas_symbol, root_symbol, contract_code, side, contracts, "
                    "exit_price, realized_pnl_usd, commission_usd, net_pnl_usd, status, reason, closed_at "
                    "FROM option_b_closed_trades ORDER BY seq DESC LIMIT ?",
                    (OPTION_B_RECENT_TRADES_LIMIT,),
                ).fetchall()
                event_rows = conn.execute(
                    "SELECT event_type, cas_symbol, root_symbol, detail, occurred_at "
                    "FROM option_b_events ORDER BY seq DESC LIMIT ?",
                    (OPTION_B_RECENT_EVENTS_LIMIT,),
                ).fetchall()

            venue_snap = self._venue.snapshot(now_utc=now)
            acct = self._emulator.account_snapshot(now_utc=now)
            open_pos = self._emulator.positions()

            starting = _q2(
                _exact_decimal(meta["starting_equity_usd"], "starting_equity_usd", positive=True)
                if meta is not None
                else self._initial_starting_equity_usd
            )
            durable_peak = _q2(
                _exact_decimal(meta["peak_equity_usd"], "peak_equity_usd", positive=True)
                if meta is not None
                else starting
            )
            hm_target = _q2(
                _exact_decimal(meta["house_money_target_usd"], "house_money_target_usd", positive=True)
                if meta is not None
                else self._house_money_target_usd
            )
            balance = _q2(acct.balance_usd)
            equity = _q2(acct.equity_usd)
            unrealized = _q2(equity - balance)
            peak_eq = _q2(max(durable_peak, acct.peak_equity_usd, balance, equity))
            net_pnl = _q2(equity - starting)
            net_pnl_pct = _q2((net_pnl / starting) * Decimal("100"))
            dd_ratio = _q10_ceil(compute_drawdown_pct(equity, peak_eq))
            dd_pct = _q2(dd_ratio * Decimal("100"))
            dd_locked = dd_ratio >= self._max_drawdown_pct

            surplus = max(Decimal("0.00"), _q2(balance - starting))
            vault_reserved = _q2(surplus * OPTION_B_VAULT_SWEEP_RATIO)
            retained = _q2(surplus - vault_reserved)

            hm_span = hm_target - starting
            if hm_span > Decimal("0.00"):
                raw_prog = ((equity - starting) / hm_span) * Decimal("100")
                hm_progress = _q2(max(Decimal("0.00"), min(Decimal("100.00"), raw_prog)))
            else:
                hm_progress = Decimal("100.00") if equity >= hm_target else Decimal("0.00")
            hm_ready = equity >= hm_target

            wins = int(meta["win_count"]) if meta is not None else 0
            losses = int(meta["loss_count"]) if meta is not None else 0
            total_closed = wins + losses
            win_rate = (
                _q2((Decimal(wins) / Decimal(total_closed)) * Decimal("100"))
                if total_closed > 0
                else Decimal("0.00")
            )

            contracts_list: list[dict[str, Any]] = []
            open_by_root: dict[str, int] = {}
            for p in open_pos:
                open_by_root[p.root_symbol] = open_by_root.get(p.root_symbol, 0) + int(p.contracts)

            for root in TRADOVATE_SUPPORTED_CONTRACTS:
                spec = CME_MICRO_FUTURES_SPECS[root]
                fm = resolve_front_month_contract(root, as_of_utc=now)
                q = self._last_quotes.get(root)
                contracts_list.append(
                    {
                        "root_symbol": root,
                        "cas_symbol": translate_micro_root_to_cas_symbol(root),
                        "display_name": spec.name,
                        "exchange": spec.exchange,
                        "contract_code": fm.contract_code,
                        "point_value_usd": decimal_text(spec.point_value_usd),
                        "tick_size": decimal_text(spec.tick_size),
                        "tick_value_usd": decimal_text(spec.tick_value_usd),
                        "open_contracts": open_by_root.get(root, 0),
                        "bid": q["bid"] if q is not None else None,
                        "ask": q["ask"] if q is not None else None,
                        "mid": q["mid"] if q is not None else None,
                        "quote_observed_at": q["observed_at"] if q is not None else None,
                    }
                )

            open_positions_out = [
                {
                    "position_id": p.position_id,
                    "cas_symbol": p.cas_symbol,
                    "root_symbol": p.root_symbol,
                    "contract_code": p.contract_code,
                    "side": p.side,
                    "contracts": int(p.contracts),
                    "entry_price": decimal_text(p.entry_price),
                    "mark_price": decimal_text(p.current_price),
                    "stop_loss_price": decimal_text(p.stop_loss_price) if p.stop_loss_price is not None else None,
                    "take_profit_price": decimal_text(p.take_profit_price) if p.take_profit_price is not None else None,
                    "unrealized_pnl_usd": _usd_text(_q2(p.floating_pnl_usd)),
                    "opened_at": _iso_utc(p.opened_at),
                }
                for p in open_pos
            ]

            recent_trades_out = [
                {
                    "trade_id": str(r["trade_id"]),
                    "cas_symbol": str(r["cas_symbol"]),
                    "root_symbol": str(r["root_symbol"]),
                    "contract_code": str(r["contract_code"]),
                    "side": str(r["side"]),
                    "contracts": int(r["contracts"]),
                    "exit_price": str(r["exit_price"]),
                    "realized_pnl_usd": str(r["realized_pnl_usd"]),
                    "commission_usd": str(r["commission_usd"]),
                    "net_pnl_usd": str(r["net_pnl_usd"]),
                    "status": str(r["status"]),
                    "reason": str(r["reason"]),
                    "closed_at": str(r["closed_at"]),
                }
                for r in trade_rows
            ]

            recent_events_out = [
                {
                    "event_type": str(r["event_type"]),
                    "cas_symbol": str(r["cas_symbol"]),
                    "root_symbol": str(r["root_symbol"]),
                    "detail": str(r["detail"]),
                    "occurred_at": str(r["occurred_at"]),
                }
                for r in event_rows
            ]

            return {
                "schema": OPTION_B_DEMO_SCHEMA,
                "account_id": self._account_id,
                "mode": TRADOVATE_MODE_DEMO,
                "status": "DRAWDOWN_LOCKED" if dd_locked else "PAPER_DEMO_ACTIVE",
                "paper_demo_only": True,
                "real_money_at_risk_usd": "0.00",
                "tradovate_signup_required": False,
                "regulated_jurisdiction": "US_CFTC_NFA_CME",
                "starting_equity_usd": _usd_text(starting),
                "balance_usd": _usd_text(balance),
                "equity_usd": _usd_text(equity),
                "unrealized_pnl_usd": _usd_text(unrealized),
                "net_pnl_usd": _usd_text(net_pnl),
                "net_pnl_pct": _usd_text(net_pnl_pct),
                "peak_equity_usd": _usd_text(peak_eq),
                "drawdown_pct": _usd_text(dd_pct),
                "drawdown_locked": bool(dd_locked),
                "max_stop_loss_risk_pct": _usd_text(self._max_stop_loss_risk_pct),
                "max_drawdown_pct": _usd_text(_q2(self._max_drawdown_pct * Decimal("100"))),
                "vault_50pct_reserved_usd": _usd_text(vault_reserved),
                "retained_compounding_usd": _usd_text(retained),
                "house_money_target_usd": _usd_text(hm_target),
                "house_money_progress_pct": _usd_text(hm_progress),
                "house_money_ready": bool(hm_ready),
                "house_money_reached_at": meta["house_money_reached_at"] if meta is not None else None,
                "closed_trades": total_closed,
                "win_count": wins,
                "loss_count": losses,
                "win_rate_pct": _usd_text(win_rate),
                "total_commissions_usd": (
                    str(meta["total_commissions_usd"]) if meta is not None else "0.00"
                ),
                "open_positions": open_positions_out,
                "recent_closed_trades": recent_trades_out,
                "recent_events": recent_events_out,
                "supported_contracts": contracts_list,
                "audit_chain_valid": bool(venue_snap.get("audit_chain_valid", False)),
                "owner_controls_allowed": bool(owner_controls_allowed),
                "session_scope": str(session_scope),
                "observed_at": _iso_utc(now),
            }


__all__ = [
    "OPTION_B_DEFAULT_STARTING_EQUITY_USD",
    "OPTION_B_DEMO_ACCOUNT_ID",
    "OPTION_B_DEMO_SCHEMA",
    "OPTION_B_HOUSE_MONEY_MULTIPLIER",
    "OPTION_B_MAX_OPEN_POSITIONS_CEILING",
    "OPTION_B_VAULT_SWEEP_RATIO",
    "OptionBPaperDemoRunner",
]
