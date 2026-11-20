"""PR #19 verification tests:
1. Unhandcuffed trading below High-Water Profit Floor activation (+$600 on $2,000 soft quota -> ratchet_armed=False, status=OPEN, risk_multiplier=1).
2. Peak +$2,000 on $2,000 soft / $3,000 hard -> ratchet_armed=True, protected_profit_floor_usd=1400 ($600 wiggle room);
   pullback to +$1,550 stays OPEN (still allowed to hunt $3,000); pullback to +$1,390 locks PROFIT_FLOOR_LOCKED.
3. Instant big win (+$4,094.46 >= $3,000 hard quota) via broker-closed TP -> immediate DAILY_QUOTA_LOCKED,
   50% ProfitSweepVault bank sweep ($2,047.23) with zero double-counting, and RESEARCH_RESPITE mode (0 LLM calls).
4. Backward-compatible SQLite ALTER TABLE migration on legacy daily_quota_sessions databases lacking peak_realized_pnl_usd.
5. Automatic reset back to ACTIVE_TRADING (OPEN) on next 17:00 NY session rollover.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    FOCUS_MODE_RESEARCH_RESPITE,
    OPERATING_MODE_ACTIVE_TRADING,
    AutonomousAiTrader,
)
from cas_forex_revamp.contracts import ActionKind
from cas_forex_revamp.operator.frontier_backends import ENV_ANTHROPIC_API_KEY, FrontierModelRegistry
from cas_forex_revamp.treasury import ProfitSweepVault
from cas_forex_revamp.valve.daily_quota import (
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_OPEN,
    QUOTA_STATUS_PROFIT_FLOOR_LOCKED,
    QUOTA_STATUS_SOFT,
    DailyQuotaGovernanceStore,
    session_date_for,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter, OandaQuoteTruthOracle
from cas_forex_revamp.venue.external_paper_broker import ENV_EXECUTION_MODE, EXECUTION_MODE_DEMO
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    Mt5Credentials,
    Mt5NativePythonTransport,
    Mt5PaperBrokerVenue,
    _RedactedSecret,
)

GATE = load_default_forex_valve_gate()
T0 = datetime(2026, 11, 19, 18, 0, 0, tzinfo=timezone.utc)  # 13:00 NY (session 2026-11-19)
DUMMY_VAL = "demo-v1"


class _TpCloseMt5Sdk:
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    TRADE_ACTION_DEAL = 1
    TRADE_ACTION_SLTP = 6
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    POSITION_TYPE_BUY = 0
    POSITION_TYPE_SELL = 1
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    TRADE_RETCODE_PLACED = 10008
    TRADE_RETCODE_DONE = 10009
    TRADE_RETCODE_DONE_PARTIAL = 10010

    def __init__(self, login: int, server: str) -> None:
        self._login = login
        self._server = server
        self.rows: tuple[SimpleNamespace, ...] = ()

    def initialize(self, **_kw: object) -> bool:
        return True

    def login(self, *_a: object, **_kw: object) -> bool:
        return True

    def shutdown(self) -> None:
        return None

    def last_error(self) -> tuple[int, str]:
        return (0, "OK")

    def account_info(self) -> SimpleNamespace:
        return SimpleNamespace(
            login=self._login,
            server=self._server,
            trade_mode=0,
            currency="USD",
            balance=16094.46,
            equity=16094.46,
            margin=0.0,
            margin_free=16094.46,
            margin_level=0.0,
            leverage=500,
        )

    def symbol_select(self, _sym: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, _sym: str) -> SimpleNamespace:
        return SimpleNamespace(bid=20560.00, ask=20562.50, time_msc=1795111200000)

    def positions_get(self) -> tuple[SimpleNamespace, ...]:
        return self.rows


class Pr19ProfitRatchetAndRespiteTests(unittest.TestCase):
    def test_unhandcuffed_below_activation_and_70pct_profit_floor_wiggle_room(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "quota_ratchet.sqlite3"
            store = DailyQuotaGovernanceStore(
                path=db_path,
                soft_quota_usd=Decimal("2000"),
                hard_quota_usd=Decimal("3000"),
                max_loss_usd=Decimal("5000"),
                max_consecutive_losses=3,
            )
            store.observe_day_start(Decimal("100000"), now=T0)

            # 1. +$600 win is below $1,000 activation (50% of $2,000 soft) -> unhandcuffed!
            s1 = store.record_realized_trade(
                Decimal("600"), symbol="NAS100", ticket="t-600", starting_equity=Decimal("100000"), now=T0
            )
            self.assertEqual(s1["status"], QUOTA_STATUS_OPEN)
            self.assertFalse(s1["ratchet_armed"])
            self.assertEqual(s1["ratchet_activation_usd"], "1000")
            self.assertEqual(s1["peak_realized_pnl_usd"], "600")
            self.assertEqual(s1["protected_profit_floor_usd"], "0")
            self.assertTrue(s1["new_risk_allowed"])
            ok1, rsn1, mult1 = store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertTrue(ok1)
            self.assertIsNone(rsn1)
            self.assertEqual(mult1, Decimal("1"))

            # 2. +$1,400 win -> total +$2,000 peak -> ratchet_armed=True, floor=$1,400 ($600 wiggle room!)
            s2 = store.record_realized_trade(
                Decimal("1400"), symbol="NAS100", ticket="t-1400", starting_equity=Decimal("100000"), now=T0
            )
            self.assertTrue(s2["ratchet_armed"])
            self.assertEqual(s2["peak_realized_pnl_usd"], "2000")
            self.assertEqual(s2["protected_profit_floor_usd"], "1400")
            self.assertEqual(s2["status"], QUOTA_STATUS_SOFT)
            self.assertTrue(s2["new_risk_allowed"])

            # 3. -$450 pullback -> net +$1,550 (> $1,400 floor) -> stays OPEN to keep hunting $3,000!
            s3 = store.record_realized_trade(
                Decimal("-450"), symbol="US30", ticket="t-pb1", starting_equity=Decimal("100000"), now=T0
            )
            self.assertEqual(s3["realized_net_pnl_usd"], "1550")
            self.assertEqual(s3["peak_realized_pnl_usd"], "2000")
            self.assertEqual(s3["protected_profit_floor_usd"], "1400")
            self.assertIn(s3["status"], (QUOTA_STATUS_OPEN, QUOTA_STATUS_SOFT))
            self.assertTrue(s3["new_risk_allowed"])
            ok3, _, _ = store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertTrue(ok3)

            # 4. -$160 pullback -> net +$1,390 (<= $1,400 floor) -> locks PROFIT_FLOOR_LOCKED!
            s4 = store.record_realized_trade(
                Decimal("-160"), symbol="US30", ticket="t-pb2", starting_equity=Decimal("100000"), now=T0
            )
            self.assertEqual(s4["realized_net_pnl_usd"], "1390")
            self.assertEqual(s4["status"], QUOTA_STATUS_PROFIT_FLOOR_LOCKED)
            self.assertFalse(s4["new_risk_allowed"])
            self.assertEqual(s4["risk_multiplier"], "0")
            ok4, rsn4, mult4 = store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertFalse(ok4)
            self.assertEqual(mult4, Decimal("0"))
            self.assertIn("1400", str(rsn4))
            # Protective AMEND_STOP & CLOSE remain 100% permitted!
            ok_amend, _, _ = store.evaluate_new_risk(ActionKind.AMEND_STOP, now=T0)
            ok_close, _, _ = store.evaluate_new_risk(ActionKind.CLOSE, now=T0)
            self.assertTrue(ok_amend)
            self.assertTrue(ok_close)

    def test_big_win_4094_46_locks_research_respite_sweeps_vault_and_resets_at_1700_ny(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            oracle = OandaQuoteTruthOracle.from_static_quotes({"NAS100": (Decimal("20560.00"), Decimal("20562.50"))})
            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "5.00",
                    "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.20",
                },
                valve_gate=GATE,
                oracle=oracle,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("80000"),
                    BROKER_HUGOSWAY_MT5: Decimal("12000"),
                    BROKER_LHFX_MT5: Decimal("8000"),
                },
                clock=lambda: T0,
            )
            sdk = _TpCloseMt5Sdk(1002903, "Hugosway-Demo")
            sdk.rows = (
                SimpleNamespace(
                    ticket=77001,
                    symbol="NAS100",
                    type=0,
                    volume=Decimal("0.68"),
                    price_open=Decimal("20500.00"),
                    sl=Decimal("20505.00"),
                    tp=Decimal("20560.00"),
                    profit=Decimal("4094.46"),
                ),
            )
            hugo = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=Mt5Credentials(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    login=1002903,
                    server="Hugosway-Demo",
                    password=_RedactedSecret(DUMMY_VAL),
                    execution_mode=EXECUTION_MODE_DEMO,
                ),
                transport=Mt5NativePythonTransport(mt5_module=sdk, clock=lambda: T0),
                valve_gate=GATE,
                clock=lambda: T0,
            )
            hugo.connect()
            router.attach_venue(hugo)

            llm_calls: list[str] = []

            def forbid_llm_post(
                url: str, _headers: dict[str, str], _body: bytes, _timeout: float, _max_bytes: int
            ) -> tuple[int, bytes]:
                llm_calls.append(url)
                return 500, b"{}"

            reg = FrontierModelRegistry(
                environ={ENV_ANTHROPIC_API_KEY: DUMMY_VAL},
                clock=lambda: T0,
                http_post=forbid_llm_post,
                resolve_dns=lambda _h: None,
            )
            quota = DailyQuotaGovernanceStore(
                path=root / "quota.sqlite3",
                soft_quota_usd=Decimal("2000"),
                hard_quota_usd=Decimal("3000"),
                max_loss_usd=Decimal("5000"),
            )
            vault = ProfitSweepVault(root / "vault.sqlite3", clock=lambda: T0)
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=GATE,
                quota_store=quota,
                journal_path=root / "cycles.sqlite3",
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T0,
            )
            trader._open_position_meta["77001"] = {
                "ticket": "77001",
                "broker_id": BROKER_HUGOSWAY_MT5,
                "symbol": "NAS100",
                "side": "BUY",
                "volume_lots": "0.68",
                "entry_price": "20500.00",
                "stop_loss": "20505.00",
                "take_profit": "20560.00",
                "profit": "0",
                "protection_stage": "BREAKEVEN_LOCKED",
            }

            # 1. Refresh floating +$4,094.46 profit, then broker TP closes position
            trader.protect_open_positions(quotes={"NAS100": (Decimal("20560.00"), Decimal("20562.50"))}, now=T0)
            sdk.rows = ()
            t_close = T0 + timedelta(seconds=1)
            trader.protect_open_positions(quotes={"NAS100": (Decimal("20560.00"), Decimal("20562.50"))}, now=t_close)

            # Verify ProfitSweepVault swept exact 50% ($2,047.23) with zero double-counting
            v_snap = vault.snapshot()
            self.assertEqual(v_snap["total_realized_profit_usd"], "4094.46")
            self.assertEqual(v_snap["bank_sweep_reserved_usd"], "2047.23")
            self.assertEqual(v_snap["retained_trading_usd"], "2047.23")

            # Verify immediate DAILY_QUOTA_LOCKED + RESEARCH_RESPITE snapshot
            snap_locked = trader.status_snapshot(now=t_close)
            self.assertEqual(snap_locked["daily_quota"]["status"], QUOTA_STATUS_LOCKED)
            self.assertTrue(snap_locked["daily_quota"]["ratchet_armed"])
            self.assertEqual(snap_locked["daily_quota"]["peak_realized_pnl_usd"], "4094.46")
            self.assertTrue(snap_locked["respite_mode"])
            self.assertEqual(snap_locked["operating_mode"], FOCUS_MODE_RESEARCH_RESPITE)
            self.assertIn("RESEARCH_RESPITE: Profits Banked (4094.46 USD", snap_locked["current_focus_status"])

            # 2. Running cycle during RESEARCH_RESPITE makes 0 LLM calls, observes NAS100, and journals note
            for dlt in (Decimal("0"), Decimal("8"), Decimal("18")):
                trader._tick_history["NAS100"].append((Decimal("20560.00") + dlt, Decimal("20562.50") + dlt))
            cyc = trader.run_cycle(
                None,
                mt5_quotes={"NAS100": (Decimal("20585.00"), Decimal("20587.50"))},
                fast_tick=True,
                now=t_close + timedelta(seconds=2),
            )
            self.assertEqual(len(llm_calls), 0)
            self.assertTrue(cyc["respite_mode"])
            self.assertEqual(cyc["operating_mode"], FOCUS_MODE_RESEARCH_RESPITE)
            self.assertEqual(cyc["action"], FOCUS_MODE_RESEARCH_RESPITE)
            self.assertEqual(cyc["symbol"], "NAS100")
            self.assertIn("Observing NAS100", cyc["reason"])

            # 3. Rollover past 17:00 New York time (22:05 UTC in EST) auto-resets to ACTIVE_TRADING (OPEN)
            t_rollover = datetime(2026, 11, 19, 22, 5, 0, tzinfo=timezone.utc)  # 17:05 NY -> session 2026-11-20
            self.assertNotEqual(session_date_for(t_close), session_date_for(t_rollover))
            snap_next = trader.status_snapshot(now=t_rollover)
            self.assertEqual(snap_next["daily_quota"]["status"], QUOTA_STATUS_OPEN)
            self.assertFalse(snap_next["daily_quota"]["ratchet_armed"])
            self.assertEqual(snap_next["daily_quota"]["protected_profit_floor_usd"], "0")
            self.assertFalse(snap_next["respite_mode"])
            self.assertEqual(snap_next["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)

    def test_sqlite_alter_table_migration_on_legacy_daily_quota_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            legacy_db = Path(td) / "legacy_quota.sqlite3"
            sdate = session_date_for(T0)
            conn = sqlite3.connect(str(legacy_db))
            try:
                conn.execute(
                    """
                    CREATE TABLE daily_quota_sessions (
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
                    INSERT INTO daily_quota_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"dual-shield-barbell:{sdate}",
                        sdate,
                        "dual-shield-barbell",
                        "100000",
                        "1800",
                        2,
                        2,
                        0,
                        0,
                        "OPEN",
                        None,
                        "2026-11-19T18:00:00Z",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            migrated = DailyQuotaGovernanceStore(
                path=legacy_db,
                soft_quota_usd=Decimal("2000"),
                hard_quota_usd=Decimal("3000"),
                max_loss_usd=Decimal("5000"),
            )
            snap = migrated.snapshot(now=T0)
            self.assertEqual(snap["realized_net_pnl_usd"], "1800")
            self.assertEqual(snap["peak_realized_pnl_usd"], "1800")
            self.assertTrue(snap["ratchet_armed"])
            self.assertEqual(snap["protected_profit_floor_usd"], "1260")

            # Subsequent pullback to $1,250 (<= $1,260 floor) locks PROFIT_FLOOR_LOCKED cleanly on migrated DB
            after_loss = migrated.record_realized_trade(
                Decimal("-550"), symbol="EURUSD", ticket="mig-1", starting_equity=Decimal("100000"), now=T0
            )
            self.assertEqual(after_loss["status"], QUOTA_STATUS_PROFIT_FLOOR_LOCKED)
            self.assertEqual(after_loss["peak_realized_pnl_usd"], "1800")


if __name__ == "__main__":
    unittest.main()
