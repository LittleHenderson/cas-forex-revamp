"""PR #24 tests: Live Trading Status banner, Realized P/L Provenance, Market & Broker Attribution, and 0-write GET."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.operator.frontier_backends import (
    FrontierModelRegistry,
    assert_safe_ai_catalog_payload,
)
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.profit_sweep import ProfitSweepVault
from cas_forex_revamp.valve.daily_quota import (
    DailyQuotaGovernanceStore,
    forex_session_label_for_utc,
    format_pacific_timestamp,
    friendly_broker_label,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
)
from tests.phase6.test_cockpit_api_contracts import validate_contract_schema

D = Decimal
REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "docs" / "contracts"
T_ASIA = datetime(2026, 11, 20, 0, 46, 41, tzinfo=timezone.utc)
T_LONDON = datetime(2026, 11, 20, 9, 15, 0, tzinfo=timezone.utc)
T_NY = datetime(2026, 11, 20, 15, 30, 0, tzinfo=timezone.utc)

QUOTES: dict[str, tuple[Decimal, Decimal]] = {
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27012")),
    "NAS100": (D("20500.00"), D("20502.50")),
    "XAUUSD": (D("2640.00"), D("2640.40")),
}


class _StubOandaTransport:
    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float, max_bytes: int) -> bytes:
        if url.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": "101-001-1234567-001",
                    "currency": "USD",
                    "balance": "80000",
                    "NAV": "80000",
                    "unrealizedPL": "0",
                    "marginAvailable": "80000",
                    "openPositionCount": 0,
                    "lastTransactionID": "1",
                }
            }).encode("utf-8")
        if "/pricing?" in url:
            return json.dumps({
                "prices": [
                    {"instrument": "EUR_USD", "bids": [{"price": "1.10000"}], "asks": [{"price": "1.10010"}]},
                    {"instrument": "GBP_USD", "bids": [{"price": "1.27000"}], "asks": [{"price": "1.27012"}]},
                ]
            }).encode("utf-8")
        raise RuntimeError(f"Unexpected OANDA call: {method} {url}")


class Pr24TradingStatusAndProvenanceTests(unittest.TestCase):
    def _load_schema(self, name: str) -> dict[str, object]:
        return json.loads((CONTRACTS_DIR / name).read_text(encoding="utf-8"))

    def _build_rig(self, root: Path, *, now: datetime = T_ASIA) -> tuple[AutonomousAiTrader, ProfitSweepVault, DailyQuotaGovernanceStore, dict[str, Mt5SpoolPaperTerminalEmulator]]:
        gate = load_default_forex_valve_gate()
        emus = {
            BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES,
                balance=D("12000"),
                leverage=500,
                clock=lambda: now,
            ),
            BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes=QUOTES,
                balance=D("8000"),
                leverage=500,
                clock=lambda: now,
            ),
        }
        emus[BROKER_HUGOSWAY_MT5].publish_market()
        emus[BROKER_LHFX_MT5].publish_market()
        env = {
            "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
            "CAS_FOREX_MT5_SPOOL_DIR": str(root),
            "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
            "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": "demo-v1",  # nosec B105: low-entropy test placeholder
            "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
            "CAS_FOREX_OANDA_PRACTICE_TOKEN": "demo-v1",  # nosec B105: low-entropy test placeholder
            "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-1234567-001",
        }
        router = DualShieldBrokerRouter(
            environ=env,
            valve_gate=gate,
            transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                Path(r) / bid.lower(),
                sleep=emus[bid].sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
                clock=lambda: now,
            ),
            oanda_client_factory=lambda e: OandaPracticePaperClient(environ=e, transport=_StubOandaTransport()),
            clock=lambda: now,
        )
        router.activate_all()
        vault = ProfitSweepVault(root / "vault.sqlite3", scope_id="main", clock=lambda: now)
        quota = DailyQuotaGovernanceStore(path=root / "quota.sqlite3")
        trader = AutonomousAiTrader(
            router=router,
            model_registry=FrontierModelRegistry(environ={}),
            valve_gate=gate,
            quota_store=quota,
            profit_vault=vault,
            execution_gate=DurableModelExecutionGate(root / "mg.sqlite3"),
            clock=lambda: now,
        )
        return trader, vault, quota, emus

    def test_session_labels_pacific_formatting_and_broker_labels(self) -> None:
        self.assertEqual(forex_session_label_for_utc("2026-11-20T00:46:41Z"), "Asia / Tokyo\u2013Sydney")
        self.assertEqual(forex_session_label_for_utc("2026-11-19T22:00:00Z"), "Asia / Tokyo\u2013Sydney")
        self.assertEqual(forex_session_label_for_utc("2026-11-20T07:00:00Z"), "London")
        self.assertEqual(forex_session_label_for_utc("2026-11-20T11:59:59Z"), "London")
        self.assertEqual(forex_session_label_for_utc("2026-11-20T12:00:00Z"), "New York / US")
        self.assertEqual(forex_session_label_for_utc("2026-11-20T21:59:59Z"), "New York / US")

        self.assertEqual(format_pacific_timestamp("2026-11-20T00:46:41Z"), "2026-11-19 16:46:41 PST")
        self.assertEqual(format_pacific_timestamp("2026-07-15T18:30:00Z"), "2026-07-15 11:30:00 PDT")

        self.assertEqual(friendly_broker_label("LHFX_MT5"), "LHFX")
        self.assertEqual(friendly_broker_label("HUGOSWAY_MT5"), "Hugo's Way")
        self.assertEqual(friendly_broker_label("OANDA_PRACTICE"), "OANDA")
        self.assertEqual(friendly_broker_label("OANDA_LIVE"), "OANDA")
        self.assertEqual(friendly_broker_label("OANDA"), "OANDA")

    def test_daily_quota_legacy_migration_and_read_only_recent_closed_trades(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "legacy_quota.sqlite3"
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """
                    CREATE TABLE daily_quota_events (
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
                conn.execute(
                    """
                    INSERT INTO daily_quota_events (
                        session_key, event_kind, delta_pnl_usd, status_after, observed_at, prev_sha256, event_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "dual-shield-barbell:2026-11-20-ASIA",
                        "REALIZED_TRADE",
                        "125.50",
                        "OPEN",
                        "2026-11-20T00:10:00Z",
                        "0" * 64,
                        "1" * 64,
                    ),
                )
                conn.commit()

            store = DailyQuotaGovernanceStore(path=db_path)
            with closing(sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)) as ro_conn:
                dv_before = int(ro_conn.execute("PRAGMA data_version").fetchone()[0])
                legacy_rows = store.recent_closed_trades(limit=10)
                dv_after = int(ro_conn.execute("PRAGMA data_version").fetchone()[0])
            self.assertEqual(dv_before, dv_after)
            self.assertEqual(len(legacy_rows), 1)
            self.assertIsNone(legacy_rows[0]["symbol"])
            self.assertIsNone(legacy_rows[0]["trade_id"])
            self.assertIsNone(legacy_rows[0]["broker_id"])
            self.assertEqual(legacy_rows[0]["session_label"], "Asia / Tokyo\u2013Sydney")

            # Now record a PR #24 closed trade -> migrates schema in _connect() and persists provenance
            store.record_realized_trade(
                D("420.75"),
                symbol="XAUUSD",
                trade_id="tkt-xau-77",
                broker_id="HUGOSWAY_MT5",
                starting_equity=D("100000"),
                now=T_ASIA,
                in_recovery_mode=True,
            )
            rows_after = store.recent_closed_trades(limit=10)
            self.assertEqual(len(rows_after), 2)
            newest = rows_after[0]
            self.assertEqual(newest["symbol"], "XAUUSD")
            self.assertEqual(newest["trade_id"], "tkt-xau-77")
            self.assertEqual(newest["broker_id"], "HUGOSWAY_MT5")
            self.assertEqual(newest["broker_label"], "Hugo's Way")
            self.assertEqual(newest["realized_pnl_usd"], "420.75")
            self.assertEqual(newest["occurred_at_pacific"], "2026-11-19 16:46:41 PST")
            self.assertEqual(newest["session_label"], "Asia / Tokyo\u2013Sydney")

            # In-memory store parity
            mem_store = DailyQuotaGovernanceStore(path=None)
            mem_store.record_closed_trade(
                D("-85.00"),
                symbol="NAS100",
                trade_id="tkt-nas-mem-1",
                broker_id="LHFX_MT5",
                starting_equity=D("50000"),
                now=T_NY,
            )
            mem_rows = mem_store.recent_closed_trades()
            self.assertEqual(len(mem_rows), 1)
            self.assertEqual(mem_rows[0]["broker_label"], "LHFX")
            self.assertEqual(mem_rows[0]["session_label"], "New York / US")

    def test_treasury_trade_sweeps_excludes_session_sync_and_validates_schema(self) -> None:
        treasury_schema = self._load_schema("treasury.schema.json")
        with tempfile.TemporaryDirectory() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", scope_id="main", clock=lambda: T_ASIA)
            vault.record_realized_close(
                trade_id="tr-hugo-1",
                symbol="XAUUSD",
                broker_id="HUGOSWAY_MT5",
                realized_net_usd=D("1332.15"),
                occurred_at=T_ASIA,
                session_date="2026-11-20-ASIA",
            )
            vault.record_realized_close(
                trade_id="tr-lhfx-2",
                symbol="NAS100",
                broker_id="LHFX_MT5",
                realized_net_usd=D("540.00"),
                occurred_at=T_LONDON,
                session_date="2026-11-20-LONDON",
            )
            vault.record_realized_close(
                trade_id="tr-oanda-3",
                symbol="EURUSD",
                broker_id="OANDA_PRACTICE",
                realized_net_usd=D("110.00"),
                occurred_at=T_NY,
                session_date="2026-11-20-NY",
            )
            # Trigger a synthetic SESSION_SYNC_* / SESSION_BASKET reconciliation row
            vault.reconcile_session_realized_profit(
                session_date="2026-11-20-NY",
                session_realized_net_usd=D("210.00"),
                occurred_at=T_NY + timedelta(minutes=5),
            )

            with closing(sqlite3.connect(f"{vault.db_path.resolve().as_uri()}?mode=ro", uri=True)) as ro_v:
                dv_before = int(ro_v.execute("PRAGMA data_version").fetchone()[0])
                snap = assert_safe_ai_catalog_payload(vault.snapshot())
                _ = vault.session_totals("2026-11-20-NY")
                dv_after = int(ro_v.execute("PRAGMA data_version").fetchone()[0])
            self.assertEqual(dv_before, dv_after)

            validate_contract_schema(snap, treasury_schema)
            self.assertEqual(len(snap["recent_sweeps"]), 4)
            self.assertTrue(snap["recent_sweeps"][0]["is_reconciliation_sync"])
            self.assertEqual(len(snap["trade_sweeps"]), 3)
            for ts_row in snap["trade_sweeps"]:
                self.assertFalse(ts_row["is_reconciliation_sync"])
                self.assertFalse(str(ts_row["trade_id"]).startswith("SESSION_SYNC_"))
                self.assertNotEqual(ts_row["symbol"], "SESSION_BASKET")

            by_mkt = {m["symbol"]: m for m in snap["realized_by_market"]}
            self.assertNotIn("SESSION_BASKET", by_mkt)
            self.assertEqual(set(by_mkt.keys()), {"XAUUSD", "NAS100", "EURUSD"})
            self.assertEqual(by_mkt["XAUUSD"]["realized_net_usd"], "1332.15")
            self.assertEqual(by_mkt["XAUUSD"]["last_session_label"], "Asia / Tokyo\u2013Sydney")

            by_brk = {b["broker_id"]: b for b in snap["realized_by_broker"]}
            self.assertNotIn("DUAL_SHIELD_BARBELL", by_brk)
            self.assertEqual(by_brk["HUGOSWAY_MT5"]["broker_label"], "Hugo's Way")
            self.assertEqual(by_brk["LHFX_MT5"]["broker_label"], "LHFX")
            self.assertEqual(by_brk["OANDA_PRACTICE"]["broker_label"], "OANDA")

    def test_autonomous_trader_live_status_all_states_last_trade_and_zero_writes(self) -> None:
        trader_schema = self._load_schema("ai-trader.schema.json")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trader, vault, quota, _ = self._build_rig(root, now=T_ASIA)

            # 1. ACTIVE_SCANNING_MARKETS (0 open trades, 0 closed trades)
            s0 = trader.status_snapshot(now=T_ASIA)
            validate_contract_schema(s0, trader_schema)
            self.assertEqual(s0["live_trading_status"]["state_code"], "ACTIVE_SCANNING_MARKETS")
            self.assertEqual(s0["live_trading_status"]["headline"], "ACTIVE \u2014 SCANNING MARKETS (0 OPEN TRADES)")
            self.assertTrue(s0["live_trading_status"]["is_currently_trading"])
            self.assertFalse(s0["live_trading_status"]["has_open_positions"])
            self.assertIsNone(s0["last_trade"])
            self.assertEqual(
                s0["realized_pnl_ledger"]["session_provenance_summary"],
                "No closed trades in current session yet",
            )

            # 2. TRADING_NOW_OPEN_POSITIONS (1 and 2 open positions)
            trader._open_position_meta["tkt-open-1"] = {
                "ticket": "tkt-open-1",
                "broker_id": "HUGOSWAY_MT5",
                "symbol": "NAS100",
                "side": "BUY",
                "volume_lots": "0.10",
                "entry_price": "20502.50",
                "stop_loss": "20450.00",
                "take_profit": "20650.00",
                "profit": "45.00",
                "protection_stage": "INITIAL_SL",
            }
            s_open1 = trader.status_snapshot(now=T_ASIA)
            validate_contract_schema(s_open1, trader_schema)
            self.assertEqual(s_open1["live_trading_status"]["state_code"], "TRADING_NOW_OPEN_POSITIONS")
            self.assertEqual(
                s_open1["live_trading_status"]["headline"],
                "TRADING NOW \u2014 1 OPEN POSITION: NAS100",
            )
            self.assertTrue(s_open1["live_trading_status"]["has_open_positions"])

            trader._open_position_meta["tkt-open-2"] = {
                "ticket": "tkt-open-2",
                "broker_id": "LHFX_MT5",
                "symbol": "XAUUSD",
                "side": "BUY",
                "volume_lots": "0.10",
                "entry_price": "2640.40",
                "stop_loss": "2630.00",
                "take_profit": "2670.00",
                "profit": "22.00",
                "protection_stage": "INITIAL_SL",
            }
            s_open2 = trader.status_snapshot(now=T_ASIA)
            validate_contract_schema(s_open2, trader_schema)
            self.assertEqual(
                s_open2["live_trading_status"]["headline"],
                "TRADING NOW \u2014 2 OPEN POSITIONS: NAS100, XAUUSD",
            )

            # 3. Broker-closed trade on Hugo's Way + LHFX + synthetic SESSION_SYNC noise -> PAUSED_RESEARCH_RESPITE
            trader._open_position_meta.clear()
            trader.record_closed_pnl(
                D("450.00"),
                symbol="NAS100",
                ticket="tkt-lhfx-win",
                broker_id="LHFX_MT5",
                now=T_ASIA,
            )
            trader.record_closed_pnl(
                D("882.15"),
                symbol="XAUUSD",
                ticket="tkt-hugo-win",
                broker_id="HUGOSWAY_MT5",
                now=T_ASIA + timedelta(seconds=20),
            )
            vault.reconcile_session_realized_profit(
                session_date="2026-11-20-ASIA",
                session_realized_net_usd=D("1400.00"),
                occurred_at=T_ASIA + timedelta(seconds=50),
            )

            # Verify 0 SQLite writes during status_snapshot() on both quota.sqlite3 and vault.sqlite3
            with closing(sqlite3.connect(f"{quota.path.resolve().as_uri()}?mode=ro", uri=True)) as ro_q, closing(
                sqlite3.connect(f"{vault.db_path.resolve().as_uri()}?mode=ro", uri=True)
            ) as ro_v:
                q_dv_before = int(ro_q.execute("PRAGMA data_version").fetchone()[0])
                v_dv_before = int(ro_v.execute("PRAGMA data_version").fetchone()[0])
                s_locked = trader.status_snapshot(now=T_ASIA + timedelta(minutes=1))
                q_dv_after = int(ro_q.execute("PRAGMA data_version").fetchone()[0])
                v_dv_after = int(ro_v.execute("PRAGMA data_version").fetchone()[0])
            self.assertEqual(q_dv_before, q_dv_after)
            self.assertEqual(v_dv_before, v_dv_after)

            validate_contract_schema(s_locked, trader_schema)
            self.assertEqual(s_locked["live_trading_status"]["state_code"], "PAUSED_RESEARCH_RESPITE")
            self.assertEqual(
                s_locked["live_trading_status"]["headline"],
                "PAUSED \u2014 RESEARCH RESPITE (PROFIT LOCKED)",
            )
            self.assertFalse(s_locked["live_trading_status"]["is_currently_trading"])

            # Verify last_trade is XAUUSD on Hugo's Way (NEVER SESSION_SYNC_* despite newer timestamp!)
            lt = s_locked["last_trade"]
            self.assertIsNotNone(lt)
            self.assertEqual(lt["trade_id"], "tkt-hugo-win")
            self.assertEqual(lt["symbol"], "XAUUSD")
            self.assertEqual(lt["broker_id"], "HUGOSWAY_MT5")
            self.assertEqual(lt["broker_label"], "Hugo's Way")
            self.assertEqual(lt["realized_pnl_usd"], "882.15")
            self.assertEqual(lt["session_label"], "Asia / Tokyo\u2013Sydney")

            ledger = s_locked["realized_pnl_ledger"]
            self.assertEqual(len(ledger["entries"]), 2)
            for ent in ledger["entries"]:
                self.assertFalse(str(ent["trade_id"]).startswith("SESSION_SYNC_"))
                self.assertNotEqual(ent["symbol"], "SESSION_BASKET")
            self.assertEqual([m["symbol"] for m in ledger["session_by_market"]], ["XAUUSD", "NAS100"])
            self.assertEqual(
                {b["broker_label"] for b in ledger["session_by_broker"]},
                {"Hugo's Way", "LHFX"},
            )
            self.assertIn("XAUUSD (+$882.15)", ledger["session_provenance_summary"])
            self.assertIn("Hugo's Way", ledger["session_provenance_summary"])
            self.assertEqual(
                s_locked["banked_session"]["session_provenance_summary"],
                ledger["session_provenance_summary"],
            )
            self.assertEqual(
                s_locked["banked_session"]["session_by_broker"],
                ledger["session_by_broker"],
            )

            # 4. STOPPED_OR_PAUSED and PAUSED_SAFETY_LOCK states
            s_london_pause = trader.pause_new_risk(reason="Manual check", now=T_LONDON)
            validate_contract_schema(s_london_pause, trader_schema)
            self.assertEqual(s_london_pause["live_trading_status"]["state_code"], "STOPPED_OR_PAUSED")
            self.assertEqual(s_london_pause["live_trading_status"]["headline"], "PAUSED \u2014 PAUSED_NEW_RISK")

            trader.resume_autonomous(now=T_LONDON)
            trader.record_closed_pnl(
                D("-600.00"),
                symbol="EURUSD",
                ticket="tkt-oanda-loss",
                broker_id="OANDA_PRACTICE",
                now=T_LONDON,
            )
            s_safety = trader.status_snapshot(now=T_LONDON)
            validate_contract_schema(s_safety, trader_schema)
            self.assertEqual(s_safety["live_trading_status"]["state_code"], "PAUSED_SAFETY_LOCK")
            self.assertEqual(s_safety["live_trading_status"]["headline"], "PAUSED \u2014 SAFETY LOCK")
            self.assertEqual(s_safety["last_trade"]["broker_label"], "OANDA")

    def test_stale_close_emergency_close_and_open_fill_last_trade_attribution(self) -> None:
        trader_schema = self._load_schema("ai-trader.schema.json")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trader, _vault, _quota, emus = self._build_rig(root, now=T_ASIA)

            # Open fill in _recent_actions before any trade closes -> last_trade has realized_pnl_usd=None & broker_label
            trader._recent_actions.appendleft({
                "cycle_id": "cyc-1",
                "observed_at": "2026-11-20T00:40:00Z",
                "model_id": "claude-fable-5.2",
                "action": "OPEN_BUY",
                "symbol": "NAS100",
                "executed_on": "LHFX_MT5",
                "ticket": "tkt-open-fill-1",
                "stop_loss": "20450.00",
                "take_profit": "20650.00",
                "leg_index": 1,
                "pyramid_parent_ticket": None,
                "regime": "STRONG_TREND",
                "thinking_depth": "HIGH",
                "valve_score": "0.82",
                "reason": "Momentum breakout",
            })
            s_fill = trader.status_snapshot(now=T_ASIA)
            validate_contract_schema(s_fill, trader_schema)
            self.assertEqual(s_fill["last_trade"]["trade_id"], "tkt-open-fill-1")
            self.assertEqual(s_fill["last_trade"]["broker_label"], "LHFX")
            self.assertIsNone(s_fill["last_trade"]["realized_pnl_usd"])

            # Simulate broker-closed stale_tkt in protect_open_positions on HUGOSWAY_MT5
            trader._open_position_meta["tkt-stale-hugo-9"] = {
                "ticket": "tkt-stale-hugo-9",
                "broker_id": BROKER_HUGOSWAY_MT5,
                "symbol": "XAUUSD",
                "side": "BUY",
                "volume_lots": "0.10",
                "entry_price": "2640.40",
                "stop_loss": "2630.00",
                "take_profit": "2670.00",
                "profit": "315.40",
                "protection_stage": "TRAILING_PROFIT",
            }
            emus[BROKER_HUGOSWAY_MT5].publish_market()
            trader.protect_open_positions(now=T_ASIA)

            s_after_stale = trader.status_snapshot(now=T_ASIA)
            validate_contract_schema(s_after_stale, trader_schema)
            self.assertEqual(s_after_stale["last_trade"]["trade_id"], "tkt-stale-hugo-9")
            self.assertEqual(s_after_stale["last_trade"]["symbol"], "XAUUSD")
            self.assertEqual(s_after_stale["last_trade"]["broker_id"], BROKER_HUGOSWAY_MT5)
            self.assertEqual(s_after_stale["last_trade"]["broker_label"], "Hugo's Way")
            self.assertEqual(s_after_stale["last_trade"]["realized_pnl_usd"], "315.4")


if __name__ == "__main__":
    unittest.main()
