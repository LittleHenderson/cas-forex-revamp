"""PR #21 verification tests:
1. Wakil's exact Principal High-Water Mark journey ($300,000 -> $277,618.09 -> +$4,640.06 to $282,258.15
   RECOVERY_MODE with -$17,741.85 net surplus & $0 vaulted including clawback of legacy $666.08 underwater row
   -> automatic London 07:00 UTC wakeup -> +$21,741.85 to $304,000 IN_SURPLUS with +$4,000 surplus & $2,000
   internal vault reserve / $2,000 retained -> pullback to $299,500 back to RECOVERY_MODE & $0 vaulted).
2. Strictly read-only status_snapshot() proof (0 SQLite writes, PRAGMA data_version unchanged on BOTH
   profit_vault.sqlite3 and daily_quota.sqlite3 across repeated reads and rollover timestamps).
3. Contiguous 24h Global Forex Region windows (ASIA 22:00-07:00 UTC across midnight, LONDON 07:00-12:00 UTC,
   NY 12:00-22:00 UTC) with zero gaps.
4. Recovery leg advance (#leg2+) with <=30% prior-leg giveback cap (70% profit floor preserved across legs)
   and hard refusals when IN_SURPLUS or DAILY_LOSS_CIRCUIT_TRIPPED, keeping Valve / 20% DD / 1,000% margin intact.
5. LoopbackCockpitServer /api/ai-trader-control, /api/ai-overseer-action, and /api/treasury-config routes,
   plus legacy vault_config ALTER TABLE migration & disbursed payout economic-equity accounting.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    CAPITAL_STATUS_IN_SURPLUS,
    CAPITAL_STATUS_RECOVERY_MODE,
    FOCUS_MODE_RESEARCH_RESPITE,
    OPERATING_MODE_ACTIVE_TRADING,
    AutonomousAiTrader,
)
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.operator.frontier_backends import (
    FrontierModelRegistry,
    assert_safe_ai_catalog_payload,
)
from cas_forex_revamp.treasury.profit_sweep import ENV_INITIAL_CAPITAL_USD, ProfitSweepVault
from cas_forex_revamp.valve.daily_quota import (
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_LOSS_TRIPPED,
    QUOTA_STATUS_OPEN,
    SESSION_CADENCE_AUTO,
    SESSION_CADENCE_DAILY_NY,
    SESSION_CADENCE_REGIONAL_8H,
    SESSION_CADENCE_REGIONAL_RECOVERY,
    DailyQuotaGovernanceStore,
    regional_session_window_for,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import ENV_EXECUTION_MODE, EXECUTION_MODE_DEMO
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
)

GATE = load_default_forex_valve_gate()
T_ASIA = datetime(2026, 11, 20, 1, 15, 0, tzinfo=timezone.utc)
T_LONDON = datetime(2026, 11, 20, 7, 0, 0, tzinfo=timezone.utc)
T_NY = datetime(2026, 11, 20, 12, 30, 0, tzinfo=timezone.utc)


def _verify_vault_audit_chain(tc: unittest.TestCase, db_file: Path) -> int:
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT prev_sha256, entry_sha256, scope_id, event_type, payload_json, created_at "
            "FROM vault_audit ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()
    expected_prev = "0" * 64
    for r in rows:
        tc.assertEqual(str(r["prev_sha256"]), expected_prev)
        recomputed = sha256(
            f"{r['prev_sha256']}|{r['scope_id']}|{r['event_type']}|".encode("utf-8")
            + str(r["payload_json"]).encode("utf-8")
            + f"|{r['created_at']}".encode("utf-8")
        ).hexdigest()
        tc.assertEqual(str(r["entry_sha256"]), recomputed)
        expected_prev = recomputed
    return len(rows)


def _set_router_total_equity(router: DualShieldBrokerRouter, total_usd: Decimal) -> None:
    oanda_eq = (total_usd * Decimal("0.80")).quantize(Decimal("0.01"))
    hugo_eq = (total_usd * Decimal("0.12")).quantize(Decimal("0.01"))
    lhfx_eq = total_usd - oanda_eq - hugo_eq
    router._attestations[BROKER_OANDA_PRACTICE] = oanda_eq
    router._attestations[BROKER_HUGOSWAY_MT5] = hugo_eq
    router._attestations[BROKER_LHFX_MT5] = lhfx_eq
    router._last_equity.clear()


class Pr21PrincipalHwmAndRecoveryCadenceTests(unittest.TestCase):
    def test_wakil_benchmark_journey_underwater_clawback_surplus_and_pullback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("225806.52"),
                    BROKER_HUGOSWAY_MT5: Decimal("33870.98"),
                    BROKER_LHFX_MT5: Decimal("22580.65"),
                },
                clock=lambda: T_ASIA,
            )
            self.assertEqual(router.barbell.total_equity(router.equities()), Decimal("282258.15"))

            # Seed live cloud legacy state: 2026-11-20 row created inside [22:00Z, 07:00Z) Asia window
            quota_db = root / "quota.sqlite3"
            quota = DailyQuotaGovernanceStore(
                path=quota_db,
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
                max_loss_usd=Decimal("5000.00"),
            )
            quota.observe_day_start(Decimal("277618.09"), now=T_ASIA, in_recovery_mode=False)
            for idx in range(6):
                quota.record_realized_trade(
                    Decimal("600.00"), symbol="NAS100", ticket=f"w-{idx}", now=T_ASIA, in_recovery_mode=False
                )
            quota.record_realized_trade(
                Decimal("1252.73"), symbol="NAS100", ticket="w-6", now=T_ASIA, in_recovery_mode=False
            )
            for idx, loss_amt in enumerate((Decimal("-80.00"), Decimal("-60.00"), Decimal("-72.67"))):
                quota.record_realized_trade(
                    loss_amt, symbol="US30", ticket=f"l-{idx}", now=T_ASIA, in_recovery_mode=False
                )

            # Seed legacy underwater vault row ($666.08 prematurely swept before PR #21)
            vault_db = root / "vault.sqlite3"
            vault = ProfitSweepVault(vault_db, clock=lambda: T_ASIA)
            vault.record_realized_close(
                trade_id="w-6",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("1332.15"),
                occurred_at=datetime(2026, 11, 20, 0, 45, 0, tzinfo=timezone.utc),
                session_date="2026-11-20",
            )
            self.assertEqual(vault.snapshot()["bank_sweep_reserved_usd"], "666.08")

            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T_ASIA,
            )

            # 1. Strictly read-only status_snapshot() proof on BOTH SQLite databases
            v_conn = sqlite3.connect(str(vault_db))
            q_conn = sqlite3.connect(str(quota_db))
            try:
                v_dv_before = int(v_conn.execute("PRAGMA data_version").fetchone()[0])
                q_dv_before = int(q_conn.execute("PRAGMA data_version").fetchone()[0])
                v_se_before = int(v_conn.execute("SELECT COUNT(*) FROM sweep_events").fetchone()[0])
                q_rows_before = int(q_conn.execute("SELECT COUNT(*) FROM daily_quota_sessions").fetchone()[0])

                for check_ts in (T_ASIA, T_ASIA, T_LONDON):
                    _ = assert_safe_ai_catalog_payload(trader.status_snapshot(now=check_ts))

                self.assertEqual(int(v_conn.execute("PRAGMA data_version").fetchone()[0]), v_dv_before)
                self.assertEqual(int(q_conn.execute("PRAGMA data_version").fetchone()[0]), q_dv_before)
                self.assertEqual(int(v_conn.execute("SELECT COUNT(*) FROM sweep_events").fetchone()[0]), v_se_before)
                self.assertEqual(int(q_conn.execute("SELECT COUNT(*) FROM daily_quota_sessions").fetchone()[0]), q_rows_before)
            finally:
                v_conn.close()
                q_conn.close()

            # 2. Verify Asia RECOVERY_MODE snapshot & legacy $666.08 clawback to $0.00 on sync
            sync_asia = trader.sync_session_profit_to_vault(now=T_ASIA)
            self.assertIsNotNone(sync_asia)
            self.assertIsNone(trader.sync_session_profit_to_vault(now=T_ASIA))

            snap_asia = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_ASIA))
            bs_asia = snap_asia["banked_session"]
            self.assertEqual(bs_asia["session_date"], "2026-11-20-ASIA")
            self.assertEqual(bs_asia["initial_capital_usd"], "300000")
            self.assertEqual(bs_asia["current_total_equity_usd"], "282258.15")
            self.assertEqual(bs_asia["net_surplus_usd"], "-17741.85")
            self.assertEqual(bs_asia["net_surplus_pct"], "-5.91")
            self.assertEqual(bs_asia["deficit_to_principal_usd"], "17741.85")
            self.assertEqual(bs_asia["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertTrue(bs_asia["vault_sweeps_paused_for_recovery"])
            self.assertEqual(bs_asia["session_cadence"], SESSION_CADENCE_AUTO)
            self.assertEqual(bs_asia["active_region_window"], "ASIA (22:00–07:00 UTC / 14:00–23:00 PT)")
            self.assertEqual(bs_asia["next_session_opens_utc"], "2026-11-20T07:00:00Z")
            self.assertEqual(bs_asia["session_rollover_label"], "London Session 07:00 UTC (23:00 PT)")
            self.assertEqual(bs_asia["banked_net_pnl_usd"], "4640.06")
            self.assertEqual(bs_asia["vault_total_realized_usd"], "4640.06")
            self.assertEqual(bs_asia["vault_retained_50pct_usd"], "4640.06")
            self.assertEqual(bs_asia["vault_swept_50pct_usd"], "0")
            self.assertEqual(bs_asia["session_vault_reserved_50pct_usd"], "0")
            self.assertEqual(bs_asia["confirmed_bank_payouts_usd"], "0")
            self.assertTrue(bs_asia["profits_locked_for_session"])
            self.assertTrue(bs_asia["can_advance_recovery_session"])
            self.assertEqual(bs_asia["operating_mode"], FOCUS_MODE_RESEARCH_RESPITE)

            # 3. At 07:00 UTC (23:00 PT), London session opens automatically without manual clicks
            snap_london = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_LONDON))
            bs_london = snap_london["banked_session"]
            self.assertEqual(bs_london["session_date"], "2026-11-20-LONDON")
            self.assertEqual(bs_london["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)
            self.assertFalse(bs_london["profits_locked_for_session"])
            self.assertEqual(bs_london["active_region_window"], "LONDON (07:00–12:00 UTC / 23:00–04:00 PT)")
            self.assertEqual(bs_london["next_session_opens_utc"], "2026-11-20T12:00:00Z")

            # 4. Climb +$21,741.85 to $304,000.00 -> IN_SURPLUS (+$4,000 surplus -> $2,000 reserved / $2,000 retained)
            _set_router_total_equity(router, Decimal("304000.00"))
            trader.record_closed_pnl(
                Decimal("21741.85"), symbol="NAS100", ticket="surplus-breakout-1", now=T_LONDON
            )
            snap_surplus = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_LONDON))
            bs_surp = snap_surplus["banked_session"]
            self.assertEqual(bs_surp["capital_status"], CAPITAL_STATUS_IN_SURPLUS)
            self.assertFalse(bs_surp["vault_sweeps_paused_for_recovery"])
            self.assertEqual(bs_surp["current_total_equity_usd"], "304000")
            self.assertEqual(bs_surp["net_surplus_usd"], "4000")
            self.assertEqual(bs_surp["net_surplus_pct"], "1.33")
            self.assertEqual(bs_surp["deficit_to_principal_usd"], "0")
            self.assertEqual(bs_surp["vault_swept_50pct_usd"], "2000")
            self.assertEqual(bs_surp["confirmed_bank_payouts_usd"], "0")
            self.assertFalse(bs_surp["can_advance_recovery_session"])
            self.assertEqual(bs_surp["active_region_window"], "DAILY_NY (17:00 America/New_York)")
            self.assertEqual(bs_surp["session_rollover_label"], "17:00 America/New_York (14:00 Pacific)")
            self.assertEqual(snap_surplus["deployable_equity_usd"], "302000")

            # 5. Pullback -$4,500.00 to $299,500.00 -> back to RECOVERY_MODE, $0.00 vaulted!
            _set_router_total_equity(router, Decimal("299500.00"))
            trader.record_closed_pnl(
                Decimal("-4500.00"), symbol="US30", ticket="pullback-below-hwm", now=T_NY
            )
            snap_pb = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_NY))
            bs_pb = snap_pb["banked_session"]
            self.assertEqual(bs_pb["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertTrue(bs_pb["vault_sweeps_paused_for_recovery"])
            self.assertEqual(bs_pb["net_surplus_usd"], "-500")
            self.assertEqual(bs_pb["deficit_to_principal_usd"], "500")
            self.assertEqual(bs_pb["vault_swept_50pct_usd"], "0")
            self.assertEqual(bs_pb["active_region_window"], "NEW_YORK (12:00–22:00 UTC / 04:00–14:00 PT)")
            self.assertEqual(bs_pb["next_session_opens_utc"], "2026-11-20T22:00:00Z")

            audit_len = _verify_vault_audit_chain(self, vault_db)
            self.assertGreaterEqual(audit_len, 4)

    def test_contiguous_24h_regional_windows_and_3broker_default_principal(self) -> None:
        # 22:00 UTC Nov 19 through 06:59 UTC Nov 20 must all be ONE unbroken 2026-11-20-ASIA session
        base = datetime(2026, 11, 19, 22, 0, 0, tzinfo=timezone.utc)
        for offset_hours in range(9):
            w = regional_session_window_for(base + timedelta(hours=offset_hours, minutes=15))
            self.assertEqual(w["period_key"], "2026-11-20-ASIA")
            self.assertEqual(w["next_session_opens_utc"], "2026-11-20T07:00:00Z")

        # 07:00..11:59 UTC -> LONDON (5 hours)
        for hr in range(7, 12):
            w = regional_session_window_for(datetime(2026, 11, 20, hr, 30, 0, tzinfo=timezone.utc))
            self.assertEqual(w["period_key"], "2026-11-20-LONDON")
            self.assertEqual(w["next_session_opens_utc"], "2026-11-20T12:00:00Z")

        # 12:00..21:59 UTC -> NY (10 hours)
        for hr in range(12, 22):
            w = regional_session_window_for(datetime(2026, 11, 20, hr, 30, 0, tzinfo=timezone.utc))
            self.assertEqual(w["period_key"], "2026-11-20-NY")
            self.assertEqual(w["next_session_opens_utc"], "2026-11-20T22:00:00Z")

        # 22:00 UTC Nov 20 -> next Asia session 2026-11-21-ASIA
        w_next = regional_session_window_for(datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(w_next["period_key"], "2026-11-21-ASIA")
        self.assertEqual(w_next["next_session_opens_utc"], "2026-11-21T07:00:00Z")

        # Verify 3 configured demo brokers default initial_capital_usd to $300,000.00 automatically
        with tempfile.TemporaryDirectory() as spool_td:
            router_3 = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
                    "CAS_FOREX_MT5_SPOOL_DIR": spool_td,
                    "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                    "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
                    "CAS_FOREX_OANDA_PRACTICE_TOKEN": "demo-v1",
                    "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-123456-001",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("225806.52"),
                    BROKER_HUGOSWAY_MT5: Decimal("33870.98"),
                    BROKER_LHFX_MT5: Decimal("22580.65"),
                },
                clock=lambda: T_ASIA,
            )
            trader_3 = AutonomousAiTrader(
                router=router_3,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                execution_gate=lambda _inv: None,
                clock=lambda: T_ASIA,
            )
            bs_3 = trader_3.status_snapshot(now=T_ASIA)["banked_session"]
            self.assertEqual(bs_3["initial_capital_usd"], "300000")
            self.assertEqual(bs_3["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertEqual(bs_3["net_surplus_usd"], "-17741.85")

    def test_advance_recovery_session_30pct_giveback_cap_and_refusal_guards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("228000.00"),
                    BROKER_HUGOSWAY_MT5: Decimal("34200.00"),
                    BROKER_LHFX_MT5: Decimal("22800.00"),
                },
                clock=lambda: T_ASIA,
            )
            quota = DailyQuotaGovernanceStore(
                path=root / "quota_leg.sqlite3",
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
                max_loss_usd=Decimal("5000.00"),
            )
            vault = ProfitSweepVault(
                root / "vault_leg.sqlite3",
                initial_capital_usd=Decimal("300000.00"),
                clock=lambda: T_ASIA,
            )
            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T_ASIA,
            )

            # Cannot advance before locking profits
            with self.assertRaises(ContractError):
                trader.advance_recovery_session(reason="Too early", now=T_ASIA)

            # Lock +$4,000.00 in Leg 1 of 2026-11-20-ASIA
            trader.record_closed_pnl(Decimal("4000.00"), symbol="NAS100", ticket="leg1-win", now=T_ASIA)
            snap_l1 = trader.status_snapshot(now=T_ASIA)
            self.assertEqual(snap_l1["daily_quota"]["status"], QUOTA_STATUS_LOCKED)
            self.assertTrue(snap_l1["banked_session"]["can_advance_recovery_session"])
            self.assertEqual(snap_l1["banked_session"]["active_session_leg"], 1)
            self.assertEqual(snap_l1["banked_session"]["vault_swept_50pct_usd"], "0")

            # Advance to Leg 2: max loss capped at 30% of $4,000.00 = $1,200.00 (70% = $2,800 protected!)
            snap_l2 = trader.advance_recovery_session(reason="Owner resumed recovery leg 2", now=T_ASIA)
            self.assertEqual(snap_l2["banked_session"]["session_date"], "2026-11-20-ASIA#leg2")
            self.assertEqual(snap_l2["banked_session"]["active_session_leg"], 2)
            self.assertEqual(snap_l2["daily_quota"]["status"], QUOTA_STATUS_OPEN)
            self.assertEqual(snap_l2["daily_quota"]["max_daily_loss_usd"], "1200")
            self.assertEqual(snap_l2["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)

            # Verify Valve, drawdown wall, and 1,000% margin cushion remain 100% intact
            self.assertEqual(snap_l2["valve_controller"], "tks_meta_valve_controller")
            self.assertEqual(GATE.max_drawdown_pct, Decimal("0.10"))
            self.assertEqual(router.barbell.max_drawdown_pct, Decimal("0.10"))
            self.assertEqual(router._min_level, Decimal("1000"))

            # Verify Leg 1 locked row is permanently preserved in SQLite
            conn = sqlite3.connect(str(root / "quota_leg.sqlite3"))
            try:
                leg1_db = conn.execute(
                    "SELECT realized_net_pnl_usd, status FROM daily_quota_sessions WHERE session_date = ?",
                    ("2026-11-20-ASIA",),
                ).fetchone()
                self.assertEqual(str(leg1_db[0]), "4000")
                self.assertEqual(str(leg1_db[1]), QUOTA_STATUS_LOCKED)
            finally:
                conn.close()

            # Losing -$1,205 on Leg 2 trips DAILY_LOSS_CIRCUIT_TRIPPED and CANNOT be bypassed by advance_recovery_session
            trader.record_closed_pnl(Decimal("-1205.00"), symbol="US30", ticket="leg2-stop", now=T_ASIA)
            snap_tripped = trader.status_snapshot(now=T_ASIA)
            self.assertEqual(snap_tripped["daily_quota"]["status"], QUOTA_STATUS_LOSS_TRIPPED)
            self.assertFalse(snap_tripped["banked_session"]["can_advance_recovery_session"])
            with self.assertRaises(ContractError):
                trader.advance_recovery_session(reason="Attempt bypass loss circuit", now=T_ASIA)

            # Next region open (07:00 UTC London) resets active leg to 1 with standard loss limit
            snap_next_reg = trader.status_snapshot(now=T_LONDON)
            self.assertEqual(snap_next_reg["banked_session"]["session_date"], "2026-11-20-LONDON")
            self.assertEqual(snap_next_reg["banked_session"]["active_session_leg"], 1)
            self.assertEqual(snap_next_reg["daily_quota"]["status"], QUOTA_STATUS_OPEN)

            # Refused when IN_SURPLUS
            _set_router_total_equity(router, Decimal("305000.00"))
            trader.record_closed_pnl(Decimal("3500.00"), symbol="NAS100", ticket="surp-lock", now=T_LONDON)
            with self.assertRaises(ContractError):
                trader.advance_recovery_session(reason="Not allowed in surplus", now=T_LONDON)

    def test_cockpit_routes_and_legacy_vault_migration_and_disbursed_payout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 1. Legacy vault_config without initial_capital_usd_text migrates cleanly & respects settled payouts
            legacy_vdb = root / "legacy_cfg_vault.sqlite3"
            conn = sqlite3.connect(str(legacy_vdb))
            try:
                conn.execute(
                    """
                    CREATE TABLE vault_config (
                        scope_id TEXT PRIMARY KEY,
                        sweep_ratio_text TEXT NOT NULL,
                        auto_sweep_enabled INTEGER NOT NULL,
                        preferred_rail TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "INSERT INTO vault_config VALUES ('default', '0.5', 1, 'BROKER_2FA_MANUAL', '2026-11-19T00:00:00Z')"
                )
                conn.commit()
            finally:
                conn.close()

            migrated_vault = ProfitSweepVault(
                legacy_vdb,
                environ={ENV_INITIAL_CAPITAL_USD: "300000.00"},
                clock=lambda: T_ASIA,
            )
            self.assertEqual(migrated_vault.snapshot()["initial_capital_usd"], "300000")

            # Simulate $2,000 settled external bank payout + $308,000 broker equity => $310,000 economic equity ($10,000 surplus)
            conn2 = sqlite3.connect(str(legacy_vdb))
            try:
                conn2.execute(
                    """
                    INSERT INTO bank_transfers (
                        transfer_id, scope_id, rail, broker_id, destination_bank_id,
                        amount_usd_text, status, provider_tx_id, owner_request_id, reason, created_at, settled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "tr-settled-1",
                        "default",
                        "BROKER_2FA_MANUAL",
                        BROKER_OANDA_PRACTICE,
                        "OWNER_BANK",
                        "2000.00",
                        "SETTLED",
                        "tx-001",
                        "req-001",
                        "Settled payout",
                        "2026-11-20T01:00:00Z",
                        "2026-11-20T01:05:00Z",
                    ),
                )
                conn2.commit()
            finally:
                conn2.close()

            migrated_vault.reconcile_session_realized_profit(
                session_date="2026-11-20",
                session_realized_net_usd=Decimal("10000.00"),
                occurred_at=T_ASIA,
                total_equity_usd=Decimal("308000.00"),
            )
            msnap = migrated_vault.snapshot()
            self.assertEqual(msnap["bank_sweep_reserved_usd"], "5000")
            self.assertEqual(msnap["disbursed_to_bank_usd"], "2000")
            self.assertEqual(msnap["pending_disbursement_usd"], "3000")

            # 2. HTTP routes: /api/ai-trader-control, /api/ai-overseer-action, and /api/treasury-config
            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("225806.52"),
                    BROKER_HUGOSWAY_MT5: Decimal("33870.98"),
                    BROKER_LHFX_MT5: Decimal("22580.65"),
                },
                clock=lambda: T_ASIA,
            )
            quota = DailyQuotaGovernanceStore(
                path=root / "srv_quota.sqlite3",
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
            )
            srv_vault = ProfitSweepVault(root / "srv_vault.sqlite3", clock=lambda: T_ASIA)
            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=srv_vault,
                clock=lambda: T_ASIA,
            )
            trader.record_closed_pnl(Decimal("3500.00"), symbol="NAS100", ticket="http-leg1", now=T_ASIA)

            repo_root = Path(__file__).resolve().parents[2]
            srv = LoopbackCockpitServer(
                repo_root=repo_root,
                host="127.0.0.1",
                port=0,
                broker_router_reader=router.routing_snapshot,
                autonomous_trader=trader,
                profit_vault=srv_vault,
            )
            srv.start()
            try:
                c_unauth = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
                try:
                    c_unauth.request(
                        "POST",
                        "/api/ai-trader-control",
                        body=json.dumps({"action": "ADVANCE_RECOVERY_SESSION"}),
                        headers={"Content-Type": "application/json"},
                    )
                    self.assertEqual(c_unauth.getresponse().status, 401)
                finally:
                    c_unauth.close()

                hdrs = {**srv.auth_headers(), "Content-Type": "application/json"}

                def _post(route: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
                    hc = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
                    try:
                        hc.request("POST", route, body=json.dumps(payload), headers=hdrs)
                        resp = hc.getresponse()
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                    finally:
                        hc.close()

                st1, doc1 = _post(
                    "/api/ai-trader-control",
                    {"action": "SET_SESSION_CADENCE", "session_cadence": SESSION_CADENCE_REGIONAL_8H},
                )
                self.assertEqual(st1, 200)
                self.assertEqual(doc1["banked_session"]["session_cadence"], SESSION_CADENCE_REGIONAL_8H)

                st2, doc2 = _post(
                    "/api/ai-overseer-action",
                    {"action": "SET_SESSION_CADENCE", "session_cadence": SESSION_CADENCE_REGIONAL_RECOVERY},
                )
                self.assertEqual(st2, 200)
                self.assertEqual(doc2["banked_session"]["session_cadence"], SESSION_CADENCE_REGIONAL_RECOVERY)

                st3, doc3 = _post(
                    "/api/ai-trader-control",
                    {"action": "SET_SESSION_CADENCE", "session_cadence": SESSION_CADENCE_DAILY_NY},
                )
                self.assertEqual(st3, 200)
                self.assertEqual(doc3["banked_session"]["session_cadence"], SESSION_CADENCE_DAILY_NY)

                st4, doc4 = _post(
                    "/api/ai-trader-control",
                    {"action": "SET_SESSION_CADENCE", "session_cadence": SESSION_CADENCE_AUTO},
                )
                self.assertEqual(st4, 200)
                self.assertEqual(doc4["banked_session"]["session_cadence"], SESSION_CADENCE_AUTO)

                st5, doc5 = _post(
                    "/api/ai-trader-control",
                    {"action": "ADVANCE_RECOVERY_SESSION", "reason": "HTTP recovery leg advance"},
                )
                self.assertEqual(st5, 200)
                self.assertEqual(doc5["banked_session"]["active_session_leg"], 2)
                self.assertEqual(doc5["daily_quota"]["status"], QUOTA_STATUS_OPEN)

                st6, doc6 = _post("/api/treasury-config", {"initial_capital_usd": "300000.00"})
                self.assertEqual(st6, 200)
                self.assertEqual(doc6["initial_capital_usd"], "300000")
            finally:
                srv.stop()


if __name__ == "__main__":
    unittest.main()
