"""PR #21 verification tests (rev2 + addendum #171):
1. Slow Ledger (0.45s sleep) + Fault-Injected Startup Sync (OperationalError) vs Stop Protection:
   evaluate_fast_protection() amends open position SL in <0.1s with ZERO vault touches (and while another
   thread holds slow vault I/O), run_once() executes stop protection FIRST before startup vault sync,
   keeps _startup_vault_synced=False with 5s retry cooldown on failure, retries cleanly after cooldown,
   and run_cockpit_cli starts fast_poller BEFORE poller with zero pre-poller synchronous vault sync.
2. Rollover 100% Read-Only quota.sqlite3 proof across 17:00 NY daily rollover AND all 3 regional rollovers
   (ASIA -> LONDON -> NY -> next ASIA) with ?mode=ro URI, 0 new rows, and PRAGMA data_version unchanged.
3. Trading-Day-Wide Loss-Lock Carryover Across $300,000.00 in BOTH Directions ($301k -> $295k downward,
   split losses across $300k, and $299k -> $301k upward), cleared only on next trading day or OwnerRecoveryVerifier.
4. Pending / Unconfirmed Transfers Excluded from $300,000.00 Principal Switch ($298k + $5k RESERVED_PENDING_DISPATCH
   + $5k ACH_SUBMITTED + $5k OUTCOME_UNKNOWN => economic_eq=$298k, RECOVERY_MODE, $0 swept; ONLY SETTLED counts).
5. Wakil's exact benchmark journey, contiguous 24h regional windows, <=30% giveback recovery leg advance,
   and LoopbackCockpitServer HTTP control routes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import http.client
import inspect
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    CAPITAL_STATUS_IN_SURPLUS,
    CAPITAL_STATUS_RECOVERY_MODE,
    FOCUS_MODE_RESEARCH_RESPITE,
    OPERATING_MODE_ACTIVE_TRADING,
    AutonomousAiTrader,
)
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer, run_cockpit_cli
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.contracts import ActionKind, ContractError
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
T_ASIA = datetime(2026, 11, 20, 1, 15, 0, tzinfo=timezone.utc)
T_LONDON = datetime(2026, 11, 20, 7, 0, 0, tzinfo=timezone.utc)
T_NY = datetime(2026, 11, 20, 12, 30, 0, tzinfo=timezone.utc)
DUMMY_CRED = "demo-v1"


class _AmendableMt5Sdk:
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

    def __init__(self, login: int, server: str, event_log: list[str]) -> None:
        self._login = login
        self._server = server
        self._event_log = event_log
        self.bid = Decimal("20518.00")
        self.ask = Decimal("20520.00")
        self.rows: list[SimpleNamespace] = [
            SimpleNamespace(
                ticket=88001,
                symbol="NAS100",
                type=0,
                volume=Decimal("0.50"),
                price_open=Decimal("20500.00"),
                sl=Decimal("20475.00"),
                tp=Decimal("20580.00"),
                profit=Decimal("900.00"),
            )
        ]

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
            balance=33870.98,
            equity=33870.98,
            margin=2050.00,
            margin_free=31820.98,
            margin_level=1652.24,
            leverage=500,
        )

    def symbol_select(self, _sym: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, _sym: str) -> SimpleNamespace:
        return SimpleNamespace(bid=float(self.bid), ask=float(self.ask), time_msc=1795137300000)

    def positions_get(self) -> tuple[SimpleNamespace, ...]:
        return tuple(self.rows)

    def order_send(self, payload: dict[str, object]) -> SimpleNamespace:
        if int(payload.get("action", 0)) == self.TRADE_ACTION_SLTP:
            new_sl = Decimal(str(payload["sl"]))
            self.rows[0].sl = new_sl
            self._event_log.append(f"AMEND_STOP:{new_sl}")
            return SimpleNamespace(
                retcode=self.TRADE_RETCODE_DONE,
                deal=0,
                order=88001,
                volume=Decimal("0.50"),
                price=self.bid,
                comment="SL amended",
            )
        return SimpleNamespace(
            retcode=self.TRADE_RETCODE_DONE,
            deal=99001,
            order=88002,
            volume=Decimal("0.10"),
            price=self.ask,
            comment="OK",
        )


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
    def test_slow_ledger_and_fault_injected_startup_sync_never_delay_stop_protection(self) -> None:
        # Verify run_cockpit_cli starts fast_poller BEFORE poller and has zero synchronous pre-poller vault sync
        cli_src = inspect.getsource(run_cockpit_cli)
        fast_idx = cli_src.index("fast_poller.start()")
        poll_idx = cli_src.index("poller.start()")
        self.assertLess(fast_idx, poll_idx)
        self.assertNotIn("trader.sync_session_profit_to_vault()", cli_src[:fast_idx])

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            event_log: list[str] = []
            sdk = _AmendableMt5Sdk(login=1002903, server="Hugosway-Demo", event_log=event_log)
            oracle = OandaQuoteTruthOracle.from_static_quotes(
                {"NAS100": (Decimal("20518.00"), Decimal("20520.00"))}
            )
            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                oracle=oracle,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("225806.52"),
                    BROKER_HUGOSWAY_MT5: Decimal("33870.98"),
                    BROKER_LHFX_MT5: Decimal("22580.65"),
                },
                clock=lambda: T_ASIA,
            )
            hugo = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=Mt5Credentials(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    login=1002903,
                    server="Hugosway-Demo",
                    password=_RedactedSecret(DUMMY_CRED),
                    execution_mode=EXECUTION_MODE_DEMO,
                ),
                transport=Mt5NativePythonTransport(mt5_module=sdk, clock=lambda: T_ASIA),
                valve_gate=GATE,
                clock=lambda: T_ASIA,
            )
            hugo.connect()
            router.attach_venue(hugo)

            quota = DailyQuotaGovernanceStore(
                path=root / "quota_fault.sqlite3",
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
            )
            quota.observe_day_start(Decimal("282258.15"), now=T_ASIA, in_recovery_mode=True)
            quota.record_realized_trade(
                Decimal("4640.06"), symbol="NAS100", ticket="asia-locked", now=T_ASIA, in_recovery_mode=True
            )

            vault_db = root / "vault_fault.sqlite3"
            vault = ProfitSweepVault(vault_db, clock=lambda: T_ASIA)
            vault.record_realized_close(
                trade_id="legacy-underwater-row",
                symbol="NAS100",
                broker_id=BROKER_HUGOSWAY_MT5,
                realized_net_usd=Decimal("1332.15"),
                occurred_at=datetime(2026, 11, 20, 0, 45, 0, tzinfo=timezone.utc),
                session_date="2026-11-20",
            )
            self.assertEqual(vault.snapshot()["bank_sweep_reserved_usd"], "666.08")

            orig_reconcile = vault.reconcile_session_realized_profit
            orig_snapshot = vault.snapshot
            sync_attempts: list[datetime] = []
            vault_snap_touches: list[str] = []
            fail_sync = True
            slow_vault = True
            entered_slow_sync = threading.Event()

            def slow_snapshot() -> dict[str, object]:
                vault_snap_touches.append("SNAPSHOT")
                if slow_vault:
                    time.sleep(0.45)
                return orig_snapshot()

            def flaky_reconcile(**kwargs: object) -> dict[str, object] | None:
                occ = kwargs.get("occurred_at")
                sync_attempts.append(occ if isinstance(occ, datetime) else T_ASIA)
                event_log.append("VAULT_SYNC_ATTEMPT")
                entered_slow_sync.set()
                if slow_vault:
                    time.sleep(0.45)
                if fail_sync:
                    raise sqlite3.OperationalError("database is locked")
                return orig_reconcile(**kwargs)  # type: ignore[arg-type]

            vault.snapshot = slow_snapshot  # type: ignore[method-assign]
            vault.reconcile_session_realized_profit = flaky_reconcile  # type: ignore[method-assign]

            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                startup_vault_retry_cooldown_seconds=5.0,
                clock=lambda: T_ASIA,
            )
            self.assertFalse(trader._startup_vault_synced)

            # A. Test A (Slow 0.45s Ledger vs 50ms Stop Protection):
            #    evaluate_fast_protection() completes in <0.1s with ZERO vault touches!
            t0 = time.perf_counter()
            prot_1 = trader.evaluate_fast_protection(
                quotes={"NAS100": (Decimal("20518.00"), Decimal("20520.00"))},
                now=T_ASIA,
            )
            elapsed_prot = time.perf_counter() - t0
            self.assertLess(elapsed_prot, 0.10)
            self.assertEqual(len(prot_1), 1)
            self.assertEqual(prot_1[0]["stage"], "BREAKEVEN_LOCKED")
            self.assertEqual(prot_1[0]["new_stop_loss"], "20501.5")
            self.assertEqual(sdk.rows[0].sl, Decimal("20501.5"))
            self.assertEqual(len(vault_snap_touches), 0)
            self.assertEqual(len(sync_attempts), 0)
            self.assertFalse(trader._startup_vault_synced)

            # Also prove evaluate_fast_protection() is NOT blocked (<0.1s) even while background boot sync is sleeping 0.45s!
            bg_sync = threading.Thread(
                target=lambda: trader._attempt_startup_vault_sync_post_protection(T_ASIA),
                daemon=True,
            )
            bg_sync.start()
            self.assertTrue(entered_slow_sync.wait(timeout=2.0))
            sdk.bid = Decimal("20526.00")
            sdk.ask = Decimal("20528.00")
            t_conc = time.perf_counter()
            prot_conc = trader.evaluate_fast_protection(
                quotes={"NAS100": (Decimal("20526.00"), Decimal("20528.00"))},
                now=T_ASIA,
            )
            elapsed_conc = time.perf_counter() - t_conc
            bg_sync.join(timeout=2.0)
            self.assertLess(elapsed_conc, 0.10)
            self.assertEqual(len(prot_conc), 1)
            self.assertEqual(prot_conc[0]["stage"], "TRAILING_ACTIVE")

            # Reset cooldown for deterministic run_once() stop-protection-first + retry-cooldown proof
            slow_vault = False
            sync_attempts.clear()
            event_log.clear()
            trader._startup_vault_synced = False
            trader._startup_vault_next_retry_at = None

            # B. Call 1 of run_once() with NAS100 advancing to 20535/20537:
            #    Stop protection MUST execute FIRST (TRAILING_ACTIVE -> 20527.8), BEFORE vault sync raises OperationalError!
            sdk.bid = Decimal("20535.00")
            sdk.ask = Decimal("20537.00")
            cyc_1 = trader.run_once(
                None,
                mt5_quotes={"NAS100": (Decimal("20535.00"), Decimal("20537.00"))},
                fast_tick=True,
                now=T_ASIA,
            )
            self.assertEqual(len(cyc_1["protection_updates"]), 1)
            self.assertEqual(cyc_1["protection_updates"][0]["stage"], "TRAILING_ACTIVE")
            self.assertEqual(cyc_1["protection_updates"][0]["new_stop_loss"], "20527.8")
            self.assertEqual(sdk.rows[0].sl, Decimal("20527.8"))
            self.assertEqual(event_log, ["AMEND_STOP:20527.8", "VAULT_SYNC_ATTEMPT"])
            self.assertEqual(len(sync_attempts), 1)
            self.assertFalse(trader._startup_vault_synced)
            self.assertEqual(trader._last_vault_sync_error, "OperationalError")
            self.assertEqual(trader._startup_vault_next_retry_at, T_ASIA + timedelta(seconds=5))

            # C. Within 5s cooldown (T_ASIA + 2s): does NOT hammer SQLite
            _ = trader.run_once(
                None,
                mt5_quotes={"NAS100": (Decimal("20535.00"), Decimal("20537.00"))},
                fast_tick=True,
                now=T_ASIA + timedelta(seconds=2),
            )
            self.assertEqual(len(sync_attempts), 1)
            self.assertFalse(trader._startup_vault_synced)

            # D. Call 2 after retry window (T_ASIA + 6s) with SQLite lock cleared: retries, claws back $666.08 -> $0, sets True!
            fail_sync = False
            _ = trader.run_once(
                None,
                mt5_quotes={"NAS100": (Decimal("20535.00"), Decimal("20537.00"))},
                fast_tick=True,
                now=T_ASIA + timedelta(seconds=6),
            )
            self.assertEqual(len(sync_attempts), 2)
            self.assertTrue(trader._startup_vault_synced)
            self.assertIsNone(trader._startup_vault_next_retry_at)
            self.assertIsNone(trader._last_vault_sync_error)
            self.assertEqual(orig_snapshot()["bank_sweep_reserved_usd"], "0")
            self.assertEqual(orig_snapshot()["total_realized_profit_usd"], "4640.06")

    def test_loss_lock_carryover_across_300k_threshold_both_directions_and_owner_unlock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 1. Downward crossing ($301,000 -> $295,000, in_recovery_mode flips False -> True)
            router_down = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("240800.00"),
                    BROKER_HUGOSWAY_MT5: Decimal("36120.00"),
                    BROKER_LHFX_MT5: Decimal("24080.00"),
                },
                clock=lambda: T_LONDON,
            )
            q_down = DailyQuotaGovernanceStore(
                path=root / "q_down.sqlite3",
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
                max_loss_usd=Decimal("5000.00"),
                max_consecutive_losses=3,
            )
            t_down = AutonomousAiTrader(
                router=router_down,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=q_down,
                execution_gate=lambda _inv: None,
                clock=lambda: T_LONDON,
            )
            # At $301,000 (IN_SURPLUS -> daily row 2026-11-20), lose -$6,000 -> trips DAILY_LOSS_CIRCUIT_TRIPPED
            q_down.record_realized_trade(
                Decimal("-6000.00"),
                symbol="NAS100",
                ticket="surp-big-loss",
                starting_equity=Decimal("301000.00"),
                now=T_LONDON,
                in_recovery_mode=False,
            )
            # Equity is now $295,000 (< $300,000 -> in_recovery_mode=True -> regional row 2026-11-20-LONDON)
            _set_router_total_equity(router_down, Decimal("295000.00"))
            ok_d, rsn_d, mult_d = q_down.evaluate_new_risk(
                ActionKind.OPEN, now=T_LONDON, starting_equity=Decimal("295000.00"), in_recovery_mode=True
            )
            self.assertFalse(ok_d)
            self.assertEqual(rsn_d, QUOTA_STATUS_LOSS_TRIPPED)
            self.assertEqual(mult_d, Decimal("0"))
            snap_qd = q_down.snapshot(now=T_LONDON, starting_equity=Decimal("295000.00"), in_recovery_mode=True)
            self.assertEqual(snap_qd["session_date"], "2026-11-20-LONDON")
            self.assertEqual(snap_qd["status"], QUOTA_STATUS_LOSS_TRIPPED)
            self.assertFalse(snap_qd["new_risk_allowed"])
            snap_td = t_down.status_snapshot(now=T_LONDON)
            self.assertEqual(snap_td["banked_session"]["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertEqual(snap_td["daily_quota"]["status"], QUOTA_STATUS_LOSS_TRIPPED)

            # 2. Split losses across $300k ($301k loses -$3,000 -> $298k loses -$2,100 => -$5,100 <= -$5,000)
            q_split = DailyQuotaGovernanceStore(
                path=root / "q_split.sqlite3",
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
                max_loss_usd=Decimal("5000.00"),
                max_consecutive_losses=5,
            )
            s_part1 = q_split.record_realized_trade(
                Decimal("-3000.00"),
                symbol="NAS100",
                ticket="sp-1",
                starting_equity=Decimal("301000.00"),
                now=T_LONDON,
                in_recovery_mode=False,
            )
            self.assertEqual(s_part1["status"], QUOTA_STATUS_OPEN)
            s_part2 = q_split.record_realized_trade(
                Decimal("-2100.00"),
                symbol="US30",
                ticket="sp-2",
                starting_equity=Decimal("298000.00"),
                now=T_LONDON + timedelta(minutes=5),
                in_recovery_mode=True,
            )
            self.assertEqual(s_part2["status"], QUOTA_STATUS_LOSS_TRIPPED)
            self.assertFalse(s_part2["new_risk_allowed"])

            # 3. Upward crossing ($299,000 regional loss trip -> equity ticks to $301,000, in_recovery_mode True -> False)
            router_up = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("239200.00"),
                    BROKER_HUGOSWAY_MT5: Decimal("35880.00"),
                    BROKER_LHFX_MT5: Decimal("23920.00"),
                },
                clock=lambda: T_LONDON,
            )
            q_up_db = root / "q_up.sqlite3"
            q_up = DailyQuotaGovernanceStore(
                path=q_up_db,
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
                max_loss_usd=Decimal("5000.00"),
                max_consecutive_losses=3,
            )
            t_up = AutonomousAiTrader(
                router=router_up,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=q_up,
                execution_gate=lambda _inv: None,
                clock=lambda: T_LONDON,
            )
            for idx in range(3):
                q_up.record_realized_trade(
                    Decimal("-100.00"),
                    symbol="EURUSD",
                    ticket=f"reg-loss-{idx}",
                    starting_equity=Decimal("299000.00"),
                    now=T_LONDON + timedelta(minutes=idx),
                    in_recovery_mode=True,
                )
            # Equity rises to $301,000 (>= $300,000 -> in_recovery_mode=False -> daily row 2026-11-20)
            _set_router_total_equity(router_up, Decimal("301000.00"))
            ok_u, rsn_u, mult_u = q_up.evaluate_new_risk(
                ActionKind.OPEN, now=T_LONDON + timedelta(minutes=10), starting_equity=Decimal("301000.00"), in_recovery_mode=False
            )
            self.assertFalse(ok_u)
            self.assertEqual(rsn_u, QUOTA_STATUS_LOSS_TRIPPED)
            self.assertEqual(mult_u, Decimal("0"))
            snap_qu = q_up.snapshot(
                now=T_LONDON + timedelta(minutes=10), starting_equity=Decimal("301000.00"), in_recovery_mode=False
            )
            self.assertEqual(snap_qu["session_date"], "2026-11-20")
            self.assertEqual(snap_qu["status"], QUOTA_STATUS_LOSS_TRIPPED)
            snap_tu = t_up.status_snapshot(now=T_LONDON + timedelta(minutes=10))
            self.assertEqual(snap_tu["banked_session"]["capital_status"], CAPITAL_STATUS_IN_SURPLUS)
            self.assertEqual(snap_tu["daily_quota"]["status"], QUOTA_STATUS_LOSS_TRIPPED)

            # Owner recovery unlock clears day-wide loss trip cleanly
            verifier = OwnerRecoveryVerifier(db_path=q_up_db, clock=lambda: T_LONDON + timedelta(minutes=15))
            tok = verifier.mint_token(action_scope="UNLOCK_QUOTA_SESSION", now=T_LONDON + timedelta(minutes=15))
            unlocked = q_up.unlock_session(
                owner_request_id="owner-unlk-up-1",
                reason="Verified owner unlock",
                recovery_verifier=verifier,
                recovery_token=tok,
                now=T_LONDON + timedelta(minutes=15),
                in_recovery_mode=False,
            )
            self.assertEqual(unlocked["status"], QUOTA_STATUS_OPEN)
            ok_after, _, _ = q_up.evaluate_new_risk(
                ActionKind.OPEN, now=T_LONDON + timedelta(minutes=16), starting_equity=Decimal("301000.00"), in_recovery_mode=False
            )
            self.assertTrue(ok_after)

    def test_pending_and_unconfirmed_transfers_excluded_from_300k_surplus_switch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault_db = root / "vault_transfers.sqlite3"
            vault = ProfitSweepVault(
                vault_db,
                initial_capital_usd=Decimal("300000.00"),
                clock=lambda: T_ASIA,
            )
            conn = sqlite3.connect(str(vault_db))
            try:
                for idx, st_code in enumerate(
                    ("RESERVED_PENDING_DISPATCH", "ACH_SUBMITTED", "OUTCOME_UNKNOWN"), start=1
                ):
                    conn.execute(
                        """
                        INSERT INTO bank_transfers (
                            transfer_id, scope_id, rail, broker_id, destination_bank_id,
                            amount_usd_text, status, provider_tx_id, owner_request_id, reason, created_at, settled_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"tr-unconf-{idx}",
                            "default",
                            "COINBASE_ACH",
                            None,
                            "OWNER_BANK",
                            "5000.00",
                            st_code,
                            f"tx-u-{idx}",
                            f"req-u-{idx}",
                            "In-flight test",
                            "2026-11-20T01:00:00Z",
                            None,
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_INITIAL_CAPITAL_USD: "300000.00",
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("238400.00"),
                    BROKER_HUGOSWAY_MT5: Decimal("35760.00"),
                    BROKER_LHFX_MT5: Decimal("23840.00"),
                },
                clock=lambda: T_ASIA,
            )
            self.assertEqual(router.barbell.total_equity(router.equities()), Decimal("298000.00"))

            quota = DailyQuotaGovernanceStore(path=root / "q_tr.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T_ASIA,
            )
            trader.record_closed_pnl(Decimal("2500.00"), symbol="NAS100", ticket="win-under-300k", now=T_ASIA)

            v_snap = vault.snapshot()
            self.assertEqual(v_snap["confirmed_settled_disbursed_usd"], "0")
            self.assertEqual(v_snap["pending_or_unconfirmed_transfers_usd"], "15000")
            self.assertEqual(v_snap["bank_sweep_reserved_usd"], "0")

            t_snap = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_ASIA))
            bs = t_snap["banked_session"]
            ps = trader._principal_surplus_metrics(Decimal("298000.00"), v_snap=v_snap)
            self.assertEqual(ps["economic_equity_usd"], Decimal("298000.00"))
            self.assertEqual(bs["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertTrue(bs["vault_sweeps_paused_for_recovery"])
            self.assertEqual(bs["net_surplus_usd"], "-2000")
            self.assertEqual(bs["confirmed_bank_payouts_usd"], "0")
            self.assertEqual(bs["pending_unconfirmed_transfers_usd"], "15000")
            self.assertEqual(bs["vault_swept_50pct_usd"], "0")

            # Now transition tr-unconf-1 ($5,000.00) to SETTLED -> economic_eq becomes $298k + $5k = $303k (IN_SURPLUS!)
            conn2 = sqlite3.connect(str(vault_db))
            try:
                conn2.execute(
                    "UPDATE bank_transfers SET status = 'SETTLED', settled_at = '2026-11-20T01:20:00Z' WHERE transfer_id = 'tr-unconf-1'"
                )
                conn2.commit()
            finally:
                conn2.close()

            trader.sync_session_profit_to_vault(now=T_ASIA + timedelta(minutes=10))
            v_settled = vault.snapshot()
            self.assertEqual(v_settled["confirmed_settled_disbursed_usd"], "5000")
            self.assertEqual(v_settled["pending_or_unconfirmed_transfers_usd"], "10000")
            t_settled = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_ASIA + timedelta(minutes=10)))
            bs_s = t_settled["banked_session"]
            self.assertEqual(bs_s["capital_status"], CAPITAL_STATUS_IN_SURPLUS)
            self.assertEqual(bs_s["net_surplus_usd"], "3000")
            self.assertEqual(bs_s["confirmed_bank_payouts_usd"], "5000")
            self.assertEqual(bs_s["pending_unconfirmed_transfers_usd"], "10000")

    def test_rollover_snapshot_pure_readonly_across_ny_and_all_3_regions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            quota_db = root / "quota_rollover.sqlite3"
            vault_db = root / "vault_rollover.sqlite3"
            quota = DailyQuotaGovernanceStore(
                path=quota_db,
                soft_quota_usd=Decimal("2000.00"),
                hard_quota_usd=Decimal("3000.00"),
                max_loss_usd=Decimal("5000.00"),
            )
            t_day1_ny = datetime(2026, 11, 19, 18, 0, 0, tzinfo=timezone.utc)
            quota.observe_day_start(Decimal("305000.00"), now=t_day1_ny, in_recovery_mode=False)
            quota.record_realized_trade(
                Decimal("3200.00"), symbol="NAS100", ticket="ny-d1", now=t_day1_ny, in_recovery_mode=False
            )
            quota.observe_day_start(Decimal("282258.15"), now=T_ASIA, in_recovery_mode=True)
            quota.record_realized_trade(
                Decimal("3500.00"), symbol="NAS100", ticket="asia-r1", now=T_ASIA, in_recovery_mode=True
            )

            vault = ProfitSweepVault(
                vault_db,
                initial_capital_usd=Decimal("300000.00"),
                clock=lambda: T_ASIA,
            )
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
            trader = AutonomousAiTrader(
                router=router,
                model_registry=FrontierModelRegistry(environ={}),
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                clock=lambda: T_ASIA,
            )

            ro_q = sqlite3.connect(f"{quota_db.resolve().as_uri()}?mode=ro", uri=True)
            ro_v = sqlite3.connect(f"{vault_db.resolve().as_uri()}?mode=ro", uri=True)
            try:
                q_dv_before = int(ro_q.execute("PRAGMA data_version").fetchone()[0])
                v_dv_before = int(ro_v.execute("PRAGMA data_version").fetchone()[0])
                q_rows_before = int(ro_q.execute("SELECT COUNT(*) FROM daily_quota_sessions").fetchone()[0])
                q_ev_before = int(ro_q.execute("SELECT COUNT(*) FROM daily_quota_events").fetchone()[0])
                self.assertEqual(q_rows_before, 2)

                _set_router_total_equity(router, Decimal("305000.00"))
                for t_ny_roll, expected_sdate in (
                    (datetime(2026, 11, 19, 22, 5, 0, tzinfo=timezone.utc), "2026-11-20"),
                    (datetime(2026, 11, 20, 22, 5, 0, tzinfo=timezone.utc), "2026-11-21"),
                ):
                    s_q = quota.snapshot(now=t_ny_roll, starting_equity=Decimal("305000.00"), in_recovery_mode=False)
                    self.assertEqual(s_q["session_date"], expected_sdate)
                    self.assertEqual(s_q["status"], QUOTA_STATUS_OPEN)
                    self.assertTrue(s_q["new_risk_allowed"])
                    self.assertEqual(s_q["realized_net_pnl_usd"], "0")
                    self.assertEqual(s_q["peak_realized_pnl_usd"], "0")
                    self.assertEqual(s_q["protected_profit_floor_usd"], "0")

                    s_t = assert_safe_ai_catalog_payload(trader.status_snapshot(now=t_ny_roll))
                    self.assertEqual(s_t["banked_session"]["session_date"], expected_sdate)
                    self.assertEqual(s_t["daily_quota"]["status"], QUOTA_STATUS_OPEN)

                _set_router_total_equity(router, Decimal("282258.15"))
                for t_reg, expected_reg_key in (
                    (datetime(2026, 11, 20, 7, 0, 0, tzinfo=timezone.utc), "2026-11-20-LONDON"),
                    (datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc), "2026-11-20-NY"),
                    (datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc), "2026-11-21-ASIA"),
                ):
                    s_reg = quota.snapshot(now=t_reg, starting_equity=Decimal("282258.15"), in_recovery_mode=True)
                    self.assertEqual(s_reg["session_date"], expected_reg_key)
                    self.assertEqual(s_reg["status"], QUOTA_STATUS_OPEN)
                    self.assertTrue(s_reg["new_risk_allowed"])
                    self.assertEqual(s_reg["realized_net_pnl_usd"], "0")

                    s_tr = assert_safe_ai_catalog_payload(trader.status_snapshot(now=t_reg))
                    self.assertEqual(s_tr["banked_session"]["session_date"], expected_reg_key)
                    self.assertEqual(s_tr["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)

                self.assertEqual(int(ro_q.execute("SELECT COUNT(*) FROM daily_quota_sessions").fetchone()[0]), q_rows_before)
                self.assertEqual(int(ro_q.execute("SELECT COUNT(*) FROM daily_quota_events").fetchone()[0]), q_ev_before)
                self.assertEqual(int(ro_q.execute("PRAGMA data_version").fetchone()[0]), q_dv_before)
                self.assertEqual(int(ro_v.execute("PRAGMA data_version").fetchone()[0]), v_dv_before)
            finally:
                ro_q.close()
                ro_v.close()

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

            sync_asia = trader.sync_session_profit_to_vault(now=T_ASIA)
            self.assertIsNotNone(sync_asia)
            self.assertTrue(trader._startup_vault_synced)
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

            snap_london = assert_safe_ai_catalog_payload(trader.status_snapshot(now=T_LONDON))
            bs_london = snap_london["banked_session"]
            self.assertEqual(bs_london["session_date"], "2026-11-20-LONDON")
            self.assertEqual(bs_london["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)
            self.assertFalse(bs_london["profits_locked_for_session"])
            self.assertEqual(bs_london["active_region_window"], "LONDON (07:00–12:00 UTC / 23:00–04:00 PT)")
            self.assertEqual(bs_london["next_session_opens_utc"], "2026-11-20T12:00:00Z")

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
        base = datetime(2026, 11, 19, 22, 0, 0, tzinfo=timezone.utc)
        for offset_hours in range(9):
            w = regional_session_window_for(base + timedelta(hours=offset_hours, minutes=15))
            self.assertEqual(w["period_key"], "2026-11-20-ASIA")
            self.assertEqual(w["next_session_opens_utc"], "2026-11-20T07:00:00Z")

        for hr in range(7, 12):
            w = regional_session_window_for(datetime(2026, 11, 20, hr, 30, 0, tzinfo=timezone.utc))
            self.assertEqual(w["period_key"], "2026-11-20-LONDON")
            self.assertEqual(w["next_session_opens_utc"], "2026-11-20T12:00:00Z")

        for hr in range(12, 22):
            w = regional_session_window_for(datetime(2026, 11, 20, hr, 30, 0, tzinfo=timezone.utc))
            self.assertEqual(w["period_key"], "2026-11-20-NY")
            self.assertEqual(w["next_session_opens_utc"], "2026-11-20T22:00:00Z")

        w_next = regional_session_window_for(datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(w_next["period_key"], "2026-11-21-ASIA")
        self.assertEqual(w_next["next_session_opens_utc"], "2026-11-21T07:00:00Z")

        with tempfile.TemporaryDirectory() as spool_td:
            router_3 = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
                    "CAS_FOREX_MT5_SPOOL_DIR": spool_td,
                    "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                    "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
                    "CAS_FOREX_OANDA_PRACTICE_TOKEN": DUMMY_CRED,
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

            with self.assertRaises(ContractError):
                trader.advance_recovery_session(reason="Too early", now=T_ASIA)

            trader.record_closed_pnl(Decimal("4000.00"), symbol="NAS100", ticket="leg1-win", now=T_ASIA)
            snap_l1 = trader.status_snapshot(now=T_ASIA)
            self.assertEqual(snap_l1["daily_quota"]["status"], QUOTA_STATUS_LOCKED)
            self.assertTrue(snap_l1["banked_session"]["can_advance_recovery_session"])
            self.assertEqual(snap_l1["banked_session"]["active_session_leg"], 1)
            self.assertEqual(snap_l1["banked_session"]["vault_swept_50pct_usd"], "0")

            snap_l2 = trader.advance_recovery_session(reason="Owner resumed recovery leg 2", now=T_ASIA)
            self.assertEqual(snap_l2["banked_session"]["session_date"], "2026-11-20-ASIA#leg2")
            self.assertEqual(snap_l2["banked_session"]["active_session_leg"], 2)
            self.assertEqual(snap_l2["daily_quota"]["status"], QUOTA_STATUS_OPEN)
            self.assertEqual(snap_l2["daily_quota"]["max_daily_loss_usd"], "1200")
            self.assertEqual(snap_l2["operating_mode"], OPERATING_MODE_ACTIVE_TRADING)

            self.assertEqual(snap_l2["valve_controller"], "tks_meta_valve_controller")
            self.assertEqual(GATE.max_drawdown_pct, Decimal("0.10"))
            self.assertEqual(router.barbell.max_drawdown_pct, Decimal("0.10"))
            self.assertEqual(router._min_level, Decimal("1000"))

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

            trader.record_closed_pnl(Decimal("-1205.00"), symbol="US30", ticket="leg2-stop", now=T_ASIA)
            snap_tripped = trader.status_snapshot(now=T_ASIA)
            self.assertEqual(snap_tripped["daily_quota"]["status"], QUOTA_STATUS_LOSS_TRIPPED)
            self.assertFalse(snap_tripped["banked_session"]["can_advance_recovery_session"])
            with self.assertRaises(ContractError):
                trader.advance_recovery_session(reason="Attempt bypass loss circuit", now=T_ASIA)

            # Same trading day London (2026-11-20-LONDON) keeps trading-day-wide loss circuit locked!
            snap_same_day_lon = trader.status_snapshot(now=T_LONDON)
            self.assertEqual(snap_same_day_lon["banked_session"]["session_date"], "2026-11-20-LONDON")
            self.assertEqual(snap_same_day_lon["daily_quota"]["status"], QUOTA_STATUS_LOSS_TRIPPED)

            # Next trading day London (2026-11-21T07:00:00Z) resets active leg to 1 with OPEN status
            t_next_day_lon = datetime(2026, 11, 21, 7, 0, 0, tzinfo=timezone.utc)
            snap_next_day = trader.status_snapshot(now=t_next_day_lon)
            self.assertEqual(snap_next_day["banked_session"]["session_date"], "2026-11-21-LONDON")
            self.assertEqual(snap_next_day["banked_session"]["active_session_leg"], 1)
            self.assertEqual(snap_next_day["daily_quota"]["status"], QUOTA_STATUS_OPEN)

            # Refused when IN_SURPLUS
            _set_router_total_equity(router, Decimal("305000.00"))
            trader.record_closed_pnl(Decimal("3500.00"), symbol="NAS100", ticket="surp-lock", now=t_next_day_lon)
            with self.assertRaises(ContractError):
                trader.advance_recovery_session(reason="Not allowed in surplus", now=t_next_day_lon)

    def test_cockpit_routes_and_legacy_vault_migration_and_disbursed_payout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
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
            self.assertEqual(msnap["confirmed_settled_disbursed_usd"], "2000")
            self.assertEqual(msnap["pending_or_unconfirmed_transfers_usd"], "0")
            self.assertEqual(msnap["pending_disbursement_usd"], "3000")

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
