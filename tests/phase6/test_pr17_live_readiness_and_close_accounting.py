"""PR #17 verification tests:
1. DualShieldBrokerRouter.live_funding_readiness() & routing_snapshot()["live_readiness"] in DEMO vs staged/armed LIVE mode.
2. Broker-closed stale_tkt accounting in AutonomousAiTrader.protect_open_positions() -> DailyQuotaGovernanceStore & 3-Gear AUTO_ADAPTIVE downshift to CONSERVATIVE.
3. Opposite-side self-hedge blocking in AutonomousAiTrader._assess_setup_and_pyramid().
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    ACTIVE_GEAR_CONSERVATIVE,
    ACTIVE_GEAR_STRONG_TREND_RUNNER,
    RISK_GEAR_AUTO_ADAPTIVE,
    AutonomousAiTrader,
)
from cas_forex_revamp.composition.live_cockpit_server import safe_broker_routing_payload
from cas_forex_revamp.composition.trend_regime import REGIME_STRONG_TREND
from cas_forex_revamp.contracts import Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import (
    ENV_DEMO_BARBELL_VIRTUAL_SLEEVE,
    ENV_HUGOSWAY_MT5_LIVE_TICKET,
    ENV_LHFX_MT5_LIVE_TICKET,
    ENV_OANDA_LIVE_API_TOKEN,
    ENV_OANDA_LIVE_TICKET,
    LIVE_FUNDING_ARM_PHRASE,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_EXECUTION_MODE,
    ENV_LIVE_ARM_PHRASE,
    ENV_OANDA_LIVE_ACCOUNT_ID,
    ENV_OANDA_LIVE_TOKEN,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    OandaMutationJournal,
    REQUIRED_LIVE_ARM_PHRASE,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    ENV_LIVE_AUTH_KEY_FILE,
    ENV_LIVE_AUTH_TICKET_FILE,
    mint_live_authorization_bundle,
    provision_live_auth_key,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_LIVE,
    BROKER_OANDA_PRACTICE,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_PASSWORD,
    ENV_LHFX_MT5_SERVER,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5NativePythonTransport,
    Mt5PaperBrokerVenue,
    _RedactedSecret,
)

GATE = load_default_forex_valve_gate()
T0 = datetime(2026, 11, 19, 17, 0, 0, tzinfo=timezone.utc)
DUMMY_VAL = "demo-v1"


class _MutablePositionMt5Sdk:
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
            balance=12000.0,
            equity=12000.0,
            margin=0.0,
            margin_free=12000.0,
            margin_level=0.0,
            leverage=500,
        )

    def symbol_select(self, _sym: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, _sym: str) -> SimpleNamespace:
        return SimpleNamespace(bid=1.09800, ask=1.09810, time_msc=1795107600000)

    def positions_get(self) -> tuple[SimpleNamespace, ...]:
        return self.rows


class Pr17LiveReadinessAndCloseAccountingTests(unittest.TestCase):
    def test_live_readiness_snapshot_demo_vs_staged_and_armed_live_mode(self) -> None:
        # 1. Default DEMO virtual-sleeve mode: all 5 Real-Money LIVE gates report passed=False
        router_demo = DualShieldBrokerRouter(
            environ={
                ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "1",
            },
            valve_gate=GATE,
            equity_attestations={
                BROKER_OANDA_PRACTICE: Decimal("100000"),
                BROKER_HUGOSWAY_MT5: Decimal("100000"),
                BROKER_LHFX_MT5: Decimal("100000"),
            },
            clock=lambda: T0,
        )
        snap_demo = safe_broker_routing_payload(router_demo.routing_snapshot())
        lr_demo = snap_demo["live_readiness"]
        self.assertEqual(lr_demo["execution_mode"], EXECUTION_MODE_DEMO)
        self.assertFalse(lr_demo["live_armed"])
        self.assertEqual(lr_demo["required_arm_phrase"], LIVE_FUNDING_ARM_PHRASE)
        self.assertFalse(lr_demo["all_gates_ready"])
        self.assertEqual(len(lr_demo["gates"]), 5)
        expected_ids = [
            "LIVE_CREDENTIALS_STAGED",
            "OWNER_ED25519_LIVE_TICKETS",
            "REAL_BARBELL_80_12_8_CUSTODY",
            "VALVE_AND_DURABLE_JOURNALS",
            "TWO_KEY_LIVE_ARMED",
        ]
        self.assertEqual([g["id"] for g in lr_demo["gates"]], expected_ids)
        self.assertEqual([g["step"] for g in lr_demo["gates"]], [1, 2, 3, 4, 5])
        for gate_item in lr_demo["gates"]:
            self.assertFalse(gate_item["passed"], gate_item["id"])

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_file = root / "durable_journal.sqlite3"

            # 2. Staged LIVE credentials + Ed25519 tickets + 80/12/8 barbell + durable journals while still in DEMO mode
            router_staged = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "0",
                    ENV_OANDA_LIVE_ACCOUNT_ID: "001-001-9900112-001",
                    ENV_OANDA_LIVE_API_TOKEN: DUMMY_VAL,
                    ENV_HUGOSWAY_MT5_LIVE_TICKET: DUMMY_VAL,
                    ENV_LHFX_MT5_LIVE_TICKET: DUMMY_VAL,
                    ENV_OANDA_LIVE_TICKET: DUMMY_VAL,
                },
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("8000"),
                    BROKER_HUGOSWAY_MT5: Decimal("1200"),
                    BROKER_LHFX_MT5: Decimal("800"),
                },
                mt5_mutation_journal=Mt5MutationJournal(db_file),
                oanda_mutation_journal=OandaMutationJournal(db_file),
                clock=lambda: T0,
            )
            router_staged._env[ENV_HUGOSWAY_MT5_LOGIN] = "9001122"
            router_staged._env[ENV_HUGOSWAY_MT5_SERVER] = "Hugosway-Real3"
            router_staged._env[ENV_LHFX_MT5_LOGIN] = "9003344"
            router_staged._env[ENV_LHFX_MT5_SERVER] = "LHFXSA-Live"
            lr_staged = safe_broker_routing_payload(router_staged.routing_snapshot())["live_readiness"]
            by_id_staged = {g["id"]: g["passed"] for g in lr_staged["gates"]}
            self.assertTrue(by_id_staged["LIVE_CREDENTIALS_STAGED"])
            self.assertTrue(by_id_staged["OWNER_ED25519_LIVE_TICKETS"])
            self.assertTrue(by_id_staged["REAL_BARBELL_80_12_8_CUSTODY"])
            self.assertTrue(by_id_staged["VALVE_AND_DURABLE_JOURNALS"])
            self.assertFalse(by_id_staged["TWO_KEY_LIVE_ARMED"])
            self.assertFalse(lr_staged["all_gates_ready"])

            # Drifted barbell shares outside +/-0.02 tolerance fail Gate 3
            router_drifted = DualShieldBrokerRouter(
                environ={ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO, ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "0"},
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("5000"),
                    BROKER_HUGOSWAY_MT5: Decimal("3000"),
                    BROKER_LHFX_MT5: Decimal("2000"),
                },
                clock=lambda: T0,
            )
            by_id_drifted = {g["id"]: g["passed"] for g in router_drifted.live_funding_readiness()["gates"]}
            self.assertFalse(by_id_drifted["REAL_BARBELL_80_12_8_CUSTODY"])

            # 3. Full Two-Key Armed LIVE router: all 5 gates ready and zero credential leakage
            key_path = root / "live_auth.key"
            ticket_path = root / "live_auth_bundle.json"
            provision_live_auth_key(key_path)
            bundle = mint_live_authorization_bundle(
                key_file=key_path,
                targets=[
                    (BROKER_HUGOSWAY_MT5, "9001122", "Hugo PRO5"),
                    (BROKER_LHFX_MT5, "9003344", "LHFXSA-Live"),
                    (BROKER_OANDA_LIVE, "001-001-9900112-001", "api-fxtrade.oanda.com"),
                ],
                ttl_seconds=86400,
            )
            ticket_path.write_text(json.dumps(bundle), encoding="utf-8")
            live_env = {
                ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
                ENV_LIVE_AUTH_KEY_FILE: str(key_path),
                ENV_LIVE_AUTH_TICKET_FILE: str(ticket_path),
                "CAS_FOREX_STATE_DIR": str(root / "state"),
                ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "0",
                ENV_HUGOSWAY_MT5_LOGIN: "9001122",
                ENV_HUGOSWAY_MT5_PASSWORD: DUMMY_VAL,
                ENV_HUGOSWAY_MT5_SERVER: "Hugo PRO5",
                ENV_HUGOSWAY_MT5_LIVE_TICKET: DUMMY_VAL,
                ENV_LHFX_MT5_LOGIN: "9003344",
                ENV_LHFX_MT5_PASSWORD: DUMMY_VAL,
                ENV_LHFX_MT5_SERVER: "LHFXSA-Live",
                ENV_LHFX_MT5_LIVE_TICKET: DUMMY_VAL,
                ENV_OANDA_LIVE_ACCOUNT_ID: "001-001-9900112-001",
                ENV_OANDA_LIVE_TOKEN: DUMMY_VAL,
                ENV_OANDA_LIVE_API_TOKEN: DUMMY_VAL,
                ENV_OANDA_LIVE_TICKET: DUMMY_VAL,
            }
            router_live = DualShieldBrokerRouter(
                environ=live_env,
                valve_gate=GATE,
                equity_attestations={
                    BROKER_OANDA_LIVE: Decimal("8000"),
                    BROKER_HUGOSWAY_MT5: Decimal("1200"),
                    BROKER_LHFX_MT5: Decimal("800"),
                },
                clock=lambda: datetime.now(timezone.utc),
            )
            snap_live = safe_broker_routing_payload(router_live.routing_snapshot())
            lr_live = snap_live["live_readiness"]
            self.assertEqual(lr_live["execution_mode"], EXECUTION_MODE_LIVE)
            self.assertTrue(lr_live["live_armed"])
            self.assertTrue(lr_live["all_gates_ready"])
            for gate_item in lr_live["gates"]:
                self.assertTrue(gate_item["passed"], gate_item["id"])
            self.assertNotIn(DUMMY_VAL, json.dumps(snap_live))

    def test_broker_closed_stale_ticket_records_pnl_and_downshifts_auto_adaptive_gear(self) -> None:
        oracle = OandaQuoteTruthOracle.from_static_quotes({"EURUSD": (Decimal("1.09800"), Decimal("1.09810"))})
        router = DualShieldBrokerRouter(
            environ={
                ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "1.00",
                "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.10",
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
        sdk = _MutablePositionMt5Sdk(1002903, "Hugosway-Demo")
        sdk.rows = (
            SimpleNamespace(
                ticket=88001,
                symbol="EURUSD",
                type=0,
                volume=Decimal("0.10"),
                price_open=Decimal("1.10000"),
                sl=Decimal("1.09800"),
                tp=Decimal("1.10400"),
                profit=Decimal("-185.25"),
            ),
        )
        creds = Mt5Credentials(
            broker_id=BROKER_HUGOSWAY_MT5,
            login=1002903,
            server="Hugosway-Demo",
            password=_RedactedSecret(DUMMY_VAL),
            execution_mode=EXECUTION_MODE_DEMO,
        )
        hugo = Mt5PaperBrokerVenue(
            broker_id=BROKER_HUGOSWAY_MT5,
            credentials=creds,
            transport=Mt5NativePythonTransport(mt5_module=sdk, clock=lambda: T0),
            valve_gate=GATE,
            clock=lambda: T0,
        )
        hugo.connect()
        router.attach_venue(hugo)

        quota = DailyQuotaGovernanceStore(
            soft_quota_usd=Decimal("2000"),
            hard_quota_usd=Decimal("3000"),
            max_loss_usd=Decimal("5000"),
            max_consecutive_losses=3,
        )
        trader = AutonomousAiTrader(
            router=router,
            model_registry=FrontierModelRegistry(environ={}),
            valve_gate=GATE,
            quota_store=quota,
            execution_gate=lambda _inv: None,
            risk_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
            clock=lambda: T0,
        )
        trader._last_regime = REGIME_STRONG_TREND
        pre_snap = trader.status_snapshot(now=T0)
        self.assertEqual(pre_snap["risk_gear"]["active_gear"], ACTIVE_GEAR_STRONG_TREND_RUNNER)
        self.assertEqual(pre_snap["risk_gear"]["effective_risk_pct"], "1")

        trader._open_position_meta["88001"] = {
            "ticket": "88001",
            "broker_id": BROKER_HUGOSWAY_MT5,
            "symbol": "EURUSD",
            "side": "BUY",
            "volume_lots": "0.10",
            "entry_price": "1.10000",
            "stop_loss": "1.09800",
            "take_profit": "1.10400",
            "profit": "0",
            "protection_stage": "INITIAL_SL",
        }

        # 1. Live position updates tracked floating profit in _open_position_meta
        trader.protect_open_positions(quotes={"EURUSD": (Decimal("1.09815"), Decimal("1.09825"))}, now=T0)
        self.assertEqual(trader._open_position_meta["88001"]["profit"], "-185.25")

        # 2. Broker SL closes ticket 88001 -> realized loss recorded & AUTO_ADAPTIVE downshifts to CONSERVATIVE
        sdk.rows = ()
        t1 = T0 + timedelta(seconds=1)
        trader.protect_open_positions(quotes={"EURUSD": (Decimal("1.09800"), Decimal("1.09810"))}, now=t1)
        self.assertNotIn("88001", trader._open_position_meta)

        q_snap = quota.snapshot(now=t1, starting_equity=Decimal("100000"))
        self.assertEqual(q_snap["closed_trades"], 1)
        self.assertEqual(q_snap["loss_count"], 1)
        self.assertEqual(q_snap["consecutive_losses"], 1)
        self.assertEqual(q_snap["realized_net_pnl_usd"], "-185.25")

        post_snap = trader.status_snapshot(now=t1)
        self.assertEqual(post_snap["risk_gear"]["active_gear"], ACTIVE_GEAR_CONSERVATIVE)
        self.assertEqual(post_snap["risk_gear"]["effective_risk_pct"], "0.5")

        # 3. Zero-profit metadata estimates realized P&L from quote & sanitizes non-identifier ticket safely
        trader._open_position_meta["#tkt/sl 99"] = {
            "ticket": "#tkt/sl 99",
            "broker_id": BROKER_HUGOSWAY_MT5,
            "symbol": "EURUSD",
            "side": "SELL",
            "volume_lots": "0.10",
            "entry_price": "1.10000",
            "stop_loss": "1.10200",
            "take_profit": "1.09600",
            "profit": "0",
            "protection_stage": "INITIAL_SL",
        }
        t2 = T0 + timedelta(seconds=2)
        trader.protect_open_positions(quotes={"EURUSD": (Decimal("1.10190"), Decimal("1.10200"))}, now=t2)
        q_snap2 = quota.snapshot(now=t2, starting_equity=Decimal("100000"))
        self.assertEqual(q_snap2["closed_trades"], 2)
        self.assertEqual(q_snap2["loss_count"], 2)
        self.assertEqual(q_snap2["consecutive_losses"], 2)
        self.assertEqual(q_snap2["realized_net_pnl_usd"], "-205.25")

    def test_opposite_side_self_hedge_blocked_in_assess_setup_and_pyramid(self) -> None:
        oracle = OandaQuoteTruthOracle.from_static_quotes({"NAS100": (Decimal("20460.00"), Decimal("20462.00"))})
        router = DualShieldBrokerRouter(
            environ={
                ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "1.00",
                "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.10",
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
        trader = AutonomousAiTrader(
            router=router,
            model_registry=FrontierModelRegistry(environ={}),
            valve_gate=GATE,
            execution_gate=lambda _inv: None,
            clock=lambda: T0,
        )

        # Seed descending NAS100 burst producing a SELL signal
        for b_str, a_str in (
            ("20500.00", "20502.00"),
            ("20482.00", "20484.00"),
            ("20460.00", "20462.00"),
        ):
            trader._tick_history["NAS100"].append((Decimal(b_str), Decimal(a_str)))

        markets = {"NAS100": {"bid": "20460.00", "ask": "20462.00"}}
        quotes_map = {"NAS100": (Decimal("20460.00"), Decimal("20462.00"))}

        # Open BUY on NAS100 MUST block opposite-side SELL self-hedging
        trader._open_position_meta["99001"] = {
            "ticket": "99001",
            "broker_id": BROKER_HUGOSWAY_MT5,
            "symbol": "NAS100",
            "side": "BUY",
            "volume_lots": "0.10",
            "entry_price": "20502.00",
            "stop_loss": "20440.00",
            "take_profit": "20620.00",
            "profit": "-42.00",
            "protection_stage": "INITIAL_SL",
        }
        blocked = trader._assess_setup_and_pyramid(
            markets,
            quotes_map=quotes_map,
            total_eq=Decimal("100000"),
            deployable_eq=Decimal("100000"),
            risk_mult=Decimal("1"),
            fast_tick=True,
            allow_cold_open=True,
        )
        self.assertIsNone(blocked)

        # Once BUY is closed/absent, the exact same SELL setup is admitted
        trader._open_position_meta.clear()
        admitted = trader._assess_setup_and_pyramid(
            markets,
            quotes_map=quotes_map,
            total_eq=Decimal("100000"),
            deployable_eq=Decimal("100000"),
            risk_mult=Decimal("1"),
            fast_tick=True,
            allow_cold_open=True,
        )
        self.assertIsNotNone(admitted)
        if admitted is not None:
            self.assertEqual(admitted[0], "NAS100")
            self.assertEqual(admitted[1], Side.SELL)


if __name__ == "__main__":
    unittest.main()
