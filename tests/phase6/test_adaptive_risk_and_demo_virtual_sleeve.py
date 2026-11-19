"""Tests for PR #15: DEMO virtual barbell sleeve end-to-end, 3-Gear Auto-Adaptive Risk & Dynamic Daily Quota."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import http.client
from urllib.parse import urlparse

from cas_forex_revamp.composition.autonomous_trader import (
    ACTIVE_GEAR_CONSERVATIVE,
    ACTIVE_GEAR_GROWTH,
    ACTIVE_GEAR_STRONG_TREND_RUNNER,
    AutonomousAiTrader,
    RISK_GEAR_AGGRESSIVE,
    RISK_GEAR_AUTO_ADAPTIVE,
    RISK_GEAR_CONSERVATIVE,
    resolve_adaptive_risk_and_quota,
)
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.state_store import initialize_shared_runtime_state
from cas_forex_revamp.composition.trend_regime import (
    REGIME_CHOP_RANGE,
    REGIME_STRONG_TREND,
    REGIME_TREND_IGNITION,
)
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    DualShieldBrokerRouter,
    ENV_DEMO_BARBELL_VIRTUAL_SLEEVE,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import (
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    REQUIRED_LIVE_ARM_PHRASE,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    Mt5Credentials,
    Mt5NativePythonTransport,
    Mt5PaperBrokerVenue,
    OrderIntent,
    _RedactedSecret,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 19, 7, 0, 0, tzinfo=timezone.utc)
GATE = load_default_forex_valve_gate()


def _admitted_open(order_id: str, symbol: str = "EURUSD", units: Decimal = Decimal("10000"), stop: Decimal = Decimal("1.09500")):
    order = OrderIntent(
        order_id=order_id,
        action_ref=f"ref-{order_id}",
        kind=ActionKind.OPEN,
        symbol=symbol,
        quantity_units=units,
        side=Side.BUY,
        stop_price=stop,
    )
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=None,
        target_id=None,
    )
    req = SimpleNamespace(
        request_id=f"req-{order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-quote-1"),),
        state=SimpleNamespace(observed_at=T0, valid_until=T0 + timedelta(minutes=5)),
    )
    prop = SimpleNamespace(
        request=req,
        result=SimpleNamespace(selection=SimpleNamespace(evidence_ids=("ev-quote-1",), reason="trend", selected_action_ref=order.action_ref)),
        intent=intent,
    )
    view = {"balance": "100000", "equity": "100000", "peak_equity": "100000", "available_margin": "95000", "position_inventory": "[]"}
    pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "500000"}
    dec = GATE.require_admissible(prop, current_view=view, policy=pol, now=T0 + timedelta(seconds=1))
    return dec, order


class _FillSdk:
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    TRADE_ACTION_DEAL = 1
    TRADE_ACTION_SLTP = 6
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    TRADE_RETCODE_DONE = 10009

    def __init__(self, login: int, server: str) -> None:
        self._login = login
        self._server = server

    def initialize(self, **_kw): return True
    def login(self, *_a, **_kw): return True
    def shutdown(self): return None
    def last_error(self): return (0, "OK")

    def account_info(self):
        return SimpleNamespace(
            login=self._login, server=self._server, trade_mode=0, currency="USD",
            balance=100000.0, equity=100000.0, margin=0.0, margin_free=100000.0,
            margin_level=0.0, leverage=500,
        )

    def symbol_info_tick(self, sym):
        return SimpleNamespace(bid=1.09800, ask=1.09815, time_msc=1795057994298)

    def positions_get(self): return ()

    def order_send(self, payload):
        return SimpleNamespace(
            retcode=10009, deal=77001, order=77001,
            volume=payload.get("volume", 0.1), price=1.09815, comment="filled",
        )


class AdaptiveRiskAndDemoVirtualSleeveTests(unittest.TestCase):
    def test_demo_virtual_sleeve_executes_mt5_on_equal_100k_balances_and_blocks_live(self) -> None:
        # 1. DEMO mode with CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE=1 constructs cleanly & executes MT5 OPEN
        oracle = OandaQuoteTruthOracle.from_static_quotes({"EURUSD": (Decimal("1.09800"), Decimal("1.09815"))})
        router = DualShieldBrokerRouter(
            environ={
                "CAS_FOREX_EXECUTION_MODE": EXECUTION_MODE_DEMO,
                "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "5.00",
                "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.20",
                ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "1",
            },
            valve_gate=GATE,
            oracle=oracle,
            equity_attestations={
                BROKER_OANDA_PRACTICE: Decimal("100000"),
                BROKER_HUGOSWAY_MT5: Decimal("100000"),
                BROKER_LHFX_MT5: Decimal("100000"),
            },
            clock=lambda: T0,
        )
        self.assertTrue(router.barbell.demo_virtual_sleeve)
        creds = Mt5Credentials(
            broker_id=BROKER_HUGOSWAY_MT5, login=1002903, server="Hugosway-Demo",
            password=_RedactedSecret("demo-v1"), execution_mode=EXECUTION_MODE_DEMO,
        )
        hugo = Mt5PaperBrokerVenue(
            broker_id=BROKER_HUGOSWAY_MT5,
            credentials=creds,
            transport=Mt5NativePythonTransport(mt5_module=_FillSdk(1002903, "Hugosway-Demo")),
            valve_gate=GATE,
            clock=lambda: T0,
        )
        hugo.connect()
        router._venues[BROKER_HUGOSWAY_MT5] = hugo
        router._status[BROKER_HUGOSWAY_MT5] = "ACTIVE"

        elig_ok, elig_msg = router.check_open_eligibility("EURUSD")
        self.assertTrue(elig_ok, elig_msg)

        dec, order = _admitted_open("demo-vs-open-1")
        ex = router.execute_open(order, valve_decision=dec)
        self.assertEqual(ex.executed_on, BROKER_HUGOSWAY_MT5)
        self.assertFalse(ex.safe_harbor)

        # 2. LIVE mode MUST hard-reject CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE=1
        with self.assertRaises(ContractError):
            DualShieldBrokerRouter(
                environ={
                    "CAS_FOREX_EXECUTION_MODE": EXECUTION_MODE_LIVE,
                    "CAS_FOREX_LIVE_ARM_PHRASE": REQUIRED_LIVE_ARM_PHRASE,
                    ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "1",
                },
                valve_gate=GATE,
                clock=lambda: T0,
            )

    def test_three_gear_auto_adaptive_risk_and_dynamic_daily_quota_envelope(self) -> None:
        base = dict(
            owner_max_risk_pct=Decimal("5.00"),
            owner_max_drawdown_pct=Decimal("0.20"),
            owner_soft_quota_usd=Decimal("2000"),
            owner_hard_quota_usd=Decimal("3000"),
        )
        # 1. CHOP_RANGE -> Conservative (1.00%, $500/$1,000)
        g_chop = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE, regime=REGIME_CHOP_RANGE,
            drawdown_pct=Decimal("0.02"), consecutive_losses=0, **base,
        )
        self.assertEqual(g_chop["active_gear"], ACTIVE_GEAR_CONSERVATIVE)
        self.assertEqual(g_chop["effective_risk_pct"], "1")
        self.assertEqual(g_chop["effective_soft_quota_usd"], "500")
        self.assertEqual(g_chop["effective_hard_quota_usd"], "1000")

        # 2. TREND_IGNITION -> Growth (2.50%, $2,000/$2,500)
        g_grow = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE, regime=REGIME_TREND_IGNITION,
            drawdown_pct=Decimal("0.03"), consecutive_losses=0, **base,
        )
        self.assertEqual(g_grow["active_gear"], ACTIVE_GEAR_GROWTH)
        self.assertEqual(g_grow["effective_risk_pct"], "2.5")
        self.assertEqual(g_grow["effective_soft_quota_usd"], "2000")
        self.assertEqual(g_grow["effective_hard_quota_usd"], "2500")

        # 3. STRONG_TREND with 0 losses & <10% DD -> Strong-Trend Runner (5.00%, $2,000/$3,000)
        g_run = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE, regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0.04"), consecutive_losses=0, **base,
        )
        self.assertEqual(g_run["active_gear"], ACTIVE_GEAR_STRONG_TREND_RUNNER)
        self.assertEqual(g_run["effective_risk_pct"], "5")
        self.assertEqual(g_run["effective_soft_quota_usd"], "2000")
        self.assertEqual(g_run["effective_hard_quota_usd"], "3000")

        # 4. Drawdown >= 10% auto-downshifts even on STRONG_TREND
        g_dd = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE, regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0.10"), consecutive_losses=0, **base,
        )
        self.assertEqual(g_dd["active_gear"], ACTIVE_GEAR_CONSERVATIVE)
        self.assertEqual(g_dd["effective_risk_pct"], "1")

        # 5. Losing streak >= 1 auto-downshifts even on STRONG_TREND
        g_ls = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE, regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0.01"), consecutive_losses=1, **base,
        )
        self.assertEqual(g_ls["active_gear"], ACTIVE_GEAR_CONSERVATIVE)
        self.assertEqual(g_ls["effective_risk_pct"], "1")

        # 6. Owner hard ceiling is UNBREAKABLE (AI can NEVER exceed owner_max_risk_pct or owner_hard_quota_usd)
        g_cap = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AGGRESSIVE, regime=REGIME_STRONG_TREND,
            drawdown_pct=Decimal("0"), consecutive_losses=0,
            owner_max_risk_pct=Decimal("1.00"),
            owner_max_drawdown_pct=Decimal("0.10"),
            owner_soft_quota_usd=Decimal("500"),
            owner_hard_quota_usd=Decimal("1000"),
        )
        self.assertEqual(g_cap["effective_risk_pct"], "1")
        self.assertEqual(g_cap["effective_hard_quota_usd"], "1000")

    def test_cockpit_endpoint_set_risk_gear_persists_and_rejects_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            router = DualShieldBrokerRouter(
                environ={
                    "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "5.00",
                    "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.20",
                    ENV_DEMO_BARBELL_VIRTUAL_SLEEVE: "1",
                },
                valve_gate=st.valve_gate,
                peak_equity_store=st.peak_equity_store,
                clock=lambda: T0,
            )
            reg = FrontierModelRegistry(environ={})
            gear_file = Path(td) / "risk_gear.json"
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=st.valve_gate,
                quota_store=st.quota_store,
                peak_equity_store=st.peak_equity_store,
                owner_verifier=st.owner_recovery,
                execution_gate=st.model_gate,
                clock=lambda: T0,
                risk_gear_path=gear_file,
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=router.routing_snapshot,
                ai_model_registry=reg,
                autonomous_trader=trader,
                profit_vault=st.profit_vault,
                owner_recovery=st.owner_recovery,
            )
            srv.start()
            try:
                parsed = urlparse(srv.base_url)
                conn = http.client.HTTPConnection(parsed.hostname or "127.0.0.1", parsed.port, timeout=10)
                try:
                    conn.request(
                        "POST",
                        "/api/ai-overseer-action",
                        body=json.dumps({"action": "SET_RISK_GEAR", "risk_gear": RISK_GEAR_CONSERVATIVE}).encode("utf-8"),
                        headers={"Authorization": f"Bearer {srv.auth_token}", "Content-Type": "application/json"},
                    )
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    doc = json.loads(resp.read().decode("utf-8"))
                finally:
                    conn.close()
                self.assertEqual(doc["risk_gear"]["owner_mode"], RISK_GEAR_CONSERVATIVE)
                self.assertEqual(doc["risk_gear"]["active_gear"], ACTIVE_GEAR_CONSERVATIVE)
                self.assertTrue(gear_file.is_file())
                self.assertEqual(json.loads(gear_file.read_text(encoding="utf-8"))["risk_gear_mode"], RISK_GEAR_CONSERVATIVE)

                with self.assertRaises(ContractError):
                    trader.set_risk_gear_mode("YOLO_100X")
            finally:
                srv.stop()


if __name__ == "__main__":
    unittest.main()
