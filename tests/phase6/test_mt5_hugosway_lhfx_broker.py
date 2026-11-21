"""Phase 6 suite: MetaTrader 5 Hugo's Way (primary) + LHFX (secondary) + OANDA practice dual-shield routing.

Every test is offline and air-gap safe: the MetaTrader5 SDK is replaced by an injected fake, the MT5
terminal by ``Mt5SpoolPaperTerminalEmulator`` (a Python twin of ``mt5/CasForexMt5Bridge.mq5``), and
OANDA by an injected practice transport. Only 127.0.0.1 is bound (cockpit endpoint test).
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import pickle
import sys
import tempfile
from types import SimpleNamespace
import unittest
import urllib.error
import urllib.parse
import urllib.request

from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer, safe_broker_routing_payload
from cas_forex_revamp.contracts import ActionKind, ContractError, Side, canonical_bytes
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveRefusalError, load_default_forex_valve_gate
from cas_forex_revamp.venue.external_paper_broker import EXPANDED_FX_PAIRS, OandaPracticePaperClient
from cas_forex_revamp.venue.live_market_stream import MarketStreamEnvelope
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    MT5_SPOOL_PROTOCOL,
    MT5_TIMEFRAMES,
    BrokerFailoverExhaustedError,
    BrokerHierarchyRouter,
    LiveBrokerEndpointForbiddenError,
    Mt5BridgeError,
    Mt5Credentials,
    Mt5MarginCalculator,
    Mt5MarginRefusalError,
    Mt5NativePythonTransport,
    Mt5NotConfiguredError,
    Mt5OrderRequest,
    Mt5OutcomeUnknownError,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5TransportError,
    Mt5ValveClearanceError,
    OrderIntent,
    apply_verified_directory_mode,
    load_mt5_credentials,
    sign_spool_valve_admission,
    validate_demo_server,
)
from cas_forex_revamp.venue.dual_shield_router import (
    MAJOR_FX_PAIRS,
    BarbellCapitalPolicy,
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
    OandaProtectiveOffsetPlanner,
    OandaQuoteTruthOracle,
    QuoteReferenceUnavailableError,
)

D = Decimal
REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 16, 13, 0, tzinfo=timezone.utc)
PASSWORD_VALUE = "Demo-Pass-9f3K!q"  # synthetic test value, not a real credential
OANDA_TOKEN_VALUE = "practice-token-abc123"  # synthetic test value, not a real credential
OANDA_ACCOUNT = "101-001-1234567-001"

QUOTES: dict[str, tuple[Decimal, Decimal]] = {
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27012")),
    "USDJPY": (D("150.000"), D("150.012")),
    "USDCHF": (D("0.88000"), D("0.88010")),
    "AUDUSD": (D("0.65000"), D("0.65010")),
    "USDCAD": (D("1.36000"), D("1.36012")),
    "NZDUSD": (D("0.60000"), D("0.60010")),
    "EURGBP": (D("0.86600"), D("0.86612")),
    "EURJPY": (D("165.000"), D("165.015")),
    "GBPJPY": (D("190.500"), D("190.520")),
    "EURCHF": (D("0.96800"), D("0.96812")),
    "EURAUD": (D("1.69200"), D("1.69220")),
    "EURCAD": (D("1.49600"), D("1.49615")),
    "AUDJPY": (D("97.500"), D("97.512")),
    "CHFJPY": (D("170.400"), D("170.420")),
    "CADJPY": (D("110.300"), D("110.312")),
}

GATE = load_default_forex_valve_gate()
VIEW = {"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"}


def policy(max_qty: str = "500000") -> dict[str, str]:
    return {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": max_qty}


def proposal_for(order: OrderIntent, *, reason: str = "Trend entry", quantity=None, stop=None, kind=None):
    """Duck-typed DecisionProposal accepted by ForexMetaValveGate (request/result/intent)."""
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=kind or order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units if quantity is None else quantity,
        side=order.side,
        stop_price=order.stop_price if stop is None else stop,
        limit_price=order.limit_price,
        target_id=order.position_ticket,
    )
    request = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-quote-1"),),
        state=SimpleNamespace(observed_at=T0, valid_until=T0 + timedelta(minutes=5)),
    )
    selection = SimpleNamespace(evidence_ids=("ev-quote-1",), reason=reason, selected_action_ref=order.action_ref)
    return SimpleNamespace(request=request, result=SimpleNamespace(selection=selection), intent=intent)


def clear(order: OrderIntent, max_qty: str = "500000"):
    return GATE.require_admissible(proposal_for(order), current_view=VIEW, policy=policy(max_qty), now=T0 + timedelta(seconds=1))


def _grant_for_req(req: Mt5OrderRequest, *, broker_id: str = BROKER_HUGOSWAY_MT5, login: int = 7001234, server: str = "Hugo demo PRO5", now: datetime | None = None):
    eff_now = datetime.now(timezone.utc) if now is None else now
    units = (req.volume_lots * D("100000")) if req.volume_lots is not None else D("10000")
    ord_i = OrderIntent(
        order_id=req.request_id,
        action_ref=f"act-{req.request_id}",
        kind=ActionKind(req.action),
        symbol=req.symbol,
        quantity_units=units if req.action in ("OPEN", "REDUCE") else None,
        side=req.side if req.action == "OPEN" else None,
        stop_price=req.stop_loss,
        take_profit_price=req.take_profit,
        position_ticket=req.position_ticket,
    )
    prop = proposal_for(ord_i)
    prop.request.state = SimpleNamespace(observed_at=eff_now, valid_until=eff_now + timedelta(minutes=5))
    dec = GATE.require_admissible(prop, current_view=VIEW, policy=policy("10000000"), now=eff_now)
    return GATE.issue_order_grant(
        dec,
        broker_id=broker_id,
        account_id=str(login),
        server=server,
        execution_mode="DEMO",
        action_kind=req.action,
        symbol=req.symbol,
        side=req.side.value,
        volume=req.volume_lots,
        stop_loss=req.stop_loss,
        take_profit=req.take_profit,
        position_ticket=req.position_ticket,
        order_action_ref=ord_i.action_ref,
        order_quantity_units=ord_i.quantity_units,
        order_side=ord_i.side,
        now=eff_now,
    )


def open_order(order_id: str, symbol: str = "EURUSD", side: Side = Side.BUY, units: str = "100000", stop: str = "1.09500") -> OrderIntent:
    return OrderIntent(order_id=order_id, action_ref=f"act-{order_id}", kind=ActionKind.OPEN, symbol=symbol,
                       quantity_units=D(units), side=side, stop_price=D(stop))


class _Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        self.now += timedelta(milliseconds=10)
        return self.now


class FakeMt5Sdk:
    """Injected stand-in for the official MetaTrader5 package (float API, like the real SDK)."""

    TRADE_ACTION_DEAL = 1
    TRADE_ACTION_SLTP = 6
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    POSITION_TYPE_BUY = 0
    POSITION_TYPE_SELL = 1
    ACCOUNT_TRADE_MODE_DEMO = 0
    TRADE_RETCODE_PLACED = 10008
    TRADE_RETCODE_DONE = 10009
    TRADE_RETCODE_DONE_PARTIAL = 10010
    TIMEFRAME_M1 = 1
    TIMEFRAME_M5 = 5
    TIMEFRAME_H1 = 16385

    def __init__(self, *, trade_mode: int = 0, leverage: int = 500, server: str = "Hugosway-Demo", login: int = 7001234) -> None:
        self.trade_mode = trade_mode
        self.leverage = leverage
        self.server = server
        self.login_no = login
        self.sent: list[dict] = []
        self.initialize_kwargs: dict = {}
        self.shutdown_calls = 0
        self.positions: dict[int, SimpleNamespace] = {}
        self.next_ticket = 900001
        self.fail_send = False

    def initialize(self, **kwargs):
        self.initialize_kwargs = kwargs
        return True

    def login(self, login, password="", server="", timeout=60000):
        return login == self.login_no and server == self.server

    def last_error(self):
        return (1, "Success")

    def shutdown(self):
        self.shutdown_calls += 1

    def account_info(self):
        return SimpleNamespace(login=self.login_no, trade_mode=self.trade_mode, server=self.server, leverage=self.leverage,
                               balance=10000.0, equity=10000.0, margin=0.0, margin_free=10000.0, currency="USD")

    def symbol_select(self, symbol, enable):
        return symbol in QUOTES

    def symbol_info_tick(self, symbol):
        bid, ask = QUOTES[symbol]
        return SimpleNamespace(bid=float(bid), ask=float(ask), time_msc=1794834000123)

    def copy_rates_from_pos(self, symbol, timeframe, start, count):
        return [{"time": 1794834000, "open": 1.1, "high": 1.1005, "low": 1.0995, "close": 1.1002, "tick_volume": 42}] * count

    def positions_get(self):
        return tuple(self.positions.values())

    def order_send(self, request):
        self.sent.append(dict(request))
        if self.fail_send:
            return None
        if request["action"] == self.TRADE_ACTION_SLTP:
            self.positions[request["position"]].sl = request["sl"]
            return SimpleNamespace(retcode=10009, deal=0, order=0, volume=0.0, price=0.0, comment="Request executed")
        if "position" in request:
            pos = self.positions[request["position"]]
            pos.volume = round(pos.volume - request["volume"], 2)
            if pos.volume <= 0:
                del self.positions[request["position"]]
            return SimpleNamespace(retcode=10009, deal=800001, order=0, volume=request["volume"], price=request["price"], comment="done")
        ticket = self.next_ticket
        self.next_ticket += 1
        self.positions[ticket] = SimpleNamespace(ticket=ticket, symbol=request["symbol"], type=request["type"], volume=request["volume"],
                                                 price_open=request["price"], sl=request["sl"], profit=0.0)
        return SimpleNamespace(retcode=10009, deal=800000 + ticket, order=ticket, volume=request["volume"], price=request["price"], comment="done")


class FakeOandaTransport:
    """Injected OANDA v20 practice transport: summary, pricing, and market-order fills."""

    def __init__(self, quotes: dict[str, tuple[Decimal, Decimal]], *, nav: str = "80000", margin_available: str = "80000") -> None:
        self.quotes = dict(quotes)
        self.nav = nav
        self.margin_available = margin_available
        self.calls: list[tuple[str, str]] = []
        self.orders: list[dict] = []

    def __call__(self, method, url, headers, body, timeout, max_bytes):
        self.calls.append((method, url))
        if urllib.parse.urlsplit(url).hostname != "api-fxpractice.oanda.com":
            raise RuntimeError("non-practice host")
        if url.endswith("/summary"):
            return json.dumps({"account": {"id": OANDA_ACCOUNT, "currency": "USD", "balance": self.nav, "NAV": self.nav,
                                           "unrealizedPL": "0", "marginAvailable": self.margin_available,
                                           "openPositionCount": 0, "lastTransactionID": "1"}}).encode()
        if "/pricing?" in url:
            insts = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["instruments"][0].split(",")
            prices = []
            for inst in insts:
                bid, ask = self.quotes[inst.replace("_", "")]
                prices.append({"instrument": inst, "bids": [{"price": str(bid)}], "asks": [{"price": str(ask)}]})
            return json.dumps({"prices": prices}).encode()
        if method == "POST" and url.endswith("/orders"):
            order = json.loads(body)["order"]
            self.orders.append(order)
            bid, ask = self.quotes[order["instrument"].replace("_", "")]
            price = ask if not order["units"].startswith("-") else bid
            return json.dumps({"orderCreateTransaction": {"id": "10"}, "orderFillTransaction": {"id": "11", "price": str(price)},
                               "lastTransactionID": "11"}).encode()
        if method == "PUT" and "/trades/" in url and url.endswith("/orders"):
            amend = json.loads(body)
            self.orders.append(amend)
            return json.dumps({"stopLossOrderTransaction": {"id": "12"}, "lastTransactionID": "12"}).encode()
        if method == "GET" and url.endswith("/openTrades"):
            trades = []
            for idx, ord_item in enumerate(self.orders, start=1):
                if "instrument" in ord_item and "units" in ord_item:
                    trades.append({
                        "id": str(idx),
                        "instrument": ord_item["instrument"],
                        "currentUnits": str(ord_item["units"]),
                        "price": "1.10010",
                        "unrealizedPL": "0.00",
                        "state": "OPEN",
                    })
            return json.dumps({"trades": trades, "lastTransactionID": "12"}).encode()
        if method == "PUT" and "/trades/" in url and url.endswith("/close"):
            close_doc = json.loads(body)
            self.orders.append(close_doc)
            return json.dumps({
                "orderCreateTransaction": {"id": "13"},
                "orderFillTransaction": {"id": "14", "price": "1.10000", "pl": "0.00"},
                "lastTransactionID": "14",
            }).encode()
        raise RuntimeError("unexpected OANDA call")


def mt5_env(tmp: str, *, hugo: bool = True, lhfx: bool = True, oanda: bool = False, **extra: str) -> dict[str, str]:
    env = {"CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE", "CAS_FOREX_MT5_SPOOL_DIR": tmp}
    if hugo:
        env["CAS_FOREX_HUGOSWAY_MT5_LOGIN"] = "7001234"
    if lhfx:
        env["CAS_FOREX_LHFX_MT5_LOGIN"] = "8005678"
    if oanda:
        env["CAS_FOREX_OANDA_PRACTICE_TOKEN"] = OANDA_TOKEN_VALUE
        env["CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID"] = OANDA_ACCOUNT
    env.update(extra)
    return env


class _Rig:
    """Spool emulators for both MT5 brokers plus an injected OANDA practice transport."""

    def __init__(self, tmp: str, *, hugo_balance: str = "12000", lhfx_balance: str = "8000",
                 oanda_nav: str = "80000", publish: tuple[str, ...] = (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5),
                 hugo_trade_mode: str = "DEMO") -> None:
        self.root = Path(tmp)
        self.clock = _Clock()
        self.emus = {
            BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(self.root / "hugosway_mt5", server="Hugosway-Demo", login=7001234,
                                                               quotes=QUOTES, balance=D(hugo_balance), trade_mode=hugo_trade_mode),
            BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(self.root / "lhfx_mt5", server="LHFXSA-Trade", login=8005678,
                                                           quotes=QUOTES, balance=D(lhfx_balance)),
        }
        for broker_id in publish:
            self.emus[broker_id].publish_market()
        self.oanda = FakeOandaTransport(QUOTES, nav=oanda_nav, margin_available=oanda_nav)

    def transport_factory(self, broker_id: str, mode: str, root):
        return Mt5SpoolBridgeTransport(Path(root) / broker_id.lower(), sleep=self.emus[broker_id].sleep_hook,
                                       poll_interval_seconds=0.01, receipt_timeout_seconds=5)

    def oanda_factory(self, env):
        return OandaPracticePaperClient(environ=env, transport=self.oanda)

    def hierarchy(self, env, **kw) -> BrokerHierarchyRouter:
        return BrokerHierarchyRouter(environ=env, valve_gate=GATE, transport_factory=self.transport_factory,
                                     oanda_client_factory=self.oanda_factory, clock=self.clock, **kw)

    def dual(self, env, **kw) -> DualShieldBrokerRouter:
        return DualShieldBrokerRouter(environ=env, valve_gate=GATE, transport_factory=self.transport_factory,
                                      oanda_client_factory=self.oanda_factory, clock=self.clock, **kw)


def spool_venue(tmp: str, *, balance: str = "10000", **kw):
    emu = Mt5SpoolPaperTerminalEmulator(Path(tmp) / "hugosway_mt5", server="Hugo demo PRO5", login=7001234, quotes=QUOTES, balance=D(balance))
    emu.publish_market()
    transport = Mt5SpoolBridgeTransport(Path(tmp) / "hugosway_mt5", sleep=emu.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=5)
    creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
    venue = Mt5PaperBrokerVenue(broker_id=BROKER_HUGOSWAY_MT5, credentials=creds, transport=transport, valve_gate=GATE, clock=_Clock(), **kw)
    venue.connect()
    return emu, venue


class BrokerHierarchyConfigTests(unittest.TestCase):
    def test_hugosway_is_primary_main_by_default_with_lhfx_secondary_and_oanda_tertiary(self) -> None:
        router = BrokerHierarchyRouter(environ={}, valve_gate=GATE)
        self.assertEqual(router.priority_order, (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5, BROKER_OANDA_PRACTICE))
        snap = router.routing_snapshot()
        self.assertEqual(snap["platform"], "MetaTrader 5")
        self.assertTrue(snap["demo_only"])
        self.assertTrue(snap["live_trading_locked"])
        chain = snap["chain"]
        self.assertEqual([c["broker_id"] for c in chain], list(router.priority_order))
        self.assertEqual(chain[0]["role"], "PRIMARY_MAIN")
        self.assertEqual(chain[0]["server"], "Hugosway-Demo")
        self.assertEqual(chain[1]["role"], "SECONDARY_MT5")
        self.assertEqual(chain[1]["server"], "LHFXSA-Trade")
        self.assertEqual(chain[2]["role"], "TERTIARY_REST_FALLBACK")
        self.assertEqual(chain[2]["server"], "https://api-fxpractice.oanda.com/v3")
        self.assertEqual(chain[0]["max_leverage"], "1:500")
        self.assertEqual(chain[1]["max_leverage"], "1:500")
        self.assertEqual(snap["valve"]["parameters"], 161)
        self.assertEqual(snap["valve"]["threshold"], "0.55")
        self.assertEqual(len(MT5_TIMEFRAMES), 21)
        safe_broker_routing_payload(snap)

    def test_primary_override_reorders_hierarchy(self) -> None:
        lhfx = BrokerHierarchyRouter(environ={"CAS_FOREX_PRIMARY_BROKER": "LHFX_MT5"}, valve_gate=GATE)
        self.assertEqual(lhfx.priority_order, (BROKER_LHFX_MT5, BROKER_HUGOSWAY_MT5, BROKER_OANDA_PRACTICE))
        oanda = BrokerHierarchyRouter(environ={"CAS_FOREX_PRIMARY_BROKER": "oanda_practice"}, valve_gate=GATE)
        self.assertEqual(oanda.priority_order[0], BROKER_OANDA_PRACTICE)
        for bad in ({"CAS_FOREX_PRIMARY_BROKER": "FXCM"}, {"CAS_FOREX_MT5_TRANSPORT_MODE": "SOCKET"}):
            with self.assertRaises(ContractError):
                BrokerHierarchyRouter(environ=bad, valve_gate=GATE)

    def test_live_real_money_servers_are_hard_rejected(self) -> None:
        for server in ("Hugo PRO5", "HugosWay-Live", "Hugo Live 3", "HugosWay-Real"):
            with self.assertRaises(LiveBrokerEndpointForbiddenError, msg=server):
                BrokerHierarchyRouter(environ={"CAS_FOREX_HUGOSWAY_MT5_SERVER": server}, valve_gate=GATE)
        for server in ("LHFXSA-Live", "LHFX-Real", "LHFXSA"):
            with self.assertRaises(LiveBrokerEndpointForbiddenError, msg=server):
                BrokerHierarchyRouter(environ={"CAS_FOREX_LHFX_MT5_SERVER": server}, valve_gate=GATE)
        self.assertEqual(validate_demo_server(BROKER_HUGOSWAY_MT5, " Hugo demo PRO5 "), "Hugo demo PRO5")
        self.assertEqual(validate_demo_server(BROKER_LHFX_MT5, "LHFXSA-Demo"), "LHFXSA-Demo")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            BrokerHierarchyRouter(environ={}, valve_gate=GATE, oanda_base_url="https://api-fxtrade.oanda.com/v3")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            OandaPracticePaperClient.validate_practice_url("https://api-fxtrade.oanda.com/v3")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=1, server="Hugo PRO5")

    def test_credentials_are_redacted_everywhere(self) -> None:
        env = {"CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234", "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": PASSWORD_VALUE,
               "CAS_FOREX_OANDA_PRACTICE_TOKEN": OANDA_TOKEN_VALUE, "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": OANDA_ACCOUNT}
        creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, env)
        self.assertIsNotNone(creds)
        router = BrokerHierarchyRouter(environ=env, valve_gate=GATE)
        rendered = " ".join([repr(creds), str(creds), f"{creds.password}", repr(creds.password), repr(router),
                             json.dumps(router.routing_snapshot())])
        self.assertNotIn(PASSWORD_VALUE, rendered)
        self.assertNotIn(OANDA_TOKEN_VALUE, rendered)
        self.assertNotIn("7001234", rendered)
        self.assertIn("[REDACTED]", rendered)
        with self.assertRaises(TypeError):
            pickle.dumps(creds.password)
        self.assertEqual(creds.password.reveal(), PASSWORD_VALUE)

    def test_partial_credentials_are_refused(self) -> None:
        with self.assertRaises(Mt5NotConfiguredError):
            load_mt5_credentials(BROKER_HUGOSWAY_MT5, {"CAS_FOREX_HUGOSWAY_MT5_PASSWORD": PASSWORD_VALUE})
        with self.assertRaises(Mt5NotConfiguredError):
            load_mt5_credentials(BROKER_LHFX_MT5, {"CAS_FOREX_LHFX_MT5_LOGIN": "8005678"})
        with self.assertRaises(Mt5NotConfiguredError):
            load_mt5_credentials(BROKER_LHFX_MT5, {"CAS_FOREX_LHFX_MT5_LOGIN": "abc", "CAS_FOREX_LHFX_MT5_PASSWORD": "x"})
        with self.assertRaises(Mt5NotConfiguredError):
            BrokerHierarchyRouter(environ={"CAS_FOREX_OANDA_PRACTICE_TOKEN": OANDA_TOKEN_VALUE}, valve_gate=GATE)
        self.assertIsNone(load_mt5_credentials(BROKER_HUGOSWAY_MT5, {}))
        spool_ok = load_mt5_credentials(BROKER_LHFX_MT5, {"CAS_FOREX_LHFX_MT5_LOGIN": "8005678"}, password_required=False)
        self.assertEqual(spool_ok.server, "LHFXSA-Trade")

    def test_construction_is_inert(self) -> None:
        had_sdk = "MetaTrader5" in sys.modules
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "not-created"
            Mt5SpoolBridgeTransport(spool)
            Mt5NativePythonTransport()
            BrokerHierarchyRouter(environ=mt5_env(str(spool)), valve_gate=GATE)
            DualShieldBrokerRouter(environ=mt5_env(str(spool)), valve_gate=GATE)
            self.assertFalse(spool.exists())
        self.assertEqual("MetaTrader5" in sys.modules, had_sdk)

    def test_router_requires_valve_gate(self) -> None:
        with self.assertRaises(ContractError):
            BrokerHierarchyRouter(environ={}, valve_gate=None)  # type: ignore[arg-type]
        with self.assertRaises(ContractError):
            Mt5PaperBrokerVenue(broker_id=BROKER_HUGOSWAY_MT5,
                                credentials=Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=1, server="Hugo demo PRO5"),
                                transport=Mt5NativePythonTransport(mt5_module=FakeMt5Sdk()))


class Mt5MarginCalculatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calc = Mt5MarginCalculator()

    def test_exact_1_to_500_margin_for_majors(self) -> None:
        self.assertEqual(self.calc.required_margin("EURUSD", Side.BUY, D("100000"), QUOTES), D("220.02"))
        self.assertEqual(self.calc.required_margin("GBPUSD", Side.SELL, D("100000"), QUOTES), D("254.00"))
        self.assertEqual(self.calc.required_margin("USDJPY", Side.BUY, D("100000"), QUOTES), D("200.00"))
        self.assertEqual(self.calc.required_margin("EURGBP", Side.BUY, D("100000"), QUOTES), D("220.01"))
        self.assertEqual(self.calc.required_margin("EURUSD", Side.BUY, D("1000"), {"EURUSD": (D("1.10003"), D("1.10013"))}), D("2.21"))

    def test_all_16_expanded_pairs_have_exact_margin(self) -> None:
        self.assertEqual(len(EXPANDED_FX_PAIRS), 16)
        for symbol in EXPANDED_FX_PAIRS:
            margin = self.calc.required_margin(symbol, Side.BUY, D("100000"), QUOTES)
            notional = self.calc.notional_in_account(symbol, Side.BUY, D("100000"), QUOTES)
            self.assertGreater(margin, D("0"), symbol)
            self.assertGreaterEqual(margin * 500, notional, symbol)
            self.assertLess(margin * 500 - notional, D("5"), symbol)
            self.assertEqual(margin, margin.quantize(D("0.01")), symbol)

    def test_lots_volume_steps_and_leverage_cap(self) -> None:
        self.assertEqual(self.calc.units_to_lots(D("150000")), D("1.50"))
        self.assertEqual(self.calc.lots_to_units(D("0.25")), D("25000"))
        with self.assertRaises(ContractError):
            self.calc.units_to_lots(D("1500"))
        with self.assertRaises(ContractError):
            Mt5MarginCalculator(leverage=1000)

    def test_free_margin_and_margin_level(self) -> None:
        m = self.calc.account_metrics(balance=D("10000"), floating_pnl=D("-250"), used_margin=D("500"))
        self.assertEqual(m["equity"], D("9750"))
        self.assertEqual(m["free_margin"], D("9250"))
        self.assertEqual(m["margin_level_pct"], D("1950.00"))
        ok = self.calc.check_new_position(symbol="EURUSD", side=Side.BUY, units=D("100000"), quotes=QUOTES,
                                          equity=D("10000"), used_margin=D("0"), free_margin=D("10000"))
        self.assertTrue(ok.admitted)
        self.assertEqual(ok.margin_level_after_pct, D("4545.04"))
        rogue = self.calc.check_new_position(symbol="EURUSD", side=Side.BUY, units=D("5000000"), quotes=QUOTES,
                                             equity=D("10000"), used_margin=D("0"), free_margin=D("10000"))
        self.assertFalse(rogue.admitted)
        self.assertEqual(rogue.reason, "INSUFFICIENT_FREE_MARGIN")
        floor = self.calc.check_new_position(symbol="EURUSD", side=Side.BUY, units=D("1000000"), quotes=QUOTES,
                                             equity=D("10000"), used_margin=D("0"), free_margin=D("10000"))
        self.assertEqual(floor.reason, "POST_TRADE_MARGIN_LEVEL_BELOW_FLOOR")


class NativePythonTransportTests(unittest.TestCase):
    def _venue(self, sdk: FakeMt5Sdk) -> Mt5PaperBrokerVenue:
        creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, {"CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                                                           "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": PASSWORD_VALUE})
        transport = Mt5NativePythonTransport(mt5_module=sdk, clock=_Clock())
        return Mt5PaperBrokerVenue(broker_id=BROKER_HUGOSWAY_MT5, credentials=creds, transport=transport, valve_gate=GATE, clock=_Clock())

    def test_full_lifecycle_open_amend_reduce_close(self) -> None:
        sdk = FakeMt5Sdk()
        venue = self._venue(sdk)
        snap = venue.connect()
        self.assertEqual(snap.trade_mode, "DEMO")
        self.assertEqual(sdk.initialize_kwargs["server"], "Hugosway-Demo")
        self.assertEqual(sdk.initialize_kwargs["password"], PASSWORD_VALUE)

        o1 = open_order("n-open-1")
        r1 = venue.execute(o1, valve_decision=clear(o1))
        self.assertTrue(r1.accepted)
        ticket = r1.receipt.position_ticket
        self.assertEqual(sdk.sent[0]["action"], 1)
        self.assertEqual(sdk.sent[0]["type"], 0)
        self.assertEqual(sdk.sent[0]["volume"], 1.0)
        self.assertEqual(sdk.sent[0]["sl"], 1.095)
        self.assertEqual(r1.margin_check.required_margin, D("220.02"))

        o2 = OrderIntent(order_id="n-amend-1", action_ref="act-n-amend-1", kind=ActionKind.AMEND_STOP, symbol="EURUSD",
                         stop_price=D("1.09700"), position_ticket=ticket)
        r2 = venue.execute(o2, valve_decision=clear(o2))
        self.assertEqual(r2.receipt.status, "MODIFIED")
        self.assertEqual(sdk.sent[1]["action"], 6)
        self.assertEqual(sdk.sent[1]["position"], int(ticket))

        o3 = OrderIntent(order_id="n-reduce-1", action_ref="act-n-reduce-1", kind=ActionKind.REDUCE, symbol="EURUSD",
                         quantity_units=D("40000"), position_ticket=ticket)
        venue.execute(o3, valve_decision=clear(o3))
        self.assertEqual(sdk.sent[2]["type"], 1)
        self.assertEqual(sdk.sent[2]["volume"], 0.4)
        self.assertEqual(sdk.sent[2]["position"], int(ticket))

        o4 = OrderIntent(order_id="n-close-1", action_ref="act-n-close-1", kind=ActionKind.CLOSE, symbol="EURUSD",
                         quantity_units=D("60000"), position_ticket=ticket)
        r4 = venue.execute(o4, valve_decision=clear(o4))
        self.assertEqual(sdk.sent[3]["volume"], 0.6)
        self.assertEqual(r4.positions_after, ())
        self.assertEqual(len(venue.audit_chain), 5)
        self.assertTrue(venue.verify_audit_chain())
        self.assertNotIn(PASSWORD_VALUE, json.dumps([rec.to_wire_dict() for rec in venue.audit_chain]))

    def test_real_account_and_excess_leverage_are_refused(self) -> None:
        live = FakeMt5Sdk(trade_mode=2)
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            self._venue(live).connect()
        self.assertGreaterEqual(live.shutdown_calls, 1)
        with self.assertRaises(Mt5MarginRefusalError):
            self._venue(FakeMt5Sdk(leverage=1000)).connect()

    def test_rates_and_unknown_outcome(self) -> None:
        sdk = FakeMt5Sdk()
        transport = Mt5NativePythonTransport(mt5_module=sdk)
        creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, {"CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                                                           "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": PASSWORD_VALUE})
        transport.connect(creds)
        bars = transport.copy_rates("EURUSD", "M5", 3)
        self.assertEqual(len(bars), 3)
        self.assertEqual(bars[0]["high"], "1.1005")
        with self.assertRaises(ContractError):
            transport.copy_rates("EURUSD", "M7", 3)
        sdk.fail_send = True
        req = Mt5OrderRequest(request_id="req-x", action="OPEN", symbol="EURUSD", side=Side.BUY, volume_lots=D("0.10"),
                              price=D("1.10010"), stop_loss=D("1.09500"), position_ticket=None, deviation_points=20,
                              magic=20261116, comment="cas-open", created_at=T0)
        with self.assertRaises(Mt5OutcomeUnknownError):
            transport.send_order(req, valve_grant=_grant_for_req(req, server=creds.server))

    def test_native_transport_requires_password(self) -> None:
        creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
        with self.assertRaises(Mt5NotConfiguredError):
            Mt5NativePythonTransport(mt5_module=FakeMt5Sdk()).connect(creds)


class SpoolBridgeTransportTests(unittest.TestCase):
    def test_full_spool_lifecycle_with_hash_bound_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            emu, venue = spool_venue(tmp)
            o1 = open_order("s-open-1")
            r1 = venue.execute(o1, valve_decision=clear(o1))
            self.assertEqual(r1.receipt.status, "FILLED")
            self.assertEqual(r1.receipt.price, D("1.10010"))
            self.assertEqual(r1.request.to_spool_dict()["protocol"], MT5_SPOOL_PROTOCOL)
            doc = r1.request.to_spool_dict()
            self.assertTrue(all(isinstance(v, str) for v in doc.values()))
            core = {k: v for k, v in doc.items() if k not in ("request_sha256", "request_hmac_sha256")}
            self.assertEqual(sha256(canonical_bytes(core)).hexdigest(), doc["request_sha256"])
            ticket = r1.receipt.position_ticket

            o2 = OrderIntent(order_id="s-amend-1", action_ref="act-s-amend-1", kind=ActionKind.AMEND_STOP, symbol="EURUSD",
                             stop_price=D("1.09800"), position_ticket=ticket)
            self.assertEqual(venue.execute(o2, valve_decision=clear(o2)).receipt.status, "MODIFIED")
            emu.set_quote("EURUSD", D("1.10200"), D("1.10210"))
            emu.publish_market()
            o3 = OrderIntent(order_id="s-reduce-1", action_ref="act-s-reduce-1", kind=ActionKind.REDUCE, symbol="EURUSD",
                             quantity_units=D("50000"), position_ticket=ticket)
            r3 = venue.execute(o3, valve_decision=clear(o3))
            self.assertEqual(r3.positions_after[0].volume_lots, D("0.5"))
            self.assertEqual(r3.account_after.balance, D("10095.00"))
            o4 = OrderIntent(order_id="s-close-1", action_ref="act-s-close-1", kind=ActionKind.CLOSE, symbol="EURUSD",
                             quantity_units=D("50000"), position_ticket=ticket)
            r4 = venue.execute(o4, valve_decision=clear(o4))
            self.assertEqual(r4.positions_after, ())
            self.assertEqual(r4.account_after.balance, D("10190.00"))
            self.assertEqual(sorted(p.name for p in Path(tmp, "hugosway_mt5").iterdir()), ["market_ticks.json"])
            self.assertEqual(len(emu.processed), 4)
            self.assertTrue(venue.verify_audit_chain())
            self.assertEqual(venue.audit_chain[-1].previous_sha256, venue.audit_chain[-2].record_sha256)

    def test_non_demo_terminal_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            emu = Mt5SpoolPaperTerminalEmulator(Path(tmp), server="Hugo demo PRO5", login=7001234, quotes=QUOTES, trade_mode="REAL")
            emu.publish_market()
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
            with self.assertRaises(LiveBrokerEndpointForbiddenError):
                Mt5SpoolBridgeTransport(tmp).connect(creds)
            wrong_login = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=1, server="Hugo demo PRO5")
            emu.trade_mode = "DEMO"
            emu.publish_market()
            with self.assertRaises(Mt5TransportError):
                Mt5SpoolBridgeTransport(tmp).connect(wrong_login)

    def test_tampered_receipt_and_timeout_are_never_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            emu = Mt5SpoolPaperTerminalEmulator(Path(tmp), server="Hugo demo PRO5", login=7001234, quotes=QUOTES)
            emu.publish_market()
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
            req = Mt5OrderRequest(request_id="req-tamper", action="OPEN", symbol="EURUSD", side=Side.BUY, volume_lots=D("0.10"),
                                  price=D("1.10010"), stop_loss=D("1.09500"), position_ticket=None, deviation_points=20,
                                  magic=20261116, comment="cas-open", created_at=T0, valve_decision_sha256="a" * 64)

            def tamper(_seconds: float) -> None:
                emu.process_pending()
                path = Path(tmp) / "order_receipt_req-tamper.json"
                doc = json.loads(path.read_text(encoding="ascii"))
                doc["request_sha256"] = "f" * 64
                path.write_text(json.dumps(doc), encoding="ascii")

            transport = Mt5SpoolBridgeTransport(tmp, sleep=tamper, poll_interval_seconds=0.01)
            transport.connect(creds)
            signed_req = sign_spool_valve_admission(transport.prepare_request(req), spool_dir=tmp)
            with self.assertRaises(Mt5TransportError):
                transport.send_order(signed_req, valve_grant=_grant_for_req(signed_req))

            ticks = iter(range(1000))
            silent = Mt5SpoolBridgeTransport(tmp, sleep=lambda _s: None, monotonic=lambda: float(next(ticks)),
                                             receipt_timeout_seconds=3, poll_interval_seconds=0.01)
            silent.connect(creds)
            req2 = sign_spool_valve_admission(
                silent.prepare_request(dataclasses.replace(req, request_id="req-silent")), spool_dir=tmp
            )
            with self.assertRaises(Mt5OutcomeUnknownError):
                silent.send_order(req2, valve_grant=_grant_for_req(req2))
            with self.assertRaises(Mt5TransportError):
                silent.send_order(req2, valve_grant=_grant_for_req(req2))

    def test_float_and_unsafe_integer_spool_json_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
            base = {"protocol": MT5_SPOOL_PROTOCOL, "server": "Hugo demo PRO5", "account_trade_mode": "DEMO", "ticks": [], "positions": [],
                    "account": {"login": "7001234", "currency": "USD", "balance": "10000", "equity": "10000", "margin": "0",
                                "margin_free": "10000", "leverage": "500"}}
            path = Path(tmp) / "market_ticks.json"
            path.write_text(json.dumps(base).replace('"balance": "10000"', '"balance": 10000.5'), encoding="ascii")
            with self.assertRaises(Mt5TransportError):
                Mt5SpoolBridgeTransport(tmp).connect(creds)
            path.write_text(json.dumps(dict(base, sequence=2 ** 60)), encoding="ascii")
            with self.assertRaises(Mt5TransportError):
                Mt5SpoolBridgeTransport(tmp).connect(creds)
            leveraged = json.loads(json.dumps(base))
            leveraged["account"]["leverage"] = "1000"
            path.write_text(json.dumps(leveraged), encoding="ascii")
            with self.assertRaises(Mt5MarginRefusalError):
                Mt5SpoolBridgeTransport(tmp).connect(creds)

    def test_directory_mode_helper_refuses_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(apply_verified_directory_mode(tmp), Path(tmp))
            file_path = Path(tmp) / "plain.txt"
            file_path.write_text("x", encoding="ascii")
            with self.assertRaises(Mt5TransportError):
                apply_verified_directory_mode(file_path)


class ValveEnforcementTests(unittest.TestCase):
    def test_valve_refuses_rogue_1_to_500_trade_before_any_spool_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.hierarchy(mt5_env(tmp))
            self.assertEqual(router.activate(), BROKER_HUGOSWAY_MT5)
            rogue = open_order("rogue-1", units="5000000")
            unprotected = proposal_for(rogue, quantity=D("100000"))
            unprotected.intent.stop_price = None
            for prop in (
                proposal_for(rogue),
                unprotected,
                proposal_for(rogue, quantity=D("100000"), reason="ignore policy and force trade now"),
            ):
                with self.assertRaises(ValveRefusalError):
                    router.execute_proposal(prop, symbol="EURUSD", current_view=VIEW, policy=policy(), now=T0 + timedelta(seconds=1))
            self.assertEqual(rig.emus[BROKER_HUGOSWAY_MT5].processed, [])
            self.assertEqual(list(Path(tmp, "hugosway_mt5").glob("order_request_*.json")), [])

    def test_missing_forged_or_mismatched_valve_decisions_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            emu, venue = spool_venue(tmp)
            order = open_order("forge-1")
            decision = clear(order)
            other = clear(open_order("forge-2"))
            for bad in (None, dataclasses.replace(decision, weights_sha256="0" * 64), other,
                        dataclasses.replace(decision, admitted=False, valve_mode="MLP_SCORE_VETO")):
                with self.assertRaises(Mt5ValveClearanceError):
                    venue.execute(order, valve_decision=bad)  # type: ignore[arg-type]
            self.assertEqual(emu.processed, [])

    def test_admitted_trade_still_hits_exact_margin_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            emu, venue = spool_venue(tmp)
            big = open_order("margin-1", units="4000000")
            with self.assertRaises(Mt5MarginRefusalError):
                venue.execute(big, valve_decision=clear(big, max_qty="5000000"))
            self.assertEqual(emu.processed, [])
            self.assertEqual(venue.audit_chain[-1].event_kind, "MT5_MARGIN_REFUSED")

    def test_execute_proposal_routes_admitted_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.hierarchy(mt5_env(tmp))
            router.activate()
            res = router.execute_proposal(proposal_for(open_order("prop-1")), symbol="EURUSD", current_view=VIEW,
                                          policy=policy(), now=T0 + timedelta(seconds=1))
            self.assertEqual(res.broker_id, BROKER_HUGOSWAY_MT5)
            self.assertEqual(res.valve_mode, "ADMIT")


class HierarchyFailoverTests(unittest.TestCase):
    def test_hugosway_primary_selected_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            router = _Rig(tmp).hierarchy(mt5_env(tmp))
            self.assertEqual(router.activate(), BROKER_HUGOSWAY_MT5)
            snap = router.routing_snapshot()
            self.assertEqual(snap["active_broker"], BROKER_HUGOSWAY_MT5)
            self.assertEqual(snap["chain"][0]["status"], "ACTIVE")
            self.assertEqual(snap["chain"][1]["status"], "STANDBY")

    def test_lhfx_secondary_takes_over_when_hugosway_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp, publish=(BROKER_LHFX_MT5,))
            router = rig.hierarchy(mt5_env(tmp))
            self.assertEqual(router.activate(), BROKER_LHFX_MT5)
            chain = {c["broker_id"]: c for c in router.routing_snapshot()["chain"]}
            self.assertEqual(chain[BROKER_HUGOSWAY_MT5]["status"], "FAILED")
            self.assertEqual(chain[BROKER_LHFX_MT5]["status"], "ACTIVE")
            o = open_order("lhfx-1")
            res = router.execute(o, valve_decision=clear(o))
            self.assertEqual(res.broker_id, BROKER_LHFX_MT5)
            self.assertEqual(rig.emus[BROKER_LHFX_MT5].processed, [res.request.request_id])

    def test_oanda_practice_fallback_when_no_mt5_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.hierarchy(mt5_env(tmp, hugo=False, lhfx=False, oanda=True))
            self.assertEqual(router.activate(), BROKER_OANDA_PRACTICE)
            o = open_order("oanda-1")
            res = router.execute(o, valve_decision=clear(o))
            self.assertEqual(res.oanda_receipt["status"], "FILLED")
            self.assertEqual(rig.oanda.orders[0]["stopLossOnFill"]["price"], "1.095")
            amend = OrderIntent(order_id="oanda-amend", action_ref="act-oanda-amend", kind=ActionKind.AMEND_STOP, symbol="EURUSD",
                                stop_price=D("1.09700"), take_profit_price=D("1.10600"), position_ticket="1")
            amend_res = router.execute(amend, valve_decision=clear(amend))
            self.assertEqual(amend_res.oanda_receipt["status"], "MODIFIED")
            self.assertEqual(rig.oanda.orders[-1]["takeProfit"]["price"], "1.106")
            close_ok = OrderIntent(order_id="oanda-close", action_ref="act-oanda-close", kind=ActionKind.CLOSE,
                                   symbol="EURUSD", quantity_units=D("100000"), position_ticket="1")
            close_res = router.execute(close_ok, valve_decision=clear(close_ok))
            self.assertTrue(close_res.accepted)
            self.assertEqual(close_res.oanda_receipt["status"], "CLOSED")
            close_missing = OrderIntent(order_id="oanda-close-miss", action_ref="act-oanda-close-miss", kind=ActionKind.CLOSE,
                                        symbol="EURUSD", quantity_units=D("1000"), position_ticket="999")
            with self.assertRaises(Mt5BridgeError):
                router.execute(close_missing, valve_decision=clear(close_missing))
            self.assertTrue(router.active_venue.verify_audit_chain())

    def test_nothing_configured_and_live_account_abort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BrokerFailoverExhaustedError):
                _Rig(tmp).hierarchy(mt5_env(tmp, hugo=False, lhfx=False)).activate()
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp, hugo_trade_mode="REAL")
            router = rig.hierarchy(mt5_env(tmp))
            with self.assertRaises(LiveBrokerEndpointForbiddenError):
                router.activate()
            self.assertIsNone(router.active_broker)


class DualShieldBarbellTests(unittest.TestCase):
    def _router(self, tmp: str, rig: _Rig, **env_kw) -> DualShieldBrokerRouter:
        router = rig.dual(mt5_env(tmp, oanda=True, **env_kw))
        router.activate_all()
        return router

    def test_a_normal_hugosway_trade_verified_against_oanda_quote_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig)
            self.assertEqual(set(router.venues), {BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5, BROKER_OANDA_PRACTICE})
            o = open_order("ds-a-1")
            ex = router.execute_open(o, valve_decision=clear(o))
            self.assertEqual(ex.executed_on, BROKER_HUGOSWAY_MT5)
            self.assertFalse(ex.safe_harbor)
            self.assertEqual(ex.quote_verdicts[0].reference_source, "OANDA_PRACTICE")
            self.assertTrue(ex.quote_verdicts[0].passed)
            self.assertEqual(ex.quote_verdicts[0].divergence_bps, D("0"))
            self.assertEqual(ex.stop_loss_risk, D("510.00"))
            self.assertEqual(ex.stop_loss_risk_cap, D("1000.00"))
            self.assertEqual(ex.result.margin_check.required_margin, D("220.02"))
            self.assertEqual(rig.oanda.orders, [])
            json.dumps(ex.to_wire_dict())

    def test_b_offshore_wick_spike_blocked_and_degraded_to_oanda_safe_harbor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig, CAS_FOREX_LHFX_MT5_LOGIN="")
            hugo = rig.emus[BROKER_HUGOSWAY_MT5]
            hugo.set_quote("EURUSD", D("1.10500"), D("1.10510"))
            hugo.publish_market()
            o = open_order("ds-b-1")
            ex = router.execute_open(o, valve_decision=clear(o))
            self.assertTrue(ex.safe_harbor)
            self.assertEqual(ex.executed_on, BROKER_OANDA_PRACTICE)
            self.assertEqual(ex.trail[0]["outcome"], "OFF_MARKET_QUOTE")
            self.assertEqual(ex.trail[0]["reason"], "MID_DIVERGES_FROM_REGULATED_REFERENCE")
            self.assertEqual(ex.result.oanda_receipt["status"], "FILLED")
            self.assertEqual(hugo.processed, [])
            harbor = router.routing_snapshot()["dual_shield"]["safe_harbor"]
            self.assertEqual(harbor["leverage"], "1:50")
            self.assertGreaterEqual(len(harbor["recent_degradations"]), 1)

    def test_b2_hugosway_spike_fails_over_to_healthy_lhfx(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig)
            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("EURUSD", D("1.09400"), D("1.09410"))
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            o = open_order("ds-b2-1", stop="1.09300")
            ex = router.execute_open(o, valve_decision=clear(o))
            self.assertEqual(ex.executed_on, BROKER_LHFX_MT5)
            self.assertEqual([t["outcome"] for t in ex.trail], ["OFF_MARKET_QUOTE", "EXECUTED"])

    def test_c_lhfx_secondary_executes_within_8pct_sleeve_when_hugosway_disconnected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig)
            (Path(tmp) / "hugosway_mt5" / "market_ticks.json").unlink()
            o = open_order("ds-c-1")
            ex = router.execute_open(o, valve_decision=clear(o))
            self.assertEqual(ex.executed_on, BROKER_LHFX_MT5)
            self.assertEqual(ex.trail[0]["outcome"], "DISCONNECTED")
            self.assertLessEqual(ex.result.margin_check.used_margin_after, D("8000"))
            self.assertEqual(router.routing_snapshot()["chain"][0]["status"], "DISCONNECTED")

    def test_c2_lhfx_sleeve_cap_breach_degrades_to_oanda(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp, lhfx_balance="5000")
            barbell = BarbellCapitalPolicy(oanda_reserve_share=D("0.80"), hugosway_share=D("0.15"), lhfx_share=D("0.05"))
            router = rig.dual(mt5_env(tmp, hugo=False, oanda=True), barbell=barbell, min_post_trade_margin_level_pct=D("100"))
            router.activate_all()
            o = open_order("ds-c2-1", units="2250000", stop="1.09990")
            ex = router.execute_open(o, valve_decision=clear(o, max_qty="3000000"))
            self.assertIn({"broker_id": BROKER_LHFX_MT5, "outcome": "BARBELL_REFUSED", "reason": "SLEEVE_CAP_EXCEEDED"}, ex.trail)
            self.assertTrue(ex.safe_harbor)
            self.assertEqual(rig.emus[BROKER_LHFX_MT5].processed, [])

    def test_barbell_policy_math(self) -> None:
        pol = BarbellCapitalPolicy()
        eq = {BROKER_OANDA_PRACTICE: D("80000"), BROKER_HUGOSWAY_MT5: D("12000"), BROKER_LHFX_MT5: D("8000")}
        self.assertEqual(pol.require_sleeve(BROKER_LHFX_MT5, equities=eq, used_margin_after=D("8000.00"))["sleeve_cap"], "8000")
        with self.assertRaises(BarbellPolicyRefusalError) as ctx:
            pol.require_sleeve(BROKER_LHFX_MT5, equities=eq, used_margin_after=D("8000.01"))
        self.assertEqual(ctx.exception.reason, "SLEEVE_CAP_EXCEEDED")
        with self.assertRaises(BarbellPolicyRefusalError) as ctx:
            pol.require_sleeve(BROKER_HUGOSWAY_MT5, equities=dict(eq, OANDA_PRACTICE=D("10000")), used_margin_after=D("1"))
        self.assertEqual(ctx.exception.reason, "RESERVE_UNDERFUNDED")
        with self.assertRaises(BarbellPolicyRefusalError) as ctx:
            pol.require_sleeve(BROKER_HUGOSWAY_MT5, equities=dict(eq, OANDA_PRACTICE=D("90000"), HUGOSWAY_MT5=D("16000")),
                               used_margin_after=D("1"))
        self.assertEqual(ctx.exception.reason, "VENUE_CUSTODY_OVER_ALLOCATED")
        risk = pol.stop_loss_risk(symbol="USDJPY", units=D("50000"), entry_price=D("150.000"), stop_price=D("151.000"), quotes=QUOTES)
        self.assertEqual(risk, D("333.33"))
        self.assertEqual(pol.require_stop_risk(D("1000.00"), eq), D("1000.00"))
        with self.assertRaises(BarbellPolicyRefusalError):
            pol.require_stop_risk(D("1000.01"), eq)
        for bad in ({"oanda_reserve_share": D("0.70")}, {"oanda_reserve_share": D("0.40"), "hugosway_share": D("0.40"), "lhfx_share": D("0.20")}):
            with self.assertRaises(ContractError):
                BarbellCapitalPolicy(**bad)
        env_pol = BarbellCapitalPolicy.from_environ({"CAS_FOREX_BARBELL_OANDA_RESERVE_SHARE": "0.85",
                                                     "CAS_FOREX_BARBELL_HUGOSWAY_SHARE": "0.10",
                                                     "CAS_FOREX_BARBELL_LHFX_SHARE": "0.05"})
        self.assertEqual(env_pol.share_for(BROKER_OANDA_PRACTICE), D("0.85"))
        report = pol.allocation_report(eq)
        self.assertEqual(report["total_equity"], "100000")
        self.assertEqual(report["venues"][0]["actual_share"], "0.8")

    def test_stop_risk_over_1pct_refused_before_any_venue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig)
            o = open_order("ds-risk-1", units="300000", stop="1.09500")
            with self.assertRaises(BarbellPolicyRefusalError) as ctx:
                router.execute_open(o, valve_decision=clear(o))
            self.assertEqual(ctx.exception.reason, "STOP_RISK_EXCEEDS_EQUITY_PCT")
            self.assertEqual(rig.emus[BROKER_HUGOSWAY_MT5].processed, [])
            self.assertEqual(rig.oanda.orders, [])

    def test_quote_truth_oracle_limits(self) -> None:
        oracle = OandaQuoteTruthOracle.from_static_quotes(QUOTES)
        self.assertEqual(len(MAJOR_FX_PAIRS), 7)
        self.assertTrue(oracle.verify(BROKER_HUGOSWAY_MT5, "EURUSD", D("1.10010"), D("1.10020")).passed)
        wide = oracle.verify(BROKER_HUGOSWAY_MT5, "EURUSD", D("1.09990"), D("1.10030"))
        self.assertEqual(wide.reason, "OFFSHORE_SPREAD_EXCEEDS_REFERENCE_MULTIPLE")
        self.assertEqual(wide.spread_multiple, D("4.0000"))
        cross_ok = oracle.verify(BROKER_LHFX_MT5, "EURGBP", D("0.86780"), D("0.86792"))
        self.assertEqual(cross_ok.max_divergence_bps, D("25"))
        self.assertTrue(cross_ok.passed, cross_ok.divergence_bps)
        major_bad = oracle.verify(BROKER_LHFX_MT5, "EURUSD", D("1.10180"), D("1.10190"))
        self.assertFalse(major_bad.passed)
        abs_wide = OandaQuoteTruthOracle.from_static_quotes(QUOTES, max_spread_bps=D("1"), max_oanda_spread_multiple=D("100"))
        self.assertEqual(abs_wide.verify(BROKER_HUGOSWAY_MT5, "USDJPY", D("150.000"), D("150.030")).reason, "OFFSHORE_SPREAD_EXCEEDS_MAX_BPS")
        with self.assertRaises(QuoteReferenceUnavailableError):
            OandaQuoteTruthOracle.from_static_quotes({}).reference_quotes(("EURUSD",))

    def test_reference_unavailable_fails_closed_and_kraken_ecb_reference_with_attested_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.dual(mt5_env(tmp, lhfx=False))
            router.activate_all()
            o = open_order("ds-ref-1")
            with self.assertRaises(QuoteReferenceUnavailableError):
                router.execute_open(o, valve_decision=clear(o))
        stream = MarketStreamEnvelope.from_json_bytes((REPO_ROOT / "docs" / "contracts" / "initial-market-stream.json").read_bytes())
        eur = stream.pair_map()["EURUSD"]
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("EURUSD", eur.bid, eur.ask)
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            oracle = OandaQuoteTruthOracle.from_market_stream(lambda: stream)
            stop = (eur.bid - D("0.00300")).quantize(D("0.00001"))
            o = open_order("ds-ref-2", units="10000", stop=str(stop))
            unattested = rig.dual(mt5_env(tmp, lhfx=False), oracle=oracle)
            unattested.activate_all()
            with self.assertRaises(BrokerFailoverExhaustedError):
                unattested.execute_open(o, valve_decision=clear(o))
            attested = rig.dual(mt5_env(tmp, lhfx=False), oracle=oracle, equity_attestations={BROKER_OANDA_PRACTICE: D("80000")})
            attested.activate_all()
            o2 = open_order("ds-ref-3", units="10000", stop=str(stop))
            ex = attested.execute_open(o2, valve_decision=clear(o2))
            self.assertEqual(ex.executed_on, BROKER_HUGOSWAY_MT5)
            self.assertEqual(ex.quote_verdicts[0].reference_source, "KRAKEN_ECB_REFERENCE")

    def test_conservative_mode_routes_straight_to_oanda(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig, CAS_FOREX_PRIMARY_BROKER="OANDA_PRACTICE")
            o = open_order("ds-cons-1")
            ex = router.execute_open(o, valve_decision=clear(o))
            self.assertTrue(ex.safe_harbor)
            self.assertEqual(ex.trail, ({"broker_id": BROKER_OANDA_PRACTICE, "outcome": "EXECUTED", "reason": "SAFE_HARBOR"},))
            self.assertTrue(router.routing_snapshot()["dual_shield"]["safe_harbor"]["conservative_mode"])

    def test_unknown_outcome_is_never_rerouted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            ticks = iter(range(100000))

            def silent_factory(broker_id, mode, root):
                return Mt5SpoolBridgeTransport(Path(root) / broker_id.lower(), sleep=lambda _s: None,
                                               monotonic=lambda: float(next(ticks)), receipt_timeout_seconds=3,
                                               poll_interval_seconds=0.01)

            router = DualShieldBrokerRouter(environ=mt5_env(tmp, oanda=True), valve_gate=GATE, transport_factory=silent_factory,
                                            oanda_client_factory=rig.oanda_factory, clock=rig.clock)
            router.activate_all()
            o = open_order("ds-unk-1")
            with self.assertRaises(Mt5OutcomeUnknownError):
                router.execute_open(o, valve_decision=clear(o))
            self.assertEqual(rig.oanda.orders, [])
            self.assertEqual(rig.emus[BROKER_LHFX_MT5].processed, [])

    def test_d_protective_offset_plan_when_mt5_terminal_freezes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig)
            o1 = open_order("ds-d-1")
            o2 = open_order("ds-d-2", symbol="USDJPY", side=Side.SELL, units="50000", stop="151.000")
            for o in (o1, o2):
                self.assertEqual(router.execute_open(o, valve_decision=clear(o)).executed_on, BROKER_HUGOSWAY_MT5)
            self.assertIsNone(router.plan_protective_offsets(BROKER_HUGOSWAY_MT5))
            (Path(tmp) / "hugosway_mt5" / "market_ticks.json").unlink()
            plan = router.plan_protective_offsets(BROKER_HUGOSWAY_MT5)
            self.assertIsNotNone(plan)
            self.assertTrue(plan.delta_neutral)
            self.assertTrue(plan.fully_funded)
            by_symbol = {order.symbol: order for order in plan.orders}
            self.assertEqual(by_symbol["EURUSD"].side, Side.SELL)
            self.assertEqual(by_symbol["EURUSD"].units, D("100000"))
            self.assertEqual(by_symbol["EURUSD"].stop_price, D("1.10510"))
            self.assertEqual(by_symbol["EURUSD"].required_margin, D("2200.00"))
            self.assertEqual(by_symbol["USDJPY"].side, Side.BUY)
            self.assertEqual(by_symbol["USDJPY"].units, D("50000"))
            self.assertEqual(by_symbol["USDJPY"].stop_price, D("149.012"))
            self.assertEqual(plan.total_required_margin, D("3200.00"))
            self.assertEqual(router.routing_snapshot()["chain"][0]["status"], "FROZEN")
            json.dumps(plan.to_wire_dict())
            with self.assertRaises(Mt5ValveClearanceError):
                router.execute_offset_plan(plan, valve_decisions={})
            decisions = {intent.action_ref: clear(intent) for intent in plan.to_order_intents()}
            results = router.execute_offset_plan(plan, valve_decisions=decisions)
            self.assertTrue(all(r.oanda_receipt["status"] == "FILLED" for r in results))
            self.assertEqual(sorted(order["units"] for order in rig.oanda.orders), ["-100000", "50000"])

    def test_offset_planner_nets_opposing_positions(self) -> None:
        from cas_forex_revamp.venue.mt5_broker_bridge import Mt5Position
        planner = OandaProtectiveOffsetPlanner()
        positions = (
            Mt5Position(ticket="1", symbol="EURUSD", side=Side.BUY, volume_lots=D("1.00"), price_open=D("1.10010"), stop_loss=None, profit=D("0")),
            Mt5Position(ticket="2", symbol="EURUSD", side=Side.SELL, volume_lots=D("1.00"), price_open=D("1.10000"), stop_loss=None, profit=D("0")),
            Mt5Position(ticket="3", symbol="GBPUSD", side=Side.BUY, volume_lots=D("0.30"), price_open=D("1.27012"), stop_loss=None, profit=D("0")),
        )
        plan = planner.plan(broker_id=BROKER_LHFX_MT5, frozen_positions=positions, reference_quotes=QUOTES, oanda_margin_available=D("100"))
        self.assertEqual(len(plan.orders), 1)
        self.assertEqual(plan.orders[0].symbol, "GBPUSD")
        self.assertEqual(plan.orders[0].stop_price, D("1.28270"))
        self.assertEqual(plan.orders[0].required_margin, D("762.00"))
        self.assertFalse(plan.fully_funded)
        self.assertTrue(plan.delta_neutral)

    def test_dual_shield_snapshot_surfaces_all_four_pillars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = self._router(tmp, rig)
            snap = router.routing_snapshot()
            self.assertEqual(snap["architecture"], "DUAL_SHIELD_BARBELL")
            ds = snap["dual_shield"]
            self.assertEqual(ds["quote_truth_oracle"]["max_divergence_bps_major"], "15")
            self.assertEqual(ds["quote_truth_oracle"]["max_divergence_bps_cross"], "25")
            self.assertEqual(ds["quote_truth_oracle"]["max_oanda_spread_multiple"], "3")
            self.assertEqual(ds["barbell"]["oanda_reserve_share"], "0.8")
            self.assertEqual(ds["barbell"]["hugosway_share"], "0.12")
            self.assertEqual(ds["barbell"]["lhfx_share"], "0.08")
            self.assertEqual(ds["barbell"]["max_stop_loss_equity_risk_pct"], "1")
            self.assertEqual(ds["offset_planner"]["venue"], BROKER_OANDA_PRACTICE)
            self.assertEqual(ds["allocation"]["total_equity"], "100000")
            safe_broker_routing_payload(snap)
            self.assertNotIn(OANDA_TOKEN_VALUE, json.dumps(snap))


class CockpitBrokerRoutingEndpointTests(unittest.TestCase):
    def _get(self, base: str, path: str, headers: dict[str, str] | None = None):
        req = urllib.request.Request(base + path, headers=headers or {}, method="GET")
        return urllib.request.urlopen(req, timeout=5)  # nosec B310: local loopback cockpit test URL

    def test_broker_routing_endpoint_requires_auth_and_serves_safe_json_with_csp(self) -> None:
        router = DualShieldBrokerRouter(environ={}, valve_gate=GATE)
        srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, broker_router_reader=router.routing_snapshot)
        base = srv.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as unauth:
                self._get(base, "/api/broker-routing")
            self.assertEqual(unauth.exception.code, 401)
            unauth.exception.close()

            with self._get(base, "/api/broker-routing", headers=srv.auth_headers()) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("default-src 'none'", resp.headers.get("Content-Security-Policy", ""))
                doc = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(doc["chain"][0]["broker_id"], BROKER_HUGOSWAY_MT5)
            self.assertEqual(doc["chain"][0]["server"], "Hugosway-Demo")
            self.assertEqual(doc["platform"], "MetaTrader 5")
            self.assertIn("dual_shield", doc)
            self.assertEqual(doc["dual_shield"]["barbell"]["max_drawdown_pct"], "0.1")
        finally:
            srv.stop()

    def test_broker_routing_endpoint_absent_unsafe_or_failing(self) -> None:
        cases = [
            (None, 404),
            (lambda: {"schema": "x", "password": "leak-me-now"}, 500),
            (lambda: {"schema": "x", "ratio": 0.5}, 500),
            (lambda: (_ for _ in ()).throw(RuntimeError("boom-internal")), 500),
        ]
        for reader, code in cases:
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, broker_router_reader=reader)
            base = srv.start()
            try:
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    self._get(base, "/api/broker-routing", headers=srv.auth_headers())
                self.assertEqual(ctx.exception.code, code)
                body = ctx.exception.read().decode("utf-8")
                ctx.exception.close()
                self.assertNotIn("leak-me-now", body)
                self.assertNotIn("boom-internal", body)
            finally:
                srv.stop()
        with self.assertRaises(ContractError):
            LoopbackCockpitServer(repo_root=REPO_ROOT, broker_router_reader="not-callable")  # type: ignore[arg-type]




def _strip_mql5_comments_preserving_strings(src: str) -> str:
    """Strip MQL5 // and /* ... */ comments while keeping string literals and line numbers intact."""
    out: list[str] = []
    n = len(src)
    i = 0
    in_str = False
    while i < n:
        ch = src[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_balanced_parens(src: str, open_paren_idx: int) -> tuple[str, int]:
    """Return content inside (...) starting at open_paren_idx and closing index."""
    depth = 0
    in_str = False
    i = open_paren_idx
    n = len(src)
    while i < n:
        ch = src[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return src[open_paren_idx + 1 : i], i
        i += 1
    raise AssertionError("Unclosed '(' in MQL5 source")


def _split_top_level_commas(expr: str) -> list[str]:
    """Split comma-separated MQL5 arguments/parameters ignoring nested parens and strings."""
    parts: list[str] = []
    start = 0
    depth = 0
    in_str = False
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "(":
                depth += 1
            elif ch == ")" and depth > 0:
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(expr[start:i].strip())
                start = i + 1
        i += 1
    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


class Mql5BridgeSourceContractTests(unittest.TestCase):
    _NUMERIC_LITERAL_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")

    def _assert_receipt_json_contract(self, src: str, *, expected_min_calls: int = 1) -> tuple[list[str], list[tuple[int, list[str]]]]:
        cleaned = _strip_mql5_comments_preserving_strings(src)
        sig_match = re.search(r"\bstring\s+ReceiptJson\s*\(", cleaned)
        self.assertIsNotNone(sig_match, "ReceiptJson signature missing from MQL5 source")
        if sig_match is None:
            raise AssertionError("ReceiptJson signature missing")
        sig_open = sig_match.end() - 1
        sig_inner, _ = _extract_balanced_parens(cleaned, sig_open)
        params = _split_top_level_commas(sig_inner)
        self.assertEqual(len(params), 11, f"Expected 11 ReceiptJson params, got {len(params)}: {params}")
        self.assertEqual(" ".join(params[3].split()), "const uint retcode")
        for idx, param in enumerate(params):
            if idx != 3:
                self.assertTrue(" ".join(param.split()).startswith("const string "), f"Param {idx} changed unexpectedly: {param}")

        calls: list[tuple[int, list[str]]] = []
        for match in re.finditer(r"\bReceiptJson\s*\(", cleaned):
            open_idx = match.end() - 1
            if open_idx == sig_open:
                continue
            line_no = cleaned[: match.start()].count("\n") + 1
            inner, _ = _extract_balanced_parens(cleaned, open_idx)
            args = _split_top_level_commas(inner)
            self.assertEqual(len(args), 11, f"ReceiptJson call at line {line_no} has {len(args)} args, expected 11: {args}")
            ret_arg = args[3].strip()
            self.assertFalse(ret_arg.startswith('"'), f"ReceiptJson retcode at line {line_no} must be uint, got string {ret_arg}")
            self.assertNotEqual(ret_arg, "0", f"ReceiptJson retcode at line {line_no} uses untyped 0 instead of (uint)0")
            for idx, arg in enumerate(args):
                if idx == 3:
                    continue
                stripped = arg.strip()
                self.assertTrue(bool(stripped), f"Empty string arg {idx} at line {line_no}")
                self.assertIsNone(
                    self._NUMERIC_LITERAL_RE.fullmatch(stripped),
                    f"Implicit number-to-string arg {idx}={stripped!r} at line {line_no}",
                )
            calls.append((line_no, args))

        self.assertGreaterEqual(len(calls), expected_min_calls)
        return params, calls

    def test_cas_forex_mt5_bridge_all_receipt_json_calls_pass_11_typed_args(self) -> None:
        mq5_path = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"
        src = mq5_path.read_text(encoding="utf-8")
        _, calls = self._assert_receipt_json_contract(src, expected_min_calls=16)
        self.assertEqual(len(calls), 16)

    def test_receipt_json_contract_catches_10_arg_and_untyped_number_regressions(self) -> None:
        sig_header = (
            "string ReceiptJson(const string request_id, const string request_sha, const string status, const uint retcode,\n"
            "                   const string position_ticket, const string deal_ticket, const string volume,\n"
            "                   const string price, const string sl, const string tp, const string message) { return(""); }\n"
        )
        missing_tp_10_args = sig_header + (
            'void f() { WriteReceipt("r1", ReceiptJson("r1", "sha", "UNKNOWN", (uint)0, "0", "0", "0", "0", "0", "msg")); }\n'
        )
        with self.assertRaises(AssertionError):
            self._assert_receipt_json_contract(missing_tp_10_args)

        untyped_retcode_zero = sig_header + (
            'void f() { WriteReceipt("r1", ReceiptJson("r1", "sha", "UNKNOWN", 0, "0", "0", "0", "0", "0", "0", "msg")); }\n'
        )
        with self.assertRaises(AssertionError):
            self._assert_receipt_json_contract(untyped_retcode_zero)

        implicit_number_to_string_tp = sig_header + (
            'void f() { WriteReceipt("r1", ReceiptJson("r1", "sha", "REJECTED", (uint)10013, "0", "0", "0", "0", "0", 0, "msg")); }\n'
        )
        with self.assertRaises(AssertionError):
            self._assert_receipt_json_contract(implicit_number_to_string_tp)

    def test_cas_forex_mt5_bridge_lhfxsa_trade_mode_guard_requires_demo_or_two_key_real(self) -> None:
        src = (REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5").read_text(encoding="utf-8")
        cleaned = _strip_mql5_comments_preserving_strings(src)
        pinned_match = re.search(r"bool\s+IsPinnedLiveServer\s*\([^)]*\)\s*\{(.*?)\n\s*\}", cleaned, re.DOTALL)
        self.assertIsNotNone(pinned_match)
        assert pinned_match is not None
        self.assertIn('"lhfxsa-trade"', pinned_match.group(1))
        guard_match = re.search(r"bool\s+ModeGuard\s*\(\s*\)\s*\{(.*?)\n\s*\}", cleaned, re.DOTALL)
        self.assertIsNotNone(guard_match)
        assert guard_match is not None
        guard_body = guard_match.group(1)
        demo_pos = guard_body.find("m != ACCOUNT_TRADE_MODE_DEMO")
        lhfx_pos = guard_body.find('InpBrokerChannel == "lhfx_mt5" && server == "lhfxsa-trade"')
        live_sub_pos = guard_body.find('StringFind(server, "live") >= 0')
        self.assertGreater(demo_pos, 0)
        self.assertGreater(live_sub_pos, demo_pos)
        self.assertGreater(lhfx_pos, live_sub_pos)
        self.assertIn("StringTrimLeft(server);", guard_body)
        self.assertIn("StringTrimRight(server);", guard_body)


if __name__ == "__main__":
    unittest.main()
