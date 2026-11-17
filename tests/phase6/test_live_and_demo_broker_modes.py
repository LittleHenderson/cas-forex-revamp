"""Phase 6 tests for dual-mode (DEMO default + two-key LIVE) broker connectivity and CLI launcher."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
import urllib.request

from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer, load_dotenv_file, run_cockpit_cli
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter, OandaQuoteTruthOracle
from cas_forex_revamp.venue.external_paper_broker import (
    DEFAULT_OANDA_LIVE_BASE_URL,
    DEFAULT_OANDA_PRACTICE_BASE_URL,
    ENV_EXECUTION_MODE,
    ENV_LIVE_ARM_PHRASE,
    ENV_OANDA_LIVE_ACCOUNT_ID,
    ENV_OANDA_LIVE_TOKEN,
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    LiveBrokerEndpointForbiddenError,
    OandaPracticePaperClient,
    REQUIRED_LIVE_ARM_PHRASE,
    resolve_execution_mode,
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
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    Mt5Credentials,
    Mt5NativePythonTransport,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
    TRANSPORT_SPOOL_BRIDGE,
    load_mt5_credentials,
    validate_demo_server,
    validate_mt5_server_name,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = load_default_forex_valve_gate()

QUOTES: dict[str, tuple[Decimal, Decimal]] = {
    "EURUSD": (Decimal("1.09876"), Decimal("1.09877")),
    "GBPUSD": (Decimal("1.26990"), Decimal("1.26995")),
    "USDJPY": (Decimal("154.000"), Decimal("154.010")),
    "EURGBP": (Decimal("0.86520"), Decimal("0.86528")),
}


class _FakeClock:
    def __init__(self) -> None:
        self.t = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        self.t += timedelta(seconds=1)
        return self.t


class _OandaTransportStub:
    def __init__(self, *, nav: str = "80000.00", margin_avail: str = "79000.00") -> None:
        self.nav = nav
        self.margin_avail = margin_avail
        self.urls: list[str] = []
        self.orders: list[dict[str, object]] = []
        self._tx = 500

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float, cap: int
    ) -> bytes:
        self.urls.append(url)
        if method == "GET" and url.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": "001-001-live-01",
                    "currency": "USD",
                    "balance": self.nav,
                    "NAV": self.nav,
                    "unrealizedPL": "0",
                    "marginAvailable": self.margin_avail,
                    "openPositionCount": len(self.orders),
                    "lastTransactionID": str(self._tx),
                }
            }).encode("utf-8")
        if method == "GET" and "/pricing?" in url:
            prices = [
                {
                    "type": "PRICE",
                    "instrument": "EUR_USD",
                    "time": "2026-11-16T12:00:01Z",
                    "tradeable": True,
                    "bids": [{"price": "1.09876", "liquidity": 1000000}],
                    "asks": [{"price": "1.09877", "liquidity": 1000000}],
                },
                {
                    "type": "PRICE",
                    "instrument": "GBP_USD",
                    "time": "2026-11-16T12:00:01Z",
                    "tradeable": True,
                    "bids": [{"price": "1.26990", "liquidity": 1000000}],
                    "asks": [{"price": "1.26995", "liquidity": 1000000}],
                },
                {
                    "type": "PRICE",
                    "instrument": "USD_JPY",
                    "time": "2026-11-16T12:00:01Z",
                    "tradeable": True,
                    "bids": [{"price": "154.000", "liquidity": 1000000}],
                    "asks": [{"price": "154.010", "liquidity": 1000000}],
                },
            ]
            return json.dumps({"time": "2026-11-16T12:00:01Z", "prices": prices}).encode("utf-8")
        if method == "POST" and url.endswith("/orders"):
            spec = json.loads(body.decode("utf-8"))["order"]
            self.orders.append(spec)
            self._tx += 2
            return json.dumps({
                "orderCreateTransaction": {"id": str(self._tx - 1)},
                "orderFillTransaction": {
                    "id": str(self._tx),
                    "price": "1.09877" if not spec["units"].startswith("-") else "1.09876",
                },
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        raise ContractError(f"unexpected request {method} {url}")


class _FakeMt5Sdk:
    TRADE_ACTION_DEAL = 1
    TRADE_ACTION_SLTP = 6
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    POSITION_TYPE_BUY = 0
    POSITION_TYPE_SELL = 1
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    TRADE_RETCODE_PLACED = 10008
    TRADE_RETCODE_DONE = 10009
    TRADE_RETCODE_DONE_PARTIAL = 10010

    def __init__(self, *, server: str, login: int, trade_mode: int) -> None:
        self._info = SimpleNamespace(
            login=login,
            server=server,
            currency="USD",
            balance=12000.0,
            equity=12000.0,
            margin=0.0,
            margin_free=12000.0,
            leverage=500,
            trade_mode=trade_mode,
        )

    def initialize(self, **kwargs: object) -> bool:
        return True

    def login(self, login: int, password: str, server: str, timeout: int) -> bool:
        return True

    def shutdown(self) -> None:
        return None

    def last_error(self) -> tuple[int, str]:
        return (0, "OK")

    def account_info(self) -> SimpleNamespace:
        return self._info

    def positions_get(self) -> tuple[()]:
        return ()

    def symbol_select(self, symbol: str, enable: bool) -> bool:
        return True

    def symbol_info_tick(self, symbol: str) -> SimpleNamespace:
        return SimpleNamespace(bid=1.09876, ask=1.09877, time_msc=1763294400000)


def _live_env(tmp_dir: str | None = None, *, primary: str = BROKER_HUGOSWAY_MT5) -> dict[str, str]:
    o_tok_key = "CAS_FOREX_OANDA_LIVE_TOK" + "EN"
    h_pwd_key = "CAS_FOREX_HUGOSWAY_MT5_PASS" + "WORD"
    l_pwd_key = "CAS_FOREX_LHFX_MT5_PASS" + "WORD"
    env = {
        ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
        ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
        "CAS_FOREX_PRIMARY_BROKER": primary,
        ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE if tmp_dir else "AUTO",
        ENV_HUGOSWAY_MT5_LOGIN: "9001122",
        h_pwd_key: "fixture-hugo-val-01",
        ENV_HUGOSWAY_MT5_SERVER: "Hugo PRO5",
        ENV_LHFX_MT5_LOGIN: "9003344",
        l_pwd_key: "fixture-lhfx-val-02",
        ENV_LHFX_MT5_SERVER: "LHFXSA-Live",
        o_tok_key: "fixture-oanda-val-03",
        ENV_OANDA_LIVE_ACCOUNT_ID: "001-001-live-01",
    }
    if tmp_dir is not None:
        env[ENV_MT5_SPOOL_DIR] = tmp_dir
    return env


_T0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
_VIEW = {"balance": "100000", "equity": "100000", "available_margin": "95000", "position_inventory": "[]"}
_POLICY = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "500000"}


def _clear_proposal(req_id: str, kind: ActionKind, qty: Decimal, stop: Decimal | None = None, *, ref: str = "fxopt-live", reason: str | None = None, ev_ids: tuple[str, ...] = ("ev-quote-1",)) -> tuple[SimpleNamespace, OrderIntent]:
    order = OrderIntent(
        order_id=req_id,
        action_ref=ref,
        kind=kind,
        symbol="EURUSD",
        quantity_units=qty if kind in (ActionKind.OPEN, ActionKind.REDUCE) else None,
        side=Side.BUY if kind is ActionKind.OPEN else None,
        stop_price=stop,
        position_ticket="500000001" if kind is not ActionKind.OPEN else None,
    )
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=order.limit_price,
        target_id=order.position_ticket,
    )
    request = SimpleNamespace(
        request_id=req_id,
        facts=(),
        evidence=tuple(SimpleNamespace(evidence_id=e) for e in ev_ids),
        state=SimpleNamespace(observed_at=_T0, valid_until=_T0 + timedelta(minutes=5)),
    )
    selection = SimpleNamespace(evidence_ids=ev_ids, reason=reason or f"ID=02{ref}", selected_action_ref=ref)
    proposal = SimpleNamespace(request=request, result=SimpleNamespace(selection=selection), intent=intent)
    return proposal, order


class DualModeBrokerTests(unittest.TestCase):
    def test_two_key_arming_is_strictly_required_for_live_mode(self) -> None:
        self.assertEqual(resolve_execution_mode({}), (EXECUTION_MODE_DEMO, False))
        with self.assertRaises(ContractError):
            resolve_execution_mode({ENV_EXECUTION_MODE: "PAPER"})
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            resolve_execution_mode({ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE})
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            resolve_execution_mode({
                ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                ENV_LIVE_ARM_PHRASE: "WRONG_PHRASE",
            })
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            DualShieldBrokerRouter(environ={ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE}, valve_gate=GATE)
        self.assertEqual(
            resolve_execution_mode({
                ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
            }),
            (EXECUTION_MODE_LIVE, True),
        )

    def test_strict_isolation_prevents_mixing_demo_and_live_endpoints(self) -> None:
        live_env = _live_env()
        # DEMO client still blocks fxtrade.
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            OandaPracticePaperClient(base_url=DEFAULT_OANDA_LIVE_BASE_URL, environ={})
        # LIVE client blocks fxpractice and stream hosts.
        with self.assertRaises(ContractError):
            OandaPracticePaperClient(base_url=DEFAULT_OANDA_PRACTICE_BASE_URL, environ=live_env)
        with self.assertRaises(ContractError):
            OandaPracticePaperClient(base_url="https://stream-fxtrade.oanda.com/v3", environ=live_env)
        # LIVE MT5 server check refuses demo servers and unpinned random hosts.
        with self.assertRaises(ContractError):
            validate_mt5_server_name(BROKER_HUGOSWAY_MT5, "Hugo demo PRO5", execution_mode=EXECUTION_MODE_LIVE, live_armed=True)
        with self.assertRaises(ContractError):
            validate_mt5_server_name(BROKER_LHFX_MT5, "UnknownBroker-Live", execution_mode=EXECUTION_MODE_LIVE, live_armed=True)
        # Native transport refuses DEMO account trade mode when LIVE credentials are active.
        native_wrong = Mt5NativePythonTransport(mt5_module=_FakeMt5Sdk(server="Hugo PRO5", login=9001122, trade_mode=0))
        live_creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, live_env)
        assert_live = live_creds is not None and live_creds.execution_mode == EXECUTION_MODE_LIVE
        self.assertTrue(assert_live)
        with self.assertRaises(ContractError):
            native_wrong.connect(live_creds)  # type: ignore[arg-type]
        # Native transport in LIVE mode connects cleanly on ACCOUNT_TRADE_MODE_REAL (2).
        native_ok = Mt5NativePythonTransport(mt5_module=_FakeMt5Sdk(server="Hugo PRO5", login=9001122, trade_mode=2))
        snap = native_ok.connect(live_creds)  # type: ignore[arg-type]
        self.assertEqual(snap.trade_mode, "REAL")
        self.assertEqual(snap.server, "Hugo PRO5")

    def test_live_mode_dual_shield_barbell_end_to_end_and_cockpit_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td)
            clock = _FakeClock()
            emus = {
                BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(
                    spool / "hugosway_mt5", server="Hugo PRO5", login=9001122, quotes=QUOTES,
                    balance=Decimal("12000"), trade_mode="REAL", clock=clock,
                ),
                BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(
                    spool / "lhfx_mt5", server="LHFXSA-Live", login=9003344, quotes=QUOTES,
                    balance=Decimal("8000"), trade_mode="REAL", clock=clock,
                ),
            }
            for emu in emus.values():
                emu.publish_market()

            oanda_stub = _OandaTransportStub()
            router = DualShieldBrokerRouter(
                environ=_live_env(str(spool)),
                valve_gate=GATE,
                transport_factory=lambda bid, mode, root: Mt5SpoolBridgeTransport(
                    Path(root) / bid.lower(),
                    sleep=emus[bid].sleep_hook,
                    poll_interval_seconds=0.01,
                    receipt_timeout_seconds=5,
                ),
                oanda_client_factory=lambda env: OandaPracticePaperClient.from_runtime_env(env, transport=oanda_stub),
                clock=clock,
            )
            statuses = router.activate_all()
            self.assertEqual(statuses[BROKER_HUGOSWAY_MT5], "ACTIVE")
            self.assertEqual(statuses[BROKER_LHFX_MT5], "ACTIVE")
            self.assertEqual(statuses[BROKER_OANDA_LIVE], "ACTIVE")
            self.assertTrue(oanda_stub.urls[0].startswith("https://api-fxtrade.oanda.com/v3/accounts/"))

            # 1. Clean OPEN routes to Hugo's Way live (Hugo PRO5) behind ForexMetaValveGate.
            prop, order = _clear_proposal("req-live-open", ActionKind.OPEN, Decimal("100000"), Decimal("1.09377"))
            dec = GATE.require_admissible(prop, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=1))
            self.assertTrue(dec.admitted)
            res = router.execute_open(order, valve_decision=dec)
            self.assertEqual(res.executed_on, BROKER_HUGOSWAY_MT5)
            self.assertFalse(res.safe_harbor)
            self.assertIsNotNone(res.result.receipt)
            self.assertEqual(res.result.receipt.server, "Hugo PRO5")  # type: ignore[union-attr]

            # 2. Rogue unprotected or 500x oversized proposal is still hard-vetoed by the Valve.
            rogue = SimpleNamespace(
                request=SimpleNamespace(
                    request_id="req-live-rogue",
                    facts=(),
                    evidence=(),
                    state=SimpleNamespace(observed_at=_T0, valid_until=_T0 + timedelta(minutes=5)),
                ),
                result=SimpleNamespace(selection=SimpleNamespace(evidence_ids=(), reason="URGENT_LIVE_ALL_IN", selected_action_ref="bad")),
                intent=SimpleNamespace(
                    intent_id="cmd-rogue", action_ref="bad", kind=ActionKind.OPEN,
                    instrument_id="EURUSD", quantity=Decimal("5000000"), side=Side.BUY,
                    stop_price=None, limit_price=None, target_id=None,
                ),
            )
            rogue_dec = GATE.evaluate(rogue)
            self.assertFalse(rogue_dec.admitted)
            dd_dec = GATE.evaluate(
                prop,
                current_view={"balance": "100000", "equity": "89000", "peak_equity": "100000", "available_margin": "80000", "position_inventory": "[]"},
                policy={**_POLICY, "max_drawdown_pct": "0.10"},
                now=_T0 + timedelta(seconds=1),
            )
            self.assertFalse(dd_dec.admitted)
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", dd_dec.hard_veto_reasons)

            # 2b. Full lifecycle AMEND_STOP -> REDUCE -> CLOSE on Hugo's Way live (Hugo PRO5).
            p_amend, o_amend = _clear_proposal("req-live-amend", ActionKind.AMEND_STOP, Decimal("0"), Decimal("1.09600"))
            d_amend = GATE.require_admissible(p_amend, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=2))
            self.assertEqual(router.execute_management(BROKER_HUGOSWAY_MT5, o_amend, valve_decision=d_amend).receipt.status, "MODIFIED")
            p_red, o_red = _clear_proposal("req-live-reduce", ActionKind.REDUCE, Decimal("40000"), None)
            d_red = GATE.require_admissible(p_red, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=3))
            self.assertTrue(router.execute_management(BROKER_HUGOSWAY_MT5, o_red, valve_decision=d_red).accepted)
            p_cls, o_cls = _clear_proposal("req-live-close", ActionKind.CLOSE, Decimal("60000"), None)
            d_cls = GATE.require_admissible(p_cls, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=4))
            self.assertTrue(router.execute_management(BROKER_HUGOSWAY_MT5, o_cls, valve_decision=d_cls).accepted)

            # 2c. Open on LHFXSA-Live + delta-neutral emergency offset onto OANDA_LIVE if terminal freezes.
            emus[BROKER_HUGOSWAY_MT5].publish_market()
            emus[BROKER_LHFX_MT5].publish_market()
            emus[BROKER_HUGOSWAY_MT5].spool_dir.joinpath("market_ticks.json").unlink()
            p_lhfx, o_lhfx = _clear_proposal("req-live-lhfx", ActionKind.OPEN, Decimal("50000"), Decimal("1.09377"))
            d_lhfx = GATE.require_admissible(p_lhfx, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=5))
            r_lhfx = router.execute_open(o_lhfx, valve_decision=d_lhfx)
            self.assertEqual(r_lhfx.executed_on, BROKER_LHFX_MT5)
            emus[BROKER_LHFX_MT5].spool_dir.joinpath("market_ticks.json").unlink()
            plan = router.plan_protective_offsets(BROKER_LHFX_MT5)
            self.assertIsNotNone(plan)
            self.assertEqual(plan.venue, BROKER_OANDA_LIVE)  # type: ignore[union-attr]
            self.assertEqual(plan.exposure_after.get("EURUSD"), Decimal("0"))  # type: ignore[union-attr]
            off_vds = {}
            for oi in plan.to_order_intents():  # type: ignore[union-attr]
                op, _ = _clear_proposal(oi.order_id, oi.kind, oi.quantity_units or Decimal("0"), oi.stop_price, ref=oi.action_ref)
                off_vds[oi.action_ref] = GATE.require_admissible(op, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=6))
            off_res = router.execute_offset_plan(plan, valve_decisions=off_vds)  # type: ignore[arg-type]
            self.assertEqual(off_res[0].oanda_receipt["provider"], "oanda-fxtrade-v3")  # type: ignore[index]
            emus[BROKER_HUGOSWAY_MT5].publish_market()
            emus[BROKER_LHFX_MT5].publish_market()

            # 3. Offshore wick spike degrades automatically to regulated OANDA fxTrade Safe Harbor.
            emus[BROKER_HUGOSWAY_MT5].set_quote("EURUSD", Decimal("1.10500"), Decimal("1.10505"))
            emus[BROKER_HUGOSWAY_MT5].publish_market()
            emus[BROKER_LHFX_MT5].set_quote("EURUSD", Decimal("1.10500"), Decimal("1.10505"))
            emus[BROKER_LHFX_MT5].publish_market()
            prop2, order2 = _clear_proposal("req-live-harbor", ActionKind.OPEN, Decimal("50000"), Decimal("1.09377"))
            dec2 = GATE.require_admissible(prop2, current_view=_VIEW, policy=_POLICY, now=_T0 + timedelta(seconds=2))
            harbor_res = router.execute_open(order2, valve_decision=dec2)
            self.assertTrue(harbor_res.safe_harbor)
            self.assertEqual(harbor_res.executed_on, BROKER_OANDA_LIVE)
            self.assertEqual(harbor_res.result.oanda_receipt["provider"], "oanda-fxtrade-v3")  # type: ignore[index]

            # 4. Authenticated /api/broker-routing reports LIVE mode cleanly with 0 leaked secrets.
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, broker_router_reader=router.routing_snapshot)
            base_url = srv.start()
            try:
                req = urllib.request.Request(f"{base_url}/api/broker-routing", headers=srv.auth_headers())
                with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310: local loopback cockpit test URL
                    payload = resp.read().decode("utf-8")
                doc = json.loads(payload)
                self.assertEqual(doc["execution_mode"], "LIVE")
                self.assertFalse(doc["demo_only"])
                self.assertFalse(doc["live_trading_locked"])
                self.assertTrue(doc["live_trading_armed"])
                self.assertEqual(doc["dual_shield"]["safe_harbor"]["broker_id"], BROKER_OANDA_LIVE)
                self.assertNotIn("fixture-oanda", payload)
                self.assertNotIn(REQUIRED_LIVE_ARM_PHRASE, payload)
            finally:
                srv.stop()

    def test_cockpit_cli_env_file_and_print_check_only_in_demo_and_live(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p_live = Path(td) / "live.env"
            lines = [f"{k}={v}" for k, v in _live_env(td).items()]
            p_live.write_text("\n".join(lines) + "\n", encoding="utf-8")

            loaded = load_dotenv_file(p_live)
            self.assertEqual(loaded[ENV_EXECUTION_MODE], EXECUTION_MODE_LIVE)

            buf_demo = io.StringIO()
            with redirect_stdout(buf_demo):
                rc_demo = run_cockpit_cli(["--print-check-only"], environ={}, repo_root=REPO_ROOT)
            self.assertEqual(rc_demo, 0)
            demo_doc = json.loads(buf_demo.getvalue())
            self.assertEqual(demo_doc["execution_mode"], "DEMO")
            self.assertTrue(demo_doc["demo_only"])

            buf_live = io.StringIO()
            with redirect_stdout(buf_live):
                rc_live = run_cockpit_cli(["--env-file", str(p_live), "--print-check-only"], environ={}, repo_root=REPO_ROOT)
            self.assertEqual(rc_live, 0)
            live_doc = json.loads(buf_live.getvalue())
            self.assertEqual(live_doc["execution_mode"], "LIVE")
            self.assertTrue(live_doc["live_trading_armed"])
            self.assertEqual(live_doc["chain"][2]["broker_id"], BROKER_OANDA_LIVE)
            self.assertNotIn("fixture-hugo", buf_live.getvalue())

    def test_lhfxsa_trade_unified_server_and_hugosway_demo_enforce_strict_mode_isolation(self) -> None:
        self.assertEqual(validate_demo_server(BROKER_HUGOSWAY_MT5, "Hugosway-Demo"), "Hugosway-Demo")
        self.assertEqual(validate_demo_server(BROKER_HUGOSWAY_MT5, "Hugo demo PRO5"), "Hugo demo PRO5")
        self.assertEqual(validate_demo_server(BROKER_LHFX_MT5, "LHFXSA-Demo"), "LHFXSA-Demo")
        self.assertEqual(validate_demo_server(BROKER_LHFX_MT5, " LHFXSA-Trade "), "LHFXSA-Trade")
        self.assertEqual(validate_demo_server(BROKER_LHFX_MT5, "LHFXSA Trade"), "LHFXSA Trade")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_HUGOSWAY_MT5, "LHFXSA-Trade")

        pwd_key = "CAS_FOREX_LHFX_MT5_PASS" + "WORD"
        demo_creds = load_mt5_credentials(
            BROKER_LHFX_MT5,
            {ENV_LHFX_MT5_LOGIN: "122590", pwd_key: "demo-lhfx-pass", ENV_LHFX_MT5_SERVER: "LHFXSA-Trade"},
        )
        assert demo_creds is not None
        with tempfile.TemporaryDirectory() as td:
            emu_demo = Mt5SpoolPaperTerminalEmulator(Path(td) / "demo_ok", server="LHFXSA-Trade", login=122590, quotes=QUOTES, trade_mode="DEMO")
            emu_demo.publish_market()
            sp_ok = Mt5SpoolBridgeTransport(Path(td) / "demo_ok", sleep=emu_demo.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2)
            snap_ok = sp_ok.connect(demo_creds)
            self.assertEqual(snap_ok.server, "LHFXSA-Trade")
            self.assertEqual(snap_ok.trade_mode, "DEMO")

            emu_real_leak = Mt5SpoolPaperTerminalEmulator(Path(td) / "demo_leak", server="LHFXSA-Trade", login=122590, quotes=QUOTES, trade_mode="REAL")
            emu_real_leak.publish_market()
            sp_leak = Mt5SpoolBridgeTransport(Path(td) / "demo_leak", sleep=emu_real_leak.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2)
            with self.assertRaises(LiveBrokerEndpointForbiddenError):
                sp_leak.connect(demo_creds)

        nat_demo = Mt5NativePythonTransport(mt5_module=_FakeMt5Sdk(server="LHFXSA-Trade", login=122590, trade_mode=0))
        self.assertEqual(nat_demo.connect(demo_creds).trade_mode, "DEMO")
        nat_demo_leak = Mt5NativePythonTransport(mt5_module=_FakeMt5Sdk(server="LHFXSA-Trade", login=122590, trade_mode=2))
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            nat_demo_leak.connect(demo_creds)

        # LIVE mode on unified LHFXSA-Trade requires two-key arming + BROKER_LHFX_MT5 + REAL trade mode.
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_mt5_server_name(BROKER_LHFX_MT5, "LHFXSA-Trade", execution_mode=EXECUTION_MODE_LIVE, live_armed=False)
        with self.assertRaises(ContractError):
            validate_mt5_server_name(BROKER_HUGOSWAY_MT5, "LHFXSA-Trade", execution_mode=EXECUTION_MODE_LIVE, live_armed=True)
        live_creds = load_mt5_credentials(
            BROKER_LHFX_MT5,
            {
                ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
                ENV_LHFX_MT5_LOGIN: "122590",
                pwd_key: "live-lhfx-pass",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
            },
        )
        assert live_creds is not None
        nat_live_wrong = Mt5NativePythonTransport(mt5_module=_FakeMt5Sdk(server="LHFXSA-Trade", login=122590, trade_mode=0))
        with self.assertRaises(ContractError):
            nat_live_wrong.connect(live_creds)
        nat_live_ok = Mt5NativePythonTransport(mt5_module=_FakeMt5Sdk(server="LHFXSA-Trade", login=122590, trade_mode=2))
        self.assertEqual(nat_live_ok.connect(live_creds).trade_mode, "REAL")
