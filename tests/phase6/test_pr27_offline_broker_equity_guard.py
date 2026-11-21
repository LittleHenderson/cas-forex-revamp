"""PR #27 unit & contract tests: Offline Broker Zero-Equity & Drawdown Guard.

Verifies all 9 safety & accounting invariants across Mt5SpoolBridgeTransport,
Mt5PaperBrokerVenue, DualShieldBrokerRouter, AutonomousAiTrader, and
LoopbackCockpitServer:
1. Connected -> disconnected zero-equity preservation (no fake -$102k deficit).
2. Cold-start disconnected $0.00 (no fake RECOVERY_MODE deficit or false 10% drawdown).
3. Order refusal on offline Hugo (BROKER_OFFLINE) & clean failover to LHFX / OANDA.
4. Online-only deployable_equity_usd & <= 1.00% stop-risk sizing cap.
5. No false 10% drawdown trip when a 34% sleeve disconnects.
6. Real 10% drawdown STILL trips both when all online and when remaining online venues drop >= 10%.
7. Real $0.00 connected equity (connected=True) is NEVER masked and immediately trips 10% drawdown.
8. Strict JSON schema validation (additionalProperties: false, 0 floats, 0 SQLite GET writes).
9. Reconnection recovery restores ACTIVE status, full deployable_equity_usd, and clears notices.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import (
    CAPITAL_STATUS_AT_PRINCIPAL,
    CAPITAL_STATUS_RECOVERY_MODE,
    AutonomousAiTrader,
)
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.contracts import (
    ActionKind,
    Side,
    decimal_text,
)
from cas_forex_revamp.operator.frontier_backends import (
    _SENSITIVE_KEY_WORDS,
    FrontierModelRegistry,
)
from cas_forex_revamp.treasury.compounding_controller import CompoundingAndMilestoneController
from cas_forex_revamp.treasury.profit_sweep import ProfitSweepVault
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore, friendly_broker_label
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    ValveDecision,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
    STATUS_BROKER_OFFLINE,
)
from cas_forex_revamp.venue.external_paper_broker import (
    OandaPracticePaperClient,
    PaperBrokerTransportError,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_LIVE,
    BROKER_OANDA_PRACTICE,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5PaperBrokerVenue,
    Mt5PreDispatchTransportError,
    Mt5SpoolBridgeTransport,
    Mt5TransportError,
    OandaPracticeFallbackVenue,
    OrderIntent,
    SimMt5SpoolEa,
)
from tests.phase6.test_cockpit_api_contracts import validate_contract_schema

D = Decimal
T0 = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "docs" / "contracts"
VALVE_GATE = load_default_forex_valve_gate()

QUOTES_FX: dict[str, tuple[Decimal, Decimal]] = {
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.26500"), D("1.26512")),
    "USDJPY": (D("150.100"), D("150.115")),
}


def _dummy_cred(slot: str) -> str:
    return f"demo-v1-{slot}"


def _admit_order(order: OrderIntent) -> ValveDecision:
    return ValveDecision(
        admitted=True,
        valve_mode="ADMIT",
        mlp_score=0.92,
        threshold=0.55,
        mlp_admitted=True,
        hard_veto=False,
        hard_veto_reasons=(),
        features={},
        weights_sha256=VALVE_GATE.weights_sha256,
        request_id=order.order_id,
        selected_action_ref=order.action_ref,
    )


def _make_open_order(
    order_id: str,
    *,
    symbol: str = "EURUSD",
    side: Side = Side.BUY,
    units: Decimal = D("100000"),
    stop_price: Decimal = D("1.09000"),
    take_profit_price: Decimal | None = D("1.12000"),
) -> OrderIntent:
    return OrderIntent(
        order_id=f"ord-{order_id}",
        action_ref=f"act-{order_id}",
        kind=ActionKind.OPEN,
        symbol=symbol,
        quantity_units=units,
        side=side,
        stop_price=stop_price,
        take_profit_price=take_profit_price,
    )


class _FakeOandaTransport:
    def __init__(
        self,
        *,
        nav: Decimal,
        quotes: dict[str, tuple[Decimal, Decimal]],
        fail_http_520: bool = False,
    ) -> None:
        self.nav = nav
        self.quotes = dict(quotes)
        self.fail_http_520 = fail_http_520
        self._next_trade_id = 9001
        self._trades: list[dict[str, object]] = []

    def set_nav(self, nav: Decimal) -> None:
        self.nav = nav

    def set_fail_http_520(self, fail: bool) -> None:
        self.fail_http_520 = fail

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_wire_bytes: int = 32768,
    ) -> bytes:
        _ = (headers, timeout, max_wire_bytes)
        if self.fail_http_520:
            raise PaperBrokerTransportError("OANDA HTTP 520: Cloudflare origin weekend maintenance")
        if method == "GET" and url.endswith("/summary"):
            used = D("0.00")
            doc = {
                "account": {
                    "id": "101-001-7777777-001",
                    "currency": "USD",
                    "balance": decimal_text(self.nav),
                    "NAV": decimal_text(self.nav),
                    "unrealizedPL": "0.00",
                    "marginUsed": decimal_text(used),
                    "marginAvailable": decimal_text(self.nav - used),
                    "openTradeCount": len(self._trades),
                }
            }
            return json.dumps(doc).encode("utf-8")
        if method == "GET" and "/pricing" in url:
            prices = []
            for sym, (bid, ask) in sorted(self.quotes.items()):
                inst = f"{sym[:3]}_{sym[3:]}"
                prices.append({
                    "instrument": inst,
                    "time": "2026-11-20T15:00:00.000000000Z",
                    "tradeable": True,
                    "bids": [{"price": decimal_text(bid), "liquidity": 1000000}],
                    "asks": [{"price": decimal_text(ask), "liquidity": 1000000}],
                })
            return json.dumps({"time": "2026-11-20T15:00:00Z", "prices": prices}).encode("utf-8")
        if method == "GET" and url.endswith("/openTrades"):
            return json.dumps({"trades": list(self._trades)}).encode("utf-8")
        if method == "GET" and "/transactions" in url:
            return json.dumps({"transactions": [], "lastTransactionID": "1"}).encode("utf-8")
        if method == "POST" and url.endswith("/orders"):
            payload = json.loads((body or b"{}").decode("utf-8"))
            order_spec = payload.get("order", {})
            inst = str(order_spec.get("instrument", "EUR_USD")).replace("_", "")
            units_str = str(order_spec.get("units", "1000"))
            bid, ask = self.quotes.get(inst, (D("1.10000"), D("1.10010")))
            px = ask if not units_str.startswith("-") else bid
            tid = str(self._next_trade_id)
            self._next_trade_id += 1
            sl_px = (order_spec.get("stopLossOnFill") or {}).get("price")
            tp_px = (order_spec.get("takeProfitOnFill") or {}).get("price")
            self._trades.append({
                "id": tid,
                "instrument": f"{inst[:3]}_{inst[3:]}",
                "currentUnits": units_str,
                "price": decimal_text(px),
                "unrealizedPL": "0.00",
                "stopLossOrder": {"price": sl_px} if sl_px else None,
                "takeProfitOrder": {"price": tp_px} if tp_px else None,
            })
            fill_doc = {
                "orderFillTransaction": {
                    "id": tid,
                    "orderID": tid,
                    "instrument": f"{inst[:3]}_{inst[3:]}",
                    "units": units_str,
                    "price": decimal_text(px),
                    "pl": "0.00",
                    "time": "2026-11-20T15:00:00.000000000Z",
                    "tradeOpened": {"tradeID": tid, "units": units_str},
                },
                "lastTransactionID": tid,
            }
            return json.dumps(fill_doc).encode("utf-8")
        return b'{"errorMessage":"not found"}'


def _build_three_broker_rig(
    root: Path,
    *,
    oanda_nav: Decimal = D("240000.00"),
    hugo_balance: Decimal = D("36000.00"),
    lhfx_balance: Decimal = D("24000.00"),
    hugo_connected: bool = True,
    lhfx_connected: bool = True,
    demo_virtual_sleeve: bool = False,
    peak_store: PeakEquityStore | None = None,
    initial_capital_usd: Decimal | None = D("300000.00"),
) -> dict[str, object]:
    spool_root = root / "spool"
    emu_hugo = SimMt5SpoolEa(
        spool_root / "hugosway_mt5",
        server="Hugosway-Demo",
        login=7001111,
        quotes=QUOTES_FX,
        balance=hugo_balance,
        connected=hugo_connected,
        clock=lambda: T0,
    )
    emu_lhfx = SimMt5SpoolEa(
        spool_root / "lhfx_mt5",
        server="LHFXSA-Trade",
        login=8002222,
        quotes=QUOTES_FX,
        balance=lhfx_balance,
        connected=lhfx_connected,
        clock=lambda: T0,
    )
    emu_hugo.publish_market()
    emu_lhfx.publish_market()

    mt5_journal = Mt5MutationJournal(root / "mt5_mutations.sqlite3")
    tr_hugo = Mt5SpoolBridgeTransport(
        spool_root / "hugosway_mt5",
        sleep=emu_hugo.sleep_hook,
        poll_interval_seconds=0.005,
        receipt_timeout_seconds=1.0,
        clock=lambda: T0,
    )
    tr_lhfx = Mt5SpoolBridgeTransport(
        spool_root / "lhfx_mt5",
        sleep=emu_lhfx.sleep_hook,
        poll_interval_seconds=0.005,
        receipt_timeout_seconds=1.0,
        clock=lambda: T0,
    )
    hugo_venue = Mt5PaperBrokerVenue(
        broker_id=BROKER_HUGOSWAY_MT5,
        credentials=Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001111, "Hugosway-Demo"),
        transport=tr_hugo,
        valve_gate=VALVE_GATE,
        clock=lambda: T0,
        mutation_journal=mt5_journal,
    )
    lhfx_venue = Mt5PaperBrokerVenue(
        broker_id=BROKER_LHFX_MT5,
        credentials=Mt5Credentials(BROKER_LHFX_MT5, 8002222, "LHFXSA-Trade"),
        transport=tr_lhfx,
        valve_gate=VALVE_GATE,
        clock=lambda: T0,
        mutation_journal=mt5_journal,
    )
    hugo_venue.connect()
    lhfx_venue.connect()

    oanda_http = _FakeOandaTransport(nav=oanda_nav, quotes=QUOTES_FX)
    oanda_env = {
        "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-7777777-001",
        "CAS_FOREX_OANDA_PRACTICE_TOKEN": _dummy_cred("oanda"),
        "CAS_FOREX_OANDA_ACCOUNT_ID": "101-001-7777777-001",
        "CAS_FOREX_OANDA_API_TOKEN": _dummy_cred("oanda"),
    }
    oanda_client = OandaPracticePaperClient(
        environ=oanda_env,
        transport=oanda_http,
        clock=lambda: T0,
    )
    oanda_venue = OandaPracticeFallbackVenue(
        client=oanda_client,
        valve_gate=VALVE_GATE,
        clock=lambda: T0,
    )
    oanda_venue.connect()

    env = {
        **oanda_env,
        "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001111",
        "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": _dummy_cred("hugo"),
        "CAS_FOREX_HUGOSWAY_MT5_SERVER": "Hugosway-Demo",
        "CAS_FOREX_LHFX_MT5_LOGIN": "8002222",
        "CAS_FOREX_LHFX_MT5_PASSWORD": _dummy_cred("lhfx"),
        "CAS_FOREX_LHFX_MT5_SERVER": "LHFXSA-Trade",
        "CAS_FOREX_MT5_SPOOL_DIR": str(spool_root),
        "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1" if demo_virtual_sleeve else "0",
    }
    pk_store = peak_store if peak_store is not None else PeakEquityStore(root / "peak.sqlite3")
    router = DualShieldBrokerRouter(
        environ=env,
        valve_gate=VALVE_GATE,
        oracle=OandaQuoteTruthOracle.from_static_quotes(QUOTES_FX, reference_name="OANDA_PRACTICE_ORACLE"),
        barbell=BarbellCapitalPolicy(demo_virtual_sleeve=demo_virtual_sleeve),
        peak_equity_store=pk_store,
        mt5_mutation_journal=mt5_journal,
        clock=lambda: T0,
    )
    router.attach_venue(hugo_venue)
    router.attach_venue(lhfx_venue)
    router.attach_venue(oanda_venue)

    quota_store = DailyQuotaGovernanceStore(root / "quota.sqlite3")
    vault = ProfitSweepVault(root / "vault.sqlite3", initial_capital_usd=initial_capital_usd)
    dial_store = AggressionDialStore(root / "dial.sqlite3")
    registry = FrontierModelRegistry(
        environ={},
        resolve_dns=lambda _h: ("127.0.0.1",),
        clock=lambda: T0,
    )
    trader = AutonomousAiTrader(
        router=router,
        valve_gate=VALVE_GATE,
        model_registry=registry,
        execution_gate=lambda _inv: None,
        quota_store=quota_store,
        profit_vault=vault,
        aggression_dial=dial_store,
        initial_capital_usd=initial_capital_usd,
        journal_path=root / "ai_cycles.sqlite3",
        clock=lambda: T0,
    )
    return {
        "emu_hugo": emu_hugo,
        "emu_lhfx": emu_lhfx,
        "hugo_venue": hugo_venue,
        "lhfx_venue": lhfx_venue,
        "oanda_venue": oanda_venue,
        "oanda_http": oanda_http,
        "router": router,
        "pk_store": pk_store,
        "quota_store": quota_store,
        "vault": vault,
        "dial_store": dial_store,
        "trader": trader,
        "mt5_journal": mt5_journal,
    }


def _assert_no_floats_or_sensitive_keys(tc: unittest.TestCase, obj: object, path: str = "$") -> None:
    if isinstance(obj, float):
        tc.fail(f"Forbidden float at {path}: {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            low = str(k).lower()
            for word in _SENSITIVE_KEY_WORDS:
                if word in low:
                    tc.fail(f"Sensitive key {k!r} exposed at {path}")
            _assert_no_floats_or_sensitive_keys(tc, v, f"{path}.{k}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _assert_no_floats_or_sensitive_keys(tc, item, f"{path}[{idx}]")


class Pr27OfflineBrokerEquityGuardTests(unittest.TestCase):
    def test_connected_then_disconnected_hugo_preserves_equity_without_fake_deficit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = _build_three_broker_rig(
                Path(td),
                oanda_nav=D("100000.00"),
                hugo_balance=D("89695.34"),
                lhfx_balance=D("97478.59"),
                demo_virtual_sleeve=True,
                initial_capital_usd=D("287173.93"),
            )
            emu_hugo: SimMt5SpoolEa = rig["emu_hugo"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]

            # Baseline while all 3 brokers are connected
            eq_before = router.equities()
            self.assertEqual(eq_before[BROKER_HUGOSWAY_MT5], D("89695.34"))
            self.assertEqual(router.offline_brokers(), [])
            self.assertFalse(router.equity_incomplete())

            # Test both EA-cached disconnect AND raw-zero disconnect (un-recompiled terminal reporting 0.00)
            for raw_zero in (False, True):
                emu_hugo.set_connected(False, raw_zero_account=raw_zero)
                emu_hugo.publish_market()

                self.assertEqual(router.offline_brokers(), [BROKER_HUGOSWAY_MT5])
                self.assertTrue(router.equity_incomplete())
                eq_after = router.equities()
                self.assertEqual(eq_after[BROKER_HUGOSWAY_MT5], D("89695.34"))
                self.assertEqual(
                    router.online_equities(),
                    {
                        BROKER_OANDA_PRACTICE: D("100000.00"),
                        BROKER_LHFX_MT5: D("97478.59"),
                    },
                )
                self.assertEqual(router.online_total_equity(), D("197478.59"))

                snap = trader.status_snapshot(now=T0)
                self.assertEqual(snap["deployable_equity_usd"], "197478.59")
                bs = snap["banked_session"]
                self.assertEqual(bs["current_total_equity_usd"], "287173.93")
                self.assertEqual(bs["deficit_to_principal_usd"], "0")
                self.assertEqual(bs["capital_status"], CAPITAL_STATUS_AT_PRINCIPAL)
                self.assertEqual(bs["offline_brokers"], [BROKER_HUGOSWAY_MT5])
                self.assertEqual(bs["online_equity_usd"], "197478.59")
                self.assertIs(bs["equity_incomplete_brokers_offline"], True)
                self.assertIsNotNone(bs["offline_broker_notice"])
                self.assertIn("Hugo's Way", str(bs["offline_broker_notice"]))
                self.assertIn("not a trading loss", str(bs["offline_broker_notice"]))

    def test_cold_start_disconnected_zero_equity_prevents_fake_recovery_and_false_drawdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Pre-seed PeakEquityStore with $300,000 from yesterday's full 3-broker session
            pk_store = PeakEquityStore(root / "peak.sqlite3")
            pk_store.observe_equity(
                "dual-shield-barbell",
                current_equity=D("300000.00"),
                opening_balance=D("300000.00"),
                now=T0 - timedelta(hours=4),
            )
            self.assertEqual(pk_store.read_peak("dual-shield-barbell"), D("300000.00"))

            # Cold-start with Hugo already disconnected ($0.00, never connected in this process)
            rig = _build_three_broker_rig(
                root,
                oanda_nav=D("240000.00"),
                hugo_balance=D("0.00"),
                lhfx_balance=D("24000.00"),
                hugo_connected=False,
                lhfx_connected=True,
                demo_virtual_sleeve=False,
                peak_store=pk_store,
                initial_capital_usd=D("300000.00"),
            )
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]

            self.assertEqual(router.offline_brokers(), [BROKER_HUGOSWAY_MT5])
            self.assertEqual(router.peak_equity(), D("300000.00"))
            self.assertEqual(router.online_total_equity(), D("264000.00"))

            rsnap = router.routing_snapshot()
            self.assertEqual(rsnap["dual_shield"]["allocation"]["drawdown_pct"], "0")
            self.assertEqual(rsnap["dual_shield"]["allocation"]["offline_brokers"], [BROKER_HUGOSWAY_MT5])
            self.assertEqual(rsnap["dual_shield"]["allocation"]["online_equity"], "264000")
            self.assertIs(rsnap["dual_shield"]["allocation"]["equity_incomplete"], True)

            ok, elig_reason = router.check_open_eligibility("EURUSD")
            self.assertTrue(ok)
            self.assertEqual(elig_reason, f"ELIGIBLE:{BROKER_LHFX_MT5}")

            tsnap = trader.status_snapshot(now=T0)
            self.assertEqual(tsnap["deployable_equity_usd"], "264000")
            bs = tsnap["banked_session"]
            self.assertEqual(bs["capital_status"], CAPITAL_STATUS_AT_PRINCIPAL)
            self.assertEqual(bs["deficit_to_principal_usd"], "0")
            self.assertIs(bs["vault_sweeps_paused_for_recovery"], True)
            self.assertIs(bs["equity_incomplete_brokers_offline"], True)

            # If an online broker genuinely loses $2,500 during the cold-start offline session,
            # that real -$2,500 online deficit IS tracked (not -$38,500, and not masked!)
            oanda_http: _FakeOandaTransport = rig["oanda_http"]  # type: ignore[assignment]
            oanda_venue: OandaPracticeFallbackVenue = rig["oanda_venue"]  # type: ignore[assignment]
            oanda_http.set_nav(D("237500.00"))
            oanda_venue.probe_account_summary(now=T0 + timedelta(seconds=5))
            tsnap_loss = trader.status_snapshot(now=T0 + timedelta(seconds=5))
            bs_loss = tsnap_loss["banked_session"]
            self.assertEqual(bs_loss["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertEqual(bs_loss["deficit_to_principal_usd"], "2500")

    def test_offline_hugo_refuses_order_and_cleanly_fails_over_to_lhfx_and_oanda(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = _build_three_broker_rig(Path(td))
            emu_hugo: SimMt5SpoolEa = rig["emu_hugo"]  # type: ignore[assignment]
            emu_lhfx: SimMt5SpoolEa = rig["emu_lhfx"]  # type: ignore[assignment]
            hugo_venue: Mt5PaperBrokerVenue = rig["hugo_venue"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]

            emu_hugo.set_connected(False, raw_zero_account=True)
            emu_hugo.publish_market()
            hugo_venue.probe()
            self.assertTrue(hugo_venue.is_offline)

            # 1. Direct venue.execute refuses pre-dispatch with Mt5PreDispatchTransportError (Mt5TransportError)
            direct_order = _make_open_order("direct-offline-1", units=D("10000"))
            with self.assertRaises(Mt5TransportError) as ctx:
                hugo_venue.execute(direct_order, valve_decision=_admit_order(direct_order))
            self.assertIsInstance(ctx.exception, Mt5PreDispatchTransportError)
            self.assertIn(STATUS_BROKER_OFFLINE, str(ctx.exception))
            self.assertFalse(router.has_any_unresolved_mutation())

            # 2. Router fails over cleanly from offline Hugo -> online LHFX_MT5
            routed_1 = _make_open_order("failover-lhfx-1", units=D("10000"))
            exec_1 = router.execute_open(routed_1, valve_decision=_admit_order(routed_1))
            self.assertEqual(exec_1.executed_on, BROKER_LHFX_MT5)
            self.assertFalse(exec_1.safe_harbor)
            self.assertEqual(exec_1.trail[0]["broker_id"], BROKER_HUGOSWAY_MT5)
            self.assertEqual(exec_1.trail[0]["outcome"], STATUS_BROKER_OFFLINE)
            self.assertFalse(router.has_any_unresolved_mutation())

            # 3. Both MT5 brokers offline -> router fails over cleanly to OANDA_PRACTICE safe harbor
            emu_lhfx.set_connected(False, raw_zero_account=True)
            emu_lhfx.publish_market()
            routed_2 = _make_open_order("failover-oanda-2", units=D("10000"))
            exec_2 = router.execute_open(routed_2, valve_decision=_admit_order(routed_2))
            self.assertEqual(exec_2.executed_on, BROKER_OANDA_PRACTICE)
            self.assertTrue(exec_2.safe_harbor)
            self.assertEqual(
                [(t["broker_id"], t["outcome"]) for t in exec_2.trail],
                [
                    (BROKER_HUGOSWAY_MT5, STATUS_BROKER_OFFLINE),
                    (BROKER_LHFX_MT5, STATUS_BROKER_OFFLINE),
                    (BROKER_OANDA_PRACTICE, "EXECUTED"),
                ],
            )
            self.assertFalse(router.has_any_unresolved_mutation())

    def test_online_only_deployable_equity_and_one_percent_stop_risk_sizing_cap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = _build_three_broker_rig(
                Path(td),
                oanda_nav=D("240000.00"),
                hugo_balance=D("36000.00"),
                lhfx_balance=D("24000.00"),
                demo_virtual_sleeve=False,
            )
            emu_hugo: SimMt5SpoolEa = rig["emu_hugo"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]

            # Disconnect Hugo ($36k) -> online equity is $264,000 -> 1.00% cap is $2,640.00 (not $3,000.00!)
            emu_hugo.set_connected(False, raw_zero_account=True)
            emu_hugo.publish_market()
            self.assertEqual(router.online_total_equity(), D("264000.00"))
            self.assertEqual(trader.status_snapshot(now=T0)["deployable_equity_usd"], "264000")

            # Order with stop distance 0.01010 (1.10010 ask -> 1.09000 SL) & 277,000 units = $2,797.70 risk:
            # $2,797.70 <= $3,000 (1% of $300k), so it WOULD pass if offline Hugo funds were counted,
            # MUST fail because $2,797.70 > $2,640.00 (1% of $264k online equity)!
            oversized = _make_open_order(
                "oversized-vs-online",
                units=D("277000"),
                stop_price=D("1.09000"),
            )
            with self.assertRaises(BarbellPolicyRefusalError) as ctx:
                router.execute_open(oversized, valve_decision=_admit_order(oversized))
            self.assertEqual(ctx.exception.reason, "STOP_RISK_EXCEEDS_EQUITY_PCT")

            # AutonomousAiTrader._compute_quantity also caps lot sizing strictly inside $2,640.00 online risk
            qty = trader._compute_quantity(
                symbol="EURUSD",
                side=Side.BUY,
                bid=D("1.10000"),
                ask=D("1.10010"),
                sl_price=D("1.09000"),
                total_equity=D("300000.00"),  # even if caller passed 300k, internal online cap clamps to 264k!
                risk_multiplier=D("1.00"),
                quotes_map=QUOTES_FX,
            )
            computed_risk = router.barbell.stop_loss_risk(
                symbol="EURUSD",
                units=qty,
                entry_price=D("1.10010"),
                stop_price=D("1.09000"),
                quotes=QUOTES_FX,
            )
            self.assertLessEqual(computed_risk, D("2640.00"))

    def test_no_false_ten_percent_drawdown_trip_when_thirty_four_percent_broker_disconnects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = _build_three_broker_rig(
                Path(td),
                oanda_nav=D("100000.00"),
                hugo_balance=D("102521.41"),
                lhfx_balance=D("97478.59"),
                demo_virtual_sleeve=True,
                initial_capital_usd=D("300000.00"),
            )
            emu_hugo: SimMt5SpoolEa = rig["emu_hugo"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]

            # Record $300,000 peak while all 3 are online
            router.equities()
            self.assertEqual(router.peak_equity(), D("300000.00"))

            # Disconnect Hugo (34.17% of demo funds) with raw 0.00
            emu_hugo.set_connected(False, raw_zero_account=True)
            emu_hugo.publish_market()

            rsnap = router.routing_snapshot()
            self.assertEqual(rsnap["dual_shield"]["allocation"]["drawdown_pct"], "0")
            ok, reason = router.check_open_eligibility("EURUSD")
            self.assertTrue(ok)
            self.assertEqual(reason, f"ELIGIBLE:{BROKER_LHFX_MT5}")

    def test_real_ten_percent_drawdown_still_trips_when_all_online_and_while_broker_offline(self) -> None:
        # Subcase A: All 3 brokers connected; real >= 10% loss trips MAX_DRAWDOWN_EXCEEDED
        with tempfile.TemporaryDirectory() as td_a:
            rig_a = _build_three_broker_rig(Path(td_a))
            router_a: DualShieldBrokerRouter = rig_a["router"]  # type: ignore[assignment]
            oanda_http_a: _FakeOandaTransport = rig_a["oanda_http"]  # type: ignore[assignment]
            oanda_venue_a: OandaPracticeFallbackVenue = rig_a["oanda_venue"]  # type: ignore[assignment]

            router_a.equities()
            self.assertEqual(router_a.peak_equity(), D("300000.00"))

            oanda_http_a.set_nav(D("209000.00"))  # $269k / $300k -> 10.33% drawdown
            oanda_venue_a.probe_account_summary(now=T0 + timedelta(seconds=2))
            ok_a, reason_a = router_a.check_open_eligibility("EURUSD")
            self.assertFalse(ok_a)
            self.assertEqual(reason_a, "DRAWDOWN_BLOCKED:MAX_DRAWDOWN_EXCEEDED")

            ord_a = _make_open_order("real-dd-all-online", units=D("10000"))
            with self.assertRaises(BarbellPolicyRefusalError) as ctx_a:
                router_a.execute_open(ord_a, valve_decision=_admit_order(ord_a))
            self.assertEqual(ctx_a.exception.reason, "MAX_DRAWDOWN_EXCEEDED")

        # Subcase B: Hugo is offline, and remaining online brokers drop >= 10% ($264k -> $237k = 10.23%)
        with tempfile.TemporaryDirectory() as td_b:
            rig_b = _build_three_broker_rig(Path(td_b))
            emu_hugo_b: SimMt5SpoolEa = rig_b["emu_hugo"]  # type: ignore[assignment]
            router_b: DualShieldBrokerRouter = rig_b["router"]  # type: ignore[assignment]
            oanda_http_b: _FakeOandaTransport = rig_b["oanda_http"]  # type: ignore[assignment]
            oanda_venue_b: OandaPracticeFallbackVenue = rig_b["oanda_venue"]  # type: ignore[assignment]

            router_b.equities()
            emu_hugo_b.set_connected(False, raw_zero_account=True)
            emu_hugo_b.publish_market()
            self.assertTrue(router_b.check_open_eligibility("EURUSD")[0])

            # Note: $27,000 drop on OANDA would only be 9.00% of $300k (below 10%),
            # yet it IS 10.23% of the $264k online cohort -> MUST trip MAX_DRAWDOWN_EXCEEDED!
            oanda_http_b.set_nav(D("213000.00"))
            oanda_venue_b.probe_account_summary(now=T0 + timedelta(seconds=3))
            ok_b, reason_b = router_b.check_open_eligibility("EURUSD")
            self.assertFalse(ok_b)
            self.assertEqual(reason_b, "DRAWDOWN_BLOCKED:MAX_DRAWDOWN_EXCEEDED")

            ord_b = _make_open_order("real-dd-while-hugo-offline", units=D("10000"))
            with self.assertRaises(BarbellPolicyRefusalError) as ctx_b:
                router_b.execute_open(ord_b, valve_decision=_admit_order(ord_b))
            self.assertEqual(ctx_b.exception.reason, "MAX_DRAWDOWN_EXCEEDED")

    def test_real_zero_connected_equity_is_never_masked_and_trips_ten_percent_drawdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = _build_three_broker_rig(
                Path(td),
                oanda_nav=D("240000.00"),
                hugo_balance=D("36000.00"),
                lhfx_balance=D("24000.00"),
                demo_virtual_sleeve=False,
            )
            emu_hugo: SimMt5SpoolEa = rig["emu_hugo"]  # type: ignore[assignment]
            hugo_venue: Mt5PaperBrokerVenue = rig["hugo_venue"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]

            router.equities()
            self.assertEqual(router.peak_equity(), D("300000.00"))

            # Genuine wipeout to $0.00 while STILL CONNECTED (connected=True)
            emu_hugo.balance = D("0.00")
            emu_hugo.publish_market()

            eq_now = router.equities()
            self.assertFalse(hugo_venue.is_offline)
            self.assertEqual(router.offline_brokers(), [])
            self.assertEqual(eq_now[BROKER_HUGOSWAY_MT5], D("0.00"))
            # $264,000 / $300,000 = 12.00% real drawdown >= 10.00% constitutional ceiling!
            ok, reason = router.check_open_eligibility("EURUSD")
            self.assertFalse(ok)
            self.assertEqual(reason, "DRAWDOWN_BLOCKED:MAX_DRAWDOWN_EXCEEDED")

            ord_wipeout = _make_open_order("real-connected-wipeout", units=D("10000"))
            with self.assertRaises(BarbellPolicyRefusalError) as ctx:
                router.execute_open(ord_wipeout, valve_decision=_admit_order(ord_wipeout))
            self.assertEqual(ctx.exception.reason, "MAX_DRAWDOWN_EXCEEDED")

    def test_cockpit_http_contracts_and_reconnection_recovery_end_to_end(self) -> None:
        br_schema = json.loads((CONTRACTS_DIR / "broker-routing.schema.json").read_text(encoding="utf-8"))
        ai_schema = json.loads((CONTRACTS_DIR / "ai-trader.schema.json").read_text(encoding="utf-8"))
        stream_doc = json.loads((CONTRACTS_DIR / "initial-market-stream.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rig = _build_three_broker_rig(root)
            emu_hugo: SimMt5SpoolEa = rig["emu_hugo"]  # type: ignore[assignment]
            hugo_venue: Mt5PaperBrokerVenue = rig["hugo_venue"]  # type: ignore[assignment]
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]
            quota_store: DailyQuotaGovernanceStore = rig["quota_store"]  # type: ignore[assignment]
            vault: ProfitSweepVault = rig["vault"]  # type: ignore[assignment]
            dial_store: AggressionDialStore = rig["dial_store"]  # type: ignore[assignment]

            # Open 1 live position on Hugo before disconnect to ensure disconnect never records a fake close
            open_ord = _make_open_order("pre-disconnect-pos", units=D("10000"))
            open_res = hugo_venue.execute(open_ord, valve_decision=_admit_order(open_ord))
            self.assertTrue(open_res.accepted)
            pos_tkt = str(open_res.receipt.position_ticket)
            trader._open_position_meta[pos_tkt] = {
                "ticket": pos_tkt,
                "broker_id": BROKER_HUGOSWAY_MT5,
                "symbol": "EURUSD",
                "side": "BUY",
                "volume_lots": "0.10",
                "entry_price": "1.10010",
                "stop_loss": "1.09000",
                "take_profit": "1.12000",
                "profit": "0.00",
                "protection_stage": "INITIAL_SL",
            }

            tiers = ParallelTierEngine(
                db_path=root / "tiers.sqlite3",
                valve_gate=VALVE_GATE,
                aggression_dial=dial_store,
                clock=lambda: T0,
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                broker_router_reader=router.routing_snapshot,
                autonomous_trader=trader,
                profit_vault=vault,
                aggression_dial=dial_store,
                parallel_tiers=tiers,
                market_stream_reader=lambda: stream_doc,
            )
            srv.start()
            try:
                bound_port = int(urllib.parse.urlparse(srv.base_url).port or 0)

                def _get_json(path: str) -> dict[str, object]:
                    conn = http.client.HTTPConnection("127.0.0.1", bound_port, timeout=5.0)
                    try:
                        hdrs = {"Host": srv.expected_host_header, **srv.auth_headers()}
                        conn.request("GET", path, headers=hdrs)
                        resp = conn.getresponse()
                        raw = resp.read()
                        self.assertEqual(resp.status, 200)
                        return json.loads(raw.decode("utf-8"))
                    finally:
                        conn.close()

                def _sqlite_data_version(db_file: Path) -> int:
                    conn = sqlite3.connect(str(db_file))
                    try:
                        row = conn.execute("PRAGMA data_version").fetchone()
                        return int(row[0]) if row else 0
                    finally:
                        conn.close()

                # Phase 1: All 3 online
                br_1 = _get_json("/api/broker-routing")
                ai_1 = _get_json("/api/ai-trader")
                validate_contract_schema(br_1, br_schema)
                validate_contract_schema(ai_1, ai_schema)
                _assert_no_floats_or_sensitive_keys(self, br_1)
                _assert_no_floats_or_sensitive_keys(self, ai_1)
                self.assertEqual(br_1["dual_shield"]["allocation"]["offline_brokers"], [])  # type: ignore[index]
                self.assertIs(br_1["dual_shield"]["allocation"]["equity_incomplete"], False)  # type: ignore[index]
                self.assertEqual(ai_1["deployable_equity_usd"], "299999")
                self.assertIsNone(ai_1["banked_session"]["offline_broker_notice"])  # type: ignore[index]

                # Phase 2: Hugo disconnects -> BROKER_OFFLINE
                emu_hugo.set_connected(False, raw_zero_account=True)
                emu_hugo.publish_market()
                trader.protect_open_positions(quotes=QUOTES_FX, now=T0 + timedelta(seconds=1))
                # Open position on offline Hugo must NOT be closed or recorded as a loss!
                self.assertEqual(quota_store.snapshot(now=T0 + timedelta(seconds=1))["closed_trades"], 0)
                self.assertIn(pos_tkt, trader._open_position_meta)

                v_ver_before = _sqlite_data_version(root / "vault.sqlite3")
                d_ver_before = _sqlite_data_version(root / "dial.sqlite3")
                t_ver_before = _sqlite_data_version(root / "tiers.sqlite3")

                br_2 = _get_json("/api/broker-routing")
                ai_2 = _get_json("/api/ai-trader")
                validate_contract_schema(br_2, br_schema)
                validate_contract_schema(ai_2, ai_schema)
                _assert_no_floats_or_sensitive_keys(self, br_2)
                _assert_no_floats_or_sensitive_keys(self, ai_2)

                # Zero SQLite writes on GET endpoints for vault, dial, and tiers
                self.assertEqual(_sqlite_data_version(root / "vault.sqlite3"), v_ver_before)
                self.assertEqual(_sqlite_data_version(root / "dial.sqlite3"), d_ver_before)
                self.assertEqual(_sqlite_data_version(root / "tiers.sqlite3"), t_ver_before)

                chain_map_2 = {c["broker_id"]: c["status"] for c in br_2["chain"]}  # type: ignore[index]
                self.assertEqual(chain_map_2[BROKER_HUGOSWAY_MT5], STATUS_BROKER_OFFLINE)
                self.assertEqual(chain_map_2[BROKER_LHFX_MT5], "ACTIVE")
                self.assertEqual(chain_map_2[BROKER_OANDA_PRACTICE], "ACTIVE")
                self.assertEqual(
                    br_2["dual_shield"]["allocation"]["offline_brokers"],  # type: ignore[index]
                    [BROKER_HUGOSWAY_MT5],
                )
                self.assertEqual(br_2["dual_shield"]["allocation"]["online_equity"], "264000")  # type: ignore[index]
                self.assertIs(br_2["dual_shield"]["allocation"]["equity_incomplete"], True)  # type: ignore[index]

                self.assertEqual(ai_2["deployable_equity_usd"], "264000")
                bs_2 = ai_2["banked_session"]  # type: ignore[assignment]
                self.assertEqual(bs_2["offline_brokers"], [BROKER_HUGOSWAY_MT5])  # type: ignore[index]
                self.assertEqual(bs_2["online_equity_usd"], "264000")  # type: ignore[index]
                self.assertIs(bs_2["equity_incomplete_brokers_offline"], True)  # type: ignore[index]
                self.assertIn("Hugo's Way", str(bs_2["offline_broker_notice"]))  # type: ignore[index]

                # Phase 3: Hugo reconnects -> restores ACTIVE, 300k deployable equity, and clears notices
                emu_hugo.set_connected(True)
                emu_hugo.publish_market()

                br_3 = _get_json("/api/broker-routing")
                ai_3 = _get_json("/api/ai-trader")
                validate_contract_schema(br_3, br_schema)
                validate_contract_schema(ai_3, ai_schema)
                _assert_no_floats_or_sensitive_keys(self, br_3)
                _assert_no_floats_or_sensitive_keys(self, ai_3)

                chain_map_3 = {c["broker_id"]: c["status"] for c in br_3["chain"]}  # type: ignore[index]
                self.assertEqual(chain_map_3[BROKER_HUGOSWAY_MT5], "ACTIVE")
                self.assertEqual(br_3["dual_shield"]["allocation"]["offline_brokers"], [])  # type: ignore[index]
                self.assertEqual(br_3["dual_shield"]["allocation"]["online_equity"], "299999")  # type: ignore[index]
                self.assertIs(br_3["dual_shield"]["allocation"]["equity_incomplete"], False)  # type: ignore[index]

                self.assertEqual(ai_3["deployable_equity_usd"], "299999")
                bs_3 = ai_3["banked_session"]  # type: ignore[assignment]
                self.assertEqual(bs_3["offline_brokers"], [])  # type: ignore[index]
                self.assertIsNone(bs_3["offline_broker_notice"])  # type: ignore[index]
                self.assertIs(bs_3["equity_incomplete_brokers_offline"], False)  # type: ignore[index]
            finally:
                srv.stop()


    def test_cold_start_oanda_http_520_weekend_maintenance_prevents_fake_deficit_and_false_drawdown(self) -> None:
        br_schema = json.loads((CONTRACTS_DIR / "broker-routing.schema.json").read_text(encoding="utf-8"))
        ai_schema = json.loads((CONTRACTS_DIR / "ai-trader.schema.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pk_store = PeakEquityStore(root / "peak.sqlite3")
            pk_store.observe_equity(
                "dual-shield-barbell",
                current_equity=D("300000.00"),
                opening_balance=D("300000.00"),
                now=T0 - timedelta(hours=6),
            )

            spool_root = root / "spool"
            emu_hugo = SimMt5SpoolEa(
                spool_root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001111,
                quotes=QUOTES_FX,
                balance=D("89695.34"),
                connected=True,
                clock=lambda: T0,
            )
            emu_lhfx = SimMt5SpoolEa(
                spool_root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8002222,
                quotes=QUOTES_FX,
                balance=D("97478.59"),
                connected=True,
                clock=lambda: T0,
            )
            emu_hugo.publish_market()
            emu_lhfx.publish_market()
            emus = {
                BROKER_HUGOSWAY_MT5: emu_hugo,
                BROKER_LHFX_MT5: emu_lhfx,
            }

            oanda_http = _FakeOandaTransport(
                nav=D("100000.00"),
                quotes=QUOTES_FX,
                fail_http_520=True,
            )
            env = {
                "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-7777777-001",
                "CAS_FOREX_OANDA_PRACTICE_TOKEN": _dummy_cred("oanda"),
                "CAS_FOREX_OANDA_ACCOUNT_ID": "101-001-7777777-001",
                "CAS_FOREX_OANDA_API_TOKEN": _dummy_cred("oanda"),
                "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001111",
                "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": _dummy_cred("hugo"),
                "CAS_FOREX_HUGOSWAY_MT5_SERVER": "Hugosway-Demo",
                "CAS_FOREX_LHFX_MT5_LOGIN": "8002222",
                "CAS_FOREX_LHFX_MT5_PASSWORD": _dummy_cred("lhfx"),
                "CAS_FOREX_LHFX_MT5_SERVER": "LHFXSA-Trade",
                "CAS_FOREX_MT5_SPOOL_DIR": str(spool_root),
                "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
            }
            mt5_journal = Mt5MutationJournal(root / "mt5_mutations.sqlite3")
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=VALVE_GATE,
                oracle=OandaQuoteTruthOracle.from_static_quotes(QUOTES_FX, reference_name="OANDA_PRACTICE_ORACLE"),
                barbell=BarbellCapitalPolicy(demo_virtual_sleeve=True),
                peak_equity_store=pk_store,
                mt5_mutation_journal=mt5_journal,
                transport_factory=lambda bid, _mode, sp_dir: Mt5SpoolBridgeTransport(
                    Path(str(sp_dir)) / bid.lower(),
                    sleep=emus[bid].sleep_hook,
                    poll_interval_seconds=0.005,
                    receipt_timeout_seconds=1.0,
                    clock=lambda: T0,
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient(
                    environ=e,
                    transport=oanda_http,
                    clock=lambda: T0,
                ),
                clock=lambda: T0,
            )
            statuses = router.activate_all()
            self.assertEqual(statuses[BROKER_HUGOSWAY_MT5], "ACTIVE")
            self.assertEqual(statuses[BROKER_LHFX_MT5], "ACTIVE")
            self.assertEqual(statuses[BROKER_OANDA_PRACTICE], "FAILED")
            self.assertTrue(router.is_broker_offline(BROKER_OANDA_PRACTICE))
            self.assertEqual(router.offline_brokers(), [BROKER_OANDA_PRACTICE])
            self.assertEqual(
                router.online_equities(),
                {
                    BROKER_HUGOSWAY_MT5: D("89695.34"),
                    BROKER_LHFX_MT5: D("97478.59"),
                },
            )
            self.assertEqual(router.online_total_equity(), D("187173.93"))
            self.assertEqual(router.peak_equity(), D("300000.00"))

            # PR #25 Finding [3] invariant: require_fresh_oanda=True still fails closed!
            with self.assertRaises(Mt5TransportError):
                router.equities(require_fresh_oanda=True)

            rsnap = router.routing_snapshot()
            validate_contract_schema(rsnap, br_schema)
            _assert_no_floats_or_sensitive_keys(self, rsnap)
            chain_map = {c["broker_id"]: c["status"] for c in rsnap["chain"]}
            self.assertEqual(chain_map[BROKER_OANDA_PRACTICE], "FAILED")
            self.assertEqual(rsnap["dual_shield"]["allocation"]["offline_brokers"], [BROKER_OANDA_PRACTICE])
            self.assertEqual(rsnap["dual_shield"]["allocation"]["online_equity"], "187173.93")
            self.assertIs(rsnap["dual_shield"]["allocation"]["equity_incomplete"], True)
            self.assertEqual(rsnap["dual_shield"]["allocation"]["drawdown_pct"], "0")

            comp_ctrl = CompoundingAndMilestoneController(
                root / "compounding.sqlite3",
                starting_principal_usd=D("300000.00"),
            )
            trader = AutonomousAiTrader(
                router=router,
                valve_gate=VALVE_GATE,
                model_registry=FrontierModelRegistry(
                    environ={},
                    resolve_dns=lambda _h: ("127.0.0.1",),
                    clock=lambda: T0,
                ),
                execution_gate=lambda _inv: None,
                quota_store=DailyQuotaGovernanceStore(root / "quota.sqlite3"),
                profit_vault=ProfitSweepVault(root / "vault.sqlite3", initial_capital_usd=D("300000.00")),
                aggression_dial=AggressionDialStore(root / "dial.sqlite3"),
                compounding_controller=comp_ctrl,
                initial_capital_usd=D("300000.00"),
                journal_path=root / "ai_cycles.sqlite3",
                clock=lambda: T0,
            )
            tsnap = trader.status_snapshot(now=T0)
            validate_contract_schema(tsnap, ai_schema)
            _assert_no_floats_or_sensitive_keys(self, tsnap)
            self.assertEqual(tsnap["deployable_equity_usd"], "187173.93")
            bs = tsnap["banked_session"]
            self.assertEqual(bs["offline_brokers"], [BROKER_OANDA_PRACTICE])
            self.assertEqual(bs["online_equity_usd"], "187173.93")
            self.assertIs(bs["equity_incomplete_brokers_offline"], True)
            self.assertEqual(bs["capital_status"], CAPITAL_STATUS_AT_PRINCIPAL)
            self.assertEqual(bs["deficit_to_principal_usd"], "0")
            notice_txt = str(bs["offline_broker_notice"])
            self.assertIn("OANDA is temporarily offline", notice_txt)
            self.assertIn("not a trading loss", notice_txt)

            csnap = trader.compounding_snapshot(now=T0)
            self.assertIsNotNone(csnap)
            self.assertEqual(csnap["current_equity_usd"], "300000.00")  # type: ignore[index]
            self.assertIs(csnap["underwater"], False)  # type: ignore[index]

            # Real >=10% online cohort drawdown STILL trips while OANDA is cold-start offline
            emu_lhfx.balance = D("77478.59")
            emu_lhfx.publish_market()
            eff_curr, eff_pk, eff_dd = router.effective_drawdown_state()
            self.assertGreater(eff_dd, D("0.10"))
            with self.assertRaises(BarbellPolicyRefusalError) as ctx_dd:
                router.barbell.require_drawdown(current_equity=eff_curr, peak_equity=eff_pk)
            self.assertEqual(ctx_dd.exception.reason, "MAX_DRAWDOWN_EXCEEDED")
            tsnap_loss = trader.status_snapshot(now=T0 + timedelta(seconds=5))
            self.assertEqual(tsnap_loss["banked_session"]["capital_status"], CAPITAL_STATUS_RECOVERY_MODE)
            self.assertEqual(tsnap_loss["banked_session"]["deficit_to_principal_usd"], "20000")

    def test_mid_session_oanda_drop_preserves_continuity_excludes_online_and_keeps_finding3_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rig = _build_three_broker_rig(
                root,
                oanda_nav=D("100000.00"),
                hugo_balance=D("89695.34"),
                lhfx_balance=D("97478.59"),
                demo_virtual_sleeve=True,
                initial_capital_usd=D("287173.93"),
            )
            router: DualShieldBrokerRouter = rig["router"]  # type: ignore[assignment]
            trader: AutonomousAiTrader = rig["trader"]  # type: ignore[assignment]
            oanda_http: _FakeOandaTransport = rig["oanda_http"]  # type: ignore[assignment]
            oanda_venue: OandaPracticeFallbackVenue = rig["oanda_venue"]  # type: ignore[assignment]

            self.assertEqual(router.offline_brokers(), [])
            self.assertEqual(router.online_total_equity(), D("287173.93"))

            # Mid-session OANDA HTTP 520 failure: new-risk refresh MUST fail closed (Finding [3])
            oanda_http.set_fail_http_520(True)
            ord_new = _make_open_order("oanda-mid-drop", units=D("10000"))
            with self.assertRaises(Mt5TransportError):
                router.execute_open(ord_new, valve_decision=_admit_order(ord_new))
            with self.assertRaises(Mt5TransportError):
                router.equities(require_fresh_oanda=True)

            # Read/snapshot path preserves $100,000 continuity in equities() while excluding OANDA from online_equities()
            self.assertTrue(router.is_broker_offline(BROKER_OANDA_PRACTICE))
            self.assertEqual(router.offline_brokers(), [BROKER_OANDA_PRACTICE])
            eq_map = router.equities()
            self.assertEqual(eq_map[BROKER_OANDA_PRACTICE], D("100000.00"))
            self.assertEqual(router.barbell.total_equity(eq_map), D("287173.93"))
            self.assertEqual(
                router.online_equities(),
                {
                    BROKER_HUGOSWAY_MT5: D("89695.34"),
                    BROKER_LHFX_MT5: D("97478.59"),
                },
            )
            self.assertEqual(router.online_total_equity(), D("187173.93"))

            snap_drop = trader.status_snapshot(now=T0)
            self.assertEqual(snap_drop["deployable_equity_usd"], "187173.93")
            bs_drop = snap_drop["banked_session"]
            self.assertEqual(bs_drop["current_total_equity_usd"], "287173.93")
            self.assertEqual(bs_drop["capital_status"], CAPITAL_STATUS_AT_PRINCIPAL)
            self.assertEqual(bs_drop["deficit_to_principal_usd"], "0")
            self.assertEqual(bs_drop["offline_brokers"], [BROKER_OANDA_PRACTICE])
            self.assertEqual(bs_drop["online_equity_usd"], "187173.93")
            self.assertIs(bs_drop["equity_incomplete_brokers_offline"], True)
            self.assertIn("OANDA is temporarily offline", str(bs_drop["offline_broker_notice"]))
            self.assertEqual(friendly_broker_label(BROKER_OANDA_LIVE), "OANDA")
            live_notice = str(trader._build_offline_broker_notice([BROKER_OANDA_LIVE], D("187173.93")))
            self.assertIn("OANDA is temporarily offline", live_notice)

            # Recovery: OANDA returns 200 OK -> offline_brokers clears and online_total_equity restores $287,173.93
            oanda_http.set_fail_http_520(False)
            oanda_venue.probe_account_summary(now=T0 + timedelta(seconds=5))
            self.assertFalse(router.is_broker_offline(BROKER_OANDA_PRACTICE))
            self.assertEqual(router.offline_brokers(), [])
            self.assertEqual(router.online_total_equity(), D("287173.93"))
            fresh_eq = router.equities(require_fresh_oanda=True)
            self.assertEqual(fresh_eq[BROKER_OANDA_PRACTICE], D("100000.00"))


if __name__ == "__main__":
    unittest.main()
