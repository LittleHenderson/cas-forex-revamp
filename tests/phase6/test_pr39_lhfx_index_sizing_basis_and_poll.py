"""PR #39 tests: MT5 index entry stop-risk, 150 bps public futures basis tolerance, and independent index poll."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import threading
import unittest

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import _poll_index_and_fx_once
from types import SimpleNamespace

from cas_forex_revamp.contracts import (
    ActionKind,
    ContractError,
    Side,
)
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
)
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BrokerFailoverExhaustedError,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
    TRANSPORT_SPOOL_BRIDGE,
)

D = Decimal
T0 = datetime(2026, 11, 23, 9, 25, 0, tzinfo=timezone.utc)


def _fixture_str(slot: str) -> str:
    return f"pr39-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-3900001-001", equity: str = "100000.00") -> None:
        self.account_id = account_id
        self.equity = equity

    def __call__(self, method: str, url: str, *_args: object) -> bytes:
        if method.upper() == "GET" and url.endswith("/summary"):
            return json.dumps({
                "lastTransactionID": "100",
                "account": {
                    "id": self.account_id,
                    "currency": "USD",
                    "balance": self.equity,
                    "NAV": self.equity,
                    "unrealizedPL": "0.00",
                    "marginAvailable": self.equity,
                    "openPositionCount": 0,
                    "lastTransactionID": "100",
                },
            }).encode("utf-8")
        if method.upper() == "GET" and "/pricing" in url:
            return json.dumps({
                "time": T0.isoformat().replace("+00:00", "Z"),
                "prices": [{
                    "instrument": "EUR_USD",
                    "time": T0.isoformat().replace("+00:00", "Z"),
                    "bids": [{"price": "1.10000", "liquidity": 1000000}],
                    "asks": [{"price": "1.10010", "liquidity": 1000000}],
                    "tradeable": True,
                }],
            }).encode("utf-8")
        return json.dumps({"lastTransactionID": "100", "trades": []}).encode("utf-8")


def _assert_no_eventbus_threads_alive(test: unittest.TestCase) -> None:
    alive = [t for t in threading.enumerate() if t.name.startswith("cas-eventbus-") and t.is_alive()]
    test.assertEqual(alive, [])


def _clear_valve(
    gate,
    order: OrderIntent,
    *,
    now: datetime,
    bid: str = "25950.86",
    ask: str = "25952.10",
    target_id: str | None = None,
):
    inv: list[dict[str, object]] = []
    if target_id is not None:
        inv.append({
            "ticket": target_id,
            "symbol": order.symbol,
            "side": "BUY",
            "stop_loss": "25925.86",
        })
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units if order.quantity_units is not None else D("32"),
        side=order.side if order.side is not None else Side.BUY,
        stop_price=order.stop_price,
        limit_price=order.limit_price,
        take_profit_price=order.take_profit_price,
        target_id=target_id,
    )
    req = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=now, valid_until=now + timedelta(minutes=5)),
    )
    sel = SimpleNamespace(
        evidence_ids=("ev-1",),
        reason=f"ID=0{order.action_ref} verified setup",
        selected_action_ref=order.action_ref,
    )
    prop = SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)
    view = {
        "scope_id": "dual-shield-barbell:g0:online:LHFX_MT5+OANDA_PRACTICE",
        "balance": "197478.59",
        "equity": "197478.59",
        "peak_equity": "197478.59",
        "available_margin": "190000",
        "position_inventory": inv,
        "bid": bid,
        "ask": ask,
        "policy": {
            "new_risk_permission": "ALLOWED",
            "management_permission": "ALLOWED",
            "max_entry_quantity": "500000",
        },
    }
    return gate.require_admissible(prop, current_view=view, now=now)


class Pr39LhfxIndexSizingBasisAndPollTests(unittest.TestCase):
    def _build_router(
        self,
        root: Path,
        clock: _MutableClock,
        *,
        pub_bid: D = D("26082.50"),
        pub_ask: D = D("26085.00"),
        is_independent_public: bool = True,
        source_provider: str = "PUBLIC_US_INDEX_FEED",
        source_broker_id: str | None = None,
    ):
        emu_h = Mt5SpoolPaperTerminalEmulator(
            root / "hugosway_mt5",
            server="Hugosway-Demo",
            login=1002903,
            quotes={"NAS100": (D("25950.86"), D("25952.10"))},
            balance=D("0.00"),
            connected=False,
            clock=clock,
        )
        emu_h.publish_market()
        emu_l = Mt5SpoolPaperTerminalEmulator(
            root / "lhfx_mt5",
            server="LHFXSA-Trade",
            login=122590,
            quotes={
                "NAS100": (D("25950.86"), D("25952.10")),
                "US30": (D("49063.00"), D("49066.00")),
                "SPX500": (D("7108.30"), D("7108.90")),
                "XAUUSD": (D("3619.04"), D("3619.43")),
            },
            balance=D("97478.59"),
            clock=clock,
        )
        emu_l.publish_market()
        peak_store = PeakEquityStore(root / "peak.sqlite3")
        peak_store.observe_equity(
            "dual-shield-barbell:g0:online:LHFX_MT5+OANDA_PRACTICE",
            current_equity=D("197478.59"),
            opening_balance=D("197478.59"),
            now=clock(),
        )
        gate = load_default_forex_valve_gate(peak_equity_store=peak_store)
        oanda = _StubOandaTransport()
        env = {
            ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
            ENV_MT5_SPOOL_DIR: str(root),
            ENV_HUGOSWAY_MT5_LOGIN: "1002903",
            ENV_HUGOSWAY_MT5_PASSWORD: _fixture_str("hugo"),
            ENV_HUGOSWAY_MT5_SERVER: "Hugosway-Demo",
            ENV_LHFX_MT5_LOGIN: "122590",
            ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
            ENV_OANDA_PRACTICE_TOKEN: _fixture_str("oanda"),
            ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
            "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
            "CAS_FOREX_INDEX_CONTRACT_SIZE": "100",
            "CAS_FOREX_INDEX_LEVERAGE": "200",
        }
        ref_state = {
            "bid": pub_bid,
            "ask": pub_ask,
            "is_independent_public": is_independent_public,
            "source_provider": source_provider,
            "source_broker_id": source_broker_id,
        }

        def idx_ref(syms: tuple[str, ...]) -> dict[str, dict[str, object]]:
            return {
                s: {
                    "bid": ref_state["bid"],
                    "ask": ref_state["ask"],
                    "source_provider": ref_state["source_provider"],
                    "source_broker_id": ref_state["source_broker_id"],
                    "is_independent_public": ref_state["is_independent_public"],
                    "observed_at": clock().isoformat().replace("+00:00", "Z"),
                }
                for s in syms
                if s == "NAS100"
            }

        emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}
        router = DualShieldBrokerRouter(
            environ=env,
            valve_gate=gate,
            peak_equity_store=peak_store,
            index_reference_source=idx_ref,
            transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                Path(r) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
            ),
            oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda, clock=clock),
            clock=clock,
        )
        router.activate_all()
        return router, gate, emu_h, emu_l, peak_store, ref_state, env, oanda

    def test_lhfx_nas100_open_and_amend_pass_under_public_futures_basis_while_enforcing_caps(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            router, gate, _emu_h, _emu_l, _pk, ref_state, _env, _oa = self._build_router(Path(td), clock)

            # 1. Valid 32-unit BUY (0.32 lots): LHFX ask=25952.10, limit=25958.35, sl=25925.86
            #    Actual risk = 32 * (25958.35 - 25925.86) = $1,039.68 <= $1,250.00 cap
            #    Even though PUBLIC_US_INDEX_FEED (NQ=F futures) is +50.7 bps higher (26082.50 / 26085.00).
            buy_order = OrderIntent(
                order_id="ord-pr39-buy",
                action_ref="act-pr39-buy",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=D("32"),
                side=Side.BUY,
                limit_price=D("25958.35"),
                stop_price=D("25925.86"),
                take_profit_price=D("26012.10"),
            )
            ex_buy = router.execute_open(buy_order, valve_decision=_clear_valve(gate, buy_order, now=clock()))
            self.assertEqual(ex_buy.executed_on, BROKER_LHFX_MT5)
            self.assertEqual(ex_buy.stop_loss_risk, D("1039.68"))
            self.assertEqual(ex_buy.stop_loss_risk_cap, D("1250.00"))
            self.assertTrue(ex_buy.quote_verdicts[-1].passed)
            self.assertEqual(ex_buy.quote_verdicts[-1].max_divergence_bps, D("150"))

            # 2. AMEND_STOP management on filled NAS100 position ALSO succeeds under +50.7 bps futures basis
            ticket = ex_buy.result.receipt.position_ticket
            amend_order = OrderIntent(
                order_id="ord-pr39-amend",
                action_ref="act-pr39-amend",
                kind=ActionKind.AMEND_STOP,
                symbol="NAS100",
                position_ticket=ticket,
                stop_price=D("25940.00"),
                take_profit_price=D("26020.00"),
            )
            ex_amend = router.execute_management(
                BROKER_LHFX_MT5,
                amend_order,
                valve_decision=_clear_valve(gate, amend_order, now=clock(), target_id=ticket),
            )
            self.assertIsNotNone(ex_amend.receipt)
            self.assertTrue(ex_amend.receipt.accepted)

            # 3. Valid 32-unit SELL: LHFX bid=25950.86, limit=25944.61, sl=25977.10 -> risk = $1,039.68 <= $1,250.00
            sell_order = OrderIntent(
                order_id="ord-pr39-sell",
                action_ref="act-pr39-sell",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=D("32"),
                side=Side.SELL,
                limit_price=D("25944.61"),
                stop_price=D("25977.10"),
                take_profit_price=D("25890.86"),
            )
            ex_sell = router.execute_open(sell_order, valve_decision=_clear_valve(gate, sell_order, now=clock()))
            self.assertEqual(ex_sell.executed_on, BROKER_LHFX_MT5)
            self.assertEqual(ex_sell.stop_loss_risk, D("1039.68"))

            # 4. Truly oversized order (45 units -> $1,462.05 > $1,250.00) MUST still be refused
            oversized = OrderIntent(
                order_id="ord-pr39-big",
                action_ref="act-pr39-big",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=D("45"),
                side=Side.BUY,
                limit_price=D("25958.35"),
                stop_price=D("25925.86"),
                take_profit_price=D("26012.10"),
            )
            with self.assertRaises(BarbellPolicyRefusalError) as ctx_big:
                router.execute_open(oversized, valve_decision=_clear_valve(gate, oversized, now=clock()))
            self.assertEqual(ctx_big.exception.reason, "STOP_RISK_EXCEEDS_EQUITY_PCT")

            # 5. Adversarial spoofed low BUY limit_price (25930.00 < ask 25952.10) cannot understate risk
            #    True risk uses ask=25952.10 -> 32 * (25952.10 - 25900.00) = $1,667.20 > $1,250.00 -> refused!
            spoofed = OrderIntent(
                order_id="ord-pr39-spoof",
                action_ref="act-pr39-spoof",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=D("32"),
                side=Side.BUY,
                limit_price=D("25930.00"),
                stop_price=D("25900.00"),
                take_profit_price=D("26010.00"),
            )
            with self.assertRaises(BarbellPolicyRefusalError) as ctx_spoof:
                router.execute_open(spoofed, valve_decision=_clear_valve(gate, spoofed, now=clock()))
            self.assertEqual(ctx_spoof.exception.reason, "STOP_RISK_EXCEEDS_EQUITY_PCT")

            # 6. Genuine >150 bps off-market manipulation (+200 bps) MUST still be rejected by QuoteTruthOracle
            ref_state["bid"] = D("26469.88")
            ref_state["ask"] = D("26471.14")
            off_mkt = OrderIntent(
                order_id="ord-pr39-offmkt",
                action_ref="act-pr39-offmkt",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=D("32"),
                side=Side.BUY,
                limit_price=D("25958.35"),
                stop_price=D("25925.86"),
                take_profit_price=D("26012.10"),
            )
            router._degradations.clear()
            with self.assertRaises(BrokerFailoverExhaustedError):
                router.execute_open(off_mkt, valve_decision=_clear_valve(gate, off_mkt, now=clock()))
            self.assertTrue(
                any(
                    d.get("broker_id") == BROKER_LHFX_MT5
                    and d.get("outcome") == "OFF_MARKET_QUOTE"
                    and d.get("reason") == "MID_DIVERGES_FROM_REGULATED_REFERENCE"
                    for d in router._degradations
                ),
                f"Expected MID_DIVERGES_FROM_REGULATED_REFERENCE in {router._degradations}",
            )

            # 7. Non-public peer reference retains strict 25 bps ceiling (+40 bps MUST fail closed)
            ref_state["bid"] = D("26054.66")
            ref_state["ask"] = D("26055.91")
            ref_state["is_independent_public"] = False
            ref_state["source_provider"] = "CROSS_VENUE_PEER"
            ref_state["source_broker_id"] = BROKER_HUGOSWAY_MT5
            strict_nonpub = OrderIntent(
                order_id="ord-pr39-nonpub",
                action_ref="act-pr39-nonpub",
                kind=ActionKind.OPEN,
                symbol="NAS100",
                quantity_units=D("32"),
                side=Side.BUY,
                limit_price=D("25958.35"),
                stop_price=D("25925.86"),
                take_profit_price=D("26012.10"),
            )
            router._degradations.clear()
            with self.assertRaises(BrokerFailoverExhaustedError):
                router.execute_open(strict_nonpub, valve_decision=_clear_valve(gate, strict_nonpub, now=clock()))
            self.assertTrue(
                any(
                    d.get("broker_id") == BROKER_LHFX_MT5
                    and d.get("outcome") == "OFF_MARKET_QUOTE"
                    and d.get("reason") == "MID_DIVERGES_FROM_REGULATED_REFERENCE"
                    for d in router._degradations
                ),
                f"Expected strict 25 bps refusal in {router._degradations}",
            )

    def test_poll_index_and_fx_once_keeps_public_index_fresh_during_fx_contract_errors(self) -> None:
        stream_lock = threading.Lock()
        latest_stream: list[dict | None] = [None]
        latest_pub_idx: list[dict | None] = [None]
        latest_mt5_idx: list[dict | None] = [None]
        poll_cache: dict[str, dict] = {}
        log_throttle: dict[tuple[str, str, str], tuple[float, int]] = {}
        poll_state: dict[str, object] = {"consecutive_feed_errors": 0, "next_fx_poll_mono": 0.0}

        class _FakeEnv:
            def __init__(self, seq: int) -> None:
                self._seq = seq

            def to_wire_dict(self) -> dict:
                return {"sequence": self._seq, "markets": []}

        class _FakeFeedClient:
            def __init__(self) -> None:
                self.calls = 0

            def fetch_market_stream(self):
                self.calls += 1
                if self.calls <= 2:
                    raise ContractError("USDJPY: spread 332.3110 bps exceeds pair max_spread_bps=300")
                return _FakeEnv(self.calls)

        class _FakeIndexClient:
            def __init__(self) -> None:
                self.calls = 0

            def fetch_index_stream(self) -> dict:
                self.calls += 1
                return {
                    "schema": "cas-forex.index-stream/1",
                    "sequence": self.calls,
                    "observed_at": (T0 + timedelta(seconds=15 * self.calls)).isoformat().replace("+00:00", "Z"),
                    "feed_mode": "PUBLIC_US_INDEX_FEED",
                    "markets": [
                        {
                            "pair": "NAS100",
                            "bid": "26082.50",
                            "ask": "26085.00",
                        }
                    ],
                }

        class _FakeTrader:
            def __init__(self) -> None:
                self.cycles = 0

            def run_cycle(self, env_stream, index_stream=None) -> None:
                self.cycles += 1

        class _FakeRouter:
            venues: dict = {}

        feed_c = _FakeFeedClient()
        idx_c = _FakeIndexClient()
        trader = _FakeTrader()
        notify_count = [0]

        for tick_sec in (15.0, 30.0, 45.0, 60.0, 75.0):
            _poll_index_and_fx_once(
                router=_FakeRouter(),
                feed_client=feed_c,
                index_client=idx_c,
                trader=trader,
                autonomous_ai=True,
                stream_lock=stream_lock,
                latest_stream=latest_stream,
                latest_public_index_stream=latest_pub_idx,
                latest_mt5_index_stream=latest_mt5_idx,
                poll_mt5_cache=poll_cache,
                poll_log_throttle=log_throttle,
                poll_state=poll_state,
                base_wait=15.0,
                now_mono=tick_sec,
                notify_updated=lambda: notify_count.__setitem__(0, notify_count[0] + 1),
            )

        # Public index feed refreshed on ALL 5 ticks (never frozen by USDJPY ContractError or FX backoff!)
        self.assertEqual(idx_c.calls, 5)
        self.assertIsNotNone(latest_pub_idx[0])
        self.assertEqual(latest_pub_idx[0]["sequence"], 5)
        self.assertTrue(latest_pub_idx[0]["is_independent_public"])
        # FX feed obeyed backoff on tick 45.0s, then recovered on ticks 60.0s & 75.0s
        self.assertEqual(feed_c.calls, 4)
        self.assertEqual(trader.cycles, 2)
        self.assertIsNotNone(latest_stream[0])
        self.assertEqual(poll_state["consecutive_feed_errors"], 0)

    def test_autonomous_trader_opens_lhfx_nas100_cleanly_under_futures_basis_with_zero_thread_leaks(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            router, gate, _emu_h, emu_l, peak_store, _ref_state, env, _oa = self._build_router(root, clock)
            env["CAS_FOREX_ANTHROPIC_API_KEY"] = _fixture_str("claude")

            def open_choice_http(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
                body_doc = json.loads(body.decode("utf-8"))
                user_doc = json.loads(body_doc["messages"][0]["content"])
                ref = user_doc["options"][0]["action_ref"]
                sel = {
                    "request_id": user_doc["request_id"],
                    "opportunity_set_id": user_doc["opportunity_set_id"],
                    "source_state_id": user_doc["state"]["state_id"],
                    "selected_action_ref": ref,
                    "reason": f"ID=0{ref} LHFX NAS100 open cleared under futures basis",
                    "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
                }
                return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 45}}).encode("utf-8")

            reg = FrontierModelRegistry(environ=env, clock=clock, http_post=open_choice_http, resolve_dns=lambda _h: None)
            quota = DailyQuotaGovernanceStore(root / "quota.sqlite3")
            exec_gate = DurableModelExecutionGate(db_path=root / "model_gate.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=quota,
                peak_equity_store=peak_store,
                execution_gate=exec_gate,
                state_dir=root / "trader_state",
                fast_tick_ms=50,
                clock=clock,
            )
            try:
                out = {}
                for delta in (D("0.00"), D("6.00"), D("14.00")):
                    b = D("25950.86") + delta
                    a = b + D("1.24")
                    emu_l.set_quote("NAS100", b, a)
                    emu_l.publish_market()
                    out = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")

                self.assertEqual(out["action"], "OPEN_BUY")
                self.assertEqual(out["symbol"], "NAS100")
                self.assertEqual(len(router.venues[BROKER_LHFX_MT5].positions), 1)
                pos = router.venues[BROKER_LHFX_MT5].positions[0]
                self.assertGreater(pos.volume_lots, D("0"))
                self.assertLessEqual(pos.volume_lots, D("0.39"))
            finally:
                self.assertTrue(trader.close())
            _assert_no_eventbus_threads_alive(self)


if __name__ == "__main__":
    unittest.main()
