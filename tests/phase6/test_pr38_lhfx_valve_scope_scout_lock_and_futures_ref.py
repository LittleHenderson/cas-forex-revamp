"""PR #38 tests: online drawdown scope for ForexMetaValveGate, lock-free Fast Scout, and 23/5 futures index reference priority."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.operator.frontier_backends import (
    FrontierModelRegistry,
    FrontierTransportError,
)
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    ValveRefusalError,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.live_market_stream import PublicUsIndexFeedClient
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    TRANSPORT_SPOOL_BRIDGE,
)

D = Decimal
T0 = datetime(2026, 11, 23, 7, 15, 0, tzinfo=timezone.utc)


def _fixture_str(slot: str) -> str:
    return f"pr38-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-3800001-001", equity: str = "100000.00") -> None:
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


class Pr38LhfxValveScopeScoutLockAndFuturesRefTests(unittest.TestCase):
    def test_online_drawdown_scope_allows_lhfx_open_while_hugosway_offline_and_still_blocks_real_10pct_loss(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes={"NAS100": (D("25849.00"), D("25851.50"))},
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
                    "NAS100": (D("25849.00"), D("25851.50")),
                    "US30": (D("48895.00"), D("48899.00")),
                    "SPX500": (D("7079.50"), D("7080.25")),
                    "XAUUSD": (D("3623.00"), D("3623.50")),
                },
                balance=D("97478.59"),
                clock=clock,
            )
            emu_l.publish_market()

            peak_store = PeakEquityStore(root / "peak.sqlite3")
            # Seed the historical 3-broker high-water mark ($305,004.91) AND 2-broker online mark ($197,478.59)
            peak_store.observe_equity(
                "dual-shield-barbell",
                current_equity=D("305004.91"),
                opening_balance=D("305004.91"),
                now=clock(),
            )
            peak_store.observe_equity(
                "dual-shield-barbell:auto-ai-session",
                current_equity=D("304836.21"),
                opening_balance=D("304836.21"),
                now=clock(),
            )
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
                "CAS_FOREX_ANTHROPIC_API_KEY": _fixture_str("claude"),
                "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}

            def idx_ref(syms: tuple[str, ...]) -> dict[str, dict[str, object]]:
                q_map = {
                    "NAS100": (emu_l.quotes["NAS100"][0], emu_l.quotes["NAS100"][1]),
                    "US30": (emu_l.quotes["US30"][0], emu_l.quotes["US30"][1]),
                    "SPX500": (emu_l.quotes["SPX500"][0], emu_l.quotes["SPX500"][1]),
                    "XAUUSD": (emu_l.quotes["XAUUSD"][0], emu_l.quotes["XAUUSD"][1]),
                }
                return {
                    s: {
                        "bid": q_map[s][0],
                        "ask": q_map[s][1],
                        "source_provider": "PUBLIC_US_INDEX_FEED",
                        "source_broker_id": None,
                        "is_independent_public": True,
                        "observed_at": clock().isoformat().replace("+00:00", "Z"),
                    }
                    for s in syms
                    if s in q_map
                }

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

            def open_choice_http(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
                body_doc = json.loads(body.decode("utf-8"))
                user_doc = json.loads(body_doc["messages"][0]["content"])
                ref = user_doc["options"][0]["action_ref"]
                sel = {
                    "request_id": user_doc["request_id"],
                    "opportunity_set_id": user_doc["opportunity_set_id"],
                    "source_state_id": user_doc["state"]["state_id"],
                    "selected_action_ref": ref,
                    "reason": f"ID=0{ref} NAS100 momentum verified on LHFX",
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
                self.assertEqual(
                    router.effective_drawdown_scope_id(),
                    "dual-shield-barbell:g0:online:LHFX_MT5+OANDA_PRACTICE",
                )
                # 3 ascending NAS100 ticks -> ForexMetaValveGate uses online scope ($197,478.59 == 0% DD), LHFX_MT5 opens!
                out = {}
                for delta in (D("0.00"), D("6.00"), D("14.00")):
                    b = D("25849.00") + delta
                    a = b + D("2.50")
                    emu_l.set_quote("NAS100", b, a)
                    emu_l.publish_market()
                    out = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")

                self.assertEqual(out["action"], "OPEN_BUY")
                self.assertEqual(out["symbol"], "NAS100")
                self.assertEqual(len(router.venues[BROKER_LHFX_MT5].positions), 1)

                # Real >= 10% loss on online LHFX_MT5 ($97,478.59 -> $77,478.59 => $177,478.59 vs $197,478.59 = 10.13% DD)
                # MUST still block both pre-inference eligibility AND ForexMetaValveGate HARD_FLOOR_VETO!
                emu_l._positions.clear()
                emu_l.balance = D("77478.59")
                emu_l.publish_market()
                clock.advance(2)
                blocked = trader.run_fast_tick_cycle(
                    mt5_quotes={"NAS100": (D("25869.00"), D("25871.50"))},
                    feed_source="MT5_DIRECT_SPOOL_50MS",
                )
                self.assertEqual(blocked["action"], "WAIT")
                self.assertIn("MAX_DRAWDOWN_EXCEEDED", str(blocked["reason"]))

                # Also verify direct ForexMetaValveGate call against the online scope raises MAX_DRAWDOWN_EXCEEDED
                from cas_forex_revamp.contracts import ActionIntent, ActionKind, DecisionOrigin, Side
                st_ref_dd = trader._build_state_ref(clock())
                bad_intent = ActionIntent(
                    intent_id="intent-pr38-dd-check",
                    scope=trader._scope,
                    decision_id="dec-pr38-dd-check",
                    opportunity_id="opp-pr38-dd-check",
                    action_ref="act-pr38-dd-check",
                    source_state=st_ref_dd,
                    kind=ActionKind.OPEN,
                    instrument_id="NAS100",
                    origin=DecisionOrigin.ACTUAL_MODEL,
                    created_at=clock(),
                    expires_at=st_ref_dd.valid_until,
                    quantity=D("1"),
                    side=Side.BUY,
                    stop_price=D("25850.00"),
                    take_profit_price=D("25920.00"),
                )
                with self.assertRaises(ValveRefusalError) as ctx:
                    trader._make_valve_request_and_clear(
                        intent=bad_intent,
                        strategy_id="pr38-dd-test",
                        timeframe="50ms",
                        label="Test real 10% DD",
                        reason="Verify MAX_DRAWDOWN_EXCEEDED fires on online scope",
                        bid=D("25869.00"),
                        ask=D("25871.50"),
                        total_eq=D("177478.59"),
                        peak_eq=D("197478.59"),
                        scope_id="dual-shield-barbell:g0:online:LHFX_MT5+OANDA_PRACTICE",
                        now=clock(),
                    )
                self.assertIn("MAX_DRAWDOWN_EXCEEDED", str(ctx.exception))

                # When Hugo's Way reconnects cleanly, effective_drawdown_scope_id returns the full dual-shield-barbell scope
                emu_h.connected = True
                emu_h.balance = D("89695.34")
                emu_h.publish_market()
                router.venues[BROKER_HUGOSWAY_MT5].probe()
                self.assertEqual(router.effective_drawdown_scope_id(), "dual-shield-barbell")
            finally:
                self.assertTrue(trader.close())
            _assert_no_eventbus_threads_alive(self)

    def test_fast_scout_releases_trader_lock_so_metrics_and_dial_stay_unblocked(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes={"NAS100": (D("25849.00"), D("25851.50"))},
                balance=D("0.00"),
                connected=False,
                clock=clock,
            )
            emu_h.publish_market()
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=122590,
                quotes={"NAS100": (D("25849.00"), D("25851.50"))},
                balance=D("97478.59"),
                clock=clock,
            )
            emu_l.publish_market()

            gate = load_default_forex_valve_gate()
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
                "CAS_FOREX_ANTHROPIC_API_KEY": _fixture_str("claude"),
                "CAS_FOREX_GEMINI_API_KEY": _fixture_str("gemini"),
                "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                peak_equity_store=gate.peak_equity_store,
                transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                    Path(r) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda, clock=clock),
                clock=clock,
            )
            router.activate_all()
            reg = FrontierModelRegistry(environ=env, clock=clock, resolve_dns=lambda _h: None)
            reg.set_fast_scout_enabled(True)
            quota = DailyQuotaGovernanceStore(root / "quota.sqlite3")
            exec_gate = DurableModelExecutionGate(db_path=root / "model_gate.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=quota,
                peak_equity_store=gate.peak_equity_store,
                execution_gate=exec_gate,
                state_dir=root / "trader_state",
                fast_tick_ms=50,
                clock=clock,
            )
            try:
                # Prime 2 ticks before the 3rd ascending tick triggers scout_opportunities
                for delta in (D("0.00"), D("6.00")):
                    b = D("25849.00") + delta
                    a = b + D("2.50")
                    emu_l.set_quote("NAS100", b, a)
                    emu_l.publish_market()
                    trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")

                scout_entered = threading.Event()
                allow_scout_finish = threading.Event()
                read_timings: dict[str, float] = {}
                read_errors: list[BaseException] = []
                cycle_out: dict[str, object] = {}

                def slow_scout(*_args: object, **_kwargs: object) -> dict[str, object]:
                    scout_entered.set()
                    if not allow_scout_finish.wait(timeout=5.0):
                        raise TimeoutError("allow_scout_finish timed out")
                    return {
                        "executed": True,
                        "reason": "HOLD_WAIT",
                        "wake_heavy_model": False,
                        "best_market": "NAS100",
                        "best_probability": "0.40",
                        "decisions": [],
                    }

                def run_slow_cycle() -> None:
                    b3, a3 = D("25863.00"), D("25865.50")
                    emu_l.set_quote("NAS100", b3, a3)
                    emu_l.publish_market()
                    res = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b3, a3)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                    cycle_out.update(res)

                with mock.patch.object(reg, "scout_opportunities", side_effect=slow_scout):
                    t = threading.Thread(target=run_slow_cycle, daemon=True)
                    t.start()
                    self.assertTrue(scout_entered.wait(timeout=3.0))
                    try:
                        for name, fn in (
                            ("metrics_summary", trader.metrics_summary),
                            ("dial_context_summary", trader.dial_context_summary),
                            ("compounding_eq", trader._live_economic_equity_for_compounding),
                        ):
                            t0 = time.perf_counter()
                            fn()
                            read_timings[name] = time.perf_counter() - t0
                    except BaseException as exc:
                        read_errors.append(exc)
                    finally:
                        allow_scout_finish.set()
                        t.join(timeout=3.0)

                self.assertEqual(read_errors, [])
                for name, dt in read_timings.items():
                    self.assertLess(dt, 0.5, f"{name} blocked while scout ran: {dt:.3f}s")
                self.assertEqual(cycle_out.get("action"), "WAIT")
                self.assertEqual(cycle_out.get("reason"), "Gemini Decision 1 Fast Scout held WAIT on NAS100")

                # Verify FrontierTransportError inside off-lock scout records SCOUT_DEGRADED and wakes heavy model
                with (
                    mock.patch.object(reg, "scout_opportunities", side_effect=FrontierTransportError("timeout")),
                    mock.patch.object(reg, "record_call", wraps=reg.record_call) as w_rec,
                    mock.patch.object(
                        trader,
                        "_observe_markets_readonly",
                        wraps=trader._observe_markets_readonly,
                    ),
                ):
                    b4, a4 = D("25870.00"), D("25872.50")
                    emu_l.set_quote("NAS100", b4, a4)
                    emu_l.publish_market()
                    with mock.patch(
                        "cas_forex_revamp.composition.autonomous_trader.ActualModelDecisionAdapter.decide",
                        side_effect=FrontierTransportError("stop-here-after-degraded-scout"),
                    ):
                        with self.assertRaises(FrontierTransportError):
                            trader.run_fast_tick_cycle(
                                mt5_quotes={"NAS100": (b4, a4)},
                                feed_source="MT5_DIRECT_SPOOL_50MS",
                            )
                    degraded_calls = [c for c in w_rec.call_args_list if c.kwargs.get("status") == "SCOUT_DEGRADED"]
                    self.assertGreaterEqual(len(degraded_calls), 1)
            finally:
                self.assertTrue(trader.close())
            _assert_no_eventbus_threads_alive(self)

    def test_public_index_feed_prefers_23x5_futures_before_cash_indices(self) -> None:
        attempted_urls: list[str] = []

        def fake_get(url: str, _timeout: float, _max_bytes: int) -> bytes:
            attempted_urls.append(url)
            price = 25849.0 if "NQ=F" in url or "NDX" in url else (
                48895.0 if "YM=F" in url or "DJI" in url else (
                    7079.75 if "ES=F" in url or "GSPC" in url else 3623.5
                )
            )
            return json.dumps({
                "chart": {
                    "result": [{
                        "meta": {"regularMarketPrice": price},
                        "timestamp": [int(T0.timestamp()) - 60, int(T0.timestamp())],
                        "indicators": {"quote": [{"open": [price, price], "high": [price, price],
                                                  "low": [price, price], "close": [price, price], "volume": [10, 12]}]},
                    }]
                }
            }).encode("utf-8")

        client = PublicUsIndexFeedClient(transport=fake_get, clock=lambda: T0)
        doc = client.fetch_index_stream(sequence=1)
        self.assertEqual([m["pair"] for m in doc["markets"]], ["NAS100", "US30", "SPX500", "XAUUSD"])
        self.assertEqual(len(attempted_urls), 4)
        self.assertIn("/v8/finance/chart/NQ=F", attempted_urls[0])
        self.assertIn("/v8/finance/chart/YM=F", attempted_urls[1])
        self.assertIn("/v8/finance/chart/ES=F", attempted_urls[2])
        self.assertIn("/v8/finance/chart/GC=F", attempted_urls[3])

        # Cash-index paths still act as fallback if futures paths fail
        fallback_urls: list[str] = []

        def fallback_get(url: str, timeout: float, max_bytes: int) -> bytes:
            fallback_urls.append(url)
            if any(f in url for f in ("NQ=F", "YM=F", "ES=F")):
                raise RuntimeError("simulated futures endpoint error")
            return fake_get(url, timeout, max_bytes)

        client_fb = PublicUsIndexFeedClient(transport=fallback_get, clock=lambda: T0)
        doc_fb = client_fb.fetch_index_stream(sequence=2)
        self.assertEqual([m["pair"] for m in doc_fb["markets"]], ["NAS100", "US30", "SPX500", "XAUUSD"])
        self.assertTrue(any("%5ENDX" in u for u in fallback_urls))
        self.assertTrue(any("%5EDJI" in u for u in fallback_urls))
        self.assertTrue(any("%5EGSPC" in u for u in fallback_urls))


if __name__ == "__main__":
    unittest.main()
