"""PR #46 comprehensive pure-stdlib regression tests for Update 46 Fixes 1, 2, and 3."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.composition import option_b_paper_runner as ob_mod  # noqa: F401
from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    _default_protection_params,
)
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.trend_regime import (
    REGIME_CHOP_RANGE,
    REGIME_STRONG_TREND,
    REGIME_TREND_IGNITION,
    TrendRegimeDetector,
)
from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.risk.demo_high_growth_profile import DemoHighGrowthProfile
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue import dual_shield_router as router_mod
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
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
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_INDEX_CONTRACT_SIZE,
    ENV_INDEX_LEVERAGE,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    ENV_SPX500_CONTRACT_SIZE,
    MT5_INDEX_CONTRACT_SIZE,
    MT5_SPX500_CONTRACT_SIZE_MULTI,
    Mt5MarginCalculator,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    TRANSPORT_SPOOL_BRIDGE,
)

D = Decimal
T0 = datetime(2026, 11, 24, 14, 0, 0, tzinfo=timezone.utc)


def _fixture_str(slot: str) -> str:
    return f"pr46-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-4600001-001", equity: str = "100000.00") -> None:
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


def _open_first_choice_http(call_counter: list[int]):
    def _post(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
        call_counter[0] += 1
        body_doc = json.loads(body.decode("utf-8"))
        user_doc = json.loads(body_doc["messages"][0]["content"])
        ref = user_doc["options"][0]["action_ref"]
        sel = {
            "request_id": user_doc["request_id"],
            "opportunity_set_id": user_doc["opportunity_set_id"],
            "source_state_id": user_doc["state"]["state_id"],
            "selected_action_ref": ref,
            "reason": f"ID=0{ref} approved pr46",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
        }
        return 200, json.dumps({
            "content": [{"type": "text", "text": json.dumps(sel)}],
            "usage": {"output_tokens": 32},
        }).encode("utf-8")

    return _post


def _build_pr46_harness(
    root: Path,
    *,
    clock: _MutableClock,
    call_counter: list[int],
    lhfx_balance: Decimal = D("75379.44"),
    oanda_equity: str = "100000.00",
    idx_contract_size: str = "10",
    spx_contract_size: str = "100",
    demo_high_growth: DemoHighGrowthProfile | None = None,
    with_option_b: bool = True,
):
    live_prices: dict[str, tuple[Decimal, Decimal]] = {
        "NAS100": (D("26800.00"), D("26802.00")),
        "US30": (D("49000.00"), D("49004.00")),
        "SPX500": (D("7200.00"), D("7200.60")),
        "XAUUSD": (D("3650.00"), D("3650.60")),
    }
    emu_h = Mt5SpoolPaperTerminalEmulator(
        root / "hugosway_mt5",
        server="Hugosway-Demo",
        login=1002903,
        quotes=dict(live_prices),
        balance=D("0.00"),
        connected=False,
        clock=clock,
    )
    emu_h.publish_market()
    emu_l = Mt5SpoolPaperTerminalEmulator(
        root / "lhfx_mt5",
        server="LHFXSA-Trade",
        login=122590,
        quotes=dict(live_prices),
        balance=lhfx_balance,
        clock=clock,
    )
    emu_l.publish_market()

    peak_store = PeakEquityStore(root / "peak.sqlite3")
    gate = load_default_forex_valve_gate(peak_equity_store=peak_store)
    oanda = _StubOandaTransport(equity=oanda_equity)
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
        ENV_INDEX_CONTRACT_SIZE: idx_contract_size,
        ENV_SPX500_CONTRACT_SIZE: spx_contract_size,
        ENV_INDEX_LEVERAGE: "200",
    }
    emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}

    def idx_ref(syms: tuple[str, ...]) -> dict[str, dict[str, object]]:
        return {
            s: {
                "bid": live_prices[s][0],
                "ask": live_prices[s][1],
                "source_provider": "PUBLIC_US_INDEX_FEED",
                "source_broker_id": None,
                "is_independent_public": True,
                "observed_at": clock().isoformat().replace("+00:00", "Z"),
            }
            for s in syms
            if s in live_prices
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

    state_dir = root / "trader_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    reg = FrontierModelRegistry(
        environ=env, clock=clock, http_post=_open_first_choice_http(call_counter), resolve_dns=lambda _h: None
    )
    quota = DailyQuotaGovernanceStore(state_dir / "quota.sqlite3")
    exec_gate = DurableModelExecutionGate(db_path=state_dir / "model_gate.sqlite3", max_calls_per_day=5000, clock=clock)
    dial = AggressionDialStore(state_dir / "dial.sqlite3", scope_id="dual-shield-barbell")
    tiers = ParallelTierEngine(
        state_dir / "tiers.sqlite3",
        valve_gate=gate,
        aggression_dial=dial,
        demo_high_growth=demo_high_growth,
        clock=clock,
    )
    ob_runner = None
    if with_option_b:
        ob_runner = OptionBPaperDemoRunner(
            db_path=state_dir / "option_b.sqlite3",
            valve_gate=gate,
            demo_high_growth=demo_high_growth,
            clock=clock,
        )
        for q_sym, (q_b, q_a) in live_prices.items():
            ob_runner.ingest_spot_quote(q_sym, q_b, q_a, now_utc=clock())

    trader = AutonomousAiTrader(
        router=router,
        model_registry=reg,
        valve_gate=gate,
        quota_store=quota,
        peak_equity_store=peak_store,
        execution_gate=exec_gate,
        state_dir=state_dir,
        initial_capital_usd=D("100000.00"),
        fast_tick_ms=50,
        ai_inference_cooldown_seconds=0.0,
        parallel_tiers=tiers,
        aggression_dial=dial,
        demo_high_growth=demo_high_growth,
        option_b_demo=ob_runner,
        clock=clock,
    )
    return trader, emu_l, emu_h, router, tiers, ob_runner, live_prices


class TestPr46Update46Regression(unittest.TestCase):
    def test_fix1_countertrend_5tick_spike_blocked_antichase_and_thinking_floor(self) -> None:
        det = TrendRegimeDetector()
        # Persistent bearish selloff (EMA9 < EMA21 < EMA50) followed by sharp 5-tick dead-cat bounce
        bear_series = [D("7250.0") - D("1.5") * i for i in range(45)]
        bear_bounce = bear_series + [D("7183.0"), D("7186.0"), D("7189.0"), D("7193.0")]
        r_ct_buy = det.classify(mids=bear_bounce, spread=D("0.6"), normal_sl_distance=D("60.0"))
        self.assertEqual(r_ct_buy.regime, REGIME_CHOP_RANGE)
        self.assertIsNone(r_ct_buy.direction)
        self.assertIn("Counter-trend BUY", r_ct_buy.reason)

        # Persistent bullish rally followed by sharp 5-tick dip -> counter-trend SELL blocked
        bull_series = [D("3600.0") + D("1.2") * i for i in range(45)]
        bull_dip = bull_series + [D("3652.0"), D("3649.0"), D("3646.0"), D("3642.0")]
        r_ct_sell = det.classify(mids=bull_dip, spread=D("0.6"), normal_sl_distance=D("60.0"))
        self.assertEqual(r_ct_sell.regime, REGIME_CHOP_RANGE)
        self.assertIsNone(r_ct_sell.direction)
        self.assertIn("Counter-trend SELL", r_ct_sell.reason)

        # Aligned bullish burst returns TREND_IGNITION BUY
        aligned_up = [D("3600.0") + D("0.05") * i for i in range(10)] + [D("3601.5"), D("3603.0"), D("3605.0"), D("3609.0")]
        r_ok = det.classify(mids=aligned_up, spread=D("2.5"), normal_sl_distance=D("60.0"))
        self.assertEqual(r_ok.regime, REGIME_TREND_IGNITION)
        self.assertEqual(r_ok.direction, Side.BUY)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _MutableClock()
            calls = [0]
            dhg = DemoHighGrowthProfile(enabled=True)
            trader, emu_l, emu_h, _router, _tiers, _ob, live_prices = _build_pr46_harness(
                root, clock=clock, call_counter=calls, demo_high_growth=dhg
            )
            self.addCleanup(trader.close)

            # Seed downtrend + bounce into SPX500 history -> trader MUST NOT fire 5-tick counter-trend BUY
            for m in bear_bounce[:-1]:
                b, a = m - D("0.30"), m + D("0.30")
                trader._tick_history.setdefault("SPX500", trader._tick_history.get("SPX500") or __import__("collections").deque(maxlen=64)).append((b, a))
            b_last, a_last = bear_bounce[-1] - D("0.30"), bear_bounce[-1] + D("0.30")
            live_prices["SPX500"] = (b_last, a_last)
            emu_l.set_quote("SPX500", b_last, a_last)
            emu_h.set_quote("SPX500", b_last, a_last)
            clock.advance(2)
            emu_h.publish_market()
            emu_l.publish_market()
            rep_ct = trader.run_cycle(mt5_quotes={"SPX500": (b_last, a_last)})
            self.assertEqual(rep_ct["action"], "WAIT")
            self.assertEqual(calls[0], 0)

            # Reset history cleanly; seed stretched BUY above EMA21 (> 0.60 * 60 = 36 pts) on NAS100 -> blocked
            trader._tick_history.clear()
            base_mids = [D("26800.00") + D("0.10") * i for i in range(45)]
            for m in base_mids:
                trader._tick_history.setdefault("NAS100", __import__("collections").deque(maxlen=64)).append((m - D("1"), m + D("1")))
            stretch_b, stretch_a = D("26850.00"), D("26852.00")  # > 36 pts above EMA21 (~26803)
            live_prices["NAS100"] = (stretch_b, stretch_a)
            emu_l.set_quote("NAS100", stretch_b, stretch_a)
            emu_h.set_quote("NAS100", stretch_b, stretch_a)
            clock.advance(2)
            emu_h.publish_market()
            emu_l.publish_market()
            rep_stretch = trader.run_cycle(mt5_quotes={"NAS100": (stretch_b, stretch_a)})
            self.assertEqual(rep_stretch["action"], "WAIT")
            self.assertEqual(calls[0], 0)

            # Seed overextended >2.0x ATR M1 impulse bar with ask in top 10% -> blocked
            trader._tick_history.clear()
            for m in [D("26800.00"), D("26803.00"), D("26806.00")]:
                trader._tick_history.setdefault("NAS100", __import__("collections").deque(maxlen=64)).append((m - D("1"), m + D("1")))
            imp_bars = [
                {"t": f"2026-11-24T13:{50 + i:02d}:00Z", "o": "26800.00", "h": "26820.00", "l": "26800.00", "c": "26810.00"}
                for i in range(4)
            ] + [
                {"t": "2026-11-24T13:55:00Z", "o": "26800.00", "h": "26875.00", "l": "26800.00", "c": "26872.00"}
            ]
            # Wait: make bar within anti-stretch by using larger M1 ATR so eff_sl widens above stretch/0.60
            # Keep previous bars at 20 pts, impulse bar 75 pts: live_atr = (20*4 + 75)/5 = 31 -> 2.0*31=62 < 75!
            # Wait: 0.60 * max(60, 77.5) = 46.50; if ema21 ~ 26803 and ask=26874 -> stretch=71 > 46.5.
            # Test pure impulse top-10% with bar centered on EMA21 (range 26780..26845 = 65 pts, ask=26843, ema21~26803, stretch=40 < 0.60*77.5=46.5)!
            imp_bars2 = [
                {"t": f"2026-11-24T13:{50 + i:02d}:00Z", "o": "26800.00", "h": "26820.00", "l": "26800.00", "c": "26810.00"}
                for i in range(4)
            ] + [
                {"t": "2026-11-24T13:55:00Z", "o": "26780.00", "h": "26845.00", "l": "26780.00", "c": "26844.00"}
            ]
            # Make 3 ascending ticks near 26841 -> top 10% of 26780..26845 (>= 26838.5), while within 0.60 * SL of EMA21
            trader._tick_history.clear()
            for p in (D("26831.00"), D("26836.00"), D("26841.00")):
                trader._tick_history.setdefault("NAS100", __import__("collections").deque(maxlen=64)).append((p - D("1"), p + D("1")))
            live_prices["NAS100"] = (D("26842.00"), D("26844.00"))
            emu_l.set_quote("NAS100", D("26842.00"), D("26844.00"))
            emu_h.set_quote("NAS100", D("26842.00"), D("26844.00"))
            clock.advance(2)
            emu_h.publish_market()
            emu_l.publish_market()
            rep_imp = trader.run_cycle(
                mt5_quotes={"NAS100": (D("26842.00"), D("26844.00"))},
                index_stream={"markets": [{"pair": "NAS100", "bid": "26842.00", "ask": "26844.00", "candles_m1": imp_bars2}]},
            )
            self.assertEqual(rep_imp["action"], "WAIT")
            self.assertEqual(calls[0], 0)

            # Now clean aligned TREND_IGNITION entry under DemoHighGrowthProfile -> upgrades effort from low to medium
            trader._tick_history.clear()
            for p in (D("26800.00"), D("26810.00"), D("26822.00")):
                bid_p, ask_p = p, p + D("2.00")
                live_prices["NAS100"] = (bid_p, ask_p)
                emu_l.set_quote("NAS100", bid_p, ask_p)
                emu_h.set_quote("NAS100", bid_p, ask_p)
                clock.advance(2)
                emu_h.publish_market()
                emu_l.publish_market()
                rep_ok = trader.run_cycle(mt5_quotes={"NAS100": (bid_p, ask_p)})
            self.assertEqual(rep_ok["action"], "OPEN_BUY")
            self.assertIn(rep_ok["thinking_depth"], ("medium", "high"))
            self.assertEqual(calls[0], 1)

    def test_fix2_1r_breakeven_r_multiple_trailing_restart_and_parallel_tiers_option_b(self) -> None:
        dhg_p = _default_protection_params("NAS100", D("1.00"), let_winners_run=True)
        self.assertGreaterEqual(dhg_p["be_trigger"], dhg_p["sl_distance"])
        self.assertEqual(dhg_p["be_offset"], (dhg_p["sl_distance"] * D("0.15")).quantize(D("0.01")))
        self.assertGreaterEqual(dhg_p["trail_activation"], (dhg_p["sl_distance"] * D("1.50")).quantize(D("0.01")))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _MutableClock()
            calls = [0]
            dhg = DemoHighGrowthProfile(enabled=True)
            trader, emu_l, emu_h, router, tiers, ob_runner, live_prices = _build_pr46_harness(
                root, clock=clock, call_counter=calls, demo_high_growth=dhg, with_option_b=True
            )
            self.addCleanup(trader.close)

            # Open NAS100 BUY with 60.00 default sl_distance + 2.00 spread => initial_sl_distance = 62.00
            for p in (D("26800.00"), D("26810.00"), D("26822.00")):
                bid_p, ask_p = p, p + D("2.00")
                live_prices["NAS100"] = (bid_p, ask_p)
                emu_l.set_quote("NAS100", bid_p, ask_p)
                emu_h.set_quote("NAS100", bid_p, ask_p)
                clock.advance(2)
                emu_h.publish_market()
                emu_l.publish_market()
                rep = trader.run_cycle(mt5_quotes={"NAS100": (bid_p, ask_p)})
            self.assertEqual(rep["action"], "OPEN_BUY")
            pos = router.venues[BROKER_LHFX_MT5].positions[0]
            init_sl_dist = abs(pos.price_open - pos.stop_loss)
            self.assertEqual(init_sl_dist, D("62.00"))
            self.assertEqual(trader._open_position_meta[pos.ticket]["initial_sl_distance"], "62")

            # Verify Option B symmetric risk_pct (10.00%, never spiked) and >= 2.20R TP
            self.assertIsNotNone(ob_runner)
            ob_pos = ob_runner.snapshot()["open_positions"][0]
            ob_stop_pts = abs(D(ob_pos["entry_price"]) - D(ob_pos["stop_loss_price"]))
            ob_tp_pts = abs(D(ob_pos["take_profit_price"]) - D(ob_pos["entry_price"]))
            self.assertGreaterEqual(ob_tp_pts, ob_stop_pts * D("2.20") - D("1"))

            # +15 pts and +59 pts (< 1.00R = 62.00): MUST NOT snap to breakeven!
            for gain in (D("15.00"), D("59.00")):
                b_g = pos.price_open + gain
                a_g = b_g + D("2.00")
                emu_l.set_quote("NAS100", b_g, a_g)
                emu_h.set_quote("NAS100", b_g, a_g)
                emu_h.publish_market()
                emu_l.publish_market()
                router.venues[BROKER_LHFX_MT5].probe()
                ev = trader.evaluate_fast_protection(quotes={"NAS100": (b_g, a_g)}, now=clock())
                self.assertEqual(ev, [])

            # Simulate restart (clear in-memory _open_position_meta while stage == INITIAL_SL) & move +62.00 (1.00R)
            saved_meta = dict(trader._open_position_meta)
            trader._open_position_meta.clear()
            b_1r = pos.price_open + D("62.00")
            a_1r = b_1r + D("2.00")
            emu_l.set_quote("NAS100", b_1r, a_1r)
            emu_h.set_quote("NAS100", b_1r, a_1r)
            emu_h.publish_market()
            emu_l.publish_market()
            router.venues[BROKER_LHFX_MT5].probe()
            ev_be = trader.evaluate_fast_protection(quotes={"NAS100": (b_1r, a_1r)}, now=clock())
            self.assertEqual(len(ev_be), 1)
            self.assertEqual(ev_be[0]["stage"], "BREAKEVEN_LOCKED")
            # +0.15 * 62.00 = +9.30 offset!
            self.assertEqual(D(ev_be[0]["new_stop_loss"]), pos.price_open + D("9.30"))
            self.assertGreaterEqual(D(saved_meta[pos.ticket]["initial_sl_distance"]), D("62"))

            # Move +93.00 (1.50R) -> TRAILING_ACTIVE with 0.75R = 46.50 trail distance -> SL = peak - 46.50 = entry + 46.50
            b_tr = pos.price_open + D("93.00")
            a_tr = b_tr + D("2.00")
            emu_l.set_quote("NAS100", b_tr, a_tr)
            emu_h.set_quote("NAS100", b_tr, a_tr)
            emu_h.publish_market()
            emu_l.publish_market()
            router.venues[BROKER_LHFX_MT5].probe()
            ev_tr = trader.evaluate_fast_protection(quotes={"NAS100": (b_tr, a_tr)}, now=clock())
            self.assertEqual(len(ev_tr), 1)
            self.assertEqual(ev_tr[0]["stage"], "TRAILING_ACTIVE")
            self.assertEqual(D(ev_tr[0]["new_stop_loss"]), pos.price_open + D("46.50"))

            # Verify reconstructed initial_sl_distance in trader meta
            self.assertEqual(D(trader._open_position_meta[pos.ticket]["initial_sl_distance"]), D("62"))

            # Verify ParallelTierEngine persisted initial_stop_loss & waited for 1.00R before BE/Trailing
            with contextlib.closing(sqlite3.connect(str(tiers.db_path))) as conn:
                rows = conn.execute("SELECT ticket, entry_price, initial_stop_loss, protection_stage FROM tier_positions").fetchall()
                self.assertGreaterEqual(len(rows), 1)
                pt_entry = D(rows[0][1])
                pt_init_sl = D(rows[0][2])
                pt_r = abs(pt_entry - pt_init_sl)
                self.assertGreater(pt_r, D("0"))
                # Earlier ticks moved +62 and +93; now step fresh position on standalone ParallelTierEngine at +15, +1R, +1.5R
            with tempfile.TemporaryDirectory() as td_pt:
                pt_dir = Path(td_pt)
                pt_gate = load_default_forex_valve_gate()
                pt_eng = ParallelTierEngine(
                    pt_dir / "pt_1r.sqlite3",
                    valve_gate=pt_gate,
                    demo_high_growth=DemoHighGrowthProfile(enabled=True),
                    clock=clock,
                )
                pt_q0 = {
                    "NAS100": (D("26800.00"), D("26802.00")),
                    "US30": (D("49000.00"), D("49004.00")),
                    "SPX500": (D("7200.00"), D("7200.60")),
                    "XAUUSD": (D("3650.00"), D("3650.60")),
                    "EURUSD": (D("1.10000"), D("1.10010")),
                }
                pt_eng.process_tick(
                    quotes=pt_q0,
                    signal={
                        "symbol": "NAS100",
                        "side": "BUY",
                        "stop_price": "26742.00",
                        "take_profit_price": "26934.00",
                        "regime": REGIME_STRONG_TREND,
                    },
                    now=clock(),
                )
                # +15 pts and +59 pts (< 60.00 = 1.00R): stays INITIAL_SL
                for gain in (D("15.00"), D("59.00")):
                    clock.advance(2)
                    pt_eng.process_tick(
                        quotes={**pt_q0, "NAS100": (D("26802.00") + gain, D("26804.00") + gain)},
                        signal=None,
                        now=clock(),
                    )
                    with contextlib.closing(sqlite3.connect(str(pt_eng.db_path))) as c_pt:
                        st_rows = [r[0] for r in c_pt.execute("SELECT protection_stage FROM tier_positions").fetchall()]
                    self.assertTrue(all(s == "INITIAL_SL" for s in st_rows))
                # +60.00 pts (1.00R) -> BREAKEVEN_LOCKED at entry + 9.00 (+0.15R)
                clock.advance(2)
                pt_eng.process_tick(
                    quotes={**pt_q0, "NAS100": (D("26862.00"), D("26864.00"))},
                    signal=None,
                    now=clock(),
                )
                with contextlib.closing(sqlite3.connect(str(pt_eng.db_path))) as c_pt:
                    be_rows = c_pt.execute("SELECT protection_stage, stop_loss FROM tier_positions").fetchall()
                self.assertTrue(all(st == "BREAKEVEN_LOCKED" and D(sl) == D("26811.00") for st, sl in be_rows))
                # +90.00 pts (1.50R) -> TRAILING_PROFIT at peak - 45.00 (0.75R) = 26847.00
                clock.advance(2)
                pt_eng.process_tick(
                    quotes={**pt_q0, "NAS100": (D("26892.00"), D("26894.00"))},
                    signal=None,
                    now=clock(),
                )
                with contextlib.closing(sqlite3.connect(str(pt_eng.db_path))) as c_pt:
                    tr_rows = c_pt.execute("SELECT protection_stage, stop_loss FROM tier_positions").fetchall()
                self.assertTrue(all(st == "TRAILING_PROFIT" and D(sl) == D("26847.00") for st, sl in tr_rows))

            # Verify AutonomousAiTrader Option B mirror call passes uniform target_risk_pct (10.00%, never 12%) even in STRONG_TREND
            recorded_ob_calls = []
            orig_mirror = ob_runner.mirror_entry_signal
            def _spy_mirror(**kw):
                recorded_ob_calls.append(dict(kw))
                return orig_mirror(**kw)
            ob_runner.mirror_entry_signal = _spy_mirror
            # Close existing NAS100 & feed STRONG_TREND XAUUSD rally -> trader passes risk_pct=10.00%
            emu_l._positions.clear()
            emu_h._positions.clear()
            emu_l.publish_market()
            emu_h.publish_market()
            trader._open_position_meta.clear()
            for step_i in range(12):
                px_b = D("3650.00") + D("1.50") * step_i
                px_a = px_b + D("0.60")
                live_prices["XAUUSD"] = (px_b, px_a)
                emu_l.set_quote("XAUUSD", px_b, px_a)
                emu_h.set_quote("XAUUSD", px_b, px_a)
                clock.advance(2)
                emu_h.publish_market()
                emu_l.publish_market()
                rep_st = trader.run_cycle(mt5_quotes={"XAUUSD": (px_b, px_a)})
                if rep_st.get("action") == "OPEN_BUY":
                    break
            self.assertGreaterEqual(len(recorded_ob_calls), 1)
            self.assertEqual(recorded_ob_calls[-1]["risk_pct"], D("10.00"))
            self.assertGreaterEqual(
                recorded_ob_calls[-1]["take_profit_points"],
                recorded_ob_calls[-1]["stop_distance_points"] * D("2.20") - D("0.01"),
            )

    def test_fix3_venue_scoped_equity_sizing_and_spx500_100x_contract_size(self) -> None:
        # 1. Backwards-compatible unconfigured default vs multi-contract SPX500=100 safety & env override
        calc_default = Mt5MarginCalculator()
        self.assertEqual(calc_default.contract_size_for("SPX500"), MT5_INDEX_CONTRACT_SIZE)

        calc_multi = Mt5MarginCalculator(index_contract_size=D("10"))
        self.assertEqual(calc_multi.contract_size_for("NAS100"), D("10"))
        self.assertEqual(calc_multi.contract_size_for("US30"), D("10"))
        self.assertEqual(calc_multi.contract_size_for("SPX500"), MT5_SPX500_CONTRACT_SIZE_MULTI)

        # Barbell risk on 1.00 lot SPX500 (100 units) with 60.1-pt SL = $6,010.00
        policy = BarbellCapitalPolicy()
        policy._calc = calc_multi
        self.assertEqual(
            policy.stop_loss_risk(
                symbol="SPX500",
                units=D("100"),
                entry_price=D("7218.4"),
                stop_price=D("7158.3"),
                quotes={"SPX500": (D("7217.8"), D("7218.4"))},
            ),
            D("6010.00"),
        )

        # Preserve Valve (161 params, 0.55) & LIVE constitutional bounds unchanged
        self.assertEqual(router_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(router_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _MutableClock()
            calls = [0]
            dhg = DemoHighGrowthProfile(enabled=True)  # 10.00% target risk
            # Exact live repro: OANDA = $100,000.00, LHFX = $75,379.44, SPX500 csize=100
            trader, _emu_l, _emu_h, router, _tiers, _ob, live_prices = _build_pr46_harness(
                root,
                clock=clock,
                call_counter=calls,
                lhfx_balance=D("75379.44"),
                oanda_equity="100000.00",
                idx_contract_size="10",
                spx_contract_size="100",
                demo_high_growth=dhg,
                with_option_b=False,
            )
            self.addCleanup(trader.close)
            self.assertEqual(trader._valve_gate.controller.parameter_count, 161)
            self.assertAlmostEqual(trader._valve_gate.controller.threshold, 0.55, places=6)

            lhfx_venue = router.venues[BROKER_LHFX_MT5]
            self.assertIsInstance(lhfx_venue, Mt5PaperBrokerVenue)
            self.assertEqual(lhfx_venue.margin_calculator.contract_size_for("SPX500"), D("100"))
            self.assertEqual(lhfx_venue.margin_calculator.contract_size_for("NAS100"), D("10"))
            # Currency rebuild on connect() MUST preserve symbol_contract_sizes
            lhfx_venue._calc = Mt5MarginCalculator(
                leverage=500, account_currency="EUR", index_contract_size=D("10"), symbol_contract_sizes={"SPX500": D("100")}
            )
            lhfx_venue.connect()
            self.assertEqual(lhfx_venue.margin_calculator.account_currency, "USD")
            self.assertEqual(lhfx_venue.margin_calculator.contract_size_for("SPX500"), D("100"))

            # SPX500 60.1-pt SL on $75,379.44 LHFX + $100,000 OANDA @ 10.00% risk:
            # Cap MUST be $7,537.94 (10% of LHFX), NOT $17,537.94 (10% of combined)!
            # 1.25 lots * 100 * 60.1 = $7,512.50 <= $7,537.94 (NEVER 1.78 lots!)
            spx_units = trader._compute_quantity(
                symbol="SPX500",
                side=Side.BUY,
                bid=D("7217.8"),
                ask=D("7218.4"),
                sl_price=D("7158.3"),
                total_equity=D("175379.44"),
                risk_multiplier=D("0.8333333333"),
                quotes_map=live_prices,
            )
            spx_lots = lhfx_venue.margin_calculator.units_to_lots(spx_units, symbol="SPX500")
            spx_risk = router.barbell.stop_loss_risk(
                symbol="SPX500", units=spx_units, entry_price=D("7218.4"), stop_price=D("7158.3"), quotes=live_prices
            )
            self.assertLessEqual(spx_lots, D("1.25"))
            self.assertLessEqual(spx_risk, D("7537.94"))

            # XAUUSD 59.78-pt SL: 1.26 lots * 100 * 59.78 = $7,532.28 <= $7,537.94 (NEVER 1.95 lots!)
            xau_units = trader._compute_quantity(
                symbol="XAUUSD",
                side=Side.BUY,
                bid=D("3650.77"),
                ask=D("3651.37"),
                sl_price=D("3591.59"),
                total_equity=D("175379.44"),
                risk_multiplier=D("0.8333333333"),
                quotes_map=live_prices,
            )
            xau_lots = lhfx_venue.margin_calculator.units_to_lots(xau_units, symbol="XAUUSD")
            xau_risk = router.barbell.stop_loss_risk(
                symbol="XAUUSD", units=xau_units, entry_price=D("3651.37"), stop_price=D("3591.59"), quotes=live_prices
            )
            self.assertLessEqual(xau_lots, D("1.26"))
            self.assertLessEqual(xau_risk, D("7537.94"))


if __name__ == "__main__":
    unittest.main()
