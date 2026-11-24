"""PR #44 pure-stdlib tests: Cross-Market Anti-Cancellation Correlation Guard & Open-Positions Exposure Safety."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.composition.parallel_tiers import DEFAULT_PARALLEL_TIER_SPECS, ParallelTierEngine
from cas_forex_revamp.composition.trend_regime import (
    CORRELATED_OFFSET_BLOCKED_CODE,
    CORRELATION_NEGATIVE_THRESHOLD,
    CORRELATION_POSITIVE_THRESHOLD,
    compute_rolling_return_correlation,
    evaluate_correlation_cap,
    evaluate_cross_market_offset_guard,
)
from cas_forex_revamp.contracts import Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import PeakEquityStore, load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
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
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OandaPracticePaperClient,
    TRANSPORT_SPOOL_BRIDGE,
)

D = Decimal
T0 = datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc)


def _fx_secret(tag: str) -> str:
    return f"pr44-fixture-{tag}"


class _Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOanda:
    def __init__(self, account_id: str = "101-001-4400001-001", equity: str = "100000.00") -> None:
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


def _model_http_first_option(calls: list[int]):
    def _post(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
        calls[0] += 1
        req_doc = json.loads(body.decode("utf-8"))
        user_doc = json.loads(req_doc["messages"][0]["content"])
        ref = user_doc["options"][0]["action_ref"]
        sel = {
            "request_id": user_doc["request_id"],
            "opportunity_set_id": user_doc["opportunity_set_id"],
            "source_state_id": user_doc["state"]["state_id"],
            "selected_action_ref": ref,
            "reason": f"ID=0{ref} approved pr44",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
        }
        return 200, json.dumps({
            "content": [{"type": "text", "text": json.dumps(sel)}],
            "usage": {"output_tokens": 32},
        }).encode("utf-8")

    return _post


def _build_trader_harness(root: Path, *, clock: _Clock, calls: list[int]):
    live_prices: dict[str, tuple[Decimal, Decimal]] = {
        "XAUUSD": (D("2600.00"), D("2600.60")),
        "SPX500": (D("6000.00"), D("6000.50")),
        "NAS100": (D("25000.00"), D("25002.00")),
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
        balance=D("100000.00"),
        clock=clock,
    )
    emu_l.publish_market()

    peak_store = PeakEquityStore(root / "peak.sqlite3")
    gate = load_default_forex_valve_gate(peak_equity_store=peak_store)
    oanda = _StubOanda()
    env = {
        ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
        ENV_MT5_SPOOL_DIR: str(root),
        ENV_HUGOSWAY_MT5_LOGIN: "1002903",
        ENV_HUGOSWAY_MT5_PASSWORD: _fx_secret("hugo"),
        ENV_HUGOSWAY_MT5_SERVER: "Hugosway-Demo",
        ENV_LHFX_MT5_LOGIN: "122590",
        ENV_LHFX_MT5_SERVER: "LHFXSA-Trade",
        ENV_OANDA_PRACTICE_TOKEN: _fx_secret("oanda"),
        ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
        "CAS_FOREX_ANTHROPIC_API_KEY": _fx_secret("claude"),
        "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
        "CAS_FOREX_INDEX_CONTRACT_SIZE": "1",
        "CAS_FOREX_INDEX_LEVERAGE": "200",
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

    state_dir = root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    reg = FrontierModelRegistry(
        environ=env, clock=clock, http_post=_model_http_first_option(calls), resolve_dns=lambda _h: None
    )
    quota = DailyQuotaGovernanceStore(state_dir / "quota.sqlite3")
    exec_gate = DurableModelExecutionGate(db_path=state_dir / "model_gate.sqlite3", max_calls_per_day=5000, clock=clock)
    dial = AggressionDialStore(state_dir / "dial.sqlite3", scope_id="dual-shield-barbell")
    tiers = ParallelTierEngine(state_dir / "tiers.sqlite3", valve_gate=gate, aggression_dial=dial, clock=clock)
    ob = OptionBPaperDemoRunner(db_path=state_dir / "option_b.sqlite3", valve_gate=gate, clock=clock)
    for sym, (b, a) in live_prices.items():
        ob.ingest_spot_quote(sym, b, a, now_utc=clock())

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
        option_b_demo=ob,
        clock=clock,
    )
    return trader, emu_l, emu_h, tiers, ob, live_prices


class Pr44CorrelationOffsetGuardTests(unittest.TestCase):
    def test_01_rolling_return_correlation_positive_negative_and_gold_index_matrix(self) -> None:
        self.assertEqual(CORRELATION_POSITIVE_THRESHOLD, D("0.45"))
        self.assertEqual(CORRELATION_NEGATIVE_THRESHOLD, D("-0.45"))

        # Positively correlated returns across XAUUSD & SPX500 (varying steps, identical signs)
        pos_rets = [D("0.0020"), D("0.0010"), D("-0.0005"), D("0.0030"), D("0.0015"), D("-0.0010"), D("0.0025")]
        xau_pos = [D("2600.00")]
        spx_pos = [D("6000.00")]
        for r in pos_rets:
            xau_pos.append(xau_pos[-1] * (D("1") + r))
            spx_pos.append(spx_pos[-1] * (D("1") + r))
        r_pos = compute_rolling_return_correlation(xau_pos, spx_pos)
        self.assertEqual(r_pos, D("1.0000"))

        hist_pos = {"XAUUSD": xau_pos, "SPX500": spx_pos}
        ok_opp, reason_opp = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "XAUUSD", "side": "BUY"}],
            price_history=hist_pos,
        )
        self.assertFalse(ok_opp)
        self.assertIn(CORRELATED_OFFSET_BLOCKED_CODE, reason_opp)
        self.assertIn("r=+1.0000", reason_opp)

        ok_same, _ = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.BUY,
            open_positions=[{"symbol": "XAUUSD", "side": "BUY"}],
            price_history=hist_pos,
        )
        self.assertTrue(ok_same)

        # Negatively correlated returns across XAUUSD & SPX500
        xau_neg = [D("2600.00")]
        spx_neg = [D("6000.00")]
        for r in pos_rets:
            xau_neg.append(xau_neg[-1] * (D("1") + r))
            spx_neg.append(spx_neg[-1] * (D("1") - r))
        r_neg = compute_rolling_return_correlation(xau_neg, spx_neg)
        self.assertEqual(r_neg, D("-1.0000"))

        hist_neg = {"XAUUSD": xau_neg, "SPX500": spx_neg}
        ok_neg_same, reason_neg_same = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.BUY,
            open_positions=[{"symbol": "XAUUSD", "side": "BUY"}],
            price_history=hist_neg,
        )
        self.assertFalse(ok_neg_same)
        self.assertIn(CORRELATED_OFFSET_BLOCKED_CODE, reason_neg_same)
        self.assertIn("r=-1.0000", reason_neg_same)

        ok_neg_opp, _ = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "XAUUSD", "side": "BUY"}],
            price_history=hist_neg,
        )
        self.assertTrue(ok_neg_opp)

        # Insufficient / flat / uncorrelated series -> Gold vs SPX500 returns None and allows trade
        self.assertIsNone(compute_rolling_return_correlation(xau_pos[:5], spx_pos[:5]))
        self.assertIsNone(compute_rolling_return_correlation([D("100")] * 8, spx_pos))
        ok_cold_gold, _ = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "XAUUSD", "side": "BUY"}],
            price_history=None,
        )
        self.assertTrue(ok_cold_gold)

    def test_02_structural_priors_alias_normalization_and_cap_compatibility(self) -> None:
        # US equity indices opposing blocked cleanly at cold start (incl. MNQ/MES/broker aliases)
        ok_idx, msg_idx = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "NAS100", "side": "BUY"}],
        )
        self.assertFalse(ok_idx)
        self.assertIn(CORRELATED_OFFSET_BLOCKED_CODE, msg_idx)

        ok_micro, _ = evaluate_cross_market_offset_guard(
            candidate_symbol="MES",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "MNQ", "side": "BUY"}],
        )
        self.assertFalse(ok_micro)

        # Same-side indices allowed by offset guard & evaluate_correlation_cap
        ok_idx_same, _ = evaluate_correlation_cap(
            candidate_symbol="SPX500",
            candidate_side=Side.BUY,
            open_positions=[{"symbol": "NAS100", "side": "BUY"}],
        )
        self.assertTrue(ok_idx_same)

        # FX positive prior: EURUSD BUY blocks GBPUSD SELL; allows GBPUSD BUY
        ok_fx_opp, _ = evaluate_cross_market_offset_guard(
            candidate_symbol="GBPUSD",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "EURUSD", "side": "BUY"}],
        )
        self.assertFalse(ok_fx_opp)
        ok_fx_same, _ = evaluate_correlation_cap(
            candidate_symbol="GBPUSD",
            candidate_side=Side.BUY,
            open_positions=[{"symbol": "EURUSD", "side": "BUY"}],
        )
        self.assertTrue(ok_fx_same)

        # FX negative prior: EURUSD BUY blocks USDCHF BUY (self-canceling long+short USD), allows USDCHF SELL
        ok_chf_same, msg_chf = evaluate_cross_market_offset_guard(
            candidate_symbol="USDCHF",
            candidate_side=Side.BUY,
            open_positions=[{"symbol": "EURUSD", "side": "BUY"}],
        )
        self.assertFalse(ok_chf_same)
        self.assertIn(CORRELATED_OFFSET_BLOCKED_CODE, msg_chf)
        ok_chf_opp, _ = evaluate_cross_market_offset_guard(
            candidate_symbol="USDCHF",
            candidate_side=Side.SELL,
            open_positions=[{"symbol": "EURUSD", "side": "BUY"}],
        )
        self.assertTrue(ok_chf_opp)

        # House-Money pyramid ADD on same symbol & side is never blocked
        ok_pyr, reason_pyr = evaluate_cross_market_offset_guard(
            candidate_symbol="SPX500",
            candidate_side=Side.BUY,
            open_positions=[{"symbol": "SPX500", "side": "BUY"}],
            is_pyramid_add=True,
        )
        self.assertTrue(ok_pyr)
        self.assertEqual(reason_pyr, "CORRELATED_OFFSET_CLEAR")

    def test_03_autonomous_trader_blocks_correlated_offset_and_surfaces_skip_reason(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _Clock(T0)
            calls = [0]
            trader, emu_l, emu_h, _tiers, _ob, live_prices = _build_trader_harness(root, clock=clock, calls=calls)
            self.addCleanup(trader.close)

            # Step 1: Open real XAUUSD BUY position through AutonomousAiTrader
            xau_up_bars = [
                {"t": f"2026-11-23T17:{50 + idx:02d}:00Z", "o": "2600.00", "h": "2604.00", "l": "2599.50", "c": str(D("2600.00") + D(idx * 2))}
                for idx in range(5)
            ]
            rep_open = None
            for px in ("2600.00", "2606.00", "2612.00"):
                xb = D(px)
                xa = xb + D("0.60")
                live_prices["XAUUSD"] = (xb, xa)
                emu_l.set_quote("XAUUSD", xb, xa)
                emu_h.set_quote("XAUUSD", xb, xa)
                emu_l.publish_market()
                emu_h.publish_market()
                clock.advance(2)
                rep_open = trader.run_cycle(
                    mt5_quotes={"XAUUSD": (xb, xa)},
                    index_stream={"markets": [{"pair": "XAUUSD", "bid": str(xb), "ask": str(xa), "candles_m1": xau_up_bars}]},
                )
            self.assertIsNotNone(rep_open)
            self.assertEqual(rep_open["action"], "OPEN_BUY")
            self.assertEqual(rep_open["symbol"], "XAUUSD")
            calls[0] = 0

            # Step 2: Feed positively correlated falling candles across both XAUUSD & SPX500 (r = +1.0000),
            # while SPX500 fires a SELL setup -> must be blocked because XAUUSD BUY is open.
            steps = [D("0"), D("-0.0020"), D("-0.0010"), D("-0.0030"), D("-0.0015"), D("0.0005"), D("-0.0025"), D("-0.0035")]
            xau_bars = []
            spx_bars = []
            xp = D("2612.00")
            sp = D("6000.00")
            for idx, r in enumerate(steps):
                xp = (xp * (D("1") + r)).quantize(D("0.01"))
                sp = (sp * (D("1") + r)).quantize(D("0.01"))
                ts_s = f"2026-11-23T18:{10 + idx:02d}:00Z"
                xau_bars.append({"t": ts_s, "o": str(xp), "h": str(xp + D("1")), "l": str(xp - D("1")), "c": str(xp)})
                spx_bars.append({"t": ts_s, "o": str(sp), "h": str(sp + D("1")), "l": str(sp - D("1")), "c": str(sp)})

            for s_bid_s in ("5990.00", "5978.00", "5966.00"):
                s_bid = D(s_bid_s)
                s_ask = s_bid + D("0.50")
                live_prices["SPX500"] = (s_bid, s_ask)
                emu_l.set_quote("SPX500", s_bid, s_ask)
                emu_h.set_quote("SPX500", s_bid, s_ask)
                emu_l.publish_market()
                emu_h.publish_market()
                clock.advance(2)
                rep = trader.run_cycle(
                    mt5_quotes={"SPX500": (s_bid, s_ask)},
                    index_stream={
                        "markets": [
                            {"pair": "XAUUSD", "bid": str(live_prices["XAUUSD"][0]), "ask": str(live_prices["XAUUSD"][1]), "candles_m1": xau_bars},
                            {"pair": "SPX500", "bid": str(s_bid), "ask": str(s_ask), "candles_m1": spx_bars},
                        ]
                    },
                )

            self.assertEqual(rep["action"], "WAIT")
            self.assertEqual(calls[0], 0)
            self.assertIn(CORRELATED_OFFSET_BLOCKED_CODE, str(trader._last_dial_skip_reason))

    def test_04_parallel_tiers_blocks_correlated_offset_and_sets_skip_reason(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _Clock(T0)
            gate = load_default_forex_valve_gate()
            eng = ParallelTierEngine(
                root / "tiers.sqlite3",
                valve_gate=gate,
                specs=DEFAULT_PARALLEL_TIER_SPECS,
                clock=clock,
            )

            # Warm up 8 ticks with strong positive correlation between XAUUSD & SPX500 (same fractional returns)
            rets = [D("0.0010"), D("0.0020"), D("-0.0005"), D("0.0015"), D("0.0025"), D("-0.0010"), D("0.0020")]
            x_px = D("2600.00")
            s_px = D("6000.00")
            quotes = {"XAUUSD": (x_px, x_px + D("0.40")), "SPX500": (s_px, s_px + D("0.50"))}
            eng.process_tick(quotes=quotes, signal=None, now=clock())
            for r in rets:
                clock.advance(1)
                x_px = (x_px * (D("1") + r)).quantize(D("0.01"))
                s_px = (s_px * (D("1") + r)).quantize(D("0.01"))
                quotes = {"XAUUSD": (x_px, x_px + D("0.40")), "SPX500": (s_px, s_px + D("0.50"))}
                eng.process_tick(quotes=quotes, signal=None, now=clock())

            # Open XAUUSD BUY across tiers (on tiers where 0.01 lot fits stop risk)
            clock.advance(1)
            snap_open = eng.process_tick(
                quotes=quotes,
                signal={
                    "symbol": "XAUUSD",
                    "side": "BUY",
                    "stop_price": str((x_px - D("15.00")).quantize(D("0.01"))),
                    "take_profit_price": str((x_px + D("35.00")).quantize(D("0.01"))),
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_id_1 = {t["tier_id"]: t for t in snap_open["tiers"]}
            self.assertEqual(by_id_1["TIER_1_CURRENT"]["open_positions"], 1)

            # Attempt opposing SPX500 SELL -> must be blocked by live r >= +0.45 with CORRELATED_OFFSET_BLOCKED
            clock.advance(1)
            snap_blk = eng.process_tick(
                quotes=quotes,
                signal={
                    "symbol": "SPX500",
                    "side": "SELL",
                    "stop_price": str((s_px + D("25.00")).quantize(D("0.01"))),
                    "take_profit_price": str((s_px - D("55.00")).quantize(D("0.01"))),
                    "regime": "STRONG_TREND",
                },
                now=clock(),
            )
            by_id_2 = {t["tier_id"]: t for t in snap_blk["tiers"]}
            self.assertEqual(by_id_2["TIER_1_CURRENT"]["open_positions"], 1)
            self.assertIn(CORRELATED_OFFSET_BLOCKED_CODE, str(by_id_2["TIER_1_CURRENT"]["last_skip_reason"]))

    def test_05_option_b_paper_runner_blocks_canceling_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _Clock(T0)
            gate = load_default_forex_valve_gate()
            runner = OptionBPaperDemoRunner(db_path=root / "ob.sqlite3", valve_gate=gate, clock=clock)

            # Cold-start structural test: NAS100 BUY blocks opposing SPX500 SELL (prior r=+0.85), allows SPX500 BUY
            runner.ingest_spot_quote("NAS100", D("25000.00"), D("25001.00"), now_utc=clock())
            runner.ingest_spot_quote("SPX500", D("6000.00"), D("6000.50"), now_utc=clock())
            r_nas = runner.mirror_entry_signal(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=D("20.00"),
                take_profit_points=D("50.00"),
                now_utc=clock(),
            )
            self.assertTrue(r_nas["executed"], r_nas)

            clock.advance(1)
            r_opp = runner.mirror_entry_signal(
                symbol="SPX500",
                side="SELL",
                stop_distance_points=D("8.00"),
                take_profit_points=D("20.00"),
                now_utc=clock(),
            )
            self.assertFalse(r_opp["executed"])
            self.assertEqual(r_opp["status"], CORRELATED_OFFSET_BLOCKED_CODE)

            clock.advance(1)
            r_same = runner.mirror_entry_signal(
                symbol="SPX500",
                side="BUY",
                stop_distance_points=D("8.00"),
                take_profit_points=D("20.00"),
                now_utc=clock(),
            )
            self.assertTrue(r_same["executed"], r_same)

    def test_06_option_b_gold_vs_index_live_rolling_and_same_symbol_pyramid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _Clock(T0)
            gate = load_default_forex_valve_gate()
            runner = OptionBPaperDemoRunner(db_path=root / "ob_live.sqlite3", valve_gate=gate, clock=clock)

            rets = [D("0.0015"), D("0.0020"), D("-0.0008"), D("0.0012"), D("0.0022"), D("-0.0005"), D("0.0018")]
            x_px = D("2600.00")
            s_px = D("6000.00")
            runner.ingest_spot_quote("XAUUSD", x_px, x_px + D("0.40"), now_utc=clock())
            runner.ingest_spot_quote("SPX500", s_px, s_px + D("0.50"), now_utc=clock())
            for r in rets:
                clock.advance(1)
                x_px = (x_px * (D("1") + r)).quantize(D("0.01"))
                s_px = (s_px * (D("1") + r)).quantize(D("0.01"))
                runner.ingest_spot_quote("XAUUSD", x_px, x_px + D("0.40"), now_utc=clock())
                runner.ingest_spot_quote("SPX500", s_px, s_px + D("0.50"), now_utc=clock())

            r_xau = runner.mirror_entry_signal(
                symbol="XAUUSD",
                side="BUY",
                stop_distance_points=D("4.00"),
                take_profit_points=D("10.00"),
                max_open_positions=4,
                now_utc=clock(),
            )
            self.assertTrue(r_xau["executed"], r_xau)

            # Same-symbol same-side add allowed; opposing SPX500 SELL blocked by live r >= +0.45
            clock.advance(1)
            r_add = runner.mirror_entry_signal(
                symbol="XAUUSD",
                side="BUY",
                stop_distance_points=D("4.00"),
                take_profit_points=D("10.00"),
                max_open_positions=4,
                now_utc=clock(),
            )
            self.assertTrue(r_add["executed"], r_add)

            clock.advance(1)
            r_cancel = runner.mirror_entry_signal(
                symbol="SPX500",
                side="SELL",
                stop_distance_points=D("8.00"),
                take_profit_points=D("20.00"),
                max_open_positions=4,
                now_utc=clock(),
            )
            self.assertFalse(r_cancel["executed"])
            self.assertEqual(r_cancel["status"], CORRELATED_OFFSET_BLOCKED_CODE)
