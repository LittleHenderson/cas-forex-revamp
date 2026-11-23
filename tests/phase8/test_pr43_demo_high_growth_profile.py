"""PR #43 comprehensive pure-stdlib tests: DEMO-only High-Growth Practice Profile & 4 Forensic Autopsy Fixes."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import urllib.parse

from cas_forex_revamp.composition import autonomous_trader as trader_mod
from cas_forex_revamp.composition import option_b_paper_runner as ob_mod
from cas_forex_revamp.composition import parallel_tiers as pt_mod
from cas_forex_revamp.composition import phase8_live_bridge as p8_mod
from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    _compute_live_candle_atr,
    _default_protection_params,
    _is_us_equity_pre_close_chop,
)
from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    _roll_mt5_index_bars,
)
from cas_forex_revamp.composition.option_b_paper_runner import OptionBPaperDemoRunner
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.phase8_live_bridge import Phase8LiveTradingBridge
from cas_forex_revamp.contracts import ContractError, Side
from cas_forex_revamp.execution.smart_execution import SmartExecutionPlanner, SmartSliceExecutor
from cas_forex_revamp.futures import micro_futures_specs as mfs_mod
from cas_forex_revamp.futures import tradovate_venue as tv_mod
from cas_forex_revamp.futures.micro_futures_specs import size_micro_futures_order
from cas_forex_revamp.futures.tradovate_venue import TradovateMicroFuturesVenue
from cas_forex_revamp.ledger.unified_ledger import UnifiedRealTimeLedger
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.risk.demo_high_growth_profile import (
    DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE,
    DEMO_HIGH_GROWTH_POST_LOSS_COOLDOWN_SECONDS,
    DEMO_HIGH_GROWTH_SCHEMA,
    DemoHighGrowthProfile,
    DemoHighGrowthProfileStore,
)
from cas_forex_revamp.risk.news_shock_shield import NewsShockShield
from cas_forex_revamp.treasury import compounding_controller as comp_mod
from cas_forex_revamp.treasury.compounding_controller import CompoundingAndMilestoneController
from cas_forex_revamp.valve import tks_meta_valve_controller as valve_mod
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue import dual_shield_router as router_mod
from cas_forex_revamp.venue.dual_shield_router import BarbellCapitalPolicy, DualShieldBrokerRouter
from cas_forex_revamp.venue.execution_event_bus import ExecutionEventBus
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
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    TRANSPORT_SPOOL_BRIDGE,
)

D = Decimal
T0 = datetime(2026, 11, 23, 15, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
OB_SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "option-b-demo.schema.json"


def _fixture_str(slot: str) -> str:
    return f"pr43-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-4300001-001", equity: str = "100000.00") -> None:
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
            "reason": f"ID=0{ref} approved pr43",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
        }
        return 200, json.dumps({
            "content": [{"type": "text", "text": json.dumps(sel)}],
            "usage": {"output_tokens": 32},
        }).encode("utf-8")

    return _post


def _validate_option_b_snapshot(snapshot: dict) -> list[str]:
    schema = json.loads(OB_SCHEMA_PATH.read_text(encoding="utf-8"))
    errors: list[str] = []
    props = schema.get("properties", {})
    for k in schema.get("required", ()):
        if k not in snapshot:
            errors.append(f"missing {k}")
    extra = sorted(set(snapshot.keys()) - set(props.keys()))
    if extra:
        errors.append(f"extra keys {extra}")
    if snapshot.get("schema") != "cas-forex.option-b-demo/1":
        errors.append("bad schema")
    if snapshot.get("mode") != "DEMO" or snapshot.get("paper_demo_only") is not True:
        errors.append("must be DEMO paper only")
    if snapshot.get("real_money_at_risk_usd") != "0.00":
        errors.append("real_money_at_risk_usd must be 0.00")
    return errors


def _build_trader_harness(
    root: Path,
    *,
    clock: _MutableClock,
    call_counter: list[int],
    demo_high_growth: DemoHighGrowthProfile | None = None,
    with_option_b: bool = True,
) -> tuple[AutonomousAiTrader, Mt5SpoolPaperTerminalEmulator, Mt5SpoolPaperTerminalEmulator, OptionBPaperDemoRunner | None, dict[str, tuple[Decimal, Decimal]]]:
    live_prices: dict[str, tuple[Decimal, Decimal]] = {
        "NAS100": (D("26800.00"), D("26802.00")),
        "US30": (D("49000.00"), D("49004.00")),
        "XAUUSD": (D("2650.00"), D("2650.60")),
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

    state_dir = root / "trader_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    reg = FrontierModelRegistry(environ=env, clock=clock, http_post=_open_first_choice_http(call_counter), resolve_dns=lambda _h: None)
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
    ob_runner: OptionBPaperDemoRunner | None = None
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
    return trader, emu_l, emu_h, ob_runner, live_prices


class TestPr43DemoHighGrowthProfile(unittest.TestCase):
    def test_constitutional_constants_immutable_and_defaults_preserved(self) -> None:
        self.assertEqual(router_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(router_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(valve_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(trader_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(trader_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(pt_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(mfs_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(tv_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(ob_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(ob_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(comp_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(comp_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(p8_mod.MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(p8_mod.MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))

        default_prof = DemoHighGrowthProfile()
        self.assertFalse(default_prof.enabled)
        self.assertEqual(default_prof.effective_stop_risk_ceiling_pct(), D("1.00"))
        self.assertEqual(default_prof.effective_drawdown_ceiling_pct(), D("0.10"))
        self.assertEqual(default_prof.effective_sweep_ratio(), D("0.50"))
        self.assertEqual(default_prof.post_loss_cooldown_seconds, DEMO_HIGH_GROWTH_POST_LOSS_COOLDOWN_SECONDS)
        self.assertTrue(default_prof.block_us_close_chop)

        pol = BarbellCapitalPolicy()
        self.assertEqual(pol.max_stop_loss_equity_risk_pct, D("1.00"))
        self.assertEqual(pol.max_drawdown_pct, D("0.10"))

    def test_profile_validation_and_live_mode_fail_closed_across_modules(self) -> None:
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, max_risk_pct=D("12.01"))
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, max_drawdown_pct=D("0.31"))
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, target_risk_pct=D("11.00"), max_risk_pct=D("10.00"))
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, max_risk_pct=D("10.00"), max_drawdown_pct=D("0.10"))
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, demo_only_locked=False)
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, post_loss_cooldown_seconds=True)  # type: ignore[arg-type]
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, post_loss_cooldown_seconds=3601)
        with self.assertRaises(ContractError):
            DemoHighGrowthProfile(enabled=True, block_us_close_chop=1)  # type: ignore[arg-type]

        active = DemoHighGrowthProfile(enabled=True)
        for kwargs in (
            {"execution_mode": "LIVE", "live_trading_armed": False, "live_trading_locked": True},
            {"execution_mode": "DEMO", "live_trading_armed": True, "live_trading_locked": True},
            {"execution_mode": "DEMO", "live_trading_armed": False, "live_trading_locked": False},
        ):
            with self.assertRaises(ContractError) as ctx:
                active.assert_demo_mode(**kwargs)
            self.assertIn(DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE, str(ctx.exception))

        pol = BarbellCapitalPolicy(demo_high_growth=active)
        self.assertEqual(pol.max_stop_loss_equity_risk_pct, D("12.00"))
        self.assertEqual(pol.max_drawdown_pct, D("0.30"))
        pol.require_drawdown(current_equity=D("7500.00"), peak_equity=D("10000.00"))

        with self.assertRaises(ContractError):
            pol.apply_demo_high_growth_profile(active, execution_mode="LIVE", live_trading_armed=True, live_trading_locked=False)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctrl = CompoundingAndMilestoneController(root / "comp.sqlite3", starting_principal_usd=D("5000.00"))
            ctrl.set_demo_high_growth_profile(active)
            ok_dec = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=D("5000.00"),
                risk_pct=D("10.00"),
                drawdown_pct=D("0.20"),
            )
            self.assertTrue(ok_dec.allowed)
            over_dec = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=D("5000.00"),
                risk_pct=D("12.01"),
                drawdown_pct=D("0.20"),
            )
            self.assertFalse(over_dec.allowed)
            with self.assertRaises(ContractError):
                ctrl.set_demo_high_growth_profile(active, execution_mode="LIVE")

            gate = load_default_forex_valve_gate(peak_equity_store=PeakEquityStore(root / "pk.sqlite3"))
            gate.set_demo_high_growth_profile(active)
            ledger = UnifiedRealTimeLedger(root / "led.sqlite3", scope_id="test", principal_usd=D("5000.00"))
            bus = ExecutionEventBus()
            bridge = Phase8LiveTradingBridge(
                gate,
                ledger=ledger,
                event_bus=bus,
                news_shield=NewsShockShield(),
                smart_planner=SmartExecutionPlanner(),
                smart_executor=SmartSliceExecutor(valve_gate=gate),
                compounding_controller=ctrl,
                demo_high_growth=active,
            )
            self.addCleanup(bridge.close)
            self.assertEqual(bridge._effective_max_stop_risk_pct(), D("12.00"))
            self.assertEqual(bridge._effective_max_drawdown_pct(), D("0.30"))
            with self.assertRaises(Exception):
                bridge.set_demo_high_growth_profile(active, execution_mode="LIVE")

        sz_ok = size_micro_futures_order(
            symbol_or_root="MNQ",
            equity_usd=D("5000.00"),
            risk_pct=D("10.00"),
            stop_distance_points=D("25.00"),
            demo_max_stop_risk_pct=D("12.00"),
        )
        self.assertGreaterEqual(sz_ok.contracts, 1)
        with self.assertRaises(Exception):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=D("5000.00"),
                risk_pct=D("12.50"),
                stop_distance_points=D("25.00"),
                demo_max_stop_risk_pct=D("12.00"),
            )

        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(Exception):
                TradovateMicroFuturesVenue(Path(td) / "tv.sqlite3", mode="LIVE", demo_high_growth=active)

    def test_parallel_tiers_unblocks_300_1000_gold_100pct_compound_and_cooldown(self) -> None:
        quotes = {
            "XAUUSD": (D("2650.00"), D("2650.60")),
            "NAS100": (D("26800.00"), D("26802.00")),
        }
        sig_gold = {
            "symbol": "XAUUSD",
            "side": "BUY",
            "stop_price": "2625.00",
            "take_profit_price": "2750.00",
            "regime": "STRONG_TREND",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _MutableClock(T0)
            gate_def = load_default_forex_valve_gate()
            eng_def = ParallelTierEngine(root / "tiers_def.sqlite3", valve_gate=gate_def, clock=clock)
            snap_def = eng_def.process_tick(quotes=quotes, signal=sig_gold, now=clock())
            by_id_def = {t["tier_id"]: t for t in snap_def["tiers"]}
            self.assertEqual(by_id_def["TIER_5_300"]["open_positions"], 0)
            self.assertEqual(by_id_def["TIER_2_1000"]["open_positions"], 0)
            self.assertIn("LOT_FLOOR", str(by_id_def["TIER_5_300"]["last_skip_reason"]))

            dhg = DemoHighGrowthProfile(enabled=True)
            gate_dhg = load_default_forex_valve_gate()
            gate_dhg.set_demo_high_growth_profile(dhg)
            eng_dhg = ParallelTierEngine(
                root / "tiers_dhg.sqlite3",
                valve_gate=gate_dhg,
                demo_high_growth=dhg,
                clock=clock,
            )
            snap_dhg = eng_dhg.process_tick(quotes=quotes, signal=sig_gold, now=clock())
            by_id_dhg = {t["tier_id"]: t for t in snap_dhg["tiers"]}
            self.assertGreaterEqual(by_id_dhg["TIER_5_300"]["open_positions"], 1)
            self.assertGreaterEqual(by_id_dhg["TIER_2_1000"]["open_positions"], 1)

            # Verify all 5 vaults configured to 0.00 sweep (100% compounding)
            for tid, vault in eng_dhg._vaults.items():
                self.assertEqual(D(vault.snapshot()["sweep_ratio"]), D("0.00"), f"{tid} vault not 0% sweep")

            # Verify per-(tier_id, symbol) post-loss cooldown blocks rapid re-entry on loss
            with contextlib.closing(sqlite3.connect(str(eng_dhg.db_path))) as conn:
                conn.execute(
                    "UPDATE tier_positions SET take_profit = NULL WHERE tier_id = 'TIER_5_300' AND symbol = 'XAUUSD'"
                )
                conn.commit()
            clock.advance(30)
            loss_quotes = {
                "XAUUSD": (D("2620.00"), D("2620.60")),
                "NAS100": (D("26800.00"), D("26802.00")),
            }
            eng_dhg.process_tick(quotes=loss_quotes, signal=None, now=clock())
            clock.advance(20)
            re_sig_gold = {
                "symbol": "XAUUSD",
                "side": "SELL",
                "stop_price": "2645.00",
                "take_profit_price": "2550.00",
                "regime": "STRONG_TREND",
            }
            snap_cd = eng_dhg.process_tick(quotes=loss_quotes, signal=re_sig_gold, now=clock())
            by_id_cd = {t["tier_id"]: t for t in snap_cd["tiers"]}
            self.assertIn("DEMO_POST_LOSS_COOLDOWN", str(by_id_cd["TIER_5_300"]["last_skip_reason"]))

            clock.advance(905)
            snap_after = eng_dhg.process_tick(quotes=loss_quotes, signal=re_sig_gold, now=clock())
            by_id_after = {t["tier_id"]: t for t in snap_after["tiers"]}
            self.assertGreaterEqual(by_id_after["TIER_5_300"]["open_positions"], 1)

    def test_option_b_demo_high_growth_10pct_30pct_100pct_and_schema(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _MutableClock(T0)
            gate = load_default_forex_valve_gate()
            runner = OptionBPaperDemoRunner(db_path=root / "ob.sqlite3", valve_gate=gate, clock=clock)
            runner.ingest_spot_quote("NAS100", D("26800.00"), D("26802.00"), now_utc=clock())
            self.assertEqual(runner.default_risk_pct, D("1.00"))
            self.assertEqual(runner.max_stop_loss_risk_pct, D("1.00"))

            runner.set_demo_high_growth_profile(DemoHighGrowthProfile(enabled=True))
            self.assertEqual(runner.default_risk_pct, D("10.00"))
            self.assertEqual(runner.max_stop_loss_risk_pct, D("12.00"))
            self.assertEqual(runner.max_drawdown_pct, D("0.30"))

            res_10 = runner.mirror_entry_signal(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=D("60.00"),
                take_profit_points=D("132.00"),
                now_utc=clock(),
            )
            self.assertTrue(res_10["executed"])
            self.assertGreaterEqual(int(res_10["contracts"]), 3)

            with self.assertRaises(ContractError):
                runner.mirror_entry_signal(
                    symbol="NAS100",
                    side="BUY",
                    stop_distance_points=D("60.00"),
                    take_profit_points=D("132.00"),
                    risk_pct=D("12.01"),
                    now_utc=clock(),
                )

            clock.advance(60)
            runner.ingest_spot_quote("NAS100", D("26950.00"), D("26952.00"), now_utc=clock())
            snap_win = runner.snapshot()
            self.assertEqual(snap_win["vault_50pct_reserved_usd"], "0.00")
            self.assertGreater(D(snap_win["retained_compounding_usd"]), D("0.00"))
            self.assertEqual(snap_win["max_stop_loss_risk_pct"], "12.00")
            self.assertEqual(snap_win["max_drawdown_pct"], "30.00")
            self.assertEqual(_validate_option_b_snapshot(snap_win), [])

    def test_forensic_1_roll_mt5_index_bars_never_stitches_stale_gap(self) -> None:
        from cas_forex_revamp.contracts import decimal_text

        stale_friday = [{
            "t": "2026-11-20T21:59:00Z",
            "o": "25220.00",
            "h": "25230.00",
            "l": "25215.00",
            "c": "25224.64",
            "v": "10",
            "n": 10,
        }]
        monday_bars = _roll_mt5_index_bars(stale_friday, "2026-11-23T20:36:00Z", D("26838.425"), decimal_text)
        last = monday_bars[-1]
        self.assertEqual(last["o"], "26838.425")
        self.assertEqual(last["h"], "26838.425")
        self.assertEqual(last["l"], "26838.425")
        self.assertEqual(last["c"], "26838.425")

        # Continuous 1-minute tick stitches normally
        next_bar = _roll_mt5_index_bars(monday_bars, "2026-11-23T20:37:00Z", D("26842.25"), decimal_text)
        self.assertEqual(next_bar[-1]["o"], "26838.425")
        self.assertEqual(next_bar[-1]["c"], "26842.25")

    def test_forensic_2_3_4_and_trader_integration(self) -> None:
        # 2a. Structural SL & let_winners_run scaling
        std_p = _default_protection_params("NAS100", D("0.50"), let_winners_run=False)
        dhg_p = _default_protection_params("NAS100", D("0.8333"), let_winners_run=True)
        self.assertEqual(std_p["trail_distance"], D("7.20"))
        self.assertEqual(dhg_p["trail_distance"], D("21.00"))
        self.assertEqual(dhg_p["sl_distance"], D("60.00"))
        self.assertEqual(dhg_p["tp_distance"], D("132.00"))

        # 2b. Spike filter on M1 ATR
        spike_plus_normal = [
            {"h": "26840.00", "l": "26800.00"},
            {"h": "26845.00", "l": "26805.00"},
            {"h": "26835.00", "l": "26795.00"},
            {"h": "26845.88", "l": "25224.64"},  # bogus 1621-pt cold-start candle skipped
        ]
        atr = _compute_live_candle_atr(spike_plus_normal)
        self.assertEqual(atr, D("40.00"))

        # 4a. US pre-close chop helper
        self.assertTrue(_is_us_equity_pre_close_chop(datetime(2026, 11, 23, 20, 38, 0, tzinfo=timezone.utc)))
        self.assertFalse(_is_us_equity_pre_close_chop(datetime(2026, 11, 23, 21, 5, 0, tzinfo=timezone.utc)))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clock = _MutableClock(datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc))
            calls = [0]
            dhg = DemoHighGrowthProfile(enabled=True)
            trader, emu_l, emu_h, ob_runner, live_prices = _build_trader_harness(
                root, clock=clock, call_counter=calls, demo_high_growth=dhg, with_option_b=True
            )
            self.addCleanup(trader.close)

            def _sync_quotes() -> None:
                emu_h.publish_market()
                emu_l.publish_market()

            # Feed strong upward ticks + live M1 bars so ATR noise floor widens NAS100 SL to 100.00
            m1_bars = [
                {"t": f"2026-11-23T17:{50 + idx:02d}:00Z", "o": "26800.00", "h": "26840.00", "l": "26800.00", "c": "26835.00"}
                for idx in range(5)
            ]
            for px in ("26800.00", "26815.00", "26830.00"):
                bid = D(px)
                ask = bid + D("2.00")
                live_prices["NAS100"] = (bid, ask)
                emu_l.set_quote("NAS100", bid, ask)
                emu_h.set_quote("NAS100", bid, ask)
                clock.advance(2)
                _sync_quotes()
                rep = trader.run_cycle(
                    mt5_quotes={"NAS100": (bid, ask)},
                    index_stream={"markets": [{"pair": "NAS100", "bid": str(bid), "ask": str(ask), "candles_m1": m1_bars}]},
                )
            self.assertEqual(rep["action"], "OPEN_BUY")
            self.assertEqual(rep["symbol"], "NAS100")
            entry_approx = D("26832.00")
            self.assertEqual(abs(entry_approx - D(rep["stop_loss"])), D("102.00"))
            snap_st = trader.status_snapshot()
            self.assertNotIn("demo_high_growth_profile", snap_st)
            self.assertLessEqual(int(snap_st["aggression_dial"]["effective_risk_bps"]), 100)
            self.assertTrue(trader.demo_high_growth_snapshot()["enabled"])
            self.assertIsNotNone(ob_runner)
            self.assertGreaterEqual(len(ob_runner.snapshot()["open_positions"]), 1)

            # Forensic 3: Simulate broker SL close on NAS100 -> opposite-side SELL whipsaw blocked for 15 min
            live_prices["NAS100"] = (D("26748.00"), D("26750.00"))
            emu_l.set_quote("NAS100", D("26748.00"), D("26750.00"))
            emu_h.set_quote("NAS100", D("26748.00"), D("26750.00"))
            emu_l._positions.clear()
            clock.advance(5)
            _sync_quotes()
            trader._router.venues[BROKER_LHFX_MT5].probe()
            trader.evaluate_fast_protection(quotes={"NAS100": (D("26748.00"), D("26750.00"))}, now=clock())

            for px in ("26748.00", "26735.00", "26720.00", "26700.00"):
                bid = D(px)
                ask = bid + D("2.00")
                live_prices["NAS100"] = (bid, ask)
                emu_l.set_quote("NAS100", bid, ask)
                emu_h.set_quote("NAS100", bid, ask)
                clock.advance(2)
                _sync_quotes()
                rep_cd = trader.run_cycle(
                    mt5_quotes={"NAS100": (bid, ask)},
                    index_stream={"markets": [{"pair": "NAS100", "bid": str(bid), "ask": str(ask), "candles_m1": m1_bars}]},
                )
            self.assertEqual(rep_cd["action"], "WAIT")
            self.assertIn("DEMO_POST_LOSS_COOLDOWN", rep_cd["reason"])

            # Other symbol US30 is not blocked
            calls_before = calls[0]
            for px in ("49000.00", "49020.00", "49045.00"):
                bid = D(px)
                ask = bid + D("4.00")
                live_prices["US30"] = (bid, ask)
                emu_l.set_quote("US30", bid, ask)
                emu_h.set_quote("US30", bid, ask)
                clock.advance(2)
                _sync_quotes()
                rep_us30 = trader.run_cycle(mt5_quotes={"US30": (bid, ask)})
            self.assertEqual(rep_us30["action"], "OPEN_BUY")
            self.assertEqual(rep_us30["symbol"], "US30")
            self.assertEqual(calls[0], calls_before + 1)

            # Advance past 15-min cooldown and close US30 -> now enter Wall Street pre-close chop 20:38 UTC
            clock.now = datetime(2026, 11, 23, 20, 38, 0, tzinfo=timezone.utc)
            emu_l._positions.clear()
            _sync_quotes()
            trader._router.venues[BROKER_LHFX_MT5].probe()
            trader.evaluate_fast_protection(quotes={"US30": (D("49070.00"), D("49074.00"))}, now=clock())
            for px in ("26710.00", "26730.00", "26755.00"):
                bid = D(px)
                ask = bid + D("2.00")
                live_prices["NAS100"] = (bid, ask)
                emu_l.set_quote("NAS100", bid, ask)
                emu_h.set_quote("NAS100", bid, ask)
                clock.advance(2)
                _sync_quotes()
                rep_chop = trader.run_cycle(mt5_quotes={"NAS100": (bid, ask)})
            self.assertEqual(rep_chop["action"], "WAIT")
            self.assertIn("DEMO_US_CLOSE_CHOP_GUARD", rep_chop["reason"])

    def test_cockpit_http_sse_lifecycle_live_lock_keepalive_403_and_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store_path = root / "demo_high_growth_profile.json"
            dhg_store = DemoHighGrowthProfileStore(store_path, execution_mode="DEMO")
            gate = load_default_forex_valve_gate()
            ob = OptionBPaperDemoRunner(db_path=root / "ob.sqlite3", valve_gate=gate)
            ob.ingest_spot_quote("NAS100", D("26800.00"), D("26802.00"))
            tiers = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=gate)
            comp = CompoundingAndMilestoneController(root / "comp.sqlite3", starting_principal_usd=D("5000.00"))

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=lambda: {"execution_mode": "DEMO", "live_trading_armed": False},
                option_b_demo=ob,
                parallel_tiers=tiers,
                compounding_controller=comp,
                demo_high_growth_store=dhg_store,
            )
            srv.start()
            self.addCleanup(srv.stop)
            owner_tok = srv.auth_headers()["Authorization"].split(" ", 1)[1]
            srv_port = int(urllib.parse.urlsplit(srv.base_url).port or 0)

            def _req(method: str, path: str, token: str | None, body_obj: dict | None = None, conn: http.client.HTTPConnection | None = None):
                body = json.dumps(body_obj).encode("utf-8") if body_obj is not None else b""
                hdrs = {"Host": f"127.0.0.1:{srv_port}"}
                if body_obj is not None:
                    hdrs["Content-Type"] = "application/json"
                    hdrs["Content-Length"] = str(len(body))
                if token is not None:
                    hdrs["Authorization"] = f"Bearer {token}"
                c = conn or http.client.HTTPConnection("127.0.0.1", srv_port, timeout=5)
                try:
                    c.request(method, path, body=body if body_obj is not None else None, headers=hdrs)
                    resp = c.getresponse()
                    raw = resp.read().decode("utf-8")
                    return resp.status, json.loads(raw)
                finally:
                    if conn is None:
                        c.close()

            st_unauth, _ = _req("GET", "/api/demo-high-growth-profile", None)
            self.assertEqual(st_unauth, 401)

            st_get, doc_get = _req("GET", "/api/demo-high-growth-profile", owner_tok)
            self.assertEqual(st_get, 200)
            self.assertEqual(doc_get["schema"], DEMO_HIGH_GROWTH_SCHEMA)
            self.assertFalse(doc_get["enabled"])
            self.assertFalse(doc_get["live_mode_blocked"])
            self.assertTrue(doc_get["owner_controls_allowed"])

            # Enable via owner POST -> propagates to Option B, Parallel Tiers, Compounding
            st_on, doc_on = _req("POST", "/api/demo-high-growth-profile", owner_tok, {"enabled": True})
            self.assertEqual(st_on, 200)
            self.assertTrue(doc_on["enabled"])
            self.assertEqual(ob.default_risk_pct, D("10.00"))
            self.assertEqual(ob.max_stop_loss_risk_pct, D("12.00"))
            self.assertEqual(comp.snapshot()["mode"], "FULL_COMPOUND_100")

            # POST /api/option-b-demo mirror_signal without explicit risk_pct uses default 10%
            st_mir, doc_mir = _req("POST", "/api/option-b-demo", owner_tok, {
                "action": "MIRROR_SIGNAL",
                "symbol": "NAS100",
                "side": "BUY",
                "stop_distance_points": "60.00",
                "take_profit_points": "132.00",
            })
            self.assertEqual(st_mir, 200)
            self.assertTrue(doc_mir["result"]["executed"])

            # Persistence across reload
            reloaded = DemoHighGrowthProfileStore(store_path, execution_mode="DEMO")
            self.assertTrue(reloaded.profile().enabled)
            self.assertEqual(reloaded.profile().post_loss_cooldown_seconds, 900)

            # Paired read-only token: 5 consecutive keep-alive POST 403s on single persistent HTTPConnection
            _, pc = _req("POST", "/api/pair-code", owner_tok, {})
            _, ex = _req("POST", "/api/pair-exchange", None, {"pair_code": pc["pair_code"], "device_label": "pr43-ro"})
            dev_tok = str(ex["session_token"])
            keep_conn = http.client.HTTPConnection("127.0.0.1", srv_port, timeout=5)
            self.addCleanup(keep_conn.close)
            for _ in range(5):
                st_403, d_403 = _req("POST", "/api/demo-high-growth-profile", dev_tok, {"enabled": False}, conn=keep_conn)
                self.assertEqual(st_403, 403)
                self.assertEqual(d_403.get("required_scope"), "OWNER_FULL_CONTROL")

            # SSE emits demo_high_growth_profile event
            sse_conn = http.client.HTTPConnection("127.0.0.1", srv_port, timeout=5)
            self.addCleanup(sse_conn.close)
            sse_conn.request("GET", "/api/market-events", headers={"Host": f"127.0.0.1:{srv_port}", "Authorization": f"Bearer {owner_tok}"})
            sse_resp = sse_conn.getresponse()
            self.assertEqual(sse_resp.status, 200)
            seen_dhg_evt = False
            for _ in range(60):
                line = sse_resp.readline().decode("utf-8", errors="replace")
                if "event: demo_high_growth_profile" in line:
                    seen_dhg_evt = True
                    break
            self.assertTrue(seen_dhg_evt)

            # Fail-closed LIVE cockpit refuses enable with HTTP 403
            live_store = DemoHighGrowthProfileStore(root / "live_dhg.json", execution_mode="LIVE", live_trading_armed=True)
            live_srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=lambda: {"execution_mode": "LIVE", "live_trading_armed": True},
                demo_high_growth_store=live_store,
            )
            live_srv.start()
            self.addCleanup(live_srv.stop)
            live_tok = live_srv.auth_headers()["Authorization"].split(" ", 1)[1]
            live_port = int(urllib.parse.urlsplit(live_srv.base_url).port or 0)
            lc = http.client.HTTPConnection("127.0.0.1", live_port, timeout=5)
            self.addCleanup(lc.close)
            body = json.dumps({"enabled": True}).encode("utf-8")
            lc.request(
                "POST",
                "/api/demo-high-growth-profile",
                body=body,
                headers={
                    "Host": f"127.0.0.1:{live_port}",
                    "Authorization": f"Bearer {live_tok}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            l_resp = lc.getresponse()
            l_doc = json.loads(l_resp.read().decode("utf-8"))
            self.assertEqual(l_resp.status, 403)
            self.assertEqual(l_doc.get("code"), DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE)
            self.assertFalse(live_store.profile().enabled)


if __name__ == "__main__":
    unittest.main()
