"""PR #40 tests: conservative 10-dp ROUND_CEILING drawdown_pct quantization across compounding & Phase 8."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import threading
import unittest

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.compounding_controller import (
    CompoundingAndMilestoneController,
    CompoundingControllerError,
)
from cas_forex_revamp.valve.aggression_dial import AggressionDialStore
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    compute_drawdown_pct,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
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
T0 = datetime(2026, 11, 23, 11, 20, 0, tzinfo=timezone.utc)


def _fixture_str(slot: str) -> str:
    return f"pr40-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-4000001-001", equity: str = "100000.00") -> None:
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


class Pr40DrawdownQuantizationGuardTests(unittest.TestCase):
    def test_40_digit_repeating_drawdown_passes_compounding_and_phase8_while_preserving_10pct_ceiling(self) -> None:
        # Exact live equity ratio producing a 40-digit repeating Decimal (0.1132% drawdown)
        dd = compute_drawdown_pct(D("197671.91"), D("197896.00"))
        self.assertGreater(abs(dd.as_tuple().exponent), 12)

        with tempfile.TemporaryDirectory() as td:
            ctrl = CompoundingAndMilestoneController(
                Path(td) / "compounding.sqlite3",
                starting_principal_usd=D("197478.59"),
            )
            ok_budget = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=D("197671.91"),
                risk_pct=D("0.95"),
                drawdown_pct=dd,
            )
            self.assertTrue(ok_budget.allowed)
            self.assertEqual(ok_budget.reason_code, "APPROVED")

            # Conservative ROUND_CEILING ensures near-10% repeating drawdown rounds UP to 0.1000000000 and is DENIED!
            near_ceiling = D("0.099999999999999")
            denied = ctrl.compute_compounding_sizing_budget(
                current_equity_usd=D("178106.40"),
                risk_pct=D("0.95"),
                drawdown_pct=near_ceiling,
            )
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.reason_code, "CONSTITUTIONAL_DRAWDOWN_LIMIT_REACHED")

            # Invalid inputs still fail closed with CompoundingControllerError
            for bad in (D("-0.0001"), 0.01, True, D("NaN"), D("1e18")):
                with self.assertRaises(CompoundingControllerError):
                    ctrl.compute_compounding_sizing_budget(
                        current_equity_usd=D("197671.91"),
                        risk_pct=D("0.95"),
                        drawdown_pct=bad,  # type: ignore[arg-type]
                    )

    def test_autonomous_trader_opens_lhfx_nas100_with_phase8_compounding_when_drawdown_is_repeating_decimal(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=1002903,
                quotes={"NAS100": (D("25928.49"), D("25929.76"))},
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
                    "NAS100": (D("25928.49"), D("25929.76")),
                    "US30": (D("49164.00"), D("49168.00")),
                    "SPX500": (D("7115.20"), D("7115.90")),
                    "XAUUSD": (D("3621.55"), D("3621.93")),
                },
                balance=D("97671.91"),
                clock=clock,
            )
            emu_l.publish_market()

            peak_store = PeakEquityStore(root / "peak.sqlite3")
            # Peak $197,896.00 vs live $197,671.91 -> 40-digit repeating 0.001132362453... drawdown!
            peak_store.observe_equity(
                "dual-shield-barbell:g0:online:LHFX_MT5+OANDA_PRACTICE",
                current_equity=D("197896.00"),
                opening_balance=D("197896.00"),
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
                "CAS_FOREX_INDEX_CONTRACT_SIZE": "100",
                "CAS_FOREX_INDEX_LEVERAGE": "200",
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}

            def idx_ref(syms: tuple[str, ...]) -> dict[str, dict[str, object]]:
                return {
                    s: {
                        "bid": D("26060.00"),
                        "ask": D("26062.50"),
                        "source_provider": "PUBLIC_US_INDEX_FEED",
                        "source_broker_id": None,
                        "is_independent_public": True,
                        "observed_at": clock().isoformat().replace("+00:00", "Z"),
                    }
                    for s in syms
                    if s == "NAS100"
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
                    "reason": f"ID=0{ref} LHFX NAS100 open cleared with quantized drawdown",
                    "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
                }
                return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 45}}).encode("utf-8")

            state_dir = root / "trader_state"
            state_dir.mkdir(parents=True, exist_ok=True)
            reg = FrontierModelRegistry(environ=env, clock=clock, http_post=open_choice_http, resolve_dns=lambda _h: None)
            quota = DailyQuotaGovernanceStore(state_dir / "quota.sqlite3")
            dial = AggressionDialStore(state_dir / "aggression_dial.sqlite3", scope_id="dual-shield-barbell")
            exec_gate = DurableModelExecutionGate(db_path=state_dir / "model_gate.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=quota,
                peak_equity_store=peak_store,
                execution_gate=exec_gate,
                aggression_dial=dial,
                state_dir=state_dir,
                initial_capital_usd=D("197478.59"),
                fast_tick_ms=50,
                clock=clock,
            )
            try:
                self.assertIsNotNone(trader.compounding_controller)
                self.assertIsNotNone(trader.phase8_bridge)
                out = {}
                for delta in (D("0.00"), D("6.00"), D("14.00")):
                    b = D("25928.49") + delta
                    a = b + D("1.27")
                    emu_l.set_quote("NAS100", b, a)
                    emu_l.publish_market()
                    out = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")

                # Must NOT raise CompoundingControllerError; both dial context and NAS100 open succeed!
                dial_ctx = trader.dial_context_summary()
                self.assertEqual(dial_ctx["drawdown_pct"], "0.0011323625")
                self.assertEqual(out["action"], "OPEN_BUY")
                self.assertEqual(out["symbol"], "NAS100")
                self.assertEqual(len(router.venues[BROKER_LHFX_MT5].positions), 1)
            finally:
                self.assertTrue(trader.close())
            _assert_no_eventbus_threads_alive(self)


if __name__ == "__main__":
    unittest.main()
