"""PR #41 tests: AI inference cooldown, UTC daily-cap pause, decoupled 50ms loop, and HTTP 403 POST body drain."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import http.client
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    DEFAULT_LIVE_AI_INFERENCE_COOLDOWN_SECONDS,
)
from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    _run_fast_tick_iteration,
)
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.compounding_controller import CompoundingAndMilestoneController
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
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
T0 = datetime(2026, 11, 23, 23, 57, 0, tzinfo=timezone.utc)


def _fixture_str(slot: str) -> str:
    return f"pr41-fixture-{slot}"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int | float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-4100001-001", equity: str = "100000.00") -> None:
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


def _build_dual_shield_trader(
    root: Path,
    *,
    clock: _MutableClock,
    http_post: object,
    ai_inference_cooldown_seconds: float,
    max_calls_per_day: int = 5000,
) -> tuple[AutonomousAiTrader, Mt5SpoolPaperTerminalEmulator, DualShieldBrokerRouter]:
    emu_h = Mt5SpoolPaperTerminalEmulator(
        root / "hugosway_mt5",
        server="Hugosway-Demo",
        login=1002903,
        quotes={"NAS100": (D("25900.00"), D("25902.00")), "US30": (D("49000.00"), D("49004.00"))},
        balance=D("0.00"),
        connected=False,
        clock=clock,
    )
    emu_h.publish_market()
    emu_l = Mt5SpoolPaperTerminalEmulator(
        root / "lhfx_mt5",
        server="LHFXSA-Trade",
        login=122590,
        quotes={"NAS100": (D("25900.00"), D("25902.00")), "US30": (D("49000.00"), D("49004.00"))},
        balance=D("97478.59"),
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
        "CAS_FOREX_INDEX_CONTRACT_SIZE": "100",
        "CAS_FOREX_INDEX_LEVERAGE": "200",
    }
    emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}

    def idx_ref(syms: tuple[str, ...]) -> dict[str, dict[str, object]]:
        prices = {
            "NAS100": (D("25900.00"), D("25902.00")),
            "US30": (D("49000.00"), D("49004.00")),
        }
        return {
            s: {
                "bid": prices[s][0],
                "ask": prices[s][1],
                "source_provider": "PUBLIC_US_INDEX_FEED",
                "source_broker_id": None,
                "is_independent_public": True,
                "observed_at": clock().isoformat().replace("+00:00", "Z"),
            }
            for s in syms
            if s in prices
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
    reg = FrontierModelRegistry(environ=env, clock=clock, http_post=http_post, resolve_dns=lambda _h: None)
    quota = DailyQuotaGovernanceStore(state_dir / "quota.sqlite3")
    exec_gate = DurableModelExecutionGate(
        db_path=state_dir / "model_gate.sqlite3",
        max_calls_per_day=max_calls_per_day,
        clock=clock,
    )
    trader = AutonomousAiTrader(
        router=router,
        model_registry=reg,
        valve_gate=gate,
        quota_store=quota,
        peak_equity_store=peak_store,
        execution_gate=exec_gate,
        state_dir=state_dir,
        initial_capital_usd=D("197478.59"),
        fast_tick_ms=50,
        ai_inference_cooldown_seconds=ai_inference_cooldown_seconds,
        clock=clock,
    )
    return trader, emu_h, emu_l, router


def _wait_choice_http(call_counter: list[int]):
    def _post(_url: str, _hdrs: object, body: bytes, *_args: object) -> tuple[int, bytes]:
        call_counter[0] += 1
        body_doc = json.loads(body.decode("utf-8"))
        user_doc = json.loads(body_doc["messages"][0]["content"])
        sel = {
            "request_id": user_doc["request_id"],
            "opportunity_set_id": user_doc["opportunity_set_id"],
            "source_state_id": user_doc["state"]["state_id"],
            "selected_action_ref": None,
            "reason": f"ID=0wait hold WAIT on {call_counter[0]}",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
        }
        return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 32}}).encode("utf-8")
    return _post


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
            "reason": f"ID=0{ref} approved",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
        }
        return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 32}}).encode("utf-8")
    return _post


def _assert_no_eventbus_threads_alive(test: unittest.TestCase) -> None:
    alive = [t for t in threading.enumerate() if t.name.startswith("cas-eventbus-") and t.is_alive()]
    test.assertEqual(alive, [])


class Pr41AiCallPacingAnd403DrainTests(unittest.TestCase):
    def test_per_symbol_ai_inference_cooldown_and_backward_compat(self) -> None:
        clock = _MutableClock(T0)
        calls = [0]
        with tempfile.TemporaryDirectory() as td:
            trader, _emu_h, emu_l, _ = _build_dual_shield_trader(
                Path(td),
                clock=clock,
                http_post=_wait_choice_http(calls),
                ai_inference_cooldown_seconds=DEFAULT_LIVE_AI_INFERENCE_COOLDOWN_SECONDS,
            )
            try:
                # 3 ascending NAS100 ticks -> first setup invokes AI once and returns WAIT
                out1: dict[str, object] = {}
                for delta in (D("0.00"), D("6.00"), D("14.00")):
                    b = D("25900.00") + delta
                    a = b + D("2.00")
                    emu_l.set_quote("NAS100", b, a)
                    emu_l.publish_market()
                    out1 = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                self.assertEqual(calls[0], 1)
                self.assertEqual(out1.get("action"), "WAIT")

                # 5s later: persistent setup is cooled down with 0 extra AI calls and 0 veto increments
                clock.advance(5)
                b4, a4 = D("25922.00"), D("25924.00")
                emu_l.set_quote("NAS100", b4, a4)
                emu_l.publish_market()
                out2 = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b4, a4)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                self.assertEqual(calls[0], 1)
                self.assertEqual(out2.get("action"), "WAIT")
                self.assertIn("AI_INFERENCE_COOLDOWN", str(out2.get("reason")))
                self.assertEqual(trader.status_snapshot()["veto_count"], 0)

                # Advance past 60s cooldown (total 61s): next setup invokes AI again
                clock.advance(56)
                b5, a5 = D("25930.00"), D("25932.00")
                emu_l.set_quote("NAS100", b5, a5)
                emu_l.publish_market()
                trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b5, a5)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                self.assertEqual(calls[0], 2)

                # Invalid cooldown bounds fail closed
                for bad_cd in (-0.1, True, float("nan"), 3601.0):
                    with self.assertRaises(ContractError):
                        AutonomousAiTrader(
                            router=trader._router,
                            model_registry=trader._registry,
                            valve_gate=trader._valve_gate,
                            execution_gate=trader._execution_gate,
                            ai_inference_cooldown_seconds=bad_cd,  # type: ignore[arg-type]
                        )
            finally:
                self.assertTrue(trader.close())

        # Backward compatibility: default 0.0 cooldown preserves immediate back-to-back calls
        clock2 = _MutableClock(T0)
        calls2 = [0]
        with tempfile.TemporaryDirectory() as td2:
            trader2, _emu_h2, emu_l2, _ = _build_dual_shield_trader(
                Path(td2),
                clock=clock2,
                http_post=_wait_choice_http(calls2),
                ai_inference_cooldown_seconds=0.0,
            )
            try:
                for delta in (D("0.00"), D("6.00"), D("14.00")):
                    b = D("25900.00") + delta
                    a = b + D("2.00")
                    emu_l2.set_quote("NAS100", b, a)
                    emu_l2.publish_market()
                    trader2.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                clock2.advance(1)
                emu_l2.set_quote("NAS100", D("25922.00"), D("25924.00"))
                emu_l2.publish_market()
                trader2.run_fast_tick_cycle(
                    mt5_quotes={"NAS100": (D("25922.00"), D("25924.00"))},
                    feed_source="MT5_DIRECT_SPOOL_50MS",
                )
                self.assertEqual(calls2[0], 2)
            finally:
                self.assertTrue(trader2.close())
        _assert_no_eventbus_threads_alive(self)

    def test_daily_call_cap_paused_keeps_50ms_protection_and_resumes_at_utc_midnight(self) -> None:
        clock = _MutableClock(T0)
        calls = [0]
        with tempfile.TemporaryDirectory() as td:
            trader, emu_h, emu_l, router = _build_dual_shield_trader(
                Path(td),
                clock=clock,
                http_post=_open_first_choice_http(calls),
                ai_inference_cooldown_seconds=60.0,
                max_calls_per_day=1,
            )
            try:
                # Call 1/1 on 2026-11-23 opens NAS100 BUY on LHFX_MT5
                for delta in (D("0.00"), D("6.00"), D("14.00")):
                    b = D("25900.00") + delta
                    a = b + D("2.00")
                    emu_l.set_quote("NAS100", b, a)
                    emu_l.publish_market()
                    trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                self.assertEqual(calls[0], 1)
                self.assertEqual(len(router.venues[BROKER_LHFX_MT5].positions), 1)
                open_entry_px = router.venues[BROKER_LHFX_MT5].positions[0].price_open

                # Now seed US30 3-tick impulse -> exhausts 1/day cap -> returns clean AI_DAILY_CALL_CAP_PAUSED WAIT (never raises!)
                clock.advance(2)
                paused_res: dict[str, object] = {}
                for d_us in (D("0.00"), D("10.00"), D("24.00")):
                    bu = D("49000.00") + d_us
                    au = bu + D("4.00")
                    emu_l.set_quote("US30", bu, au)
                    emu_l.publish_market()
                    paused_res = trader.run_fast_tick_cycle(mt5_quotes={"US30": (bu, au)}, feed_source="MT5_DIRECT_SPOOL_50MS")
                self.assertEqual(paused_res.get("action"), "WAIT")
                self.assertIn("AI_DAILY_CALL_CAP_PAUSED", str(paused_res.get("reason")))
                self.assertEqual(calls[0], 1)

                # Subsequent US30 tick on 2026-11-23 does NOT even probe gate (stays cached for the UTC day)
                clock.advance(2)
                emu_l.set_quote("US30", D("49034.00"), D("49038.00"))
                emu_l.publish_market()
                paused2 = trader.run_fast_tick_cycle(
                    mt5_quotes={"US30": (D("49034.00"), D("49038.00"))},
                    feed_source="MT5_DIRECT_SPOOL_50MS",
                )
                self.assertEqual(paused2.get("action"), "WAIT")
                self.assertIn("AI_DAILY_CALL_CAP_PAUSED", str(paused2.get("reason")))

                # Meanwhile 50ms stop protection STILL snaps open NAS100 trade to breakeven!
                b_be = open_entry_px + D("15.00")
                a_be = b_be + D("2.00")
                emu_l.set_quote("NAS100", b_be, a_be)
                emu_l.publish_market()
                prot = trader.evaluate_fast_protection(quotes={"NAS100": (b_be, a_be)})
                self.assertTrue(any(ev.get("stage") == "BREAKEVEN_LOCKED" for ev in prot))
                self.assertGreaterEqual(router.venues[BROKER_LHFX_MT5].positions[0].stop_loss, open_entry_px)

                # Advance clock across 00:00 UTC into 2026-11-24 -> daily cap resets and AI resumes cleanly!
                clock.now = datetime(2026, 11, 24, 0, 0, 5, tzinfo=timezone.utc)
                emu_h.publish_market()
                emu_l.set_quote("US30", D("49048.00"), D("49052.00"))
                emu_l.publish_market()
                resumed = trader.run_fast_tick_cycle(
                    mt5_quotes={"US30": (D("49048.00"), D("49052.00"))},
                    feed_source="MT5_DIRECT_SPOOL_50MS",
                )
                self.assertEqual(calls[0], 2)
                self.assertEqual(resumed.get("action"), "OPEN_BUY")
                self.assertEqual(resumed.get("symbol"), "US30")
            finally:
                self.assertTrue(trader.close())
        _assert_no_eventbus_threads_alive(self)

    def test_run_fast_tick_iteration_decouples_50ms_protection_and_throttles_logs(self) -> None:
        class _TickObj:
            bid = D("25900.00")
            ask = D("25902.00")

        class _StubTransport:
            def symbol_ticks_batch(self, _syms: object) -> tuple[dict[str, object], dict[str, str]]:
                return {"NAS100": _TickObj()}, {}

        class _StubVenue:
            connected = True
            account = object()
            _transport = _StubTransport()

        class _StubRouter:
            venues = {"LHFX_MT5": _StubVenue()}

        class _StubTrader:
            def __init__(self) -> None:
                self._inference_lock = threading.RLock()
                self.has_open = True
                self.fast_cycles = 0
                self.prot_calls = 0
                self.raise_err = False

            def has_open_positions_fast(self) -> bool:
                return self.has_open

            def run_fast_tick_cycle(self, *, mt5_quotes: object) -> dict[str, object]:
                self.fast_cycles += 1
                if self.raise_err:
                    raise RuntimeError("transient test error")
                return {"action": "WAIT"}

            def evaluate_fast_protection(self, *, quotes: object) -> list[object]:
                self.prot_calls += 1
                return []

        class _StubTiers:
            def __init__(self) -> None:
                self.ticks = 0

            def process_tick(self, **_kw: object) -> None:
                self.ticks += 1

        fake_mono = [100.0]
        logged: list[str] = []
        router = _StubRouter()
        trader = _StubTrader()
        tiers = _StubTiers()
        stream_lock = threading.Lock()
        latest_mt5: list[dict[str, object] | None] = [None]
        poll_cache: dict[str, dict[str, object]] = {}
        poll_log: dict[tuple[str, str, str], tuple[float, int]] = {}
        fast_state: dict[str, object] = {}

        # With has_open=True: 10 rapid 50ms ticks -> 1 entry cycle + 9 pure 50ms protection ticks
        for i in range(10):
            fake_mono[0] = 100.0 + (i * 0.05)
            _run_fast_tick_iteration(
                router=router,
                trader=trader,
                parallel_tiers=tiers,
                stream_lock=stream_lock,
                latest_mt5_index_stream=latest_mt5,
                fast_poll_cache=poll_cache,
                fast_log_throttle=poll_log,
                fast_state=fast_state,
                mono_clock=lambda: fake_mono[0],
                log_fn=logged.append,
            )
        self.assertEqual(trader.fast_cycles, 1)
        self.assertEqual(trader.prot_calls, 9)
        self.assertEqual(tiers.ticks, 9)

        # Advancing >=15s runs second open-position scan
        fake_mono[0] = 115.1
        _run_fast_tick_iteration(
            router=router,
            trader=trader,
            parallel_tiers=tiers,
            stream_lock=stream_lock,
            latest_mt5_index_stream=latest_mt5,
            fast_poll_cache=poll_cache,
            fast_log_throttle=poll_log,
            fast_state=fast_state,
            mono_clock=lambda: fake_mono[0],
            log_fn=logged.append,
        )
        self.assertEqual(trader.fast_cycles, 2)

        # With has_open=False: throttled to 5.0s
        trader.has_open = False
        fake_mono[0] = 122.0  # >5s past 115.1 -> runs scan #3
        _run_fast_tick_iteration(
            router=router,
            trader=trader,
            parallel_tiers=tiers,
            stream_lock=stream_lock,
            latest_mt5_index_stream=latest_mt5,
            fast_poll_cache=poll_cache,
            fast_log_throttle=poll_log,
            fast_state=fast_state,
            mono_clock=lambda: fake_mono[0],
            log_fn=logged.append,
        )
        fake_mono[0] = 124.0  # <5s past 122.0 -> skipped
        _run_fast_tick_iteration(
            router=router,
            trader=trader,
            parallel_tiers=tiers,
            stream_lock=stream_lock,
            latest_mt5_index_stream=latest_mt5,
            fast_poll_cache=poll_cache,
            fast_log_throttle=poll_log,
            fast_state=fast_state,
            mono_clock=lambda: fake_mono[0],
            log_fn=logged.append,
        )
        self.assertEqual(trader.fast_cycles, 3)

        # Repeated errors inside 60s throttle logs cleanly and emit suppressed count after 60s
        trader.raise_err = True
        for t_val in (130.0, 136.0, 142.0, 191.0):
            fake_mono[0] = t_val
            _run_fast_tick_iteration(
                router=router,
                trader=trader,
                parallel_tiers=tiers,
                stream_lock=stream_lock,
                latest_mt5_index_stream=latest_mt5,
                fast_poll_cache=poll_cache,
                fast_log_throttle=poll_log,
                fast_state=fast_state,
                mono_clock=lambda: fake_mono[0],
                log_fn=logged.append,
            )
        self.assertEqual(len(logged), 2)
        self.assertIn("suppressed 2 repeated", logged[1])

    def test_paired_device_post_compounding_drains_body_and_returns_clean_403(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as td:
            ctrl = CompoundingAndMilestoneController(
                Path(td) / "compounding.sqlite3",
                starting_principal_usd=D("300000.00"),
            )
            srv = LoopbackCockpitServer(
                repo_root=repo_root,
                port=0,
                compounding_controller=ctrl,
            )
            srv.start()
            self.addCleanup(srv.stop)
            owner_tok = srv.auth_headers()["Authorization"].split(" ", 1)[1]

            srv_port = int(urllib.parse.urlsplit(srv.base_url).port or 0)

            def _http_post(path: str, token: str | None, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
                body = json.dumps(payload).encode("utf-8")
                hdrs: dict[str, str] = {
                    "Host": f"127.0.0.1:{srv_port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                }
                if token is not None:
                    hdrs["Authorization"] = f"Bearer {token}"
                conn = http.client.HTTPConnection("127.0.0.1", srv_port, timeout=5)
                try:
                    conn.request("POST", path, body=body, headers=hdrs)
                    resp = conn.getresponse()
                    raw_b = resp.read().decode("utf-8")
                    return resp.status, json.loads(raw_b)
                finally:
                    conn.close()

            st_pc, pc = _http_post("/api/pair-code", owner_tok, {})
            self.assertEqual(st_pc, 200)
            st_ex, ex_doc = _http_post(
                "/api/pair-exchange",
                None,
                {"pair_code": pc["pair_code"], "device_label": "pr41-drain-test"},
            )
            self.assertEqual(st_ex, 200)
            dev_tok = str(ex_doc["session_token"])

            # 20 consecutive paired POSTs with JSON body must all cleanly return 403 (0 RemoteDisconnected / TCP RST)
            for _ in range(20):
                st_403, doc_403 = _http_post("/api/compounding", dev_tok, {"mode": "BALANCED_SPLIT_50_50"})
                self.assertEqual(st_403, 403)
                self.assertEqual(doc_403.get("required_scope"), "OWNER_FULL_CONTROL")

            # Transfer-Encoding / oversized Content-Length still fail closed with 403 without reading unbounded body
            with socket.create_connection(("127.0.0.1", srv_port), timeout=5) as sock:
                raw_req = (
                    f"POST /api/compounding HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{srv_port}\r\n"
                    f"Authorization: Bearer {dev_tok}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: 999999\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                sock.sendall(raw_req)
                raw_resp = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw_resp += chunk
                self.assertIn(b"403 Forbidden", raw_resp)


if __name__ == "__main__":
    unittest.main()
