"""Phase 6 verification suite: Autonomous AI Trader, NAS100 & US30 indices,
broker-side resting TP+SL, snap-to-breakeven/trailing stops, $500-$1,000 daily quota lock,
ordered 9-model frontier selector (qwen3:0.6b strictly #9 last), and D:\\MetaTrader5 auto-discovery.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import urllib.parse

from cas_forex_revamp.composition.autonomous_trader import (
    GOVERNANCE_ACTIVE,
    GOVERNANCE_PAUSED_NEW_RISK,
    GOVERNANCE_STOPPED,
    AutonomousAiTrader,
    compute_market_sessions_status,
)
from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    assert_safe_ai_catalog_payload,
    run_cockpit_cli,
    safe_broker_routing_payload,
)
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.operator.frontier_backends import (
    FRONTIER_MODEL_CATALOG,
    FrontierConfigurationError,
    FrontierModelRegistry,
    FrontierTransportError,
    SupervisedOllamaBinding,
    SupervisedOllamaReceiptSigner,
    _RedactedSecret,
    _validate_frontier_https_url,
)
from cas_forex_revamp.operator.model import ActualModelDecisionAdapter, InferenceBudget, SYSTEM_POLICY
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ValveRefusalError,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    DualShieldBrokerRouter,
    QuoteReferenceUnavailableError,
)
from cas_forex_revamp.venue.live_market_stream import (
    EXPANDED_FX_PAIRS,
    EXPANDED_MARKETS,
    INDEX_INSTRUMENTS,
    PublicUsIndexFeedClient,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    BrokerFailoverExhaustedError,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
    normalize_market_symbol,
    resolve_mt5_spool_dir,
)
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient

D = Decimal
T0 = datetime(2026, 11, 17, 14, 0, tzinfo=timezone.utc)
SYNTH_MT5_PASS = "Demo-Pass-9f3K!q"  # synthetic test value, not a real credential
SYNTH_OANDA_TOK = "practice-token-abc123"  # synthetic test value, not a real credential
SYNTH_OANDA_ACCT = "101-001-1234567-001"
SYNTH_API_KEY = "test-placeholder-ant-alpha-01"  # synthetic test value

QUOTES_18: dict[str, tuple[Decimal, Decimal]] = {
    "NAS100": (D("20500.00"), D("20502.50")),
    "US30": (D("43800.00"), D("43804.00")),
    "SPX500": (D("6000.00"), D("6000.50")),
    "XAUUSD": (D("2600.00"), D("2600.60")),
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


class _SeqClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        self.now += timedelta(milliseconds=50)
        return self.now


class _FakeOandaTransport:
    def __init__(self, quotes: dict[str, tuple[Decimal, Decimal]]) -> None:
        self.quotes = dict(quotes)
        self.orders: list[dict] = []

    def __call__(self, method, url, headers, body, timeout, max_bytes):
        if urllib.parse.urlsplit(url).hostname != "api-fxpractice.oanda.com":
            raise RuntimeError("Unexpected non-practice OANDA host")
        if url.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": SYNTH_OANDA_ACCT, "currency": "USD", "balance": "80000", "NAV": "80000",
                    "unrealizedPL": "0", "marginAvailable": "80000", "openPositionCount": 0, "lastTransactionID": "1",
                }
            }).encode()
        if "/pricing?" in url:
            insts = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["instruments"][0].split(",")
            prices = []
            for inst in insts:
                sym = inst.replace("_", "")
                if sym in self.quotes:
                    bid, ask = self.quotes[sym]
                    prices.append({"instrument": inst, "bids": [{"price": str(bid)}], "asks": [{"price": str(ask)}]})
            return json.dumps({"prices": prices}).encode()
        if method == "POST" and url.endswith("/orders"):
            order = json.loads(body)["order"]
            self.orders.append(order)
            sym = order["instrument"].replace("_", "")
            bid, ask = self.quotes[sym]
            price = ask if not str(order["units"]).startswith("-") else bid
            return json.dumps({
                "orderCreateTransaction": {"id": "10", "clientExtensions": order.get("clientExtensions", {})},
                "orderFillTransaction": {
                    "id": "11",
                    "instrument": order["instrument"],
                    "units": order["units"],
                    "price": str(price),
                    "clientExtensions": order.get("clientExtensions", {}),
                },
                "lastTransactionID": "11",
            }).encode()
        if method == "GET" and url.endswith("/openTrades"):
            trades = []
            for idx, o in enumerate(self.orders, start=1):
                if "instrument" in o:
                    sl_p = (o.get("stopLossOnFill") or {}).get("price")
                    trades.append({
                        "id": str(idx),
                        "instrument": o["instrument"],
                        "currentUnits": str(o["units"]),
                        "price": "1.10010",
                        "unrealizedPL": "0.00",
                        "state": "OPEN",
                        **({"stopLossOrder": {"price": str(sl_p)}} if sl_p else {}),
                    })
            return json.dumps({"trades": trades, "lastTransactionID": "11"}).encode()
        if method == "PUT" and "/trades/" in url and url.endswith("/orders"):
            amend = json.loads(body)
            self.orders.append(amend)
            tid_a = url.split("/")[-2]
            sl_b = amend.get("stopLoss") or {}
            return json.dumps({
                "stopLossOrderTransaction": {
                    "id": "12",
                    "tradeID": tid_a,
                    "price": str(sl_b.get("price", "1.09800")),
                    "clientExtensions": sl_b.get("clientExtensions", {}),
                },
                "lastTransactionID": "12",
            }).encode()
        raise RuntimeError(f"Unexpected OANDA route {method} {url}")


class _Rig:
    def __init__(self, tmp: str) -> None:
        self.root = Path(tmp)
        self.clock = _SeqClock()
        self.emus = {
            BROKER_HUGOSWAY_MT5: Mt5SpoolPaperTerminalEmulator(
                self.root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_18,
                balance=D("12000"),
                leverage=500,
                clock=self.clock,
            ),
            BROKER_LHFX_MT5: Mt5SpoolPaperTerminalEmulator(
                self.root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes=QUOTES_18,
                balance=D("8000"),
                leverage=500,
                clock=self.clock,
            ),
        }
        self.emus[BROKER_HUGOSWAY_MT5].publish_market()
        self.emus[BROKER_LHFX_MT5].publish_market()
        self.oanda = _FakeOandaTransport(QUOTES_18)

    def env(self, **extra: str) -> dict[str, str]:
        out = {
            "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
            "CAS_FOREX_MT5_SPOOL_DIR": str(self.root),
            "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
            "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": SYNTH_MT5_PASS,
            "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
            "CAS_FOREX_OANDA_PRACTICE_TOKEN": SYNTH_OANDA_TOK,
            "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": SYNTH_OANDA_ACCT,
        }
        out.update(extra)
        return out

    def transport_factory(self, broker_id: str, mode: str, root):
        return Mt5SpoolBridgeTransport(
            Path(root) / broker_id.lower(),
            sleep=self.emus[broker_id].sleep_hook,
            poll_interval_seconds=0.01,
            receipt_timeout_seconds=5,
            clock=self.clock,
        )

    def oanda_factory(self, env):
        return OandaPracticePaperClient(environ=env, transport=self.oanda)

    def dual_router(self, gate=None, **extra_kwargs) -> DualShieldBrokerRouter:
        router = DualShieldBrokerRouter(
            environ=self.env(),
            valve_gate=gate or load_default_forex_valve_gate(),
            transport_factory=self.transport_factory,
            oanda_client_factory=self.oanda_factory,
            clock=self.clock,
            **extra_kwargs,
        )
        router.activate_all()
        return router


class _FakeFrontierHttp:
    """Offline mock transport verifying HTTPS endpoints & headers across all 9 model tiers."""

    def __init__(self, *, choice_ref: str = "opt-open-0", probability: str = "0.88") -> None:
        self.calls: list[dict] = []
        self.choice_ref = choice_ref
        self.probability = probability

    def __call__(self, url: str, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int):
        self.calls.append({"url": url, "headers": dict(headers), "body": json.loads(body.decode("utf-8"))})
        selection_json = json.dumps({
            "request_id": self.calls[-1]["body"].get("request_id", "req-1"),
            "opportunity_set_id": "set-1",
            "source_state_id": "state-1",
            "selected_action_ref": self.choice_ref,
            "reason": f"ID=0{self.choice_ref} verified signal",
            "evidence_ids": ["ev-1"],
        })
        if "anthropic.com" in url:
            body_req = self.calls[-1]["body"]
            user_doc = json.loads(body_req["messages"][0]["content"])
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": self.choice_ref,
                "reason": f"ID=0{self.choice_ref} anthropic verified",
                "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]] or ["ev-1"],
            }
            return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 48}}).encode()
        if "generativelanguage.googleapis.com" in url and url.endswith(":decide"):
            req_b = self.calls[-1]["body"]
            if "batch_questions" in req_b:
                decisions = [
                    {"market": q["market"], "choice": f"OPEN_{q['market']}", "probability": self.probability}
                    for q in req_b["batch_questions"]
                ]
                return 200, json.dumps({"decisions": decisions}).encode()
            return 200, json.dumps({"choice": self.choice_ref, "probability": self.probability}).encode()
        if "generativelanguage.googleapis.com" in url:
            user_doc = json.loads(self.calls[-1]["body"]["contents"][0]["parts"][0]["text"])
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": self.choice_ref,
                "reason": f"ID=0{self.choice_ref} gemini verified",
                "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]] or ["ev-1"],
            }
            return 200, json.dumps({
                "candidates": [{"content": {"parts": [{"text": json.dumps(sel)}]}}],
                "usageMetadata": {"candidatesTokenCount": 42},
            }).encode()
        if "openai.com" in url or "deepseek.com" in url:
            user_doc = json.loads(self.calls[-1]["body"]["messages"][1]["content"])
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": self.choice_ref,
                "reason": f"ID=0{self.choice_ref} openai-compatible verified",
                "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]] or ["ev-1"],
            }
            return 200, json.dumps({"choices": [{"message": {"content": json.dumps(sel)}}], "usage": {"completion_tokens": 39}}).encode()
        user_doc = json.loads(self.calls[-1]["body"]["messages"][1]["content"])
        sel = {
            "request_id": user_doc["request_id"],
            "opportunity_set_id": user_doc["opportunity_set_id"],
            "source_state_id": user_doc["state"]["state_id"],
            "selected_action_ref": self.choice_ref,
            "reason": f"ID=0{self.choice_ref} ollama fallback verified",
            "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]] or ["ev-1"],
        }
        sel_json = json.dumps(sel)
        resp_obj: dict = {"message": {"content": sel_json}, "eval_count": 35}
        sup_cb = getattr(self, "ollama_receipt_builder", None)
        if callable(sup_cb):
            resp_obj["cas_supervisor_receipt"] = sup_cb(sel_json)
        return 200, json.dumps(resp_obj).encode()


def _decision_proposal(order: OrderIntent, *, gate, view: dict, reason: str = "Verified signal"):
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=order.limit_price,
        take_profit_price=order.take_profit_price,
        target_id=order.position_ticket,
    )
    request = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=T0, valid_until=T0 + timedelta(minutes=5)),
    )
    selection = SimpleNamespace(evidence_ids=("ev-1",), reason=reason, selected_action_ref=order.action_ref)
    prop = SimpleNamespace(request=request, result=SimpleNamespace(selection=selection), intent=intent)
    pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "500000"}
    return gate.require_admissible(prop, current_view=view, policy=pol, now=T0 + timedelta(seconds=1))


class AutonomousAiTraderAndMarketsTests(unittest.TestCase):
    def test_18_markets_us_indices_oracle_and_oanda_cfd_block(self) -> None:
        self.assertEqual(len(EXPANDED_FX_PAIRS), 16)
        self.assertEqual(INDEX_INSTRUMENTS, ("NAS100", "US30", "SPX500", "XAUUSD"))
        self.assertEqual(len(EXPANDED_MARKETS), 20)
        self.assertEqual(normalize_market_symbol("US500.pro"), "SPX500")
        self.assertEqual(normalize_market_symbol("GOLD.ecn"), "XAUUSD")
        self.assertEqual(normalize_market_symbol("USTEC.pro"), "NAS100")
        self.assertEqual(normalize_market_symbol("US100"), "NAS100")
        self.assertEqual(normalize_market_symbol("NAS100USD"), "NAS100")
        self.assertEqual(normalize_market_symbol("DJ30.ecn"), "US30")
        self.assertEqual(normalize_market_symbol("WS30"), "US30")
        self.assertEqual(normalize_market_symbol("US30USD"), "US30")

        yahoo_payloads = {
            "NDX": json.dumps({
                "chart": {
                    "result": [{
                        "meta": {"regularMarketPrice": 20501.25},
                        "timestamp": [int(T0.timestamp()) - 60, int(T0.timestamp())],
                        "indicators": {"quote": [{"open": [20495.0, 20499.0], "high": [20502.0, 20505.0],
                                                  "low": [20494.0, 20498.0], "close": [20499.0, 20501.25], "volume": [12, 18]}]},
                    }]
                }
            }).encode(),
            "DJI": json.dumps({
                "chart": {
                    "result": [{
                        "meta": {"regularMarketPrice": 43802.00},
                        "timestamp": [int(T0.timestamp()) - 60, int(T0.timestamp())],
                        "indicators": {"quote": [{"open": [43790.0, 43798.0], "high": [43805.0, 43810.0],
                                                  "low": [43788.0, 43795.0], "close": [43798.0, 43802.0], "volume": [10, 15]}]},
                    }]
                }
            }).encode(),
            "GSPC": json.dumps({
                "chart": {
                    "result": [{
                        "meta": {"regularMarketPrice": 6000.25},
                        "timestamp": [int(T0.timestamp()) - 60, int(T0.timestamp())],
                        "indicators": {"quote": [{"open": [5995.0, 5998.0], "high": [6002.0, 6004.0],
                                                  "low": [5994.0, 5997.0], "close": [5998.0, 6000.25], "volume": [8, 12]}]},
                    }]
                }
            }).encode(),
            "GOLD": json.dumps({
                "chart": {
                    "result": [{
                        "meta": {"regularMarketPrice": 2600.30},
                        "timestamp": [int(T0.timestamp()) - 60, int(T0.timestamp())],
                        "indicators": {"quote": [{"open": [2598.0, 2599.0], "high": [2601.0, 2602.0],
                                                  "low": [2597.0, 2598.5], "close": [2599.0, 2600.30], "volume": [9, 11]}]},
                    }]
                }
            }).encode(),
        }

        def fake_index_get(url: str, timeout: float, max_bytes: int) -> bytes:
            if "NDX" in url or "NQ" in url:
                return yahoo_payloads["NDX"]
            if "DJI" in url or "YM" in url:
                return yahoo_payloads["DJI"]
            if "GSPC" in url or "ES=F" in url:
                return yahoo_payloads["GSPC"]
            return yahoo_payloads["GOLD"]

        idx_client = PublicUsIndexFeedClient(transport=fake_index_get, clock=lambda: T0)
        idx_env = idx_client.fetch_index_stream(sequence=4)
        self.assertEqual(idx_env["schema"], "cas-forex.index-stream/1")
        self.assertEqual([m["pair"] for m in idx_env["markets"]], ["NAS100", "US30", "SPX500", "XAUUSD"])

        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.dual_router(
                gate=gate,
                index_reference_source=lambda syms: {
                    s: {
                        "bid": QUOTES_18[s][0],
                        "ask": QUOTES_18[s][1],
                        "source_provider": "TEST_PUBLIC_INDEX",
                        "source_broker_id": None,
                        "is_independent_public": True,
                        "observed_at": T0.isoformat().replace("+00:00", "Z"),
                    }
                    for s in syms
                    if s in QUOTES_18
                },
            )
            oracle = router.oracle()
            verdicts = oracle.verify_cross_venue_index_quotes(
                symbol="NAS100",
                hugo_quote=QUOTES_18["NAS100"],
                lhfx_quote=(D("20500.50"), D("20503.00")),
                reference_quote=(D("20500.25"), D("20502.75")),
            )
            self.assertEqual(len(verdicts), 2)
            with self.assertRaises(ContractError):
                oracle.verify_cross_venue_index_quotes(
                    symbol="NAS100",
                    hugo_quote=(D("20750.00"), D("20753.00")),
                    lhfx_quote=QUOTES_18["NAS100"],
                    reference_quote=QUOTES_18["NAS100"],
                )

            # Force both MT5 index quotes off-market so router would look at safe harbor; US OANDA must fail closed on CFDs.
            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("NAS100", D("21200.00"), D("21204.00"))
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            rig.emus[BROKER_LHFX_MT5].set_quote("NAS100", D("21200.00"), D("21204.00"))
            rig.emus[BROKER_LHFX_MT5].publish_market()
            idx_order = OrderIntent(
                order_id="idx-us-block", action_ref="act-idx-block", kind=ActionKind.OPEN,
                symbol="NAS100", quantity_units=D("1"), side=Side.BUY,
                stop_price=D("20475.00"), take_profit_price=D("20560.00"),
            )
            view = {"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"}
            dec = _decision_proposal(idx_order, gate=gate, view=view)
            with self.assertRaises(BrokerFailoverExhaustedError) as ctx_blk:
                router.execute_open(idx_order, valve_decision=dec)
            self.assertIn("restricts index CFDs", str(ctx_blk.exception))

    def test_resting_take_profit_sl_valve_enforcement_and_broker_persistence(self) -> None:
        gate = load_default_forex_valve_gate()
        view = {"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"}

        with self.assertRaises(ContractError):
            OrderIntent(
                order_id="bad-tp-buy", action_ref="act-bad-tp-b", kind=ActionKind.OPEN,
                symbol="NAS100", quantity_units=D("1"), side=Side.BUY,
                stop_price=D("20470.00"), limit_price=D("20502.50"), take_profit_price=D("20480.00"),
            )
        with self.assertRaises(ContractError):
            OrderIntent(
                order_id="bad-tp-sell", action_ref="act-bad-tp-s", kind=ActionKind.OPEN,
                symbol="US30", quantity_units=D("1"), side=Side.SELL,
                stop_price=D("43860.00"), limit_price=D("43800.00"), take_profit_price=D("43830.00"),
            )

        bad_buy = SimpleNamespace(
            order_id="bad-tp-buy", action_ref="act-bad-tp-b", kind=ActionKind.OPEN,
            symbol="NAS100", quantity_units=D("1"), side=Side.BUY,
            stop_price=D("20470.00"), limit_price=D("20502.50"), take_profit_price=D("20480.00"),
            position_ticket=None,
        )
        with self.assertRaises(ValveRefusalError) as ctx_b:
            _decision_proposal(bad_buy, gate=gate, view=view)
        self.assertIn("INVERTED_BUY_TAKE_PROFIT", str(ctx_b.exception))

        bad_sell = SimpleNamespace(
            order_id="bad-tp-sell", action_ref="act-bad-tp-s", kind=ActionKind.OPEN,
            symbol="US30", quantity_units=D("1"), side=Side.SELL,
            stop_price=D("43860.00"), limit_price=D("43800.00"), take_profit_price=D("43830.00"),
            position_ticket=None,
        )
        with self.assertRaises(ValveRefusalError) as ctx_s:
            _decision_proposal(bad_sell, gate=gate, view=view)
        self.assertIn("INVERTED_SELL_TAKE_PROFIT", str(ctx_s.exception))

        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.dual_router(gate=gate)
            ok_buy = OrderIntent(
                order_id="good-tp-nas", action_ref="act-good-nas", kind=ActionKind.OPEN,
                symbol="NAS100", quantity_units=D("1"), side=Side.BUY,
                stop_price=D("20475.00"), take_profit_price=D("20560.00"),
            )
            dec = _decision_proposal(ok_buy, gate=gate, view=view)
            res = router.execute_open(ok_buy, valve_decision=dec)
            self.assertEqual(res.executed_on, BROKER_HUGOSWAY_MT5)
            pos = res.result.positions_after[0]
            self.assertEqual(pos.symbol, "NAS100")
            self.assertEqual(pos.stop_loss, D("20475.00"))
            self.assertEqual(pos.take_profit, D("20560.00"))

    def test_fast_tick_50ms_burst_snap_to_breakeven_and_monotonic_trail(self) -> None:
        gate = load_default_forex_valve_gate()
        http_mock = _FakeFrontierHttp(choice_ref="act-auto-buy")
        with tempfile.TemporaryDirectory() as tmp:
            rig = _Rig(tmp)
            router = rig.dual_router(gate=gate)
            env = rig.env(CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY)
            reg = FrontierModelRegistry(environ=env, clock=rig.clock, http_post=http_mock, resolve_dns=lambda _h: None)
            quota = DailyQuotaGovernanceStore(path=Path(tmp) / "quota.sqlite3")

            # Use Deterministic/Actual mock HTTP backend: ensure choice_ref matches the single offered ActionOption ref.
            def open_choice_http(url, headers, body, timeout, max_bytes):
                body_doc = json.loads(body.decode("utf-8"))
                user_doc = json.loads(body_doc["messages"][0]["content"])
                ref = user_doc["options"][0]["action_ref"]
                sel = {
                    "request_id": user_doc["request_id"],
                    "opportunity_set_id": user_doc["opportunity_set_id"],
                    "source_state_id": user_doc["state"]["state_id"],
                    "selected_action_ref": ref,
                    "reason": f"ID=0{ref} 50ms NAS100 momentum burst verified",
                    "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]],
                }
                return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 45}}).encode()

            reg = FrontierModelRegistry(environ=env, clock=rig.clock, http_post=open_choice_http, resolve_dns=lambda _h: None)
            exec_gate = DurableModelExecutionGate(db_path=Path(tmp) / "model_gate.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=quota,
                execution_gate=exec_gate,
                fast_tick_ms=50,
                clock=rig.clock,
            )

            # Seed 3 ascending 50ms NAS100 ticks creating a clean upward burst (> 3x spread).
            for delta in (D("0.00"), D("6.00"), D("14.00")):
                b = QUOTES_18["NAS100"][0] + delta
                a = QUOTES_18["NAS100"][1] + delta
                rig.emus[BROKER_HUGOSWAY_MT5].set_quote("NAS100", b, a)
                rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
                rig.emus[BROKER_LHFX_MT5].set_quote("NAS100", b, a)
                rig.emus[BROKER_LHFX_MT5].publish_market()
                out = trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (b, a)}, feed_source="MT5_DIRECT_SPOOL_50MS")

            self.assertEqual(out["action"], "OPEN_BUY")
            self.assertEqual(out["symbol"], "NAS100")
            pos_list = router.venues[BROKER_HUGOSWAY_MT5].positions
            self.assertEqual(len(pos_list), 1)
            entry_pos = pos_list[0]
            self.assertIsNotNone(entry_pos.stop_loss)
            self.assertIsNotNone(entry_pos.take_profit)
            self.assertGreater(entry_pos.take_profit, entry_pos.price_open)

            # Slow 15s public feed must never trigger 50ms micro-scalp entries.
            m_gate_slow = DurableModelExecutionGate(Path(tmp) / 'm_gate_slow.sqlite3')
            trader_slow = AutonomousAiTrader(router=router, model_registry=reg, valve_gate=gate, quota_store=quota, execution_gate=m_gate_slow, fast_tick_ms=50, clock=rig.clock)
            slow_res = trader_slow.run_fast_tick_cycle(mt5_quotes={"US30": QUOTES_18["US30"]}, feed_source="PUBLIC_15S_POLL")
            self.assertEqual(slow_res["action"], "VETOED")

            # Advance NAS100 +15 pts on both MT5 feeds -> instant deterministic Snap-to-Breakeven (no AI latency Wait).
            b_be = entry_pos.price_open + D("15.00")
            a_be = b_be + D("2.50")
            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("NAS100", b_be, a_be)
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            rig.emus[BROKER_LHFX_MT5].set_quote("NAS100", b_be, a_be)
            rig.emus[BROKER_LHFX_MT5].publish_market()
            be_events = trader.evaluate_fast_protection(quotes={"NAS100": (b_be, a_be)})
            self.assertTrue(any(ev["stage"] == "BREAKEVEN_LOCKED" for ev in be_events))
            pos_be = router.venues[BROKER_HUGOSWAY_MT5].positions[0]
            self.assertGreaterEqual(pos_be.stop_loss, entry_pos.price_open)

            # Advance NAS100 +35 pts on both MT5 feeds -> monotonic Trailing Stop, then pull back -6 pts -> SL must NEVER widen!
            b_tr = entry_pos.price_open + D("35.00")
            a_tr = b_tr + D("2.50")
            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("NAS100", b_tr, a_tr)
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            rig.emus[BROKER_LHFX_MT5].set_quote("NAS100", b_tr, a_tr)
            rig.emus[BROKER_LHFX_MT5].publish_market()
            tr_events = trader.evaluate_fast_protection(quotes={"NAS100": (b_tr, a_tr)})
            self.assertTrue(any(ev["stage"] == "TRAILING_ACTIVE" for ev in tr_events))
            sl_after_trail = router.venues[BROKER_HUGOSWAY_MT5].positions[0].stop_loss

            b_pb = entry_pos.price_open + D("29.00")
            a_pb = b_pb + D("2.50")
            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("NAS100", b_pb, a_pb)
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            rig.emus[BROKER_LHFX_MT5].set_quote("NAS100", b_pb, a_pb)
            rig.emus[BROKER_LHFX_MT5].publish_market()
            pb_events = trader.evaluate_fast_protection(quotes={"NAS100": (b_pb, a_pb)})
            self.assertEqual(pb_events, [])
            self.assertEqual(router.venues[BROKER_HUGOSWAY_MT5].positions[0].stop_loss, sl_after_trail)

    def test_daily_quota_soft_hard_lock_pct_mode_and_loss_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = DailyQuotaGovernanceStore(
                path=Path(tmp) / "quota.sqlite3",
                soft_quota_usd=D("500"),
                hard_quota_usd=D("1000"),
                max_loss_usd=D("500"),
                max_consecutive_losses=3,
            )
            store.observe_day_start(D("20000"), now=T0)
            ok, reason, mult = store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertTrue(ok)
            self.assertEqual(mult, D("1"))

            # Soft quota $500 -> halves risk multiplier to 0.50.
            snap_soft = store.record_realized_trade(D("520"), symbol="NAS100", ticket="101", starting_equity=D("20000"), now=T0)
            self.assertEqual(snap_soft["status"], "SOFT_QUOTA_REACHED")
            self.assertEqual(snap_soft["risk_multiplier"], "0.5")
            ok_soft, _, mult_soft = store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertTrue(ok_soft)
            self.assertEqual(mult_soft, D("0.5"))

            # Hard quota $1,000 -> vetoes OPEN/ADD while keeping CLOSE & AMEND_STOP open.
            snap_hard = store.record_realized_trade(D("510"), symbol="US30", ticket="102", starting_equity=D("20000"), now=T0)
            self.assertEqual(snap_hard["status"], "DAILY_QUOTA_LOCKED")
            ok_open, rsn_open, _ = store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertFalse(ok_open)
            self.assertIn("DAILY_QUOTA_LOCKED", rsn_open)
            ok_close, _, _ = store.evaluate_new_risk(ActionKind.CLOSE, now=T0)
            self.assertTrue(ok_close)
            ok_amend, _, _ = store.evaluate_new_risk(ActionKind.AMEND_STOP, now=T0)
            self.assertTrue(ok_amend)

            # Next NY 17:00 rollover resets cleanly, and consecutive loss circuit trips on 3 straight losses.
            next_day = T0 + timedelta(days=1)
            ok_next, _, mult_next = store.evaluate_new_risk(ActionKind.OPEN, now=next_day, starting_equity=D("21030"))
            self.assertTrue(ok_next)
            self.assertEqual(mult_next, D("1"))
            for idx in range(3):
                snap_loss = store.record_realized_trade(D("-100"), symbol="EURUSD", ticket=f"L-{idx}", now=next_day)
            self.assertEqual(snap_loss["status"], "DAILY_LOSS_CIRCUIT_TRIPPED")
            ok_tripped, rsn_tripped, _ = store.evaluate_new_risk(ActionKind.OPEN, now=next_day)
            self.assertFalse(ok_tripped)
            self.assertIn("CIRCUIT", rsn_tripped)
            rec_v = OwnerRecoveryVerifier(db_path=Path(tmp) / 'quota.sqlite3', clock=lambda: next_day)
            tok = rec_v.mint_token(action_scope='UNLOCK_QUOTA_SESSION', now=next_day)
            unlocked = store.unlock_session(owner_request_id="owner-req-1", reason="Overseer verified", recovery_verifier=rec_v, recovery_token=tok, now=next_day)
            self.assertEqual(unlocked["status"], "OPEN")

            # Percentage compounding mode test (e.g. 5% of $20,000 = $1,000 target).
            pct_store = DailyQuotaGovernanceStore(
                path=Path(tmp) / "quota_pct.sqlite3",
                quota_mode="PCT",
                daily_quota_pct=D("0.05"),
            )
            pct_store.observe_day_start(D("20000"), now=T0)
            snap_pct = pct_store.record_realized_trade(D("1050"), symbol="NAS100", ticket="P-1", starting_equity=D("20000"), now=T0)
            self.assertEqual(snap_pct["status"], "DAILY_QUOTA_LOCKED")

    def test_9_model_frontier_catalog_qwen_last_and_gemini_decision_1(self) -> None:
        self.assertEqual(len(SYSTEM_POLICY.encode("utf-8")), 928)
        expected_order = [
            "claude-fable-5.2",
            "claude-fable",
            "claude-5.5",
            "gemini-decision-1",
            "gemini-carbon",
            "gemini-argon",
            "openai-astra",
            "deepseek-flash-1017",
            "qwen3:0.6b",
        ]
        self.assertEqual([e.model_id for e in FRONTIER_MODEL_CATALOG], expected_order)
        self.assertEqual(FRONTIER_MODEL_CATALOG[-1].rank, 9)
        self.assertTrue(FRONTIER_MODEL_CATALOG[-1].is_fallback)

        fake_http = _FakeFrontierHttp(choice_ref="opt-0", probability="0.91")
        env = {
            "CAS_FOREX_ANTHROPIC_API_KEY": SYNTH_API_KEY,
            "CAS_FOREX_GEMINI_API_KEY": "test-placeholder-gem-alpha-01",
            "CAS_FOREX_OPENAI_API_KEY": "test-placeholder-oai-alpha-01",
            "CAS_FOREX_DEEPSEEK_API_KEY": "test-placeholder-ds-alpha-01",
            "CAS_FOREX_OLLAMA_FALLBACK_ENABLED": "1",
        }
        import os
        from hashlib import sha256 as _sha256

        sup_signer = SupervisedOllamaReceiptSigner(
            algorithm="Ed25519",
            signing_key=bytes(range(10, 42)),
            pid=os.getpid(),
            start_time="p6-ollama-start-1",
        )
        sup_binding = SupervisedOllamaBinding(
            pid=os.getpid(),
            start_time="p6-ollama-start-1",
            executable_sha256="a" * 64,
            model_manifest_sha256="b" * 64,
            weights_sha256="c" * 64,
            template_sha256="d" * 64,
            tokenizer_sha256="e" * 64,
            endpoint_url="http://127.0.0.1:21435/api/chat",
            auth_secret="p6-sup-token-" + ("z" * 32),
            receipt_verify_key=sup_signer.public_verify_key(),
            receipt_algorithm="Ed25519",
            process_verifier=lambda _b: True,
            artifact_verifier=lambda _b: True,
            listener_ownership_verifier=lambda _b: True,
        )
        reg = FrontierModelRegistry(
            environ=env,
            clock=lambda: T0,
            http_post=fake_http,
            ollama_http_post=fake_http,
            resolve_dns=lambda _h: None,
            supervised_ollama=sup_binding,
        )
        snap = assert_safe_ai_catalog_payload(reg.catalog_snapshot())
        self.assertEqual([m["model_id"] for m in snap["models"]], expected_order)
        self.assertEqual(snap["active_model_id"], "claude-fable-5.2")
        self.assertNotIn(SYNTH_API_KEY, json.dumps(snap))

        secret = _RedactedSecret(SYNTH_API_KEY)
        self.assertNotIn(SYNTH_API_KEY, repr(secret))
        self.assertNotIn(SYNTH_API_KEY, str(secret))

        scout = reg.scout_opportunities([
            {"market": "NAS100", "spread_ok": True},
            {"market": "US30", "spread_ok": True},
        ])
        self.assertTrue(scout["executed"])
        self.assertTrue(scout["wake_heavy_model"])
        self.assertEqual(scout["best_market"], "NAS100")

        # Exercise Decision invocation on Anthropic, Gemini Decision 1 (:decide), OpenAI, and Qwen #9 fallback.
        from cas_forex_revamp.contracts import (
            ActionIntent,
            ActionOption,
            DecisionFact,
            DecisionOrigin,
            DecisionRequest,
            EvidenceKind,
            EvidenceReference,
            RunScope,
            StateReference,
            canonical_bytes,
            content_digest,
        )

        scope = RunScope("acct-1", "run-1", 1, "b1", "p1", "s1", "adapter-test")
        st = StateReference("st-1", scope, 1, T0, T0 + timedelta(seconds=30), 1)
        ai_intent = ActionIntent(
            intent_id="ai-ord-1",
            scope=scope,
            decision_id="dec-ai-ord-1",
            opportunity_id="opp-ai-ord-1",
            action_ref="opt-0",
            kind=ActionKind.OPEN,
            origin=DecisionOrigin.ACTUAL_MODEL,
            instrument_id="NAS100",
            source_state=st,
            created_at=T0,
            expires_at=T0 + timedelta(seconds=30),
            quantity=D("1"),
            side=Side.BUY,
            limit_price=D("20502.50"),
            stop_price=D("20475.00"),
            take_profit_price=D("20560.00"),
        )
        ev_id = "ev-1"
        fact_obj = {"sym": "NAS100", "bid": "20500.00", "ask": "20502.50"}
        fact_bytes = canonical_bytes(fact_obj)
        req = DecisionRequest(
            request_id="req-model-check",
            opportunity_set_id="set-model-check",
            state=st,
            options=(ActionOption("opt-0", "burst", "50ms", "BUY NAS100", ai_intent),),
            facts=(DecisionFact("f-1", "quote", fact_bytes.decode("utf-8"), (ev_id,)),),
            evidence=(EvidenceReference(ev_id, EvidenceKind.OBSERVATION, "test", content_digest(fact_obj), T0),),
        )
        budget = InferenceBudget(max_calls=1, max_input_tokens_per_call=16_384, max_generated_tokens_per_call=256, max_seconds_per_call=10, max_total_seconds=10)
        for mid in ("claude-fable-5.2", "gemini-decision-1", "openai-astra", "qwen3:0.6b"):
            spec, backend, verifier = reg.build_backend(mid)
            if mid == "qwen3:0.6b":
                from cas_forex_revamp.operator.model import ModelInvocation

                expected_inv = ModelInvocation(
                    content_digest(req),
                    spec,
                    "session-" + content_digest(("isolated", req.request_id, 0)),
                    SYSTEM_POLICY,
                    canonical_bytes(req).decode("utf-8"),
                    budget,
                )
                exp_inv_sha = content_digest(expected_inv)
                fake_http.ollama_receipt_builder = lambda sel_text, _sha=exp_inv_sha, _sp=spec: sup_signer.sign_receipt(
                    receipt_id="rcpt-ollama-p6-1",
                    invocation_sha256=_sha,
                    model_id=_sp.model_id,
                    artifact_sha256=_sp.artifact_sha256,
                    response_sha256=_sha256(sel_text.encode("utf-8")).hexdigest(),
                )
            out = ActualModelDecisionAdapter(
                adapter_id=f"test-{mid}",
                model=spec,
                budget=budget,
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=lambda _: None,
                clock=lambda: T0,
            ).decide(req)
            self.assertEqual(out.selection.selected_action_ref, "opt-0")

        # Non-443 / HTTP / host-mismatch URLs fail closed.
        with self.assertRaises((FrontierConfigurationError, FrontierTransportError)):
            _validate_frontier_https_url("http://api.anthropic.com/v1/messages", expected_host="api.anthropic.com")
        with self.assertRaises((FrontierConfigurationError, FrontierTransportError)):
            _validate_frontier_https_url("https://evil.example/v1/messages", expected_host="api.anthropic.com")

    def test_windows_d_metatrader5_spool_auto_discovery_and_cockpit_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_default = Path(tmp) / "MetaTrader5" / "cas_forex_spool"
            fake_default.mkdir(parents=True)
            self.assertIsNone(resolve_mt5_spool_dir({}, is_windows=True, default_dir=fake_default))
            self.assertEqual(
                resolve_mt5_spool_dir({"CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234"}, is_windows=True, default_dir=fake_default),
                str(fake_default),
            )
            self.assertIsNone(resolve_mt5_spool_dir({"CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234"}, is_windows=False, default_dir=fake_default))
            self.assertEqual(
                resolve_mt5_spool_dir({"CAS_FOREX_MT5_SPOOL_DIR": tmp, "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234"}, is_windows=True, default_dir=fake_default),
                tmp,
            )

            rig = _Rig(tmp)
            router = rig.dual_router()
            gate = load_default_forex_valve_gate()
            reg = FrontierModelRegistry(environ=rig.env(CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY), http_post=_FakeFrontierHttp(), resolve_dns=lambda _h: None)
            quota = DailyQuotaGovernanceStore(path=Path(tmp) / "quota.sqlite3")
            m_gate_w = DurableModelExecutionGate(Path(tmp) / 'm_gate_win.sqlite3')
            trader = AutonomousAiTrader(router=router, model_registry=reg, valve_gate=gate, quota_store=quota, execution_gate=m_gate_w)

            srv = LoopbackCockpitServer(
                repo_root=Path(__file__).resolve().parents[2],
                host="127.0.0.1",
                port=0,
                broker_router_reader=router.routing_snapshot,
                ai_model_registry=reg,
                autonomous_trader=trader,
                index_stream_reader=lambda: {
                    "schema": "cas-forex.index-stream/1",
                    "sequence": 1,
                    "observed_at": "2026-11-17T14:00:00Z",
                    "instruments": ["NAS100", "US30"],
                    "markets": [],
                },
            )
            srv.start()
            try:
                tok = srv.auth_token
                conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
                conn.request("GET", "/api/ai-models")
                r_unauth = conn.getresponse()
                r_unauth.read()
                self.assertEqual(r_unauth.status, 401)

                headers = {"Authorization": f"Bearer {tok}"}
                conn.request("GET", "/api/ai-models", headers=headers)
                models_doc = json.loads(conn.getresponse().read().decode("utf-8"))
                self.assertEqual(models_doc["models"][-1]["model_id"], "qwen3:0.6b")

                conn.request("POST", "/api/select-ai-model", body=json.dumps({"model_id": "gemini-decision-1", "fast_scout_enabled": True}), headers={**headers, "Content-Type": "application/json"})
                sel_doc = json.loads(conn.getresponse().read().decode("utf-8"))
                self.assertEqual(sel_doc["active_model_id"], "gemini-decision-1")
                self.assertTrue(sel_doc["fast_scout_enabled"])

                conn.request("POST", "/api/ai-overseer-action", body=json.dumps({"action": "PAUSE_NEW_RISK"}), headers={**headers, "Content-Type": "application/json"})
                pause_doc = json.loads(conn.getresponse().read().decode("utf-8"))
                self.assertEqual(pause_doc["governance_mode"], GOVERNANCE_PAUSED_NEW_RISK)

                conn.request("POST", "/api/ai-overseer-action", body=json.dumps({"action": "RESUME_AUTONOMOUS"}), headers={**headers, "Content-Type": "application/json"})
                res_doc = json.loads(conn.getresponse().read().decode("utf-8"))
                self.assertEqual(res_doc["governance_mode"], GOVERNANCE_ACTIVE)

                conn.request("GET", "/api/index-stream", headers=headers)
                idx_doc = json.loads(conn.getresponse().read().decode("utf-8"))
                self.assertEqual(idx_doc["schema"], "cas-forex.index-stream/1")
            finally:
                srv.stop()

        cli_rc = run_cockpit_cli(["--print-check-only"], environ={}, repo_root=Path(__file__).resolve().parents[2])
        self.assertEqual(cli_rc, 0)

    def test_pr11_exclusive_port_bind_mt5_index_seed_and_gemini_404_fallback_and_scout_degraded(self) -> None:
        # 1. _ExclusiveThreadingHTTPServer blocks duplicate port hijack immediately.
        srv1 = LoopbackCockpitServer(repo_root=Path(__file__).resolve().parents[2], host="127.0.0.1", port=0)
        srv1.start()
        try:
            srv2 = LoopbackCockpitServer(repo_root=Path(__file__).resolve().parents[2], host="127.0.0.1", port=srv1.bound_port)
            with self.assertRaises(OSError):
                srv2.start()
            c = http.client.HTTPConnection("127.0.0.1", srv1.bound_port, timeout=5)
            try:
                c.request("GET", "/api/health", headers=srv1.auth_headers())
                r = c.getresponse()
                self.assertEqual(r.status, 200)
                self.assertTrue(json.loads(r.read().decode("utf-8"))["authenticated"])
            finally:
                c.close()
        finally:
            srv1.stop()

        # 2. Gemini Decision 1 HTTP 404 on :decide falls back to ("gemini-2.5-flash", "gemini-3.8-flash"),
        #    memoizes _decide_404 so :decide is not re-requested, and if scout fails, AutonomousAiTrader marks SCOUT_DEGRADED.
        seen_urls: list[str] = []

        def scout_404_then_flash_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            seen_urls.append(url)
            if url.endswith(":decide") or "gemini-2.5-flash:generateContent" in url:
                return 404, b'{"error":"not found"}'
            if "gemini-3.8-flash:generateContent" in url:
                return 200, json.dumps({
                    "candidates": [{"content": {"parts": [{"text": json.dumps({"decisions": [{"market": "NAS100", "choice": "OPEN_BUY", "probability": "0.86"}]})}]}}],
                    "usageMetadata": {"candidatesTokenCount": 24},
                }).encode("utf-8")
            user_doc = json.loads(json.loads(body.decode("utf-8"))["messages"][0]["content"])
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": None,
                "reason": "ID=0wait_after_scout",
                "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]] or ["ev-1"],
            }
            return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 32}}).encode("utf-8")

        reg_fb = FrontierModelRegistry(
            environ={"CAS_FOREX_GEMINI_API_KEY": "test-placeholder-gem-alpha-01"},
            clock=lambda: T0,
            http_post=scout_404_then_flash_http,
            resolve_dns=lambda _h: None,
        )
        fb_out = reg_fb.scout_opportunities([{"market": "NAS100", "choices": ["WAIT", "opt-1"]}])
        self.assertTrue(fb_out["executed"])
        self.assertEqual(fb_out["best_market"], "NAS100")
        self.assertTrue(any("gemini-2.5-flash:generateContent" in u for u in seen_urls))
        self.assertTrue(any("gemini-3.8-flash:generateContent" in u for u in seen_urls))
        fb_out2 = reg_fb.scout_opportunities([{"market": "NAS100", "choices": ["WAIT", "opt-1"]}])
        self.assertTrue(fb_out2["executed"])
        self.assertEqual(sum(1 for u in seen_urls if u.endswith(":decide")), 1)
        g_spec, g_back, g_ver = reg_fb.build_backend("gemini-decision-1")
        from cas_forex_revamp.contracts import ActionIntent, ActionOption, DecisionFact, DecisionOrigin, DecisionRequest, EvidenceKind, EvidenceReference, RunScope, StateReference, canonical_bytes, content_digest
        g_scope = RunScope("acct-g", "run-g", 1, "b1", "p1", "s1", "adapter-g")
        g_st = StateReference("st-g", g_scope, 1, T0, T0 + timedelta(seconds=30), 1)
        g_intent = ActionIntent(intent_id="g-ord-1", scope=g_scope, decision_id="dec-g1", opportunity_id="opp-g1", action_ref="opt-g", kind=ActionKind.OPEN, origin=DecisionOrigin.ACTUAL_MODEL, instrument_id="NAS100", source_state=g_st, created_at=T0, expires_at=T0 + timedelta(seconds=30), quantity=D("1"), side=Side.BUY, limit_price=D("20502.50"), stop_price=D("20475.00"), take_profit_price=D("20560.00"))
        g_fact = {"sym": "NAS100"}
        g_req = DecisionRequest(request_id="req-g1", opportunity_set_id="set-g1", state=g_st, options=(ActionOption("opt-g", "wait", "50ms", "WAIT", g_intent),), facts=(DecisionFact("fg1", "q", canonical_bytes(g_fact).decode("utf-8"), ("ev-g1",)),), evidence=(EvidenceReference("ev-g1", EvidenceKind.OBSERVATION, "test", content_digest(g_fact), T0),))
        g2_urls: list[str] = []
        class _FakeGen404:
            def __call__(self, u, h, b, t, m):
                g2_urls.append(u)
                if u.endswith(":decide"):
                    raise FrontierTransportError("frontier AI HTTP status 404")
                ud = json.loads(json.loads(b.decode("utf-8"))["contents"][0]["parts"][0]["text"])
                if "candidates" in ud:
                    payload = {"decisions": [{"market": "EURUSD", "choice": "OPEN LONG", "probability": "0.88"}]}
                    return 200, json.dumps({"candidates": [{"content": {"parts": [{"text": json.dumps(payload)}]}}], "usageMetadata": {"candidatesTokenCount": 16}}).encode("utf-8")
                return 200, json.dumps({"candidates": [{"content": {"parts": [{"text": json.dumps({"request_id": ud["request_id"], "opportunity_set_id": ud["opportunity_set_id"], "source_state_id": ud["state"]["state_id"], "selected_action_ref": None, "reason": "ID=0wait_flash", "evidence_ids": ["ev-g1"]})}]}}], "usageMetadata": {"candidatesTokenCount": 20}}).encode("utf-8")
        reg_g2 = FrontierModelRegistry(environ={"CAS_FOREX_GEMINI_API_KEY": "test-placeholder-gem-alpha-01"}, clock=lambda: T0, http_post=_FakeGen404(), resolve_dns=lambda _h: None)
        scout_exc_out = reg_g2.scout_opportunities([{"market": "EURUSD", "choice": "OPEN LONG", "question": "q"}])
        self.assertTrue(scout_exc_out["executed"])
        self.assertEqual(scout_exc_out["best_market"], "EURUSD")
        self.assertEqual([d["market"] for d in scout_exc_out["decisions"] if d["admitted"]], ["EURUSD"])
        self.assertTrue(any("gemini-2.5-flash:generateContent" in u for u in g2_urls))
        gs2, gb2, gv2 = reg_g2.build_backend("gemini-decision-1")
        g_res = ActualModelDecisionAdapter(adapter_id="test-g404", model=gs2, budget=InferenceBudget(max_calls=1, max_input_tokens_per_call=16_384, max_generated_tokens_per_call=512, max_seconds_per_call=10, max_total_seconds=10), backend=gb2, receipt_verifier=gv2, execution_gate=lambda _: None, clock=lambda: T0).decide(g_req)
        self.assertIsNone(g_res.selection.selected_action_ref)
        g_req2 = DecisionRequest(request_id="req-g2", opportunity_set_id="set-g2", state=g_st, options=(ActionOption("opt-g", "wait", "50ms", "WAIT", g_intent),), facts=(DecisionFact("fg1", "q", canonical_bytes(g_fact).decode("utf-8"), ("ev-g1",)),), evidence=(EvidenceReference("ev-g1", EvidenceKind.OBSERVATION, "test", content_digest(g_fact), T0),))
        ActualModelDecisionAdapter(adapter_id="test-g404-2", model=gs2, budget=InferenceBudget(max_calls=1, max_input_tokens_per_call=16_384, max_generated_tokens_per_call=512, max_seconds_per_call=10, max_total_seconds=10), backend=gb2, receipt_verifier=gv2, execution_gate=lambda _: None, clock=lambda: T0).decide(g_req2)
        self.assertEqual(sum(1 for u in g2_urls if u.endswith(":decide")), 2)

        def scout_503_primary_ok_http(url: str, headers: dict, body: bytes, timeout: float, max_bytes: int):
            if "generativelanguage.googleapis.com" in url:
                return 503, b'{"error":"unavailable"}'
            req_b = json.loads(body.decode("utf-8"))
            self.assertEqual(req_b["thinking"], {"type": "adaptive"})
            self.assertEqual(req_b["output_config"], {"effort": "low"})
            self.assertNotIn("temperature", req_b)
            user_doc = json.loads(req_b["messages"][0]["content"])
            sel = {
                "request_id": user_doc["request_id"],
                "opportunity_set_id": user_doc["opportunity_set_id"],
                "source_state_id": user_doc["state"]["state_id"],
                "selected_action_ref": None,
                "reason": "ID=0wait_primary_ok",
                "evidence_ids": [e["evidence_id"] for e in user_doc["evidence"][:1]] or ["ev-1"],
            }
            return 200, json.dumps({"content": [{"type": "text", "text": json.dumps(sel)}], "usage": {"output_tokens": 28}}).encode("utf-8")

        with tempfile.TemporaryDirectory() as tmp2:
            from cas_forex_revamp.composition.live_cockpit_server import _build_mt5_index_snapshot_from_router

            rig2 = _Rig(tmp2)
            router2 = rig2.dual_router()
            idx_snap, mt5_q = _build_mt5_index_snapshot_from_router(router2)
            self.assertIsNotNone(idx_snap)
            self.assertEqual(idx_snap["feed_mode"], "MT5_DIRECT_SPOOL_50MS")
            self.assertEqual([m["pair"] for m in idx_snap["markets"]], ["NAS100", "US30", "SPX500", "XAUUSD"])
            self.assertIn("NAS100", mt5_q)
            self.assertGreaterEqual(len(idx_snap["markets"][0]["candles_m1"]), 1)
            self.assertGreaterEqual(len(idx_snap["markets"][0]["candles_m5"]), 1)
            self.assertGreaterEqual(len(idx_snap["markets"][0]["candles_h1"]), 1)
            idx_snap2, _ = _build_mt5_index_snapshot_from_router(router2, prev_stream=idx_snap)
            self.assertEqual(idx_snap2["sequence"], 2)
            self.assertGreaterEqual(len(idx_snap2["markets"][0]["candles_m5"]), 1)

            gate2 = load_default_forex_valve_gate()
            reg_res = FrontierModelRegistry(
                environ=rig2.env(
                    CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY,
                    CAS_FOREX_GEMINI_API_KEY="test-placeholder-gem-alpha-01",
                    CAS_FOREX_GEMINI_DECISION_SCOUT="true",
                ),
                clock=lambda: T0,
                http_post=scout_503_primary_ok_http,
                resolve_dns=lambda _h: None,
            )
            trader2 = AutonomousAiTrader(
                router=router2,
                model_registry=reg_res,
                valve_gate=gate2,
                quota_store=DailyQuotaGovernanceStore(path=Path(tmp2) / "q2.sqlite3"),
                execution_gate=DurableModelExecutionGate(Path(tmp2) / "g2.sqlite3"),
                clock=lambda: T0,
            )
            quotes = dict(QUOTES_18)
            for dlt in (D("0"), D("6"), D("14")):
                trader2._tick_history["NAS100"].append((quotes["NAS100"][0] + dlt, quotes["NAS100"][1] + dlt))
            cyc = trader2.run_fast_tick_cycle(mt5_quotes={"NAS100": (quotes["NAS100"][0] + D("14"), quotes["NAS100"][1] + D("14"))}, now=T0)
            self.assertEqual(cyc["action"], "WAIT")
            snap_t = trader2.status_snapshot()
            self.assertIn("SCOUT_DEGRADED", trader2._last_scout["reason"])
            cat_res = reg_res.catalog_snapshot()
            self.assertEqual(cat_res["models"][3]["last_status"], "SCOUT_DEGRADED")
            self.assertEqual(cat_res["models"][0]["calls"], 1)
            self.assertEqual(snap_t["cycle_count"], 1)


    def test_phase7_xauusd_100oz_contract_token_file_and_pwa_manifest(self) -> None:
        from cas_forex_revamp.venue.mt5_broker_bridge import Mt5MarginCalculator, MT5_GOLD_CONTRACT_SIZE

        calc = Mt5MarginCalculator(leverage=500, index_leverage=200)
        self.assertEqual(calc.contract_size_for("XAUUSD"), MT5_GOLD_CONTRACT_SIZE)
        self.assertEqual(calc.units_to_lots(D("1"), symbol="XAUUSD"), D("0.01"))
        with tempfile.TemporaryDirectory() as td3:
            tok_path = Path(td3) / "cockpit.token"
            srv_p7 = LoopbackCockpitServer(
                repo_root=Path(__file__).resolve().parents[2],
                token_file=tok_path,
                public_origin="https://52-33-1-177.sslip.io",
            )
            srv_p7.start()
            try:
                tok1 = srv_p7.auth_token
                self.assertEqual(tok_path.read_text(encoding="utf-8").strip(), tok1)
                c = http.client.HTTPConnection("127.0.0.1", srv_p7.bound_port, timeout=5)
                try:
                    c.request("GET", "/ui/manifest.webmanifest", headers={"Host": "52-33-1-177.sslip.io"})
                    rm = c.getresponse()
                    raw_mf = rm.read()
                    self.assertEqual(rm.status, 200)
                    self.assertEqual(json.loads(raw_mf.decode("utf-8"))["short_name"], "CAS Forex")
                finally:
                    c.close()
            finally:
                srv_p7.stop()

            srv_p7_b = LoopbackCockpitServer(repo_root=Path(__file__).resolve().parents[2], token_file=tok_path)
            srv_p7_b.start()
            try:
                self.assertNotEqual(srv_p7_b.auth_token, tok1)
                self.assertEqual(tok_path.read_text(encoding="utf-8").strip(), srv_p7_b.auth_token)
            finally:
                srv_p7_b.stop()


    def test_pr13_market_sessions_working_focus_and_explainer_ask(self) -> None:
        # Wednesday 14:45 UTC: Forex 24/5 OPEN, London & NY & Overlap OPEN, Wall Street Cash OPEN
        wed_cash = datetime(2026, 11, 18, 14, 45, tzinfo=timezone.utc)
        s_cash = compute_market_sessions_status(wed_cash, mt5_tick_fresh=True)
        self.assertTrue(s_cash["forex_24_5_open"])
        self.assertEqual(s_cash["forex_label"], "FOREX 24/5 OPEN")
        self.assertEqual(s_cash["us_indices_status"], "CASH_OPEN")
        by_id = {row["id"]: row for row in s_cash["sessions"]}
        self.assertTrue(by_id["london"]["open"])
        self.assertTrue(by_id["new_york"]["open"])
        self.assertTrue(by_id["london_ny_overlap"]["open"])
        self.assertFalse(by_id["tokyo"]["open"])

        # Daily break 21:30 UTC
        wed_break = datetime(2026, 11, 18, 21, 30, tzinfo=timezone.utc)
        self.assertEqual(compute_market_sessions_status(wed_break)["us_indices_status"], "DAILY_BREAK")

        # Saturday 15:00 UTC: Weekend Closed
        sat = datetime(2026, 11, 21, 15, 0, tzinfo=timezone.utc)
        s_sat = compute_market_sessions_status(sat)
        self.assertFalse(s_sat["forex_24_5_open"])
        self.assertEqual(s_sat["us_indices_status"], "WEEKEND_CLOSED")
        self.assertTrue(all(not row["open"] for row in s_sat["sessions"]))

        def fake_explainer_post(url, headers, body, timeout, max_bytes):
            return 200, json.dumps({
                "content": [{"type": "text", "text": json.dumps({"answer": "Read-only summary verified for NAS100."})}],
                "usage": {"output_tokens": 12},
            }).encode("utf-8")

        reg_e = FrontierModelRegistry(
            environ={"CAS_FOREX_ANTHROPIC_API_KEY": SYNTH_API_KEY},
            clock=lambda: wed_cash,
            http_post=fake_explainer_post,
            resolve_dns=lambda _h: None,
        )
        ans_doc = reg_e.answer_explainer_question(
            question="Which market is active right now?",
            context_summary={"current_focus_status": "IN TRADE: NAS100 (BUY)", "execution_mode": "DEMO"},
        )
        self.assertEqual(ans_doc["read_only"], True)
        self.assertEqual(ans_doc["source"], "FRONTIER_READ_ONLY")
        self.assertIn("NAS100", ans_doc["answer"])

        srv_e = LoopbackCockpitServer(
            repo_root=Path(__file__).resolve().parents[2],
            ai_model_registry=reg_e,
        )
        srv_e.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv_e.bound_port, timeout=5)
            try:
                body_b = json.dumps({"question": "What session is open?"}).encode("utf-8")
                c.request("POST", "/api/explainer-ask", body=body_b, headers={"Host": f"127.0.0.1:{srv_e.bound_port}", "Content-Type": "application/json"})
                self.assertEqual(c.getresponse().status, 401)
                c.request(
                    "POST",
                    "/api/explainer-ask",
                    body=body_b,
                    headers={
                        "Host": f"127.0.0.1:{srv_e.bound_port}",
                        "Origin": f"http://127.0.0.1:{srv_e.bound_port}",
                        "Authorization": f"Bearer {srv_e.auth_token}",
                        "Content-Type": "application/json",
                    },
                )
                r_ok = c.getresponse()
                raw_ok = json.loads(r_ok.read().decode("utf-8"))
                self.assertEqual(r_ok.status, 200)
                self.assertEqual(raw_ok["schema"], "cas-forex.explainer-answer/1")
                self.assertTrue(raw_ok["read_only"])
            finally:
                c.close()
        finally:
            srv_e.stop()


if __name__ == "__main__":
    unittest.main()
