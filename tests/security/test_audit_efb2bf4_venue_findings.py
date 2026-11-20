"""Independent security regression tests for audit_efb2bf4_report6.md Findings [1], [3], [4], [5], [6], [7], [9], [12]."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from types import SimpleNamespace
import unittest
import urllib.parse

from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
    TKSMetaValveController,
    ValveDecision,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_EXECUTION_MODE,
    ENV_LIVE_ARM_PHRASE,
    ENV_OANDA_LIVE_ACCOUNT_ID,
    ENV_OANDA_LIVE_TOKEN,
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    OandaMutationJournal,
    OandaOutcomeUnknownError,
    OandaPracticePaperClient,
    REQUIRED_LIVE_ARM_PHRASE,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    ENV_LIVE_AUTH_KEY_FILE,
    ENV_LIVE_AUTH_TICKET_FILE,
    LiveAuthorizationContext,
    LiveAuthorizationError,
    mint_live_authorization_bundle,
    provision_live_auth_key,
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
    Mt5AccountSnapshot,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5NativePythonTransport,
    Mt5OrderReceipt,
    Mt5OrderRequest,
    Mt5OutcomeUnknownError,
    Mt5PaperBrokerVenue,
    Mt5Position,
    Mt5PostFillObservationError,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5Tick,
    Mt5TransportError,
    Mt5ValveClearanceError,
    OandaPracticeFallbackVenue,
    OrderIntent,
    SpoolCustodyAce,
    SpoolPathCustodyObservation,
    TRANSPORT_SPOOL_BRIDGE,
    _canonical_spool_request_hmac_input,
    _canonical_valve_admission_input,
    _load_or_create_spool_hmac_key,
    _load_or_create_valve_admission_key,
    _spool_hmac_hex,
    derive_spool_channel_key,
    load_mt5_credentials,
    sign_spool_valve_admission,
    spool_channel_key_id,
    verify_spool_path_custody,
)

D = Decimal
T0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
MQ5_PATH = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"
SYNTH_OANDA_PRACTICE_VAL = "fixture-oanda-practice-val-99"
SYNTH_OANDA_LIVE_VAL = "fixture-oanda-live-val-99"
SYNTH_MT5_VAL = "fixture-mt5-val-99"
EXPECTED_VALVE_WEIGHTS_SHA256 = "57fc5084b667497e9a6c68b27b444fb62521a0e44569d74a5f6cbb0e9e7377b5"

QUOTES: dict[str, tuple[Decimal, Decimal]] = {
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27010")),
    "USDJPY": (D("150.000"), D("150.010")),
    "EURGBP": (D("0.86600"), D("0.86610")),
}


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> datetime:
        self.current = self.current + timedelta(seconds=seconds)
        return self.current


def _valve_decision(gate: ForexMetaValveGate, order: OrderIntent) -> ValveDecision:
    return ValveDecision(
        admitted=True,
        valve_mode="ADMIT",
        mlp_score=0.92,
        threshold=gate.controller.threshold,
        mlp_admitted=True,
        hard_veto=False,
        hard_veto_reasons=(),
        features={f"f{i}": 0.0 for i in range(16)},
        weights_sha256=gate.controller.weights_sha256(),
        request_id=f"req-{order.order_id}",
        selected_action_ref=order.action_ref,
    )


def _open_order(order_id: str, *, symbol: str = "EURUSD", units: Decimal = D("50000"), stop: Decimal = D("1.09500")) -> OrderIntent:
    return OrderIntent(
        order_id=order_id,
        action_ref=f"act-{order_id}",
        kind=ActionKind.OPEN,
        symbol=symbol,
        quantity_units=units,
        side=Side.BUY,
        stop_price=stop,
    )


class _StatefulOandaTransport:
    def __init__(
        self,
        *,
        host: str = "api-fxpractice.oanda.com",
        account_id: str = "101-001-9999999-001",
        nav: str = "80000.00",
        margin_available: str = "79000.00",
    ) -> None:
        self.host = host
        self.account_id = account_id
        self.nav = nav
        self.margin_available = margin_available
        self.fail_summary = False
        self.fail_close = False
        self.summary_calls = 0
        self.mutation_calls: list[tuple[str, str]] = []
        self.open_trades: dict[str, dict[str, str]] = {}
        self.transactions: list[dict[str, object]] = []
        self._tx = 100
        self._next_trade = 500

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if parsed.hostname != self.host:
            raise RuntimeError(f"unexpected host {parsed.hostname}")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            self.mutation_calls.append((method, parsed.path))
        if method == "GET" and parsed.path.endswith("/summary"):
            self.summary_calls += 1
            if self.fail_summary:
                raise TimeoutError("simulated OANDA summary timeout")
            return json.dumps({
                "account": {
                    "id": self.account_id,
                    "currency": "USD",
                    "balance": self.nav,
                    "NAV": self.nav,
                    "unrealizedPL": "0.00",
                    "marginAvailable": self.margin_available,
                    "openPositionCount": len(self.open_trades),
                    "lastTransactionID": str(self._tx),
                },
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/pricing"):
            insts = urllib.parse.parse_qs(parsed.query)["instruments"][0].split(",")
            prices = []
            for inst in insts:
                sym = inst.replace("_", "")
                bid, ask = QUOTES[sym]
                prices.append({
                    "type": "PRICE",
                    "instrument": inst,
                    "time": "2026-11-20T12:00:00Z",
                    "tradeable": True,
                    "bids": [{"price": str(bid), "liquidity": 1000000}],
                    "asks": [{"price": str(ask), "liquidity": 1000000}],
                })
            return json.dumps({"prices": prices}).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/openTrades"):
            return json.dumps({
                "trades": list(self.open_trades.values()),
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/trades"):
            return json.dumps({
                "trades": list(self.open_trades.values()),
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        if method == "GET" and "/transactions/idrange" in parsed.path:
            qs = urllib.parse.parse_qs(parsed.query)
            lo = int(qs["from"][0])
            hi = int(qs["to"][0])
            rows = [t for t in self.transactions if lo <= int(str(t["id"])) <= hi]
            return json.dumps({"transactions": rows, "lastTransactionID": str(self._tx)}).encode("utf-8")
        if method == "POST" and parsed.path.endswith("/orders"):
            order = json.loads((body or b"{}").decode("utf-8"))["order"]
            self._tx += 1
            create_id = str(self._tx)
            self._tx += 1
            fill_id = str(self._tx)
            self._next_trade += 1
            tid = str(self._next_trade)
            inst = str(order["instrument"])
            sym = inst.replace("_", "")
            bid, ask = QUOTES[sym]
            units_str = str(order["units"])
            px = ask if not units_str.startswith("-") else bid
            self.open_trades[tid] = {
                "id": tid,
                "instrument": inst,
                "currentUnits": units_str,
                "price": str(px),
                "unrealizedPL": "12.50",
                "state": "OPEN",
            }
            self.transactions.append({"id": create_id, "type": "MARKET_ORDER", "clientExtensions": order.get("clientExtensions", {})})
            self.transactions.append({"id": fill_id, "type": "ORDER_FILL", "clientExtensions": order.get("clientExtensions", {})})
            return json.dumps({
                "orderCreateTransaction": {"id": create_id},
                "orderFillTransaction": {"id": fill_id, "price": str(px)},
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        if method == "PUT" and parsed.path.endswith("/orders"):
            self._tx += 1
            return json.dumps({
                "stopLossOrderTransaction": {"id": str(self._tx)},
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        if method == "PUT" and parsed.path.endswith("/close"):
            tid = parsed.path.split("/")[-2]
            req_doc = json.loads((body or b"{}").decode("utf-8"))
            req_units = str(req_doc["units"])
            self._tx += 1
            create_id = str(self._tx)
            self._tx += 1
            fill_id = str(self._tx)
            tr = self.open_trades.get(tid)
            if tr is None:
                raise RuntimeError("HTTP error 404 trade missing")
            if req_units == "ALL":
                self.open_trades.pop(tid, None)
                tx_fill = {"id": fill_id, "type": "ORDER_FILL", "price": "1.10000", "pl": "12.50", "tradesClosed": [{"tradeID": tid, "realizedPL": "12.50"}]}
            else:
                cur_u = Decimal(tr["currentUnits"])
                rem = (abs(cur_u) - Decimal(req_units)) * (Decimal(1) if cur_u > 0 else Decimal(-1))
                tr["currentUnits"] = str(rem)
                tx_fill = {"id": fill_id, "type": "ORDER_FILL", "price": "1.10000", "pl": "5.00", "tradeReduced": {"tradeID": tid, "realizedPL": "5.00"}}
            self.transactions.append({"id": create_id, "type": "MARKET_ORDER", "tradeClose": {"tradeID": tid, "units": req_units}})
            self.transactions.append(tx_fill)
            if self.fail_close:
                raise TimeoutError("simulated post-dispatch OANDA close timeout")
            return json.dumps({
                "orderCreateTransaction": {"id": create_id},
                "orderFillTransaction": tx_fill,
                "lastTransactionID": str(self._tx),
            }).encode("utf-8")
        raise RuntimeError(f"unexpected OANDA request {method} {url}")


class _FakeNativeSdk:
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

    def __init__(self, *, server: str = "Hugo PRO5", login: int = 9001122, trade_mode: int = 2) -> None:
        self.server = server
        self._login_id = login
        self.trade_mode = trade_mode
        self.order_send_calls = 0

    def initialize(self, **_kwargs: object) -> bool:
        return True

    def login(self, *_args: object, **_kwargs: object) -> bool:
        return True

    def shutdown(self) -> None:
        return None

    def last_error(self) -> tuple[int, str]:
        return (0, "ok")

    def account_info(self) -> SimpleNamespace:
        return SimpleNamespace(
            server=self.server,
            login=self._login_id,
            currency="USD",
            balance=12000.0,
            equity=12000.0,
            margin=0.0,
            margin_free=12000.0,
            leverage=500,
            trade_mode=self.trade_mode,
        )

    def symbol_select(self, _symbol: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, symbol: str) -> SimpleNamespace:
        bid, ask = QUOTES[symbol]
        return SimpleNamespace(bid=float(bid), ask=float(ask), time_msc=1763640000000)

    def positions_get(self) -> tuple[object, ...]:
        return ()

    def order_send(self, _payload: dict[str, object]) -> SimpleNamespace:
        self.order_send_calls += 1
        return SimpleNamespace(retcode=10009, deal=77001, order=55001, volume=0.10, price=1.10010, comment="filled")


class _RefreshFaultTransport:
    """Wraps a real Mt5SpoolBridgeTransport and injects post-fill account_info or positions errors."""

    transport_name = TRANSPORT_SPOOL_BRIDGE

    def __init__(self, inner: Mt5SpoolBridgeTransport) -> None:
        self.inner = inner
        self.fail_next_account_info_after_send = False
        self.fail_next_positions_after_send = False
        self.fail_pre_dispatch_tick = False
        self._sent = False

    def connect(self, credentials: Mt5Credentials) -> Mt5AccountSnapshot:
        return self.inner.connect(credentials)

    def account_info(self) -> Mt5AccountSnapshot:
        if self._sent and self.fail_next_account_info_after_send:
            self.fail_next_account_info_after_send = False
            raise Mt5TransportError("simulated post-fill account_info failure")
        return self.inner.account_info()

    def symbol_tick(self, symbol: str) -> Mt5Tick:
        if self.fail_pre_dispatch_tick:
            raise Mt5TransportError("simulated pre-dispatch tick failure")
        return self.inner.symbol_tick(symbol)

    def positions(self) -> tuple[Mt5Position, ...]:
        if self._sent and self.fail_next_positions_after_send:
            self.fail_next_positions_after_send = False
            raise Mt5TransportError("simulated post-fill positions failure")
        return self.inner.positions()

    def prepare_request(self, request: Mt5OrderRequest) -> Mt5OrderRequest:
        prepared = self.inner.prepare_request(request)
        return sign_spool_valve_admission(
            prepared,
            spool_dir=self.inner.spool_dir,
            key_dir=self.inner.key_dir,
            valve_key_file=self.inner.valve_key_file,
            expires_at=prepared.expires_at,
        )

    def send_order(self, request: Mt5OrderRequest) -> Mt5OrderReceipt:
        rcpt = self.inner.send_order(request)
        self._sent = True
        return rcpt

    def shutdown(self) -> None:
        self.inner.shutdown()


class AuditEfb2bf4VenueSecurityTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Finding [1]: Barbell-Wide Unresolved-Mutation Latch
    # ------------------------------------------------------------------
    def test_finding_01_barbell_wide_unresolved_mutation_latch_blocks_sibling_venues_and_symbols(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5", server="Hugo demo PRO5", login=7001234, quotes=QUOTES, balance=D("12000"), clock=clock
            )
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5", server="LHFXSA-Demo", login=8005678, quotes=QUOTES, balance=D("8000"), clock=clock
            )
            emu_h.publish_market()
            emu_l.publish_market()
            oanda_stub = _StatefulOandaTransport()
            mt5_journal = Mt5MutationJournal(root / "barbell_state.sqlite3")
            oanda_journal = OandaMutationJournal(root / "barbell_state.sqlite3")
            env = {
                ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
                ENV_MT5_SPOOL_DIR: str(root),
                ENV_HUGOSWAY_MT5_LOGIN: "7001234",
                ENV_HUGOSWAY_MT5_SERVER: "Hugo demo PRO5",
                ENV_LHFX_MT5_LOGIN: "8005678",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Demo",
                ENV_OANDA_PRACTICE_TOKEN: SYNTH_OANDA_PRACTICE_VAL,
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda_stub.account_id,
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}
            hugo_silent = {"enabled": False}

            def _hugo_sleep(_sec: float) -> None:
                if not hugo_silent["enabled"]:
                    emu_h.sleep_hook(_sec)

            def _tf(bid: str, _mode: str, sp_root: str | None) -> Mt5SpoolBridgeTransport:
                return Mt5SpoolBridgeTransport(
                    Path(str(sp_root)) / bid.lower(),
                    sleep=_hugo_sleep if bid == BROKER_HUGOSWAY_MT5 else emus[bid].sleep_hook,
                    poll_interval_seconds=0.005,
                    receipt_timeout_seconds=0.05,
                    clock=clock,
                )

            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                transport_factory=_tf,
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(
                    e, transport=oanda_stub, mutation_journal=oanda_journal, clock=clock
                ),
                mt5_mutation_journal=mt5_journal,
                oanda_mutation_journal=oanda_journal,
                clock=clock,
            )
            router.activate_all()

            # Pre-open a known LHFX position directly so we can verify safe CLOSE/REDUCE/AMEND_STOP during latch
            lhfx_venue = router.venues[BROKER_LHFX_MT5]
            assert isinstance(lhfx_venue, Mt5PaperBrokerVenue)
            seed_open = _open_order("seed-lhfx-1", symbol="GBPUSD", units=D("20000"), stop=D("1.26500"))
            seed_res = lhfx_venue.execute(seed_open, valve_decision=_valve_decision(gate, seed_open))
            lhfx_ticket = str(seed_res.receipt.position_ticket)

            # Induce OUTCOME_UNKNOWN on HUGOSWAY EURUSD
            hugo_silent["enabled"] = True
            ambig_open = _open_order("hugo-ambig-eurusd", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            with self.assertRaises(Mt5OutcomeUnknownError):
                router.execute_open(ambig_open, valve_decision=_valve_decision(gate, ambig_open))

            self.assertTrue(mt5_journal.has_any_unresolved_mutation())
            self.assertEqual(len(mt5_journal.list_unresolved_mutations()), 1)
            self.assertTrue(router.has_any_unresolved_mutation())
            ok_elig, elig_reason = router.check_open_eligibility("GBPUSD")
            self.assertFalse(ok_elig)
            self.assertIn("UNRESOLVED_MUTATION_LATCH", elig_reason)

            # Different symbol (GBPUSD) and sibling routes (LHFX, OANDA) MUST ALL be blocked!
            gbp_open = _open_order("gbp-after-latch", symbol="GBPUSD", units=D("10000"), stop=D("1.26500"))
            lhfx_before = len(emu_l.processed)
            oanda_before = len(oanda_stub.mutation_calls)
            with self.assertRaises(Mt5OutcomeUnknownError) as ctx_latched:
                router.execute_open(gbp_open, valve_decision=_valve_decision(gate, gbp_open))
            self.assertIn("BARBELL_UNRESOLVED_MUTATION_LATCH", str(ctx_latched.exception))
            self.assertEqual(len(emu_l.processed), lhfx_before)
            self.assertEqual(len(oanda_stub.mutation_calls), oanda_before)

            # Even direct LHFX OPEN via shared journal is blocked!
            with self.assertRaises(Mt5OutcomeUnknownError):
                lhfx_venue.execute(gbp_open, valve_decision=_valve_decision(gate, gbp_open))

            # Demonstrably risk-reducing AMEND_STOP / REDUCE / CLOSE on known LHFX ticket MUST STILL SUCCEED!
            amend = OrderIntent(
                order_id="lhfx-safe-amend", action_ref="act-lhfx-safe-amend", kind=ActionKind.AMEND_STOP,
                symbol="GBPUSD", stop_price=D("1.26600"), position_ticket=lhfx_ticket,
            )
            self.assertTrue(router.execute_management(BROKER_LHFX_MT5, amend, valve_decision=_valve_decision(gate, amend)).accepted)
            reduce_ord = OrderIntent(
                order_id="lhfx-safe-reduce", action_ref="act-lhfx-safe-reduce", kind=ActionKind.REDUCE,
                symbol="GBPUSD", quantity_units=D("10000"), position_ticket=lhfx_ticket,
            )
            self.assertTrue(router.execute_management(BROKER_LHFX_MT5, reduce_ord, valve_decision=_valve_decision(gate, reduce_ord)).accepted)
            close_ord = OrderIntent(
                order_id="lhfx-safe-close", action_ref="act-lhfx-safe-close", kind=ActionKind.CLOSE,
                symbol="GBPUSD", quantity_units=D("10000"), position_ticket=lhfx_ticket,
            )
            self.assertTrue(router.execute_management(BROKER_LHFX_MT5, close_ord, valve_decision=_valve_decision(gate, close_ord)).accepted)

            # Complete account-bound reconciliation clears the latch and restores GBPUSD new risk
            hugo_venue = router.venues[BROKER_HUGOSWAY_MT5]
            assert isinstance(hugo_venue, Mt5PaperBrokerVenue)
            rec = hugo_venue.reconcile_unknown_mutations(
                terminal_history_fn=lambda login, srv: {
                    "account_login": login, "server": srv, "complete": True, "orders": [], "deals": []
                },
                now=clock(),
            )
            self.assertEqual(rec["remaining_unknown"], 0)
            self.assertFalse(router.has_any_unresolved_mutation())

            # Clean up timed-out request file on Hugo spool and verify GBPUSD OPEN now succeeds
            for p in (root / "hugosway_mt5").glob("order_request_*.json"):
                p.unlink()
            hugo_silent["enabled"] = False
            gbp_after = _open_order("gbp-post-reconcile", symbol="GBPUSD", units=D("10000"), stop=D("1.26500"))
            exec_ok = router.execute_open(gbp_after, valve_decision=_valve_decision(gate, gbp_after))
            self.assertTrue(exec_ok.result.accepted)

            # Also verify OANDA unresolved EURUSD mutation blocks OANDA GBPUSD AND MT5 new risk
            oanda_journal.record_pending(
                client_ext_id="oanda-unk-eur", account_id=oanda_stub.account_id, symbol="EURUSD",
                action_kind="OPEN", method="POST", relative_path="accounts/x/orders",
                now_utc="2026-11-20T12:00:05Z", semantic_key="OPEN|x|EURUSD|BUY",
            )
            oanda_journal.mark_outcome(
                client_ext_id="oanda-unk-eur", status="OUTCOME_UNKNOWN", now_utc="2026-11-20T12:00:06Z", error_detail="TimeoutError"
            )
            self.assertTrue(oanda_journal.has_any_unresolved_mutation())
            with self.assertRaises(OandaOutcomeUnknownError):
                router.execute_open(_open_order("blocked-by-oanda", symbol="GBPUSD", units=D("10000"), stop=D("1.26500")), valve_decision=_valve_decision(gate, _open_order("blocked-by-oanda", symbol="GBPUSD", units=D("10000"), stop=D("1.26500"))))
            oanda_client = router.venues[BROKER_OANDA_PRACTICE].client  # type: ignore[union-attr]
            with self.assertRaises(OandaOutcomeUnknownError):
                oanda_client.submit_paper_market_order(
                    symbol="GBPUSD", side=Side.BUY, units=D("1000"), client_order_id="oanda-gbp-blocked",
                    stop_loss_price=D("1.26500"), now=clock(),
                )

    # ------------------------------------------------------------------
    # Finding [3]: Fresh OANDA NAV & Margin Probe
    # ------------------------------------------------------------------
    def test_finding_03_oanda_fresh_nav_margin_probe_and_fail_closed_on_stale_or_error(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5", server="Hugo demo PRO5", login=7001234, quotes=QUOTES, balance=D("12000"), clock=clock
            )
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5", server="LHFXSA-Demo", login=8005678, quotes=QUOTES, balance=D("8000"), clock=clock
            )
            emu_h.publish_market()
            emu_l.publish_market()
            oanda_stub = _StatefulOandaTransport(nav="80000.00", margin_available="79000.00")
            env = {
                ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
                ENV_MT5_SPOOL_DIR: str(root),
                ENV_HUGOSWAY_MT5_LOGIN: "7001234",
                ENV_HUGOSWAY_MT5_SERVER: "Hugo demo PRO5",
                ENV_LHFX_MT5_LOGIN: "8005678",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Demo",
                ENV_OANDA_PRACTICE_TOKEN: SYNTH_OANDA_PRACTICE_VAL,
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda_stub.account_id,
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, BROKER_LHFX_MT5: emu_l}
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                transport_factory=lambda bid, _m, sp_root: Mt5SpoolBridgeTransport(
                    Path(str(sp_root)) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda_stub, clock=clock),
                clock=clock,
            )
            router.activate_all()
            # Observe initial $100,000 peak
            self.assertEqual(router.barbell.total_equity(router.equities()), D("100000.00"))
            oanda_venue = router.venues[BROKER_OANDA_PRACTICE]
            assert isinstance(oanda_venue, OandaPracticeFallbackVenue)
            self.assertTrue(oanda_venue.is_summary_fresh(now=clock()))

            # 1. Change OANDA NAV AFTER connect from $80,000 -> $68,000 (12% drawdown >= 10% cap!)
            oanda_stub.nav = "68000.00"
            oanda_stub.margin_available = "67000.00"
            ord_dd = _open_order("oanda-dd-refuse", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            with self.assertRaises(BarbellPolicyRefusalError) as ctx_dd:
                router.execute_open(ord_dd, valve_decision=_valve_decision(gate, ord_dd))
            self.assertEqual(ctx_dd.exception.reason, "MAX_DRAWDOWN_EXCEEDED")
            self.assertEqual(oanda_venue.nav, D("68000.00"))

            # 2. Fail refresh -> new risk MUST fail closed (never reuse cached NAV/margin)
            oanda_stub.nav = "80000.00"
            oanda_stub.margin_available = "79000.00"
            oanda_stub.fail_summary = True
            ord_fail = _open_order("oanda-refresh-fail", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            with self.assertRaises(Mt5TransportError):
                router.execute_open(ord_fail, valve_decision=_valve_decision(gate, ord_fail))
            self.assertFalse(oanda_venue.is_summary_fresh(now=clock()))

            # 3. Restore refresh, verify TTL staleness check when clock advances > 15s
            oanda_stub.fail_summary = False
            oanda_venue.probe_account_summary(now=clock())
            self.assertTrue(oanda_venue.is_summary_fresh(now=clock()))
            clock.advance(20)
            self.assertFalse(oanda_venue.is_summary_fresh(now=clock()))
            with self.assertRaises(Mt5TransportError):
                oanda_venue.require_fresh_summary(now=clock())

            # 4. Safe-harbor OANDA OPEN refreshes summary before AND after mutation
            summary_before = oanda_stub.summary_calls
            ord_sh = _open_order("oanda-sh-fresh", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            res_sh = oanda_venue.execute(ord_sh, valve_decision=_valve_decision(gate, ord_sh))
            self.assertTrue(res_sh.accepted)
            self.assertGreaterEqual(oanda_stub.summary_calls, summary_before + 2)
            self.assertTrue(oanda_venue.is_summary_fresh(now=clock()))

    # ------------------------------------------------------------------
    # Finding [4]: Post-Fill MT5 Refresh Failure Never Reroutes
    # ------------------------------------------------------------------
    def test_finding_04_post_fill_mt5_refresh_failure_never_reroutes_to_sibling_or_oanda(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5", server="Hugo demo PRO5", login=7001234, quotes=QUOTES, balance=D("12000"), clock=clock
            )
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5", server="LHFXSA-Demo", login=8005678, quotes=QUOTES, balance=D("8000"), clock=clock
            )
            emu_h.publish_market()
            emu_l.publish_market()
            oanda_stub = _StatefulOandaTransport()
            wrappers: dict[str, _RefreshFaultTransport] = {}

            def _tf(bid: str, _mode: str, sp_root: str | None) -> _RefreshFaultTransport:
                emu = emu_h if bid == BROKER_HUGOSWAY_MT5 else emu_l
                inner = Mt5SpoolBridgeTransport(
                    Path(str(sp_root)) / bid.lower(), sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock
                )
                wrap = _RefreshFaultTransport(inner)
                wrappers[bid] = wrap
                return wrap

            env = {
                ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
                ENV_MT5_SPOOL_DIR: str(root),
                ENV_HUGOSWAY_MT5_LOGIN: "7001234",
                ENV_HUGOSWAY_MT5_SERVER: "Hugo demo PRO5",
                ENV_LHFX_MT5_LOGIN: "8005678",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Demo",
                ENV_OANDA_PRACTICE_TOKEN: SYNTH_OANDA_PRACTICE_VAL,
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda_stub.account_id,
            }
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                transport_factory=_tf,
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda_stub, clock=clock),
                clock=clock,
            )
            router.activate_all()

            # Case A: account_info fails right AFTER confirmed fill on HUGOSWAY -> NEVER reroute to LHFX/OANDA!
            wrappers[BROKER_HUGOSWAY_MT5].fail_next_account_info_after_send = True
            o1 = _open_order("postfill-acct-1", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            ex1 = router.execute_open(o1, valve_decision=_valve_decision(gate, o1))
            self.assertEqual(ex1.executed_on, BROKER_HUGOSWAY_MT5)
            self.assertFalse(ex1.safe_harbor)
            self.assertTrue(ex1.result.accepted)
            self.assertTrue(ex1.result.reconciliation_required)
            self.assertIsNone(ex1.result.account_after)
            self.assertIn("account_info", str(ex1.result.post_fill_refresh_error))
            self.assertEqual(len(emu_l.processed), 0)
            self.assertEqual(len(oanda_stub.mutation_calls), 0)

            # Case B: positions() fails right AFTER confirmed fill on HUGOSWAY -> NEVER reroute!
            wrappers[BROKER_HUGOSWAY_MT5]._sent = False
            wrappers[BROKER_HUGOSWAY_MT5].fail_next_positions_after_send = True
            o2 = _open_order("postfill-pos-2", symbol="GBPUSD", units=D("10000"), stop=D("1.26500"))
            ex2 = router.execute_open(o2, valve_decision=_valve_decision(gate, o2))
            self.assertEqual(ex2.executed_on, BROKER_HUGOSWAY_MT5)
            self.assertTrue(ex2.result.accepted)
            self.assertTrue(ex2.result.reconciliation_required)
            self.assertIn("positions", str(ex2.result.post_fill_refresh_error))
            self.assertEqual(len(emu_l.processed), 0)
            self.assertEqual(len(oanda_stub.mutation_calls), 0)

            # Case C: Explicit pre-dispatch failure on HUGOSWAY STILL safely fails over to LHFX!
            wrappers[BROKER_HUGOSWAY_MT5].fail_pre_dispatch_tick = True
            o3 = _open_order("predisp-failover-3", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            ex3 = router.execute_open(o3, valve_decision=_valve_decision(gate, o3))
            self.assertEqual(ex3.executed_on, BROKER_LHFX_MT5)
            self.assertEqual(len(emu_l.processed), 1)

            # Case D: Mt5PostFillObservationError is NOT a subclass of Mt5TransportError
            self.assertFalse(issubclass(Mt5PostFillObservationError, Mt5TransportError))

    # ------------------------------------------------------------------
    # Finding [5]: Immutable Constitutional 1.00% Stop-Risk & 10.00% Drawdown Ceilings
    # ------------------------------------------------------------------
    def test_finding_05_immutable_constitutional_1pct_stop_risk_and_10pct_drawdown_ceilings(self) -> None:
        self.assertEqual(MAX_CONSTITUTIONAL_STOP_RISK_PCT, D("1.00"))
        self.assertEqual(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, D("0.10"))
        self.assertEqual(DEFAULT_MAX_DRAWDOWN_PCT, D("0.10"))

        # Reject 1.01% stop-risk and 10.01% drawdown in BarbellCapitalPolicy constructor & env parser
        with self.assertRaises(ContractError):
            BarbellCapitalPolicy(max_stop_loss_equity_risk_pct=D("1.01"))
        with self.assertRaises(ContractError):
            BarbellCapitalPolicy(max_drawdown_pct=D("0.1001"))
        with self.assertRaises(ContractError):
            BarbellCapitalPolicy.from_environ({"CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "1.01"})
        with self.assertRaises(ContractError):
            BarbellCapitalPolicy.from_environ({"CAS_FOREX_MAX_DRAWDOWN_PCT": "0.1001"})
        with self.assertRaises(ContractError):
            BarbellCapitalPolicy.from_environ({"CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "5.00"})
        with self.assertRaises(ContractError):
            BarbellCapitalPolicy.from_environ({"CAS_FOREX_MAX_DRAWDOWN_PCT": "0.20"})

        # Allow ONLY tighter/lower values
        tight = BarbellCapitalPolicy.from_environ({
            "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "0.50",
            "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.05",
        })
        self.assertEqual(tight.max_stop_loss_equity_risk_pct, D("0.50"))
        self.assertEqual(tight.max_drawdown_pct, D("0.05"))

        # Reject > 10.00% drawdown in ForexMetaValveGate constructor, loader, default_policy, and runtime policy patch
        with self.assertRaises(ContractError):
            load_default_forex_valve_gate(max_drawdown_pct=D("0.1001"))
        with self.assertRaises(ContractError):
            load_default_forex_valve_gate(max_drawdown_pct=D("0.20"))
        gate = load_default_forex_valve_gate()
        self.assertEqual(gate.controller.parameter_count, 161)
        self.assertEqual(gate.controller.threshold, 0.55)
        self.assertEqual(gate.weights_sha256, EXPECTED_VALVE_WEIGHTS_SHA256)
        with self.assertRaises(ContractError):
            ForexMetaValveGate(gate.controller, default_policy={"max_drawdown_pct": "0.15"})

        # Runtime policy patch trying to loosen max_drawdown_pct to 0.15 MUST be rejected even at 5% drawdown,
        # and at 10% drawdown MUST also trigger MAX_DRAWDOWN_EXCEEDED!
        proposal = SimpleNamespace(
            request=SimpleNamespace(
                request_id="req-const-dd",
                facts=(),
                evidence=(SimpleNamespace(evidence_id="ev-1"),),
                state=SimpleNamespace(
                    scope=SimpleNamespace(account_id="acct-1", run_id="run-1"),
                    observed_at=T0,
                    valid_until=T0 + timedelta(minutes=5),
                ),
            ),
            result=SimpleNamespace(selection=SimpleNamespace(evidence_ids=("ev-1",), reason="clean", selected_action_ref="act-const-1")),
            intent=SimpleNamespace(
                intent_id="intent-const-1", action_ref="act-const-1", kind=ActionKind.OPEN,
                instrument_id="EURUSD", quantity=D("10000"), side=Side.BUY,
                stop_price=D("1.09500"), limit_price=None, target_id=None, take_profit_price=D("1.11000"),
            ),
        )
        view_5pct_dd = {"balance": "100000", "equity": "95000", "peak_equity": "100000", "available_margin": "90000", "position_inventory": "[]"}
        dec_patch = gate.evaluate(
            proposal,
            current_view=view_5pct_dd,
            policy={"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "50000", "max_drawdown_pct": "0.15"},
            now=T0 + timedelta(seconds=1),
        )
        self.assertFalse(dec_patch.admitted)
        self.assertIn("CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED", dec_patch.hard_veto_reasons)

        view_10pct_dd = {"balance": "100000", "equity": "90000", "peak_equity": "100000", "available_margin": "85000", "position_inventory": "[]"}
        dec_10pct = gate.evaluate(
            proposal,
            current_view=view_10pct_dd,
            policy={"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "50000", "max_drawdown_pct": "0.25"},
            now=T0 + timedelta(seconds=2),
        )
        self.assertFalse(dec_10pct.admitted)
        self.assertIn("CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED", dec_10pct.hard_veto_reasons)
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", dec_10pct.hard_veto_reasons)

    # ------------------------------------------------------------------
    # Finding [6]: Per-Dispatch LIVE Authorization Ticket Expiry Guard
    # ------------------------------------------------------------------
    def test_finding_06_per_dispatch_live_ticket_expiry_blocks_native_mt5_and_oanda_and_spool(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key_path = provision_live_auth_key(root / ".live_auth.key")
            bundle = mint_live_authorization_bundle(
                key_file=key_path,
                targets=[
                    (BROKER_HUGOSWAY_MT5, "9001122", "Hugo PRO5"),
                    (BROKER_OANDA_LIVE, "001-001-live-01", "api-fxtrade.oanda.com"),
                ],
                ttl_seconds=60,
                issued_at=T0,
            )
            ticket_path = root / "live_bundle.json"
            ticket_path.write_text(json.dumps(bundle), encoding="utf-8")
            live_env = {
                ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
                ENV_LIVE_AUTH_KEY_FILE: str(key_path),
                ENV_LIVE_AUTH_TICKET_FILE: str(ticket_path),
                "CAS_FOREX_STATE_DIR": str(root / "state"),
                ENV_HUGOSWAY_MT5_LOGIN: "9001122",
                ENV_HUGOSWAY_MT5_PASSWORD: SYNTH_MT5_VAL,
                ENV_HUGOSWAY_MT5_SERVER: "Hugo PRO5",
                ENV_OANDA_LIVE_TOKEN: SYNTH_OANDA_LIVE_VAL,
                ENV_OANDA_LIVE_ACCOUNT_ID: "001-001-live-01",
            }

            # 1. Native MT5 transport: succeeds before expiry, NEVER invokes order_send after expiry
            sdk = _FakeNativeSdk(server="Hugo PRO5", login=9001122, trade_mode=2)
            native = Mt5NativePythonTransport(mt5_module=sdk, clock=clock)
            live_creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, live_env, now=clock())
            assert live_creds is not None and isinstance(live_creds.live_auth_context, LiveAuthorizationContext)
            native.connect(live_creds)
            req_valid = Mt5OrderRequest(
                request_id="live-native-ok", action="OPEN", symbol="EURUSD", side=Side.BUY,
                volume_lots=D("0.10"), price=D("1.10010"), stop_loss=D("1.09500"),
                position_ticket=None, deviation_points=20, magic=20261120, comment="live-ok", created_at=clock(),
            )
            rcpt_ok = native.send_order(req_valid)
            self.assertTrue(rcpt_ok.accepted)
            self.assertEqual(sdk.order_send_calls, 1)

            # 2. OANDA LIVE client: POST succeeds before expiry
            oanda_stub = _StatefulOandaTransport(host="api-fxtrade.oanda.com", account_id="001-001-live-01")
            oanda_client = OandaPracticePaperClient.from_runtime_env(live_env, transport=oanda_stub, clock=clock)
            assert oanda_client.live_auth_context is not None
            r_open = oanda_client.submit_paper_market_order(
                symbol="EURUSD", side=Side.BUY, units=D("1000"), client_order_id="live-oanda-ok",
                stop_loss_price=D("1.09500"), now=clock(),
            )
            self.assertEqual(r_open["status"], "FILLED")
            open_tid = next(iter(oanda_stub.open_trades.keys()))
            oanda_calls_before_expiry = len(oanda_stub.mutation_calls)

            # 3. Spool transport in LIVE mode
            spool_dir = root / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir, server="Hugo PRO5", login=9001122, quotes=QUOTES, trade_mode="REAL", clock=clock
            )
            emu.publish_market()
            spool_tr = Mt5SpoolBridgeTransport(spool_dir, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            spool_tr.connect(live_creds)

            # Advance clock BEYOND 60s LIVE ticket expiry!
            clock.advance(61)

            # Native MT5 order_send MUST NOT be invoked
            req_exp = dataclasses.replace(req_valid, request_id="live-native-expired")
            with self.assertRaises(LiveAuthorizationError):
                native.send_order(req_exp)
            self.assertEqual(sdk.order_send_calls, 1)

            # OANDA LIVE POST, PUT (amend), and PUT (close) MUST ALL fail closed with 0 HTTP calls!
            with self.assertRaises(LiveAuthorizationError):
                oanda_client.submit_paper_market_order(
                    symbol="EURUSD", side=Side.BUY, units=D("1000"), client_order_id="live-oanda-exp-post",
                    stop_loss_price=D("1.09500"), now=clock(),
                )
            with self.assertRaises(LiveAuthorizationError):
                oanda_client.amend_trade_protection(trade_id=open_tid, stop_loss_price=D("1.09600"), now=clock())
            with self.assertRaises(LiveAuthorizationError):
                oanda_client.close_trade(trade_id=open_tid, units="ALL", now=clock())
            self.assertEqual(len(oanda_stub.mutation_calls), oanda_calls_before_expiry)

            # Spool transport MUST ALSO fail closed before writing request file!
            spool_req = sign_spool_valve_admission(
                spool_tr.prepare_request(
                    Mt5OrderRequest(
                        request_id="live-spool-exp", action="OPEN", symbol="EURUSD", side=Side.BUY,
                        volume_lots=D("0.10"), price=D("1.10010"), stop_loss=D("1.09500"),
                        position_ticket=None, deviation_points=20, magic=20261120, comment="exp",
                        created_at=clock(), issued_at=clock(), expires_at=clock() + timedelta(seconds=30),
                        valve_decision_sha256="a" * 64,
                    )
                ),
                spool_dir=spool_dir,
            )
            with self.assertRaises(LiveAuthorizationError):
                spool_tr.send_order(spool_req)
            self.assertEqual(list(spool_dir.glob("order_request_*.json")), [])

            # Re-arming with a freshly minted valid ticket restores OANDA LIVE dispatch cleanly
            bundle2 = mint_live_authorization_bundle(
                key_file=key_path,
                targets=[(BROKER_OANDA_LIVE, "001-001-live-01", "api-fxtrade.oanda.com")],
                ttl_seconds=120,
                issued_at=clock(),
            )
            ticket_path.write_text(json.dumps(bundle2), encoding="utf-8")
            oanda_client.refresh_live_authorization(live_env, now=clock())
            r_cls = oanda_client.close_trade(trade_id=open_tid, units="ALL", now=clock())
            self.assertEqual(r_cls["status"], "CLOSED")

    # ------------------------------------------------------------------
    # Finding [7]: Windows Spool Custody (Cross-Platform + Live Win32) &
    #              Key Separation + Per-Channel Keys + Signed Valve Admission
    # ------------------------------------------------------------------
    def test_finding_07_windows_spool_custody_rejects_broad_inherited_aces_foreign_owner_and_reparse(self) -> None:
        owner_sid = "S-1-5-21-1000-2000-3000-1001"
        foreign_sid = "S-1-5-21-1000-2000-3000-1002"
        clean_aces = (
            SpoolCustodyAce(ace_type=0, ace_flags=3, access_mask=0x1F01FF, sid=owner_sid),
            SpoolCustodyAce(ace_type=0, ace_flags=3, access_mask=0x1F01FF, sid="S-1-5-18"),
            SpoolCustodyAce(ace_type=0, ace_flags=3, access_mask=0x1F01FF, sid="S-1-5-32-544"),
        )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool_ch = root / "hugosway_mt5"
            spool_ch.mkdir()
            snap = spool_ch / "market_ticks.json"
            snap.write_text("{}\n", encoding="utf-8")

            def _make_inspector(bad_target: Path, bad_obs: SpoolPathCustodyObservation):
                def _inspect(p: Path) -> SpoolPathCustodyObservation:
                    if p == bad_target:
                        return bad_obs
                    return SpoolPathCustodyObservation(
                        path=str(p), platform="nt", exists=True, is_dir=p.is_dir(), is_reg=p.is_file(),
                        is_reparse_or_symlink=False, owner_sid=owner_sid, current_user_sid=owner_sid,
                        dacl_present=True, dacl_protected=True, aces=clean_aces,
                    )
                return _inspect

            # 1. Clean owner-only Windows DACL passes
            ok_obs = verify_spool_path_custody(
                snap, expect_file=True, inspector=_make_inspector(Path("__none__"), SpoolPathCustodyObservation(
                    path="__none__", platform="nt", exists=False, is_dir=False, is_reg=False, is_reparse_or_symlink=False
                ))
            )
            self.assertEqual(ok_obs.owner_sid, owner_sid)

            # 2. Inherited broad ACEs (Everyone, Users, Authenticated Users) on channel dir MUST fail closed
            for broad_sid in ("S-1-1-0", "S-1-5-32-545", "S-1-5-11"):
                bad_aces = clean_aces + (SpoolCustodyAce(ace_type=0, ace_flags=0x10, access_mask=0x1200A9, sid=broad_sid),)
                insp = _make_inspector(
                    spool_ch,
                    SpoolPathCustodyObservation(
                        path=str(spool_ch), platform="nt", exists=True, is_dir=True, is_reg=False,
                        is_reparse_or_symlink=False, owner_sid=owner_sid, current_user_sid=owner_sid,
                        dacl_present=True, dacl_protected=False, aces=bad_aces,
                    ),
                )
                with self.assertRaises(Mt5TransportError):
                    Mt5SpoolBridgeTransport(spool_ch, custody_inspector=insp).prepare_spool_directory()

            # 3. Foreign owner SID on snapshot/key/channel MUST fail closed
            insp_owner = _make_inspector(
                snap,
                SpoolPathCustodyObservation(
                    path=str(snap), platform="nt", exists=True, is_dir=False, is_reg=True,
                    is_reparse_or_symlink=False, owner_sid=foreign_sid, current_user_sid=owner_sid,
                    dacl_present=True, dacl_protected=True, aces=clean_aces,
                ),
            )
            with self.assertRaises(Mt5TransportError):
                verify_spool_path_custody(snap, expect_file=True, inspector=insp_owner)

            # 4. NULL DACL on spool root MUST fail closed
            insp_null = _make_inspector(
                root,
                SpoolPathCustodyObservation(
                    path=str(root), platform="nt", exists=True, is_dir=True, is_reg=False,
                    is_reparse_or_symlink=False, owner_sid=owner_sid, current_user_sid=owner_sid,
                    dacl_present=False, dacl_protected=False, aces=(),
                ),
            )
            with self.assertRaises(Mt5TransportError):
                verify_spool_path_custody(root, expect_dir=True, inspector=insp_null)

            # 5. Reparse point / junction on ancestor MUST fail closed
            insp_rep = _make_inspector(
                root,
                SpoolPathCustodyObservation(
                    path=str(root), platform="nt", exists=True, is_dir=True, is_reg=False,
                    is_reparse_or_symlink=True, owner_sid=owner_sid, current_user_sid=owner_sid,
                    dacl_present=True, dacl_protected=True, aces=clean_aces,
                ),
            )
            with self.assertRaises(Mt5TransportError):
                verify_spool_path_custody(spool_ch, expect_dir=True, inspector=insp_rep)

            # 6. Live Windows NTFS test (when running on real Windows): create a directory with Everyone ACE and assert refusal!
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes

                bad_win_dir = root / "win_permissive_spool"
                bad_win_dir.mkdir()
                advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
                    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)
                ]
                advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
                advapi32.GetSecurityDescriptorDacl.argtypes = [
                    ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)
                ]
                advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
                advapi32.SetNamedSecurityInfoW.argtypes = [
                    wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ]
                advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
                kernel32.LocalFree.argtypes = [ctypes.c_void_p]

                sd = ctypes.c_void_p()
                self.assertTrue(
                    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        "D:(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ctypes.byref(sd), None
                    )
                )
                try:
                    pres = wintypes.BOOL()
                    dacl = ctypes.c_void_p()
                    dflt = wintypes.BOOL()
                    self.assertTrue(advapi32.GetSecurityDescriptorDacl(sd, ctypes.byref(pres), ctypes.byref(dacl), ctypes.byref(dflt)))
                    rc = advapi32.SetNamedSecurityInfoW(str(bad_win_dir), 1, 0x00000004, None, None, dacl, None)
                    self.assertEqual(rc, 0)
                finally:
                    kernel32.LocalFree(sd)
                with self.assertRaises(Mt5TransportError) as ctx_win:
                    Mt5SpoolBridgeTransport(bad_win_dir).prepare_spool_directory()
                self.assertIn("MT5_SPOOL_CUSTODY_VIOLATION", str(ctx_win.exception))

    def test_finding_07_key_separation_per_channel_hmac_and_signed_valve_admission(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data_spool = root / "data_spool"
            key_vault = root / "isolated_keys"
            hugo_spool = data_spool / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                hugo_spool, server="Hugo demo PRO5", login=7001234, quotes=QUOTES, key_dir=key_vault, clock=clock
            )
            emu.publish_market()

            # 1. Keys live strictly in isolated key_vault (NEVER in data_spool) and are strictly distinct
            self.assertTrue((key_vault / ".spool_hmac.key").is_file())
            self.assertTrue((key_vault / ".valve_admission.key").is_file())
            self.assertFalse((data_spool / ".spool_hmac.key").exists())
            self.assertFalse((hugo_spool / ".spool_hmac.key").exists())
            master_key = _load_or_create_spool_hmac_key(hugo_spool, key_dir=key_vault)
            valve_key = _load_or_create_valve_admission_key(hugo_spool, key_dir=key_vault)
            self.assertNotEqual(master_key, valve_key)

            # 2. Per-channel HMAC keys & key IDs are cryptographically isolated between HUGOSWAY and LHFX
            k_hugo = derive_spool_channel_key(master_key, "hugosway_mt5")
            k_lhfx = derive_spool_channel_key(master_key, "lhfx_mt5")
            self.assertNotEqual(k_hugo, k_lhfx)
            self.assertNotEqual(k_hugo, master_key)
            self.assertNotEqual(spool_channel_key_id(k_hugo, "hugosway_mt5"), spool_channel_key_id(k_lhfx, "lhfx_mt5"))

            # 3. Valid-HMAC forged request with unauthenticated Valve digest MUST be refused by emulator!
            kid_hugo = spool_channel_key_id(k_hugo, "hugosway_mt5")
            forged_req = Mt5OrderRequest(
                request_id="forged-no-valve-sig", action="OPEN", symbol="EURUSD", side=Side.BUY,
                volume_lots=D("0.10"), price=D("1.10010"), stop_loss=D("1.09500"),
                position_ticket=None, deviation_points=20, magic=20261120, comment="forged",
                created_at=T0, monotonic_nonce=1, issued_at=T0, expires_at=T0 + timedelta(seconds=30),
                broker_channel="hugosway_mt5", channel_key_id=kid_hugo, account_login="7001234",
                server="Hugo demo PRO5", execution_mode=EXECUTION_MODE_DEMO,
                valve_decision_sha256="a" * 64,
                valve_admission_expires_at=T0 + timedelta(seconds=30),
                valve_admission_sig="",  # unauthenticated!
            )
            forged_doc = forged_req.to_spool_dict()
            forged_doc["request_hmac_sha256"] = _spool_hmac_hex(k_hugo, _canonical_spool_request_hmac_input(forged_doc))
            (hugo_spool / "order_request_forged-no-valve-sig.json").write_text(json.dumps(forged_doc), encoding="utf-8")
            emu.process_pending()
            rcpt1 = json.loads((hugo_spool / "order_receipt_forged-no-valve-sig.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt1["status"], "REJECTED")
            self.assertEqual(rcpt1["retcode"], "10017")
            self.assertEqual(len(emu._positions), 0)

            # 4. Attacker holding ONLY spool HMAC key tries signing valve_admission_sig with spool key -> REFUSED!
            spoof_sig = _spool_hmac_hex(k_hugo, _canonical_valve_admission_input(forged_req._core_dict()))
            spoof_req = dataclasses.replace(forged_req, request_id="forged-wrong-valve-key", valve_admission_sig=spoof_sig)
            spoof_doc = spoof_req.to_spool_dict()
            spoof_doc["request_hmac_sha256"] = _spool_hmac_hex(k_hugo, _canonical_spool_request_hmac_input(spoof_doc))
            (hugo_spool / "order_request_forged-wrong-valve-key.json").write_text(json.dumps(spoof_doc), encoding="utf-8")
            emu.process_pending()
            rcpt2 = json.loads((hugo_spool / "order_receipt_forged-wrong-valve-key.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt2["status"], "REJECTED")
            self.assertEqual(rcpt2["retcode"], "10017")
            self.assertEqual(len(emu._positions), 0)

            # 5. Tampering volume/sl after valid Valve signing -> REFUSED!
            legit = sign_spool_valve_admission(
                dataclasses.replace(forged_req, request_id="tampered-volume-after-valve"),
                spool_dir=hugo_spool, key_dir=key_vault,
            )
            tampered_vol = dataclasses.replace(legit, volume_lots=D("5.00"))
            tampered_doc = tampered_vol.to_spool_dict()
            tampered_doc["request_hmac_sha256"] = _spool_hmac_hex(k_hugo, _canonical_spool_request_hmac_input(tampered_doc))
            (hugo_spool / "order_request_tampered-volume-after-valve.json").write_text(json.dumps(tampered_doc), encoding="utf-8")
            emu.process_pending()
            rcpt3 = json.loads((hugo_spool / "order_receipt_tampered-volume-after-valve.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt3["status"], "REJECTED")
            self.assertEqual(rcpt3["retcode"], "10017")
            self.assertEqual(len(emu._positions), 0)

            # 6. Genuine Valve-signed request through Mt5PaperBrokerVenue succeeds cleanly!
            tr = Mt5SpoolBridgeTransport(hugo_spool, key_dir=key_vault, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            creds = Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugo demo PRO5")
            gate = load_default_forex_valve_gate()
            venue = Mt5PaperBrokerVenue(broker_id=BROKER_HUGOSWAY_MT5, credentials=creds, transport=tr, valve_gate=gate, clock=clock)
            venue.connect()
            ord_ok = _open_order("legit-isolated-key-open", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))
            res_ok = venue.execute(ord_ok, valve_decision=_valve_decision(gate, ord_ok))
            self.assertTrue(res_ok.accepted)
            self.assertEqual(len(emu._positions), 1)

    # ------------------------------------------------------------------
    # Finding [9]: Full EA Sink Context Binding & Cross-Channel Replay Refusal
    # ------------------------------------------------------------------
    def test_finding_09_ea_sink_context_binding_and_cross_channel_replay_refusal(self) -> None:
        mq5 = MQ5_PATH.read_text(encoding="utf-8")
        # Static verification of all Finding [7] & [9] sink guards in CasForexMt5Bridge.mq5
        for required_snippet in (
            'string json_req_id = JsonGet(text, "request_id");',
            'json_req_id != request_id',
            'JsonGet(text, "channel_key_id") != g_channel_key_id',
            'NormalizeLowerTrim(JsonGet(text, "broker_channel")) != NormalizeLowerTrim(InpBrokerChannel)',
            'NormalizeLowerTrim(JsonGet(text, "server")) != NormalizeLowerTrim(AccountInfoString(ACCOUNT_SERVER))',
            'JsonGet(text, "execution_mode") != expected_mode',
            'VerifyValveAdmission(text)',
            'IsGlobalReplayIdSeen(request_id)',
            'DeriveChannelKey(',
            'ComputeChannelKeyId(',
            'cas-forex-valve-admission/1|',
        ):
            self.assertIn(required_snippet, mq5)

        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hugo_dir = root / "hugosway_mt5"
            lhfx_dir = root / "lhfx_mt5"
            emu_h = Mt5SpoolPaperTerminalEmulator(
                hugo_dir, server="Hugo demo PRO5", login=7001234, quotes=QUOTES, clock=clock
            )
            emu_l = Mt5SpoolPaperTerminalEmulator(
                lhfx_dir, server="LHFXSA-Demo", login=7001234, quotes=QUOTES, clock=clock
            )
            emu_h.publish_market()
            emu_l.publish_market()

            master = _load_or_create_spool_hmac_key(hugo_dir)
            k_hugo = derive_spool_channel_key(master, "hugosway_mt5")
            kid_hugo = spool_channel_key_id(k_hugo, "hugosway_mt5")

            def _make_signed_doc(req_id: str, **overrides: object) -> dict[str, str]:
                base = Mt5OrderRequest(
                    request_id=req_id, action="OPEN", symbol="EURUSD", side=Side.BUY,
                    volume_lots=D("0.10"), price=D("1.10010"), stop_loss=D("1.09500"),
                    position_ticket=None, deviation_points=20, magic=20261120, comment="f9",
                    created_at=T0, monotonic_nonce=1, issued_at=T0, expires_at=T0 + timedelta(seconds=30),
                    broker_channel="hugosway_mt5", channel_key_id=kid_hugo, account_login="7001234",
                    server="Hugo demo PRO5", execution_mode=EXECUTION_MODE_DEMO,
                    valve_decision_sha256="b" * 64,
                )
                req = sign_spool_valve_admission(dataclasses.replace(base, **overrides), spool_dir=hugo_dir)
                doc = req.to_spool_dict()
                doc["request_hmac_sha256"] = _spool_hmac_hex(k_hugo, _canonical_spool_request_hmac_input(doc))
                return doc

            # 1. Renamed file (filename != JSON request_id) -> REFUSED (10013)
            doc_ren = _make_signed_doc("req-real-id")
            (hugo_dir / "order_request_req-renamed-id.json").write_text(json.dumps(doc_ren), encoding="utf-8")
            emu_h.process_pending()
            rcpt_ren = json.loads((hugo_dir / "order_receipt_req-renamed-id.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_ren["status"], "REJECTED")
            self.assertEqual(rcpt_ren["retcode"], "10013")

            # 2. Mismatch each routing field independently -> REFUSED (10017)
            for case_id, overrides in (
                ("bad-channel", {"broker_channel": "lhfx_mt5"}),
                ("bad-key-id", {"channel_key_id": "0" * 16}),
                ("bad-server", {"server": "OtherBroker-Demo"}),
                ("bad-mode", {"execution_mode": EXECUTION_MODE_LIVE}),
                ("bad-login", {"account_login": "9999999"}),
            ):
                doc_bad = _make_signed_doc(case_id, **overrides)
                (hugo_dir / f"order_request_{case_id}.json").write_text(json.dumps(doc_bad), encoding="utf-8")
                emu_h.process_pending()
                rcpt_bad = json.loads((hugo_dir / f"order_receipt_{case_id}.json").read_text(encoding="utf-8"))
                self.assertEqual(rcpt_bad["status"], "REJECTED", f"expected refusal for {case_id}")
                self.assertEqual(rcpt_bad["retcode"], "10017", f"expected 10017 for {case_id}")
            self.assertEqual(len(emu_h._positions), 0)

            # 3. Copy a valid HUGOSWAY request into LHFX channel -> REFUSED (per-channel key + channel binding + global replay)!
            doc_valid = _make_signed_doc("req-valid-hugo-1")
            (hugo_dir / "order_request_req-valid-hugo-1.json").write_text(json.dumps(doc_valid), encoding="utf-8")
            emu_h.process_pending()
            rcpt_ok = json.loads((hugo_dir / "order_receipt_req-valid-hugo-1.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_ok["status"], "FILLED")

            (lhfx_dir / "order_request_req-valid-hugo-1.json").write_text(json.dumps(doc_valid), encoding="utf-8")
            emu_l.process_pending()
            rcpt_cross = json.loads((lhfx_dir / "order_receipt_req-valid-hugo-1.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_cross["status"], "REJECTED")
            self.assertEqual(len(emu_l._positions), 0)

            # Even if an attacker re-signs the same request_id for LHFX, global replay domain rejects duplicate request_id!
            k_lhfx = derive_spool_channel_key(master, "lhfx_mt5")
            kid_lhfx = spool_channel_key_id(k_lhfx, "lhfx_mt5")
            replayed_lhfx = sign_spool_valve_admission(
                Mt5OrderRequest(
                    request_id="req-valid-hugo-1", action="OPEN", symbol="EURUSD", side=Side.BUY,
                    volume_lots=D("0.10"), price=D("1.10010"), stop_loss=D("1.09500"),
                    position_ticket=None, deviation_points=20, magic=20261120, comment="cross-replay",
                    created_at=T0, monotonic_nonce=1, issued_at=T0, expires_at=T0 + timedelta(seconds=30),
                    broker_channel="lhfx_mt5", channel_key_id=kid_lhfx, account_login="7001234",
                    server="LHFXSA-Demo", execution_mode=EXECUTION_MODE_DEMO,
                    valve_decision_sha256="b" * 64,
                ),
                spool_dir=lhfx_dir,
            )
            doc_gl = replayed_lhfx.to_spool_dict()
            doc_gl["request_hmac_sha256"] = _spool_hmac_hex(k_lhfx, _canonical_spool_request_hmac_input(doc_gl))
            (lhfx_dir / "order_request_req-valid-hugo-1.json").write_text(json.dumps(doc_gl), encoding="utf-8")
            emu_l.process_pending()
            rcpt_gl = json.loads((lhfx_dir / "order_receipt_req-valid-hugo-1.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_gl["status"], "REJECTED")
            self.assertEqual(rcpt_gl["retcode"], "10013")
            self.assertEqual(len(emu_l._positions), 0)

    # ------------------------------------------------------------------
    # Finding [12]: Durable Journaled OANDA CLOSE & REDUCE + Drawdown Survival
    # ------------------------------------------------------------------
    def test_finding_12_oanda_journaled_close_reduce_positions_unknown_freeze_and_drawdown_survival(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            oanda_stub = _StatefulOandaTransport(nav="80000.00", margin_available="79000.00")
            journal = OandaMutationJournal(root / "oanda_close.sqlite3")
            env = {
                ENV_OANDA_PRACTICE_TOKEN: SYNTH_OANDA_PRACTICE_VAL,
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda_stub.account_id,
                "CAS_FOREX_PRIMARY_BROKER": BROKER_OANDA_PRACTICE,
            }
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(
                    e, transport=oanda_stub, mutation_journal=journal, clock=clock
                ),
                oanda_mutation_journal=journal,
                clock=clock,
            )
            router.activate_all()
            oanda_venue = router.venues[BROKER_OANDA_PRACTICE]
            assert isinstance(oanda_venue, OandaPracticeFallbackVenue)

            # 1. Open OANDA position (100,000 units)
            o_open = _open_order("oanda-f12-open", symbol="EURUSD", units=D("100000"), stop=D("1.09500"))
            ex_open = router.execute_open(o_open, valve_decision=_valve_decision(gate, o_open))
            self.assertTrue(ex_open.result.accepted)
            positions = oanda_venue.positions()
            self.assertEqual(len(positions), 1)
            tid = positions[0].ticket
            self.assertEqual(oanda_venue.position_units(tid), D("100000"))

            # 2. Partial REDUCE (40,000 units) via execute_management
            o_red = OrderIntent(
                order_id="oanda-f12-reduce", action_ref="act-oanda-f12-reduce",
                kind=ActionKind.REDUCE, symbol="EURUSD", quantity_units=D("40000"), position_ticket=tid,
            )
            res_red = router.execute_management(BROKER_OANDA_PRACTICE, o_red, valve_decision=_valve_decision(gate, o_red))
            self.assertTrue(res_red.accepted)
            self.assertEqual(res_red.oanda_receipt["status"], "REDUCED")  # type: ignore[index]
            self.assertEqual(oanda_venue.position_units(tid), D("60000"))

            # 3. Verify 15% drawdown blocks OPEN in Valve, while CLOSE remains ALLOWED and closes remaining 60,000 units!
            dd_view = {"balance": "80000", "equity": "68000", "peak_equity": "80000", "available_margin": "60000", "position_inventory": "[]"}
            dd_policy = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "100000", "max_drawdown_pct": "0.10"}
            close_prop = SimpleNamespace(
                request=SimpleNamespace(
                    request_id="req-dd-close",
                    facts=(),
                    evidence=(SimpleNamespace(evidence_id="ev-c1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-oanda", run_id="run-oanda"),
                        observed_at=clock(),
                        valid_until=clock() + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(selection=SimpleNamespace(evidence_ids=("ev-c1",), reason="emergency exit", selected_action_ref="act-oanda-f12-close")),
                intent=SimpleNamespace(
                    intent_id="oanda-f12-close", action_ref="act-oanda-f12-close", kind=ActionKind.CLOSE,
                    instrument_id="EURUSD", quantity=D("60000"), side=Side.SELL,
                    stop_price=None, limit_price=None, target_id=tid, take_profit_price=None,
                ),
            )
            dec_close = gate.require_admissible(close_prop, current_view=dd_view, policy=dd_policy, now=clock())
            self.assertTrue(dec_close.admitted)
            o_close = OrderIntent.from_action_intent(close_prop.intent, symbol="EURUSD", position_ticket=tid)
            res_close = router.execute_management(BROKER_OANDA_PRACTICE, o_close, valve_decision=dec_close)
            self.assertTrue(res_close.accepted)
            self.assertEqual(res_close.oanda_receipt["status"], "CLOSED")  # type: ignore[index]
            self.assertEqual(oanda_venue.positions(), ())

            # 4. Ambiguous CLOSE timeout freezes trade in journal and reconciles cleanly via tradesClosed
            o_open2 = _open_order("oanda-f12-open2", symbol="GBPUSD", units=D("20000"), stop=D("1.26500"))
            router.execute_open(o_open2, valve_decision=_valve_decision(gate, o_open2))
            tid2 = oanda_venue.positions()[0].ticket
            oanda_stub.fail_close = True
            o_close2 = OrderIntent(
                order_id="oanda-f12-close-unk", action_ref="act-oanda-f12-close-unk",
                kind=ActionKind.CLOSE, symbol="GBPUSD", quantity_units=D("20000"), position_ticket=tid2,
            )
            with self.assertRaises(OandaOutcomeUnknownError):
                router.execute_management(BROKER_OANDA_PRACTICE, o_close2, valve_decision=_valve_decision(gate, o_close2))
            self.assertTrue(journal.has_any_unresolved_mutation())
            # While frozen, new OPEN is latched
            with self.assertRaises(OandaOutcomeUnknownError):
                router.execute_open(_open_order("oanda-latched-open", symbol="EURUSD", units=D("10000"), stop=D("1.09500")), valve_decision=_valve_decision(gate, _open_order("oanda-latched-open", symbol="EURUSD", units=D("10000"), stop=D("1.09500"))))
            # Reconcile clears the latch via tradesClosed transaction history
            oanda_stub.fail_close = False
            rec = oanda_venue.reconcile_unknown_mutations(now=clock())
            self.assertEqual(rec["remaining_unknown"], 0)
            self.assertFalse(journal.has_any_unresolved_mutation())


if __name__ == "__main__":
    unittest.main()
