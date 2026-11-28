"""Regression security suite for all 7 findings from scan-bundle_(2).tar.gz (commit 02a0e0c).

Pure deterministic `unittest.TestCase` coverage with zero third-party test-runner imports, zero skips,
and zero external network traffic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import urllib.parse

_ROOT = Path(__file__).resolve().parents[2]
for _p in ("src", "", "tests/e2e_hardening"):
    _c = str((_ROOT / _p).resolve())
    if _c not in sys.path:
        sys.path.insert(0, _c)

from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    _EmergencyAdmissionHTTPServer,
    build_public_index_reference_map,
    stamp_public_index_provenance,
)
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.futures.tradovate_venue import (
    TradovateMicroFuturesPaperEmulator,
    TradovateOrderError,
)
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.treasury.profit_sweep import (
    OfframpSecurityError,
    OfframpTransportError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
    RAIL_KRAKEN_ACH,
    WITHDRAWAL_STATUS_NOT_STARTED,
    WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
    WITHDRAWAL_STATUS_PENDING,
    WITHDRAWAL_STATUS_SUBMITTED,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    ValveGrantError,
    ValveRefusalError,
    load_default_forex_valve_gate,
    verify_and_consume_valve_order_grant,
)
from cas_forex_revamp.venue.dual_shield_router import (
    QuoteReferenceUnavailableError,
    ReferenceQuote,
)
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    OandaOutcomeUnknownError,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.live_market_stream import PublicUsIndexFeedClient
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_OANDA_PRACTICE,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    Mt5Credentials,
    Mt5NativePythonTransport,
    Mt5OrderRequest,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5TransportError,
    OandaPracticeFallbackVenue,
    OrderIntent,
    _SpoolReplayLedger,
    _canonical_spool_request_hmac_input,
    _load_or_create_spool_hmac_key,
    _spool_hmac_hex,
    derive_spool_channel_key,
    provision_sealed_replay_ledger,
    sign_spool_valve_admission,
    spool_channel_key_id,
)

D = Decimal
T0 = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = _ROOT
MQ5_PATH = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"
QUOTES_BASIC = {"EURUSD": (D("1.10000"), D("1.10010"))}


def _amend_proposal(
    *,
    symbol: str = "EURUSD",
    stop_price: Decimal = D("1.09600"),
    side: Side | None = None,
    target_id: str | None = "pos-1",
    now: datetime = T0,
) -> SimpleNamespace:
    intent = SimpleNamespace(
        intent_id="ord-amend-sec",
        action_ref="act-amend-sec",
        kind=ActionKind.AMEND_STOP,
        instrument_id=symbol,
        quantity=None,
        side=side,
        stop_price=stop_price,
        limit_price=None,
        take_profit_price=None,
        target_id=target_id,
    )
    req = SimpleNamespace(
        request_id="req-amend-sec",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=now, valid_until=now + timedelta(minutes=5)),
    )
    sel = SimpleNamespace(
        evidence_ids=("ev-1",),
        reason="Tighten stop",
        selected_action_ref="act-amend-sec",
    )
    return SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)


def _open_proposal(
    *,
    symbol: str = "EURUSD",
    stop_price: Decimal = D("1.09500"),
    side: Side = Side.BUY,
    now: datetime = T0,
) -> SimpleNamespace:
    intent = SimpleNamespace(
        intent_id="ord-open-sec",
        action_ref="act-open-sec",
        kind=ActionKind.OPEN,
        instrument_id=symbol,
        quantity=D("1000"),
        side=side,
        stop_price=stop_price,
        limit_price=None,
        take_profit_price=D("1.11000"),
        target_id=None,
    )
    req = SimpleNamespace(
        request_id="req-open-sec",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=now, valid_until=now + timedelta(minutes=5)),
    )
    sel = SimpleNamespace(
        evidence_ids=("ev-1",),
        reason="Trend entry",
        selected_action_ref="act-open-sec",
    )
    return SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)


class _StrictOandaStub:
    def __init__(self, *, trade_stop: str | None = "1.09500", trade_side: str = "BUY") -> None:
        self.tx_seq = 100
        self.trade_stop = trade_stop
        self.trade_side = trade_side
        self.put_calls = 0
        self.open_trades: dict[str, dict[str, object]] = {
            "1001": {
                "id": "1001",
                "instrument": "EUR_USD",
                "currentUnits": "1000" if trade_side == "BUY" else "-1000",
                "price": "1.10000",
                "unrealizedPL": "0.00",
                "state": "OPEN",
                **({"stopLossOrder": {"price": trade_stop}} if trade_stop is not None else {}),
            }
        }
        self.custom_post_response: bytes | None = None
        self.custom_amend_response: bytes | None = None
        self.custom_close_response: bytes | None = None

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float, max_bytes: int
    ) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if method == "GET" and parsed.path.endswith("/summary"):
            return json.dumps({
                "account": {
                    "id": "101-001-9999999-001",
                    "currency": "USD",
                    "balance": "100000.00",
                    "NAV": "100000.00",
                    "unrealizedPL": "0.00",
                    "marginAvailable": "90000.00",
                    "openPositionCount": len(self.open_trades),
                    "lastTransactionID": str(self.tx_seq),
                }
            }).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/pricing"):
            return json.dumps({
                "prices": [{
                    "instrument": "EUR_USD",
                    "time": "2026-11-27T12:00:00Z",
                    "tradeable": True,
                    "bids": [{"price": "1.10000", "liquidity": 1000000}],
                    "asks": [{"price": "1.10010", "liquidity": 1000000}],
                }]
            }).encode("utf-8")
        if method == "GET" and parsed.path.endswith("/openTrades"):
            return json.dumps({
                "trades": list(self.open_trades.values()),
                "lastTransactionID": str(self.tx_seq),
            }).encode("utf-8")
        if method == "POST" and parsed.path.endswith("/orders"):
            if self.custom_post_response is not None:
                return self.custom_post_response
            order = json.loads((body or b"{}").decode("utf-8"))["order"]
            self.tx_seq += 1
            cid = str(self.tx_seq)
            self.tx_seq += 1
            fid = str(self.tx_seq)
            return json.dumps({
                "orderCreateTransaction": {"id": cid, "clientExtensions": order.get("clientExtensions", {})},
                "orderFillTransaction": {
                    "id": fid,
                    "accountID": "101-001-9999999-001",
                    "instrument": order["instrument"],
                    "units": order["units"],
                    "price": "1.10010",
                    "clientExtensions": order.get("clientExtensions", {}),
                },
                "lastTransactionID": fid,
            }).encode("utf-8")
        if method == "PUT" and parsed.path.endswith("/orders"):
            self.put_calls += 1
            if self.custom_amend_response is not None:
                return self.custom_amend_response
            self.tx_seq += 1
            doc = json.loads((body or b"{}").decode("utf-8"))
            tid = parsed.path.split("/")[-2]
            sl_b = doc.get("stopLoss") or {}
            return json.dumps({
                "stopLossOrderTransaction": {
                    "id": str(self.tx_seq),
                    "accountID": "101-001-9999999-001",
                    "tradeID": tid,
                    "price": sl_b.get("price", "1.09600"),
                    "clientExtensions": sl_b.get("clientExtensions", {}),
                },
                "lastTransactionID": str(self.tx_seq),
            }).encode("utf-8")
        if method == "PUT" and parsed.path.endswith("/close"):
            if self.custom_close_response is not None:
                return self.custom_close_response
            tid = parsed.path.split("/")[-2]
            self.tx_seq += 1
            cid = str(self.tx_seq)
            self.tx_seq += 1
            fid = str(self.tx_seq)
            self.open_trades.pop(tid, None)
            return json.dumps({
                "orderCreateTransaction": {"id": cid},
                "orderFillTransaction": {
                    "id": fid,
                    "accountID": "101-001-9999999-001",
                    "price": "1.10000",
                    "pl": "10.00",
                    "tradesClosed": [{"tradeID": tid, "units": "-1000", "realizedPL": "10.00"}],
                },
                "lastTransactionID": fid,
            }).encode("utf-8")
        raise AssertionError(f"Unexpected call {method} {url}")


class TestFinding01StopWideningPrevention(unittest.TestCase):
    def test_valve_and_grant_block_widened_or_unverified_amend_stop_even_in_drawdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            peak_store = PeakEquityStore(Path(td) / "peak.sqlite3")
            peak_store.observe_equity("acct:run", current_equity=D("100000"), opening_balance=D("100000"), now=T0)
            gate = load_default_forex_valve_gate(max_drawdown_pct=D("0.10"), peak_equity_store=peak_store)
            pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "500000", "max_drawdown_pct": "0.10"}

            # 12% drawdown view with BUY position at SL=1.09500
            dd_view = {
                "account_id": "acct",
                "run_id": "run",
                "balance": "88000",
                "equity": "88000",
                "peak_equity": "100000",
                "available_margin": "80000",
                "current_market": [{"instrument_id": "EURUSD", "bid": "1.10000", "ask": "1.10010"}],
                "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.09500"}],
            }

            # Widened BUY AMEND_STOP (1.09400 < 1.09500) blocked even during drawdown!
            with self.assertRaises(ValveRefusalError) as ctx_w:
                gate.require_admissible(_amend_proposal(stop_price=D("1.09400")), current_view=dd_view, policy=pol, now=T0 + timedelta(seconds=1))
            self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_w.exception.decision.hard_veto_reasons)

            # Empty/missing previous stop refused even without quotes or in drawdown
            no_prev_view = {**dd_view, "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY"}]}
            with self.assertRaises(ValveRefusalError) as ctx_np:
                gate.require_admissible(_amend_proposal(stop_price=D("1.09600")), current_view=no_prev_view, policy=pol, now=T0 + timedelta(seconds=1))
            self.assertIn("MISSING_AUTHORITATIVE_PREVIOUS_STOP", ctx_np.exception.decision.hard_veto_reasons)

            # Valid tightening BUY AMEND_STOP (1.09700 > 1.09500) admitted even during drawdown!
            dec_ok = gate.require_admissible(_amend_proposal(stop_price=D("1.09700")), current_view=dd_view, policy=pol, now=T0 + timedelta(seconds=1))
            self.assertTrue(dec_ok.admitted)

            # Direct protective grant minting rejects widened/missing previous_stop_loss
            with self.assertRaises(ValveGrantError):
                gate.issue_protective_order_grant(
                    broker_id=BROKER_OANDA_PRACTICE,
                    account_id="101-001-9999999-001",
                    server="api-fxpractice.oanda.com",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="AMEND_STOP",
                    symbol="EURUSD",
                    position_ticket="1001",
                    side=Side.BUY,
                    stop_loss=D("1.09400"),
                    previous_stop_loss=D("1.09500"),
                    now=T0,
                )

            # Grant verifier itself refuses replay or widened stop
            grant = gate.issue_protective_order_grant(
                broker_id=BROKER_OANDA_PRACTICE,
                account_id="101-001-9999999-001",
                server="api-fxpractice.oanda.com",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="AMEND_STOP",
                symbol="EURUSD",
                position_ticket="1001",
                side=Side.BUY,
                stop_loss=D("1.09700"),
                previous_stop_loss=D("1.09500"),
                now=T0,
            )
            with self.assertRaises(ValveGrantError):
                verify_and_consume_valve_order_grant(
                    grant,
                    broker_id=BROKER_OANDA_PRACTICE,
                    account_id="101-001-9999999-001",
                    server="api-fxpractice.oanda.com",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="AMEND_STOP",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=None,
                    stop_loss=D("1.09700"),
                    previous_stop_loss=D("1.09800"),
                    position_ticket="1001",
                    now=T0,
                    require_risk_reducing=True,
                )

    def test_oanda_mt5_tradovate_and_mq5_reject_stop_widening(self) -> None:
        gate = load_default_forex_valve_gate()

        # 1. OandaPracticePaperClient refuses widened SL before sending PUT
        stub = _StrictOandaStub(trade_stop="1.09500", trade_side="BUY")
        client = OandaPracticePaperClient.from_runtime_env(
            {ENV_OANDA_PRACTICE_TOKEN: "tok", ENV_OANDA_PRACTICE_ACCOUNT_ID: "101-001-9999999-001"},
            transport=stub,
            clock=lambda: T0,
        )
        grant_wide = gate.issue_protective_order_grant(
            broker_id=BROKER_OANDA_PRACTICE,
            account_id="101-001-9999999-001",
            server="api-fxpractice.oanda.com",
            execution_mode=EXECUTION_MODE_DEMO,
            action_kind="AMEND_STOP",
            symbol="EURUSD",
            position_ticket="1001",
            side=Side.BUY,
            stop_loss=D("1.09400"),
            previous_stop_loss=D("1.09400"),
            now=T0,
        )
        with self.assertRaises(ContractError):
            client.amend_trade_protection(trade_id="1001", stop_loss_price=D("1.09400"), symbol="EURUSD", valve_grant=grant_wide, now=T0)
        self.assertEqual(stub.put_calls, 0)

        # 2. MT5 spool emulator refuses widened BUY/SELL stops directly at terminal
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(sp, server="Hugo demo PRO5", login=7001234, quotes=QUOTES_BASIC, clock=lambda: T0)
            emu.publish_market()
            emu._positions["5001"] = {"symbol": "EURUSD", "side": Side.BUY, "volume": D("0.10"), "price_open": D("1.10010"), "sl": D("1.09500"), "tp": None}
            t = Mt5SpoolBridgeTransport(sp, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=lambda: T0)
            t.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugo demo PRO5"))
            req = Mt5OrderRequest(
                request_id="req-emu-widen-1",
                action="AMEND_STOP",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=None,
                price=None,
                stop_loss=D("1.09300"),
                position_ticket="5001",
                deviation_points=20,
                magic=2026,
                comment="widen",
                created_at=T0,
                valve_decision_sha256="a" * 64,
            )
            signed = sign_spool_valve_admission(t.prepare_request(req), spool_dir=sp, key_dir=t.key_dir, valve_key_file=t.valve_key_file)
            g_ok = gate.issue_protective_order_grant(
                broker_id=BROKER_HUGOSWAY_MT5, account_id="7001234", server="Hugo demo PRO5", execution_mode=EXECUTION_MODE_DEMO,
                action_kind="AMEND_STOP", symbol="EURUSD", position_ticket="5001", side=Side.BUY, stop_loss=D("1.09300"), previous_stop_loss=D("1.09300"), now=T0,
            )
            rcpt = t.send_order(signed, valve_grant=g_ok, require_risk_reducing=True, now=T0)
            self.assertFalse(rcpt.accepted)
            self.assertEqual(rcpt.retcode, 10016)
            self.assertEqual(emu._positions["5001"]["sl"], D("1.09500"))

        # 3. TradovateMicroFuturesPaperEmulator refuses widened stop
        from cas_forex_revamp.futures.tradovate_venue import _MutablePaperPosition
        tv = TradovateMicroFuturesPaperEmulator(starting_equity_usd=D("5000"), clock=lambda: T0)
        tv.connect()
        tv.set_quote("NAS100", D("21000.00"), D("21000.25"), observed_at=T0)
        tv._positions["pos-tv-1"] = _MutablePaperPosition(
            position_id="pos-tv-1",
            contract_code="MNQZ26",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=D("21000.25"),
            stop_loss_price=D("20975.25"),
            take_profit_price=D("21050.25"),
            used_margin_usd=D("200.00"),
            commission_usd=D("1.24"),
            opened_at=T0,
            updated_at=T0,
        )
        with self.assertRaises(TradovateOrderError):
            tv.amend_stop("pos-tv-1", D("20970.25"), now_utc=T0)

        # 4. CasForexMt5Bridge.mq5 static non-widening guard present
        mq5 = MQ5_PATH.read_text(encoding="utf-8")
        self.assertIn("PositionGetDouble(POSITION_SL)", mq5)
        self.assertIn("cannot widen BUY stop loss", mq5)
        self.assertIn("cannot widen SELL stop loss", mq5)


class TestFinding02YahooIndexTimestampProvenance(unittest.TestCase):
    @staticmethod
    def _price_for_url(url: str) -> float:
        if "NQ" in url or "NDX" in url:
            return 20500.0
        if "YM" in url or "DJI" in url:
            return 43800.0
        if "ES" in url or "GSPC" in url:
            return 6000.0
        return 2600.0

    def _yahoo_bytes(self, url: str, timestamps: list[int], closes: list[float] | None = None, rmt: int | None = None) -> bytes:
        price = self._price_for_url(url)
        c = closes if closes is not None else [price] * len(timestamps)
        meta: dict[str, object] = {"regularMarketPrice": price}
        if rmt is not None:
            meta["regularMarketTime"] = rmt
        return json.dumps({
            "chart": {
                "result": [{
                    "meta": meta,
                    "timestamp": timestamps,
                    "indicators": {"quote": [{"open": c, "high": c, "low": c, "close": c, "volume": [10] * len(c)}]},
                }]
            }
        }).encode("utf-8")

    def test_stale_missing_future_or_non_monotonic_provider_timestamps_fail_closed(self) -> None:
        now_ep = int(T0.timestamp())

        # Stale candles rejected even though local self._clock() is T0
        client_stale_c = PublicUsIndexFeedClient(
            transport=lambda u, *_a: self._yahoo_bytes(u, [now_ep - 900, now_ep - 840]),
            clock=lambda: T0,
        )
        with self.assertRaises(ContractError):
            client_stale_c.fetch_index_stream()

        # Stale regularMarketTime rejected even when candle is fresh
        client_stale_rmt = PublicUsIndexFeedClient(
            transport=lambda u, *_a: self._yahoo_bytes(u, [now_ep - 30], rmt=now_ep - 900),
            clock=lambda: T0,
        )
        with self.assertRaises(ContractError):
            client_stale_rmt.fetch_index_stream()

        # Missing both candles & regularMarketTime rejected
        client_missing = PublicUsIndexFeedClient(
            transport=lambda u, *_a: self._yahoo_bytes(u, [], closes=[]),
            clock=lambda: T0,
        )
        with self.assertRaises(ContractError):
            client_missing.fetch_index_stream()

        # Non-monotonic candle timestamps rejected
        client_nonmono = PublicUsIndexFeedClient(
            transport=lambda u, *_a: self._yahoo_bytes(u, [now_ep - 10, now_ep - 60]),
            clock=lambda: T0,
        )
        with self.assertRaises(ContractError):
            client_nonmono.fetch_index_stream()

        # Fresh valid stream preserves provider_observed_at (older than received_at) and never restamps
        prov_ep = now_ep - 120
        client_ok = PublicUsIndexFeedClient(
            transport=lambda u, *_a: self._yahoo_bytes(u, [prov_ep - 60, prov_ep], rmt=prov_ep),
            clock=lambda: T0,
        )
        doc = client_ok.fetch_index_stream()
        stamped = stamp_public_index_provenance(doc)
        ref_map = build_public_index_reference_map(stamped, ["NAS100"])
        self.assertEqual(ref_map["NAS100"]["provider_observed_at"], datetime.fromtimestamp(prov_ep, tz=timezone.utc).isoformat().replace("+00:00", "Z"))
        self.assertEqual(ref_map["NAS100"]["observed_at"], ref_map["NAS100"]["provider_observed_at"])

        # ReferenceQuote refuses received_at without provider_observed_at & enforces age using provider_observed_at
        with self.assertRaises(QuoteReferenceUnavailableError):
            ReferenceQuote.from_entry("NAS100", {
                "bid": "20499.00", "ask": "20501.00", "source_provider": "PUBLIC_US_INDEX_FEED",
                "source_broker_id": None, "is_independent_public": True,
                "observed_at": T0.isoformat().replace("+00:00", "Z"),
                "received_at": T0.isoformat().replace("+00:00", "Z"),
            })
        rq_stale = ReferenceQuote.from_entry("NAS100", {
            "bid": "20499.00", "ask": "20501.00", "source_provider": "PUBLIC_US_INDEX_FEED",
            "source_broker_id": None, "is_independent_public": True,
            "observed_at": T0.isoformat().replace("+00:00", "Z"),
            "provider_observed_at": (T0 - timedelta(seconds=900)).isoformat().replace("+00:00", "Z"),
            "received_at": T0.isoformat().replace("+00:00", "Z"),
        })
        with self.assertRaises(QuoteReferenceUnavailableError):
            rq_stale.assert_fresh(now=T0, max_age_seconds=300)


class TestFinding03OandaUnboundResponseFailClosed(unittest.TestCase):
    def test_unbound_empty_mismatched_and_replayed_oanda_responses_fail_closed(self) -> None:
        gate = load_default_forex_valve_gate()

        def _client(stub: _StrictOandaStub) -> OandaPracticePaperClient:
            return OandaPracticePaperClient.from_runtime_env(
                {ENV_OANDA_PRACTICE_TOKEN: "tok", ENV_OANDA_PRACTICE_ACCOUNT_ID: "101-001-9999999-001"},
                transport=stub,
                clock=lambda: T0,
            )

        def _open_grant(oid: str) -> object:
            dec = gate.require_admissible(_open_proposal(), current_view={"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": []}, now=T0)
            return gate.issue_order_grant(
                dec, broker_id=BROKER_OANDA_PRACTICE, account_id="101-001-9999999-001", server="api-fxpractice.oanda.com",
                execution_mode=EXECUTION_MODE_DEMO, action_kind="OPEN", symbol="EURUSD", side=Side.BUY, volume=D("1000"),
                stop_loss=D("1.09500"), take_profit=D("1.11000"), order_action_ref="act-open-sec", order_quantity_units=D("1000"), now=T0,
            )

        # 1. Empty {} POST /orders -> OandaOutcomeUnknownError
        s1 = _StrictOandaStub()
        s1.custom_post_response = b"{}"
        c1 = _client(s1)
        with self.assertRaises(OandaOutcomeUnknownError):
            c1.submit_paper_market_order(symbol="EURUSD", side=Side.BUY, units=D("1000"), client_order_id="o-empty", stop_loss_price=D("1.09500"), take_profit_price=D("1.11000"), valve_grant=_open_grant("o-empty"), now=T0)

        # 2. Wrong instrument in orderFillTransaction -> OandaOutcomeUnknownError
        s2 = _StrictOandaStub()
        s2.custom_post_response = json.dumps({
            "orderFillTransaction": {"id": "202", "instrument": "GBP_USD", "units": "1000", "price": "1.10010", "clientExtensions": {"id": "o-inst"}},
            "lastTransactionID": "202",
        }).encode()
        c2 = _client(s2)
        with self.assertRaises(OandaOutcomeUnknownError):
            c2.submit_paper_market_order(symbol="EURUSD", side=Side.BUY, units=D("1000"), client_order_id="o-inst", stop_loss_price=D("1.09500"), take_profit_price=D("1.11000"), valve_grant=_open_grant("o-inst"), now=T0)

        # 3. Unbound PUT /orders amend without stopLossOrderTransaction -> OandaOutcomeUnknownError
        s3 = _StrictOandaStub()
        s3.custom_amend_response = json.dumps({"lastTransactionID": "205"}).encode()
        c3 = _client(s3)
        ag = gate.issue_protective_order_grant(
            broker_id=BROKER_OANDA_PRACTICE, account_id="101-001-9999999-001", server="api-fxpractice.oanda.com",
            execution_mode=EXECUTION_MODE_DEMO, action_kind="AMEND_STOP", symbol="EURUSD", position_ticket="1001",
            side=Side.BUY, stop_loss=D("1.09600"), previous_stop_loss=D("1.09500"), now=T0,
        )
        with self.assertRaises(OandaOutcomeUnknownError):
            c3.amend_trade_protection(trade_id="1001", stop_loss_price=D("1.09600"), symbol="EURUSD", valve_grant=ag, now=T0)

        # 4. Wrong tradeID on close_trade -> OandaOutcomeUnknownError
        s4 = _StrictOandaStub()
        s4.custom_close_response = json.dumps({
            "orderFillTransaction": {"id": "209", "price": "1.10000", "pl": "5.00", "tradesClosed": [{"tradeID": "9999", "units": "-1000"}]},
            "lastTransactionID": "209",
        }).encode()
        c4 = _client(s4)
        cg = gate.issue_protective_order_grant(
            broker_id=BROKER_OANDA_PRACTICE, account_id="101-001-9999999-001", server="api-fxpractice.oanda.com",
            execution_mode=EXECUTION_MODE_DEMO, action_kind="CLOSE", symbol="EURUSD", position_ticket="1001", volume="ALL", now=T0,
        )
        with self.assertRaises(OandaOutcomeUnknownError):
            c4.close_trade(trade_id="1001", units="ALL", symbol="EURUSD", valve_grant=cg, now=T0)


class TestFinding04And06AchReconciliationAndRetryGuards(unittest.TestCase):
    def test_outcome_unknown_retry_blocked_until_complete_bound_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "vault.sqlite3"
            vault = ProfitSweepVault(db_path, clock=lambda: T0)
            vault.record_realized_close(trade_id="t1", symbol="EURUSD", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=D("500.00"), occurred_at=T0)
            rec = OwnerRecoveryVerifier(db_path=db_path, clock=lambda: T0)

            wd_calls = {"n": 0}
            class _StubCb:
                linked_bank_account_id = "pm-bank-1"
                def withdraw_usd_to_linked_bank_ach(self, **_kw: object) -> dict[str, str]:
                    wd_calls["n"] += 1
                    if wd_calls["n"] == 1:
                        raise OfframpTransportError("ambiguous ACH timeout")
                    return {"payout_id": "cb-ok-1", "status": "ACH_SUBMITTED"}

            cb = _StubCb()
            prep1 = vault.prepare_offramp_ach_payout(rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"), owner_request_id="r1", reason="sweep", coinbase_client=cb)
            tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep1["intent_sha256"], now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"), owner_request_id="r1", reason="sweep",
                    verifier=rec, recovery_token=tok1, coinbase_client=cb, intent_id=prep1["intent_id"], intent_sha256=prep1["intent_sha256"],
                )
            tid = str(prep1["transfer_id"])

            # Direct retry BEFORE reconciliation MUST fail closed (Finding [4])
            prep_r = vault.prepare_offramp_ach_payout(rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"), owner_request_id="r2", reason="retry", coinbase_client=cb, retry_transfer_id=tid)
            tok_r = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_r["intent_sha256"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"), owner_request_id="r2", reason="retry",
                    verifier=rec, recovery_token=tok_r, coinbase_client=cb, retry_transfer_id=tid,
                    intent_id=prep_r["intent_id"], intent_sha256=prep_r["intent_sha256"],
                )
            self.assertEqual(wd_calls["n"], 1)

            # Incomplete/truncated/unbound history MUST keep transfer UNRESOLVED (Finding [6])
            for bad_ev in (
                {"status": "NOT_FOUND", "history_complete": False},
                {"withdrawals": [], "history_complete": True, "truncated": True},
                {"status": "CANCELLED"},
                {"status": "SETTLED", "provider_tx_id": "tx-1", "destination_bank_id": "pm-bank-1", "amount_usd": "100.00"},
                {"status": "SETTLED", "provider_tx_id": "tx-1", "client_reference_id": f"ach-{tid}", "destination_bank_id": "pm-bank-1", "amount_usd": "100.00", "currency": "EUR"},
            ):
                p_u, _, _ = vault._parse_withdrawal_history_evidence(
                    evidence=bad_ev,
                    expected_client_ref=f"ach-{tid}",
                    expected_amount=D("100.00"),
                    expected_dest_bank="pm-bank-1",
                    expected_rail=RAIL_COINBASE_ACH,
                )
                self.assertEqual(p_u, "UNRESOLVED", msg=f"Should be UNRESOLVED for {bad_ev}")

            # Complete NOT_EXECUTED evidence clears status -> NOT_STARTED, allowing single clean retry
            rec_res = vault.reconcile_withdrawal_outcome(
                transfer_id=tid,
                exchange_history_checker=lambda q: {"status": "NOT_EXECUTED", "history_complete": True, "queried_client_reference_id": q["idempotency_key"]},
                owner_request_id="rec-1",
            )
            self.assertEqual(rec_res["withdrawal_status"], WITHDRAWAL_STATUS_NOT_STARTED)

            prep_ok = vault.prepare_offramp_ach_payout(rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"), owner_request_id="r3", reason="retry ok", coinbase_client=cb, retry_transfer_id=tid)
            tok_ok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_ok["intent_sha256"], now=T0)
            res = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"), owner_request_id="r3", reason="retry ok",
                verifier=rec, recovery_token=tok_ok, coinbase_client=cb, retry_transfer_id=tid,
                intent_id=prep_ok["intent_id"], intent_sha256=prep_ok["intent_sha256"],
            )
            self.assertEqual(res["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)
            self.assertEqual(wd_calls["n"], 2)


class TestFinding05Mt5ReplayLedgerDeletionResilience(unittest.TestCase):
    def test_sealed_hwm_and_key_dir_isolation_defeat_ledger_deletion_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool_dir = root / "spool" / "hugosway_mt5"
            key_dir = root / "isolated_keys"
            provision_sealed_replay_ledger(spool_dir, key_dir=key_dir, broker_channel="hugosway_mt5")
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir, server="Hugo demo PRO5", login=7001234, quotes=QUOTES_BASIC,
                key_dir=key_dir, clock=lambda: T0,
            )
            emu.publish_market()
            self.assertEqual(emu._replay_ledger.path.parent, key_dir)
            self.assertEqual(emu._global_replay_ledger.path.parent, key_dir)
            emu._replay_ledger.verify_and_record(request_id="req-seal-1", nonce=1)

            # 1. Deleting ledger JSON while .hwm exists MUST fail closed
            emu._replay_ledger.path.unlink()
            with self.assertRaises(Mt5TransportError):
                emu._replay_ledger.load()

            # 2. Deleting BOTH ledger + .hwm after in-memory HWM advance MUST still fail closed
            emu._replay_ledger._hwm_path.unlink()
            with self.assertRaises(Mt5TransportError):
                emu._replay_ledger.load()

            # 3. LIVE mode requires pre-sealed .hwm ledger via provision_sealed_replay_ledger
            live_spool = root / "live_spool" / "lhfx_mt5"
            live_keys = root / "live_keys"
            live_ledger = _SpoolReplayLedger(live_keys / ".lhfx_mt5.emu_replay.json", require_sealed_init=True)
            with self.assertRaises(Mt5TransportError):
                live_ledger.load()
            provision_sealed_replay_ledger(live_spool, key_dir=live_keys, broker_channel="lhfx_mt5")
            hmac_k = _load_or_create_spool_hmac_key(live_spool, key_dir=live_keys)
            live_ledger_ok = _SpoolReplayLedger(
                live_keys / ".lhfx_mt5.emu_replay.json",
                require_sealed_init=True,
                hmac_key_loader=lambda: hmac_k,
            )
            n, seen = live_ledger_ok.load()
            self.assertEqual(n, 0)
            self.assertEqual(seen, [])

        mq5 = MQ5_PATH.read_text(encoding="utf-8")
        for snippet in ("InpReplayStateDir", "ReplayStatePath(", "VerifyAndLoadSealedEaHwm(", "SaveSealedEaHwm(", "INIT_FAILED"):
            self.assertIn(snippet, mq5)


class TestFinding07EmergencyChannelAntiStarvation(unittest.TestCase):
    def test_owner_emergency_request_succeeds_under_continuous_churn_flood(self) -> None:
        class _UiStub:
            def resolveEvidence(self, body: dict) -> dict:
                return {}
            def prepareControl(self, body: dict) -> dict:
                return {}
            def prepareClose(self, body: dict) -> dict:
                return {}
            def requestReviewedClose(self, body: dict) -> dict:
                return {}
            def readCommand(self, cid: str) -> dict:
                return {}
            def readControl(self, body: dict) -> dict:
                return {"state": "NORMAL"}
            def requestControl(self, body: dict) -> dict:
                return {"status": "APPLIED", "action": body.get("action", "PAUSE_NEW_RISK")}

        with tempfile.TemporaryDirectory() as td:
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                ui_service=_UiStub(),
                max_emergency_connections=2,
                emergency_header_deadline_seconds=0.30,
                emergency_unix_socket="" if os.name != "posix" else (Path(td) / "emerg.sock"),
            )
            srv.start()
            # Blast 80 concurrent churning unauthenticated partial-header TCP sockets (>64 queue limit)
            churn_socks: list[socket.socket] = []
            try:
                emerg_port = srv.emergency_port
                for _ in range(80):
                    try:
                        s = socket.create_connection(("127.0.0.1", emerg_port), timeout=1.0)
                        s.sendall(f"POST /api/request-control HTTP/1.1\r\nHost: 127.0.0.1:{emerg_port}\r\n".encode("ascii"))
                        churn_socks.append(s)
                    except OSError:
                        pass

                t0 = time.monotonic()
                conn = http.client.HTTPConnection("127.0.0.1", emerg_port, timeout=2.0)
                hdrs = dict(srv.auth_headers())
                hdrs["Content-Type"] = "application/json"
                conn.request("POST", "/api/request-control", body=json.dumps({"action": "PAUSE_NEW_RISK"}).encode("utf-8"), headers=hdrs)
                resp = conn.getresponse()
                body_data = json.loads(resp.read().decode("utf-8"))
                elapsed = time.monotonic() - t0
                conn.close()
                self.assertEqual(resp.status, 200)
                self.assertEqual(body_data["status"], "APPLIED")
                self.assertLess(elapsed, 2.0)
            finally:
                for s in churn_socks:
                    try:
                        s.close()
                    except OSError:
                        pass
                srv.stop()


if __name__ == "__main__":
    unittest.main()
