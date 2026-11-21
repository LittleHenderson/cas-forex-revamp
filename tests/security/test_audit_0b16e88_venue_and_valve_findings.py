"""Security regression tests for PR #31 Audit 0b16e88 — Venue & Valve Findings [1], [5] (router), [7], [8], [9], [10].

Covers:
- Finding [9]: Unforgeable opaque LiveAuthorizationContext + TRADOVATE_FUTURES support + sink re-verification
- Finding [8]: Hardened immutable ValveDecision + opaque single-use order-bound ValveOrderGrant
- Finding [1]: No valve bypass on MT5 native, MT5 spool, and OANDA mutation methods + always-available protective grants
- Finding [7]: Mandatory native MT5 terminal account/server/mode/connected rebind immediately before every order_send
- Finding [10]: DualShieldBrokerRouter.execute_management & broker sinks strictly reject OPEN/ADD
- Finding [5] (router side): Strict ReferenceQuote provenance separation rejecting same-venue self-corroboration & unlabeled ticks
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from typing import Any

from cas_forex_revamp.composition.state_store import create_owner_only_file_atomic
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    ForexMetaValveGate,
    ValveDecision,
    ValveGrantError,
    ValveOrderGrant,
    ValveRefusalError,
    load_default_forex_valve_gate,
    verify_and_consume_valve_order_grant,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
    QuoteReferenceUnavailableError,
    ReferenceQuote,
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
    REQUIRED_LIVE_ARM_PHRASE,
    LiveBrokerEndpointForbiddenError,
    OandaMutationJournal,
    OandaPracticePaperClient,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    BROKER_TRADOVATE_FUTURES,
    ENV_LIVE_AUTH_KEY_FILE,
    ENV_LIVE_AUTH_TICKET_FILE,
    LIVE_ARM_CONFIRMATION_TEXT,
    LiveAuthorizationContext,
    LiveAuthorizationError,
    build_live_authorization_context,
    mint_live_authorization_bundle,
    mint_live_authorization_ticket,
    provision_live_auth_key,
    verify_live_authorization_context,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_LIVE,
    BROKER_OANDA_PRACTICE,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    MANAGEMENT_ACTION_KINDS,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5NativePythonTransport,
    Mt5OrderRequest,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5TransportError,
    Mt5ValveClearanceError,
    OandaPracticeFallbackVenue,
    OrderIntent,
    RiskIncreasingOrderIntent,
    RiskReducingOrderIntent,
    _RedactedSecret,
    load_mt5_credentials,
    sign_spool_valve_admission,
)

D = Decimal
T0 = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
QUOTES_FX = {
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.26500"), D("1.26512")),
    "USDJPY": (D("150.100"), D("150.115")),
    "NAS100": (D("20500.00"), D("20501.00")),
}


def _synth_val(slot: str) -> str:
    return f"test-fixture-{slot}-value-01"


class _Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _DriftableNativeSdk:
    """Fake MetaTrader5 SDK supporting runtime login/server/trade_mode/connected drift."""

    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_CONTEST = 1
    ACCOUNT_TRADE_MODE_REAL = 2
    TRADE_ACTION_DEAL = 1
    TRADE_ACTION_SLTP = 6
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    TRADE_RETCODE_DONE = 10009
    TRADE_RETCODE_DONE_PARTIAL = 10010
    POSITION_TYPE_BUY = 0
    POSITION_TYPE_SELL = 1

    def __init__(
        self,
        *,
        login: int = 7001234,
        server: str = "Hugo demo PRO5",
        trade_mode: int = 0,
        connected: bool = True,
    ) -> None:
        self.login_val = login
        self.server_val = server
        self.trade_mode_val = trade_mode
        self.connected_val = connected
        self.order_send_calls = 0
        self.shutdown_calls = 0
        self.positions_list: list[Any] = []

    def initialize(self, **_kw: Any) -> bool:
        return True

    def login(self, *_a: Any, **_kw: Any) -> bool:
        return True

    def shutdown(self) -> None:
        self.shutdown_calls += 1

    def last_error(self) -> tuple[int, str]:
        return (0, "OK")

    def terminal_info(self) -> Any:
        return SimpleNamespace(connected=self.connected_val)

    def account_info(self) -> Any:
        return SimpleNamespace(
            login=self.login_val,
            server=self.server_val,
            trade_mode=self.trade_mode_val,
            currency="USD",
            balance=100000.0,
            equity=100000.0,
            margin=0.0,
            margin_free=100000.0,
            leverage=500,
        )

    def symbol_select(self, _sym: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, sym: str) -> Any:
        bid, ask = QUOTES_FX.get(sym, (D("1.10000"), D("1.10010")))
        return SimpleNamespace(bid=float(bid), ask=float(ask), time_msc=1795176000000)

    def positions_get(self) -> tuple[Any, ...]:
        return tuple(self.positions_list)

    def order_send(self, payload: dict[str, Any]) -> Any:
        self.order_send_calls += 1
        return SimpleNamespace(
            retcode=self.TRADE_RETCODE_DONE,
            deal=900000 + self.order_send_calls,
            order=800000 + self.order_send_calls,
            volume=float(payload.get("volume", 0.1)),
            price=float(payload.get("price", 1.1001)),
            comment="ok",
        )


class _FakeOandaTransport:
    def __init__(self, *, account_id: str = "101-001-9999999-001", host: str = "api-fxpractice.oanda.com") -> None:
        self.account_id = account_id
        self.host = host
        self.mutation_calls: list[tuple[str, str]] = []
        self.tx_seq = 1000
        self.open_trades: dict[str, dict[str, Any]] = {}

    def __call__(
        self,
        method: str,
        url: str,
        _headers: dict[str, str],
        body: bytes | None,
        _timeout: float,
        _max_bytes: int,
    ) -> bytes:
        m = method.upper()
        if m == "GET" and url.endswith("/summary"):
            return json.dumps({
                "lastTransactionID": str(self.tx_seq),
                "account": {
                    "id": self.account_id,
                    "currency": "USD",
                    "balance": "80000.00",
                    "NAV": "80000.00",
                    "unrealizedPL": "0.00",
                    "marginAvailable": "78000.00",
                    "openPositionCount": len(self.open_trades),
                    "lastTransactionID": str(self.tx_seq),
                },
            }).encode("utf-8")
        if m == "GET" and "/openTrades" in url:
            return json.dumps({
                "lastTransactionID": str(self.tx_seq),
                "trades": list(self.open_trades.values()),
            }).encode("utf-8")
        if m == "GET" and "/pricing" in url:
            return json.dumps({
                "time": "2026-11-21T12:00:00.000000Z",
                "prices": [
                    {
                        "instrument": "EUR_USD",
                        "time": "2026-11-21T12:00:00.000000Z",
                        "bids": [{"price": "1.10000", "liquidity": 1000000}],
                        "asks": [{"price": "1.10010", "liquidity": 1000000}],
                        "tradeable": True,
                    }
                ],
            }).encode("utf-8")
        self.mutation_calls.append((m, url))
        self.tx_seq += 1
        tid = str(self.tx_seq)
        doc = json.loads(body.decode("utf-8")) if body else {}
        if m == "POST" and url.endswith("/orders"):
            ospec = doc["order"]
            self.open_trades[tid] = {
                "id": tid,
                "instrument": ospec["instrument"],
                "currentUnits": ospec["units"],
                "price": "1.10010",
                "unrealizedPL": "0.00",
                "state": "OPEN",
            }
            return json.dumps({
                "lastTransactionID": tid,
                "orderCreateTransaction": {"id": tid},
                "orderFillTransaction": {"id": tid, "price": "1.10010"},
            }).encode("utf-8")
        if m == "PUT" and url.endswith("/orders"):
            return json.dumps({"lastTransactionID": tid}).encode("utf-8")
        if m == "PUT" and url.endswith("/close"):
            parts = url.split("/")
            target_tid = parts[-2]
            if doc.get("units") == "ALL":
                self.open_trades.pop(target_tid, None)
            return json.dumps({
                "lastTransactionID": tid,
                "orderCreateTransaction": {"id": tid},
                "orderFillTransaction": {"id": tid, "price": "1.10050", "pl": "12.50"},
            }).encode("utf-8")
        raise AssertionError(f"Unexpected request {m} {url}")


def _admit_order(
    gate: ForexMetaValveGate,
    order: OrderIntent,
    *,
    now: datetime = T0,
    bid: str = "1.10000",
    ask: str = "1.10010",
    position_side: str | None = None,
) -> ValveDecision:
    inv: list[dict[str, Any]] = []
    if order.position_ticket is not None:
        inv.append({
            "ticket": order.position_ticket,
            "symbol": order.symbol,
            "side": position_side or "BUY",
            "stop_loss": "1.09400",
        })
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
    req = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=now, valid_until=now + timedelta(minutes=5)),
    )
    sel = SimpleNamespace(evidence_ids=("ev-1",), reason="ID=02 verified setup", selected_action_ref=order.action_ref)
    prop = SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)
    view = {
        "balance": "100000",
        "equity": "100000",
        "available_margin": "90000",
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


class Audit0b16e88VenueAndValveSecurityTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Finding [9]: Unforgeable opaque LiveAuthorizationContext
    # ------------------------------------------------------------------
    def test_finding_09_live_auth_context_cannot_be_synthesized_and_supports_tradovate(self) -> None:
        # 1. Direct construction fails closed
        with self.assertRaises(LiveAuthorizationError):
            LiveAuthorizationContext(
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="9001122",
                server="Hugo PRO5",
                execution_mode="LIVE",
                issued_at=T0,
                expires_at=T0 + timedelta(seconds=300),
                ticket_sha256="a" * 64,
            )

        # 2. object.__new__ + object.__setattr__ bypass fails verify_provenance & Mt5Credentials
        forged_ctx = object.__new__(LiveAuthorizationContext)
        for k, v in [
            ("broker_id", BROKER_HUGOSWAY_MT5),
            ("account_id", "9001122"),
            ("server", "Hugo PRO5"),
            ("execution_mode", "LIVE"),
            ("issued_at", T0),
            ("expires_at", T0 + timedelta(seconds=300)),
            ("ticket_sha256", "a" * 64),
            ("arm_phrase_verified", True),
            ("_provenance_seal", "b" * 64),
            ("_mint_token", object()),
            ("_key_file", None),
            ("_ticket_json", None),
            ("_ticket_nonce", "n" * 32),
        ]:
            object.__setattr__(forged_ctx, k, v)
        with self.assertRaises(LiveAuthorizationError):
            forged_ctx.verify_provenance(now=T0)
        with self.assertRaises(LiveAuthorizationError):
            Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5,
                login=9001122,
                server="Hugo PRO5",
                password=_RedactedSecret(_synth_val("mt5-live")),
                execution_mode=EXECUTION_MODE_LIVE,
                live_auth_context=forged_ctx,
            )

        # 3. LIVE Mt5Credentials without context fails closed
        with self.assertRaises(LiveAuthorizationError):
            Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5,
                login=9001122,
                server="Hugo PRO5",
                password=_RedactedSecret(_synth_val("mt5-live")),
                execution_mode=EXECUTION_MODE_LIVE,
                live_auth_context=None,
            )

        # 4. Unverified build_live_authorization_context fails closed
        with self.assertRaises(LiveAuthorizationError):
            build_live_authorization_context({
                "protocol": "cas-forex-live-auth/1",
                "execution_mode": "LIVE",
                "broker_id": BROKER_HUGOSWAY_MT5,
                "account_login": "9001122",
                "server": "Hugo PRO5",
                "issued_at_utc": "2026-11-21T12:00:00Z",
                "expires_at_utc": "2026-11-21T12:05:00Z",
                "nonce": "1" * 32,
                "hmac_sha256": "c" * 64,
            })

        # 5. TRADOVATE_FUTURES supported; unknown broker rejected; key rotation invalidates sink
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kp = provision_live_auth_key(root / "owner_live.key")
            with self.assertRaises(LiveAuthorizationError):
                mint_live_authorization_ticket(
                    key_file=kp,
                    broker_id="UNTRUSTED_BROKER",
                    account_login="12345",
                    server="live.example.com",
                    ttl_seconds=300,
                    issued_at=T0,
                )
            tv_tkt = mint_live_authorization_ticket(
                key_file=kp,
                broker_id=BROKER_TRADOVATE_FUTURES,
                account_login="TV-LIVE-888",
                server="live.tradovateapi.com",
                ttl_seconds=300,
                issued_at=T0,
            )
            _, tv_ctx = verify_live_authorization_context(
                tv_tkt,
                key_file=kp,
                expected_broker_id=BROKER_TRADOVATE_FUTURES,
                expected_account_login="TV-LIVE-888",
                expected_server="live.tradovateapi.com",
                live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
                require_arm_phrase=True,
                now=T0,
            )
            self.assertTrue(tv_ctx.arm_phrase_verified)
            tv_ctx.verify_provenance(now=T0, require_arm_phrase=True)
            # Cross-broker context rejected on Mt5Credentials
            with self.assertRaises(LiveAuthorizationError):
                Mt5Credentials(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    login=9001122,
                    server="Hugo PRO5",
                    password=_RedactedSecret(_synth_val("mt5-live")),
                    execution_mode=EXECUTION_MODE_LIVE,
                    live_auth_context=tv_ctx,
                )
            # Rotate key on disk -> live re-verification at sink fails closed!
            mt5_tkt = mint_live_authorization_ticket(
                key_file=kp,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_login="9001122",
                server="Hugo PRO5",
                ttl_seconds=300,
                issued_at=T0,
            )
            tkt_path = root / "mt5_live_ticket.json"
            create_owner_only_file_atomic(
                tkt_path.parent,
                tkt_path.name,
                json.dumps(mt5_tkt).encode("utf-8"),
                replace_existing=True,
                label="LIVE auth ticket",
            )
            live_env = {
                ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
                ENV_LIVE_AUTH_KEY_FILE: str(kp),
                ENV_LIVE_AUTH_TICKET_FILE: str(tkt_path),
                ENV_HUGOSWAY_MT5_LOGIN: "9001122",
                ENV_HUGOSWAY_MT5_PASSWORD: _synth_val("mt5-pw"),
                ENV_HUGOSWAY_MT5_SERVER: "Hugo PRO5",
            }
            live_creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, live_env, now=T0)
            self.assertIsNotNone(live_creds)
            sdk = _DriftableNativeSdk(login=9001122, server="Hugo PRO5", trade_mode=2)
            clock = _Clock(T0)
            native = Mt5NativePythonTransport(mt5_module=sdk, clock=clock)
            native.connect(live_creds)  # type: ignore[arg-type]
            # Overwrite key file with different 32-byte key -> sink re-verification MUST fail closed
            kp.write_text(("f" * 64) + "\n", encoding="ascii")
            gate = load_default_forex_valve_gate()
            req = Mt5OrderRequest(
                request_id="live-revoked-1",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=20,
                magic=20261121,
                comment="live",
                created_at=T0,
            )
            ord_intent = OrderIntent(
                order_id="live-revoked-1",
                action_ref="act-live-rev-1",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            dec = _admit_order(gate, ord_intent, now=T0)
            grant = gate.issue_order_grant(
                dec,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="9001122",
                server="Hugo PRO5",
                execution_mode=EXECUTION_MODE_LIVE,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                order_action_ref=ord_intent.action_ref,
                order_quantity_units=ord_intent.quantity_units,
                now=T0,
            )
            with self.assertRaises(LiveAuthorizationError):
                native.send_order(req, valve_grant=grant)
            self.assertEqual(sdk.order_send_calls, 0)

    # ------------------------------------------------------------------
    # Finding [8] & Finding [1]: Order-bound single-use ValveOrderGrant & No Bypass
    # ------------------------------------------------------------------
    def test_finding_08_and_01_valve_grant_binding_replay_expiry_and_no_bypass(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _Clock(T0)
        order = OrderIntent(
            order_id="ord-f8-1",
            action_ref="act-f8-1",
            kind=ActionKind.OPEN,
            symbol="EURUSD",
            quantity_units=D("10000"),
            side=Side.BUY,
            stop_price=D("1.09500"),
            take_profit_price=D("1.11000"),
        )
        dec = _admit_order(gate, order, now=clock())

        # 1. ValveDecision is immutable including features mapping
        with self.assertRaises(TypeError):
            dec.features["missing_accounting_ratio"] = 0.99  # type: ignore[index]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            dec.admitted = False  # type: ignore[misc]

        # 2. Manually synthesized ValveDecision is refused at venue & grant issuance
        fake_dec = ValveDecision(
            admitted=True,
            valve_mode="ADMIT",
            mlp_score=0.99,
            threshold=0.55,
            mlp_admitted=True,
            hard_veto=False,
            hard_veto_reasons=(),
            features={},
            weights_sha256=gate.weights_sha256,
            request_id="req-fake",
            selected_action_ref=order.action_ref,
        )
        with self.assertRaises(ValveGrantError):
            gate.issue_order_grant(
                fake_dec,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                take_profit=D("1.11000"),
                order_action_ref=order.action_ref,
                order_quantity_units=order.quantity_units,
                now=clock(),
            )

        # 3. Direct ValveOrderGrant construction fails closed
        with self.assertRaises(ValveGrantError):
            ValveOrderGrant(
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side="BUY",
                volume="0.1",
                stop_loss="1.095",
                take_profit="1.11",
                position_ticket="",
                grant_nonce="a" * 32,
                issued_at=T0,
                expires_at=T0 + timedelta(seconds=30),
                weights_sha256=gate.weights_sha256,
                decision_sha256="b" * 64,
                risk_reducing=False,
                order_digest_sha256="c" * 64,
                signature_hmac_sha256="d" * 64,
            )

        # 4. Tampering ANY order field after Valve evaluation fails closed
        sdk = _DriftableNativeSdk(login=7001234, server="Hugo demo PRO5", trade_mode=0)
        creds = Mt5Credentials(
            broker_id=BROKER_HUGOSWAY_MT5,
            login=7001234,
            server="Hugo demo PRO5",
            password=_RedactedSecret(_synth_val("demo-pw")),
        )
        native = Mt5NativePythonTransport(mt5_module=sdk, clock=clock)
        native.connect(creds)

        # Missing grant at native transport sink MUST fail closed (Finding [1])
        req = Mt5OrderRequest(
            request_id="req-native-1",
            action="OPEN",
            symbol="EURUSD",
            side=Side.BUY,
            volume_lots=D("0.10"),
            price=D("1.10010"),
            stop_loss=D("1.09500"),
            take_profit=D("1.11000"),
            position_ticket=None,
            deviation_points=20,
            magic=20261121,
            comment="test",
            created_at=clock(),
        )
        with self.assertRaises(ValveGrantError):
            native.send_order(req)
        self.assertEqual(sdk.order_send_calls, 0)

        # Issue valid grant for exact order
        grant = gate.issue_order_grant(
            dec,
            broker_id=BROKER_HUGOSWAY_MT5,
            account_id="7001234",
            server="Hugo demo PRO5",
            execution_mode=EXECUTION_MODE_DEMO,
            action_kind="OPEN",
            symbol="EURUSD",
            side=Side.BUY,
            volume=D("0.10"),
            stop_loss=D("1.09500"),
            take_profit=D("1.11000"),
            order_action_ref=order.action_ref,
            order_quantity_units=order.quantity_units,
            now=clock(),
            ttl_seconds=30.0,
        )

        # Replaying the same ValveDecision on the same broker/account MUST fail closed
        with self.assertRaises(ValveGrantError):
            gate.issue_order_grant(
                dec,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                take_profit=D("1.11000"),
                order_action_ref=order.action_ref,
                order_quantity_units=order.quantity_units,
                now=clock(),
            )

        # Tampered volume / symbol / side / stop_loss / take_profit rejected without consuming
        for bad_req in (
            dataclasses.replace(req, volume_lots=D("0.20")),
            dataclasses.replace(req, symbol="GBPUSD"),
            dataclasses.replace(req, side=Side.SELL),
            dataclasses.replace(req, stop_loss=D("1.09000")),
            dataclasses.replace(req, take_profit=D("1.12000")),
        ):
            with self.assertRaises(ValveGrantError):
                native.send_order(bad_req, valve_grant=grant)
        self.assertEqual(sdk.order_send_calls, 0)

        # Exact matching request succeeds once
        rcpt = native.send_order(req, valve_grant=grant)
        self.assertTrue(rcpt.accepted)
        self.assertEqual(sdk.order_send_calls, 1)

        # Replaying the exact same consumed grant MUST fail closed
        with self.assertRaises(ValveGrantError):
            native.send_order(dataclasses.replace(req, request_id="req-native-replay"), valve_grant=grant)
        self.assertEqual(sdk.order_send_calls, 1)

        # Expired grant fails closed
        order2 = OrderIntent(
            order_id="ord-f8-exp",
            action_ref="act-f8-exp",
            kind=ActionKind.OPEN,
            symbol="EURUSD",
            quantity_units=D("10000"),
            side=Side.BUY,
            stop_price=D("1.09500"),
        )
        dec2 = _admit_order(gate, order2, now=clock())
        grant_exp = gate.issue_order_grant(
            dec2,
            broker_id=BROKER_HUGOSWAY_MT5,
            account_id="7001234",
            server="Hugo demo PRO5",
            execution_mode=EXECUTION_MODE_DEMO,
            action_kind="OPEN",
            symbol="EURUSD",
            side=Side.BUY,
            volume=D("0.10"),
            stop_loss=D("1.09500"),
            order_action_ref=order2.action_ref,
            order_quantity_units=order2.quantity_units,
            now=clock(),
            ttl_seconds=10.0,
        )
        clock.advance(15.0)
        with self.assertRaises(ValveGrantError):
            native.send_order(
                dataclasses.replace(req, request_id="req-native-exp", take_profit=None),
                valve_grant=grant_exp,
            )
        self.assertEqual(sdk.order_send_calls, 1)

        # 5. OANDA client refuses ALL raw mutations without valid grant (Finding [1])
        oanda_stub = _FakeOandaTransport()
        oanda_client = OandaPracticePaperClient.from_runtime_env(
            {
                ENV_OANDA_PRACTICE_TOKEN: _synth_val("oanda-prac"),
                ENV_OANDA_PRACTICE_ACCOUNT_ID: "101-001-9999999-001",
            },
            transport=oanda_stub,
            clock=clock,
        )
        with self.assertRaises(ValveGrantError):
            oanda_client.submit_paper_market_order(
                symbol="EURUSD", side=Side.BUY, units=D("1000"), client_order_id="o-no-grant", stop_loss_price=D("1.09500")
            )
        with self.assertRaises(ValveGrantError):
            oanda_client.amend_trade_protection(trade_id="1001", stop_loss_price=D("1.09600"))
        with self.assertRaises(ValveGrantError):
            oanda_client.close_trade(trade_id="1001", units="ALL")
        with self.assertRaises(ValveGrantError):
            oanda_client._request("POST", "accounts/101-001-9999999-001/orders", body_obj={})
        self.assertEqual(len(oanda_stub.mutation_calls), 0)

        # 6. Protective risk-reducing grants: always admit CLOSE/REDUCE/AMEND_STOP, reject OPEN/ADD
        with self.assertRaises(ValveGrantError):
            gate.issue_protective_order_grant(
                broker_id=BROKER_OANDA_PRACTICE,
                account_id="101-001-9999999-001",
                server="api-fxpractice.oanda.com",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                position_ticket="1001",
                volume=D("1000"),
                now=clock(),
            )
        with self.assertRaises(ValveGrantError):
            gate.issue_protective_order_grant(
                broker_id=BROKER_OANDA_PRACTICE,
                account_id="101-001-9999999-001",
                server="api-fxpractice.oanda.com",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="ADD",
                symbol="EURUSD",
                position_ticket="1001",
                volume=D("1000"),
                now=clock(),
            )
        # Open an OANDA trade with valid grant, then emergency CLOSE via protective grant
        o_ord = OrderIntent(
            order_id="ord-oanda-1",
            action_ref="act-oanda-1",
            kind=ActionKind.OPEN,
            symbol="EURUSD",
            quantity_units=D("1000"),
            side=Side.BUY,
            stop_price=D("1.09500"),
        )
        o_dec = _admit_order(gate, o_ord, now=clock())
        o_grant = gate.issue_order_grant(
            o_dec,
            broker_id=BROKER_OANDA_PRACTICE,
            account_id="101-001-9999999-001",
            server="api-fxpractice.oanda.com",
            execution_mode=EXECUTION_MODE_DEMO,
            action_kind="OPEN",
            symbol="EURUSD",
            side=Side.BUY,
            volume=D("1000"),
            stop_loss=D("1.09500"),
            order_action_ref=o_ord.action_ref,
            order_quantity_units=o_ord.quantity_units,
            now=clock(),
        )
        o_rcpt = oanda_client.submit_paper_market_order(
            symbol="EURUSD",
            side=Side.BUY,
            units=D("1000"),
            client_order_id="ord-oanda-1",
            stop_loss_price=D("1.09500"),
            valve_grant=o_grant,
            now=clock(),
        )
        self.assertEqual(o_rcpt["status"], "FILLED")
        open_tid = o_rcpt["fill_transaction_id"]
        prot_close_grant = gate.issue_protective_order_grant(
            broker_id=BROKER_OANDA_PRACTICE,
            account_id="101-001-9999999-001",
            server="api-fxpractice.oanda.com",
            execution_mode=EXECUTION_MODE_DEMO,
            action_kind="CLOSE",
            symbol="EURUSD",
            position_ticket=open_tid,
            volume="ALL",
            reason="EMERGENCY_KILL_SWITCH",
            now=clock(),
        )
        cls_rcpt = oanda_client.close_trade(
            trade_id=open_tid,
            units="ALL",
            symbol="EURUSD",
            valve_grant=prot_close_grant,
            now=clock(),
        )
        self.assertEqual(cls_rcpt["status"], "CLOSED")
        # Replay of protective grant MUST fail closed
        with self.assertRaises(ValveGrantError):
            oanda_client.close_trade(
                trade_id=open_tid,
                units="ALL",
                symbol="EURUSD",
                valve_grant=prot_close_grant,
                now=clock(),
            )

        # 7. Spool transport also refuses send_order without valid ValveOrderGrant
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir, server="Hugo demo PRO5", login=7001234, quotes=QUOTES_FX, clock=clock
            )
            emu.publish_market()
            sp_tr = Mt5SpoolBridgeTransport(spool_dir, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            sp_tr.connect(creds)
            sp_req = sign_spool_valve_admission(
                sp_tr.prepare_request(
                    Mt5OrderRequest(
                        request_id="sp-no-grant-1",
                        action="OPEN",
                        symbol="EURUSD",
                        side=Side.BUY,
                        volume_lots=D("0.10"),
                        price=D("1.10010"),
                        stop_loss=D("1.09500"),
                        position_ticket=None,
                        deviation_points=20,
                        magic=20261121,
                        comment="sp",
                        created_at=clock(),
                        valve_decision_sha256="a" * 64,
                    )
                ),
                spool_dir=spool_dir,
            )
            with self.assertRaises(ValveGrantError):
                sp_tr.send_order(sp_req)
            self.assertEqual(list(spool_dir.glob("order_request_*.json")), [])

    # ------------------------------------------------------------------
    # Finding [7]: Rebind native MT5 terminal account before EVERY order_send
    # ------------------------------------------------------------------
    def test_finding_07_native_mt5_rebinds_terminal_account_before_every_order_send(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _Clock(T0)
        creds = Mt5Credentials(
            broker_id=BROKER_HUGOSWAY_MT5,
            login=7001234,
            server="Hugo demo PRO5",
            password=_RedactedSecret(_synth_val("demo-pw")),
        )

        def _make_req_and_grant(tag: str) -> tuple[Mt5OrderRequest, ValveOrderGrant]:
            o = OrderIntent(
                order_id=f"ord-f7-{tag}",
                action_ref=f"act-f7-{tag}",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            d = _admit_order(gate, o, now=clock())
            g = gate.issue_order_grant(
                d,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                order_action_ref=o.action_ref,
                order_quantity_units=o.quantity_units,
                now=clock(),
            )
            r = Mt5OrderRequest(
                request_id=f"req-f7-{tag}",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=20,
                magic=20261121,
                comment="f7",
                created_at=clock(),
            )
            return r, g

        # Case A: login drift mid-session shuts down transport and blocks order_send
        sdk_a = _DriftableNativeSdk(login=7001234, server="Hugo demo PRO5", trade_mode=0)
        tr_a = Mt5NativePythonTransport(mt5_module=sdk_a, clock=clock)
        tr_a.connect(creds)
        r1, g1 = _make_req_and_grant("ok")
        self.assertTrue(tr_a.send_order(r1, valve_grant=g1).accepted)
        self.assertEqual(sdk_a.order_send_calls, 1)

        sdk_a.login_val = 9998888  # terminal switched accounts!
        r2, g2 = _make_req_and_grant("login-drift")
        with self.assertRaises(Mt5TransportError):
            tr_a.send_order(r2, valve_grant=g2)
        self.assertEqual(sdk_a.order_send_calls, 1)
        self.assertEqual(sdk_a.shutdown_calls, 1)
        # Transport is now disconnected; even if login reverts, reconnect is required!
        sdk_a.login_val = 7001234
        r3, g3 = _make_req_and_grant("must-reconnect")
        with self.assertRaises(Mt5TransportError):
            tr_a.send_order(r3, valve_grant=g3)
        self.assertEqual(sdk_a.order_send_calls, 1)

        # Case B: server drift mid-session
        sdk_b = _DriftableNativeSdk(login=7001234, server="Hugo demo PRO5", trade_mode=0)
        tr_b = Mt5NativePythonTransport(mt5_module=sdk_b, clock=clock)
        tr_b.connect(creds)
        sdk_b.server_val = "Hugosway-Demo"
        rb, gb = _make_req_and_grant("srv-drift")
        with self.assertRaises(Mt5TransportError):
            tr_b.send_order(rb, valve_grant=gb)
        self.assertEqual(sdk_b.order_send_calls, 0)
        self.assertGreaterEqual(sdk_b.shutdown_calls, 1)

        # Case C: trade_mode drift DEMO -> REAL mid-session
        sdk_c = _DriftableNativeSdk(login=7001234, server="Hugo demo PRO5", trade_mode=0)
        tr_c = Mt5NativePythonTransport(mt5_module=sdk_c, clock=clock)
        tr_c.connect(creds)
        sdk_c.trade_mode_val = 2  # REAL!
        rc, gc = _make_req_and_grant("mode-drift")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            tr_c.send_order(rc, valve_grant=gc)
        self.assertEqual(sdk_c.order_send_calls, 0)
        self.assertGreaterEqual(sdk_c.shutdown_calls, 1)

        # Case D: terminal_info().connected becomes False
        sdk_d = _DriftableNativeSdk(login=7001234, server="Hugo demo PRO5", trade_mode=0, connected=True)
        tr_d = Mt5NativePythonTransport(mt5_module=sdk_d, clock=clock)
        tr_d.connect(creds)
        sdk_d.connected_val = False
        rd, gd = _make_req_and_grant("disconnected")
        with self.assertRaises(Mt5TransportError):
            tr_d.send_order(rd, valve_grant=gd)
        self.assertEqual(sdk_d.order_send_calls, 0)
        self.assertGreaterEqual(sdk_d.shutdown_calls, 1)

    # ------------------------------------------------------------------
    # Finding [10]: execute_management strictly rejects OPEN/ADD
    # ------------------------------------------------------------------
    def test_finding_10_execute_management_and_sinks_reject_open_and_add(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _Clock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool_h = root / "hugosway_mt5"
            emu_h = Mt5SpoolPaperTerminalEmulator(
                spool_h, server="Hugo demo PRO5", login=7001234, quotes=QUOTES_FX, balance=D("12000"), clock=clock
            )
            emu_h.publish_market()
            tr_h = Mt5SpoolBridgeTransport(spool_h, sleep=emu_h.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            creds_h = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
            venue_h = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5, credentials=creds_h, transport=tr_h, valve_gate=gate, clock=clock
            )
            venue_h.connect()

            oanda_stub = _FakeOandaTransport()
            oanda_client = OandaPracticePaperClient.from_runtime_env(
                {
                    ENV_OANDA_PRACTICE_TOKEN: _synth_val("oanda-prac"),
                    ENV_OANDA_PRACTICE_ACCOUNT_ID: "101-001-9999999-001",
                },
                transport=oanda_stub,
                clock=clock,
            )
            venue_o = OandaPracticeFallbackVenue(client=oanda_client, valve_gate=gate, clock=clock)
            venue_o.connect()

            router = DualShieldBrokerRouter(
                environ={},
                valve_gate=gate,
                barbell=BarbellCapitalPolicy(demo_virtual_sleeve=True),
                oracle=OandaQuoteTruthOracle.from_static_quotes(QUOTES_FX),
                clock=clock,
            )
            router.attach_venue(venue_h)
            router.attach_venue(venue_o)

            open_order = OrderIntent(
                order_id="ord-f10-open",
                action_ref="act-f10-open",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            dec_open = _admit_order(gate, open_order, now=clock())

            # 1. Router execute_management rejects OPEN on BOTH MT5 and OANDA
            with self.assertRaises(ContractError):
                router.execute_management(BROKER_HUGOSWAY_MT5, open_order, valve_decision=dec_open)
            with self.assertRaises(ContractError):
                router.execute_management(BROKER_OANDA_PRACTICE, open_order, valve_decision=dec_open)
            with self.assertRaises(ContractError):
                router.execute_management(
                    BROKER_HUGOSWAY_MT5,
                    RiskIncreasingOrderIntent(open_order),  # type: ignore[arg-type]
                    valve_decision=dec_open,
                )
            with self.assertRaises(ContractError):
                RiskReducingOrderIntent(open_order)
            self.assertEqual(len(venue_h.positions), 0)
            self.assertEqual(len(oanda_stub.mutation_calls), 0)

            # 2. Venue sink & grant check also reject OPEN when require_risk_reducing=True
            with self.assertRaises(ContractError):
                venue_h.execute(
                    open_order,
                    valve_decision=dec_open,
                    allowed_actions=MANAGEMENT_ACTION_KINDS,
                    require_risk_reducing=True,
                )
            with self.assertRaises(ContractError):
                venue_o.execute(
                    open_order,
                    valve_decision=dec_open,
                    allowed_actions=MANAGEMENT_ACTION_KINDS,
                    require_risk_reducing=True,
                )
            open_grant = gate.issue_order_grant(
                dec_open,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                order_action_ref=open_order.action_ref,
                order_quantity_units=open_order.quantity_units,
                now=clock(),
            )
            with self.assertRaises(ValveGrantError):
                verify_and_consume_valve_order_grant(
                    open_grant,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_id="7001234",
                    server="Hugo demo PRO5",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=D("0.10"),
                    stop_loss=D("1.09500"),
                    now=clock(),
                    require_risk_reducing=True,
                )

            # 3. Legitimate OPEN via execute_open + CLOSE via execute_management (RiskReducingOrderIntent) succeeds!
            open_order2 = OrderIntent(
                order_id="ord-f10-open2",
                action_ref="act-f10-open2",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            dec_open2 = _admit_order(gate, open_order2, now=clock())
            exec_res = router.execute_open(RiskIncreasingOrderIntent(open_order2), valve_decision=dec_open2)
            self.assertEqual(exec_res.executed_on, BROKER_HUGOSWAY_MT5)
            pos_ticket = exec_res.result.receipt.position_ticket  # type: ignore[union-attr]
            self.assertIsNotNone(pos_ticket)

            close_order = OrderIntent(
                order_id="ord-f10-close",
                action_ref="act-f10-close",
                kind=ActionKind.CLOSE,
                symbol="EURUSD",
                position_ticket=pos_ticket,
            )
            dec_close = _admit_order(gate, close_order, now=clock())
            cls_res = router.execute_management(
                BROKER_HUGOSWAY_MT5, RiskReducingOrderIntent(close_order), valve_decision=dec_close
            )
            self.assertTrue(cls_res.accepted)

    # ------------------------------------------------------------------
    # Finding [5] (router side): Strict provenance separation on index references
    # ------------------------------------------------------------------
    def test_finding_05_router_rejects_same_venue_self_corroboration_and_unlabeled_index_quotes(self) -> None:
        gate = load_default_forex_valve_gate()
        clock = _Clock(T0)

        def _run_nas100_open(ref_source: Any) -> Any:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                spool_h = root / "hugosway_mt5"
                emu_h = Mt5SpoolPaperTerminalEmulator(
                    spool_h, server="Hugo demo PRO5", login=7001234, quotes=QUOTES_FX, balance=D("100000"), clock=clock
                )
                emu_h.publish_market()
                tr_h = Mt5SpoolBridgeTransport(spool_h, sleep=emu_h.sleep_hook, poll_interval_seconds=0.01, clock=clock)
                creds_h = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugo demo PRO5")
                venue_h = Mt5PaperBrokerVenue(
                    broker_id=BROKER_HUGOSWAY_MT5, credentials=creds_h, transport=tr_h, valve_gate=gate, clock=clock
                )
                venue_h.connect()
                router = DualShieldBrokerRouter(
                    environ={},
                    valve_gate=gate,
                    barbell=BarbellCapitalPolicy(demo_virtual_sleeve=True),
                    equity_attestations={BROKER_OANDA_PRACTICE: D("800000")},
                    index_reference_source=ref_source,
                    clock=clock,
                )
                router.attach_venue(venue_h)
                order = OrderIntent(
                    order_id="ord-nas-f5",
                    action_ref="act-nas-f5",
                    kind=ActionKind.OPEN,
                    symbol="NAS100",
                    quantity_units=D("1"),
                    side=Side.BUY,
                    stop_price=D("20450.00"),
                )
                dec = _admit_order(gate, order, now=clock(), bid="20500.00", ask="20501.00")
                return router.execute_open(order, valve_decision=dec)

        # 1. Bare unlabeled (bid, ask) tuple MUST fail closed
        with self.assertRaises(QuoteReferenceUnavailableError):
            _run_nas100_open(lambda _s: {"NAS100": (D("20500.00"), D("20501.00"))})

        # 2. Same-venue MT5 tick (HUGOSWAY_MT5 corroborating HUGOSWAY_MT5) MUST fail closed
        with self.assertRaises(QuoteReferenceUnavailableError):
            _run_nas100_open(
                lambda _s: {
                    "NAS100": {
                        "bid": D("20500.00"),
                        "ask": D("20501.00"),
                        "source_provider": "MT5_DIRECT_SPOOL_50MS",
                        "source_broker_id": BROKER_HUGOSWAY_MT5,
                        "is_independent_public": False,
                        "observed_at": "2026-11-21T12:00:00Z",
                    }
                }
            )

        # 3. Unlabeled non-public broker tick (source_broker_id=None, is_independent_public=False) MUST fail closed
        with self.assertRaises(QuoteReferenceUnavailableError):
            _run_nas100_open(
                lambda _s: {
                    "NAS100": {
                        "bid": D("20500.00"),
                        "ask": D("20501.00"),
                        "source_provider": "MT5_DIRECT_SPOOL_50MS",
                        "source_broker_id": None,
                        "is_independent_public": False,
                        "observed_at": "2026-11-21T12:00:00Z",
                    }
                }
            )

        # 4. MT5 provider falsely claiming is_independent_public=True MUST fail closed
        with self.assertRaises(QuoteReferenceUnavailableError):
            _run_nas100_open(
                lambda _s: {
                    "NAS100": {
                        "bid": D("20500.00"),
                        "ask": D("20501.00"),
                        "source_provider": "MT5_DIRECT_SPOOL_50MS",
                        "source_broker_id": None,
                        "is_independent_public": True,
                        "observed_at": "2026-11-21T12:00:00Z",
                    }
                }
            )

        # 5. Stale independent public reference (>60s old) MUST fail closed
        with self.assertRaises(QuoteReferenceUnavailableError):
            _run_nas100_open(
                lambda _s: {
                    "NAS100": {
                        "bid": D("20500.00"),
                        "ask": D("20501.00"),
                        "source_provider": "YAHOO_STOOQ_PUBLIC",
                        "source_broker_id": None,
                        "is_independent_public": True,
                        "observed_at": "2026-11-21T11:55:00Z",
                    }
                }
            )

        # 6. Fresh independent public 6-key dict succeeds cleanly
        res_pub = _run_nas100_open(
            lambda _s: {
                "NAS100": {
                    "bid": D("20500.00"),
                    "ask": D("20501.00"),
                    "source_provider": "YAHOO_STOOQ_PUBLIC",
                    "source_broker_id": None,
                    "is_independent_public": True,
                    "observed_at": "2026-11-21T12:00:00Z",
                }
            }
        )
        self.assertEqual(res_pub.executed_on, BROKER_HUGOSWAY_MT5)

        # 7. Distinct non-target venue ReferenceQuote (LHFX_MT5 corroborating HUGOSWAY_MT5) succeeds cleanly
        res_distinct = _run_nas100_open(
            lambda _s: {
                "NAS100": ReferenceQuote(
                    symbol="NAS100",
                    bid=D("20500.00"),
                    ask=D("20501.00"),
                    source_provider="CROSS_VENUE_MT5",
                    source_broker_id=BROKER_LHFX_MT5,
                    is_independent_public=False,
                    observed_at=T0,
                )
            }
        )
        self.assertEqual(res_distinct.executed_on, BROKER_HUGOSWAY_MT5)


if __name__ == "__main__":
    unittest.main()
