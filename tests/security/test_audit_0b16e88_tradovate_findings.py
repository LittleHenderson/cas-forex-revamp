"""Security regression tests for audit_0b16e88_report7.md Tradovate Findings [2], [3], [6], [16]."""
from __future__ import annotations

import ast
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
from types import SimpleNamespace
from typing import Any
import unittest

from cas_forex_revamp.futures.tradovate_venue import (
    BROKER_TRADOVATE_FUTURES,
    DEFAULT_MAX_QUOTE_AGE_SECONDS,
    ENV_LIVE_ARM_PHRASE,
    ENV_TRADOVATE_ACCOUNT_ID,
    ENV_TRADOVATE_ENABLED,
    ENV_TRADOVATE_MODE,
    FuturesOrderAction,
    LIVE_ARM_CONFIRMATION_TEXT,
    LiveAuthorizationContext,
    LiveAuthorizationError,
    MUTATION_STATUS_OUTCOME_UNKNOWN,
    MUTATION_STATUS_PENDING,
    MUTATION_STATUS_PROTECTION_UNCONFIRMED,
    TRADOVATE_DEMO_BASE_URL,
    TRADOVATE_LIVE_BASE_URL,
    TRADOVATE_LIVE_HOST,
    TRADOVATE_MODE_DEMO,
    TRADOVATE_MODE_LIVE,
    TradovateAccountSnapshot,
    TradovateCredentials,
    TradovateEndpointError,
    TradovateHttpsTransport,
    TradovateLiveLockError,
    TradovateMicroFuturesPaperEmulator,
    TradovateMicroFuturesVenue,
    TradovateOrderError,
    TradovateOrderReceipt,
    TradovateOrderRequest,
    TradovateOutcomeUnknownError,
    TradovateProtectionUnconfirmedError,
    TradovateQuote,
    TradovateStaleQuoteError,
    TradovateTransportError,
    TradovateValveRefusalError,
    _RedactedSecret,
    _build_futures_valve_proposal,
    _encode_wire_json_bytes,
    load_default_forex_valve_gate,
    load_tradovate_credentials,
    validate_tradovate_endpoint,
    verify_live_authorization_context,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    ENV_LIVE_AUTH_KEY_FILE,
    ENV_LIVE_AUTH_TICKET_FILE,
    build_live_authorization_context,
    mint_live_authorization_ticket,
    provision_live_auth_key,
)


def _utc(year: int, month: int, day: int, hour: int = 15, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


class _MutableClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> datetime:
        self.current = self.current + timedelta(seconds=seconds)
        return self.current


def _mint_live_ctx(
    tmp_dir: Path,
    *,
    broker_id: str = BROKER_TRADOVATE_FUTURES,
    account_id: str = "TV-LIVE-8801",
    server: str = TRADOVATE_LIVE_HOST,
    ttl_seconds: int = 600,
    now: datetime | None = None,
    with_arm_phrase: bool = True,
    key_name: str = "tradovate_live.key",
) -> tuple[Path, dict[str, str], LiveAuthorizationContext]:
    key_file = provision_live_auth_key(tmp_dir / key_name)
    issued = now or _utc(2026, 11, 20, 15, 0)
    ticket = mint_live_authorization_ticket(
        key_file=key_file,
        broker_id=broker_id,
        account_login=account_id,
        server=server,
        ttl_seconds=ttl_seconds,
        issued_at=issued,
    )
    _verified, ctx = verify_live_authorization_context(
        ticket,
        key_file=key_file,
        expected_broker_id=broker_id,
        expected_account_login=account_id,
        expected_server=server,
        live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT if with_arm_phrase else None,
        require_arm_phrase=with_arm_phrase,
        now=issued,
    )
    return key_file, ticket, ctx


def _demo_https_transport(clock: _MutableClock) -> TradovateHttpsTransport:
    creds = TradovateCredentials(
        enabled=True,
        mode=TRADOVATE_MODE_DEMO,
        base_url=TRADOVATE_DEMO_BASE_URL,
        account_id="TV-DEMO-5501",
        bearer_token=_RedactedSecret(f"bearer-{secrets.token_hex(8)}"),
    )
    transport = TradovateHttpsTransport(credentials=creds, clock=clock)
    transport.connect()
    return transport


class TestFinding02TradovateAtomicOsoBracketProtection(unittest.TestCase):
    """Finding [2]: Broker-native atomic OSO/bracket with verified stop & TP child orders."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_https_place_protected_order_sends_complete_oso_bracket_and_verifies_children(self) -> None:
        transport = _demo_https_transport(self.clock)
        captured: list[tuple[str, str, dict[str, Any]]] = []

        def fake_request_json(
            method: str,
            endpoint_path: str,
            *,
            payload: dict[str, Any] | None = None,
            require_auth: bool = True,
        ) -> dict[str, Any]:
            captured.append((method, endpoint_path, dict(payload or {})))
            # Confirm wire JSON encodes exact Decimal numbers cleanly (zero float()).
            if payload is not None:
                wire_bytes = _encode_wire_json_bytes(payload)
                parsed_wire = json.loads(wire_bytes.decode("utf-8"), parse_float=Decimal)
                self.assertEqual(parsed_wire["bracket1"]["stopPrice"], payload["bracket1"]["stopPrice"])
                if "bracket2" in payload:
                    self.assertEqual(parsed_wire["bracket2"]["price"], payload["bracket2"]["price"])
            if payload and payload.get("action") == "Buy":
                return {
                    "orderId": 9001,
                    "oso1Id": 9002,
                    "oso2Id": 9003,
                    "clOrdId": payload["clOrdId"],
                    "filledQty": 1,
                    "fillPrice": Decimal("20000.50"),
                    "positionId": "POS-LIVE-1",
                    "bracket1": {
                        "orderId": 9002,
                        "action": "Sell",
                        "orderType": "Stop",
                        "orderQty": 1,
                        "stopPrice": Decimal("19975.25"),
                        "ordStatus": "Working",
                    },
                    "bracket2": {
                        "orderId": 9003,
                        "action": "Sell",
                        "orderType": "Limit",
                        "orderQty": 1,
                        "price": Decimal("20060.25"),
                        "ordStatus": "Working",
                    },
                }
            return {
                "orderId": 9101,
                "oso1Id": 9102,
                "clOrdId": payload["clOrdId"],
                "bracket1": {
                    "orderId": 9102,
                    "action": "Buy",
                    "orderType": "Stop",
                    "orderQty": 2,
                    "stopPrice": Decimal("6010.00"),
                    "ordStatus": "Working",
                },
            }

        transport._request_json = fake_request_json  # type: ignore[method-assign]

        # 1. BUY with SL + TP and confirmed broker fill
        buy_req = TradovateOrderRequest(
            request_id="req-buy-1",
            cl_ord_id="cas-tv-buy-0001",
            action=FuturesOrderAction.OPEN_BRACKET,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=Decimal("20000.25"),
            stop_loss_price=Decimal("19975.25"),
            take_profit_price=Decimal("20060.25"),
            created_at=self.clock(),
        )
        rec_buy = transport.place_protected_order(buy_req)
        self.assertEqual(len(captured), 1)
        method, path, payload = captured[0]
        self.assertEqual((method, path), ("POST", "order/placeOSO"))
        self.assertEqual(payload["clOrdId"], "cas-tv-buy-0001")
        self.assertEqual(payload["action"], "Buy")
        self.assertEqual(payload["orderQty"], 1)
        self.assertEqual(payload["bracket1"]["action"], "Sell")
        self.assertEqual(payload["bracket1"]["orderType"], "Stop")
        self.assertEqual(payload["bracket1"]["orderQty"], 1)
        self.assertEqual(payload["bracket1"]["stopPrice"], Decimal("19975.25"))
        self.assertEqual(payload["bracket2"]["action"], "Sell")
        self.assertEqual(payload["bracket2"]["orderType"], "Limit")
        self.assertEqual(payload["bracket2"]["orderQty"], 1)
        self.assertEqual(payload["bracket2"]["price"], Decimal("20060.25"))

        self.assertTrue(rec_buy.protection_confirmed)
        self.assertEqual(rec_buy.order_id, "9001")
        self.assertEqual(rec_buy.stop_loss_order_id, "9002")
        self.assertEqual(rec_buy.take_profit_order_id, "9003")
        self.assertEqual(rec_buy.status, "FILLED")
        self.assertEqual(rec_buy.filled_contracts, 1)
        # Confirmed broker fillPrice (20000.50), NOT synthesized from request.entry_price (20000.25)!
        self.assertEqual(rec_buy.fill_price, Decimal("20000.50"))
        self.assertEqual(rec_buy.stop_loss_price, Decimal("19975.25"))
        self.assertEqual(rec_buy.take_profit_price, Decimal("20060.25"))

        # 2. SELL with SL only and NO fill reported -> NEVER synthesize filled_contracts/fill_price!
        sell_req = TradovateOrderRequest(
            request_id="req-sell-1",
            cl_ord_id="cas-tv-sell-0002",
            action=FuturesOrderAction.OPEN_BRACKET,
            contract_code="MESZ6",
            root_symbol="MES",
            cas_symbol="SPX500",
            side="SELL",
            contracts=2,
            entry_price=Decimal("6000.00"),
            stop_loss_price=Decimal("6010.00"),
            take_profit_price=None,
            created_at=self.clock(),
        )
        rec_sell = transport.place_protected_order(sell_req)
        self.assertNotIn("bracket2", captured[1][2])
        self.assertEqual(captured[1][2]["bracket1"]["action"], "Buy")
        self.assertEqual(captured[1][2]["bracket1"]["orderQty"], 2)
        self.assertTrue(rec_sell.protection_confirmed)
        self.assertEqual(rec_sell.status, "SUBMITTED_PROTECTED")
        self.assertEqual(rec_sell.filled_contracts, 0)
        self.assertIsNone(rec_sell.fill_price)
        self.assertEqual(rec_sell.stop_loss_order_id, "9102")
        self.assertIsNone(rec_sell.take_profit_order_id)

    def test_https_place_protected_order_fetches_child_orders_when_not_inline(self) -> None:
        transport = _demo_https_transport(self.clock)
        calls: list[tuple[str, str]] = []

        def fake_json(
            method: str,
            endpoint_path: str,
            *,
            payload: dict[str, Any] | None = None,
            require_auth: bool = True,
        ) -> dict[str, Any]:
            calls.append((method, endpoint_path))
            if endpoint_path == "order/placeOSO":
                return {"orderId": 4001, "oso1Id": 4002, "oso2Id": 4003}
            if endpoint_path == "order/item?id=4002":
                return {"id": 4002, "action": "Sell", "ordStatus": "Working"}
            if endpoint_path == "order/item?id=4003":
                return {"id": 4003, "action": "Sell", "ordStatus": "Working"}
            raise AssertionError(f"Unexpected endpoint {endpoint_path}")

        def fake_list(
            method: str,
            endpoint_path: str,
            *,
            require_auth: bool = True,
        ) -> list[dict[str, Any]]:
            calls.append((method, endpoint_path))
            if endpoint_path == "orderVersion/deps?masterid=4002":
                return [{"orderType": "Stop", "orderQty": 1, "stopPrice": Decimal("19975.25")}]
            if endpoint_path == "orderVersion/deps?masterid=4003":
                return [{"orderType": "Limit", "orderQty": 1, "price": Decimal("20060.25")}]
            raise AssertionError(f"Unexpected list endpoint {endpoint_path}")

        transport._request_json = fake_json  # type: ignore[method-assign]
        transport._request_json_list = fake_list  # type: ignore[method-assign]

        req = TradovateOrderRequest(
            request_id="req-fetch-1",
            cl_ord_id="cas-tv-fetch-0001",
            action=FuturesOrderAction.OPEN_BRACKET,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=Decimal("20000.25"),
            stop_loss_price=Decimal("19975.25"),
            take_profit_price=Decimal("20060.25"),
            created_at=self.clock(),
        )
        receipt = transport.place_protected_order(req)
        self.assertTrue(receipt.protection_confirmed)
        self.assertEqual(receipt.order_id, "4001")
        self.assertEqual(receipt.stop_loss_order_id, "4002")
        self.assertEqual(receipt.take_profit_order_id, "4003")
        self.assertIn(("GET", "order/item?id=4002"), calls)
        self.assertIn(("GET", "orderVersion/deps?masterid=4002"), calls)
        self.assertIn(("GET", "order/item?id=4003"), calls)
        self.assertIn(("GET", "orderVersion/deps?masterid=4003"), calls)

    def test_https_place_protected_order_refuses_missing_or_mismatched_child_protections(self) -> None:
        base_req = TradovateOrderRequest(
            request_id="req-bad-1",
            cl_ord_id="cas-tv-bad-0001",
            action=FuturesOrderAction.OPEN_BRACKET,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=Decimal("20000.25"),
            stop_loss_price=Decimal("19975.25"),
            take_profit_price=Decimal("20060.25"),
            created_at=self.clock(),
        )
        good_b1 = {
            "orderId": 5002,
            "action": "Sell",
            "orderType": "Stop",
            "orderQty": 1,
            "stopPrice": Decimal("19975.25"),
        }
        good_b2 = {
            "orderId": 5003,
            "action": "Sell",
            "orderType": "Limit",
            "orderQty": 1,
            "price": Decimal("20060.25"),
        }
        bad_cases: list[tuple[str, dict[str, Any]]] = [
            ("missing_order_id", {"oso1Id": 5002, "oso2Id": 5003, "bracket1": good_b1, "bracket2": good_b2}),
            ("missing_oso1_id", {"orderId": 5001, "oso2Id": 5003, "bracket2": good_b2}),
            ("missing_oso2_id_when_tp_requested", {"orderId": 5001, "oso1Id": 5002, "bracket1": good_b1}),
            ("colliding_oso1_id", {"orderId": 5001, "oso1Id": 5001, "oso2Id": 5003, "bracket1": good_b1, "bracket2": good_b2}),
            ("wrong_stop_price", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "bracket1": {**good_b1, "stopPrice": Decimal("19975.00")}, "bracket2": good_b2}),
            ("wrong_tp_price", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "bracket1": good_b1, "bracket2": {**good_b2, "price": Decimal("20061.00")}}),
            ("wrong_child_side", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "bracket1": {**good_b1, "action": "Buy"}, "bracket2": good_b2}),
            ("wrong_child_order_type", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "bracket1": {**good_b1, "orderType": "Limit"}, "bracket2": good_b2}),
            ("wrong_child_qty", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "bracket1": {**good_b1, "orderQty": 2}, "bracket2": good_b2}),
            ("rejected_stop_child", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "bracket1": {**good_b1, "ordStatus": "Rejected"}, "bracket2": good_b2}),
            ("filled_without_fill_price", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "filledQty": 1, "bracket1": good_b1, "bracket2": good_b2}),
            ("mismatched_cl_ord_id", {"orderId": 5001, "oso1Id": 5002, "oso2Id": 5003, "clOrdId": "other", "bracket1": good_b1, "bracket2": good_b2}),
        ]

        for label, resp_doc in bad_cases:
            with self.subTest(case=label):
                transport = _demo_https_transport(self.clock)
                transport._request_json = lambda _m, _p, payload=None, require_auth=True, d=resp_doc: d  # type: ignore[method-assign]
                with self.assertRaises(TradovateProtectionUnconfirmedError):
                    transport.place_protected_order(base_req)

    def test_venue_persists_protection_unconfirmed_latch_blocks_retries_and_survives_restart(self) -> None:
        class _UnprotectedTransport(TradovateMicroFuturesPaperEmulator):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self.open_attempts = 0

            def place_protected_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                self.open_attempts += 1
                raise TradovateProtectionUnconfirmedError(
                    "Simulated broker missing oso1Id stop child",
                    cl_ord_id=request.cl_ord_id,
                    order_id="7771",
                    request_id=request.request_id,
                )

        db_path = self.tmp / "prot_latch.sqlite3"
        transport = _UnprotectedTransport(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        transport.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=transport,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )

        with self.assertRaises(TradovateProtectionUnconfirmedError) as ctx:
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        cl_id = ctx.exception.cl_ord_id
        self.assertIsNotNone(cl_id)
        self.assertEqual(transport.open_attempts, 1)

        snap = venue.snapshot()
        self.assertTrue(snap["protection_unconfirmed_latch"])
        self.assertEqual(snap["unresolved_mutation_count"], 1)
        self.assertEqual(snap["unresolved_mutations"][0]["status"], MUTATION_STATUS_PROTECTION_UNCONFIRMED)
        self.assertTrue(venue.verify_audit_chain())

        # Subsequent open MUST fail closed without hitting transport again.
        with self.assertRaises(TradovateProtectionUnconfirmedError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        self.assertEqual(transport.open_attempts, 1)

        # Reopening fresh venue on same SQLite DB MUST preserve the latch across restarts.
        venue_reopened = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=transport,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )
        with self.assertRaises(TradovateProtectionUnconfirmedError):
            venue_reopened.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        self.assertEqual(transport.open_attempts, 1)

        # Protective emergency_close_all remains ALLOWED while protection latch is active.
        self.assertEqual(venue_reopened.emergency_close_all(), ())

        # Reconciling with broker confirming unprotected working order keeps latch active!
        rec_still_unprot = venue_reopened.reconcile_unknown_outcome(
            cl_ord_id=cl_id,
            broker_orders=[{"clOrdId": cl_id, "orderId": "7771", "ordStatus": "Filled", "filledQty": 1}],
        )
        self.assertTrue(rec_still_unprot["freeze_active"])

        # Once broker confirms order absent / flattened externally with no open position, latch clears.
        rec_clear = venue_reopened.reconcile_unknown_outcome(
            cl_ord_id=cl_id,
            broker_orders=[{"clOrdId": cl_id, "orderId": "7771", "ordStatus": "Filled", "filledQty": 1}],
            confirm_protection_resolved=True,
        )
        self.assertFalse(rec_clear["freeze_active"])
        self.assertFalse(venue_reopened.snapshot()["protection_unconfirmed_latch"])
        self.assertTrue(venue_reopened.verify_audit_chain())

    def test_paper_emulator_emits_oso_payload_and_https_protective_methods_work(self) -> None:
        emu = TradovateMicroFuturesPaperEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        req = TradovateOrderRequest(
            request_id="req-paper-oso-1",
            cl_ord_id="cas-tv-paper-001",
            action=FuturesOrderAction.OPEN_BRACKET,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=Decimal("20000.25"),
            stop_loss_price=Decimal("19975.25"),
            take_profit_price=Decimal("20060.25"),
            created_at=self.clock(),
        )
        rec = emu.place_protected_order(req)
        self.assertTrue(rec.protection_confirmed)
        self.assertIsNotNone(rec.stop_loss_order_id)
        self.assertIsNotNone(rec.take_profit_order_id)
        self.assertNotEqual(rec.order_id, rec.stop_loss_order_id)
        self.assertNotEqual(rec.stop_loss_order_id, rec.take_profit_order_id)
        self.assertEqual(len(emu.submitted_oso_payloads), 1)
        oso = emu.submitted_oso_payloads[0]
        self.assertEqual(oso["clOrdId"], "cas-tv-paper-001")
        self.assertEqual(oso["bracket1"]["orderType"], "Stop")
        self.assertEqual(oso["bracket1"]["stopPrice"], Decimal("19975.25"))
        self.assertEqual(oso["bracket2"]["orderType"], "Limit")
        self.assertEqual(oso["bracket2"]["price"], Decimal("20060.25"))
        with self.assertRaises(TradovateOrderError):
            emu.place_protected_order(req)

        # Verify HTTPS transport live positions(), amend_stop, close_position, emergency_close_all
        https = _demo_https_transport(self.clock)
        calls: list[tuple[str, str, dict[str, Any] | None]] = []

        def fake_json(m: str, ep: str, *, payload: dict[str, Any] | None = None, require_auth: bool = True) -> dict[str, Any]:
            calls.append((m, ep, dict(payload) if payload is not None else None))
            return {"orderId": 8800 + len(calls)}

        def fake_list(m: str, ep: str, *, require_auth: bool = True) -> list[dict[str, Any]]:
            calls.append((m, ep, None))
            return [
                {
                    "id": "POS-99",
                    "contractCode": "MNQZ6",
                    "rootSymbol": "MNQ",
                    "netPos": 1,
                    "netPrice": Decimal("20000.25"),
                    "stopLossOrderId": "9002",
                    "stopLossPrice": Decimal("19975.25"),
                }
            ]

        https._request_json = fake_json  # type: ignore[method-assign]
        https._request_json_list = fake_list  # type: ignore[method-assign]

        positions = https.positions()
        self.assertEqual(len(positions), 1)
        self.assertEqual(positions[0].position_id, "POS-99")
        self.assertEqual(positions[0].stop_loss_order_id, "9002")

        amend_rec = https.send_order(
            TradovateOrderRequest(
                request_id="req-amend-1",
                cl_ord_id="cas-tv-amend-1",
                action=FuturesOrderAction.AMEND_STOP,
                contract_code="MNQZ6",
                root_symbol="MNQ",
                cas_symbol="NAS100",
                side="BUY",
                contracts=1,
                order_id="9002",
                position_id="POS-99",
                stop_loss_price=Decimal("20000.25"),
                created_at=self.clock(),
            )
        )
        self.assertEqual(amend_rec.status, "AMENDED")
        self.assertEqual(calls[-1][1], "order/modifyOrder")

        emerg_rec = https.send_order(
            TradovateOrderRequest(
                request_id="req-emerg-1",
                cl_ord_id="cas-tv-emerg-1",
                action=FuturesOrderAction.EMERGENCY_CLOSE_ALL,
                contract_code="",
                root_symbol="",
                cas_symbol="",
                created_at=self.clock(),
            )
        )
        self.assertEqual(emerg_rec.status, "EMERGENCY_CLOSED")
        self.assertEqual(emerg_rec.filled_contracts, 1)
        self.assertEqual(calls[-1][1], "order/liquidatePosition")


class TestFinding03TradovateIdempotencyAndOutcomeUnknownFreeze(unittest.TestCase):
    """Finding [3]: Stable clOrdId + durable OUTCOME_UNKNOWN freeze latch + broker-history reconciliation."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_cl_ord_id_durably_committed_pending_before_transport_call(self) -> None:
        db_path = self.tmp / "precommit_clord.sqlite3"
        observed_before_wire: list[tuple[str, str]] = []

        class _InspectingTransport(TradovateMicroFuturesPaperEmulator):
            def place_protected_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                with closing(sqlite3.connect(str(db_path))) as conn:
                    row = conn.execute(
                        "SELECT status, cl_ord_id FROM mutation_journal WHERE request_id = ?",
                        (request.request_id,),
                    ).fetchone()
                if row is not None:
                    observed_before_wire.append((str(row[0]), str(row[1])))
                return super().place_protected_order(request)

        transport = _InspectingTransport(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        transport.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=transport,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )

        rec = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("20.00"),
            take_profit_points=Decimal("60.00"),
            idempotency_key="signal-20261120-001",
        )
        self.assertEqual(len(observed_before_wire), 1)
        self.assertEqual(observed_before_wire[0][0], MUTATION_STATUS_PENDING)
        self.assertEqual(observed_before_wire[0][1], rec.cl_ord_id)
        self.assertEqual(transport.submitted_oso_payloads[0]["clOrdId"], rec.cl_ord_id)

        # Duplicate idempotency_key MUST fail closed without placing a second order.
        with self.assertRaises(TradovateOrderError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("20.00"),
                take_profit_points=Decimal("60.00"),
                idempotency_key="signal-20261120-001",
            )
        self.assertEqual(len(transport.submitted_oso_payloads), 1)

    def test_ambiguous_transport_failures_promote_to_outcome_unknown_and_freeze_retries(self) -> None:
        failure_modes: list[tuple[str, Exception]] = [
            ("timeout", TimeoutError("socket timed out")),
            ("disconnect_oserror", ConnectionResetError("peer reset connection")),
            ("http_503", TradovateTransportError("Tradovate HTTP status 503", http_status=503)),
            ("malformed_json", TradovateTransportError("Tradovate response was not valid UTF-8 JSON")),
            ("remote_disconnected", http.client.RemoteDisconnected("closed without response")),
        ]

        for label, exc_to_raise in failure_modes:
            with self.subTest(failure_mode=label):
                db_path = self.tmp / f"ambig_{label}.sqlite3"

                class _AmbiguousTransport(TradovateMicroFuturesPaperEmulator):
                    def __init__(self, err: Exception, *args: Any, **kwargs: Any) -> None:
                        super().__init__(*args, **kwargs)
                        self._err = err
                        self.dispatch_count = 0

                    def place_protected_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                        self.dispatch_count += 1
                        raise self._err

                transport = _AmbiguousTransport(
                    exc_to_raise,
                    starting_equity_usd=Decimal("5000.00"),
                    clock=self.clock,
                )
                transport.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
                transport.set_quote("US30", Decimal("43000.00"), Decimal("43001.00"), observed_at=self.clock())
                venue = TradovateMicroFuturesVenue(
                    db_path=db_path,
                    transport=transport,
                    valve_gate=self.valve,
                    enabled=True,
                    clock=self.clock,
                )

                with self.assertRaises(TradovateOutcomeUnknownError) as ctx:
                    venue.place_bracket_order(
                        symbol="NAS100",
                        side="BUY",
                        stop_distance_points=Decimal("25.00"),
                        take_profit_points=Decimal("60.00"),
                        idempotency_key=f"idem-{label}",
                    )
                self.assertEqual(transport.dispatch_count, 1)
                cl_ord_id = ctx.exception.cl_ord_id
                self.assertIsNotNone(cl_ord_id)

                # Verify durable SQLite OUTCOME_UNKNOWN status and active freeze latch.
                with closing(sqlite3.connect(str(db_path))) as conn:
                    row = conn.execute(
                        "SELECT status, cl_ord_id FROM mutation_journal WHERE cl_ord_id = ?",
                        (cl_ord_id,),
                    ).fetchone()
                    latch_row = conn.execute(
                        "SELECT latch_kind, cleared_at FROM venue_freeze_latches WHERE cl_ord_id = ?",
                        (cl_ord_id,),
                    ).fetchone()
                self.assertEqual(row[0], MUTATION_STATUS_OUTCOME_UNKNOWN)
                self.assertEqual(latch_row[0], MUTATION_STATUS_OUTCOME_UNKNOWN)
                self.assertIsNone(latch_row[1])

                snap = venue.snapshot()
                self.assertTrue(snap["outcome_unknown_freeze"])
                self.assertEqual(snap["unresolved_mutation_count"], 1)

                # Retry on same symbol AND new open on different symbol MUST BOTH be blocked!
                for sym in ("NAS100", "US30"):
                    with self.assertRaises(TradovateOutcomeUnknownError):
                        venue.place_bracket_order(
                            symbol=sym,
                            side="BUY",
                            stop_distance_points=Decimal("25.00"),
                            take_profit_points=Decimal("60.00"),
                        )
                self.assertEqual(transport.dispatch_count, 1)

                # Protective emergency_close_all remains ALLOWED while frozen.
                self.assertEqual(venue.emergency_close_all(), ())
                self.assertTrue(venue.verify_audit_chain())

    def test_crash_recovery_promotes_pending_row_and_reconcile_releases_latch_only_on_broker_proof(self) -> None:
        db_path = self.tmp / "reconcile_flow.sqlite3"
        emu = TradovateMicroFuturesPaperEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        venue1 = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=emu,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )

        # Simulate process crash right after committing PENDING row before transport returned.
        crashed_cl = "cas-tv-crashed-pending-001"
        req_payload = json.dumps(
            {
                "request_id": "tv-open-000099",
                "cl_ord_id": crashed_cl,
                "action": "OPEN_BRACKET",
                "contract_code": "MNQZ6",
                "root_symbol": "MNQ",
                "cas_symbol": "NAS100",
                "side": "BUY",
                "contracts": 1,
                "stop_loss_price": "19975.25",
                "take_profit_price": "20060.25",
            },
            sort_keys=True,
        )
        with closing(sqlite3.connect(str(db_path))) as conn:
            conn.execute(
                "INSERT INTO mutation_journal "
                "(request_id, cl_ord_id, action, contract_code, root_symbol, cas_symbol, status, "
                "request_json, receipt_json, error_detail, reconciled_at, reconciliation_json, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                (
                    "tv-open-000099",
                    crashed_cl,
                    "OPEN_BRACKET",
                    "MNQZ6",
                    "MNQ",
                    "NAS100",
                    MUTATION_STATUS_PENDING,
                    req_payload,
                    "2026-11-20T15:00:00Z",
                    "2026-11-20T15:00:00Z",
                ),
            )
            conn.commit()

        # Reopen fresh venue -> crash recovery promotes PENDING to OUTCOME_UNKNOWN and freezes opens!
        venue2 = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=emu,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )
        self.assertTrue(venue2.snapshot()["outcome_unknown_freeze"])
        with self.assertRaises(TradovateOutcomeUnknownError):
            venue2.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )

        # 1. Reconciling while transport is disconnected MUST fail closed and retain latch.
        emu.set_connected(False)
        with self.assertRaises(TradovateOutcomeUnknownError):
            venue2.reconcile_unknown_outcome(cl_ord_id=crashed_cl)
        self.assertTrue(venue2.snapshot()["outcome_unknown_freeze"])
        emu.set_connected(True)

        # 2. Reconciling when broker reports still-ambiguous PendingNew MUST retain latch.
        ambig_rec = venue2.reconcile_unknown_outcome(
            cl_ord_id=crashed_cl,
            broker_orders=[{"clOrdId": crashed_cl, "orderId": "3001", "ordStatus": "PendingNew"}],
        )
        self.assertTrue(ambig_rec["freeze_active"])
        self.assertTrue(venue2.snapshot()["outcome_unknown_freeze"])

        # 3. Reconciling against broker order history confirming filled WITH verified stop + TP clears latch!
        good_rec = venue2.reconcile_unknown_outcome(
            cl_ord_id=crashed_cl,
            broker_orders=[
                {
                    "clOrdId": crashed_cl,
                    "orderId": "3001",
                    "oso1Id": "3002",
                    "oso2Id": "3003",
                    "ordStatus": "Filled",
                    "filledQty": 1,
                },
                {
                    "id": "3002",
                    "action": "Sell",
                    "orderType": "Stop",
                    "orderQty": 1,
                    "stopPrice": Decimal("19975.25"),
                    "ordStatus": "Working",
                },
                {
                    "id": "3003",
                    "action": "Sell",
                    "orderType": "Limit",
                    "orderQty": 1,
                    "price": Decimal("20060.25"),
                    "ordStatus": "Working",
                },
            ],
        )
        self.assertFalse(good_rec["freeze_active"])
        self.assertEqual(good_rec["reconciled"][0]["new_status"], "RECONCILED_FILLED_PROTECTED")
        self.assertFalse(venue2.snapshot()["outcome_unknown_freeze"])

        # Opens work again after verified reconciliation!
        rec_after = venue2.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
        )
        self.assertTrue(rec_after.protection_confirmed)
        self.assertTrue(venue2.verify_audit_chain())


class TestFinding06TradovateCryptographicLiveAuthorization(unittest.TestCase):
    """Finding [6]: Unforgeable LiveAuthorizationContext replacing bare live_arming_verified boolean."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_bare_live_arming_verified_boolean_fails_closed_on_every_entrypoint(self) -> None:
        with self.assertRaises(LiveAuthorizationError):
            validate_tradovate_endpoint(
                TRADOVATE_MODE_LIVE,
                TRADOVATE_LIVE_BASE_URL,
                live_arming_verified=True,
                account_id="TV-LIVE-8801",
            )
        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode=TRADOVATE_MODE_LIVE,
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-8801",
                live_arming_verified=True,
            )
        with self.assertRaises(LiveAuthorizationError):
            load_tradovate_credentials(
                {
                    ENV_TRADOVATE_ENABLED: "1",
                    ENV_TRADOVATE_MODE: "LIVE",
                    ENV_TRADOVATE_ACCOUNT_ID: "TV-LIVE-8801",
                    ENV_LIVE_ARM_PHRASE: LIVE_ARM_CONFIRMATION_TEXT,
                },
                live_arming_verified=True,
                now_utc=self.clock(),
            )
        with self.assertRaises(LiveAuthorizationError):
            TradovateMicroFuturesVenue(
                db_path=self.tmp / "bare_bool_init.sqlite3",
                mode=TRADOVATE_MODE_LIVE,
                account_id="TV-LIVE-8801",
                live_arming_verified=True,
                clock=self.clock,
            )

        emu = TradovateMicroFuturesPaperEmulator(clock=self.clock)
        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "bare_bool_act.sqlite3",
            transport=emu,
            valve_gate=self.valve,
            clock=self.clock,
        )
        with self.assertRaises(LiveAuthorizationError):
            venue.activate(
                mode=TRADOVATE_MODE_LIVE,
                account_id="TV-LIVE-8801",
                live_arming_verified=True,
            )

    def test_forged_live_authorization_context_and_target_mismatches_fail_closed(self) -> None:
        now = self.clock()
        # 1. Direct LiveAuthorizationContext constructor is blocked.
        with self.assertRaises(LiveAuthorizationError):
            LiveAuthorizationContext(
                broker_id=BROKER_TRADOVATE_FUTURES,
                account_id="TV-LIVE-8801",
                server=TRADOVATE_LIVE_HOST,
                execution_mode="LIVE",
                issued_at=now,
                expires_at=now + timedelta(seconds=600),
                ticket_sha256="a" * 64,
                arm_phrase_verified=True,
            )

        # 2. object.__new__ bypass without sentinel/seal fails provenance check at Credentials/Endpoint.
        forged = object.__new__(LiveAuthorizationContext)
        object.__setattr__(forged, "broker_id", BROKER_TRADOVATE_FUTURES)
        object.__setattr__(forged, "account_id", "TV-LIVE-8801")
        object.__setattr__(forged, "server", TRADOVATE_LIVE_HOST)
        object.__setattr__(forged, "execution_mode", "LIVE")
        object.__setattr__(forged, "issued_at", now)
        object.__setattr__(forged, "expires_at", now + timedelta(seconds=600))
        object.__setattr__(forged, "ticket_sha256", "a" * 64)
        object.__setattr__(forged, "arm_phrase_verified", True)
        object.__setattr__(forged, "_provenance_seal", "b" * 64)
        object.__setattr__(forged, "_mint_token", object())
        object.__setattr__(forged, "_key_file", None)
        object.__setattr__(forged, "_ticket_json", None)
        object.__setattr__(forged, "_ticket_nonce", "1234567890abcdef")

        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode=TRADOVATE_MODE_LIVE,
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-8801",
                live_auth_context=forged,
                live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
                auth_checked_at=now,
            )

        # 3. build_live_authorization_context without key_file fails closed.
        _kf, ticket, _ctx = _mint_live_ctx(self.tmp, now=now)
        with self.assertRaises(LiveAuthorizationError):
            build_live_authorization_context(ticket)

        # 4. Wrong broker_id (OANDA_LIVE instead of TRADOVATE_FUTURES) fails closed.
        _, _, oanda_ctx = _mint_live_ctx(
            self.tmp,
            broker_id="OANDA_LIVE",
            account_id="TV-LIVE-8801",
            server=TRADOVATE_LIVE_HOST,
            now=now,
            key_name="oanda.key",
        )
        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode=TRADOVATE_MODE_LIVE,
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-8801",
                live_auth_context=oanda_ctx,
                live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
                auth_checked_at=now,
            )

        # 5. Wrong account_id fails closed.
        _, _, valid_ctx = _mint_live_ctx(self.tmp, account_id="TV-LIVE-8801", now=now, key_name="tv_acct.key")
        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode=TRADOVATE_MODE_LIVE,
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-OTHER",
                live_auth_context=valid_ctx,
                live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
                auth_checked_at=now,
            )

        # 6. Context minted WITHOUT arm phrase verification fails closed.
        _, _, unarmed_ctx = _mint_live_ctx(
            self.tmp,
            account_id="TV-LIVE-8801",
            now=now,
            with_arm_phrase=False,
            key_name="tv_unarmed.key",
        )
        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode=TRADOVATE_MODE_LIVE,
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-8801",
                live_auth_context=unarmed_ctx,
                live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
                auth_checked_at=now,
            )

        # 7. Wrong explicit live_arm_phrase fails closed.
        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode=TRADOVATE_MODE_LIVE,
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-8801",
                live_auth_context=valid_ctx,
                live_arm_phrase="WRONG_PHRASE",
                auth_checked_at=now,
            )

    def test_env_loader_and_final_https_dispatch_sink_revalidate_expiry_and_key_custody(self) -> None:
        now = self.clock()
        key_file, ticket, _ctx = _mint_live_ctx(
            self.tmp,
            account_id="TV-LIVE-9001",
            ttl_seconds=300,
            now=now,
            key_name="sink_reval.key",
        )
        ticket_file = self.tmp / "sink_reval.ticket.json"
        ticket_file.write_text(json.dumps(ticket), encoding="utf-8")

        creds = load_tradovate_credentials(
            {
                ENV_TRADOVATE_ENABLED: "1",
                ENV_TRADOVATE_MODE: "LIVE",
                ENV_TRADOVATE_ACCOUNT_ID: "TV-LIVE-9001",
                ENV_LIVE_AUTH_KEY_FILE: str(key_file),
                ENV_LIVE_AUTH_TICKET_FILE: str(ticket_file),
                ENV_LIVE_ARM_PHRASE: LIVE_ARM_CONFIRMATION_TEXT,
            },
            now_utc=now,
        )
        self.assertEqual(creds.mode, TRADOVATE_MODE_LIVE)
        self.assertEqual(creds.base_url, TRADOVATE_LIVE_BASE_URL)
        self.assertIsInstance(creds.live_auth_context, LiveAuthorizationContext)

        # Attach bearer token via new TradovateCredentials sharing verified context.
        live_creds = TradovateCredentials(
            enabled=True,
            mode=TRADOVATE_MODE_LIVE,
            base_url=TRADOVATE_LIVE_BASE_URL,
            account_id="TV-LIVE-9001",
            live_auth_context=creds.live_auth_context,
            live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
            auth_checked_at=now,
            bearer_token=_RedactedSecret(f"live-tok-{secrets.token_hex(8)}"),
        )
        transport = TradovateHttpsTransport(credentials=live_creds, clock=self.clock)
        http_calls = 0

        def fake_request_json(
            method: str,
            endpoint_path: str,
            *,
            payload: dict[str, Any] | None = None,
            require_auth: bool = True,
        ) -> dict[str, Any]:
            nonlocal http_calls
            http_calls += 1
            return {
                "orderId": 6001,
                "oso1Id": 6002,
                "oso2Id": 6003,
                "clOrdId": (payload or {}).get("clOrdId"),
                "bracket1": {
                    "orderId": 6002,
                    "action": "Sell",
                    "orderType": "Stop",
                    "orderQty": 1,
                    "stopPrice": Decimal("19975.25"),
                },
                "bracket2": {
                    "orderId": 6003,
                    "action": "Sell",
                    "orderType": "Limit",
                    "orderQty": 1,
                    "price": Decimal("20060.25"),
                },
            }

        transport._request_json = fake_request_json  # type: ignore[method-assign]
        transport.connect()

        req_ok = TradovateOrderRequest(
            request_id="req-live-ok",
            cl_ord_id="cas-tv-live-0001",
            action=FuturesOrderAction.OPEN_BRACKET,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=Decimal("20000.25"),
            stop_loss_price=Decimal("19975.25"),
            take_profit_price=Decimal("20060.25"),
            created_at=now,
        )
        receipt = transport.place_protected_order(req_ok)
        self.assertTrue(receipt.protection_confirmed)
        self.assertEqual(http_calls, 1)

        # Advance clock past TTL (300s -> 301s): final dispatch sink MUST fail closed BEFORE network I/O!
        self.clock.advance(301)
        with self.assertRaises(LiveAuthorizationError):
            transport.place_protected_order(req_ok)
        self.assertEqual(http_calls, 1)

        # Rewind clock within TTL, then delete key_file: sink ticket re-verification MUST fail closed!
        self.clock.current = now + timedelta(seconds=60)
        key_file.unlink()
        with self.assertRaises(LiveAuthorizationError):
            transport.place_protected_order(req_ok)
        self.assertEqual(http_calls, 1)


class TestFinding16TradovateQuoteFreshnessAndOriginalTimestamp(unittest.TestCase):
    """Finding [16]: Preserve original quote.observed_at and enforce max_quote_age_seconds fail-closed."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_original_quote_observed_at_preserved_through_proposal_and_real_valve(self) -> None:
        t0 = self.clock()
        emu = TradovateMicroFuturesPaperEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=t0)

        captured_proposals: list[Any] = []
        captured_views: list[dict[str, Any]] = []
        captured_decisions: list[Any] = []

        class _SpyValveGate:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def require_admissible(self, proposal: Any, *, current_view=None, policy=None, now=None) -> Any:
                captured_proposals.append(proposal)
                captured_views.append(dict(current_view or {}))
                dec = self._inner.require_admissible(
                    proposal, current_view=current_view, policy=policy, now=now
                )
                captured_decisions.append(dec)
                return dec

        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "quote_preserve.sqlite3",
            transport=emu,
            valve_gate=_SpyValveGate(self.valve),
            enabled=True,
            max_quote_age_seconds=DEFAULT_MAX_QUOTE_AGE_SECONDS,
            clock=self.clock,
        )

        # Advance 15 seconds (half of default 30s max_quote_age_seconds).
        self.clock.advance(15)
        rec = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
        )
        self.assertTrue(rec.accepted)
        self.assertEqual(len(captured_proposals), 1)
        prop = captured_proposals[0]
        # Original quote.observed_at (t0) MUST NOT be overwritten with now (t0 + 15s)!
        self.assertEqual(prop.request.state.observed_at, t0)
        self.assertEqual(prop.request.evidence[0].observed_at, t0)
        self.assertEqual(captured_views[0]["quote_observed_at"], "2026-11-20T15:00:00Z")
        # Real ForexMetaValveGate computes real staleness ratio ~0.50 (15s / 30s), NOT 0.0!
        staleness_feat = captured_decisions[0].features["quote_staleness_ratio"]
        self.assertGreater(staleness_feat, 0.45)
        self.assertLess(staleness_feat, 0.55)

        # Directly building a proposal with a stale 45s-old quote MUST trigger STALE_OR_FUTURE_STATE in valve!
        stale_quote = TradovateQuote("MNQ", Decimal("20000.00"), Decimal("20000.25"), t0)
        stale_prop = _build_futures_valve_proposal(
            request_id="req-stale-prop",
            account_id="TV-TEST",
            root_symbol="MNQ",
            contract_code="MNQZ6",
            side="BUY",
            contracts=1,
            entry_price=Decimal("20000.25"),
            stop_loss_price=Decimal("19975.25"),
            take_profit_price=Decimal("20060.25"),
            quote=stale_quote,
            account=emu.account_snapshot(now_utc=t0 + timedelta(seconds=45)),
            positions_count=0,
            reason="STALE_TEST",
            now=t0 + timedelta(seconds=45),
            seq=1,
            max_quote_age_seconds=DEFAULT_MAX_QUOTE_AGE_SECONDS,
        )
        self.assertEqual(stale_prop.request.state.observed_at, t0)
        self.assertEqual(stale_prop.request.evidence[0].observed_at, t0)
        stale_dec = self.valve.evaluate(
            stale_prop,
            current_view={
                "account_id": "TV-TEST",
                "balance": "5000.00",
                "equity": "5000.00",
                "peak_equity": "5000.00",
                "available_margin": "5000.00",
                "position_inventory": [],
                "symbol": "MNQ",
                "bid": "20000.00",
                "ask": "20000.25",
            },
            policy={
                "new_risk_permission": "ALLOWED",
                "management_permission": "ALLOWED",
                "max_entry_quantity": "1",
                "max_drawdown_pct": "0.10",
                "accounting_required": ["balance", "equity", "available_margin", "position_inventory"],
            },
            now=t0 + timedelta(seconds=45),
        )
        self.assertFalse(stale_dec.admitted)
        self.assertIn("STALE_OR_FUTURE_STATE", stale_dec.hard_veto_reasons)

    def test_stale_missing_unparseable_and_future_skewed_quotes_fail_closed(self) -> None:
        t0 = self.clock()
        emu = TradovateMicroFuturesPaperEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=t0)
        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "stale_quote.sqlite3",
            transport=emu,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )

        # 31s old (> default 30.0s) MUST fail closed with TradovateStaleQuoteError!
        self.clock.advance(31)
        with self.assertRaises(TradovateStaleQuoteError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        self.assertEqual(len(emu.submitted_oso_payloads), 0)
        self.assertTrue(venue.verify_audit_chain())

        # Future-skewed beyond 5.0s tolerance (+10s) MUST fail closed with TradovateStaleQuoteError!
        future_ts = self.clock() + timedelta(seconds=10)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=future_ts)
        with self.assertRaises(TradovateStaleQuoteError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )

        # Slightly future-skewed (+2s, inside 5s tolerance) STILL preserves timestamp -> valve vetoes STALE_OR_FUTURE_STATE!
        slight_future_ts = self.clock() + timedelta(seconds=2)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=slight_future_ts)
        with self.assertRaises(TradovateValveRefusalError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )

        # Missing, unparseable, and naive observed_at on custom transport quote MUST all fail closed!
        bad_quotes: list[tuple[str, Any]] = [
            ("missing_observed_at", SimpleNamespace(symbol="MNQ", bid=Decimal("20000.00"), ask=Decimal("20000.25"), observed_at=None)),
            ("unparseable_observed_at", SimpleNamespace(symbol="MNQ", bid=Decimal("20000.00"), ask=Decimal("20000.25"), observed_at="not-a-date")),
            ("naive_observed_at", SimpleNamespace(symbol="MNQ", bid=Decimal("20000.00"), ask=Decimal("20000.25"), observed_at=datetime(2026, 11, 20, 15, 0, 0))),
            ("none_quote", None),
        ]
        for label, bad_q in bad_quotes:
            with self.subTest(bad_quote=label):
                class _BadQuoteTransport(TradovateMicroFuturesPaperEmulator):
                    def get_quote(self, symbol_or_root: str) -> Any:
                        return bad_q

                bt = _BadQuoteTransport(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
                bv = TradovateMicroFuturesVenue(
                    db_path=self.tmp / f"bad_q_{label}.sqlite3",
                    transport=bt,
                    valve_gate=self.valve,
                    enabled=True,
                    clock=self.clock,
                )
                with self.assertRaises(TradovateStaleQuoteError):
                    bv.place_bracket_order(
                        symbol="NAS100",
                        side="BUY",
                        stop_distance_points=Decimal("25.00"),
                        take_profit_points=Decimal("60.00"),
                    )

    def test_pre_dispatch_quote_age_recheck_blocks_quote_that_ages_during_valve_eval(self) -> None:
        t0 = self.clock()
        emu = TradovateMicroFuturesPaperEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=t0)

        # Quote is 28s old at entry admission (fresh <= 30s), then ages +5s during valve eval -> 33s at dispatch!
        self.clock.advance(28)

        class _SlowValveGate:
            def __init__(self, inner: Any, clk: _MutableClock) -> None:
                self._inner = inner
                self._clk = clk

            def require_admissible(self, proposal: Any, *, current_view=None, policy=None, now=None) -> Any:
                dec = self._inner.require_admissible(
                    proposal, current_view=current_view, policy=policy, now=now
                )
                self._clk.advance(5)
                return dec

        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "toctou_stale.sqlite3",
            transport=emu,
            valve_gate=_SlowValveGate(self.valve, self.clock),
            enabled=True,
            clock=self.clock,
        )
        with self.assertRaises(TradovateStaleQuoteError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        self.assertEqual(len(emu.submitted_oso_payloads), 0)
        self.assertTrue(venue.verify_audit_chain())


class TestAudit0b16e88TradovateHygiene(unittest.TestCase):
    """Hard security hygiene constraints across owned futures files."""

    def test_owned_files_lf_only_no_bom_no_nosec_no_assert_no_float_no_urlopen(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        src_files = [
            repo_root / "src" / "cas_forex_revamp" / "futures" / "tradovate_venue.py",
            repo_root / "src" / "cas_forex_revamp" / "futures" / "micro_futures_specs.py",
            repo_root / "src" / "cas_forex_revamp" / "futures" / "__init__.py",
        ]
        for path in src_files:
            raw = path.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"BOM forbidden in {path.name}")
            self.assertNotIn(b"\r", raw, f"CR forbidden in {path.name}")
            text = raw.decode("utf-8")
            self.assertNotIn("# " + "nosec", text, f"nosec marker forbidden in {path.name}")
            self.assertNotIn("urlopen(", text, f"urlopen forbidden in {path.name}")
            tree = ast.parse(text)
            asserts = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
            self.assertEqual(asserts, [], f"assert forbidden in {path.name}: {asserts}")

        tv_text = (repo_root / "src" / "cas_forex_revamp" / "futures" / "tradovate_venue.py").read_text(
            encoding="utf-8"
        )
        tv_tree = ast.parse(tv_text)
        floats = [
            n.lineno
            for n in ast.walk(tv_tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "float"
        ]
        self.assertEqual(floats, [], f"float() forbidden in tradovate_venue.py: {floats}")
        self.assertIn("class _PinnedPublicIPHTTPSConnection", tv_text)

        # Verify TradovateCredentials.__repr__ has no quoted secret=/key= leaks.
        creds = TradovateCredentials(
            enabled=False,
            mode=TRADOVATE_MODE_DEMO,
            password=_RedactedSecret(f"pw-{secrets.token_hex(6)}"),
            sec=_RedactedSecret(f"sc-{secrets.token_hex(6)}"),
            bearer_token=_RedactedSecret(f"tk-{secrets.token_hex(6)}"),
        )
        rendered = repr(creds)
        self.assertNotIn("sec" + "ret=", rendered.lower())
        self.assertNotIn("ke" + "y=", rendered.lower())


if __name__ == "__main__":
    unittest.main()
