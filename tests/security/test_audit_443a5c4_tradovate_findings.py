"""Security regression tests for PR #32 Tradovate Findings [1], [2], and [3] (audit_443a5c4)."""
from __future__ import annotations

import ast
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import inspect
from pathlib import Path
import secrets
import sqlite3
import tempfile
from types import SimpleNamespace
from typing import Any
import unittest

from cas_forex_revamp.futures.tradovate_venue import (
    BROKER_TRADOVATE_FUTURES,
    ENV_TRADOVATE_ACCOUNT_ID,
    ENV_TRADOVATE_ACCOUNT_SPEC,
    FuturesOrderAction,
    LIVE_ARM_CONFIRMATION_TEXT,
    MUTATION_STATUS_OUTCOME_UNKNOWN,
    MUTATION_STATUS_PENDING,
    TRADOVATE_DEMO_BASE_URL,
    TRADOVATE_LIVE_BASE_URL,
    TRADOVATE_LIVE_HOST,
    TRADOVATE_MODE_DEMO,
    TRADOVATE_MODE_LIVE,
    TradovateAccountSnapshot,
    TradovateCredentials,
    TradovateHttpsTransport,
    TradovateMicroFuturesPaperEmulator,
    TradovateMicroFuturesVenue,
    TradovateOrderError,
    TradovateOrderReceipt,
    TradovateOrderRequest,
    TradovateOutcomeUnknownError,
    TradovatePosition,
    TradovateTransportError,
    _RedactedSecret,
    load_default_forex_valve_gate,
    load_tradovate_credentials,
    verify_live_authorization_context,
)
from cas_forex_revamp.venue.live_auth_ticket import (
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
    account_id: str = "TV-LIVE-A1",
    ttl_seconds: int = 600,
    now: datetime | None = None,
    key_name: str = "tv_live.key",
):
    key_file = provision_live_auth_key(tmp_dir / key_name)
    issued = now or _utc(2026, 11, 20, 15, 0)
    ticket = mint_live_authorization_ticket(
        key_file=key_file,
        broker_id=BROKER_TRADOVATE_FUTURES,
        account_login=account_id,
        server=TRADOVATE_LIVE_HOST,
        ttl_seconds=ttl_seconds,
        issued_at=issued,
    )
    _verified, ctx = verify_live_authorization_context(
        ticket,
        key_file=key_file,
        expected_broker_id=BROKER_TRADOVATE_FUTURES,
        expected_account_login=account_id,
        expected_server=TRADOVATE_LIVE_HOST,
        live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
        require_arm_phrase=True,
        now=issued,
    )
    return key_file, ticket, ctx


def _make_https_transport(
    clock: _MutableClock,
    *,
    account_id: str = "100100",
    account_spec: str = "",
) -> TradovateHttpsTransport:
    creds = TradovateCredentials(
        enabled=True,
        mode=TRADOVATE_MODE_DEMO,
        base_url=TRADOVATE_DEMO_BASE_URL,
        account_id=account_id,
        account_spec=account_spec,
        bearer_token=_RedactedSecret(f"tok-{secrets.token_hex(8)}"),
    )
    t = TradovateHttpsTransport(credentials=creds, clock=clock)
    t.connect()
    return t


class TestAudit443a5c4Finding01MultiAccountIsolation(unittest.TestCase):
    """Finding [1]: Strict account_id/accountSpec binding on reads, filters, and protective mutations."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_empty_account_id_fails_closed_on_https_transport(self) -> None:
        creds = TradovateCredentials(
            enabled=True,
            mode=TRADOVATE_MODE_DEMO,
            base_url=TRADOVATE_DEMO_BASE_URL,
            account_id="",
            bearer_token=_RedactedSecret(f"tok-{secrets.token_hex(8)}"),
        )
        t = TradovateHttpsTransport(credentials=creds, clock=self.clock)
        with self.assertRaises(TradovateTransportError):
            t.connect()

        t._connected = True
        with self.assertRaises(TradovateTransportError):
            t.account_snapshot()
        with self.assertRaises(TradovateTransportError):
            t.positions()
        with self.assertRaises(TradovateTransportError):
            t.list_orders()
        with self.assertRaises(TradovateTransportError):
            t.list_order_deps()
        with self.assertRaises(TradovateTransportError):
            t.list_orders_paginated()

    def test_account_id_and_account_spec_sent_on_all_queries_and_mutations(self) -> None:
        creds = load_tradovate_credentials(
            {
                "CAS_FOREX_TRADOVATE_ENABLED": "1",
                "CAS_FOREX_TRADOVATE_MODE": "DEMO",
                ENV_TRADOVATE_ACCOUNT_ID: "100100",
                ENV_TRADOVATE_ACCOUNT_SPEC: "SPEC-ALPHA",
            }
        )
        self.assertEqual(creds.account_id, "100100")
        self.assertEqual(creds.account_spec, "SPEC-ALPHA")
        self.assertEqual(creds.effective_account_spec, "SPEC-ALPHA")

        t = _make_https_transport(self.clock, account_id="100100", account_spec="SPEC-ALPHA")
        seen_endpoints: list[tuple[str, str, dict[str, Any] | None]] = []

        def fake_json(method: str, ep: str, *, payload: dict[str, Any] | None = None, require_auth: bool = True):
            seen_endpoints.append((method, ep, dict(payload) if payload is not None else None))
            if ep.startswith("cashBalance/getcashbalancesnapshot"):
                return {
                    "accountId": 100100,
                    "accountSpec": "SPEC-ALPHA",
                    "amount": Decimal("5000.00"),
                    "openPnL": Decimal("0.00"),
                    "initialMargin": Decimal("0.00"),
                }
            if ep == "order/modifyOrder":
                return {
                    "orderId": 9002,
                    "accountId": 100100,
                    "accountSpec": "SPEC-ALPHA",
                    "clOrdId": (payload or {}).get("clOrdId"),
                    "ordStatus": "Working",
                    "stopPrice": (payload or {}).get("stopPrice"),
                }
            if ep == "order/liquidatePosition":
                return {
                    "orderId": 9005,
                    "accountId": 100100,
                    "accountSpec": "SPEC-ALPHA",
                    "clOrdId": (payload or {}).get("clOrdId"),
                    "ordStatus": "Filled",
                    "filledQty": 1,
                }
            raise AssertionError(f"Unexpected endpoint {ep}")

        def fake_list(method: str, ep: str, *, require_auth: bool = True):
            seen_endpoints.append((method, ep, None))
            if ep.startswith("position/list"):
                return [
                    {
                        "id": "POS-A1",
                        "accountId": 100100,
                        "accountSpec": "SPEC-ALPHA",
                        "contractCode": "MNQZ6",
                        "rootSymbol": "MNQ",
                        "netPos": 1,
                        "netPrice": Decimal("20000.25"),
                        "stopLossOrderId": "9002",
                    }
                ]
            if ep.startswith("order/list") or ep.startswith("order/deps"):
                return [
                    {
                        "id": "9001",
                        "accountId": 100100,
                        "accountSpec": "SPEC-ALPHA",
                        "clOrdId": "cl-alpha-1",
                        "ordStatus": "Filled",
                    }
                ]
            raise AssertionError(f"Unexpected list endpoint {ep}")

        t._request_json = fake_json  # type: ignore[method-assign]
        t._request_json_list = fake_list  # type: ignore[method-assign]

        snap = t.account_snapshot()
        self.assertEqual(snap.account_id, "100100")
        pos = t.positions()
        self.assertEqual(len(pos), 1)
        self.assertEqual(pos[0].account_id, "100100")
        orders = t.list_orders()
        self.assertEqual(len(orders), 1)
        deps = t.list_order_deps()
        self.assertEqual(len(deps), 1)

        t.send_order(
            TradovateOrderRequest(
                request_id="req-m1",
                cl_ord_id="cl-m1",
                action=FuturesOrderAction.AMEND_STOP,
                contract_code="MNQZ6",
                root_symbol="MNQ",
                cas_symbol="NAS100",
                side="BUY",
                contracts=1,
                order_id="9002",
                position_id="POS-A1",
                stop_loss_price=Decimal("19980.00"),
                created_at=self.clock(),
            )
        )
        t.send_order(
            TradovateOrderRequest(
                request_id="req-c1",
                cl_ord_id="cl-c1",
                action=FuturesOrderAction.CLOSE_POSITION,
                contract_code="MNQZ6",
                root_symbol="MNQ",
                cas_symbol="NAS100",
                side="BUY",
                contracts=1,
                position_id="POS-A1",
                created_at=self.clock(),
            )
        )

        get_eps = [ep for m, ep, _ in seen_endpoints if m == "GET"]
        for prefix in ("cashBalance/getcashbalancesnapshot?", "position/list?", "order/list?", "order/deps?"):
            matched = [ep for ep in get_eps if ep.startswith(prefix)]
            self.assertEqual(len(matched), 1, f"Expected query for {prefix}")
            self.assertIn("accountId=100100", matched[0])
            self.assertIn("accountSpec=SPEC-ALPHA", matched[0])

        post_payloads = [pl for m, _, pl in seen_endpoints if m == "POST"]
        self.assertEqual(len(post_payloads), 2)
        for pl in post_payloads:
            self.assertIsNotNone(pl)
            self.assertEqual(pl["accountId"], 100100)
            self.assertEqual(pl["accountSpec"], "SPEC-ALPHA")

    def test_balance_missing_or_mismatched_account_id_rejected_fail_closed(self) -> None:
        for label, bad_resp in (
            ("missing_account_id", {"amount": Decimal("500000.00"), "openPnL": Decimal("0.00")}),
            ("empty_account_id", {"accountId": "", "amount": Decimal("500000.00")}),
            ("bool_account_id", {"accountId": True, "amount": Decimal("500000.00")}),
            ("other_account_id", {"accountId": "ACCT-B", "amount": Decimal("500000.00")}),
            ("mismatched_account_spec", {"accountId": "ACCT-A", "accountSpec": "SPEC-B", "amount": Decimal("5000.00")}),
        ):
            with self.subTest(case=label):
                t = _make_https_transport(self.clock, account_id="ACCT-A", account_spec="SPEC-A")
                t._request_json = lambda _m, _ep, payload=None, require_auth=True, d=bad_resp: d  # type: ignore[method-assign]
                with self.assertRaises(TradovateTransportError):
                    t.account_snapshot()

        t_venue = _make_https_transport(self.clock, account_id="ACCT-A")
        t_venue._request_json = lambda _m, _ep, payload=None, require_auth=True: {  # type: ignore[method-assign]
            "accountId": "ACCT-B",
            "amount": Decimal("999999.00"),
            "openPnL": Decimal("0.00"),
            "initialMargin": Decimal("0.00"),
        }
        t_venue._request_json_list = lambda _m, _ep, require_auth=True: []  # type: ignore[method-assign]
        db_path = self.tmp / "cross_acct_bal.sqlite3"
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=t_venue,
            valve_gate=self.valve,
            account_id="ACCT-A",
            enabled=True,
            clock=self.clock,
        )
        with self.assertRaises(TradovateTransportError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        with self.assertRaises(TradovateTransportError):
            venue.snapshot()
        with closing(sqlite3.connect(str(db_path))) as conn:
            peak = conn.execute("SELECT peak_equity_usd FROM venue_meta WHERE id = 1").fetchone()[0]
        self.assertEqual(Decimal(peak), Decimal("0.00"))

    def test_position_and_order_lists_reject_missing_account_id_and_filter_foreign_accounts(self) -> None:
        t = _make_https_transport(self.clock, account_id="ACCT-A")

        t._request_json_list = lambda _m, _ep, require_auth=True: [  # type: ignore[method-assign]
            {
                "id": "POS-B-99",
                "accountId": "ACCT-B",
                "contractCode": "MNQZ6",
                "rootSymbol": "MNQ",
                "netPos": 3,
                "netPrice": Decimal("20000.25"),
                "stopLossOrderId": "SL-B",
            },
            {
                "id": "POS-A-1",
                "accountId": "ACCT-A",
                "contractCode": "MESZ6",
                "rootSymbol": "MES",
                "netPos": 1,
                "netPrice": Decimal("6000.00"),
                "stopLossOrderId": "SL-A",
            },
        ]
        filtered_pos = t.positions()
        self.assertEqual([p.position_id for p in filtered_pos], ["POS-A-1"])
        self.assertEqual(filtered_pos[0].account_id, "ACCT-A")

        t._request_json_list = lambda _m, _ep, require_auth=True: [  # type: ignore[method-assign]
            {
                "id": "POS-NO-ACCT",
                "contractCode": "MNQZ6",
                "rootSymbol": "MNQ",
                "netPos": 0,
                "netPrice": Decimal("20000.25"),
            }
        ]
        with self.assertRaises(TradovateTransportError):
            t.positions()

        liquidate_calls = 0

        def fake_post(m: str, ep: str, *, payload: dict[str, Any] | None = None, require_auth: bool = True):
            nonlocal liquidate_calls
            if ep.startswith("cashBalance/getcashbalancesnapshot"):
                return {
                    "accountId": "ACCT-A",
                    "amount": Decimal("5000.00"),
                    "openPnL": Decimal("0.00"),
                    "initialMargin": Decimal("0.00"),
                }
            liquidate_calls += 1
            return {"orderId": 9999}

        t._request_json = fake_post  # type: ignore[method-assign]
        t._request_json_list = lambda _m, _ep, require_auth=True: [  # type: ignore[method-assign]
            {
                "id": "POS-B-99",
                "accountId": "ACCT-B",
                "contractCode": "MNQZ6",
                "rootSymbol": "MNQ",
                "netPos": 2,
                "netPrice": Decimal("20000.25"),
                "stopLossOrderId": "SL-B",
            }
        ]
        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "cross_acct_pos.sqlite3",
            transport=t,
            valve_gate=self.valve,
            account_id="ACCT-A",
            enabled=True,
            clock=self.clock,
        )
        with self.assertRaises(TradovateOrderError):
            venue.amend_stop("POS-B-99", Decimal("19990.00"))
        with self.assertRaises(TradovateOrderError):
            venue.amend_protective_brackets("POS-B-99", Decimal("19990.00"))
        with self.assertRaises(TradovateOrderError):
            venue.close_position("POS-B-99")
        self.assertEqual(venue.emergency_close_all(), ())
        self.assertEqual(liquidate_calls, 0)

        t._request_json_list = lambda _m, _ep, require_auth=True: [  # type: ignore[method-assign]
            {"id": "1", "accountId": "ACCT-B", "clOrdId": "cl-b"},
            {"id": "2", "accountId": "ACCT-A", "clOrdId": "cl-a"},
        ]
        self.assertEqual([o["id"] for o in t.list_orders()], ["2"])
        self.assertEqual([o["id"] for o in t.list_order_deps()], ["2"])

        t._request_json_list = lambda _m, _ep, require_auth=True: [{"id": "3", "clOrdId": "no-acct"}]  # type: ignore[method-assign]
        with self.assertRaises(TradovateTransportError):
            t.list_orders()
        with self.assertRaises(TradovateTransportError):
            t.list_order_deps()

    def test_venue_rejects_foreign_position_objects_from_custom_transport_before_mutation(self) -> None:
        now = self.clock()
        mutated = 0

        class _CrossAccountCustomTransport:
            account_id = "ACCT-A"

            def connect(self) -> None:
                pass

            def disconnect(self) -> None:
                pass

            def is_connected(self) -> bool:
                return True

            def account_snapshot(self, *, now_utc: datetime | None = None) -> TradovateAccountSnapshot:
                return TradovateAccountSnapshot(
                    account_id="ACCT-A",
                    mode=TRADOVATE_MODE_DEMO,
                    connected=True,
                    connection_status="TERMINAL_CONNECTED",
                    currency="USD",
                    balance_usd=Decimal("5000.00"),
                    equity_usd=Decimal("5000.00"),
                    peak_equity_usd=Decimal("5000.00"),
                    drawdown_pct=Decimal("0.0000"),
                    used_margin_usd=Decimal("0.00"),
                    available_margin_usd=Decimal("5000.00"),
                    margin_level_pct=None,
                    floating_pnl_usd=Decimal("0.00"),
                    realized_pnl_usd=Decimal("0.00"),
                    total_commissions_usd=Decimal("0.00"),
                    open_position_count=1,
                    observed_at=now,
                )

            def positions(self) -> tuple[TradovatePosition, ...]:
                return (
                    TradovatePosition(
                        position_id="POS-FOREIGN",
                        contract_code="MNQZ6",
                        root_symbol="MNQ",
                        cas_symbol="NAS100",
                        side="BUY",
                        contracts=1,
                        entry_price=Decimal("20000.25"),
                        current_price=Decimal("20000.25"),
                        stop_loss_price=Decimal("19975.25"),
                        take_profit_price=Decimal("20060.25"),
                        used_margin_usd=Decimal("100.00"),
                        floating_pnl_usd=Decimal("0.00"),
                        commission_usd=Decimal("1.24"),
                        opened_at=now,
                        updated_at=now,
                        stop_loss_order_id="SL-1",
                        account_id="ACCT-B",
                    ),
                )

            def get_quote(self, symbol_or_root: str):
                raise TradovateTransportError("unused")

            def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                nonlocal mutated
                mutated += 1
                raise AssertionError("send_order must never be reached for foreign position")

        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "custom_cross_acct.sqlite3",
            transport=_CrossAccountCustomTransport(),
            valve_gate=self.valve,
            account_id="ACCT-A",
            enabled=True,
            clock=self.clock,
        )
        with self.assertRaises(TradovateTransportError):
            venue.amend_stop("POS-FOREIGN", Decimal("19990.00"))
        with self.assertRaises(TradovateTransportError):
            venue.close_position("POS-FOREIGN")
        with self.assertRaises(TradovateTransportError):
            venue.emergency_close_all()
        self.assertEqual(mutated, 0)

    def test_live_mode_binds_authorized_account_across_reads_and_protections(self) -> None:
        now = self.clock()
        _kf, _tkt, ctx = _mint_live_ctx(self.tmp, account_id="TV-LIVE-A1", now=now)
        live_creds = TradovateCredentials(
            enabled=True,
            mode=TRADOVATE_MODE_LIVE,
            base_url=TRADOVATE_LIVE_BASE_URL,
            account_id="TV-LIVE-A1",
            live_auth_context=ctx,
            live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
            auth_checked_at=now,
            bearer_token=_RedactedSecret(f"live-{secrets.token_hex(8)}"),
        )
        t = TradovateHttpsTransport(credentials=live_creds, clock=self.clock)
        t.connect()
        t._request_json = lambda _m, _ep, payload=None, require_auth=True: {  # type: ignore[method-assign]
            "accountId": "TV-LIVE-B2",
            "amount": Decimal("50000.00"),
        }
        with self.assertRaises(TradovateTransportError):
            t.account_snapshot()


class TestAudit443a5c4Finding02ProtectiveProtocol(unittest.TestCase):
    """Finding [2]: Pre-journaled PENDING, strict response validation, OUTCOME_UNKNOWN & multi-leg emergency."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_protective_mutations_commit_pending_before_io_and_enforce_idempotency(self) -> None:
        db_path = self.tmp / "prot_pending.sqlite3"
        observed_before_io: list[tuple[str, str, str, str]] = []

        class _InspectingTransport(TradovateMicroFuturesPaperEmulator):
            def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                if request.action in (FuturesOrderAction.AMEND_STOP, FuturesOrderAction.CLOSE_POSITION):
                    with closing(sqlite3.connect(str(db_path))) as conn:
                        row = conn.execute(
                            "SELECT status, cl_ord_id, action FROM mutation_journal WHERE request_id = ?",
                            (request.request_id,),
                        ).fetchone()
                    if row is not None:
                        observed_before_io.append(
                            (request.action.value, str(row[0]), str(row[1]), str(request.cl_ord_id))
                        )
                return super().send_order(request)

        emu = _InspectingTransport(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        emu.set_quote("US30", Decimal("43000.00"), Decimal("43001.00"), observed_at=self.clock())
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=emu,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )

        r1 = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
        )
        r2 = venue.place_bracket_order(
            symbol="US30",
            side="BUY",
            stop_distance_points=Decimal("50.00"),
            take_profit_points=Decimal("100.00"),
        )

        amend_rec = venue.amend_stop(r1.position_id, Decimal("19990.00"), idempotency_key="be-1")
        self.assertEqual(amend_rec.status, "AMENDED")
        self.assertIsNotNone(amend_rec.cl_ord_id)
        self.assertLessEqual(len(amend_rec.cl_ord_id or ""), 64)

        pre_count = len(observed_before_io)
        with self.assertRaises(TradovateOrderError):
            venue.amend_stop(r1.position_id, Decimal("19990.00"), idempotency_key="be-1")
        self.assertEqual(len(observed_before_io), pre_count)

        close_rec = venue.close_position(r1.position_id, idempotency_key="close-1")
        self.assertEqual(close_rec.status, "CLOSED")
        self.assertIsNotNone(close_rec.cl_ord_id)

        emerg_recs = venue.emergency_close_all(idempotency_key="emerg-1")
        self.assertEqual(len(emerg_recs), 1)
        self.assertEqual(emerg_recs[0].position_id, r2.position_id)

        self.assertEqual(len(observed_before_io), 3)
        for _act, status, db_cl, req_cl in observed_before_io:
            self.assertEqual(status, MUTATION_STATUS_PENDING)
            self.assertEqual(db_cl, req_cl)
        self.assertTrue(venue.verify_audit_chain())

    def test_https_transport_rejects_empty_error_rejected_and_mismatched_protective_responses(self) -> None:
        t = _make_https_transport(self.clock, account_id="ACCT-A")
        amend_req = TradovateOrderRequest(
            request_id="req-a1",
            cl_ord_id="cas-tv-amend-test-1",
            action=FuturesOrderAction.AMEND_STOP,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            order_id="9002",
            position_id="POS-1",
            stop_loss_price=Decimal("20000.00"),
            created_at=self.clock(),
        )
        close_req = TradovateOrderRequest(
            request_id="req-c1",
            cl_ord_id="cas-tv-close-test-1",
            action=FuturesOrderAction.CLOSE_POSITION,
            contract_code="MNQZ6",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            position_id="POS-1",
            created_at=self.clock(),
        )

        bad_amend_bodies: list[tuple[str, dict[str, Any]]] = [
            ("empty_dict", {}),
            ("missing_order_id", {"ordStatus": "Working", "clOrdId": "cas-tv-amend-test-1"}),
            ("error_text_with_id", {"orderId": 9002, "errorText": "Cannot modify stop"}),
            ("failure_reason", {"orderId": 9002, "failureReason": "Rejected"}),
            ("failure_text", {"orderId": 9002, "failureText": "Invalid price"}),
            ("status_rejected", {"orderId": 9002, "ordStatus": "Rejected"}),
            ("status_expired", {"orderId": 9002, "ordStatus": "Expired"}),
            ("status_canceled", {"orderId": 9002, "ordStatus": "Canceled"}),
            ("status_pending_new", {"orderId": 9002, "ordStatus": "PendingNew"}),
            ("wrong_cl_ord_id", {"orderId": 9002, "ordStatus": "Working", "clOrdId": "other"}),
            ("wrong_account_id", {"orderId": 9002, "ordStatus": "Working", "accountId": "ACCT-B"}),
            ("wrong_stop_price", {"orderId": 9002, "ordStatus": "Working", "stopPrice": Decimal("19950.00")}),
            ("wrong_qty", {"orderId": 9002, "ordStatus": "Working", "orderQty": 3}),
        ]
        for label, resp_body in bad_amend_bodies:
            with self.subTest(amend_case=label):
                t._request_json = lambda _m, _ep, payload=None, require_auth=True, d=resp_body: d  # type: ignore[method-assign]
                with self.assertRaises(TradovateTransportError):
                    t.send_order(amend_req)

        bad_close_bodies: list[tuple[str, dict[str, Any]]] = [
            ("empty_dict", {}),
            ("missing_order_id", {"ordStatus": "Filled", "filledQty": 1}),
            ("error_text", {"orderId": 9009, "errorText": "Position not found"}),
            ("status_rejected", {"orderId": 9009, "ordStatus": "Rejected"}),
            ("status_expired", {"orderId": 9009, "ordStatus": "Expired"}),
            ("status_canceled", {"orderId": 9009, "ordStatus": "Canceled"}),
            ("status_working", {"orderId": 9009, "ordStatus": "Working"}),
            ("zero_filled_qty", {"orderId": 9009, "ordStatus": "Filled", "filledQty": 0}),
            ("wrong_symbol", {"orderId": 9009, "ordStatus": "Filled", "symbol": "MESZ6"}),
            ("wrong_cl_ord_id", {"orderId": 9009, "ordStatus": "Filled", "clOrdId": "wrong"}),
            ("wrong_account_id", {"orderId": 9009, "ordStatus": "Filled", "accountId": "ACCT-B"}),
        ]
        for label, resp_body in bad_close_bodies:
            with self.subTest(close_case=label):
                t._request_json = lambda _m, _ep, payload=None, require_auth=True, d=resp_body: d  # type: ignore[method-assign]
                with self.assertRaises(TradovateTransportError):
                    t.send_order(close_req)

    def test_protective_timeout_rejection_and_post_effect_sqlite_failure_engage_freeze_without_retry(self) -> None:
        for action_kind in ("amend", "close"):
            for mode in ("timeout", "rejection"):
                with self.subTest(action=action_kind, failure_mode=mode):
                    db_path = self.tmp / f"prot_{action_kind}_{mode}.sqlite3"

                    class _FaultyProtEmulator(TradovateMicroFuturesPaperEmulator):
                        def __init__(self, *args: Any, **kwargs: Any) -> None:
                            super().__init__(*args, **kwargs)
                            self.prot_calls = 0

                        def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                            if request.action in (FuturesOrderAction.AMEND_STOP, FuturesOrderAction.CLOSE_POSITION):
                                self.prot_calls += 1
                                if mode == "timeout":
                                    raise TimeoutError("socket read timeout after POST")
                                return TradovateOrderReceipt(
                                    request_id=request.request_id,
                                    cl_ord_id=request.cl_ord_id,
                                    action=request.action,
                                    accepted=False,
                                    status="Rejected",
                                    order_id="ERR-1",
                                    position_id=request.position_id,
                                    contract_code=request.contract_code,
                                    root_symbol=request.root_symbol,
                                    cas_symbol=request.cas_symbol,
                                    side=request.side,
                                    filled_contracts=0,
                                    fill_price=None,
                                    stop_loss_price=request.stop_loss_price,
                                    take_profit_price=None,
                                    commission_usd=Decimal("0.00"),
                                    realized_pnl_usd=Decimal("0.00"),
                                    net_pnl_usd=Decimal("0.00"),
                                    reason="REJECTED",
                                    executed_at=self._clock(),
                                )
                            return super().send_order(request)

                    emu = _FaultyProtEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
                    emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
                    venue = TradovateMicroFuturesVenue(
                        db_path=db_path,
                        transport=emu,
                        valve_gate=self.valve,
                        enabled=True,
                        clock=self.clock,
                    )
                    pos = venue.place_bracket_order(
                        symbol="NAS100",
                        side="BUY",
                        stop_distance_points=Decimal("25.00"),
                        take_profit_points=Decimal("60.00"),
                    )

                    with self.assertRaises(TradovateOutcomeUnknownError) as ctx:
                        if action_kind == "amend":
                            venue.amend_stop(pos.position_id, Decimal("19990.00"), idempotency_key="k1")
                        else:
                            venue.close_position(pos.position_id, idempotency_key="k1")
                    cl_id = ctx.exception.cl_ord_id
                    self.assertIsNotNone(cl_id)
                    self.assertEqual(emu.prot_calls, 1)

                    snap = venue.snapshot()
                    self.assertTrue(snap["outcome_unknown_freeze"])
                    self.assertEqual(snap["unresolved_mutation_count"], 1)
                    self.assertEqual(snap["unresolved_mutations"][0]["status"], MUTATION_STATUS_OUTCOME_UNKNOWN)

                    with self.assertRaises(TradovateOutcomeUnknownError):
                        if action_kind == "amend":
                            venue.amend_stop(pos.position_id, Decimal("19990.00"), idempotency_key="k1")
                        else:
                            venue.close_position(pos.position_id, idempotency_key="k1")
                    self.assertEqual(emu.prot_calls, 1)

                    with self.assertRaises(TradovateOutcomeUnknownError):
                        venue.place_bracket_order(
                            symbol="NAS100",
                            side="BUY",
                            stop_distance_points=Decimal("25.00"),
                            take_profit_points=Decimal("60.00"),
                        )
                    self.assertTrue(venue.verify_audit_chain())

        db_sql = self.tmp / "post_effect_sqlite_fail.sqlite3"
        emu2 = TradovateMicroFuturesPaperEmulator(starting_equity_usd=Decimal("5000.00"), clock=self.clock)
        emu2.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        venue2 = TradovateMicroFuturesVenue(
            db_path=db_sql,
            transport=emu2,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )
        pos2 = venue2.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
        )
        orig_connect_rw = venue2._connect_rw
        rw_calls = 0

        def flaky_connect_rw() -> sqlite3.Connection:
            nonlocal rw_calls
            rw_calls += 1
            if rw_calls == 2:
                raise sqlite3.OperationalError("simulated post-effect SQLite disk full")
            return orig_connect_rw()

        venue2._connect_rw = flaky_connect_rw  # type: ignore[method-assign]
        with self.assertRaises(TradovateOutcomeUnknownError):
            venue2.amend_stop(pos2.position_id, Decimal("19995.00"), idempotency_key="post-sql-1")
        venue2._connect_rw = orig_connect_rw  # type: ignore[method-assign]
        self.assertTrue(venue2.snapshot()["outcome_unknown_freeze"])
        self.assertEqual(venue2.snapshot()["unresolved_mutations"][0]["status"], MUTATION_STATUS_OUTCOME_UNKNOWN)
        self.assertTrue(venue2.verify_audit_chain())

    def test_emergency_close_all_journals_dispatches_and_reconciles_each_leg_independently(self) -> None:
        db_path = self.tmp / "emerg_multi_leg.sqlite3"

        class _PartialFailEmergencyEmulator(TradovateMicroFuturesPaperEmulator):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self.close_dispatches: list[tuple[str, str]] = []

            def send_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                if request.action is FuturesOrderAction.CLOSE_POSITION:
                    self.close_dispatches.append((str(request.position_id), str(request.cl_ord_id)))
                    if len(self.close_dispatches) == 2:
                        raise TimeoutError("leg 2 timeout after dispatch")
                    if len(self.close_dispatches) == 3:
                        raise TradovateTransportError("leg 3 HTTP 503", http_status=503)
                return super().send_order(request)

        emu = _PartialFailEmergencyEmulator(starting_equity_usd=Decimal("10000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        emu.set_quote("US30", Decimal("43000.00"), Decimal("43001.00"), observed_at=self.clock())
        emu.set_quote("SPX500", Decimal("6000.00"), Decimal("6000.25"), observed_at=self.clock())
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=emu,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )
        p1 = venue.place_bracket_order(symbol="NAS100", side="BUY", stop_distance_points=Decimal("25.00"), take_profit_points=Decimal("60.00"))
        p2 = venue.place_bracket_order(symbol="US30", side="BUY", stop_distance_points=Decimal("50.00"), take_profit_points=Decimal("100.00"))
        p3 = venue.place_bracket_order(symbol="SPX500", side="BUY", stop_distance_points=Decimal("10.00"), take_profit_points=Decimal("20.00"))

        with self.assertRaises(TradovateOutcomeUnknownError):
            venue.emergency_close_all(idempotency_key="emerg-3-legs")

        self.assertEqual(len(emu.close_dispatches), 3)
        dispatched_pids = [pid for pid, _ in emu.close_dispatches]
        dispatched_cls = [cid for _, cid in emu.close_dispatches]
        self.assertEqual(dispatched_pids, [p1.position_id, p2.position_id, p3.position_id])
        self.assertEqual(len(set(dispatched_cls)), 3)

        with closing(sqlite3.connect(str(db_path))) as conn:
            rows = conn.execute(
                "SELECT cl_ord_id, status FROM mutation_journal WHERE cl_ord_id IN (?, ?, ?) ORDER BY seq ASC",
                tuple(dispatched_cls),
            ).fetchall()
        self.assertEqual(
            [(str(r[0]), str(r[1])) for r in rows],
            [
                (dispatched_cls[0], "CLOSED"),
                (dispatched_cls[1], MUTATION_STATUS_OUTCOME_UNKNOWN),
                (dispatched_cls[2], MUTATION_STATUS_OUTCOME_UNKNOWN),
            ],
        )

        emu._order_history.append(
            {
                "accountId": emu.account_id,
                "clOrdId": dispatched_cls[1],
                "orderId": "ORD-LEG2-FILLED",
                "ordStatus": "Filled",
                "filledQty": 1,
            }
        )
        res_leg2 = venue.reconcile_unknown_outcome(cl_ord_id=dispatched_cls[1])
        self.assertEqual(res_leg2["reconciled"][0]["new_status"], "RECONCILED_CLOSED")
        self.assertTrue(res_leg2["freeze_active"])
        self.assertEqual(res_leg2["remaining_unresolved_count"], 1)

        res_leg3 = venue.reconcile_unknown_outcome(cl_ord_id=dispatched_cls[2])
        self.assertEqual(res_leg3["reconciled"][0]["new_status"], "RECONCILED_ABSENT")
        self.assertFalse(res_leg3["freeze_active"])
        self.assertEqual(res_leg3["remaining_unresolved_count"], 0)
        self.assertTrue(venue.verify_audit_chain())

    def test_protective_actions_remain_allowed_during_earlier_outcome_unknown_freeze(self) -> None:
        db_path = self.tmp / "prot_during_freeze.sqlite3"

        class _EntryTimeoutEmulator(TradovateMicroFuturesPaperEmulator):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self.fail_next_entry = False

            def place_protected_order(self, request: TradovateOrderRequest) -> TradovateOrderReceipt:
                if self.fail_next_entry:
                    raise TimeoutError("simulated timeout on second entry")
                return super().place_protected_order(request)

        emu = _EntryTimeoutEmulator(starting_equity_usd=Decimal("10000.00"), clock=self.clock)
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"), observed_at=self.clock())
        emu.set_quote("US30", Decimal("43000.00"), Decimal("43001.00"), observed_at=self.clock())
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=emu,
            valve_gate=self.valve,
            enabled=True,
            clock=self.clock,
        )
        p1 = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
            idempotency_key="open-1",
        )
        emu.fail_next_entry = True
        with self.assertRaises(TradovateOutcomeUnknownError):
            venue.place_bracket_order(
                symbol="US30",
                side="BUY",
                stop_distance_points=Decimal("50.00"),
                take_profit_points=Decimal("100.00"),
                idempotency_key="entry-timeout-2",
            )
        self.assertTrue(venue.snapshot()["outcome_unknown_freeze"])

        # New entries remain frozen, while protective bracket amend and close on existing position still execute.
        with self.assertRaises(TradovateOutcomeUnknownError):
            venue.place_bracket_order(
                symbol="US30",
                side="BUY",
                stop_distance_points=Decimal("50.00"),
                take_profit_points=Decimal("100.00"),
                idempotency_key="blocked-entry-3",
            )
        amended = venue.amend_protective_brackets(p1.position_id, Decimal("19992.50"), idempotency_key="prot-amend-while-frozen")
        self.assertEqual(amended.status, "AMENDED")
        emerg = venue.emergency_close_all(idempotency_key="prot-emerg-while-frozen")
        self.assertEqual(len(emerg), 1)
        self.assertEqual(emerg[0].status, "CLOSED")
        self.assertTrue(venue.snapshot()["outcome_unknown_freeze"])
        self.assertTrue(venue.verify_audit_chain())


class TestAudit443a5c4Finding03CompletenessReconciliation(unittest.TestCase):
    """Finding [3]: Reject raw caller overrides, incomplete/unpaged/stale-watermark histories; require completeness proof."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _MutableClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _create_frozen_https_venue(
        self,
        db_name: str = "reconcile.sqlite3",
        *,
        account_id: str = "ACCT-A",
    ) -> tuple[TradovateMicroFuturesVenue, TradovateHttpsTransport, str]:
        t = _make_https_transport(self.clock, account_id=account_id)

        def fake_json(method: str, ep: str, *, payload: dict[str, Any] | None = None, require_auth: bool = True):
            if ep.startswith("cashBalance/getcashbalancesnapshot"):
                return {
                    "accountId": account_id,
                    "amount": Decimal("5000.00"),
                    "openPnL": Decimal("0.00"),
                    "initialMargin": Decimal("0.00"),
                }
            raise TimeoutError("broker timeout on placeOSO")

        t._request_json = fake_json  # type: ignore[method-assign]
        t._request_json_list = lambda _m, _ep, require_auth=True: []  # type: ignore[method-assign]
        quote = SimpleNamespace(
            symbol="MNQ",
            bid=Decimal("20000.00"),
            ask=Decimal("20000.25"),
            observed_at=self.clock(),
        )
        t.get_quote = lambda _sym: quote  # type: ignore[method-assign]

        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / db_name,
            transport=t,
            valve_gate=self.valve,
            account_id=account_id,
            enabled=True,
            clock=self.clock,
        )
        with self.assertRaises(TradovateOutcomeUnknownError) as ctx:
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
                idempotency_key="rec-entry-1",
            )
        cl_id = str(ctx.exception.cl_ord_id)
        return venue, t, cl_id

    def test_raw_broker_orders_override_removed_from_production(self) -> None:
        sig = inspect.signature(TradovateMicroFuturesVenue.reconcile_unknown_outcome)
        self.assertNotIn("broker_orders", sig.parameters)

        venue, _t, cl_id = self._create_frozen_https_venue("no_override.sqlite3")
        with self.assertRaises(TypeError):
            venue.reconcile_unknown_outcome(cl_ord_id=cl_id, broker_orders=[])  # type: ignore[call-arg]
        self.assertTrue(venue.snapshot()["outcome_unknown_freeze"])

    def test_incomplete_unpaged_truncated_stale_watermark_or_mismatched_responses_keep_latch_locked(self) -> None:
        stale_ts = _utc(2026, 11, 20, 14, 59, 59)
        valid_ts = _utc(2026, 11, 20, 15, 1, 0)

        bad_responses: list[tuple[str, Any]] = [
            ("bare_empty_list", []),
            (
                "missing_watermark",
                {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": False},
            ),
            (
                "stale_watermark_before_submission",
                {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": False, "watermarkUtc": stale_ts.isoformat()},
            ),
            (
                "truncated_true",
                {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": False, "truncated": True, "watermarkUtc": valid_ts.isoformat()},
            ),
            (
                "has_more_true_no_cursor",
                {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": True, "watermarkUtc": valid_ts.isoformat()},
            ),
            (
                "missing_pagination_exhaustion_markers",
                {"accountId": "ACCT-A", "orders": [], "watermarkUtc": valid_ts.isoformat()},
            ),
            (
                "missing_envelope_account_id",
                {"orders": [], "nextCursor": None, "hasMore": False, "watermarkUtc": valid_ts.isoformat()},
            ),
        ]

        venue, t, cl_id = self._create_frozen_https_venue("bad_reconcile.sqlite3")
        for label, resp_obj in bad_responses:
            with self.subTest(case=label):
                t._request_json_raw = lambda _m, _ep, payload=None, require_auth=True, r=resp_obj: r  # type: ignore[method-assign]
                res = venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
                self.assertTrue(res["freeze_active"], f"Freeze cleared prematurely on {label}")
                self.assertEqual(res["reconciled"][0]["new_status"], MUTATION_STATUS_OUTCOME_UNKNOWN)
                self.assertTrue(venue.snapshot()["outcome_unknown_freeze"])

        t._request_json_raw = lambda _m, _ep, payload=None, require_auth=True: {  # type: ignore[method-assign]
            "accountId": "ACCT-B",
            "orders": [],
            "nextCursor": None,
            "hasMore": False,
            "watermarkUtc": valid_ts.isoformat(),
        }
        with self.assertRaises(TradovateOutcomeUnknownError):
            venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
        self.assertTrue(venue.snapshot()["outcome_unknown_freeze"])

        t._request_json_raw = lambda _m, _ep, payload=None, require_auth=True: {  # type: ignore[method-assign]
            "accountId": "ACCT-A",
            "orders": [],
            "nextCursor": "loop-cursor",
            "hasMore": True,
            "watermarkUtc": valid_ts.isoformat(),
        }
        res_cycle = venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
        self.assertTrue(res_cycle["freeze_active"])
        self.assertEqual(res_cycle["reconciled"][0]["new_status"], MUTATION_STATUS_OUTCOME_UNKNOWN)

        obs_calls = 0

        def fake_two_obs_inconsistent(m: str, ep: str, *, payload=None, require_auth: bool = True):
            nonlocal obs_calls
            obs_calls += 1
            if obs_calls == 1:
                return {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": False, "watermarkUtc": valid_ts.isoformat()}
            return {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": True, "watermarkUtc": valid_ts.isoformat()}

        t._request_json_raw = fake_two_obs_inconsistent  # type: ignore[method-assign]
        res_incons = venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
        self.assertTrue(res_incons["freeze_active"])
        self.assertEqual(res_incons["reconciled"][0]["new_status"], MUTATION_STATUS_OUTCOME_UNKNOWN)

        obs2 = 0

        def fake_two_obs_catches_fill(m: str, ep: str, *, payload=None, require_auth: bool = True):
            nonlocal obs2
            obs2 += 1
            if obs2 == 1:
                return {"accountId": "ACCT-A", "orders": [], "nextCursor": None, "hasMore": False, "watermarkUtc": valid_ts.isoformat()}
            return {
                "accountId": "ACCT-A",
                "orders": [{"accountId": "ACCT-A", "clOrdId": cl_id, "orderId": "8100", "ordStatus": "Filled", "filledQty": 1}],
                "nextCursor": None,
                "hasMore": False,
                "watermarkUtc": valid_ts.isoformat(),
            }

        t._request_json_raw = fake_two_obs_catches_fill  # type: ignore[method-assign]
        res_caught = venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
        self.assertTrue(res_caught["freeze_active"])
        self.assertEqual(res_caught["reconciled"][0]["new_status"], "PROTECTION_UNCONFIRMED")
        self.assertTrue(venue.verify_audit_chain())

    def test_paginated_multi_page_completeness_proof_clears_latch_only_when_proven(self) -> None:
        venue, t, cl_id = self._create_frozen_https_venue("paginated_clear.sqlite3")
        valid_ts = _utc(2026, 11, 20, 15, 2, 0).isoformat()
        seen_cursors: list[str | None] = []

        def fake_paginated_empty(m: str, ep: str, *, payload=None, require_auth: bool = True):
            self.assertIn("accountId=ACCT-A", ep)
            if "cursor=p2" in ep:
                seen_cursors.append("p2")
                return {
                    "accountId": "ACCT-A",
                    "orders": [{"accountId": "ACCT-A", "clOrdId": "other-order-2", "orderId": "702", "ordStatus": "Filled"}],
                    "nextCursor": None,
                    "hasMore": False,
                    "watermarkUtc": valid_ts,
                }
            seen_cursors.append(None)
            return {
                "accountId": "ACCT-A",
                "orders": [{"accountId": "ACCT-A", "clOrdId": "other-order-1", "orderId": "701", "ordStatus": "Filled"}],
                "nextCursor": "p2",
                "hasMore": True,
                "watermarkUtc": valid_ts,
            }

        t._request_json_raw = fake_paginated_empty  # type: ignore[method-assign]
        ev = t.fetch_reconciliation_evidence()
        self.assertTrue(ev.complete)
        self.assertTrue(ev.provider_cursor_exhausted)
        self.assertEqual(ev.pages_fetched, 2)
        self.assertEqual(ev.account_id, "ACCT-A")
        self.assertEqual(ev.observed_cl_ord_ids, frozenset({"other-order-1", "other-order-2"}))

        seen_cursors.clear()
        res = venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
        self.assertEqual(seen_cursors, [None, "p2", None, "p2"])
        self.assertFalse(res["freeze_active"])
        self.assertEqual(res["reconciled"][0]["new_status"], "RECONCILED_ABSENT")
        self.assertTrue(res["reconciled"][0]["evidence_complete"])
        self.assertTrue(res["reconciled"][0]["provider_cursor_exhausted"])
        self.assertFalse(venue.snapshot()["outcome_unknown_freeze"])
        self.assertTrue(venue.verify_audit_chain())

    def test_paginated_multi_page_finds_filled_protected_order_on_later_page(self) -> None:
        venue, t, cl_id = self._create_frozen_https_venue("paginated_page2_fill.sqlite3")
        valid_ts = _utc(2026, 11, 20, 15, 2, 0).isoformat()

        def fake_paginated_hit(m: str, ep: str, *, payload=None, require_auth: bool = True):
            if "cursor=p2" in ep:
                return {
                    "accountId": "ACCT-A",
                    "orders": [
                        {
                            "accountId": "ACCT-A",
                            "clOrdId": cl_id,
                            "orderId": "8801",
                            "oso1Id": "8802",
                            "oso2Id": "8803",
                            "ordStatus": "Filled",
                            "filledQty": 1,
                            "bracket1": {
                                "accountId": "ACCT-A",
                                "orderId": "8802",
                                "action": "Sell",
                                "orderType": "Stop",
                                "orderQty": 1,
                                "stopPrice": Decimal("19975.25"),
                                "ordStatus": "Working",
                            },
                            "bracket2": {
                                "accountId": "ACCT-A",
                                "orderId": "8803",
                                "action": "Sell",
                                "orderType": "Limit",
                                "orderQty": 1,
                                "price": Decimal("20060.25"),
                                "ordStatus": "Working",
                            },
                        }
                    ],
                    "nextCursor": None,
                    "hasMore": False,
                    "watermarkUtc": valid_ts,
                }
            return {
                "accountId": "ACCT-A",
                "orders": [],
                "nextCursor": "p2",
                "hasMore": True,
                "watermarkUtc": valid_ts,
            }

        t._request_json_raw = fake_paginated_hit  # type: ignore[method-assign]
        res = venue.reconcile_unknown_outcome(cl_ord_id=cl_id)
        self.assertFalse(res["freeze_active"])
        self.assertEqual(res["reconciled"][0]["new_status"], "RECONCILED_FILLED_PROTECTED")
        self.assertEqual(res["reconciled"][0]["pages_fetched"], 2)
        self.assertTrue(venue.verify_audit_chain())


class TestAudit443a5c4TradovateHygiene(unittest.TestCase):
    """Verify LF-only, zero BOM, zero nosec markers, zero assert in src/, and pre-I/O PENDING in executing methods."""

    def test_source_and_test_hygiene_plus_direct_pending_before_io(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        for rel in (
            "src/cas_forex_revamp/futures/tradovate_venue.py",
            "tests/security/test_audit_443a5c4_tradovate_findings.py",
        ):
            raw = (repo_root / rel).read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"BOM forbidden in {rel}")
            self.assertNotIn(b"\r", raw, f"CR forbidden in {rel}")
            text = raw.decode("utf-8")
            self.assertNotIn("# " + "nosec", text, f"nosec forbidden in {rel}")

        tv_text = (repo_root / "src/cas_forex_revamp/futures/tradovate_venue.py").read_text(encoding="utf-8")
        tree = ast.parse(tv_text)
        asserts = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        self.assertEqual(asserts, [])
        floats = [
            n.lineno
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "float"
        ]
        self.assertEqual(floats, [])

        for method_name in ("place_bracket_order", "amend_stop", "close_position", "emergency_close_all"):
            fn_src = inspect.getsource(getattr(TradovateMicroFuturesVenue, method_name))
            idx_begin = fn_src.find("BEGIN IMMEDIATE")
            idx_insert = fn_src.find("INSERT INTO mutation_journal")
            idx_send = fn_src.find("send_order(")
            self.assertGreater(idx_begin, -1, method_name)
            self.assertGreater(idx_insert, idx_begin, method_name)
            self.assertGreater(idx_send, idx_insert, method_name)


if __name__ == "__main__":
    unittest.main()
