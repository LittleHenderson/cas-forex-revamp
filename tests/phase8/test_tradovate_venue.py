"""Comprehensive offline unit tests for TradovateMicroFuturesVenue & PaperEmulator."""
from __future__ import annotations

import ast
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import pickle
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.futures import (
    ExpiredFuturesContractError,
    MicroFuturesSizingRefusalError,
    UnsupportedMicroFuturesSymbolError,
)
from cas_forex_revamp.futures.tradovate_venue import (
    CONNECTION_STATUS_CONNECTED,
    CONNECTION_STATUS_DISCONNECTED,
    CONNECTION_STATUS_STANDBY,
    ENV_TRADOVATE_APP_ID,
    ENV_TRADOVATE_BASE_URL,
    ENV_TRADOVATE_CID,
    ENV_TRADOVATE_ENABLED,
    ENV_TRADOVATE_MODE,
    ENV_TRADOVATE_PASSWORD,
    ENV_TRADOVATE_SEC,
    ENV_TRADOVATE_USERNAME,
    FuturesOrderAction,
    PINNED_TRADOVATE_HOSTS,
    TRADOVATE_BROKER_ID,
    TRADOVATE_DEMO_BASE_URL,
    TRADOVATE_LIVE_BASE_URL,
    TRADOVATE_MODE_DEMO,
    TRADOVATE_MODE_LIVE,
    TRADOVATE_REGULATED_JURISDICTION,
    TRADOVATE_SUPPORTED_CONTRACTS,
    TradovateCredentials,
    TradovateDrawdownLockError,
    TradovateEndpointError,
    TradovateHttpsTransport,
    TradovateLiveLockError,
    TradovateMicroFuturesPaperEmulator,
    TradovateMicroFuturesVenue,
    TradovateNotConfiguredError,
    TradovateOrderRequest,
    TradovateStandbyError,
    TradovateTransportError,
    TradovateValveRefusalError,
    VENUE_STATUS_DEMO_ACTIVE,
    VENUE_STATUS_STANDBY,
    _NoRedirectHandler,
    _RedactedSecret,
    load_default_forex_valve_gate,
    load_tradovate_credentials,
    validate_tradovate_endpoint,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision


def _utc(year: int, month: int, day: int, hour: int = 15, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, 0, tzinfo=timezone.utc)


class _FixedClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int = 60) -> datetime:
        self.current = self.current + timedelta(seconds=seconds)
        return self.current


class _MockValveGate:
    """Deterministic mock valve for testing low-score (< 0.55) and hard-veto refusals."""

    def __init__(
        self,
        *,
        admitted: bool,
        mlp_score: float,
        hard_veto: bool = False,
        hard_veto_reasons: tuple[str, ...] = (),
        valve_mode: str = "MLP_SCORE_VETO",
    ) -> None:
        self.admitted = admitted
        self.mlp_score = mlp_score
        self.hard_veto = hard_veto
        self.hard_veto_reasons = hard_veto_reasons
        self.valve_mode = valve_mode
        self.calls = 0

    def evaluate(self, proposal, *, current_view=None, policy=None, now=None) -> ValveDecision:
        self.calls += 1
        return ValveDecision(
            admitted=self.admitted,
            valve_mode=self.valve_mode,
            mlp_score=self.mlp_score,
            threshold=0.55,
            mlp_admitted=self.mlp_score >= 0.55,
            hard_veto=self.hard_veto,
            hard_veto_reasons=self.hard_veto_reasons,
            features={},
            weights_sha256="mock-weights-sha256",
            request_id=proposal.request.request_id,
            selected_action_ref=proposal.result.selection.selected_action_ref,
        )


class _DummyRedirectResponse:
    def __init__(self, status: int) -> None:
        self.status = status
        self.closed = False

    def close(self) -> None:
        self.closed = True


class TestTradovateEndpointAndSecrets(unittest.TestCase):
    def test_default_credentials_standby_zero_impact(self) -> None:
        creds = load_tradovate_credentials({})
        self.assertFalse(creds.enabled)
        self.assertEqual(creds.mode, TRADOVATE_MODE_DEMO)
        self.assertEqual(creds.base_url, TRADOVATE_DEMO_BASE_URL)
        self.assertFalse(creds.live_arming_verified)
        self.assertIsNone(creds.password)
        self.assertIsNone(creds.sec)

    def test_endpoint_pinning_demo_vs_live_and_ssrf_blocks(self) -> None:
        self.assertEqual(
            PINNED_TRADOVATE_HOSTS,
            frozenset({"demo.tradovateapi.com", "live.tradovateapi.com"}),
        )
        # Valid DEMO
        self.assertEqual(
            validate_tradovate_endpoint("DEMO", "https://demo.tradovateapi.com/v1"),
            TRADOVATE_DEMO_BASE_URL,
        )
        self.assertEqual(
            validate_tradovate_endpoint("DEMO", "https://demo.tradovateapi.com:443/v1/"),
            TRADOVATE_DEMO_BASE_URL,
        )
        # Valid LIVE only with live_arming_verified=True
        self.assertEqual(
            validate_tradovate_endpoint(
                "LIVE",
                "https://live.tradovateapi.com/v1",
                live_arming_verified=True,
            ),
            TRADOVATE_LIVE_BASE_URL,
        )
        # DEMO refuses live host
        with self.assertRaises(TradovateLiveLockError):
            validate_tradovate_endpoint("DEMO", "https://live.tradovateapi.com/v1")
        # LIVE without live_arming_verified=True refuses fail-closed
        with self.assertRaises(TradovateLiveLockError):
            validate_tradovate_endpoint("LIVE", "https://live.tradovateapi.com/v1")
        with self.assertRaises(TradovateLiveLockError):
            validate_tradovate_endpoint(
                "LIVE", "https://live.tradovateapi.com/v1", live_arming_verified=False
            )
        # LIVE refuses demo host even if armed
        with self.assertRaises(TradovateEndpointError):
            validate_tradovate_endpoint(
                "LIVE", "https://demo.tradovateapi.com/v1", live_arming_verified=True
            )
        # Reject http, file, credentials, query, fragment, non-443 ports, localhost/private IPs, unpinned hosts
        bad_urls = [
            "http://demo.tradovateapi.com/v1",
            "file:///etc/passwd",
            "https://user:pass@demo.tradovateapi.com/v1",
            "https://demo.tradovateapi.com/v1?token=secret123",
            "https://demo.tradovateapi.com/v1#frag",
            "https://demo.tradovateapi.com:8443/v1",
            "https://demo.tradovateapi.com:80/v1",
            "https://localhost/v1",
            "https://127.0.0.1/v1",
            "https://169.254.169.254/v1",
            "https://10.0.0.5/v1",
            "https://[::1]/v1",
            "https://demo.tradovateapi.com.evil.com/v1",
            "https://demo.tradovateapi.com/v2",
            "https://demo.tradovateapi.com/v1/../v2",
        ]
        for bad in bad_urls:
            with self.subTest(bad_url=bad):
                with self.assertRaises(TradovateEndpointError):
                    validate_tradovate_endpoint("DEMO", bad)

    def test_no_redirect_handler_and_https_query_secret_block(self) -> None:
        handler = _NoRedirectHandler()
        for code in (301, 302, 307, 308):
            resp = _DummyRedirectResponse(code)
            with self.assertRaises(TradovateTransportError):
                handler.https_response(None, resp)
            self.assertTrue(resp.closed)
        with self.assertRaises(TradovateTransportError):
            handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/v1")

        creds = TradovateCredentials(
            enabled=True,
            mode=TRADOVATE_MODE_DEMO,
            base_url=TRADOVATE_DEMO_BASE_URL,
            bearer_token=_RedactedSecret("super-secret-bearer-token"),
        )
        transport = TradovateHttpsTransport(credentials=creds)
        self.assertEqual(
            transport._build_safe_url("cashBalance/getcashbalancesnapshot"),
            "https://demo.tradovateapi.com/v1/cashBalance/getcashbalancesnapshot",
        )
        for bad_path in (
            "order/list?token=leak",
            "order/list?password=leak",
            "order/list?sec=leak",
            "https://evil.example/v1/order",
            "../etc/passwd",
            "order/list#anchor",
        ):
            with self.subTest(bad_path=bad_path):
                with self.assertRaises(TradovateEndpointError):
                    transport._build_safe_url(bad_path)
        self.assertNotIn("super-secret-bearer-token", repr(transport))

    def test_redacted_secret_never_leaks(self) -> None:
        secret_pw = "-".join(("demo", "tv", "alpha", "01"))
        secret_api = "-".join(("demo", "tv", "beta", "02"))
        s = _RedactedSecret(secret_pw)
        self.assertEqual(s.reveal(), secret_pw)
        self.assertEqual(str(s), "[REDACTED]")
        self.assertEqual(repr(s), "'[REDACTED]'")
        self.assertEqual(f"{s}", "[REDACTED]")
        self.assertNotIn(secret_pw, str(s))
        self.assertNotIn(secret_pw, repr(s))
        self.assertNotEqual(s, secret_pw)
        self.assertEqual(s, _RedactedSecret(secret_pw))
        with self.assertRaises(TypeError):
            pickle.dumps(s)

        creds = load_tradovate_credentials(
            {
                ENV_TRADOVATE_ENABLED: "0",
                ENV_TRADOVATE_MODE: "DEMO",
                ENV_TRADOVATE_BASE_URL: TRADOVATE_DEMO_BASE_URL,
                ENV_TRADOVATE_USERNAME: "trader_demo",
                ENV_TRADOVATE_PASSWORD: secret_pw,
                ENV_TRADOVATE_APP_ID: "cas-forex",
                ENV_TRADOVATE_CID: "1234",
                ENV_TRADOVATE_SEC: secret_api,
            }
        )
        rendered = f"{creds!r} | {creds!s}"
        self.assertNotIn(secret_pw, rendered)
        self.assertNotIn(secret_api, rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertTrue(creds.has_api_credentials())


class TestTradovateVenueStandbyValveAndLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.clock = _FixedClock(_utc(2026, 11, 20, 15, 0))
        self.valve = load_default_forex_valve_gate()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _make_venue(
        self,
        *,
        starting_equity: Decimal = Decimal("5000.00"),
        enabled: bool = False,
        valve_gate: object = "DEFAULT",
        db_name: str = "tradovate.db",
    ) -> tuple[TradovateMicroFuturesVenue, TradovateMicroFuturesPaperEmulator]:
        emu = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=starting_equity,
            clock=self.clock,
        )
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"))
        emu.set_quote("US30", Decimal("43000.00"), Decimal("43001.00"))
        emu.set_quote("SPX500", Decimal("6000.00"), Decimal("6000.25"))
        emu.set_quote("XAUUSD", Decimal("2650.00"), Decimal("2650.20"))
        eff_valve = self.valve if valve_gate == "DEFAULT" else valve_gate
        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / db_name,
            transport=emu,
            valve_gate=eff_valve,
            enabled=enabled,
            clock=self.clock,
        )
        return venue, emu

    def test_standby_by_default_refuses_new_entries_until_activated(self) -> None:
        venue, _emu = self._make_venue(enabled=False)
        snap = venue.status_snapshot()
        self.assertEqual(snap["status"], VENUE_STATUS_STANDBY)
        self.assertFalse(snap["enabled"])
        self.assertEqual(snap["broker_id"], TRADOVATE_BROKER_ID)
        self.assertEqual(snap["regulated_jurisdiction"], TRADOVATE_REGULATED_JURISDICTION)
        self.assertEqual(snap["supported_contracts"], TRADOVATE_SUPPORTED_CONTRACTS)
        self.assertEqual(snap["connection_status"], CONNECTION_STATUS_STANDBY)
        self.assertTrue(snap["audit_chain_valid"])

        with self.assertRaises(TradovateStandbyError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
                risk_pct=Decimal("1.00"),
            )

        # Activate into DEMO_ACTIVE and verify order succeeds
        act_snap = venue.activate()
        self.assertEqual(act_snap["status"], VENUE_STATUS_DEMO_ACTIVE)
        self.assertTrue(act_snap["enabled"])
        self.assertEqual(act_snap["connection_status"], CONNECTION_STATUS_CONNECTED)

        receipt = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertTrue(receipt.accepted)
        self.assertEqual(receipt.root_symbol, "MNQ")
        self.assertEqual(receipt.filled_contracts, 1)
        self.assertTrue(venue.verify_audit_chain())

    def test_mandatory_valve_gate_none_and_low_score_refusal(self) -> None:
        # 1. valve_gate=None fails closed immediately
        venue_none, _ = self._make_venue(enabled=True, valve_gate=None, db_name="none_valve.db")
        with self.assertRaises(TradovateValveRefusalError):
            venue_none.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        self.assertTrue(venue_none.verify_audit_chain())

        # 2. Mock valve scoring 0.54 (< 0.55 cutoff) fails closed
        low_valve = _MockValveGate(admitted=False, mlp_score=0.54, valve_mode="MLP_SCORE_VETO")
        venue_low, _ = self._make_venue(enabled=True, valve_gate=low_valve, db_name="low_valve.db")
        with self.assertRaises(TradovateValveRefusalError):
            venue_low.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )
        self.assertEqual(low_valve.calls, 1)
        self.assertTrue(venue_low.verify_audit_chain())

        # 3. Even if mock claims admitted=True, score < 0.55 MUST still be refused!
        sneaky_valve = _MockValveGate(admitted=True, mlp_score=0.549, valve_mode="ADMIT")
        venue_sneaky, _ = self._make_venue(
            enabled=True, valve_gate=sneaky_valve, db_name="sneaky_valve.db"
        )
        with self.assertRaises(TradovateValveRefusalError):
            venue_sneaky.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )

        # 4. Real 161-parameter ForexMetaValveGate refuses forbidden new_risk_permission
        venue_real, _ = self._make_venue(enabled=True, db_name="real_valve_veto.db")
        self.assertEqual(self.valve.controller.parameter_count, 161)
        with self.assertRaises(TradovateValveRefusalError):
            venue_real.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
                policy_overrides={"new_risk_permission": "FORBIDDEN"},
            )
        self.assertTrue(venue_real.verify_audit_chain())

    def test_full_5000_paper_lifecycle_mnq_tp_mym_be_and_sl(self) -> None:
        venue, emu = self._make_venue(starting_equity=Decimal("5000.00"), enabled=True)

        # Trade 1: NAS100 -> MNQ (25-pt SL -> 1 contract = $50.00 risk, 60-pt TP -> +$120.00 gross, +$118.76 net)
        open_mnq = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(open_mnq.root_symbol, "MNQ")
        self.assertEqual(open_mnq.cas_symbol, "NAS100")
        self.assertEqual(open_mnq.contract_code, "MNQZ6")
        self.assertEqual(open_mnq.filled_contracts, 1)
        self.assertEqual(open_mnq.fill_price, Decimal("20000.25"))
        self.assertEqual(open_mnq.stop_loss_price, Decimal("19975.25"))
        self.assertEqual(open_mnq.take_profit_price, Decimal("20060.25"))
        self.assertIsNotNone(open_mnq.valve_score)
        self.assertGreaterEqual(open_mnq.valve_score, Decimal("0.55"))
        self.assertEqual(open_mnq.valve_weights_sha256, self.valve.weights_sha256)

        # Trigger exact 60-pt TP fill via process_market_quote
        self.clock.advance(120)
        tp_fills = venue.process_market_quote("NAS100", Decimal("20060.25"), Decimal("20060.50"))
        self.assertEqual(len(tp_fills), 1)
        tp = tp_fills[0]
        self.assertEqual(tp.status, "TAKE_PROFIT_FILLED")
        self.assertEqual(tp.realized_pnl_usd, Decimal("120.00"))
        self.assertEqual(tp.commission_usd, Decimal("1.24"))
        self.assertEqual(tp.net_pnl_usd, Decimal("118.76"))

        acct_after_tp = emu.account_snapshot()
        self.assertEqual(acct_after_tp.balance_usd, Decimal("5118.76"))
        self.assertEqual(acct_after_tp.equity_usd, Decimal("5118.76"))
        self.assertEqual(acct_after_tp.peak_equity_usd, Decimal("5118.76"))
        self.assertEqual(acct_after_tp.open_position_count, 0)

        # Trade 2: US30 -> MYM (50-pt SL = $25.00/contract -> 1 contract at 0.50% risk)
        # Move stop to break-even, then hit break-even stop -> $0.00 gross, -$1.24 net
        self.clock.advance(60)
        open_mym = venue.place_bracket_order(
            symbol="US30",
            side="BUY",
            stop_distance_points=Decimal("50.00"),
            take_profit_points=Decimal("100.00"),
            risk_pct=Decimal("0.50"),
        )
        self.assertEqual(open_mym.root_symbol, "MYM")
        self.assertEqual(open_mym.contract_code, "MYMZ6")
        self.assertEqual(open_mym.filled_contracts, 1)
        self.assertEqual(open_mym.fill_price, Decimal("43001.00"))
        self.assertEqual(open_mym.stop_loss_price, Decimal("42951.00"))

        self.clock.advance(60)
        venue.process_market_quote("US30", Decimal("43050.00"), Decimal("43051.00"))
        be_receipt = venue.amend_stop(open_mym.position_id, open_mym.fill_price)
        self.assertEqual(be_receipt.status, "AMENDED")
        self.assertEqual(be_receipt.stop_loss_price, Decimal("43001.00"))

        self.clock.advance(60)
        be_fills = venue.process_market_quote("US30", Decimal("43001.00"), Decimal("43002.00"))
        self.assertEqual(len(be_fills), 1)
        self.assertEqual(be_fills[0].status, "STOP_LOSS_FILLED")
        self.assertEqual(be_fills[0].realized_pnl_usd, Decimal("0.00"))
        self.assertEqual(be_fills[0].commission_usd, Decimal("1.24"))
        self.assertEqual(be_fills[0].net_pnl_usd, Decimal("-1.24"))

        # Trade 3: MNQ SL hit (25-pt SL -> -$50.00 gross, -$51.24 net)
        self.clock.advance(60)
        venue.process_market_quote("NAS100", Decimal("20100.00"), Decimal("20100.25"))
        open_sl = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(open_sl.filled_contracts, 1)
        self.clock.advance(60)
        sl_fills = venue.process_market_quote("NAS100", Decimal("20075.25"), Decimal("20075.50"))
        self.assertEqual(len(sl_fills), 1)
        self.assertEqual(sl_fills[0].status, "STOP_LOSS_FILLED")
        self.assertEqual(sl_fills[0].realized_pnl_usd, Decimal("-50.00"))
        self.assertEqual(sl_fills[0].commission_usd, Decimal("1.24"))
        self.assertEqual(sl_fills[0].net_pnl_usd, Decimal("-51.24"))

        final_acct = emu.account_snapshot()
        expected_balance = Decimal("5000.00") + Decimal("118.76") - Decimal("1.24") - Decimal("51.24")
        self.assertEqual(final_acct.balance_usd, expected_balance)
        self.assertEqual(final_acct.total_commissions_usd, Decimal("3.72"))
        self.assertTrue(venue.verify_audit_chain())

    def test_protective_actions_always_allowed_in_standby_and_drawdown_lock(self) -> None:
        venue, emu = self._make_venue(starting_equity=Decimal("5000.00"), enabled=True)

        # Open 1 MNQ and 1 MYM position
        r1 = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("80.00"),
            risk_pct=Decimal("1.00"),
        )
        r2 = venue.place_bracket_order(
            symbol="US30",
            side="BUY",
            stop_distance_points=Decimal("40.00"),
            take_profit_points=Decimal("100.00"),
            risk_pct=Decimal("0.50"),
        )
        self.assertEqual(len(emu.positions()), 2)

        # Toggle venue back to STANDBY_READY & strip valve_gate to None
        venue.deactivate(reason="OPERATOR_PAUSE")
        venue._valve_gate = None  # Simulate missing/refusing entry valve

        # New entry MUST fail closed
        with self.assertRaises(TradovateStandbyError):
            venue.place_bracket_order(
                symbol="SPX500",
                side="BUY",
                stop_distance_points=Decimal("10.00"),
                take_profit_points=Decimal("20.00"),
            )

        # Protective amend_stop, close_position, emergency_close_all MUST ALL SUCCEED
        amend = venue.amend_stop(r1.position_id, Decimal("19990.00"))
        self.assertEqual(amend.status, "AMENDED")
        self.assertEqual(amend.stop_loss_price, Decimal("19990.00"))

        closed_one = venue.close_position(r1.position_id)
        self.assertEqual(closed_one.status, "CLOSED")
        self.assertEqual(len(emu.positions()), 1)

        emerg = venue.emergency_close_all()
        self.assertEqual(len(emerg), 1)
        self.assertEqual(emerg[0].position_id, r2.position_id)
        self.assertEqual(len(emu.positions()), 0)
        self.assertTrue(venue.verify_audit_chain())

    def test_10pct_drawdown_lock_blocks_new_entries_but_allows_emergency_close(self) -> None:
        venue, emu = self._make_venue(starting_equity=Decimal("5000.00"), enabled=True)

        # Drive consecutive 1-contract MNQ 20-pt stop-outs ($40.00 + $1.24 = $41.24 each)
        # 13 losses = $536.12 -> equity $4,463.88 (10.72% drawdown >= 10.00% lock!)
        for _ in range(13):
            self.clock.advance(60)
            venue.process_market_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"))
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("20.00"),
                take_profit_points=Decimal("60.00"),
                risk_pct=Decimal("1.00"),
                contracts=1,
            )
            self.clock.advance(60)
            venue.process_market_quote("NAS100", Decimal("19980.25"), Decimal("19980.50"))

        acct = emu.account_snapshot()
        self.assertEqual(acct.peak_equity_usd, Decimal("5000.00"))
        self.assertEqual(acct.equity_usd, Decimal("4463.88"))
        self.assertGreaterEqual(acct.drawdown_pct, Decimal("0.10"))

        snap = venue.snapshot()
        self.assertTrue(snap["drawdown_locked"])

        # New entry MUST fail closed with TradovateDrawdownLockError
        with self.assertRaises(TradovateDrawdownLockError):
            venue.place_bracket_order(
                symbol="US30",
                side="BUY",
                stop_distance_points=Decimal("40.00"),
                take_profit_points=Decimal("100.00"),
                risk_pct=Decimal("0.50"),
            )

        # Emergency close all remains ALWAYS allowed even under drawdown lock
        emerg = venue.emergency_close_all()
        self.assertEqual(emerg, ())
        self.assertTrue(venue.verify_audit_chain())

    def test_constitutional_sizing_expired_contract_and_disconnected_honesty(self) -> None:
        # $3,000 account: MNQ 25-pt SL = $50/contract > $30 budget -> honest refusal
        venue_3k, emu_3k = self._make_venue(
            starting_equity=Decimal("3000.00"), enabled=True, db_name="acct3k.db"
        )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            venue_3k.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
                risk_pct=Decimal("1.00"),
            )

        # risk_pct > 1.00% refused fail-closed
        venue_5k, emu_5k = self._make_venue(
            starting_equity=Decimal("5000.00"), enabled=True, db_name="acct5k.db"
        )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            venue_5k.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
                risk_pct=Decimal("1.01"),
            )

        # Expired contract rejected fail-closed
        with self.assertRaises(ExpiredFuturesContractError):
            venue_5k.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
                contract_code="MNQU6",
            )

        # Unsupported FX symbol rejected fail-closed
        with self.assertRaises(UnsupportedMicroFuturesSymbolError):
            venue_5k.place_bracket_order(
                symbol="EURUSD",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )

        # Disconnected transport NEVER fakes $0.00 balance
        emu_5k.set_connected(False)
        disc_snap = venue_5k.snapshot()
        self.assertFalse(disc_snap["connected"])
        self.assertEqual(disc_snap["connection_status"], CONNECTION_STATUS_DISCONNECTED)
        self.assertIsNone(disc_snap["account"])
        with self.assertRaises(TradovateTransportError):
            venue_5k.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("60.00"),
            )

    def test_zero_write_ro_snapshot_data_version_and_audit_tamper_detection(self) -> None:
        venue, _emu = self._make_venue(starting_equity=Decimal("5000.00"), enabled=True)
        venue.place_bracket_order(
            symbol="XAUUSD",
            side="BUY",
            stop_distance_points=Decimal("5.00"),
            take_profit_points=Decimal("12.00"),
            risk_pct=Decimal("1.00"),
        )

        # Open an external observer connection and record PRAGMA data_version
        with closing(sqlite3.connect(str(venue.db_path))) as observer:
            dv_before = observer.execute("PRAGMA data_version").fetchone()[0]
            count_before = observer.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

            # Call snapshot(), status_snapshot(), verify_audit_chain() repeatedly
            for _ in range(3):
                snap = venue.snapshot()
                self.assertTrue(snap["audit_chain_valid"])
                self.assertEqual(snap["contract_mappings"]["XAUUSD"], "MGC")
                self.assertTrue(venue.verify_audit_chain())
                _ = venue.status_snapshot()

            dv_after = observer.execute("PRAGMA data_version").fetchone()[0]
            count_after = observer.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            self.assertEqual(dv_before, dv_after)
            self.assertEqual(count_before, count_after)

        # Tamper with 1 row in audit_events and verify tamper detection triggers False
        with closing(sqlite3.connect(str(venue.db_path))) as tamper_conn:
            tamper_conn.execute(
                "UPDATE audit_events SET payload_json = '{\"tampered\":true}' WHERE seq = 1"
            )
            tamper_conn.commit()

        self.assertFalse(venue.verify_audit_chain())
        self.assertFalse(venue.snapshot()["audit_chain_valid"])

    def test_reopen_db_preserves_peak_and_request_sequence(self) -> None:
        db_file = self.tmp / "reopen.db"
        emu = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            clock=self.clock,
        )
        emu.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"))
        venue1 = TradovateMicroFuturesVenue(
            db_path=db_file, transport=emu, valve_gate=self.valve, enabled=True, clock=self.clock
        )
        r1 = venue1.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("60.00"),
        )
        venue1.close_position(r1.position_id)

        # Reopen fresh venue instance on same DB and place another order (no request_id collision!)
        venue2 = TradovateMicroFuturesVenue(
            db_path=db_file, transport=emu, valve_gate=self.valve, enabled=True, clock=self.clock
        )
        r2 = venue2.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("20.00"),
            take_profit_points=Decimal("60.00"),
        )
        self.assertNotEqual(r1.request_id, r2.request_id)
        self.assertTrue(venue2.verify_audit_chain())

    def test_short_side_mes_and_gold_mgc_with_margin_floor(self) -> None:
        venue, emu = self._make_venue(starting_equity=Decimal("5000.00"), enabled=True)

        # Short SPX500 -> MES ($5.00/pt, 0.25 tick): 10-pt SL = $50.00 -> 1 contract, 20-pt TP -> +$100.00 gross, +$98.76 net
        r_mes = venue.place_bracket_order(
            symbol="SPX500",
            side="SELL",
            stop_distance_points=Decimal("10.00"),
            take_profit_points=Decimal("20.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(r_mes.root_symbol, "MES")
        self.assertEqual(r_mes.side, "SELL")
        self.assertEqual(r_mes.fill_price, Decimal("6000.00"))
        self.assertEqual(r_mes.stop_loss_price, Decimal("6010.00"))
        self.assertEqual(r_mes.take_profit_price, Decimal("5980.00"))
        self.assertEqual(r_mes.filled_contracts, 1)

        # Trigger short TP when ask <= 5980.00
        self.clock.advance(60)
        mes_fills = venue.process_market_quote("SPX500", Decimal("5979.75"), Decimal("5980.00"))
        self.assertEqual(len(mes_fills), 1)
        self.assertEqual(mes_fills[0].status, "TAKE_PROFIT_FILLED")
        self.assertEqual(mes_fills[0].realized_pnl_usd, Decimal("100.00"))
        self.assertEqual(mes_fills[0].commission_usd, Decimal("1.24"))
        self.assertEqual(mes_fills[0].net_pnl_usd, Decimal("98.76"))

        # Exchange-margin 1,000% cushion enforcement on $5,000.00 (max used margin = $500.00 < $2,200.00 MNQ exchange margin -> refused!)
        emu_exch = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            clock=self.clock,
            use_exchange_margin=True,
        )
        emu_exch.set_quote("NAS100", Decimal("20000.00"), Decimal("20000.25"))
        venue_exch = TradovateMicroFuturesVenue(
            db_path=self.tmp / "exch_margin.db",
            transport=emu_exch,
            valve_gate=self.valve,
            enabled=True,
            use_exchange_margin=True,
            clock=self.clock,
        )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            venue_exch.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("10.00"),
                take_profit_points=Decimal("30.00"),
                risk_pct=Decimal("1.00"),
            )

    def test_float_money_strictly_rejected(self) -> None:
        from cas_forex_revamp.contracts import ContractError

        with self.assertRaises(ContractError):
            TradovateMicroFuturesPaperEmulator(starting_equity_usd=5000.0)  # type: ignore[arg-type]
        emu = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            clock=self.clock,
        )
        with self.assertRaises(ContractError):
            emu.set_quote("MNQ", 20000.0, Decimal("20000.25"))  # type: ignore[arg-type]
        with self.assertRaises(ContractError):
            TradovateOrderRequest(
                request_id="req-float",
                action=FuturesOrderAction.OPEN_BRACKET,
                contract_code="MNQZ6",
                root_symbol="MNQ",
                cas_symbol="NAS100",
                side="BUY",
                contracts=1,
                entry_price=20000.25,  # type: ignore[arg-type]
                stop_loss_price=Decimal("19975.25"),
            )

    def test_source_hygiene_no_assert_no_float_money_lf_only(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        src_path = repo_root / "src" / "cas_forex_revamp" / "futures" / "tradovate_venue.py"
        test_path = Path(__file__).resolve()

        src_bytes = src_path.read_bytes()
        self.assertFalse(src_bytes.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM forbidden")
        self.assertNotIn(b"\r", src_bytes, "CRLF/CR forbidden in tradovate_venue.py")

        test_bytes = test_path.read_bytes()
        self.assertFalse(test_bytes.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM forbidden")
        self.assertNotIn(b"\r", test_bytes, "CRLF/CR forbidden in test_tradovate_venue.py")

        src_text = src_bytes.decode("utf-8")
        tree = ast.parse(src_text)
        assert_lines = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        self.assertEqual(assert_lines, [], f"assert forbidden in src/: {assert_lines}")

        float_calls = [
            n.lineno
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "float"
        ]
        self.assertEqual(float_calls, [], f"float() forbidden in tradovate_venue.py: {float_calls}")

        for forbidden in ("shell=True", "verify=False", "pickle.loads", "eval(", "exec("):
            self.assertNotIn(forbidden, src_text)

    def test_strict_bool_enforced_on_live_arming_verified_and_enabled(self) -> None:
        from cas_forex_revamp.contracts import ContractError

        # __init__ without credentials: non-bool live_arming_verified MUST fail closed
        for bad_arm in ("false", "true", 1, 0):
            with self.subTest(bad_arm=bad_arm):
                with self.assertRaises(TradovateLiveLockError):
                    TradovateMicroFuturesVenue(
                        db_path=self.tmp / "bad_arm_init.db",
                        mode=TRADOVATE_MODE_LIVE,
                        live_arming_verified=bad_arm,  # type: ignore[arg-type]
                        clock=self.clock,
                    )

        # __init__ with credentials: non-bool live_arming_verified & enabled MUST fail closed
        base_creds = load_tradovate_credentials({})
        with self.assertRaises(TradovateLiveLockError):
            TradovateMicroFuturesVenue(
                db_path=self.tmp / "bad_arm_creds.db",
                credentials=base_creds,
                mode=TRADOVATE_MODE_LIVE,
                live_arming_verified="false",  # type: ignore[arg-type]
                clock=self.clock,
            )
        for bad_enabled in ("false", "0", 1, 0):
            with self.subTest(bad_enabled=bad_enabled):
                with self.assertRaises(ContractError):
                    TradovateMicroFuturesVenue(
                        db_path=self.tmp / "bad_enabled.db",
                        enabled=bad_enabled,  # type: ignore[arg-type]
                        clock=self.clock,
                    )

        # activate(): non-bool live_arming_verified MUST fail closed and keep STANDBY_READY
        venue, _emu = self._make_venue(enabled=False, db_name="strict_bool_activate.db")
        with self.assertRaises(TradovateLiveLockError):
            venue.activate(
                mode=TRADOVATE_MODE_LIVE,
                live_arming_verified="false",  # type: ignore[arg-type]
            )
        self.assertFalse(venue.enabled)
        self.assertEqual(venue.venue_status, VENUE_STATUS_STANDBY)
        self.assertEqual(venue.mode, TRADOVATE_MODE_DEMO)

    def test_activate_is_atomic_when_connect_fails(self) -> None:
        class _FailingConnectTransport(TradovateMicroFuturesPaperEmulator):
            def connect(self) -> None:
                raise TradovateNotConfiguredError("simulated missing credentials on connect()")

        transport = _FailingConnectTransport(
            starting_equity_usd=Decimal("5000.00"),
            clock=self.clock,
            connected=False,
        )
        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp / "atomic_activate.db",
            transport=transport,
            valve_gate=self.valve,
            enabled=False,
            clock=self.clock,
        )
        with self.assertRaises(TradovateNotConfiguredError):
            venue.activate(mode=TRADOVATE_MODE_LIVE, live_arming_verified=True)

        # In-memory state AND SQLite venue_meta MUST BOTH remain unchanged (STANDBY_READY / DEMO)
        self.assertFalse(venue.enabled)
        self.assertEqual(venue.venue_status, VENUE_STATUS_STANDBY)
        self.assertEqual(venue.mode, TRADOVATE_MODE_DEMO)
        self.assertEqual(venue.base_url, TRADOVATE_DEMO_BASE_URL)
        with closing(sqlite3.connect(str(venue.db_path))) as conn:
            row = conn.execute("SELECT enabled, mode, base_url FROM venue_meta WHERE id = 1").fetchone()
            self.assertEqual(row[0], 0)
            self.assertEqual(row[1], TRADOVATE_MODE_DEMO)
            self.assertEqual(row[2], TRADOVATE_DEMO_BASE_URL)
        self.assertTrue(venue.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
