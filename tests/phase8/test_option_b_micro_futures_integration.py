"""End-to-end Option B US-Regulated CME Micro Futures integration suite.

Exercises the complete standalone Option B workflow across `micro_futures_specs`,
`tradovate_venue`, and the real 161-parameter `ForexMetaValveGate` (`0.55` cutoff)
with zero live network calls and exact Decimal accounting:

- Scenario A: Standby -> Flip ON -> Live-Simulated `$5,000.00` Trade (`NAS100` -> `MNQ`
  & `US30` -> `MYM`, break-even `amend_stop`, take-profit fills, exact net P&L,
  tamper-evident SHA-256 audit chain, strictly 0-write `?mode=ro` `snapshot()`).
- Scenario B: Gold `XAUUSD` -> `MGC` roll & execution, constitutional `1.01%` refusal,
  `$3,000.00` honest refusal, and `>= 10.00%` drawdown brake blocking new entries
  while preserving protective `amend_stop` / `emergency_close_all`.
- Scenario C: LIVE host pinning (cryptographic `LiveAuthorizationContext` required; bare boolean rejected), DEMO
  isolation from `live.tradovateapi.com`, failed-connect `activate()` atomicity,
  credential redaction across `repr`/`str`/`format`/SQLite audit log, and SHA-256
  audit tamper detection.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal
import pickle
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cas_forex_revamp.futures import (
    CME_MICRO_FUTURES_SPECS,
    ExpiredFuturesContractError,
    MicroFuturesSizingRefusalError,
    compute_contract_pnl_usd,
    resolve_front_month_contract,
    size_micro_futures_order,
    translate_cas_symbol_to_micro_root,
)
from cas_forex_revamp.futures.tradovate_venue import (
    CONNECTION_STATUS_CONNECTED,
    CONNECTION_STATUS_STANDBY,
    TRADOVATE_BROKER_ID,
    TRADOVATE_DEMO_BASE_URL,
    TRADOVATE_LIVE_BASE_URL,
    TRADOVATE_REGULATED_JURISDICTION,
    VALVE_ADMISSIBILITY_CUTOFF,
    VENUE_STATUS_DEMO_ACTIVE,
    VENUE_STATUS_STANDBY,
    TradovateCredentials,
    TradovateDrawdownLockError,
    TradovateEndpointError,
    TradovateHttpsTransport,
    LiveAuthorizationError,
    TradovateLiveLockError,
    TradovateMicroFuturesPaperEmulator,
    TradovateMicroFuturesVenue,
    TradovateNotConfiguredError,
    TradovateStandbyError,
    TradovateTransportError,
    TradovateValveRefusalError,
    _NoRedirectHandler,
    _RedactedSecret,
    load_tradovate_credentials,
    validate_tradovate_endpoint,
)
from cas_forex_revamp.valve import ForexMetaValveGate, load_default_forex_valve_gate


class TestOptionBMicroFuturesIntegration(unittest.TestCase):
    """End-to-end Option B $5,000.00 US-regulated CME micro futures integration tests."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_dir = Path(self._tmp.name)
        self.valve_gate: ForexMetaValveGate = load_default_forex_valve_gate()

    def _fixed_clock(self, dt: datetime):
        return lambda: dt

    def test_scenario_a_standby_flip_on_5000_mnq_and_mym_full_trade_lifecycle(self) -> None:
        """Scenario A: Standby -> Flip ON -> $5,000.00 MNQ & MYM lifecycle with 0-write snapshot."""
        now = datetime(2026, 11, 20, 15, 30, 0, tzinfo=timezone.utc)

        # Verify real 161-param ForexMetaValveGate with 0.55 cutoff is loaded.
        self.assertIsInstance(self.valve_gate, ForexMetaValveGate)
        self.assertEqual(self.valve_gate.controller.parameter_count, 161)
        self.assertEqual(Decimal(str(self.valve_gate.controller.threshold)), VALVE_ADMISSIBILITY_CUTOFF)
        self.assertEqual(VALVE_ADMISSIBILITY_CUTOFF, Decimal("0.55"))

        # Verify exact CME Micro contract specs for MNQ, MYM, MES, MGC.
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MNQ"].point_value_usd, Decimal("2.00"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MNQ"].tick_size, Decimal("0.25"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MYM"].point_value_usd, Decimal("0.50"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MYM"].tick_size, Decimal("1.00"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MES"].point_value_usd, Decimal("5.00"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MES"].tick_size, Decimal("0.25"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MGC"].point_value_usd, Decimal("10.00"))
        self.assertEqual(CME_MICRO_FUTURES_SPECS["MGC"].tick_size, Decimal("0.10"))

        emulator = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            account_id="TV-DEMO-5000-A",
            mode="DEMO",
            clock=self._fixed_clock(now),
        )
        emulator.connect()
        emulator.set_quote("NAS100", Decimal("21000.00"), Decimal("21000.25"), observed_at=now)
        emulator.set_quote("US30", Decimal("43500.00"), Decimal("43501.00"), observed_at=now)

        db_path = self.tmp_dir / "scenario_a.sqlite3"
        venue = TradovateMicroFuturesVenue(
            db_path=db_path,
            transport=emulator,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(now),
        )

        # 1. Starts dormant in STANDBY_READY and refuses new entries fail-closed.
        standby_snap = venue.snapshot(now_utc=now)
        self.assertEqual(standby_snap["broker_id"], TRADOVATE_BROKER_ID)
        self.assertEqual(standby_snap["regulated_jurisdiction"], TRADOVATE_REGULATED_JURISDICTION)
        self.assertEqual(standby_snap["status"], VENUE_STATUS_STANDBY)
        self.assertFalse(standby_snap["enabled"])
        self.assertEqual(standby_snap["connection_status"], CONNECTION_STATUS_STANDBY)
        with self.assertRaises(TradovateStandbyError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("50.00"),
                risk_pct=Decimal("1.00"),
                now_utc=now,
            )

        # 2. Owner flips venue ON in DEMO mode.
        active_snap = venue.activate(mode="DEMO", now_utc=now)
        self.assertEqual(active_snap["status"], VENUE_STATUS_DEMO_ACTIVE)
        self.assertTrue(active_snap["enabled"])
        self.assertEqual(active_snap["mode"], "DEMO")
        self.assertEqual(active_snap["base_url"], TRADOVATE_DEMO_BASE_URL)
        self.assertEqual(active_snap["connection_status"], CONNECTION_STATUS_CONNECTED)

        # Verify exact $5,000.00 whole-contract sizing math before entry.
        mnq_sizing = size_micro_futures_order(
            symbol_or_root="NAS100",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("25.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(mnq_sizing.root, "MNQ")
        self.assertEqual(mnq_sizing.contracts, 1)
        self.assertEqual(mnq_sizing.total_stop_risk_usd, Decimal("50.00"))
        self.assertEqual(mnq_sizing.effective_risk_pct, Decimal("1.0000"))

        mym_half_sizing = size_micro_futures_order(
            symbol_or_root="US30",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("50.00"),
            risk_pct=Decimal("0.50"),
            existing_used_margin_usd=mnq_sizing.required_margin_usd,
        )
        self.assertEqual(mym_half_sizing.root, "MYM")
        self.assertEqual(mym_half_sizing.contracts, 1)
        self.assertEqual(mym_half_sizing.total_stop_risk_usd, Decimal("25.00"))
        self.assertEqual(mym_half_sizing.effective_risk_pct, Decimal("0.5000"))

        mym_full_sizing = size_micro_futures_order(
            symbol_or_root="US30",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("50.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(mym_full_sizing.contracts, 2)
        self.assertEqual(mym_full_sizing.total_stop_risk_usd, Decimal("50.00"))

        # 3. Translate NAS100 -> front-month MNQ & US30 -> front-month MYM, pass real valve, fill.
        expected_mnq_fm = resolve_front_month_contract("NAS100", as_of_utc=now)
        expected_mym_fm = resolve_front_month_contract("US30", as_of_utc=now)
        self.assertEqual(expected_mnq_fm.contract_code, "MNQZ6")
        self.assertEqual(expected_mym_fm.contract_code, "MYMZ6")

        mnq_open = venue.place_bracket_order(
            symbol="NAS100",
            side="BUY",
            stop_distance_points=Decimal("25.00"),
            take_profit_points=Decimal("50.00"),
            risk_pct=Decimal("1.00"),
            reason="SCENARIO_A_MNQ_ENTRY",
            now_utc=now,
        )
        self.assertTrue(mnq_open.accepted)
        self.assertTrue(mnq_open.protection_confirmed)
        self.assertIsNotNone(mnq_open.cl_ord_id)
        self.assertIsNotNone(mnq_open.stop_loss_order_id)
        self.assertIsNotNone(mnq_open.take_profit_order_id)
        self.assertEqual(mnq_open.root_symbol, "MNQ")
        self.assertEqual(mnq_open.cas_symbol, "NAS100")
        self.assertEqual(mnq_open.contract_code, "MNQZ6")
        self.assertEqual(mnq_open.filled_contracts, 1)
        self.assertEqual(mnq_open.fill_price, Decimal("21000.25"))
        self.assertEqual(mnq_open.stop_loss_price, Decimal("20975.25"))
        self.assertEqual(mnq_open.take_profit_price, Decimal("21050.25"))
        self.assertIsNotNone(mnq_open.valve_score)
        self.assertGreaterEqual(mnq_open.valve_score, VALVE_ADMISSIBILITY_CUTOFF)
        self.assertEqual(mnq_open.valve_weights_sha256, self.valve_gate.weights_sha256)

        # With 1 MNQ open (0.25-pt spread = -$0.50 -> $4,999.50 equity), 0.50% ($24.99 budget)
        # honestly refuses a 50-pt MYM stop ($25.00), while 1.00% ($49.99 budget) sizes exact 1 contract.
        with self.assertRaises(MicroFuturesSizingRefusalError):
            venue.place_bracket_order(
                symbol="US30",
                side="BUY",
                stop_distance_points=Decimal("50.00"),
                take_profit_points=Decimal("100.00"),
                risk_pct=Decimal("0.50"),
                reason="SCENARIO_A_MYM_HONEST_SPREAD_REFUSAL",
                now_utc=now,
            )

        mym_open = venue.place_bracket_order(
            symbol="US30",
            side="BUY",
            stop_distance_points=Decimal("50.00"),
            take_profit_points=Decimal("100.00"),
            risk_pct=Decimal("1.00"),
            reason="SCENARIO_A_MYM_ENTRY",
            now_utc=now,
        )
        self.assertTrue(mym_open.accepted)
        self.assertEqual(mym_open.root_symbol, "MYM")
        self.assertEqual(mym_open.cas_symbol, "US30")
        self.assertEqual(mym_open.contract_code, "MYMZ6")
        self.assertEqual(mym_open.filled_contracts, 1)
        self.assertEqual(mym_open.fill_price, Decimal("43501.00"))
        self.assertEqual(mym_open.stop_loss_price, Decimal("43451.00"))
        self.assertEqual(mym_open.take_profit_price, Decimal("43601.00"))
        self.assertEqual(mym_open.valve_weights_sha256, self.valve_gate.weights_sha256)

        # 4. Move MNQ stop to break-even (protective amend_stop) as price advances.
        t_be = datetime(2026, 11, 20, 15, 45, 0, tzinfo=timezone.utc)
        venue.process_market_quote("MNQ", Decimal("21025.00"), Decimal("21025.25"), now_utc=t_be)
        be_receipt = venue.amend_stop(
            mnq_open.position_id,
            mnq_open.fill_price,
            reason="SCENARIO_A_MOVE_STOP_TO_BREAKEVEN",
            now_utc=t_be,
        )
        self.assertTrue(be_receipt.accepted)
        self.assertEqual(be_receipt.stop_loss_price, Decimal("21000.25"))

        # 5. Hit take-profit on both MNQ (+50 pts) and MYM (+100 pts).
        t_tp = datetime(2026, 11, 20, 16, 10, 0, tzinfo=timezone.utc)
        mnq_tp_fills = venue.process_market_quote(
            "NAS100", Decimal("21050.25"), Decimal("21050.50"), now_utc=t_tp
        )
        mym_tp_fills = venue.process_market_quote(
            "US30", Decimal("43601.00"), Decimal("43602.00"), now_utc=t_tp
        )
        self.assertEqual(len(mnq_tp_fills), 1)
        self.assertEqual(len(mym_tp_fills), 1)

        mnq_close = mnq_tp_fills[0]
        mym_close = mym_tp_fills[0]
        self.assertEqual(mnq_close.status, "TAKE_PROFIT_FILLED")
        self.assertEqual(mym_close.status, "TAKE_PROFIT_FILLED")

        # Verify exact realized P&L net of commissions against spec math.
        expected_mnq_net = compute_contract_pnl_usd(
            "MNQ", "BUY", Decimal("21000.25"), Decimal("21050.25"), 1, include_commission=True
        )
        expected_mym_net = compute_contract_pnl_usd(
            "MYM", "BUY", Decimal("43501.00"), Decimal("43601.00"), 1, include_commission=True
        )
        self.assertEqual(expected_mnq_net, Decimal("98.76"))
        self.assertEqual(expected_mym_net, Decimal("48.76"))
        self.assertEqual(mnq_close.realized_pnl_usd, Decimal("100.00"))
        self.assertEqual(mnq_close.commission_usd, Decimal("1.24"))
        self.assertEqual(mnq_close.net_pnl_usd, expected_mnq_net)
        self.assertEqual(mym_close.realized_pnl_usd, Decimal("50.00"))
        self.assertEqual(mym_close.commission_usd, Decimal("1.24"))
        self.assertEqual(mym_close.net_pnl_usd, expected_mym_net)

        # 6. Verify SHA-256 audit chain AND strictly 0-write ?mode=ro snapshot().
        self.assertTrue(venue.verify_audit_chain())
        with closing(sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)) as obs:
            dv_before = obs.execute("PRAGMA data_version").fetchone()[0]
            final_snap = venue.snapshot(now_utc=t_tp)
            status_snap = venue.status_snapshot(now_utc=t_tp)
            chain_ok = venue.verify_audit_chain()
            dv_after = obs.execute("PRAGMA data_version").fetchone()[0]

        self.assertEqual(dv_before, dv_after)
        self.assertTrue(chain_ok)
        self.assertTrue(final_snap["audit_chain_valid"])
        self.assertEqual(final_snap, status_snap)
        self.assertEqual(final_snap["positions"], [])
        self.assertEqual(final_snap["account"]["balance_usd"], "5147.52")
        self.assertEqual(final_snap["account"]["equity_usd"], "5147.52")
        self.assertEqual(final_snap["account"]["realized_pnl_usd"], "147.52")
        self.assertEqual(final_snap["account"]["total_commissions_usd"], "2.48")

    def test_scenario_b_gold_mgc_roll_constitutional_refusals_and_drawdown_brake(self) -> None:
        """Scenario B: XAUUSD -> MGC roll & trade, 1.01% refusal, $3,000 refusal, >=10% drawdown brake."""
        # 1. Verify XAUUSD -> MGC roll ahead of Dec 2026 expiry (2026-12-29; 7-day roll = 2026-12-22).
        pre_roll_dt = datetime(2026, 12, 21, 14, 0, 0, tzinfo=timezone.utc)
        on_roll_dt = datetime(2026, 12, 22, 14, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(translate_cas_symbol_to_micro_root("XAUUSD"), "MGC")
        pre_roll_fm = resolve_front_month_contract("XAUUSD", as_of_utc=pre_roll_dt)
        on_roll_fm = resolve_front_month_contract("XAUUSD", as_of_utc=on_roll_dt)
        self.assertEqual(pre_roll_fm.contract_code, "MGCZ6")
        self.assertEqual(on_roll_fm.contract_code, "MGCG7")

        # 2. Execute XAUUSD -> MGC trade on $5,000.00 DEMO venue with auto-rolled MGCG7.
        emulator = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            account_id="TV-DEMO-5000-B",
            mode="DEMO",
            clock=self._fixed_clock(on_roll_dt),
        )
        emulator.connect()
        emulator.set_quote("XAUUSD", Decimal("2700.00"), Decimal("2700.10"), observed_at=on_roll_dt)
        emulator.set_quote("NAS100", Decimal("21000.00"), Decimal("21000.25"), observed_at=on_roll_dt)

        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp_dir / "scenario_b.sqlite3",
            transport=emulator,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(on_roll_dt),
        )
        venue.activate(mode="DEMO", now_utc=on_roll_dt)

        # Explicit locked-out MGCZ6 contract is rejected fail-closed.
        with self.assertRaises(ExpiredFuturesContractError):
            venue.place_bracket_order(
                symbol="XAUUSD",
                side="BUY",
                stop_distance_points=Decimal("5.00"),
                take_profit_points=Decimal("10.00"),
                risk_pct=Decimal("1.00"),
                contract_code="MGCZ6",
                now_utc=on_roll_dt,
            )

        # Auto-rolled MGCG7 trade: 5.0-pt SL * $10.00/pt = $50.00 = 1.00% -> exact 1 contract.
        mgc_open = venue.place_bracket_order(
            symbol="XAUUSD",
            side="BUY",
            stop_distance_points=Decimal("5.00"),
            take_profit_points=Decimal("10.00"),
            risk_pct=Decimal("1.00"),
            reason="SCENARIO_B_GOLD_MGC",
            now_utc=on_roll_dt,
        )
        self.assertEqual(mgc_open.root_symbol, "MGC")
        self.assertEqual(mgc_open.cas_symbol, "XAUUSD")
        self.assertEqual(mgc_open.contract_code, "MGCG7")
        self.assertEqual(mgc_open.filled_contracts, 1)
        self.assertEqual(mgc_open.fill_price, Decimal("2700.10"))

        mgc_tp = venue.process_market_quote(
            "XAUUSD", Decimal("2710.10"), Decimal("2710.20"), now_utc=on_roll_dt
        )
        self.assertEqual(len(mgc_tp), 1)
        self.assertEqual(mgc_tp[0].realized_pnl_usd, Decimal("100.00"))
        self.assertEqual(mgc_tp[0].net_pnl_usd, Decimal("97.58"))

        # 3. Constitutional risk_pct=1.01% MUST fail closed on both engine & venue.
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("1.01"),
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("50.00"),
                risk_pct=Decimal("1.01"),
                now_utc=on_roll_dt,
            )

        # 4. $3,000.00 account MNQ 25-pt stop ($50 risk > $30 budget) -> honest refusal.
        small_emu = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("3000.00"),
            account_id="TV-DEMO-3000",
            mode="DEMO",
            clock=self._fixed_clock(on_roll_dt),
        )
        small_emu.connect()
        small_emu.set_quote("NAS100", Decimal("21000.00"), Decimal("21000.25"), observed_at=on_roll_dt)
        small_venue = TradovateMicroFuturesVenue(
            db_path=self.tmp_dir / "scenario_b_small.sqlite3",
            transport=small_emu,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(on_roll_dt),
        )
        small_venue.activate(mode="DEMO", now_utc=on_roll_dt)
        with self.assertRaises(MicroFuturesSizingRefusalError):
            small_venue.place_bracket_order(
                symbol="NAS100",
                side="BUY",
                stop_distance_points=Decimal("25.00"),
                take_profit_points=Decimal("50.00"),
                risk_pct=Decimal("1.00"),
                now_utc=on_roll_dt,
            )

        # 5. >= 10.00% drawdown brake refuses new entries while still allowing emergency_close_all().
        dd_emu = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            account_id="TV-DEMO-DD",
            mode="DEMO",
            clock=self._fixed_clock(on_roll_dt),
        )
        dd_emu.connect()
        dd_emu.set_quote("NAS100", Decimal("21000.00"), Decimal("21000.25"), observed_at=on_roll_dt)
        dd_emu.set_quote("US30", Decimal("43500.00"), Decimal("43501.00"), observed_at=on_roll_dt)
        dd_venue = TradovateMicroFuturesVenue(
            db_path=self.tmp_dir / "scenario_b_dd.sqlite3",
            transport=dd_emu,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(on_roll_dt),
        )
        dd_venue.activate(mode="DEMO", now_utc=on_roll_dt)

        # Open 1 MNQ with a wide enough initial protective stop (without widening after entry) that
        # a 260-pt drop creates >=10% unrealized drawdown ($520.00 drop on $5,000.00 = 10.40% drawdown).
        dd_emu._positions.clear()
        from cas_forex_revamp.futures.tradovate_venue import _MutablePaperPosition
        pos_open = _MutablePaperPosition(
            position_id="pos-dd-mnq-1",
            contract_code="MNQZ26",
            root_symbol="MNQ",
            cas_symbol="NAS100",
            side="BUY",
            contracts=1,
            entry_price=Decimal("21000.25"),
            stop_loss_price=Decimal("20500.00"),
            take_profit_price=Decimal("21100.00"),
            used_margin_usd=Decimal("200.00"),
            commission_usd=Decimal("1.24"),
            opened_at=on_roll_dt,
            updated_at=on_roll_dt,
        )
        dd_emu._positions[pos_open.position_id] = pos_open
        dd_venue.process_market_quote(
            "NAS100", Decimal("20740.25"), Decimal("20740.50"), now_utc=on_roll_dt
        )

        dd_snap = dd_venue.snapshot(now_utc=on_roll_dt)
        self.assertTrue(dd_snap["drawdown_locked"])
        self.assertGreaterEqual(Decimal(dd_snap["drawdown_pct"]), Decimal("0.10"))

        # New entry MUST fail closed with TradovateDrawdownLockError.
        with self.assertRaises(TradovateDrawdownLockError):
            dd_venue.place_bracket_order(
                symbol="US30",
                side="BUY",
                stop_distance_points=Decimal("50.00"),
                take_profit_points=Decimal("100.00"),
                risk_pct=Decimal("0.50"),
                now_utc=on_roll_dt,
            )

        # Protective emergency_close_all() MUST remain allowed under drawdown lock.
        closed = dd_venue.emergency_close_all(reason="SCENARIO_B_DD_BRAKE_FLATTEN", now_utc=on_roll_dt)
        self.assertEqual(len(closed), 1)
        self.assertTrue(closed[0].accepted)
        self.assertEqual(closed[0].position_id, pos_open.position_id)
        self.assertEqual(dd_venue.snapshot(now_utc=on_roll_dt)["positions"], [])
        self.assertTrue(dd_venue.verify_audit_chain())
        self.assertTrue(venue.verify_audit_chain())

    def test_scenario_c_live_host_pinning_security_isolation_and_audit_tamper(self) -> None:
        """Scenario C: LIVE lock, DEMO pinning, failed-activate atomicity, secret redaction, tamper detection."""
        now = datetime(2026, 11, 20, 17, 0, 0, tzinfo=timezone.utc)

        # 1. LIVE without verified LiveAuthorizationContext (including bare live_arming_verified=True) fails closed everywhere.
        with self.assertRaises(LiveAuthorizationError):
            validate_tradovate_endpoint("LIVE", TRADOVATE_LIVE_BASE_URL, live_arming_verified=True)
        with self.assertRaises(LiveAuthorizationError):
            TradovateCredentials(
                enabled=True,
                mode="LIVE",
                base_url=TRADOVATE_LIVE_BASE_URL,
                account_id="TV-LIVE-SCENARIO-C",
                live_arming_verified=True,
            )
        with self.assertRaises(TradovateLiveLockError):
            validate_tradovate_endpoint("LIVE", TRADOVATE_LIVE_BASE_URL, live_arming_verified=False)
        with self.assertRaises(TradovateLiveLockError):
            TradovateCredentials(
                enabled=True,
                mode="LIVE",
                base_url=TRADOVATE_LIVE_BASE_URL,
                live_arming_verified=False,
            )
        with self.assertRaises(TradovateLiveLockError):
            TradovateMicroFuturesVenue(
                db_path=self.tmp_dir / "live_unarmed_init.sqlite3",
                mode="LIVE",
                live_arming_verified=False,
            )

        # Non-bool truthy strings like "false" MUST NOT bypass live_arming_verified.
        with self.assertRaises(TradovateLiveLockError):
            TradovateMicroFuturesVenue(
                db_path=self.tmp_dir / "live_str_init.sqlite3",
                mode="LIVE",
                live_arming_verified="false",  # type: ignore[arg-type]
            )

        emu = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            account_id="TV-SEC-TEST",
            mode="DEMO",
            clock=self._fixed_clock(now),
        )
        venue = TradovateMicroFuturesVenue(
            db_path=self.tmp_dir / "scenario_c.sqlite3",
            transport=emu,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(now),
        )
        with self.assertRaises(TradovateLiveLockError):
            venue.activate(mode="LIVE", live_arming_verified=False, now_utc=now)
        with self.assertRaises(TradovateLiveLockError):
            venue.activate(mode="LIVE", live_arming_verified="false", now_utc=now)  # type: ignore[arg-type]
        self.assertEqual(venue.venue_status, VENUE_STATUS_STANDBY)
        self.assertFalse(venue.enabled)

        # 2. DEMO cannot touch live.tradovateapi.com; unpinned/http/localhost/redirect refused.
        with self.assertRaises(TradovateLiveLockError):
            validate_tradovate_endpoint("DEMO", TRADOVATE_LIVE_BASE_URL)
        for bad_url in (
            "http://demo.tradovateapi.com/v1",
            "https://demo.tradovateapi.com:8443/v1",
            "https://127.0.0.1/v1",
            "https://localhost/v1",
            "https://evil.tradovateapi.com/v1",
            "https://demo.tradovateapi.com/v1?token=leak",
        ):
            with self.assertRaises(TradovateEndpointError):
                validate_tradovate_endpoint("DEMO", bad_url)
        no_redir = _NoRedirectHandler()
        with self.assertRaises(TradovateTransportError):
            no_redir.redirect_request(None, None, 302, "Found", {}, "https://evil.example/v1")

        # 3. Failed transport.connect() during activate() MUST leave venue in STANDBY_READY (atomic).
        unconfigured_creds = TradovateCredentials(enabled=False, mode="DEMO")
        https_transport = TradovateHttpsTransport(credentials=unconfigured_creds)
        atomic_venue = TradovateMicroFuturesVenue(
            db_path=self.tmp_dir / "scenario_c_atomic.sqlite3",
            credentials=unconfigured_creds,
            transport=https_transport,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(now),
        )
        with self.assertRaises(TradovateNotConfiguredError):
            atomic_venue.activate(mode="DEMO", now_utc=now)
        self.assertFalse(atomic_venue.enabled)
        self.assertEqual(atomic_venue.venue_status, VENUE_STATUS_STANDBY)

        # 4. Credentials never leak in repr/str/format/pickle/snapshot/SQLite audit log.
        secret_pw = "-".join(("demo", "tv", "val", "01"))
        secret_api = "-".join(("demo", "tv", "val", "02"))
        secret_tok = "-".join(("demo", "tv", "val", "03"))
        creds = load_tradovate_credentials(
            {
                "CAS_TRADOVATE_ENABLED": "0",
                "CAS_TRADOVATE_MODE": "DEMO",
                "CAS_TRADOVATE_USERNAME": "trader_demo_user",
                "CAS_TRADOVATE_PASSWORD": secret_pw,
                "CAS_TRADOVATE_APP_ID": "CAS_APP",
                "CAS_TRADOVATE_CID": "42",
                "CAS_TRADOVATE_SEC": secret_api,
            }
        )
        redacted_tok = _RedactedSecret(secret_tok)
        self.assertFalse(creds.enabled)
        for rendered in (
            repr(creds),
            str(creds),
            repr(creds.password),
            str(creds.password),
            f"{creds.password}",
            repr(creds.sec),
            str(creds.sec),
            f"{creds.sec}",
            repr(redacted_tok),
            str(redacted_tok),
            f"{redacted_tok}",
        ):
            self.assertNotIn(secret_pw, rendered)
            self.assertNotIn(secret_api, rendered)
            self.assertNotIn(secret_tok, rendered)
        with self.assertRaises(TypeError):
            pickle.dumps(redacted_tok)

        db_sec = self.tmp_dir / "scenario_c_secrets.sqlite3"
        emu_sec = TradovateMicroFuturesPaperEmulator(
            starting_equity_usd=Decimal("5000.00"),
            account_id="TV-SEC-AUDIT",
            mode="DEMO",
            clock=self._fixed_clock(now),
        )
        emu_sec.connect()
        emu_sec.set_quote("SPX500", Decimal("6000.00"), Decimal("6000.25"), observed_at=now)
        sec_venue = TradovateMicroFuturesVenue(
            db_path=db_sec,
            credentials=creds,
            transport=emu_sec,
            valve_gate=self.valve_gate,
            clock=self._fixed_clock(now),
        )
        snap_active = sec_venue.activate(mode="DEMO", now_utc=now)
        sec_venue.place_bracket_order(
            symbol="SPX500",
            side="BUY",
            stop_distance_points=Decimal("10.00"),
            take_profit_points=Decimal("20.00"),
            risk_pct=Decimal("1.00"),
            now_utc=now,
        )
        snap_text = repr(snap_active) + repr(sec_venue.snapshot(now_utc=now))
        self.assertNotIn(secret_pw, snap_text)
        self.assertNotIn(secret_api, snap_text)

        # Verify raw SQLite database bytes contain zero credential leaks.
        raw_db_bytes = db_sec.read_bytes()
        for wal_suffix in ("-wal", "-shm"):
            sidecar = Path(f"{db_sec}{wal_suffix}")
            if sidecar.exists():
                raw_db_bytes += sidecar.read_bytes()
        self.assertNotIn(secret_pw.encode("utf-8"), raw_db_bytes)
        self.assertNotIn(secret_api.encode("utf-8"), raw_db_bytes)

        # 5. Mandatory valve gate cannot be bypassed (valve_gate=None fails closed).
        no_valve_venue = TradovateMicroFuturesVenue(
            db_path=self.tmp_dir / "scenario_c_no_valve.sqlite3",
            transport=emu_sec,
            valve_gate=None,
            clock=self._fixed_clock(now),
        )
        no_valve_venue.activate(mode="DEMO", now_utc=now)
        with self.assertRaises(TradovateValveRefusalError):
            no_valve_venue.place_bracket_order(
                symbol="SPX500",
                side="BUY",
                stop_distance_points=Decimal("5.00"),
                take_profit_points=Decimal("10.00"),
                risk_pct=Decimal("1.00"),
                now_utc=now,
            )

        # 6. Tampering with a single SQLite audit row flips verify_audit_chain() to False.
        self.assertTrue(sec_venue.verify_audit_chain())
        with closing(sqlite3.connect(str(db_sec))) as conn:
            conn.execute(
                "UPDATE audit_events SET payload_json = ? WHERE seq = 1",
                ('{"tampered":true}',),
            )
            conn.commit()
        self.assertFalse(sec_venue.verify_audit_chain())
        self.assertFalse(sec_venue.snapshot(now_utc=now)["audit_chain_valid"])


if __name__ == "__main__":
    unittest.main()
