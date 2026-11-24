"""Phase 8 Unit Tests for CME Micro Futures Specifications, Roll Resolver & Constitutional Sizing."""
from __future__ import annotations

import ast
from datetime import date, datetime, timedelta, timezone
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal
from pathlib import Path
import unittest

import cas_forex_revamp.futures as futures_pkg
from cas_forex_revamp.contracts import ContractError, Side
from cas_forex_revamp.futures import (
    CME_MICRO_FUTURES_SPECS,
    CODE_TO_MONTH_MAP,
    DEFAULT_MIN_MARGIN_LEVEL_PCT,
    DEFAULT_ROLL_BUFFER_DAYS,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    MONTH_CODE_MAP,
    ExpiredFuturesContractError,
    FrontMonthContract,
    MicroFuturesContractSpec,
    MicroFuturesError,
    MicroFuturesSizingRefusalError,
    MicroFuturesSizingResult,
    UnsupportedMicroFuturesSymbolError,
    align_price_to_tick,
    compute_contract_expiry_date,
    compute_contract_pnl_usd,
    get_contract_spec,
    resolve_front_month_contract,
    size_micro_futures_order,
    translate_cas_symbol_to_micro_root,
    translate_micro_root_to_cas_symbol,
    validate_contract_not_expired,
)


class TestMicroFuturesCatalogAndTranslation(unittest.TestCase):
    def test_catalog_contains_all_four_cme_micro_specs_with_exact_decimals(self) -> None:
        self.assertEqual(set(CME_MICRO_FUTURES_SPECS.keys()), {"MNQ", "MYM", "MES", "MGC"})

        mnq = CME_MICRO_FUTURES_SPECS["MNQ"]
        self.assertEqual(mnq.exchange, "CME")
        self.assertEqual(mnq.cas_symbol, "NAS100")
        self.assertEqual(mnq.point_value_usd, Decimal("2.00"))
        self.assertEqual(mnq.tick_size, Decimal("0.25"))
        self.assertEqual(mnq.tick_value_usd, Decimal("0.50"))
        self.assertEqual(mnq.roll_months, (3, 6, 9, 12))
        self.assertEqual(mnq.roll_month_codes, ("H", "M", "U", "Z"))
        self.assertEqual(mnq.default_intraday_margin_usd, Decimal("100.00"))
        self.assertEqual(mnq.default_exchange_initial_margin_usd, Decimal("2200.00"))
        self.assertEqual(mnq.default_round_turn_commission_usd, Decimal("1.24"))
        self.assertEqual(mnq.cas_aliases, ("NAS100", "USTEC", "US100", "NDX", "MNQ"))

        mym = CME_MICRO_FUTURES_SPECS["MYM"]
        self.assertEqual(mym.exchange, "CBOT")
        self.assertEqual(mym.cas_symbol, "US30")
        self.assertEqual(mym.point_value_usd, Decimal("0.50"))
        self.assertEqual(mym.tick_size, Decimal("1.00"))
        self.assertEqual(mym.tick_value_usd, Decimal("0.50"))
        self.assertEqual(mym.roll_months, (3, 6, 9, 12))
        self.assertEqual(mym.roll_month_codes, ("H", "M", "U", "Z"))
        self.assertEqual(mym.default_intraday_margin_usd, Decimal("50.00"))
        self.assertEqual(mym.default_exchange_initial_margin_usd, Decimal("1100.00"))
        self.assertEqual(mym.default_round_turn_commission_usd, Decimal("1.24"))
        self.assertEqual(mym.cas_aliases, ("US30", "DJ30", "DJI", "MYM"))

        mes = CME_MICRO_FUTURES_SPECS["MES"]
        self.assertEqual(mes.exchange, "CME")
        self.assertEqual(mes.cas_symbol, "SPX500")
        self.assertEqual(mes.point_value_usd, Decimal("5.00"))
        self.assertEqual(mes.tick_size, Decimal("0.25"))
        self.assertEqual(mes.tick_value_usd, Decimal("1.25"))
        self.assertEqual(mes.roll_months, (3, 6, 9, 12))
        self.assertEqual(mes.roll_month_codes, ("H", "M", "U", "Z"))
        self.assertEqual(mes.default_intraday_margin_usd, Decimal("50.00"))
        self.assertEqual(mes.default_exchange_initial_margin_usd, Decimal("1500.00"))
        self.assertEqual(mes.default_round_turn_commission_usd, Decimal("1.24"))
        self.assertEqual(mes.cas_aliases, ("SPX500", "US500", "SPX", "MES"))

        mgc = CME_MICRO_FUTURES_SPECS["MGC"]
        self.assertEqual(mgc.exchange, "COMEX")
        self.assertEqual(mgc.cas_symbol, "XAUUSD")
        self.assertEqual(mgc.point_value_usd, Decimal("10.00"))
        self.assertEqual(mgc.tick_size, Decimal("0.10"))
        self.assertEqual(mgc.tick_value_usd, Decimal("1.00"))
        self.assertEqual(mgc.roll_months, (2, 4, 6, 8, 10, 12))
        self.assertEqual(mgc.roll_month_codes, ("G", "J", "M", "Q", "V", "Z"))
        self.assertEqual(mgc.default_intraday_margin_usd, Decimal("200.00"))
        self.assertEqual(mgc.default_exchange_initial_margin_usd, Decimal("1200.00"))
        self.assertEqual(mgc.default_round_turn_commission_usd, Decimal("2.42"))
        self.assertEqual(mgc.cas_aliases, ("XAUUSD", "XAU_USD", "GOLD", "MGC"))

    def test_cme_month_codes_and_constitutional_constants(self) -> None:
        self.assertEqual(
            dict(MONTH_CODE_MAP),
            {
                1: "F",
                2: "G",
                3: "H",
                4: "J",
                5: "K",
                6: "M",
                7: "N",
                8: "Q",
                9: "U",
                10: "V",
                11: "X",
                12: "Z",
            },
        )
        self.assertEqual(len(CODE_TO_MONTH_MAP), 12)
        self.assertEqual(CODE_TO_MONTH_MAP["H"], 3)
        self.assertEqual(CODE_TO_MONTH_MAP["Z"], 12)
        self.assertEqual(MAX_CONSTITUTIONAL_STOP_RISK_PCT, Decimal("1.00"))
        self.assertEqual(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, Decimal("0.10"))
        self.assertEqual(DEFAULT_MIN_MARGIN_LEVEL_PCT, Decimal("1000.0"))
        self.assertEqual(DEFAULT_ROLL_BUFFER_DAYS, 7)

    def test_spec_validation_rejects_mismatched_tick_value_and_floats(self) -> None:
        with self.assertRaises(MicroFuturesError):
            MicroFuturesContractSpec(
                root="MNQ",
                name="Bad Tick",
                cas_symbol="NAS100",
                exchange="CME",
                point_value_usd=Decimal("2.00"),
                tick_size=Decimal("0.25"),
                tick_value_usd=Decimal("0.75"),
                roll_months=(3, 6, 9, 12),
                default_intraday_margin_usd=Decimal("100.00"),
                default_exchange_initial_margin_usd=Decimal("2200.00"),
                default_round_turn_commission_usd=Decimal("1.24"),
                cas_aliases=("NAS100", "MNQ"),
            )
        with self.assertRaises(MicroFuturesError):
            MicroFuturesContractSpec(
                root="MNQ",
                name="Float Point Value",
                cas_symbol="NAS100",
                exchange="CME",
                point_value_usd=2.0,  # type: ignore[arg-type]
                tick_size=Decimal("0.25"),
                tick_value_usd=Decimal("0.50"),
                roll_months=(3, 6, 9, 12),
                default_intraday_margin_usd=Decimal("100.00"),
                default_exchange_initial_margin_usd=Decimal("2200.00"),
                default_round_turn_commission_usd=Decimal("1.24"),
                cas_aliases=("NAS100", "MNQ"),
            )

    def test_cas_to_micro_root_translation_and_reverse(self) -> None:
        cases = [
            ("NAS100", "MNQ"),
            ("ustec", "MNQ"),
            ("US100", "MNQ"),
            ("NDX", "MNQ"),
            ("MNQ", "MNQ"),
            ("MNQZ6", "MNQ"),
            ("MNQZ26", "MNQ"),
            ("US30", "MYM"),
            ("DJ30", "MYM"),
            ("DJI", "MYM"),
            ("MYM", "MYM"),
            ("MYMH7", "MYM"),
            ("SPX500", "MES"),
            ("US500", "MES"),
            ("SPX", "MES"),
            ("MES", "MES"),
            ("MESU6", "MES"),
            ("XAUUSD", "MGC"),
            ("XAU_USD", "MGC"),
            ("GOLD", "MGC"),
            ("MGC", "MGC"),
            ("MGCG7", "MGC"),
        ]
        for raw, expected_root in cases:
            self.assertEqual(translate_cas_symbol_to_micro_root(raw), expected_root)
            self.assertEqual(get_contract_spec(raw).root, expected_root)

        self.assertEqual(translate_micro_root_to_cas_symbol("MNQ"), "NAS100")
        self.assertEqual(translate_micro_root_to_cas_symbol("MYM"), "US30")
        self.assertEqual(translate_micro_root_to_cas_symbol("MES"), "SPX500")
        self.assertEqual(translate_micro_root_to_cas_symbol("MGC"), "XAUUSD")
        self.assertEqual(translate_micro_root_to_cas_symbol("mnqz6"), "NAS100")

    def test_unsupported_symbols_raise_fail_closed(self) -> None:
        for bad in ("EURUSD", "GBPUSD", "USDJPY", "BTCUSD", "ETHUSD", "NQ", "ES", "CL", "MNQF6", "", "   "):
            with self.assertRaises(UnsupportedMicroFuturesSymbolError):
                translate_cas_symbol_to_micro_root(bad)
        for bad_root in ("EURUSD", "NAS100", "NQ", "MGCX6", ""):
            with self.assertRaises(UnsupportedMicroFuturesSymbolError):
                translate_micro_root_to_cas_symbol(bad_root)
        with self.assertRaises(UnsupportedMicroFuturesSymbolError):
            translate_cas_symbol_to_micro_root(None)  # type: ignore[arg-type]


class TestFrontMonthRollResolver(unittest.TestCase):
    def test_exact_expiry_dates_indices_and_gold(self) -> None:
        # Equity indices: 3rd Friday of Mar/Jun/Sep/Dec
        self.assertEqual(compute_contract_expiry_date("MNQ", 2026, 3), date(2026, 3, 20))
        self.assertEqual(compute_contract_expiry_date("MYM", 2026, 6), date(2026, 6, 19))
        self.assertEqual(compute_contract_expiry_date("MES", 2026, 9), date(2026, 9, 18))
        self.assertEqual(compute_contract_expiry_date("NAS100", 2026, 12), date(2026, 12, 18))
        self.assertEqual(compute_contract_expiry_date("MNQ", 2027, 3), date(2027, 3, 19))

        # Gold (MGC): 3rd-to-last business day of Feb/Apr/Jun/Aug/Oct/Dec
        # Dec 2026 ends Thu 31 -> business days from end: 31 (Thu), 30 (Wed), 29 (Tue)
        self.assertEqual(compute_contract_expiry_date("MGC", 2026, 12), date(2026, 12, 29))
        # Feb 2027 ends Sun 28 -> business days from end: 26 (Fri), 25 (Thu), 24 (Wed)
        self.assertEqual(compute_contract_expiry_date("XAUUSD", 2027, 2), date(2027, 2, 24))
        # Apr 2027 ends Fri 30 -> business days from end: 30 (Fri), 29 (Thu), 28 (Wed)
        self.assertEqual(compute_contract_expiry_date("MGC", 2027, 4), date(2027, 4, 28))

        with self.assertRaises(UnsupportedMicroFuturesSymbolError):
            compute_contract_expiry_date("MNQ", 2026, 2)

    def test_quarterly_automatic_roll_boundary(self) -> None:
        # Dec 2026 MNQ expiry = 2026-12-18; 7-day roll date = 2026-12-11
        before_roll = datetime(2026, 12, 10, 23, 59, 0, tzinfo=timezone.utc)
        c1 = resolve_front_month_contract("NAS100", as_of_utc=before_roll)
        self.assertIsInstance(c1, FrontMonthContract)
        self.assertEqual(c1.root, "MNQ")
        self.assertEqual(c1.cas_symbol, "NAS100")
        self.assertEqual(c1.contract_code, "MNQZ6")
        self.assertEqual(c1.contract_code_4digit, "MNQZ26")
        self.assertEqual(c1.month_code, "Z")
        self.assertEqual(c1.expiry_date, date(2026, 12, 18))
        self.assertEqual(c1.roll_date, date(2026, 12, 11))
        self.assertEqual(c1.days_to_expiry, 8)

        # On exact roll date (2026-12-11), must roll forward to Mar 2027 (MNQH7 / MNQH27)
        on_roll = datetime(2026, 12, 11, 0, 0, 0, tzinfo=timezone.utc)
        c2 = resolve_front_month_contract("MNQ", as_of_utc=on_roll)
        self.assertEqual(c2.contract_code, "MNQH7")
        self.assertEqual(c2.contract_code_4digit, "MNQH27")
        self.assertEqual(c2.month_code, "H")
        self.assertEqual(c2.expiry_date, date(2027, 3, 19))
        self.assertEqual(c2.roll_date, date(2027, 3, 12))
        self.assertEqual(c2.days_to_expiry, (date(2027, 3, 19) - date(2026, 12, 11)).days)

    def test_gold_automatic_roll_boundary(self) -> None:
        # Dec 2026 MGC expiry = 2026-12-29; 7-day roll date = 2026-12-22
        before_roll = datetime(2026, 12, 21, 18, 0, 0, tzinfo=timezone.utc)
        c1 = resolve_front_month_contract("XAUUSD", as_of_utc=before_roll)
        self.assertEqual(c1.root, "MGC")
        self.assertEqual(c1.cas_symbol, "XAUUSD")
        self.assertEqual(c1.contract_code, "MGCZ6")
        self.assertEqual(c1.contract_code_4digit, "MGCZ26")
        self.assertEqual(c1.expiry_date, date(2026, 12, 29))
        self.assertEqual(c1.roll_date, date(2026, 12, 22))
        self.assertEqual(c1.days_to_expiry, 8)

        on_roll = datetime(2026, 12, 22, 0, 0, 0, tzinfo=timezone.utc)
        c2 = resolve_front_month_contract("MGC", as_of_utc=on_roll)
        self.assertEqual(c2.contract_code, "MGCG7")
        self.assertEqual(c2.contract_code_4digit, "MGCG27")
        self.assertEqual(c2.month_code, "G")
        self.assertEqual(c2.expiry_date, date(2027, 2, 24))
        self.assertEqual(c2.roll_date, date(2027, 2, 17))

    def test_validate_contract_not_expired_and_lockout(self) -> None:
        as_of = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
        valid_short = validate_contract_not_expired("MNQZ6", as_of_utc=as_of)
        valid_long = validate_contract_not_expired("MNQZ26", as_of_utc=as_of)
        self.assertEqual(valid_short, valid_long)
        self.assertEqual(valid_short.contract_code, "MNQZ6")
        self.assertEqual(valid_short.contract_code_4digit, "MNQZ26")

        # Expired past contracts (single-digit & two-digit) must fail closed
        for expired_code in ("MNQZ5", "MNQZ25", "MNQU6", "MNQU26", "MGCQ6", "MGCQ26"):
            with self.assertRaises(ExpiredFuturesContractError):
                validate_contract_not_expired(expired_code, as_of_utc=as_of)

        # Inside 7-day roll lockout window must fail closed
        inside_lockout = datetime(2026, 12, 11, 12, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ExpiredFuturesContractError):
            validate_contract_not_expired("MNQZ6", as_of_utc=inside_lockout)

        # Decade transition: Dec 2029 looking at MNQH0 (Mar 2030) active; Jan 2030 looking at MNQZ9 expired
        dec_2029 = datetime(2029, 12, 20, 0, 0, 0, tzinfo=timezone.utc)
        next_decade = validate_contract_not_expired("MNQH0", as_of_utc=dec_2029)
        self.assertEqual(next_decade.expiry_date, date(2030, 3, 15))
        self.assertEqual(next_decade.contract_code_4digit, "MNQH30")

        jan_2030 = datetime(2030, 1, 5, 0, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ExpiredFuturesContractError):
            validate_contract_not_expired("MNQZ9", as_of_utc=jan_2030)

    def test_naive_datetime_rejected_and_aware_tz_normalized(self) -> None:
        with self.assertRaises(MicroFuturesError):
            resolve_front_month_contract("MNQ", as_of_utc=datetime(2026, 11, 20, 12, 0))
        with self.assertRaises(MicroFuturesError):
            validate_contract_not_expired("MNQZ6", as_of_utc=datetime(2026, 11, 20, 12, 0))

        # 2026-12-10 20:00 EST (UTC-5) == 2026-12-11 01:00 UTC -> rolled to MNQH7!
        est = timezone(timedelta(hours=-5))
        est_dt = datetime(2026, 12, 10, 20, 0, 0, tzinfo=est)
        rolled = resolve_front_month_contract("MNQ", as_of_utc=est_dt)
        self.assertEqual(rolled.contract_code, "MNQH7")


class TestTickAlignmentAndPnL(unittest.TestCase):
    def test_align_price_to_tick_all_contracts(self) -> None:
        self.assertEqual(align_price_to_tick("MNQ", Decimal("21000.13")), Decimal("21000.25"))
        self.assertEqual(align_price_to_tick("MNQ", Decimal("21000.12")), Decimal("21000.00"))
        self.assertEqual(
            align_price_to_tick("MNQ", Decimal("21000.37"), rounding=ROUND_FLOOR),
            Decimal("21000.25"),
        )
        self.assertEqual(
            align_price_to_tick("MNQ", Decimal("21000.01"), rounding=ROUND_CEILING),
            Decimal("21000.25"),
        )
        self.assertEqual(align_price_to_tick("MYM", Decimal("43500.60")), Decimal("43501.00"))
        self.assertEqual(align_price_to_tick("MES", Decimal("6000.38")), Decimal("6000.50"))
        self.assertEqual(align_price_to_tick("XAUUSD", Decimal("2650.16")), Decimal("2650.20"))
        self.assertEqual(
            align_price_to_tick("MGC", Decimal("2650.15"), rounding=ROUND_HALF_UP),
            Decimal("2650.20"),
        )

    def test_align_price_rejects_floats_bools_and_non_positive(self) -> None:
        with self.assertRaises(MicroFuturesError):
            align_price_to_tick("MNQ", 21000.25)  # type: ignore[arg-type]
        with self.assertRaises(MicroFuturesError):
            align_price_to_tick("MNQ", True)  # type: ignore[arg-type]
        with self.assertRaises(MicroFuturesError):
            align_price_to_tick("MNQ", Decimal("0"))
        with self.assertRaises(MicroFuturesError):
            align_price_to_tick("MNQ", Decimal("-10.00"))
        with self.assertRaises(MicroFuturesError):
            align_price_to_tick("MNQ", Decimal("NaN"))

    def test_compute_contract_pnl_usd_exact_gross_and_net(self) -> None:
        # MNQ: 60-pt TP on 1 contract -> +$120.00 gross, +$118.76 net of $1.24 commission
        self.assertEqual(
            compute_contract_pnl_usd(
                "NAS100",
                "BUY",
                Decimal("21000.00"),
                Decimal("21060.00"),
                1,
                include_commission=False,
            ),
            Decimal("120.00"),
        )
        self.assertEqual(
            compute_contract_pnl_usd(
                "MNQ",
                Side.BUY,  # type: ignore[arg-type]
                Decimal("21000.00"),
                Decimal("21060.00"),
                1,
                include_commission=True,
            ),
            Decimal("118.76"),
        )
        # MNQ: 25-pt SL on 1 contract -> -$50.00 gross, -$51.24 net
        self.assertEqual(
            compute_contract_pnl_usd("MNQ", "LONG", Decimal("21000.00"), Decimal("20975.00"), 1),
            Decimal("-51.24"),
        )
        # MYM: 50-pt SHORT profit on 2 contracts -> +$50.00 gross, -$2.48 comm = +$47.52 net
        self.assertEqual(
            compute_contract_pnl_usd("MYM", "SHORT", Decimal("43500.00"), Decimal("43450.00"), 2),
            Decimal("47.52"),
        )
        # MES: 10.25-pt BUY profit on 1 contract -> +$51.25 gross, -$1.24 comm = +$50.01 net
        self.assertEqual(
            compute_contract_pnl_usd("MES", "BUY", Decimal("6000.00"), Decimal("6010.25"), 1),
            Decimal("50.01"),
        )
        # MGC: 12.40-pt SELL profit on 3 contracts -> +$372.00 gross, -$7.26 comm = +$364.74 net
        self.assertEqual(
            compute_contract_pnl_usd("XAUUSD", Side.SELL, Decimal("2650.00"), Decimal("2637.60"), 3),  # type: ignore[arg-type]
            Decimal("364.74"),
        )

        # Reject float prices, bool contracts, zero contracts, bad side
        with self.assertRaises(MicroFuturesError):
            compute_contract_pnl_usd("MNQ", "BUY", 21000.0, Decimal("21010.00"), 1)  # type: ignore[arg-type]
        with self.assertRaises(MicroFuturesError):
            compute_contract_pnl_usd("MNQ", "BUY", Decimal("21000.00"), Decimal("21010.00"), True)  # type: ignore[arg-type]
        with self.assertRaises(MicroFuturesError):
            compute_contract_pnl_usd("MNQ", "BUY", Decimal("21000.00"), Decimal("21010.00"), 0)
        with self.assertRaises(MicroFuturesError):
            compute_contract_pnl_usd("MNQ", "HOLD", Decimal("21000.00"), Decimal("21010.00"), 1)


class TestConstitutionalSizingEngine(unittest.TestCase):
    def test_5000_usd_exact_sizing_mnq_mym_mes_mgc(self) -> None:
        # $5,000.00 @ 1.00% risk, MNQ 25-pt stop -> 1 contract ($50.00 risk, $100.00 margin, 5,000% margin level)
        mnq_res = size_micro_futures_order(
            symbol_or_root="NAS100",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("25.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertIsInstance(mnq_res, MicroFuturesSizingResult)
        self.assertEqual(mnq_res.root, "MNQ")
        self.assertEqual(mnq_res.cas_symbol, "NAS100")
        self.assertEqual(mnq_res.contracts, 1)
        self.assertEqual(mnq_res.contracts_by_risk, 1)
        self.assertEqual(mnq_res.contracts_by_margin, 5)
        self.assertEqual(mnq_res.risk_budget_usd, Decimal("50.00"))
        self.assertEqual(mnq_res.risk_per_contract_usd, Decimal("50.00"))
        self.assertEqual(mnq_res.total_stop_risk_usd, Decimal("50.00"))
        self.assertEqual(mnq_res.effective_risk_pct, Decimal("1.0000"))
        self.assertEqual(mnq_res.required_margin_usd, Decimal("100.00"))
        self.assertEqual(mnq_res.projected_margin_level_pct, Decimal("5000.00"))
        self.assertEqual(mnq_res.estimated_round_turn_commission_usd, Decimal("1.24"))
        self.assertFalse(mnq_res.used_exchange_margin)

        # $5,000.00 @ 1.00% risk, MYM 50-pt stop -> 2 contracts ($50.00 risk)
        mym_2 = size_micro_futures_order(
            symbol_or_root="US30",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("50.00"),
            risk_pct=Decimal("1.00"),
        )
        self.assertEqual(mym_2.root, "MYM")
        self.assertEqual(mym_2.contracts, 2)
        self.assertEqual(mym_2.total_stop_risk_usd, Decimal("50.00"))
        self.assertEqual(mym_2.required_margin_usd, Decimal("100.00"))
        self.assertEqual(mym_2.estimated_round_turn_commission_usd, Decimal("2.48"))

        # $5,000.00 @ 0.50% risk, MYM 50-pt stop -> 1 contract ($25.00 risk)
        mym_1 = size_micro_futures_order(
            symbol_or_root="MYM",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("50.00"),
            risk_pct=Decimal("0.50"),
        )
        self.assertEqual(mym_1.contracts, 1)
        self.assertEqual(mym_1.total_stop_risk_usd, Decimal("25.00"))
        self.assertEqual(mym_1.effective_risk_pct, Decimal("0.5000"))
        self.assertEqual(mym_1.projected_margin_level_pct, Decimal("10000.00"))

        # $5,000.00 @ 1.00% risk, MES 10-pt stop -> 1 contract ($50.00 risk)
        mes_1 = size_micro_futures_order(
            symbol_or_root="SPX500",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("10.00"),
        )
        self.assertEqual(mes_1.root, "MES")
        self.assertEqual(mes_1.contracts, 1)
        self.assertEqual(mes_1.total_stop_risk_usd, Decimal("50.00"))

        # $5,000.00 @ 1.00% risk, MGC 5-pt stop -> 1 contract ($50.00 risk, $200.00 intraday margin, $2.42 RT fee)
        mgc_1 = size_micro_futures_order(
            symbol_or_root="XAUUSD",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("5.00"),
        )
        self.assertEqual(mgc_1.root, "MGC")
        self.assertEqual(mgc_1.contracts, 1)
        self.assertEqual(mgc_1.total_stop_risk_usd, Decimal("50.00"))
        self.assertEqual(mgc_1.margin_per_contract_usd, Decimal("200.00"))
        self.assertEqual(mgc_1.estimated_round_turn_commission_usd, Decimal("2.42"))

    def test_3000_usd_honest_refusal_never_rounds_up(self) -> None:
        # $3,000 @ 1.00% = $30.00 budget; MNQ 25-pt stop = $50.00/contract -> honest refusal!
        with self.assertRaises(MicroFuturesSizingRefusalError) as ctx:
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("3000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=Decimal("1.00"),
            )
        self.assertIn("30.00", str(ctx.exception))
        self.assertIn("50.00", str(ctx.exception))

    def test_constitutional_risk_ceiling_refusal(self) -> None:
        for bad_risk in (Decimal("1.01"), Decimal("1.50"), Decimal("2.00"), Decimal("0"), Decimal("-0.25")):
            with self.assertRaises(MicroFuturesSizingRefusalError):
                size_micro_futures_order(
                    symbol_or_root="MNQ",
                    equity_usd=Decimal("5000.00"),
                    stop_distance_points=Decimal("10.00"),
                    risk_pct=bad_risk,
                )

    def test_1000_pct_margin_floor_refusal_and_exchange_margin_cap(self) -> None:
        # $5,000 equity with 1000% floor -> max allowed total margin = $500.00.
        # With $450.00 already used, only $50.00 remains: MNQ ($100) refused, MYM ($50) allowed.
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("10.00"),
                existing_used_margin_usd=Decimal("450.00"),
            )
        mym_tight = size_micro_futures_order(
            symbol_or_root="MYM",
            equity_usd=Decimal("5000.00"),
            stop_distance_points=Decimal("20.00"),
            existing_used_margin_usd=Decimal("450.00"),
        )
        self.assertEqual(mym_tight.contracts, 1)
        self.assertEqual(mym_tight.projected_total_used_margin_usd, Decimal("500.00"))
        self.assertEqual(mym_tight.projected_margin_level_pct, Decimal("1000.00"))

        # Exchange initial margin ($2,200) on $5,000 equity violates 1000% floor -> refused
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("10.00"),
                use_exchange_margin=True,
            )

        # Exchange initial margin ($2,200) on $25,000 equity -> $2,500 allowed -> 1 contract
        ex_res = size_micro_futures_order(
            symbol_or_root="MNQ",
            equity_usd=Decimal("25000.00"),
            stop_distance_points=Decimal("10.00"),
            use_exchange_margin=True,
        )
        self.assertEqual(ex_res.contracts, 1)
        self.assertTrue(ex_res.used_exchange_margin)
        self.assertEqual(ex_res.margin_per_contract_usd, Decimal("2200.00"))

        # max_contracts cap enforced
        capped = size_micro_futures_order(
            symbol_or_root="MYM",
            equity_usd=Decimal("50000.00"),
            stop_distance_points=Decimal("5.00"),
            max_contracts=3,
        )
        self.assertEqual(capped.contracts, 3)

    def test_sizing_rejects_float_and_bool_inputs(self) -> None:
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=5000.0,  # type: ignore[arg-type]
                stop_distance_points=Decimal("25.00"),
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=25.0,  # type: ignore[arg-type]
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                risk_pct=1.0,  # type: ignore[arg-type]
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                existing_used_margin_usd=0.0,  # type: ignore[arg-type]
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                min_margin_level_pct=1000.0,  # type: ignore[arg-type]
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=True,  # type: ignore[arg-type]
                stop_distance_points=Decimal("25.00"),
            )
        with self.assertRaises(MicroFuturesSizingRefusalError):
            size_micro_futures_order(
                symbol_or_root="MNQ",
                equity_usd=Decimal("5000.00"),
                stop_distance_points=Decimal("25.00"),
                max_contracts=True,  # type: ignore[arg-type]
            )


class TestPackageSurfaceAndSourceHygiene(unittest.TestCase):
    def test_exception_hierarchy_and_package_exports(self) -> None:
        self.assertTrue(issubclass(MicroFuturesError, ContractError))
        self.assertTrue(issubclass(UnsupportedMicroFuturesSymbolError, MicroFuturesError))
        self.assertTrue(issubclass(ExpiredFuturesContractError, MicroFuturesError))
        self.assertTrue(issubclass(MicroFuturesSizingRefusalError, MicroFuturesError))
        for symbol in futures_pkg.__all__:
            self.assertTrue(hasattr(futures_pkg, symbol), f"Missing export {symbol}")
        with self.assertRaises(AttributeError):
            getattr(futures_pkg, "NON_EXISTENT_FUTURES_SYMBOL_XYZ")

    def test_zero_assert_zero_float_money_zero_crlf_zero_bom_in_src(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        src_files = [
            repo_root / "src" / "cas_forex_revamp" / "futures" / "__init__.py",
            repo_root / "src" / "cas_forex_revamp" / "futures" / "micro_futures_specs.py",
        ]
        for path in src_files:
            raw = path.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM found in {path.name}")
            self.assertNotIn(b"\r", raw, f"CR/CRLF found in {path.name}")
            text = raw.decode("utf-8")
            tree = ast.parse(text, filename=str(path))
            assert_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
            self.assertEqual(assert_nodes, [], f"Bandit B101 assert found in {path.name}")
            float_calls = [
                n
                for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "float"
            ]
            self.assertEqual(float_calls, [], f"float() call found in {path.name}")


if __name__ == "__main__":
    unittest.main()
